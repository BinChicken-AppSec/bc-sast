//! Function-level chunk slicing (`taint_chunk_slice: function`), ported
//! from `s4_deepdive.py:1009-1254`'s `_load_taint_slice`,
//! `_load_graph_slice` and `_merge_ranges`.
//!
//! **What it buys.** Without it a taint chunk ships every byte of every
//! file on the path — a 5-hop path through three 2,000-line classes is
//! 6,000 lines of prompt, of which maybe 120 are the path. With it the
//! model sees the def-span of each hop plus a few lines either side, in
//! `chunk.files` order (entry -> sink), and nothing else. That is also
//! what makes the confirm/refute prompt's "ONLY the functions on this
//! path" wording true — see [`crate::prompts::build_confirm_refute_prompt`],
//! which now takes the honest wording when slicing is off.
//!
//! **Two tiers, in Python's order.** A chunk carrying a static taint path
//! (`chunk.path_funcs`) gets [`load_taint_slice`], which follows the path
//! exactly. Every other chunk in `function` mode gets [`load_graph_slice`],
//! which ranks the chunk's def-spans by call-graph/entry-point/sink
//! relevance and takes the top ones per file. Either tier returning an
//! empty string means "nothing resolved" and hands the chunk back to the
//! whole-file / sliding-window loaders — a missing tree-sitter install
//! degrades coverage, never drops code.
//!
//! **Fallbacks are per file, never per chunk**, in both tiers, because
//! the prompt tells the model the slice contains the whole path: a hop
//! whose file the graph could not resolve is shipped WHOLE rather than
//! silently omitted (`_load_taint_slice`'s `whole_file` set,
//! `_load_graph_slice`'s `clipped_files` + un-ranged files).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use bc_model::{Chunk, ContextPackage};
use bc_repo_analysis::{q_file, q_name};

use crate::code_loading::{read_confined, truncate_chars, MAX_LINE_CHARS};
use crate::redact_source::redact_source;

/// The `taint_chunk_slice` value that turns slicing on. Any other value
/// (including the default `"file"`) leaves loading exactly as it was.
pub const FUNCTION_MODE: &str = "function";

/// Context lines either side of each def-span. Python uses two different
/// pads — the taint slice is more generous because its ranges ARE the
/// answer, while the graph slice takes many more spans per file.
const TAINT_PAD: i64 = 8;
const GRAPH_PAD: i64 = 6;

/// Python's `_DEF_SPANS_ABSENT_WARNED` module global: the "you asked for
/// function slicing and there are no def_spans" warning is per process,
/// not per chunk, or a 60-chunk taint run prints it 60 times.
static DEF_SPANS_ABSENT_WARNED: AtomicBool = AtomicBool::new(false);

/// Warn once when `function` mode was requested but S0/S1 produced no
/// `def_spans` to slice on (`step1.call_graph: regex`, or no tree-sitter
/// backend at all). Ported from `_load_chunk_code`'s own guard
/// (`s4_deepdive.py:968-975`) — slicing then silently no-ops into
/// whole-file loading, which is safe but not what the operator asked for.
pub fn warn_if_no_def_spans(ctx: &ContextPackage) {
    if !ctx.def_spans.is_empty() {
        return;
    }
    if !DEF_SPANS_ABSENT_WARNED.swap(true, Ordering::Relaxed) {
        tracing::warn!(
            "[s4] def_spans absent — function-level slicing unavailable; \
             using whole-file fallback mode."
        );
    }
}

/// Merge overlapping or near-adjacent (`<= gap` apart) line ranges,
/// ported from `_merge_ranges` (`s4_deepdive.py:1244-1254`). So a 5-hop
/// path through one large class emits one contiguous block, not five
/// overlapping ones.
fn merge_ranges(mut ranges: Vec<(i64, i64)>, gap: i64) -> Vec<(i64, i64)> {
    ranges.sort_unstable();
    let mut out: Vec<(i64, i64)> = Vec::new();
    for (lo, hi) in ranges {
        match out.last_mut() {
            Some(last) if lo <= last.1 + gap + 1 => last.1 = last.1.max(hi),
            _ => out.push((lo, hi)),
        }
    }
    out
}

/// `"<file>:<line>"` -> `(file, line)`, with Python's
/// `rpartition(":")` + `str.isdigit()` semantics: the separator must be
/// present, the file half non-empty, and the line half ASCII digits only
/// — so `"a.py"`, `":12"` and `"a.py:-1"` are all "not a location"
/// rather than a location at line 0.
fn split_loc(loc: &str) -> Option<(&str, i64)> {
    let (file, line) = loc.rsplit_once(':')?;
    if file.is_empty() || line.is_empty() || !line.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    line.parse::<i64>().ok().map(|n| (file, n))
}

/// What to emit for one chunk file.
enum FilePlan {
    /// Every line — the per-file fallback both tiers use rather than
    /// dropping code the prompt claims is present.
    Whole,
    /// Merged def-span windows.
    Ranges(Vec<(i64, i64)>),
}

/// Render one file's plan as `=== rel [lines lo-hi] ===` blocks appended
/// to `parts`, returning how many source lines were emitted. A missing /
/// unreadable / jail-escaping path degrades to the same inline
/// placeholder the whole-file loader uses, never aborting the chunk.
fn render_file(
    repo_root: &Path,
    rel: &str,
    plan: &FilePlan,
    gap: i64,
    parts: &mut Vec<String>,
) -> usize {
    let text = match read_confined(repo_root, rel) {
        Ok(text) => text,
        Err(placeholder) => {
            parts.push(placeholder);
            return 0;
        }
    };
    let redacted = redact_source(&text, rel);
    let lines: Vec<String> = redacted
        .lines()
        .map(|ln| truncate_chars(ln, MAX_LINE_CHARS))
        .collect();
    let total = lines.len() as i64;
    let emit = match plan {
        FilePlan::Whole if total == 0 => Vec::new(),
        FilePlan::Whole => vec![(1, total)],
        FilePlan::Ranges(ranges) => merge_ranges(ranges.clone(), gap),
    };

    let mut emitted = 0usize;
    for (lo, hi) in emit {
        let hi = hi.min(total);
        if lo > hi {
            continue;
        }
        let body: Vec<String> = (lo..=hi)
            .map(|i| format!("{i:5}| {}", lines[(i - 1) as usize]))
            .collect();
        parts.push(format!(
            "=== {rel} [lines {lo}-{hi}] ===\n{}\n",
            body.join("\n")
        ));
        emitted += (hi - lo + 1) as usize;
    }
    emitted
}

/// The def-span of each qnode on `chunk.path_funcs` (plus [`TAINT_PAD`]
/// context lines either side and the sink line itself), ported from
/// `_load_taint_slice` (`s4_deepdive.py:1146-1242`).
///
/// A hop with no AST span anchors on its def line from
/// `call_graph_files`; a hop with neither ships its whole file, because
/// the confirm/refute prompt tells the model the slice contains the
/// whole path and a dropped hop would make that a lie. `""` when no path
/// qnode resolves at all — the caller then falls back to whole-file
/// loading, so a missing tree-sitter install never drops code.
pub fn load_taint_slice(chunk: &Chunk, ctx: &ContextPackage, repo_root: &Path) -> String {
    if ctx.def_spans.is_empty() {
        return String::new();
    }
    let mut by_file: BTreeMap<String, Vec<(i64, i64)>> = BTreeMap::new();
    let mut whole_file: BTreeSet<String> = BTreeSet::new();
    let mut seen: BTreeSet<&str> = BTreeSet::new();

    for qn in &chunk.path_funcs {
        // `dict.fromkeys(chunk.path_funcs)`: a hop repeated on the path
        // contributes its span once.
        if !seen.insert(qn.as_str()) {
            continue;
        }
        let file = q_file(qn);
        if file.is_empty() {
            continue;
        }
        let (lo, hi) = match ctx.def_spans.get(qn) {
            Some(&span) => span,
            None => {
                // No AST span (regex-fallback file or unmapped language)
                // — anchor on the def line from `call_graph_files` and
                // let the pad do the rest.
                let anchor = ctx
                    .call_graph_files
                    .get(&q_name(qn))
                    .into_iter()
                    .flatten()
                    .find_map(|loc| split_loc(loc).filter(|&(rf, line)| rf == file && line != 0));
                match anchor {
                    Some((_, line)) => (line, line),
                    None => {
                        whole_file.insert(file);
                        continue;
                    }
                }
            }
        };
        by_file
            .entry(file)
            .or_default()
            .push(((lo - TAINT_PAD).max(1), hi + TAINT_PAD));
    }

    // Always include the sink line even when its enclosing def was not on
    // the path (e.g. the sink is a bare call at module scope).
    if let Some((sink_file, line)) = split_loc(&chunk.sink_ref) {
        by_file
            .entry(sink_file.to_string())
            .or_default()
            .push(((line - TAINT_PAD).max(1), line + TAINT_PAD));
    }
    if by_file.is_empty() && whole_file.is_empty() {
        return String::new();
    }

    let mut parts: Vec<String> = Vec::new();
    // `chunk.files` order, not `by_file` order: S3 emits a taint chunk's
    // files entry -> sink, and reading the path in flow order is the
    // whole point of the confirm/refute prompt.
    for rel in &chunk.files {
        let plan = if whole_file.contains(rel) {
            FilePlan::Whole
        } else {
            match by_file.get(rel) {
                Some(ranges) => FilePlan::Ranges(ranges.clone()),
                None => continue,
            }
        };
        render_file(repo_root, rel, &plan, TAINT_PAD, &mut parts);
    }
    if parts.is_empty() {
        return String::new();
    }
    parts.join("\n")
}

/// Relevance score for one qnode, ported from `_load_graph_slice`'s
/// scoring block (`s4_deepdive.py:1029-1064`). The weights are Python's
/// verbatim: an explicit path hop (100) beats an entry point (50) beats a
/// sink (45) beats a focus anchor (40) beats mere call-graph
/// connectivity (10/8/+3 either side for an intra-chunk edge).
fn graph_scores(chunk: &Chunk, ctx: &ContextPackage) -> BTreeMap<String, i64> {
    let chunk_files: BTreeSet<&str> = chunk.files.iter().map(String::as_str).collect();
    let focus: BTreeSet<&str> = chunk
        .focus_entry_points
        .iter()
        .map(String::as_str)
        .collect();
    let mut scores: BTreeMap<String, i64> = BTreeMap::new();

    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for qn in &chunk.path_funcs {
        if seen.insert(qn.as_str()) && chunk_files.contains(q_file(qn).as_str()) {
            *scores.entry(qn.clone()).or_default() += 100;
        }
    }

    // Index qnodes by (file, name) once, so entry-point and sink
    // attribution are direct lookups instead of a full scan of the span
    // map per anchor.
    let mut by_file_name: BTreeMap<(String, String), Vec<&str>> = BTreeMap::new();
    for qn in ctx.def_spans.keys() {
        by_file_name
            .entry((q_file(qn), q_name(qn)))
            .or_default()
            .push(qn.as_str());
    }
    let mut anchored: Vec<(&str, &str, i64)> = Vec::new();
    for ep in &ctx.entry_points {
        anchored.push((&ep.file, &ep.function, 50));
    }
    for sink in &ctx.unsafe_sinks {
        anchored.push((&sink.file, &sink.function, 45));
    }
    for (file, function, by) in anchored {
        if !chunk_files.contains(file) || function.is_empty() {
            continue;
        }
        let key = (file.to_string(), function.to_string());
        for qn in by_file_name.get(&key).into_iter().flatten() {
            *scores.entry((*qn).to_string()).or_default() += by;
        }
    }

    for (caller, callees) in &ctx.call_graph {
        let caller_in = chunk_files.contains(q_file(caller).as_str());
        if caller_in {
            *scores.entry(caller.clone()).or_default() += 10;
        }
        for callee in callees {
            let callee_in = chunk_files.contains(q_file(callee).as_str());
            if callee_in {
                *scores.entry(callee.clone()).or_default() += 8;
            }
            if caller_in && callee_in {
                *scores.entry(caller.clone()).or_default() += 3;
                *scores.entry(callee.clone()).or_default() += 3;
            }
        }
    }

    for qn in ctx.def_spans.keys() {
        if chunk_files.contains(q_file(qn).as_str()) && focus.contains(q_name(qn).as_str()) {
            *scores.entry(qn.clone()).or_default() += 40;
        }
    }
    scores
}

/// A graph/AST-prioritized slice for a chunk with no static taint path,
/// ported from `_load_graph_slice` (`s4_deepdive.py:1009-1143`).
///
/// Picks the highest-scoring def-spans in each chunk file (capped at
/// `max_funcs_per_file`), plus focus-anchor and sink lines. A chunk file
/// the graph resolved no span for — or whose functions were CLIPPED at
/// the cap — is shipped WHOLE rather than truncated to a fixed head, so
/// no code below the cut is silently dropped. `""` when nothing at all
/// resolved, so the caller falls back rather than emitting file-head
/// snippets.
pub fn load_graph_slice(
    chunk: &Chunk,
    ctx: &ContextPackage,
    repo_root: &Path,
    max_funcs_per_file: usize,
) -> String {
    let chunk_files: BTreeSet<&str> = chunk.files.iter().map(String::as_str).collect();
    let scores = graph_scores(chunk, ctx);

    let mut ranked: Vec<&String> = ctx
        .def_spans
        .keys()
        .filter(|qn| chunk_files.contains(q_file(qn).as_str()))
        .collect();
    ranked.sort_by_key(|qn| {
        (
            -scores.get(*qn).copied().unwrap_or(0),
            q_file(qn),
            q_name(qn),
        )
    });

    let mut by_file: BTreeMap<String, Vec<(i64, i64)>> = BTreeMap::new();
    let mut picked_per_file: BTreeMap<String, usize> = BTreeMap::new();
    let mut clipped_files: BTreeSet<String> = BTreeSet::new();
    for qn in ranked {
        let file = q_file(qn);
        let picked = picked_per_file.entry(file.clone()).or_default();
        if *picked >= max_funcs_per_file {
            // More resolved functions than the cap: record the file so
            // the emit loop ships it WHOLE rather than dropping whatever
            // ranked past the cap.
            clipped_files.insert(file);
            continue;
        }
        // `def_spans` is typed `(i64, i64)` here, so Python's
        // "missing or shorter than 2" guard has no counterpart; the
        // degenerate-span guard below does still apply.
        let (lo, hi) = ctx.def_spans[qn];
        if lo <= 0 || hi <= lo {
            continue;
        }
        by_file
            .entry(file)
            .or_default()
            .push(((lo - GRAPH_PAD).max(1), hi + GRAPH_PAD));
        *picked += 1;
    }

    // Focus anchors from `call_graph_files`: for specialist shards this
    // can yield usable ranges even when no retained def_spans qnode hits
    // the file at all.
    for name in &chunk.focus_entry_points {
        for loc in ctx.call_graph_files.get(name).into_iter().flatten() {
            let Some((file, line)) = split_loc(loc) else {
                continue;
            };
            if !chunk_files.contains(file) {
                continue;
            }
            by_file
                .entry(file.to_string())
                .or_default()
                .push(((line - GRAPH_PAD).max(1), line + GRAPH_PAD));
        }
    }

    // The explicit sink line, for a sink called at module scope.
    if let Some((file, line)) = split_loc(&chunk.sink_ref) {
        if chunk_files.contains(file) {
            by_file
                .entry(file.to_string())
                .or_default()
                .push(((line - GRAPH_PAD).max(1), line + GRAPH_PAD));
        }
    }

    // No span/anchor resolved anywhere in this chunk: force the caller
    // back to per-file loading instead of emitting tiny head snippets.
    if by_file.is_empty() {
        return String::new();
    }

    let mut parts: Vec<String> = Vec::new();
    for rel in &chunk.files {
        let ranges = by_file.get(rel).cloned().unwrap_or_default();
        let merged = merge_ranges(ranges, GRAPH_PAD);
        let plan = if merged.is_empty() || clipped_files.contains(rel) {
            FilePlan::Whole
        } else {
            FilePlan::Ranges(merged)
        };
        // Already merged above; a second merge with the same gap is
        // idempotent, so `render_file` can keep one code path.
        render_file(repo_root, rel, &plan, GRAPH_PAD, &mut parts);
    }
    if parts.is_empty() {
        return String::new();
    }
    parts.join("\n")
}

#[cfg(test)]
mod tests;
