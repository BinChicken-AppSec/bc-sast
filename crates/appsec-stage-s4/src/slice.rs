use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use appsec_model::{Chunk, ContextPackage};
use appsec_repo_analysis::{q_file, q_name};

use crate::code_loading::{read_confined, truncate_chars, MAX_LINE_CHARS};
use crate::redact_source::redact_source;

pub const FUNCTION_MODE: &str = "function";

const TAINT_PAD: i64 = 8;
const GRAPH_PAD: i64 = 6;

static DEF_SPANS_ABSENT_WARNED: AtomicBool = AtomicBool::new(false);

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

fn split_loc(loc: &str) -> Option<(&str, i64)> {
    let (file, line) = loc.rsplit_once(':')?;
    if file.is_empty() || line.is_empty() || !line.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    line.parse::<i64>().ok().map(|n| (file, n))
}

enum FilePlan {
    Whole,
    Ranges(Vec<(i64, i64)>),
}

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

pub fn load_taint_slice(chunk: &Chunk, ctx: &ContextPackage, repo_root: &Path) -> String {
    if ctx.def_spans.is_empty() {
        return String::new();
    }
    let mut by_file: BTreeMap<String, Vec<(i64, i64)>> = BTreeMap::new();
    let mut whole_file: BTreeSet<String> = BTreeSet::new();
    let mut seen: BTreeSet<&str> = BTreeSet::new();

    for qn in &chunk.path_funcs {
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
            clipped_files.insert(file);
            continue;
        }
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

    if let Some((file, line)) = split_loc(&chunk.sink_ref) {
        if chunk_files.contains(file) {
            by_file
                .entry(file.to_string())
                .or_default()
                .push(((line - GRAPH_PAD).max(1), line + GRAPH_PAD));
        }
    }

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
        render_file(repo_root, rel, &plan, GRAPH_PAD, &mut parts);
    }
    if parts.is_empty() {
        return String::new();
    }
    parts.join("\n")
}

#[cfg(test)]
mod tests;
