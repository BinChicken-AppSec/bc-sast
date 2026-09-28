//! Chunk source-code loading, ported from `s4_deepdive.py`'s
//! `_load_chunk_code`/`_load_files_full`/`_load_sliding_window`/
//! `_windows_for_entrypoints`. Every per-file failure (missing file, read
//! error) degrades to an inline placeholder block — never aborts the
//! whole chunk.

use std::path::Path;

use bc_model::{Chunk, ChunkSize, ContextPackage};
// The shared `q_split`-based helpers, not a local pair: Python's
// `q_file`/`q_name` (`s1_preprocess.py:617-629`) split on the LAST `::`
// and return an EMPTY file for a qnode carrying no separator at all.
// This module used to define its own first-`::` variant that returned the
// whole string as the file — which quietly disagreed with `neighbor.rs`
// (already on the shared pair) about what `q_file("builtin_fn")` means.
use bc_repo_analysis::{q_file, q_name};

use crate::redact_source::redact_source;
use crate::slice::{load_graph_slice, load_taint_slice, warn_if_no_def_spans, FUNCTION_MODE};
use crate::Step4Config;

const WINDOW_LINES: usize = 600;
const WINDOW_OVERLAP: usize = 100;
pub(crate) const MAX_LINE_CHARS: usize = 8000;

pub(crate) fn truncate_chars(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// `Ok(text)` read losslessly as UTF-8 (invalid byte sequences replaced,
/// matching Python's `errors="replace"`), or `Err(placeholder block)` for
/// a missing file or genuine I/O error (permissions, etc.) — the caller
/// splices the placeholder in verbatim rather than treating it as fatal.
pub(crate) fn read_file_lossy(rel: &str, path: &Path) -> Result<String, String> {
    if !path.is_file() {
        return Err(format!("=== {rel} ===\n[FILE NOT FOUND]\n"));
    }
    match std::fs::read(path) {
        Ok(bytes) => Ok(String::from_utf8_lossy(&bytes).into_owned()),
        Err(e) => Err(format!("=== {rel} ===\n[READ ERROR: {e}]\n")),
    }
}

/// [`read_file_lossy`], but confines `rel` to `repo_root` first —
/// `rel` here comes straight from an LLM-authored chunk's `files` list
/// (`Chunk::files`/`Chunk::focus_entry_points`-adjacent data), so a
/// `../../etc/passwd`-shaped entry must degrade to the same
/// "FILE NOT FOUND" placeholder a genuinely missing file gets, never
/// actually reach outside the repo (CWE-22).
pub(crate) fn read_confined(repo_root: &Path, rel: &str) -> Result<String, String> {
    match bc_pathjail::confine(repo_root, rel) {
        Some(path) => read_file_lossy(rel, &path),
        None => Err(format!("=== {rel} ===\n[FILE NOT FOUND]\n")),
    }
}

/// For SMALL/MEDIUM chunks: every file in full, redacted and line-numbered.
pub fn load_files_full(files: &[String], repo_root: &Path) -> String {
    let mut parts = Vec::new();
    for rel in files {
        match read_confined(repo_root, rel) {
            Err(placeholder) => parts.push(placeholder),
            Ok(text) => {
                let redacted = redact_source(&text, rel);
                let numbered: Vec<String> = redacted
                    .lines()
                    .enumerate()
                    .map(|(i, ln)| format!("{:5}| {}", i + 1, truncate_chars(ln, MAX_LINE_CHARS)))
                    .collect();
                parts.push(format!("=== {rel} ===\n{}\n", numbered.join("\n")));
            }
        }
    }
    parts.join("\n")
}

/// Anchor every line containing an entry-point function name followed by
/// `(` (a crude call/def-site heuristic, no AST), then merge overlapping-
/// or-close `±300`-line windows around each anchor into disjoint ranges.
/// `[]` when there are no entry points or no anchor is found anywhere —
/// the caller falls back to tiling the whole file in that case.
fn windows_for_entrypoints(lines: &[String], entry_fns: &[String]) -> Vec<(usize, usize)> {
    if entry_fns.is_empty() {
        return Vec::new();
    }
    let mut anchors: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
    for (i, ln) in lines.iter().enumerate() {
        if entry_fns
            .iter()
            .any(|fname| ln.contains(fname.as_str()) && ln.contains('('))
        {
            anchors.insert(i);
        }
    }
    if anchors.is_empty() {
        return Vec::new();
    }

    let half = WINDOW_LINES / 2;
    let raw: Vec<(usize, usize)> = anchors
        .iter()
        .map(|&a| (a.saturating_sub(half), (a + half).min(lines.len())))
        .collect();

    merge_windows(raw)
}

/// Graph/AST anchor lines for one file of a chunk, ported from
/// `_graph_anchor_lines_for_file` (`s4_deepdive.py:1460-1517`).
///
/// This whole tier was missing: `load_sliding_window` went straight to the
/// text-scan heuristic, so a LARGE chunk's windows were placed by "a line
/// mentioning an entry-point name followed by `(`" — which matches call
/// sites, comments and unrelated same-named symbols as readily as the
/// definition it wants, and finds nothing at all for a chunk whose
/// `focus_entry_points` are empty. The parsed `def_spans` and call graph
/// S0/S1 already produced say exactly where the interesting code is.
///
/// Anchors are 1-based line numbers in insertion order, first-write-wins
/// (Python's `_add` does a linear `not in out` check); `windows_for_anchors`
/// sorts and dedups them afterwards, so the order only decides which
/// duplicate survives, not the output.
fn graph_anchor_lines_for_file(chunk: &Chunk, ctx: &ContextPackage, rel: &str) -> Vec<i64> {
    let mut out: Vec<i64> = Vec::new();
    let add = |n: i64, out: &mut Vec<i64>| {
        if n > 0 && !out.contains(&n) {
            out.push(n);
        }
    };

    // 1. Def-starts of this file's hops on the candidate taint path.
    let mut seen_path_funcs: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for qn in &chunk.path_funcs {
        if !seen_path_funcs.insert(qn.as_str()) || q_file(qn) != rel {
            continue;
        }
        if let Some((start, _)) = ctx.def_spans.get(qn) {
            add(*start, &mut out);
        }
    }

    // 2. Def-starts of this file's focus entry points.
    let focus: std::collections::BTreeSet<&str> = chunk
        .focus_entry_points
        .iter()
        .map(String::as_str)
        .collect();
    for (qn, (start, _)) in &ctx.def_spans {
        if q_file(qn) == rel && focus.contains(q_name(qn).as_str()) {
            add(*start, &mut out);
        }
    }

    // 3. Def-starts of entry points the context package names in this file.
    for ep in &ctx.entry_points {
        if ep.file != rel {
            continue;
        }
        if let Some((_, (start, _))) = ctx
            .def_spans
            .iter()
            .find(|(qn, _)| q_file(qn) == rel && q_name(qn) == ep.function)
        {
            add(*start, &mut out);
        }
    }

    // 4. Each sink's own line, then its enclosing function's def-start.
    for sink in &ctx.unsafe_sinks {
        if sink.file != rel {
            continue;
        }
        add(sink.line, &mut out);
        if let Some((_, (start, _))) = ctx
            .def_spans
            .iter()
            .find(|(qn, _)| q_file(qn) == rel && q_name(qn) == sink.function)
        {
            add(*start, &mut out);
        }
    }

    // 5. The chunk's own `file:line` sink ref.
    if let Some((sf, sl)) = chunk.sink_ref.rsplit_once(':') {
        if sf == rel {
            if let Ok(line) = sl.parse::<i64>() {
                add(line, &mut out);
            }
        }
    }

    // 6. Def-site hints for focus functions with no AST span at all — the
    //    tier that makes specialist shards (which carry focus names but
    //    often no retained span) anchorable.
    if !focus.is_empty() {
        for fname in &focus {
            for loc in ctx.call_graph_files.get(*fname).into_iter().flatten() {
                if let Some((lf, ln)) = loc.rsplit_once(':') {
                    if lf == rel {
                        if let Ok(line) = ln.parse::<i64>() {
                            add(line, &mut out);
                        }
                    }
                }
            }
        }
    }

    out
}

/// Windows around exact **1-based** anchor lines, ported from
/// `_windows_for_anchors` (`s4_deepdive.py:1441-1457`).
///
/// Deliberately a separate function from [`windows_for_entrypoints`] and
/// not a refactor of it: that one takes 0-based text-scan hits, this one
/// takes 1-based line numbers and additionally drops anchors outside the
/// file (a `def_spans` entry can name a line past the end of a file that
/// changed since the graph was built). The merge tail is identical.
fn windows_for_anchors(lines: &[String], anchors: &[i64]) -> Vec<(usize, usize)> {
    let half = WINDOW_LINES / 2;
    let norm: std::collections::BTreeSet<usize> = anchors
        .iter()
        .filter(|&&a| a >= 1 && (a as usize) <= lines.len())
        .map(|&a| a as usize)
        .collect();
    if norm.is_empty() {
        return Vec::new();
    }
    let raw: Vec<(usize, usize)> = norm
        .iter()
        .map(|&a| {
            (
                (a - 1).saturating_sub(half),
                (a - 1 + half).min(lines.len()),
            )
        })
        .collect();
    merge_windows(raw)
}

/// The shared overlap-merge tail of `_windows_for_anchors` and
/// `_windows_for_entrypoints`: `raw` must be sorted by `lo`.
fn merge_windows(raw: Vec<(usize, usize)>) -> Vec<(usize, usize)> {
    let mut merged: Vec<(usize, usize)> = vec![raw[0]];
    for &(lo, hi) in &raw[1..] {
        let (plo, phi) = *merged.last().expect("merged always has at least raw[0]");
        if lo <= phi + WINDOW_OVERLAP {
            *merged
                .last_mut()
                .expect("merged always has at least raw[0]") = (plo, phi.max(hi));
        } else {
            merged.push((lo, hi));
        }
    }
    merged
}

/// For LARGE chunks: one or more line-range-labeled window blocks per
/// file, anchored on graph/AST evidence first, then on a text scan of
/// `chunk.focus_entry_points`, else tiled across the whole file so
/// nothing is skipped. The three-tier order is Python's
/// (`s4_deepdive.py:1400-1410`).
pub fn load_sliding_window(chunk: &Chunk, ctx: &ContextPackage, repo_root: &Path) -> String {
    let mut parts = Vec::new();
    for rel in &chunk.files {
        match read_confined(repo_root, rel) {
            Err(placeholder) => parts.push(placeholder),
            Ok(text) => {
                let redacted = redact_source(&text, rel);
                let lines: Vec<String> = redacted
                    .lines()
                    .map(|ln| truncate_chars(ln, MAX_LINE_CHARS))
                    .collect();

                let anchors = graph_anchor_lines_for_file(chunk, ctx, rel);
                let mut windows = windows_for_anchors(&lines, &anchors);
                if windows.is_empty() {
                    windows = windows_for_entrypoints(&lines, &chunk.focus_entry_points);
                }
                if windows.is_empty() {
                    let step = WINDOW_LINES - WINDOW_OVERLAP;
                    let total = lines.len().max(1);
                    let mut lo = 0;
                    while lo < total {
                        windows.push((lo, (lo + WINDOW_LINES).min(lines.len())));
                        lo += step;
                    }
                }

                for (lo, hi) in windows {
                    let numbered: Vec<String> = lines[lo..hi]
                        .iter()
                        .enumerate()
                        .map(|(i, ln)| format!("{:5}| {}", i + lo + 1, ln))
                        .collect();
                    parts.push(format!(
                        "=== {rel} [lines {}-{hi}] ===\n{}\n",
                        lo + 1,
                        numbered.join("\n")
                    ));
                }
            }
        }
    }
    parts.join("\n")
}

/// Ported from `_load_chunk_code` (`s4_deepdive.py:966-990`), tier by
/// tier: with `step4.taint_chunk_slice: function` a chunk carrying a
/// static taint path gets [`load_taint_slice`], any other chunk gets
/// [`load_graph_slice`], and either falling through empty (or the
/// default `file` mode) leaves the original size dispatch — `Large` gets
/// the sliding window, everything else the whole file.
///
/// Returns `(code, was_sliced)`. The flag is not cosmetic: the
/// confirm/refute prompt's claim that the source below holds "ONLY the
/// functions on this path" is only true when a slicer actually produced
/// the text, so [`crate::prompts::build_confirm_refute_prompt`] takes it
/// and words itself honestly otherwise. Python asserts the sliced
/// wording unconditionally, which is wrong in its own shipped default
/// (`taint_chunk_slice: "file"`) — a bug fixed here rather than ported.
pub fn load_chunk_code(
    chunk: &Chunk,
    ctx: &ContextPackage,
    repo_root: &Path,
    config: &Step4Config,
) -> (String, bool) {
    if config.taint_chunk_slice.eq_ignore_ascii_case(FUNCTION_MODE) {
        warn_if_no_def_spans(ctx);
        if !chunk.path_funcs.is_empty() {
            let sliced = load_taint_slice(chunk, ctx, repo_root);
            if !sliced.is_empty() {
                return (sliced, true);
            }
        }
        let sliced = load_graph_slice(chunk, ctx, repo_root, config.frontier_max_funcs_per_file);
        if !sliced.is_empty() {
            return (sliced, true);
        }
    }
    let code = if chunk.size == ChunkSize::Large {
        load_sliding_window(chunk, ctx, repo_root)
    } else {
        load_files_full(&chunk.files, repo_root)
    };
    (code, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, rel: &str, contents: &str) {
        std::fs::write(dir.join(rel), contents).unwrap();
    }

    fn chunk(size: ChunkSize, files: Vec<&str>, focus_entry_points: Vec<&str>) -> Chunk {
        Chunk {
            id: "c1".to_string(),
            size,
            risk_rank: 1,
            files: files.into_iter().map(String::from).collect(),
            focus_entry_points: focus_entry_points.into_iter().map(String::from).collect(),
            hypothesis: String::new(),
            related_cves: Vec::new(),
            threat_id: None,
            languages: Vec::new(),
            specialist: None,
            path_funcs: Vec::new(),
            source_ref: String::new(),
            sink_ref: String::new(),
            sink_cwe: Vec::new(),
            shard_id: String::new(),
        }
    }

    // ── graph/AST anchors ────────────────────────────────────────────

    fn ctx_with_span(qnode: &str, start: i64, end: i64) -> ContextPackage {
        let mut ctx = ContextPackage::default();
        ctx.def_spans.insert(qnode.to_string(), (start, end));
        ctx
    }

    #[test]
    fn a_path_hop_in_this_file_anchors_on_its_def_span_start() {
        let ctx = ctx_with_span("app.py::handler", 10, 40);
        let mut c = chunk(ChunkSize::Large, vec!["app.py"], vec![]);
        // Duplicated deliberately: Python dedups path_funcs first.
        c.path_funcs = vec!["app.py::handler".to_string(), "app.py::handler".to_string()];
        assert_eq!(graph_anchor_lines_for_file(&c, &ctx, "app.py"), vec![10]);
        // A hop in a different file contributes nothing to this one.
        assert!(graph_anchor_lines_for_file(&c, &ctx, "other.py").is_empty());
    }

    #[test]
    fn a_focus_entry_point_anchors_on_its_def_span_start() {
        let ctx = ctx_with_span("app.py::login", 7, 20);
        let c = chunk(ChunkSize::Large, vec!["app.py"], vec!["login"]);
        assert_eq!(graph_anchor_lines_for_file(&c, &ctx, "app.py"), vec![7]);
    }

    #[test]
    fn a_context_entry_point_anchors_on_the_matching_def_span() {
        let mut ctx = ctx_with_span("app.py::main", 3, 9);
        ctx.entry_points.push(bc_model::EntryPoint {
            file: "app.py".to_string(),
            function: "main".to_string(),
            kind: bc_model::EntryPointKind::Network,
            reachable_from_unauth: true,
        });
        // An entry point in another file is skipped outright.
        ctx.entry_points.push(bc_model::EntryPoint {
            file: "other.py".to_string(),
            function: "main".to_string(),
            kind: bc_model::EntryPointKind::Cli,
            reachable_from_unauth: false,
        });
        let c = chunk(ChunkSize::Large, vec!["app.py"], vec![]);
        assert_eq!(graph_anchor_lines_for_file(&c, &ctx, "app.py"), vec![3]);
    }

    #[test]
    fn a_sink_contributes_its_own_line_then_its_enclosing_def_start() {
        let mut ctx = ctx_with_span("app.py::query", 20, 30);
        ctx.unsafe_sinks.push(bc_model::Sink {
            file: "app.py".to_string(),
            line: 25,
            function: "query".to_string(),
            snippet: String::new(),
            cwe: Vec::new(),
        });
        ctx.unsafe_sinks.push(bc_model::Sink {
            file: "elsewhere.py".to_string(),
            line: 99,
            function: "query".to_string(),
            snippet: String::new(),
            cwe: Vec::new(),
        });
        let c = chunk(ChunkSize::Large, vec!["app.py"], vec![]);
        // The sink's own line first, then the def-start — Python's order.
        assert_eq!(
            graph_anchor_lines_for_file(&c, &ctx, "app.py"),
            vec![25, 20]
        );
    }

    #[test]
    fn a_sink_with_no_usable_line_still_anchors_on_its_enclosing_def() {
        // `_add`'s `n > 0` guard drops a zero line without dropping the
        // sink's function anchor.
        let mut ctx = ctx_with_span("app.py::query", 20, 30);
        ctx.unsafe_sinks.push(bc_model::Sink {
            file: "app.py".to_string(),
            line: 0,
            function: "query".to_string(),
            snippet: String::new(),
            cwe: Vec::new(),
        });
        let c = chunk(ChunkSize::Large, vec!["app.py"], vec![]);
        assert_eq!(graph_anchor_lines_for_file(&c, &ctx, "app.py"), vec![20]);
    }

    #[test]
    fn the_chunks_own_sink_ref_anchors_when_it_names_this_file() {
        let ctx = ContextPackage::default();
        let mut c = chunk(ChunkSize::Large, vec!["app.py"], vec![]);
        c.sink_ref = "app.py:88".to_string();
        assert_eq!(graph_anchor_lines_for_file(&c, &ctx, "app.py"), vec![88]);
        // A sink_ref naming a different file, or carrying a non-numeric
        // line, or no colon at all, contributes nothing.
        c.sink_ref = "other.py:88".to_string();
        assert!(graph_anchor_lines_for_file(&c, &ctx, "app.py").is_empty());
        c.sink_ref = "app.py:notaline".to_string();
        assert!(graph_anchor_lines_for_file(&c, &ctx, "app.py").is_empty());
        c.sink_ref = "app.py".to_string();
        assert!(graph_anchor_lines_for_file(&c, &ctx, "app.py").is_empty());
    }

    #[test]
    fn a_focus_function_with_no_ast_span_falls_back_to_its_call_graph_def_site() {
        // The tier that makes specialist shards anchorable: they carry
        // focus names but often no retained def_span.
        let mut ctx = ContextPackage::default();
        ctx.call_graph_files.insert(
            "encrypt".to_string(),
            vec![
                "app.py:64".to_string(),
                "other.py:5".to_string(),
                "malformed".to_string(),
                "app.py:notaline".to_string(),
            ],
        );
        let c = chunk(ChunkSize::Large, vec!["app.py"], vec!["encrypt"]);
        assert_eq!(graph_anchor_lines_for_file(&c, &ctx, "app.py"), vec![64]);
    }

    #[test]
    fn windows_for_anchors_drops_anchors_outside_the_file_and_merges_close_ones() {
        let lines: Vec<String> = (0..1000).map(|i| format!("line {i}")).collect();
        // 0 and 5000 are both out of range; 400 and 500 are within
        // WINDOW_OVERLAP of each other and merge into one window.
        let got = windows_for_anchors(&lines, &[0, 5000, 400, 500]);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], (99, 799));
        // Far apart -> two windows.
        let got = windows_for_anchors(&lines, &[1, 999]);
        assert_eq!(got.len(), 2);
    }

    #[test]
    fn windows_for_anchors_yields_nothing_when_no_anchor_is_in_range() {
        let lines: Vec<String> = (0..10).map(|i| format!("line {i}")).collect();
        assert!(windows_for_anchors(&lines, &[]).is_empty());
        assert!(windows_for_anchors(&lines, &[0, -3, 11]).is_empty());
    }

    #[test]
    fn a_large_chunk_prefers_graph_anchors_over_the_entry_point_text_scan() {
        // The text scan would anchor on the CALL site at line 2; the AST
        // span points at the definition 900 lines later. Only the graph
        // tier gets that right, and it is what Python uses first.
        let dir = tempfile::tempdir().unwrap();
        let mut body = String::from("import x\nrun()\n");
        for i in 0..900 {
            body.push_str(&format!("# filler {i}\n"));
        }
        body.push_str("def run():\n    danger()\n");
        write(dir.path(), "app.py", &body);

        let ctx = ctx_with_span("app.py::run", 903, 904);
        let c = chunk(ChunkSize::Large, vec!["app.py"], vec!["run"]);
        let out = load_sliding_window(&c, &ctx, dir.path());
        assert!(out.contains("danger()"), "{out}");
        // One window, centered on the definition — not the whole file and
        // not the call-site window the text scan would have produced.
        assert_eq!(out.matches("=== app.py [lines").count(), 1, "{out}");
        assert!(!out.contains("import x"), "{out}");
    }

    #[test]
    fn a_large_chunk_with_no_graph_evidence_still_falls_back_to_the_text_scan() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "app.py", "import x\ndef run():\n    danger()\n");
        let c = chunk(ChunkSize::Large, vec!["app.py"], vec!["run"]);
        let out = load_sliding_window(&c, &ContextPackage::default(), dir.path());
        assert!(out.contains("danger()"), "{out}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn load_files_full_unreadable_file_is_a_read_error_placeholder() {
        // `drop_caches` is a regular file nobody can open for reading. The
        // kernel checks a sysctl's mode bits itself, without the
        // CAP_DAC_OVERRIDE bypass a chmod 000 file gets, so the read fails
        // for root as well. Its directory stands in for the repository so
        // the file is inside the jail.
        let repo = Path::new("/proc/sys/vm");
        let out = load_files_full(&["drop_caches".to_string()], repo);
        assert!(
            out.contains("=== drop_caches ===\n[READ ERROR: Permission denied"),
            "unexpected: {out}"
        );
    }

    #[test]
    fn load_files_full_numbers_lines_and_redacts() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.py", "line0\nline1\n");
        let out = load_files_full(&["a.py".to_string()], dir.path());
        assert!(out.contains("=== a.py ==="));
        assert!(out.contains("    1| line0"));
        assert!(out.contains("    2| line1"));
    }

    #[test]
    fn load_files_full_missing_file_is_a_placeholder() {
        let dir = tempfile::tempdir().unwrap();
        let out = load_files_full(&["missing.py".to_string()], dir.path());
        assert!(out.contains("=== missing.py ===\n[FILE NOT FOUND]"));
    }

    #[test]
    fn load_files_full_an_llm_chosen_path_that_escapes_the_repo_root_is_not_found_not_read() {
        let dir = tempfile::tempdir().unwrap();
        let out = load_files_full(&["../outside.py".to_string()], dir.path());
        assert!(out.contains("=== ../outside.py ===\n[FILE NOT FOUND]"));
    }

    #[test]
    fn load_sliding_window_an_llm_chosen_path_that_escapes_the_repo_root_is_not_found_not_read() {
        let dir = tempfile::tempdir().unwrap();
        let out = load_sliding_window(
            &chunk(ChunkSize::Large, vec!["../outside.py"], vec![]),
            &ContextPackage::default(),
            dir.path(),
        );
        assert!(out.contains("=== ../outside.py ===\n[FILE NOT FOUND]"));
    }

    #[test]
    fn load_files_full_truncates_overlong_lines() {
        let dir = tempfile::tempdir().unwrap();
        let long_line = "x".repeat(MAX_LINE_CHARS + 500);
        write(dir.path(), "a.py", &long_line);
        let out = load_files_full(&["a.py".to_string()], dir.path());
        // header "    1| " + MAX_LINE_CHARS x's, nothing more of the line.
        assert!(out.contains(&"x".repeat(MAX_LINE_CHARS)));
        assert!(!out.contains(&"x".repeat(MAX_LINE_CHARS + 1)));
    }

    #[test]
    fn load_files_full_multiple_files_are_joined() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.py", "a\n");
        write(dir.path(), "b.py", "b\n");
        let out = load_files_full(&["a.py".to_string(), "b.py".to_string()], dir.path());
        assert!(out.contains("=== a.py ==="));
        assert!(out.contains("=== b.py ==="));
    }

    #[test]
    fn windows_for_entrypoints_empty_entry_fns_yields_no_windows() {
        let lines = vec!["def handler():".to_string()];
        assert!(windows_for_entrypoints(&lines, &[]).is_empty());
    }

    #[test]
    fn windows_for_entrypoints_no_anchor_found_yields_no_windows() {
        let lines = vec!["print(1)".to_string()];
        let entry_fns = vec!["handler".to_string()];
        assert!(windows_for_entrypoints(&lines, &entry_fns).is_empty());
    }

    #[test]
    fn windows_for_entrypoints_single_anchor_centers_a_window() {
        let mut lines = vec![String::new(); 1000];
        lines[500] = "def handler():".to_string();
        let entry_fns = vec!["handler".to_string()];
        let windows = windows_for_entrypoints(&lines, &entry_fns);
        assert_eq!(windows, vec![(200, 800)]);
    }

    #[test]
    fn windows_for_entrypoints_clamps_at_file_boundaries() {
        let mut lines = vec![String::new(); 50];
        lines[10] = "def handler():".to_string();
        let entry_fns = vec!["handler".to_string()];
        let windows = windows_for_entrypoints(&lines, &entry_fns);
        assert_eq!(windows, vec![(0, 50)]);
    }

    #[test]
    fn windows_for_entrypoints_merges_close_anchors_into_one_window() {
        let mut lines = vec![String::new(); 1000];
        lines[100] = "def handler():".to_string();
        lines[200] = "def other():".to_string();
        let entry_fns = vec!["handler".to_string(), "other".to_string()];
        let windows = windows_for_entrypoints(&lines, &entry_fns);
        // Anchor 100 -> (0, 400); anchor 200 -> (0, 500) merges since
        // 0 <= 400 + 100 -> single window (0, 500).
        assert_eq!(windows, vec![(0, 500)]);
    }

    #[test]
    fn windows_for_entrypoints_keeps_far_apart_anchors_disjoint() {
        let mut lines = vec![String::new(); 5000];
        lines[100] = "def handler():".to_string();
        lines[4000] = "def other():".to_string();
        let entry_fns = vec!["handler".to_string(), "other".to_string()];
        let windows = windows_for_entrypoints(&lines, &entry_fns);
        assert_eq!(windows, vec![(0, 400), (3700, 4300)]);
    }

    #[test]
    fn windows_for_entrypoints_deduplicates_repeated_anchor_lines() {
        let mut lines = vec![String::new(); 1000];
        lines[500] = "handler() and handler() again".to_string();
        let entry_fns = vec!["handler".to_string()];
        let windows = windows_for_entrypoints(&lines, &entry_fns);
        assert_eq!(windows, vec![(200, 800)]);
    }

    #[test]
    fn load_sliding_window_with_anchor_labels_the_line_range() {
        let dir = tempfile::tempdir().unwrap();
        let mut content = String::new();
        for i in 0..1000 {
            if i == 500 {
                content.push_str("def handler():\n");
            } else {
                content.push_str("pass\n");
            }
        }
        write(dir.path(), "a.py", &content);
        let c = chunk(ChunkSize::Large, vec!["a.py"], vec!["handler"]);
        let out = load_sliding_window(&c, &ContextPackage::default(), dir.path());
        assert!(out.contains("=== a.py [lines 201-800] ==="));
    }

    #[test]
    fn load_sliding_window_with_no_anchors_tiles_the_whole_file() {
        let dir = tempfile::tempdir().unwrap();
        let content = "pass\n".repeat(1000);
        write(dir.path(), "a.py", &content);
        let c = chunk(ChunkSize::Large, vec!["a.py"], vec![]);
        let out = load_sliding_window(&c, &ContextPackage::default(), dir.path());
        assert!(out.contains("[lines 1-600]"));
        assert!(out.contains("[lines 501-1000]"));
    }

    #[test]
    fn load_sliding_window_missing_file_is_a_placeholder() {
        let dir = tempfile::tempdir().unwrap();
        let c = chunk(ChunkSize::Large, vec!["missing.py"], vec![]);
        let out = load_sliding_window(&c, &ContextPackage::default(), dir.path());
        assert!(out.contains("[FILE NOT FOUND]"));
    }

    #[test]
    fn load_chunk_code_dispatches_on_size() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.py", "x\n");
        let cfg = Step4Config::new("m");
        let small = chunk(ChunkSize::Small, vec!["a.py"], vec![]);
        let (out, sliced) = load_chunk_code(&small, &ContextPackage::default(), dir.path(), &cfg);
        assert!(out.contains("=== a.py ===\n") && !out.contains("[lines"));
        assert!(!sliced, "the default `file` mode never slices");

        let large = chunk(ChunkSize::Large, vec!["a.py"], vec![]);
        let (out, sliced) = load_chunk_code(&large, &ContextPackage::default(), dir.path(), &cfg);
        assert!(out.contains("[lines 1-"));
        assert!(!sliced);
    }
}
