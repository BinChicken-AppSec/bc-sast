//! Cross-chunk "neighbor context": excerpts of callers/callees that live
//! OUTSIDE the current chunk, giving the researcher just enough
//! upstream/downstream visibility to rule out false positives ("input is
//! already validated in the caller") or confirm true positives ("callee
//! passes it to Runtime.exec") without paying for the whole other chunk.
//! Ported from `s4_deepdive.py`'s `_neighbor_context`/`_excerpt`.
//!
//! Iteration over "which in-chunk functions have out-of-chunk neighbors"
//! is a Python `set` in the original (hash-randomized, not stably
//! reproducible even across two runs of the Python tool itself); this port
//! reaches the same intended coverage via a `BTreeSet`, giving this port
//! its own deterministic (and therefore testable) neighbor ordering — the
//! same accepted divergence already used in `bc-stage-s3`'s
//! `grouping.rs`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use bc_model::{Chunk, ContextPackage};
use bc_repo_analysis::{q_file, q_name};

use crate::code_loading::read_confined;
use crate::redact_source::redact_source;

fn reverse_call_graph(fwd: &BTreeMap<String, Vec<String>>) -> BTreeMap<String, Vec<String>> {
    let mut rev: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (caller, callees) in fwd {
        for callee in callees {
            rev.entry(callee.clone()).or_default().push(caller.clone());
        }
    }
    rev
}

/// `(file, function-name) -> 1-based def-site line`, built from
/// `ctx.call_graph_files`. A location with no `:` (no line recorded)
/// yields line `0` (the "no hint, fall back to scanning" sentinel), same
/// as the Python original's `f, _, ln = loc.rpartition(":")`.
fn def_line_map(
    call_graph_files: &BTreeMap<String, Vec<String>>,
) -> BTreeMap<(String, String), i64> {
    let mut out = BTreeMap::new();
    for (fn_name, locs) in call_graph_files {
        for loc in locs {
            let (file, line) = match loc.rsplit_once(':') {
                Some((f, l)) => (f.to_string(), l.parse::<i64>().unwrap_or(0)),
                None => (loc.clone(), 0),
            };
            out.insert((file, fn_name.clone()), line);
        }
    }
    out
}

/// `hint_line - 1` (0-indexed) if the call graph gave a valid in-bounds
/// line, else the first line containing `fn_name` immediately followed by
/// `(` — the same crude call/def-site heuristic used for entry-point
/// anchors in `code_loading::windows_for_entrypoints`.
fn find_anchor(lines: &[&str], fn_name: &str, hint_line: i64) -> Option<usize> {
    if hint_line > 0 && (hint_line as usize) <= lines.len() {
        return Some(hint_line as usize - 1);
    }
    if fn_name.is_empty() {
        return None;
    }
    lines
        .iter()
        .position(|ln| ln.contains(fn_name) && ln.contains('('))
}

/// `(excerpt text, 1-based first line number)` for `n` lines of context
/// after the anchor (plus 2 lines of lead-in), or `None` if the file can't
/// be read or no anchor is found anywhere. The excerpt is redacted before
/// it can ever reach a prompt, same as every other source excerpt in this
/// crate. The read is confined to `repo_root` like every chunk-file read,
/// so a call-graph path through a symlink cannot pull text from outside
/// the repository into the prompt.
fn excerpt(
    repo_root: &Path,
    rel: &str,
    fn_name: &str,
    hint_line: i64,
    n: usize,
) -> Option<(String, usize)> {
    let text = read_confined(repo_root, rel).ok()?;
    let redacted = redact_source(&text, rel);
    let lines: Vec<&str> = redacted.lines().collect();
    let anchor = find_anchor(&lines, fn_name, hint_line)?;
    let lo = anchor.saturating_sub(2);
    let hi = (anchor + n).min(lines.len());
    let body: Vec<String> = (lo..hi)
        .map(|i| format!("{:5}| {}", i + 1, lines[i]))
        .collect();
    Some((body.join("\n"), lo + 1))
}

/// Ported from `_neighbor_context`: `""` if `neighbor_context_lines <= 0`
/// (the config opt-out) or no qualifying neighbor is found; otherwise a
/// `"=== NEIGHBOR CONTEXT ... ==="`-headed block of up to
/// `neighbor_context_max` caller/callee excerpts.
pub fn neighbor_context(
    chunk: &Chunk,
    ctx: &ContextPackage,
    repo_root: &Path,
    neighbor_context_lines: i64,
    neighbor_context_max: usize,
) -> String {
    if neighbor_context_lines <= 0 {
        return String::new();
    }
    let n_lines = neighbor_context_lines as usize;

    let chunk_files: BTreeSet<&str> = chunk.files.iter().map(String::as_str).collect();
    let fwd = &ctx.call_graph;
    let rev = reverse_call_graph(fwd);
    let def_line = def_line_map(&ctx.call_graph_files);
    // AST def-start lines, keyed by full qnode — the PREFERRED anchor
    // source (`s4_deepdive.py:1288-1294`, consumed at `:1324` as
    // `qn_line.get(neighbor_qn) or def_line.get((nfile, nname), 0)`).
    // This half was never ported, so every neighbor excerpt fell back to
    // `call_graph_files`' bare-name def-site map, which cannot tell two
    // same-named functions in one file apart and is regex-derived rather
    // than parsed. With no anchor at all, `excerpt` re-scans the file for
    // the function's name in text — the very heuristic `def_spans` exists
    // to replace.
    let qn_line: BTreeMap<&str, i64> = ctx
        .def_spans
        .iter()
        .map(|(qn, (start, _))| (qn.as_str(), *start))
        .collect();

    // The Python original also `.update()`s a second, strictly narrower
    // comprehension here — same "file is in this chunk" condition ANDed
    // with an extra focus-entry-point check. Every element that second
    // comprehension could add already satisfies the first (weaker)
    // condition, making it a no-op given how `in_chunk_qns` is built; it
    // is not ported.
    let in_chunk_qns: BTreeSet<String> = fwd
        .keys()
        .chain(rev.keys())
        .filter(|qn| chunk_files.contains(q_file(qn).as_str()))
        .cloned()
        .collect();

    let mut want: Vec<(&'static str, String, String)> = Vec::new();
    for qn in &in_chunk_qns {
        if let Some(callers) = rev.get(qn) {
            for caller in callers {
                if !chunk_files.contains(q_file(caller).as_str()) {
                    want.push(("CALLS", caller.clone(), qn.clone()));
                }
            }
        }
        if let Some(callees) = fwd.get(qn) {
            for callee in callees {
                if !chunk_files.contains(q_file(callee).as_str()) {
                    want.push(("CALLED BY", callee.clone(), qn.clone()));
                }
            }
        }
    }

    let mut seen: BTreeSet<(String, usize)> = BTreeSet::new();
    let mut parts: Vec<String> = Vec::new();
    for (relation, neighbor_qn, anchor_qn) in &want {
        if parts.len() >= neighbor_context_max {
            break;
        }
        let nfile = q_file(neighbor_qn);
        let nname = q_name(neighbor_qn);
        // Python's guard is `if not nfile or nfile in chunk_files: continue`
        // — the `nfile in chunk_files` half can never be true here (every
        // entry in `want` was already filtered on that same condition
        // above), so only the empty-file half is load-bearing.
        if nfile.is_empty() {
            continue;
        }
        // Python's `or` chain: a `qn_line` hit of 0 is falsy and falls
        // through to the bare-name map, so the filter is not redundant.
        let nline = qn_line
            .get(neighbor_qn.as_str())
            .copied()
            .filter(|&line| line != 0)
            .unwrap_or_else(|| *def_line.get(&(nfile.clone(), nname.clone())).unwrap_or(&0));
        let Some((body, lo)) = excerpt(repo_root, &nfile, &nname, nline, n_lines) else {
            continue;
        };
        if !seen.insert((nfile.clone(), lo)) {
            continue;
        }
        parts.push(format!(
            "-- {nfile}:{lo}  [{nname} {relation} {}] --\n{body}\n",
            q_name(anchor_qn)
        ));
    }

    if parts.is_empty() {
        return String::new();
    }
    format!(
        "\n=== NEIGHBOR CONTEXT (callers/callees OUTSIDE this chunk — read-only, do NOT report findings in these files) ===\n{}",
        parts.join("\n")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunk(files: Vec<&str>) -> Chunk {
        Chunk {
            id: "c1".to_string(),
            size: bc_model::ChunkSize::Medium,
            risk_rank: 1,
            files: files.into_iter().map(String::from).collect(),
            focus_entry_points: Vec::new(),
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

    fn ctx_with(
        call_graph: Vec<(&str, Vec<&str>)>,
        call_graph_files: Vec<(&str, Vec<&str>)>,
    ) -> ContextPackage {
        let mut c = ContextPackage::default();
        for (k, v) in call_graph {
            c.call_graph
                .insert(k.to_string(), v.into_iter().map(String::from).collect());
        }
        for (k, v) in call_graph_files {
            c.call_graph_files
                .insert(k.to_string(), v.into_iter().map(String::from).collect());
        }
        c
    }

    fn write(dir: &Path, rel: &str, contents: &str) {
        std::fs::write(dir.join(rel), contents).unwrap();
    }

    #[test]
    fn an_ast_def_span_is_preferred_over_the_bare_name_def_site_map() {
        // Two same-named `helper`s in one file: `call_graph_files` is
        // keyed by bare name and can only hold one def site, so it points
        // at the FIRST. `def_spans` is keyed by qnode and knows which one
        // the edge actually names. Without the def_spans lookup this
        // excerpt anchored on the wrong function entirely.
        let dir = tempfile::tempdir().unwrap();
        let mut body = String::new();
        for i in 1..=40 {
            body.push_str(&format!("# filler {i}\n"));
        }
        write(
            dir.path(),
            "out.py",
            &format!("def helper():\n    first()\n{body}def helper():\n    second()\n"),
        );
        let mut ctx = ctx_with(
            vec![("in.py::main", vec!["out.py::helper"])],
            vec![("helper", vec!["out.py:1"])],
        );
        // The real definition the edge points at is the second one.
        ctx.def_spans.insert("out.py::helper".to_string(), (43, 44));
        let c = chunk(vec!["in.py"]);
        let out = neighbor_context(&c, &ctx, dir.path(), 3, 20);
        assert!(out.contains("second()"), "{out}");
        assert!(!out.contains("first()"), "{out}");
    }

    #[test]
    fn a_zero_def_span_start_falls_back_to_the_bare_name_def_site() {
        // Python's `qn_line.get(...) or def_line.get(...)`: a stored 0 is
        // falsy and must fall through, not win.
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "out.py",
            "line0\nline1\ndef helper():\n    pass\n",
        );
        let mut ctx = ctx_with(
            vec![("in.py::main", vec!["out.py::helper"])],
            vec![("helper", vec!["out.py:3"])],
        );
        ctx.def_spans.insert("out.py::helper".to_string(), (0, 0));
        let c = chunk(vec!["in.py"]);
        let out = neighbor_context(&c, &ctx, dir.path(), 12, 20);
        assert!(out.contains("def helper():"), "{out}");
    }

    #[test]
    fn def_line_map_treats_a_location_with_no_colon_as_line_zero() {
        let mut cgf: BTreeMap<String, Vec<String>> = BTreeMap::new();
        cgf.insert("helper".to_string(), vec!["out.py".to_string()]);
        let map = def_line_map(&cgf);
        assert_eq!(
            map.get(&("out.py".to_string(), "helper".to_string())),
            Some(&0)
        );
    }

    #[test]
    fn find_anchor_with_an_invalid_hint_and_an_empty_function_name_finds_nothing() {
        assert_eq!(find_anchor(&["some line", "another line"], "", 0), None);
    }

    #[test]
    fn zero_neighbor_context_lines_is_an_immediate_opt_out() {
        let dir = tempfile::tempdir().unwrap();
        let c = chunk(vec!["in.py"]);
        let ctx = ctx_with(vec![("in.py::main", vec!["out.py::helper"])], vec![]);
        assert_eq!(neighbor_context(&c, &ctx, dir.path(), 0, 20), "");
    }

    #[test]
    fn negative_neighbor_context_lines_is_an_immediate_opt_out() {
        let dir = tempfile::tempdir().unwrap();
        let c = chunk(vec!["in.py"]);
        let ctx = ctx_with(vec![], vec![]);
        assert_eq!(neighbor_context(&c, &ctx, dir.path(), -5, 20), "");
    }

    #[test]
    fn no_call_graph_at_all_yields_no_neighbor_context() {
        let dir = tempfile::tempdir().unwrap();
        let c = chunk(vec!["in.py"]);
        let ctx = ctx_with(vec![], vec![]);
        assert_eq!(neighbor_context(&c, &ctx, dir.path(), 12, 20), "");
    }

    #[test]
    fn a_callee_outside_the_chunk_is_included_as_called_by() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "out.py",
            "line0\nline1\ndef helper():\n    pass\n",
        );
        let c = chunk(vec!["in.py"]);
        let ctx = ctx_with(
            vec![("in.py::main", vec!["out.py::helper"])],
            vec![("helper", vec!["out.py:3"])],
        );
        let out = neighbor_context(&c, &ctx, dir.path(), 12, 20);
        assert!(out.contains("NEIGHBOR CONTEXT"));
        assert!(out.contains("[helper CALLED BY main]"));
        assert!(out.contains("out.py:1"));
        assert!(out.contains("def helper():"));
    }

    #[test]
    fn a_caller_outside_the_chunk_is_included_as_calls() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "out.py", "def caller():\n    inner()\n");
        let c = chunk(vec!["in.py"]);
        let ctx = ctx_with(
            vec![("out.py::caller", vec!["in.py::inner"])],
            vec![("caller", vec!["out.py:1"])],
        );
        let out = neighbor_context(&c, &ctx, dir.path(), 12, 20);
        assert!(out.contains("[caller CALLS inner]"));
    }

    #[test]
    fn a_neighbor_in_a_chunk_file_is_never_pulled_in() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "in.py",
            "def main():\n    helper()\ndef helper():\n    pass\n",
        );
        let c = chunk(vec!["in.py"]);
        // Both endpoints of this edge live inside the chunk already.
        let ctx = ctx_with(vec![("in.py::main", vec!["in.py::helper"])], vec![]);
        assert_eq!(neighbor_context(&c, &ctx, dir.path(), 12, 20), "");
    }

    #[test]
    fn a_bare_unqualified_neighbor_name_with_no_file_is_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let c = chunk(vec!["in.py"]);
        // "builtin_fn" has no "::" separator, so q_file(...) == "".
        let ctx = ctx_with(vec![("in.py::main", vec!["builtin_fn"])], vec![]);
        assert_eq!(neighbor_context(&c, &ctx, dir.path(), 12, 20), "");
    }

    #[test]
    fn a_missing_neighbor_file_is_skipped_without_crashing() {
        let dir = tempfile::tempdir().unwrap();
        let c = chunk(vec!["in.py"]);
        let ctx = ctx_with(vec![("in.py::main", vec!["missing.py::helper"])], vec![]);
        assert_eq!(neighbor_context(&c, &ctx, dir.path(), 12, 20), "");
    }

    #[test]
    fn no_def_site_hint_falls_back_to_scanning_for_the_function_name() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "out.py",
            "noise\nnoise\ndef helper():\n    pass\n",
        );
        let c = chunk(vec!["in.py"]);
        // No call_graph_files entry at all -> def_line lookup misses -> 0 ->
        // find_anchor must fall back to scanning for "helper(".
        let ctx = ctx_with(vec![("in.py::main", vec!["out.py::helper"])], vec![]);
        let out = neighbor_context(&c, &ctx, dir.path(), 12, 20);
        assert!(out.contains("def helper():"));
    }

    #[test]
    fn a_function_never_found_by_hint_or_scan_yields_no_excerpt() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "out.py", "nothing relevant here\n");
        let c = chunk(vec!["in.py"]);
        let ctx = ctx_with(vec![("in.py::main", vec!["out.py::helper"])], vec![]);
        assert_eq!(neighbor_context(&c, &ctx, dir.path(), 12, 20), "");
    }

    #[test]
    fn duplicate_excerpts_for_the_same_neighbor_are_deduplicated() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "out.py", "def helper():\n    pass\n");
        let c = chunk(vec!["in.py"]);
        // Two different in-chunk callers share the exact same out-of-chunk
        // callee -> same (file, anchor) excerpt should appear only once.
        let ctx = ctx_with(
            vec![
                ("in.py::main", vec!["out.py::helper"]),
                ("in.py::main2", vec!["out.py::helper"]),
            ],
            vec![("helper", vec!["out.py:1"])],
        );
        let out = neighbor_context(&c, &ctx, dir.path(), 12, 20);
        assert_eq!(out.matches("-- out.py:").count(), 1);
    }

    #[test]
    fn neighbor_context_max_caps_the_number_of_excerpts() {
        let dir = tempfile::tempdir().unwrap();
        let mut fwd = Vec::new();
        for i in 0..5 {
            let file = format!("out{i}.py");
            write(dir.path(), &file, "def helper():\n    pass\n");
            fwd.push((format!("in.py::caller{i}"), vec![format!("{file}::helper")]));
        }
        let c = chunk(vec!["in.py"]);
        let mut ctx = ContextPackage::default();
        for (k, v) in &fwd {
            ctx.call_graph.insert(k.clone(), v.clone());
        }
        let out = neighbor_context(&c, &ctx, dir.path(), 12, 2);
        assert_eq!(out.matches("-- out").count(), 2);
    }
}
