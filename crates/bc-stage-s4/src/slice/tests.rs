//! Tests for `taint_chunk_slice: function`. Fixtures are real files on
//! disk with known line numbers, because the whole contract of a slicer
//! is "which lines came out", and the line numbers in the output headers
//! must be real file positions the model can cite.

use super::*;

use bc_model::{Chunk, ChunkSize, ContextPackage, EntryPoint, EntryPointKind, Sink};

use crate::code_loading::load_chunk_code;
use crate::Step4Config;

fn write(dir: &Path, rel: &str, contents: &str) {
    let path = dir.join(rel);
    std::fs::create_dir_all(path.parent().expect("fixture paths have a parent"))
        .expect("fixture dir is writable");
    std::fs::write(path, contents).expect("fixture file is writable");
}

fn chunk(files: Vec<&str>) -> Chunk {
    Chunk {
        id: "c1".to_string(),
        size: ChunkSize::Medium,
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
    }
}

/// 80 numbered lines, with `handler` defined at 10-14 and `sink` at
/// 60-63 — far enough apart that an 8-line pad plus an 8-line merge gap
/// still leaves them as two separate blocks.
fn app_py() -> String {
    let mut out = String::new();
    for i in 1..=80 {
        match i {
            10 => out.push_str("def handler(req):\n"),
            14 => out.push_str("    return sink(req)\n"),
            60 => out.push_str("def sink(x):\n"),
            63 => out.push_str("    execute(x)\n"),
            _ => out.push_str(&format!("# filler {i}\n")),
        }
    }
    out
}

fn app_repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    write(dir.path(), "app.py", &app_py());
    dir
}

fn ctx_with_spans(spans: &[(&str, i64, i64)]) -> ContextPackage {
    let mut ctx = ContextPackage::default();
    for &(qn, lo, hi) in spans {
        ctx.def_spans.insert(qn.to_string(), (lo, hi));
    }
    ctx
}

fn function_config() -> Step4Config {
    let mut cfg = Step4Config::new("m");
    cfg.taint_chunk_slice = FUNCTION_MODE.to_string();
    cfg
}

// ── merge_ranges ─────────────────────────────────────────────────────────

#[test]
fn merge_ranges_joins_overlapping_and_near_adjacent_runs() {
    // (1,5) and (6,9) are adjacent: 6 <= 5 + 0 + 1 even at gap 0.
    assert_eq!(merge_ranges(vec![(1, 5), (6, 9)], 0), vec![(1, 9)]);
    // A two-line hole closes only once the gap allows it.
    assert_eq!(merge_ranges(vec![(1, 5), (8, 9)], 0), vec![(1, 5), (8, 9)]);
    assert_eq!(merge_ranges(vec![(1, 5), (8, 9)], 2), vec![(1, 9)]);
    // A range wholly inside another does not shorten it.
    assert_eq!(merge_ranges(vec![(1, 20), (3, 4)], 0), vec![(1, 20)]);
    // Input order does not matter.
    assert_eq!(
        merge_ranges(vec![(30, 40), (1, 5)], 0),
        vec![(1, 5), (30, 40)]
    );
    assert!(merge_ranges(Vec::new(), 8).is_empty());
}

// ── split_loc ────────────────────────────────────────────────────────────

#[test]
fn split_loc_matches_pythons_rpartition_plus_isdigit_semantics() {
    assert_eq!(split_loc("a/b.py:12"), Some(("a/b.py", 12)));
    // Last colon wins, so a Windows-ish path keeps its drive letter.
    assert_eq!(split_loc("C:/x.py:3"), Some(("C:/x.py", 3)));
    // `str.isdigit()` rejects a sign; no separator / empty half is not a
    // location at all rather than a location at line 0.
    assert_eq!(split_loc("a.py:-1"), None);
    assert_eq!(split_loc("a.py:x"), None);
    assert_eq!(split_loc("a.py:"), None);
    assert_eq!(split_loc(":12"), None);
    assert_eq!(split_loc("a.py"), None);
}

// ── the taint slice ──────────────────────────────────────────────────────

#[test]
fn a_taint_slice_ships_only_the_path_functions_plus_context() {
    let dir = app_repo();
    let ctx = ctx_with_spans(&[("app.py::handler", 10, 14), ("app.py::sink", 60, 63)]);
    let mut c = chunk(vec!["app.py"]);
    c.path_funcs = vec!["app.py::handler".to_string(), "app.py::sink".to_string()];

    let out = load_taint_slice(&c, &ctx, dir.path());
    // Two blocks, each padded by 8 either side.
    assert!(out.contains("=== app.py [lines 2-22] ==="), "{out}");
    assert!(out.contains("=== app.py [lines 52-71] ==="), "{out}");
    assert!(out.contains("def handler(req):"), "{out}");
    assert!(out.contains("    execute(x)"), "{out}");
    // Line numbers are real file positions, not slice-relative.
    assert!(out.contains("   10| def handler(req):"), "{out}");
    // Nothing before the first pad.
    assert!(!out.contains("# filler 1\n"), "{out}");
}

#[test]
fn overlapping_hops_in_one_file_become_one_contiguous_block() {
    // The reason `_merge_ranges` exists: a 3-hop path through one class
    // must not emit three overlapping copies of the same lines.
    let dir = app_repo();
    let ctx = ctx_with_spans(&[
        ("app.py::a", 10, 12),
        ("app.py::b", 14, 16),
        ("app.py::c", 18, 20),
    ]);
    let mut c = chunk(vec!["app.py"]);
    c.path_funcs = vec![
        "app.py::a".to_string(),
        "app.py::b".to_string(),
        "app.py::c".to_string(),
    ];
    let out = load_taint_slice(&c, &ctx, dir.path());
    assert_eq!(out.matches("=== app.py [lines").count(), 1, "{out}");
    assert!(out.contains("=== app.py [lines 2-28] ==="), "{out}");
}

#[test]
fn a_hop_repeated_on_the_path_contributes_its_span_once() {
    let dir = app_repo();
    let ctx = ctx_with_spans(&[("app.py::handler", 10, 14)]);
    let mut c = chunk(vec!["app.py"]);
    c.path_funcs = vec!["app.py::handler".to_string(); 3];
    let out = load_taint_slice(&c, &ctx, dir.path());
    assert_eq!(out.matches("=== app.py [lines").count(), 1, "{out}");
}

#[test]
fn a_hop_without_an_ast_span_anchors_on_its_call_graph_def_line() {
    let dir = app_repo();
    let mut ctx = ctx_with_spans(&[("app.py::handler", 10, 14)]);
    // `sink` has no span, but S1's def-site scan knows where it starts.
    ctx.call_graph_files.insert(
        "sink".to_string(),
        vec![
            "other.py:5".to_string(),      // wrong file, skipped
            "app.py:notaline".to_string(), // not a location, skipped
            "app.py:60".to_string(),
        ],
    );
    let mut c = chunk(vec!["app.py"]);
    c.path_funcs = vec!["app.py::handler".to_string(), "app.py::sink".to_string()];
    let out = load_taint_slice(&c, &ctx, dir.path());
    // The anchor is a single line padded either side: 52-68.
    assert!(out.contains("=== app.py [lines 52-68] ==="), "{out}");
}

#[test]
fn a_hop_with_neither_a_span_nor_an_anchor_ships_its_whole_file() {
    // The prompt tells the model the slice holds the WHOLE path, so a hop
    // that cannot be located must not simply vanish from it.
    let dir = tempfile::tempdir().expect("tempdir");
    write(dir.path(), "app.py", &app_py());
    write(dir.path(), "opaque.rb", "line one\nline two\n");
    let ctx = ctx_with_spans(&[("app.py::handler", 10, 14)]);
    let mut c = chunk(vec!["app.py", "opaque.rb"]);
    c.path_funcs = vec![
        "app.py::handler".to_string(),
        "opaque.rb::mystery".to_string(),
    ];
    let out = load_taint_slice(&c, &ctx, dir.path());
    assert!(out.contains("=== opaque.rb [lines 1-2] ==="), "{out}");
    assert!(out.contains("line two"), "{out}");
}

#[test]
fn an_empty_whole_file_fallback_emits_no_block_at_all() {
    let dir = tempfile::tempdir().expect("tempdir");
    write(dir.path(), "app.py", &app_py());
    write(dir.path(), "empty.rb", "");
    let ctx = ctx_with_spans(&[("app.py::handler", 10, 14)]);
    let mut c = chunk(vec!["app.py", "empty.rb"]);
    c.path_funcs = vec![
        "app.py::handler".to_string(),
        "empty.rb::mystery".to_string(),
    ];
    let out = load_taint_slice(&c, &ctx, dir.path());
    assert!(!out.contains("empty.rb"), "{out}");
    assert!(out.contains("app.py"), "{out}");
}

#[test]
fn the_sink_line_is_included_even_when_no_hop_encloses_it() {
    // A sink called at module scope has no enclosing def on the path.
    let dir = app_repo();
    let ctx = ctx_with_spans(&[("app.py::handler", 10, 14)]);
    let mut c = chunk(vec!["app.py"]);
    c.path_funcs = vec!["app.py::handler".to_string()];
    c.sink_ref = "app.py:78".to_string();
    let out = load_taint_slice(&c, &ctx, dir.path());
    // Padded past the end of the file, then clamped at line 80.
    assert!(out.contains("=== app.py [lines 70-80] ==="), "{out}");
}

#[test]
fn a_qnode_with_no_file_half_is_skipped() {
    // `q_file("bare")` is "" — a bare name carries no file to slice.
    let dir = app_repo();
    let ctx = ctx_with_spans(&[("app.py::handler", 10, 14)]);
    let mut c = chunk(vec!["app.py"]);
    c.path_funcs = vec!["builtin_open".to_string(), "app.py::handler".to_string()];
    let out = load_taint_slice(&c, &ctx, dir.path());
    assert_eq!(out.matches("=== app.py [lines").count(), 1, "{out}");
}

#[test]
fn files_are_emitted_in_chunk_order_not_alphabetical_order() {
    // S3 orders a taint chunk's files entry -> sink; reading the path in
    // flow order is the point of the confirm/refute prompt.
    let dir = tempfile::tempdir().expect("tempdir");
    write(dir.path(), "zzz_entry.py", "def entry():\n    pass\n");
    write(dir.path(), "aaa_sink.py", "def sink():\n    pass\n");
    let ctx = ctx_with_spans(&[("zzz_entry.py::entry", 1, 2), ("aaa_sink.py::sink", 1, 2)]);
    let mut c = chunk(vec!["zzz_entry.py", "aaa_sink.py"]);
    c.path_funcs = vec![
        "zzz_entry.py::entry".to_string(),
        "aaa_sink.py::sink".to_string(),
    ];
    let out = load_taint_slice(&c, &ctx, dir.path());
    let entry_at = out.find("zzz_entry.py").expect("entry file present");
    let sink_at = out.find("aaa_sink.py").expect("sink file present");
    assert!(entry_at < sink_at, "{out}");
}

#[test]
fn a_chunk_file_with_no_path_hop_in_it_is_left_out_entirely() {
    let dir = tempfile::tempdir().expect("tempdir");
    write(dir.path(), "app.py", &app_py());
    write(dir.path(), "unrelated.py", "print(1)\n");
    let ctx = ctx_with_spans(&[("app.py::handler", 10, 14)]);
    let mut c = chunk(vec!["app.py", "unrelated.py"]);
    c.path_funcs = vec!["app.py::handler".to_string()];
    let out = load_taint_slice(&c, &ctx, dir.path());
    assert!(!out.contains("unrelated.py"), "{out}");
}

#[test]
fn a_missing_or_escaping_path_degrades_to_a_placeholder_not_a_read() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ctx = ctx_with_spans(&[("../outside.py::f", 1, 2), ("gone.py::g", 1, 2)]);
    let mut c = chunk(vec!["../outside.py", "gone.py"]);
    c.path_funcs = vec!["../outside.py::f".to_string(), "gone.py::g".to_string()];
    let out = load_taint_slice(&c, &ctx, dir.path());
    assert!(
        out.contains("=== ../outside.py ===\n[FILE NOT FOUND]"),
        "{out}"
    );
    assert!(out.contains("=== gone.py ===\n[FILE NOT FOUND]"), "{out}");
}

#[test]
fn a_taint_slice_with_no_def_spans_at_all_declines() {
    let dir = app_repo();
    let mut c = chunk(vec!["app.py"]);
    c.path_funcs = vec!["app.py::handler".to_string()];
    assert!(load_taint_slice(&c, &ContextPackage::default(), dir.path()).is_empty());
}

#[test]
fn a_taint_slice_that_resolves_nothing_declines() {
    // Spans exist, but none for this chunk's hops, and no sink ref.
    let dir = app_repo();
    let ctx = ctx_with_spans(&[("elsewhere.py::f", 1, 2)]);
    let mut c = chunk(vec!["app.py"]);
    c.path_funcs = vec!["bare_name".to_string()];
    assert!(load_taint_slice(&c, &ctx, dir.path()).is_empty());
}

#[test]
fn a_slice_whose_only_file_is_missing_from_the_chunk_list_declines() {
    // `by_file` is non-empty (the sink ref resolved) but names a file the
    // chunk does not list, so the emit loop produces nothing.
    let dir = app_repo();
    let ctx = ctx_with_spans(&[("app.py::handler", 10, 14)]);
    let mut c = chunk(vec!["app.py"]);
    c.path_funcs = vec!["other.py::hop".to_string()];
    c.sink_ref = "other.py:5".to_string();
    assert!(load_taint_slice(&c, &ctx, dir.path()).is_empty());
}

#[test]
fn a_slice_redacts_and_truncates_exactly_as_a_whole_file_load_does() {
    let dir = tempfile::tempdir().expect("tempdir");
    let long = "x".repeat(MAX_LINE_CHARS + 100);
    // The over-long line carries no prefix, so the truncation boundary is
    // exactly MAX_LINE_CHARS `x`s rather than that minus an indent.
    write(
        dir.path(),
        "app.py",
        &format!("def f():\n    key = \"AKIAAAAAAAAAAAAAAAAA\"\n{long}\n"),
    );
    let ctx = ctx_with_spans(&[("app.py::f", 1, 3)]);
    let mut c = chunk(vec!["app.py"]);
    c.path_funcs = vec!["app.py::f".to_string()];
    let out = load_taint_slice(&c, &ctx, dir.path());
    assert!(!out.contains("AKIAAAAAAAAAAAAAAAAA"), "{out}");
    assert!(out.contains(&"x".repeat(MAX_LINE_CHARS)));
    assert!(!out.contains(&"x".repeat(MAX_LINE_CHARS + 1)));
}

// ── the graph slice ──────────────────────────────────────────────────────

#[test]
fn a_graph_slice_picks_the_spans_in_this_chunks_files() {
    let dir = app_repo();
    let ctx = ctx_with_spans(&[
        ("app.py::handler", 10, 14),
        ("elsewhere.py::other", 1, 5), // not a chunk file
    ]);
    let c = chunk(vec!["app.py"]);
    let out = load_graph_slice(&c, &ctx, dir.path(), 24);
    assert!(out.contains("=== app.py [lines 4-20] ==="), "{out}");
    assert!(!out.contains("elsewhere.py"), "{out}");
}

#[test]
fn a_graph_slice_ranks_path_hops_and_anchors_above_bare_connectivity() {
    // With a cap of 1, only the top-scoring span survives — and the
    // clipped file is then shipped whole, so assert on the ranking via
    // `graph_scores` directly rather than the (whole-file) output.
    let mut ctx = ctx_with_spans(&[
        ("app.py::hop", 10, 14),
        ("app.py::entry", 16, 18),
        ("app.py::sunk", 20, 24),
        ("app.py::focus", 26, 28),
        ("app.py::called", 60, 63),
    ]);
    ctx.entry_points.push(EntryPoint {
        file: "app.py".to_string(),
        function: "entry".to_string(),
        kind: EntryPointKind::Network,
        reachable_from_unauth: true,
    });
    // An entry point outside the chunk, and one with no function name:
    // both contribute nothing.
    ctx.entry_points.push(EntryPoint {
        file: "other.py".to_string(),
        function: "entry".to_string(),
        kind: EntryPointKind::Cli,
        reachable_from_unauth: false,
    });
    ctx.entry_points.push(EntryPoint {
        file: "app.py".to_string(),
        function: String::new(),
        kind: EntryPointKind::Cli,
        reachable_from_unauth: false,
    });
    ctx.unsafe_sinks.push(Sink {
        file: "app.py".to_string(),
        line: 22,
        function: "sunk".to_string(),
        snippet: String::new(),
        cwe: Vec::new(),
    });
    ctx.call_graph.insert(
        "app.py::hop".to_string(),
        vec!["app.py::called".to_string(), "outside.py::far".to_string()],
    );
    let mut c = chunk(vec!["app.py"]);
    c.path_funcs = vec!["app.py::hop".to_string()];
    c.focus_entry_points = vec!["focus".to_string()];

    let scores = graph_scores(&c, &ctx);
    // 100 (path hop) + 10 (caller in chunk) + 3 (intra-chunk edge).
    assert_eq!(scores["app.py::hop"], 113);
    assert_eq!(scores["app.py::entry"], 50);
    assert_eq!(scores["app.py::sunk"], 45);
    assert_eq!(scores["app.py::focus"], 40);
    // 8 (callee in chunk) + 3 (intra-chunk edge).
    assert_eq!(scores["app.py::called"], 11);
    // A callee outside the chunk scores nothing at all.
    assert!(!scores.contains_key("outside.py::far"));
}

#[test]
fn a_graph_slice_ships_a_file_whole_once_its_functions_exceed_the_cap() {
    let dir = app_repo();
    let ctx = ctx_with_spans(&[
        ("app.py::a", 10, 12),
        ("app.py::b", 30, 32),
        ("app.py::c", 50, 52),
    ]);
    let c = chunk(vec!["app.py"]);
    // Cap of 2 with 3 resolved spans: no code below the cut may be lost,
    // so the file is shipped whole rather than truncated.
    let out = load_graph_slice(&c, &ctx, dir.path(), 2);
    assert!(out.contains("=== app.py [lines 1-80] ==="), "{out}");
    assert_eq!(out.matches("=== app.py [lines").count(), 1, "{out}");
}

#[test]
fn a_chunk_file_the_graph_resolved_nothing_for_is_shipped_whole() {
    let dir = tempfile::tempdir().expect("tempdir");
    write(dir.path(), "app.py", &app_py());
    write(dir.path(), "plain.py", "one\ntwo\nthree\n");
    let ctx = ctx_with_spans(&[("app.py::handler", 10, 14)]);
    let c = chunk(vec!["app.py", "plain.py"]);
    let out = load_graph_slice(&c, &ctx, dir.path(), 24);
    assert!(out.contains("=== plain.py [lines 1-3] ==="), "{out}");
    assert!(out.contains("=== app.py [lines 4-20] ==="), "{out}");
}

#[test]
fn a_graph_slice_anchors_a_focus_function_that_has_no_ast_span() {
    // The tier that makes specialist shards sliceable: they carry focus
    // names but often no retained def_span.
    let dir = app_repo();
    let mut ctx = ctx_with_spans(&[("app.py::handler", 10, 14)]);
    ctx.call_graph_files.insert(
        "encrypt".to_string(),
        vec![
            "app.py:60".to_string(),
            "malformed".to_string(),  // no separator
            "other.py:5".to_string(), // outside the chunk
        ],
    );
    let mut c = chunk(vec!["app.py"]);
    c.focus_entry_points = vec!["encrypt".to_string()];
    let out = load_graph_slice(&c, &ctx, dir.path(), 24);
    // Two blocks: handler at 10±6 and the 60±6 anchor stay far apart.
    assert!(out.contains("=== app.py [lines 4-20] ==="), "{out}");
    assert!(out.contains("=== app.py [lines 54-66] ==="), "{out}");
}

#[test]
fn a_graph_slice_includes_the_chunks_own_sink_ref_line() {
    let dir = app_repo();
    let ctx = ctx_with_spans(&[("app.py::handler", 10, 14)]);
    let mut c = chunk(vec!["app.py"]);
    c.sink_ref = "app.py:70".to_string();
    let out = load_graph_slice(&c, &ctx, dir.path(), 24);
    assert!(out.contains("=== app.py [lines 64-76] ==="), "{out}");
    // A sink ref naming a file outside the chunk contributes nothing.
    c.sink_ref = "other.py:70".to_string();
    let out = load_graph_slice(&c, &ctx, dir.path(), 24);
    assert!(!out.contains("[lines 64-76]"), "{out}");
}

#[test]
fn a_graph_slice_skips_a_degenerate_span() {
    let dir = app_repo();
    let ctx = ctx_with_spans(&[
        ("app.py::zero", 0, 5),       // lo <= 0
        ("app.py::inverted", 40, 40), // hi <= lo
        ("app.py::good", 10, 14),
    ]);
    let c = chunk(vec!["app.py"]);
    let out = load_graph_slice(&c, &ctx, dir.path(), 24);
    assert_eq!(out.matches("=== app.py [lines").count(), 1, "{out}");
    assert!(out.contains("=== app.py [lines 4-20] ==="), "{out}");
}

#[test]
fn a_graph_slice_with_nothing_resolved_declines() {
    let dir = app_repo();
    let c = chunk(vec!["app.py"]);
    assert!(load_graph_slice(&c, &ContextPackage::default(), dir.path(), 24).is_empty());
}

#[test]
fn a_graph_slice_whose_only_resolved_file_is_not_a_chunk_file_declines() {
    // `by_file` is non-empty but the emit loop, which walks `chunk.files`,
    // reaches nothing — a distinct exit from the one above.
    let dir = app_repo();
    let mut ctx = ContextPackage::default();
    ctx.call_graph_files
        .insert("encrypt".to_string(), vec!["app.py:34".to_string()]);
    let mut c = chunk(vec![]);
    c.focus_entry_points = vec!["encrypt".to_string()];
    // Chunk lists no files at all, so nothing can be emitted.
    assert!(load_graph_slice(&c, &ctx, dir.path(), 24).is_empty());
}

// ── dispatch through load_chunk_code ─────────────────────────────────────

#[test]
fn file_mode_never_slices() {
    let dir = app_repo();
    let ctx = ctx_with_spans(&[("app.py::handler", 10, 14)]);
    let mut c = chunk(vec!["app.py"]);
    c.path_funcs = vec!["app.py::handler".to_string()];
    let (out, sliced) = load_chunk_code(&c, &ctx, dir.path(), &Step4Config::new("m"));
    assert!(!sliced);
    assert!(out.contains("=== app.py ===\n"), "{out}");
    assert!(out.contains("# filler 1\n"), "whole file expected: {out}");
}

#[test]
fn function_mode_takes_the_taint_tier_for_a_chunk_with_a_path() {
    let dir = app_repo();
    let ctx = ctx_with_spans(&[("app.py::handler", 10, 14)]);
    let mut c = chunk(vec!["app.py"]);
    c.path_funcs = vec!["app.py::handler".to_string()];
    let (out, sliced) = load_chunk_code(&c, &ctx, dir.path(), &function_config());
    assert!(sliced);
    // TAINT_PAD (8), not GRAPH_PAD (6) — this came from the taint tier.
    assert!(out.contains("=== app.py [lines 2-22] ==="), "{out}");
}

#[test]
fn function_mode_falls_through_to_the_graph_tier_for_a_chunk_without_a_path() {
    let dir = app_repo();
    let ctx = ctx_with_spans(&[("app.py::handler", 10, 14)]);
    let c = chunk(vec!["app.py"]);
    let (out, sliced) = load_chunk_code(&c, &ctx, dir.path(), &function_config());
    assert!(sliced);
    // GRAPH_PAD (6).
    assert!(out.contains("=== app.py [lines 4-20] ==="), "{out}");
}

#[test]
fn function_mode_falls_back_to_whole_file_loading_when_no_span_resolves() {
    // The "missing tree-sitter install" case: slicing silently no-ops
    // into the loader that was there before, never dropping code.
    let dir = app_repo();
    let mut c = chunk(vec!["app.py"]);
    c.path_funcs = vec!["app.py::handler".to_string()];
    let (out, sliced) = load_chunk_code(
        &c,
        &ContextPackage::default(),
        dir.path(),
        &function_config(),
    );
    assert!(!sliced);
    assert!(out.contains("=== app.py ===\n"), "{out}");
    assert!(out.contains("# filler 1\n"), "{out}");
}

#[test]
fn function_mode_falls_back_to_the_sliding_window_for_a_large_chunk() {
    let dir = tempfile::tempdir().expect("tempdir");
    write(dir.path(), "big.py", &"pass\n".repeat(1000));
    let mut c = chunk(vec!["big.py"]);
    c.size = ChunkSize::Large;
    let (out, sliced) = load_chunk_code(
        &c,
        &ContextPackage::default(),
        dir.path(),
        &function_config(),
    );
    assert!(!sliced);
    assert!(out.contains("[lines 1-600]"), "{out}");
}

#[test]
fn the_mode_string_is_matched_case_insensitively() {
    let dir = app_repo();
    let ctx = ctx_with_spans(&[("app.py::handler", 10, 14)]);
    let c = chunk(vec!["app.py"]);
    let mut cfg = Step4Config::new("m");
    cfg.taint_chunk_slice = "FUNCTION".to_string();
    let (_, sliced) = load_chunk_code(&c, &ctx, dir.path(), &cfg);
    assert!(sliced);
    // Anything else is "file", including a typo — fail safe, not closed.
    cfg.taint_chunk_slice = "functionn".to_string();
    let (_, sliced) = load_chunk_code(&c, &ctx, dir.path(), &cfg);
    assert!(!sliced);
}

#[test]
fn asking_for_function_mode_without_def_spans_warns_once() {
    // Exercises the warn-once guard; the flag is process-global, so this
    // asserts the call is harmless and idempotent rather than on output.
    let ctx = ContextPackage::default();
    warn_if_no_def_spans(&ctx);
    warn_if_no_def_spans(&ctx);
    // A context that HAS spans returns before touching the flag.
    warn_if_no_def_spans(&ctx_with_spans(&[("a.py::f", 1, 2)]));
}

#[test]
fn a_span_pointing_past_the_end_of_its_file_emits_nothing_and_declines() {
    // `def_spans` describe the tree as S0/S1 saw it; a file that has since
    // shrunk (or a resumed checkpoint from an older commit) can carry a
    // span past its current end. Clamping the range then leaves `lo > hi`,
    // which must skip the block rather than index past the line vector —
    // and with nothing left to emit, the slice declines and the chunk
    // falls back to whole-file loading.
    let dir = tempfile::tempdir().expect("tempdir");
    write(dir.path(), "shrunk.py", "one\ntwo\nthree\n");
    let ctx = ctx_with_spans(&[("shrunk.py::gone", 200, 240)]);
    let c = chunk(vec!["shrunk.py"]);
    assert!(load_graph_slice(&c, &ctx, dir.path(), 24).is_empty());

    // Same story through the taint tier, and through the dispatcher: the
    // chunk still gets its code, just not sliced.
    let mut c = chunk(vec!["shrunk.py"]);
    c.path_funcs = vec!["shrunk.py::gone".to_string()];
    assert!(load_taint_slice(&c, &ctx, dir.path()).is_empty());
    let (out, sliced) = load_chunk_code(&c, &ctx, dir.path(), &function_config());
    assert!(!sliced);
    assert!(out.contains("=== shrunk.py ===\n    1| one"), "{out}");
}
