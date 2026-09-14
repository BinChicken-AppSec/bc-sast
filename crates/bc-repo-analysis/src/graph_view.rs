//! Shared post-S2 call-graph consumers, ported from
//! `vvaharness/pipeline/callgraph_consumer.py`. Deterministic, read-only
//! helpers consuming the SQLite-hydrated call graph already attached to
//! `ContextPackage`, so S3/S5/S6/S7/S8 don't each re-derive their own
//! reachability logic.
//!
//! Graph resolution is call-graph-first: the call graph is authoritative
//! for reachability/function membership, and `def_spans` (an AST-derived
//! artifact) is corroborating evidence that pins a tighter location. See
//! [`qnodes_at`].
//!
//! **Deliberately not ported** (confirmed zero callers anywhere in
//! `vvaharness/pipeline/stages/` or its tests, not just at the time of
//! writing but re-verified for this port): `seed_evidence_reachable_files`,
//! `seed_evidence_by_file`, `best_source_from_evidence` (the
//! `seed_taint_evidence`-flavored siblings of [`seed_reachable_files`]/
//! [`seed_paths_by_file`]/[`best_source_from_seed`] — nothing in the
//! pipeline calls them; `ctx.seed_taint_evidence` itself is read directly
//! elsewhere, just not through these helpers), `cfgs_for_function`,
//! `reflection_facts_for_function`, `reflection_facts_by_file`,
//! `condition_edges_in_evidence`, `reflection_edges_in_evidence`,
//! `framework_markers_for_function`, `route_facts_for_file`,
//! `response_dataflows_for_function` (all operate on `FileIndex`/CFG
//! producer-side data that no stage ever populates or consumes today).
//!
//! **Deliberate simplification**: Python's `graph_view(ctx)` factory
//! memoizes one [`GraphView`] per `ContextPackage` via an `id(ctx)`-keyed
//! cache validated by a `weakref` (working around `ContextPackage` being
//! an unhashable pydantic model with no attribute injection). This port
//! has no such constraint — a stage's `run()` builds one `GraphView` up
//! front with [`GraphView::new`] and passes `&view` down to every
//! per-finding/per-chunk call, which achieves the same "built once per
//! run, not once per finding" property through ordinary ownership instead
//! of a global cache table.

use std::collections::{BTreeMap, HashMap, HashSet};

use bc_model::ContextPackage;

use crate::callgraph::q_file;

/// `"file:line"` -> `(file, Some(line))`; anything else -> `(hop, None)`.
/// Ported from `parse_hop`.
pub fn parse_hop(hop: &str) -> (String, Option<i64>) {
    if let Some((file_part, line_part)) = hop.rsplit_once(':') {
        if !file_part.is_empty()
            && !line_part.is_empty()
            && line_part.chars().all(|c| c.is_ascii_digit())
        {
            let line: i64 = line_part.parse().unwrap_or(1).max(1);
            return (file_part.to_string(), Some(line));
        }
    }
    (hop.to_string(), None)
}

/// Files proven by seed taint paths (widen-only reachability). Ported
/// from `seed_reachable_files`.
pub fn seed_reachable_files(seed_taint_paths: &[Vec<String>]) -> HashSet<String> {
    let mut out = HashSet::new();
    for path in seed_taint_paths {
        for hop in path {
            if hop.is_empty() {
                continue;
            }
            let (f, _) = parse_hop(hop);
            if !f.is_empty() {
                out.insert(f);
            }
        }
    }
    out
}

/// Index seed taint paths by every file they touch. Ported from
/// `seed_paths_by_file`.
pub fn seed_paths_by_file(seed_taint_paths: &[Vec<String>]) -> BTreeMap<String, Vec<Vec<String>>> {
    let mut out: BTreeMap<String, Vec<Vec<String>>> = BTreeMap::new();
    for path in seed_taint_paths {
        let mut touched: Vec<String> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        for hop in path {
            let (f, _) = parse_hop(hop);
            if !f.is_empty() && seen.insert(f.clone()) {
                touched.push(f);
            }
        }
        for f in touched {
            out.entry(f).or_default().push(path.clone());
        }
    }
    out
}

/// First source hop from a set of seed paths touching a file. Ported from
/// `best_source_from_seed`.
pub fn best_source_from_seed(paths: &[Vec<String>]) -> Option<String> {
    for path in paths {
        let Some(src) = path.first() else { continue };
        let (sf, sl) = parse_hop(src);
        if !sf.is_empty() {
            if let Some(line) = sl {
                return Some(format!("{sf}:{line}"));
            }
        }
        if !src.is_empty() {
            return Some(src.clone());
        }
    }
    None
}

/// Best-effort entry-point def-site anchors by file. Sources, in order:
/// 1) `call_graph_files[entry.function]` entries matching `entry.file`;
/// 2) `def_spans` qnodes matching `entry.file::entry.function`;
/// 3) fallback line 1 in `entry.file`.
///
/// Ported from `entry_anchor_lines`.
pub fn entry_anchor_lines(ctx: &ContextPackage) -> BTreeMap<String, Vec<i64>> {
    let mut by_file: BTreeMap<String, HashSet<i64>> = BTreeMap::new();
    for ep in &ctx.entry_points {
        let mut matched = false;
        if let Some(sites) = ctx.call_graph_files.get(&ep.function) {
            for site in sites {
                if let Some((sf, sl)) = site.rsplit_once(':') {
                    if sf == ep.file && !sl.is_empty() && sl.chars().all(|c| c.is_ascii_digit()) {
                        let line: i64 = sl.parse().unwrap_or(1).max(1);
                        by_file.entry(ep.file.clone()).or_default().insert(line);
                        matched = true;
                    }
                }
            }
        }
        if !matched {
            for (qn, span) in &ctx.def_spans {
                let (qf, qname) = q_file_name(qn);
                if qf == ep.file && qname == ep.function {
                    by_file
                        .entry(ep.file.clone())
                        .or_default()
                        .insert(span.0.max(1));
                    matched = true;
                    break;
                }
            }
        }
        if !matched && !ep.file.is_empty() {
            by_file.entry(ep.file.clone()).or_default().insert(1);
        }
    }
    by_file
        .into_iter()
        .map(|(f, lines)| {
            let mut lines: Vec<i64> = lines.into_iter().collect();
            lines.sort_unstable();
            (f, lines)
        })
        .collect()
}

fn q_file_name(qn: &str) -> (&str, &str) {
    match qn.rfind("::") {
        Some(idx) => (&qn[..idx], &qn[idx + 2..]),
        None => ("", qn),
    }
}

/// `file -> [(lo, hi, qnode)]` sorted by `lo`. Only well-formed spans are
/// indexed; malformed entries are skipped. Ported from `build_span_index`
/// — internal to [`GraphView::new`], no direct caller in the Python
/// original either.
fn build_span_index(ctx: &ContextPackage) -> HashMap<String, Vec<(i64, i64, String)>> {
    let mut index: HashMap<String, Vec<(i64, i64, String)>> = HashMap::new();
    for (qn, (lo, hi)) in &ctx.def_spans {
        let f = q_file(qn);
        if f.is_empty() {
            continue;
        }
        let hi = (*hi).max(*lo);
        index.entry(f).or_default().push((*lo, hi, qn.clone()));
    }
    for v in index.values_mut() {
        v.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)).then(a.2.cmp(&b.2)));
    }
    index
}

/// `file -> ordered unique list of every qnode the call graph places in
/// it` — the authoritative function-membership set per file. Ported from
/// `graph_qnodes_by_file` — internal to [`GraphView::new`].
fn graph_qnodes_by_file(ctx: &ContextPackage) -> HashMap<String, Vec<String>> {
    let mut out: HashMap<String, Vec<String>> = HashMap::new();
    let mut seen: HashMap<String, HashSet<String>> = HashMap::new();
    for (caller, callees) in &ctx.call_graph {
        for qn in std::iter::once(caller).chain(callees.iter()) {
            let f = q_file(qn);
            if f.is_empty() {
                continue;
            }
            if seen.entry(f.clone()).or_default().insert(qn.clone()) {
                out.entry(f).or_default().push(qn.clone());
            }
        }
    }
    out
}

/// `callee -> [callers]` (insertion-ordered, deduped). Ported from
/// `reverse_edges` — internal to [`GraphView::new`].
fn reverse_edges(ctx: &ContextPackage) -> HashMap<String, Vec<String>> {
    let mut rev: HashMap<String, Vec<String>> = HashMap::new();
    let mut seen: HashMap<String, HashSet<String>> = HashMap::new();
    for (caller, callees) in &ctx.call_graph {
        for callee in callees {
            if seen
                .entry(callee.clone())
                .or_default()
                .insert(caller.clone())
            {
                rev.entry(callee.clone()).or_default().push(caller.clone());
            }
        }
    }
    rev
}

/// Memoized-per-run bundle of the shared graph indices: the span index,
/// call-graph file membership, forward edges, and reverse edges, so a
/// stage builds each exactly once per run rather than per finding/sink/
/// chunk. Ported from `GraphView` (see the module docs for why this port
/// has no `graph_view(ctx)` cache-factory equivalent — callers build one
/// `GraphView` and share it by reference instead).
pub struct GraphView {
    pub forward: BTreeMap<String, Vec<String>>,
    span_index: HashMap<String, Vec<(i64, i64, String)>>,
    file_qnodes: HashMap<String, Vec<String>>,
    pub rev: HashMap<String, Vec<String>>,
}

impl GraphView {
    pub fn new(ctx: &ContextPackage) -> Self {
        GraphView {
            forward: ctx.call_graph.clone(),
            span_index: build_span_index(ctx),
            file_qnodes: graph_qnodes_by_file(ctx),
            rev: reverse_edges(ctx),
        }
    }
}

/// Qnodes covering `[line_start, line_end]` in `file`. Resolution order
/// (call-graph-first, spans as corroborating evidence):
/// 1. spans that overlap the line window (tightest, code-corroborated);
/// 2. otherwise the call graph's file membership (the authoritative
///    reachability set for the file);
/// 3. otherwise, only when `nearest_if_empty` is set, the nearest span in
///    the file (single-anchor lookup, used by S3).
///
/// Ported from `qnodes_at`.
pub fn qnodes_at(
    view: &GraphView,
    file: &str,
    line_start: i64,
    line_end: i64,
    limit: usize,
    nearest_if_empty: bool,
) -> Vec<String> {
    let file = file.replace('\\', "/");
    let start = line_start.max(1);
    let end = line_end.max(start);

    let mut exact: Vec<&String> = Vec::new();
    let mut nearby: Vec<(i64, &String)> = Vec::new();
    if let Some(spans) = view.span_index.get(&file) {
        for (lo, hi, qn) in spans {
            if *lo <= end && *hi >= start {
                exact.push(qn);
            } else {
                nearby.push(((start - hi).abs().min((end - lo).abs()), qn));
            }
        }
    }
    if !exact.is_empty() {
        return dedup_preserve_order(&exact)
            .into_iter()
            .take(limit)
            .collect();
    }

    if let Some(cg) = view.file_qnodes.get(&file) {
        if !cg.is_empty() {
            return dedup_preserve_order(&cg.iter().collect::<Vec<_>>())
                .into_iter()
                .take(limit)
                .collect();
        }
    }

    if nearest_if_empty && !nearby.is_empty() {
        nearby.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(b.1)));
        return vec![nearby[0].1.clone()];
    }
    Vec::new()
}

fn dedup_preserve_order(items: &[&String]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for item in items {
        if seen.insert((*item).clone()) {
            out.push((*item).clone());
        }
    }
    out
}

pub struct Neighbors {
    pub callers: Vec<String>,
    pub callees: Vec<String>,
}

/// Shared callers/callees view for S6/S7/S8. Ported from `neighborhood`.
pub fn neighborhood(
    view: &GraphView,
    qnodes: &[String],
    max_edges: usize,
) -> BTreeMap<String, Neighbors> {
    let mut around = BTreeMap::new();
    for qn in qnodes {
        let callers = view
            .rev
            .get(qn)
            .map(|v| v.iter().take(max_edges).cloned().collect())
            .unwrap_or_default();
        let callees = view
            .forward
            .get(qn)
            .map(|v| v.iter().take(max_edges).cloned().collect())
            .unwrap_or_default();
        around.insert(qn.clone(), Neighbors { callers, callees });
    }
    around
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_model::{EntryPoint, EntryPointKind};

    fn ep(file: &str, function: &str) -> EntryPoint {
        EntryPoint {
            file: file.into(),
            function: function.into(),
            kind: EntryPointKind::Other,
            reachable_from_unauth: false,
        }
    }

    fn ctx_with(
        call_graph: &[(&str, &[&str])],
        call_graph_files: &[(&str, &[&str])],
        entry_points: Vec<EntryPoint>,
        def_spans: &[(&str, (i64, i64))],
    ) -> ContextPackage {
        ContextPackage {
            call_graph: call_graph
                .iter()
                .map(|(k, vs)| (k.to_string(), vs.iter().map(|s| s.to_string()).collect()))
                .collect(),
            call_graph_files: call_graph_files
                .iter()
                .map(|(k, vs)| (k.to_string(), vs.iter().map(|s| s.to_string()).collect()))
                .collect(),
            entry_points,
            def_spans: def_spans.iter().map(|(k, v)| (k.to_string(), *v)).collect(),
            ..Default::default()
        }
    }

    // ── parse_hop ──────────────────────────────────────────────────────

    #[test]
    fn parse_hop_file_colon_line_parses_both() {
        assert_eq!(parse_hop("a.py:42"), ("a.py".to_string(), Some(42)));
    }

    #[test]
    fn parse_hop_zero_line_clamps_up_to_one() {
        assert_eq!(parse_hop("a.py:0"), ("a.py".to_string(), Some(1)));
    }

    #[test]
    fn parse_hop_non_digit_suffix_is_unparsed() {
        assert_eq!(
            parse_hop("a.py:notaline"),
            ("a.py:notaline".to_string(), None)
        );
    }

    #[test]
    fn parse_hop_no_colon_is_unparsed() {
        assert_eq!(parse_hop("bare"), ("bare".to_string(), None));
    }

    #[test]
    fn parse_hop_empty_string_is_unparsed() {
        assert_eq!(parse_hop(""), (String::new(), None));
    }

    #[test]
    fn parse_hop_uses_the_last_colon_for_multi_colon_hops() {
        assert_eq!(parse_hop("a:b.py:7"), ("a:b.py".to_string(), Some(7)));
    }

    #[test]
    fn parse_hop_trailing_colon_with_empty_tail_is_unparsed() {
        assert_eq!(parse_hop("a.py:"), ("a.py:".to_string(), None));
    }

    // ── seed_reachable_files ──────────────────────────────────────────

    #[test]
    fn seed_reachable_files_of_empty_input_is_empty() {
        assert!(seed_reachable_files(&[]).is_empty());
    }

    #[test]
    fn seed_reachable_files_unions_files_across_paths_and_skips_empty_hops() {
        let paths = vec![
            vec!["a.py:1".to_string(), "".to_string(), "b.py:2".to_string()],
            vec!["b.py:3".to_string(), "c.py:4".to_string()],
        ];
        let out = seed_reachable_files(&paths);
        assert_eq!(
            out,
            HashSet::from(["a.py".to_string(), "b.py".to_string(), "c.py".to_string()])
        );
    }

    // ── seed_paths_by_file ──────────────────────────────────────────

    #[test]
    fn seed_paths_by_file_indexes_each_touched_file_once_per_path() {
        let path = vec![
            "a.py:1".to_string(),
            "a.py:5".to_string(),
            "b.py:2".to_string(),
        ];
        let out = seed_paths_by_file(std::slice::from_ref(&path));
        assert_eq!(out.get("a.py"), Some(&vec![path.clone()]));
        assert_eq!(out.get("b.py"), Some(&vec![path]));
    }

    #[test]
    fn seed_paths_by_file_of_empty_input_is_empty() {
        assert!(seed_paths_by_file(&[]).is_empty());
    }

    // ── best_source_from_seed ──────────────────────────────────────────

    #[test]
    fn best_source_from_seed_of_no_paths_is_none() {
        assert_eq!(best_source_from_seed(&[]), None);
    }

    #[test]
    fn best_source_from_seed_formats_a_parseable_first_hop() {
        let paths = vec![vec!["a.py:9".to_string()]];
        assert_eq!(best_source_from_seed(&paths), Some("a.py:9".to_string()));
    }

    #[test]
    fn best_source_from_seed_returns_the_raw_hop_when_unparseable() {
        let paths = vec![vec!["not-a-hop".to_string()]];
        assert_eq!(best_source_from_seed(&paths), Some("not-a-hop".to_string()));
    }

    #[test]
    fn best_source_from_seed_skips_an_empty_leading_path_then_an_empty_hop() {
        let paths = vec![vec![], vec!["".to_string()], vec!["a.py:1".to_string()]];
        assert_eq!(best_source_from_seed(&paths), Some("a.py:1".to_string()));
    }

    // ── entry_anchor_lines ──────────────────────────────────────────

    #[test]
    fn entry_anchor_lines_tier1_call_graph_files_match() {
        let ctx = ctx_with(
            &[],
            &[("handler", &["a.py:10", "a.py:20", "b.py:5"])],
            vec![ep("a.py", "handler")],
            &[],
        );
        let out = entry_anchor_lines(&ctx);
        assert_eq!(out.get("a.py"), Some(&vec![10, 20]));
        assert!(!out.contains_key("b.py"));
    }

    #[test]
    fn entry_anchor_lines_tier2_def_spans_fallback_when_call_graph_files_has_no_match() {
        let ctx = ctx_with(
            &[],
            &[("handler", &["other.py:10"])],
            vec![ep("a.py", "handler")],
            &[("a.py::handler", (7, 12))],
        );
        let out = entry_anchor_lines(&ctx);
        assert_eq!(out.get("a.py"), Some(&vec![7]));
    }

    #[test]
    fn entry_anchor_lines_tier3_falls_back_to_line_one() {
        let ctx = ctx_with(&[], &[], vec![ep("a.py", "handler")], &[]);
        let out = entry_anchor_lines(&ctx);
        assert_eq!(out.get("a.py"), Some(&vec![1]));
    }

    #[test]
    fn entry_anchor_lines_skips_the_fallback_when_entry_file_is_empty() {
        let ctx = ctx_with(&[], &[], vec![ep("", "handler")], &[]);
        assert!(entry_anchor_lines(&ctx).is_empty());
    }

    #[test]
    fn entry_anchor_lines_call_graph_files_site_without_a_colon_is_ignored() {
        let ctx = ctx_with(
            &[],
            &[("handler", &["nocolonsite"])],
            vec![ep("a.py", "handler")],
            &[],
        );
        let out = entry_anchor_lines(&ctx);
        assert_eq!(out.get("a.py"), Some(&vec![1]));
    }

    #[test]
    fn entry_anchor_lines_call_graph_files_site_with_a_non_digit_line_suffix_is_ignored() {
        let ctx = ctx_with(
            &[],
            &[("handler", &["a.py:notaline"])],
            vec![ep("a.py", "handler")],
            &[],
        );
        let out = entry_anchor_lines(&ctx);
        // Falls through to tier 3 (no span either) since the site never matches.
        assert_eq!(out.get("a.py"), Some(&vec![1]));
    }

    #[test]
    fn entry_anchor_lines_def_spans_with_a_bare_unqualified_key_never_matches() {
        let ctx = ctx_with(
            &[],
            &[],
            vec![ep("a.py", "handler")],
            &[("bare_key", (7, 12))],
        );
        let out = entry_anchor_lines(&ctx);
        // q_file_name("bare_key") has no "::" so it can never equal
        // ("a.py", "handler") — falls through to the tier-3 fallback.
        assert_eq!(out.get("a.py"), Some(&vec![1]));
    }

    #[test]
    fn entry_anchor_lines_dedupes_and_sorts_lines_across_entry_points_in_the_same_file() {
        let ctx = ctx_with(
            &[],
            &[("h1", &["a.py:20"]), ("h2", &["a.py:5"])],
            vec![ep("a.py", "h1"), ep("a.py", "h2")],
            &[],
        );
        let out = entry_anchor_lines(&ctx);
        assert_eq!(out.get("a.py"), Some(&vec![5, 20]));
    }

    // ── build_span_index / graph_qnodes_by_file / reverse_edges (internal) ──

    #[test]
    fn build_span_index_sorts_by_lo_and_clamps_hi_to_lo() {
        let ctx = ctx_with(
            &[],
            &[],
            vec![],
            &[("a.py::z", (20, 5)), ("a.py::a", (1, 3))],
        );
        let idx = build_span_index(&ctx);
        assert_eq!(
            idx.get("a.py"),
            Some(&vec![
                (1, 3, "a.py::a".to_string()),
                (20, 20, "a.py::z".to_string())
            ])
        );
    }

    #[test]
    fn build_span_index_skips_a_qnode_with_no_file_prefix() {
        let ctx = ctx_with(&[], &[], vec![], &[("bare", (1, 2))]);
        assert!(build_span_index(&ctx).is_empty());
    }

    #[test]
    fn graph_qnodes_by_file_collects_unique_caller_and_callee_qnodes_per_file() {
        let ctx = ctx_with(&[("a.py::f", &["a.py::g", "b.py::h"])], &[], vec![], &[]);
        let out = graph_qnodes_by_file(&ctx);
        assert_eq!(
            out.get("a.py"),
            Some(&vec!["a.py::f".to_string(), "a.py::g".to_string()])
        );
        assert_eq!(out.get("b.py"), Some(&vec!["b.py::h".to_string()]));
    }

    #[test]
    fn reverse_edges_maps_callee_to_deduped_callers() {
        let ctx = ctx_with(
            &[("a::f", &["c::sink"]), ("b::g", &["c::sink", "c::sink"])],
            &[],
            vec![],
            &[],
        );
        let rev = reverse_edges(&ctx);
        let mut callers = rev.get("c::sink").cloned().unwrap_or_default();
        callers.sort();
        assert_eq!(callers, vec!["a::f".to_string(), "b::g".to_string()]);
    }

    // ── GraphView::new ──────────────────────────────────────────

    #[test]
    fn graph_view_new_builds_every_index_from_ctx() {
        let ctx = ctx_with(
            &[("a.py::f", &["a.py::g"])],
            &[],
            vec![],
            &[("a.py::f", (1, 5))],
        );
        let view = GraphView::new(&ctx);
        assert_eq!(
            view.forward.get("a.py::f"),
            Some(&vec!["a.py::g".to_string()])
        );
        assert_eq!(view.rev.get("a.py::g"), Some(&vec!["a.py::f".to_string()]));
        assert!(view.span_index.contains_key("a.py"));
        assert!(view.file_qnodes.contains_key("a.py"));
    }

    // ── qnodes_at ──────────────────────────────────────────

    #[test]
    fn qnodes_at_returns_overlapping_spans_first() {
        let ctx = ctx_with(
            &[],
            &[],
            vec![],
            &[("a.py::f", (1, 10)), ("a.py::g", (20, 30))],
        );
        let view = GraphView::new(&ctx);
        let out = qnodes_at(&view, "a.py", 5, 5, 6, false);
        assert_eq!(out, vec!["a.py::f".to_string()]);
    }

    #[test]
    fn qnodes_at_falls_back_to_call_graph_file_membership_when_no_span_overlaps() {
        let ctx = ctx_with(&[("a.py::f", &["a.py::g"])], &[], vec![], &[]);
        let view = GraphView::new(&ctx);
        let out = qnodes_at(&view, "a.py", 5, 5, 6, false);
        assert_eq!(out, vec!["a.py::f".to_string(), "a.py::g".to_string()]);
    }

    #[test]
    fn qnodes_at_treats_a_present_but_empty_file_qnodes_entry_as_no_match() {
        let mut view = GraphView::new(&ContextPackage::default());
        view.file_qnodes.insert("a.py".to_string(), Vec::new());
        assert!(qnodes_at(&view, "a.py", 5, 5, 6, false).is_empty());
    }

    #[test]
    fn qnodes_at_returns_empty_when_nothing_matches_and_nearest_if_empty_is_false() {
        let ctx = ContextPackage::default();
        let view = GraphView::new(&ctx);
        assert!(qnodes_at(&view, "a.py", 5, 5, 6, false).is_empty());
    }

    #[test]
    fn qnodes_at_nearest_if_empty_returns_the_closest_span_when_none_overlap() {
        let ctx = ctx_with(&[], &[], vec![], &[("a.py::f", (100, 110))]);
        let view = GraphView::new(&ctx);
        let out = qnodes_at(&view, "a.py", 5, 5, 6, true);
        assert_eq!(out, vec!["a.py::f".to_string()]);
    }

    #[test]
    fn qnodes_at_nearest_if_empty_picks_the_closest_of_several_non_overlapping_spans() {
        let ctx = ctx_with(
            &[],
            &[],
            vec![],
            &[("a.py::far", (100, 110)), ("a.py::near", (20, 25))],
        );
        let view = GraphView::new(&ctx);
        let out = qnodes_at(&view, "a.py", 5, 5, 6, true);
        assert_eq!(out, vec!["a.py::near".to_string()]);
    }

    #[test]
    fn qnodes_at_nearest_if_empty_is_still_empty_when_the_file_has_no_spans_at_all() {
        let ctx = ContextPackage::default();
        let view = GraphView::new(&ctx);
        assert!(qnodes_at(&view, "a.py", 5, 5, 6, true).is_empty());
    }

    #[test]
    fn qnodes_at_caps_results_at_limit() {
        let ctx = ctx_with(
            &[],
            &[],
            vec![],
            &[("a.py::f", (1, 10)), ("a.py::g", (2, 9))],
        );
        let view = GraphView::new(&ctx);
        let out = qnodes_at(&view, "a.py", 5, 5, 1, false);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn qnodes_at_normalizes_backslashes_in_the_file_argument() {
        let ctx = ctx_with(&[], &[], vec![], &[("a/b.py::f", (1, 10))]);
        let view = GraphView::new(&ctx);
        let out = qnodes_at(&view, "a\\b.py", 5, 5, 6, false);
        assert_eq!(out, vec!["a/b.py::f".to_string()]);
    }

    #[test]
    fn qnodes_at_clamps_a_backwards_line_window_up_to_start() {
        let ctx = ctx_with(&[], &[], vec![], &[("a.py::f", (5, 5))]);
        let view = GraphView::new(&ctx);
        // line_end (1) < line_start (5): end is clamped up to start.
        let out = qnodes_at(&view, "a.py", 5, 1, 6, false);
        assert_eq!(out, vec!["a.py::f".to_string()]);
    }

    // ── neighborhood ──────────────────────────────────────────

    #[test]
    fn neighborhood_reports_callers_and_callees_capped_at_max_edges() {
        let ctx = ctx_with(
            &[
                ("caller1", &["mid"]),
                ("caller2", &["mid"]),
                ("mid", &["callee1", "callee2"]),
            ],
            &[],
            vec![],
            &[],
        );
        let view = GraphView::new(&ctx);
        let out = neighborhood(&view, &["mid".to_string()], 1);
        let n = &out["mid"];
        assert_eq!(n.callers.len(), 1);
        assert_eq!(n.callees.len(), 1);
    }

    #[test]
    fn neighborhood_of_an_unknown_qnode_is_empty_on_both_sides() {
        let ctx = ContextPackage::default();
        let view = GraphView::new(&ctx);
        let out = neighborhood(&view, &["nowhere".to_string()], 5);
        let n = &out["nowhere"];
        assert!(n.callers.is_empty());
        assert!(n.callees.is_empty());
    }
}
