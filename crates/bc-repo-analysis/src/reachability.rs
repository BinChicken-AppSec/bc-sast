//! File-level reachability for `step3.catchall_mode: reachable_only`.
//! Ported from `s3_decompose.py::_reachable_files`.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use bc_model::ContextPackage;

use crate::callgraph::{q_file, q_name};
use crate::graph_view::seed_reachable_files;
use crate::lang::ext_to_lang;

fn lang_of_file(f: &str) -> Option<&'static str> {
    let ext = Path::new(f)
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy().to_lowercase()))
        .unwrap_or_default();
    if ext.is_empty() {
        return None;
    }
    ext_to_lang(&ext)
}

fn bfs(seeds: &HashSet<String>, graph: &HashMap<String, HashSet<String>>) -> HashSet<String> {
    let mut seen: HashSet<String> = seeds.clone();
    let mut frontier: Vec<String> = seeds.iter().cloned().collect();
    while !frontier.is_empty() {
        let mut next = Vec::new();
        for n in &frontier {
            let Some(neighbors) = graph.get(n) else {
                continue;
            };
            for m in neighbors {
                if seen.insert(m.clone()) {
                    next.push(m.clone());
                }
            }
        }
        frontier = next;
    }
    seen
}

/// A file is reachable iff it lies on the forward closure from any
/// `EntryPoint.file` OR the backward closure to any `Sink.file` over a
/// file-level projection of `ctx.call_graph` — deliberately coarser than
/// the function-level taint walk (see [`crate::add_taint_chunks`]): for
/// catch-all gating we only need to decide which FILES might sit on an
/// attacker-controlled data path, not which functions. Full BFS with no
/// hop cap — the file graph has at most `all_files.len()` nodes, so it's
/// cheap.
///
/// Conservative biases (all widen the set, never shrink it):
/// - every `EntryPoint.file`/`Sink.file` is always reachable, even if the
///   call graph never mentions it;
/// - polymorphic defs: any file listed in `ctx.call_graph_files[name]` for
///   a reachable function name is pulled in too, so an interface call
///   keeps every implementation file in scope;
/// - S0 seed-taint-path files (widen-only, call-graph-blind evidence);
/// - files in a language the S0 engine has no call-graph plugin for at
///   all (an "unknown", not a proven-unreachable, state).
pub fn reachable_files(ctx: &ContextPackage) -> HashSet<String> {
    let mut fwd: HashMap<String, HashSet<String>> = HashMap::new();
    let mut rev: HashMap<String, HashSet<String>> = HashMap::new();
    for (caller, callees) in &ctx.call_graph {
        let cf = q_file(caller);
        for callee in callees {
            let tf = q_file(callee);
            if !cf.is_empty() && !tf.is_empty() && cf != tf {
                fwd.entry(cf.clone()).or_default().insert(tf.clone());
                rev.entry(tf).or_default().insert(cf.clone());
            }
        }
    }

    let mut name_to_files: HashMap<String, HashSet<String>> = HashMap::new();
    for (name, sites) in &ctx.call_graph_files {
        let bare = q_name(name);
        for ref_ in sites {
            let f = ref_.split_once(':').map(|(f, _)| f).unwrap_or(ref_);
            if !f.is_empty() {
                name_to_files
                    .entry(bare.clone())
                    .or_default()
                    .insert(f.to_string());
            }
        }
    }
    for (caller, callees) in &ctx.call_graph {
        let cf = q_file(caller);
        if cf.is_empty() {
            continue;
        }
        for callee in callees {
            let Some(files) = name_to_files.get(&q_name(callee)) else {
                continue;
            };
            for tf in files {
                if tf != &cf {
                    fwd.entry(cf.clone()).or_default().insert(tf.clone());
                    rev.entry(tf.clone()).or_default().insert(cf.clone());
                }
            }
        }
    }

    let ep_files: HashSet<String> = ctx
        .entry_points
        .iter()
        .filter(|e| !e.file.is_empty())
        .map(|e| e.file.clone())
        .collect();
    let sk_files: HashSet<String> = ctx
        .unsafe_sinks
        .iter()
        .filter(|s| !s.file.is_empty())
        .map(|s| s.file.clone())
        .collect();
    let seed_files = seed_reachable_files(&ctx.seed_taint_paths);

    let mut graph_node_files: HashSet<String> = ep_files
        .iter()
        .chain(sk_files.iter())
        .chain(seed_files.iter())
        .cloned()
        .collect();
    for (caller, callees) in &ctx.call_graph {
        let cf = q_file(caller);
        if !cf.is_empty() {
            graph_node_files.insert(cf);
        }
        for callee in callees {
            let tf = q_file(callee);
            if !tf.is_empty() {
                graph_node_files.insert(tf);
            }
        }
    }
    for sites in ctx.call_graph_files.values() {
        for ref_ in sites {
            let f = ref_.split_once(':').map(|(f, _)| f).unwrap_or(ref_);
            if !f.is_empty() {
                graph_node_files.insert(f.to_string());
            }
        }
    }
    let covered_langs: HashSet<&'static str> = graph_node_files
        .iter()
        .filter_map(|f| lang_of_file(f))
        .collect();
    let unknown_lang_files: HashSet<String> = ctx
        .all_files
        .iter()
        .filter(|f| lang_of_file(f).is_some_and(|lang| !covered_langs.contains(lang)))
        .cloned()
        .collect();

    bfs(&ep_files, &fwd)
        .into_iter()
        .chain(bfs(&sk_files, &rev))
        .chain(ep_files)
        .chain(sk_files)
        .chain(seed_files)
        .chain(unknown_lang_files)
        .collect()
}

/// `(too_sparse, reason)` — `true` when reachable-only coverage is too
/// sparse to trust and should fall back to `mode: all` instead of gating.
/// Both thresholds default to disabled (`0.0`/`0`); `taint.yaml` opts in.
/// Ported from `_reachable_only_too_sparse`.
pub fn reachable_only_too_sparse(
    reachable_count: usize,
    total_count: usize,
    min_ratio: f64,
    min_files: usize,
) -> (bool, String) {
    if total_count == 0 {
        return (false, String::new());
    }
    let ratio = reachable_count as f64 / total_count as f64;
    let mut reasons: Vec<String> = Vec::new();
    if min_ratio > 0.0 && ratio < min_ratio {
        reasons.push(format!(
            "reachable ratio {:.0}% < {:.0}%",
            ratio * 100.0,
            min_ratio * 100.0
        ));
    }
    if min_files > 0 && reachable_count < min_files {
        reasons.push(format!("reachable files {reachable_count} < {min_files}"));
    }
    (!reasons.is_empty(), reasons.join("; "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_model::{EntryPoint, EntryPointKind, Sink};

    fn ctx() -> ContextPackage {
        ContextPackage::default()
    }

    fn ep(file: &str) -> EntryPoint {
        EntryPoint {
            file: file.to_string(),
            function: "f".to_string(),
            kind: EntryPointKind::Network,
            reachable_from_unauth: false,
        }
    }

    fn sink(file: &str) -> Sink {
        Sink {
            file: file.to_string(),
            line: 1,
            function: "g".to_string(),
            snippet: String::new(),
            cwe: Vec::new(),
        }
    }

    #[test]
    fn empty_context_yields_empty_set() {
        assert!(reachable_files(&ctx()).is_empty());
    }

    #[test]
    fn entry_point_file_is_always_reachable() {
        let mut c = ctx();
        c.entry_points = vec![ep("a.py")];
        assert!(reachable_files(&c).contains("a.py"));
    }

    #[test]
    fn sink_file_is_always_reachable() {
        let mut c = ctx();
        c.unsafe_sinks = vec![sink("s.py")];
        assert!(reachable_files(&c).contains("s.py"));
    }

    #[test]
    fn forward_closure_from_an_entry_file_is_reachable() {
        let mut c = ctx();
        c.entry_points = vec![ep("a.py")];
        c.call_graph
            .insert("a.py::f".to_string(), vec!["b.py::g".to_string()]);
        let reach = reachable_files(&c);
        assert!(reach.contains("a.py"));
        assert!(reach.contains("b.py"));
    }

    #[test]
    fn multi_hop_forward_closure_is_reachable() {
        let mut c = ctx();
        c.entry_points = vec![ep("a.py")];
        c.call_graph
            .insert("a.py::f".to_string(), vec!["b.py::g".to_string()]);
        c.call_graph
            .insert("b.py::g".to_string(), vec!["c.py::h".to_string()]);
        assert!(reachable_files(&c).contains("c.py"));
    }

    #[test]
    fn backward_closure_to_a_sink_file_is_reachable() {
        let mut c = ctx();
        c.unsafe_sinks = vec![sink("b.py")];
        c.call_graph
            .insert("a.py::f".to_string(), vec!["b.py::g".to_string()]);
        assert!(reachable_files(&c).contains("a.py"));
    }

    #[test]
    fn a_file_disconnected_from_every_seed_is_not_reachable_when_language_is_covered() {
        let mut c = ctx();
        c.entry_points = vec![ep("a.py")];
        c.call_graph
            .insert("a.py::f".to_string(), vec!["b.py::g".to_string()]);
        c.all_files = vec!["a.py".to_string(), "b.py".to_string(), "c.py".to_string()];
        // "c.py" is python (a covered language, since a.py/b.py contributed
        // graph nodes) but never appears in the graph at all.
        assert!(!reachable_files(&c).contains("c.py"));
    }

    #[test]
    fn self_loop_edges_are_ignored() {
        let mut c = ctx();
        c.call_graph
            .insert("a.py::f".to_string(), vec!["a.py::g".to_string()]);
        // No entry/sink seeds at all -- a same-file edge must not create a
        // reachability entry point of its own.
        assert!(reachable_files(&c).is_empty());
    }

    #[test]
    fn polymorphic_widening_pulls_in_every_implementation_file() {
        let mut c = ctx();
        c.entry_points = vec![ep("a.py")];
        c.call_graph
            .insert("a.py::f".to_string(), vec!["iface.py::run".to_string()]);
        c.call_graph_files.insert(
            "run".to_string(),
            vec!["impl1.py:10".to_string(), "impl2.py:20".to_string()],
        );
        let reach = reachable_files(&c);
        assert!(reach.contains("impl1.py"));
        assert!(reach.contains("impl2.py"));
    }

    #[test]
    fn polymorphic_widening_skips_a_caller_with_no_file_prefix() {
        // A bare "run" caller (no "::" separator) resolves to an empty
        // file via `q_file` -- the widening pass must skip it rather than
        // attributing an edge to a "" file.
        let mut c = ctx();
        c.call_graph
            .insert("run".to_string(), vec!["iface.py::run".to_string()]);
        c.call_graph_files
            .insert("run".to_string(), vec!["impl.py:10".to_string()]);
        assert!(!reachable_files(&c).contains("impl.py"));
    }

    #[test]
    fn polymorphic_widening_skips_a_same_file_target() {
        let mut c = ctx();
        c.entry_points = vec![ep("a.py")];
        c.call_graph
            .insert("a.py::f".to_string(), vec!["a.py::run".to_string()]);
        c.call_graph_files
            .insert("run".to_string(), vec!["a.py:10".to_string()]);
        // Only "a.py" itself -- polymorphic widening never adds a self-edge.
        assert_eq!(reachable_files(&c), HashSet::from(["a.py".to_string()]));
    }

    #[test]
    fn call_graph_files_ref_with_no_colon_uses_the_whole_ref_as_the_file() {
        let mut c = ctx();
        c.entry_points = vec![ep("a.py")];
        c.call_graph
            .insert("a.py::f".to_string(), vec!["iface.py::run".to_string()]);
        c.call_graph_files
            .insert("run".to_string(), vec!["impl.py".to_string()]);
        assert!(reachable_files(&c).contains("impl.py"));
    }

    #[test]
    fn seed_taint_path_files_are_always_reachable() {
        let mut c = ctx();
        c.seed_taint_paths = vec![vec!["seed.py:1".to_string()]];
        assert!(reachable_files(&c).contains("seed.py"));
    }

    #[test]
    fn a_file_in_an_uncovered_language_is_reachable_by_the_unknown_language_fail_safe() {
        let mut c = ctx();
        c.entry_points = vec![ep("a.py")];
        c.all_files = vec!["a.py".to_string(), "b.rb".to_string()];
        // No .rb file ever appears in the call graph, so "ruby" contributes
        // zero graph nodes -- it must be treated as unknown, not pruned.
        assert!(reachable_files(&c).contains("b.rb"));
    }

    #[test]
    fn a_file_with_no_extension_never_triggers_the_unknown_language_fail_safe() {
        let mut c = ctx();
        c.all_files = vec!["Makefile".to_string()];
        assert!(!reachable_files(&c).contains("Makefile"));
    }

    // ── reachable_only_too_sparse ────────────────────────────────────────

    #[test]
    fn zero_total_is_never_sparse() {
        assert_eq!(
            reachable_only_too_sparse(0, 0, 0.5, 0),
            (false, String::new())
        );
    }

    #[test]
    fn disabled_thresholds_are_never_sparse() {
        assert_eq!(
            reachable_only_too_sparse(1, 100, 0.0, 0),
            (false, String::new())
        );
    }

    #[test]
    fn ratio_below_threshold_is_sparse() {
        let (sparse, reason) = reachable_only_too_sparse(10, 100, 0.5, 0);
        assert!(sparse);
        assert!(reason.contains("reachable ratio 10% < 50%"));
    }

    #[test]
    fn ratio_at_or_above_threshold_is_not_sparse() {
        assert_eq!(
            reachable_only_too_sparse(50, 100, 0.5, 0),
            (false, String::new())
        );
    }

    #[test]
    fn count_below_min_files_is_sparse() {
        let (sparse, reason) = reachable_only_too_sparse(2, 100, 0.0, 5);
        assert!(sparse);
        assert!(reason.contains("reachable files 2 < 5"));
    }

    #[test]
    fn both_reasons_are_joined() {
        let (sparse, reason) = reachable_only_too_sparse(2, 100, 0.5, 5);
        assert!(sparse);
        assert!(reason.contains("reachable ratio"));
        assert!(reason.contains("reachable files"));
        assert!(reason.contains("; "));
    }
}
