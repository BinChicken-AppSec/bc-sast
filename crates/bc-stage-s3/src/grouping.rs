//! File-grouping cascade used to split oversize chunks and to bucket
//! catch-all/specialist coverage, ported from `s3_decompose.py`'s
//! `_file_call_graph`/`_cohesive_groups`.
//!
//! **Deliberate divergence, not a bug**: Python's `_cohesive_groups` labels
//! a call-graph component `f"cg:{PurePosixPath(comp[0]).stem}"` where
//! `comp[0]` is whichever file the DFS discovers first via `set` iteration
//! — and Python's own `set`/`dict`-of-strings iteration order is itself
//! hash-randomized per process (`PYTHONHASHSEED`) unless explicitly
//! disabled, so the Python original does not actually guarantee a
//! reproducible label across runs either. This port uses a `BTreeSet` for
//! adjacency (sorted-ascending traversal) so the *Rust* port is
//! deterministic and testable — every file that ends up in a given
//! component (and hence every chunk's actual file list) is identical to
//! Python's either way, since both sort `comp` before use; only the
//! human-readable `cg:` label stem could conceivably differ, and Python's
//! own choice there isn't a stable target to match in the first place.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use bc_model::ContextPackage;

fn file_call_graph(ctx: &ContextPackage) -> BTreeMap<String, BTreeSet<String>> {
    let mut adj: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (caller, callees) in &ctx.call_graph {
        let cf = bc_repo_analysis::q_file(caller);
        if cf.is_empty() {
            continue;
        }
        for cal in callees {
            let tf = bc_repo_analysis::q_file(cal);
            if !tf.is_empty() && tf != cf {
                adj.entry(cf.clone()).or_default().insert(tf.clone());
                adj.entry(tf).or_default().insert(cf.clone());
            }
        }
    }
    adj
}

/// Partition `files` into semantically related groups so a researcher sees
/// callers and callees together. Preference order: `ctx.modules` (S1's
/// agentic grouping), then call-graph connected components, then a
/// depth-2-directory fallback for whatever has no graph edges. Every input
/// file lands in exactly one group.
pub fn cohesive_groups(files: &[String], ctx: &ContextPackage) -> Vec<(String, Vec<String>)> {
    let mut pending: BTreeSet<String> = files.iter().cloned().collect();
    let mut groups: Vec<(String, Vec<String>)> = Vec::new();

    for m in &ctx.modules {
        let hit: Vec<String> = m
            .files
            .iter()
            .filter(|f| pending.contains(f.as_str()))
            .cloned()
            .collect();
        if hit.is_empty() {
            continue;
        }
        for f in &hit {
            pending.remove(f);
        }
        groups.push((m.name.clone(), hit));
    }

    let adj = file_call_graph(ctx);
    let mut visited: BTreeSet<String> = BTreeSet::new();
    for f in pending.clone() {
        if visited.contains(&f) || !adj.contains_key(&f) {
            continue;
        }
        let mut comp: Vec<String> = Vec::new();
        let mut stack: Vec<String> = vec![f];
        while let Some(n) = stack.pop() {
            if visited.contains(&n) || !pending.contains(&n) {
                continue;
            }
            visited.insert(n.clone());
            comp.push(n.clone());
            if let Some(neighbors) = adj.get(&n) {
                stack.extend(neighbors.iter().cloned());
            }
        }
        // `comp` is never empty here: the seed `f` came from iterating
        // `pending` itself, so the DFS's first pop (`n == f`) always passes
        // both the `visited`/`pending` checks above and pushes at least
        // that one element — unlike the Python original's structurally
        // identical (and equally unreachable) `if comp:` guard, this isn't
        // kept as untestable dead code.
        let stem = Path::new(&comp[0])
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or(comp[0].as_str())
            .to_string();
        let mut sorted_comp = comp;
        sorted_comp.sort();
        groups.push((format!("cg:{stem}"), sorted_comp));
    }
    for f in &visited {
        pending.remove(f);
    }

    let mut by_dir: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for f in &pending {
        let parts: Vec<&str> = f.split('/').collect();
        let key = if parts.len() > 1 {
            format!("{}/{}", parts[0], parts[1])
        } else {
            ".".to_string()
        };
        by_dir.entry(key).or_default().push(f.clone());
    }
    for (key, files) in by_dir {
        groups.push((key, files));
    }

    groups
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_model::ModuleInfo;

    fn minimal_ctx() -> ContextPackage {
        ContextPackage {
            seed_taint_paths: Default::default(),
            seed_taint_evidence: Default::default(),
            def_spans: Default::default(),
            repo_root: "/repo".to_string(),
            language: "python".to_string(),
            call_graph: Default::default(),
            call_graph_files: Default::default(),
            entry_points: Vec::new(),
            unsafe_sinks: Vec::new(),
            modules: Vec::new(),
            all_files: Vec::new(),
            excluded: Default::default(),
            known_cves: Vec::new(),
            design_controls: Vec::new(),
            changed_files: Default::default(),
            diff_scope_active: false,
            app_profile: None,
            threat_model: None,
            notes: String::new(),
            compliance_guidance: String::new(),
        }
    }

    #[test]
    fn module_membership_takes_priority() {
        let mut ctx = minimal_ctx();
        ctx.modules = vec![ModuleInfo {
            name: "auth".to_string(),
            files: vec!["a.py".to_string(), "b.py".to_string()],
            loc: 10,
            purpose: "p".to_string(),
        }];
        let files = vec!["a.py".to_string(), "b.py".to_string(), "c.py".to_string()];
        let groups = cohesive_groups(&files, &ctx);
        assert_eq!(
            groups[0],
            (
                "auth".to_string(),
                vec!["a.py".to_string(), "b.py".to_string()]
            )
        );
    }

    #[test]
    fn a_module_with_no_files_in_the_input_set_contributes_no_group() {
        let mut ctx = minimal_ctx();
        ctx.modules = vec![ModuleInfo {
            name: "unrelated".to_string(),
            files: vec!["z.py".to_string()],
            loc: 5,
            purpose: "p".to_string(),
        }];
        let files = vec!["a.py".to_string()];
        let groups = cohesive_groups(&files, &ctx);
        assert!(groups.iter().all(|(name, _)| name != "unrelated"));
        assert_eq!(groups, vec![(".".to_string(), vec!["a.py".to_string()])]);
    }

    #[test]
    fn call_graph_edges_with_an_unqualified_caller_are_skipped() {
        let mut ctx = minimal_ctx();
        // "bare_name" has no `::` separator, so `q_file` returns "" for it —
        // the edge must be skipped entirely, not treated as a same-file
        // (self-loop) edge or a real file node.
        ctx.call_graph
            .insert("bare_name".to_string(), vec!["b.py::helper".to_string()]);
        let files = vec!["b.py".to_string()];
        let groups = cohesive_groups(&files, &ctx);
        // No graph edge reaches b.py (the caller side had no file), so it
        // falls through to the directory-bucket fallback.
        assert_eq!(groups, vec![(".".to_string(), vec!["b.py".to_string()])]);
    }

    #[test]
    fn call_graph_connected_files_form_a_cg_group() {
        let mut ctx = minimal_ctx();
        ctx.call_graph.insert(
            "a.py::handler".to_string(),
            vec!["b.py::helper".to_string()],
        );
        let files = vec!["a.py".to_string(), "b.py".to_string()];
        let groups = cohesive_groups(&files, &ctx);
        assert_eq!(groups.len(), 1);
        assert!(groups[0].0.starts_with("cg:"));
        assert_eq!(groups[0].1, vec!["a.py".to_string(), "b.py".to_string()]);
    }

    #[test]
    fn files_with_no_graph_edges_fall_back_to_depth_2_directory() {
        let ctx = minimal_ctx();
        let files = vec![
            "src/pkg/a.py".to_string(),
            "src/pkg/b.py".to_string(),
            "top.py".to_string(),
        ];
        let groups = cohesive_groups(&files, &ctx);
        let group_map: std::collections::HashMap<&str, &Vec<String>> =
            groups.iter().map(|(k, v)| (k.as_str(), v)).collect();
        assert_eq!(
            group_map["src/pkg"],
            &vec!["src/pkg/a.py".to_string(), "src/pkg/b.py".to_string()]
        );
        assert_eq!(group_map["."], &vec!["top.py".to_string()]);
    }

    #[test]
    fn same_file_call_graph_edges_are_not_self_loops() {
        let mut ctx = minimal_ctx();
        ctx.call_graph
            .insert("a.py::f1".to_string(), vec!["a.py::f2".to_string()]);
        let files = vec!["a.py".to_string()];
        let groups = cohesive_groups(&files, &ctx);
        // No graph edge (same file), so it falls through to the directory bucket.
        assert_eq!(groups, vec![(".".to_string(), vec!["a.py".to_string()])]);
    }

    #[test]
    fn every_input_file_lands_in_exactly_one_group() {
        let mut ctx = minimal_ctx();
        ctx.modules = vec![ModuleInfo {
            name: "mod".to_string(),
            files: vec!["a.py".to_string()],
            loc: 1,
            purpose: String::new(),
        }];
        ctx.call_graph
            .insert("b.py::x".to_string(), vec!["c.py::y".to_string()]);
        let files = vec![
            "a.py".to_string(),
            "b.py".to_string(),
            "c.py".to_string(),
            "d.py".to_string(),
        ];
        let groups = cohesive_groups(&files, &ctx);
        let all: Vec<&String> = groups.iter().flat_map(|(_, fs)| fs.iter()).collect();
        assert_eq!(all.len(), 4);
    }

    #[test]
    fn empty_input_produces_no_groups() {
        let ctx = minimal_ctx();
        assert!(cohesive_groups(&[], &ctx).is_empty());
    }
}
