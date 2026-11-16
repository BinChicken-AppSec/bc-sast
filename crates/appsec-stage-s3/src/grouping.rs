use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use appsec_model::ContextPackage;

pub(crate) fn file_call_graph(ctx: &ContextPackage) -> BTreeMap<String, BTreeSet<String>> {
    let mut adj: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (caller, callees) in &ctx.call_graph {
        let cf = appsec_repo_analysis::q_file(caller);
        if cf.is_empty() {
            continue;
        }
        for cal in callees {
            let tf = appsec_repo_analysis::q_file(cal);
            if !tf.is_empty() && tf != cf {
                adj.entry(cf.clone()).or_default().insert(tf.clone());
                adj.entry(tf).or_default().insert(cf.clone());
            }
        }
    }
    adj
}

fn parent_dir(f: &str) -> &str {
    match f.rsplit_once('/') {
        Some((parent, _)) if !parent.is_empty() => parent,
        _ => ".",
    }
}

fn merge_dir_groups_to_cap(
    mut groups: BTreeMap<String, Vec<String>>,
    max_groups: usize,
) -> BTreeMap<String, Vec<String>> {
    if max_groups == 0 {
        return groups;
    }
    while let Some(smallest) = (groups.len() > max_groups)
        .then(|| {
            groups
                .iter()
                .filter(|(k, _)| k.as_str() != ".")
                .min_by(|(ka, va), (kb, vb)| va.len().cmp(&vb.len()).then_with(|| ka.cmp(kb)))
                .map(|(k, _)| k.clone())
        })
        .flatten()
    {
        let parent = parent_dir(&smallest).to_string();
        let moved = groups.remove(&smallest).unwrap_or_default();
        groups.entry(parent).or_default().extend(moved);
    }
    groups
}

pub fn cohesive_groups(
    files: &[String],
    ctx: &ContextPackage,
    max_groups: usize,
) -> Vec<(String, Vec<String>)> {
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
        by_dir
            .entry(parent_dir(f).to_string())
            .or_default()
            .push(f.clone());
    }
    for (key, mut files) in merge_dir_groups_to_cap(by_dir, max_groups) {
        files.sort();
        groups.push((key, files));
    }

    groups
}

#[cfg(test)]
mod tests {
    use super::*;
    use appsec_model::ModuleInfo;

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
            design_controls: Vec::new(),
            changed_files: Default::default(),
            diff_scope_active: false,
            app_profile: None,
            threat_model: None,
            provider_digest: None,
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
        let groups = cohesive_groups(&files, &ctx, 0);
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
        let groups = cohesive_groups(&files, &ctx, 0);
        assert!(groups.iter().all(|(name, _)| name != "unrelated"));
        assert_eq!(groups, vec![(".".to_string(), vec!["a.py".to_string()])]);
    }

    #[test]
    fn call_graph_edges_with_an_unqualified_caller_are_skipped() {
        let mut ctx = minimal_ctx();
        ctx.call_graph
            .insert("bare_name".to_string(), vec!["b.py::helper".to_string()]);
        let files = vec!["b.py".to_string()];
        let groups = cohesive_groups(&files, &ctx, 0);
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
        let groups = cohesive_groups(&files, &ctx, 0);
        assert_eq!(groups.len(), 1);
        assert!(groups[0].0.starts_with("cg:"));
        assert_eq!(groups[0].1, vec!["a.py".to_string(), "b.py".to_string()]);
    }

    fn strs(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn files_with_no_graph_edges_fall_back_to_their_immediate_parent_directory() {
        let ctx = minimal_ctx();
        let files = strs(&["src/pkg/a.py", "src/pkg/b.py", "src/pkg/sub/c.py", "top.py"]);
        let groups = cohesive_groups(&files, &ctx, 0);
        let group_map: std::collections::HashMap<&str, &Vec<String>> =
            groups.iter().map(|(k, v)| (k.as_str(), v)).collect();
        assert_eq!(
            group_map["src/pkg"],
            &strs(&["src/pkg/a.py", "src/pkg/b.py"])
        );
        assert_eq!(group_map["src/pkg/sub"], &strs(&["src/pkg/sub/c.py"]));
        assert_eq!(group_map["."], &strs(&["top.py"]));
    }

    #[test]
    fn parent_dir_is_the_root_for_a_top_level_or_leading_slash_path() {
        assert_eq!(parent_dir("/a.py"), ".");
        assert_eq!(parent_dir("a.py"), ".");
        assert_eq!(parent_dir("x/y/a.py"), "x/y");
    }

    #[test]
    fn the_group_cap_folds_the_smallest_directory_into_its_parent() {
        let ctx = minimal_ctx();
        let files = strs(&[
            "app/a/1.py",
            "app/a/2.py",
            "app/a/3.py",
            "app/b/1.py",
            "app/b/2.py",
            "lib/1.py",
            "lib/2.py",
            "lib/3.py",
            "lib/4.py",
            "app/c.py",
        ]);
        let groups = cohesive_groups(&files, &ctx, 3);
        assert_eq!(groups.len(), 3);
        let keys: Vec<&str> = groups.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, vec![".", "app/a", "lib"]);
        assert_eq!(groups[0].1, strs(&["app/b/1.py", "app/b/2.py", "app/c.py"]));
        let mut flat: Vec<String> = groups.into_iter().flat_map(|(_, fs)| fs).collect();
        flat.sort();
        let mut want = files.clone();
        want.sort();
        assert_eq!(flat, want);
    }

    #[test]
    fn merge_dir_groups_to_cap_breaks_size_ties_by_name() {
        let mut by_dir = BTreeMap::new();
        by_dir.insert("b".to_string(), strs(&["b/1.py"]));
        by_dir.insert("a".to_string(), strs(&["a/1.py"]));
        by_dir.insert(".".to_string(), strs(&["1.py", "2.py"]));
        let merged = merge_dir_groups_to_cap(by_dir, 2);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged["."], strs(&["1.py", "2.py", "a/1.py"]));
        assert!(merged.contains_key("b"));
    }

    #[test]
    fn merge_dir_groups_to_cap_never_moves_the_root_group_and_stops_there() {
        let mut by_dir = BTreeMap::new();
        by_dir.insert(".".to_string(), strs(&["1.py"]));
        by_dir.insert("a/b".to_string(), strs(&["a/b/1.py", "a/b/2.py"]));
        let merged = merge_dir_groups_to_cap(by_dir.clone(), 1);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged["."].len(), 3);
        assert_eq!(merge_dir_groups_to_cap(by_dir.clone(), 5), by_dir);
        assert_eq!(merge_dir_groups_to_cap(by_dir.clone(), 0), by_dir);
    }

    #[test]
    fn same_file_call_graph_edges_are_not_self_loops() {
        let mut ctx = minimal_ctx();
        ctx.call_graph
            .insert("a.py::f1".to_string(), vec!["a.py::f2".to_string()]);
        let files = vec!["a.py".to_string()];
        let groups = cohesive_groups(&files, &ctx, 0);
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
        let groups = cohesive_groups(&files, &ctx, 0);
        let all: Vec<&String> = groups.iter().flat_map(|(_, fs)| fs.iter()).collect();
        assert_eq!(all.len(), 4);
    }

    #[test]
    fn empty_input_produces_no_groups() {
        let ctx = minimal_ctx();
        assert!(cohesive_groups(&[], &ctx, 0).is_empty());
    }
}
