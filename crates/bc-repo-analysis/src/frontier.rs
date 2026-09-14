//! AST-frontier narrowing, ported from `models.py::ContextPackage.
//! ast_context_view`. Both S2 (threat-model evidence gathering) and S3
//! (decompose prompt building) call this on the full `ContextPackage`
//! before building their prompts: it picks a bounded, high-signal subset
//! of files (entry points, sinks, seed-taint hops, call-graph def sites,
//! module files) and trims every other collection down to just what
//! touches that subset — so a huge repo's prompt stays bounded without
//! ever silently dropping the parts of the graph a finding/threat
//! actually needs.

use std::collections::{BTreeMap, HashSet};

use bc_model::{ContextPackage, EntryPoint, ModuleInfo, Sink, TaintEvidencePath};

use crate::callgraph::q_file;

pub struct FrontierConfig {
    pub max_files: usize,
    pub max_entry_points: usize,
    pub max_sinks: usize,
    pub max_modules: usize,
    pub max_edges: usize,
    pub max_notes_chars: usize,
}

impl FrontierConfig {
    pub fn new() -> Self {
        FrontierConfig {
            max_files: 250,
            max_entry_points: 120,
            max_sinks: 160,
            max_modules: 40,
            max_edges: 120,
            max_notes_chars: 4000,
        }
    }
}

impl Default for FrontierConfig {
    fn default() -> Self {
        Self::new()
    }
}

fn norm_file(path: &str) -> String {
    let mut norm = path.replace('\\', "/");
    while let Some(rest) = norm.strip_prefix("./") {
        norm = rest.to_string();
    }
    norm
}

fn add_file(path: &str, seed_files: &mut Vec<String>, seen: &mut HashSet<String>) {
    let norm = norm_file(path);
    if !norm.is_empty() && seen.insert(norm.clone()) {
        seed_files.push(norm);
    }
}

/// `"file:line"` hop -> `"file"`. A naive first-colon split (Python's
/// `node.split(":", 1)[0]`) — unlike `graph_view::parse_hop`, this has no
/// numeric-suffix validation; it's only ever used here to recover a file
/// path for allow-list membership, not to parse a real line number.
fn hop_file(s: &str) -> &str {
    s.split(':').next().unwrap_or(s)
}

fn bare(qn: &str) -> &str {
    qn.rsplit_once("::").map(|(_, n)| n).unwrap_or(qn)
}

/// Ported from `ast_context_view`'s nested `_is_hot`: true when either
/// endpoint of a call-graph edge is an entry point/sink qnode (exact
/// match) or, for an unqualified name only, shares a bare function name
/// with one. A small, deliberate duplicate of `bc-stage-s3::prompts`'s
/// own `is_hot`/`bare` (a different Python function, `s3_decompose.py`'s
/// `_hot`, with the same shape) — not shared cross-crate since
/// `bc-repo-analysis` sits below `bc-stage-s3` in the dependency graph.
fn is_hot_name(
    name: &str,
    ep_fqns: &HashSet<String>,
    sink_fqns: &HashSet<String>,
    ep_bare: &HashSet<&str>,
    sink_bare: &HashSet<&str>,
) -> bool {
    if ep_fqns.contains(name) || sink_fqns.contains(name) {
        return true;
    }
    if !name.contains("::") {
        let b = bare(name);
        return ep_bare.contains(b) || sink_bare.contains(b);
    }
    false
}

/// `caller -> [callee, ...]` flattened to `(caller, callee)` pairs, empty
/// callees dropped and duplicates-per-caller removed (first occurrence
/// kept) — ported from `ast_context_view`'s nested `_edges` generator.
fn edges(call_graph: &BTreeMap<String, Vec<String>>) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (caller, callees) in call_graph {
        let mut seen = HashSet::new();
        for callee in callees {
            if callee.is_empty() {
                continue;
            }
            if seen.insert(callee.clone()) {
                out.push((caller.clone(), callee.clone()));
            }
        }
    }
    out
}

/// Narrow `ctx` to a bounded AST frontier for prompt building. Ported
/// from `ContextPackage.ast_context_view`. Every field not touched here
/// (`repo_root`/`language`/`excluded`/`known_cves`/`design_controls`/
/// `changed_files`/`app_profile`/`threat_model`) passes through
/// unchanged, matching Python's `model_copy(update={...})` semantics —
/// only the ten fields below are ever overridden.
pub fn ast_context_view(ctx: &ContextPackage, config: &FrontierConfig) -> ContextPackage {
    let mut seed_files: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    for entry in ctx.entry_points.iter().take(config.max_entry_points) {
        add_file(&entry.file, &mut seed_files, &mut seen);
    }
    for sink in ctx.unsafe_sinks.iter().take(config.max_sinks) {
        add_file(&sink.file, &mut seed_files, &mut seen);
    }
    for path in &ctx.seed_taint_paths {
        for node in path {
            add_file(hop_file(node), &mut seed_files, &mut seen);
        }
    }
    for sites in ctx.call_graph_files.values() {
        for site in sites.iter().take(2) {
            add_file(hop_file(site), &mut seed_files, &mut seen);
        }
    }
    for module in ctx.modules.iter().take(config.max_modules) {
        for path in module.files.iter().take(5) {
            add_file(path, &mut seed_files, &mut seen);
        }
    }

    let all_files_set: HashSet<&str> = ctx.all_files.iter().map(String::as_str).collect();
    let mut all_files: Vec<String> = Vec::new();
    let mut seen_all: HashSet<String> = HashSet::new();
    for path in &seed_files {
        if all_files_set.contains(path.as_str()) && seen_all.insert(path.clone()) {
            all_files.push(path.clone());
            if all_files.len() >= config.max_files {
                break;
            }
        }
    }
    if all_files.len() < config.max_files {
        for path in &ctx.all_files {
            if seen_all.insert(path.clone()) {
                all_files.push(path.clone());
                if all_files.len() >= config.max_files {
                    break;
                }
            }
        }
    }

    let allowed_files: HashSet<&str> = all_files.iter().map(String::as_str).collect();
    let entry_points: Vec<EntryPoint> = ctx
        .entry_points
        .iter()
        .filter(|e| allowed_files.contains(e.file.as_str()))
        .take(config.max_entry_points)
        .cloned()
        .collect();
    let unsafe_sinks: Vec<Sink> = ctx
        .unsafe_sinks
        .iter()
        .filter(|s| allowed_files.contains(s.file.as_str()))
        .take(config.max_sinks)
        .cloned()
        .collect();

    let mut modules: Vec<ModuleInfo> = Vec::new();
    for module in &ctx.modules {
        let kept: Vec<String> = module
            .files
            .iter()
            .filter(|f| allowed_files.contains(f.as_str()))
            .take(10)
            .cloned()
            .collect();
        if !kept.is_empty() {
            let mut m = module.clone();
            m.files = kept;
            modules.push(m);
        }
        if modules.len() >= config.max_modules {
            break;
        }
    }

    let ep_fqns: HashSet<String> = entry_points
        .iter()
        .map(|e| format!("{}::{}", e.file, e.function))
        .collect();
    let sink_fqns: HashSet<String> = unsafe_sinks
        .iter()
        .map(|s| format!("{}::{}", s.file, s.function))
        .collect();
    let ep_bare: HashSet<&str> = entry_points.iter().map(|e| e.function.as_str()).collect();
    let sink_bare: HashSet<&str> = unsafe_sinks.iter().map(|s| s.function.as_str()).collect();

    let all_edges = edges(&ctx.call_graph);
    let mut trimmed_graph: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut total_edges = 0usize;
    for want_hot in [true, false] {
        if total_edges >= config.max_edges {
            break;
        }
        for (caller, callee) in &all_edges {
            let hot = is_hot_name(caller, &ep_fqns, &sink_fqns, &ep_bare, &sink_bare)
                || is_hot_name(callee, &ep_fqns, &sink_fqns, &ep_bare, &sink_bare);
            if hot != want_hot {
                continue;
            }
            let cf = q_file(caller);
            let tf = q_file(callee);
            if !cf.is_empty()
                && !allowed_files.contains(cf.as_str())
                && !tf.is_empty()
                && !allowed_files.contains(tf.as_str())
            {
                continue;
            }
            trimmed_graph
                .entry(caller.clone())
                .or_default()
                .push(callee.clone());
            total_edges += 1;
            if total_edges >= config.max_edges {
                break;
            }
        }
    }

    let mut kept_functions: HashSet<&str> = trimmed_graph.keys().map(String::as_str).collect();
    for callees in trimmed_graph.values() {
        kept_functions.extend(callees.iter().map(String::as_str));
    }

    let mut trimmed_graph_files: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (fn_, sites) in &ctx.call_graph_files {
        if !kept_functions.contains(fn_.as_str()) {
            continue;
        }
        if !sites
            .iter()
            .any(|site| allowed_files.contains(hop_file(site)))
        {
            continue;
        }
        let kept_sites: Vec<String> = sites
            .iter()
            .filter(|site| allowed_files.contains(hop_file(site)))
            .take(3)
            .cloned()
            .collect();
        trimmed_graph_files.insert(fn_.clone(), kept_sites);
    }

    let trimmed_def_spans: BTreeMap<String, (i64, i64)> = ctx
        .def_spans
        .iter()
        .filter(|(fn_, _)| kept_functions.contains(fn_.as_str()))
        .map(|(k, v)| (k.clone(), *v))
        .collect();

    let mut trimmed_paths: Vec<Vec<String>> = Vec::new();
    for path in &ctx.seed_taint_paths {
        let kept: Vec<String> = path
            .iter()
            .filter(|node| allowed_files.contains(hop_file(node)))
            .take(8)
            .cloned()
            .collect();
        if !kept.is_empty() {
            trimmed_paths.push(kept);
        }
    }

    let mut trimmed_evidence: Vec<TaintEvidencePath> = Vec::new();
    for evidence in &ctx.seed_taint_evidence {
        let source_file = hop_file(&evidence.source_ref);
        let sink_file = hop_file(&evidence.sink_ref);
        if !allowed_files.contains(source_file) || !allowed_files.contains(sink_file) {
            continue;
        }
        let mut ev = evidence.clone();
        ev.edges.truncate(24);
        trimmed_evidence.push(ev);
        if trimmed_evidence.len() >= 60 {
            break;
        }
    }

    let notes = if ctx.notes.chars().count() > config.max_notes_chars {
        let truncated: String = ctx.notes.chars().take(config.max_notes_chars).collect();
        format!(
            "{}\n[truncated for AST frontier prompt]",
            truncated.trim_end()
        )
    } else {
        ctx.notes.clone()
    };

    ContextPackage {
        all_files,
        entry_points,
        unsafe_sinks,
        modules,
        call_graph: trimmed_graph,
        call_graph_files: trimmed_graph_files,
        def_spans: trimmed_def_spans,
        seed_taint_paths: trimmed_paths,
        seed_taint_evidence: trimmed_evidence,
        notes,
        ..ctx.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_model::{EntryPointKind, TaintSymbolRef};

    fn ep(file: &str, function: &str) -> EntryPoint {
        EntryPoint {
            file: file.to_string(),
            function: function.to_string(),
            kind: EntryPointKind::Other,
            reachable_from_unauth: false,
        }
    }

    fn sink(file: &str, function: &str) -> Sink {
        Sink {
            file: file.to_string(),
            line: 1,
            function: function.to_string(),
            snippet: String::new(),
            cwe: Vec::new(),
        }
    }

    fn module(name: &str, files: &[&str]) -> ModuleInfo {
        ModuleInfo {
            name: name.to_string(),
            files: files.iter().map(|s| s.to_string()).collect(),
            loc: 0,
            purpose: String::new(),
        }
    }

    fn sym(qnode: &str, symbol: &str) -> TaintSymbolRef {
        TaintSymbolRef {
            qnode: qnode.to_string(),
            symbol: symbol.to_string(),
            kind: "local".to_string(),
        }
    }

    fn taint_edge(file: &str) -> bc_model::TaintTransferEdge {
        bc_model::TaintTransferEdge {
            file: file.to_string(),
            line: 1,
            function_qnode: format!("{file}::f"),
            src: sym(&format!("{file}::f"), "a"),
            dst: sym(&format!("{file}::f"), "b"),
            transfer_kind: "assign".to_string(),
            condition_text: None,
            is_tainted_condition: None,
            confidence: None,
            call_type: None,
            reflected_targets: None,
            is_speculative: None,
            framework: None,
            marker_type: None,
        }
    }

    fn evidence(source_ref: &str, sink_ref: &str, n_edges: usize) -> TaintEvidencePath {
        TaintEvidencePath {
            source_ref: source_ref.to_string(),
            sink_ref: sink_ref.to_string(),
            path_funcs: Vec::new(),
            edges: (0..n_edges).map(|_| taint_edge("a.py")).collect(),
            sink_cwe: Vec::new(),
            sanitized: false,
        }
    }

    fn graph(pairs: &[(&str, &[&str])]) -> BTreeMap<String, Vec<String>> {
        pairs
            .iter()
            .map(|(k, vs)| (k.to_string(), vs.iter().map(|s| s.to_string()).collect()))
            .collect()
    }

    fn base_ctx() -> ContextPackage {
        ContextPackage {
            repo_root: "/repo".to_string(),
            language: "python".to_string(),
            all_files: vec!["a.py".to_string(), "b.py".to_string(), "c.py".to_string()],
            ..Default::default()
        }
    }

    // ── seed-file collection + all_files build-up ──────────────────────

    #[test]
    fn seed_files_come_from_entry_points_sinks_seed_paths_call_graph_files_and_modules() {
        let mut ctx = base_ctx();
        ctx.all_files = vec![
            "a.py".to_string(),
            "b.py".to_string(),
            "c.py".to_string(),
            "d.py".to_string(),
            "e.py".to_string(),
        ];
        ctx.entry_points = vec![ep("a.py", "handler")];
        ctx.unsafe_sinks = vec![sink("b.py", "exec")];
        ctx.seed_taint_paths = vec![vec!["c.py:1".to_string()]];
        ctx.call_graph_files = BTreeMap::from([("f".to_string(), vec!["d.py:1".to_string()])]);
        ctx.modules = vec![module("m", &["e.py"])];
        let out = ast_context_view(&ctx, &FrontierConfig::new());
        let mut files = out.all_files.clone();
        files.sort();
        assert_eq!(files, vec!["a.py", "b.py", "c.py", "d.py", "e.py"]);
    }

    #[test]
    fn seed_file_paths_are_normalized_and_deduped() {
        let mut ctx = base_ctx();
        ctx.entry_points = vec![ep("./a.py", "h1"), ep("a.py", "h2")];
        let mut cfg = FrontierConfig::new();
        cfg.max_files = 1;
        let out = ast_context_view(&ctx, &cfg);
        // Both entry points normalize to "a.py" and dedup to one seed file
        // — max_files=1 isolates this from the full-inventory fallback
        // fill so only the deduped seed is observable.
        assert_eq!(out.all_files, vec!["a.py".to_string()]);
    }

    #[test]
    fn seed_files_not_present_in_all_files_are_dropped() {
        let mut ctx = base_ctx();
        ctx.entry_points = vec![ep("nope.py", "h")];
        let out = ast_context_view(&ctx, &FrontierConfig::new());
        assert!(!out.all_files.contains(&"nope.py".to_string()));
    }

    #[test]
    fn all_files_fills_remaining_budget_from_the_full_inventory_after_seeds() {
        let mut ctx = base_ctx();
        ctx.entry_points = vec![ep("a.py", "h")];
        let mut cfg = FrontierConfig::new();
        cfg.max_files = 2;
        let out = ast_context_view(&ctx, &cfg);
        assert_eq!(out.all_files.len(), 2);
        assert_eq!(out.all_files[0], "a.py");
    }

    #[test]
    fn all_files_stops_filling_once_max_files_is_reached_by_seeds_alone() {
        let mut ctx = base_ctx();
        ctx.entry_points = vec![ep("a.py", "h"), ep("b.py", "h2")];
        let mut cfg = FrontierConfig::new();
        cfg.max_files = 1;
        let out = ast_context_view(&ctx, &cfg);
        assert_eq!(out.all_files, vec!["a.py".to_string()]);
    }

    #[test]
    fn entry_points_seed_source_is_capped_at_max_entry_points() {
        let mut ctx = base_ctx();
        ctx.all_files = vec!["a.py".to_string(), "b.py".to_string()];
        ctx.entry_points = vec![ep("a.py", "h1"), ep("b.py", "h2")];
        let mut cfg = FrontierConfig::new();
        cfg.max_entry_points = 1;
        cfg.max_files = 1;
        let out = ast_context_view(&ctx, &cfg);
        // Only "a.py" (the first entry point) ever becomes a seed file —
        // max_files=1 isolates this from the full-inventory fallback fill.
        assert_eq!(out.all_files, vec!["a.py".to_string()]);
    }

    #[test]
    fn unsafe_sinks_seed_source_is_capped_at_max_sinks() {
        let mut ctx = base_ctx();
        ctx.all_files = vec!["a.py".to_string(), "b.py".to_string()];
        ctx.unsafe_sinks = vec![sink("a.py", "s1"), sink("b.py", "s2")];
        let mut cfg = FrontierConfig::new();
        cfg.max_sinks = 1;
        cfg.max_files = 1;
        let out = ast_context_view(&ctx, &cfg);
        assert_eq!(out.all_files, vec!["a.py".to_string()]);
    }

    #[test]
    fn modules_seed_source_is_capped_at_max_modules_and_five_files_per_module() {
        let mut ctx = base_ctx();
        ctx.all_files = (0..10).map(|i| format!("f{i}.py")).collect();
        ctx.modules = vec![module(
            "m",
            &["f0.py", "f1.py", "f2.py", "f3.py", "f4.py", "f5.py"],
        )];
        let mut cfg = FrontierConfig::new();
        cfg.max_files = 5;
        let out = ast_context_view(&ctx, &cfg);
        // Only the first 5 files of the module become seeds — max_files=5
        // isolates this from the full-inventory fallback fill.
        assert!(out.all_files.contains(&"f4.py".to_string()));
        assert!(!out.all_files.iter().any(|f| f == "f5.py"));
    }

    #[test]
    fn call_graph_files_seed_source_caps_at_two_sites_per_function() {
        let mut ctx = base_ctx();
        ctx.all_files = vec!["a.py".to_string(), "b.py".to_string(), "c.py".to_string()];
        ctx.call_graph_files = BTreeMap::from([(
            "f".to_string(),
            vec![
                "a.py:1".to_string(),
                "b.py:1".to_string(),
                "c.py:1".to_string(),
            ],
        )]);
        let mut cfg = FrontierConfig::new();
        cfg.max_files = 2;
        let out = ast_context_view(&ctx, &cfg);
        assert!(out.all_files.contains(&"a.py".to_string()));
        assert!(out.all_files.contains(&"b.py".to_string()));
        assert!(!out.all_files.contains(&"c.py".to_string()));
    }

    // ── entry_points / unsafe_sinks / modules post-filter ──────────────

    #[test]
    fn entry_points_and_sinks_outside_the_frontier_are_dropped() {
        let mut ctx = base_ctx();
        ctx.all_files = vec!["a.py".to_string(), "z.py".to_string()];
        ctx.entry_points = vec![ep("a.py", "h"), ep("z.py", "h2")];
        let mut cfg = FrontierConfig::new();
        cfg.max_files = 1;
        let out = ast_context_view(&ctx, &cfg);
        assert_eq!(out.entry_points.len(), 1);
        assert_eq!(out.entry_points[0].file, "a.py");
    }

    #[test]
    fn module_with_no_allowed_files_is_dropped_entirely() {
        let mut ctx = base_ctx();
        ctx.modules = vec![
            module("kept", &["a.py"]),
            module("dropped", &["nowhere.py"]),
        ];
        let out = ast_context_view(&ctx, &FrontierConfig::new());
        assert_eq!(out.modules.len(), 1);
        assert_eq!(out.modules[0].name, "kept");
    }

    #[test]
    fn module_files_are_filtered_to_allowed_and_capped_at_ten() {
        let mut ctx = base_ctx();
        ctx.all_files = (0..12).map(|i| format!("f{i}.py")).collect();
        let many: Vec<&str> = ctx.all_files.iter().map(|s| s.as_str()).collect();
        ctx.modules = vec![module("m", &many)];
        let out = ast_context_view(&ctx, &FrontierConfig::new());
        assert_eq!(out.modules[0].files.len(), 10);
    }

    #[test]
    fn modules_cap_check_runs_even_when_a_module_is_skipped() {
        let mut ctx = base_ctx();
        ctx.modules = vec![
            module("skipped", &["nowhere.py"]),
            module("also_skipped", &["also_nowhere.py"]),
        ];
        let mut cfg = FrontierConfig::new();
        cfg.max_modules = 1;
        // Both modules are skipped (no allowed files), but the cap-check
        // still runs on every iteration — with only 2 modules total this
        // can't distinguish the "runs every iteration" claim numerically,
        // so this test only asserts the (unsurprising) end state.
        let out = ast_context_view(&ctx, &cfg);
        assert!(out.modules.is_empty());
    }

    #[test]
    fn modules_loop_stops_once_a_kept_module_reaches_max_modules() {
        let mut ctx = base_ctx();
        ctx.modules = vec![module("first", &["a.py"]), module("second", &["b.py"])];
        let mut cfg = FrontierConfig::new();
        cfg.max_modules = 1;
        let out = ast_context_view(&ctx, &cfg);
        assert_eq!(out.modules.len(), 1);
        assert_eq!(out.modules[0].name, "first");
    }

    // ── hot/cold edge trimming ──────────────────────────────────────────

    #[test]
    fn hot_edges_touching_an_entry_point_or_sink_qnode_are_kept_first() {
        let mut ctx = base_ctx();
        ctx.entry_points = vec![ep("a.py", "handler")];
        ctx.call_graph = graph(&[("a.py::handler", &["a.py::helper"])]);
        let out = ast_context_view(&ctx, &FrontierConfig::new());
        assert_eq!(
            out.call_graph.get("a.py::handler"),
            Some(&vec!["a.py::helper".to_string()])
        );
    }

    #[test]
    fn bare_unqualified_name_matches_an_entry_point_by_bare_function_name() {
        let mut ctx = base_ctx();
        ctx.entry_points = vec![ep("a.py", "handler")];
        // "handler" (bare, no "::") is hot via bare-name match even though
        // it isn't a qualified qnode.
        ctx.call_graph = graph(&[("handler", &["a.py::helper"])]);
        let out = ast_context_view(&ctx, &FrontierConfig::new());
        assert_eq!(
            out.call_graph.get("handler"),
            Some(&vec!["a.py::helper".to_string()])
        );
    }

    #[test]
    fn qualified_name_does_not_bare_match_a_different_files_entry_point() {
        let mut ctx = base_ctx();
        ctx.all_files = vec!["a.py".to_string(), "b.py".to_string()];
        ctx.entry_points = vec![ep("a.py", "handler")];
        // "b.py::handler" shares a bare name with the entry point but is a
        // DIFFERENT qualified qnode — must not be classified hot by that
        // alone (it's still edge-eligible via file membership, just not
        // prioritized as hot).
        ctx.call_graph = graph(&[("b.py::handler", &["b.py::other"])]);
        let out = ast_context_view(&ctx, &FrontierConfig::new());
        // Still present (cold pass keeps it since both files are allowed)
        // but this asserts it doesn't crash/misclassify; presence is the
        // meaningful signal here since there's no hot/cold-cap distinction
        // to observe directly without exhausting max_edges.
        assert_eq!(
            out.call_graph.get("b.py::handler"),
            Some(&vec!["b.py::other".to_string()])
        );
    }

    #[test]
    fn cold_edges_fill_in_after_hot_edges_up_to_max_edges() {
        let mut ctx = base_ctx();
        ctx.entry_points = vec![ep("a.py", "hot_fn")];
        ctx.call_graph = graph(&[
            ("a.py::hot_fn", &["a.py::hot_callee"]),
            ("a.py::cold_fn", &["a.py::cold_callee"]),
        ]);
        let out = ast_context_view(&ctx, &FrontierConfig::new());
        assert!(out.call_graph.contains_key("a.py::hot_fn"));
        assert!(out.call_graph.contains_key("a.py::cold_fn"));
    }

    #[test]
    fn max_edges_caps_total_edges_and_the_cold_pass_is_skipped_once_hot_fills_the_budget() {
        let mut ctx = base_ctx();
        ctx.entry_points = vec![ep("a.py", "hot_fn")];
        ctx.call_graph = graph(&[
            ("a.py::hot_fn", &["a.py::hot_callee"]),
            ("a.py::cold_fn", &["a.py::cold_callee"]),
        ]);
        let mut cfg = FrontierConfig::new();
        cfg.max_edges = 1;
        let out = ast_context_view(&ctx, &cfg);
        assert_eq!(out.call_graph.len(), 1);
        assert!(out.call_graph.contains_key("a.py::hot_fn"));
        assert!(!out.call_graph.contains_key("a.py::cold_fn"));
    }

    #[test]
    fn duplicate_and_empty_callees_are_deduped_and_dropped() {
        let mut ctx = base_ctx();
        ctx.call_graph = graph(&[("a.py::f", &["a.py::g", "a.py::g", "", "a.py::h"])]);
        let out = ast_context_view(&ctx, &FrontierConfig::new());
        assert_eq!(
            out.call_graph.get("a.py::f"),
            Some(&vec!["a.py::g".to_string(), "a.py::h".to_string()])
        );
    }

    #[test]
    fn an_edge_between_two_disallowed_files_is_dropped() {
        let mut ctx = base_ctx();
        ctx.all_files = vec!["a.py".to_string()];
        ctx.call_graph = graph(&[("z.py::f", &["y.py::g"])]);
        let out = ast_context_view(&ctx, &FrontierConfig::new());
        assert!(out.call_graph.is_empty());
    }

    #[test]
    fn an_edge_with_one_endpoint_unqualified_survives_even_if_the_other_is_disallowed() {
        let mut ctx = base_ctx();
        ctx.all_files = vec!["a.py".to_string()];
        // Caller has no "::" (q_file is empty) so the "both disallowed"
        // drop condition can never trigger for it.
        ctx.call_graph = graph(&[("bare_caller", &["z.py::g"])]);
        let out = ast_context_view(&ctx, &FrontierConfig::new());
        assert_eq!(
            out.call_graph.get("bare_caller"),
            Some(&vec!["z.py::g".to_string()])
        );
    }

    // ── call_graph_files / def_spans trimming ──────────────────────────

    #[test]
    fn call_graph_files_kept_only_for_functions_surviving_the_trimmed_graph() {
        let mut ctx = base_ctx();
        ctx.call_graph = graph(&[("a.py::f", &["a.py::g"])]);
        ctx.call_graph_files = BTreeMap::from([
            ("a.py::f".to_string(), vec!["a.py:1".to_string()]),
            ("a.py::unrelated".to_string(), vec!["a.py:2".to_string()]),
        ]);
        let out = ast_context_view(&ctx, &FrontierConfig::new());
        assert!(out.call_graph_files.contains_key("a.py::f"));
        assert!(!out.call_graph_files.contains_key("a.py::unrelated"));
    }

    #[test]
    fn call_graph_files_sites_are_filtered_to_allowed_files_and_capped_at_three() {
        let mut ctx = base_ctx();
        ctx.all_files = vec!["a.py".to_string(), "b.py".to_string()];
        ctx.call_graph = graph(&[("a.py::f", &["a.py::g"])]);
        ctx.call_graph_files = BTreeMap::from([(
            "a.py::f".to_string(),
            vec![
                "a.py:1".to_string(),
                "a.py:2".to_string(),
                "a.py:3".to_string(),
                "a.py:4".to_string(),
                "z.py:1".to_string(),
            ],
        )]);
        let out = ast_context_view(&ctx, &FrontierConfig::new());
        let sites = out.call_graph_files.get("a.py::f").unwrap();
        assert_eq!(sites.len(), 3);
        assert!(sites.iter().all(|s| s.starts_with("a.py:")));
    }

    #[test]
    fn call_graph_files_function_with_no_allowed_site_at_all_is_dropped() {
        let mut ctx = base_ctx();
        ctx.all_files = vec!["a.py".to_string()];
        ctx.call_graph = graph(&[("a.py::f", &["a.py::g"])]);
        ctx.call_graph_files =
            BTreeMap::from([("a.py::f".to_string(), vec!["nowhere.py:1".to_string()])]);
        let out = ast_context_view(&ctx, &FrontierConfig::new());
        assert!(!out.call_graph_files.contains_key("a.py::f"));
    }

    #[test]
    fn def_spans_kept_only_for_functions_surviving_the_trimmed_graph() {
        let mut ctx = base_ctx();
        ctx.call_graph = graph(&[("a.py::f", &["a.py::g"])]);
        ctx.def_spans = BTreeMap::from([
            ("a.py::f".to_string(), (1, 5)),
            ("a.py::unrelated".to_string(), (10, 20)),
        ]);
        let out = ast_context_view(&ctx, &FrontierConfig::new());
        assert_eq!(out.def_spans.get("a.py::f"), Some(&(1, 5)));
        assert!(!out.def_spans.contains_key("a.py::unrelated"));
    }

    // ── seed_taint_paths / seed_taint_evidence trimming ────────────────

    #[test]
    fn seed_taint_paths_nodes_outside_the_frontier_are_dropped_and_capped_at_eight() {
        let mut ctx = base_ctx();
        ctx.all_files = vec!["a.py".to_string()];
        ctx.seed_taint_paths = vec![(0..10).map(|i| format!("a.py:{i}")).collect()];
        let out = ast_context_view(&ctx, &FrontierConfig::new());
        assert_eq!(out.seed_taint_paths[0].len(), 8);
    }

    #[test]
    fn seed_taint_path_that_touches_no_allowed_file_is_dropped_entirely() {
        let mut ctx = base_ctx();
        ctx.all_files = vec!["a.py".to_string()];
        ctx.seed_taint_paths = vec![vec!["nowhere.py:1".to_string()]];
        let out = ast_context_view(&ctx, &FrontierConfig::new());
        assert!(out.seed_taint_paths.is_empty());
    }

    #[test]
    fn seed_taint_evidence_outside_the_frontier_is_dropped() {
        let mut ctx = base_ctx();
        ctx.all_files = vec!["a.py".to_string()];
        ctx.seed_taint_evidence = vec![evidence("nowhere.py:1", "a.py:2", 1)];
        let out = ast_context_view(&ctx, &FrontierConfig::new());
        assert!(out.seed_taint_evidence.is_empty());
    }

    #[test]
    fn seed_taint_evidence_in_frontier_keeps_edges_capped_at_24() {
        let mut ctx = base_ctx();
        ctx.seed_taint_evidence = vec![evidence("a.py:1", "a.py:2", 30)];
        let out = ast_context_view(&ctx, &FrontierConfig::new());
        assert_eq!(out.seed_taint_evidence[0].edges.len(), 24);
    }

    #[test]
    fn seed_taint_evidence_is_capped_at_sixty_entries() {
        let mut ctx = base_ctx();
        ctx.seed_taint_evidence = (0..65).map(|_| evidence("a.py:1", "a.py:2", 1)).collect();
        let out = ast_context_view(&ctx, &FrontierConfig::new());
        assert_eq!(out.seed_taint_evidence.len(), 60);
    }

    // ── notes truncation ─────────────────────────────────────────────

    #[test]
    fn notes_under_the_cap_pass_through_unchanged() {
        let mut ctx = base_ctx();
        ctx.notes = "short note".to_string();
        let out = ast_context_view(&ctx, &FrontierConfig::new());
        assert_eq!(out.notes, "short note");
    }

    #[test]
    fn notes_over_the_cap_are_truncated_and_marked() {
        let mut ctx = base_ctx();
        ctx.notes = "x".repeat(10);
        let mut cfg = FrontierConfig::new();
        cfg.max_notes_chars = 5;
        let out = ast_context_view(&ctx, &cfg);
        assert_eq!(out.notes, "xxxxx\n[truncated for AST frontier prompt]");
    }

    #[test]
    fn notes_truncation_trims_trailing_whitespace_before_the_marker() {
        let mut ctx = base_ctx();
        ctx.notes = "abc   xyz".to_string();
        let mut cfg = FrontierConfig::new();
        cfg.max_notes_chars = 6; // "abc   " (trailing spaces trimmed)
        let out = ast_context_view(&ctx, &cfg);
        assert_eq!(out.notes, "abc\n[truncated for AST frontier prompt]");
    }

    // ── untouched fields pass through unchanged ────────────────────────

    #[test]
    fn fields_outside_the_frontiers_scope_pass_through_unchanged() {
        let mut ctx = base_ctx();
        ctx.repo_root = "/my/repo".to_string();
        ctx.language = "rust".to_string();
        ctx.notes = "keep".to_string();
        let out = ast_context_view(&ctx, &FrontierConfig::new());
        assert_eq!(out.repo_root, "/my/repo");
        assert_eq!(out.language, "rust");
    }

    #[test]
    fn frontier_config_default_matches_new() {
        let a = FrontierConfig::new();
        let b = FrontierConfig::default();
        assert_eq!(a.max_files, b.max_files);
        assert_eq!(a.max_entry_points, b.max_entry_points);
        assert_eq!(a.max_sinks, b.max_sinks);
        assert_eq!(a.max_modules, b.max_modules);
        assert_eq!(a.max_edges, b.max_edges);
        assert_eq!(a.max_notes_chars, b.max_notes_chars);
    }
}
