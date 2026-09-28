//! Deterministic logic for S1 that isn't already shared with S3 in
//! `bc-repo-analysis` (which owns the repo walk, config dedup, and
//! call-graph validate/supplement passes). This module ports the parts
//! specific to S1's own `run()`: agent-output path resolution, the
//! LLM-JSON container-unwrap heuristic, scope-filtering the model's
//! output against ground truth, and the language-fallback vote — all
//! from `s1_preprocess.py`'s `_norm_rel`/`_resolve_scope_path`/`run()`.

use std::collections::{BTreeSet, HashSet};
use std::path::Path;

use serde_json::{json, Value};

use bc_model::{EntryPointKind, Sink};
use bc_stage_s0::SeedPackage;

/// Normalize an agent-emitted path to the same repo-relative POSIX form
/// `bc_repo_analysis::walk_repo` produces, so set-membership checks
/// work: backslashes, a leading `./`, and an absolute (resolved-cwd or
/// as-given) prefix are all stripped.
pub fn norm_rel(repo_root: &Path, p: &str) -> String {
    if p.is_empty() {
        return String::new();
    }
    let mut p = p.replace('\\', "/");
    while let Some(stripped) = p.strip_prefix("./") {
        p = stripped.to_string();
    }
    let rel_root = format!(
        "{}/",
        repo_root
            .to_string_lossy()
            .replace('\\', "/")
            .trim_end_matches('/')
    );
    let abs_root = format!(
        "{}/",
        repo_root
            .canonicalize()
            .unwrap_or_else(|_| repo_root.to_path_buf())
            .to_string_lossy()
            .replace('\\', "/")
            .trim_end_matches('/')
    );
    let pl = p.to_lowercase();
    for r in [&abs_root, &rel_root] {
        if pl.starts_with(&r.to_lowercase()) {
            return p[r.len()..].to_string();
        }
    }
    p
}

/// Resolve an agent-emitted path to its in-scope inventory form.
/// `(Some(rel), false)` on an exact or single-top-dir-prefixed hit,
/// `(None, true)` when 2+ top dirs match the same relative path
/// (ambiguous — the caller drops it rather than guessing, fail-safe
/// against misattributing a sink/entry-point/module file to the wrong
/// directory), `(None, false)` on no match at all.
pub fn resolve_scope_path(
    path: &str,
    repo_root: &Path,
    keep: &HashSet<String>,
    top_dirs: &[String],
) -> (Option<String>, bool) {
    let rel = norm_rel(repo_root, path);
    if keep.contains(&rel) {
        return (Some(rel), false);
    }
    let matches: Vec<String> = top_dirs
        .iter()
        .map(|td| format!("{td}/{rel}"))
        .filter(|candidate| keep.contains(candidate))
        .collect();
    match matches.len() {
        1 => (
            Some(matches.into_iter().next().expect("len checked above")),
            false,
        ),
        n => (None, n > 1),
    }
}

/// Immediate subdirectories of `repo_root`, excluding the tool's own
/// `checkpoints`/`security-scan` working directories, sorted. Used as the
/// `--group-by-app`-mode fallback prefix when the agent omits a repo's
/// top-level directory from an emitted path. `repo_root` is guaranteed to
/// exist by the time this runs (the ground-truth walk already succeeded
/// against it), so a read failure here is a near-unreachable TOCTOU edge
/// case handled by degrading to an empty list rather than propagating.
pub fn top_level_dirs(repo_root: &Path) -> Vec<String> {
    let mut dirs: Vec<String> = std::fs::read_dir(repo_root)
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|name| name != "checkpoints" && name != "security-scan")
        .collect();
    dirs.sort();
    dirs
}

/// The model occasionally wraps its payload in a single container key
/// (e.g. `{"context_package": {...}}`) because the prompt says "output
/// the JSON ContextPackage" — unwrap it.
pub fn unwrap_container(data: Value) -> Value {
    let Value::Object(ref map) = data else {
        return data;
    };
    if map.contains_key("language") || map.len() != 1 {
        return data;
    }
    let inner = map.values().next().expect("len == 1 checked above").clone();
    let Value::Object(ref inner_map) = inner else {
        return data;
    };
    if inner_map.contains_key("language")
        || inner_map.contains_key("modules")
        || inner_map.contains_key("entry_points")
    {
        inner
    } else {
        data
    }
}

fn resolve_in_scope(
    path: &str,
    repo_root: &Path,
    keep: &HashSet<String>,
    top_dirs: &[String],
) -> Option<String> {
    resolve_scope_path(path, repo_root, keep, top_dirs).0
}

/// Strip any agent-emitted path that isn't in the exclusion-filtered
/// ground-truth inventory: `unsafe_sinks`/`entry_points` items whose
/// `file` doesn't resolve are dropped entirely (and always
/// unconditionally reassigned, becoming `[]` if the key was absent);
/// each `modules[].files` entry is filtered the same way but the module
/// itself is always kept, even with an empty `files` list.
pub fn scope_filter(data: &mut Value, repo_root: &Path, all_files: &[String]) {
    let keep: HashSet<String> = all_files.iter().cloned().collect();
    let top_dirs = top_level_dirs(repo_root);

    let filter_items = |items: Option<&Value>| -> Vec<Value> {
        items
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|item| {
                        let file = item.get("file").and_then(Value::as_str).unwrap_or("");
                        let hit = resolve_in_scope(file, repo_root, &keep, &top_dirs)?;
                        let mut item = item.clone();
                        if let Value::Object(ref mut map) = item {
                            map.insert("file".to_string(), Value::String(hit));
                        }
                        Some(item)
                    })
                    .collect()
            })
            .unwrap_or_default()
    };

    let sinks = filter_items(data.get("unsafe_sinks"));
    let entry_points = filter_items(data.get("entry_points"));

    if let Value::Object(ref mut map) = data {
        map.insert("unsafe_sinks".to_string(), Value::Array(sinks));
        map.insert("entry_points".to_string(), Value::Array(entry_points));

        if let Some(Value::Array(modules)) = map.get_mut("modules") {
            for m in modules.iter_mut() {
                let Value::Object(ref mut mmap) = m else {
                    continue;
                };
                let files: Vec<Value> = mmap
                    .get("files")
                    .and_then(Value::as_array)
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|f| {
                                let s = f.as_str().unwrap_or("");
                                resolve_in_scope(s, repo_root, &keep, &top_dirs).map(Value::String)
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                mmap.insert("files".to_string(), Value::Array(files));
            }
        }
    }
}

/// Bare `.function` names out of a (by this point, scope-filtered)
/// `entry_points`/`unsafe_sinks` JSON array — the seed lists
/// `bc_repo_analysis::supplement_call_graph` expands from.
pub fn extract_function_names(data: &Value, key: &str) -> Vec<String> {
    data.get(key)
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|item| item.get("function").and_then(Value::as_str))
                .filter(|f| !f.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Lenient `{"caller": ["callee", ...]}` extraction (used for both
/// `call_graph` and `call_graph_files` — same shape) — any key whose
/// value isn't an array, or any non-string array entry, is silently
/// dropped rather than treated as a hard parse error (this is untrusted
/// LLM JSON that has already survived one repair pass).
fn parse_str_list_map(data: &Value, key: &str) -> std::collections::BTreeMap<String, Vec<String>> {
    data.get(key)
        .and_then(Value::as_object)
        .map(|obj| {
            obj.iter()
                .filter_map(|(k, v)| {
                    let vs: Vec<String> = v
                        .as_array()?
                        .iter()
                        .filter_map(|c| c.as_str().map(str::to_string))
                        .collect();
                    Some((k.clone(), vs))
                })
                .collect()
        })
        .unwrap_or_default()
}

pub fn parse_call_graph(data: &Value) -> std::collections::BTreeMap<String, Vec<String>> {
    parse_str_list_map(data, "call_graph")
}

pub fn parse_call_graph_files(data: &Value) -> std::collections::BTreeMap<String, Vec<String>> {
    parse_str_list_map(data, "call_graph_files")
}

/// Lenient `{"qname": [start_line, end_line]}` extraction, matching
/// `parse_call_graph`'s tolerance for malformed/foreign JSON shapes.
pub fn parse_def_spans(data: &Value) -> std::collections::BTreeMap<String, (i64, i64)> {
    data.get("def_spans")
        .and_then(Value::as_object)
        .map(|obj| {
            obj.iter()
                .filter_map(|(k, v)| {
                    let arr = v.as_array()?;
                    let sl = arr.first()?.as_i64()?;
                    let el = arr.get(1)?.as_i64()?;
                    Some((k.clone(), (sl, el)))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Ported from `_seed_covered_languages`: languages S0's callgraph
/// artifacts actually name a file in, derived from the artifacts
/// themselves (rather than a hard-coded plugin list) so a plugin
/// language that happened to contribute no nodes is treated as residual
/// and re-scanned, which only improves coverage.
pub fn seed_covered_languages(data: &Value) -> BTreeSet<&'static str> {
    let mut langs = BTreeSet::new();
    let mut add = |rel: &str| {
        if let Some(lang) = bc_repo_analysis::ext_to_lang(&bc_repo_analysis::suffix_lower(rel)) {
            langs.insert(lang);
        }
    };
    for qn in parse_def_spans(data).keys() {
        add(&bc_repo_analysis::q_file(qn));
    }
    let cg = parse_call_graph(data);
    for (k, vs) in &cg {
        add(&bc_repo_analysis::q_file(k));
        for v in vs {
            add(&bc_repo_analysis::q_file(v));
        }
    }
    for locs in parse_call_graph_files(data).values() {
        for loc in locs {
            if let Some((f, _)) = loc.rsplit_once(':') {
                add(f);
            }
        }
    }
    langs
}

/// Ported from the `[f for f in all_files if EXT_TO_LANG.get(...) not in
/// covered]` residual-file filter inside `run()`'s `cg_mode ==
/// "tree_sitter"` dispatch: `true` when `rel`'s language IS recognized
/// AND is NOT already in `covered` — an unrecognized extension is never
/// "residual", since nothing could scan it either way.
pub fn is_residual_language_file(rel: &str, covered: &BTreeSet<&str>) -> bool {
    bc_repo_analysis::ext_to_lang(&bc_repo_analysis::suffix_lower(rel))
        .is_some_and(|l| !covered.contains(l))
}

/// Overwrites `data`'s three graph keys with a fresh
/// [`bc_repo_analysis::TsGraphResult`] — `ts_graph::build`'s own output
/// contract on the equivalent Python `data` dict.
pub fn apply_ts_graph_result(data: &mut Value, result: &bc_repo_analysis::TsGraphResult) {
    let Value::Object(ref mut map) = data else {
        return;
    };
    map.insert("call_graph".to_string(), json!(result.call_graph));
    map.insert(
        "call_graph_files".to_string(),
        json!(result.call_graph_files),
    );
    map.insert("def_spans".to_string(), json!(result.def_spans));
}

/// Ported from `_merge_graph_artifacts`: folds a snapshotted prior
/// (S0-seed) call graph back over a residual-language `ts_graph` rebuild
/// that overwrote `data`'s three graph dicts wholesale. Keys are qnodes
/// for the edge/span maps (no cross-language collisions, since each
/// qnode's file is in exactly one language); bare names for
/// `call_graph_files` CAN collide across languages, so those lists are
/// unioned. The seed's `def_spans` win on a qnode collision — its AST
/// spans are authoritative.
pub fn merge_graph_artifacts(
    data: &mut Value,
    seed_cg: std::collections::BTreeMap<String, Vec<String>>,
    seed_cgf: std::collections::BTreeMap<String, Vec<String>>,
    seed_spans: std::collections::BTreeMap<String, (i64, i64)>,
) {
    if !matches!(data, Value::Object(_)) {
        return;
    }
    let mut cg = parse_call_graph(data);
    for (k, vs) in seed_cg {
        let entry = cg.entry(k).or_default();
        entry.extend(vs);
        entry.sort();
        entry.dedup();
    }
    let mut cgf = parse_call_graph_files(data);
    for (k, vs) in seed_cgf {
        let entry = cgf.entry(k).or_default();
        entry.extend(vs);
        entry.sort();
        entry.dedup();
    }
    let mut spans = parse_def_spans(data);
    spans.extend(seed_spans); // seed (plugin AST) wins on collision

    if let Value::Object(map) = data {
        map.insert("call_graph".to_string(), json!(cg));
        map.insert("call_graph_files".to_string(), json!(cgf));
        map.insert("def_spans".to_string(), json!(spans));
    }
}

/// Majority-vote language across `all_files` by extension, ties broken by
/// first-encountered (matching Python's `max(dict, key=dict.get)`, which
/// scans insertion order and only updates on a STRICTLY greater count) —
/// `"unknown"` if no file's extension maps to a known language.
pub fn language_fallback(all_files: &[String]) -> String {
    let mut counts: Vec<(&'static str, i64)> = Vec::new();
    for f in all_files {
        let ext = bc_repo_analysis::suffix_lower(f);
        let Some(lang) = bc_repo_analysis::ext_to_lang(&ext) else {
            continue;
        };
        match counts.iter_mut().find(|(l, _)| *l == lang) {
            Some(entry) => entry.1 += 1,
            None => counts.push((lang, 1)),
        }
    }
    let mut best: Option<(&'static str, i64)> = None;
    for (lang, n) in counts {
        let update = match best {
            Some((_, best_n)) => n > best_n,
            None => true,
        };
        if update {
            best = Some((lang, n));
        }
    }
    best.map(|(lang, _)| lang.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// The default-exclude-dirs-plus-config-additions advisory list shown to
/// the agent as a skip-hint (Option B in the Python source — enforcement
/// is Option A, `scope_filter`, applied deterministically afterward
/// regardless of whether the agent honored the hint).
pub fn advisory_skip_dirs(config_exclude_dirs: &[String]) -> String {
    let mut set: HashSet<String> = bc_repo_analysis::DEFAULT_EXCLUDE_DIRS
        .iter()
        .map(|s| s.to_lowercase())
        .collect();
    set.extend(config_exclude_dirs.iter().map(|s| s.to_lowercase()));
    let mut sorted: Vec<String> = set.into_iter().collect();
    sorted.sort();
    sorted.join(", ")
}

const GAP_FILL_ESCALATE_REPO_KINDS: &[&str] = &["service", "web-api", "web-app"];
const GAP_FILL_SERVICE_HINTS: &[&str] = &[
    "dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "chart.yaml",
    "values.yaml",
    "procfile",
    "wsgi.py",
    "asgi.py",
];
const GAP_FILL_WEBAPP_SUFFIXES: &[&str] = &[
    ".html", ".htm", ".jinja", ".jinja2", ".jsx", ".tsx", ".vue", ".svelte",
];

/// Cheap repo-kind guess for deciding whether S1 should stay in
/// `gap_fill`. Intentionally path/seed based only — the decision must be
/// available before any agentic exploration. Ported from
/// `_seed_repo_kinds`.
pub fn seed_repo_kinds(seed: &SeedPackage, all_files: &[String]) -> BTreeSet<String> {
    let mut kinds = BTreeSet::new();
    if seed
        .entry_points
        .iter()
        .any(|ep| ep.kind == EntryPointKind::Network || ep.reachable_from_unauth)
    {
        kinds.insert("web-api".to_string());
    }

    let low_files: Vec<String> = all_files.iter().map(|f| f.to_lowercase()).collect();
    let base_names: BTreeSet<String> = all_files
        .iter()
        .map(|f| {
            Path::new(f)
                .file_name()
                .map(|n| n.to_string_lossy().to_lowercase())
                .unwrap_or_default()
        })
        .collect();
    if base_names
        .iter()
        .any(|n| GAP_FILL_SERVICE_HINTS.contains(&n.as_str()))
    {
        kinds.insert("service".to_string());
    }
    if low_files
        .iter()
        .any(|f| GAP_FILL_WEBAPP_SUFFIXES.iter().any(|suf| f.ends_with(suf)))
    {
        kinds.insert("web-app".to_string());
    }

    if kinds.is_empty() {
        kinds.insert("library".to_string());
    }
    kinds
}

/// Decide whether sparse S0 seed coverage should re-enable S1's own
/// agentic discovery despite `step1.mode: gap_fill`. Ported from
/// `_should_escalate_gap_fill`. Returns `(escalate, reason)` — `reason`
/// is a human-readable diagnostic, not machine-parsed.
pub fn should_escalate_gap_fill(seed: &SeedPackage, all_files: &[String]) -> (bool, String) {
    let source_files = all_files
        .iter()
        .filter(|f| bc_repo_analysis::ext_to_lang(&bc_repo_analysis::suffix_lower(f)).is_some())
        .count();
    if source_files <= 500 {
        return (false, format!("source_files={source_files} <= 500"));
    }

    let kinds = seed_repo_kinds(seed, all_files);
    let active_kinds: Vec<&str> = GAP_FILL_ESCALATE_REPO_KINDS
        .iter()
        .filter(|k| kinds.contains(**k))
        .copied()
        .collect();
    if active_kinds.is_empty() {
        return (false, format!("repo_kind={kinds:?}"));
    }

    let entry_points = seed.entry_points.len();
    if entry_points < 10 {
        return (false, format!("entry_points={entry_points} < 10"));
    }

    let sinks = seed.unsafe_sinks.len();
    if sinks >= 5 {
        return (false, format!("sinks={sinks} >= 5"));
    }

    (
        true,
        format!(
            "source_files={source_files}, repo_kind={active_kinds:?}, \
             entry_points={entry_points}, sinks={sinks}"
        ),
    )
}

/// Re-resolve one `"file:line"` taint hop against the in-scope
/// inventory, returning `None` when the file half is out of scope.
///
/// Ported from the `f, sep, ln = hop.rpartition(":")` half of
/// `s1_preprocess.py:1320-1327`. Python's `rpartition` yields an empty
/// separator when there is no colon at all, in which case the whole hop
/// is the filename and the resolved path is emitted bare — a bare-file
/// hop is legal input (`_resolve_in_scope(f or hop)`), not a malformed
/// one, so it must not be dropped.
fn resolve_taint_hop(
    hop: &str,
    repo_root: &Path,
    keep: &HashSet<String>,
    top_dirs: &[String],
) -> Option<String> {
    match hop.rsplit_once(':') {
        Some((file, line)) => {
            // `":12"` has an empty file half; Python's `f or hop` falls
            // back to the whole hop rather than resolving `""`.
            let candidate = if file.is_empty() { hop } else { file };
            let hit = resolve_in_scope(candidate, repo_root, keep, top_dirs)?;
            Some(format!("{hit}:{line}"))
        }
        None => resolve_in_scope(hop, repo_root, keep, top_dirs),
    }
}

/// Re-resolve S0's `taint_paths` against the ground-truth inventory,
/// ported from `s1_preprocess.py:1316-1330`.
///
/// Hops are dropped individually when their file is out of scope, but the
/// *path* survives as long as at least two hops remain — a taint path
/// with one endpoint left says nothing about a flow. Seed paths are
/// already repo-relative and pre-filtered to S0's own in-scope set; this
/// second pass exists so config-dedup drops (which happen after S0 ran)
/// propagate, letting `bc_repo_analysis`'s reachability and seed-path
/// promotion trust every file a path names.
fn resolve_seed_taint_paths(
    seed: &SeedPackage,
    repo_root: &Path,
    keep: &HashSet<String>,
    top_dirs: &[String],
) -> Vec<Vec<String>> {
    seed.taint_paths
        .iter()
        .filter_map(|path| {
            let resolved: Vec<String> = path
                .iter()
                .filter_map(|hop| resolve_taint_hop(hop, repo_root, keep, top_dirs))
                .collect();
            (resolved.len() >= 2).then_some(resolved)
        })
        .collect()
}

/// Re-resolve a `"file::symbol"` qnode against the in-scope inventory,
/// keeping the `::symbol` tail. `None` when the file half is out of
/// scope. Ported from the repeated `partition("::")` + `_resolve_in_scope`
/// idiom in `s1_preprocess.py:1338-1385`.
fn resolve_qnode(
    qnode: &str,
    repo_root: &Path,
    keep: &HashSet<String>,
    top_dirs: &[String],
) -> Option<String> {
    match qnode.split_once("::") {
        Some((file, tail)) => {
            let hit = resolve_in_scope(file, repo_root, keep, top_dirs)?;
            Some(format!("{hit}::{tail}"))
        }
        None => resolve_in_scope(qnode, repo_root, keep, top_dirs),
    }
}

/// Re-resolve one seed evidence path's file references against the
/// ground-truth inventory. `None` drops the whole path — both endpoints
/// must resolve, mirroring the two `continue`s in
/// `s1_preprocess.py:1338-1352`. Path funcs and edges are pruned
/// individually (an edge whose own file fell out of scope is dropped;
/// a qnode that fails to resolve is kept verbatim, matching the
/// original's asymmetric `if hit else edge.src.qnode` fallbacks).
fn resolve_seed_evidence(
    ev: &bc_model::TaintEvidencePath,
    repo_root: &Path,
    keep: &HashSet<String>,
    top_dirs: &[String],
) -> Option<Value> {
    // Python tries `"::"` first and only falls back to the trailing
    // `":"` split when the source ref carries no qnode separator; the
    // sink ref is always split on `":"`.
    let source_ref = match ev.source_ref.split_once("::") {
        Some(_) => resolve_qnode(&ev.source_ref, repo_root, keep, top_dirs)?,
        None => resolve_taint_hop(&ev.source_ref, repo_root, keep, top_dirs)?,
    };
    let sink_ref = resolve_taint_hop(&ev.sink_ref, repo_root, keep, top_dirs)?;

    let path_funcs: Vec<String> = ev
        .path_funcs
        .iter()
        .filter_map(|qn| resolve_qnode(qn, repo_root, keep, top_dirs))
        .collect();

    let edges: Vec<Value> = ev
        .edges
        .iter()
        .filter_map(|edge| {
            let file = resolve_in_scope(&edge.file, repo_root, keep, top_dirs)?;
            let mut out = serde_json::to_value(edge).ok()?;
            let Value::Object(ref mut m) = out else {
                return None;
            };
            m.insert("file".to_string(), Value::String(file));
            let fq = resolve_qnode(&edge.function_qnode, repo_root, keep, top_dirs)
                .unwrap_or_else(|| edge.function_qnode.clone());
            m.insert("function_qnode".to_string(), Value::String(fq));
            for (key, qnode) in [("src", &edge.src.qnode), ("dst", &edge.dst.qnode)] {
                let resolved = resolve_qnode(qnode, repo_root, keep, top_dirs)
                    .unwrap_or_else(|| qnode.clone());
                if let Some(Value::Object(sym)) = m.get_mut(key) {
                    sym.insert("qnode".to_string(), Value::String(resolved));
                }
            }
            Some(out)
        })
        .collect();

    Some(json!({
        "source_ref": source_ref,
        "sink_ref": sink_ref,
        "path_funcs": path_funcs,
        "edges": edges,
        "sink_cwe": ev.sink_cwe,
        // Python's own dict literal (`s1_preprocess.py:1388-1394`) omits
        // `sanitized`, so every merged path silently arrives with the
        // model default `False` — which makes
        // `bc_repo_analysis::taint`'s "skip a sanitized flow" branch
        // dead. The flag is carried through here instead.
        "sanitized": ev.sanitized,
    }))
}

/// Resolve and append S0 seed `entry_points`/`unsafe_sinks` into `data`'s
/// already scope-filtered arrays — mirrors `run()`'s `data["unsafe_sinks"]
/// .extend(seed_sinks)` / `.extend(seed_eps)`, applying the same
/// in-scope path resolution the agent's own output already went through —
/// and set `data["seed_taint_paths"]` from the seed's own `taint_paths`.
///
/// The taint-path half closed a real dead end: `ContextPackage::
/// seed_taint_paths` had three ported consumers already waiting on it
/// (`bc_repo_analysis::reachability`, its taint seed-path promotion, and
/// `bc_stage_s5::backfill`) while nothing ever wrote the field, so every
/// one of them was permanently starved no matter what S0 found.
///
/// `SeedPackage::framework_entry_points` is merged in alongside the plain
/// `entry_points` (ported from `s1_preprocess.py:1399-1412`), closing the
/// consumer half of that plane — the field previously had no writer AND
/// no reader, so route detection would have had nowhere to deliver even
/// once it lands. **Still missing**: the producer. Nothing in
/// `bc-callgraph`'s scan emits framework markers yet, so this field is
/// empty for every seed S0 can currently build; the decorator/annotation
/// route detection of `_graph.py:1494-1554` remains unported.
///
/// Note this port keeps routes in their own field rather than mixing them
/// into `entry_points` and re-extracting by `kind == "framework"`, and
/// dedups by `(file, function)`: Python's re-extraction appends its
/// framework set a SECOND time on top of the extend that already carried
/// it, double-counting every route — a bug not replicated here.
///
/// The structured `seed_taint_evidence` plane
/// (`s1_preprocess.py:1333-1397`) is merged the same way: evidence whose
/// source *and* sink refs both resolve in scope survives, with its path
/// funcs and edges pruned to in-scope files. That closes the last dead
/// end in this plane — `ContextPackage::seed_taint_evidence` is what
/// `bc_stage_s4`'s `STRUCTURED TAINT EVIDENCE` prompt block and
/// `bc_repo_analysis::taint`'s seed-path promotion both read.
pub fn merge_seed_into_data(
    data: &mut Value,
    repo_root: &Path,
    all_files: &[String],
    seed: &SeedPackage,
) {
    let keep: HashSet<String> = all_files.iter().cloned().collect();
    let top_dirs = top_level_dirs(repo_root);

    // Framework-detected routes are carried in their own `SeedPackage`
    // field here rather than mixed into `entry_points` and re-extracted by
    // `kind == "framework"` the way Python does, so they are resolved and
    // appended alongside them. Deduplicated against the plain entry points
    // by `(file, function)`: Python appends its framework set a SECOND
    // time on top of the extend that already carried it
    // (`s1_preprocess.py:1399-1412`), which double-counts every route.
    // Framework routes FIRST: they carry the guard truth (`reachable_from_
    // unauth` from the route table), while a plain entry point for the same
    // `(file, function)` only says "reads a source" with the flag defaulted.
    // The 2026-09-07 polyglot probe showed a Laravel page's guarded
    // framework entry losing the dedup to its plain twin and coming out
    // `Other`/open.
    let mut seen_eps: HashSet<(String, String)> = HashSet::new();
    let resolved_eps: Vec<Value> = seed
        .framework_entry_points
        .iter()
        .chain(seed.entry_points.iter())
        .filter_map(|ep| {
            let hit = resolve_in_scope(&ep.file, repo_root, &keep, &top_dirs)?;
            if !seen_eps.insert((hit.clone(), ep.function.clone())) {
                return None;
            }
            Some(json!({
                "file": hit,
                "function": ep.function,
                "kind": ep.kind,
                "reachable_from_unauth": ep.reachable_from_unauth,
            }))
        })
        .collect();

    let resolved_sinks: Vec<Value> = seed
        .unsafe_sinks
        .iter()
        .filter_map(|s| {
            let hit = resolve_in_scope(&s.file, repo_root, &keep, &top_dirs)?;
            Some(sink_to_json(s, hit))
        })
        .collect();

    let seed_paths = resolve_seed_taint_paths(seed, repo_root, &keep, &top_dirs);
    let seed_evidence: Vec<Value> = seed
        .taint_evidence
        .iter()
        .filter_map(|ev| resolve_seed_evidence(ev, repo_root, &keep, &top_dirs))
        .collect();

    let Value::Object(ref mut map) = data else {
        return;
    };
    // Unconditional assignment, matching Python's `data["seed_taint_paths"]
    // = seed_paths` — an S0 run that found no surviving path must clear
    // any stale value, not leave one behind.
    map.insert(
        "seed_taint_paths".to_string(),
        Value::Array(
            seed_paths
                .into_iter()
                .map(|p| Value::Array(p.into_iter().map(Value::String).collect()))
                .collect(),
        ),
    );
    // Unconditional too, matching `data["seed_taint_evidence"] =
    // seed_evidence`.
    map.insert(
        "seed_taint_evidence".to_string(),
        Value::Array(seed_evidence),
    );
    // When the deterministic framework plane found routes, the survey
    // model's own "framework" labels stop counting as framework entry
    // points: `EntryPointKind::Framework` is what the S5 route gate and
    // the S6 `[GUARDED]` marker take as the guard truth, and a survey entry
    // for the same handler with `reachable_from_unauth: true` (the model
    // guesses; it does not read middleware) neutralized the gate on every
    // guarded route in a 2026-09-07 live run. Demoted to `other`; the
    // model's reachability claim stays visible on the entry itself.
    let mut demoted = 0usize;
    if !seed.framework_entry_points.is_empty() {
        if let Some(Value::Array(existing)) = map.get_mut("entry_points") {
            for ep in existing.iter_mut() {
                let is_framework = serde_json::from_value::<bc_model::EntryPoint>(ep.clone())
                    .is_ok_and(|e| e.kind == bc_model::EntryPointKind::Framework);
                if is_framework {
                    if let Value::Object(obj) = ep {
                        obj.insert("kind".to_string(), Value::String("other".to_string()));
                        demoted += 1;
                    }
                }
            }
        }
    }
    {
        let seed_framework = seed.framework_entry_points.len();
        let seed_plain = seed.entry_points.len();
        let resolved = resolved_eps.len();
        tracing::info!(
            seed_framework,
            seed_plain,
            resolved,
            demoted,
            "[s1] seed entry points merged into the survey context"
        );
    }
    if !resolved_eps.is_empty() {
        let arr = map
            .entry("entry_points")
            .or_insert_with(|| Value::Array(Vec::new()));
        if let Value::Array(a) = arr {
            a.extend(resolved_eps);
        }
    }
    if !resolved_sinks.is_empty() {
        let arr = map
            .entry("unsafe_sinks")
            .or_insert_with(|| Value::Array(Vec::new()));
        if let Value::Array(a) = arr {
            a.extend(resolved_sinks);
        }
    }
}

fn sink_to_json(s: &Sink, resolved_file: String) -> Value {
    json!({
        "file": resolved_file,
        "line": s.line,
        "function": s.function,
        "snippet": s.snippet,
        "cwe": s.cwe,
    })
}

/// Override `data["call_graph"]`/`data["call_graph_files"]` with S0's own
/// AST-derived artifacts when present, avoiding a second repo parse in
/// S1 for callgraph-enabled profiles. Ported from `run()`'s
/// `if getattr(seed, "call_graph", None): data["call_graph"] = {...}`
/// tail. A no-op when the seed carries neither (S0 disabled, or its scan
/// matched nothing).
pub fn apply_seed_call_graph(data: &mut Value, seed: &SeedPackage) {
    let Value::Object(ref mut map) = data else {
        return;
    };
    if !seed.call_graph.is_empty() {
        let cg: std::collections::BTreeMap<String, Vec<String>> = seed
            .call_graph
            .iter()
            .filter(|(_, v)| !v.is_empty())
            .map(|(k, v)| {
                let mut v = v.clone();
                v.sort();
                (k.clone(), v)
            })
            .collect();
        map.insert("call_graph".to_string(), json!(cg));
    }
    if !seed.call_graph_files.is_empty() {
        let cgf: std::collections::BTreeMap<String, Vec<String>> = seed
            .call_graph_files
            .iter()
            .filter(|(_, v)| !v.is_empty())
            .map(|(k, v)| {
                let mut v = v.clone();
                v.sort();
                (k.clone(), v)
            })
            .collect();
        map.insert("call_graph_files".to_string(), json!(cgf));
    }
    if !seed.def_spans.is_empty() {
        let spans: std::collections::BTreeMap<String, (i64, i64)> = seed
            .def_spans
            .iter()
            .map(|(k, (sl, el))| (k.clone(), (*sl as i64, *el as i64)))
            .collect();
        map.insert("def_spans".to_string(), json!(spans));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_model::{TaintEvidencePath, TaintTransferEdge};
    use serde_json::json;

    // ── norm_rel ─────────────────────────────────────────────────────

    #[test]
    fn norm_rel_empty_string_is_unchanged() {
        assert_eq!(norm_rel(Path::new("/repo"), ""), "");
    }

    #[test]
    fn norm_rel_strips_leading_dot_slash_and_backslashes() {
        assert_eq!(norm_rel(Path::new("/repo"), "./a/b"), "a/b");
        assert_eq!(norm_rel(Path::new("/repo"), "a\\b\\c.py"), "a/b/c.py");
    }

    #[test]
    fn norm_rel_strips_repo_root_prefix_case_insensitively() {
        assert_eq!(norm_rel(Path::new("/repo"), "/REPO/a/b.py"), "a/b.py");
    }

    #[test]
    fn norm_rel_passthrough_when_no_prefix_matches() {
        assert_eq!(
            norm_rel(Path::new("/repo"), "unrelated/x.py"),
            "unrelated/x.py"
        );
    }

    // ── resolve_scope_path ───────────────────────────────────────────

    #[test]
    fn resolve_scope_path_exact_hit() {
        let keep: HashSet<String> = ["a/b.py".to_string()].into_iter().collect();
        let result = resolve_scope_path("a/b.py", Path::new("/repo"), &keep, &[]);
        assert_eq!(result, (Some("a/b.py".to_string()), false));
    }

    #[test]
    fn resolve_scope_path_unique_top_dir_prefix_match() {
        let keep: HashSet<String> = ["svc1/a/b.py".to_string()].into_iter().collect();
        let top_dirs = vec!["svc1".to_string(), "svc2".to_string()];
        let result = resolve_scope_path("a/b.py", Path::new("/repo"), &keep, &top_dirs);
        assert_eq!(result, (Some("svc1/a/b.py".to_string()), false));
    }

    #[test]
    fn resolve_scope_path_ambiguous_across_two_top_dirs_is_dropped_not_guessed() {
        let keep: HashSet<String> = ["svc1/a/b.py".to_string(), "svc2/a/b.py".to_string()]
            .into_iter()
            .collect();
        let top_dirs = vec!["svc1".to_string(), "svc2".to_string()];
        let result = resolve_scope_path("a/b.py", Path::new("/repo"), &keep, &top_dirs);
        assert_eq!(result, (None, true));
    }

    #[test]
    fn resolve_scope_path_no_match_at_all() {
        let keep: HashSet<String> = ["other.py".to_string()].into_iter().collect();
        let result = resolve_scope_path("a/b.py", Path::new("/repo"), &keep, &[]);
        assert_eq!(result, (None, false));
    }

    // ── top_level_dirs ───────────────────────────────────────────────

    #[test]
    fn top_level_dirs_excludes_tool_working_dirs_and_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("src")).unwrap();
        std::fs::create_dir(dir.path().join("checkpoints")).unwrap();
        std::fs::create_dir(dir.path().join("security-scan")).unwrap();
        std::fs::write(dir.path().join("README.md"), "").unwrap();
        assert_eq!(top_level_dirs(dir.path()), vec!["src".to_string()]);
    }

    #[test]
    fn top_level_dirs_nonexistent_root_is_empty_not_a_panic() {
        assert!(top_level_dirs(Path::new("/nonexistent/does-not-exist")).is_empty());
    }

    // ── unwrap_container ─────────────────────────────────────────────

    #[test]
    fn unwrap_container_unwraps_a_single_key_wrapper() {
        let wrapped = json!({"context_package": {"language": "python", "modules": []}});
        let unwrapped = unwrap_container(wrapped);
        assert_eq!(unwrapped["language"], "python");
    }

    #[test]
    fn unwrap_container_leaves_a_direct_object_untouched() {
        let direct = json!({"language": "python"});
        assert_eq!(unwrap_container(direct.clone()), direct);
    }

    #[test]
    fn unwrap_container_leaves_a_multi_key_object_untouched() {
        let multi = json!({"a": {"language": "x"}, "b": 1});
        assert_eq!(unwrap_container(multi.clone()), multi);
    }

    #[test]
    fn unwrap_container_does_not_unwrap_when_inner_lacks_recognizable_keys() {
        let wrapped = json!({"wrapper": {"unrelated": true}});
        assert_eq!(unwrap_container(wrapped.clone()), wrapped);
    }

    #[test]
    fn unwrap_container_non_object_input_is_unchanged() {
        let arr = json!([1, 2, 3]);
        assert_eq!(unwrap_container(arr.clone()), arr);
    }

    #[test]
    fn unwrap_container_inner_non_object_value_is_unchanged() {
        let wrapped = json!({"key": "just a string"});
        assert_eq!(unwrap_container(wrapped.clone()), wrapped);
    }

    #[test]
    fn unwrap_container_recognizes_modules_or_entry_points_key_too() {
        let wrapped_modules = json!({"x": {"modules": []}});
        assert_eq!(unwrap_container(wrapped_modules)["modules"], json!([]));
        let wrapped_eps = json!({"x": {"entry_points": []}});
        assert_eq!(unwrap_container(wrapped_eps)["entry_points"], json!([]));
    }

    // ── scope_filter ──────────────────────────────────────────────────

    #[test]
    fn scope_filter_drops_sinks_and_entry_points_outside_ground_truth() {
        let dir = tempfile::tempdir().unwrap();
        let mut data = json!({
            "unsafe_sinks": [{"file": "a.py", "line": 1, "function": "f"}, {"file": "missing.py", "line": 2, "function": "g"}],
            "entry_points": [{"file": "a.py", "function": "h"}, {"file": "missing.py", "function": "i"}],
        });
        scope_filter(&mut data, dir.path(), &["a.py".to_string()]);
        assert_eq!(data["unsafe_sinks"].as_array().unwrap().len(), 1);
        assert_eq!(data["entry_points"].as_array().unwrap().len(), 1);
        assert_eq!(data["unsafe_sinks"][0]["file"], "a.py");
    }

    #[test]
    fn scope_filter_missing_keys_become_empty_arrays() {
        let dir = tempfile::tempdir().unwrap();
        let mut data = json!({});
        scope_filter(&mut data, dir.path(), &[]);
        assert_eq!(data["unsafe_sinks"], json!([]));
        assert_eq!(data["entry_points"], json!([]));
    }

    #[test]
    fn scope_filter_module_files_filtered_but_module_itself_kept() {
        let dir = tempfile::tempdir().unwrap();
        let mut data = json!({
            "modules": [{"name": "core", "files": ["a.py", "missing.py"]}],
        });
        scope_filter(&mut data, dir.path(), &["a.py".to_string()]);
        assert_eq!(data["modules"].as_array().unwrap().len(), 1);
        assert_eq!(data["modules"][0]["files"], json!(["a.py"]));
    }

    #[test]
    fn scope_filter_skips_a_non_object_module_entry_without_panicking() {
        let dir = tempfile::tempdir().unwrap();
        let mut data = json!({
            "modules": ["not a module object", {"name": "core", "files": ["a.py"]}],
        });
        scope_filter(&mut data, dir.path(), &["a.py".to_string()]);
        let modules = data["modules"].as_array().unwrap();
        assert_eq!(modules.len(), 2);
        assert_eq!(modules[0], json!("not a module object"));
        assert_eq!(modules[1]["files"], json!(["a.py"]));
    }

    #[test]
    fn scope_filter_resolves_unprefixed_path_via_top_level_dir() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("svc1")).unwrap();
        let mut data = json!({
            "unsafe_sinks": [{"file": "a.py", "line": 1, "function": "f"}],
        });
        scope_filter(&mut data, dir.path(), &["svc1/a.py".to_string()]);
        assert_eq!(data["unsafe_sinks"][0]["file"], "svc1/a.py");
    }

    #[test]
    fn scope_filter_non_object_data_is_a_no_op() {
        let dir = tempfile::tempdir().unwrap();
        let mut data = json!([1, 2, 3]);
        scope_filter(&mut data, dir.path(), &[]);
        assert_eq!(data, json!([1, 2, 3]));
    }

    // ── extract_function_names ───────────────────────────────────────

    #[test]
    fn extract_function_names_pulls_non_empty_function_fields() {
        let data = json!({"entry_points": [{"function": "handle"}, {"function": ""}, {}]});
        assert_eq!(
            extract_function_names(&data, "entry_points"),
            vec!["handle".to_string()]
        );
    }

    #[test]
    fn extract_function_names_missing_key_is_empty() {
        assert!(extract_function_names(&json!({}), "entry_points").is_empty());
    }

    // ── parse_call_graph ──────────────────────────────────────────────

    #[test]
    fn parse_call_graph_extracts_string_callees() {
        let data = json!({"call_graph": {"f": ["g", "h"]}});
        let cg = parse_call_graph(&data);
        assert_eq!(cg.get("f"), Some(&vec!["g".to_string(), "h".to_string()]));
    }

    #[test]
    fn parse_call_graph_drops_non_array_values_and_non_string_callees() {
        let data = json!({"call_graph": {"f": ["g", 5, null], "h": "not-an-array"}});
        let cg = parse_call_graph(&data);
        assert_eq!(cg.get("f"), Some(&vec!["g".to_string()]));
        assert!(!cg.contains_key("h"));
    }

    #[test]
    fn parse_call_graph_missing_key_is_empty() {
        assert!(parse_call_graph(&json!({})).is_empty());
    }

    // ── language_fallback ─────────────────────────────────────────────

    #[test]
    fn language_fallback_majority_vote() {
        let files = vec!["a.py".to_string(), "b.py".to_string(), "c.rs".to_string()];
        assert_eq!(language_fallback(&files), "python");
    }

    #[test]
    fn language_fallback_tie_breaks_to_first_encountered() {
        let files = vec!["a.rs".to_string(), "b.py".to_string()];
        assert_eq!(language_fallback(&files), "rust");
    }

    #[test]
    fn language_fallback_no_recognized_extension_is_unknown() {
        let files = vec!["README".to_string(), "Makefile".to_string()];
        assert_eq!(language_fallback(&files), "unknown");
    }

    #[test]
    fn language_fallback_empty_files_is_unknown() {
        assert_eq!(language_fallback(&[]), "unknown");
    }

    // ── advisory_skip_dirs ────────────────────────────────────────────

    #[test]
    fn advisory_skip_dirs_includes_defaults_and_config_additions_sorted() {
        let s = advisory_skip_dirs(&["my_custom_dir".to_string()]);
        assert!(s.contains("my_custom_dir"));
        assert!(s.contains("node_modules"));
        let parts: Vec<&str> = s.split(", ").collect();
        let mut sorted_parts = parts.clone();
        sorted_parts.sort();
        assert_eq!(parts, sorted_parts);
    }

    #[test]
    fn advisory_skip_dirs_config_addition_is_lowercased() {
        let s = advisory_skip_dirs(&["MyDir".to_string()]);
        assert!(s.contains("mydir"));
        assert!(!s.contains("MyDir"));
    }

    // ── seed_repo_kinds ────────────────────────────────────────────────

    #[test]
    fn seed_repo_kinds_network_entry_point_yields_web_api() {
        let seed = SeedPackage {
            entry_points: vec![bc_model::EntryPoint {
                file: "a.py".to_string(),
                function: "f".to_string(),
                kind: EntryPointKind::Network,
                reachable_from_unauth: false,
            }],
            ..Default::default()
        };
        assert!(seed_repo_kinds(&seed, &[]).contains("web-api"));
    }

    #[test]
    fn seed_repo_kinds_reachable_from_unauth_yields_web_api_even_with_other_kind() {
        let seed = SeedPackage {
            entry_points: vec![bc_model::EntryPoint {
                file: "a.py".to_string(),
                function: "f".to_string(),
                kind: EntryPointKind::Cli,
                reachable_from_unauth: true,
            }],
            ..Default::default()
        };
        assert!(seed_repo_kinds(&seed, &[]).contains("web-api"));
    }

    #[test]
    fn seed_repo_kinds_service_hint_filename_yields_service() {
        let seed = SeedPackage::default();
        let files = vec!["deploy/Dockerfile".to_string()];
        assert!(seed_repo_kinds(&seed, &files).contains("service"));
    }

    #[test]
    fn seed_repo_kinds_webapp_suffix_yields_web_app() {
        let seed = SeedPackage::default();
        let files = vec!["ui/Page.JSX".to_string()];
        assert!(seed_repo_kinds(&seed, &files).contains("web-app"));
    }

    #[test]
    fn seed_repo_kinds_defaults_to_library_when_nothing_matches() {
        let seed = SeedPackage::default();
        let files = vec!["src/lib.py".to_string()];
        assert_eq!(
            seed_repo_kinds(&seed, &files),
            BTreeSet::from(["library".to_string()])
        );
    }

    // ── should_escalate_gap_fill ─────────────────────────────────────

    fn many_source_files(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("src/f{i}.py")).collect()
    }

    #[test]
    fn should_escalate_gap_fill_false_under_the_source_file_threshold() {
        let seed = SeedPackage::default();
        let (escalate, reason) = should_escalate_gap_fill(&seed, &many_source_files(10));
        assert!(!escalate);
        assert!(reason.contains("<= 500"));
    }

    #[test]
    fn should_escalate_gap_fill_false_when_repo_kind_is_library_only() {
        let seed = SeedPackage::default();
        let (escalate, reason) = should_escalate_gap_fill(&seed, &many_source_files(501));
        assert!(!escalate);
        assert!(reason.contains("repo_kind"));
    }

    #[test]
    fn should_escalate_gap_fill_false_when_entry_points_below_ten() {
        let seed = SeedPackage {
            entry_points: vec![bc_model::EntryPoint {
                file: "src/f0.py".to_string(),
                function: "f".to_string(),
                kind: EntryPointKind::Network,
                reachable_from_unauth: false,
            }],
            ..Default::default()
        };
        let (escalate, reason) = should_escalate_gap_fill(&seed, &many_source_files(501));
        assert!(!escalate);
        assert!(reason.contains("entry_points"));
    }

    #[test]
    fn should_escalate_gap_fill_false_when_sinks_at_or_above_five() {
        let entry_points = (0..10)
            .map(|i| bc_model::EntryPoint {
                file: format!("src/f{i}.py"),
                function: "f".to_string(),
                kind: EntryPointKind::Network,
                reachable_from_unauth: false,
            })
            .collect();
        let unsafe_sinks = (0..5)
            .map(|i| Sink {
                file: format!("src/f{i}.py"),
                line: 1,
                function: "sink".to_string(),
                snippet: String::new(),
                cwe: Vec::new(),
            })
            .collect();
        let seed = SeedPackage {
            entry_points,
            unsafe_sinks,
            ..Default::default()
        };
        let (escalate, reason) = should_escalate_gap_fill(&seed, &many_source_files(501));
        assert!(!escalate);
        assert!(reason.contains("sinks"));
    }

    #[test]
    fn should_escalate_gap_fill_true_when_every_predicate_holds() {
        let entry_points = (0..10)
            .map(|i| bc_model::EntryPoint {
                file: format!("src/f{i}.py"),
                function: "f".to_string(),
                kind: EntryPointKind::Network,
                reachable_from_unauth: false,
            })
            .collect();
        let seed = SeedPackage {
            entry_points,
            unsafe_sinks: Vec::new(),
            ..Default::default()
        };
        let (escalate, reason) = should_escalate_gap_fill(&seed, &many_source_files(501));
        assert!(escalate);
        assert!(reason.contains("source_files"));
    }

    // ── merge_seed_into_data / apply_seed_call_graph ─────────────────

    #[test]
    fn merge_seed_into_data_non_object_data_is_a_no_op() {
        let dir = tempfile::tempdir().unwrap();
        let mut data = json!([1, 2, 3]);
        let seed = SeedPackage {
            entry_points: vec![bc_model::EntryPoint {
                file: "a.py".to_string(),
                function: "f".to_string(),
                kind: EntryPointKind::Network,
                reachable_from_unauth: false,
            }],
            ..Default::default()
        };
        merge_seed_into_data(&mut data, dir.path(), &["a.py".to_string()], &seed);
        assert_eq!(data, json!([1, 2, 3]));
    }

    /// `resolve_in_scope` only keeps a path that's in the ground-truth
    /// inventory, so the tempdir needs the files to actually exist for a
    /// merge test to be meaningful about anything but the filtering.
    fn seed_paths_fixture(paths: Vec<Vec<&str>>) -> SeedPackage {
        SeedPackage {
            taint_paths: paths
                .into_iter()
                .map(|p| p.into_iter().map(str::to_string).collect())
                .collect(),
            ..Default::default()
        }
    }

    fn seed_ep(file: &str, function: &str) -> bc_model::EntryPoint {
        bc_model::EntryPoint {
            file: file.to_string(),
            function: function.to_string(),
            kind: EntryPointKind::Network,
            reachable_from_unauth: true,
        }
    }

    fn evidence(source_ref: &str, sink_ref: &str) -> TaintEvidencePath {
        TaintEvidencePath {
            source_ref: source_ref.to_string(),
            sink_ref: sink_ref.to_string(),
            path_funcs: Vec::new(),
            edges: Vec::new(),
            sink_cwe: Vec::new(),
            sanitized: false,
        }
    }

    fn edge(file: &str, function_qnode: &str, src_q: &str, dst_q: &str) -> TaintTransferEdge {
        TaintTransferEdge {
            file: file.to_string(),
            line: 4,
            function_qnode: function_qnode.to_string(),
            src: bc_model::TaintSymbolRef {
                qnode: src_q.to_string(),
                symbol: "raw".to_string(),
                kind: "local".to_string(),
            },
            dst: bc_model::TaintSymbolRef {
                qnode: dst_q.to_string(),
                symbol: "arg0".to_string(),
                kind: "arg".to_string(),
            },
            transfer_kind: "local_to_sink".to_string(),
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

    #[test]
    fn seed_taint_evidence_is_resolved_against_the_in_scope_inventory() {
        let dir = tempfile::tempdir().unwrap();
        let mut data = json!({});
        let seed = SeedPackage {
            taint_evidence: vec![TaintEvidencePath {
                source_ref: "src/a.py:3".to_string(),
                sink_ref: "src/a.py:9".to_string(),
                path_funcs: vec!["src/a.py::f".to_string(), "vendor/z.py::g".to_string()],
                edges: vec![
                    edge("src/a.py", "src/a.py::f", "src/a.py::f", "src/a.py::f"),
                    // Out of scope -> the edge itself is dropped.
                    edge(
                        "vendor/z.py",
                        "vendor/z.py::g",
                        "src/a.py::f",
                        "src/a.py::f",
                    ),
                    // In scope, but its qnodes are not -> kept verbatim.
                    edge(
                        "src/a.py",
                        "vendor/z.py::g",
                        "vendor/z.py::g",
                        "vendor/z.py::g",
                    ),
                ],
                sink_cwe: vec!["CWE-78".to_string()],
                sanitized: true,
            }],
            ..Default::default()
        };
        merge_seed_into_data(&mut data, dir.path(), &["src/a.py".to_string()], &seed);
        let ev = data["seed_taint_evidence"].as_array().unwrap();
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0]["source_ref"], "src/a.py:3");
        assert_eq!(ev[0]["sink_ref"], "src/a.py:9");
        assert_eq!(
            ev[0]["path_funcs"].as_array().unwrap(),
            &vec![json!("src/a.py::f")]
        );
        assert_eq!(
            ev[0]["sink_cwe"].as_array().unwrap(),
            &vec![json!("CWE-78")]
        );
        // Python's own merge drops `sanitized`; this port carries it.
        assert_eq!(ev[0]["sanitized"], true);
        let edges = ev[0]["edges"].as_array().unwrap();
        assert_eq!(edges.len(), 2);
        assert_eq!(edges[0]["file"], "src/a.py");
        assert_eq!(edges[0]["function_qnode"], "src/a.py::f");
        assert_eq!(edges[0]["src"]["qnode"], "src/a.py::f");
        assert_eq!(edges[0]["dst"]["qnode"], "src/a.py::f");
        assert_eq!(edges[1]["function_qnode"], "vendor/z.py::g");
        assert_eq!(edges[1]["src"]["qnode"], "vendor/z.py::g");
    }

    #[test]
    fn merged_seed_evidence_round_trips_into_a_context_package() {
        // The load-bearing integration check for this plane: the JSON the
        // merge writes has to deserialize into the very
        // `ContextPackage::seed_taint_evidence` that S4's
        // `STRUCTURED TAINT EVIDENCE` block and
        // `bc_repo_analysis::taint`'s seed-path promotion read.
        let dir = tempfile::tempdir().unwrap();
        let mut data = json!({"repo_root": "/r", "language": "python"});
        let seed = SeedPackage {
            taint_evidence: vec![TaintEvidencePath {
                source_ref: "src/a.py:3".to_string(),
                sink_ref: "src/a.py:9".to_string(),
                path_funcs: vec!["src/a.py::f".to_string()],
                edges: vec![edge(
                    "src/a.py",
                    "src/a.py::f",
                    "src/a.py::f",
                    "src/a.py::f",
                )],
                sink_cwe: vec!["CWE-78".to_string()],
                sanitized: false,
            }],
            ..Default::default()
        };
        merge_seed_into_data(&mut data, dir.path(), &["src/a.py".to_string()], &seed);
        let ctx: bc_model::ContextPackage = serde_json::from_value(data).unwrap();
        assert_eq!(ctx.seed_taint_evidence.len(), 1);
        let ev = &ctx.seed_taint_evidence[0];
        assert_eq!(ev.source_ref, "src/a.py:3");
        assert_eq!(ev.path_funcs, vec!["src/a.py::f".to_string()]);
        assert_eq!(ev.sink_cwe, vec!["CWE-78".to_string()]);
        assert_eq!(ev.edges.len(), 1);
        assert_eq!(ev.edges[0].transfer_kind, "local_to_sink");
        assert_eq!(ev.edges[0].src.symbol, "raw");
        assert_eq!(ev.edges[0].dst.kind, "arg");
    }

    #[test]
    fn seed_evidence_whose_endpoint_falls_out_of_scope_is_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let mut data = json!({});
        let seed = SeedPackage {
            taint_evidence: vec![
                evidence("vendor/z.py:3", "src/a.py:9"),
                evidence("src/a.py:3", "vendor/z.py:9"),
            ],
            ..Default::default()
        };
        merge_seed_into_data(&mut data, dir.path(), &["src/a.py".to_string()], &seed);
        assert!(data["seed_taint_evidence"].as_array().unwrap().is_empty());
    }

    #[test]
    fn a_qnode_style_source_ref_keeps_its_symbol_tail() {
        let dir = tempfile::tempdir().unwrap();
        let mut data = json!({});
        let seed = SeedPackage {
            taint_evidence: vec![evidence("src/a.py::f", "src/a.py")],
            ..Default::default()
        };
        merge_seed_into_data(&mut data, dir.path(), &["src/a.py".to_string()], &seed);
        let ev = &data["seed_taint_evidence"].as_array().unwrap()[0];
        // No trailing `:line` on either ref: both resolve bare.
        assert_eq!(ev["source_ref"], "src/a.py::f");
        assert_eq!(ev["sink_ref"], "src/a.py");
    }

    #[test]
    fn an_empty_seed_clears_any_stale_evidence_key() {
        let dir = tempfile::tempdir().unwrap();
        let mut data = json!({"seed_taint_evidence": [{"source_ref": "old"}]});
        merge_seed_into_data(
            &mut data,
            dir.path(),
            &["src/a.py".to_string()],
            &SeedPackage::default(),
        );
        assert!(data["seed_taint_evidence"].as_array().unwrap().is_empty());
    }

    #[test]
    fn seed_sinks_are_merged_into_data_that_has_no_unsafe_sinks_key_yet() {
        let dir = tempfile::tempdir().unwrap();
        let mut data = json!({});
        let seed = SeedPackage {
            unsafe_sinks: vec![Sink {
                file: "src/a.py".to_string(),
                line: 12,
                function: "run".to_string(),
                snippet: "exec(q)".to_string(),
                cwe: vec!["CWE-78".to_string()],
            }],
            ..Default::default()
        };
        merge_seed_into_data(&mut data, dir.path(), &["src/a.py".to_string()], &seed);
        let sinks = data["unsafe_sinks"].as_array().unwrap();
        assert_eq!(sinks.len(), 1);
        assert_eq!(sinks[0]["file"], "src/a.py");
        assert_eq!(sinks[0]["line"], 12);
    }

    #[test]
    fn framework_entry_points_are_merged_alongside_the_plain_ones() {
        let dir = tempfile::tempdir().unwrap();
        let mut data = json!({});
        let seed = SeedPackage {
            entry_points: vec![seed_ep("src/a.py", "main")],
            framework_entry_points: vec![
                seed_ep("src/b.py", "route_handler"),
                // Out of scope -> dropped, same as a plain entry point.
                seed_ep("vendor/c.py", "vendor_route"),
            ],
            ..Default::default()
        };
        merge_seed_into_data(
            &mut data,
            dir.path(),
            &["src/a.py".to_string(), "src/b.py".to_string()],
            &seed,
        );
        let eps = data["entry_points"].as_array().unwrap();
        let names: Vec<&str> = eps
            .iter()
            .map(|e| e["function"].as_str().unwrap())
            .collect();
        // Framework routes come first: they win the `(file, function)` dedup.
        assert_eq!(names, vec!["route_handler", "main"]);
    }

    #[test]
    fn a_framework_entry_point_wins_the_dedup_over_its_plain_twin() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("page.php"), "<?php\n").unwrap();
        let mut plain = seed_ep("page.php", "__main__");
        plain.kind = EntryPointKind::Other;
        plain.reachable_from_unauth = false;
        let mut framework = seed_ep("page.php", "__main__");
        framework.kind = EntryPointKind::Framework;
        framework.reachable_from_unauth = true;
        let seed = SeedPackage {
            entry_points: vec![plain],
            framework_entry_points: vec![framework],
            ..SeedPackage::default()
        };
        let mut data = json!({"entry_points": []});
        merge_seed_into_data(&mut data, dir.path(), &["page.php".to_string()], &seed);
        let eps = data["entry_points"].as_array().unwrap();
        assert_eq!(eps.len(), 1);
        assert_eq!(eps[0]["kind"], "framework");
        assert_eq!(eps[0]["reachable_from_unauth"], true);
    }

    #[test]
    fn survey_framework_labels_are_demoted_once_the_seed_found_routes() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("ctl.php"), "<?php\n").unwrap();
        std::fs::write(dir.path().join("web.php"), "<?php\n").unwrap();
        let mut route = seed_ep("web.php", "Ctl@run");
        route.kind = EntryPointKind::Framework;
        route.reachable_from_unauth = false;
        let seed = SeedPackage {
            framework_entry_points: vec![route],
            ..SeedPackage::default()
        };
        // The survey model guessed the same handler is an open framework
        // route (`spring` is an alias of `framework`); a CLI entry stays.
        let mut data = json!({"entry_points": [
            {"file": "ctl.php", "function": "run", "kind": "spring", "reachable_from_unauth": true},
            {"file": "tool.php", "function": "main", "kind": "cli", "reachable_from_unauth": true}
        ]});
        merge_seed_into_data(
            &mut data,
            dir.path(),
            &["ctl.php".to_string(), "web.php".to_string()],
            &seed,
        );
        let eps = data["entry_points"].as_array().unwrap();
        assert_eq!(eps[0]["kind"], "other");
        assert_eq!(eps[0]["reachable_from_unauth"], true);
        assert_eq!(eps[1]["kind"], "cli");
        assert_eq!(eps[2]["kind"], "framework");
        assert_eq!(eps[2]["reachable_from_unauth"], false);

        // Without a seed route the survey's label is left alone.
        let mut untouched = json!({"entry_points": [
            {"file": "ctl.php", "function": "run", "kind": "framework", "reachable_from_unauth": true}
        ]});
        merge_seed_into_data(
            &mut untouched,
            dir.path(),
            &["ctl.php".to_string()],
            &SeedPackage::default(),
        );
        assert_eq!(untouched["entry_points"][0]["kind"], "framework");
    }

    #[test]
    fn a_framework_entry_point_duplicating_a_plain_one_is_not_added_twice() {
        // Python appends its framework set on top of the extend that
        // already carried it, double-counting every route.
        let dir = tempfile::tempdir().unwrap();
        let mut data = json!({});
        let seed = SeedPackage {
            entry_points: vec![seed_ep("src/a.py", "handler")],
            framework_entry_points: vec![seed_ep("src/a.py", "handler")],
            ..Default::default()
        };
        merge_seed_into_data(&mut data, dir.path(), &["src/a.py".to_string()], &seed);
        assert_eq!(data["entry_points"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn seed_taint_paths_are_merged_with_hops_re_resolved_in_scope() {
        let dir = tempfile::tempdir().unwrap();
        let mut data = json!({});
        let seed = seed_paths_fixture(vec![vec!["src/a.py:10", "src/b.py:42"]]);
        merge_seed_into_data(
            &mut data,
            dir.path(),
            &["src/a.py".to_string(), "src/b.py".to_string()],
            &seed,
        );
        assert_eq!(
            data["seed_taint_paths"],
            json!([["src/a.py:10", "src/b.py:42"]])
        );
    }

    #[test]
    fn a_seed_taint_path_survives_an_out_of_scope_hop_while_two_remain() {
        // Config-dedup can drop a file after S0 ran; Python keeps the
        // path so long as >=2 hops still resolve.
        let dir = tempfile::tempdir().unwrap();
        let mut data = json!({});
        let seed = seed_paths_fixture(vec![vec![
            "src/a.py:1",
            "vendor/dropped.py:2",
            "src/b.py:3",
        ]]);
        merge_seed_into_data(
            &mut data,
            dir.path(),
            &["src/a.py".to_string(), "src/b.py".to_string()],
            &seed,
        );
        assert_eq!(
            data["seed_taint_paths"],
            json!([["src/a.py:1", "src/b.py:3"]])
        );
    }

    #[test]
    fn a_seed_taint_path_reduced_below_two_hops_is_dropped_entirely() {
        let dir = tempfile::tempdir().unwrap();
        let mut data = json!({});
        let seed = seed_paths_fixture(vec![vec!["src/a.py:1", "vendor/dropped.py:2"]]);
        merge_seed_into_data(&mut data, dir.path(), &["src/a.py".to_string()], &seed);
        assert_eq!(data["seed_taint_paths"], json!([]));
    }

    #[test]
    fn a_seed_taint_hop_without_a_line_number_keeps_its_bare_path() {
        // `rpartition(":")` yields an empty separator for a colon-less
        // hop, which Python emits bare rather than dropping.
        let dir = tempfile::tempdir().unwrap();
        let mut data = json!({});
        let seed = seed_paths_fixture(vec![vec!["src/a.py", "src/b.py:9"]]);
        merge_seed_into_data(
            &mut data,
            dir.path(),
            &["src/a.py".to_string(), "src/b.py".to_string()],
            &seed,
        );
        assert_eq!(
            data["seed_taint_paths"],
            json!([["src/a.py", "src/b.py:9"]])
        );
    }

    #[test]
    fn a_seed_taint_hop_with_an_empty_file_half_falls_back_to_the_whole_hop() {
        // `":12".rpartition(":")` gives an empty file half; Python's
        // `f or hop` resolves the raw hop instead of the empty string.
        // Nothing named `:12` is ever in scope, so the hop drops — and
        // with it the path, which is the point: this must not panic or
        // silently resolve to the repo root.
        let dir = tempfile::tempdir().unwrap();
        let mut data = json!({});
        let seed = seed_paths_fixture(vec![vec![":12", "src/b.py:9"]]);
        merge_seed_into_data(&mut data, dir.path(), &["src/b.py".to_string()], &seed);
        assert_eq!(data["seed_taint_paths"], json!([]));
    }

    #[test]
    fn an_empty_seed_clears_seed_taint_paths_rather_than_leaving_a_stale_value() {
        let dir = tempfile::tempdir().unwrap();
        let mut data = json!({"seed_taint_paths": [["stale.py:1", "stale.py:2"]]});
        merge_seed_into_data(&mut data, dir.path(), &[], &SeedPackage::default());
        assert_eq!(data["seed_taint_paths"], json!([]));
    }

    #[test]
    fn apply_seed_call_graph_non_object_data_is_a_no_op() {
        let mut data = json!([1, 2, 3]);
        let seed = SeedPackage {
            call_graph: std::collections::BTreeMap::from([(
                "f".to_string(),
                vec!["g".to_string()],
            )]),
            ..Default::default()
        };
        apply_seed_call_graph(&mut data, &seed);
        assert_eq!(data, json!([1, 2, 3]));
    }

    #[test]
    fn apply_ts_graph_result_non_object_data_is_a_no_op() {
        let mut data = json!([1, 2, 3]);
        let result = bc_repo_analysis::TsGraphResult {
            call_graph: std::collections::BTreeMap::from([(
                "a.py::f".to_string(),
                vec!["a.py::g".to_string()],
            )]),
            ..Default::default()
        };
        apply_ts_graph_result(&mut data, &result);
        assert_eq!(data, json!([1, 2, 3]));
    }

    #[test]
    fn merge_graph_artifacts_non_object_data_is_a_no_op() {
        let mut data = json!([1, 2, 3]);
        merge_graph_artifacts(
            &mut data,
            std::collections::BTreeMap::from([(
                "a.py::f".to_string(),
                vec!["a.py::g".to_string()],
            )]),
            std::collections::BTreeMap::new(),
            std::collections::BTreeMap::new(),
        );
        assert_eq!(data, json!([1, 2, 3]));
    }
}
