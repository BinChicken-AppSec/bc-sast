use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::Path;

use crate::evidence::TaintEvidencePath;
use crate::families::PROTECTED_SEMANTIC_FAMILIES;
use crate::scan::{CallSite, FileIndex};

const BASE_INTER_HOPS: usize = 3;
const HIGH_RISK_INTER_HOPS: usize = 5;
pub const DEFAULT_MAX_TARGETS_PER_CALL: usize = 3;

fn high_risk_cwe() -> &'static [&'static str] {
    &[
        "22", "78", "79", "89", "90", "94", "95", "434", "502", "601", "611", "918",
    ]
}

fn source_kind_compat(src_kind: &str) -> Option<&'static [&'static str]> {
    const INJECTION_ISH: &[&str] = &[
        "cmd",
        "crypto",
        "format",
        "memory",
        "credentials",
        "deserialize",
        "dyn-eval",
        "el-injection",
        "header",
        "intent-redirection",
        "jndi",
        "ldap",
        "log-injection",
        "path",
        "pending-intent",
        "redirect",
        "regex",
        "sql",
        "ssrf",
        "template",
        "xpath",
        "xss",
        "xxe",
    ];
    Some(match src_kind {
        "network" | "ipc" | "http" => INJECTION_ISH,
        "cli" | "stdin" => &[
            "cmd",
            "crypto",
            "format",
            "memory",
            "credentials",
            "deserialize",
            "dyn-eval",
            "el-injection",
            "jndi",
            "ldap",
            "log-injection",
            "path",
            "regex",
            "sql",
            "ssrf",
            "template",
            "xpath",
            "xxe",
        ],
        "filesystem" | "file" => &[
            "cmd",
            "crypto",
            "format",
            "memory",
            "credentials",
            "deserialize",
            "dyn-eval",
            "jndi",
            "ldap",
            "path",
            "regex",
            "sql",
            "template",
            "xpath",
            "xxe",
        ],
        "env" => &[
            "cmd",
            "crypto",
            "format",
            "memory",
            "credentials",
            "deserialize",
            "dyn-eval",
            "el-injection",
            "jndi",
            "ldap",
            "log-injection",
            "path",
            "redirect",
            "regex",
            "sql",
            "ssrf",
            "template",
            "xpath",
            "xxe",
        ],
        _ => return None,
    })
}

const GLOBAL_PATH_BUDGET: usize = 200;
const GLOBAL_PATH_BUDGET_MAX: usize = 500;

fn cwe_severity(cwe_num: &str) -> f64 {
    match cwe_num {
        "22" => 1.0,
        "78" => 1.0,
        "79" => 0.9,
        "89" => 1.0,
        "94" => 1.0,
        "95" => 0.8,
        "434" => 0.7,
        "502" => 1.0,
        "601" => 0.8,
        "611" => 0.6,
        "918" => 1.0,
        "80" => 0.9,
        "90" => 0.8,
        "269" => 0.7,
        _ => 0.5,
    }
}

pub fn cwe_num(cwe: &str) -> String {
    if cwe.is_empty() {
        return String::new();
    }
    let upper = cwe.to_uppercase();
    let Some(i) = upper.find("CWE-") else {
        return String::new();
    };
    upper[i + 4..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect()
}

fn is_high_risk(cs: &CallSite) -> bool {
    let c = cwe_num(&cs.cwe);
    if high_risk_cwe().contains(&c.as_str()) {
        return true;
    }
    let k = cs.kind.to_lowercase();
    [
        "auth", "deserial", "command", "inject", "exec", "path", "sql", "ssrf",
    ]
    .iter()
    .any(|tok| k.contains(tok))
}

fn prefix_score(a: &str, b: &str) -> usize {
    let ap: Vec<_> = Path::new(a)
        .parent()
        .map(|p| p.components().collect())
        .unwrap_or_default();
    let bp: Vec<_> = Path::new(b)
        .parent()
        .map(|p| p.components().collect())
        .unwrap_or_default();
    ap.iter().zip(bp.iter()).take_while(|(x, y)| x == y).count()
}

fn compatible_taint_pair(source: &CallSite, sink: &CallSite) -> bool {
    if PROTECTED_SEMANTIC_FAMILIES.contains(&sink.semantic_family.to_lowercase().as_str()) {
        return true;
    }
    let src_kind = source.kind.trim().to_lowercase();
    let sink_kind = sink.kind.trim().to_lowercase();
    if src_kind.is_empty() || src_kind == "other" || sink_kind.is_empty() || sink_kind == "other" {
        return true;
    }
    match source_kind_compat(&src_kind) {
        Some(allowed) => allowed.contains(&sink_kind.as_str()),
        None => true,
    }
}

pub const MODULE_SCOPE: &str = "<module>";

pub fn fn_id(file: &str, fn_name: &str) -> String {
    let name = if fn_name.is_empty() {
        MODULE_SCOPE
    } else {
        fn_name
    };
    format!("{file}::{name}")
}

fn fid_name(fid: &str) -> &str {
    fid.split_once("::").map(|(_, n)| n).unwrap_or(fid)
}

fn dedup_preserve_order(items: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    items
        .iter()
        .filter(|s| seen.insert((*s).clone()))
        .cloned()
        .collect()
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn resolve_called_fids(
    caller_file: &str,
    caller_fn: &str,
    receiver: &str,
    called_name: &str,
    fn_defs_by_name: &BTreeMap<String, Vec<String>>,
    fn_meta: &BTreeMap<String, (String, usize, usize)>,
    file_index: &BTreeMap<String, &FileIndex>,
    max_targets: usize,
) -> Vec<String> {
    let cands = dedup_preserve_order(
        fn_defs_by_name
            .get(called_name)
            .map(Vec::as_slice)
            .unwrap_or(&[]),
    );
    let through_other = !receiver.is_empty() && !matches!(receiver, "this" | "self");
    let self_fid = fn_id(caller_file, caller_fn);
    let cands: Vec<String> = if through_other {
        cands.into_iter().filter(|fid| *fid != self_fid).collect()
    } else {
        cands
    };
    if cands.is_empty() {
        return Vec::new();
    }
    if cands.len() == 1 {
        return cands;
    }

    let same_file: Vec<String> = cands
        .iter()
        .filter(|fid| fn_meta.get(*fid).map(|(f, _, _)| f.as_str()) == Some(caller_file))
        .cloned()
        .collect();
    if !same_file.is_empty() {
        return same_file.into_iter().take(max_targets).collect();
    }

    let hinted = if !receiver.is_empty() {
        file_index
            .get(caller_file)
            .and_then(|idx| idx.imports.get(receiver))
            .cloned()
            .unwrap_or_default()
    } else {
        String::new()
    };
    let hint_parts: Vec<String> = hinted
        .split('.')
        .filter(|p| !p.is_empty())
        .map(|p| p.to_lowercase())
        .collect();

    if receiver.is_empty() && hint_parts.is_empty() {
        return Vec::new();
    }

    let mut scored: Vec<(usize, String)> = cands
        .iter()
        .map(|fid| {
            let f = fn_meta.get(fid).map(|(f, _, _)| f.as_str()).unwrap_or("");
            let mut score = prefix_score(caller_file, f);
            if !hint_parts.is_empty() {
                let low = f.to_lowercase();
                score += hint_parts
                    .iter()
                    .filter(|p| low.contains(p.as_str()))
                    .count();
            }
            (score, fid.clone())
        })
        .collect();
    scored.sort_by_key(|(score, _)| std::cmp::Reverse(*score));

    let top = scored[0].0;
    scored
        .into_iter()
        .filter(|(score, _)| *score == top)
        .map(|(_, fid)| fid)
        .take(max_targets)
        .collect()
}

fn import_hint_matches(hinted: &str, callee_file: &str) -> bool {
    if hinted.is_empty() {
        return false;
    }
    if callee_file.contains(hinted) {
        return true;
    }
    let hint_parts: Vec<String> = hinted
        .split('.')
        .filter(|p| !p.is_empty())
        .map(|p| p.to_lowercase())
        .collect();
    if hint_parts.is_empty() {
        return false;
    }
    let callee_lower = callee_file.to_lowercase();
    let hint_matches = hint_parts
        .iter()
        .filter(|p| callee_lower.contains(p.as_str()))
        .count();
    hint_matches >= hint_parts.len() / 2
}

fn edge_confidence(
    caller_file: &str,
    callee_file: &str,
    receiver: &str,
    file_index: &BTreeMap<String, &FileIndex>,
) -> f64 {
    if caller_file == callee_file {
        return 1.0;
    }
    let hinted = (!receiver.is_empty())
        .then(|| {
            file_index
                .get(caller_file)
                .and_then(|idx| idx.imports.get(receiver))
        })
        .flatten();
    if hinted.is_some_and(|h| import_hint_matches(h, callee_file)) {
        return 0.9;
    }
    match prefix_score(caller_file, callee_file) {
        n if n >= 2 => 0.8,
        1 => 0.7,
        _ => 0.5,
    }
}

fn score_path(hops: usize, sink_cwe: &str) -> f64 {
    let conf_score = if hops == 1 {
        1.0
    } else if hops <= 3 {
        0.8
    } else {
        0.5
    };
    let sev = cwe_severity(&cwe_num(sink_cwe));
    let hop_penalty = 1.0 / hops.max(1) as f64;
    conf_score * sev * hop_penalty
}

fn extract_sink_family(sink: &CallSite) -> String {
    let cwe_n = cwe_num(&sink.cwe);
    let semantic = sink.semantic_family.trim().to_lowercase();
    if !semantic.is_empty() {
        format!("{cwe_n}:{semantic}")
    } else {
        format!("{cwe_n}:{}", sink.kind)
    }
}

fn effective_global_budget(
    taint_path_count: usize,
    source_count: usize,
    sink_count: usize,
) -> usize {
    let fanout = source_count * sink_count;
    if fanout < 600 && taint_path_count <= GLOBAL_PATH_BUDGET {
        GLOBAL_PATH_BUDGET
    } else if fanout >= 600 {
        GLOBAL_PATH_BUDGET_MAX.min(GLOBAL_PATH_BUDGET + 150)
    } else {
        GLOBAL_PATH_BUDGET_MAX.min(GLOBAL_PATH_BUDGET + 100)
    }
}

struct ScoredPath {
    score: f64,
    src_fn: String,
    sink_family: String,
    path: Vec<String>,
}

fn sink_semantic(sink_family: &str) -> &str {
    sink_family
        .split_once(':')
        .map(|(_, s)| s)
        .unwrap_or(sink_family)
}

fn filter_paths_by_budget(
    taint_paths: Vec<Vec<String>>,
    sources: &BTreeMap<String, Vec<CallSite>>,
    sinks: &BTreeMap<String, Vec<CallSite>>,
) -> Vec<Vec<String>> {
    if taint_paths.is_empty() {
        return taint_paths;
    }

    let mut scored_paths: Vec<ScoredPath> = Vec::new();
    for path in &taint_paths {
        if path.len() < 2 {
            continue;
        }
        let Some((src_file, src_line)) = parse_hop(&path[0]) else {
            scored_paths.push(ScoredPath {
                score: 0.5,
                src_fn: path[0].clone(),
                sink_family: "unknown".to_string(),
                path: path.clone(),
            });
            continue;
        };
        let Some((snk_file, snk_line)) = parse_hop(&path[path.len() - 1]) else {
            scored_paths.push(ScoredPath {
                score: 0.5,
                src_fn: src_file,
                sink_family: "unknown".to_string(),
                path: path.clone(),
            });
            continue;
        };

        let src_cs = sources
            .values()
            .flatten()
            .find(|cs| cs.file == src_file && cs.line == src_line);
        let snk_cs = sinks
            .values()
            .flatten()
            .find(|cs| cs.file == snk_file && cs.line == snk_line);
        let (Some(src_cs), Some(snk_cs)) = (src_cs, snk_cs) else {
            scored_paths.push(ScoredPath {
                score: 0.5,
                src_fn: src_file,
                sink_family: "unknown".to_string(),
                path: path.clone(),
            });
            continue;
        };

        let score = score_path(path.len() - 1, &snk_cs.cwe);
        let sink_family = extract_sink_family(snk_cs);
        let src_fn = if !src_cs.containing_fn.is_empty() {
            src_cs.containing_fn.clone()
        } else {
            format!("<{}:{}>", src_cs.file, src_cs.line)
        };
        scored_paths.push(ScoredPath {
            score,
            src_fn,
            sink_family,
            path: path.clone(),
        });
    }

    scored_paths.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let mut kept_by_source: BTreeMap<String, usize> = BTreeMap::new();
    const PER_SOURCE_LIMIT: usize = 5;
    let global_budget = effective_global_budget(
        taint_paths.len(),
        sources.values().map(Vec::len).sum(),
        sinks.values().map(Vec::len).sum(),
    );
    let mut kept_paths: Vec<Vec<String>> = Vec::new();
    let mut kept_pairs: BTreeSet<(String, String)> = BTreeSet::new();
    let mut protected_family_kept: BTreeSet<String> = BTreeSet::new();

    let mut floor: Vec<usize> = Vec::new();
    let mut floor_families: BTreeSet<&str> = BTreeSet::new();
    for (i, sp) in scored_paths.iter().enumerate() {
        if floor_families.insert(sp.sink_family.as_str()) {
            floor.push(i);
        }
    }
    if floor.len() > global_budget {
        floor.sort_by_key(|&i| {
            !PROTECTED_SEMANTIC_FAMILIES.contains(&sink_semantic(&scored_paths[i].sink_family))
        });
        floor.truncate(global_budget);
    }
    let mut floor_kept = vec![false; scored_paths.len()];
    for &i in &floor {
        let sp = &scored_paths[i];
        floor_kept[i] = true;
        kept_paths.push(sp.path.clone());
        *kept_by_source.entry(sp.src_fn.clone()).or_insert(0) += 1;
        kept_pairs.insert((sp.src_fn.clone(), sp.sink_family.clone()));
        let semantic = sink_semantic(&sp.sink_family);
        if PROTECTED_SEMANTIC_FAMILIES.contains(&semantic) {
            protected_family_kept.insert(semantic.to_string());
        }
    }

    for (i, sp) in scored_paths.into_iter().enumerate() {
        if floor_kept[i] {
            continue;
        }
        let pair = (sp.src_fn.clone(), sp.sink_family.clone());
        if kept_paths.len() >= global_budget && kept_pairs.contains(&pair) {
            continue;
        }
        if kept_pairs.contains(&pair)
            && kept_by_source.get(&sp.src_fn).copied().unwrap_or(0) >= PER_SOURCE_LIMIT
        {
            continue;
        }
        let semantic = sink_semantic(&sp.sink_family).to_string();
        if kept_paths.len() >= global_budget {
            let protected = PROTECTED_SEMANTIC_FAMILIES.contains(&semantic.as_str())
                && !protected_family_kept.contains(&semantic);
            if !protected {
                break;
            }
        }

        kept_paths.push(sp.path);
        *kept_by_source.entry(sp.src_fn).or_insert(0) += 1;
        kept_pairs.insert(pair);
        if PROTECTED_SEMANTIC_FAMILIES.contains(&semantic.as_str()) {
            protected_family_kept.insert(semantic);
        }
    }
    kept_paths
}

fn parse_hop(hop: &str) -> Option<(String, usize)> {
    let (file, line_str) = hop.rsplit_once(':')?;
    let line: usize = line_str.parse().ok()?;
    Some((file.to_string(), line))
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct TaintSeed {
    pub entry_points: Vec<crate::EntryPoint>,
    pub framework_entry_points: Vec<crate::EntryPoint>,
    pub unsafe_sinks: Vec<crate::Sink>,
    pub taint_paths: Vec<Vec<String>>,
    pub taint_evidence: Vec<TaintEvidencePath>,
    pub rule_cwe: BTreeMap<String, Vec<String>>,
    pub call_graph: BTreeMap<String, Vec<String>>,
    pub call_graph_files: BTreeMap<String, Vec<String>>,
    pub def_spans: BTreeMap<String, (usize, usize)>,
    pub call_graph_confidence: BTreeMap<(String, String), f64>,
}

fn evidence_for(
    source: &CallSite,
    sink: &CallSite,
    path_fids: &[String],
    facts: &crate::evidence::FactIndex,
    resolver: &crate::evidence::PathResolver,
) -> TaintEvidencePath {
    if facts.has_phase1_facts(path_fids) {
        if let Some(ev) =
            crate::evidence::build_taint_evidence_for_path(source, sink, path_fids, facts, resolver)
        {
            return ev;
        }
    }
    crate::evidence::fallback_evidence(source, sink, path_fids)
}

fn record_evidence(
    evidence: TaintEvidencePath,
    seen: &mut BTreeSet<(String, String, Vec<String>)>,
    out: &mut Vec<TaintEvidencePath>,
) {
    let key = (
        evidence.source_ref.clone(),
        evidence.sink_ref.clone(),
        evidence.path_funcs.clone(),
    );
    if seen.insert(key) {
        out.push(evidence);
    }
}

pub fn build_taint_paths(
    indices: &[FileIndex],
    rule_cwe: &BTreeMap<String, Vec<String>>,
    max_targets: usize,
) -> TaintSeed {
    let mut fn_source_hits: BTreeMap<String, Vec<CallSite>> = BTreeMap::new();
    let mut fn_sink_hits: BTreeMap<String, Vec<CallSite>> = BTreeMap::new();
    let mut fn_meta: BTreeMap<String, (String, usize, usize)> = BTreeMap::new();
    let mut fn_defs_by_name: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut fn_calls_out: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    let mut file_index: BTreeMap<String, &FileIndex> = BTreeMap::new();

    for idx in indices {
        file_index.insert(idx.file.clone(), idx);
        fn_meta.insert(fn_id(&idx.file, ""), (idx.file.clone(), 1, 1));
        for fd in &idx.functions {
            let fid = fn_id(&idx.file, &fd.name);
            fn_meta.insert(fid.clone(), (idx.file.clone(), fd.start_line, fd.end_line));
            fn_defs_by_name
                .entry(fd.name.clone())
                .or_default()
                .push(fid);
        }
        for cs in &idx.source_hits {
            fn_source_hits
                .entry(fn_id(&idx.file, &cs.containing_fn))
                .or_default()
                .push(cs.clone());
        }
        for cs in &idx.sink_hits {
            fn_sink_hits
                .entry(fn_id(&idx.file, &cs.containing_fn))
                .or_default()
                .push(cs.clone());
        }
        for (containing_fn, receiver, called_method) in &idx.call_edges {
            fn_calls_out
                .entry(fn_id(&idx.file, containing_fn))
                .or_default()
                .push((receiver.clone(), called_method.clone()));
        }
    }

    let mut call_graph: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut call_graph_confidence: BTreeMap<(String, String), f64> = BTreeMap::new();
    for (caller_fid, edges) in &fn_calls_out {
        let Some((caller_file, ..)) = fn_meta.get(caller_fid) else {
            continue;
        };
        let caller_file = caller_file.clone();
        for (receiver, called_name) in edges {
            for callee_fid in resolve_called_fids(
                &caller_file,
                fid_name(caller_fid),
                receiver,
                called_name,
                &fn_defs_by_name,
                &fn_meta,
                &file_index,
                max_targets,
            ) {
                if &callee_fid == caller_fid {
                    continue;
                }
                call_graph
                    .entry(caller_fid.clone())
                    .or_default()
                    .insert(callee_fid.clone());
                let callee_file = fn_meta
                    .get(&callee_fid)
                    .map(|(f, ..)| f.as_str())
                    .unwrap_or("");
                let conf = edge_confidence(&caller_file, callee_file, receiver, &file_index);
                call_graph_confidence.insert((caller_fid.clone(), callee_fid), conf);
            }
        }
    }

    let mut relevant_qnodes: BTreeSet<String> = call_graph.keys().cloned().collect();
    for vals in call_graph.values() {
        relevant_qnodes.extend(vals.iter().cloned());
    }
    relevant_qnodes.extend(fn_source_hits.keys().cloned());
    relevant_qnodes.extend(fn_sink_hits.keys().cloned());

    let mut call_graph_files: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut def_spans: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for fid in &relevant_qnodes {
        if fid_name(fid) == MODULE_SCOPE {
            continue;
        }
        let Some((file, start, end)) = fn_meta.get(fid) else {
            continue;
        };
        call_graph_files
            .entry(fid_name(fid).to_string())
            .or_default()
            .push(format!("{file}:{start}"));
        def_spans.insert(fid.clone(), (*start, *end));
    }
    for v in call_graph_files.values_mut() {
        v.sort();
    }

    let mut entry_points: Vec<crate::EntryPoint> = Vec::new();
    let mut unsafe_sinks: Vec<crate::Sink> = Vec::new();
    let mut taint_paths: Vec<Vec<String>> = Vec::new();
    let mut seen_ep: BTreeSet<(String, String)> = BTreeSet::new();
    let mut seen_sink: BTreeSet<(String, usize, String)> = BTreeSet::new();
    let mut seen_path: BTreeSet<Vec<String>> = BTreeSet::new();

    for idx in indices {
        for cs in &idx.sink_hits {
            let sink_fn = if !cs.containing_fn.is_empty() {
                cs.containing_fn.clone()
            } else {
                cs.method.clone()
            };
            let key = (cs.file.clone(), cs.line, sink_fn.clone());
            if !seen_sink.insert(key) {
                continue;
            }
            unsafe_sinks.push(crate::Sink {
                file: cs.file.clone(),
                line: cs.line,
                function: sink_fn,
                snippet: cs.snippet.clone(),
                cwe: if cs.cwe.is_empty() {
                    Vec::new()
                } else {
                    vec![cs.cwe.clone()]
                },
            });
        }
    }
    for idx in indices {
        for cs in &idx.source_hits {
            let scope = if !cs.containing_fn.is_empty() {
                cs.containing_fn.clone()
            } else {
                format!("<line-{}>", cs.line)
            };
            let key = (cs.file.clone(), scope.clone());
            if !seen_ep.insert(key) {
                continue;
            }
            entry_points.push(crate::EntryPoint {
                file: cs.file.clone(),
                function: scope,
                kind: if cs.kind.is_empty() {
                    "other".to_string()
                } else {
                    cs.kind.clone()
                },
                reachable_from_unauth: false,
            });
        }
    }

    let facts = crate::evidence::FactIndex::build(indices);
    let resolver = crate::evidence::PathResolver {
        fn_defs_by_name: &fn_defs_by_name,
        fn_meta: &fn_meta,
        file_index: &file_index,
        max_targets,
    };
    let mut taint_evidence: Vec<TaintEvidencePath> = Vec::new();
    let mut seen_evidence: BTreeSet<(String, String, Vec<String>)> = BTreeSet::new();

    for (fid, srcs) in &fn_source_hits {
        let Some(sinks) = fn_sink_hits.get(fid) else {
            continue;
        };
        for s in srcs {
            for k in sinks {
                if !compatible_taint_pair(s, k) {
                    continue;
                }
                let path_fids = vec![fid.clone()];
                let evidence = evidence_for(s, k, &path_fids, &facts, &resolver);
                let hop = vec![
                    format!("{}:{}", s.file, s.line),
                    format!("{}:{}", k.file, k.line),
                ];
                if !evidence.sanitized && seen_path.insert(hop.clone()) {
                    taint_paths.push(hop);
                }
                record_evidence(evidence, &mut seen_evidence, &mut taint_evidence);
            }
        }
    }

    for (src_fid, srcs) in &fn_source_hits {
        if !fn_meta.contains_key(src_fid) {
            continue;
        }
        let deep_mode = srcs.iter().any(is_high_risk);
        let max_hops = if deep_mode {
            HIGH_RISK_INTER_HOPS
        } else {
            BASE_INTER_HOPS
        };

        let mut queue: std::collections::VecDeque<(String, Vec<String>)> =
            std::collections::VecDeque::from([(src_fid.clone(), vec![src_fid.clone()])]);
        let mut visited: BTreeSet<String> = BTreeSet::from([src_fid.clone()]);
        while let Some((cur, path)) = queue.pop_front() {
            if path.len() - 1 > max_hops {
                continue;
            }
            let cur_file = fn_meta
                .get(&cur)
                .map(|(f, ..)| f.clone())
                .unwrap_or_default();
            let Some(edges) = fn_calls_out.get(&cur) else {
                continue;
            };
            for (receiver, called_name) in edges.clone() {
                for next_fid in resolve_called_fids(
                    &cur_file,
                    fid_name(&cur),
                    &receiver,
                    &called_name,
                    &fn_defs_by_name,
                    &fn_meta,
                    &file_index,
                    max_targets,
                ) {
                    if !visited.insert(next_fid.clone()) {
                        continue;
                    }
                    let mut new_path = path.clone();
                    new_path.push(next_fid.clone());
                    queue.push_back((next_fid.clone(), new_path.clone()));
                    let hop_count = new_path.len() - 1;
                    if hop_count > max_hops {
                        continue;
                    }
                    let Some(sinks_here) = fn_sink_hits.get(&next_fid) else {
                        continue;
                    };
                    for k in sinks_here {
                        if hop_count > BASE_INTER_HOPS && !is_high_risk(k) {
                            continue;
                        }
                        for s in srcs {
                            if !compatible_taint_pair(s, k) {
                                continue;
                            }
                            let evidence = evidence_for(s, k, &new_path, &facts, &resolver);
                            let mut hop_list = vec![format!("{}:{}", s.file, s.line)];
                            for fid in &new_path[1..] {
                                if let Some((f, start, _)) = fn_meta.get(fid) {
                                    hop_list.push(format!("{f}:{start}"));
                                }
                            }
                            hop_list.push(format!("{}:{}", k.file, k.line));
                            if seen_path.contains(&hop_list) {
                                continue;
                            }
                            if !evidence.sanitized {
                                seen_path.insert(hop_list.clone());
                                taint_paths.push(hop_list);
                            }
                            record_evidence(evidence, &mut seen_evidence, &mut taint_evidence);
                        }
                    }
                }
            }
        }
    }

    let taint_paths = filter_paths_by_budget(taint_paths, &fn_source_hits, &fn_sink_hits);

    let symbol_table = crate::evidence::build_symbol_table(indices);
    for idx in indices {
        if idx.reflection_facts.is_empty() {
            continue;
        }
        let tainted_fids: BTreeSet<String> = taint_evidence
            .iter()
            .flat_map(|ep| ep.path_funcs.iter())
            .filter(|pfid| pfid.starts_with(&idx.file))
            .cloned()
            .collect();
        for fid in tainted_fids {
            let mut ts: BTreeSet<String> = BTreeSet::new();
            for ep in taint_evidence
                .iter()
                .filter(|ep| ep.path_funcs.contains(&fid))
            {
                for e in &ep.edges {
                    if !e.dst.symbol.is_empty() {
                        ts.insert(e.dst.symbol.clone());
                    }
                }
            }
            if ts.is_empty() {
                continue;
            }
            let refl = crate::evidence::apply_reflection_to_taint(
                &ts,
                &idx.reflection_facts,
                &symbol_table,
                &fid,
            );
            if refl.is_empty() {
                continue;
            }
            if let Some(ep) = taint_evidence
                .iter_mut()
                .find(|ep| ep.path_funcs.contains(&fid))
            {
                ep.edges.extend(refl);
            }
        }
    }

    let framework_entry_points = crate::evidence::emit_framework_entry_points(indices);
    let response_by_fid = crate::evidence::response_dataflow_by_fid(indices);
    crate::evidence::apply_response_dataflow(&mut taint_evidence, &response_by_fid);

    TaintSeed {
        entry_points,
        framework_entry_points,
        unsafe_sinks,
        taint_paths,
        taint_evidence,
        rule_cwe: rule_cwe.clone(),
        call_graph: call_graph
            .into_iter()
            .filter(|(_, v)| !v.is_empty())
            .map(|(k, v)| (k, v.into_iter().collect()))
            .collect(),
        call_graph_files,
        def_spans,
        call_graph_confidence,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::FuncDef;

    fn call_site(
        file: &str,
        line: usize,
        containing_fn: &str,
        role: &str,
        kind: &str,
        cwe: &str,
    ) -> CallSite {
        CallSite {
            file: file.to_string(),
            line,
            receiver: String::new(),
            method: "m".to_string(),
            containing_fn: containing_fn.to_string(),
            snippet: "snippet".to_string(),
            matched_rule: "r1".to_string(),
            cwe: cwe.to_string(),
            role: role.to_string(),
            kind: kind.to_string(),
            semantic_family: String::new(),
            owasp_top10_2025: Vec::new(),
        }
    }

    fn func_def(name: &str, start: usize, end: usize) -> FuncDef {
        FuncDef {
            name: name.to_string(),
            start_line: start,
            end_line: end,
            class_name: String::new(),
            params: Vec::new(),
        }
    }

    fn file_index(
        file: &str,
        functions: Vec<FuncDef>,
        source_hits: Vec<CallSite>,
        sink_hits: Vec<CallSite>,
        call_edges: Vec<(&str, &str, &str)>,
        imports: BTreeMap<String, String>,
    ) -> FileIndex {
        FileIndex {
            file: file.to_string(),
            language: "python".to_string(),
            imports,
            functions,
            source_hits,
            sink_hits,
            call_edges: call_edges
                .into_iter()
                .map(|(a, b, c)| (a.to_string(), b.to_string(), c.to_string()))
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn cwe_num_extracts_the_digits() {
        assert_eq!(cwe_num("CWE-89"), "89");
    }

    #[test]
    fn cwe_num_is_case_insensitive() {
        assert_eq!(cwe_num("cwe-78"), "78");
    }

    #[test]
    fn cwe_num_stops_at_the_first_non_digit() {
        assert_eq!(cwe_num("CWE-89-something"), "89");
    }

    #[test]
    fn cwe_num_empty_for_empty_input() {
        assert_eq!(cwe_num(""), "");
    }

    #[test]
    fn cwe_num_empty_when_no_cwe_marker_present() {
        assert_eq!(cwe_num("not a cwe"), "");
    }

    #[test]
    fn is_high_risk_true_for_a_high_risk_cwe() {
        let cs = call_site("a.py", 1, "f", "sink", "other", "CWE-89");
        assert!(is_high_risk(&cs));
    }

    #[test]
    fn is_high_risk_true_for_a_risky_kind_substring() {
        let cs = call_site("a.py", 1, "f", "sink", "command_injection", "");
        assert!(is_high_risk(&cs));
    }

    #[test]
    fn is_high_risk_false_otherwise() {
        let cs = call_site("a.py", 1, "f", "sink", "other", "CWE-200");
        assert!(!is_high_risk(&cs));
    }

    #[test]
    fn prefix_score_counts_shared_leading_dirs() {
        assert_eq!(prefix_score("a/b/c.py", "a/b/d.py"), 2);
        assert_eq!(prefix_score("a/b/c.py", "a/x/d.py"), 1);
        assert_eq!(prefix_score("a/b/c.py", "x/y/d.py"), 0);
    }

    #[test]
    fn prefix_score_handles_a_top_level_file() {
        assert_eq!(prefix_score("app.py", "other.py"), 0);
    }

    #[test]
    fn compatible_taint_pair_always_true_for_a_protected_sink_family() {
        let s = call_site("a.py", 1, "f", "source", "cli", "");
        let mut k = call_site("a.py", 2, "f", "sink", "unrelated", "");
        k.semantic_family = "sql-exec".to_string();
        assert!(compatible_taint_pair(&s, &k));
    }

    #[test]
    fn compatible_taint_pair_true_when_either_kind_is_blank_or_other() {
        let s = call_site("a.py", 1, "f", "source", "", "");
        let k = call_site("a.py", 2, "f", "sink", "cmd", "");
        assert!(compatible_taint_pair(&s, &k));

        let s2 = call_site("a.py", 1, "f", "source", "network", "");
        let k2 = call_site("a.py", 2, "f", "sink", "other", "");
        assert!(compatible_taint_pair(&s2, &k2));
    }

    #[test]
    fn compatible_taint_pair_true_for_a_source_kind_with_no_restriction_table() {
        let s = call_site("a.py", 1, "f", "source", "totally-unknown-kind", "");
        let k = call_site("a.py", 2, "f", "sink", "cmd", "");
        assert!(compatible_taint_pair(&s, &k));
    }

    #[test]
    fn compatible_taint_pair_true_when_sink_kind_is_allowed() {
        let s = call_site("a.py", 1, "f", "source", "network", "");
        let k = call_site("a.py", 2, "f", "sink", "sql", "");
        assert!(compatible_taint_pair(&s, &k));
    }

    #[test]
    fn compatible_taint_pair_false_when_sink_kind_is_not_allowed() {
        let s = call_site("a.py", 1, "f", "source", "cli", "");
        let k = call_site("a.py", 2, "f", "sink", "header", "");
        assert!(!compatible_taint_pair(&s, &k));
    }

    #[test]
    fn compatible_taint_pair_true_for_a_filesystem_source_with_an_allowed_sink() {
        let s = call_site("a.py", 1, "f", "source", "filesystem", "");
        let k = call_site("a.py", 2, "f", "sink", "sql", "");
        assert!(compatible_taint_pair(&s, &k));
    }

    #[test]
    fn compatible_taint_pair_false_for_a_filesystem_source_with_a_disallowed_sink() {
        let s = call_site("a.py", 1, "f", "source", "filesystem", "");
        let k = call_site("a.py", 2, "f", "sink", "ssrf", "");
        assert!(!compatible_taint_pair(&s, &k));
    }

    #[test]
    fn compatible_taint_pair_true_for_an_env_source_with_an_allowed_sink() {
        let s = call_site("a.py", 1, "f", "source", "env", "");
        let k = call_site("a.py", 2, "f", "sink", "redirect", "");
        assert!(compatible_taint_pair(&s, &k));
    }

    #[test]
    fn compatible_taint_pair_keeps_a_crypto_sink_for_every_source_row() {
        for src in [
            "network",
            "ipc",
            "http",
            "cli",
            "stdin",
            "filesystem",
            "file",
            "env",
        ] {
            let s = call_site("a.go", 1, "f", "source", src, "");
            let k = call_site("a.go", 2, "f", "sink", "crypto", "");
            assert!(compatible_taint_pair(&s, &k), "{src} -> crypto");
        }
    }

    #[test]
    fn compatible_taint_pair_resolves_http_to_the_network_row() {
        let s = call_site("a.py", 1, "f", "source", "http", "");
        let header = call_site("a.py", 2, "f", "sink", "header", "");
        assert!(compatible_taint_pair(&s, &header));
        let unlisted = call_site("a.py", 3, "f", "sink", "unlisted-kind", "");
        assert!(!compatible_taint_pair(&s, &unlisted));
    }

    #[test]
    fn compatible_taint_pair_resolves_stdin_to_the_cli_row() {
        let s = call_site("a.c", 1, "f", "source", "stdin", "");
        let cmd = call_site("a.c", 2, "f", "sink", "cmd", "");
        assert!(compatible_taint_pair(&s, &cmd));
        let header = call_site("a.c", 3, "f", "sink", "header", "");
        assert!(!compatible_taint_pair(&s, &header));
    }

    #[test]
    fn compatible_taint_pair_resolves_file_to_the_filesystem_row_not_env() {
        let s = call_site("a.py", 1, "f", "source", "file", "");
        let sql = call_site("a.py", 2, "f", "sink", "sql", "");
        assert!(compatible_taint_pair(&s, &sql));
        let ssrf = call_site("a.py", 3, "f", "sink", "ssrf", "");
        assert!(!compatible_taint_pair(&s, &ssrf));
        let redirect = call_site("a.py", 4, "f", "sink", "redirect", "");
        assert!(!compatible_taint_pair(&s, &redirect));
    }

    #[test]
    fn fn_id_joins_file_and_function() {
        assert_eq!(fn_id("a.py", "handler"), "a.py::handler");
    }

    #[test]
    fn a_module_scope_source_reaches_a_sink_in_another_file_without_claiming_a_span() {
        let caller = file_index(
            "script.py",
            vec![],
            vec![call_site("script.py", 2, "", "source", "network", "")],
            vec![],
            vec![("", "helper", "run")],
            BTreeMap::new(),
        );
        let callee = file_index(
            "helper.py",
            vec![func_def("run", 1, 4)],
            vec![],
            vec![call_site("helper.py", 3, "run", "sink", "cmd", "CWE-78")],
            vec![],
            BTreeMap::new(),
        );
        let seed = build_taint_paths(&[caller, callee], &BTreeMap::new(), 3);
        assert_eq!(
            seed.taint_paths,
            vec![vec![
                "script.py:2".to_string(),
                "helper.py:1".to_string(),
                "helper.py:3".to_string()
            ]]
        );
        assert!(!seed.def_spans.contains_key("script.py::<module>"));
        assert_eq!(seed.def_spans.get("helper.py::run"), Some(&(1, 4)));
        assert!(!seed.call_graph_files.contains_key(MODULE_SCOPE));
        assert_eq!(
            seed.call_graph_files.get("run"),
            Some(&vec!["helper.py:1".to_string()])
        );
    }

    #[test]
    fn fn_id_uses_module_placeholder_for_an_empty_function_name() {
        assert_eq!(fn_id("a.py", ""), "a.py::<module>");
    }

    #[test]
    fn fid_name_extracts_the_function_part() {
        assert_eq!(fid_name("a.py::handler"), "handler");
    }

    #[test]
    fn fid_name_returns_the_whole_string_when_there_is_no_separator() {
        assert_eq!(fid_name("bare"), "bare");
    }

    #[test]
    fn dedup_preserve_order_keeps_first_occurrence_order() {
        let items = vec![
            "b".to_string(),
            "a".to_string(),
            "b".to_string(),
            "c".to_string(),
        ];
        assert_eq!(
            dedup_preserve_order(&items),
            vec!["b".to_string(), "a".to_string(), "c".to_string()]
        );
    }

    #[test]
    fn resolve_called_fids_empty_when_no_candidates() {
        let got = resolve_called_fids(
            "a.py",
            "caller",
            "",
            "missing",
            &BTreeMap::new(),
            &BTreeMap::new(),
            &BTreeMap::new(),
            3,
        );
        assert!(got.is_empty());
    }

    #[test]
    fn resolve_called_fids_returns_the_sole_candidate() {
        let defs = BTreeMap::from([("f".to_string(), vec!["a.py::f".to_string()])]);
        let got = resolve_called_fids(
            "a.py",
            "caller",
            "",
            "f",
            &defs,
            &BTreeMap::new(),
            &BTreeMap::new(),
            3,
        );
        assert_eq!(got, vec!["a.py::f".to_string()]);
    }

    #[test]
    fn resolve_called_fids_prefers_same_file_candidates() {
        let defs = BTreeMap::from([(
            "f".to_string(),
            vec!["a.py::f".to_string(), "b.py::f".to_string()],
        )]);
        let meta = BTreeMap::from([
            ("a.py::f".to_string(), ("a.py".to_string(), 1, 5)),
            ("b.py::f".to_string(), ("b.py".to_string(), 1, 5)),
        ]);
        let got = resolve_called_fids("a.py", "caller", "", "f", &defs, &meta, &BTreeMap::new(), 3);
        assert_eq!(got, vec!["a.py::f".to_string()]);
    }

    #[test]
    fn resolve_called_fids_drops_an_ambiguous_call_with_no_receiver_or_hint() {
        let defs = BTreeMap::from([(
            "f".to_string(),
            vec!["a.py::f".to_string(), "b.py::f".to_string()],
        )]);
        let meta = BTreeMap::from([
            ("a.py::f".to_string(), ("a.py".to_string(), 1, 5)),
            ("b.py::f".to_string(), ("b.py".to_string(), 1, 5)),
        ]);
        let got = resolve_called_fids(
            "caller.py",
            "caller",
            "",
            "f",
            &defs,
            &meta,
            &BTreeMap::new(),
            3,
        );
        assert!(got.is_empty());
    }

    #[test]
    fn resolve_called_fids_uses_the_import_hint_to_narrow_ambiguous_candidates() {
        let defs = BTreeMap::from([(
            "f".to_string(),
            vec!["a/mod.py::f".to_string(), "b/mod.py::f".to_string()],
        )]);
        let meta = BTreeMap::from([
            ("a/mod.py::f".to_string(), ("a/mod.py".to_string(), 1, 5)),
            ("b/mod.py::f".to_string(), ("b/mod.py".to_string(), 1, 5)),
        ]);
        let idx = file_index(
            "caller.py",
            vec![],
            vec![],
            vec![],
            vec![],
            BTreeMap::from([("recv".to_string(), "a.mod".to_string())]),
        );
        let file_idx = BTreeMap::from([("caller.py".to_string(), &idx)]);
        let got = resolve_called_fids(
            "caller.py",
            "caller",
            "recv",
            "f",
            &defs,
            &meta,
            &file_idx,
            3,
        );
        assert_eq!(got, vec!["a/mod.py::f".to_string()]);
    }

    #[test]
    fn resolve_called_fids_caps_narrowed_candidates_at_max_targets() {
        let defs = BTreeMap::from([(
            "f".to_string(),
            vec![
                "a/1.py::f".to_string(),
                "a/2.py::f".to_string(),
                "a/3.py::f".to_string(),
            ],
        )]);
        let meta = BTreeMap::from([
            ("a/1.py::f".to_string(), ("a/1.py".to_string(), 1, 5)),
            ("a/2.py::f".to_string(), ("a/2.py".to_string(), 1, 5)),
            ("a/3.py::f".to_string(), ("a/3.py".to_string(), 1, 5)),
        ]);
        let idx = file_index("caller.py", vec![], vec![], vec![], vec![], BTreeMap::new());
        let file_idx = BTreeMap::from([("caller.py".to_string(), &idx)]);
        let got = resolve_called_fids(
            "a/x.py",
            "caller",
            "unused_but_present",
            "f",
            &defs,
            &meta,
            &file_idx,
            2,
        );
        assert_eq!(got.len(), 2);
    }

    #[test]
    fn import_hint_matches_false_for_an_empty_hint() {
        assert!(!import_hint_matches("", "anything.py"));
    }

    #[test]
    fn import_hint_matches_false_when_every_segment_is_an_empty_string() {
        assert!(!import_hint_matches("...", "anything.py"));
    }

    #[test]
    fn edge_confidence_same_file_is_1() {
        assert_eq!(edge_confidence("a.py", "a.py", "", &BTreeMap::new()), 1.0);
    }

    #[test]
    fn edge_confidence_import_hint_literal_substring_match_is_0_9() {
        let idx = file_index(
            "a.py",
            vec![],
            vec![],
            vec![],
            vec![],
            BTreeMap::from([("recv".to_string(), "pkg.mod".to_string())]),
        );
        let file_idx = BTreeMap::from([("a.py".to_string(), &idx)]);
        assert_eq!(
            edge_confidence("a.py", "vendor/pkg.mod.py", "recv", &file_idx),
            0.9
        );
    }

    #[test]
    fn edge_confidence_import_hint_path_segment_match_is_0_9() {
        let idx = file_index(
            "a.py",
            vec![],
            vec![],
            vec![],
            vec![],
            BTreeMap::from([("recv".to_string(), "pkg.sub.mod".to_string())]),
        );
        let file_idx = BTreeMap::from([("a.py".to_string(), &idx)]);
        assert_eq!(
            edge_confidence("a.py", "somewhere/pkg/sub.py", "recv", &file_idx),
            0.9
        );
    }

    #[test]
    fn edge_confidence_import_hint_present_but_below_half_falls_through_to_proximity() {
        let idx = file_index(
            "a.py",
            vec![],
            vec![],
            vec![],
            vec![],
            BTreeMap::from([("recv".to_string(), "pkg.sub.mod".to_string())]),
        );
        let file_idx = BTreeMap::from([("a.py".to_string(), &idx)]);
        assert_eq!(
            edge_confidence("a.py", "xyz/abc.py", "recv", &file_idx),
            0.5
        );
    }

    #[test]
    fn edge_confidence_proximity_two_shared_dirs_is_0_8() {
        assert_eq!(
            edge_confidence("a/b/x.py", "a/b/y.py", "", &BTreeMap::new()),
            0.8
        );
    }

    #[test]
    fn edge_confidence_proximity_one_shared_dir_is_0_7() {
        assert_eq!(
            edge_confidence("a/b/x.py", "a/c/y.py", "", &BTreeMap::new()),
            0.7
        );
    }

    #[test]
    fn edge_confidence_name_only_fallback_is_0_5() {
        assert_eq!(
            edge_confidence("a/x.py", "b/y.py", "", &BTreeMap::new()),
            0.5
        );
    }

    #[test]
    fn build_taint_paths_finds_an_intra_procedural_pair() {
        let idx = file_index(
            "app.py",
            vec![func_def("handler", 1, 10)],
            vec![call_site(
                "app.py", 2, "handler", "source", "network", "CWE-20",
            )],
            vec![call_site("app.py", 3, "handler", "sink", "sql", "CWE-89")],
            vec![],
            BTreeMap::new(),
        );
        let seed = build_taint_paths(&[idx], &BTreeMap::new(), DEFAULT_MAX_TARGETS_PER_CALL);
        assert_eq!(
            seed.taint_paths,
            vec![vec!["app.py:2".to_string(), "app.py:3".to_string()]]
        );
        assert_eq!(seed.entry_points.len(), 1);
        assert_eq!(seed.entry_points[0].function, "handler");
        assert_eq!(seed.unsafe_sinks.len(), 1);
        assert_eq!(seed.unsafe_sinks[0].cwe, vec!["CWE-89".to_string()]);
    }

    #[test]
    fn build_taint_paths_drops_an_incompatible_intra_procedural_pair() {
        let idx = file_index(
            "app.py",
            vec![func_def("handler", 1, 10)],
            vec![call_site("app.py", 2, "handler", "source", "cli", "CWE-20")],
            vec![call_site(
                "app.py", 3, "handler", "sink", "header", "CWE-20",
            )],
            vec![],
            BTreeMap::new(),
        );
        let seed = build_taint_paths(&[idx], &BTreeMap::new(), DEFAULT_MAX_TARGETS_PER_CALL);
        assert!(seed.taint_paths.is_empty());
        assert_eq!(seed.unsafe_sinks.len(), 1);
        assert_eq!(seed.entry_points.len(), 1);
    }

    #[test]
    fn build_taint_paths_dedups_identical_sink_and_source_hits() {
        let cs_source = call_site("app.py", 2, "handler", "source", "network", "CWE-20");
        let cs_sink = call_site("app.py", 3, "handler", "sink", "sql", "CWE-89");
        let idx = file_index(
            "app.py",
            vec![func_def("handler", 1, 10)],
            vec![cs_source.clone(), cs_source],
            vec![cs_sink.clone(), cs_sink],
            vec![],
            BTreeMap::new(),
        );
        let seed = build_taint_paths(&[idx], &BTreeMap::new(), DEFAULT_MAX_TARGETS_PER_CALL);
        assert_eq!(seed.taint_paths.len(), 1);
        assert_eq!(seed.unsafe_sinks.len(), 1);
        assert_eq!(seed.entry_points.len(), 1);
    }

    #[test]
    fn build_taint_paths_finds_a_one_hop_inter_procedural_pair() {
        let caller = file_index(
            "app.py",
            vec![func_def("handler", 1, 5)],
            vec![call_site(
                "app.py", 2, "handler", "source", "network", "CWE-20",
            )],
            vec![],
            vec![("handler", "", "helper")],
            BTreeMap::new(),
        );
        let callee = file_index(
            "app.py",
            vec![func_def("helper", 10, 15)],
            vec![],
            vec![call_site("app.py", 11, "helper", "sink", "sql", "CWE-89")],
            vec![],
            BTreeMap::new(),
        );
        let idx = FileIndex {
            functions: [caller.functions, callee.functions].concat(),
            source_hits: caller.source_hits,
            sink_hits: callee.sink_hits,
            call_edges: caller.call_edges,
            ..caller_base("app.py")
        };
        let seed = build_taint_paths(&[idx], &BTreeMap::new(), DEFAULT_MAX_TARGETS_PER_CALL);
        assert_eq!(
            seed.taint_paths,
            vec![vec![
                "app.py:2".to_string(),
                "app.py:10".to_string(),
                "app.py:11".to_string()
            ]]
        );
        assert!(seed
            .call_graph
            .get("app.py::handler")
            .unwrap()
            .contains(&"app.py::helper".to_string()));
        assert_eq!(
            seed.call_graph_confidence
                [&("app.py::handler".to_string(), "app.py::helper".to_string())],
            1.0
        );
    }

    fn caller_base(file: &str) -> FileIndex {
        FileIndex {
            file: file.to_string(),
            language: "python".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn build_taint_paths_does_not_cross_a_call_edge_to_itself() {
        let idx = FileIndex {
            functions: vec![func_def("f", 1, 5)],
            call_edges: vec![("f".to_string(), String::new(), "f".to_string())],
            ..caller_base("app.py")
        };
        let seed = build_taint_paths(&[idx], &BTreeMap::new(), DEFAULT_MAX_TARGETS_PER_CALL);
        assert!(!seed.call_graph.contains_key("app.py::f"));
    }

    #[test]
    fn build_taint_paths_ignores_a_call_edge_from_module_scope() {
        let idx = FileIndex {
            call_edges: vec![(String::new(), String::new(), "helper".to_string())],
            ..caller_base("app.py")
        };
        let seed = build_taint_paths(&[idx], &BTreeMap::new(), DEFAULT_MAX_TARGETS_PER_CALL);
        assert!(seed.call_graph.is_empty());
    }

    #[test]
    fn build_taint_paths_high_risk_source_allows_deeper_chains() {
        let idx = FileIndex {
            functions: vec![
                func_def("handler", 1, 2),
                func_def("a", 3, 4),
                func_def("b", 5, 6),
                func_def("c", 7, 8),
                func_def("d", 9, 10),
            ],
            source_hits: vec![call_site(
                "app.py", 1, "handler", "source", "network", "CWE-89",
            )],
            sink_hits: vec![call_site("app.py", 9, "d", "sink", "sql", "CWE-89")],
            call_edges: vec![
                ("handler".to_string(), String::new(), "a".to_string()),
                ("a".to_string(), String::new(), "b".to_string()),
                ("b".to_string(), String::new(), "c".to_string()),
                ("c".to_string(), String::new(), "d".to_string()),
            ],
            ..caller_base("app.py")
        };
        let seed = build_taint_paths(&[idx], &BTreeMap::new(), DEFAULT_MAX_TARGETS_PER_CALL);
        assert_eq!(seed.taint_paths.len(), 1);
    }

    #[test]
    fn build_taint_paths_non_high_risk_chain_stops_beyond_base_hops() {
        let idx = FileIndex {
            functions: vec![
                func_def("handler", 1, 2),
                func_def("a", 3, 4),
                func_def("b", 5, 6),
                func_def("c", 7, 8),
                func_def("d", 9, 10),
            ],
            source_hits: vec![call_site("app.py", 1, "handler", "source", "network", "")],
            sink_hits: vec![call_site("app.py", 9, "d", "sink", "other", "")],
            call_edges: vec![
                ("handler".to_string(), String::new(), "a".to_string()),
                ("a".to_string(), String::new(), "b".to_string()),
                ("b".to_string(), String::new(), "c".to_string()),
                ("c".to_string(), String::new(), "d".to_string()),
            ],
            ..caller_base("app.py")
        };
        let seed = build_taint_paths(&[idx], &BTreeMap::new(), DEFAULT_MAX_TARGETS_PER_CALL);
        assert!(seed.taint_paths.is_empty());
    }

    #[test]
    fn build_taint_paths_deep_mode_still_drops_a_non_high_risk_sink_beyond_base_hops() {
        let idx = FileIndex {
            functions: vec![
                func_def("handler", 1, 2),
                func_def("a", 3, 4),
                func_def("b", 5, 6),
                func_def("c", 7, 8),
                func_def("d", 9, 10),
            ],
            source_hits: vec![call_site(
                "app.py", 1, "handler", "source", "network", "CWE-89",
            )],
            sink_hits: vec![call_site("app.py", 9, "d", "sink", "other", "")],
            call_edges: vec![
                ("handler".to_string(), String::new(), "a".to_string()),
                ("a".to_string(), String::new(), "b".to_string()),
                ("b".to_string(), String::new(), "c".to_string()),
                ("c".to_string(), String::new(), "d".to_string()),
            ],
            ..caller_base("app.py")
        };
        let seed = build_taint_paths(&[idx], &BTreeMap::new(), DEFAULT_MAX_TARGETS_PER_CALL);
        assert!(seed.taint_paths.is_empty());
    }

    #[test]
    fn build_taint_paths_revisits_are_skipped_in_the_bfs() {
        let idx = FileIndex {
            functions: vec![
                func_def("handler", 1, 2),
                func_def("a", 3, 4),
                func_def("b", 5, 6),
                func_def("c", 7, 8),
            ],
            source_hits: vec![call_site("app.py", 1, "handler", "source", "network", "")],
            sink_hits: vec![call_site("app.py", 7, "c", "sink", "sql", "CWE-89")],
            call_edges: vec![
                ("handler".to_string(), String::new(), "a".to_string()),
                ("handler".to_string(), String::new(), "b".to_string()),
                ("a".to_string(), String::new(), "c".to_string()),
                ("b".to_string(), String::new(), "c".to_string()),
            ],
            ..caller_base("app.py")
        };
        let seed = build_taint_paths(&[idx], &BTreeMap::new(), DEFAULT_MAX_TARGETS_PER_CALL);
        assert_eq!(seed.taint_paths.len(), 1);
    }

    #[test]
    fn build_taint_paths_drops_an_incompatible_inter_procedural_pair() {
        let idx = FileIndex {
            functions: vec![func_def("handler", 1, 2), func_def("helper", 3, 4)],
            source_hits: vec![call_site("app.py", 1, "handler", "source", "cli", "")],
            sink_hits: vec![call_site("app.py", 3, "helper", "sink", "header", "")],
            call_edges: vec![("handler".to_string(), String::new(), "helper".to_string())],
            ..caller_base("app.py")
        };
        let seed = build_taint_paths(&[idx], &BTreeMap::new(), DEFAULT_MAX_TARGETS_PER_CALL);
        assert!(seed.taint_paths.is_empty());
    }

    #[test]
    fn build_taint_paths_propagates_rule_cwe_through_unchanged() {
        let rule_cwe = BTreeMap::from([("r1".to_string(), vec!["CWE-89".to_string()])]);
        let seed = build_taint_paths(&[], &rule_cwe, DEFAULT_MAX_TARGETS_PER_CALL);
        assert_eq!(seed.rule_cwe, rule_cwe);
    }

    #[test]
    fn build_taint_paths_empty_indices_yields_an_empty_seed() {
        let seed = build_taint_paths(&[], &BTreeMap::new(), DEFAULT_MAX_TARGETS_PER_CALL);
        assert!(seed.entry_points.is_empty());
        assert!(seed.unsafe_sinks.is_empty());
        assert!(seed.taint_paths.is_empty());
        assert!(seed.call_graph.is_empty());
    }

    #[test]
    fn build_taint_paths_source_with_no_function_scope_uses_a_line_placeholder() {
        let idx = FileIndex {
            source_hits: vec![call_site("app.py", 5, "", "source", "network", "")],
            ..caller_base("app.py")
        };
        let seed = build_taint_paths(&[idx], &BTreeMap::new(), DEFAULT_MAX_TARGETS_PER_CALL);
        assert_eq!(seed.entry_points[0].function, "<line-5>");
    }

    #[test]
    fn build_taint_paths_sink_with_no_function_scope_falls_back_to_method_name() {
        let mut cs = call_site("app.py", 5, "", "sink", "other", "");
        cs.method = "eval".to_string();
        let idx = FileIndex {
            sink_hits: vec![cs],
            ..caller_base("app.py")
        };
        let seed = build_taint_paths(&[idx], &BTreeMap::new(), DEFAULT_MAX_TARGETS_PER_CALL);
        assert_eq!(seed.unsafe_sinks[0].function, "eval");
    }

    #[test]
    fn build_taint_paths_source_kind_defaults_to_other_when_blank() {
        let idx = FileIndex {
            source_hits: vec![call_site("app.py", 5, "f", "source", "", "")],
            functions: vec![func_def("f", 1, 10)],
            ..caller_base("app.py")
        };
        let seed = build_taint_paths(&[idx], &BTreeMap::new(), DEFAULT_MAX_TARGETS_PER_CALL);
        assert_eq!(seed.entry_points[0].kind, "other");
    }

    #[test]
    fn filter_paths_by_budget_is_a_no_op_on_an_empty_input() {
        let got = filter_paths_by_budget(vec![], &BTreeMap::new(), &BTreeMap::new());
        assert!(got.is_empty());
    }

    #[test]
    fn filter_paths_by_budget_drops_a_short_malformed_path() {
        let got = filter_paths_by_budget(
            vec![vec!["only-one-hop".to_string()]],
            &BTreeMap::new(),
            &BTreeMap::new(),
        );
        assert!(got.is_empty());
    }

    #[test]
    fn filter_paths_by_budget_keeps_a_path_with_an_unparseable_source_hop() {
        let got = filter_paths_by_budget(
            vec![vec![
                "no-colon-here".to_string(),
                "also-no-colon".to_string(),
            ]],
            &BTreeMap::new(),
            &BTreeMap::new(),
        );
        assert_eq!(got.len(), 1);
    }

    #[test]
    fn filter_paths_by_budget_keeps_a_path_with_a_parseable_source_but_unparseable_sink_hop() {
        let got = filter_paths_by_budget(
            vec![vec!["app.py:1".to_string(), "also-no-colon".to_string()]],
            &BTreeMap::new(),
            &BTreeMap::new(),
        );
        assert_eq!(got.len(), 1);
    }

    #[test]
    fn filter_paths_by_budget_keeps_a_path_whose_callsites_cannot_be_resolved() {
        let got = filter_paths_by_budget(
            vec![vec!["app.py:1".to_string(), "app.py:2".to_string()]],
            &BTreeMap::new(),
            &BTreeMap::new(),
        );
        assert_eq!(got.len(), 1);
    }

    #[test]
    fn filter_paths_by_budget_uses_a_line_placeholder_for_a_module_level_source() {
        let s = call_site("app.py", 1, "", "source", "network", "");
        let k = call_site("app.py", 2, "", "sink", "sql", "CWE-89");
        let sources = BTreeMap::from([("app.py::<module>".to_string(), vec![s.clone()])]);
        let sinks = BTreeMap::from([("app.py::<module>".to_string(), vec![k.clone()])]);
        let path = vec![
            format!("{}:{}", s.file, s.line),
            format!("{}:{}", k.file, k.line),
        ];
        let got = filter_paths_by_budget(vec![path.clone()], &sources, &sinks);
        assert_eq!(got, vec![path]);
    }

    fn budget_fixture(n: usize, families: fn(usize) -> String) -> Vec<Vec<String>> {
        let src_fn = "app.py::handler".to_string();
        let mut sources = BTreeMap::new();
        let mut sinks = BTreeMap::new();
        let mut paths = Vec::new();
        for i in 0..n {
            let s = call_site("app.py", 1, "handler", "source", "network", "");
            let mut k = call_site("app.py", 100 + i, "handler", "sink", "sql", "CWE-89");
            k.semantic_family = families(i);
            sources
                .entry(src_fn.clone())
                .or_insert_with(Vec::new)
                .push(s.clone());
            sinks
                .entry(src_fn.clone())
                .or_insert_with(Vec::new)
                .push(k.clone());
            paths.push(vec![
                format!("{}:{}", s.file, s.line),
                format!("{}:{}", k.file, k.line),
            ]);
        }
        filter_paths_by_budget(paths, &sources, &sinks)
    }

    #[test]
    fn filter_paths_by_budget_caps_how_often_one_source_repeats_a_family() {
        assert_eq!(budget_fixture(7, |_| "sql-exec".to_string()).len(), 5);
    }

    #[test]
    fn filter_paths_by_budget_never_caps_away_a_whole_vulnerability_class() {
        assert_eq!(budget_fixture(7, |i| format!("family-{i}")).len(), 7);
    }

    #[test]
    fn filter_paths_by_budget_drops_paths_once_the_global_budget_is_exhausted() {
        let sinks_shared: Vec<CallSite> = (0..5)
            .map(|sink_i| {
                let mut k = call_site("app.py", 1000 + sink_i, "shared", "sink", "other", "");
                k.semantic_family = format!("non-protected-family-{sink_i}");
                k
            })
            .collect();
        let mut sources: BTreeMap<String, Vec<CallSite>> = BTreeMap::new();
        let mut paths = Vec::new();
        for fn_i in 0..61 {
            let src_fn = format!("fn{fn_i}");
            let s = call_site("app.py", fn_i, &src_fn, "source", "network", "");
            sources.entry(src_fn.clone()).or_default().push(s.clone());
            for k in &sinks_shared {
                paths.push(vec![
                    format!("{}:{}", s.file, s.line),
                    format!("{}:{}", k.file, k.line),
                ]);
            }
        }
        let sinks = BTreeMap::from([("shared".to_string(), sinks_shared)]);
        assert_eq!(paths.len(), 305);
        let got = filter_paths_by_budget(paths, &sources, &sinks);
        assert_eq!(got.len(), 300);
    }

    #[test]
    fn filter_paths_by_budget_overrides_the_exhausted_budget_for_a_protected_family() {
        let non_protected_sinks: Vec<CallSite> = (0..5)
            .map(|sink_i| {
                let mut k = call_site("app.py", 1000 + sink_i, "shared", "sink", "other", "");
                k.semantic_family = format!("non-protected-family-{sink_i}");
                k
            })
            .collect();
        let mut last_fn_sinks = non_protected_sinks.clone();
        last_fn_sinks[0].line = 2000;
        last_fn_sinks[0].semantic_family = "sql-exec".to_string();

        let mut sources: BTreeMap<String, Vec<CallSite>> = BTreeMap::new();
        let mut all_sinks: Vec<CallSite> = non_protected_sinks.clone();
        all_sinks.push(last_fn_sinks[0].clone());
        let mut paths = Vec::new();
        for fn_i in 0..61 {
            let src_fn = format!("fn{fn_i}");
            let s = call_site("app.py", fn_i, &src_fn, "source", "network", "");
            sources.entry(src_fn.clone()).or_default().push(s.clone());
            let sinks_for_this_fn = if fn_i == 60 {
                &last_fn_sinks
            } else {
                &non_protected_sinks
            };
            for k in sinks_for_this_fn {
                paths.push(vec![
                    format!("{}:{}", s.file, s.line),
                    format!("{}:{}", k.file, k.line),
                ]);
            }
        }
        let sinks = BTreeMap::from([("all".to_string(), all_sinks)]);
        assert_eq!(paths.len(), 305);
        let protected_path = vec![
            "app.py:60".to_string(),
            format!("app.py:{}", last_fn_sinks[0].line),
        ];
        let got = filter_paths_by_budget(paths, &sources, &sinks);
        assert_eq!(got.len(), 300);
        assert!(got.contains(&protected_path));
    }

    fn floor_fixture(
        n_sources: usize,
        sinks_per_source: usize,
        extra_family: &str,
    ) -> (Vec<Vec<String>>, Vec<String>, Vec<Vec<String>>) {
        let mut sources: BTreeMap<String, Vec<CallSite>> = BTreeMap::new();
        let mut a_sinks = Vec::new();
        for j in 0..sinks_per_source {
            let mut k = call_site("app.py", 5000 + j, "shared", "sink", "x", "CWE-89");
            k.semantic_family = "family-a".to_string();
            a_sinks.push(k);
        }
        let mut b = call_site("lib.py", 9000, "other", "sink", "x", "CWE-22");
        b.semantic_family = extra_family.to_string();
        let mut paths = Vec::new();
        for i in 0..n_sources {
            let src = call_site("app.py", i + 1, &format!("fn{i}"), "source", "network", "");
            sources
                .entry(format!("fn{i}"))
                .or_default()
                .push(src.clone());
            for k in &a_sinks {
                paths.push(vec![
                    format!("app.py:{}", src.line),
                    format!("app.py:{}", k.line),
                ]);
            }
        }
        let b_path = vec![
            "app.py:1".to_string(),
            "mid.py:1".to_string(),
            "mid.py:2".to_string(),
            "lib.py:9000".to_string(),
        ];
        paths.push(b_path.clone());
        let mut all_sinks = a_sinks;
        all_sinks.push(b);
        let sinks = BTreeMap::from([("s".to_string(), all_sinks)]);
        let got = filter_paths_by_budget(paths.clone(), &sources, &sinks);
        (got, b_path, paths)
    }

    #[test]
    fn the_family_floor_keeps_a_low_scoring_family_the_budget_would_cut() {
        let (got, b_path, _) = floor_fixture(70, 7, "family-b");
        assert!(got.contains(&b_path));
        assert_eq!(got.len(), 300);
    }

    #[test]
    fn a_protected_family_the_floor_could_not_fit_still_gets_its_first_path() {
        let mut sources: BTreeMap<String, Vec<CallSite>> = BTreeMap::new();
        let src = call_site("app.py", 1, "handler", "source", "network", "");
        sources.insert("handler".to_string(), vec![src]);
        let mut sinks_v = Vec::new();
        let mut paths = Vec::new();
        for i in 0..300 {
            let mut k = call_site(
                "app.py",
                100 + i,
                "h",
                "sink",
                "x",
                &format!("CWE-{}", 2000 + i),
            );
            k.semantic_family = "sql-exec".to_string();
            paths.push(vec!["app.py:1".to_string(), format!("app.py:{}", k.line)]);
            sinks_v.push(k);
        }
        let mut f = call_site("io.py", 7, "h", "sink", "x", "CWE-22");
        f.semantic_family = "file-io".to_string();
        let file_io_path = vec![
            "app.py:1".to_string(),
            "a.py:1".to_string(),
            "b.py:1".to_string(),
            "io.py:7".to_string(),
        ];
        paths.push(file_io_path.clone());
        sinks_v.push(f);
        let sinks = BTreeMap::from([("s".to_string(), sinks_v)]);
        let got = filter_paths_by_budget(paths, &sources, &sinks);
        assert_eq!(got.len(), 301);
        assert_eq!(got.last(), Some(&file_io_path));
    }

    #[test]
    fn sink_semantic_strips_the_cwe_prefix_when_present() {
        assert_eq!(sink_semantic("89:sql-exec"), "sql-exec");
        assert_eq!(sink_semantic("unknown"), "unknown");
    }

    #[test]
    fn filter_paths_by_budget_keeps_at_least_one_path_per_protected_family_past_budget() {
        let src_fn = "app.py::handler".to_string();
        let s = call_site("app.py", 1, "handler", "source", "network", "");
        let mut k = call_site("app.py", 2, "handler", "sink", "unusual", "");
        k.semantic_family = "sql-exec".to_string();
        let sources = BTreeMap::from([(src_fn.clone(), vec![s.clone()])]);
        let sinks = BTreeMap::from([(src_fn, vec![k.clone()])]);
        let path = vec![
            format!("{}:{}", s.file, s.line),
            format!("{}:{}", k.file, k.line),
        ];
        let got = filter_paths_by_budget(vec![path.clone()], &sources, &sinks);
        assert_eq!(got, vec![path]);
    }

    #[test]
    fn effective_global_budget_default_for_small_repos() {
        assert_eq!(effective_global_budget(10, 5, 5), GLOBAL_PATH_BUDGET);
    }

    #[test]
    fn effective_global_budget_expands_for_high_fanout() {
        assert_eq!(
            effective_global_budget(10, 30, 30),
            GLOBAL_PATH_BUDGET_MAX.min(GLOBAL_PATH_BUDGET + 150)
        );
    }

    #[test]
    fn effective_global_budget_moderate_expansion_when_over_the_base_cap_but_low_fanout() {
        assert_eq!(
            effective_global_budget(GLOBAL_PATH_BUDGET + 1, 2, 2),
            GLOBAL_PATH_BUDGET_MAX.min(GLOBAL_PATH_BUDGET + 100)
        );
    }

    #[test]
    fn score_path_intra_procedural_has_full_confidence() {
        assert!(score_path(1, "CWE-89") > score_path(2, "CWE-89"));
    }

    #[test]
    fn extract_sink_family_prefers_semantic_family() {
        let mut k = call_site("a.py", 1, "f", "sink", "raw-kind", "CWE-89");
        k.semantic_family = "sql-exec".to_string();
        assert_eq!(extract_sink_family(&k), "89:sql-exec");
    }

    #[test]
    fn extract_sink_family_falls_back_to_kind_when_no_semantic_family() {
        let k = call_site("a.py", 1, "f", "sink", "raw-kind", "CWE-89");
        assert_eq!(extract_sink_family(&k), "89:raw-kind");
    }

    #[test]
    fn parse_hop_splits_from_the_right() {
        assert_eq!(parse_hop("a/b:c.py:42"), Some(("a/b:c.py".to_string(), 42)));
    }

    #[test]
    fn parse_hop_none_for_a_non_numeric_suffix() {
        assert_eq!(parse_hop("app.py:notaline"), None);
    }

    #[test]
    fn parse_hop_none_for_no_colon_at_all() {
        assert_eq!(parse_hop("nofile"), None);
    }

    fn call_fact(
        f: &str,
        line: usize,
        callee: &str,
        args: &[&str],
        target: Option<&str>,
    ) -> crate::scan::CallArgFact {
        crate::scan::CallArgFact {
            function_qnode: f.to_string(),
            line,
            callee_name: callee.to_string(),
            receiver: String::new(),
            arg_symbols: args.iter().map(|s| s.to_string()).collect(),
            arg_slots: Vec::new(),
            target_symbol: target.map(String::from),
        }
    }

    fn grounded_index() -> FileIndex {
        let mut idx = file_index(
            "a.py",
            vec![func_def("f", 1, 9)],
            vec![call_site("a.py", 3, "f", "source", "network", "")],
            vec![call_site("a.py", 5, "f", "sink", "cmd", "CWE-78")],
            vec![],
            BTreeMap::new(),
        );
        idx.source_hits[0].method = "get".to_string();
        idx.sink_hits[0].method = "system".to_string();
        idx.call_args
            .push(call_fact("f", 3, "get", &[], Some("raw")));
        idx.call_args
            .push(call_fact("f", 5, "system", &["raw"], None));
        idx
    }

    #[test]
    fn a_grounded_path_carries_its_transfer_edges() {
        let seed = build_taint_paths(&[grounded_index()], &BTreeMap::new(), 3);
        assert_eq!(seed.taint_paths, vec![vec!["a.py:3", "a.py:5"]]);
        assert_eq!(seed.taint_evidence.len(), 1);
        let ev = &seed.taint_evidence[0];
        assert_eq!(ev.source_ref, "a.py:3");
        assert_eq!(ev.sink_ref, "a.py:5");
        assert_eq!(ev.path_funcs, vec!["a.py::f".to_string()]);
        let kinds: Vec<&str> = ev.edges.iter().map(|e| e.transfer_kind.as_str()).collect();
        assert_eq!(kinds, vec!["source", "local_to_sink"]);
    }

    #[test]
    fn a_reachable_pair_with_no_provable_dataflow_is_kept_with_fallback_evidence() {
        let mut idx = grounded_index();
        idx.call_args[1].arg_symbols = vec!["cold".to_string()];
        let seed = build_taint_paths(&[idx], &BTreeMap::new(), 3);
        assert_eq!(seed.taint_paths, vec![vec!["a.py:3", "a.py:5"]]);
        assert_eq!(seed.taint_evidence.len(), 1);
        assert!(seed.taint_evidence[0].edges.is_empty());
        assert!(!seed.taint_evidence[0].sanitized);
    }

    #[test]
    fn a_sanitized_flow_is_recorded_as_evidence_but_not_as_a_taint_path() {
        let mut idx = grounded_index();
        idx.call_args
            .insert(1, call_fact("f", 4, "escape", &["raw"], Some("safe")));
        idx.call_args[2].arg_symbols = vec!["safe".to_string()];
        let seed = build_taint_paths(&[idx], &BTreeMap::new(), 3);
        assert!(seed.taint_paths.is_empty());
        assert_eq!(seed.taint_evidence.len(), 1);
        assert!(seed.taint_evidence[0].sanitized);
    }

    #[test]
    fn a_path_with_no_facts_at_all_keeps_its_reachability_shape() {
        let idx = file_index(
            "a.js",
            vec![func_def("f", 1, 9)],
            vec![call_site("a.js", 3, "f", "source", "network", "")],
            vec![call_site("a.js", 5, "f", "sink", "cmd", "CWE-78")],
            vec![],
            BTreeMap::new(),
        );
        let seed = build_taint_paths(&[idx], &BTreeMap::new(), 3);
        assert_eq!(seed.taint_paths.len(), 1);
        assert_eq!(seed.taint_evidence.len(), 1);
        assert!(seed.taint_evidence[0].edges.is_empty());
    }

    #[test]
    fn an_interprocedural_path_is_grounded_across_the_call_edge() {
        let mut caller = file_index(
            "a.py",
            vec![func_def("f", 1, 9)],
            vec![call_site("a.py", 3, "f", "source", "network", "")],
            vec![],
            vec![("f", "", "sink_fn")],
            BTreeMap::new(),
        );
        caller.source_hits[0].method = "get".to_string();
        caller
            .call_args
            .push(call_fact("f", 3, "get", &[], Some("raw")));
        caller
            .call_args
            .push(call_fact("f", 4, "sink_fn", &["raw"], None));
        let mut callee = file_index(
            "b.py",
            vec![func_def("sink_fn", 20, 29)],
            vec![],
            vec![call_site("b.py", 22, "sink_fn", "sink", "cmd", "CWE-78")],
            vec![],
            BTreeMap::new(),
        );
        callee.sink_hits[0].method = "system".to_string();
        callee
            .call_args
            .push(call_fact("sink_fn", 22, "system", &["p"], None));
        let seed = build_taint_paths(&[caller, callee], &BTreeMap::new(), 3);
        assert_eq!(seed.taint_paths, vec![vec!["a.py:3", "b.py:20", "b.py:22"]]);
        let kinds: Vec<&str> = seed.taint_evidence[0]
            .edges
            .iter()
            .map(|e| e.transfer_kind.as_str())
            .collect();
        assert_eq!(kinds, vec!["source", "arg_to_param", "local_to_sink"]);
    }

    #[test]
    fn an_ungrounded_interprocedural_pair_is_kept_with_fallback_evidence() {
        let mut caller = file_index(
            "a.py",
            vec![func_def("f", 1, 9)],
            vec![call_site("a.py", 3, "f", "source", "network", "")],
            vec![],
            vec![("f", "", "sink_fn")],
            BTreeMap::new(),
        );
        caller.source_hits[0].method = "get".to_string();
        caller
            .call_args
            .push(call_fact("f", 3, "get", &[], Some("raw")));
        caller
            .call_args
            .push(call_fact("f", 4, "sink_fn", &["cold"], None));
        let callee = file_index(
            "b.py",
            vec![func_def("sink_fn", 20, 29)],
            vec![],
            vec![call_site("b.py", 22, "sink_fn", "sink", "cmd", "CWE-78")],
            vec![],
            BTreeMap::new(),
        );
        let seed = build_taint_paths(&[caller, callee], &BTreeMap::new(), 3);
        assert_eq!(seed.taint_paths, vec![vec!["a.py:3", "b.py:20", "b.py:22"]]);
        assert_eq!(seed.taint_evidence.len(), 1);
        assert!(seed.taint_evidence[0].edges.is_empty());
    }

    #[test]
    fn two_rules_matching_the_same_source_line_emit_the_hop_list_once() {
        let mut caller = file_index(
            "a.py",
            vec![func_def("f", 1, 9)],
            vec![
                call_site("a.py", 3, "f", "source", "network", ""),
                call_site("a.py", 3, "f", "source", "network", ""),
            ],
            vec![],
            vec![("f", "", "sink_fn")],
            BTreeMap::new(),
        );
        caller.source_hits[1].matched_rule = "r2".to_string();
        let callee = file_index(
            "b.py",
            vec![func_def("sink_fn", 20, 29)],
            vec![],
            vec![call_site("b.py", 22, "sink_fn", "sink", "cmd", "CWE-78")],
            vec![],
            BTreeMap::new(),
        );
        let seed = build_taint_paths(&[caller, callee], &BTreeMap::new(), 3);
        assert_eq!(seed.taint_paths, vec![vec!["a.py:3", "b.py:20", "b.py:22"]]);
        assert_eq!(seed.taint_evidence.len(), 1);
    }

    #[test]
    fn reflection_edges_are_merged_into_the_evidence_path_they_belong_to() {
        let mut idx = grounded_index();
        idx.reflection_facts.push(crate::scan::ReflectionFact {
            function_qnode: "f".to_string(),
            line: 4,
            call_type: "getattr".to_string(),
            target_symbols: vec!["raw".to_string()],
            receiver: String::new(),
            language: "python".to_string(),
        });
        let seed = build_taint_paths(&[idx], &BTreeMap::new(), 3);
        let kinds: Vec<&str> = seed.taint_evidence[0]
            .edges
            .iter()
            .map(|e| e.transfer_kind.as_str())
            .collect();
        assert_eq!(kinds, vec!["source", "local_to_sink", "reflect"]);
    }

    #[test]
    fn reflection_facts_naming_untainted_symbols_add_no_edges() {
        let mut idx = grounded_index();
        idx.reflection_facts.push(crate::scan::ReflectionFact {
            function_qnode: "f".to_string(),
            line: 4,
            call_type: "getattr".to_string(),
            target_symbols: vec!["cold".to_string()],
            receiver: String::new(),
            language: "python".to_string(),
        });
        let seed = build_taint_paths(&[idx], &BTreeMap::new(), 3);
        assert_eq!(seed.taint_evidence[0].edges.len(), 2);
    }

    #[test]
    fn reflection_is_skipped_for_a_path_whose_evidence_carries_no_edges() {
        let mut idx = file_index(
            "a.js",
            vec![func_def("f", 1, 9)],
            vec![call_site("a.js", 3, "f", "source", "network", "")],
            vec![call_site("a.js", 5, "f", "sink", "cmd", "CWE-78")],
            vec![],
            BTreeMap::new(),
        );
        idx.reflection_facts.push(crate::scan::ReflectionFact {
            function_qnode: "f".to_string(),
            target_symbols: vec!["raw".to_string()],
            ..Default::default()
        });
        let seed = build_taint_paths(&[idx], &BTreeMap::new(), 3);
        assert!(seed.taint_evidence[0].edges.is_empty());
    }

    #[test]
    fn framework_markers_become_their_own_entry_point_list() {
        let mut idx = file_index(
            "a.py",
            vec![func_def("show", 1, 9)],
            vec![],
            vec![],
            vec![],
            BTreeMap::new(),
        );
        idx.framework_markers
            .push(crate::scan::FrameworkMarkerFact {
                function_qnode: "show".to_string(),
                marker_name: "/u/{id}".to_string(),
                ..Default::default()
            });
        let seed = build_taint_paths(&[idx], &BTreeMap::new(), 3);
        assert!(seed.entry_points.is_empty());
        assert_eq!(seed.framework_entry_points.len(), 1);
        assert_eq!(seed.framework_entry_points[0].function, "show");
        assert_eq!(seed.framework_entry_points[0].kind, "framework");
    }

    #[test]
    fn a_response_write_widens_the_evidence_paths_cwe_set() {
        let mut idx = grounded_index();
        idx.response_dataflow
            .push(crate::scan::ResponseDataflowFact {
                function_qnode: "f".to_string(),
                line: 6,
                from_symbol: "raw".to_string(),
                to_sink: "HttpResponse".to_string(),
                framework: "django".to_string(),
                response_type: "html".to_string(),
            });
        let seed = build_taint_paths(&[idx], &BTreeMap::new(), 3);
        assert_eq!(
            seed.taint_evidence[0].sink_cwe,
            vec!["CWE-78".to_string(), "CWE-79".to_string()]
        );
    }
}
