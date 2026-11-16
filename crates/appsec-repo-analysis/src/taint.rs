use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::Path;
use std::sync::LazyLock;

use appsec_model::{Chunk, ChunkSize, ContextPackage, EntryPoint, EntryPointKind, Sink, Threat};
use regex::Regex;

use crate::callgraph::{q_file, q_join, q_name};
use crate::graph_view::{qnodes_at, seed_paths_by_file, GraphView};

#[derive(Debug, Clone, PartialEq)]
pub struct TaintChunkConfig {
    pub enabled: bool,
    pub max_hops: usize,
    pub max_chunks: usize,
    pub files_per_hop: usize,
}

impl TaintChunkConfig {
    pub fn new() -> Self {
        TaintChunkConfig {
            enabled: true,
            max_hops: 10,
            max_chunks: 60,
            files_per_hop: 5,
        }
    }
}

impl Default for TaintChunkConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct TaintChunkResult {
    pub chunks: Vec<Chunk>,
    pub total_sinks: usize,
    pub reached_sinks: usize,
    pub orphaned_sinks: Vec<String>,
}

#[derive(Default)]
struct TaintAccum<'a> {
    seen_paths: HashSet<(String, String, Vec<String>)>,
    chunk_by_work: HashMap<WorkSig, usize>,
    merges: Vec<ChunkMerge<'a>>,
    reached_fns: HashSet<String>,
    chunks: Vec<Chunk>,
    added: usize,
}

#[allow(clippy::too_many_arguments)]
fn emit_seed_chunks<'a>(
    acc: &mut TaintAccum<'a>,
    ep: &'a EntryPoint,
    ctx: &ContextPackage,
    view: &GraphView,
    sink_by_qn: &HashMap<String, Vec<usize>>,
    unsafe_sinks: &[Sink],
    threats: &[Threat],
    all_file_set: &HashSet<&String>,
    repo_root: &Path,
    config: &TaintChunkConfig,
) {
    for (sink_qn, qpath, src_ref, snk_ref, cwes) in
        seed_paths_for_entry(ctx, view, ep, sink_by_qn, unsafe_sinks, all_file_set)
    {
        if acc.added >= config.max_chunks {
            break;
        }
        let mut hop_files: Vec<String> = qpath
            .iter()
            .map(|fn_| q_file(fn_))
            .filter(|f| !f.is_empty())
            .collect();
        if hop_files.is_empty() {
            let (sf, _) = rpartition(&src_ref, ':');
            let (tf, _) = rpartition(&snk_ref, ':');
            hop_files = [sf, tf].into_iter().filter(|f| !f.is_empty()).collect();
        }
        let effective_len = if qpath.is_empty() { 2 } else { qpath.len() };
        let cap = (config.files_per_hop * effective_len) as i64;
        let mut files = pick_hop_files(&hop_files, std::slice::from_ref(&ep.file), cap);
        files.push(ep.file.clone());
        if !snk_ref.is_empty() {
            let (tf, _) = rpartition(&snk_ref, ':');
            if !tf.is_empty() {
                files.push(tf);
            }
        }
        let files = dedup_preserve_order(&files)
            .into_iter()
            .filter(|f| all_file_set.contains(f))
            .collect::<Vec<_>>();
        if files.is_empty() {
            continue;
        }

        let sig_key = if !sink_qn.is_empty() {
            sink_qn.clone()
        } else if !snk_ref.is_empty() {
            snk_ref.clone()
        } else {
            "seed".to_string()
        };
        let mut sorted_files = files.clone();
        sorted_files.sort();
        let legacy_sig = (ep.function.clone(), sig_key, sorted_files.clone());

        let source_ref = if !src_ref.is_empty() {
            src_ref
        } else {
            q_join(&ep.file, &ep.function)
        };
        let sink_ref = if !snk_ref.is_empty() {
            snk_ref.clone()
        } else if !sink_qn.is_empty() {
            q_file(&sink_qn)
        } else {
            String::new()
        };
        let threat_id = threat_for(&ep.function, threats);
        let work_sig: WorkSig = (
            source_ref.clone(),
            sink_ref.clone(),
            sorted_files,
            qpath.clone(),
            cwes.clone(),
            threat_id.clone(),
        );

        if let Some(&idx) = acc.chunk_by_work.get(&work_sig) {
            acc.seen_paths.insert(legacy_sig);
            if let Some(hypothesis) = acc.merges[idx].fold(ep) {
                acc.chunks[idx].focus_entry_points.push(ep.function.clone());
                acc.chunks[idx].hypothesis = hypothesis;
            }
            continue;
        }
        if !acc.seen_paths.insert(legacy_sig) {
            continue;
        }
        acc.added += 1;

        let loc: usize = files.iter().map(|f| count_lines(&repo_root.join(f))).sum();
        let sink_display = if !snk_ref.is_empty() {
            snk_ref.clone()
        } else if !sink_qn.is_empty() {
            sink_qn.clone()
        } else {
            "unknown".to_string()
        };

        let prefix = "Seed path evidence: ".to_string();
        let suffix = format!(
            " reaches sink [{sink_display}]. Validate each hop for missing sanitization and real exploitability."
        );
        acc.chunks.push(Chunk {
            id: format!("taint-{:02}", acc.added),
            size: size_for(loc),
            risk_rank: acc.added as i64,
            files,
            focus_entry_points: vec![ep.function.clone()],
            hypothesis: format!("{prefix}{}{suffix}", entry_phrase(ep, &[])),
            related_cves: Vec::new(),
            threat_id,
            languages: Vec::new(),
            specialist: None,
            path_funcs: qpath,
            source_ref,
            sink_ref,
            sink_cwe: cwes,
            shard_id: String::new(),
        });
        acc.merges.push(ChunkMerge {
            first: ep,
            rest: Vec::new(),
            prefix,
            suffix,
        });
        acc.chunk_by_work.insert(work_sig, acc.chunks.len() - 1);
    }
}

#[allow(clippy::too_many_arguments)]
fn emit_bfs_chunks<'a>(
    acc: &mut TaintAccum<'a>,
    ep: &'a EntryPoint,
    hits: &[(String, Vec<String>)],
    sink_by_qn: &HashMap<String, Vec<usize>>,
    unsafe_sinks: &[Sink],
    threats: &[Threat],
    all_file_set: &HashSet<&String>,
    repo_root: &Path,
    config: &TaintChunkConfig,
) {
    for (sink_qn, path) in hits {
        if acc.added >= config.max_chunks {
            break;
        }
        let sink_idxs: &[usize] = sink_by_qn.get(sink_qn).map(Vec::as_slice).unwrap_or(&[]);
        let sinks_here: Vec<&Sink> = sink_idxs.iter().map(|&i| &unsafe_sinks[i]).collect();
        let sink_files: Vec<String> = if sinks_here.is_empty() {
            vec![q_file(sink_qn)]
        } else {
            sinks_here.iter().map(|s| s.file.clone()).collect()
        };
        let mut anchors = vec![ep.file.clone()];
        anchors.extend(sink_files.iter().cloned());
        let hop_files: Vec<String> = path
            .iter()
            .map(|fn_| q_file(fn_))
            .filter(|f| !f.is_empty())
            .collect();
        let cap = (config.files_per_hop * path.len().max(1)) as i64;
        let mut files = pick_hop_files(&hop_files, &anchors, cap);
        files.push(ep.file.clone());
        files.extend(sink_files.iter().cloned());
        let files = dedup_preserve_order(&files)
            .into_iter()
            .filter(|f| all_file_set.contains(f))
            .collect::<Vec<_>>();
        if files.is_empty() {
            continue;
        }

        let mut sorted_files = files.clone();
        sorted_files.sort();
        let legacy_sig = (ep.function.clone(), sink_qn.clone(), sorted_files.clone());

        let sink_ref = sinks_here
            .first()
            .map(|s| format!("{}:{}", s.file, s.line))
            .unwrap_or_else(|| q_file(sink_qn));
        let mut sink_cwe: Vec<String> = sinks_here
            .iter()
            .flat_map(|s| s.cwe.iter().cloned())
            .collect();
        sink_cwe.sort();
        sink_cwe.dedup();
        let source_ref = q_join(&ep.file, &ep.function);
        let threat_id = threat_for(&ep.function, threats);
        let work_sig: WorkSig = (
            source_ref.clone(),
            sink_ref.clone(),
            sorted_files,
            path.clone(),
            sink_cwe.clone(),
            threat_id.clone(),
        );

        if acc.chunk_by_work.contains_key(&work_sig) {
            acc.seen_paths.insert(legacy_sig);
            continue;
        }
        if !acc.seen_paths.insert(legacy_sig) {
            continue;
        }
        acc.added += 1;

        let sink_refs = if sinks_here.is_empty() {
            q_file(sink_qn)
        } else {
            sinks_here
                .iter()
                .take(3)
                .map(|s| format!("{}:{}", s.file, s.line))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let unauth = if ep.reachable_from_unauth {
            "UNAUTH "
        } else {
            ""
        };
        let hop_chain = path
            .iter()
            .map(|n| q_name(n))
            .collect::<Vec<_>>()
            .join(" -> ");
        let loc: usize = files.iter().map(|f| count_lines(&repo_root.join(f))).sum();

        let prefix = format!("Taint path: {unauth}");
        let suffix = format!(
            " flows via {hop_chain} to sink {}() [{sink_refs}]. Verify every hop for sanitization/validation; if none, this is exploitable.",
            q_name(sink_qn)
        );
        acc.chunks.push(Chunk {
            id: format!("taint-{:02}", acc.added),
            size: size_for(loc),
            risk_rank: acc.added as i64,
            files,
            focus_entry_points: vec![ep.function.clone()],
            hypothesis: format!("{prefix}{}{suffix}", entry_phrase(ep, &[])),
            related_cves: Vec::new(),
            threat_id,
            languages: Vec::new(),
            specialist: None,
            path_funcs: path.clone(),
            source_ref,
            sink_ref,
            sink_cwe,
            shard_id: String::new(),
        });
        acc.merges.push(ChunkMerge {
            first: ep,
            rest: Vec::new(),
            prefix,
            suffix,
        });
        acc.chunk_by_work.insert(work_sig, acc.chunks.len() - 1);
    }
}
#[allow(clippy::too_many_arguments)]
pub fn add_taint_chunks(
    ctx: &ContextPackage,
    entry_points: &[EntryPoint],
    unsafe_sinks: &[Sink],
    threats: &[Threat],
    call_graph: &BTreeMap<String, Vec<String>>,
    all_files: &[String],
    repo_root: &Path,
    config: &TaintChunkConfig,
) -> TaintChunkResult {
    let total_sinks = unsafe_sinks.len();
    if !config.enabled || entry_points.is_empty() || unsafe_sinks.is_empty() {
        return TaintChunkResult {
            total_sinks,
            ..Default::default()
        };
    }

    let mut graph_nodes: HashSet<String> = call_graph.keys().cloned().collect();
    for vs in call_graph.values() {
        graph_nodes.extend(vs.iter().cloned());
    }
    let mut by_bare: HashMap<String, Vec<String>> = HashMap::new();
    for k in &graph_nodes {
        by_bare.entry(q_name(k)).or_default().push(k.clone());
    }

    let view = GraphView::new(ctx);

    let mut sink_qnodes: HashSet<String> = HashSet::new();
    let mut sink_by_qn: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, s) in unsafe_sinks.iter().enumerate() {
        if s.function.is_empty() && s.line <= 0 {
            continue;
        }
        for qn in sink_qnodes_for_sink(s, &view, &by_bare) {
            sink_qnodes.insert(qn.clone());
            sink_by_qn.entry(qn).or_default().push(i);
        }
    }

    let sink_cwes: HashMap<String, Vec<String>> = sink_by_qn
        .keys()
        .map(|qn| {
            (
                qn.clone(),
                cwe_union_for_sink_qn(qn, &sink_by_qn, unsafe_sinks),
            )
        })
        .collect();

    let all_file_set: HashSet<&String> = all_files.iter().collect();
    let entry_files: HashSet<&String> = entry_points.iter().map(|e| &e.file).collect();

    let mut entries: Vec<&EntryPoint> = entry_points.iter().collect();
    entries.sort_by_key(|e| (!e.reachable_from_unauth, kind_sort_key(e.kind)));

    let mut acc = TaintAccum::default();

    for ep in &entries {
        if acc.added >= config.max_chunks {
            break;
        }

        emit_seed_chunks(
            &mut acc,
            ep,
            ctx,
            &view,
            &sink_by_qn,
            unsafe_sinks,
            threats,
            &all_file_set,
            repo_root,
            config,
        );

        let mut hits: Vec<(String, Vec<String>)> = Vec::new();
        for start in match_qnodes(&ep.file, &ep.function, &by_bare) {
            hits.extend(bfs_to_sinks(
                &start,
                call_graph,
                &sink_qnodes,
                config.max_hops,
                &sink_cwes,
            ));
        }
        for (qn, _) in &hits {
            acc.reached_fns.insert(qn.clone());
        }
        if hits.is_empty() {
            hits = unsafe_sinks
                .iter()
                .filter(|s| s.file == ep.file)
                .map(|s| {
                    let sink_qn = q_join(&s.file, &s.function);
                    (
                        sink_qn,
                        vec![q_join(&ep.file, &ep.function), q_join(&s.file, &s.function)],
                    )
                })
                .collect();
        }

        emit_bfs_chunks(
            &mut acc,
            ep,
            &hits,
            &sink_by_qn,
            unsafe_sinks,
            threats,
            &all_file_set,
            repo_root,
            config,
        );
    }

    let reached_sink_idxs: HashSet<usize> = acc
        .reached_fns
        .iter()
        .filter_map(|qn| sink_by_qn.get(qn))
        .flatten()
        .copied()
        .collect();
    let orphaned_sinks: Vec<String> = unsafe_sinks
        .iter()
        .enumerate()
        .filter(|(i, s)| !reached_sink_idxs.contains(i) && !entry_files.contains(&s.file))
        .map(|(_, s)| format!("{}:{}", s.file, s.line))
        .collect();

    let reached_sinks = total_sinks - orphaned_sinks.len();
    TaintChunkResult {
        chunks: acc.chunks,
        total_sinks,
        reached_sinks,
        orphaned_sinks,
    }
}

type WorkSig = (
    String,
    String,
    Vec<String>,
    Vec<String>,
    Vec<String>,
    Option<String>,
);

struct ChunkMerge<'a> {
    first: &'a EntryPoint,
    rest: Vec<&'a EntryPoint>,
    prefix: String,
    suffix: String,
}

impl<'a> ChunkMerge<'a> {
    fn fold(&mut self, ep: &'a EntryPoint) -> Option<String> {
        let same = |e: &&EntryPoint| e.function == ep.function && e.file == ep.file;
        if same(&self.first) || self.rest.iter().any(same) {
            return None;
        }
        self.rest.push(ep);
        Some(format!(
            "{}{}{}",
            self.prefix,
            entry_phrase(self.first, &self.rest),
            self.suffix
        ))
    }
}

fn entry_phrase(first: &EntryPoint, rest: &[&EntryPoint]) -> String {
    let mut out = format!(
        "{} input at {}() [{}]",
        kind_sort_key(first.kind),
        first.function,
        first.file
    );
    if !rest.is_empty() {
        let also: Vec<String> = rest
            .iter()
            .map(|e| {
                if e.file == first.file {
                    format!("{}()", e.function)
                } else {
                    format!("{}() [{}]", e.function, e.file)
                }
            })
            .collect();
        out.push_str(&format!(" (and {})", also.join(", ")));
    }
    out
}

fn kind_sort_key(kind: EntryPointKind) -> &'static str {
    match kind {
        EntryPointKind::Cli => "cli",
        EntryPointKind::Deserialization => "deserialization",
        EntryPointKind::File => "file",
        EntryPointKind::Ipc => "ipc",
        EntryPointKind::Framework => "framework",
        EntryPointKind::Network => "network",
        EntryPointKind::Other => "other",
    }
}

fn match_qnodes(file: &str, name: &str, by_bare: &HashMap<String, Vec<String>>) -> Vec<String> {
    let empty: Vec<String> = Vec::new();
    let cands = by_bare.get(name).unwrap_or(&empty);
    let exact: Vec<String> = cands
        .iter()
        .filter(|k| q_file(k) == file)
        .cloned()
        .collect();
    if !exact.is_empty() {
        return exact;
    }
    let suffix: Vec<String> = cands
        .iter()
        .filter(|k| path_suffix(&q_file(k), file))
        .cloned()
        .collect();
    if !suffix.is_empty() {
        suffix
    } else {
        vec![q_join(file, name)]
    }
}

fn path_suffix(a: &str, b: &str) -> bool {
    a == b || a.ends_with(&format!("/{b}")) || b.ends_with(&format!("/{a}"))
}

fn rpartition(s: &str, sep: char) -> (String, String) {
    match s.rfind(sep) {
        Some(idx) => (s[..idx].to_string(), s[idx + sep.len_utf8()..].to_string()),
        None => (String::new(), s.to_string()),
    }
}

fn ref_file(r: &str) -> String {
    if r.is_empty() {
        return String::new();
    }
    if let Some(idx) = r.find("::") {
        return r[..idx].to_string();
    }
    match r.split_once(':') {
        Some((f, _)) => f.to_string(),
        None => r.to_string(),
    }
}

fn ref_line(r: &str) -> i64 {
    if r.is_empty() || r.contains("::") {
        return 0;
    }
    let (_, tail) = rpartition(r, ':');
    if !tail.is_empty() && tail.chars().all(|c| c.is_ascii_digit()) {
        tail.parse().unwrap_or(0)
    } else {
        0
    }
}

fn sink_qnodes_for_sink(
    s: &Sink,
    view: &GraphView,
    by_bare: &HashMap<String, Vec<String>>,
) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if !s.function.is_empty() {
        out.extend(match_qnodes(&s.file, &s.function, by_bare));
    }
    if out.is_empty() && s.line > 0 {
        if let Some(qn) = qnode_for_file_line(view, &s.file, s.line) {
            out.push(qn);
        }
    }
    let mut seen: HashSet<&str> = HashSet::new();
    let mut deduped = Vec::with_capacity(out.len());
    for qn in &out {
        if seen.insert(qn.as_str()) {
            deduped.push(qn.clone());
        }
    }
    deduped
}

fn qnode_for_file_line(view: &GraphView, file_rel: &str, line: i64) -> Option<String> {
    if line <= 0 {
        return None;
    }
    qnodes_at(view, file_rel, line, line, 1, true)
        .into_iter()
        .next()
}

fn cwe_union_for_sink_qn(
    sink_qn: &str,
    sink_by_qn: &HashMap<String, Vec<usize>>,
    unsafe_sinks: &[Sink],
) -> Vec<String> {
    let Some(idxs) = sink_by_qn.get(sink_qn) else {
        return Vec::new();
    };
    let mut set: HashSet<String> = HashSet::new();
    for &i in idxs {
        set.extend(unsafe_sinks[i].cwe.iter().cloned());
    }
    let mut out: Vec<String> = set.into_iter().collect();
    out.sort();
    out
}

fn dedup_preserve_order_str(items: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    items
        .iter()
        .filter(|i| seen.insert((*i).clone()))
        .cloned()
        .collect()
}

#[allow(clippy::type_complexity)]
fn seed_paths_for_entry(
    ctx: &ContextPackage,
    view: &GraphView,
    ep: &EntryPoint,
    sink_by_qn: &HashMap<String, Vec<usize>>,
    unsafe_sinks: &[Sink],
    all_file_set: &HashSet<&String>,
) -> Vec<(String, Vec<String>, String, String, Vec<String>)> {
    let mut out: Vec<(String, Vec<String>, String, String, Vec<String>)> = Vec::new();

    if !ctx.seed_taint_evidence.is_empty() {
        let mut seen_ev: HashSet<(String, String, Vec<String>)> = HashSet::new();
        for evidence in &ctx.seed_taint_evidence {
            if evidence.sanitized {
                continue;
            }
            let source_ref = evidence.source_ref.clone();
            let sink_ref = evidence.sink_ref.clone();
            let source_file = ref_file(&source_ref).replace('\\', "/");
            let sink_file = ref_file(&sink_ref).replace('\\', "/");
            if source_file != ep.file {
                continue;
            }

            let qpath = dedup_preserve_order_str(&evidence.path_funcs);
            let mut hop_files: Vec<String> = qpath
                .iter()
                .map(|fn_| q_file(fn_))
                .filter(|f| !f.is_empty())
                .collect();
            hop_files = dedup_preserve_order_str(&hop_files)
                .into_iter()
                .filter(|f| all_file_set.contains(f))
                .collect();
            if hop_files.is_empty() {
                hop_files = [source_file.clone(), sink_file.clone()]
                    .into_iter()
                    .filter(|f| all_file_set.contains(f))
                    .collect();
            }
            if hop_files.len() < 2 {
                continue;
            }

            let mut sink_qn = String::new();
            let sink_line = ref_line(&sink_ref);
            if all_file_set.contains(&sink_file) && sink_line > 0 {
                sink_qn = qnode_for_file_line(view, &sink_file, sink_line).unwrap_or_default();
            }
            if sink_qn.is_empty() {
                if let Some(last) = qpath.last() {
                    sink_qn = last.clone();
                }
            }

            let mut sink_cwe = dedup_preserve_order_str(&evidence.sink_cwe);
            sink_cwe.sort();
            if sink_cwe.is_empty() {
                sink_cwe = cwe_union_for_sink_qn(&sink_qn, sink_by_qn, unsafe_sinks);
            }

            let ev_key = (source_ref.clone(), sink_ref.clone(), qpath.clone());
            if !seen_ev.insert(ev_key) {
                continue;
            }
            out.push((sink_qn, qpath, source_ref, sink_ref, sink_cwe));
        }
        if !out.is_empty() {
            return out;
        }
    }

    let by_file = seed_paths_by_file(&ctx.seed_taint_paths);
    let Some(paths) = by_file.get(&ep.file) else {
        return out;
    };
    for path in paths {
        if path.len() < 2 {
            continue;
        }
        let mut qpath: Vec<String> = Vec::new();
        let mut hop_files: Vec<String> = Vec::new();
        for hop in path {
            let (hf, hline) = rpartition(hop, ':');
            let file_rel = if !hline.is_empty() { hf } else { hop.clone() };
            let file_rel = file_rel.replace('\\', "/");
            if !all_file_set.contains(&file_rel) {
                continue;
            }
            hop_files.push(file_rel.clone());
            if !hline.is_empty() && hline.chars().all(|c| c.is_ascii_digit()) {
                if let Ok(line) = hline.parse::<i64>() {
                    if let Some(qn) = qnode_for_file_line(view, &file_rel, line) {
                        qpath.push(qn);
                    }
                }
            }
        }
        if hop_files.len() < 2 {
            continue;
        }
        let qpath = dedup_preserve_order_str(&qpath);
        let sink_ref = path.last().cloned().unwrap_or_default();
        let (sf, sl) = rpartition(&sink_ref, ':');
        let mut sink_qn = String::new();
        let mut sink_cwe: Vec<String> = Vec::new();
        if !sf.is_empty() && !sl.is_empty() && sl.chars().all(|c| c.is_ascii_digit()) {
            if let Ok(line) = sl.parse::<i64>() {
                sink_qn = qnode_for_file_line(view, &sf, line).unwrap_or_default();
            }
            if !sink_qn.is_empty() {
                sink_cwe = cwe_union_for_sink_qn(&sink_qn, sink_by_qn, unsafe_sinks);
            }
        }
        let source_ref = path.first().cloned().unwrap_or_default();
        out.push((sink_qn, qpath, source_ref, sink_ref, sink_cwe));
    }
    out
}

const SANITIZER_UNIVERSAL: &[&str] = &[
    "escape",
    "quote",
    "strip_tags",
    "html_escape",
    "xml_escape",
    "quote_plus",
    "urlencode",
    "bleach_clean",
    "prepared_statement",
    "parameterized",
];

const SANITIZER_BY_CWE: &[(&str, &[&str])] = &[
    ("CWE-89", &["int", "float", "bool", "to_int"]),
    ("CWE-90", &["int", "float", "bool", "to_int"]),
    ("CWE-79", &["encode", "html_escape"]),
];

fn is_universal_sanitizer(bare: &str) -> bool {
    SANITIZER_UNIVERSAL.contains(&bare)
}

fn class_sanitizer_name(bare: &str) -> Option<&'static str> {
    SANITIZER_BY_CWE
        .iter()
        .flat_map(|(_, names)| names.iter())
        .find(|name| **name == bare)
        .copied()
}

fn cwe_sanitizers(cwe: &str) -> &'static [&'static str] {
    let upper = cwe.to_uppercase();
    SANITIZER_BY_CWE
        .iter()
        .find(|(key, _)| *key == upper)
        .map(|(_, names)| *names)
        .unwrap_or(&[])
}

pub fn bfs_to_sinks(
    start: &str,
    graph: &BTreeMap<String, Vec<String>>,
    sinks: &HashSet<String>,
    max_hops: usize,
    sink_cwes: &HashMap<String, Vec<String>>,
) -> Vec<(String, Vec<String>)> {
    if start.is_empty() {
        return Vec::new();
    }
    type State = (String, bool, BTreeSet<&'static str>);

    let mut out: Vec<(String, Vec<String>)> = Vec::new();
    let mut visited: HashSet<State> = HashSet::from([(start.to_string(), false, BTreeSet::new())]);
    let mut clean_sinks: HashSet<String> = HashSet::new();
    let mut sanitized_sinks_expanded: HashSet<State> = HashSet::new();
    let mut frontier: Vec<(String, Vec<String>, bool, BTreeSet<&'static str>)> = vec![(
        start.to_string(),
        vec![start.to_string()],
        false,
        BTreeSet::new(),
    )];

    while !frontier.is_empty() {
        let mut next = Vec::new();
        for (node, path, uhit, chits) in &frontier {
            let Some(callees) = graph.get(node) else {
                continue;
            };
            for callee in callees {
                let bare = q_name(callee).to_lowercase();
                let new_uhit = *uhit || is_universal_sanitizer(&bare);
                let mut new_chits = chits.clone();
                if let Some(name) = class_sanitizer_name(&bare) {
                    new_chits.insert(name);
                }
                let mut p = path.clone();
                p.push(callee.clone());
                let state: State = (callee.clone(), new_uhit, new_chits.clone());

                if sinks.contains(callee) {
                    if clean_sinks.contains(callee) {
                        continue;
                    }
                    let cwes = sink_cwes.get(callee).map(Vec::as_slice).unwrap_or(&[]);
                    let class_sanitized = !cwes.is_empty()
                        && cwes.iter().all(|cwe| {
                            let names = cwe_sanitizers(cwe);
                            new_chits.iter().any(|n| names.contains(n))
                        });
                    if new_uhit || class_sanitized {
                        if sanitized_sinks_expanded.insert(state) && p.len() <= max_hops {
                            next.push((callee.clone(), p, new_uhit, new_chits));
                        }
                    } else {
                        out.push((callee.clone(), p.clone()));
                        clean_sinks.insert(callee.clone());
                        if p.len() <= max_hops {
                            next.push((callee.clone(), p, new_uhit, new_chits));
                        }
                    }
                    continue;
                }

                if !visited.insert(state) {
                    continue;
                }
                if p.len() <= max_hops {
                    next.push((callee.clone(), p, new_uhit, new_chits));
                }
            }
        }
        frontier = next;
    }
    out
}

pub fn pick_hop_files(candidates: &[String], anchors: &[String], cap: i64) -> Vec<String> {
    let mut cands = dedup_preserve_order(candidates);
    if cap <= 0 || (cands.len() as i64) <= cap {
        return cands;
    }
    let anchor_parts: Vec<Vec<&str>> = anchors
        .iter()
        .filter(|a| !a.is_empty())
        .map(|a| a.split('/').collect())
        .collect();
    let affinity = |f: &str| -> usize {
        let parts: Vec<&str> = f.split('/').collect();
        anchor_parts
            .iter()
            .map(|ap| {
                parts
                    .iter()
                    .zip(ap.iter())
                    .take_while(|(x, y)| *x == *y)
                    .count()
            })
            .max()
            .unwrap_or(0)
    };
    cands.sort_by(|a, b| affinity(b).cmp(&affinity(a)).then_with(|| a.cmp(b)));
    cands.truncate(cap as usize);
    cands
}

fn dedup_preserve_order(items: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    items
        .iter()
        .filter(|i| seen.insert((*i).clone()))
        .cloned()
        .collect()
}

pub fn size_for(loc: usize) -> ChunkSize {
    if loc < 2000 {
        ChunkSize::Small
    } else if loc < 8000 {
        ChunkSize::Medium
    } else {
        ChunkSize::Large
    }
}

static TOKEN_RX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[a-z0-9]+").unwrap());

fn tokenize(s: &str) -> HashSet<String> {
    TOKEN_RX
        .find_iter(&s.to_lowercase())
        .map(|m| m.as_str().to_string())
        .collect()
}

pub fn threat_for(entry_function: &str, threats: &[Threat]) -> Option<String> {
    let fn_lower = entry_function.to_lowercase();
    let fn_tokens = tokenize(&fn_lower);
    let mut best: Option<String> = None;
    for t in threats {
        if t.surface.is_empty() {
            continue;
        }
        if t.surface.to_lowercase() == fn_lower {
            return Some(t.id.clone());
        }
        if best.is_none() && !fn_tokens.is_empty() && !tokenize(&t.surface).is_disjoint(&fn_tokens)
        {
            best = Some(t.id.clone());
        }
    }
    best
}

fn count_lines(path: &Path) -> usize {
    match std::fs::read(path) {
        Ok(bytes) => String::from_utf8_lossy(&bytes).lines().count(),
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use appsec_model::{Actor, Impact, Likelihood};

    fn ep(file: &str, function: &str, kind: EntryPointKind, reachable: bool) -> EntryPoint {
        EntryPoint {
            file: file.into(),
            function: function.into(),
            kind,
            reachable_from_unauth: reachable,
        }
    }

    fn sink(file: &str, line: i64, function: &str) -> Sink {
        Sink {
            file: file.into(),
            line,
            function: function.into(),
            snippet: String::new(),
            cwe: Vec::new(),
        }
    }

    fn threat(id: &str, surface: &str) -> Threat {
        Threat {
            id: id.into(),
            threat: format!("threat {id}"),
            actor: Actor::RemoteUnauth,
            surface: surface.into(),
            asset: "user-data".into(),
            impact: Impact::High,
            likelihood: Likelihood::Likely,
            controls: String::new(),
            evidence: String::new(),
        }
    }

    fn graph(pairs: &[(&str, &[&str])]) -> BTreeMap<String, Vec<String>> {
        pairs
            .iter()
            .map(|(k, vs)| (k.to_string(), vs.iter().map(|s| s.to_string()).collect()))
            .collect()
    }

    fn write(dir: &Path, rel: &str, contents: &str) {
        let path = dir.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }

    fn cwes(pairs: &[(&str, &[&str])]) -> HashMap<String, Vec<String>> {
        pairs
            .iter()
            .map(|(k, vs)| (k.to_string(), vs.iter().map(|s| s.to_string()).collect()))
            .collect()
    }

    fn no_cwes() -> HashMap<String, Vec<String>> {
        HashMap::new()
    }

    #[test]
    fn size_for_boundaries() {
        assert_eq!(size_for(0), ChunkSize::Small);
        assert_eq!(size_for(1999), ChunkSize::Small);
        assert_eq!(size_for(2000), ChunkSize::Medium);
        assert_eq!(size_for(7999), ChunkSize::Medium);
        assert_eq!(size_for(8000), ChunkSize::Large);
    }

    #[test]
    fn kind_sort_key_covers_every_variant() {
        assert_eq!(kind_sort_key(EntryPointKind::Cli), "cli");
        assert_eq!(
            kind_sort_key(EntryPointKind::Deserialization),
            "deserialization"
        );
        assert_eq!(kind_sort_key(EntryPointKind::File), "file");
        assert_eq!(kind_sort_key(EntryPointKind::Framework), "framework");
        assert_eq!(kind_sort_key(EntryPointKind::Ipc), "ipc");
        assert_eq!(kind_sort_key(EntryPointKind::Network), "network");
        assert_eq!(kind_sort_key(EntryPointKind::Other), "other");
    }

    #[test]
    fn dedup_preserve_order_keeps_first_occurrence() {
        let items: Vec<String> = ["a", "b", "a", "c", "b"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(dedup_preserve_order(&items), vec!["a", "b", "c"]);
    }

    #[test]
    fn count_lines_counts_trailing_and_non_trailing_newline_the_same() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.txt", "a\nb\nc");
        write(dir.path(), "b.txt", "a\nb\nc\n");
        write(dir.path(), "empty.txt", "");
        assert_eq!(count_lines(&dir.path().join("a.txt")), 3);
        assert_eq!(count_lines(&dir.path().join("b.txt")), 3);
        assert_eq!(count_lines(&dir.path().join("empty.txt")), 0);
    }

    #[test]
    fn count_lines_missing_file_is_zero() {
        assert_eq!(
            count_lines(Path::new("/nonexistent/path/does-not-exist.txt")),
            0
        );
    }

    #[test]
    fn match_qnodes_exact_match_wins_over_suffix() {
        let mut by_bare: HashMap<String, Vec<String>> = HashMap::new();
        by_bare.insert(
            "foo".into(),
            vec!["src/a.py::foo".into(), "src/b.py::foo".into()],
        );
        let hit = match_qnodes("src/a.py", "foo", &by_bare);
        assert_eq!(hit, vec!["src/a.py::foo".to_string()]);
    }

    #[test]
    fn match_qnodes_falls_back_to_boundary_anchored_suffix() {
        let mut by_bare: HashMap<String, Vec<String>> = HashMap::new();
        by_bare.insert("foo".into(), vec!["pkg/src/a.py::foo".into()]);
        let hit = match_qnodes("a.py", "foo", &by_bare);
        assert_eq!(hit, vec!["pkg/src/a.py::foo".to_string()]);
    }

    #[test]
    fn match_qnodes_does_not_match_a_partial_path_component() {
        let mut by_bare: HashMap<String, Vec<String>> = HashMap::new();
        by_bare.insert("foo".into(), vec!["src/oauth.py::foo".into()]);
        let hit = match_qnodes("auth.py", "foo", &by_bare);
        assert_eq!(hit, vec!["auth.py::foo".to_string()]);
    }

    #[test]
    fn match_qnodes_synthesizes_a_node_when_nothing_matches() {
        let by_bare: HashMap<String, Vec<String>> = HashMap::new();
        let hit = match_qnodes("x.py", "bar", &by_bare);
        assert_eq!(hit, vec!["x.py::bar".to_string()]);
    }

    #[test]
    fn bfs_to_sinks_finds_direct_neighbor() {
        let g = graph(&[("a", &["b"])]);
        let sinks: HashSet<String> = ["b".to_string()].into_iter().collect();
        let hits = bfs_to_sinks("a", &g, &sinks, 8, &no_cwes());
        assert_eq!(
            hits,
            vec![("b".to_string(), vec!["a".to_string(), "b".to_string()])]
        );
    }

    #[test]
    fn bfs_to_sinks_collects_all_reachable_sinks_not_just_the_first() {
        let g = graph(&[("a", &["b", "c"])]);
        let sinks: HashSet<String> = ["b".to_string(), "c".to_string()].into_iter().collect();
        let mut hits = bfs_to_sinks("a", &g, &sinks, 8, &no_cwes());
        hits.sort();
        assert_eq!(
            hits,
            vec![
                ("b".to_string(), vec!["a".to_string(), "b".to_string()]),
                ("c".to_string(), vec!["a".to_string(), "c".to_string()]),
            ]
        );
    }

    #[test]
    fn bfs_to_sinks_keeps_expanding_past_a_found_sink() {
        let g = graph(&[("a", &["b"]), ("b", &["c"])]);
        let sinks: HashSet<String> = ["b".to_string(), "c".to_string()].into_iter().collect();
        let mut hits = bfs_to_sinks("a", &g, &sinks, 8, &no_cwes());
        hits.sort();
        assert_eq!(
            hits,
            vec![
                ("b".to_string(), vec!["a".to_string(), "b".to_string()]),
                (
                    "c".to_string(),
                    vec!["a".to_string(), "b".to_string(), "c".to_string()]
                ),
            ]
        );
    }

    #[test]
    fn bfs_to_sinks_respects_max_hops() {
        let g = graph(&[("a", &["b"]), ("b", &["c"])]);
        let sinks: HashSet<String> = ["c".to_string()].into_iter().collect();
        let hits = bfs_to_sinks("a", &g, &sinks, 1, &no_cwes());
        assert!(hits.is_empty());
        let hits = bfs_to_sinks("a", &g, &sinks, 2, &no_cwes());
        assert_eq!(
            hits,
            vec![(
                "c".to_string(),
                vec!["a".to_string(), "b".to_string(), "c".to_string()]
            )]
        );
    }

    #[test]
    fn bfs_to_sinks_handles_cycles_without_looping_forever() {
        let g = graph(&[("a", &["b"]), ("b", &["a", "c"])]);
        let sinks: HashSet<String> = ["c".to_string()].into_iter().collect();
        let hits = bfs_to_sinks("a", &g, &sinks, 8, &no_cwes());
        assert_eq!(
            hits,
            vec![(
                "c".to_string(),
                vec!["a".to_string(), "b".to_string(), "c".to_string()]
            )]
        );
    }

    #[test]
    fn bfs_to_sinks_empty_start_returns_empty() {
        let g = graph(&[("a", &["b"])]);
        let sinks: HashSet<String> = ["b".to_string()].into_iter().collect();
        assert!(bfs_to_sinks("", &g, &sinks, 8, &no_cwes()).is_empty());
    }

    #[test]
    fn bfs_to_sinks_start_with_no_outgoing_edges_returns_empty() {
        let g = graph(&[]);
        let sinks: HashSet<String> = ["b".to_string()].into_iter().collect();
        assert!(bfs_to_sinks("a", &g, &sinks, 8, &no_cwes()).is_empty());
    }

    #[test]
    fn bfs_to_sinks_drops_a_sink_reached_only_through_a_universal_sanitizer() {
        let g = graph(&[("a", &["escape"]), ("escape", &["sink"])]);
        let sinks: HashSet<String> = ["sink".to_string()].into_iter().collect();
        assert!(bfs_to_sinks("a", &g, &sinks, 8, &no_cwes()).is_empty());
    }

    #[test]
    fn bfs_to_sinks_reports_a_sink_reached_only_through_an_unproven_validator() {
        let g = graph(&[("a", &["validate"]), ("validate", &["sink"])]);
        let sinks: HashSet<String> = ["sink".to_string()].into_iter().collect();
        let hits = bfs_to_sinks("a", &g, &sinks, 8, &cwes(&[("sink", &["CWE-78"])]));
        assert_eq!(
            hits,
            vec![(
                "sink".to_string(),
                vec!["a".to_string(), "validate".to_string(), "sink".to_string()]
            )]
        );
        for name in ["clean", "sanitize"] {
            let g = graph(&[("a", &[name]), (name, &["sink"])]);
            assert_eq!(
                bfs_to_sinks("a", &g, &sinks, 8, &cwes(&[("sink", &["CWE-78"])])).len(),
                1,
                "{name} is not evidence for any weakness class"
            );
        }
    }

    #[test]
    fn bfs_to_sinks_reports_a_sink_reachable_both_through_and_around_a_sanitizer() {
        for callees in [["escape", "mid"], ["mid", "escape"]] {
            let g = graph(&[
                ("a", &callees[..]),
                ("escape", &["sink"]),
                ("mid", &["sink"]),
            ]);
            let sinks: HashSet<String> = ["sink".to_string()].into_iter().collect();
            let hits = bfs_to_sinks("a", &g, &sinks, 8, &no_cwes());
            assert_eq!(
                hits,
                vec![(
                    "sink".to_string(),
                    vec!["a".to_string(), "mid".to_string(), "sink".to_string()]
                )],
                "callee order {callees:?} must not change the result"
            );
        }
    }

    #[test]
    fn bfs_to_sinks_a_numeric_coercion_neutralizes_injection_but_not_other_classes() {
        let g = graph(&[("a", &["int"]), ("int", &["sink"])]);
        let sinks: HashSet<String> = ["sink".to_string()].into_iter().collect();
        for cwe in ["CWE-89", "CWE-90"] {
            assert!(
                bfs_to_sinks("a", &g, &sinks, 8, &cwes(&[("sink", &[cwe])])).is_empty(),
                "{cwe} is neutralized by a numeric coercion"
            );
        }
        assert_eq!(
            bfs_to_sinks("a", &g, &sinks, 8, &cwes(&[("sink", &["CWE-78"])])).len(),
            1
        );
        assert_eq!(
            bfs_to_sinks("a", &g, &sinks, 8, &cwes(&[("sink", &["CWE-79"])])).len(),
            1
        );
    }

    #[test]
    fn bfs_to_sinks_encoding_neutralizes_xss_but_not_command_injection() {
        let g = graph(&[("a", &["encode"]), ("encode", &["sink"])]);
        let sinks: HashSet<String> = ["sink".to_string()].into_iter().collect();
        assert!(bfs_to_sinks("a", &g, &sinks, 8, &cwes(&[("sink", &["CWE-79"])])).is_empty());
        assert_eq!(
            bfs_to_sinks("a", &g, &sinks, 8, &cwes(&[("sink", &["CWE-78"])])).len(),
            1
        );
    }

    #[test]
    fn bfs_to_sinks_class_sanitizer_match_is_case_insensitive_on_the_cwe_id() {
        let g = graph(&[("a", &["to_int"]), ("to_int", &["sink"])]);
        let sinks: HashSet<String> = ["sink".to_string()].into_iter().collect();
        assert!(bfs_to_sinks("a", &g, &sinks, 8, &cwes(&[("sink", &["cwe-89"])])).is_empty());
    }

    #[test]
    fn bfs_to_sinks_every_cwe_at_a_sink_must_be_sanitized_not_just_one() {
        let g = graph(&[("a", &["int"]), ("int", &["sink"])]);
        let sinks: HashSet<String> = ["sink".to_string()].into_iter().collect();
        assert_eq!(
            bfs_to_sinks(
                "a",
                &g,
                &sinks,
                8,
                &cwes(&[("sink", &["CWE-89", "CWE-78"])])
            )
            .len(),
            1
        );
        assert!(bfs_to_sinks(
            "a",
            &g,
            &sinks,
            8,
            &cwes(&[("sink", &["CWE-89", "CWE-90"])])
        )
        .is_empty());
    }

    #[test]
    fn bfs_to_sinks_a_sink_with_no_cwes_is_never_class_sanitized() {
        let g = graph(&[("a", &["int"]), ("int", &["sink"])]);
        let sinks: HashSet<String> = ["sink".to_string()].into_iter().collect();
        assert_eq!(bfs_to_sinks("a", &g, &sinks, 8, &no_cwes()).len(), 1);
        assert_eq!(
            bfs_to_sinks("a", &g, &sinks, 8, &cwes(&[("sink", &[])])).len(),
            1
        );
        assert_eq!(
            bfs_to_sinks("a", &g, &sinks, 8, &cwes(&[("sink", &["CWE-22"])])).len(),
            1
        );
    }

    #[test]
    fn bfs_to_sinks_a_universal_sanitizer_neutralizes_even_a_class_tagged_sink() {
        let g = graph(&[("a", &["quote_plus"]), ("quote_plus", &["sink"])]);
        let sinks: HashSet<String> = ["sink".to_string()].into_iter().collect();
        assert!(bfs_to_sinks("a", &g, &sinks, 8, &cwes(&[("sink", &["CWE-78"])])).is_empty());
    }

    #[test]
    fn bfs_to_sinks_a_class_sanitized_sink_is_expanded_through_exactly_once() {
        let g = graph(&[
            ("a", &["int"]),
            ("int", &["sink1"]),
            ("sink1", &["a", "sink2"]),
        ]);
        let sinks: HashSet<String> = ["sink1".to_string(), "sink2".to_string()]
            .into_iter()
            .collect();
        let hits = bfs_to_sinks("a", &g, &sinks, 8, &cwes(&[("sink1", &["CWE-89"])]));
        assert_eq!(
            hits,
            vec![(
                "sink2".to_string(),
                vec![
                    "a".to_string(),
                    "int".to_string(),
                    "sink1".to_string(),
                    "sink2".to_string()
                ]
            )]
        );
    }

    #[test]
    fn bfs_to_sinks_class_hits_accumulate_across_hops() {
        let g = graph(&[("a", &["int"]), ("int", &["mid"]), ("mid", &["sink"])]);
        let sinks: HashSet<String> = ["sink".to_string()].into_iter().collect();
        assert!(bfs_to_sinks("a", &g, &sinks, 8, &cwes(&[("sink", &["CWE-89"])])).is_empty());
        assert_eq!(
            bfs_to_sinks("a", &g, &sinks, 8, &cwes(&[("sink", &["CWE-78"])])).len(),
            1
        );
    }

    #[test]
    fn bfs_to_sinks_one_node_is_explored_once_per_distinct_sanitizer_history() {
        let g = graph(&[
            ("a", &["int", "plain"]),
            ("int", &["mid"]),
            ("plain", &["mid"]),
            ("mid", &["sink"]),
        ]);
        let sinks: HashSet<String> = ["sink".to_string()].into_iter().collect();
        let hits = bfs_to_sinks("a", &g, &sinks, 8, &cwes(&[("sink", &["CWE-89"])]));
        assert_eq!(
            hits,
            vec![(
                "sink".to_string(),
                vec![
                    "a".to_string(),
                    "plain".to_string(),
                    "mid".to_string(),
                    "sink".to_string()
                ]
            )]
        );
    }

    #[test]
    fn bfs_to_sinks_still_finds_other_sinks_past_a_sanitized_path() {
        let g = graph(&[("a", &["escape", "sink2"]), ("escape", &["sink1"])]);
        let sinks: HashSet<String> = ["sink1".to_string(), "sink2".to_string()]
            .into_iter()
            .collect();
        let hits = bfs_to_sinks("a", &g, &sinks, 8, &no_cwes());
        assert_eq!(
            hits,
            vec![(
                "sink2".to_string(),
                vec!["a".to_string(), "sink2".to_string()]
            )]
        );
    }

    #[test]
    fn bfs_to_sinks_sanitizer_match_is_case_insensitive() {
        let g = graph(&[("a", &["ESCAPE"]), ("ESCAPE", &["sink"])]);
        let sinks: HashSet<String> = ["sink".to_string()].into_iter().collect();
        assert!(bfs_to_sinks("a", &g, &sinks, 8, &no_cwes()).is_empty());
    }

    #[test]
    fn bfs_to_sinks_sanitizer_match_uses_the_bare_qualified_suffix() {
        let g = graph(&[
            ("a.py::a", &["pkg/mod.py::escape"]),
            ("pkg/mod.py::escape", &["sink.py::sink"]),
        ]);
        let sinks: HashSet<String> = ["sink.py::sink".to_string()].into_iter().collect();
        assert!(bfs_to_sinks("a.py::a", &g, &sinks, 8, &no_cwes()).is_empty());
    }

    #[test]
    fn bfs_to_sinks_a_node_that_is_itself_both_sink_and_sanitizer_is_judged_per_class() {
        let g = graph(&[("a", &["escape"])]);
        let sinks: HashSet<String> = ["escape".to_string()].into_iter().collect();
        assert!(bfs_to_sinks("a", &g, &sinks, 8, &no_cwes()).is_empty());

        let g = graph(&[("a", &["int"])]);
        let sinks: HashSet<String> = ["int".to_string()].into_iter().collect();
        assert_eq!(
            bfs_to_sinks("a", &g, &sinks, 8, &cwes(&[("int", &["CWE-78"])])),
            vec![("int".to_string(), vec!["a".to_string(), "int".to_string()])]
        );
        assert!(bfs_to_sinks("a", &g, &sinks, 8, &cwes(&[("int", &["CWE-89"])])).is_empty());
    }

    #[test]
    fn pick_hop_files_returns_deduped_list_unsorted_when_under_cap() {
        let candidates: Vec<String> = ["a", "b", "a", "c"].iter().map(|s| s.to_string()).collect();
        assert_eq!(pick_hop_files(&candidates, &[], 10), vec!["a", "b", "c"]);
    }

    #[test]
    fn pick_hop_files_zero_cap_means_no_cap() {
        let candidates: Vec<String> = ["a", "b", "c"].iter().map(|s| s.to_string()).collect();
        assert_eq!(pick_hop_files(&candidates, &[], 0), vec!["a", "b", "c"]);
    }

    #[test]
    fn pick_hop_files_ranks_by_anchor_affinity_then_truncates() {
        let candidates: Vec<String> = ["z/1.py", "a/x/2.py", "a/x/3.py", "b/4.py"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let anchors = vec!["a/x/main.py".to_string()];
        let picked = pick_hop_files(&candidates, &anchors, 2);
        assert_eq!(picked, vec!["a/x/2.py".to_string(), "a/x/3.py".to_string()]);
    }

    #[test]
    fn pick_hop_files_empty_anchors_ties_break_alphabetically() {
        let candidates: Vec<String> = ["z.py", "a.py", "m.py"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let picked = pick_hop_files(&candidates, &[], 2);
        assert_eq!(picked, vec!["a.py".to_string(), "m.py".to_string()]);
    }

    #[test]
    fn exact_match_assigns_threat_id() {
        let threats = vec![threat("T1", "handle_login")];
        assert_eq!(threat_for("handle_login", &threats), Some("T1".to_string()));
    }

    #[test]
    fn exact_match_is_case_insensitive() {
        let threats = vec![threat("T7", "Handle_Login")];
        assert_eq!(threat_for("handle_login", &threats), Some("T7".to_string()));
    }

    #[test]
    fn exact_match_beats_an_earlier_token_match() {
        let threats = vec![threat("T1", "login"), threat("T2", "handle_login")];
        assert_eq!(threat_for("handle_login", &threats), Some("T2".to_string()));
    }

    #[test]
    fn shared_token_match_when_no_exact() {
        let threats = vec![threat("T9", "login_v2")];
        assert_eq!(threat_for("handle_login", &threats), Some("T9".to_string()));
    }

    #[test]
    fn first_token_sharing_threat_wins() {
        let threats = vec![threat("T1", "do_login"), threat("T2", "handle_request")];
        assert_eq!(threat_for("handle_login", &threats), Some("T1".to_string()));
    }

    #[test]
    fn token_match_is_case_insensitive() {
        let threats = vec![threat("T3", "USER_LOGIN")];
        assert_eq!(threat_for("handle_login", &threats), Some("T3".to_string()));
    }

    #[test]
    fn substring_inside_a_token_does_not_match() {
        let threats = vec![threat("T5", "log")];
        assert_eq!(threat_for("handle_login", &threats), None);
    }

    #[test]
    fn reverse_substring_does_not_match() {
        let threats = vec![threat("T6", "authenticate")];
        assert_eq!(threat_for("auth", &threats), None);
    }

    #[test]
    fn surface_matching_the_file_path_does_not_match() {
        let threats = vec![threat("T8", "login")];
        assert_eq!(threat_for("process", &threats), None);
    }

    #[test]
    fn surface_matching_path_directory_does_not_match() {
        let threats = vec![threat("T8", "app")];
        assert_eq!(threat_for("process", &threats), None);
    }

    #[test]
    fn empty_surface_is_skipped() {
        let threats = vec![threat("T1", ""), threat("T2", "login")];
        assert_eq!(threat_for("handle_login", &threats), Some("T2".to_string()));
    }

    #[test]
    fn no_threats_yields_none() {
        assert_eq!(threat_for("handle_login", &[]), None);
    }

    #[test]
    fn no_matching_threat_yields_none() {
        let threats = vec![threat("T1", "totally_unrelated")];
        assert_eq!(threat_for("handle_login", &threats), None);
    }

    #[test]
    fn digit_tokens_participate_in_matching() {
        let threats = vec![threat("T4", "endpoint_v2")];
        assert_eq!(threat_for("parse_v2", &threats), Some("T4".to_string()));
    }

    #[test]
    fn a_sink_with_a_line_but_no_function_is_resolved_not_skipped() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "app/login.py", "line1\nline2\n");
        write(dir.path(), "app/db.py", "line1\nline2\n");

        let entry_points = vec![ep(
            "app/login.py",
            "handle_login",
            EntryPointKind::Network,
            true,
        )];
        let sinks = vec![sink("app/db.py", 42, "")];
        let cg = graph(&[("app/login.py::handle_login", &["app/db.py::run_query"])]);
        let all_files = vec!["app/login.py".to_string(), "app/db.py".to_string()];

        let mut ctx = ContextPackage::default();
        ctx.def_spans
            .insert("app/db.py::run_query".to_string(), (40, 50));

        let result = add_taint_chunks(
            &ctx,
            &entry_points,
            &sinks,
            &[],
            &cg,
            &all_files,
            dir.path(),
            &TaintChunkConfig::new(),
        );

        assert_eq!(result.chunks.len(), 1, "{:?}", result.chunks);
        assert!(result.chunks[0].hypothesis.contains("run_query"));
        assert_eq!(result.reached_sinks, 1);
        assert!(result.orphaned_sinks.is_empty());
    }

    #[test]
    fn a_sink_with_neither_a_function_nor_a_line_is_still_skipped() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "app/login.py", "line1\n");
        write(dir.path(), "app/db.py", "line1\n");
        let entry_points = vec![ep(
            "app/login.py",
            "handle_login",
            EntryPointKind::Network,
            true,
        )];
        let sinks = vec![sink("app/db.py", 0, "")];
        let cg = graph(&[("app/login.py::handle_login", &["app/db.py::run_query"])]);
        let mut ctx = ContextPackage::default();
        ctx.def_spans
            .insert("app/db.py::run_query".to_string(), (1, 5));
        let result = add_taint_chunks(
            &ctx,
            &entry_points,
            &sinks,
            &[],
            &cg,
            &["app/login.py".to_string(), "app/db.py".to_string()],
            dir.path(),
            &TaintChunkConfig::new(),
        );
        assert!(result.chunks.is_empty(), "{:?}", result.chunks);
        assert_eq!(result.reached_sinks, 0);
        assert_eq!(result.orphaned_sinks, vec!["app/db.py:0".to_string()]);
    }

    #[test]
    fn sink_qnodes_for_sink_prefers_the_function_and_dedups() {
        let view = GraphView::new(&ContextPackage::default());
        let mut by_bare: HashMap<String, Vec<String>> = HashMap::new();
        by_bare.insert(
            "run".to_string(),
            vec!["a.py::run".to_string(), "a.py::run".to_string()],
        );
        let got = sink_qnodes_for_sink(&sink("a.py", 5, "run"), &view, &by_bare);
        assert_eq!(got, vec!["a.py::run".to_string()]);
    }

    #[test]
    fn sink_qnodes_for_sink_returns_nothing_when_a_line_anchor_resolves_to_nothing() {
        let view = GraphView::new(&ContextPackage::default());
        let by_bare: HashMap<String, Vec<String>> = HashMap::new();
        assert!(sink_qnodes_for_sink(&sink("a.py", 5, ""), &view, &by_bare).is_empty());
    }

    #[test]
    fn basic_taint_chunk_emitted_via_call_graph_edge() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "app/login.py", "line1\nline2\nline3\n");

        let entry_points = vec![ep(
            "app/login.py",
            "handle_login",
            EntryPointKind::Network,
            true,
        )];
        let sinks = vec![sink("app/login.py", 42, "run_query")];
        let cg = graph(&[("app/login.py::handle_login", &["app/login.py::run_query"])]);
        let all_files = vec!["app/login.py".to_string()];

        let result = add_taint_chunks(
            &ContextPackage::default(),
            &entry_points,
            &sinks,
            &[],
            &cg,
            &all_files,
            dir.path(),
            &TaintChunkConfig::new(),
        );

        assert_eq!(result.chunks.len(), 1);
        let chunk = &result.chunks[0];
        assert_eq!(chunk.id, "taint-01");
        assert_eq!(chunk.risk_rank, 1);
        assert_eq!(chunk.focus_entry_points, vec!["handle_login".to_string()]);
        assert!(chunk.files.contains(&"app/login.py".to_string()));
        assert_eq!(chunk.size, ChunkSize::Small);
        assert!(chunk.threat_id.is_none());
        assert!(chunk.hypothesis.contains("network"));
        assert!(chunk.hypothesis.contains("handle_login"));
        assert!(chunk.hypothesis.contains("run_query"));
        assert!(chunk.hypothesis.contains("UNAUTH"));

        assert_eq!(result.total_sinks, 1);
        assert_eq!(result.reached_sinks, 1);
        assert!(result.orphaned_sinks.is_empty());

        assert_eq!(
            chunk.path_funcs,
            vec!["app/login.py::handle_login", "app/login.py::run_query"]
        );
        assert_eq!(chunk.source_ref, "app/login.py::handle_login");
        assert_eq!(chunk.sink_ref, "app/login.py:42");
        assert!(chunk.sink_cwe.is_empty());
    }

    #[test]
    fn taint_chunk_unions_and_dedupes_cwe_tags_across_matched_sinks_at_one_qnode() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "app/login.py", "line1\nline2\nline3\n");

        let entry_points = vec![ep(
            "app/login.py",
            "handle_login",
            EntryPointKind::Network,
            true,
        )];
        let sinks = vec![
            Sink {
                file: "app/login.py".to_string(),
                line: 42,
                function: "run_query".to_string(),
                snippet: String::new(),
                cwe: vec!["CWE-89".to_string(), "CWE-943".to_string()],
            },
            Sink {
                file: "app/login.py".to_string(),
                line: 42,
                function: "run_query".to_string(),
                snippet: String::new(),
                cwe: vec!["CWE-89".to_string()],
            },
        ];
        let cg = graph(&[("app/login.py::handle_login", &["app/login.py::run_query"])]);
        let all_files = vec!["app/login.py".to_string()];

        let result = add_taint_chunks(
            &ContextPackage::default(),
            &entry_points,
            &sinks,
            &[],
            &cg,
            &all_files,
            dir.path(),
            &TaintChunkConfig::new(),
        );

        assert_eq!(result.chunks.len(), 1);
        assert_eq!(
            result.chunks[0].sink_cwe,
            vec!["CWE-89".to_string(), "CWE-943".to_string()]
        );
        assert_eq!(result.chunks[0].sink_ref, "app/login.py:42");
    }

    #[test]
    fn disabled_config_returns_empty_with_total_sinks_set() {
        let entry_points = vec![ep("a.py", "f", EntryPointKind::Other, false)];
        let sinks = vec![sink("a.py", 1, "g")];
        let mut cfg = TaintChunkConfig::new();
        cfg.enabled = false;

        let result = add_taint_chunks(
            &ContextPackage::default(),
            &entry_points,
            &sinks,
            &[],
            &graph(&[]),
            &[],
            Path::new("/x"),
            &cfg,
        );
        assert!(result.chunks.is_empty());
        assert_eq!(result.total_sinks, 1);
        assert_eq!(result.reached_sinks, 0);
        assert!(result.orphaned_sinks.is_empty());
    }

    #[test]
    fn no_entry_points_returns_empty_with_total_sinks_set() {
        let sinks = vec![sink("a.py", 1, "g")];
        let result = add_taint_chunks(
            &ContextPackage::default(),
            &[],
            &sinks,
            &[],
            &graph(&[]),
            &[],
            Path::new("/x"),
            &TaintChunkConfig::new(),
        );
        assert!(result.chunks.is_empty());
        assert_eq!(result.total_sinks, 1);
    }

    #[test]
    fn no_sinks_returns_empty() {
        let entry_points = vec![ep("a.py", "f", EntryPointKind::Other, false)];
        let result = add_taint_chunks(
            &ContextPackage::default(),
            &entry_points,
            &[],
            &[],
            &graph(&[]),
            &[],
            Path::new("/x"),
            &TaintChunkConfig::new(),
        );
        assert!(result.chunks.is_empty());
        assert_eq!(result.total_sinks, 0);
    }

    #[test]
    fn direct_sink_in_entry_file_without_graph_edge_still_emits_chunk() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "svc/handler.py", "a\nb\n");

        let entry_points = vec![ep("svc/handler.py", "handle", EntryPointKind::Cli, false)];
        let sinks = vec![sink("svc/handler.py", 10, "run_query")];
        let all_files = vec!["svc/handler.py".to_string()];

        let result = add_taint_chunks(
            &ContextPackage::default(),
            &entry_points,
            &sinks,
            &[],
            &graph(&[]),
            &all_files,
            dir.path(),
            &TaintChunkConfig::new(),
        );

        assert_eq!(result.chunks.len(), 1);
        assert!(result.chunks[0]
            .files
            .contains(&"svc/handler.py".to_string()));
        assert_eq!(result.reached_sinks, 1);
        assert!(result.orphaned_sinks.is_empty());
    }

    #[test]
    fn duplicate_signature_paths_are_deduped() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.py", "x\n");
        write(dir.path(), "sink.py", "y\n");

        let entry_points = vec![ep("a.py", "f", EntryPointKind::Other, false)];
        let sinks = vec![sink("sink.py", 5, "g")];
        let cg = graph(&[
            ("pkg1/a.py::f", &["sink.py::g"]),
            ("pkg2/a.py::f", &["sink.py::g"]),
        ]);
        let all_files = vec!["a.py".to_string(), "sink.py".to_string()];

        let result = add_taint_chunks(
            &ContextPackage::default(),
            &entry_points,
            &sinks,
            &[],
            &cg,
            &all_files,
            dir.path(),
            &TaintChunkConfig::new(),
        );

        assert_eq!(result.chunks.len(), 1);
    }

    #[test]
    fn max_chunks_stops_the_entry_loop() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "e1.py", "x\n");
        write(dir.path(), "e2.py", "x\n");
        write(dir.path(), "e3.py", "x\n");
        write(dir.path(), "s1.py", "x\n");
        write(dir.path(), "s2.py", "x\n");
        write(dir.path(), "s3.py", "x\n");

        let entry_points = vec![
            ep("e1.py", "f1", EntryPointKind::Network, true),
            ep("e2.py", "f2", EntryPointKind::Network, true),
            ep("e3.py", "f3", EntryPointKind::Network, false),
        ];
        let sinks = vec![
            sink("s1.py", 1, "g1"),
            sink("s2.py", 2, "g2"),
            sink("s3.py", 3, "g3"),
        ];
        let cg = graph(&[
            ("e1.py::f1", &["s1.py::g1"]),
            ("e2.py::f2", &["s2.py::g2"]),
            ("e3.py::f3", &["s3.py::g3"]),
        ]);
        let all_files: Vec<String> = ["e1.py", "e2.py", "e3.py", "s1.py", "s2.py", "s3.py"]
            .iter()
            .map(|s| s.to_string())
            .collect();

        let mut cfg = TaintChunkConfig::new();
        cfg.max_chunks = 2;

        let result = add_taint_chunks(
            &ContextPackage::default(),
            &entry_points,
            &sinks,
            &[],
            &cg,
            &all_files,
            dir.path(),
            &cfg,
        );

        assert_eq!(result.chunks.len(), 2);
        assert_eq!(result.chunks[0].focus_entry_points, vec!["f1".to_string()]);
        assert_eq!(result.chunks[1].focus_entry_points, vec!["f2".to_string()]);
    }

    #[test]
    fn max_chunks_stops_mid_hit_loop_for_a_single_entry() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "e.py", "x\n");
        write(dir.path(), "s1.py", "x\n");
        write(dir.path(), "s2.py", "x\n");

        let entry_points = vec![ep("e.py", "f", EntryPointKind::Network, true)];
        let sinks = vec![sink("s1.py", 1, "g1"), sink("s2.py", 2, "g2")];
        let cg = graph(&[("e.py::f", &["s1.py::g1", "s2.py::g2"])]);
        let all_files: Vec<String> = ["e.py", "s1.py", "s2.py"]
            .iter()
            .map(|s| s.to_string())
            .collect();

        let mut cfg = TaintChunkConfig::new();
        cfg.max_chunks = 1;

        let result = add_taint_chunks(
            &ContextPackage::default(),
            &entry_points,
            &sinks,
            &[],
            &cg,
            &all_files,
            dir.path(),
            &cfg,
        );
        assert_eq!(result.chunks.len(), 1);
    }

    #[test]
    fn orphaned_sink_reported_when_unreachable_and_not_colocated() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "e.py", "x\n");
        write(dir.path(), "s.py", "x\n");
        write(dir.path(), "orphan.py", "x\n");

        let entry_points = vec![ep("e.py", "f", EntryPointKind::Network, true)];
        let sinks = vec![sink("s.py", 5, "g"), sink("orphan.py", 99, "h")];
        let cg = graph(&[("e.py::f", &["s.py::g"])]);
        let all_files: Vec<String> = ["e.py", "s.py", "orphan.py"]
            .iter()
            .map(|s| s.to_string())
            .collect();

        let result = add_taint_chunks(
            &ContextPackage::default(),
            &entry_points,
            &sinks,
            &[],
            &cg,
            &all_files,
            dir.path(),
            &TaintChunkConfig::new(),
        );

        assert_eq!(result.total_sinks, 2);
        assert_eq!(result.reached_sinks, 1);
        assert_eq!(result.orphaned_sinks, vec!["orphan.py:99".to_string()]);
    }

    #[test]
    fn multi_hop_path_includes_intermediate_files_within_cap() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "e.py", "x\n");
        write(dir.path(), "mid.py", "x\n");
        write(dir.path(), "s.py", "x\n");

        let entry_points = vec![ep("e.py", "f", EntryPointKind::Network, true)];
        let sinks = vec![sink("s.py", 1, "g")];
        let cg = graph(&[("e.py::f", &["mid.py::h"]), ("mid.py::h", &["s.py::g"])]);
        let all_files: Vec<String> = ["e.py", "mid.py", "s.py"]
            .iter()
            .map(|s| s.to_string())
            .collect();

        let result = add_taint_chunks(
            &ContextPackage::default(),
            &entry_points,
            &sinks,
            &[],
            &cg,
            &all_files,
            dir.path(),
            &TaintChunkConfig::new(),
        );

        assert_eq!(result.chunks.len(), 1);
        assert!(result.chunks[0].files.contains(&"mid.py".to_string()));
        assert!(result.chunks[0].hypothesis.contains("h -> g"));
    }

    #[test]
    fn threat_id_is_wired_through_from_threat_for() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "e.py", "x\n");
        write(dir.path(), "s.py", "x\n");

        let entry_points = vec![ep("e.py", "handle_login", EntryPointKind::Network, true)];
        let sinks = vec![sink("s.py", 1, "g")];
        let cg = graph(&[("e.py::handle_login", &["s.py::g"])]);
        let all_files: Vec<String> = ["e.py", "s.py"].iter().map(|s| s.to_string()).collect();
        let threats = vec![threat("T1", "handle_login")];

        let result = add_taint_chunks(
            &ContextPackage::default(),
            &entry_points,
            &sinks,
            &threats,
            &cg,
            &all_files,
            dir.path(),
            &TaintChunkConfig::new(),
        );

        assert_eq!(result.chunks[0].threat_id, Some("T1".to_string()));
    }

    #[test]
    fn missing_file_on_disk_yields_zero_loc_but_still_emits_chunk() {
        let dir = tempfile::tempdir().unwrap();
        let entry_points = vec![ep("e.py", "f", EntryPointKind::Network, true)];
        let sinks = vec![sink("s.py", 1, "g")];
        let cg = graph(&[("e.py::f", &["s.py::g"])]);
        let all_files: Vec<String> = ["e.py", "s.py"].iter().map(|s| s.to_string()).collect();

        let result = add_taint_chunks(
            &ContextPackage::default(),
            &entry_points,
            &sinks,
            &[],
            &cg,
            &all_files,
            dir.path(),
            &TaintChunkConfig::new(),
        );

        assert_eq!(result.chunks.len(), 1);
        assert_eq!(result.chunks[0].size, ChunkSize::Small);
    }

    #[test]
    fn files_not_in_all_files_are_filtered_out_of_the_chunk() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "e.py", "x\n");
        write(dir.path(), "s.py", "x\n");

        let entry_points = vec![ep("e.py", "f", EntryPointKind::Network, true)];
        let sinks = vec![sink("s.py", 1, "g")];
        let cg = graph(&[("e.py::f", &["s.py::g"])]);
        let all_files: Vec<String> = ["s.py"].iter().map(|s| s.to_string()).collect();

        let result = add_taint_chunks(
            &ContextPackage::default(),
            &entry_points,
            &sinks,
            &[],
            &cg,
            &all_files,
            dir.path(),
            &TaintChunkConfig::new(),
        );

        assert_eq!(result.chunks.len(), 1);
        assert!(!result.chunks[0].files.contains(&"e.py".to_string()));
    }

    #[test]
    fn empty_files_after_filtering_drops_the_hit_entirely() {
        let entry_points = vec![ep("e.py", "f", EntryPointKind::Network, true)];
        let sinks = vec![sink("s.py", 1, "g")];
        let cg = graph(&[("e.py::f", &["s.py::g"])]);
        let result = add_taint_chunks(
            &ContextPackage::default(),
            &entry_points,
            &sinks,
            &[],
            &cg,
            &[],
            Path::new("/nonexistent"),
            &TaintChunkConfig::new(),
        );
        assert!(result.chunks.is_empty());
    }

    #[test]
    fn config_default_matches_new() {
        assert_eq!(TaintChunkConfig::default(), TaintChunkConfig::new());
    }

    #[test]
    fn a_sink_with_no_function_name_is_skipped_and_stays_orphaned() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "e.py", "x\n");
        write(dir.path(), "orphan_empty.py", "x\n");

        let entry_points = vec![ep("e.py", "f", EntryPointKind::Network, true)];
        let sinks = vec![sink("orphan_empty.py", 3, "")];
        let all_files: Vec<String> = ["e.py", "orphan_empty.py"]
            .iter()
            .map(|s| s.to_string())
            .collect();

        let result = add_taint_chunks(
            &ContextPackage::default(),
            &entry_points,
            &sinks,
            &[],
            &graph(&[]),
            &all_files,
            dir.path(),
            &TaintChunkConfig::new(),
        );

        assert!(result.chunks.is_empty());
        assert_eq!(result.total_sinks, 1);
        assert_eq!(result.reached_sinks, 0);
        assert_eq!(result.orphaned_sinks, vec!["orphan_empty.py:3".to_string()]);
    }

    #[test]
    fn fallback_hit_whose_sink_qn_is_unregistered_falls_back_to_bare_file_refs() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "auth.py", "x\n");

        let entry_points = vec![ep("auth.py", "handle", EntryPointKind::Other, false)];
        let sinks = vec![sink("auth.py", 7, "check")];
        let cg = graph(&[("pkg/auth.py::check", &["something_else.py::x"])]);
        let all_files = vec!["auth.py".to_string()];

        let result = add_taint_chunks(
            &ContextPackage::default(),
            &entry_points,
            &sinks,
            &[],
            &cg,
            &all_files,
            dir.path(),
            &TaintChunkConfig::new(),
        );

        assert_eq!(result.chunks.len(), 1);
        assert_eq!(result.chunks[0].files, vec!["auth.py".to_string()]);
        assert!(result.chunks[0].hypothesis.contains("check() [auth.py]"));
        assert_eq!(result.reached_sinks, 1);
        assert!(result.orphaned_sinks.is_empty());
    }

    #[test]
    fn rpartition_splits_on_last_separator() {
        assert_eq!(
            rpartition("a:b:c", ':'),
            ("a:b".to_string(), "c".to_string())
        );
    }

    #[test]
    fn rpartition_with_no_separator_returns_empty_head_and_whole_string_as_tail() {
        assert_eq!(rpartition("abc", ':'), (String::new(), "abc".to_string()));
    }

    #[test]
    fn ref_file_splits_on_double_colon() {
        assert_eq!(ref_file("file.py::func"), "file.py");
    }

    #[test]
    fn ref_file_splits_on_single_colon() {
        assert_eq!(ref_file("file.py:42"), "file.py");
    }

    #[test]
    fn ref_file_with_no_colon_returns_whole_string() {
        assert_eq!(ref_file("file.py"), "file.py");
    }

    #[test]
    fn ref_file_empty_is_empty() {
        assert_eq!(ref_file(""), "");
    }

    #[test]
    fn ref_line_parses_trailing_digits() {
        assert_eq!(ref_line("file.py:42"), 42);
    }

    #[test]
    fn ref_line_is_zero_for_double_colon_refs() {
        assert_eq!(ref_line("file.py::func"), 0);
    }

    #[test]
    fn ref_line_is_zero_for_non_digit_tail() {
        assert_eq!(ref_line("file.py:abc"), 0);
    }

    #[test]
    fn ref_line_is_zero_for_empty_ref() {
        assert_eq!(ref_line(""), 0);
    }

    #[test]
    fn ref_line_is_zero_with_no_colon_at_all() {
        assert_eq!(ref_line("file.py"), 0);
    }

    #[test]
    fn qnode_for_file_line_returns_none_for_non_positive_line() {
        let view = GraphView::new(&ContextPackage::default());
        assert_eq!(qnode_for_file_line(&view, "a.py", 0), None);
    }

    #[test]
    fn qnode_for_file_line_resolves_via_call_graph_file_membership() {
        let mut cg: BTreeMap<String, Vec<String>> = BTreeMap::new();
        cg.insert("a.py::f".to_string(), vec!["b.py::g".to_string()]);
        let ctx = ContextPackage {
            call_graph: cg,
            ..Default::default()
        };
        let view = GraphView::new(&ctx);
        assert_eq!(
            qnode_for_file_line(&view, "a.py", 5),
            Some("a.py::f".to_string())
        );
    }

    #[test]
    fn qnode_for_file_line_returns_none_when_nothing_resolves() {
        let view = GraphView::new(&ContextPackage::default());
        assert_eq!(qnode_for_file_line(&view, "a.py", 5), None);
    }

    #[test]
    fn cwe_union_for_sink_qn_unions_and_sorts_across_matched_sinks() {
        let mut sink_by_qn: HashMap<String, Vec<usize>> = HashMap::new();
        sink_by_qn.insert("a.py::f".to_string(), vec![0, 1]);
        let sinks = vec![
            sink_with_cwe("a.py", 1, "f", &["CWE-89"]),
            sink_with_cwe("a.py", 1, "f", &["CWE-79", "CWE-89"]),
        ];
        assert_eq!(
            cwe_union_for_sink_qn("a.py::f", &sink_by_qn, &sinks),
            vec!["CWE-79".to_string(), "CWE-89".to_string()]
        );
    }

    #[test]
    fn cwe_union_for_sink_qn_unknown_qn_is_empty() {
        let sink_by_qn: HashMap<String, Vec<usize>> = HashMap::new();
        assert!(cwe_union_for_sink_qn("a.py::f", &sink_by_qn, &[]).is_empty());
    }

    #[test]
    fn dedup_preserve_order_str_keeps_first_occurrence() {
        let items: Vec<String> = ["a", "b", "a"].iter().map(|s| s.to_string()).collect();
        assert_eq!(dedup_preserve_order_str(&items), vec!["a", "b"]);
    }

    fn sink_with_cwe(file: &str, line: i64, function: &str, cwe: &[&str]) -> Sink {
        Sink {
            file: file.into(),
            line,
            function: function.into(),
            snippet: String::new(),
            cwe: cwe.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn evidence(
        source_ref: &str,
        sink_ref: &str,
        path_funcs: &[&str],
        sink_cwe: &[&str],
        sanitized: bool,
    ) -> appsec_model::TaintEvidencePath {
        appsec_model::TaintEvidencePath {
            source_ref: source_ref.to_string(),
            sink_ref: sink_ref.to_string(),
            path_funcs: path_funcs.iter().map(|s| s.to_string()).collect(),
            edges: Vec::new(),
            sink_cwe: sink_cwe.iter().map(|s| s.to_string()).collect(),
            sanitized,
        }
    }

    #[test]
    fn seed_paths_for_entry_skips_evidence_whose_source_file_does_not_match_the_entry() {
        let view = GraphView::new(&ContextPackage::default());
        let entry = ep("other.py", "handle", EntryPointKind::Network, true);
        let ctx = ContextPackage {
            seed_taint_evidence: vec![evidence(
                "app/handler.py::handle",
                "app/sink.py:10",
                &[],
                &[],
                false,
            )],
            ..Default::default()
        };
        let all_file_set: HashSet<&String> = HashSet::new();
        let sink_by_qn: HashMap<String, Vec<usize>> = HashMap::new();
        let hits = seed_paths_for_entry(&ctx, &view, &entry, &sink_by_qn, &[], &all_file_set);
        assert!(hits.is_empty());
    }

    #[test]
    fn seed_paths_for_entry_skips_a_sanitized_flow() {
        let view = GraphView::new(&ContextPackage::default());
        let entry = ep("app/handler.py", "handle", EntryPointKind::Network, true);
        let ctx = ContextPackage {
            seed_taint_evidence: vec![evidence(
                "app/handler.py::handle",
                "app/sink.py:10",
                &["app/handler.py::handle", "app/sink.py::run_query"],
                &[],
                true,
            )],
            ..Default::default()
        };
        let all_files = ["app/handler.py".to_string(), "app/sink.py".to_string()];
        let all_file_set: HashSet<&String> = all_files.iter().collect();
        let sink_by_qn: HashMap<String, Vec<usize>> = HashMap::new();
        let hits = seed_paths_for_entry(&ctx, &view, &entry, &sink_by_qn, &[], &all_file_set);
        assert!(hits.is_empty());
    }

    #[test]
    fn seed_paths_for_entry_skips_a_path_shorter_than_two_hop_files() {
        let view = GraphView::new(&ContextPackage::default());
        let entry = ep("app/handler.py", "handle", EntryPointKind::Network, true);
        let ctx = ContextPackage {
            seed_taint_evidence: vec![evidence(
                "app/handler.py::handle",
                "other.py:2",
                &[],
                &[],
                false,
            )],
            ..Default::default()
        };
        let all_files = ["app/handler.py".to_string()];
        let all_file_set: HashSet<&String> = all_files.iter().collect();
        let sink_by_qn: HashMap<String, Vec<usize>> = HashMap::new();
        let hits = seed_paths_for_entry(&ctx, &view, &entry, &sink_by_qn, &[], &all_file_set);
        assert!(hits.is_empty());
    }

    #[test]
    fn seed_paths_for_entry_dedupes_identical_evidence_entries() {
        let view = GraphView::new(&ContextPackage::default());
        let entry = ep("app/handler.py", "handle", EntryPointKind::Network, true);
        let ev = evidence(
            "app/handler.py::handle",
            "app/sink.py:10",
            &["app/handler.py::handle", "app/sink.py::run_query"],
            &[],
            false,
        );
        let ctx = ContextPackage {
            seed_taint_evidence: vec![ev.clone(), ev],
            ..Default::default()
        };
        let all_files = ["app/handler.py".to_string(), "app/sink.py".to_string()];
        let all_file_set: HashSet<&String> = all_files.iter().collect();
        let sink_by_qn: HashMap<String, Vec<usize>> = HashMap::new();
        let hits = seed_paths_for_entry(&ctx, &view, &entry, &sink_by_qn, &[], &all_file_set);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn seed_paths_for_entry_falls_back_to_legacy_paths_when_structured_evidence_yields_nothing() {
        let view = GraphView::new(&ContextPackage::default());
        let entry = ep("app/handler.py", "handle", EntryPointKind::Network, true);
        let ctx = ContextPackage {
            seed_taint_evidence: vec![evidence("other.py::x", "app/sink.py:10", &[], &[], false)],
            seed_taint_paths: vec![vec![
                "app/handler.py:1".to_string(),
                "app/sink.py:10".to_string(),
            ]],
            ..Default::default()
        };
        let all_files = ["app/handler.py".to_string(), "app/sink.py".to_string()];
        let all_file_set: HashSet<&String> = all_files.iter().collect();
        let sink_by_qn: HashMap<String, Vec<usize>> = HashMap::new();
        let hits = seed_paths_for_entry(&ctx, &view, &entry, &sink_by_qn, &[], &all_file_set);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].2, "app/handler.py:1");
        assert_eq!(hits[0].3, "app/sink.py:10");
    }

    #[test]
    fn seed_paths_for_entry_legacy_path_shorter_than_two_hops_is_skipped() {
        let view = GraphView::new(&ContextPackage::default());
        let entry = ep("app/handler.py", "handle", EntryPointKind::Network, true);
        let ctx = ContextPackage {
            seed_taint_paths: vec![vec!["app/handler.py:1".to_string()]],
            ..Default::default()
        };
        let all_files = ["app/handler.py".to_string()];
        let all_file_set: HashSet<&String> = all_files.iter().collect();
        let sink_by_qn: HashMap<String, Vec<usize>> = HashMap::new();
        let hits = seed_paths_for_entry(&ctx, &view, &entry, &sink_by_qn, &[], &all_file_set);
        assert!(hits.is_empty());
    }

    #[test]
    fn seed_paths_for_entry_legacy_hop_with_no_colon_is_dropped_matching_pythons_own_quirk() {
        let view = GraphView::new(&ContextPackage::default());
        let entry = ep("app/handler.py", "handle", EntryPointKind::Network, true);
        let ctx = ContextPackage {
            seed_taint_paths: vec![vec![
                "app/handler.py".to_string(),
                "app/sink.py:10".to_string(),
            ]],
            ..Default::default()
        };
        let all_files = ["app/handler.py".to_string(), "app/sink.py".to_string()];
        let all_file_set: HashSet<&String> = all_files.iter().collect();
        let sink_by_qn: HashMap<String, Vec<usize>> = HashMap::new();
        let hits = seed_paths_for_entry(&ctx, &view, &entry, &sink_by_qn, &[], &all_file_set);
        assert!(hits.is_empty());
    }

    #[test]
    fn seed_paths_for_entry_no_evidence_and_no_matching_legacy_path_is_empty() {
        let view = GraphView::new(&ContextPackage::default());
        let entry = ep("app/handler.py", "handle", EntryPointKind::Network, true);
        let ctx = ContextPackage::default();
        let all_file_set: HashSet<&String> = HashSet::new();
        let sink_by_qn: HashMap<String, Vec<usize>> = HashMap::new();
        let hits = seed_paths_for_entry(&ctx, &view, &entry, &sink_by_qn, &[], &all_file_set);
        assert!(hits.is_empty());
    }

    #[test]
    fn add_taint_chunks_promotes_a_structured_seed_evidence_path_ahead_of_bfs() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "app/handler.py", "x\n");
        write(dir.path(), "app/sink.py", "y\n");

        let entry_points = vec![ep(
            "app/handler.py",
            "handle",
            EntryPointKind::Network,
            true,
        )];
        let sinks = vec![sink("app/sink.py", 10, "run_query")];
        let all_files = vec!["app/handler.py".to_string(), "app/sink.py".to_string()];
        let cg = graph(&[]);
        let mut ctx_cg: BTreeMap<String, Vec<String>> = BTreeMap::new();
        ctx_cg.insert(
            "app/handler.py::handle".to_string(),
            vec!["app/sink.py::run_query".to_string()],
        );
        let ctx = ContextPackage {
            call_graph: ctx_cg,
            seed_taint_evidence: vec![evidence(
                "app/handler.py::handle",
                "app/sink.py:10",
                &["app/handler.py::handle", "app/sink.py::run_query"],
                &["CWE-89"],
                false,
            )],
            ..Default::default()
        };

        let result = add_taint_chunks(
            &ctx,
            &entry_points,
            &sinks,
            &[],
            &cg,
            &all_files,
            dir.path(),
            &TaintChunkConfig::new(),
        );

        assert_eq!(result.chunks.len(), 1);
        let c = &result.chunks[0];
        assert_eq!(c.id, "taint-01");
        assert!(c.hypothesis.starts_with("Seed path evidence:"));
        assert_eq!(
            c.path_funcs,
            vec![
                "app/handler.py::handle".to_string(),
                "app/sink.py::run_query".to_string()
            ]
        );
        assert_eq!(c.source_ref, "app/handler.py::handle");
        assert_eq!(c.sink_ref, "app/sink.py:10");
        assert_eq!(c.sink_cwe, vec!["CWE-89".to_string()]);
        assert!(c.files.contains(&"app/handler.py".to_string()));
        assert!(c.files.contains(&"app/sink.py".to_string()));
    }

    #[test]
    fn add_taint_chunks_falls_back_to_legacy_seed_taint_paths_when_no_structured_evidence() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "app/handler.py", "x\n");
        write(dir.path(), "app/sink.py", "y\n");

        let entry_points = vec![ep(
            "app/handler.py",
            "handle",
            EntryPointKind::Network,
            true,
        )];
        let sinks = vec![sink("app/sink.py", 10, "run_query")];
        let all_files = vec!["app/handler.py".to_string(), "app/sink.py".to_string()];
        let cg = graph(&[]);
        let mut ctx_cg: BTreeMap<String, Vec<String>> = BTreeMap::new();
        ctx_cg.insert(
            "app/handler.py::handle".to_string(),
            vec!["app/sink.py::run_query".to_string()],
        );
        let ctx = ContextPackage {
            call_graph: ctx_cg,
            seed_taint_paths: vec![vec![
                "app/handler.py:1".to_string(),
                "app/sink.py:10".to_string(),
            ]],
            ..Default::default()
        };

        let result = add_taint_chunks(
            &ctx,
            &entry_points,
            &sinks,
            &[],
            &cg,
            &all_files,
            dir.path(),
            &TaintChunkConfig::new(),
        );

        assert_eq!(result.chunks.len(), 1);
        assert_eq!(result.chunks[0].source_ref, "app/handler.py:1");
        assert_eq!(result.chunks[0].sink_ref, "app/sink.py:10");
    }

    #[test]
    fn add_taint_chunks_seed_evidence_with_empty_qpath_falls_back_to_source_sink_refs_for_hop_files(
    ) {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "app/handler.py", "x\n");
        write(dir.path(), "app/sink.py", "y\n");

        let entry_points = vec![ep(
            "app/handler.py",
            "handle",
            EntryPointKind::Network,
            true,
        )];
        let sinks = vec![sink("app/sink.py", 10, "run_query")];
        let all_files = vec!["app/handler.py".to_string(), "app/sink.py".to_string()];
        let cg = graph(&[]);
        let ctx = ContextPackage {
            seed_taint_evidence: vec![evidence(
                "app/handler.py::handle",
                "app/sink.py:10",
                &[],
                &[],
                false,
            )],
            ..Default::default()
        };

        let result = add_taint_chunks(
            &ctx,
            &entry_points,
            &sinks,
            &[],
            &cg,
            &all_files,
            dir.path(),
            &TaintChunkConfig::new(),
        );

        assert_eq!(result.chunks.len(), 1);
        assert!(result.chunks[0].path_funcs.is_empty());
        assert!(result.chunks[0]
            .files
            .contains(&"app/handler.py".to_string()));
        assert!(result.chunks[0].files.contains(&"app/sink.py".to_string()));
    }

    #[test]
    fn add_taint_chunks_seed_promotion_respects_max_chunks() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "e1.py", "x\n");
        write(dir.path(), "e2.py", "x\n");
        write(dir.path(), "s1.py", "x\n");
        write(dir.path(), "s2.py", "x\n");

        let entry_points = vec![
            ep("e1.py", "f1", EntryPointKind::Network, true),
            ep("e2.py", "f2", EntryPointKind::Network, true),
        ];
        let sinks = vec![sink("s1.py", 1, "g1"), sink("s2.py", 2, "g2")];
        let all_files: Vec<String> = ["e1.py", "e2.py", "s1.py", "s2.py"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let cg = graph(&[]);
        let ctx = ContextPackage {
            seed_taint_evidence: vec![
                evidence(
                    "e1.py::f1",
                    "s1.py:1",
                    &["e1.py::f1", "s1.py::g1"],
                    &[],
                    false,
                ),
                evidence(
                    "e2.py::f2",
                    "s2.py:2",
                    &["e2.py::f2", "s2.py::g2"],
                    &[],
                    false,
                ),
            ],
            ..Default::default()
        };
        let mut cfg = TaintChunkConfig::new();
        cfg.max_chunks = 1;

        let result = add_taint_chunks(
            &ctx,
            &entry_points,
            &sinks,
            &[],
            &cg,
            &all_files,
            dir.path(),
            &cfg,
        );

        assert_eq!(result.chunks.len(), 1);
    }

    #[test]
    fn add_taint_chunks_duplicate_seed_and_bfs_signature_is_deduped() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "app/handler.py", "x\n");
        write(dir.path(), "app/sink.py", "y\n");

        let entry_points = vec![ep(
            "app/handler.py",
            "handle",
            EntryPointKind::Network,
            true,
        )];
        let sinks = vec![sink("app/sink.py", 10, "run_query")];
        let all_files = vec!["app/handler.py".to_string(), "app/sink.py".to_string()];
        let cg = graph(&[("app/handler.py::handle", &["app/sink.py::run_query"])]);
        let mut ctx_cg: BTreeMap<String, Vec<String>> = BTreeMap::new();
        ctx_cg.insert(
            "app/handler.py::handle".to_string(),
            vec!["app/sink.py::run_query".to_string()],
        );
        let ctx = ContextPackage {
            call_graph: ctx_cg,
            seed_taint_evidence: vec![evidence(
                "app/handler.py::handle",
                "app/sink.py:10",
                &["app/handler.py::handle", "app/sink.py::run_query"],
                &[],
                false,
            )],
            ..Default::default()
        };

        let result = add_taint_chunks(
            &ctx,
            &entry_points,
            &sinks,
            &[],
            &cg,
            &all_files,
            dir.path(),
            &TaintChunkConfig::new(),
        );

        assert_eq!(result.chunks.len(), 1);
        assert!(result.chunks[0]
            .hypothesis
            .starts_with("Seed path evidence:"));
    }

    #[test]
    fn add_taint_chunks_seed_promotion_max_chunks_breaks_mid_entry() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "e.py", "x\n");
        write(dir.path(), "s1.py", "x\n");
        write(dir.path(), "s2.py", "x\n");

        let entry_points = vec![ep("e.py", "handle", EntryPointKind::Network, true)];
        let sinks = vec![sink("unrelated_sink.py", 1, "g")];
        let all_files: Vec<String> = ["e.py", "s1.py", "s2.py"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let cg = graph(&[]);
        let ctx = ContextPackage {
            seed_taint_paths: vec![
                vec!["e.py:1".to_string(), "s1.py:1".to_string()],
                vec!["e.py:1".to_string(), "s2.py:1".to_string()],
            ],
            ..Default::default()
        };
        let mut cfg = TaintChunkConfig::new();
        cfg.max_chunks = 1;

        let result = add_taint_chunks(
            &ctx,
            &entry_points,
            &sinks,
            &[],
            &cg,
            &all_files,
            dir.path(),
            &cfg,
        );

        assert_eq!(result.chunks.len(), 1);
    }

    #[test]
    fn add_taint_chunks_seed_hit_with_only_out_of_scope_files_is_dropped() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "middle1.py", "x\n");
        write(dir.path(), "middle2.py", "x\n");

        let entry_points = vec![ep("ep_file.py", "handle", EntryPointKind::Network, true)];
        let sinks = vec![sink("unrelated_sink.py", 1, "g")];
        let all_files: Vec<String> = ["middle1.py", "middle2.py"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let cg = graph(&[]);
        let ctx = ContextPackage {
            seed_taint_paths: vec![vec![
                "outside.py:1".to_string(),
                "ep_file.py:2".to_string(),
                "middle1.py:3".to_string(),
                "middle2.py:4".to_string(),
                "outside2.py:5".to_string(),
            ]],
            ..Default::default()
        };

        let result = add_taint_chunks(
            &ctx,
            &entry_points,
            &sinks,
            &[],
            &cg,
            &all_files,
            dir.path(),
            &TaintChunkConfig::new(),
        );

        assert!(result.chunks.is_empty());
    }

    #[test]
    fn add_taint_chunks_seed_hit_with_empty_sink_ref_uses_the_seed_sig_key_and_dedupes() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "middle1.py", "x\n");
        write(dir.path(), "middle2.py", "x\n");

        let entry_points = vec![ep("middle1.py", "handle", EntryPointKind::Network, true)];
        let sinks = vec![sink("unrelated_sink.py", 1, "g")];
        let all_files = ["middle1.py".to_string(), "middle2.py".to_string()];
        let cg = graph(&[]);
        let path = vec![
            "middle1.py:1".to_string(),
            "middle2.py:2".to_string(),
            "".to_string(),
        ];
        let ctx = ContextPackage {
            seed_taint_paths: vec![path.clone(), path],
            ..Default::default()
        };

        let result = add_taint_chunks(
            &ctx,
            &entry_points,
            &sinks,
            &[],
            &cg,
            &all_files,
            dir.path(),
            &TaintChunkConfig::new(),
        );

        assert_eq!(result.chunks.len(), 1);
        assert!(result.chunks[0].sink_ref.is_empty());
        assert!(result.chunks[0]
            .hypothesis
            .contains("reaches sink [unknown]"));
    }

    #[test]
    fn add_taint_chunks_seed_evidence_empty_sink_ref_falls_back_to_the_resolved_sink_qnode() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "app/handler.py", "x\n");
        write(dir.path(), "app/sink.py", "y\n");

        let entry_points = vec![ep(
            "app/handler.py",
            "handle",
            EntryPointKind::Network,
            true,
        )];
        let sinks = vec![sink("unrelated_sink.py", 1, "g")];
        let all_files = ["app/handler.py".to_string(), "app/sink.py".to_string()];
        let cg = graph(&[]);
        let mut ctx_cg: BTreeMap<String, Vec<String>> = BTreeMap::new();
        ctx_cg.insert(
            "app/handler.py::handle".to_string(),
            vec!["app/sink.py::run_query".to_string()],
        );
        let ctx = ContextPackage {
            call_graph: ctx_cg,
            seed_taint_evidence: vec![evidence(
                "app/handler.py::handle",
                "",
                &["app/handler.py::handle", "app/sink.py::run_query"],
                &[],
                false,
            )],
            ..Default::default()
        };

        let result = add_taint_chunks(
            &ctx,
            &entry_points,
            &sinks,
            &[],
            &cg,
            &all_files,
            dir.path(),
            &TaintChunkConfig::new(),
        );

        assert_eq!(result.chunks.len(), 1);
        assert_eq!(result.chunks[0].sink_ref, "app/sink.py");
        assert!(result.chunks[0]
            .hypothesis
            .contains("reaches sink [app/sink.py::run_query]"));
    }

    #[test]
    fn add_taint_chunks_seed_legacy_empty_source_hop_falls_back_to_a_constructed_source_ref() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "middle1.py", "x\n");
        write(dir.path(), "middle2.py", "x\n");

        let entry_points = vec![ep("middle1.py", "handle", EntryPointKind::Network, true)];
        let sinks = vec![sink("unrelated_sink.py", 1, "g")];
        let all_files = ["middle1.py".to_string(), "middle2.py".to_string()];
        let cg = graph(&[]);
        let ctx = ContextPackage {
            seed_taint_paths: vec![vec![
                "".to_string(),
                "middle1.py:1".to_string(),
                "middle2.py:2".to_string(),
            ]],
            ..Default::default()
        };

        let result = add_taint_chunks(
            &ctx,
            &entry_points,
            &sinks,
            &[],
            &cg,
            &all_files,
            dir.path(),
            &TaintChunkConfig::new(),
        );

        assert_eq!(result.chunks.len(), 1);
        assert_eq!(result.chunks[0].source_ref, "middle1.py::handle");
    }

    #[test]
    fn two_entry_points_in_one_file_on_one_seed_path_yield_one_folded_chunk() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "main.c", "x\n");
        write(dir.path(), "report.c", "y\n");

        let entry_points = vec![
            ep("main.c", "main", EntryPointKind::Cli, true),
            ep(
                "main.c",
                "replay_operator_notices",
                EntryPointKind::Cli,
                true,
            ),
        ];
        let sinks = vec![sink("report.c", 19, "report_open")];
        let all_files = vec!["main.c".to_string(), "report.c".to_string()];
        let ctx = ContextPackage {
            seed_taint_evidence: vec![evidence(
                "main.c:54",
                "report.c:19",
                &["main.c::main", "report.c::report_open"],
                &["CWE-22"],
                false,
            )],
            ..Default::default()
        };

        let result = add_taint_chunks(
            &ctx,
            &entry_points,
            &sinks,
            &[],
            &graph(&[]),
            &all_files,
            dir.path(),
            &TaintChunkConfig::new(),
        );

        assert_eq!(result.chunks.len(), 1, "{:?}", result.chunks);
        let c = &result.chunks[0];
        assert_eq!(
            c.focus_entry_points,
            vec!["main".to_string(), "replay_operator_notices".to_string()]
        );
        assert_eq!(
            c.hypothesis,
            "Seed path evidence: cli input at main() [main.c] (and \
             replay_operator_notices()) reaches sink [report.c:19]. Validate \
             each hop for missing sanitization and real exploitability."
        );
    }

    #[test]
    fn a_lone_entry_point_renders_the_pre_fold_hypothesis_verbatim() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "main.c", "x\n");
        write(dir.path(), "report.c", "y\n");

        let entry_points = vec![ep("main.c", "main", EntryPointKind::Cli, true)];
        let sinks = vec![sink("report.c", 19, "report_open")];
        let all_files = vec!["main.c".to_string(), "report.c".to_string()];
        let ctx = ContextPackage {
            seed_taint_evidence: vec![evidence(
                "main.c:54",
                "report.c:19",
                &["main.c::main", "report.c::report_open"],
                &[],
                false,
            )],
            ..Default::default()
        };

        let result = add_taint_chunks(
            &ctx,
            &entry_points,
            &sinks,
            &[],
            &graph(&[]),
            &all_files,
            dir.path(),
            &TaintChunkConfig::new(),
        );

        assert_eq!(result.chunks.len(), 1);
        assert_eq!(
            result.chunks[0].hypothesis,
            "Seed path evidence: cli input at main() [main.c] reaches sink \
             [report.c:19]. Validate each hop for missing sanitization and \
             real exploitability."
        );
    }

    #[test]
    fn folded_entry_points_in_another_file_keep_their_own_file_in_the_phrase() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "main.c", "x\n");
        write(dir.path(), "util.c", "y\n");

        let entry_points = vec![
            ep("main.c", "main", EntryPointKind::Cli, true),
            ep("util.c", "util_flag_index", EntryPointKind::Cli, true),
        ];
        let sinks = vec![sink("util.c", 29, "util_render_banner")];
        let all_files = vec!["main.c".to_string(), "util.c".to_string()];
        let ctx = ContextPackage {
            seed_taint_paths: vec![vec!["main.c:54".to_string(), "util.c:29".to_string()]],
            ..Default::default()
        };

        let result = add_taint_chunks(
            &ctx,
            &entry_points,
            &sinks,
            &[],
            &graph(&[]),
            &all_files,
            dir.path(),
            &TaintChunkConfig::new(),
        );

        let folded = result
            .chunks
            .iter()
            .find(|c| c.focus_entry_points.len() == 2)
            .expect("the shared seed path folds both entry points");
        assert_eq!(
            folded.hypothesis,
            "Seed path evidence: cli input at main() [main.c] (and \
             util_flag_index() [util.c]) reaches sink [util.c:29]. Validate \
             each hop for missing sanitization and real exploitability."
        );
    }

    #[test]
    fn two_sink_lines_in_one_function_stay_two_chunks() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "main.c", "x\n");
        write(dir.path(), "util.c", "y\n");

        let entry_points = vec![
            ep("main.c", "main", EntryPointKind::Cli, true),
            ep("util.c", "util_flag_index", EntryPointKind::Cli, true),
        ];
        let sinks = vec![
            sink("util.c", 85, "util_run_archive"),
            sink("util.c", 87, "util_run_archive"),
        ];
        let all_files = vec!["main.c".to_string(), "util.c".to_string()];
        let mut def_spans: BTreeMap<String, (i64, i64)> = BTreeMap::new();
        def_spans.insert("main.c::main".to_string(), (50, 60));
        def_spans.insert("util.c::util_run_archive".to_string(), (80, 90));
        let ctx = ContextPackage {
            def_spans,
            seed_taint_evidence: vec![evidence(
                "main.c:54",
                "util.c:85",
                &["main.c::main", "util.c::util_run_archive"],
                &[],
                false,
            )],
            seed_taint_paths: vec![vec!["main.c:54".to_string(), "util.c:87".to_string()]],
            ..Default::default()
        };

        let result = add_taint_chunks(
            &ctx,
            &entry_points,
            &sinks,
            &[],
            &graph(&[]),
            &all_files,
            dir.path(),
            &TaintChunkConfig::new(),
        );

        let mut refs: Vec<&str> = result
            .chunks
            .iter()
            .filter(|c| c.hypothesis.starts_with("Seed path evidence:"))
            .map(|c| c.sink_ref.as_str())
            .collect();
        refs.sort_unstable();
        assert_eq!(refs, vec!["util.c:85", "util.c:87"], "{:?}", result.chunks);
    }

    #[test]
    fn entry_points_attributing_to_different_threats_do_not_fold() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "main.c", "x\n");
        write(dir.path(), "report.c", "y\n");

        let entry_points = vec![
            ep("main.c", "main", EntryPointKind::Cli, true),
            ep("main.c", "replay", EntryPointKind::Cli, true),
        ];
        let sinks = vec![sink("report.c", 19, "report_open")];
        let all_files = vec!["main.c".to_string(), "report.c".to_string()];
        let threats = vec![threat("T1", "main"), threat("T2", "replay")];
        let ctx = ContextPackage {
            seed_taint_evidence: vec![evidence(
                "main.c:54",
                "report.c:19",
                &["main.c::main", "report.c::report_open"],
                &[],
                false,
            )],
            ..Default::default()
        };

        let result = add_taint_chunks(
            &ctx,
            &entry_points,
            &sinks,
            &threats,
            &graph(&[]),
            &all_files,
            dir.path(),
            &TaintChunkConfig::new(),
        );

        assert_eq!(result.chunks.len(), 2, "{:?}", result.chunks);
        let mut ids: Vec<&str> = result
            .chunks
            .iter()
            .filter_map(|c| c.threat_id.as_deref())
            .collect();
        ids.sort_unstable();
        assert_eq!(ids, vec!["T1", "T2"]);
    }

    #[test]
    fn the_same_entry_point_listed_twice_folds_without_growing_the_phrase() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "main.c", "x\n");
        write(dir.path(), "report.c", "y\n");

        let entry_points = vec![
            ep("main.c", "main", EntryPointKind::Cli, true),
            ep("main.c", "main", EntryPointKind::Cli, true),
        ];
        let sinks = vec![sink("report.c", 19, "report_open")];
        let all_files = vec!["main.c".to_string(), "report.c".to_string()];
        let ctx = ContextPackage {
            seed_taint_evidence: vec![evidence(
                "main.c:54",
                "report.c:19",
                &["main.c::main", "report.c::report_open"],
                &[],
                false,
            )],
            ..Default::default()
        };

        let result = add_taint_chunks(
            &ctx,
            &entry_points,
            &sinks,
            &[],
            &graph(&[]),
            &all_files,
            dir.path(),
            &TaintChunkConfig::new(),
        );

        assert_eq!(result.chunks.len(), 1);
        assert_eq!(
            result.chunks[0].focus_entry_points,
            vec!["main".to_string()]
        );
        assert!(!result.chunks[0].hypothesis.contains("(and"));
    }

    #[test]
    fn an_entry_point_already_folded_in_is_not_named_twice() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "main.c", "x\n");
        write(dir.path(), "report.c", "y\n");

        let entry_points = vec![
            ep("main.c", "main", EntryPointKind::Cli, true),
            ep("main.c", "replay", EntryPointKind::Cli, true),
            ep("main.c", "replay", EntryPointKind::Cli, true),
        ];
        let sinks = vec![sink("report.c", 19, "report_open")];
        let all_files = vec!["main.c".to_string(), "report.c".to_string()];
        let ctx = ContextPackage {
            seed_taint_evidence: vec![evidence(
                "main.c:54",
                "report.c:19",
                &["main.c::main", "report.c::report_open"],
                &[],
                false,
            )],
            ..Default::default()
        };

        let result = add_taint_chunks(
            &ctx,
            &entry_points,
            &sinks,
            &[],
            &graph(&[]),
            &all_files,
            dir.path(),
            &TaintChunkConfig::new(),
        );

        assert_eq!(result.chunks.len(), 1, "{:?}", result.chunks);
        assert_eq!(
            result.chunks[0].focus_entry_points,
            vec!["main".to_string(), "replay".to_string()]
        );
        assert_eq!(
            result.chunks[0].hypothesis,
            "Seed path evidence: cli input at main() [main.c] (and replay()) \
             reaches sink [report.c:19]. Validate each hop for missing \
             sanitization and real exploitability."
        );
    }

    #[test]
    fn a_duplicate_entry_point_on_the_bfs_branch_yields_one_chunk() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.py", "x\n");
        write(dir.path(), "b.py", "y\n");

        let entry_points = vec![
            ep("a.py", "handle", EntryPointKind::Network, true),
            ep("a.py", "handle", EntryPointKind::Network, true),
        ];
        let sinks = vec![sink("b.py", 3, "run_query")];
        let all_files = vec!["a.py".to_string(), "b.py".to_string()];
        let cg = graph(&[("a.py::handle", &["b.py::run_query"][..])]);

        let result = add_taint_chunks(
            &ContextPackage::default(),
            &entry_points,
            &sinks,
            &[],
            &cg,
            &all_files,
            dir.path(),
            &TaintChunkConfig::new(),
        );

        assert_eq!(result.chunks.len(), 1, "{:?}", result.chunks);
        let c = &result.chunks[0];
        assert!(c.hypothesis.starts_with("Taint path:"), "{}", c.hypothesis);
        assert_eq!(c.focus_entry_points, vec!["handle".to_string()]);
        assert!(!c.hypothesis.contains("(and"));
    }

    #[test]
    fn a_bfs_chunk_is_still_suppressed_by_a_seed_chunk_it_was_folded_into() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "main.c", "x\n");
        write(dir.path(), "report.c", "y\n");

        let entry_points = vec![
            ep("main.c", "main", EntryPointKind::Cli, true),
            ep("main.c", "replay", EntryPointKind::Cli, true),
        ];
        let sinks = vec![sink("report.c", 19, "report_open")];
        let all_files = vec!["main.c".to_string(), "report.c".to_string()];
        let cg = graph(&[
            ("main.c::main", &["report.c::report_open"][..]),
            ("main.c::replay", &["report.c::report_open"][..]),
        ]);
        let ctx = ContextPackage {
            call_graph: cg.clone(),
            seed_taint_evidence: vec![evidence(
                "main.c:54",
                "report.c:19",
                &["main.c::main", "report.c::report_open"],
                &[],
                false,
            )],
            ..Default::default()
        };

        let result = add_taint_chunks(
            &ctx,
            &entry_points,
            &sinks,
            &[],
            &cg,
            &all_files,
            dir.path(),
            &TaintChunkConfig::new(),
        );

        assert_eq!(result.chunks.len(), 1, "{:?}", result.chunks);
        assert_eq!(
            result.chunks[0].focus_entry_points,
            vec!["main".to_string(), "replay".to_string()]
        );
    }

    #[test]
    fn a_legacy_seed_path_revisiting_one_function_renders_no_self_edge() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "main.c", "x\n");
        write(
            dir.path(),
            "util.c",
            "fn util_run_archive() {\n  a\n  b\n}\n",
        );

        let entry_points = vec![ep("main.c", "main", EntryPointKind::Cli, true)];
        let sinks = vec![sink("util.c", 3, "util_run_archive")];
        let all_files = vec!["main.c".to_string(), "util.c".to_string()];
        let mut def_spans: BTreeMap<String, (i64, i64)> = BTreeMap::new();
        def_spans.insert("util.c::util_run_archive".to_string(), (1, 4));
        let ctx = ContextPackage {
            def_spans,
            seed_taint_paths: vec![vec![
                "main.c:1".to_string(),
                "util.c:2".to_string(),
                "util.c:3".to_string(),
            ]],
            ..Default::default()
        };

        let result = add_taint_chunks(
            &ctx,
            &entry_points,
            &sinks,
            &[],
            &graph(&[]),
            &all_files,
            dir.path(),
            &TaintChunkConfig::new(),
        );

        let seeded = result
            .chunks
            .iter()
            .find(|c| c.hypothesis.starts_with("Seed path evidence:"))
            .expect("the legacy seed path produces a chunk");
        assert_eq!(
            seeded.path_funcs,
            vec!["util.c::util_run_archive".to_string()],
            "the repeated hop must appear once"
        );
    }
}
