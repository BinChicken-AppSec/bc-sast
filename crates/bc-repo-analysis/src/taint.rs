//! BFS taint-path chunking, ported from
//! `s3_decompose.py::_add_taint_chunks`/`_bfs_to_sinks`/`_pick_hop_files`/
//! `_threat_for`/`_seed_paths_for_entry`/`_qnode_for_file_line`. Walks the
//! call graph from each entry point to each
//! unsafe sink and emits one chunk per reachable `(entry, sink)` pair
//! containing every file resolvable along the path — guaranteeing the S4
//! researcher sees source AND sink together, the precondition for a
//! confirmed data-flow finding.
//!
//! Unlike the Python original (which mutates a shared `TaskManifest` in
//! place, including shifting every *other* chunk's `risk_rank` so taint
//! chunks always sort first), [`add_taint_chunks`] is a pure function
//! returning just the new chunks it found, each with a `risk_rank`
//! starting at 1. Merging those into a full manifest — and re-ranking the
//! LLM-authored chunks above/below them — is a `TaskManifest`-level
//! concern the eventual S3 stage crate owns, not this one; keeping it out
//! here means this function needs only entry points/sinks/threats/graph
//! data to test, not a fully-populated manifest.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::Path;
use std::sync::LazyLock;

use bc_model::{Chunk, ChunkSize, ContextPackage, EntryPoint, EntryPointKind, Sink, Threat};
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
    /// New chunks, `risk_rank` 1..N in discovery order.
    pub chunks: Vec<Chunk>,
    pub total_sinks: usize,
    pub reached_sinks: usize,
    /// `"file:line"` for every sink with no entry->sink path found (and
    /// not simply co-located in the same file as an entry point).
    pub orphaned_sinks: Vec<String>,
}

/// `ctx` is used ONLY for seed-path promotion (`GraphView::new(ctx)` plus
/// `ctx.seed_taint_evidence`/`ctx.seed_taint_paths`) — every other field
/// this function needs is still taken as its own explicit parameter below,
/// which looks redundant but keeps every one of this function's ~20
/// existing tests (built from bare entry-point/sink/graph fixtures, no
/// full `ContextPackage`) unchanged; they simply pass
/// `&ContextPackage::default()`, under which seed-path promotion is a
/// guaranteed no-op and behavior is identical to before this parameter
/// existed.
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

    // Built here, before the sink loop, because that loop now needs it to
    // resolve a line-anchored sink (see `sink_qnodes_for_sink`); it
    // depends on `ctx` alone, so hoisting it is free.
    let view = GraphView::new(ctx);

    let mut sink_qnodes: HashSet<String> = HashSet::new();
    let mut sink_by_qn: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, s) in unsafe_sinks.iter().enumerate() {
        // Python skips a sink only when it has NEITHER a function name nor
        // a line (`s3_decompose.py:719`). This port skipped on a missing
        // function alone, silently dropping every S0 static-seed sink that
        // carries a real `file:line` but no enclosing function — precisely
        // the shape a rules-mode or regex-fallback seed produces, so whole
        // classes of seeded sink never reached taint chunking at all.
        if s.function.is_empty() && s.line <= 0 {
            continue;
        }
        for qn in sink_qnodes_for_sink(s, &view, &by_bare) {
            sink_qnodes.insert(qn.clone());
            sink_by_qn.entry(qn).or_default().push(i);
        }
    }

    // Sink qnode -> union of CWE ids tagged on the sinks resolving to it.
    // `bfs_to_sinks` needs this to decide whether a class-specific
    // sanitizer crossed on the path actually neutralizes the sink it
    // arrived at; built once here rather than per entry point.
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

    let mut seen_paths: HashSet<(String, String, Vec<String>)> = HashSet::new();
    let mut reached_fns: HashSet<String> = HashSet::new();
    let mut chunks: Vec<Chunk> = Vec::new();
    let mut added = 0usize;

    for ep in &entries {
        if added >= config.max_chunks {
            break;
        }

        // Prefer concrete S0-proven taint paths when available — found and
        // emitted ahead of (and sharing the same `seen_paths`/`added`
        // budget as) the BFS-derived hits below, so seed evidence gets
        // first claim on the per-entry chunk budget. Ported from
        // `_add_taint_chunks`'s own seed-path promotion block.
        for (sink_qn, qpath, src_ref, snk_ref, cwes) in
            seed_paths_for_entry(ctx, &view, ep, &sink_by_qn, unsafe_sinks, &all_file_set)
        {
            if added >= config.max_chunks {
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
            let sig = (ep.function.clone(), sig_key, {
                let mut sorted = files.clone();
                sorted.sort();
                sorted
            });
            if !seen_paths.insert(sig) {
                continue;
            }
            added += 1;

            let loc: usize = files.iter().map(|f| count_lines(&repo_root.join(f))).sum();
            let sink_display = if !snk_ref.is_empty() {
                snk_ref.clone()
            } else if !sink_qn.is_empty() {
                sink_qn.clone()
            } else {
                "unknown".to_string()
            };

            chunks.push(Chunk {
                id: format!("taint-{added:02}"),
                size: size_for(loc),
                risk_rank: added as i64,
                files,
                focus_entry_points: vec![ep.function.clone()],
                hypothesis: format!(
                    "Seed path evidence: {} input at {}() [{}] reaches sink [{sink_display}]. Validate each hop for missing sanitization and real exploitability.",
                    kind_sort_key(ep.kind), ep.function, ep.file
                ),
                related_cves: Vec::new(),
                threat_id: threat_for(&ep.function, threats),
                languages: Vec::new(),
                specialist: None,
                path_funcs: qpath,
                source_ref: if !src_ref.is_empty() {
                    src_ref
                } else {
                    q_join(&ep.file, &ep.function)
                },
                sink_ref: if !snk_ref.is_empty() {
                    snk_ref
                } else if !sink_qn.is_empty() {
                    q_file(&sink_qn)
                } else {
                    String::new()
                },
                sink_cwe: cwes,
                shard_id: String::new(),
            });
        }

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
            reached_fns.insert(qn.clone());
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

        for (sink_qn, path) in &hits {
            if added >= config.max_chunks {
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

            let sig = (ep.function.clone(), sink_qn.clone(), {
                let mut sorted = files.clone();
                sorted.sort();
                sorted
            });
            if !seen_paths.insert(sig) {
                continue;
            }
            added += 1;

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

            chunks.push(Chunk {
                id: format!("taint-{added:02}"),
                size: size_for(loc),
                risk_rank: added as i64,
                files,
                focus_entry_points: vec![ep.function.clone()],
                hypothesis: format!(
                    "Taint path: {unauth}{} input at {}() [{}] flows via {hop_chain} to sink {}() [{sink_refs}]. Verify every hop for sanitization/validation; if none, this is exploitable.",
                    kind_sort_key(ep.kind), ep.function, ep.file, q_name(sink_qn)
                ),
                related_cves: Vec::new(),
                threat_id: threat_for(&ep.function, threats),
                languages: Vec::new(),
                specialist: None,
                // Structured taint metadata -> S4 function-slice loading +
                // confirm/refute prompt (task #37). The seed-path-
                // preferring branch that ALSO sets these three fields
                // (`seed_paths_for_entry`, reading `ctx.seed_taint_paths`/
                // `seed_taint_evidence`) runs earlier in this same
                // per-entry loop, above — it gets first claim on the
                // chunk budget, and this BFS walk only ever sees whatever
                // it didn't already claim.
                path_funcs: path.clone(),
                source_ref: q_join(&ep.file, &ep.function),
                sink_ref,
                sink_cwe,
                shard_id: String::new(),
            });
        }
    }

    let reached_sink_idxs: HashSet<usize> = reached_fns
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
        chunks,
        total_sinks,
        reached_sinks,
        orphaned_sinks,
    }
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

/// Resolve an `EntryPoint`/`Sink`'s `(file, function)` to graph node(s):
/// exact `file::name` match first, else a `/`-boundary-anchored path
/// suffix match (`"auth.py"` matches `"src/auth.py"` but never
/// `"src/oauth.py"`), else a synthetic node so BFS can still "start" even
/// when the graph has no matching node at all.
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

/// Python `str.rpartition(sep)` semantics: `(head, sep_or_empty, tail)` —
/// when `sep` isn't found, returns `("", "", original)`, unlike Rust's
/// `rsplit_once`, which returns `None`. Faithfully preserved here because
/// `s3_decompose.py`'s own seed-path parsing relies on this exact
/// falls-through-to-empty-head behavior for refs with no colon at all
/// (confirmed against real Python — not a hypothetical edge case).
fn rpartition(s: &str, sep: char) -> (String, String) {
    match s.rfind(sep) {
        Some(idx) => (s[..idx].to_string(), s[idx + sep.len_utf8()..].to_string()),
        None => (String::new(), s.to_string()),
    }
}

/// `"file::function"` -> `"file"`; `"file:line"` -> `"file"`; anything
/// else -> itself. Ported from `_seed_paths_for_entry::_ref_file`.
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

/// `"file:line"` -> `line`; anything with `::` or no digit tail -> `0`.
/// Ported from `_seed_paths_for_entry::_ref_line`.
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

/// Resolve one sink to its candidate qnodes, function-first then
/// line-anchored. Ported from `_sink_qnodes_for_sink`
/// (`s3_decompose.py:567-577`).
///
/// The `out.is_empty()` guard before the line fallback is Python's
/// (`if not out and ...`), not a simplification of it: `match_qnodes`
/// always returns at least a synthesized `file::name`, so with a non-empty
/// `function` the line branch is unreachable in practice — but keeping the
/// structure means a future `match_qnodes` that can genuinely return
/// nothing still falls back instead of dropping the sink.
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
    // `list(dict.fromkeys(out))` — dedup, order preserved.
    let mut seen: HashSet<&str> = HashSet::new();
    let mut deduped = Vec::with_capacity(out.len());
    for qn in &out {
        if seen.insert(qn.as_str()) {
            deduped.push(qn.clone());
        }
    }
    deduped
}

/// Best-effort qnode lookup for a concrete `file:line` anchor — a single-
/// anchor result via `nearest_if_empty` when neither a span nor the call
/// graph resolves the file. Ported from `_qnode_for_file_line`.
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

/// `(sink_qn, qnode_path, source_ref, sink_ref, sink_cwe)` for every
/// concrete S0-proven taint path touching this entry point's file —
/// preferred over the BFS graph-walk below when available, since it's
/// evidence the harness already gathered, not an inferred reachability
/// guess. Prefers `ctx.seed_taint_evidence` (structured); falls back to
/// the legacy `ctx.seed_taint_paths` hop-list shape only when the
/// structured evidence yields nothing for this entry. Ported from
/// `_seed_paths_for_entry`.
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

/// Bare (unqualified) function names that neutralize taint for ANY sink
/// class: the classic escaping/parameterization primitives whose whole job
/// is "make this string safe to use", whatever consumes it afterward.
/// Matched case-insensitively against a node's bare name (the part after
/// the last `::`).
///
/// Ported from `s3_decompose.py::_SANITIZER_UNIVERSAL` as of upstream
/// v1.3.0. The v1.2.0 shape this port originally followed was a single flat
/// `_SANITIZER_BARE` set that also folded in `sanitize`, `clean`,
/// `validate`, `encode` and the numeric coercions, and neutralized every
/// sink class on a hit. `validate_input(x)` is not evidence that any
/// specific sink class was neutralized, so that flat set silently dropped
/// real command- and SQL-injection findings behind an aptly named but
/// unproven function. `sanitize`/`clean`/`validate` are therefore in
/// NEITHER set now: upstream deleted them outright rather than demoting
/// them per-class, because there is no vulnerability class for which a
/// function merely *named* `clean` is proof of anything.
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

/// Bare names that only neutralize taint for a SPECIFIC weakness class. A
/// numeric coercion stops a SQL-injection payload built from that value but
/// does nothing for a command-injection payload built from the SAME tainted
/// string reaching a different sink, so whether one of these counts as a
/// sanitizer can only be decided once the arriving sink's CWE is known, not
/// per hop while the path is still being walked.
///
/// Ported from `s3_decompose.py::_SANITIZER_BY_CWE`. Keys are compared
/// case-insensitively (see [`cwe_sanitizers`]).
const SANITIZER_BY_CWE: &[(&str, &[&str])] = &[
    ("CWE-89", &["int", "float", "bool", "to_int"]),
    ("CWE-90", &["int", "float", "bool", "to_int"]),
    ("CWE-79", &["encode", "html_escape"]),
];

fn is_universal_sanitizer(bare: &str) -> bool {
    SANITIZER_UNIVERSAL.contains(&bare)
}

/// The `&'static str` entry in [`SANITIZER_BY_CWE`] matching `bare`, if
/// any. Returning the static rather than a `bool` lets the BFS carry the
/// accumulated class-sanitizer names in its state key without allocating a
/// `String` per hop.
fn class_sanitizer_name(bare: &str) -> Option<&'static str> {
    SANITIZER_BY_CWE
        .iter()
        .flat_map(|(_, names)| names.iter())
        .find(|name| **name == bare)
        .copied()
}

/// The class-specific sanitizer names registered for `cwe`, or an empty
/// slice for a weakness class with no known coercion-style neutralizer.
/// Unlike upstream's exact `dict` lookup, the key match is
/// case-insensitive, matching how `bc-callgraph` normalizes CWE ids
/// elsewhere in this workspace.
fn cwe_sanitizers(cwe: &str) -> &'static [&'static str] {
    let upper = cwe.to_uppercase();
    SANITIZER_BY_CWE
        .iter()
        .find(|(key, _)| *key == upper)
        .map(|(_, names)| *names)
        .unwrap_or(&[])
}

/// `(sink_qname, path)` for every sink reachable from `start` via a path
/// that does NOT cross a sanitizer actually neutralizing THAT sink's
/// weakness class, collecting ALL such reachable sinks rather than stopping
/// at the first, bounded by `max_hops` on path length (not on nodes visited
/// per level). `sink_cwes` maps a sink qnode to the union of the CWE ids
/// tagged on the sinks resolving to it; a sink absent from it (or present
/// with no CWEs) can never be class-sanitized, only universally sanitized.
///
/// Ported from `s3_decompose.py::_bfs_to_sinks` as of upstream v1.3.0, with
/// one deliberate deviation noted below. Two rules the v1.2.0 shape got
/// wrong, both of which cost real findings:
///
/// 1. A [`SANITIZER_UNIVERSAL`] hit is decided per hop, because it
///    neutralizes every class and can therefore safely gate expansion the
///    moment it is seen. A [`SANITIZER_BY_CWE`] hit CANNOT be decided per
///    hop: the sink at the far end, and so its CWE, is not known yet. The
///    path instead carries the SET of class-sanitizer names it has crossed,
///    and the decision is made at sink arrival against that sink's own
///    CWEs. Every class tagged at the sink must be neutralized, not just
///    one: a single call site can carry several CWEs, and suppressing on
///    the first match would discard the unsanitized aspect. Requiring all
///    of them errs toward reporting, which is the correct direction here
///    because S4 re-checks what is emitted but nothing re-checks a path
///    that was never emitted.
///
/// 2. Sink visited-tracking is separate from non-sink nodes. A sink first
///    reached via a sanitized path is NOT marked clean-visited, so a later
///    genuinely clean path can still discover it: the classic
///    validation-bypass/auth-bypass shape where one sink is reachable both
///    through and around a sanitizer. Marking it visited before the sink
///    check (as v1.2.0 did) made that loss depend on callee iteration
///    order, so it was nondeterministic as well as wrong.
///
/// Deviation from upstream v1.3.0: a CLEAN sink arrival is still expanded
/// past (`bfs_to_sinks_keeps_expanding_past_a_found_sink` pins this, and
/// v1.2.0 behaved this way). Upstream's rewrite made a clean sink terminal,
/// which silently drops any sink reachable only *through* another sink, a
/// recall regression in a change whose whole purpose is recall. `clean_sinks`
/// still bounds that expansion to one arrival per sink.
///
/// Termination: state is `(node, universal_hit, class_hits)`, drawn from a
/// finite space — nodes x 2 x the 2^6 subsets of the [`SANITIZER_BY_CWE`]
/// name set — and every set below only ever grows. A non-sink state is
/// pushed at most once, guarded by `visited.insert`. A sink is pushed at
/// most once clean (`clean_sinks` short-circuits every later arrival at
/// that node, sanitized or not) plus at most once per sanitized state
/// (`sanitized_sinks_expanded`). So each round pushes only states never
/// pushed before, of which there are finitely many; the frontier therefore
/// empties in finitely many rounds even before `max_hops` applies.
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
    // `(node, universal_hit, class_hits)`. Keying on the sanitized state
    // rather than the node alone is what lets two paths through one node
    // with different sanitizer history be explored independently, since
    // which one "counts" depends on the sink each eventually reaches.
    // `class_hits` is realistically 0-2 names on any real path, so the
    // clone-per-edge stays cheap.
    type State = (String, bool, BTreeSet<&'static str>);

    let mut out: Vec<(String, Vec<String>)> = Vec::new();
    // Upstream splits this into `visited_clean`/`visited_sanitized`, but the
    // two are disjoint by construction — a state's `universal_hit` component
    // decides which set it would land in — so one set is exactly equivalent
    // and drops upstream's `state in visited_clean` guard on the sanitized
    // arm, which can never fire.
    let mut visited: HashSet<State> = HashSet::from([(start.to_string(), false, BTreeSet::new())]);
    // Sinks already reported via a clean path; further arrivals are noise.
    let mut clean_sinks: HashSet<String> = HashSet::new();
    // Sanitized-only sink states already expanded once, bounding BFS
    // expansion through them so a cycle cannot re-enter them forever.
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
                        // Sanitized FOR THIS SINK. Do not record it as
                        // reached: a different, cleaner path may still get
                        // here, and that path is the whole finding.
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

/// Up to `cap` candidates, ranked by longest common leading-path-segment
/// count with any anchor (entry/sink file) — same-package definitions
/// (Java package == directory path) sort first. `cap <= 0` means no cap.
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

/// Associate a taint chunk with a threat by matching the threat's surface
/// (an entry-point/function name) to the entry function on a whole-token
/// basis, never a path/substring match (which over-tags this metric).
/// Exact case-insensitive match wins outright; otherwise the first threat
/// sharing a whole token with the function name.
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
    use bc_model::{Actor, Impact, Likelihood};

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

    /// Sink-qnode -> CWE map for `bfs_to_sinks`. Untagged sinks (the empty
    /// map) can only ever be universally sanitized, which is what most of
    /// the traversal-shape tests want.
    fn cwes(pairs: &[(&str, &[&str])]) -> HashMap<String, Vec<String>> {
        pairs
            .iter()
            .map(|(k, vs)| (k.to_string(), vs.iter().map(|s| s.to_string()).collect()))
            .collect()
    }

    fn no_cwes() -> HashMap<String, Vec<String>> {
        HashMap::new()
    }

    // ── size_for ────────────────────────────────────────────────────────

    #[test]
    fn size_for_boundaries() {
        assert_eq!(size_for(0), ChunkSize::Small);
        assert_eq!(size_for(1999), ChunkSize::Small);
        assert_eq!(size_for(2000), ChunkSize::Medium);
        assert_eq!(size_for(7999), ChunkSize::Medium);
        assert_eq!(size_for(8000), ChunkSize::Large);
    }

    // ── kind_sort_key ───────────────────────────────────────────────────

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

    // ── dedup_preserve_order ────────────────────────────────────────────

    #[test]
    fn dedup_preserve_order_keeps_first_occurrence() {
        let items: Vec<String> = ["a", "b", "a", "c", "b"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(dedup_preserve_order(&items), vec!["a", "b", "c"]);
    }

    // ── count_lines ─────────────────────────────────────────────────────

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

    // ── path_suffix / match_qnodes ──────────────────────────────────────

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
        // "auth.py" must NOT match "src/oauth.py" — no "/"-boundary suffix.
        let hit = match_qnodes("auth.py", "foo", &by_bare);
        assert_eq!(hit, vec!["auth.py::foo".to_string()]);
    }

    #[test]
    fn match_qnodes_synthesizes_a_node_when_nothing_matches() {
        let by_bare: HashMap<String, Vec<String>> = HashMap::new();
        let hit = match_qnodes("x.py", "bar", &by_bare);
        assert_eq!(hit, vec!["x.py::bar".to_string()]);
    }

    // ── bfs_to_sinks ────────────────────────────────────────────────────

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
        // path to "b" has length 2, which exceeds max_hops=1, so expansion
        // stops before ever reaching "c".
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

    // ── bfs_to_sinks: sanitizer-path filter ────────────────────────────

    #[test]
    fn bfs_to_sinks_drops_a_sink_reached_only_through_a_universal_sanitizer() {
        let g = graph(&[("a", &["escape"]), ("escape", &["sink"])]);
        let sinks: HashSet<String> = ["sink".to_string()].into_iter().collect();
        assert!(bfs_to_sinks("a", &g, &sinks, 8, &no_cwes()).is_empty());
    }

    #[test]
    fn bfs_to_sinks_reports_a_sink_reached_only_through_an_unproven_validator() {
        // Replaces `bfs_to_sinks_drops_a_sink_reached_only_through_a_
        // sanitizer`, which pinned the pre-v1.3.0 rule that any name in one
        // flat set neutralized EVERY sink class. `validate` (like `clean`
        // and `sanitize`) is now in neither the universal set nor any
        // per-CWE set, so a command-injection sink behind an aptly named
        // but unproven function is reported rather than silently dropped.
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
        // The change this whole fix exists for: the validation-bypass /
        // auth-bypass shape. One sink, two routes — through `escape` and
        // around it via `mid`. The old code marked the sink visited on the
        // sanitized arrival and then skipped the clean route as already
        // seen, losing a real finding. Asserted under BOTH callee orders
        // because the old loss depended on which route arrived first.
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
        // CWE-89/CWE-90: `int()` really does neutralize these.
        for cwe in ["CWE-89", "CWE-90"] {
            assert!(
                bfs_to_sinks("a", &g, &sinks, 8, &cwes(&[("sink", &[cwe])])).is_empty(),
                "{cwe} is neutralized by a numeric coercion"
            );
        }
        // CWE-78 (command injection) built from the SAME value is not.
        assert_eq!(
            bfs_to_sinks("a", &g, &sinks, 8, &cwes(&[("sink", &["CWE-78"])])).len(),
            1
        );
        // Nor is CWE-79: an int is not an HTML-escaped string.
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
        // One call site tagged both SQL and command injection: the numeric
        // coercion neutralizes the SQL aspect and does nothing for the
        // command aspect, so the path must still be reported. Suppressing
        // on the first match would lose the unsanitized aspect silently.
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
        // An untagged sink cannot be proven neutralized by a class-specific
        // name, only by a universal one.
        let g = graph(&[("a", &["int"]), ("int", &["sink"])]);
        let sinks: HashSet<String> = ["sink".to_string()].into_iter().collect();
        assert_eq!(bfs_to_sinks("a", &g, &sinks, 8, &no_cwes()).len(), 1);
        assert_eq!(
            bfs_to_sinks("a", &g, &sinks, 8, &cwes(&[("sink", &[])])).len(),
            1
        );
        // Same for a class this port has no registered coercion for.
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
        // A sanitized sink is not reported but IS walked past once, so a
        // later sink behind it is still found — and a cycle back into it
        // cannot re-expand it.
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
        // The coercion and the sink are two hops apart: the class-hit set
        // must be carried along the path, not tested only at the last edge.
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
        // "mid" is reachable clean (via "plain") and with a CWE-89 coercion
        // on the path (via "int"). Both states must be explored, because
        // which one counts is only decided at the sink: the CWE-78 sink
        // behind "mid" is reported either way, but the CWE-89 one is only
        // reachable cleanly through "plain".
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
        // "a" -> "escape" (sanitized) -> "sink1" (dropped), and "a" ->
        // "sink2" directly (unsanitized, still reported) — traversal past
        // the sanitizer call must not stop the whole BFS.
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
        // "pkg/mod.py::escape" must match on its bare "escape" suffix, the
        // same as an unqualified "escape" node would.
        let g = graph(&[
            ("a.py::a", &["pkg/mod.py::escape"]),
            ("pkg/mod.py::escape", &["sink.py::sink"]),
        ]);
        let sinks: HashSet<String> = ["sink.py::sink".to_string()].into_iter().collect();
        assert!(bfs_to_sinks("a.py::a", &g, &sinks, 8, &no_cwes()).is_empty());
    }

    #[test]
    fn bfs_to_sinks_a_node_that_is_itself_both_sink_and_sanitizer_is_judged_per_class() {
        // Replaces `bfs_to_sinks_a_node_that_is_itself_both_sink_and_
        // sanitizer_is_dropped`. The callee's OWN bare name is still folded
        // in before the `callee in sinks` check, but what that fold means
        // now depends on the name. A universal sanitizer still drops the
        // node; a class-specific one is judged against the node's own CWEs,
        // so a sink named `int` that is tagged CWE-78 is reported (being
        // named `int` neutralizes nothing about a shell command) while the
        // same node tagged CWE-89 is dropped.
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

    // ── pick_hop_files ──────────────────────────────────────────────────

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

    // ── threat_for ──────────────────────────────────────────────────────
    // Ported 1:1 from tests/test_s3_decompose.py's documented behavioral
    // cases for the `_threat_for` closure.

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
        // threat_for only ever sees the function NAME, never the file path,
        // so a surface equal to a path component can't tag the chunk.
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

    // ── add_taint_chunks ────────────────────────────────────────────────

    #[test]
    fn a_sink_with_a_line_but_no_function_is_resolved_not_skipped() {
        // Regression: this port skipped on an empty `function` alone, so
        // every S0 static-seed sink carrying a real `file:line` but no
        // enclosing function name was dropped before taint chunking.
        // Python skips only when BOTH are missing, then line-anchors.
        // The sink lives in a NON-entry file so "reached" can only mean
        // "the BFS actually got there", not "co-located with an entry".
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

        // `def_spans` is what lets `qnodes_at` map line 42 back to a
        // qnode the BFS can actually reach.
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
        // Nothing at all identifies this sink, so it stays unreachable —
        // exactly the case Python also drops.
        assert!(result.chunks.is_empty(), "{:?}", result.chunks);
        assert_eq!(result.reached_sinks, 0);
        assert_eq!(result.orphaned_sinks, vec!["app/db.py:0".to_string()]);
    }

    #[test]
    fn sink_qnodes_for_sink_prefers_the_function_and_dedups() {
        let view = GraphView::new(&ContextPackage::default());
        let mut by_bare: HashMap<String, Vec<String>> = HashMap::new();
        // The same qnode listed twice: `dict.fromkeys` order-preserving
        // dedup must collapse it.
        by_bare.insert(
            "run".to_string(),
            vec!["a.py::run".to_string(), "a.py::run".to_string()],
        );
        let got = sink_qnodes_for_sink(&sink("a.py", 5, "run"), &view, &by_bare);
        assert_eq!(got, vec!["a.py::run".to_string()]);
    }

    #[test]
    fn sink_qnodes_for_sink_returns_nothing_when_a_line_anchor_resolves_to_nothing() {
        // No def_spans and no call graph -> `qnodes_at` finds no anchor,
        // so the sink contributes no qnode rather than a fabricated one.
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

        // Structured taint metadata (task #37's own prerequisite): the
        // BFS path, the entry point's qnode, the matched sink's
        // "file:line", and its (here empty) CWE tags.
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
        // Two `Sink` entries resolving to the SAME qnode (same file +
        // function) with overlapping/distinct CWE tags — the real-world
        // shape when multiple rule matches hit one call site.
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
        // Both same-qnode sinks feed the "file:line" summary.
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

        // Two ambiguous graph nodes resolve as "starts" for entry (a.py, f)
        // via suffix matching, but both paths collapse to the same final
        // file set once filtered against all_files, so they must dedup to
        // a single chunk.
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
        // Files are declared in all_files but never actually written to disk.
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
        // Deliberately omit "e.py" from all_files, but keep "s.py" so the
        // chunk is not dropped for being entirely empty.
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
        // Neither file is in all_files, so the candidate hit's file list is
        // empty after filtering and must be skipped rather than emitted.
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
        // An empty function name must never be registered as a graph node
        // to match against, so this sink can never be "reached" and, since
        // it isn't co-located with any entry point's file, must surface as
        // orphaned rather than silently vanishing.
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
        // The same-file fallback path builds its sink_qn directly from the
        // sink's own (file, function) — bypassing match_qnodes — so it can
        // diverge from the qn actually registered in sink_by_qn whenever
        // the sink's bare function name resolves (via path-suffix matching)
        // to a DIFFERENT file spelling elsewhere in the call graph. That
        // divergence must degrade gracefully to the sink's own bare file
        // rather than panicking or fabricating sink metadata.
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "auth.py", "x\n");

        let entry_points = vec![ep("auth.py", "handle", EntryPointKind::Other, false)];
        let sinks = vec![sink("auth.py", 7, "check")];
        // "check" only appears in the graph under a different file, so
        // match_qnodes suffix-resolves the sink to "pkg/auth.py::check" —
        // NOT the literal "auth.py::check" the fallback path constructs.
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

    // ── rpartition / ref_file / ref_line ───────────────────────────────

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

    // ── qnode_for_file_line ─────────────────────────────────────────────

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

    // ── cwe_union_for_sink_qn / dedup_preserve_order_str ────────────────

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

    // ── seed_paths_for_entry ────────────────────────────────────────────

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
    ) -> bc_model::TaintEvidencePath {
        bc_model::TaintEvidencePath {
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
        // qpath resolves to zero files, and the sink's file isn't in scope
        // at all, so the source/sink fallback supplies only one file.
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
            // Present but entirely filtered out (wrong entry file) -> the
            // legacy branch must still run.
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
        // A hop lacking a "file:line" suffix rpartitions to an EMPTY head
        // in Python (`hf, _, hline = hop.rpartition(":")` -> `hf=""` when
        // `hline` is the whole string) — faithfully reproduced here, not
        // "fixed", so this hop never contributes to `hop_files`.
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

    // ── add_taint_chunks: seed-path promotion integration ───────────────

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
        // The seed-derived chunk and a BFS-derived chunk for the same
        // (entry, sink, files) signature share `seen_paths` — the BFS
        // pass must not double-emit once the seed pass already claimed
        // that exact signature.
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
        // The SAME edge exists in both the BFS graph and ctx.call_graph,
        // so BFS would also find this exact (entry, sink) pair.
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

        // Only the seed-derived chunk survives — BFS's identical
        // signature is a no-op dedup, not a second chunk.
        assert_eq!(result.chunks.len(), 1);
        assert!(result.chunks[0]
            .hypothesis
            .starts_with("Seed path evidence:"));
    }

    #[test]
    fn add_taint_chunks_seed_promotion_max_chunks_breaks_mid_entry() {
        // A SINGLE entry with two distinct legacy seed paths — the second
        // hit must hit the inner `added >= max_chunks` break, not just the
        // outer per-entry one.
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
        // Every candidate file the seed-promotion block would use --
        // qpath-derived (empty here), the rpartitioned source/sink refs,
        // and the entry's own file -- is out of `all_files` scope, so the
        // hit must be dropped via the post-filter `files.is_empty()` gate,
        // not emitted as a chunk with no files.
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "middle1.py", "x\n");
        write(dir.path(), "middle2.py", "x\n");

        let entry_points = vec![ep("ep_file.py", "handle", EntryPointKind::Network, true)];
        let sinks = vec![sink("unrelated_sink.py", 1, "g")];
        // Deliberately excludes "outside.py"/"outside2.py"/"ep_file.py" --
        // only the two middle hops are in scope.
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
        // A trailing empty-string hop makes `sink_ref` (and therefore
        // `sink_qn`) empty -- the sig key falls back to the literal
        // "seed" marker and the display text falls back to "unknown".
        // Duplicating the exact same path exercises the seen_paths dedup
        // for that shared "seed" signature too.
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
            // `sink_ref` deliberately empty -- `sink_qn` is resolved from
            // the qpath's own last entry instead.
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
}
