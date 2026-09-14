//! Naive call graph + source→sink reachability. Ported from
//! `vvaharness/pipeline/stages/callgraph_engine/_graph.py`.
//!
//! Given a list of [`FileIndex`] records (each pre-labeled with source/
//! sink call sites and containing-function scopes), this builds:
//!   * a global call graph keyed by function name — a call to `foo(...)`
//!     links the caller to every `def foo` in the codebase (no type
//!     resolution beyond what the scanner already did)
//!   * intra-procedural pairs — source and sink in the same function
//!   * bounded inter-procedural pairs — source in F, F calls G
//!     (transitively), G contains a sink (3 hops normally, 5 for
//!     high-risk source/sink candidates)
//!
//!   * structured taint evidence — for every candidate pair, the
//!     variable-level [`TaintEvidencePath`] that grounds it (see
//!     [`crate::evidence`]), plus the reflection and response-dataflow
//!     passes that decorate it
//!   * framework entry points — the route/annotation-derived
//!     `kind = "framework"` sources [`crate::framework`] detects
//!
//! **What the evidence gate does to `taint_paths` — a soft gate, and
//! why.** A call-graph-reachable, kind-compatible source/sink pair is
//! always emitted as a taint path unless the symbolic walk positively
//! shows the value reaching the sink *sanitized*; that case is recorded
//! in `taint_evidence` with `sanitized: true` and kept out of
//! `taint_paths`, exactly as upstream. What differs is the *ungrounded*
//! case: a path the symbolic walk cannot ground keeps its place in
//! `taint_paths`, carrying the same bare fallback evidence
//! (`edges: []`, unsanitized) a path with no facts to walk gets.
//!
//! `_graph.py` gates this hard instead — `if evidence is None: continue`
//! (L1798 / L1878) drops the path outright — but only where
//! `_has_phase1_facts_for_path` holds, i.e. for Python, Java and C#.
//! JavaScript, TypeScript and Go had no fact extractor at all upstream
//! (`_js_extract`/`_go_extract` return empty assign/return/call-arg
//! lists), so they never reached the gate and kept pure reachability.
//! This port extracts facts for all six languages, so all six reach the
//! gate — which is exactly why the gate had to become a soft one.
//! The net effect upstream is inverted from the intent: **the languages
//! the engine understands best get the fewest seed paths.** Field
//! evidence (2026-09-06): a five-file Flask app with three genuine
//! reachable sinks produced `taint_paths = 0` while its call graph
//! resolved every cross-file edge correctly — strictly worse than the
//! reachability-only engine that preceded the evidence plane, and a
//! silent regression for every downstream stage that reads
//! `taint_paths` as its candidate set (S3 decompose in particular).
//!
//! Grounded evidence is a *confidence signal*, not an admission
//! criterion: an extractor gap (see `scan`'s composed-value section for
//! how wide those were) must not erase a path the call graph proves
//! reachable. So the gate keeps only its sound half — a demonstrated
//! sanitizer excludes a path; a failure to demonstrate anything does
//! not. Consumers that want the stronger signal can filter on
//! `TaintEvidencePath::edges` being non-empty.
//!
//! **Still not ported, and why.** Python's CFG-based path-sensitive
//! solver (`_solve_with_cfgs` and the `ConditionTaintEdge`s it would
//! emit) is dead code upstream: `_scan.py::scan_file` calls
//! `_build_cfg_for_function` with a `None` node for every function and
//! that helper returns `None` for a `None` node, so `FileIndex.cfgs` is
//! empty on every index the original itself builds. `FileIndex` here
//! carries no `cfgs` field for the same reason. See
//! [`crate::evidence`]'s module doc for the rest of the deliberate
//! divergences.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::Path;

use crate::evidence::TaintEvidencePath;
use crate::families::PROTECTED_SEMANTIC_FAMILIES;
use crate::scan::{CallSite, FileIndex};

const BASE_INTER_HOPS: usize = 3;
const HIGH_RISK_INTER_HOPS: usize = 5;
/// Fallback fanout cap when a bare callee resolves to several def-sites,
/// used only when the caller doesn't thread a real
/// `step1.call_graph_max_targets` value through.
pub const DEFAULT_MAX_TARGETS_PER_CALL: usize = 3;

fn high_risk_cwe() -> &'static [&'static str] {
    &[
        "22", "78", "79", "89", "90", "94", "95", "434", "502", "601", "611", "918",
    ]
}

/// Sink kinds compatible with each source kind — `None`/absent-key
/// means "no restriction" (see [`compatible_taint_pair`]).
///
/// Keyed on the spellings the inherited table used (`network`, `ipc`,
/// `cli`, `filesystem`, `env`) plus the ones a rule corpus actually
/// writes: `http` is `network`, `stdin` is `cli`, and `file` (the
/// `bc_model::EntryPointKind` spelling) is `filesystem`. Before those
/// aliases a source rule tagged `http` or `stdin` fell through to `None`
/// and admitted every sink kind, which left the filter inert for 18 of
/// the 21 rules in S0's own bundled corpus. `env` keeps its own row
/// rather than folding into `file`: an environment variable feeds an
/// open-redirect target in a way a file's bytes do not, so the
/// entry-point model's `env -> file` alias is a coarser bucket than
/// this table wants.
fn source_kind_compat(src_kind: &str) -> Option<&'static [&'static str]> {
    // `format` (CWE-134) and `memory` (CWE-121/787) joined this table
    // with C and C++: a buffer overflow and a format-string bug are
    // reachable from a command line, a file, an environment variable
    // and the network alike, and the table predates any language whose
    // sinks are memory-unsafe rather than injection-shaped.
    //
    // `crypto` (CWE-327, `semantic_family: other`, so no protected-
    // family bypass) joined when the `http`/`stdin`/`file` aliases
    // switched the filter on. Those pairs were reported before only
    // because `http` had no row; without an entry here every
    // request-to-weak-hash pair in the corpus would have vanished the
    // moment `http` started resolving.
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

/// Digits following the first `CWE-` in `cwe` (case-insensitive),
/// stopping at the first non-digit — `""` if `cwe` is empty or has no
/// `CWE-` marker.
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

/// Number of shared leading path components between `a`'s and `b`'s
/// *parent* directories (the file's own name is never compared).
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

/// Iteration E recall floor: a sink in a [`PROTECTED_SEMANTIC_FAMILIES`]
/// family is always kept, regardless of source/sink kind compatibility.
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

/// `"{file}::{fn_name}"`, `"<module>"` standing in for an empty
/// (module-level) function name.
/// The name half of a file's module-scope id — the scope a statement at
/// the top level of a script belongs to, which has no `FuncDef` of its
/// own.
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

/// De-duplicates `items`, keeping only the first occurrence of each
/// value — matches Python's `list(dict.fromkeys(items))` idiom.
fn dedup_preserve_order(items: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    items
        .iter()
        .filter(|s| seen.insert((*s).clone()))
        .cloned()
        .collect()
}

/// Resolve `called_name` to its function definition(s). When multiple
/// candidates exist: same-file candidates win outright; otherwise a
/// receiver/import type hint plus directory-prefix proximity narrows to
/// the top-scoring candidate(s) (capped at `max_targets`); with no
/// receiver/hint signal at all, ambiguity is judged too high and the
/// edge is dropped rather than fanning out to every same-named function
/// in the repo.
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
    // A method that delegates to a same-named method on another object
    // — a Spring controller's `exportReport` calling
    // `adminOperationsService.exportReport(...)`, or an ASP.NET
    // controller's `IngestSubmission` calling
    // `_maintenance.IngestSubmission(...)` — is the commonest
    // service-layer shape there is, and the caller used to WIN the
    // resolution: it shares a file with itself, so both the same-file
    // shortcut and the directory-proximity score rank it top. The
    // call-graph builder then drops that self-edge, leaving the
    // delegating method with no outgoing edge at all and everything
    // downstream of it unreachable. A call made through a receiver that
    // is not `this` is never a call to the calling function, so the
    // caller is not a candidate for it.
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

    // `scored` is non-empty here (it's a 1:1 `.map()` of the already-
    // checked-non-empty `cands`), so its first entry's score always
    // matches at least itself below — `narrowed` can never end up
    // empty, unlike Python's own `_resolve_called_fids`, which carries
    // a same-shaped (and equally unreachable) `if narrowed: ... else:
    // scored[:max_targets]` fallback branch.
    let top = scored[0].0;
    scored
        .into_iter()
        .filter(|(score, _)| *score == top)
        .map(|(_, fid)| fid)
        .take(max_targets)
        .collect()
}

/// Whether `hinted` (a receiver's resolved import) is a strong enough
/// signal that `callee_file` is its target: either `hinted` literally
/// appears as a substring of `callee_file`, or at least half of
/// `hinted`'s dot-separated segments show up as their own substrings.
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

/// Confidence score for a resolved call edge: `1.0` same-file, `0.9`
/// receiver resolved via an import hint, `0.7`-`0.8` directory-prefix
/// proximity, `0.5` name-only fallback.
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

// ── path scoring / budgeting ────────────────────────────────────────────

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

/// One taint-path hop list, scored for [`filter_paths_by_budget`]:
/// `(score, source_fn, sink_family, path)`.
struct ScoredPath {
    score: f64,
    src_fn: String,
    sink_family: String,
    path: Vec<String>,
}

/// Apply confidence-weighted ranking (highest score first) and a global
/// path-count cap: keep the top 5 paths per source function, then the
/// top-scoring paths overall up to an adaptive global budget — but
/// always keep at least one path per `(source, sink_family)` pair, and
/// never drop the last surviving path for a
/// [`PROTECTED_SEMANTIC_FAMILIES`] sink family even once the budget is
/// otherwise exhausted.
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

    for sp in scored_paths {
        let pair = (sp.src_fn.clone(), sp.sink_family.clone());
        // The per-source cap limits how many times one source repeats
        // itself, not which vulnerability CLASSES it is allowed to
        // report. A path whose (source, sink-family) pair has not been
        // seen yet is always admitted: capping it instead let the five
        // highest-scoring findings decide what a reviewer ever hears
        // about, which is fatal for a program whose sources all live in
        // one function. Field evidence (2026-09-07): the polyglot bed's
        // c-cli tool reads `argv` four times in `main`, and five
        // path-traversal candidates crowded out both its seeded buffer
        // overflow and its seeded command injection. The number of sink
        // families is small and the global budget still applies, so the
        // total stays bounded.
        if kept_pairs.contains(&pair)
            && kept_by_source.get(&sp.src_fn).copied().unwrap_or(0) >= PER_SOURCE_LIMIT
        {
            continue;
        }
        if kept_paths.len() >= global_budget && !kept_pairs.contains(&pair) {
            let sink_semantic = sp
                .sink_family
                .split_once(':')
                .map(|(_, s)| s)
                .unwrap_or(&sp.sink_family);
            let protected = PROTECTED_SEMANTIC_FAMILIES.contains(&sink_semantic)
                && !protected_family_kept.contains(sink_semantic);
            if !protected {
                break;
            }
        }

        kept_paths.push(sp.path);
        *kept_by_source.entry(sp.src_fn).or_insert(0) += 1;
        let sink_semantic = sp
            .sink_family
            .split_once(':')
            .map(|(_, s)| s.to_string())
            .unwrap_or_else(|| sp.sink_family.clone());
        kept_pairs.insert(pair);
        if PROTECTED_SEMANTIC_FAMILIES.contains(&sink_semantic.as_str()) {
            protected_family_kept.insert(sink_semantic);
        }
    }
    kept_paths
}

/// A `"file:line"` hop, split from the right so a colon inside the file
/// portion itself (an unusual but legal path) doesn't get misparsed —
/// only the trailing line number is ever generated by this crate.
fn parse_hop(hop: &str) -> Option<(String, usize)> {
    let (file, line_str) = hop.rsplit_once(':')?;
    let line: usize = line_str.parse().ok()?;
    Some((file.to_string(), line))
}

// ── build_taint_paths ────────────────────────────────────────────────────

/// [`build_taint_paths`]'s result — the subset of Python's `SeedPackage`
/// this module can populate. `s0_seed.py`'s own wrapper (not yet
/// ported) is responsible for the rest (`engine`/`languages`/
/// `all_files`/`excluded`/`sarif_path`).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct TaintSeed {
    pub entry_points: Vec<crate::EntryPoint>,
    /// Synthetic `kind = "framework"` entry points derived from route
    /// annotations/decorators and request-binding markers. Python
    /// appends these straight onto `entry_points`
    /// (`_graph.py:1583-1588`) and then has `s1_preprocess.py:1399-1412`
    /// re-extract them by `kind == "framework"` and append them a SECOND
    /// time; keeping them in their own field here lets S1 merge once.
    pub framework_entry_points: Vec<crate::EntryPoint>,
    pub unsafe_sinks: Vec<crate::Sink>,
    /// Each item is a list of `"file:line"` hops, source-first,
    /// sink-last.
    pub taint_paths: Vec<Vec<String>>,
    /// Per-path symbolic dataflow: the hop list above with each transfer
    /// (`source`/`assign`/`arg_to_param`/`field_write`/`sanitize`/…)
    /// named and attributed to a symbol.
    pub taint_evidence: Vec<TaintEvidencePath>,
    pub rule_cwe: BTreeMap<String, Vec<String>>,
    pub call_graph: BTreeMap<String, Vec<String>>,
    pub call_graph_files: BTreeMap<String, Vec<String>>,
    pub def_spans: BTreeMap<String, (usize, usize)>,
    pub call_graph_confidence: BTreeMap<(String, String), f64>,
}

/// Evidence for one candidate path: the real symbolic walk when any
/// function on it carries phase-1 facts, otherwise the bare-bones
/// fallback shape.
///
/// Total, unlike `_graph.py`, whose `_build_taint_evidence_for_path`
/// returning `None` drops the candidate pair entirely (`if evidence is
/// None: continue`, L1798 / L1878). An ungrounded walk means "no
/// dataflow *demonstrated*", which an extractor gap produces just as
/// readily as a genuinely dead path — so it degrades to the same
/// fallback a factless language gets rather than deleting a pair the
/// call graph proved reachable. See the module doc for the field
/// evidence behind the change; the sanitized verdict, which *is* a
/// positive finding, still suppresses the path in the caller.
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

/// Append `evidence` unless an entry with the same `(source_ref,
/// sink_ref, path_funcs)` is already recorded — `_graph.py`'s
/// `seen_evidence` set.
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

/// Build a fresh [`TaintSeed`] from the given file indices. `max_targets`
/// caps how many def-sites an ambiguous callee resolves to.
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
        // A file's module scope is a caller in its own right. A PHP
        // script that reads `$_GET` at the top level, a Python one that
        // reads `sys.argv`, a Ruby one that reads `ARGV` — the whole
        // flow is there and there is no `FuncDef` to hang it on, so the
        // inter-procedural walk refused to start from it (it gates on
        // `fn_meta.contains_key`) and could not have named the file it
        // was standing in anyway. Such a source could only ever pair
        // with a sink in its own file. Field evidence (2026-09-07): the
        // polyglot bed's php-laravel app seeds a file-inclusion RCE
        // whose `$_GET['layout']` is read by a top-level script and
        // whose `require` is two files away, and the seed could not
        // reach it.
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

    // ── call graph ────────────────────────────────────────────────────
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
        // A module scope is not a function: it has no span worth
        // reporting and no definition site to list. It exists in
        // `fn_meta` only so the walk can start from a top-level source,
        // and claiming a span for it would either swallow the real
        // functions defined inside the file or invent a line for them.
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

    // ── entry points / sinks (unconditional) ────────────────────────────
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
                // A source call site says nothing about how — or
                // whether — a request reaches it. Only the framework
                // entry points, which are routes by construction, carry
                // a computed answer.
                reachable_from_unauth: false,
            });
        }
    }

    // ── structured taint evidence ────────────────────────────────────
    // `_build_taint_evidence_for_path` describes *how* a reachable
    // source/sink pair flows; only its sanitized verdict decides whether
    // the pair is a taint path. A path it can't ground degrades to
    // `fallback_evidence` — the same shape a path with no facts to walk
    // gets — instead of being dropped. See this module's doc for why
    // that diverges from `_graph.py`.
    let facts = crate::evidence::FactIndex::build(indices);
    let resolver = crate::evidence::PathResolver {
        fn_defs_by_name: &fn_defs_by_name,
        fn_meta: &fn_meta,
        file_index: &file_index,
        max_targets,
    };
    let mut taint_evidence: Vec<TaintEvidencePath> = Vec::new();
    let mut seen_evidence: BTreeSet<(String, String, Vec<String>)> = BTreeSet::new();

    // ── intra-procedural paths ───────────────────────────────────────
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

    // ── bounded inter-procedural BFS ─────────────────────────────────
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
                            // Python `continue`s here *before* recording
                            // evidence, so a duplicate hop list also
                            // suppresses the evidence entry.
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

    // ── reflection / dynamic-dispatch taint ──────────────────────────
    // Ported from `_graph.py:1934-2011`. Python guards the whole block
    // in `try/except: log.debug` — nothing here can panic, so there is
    // no equivalent to write. Its `if not merged:` branch is dead: every
    // fid in `tainted_fids` came out of some evidence path's own
    // `path_funcs`, so the search that sets `merged` always succeeds.
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

    // ── framework-level taint solving ────────────────────────────────
    // Ported from `_graph.py:1573-1600`.
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

    // ── cwe_num ─────────────────────────────────────────────────────

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

    // ── is_high_risk ────────────────────────────────────────────────

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
        // CWE-200 (information exposure) is not in the high-risk set,
        // and "other" doesn't match any risky kind substring.
        let cs = call_site("a.py", 1, "f", "sink", "other", "CWE-200");
        assert!(!is_high_risk(&cs));
    }

    // ── prefix_score ────────────────────────────────────────────────

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

    // ── compatible_taint_pair ───────────────────────────────────────

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
        // "header" is allowed for network/ipc but not cli.
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
        // "ssrf" isn't in filesystem's allowed sink set (unlike network's).
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
        // `crypto` (CWE-327) is `semantic_family: other`, so nothing
        // protects it; before it had a row of its own, a `network`
        // source paired with a weak-hash sink was rejected here and the
        // bundled corpus only ever saw those pairs because its `http`
        // spelling bypassed the table entirely.
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
        // No row lists this kind. `http` used to fall through to "no
        // restriction" and admit it.
        let unlisted = call_site("a.py", 3, "f", "sink", "unlisted-kind", "");
        assert!(!compatible_taint_pair(&s, &unlisted));
    }

    #[test]
    fn compatible_taint_pair_resolves_stdin_to_the_cli_row() {
        let s = call_site("a.c", 1, "f", "source", "stdin", "");
        let cmd = call_site("a.c", 2, "f", "sink", "cmd", "");
        assert!(compatible_taint_pair(&s, &cmd));
        // `header` is network/ipc-only, exactly as it is for `cli`.
        let header = call_site("a.c", 3, "f", "sink", "header", "");
        assert!(!compatible_taint_pair(&s, &header));
    }

    #[test]
    fn compatible_taint_pair_resolves_file_to_the_filesystem_row_not_env() {
        let s = call_site("a.py", 1, "f", "source", "file", "");
        let sql = call_site("a.py", 2, "f", "sink", "sql", "");
        assert!(compatible_taint_pair(&s, &sql));
        // `file` is `filesystem`, whose row admits neither of these;
        // `env` (tested above) admits `redirect`, which is why the
        // corpus keeps spelling its environment-variable rules `env`.
        let ssrf = call_site("a.py", 3, "f", "sink", "ssrf", "");
        assert!(!compatible_taint_pair(&s, &ssrf));
        let redirect = call_site("a.py", 4, "f", "sink", "redirect", "");
        assert!(!compatible_taint_pair(&s, &redirect));
    }

    // ── fn_id / fid_name ────────────────────────────────────────────

    #[test]
    fn fn_id_joins_file_and_function() {
        assert_eq!(fn_id("a.py", "handler"), "a.py::handler");
    }

    #[test]
    fn a_module_scope_source_reaches_a_sink_in_another_file_without_claiming_a_span() {
        // The scope a top-level statement belongs to has no `FuncDef`,
        // so it had no `fn_meta` entry and the walk refused to start
        // from it. It is a caller like any other — but not a function,
        // so it reports no definition span and no definition site.
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
        // A module claims no span and no definition site; the real
        // function still reports both, unshifted.
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

    // ── dedup_preserve_order ────────────────────────────────────────

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

    // ── resolve_called_fids ─────────────────────────────────────────

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
        // Caller is in neither candidate's file, so `same_file` is
        // empty too — with no receiver and no import hint, this is
        // genuinely ambiguous.
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
        // No receiver/hint, so all three (equally-scored via prefix
        // proximity) are candidates — capped at max_targets.
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

    // ── import_hint_matches ──────────────────────────────────────────

    #[test]
    fn import_hint_matches_false_for_an_empty_hint() {
        assert!(!import_hint_matches("", "anything.py"));
    }

    #[test]
    fn import_hint_matches_false_when_every_segment_is_an_empty_string() {
        // "..." splits on '.' into four empty strings, all filtered
        // out — a non-empty `hinted` whose segment list is still empty.
        assert!(!import_hint_matches("...", "anything.py"));
    }

    // ── edge_confidence ─────────────────────────────────────────────

    #[test]
    fn edge_confidence_same_file_is_1() {
        assert_eq!(edge_confidence("a.py", "a.py", "", &BTreeMap::new()), 1.0);
    }

    #[test]
    fn edge_confidence_import_hint_literal_substring_match_is_0_9() {
        // The callee file's text literally contains the hinted string
        // as-is (dots and all) — the FIRST 0.9 branch (a plain
        // substring `.contains()` check), distinct from the
        // path-segment-matching branch below.
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
        // No literal "pkg.sub.mod" substring anywhere in the callee
        // path (dots vs slashes), so this only passes via the
        // path-segment hint-matching branch: at least half of
        // {pkg, sub, mod} appear as their own path segments.
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
        // None of {pkg, sub, mod} appear anywhere in the callee path —
        // below the `>= len/2` threshold — falls through to plain
        // directory-prefix proximity scoring (0 shared dirs here, so
        // 0.5).
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

    // ── build_taint_paths: end-to-end ────────────────────────────────

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
        // Sinks/entry-points are still always surfaced, independent of
        // pairing compatibility.
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
        // Both functions live in the same file's FileIndex in practice
        // (one FileIndex per file); merge them here to model that.
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
        // A (harmless but real) self-recursive call must not create a
        // self-loop in the call graph.
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
        // A call made at module level (`containing_fn == ""`) has no
        // corresponding `FuncDef`, so `fn_meta` has no entry for
        // `"app.py::<module>"` — the call-graph builder must skip it
        // rather than panicking on the missing lookup.
        let idx = FileIndex {
            call_edges: vec![(String::new(), String::new(), "helper".to_string())],
            ..caller_base("app.py")
        };
        let seed = build_taint_paths(&[idx], &BTreeMap::new(), DEFAULT_MAX_TARGETS_PER_CALL);
        assert!(seed.call_graph.is_empty());
    }

    #[test]
    fn build_taint_paths_high_risk_source_allows_deeper_chains() {
        // 4 hops: handler -> a -> b -> c -> d(sink). CWE-89 (sql
        // injection) on the source is high-risk, so max_hops = 5,
        // comfortably covering this chain; the sink itself need not be
        // high-risk for hop_count <= BASE_INTER_HOPS, but here hop_count
        // (4) > BASE_INTER_HOPS (3), so the sink must ALSO be high-risk
        // for it to be kept.
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
        // Same 4-hop shape, but nothing is high-risk anywhere — capped
        // at BASE_INTER_HOPS (3), so this 4-hop chain never reaches the
        // sink.
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
        // Same 4-hop shape as the high-risk-source test above (deep
        // mode, max_hops=5, so hop_count=4 clears the OUTER `hop_count
        // > max_hops` check) but the SINK itself isn't high-risk this
        // time — the selective-deepening guard
        // (`hop_count > BASE_INTER_HOPS && !is_high_risk(sink)`) drops
        // it anyway, distinct from the outer hop-count cap.
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
        // Diamond call shape: handler calls both a and b, and both a
        // and b call c (which contains the sink) — c is discovered
        // twice, the second time hitting the BFS's own
        // already-visited skip.
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
        // Only reached once (via whichever of a/b the BFS visits
        // first) — the revisit via the other branch is skipped, so
        // there's exactly one taint path, not two.
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

    // ── filter_paths_by_budget ───────────────────────────────────────

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
        // Well-formed "file:line" hops, but no matching CallSite in
        // `sources`/`sinks` — the resolve-fallback branch.
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

    /// `n` paths from one source function to `n` sinks, each sink in
    /// the semantic family `families(i)` names.
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
        // Seven sinks in ONE family from one source: the cap is what
        // stops a single source flooding the seed with the same finding.
        assert_eq!(budget_fixture(7, |_| "sql-exec".to_string()).len(), 5);
    }

    #[test]
    fn filter_paths_by_budget_never_caps_away_a_whole_vulnerability_class() {
        // Seven sinks in seven DIFFERENT families: the cap limits
        // repetition, not which classes a source is allowed to report.
        // Capping these let the five highest-scoring findings decide
        // what a reviewer ever hears about — fatal for a program whose
        // sources all live in `main`.
        assert_eq!(budget_fixture(7, |i| format!("family-{i}")).len(), 7);
    }

    #[test]
    fn filter_paths_by_budget_drops_paths_once_the_global_budget_is_exhausted() {
        // 61 distinct source functions, each paired against the SAME 5
        // shared, reused sink call sites (5 distinct semantic
        // families) = 305 candidate paths, every one a distinct
        // (source, sink_family) pair (so the "always keep one per
        // pair" override never applies) and every source function at
        // or under the per-source limit of 5 (so that check never
        // blocks anything either). Fanout stays 61 * 5 = 305, under
        // the >=600 threshold — but since the candidate count (305)
        // exceeds the base 200, `effective_global_budget` expands to
        // 300 (the "low fanout, over the base cap" case
        // `effective_global_budget_moderate_expansion_when_over_the_
        // base_cap_but_low_fanout` already exercises directly) —
        // isolating the actual drop-when-the-(possibly-expanded)-
        // budget-is-exhausted behavior as the only thing capping the
        // last 5.
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
        // Same overall shape as the test above (budget expands to
        // 300), but `protected_family_kept` is a GLOBAL set, not
        // per-source — a protected family only earns the override the
        // FIRST time it's seen; every later occurrence of the same
        // family finds it already in `protected_family_kept` and
        // breaks like any other family. So the protected family here
        // ("sql-exec") is used ONLY for the very last source function's
        // first sink (the very first candidate that needs a budget
        // check at all) — every other source function's sinks are all
        // non-protected, so "sql-exec" is genuinely fresh precisely
        // when the override needs to fire. Both halves of the
        // override's `&&` condition
        // (`PROTECTED_SEMANTIC_FAMILIES.contains(...) &&
        // !protected_family_kept.contains(...)`) must be true for it to
        // survive without breaking — this is the only construction that
        // reaches the SECOND half at all, since every OTHER test's
        // first half is false and Rust's `&&` short-circuits. It's kept
        // as one path *beyond* the nominal budget, and the very next
        // (non-protected) candidate breaks the loop.
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
        // Only 6 DISTINCT sink call sites total (the 5 shared
        // non-protected ones, plus the one extra protected one) — not
        // 10, which would push fanout (61 * 10 = 610) past the >=600
        // threshold and expand the budget enough that nothing gets
        // dropped at all.
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
        let got = filter_paths_by_budget(paths, &sources, &sinks);
        // 300 kept within the nominal budget, +1 protected-family
        // override, then the loop breaks on the next candidate.
        assert_eq!(got.len(), 301);
    }

    #[test]
    fn filter_paths_by_budget_keeps_at_least_one_path_per_protected_family_past_budget() {
        // Force a tiny budget by using a fanout >= 600 with only a
        // couple of real paths, then confirm the sole path for a
        // protected family survives even artificially exhausting the
        // budget via a direct call with a huge synthetic path list is
        // impractical here — instead this test documents the simpler,
        // directly observable guarantee: a protected-family path is
        // never dropped by the per-source-limit override path either.
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

    // ── effective_global_budget / score_path / extract_sink_family ──

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

    // ── parse_hop ─────────────────────────────────────────────────────

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

    // ── structured evidence integration ─────────────────────────────

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

    /// A single file whose `f` reads a source at line 3 and reaches a
    /// sink at line 5, with the call facts that ground the flow.
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
        // The sink call takes an unrelated symbol, so nothing grounds
        // it. Upstream `_graph.py` drops the pair here; the soft gate
        // keeps it, unsanitized and with no transfer edges, because
        // "nothing demonstrated" is what an extractor gap looks like
        // too. See this module's doc.
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
        // No assign/return/call-arg facts on any path function, so
        // every reachable pair keeps the bare fallback shape. Every
        // wired language now extracts facts, so this is the hand-built
        // -fixture and unparsed-file case rather than a whole language.
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
        // The call into `sink_fn` passes nothing tainted.
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

    // ── reflection merge ────────────────────────────────────────────

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
        // The fallback evidence shape has no edges, so there is no taint
        // state to seed the reflection walk from.
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

    // ── framework entry points / response dataflow ──────────────────

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
