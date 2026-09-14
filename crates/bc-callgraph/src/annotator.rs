//! LLM-backed source/sink spec derivation for callgraph mode. Ported
//! from `vvaharness/pipeline/stages/callgraph_engine/_annotator.py`.
//!
//! **Scope (this pass): every pure, LLM-free piece.** Candidate
//! collection, prompt construction, response parsing, heuristic
//! fallback classification, and spec-merging bookkeeping are all fully
//! ported and tested here. `detect_specs` itself — the function that
//! actually batches candidates and calls an LLM — is deliberately not
//! ported: it needs a live LLM client, which this crate doesn't (and
//! per this port's established split shouldn't) depend on, matching
//! `bc-repo-analysis`/`bc-dedup-core`'s own LLM-free domain-logic role
//! versus the `bc-stage-sN` crates that own agentic orchestration.
//! `detect_specs`'s own thin orchestration (batch the candidates this
//! module already ranks, call the LLM with the prompt this module
//! already builds, parse the response this module already parses, fall
//! back to [`supplement_with_heuristics`] this module already
//! implements) belongs in the not-yet-built `bc-stage-s0` wrapper
//! alongside `s0_seed.py`'s own `run()`.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use regex::Regex;
use serde_json::{json, Value};

use crate::families;
use crate::rules::MatchSpec;
use crate::scan::FileIndex;

/// System prompt for the LLM classification call `bc-stage-s0` will
/// eventually make with [`build_prompt_batch`]'s output.
pub const SYSTEM_PROMPT: &str = "You classify API call fingerprints for taint seeding. \
Return JSON only with key 'results': a list of objects with fields \
id, role, confidence, cwe, kind. \
role must be one of source, sink, none. \
confidence must be a number between 0 and 1. \
cwe should be like CWE-89. \
kind for source should be one of network, ipc, file, cli, \
deserialization, other. \
kind for sink can be a short snake_case label.";

fn source_method_hints() -> &'static [&'static str] {
    &[
        "get", "args", "query", "param", "params", "form", "json", "body", "headers", "header",
        "cookies", "cookie", "input", "read", "recv", "receive", "next", "fetch",
    ]
}

fn source_module_hints() -> &'static [&'static str] {
    &[
        "flask",
        "fastapi",
        "django",
        "starlette",
        "aiohttp",
        "request",
        "requests",
        "sys",
        "os",
    ]
}

fn sink_method_hints() -> &'static [&'static str] {
    &[
        "execute",
        "executemany",
        "raw",
        "query",
        "run",
        "system",
        "popen",
        "spawn",
        "exec",
        "eval",
        "loads",
        "load",
        "deserialize",
        "unmarshal",
        "parse",
        "render",
        "template",
        "write",
        "send",
        "post",
        "put",
    ]
}

fn sink_module_hints() -> &'static [&'static str] {
    &[
        "os",
        "subprocess",
        "sqlite3",
        "psycopg2",
        "pymysql",
        "mysql",
        "sqlalchemy",
        "pickle",
        "yaml",
        "jinja2",
        "mako",
        "shlex",
    ]
}

/// One aggregated, ranked observed-call fingerprint — the unit
/// `detect_specs`'s LLM classification call (and the heuristic
/// fallback) both work over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub cid: String,
    pub language: String,
    pub module: String,
    pub method: String,
    pub count: usize,
    pub sample_file: String,
    pub sample_line: usize,
    pub sample_snippet: String,
}

/// CWE normalization with a role-specific fallback (`CWE-20` for a
/// source, `CWE-78` for a sink) when `raw` doesn't parse as one.
pub fn norm_cwe_for_role(raw: &str, role: &str) -> String {
    if let Some(norm) = families::norm_cwe(raw) {
        return norm;
    }
    if role == "source" {
        "CWE-20".to_string()
    } else {
        "CWE-78".to_string()
    }
}

/// Map a source/sink kind + CWE to the semantic family used downstream
/// — a simpler cousin of [`crate::rules`]'s own (private) semantic-
/// family classifier: this one has no rule-pattern text to inspect,
/// since LLM/heuristic candidates carry only a bare kind + CWE, not a
/// rule tree.
pub fn semantic_family(kind: &str, cwe: &str) -> String {
    let k = kind.trim().to_lowercase();
    let c = cwe.to_uppercase();
    if c.contains("79") || matches!(k.as_str(), "xss" | "template") {
        return "html-response".to_string();
    }
    if c.contains("78") || matches!(k.as_str(), "cmd" | "dyn-eval") {
        return "command-exec".to_string();
    }
    if c.contains("89") || c.contains("90") || k == "sql" {
        return "sql-exec".to_string();
    }
    if c.contains("918") || k == "ssrf" {
        return "url-fetch".to_string();
    }
    if c.contains("22") || k == "path" {
        return "file-io".to_string();
    }
    if c.contains("502") || k == "deserialize" {
        return "deserialization".to_string();
    }
    if matches!(k.as_str(), "credentials" | "secret") {
        return "credentials".to_string();
    }
    if k.is_empty() {
        "other".to_string()
    } else {
        k
    }
}

/// Aggregate every [`FileIndex::observed_calls`] entry into ranked,
/// deduplicated candidates keyed by `(language, module, method)` —
/// most-frequent first, capped at `max_candidates`.
pub fn collect_candidates(
    file_indices: &[FileIndex],
    active_langs: &BTreeSet<String>,
    max_candidates: usize,
) -> Vec<Candidate> {
    let mut by_sig: BTreeMap<(String, String, String), Candidate> = BTreeMap::new();
    // Discovery order, tracked separately since `BTreeMap` iterates by
    // key rather than insertion order — needed for stable `cid`
    // numbering (`c1`, `c2`, ...) independent of the final ranked sort.
    let mut discovery_count = 0usize;
    for idx in file_indices {
        for oc in &idx.observed_calls {
            if !active_langs.contains(&oc.language) {
                continue;
            }
            let module = if !oc.resolved_receiver.is_empty() {
                oc.resolved_receiver
                    .split('.')
                    .next()
                    .unwrap_or("")
                    .to_string()
            } else if !oc.receiver.is_empty() {
                oc.receiver.split('.').next().unwrap_or("").to_string()
            } else {
                String::new()
            };
            let module = module.trim().to_string();
            let method = oc.method.trim().to_string();
            if module.is_empty() || method.is_empty() {
                continue;
            }
            let sig = (oc.language.clone(), module.clone(), method.clone());
            match by_sig.get_mut(&sig) {
                Some(cur) => cur.count += 1,
                None => {
                    discovery_count += 1;
                    by_sig.insert(
                        sig,
                        Candidate {
                            cid: format!("c{discovery_count}"),
                            language: oc.language.clone(),
                            module,
                            method,
                            count: 1,
                            sample_file: oc.file.clone(),
                            sample_line: oc.line,
                            sample_snippet: oc.snippet.clone(),
                        },
                    );
                }
            }
        }
    }
    let mut ordered: Vec<Candidate> = by_sig.into_values().collect();
    ordered.sort_by(|a, b| {
        b.count
            .cmp(&a.count)
            .then_with(|| a.language.cmp(&b.language))
            .then_with(|| a.module.cmp(&b.module))
            .then_with(|| a.method.cmp(&b.method))
    });
    ordered.truncate(max_candidates);
    ordered
}

/// Build the JSON classification prompt for one batch of candidates.
pub fn build_prompt_batch(batch: &[Candidate]) -> String {
    let payload: Vec<Value> = batch
        .iter()
        .map(|c| {
            json!({
                "id": c.cid,
                "language": c.language,
                "module": c.module,
                "method": c.method,
                "count": c.count,
                "sample": format!("{}:{}: {}", c.sample_file, c.sample_line, c.sample_snippet),
            })
        })
        .collect();
    let instr = json!({
        "task": "Classify each API as source, sink, or none for taint seeding.",
        "constraints": [
            "Use only provided IDs.",
            "Prefer role=none when uncertain.",
            "Confidence must be numeric in [0,1].",
        ],
        "output_schema": {
            "results": [
                {
                    "id": "c1",
                    "role": "source|sink|none",
                    "confidence": 0.0,
                    "cwe": "CWE-20",
                    "kind": "network|ipc|file|cli|deserialization|other|<sink_kind>",
                }
            ]
        },
        "calls": payload,
    });
    serde_json::to_string_pretty(&instr)
        .expect("MatchSpec/Candidate-derived JSON is always serializable")
}

/// Parse an LLM response into its classification rows: either a bare
/// JSON array of objects, or an object with a `results` array —
/// anything else (including a parse failure) degrades to no results,
/// matching the Python original's own tolerant contract.
pub fn parse_results(raw: &str) -> Vec<serde_json::Map<String, Value>> {
    let Ok(parsed) = bc_json_repair::extract_json(raw) else {
        return Vec::new();
    };
    match parsed {
        Value::Array(items) => items.into_iter().filter_map(as_object).collect(),
        Value::Object(mut obj) => match obj.remove("results") {
            Some(Value::Array(items)) => items.into_iter().filter_map(as_object).collect(),
            _ => Vec::new(),
        },
        _ => Vec::new(),
    }
}

fn as_object(v: Value) -> Option<serde_json::Map<String, Value>> {
    match v {
        Value::Object(m) => Some(m),
        _ => None,
    }
}

static NON_ALNUM_RX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[^a-z0-9]+").unwrap());

fn tok(s: &str) -> String {
    NON_ALNUM_RX.replace_all(&s.to_lowercase(), "").into_owned()
}

fn heuristic_source_kind(c: &Candidate) -> Option<(&'static str, &'static str)> {
    let mt = tok(&c.method);
    let md = tok(&c.module);
    let sn = c.sample_snippet.to_lowercase();
    if source_method_hints().contains(&mt.as_str())
        && (source_module_hints().contains(&md.as_str())
            || sn.contains("request")
            || sn.contains("header")
            || sn.contains("cookie"))
    {
        return Some(("network", "CWE-20"));
    }
    if matches!(mt.as_str(), "getenv" | "environ") || sn.contains("os.environ") {
        return Some(("file", "CWE-73"));
    }
    if matches!(mt.as_str(), "argv" | "next" | "readline")
        && (md.contains("sys") || sn.contains("stdin"))
    {
        return Some(("cli", "CWE-20"));
    }
    None
}

fn heuristic_sink_kind(c: &Candidate) -> Option<(&'static str, &'static str)> {
    let mt = tok(&c.method);
    let md = tok(&c.module);
    let sn = c.sample_snippet.to_lowercase();
    if matches!(mt.as_str(), "system" | "popen" | "spawn" | "exec" | "eval")
        || matches!(md.as_str(), "os" | "subprocess")
    {
        return Some(("command_injection", "CWE-78"));
    }
    if matches!(mt.as_str(), "execute" | "executemany" | "raw" | "query") {
        return Some(("sql_injection", "CWE-89"));
    }
    if matches!(mt.as_str(), "loads" | "load" | "deserialize" | "unmarshal")
        || matches!(md.as_str(), "pickle" | "yaml")
    {
        return Some(("unsafe_deserialization", "CWE-502"));
    }
    if sink_method_hints().contains(&mt.as_str())
        && (sink_module_hints().contains(&md.as_str()) || sn.contains("sql"))
    {
        return Some(("unsafe", "CWE-20"));
    }
    None
}

/// Turn one accepted LLM/heuristic classification into a fresh
/// [`MatchSpec`], deduped by `(role, language, module, method)` against
/// `seen_sig` (a no-op re-add is silently dropped, matching Python's
/// `if sig in seen_sig: return`). `suffix` distinguishes rule ids across
/// repeated candidate signatures from different call sites (LLM
/// detection passes `""`; [`supplement_with_heuristics`] uses its own).
#[allow(clippy::too_many_arguments)]
pub fn append_spec(
    role: &str,
    cand: &Candidate,
    kind: &str,
    cwe: &str,
    source_specs: &mut Vec<MatchSpec>,
    sink_specs: &mut Vec<MatchSpec>,
    rule_cwe: &mut BTreeMap<String, Vec<String>>,
    seen_sig: &mut BTreeSet<(String, String, String, String)>,
    suffix: &str,
) {
    let sig = (
        role.to_string(),
        cand.language.clone(),
        cand.module.clone(),
        cand.method.clone(),
    );
    if !seen_sig.insert(sig) {
        return;
    }
    let rule_id = format!(
        "llm-{role}:{}:{}.{}{suffix}",
        cand.language, cand.module, cand.method
    );
    let family = semantic_family(kind, cwe);
    let owasp_top10_2025 = families::owasp_labels(&family)
        .iter()
        .map(|s| s.to_string())
        .collect();
    let spec = MatchSpec {
        rule_id: rule_id.clone(),
        role: role.to_string(),
        origin: "llm".to_string(),
        cwe: cwe.to_string(),
        kind: kind.to_string(),
        languages: BTreeSet::from([cand.language.clone()]),
        semantic_family: family,
        owasp_top10_2025,
        module_attr_module: cand.module.clone(),
        module_attr_names: BTreeSet::from([cand.method.clone()]),
        ..Default::default()
    };
    rule_cwe.insert(rule_id, vec![cwe.to_string()]);
    if role == "source" {
        source_specs.push(spec);
    } else {
        sink_specs.push(spec);
    }
}

fn seed_seen_sig(
    source_specs: &[MatchSpec],
    sink_specs: &[MatchSpec],
) -> BTreeSet<(String, String, String, String)> {
    let mut seen = BTreeSet::new();
    for (role, specs) in [("source", source_specs), ("sink", sink_specs)] {
        for s in specs {
            if !s.has_module_attr() {
                continue;
            }
            let lang = s.languages.iter().next().cloned().unwrap_or_default();
            for m in &s.module_attr_names {
                seen.insert((
                    role.to_string(),
                    lang.clone(),
                    s.module_attr_module.clone(),
                    m.clone(),
                ));
            }
        }
    }
    seen
}

/// Augment `source_specs`/`sink_specs` with deterministic tree-sitter
/// heuristics: scans ranked candidates for hint-matched source/sink
/// shapes and appends up to `min_extra_sources`/`min_extra_sinks` new
/// specs (never duplicating an existing `(role, language, module,
/// method)` signature), stopping early at `max_extra_specs` total
/// additions. A no-op when `max_extra_specs` is `0`.
#[allow(clippy::too_many_arguments)]
pub fn supplement_with_heuristics(
    file_indices: &[FileIndex],
    active_langs: &[String],
    mut source_specs: Vec<MatchSpec>,
    mut sink_specs: Vec<MatchSpec>,
    mut rule_cwe: BTreeMap<String, Vec<String>>,
    min_extra_sources: usize,
    min_extra_sinks: usize,
    max_extra_specs: usize,
) -> (
    Vec<MatchSpec>,
    Vec<MatchSpec>,
    BTreeMap<String, Vec<String>>,
) {
    if max_extra_specs == 0 {
        return (source_specs, sink_specs, rule_cwe);
    }

    let active: BTreeSet<String> = active_langs.iter().cloned().collect();
    let candidates = collect_candidates(file_indices, &active, 400);
    if candidates.is_empty() {
        return (source_specs, sink_specs, rule_cwe);
    }

    let mut seen_sig = seed_seen_sig(&source_specs, &sink_specs);
    let mut add_src = min_extra_sources;
    let mut add_snk = min_extra_sinks;
    let mut added = 0usize;

    if add_src > 0 {
        for cand in &candidates {
            let Some((kind, cwe)) = heuristic_source_kind(cand) else {
                continue;
            };
            let before = source_specs.len();
            append_spec(
                "source",
                cand,
                kind,
                cwe,
                &mut source_specs,
                &mut sink_specs,
                &mut rule_cwe,
                &mut seen_sig,
                ":h",
            );
            if source_specs.len() > before {
                add_src -= 1;
                added += 1;
            }
            if add_src == 0 || added >= max_extra_specs {
                break;
            }
        }
    }

    if add_snk > 0 && added < max_extra_specs {
        for cand in &candidates {
            let Some((kind, cwe)) = heuristic_sink_kind(cand) else {
                continue;
            };
            let before = sink_specs.len();
            append_spec(
                "sink",
                cand,
                kind,
                cwe,
                &mut source_specs,
                &mut sink_specs,
                &mut rule_cwe,
                &mut seen_sig,
                ":h",
            );
            if sink_specs.len() > before {
                add_snk -= 1;
                added += 1;
            }
            if add_snk == 0 || added >= max_extra_specs {
                break;
            }
        }
    }

    (source_specs, sink_specs, rule_cwe)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::ObservedCall;

    fn observed(
        language: &str,
        receiver: &str,
        resolved_receiver: &str,
        method: &str,
        snippet: &str,
    ) -> ObservedCall {
        ObservedCall {
            file: "app.py".to_string(),
            language: language.to_string(),
            line: 1,
            receiver: receiver.to_string(),
            resolved_receiver: resolved_receiver.to_string(),
            method: method.to_string(),
            containing_fn: "handler".to_string(),
            snippet: snippet.to_string(),
        }
    }

    fn file_index_with(observed_calls: Vec<ObservedCall>) -> FileIndex {
        FileIndex {
            file: "app.py".to_string(),
            language: "python".to_string(),
            observed_calls,
            ..Default::default()
        }
    }

    fn langs(vals: &[&str]) -> BTreeSet<String> {
        vals.iter().map(|s| s.to_string()).collect()
    }

    fn candidate(cid: &str, language: &str, module: &str, method: &str, count: usize) -> Candidate {
        Candidate {
            cid: cid.to_string(),
            language: language.to_string(),
            module: module.to_string(),
            method: method.to_string(),
            count,
            sample_file: "app.py".to_string(),
            sample_line: 1,
            sample_snippet: String::new(),
        }
    }

    // ── norm_cwe_for_role ────────────────────────────────────────────

    #[test]
    fn norm_cwe_for_role_uses_a_recognized_cwe() {
        assert_eq!(norm_cwe_for_role("CWE-89", "source"), "CWE-89");
    }

    #[test]
    fn norm_cwe_for_role_falls_back_per_role() {
        assert_eq!(norm_cwe_for_role("not a cwe", "source"), "CWE-20");
        assert_eq!(norm_cwe_for_role("not a cwe", "sink"), "CWE-78");
    }

    // ── semantic_family ──────────────────────────────────────────────

    #[test]
    fn semantic_family_html_response() {
        assert_eq!(semantic_family("xss", ""), "html-response");
        assert_eq!(semantic_family("other", "CWE-79"), "html-response");
        assert_eq!(semantic_family("template", ""), "html-response");
    }

    #[test]
    fn semantic_family_command_exec() {
        assert_eq!(semantic_family("cmd", ""), "command-exec");
        assert_eq!(semantic_family("dyn-eval", ""), "command-exec");
        assert_eq!(semantic_family("other", "CWE-78"), "command-exec");
    }

    #[test]
    fn semantic_family_sql_exec() {
        assert_eq!(semantic_family("sql", ""), "sql-exec");
        assert_eq!(semantic_family("other", "CWE-89"), "sql-exec");
        assert_eq!(semantic_family("other", "CWE-90"), "sql-exec");
    }

    #[test]
    fn semantic_family_url_fetch() {
        assert_eq!(semantic_family("ssrf", ""), "url-fetch");
        assert_eq!(semantic_family("other", "CWE-918"), "url-fetch");
    }

    #[test]
    fn semantic_family_file_io() {
        assert_eq!(semantic_family("path", ""), "file-io");
        assert_eq!(semantic_family("other", "CWE-22"), "file-io");
    }

    #[test]
    fn semantic_family_deserialization() {
        assert_eq!(semantic_family("deserialize", ""), "deserialization");
        assert_eq!(semantic_family("other", "CWE-502"), "deserialization");
    }

    #[test]
    fn semantic_family_credentials() {
        assert_eq!(semantic_family("credentials", ""), "credentials");
        assert_eq!(semantic_family("secret", ""), "credentials");
    }

    #[test]
    fn semantic_family_falls_back_to_the_kind_then_other() {
        assert_eq!(semantic_family("weird-kind", ""), "weird-kind");
        assert_eq!(semantic_family("", ""), "other");
    }

    // ── collect_candidates ───────────────────────────────────────────

    #[test]
    fn collect_candidates_aggregates_repeated_calls_by_signature() {
        let idx = file_index_with(vec![
            observed("python", "", "os", "system", ""),
            observed("python", "", "os", "system", ""),
        ]);
        let got = collect_candidates(std::slice::from_ref(&idx), &langs(&["python"]), 10);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].count, 2);
        assert_eq!(got[0].module, "os");
        assert_eq!(got[0].method, "system");
    }

    #[test]
    fn collect_candidates_prefers_the_resolved_receiver_over_the_bare_one() {
        let idx = file_index_with(vec![observed("python", "o", "os.path", "join", "")]);
        let got = collect_candidates(std::slice::from_ref(&idx), &langs(&["python"]), 10);
        assert_eq!(got[0].module, "os");
    }

    #[test]
    fn collect_candidates_falls_back_to_the_bare_receiver_when_unresolved() {
        let idx = file_index_with(vec![observed("python", "sub.pkg", "", "call", "")]);
        let got = collect_candidates(std::slice::from_ref(&idx), &langs(&["python"]), 10);
        assert_eq!(got[0].module, "sub");
    }

    #[test]
    fn collect_candidates_skips_calls_with_no_resolvable_module() {
        let idx = file_index_with(vec![observed("python", "", "", "eval", "")]);
        let got = collect_candidates(std::slice::from_ref(&idx), &langs(&["python"]), 10);
        assert!(got.is_empty());
    }

    #[test]
    fn collect_candidates_skips_calls_with_a_blank_method() {
        let idx = file_index_with(vec![observed("python", "", "os", "  ", "")]);
        let got = collect_candidates(std::slice::from_ref(&idx), &langs(&["python"]), 10);
        assert!(got.is_empty());
    }

    #[test]
    fn collect_candidates_filters_by_active_language() {
        let idx = file_index_with(vec![observed("java", "", "os", "system", "")]);
        let got = collect_candidates(std::slice::from_ref(&idx), &langs(&["python"]), 10);
        assert!(got.is_empty());
    }

    #[test]
    fn collect_candidates_sorts_by_count_descending_then_by_signature() {
        let idx = file_index_with(vec![
            observed("python", "", "pickle", "loads", ""),
            observed("python", "", "os", "system", ""),
            observed("python", "", "os", "system", ""),
        ]);
        let got = collect_candidates(std::slice::from_ref(&idx), &langs(&["python"]), 10);
        assert_eq!(got[0].method, "system");
        assert_eq!(got[1].method, "loads");
    }

    #[test]
    fn collect_candidates_truncates_to_max_candidates() {
        let idx = file_index_with(vec![
            observed("python", "", "a", "f", ""),
            observed("python", "", "b", "f", ""),
            observed("python", "", "c", "f", ""),
        ]);
        let got = collect_candidates(std::slice::from_ref(&idx), &langs(&["python"]), 2);
        assert_eq!(got.len(), 2);
    }

    #[test]
    fn collect_candidates_numbers_cids_in_discovery_order() {
        let idx = file_index_with(vec![
            observed("python", "", "a", "f", ""),
            observed("python", "", "b", "g", ""),
        ]);
        let got = collect_candidates(std::slice::from_ref(&idx), &langs(&["python"]), 10);
        let cids: BTreeSet<&str> = got.iter().map(|c| c.cid.as_str()).collect();
        assert_eq!(cids, BTreeSet::from(["c1", "c2"]));
    }

    // ── build_prompt_batch ───────────────────────────────────────────

    #[test]
    fn build_prompt_batch_embeds_every_candidate_field() {
        let batch = vec![candidate("c1", "python", "os", "system", 3)];
        let prompt = build_prompt_batch(&batch);
        let parsed: Value = serde_json::from_str(&prompt).unwrap();
        let call = &parsed["calls"][0];
        assert_eq!(call["id"], "c1");
        assert_eq!(call["language"], "python");
        assert_eq!(call["module"], "os");
        assert_eq!(call["method"], "system");
        assert_eq!(call["count"], 3);
        assert!(parsed["output_schema"]["results"].is_array());
    }

    #[test]
    fn build_prompt_batch_empty_batch_has_no_calls() {
        let prompt = build_prompt_batch(&[]);
        let parsed: Value = serde_json::from_str(&prompt).unwrap();
        assert_eq!(parsed["calls"].as_array().unwrap().len(), 0);
    }

    // ── parse_results ────────────────────────────────────────────────

    #[test]
    fn parse_results_accepts_a_bare_array() {
        let got = parse_results(r#"[{"id": "c1", "role": "source"}]"#);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0]["id"], "c1");
    }

    #[test]
    fn parse_results_accepts_an_object_with_a_results_array() {
        let got = parse_results(r#"{"results": [{"id": "c1"}, {"id": "c2"}]}"#);
        assert_eq!(got.len(), 2);
    }

    #[test]
    fn parse_results_filters_out_non_object_array_entries() {
        let got = parse_results(r#"[{"id": "c1"}, "not an object", 5]"#);
        assert_eq!(got.len(), 1);
    }

    #[test]
    fn parse_results_empty_when_object_has_no_results_array() {
        assert!(parse_results(r#"{"other": []}"#).is_empty());
        assert!(parse_results(r#"{"results": "not an array"}"#).is_empty());
    }

    #[test]
    fn parse_results_empty_for_a_bare_scalar() {
        assert!(parse_results("42").is_empty());
    }

    #[test]
    fn parse_results_empty_for_unparseable_text() {
        assert!(parse_results("not json at all, sorry").is_empty());
    }

    // ── heuristic_source_kind ────────────────────────────────────────

    #[test]
    fn heuristic_source_kind_network_via_module_hint() {
        let c = candidate("c1", "python", "request", "args", 1);
        assert_eq!(heuristic_source_kind(&c), Some(("network", "CWE-20")));
    }

    #[test]
    fn heuristic_source_kind_network_via_snippet_hint() {
        let mut c = candidate("c1", "python", "unrelated_module", "get", 1);
        c.sample_snippet = "reads the request body".to_string();
        assert_eq!(heuristic_source_kind(&c), Some(("network", "CWE-20")));
    }

    #[test]
    fn heuristic_source_kind_network_via_header_snippet_hint() {
        let mut c = candidate("c1", "python", "unrelated_module", "get", 1);
        c.sample_snippet = "reads the auth header".to_string();
        assert_eq!(heuristic_source_kind(&c), Some(("network", "CWE-20")));
    }

    #[test]
    fn heuristic_source_kind_network_via_cookie_snippet_hint() {
        let mut c = candidate("c1", "python", "unrelated_module", "get", 1);
        c.sample_snippet = "reads the session cookie".to_string();
        assert_eq!(heuristic_source_kind(&c), Some(("network", "CWE-20")));
    }

    #[test]
    fn heuristic_source_kind_env_via_method() {
        let c = candidate("c1", "python", "os", "getenv", 1);
        assert_eq!(heuristic_source_kind(&c), Some(("file", "CWE-73")));
    }

    #[test]
    fn heuristic_source_kind_env_via_snippet() {
        let mut c = candidate("c1", "python", "unrelated", "unrelated", 1);
        c.sample_snippet = "os.environ['X']".to_string();
        assert_eq!(heuristic_source_kind(&c), Some(("file", "CWE-73")));
    }

    #[test]
    fn heuristic_source_kind_cli_via_module() {
        let c = candidate("c1", "python", "sys", "argv", 1);
        assert_eq!(heuristic_source_kind(&c), Some(("cli", "CWE-20")));
    }

    #[test]
    fn heuristic_source_kind_cli_via_snippet() {
        let mut c = candidate("c1", "python", "unrelated", "readline", 1);
        c.sample_snippet = "reading from stdin".to_string();
        assert_eq!(heuristic_source_kind(&c), Some(("cli", "CWE-20")));
    }

    #[test]
    fn heuristic_source_kind_none_when_nothing_matches() {
        let c = candidate("c1", "python", "myapp", "do_thing", 1);
        assert_eq!(heuristic_source_kind(&c), None);
    }

    // ── heuristic_sink_kind ──────────────────────────────────────────

    #[test]
    fn heuristic_sink_kind_command_injection_via_method() {
        let c = candidate("c1", "python", "unrelated", "system", 1);
        assert_eq!(
            heuristic_sink_kind(&c),
            Some(("command_injection", "CWE-78"))
        );
    }

    #[test]
    fn heuristic_sink_kind_command_injection_via_module() {
        let c = candidate("c1", "python", "subprocess", "call", 1);
        assert_eq!(
            heuristic_sink_kind(&c),
            Some(("command_injection", "CWE-78"))
        );
    }

    #[test]
    fn heuristic_sink_kind_sql_injection() {
        let c = candidate("c1", "python", "cursor", "execute", 1);
        assert_eq!(heuristic_sink_kind(&c), Some(("sql_injection", "CWE-89")));
    }

    #[test]
    fn heuristic_sink_kind_unsafe_deserialization_via_method() {
        let c = candidate("c1", "python", "unrelated", "loads", 1);
        assert_eq!(
            heuristic_sink_kind(&c),
            Some(("unsafe_deserialization", "CWE-502"))
        );
    }

    #[test]
    fn heuristic_sink_kind_unsafe_deserialization_via_module() {
        let c = candidate("c1", "python", "pickle", "call_it", 1);
        assert_eq!(
            heuristic_sink_kind(&c),
            Some(("unsafe_deserialization", "CWE-502"))
        );
    }

    #[test]
    fn heuristic_sink_kind_unsafe_via_generic_hint() {
        let c = candidate("c1", "python", "jinja2", "render", 1);
        assert_eq!(heuristic_sink_kind(&c), Some(("unsafe", "CWE-20")));
    }

    #[test]
    fn heuristic_sink_kind_none_when_nothing_matches() {
        let c = candidate("c1", "python", "myapp", "do_thing", 1);
        assert_eq!(heuristic_sink_kind(&c), None);
    }

    // ── supplement_with_heuristics ────────────────────────────────────

    #[test]
    fn supplement_with_heuristics_no_op_when_max_extra_specs_is_zero() {
        let idx = file_index_with(vec![observed("python", "", "os", "system", "")]);
        let (sources, sinks, cwe) = supplement_with_heuristics(
            std::slice::from_ref(&idx),
            &["python".to_string()],
            vec![],
            vec![],
            BTreeMap::new(),
            1,
            1,
            0,
        );
        assert!(sources.is_empty());
        assert!(sinks.is_empty());
        assert!(cwe.is_empty());
    }

    #[test]
    fn supplement_with_heuristics_no_op_when_there_are_no_candidates() {
        let (sources, sinks, _) = supplement_with_heuristics(
            &[],
            &["python".to_string()],
            vec![],
            vec![],
            BTreeMap::new(),
            1,
            1,
            10,
        );
        assert!(sources.is_empty());
        assert!(sinks.is_empty());
    }

    #[test]
    fn supplement_with_heuristics_adds_a_source_when_below_the_minimum() {
        let idx = file_index_with(vec![observed("python", "", "sys", "argv", "")]);
        let (sources, _, cwe) = supplement_with_heuristics(
            std::slice::from_ref(&idx),
            &["python".to_string()],
            vec![],
            vec![],
            BTreeMap::new(),
            1,
            0,
            10,
        );
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].origin, "llm");
        assert!(sources[0].rule_id.ends_with(":h"));
        assert_eq!(cwe[&sources[0].rule_id], vec!["CWE-20".to_string()]);
    }

    #[test]
    fn supplement_with_heuristics_adds_a_sink_after_sources_are_satisfied() {
        let idx = file_index_with(vec![observed("python", "", "os", "system", "")]);
        let (sources, sinks, _) = supplement_with_heuristics(
            std::slice::from_ref(&idx),
            &["python".to_string()],
            vec![],
            vec![],
            BTreeMap::new(),
            0,
            1,
            10,
        );
        assert!(sources.is_empty());
        assert_eq!(sinks.len(), 1);
        assert_eq!(sinks[0].role, "sink");
    }

    #[test]
    fn supplement_with_heuristics_never_duplicates_an_existing_signature() {
        let idx = file_index_with(vec![observed("python", "", "sys", "argv", "")]);
        let existing = MatchSpec {
            rule_id: "existing".to_string(),
            role: "source".to_string(),
            languages: BTreeSet::from(["python".to_string()]),
            module_attr_module: "sys".to_string(),
            module_attr_names: BTreeSet::from(["argv".to_string()]),
            ..Default::default()
        };
        let (sources, _, _) = supplement_with_heuristics(
            std::slice::from_ref(&idx),
            &["python".to_string()],
            vec![existing],
            vec![],
            BTreeMap::new(),
            1,
            0,
            10,
        );
        // Only the pre-existing spec — the heuristic candidate matches
        // the same (role, language, module, method) signature already
        // seen, so no new one is appended.
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].rule_id, "existing");
    }

    #[test]
    fn supplement_with_heuristics_ignores_a_qualified_existing_spec_with_no_module_attr() {
        // A codeql/fsb-style "qualified" spec (package + class + methods,
        // no module_attr) contributes nothing to `seed_seen_sig`'s
        // dedup set — it's simply skipped, not a crash or a false
        // dedup match.
        let idx = file_index_with(vec![observed("python", "", "sys", "argv", "")]);
        let qualified = MatchSpec {
            rule_id: "qualified".to_string(),
            role: "source".to_string(),
            languages: BTreeSet::from(["python".to_string()]),
            package: "sys".to_string(),
            class_name: "Argv".to_string(),
            methods: BTreeSet::from(["argv".to_string()]),
            ..Default::default()
        };
        let (sources, _, _) = supplement_with_heuristics(
            std::slice::from_ref(&idx),
            &["python".to_string()],
            vec![qualified],
            vec![],
            BTreeMap::new(),
            1,
            0,
            10,
        );
        // The qualified spec stays, AND a new heuristic one gets added
        // since it wasn't recognized as a duplicate.
        assert_eq!(sources.len(), 2);
    }

    #[test]
    fn supplement_with_heuristics_skips_a_source_candidate_that_matches_no_heuristic() {
        let idx = file_index_with(vec![
            observed("python", "", "myapp", "do_thing", ""),
            observed("python", "", "sys", "argv", ""),
        ]);
        let (sources, _, _) = supplement_with_heuristics(
            std::slice::from_ref(&idx),
            &["python".to_string()],
            vec![],
            vec![],
            BTreeMap::new(),
            1,
            0,
            10,
        );
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].module_attr_module, "sys");
    }

    #[test]
    fn supplement_with_heuristics_skips_a_sink_candidate_that_matches_no_heuristic() {
        let idx = file_index_with(vec![
            observed("python", "", "myapp", "do_thing", ""),
            observed("python", "", "os", "system", ""),
        ]);
        let (_, sinks, _) = supplement_with_heuristics(
            std::slice::from_ref(&idx),
            &["python".to_string()],
            vec![],
            vec![],
            BTreeMap::new(),
            0,
            1,
            10,
        );
        assert_eq!(sinks.len(), 1);
        assert_eq!(sinks[0].module_attr_module, "os");
    }

    #[test]
    fn supplement_with_heuristics_stops_at_max_extra_specs() {
        let idx = file_index_with(vec![
            observed("python", "", "sys", "argv", ""),
            observed("python", "", "os", "getenv", ""),
        ]);
        let (sources, _, _) = supplement_with_heuristics(
            std::slice::from_ref(&idx),
            &["python".to_string()],
            vec![],
            vec![],
            BTreeMap::new(),
            5,
            0,
            1,
        );
        assert_eq!(sources.len(), 1);
    }
}
