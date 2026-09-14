// Portions of this file are transcribed from vvaharness, Visa's agentic
// SAST harness: Copyright 2026 Visa, Inc., licensed under the Apache
// License, Version 2.0. Reimplemented in Rust and modified; see the module
// documentation below, and NOTICE for the full attribution.
//! Semantic dedup (S7's "7b" pass): one single-shot LLM call deciding
//! whether pairs of findings the deterministic pre-filter didn't resolve
//! share one root cause. Ported from `s7_dedup.py`'s `SYSTEM` /
//! `_graph_context_for_finding` / `_semantic_dedup`.

use bc_llm_client::{ChatRequest, LlmClient, LlmError, Message};
use bc_model::{ContextPackage, Finding};
use bc_repo_analysis::GraphView;

use crate::parse::parse_dedup_output;
use crate::Step7Config;

// A plain (non-`\`-continued) multi-line literal below — every physical
// source newline is a real character in the compiled string, so each
// line's own leading whitespace survives verbatim. `\`-continuation across
// an indented line silently eats that line's leading whitespace (confirmed
// by compiling and diffing against Python), the same class of bug
// `bc_prompts::EXCLUSION_RULES` already avoids by using this exact style.
pub const SYSTEM: &str = "You are collapsing overlapping SAST findings that several
independent reviewers raised against the same repository.

DECISION TEST: two findings are the SAME finding when one engineering fix
closes both. If each needs its own code change, they are separate — even if
the bug class and file are identical.

Collapse (is_duplicate=true) when any of these hold:
- Same defect, different label or line — e.g. \"OS command exec\" at L40 vs
  \"shell injection\" at L42.
- Both trace back to one shared helper / utility; the call sites differ but
  the fix lives in the helper.
- One global control is absent (auth filter, CSRF token, output encoder) and
  each affected route was filed as its own ticket.
- A cause/effect pair on one flow — \"no input validation\" filed alongside the
  resulting \"SQLi\" on the same sink.
- One insecure setting or default surfaces at several read points.
- Same file, lines within ~30 of each other, and the descriptions clearly
  describe one issue from two angles.

Keep separate (is_duplicate=false) when:
- The fixes land in different functions/files and neither fix covers the
  other.
- Same CWE class repeated independently (e.g. two unrelated string-built SQL
  queries) — each one needs its own patch.

Prefer graph-grounded decisions when graph evidence exists:
- Shared source_ref/sink_ref or shared function-hop neighborhoods usually
    indicates one root cause.
- Distinct source/sink refs and disjoint graph neighborhoods suggest
    independent bugs.
- If graph context is missing/sparse, fall back to file+line+description only.

OUTPUT — one line per input index, plain text, this exact grammar:
  index=N is_duplicate=true canonical=M reasoning=\"one sentence\"
  index=N is_duplicate=false canonical=-1 reasoning=\"one sentence\"

Rules: emit a line for EVERY input index, in ascending order. When N is a
duplicate of M, M must be smaller than N (lowest index is always canonical).
No markdown, no fences, no extra commentary.";

fn truncate_chars(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// Compact graph signature used by semantic dedup for root-cause grouping
/// — the same shared, call-graph-first resolution S6/S8 use, so the
/// deduper describes graph context identically to them. Ported from
/// `_graph_context_for_finding`. `ctx: ContextPackage | None` in Python
/// (only ever called with a real `ctx` at both of this port's actual call
/// sites — S5's pre-verify pass and S7's own top-level `run_dedup`) — this
/// port takes `ctx` by value instead: an empty `ContextPackage::default()`
/// hits the exact same `ctx.call_graph.is_empty()` early return Python's
/// `ctx is None` branch does, so nothing is lost by dropping the `Option`.
fn graph_context_for_finding(
    f: &Finding,
    ctx: &ContextPackage,
    view: &GraphView,
) -> serde_json::Value {
    if ctx.call_graph.is_empty() {
        return serde_json::json!({"available": false});
    }
    let cands = bc_repo_analysis::qnodes_at(
        view,
        &f.file,
        f.line_start.max(1),
        f.line_end.max(f.line_start).max(1),
        4,
        false,
    );
    let around = bc_repo_analysis::neighborhood(view, &cands, 5);
    let around_json: serde_json::Map<String, serde_json::Value> = around
        .into_iter()
        .map(|(qn, n)| {
            (
                qn,
                serde_json::json!({"callers": n.callers, "callees": n.callees}),
            )
        })
        .collect();
    serde_json::json!({
        "available": true,
        "source_ref": f.source_ref,
        "sink_ref": f.sink_ref,
        "qnodes": cands,
        "around": around_json,
    })
}

pub fn build_user_prompt(
    verified: &[Finding],
    unresolved: &[usize],
    ctx: &ContextPackage,
    view: &GraphView,
) -> String {
    let payload: Vec<serde_json::Value> = unresolved
        .iter()
        .enumerate()
        .map(|(local, &g)| {
            let f = &verified[g];
            serde_json::json!({
                "index": local,
                "file": f.file,
                "line": f.line_start,
                "category": f.vuln_class.as_str(),
                "title": f.title,
                "description": truncate_chars(&f.description, 500),
                "exploit_scenario": truncate_chars(&f.exploit_scenario, 300),
                "source_ref": f.source_ref,
                "sink_ref": f.sink_ref,
                "graph_context": graph_context_for_finding(f, ctx, view),
            })
        })
        .collect();
    format!(
        "FINDINGS TO DEDUPLICATE:\n{}",
        serde_json::to_string_pretty(&payload).expect("dedup payload serialization is infallible")
    )
}

/// `Ok(merges)` — a possibly-empty list of `(local_idx, local_canonical_idx,
/// reasoning)` — on a successful call, `Err` only when the LLM call itself
/// fails (the response grammar never errors to parse, only yields fewer
/// matches on garbage text). The caller treats `Err` as non-fatal, matching
/// the Python original's broad `except Exception` around this call.
#[allow(clippy::too_many_arguments)]
pub async fn semantic_dedup(
    client: &dyn LlmClient,
    verified: &[Finding],
    unresolved: &[usize],
    config: &Step7Config,
    ctx: &ContextPackage,
    view: &GraphView,
) -> Result<Vec<(usize, usize, String)>, LlmError> {
    let user_prompt = build_user_prompt(verified, unresolved, ctx, view);
    let request = ChatRequest {
        model: config.model.clone(),
        system: Some(SYSTEM.to_string()),
        messages: vec![Message::user_text(&user_prompt)],
        tools: Vec::new(),
        max_tokens: config.max_tokens,
        temperature: config.temperature,
        top_p: config.top_p,
        seed: config.seed,
        thinking_budget: None,
        betas: Vec::new(),
        json_mode: false,
        timeout: config.timeout_secs.map(std::time::Duration::from_secs),
        stream: false,
    };
    let response = bc_llm_agentic::chat_with_retry(
        client,
        &request,
        config.max_transient_retries,
        config.retry_backoff_base,
    )
    .await?;
    Ok(parse_dedup_output(&response.text(), unresolved.len()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_model::VulnClass;

    /// Matches `s7_dedup.py:142-147` — the graph-grounding preference,
    /// previously absent between the "Keep separate" list and "OUTPUT".
    #[test]
    fn system_prompt_prefers_graph_grounded_dedup_decisions() {
        assert!(SYSTEM.contains("Prefer graph-grounded decisions when graph evidence exists:"));
        assert!(SYSTEM.contains("Shared source_ref/sink_ref or shared function-hop neighborhoods"));
        assert!(SYSTEM.contains(
            "If graph context is missing/sparse, fall back to file+line+description only."
        ));
    }

    /// The `\`-continuation indentation-stripping bug (see
    /// `bc_prompts::EXCLUSION_RULES`'s own doc comment) — every bulleted
    /// continuation line must keep its real leading whitespace in the
    /// compiled string, not just the source.
    #[test]
    fn system_prompt_preserves_bullet_indentation() {
        assert!(SYSTEM.contains("\n  \"shell injection\" at L42."));
        assert!(SYSTEM.contains("\n    indicates one root cause."));
    }

    fn finding(file: &str, line: i64) -> Finding {
        Finding {
            provider_origins: Vec::new(),
            chunk_id: "c".to_string(),
            file: file.to_string(),
            line_start: line,
            line_end: line,
            vuln_class: VulnClass::Injection,
            cwe: None,
            title: "t".to_string(),
            impact: String::new(),
            description: "d".to_string(),
            exploit_scenario: String::new(),
            preconditions: Vec::new(),
            recommendation: String::new(),
            code_snippet: "x".to_string(),
            source_ref: None,
            sink_ref: None,
            backfilled_refs: Vec::new(),
            reanchored: Vec::new(),
            compliance_requirements: Vec::new(),
            confidence: 0.9,
            votes: 1,
            duplicates: Vec::new(),
            verdict: None,
            verdict_confidence: None,
            verdict_reason: String::new(),
            cvss_vector: None,
            cvss_score: None,
            cvss_rating: None,
            verifier_reasoning: String::new(),
            vsvs_vector: None,
            vsvs_score: None,
            vsvs_rating: None,
            offensive_priority: None,
            offensive_reason: String::new(),
            related_cwes: Vec::new(),
        }
    }

    #[test]
    fn graph_context_for_finding_with_no_graph_is_unavailable() {
        let ctx = ContextPackage::default();
        let view = GraphView::new(&ctx);
        let out = graph_context_for_finding(&finding("a.py", 10), &ctx, &view);
        assert_eq!(out, serde_json::json!({"available": false}));
    }

    #[test]
    fn graph_context_for_finding_with_a_graph_reports_qnodes_and_neighbors() {
        let mut ctx = ContextPackage::default();
        ctx.call_graph.insert(
            "caller.py::caller_fn".to_string(),
            vec!["a.py::handler".to_string()],
        );
        ctx.call_graph.insert(
            "a.py::handler".to_string(),
            vec!["callee.py::callee_fn".to_string()],
        );
        let view = GraphView::new(&ctx);
        let mut f = finding("a.py", 10);
        f.source_ref = Some("a.py:1".to_string());
        f.sink_ref = Some("a.py:10".to_string());
        let out = graph_context_for_finding(&f, &ctx, &view);
        assert_eq!(out["available"], serde_json::json!(true));
        assert_eq!(out["source_ref"], serde_json::json!("a.py:1"));
        assert_eq!(out["sink_ref"], serde_json::json!("a.py:10"));
        assert_eq!(out["qnodes"], serde_json::json!(["a.py::handler"]));
        assert_eq!(
            out["around"]["a.py::handler"]["callers"],
            serde_json::json!(["caller.py::caller_fn"])
        );
        assert_eq!(
            out["around"]["a.py::handler"]["callees"],
            serde_json::json!(["callee.py::callee_fn"])
        );
    }

    #[test]
    fn graph_context_for_finding_with_a_graph_but_no_candidates_still_reports_available() {
        let mut ctx = ContextPackage::default();
        ctx.call_graph
            .insert("other.py::a".to_string(), vec!["other.py::b".to_string()]);
        let view = GraphView::new(&ctx);
        let out = graph_context_for_finding(&finding("a.py", 10), &ctx, &view);
        assert_eq!(out["available"], serde_json::json!(true));
        assert_eq!(out["qnodes"], serde_json::json!([]));
        assert_eq!(out["around"], serde_json::json!({}));
    }

    #[test]
    fn build_user_prompt_includes_source_sink_and_graph_context_per_finding() {
        let ctx = ContextPackage::default();
        let view = GraphView::new(&ctx);
        let mut f = finding("a.py", 10);
        f.source_ref = Some("a.py:1".to_string());
        f.sink_ref = Some("a.py:10".to_string());
        let verified = vec![f];
        let prompt = build_user_prompt(&verified, &[0], &ctx, &view);
        assert!(prompt.contains("\"source_ref\": \"a.py:1\""));
        assert!(prompt.contains("\"sink_ref\": \"a.py:10\""));
        assert!(prompt.contains("\"graph_context\""));
        assert!(prompt.contains("\"available\": false"));
    }
}
