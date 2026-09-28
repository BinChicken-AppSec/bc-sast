//! S8 — Chain analysis: the final stage. A single LLM call sees ALL
//! verified findings together, identifies multi-step exploit chains,
//! re-ranks each finding's severity by true exploitability + design
//! controls, and checks whether a new finding combines with a known
//! unpatched CVE. Ported from `vvaharness/pipeline/stages/s8_chain.py`.
//!
//! Like S1/S3/S7, this stage has a genuine **internal** degrade policy —
//! three distinct failure points (the LLM call itself, response parsing,
//! and JSON hydration) all fall back to [`hydrate::unranked_report`]
//! rather than propagating: findings keep their CVSS-anchored severity
//! band, but lose the chain-pass exploitability ranking. This is `Stage8`'s
//! own `Output` type directly — `bc_model::FinalReport` — since there is
//! no meaningful distinction between "the degraded report" and "a normal
//! report with no chains found" at the type level (both are valid,
//! renderable `FinalReport`s); `FinalReport.degraded`/`degraded_reason`
//! carry that distinction as data, matching the Python original exactly.
//! `StageOutcome::Degraded` is therefore not used here even though the
//! stage has a real degrade policy — the degrade is already visible in the
//! `Output` value itself.
//!
//! **Deliberately not ported**: the Python original's `_errlog` structured
//! JSONL logging and the "persist the raw chain response next to the
//! errors log before parsing" (HB-009) recoverability feature. Both are
//! process-wide, orchestrator-level concerns (a single error log shared
//! across every stage) with no home in a Tier-4 stage crate yet — nothing
//! else in this port has that plumbing either.

mod degrade;
mod hydrate;
mod prompts;
mod severity;
mod wire;

/// Re-exported for `bc-cli`'s `--remediate-from`, which reconstructs a
/// `RankedFinding` from a `--out-findings-json` export: the export stores
/// bare `Finding`s (no severity band), and reconstructing one any other
/// way would rank a finding differently from the scan that produced it.
pub use severity::final_severity;

use bc_llm_client::{ChatRequest, LlmClient, Message};
use bc_model::{ContextPackage, DroppedFinding, FinalReport, Finding, ScanMetrics};
use bc_pipeline_core::{PipelineStage, StageError, StageOutcome};

pub struct Step8Config {
    pub model: String,
    pub max_tokens: u32,
    /// How many times the single chain-analysis call retries after a
    /// retryable [`bc_llm_client::LlmError`] (429/5xx/connection failure)
    /// before giving up and degrading to an unranked report — see
    /// [`bc_llm_agentic::chat_with_retry`].
    pub max_transient_retries: u32,
    /// Base delay before a transient-retry attempt; the actual delay is
    /// `retry_backoff_base * attempt_number` (linear backoff).
    pub retry_backoff_base: std::time::Duration,
    /// Sampling temperature for this stage's LLM call(s). `None` (the
    /// default) sends no `temperature` at all, leaving the provider's own
    /// default — which for both dialects is `1.0`, i.e. maximally
    /// divergent between two scans of the same repo. Ported from the
    /// Python original's per-role `models.<role>.temperature`
    /// (`backends/llm.py::resolve`), which this port had dropped.
    pub temperature: Option<f64>,
    /// Nucleus-sampling cutoff, forwarded to
    /// [`bc_llm_client::ChatRequest::top_p`]. `None` (the default) sends
    /// none — net-new versus Python, which exposes only `temperature`.
    /// The Anthropic dialect drops it when `temperature` is also set, as
    /// the Messages API rejects the pair.
    pub top_p: Option<f64>,
    /// Deterministic-sampling seed, forwarded to
    /// [`bc_llm_client::ChatRequest::seed`] (OpenAI dialect only — see
    /// that field). `None` (the default) sends no seed. Net-new versus
    /// Python.
    pub seed: Option<u64>,
    /// Reasoning-effort tier for this stage's calls (the Python
    /// original's `models.<role>.effort`, else `--reasoning-effort`),
    /// forwarded to [`bc_llm_client::ChatRequest::reasoning_effort`].
    /// `None` (the default) sends none, leaving the provider's default.
    pub reasoning_effort: Option<bc_llm_client::ReasoningEffort>,
    /// Per-role OpenAI transport pin (Python's
    /// `models.<role>.use_responses_api`), forwarded to
    /// [`bc_llm_client::ChatRequest::openai_api`]. `None` (the default)
    /// keeps the client-wide `--openai-api` choice.
    pub openai_api: Option<bc_llm_client::OpenAiApi>,
    /// Per-call wall-clock deadline in seconds, overriding the shared
    /// gateway client's own 300 s default. Ported from `step8.timeout`
    /// (`_STEP_DEFAULTS`' `3600`, matched by every shipped profile) — a
    /// chain pass over a large finding set routinely exceeds the client
    /// default, which is exactly the comment `default.yaml` puts on the
    /// key ("chain pass on large finding sets can exceed the 600s CLI
    /// default").
    pub timeout_secs: Option<u64>,
}

impl Step8Config {
    pub fn new(model: impl Into<String>) -> Self {
        Step8Config {
            model: model.into(),
            max_tokens: 64_000,
            max_transient_retries: 4,
            retry_backoff_base: std::time::Duration::from_secs(10),
            temperature: None,
            top_p: None,
            seed: None,
            reasoning_effort: None,
            openai_api: None,
            timeout_secs: Some(3600),
        }
    }
}

pub struct Step8Input {
    pub findings: Vec<Finding>,
    pub ctx: ContextPackage,
    pub dropped: Vec<DroppedFinding>,
    pub raw_findings_count: i64,
    pub metrics: Option<ScanMetrics>,
}

/// `bc_json_repair::extract_json`'s contract (see its own doc comment) is
/// "extract the first JSON object or array" — it never yields a bare
/// scalar. Combined with `coerce_list_payload` either producing an object
/// or erroring, `data` reaching the caller is therefore always an object;
/// no further "is this actually a dict" guard is reachable, unlike the
/// Python original's belt-and-suspenders `isinstance(data, dict)` check
/// (itself equally unreachable there, given the Python `extract_json` has
/// the identical "object or array only" contract this was ported from).
///
/// The `bool` is true when the reply was a salvaged top-level chains array
/// with no `ranked_findings` at all: the coverage check in [`run_chain`]
/// must not report that working path as findings shipping unranked.
fn parse_chain_response(raw: &str) -> Result<(serde_json::Value, bool), String> {
    let data = bc_json_repair::extract_json(raw).map_err(|e| e.to_string())?;
    match data {
        serde_json::Value::Array(items) => {
            let obj = hydrate::coerce_list_payload(&items)?;
            let chains_only = obj.get("ranked_findings").is_none();
            Ok((obj, chains_only))
        }
        other => Ok((other, false)),
    }
}

/// The full S8 sequence. Ported from `s8_chain.py::run`.
pub async fn run_chain(
    client: &dyn LlmClient,
    input: Step8Input,
    config: &Step8Config,
) -> FinalReport {
    let Step8Input {
        findings,
        ctx,
        dropped,
        raw_findings_count,
        metrics,
    } = input;

    if findings.is_empty() {
        let empty = degrade::scope_was_empty(metrics.as_ref());
        let (summary, degraded_reason) = if empty {
            (
                degrade::EMPTY_SCOPE_SUMMARY.to_string(),
                degrade::EMPTY_SCOPE_REASON.to_string(),
            )
        } else {
            (
                "No findings survived adversarial verification.".to_string(),
                String::new(),
            )
        };
        return FinalReport {
            provider_ledger: Default::default(),
            repo_root: ctx.repo_root,
            repo_name: None,
            git_sha: None,
            findings: Vec::new(),
            chains: Vec::new(),
            dropped,
            raw_findings_count,
            metrics,
            threat_model: None,
            app_profile: None,
            summary,
            degraded: empty,
            degraded_reason,
            unreachable_files: Vec::new(),
        };
    }

    let user_prompt = prompts::build_prompt(&findings, &ctx);
    let request = ChatRequest {
        model: config.model.clone(),
        system: Some(prompts::SYSTEM.to_string()),
        messages: vec![Message::user_text(&user_prompt)],
        tools: Vec::new(),
        max_tokens: config.max_tokens,
        temperature: config.temperature,
        top_p: config.top_p,
        seed: config.seed,
        reasoning_effort: config.reasoning_effort,
        openai_api: config.openai_api,
        thinking_budget: None,
        betas: Vec::new(),
        json_mode: false,
        timeout: config.timeout_secs.map(std::time::Duration::from_secs),
        stream: false,
        cache_key: Some("s8".to_string()),
        ..ChatRequest::default()
    };

    let response = match bc_llm_agentic::salvage_truncated(
        bc_llm_agentic::chat_with_retry(
            client,
            &request,
            config.max_transient_retries,
            config.retry_backoff_base,
        )
        .await,
        "s8",
    ) {
        Ok(r) => r,
        Err(e) => {
            // The summary ships in the customer report: never interpolate
            // raw provider-error text (it may quote source or secrets).
            let err = degrade::redacted_err(&e);
            tracing::warn!("s8: chain LLM call failed ({err}); emitting unranked report");
            let summary = format!(
                "Chain analysis call failed ({err}). {} verified findings reported unranked.",
                findings.len()
            );
            return hydrate::unranked_report(
                &ctx,
                &findings,
                &dropped,
                raw_findings_count,
                metrics,
                summary,
            );
        }
    };

    let raw = response.text();
    let (data, chains_only_salvage) = match parse_chain_response(&raw) {
        Ok(v) => v,
        Err(e) => {
            let err = degrade::redacted_err(&e);
            let (head, tail) = degrade::redacted_head_tail(&raw);
            tracing::warn!(
                "s8: chain response not parseable ({err}); emitting unranked report. \
                 raw[:500]={head:?} raw[-200:]={tail:?}"
            );
            let summary = format!(
                "Chain analysis failed to parse ({err}). {} verified findings reported unranked.",
                findings.len()
            );
            return hydrate::unranked_report(
                &ctx,
                &findings,
                &dropped,
                raw_findings_count,
                metrics,
                summary,
            );
        }
    };

    match hydrate::hydrate_report(
        &data,
        &ctx,
        &findings,
        &dropped,
        raw_findings_count,
        metrics.clone(),
    ) {
        Ok((report, covered)) => {
            // Coverage, not emptiness: a reply can carry ranked_findings
            // entries that every index filter discards (string index, out
            // of range, repeat) and still leave every finding backfilled at
            // INFO with `degraded` false. A salvaged chains-only array has
            // no ranked_findings by design and stays quiet, or the warning
            // would fire on working replies and desensitize operators.
            if !chains_only_salvage && covered < findings.len() {
                let (head, _) = degrade::redacted_head_tail(&raw);
                // Computed outside the macro: tracing skips evaluating its
                // arguments when no subscriber listens.
                let total = findings.len();
                let missing = total - covered;
                tracing::warn!(
                    "s8: chain pass ranked {covered}/{total} findings; {missing} ship unranked \
                     (severity from CVSS only). raw[:500]={head:?}"
                );
            }
            report
        }
        Err(e) => {
            let err = degrade::redacted_err(&e);
            tracing::warn!("s8: chain hydration failed ({err}); emitting unranked report");
            let summary = format!(
                "Chain analysis hydration failed ({err}). {} verified findings reported unranked.",
                findings.len()
            );
            hydrate::unranked_report(
                &ctx,
                &findings,
                &dropped,
                raw_findings_count,
                metrics,
                summary,
            )
        }
    }
}

pub struct Stage8 {
    client: std::sync::Arc<dyn LlmClient>,
    config: Step8Config,
}

impl Stage8 {
    pub fn new(client: std::sync::Arc<dyn LlmClient>, config: Step8Config) -> Self {
        Stage8 { client, config }
    }
}

impl PipelineStage for Stage8 {
    type Input = Step8Input;
    type Output = FinalReport;
    const NAME: &'static str = "s8-chain";

    async fn run(&self, input: Step8Input) -> Result<StageOutcome<FinalReport>, StageError> {
        let report = run_chain(self.client.as_ref(), input, &self.config).await;
        Ok(StageOutcome::Ok(report))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use bc_llm_client::{ChatResponse, ContentBlock, LlmError, StopReason, Usage};
    use bc_model::{DropReason, Severity, VulnClass};

    struct ScriptedClient {
        reply: String,
    }

    #[async_trait]
    impl LlmClient for ScriptedClient {
        async fn chat(&self, _request: &ChatRequest) -> Result<ChatResponse, LlmError> {
            Ok(ChatResponse {
                content: vec![ContentBlock::Text(self.reply.clone())],
                stop_reason: StopReason::EndTurn,
                usage: Usage::default(),
            })
        }
    }

    struct FailingClient;

    #[async_trait]
    impl LlmClient for FailingClient {
        async fn chat(&self, _request: &ChatRequest) -> Result<ChatResponse, LlmError> {
            Err(LlmError::ConnectionError {
                message: "provider down".to_string(),
            })
        }
    }

    /// Fails with a retryable error `fail_times` times, then succeeds
    /// with a well-formed, empty-chains reply — exercises this crate's
    /// own `chat_with_retry` call site, not just `bc-llm-agentic`'s own
    /// unit tests.
    struct RetryingClient {
        fail_times: std::sync::atomic::AtomicU32,
    }

    impl RetryingClient {
        fn new(fail_times: u32) -> Self {
            RetryingClient {
                fail_times: std::sync::atomic::AtomicU32::new(fail_times),
            }
        }
    }

    #[async_trait]
    impl LlmClient for RetryingClient {
        async fn chat(&self, _request: &ChatRequest) -> Result<ChatResponse, LlmError> {
            if self.fail_times.load(std::sync::atomic::Ordering::SeqCst) > 0 {
                self.fail_times
                    .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                return Err(LlmError::ServerError {
                    status: 503,
                    message: "down".to_string(),
                });
            }
            let payload = serde_json::json!({"summary": "s", "ranked_findings": [], "chains": []});
            Ok(ChatResponse {
                content: vec![ContentBlock::Text(payload.to_string())],
                stop_reason: StopReason::EndTurn,
                usage: Usage::default(),
            })
        }
    }

    fn finding(title: &str) -> Finding {
        Finding {
            provider_origins: Vec::new(),
            chunk_id: "chunk-01".to_string(),
            file: "src/mod.c".to_string(),
            line_start: 10,
            line_end: 11,
            vuln_class: VulnClass::Other,
            cwe: None,
            title: title.to_string(),
            impact: String::new(),
            description: "desc".to_string(),
            exploit_scenario: String::new(),
            preconditions: Vec::new(),
            recommendation: String::new(),
            code_snippet: "x = 1;".to_string(),
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

    fn rated(title: &str, rating: &str) -> Finding {
        let mut f = finding(title);
        f.cvss_rating = Some(rating.to_string());
        f.cvss_vector = Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string());
        f
    }

    fn minimal_ctx() -> ContextPackage {
        ContextPackage {
            seed_taint_paths: Default::default(),
            seed_taint_evidence: Default::default(),
            def_spans: Default::default(),
            repo_root: "/repo".to_string(),
            language: "c".to_string(),
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

    fn input(findings: Vec<Finding>) -> Step8Input {
        Step8Input {
            findings,
            ctx: minimal_ctx(),
            dropped: Vec::new(),
            raw_findings_count: 0,
            metrics: None,
        }
    }

    #[tokio::test]
    async fn no_findings_returns_empty_report_without_calling_the_llm() {
        let dropped = vec![DroppedFinding {
            file: "a.c".to_string(),
            line: 1,
            vuln_class: VulnClass::Other,
            title: "t".to_string(),
            chunk_id: "c".to_string(),
            reason: DropReason::FalsePositive,
            detail: String::new(),
            canonical_idx: None,
            provider_origins: Vec::new(),
            verification: None,
        }];
        let mut inp = input(Vec::new());
        inp.dropped = dropped.clone();
        inp.raw_findings_count = 3;
        let report = run_chain(&FailingClient, inp, &Step8Config::new("m")).await;
        assert!(report.findings.is_empty());
        assert!(report.chains.is_empty());
        assert_eq!(report.dropped, dropped);
        assert_eq!(report.raw_findings_count, 3);
        assert!(report.summary.contains("No findings survived"));
        assert!(!report.degraded);
    }

    #[tokio::test]
    async fn ranks_findings_and_builds_a_chain() {
        let findings = vec![finding("A"), finding("B"), finding("C")];
        let payload = serde_json::json!({
            "summary": "Two bugs chain into RCE.",
            "ranked_findings": [
                {"index": 0, "severity": "high", "exploitability_notes": "n0"},
                {"index": 1, "severity": "medium", "exploitability_notes": "n1"},
                {"index": 2, "severity": "low", "exploitability_notes": "n2"},
            ],
            "chains": [
                {"title": "A->B", "steps": [0, 1], "severity": "critical", "blocked_by_controls": ["sandbox"], "narrative": "boom"},
            ],
        });
        let client = ScriptedClient {
            reply: payload.to_string(),
        };
        let report = run_chain(&client, input(findings), &Step8Config::new("m")).await;

        assert_eq!(report.summary, "Two bugs chain into RCE.");
        assert_eq!(report.findings.len(), 3);
        let sevs: Vec<Severity> = report.findings.iter().map(|rf| rf.severity).collect();
        assert_eq!(sevs, vec![Severity::High, Severity::Medium, Severity::Low]);
        assert_eq!(report.findings[0].finding.title, "A");
        assert_eq!(report.findings[0].exploitability_notes, "n0");

        assert_eq!(report.chains.len(), 1);
        assert_eq!(report.chains[0].severity, Severity::Critical);
        assert_eq!(
            report.chains[0].blocked_by_controls,
            vec!["sandbox".to_string()]
        );
        let titles: std::collections::HashSet<&str> = report.chains[0]
            .steps
            .iter()
            .map(|&i| report.findings[i as usize].finding.title.as_str())
            .collect();
        assert_eq!(titles, ["A", "B"].into_iter().collect());
    }

    #[tokio::test]
    async fn uncovered_findings_default_to_info() {
        let findings = vec![finding("A"), finding("B")];
        let payload = serde_json::json!({
            "summary": "s",
            "ranked_findings": [{"index": 0, "severity": "high", "exploitability_notes": "n0"}],
            "chains": [],
        });
        let client = ScriptedClient {
            reply: payload.to_string(),
        };
        let report = run_chain(&client, input(findings), &Step8Config::new("m")).await;
        let by_title: std::collections::HashMap<&str, &bc_model::RankedFinding> = report
            .findings
            .iter()
            .map(|rf| (rf.finding.title.as_str(), rf))
            .collect();
        assert_eq!(by_title["A"].severity, Severity::High);
        assert_eq!(by_title["B"].severity, Severity::Info);
        assert_eq!(
            by_title["B"].exploitability_notes,
            "(not ranked by chaining pass)"
        );
    }

    #[tokio::test]
    async fn out_of_range_step_is_filtered_and_narrative_annotated() {
        let findings = vec![finding("A"), finding("B")];
        let payload = serde_json::json!({
            "summary": "s",
            "ranked_findings": [
                {"index": 0, "severity": "high", "exploitability_notes": "n0"},
                {"index": 1, "severity": "high", "exploitability_notes": "n1"},
            ],
            "chains": [{"title": "T", "steps": [0, 99, 1], "severity": "high", "narrative": "base"}],
        });
        let client = ScriptedClient {
            reply: payload.to_string(),
        };
        let report = run_chain(&client, input(findings), &Step8Config::new("m")).await;
        assert_eq!(report.chains.len(), 1);
        let chain = &report.chains[0];
        assert_eq!(chain.steps.len(), 2);
        for &s in &chain.steps {
            assert!((0..report.findings.len() as i64).contains(&s));
        }
        assert!(chain.narrative.contains("base"));
        assert!(chain.narrative.contains("[99]"));
        assert!(chain.narrative.contains("not in the verified"));
    }

    #[tokio::test]
    async fn more_than_20_out_of_range_steps_are_capped_with_a_more_suffix() {
        let findings = vec![finding("A"), finding("B")];
        let mut steps: Vec<i64> = vec![0, 1];
        steps.extend(100..125); // 25 out-of-range indices
        let payload = serde_json::json!({
            "summary": "s",
            "ranked_findings": [
                {"index": 0, "severity": "high", "exploitability_notes": "n0"},
                {"index": 1, "severity": "high", "exploitability_notes": "n1"},
            ],
            "chains": [{"title": "T", "steps": steps, "severity": "high", "narrative": "base"}],
        });
        let client = ScriptedClient {
            reply: payload.to_string(),
        };
        let report = run_chain(&client, input(findings), &Step8Config::new("m")).await;
        assert_eq!(report.chains.len(), 1);
        assert!(report.chains[0].narrative.contains("(+5 more)"));
    }

    #[tokio::test]
    async fn chain_with_fewer_than_two_valid_steps_is_dropped() {
        let findings = vec![finding("A"), finding("B")];
        let payload = serde_json::json!({
            "summary": "s",
            "ranked_findings": [
                {"index": 0, "severity": "high", "exploitability_notes": "n0"},
                {"index": 1, "severity": "high", "exploitability_notes": "n1"},
            ],
            "chains": [{"title": "lonely", "steps": [0, 50, 51], "severity": "high", "narrative": "x"}],
        });
        let client = ScriptedClient {
            reply: payload.to_string(),
        };
        let report = run_chain(&client, input(findings), &Step8Config::new("m")).await;
        assert!(report.chains.is_empty());
    }

    #[tokio::test]
    async fn non_int_steps_are_filtered() {
        let findings = vec![finding("A"), finding("B")];
        let payload = serde_json::json!({
            "summary": "s",
            "ranked_findings": [
                {"index": 0, "severity": "high", "exploitability_notes": "n0"},
                {"index": 1, "severity": "high", "exploitability_notes": "n1"},
            ],
            "chains": [{"title": "mixed", "steps": ["0", true, 0, 1], "severity": "high", "narrative": "n"}],
        });
        let client = ScriptedClient {
            reply: payload.to_string(),
        };
        let report = run_chain(&client, input(findings), &Step8Config::new("m")).await;
        assert_eq!(report.chains.len(), 1);
        assert_eq!(report.chains[0].steps.len(), 2);
        assert!(!report.chains[0].narrative.contains("not in the verified"));
        assert_eq!(report.chains[0].narrative, "n");
    }

    #[tokio::test]
    async fn off_schema_ranked_findings_entries_are_skipped() {
        let findings = vec![finding("A"), finding("B")];
        let payload = serde_json::json!({
            "summary": "s",
            "ranked_findings": [
                "not-a-dict",
                {"severity": "critical"},
                {"index": "1"},
                {"index": true},
                {"index": -1},
                {"index": 99},
                {"index": 0, "severity": "high"},
                {"index": 0, "severity": "low"},
            ],
            "chains": [],
        });
        let client = ScriptedClient {
            reply: payload.to_string(),
        };
        let report = run_chain(&client, input(findings), &Step8Config::new("m")).await;
        let by_title: std::collections::HashMap<&str, &bc_model::RankedFinding> = report
            .findings
            .iter()
            .map(|rf| (rf.finding.title.as_str(), rf))
            .collect();
        assert_eq!(by_title["A"].severity, Severity::High);
        assert_eq!(by_title["B"].severity, Severity::Info);
    }

    #[tokio::test]
    async fn null_lists_do_not_crash() {
        let findings = vec![finding("A")];
        let payload = serde_json::json!({"summary": "s", "ranked_findings": null, "chains": null});
        let client = ScriptedClient {
            reply: payload.to_string(),
        };
        let report = run_chain(&client, input(findings), &Step8Config::new("m")).await;
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].severity, Severity::Info);
        assert!(report.chains.is_empty());
    }

    #[tokio::test]
    async fn dropped_duplicate_canonical_idx_is_remapped_after_sort() {
        let findings = vec![finding("LOW"), finding("HIGH")];
        let payload = serde_json::json!({
            "summary": "s",
            "ranked_findings": [
                {"index": 0, "severity": "low", "exploitability_notes": ""},
                {"index": 1, "severity": "high", "exploitability_notes": ""},
            ],
            "chains": [],
        });
        let client = ScriptedClient {
            reply: payload.to_string(),
        };
        let mut inp = input(findings);
        inp.dropped = vec![DroppedFinding {
            file: "d.c".to_string(),
            line: 5,
            vuln_class: VulnClass::Other,
            title: "dup".to_string(),
            chunk_id: "c".to_string(),
            reason: DropReason::Duplicate,
            detail: String::new(),
            canonical_idx: Some(1),
            provider_origins: Vec::new(),
            verification: None,
        }];
        let report = run_chain(&client, inp, &Step8Config::new("m")).await;
        assert_eq!(report.findings[0].finding.title, "HIGH");
        assert_eq!(report.dropped[0].canonical_idx, Some(0));
    }

    #[tokio::test]
    async fn dropped_canonical_idx_not_remapped_when_hydration_fails() {
        let findings = vec![finding("LOW"), finding("HIGH")];
        let payload = serde_json::json!({
            "summary": "s",
            "ranked_findings": [
                {"index": 0, "severity": "low", "exploitability_notes": ""},
                {"index": 1, "severity": "high", "exploitability_notes": ""},
            ],
            "chains": [{"title": "boom", "steps": [0, 1], "severity": "high", "blocked_by_controls": [{"not": "a string"}], "narrative": "n"}],
        });
        let client = ScriptedClient {
            reply: payload.to_string(),
        };
        let mut inp = input(findings);
        inp.dropped = vec![DroppedFinding {
            file: "d.c".to_string(),
            line: 5,
            vuln_class: VulnClass::Other,
            title: "dup".to_string(),
            chunk_id: "c".to_string(),
            reason: DropReason::Duplicate,
            detail: String::new(),
            canonical_idx: Some(1),
            provider_origins: Vec::new(),
            verification: None,
        }];
        let report = run_chain(&client, inp, &Step8Config::new("m")).await;
        assert!(report.summary.contains("hydration failed"));
        assert_eq!(
            report
                .findings
                .iter()
                .map(|rf| rf.finding.title.as_str())
                .collect::<Vec<_>>(),
            vec!["LOW", "HIGH"]
        );
        assert_eq!(report.dropped[0].canonical_idx, Some(1));
    }

    #[tokio::test]
    async fn llm_call_failure_returns_unranked_report() {
        let findings = vec![finding("A"), finding("B")];
        let mut inp = input(findings);
        inp.raw_findings_count = 2;
        let mut cfg = Step8Config::new("m");
        cfg.retry_backoff_base = std::time::Duration::ZERO;
        let report = run_chain(&FailingClient, inp, &cfg).await;
        assert_eq!(report.findings.len(), 2);
        assert!(report
            .findings
            .iter()
            .all(|rf| rf.severity == Severity::Info));
        assert!(report.chains.is_empty());
        assert!(report.summary.contains("Chain analysis call failed"));
        assert!(report.summary.contains("provider down"));
        assert!(report.degraded);
    }

    #[tokio::test]
    async fn zero_files_in_scope_is_a_degraded_empty_report_not_a_clean_one() {
        let mut inp = input(Vec::new());
        inp.metrics = Some(ScanMetrics::default());
        let report = run_chain(&FailingClient, inp, &Step8Config::new("m")).await;
        assert!(report.summary.starts_with("0 files analyzed"));
        assert!(report.degraded);
        assert_eq!(report.degraded_reason, degrade::EMPTY_SCOPE_REASON);

        let mut inp = input(Vec::new());
        inp.metrics = Some(ScanMetrics {
            total_files_in_scope: 4,
            ..ScanMetrics::default()
        });
        let report = run_chain(&FailingClient, inp, &Step8Config::new("m")).await;
        assert!(report.summary.contains("No findings survived"));
        assert!(!report.degraded);
        assert!(report.degraded_reason.is_empty());
    }

    /// Provider error text that quotes a credential: the summary ships in
    /// the customer report so it must come out redacted.
    struct LeakyFailingClient;

    #[async_trait]
    impl LlmClient for LeakyFailingClient {
        async fn chat(&self, _request: &ChatRequest) -> Result<ChatResponse, LlmError> {
            Err(LlmError::InvalidRequest {
                message: format!("bad request near AKIA{}", "ABCDEFGHIJKLMNOP"),
            })
        }
    }

    #[tokio::test]
    async fn provider_error_text_is_redacted_in_the_delivered_summary() {
        let report = run_chain(
            &LeakyFailingClient,
            input(vec![finding("A")]),
            &Step8Config::new("m"),
        )
        .await;
        assert!(report.degraded);
        assert!(report.summary.contains("Chain analysis call failed"));
        assert!(!report.summary.contains("AKIAABCDEFGHIJKLMNOP"));
    }

    #[tokio::test]
    async fn llm_call_retries_a_transient_failure_then_succeeds() {
        let client = RetryingClient::new(2);
        let mut cfg = Step8Config::new("m");
        cfg.retry_backoff_base = std::time::Duration::ZERO;
        let report = run_chain(&client, input(vec![finding("A")]), &cfg).await;
        assert!(!report.degraded);
    }

    #[tokio::test]
    async fn unparseable_response_returns_unranked_report() {
        let client = ScriptedClient {
            reply: "this is not json at all {{{".to_string(),
        };
        let report = run_chain(&client, input(vec![finding("A")]), &Step8Config::new("m")).await;
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].severity, Severity::Info);
        assert!(report.summary.contains("failed to parse"));
    }

    #[tokio::test]
    async fn non_object_json_returns_unranked_report() {
        let client = ScriptedClient {
            reply: "[1, 2, 3]".to_string(),
        };
        let report = run_chain(&client, input(vec![finding("A")]), &Step8Config::new("m")).await;
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].severity, Severity::Info);
        assert!(report.summary.contains("failed to parse"));
        assert!(report.degraded);
    }

    #[tokio::test]
    async fn unranked_fallback_is_severity_sorted_and_remaps_canonical_idx() {
        let findings = vec![rated("LOW", "Low"), rated("HIGH", "High")];
        let client = ScriptedClient {
            reply: "not json {{{".to_string(),
        };
        let mut inp = input(findings);
        inp.dropped = vec![DroppedFinding {
            file: "d.c".to_string(),
            line: 5,
            vuln_class: VulnClass::Other,
            title: "dup".to_string(),
            chunk_id: "c".to_string(),
            reason: DropReason::Duplicate,
            detail: String::new(),
            canonical_idx: Some(0),
            provider_origins: Vec::new(),
            verification: None,
        }];
        let report = run_chain(&client, inp, &Step8Config::new("m")).await;
        assert!(report.degraded);
        assert_eq!(
            report
                .findings
                .iter()
                .map(|rf| rf.finding.title.as_str())
                .collect::<Vec<_>>(),
            vec!["HIGH", "LOW"]
        );
        assert_eq!(report.dropped[0].canonical_idx, Some(1));
    }

    #[tokio::test]
    async fn nonstring_summary_does_not_crash_and_coerces_empty() {
        let payload = serde_json::json!({
            "summary": {"unexpected": "object"},
            "ranked_findings": [{"index": 0, "severity": "high", "exploitability_notes": ""}],
            "chains": [],
        });
        let client = ScriptedClient {
            reply: payload.to_string(),
        };
        let report = run_chain(&client, input(vec![finding("A")]), &Step8Config::new("m")).await;
        assert!(!report.degraded);
        assert_eq!(report.summary, "");
        assert_eq!(report.findings.len(), 1);
    }

    #[tokio::test]
    async fn coerces_a_top_level_chain_array() {
        let findings = vec![finding("A"), finding("B")];
        let payload = serde_json::json!([{"title": "boom", "steps": [0, 1], "severity": "high", "narrative": "n"}]);
        let client = ScriptedClient {
            reply: payload.to_string(),
        };
        let report = run_chain(&client, input(findings), &Step8Config::new("m")).await;
        assert!(!report.degraded);
        assert_eq!(report.chains.len(), 1);
        assert_eq!(report.chains[0].title, "boom");
    }

    #[tokio::test]
    async fn coerces_a_top_level_ranked_findings_array() {
        let findings = vec![finding("A"), finding("B")];
        let payload =
            serde_json::json!([{"index": 0, "severity": "high", "exploitability_notes": "n0"}]);
        let client = ScriptedClient {
            reply: payload.to_string(),
        };
        let report = run_chain(&client, input(findings), &Step8Config::new("m")).await;
        assert!(!report.degraded);
        let by_title: std::collections::HashMap<&str, &bc_model::RankedFinding> = report
            .findings
            .iter()
            .map(|rf| (rf.finding.title.as_str(), rf))
            .collect();
        assert_eq!(by_title["A"].severity, Severity::High);
    }

    #[tokio::test]
    async fn a_chain_with_a_non_object_entry_is_skipped() {
        let findings = vec![finding("A"), finding("B")];
        let payload = serde_json::json!({
            "summary": "s",
            "ranked_findings": [
                {"index": 0, "severity": "high", "exploitability_notes": "n0"},
                {"index": 1, "severity": "high", "exploitability_notes": "n1"},
            ],
            "chains": ["not-a-dict", {"title": "real", "steps": [0, 1], "severity": "high", "narrative": "n"}],
        });
        let client = ScriptedClient {
            reply: payload.to_string(),
        };
        let report = run_chain(&client, input(findings), &Step8Config::new("m")).await;
        assert_eq!(report.chains.len(), 1);
        assert_eq!(report.chains[0].title, "real");
    }

    #[tokio::test]
    async fn a_duplicate_whose_canonical_idx_has_no_mapping_is_left_unchanged() {
        let findings = vec![finding("A")];
        let payload = serde_json::json!({"summary": "s", "ranked_findings": [{"index": 0, "severity": "high", "exploitability_notes": ""}], "chains": []});
        let client = ScriptedClient {
            reply: payload.to_string(),
        };
        let mut inp = input(findings);
        inp.dropped = vec![DroppedFinding {
            file: "d.c".to_string(),
            line: 5,
            vuln_class: VulnClass::Other,
            title: "dup".to_string(),
            chunk_id: "c".to_string(),
            reason: DropReason::Duplicate,
            detail: String::new(),
            canonical_idx: Some(99),
            provider_origins: Vec::new(),
            verification: None,
        }];
        let report = run_chain(&client, inp, &Step8Config::new("m")).await;
        assert_eq!(report.dropped[0].canonical_idx, Some(99));
    }

    #[tokio::test]
    async fn a_non_duplicate_dropped_finding_passes_through_the_remap_unchanged() {
        let findings = vec![finding("A")];
        let payload = serde_json::json!({"summary": "s", "ranked_findings": [{"index": 0, "severity": "high", "exploitability_notes": ""}], "chains": []});
        let client = ScriptedClient {
            reply: payload.to_string(),
        };
        let mut inp = input(findings);
        inp.dropped = vec![DroppedFinding {
            file: "d.c".to_string(),
            line: 5,
            vuln_class: VulnClass::Other,
            title: "fp".to_string(),
            chunk_id: "c".to_string(),
            reason: DropReason::FalsePositive,
            detail: "safe".to_string(),
            canonical_idx: None,
            provider_origins: Vec::new(),
            verification: None,
        }];
        let report = run_chain(&client, inp, &Step8Config::new("m")).await;
        assert_eq!(report.dropped[0].reason, DropReason::FalsePositive);
        assert_eq!(report.dropped[0].canonical_idx, None);
    }

    #[tokio::test]
    async fn a_duplicate_with_no_canonical_idx_at_all_passes_through_unchanged() {
        let findings = vec![finding("A")];
        let payload = serde_json::json!({"summary": "s", "ranked_findings": [{"index": 0, "severity": "high", "exploitability_notes": ""}], "chains": []});
        let client = ScriptedClient {
            reply: payload.to_string(),
        };
        let mut inp = input(findings);
        inp.dropped = vec![DroppedFinding {
            file: "d.c".to_string(),
            line: 5,
            vuln_class: VulnClass::Other,
            title: "dup".to_string(),
            chunk_id: "c".to_string(),
            reason: DropReason::Duplicate,
            detail: String::new(),
            canonical_idx: None,
            provider_origins: Vec::new(),
            verification: None,
        }];
        let report = run_chain(&client, inp, &Step8Config::new("m")).await;
        assert_eq!(report.dropped[0].canonical_idx, None);
    }

    #[tokio::test]
    async fn healthy_no_chains_is_not_degraded() {
        let payload = serde_json::json!({"summary": "s", "ranked_findings": [], "chains": []});
        let client = ScriptedClient {
            reply: payload.to_string(),
        };
        let report = run_chain(&client, input(vec![finding("A")]), &Step8Config::new("m")).await;
        assert!(!report.degraded);
    }

    #[tokio::test]
    async fn stage8_run_always_returns_ok_even_when_the_report_is_internally_degraded() {
        let mut cfg = Step8Config::new("m");
        cfg.retry_backoff_base = std::time::Duration::ZERO;
        let stage = Stage8::new(std::sync::Arc::new(FailingClient), cfg);
        let outcome = stage.run(input(vec![finding("A")])).await.unwrap();
        assert!(!outcome.is_degraded());
        assert!(outcome.into_value().degraded);
    }
}
