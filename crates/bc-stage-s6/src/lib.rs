//! S6 — Adversarial verification: for every finding that survived S4/S5, a
//! fresh agentic session (Read/Glob/Grep, jailed to the repo) tries to
//! PROVE THE FINDING WRONG, emitting a TRUE_POSITIVE/FALSE_POSITIVE verdict
//! plus a CVSS 3.1 vector. Only TRUE_POSITIVE above `min_confidence`
//! continues; everything else becomes a `DroppedFinding` for the audit
//! trail. Ported from `vvaharness/pipeline/stages/s6_verify.py`.
//!
//! Concurrency mirrors the Python original's `ThreadPoolExecutor` pool —
//! `config.parallel` sessions in flight at once via a `tokio::sync::
//! Semaphore`, drained as they complete via `tokio::task::JoinSet`
//! (matching `as_completed`'s "whichever finishes first" order, not spawn
//! order), so the guardrail-abort gate can still fire the moment it trips.
//!
//! **The OUTPUT order, though, is input order, not completion order** —
//! see [`run_verify`]. The Python original emits completion order, and
//! that turned out to feed a real nondeterminism: S7 keeps the
//! lowest-index member of a duplicate cluster as canonical, so network
//! timing decided which duplicate survived and therefore what line,
//! snippet, CVSS vector and SARIF fingerprint the run reported. Fixed
//! here rather than reproduced.
//!
//! **Guardrail abort is the one genuinely fatal path in this stage**: a
//! cumulative `max(3, parallel)` guardrail-blocked sessions with *zero*
//! successes so far aborts the whole run as `Err(StageError)` — mirroring
//! the Python original's `RuntimeError` raised out of `run()` in that same
//! case (as opposed to every other per-finding outcome, which is recorded
//! as data in `VerifyOutput.dropped` and never fails the stage). See
//! `bc-llm-client::LlmError::GuardrailBlocked` for why this is a distinct
//! error variant rather than a generic one.
//!
//! **Deliberately not ported**: the Python original's `cli.aborted()` check
//! at the top of `_verify_one`, which lets a prior Ctrl-C (a process-global
//! flag) make any *new* verify call fail immediately. That's a
//! cross-stage, process-lifetime concern with no clean per-stage-crate
//! home yet (it belongs to whatever Tier-5 `bc-cli`'s eventual Ctrl-C
//! handling looks like, e.g. a `tokio_util::sync::CancellationToken`
//! threaded through every stage) — not a shortcut, since no other stage
//! crate in this port has that plumbing either yet.
//!
//! **Deliberately not ported**: `max_budget_usd`. In the Python original
//! this was never a harness feature, it was a passthrough to Anthropic's
//! own tooling. `backends/claude_cli.py:874` appends `--max-budget-usd`
//! to the `claude` subprocess, and only when the installed binary
//! advertises the flag; `backends/agent_sdk.py:275` sets it on a Claude
//! Agent SDK session. Both of those backends do the enforcing, and
//! neither is ported here. The two backends this port's gateway-mediated
//! dialects are analogous to ignore it outright: `sdk.py` carries the
//! literal comment `max_budget_usd: float | None = None,   # accepted for
//! parity; unused`, and `oai.py` never reads it. Python computes a dollar
//! figure nowhere and ships no price table. So the key is not shipped as
//! a default here either; `bc_cli::config_overrides` warns when a loaded
//! config sets it, and `--max-tokens`/`--max-scan-seconds` are the caps
//! this port actually enforces.

mod parse;
mod prompts;
mod wire;

use std::sync::Arc;

use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use bc_llm_agentic::{run_agentic, AgenticConfig, AgenticOutcome};
use bc_llm_client::{LlmClient, LlmError, ToolExecutor};
use bc_model::{ContextPackage, DropReason, DroppedFinding, Finding, Verdict};
use bc_pipeline_core::{PipelineStage, StageError, StageOutcome};

pub struct Step6Config {
    pub model: String,
    pub parallel: usize,
    pub min_confidence: i64,
    pub max_turns: u32,
    pub allowed_tools: Vec<String>,
    /// How many times a single agentic turn retries after a retryable
    /// [`bc_llm_client::LlmError`] before giving up — forwarded to
    /// [`AgenticConfig::max_transient_retries`], same as every other
    /// agentic stage's own knob of the same name.
    pub max_transient_retries: u32,
    /// How many times a single agentic turn retries after a context-
    /// overflow by evicting oldest tool results — forwarded to
    /// [`AgenticConfig::max_context_shrinks`].
    pub max_context_shrinks: u32,
    /// Base linear-backoff delay before a transient-retry attempt — a
    /// Rust-only test/production timing knob with no Python equivalent
    /// (no YAML exposure via `--config`, same precedent as
    /// `bc-stage-s1`'s own field of the same name).
    pub retry_backoff_base: std::time::Duration,
    /// Sampling temperature for every verification session, forwarded to
    /// [`AgenticConfig::temperature`]. `None` (the default) sends no
    /// `temperature` at all, leaving the provider's own default — which
    /// for both dialects is `1.0`, i.e. maximally divergent between two
    /// scans of the same repo. Ported from the Python original's per-role
    /// `models.<role>.temperature` (`backends/llm.py::resolve`), which
    /// this port had dropped.
    pub temperature: Option<f64>,
    /// Nucleus-sampling cutoff, forwarded to
    /// [`bc_llm_client::ChatRequest::top_p`]. `None` (the default) sends
    /// none — net-new versus Python, which exposes only `temperature`.
    /// The Anthropic dialect drops it when `temperature` is also set, as
    /// the Messages API rejects the pair.
    pub top_p: Option<f64>,
    /// Deterministic-sampling seed, forwarded to [`AgenticConfig::seed`]
    /// (OpenAI dialect only). `None` (the default) sends no seed.
    pub seed: Option<u64>,
    /// Per-turn wall-clock deadline in seconds, forwarded to
    /// [`AgenticConfig::timeout_secs`]. `None` (the default) keeps the
    /// shared gateway client's own 300 s default — matching Python's
    /// `_STEP_DEFAULTS`, which has no `step6_verify.timeout` key.
    pub timeout_secs: Option<u64>,
    /// Consulted once per finding, on that finding's own task, right
    /// before its verification session starts — see
    /// [`bc_pipeline_core::BudgetGate`], and `Step4Config::budget_gate`
    /// for why the check belongs inside the task and not in the spawn
    /// loop. `None` (the default) is an unbounded stage.
    ///
    /// A finding whose session never runs is reported as a
    /// [`DropReason::Unconfirmed`] drop, never as a true positive and
    /// never silently: an unverified finding that quietly vanished — or
    /// worse, quietly counted as confirmed — would make the report claim
    /// something the scan never established.
    pub budget_gate: Option<bc_pipeline_core::BudgetGateRef>,
}

impl Step6Config {
    /// `min_confidence: 6` here (vs. `7` in `bc_config::step_defaults()`)
    /// is deliberate, not drift — this mirrors `config/profiles/
    /// default.yaml`'s own override of `_STEP_DEFAULTS`' shipped `7`,
    /// since that's the profile Python actually loads when no `--config`
    /// is passed at all. See `bc_config::step_defaults`'s own module doc
    /// comment for the full explanation (verified against the real
    /// Python source, not assumed).
    pub fn new(model: impl Into<String>) -> Self {
        Step6Config {
            model: model.into(),
            parallel: 5,
            min_confidence: 6,
            max_turns: 30,
            allowed_tools: vec!["Read".to_string(), "Glob".to_string(), "Grep".to_string()],
            // 6, not the agentic default of 4: S6 makes by far the most
            // calls of any stage (1,881 in one 117-file scan) at
            // `parallel` concurrency, so it is the stage that meets a
            // provider's rate limit, and the one where giving up costs a
            // real finding its verdict.
            max_transient_retries: 6,
            max_context_shrinks: 16,
            retry_backoff_base: std::time::Duration::from_secs(10),
            temperature: None,
            top_p: None,
            seed: None,
            timeout_secs: None,
            budget_gate: None,
        }
    }
}

pub struct Step6Input {
    pub findings: Vec<Finding>,
    pub ctx: ContextPackage,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct VerifyOutput {
    pub verified: Vec<Finding>,
    pub dropped: Vec<DroppedFinding>,
    /// `Some(reason)` when [`Step6Config::budget_gate`] tripped part-way
    /// through, naming the budget and how many findings went unverified.
    pub budget_stop: Option<String>,
}

fn truncate_chars(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

fn drop_finding(f: &Finding, reason: DropReason, detail: impl Into<String>) -> DroppedFinding {
    DroppedFinding {
        file: f.file.clone(),
        line: f.line_start,
        vuln_class: f.vuln_class,
        title: f.title.clone(),
        chunk_id: f.chunk_id.clone(),
        reason,
        detail: detail.into(),
        canonical_idx: None,
        provider_origins: f.provider_origins.clone(),
        verification: None,
    }
}

fn finalize_finding(mut f: Finding, parsed: parse::ParsedVerdict) -> Finding {
    let score = bc_cvss::score(parsed.cvss.as_deref());
    f.verdict = Some(parsed.verdict);
    f.verdict_confidence = Some(parsed.confidence);
    f.verdict_reason = parsed.reason;
    f.cvss_vector = parsed.cvss;
    f.cvss_score = score;
    f.cvss_rating = score.map(|s| bc_cvss::rating(Some(s)).to_string());
    f.verifier_reasoning = parsed.reasoning;
    f
}

/// Whether this reply is a confirmed true positive — i.e. whether
/// [`classify`] will route it into `verified`. Factored out of `classify`
/// so [`run_verify`]'s guardrail-abort gate ("N cumulative blocks with
/// ZERO successes") can ask the same question while draining results,
/// before any of them have actually been classified; the two must not
/// drift, or the gate would trip on a run that was in fact succeeding.
fn is_confirmed(parsed: &parse::ParsedVerdict, min_confidence: i64) -> bool {
    parsed.verdict == Verdict::TruePositive && parsed.confidence >= min_confidence
}

/// Classify one verifier reply against `min_confidence`, appending to
/// `verified`/`dropped` — the four-way split ported from `run()`'s
/// if/elif/elif/else chain: confirmed TP, low-confidence TP (UNCONFIRMED),
/// a genuinely unparseable reply (VERIFY_ERROR, never laundered into FP),
/// then a real FALSE_POSITIVE.
fn classify(
    f: Finding,
    parsed: parse::ParsedVerdict,
    min_confidence: i64,
    verified: &mut Vec<Finding>,
    dropped: &mut Vec<DroppedFinding>,
) {
    let is_unparseable = parsed.reason == "verifier output unparseable" && parsed.confidence == 0;
    if is_confirmed(&parsed, min_confidence) {
        verified.push(finalize_finding(f, parsed));
    } else if parsed.verdict == Verdict::TruePositive {
        let detail = format!(
            "verifier confidence {}/10 below gate {min_confidence}",
            parsed.confidence
        );
        let assessed = finalize_finding(f, parsed);
        let mut record = drop_finding(&assessed, DropReason::Unconfirmed, detail);
        record.verification = bc_model::VerificationEvidence::from_finding(&assessed);
        dropped.push(record);
    } else if is_unparseable {
        let reason = parsed.reason.clone();
        dropped.push(drop_finding(&f, DropReason::VerifyError, reason));
    } else {
        let reason = parsed.reason.clone();
        let assessed = finalize_finding(f, parsed);
        let mut record = drop_finding(&assessed, DropReason::FalsePositive, reason);
        record.verification = bc_model::VerificationEvidence::from_finding(&assessed);
        dropped.push(record);
    }
}

/// One session's outcome, held un-classified until every session has
/// finished so results can be replayed in INPUT order — see
/// [`run_verify`]. The error variants carry their already-truncated detail
/// string so the replay pass needs nothing from `LlmError` itself.
enum SessionResult {
    Verdict(parse::ParsedVerdict),
    Guardrail(String),
    Failed(String),
    /// The budget gate tripped before this finding's session started, so
    /// no verifier ever looked at it. Carries the gate's reason.
    BudgetSkipped(String),
}

/// What one spawned task did: ran a verification session (with whatever
/// the model or transport returned), or declined to start one because
/// [`Step6Config::budget_gate`] had tripped by the time it held a permit.
enum TaskOutcome {
    Ran(Result<AgenticOutcome, LlmError>),
    BudgetSkipped(String),
}

/// Verify every finding. Bounded to `config.parallel` concurrent agentic
/// sessions; returns as soon as either every finding has a verdict or the
/// cumulative guardrail-abort gate trips (see module docs).
///
/// **Sessions still run and drain in completion order** (matching the
/// Python original's `as_completed`, and keeping the abort gate able to
/// fire the instant it trips) — but their results are parked by INPUT
/// index and only classified once the drain finishes, so `verified` and
/// `dropped` come out in the order S4/S5 handed the findings over rather
/// than in whatever order the network answered. That ordering is
/// load-bearing downstream: S7 keeps the LOWEST-INDEX member of a
/// duplicate cluster as canonical (`bc_dedup_core::collapse_trivial`), so
/// under the previous completion-ordered output *which* duplicate survived
/// — and with it the reported line, snippet, CVSS vector and fingerprint —
/// changed run to run purely from network timing. The Python original has
/// the same bug; this is a fix, not a port.
pub async fn run_verify(
    client: Arc<dyn LlmClient>,
    tools: Arc<dyn ToolExecutor>,
    input: Step6Input,
    config: &Step6Config,
) -> Result<VerifyOutput, StageError> {
    if input.findings.is_empty() {
        return Ok(VerifyOutput::default());
    }

    let semaphore = Arc::new(Semaphore::new(config.parallel.max(1)));
    let guardrail_gate = config.parallel.max(3);

    // Built once per run, not once per finding — see `bc_repo_analysis::
    // GraphView`'s own docs on why this port passes a shared reference
    // instead of Python's `id(ctx)`-keyed cache.
    let view = bc_repo_analysis::GraphView::new(&input.ctx);

    let total = input.findings.len();
    let mut set: JoinSet<(usize, Finding, TaskOutcome)> = JoinSet::new();
    for (index, f) in input.findings.into_iter().enumerate() {
        let user_prompt = prompts::build_user_prompt(&f, &input.ctx, &view);
        let mut agentic_cfg = AgenticConfig::new(config.model.clone());
        agentic_cfg.system_prompt = Some(prompts::SYSTEM.clone());
        agentic_cfg.allowed_tools = config.allowed_tools.clone();
        agentic_cfg.max_turns = config.max_turns;
        agentic_cfg.max_transient_retries = config.max_transient_retries;
        agentic_cfg.max_context_shrinks = config.max_context_shrinks;
        agentic_cfg.retry_backoff_base = config.retry_backoff_base;
        agentic_cfg.temperature = config.temperature;
        agentic_cfg.seed = config.seed;
        agentic_cfg.timeout_secs = config.timeout_secs;

        let sem = semaphore.clone();
        let client = client.clone();
        let tools = tools.clone();
        let gate = config.budget_gate.clone();
        set.spawn(async move {
            let _permit = sem
                .acquire_owned()
                .await
                .expect("semaphore is never closed");
            // Asked here, holding the permit, rather than before the
            // spawn: see `Step6Config::budget_gate`.
            if let Some(gate) = &gate {
                if gate.should_stop() {
                    return (index, f, TaskOutcome::BudgetSkipped(gate.stop_reason()));
                }
            }
            let outcome =
                run_agentic(client.as_ref(), tools.as_ref(), &user_prompt, &agentic_cfg).await;
            (index, f, TaskOutcome::Ran(outcome))
        });
    }

    let mut results: Vec<Option<(Finding, SessionResult)>> =
        std::iter::repeat_with(|| None).take(total).collect();
    let mut guardrail_hits = 0usize;
    let mut confirmed = 0usize;
    let mut skipped = 0usize;
    let mut budget_reason: Option<String> = None;

    while let Some(joined) = set.join_next().await {
        let (index, f, outcome) = joined.expect("verify task panicked");
        let mut abort = false;
        let outcome = match outcome {
            TaskOutcome::Ran(outcome) => outcome,
            TaskOutcome::BudgetSkipped(reason) => {
                skipped += 1;
                budget_reason.get_or_insert(reason.clone());
                results[index] = Some((f, SessionResult::BudgetSkipped(reason)));
                continue;
            }
        };
        let result = match outcome {
            Ok(agentic_outcome) => {
                let parsed = parse::parse_verdict(&agentic_outcome.final_text);
                if is_confirmed(&parsed, config.min_confidence) {
                    confirmed += 1;
                }
                SessionResult::Verdict(parsed)
            }
            Err(LlmError::GuardrailBlocked { message }) => {
                guardrail_hits += 1;
                // Identical condition to the pre-reorder code's
                // `verified.is_empty()`: `confirmed` counts exactly the
                // replies `classify` would have pushed onto `verified` by
                // this point (see `is_confirmed`).
                abort = guardrail_hits >= guardrail_gate && confirmed == 0;
                SessionResult::Guardrail(truncate_chars(&message, 200))
            }
            Err(LlmError::QuotaExhausted { message }) => {
                // Not this finding's failure: the provider has said the
                // account cannot fund anything more, so every session
                // still queued behind this one would fail identically.
                // Trip the shared gate (the remaining tasks then decline
                // to start at all) and record this finding the same way
                // a budget skip is recorded — the verifier genuinely
                // never reached a verdict on it.
                let reason = format!(
                    "provider quota exhausted — {}",
                    truncate_chars(&message, 160)
                );
                if let Some(gate) = &config.budget_gate {
                    gate.trip(reason.clone());
                }
                skipped += 1;
                budget_reason.get_or_insert(reason.clone());
                SessionResult::BudgetSkipped(reason)
            }
            Err(e) => SessionResult::Failed(truncate_chars(&e.to_string(), 200)),
        };
        results[index] = Some((f, result));
        if abort {
            set.abort_all();
            return Err(StageError::new(
                Stage6::NAME,
                format!(
                    "{guardrail_hits} cumulative guardrail blocks with zero successes — \
                     aborting run."
                ),
            ));
        }
    }

    // Every slot is `Some` here: the loop above only exits normally once
    // each spawned task has been joined, and the abort path returns `Err`
    // instead of falling through. `flatten` rather than an `expect` so a
    // future early-exit can't turn a logic slip into a panic.
    let mut verified = Vec::new();
    let mut dropped = Vec::new();
    for (f, result) in results.into_iter().flatten() {
        match result {
            SessionResult::Verdict(parsed) => classify(
                f,
                parsed,
                config.min_confidence,
                &mut verified,
                &mut dropped,
            ),
            SessionResult::Guardrail(detail) => {
                dropped.push(drop_finding(&f, DropReason::GuardrailBlocked, detail));
            }
            SessionResult::Failed(detail) => {
                dropped.push(drop_finding(&f, DropReason::VerifyError, detail));
            }
            SessionResult::BudgetSkipped(reason) => {
                // `Unconfirmed`, not `FalsePositive` and not silence: the
                // verifier never ran, so the honest claim is "we could
                // not confirm this", and that reason is already excluded
                // from the report's true-positive tally.
                dropped.push(drop_finding(
                    &f,
                    DropReason::Unconfirmed,
                    format!("not verified — {reason}"),
                ));
            }
        }
    }

    let budget_stop = budget_reason.map(|reason| {
        format!(
            "{reason} — {} of {total} finding(s) verified, {skipped} left unverified",
            total - skipped
        )
    });

    Ok(VerifyOutput {
        verified,
        dropped,
        budget_stop,
    })
}

pub struct Stage6 {
    client: Arc<dyn LlmClient>,
    tools: Arc<dyn ToolExecutor>,
    config: Step6Config,
}

impl Stage6 {
    pub fn new(
        client: Arc<dyn LlmClient>,
        tools: Arc<dyn ToolExecutor>,
        config: Step6Config,
    ) -> Self {
        Stage6 {
            client,
            tools,
            config,
        }
    }
}

impl PipelineStage for Stage6 {
    type Input = Step6Input;
    type Output = VerifyOutput;
    const NAME: &'static str = "s6-verify";

    async fn run(&self, input: Step6Input) -> Result<StageOutcome<VerifyOutput>, StageError> {
        let output =
            run_verify(self.client.clone(), self.tools.clone(), input, &self.config).await?;
        match output.budget_stop.clone() {
            Some(reason) => Ok(StageOutcome::Degraded {
                value: output,
                reason,
            }),
            None => Ok(StageOutcome::Ok(output)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use bc_llm_client::{ChatRequest, ChatResponse, ContentBlock, StopReason, ToolSpec, Usage};
    use bc_model::VulnClass;
    use serde_json::{json, Value};

    const GOOD_CVSS: &str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";

    #[test]
    fn dropped_assessments_keep_each_original_provider_identity_and_full_verdict() {
        for (verdict, confidence, expected_reason) in [
            (Verdict::FalsePositive, 9, DropReason::FalsePositive),
            (Verdict::TruePositive, 4, DropReason::Unconfirmed),
        ] {
            let mut candidate = finding("src/app.py", 10);
            let origin = bc_model::ProviderOrigin {
                provider: bc_model::ProviderKind::Semgrep,
                native_ids: bc_model::ProviderNativeIds {
                    issue_id: Some("original-123".into()),
                    ..Default::default()
                },
                ..Default::default()
            };
            candidate.provider_origins.push(origin.clone());
            let parsed = parse::ParsedVerdict {
                verdict,
                confidence,
                reason: "specific control and preconditions".into(),
                reasoning: "Inspected src/app.py:10 and the actual sanitizer implementation".into(),
                cvss: Some(GOOD_CVSS.into()),
            };
            let mut verified = Vec::new();
            let mut dropped = Vec::new();
            classify(candidate, parsed.clone(), 7, &mut verified, &mut dropped);
            assert!(verified.is_empty());
            assert_eq!(dropped[0].reason, expected_reason);
            assert_eq!(dropped[0].provider_origins, [origin]);
            let evidence = dropped[0].verification.as_ref().unwrap();
            assert_eq!(evidence.verdict, verdict);
            assert_eq!(evidence.confidence, confidence);
            assert_eq!(evidence.reason, parsed.reason);
            assert_eq!(evidence.reasoning, parsed.reasoning);
            assert_eq!(evidence.cvss_vector, parsed.cvss);
        }
    }

    #[test]
    fn malformed_or_failed_verification_never_inherits_stale_assessment() {
        let mut candidate = finding("src/app.py", 10);
        candidate.verdict = Some(Verdict::FalsePositive);
        candidate.verdict_confidence = Some(10);
        candidate
            .provider_origins
            .push(bc_model::ProviderOrigin::default());
        let mut verified = Vec::new();
        let mut dropped = Vec::new();
        classify(
            candidate.clone(),
            parse::parse_verdict("provider refusal"),
            7,
            &mut verified,
            &mut dropped,
        );
        assert_eq!(dropped[0].reason, DropReason::VerifyError);
        assert!(dropped[0].verification.is_none());
        assert_eq!(dropped[0].provider_origins, candidate.provider_origins);
        for reason in [
            DropReason::VerifyError,
            DropReason::GuardrailBlocked,
            DropReason::Unconfirmed,
        ] {
            assert!(drop_finding(&candidate, reason, "not examined")
                .verification
                .is_none());
        }
    }

    fn finding(file: &str, line: i64) -> Finding {
        Finding {
            provider_origins: Vec::new(),
            chunk_id: "chunk-01".to_string(),
            file: file.to_string(),
            line_start: line,
            line_end: line + 2,
            vuln_class: VulnClass::Injection,
            cwe: None,
            title: "SQL injection in handler".to_string(),
            impact: String::new(),
            description: "user input flows into a raw query".to_string(),
            exploit_scenario: String::new(),
            preconditions: Vec::new(),
            recommendation: String::new(),
            code_snippet: "cur.execute('SELECT ' + user_in)".to_string(),
            source_ref: None,
            sink_ref: None,
            backfilled_refs: Vec::new(),
            reanchored: Vec::new(),
            compliance_requirements: Vec::new(),
            confidence: 0.8,
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

    struct NoTools;
    impl ToolExecutor for NoTools {
        fn available_tools(&self) -> Vec<ToolSpec> {
            ["Read", "Glob", "Grep"]
                .iter()
                .map(|name| ToolSpec {
                    name: name.to_string(),
                    description: String::new(),
                    parameters: json!({}),
                })
                .collect()
        }
        fn execute(&self, _name: &str, _args: &Value) -> String {
            String::new()
        }
    }

    /// Routes on a substring of the request's user prompt — every request
    /// is a single-turn `EndTurn` reply (never calls a tool) UNLESS
    /// `tool_first` is set, in which case the very first call requests a
    /// `Read` tool call before the router ever sees a reply, matching the
    /// Python test suite's `fake_agentic`/`router` fixtures plus one real
    /// tool-call round trip (needed so the fixture `ToolExecutor`'s
    /// `execute` — otherwise never invoked, since every other test's
    /// scripted client stops on turn one — and this client's own
    /// non-`Text`-content-block branch both get exercised).
    // A boxed trait object (not a generic `F` type parameter): every test's
    // closure would otherwise monomorphize its own separate copy of `chat`'s
    // body, splitting which specific match arm below each individual copy
    // exercises and defeating line-coverage union across them. One shared,
    // non-generic body lets every test's scenario accumulate onto the same
    // compiled function.
    type Router = Box<dyn Fn(&str) -> Result<String, LlmError> + Send + Sync>;

    struct RoutedClient {
        router: Router,
        tool_first: std::sync::atomic::AtomicBool,
    }

    impl RoutedClient {
        fn new(router: impl Fn(&str) -> Result<String, LlmError> + Send + Sync + 'static) -> Self {
            RoutedClient {
                router: Box::new(router),
                tool_first: std::sync::atomic::AtomicBool::new(false),
            }
        }

        fn new_with_tool_first(
            router: impl Fn(&str) -> Result<String, LlmError> + Send + Sync + 'static,
        ) -> Self {
            RoutedClient {
                router: Box::new(router),
                tool_first: std::sync::atomic::AtomicBool::new(true),
            }
        }
    }

    /// The concatenated text of the request's last message — the routing
    /// key both fixture clients below key off. Shared (rather than
    /// duplicated per fixture) so its non-`Text`-content-block arm has a
    /// single home: `RoutedClient::new_with_tool_first`'s tool round trip
    /// is what exercises it.
    fn last_message_text(request: &ChatRequest) -> String {
        request
            .messages
            .last()
            .map(|m| {
                m.content
                    .iter()
                    .filter_map(|c| match c {
                        ContentBlock::Text(t) => Some(t.as_str()),
                        _ => None,
                    })
                    .collect::<String>()
            })
            .unwrap_or_default()
    }

    #[async_trait]
    impl LlmClient for RoutedClient {
        async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, LlmError> {
            if self
                .tool_first
                .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                return Ok(ChatResponse {
                    content: vec![ContentBlock::ToolUse {
                        id: "1".to_string(),
                        name: "Read".to_string(),
                        input: json!({"path": "src/app.py"}),
                    }],
                    stop_reason: StopReason::ToolUse,
                    usage: Usage::default(),
                });
            }
            let user_text = last_message_text(request);
            let reply = (self.router)(&user_text)?;
            Ok(ChatResponse {
                content: vec![ContentBlock::Text(reply)],
                stop_reason: StopReason::EndTurn,
                usage: Usage::default(),
            })
        }
    }

    fn scripted(reply: &'static str) -> Arc<dyn LlmClient> {
        Arc::new(RoutedClient::new(move |_| Ok(reply.to_string())))
    }

    /// Answers every request with the same TRUE_POSITIVE reply, but makes
    /// the FIRST finding's session take far longer than the rest — so
    /// completion order is the exact reverse of input order and any
    /// remaining completion-order dependency in `run_verify` shows up as
    /// a reordered `verified` list.
    struct DelayedClient {
        slow_marker: &'static str,
        reply: String,
    }

    #[async_trait]
    impl LlmClient for DelayedClient {
        async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, LlmError> {
            let user_text = last_message_text(request);
            let delay = if user_text.contains(self.slow_marker) {
                std::time::Duration::from_millis(150)
            } else {
                std::time::Duration::from_millis(1)
            };
            tokio::time::sleep(delay).await;
            Ok(ChatResponse {
                content: vec![ContentBlock::Text(self.reply.clone())],
                stop_reason: StopReason::EndTurn,
                usage: Usage::default(),
            })
        }
    }

    /// A plain fn rather than a per-test closure: each closure is its
    /// own function for coverage purposes, and a test whose gate allows
    /// zero sessions never calls its client at all — so the budget tests
    /// share one already-exercised reply source.
    fn tp_reply(_: &str) -> Result<String, LlmError> {
        Ok(format!(
            "VERDICT: TRUE_POSITIVE (confidence: 9/10) — ok\nCVSS: {GOOD_CVSS}\n"
        ))
    }

    /// A gate that allows exactly `allowance` verification sessions and
    /// then stays shut — the deterministic stand-in for a real
    /// `bc_orchestrator::SpendGate` crossing its cap mid-stage.
    #[derive(Debug)]
    struct AfterNGate {
        remaining: std::sync::atomic::AtomicUsize,
    }

    impl AfterNGate {
        fn allowing(allowance: usize) -> bc_pipeline_core::BudgetGateRef {
            Arc::new(AfterNGate {
                remaining: std::sync::atomic::AtomicUsize::new(allowance),
            })
        }
    }

    impl bc_pipeline_core::BudgetGate for AfterNGate {
        fn should_stop(&self) -> bool {
            use std::sync::atomic::Ordering::SeqCst;
            self.remaining
                .fetch_update(SeqCst, SeqCst, |n| Some(n.saturating_sub(1)))
                .expect("the closure always returns Some")
                == 0
        }

        fn stop_reason(&self) -> String {
            "token budget of 3000000 reached (3012044 spent)".to_string()
        }
    }

    /// The 2026-09-06 Juice Shop failure, in miniature: S6 was 69% of the
    /// scan's whole spend (3.39M tokens over 1,881 verification sessions)
    /// and ran every one of them to completion because the only budget
    /// check was at the stage boundary it had already passed. It must now
    /// stop starting sessions — and each finding it never verified must
    /// be reported as unverified, never as a true positive and never
    /// silently dropped.
    #[tokio::test]
    async fn a_budget_gate_that_trips_part_way_stops_starting_new_verifications() {
        let client: Arc<dyn LlmClient> = Arc::new(RoutedClient::new(tp_reply));
        let mut cfg = Step6Config::new("m");
        // One session at a time, so "two allowed" means exactly two
        // findings reach the verifier.
        cfg.parallel = 1;
        cfg.budget_gate = Some(AfterNGate::allowing(2));
        let findings: Vec<Finding> = (0..5).map(|i| finding(&format!("f{i}.py"), 10)).collect();
        let out = run_verify(
            client,
            Arc::new(NoTools),
            Step6Input {
                findings,
                ctx: minimal_ctx(),
            },
            &cfg,
        )
        .await
        .unwrap();

        assert_eq!(out.verified.len(), 2, "only the funded sessions ran");
        assert_eq!(out.dropped.len(), 3);
        // NOT true positives, and NOT gone: three honest "we never
        // checked" entries.
        assert!(out
            .dropped
            .iter()
            .all(|d| d.reason == DropReason::Unconfirmed));
        assert!(out.dropped.iter().all(|d| d
            .detail
            .starts_with("not verified — token budget of 3000000 reached")));
        // Nothing is lost: five in, five accounted for.
        assert_eq!(out.verified.len() + out.dropped.len(), 5);
        let reason = out.budget_stop.unwrap();
        assert!(
            reason.ends_with("2 of 5 finding(s) verified, 3 left unverified"),
            "{reason}"
        );
    }

    /// A gate nothing computes for itself — shut only once a stage tells
    /// it to be, which is the shape a quota failure needs (and the shape
    /// `bc_orchestrator::SpendGate` takes on a scan with no
    /// `--max-tokens`/`--max-scan-seconds` at all).
    #[derive(Debug, Default)]
    struct TrippableGate {
        reason: std::sync::Mutex<Option<String>>,
    }

    impl TrippableGate {
        fn untripped() -> bc_pipeline_core::BudgetGateRef {
            Arc::new(TrippableGate::default())
        }
    }

    impl bc_pipeline_core::BudgetGate for TrippableGate {
        fn should_stop(&self) -> bool {
            self.reason.lock().unwrap().is_some()
        }

        fn stop_reason(&self) -> String {
            self.reason.lock().unwrap().clone().unwrap_or_default()
        }

        fn trip(&self, reason: String) {
            self.reason.lock().unwrap().get_or_insert(reason);
        }
    }

    /// A plain fn, not a per-test closure, for the same coverage reason
    /// `tp_reply` is one.
    fn quota_exhausted_reply(_: &str) -> Result<String, LlmError> {
        Err(LlmError::QuotaExhausted {
            message: "You exceeded your current quota, please check your plan and billing details"
                .to_string(),
        })
    }

    /// The 2026-09 CI failure itself: OpenAI answers every one of S6's
    /// ~250 verification sessions with a 429 `insufficient_quota`. The
    /// first session to hear it trips the gate, the rest never start —
    /// and every finding is reported as unverified, not as a verify
    /// error (the account being empty says nothing about the finding)
    /// and not as a true positive.
    #[tokio::test]
    async fn a_quota_exhausted_reply_trips_the_gate_and_leaves_the_rest_unverified() {
        let client: Arc<dyn LlmClient> = Arc::new(RoutedClient::new(quota_exhausted_reply));
        let mut cfg = Step6Config::new("m");
        // One session at a time, so the sessions behind the first one are
        // still queued when it learns the account is empty.
        cfg.parallel = 1;
        let gate = TrippableGate::untripped();
        cfg.budget_gate = Some(gate.clone());
        let findings: Vec<Finding> = (0..5).map(|i| finding(&format!("f{i}.py"), 10)).collect();
        let out = run_verify(
            client,
            Arc::new(NoTools),
            Step6Input {
                findings,
                ctx: minimal_ctx(),
            },
            &cfg,
        )
        .await
        .unwrap();

        // The gate is shut, and stays shut for every stage after this one
        // — the point of pushing the discovery outward instead of leaving
        // each session to rediscover it.
        assert!(gate.should_stop());
        let gate_reason = gate.stop_reason();
        assert!(
            gate_reason.starts_with("provider quota exhausted — "),
            "{gate_reason}"
        );

        assert_eq!(out.verified.len(), 0);
        assert_eq!(out.dropped.len(), 5, "five in, five accounted for");
        assert!(out
            .dropped
            .iter()
            .all(|d| d.reason == DropReason::Unconfirmed));
        // `bc-report-md` keys the "never examined" tally off exactly this
        // prefix — see `render_executive_summary`.
        let details: Vec<&str> = out.dropped.iter().map(|d| d.detail.as_str()).collect();
        assert!(
            details
                .iter()
                .all(|d| d.starts_with("not verified — provider quota exhausted — ")),
            "{details:?}"
        );
        let reason = out.budget_stop.unwrap();
        assert!(
            reason.starts_with("provider quota exhausted — "),
            "{reason}"
        );
        assert!(
            reason.ends_with("0 of 5 finding(s) verified, 5 left unverified"),
            "{reason}"
        );
    }

    /// With no gate configured there is nothing to trip — every session
    /// still runs and still hits the wall — but the finding that hit it
    /// must be reported honestly as unverified rather than as a verifier
    /// error, and the stage must not panic reaching for a gate it hasn't
    /// got.
    #[tokio::test]
    async fn a_quota_exhausted_reply_without_a_gate_is_still_reported_as_unverified() {
        let client: Arc<dyn LlmClient> = Arc::new(RoutedClient::new(quota_exhausted_reply));
        let cfg = Step6Config::new("m");
        assert!(cfg.budget_gate.is_none());
        let out = run_verify(
            client,
            Arc::new(NoTools),
            Step6Input {
                findings: vec![finding("a.py", 10)],
                ctx: minimal_ctx(),
            },
            &cfg,
        )
        .await
        .unwrap();
        assert!(out.verified.is_empty());
        assert_eq!(out.dropped.len(), 1);
        assert_eq!(out.dropped[0].reason, DropReason::Unconfirmed);
        let detail = out.dropped[0].detail.as_str();
        assert!(
            detail.starts_with("not verified — provider quota exhausted — "),
            "{detail}"
        );
        assert!(out
            .budget_stop
            .unwrap()
            .starts_with("provider quota exhausted — "));
    }

    #[tokio::test]
    async fn a_budget_gate_that_never_trips_changes_nothing_in_s6() {
        let client: Arc<dyn LlmClient> = Arc::new(RoutedClient::new(tp_reply));
        let mut cfg = Step6Config::new("m");
        cfg.budget_gate = Some(AfterNGate::allowing(usize::MAX));
        let out = run_verify(
            client,
            Arc::new(NoTools),
            Step6Input {
                findings: vec![finding("a.py", 10)],
                ctx: minimal_ctx(),
            },
            &cfg,
        )
        .await
        .unwrap();
        assert_eq!(out.verified.len(), 1);
        assert!(out.budget_stop.is_none());
    }

    #[tokio::test]
    async fn stage6_run_reports_a_budget_stop_as_degraded() {
        let client: Arc<dyn LlmClient> = Arc::new(RoutedClient::new(tp_reply));
        let mut cfg = Step6Config::new("m");
        cfg.budget_gate = Some(AfterNGate::allowing(0));
        let outcome = Stage6::new(client, Arc::new(NoTools), cfg)
            .run(Step6Input {
                findings: vec![finding("a.py", 10)],
                ctx: minimal_ctx(),
            })
            .await
            .unwrap();
        assert!(outcome.is_degraded());
        assert!(outcome
            .reason()
            .unwrap()
            .contains("0 of 1 finding(s) verified, 1 left unverified"));
        assert!(outcome.into_value().verified.is_empty());
    }

    #[tokio::test]
    async fn stage6_run_without_a_budget_stop_is_not_degraded() {
        let client: Arc<dyn LlmClient> = Arc::new(RoutedClient::new(tp_reply));
        let outcome = Stage6::new(client, Arc::new(NoTools), Step6Config::new("m"))
            .run(Step6Input {
                findings: vec![finding("a.py", 10)],
                ctx: minimal_ctx(),
            })
            .await
            .unwrap();
        assert!(!outcome.is_degraded());
    }

    #[tokio::test]
    async fn verified_findings_come_back_in_input_order_not_completion_order() {
        let reply = format!(
            "traced it\nVERDICT: TRUE_POSITIVE (confidence: 9/10) — reachable\nCVSS: {GOOD_CVSS}\n"
        );
        let client: Arc<dyn LlmClient> = Arc::new(DelayedClient {
            slow_marker: "aaa_slow.py",
            reply,
        });
        let mut cfg = Step6Config::new("m");
        cfg.parallel = 5; // all three sessions genuinely in flight at once
        let out = run_verify(
            client,
            Arc::new(NoTools),
            Step6Input {
                findings: vec![
                    finding("aaa_slow.py", 10),
                    finding("bbb_fast.py", 20),
                    finding("ccc_fast.py", 30),
                ],
                ctx: minimal_ctx(),
            },
            &cfg,
        )
        .await
        .unwrap();

        let files: Vec<&str> = out.verified.iter().map(|f| f.file.as_str()).collect();
        assert_eq!(files, vec!["aaa_slow.py", "bbb_fast.py", "ccc_fast.py"]);
    }

    #[tokio::test]
    async fn dropped_findings_also_come_back_in_input_order() {
        // Same property on the other output list: the slow session's
        // finding must still be reported first even though it finished
        // last. FALSE_POSITIVE for every finding, so all three land in
        // `dropped`.
        let client: Arc<dyn LlmClient> = Arc::new(DelayedClient {
            slow_marker: "aaa_slow.py",
            reply: "VERDICT: FALSE_POSITIVE (confidence: 9/10) — sanitized".to_string(),
        });
        let mut cfg = Step6Config::new("m");
        cfg.parallel = 5;
        let out = run_verify(
            client,
            Arc::new(NoTools),
            Step6Input {
                findings: vec![
                    finding("aaa_slow.py", 10),
                    finding("bbb_fast.py", 20),
                    finding("ccc_fast.py", 30),
                ],
                ctx: minimal_ctx(),
            },
            &cfg,
        )
        .await
        .unwrap();

        let files: Vec<&str> = out.dropped.iter().map(|d| d.file.as_str()).collect();
        assert_eq!(files, vec!["aaa_slow.py", "bbb_fast.py", "ccc_fast.py"]);
    }

    #[tokio::test]
    async fn empty_findings_short_circuits() {
        let (verified, dropped) = {
            let out = run_verify(
                scripted(""),
                Arc::new(NoTools),
                Step6Input {
                    findings: Vec::new(),
                    ctx: minimal_ctx(),
                },
                &Step6Config::new("m"),
            )
            .await
            .unwrap();
            (out.verified, out.dropped)
        };
        assert!(verified.is_empty());
        assert!(dropped.is_empty());
    }

    #[tokio::test]
    async fn true_positive_above_gate_is_verified_with_scored_cvss() {
        let reply = format!(
            "traced it\nVERDICT: TRUE_POSITIVE (confidence: 9/10) — reachable\nCVSS: {GOOD_CVSS}\n"
        );
        let client: Arc<dyn LlmClient> = Arc::new(RoutedClient::new(move |_| Ok(reply.clone())));
        let mut cfg = Step6Config::new("m");
        cfg.min_confidence = 7;
        let out = run_verify(
            client,
            Arc::new(NoTools),
            Step6Input {
                findings: vec![finding("src/app.py", 10)],
                ctx: minimal_ctx(),
            },
            &cfg,
        )
        .await
        .unwrap();
        assert_eq!(out.verified.len(), 1);
        assert!(out.dropped.is_empty());
        let f = &out.verified[0];
        assert_eq!(f.verdict, Some(Verdict::TruePositive));
        assert_eq!(f.verdict_confidence, Some(9));
        assert_eq!(f.cvss_vector.as_deref(), Some(GOOD_CVSS));
        assert_eq!(f.cvss_score, Some(9.8));
        assert_eq!(f.cvss_rating.as_deref(), Some("Critical"));
        assert!(f.verifier_reasoning.contains("traced it"));
    }

    #[tokio::test]
    async fn a_tool_call_round_trip_executes_the_tool_and_still_reaches_a_verdict() {
        // Forces one real Read tool call through `NoTools::execute` before
        // the final verdict — every other test's scripted client stops on
        // its very first turn, so without this the fixture `ToolExecutor`
        // and this client's own non-text-content-block branch (the second
        // `chat()` call's last message is a `ToolResult`, not `Text`) would
        // never actually run.
        let reply = format!("VERDICT: TRUE_POSITIVE (confidence: 9/10) — ok\nCVSS: {GOOD_CVSS}\n");
        let client: Arc<dyn LlmClient> =
            Arc::new(RoutedClient::new_with_tool_first(
                move |_| Ok(reply.clone()),
            ));
        let mut cfg = Step6Config::new("m");
        cfg.allowed_tools = vec!["Read".to_string()];
        let out = run_verify(
            client,
            Arc::new(NoTools),
            Step6Input {
                findings: vec![finding("src/app.py", 10)],
                ctx: minimal_ctx(),
            },
            &cfg,
        )
        .await
        .unwrap();
        assert_eq!(out.verified.len(), 1);
    }

    #[tokio::test]
    async fn true_positive_below_gate_is_unconfirmed() {
        let reply =
            format!("VERDICT: TRUE_POSITIVE (confidence: 4/10) — weak\nCVSS: {GOOD_CVSS}\n");
        let client: Arc<dyn LlmClient> = Arc::new(RoutedClient::new(move |_| Ok(reply.clone())));
        let mut cfg = Step6Config::new("m");
        cfg.min_confidence = 7;
        let out = run_verify(
            client,
            Arc::new(NoTools),
            Step6Input {
                findings: vec![finding("src/app.py", 10)],
                ctx: minimal_ctx(),
            },
            &cfg,
        )
        .await
        .unwrap();
        assert!(out.verified.is_empty());
        assert_eq!(out.dropped.len(), 1);
        assert_eq!(out.dropped[0].reason, DropReason::Unconfirmed);
        assert!(out.dropped[0].detail.contains("below gate 7"));
    }

    #[tokio::test]
    async fn false_positive_is_dropped_with_the_verdict_reason() {
        let reply = format!(
            "VERDICT: FALSE_POSITIVE (confidence: 9/10) — input is sanitised\nCVSS: {GOOD_CVSS}\n"
        );
        let client: Arc<dyn LlmClient> = Arc::new(RoutedClient::new(move |_| Ok(reply.clone())));
        let out = run_verify(
            client,
            Arc::new(NoTools),
            Step6Input {
                findings: vec![finding("src/app.py", 10)],
                ctx: minimal_ctx(),
            },
            &Step6Config::new("m"),
        )
        .await
        .unwrap();
        assert!(out.verified.is_empty());
        assert_eq!(out.dropped.len(), 1);
        assert_eq!(out.dropped[0].reason, DropReason::FalsePositive);
        assert_eq!(out.dropped[0].detail, "input is sanitised");
    }

    #[tokio::test]
    async fn unparseable_reply_is_verify_error_not_false_positive() {
        let client = scripted("I read the code but did not reach a conclusion.\n");
        let out = run_verify(
            client,
            Arc::new(NoTools),
            Step6Input {
                findings: vec![finding("src/app.py", 10)],
                ctx: minimal_ctx(),
            },
            &Step6Config::new("m"),
        )
        .await
        .unwrap();
        assert!(out.verified.is_empty());
        assert_eq!(out.dropped.len(), 1);
        assert_eq!(out.dropped[0].reason, DropReason::VerifyError);
        assert_ne!(out.dropped[0].reason, DropReason::FalsePositive);
        assert!(out.dropped[0].detail.contains("unparseable"));
    }

    struct FailingClient;
    #[async_trait]
    impl LlmClient for FailingClient {
        async fn chat(&self, _request: &ChatRequest) -> Result<ChatResponse, LlmError> {
            Err(LlmError::Other {
                message: "backend exploded".to_string(),
            })
        }
    }

    #[tokio::test]
    async fn a_raised_error_is_captured_as_verify_error() {
        let out = run_verify(
            Arc::new(FailingClient),
            Arc::new(NoTools),
            Step6Input {
                findings: vec![finding("src/app.py", 10)],
                ctx: minimal_ctx(),
            },
            &Step6Config::new("m"),
        )
        .await
        .unwrap();
        assert!(out.verified.is_empty());
        assert_eq!(out.dropped.len(), 1);
        assert_eq!(out.dropped[0].reason, DropReason::VerifyError);
        assert!(out.dropped[0].detail.contains("backend exploded"));
    }

    struct GuardrailClient;
    #[async_trait]
    impl LlmClient for GuardrailClient {
        async fn chat(&self, _request: &ChatRequest) -> Result<ChatResponse, LlmError> {
            Err(LlmError::GuardrailBlocked {
                message: "Your request was not allowed".to_string(),
            })
        }
    }

    #[tokio::test]
    async fn a_single_guardrail_block_among_successes_is_recorded_not_aborted() {
        // One guardrail block among several successes: gate = max(3, parallel).
        let client: Arc<dyn LlmClient> = Arc::new(RoutedClient::new(move |user_text| {
            if user_text.contains("Line: 30-") {
                return Err(LlmError::GuardrailBlocked {
                    message: "Your request was not allowed".to_string(),
                });
            }
            Ok(format!(
                "VERDICT: TRUE_POSITIVE (confidence: 9/10) — ok\nCVSS: {GOOD_CVSS}\n"
            ))
        }));
        let findings = (0..4)
            .map(|i| finding("src/app.py", 10 * (i + 1)))
            .collect();
        let mut cfg = Step6Config::new("m");
        cfg.parallel = 4;
        let out = run_verify(
            client,
            Arc::new(NoTools),
            Step6Input {
                findings,
                ctx: minimal_ctx(),
            },
            &cfg,
        )
        .await
        .unwrap();
        let gb: Vec<_> = out
            .dropped
            .iter()
            .filter(|d| d.reason == DropReason::GuardrailBlocked)
            .collect();
        assert_eq!(gb.len(), 1);
        assert_eq!(out.verified.len(), 3);
    }

    #[tokio::test]
    async fn guardrail_gate_aborts_with_zero_successes() {
        // parallel=3 -> guardrail_gate = max(3, 3) = 3. Every call blocks, so
        // the whole run must abort as an Err once cumulative blocks reach 3
        // with zero successes.
        let findings = (0..3)
            .map(|i| finding("src/app.py", 10 * (i + 1)))
            .collect();
        let mut cfg = Step6Config::new("m");
        cfg.parallel = 3;
        let result = run_verify(
            Arc::new(GuardrailClient),
            Arc::new(NoTools),
            Step6Input {
                findings,
                ctx: minimal_ctx(),
            },
            &cfg,
        )
        .await;
        let err = result.unwrap_err();
        assert!(err.to_string().contains("cumulative guardrail"));
    }

    #[tokio::test]
    async fn stage6_run_wraps_success_as_ok() {
        let reply = format!("VERDICT: TRUE_POSITIVE (confidence: 9/10) — ok\nCVSS: {GOOD_CVSS}\n");
        let client: Arc<dyn LlmClient> = Arc::new(RoutedClient::new(move |_| Ok(reply.clone())));
        let stage = Stage6::new(client, Arc::new(NoTools), Step6Config::new("m"));
        let outcome = stage
            .run(Step6Input {
                findings: vec![finding("src/app.py", 10)],
                ctx: minimal_ctx(),
            })
            .await
            .unwrap();
        assert!(!outcome.is_degraded());
        assert_eq!(outcome.into_value().verified.len(), 1);
    }

    #[tokio::test]
    async fn stage6_run_propagates_the_guardrail_abort_as_err() {
        let findings = (0..3)
            .map(|i| finding("src/app.py", 10 * (i + 1)))
            .collect();
        let mut cfg = Step6Config::new("m");
        cfg.parallel = 3;
        let stage = Stage6::new(Arc::new(GuardrailClient), Arc::new(NoTools), cfg);
        let result = stage
            .run(Step6Input {
                findings,
                ctx: minimal_ctx(),
            })
            .await;
        assert!(result.is_err());
    }
}
