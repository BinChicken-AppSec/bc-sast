mod parse;
mod prompts;
mod repair;
mod wire;

use std::sync::Arc;

use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use appsec_llm_agentic::{run_agentic, AgenticConfig, AgenticOutcome};
use appsec_llm_client::{LlmClient, LlmError, ToolExecutor};
use appsec_model::{ContextPackage, DropReason, DroppedFinding, Finding, Verdict};
use appsec_pipeline_core::{PipelineStage, StageError, StageOutcome};

pub struct Step6Config {
    pub model: String,
    pub parallel: usize,
    pub min_confidence: i64,
    pub max_turns: u32,
    pub allowed_tools: Vec<String>,
    pub max_transient_retries: u32,
    pub max_context_shrinks: u32,
    pub retry_backoff_base: std::time::Duration,
    pub temperature: Option<f64>,
    pub top_p: Option<f64>,
    pub seed: Option<u64>,
    pub reasoning_effort: Option<appsec_llm_client::ReasoningEffort>,
    pub openai_api: Option<appsec_llm_client::OpenAiApi>,
    pub timeout_secs: Option<u64>,
    pub budget_gate: Option<appsec_pipeline_core::BudgetGateRef>,
    pub progress_file: bool,
}

impl Step6Config {
    pub fn new(model: impl Into<String>) -> Self {
        Step6Config {
            model: model.into(),
            parallel: 5,
            min_confidence: 6,
            max_turns: 30,
            allowed_tools: vec!["Read".to_string(), "Glob".to_string(), "Grep".to_string()],
            max_transient_retries: 6,
            max_context_shrinks: 16,
            retry_backoff_base: std::time::Duration::from_secs(10),
            temperature: None,
            top_p: None,
            seed: None,
            reasoning_effort: None,
            openai_api: None,
            timeout_secs: None,
            budget_gate: None,
            progress_file: false,
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
    pub budget_stop: Option<String>,
    pub diagnostics: VerifyDiagnostics,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VerifyDiagnostics {
    pub verdict_repairs_attempted: usize,
    pub verdict_repairs_adopted: usize,
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
    let score = appsec_cvss::score(parsed.cvss.as_deref());
    f.verdict = Some(parsed.verdict);
    f.verdict_confidence = Some(parsed.confidence);
    f.verdict_reason = parsed.reason;
    f.cvss_vector = parsed.cvss;
    f.cvss_score = score;
    f.cvss_rating = score.map(|s| appsec_cvss::rating(Some(s)).to_string());
    f.verifier_reasoning = parsed.reasoning;
    f
}

fn is_confirmed(parsed: &parse::ParsedVerdict, min_confidence: i64) -> bool {
    parsed.verdict == Verdict::TruePositive && parsed.confidence >= min_confidence
}

fn classify(
    f: Finding,
    parsed: parse::ParsedVerdict,
    min_confidence: i64,
    verified: &mut Vec<Finding>,
    dropped: &mut Vec<DroppedFinding>,
) {
    match verdict_class(&parsed, min_confidence) {
        VerdictClass::Confirmed => verified.push(finalize_finding(f, parsed)),
        VerdictClass::Unconfirmed => {
            let detail = format!(
                "verifier confidence {}/10 below gate {min_confidence}",
                parsed.confidence
            );
            let assessed = finalize_finding(f, parsed);
            let mut record = drop_finding(&assessed, DropReason::Unconfirmed, detail);
            record.verification = appsec_model::VerificationEvidence::from_finding(&assessed);
            dropped.push(record);
        }
        VerdictClass::Unparseable => {
            let reason = parsed.reason.clone();
            dropped.push(drop_finding(&f, DropReason::VerifyError, reason));
        }
        VerdictClass::FalsePositive => {
            let reason = parsed.reason.clone();
            let assessed = finalize_finding(f, parsed);
            let mut record = drop_finding(&assessed, DropReason::FalsePositive, reason);
            record.verification = appsec_model::VerificationEvidence::from_finding(&assessed);
            dropped.push(record);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VerdictClass {
    Confirmed,
    Unconfirmed,
    Unparseable,
    FalsePositive,
}

impl VerdictClass {
    fn outcome(self) -> &'static str {
        match self {
            VerdictClass::Confirmed => "TRUE_POSITIVE",
            VerdictClass::Unconfirmed => "UNCONFIRMED",
            VerdictClass::Unparseable => "VERIFY_ERROR",
            VerdictClass::FalsePositive => "FALSE_POSITIVE",
        }
    }
}

fn verdict_class(parsed: &parse::ParsedVerdict, min_confidence: i64) -> VerdictClass {
    if is_confirmed(parsed, min_confidence) {
        VerdictClass::Confirmed
    } else if parsed.verdict == Verdict::TruePositive {
        VerdictClass::Unconfirmed
    } else if parsed.reason == repair::UNPARSEABLE && parsed.confidence == 0 {
        VerdictClass::Unparseable
    } else {
        VerdictClass::FalsePositive
    }
}

fn session_outcome(result: &SessionResult, min_confidence: i64) -> Option<&'static str> {
    match result {
        SessionResult::Verdict(parsed) => Some(verdict_class(parsed, min_confidence).outcome()),
        SessionResult::Guardrail(_) => Some("GUARDRAIL_BLOCKED"),
        SessionResult::Failed(_) => Some("VERIFY_ERROR"),
        SessionResult::BudgetSkipped(_) => None,
    }
}

enum SessionResult {
    Verdict(parse::ParsedVerdict),
    Guardrail(String),
    Failed(String),
    BudgetSkipped(String),
}

enum TaskOutcome {
    Ran(Result<(parse::ParsedVerdict, repair::RepairTrace), LlmError>),
    BudgetSkipped(String),
}

pub async fn run_verify(
    client: Arc<dyn LlmClient>,
    tools: Arc<dyn ToolExecutor>,
    input: Step6Input,
    config: &Step6Config,
) -> Result<VerifyOutput, StageError> {
    run_verify_with_progress(client, tools, input, config, None).await
}

async fn run_verify_with_progress(
    client: Arc<dyn LlmClient>,
    tools: Arc<dyn ToolExecutor>,
    input: Step6Input,
    config: &Step6Config,
    progress: Option<&appsec_pipeline_core::ProgressSink>,
) -> Result<VerifyOutput, StageError> {
    if input.findings.is_empty() {
        return Ok(VerifyOutput::default());
    }

    let semaphore = Arc::new(Semaphore::new(config.parallel.max(1)));
    let guardrail_gate = config.parallel.max(3);

    let view = appsec_repo_analysis::GraphView::new(&input.ctx);

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
        agentic_cfg.reasoning_effort = config.reasoning_effort;
        agentic_cfg.openai_api = config.openai_api;
        agentic_cfg.timeout_secs = config.timeout_secs;
        agentic_cfg.cache_key = Some("s6".to_string());

        let sem = semaphore.clone();
        let client = client.clone();
        let tools = tools.clone();
        let gate = config.budget_gate.clone();
        set.spawn(async move {
            let _permit = sem
                .acquire_owned()
                .await
                .expect("semaphore is never closed");
            if let Some(gate) = &gate {
                if gate.should_stop() {
                    return (index, f, TaskOutcome::BudgetSkipped(gate.stop_reason()));
                }
            }
            let outcome = match run_agentic(
                client.as_ref(),
                tools.as_ref(),
                &user_prompt,
                &agentic_cfg,
            )
            .await
            {
                Ok(AgenticOutcome { final_text, .. }) => Ok(repair::parse_with_repair(
                    client.as_ref(),
                    tools.as_ref(),
                    &final_text,
                    &agentic_cfg,
                    || gate.as_ref().is_none_or(|g| !g.should_stop()),
                    index,
                )
                .await),
                Err(e) => Err(e),
            };
            (index, f, TaskOutcome::Ran(outcome))
        });
    }

    let mut results: Vec<Option<(Finding, SessionResult)>> =
        std::iter::repeat_with(|| None).take(total).collect();
    let mut guardrail_hits = 0usize;
    let mut confirmed = 0usize;
    let mut skipped = 0usize;
    let mut budget_reason: Option<String> = None;
    let mut diagnostics = VerifyDiagnostics::default();
    let mut completed = 0usize;
    appsec_pipeline_core::emit(
        progress,
        appsec_pipeline_core::ScanEvent::VerifyProgress {
            stage: Stage6::NAME,
            completed,
            total,
            outcome: None,
        },
    );

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
            Ok((parsed, trace)) => {
                diagnostics.verdict_repairs_attempted += usize::from(trace.attempted);
                diagnostics.verdict_repairs_adopted += usize::from(trace.adopted);
                if is_confirmed(&parsed, config.min_confidence) {
                    confirmed += 1;
                }
                SessionResult::Verdict(parsed)
            }
            Err(LlmError::GuardrailBlocked { message }) => {
                guardrail_hits += 1;
                abort = guardrail_hits >= guardrail_gate && confirmed == 0;
                SessionResult::Guardrail(truncate_chars(&message, 200))
            }
            Err(e) if e.halts_scan() => {
                let reason = match e {
                    LlmError::QuotaExhausted { message } => format!(
                        "provider quota exhausted — {}",
                        truncate_chars(&message, 160)
                    ),
                    other => truncate_chars(&other.to_string(), 200),
                };
                if let Some(gate) = &config.budget_gate {
                    gate.trip(reason.clone());
                }
                skipped += 1;
                budget_reason.get_or_insert(reason.clone());
                SessionResult::BudgetSkipped(reason)
            }
            Err(e) => SessionResult::Failed(truncate_chars(&e.to_string(), 200)),
        };
        if let Some(outcome) = session_outcome(&result, config.min_confidence) {
            completed += 1;
            appsec_pipeline_core::emit(
                progress,
                appsec_pipeline_core::ScanEvent::VerifyProgress {
                    stage: Stage6::NAME,
                    completed,
                    total,
                    outcome: Some(outcome),
                },
            );
        }
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
        diagnostics,
    })
}

pub struct Stage6 {
    client: Arc<dyn LlmClient>,
    tools: Arc<dyn ToolExecutor>,
    config: Step6Config,
    progress: Option<appsec_pipeline_core::ProgressSink>,
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
            progress: None,
        }
    }

    pub fn with_progress(mut self, progress: Option<appsec_pipeline_core::ProgressSink>) -> Self {
        self.progress = progress;
        self
    }
}

impl PipelineStage for Stage6 {
    type Input = Step6Input;
    type Output = VerifyOutput;
    const NAME: &'static str = "s6-verify";

    async fn run(&self, input: Step6Input) -> Result<StageOutcome<VerifyOutput>, StageError> {
        let output = run_verify_with_progress(
            self.client.clone(),
            self.tools.clone(),
            input,
            &self.config,
            self.progress.as_ref(),
        )
        .await?;
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
    use appsec_llm_client::{ChatRequest, ChatResponse, ContentBlock, StopReason, ToolSpec, Usage};
    use appsec_model::VulnClass;
    use async_trait::async_trait;
    use serde_json::{json, Value};

    const GOOD_CVSS: &str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";

    #[test]
    fn dropped_assessments_keep_each_original_provider_identity_and_full_verdict() {
        for (verdict, confidence, expected_reason) in [
            (Verdict::FalsePositive, 9, DropReason::FalsePositive),
            (Verdict::TruePositive, 4, DropReason::Unconfirmed),
        ] {
            let mut candidate = finding("src/app.py", 10);
            let origin = appsec_model::ProviderOrigin {
                provider: appsec_model::ProviderKind::Semgrep,
                native_ids: appsec_model::ProviderNativeIds {
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
            .push(appsec_model::ProviderOrigin::default());
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
            component: None,
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
            design_controls: Vec::new(),
            changed_files: Default::default(),
            diff_scope_active: false,
            app_profile: None,
            threat_model: None,
            provider_digest: None,
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

    fn tp_reply(_: &str) -> Result<String, LlmError> {
        Ok(format!(
            "VERDICT: TRUE_POSITIVE (confidence: 9/10) — ok\nCVSS: {GOOD_CVSS}\n"
        ))
    }

    #[derive(Debug)]
    struct AfterNGate {
        remaining: std::sync::atomic::AtomicUsize,
    }

    impl AfterNGate {
        fn allowing(allowance: usize) -> appsec_pipeline_core::BudgetGateRef {
            Arc::new(AfterNGate {
                remaining: std::sync::atomic::AtomicUsize::new(allowance),
            })
        }
    }

    impl appsec_pipeline_core::BudgetGate for AfterNGate {
        fn should_stop(&self) -> bool {
            use std::sync::atomic::Ordering::SeqCst;
            self.remaining
                .try_update(SeqCst, SeqCst, |n| Some(n.saturating_sub(1)))
                .expect("the closure always returns Some")
                == 0
        }

        fn stop_reason(&self) -> String {
            "token budget of 3000000 reached (3012044 spent)".to_string()
        }
    }

    #[tokio::test]
    async fn a_budget_gate_that_trips_part_way_stops_starting_new_verifications() {
        let client: Arc<dyn LlmClient> = Arc::new(RoutedClient::new(tp_reply));
        let mut cfg = Step6Config::new("m");
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
        assert!(out
            .dropped
            .iter()
            .all(|d| d.reason == DropReason::Unconfirmed));
        assert!(out.dropped.iter().all(|d| d
            .detail
            .starts_with("not verified — token budget of 3000000 reached")));
        assert_eq!(out.verified.len() + out.dropped.len(), 5);
        let reason = out.budget_stop.unwrap();
        assert!(
            reason.ends_with("2 of 5 finding(s) verified, 3 left unverified"),
            "{reason}"
        );
    }

    #[derive(Debug, Default)]
    struct TrippableGate {
        reason: std::sync::Mutex<Option<String>>,
    }

    impl TrippableGate {
        fn untripped() -> appsec_pipeline_core::BudgetGateRef {
            Arc::new(TrippableGate::default())
        }
    }

    impl appsec_pipeline_core::BudgetGate for TrippableGate {
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

    fn auth_rejected_reply(_: &str) -> Result<String, LlmError> {
        Err(LlmError::Authentication {
            status: Some(401),
            message: "Incorrect API key provided".to_string(),
        })
    }

    #[tokio::test]
    async fn an_authentication_failure_trips_the_gate_and_leaves_the_rest_unverified() {
        let client: Arc<dyn LlmClient> = Arc::new(RoutedClient::new(auth_rejected_reply));
        let mut cfg = Step6Config::new("m");
        cfg.parallel = 1;
        cfg.retry_backoff_base = std::time::Duration::ZERO;
        let gate = TrippableGate::untripped();
        cfg.budget_gate = Some(gate.clone());
        let findings: Vec<Finding> = (0..3).map(|i| finding(&format!("f{i}.py"), 10)).collect();
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
        assert!(gate.should_stop());
        let reason = gate.stop_reason();
        assert!(
            reason.starts_with("[VVAH-E001] authentication failed"),
            "{reason}"
        );
        assert_eq!(out.verified.len(), 0);
        assert_eq!(out.dropped.len(), 3);
    }

    fn quota_exhausted_reply(_: &str) -> Result<String, LlmError> {
        Err(LlmError::QuotaExhausted {
            message: "You exceeded your current quota, please check your plan and billing details"
                .to_string(),
        })
    }

    #[tokio::test]
    async fn a_quota_exhausted_reply_trips_the_gate_and_leaves_the_rest_unverified() {
        let client: Arc<dyn LlmClient> = Arc::new(RoutedClient::new(quota_exhausted_reply));
        let mut cfg = Step6Config::new("m");
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

    fn every_outcome_reply(user_text: &str) -> Result<String, LlmError> {
        if user_text.contains("Line: 10-") {
            return tp_reply(user_text);
        }
        if user_text.contains("Line: 20-") {
            return Ok(format!(
                "VERDICT: TRUE_POSITIVE (confidence: 2/10) — weak\nCVSS: {GOOD_CVSS}\n"
            ));
        }
        if user_text.contains("Line: 30-") {
            return Ok("VERDICT: FALSE_POSITIVE (confidence: 9/10) — sanitized".to_string());
        }
        if user_text.contains("Line: 40-") {
            return Ok("no verdict in this reply at all".to_string());
        }
        if user_text.contains("Line: 50-") {
            return Err(LlmError::Other {
                message: "backend exploded".to_string(),
            });
        }
        Err(LlmError::GuardrailBlocked {
            message: "Your request was not allowed".to_string(),
        })
    }

    #[tokio::test]
    async fn with_progress_reports_each_finished_verification_and_nothing_for_a_skipped_one() {
        let client: Arc<dyn LlmClient> = Arc::new(RoutedClient::new(every_outcome_reply));
        let mut cfg = Step6Config::new("m");
        cfg.parallel = 1;
        cfg.budget_gate = Some(AfterNGate::allowing(6));
        let findings = (1..=7).map(|i| finding("src/app.py", 10 * i)).collect();
        let (tx, rx) = std::sync::mpsc::channel();
        let outcome = Stage6::new(client, Arc::new(NoTools), cfg)
            .with_progress(Some(tx))
            .run(Step6Input {
                findings,
                ctx: minimal_ctx(),
            })
            .await
            .unwrap();
        assert!(outcome.is_degraded());
        let events: Vec<appsec_pipeline_core::ScanEvent> = rx.try_iter().collect();
        let mut seen: Vec<(&str, usize, usize, Option<&str>)> = Vec::new();
        for event in &events {
            if let appsec_pipeline_core::ScanEvent::VerifyProgress {
                stage,
                completed,
                total,
                outcome,
            } = event
            {
                seen.push((stage, *completed, *total, *outcome));
            }
        }
        assert_eq!(seen.len(), events.len(), "{events:?}");
        let seen: Vec<(usize, usize, Option<&str>)> = seen
            .into_iter()
            .map(|(stage, completed, total, outcome)| {
                assert_eq!(stage, Stage6::NAME);
                (completed, total, outcome)
            })
            .collect();
        assert_eq!(
            seen,
            vec![
                (0, 7, None),
                (1, 7, Some("TRUE_POSITIVE")),
                (2, 7, Some("UNCONFIRMED")),
                (3, 7, Some("FALSE_POSITIVE")),
                (4, 7, Some("VERIFY_ERROR")),
                (5, 7, Some("VERIFY_ERROR")),
                (6, 7, Some("GUARDRAIL_BLOCKED")),
            ]
        );
    }

    #[test]
    fn step6_config_keeps_the_progress_file_off_by_default() {
        assert!(!Step6Config::new("m").progress_file);
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

        let files: Vec<&str> = out.verified.iter().map(|f| f.file.as_str()).collect();
        assert_eq!(files, vec!["aaa_slow.py", "bbb_fast.py", "ccc_fast.py"]);
    }

    #[tokio::test]
    async fn dropped_findings_also_come_back_in_input_order() {
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
            "VERDICT: FALSE_POSITIVE (confidence: 9/10) — input is sanitized\nCVSS: {GOOD_CVSS}\n"
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
        assert_eq!(out.dropped[0].detail, "input is sanitized");
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
    struct RepairClient {
        primary: String,
        repair: Result<String, LlmError>,
        repair_calls: std::sync::atomic::AtomicUsize,
        repair_saw_tools: std::sync::atomic::AtomicBool,
    }

    impl RepairClient {
        fn new(primary: &str, repair: Result<&str, LlmError>) -> Arc<Self> {
            Arc::new(RepairClient {
                primary: primary.to_string(),
                repair: repair.map(str::to_string),
                repair_calls: std::sync::atomic::AtomicUsize::new(0),
                repair_saw_tools: std::sync::atomic::AtomicBool::new(false),
            })
        }

        fn repair_calls(&self) -> usize {
            self.repair_calls.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl LlmClient for RepairClient {
        async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, LlmError> {
            use std::sync::atomic::Ordering::SeqCst;
            let text = if last_message_text(request).starts_with("REPAIR TASK:") {
                self.repair_calls.fetch_add(1, SeqCst);
                if !request.tools.is_empty() {
                    self.repair_saw_tools.store(true, SeqCst);
                }
                self.repair.clone()?
            } else {
                self.primary.clone()
            };
            Ok(ChatResponse {
                content: vec![ContentBlock::Text(text)],
                stop_reason: StopReason::EndTurn,
                usage: Usage::default(),
            })
        }
    }

    async fn verify_one(client: Arc<RepairClient>, config: &Step6Config) -> VerifyOutput {
        run_verify(
            client,
            Arc::new(NoTools),
            Step6Input {
                findings: vec![finding("src/app.py", 10)],
                ctx: minimal_ctx(),
            },
            config,
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn a_committed_verdict_missing_its_prefix_is_repaired_and_adopted() {
        let repaired =
            format!("VERDICT: TRUE_POSITIVE (confidence: 9/10) — confirmed\nCVSS: {GOOD_CVSS}");
        let client = RepairClient::new(
            "Traced the route.\nTRUE_POSITIVE (confidence: 9/10) — Confirmed: unauth route",
            Ok(&repaired),
        );
        let out = verify_one(client.clone(), &Step6Config::new("m")).await;
        assert_eq!(client.repair_calls(), 1);
        assert!(!client
            .repair_saw_tools
            .load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(out.verified.len(), 1);
        assert_eq!(out.verified[0].verdict_reason, "confirmed");
        assert_eq!(
            out.diagnostics,
            VerifyDiagnostics {
                verdict_repairs_attempted: 1,
                verdict_repairs_adopted: 1,
            }
        );
    }

    #[tokio::test]
    async fn a_repair_that_flips_a_single_commitment_is_rejected() {
        let client = RepairClient::new(
            "My conclusion is TRUE_POSITIVE, the input is unsanitized.",
            Ok("VERDICT: FALSE_POSITIVE (confidence: 9/10) — sanitized\nCVSS: n/a"),
        );
        let out = verify_one(client.clone(), &Step6Config::new("m")).await;
        assert_eq!(client.repair_calls(), 1);
        assert!(out.verified.is_empty());
        assert_eq!(out.dropped[0].reason, DropReason::VerifyError);
        assert!(out.dropped[0].detail.contains("unparseable"));
        assert_eq!(out.diagnostics.verdict_repairs_attempted, 1);
        assert_eq!(out.diagnostics.verdict_repairs_adopted, 0);
    }

    #[tokio::test]
    async fn a_reply_weighing_both_verdicts_adopts_whichever_the_repair_commits_to() {
        let client = RepairClient::new(
            "Could be TRUE_POSITIVE, could be FALSE_POSITIVE; the guard looks complete.",
            Ok("VERDICT: FALSE_POSITIVE (confidence: 8/10) — guard covers every route"),
        );
        let out = verify_one(client, &Step6Config::new("m")).await;
        assert_eq!(out.dropped[0].reason, DropReason::FalsePositive);
        assert_eq!(out.dropped[0].detail, "guard covers every route");
        assert_eq!(out.diagnostics.verdict_repairs_adopted, 1);
    }

    #[tokio::test]
    async fn a_verdict_free_reply_gets_no_repair_call() {
        let client = RepairClient::new("I read the code but reached no conclusion.", Ok("unused"));
        let out = verify_one(client.clone(), &Step6Config::new("m")).await;
        assert_eq!(client.repair_calls(), 0);
        assert_eq!(out.dropped[0].reason, DropReason::VerifyError);
        assert_eq!(out.diagnostics, VerifyDiagnostics::default());
    }

    #[tokio::test]
    async fn a_repair_that_stays_unparseable_keeps_verify_error() {
        let client = RepairClient::new("TRUE_POSITIVE I think", Ok("still rambling"));
        let out = verify_one(client, &Step6Config::new("m")).await;
        assert_eq!(out.dropped[0].reason, DropReason::VerifyError);
        assert_eq!(out.diagnostics.verdict_repairs_attempted, 1);
    }

    #[tokio::test]
    async fn a_failing_repair_call_keeps_verify_error_and_never_counts_as_a_guardrail_hit() {
        let client = RepairClient::new(
            "FALSE_POSITIVE, clearly",
            Err(LlmError::GuardrailBlocked {
                message: "blocked".into(),
            }),
        );
        let mut cfg = Step6Config::new("m");
        cfg.parallel = 3;
        cfg.retry_backoff_base = std::time::Duration::ZERO;
        let out = run_verify(
            client.clone(),
            Arc::new(NoTools),
            Step6Input {
                findings: (1..=3).map(|i| finding("src/app.py", i * 10)).collect(),
                ctx: minimal_ctx(),
            },
            &cfg,
        )
        .await
        .expect("a failed repair must not abort the stage");
        assert_eq!(client.repair_calls(), 3);
        assert!(out
            .dropped
            .iter()
            .all(|d| d.reason == DropReason::VerifyError));
        assert_eq!(out.diagnostics.verdict_repairs_attempted, 3);
        assert_eq!(out.diagnostics.verdict_repairs_adopted, 0);
    }

    #[tokio::test]
    async fn a_tripped_budget_gate_skips_the_repair_call() {
        let client = RepairClient::new("TRUE_POSITIVE", Ok("unused"));
        let mut cfg = Step6Config::new("m");
        cfg.budget_gate = Some(AfterNGate::allowing(1));
        let out = verify_one(client.clone(), &cfg).await;
        assert_eq!(client.repair_calls(), 0);
        assert_eq!(out.dropped[0].reason, DropReason::VerifyError);
        assert_eq!(out.diagnostics.verdict_repairs_attempted, 0);
    }

    #[test]
    fn repair_prompt_restates_the_system_contract_lines_and_embeds_the_reply() {
        let prompt = prompts::repair_verdict_prompt("PRIOR REPLY TEXT");
        assert!(prompt.starts_with("REPAIR TASK:"));
        assert!(prompt.ends_with("YOUR PREVIOUS REPLY:\nPRIOR REPLY TEXT\n"));
        let contract = "VERDICT: TRUE_POSITIVE|FALSE_POSITIVE (confidence: N/10) — brief reason\nCVSS: CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_";
        assert!(prompt.contains(contract));
        assert!(prompts::SYSTEM.ends_with(contract));
    }
}
