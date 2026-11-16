mod code_loading;
mod cwe_kb;
mod findings_shape;
mod hints;
mod lens_hints;
mod neighbor;
mod packed_text;
mod prompt_layout;
mod prompts;
mod reanchor;
mod redact_source;
mod repair;
#[cfg(test)]
mod shard_cache_tests;
mod shard_gate;
mod shared_context;
mod single_run;
mod slice;
mod vote;
mod wire;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;

use appsec_llm_client::LlmClient;
use appsec_model::{Chunk, ContextPackage, Finding};
use appsec_pipeline_core::{PipelineStage, StageError, StageOutcome};

#[derive(Debug, Clone)]
pub struct Step4Config {
    pub model: String,
    pub parallel: usize,
    pub max_tokens: u32,
    pub max_findings_per_run: Option<usize>,
    pub neighbor_context_lines: i64,
    pub neighbor_context_max: usize,
    pub runs: usize,
    pub vote_threshold: usize,
    pub specialist_runs: usize,
    pub line_bucket: i64,
    pub taint_prompt_mode: String,
    pub taint_runs: Option<usize>,
    pub max_transient_retries: u32,
    pub retry_backoff_base: std::time::Duration,
    pub temperature: Option<f64>,
    pub top_p: Option<f64>,
    pub seed: Option<u64>,
    pub reasoning_effort: Option<appsec_llm_client::ReasoningEffort>,
    pub openai_api: Option<appsec_llm_client::OpenAiApi>,
    pub timeout_secs: Option<u64>,
    pub taint_chunk_slice: String,
    pub budget_gate: Option<appsec_pipeline_core::BudgetGateRef>,
    pub frontier_max_funcs_per_file: usize,
    pub shard_cache_gating: bool,
}

impl Step4Config {
    pub fn new(model: impl Into<String>) -> Self {
        Step4Config {
            model: model.into(),
            parallel: 5,
            max_tokens: 64_000,
            max_findings_per_run: Some(10),
            neighbor_context_lines: 20,
            neighbor_context_max: 40,
            runs: 1,
            vote_threshold: 1,
            specialist_runs: 1,
            line_bucket: 10,
            taint_prompt_mode: "discover".to_string(),
            taint_runs: None,
            max_transient_retries: 4,
            retry_backoff_base: std::time::Duration::from_secs(10),
            temperature: None,
            top_p: None,
            seed: None,
            reasoning_effort: None,
            openai_api: None,
            timeout_secs: Some(1800),
            taint_chunk_slice: "file".to_string(),
            budget_gate: None,
            frontier_max_funcs_per_file: 24,
            shard_cache_gating: true,
        }
    }
}

pub struct Step4Input {
    pub chunks: Vec<Chunk>,
    pub ctx: ContextPackage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkOutcome {
    Completed,
    Error,
    Guardrail,
    Skipped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DeepdiveDiagnostics {
    pub json_repairs_attempted: usize,
    pub json_repairs_succeeded: usize,
    pub findings_truncated: usize,
    pub vote_threshold_clamped: usize,
    pub empty_chunks_skipped: usize,
    pub leader_start_cap_expired: usize,
    pub gate_cap_expired: usize,
    pub sibling_parked_ms: u64,
}

impl DeepdiveDiagnostics {
    fn absorb(&mut self, other: DeepdiveDiagnostics) {
        self.json_repairs_attempted += other.json_repairs_attempted;
        self.json_repairs_succeeded += other.json_repairs_succeeded;
        self.findings_truncated += other.findings_truncated;
        self.vote_threshold_clamped += other.vote_threshold_clamped;
        self.empty_chunks_skipped += other.empty_chunks_skipped;
        self.leader_start_cap_expired += other.leader_start_cap_expired;
        self.gate_cap_expired += other.gate_cap_expired;
        self.sibling_parked_ms += other.sibling_parked_ms;
    }

    fn record_park(&mut self, report: shard_gate::ParkReport, chunk: &str, leader: &str) {
        let cap = if report.start_cap_expired {
            self.leader_start_cap_expired += 1;
            Some(("start", shard_gate::LEADER_START_CAP))
        } else if report.done_cap_expired {
            self.gate_cap_expired += 1;
            Some(("finish", shard_gate::LEADER_DONE_CAP))
        } else {
            None
        };
        if let Some((what, cap)) = cap {
            let secs = cap.as_secs();
            tracing::warn!(
                "[s4] {chunk}: shard leader {leader} did not {what} within {secs}s; proceeding \
                 ungated (the shared cache prefix may be written again)"
            );
        }
        let parked_ms = u64::try_from(report.parked.as_millis()).unwrap_or(u64::MAX);
        self.sibling_parked_ms = self.sibling_parked_ms.saturating_add(parked_ms);
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct DeepdiveOutput {
    pub findings: Vec<Finding>,
    pub outcomes: BTreeMap<String, ChunkOutcome>,
    pub budget_stop: Option<String>,
    pub diagnostics: DeepdiveDiagnostics,
}

fn effective_runs(runs: usize, vote_threshold: usize, temperature: Option<f64>) -> (usize, usize) {
    if runs < 1 {
        tracing::warn!("[s4] invalid runs={runs}; forcing runs=1, vote_threshold=1.");
        return (1, 1);
    }
    if runs > 1 && temperature == Some(0.0) {
        tracing::warn!(
            "[s4] runs={runs} with temperature=0 cannot produce divergent samples to vote \
             over; forcing runs=1, vote_threshold=1. Raise the temperature or set runs=1."
        );
        return (1, 1);
    }
    (runs, vote_threshold.clamp(1, runs))
}

pub enum ChunkError {
    AllRunsGuardrailBlocked,
    AllRunsFailed,
    BudgetStopped(String),
}

async fn deepdive_chunk(
    client: &dyn LlmClient,
    chunk: &Chunk,
    ctx: &ContextPackage,
    repo_root: &Path,
    config: &Step4Config,
    shared: &str,
    diag: &mut DeepdiveDiagnostics,
) -> Result<Vec<Finding>, ChunkError> {
    let (mut code, sliced) = code_loading::load_chunk_code(chunk, ctx, repo_root, config);
    code.push_str(&neighbor::neighbor_context(
        chunk,
        ctx,
        repo_root,
        config.neighbor_context_lines,
        config.neighbor_context_max,
    ));
    let prompt = prompt_layout::deepdive_prompt(
        chunk,
        ctx,
        &code,
        &config.taint_prompt_mode,
        sliced,
        shared,
    );

    let (runs_n, threshold) = if chunk.specialist.is_some() {
        (config.specialist_runs, 1)
    } else {
        let (mut runs_n, mut threshold) =
            effective_runs(config.runs, config.vote_threshold, config.temperature);
        if !chunk.path_funcs.is_empty() {
            if let Some(taint_runs) = config.taint_runs {
                runs_n = taint_runs.max(1);
                threshold = threshold.min(runs_n).max(1);
            }
        }
        (runs_n, threshold)
    };

    let mut runs: Vec<Vec<Finding>> = Vec::with_capacity(runs_n);
    let mut runs_ok = 0usize;
    let mut all_guardrail = true;

    for _ in 0..runs_n {
        match single_run::single_run(
            client,
            chunk,
            &prompt,
            repo_root,
            &config.model,
            config.max_tokens,
            config.max_findings_per_run,
            config.max_transient_retries,
            config.retry_backoff_base,
            single_run::Sampling::from_config(config),
            diag,
        )
        .await
        {
            Ok(mut findings) => {
                runs_ok += 1;
                all_guardrail = false;
                if ctx.diff_scope_active {
                    findings.retain(|f| chunk.files.contains(&f.file));
                }
                runs.push(findings);
            }
            Err(single_run::RunError::QuotaExhausted(message)) => {
                let reason = format!("provider quota exhausted — {message}");
                if let Some(gate) = &config.budget_gate {
                    gate.trip(reason.clone());
                }
                return Err(ChunkError::BudgetStopped(reason));
            }
            Err(single_run::RunError::Halting(reason)) => {
                if let Some(gate) = &config.budget_gate {
                    gate.trip(reason.clone());
                }
                return Err(ChunkError::BudgetStopped(reason));
            }
            Err(single_run::RunError::GuardrailBlocked(_)) => {
                runs.push(Vec::new());
            }
            Err(single_run::RunError::Other(_)) => {
                all_guardrail = false;
                runs.push(Vec::new());
            }
        }
    }

    if runs_n > 0 && runs_ok == 0 {
        return Err(if all_guardrail {
            ChunkError::AllRunsGuardrailBlocked
        } else {
            ChunkError::AllRunsFailed
        });
    }

    let eff_threshold = threshold.min(runs_ok);
    if eff_threshold < threshold {
        diag.vote_threshold_clamped += 1;
        let id = &chunk.id;
        tracing::warn!(
            "[s4] {id}: {runs_ok}/{runs_n} run(s) succeeded; vote_threshold {threshold} -> \
             {eff_threshold} so the surviving run(s) can still carry a finding"
        );
    }

    Ok(vote::vote_within_chunk(
        &runs,
        config.line_bucket,
        eff_threshold,
    ))
}

#[derive(Clone)]
struct TaskEnv {
    client: Arc<dyn LlmClient>,
    ctx: Arc<ContextPackage>,
    repo_root: Arc<PathBuf>,
    config: Arc<Step4Config>,
    shared: Arc<str>,
    semaphore: Arc<Semaphore>,
}

type TaskResult = (Chunk, Result<Vec<Finding>, ChunkError>, DeepdiveDiagnostics);

fn dispatch(
    env: TaskEnv,
    chunks: Vec<Chunk>,
    mut gates: std::collections::HashMap<String, shard_gate::Gate>,
    tx: mpsc::UnboundedSender<TaskResult>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut set = JoinSet::new();
        for chunk in chunks {
            let permit = env
                .semaphore
                .clone()
                .acquire_owned()
                .await
                .expect("semaphore is never closed");
            let gate = gates.remove(&chunk.id);
            let (env, tx) = (env.clone(), tx.clone());
            set.spawn(async move {
                let _ = tx.send(run_chunk_task(env, chunk, permit, gate).await);
            });
        }
        drop(tx);
        while let Some(joined) = set.join_next().await {
            joined.expect("deepdive task panicked");
        }
    })
}

async fn run_chunk_task(
    env: TaskEnv,
    chunk: Chunk,
    mut permit: OwnedSemaphorePermit,
    gate: Option<shard_gate::Gate>,
) -> TaskResult {
    let mut diag = DeepdiveDiagnostics::default();
    let leader = match gate {
        Some(shard_gate::Gate::Leader(leader)) => Some(leader),
        Some(shard_gate::Gate::Sibling(mut sibling)) => {
            if !sibling.leader_finished() {
                drop(permit);
                let report = sibling.park().await;
                diag.record_park(report, &chunk.id, sibling.leader());
                permit = env
                    .semaphore
                    .clone()
                    .acquire_owned()
                    .await
                    .expect("semaphore is never closed");
            }
            None
        }
        None => None,
    };
    if let Some(gate) = &env.config.budget_gate {
        if gate.should_stop() {
            let stopped = Err(ChunkError::BudgetStopped(gate.stop_reason()));
            return (chunk, stopped, diag);
        }
    }
    if let Some(leader) = &leader {
        leader.start();
    }
    let result = deepdive_chunk(
        env.client.as_ref(),
        &chunk,
        env.ctx.as_ref(),
        env.repo_root.as_path(),
        env.config.as_ref(),
        &env.shared,
        &mut diag,
    )
    .await;
    drop(leader);
    drop(permit);
    (chunk, result, diag)
}

pub async fn run_deepdive(
    client: Arc<dyn LlmClient>,
    input: Step4Input,
    config: &Step4Config,
) -> Result<DeepdiveOutput, StageError> {
    run_deepdive_with_progress(client, input, config, None).await
}

async fn run_deepdive_with_progress(
    client: Arc<dyn LlmClient>,
    input: Step4Input,
    config: &Step4Config,
    progress: Option<&appsec_pipeline_core::ProgressSink>,
) -> Result<DeepdiveOutput, StageError> {
    if input.chunks.is_empty() {
        return Ok(DeepdiveOutput::default());
    }

    let mut chunks = input.chunks;
    chunks.sort_by_key(|c| c.risk_rank);
    let total = chunks.len();

    let mut outcomes: BTreeMap<String, ChunkOutcome> = BTreeMap::new();
    let mut diagnostics = DeepdiveDiagnostics::default();
    for chunk in chunks.iter().filter(|c| c.files.is_empty()) {
        let id = &chunk.id;
        tracing::warn!("[s4] chunk {id}: SKIPPED, no files to analyze");
        outcomes.insert(chunk.id.clone(), ChunkOutcome::Skipped);
        diagnostics.empty_chunks_skipped += 1;
    }
    chunks.retain(|c| !c.files.is_empty());

    let gates = if config.shard_cache_gating {
        shard_gate::build_gates(&chunks, |c| {
            prompt_layout::shares_shard_prefix(c, &config.taint_prompt_mode)
        })
    } else {
        std::collections::HashMap::new()
    };
    let env = TaskEnv {
        shared: Arc::from(shared_context::shared_context_block(&input.ctx)),
        repo_root: Arc::new(Path::new(&input.ctx.repo_root).to_path_buf()),
        ctx: Arc::new(input.ctx),
        config: Arc::new(config.clone()),
        semaphore: Arc::new(Semaphore::new(config.parallel.max(1))),
        client,
    };
    let guardrail_gate = config.parallel.max(3);

    let (tx, mut rx) = mpsc::unbounded_channel();
    let dispatcher = dispatch(env, chunks.clone(), gates, tx);

    let mut results: BTreeMap<String, Vec<Finding>> = BTreeMap::new();
    let mut guardrail_hits = 0usize;
    let mut successes = 0usize;
    let mut completed = 0usize;
    let mut skipped = 0usize;
    let mut budget_reason: Option<String> = None;

    while let Some((chunk, result, diag)) = rx.recv().await {
        diagnostics.absorb(diag);
        completed += 1;
        appsec_pipeline_core::emit(
            progress,
            appsec_pipeline_core::ScanEvent::ChunkProgress {
                stage: Stage4::NAME,
                completed,
                total,
            },
        );
        match result {
            Ok(findings) => {
                successes += 1;
                results.insert(chunk.id.clone(), findings);
                outcomes.insert(chunk.id.clone(), ChunkOutcome::Completed);
            }
            Err(ChunkError::AllRunsGuardrailBlocked) => {
                guardrail_hits += 1;
                outcomes.insert(chunk.id.clone(), ChunkOutcome::Guardrail);
                if guardrail_hits >= guardrail_gate && successes == 0 {
                    dispatcher.abort();
                    return Err(StageError::new(
                        Stage4::NAME,
                        format!("{guardrail_hits} guardrail blocks with zero successful chunks — aborting run."),
                    ));
                }
            }
            Err(ChunkError::AllRunsFailed) => {
                outcomes.insert(chunk.id.clone(), ChunkOutcome::Error);
            }
            Err(ChunkError::BudgetStopped(reason)) => {
                skipped += 1;
                outcomes.insert(chunk.id.clone(), ChunkOutcome::Skipped);
                budget_reason.get_or_insert(reason);
            }
        }
    }
    dispatcher.await.expect("deepdive task panicked");

    let mut all_findings = Vec::new();
    for chunk in &chunks {
        if let Some(findings) = results.get(&chunk.id) {
            all_findings.extend(findings.iter().cloned());
        }
    }
    let findings = vote::collapse_across_chunks(all_findings, config.line_bucket);

    let budget_stop = budget_reason.map(|reason| {
        format!(
            "{reason} — {} of {total} deep-dive chunk(s) analyzed, {skipped} skipped",
            total - skipped
        )
    });

    Ok(DeepdiveOutput {
        findings,
        outcomes,
        budget_stop,
        diagnostics,
    })
}

pub struct Stage4 {
    client: Arc<dyn LlmClient>,
    config: Step4Config,
    progress: Option<appsec_pipeline_core::ProgressSink>,
}

impl Stage4 {
    pub fn new(client: Arc<dyn LlmClient>, config: Step4Config) -> Self {
        Stage4 {
            client,
            config,
            progress: None,
        }
    }

    pub fn with_progress(mut self, progress: Option<appsec_pipeline_core::ProgressSink>) -> Self {
        self.progress = progress;
        self
    }
}

impl PipelineStage for Stage4 {
    type Input = Step4Input;
    type Output = DeepdiveOutput;
    const NAME: &'static str = "s4-deepdive";

    async fn run(&self, input: Step4Input) -> Result<StageOutcome<DeepdiveOutput>, StageError> {
        let output = run_deepdive_with_progress(
            self.client.clone(),
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
    use std::sync::atomic::{AtomicUsize, Ordering};

    use appsec_llm_client::{ChatRequest, ChatResponse, ContentBlock, LlmError, StopReason, Usage};
    use appsec_model::ChunkSize;
    use async_trait::async_trait;

    use super::*;

    fn chunk(id: &str, risk_rank: i64, specialist: Option<&str>) -> Chunk {
        Chunk {
            id: id.to_string(),
            size: ChunkSize::Small,
            risk_rank,
            files: vec!["a.py".to_string()],
            focus_entry_points: Vec::new(),
            hypothesis: String::new(),
            related_cves: Vec::new(),
            threat_id: None,
            languages: Vec::new(),
            specialist: specialist.map(String::from),
            path_funcs: Vec::new(),
            source_ref: String::new(),
            sink_ref: String::new(),
            sink_cwe: Vec::new(),
            shard_id: String::new(),
        }
    }

    fn finding_body(file: &str, line: i64, confidence: f64) -> String {
        serde_json::json!({"findings": [{
            "file": file, "line_start": line, "line_end": line,
            "vuln_class": "injection", "title": "t", "description": "d",
            "code_snippet": "x", "confidence": confidence,
        }]})
        .to_string()
    }

    fn empty_body() -> String {
        serde_json::json!({"findings": []}).to_string()
    }

    fn ctx_with_changed_file(file: &str, line: i64) -> ContextPackage {
        ContextPackage {
            diff_scope_active: true,
            changed_files: std::collections::BTreeMap::from([(
                file.to_string(),
                std::collections::BTreeSet::from([line]),
            )]),
            ..Default::default()
        }
    }

    type Router = Box<dyn Fn(&str) -> Result<String, LlmError> + Send + Sync>;

    struct RoutedClient {
        router: Router,
    }

    impl RoutedClient {
        fn new(router: impl Fn(&str) -> Result<String, LlmError> + Send + Sync + 'static) -> Self {
            RoutedClient {
                router: Box::new(router),
            }
        }
    }

    #[async_trait]
    impl LlmClient for RoutedClient {
        async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, LlmError> {
            let user_text = request
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
                .unwrap_or_default();
            let reply = (self.router)(&user_text)?;
            Ok(ChatResponse {
                content: vec![ContentBlock::Text(reply)],
                stop_reason: StopReason::EndTurn,
                usage: Usage::default(),
            })
        }
    }

    fn client_for(reply: String) -> Arc<dyn LlmClient> {
        Arc::new(RoutedClient::new(move |_| Ok(reply.clone())))
    }

    #[tokio::test]
    async fn routed_client_fixture_ignores_non_text_content_blocks() {
        let client = RoutedClient::new(|text| Ok(format!("echo:{text}")));
        let request = ChatRequest {
            model: "m".to_string(),
            system: None,
            messages: vec![appsec_llm_client::Message {
                role: appsec_llm_client::Role::User,
                content: vec![
                    ContentBlock::ToolResult {
                        tool_use_id: "1".to_string(),
                        content: "ignored".to_string(),
                        is_error: false,
                    },
                    ContentBlock::Text("hello".to_string()),
                ],
            }],
            tools: Vec::new(),
            max_tokens: 100,
            temperature: None,
            top_p: None,
            seed: None,
            thinking_budget: None,
            betas: Vec::new(),
            json_mode: false,
            timeout: None,
            stream: false,
            ..ChatRequest::default()
        };
        let response = client.chat(&request).await.unwrap();
        assert_eq!(response.text(), "echo:hello");
    }

    #[derive(Debug)]
    struct AfterNGate {
        remaining: AtomicUsize,
    }

    impl AfterNGate {
        fn allowing(allowance: usize) -> appsec_pipeline_core::BudgetGateRef {
            std::sync::Arc::new(AfterNGate {
                remaining: AtomicUsize::new(allowance),
            })
        }
    }

    impl appsec_pipeline_core::BudgetGate for AfterNGate {
        fn should_stop(&self) -> bool {
            self.remaining
                .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                    Some(n.saturating_sub(1))
                })
                .expect("the closure always returns Some")
                == 0
        }

        fn stop_reason(&self) -> String {
            "token budget of 3000000 reached (3012044 spent)".to_string()
        }
    }

    #[tokio::test]
    async fn a_budget_gate_that_trips_part_way_stops_starting_new_chunks() {
        let client = client_for(finding_body("a.py", 10, 0.9));
        let mut cfg = Step4Config::new("m");
        cfg.parallel = 1;
        cfg.budget_gate = Some(AfterNGate::allowing(2));
        let chunks = (0..5)
            .map(|i| chunk(&format!("c{i}"), i, None))
            .collect::<Vec<_>>();
        let out = run_deepdive(
            client,
            Step4Input {
                chunks,
                ctx: ContextPackage::default(),
            },
            &cfg,
        )
        .await
        .unwrap();

        let completed = out
            .outcomes
            .values()
            .filter(|o| **o == ChunkOutcome::Completed)
            .count();
        let skipped = out
            .outcomes
            .values()
            .filter(|o| **o == ChunkOutcome::Skipped)
            .count();
        assert_eq!(completed, 2);
        assert_eq!(skipped, 3);
        assert_eq!(out.outcomes.len(), 5);
        let reason = out.budget_stop.unwrap();
        assert!(
            reason.starts_with("token budget of 3000000 reached"),
            "{reason}"
        );
        assert!(
            reason.ends_with("2 of 5 deep-dive chunk(s) analyzed, 3 skipped"),
            "{reason}"
        );
    }

    #[derive(Debug, Default)]
    struct TrippableGate {
        reason: std::sync::Mutex<Option<String>>,
    }

    impl TrippableGate {
        fn untripped() -> appsec_pipeline_core::BudgetGateRef {
            std::sync::Arc::new(TrippableGate::default())
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

    fn auth_rejected(_: &str) -> Result<String, LlmError> {
        Err(LlmError::Authentication {
            status: Some(401),
            message: "Incorrect API key provided".to_string(),
        })
    }

    #[tokio::test]
    async fn an_authentication_failure_trips_the_gate_and_skips_every_remaining_chunk() {
        let client: Arc<dyn LlmClient> = Arc::new(RoutedClient::new(auth_rejected));
        let mut cfg = Step4Config::new("m");
        cfg.parallel = 1;
        cfg.retry_backoff_base = std::time::Duration::ZERO;
        let gate = TrippableGate::untripped();
        cfg.budget_gate = Some(gate.clone());
        let chunks = (0..3)
            .map(|i| chunk(&format!("c{i}"), i, None))
            .collect::<Vec<_>>();
        let out = run_deepdive(
            client,
            Step4Input {
                chunks,
                ctx: ContextPackage::default(),
            },
            &cfg,
        )
        .await
        .unwrap();
        assert!(gate.should_stop());
        assert!(
            out.outcomes.values().all(|o| *o == ChunkOutcome::Skipped),
            "{:?}",
            out.outcomes
        );
        let reason = out.budget_stop.unwrap();
        assert!(
            reason.starts_with("[VVAH-E001] authentication failed"),
            "{reason}"
        );
    }

    fn quota_exhausted(_: &str) -> Result<String, LlmError> {
        Err(LlmError::QuotaExhausted {
            message: "You exceeded your current quota".to_string(),
        })
    }

    #[tokio::test]
    async fn a_quota_exhausted_reply_trips_the_gate_and_skips_every_remaining_chunk() {
        let client: Arc<dyn LlmClient> = Arc::new(RoutedClient::new(quota_exhausted));
        let mut cfg = Step4Config::new("m");
        cfg.parallel = 1;
        cfg.budget_gate = Some(TrippableGate::untripped());
        let chunks = (0..4)
            .map(|i| chunk(&format!("c{i}"), i, None))
            .collect::<Vec<_>>();
        let out = run_deepdive(
            client,
            Step4Input {
                chunks,
                ctx: ContextPackage::default(),
            },
            &cfg,
        )
        .await
        .unwrap();

        assert_eq!(out.outcomes.len(), 4);
        assert!(
            out.outcomes.values().all(|o| *o == ChunkOutcome::Skipped),
            "{:?}",
            out.outcomes
        );
        assert!(out.findings.is_empty());
        let reason = out.budget_stop.unwrap();
        assert!(
            reason.starts_with("provider quota exhausted — You exceeded your current quota"),
            "{reason}"
        );
        assert!(
            reason.ends_with("0 of 4 deep-dive chunk(s) analyzed, 4 skipped"),
            "{reason}"
        );
    }

    #[tokio::test]
    async fn a_quota_exhausted_reply_without_a_gate_still_stops_the_chunk() {
        let client: Arc<dyn LlmClient> = Arc::new(RoutedClient::new(quota_exhausted));
        let mut cfg = Step4Config::new("m");
        cfg.parallel = 1;
        assert!(cfg.budget_gate.is_none());
        let out = run_deepdive(
            client,
            Step4Input {
                chunks: vec![chunk("c0", 0, None)],
                ctx: ContextPackage::default(),
            },
            &cfg,
        )
        .await
        .unwrap();
        assert_eq!(out.outcomes["c0"], ChunkOutcome::Skipped);
        assert!(out
            .budget_stop
            .unwrap()
            .starts_with("provider quota exhausted —"));
    }

    #[tokio::test]
    async fn a_budget_gate_that_never_trips_changes_nothing() {
        let client = client_for(finding_body("a.py", 10, 0.9));
        let mut cfg = Step4Config::new("m");
        cfg.budget_gate = Some(AfterNGate::allowing(usize::MAX));
        let out = run_deepdive(
            client,
            Step4Input {
                chunks: vec![chunk("c1", 1, None)],
                ctx: ContextPackage::default(),
            },
            &cfg,
        )
        .await
        .unwrap();
        assert_eq!(out.outcomes["c1"], ChunkOutcome::Completed);
        assert!(out.budget_stop.is_none());
        assert_eq!(out.findings.len(), 1);
    }

    #[tokio::test]
    async fn stage4_run_reports_a_budget_stop_as_degraded() {
        let client = client_for(finding_body("a.py", 10, 0.9));
        let mut cfg = Step4Config::new("m");
        cfg.budget_gate = Some(AfterNGate::allowing(0));
        let outcome = Stage4::new(client, cfg)
            .run(Step4Input {
                chunks: vec![chunk("c1", 1, None)],
                ctx: ContextPackage::default(),
            })
            .await
            .unwrap();
        assert!(outcome.is_degraded());
        assert!(outcome
            .reason()
            .unwrap()
            .contains("0 of 1 deep-dive chunk(s) analyzed"));
        assert!(outcome.into_value().findings.is_empty());
    }

    #[tokio::test]
    async fn stage4_run_without_a_budget_stop_is_not_degraded() {
        let client = client_for(finding_body("a.py", 10, 0.9));
        let outcome = Stage4::new(client, Step4Config::new("m"))
            .run(Step4Input {
                chunks: vec![chunk("c1", 1, None)],
                ctx: ContextPackage::default(),
            })
            .await
            .unwrap();
        assert!(!outcome.is_degraded());
    }

    #[tokio::test]
    async fn empty_chunks_short_circuits() {
        let out = run_deepdive(
            client_for(empty_body()),
            Step4Input {
                chunks: Vec::new(),
                ctx: ContextPackage::default(),
            },
            &Step4Config::new("m"),
        )
        .await
        .unwrap();
        assert!(out.findings.is_empty());
        assert!(out.outcomes.is_empty());
    }

    #[tokio::test]
    async fn a_single_successful_chunk_produces_a_finding_and_a_completed_outcome() {
        let client = client_for(finding_body("a.py", 10, 0.9));
        let out = run_deepdive(
            client,
            Step4Input {
                chunks: vec![chunk("c1", 1, None)],
                ctx: ContextPackage::default(),
            },
            &Step4Config::new("m"),
        )
        .await
        .unwrap();
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.outcomes.get("c1"), Some(&ChunkOutcome::Completed));
    }

    #[tokio::test]
    async fn diff_scope_drops_a_finding_on_a_file_outside_the_chunk() {
        let client = client_for(finding_body("neighbor.py", 10, 0.9));
        let mut c = chunk("c1", 1, None);
        c.files = vec!["a.py".to_string()];
        let out = run_deepdive(
            client,
            Step4Input {
                chunks: vec![c],
                ctx: ctx_with_changed_file("a.py", 10),
            },
            &Step4Config::new("m"),
        )
        .await
        .unwrap();
        assert!(out.findings.is_empty());
        assert_eq!(out.outcomes.get("c1"), Some(&ChunkOutcome::Completed));
    }

    #[tokio::test]
    async fn diff_scope_keeps_a_finding_on_a_file_inside_the_chunk() {
        let client = client_for(finding_body("a.py", 10, 0.9));
        let mut c = chunk("c1", 1, None);
        c.files = vec!["a.py".to_string()];
        let out = run_deepdive(
            client,
            Step4Input {
                chunks: vec![c],
                ctx: ctx_with_changed_file("a.py", 10),
            },
            &Step4Config::new("m"),
        )
        .await
        .unwrap();
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.outcomes.get("c1"), Some(&ChunkOutcome::Completed));
    }

    #[tokio::test]
    async fn diff_scope_active_with_an_empty_changed_set_still_applies_the_backstop() {
        let client = client_for(finding_body("neighbor.py", 10, 0.9));
        let mut c = chunk("c1", 1, None);
        c.files = vec!["a.py".to_string()];
        let ctx = ContextPackage {
            diff_scope_active: true,
            ..Default::default()
        };
        assert!(ctx.changed_files.is_empty());
        let out = run_deepdive(
            client,
            Step4Input {
                chunks: vec![c],
                ctx,
            },
            &Step4Config::new("m"),
        )
        .await
        .unwrap();
        assert!(out.findings.is_empty());
    }

    #[tokio::test]
    async fn without_diff_scope_a_finding_outside_chunk_files_still_survives() {
        let client = client_for(finding_body("neighbor.py", 10, 0.9));
        let mut c = chunk("c1", 1, None);
        c.files = vec!["a.py".to_string()];
        let out = run_deepdive(
            client,
            Step4Input {
                chunks: vec![c],
                ctx: ContextPackage::default(),
            },
            &Step4Config::new("m"),
        )
        .await
        .unwrap();
        assert_eq!(out.findings.len(), 1);
    }

    #[tokio::test]
    async fn step4_runs_zero_still_makes_a_real_call_instead_of_scanning_nothing() {
        let client = client_for(finding_body("a.py", 10, 0.9));
        let mut cfg = Step4Config::new("m");
        cfg.runs = 0;
        let out = run_deepdive(
            client,
            Step4Input {
                chunks: vec![chunk("c1", 1, None)],
                ctx: ContextPackage::default(),
            },
            &cfg,
        )
        .await
        .unwrap();
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.outcomes.get("c1"), Some(&ChunkOutcome::Completed));
    }

    #[tokio::test]
    async fn every_run_failing_for_a_non_guardrail_reason_marks_the_chunk_as_error() {
        let client: Arc<dyn LlmClient> = Arc::new(RoutedClient::new(|_| {
            Err(LlmError::ConnectionError {
                message: "down".to_string(),
            })
        }));
        let mut cfg = Step4Config::new("m");
        cfg.runs = 2;
        cfg.max_transient_retries = 0;
        let out = run_deepdive(
            client,
            Step4Input {
                chunks: vec![chunk("c1", 1, None)],
                ctx: ContextPackage::default(),
            },
            &cfg,
        )
        .await
        .unwrap();
        assert!(out.findings.is_empty());
        assert_eq!(out.outcomes.get("c1"), Some(&ChunkOutcome::Error));
    }

    #[tokio::test]
    async fn a_guardrail_blocked_chunk_among_a_successful_one_is_recorded_not_aborted() {
        let client: Arc<dyn LlmClient> = Arc::new(RoutedClient::new(|text| {
            if text.contains("CHUNK: blocked") {
                Err(LlmError::GuardrailBlocked {
                    message: "nope".to_string(),
                })
            } else {
                Ok(finding_body("a.py", 10, 0.9))
            }
        }));
        let mut cfg = Step4Config::new("m");
        cfg.parallel = 1;
        let out = run_deepdive(
            client,
            Step4Input {
                chunks: vec![chunk("blocked", 1, None), chunk("ok", 2, None)],
                ctx: ContextPackage::default(),
            },
            &cfg,
        )
        .await
        .unwrap();
        assert_eq!(out.outcomes.get("blocked"), Some(&ChunkOutcome::Guardrail));
        assert_eq!(out.outcomes.get("ok"), Some(&ChunkOutcome::Completed));
    }

    #[tokio::test]
    async fn guardrail_gate_aborts_when_every_chunk_is_blocked_with_zero_successes() {
        let client: Arc<dyn LlmClient> = Arc::new(RoutedClient::new(|_| {
            Err(LlmError::GuardrailBlocked {
                message: "nope".to_string(),
            })
        }));
        let mut cfg = Step4Config::new("m");
        cfg.parallel = 3;
        let chunks = (0..3).map(|i| chunk(&format!("c{i}"), i, None)).collect();
        let result = run_deepdive(
            client,
            Step4Input {
                chunks,
                ctx: ContextPackage::default(),
            },
            &cfg,
        )
        .await;
        let err = result.unwrap_err();
        assert!(err.to_string().contains("guardrail"));
    }

    #[tokio::test]
    async fn a_finding_below_the_vote_threshold_does_not_survive_but_the_chunk_still_completes() {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = calls.clone();
        let client: Arc<dyn LlmClient> = Arc::new(RoutedClient::new(move |_| {
            let n = calls_clone.fetch_add(1, Ordering::SeqCst);
            Ok(if n == 0 {
                finding_body("a.py", 10, 0.9)
            } else {
                empty_body()
            })
        }));
        let mut cfg = Step4Config::new("m");
        cfg.runs = 2;
        cfg.vote_threshold = 2;
        let out = run_deepdive(
            client,
            Step4Input {
                chunks: vec![chunk("c1", 1, None)],
                ctx: ContextPackage::default(),
            },
            &cfg,
        )
        .await
        .unwrap();
        assert!(out.findings.is_empty());
        assert_eq!(out.outcomes.get("c1"), Some(&ChunkOutcome::Completed));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn failed_runs_lower_the_vote_threshold_to_the_runs_that_succeeded() {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = calls.clone();
        let client: Arc<dyn LlmClient> = Arc::new(RoutedClient::new(move |_| {
            match calls_clone.fetch_add(1, Ordering::SeqCst) {
                0 => Ok(finding_body("a.py", 10, 0.9)),
                _ => Err(LlmError::Other {
                    message: "socket dropped".into(),
                }),
            }
        }));
        let mut cfg = Step4Config::new("m");
        cfg.runs = 3;
        cfg.vote_threshold = 2;
        cfg.max_transient_retries = 0;
        let out = run_deepdive(
            client,
            Step4Input {
                chunks: vec![chunk("c1", 1, None)],
                ctx: ContextPackage::default(),
            },
            &cfg,
        )
        .await
        .unwrap();
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].votes, 1);
        assert_eq!(out.diagnostics.vote_threshold_clamped, 1);
    }

    #[tokio::test]
    async fn a_chunk_with_no_files_is_skipped_without_a_model_call() {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = calls.clone();
        let client: Arc<dyn LlmClient> = Arc::new(RoutedClient::new(move |_| {
            calls_clone.fetch_add(1, Ordering::SeqCst);
            Ok(finding_body("a.py", 10, 0.9))
        }));
        let mut empty = chunk("empty", 1, None);
        empty.files.clear();
        let out = run_deepdive(
            client,
            Step4Input {
                chunks: vec![empty, chunk("real", 2, None)],
                ctx: ContextPackage::default(),
            },
            &Step4Config::new("m"),
        )
        .await
        .unwrap();
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "only the real chunk is sent"
        );
        assert_eq!(out.outcomes.get("empty"), Some(&ChunkOutcome::Skipped));
        assert_eq!(out.outcomes.get("real"), Some(&ChunkOutcome::Completed));
        assert_eq!(out.diagnostics.empty_chunks_skipped, 1);
        assert!(
            out.budget_stop.is_none(),
            "an empty chunk is not a budget stop"
        );
    }

    #[tokio::test]
    async fn per_chunk_repair_and_truncation_counts_are_summed_into_the_output() {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = calls.clone();
        let two = serde_json::json!({"findings": [
            {"file": "a.py", "line_start": 10, "line_end": 10, "vuln_class": "injection",
             "title": "t", "description": "d", "code_snippet": "x", "confidence": 0.9},
            {"file": "a.py", "line_start": 90, "line_end": 90, "vuln_class": "injection",
             "title": "u", "description": "d", "code_snippet": "x", "confidence": 0.5},
        ]})
        .to_string();
        let client: Arc<dyn LlmClient> = Arc::new(RoutedClient::new(move |_| {
            Ok(match calls_clone.fetch_add(1, Ordering::SeqCst) {
                0 => r#"{"findigns": []}"#.to_string(),
                _ => two.clone(),
            })
        }));
        let mut cfg = Step4Config::new("m");
        cfg.max_findings_per_run = Some(1);
        cfg.parallel = 1;
        let out = run_deepdive(
            client,
            Step4Input {
                chunks: vec![chunk("c1", 1, None), chunk("c2", 2, None)],
                ctx: ContextPackage::default(),
            },
            &cfg,
        )
        .await
        .unwrap();
        assert_eq!(
            out.diagnostics,
            DeepdiveDiagnostics {
                json_repairs_attempted: 1,
                json_repairs_succeeded: 1,
                findings_truncated: 2,
                vote_threshold_clamped: 0,
                empty_chunks_skipped: 0,
                ..DeepdiveDiagnostics::default()
            }
        );
    }

    #[tokio::test]
    async fn a_finding_agreed_on_by_every_run_survives_with_the_true_vote_count() {
        let client = client_for(finding_body("a.py", 10, 0.9));
        let mut cfg = Step4Config::new("m");
        cfg.runs = 3;
        cfg.vote_threshold = 3;
        let out = run_deepdive(
            client,
            Step4Input {
                chunks: vec![chunk("c1", 1, None)],
                ctx: ContextPackage::default(),
            },
            &cfg,
        )
        .await
        .unwrap();
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].votes, 3);
    }

    #[tokio::test]
    async fn a_specialist_chunk_ignores_runs_and_vote_threshold_and_calls_only_once() {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = calls.clone();
        let client: Arc<dyn LlmClient> = Arc::new(RoutedClient::new(move |_| {
            calls_clone.fetch_add(1, Ordering::SeqCst);
            Ok(finding_body("a.py", 10, 0.9))
        }));
        let mut cfg = Step4Config::new("m");
        cfg.runs = 5;
        cfg.vote_threshold = 5;
        cfg.specialist_runs = 1;
        let out = run_deepdive(
            client,
            Step4Input {
                chunks: vec![chunk("c1", 1, Some("crypto"))],
                ctx: ContextPackage::default(),
            },
            &cfg,
        )
        .await
        .unwrap();
        assert_eq!(out.findings.len(), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn cross_chunk_collapse_merges_the_same_bug_and_keeps_the_higher_confidence() {
        let client: Arc<dyn LlmClient> = Arc::new(RoutedClient::new(|text| {
            if text.contains("CHUNK: c1") {
                Ok(finding_body("a.py", 142, 0.6))
            } else {
                Ok(finding_body("a.py", 145, 0.9))
            }
        }));
        let out = run_deepdive(
            client,
            Step4Input {
                chunks: vec![chunk("c1", 1, None), chunk("c2", 2, None)],
                ctx: ContextPackage::default(),
            },
            &Step4Config::new("m"),
        )
        .await
        .unwrap();
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].confidence, 0.9);
    }

    #[tokio::test]
    async fn stage4_run_wraps_success_as_ok() {
        let stage = Stage4::new(
            client_for(finding_body("a.py", 10, 0.9)),
            Step4Config::new("m"),
        );
        let outcome = stage
            .run(Step4Input {
                chunks: vec![chunk("c1", 1, None)],
                ctx: ContextPackage::default(),
            })
            .await
            .unwrap();
        assert!(!outcome.is_degraded());
        assert_eq!(outcome.into_value().findings.len(), 1);
    }

    #[tokio::test]
    async fn stage4_run_propagates_the_guardrail_abort_as_err() {
        let client: Arc<dyn LlmClient> = Arc::new(RoutedClient::new(|_| {
            Err(LlmError::GuardrailBlocked {
                message: "nope".to_string(),
            })
        }));
        let mut cfg = Step4Config::new("m");
        cfg.parallel = 3;
        let chunks = (0..3).map(|i| chunk(&format!("c{i}"), i, None)).collect();
        let stage = Stage4::new(client, cfg);
        let result = stage
            .run(Step4Input {
                chunks,
                ctx: ContextPackage::default(),
            })
            .await;
        assert!(result.is_err());
    }

    #[test]
    fn effective_runs_clamps_a_too_high_threshold_down_to_the_run_count() {
        assert_eq!(effective_runs(3, 5, None), (3, 3));
    }

    #[test]
    fn effective_runs_clamps_a_sub_one_threshold_up_to_one() {
        assert_eq!(effective_runs(3, 0, None), (3, 1));
    }

    #[test]
    fn effective_runs_with_zero_runs_forces_one_run_and_one_vote() {
        assert_eq!(effective_runs(0, 0, None), (1, 1));
        assert_eq!(effective_runs(0, 5, None), (1, 1));
    }

    #[test]
    fn effective_runs_leaves_an_already_reachable_threshold_untouched() {
        assert_eq!(effective_runs(5, 2, None), (5, 2));
    }

    #[test]
    fn effective_runs_collapses_multiple_runs_at_temperature_zero() {
        assert_eq!(effective_runs(3, 2, Some(0.0)), (1, 1));
    }

    #[test]
    fn effective_runs_keeps_multiple_runs_at_a_nonzero_temperature() {
        assert_eq!(effective_runs(3, 2, Some(0.4)), (3, 2));
    }

    #[test]
    fn effective_runs_at_temperature_zero_with_a_single_run_is_untouched() {
        assert_eq!(effective_runs(1, 1, Some(0.0)), (1, 1));
    }

    #[test]
    fn step4_config_defaults_to_discover_taint_prompt_mode() {
        assert_eq!(Step4Config::new("m").taint_prompt_mode, "discover");
        assert_eq!(Step4Config::new("m").taint_runs, None);
    }

    #[tokio::test]
    async fn confirm_refute_taint_prompt_mode_is_threaded_through_from_step4_config() {
        let client: Arc<dyn LlmClient> = Arc::new(RoutedClient::new(|text| {
            if text.contains("TASK: confirm or refute") {
                Ok(finding_body("a.py", 1, 0.9))
            } else {
                Ok(empty_body())
            }
        }));
        let mut c1 = chunk("c1", 1, None);
        c1.path_funcs = vec!["a.py::hop".to_string()];
        c1.source_ref = "a.py::src".to_string();
        c1.sink_ref = "a.py:1".to_string();
        c1.files = vec!["a.py".to_string()];
        let c2 = chunk("c2", 2, None);
        let mut cfg = Step4Config::new("m");
        cfg.taint_prompt_mode = "confirm_refute".to_string();
        let out = run_deepdive(
            client,
            Step4Input {
                chunks: vec![c1, c2],
                ctx: ContextPackage::default(),
            },
            &cfg,
        )
        .await
        .unwrap();
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].file, "a.py");
    }

    #[tokio::test]
    async fn a_taint_chunk_uses_taint_runs_instead_of_the_global_runs_count() {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = calls.clone();
        let client: Arc<dyn LlmClient> = Arc::new(RoutedClient::new(move |_| {
            calls_clone.fetch_add(1, Ordering::SeqCst);
            Ok(empty_body())
        }));
        let mut c1 = chunk("c1", 1, None);
        c1.path_funcs = vec!["a.py::hop".to_string()];
        let mut cfg = Step4Config::new("m");
        cfg.runs = 3;
        cfg.vote_threshold = 3;
        cfg.taint_runs = Some(1);
        run_deepdive(
            client,
            Step4Input {
                chunks: vec![c1],
                ctx: ContextPackage::default(),
            },
            &cfg,
        )
        .await
        .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_taint_chunk_with_no_taint_runs_set_falls_through_to_the_global_runs_count() {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = calls.clone();
        let client: Arc<dyn LlmClient> = Arc::new(RoutedClient::new(move |_| {
            calls_clone.fetch_add(1, Ordering::SeqCst);
            Ok(empty_body())
        }));
        let mut c1 = chunk("c1", 1, None);
        c1.path_funcs = vec!["a.py::hop".to_string()];
        let mut cfg = Step4Config::new("m");
        cfg.runs = 3;
        cfg.vote_threshold = 3;
        run_deepdive(
            client,
            Step4Input {
                chunks: vec![c1],
                ctx: ContextPackage::default(),
            },
            &cfg,
        )
        .await
        .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn stage4_run_with_no_progress_sink_emits_nothing() {
        let stage = Stage4::new(
            client_for(finding_body("a.py", 10, 0.9)),
            Step4Config::new("m"),
        );
        stage
            .run(Step4Input {
                chunks: vec![chunk("c1", 1, None)],
                ctx: ContextPackage::default(),
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn stage4_run_with_progress_emits_one_chunk_progress_event_per_completed_chunk() {
        let (tx, rx) = std::sync::mpsc::channel();
        let stage = Stage4::new(
            client_for(finding_body("a.py", 10, 0.9)),
            Step4Config::new("m"),
        )
        .with_progress(Some(tx));
        stage
            .run(Step4Input {
                chunks: vec![chunk("c1", 1, None), chunk("c2", 2, None)],
                ctx: ContextPackage::default(),
            })
            .await
            .unwrap();

        let mut events: Vec<_> = rx.try_iter().collect();
        assert_eq!(events.len(), 2);
        events.sort_by_key(|e| format!("{e:?}"));
        assert_eq!(
            events[0],
            appsec_pipeline_core::ScanEvent::ChunkProgress {
                stage: "s4-deepdive",
                completed: 1,
                total: 2,
            }
        );
        assert_eq!(
            events[1],
            appsec_pipeline_core::ScanEvent::ChunkProgress {
                stage: "s4-deepdive",
                completed: 2,
                total: 2,
            }
        );
    }

    #[tokio::test]
    async fn empty_chunks_emits_no_progress_events() {
        let (tx, rx) = std::sync::mpsc::channel();
        let stage =
            Stage4::new(client_for(empty_body()), Step4Config::new("m")).with_progress(Some(tx));
        stage
            .run(Step4Input {
                chunks: Vec::new(),
                ctx: ContextPackage::default(),
            })
            .await
            .unwrap();
        assert_eq!(rx.try_iter().count(), 0);
    }
}
