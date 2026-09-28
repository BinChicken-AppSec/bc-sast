//! S2 — Threat model: an LLM call over deterministically-gathered
//! evidence (S1's mapped modules/entry points, on-disk docs/manifests,
//! redacted representative configuration, API-contract artifacts)
//! produces an application-level `ThreatModel`. Ported from v1.4.0
//! `vvaharness/pipeline/stages/s2_threatmodel.py::run`.
//!
//! The call is single-shot by default. With `step2.agentic: true` and a
//! tool executor supplied through [`Stage2::with_tools`], it becomes a
//! read-only agentic session (`allowed_tools` must be a subset of
//! Read/Glob/Grep, bounded by `max_turns`) so the model can open the
//! configuration files the evidence lists by path.
//!
//! A reply that fails to extract or validate gets exactly one repair
//! re-ask (single-shot, same budget: the repair must re-emit the whole
//! model, so a smaller budget would turn a shape slip into truncation).
//! After that, like the Python original, the stage has **no internal
//! degrade policy**: a second failure is `Err(StageError)`, and the
//! orchestrator falls back to no threat model at all, which every later
//! stage handles. An unparseable reply is not the same thing as a model
//! that found nothing.
//!
//! On success the threats are ranked deterministically and capped with
//! each trust boundary's sole cover preserved ([`rank`]), assets and
//! boundaries are capped, and the baseline checklist is audited (before
//! the cap) for items the model disposed of neither way.

mod baseline;
mod config_reps;
mod docs;
mod evidence;
mod manifests;
mod parse;
mod prompts;
pub mod rank;
mod repo_read;
mod wire;

use std::path::PathBuf;
use std::sync::Arc;

use bc_llm_client::{ChatRequest, LlmClient, Message, ToolExecutor};
use bc_model::{AppProfile, ContextPackage, Control, Cve, ThreatModel};
use bc_pipeline_core::{PipelineStage, StageError, StageOutcome};

/// The only tools an agentic threat-model session may be given. Anything
/// else in `step2.allowed_tools` fails the stage closed rather than being
/// silently dropped or, worse, honored.
pub const READ_ONLY_TOOLS: &[&str] = &["Read", "Glob", "Grep"];

pub struct Step2Config {
    pub model: String,
    pub max_tokens: u32,
    pub max_threats: usize,
    /// `"auto"` | `"owasp"` | `"none"`.
    pub baseline: String,
    pub max_doc_chars: usize,
    pub max_manifest_chars: usize,
    /// Prompt-display truncation cap, applied to the AST-frontier-narrowed
    /// module list — distinct from [`Self::frontier_max_modules`], which
    /// bounds the frontier itself (`_gather_evidence`'s `max_modules_prompt`
    /// vs. `max_modules`, two separate Python config keys with the same
    /// name suffix but different call sites).
    pub max_modules: usize,
    /// Prompt-display truncation cap — see [`Self::max_modules`]'s doc
    /// comment; the frontier-narrowing counterpart is
    /// [`Self::frontier_max_entry_points`].
    pub max_entry_points: usize,
    pub max_config_reps: usize,
    pub max_api_artefacts: usize,
    /// Truncation cap on `Evidence::function_sites` — a `gather_evidence`
    /// -local cap read alongside `max_config_reps`/`max_api_artefacts`
    /// (NOT one of the frontier-narrowing caps below: Python reads it via
    /// the same `_cap_int` pattern but never passes it to
    /// `ast_context_view`, ported from `s2_threatmodel.py:235`).
    pub max_function_sites: usize,
    /// `ctx.ast_context_view`'s narrowing caps, applied once before
    /// evidence gathering — ported from `_gather_evidence`'s own
    /// `max_graph_files`/`max_entry_points`/`max_graph_sinks`/
    /// `max_modules`/`max_graph_edges`/`max_notes_chars` `_cap_int` reads
    /// (all distinct config keys from the prompt-display caps above,
    /// despite the overlapping names in Python's own `step2` namespace).
    pub frontier_max_files: usize,
    pub frontier_max_entry_points: usize,
    pub frontier_max_sinks: usize,
    pub frontier_max_modules: usize,
    pub frontier_max_edges: usize,
    pub frontier_max_notes_chars: usize,
    /// How many times the single threat-model call retries after a
    /// retryable [`bc_llm_client::LlmError`] (429/5xx/connection failure)
    /// before giving up and propagating it — see
    /// [`bc_llm_agentic::chat_with_retry`].
    pub max_transient_retries: u32,
    /// Base delay before a transient-retry attempt; the actual delay is
    /// `retry_backoff_base * attempt_number` (linear backoff).
    pub retry_backoff_base: std::time::Duration,
    /// Sampling temperature for this stage's one call. `None` (the
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
    /// gateway client's own 300 s default. `None` (the default) keeps
    /// that default — matching Python's `_STEP_DEFAULTS`, which has no
    /// `step2.timeout` key.
    pub timeout_secs: Option<u64>,
    /// Per-body character cap for representative configuration contents,
    /// applied AFTER redaction of the whole file. `0` means path-only.
    pub max_config_rep_chars: usize,
    /// How many representatives carry a body (security-relevant names
    /// first); the rest are listed by path only.
    pub max_config_rep_bodies: usize,
    /// How many directories below the root the manifest search descends.
    pub max_manifest_depth: usize,
    /// Cap on manifests packed, across all kinds.
    pub max_manifests: usize,
    /// Cap on manifests of any one kind (floored at 1), so one ecosystem
    /// cannot crowd out another in a polyglot repo.
    pub max_manifests_per_kind: usize,
    /// Aggregate character cap across the whole manifests block.
    pub max_manifest_total_chars: usize,
    /// Cap on assets kept, most sensitive first.
    pub max_assets: usize,
    /// Cap on trust boundaries kept, widest reach first.
    pub max_trust_boundaries: usize,
    /// Swap the single-shot call for a read-only agentic session. Takes
    /// effect only when a tool executor was supplied via
    /// [`Stage2::with_tools`]; otherwise the stage warns and stays
    /// single-shot.
    pub agentic: bool,
    /// Tools the agentic session may use; must be a subset of
    /// [`READ_ONLY_TOOLS`].
    pub allowed_tools: Vec<String>,
    /// Turn bound for the agentic session (the only real bound on it).
    pub max_turns: u32,
}

impl Step2Config {
    pub fn new(model: impl Into<String>) -> Self {
        Step2Config {
            model: model.into(),
            max_tokens: 64_000,
            max_threats: 50,
            baseline: "auto".to_string(),
            max_doc_chars: 20_000,
            max_manifest_chars: 4_000,
            max_modules: 100,
            max_entry_points: 400,
            max_config_reps: 80,
            max_api_artefacts: 100,
            max_function_sites: 80,
            frontier_max_files: 220,
            // 400/100, not `_gather_evidence`'s own `_cap_int` FALLBACK
            // values (80/40). Those fallbacks only apply when the key is
            // absent, and it never is: `_STEP_DEFAULTS` merges
            // `max_entry_points: 400` / `max_modules: 100` under every
            // config, and `default.yaml` (the profile this constructor
            // ports) sets the same two numbers again. Porting the
            // fallbacks made this port's threat-model frontier 5x/2.5x
            // tighter than Python's on every run.
            frontier_max_entry_points: 400,
            frontier_max_sinks: 80,
            frontier_max_modules: 100,
            frontier_max_edges: 100,
            frontier_max_notes_chars: 2500,
            max_transient_retries: 4,
            retry_backoff_base: std::time::Duration::from_secs(10),
            temperature: None,
            top_p: None,
            seed: None,
            reasoning_effort: None,
            openai_api: None,
            timeout_secs: None,
            max_config_rep_chars: 2000,
            max_config_rep_bodies: 12,
            max_manifest_depth: 3,
            max_manifests: 12,
            max_manifests_per_kind: 2,
            max_manifest_total_chars: 24_000,
            max_assets: 40,
            max_trust_boundaries: 60,
            agentic: false,
            allowed_tools: READ_ONLY_TOOLS.iter().map(|t| t.to_string()).collect(),
            max_turns: 12,
        }
    }
}

/// Typed per-run counters from S2, for pipeline diagnostics. Returned by
/// [`Stage2::run_detailed`]; [`PipelineStage::run`] keeps its
/// `ThreatModel` output and drops them.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ThreatModelDiagnostics {
    /// The first reply failed to parse and the repair re-ask was made.
    pub parse_repair_attempted: bool,
    /// The repair re-ask produced a valid threat model.
    pub parse_repair_recovered: bool,
    /// Threat ranking and capping counts, see [`rank::CapStats`].
    pub threats: rank::CapStats,
    /// Repo kinds the baseline checklist was chosen for (empty with
    /// `baseline: none`).
    pub repo_kinds: Vec<String>,
    /// Baseline ids the model disposed of neither as a threat nor as an
    /// open question (audited before the cap).
    pub baseline_undisposed: Vec<String>,
    /// Whether the agentic session ran (rather than the single-shot call).
    pub agentic: bool,
}

pub struct Step2Input {
    pub repo_root: PathBuf,
    pub repo_name: String,
    pub known_cves: Vec<Cve>,
    pub design_controls: Vec<Control>,
    pub ctx: ContextPackage,
    pub app_profile: Option<AppProfile>,
}

pub struct Stage2 {
    client: Arc<dyn LlmClient>,
    config: Step2Config,
    tools: Option<Arc<dyn ToolExecutor>>,
}

impl Stage2 {
    pub fn new(client: Arc<dyn LlmClient>, config: Step2Config) -> Self {
        Stage2 {
            client,
            config,
            tools: None,
        }
    }

    /// Supplies the read-only tool executor `step2.agentic` needs (the
    /// same repo-jailed executor S1 and S6 are given). Without it the
    /// stage is always single-shot.
    pub fn with_tools(mut self, tools: Arc<dyn ToolExecutor>) -> Self {
        self.tools = Some(tools);
        self
    }

    fn request(&self, system: &str, user: String) -> ChatRequest {
        ChatRequest {
            model: self.config.model.clone(),
            system: Some(system.to_string()),
            messages: vec![Message::user_text(user)],
            tools: Vec::new(),
            max_tokens: self.config.max_tokens,
            temperature: self.config.temperature,
            top_p: self.config.top_p,
            seed: self.config.seed,
            reasoning_effort: self.config.reasoning_effort,
            openai_api: self.config.openai_api,
            thinking_budget: None,
            betas: Vec::new(),
            json_mode: false,
            timeout: self.config.timeout_secs.map(std::time::Duration::from_secs),
            stream: false,
            cache_key: Some("s2".to_string()),
            ..ChatRequest::default()
        }
    }

    async fn single_shot(&self, system: &str, user: String) -> Result<String, StageError> {
        let response = bc_llm_agentic::salvage_truncated(
            bc_llm_agentic::chat_with_retry(
                self.client.as_ref(),
                &self.request(system, user),
                self.config.max_transient_retries,
                self.config.retry_backoff_base,
            )
            .await,
            "s2",
        )
        .map_err(|e| StageError::new(Self::NAME, format!("threat-model call failed: {e}")))?;
        Ok(response.text())
    }

    /// The primary call: agentic when configured and wired, else
    /// single-shot. Returns the reply text and whether it was agentic.
    async fn primary_call(&self, user: String) -> Result<(String, bool), StageError> {
        let tools = match (self.config.agentic, &self.tools) {
            (true, Some(tools)) => tools,
            (true, None) => {
                tracing::warn!(
                    "[s2] step2.agentic is set but no tool executor was wired; \
                     running the single-shot threat model"
                );
                return Ok((self.single_shot(prompts::SYSTEM, user).await?, false));
            }
            (false, _) => return Ok((self.single_shot(prompts::SYSTEM, user).await?, false)),
        };
        if let Some(bad) = self
            .config
            .allowed_tools
            .iter()
            .find(|t| !READ_ONLY_TOOLS.contains(&t.as_str()))
        {
            return Err(StageError::new(
                Self::NAME,
                format!(
                    "step2.allowed_tools may only name read-only tools {READ_ONLY_TOOLS:?}; \
                     refusing {bad:?}"
                ),
            ));
        }
        let mut cfg = bc_llm_agentic::AgenticConfig::new(self.config.model.clone());
        cfg.system_prompt = Some(format!(
            "{}{}",
            prompts::SYSTEM,
            prompts::AGENTIC_SYSTEM_LINE
        ));
        cfg.allowed_tools = self.config.allowed_tools.clone();
        cfg.max_turns = self.config.max_turns;
        cfg.max_transient_retries = self.config.max_transient_retries;
        cfg.retry_backoff_base = self.config.retry_backoff_base;
        cfg.temperature = self.config.temperature;
        cfg.top_p = self.config.top_p;
        cfg.seed = self.config.seed;
        cfg.reasoning_effort = self.config.reasoning_effort;
        cfg.openai_api = self.config.openai_api;
        cfg.timeout_secs = self.config.timeout_secs;
        cfg.cache_key = Some("s2".to_string());
        let outcome =
            bc_llm_agentic::run_agentic(self.client.as_ref(), tools.as_ref(), &user, &cfg)
                .await
                .map_err(|e| {
                    StageError::new(Self::NAME, format!("threat-model call failed: {e}"))
                })?;
        Ok((outcome.final_text, true))
    }

    /// Parse `raw`, spending one single-shot repair re-ask on failure.
    async fn parse_or_repair(
        &self,
        raw: &str,
        diag: &mut ThreatModelDiagnostics,
    ) -> Result<ThreatModel, StageError> {
        let first_err = match parse::parse_threat_model(raw) {
            Ok(tm) => return Ok(tm),
            Err(e) => e,
        };
        diag.parse_repair_attempted = true;
        tracing::warn!("[s2] threat-model response did not parse, retrying repair: {first_err}");
        let repaired = self
            .single_shot(
                prompts::SYSTEM,
                prompts::repair_json_prompt(raw, &first_err),
            )
            .await
            .inspect_err(|_| log_unparsed(raw))?;
        let tm = parse::parse_threat_model(&repaired).map_err(|e| {
            log_unparsed(&repaired);
            StageError::new(
                Self::NAME,
                format!("threat-model response did not parse after one repair retry: {e}"),
            )
        })?;
        diag.parse_repair_recovered = true;
        Ok(tm)
    }

    /// The full stage, returning the diagnostics [`PipelineStage::run`]
    /// drops. The orchestrator can call this instead to surface them.
    pub async fn run_detailed(
        &self,
        input: Step2Input,
    ) -> Result<(ThreatModel, ThreatModelDiagnostics), StageError> {
        let frontier_config = bc_repo_analysis::FrontierConfig {
            max_files: self.config.frontier_max_files,
            max_entry_points: self.config.frontier_max_entry_points,
            max_sinks: self.config.frontier_max_sinks,
            max_modules: self.config.frontier_max_modules,
            max_edges: self.config.frontier_max_edges,
            max_notes_chars: self.config.frontier_max_notes_chars,
        };
        let frontier = bc_repo_analysis::ast_context_view(&input.ctx, &frontier_config);
        let mut ev = evidence::gather_evidence(
            &input.repo_root,
            &self.config,
            &frontier,
            &input.ctx.all_files,
        );
        ev.original_file_count = input.ctx.all_files.len();
        let (kinds, baseline) =
            baseline::baseline_block(&ev, &input.ctx.all_files, &self.config.baseline);
        let user_prompt = prompts::build_user_prompt(
            &input.repo_name,
            &ev,
            &input.known_cves,
            &input.design_controls,
            input.app_profile.as_ref(),
            &baseline,
        );

        let mut diag = ThreatModelDiagnostics {
            repo_kinds: kinds.iter().cloned().collect(),
            ..ThreatModelDiagnostics::default()
        };
        let (raw, agentic) = self.primary_call(user_prompt).await?;
        diag.agentic = agentic;
        let mut tm = self.parse_or_repair(&raw, &mut diag).await?;

        if tm.threats.is_empty() {
            tracing::warn!(
                "[s2] zero threats: downstream threat attribution, the threat-surface \
                 fallback and the access-control specialist force-on are all disabled"
            );
        }
        let undisposed = baseline::baseline_audit(&tm, &kinds);
        diag.threats = rank::cap_threats(&mut tm, self.config.max_threats);
        rank::cap_assets(&mut tm, self.config.max_assets);
        rank::cap_boundaries(&mut tm, self.config.max_trust_boundaries);
        if !undisposed.is_empty() {
            let ids: Vec<&String> = undisposed.iter().collect();
            tracing::warn!("[s2] baseline item(s) undisposed: {ids:?}");
        }
        diag.baseline_undisposed = undisposed.into_iter().collect();
        Ok((tm, diag))
    }
}

/// Log the head of a reply that could not be parsed, redacted in FULL
/// before the cut so a bisected secret cannot survive half-masked.
fn log_unparsed(raw: &str) {
    let head: String = bc_redact::redact(raw).chars().take(500).collect();
    tracing::warn!("[s2] unparseable threat-model reply, raw[:500]={head:?}");
}

impl PipelineStage for Stage2 {
    type Input = Step2Input;
    type Output = ThreatModel;
    const NAME: &'static str = "s2-threatmodel";

    async fn run(&self, input: Step2Input) -> Result<StageOutcome<ThreatModel>, StageError> {
        let (tm, _) = self.run_detailed(input).await?;
        Ok(StageOutcome::Ok(tm))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use bc_llm_client::{ChatResponse, ContentBlock, LlmError, StopReason, Usage};

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
                message: "boom".to_string(),
            })
        }
    }

    /// Fails with a retryable error `fail_times` times, then succeeds with
    /// a well-formed `ThreatModel` reply — exercises
    /// `bc_llm_agentic::chat_with_retry`'s real retry path from this
    /// crate's own call site, not just `bc-llm-agentic`'s own unit tests.
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
            Ok(ChatResponse {
                content: vec![ContentBlock::Text(
                    r#"{"system_context":"ctx","assets":[],"trust_boundaries":[],"threats":[],"open_questions":[]}"#.to_string(),
                )],
                stop_reason: StopReason::EndTurn,
                usage: Usage::default(),
            })
        }
    }

    /// Captures the outgoing user-prompt text so a test can assert on
    /// what actually got sent, not just that the call succeeded.
    struct CapturingClient {
        reply: String,
        captured: std::sync::Mutex<Option<String>>,
    }

    #[async_trait]
    impl LlmClient for CapturingClient {
        async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, LlmError> {
            let text = request
                .messages
                .last()
                .map(|m| {
                    m.content
                        .iter()
                        .filter_map(|c| match c {
                            bc_llm_client::ContentBlock::Text(t) => Some(t.as_str()),
                            _ => None,
                        })
                        .collect::<String>()
                })
                .unwrap_or_default();
            *self.captured.lock().unwrap() = Some(text);
            Ok(ChatResponse {
                content: vec![ContentBlock::Text(self.reply.clone())],
                stop_reason: StopReason::EndTurn,
                usage: Usage::default(),
            })
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
            all_files: vec!["app.py".to_string()],
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

    fn input() -> Step2Input {
        Step2Input {
            repo_root: PathBuf::from("/repo"),
            repo_name: "myrepo".to_string(),
            known_cves: Vec::new(),
            design_controls: Vec::new(),
            ctx: minimal_ctx(),
            app_profile: None,
        }
    }

    #[tokio::test]
    async fn well_formed_response_produces_ok() {
        let json = r#"{"system_context":"ctx","assets":[],"trust_boundaries":[],"threats":[],"open_questions":[]}"#;
        let stage = Stage2::new(
            Arc::new(ScriptedClient {
                reply: json.to_string(),
            }),
            Step2Config::new("test-model"),
        );
        let outcome = stage.run(input()).await.unwrap();
        assert!(!outcome.is_degraded());
        let tm = outcome.into_value();
        assert_eq!(tm.system_context, "ctx");
    }

    #[tokio::test]
    async fn malformed_response_twice_is_a_fatal_error_not_a_degrade() {
        let stage = Stage2::new(
            Arc::new(ScriptedClient {
                reply: "not json".to_string(),
            }),
            Step2Config::new("test-model"),
        );
        let result = stage.run(input()).await;
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("did not parse after one repair retry"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn well_formed_json_with_wrong_shape_twice_is_a_fatal_error() {
        // Valid JSON, but `threats` has the wrong type (`ThreatModel` requires
        // every field to default when absent, so only a genuine type mismatch,
        // not a missing field, trips deserialization).
        let stage = Stage2::new(
            Arc::new(ScriptedClient {
                reply: r#"{"threats":"not-an-array"}"#.to_string(),
            }),
            Step2Config::new("test-model"),
        );
        let err = stage.run(input()).await.unwrap_err().to_string();
        assert!(err.contains("ThreatModel validation failed"), "{err}");
    }

    /// Replays `replies` in order, recording each request's user text,
    /// system prompt and tool count.
    struct SeqClient {
        replies: std::sync::Mutex<std::collections::VecDeque<Result<String, LlmError>>>,
        seen: std::sync::Mutex<Vec<(String, String, usize)>>,
    }

    impl SeqClient {
        fn new(replies: Vec<Result<&str, LlmError>>) -> Arc<Self> {
            Arc::new(SeqClient {
                replies: std::sync::Mutex::new(
                    replies.into_iter().map(|r| r.map(str::to_string)).collect(),
                ),
                seen: std::sync::Mutex::new(Vec::new()),
            })
        }

        fn seen(&self) -> Vec<(String, String, usize)> {
            self.seen.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl LlmClient for SeqClient {
        async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, LlmError> {
            // Debug form of the content: no never-taken non-text arm.
            let user = format!("{:?}", request.messages[0].content);
            let system = request.system.clone().unwrap_or_default();
            self.seen
                .lock()
                .unwrap()
                .push((user, system, request.tools.len()));
            let text = self.replies.lock().unwrap().pop_front().unwrap()?;
            Ok(ChatResponse {
                content: vec![ContentBlock::Text(text)],
                stop_reason: StopReason::EndTurn,
                usage: Usage::default(),
            })
        }
    }

    const GOOD: &str = r#"{"system_context":"ctx","assets":[],"trust_boundaries":[],"threats":[],"open_questions":[]}"#;

    fn quick() -> Step2Config {
        let mut cfg = Step2Config::new("test-model");
        cfg.retry_backoff_base = std::time::Duration::ZERO;
        cfg.baseline = "none".to_string();
        cfg
    }

    #[test]
    fn the_single_shot_request_carries_the_role_effort_and_transport_pin() {
        let mut cfg = quick();
        cfg.reasoning_effort = Some(bc_llm_client::ReasoningEffort::Medium);
        cfg.openai_api = Some(bc_llm_client::OpenAiApi::Chat);
        let stage = Stage2::new(Arc::new(FailingClient), cfg);
        let request = stage.request("sys", "user".to_string());
        assert_eq!(
            request.reasoning_effort,
            Some(bc_llm_client::ReasoningEffort::Medium)
        );
        assert_eq!(request.openai_api, Some(bc_llm_client::OpenAiApi::Chat));
    }

    #[tokio::test]
    async fn a_shape_slip_is_repaired_once_and_recorded() {
        let client = SeqClient::new(vec![Ok(r#"{"assets": ["customer data"]}"#), Ok(GOOD)]);
        let stage = Stage2::new(client.clone(), quick());
        let (tm, diag) = stage.run_detailed(input()).await.unwrap();
        assert_eq!(tm.system_context, "ctx");
        assert!(diag.parse_repair_attempted && diag.parse_repair_recovered);
        let seen = client.seen();
        assert_eq!(seen.len(), 2);
        assert!(seen[1].0.starts_with("[Text(\"REPAIR TASK:"));
        assert!(seen[1].0.contains("customer data"));
        assert_eq!(seen[1].1, prompts::SYSTEM);
    }

    #[tokio::test]
    async fn a_failing_repair_call_is_fatal() {
        let client = SeqClient::new(vec![
            Ok("not json"),
            Err(LlmError::InvalidRequest {
                message: "rejected".into(),
            }),
        ]);
        let stage = Stage2::new(client, quick());
        let err = stage.run(input()).await.unwrap_err().to_string();
        assert!(err.contains("threat-model call failed"), "{err}");
    }

    /// Advertises the read-only tools and answers every call with nothing.
    /// The scripted replies never call a tool, so `execute` is exercised
    /// directly by `read_only_tools_fixture_answers_with_nothing`.
    struct ReadOnlyTools;

    #[test]
    fn read_only_tools_fixture_answers_with_nothing() {
        assert_eq!(ReadOnlyTools.execute("Read", &serde_json::json!({})), "");
    }

    impl ToolExecutor for ReadOnlyTools {
        fn available_tools(&self) -> Vec<bc_llm_client::ToolSpec> {
            READ_ONLY_TOOLS
                .iter()
                .map(|name| bc_llm_client::ToolSpec {
                    name: name.to_string(),
                    description: String::new(),
                    parameters: serde_json::json!({}),
                })
                .collect()
        }

        fn execute(&self, _name: &str, _args: &serde_json::Value) -> String {
            String::new()
        }
    }

    #[tokio::test]
    async fn agentic_mode_with_tools_runs_a_tool_session_with_the_extra_system_line() {
        let client = SeqClient::new(vec![Ok(GOOD)]);
        let mut cfg = quick();
        cfg.agentic = true;
        let stage = Stage2::new(client.clone(), cfg).with_tools(Arc::new(ReadOnlyTools));
        let (_, diag) = stage.run_detailed(input()).await.unwrap();
        assert!(diag.agentic);
        let seen = client.seen();
        assert!(seen[0].1.ends_with(prompts::AGENTIC_SYSTEM_LINE));
        assert_eq!(seen[0].2, 3, "Read, Glob and Grep are offered");
    }

    #[tokio::test]
    async fn agentic_mode_without_tools_stays_single_shot() {
        let client = SeqClient::new(vec![Ok(GOOD)]);
        let mut cfg = quick();
        cfg.agentic = true;
        let (_, diag) = Stage2::new(client.clone(), cfg)
            .run_detailed(input())
            .await
            .unwrap();
        assert!(!diag.agentic);
        assert_eq!(client.seen()[0].1, prompts::SYSTEM);
    }

    #[tokio::test]
    async fn agentic_mode_refuses_a_non_read_only_tool() {
        let client = SeqClient::new(vec![Ok(GOOD)]);
        let mut cfg = quick();
        cfg.agentic = true;
        cfg.allowed_tools = vec!["Read".into(), "Bash".into()];
        let stage = Stage2::new(client.clone(), cfg).with_tools(Arc::new(ReadOnlyTools));
        let err = stage.run(input()).await.unwrap_err().to_string();
        assert!(err.contains("refusing \"Bash\""), "{err}");
        assert!(client.seen().is_empty(), "no call is made");
    }

    #[tokio::test]
    async fn an_agentic_call_failure_is_fatal() {
        let client = SeqClient::new(vec![Err(LlmError::InvalidRequest {
            message: "nope".into(),
        })]);
        let mut cfg = quick();
        cfg.agentic = true;
        let stage = Stage2::new(client, cfg).with_tools(Arc::new(ReadOnlyTools));
        let err = stage.run(input()).await.unwrap_err().to_string();
        assert!(err.contains("threat-model call failed"), "{err}");
    }

    #[tokio::test]
    async fn baseline_ids_are_audited_before_the_cap_and_threats_are_ranked() {
        // Library repo: four baseline ids. The model disposes of two as
        // threats and one as an open question; BL-LIB-REDOS is undisposed.
        let reply = serde_json::json!({
            "system_context": "",
            "assets": [{"name": "db", "sensitivity": "critical"}, {"name": "logs", "sensitivity": "low"}],
            "trust_boundaries": [{"entry_point": "api", "crossing": "net"}],
            "threats": [
                {"id": "T1", "threat": "t", "actor": "remote_unauth", "surface": "api", "asset": "logs",
                 "impact": "low", "likelihood": "rare", "controls": "none", "evidence": "baseline: BL-LIB-INJ"},
                {"id": "T2", "threat": "t", "actor": "remote_unauth", "surface": "x", "asset": "db",
                 "impact": "high", "likelihood": "likely", "controls": "none", "evidence": "baseline: BL-LIB-PATH"},
            ],
            "open_questions": ["BL-LIB-DESER: no deserialization"],
        })
        .to_string();
        let client = SeqClient::new(vec![Ok(&reply)]);
        let mut cfg = quick();
        cfg.baseline = "auto".to_string();
        cfg.max_threats = 1;
        cfg.max_assets = 1;
        cfg.max_trust_boundaries = 0;
        let (tm, diag) = Stage2::new(client.clone(), cfg)
            .run_detailed(input())
            .await
            .unwrap();
        // T1 is the sole cover of "api" but boundaries are capped after
        // threats, so promotion still keeps it.
        assert_eq!(tm.threats.len(), 1);
        assert_eq!(tm.threats[0].id, "T1");
        assert_eq!(diag.threats.promoted, 1);
        assert_eq!(tm.assets.len(), 1);
        assert_eq!(tm.assets[0].name, "db");
        assert!(tm.trust_boundaries.is_empty());
        assert_eq!(diag.repo_kinds, vec!["library".to_string()]);
        assert_eq!(diag.baseline_undisposed, vec!["BL-LIB-REDOS".to_string()]);
        assert!(client.seen()[0].0.contains("[BL-LIB-INJ]"));
    }

    #[tokio::test]
    async fn llm_call_failure_is_fatal() {
        let mut config = Step2Config::new("test-model");
        config.retry_backoff_base = std::time::Duration::ZERO;
        let stage = Stage2::new(Arc::new(FailingClient), config);
        let result = stage.run(input()).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("threat-model call failed"));
    }

    #[tokio::test]
    async fn llm_call_retries_a_transient_failure_then_succeeds() {
        let client = RetryingClient::new(2);
        let mut config = Step2Config::new("test-model");
        config.retry_backoff_base = std::time::Duration::ZERO;
        let stage = Stage2::new(Arc::new(client), config);
        let outcome = stage.run(input()).await.unwrap();
        assert!(matches!(outcome, StageOutcome::Ok(_)));
    }

    #[tokio::test]
    async fn threats_beyond_max_threats_are_truncated() {
        let mut threats_json = Vec::new();
        for i in 1..=3 {
            threats_json.push(format!(
                r#"{{"id":"T{i}","threat":"t","actor":"remote_unauth","surface":"s","asset":"a","impact":"low","likelihood":"rare","controls":"none","evidence":""}}"#
            ));
        }
        let json = format!(
            r#"{{"system_context":"","assets":[],"trust_boundaries":[],"threats":[{}],"open_questions":[]}}"#,
            threats_json.join(",")
        );
        let mut cfg = Step2Config::new("test-model");
        cfg.max_threats = 2;
        let stage = Stage2::new(Arc::new(ScriptedClient { reply: json }), cfg);
        let outcome = stage.run(input()).await.unwrap();
        let tm = outcome.into_value();
        assert_eq!(tm.threats.len(), 2);
        assert_eq!(tm.threats[0].id, "T1");
        assert_eq!(tm.threats[1].id, "T2");
    }

    #[tokio::test]
    async fn threats_within_max_threats_are_not_truncated() {
        let json = r#"{"system_context":"","assets":[],"trust_boundaries":[],"threats":[{"id":"T1","threat":"t","actor":"remote_unauth","surface":"s","asset":"a","impact":"low","likelihood":"rare","controls":"none","evidence":""}],"open_questions":[]}"#;
        let stage = Stage2::new(
            Arc::new(ScriptedClient {
                reply: json.to_string(),
            }),
            Step2Config::new("test-model"),
        );
        let outcome = stage.run(input()).await.unwrap();
        assert_eq!(outcome.into_value().threats.len(), 1);
    }

    #[tokio::test]
    async fn capturing_client_fixture_ignores_non_text_content_blocks() {
        // S2 only ever sends a single `Message::user_text(...)` (never a
        // tool result), so no real `Stage2::run` call path exercises a
        // non-`Text` content block — exercised directly here against the
        // fixture itself instead, mirroring the same pattern in
        // `bc-stage-s4`/`bc-stage-s6`'s own routed-client fixtures.
        let client = CapturingClient {
            reply: "ignored".to_string(),
            captured: std::sync::Mutex::new(None),
        };
        let request = ChatRequest {
            model: "m".to_string(),
            system: None,
            messages: vec![bc_llm_client::Message {
                role: bc_llm_client::Role::User,
                content: vec![
                    bc_llm_client::ContentBlock::ToolResult {
                        tool_use_id: "1".to_string(),
                        content: "ignored".to_string(),
                        is_error: false,
                    },
                    bc_llm_client::ContentBlock::Text("hello".to_string()),
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
        client.chat(&request).await.unwrap();
        assert_eq!(client.captured.lock().unwrap().as_deref(), Some("hello"));
    }

    #[tokio::test]
    async fn ast_frontier_narrowing_drops_entry_points_outside_the_frontier() {
        use bc_model::{EntryPoint, EntryPointKind};

        let json = r#"{"system_context":"","assets":[],"trust_boundaries":[],"threats":[],"open_questions":[]}"#;
        let client = std::sync::Arc::new(CapturingClient {
            reply: json.to_string(),
            captured: std::sync::Mutex::new(None),
        });
        let mut cfg = Step2Config::new("test-model");
        // Only one file can ever survive the frontier — whichever entry
        // point's file is collected as a seed first.
        cfg.frontier_max_files = 1;
        let stage = Stage2::new(client.clone(), cfg);

        let mut inp = input();
        inp.ctx.all_files = vec!["a.py".to_string(), "b.py".to_string()];
        inp.ctx.entry_points = vec![
            EntryPoint {
                file: "a.py".to_string(),
                function: "kept_handler".to_string(),
                kind: EntryPointKind::Network,
                reachable_from_unauth: false,
            },
            EntryPoint {
                file: "b.py".to_string(),
                function: "dropped_handler".to_string(),
                kind: EntryPointKind::Network,
                reachable_from_unauth: false,
            },
        ];
        let outcome = stage.run(inp).await.unwrap();
        assert!(!outcome.is_degraded());

        let sent = client.captured.lock().unwrap().clone().unwrap();
        assert!(sent.contains("a.py::kept_handler"));
        assert!(
            !sent.contains("/repo"),
            "the absolute root is never rendered"
        );
        assert!(!sent.contains("b.py::dropped_handler"));
    }

    /// `Evidence::original_file_count` can only be set from the
    /// pre-narrowing `ContextPackage` `Stage2::run` itself holds — proves
    /// the real call site actually does this (not just `evidence.rs`'s
    /// own unit tests, which can't see past `gather_evidence`'s already-
    /// narrowed input).
    #[tokio::test]
    async fn run_reports_the_true_total_file_count_alongside_the_narrowed_frontier_count() {
        let json = r#"{"system_context":"","assets":[],"trust_boundaries":[],"threats":[],"open_questions":[]}"#;
        let client = std::sync::Arc::new(CapturingClient {
            reply: json.to_string(),
            captured: std::sync::Mutex::new(None),
        });
        let mut cfg = Step2Config::new("test-model");
        cfg.frontier_max_files = 1;
        let stage = Stage2::new(client.clone(), cfg);

        let mut inp = input();
        inp.ctx.all_files = vec!["a.py".to_string(), "b.py".to_string()];
        stage.run(inp).await.unwrap();

        let sent = client.captured.lock().unwrap().clone().unwrap();
        assert!(sent.contains("FILES IN AST FRONTIER: 1 (from 2 total in-scope files)"));
    }

    #[tokio::test]
    async fn step2_config_frontier_defaults_match_the_ported_python_caps() {
        let cfg = Step2Config::new("m");
        assert_eq!(cfg.frontier_max_files, 220);
        assert_eq!(cfg.frontier_max_entry_points, 400);
        assert_eq!(cfg.frontier_max_sinks, 80);
        assert_eq!(cfg.frontier_max_modules, 100);
        assert_eq!(cfg.frontier_max_edges, 100);
        assert_eq!(cfg.frontier_max_notes_chars, 2500);
        assert_eq!(cfg.max_function_sites, 80);
    }

    #[tokio::test]
    async fn app_profile_and_cves_flow_through_to_the_prompt() {
        // Indirect check: a request that includes a CMDB app profile and a
        // known CVE must still succeed end-to-end (the prompt-building
        // path that consumes them is exercised, not just constructed).
        let json = r#"{"system_context":"","assets":[],"trust_boundaries":[],"threats":[],"open_questions":[]}"#;
        let stage = Stage2::new(
            Arc::new(ScriptedClient {
                reply: json.to_string(),
            }),
            Step2Config::new("test-model"),
        );
        let mut inp = input();
        inp.app_profile = Some(AppProfile {
            application_id: "APP1".to_string(),
            name: "App".to_string(),
            externally_facing: true,
            pci_scoped: false,
            processes_pan: false,
            pii: false,
            source: "cmdb".to_string(),
        });
        inp.known_cves = vec![Cve {
            id: "CVE-1".to_string(),
            summary: "s".to_string(),
            affected_files: Vec::new(),
            cvss: None,
            patched: false,
        }];
        let outcome = stage.run(inp).await.unwrap();
        assert!(!outcome.is_degraded());
    }
}
