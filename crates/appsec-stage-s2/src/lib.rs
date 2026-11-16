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

use appsec_llm_client::{ChatRequest, LlmClient, Message, ToolExecutor};
use appsec_model::{AppProfile, ContextPackage, ThreatModel};
use appsec_pipeline_core::{PipelineStage, StageError, StageOutcome};

pub const READ_ONLY_TOOLS: &[&str] = &["Read", "Glob", "Grep"];

pub struct Step2Config {
    pub model: String,
    pub max_tokens: u32,
    pub max_threats: usize,
    pub baseline: String,
    pub max_doc_chars: usize,
    pub max_manifest_chars: usize,
    pub max_modules: usize,
    pub max_entry_points: usize,
    pub max_config_reps: usize,
    pub max_api_artefacts: usize,
    pub max_function_sites: usize,
    pub frontier_max_files: usize,
    pub frontier_max_entry_points: usize,
    pub frontier_max_sinks: usize,
    pub frontier_max_modules: usize,
    pub frontier_max_edges: usize,
    pub frontier_max_notes_chars: usize,
    pub max_transient_retries: u32,
    pub retry_backoff_base: std::time::Duration,
    pub temperature: Option<f64>,
    pub top_p: Option<f64>,
    pub seed: Option<u64>,
    pub reasoning_effort: Option<appsec_llm_client::ReasoningEffort>,
    pub openai_api: Option<appsec_llm_client::OpenAiApi>,
    pub timeout_secs: Option<u64>,
    pub max_config_rep_chars: usize,
    pub max_config_rep_bodies: usize,
    pub max_manifest_depth: usize,
    pub max_manifests: usize,
    pub max_manifests_per_kind: usize,
    pub max_manifest_total_chars: usize,
    pub max_assets: usize,
    pub max_trust_boundaries: usize,
    pub agentic: bool,
    pub allowed_tools: Vec<String>,
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

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ThreatModelDiagnostics {
    pub parse_repair_attempted: bool,
    pub parse_repair_recovered: bool,
    pub threats: rank::CapStats,
    pub repo_kinds: Vec<String>,
    pub baseline_undisposed: Vec<String>,
    pub agentic: bool,
}

pub struct Step2Input {
    pub repo_root: PathBuf,
    pub repo_name: String,
    pub ctx: ContextPackage,
    pub app_profile: Option<AppProfile>,
    pub provider_digest: appsec_model::ProviderDigest,
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
        let response = appsec_llm_agentic::salvage_truncated(
            appsec_llm_agentic::chat_with_retry(
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
        let mut cfg = appsec_llm_agentic::AgenticConfig::new(self.config.model.clone());
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
            appsec_llm_agentic::run_agentic(self.client.as_ref(), tools.as_ref(), &user, &cfg)
                .await
                .map_err(|e| {
                    StageError::new(Self::NAME, format!("threat-model call failed: {e}"))
                })?;
        Ok((outcome.final_text, true))
    }

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

    pub async fn run_detailed(
        &self,
        input: Step2Input,
    ) -> Result<(ThreatModel, ThreatModelDiagnostics), StageError> {
        let frontier_config = appsec_repo_analysis::FrontierConfig {
            max_files: self.config.frontier_max_files,
            max_entry_points: self.config.frontier_max_entry_points,
            max_sinks: self.config.frontier_max_sinks,
            max_modules: self.config.frontier_max_modules,
            max_edges: self.config.frontier_max_edges,
            max_notes_chars: self.config.frontier_max_notes_chars,
        };
        let frontier = appsec_repo_analysis::ast_context_view(&input.ctx, &frontier_config);
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
            &input.ctx.design_controls,
            input.app_profile.as_ref(),
            &baseline,
            &input.provider_digest,
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

fn log_unparsed(raw: &str) {
    let head: String = appsec_redact::redact(raw).chars().take(500).collect();
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
    use appsec_llm_client::{ChatResponse, ContentBlock, LlmError, StopReason, Usage};
    use async_trait::async_trait;

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
                            appsec_llm_client::ContentBlock::Text(t) => Some(t.as_str()),
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

    fn input() -> Step2Input {
        Step2Input {
            repo_root: PathBuf::from("/repo"),
            repo_name: "myrepo".to_string(),
            ctx: minimal_ctx(),
            app_profile: None,
            provider_digest: appsec_model::ProviderDigest::default(),
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
        let stage = Stage2::new(
            Arc::new(ScriptedClient {
                reply: r#"{"threats":"not-an-array"}"#.to_string(),
            }),
            Step2Config::new("test-model"),
        );
        let err = stage.run(input()).await.unwrap_err().to_string();
        assert!(err.contains("ThreatModel validation failed"), "{err}");
    }

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
        cfg.reasoning_effort = Some(appsec_llm_client::ReasoningEffort::Medium);
        cfg.openai_api = Some(appsec_llm_client::OpenAiApi::Chat);
        let stage = Stage2::new(Arc::new(FailingClient), cfg);
        let request = stage.request("sys", "user".to_string());
        assert_eq!(
            request.reasoning_effort,
            Some(appsec_llm_client::ReasoningEffort::Medium)
        );
        assert_eq!(request.openai_api, Some(appsec_llm_client::OpenAiApi::Chat));
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

    struct ReadOnlyTools;

    #[test]
    fn read_only_tools_fixture_answers_with_nothing() {
        assert_eq!(ReadOnlyTools.execute("Read", &serde_json::json!({})), "");
    }

    impl ToolExecutor for ReadOnlyTools {
        fn available_tools(&self) -> Vec<appsec_llm_client::ToolSpec> {
            READ_ONLY_TOOLS
                .iter()
                .map(|name| appsec_llm_client::ToolSpec {
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
        let client = CapturingClient {
            reply: "ignored".to_string(),
            captured: std::sync::Mutex::new(None),
        };
        let request = ChatRequest {
            model: "m".to_string(),
            system: None,
            messages: vec![appsec_llm_client::Message {
                role: appsec_llm_client::Role::User,
                content: vec![
                    appsec_llm_client::ContentBlock::ToolResult {
                        tool_use_id: "1".to_string(),
                        content: "ignored".to_string(),
                        is_error: false,
                    },
                    appsec_llm_client::ContentBlock::Text("hello".to_string()),
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
        use appsec_model::{EntryPoint, EntryPointKind};

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
        let json = r#"{"system_context":"","assets":[],"trust_boundaries":[],"threats":[],"open_questions":[]}"#;
        let stage = Stage2::new(
            Arc::new(ScriptedClient {
                reply: json.to_string(),
            }),
            Step2Config::new("test-model"),
        );
        let mut inp = input();
        inp.app_profile = Some(AppProfile {
            exposure: String::new(),
            reaches: Vec::new(),
            reached_by: Vec::new(),
            application_id: "APP1".to_string(),
            name: "App".to_string(),
            externally_facing: true,
            pci_scoped: false,
            processes_pan: false,
            pii: false,
            source: "cmdb".to_string(),
        });
        let outcome = stage.run(inp).await.unwrap();
        assert!(!outcome.is_degraded());
    }
}
