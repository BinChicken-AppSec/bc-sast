mod catchall;
pub use catchall::{catchall_eligible, catchall_skip_reason, CatchallSkip};
mod diagnostics;
mod diff_scope;
mod fallback;
mod grouping;
mod inventory;
mod normalize;
mod pack;
mod prompts;
mod report;
mod response;
mod specialist;
mod taint_merge;
mod wire;

pub use diagnostics::DecomposeDiagnostics;

use std::path::Path;

use appsec_llm_client::{ChatRequest, LlmClient, Message};
use appsec_model::{ContextPackage, TaskManifest};
use appsec_pipeline_core::{PipelineStage, StageError, StageOutcome};

pub struct Step3Config {
    pub model: String,
    pub max_tokens: u32,
    pub taint_chunks: bool,
    pub taint_max_hops: usize,
    pub taint_max_chunks: usize,
    pub taint_files_per_hop: usize,
    pub pack_by: String,
    pub pack_merge_underfilled: bool,
    pub chunk_token_budget: i64,
    pub chunk_overhead_tokens: i64,
    pub risk_chunk_loc: i64,
    pub catchall_enabled: bool,
    pub catchall_chunk_loc: i64,
    pub catchall_max_files: usize,
    pub catchall_mode: String,
    pub catchall_deduct_lens_coverage: bool,
    pub max_cohesion_groups: usize,
    pub catchall_reachable_min_ratio: f64,
    pub catchall_reachable_min_files: usize,
    pub max_files_per_chunk: usize,
    pub specialists: Vec<String>,
    pub specialist_chunk_loc: i64,
    pub threat_surface_fallbacks: bool,
    pub threat_fallback_max_files: usize,
    pub max_threat_fallback_chunks: usize,
    pub max_prompt_threats: usize,
    pub max_prompt_assets: usize,
    pub max_prompt_boundaries: usize,
    pub max_prompt_threat_context_chars: usize,
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
}

impl Step3Config {
    pub fn new(model: impl Into<String>) -> Self {
        Step3Config {
            model: model.into(),
            max_tokens: 64_000,
            taint_chunks: true,
            taint_max_hops: 10,
            taint_max_chunks: 60,
            taint_files_per_hop: 5,
            pack_by: "loc".to_string(),
            pack_merge_underfilled: true,
            chunk_token_budget: 180_000,
            chunk_overhead_tokens: 80_000,
            risk_chunk_loc: 10_000,
            catchall_enabled: true,
            catchall_chunk_loc: 4_000,
            catchall_max_files: 100,
            catchall_mode: "all".to_string(),
            catchall_reachable_min_ratio: 0.0,
            catchall_reachable_min_files: 0,
            catchall_deduct_lens_coverage: false,
            max_cohesion_groups: DEFAULT_MAX_COHESION_GROUPS,
            max_files_per_chunk: 80,
            specialists: DEFAULT_SPECIALISTS.iter().map(|s| s.to_string()).collect(),
            specialist_chunk_loc: 10_000,
            threat_surface_fallbacks: true,
            threat_fallback_max_files: 12,
            max_threat_fallback_chunks: DEFAULT_MAX_THREAT_FALLBACK_CHUNKS,
            max_prompt_threats: DEFAULT_MAX_PROMPT_THREATS,
            max_prompt_assets: DEFAULT_MAX_PROMPT_ASSETS,
            max_prompt_boundaries: DEFAULT_MAX_PROMPT_BOUNDARIES,
            max_prompt_threat_context_chars: DEFAULT_MAX_PROMPT_THREAT_CONTEXT_CHARS,
            frontier_max_files: 180,
            frontier_max_entry_points: 60,
            frontier_max_sinks: 80,
            frontier_max_modules: 24,
            frontier_max_edges: 80,
            frontier_max_notes_chars: 2500,
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

    pub fn max_cohesion_groups(&self) -> usize {
        cap_or_default(self.max_cohesion_groups, DEFAULT_MAX_COHESION_GROUPS)
    }
}

pub const DEFAULT_SPECIALISTS: &[&str] = &[
    "crypto",
    "logic-bug",
    "access-control",
    "batch-etl",
    "iac",
    "deserialization",
    "csrf",
    "sensitive-data",
    "hardcoded-creds",
    "log-injection",
    "injection",
];

pub const DEFAULT_MAX_COHESION_GROUPS: usize = 64;
pub const DEFAULT_MAX_THREAT_FALLBACK_CHUNKS: usize = 50;
pub const DEFAULT_MAX_PROMPT_THREATS: usize = 50;
pub const DEFAULT_MAX_PROMPT_ASSETS: usize = 20;
pub const DEFAULT_MAX_PROMPT_BOUNDARIES: usize = 30;
pub const DEFAULT_MAX_PROMPT_THREAT_CONTEXT_CHARS: usize = 2500;

pub(crate) fn cap_or_default(value: usize, default: usize) -> usize {
    if value == 0 {
        default
    } else {
        value
    }
}

pub struct Step3Input {
    pub ctx: ContextPackage,
}

pub async fn run_decompose(
    client: &dyn LlmClient,
    input: Step3Input,
    config: &Step3Config,
) -> Result<StageOutcome<TaskManifest>, StageError> {
    run_decompose_with_diagnostics(client, input, config)
        .await
        .map(|(outcome, _)| outcome)
}

pub async fn run_decompose_with_diagnostics(
    client: &dyn LlmClient,
    input: Step3Input,
    config: &Step3Config,
) -> Result<(StageOutcome<TaskManifest>, DecomposeDiagnostics), StageError> {
    let ctx = &input.ctx;
    let repo_root = Path::new(&ctx.repo_root);
    let mut diag = DecomposeDiagnostics::default();
    let frontier_config = appsec_repo_analysis::FrontierConfig {
        max_files: config.frontier_max_files,
        max_entry_points: config.frontier_max_entry_points,
        max_sinks: config.frontier_max_sinks,
        max_modules: config.frontier_max_modules,
        max_edges: config.frontier_max_edges,
        max_notes_chars: config.frontier_max_notes_chars,
    };
    let prompt_ctx = appsec_repo_analysis::ast_context_view(ctx, &frontier_config);
    let inventory = inventory::IdInventory::build(&prompt_ctx);
    let threat_caps = prompts::ThreatCaps {
        assets: cap_or_default(config.max_prompt_assets, DEFAULT_MAX_PROMPT_ASSETS),
        boundaries: cap_or_default(config.max_prompt_boundaries, DEFAULT_MAX_PROMPT_BOUNDARIES),
        threats: cap_or_default(config.max_prompt_threats, DEFAULT_MAX_PROMPT_THREATS),
        context_chars: cap_or_default(
            config.max_prompt_threat_context_chars,
            DEFAULT_MAX_PROMPT_THREAT_CONTEXT_CHARS,
        ),
    };
    let user_prompt =
        prompts::to_decompose_prompt_block(&prompt_ctx, repo_root, &inventory, threat_caps);
    let system = prompts::system_prompt_for(ctx);
    diag.no_threats_prompt = system == prompts::SYSTEM_NO_THREATS.as_str();
    let request = ChatRequest {
        model: config.model.clone(),
        system: Some(system.to_string()),
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
        cache_key: Some("s3".to_string()),
        ..ChatRequest::default()
    };
    let raw_text = match appsec_llm_agentic::salvage_truncated(
        appsec_llm_agentic::chat_with_retry(
            client,
            &request,
            config.max_transient_retries,
            config.retry_backoff_base,
        )
        .await,
        "s3",
    ) {
        Ok(response) => response.text(),
        Err(e) => {
            tracing::warn!(
                "[s3] strategist call failed ({e}); proceeding with deterministic \
                 coverage only (no LLM ranking)."
            );
            "{}".to_string()
        }
    };

    let (mut manifest, shapes, degraded_reason) = match response::parse(&raw_text, &inventory) {
        response::Parsed::Whole(manifest, shapes) => (manifest, shapes, None),
        response::Parsed::Salvaged {
            manifest,
            shapes,
            kept,
            total,
            error,
        } => {
            let dropped = total - kept;
            diag.invalid_chunks_dropped = dropped;
            tracing::warn!(
                "[s3] {dropped}/{total} strategist chunks failed validation and were \
                 dropped; {kept} kept ({error})"
            );
            (manifest, shapes, None)
        }
        response::Parsed::Unusable(e) => {
            let reason = format!(
                "s3 strategist output unusable ({e}); risk ranking unavailable. All files covered via deterministic taint/catch-all/specialist passes."
            );
            (
                TaskManifest {
                    chunks: Vec::new(),
                    rationale: reason.clone(),
                    unreachable_files: Vec::new(),
                },
                response::Shapes::default(),
                Some(reason),
            )
        }
    };

    let stats = normalize::normalize_chunk_files(
        &mut manifest,
        &ctx.all_files,
        &inventory,
        &shapes.shapes,
        &shapes.raw_paths,
    );
    diag.unknown_file_ids = stats.unknown_file_ids;
    diag.relocated_paths = stats.relocated_paths;
    diag.dropped_paths = stats.dropped_paths;
    diag.empty_chunks_dropped = normalize::drop_empty_chunks(&mut manifest);
    diag.llm_chunks = manifest.chunks.len();

    manifest.chunks = taint_merge::merge_taint_chunks(manifest.chunks, ctx, config);
    manifest.chunks = pack::split_oversize_risk_chunks(manifest.chunks, ctx, config);

    let mut catchall_result = None;
    if !config.catchall_deduct_lens_coverage {
        let result = catchall::add_catchall_chunks(&manifest.chunks, ctx, config);
        manifest.chunks.extend(result.chunks.iter().cloned());
        catchall_result = Some(result);
    }
    let specialist_result = specialist::add_specialist_chunks(&manifest.chunks, ctx, config);
    manifest.chunks.extend(specialist_result.chunks);
    diag.gated_off_lenses = specialist_result.gated_off;
    let fallback_result =
        fallback::add_threat_surface_fallback_chunks(&manifest.chunks, ctx, config);
    manifest.chunks.extend(fallback_result.chunks);
    diag.fallback_chunks_capped = fallback_result.capped;
    diag.fallback_files_trimmed = fallback_result.files_trimmed;
    let catchall_result = catchall_result.unwrap_or_else(|| {
        let result = catchall::add_catchall_chunks(&manifest.chunks, ctx, config);
        manifest.chunks.extend(result.chunks.iter().cloned());
        result
    });
    diag.forced_coverage_files = catchall_result.forced_coverage_files.len();
    diag.unreachable_files = catchall_result.unreachable_files.len();
    manifest.unreachable_files = catchall_result.unreachable_files;

    for c in &mut manifest.chunks {
        c.languages = appsec_repo_analysis::detect_languages(&c.files, Some(repo_root))
            .into_iter()
            .map(String::from)
            .collect();
    }

    report::drop_unknown_threat_ids(&mut manifest.chunks, ctx);
    (diag.threats_covered, diag.threats_counted) = report::threat_coverage(&manifest.chunks, ctx);
    diag.count_kinds(&manifest.chunks);

    manifest.chunks = diff_scope::trim_chunks_to_diff_scope(manifest.chunks, ctx, repo_root);

    let outcome = match degraded_reason {
        Some(reason) => StageOutcome::Degraded {
            value: manifest,
            reason,
        },
        None => StageOutcome::Ok(manifest),
    };
    Ok((outcome, diag))
}

pub struct Stage3 {
    client: std::sync::Arc<dyn LlmClient>,
    config: Step3Config,
}

impl Stage3 {
    pub fn new(client: std::sync::Arc<dyn LlmClient>, config: Step3Config) -> Self {
        Stage3 { client, config }
    }
}

impl PipelineStage for Stage3 {
    type Input = Step3Input;
    type Output = TaskManifest;
    const NAME: &'static str = "s3-decompose";

    async fn run(&self, input: Step3Input) -> Result<StageOutcome<TaskManifest>, StageError> {
        run_decompose(self.client.as_ref(), input, &self.config).await
    }
}

impl Stage3 {
    pub async fn run_with_diagnostics(
        &self,
        input: Step3Input,
    ) -> Result<(StageOutcome<TaskManifest>, DecomposeDiagnostics), StageError> {
        run_decompose_with_diagnostics(self.client.as_ref(), input, &self.config).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use appsec_llm_client::{ChatResponse, ContentBlock, LlmError, StopReason, Usage};
    use async_trait::async_trait;

    #[test]
    fn step_defaults_agree_with_step3_config_new_on_pack_merge_underfilled() {
        let cfg = Step3Config::new("m");
        let d = appsec_config::step_defaults();
        assert_eq!(
            d["step3"]["pack_merge_underfilled"],
            cfg.pack_merge_underfilled
        );
        assert!(cfg.pack_merge_underfilled);
    }

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
                    r#"{"chunks": [], "rationale": "ok"}"#.to_string(),
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
                            ContentBlock::Text(t) => Some(t.as_str()),
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

    fn ctx_with_root(root: &Path, all_files: Vec<&str>) -> ContextPackage {
        ContextPackage {
            seed_taint_paths: Default::default(),
            seed_taint_evidence: Default::default(),
            def_spans: Default::default(),
            repo_root: root.to_string_lossy().to_string(),
            language: "python".to_string(),
            call_graph: Default::default(),
            call_graph_files: Default::default(),
            entry_points: Vec::new(),
            unsafe_sinks: Vec::new(),
            modules: Vec::new(),
            all_files: all_files.into_iter().map(String::from).collect(),
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

    fn no_specialists(cfg: &mut Step3Config) {
        cfg.specialists = Vec::new();
    }

    #[tokio::test]
    async fn llm_call_failure_degrades_but_still_covers_every_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "print(1)\n").unwrap();
        let ctx = ctx_with_root(dir.path(), vec!["a.py"]);
        let mut cfg = Step3Config::new("m");
        no_specialists(&mut cfg);
        cfg.retry_backoff_base = std::time::Duration::ZERO;
        let outcome = run_decompose(&FailingClient, Step3Input { ctx }, &cfg)
            .await
            .unwrap();
        assert!(outcome.is_degraded());
        assert!(outcome
            .reason()
            .unwrap()
            .contains("strategist output unusable"));
        let manifest = outcome.into_value();
        let covered: std::collections::HashSet<&str> = manifest
            .chunks
            .iter()
            .flat_map(|c| c.files.iter().map(String::as_str))
            .collect();
        assert!(covered.contains("a.py"));
    }

    #[tokio::test]
    async fn malformed_response_degrades_but_still_covers_every_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "print(1)\n").unwrap();
        let ctx = ctx_with_root(dir.path(), vec!["a.py"]);
        let mut cfg = Step3Config::new("m");
        no_specialists(&mut cfg);
        let client = ScriptedClient {
            reply: "not json at all {{{".to_string(),
        };
        let outcome = run_decompose(&client, Step3Input { ctx }, &cfg)
            .await
            .unwrap();
        assert!(outcome.is_degraded());
        assert!(outcome
            .reason()
            .unwrap()
            .contains("strategist output unusable"));
        let manifest = outcome.into_value();
        assert!(manifest.rationale.contains("risk ranking unavailable"));
        let covered: std::collections::HashSet<&str> = manifest
            .chunks
            .iter()
            .flat_map(|c| c.files.iter().map(String::as_str))
            .collect();
        assert!(covered.contains("a.py"));
    }

    #[tokio::test]
    async fn missing_required_fields_also_degrades() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_with_root(dir.path(), vec![]);
        let mut cfg = Step3Config::new("m");
        no_specialists(&mut cfg);
        let client = ScriptedClient {
            reply: "{}".to_string(),
        };
        let outcome = run_decompose(&client, Step3Input { ctx }, &cfg)
            .await
            .unwrap();
        assert!(outcome.is_degraded());
    }

    #[tokio::test]
    async fn well_formed_response_is_not_degraded_and_normalizes_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "print(1)\n").unwrap();
        let ctx = ctx_with_root(dir.path(), vec!["a.py"]);
        let mut cfg = Step3Config::new("m");
        no_specialists(&mut cfg);
        let payload = serde_json::json!({
            "rationale": "focus on a.py",
            "chunks": [{"id": "chunk-01", "size": "small", "risk_rank": 1, "files": ["a.py"], "hypothesis": "h"}],
        });
        let client = ScriptedClient {
            reply: payload.to_string(),
        };
        let outcome = run_decompose(&client, Step3Input { ctx }, &cfg)
            .await
            .unwrap();
        assert!(!outcome.is_degraded());
        let manifest = outcome.into_value();
        assert_eq!(manifest.rationale, "focus on a.py");
        assert_eq!(manifest.chunks.len(), 1);
        assert_eq!(manifest.chunks[0].files, vec!["a.py".to_string()]);
        assert_eq!(manifest.chunks[0].languages, vec!["python".to_string()]);
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
        client.chat(&request).await.unwrap();
        assert_eq!(client.captured.lock().unwrap().as_deref(), Some("hello"));
    }

    #[tokio::test]
    async fn ast_frontier_narrowing_drops_entry_points_outside_the_frontier_from_the_prompt() {
        use appsec_model::{EntryPoint, EntryPointKind};

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "print(1)\n").unwrap();
        std::fs::write(dir.path().join("b.py"), "print(2)\n").unwrap();
        let mut ctx = ctx_with_root(dir.path(), vec!["a.py", "b.py"]);
        ctx.entry_points = vec![
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
        let mut cfg = Step3Config::new("m");
        no_specialists(&mut cfg);
        cfg.frontier_max_files = 1;
        let payload = serde_json::json!({
            "rationale": "r",
            "chunks": [],
        });
        let client = std::sync::Arc::new(CapturingClient {
            reply: payload.to_string(),
            captured: std::sync::Mutex::new(None),
        });
        let outcome = run_decompose(client.as_ref(), Step3Input { ctx }, &cfg)
            .await
            .unwrap();
        assert!(!outcome.is_degraded());

        let sent = client.captured.lock().unwrap().clone().unwrap();
        assert!(sent.contains("kept_handler @ a.py"));
        assert!(!sent.contains("dropped_handler @ b.py"));
    }

    #[test]
    fn step3_config_frontier_defaults_match_the_ported_python_caps() {
        let cfg = Step3Config::new("m");
        assert_eq!(cfg.frontier_max_files, 180);
        assert_eq!(cfg.frontier_max_entry_points, 60);
        assert_eq!(cfg.frontier_max_sinks, 80);
        assert_eq!(cfg.frontier_max_modules, 24);
        assert_eq!(cfg.frontier_max_edges, 80);
        assert_eq!(cfg.frontier_max_notes_chars, 2500);
    }

    #[tokio::test]
    async fn hallucinated_file_is_dropped_and_catchall_still_covers_ground_truth() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "print(1)\n").unwrap();
        std::fs::write(dir.path().join("b.py"), "print(2)\n").unwrap();
        let ctx = ctx_with_root(dir.path(), vec!["a.py", "b.py"]);
        let mut cfg = Step3Config::new("m");
        no_specialists(&mut cfg);
        let payload = serde_json::json!({
            "rationale": "r",
            "chunks": [{"id": "chunk-01", "size": "small", "risk_rank": 1, "files": ["hallucinated.py"], "hypothesis": "h"}],
        });
        let client = ScriptedClient {
            reply: payload.to_string(),
        };
        let outcome = run_decompose_with_diagnostics(&client, Step3Input { ctx }, &cfg)
            .await
            .unwrap();
        let (outcome, diag) = (outcome.0, outcome.1);
        let manifest = outcome.into_value();
        assert!(manifest.chunks.iter().all(|c| c.id != "chunk-01"));
        assert_eq!(diag.dropped_paths, 1);
        assert_eq!(diag.empty_chunks_dropped, 1);
        assert_eq!(diag.llm_chunks, 0);
        let covered: std::collections::HashSet<&str> = manifest
            .chunks
            .iter()
            .flat_map(|c| c.files.iter().map(String::as_str))
            .collect();
        assert!(covered.contains("a.py"));
        assert!(covered.contains("b.py"));
    }

    #[tokio::test]
    async fn taint_chunks_are_merged_ahead_of_llm_chunks_in_sort_order() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "def handler():\n    sink()\n").unwrap();
        let mut ctx = ctx_with_root(dir.path(), vec!["a.py"]);
        ctx.entry_points = vec![appsec_model::EntryPoint {
            file: "a.py".to_string(),
            function: "handler".to_string(),
            kind: appsec_model::EntryPointKind::Network,
            reachable_from_unauth: true,
        }];
        ctx.unsafe_sinks = vec![appsec_model::Sink {
            file: "a.py".to_string(),
            line: 2,
            function: "sink".to_string(),
            snippet: String::new(),
            cwe: Vec::new(),
        }];
        ctx.call_graph
            .insert("a.py::handler".to_string(), vec!["a.py::sink".to_string()]);
        let mut cfg = Step3Config::new("m");
        no_specialists(&mut cfg);
        let payload = serde_json::json!({
            "rationale": "r",
            "chunks": [{"id": "chunk-01", "size": "small", "risk_rank": 1, "files": ["a.py"], "hypothesis": "h"}],
        });
        let client = ScriptedClient {
            reply: payload.to_string(),
        };
        let outcome = run_decompose(&client, Step3Input { ctx }, &cfg)
            .await
            .unwrap();
        let manifest = outcome.into_value();
        let sorted = manifest.sorted_chunks();
        assert_eq!(sorted[0].id, "taint-01");
    }

    #[tokio::test]
    async fn specialist_chunks_are_added_when_enabled() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "print(1)\n").unwrap();
        let ctx = ctx_with_root(dir.path(), vec!["a.py"]);
        let mut cfg = Step3Config::new("m");
        cfg.specialists = vec!["logic-bug".to_string()];
        let payload = serde_json::json!({"rationale": "r", "chunks": []});
        let client = ScriptedClient {
            reply: payload.to_string(),
        };
        let outcome = run_decompose(&client, Step3Input { ctx }, &cfg)
            .await
            .unwrap();
        let manifest = outcome.into_value();
        assert!(manifest
            .chunks
            .iter()
            .any(|c| c.specialist.as_deref() == Some("logic-bug")));
    }

    #[tokio::test]
    async fn unknown_threat_id_from_the_llm_is_dropped() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "print(1)\n").unwrap();
        let mut ctx = ctx_with_root(dir.path(), vec!["a.py"]);
        ctx.threat_model = Some(appsec_model::ThreatModel {
            threats: vec![appsec_model::Threat {
                id: "T1".to_string(),
                threat: "t".to_string(),
                actor: appsec_model::Actor::RemoteUnauth,
                surface: "s".to_string(),
                asset: "a".to_string(),
                impact: appsec_model::Impact::High,
                likelihood: appsec_model::Likelihood::Likely,
                controls: String::new(),
                evidence: String::new(),
            }],
            ..Default::default()
        });
        let mut cfg = Step3Config::new("m");
        no_specialists(&mut cfg);
        let payload = serde_json::json!({
            "rationale": "r",
            "chunks": [{"id": "chunk-01", "size": "small", "risk_rank": 1, "files": ["a.py"], "hypothesis": "h", "threat_id": "T99"}],
        });
        let client = ScriptedClient {
            reply: payload.to_string(),
        };
        let outcome = run_decompose(&client, Step3Input { ctx }, &cfg)
            .await
            .unwrap();
        let manifest = outcome.into_value();
        assert_eq!(manifest.chunks[0].threat_id, None);
    }

    #[tokio::test]
    async fn stage3_run_wraps_a_successful_decompose_as_ok() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_with_root(dir.path(), vec![]);
        let mut cfg = Step3Config::new("m");
        no_specialists(&mut cfg);
        let payload = serde_json::json!({"rationale": "r", "chunks": []});
        let stage = Stage3::new(
            std::sync::Arc::new(ScriptedClient {
                reply: payload.to_string(),
            }),
            cfg,
        );
        let outcome = stage.run(Step3Input { ctx }).await.unwrap();
        assert!(!outcome.is_degraded());
    }

    #[tokio::test]
    async fn stage3_run_degrades_rather_than_erroring_on_a_call_failure() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_with_root(dir.path(), vec![]);
        let mut cfg = Step3Config::new("m");
        no_specialists(&mut cfg);
        cfg.retry_backoff_base = std::time::Duration::ZERO;
        let stage = Stage3::new(std::sync::Arc::new(FailingClient), cfg);
        let outcome = stage.run(Step3Input { ctx }).await.unwrap();
        assert!(outcome.is_degraded());
    }

    #[tokio::test]
    async fn llm_call_retries_a_transient_failure_then_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "print(1)\n").unwrap();
        let ctx = ctx_with_root(dir.path(), vec!["a.py"]);
        let mut cfg = Step3Config::new("m");
        no_specialists(&mut cfg);
        cfg.retry_backoff_base = std::time::Duration::ZERO;
        let client = RetryingClient::new(2);
        let outcome = run_decompose(&client, Step3Input { ctx }, &cfg)
            .await
            .unwrap();
        assert!(!outcome.is_degraded());
    }

    #[test]
    fn a_zero_cohesion_cap_means_the_default_and_the_default_lens_list_is_upstreams() {
        let mut cfg = Step3Config::new("m");
        assert_eq!(cfg.max_cohesion_groups(), 64);
        cfg.max_cohesion_groups = 0;
        assert_eq!(cfg.max_cohesion_groups(), 64);
        cfg.max_cohesion_groups = 7;
        assert_eq!(cfg.max_cohesion_groups(), 7);
        assert_eq!(cfg.specialists.len(), 11);
        assert!(cfg.specialists.iter().any(|s| s == "deserialization"));
        assert!(!cfg.catchall_deduct_lens_coverage);
        assert_eq!(cfg.catchall_mode, "all");
    }

    #[test]
    fn step_defaults_agree_with_step3_config_new_on_the_new_keys() {
        let cfg = Step3Config::new("m");
        let d = &appsec_config::step_defaults()["step3"];
        assert_eq!(
            d["catchall_deduct_lens_coverage"],
            cfg.catchall_deduct_lens_coverage
        );
        assert_eq!(d["max_cohesion_groups"], cfg.max_cohesion_groups);
        assert_eq!(
            d["max_threat_fallback_chunks"],
            cfg.max_threat_fallback_chunks
        );
        assert_eq!(d["max_prompt_threats"], cfg.max_prompt_threats);
        assert_eq!(d["max_prompt_assets"], cfg.max_prompt_assets);
        assert_eq!(d["max_prompt_boundaries"], cfg.max_prompt_boundaries);
        assert_eq!(
            d["max_prompt_threat_context_chars"],
            cfg.max_prompt_threat_context_chars
        );
        assert_eq!(d["threat_surface_fallbacks"], cfg.threat_surface_fallbacks);
        assert_eq!(
            d["threat_fallback_max_files"],
            cfg.threat_fallback_max_files
        );
    }

    fn strategist(reply: serde_json::Value) -> CapturingClient {
        CapturingClient {
            reply: reply.to_string(),
            captured: std::sync::Mutex::new(None),
        }
    }

    #[tokio::test]
    async fn file_ids_in_the_reply_resolve_against_the_prompts_inventory() {
        let dir = tempfile::tempdir().unwrap();
        for f in ["a.py", "b.py"] {
            std::fs::write(dir.path().join(f), "x = 1\n").unwrap();
        }
        let mut ctx = ctx_with_root(dir.path(), vec!["b.py", "a.py"]);
        ctx.entry_points = vec![appsec_model::EntryPoint {
            file: "b.py".to_string(),
            function: "handler".to_string(),
            kind: appsec_model::EntryPointKind::Network,
            reachable_from_unauth: true,
        }];
        let mut cfg = Step3Config::new("m");
        no_specialists(&mut cfg);
        let client = strategist(serde_json::json!({
            "chunks": [{"id": "chunk-01", "file_ids": ["F002", "F404"],
                        "focus_entry_point_ids": ["E001"], "hypothesis": "h"}],
        }));
        let (outcome, diag) = run_decompose_with_diagnostics(&client, Step3Input { ctx }, &cfg)
            .await
            .unwrap();
        let sent = client.captured.lock().unwrap().clone().unwrap();
        assert!(sent.starts_with("FILE INVENTORY"));
        assert!(sent.contains("  F002  b.py  (1 LOC)"));
        assert!(sent.contains("  E001  F002::handler  [network, UNAUTH]"));
        let manifest = outcome.into_value();
        assert_eq!(manifest.rationale, "");
        let c = manifest.chunks.iter().find(|c| c.id == "chunk-01").unwrap();
        assert_eq!(c.files, vec!["b.py".to_string()]);
        assert_eq!(c.focus_entry_points, vec!["handler".to_string()]);
        assert_eq!(diag.unknown_file_ids, 1);
        assert_eq!(diag.llm_chunks, 1);
        assert!(diag.no_threats_prompt);
    }

    #[tokio::test]
    async fn one_bad_chunk_no_longer_discards_the_whole_ranking() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "x = 1\n").unwrap();
        let ctx = ctx_with_root(dir.path(), vec!["a.py"]);
        let mut cfg = Step3Config::new("m");
        no_specialists(&mut cfg);
        let client = ScriptedClient {
            reply: serde_json::json!({"rationale": "r", "chunks": [
                {"id": "chunk-01", "file_ids": ["F001"], "risk_rank": 1},
                {"file_ids": ["F001"]},
            ]})
            .to_string(),
        };
        let (outcome, diag) = run_decompose_with_diagnostics(&client, Step3Input { ctx }, &cfg)
            .await
            .unwrap();
        assert!(!outcome.is_degraded());
        assert_eq!(diag.invalid_chunks_dropped, 1);
        let manifest = outcome.into_value();
        assert!(manifest.chunks.iter().any(|c| c.id == "chunk-01"));
    }

    #[tokio::test]
    async fn the_system_prompt_follows_whether_threats_exist() {
        let dir = tempfile::tempdir().unwrap();
        let mut ctx = ctx_with_root(dir.path(), vec![]);
        ctx.threat_model = Some(appsec_model::ThreatModel {
            threats: vec![appsec_model::Threat {
                id: "T1".to_string(),
                threat: "t".to_string(),
                actor: appsec_model::Actor::RemoteUnauth,
                surface: "s".to_string(),
                asset: "a".to_string(),
                impact: appsec_model::Impact::High,
                likelihood: appsec_model::Likelihood::Likely,
                controls: String::new(),
                evidence: String::new(),
            }],
            ..Default::default()
        });
        let mut cfg = Step3Config::new("m");
        no_specialists(&mut cfg);
        let client = strategist(serde_json::json!({"chunks": []}));
        let (_, diag) = run_decompose_with_diagnostics(&client, Step3Input { ctx }, &cfg)
            .await
            .unwrap();
        assert!(!diag.no_threats_prompt);
        assert_eq!((diag.threats_covered, diag.threats_counted), (0, 1));
    }

    #[tokio::test]
    async fn deducting_lens_coverage_runs_catchall_last_over_lens_claimed_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "x = 1\n").unwrap();
        let ctx = ctx_with_root(dir.path(), vec!["a.py"]);
        let mut cfg = Step3Config::new("m");
        cfg.specialists = vec!["logic-bug".to_string()];
        assert_eq!(
            chunk_ids(&ctx, &cfg).await,
            vec!["catchall-01", "spec-logic-bug-01"]
        );
        cfg.catchall_deduct_lens_coverage = true;
        assert_eq!(
            chunk_ids(&ctx, &cfg).await,
            vec!["spec-logic-bug-01", "catchall-01"]
        );
    }

    async fn chunk_ids(ctx: &ContextPackage, cfg: &Step3Config) -> Vec<String> {
        let client = strategist(serde_json::json!({"chunks": []}));
        run_decompose(&client, Step3Input { ctx: ctx.clone() }, cfg)
            .await
            .unwrap()
            .into_value()
            .chunks
            .into_iter()
            .map(|c| c.id)
            .collect()
    }

    #[tokio::test]
    async fn stage3_run_with_diagnostics_reports_kind_counts() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "x = 1\n").unwrap();
        let ctx = ctx_with_root(dir.path(), vec!["a.py"]);
        let mut cfg = Step3Config::new("m");
        cfg.specialists = vec!["logic-bug".to_string(), "crypto".to_string()];
        let stage = Stage3::new(
            std::sync::Arc::new(ScriptedClient {
                reply: "{\"chunks\": []}".to_string(),
            }),
            cfg,
        );
        let (outcome, diag) = stage
            .run_with_diagnostics(Step3Input { ctx })
            .await
            .unwrap();
        assert!(!outcome.is_degraded());
        assert_eq!(diag.catchall_chunks, 1);
        assert_eq!(diag.specialist_chunks, 1);
        assert_eq!(diag.lens_chunks["logic-bug"], 1);
        assert_eq!(diag.gated_off_lenses, vec!["crypto".to_string()]);
    }
}
