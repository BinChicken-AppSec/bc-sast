//! S2 — Threat model: a single-shot (non-agentic) LLM call over
//! deterministically-gathered evidence (S1's mapped modules/entry points,
//! on-disk docs/manifests, API-contract artefacts) produces an
//! application-level `ThreatModel`. Ported from
//! `vvaharness/pipeline/stages/s2_threatmodel.py::run`.
//!
//! Unlike S1/S3/S8, this stage has **no internal degrade policy** — a
//! malformed LLM response or an `extract_json`/`ThreatModel`-shape
//! failure propagates uncaught out of the Python original's `run()`, and
//! it's the *orchestrator* that catches it and falls back to no threat
//! model at all (`threat_model = None`). This crate mirrors that
//! precisely: every failure path here is `Err(StageError)`, never
//! `StageOutcome::Degraded` — the eventual orchestrator crate owns the
//! None-fallback, matching the Python call site exactly.

mod baseline;
mod evidence;
mod prompts;
mod wire;

use std::path::PathBuf;
use std::sync::Arc;

use bc_llm_client::{ChatRequest, LlmClient, Message};
use bc_model::{AppProfile, ContextPackage, Control, Cve, ThreatModel};
use bc_pipeline_core::{PipelineStage, StageError, StageOutcome};

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
    /// Per-call wall-clock deadline in seconds, overriding the shared
    /// gateway client's own 300 s default. `None` (the default) keeps
    /// that default — matching Python's `_STEP_DEFAULTS`, which has no
    /// `step2.timeout` key.
    pub timeout_secs: Option<u64>,
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
            timeout_secs: None,
        }
    }
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
}

impl Stage2 {
    pub fn new(client: Arc<dyn LlmClient>, config: Step2Config) -> Self {
        Stage2 { client, config }
    }
}

impl PipelineStage for Stage2 {
    type Input = Step2Input;
    type Output = ThreatModel;
    const NAME: &'static str = "s2-threatmodel";

    async fn run(&self, input: Step2Input) -> Result<StageOutcome<ThreatModel>, StageError> {
        let frontier_config = bc_repo_analysis::FrontierConfig {
            max_files: self.config.frontier_max_files,
            max_entry_points: self.config.frontier_max_entry_points,
            max_sinks: self.config.frontier_max_sinks,
            max_modules: self.config.frontier_max_modules,
            max_edges: self.config.frontier_max_edges,
            max_notes_chars: self.config.frontier_max_notes_chars,
        };
        let frontier = bc_repo_analysis::ast_context_view(&input.ctx, &frontier_config);
        let mut ev = evidence::gather_evidence(&input.repo_root, &self.config, &frontier);
        ev.original_file_count = input.ctx.all_files.len();
        let (_, baseline) =
            baseline::baseline_block(&ev, &input.ctx.all_files, &self.config.baseline);
        let user_prompt = prompts::build_user_prompt(
            &input.repo_root.to_string_lossy(),
            &input.repo_name,
            &ev,
            &input.known_cves,
            &input.design_controls,
            input.app_profile.as_ref(),
            &baseline,
        );

        let request = ChatRequest {
            model: self.config.model.clone(),
            system: Some(prompts::SYSTEM.to_string()),
            messages: vec![Message::user_text(&user_prompt)],
            tools: Vec::new(),
            max_tokens: self.config.max_tokens,
            temperature: self.config.temperature,
            top_p: self.config.top_p,
            seed: self.config.seed,
            thinking_budget: None,
            betas: Vec::new(),
            json_mode: false,
            timeout: self.config.timeout_secs.map(std::time::Duration::from_secs),
            stream: false,
        };
        let response = bc_llm_agentic::chat_with_retry(
            self.client.as_ref(),
            &request,
            self.config.max_transient_retries,
            self.config.retry_backoff_base,
        )
        .await
        .map_err(|e| StageError::new(Self::NAME, format!("threat-model call failed: {e}")))?;

        let data = bc_json_repair::extract_json(&response.text()).map_err(|e| {
            StageError::new(
                Self::NAME,
                format!("threat-model response not parseable: {e}"),
            )
        })?;
        let mut tm: ThreatModel = serde_json::from_value(data).map_err(|e| {
            StageError::new(Self::NAME, format!("ThreatModel assembly failed: {e}"))
        })?;

        if tm.threats.len() > self.config.max_threats {
            tm.threats.truncate(self.config.max_threats);
        }

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
    async fn malformed_response_is_a_fatal_error_not_a_degrade() {
        let stage = Stage2::new(
            Arc::new(ScriptedClient {
                reply: "not json".to_string(),
            }),
            Step2Config::new("test-model"),
        );
        let result = stage.run(input()).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not parseable"));
    }

    #[tokio::test]
    async fn well_formed_json_with_wrong_shape_is_a_fatal_error() {
        // Valid JSON, but `threats` has the wrong type (`ThreatModel` requires
        // every field to default when absent, so only a genuine type mismatch —
        // not a missing field — trips deserialization). Exercises the
        // `ThreatModel assembly failed` branch (extract_json succeeds,
        // serde_json::from_value::<ThreatModel> does not).
        let stage = Stage2::new(
            Arc::new(ScriptedClient {
                reply: r#"{"threats":"not-an-array"}"#.to_string(),
            }),
            Step2Config::new("test-model"),
        );
        let result = stage.run(input()).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("ThreatModel assembly failed"));
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
