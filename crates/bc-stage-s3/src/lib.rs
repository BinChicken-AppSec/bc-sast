//! S3 — Decompose: a single-shot LLM call receives the `ContextPackage`
//! (no raw code) and produces a risk-ranked `TaskManifest`, then a fully
//! deterministic pipeline guarantees 100% file coverage regardless of
//! whether the LLM call produced anything usable — taint-path chunks,
//! oversize-chunk splitting, a catch-all sweep for anything still
//! uncovered, language tagging, and repo-wide specialist passes. Ported
//! from `vvaharness/pipeline/stages/s3_decompose.py`.
//!
//! Like S1/S7/S8, this stage has a genuine **internal** degrade policy —
//! and unlike what an earlier revision of this doc comment claimed, the
//! LLM *call* itself failing is NOT fatal here: Python's `run()` wraps
//! the `prompt()` call in its own `try`/`except` (`raw = "{}"` on
//! failure), which then falls straight into the SAME
//! `extract_json`/`TaskManifest.model_validate` `try`/`except` a
//! malformed *response* hits — both failure modes degrade identically to
//! an empty manifest with an explanatory `rationale`, via
//! `StageOutcome::Degraded` (there's no `degraded` field on
//! `TaskManifest` itself, unlike S8's `FinalReport`, so the signal lives
//! at the stage-outcome level here, matching S1's approach). Either way,
//! the full deterministic pipeline below still runs and still sweeps
//! every ground-truth file into some chunk — only the LLM's risk
//! *ranking* is lost on a degrade, not coverage.
//!
//! **Deliberately not ported**: every `print(..., file=sys.stderr)`
//! diagnostic in the Python original (pack-by-mode banner, taint
//! reachability percentage, catch-all/specialist summaries, chunk-LOC
//! histogram) — matching this project's established convention that
//! stderr-only diagnostics with no other side effect aren't ported
//! (`_report_chunk_loc` is *pure* diagnostic and is dropped entirely;
//! `_report_threat_coverage`'s real side effect — nulling an unknown
//! `threat_id` — is kept, in `report::drop_unknown_threat_ids`).
//!
//! The `step3.timeout` key IS ported, as [`Step3Config::timeout_secs`]. An
//! earlier revision of this comment claimed it had no home because "that's
//! a `bc-gateway-http` client-construction concern set once, not
//! per-request" — that was simply wrong about the Python original, which
//! applies it per call in BOTH backends (`backends/oai.py:278` and
//! `backends/sdk.py:274`, `client.with_options(timeout=float(timeout))`).
//! Left unported it was a real bug: a 64k-token decompose call against the
//! shared client's 300 s default failed on the clock, not on the model.

mod catchall;
mod diff_scope;
mod fallback;
mod grouping;
mod normalize;
mod pack;
mod prompts;
mod report;
mod source;
mod specialist;
mod taint_merge;
mod wire;

use std::path::Path;

use bc_llm_client::{ChatRequest, LlmClient, Message};
use bc_model::{ContextPackage, TaskManifest};
use bc_pipeline_core::{PipelineStage, StageError, StageOutcome};

pub struct Step3Config {
    pub model: String,
    pub max_tokens: u32,
    pub taint_chunks: bool,
    pub taint_max_hops: usize,
    pub taint_max_chunks: usize,
    pub taint_files_per_hop: usize,
    /// `"loc"` | `"tokens"`.
    pub pack_by: String,
    /// Whether [`pack`](pack) may coalesce adjacent under-filled buckets
    /// after its per-group split. Read once here rather than at each of
    /// the four `pack` call sites (oversize-risk split, catch-all,
    /// specialist default + `iac`) so every packing pass flips together:
    /// a lens whose buckets merged while another's did not would make the
    /// S4 call count impossible to reason about. Ported from
    /// `step3.pack_merge_underfilled` (`_STEP_DEFAULTS`' `true`, which no
    /// shipped Python profile overrides — so this constructor and
    /// `bc_config::step_defaults()` carry the SAME value, and a test in
    /// this crate pins that).
    ///
    /// Set it to `false` to restore the previous one-bucket-per-cohesion-
    /// group packing exactly: the escape hatch if detection quality
    /// regresses on a specific target, since a merged bucket puts more,
    /// less-related code in front of a single deep-dive call.
    pub pack_merge_underfilled: bool,
    pub chunk_token_budget: i64,
    pub chunk_overhead_tokens: i64,
    pub risk_chunk_loc: i64,
    pub catchall_enabled: bool,
    pub catchall_chunk_loc: i64,
    pub catchall_max_files: usize,
    /// `"all"` (default) | `"reachable_only"` — under the latter, the
    /// catch-all sweep drops any file not on an entry→…→sink path over
    /// the file-level call graph, recording the drops on
    /// `TaskManifest.unreachable_files`. `taint.yaml` opts in; never set
    /// in `default.yaml`. Ported from `step3.catchall_mode`.
    pub catchall_mode: String,
    /// Fail-open guard for the gate above: if the reachable set would be
    /// too sparse to trust (fraction of `eligible` below this ratio),
    /// fall back to `mode: all` instead of dropping most catch-all
    /// review. `0.0` disables the check (the default).
    pub catchall_reachable_min_ratio: f64,
    /// Same fail-open guard, as an absolute reachable-file-count floor
    /// instead of a ratio. `0` disables the check (the default).
    pub catchall_reachable_min_files: usize,
    pub max_files_per_chunk: usize,
    pub specialists: Vec<String>,
    pub specialist_chunk_loc: i64,
    /// Deterministically map any threat left uncovered by the LLM/taint/
    /// catch-all/specialist passes onto concrete files, so threat coverage
    /// never silently undercounts a threat nobody was ever told to look
    /// at. Ported from `s3_decompose.py::_add_threat_surface_fallback_chunks`
    /// — active in Python's `default.yaml`.
    pub threat_surface_fallbacks: bool,
    /// Per-threat candidate-file cap for the fallback pass above.
    pub threat_fallback_max_files: usize,
    /// `ctx.ast_context_view`'s narrowing caps, applied once before
    /// building the strategist prompt — ported from `run`'s own
    /// `max_prompt_files`/`max_prompt_entry_points`/`max_prompt_sinks`/
    /// `max_prompt_modules`/`max_prompt_call_edges`/`max_prompt_notes_chars`
    /// reads. Only the ONE prompt-building call uses the narrowed
    /// frontier — every other pass in this stage (taint chunks, catchall,
    /// specialist sweeps) still sees the full, unnarrowed `ctx`.
    pub frontier_max_files: usize,
    pub frontier_max_entry_points: usize,
    pub frontier_max_sinks: usize,
    pub frontier_max_modules: usize,
    pub frontier_max_edges: usize,
    pub frontier_max_notes_chars: usize,
    /// How many times the single strategist call retries after a
    /// retryable [`bc_llm_client::LlmError`] (429/5xx/connection failure)
    /// before giving up and degrading — see
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
    /// Per-call wall-clock deadline in seconds, overriding the shared
    /// gateway client's own 300 s default. Ported from `step3.timeout`
    /// (`_STEP_DEFAULTS`' `3600`, matched by every shipped profile), which
    /// this port previously had no home for — the module doc's claim that
    /// a per-call timeout is "a `bc-gateway-http` client-construction
    /// concern set once, not per-request" was wrong: both Python backends
    /// apply it per request via `client.with_options(timeout=...)`.
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
            max_files_per_chunk: 80,
            specialists: ["crypto", "logic-bug", "access-control", "batch-etl", "iac"]
                .into_iter()
                .map(String::from)
                .collect(),
            specialist_chunk_loc: 10_000,
            threat_surface_fallbacks: true,
            threat_fallback_max_files: 12,
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
            timeout_secs: Some(3600),
        }
    }
}

pub struct Step3Input {
    pub ctx: ContextPackage,
}

fn parse_response(raw: &str) -> Result<TaskManifest, String> {
    let data = bc_json_repair::extract_json(raw).map_err(|e| e.to_string())?;
    serde_json::from_value(data).map_err(|e| e.to_string())
}

/// The full S3 sequence. Ported from `s3_decompose.py::run`.
pub async fn run_decompose(
    client: &dyn LlmClient,
    input: Step3Input,
    config: &Step3Config,
) -> Result<StageOutcome<TaskManifest>, StageError> {
    let repo_root = Path::new(&input.ctx.repo_root);
    let frontier_config = bc_repo_analysis::FrontierConfig {
        max_files: config.frontier_max_files,
        max_entry_points: config.frontier_max_entry_points,
        max_sinks: config.frontier_max_sinks,
        max_modules: config.frontier_max_modules,
        max_edges: config.frontier_max_edges,
        max_notes_chars: config.frontier_max_notes_chars,
    };
    let prompt_ctx = bc_repo_analysis::ast_context_view(&input.ctx, &frontier_config);
    let user_prompt = prompts::to_decompose_prompt_block(&prompt_ctx, repo_root);
    let request = ChatRequest {
        model: config.model.clone(),
        system: Some(prompts::SYSTEM.to_string()),
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
    let raw_text = match bc_llm_agentic::chat_with_retry(
        client,
        &request,
        config.max_transient_retries,
        config.retry_backoff_base,
    )
    .await
    {
        Ok(response) => response.text(),
        Err(e) => {
            tracing::warn!(
                "[s3] strategist call failed ({e}); proceeding with deterministic \
                 coverage only (no LLM ranking)."
            );
            // Falls straight through into the SAME malformed-response
            // degrade path below (`{}` has neither `chunks` nor
            // `rationale`, so `parse_response` fails it the same way it
            // would fail any other unusable response) — matching
            // Python's own two-stage fallback exactly: `run()` wraps the
            // LLM call itself in `try/except`, setting `raw = "{}"` on
            // failure, which then flows into the SAME extract_json/
            // model_validate try/except a malformed response hits.
            "{}".to_string()
        }
    };

    let (mut manifest, degraded_reason) = match parse_response(&raw_text) {
        Ok(m) => (m, None),
        Err(e) => {
            let reason = format!(
                "s3 strategist output unusable ({e}); risk ranking unavailable. All files covered via deterministic taint/catch-all/specialist passes."
            );
            (
                TaskManifest {
                    chunks: Vec::new(),
                    rationale: reason.clone(),
                    unreachable_files: Vec::new(),
                },
                Some(reason),
            )
        }
    };

    normalize::normalize_chunk_files(&mut manifest, &input.ctx.all_files);
    manifest.chunks = taint_merge::merge_taint_chunks(manifest.chunks, &input.ctx, config);
    manifest.chunks = pack::split_oversize_risk_chunks(manifest.chunks, &input.ctx, config);
    let catchall_result = catchall::add_catchall_chunks(&manifest.chunks, &input.ctx, config);
    manifest.chunks.extend(catchall_result.chunks);
    manifest.unreachable_files = catchall_result.unreachable_files;

    for c in &mut manifest.chunks {
        c.languages = bc_repo_analysis::detect_languages(&c.files, Some(repo_root))
            .into_iter()
            .map(String::from)
            .collect();
    }

    let specialist_chunks = specialist::add_specialist_chunks(&manifest.chunks, &input.ctx, config);
    manifest.chunks.extend(specialist_chunks);

    let fallback_chunks =
        fallback::add_threat_surface_fallback_chunks(&manifest.chunks, &input.ctx, config);
    manifest.chunks.extend(fallback_chunks);

    report::drop_unknown_threat_ids(&mut manifest.chunks, &input.ctx);

    manifest.chunks = diff_scope::trim_chunks_to_diff_scope(manifest.chunks, &input.ctx, repo_root);

    match degraded_reason {
        Some(reason) => Ok(StageOutcome::Degraded {
            value: manifest,
            reason,
        }),
        None => Ok(StageOutcome::Ok(manifest)),
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use bc_llm_client::{ChatResponse, ContentBlock, LlmError, StopReason, Usage};

    #[test]
    fn step_defaults_agree_with_step3_config_new_on_pack_merge_underfilled() {
        // The config layer and this stage's own constructor must not
        // drift: `bc_config::step_defaults()` is what a user's YAML is
        // deep-merged onto (so it governs every `--config` run), and
        // `Step3Config::new()` is what runs when no config is loaded at
        // all. A packing switch that is on in one and off in the other
        // would make the S4 call count — and therefore the spend — of the
        // same scan depend on whether `--config` was passed. Python's
        // `_STEP_DEFAULTS` ships `true` and no shipped profile overrides
        // it, so unlike the three keys called out in
        // `bc_config::step_defaults`'s module comment there is no faithful
        // reason for these two to differ.
        let cfg = Step3Config::new("m");
        let d = bc_config::step_defaults();
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

    /// Fails with a retryable error `fail_times` times, then succeeds with
    /// a well-formed, empty `TaskManifest` reply — exercises
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
                    r#"{"chunks": [], "rationale": "ok"}"#.to_string(),
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

    fn no_specialists(cfg: &mut Step3Config) {
        // Isolate tests from the specialist pass unless they're explicitly
        // testing it — every specialist not in the gate table (i.e. not
        // "logic-bug") is content/surface-gated and could flake against
        // whatever text a test's fixture files happen to contain.
        cfg.specialists = Vec::new();
    }

    #[tokio::test]
    async fn llm_call_failure_degrades_but_still_covers_every_file() {
        // Regression: matches Python's `run()`, which wraps the LLM call
        // itself in a `try`/`except` (falling through to the SAME
        // malformed-response degrade path) rather than letting a
        // transient provider failure abort the whole scan and forfeit
        // every already-spent token on earlier stages.
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
        // Valid JSON object, but missing the required "chunks"/"rationale"
        // fields TaskManifest has no defaults for.
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
        // S3 only ever sends a single `Message::user_text(...)` (never a
        // tool result), so no real `run_decompose` call path exercises a
        // non-`Text` content block — exercised directly here against the
        // fixture itself instead, mirroring the same pattern in
        // `bc-stage-s2`/`bc-stage-s4`/`bc-stage-s6`'s own client fixtures.
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
        };
        client.chat(&request).await.unwrap();
        assert_eq!(client.captured.lock().unwrap().as_deref(), Some("hello"));
    }

    #[tokio::test]
    async fn ast_frontier_narrowing_drops_entry_points_outside_the_frontier_from_the_prompt() {
        use bc_model::{EntryPoint, EntryPointKind};

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
        // Only one file can ever survive the frontier — whichever entry
        // point's file is collected as a seed first.
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
        let outcome = run_decompose(&client, Step3Input { ctx }, &cfg)
            .await
            .unwrap();
        let manifest = outcome.into_value();
        // The hallucinated file is dropped from chunk-01 (now empty), and
        // both real files land in a catch-all chunk.
        assert!(manifest
            .chunks
            .iter()
            .find(|c| c.id == "chunk-01")
            .unwrap()
            .files
            .is_empty());
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
        ctx.entry_points = vec![bc_model::EntryPoint {
            file: "a.py".to_string(),
            function: "handler".to_string(),
            kind: bc_model::EntryPointKind::Network,
            reachable_from_unauth: true,
        }];
        ctx.unsafe_sinks = vec![bc_model::Sink {
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
        ctx.threat_model = Some(bc_model::ThreatModel {
            threats: vec![bc_model::Threat {
                id: "T1".to_string(),
                threat: "t".to_string(),
                actor: bc_model::Actor::RemoteUnauth,
                surface: "s".to_string(),
                asset: "a".to_string(),
                impact: bc_model::Impact::High,
                likelihood: bc_model::Likelihood::Likely,
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
}
