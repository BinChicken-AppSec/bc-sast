//! One single-shot deep-dive LLM call for one chunk, ported from
//! `s4_deepdive.py`'s `_single_run`.
//!
//! The Python original calls `prompt()` inside a `try/except
//! GuardrailBlocked` that only re-raises, then does everything else
//! (`extract_json`, per-item coercion/validation) with no enclosing
//! `try/except` of its own — any of THOSE exceptions propagate out of
//! `_single_run` and are caught by the *caller*'s per-run loop right
//! alongside a `GuardrailBlocked`, indistinguishable by the time they
//! reach `except Exception`. This port keeps that same "either the whole
//! run failed, or it produced a (possibly empty) finding list" shape, but
//! preserves *why* a run failed as [`RunError::GuardrailBlocked`] vs.
//! [`RunError::Other`] — the per-chunk driver needs that distinction to
//! fix the Python original's dead guardrail-fail-fast gate (see the crate
//! root docs).

use std::path::Path;
use std::sync::LazyLock;

use bc_llm_client::{ChatRequest, LlmClient, LlmError, Message, StopReason};
use bc_model::{Chunk, Finding};
use regex::Regex;

use crate::prompt_layout::DeepdivePrompt;
use crate::prompts::SYSTEM;
use crate::reanchor::reanchor_temporal;

static CWE_RX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bCWE[-\s]?(\d{1,5})\b").unwrap());

const VULN_CLASS_VALUES: &[&str] = &[
    "use-after-free",
    "heap-overflow",
    "stack-overflow",
    "format-string",
    "integer-overflow",
    "type-confusion",
    "race-condition",
    "injection",
    "unsafe-deserialization",
    "logic-flaw",
    "info-leak",
    "other",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunError {
    GuardrailBlocked(String),
    /// The provider says the account cannot fund any more work — kept
    /// distinct from [`RunError::Other`] because it is not this chunk's
    /// problem: every other chunk in the scan is about to hit the same
    /// wall, so the caller stops the stage rather than logging one
    /// failed run and starting the next. See
    /// [`bc_llm_client::LlmError::QuotaExhausted`].
    QuotaExhausted(String),
    /// A credential or proxy/TLS failure (VVAH-E001/E002, see
    /// [`bc_llm_client::LlmError::halts_scan`]): like quota exhaustion,
    /// every other chunk would fail the same way, so the caller stops the
    /// stage. Carries the error's own coded message.
    Halting(String),
    Other(String),
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunError::GuardrailBlocked(m) => write!(f, "guardrail blocked: {m}"),
            RunError::QuotaExhausted(m) => write!(f, "provider quota exhausted: {m}"),
            RunError::Halting(m) => write!(f, "{m}"),
            RunError::Other(m) => write!(f, "{m}"),
        }
    }
}

fn normalize_cwe(raw: Option<&serde_json::Value>) -> Option<String> {
    let s = raw
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    CWE_RX.captures(&s).map(|c| format!("CWE-{}", &c[1]))
}

/// `item.setdefault("chunk_id", ...)` + the `vuln_class`/`cwe` coercion
/// block from `_single_run`, mutating `item` in place.
///
/// Faithfully reproduces one subtle Python behavior: a *present but
/// invalid* `vuln_class` is coerced to `"other"`, but a *missing*
/// `vuln_class` key is left missing entirely — `item.get("vuln_class",
/// "other")` only ever writes the key back in the invalid-value branch,
/// so a finding with no `vuln_class` at all silently fails
/// `Finding.model_validate` (a required field) and is dropped by the
/// caller's per-item `try/except`, same as this port's `serde_json`
/// deserialize failing on that same missing field.
fn coerce_item(item: &mut serde_json::Value, chunk_id: &str) {
    let Some(obj) = item.as_object_mut() else {
        return;
    };
    // Provider identities are attached only by trusted import normalization.
    // A model finding must not impersonate an API-origin record, even when its
    // reply contains a structurally valid ProviderOrigin. Remove before typed
    // deserialization so malformed spoofed metadata cannot discard the finding.
    obj.remove("provider_origins");
    obj.entry("chunk_id").or_insert_with(|| chunk_id.into());

    let present = obj.contains_key("vuln_class");
    let is_valid = obj
        .get("vuln_class")
        .and_then(|v| v.as_str())
        .map(|s| VULN_CLASS_VALUES.contains(&s))
        .unwrap_or(false);
    if present && !is_valid {
        obj.insert("vuln_class".to_string(), "other".into());
    }

    let cwe = normalize_cwe(obj.get("cwe"));
    obj.insert(
        "cwe".to_string(),
        cwe.map_or(serde_json::Value::Null, serde_json::Value::String),
    );
}

fn map_llm_error(e: LlmError) -> RunError {
    match e {
        LlmError::GuardrailBlocked { message } => RunError::GuardrailBlocked(message),
        LlmError::QuotaExhausted { message } => RunError::QuotaExhausted(message),
        halting if halting.halts_scan() => RunError::Halting(halting.to_string()),
        other => RunError::Other(other.to_string()),
    }
}

/// The sampling knobs one deep-dive call carries, bundled so
/// [`single_run`]'s already-long parameter list doesn't grow by three
/// more scalars that always travel together.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Sampling {
    pub temperature: Option<f64>,
    pub top_p: Option<f64>,
    pub seed: Option<u64>,
    pub reasoning_effort: Option<bc_llm_client::ReasoningEffort>,
    pub openai_api: Option<bc_llm_client::OpenAiApi>,
    pub timeout: Option<std::time::Duration>,
}

impl Sampling {
    pub fn from_config(config: &crate::Step4Config) -> Self {
        Sampling {
            temperature: config.temperature,
            top_p: config.top_p,
            seed: config.seed,
            reasoning_effort: config.reasoning_effort,
            openai_api: config.openai_api,
            timeout: config.timeout_secs.map(std::time::Duration::from_secs),
        }
    }
}

/// `Err` if the LLM call itself failed (the caller must distinguish
/// [`RunError::GuardrailBlocked`] from every other failure to fix the
/// upstream guardrail-fail-fast gate); otherwise this run's findings,
/// individually dropping any item that isn't a JSON object or fails
/// `Finding` validation, then capping to `max_findings_per_run` by
/// descending confidence.
///
/// A reply that does not parse as a findings list (bad JSON, or valid
/// JSON of the wrong shape, see [`crate::findings_shape`]) gets exactly
/// one repair re-ask capped at [`crate::repair::REPAIR_MAX_TOKENS`]; if
/// the repaired reply still fails, the run fails rather than counting as
/// a clean zero-finding run. Repair and truncation counts accumulate into
/// `diag`.
///
/// `prompt` is built once per chunk by the caller (see
/// [`crate::prompt_layout::deepdive_prompt`], which also picks the
/// confirm/refute prompt for a taint chunk when the operator opted in):
/// every run of a chunk sends the same bytes.
#[allow(clippy::too_many_arguments)]
pub async fn single_run(
    client: &dyn LlmClient,
    chunk: &Chunk,
    prompt: &DeepdivePrompt,
    // The scan root, only so a temporal finding's own file can be
    // re-read and re-anchored — see `reanchor_temporal`.
    repo_root: &Path,
    model: &str,
    max_tokens: u32,
    max_findings_per_run: Option<usize>,
    max_transient_retries: u32,
    retry_backoff_base: std::time::Duration,
    sampling: Sampling,
    diag: &mut crate::DeepdiveDiagnostics,
) -> Result<Vec<Finding>, RunError> {
    let request = ChatRequest {
        model: model.to_string(),
        system: Some(SYSTEM.clone()),
        messages: vec![Message::user_text(&prompt.user)],
        cache_prefix: prompt.cache_prefix.clone(),
        cache_key: Some(prompt.cache_key.clone()),
        tools: Vec::new(),
        max_tokens,
        temperature: sampling.temperature,
        top_p: sampling.top_p,
        seed: sampling.seed,
        reasoning_effort: sampling.reasoning_effort,
        openai_api: sampling.openai_api,
        thinking_budget: None,
        betas: Vec::new(),
        // Ported from `s4_deepdive.py:489`'s own `output_format="json"`,
        // which `backends/oai.py::prompt` turns into `response_format:
        // {"type": "json_object"}` — dropped in the initial port, leaving
        // the one stage whose reply is parsed as a strict findings array
        // free to answer in prose that `extract_json` then has to rescue.
        // A no-op for the Anthropic dialect, which has no equivalent wire
        // flag (see `ChatRequest::json_mode`).
        json_mode: true,
        timeout: sampling.timeout,
        stream: false,
        ..ChatRequest::default()
    };

    let response = bc_llm_agentic::salvage_truncated(
        bc_llm_agentic::chat_with_retry(
            client,
            &request,
            max_transient_retries,
            retry_backoff_base,
        )
        .await,
        "s4",
    )
    .map_err(map_llm_error)?;

    let raw = response.text();
    let truncated = response.stop_reason == StopReason::MaxTokens;
    let items = match crate::repair::parse_findings(&raw, truncated) {
        Ok(items) => items,
        Err(failure) => {
            // Bound outside the macro: tracing skips evaluating its
            // arguments when no subscriber listens.
            let (id, detail) = (&chunk.id, bc_redact::redact(&failure.to_string()));
            tracing::warn!(
                "[s4] {id}: reply failed to parse as a findings object, retrying repair: {detail}"
            );
            diag.json_repairs_attempted += 1;
            let repair_request = ChatRequest {
                messages: vec![Message::user_text(crate::repair::repair_json_prompt(
                    &raw, &failure,
                ))],
                max_tokens: max_tokens.min(crate::repair::REPAIR_MAX_TOKENS),
                // The repair re-ask carries the broken reply, not the
                // chunk's context or code, so the prefix must not ride
                // along (upstream's repair dispatch passes none either).
                cache_prefix: None,
                ..request
            };
            let repaired = bc_llm_agentic::salvage_truncated(
                bc_llm_agentic::chat_with_retry(
                    client,
                    &repair_request,
                    max_transient_retries,
                    retry_backoff_base,
                )
                .await,
                "s4",
            )
            .map_err(map_llm_error)?;
            // A repaired reply that still carries no well-formed findings
            // list fails the run, exactly like one that still fails to
            // parse: the run/chunk handling records the coverage loss.
            let repaired_truncated = repaired.stop_reason == StopReason::MaxTokens;
            let items = crate::repair::parse_findings(&repaired.text(), repaired_truncated)
                .map_err(|e| RunError::Other(format!("after one repair re-ask: {e}")))?;
            diag.json_repairs_succeeded += 1;
            items
        }
    };

    let mut findings: Vec<Finding> = Vec::new();
    for mut item in items {
        if !item.is_object() {
            continue;
        }
        coerce_item(&mut item, &chunk.id);
        if let Ok(mut f) = serde_json::from_value::<Finding>(item) {
            // Deterministic correction of the one field the reply schema
            // asks for but cannot enforce. Here rather than downstream
            // because the vote (and every consumer after it) keys on the
            // line: a finding has to reach `vote_within_chunk` already
            // anchored, or two runs that disagree only about the anchor
            // split their own vote.
            reanchor_temporal(&mut f, repo_root);
            findings.push(f);
        }
    }

    if let Some(cap) = max_findings_per_run {
        if findings.len() > cap {
            // Everything past the cap is real model output being
            // discarded: count it so the recall loss reaches the
            // diagnostics instead of vanishing (upstream
            // `s4_findings_truncated`).
            diag.findings_truncated += findings.len() - cap;
            findings.sort_by(|a, b| {
                b.confidence
                    .partial_cmp(&a.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            findings.truncate(cap);
        }
    }

    Ok(findings)
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use bc_llm_client::{ChatResponse, ContentBlock, StopReason, Usage};
    use bc_model::ChunkSize;

    use super::*;

    #[test]
    fn sampling_carries_the_role_effort_and_transport_pin() {
        let mut config = crate::Step4Config::new("m");
        config.reasoning_effort = Some(bc_llm_client::ReasoningEffort::Max);
        config.openai_api = Some(bc_llm_client::OpenAiApi::Auto);
        let sampling = Sampling::from_config(&config);
        assert_eq!(
            sampling.reasoning_effort,
            Some(bc_llm_client::ReasoningEffort::Max)
        );
        assert_eq!(sampling.openai_api, Some(bc_llm_client::OpenAiApi::Auto));
    }

    // Boxed trait object (not a generic type param) so every test's
    // closure shares one compiled `chat` body — see
    // `feedback_coverage_tool_gotchas.md` on why a generic fixture here
    // would split line coverage across per-closure monomorphizations.
    type Reply = Box<dyn Fn() -> Result<String, LlmError> + Send + Sync>;

    struct ScriptedClient {
        reply: Reply,
    }

    impl ScriptedClient {
        fn text(body: impl Into<String>) -> Self {
            let body = body.into();
            ScriptedClient {
                reply: Box::new(move || Ok(body.clone())),
            }
        }

        fn erroring(err: impl Fn() -> LlmError + Send + Sync + 'static) -> Self {
            ScriptedClient {
                reply: Box::new(move || Err(err())),
            }
        }
    }

    #[async_trait]
    impl LlmClient for ScriptedClient {
        async fn chat(&self, _request: &ChatRequest) -> Result<ChatResponse, LlmError> {
            let text = (self.reply)()?;
            Ok(ChatResponse {
                content: vec![ContentBlock::Text(text)],
                stop_reason: StopReason::EndTurn,
                usage: Usage::default(),
            })
        }
    }

    fn chunk() -> Chunk {
        Chunk {
            id: "chunk-01".to_string(),
            size: ChunkSize::Small,
            risk_rank: 1,
            files: vec!["a.py".to_string()],
            focus_entry_points: Vec::new(),
            hypothesis: String::new(),
            related_cves: Vec::new(),
            threat_id: None,
            languages: Vec::new(),
            specialist: None,
            path_funcs: Vec::new(),
            source_ref: String::new(),
            sink_ref: String::new(),
            sink_cwe: Vec::new(),
            shard_id: String::new(),
        }
    }

    fn finding_json(vuln_class: &str, confidence: f64, cwe: &str) -> serde_json::Value {
        serde_json::json!({
            "file": "a.py",
            "line_start": 10,
            "line_end": 12,
            "vuln_class": vuln_class,
            "title": "t",
            "description": "d",
            "code_snippet": "x",
            "confidence": confidence,
            "cwe": cwe,
        })
    }

    fn prompt_for(c: &Chunk, taint_prompt_mode: &str) -> DeepdivePrompt {
        crate::prompt_layout::deepdive_prompt(
            c,
            &bc_model::ContextPackage::default(),
            "code",
            taint_prompt_mode,
            false,
            "SHARED",
        )
    }

    /// Answers with an unparseable reply first, then a valid one, keeping
    /// every request it saw.
    struct RepairCapture {
        seen: std::sync::Mutex<Vec<ChatRequest>>,
    }

    #[async_trait]
    impl LlmClient for RepairCapture {
        async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, LlmError> {
            let mut seen = self.seen.lock().unwrap();
            seen.push(request.clone());
            let body = if seen.len() == 1 {
                "not json at all".to_string()
            } else {
                serde_json::json!({"findings": []}).to_string()
            };
            Ok(ChatResponse {
                content: vec![ContentBlock::Text(body)],
                stop_reason: StopReason::EndTurn,
                usage: Usage::default(),
            })
        }
    }

    #[tokio::test]
    async fn the_request_carries_the_prompt_prefix_and_key_but_the_repair_drops_the_prefix() {
        let client = RepairCapture {
            seen: std::sync::Mutex::new(Vec::new()),
        };
        let mut c = chunk();
        c.shard_id = "shard-03".to_string();
        let prompt = prompt_for(&c, "discover");
        let mut diag = crate::DeepdiveDiagnostics::default();
        single_run(
            &client,
            &c,
            &prompt,
            std::path::Path::new("."),
            "m",
            1000,
            None,
            0,
            std::time::Duration::ZERO,
            Sampling::default(),
            &mut diag,
        )
        .await
        .unwrap();
        let seen = client.seen.into_inner().unwrap();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0].cache_prefix, prompt.cache_prefix);
        assert!(seen[0]
            .cache_prefix
            .as_deref()
            .unwrap()
            .starts_with("SHARED\n\nSOURCE CODE:\ncode"));
        assert_eq!(seen[0].cache_key.as_deref(), Some("s4:shard-03"));
        assert_eq!(
            seen[0].messages[0].content,
            vec![ContentBlock::Text(prompt.user)]
        );
        assert_eq!(seen[1].cache_prefix, None);
        assert_eq!(seen[1].cache_key.as_deref(), Some("s4:shard-03"));
        assert_eq!(diag.json_repairs_succeeded, 1);
    }

    async fn run(client: &dyn LlmClient, cap: Option<usize>) -> Result<Vec<Finding>, RunError> {
        single_run(
            client,
            &chunk(),
            &prompt_for(&chunk(), "discover"),
            std::path::Path::new("."),
            "m",
            1000,
            cap,
            0,
            std::time::Duration::ZERO,
            Sampling::default(),
            &mut crate::DeepdiveDiagnostics::default(),
        )
        .await
    }

    /// Always stops at its output budget, echoing a findings document cut
    /// off after its first complete finding.
    struct AlwaysTruncatedClient;

    #[async_trait]
    impl LlmClient for AlwaysTruncatedClient {
        async fn chat(&self, _request: &ChatRequest) -> Result<ChatResponse, LlmError> {
            let whole = serde_json::json!({"findings": [finding_json("injection", 0.9, "CWE-89")]})
                .to_string();
            // Drop the closing `]}` and start a second finding, as a reply
            // cut off mid-document looks.
            let cut = format!("{},{{\"file\": \"b.py\", \"li", &whole[..whole.len() - 2]);
            Ok(ChatResponse {
                content: vec![ContentBlock::Text(cut)],
                stop_reason: StopReason::MaxTokens,
                usage: Usage::default(),
            })
        }
    }

    /// A reply still truncated after the doubled-budget retry (VVAH-E005)
    /// keeps the findings it did finish instead of failing the run.
    #[tokio::test]
    async fn a_reply_truncated_twice_keeps_its_completed_findings() {
        let findings = run(&AlwaysTruncatedClient, None).await.unwrap();
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].file, "a.py");
    }

    #[tokio::test]
    async fn a_findings_object_wrapper_is_parsed() {
        let body =
            serde_json::json!({"findings": [finding_json("injection", 0.9, "CWE-89")]}).to_string();
        let client = ScriptedClient::text(body);
        let findings = run(&client, None).await.unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].vuln_class, bc_model::VulnClass::Injection);
        assert_eq!(findings[0].cwe.as_deref(), Some("CWE-89"));
        assert_eq!(findings[0].chunk_id, "chunk-01");
    }

    #[tokio::test]
    async fn model_supplied_provider_provenance_is_discarded_before_validation() {
        for supplied in [
            serde_json::json!([{
                "provider":"semgrep", "product":"sast", "source":"api",
                "native_ids":{"issue_id":"123"}, "tenant_id":"deployment",
                "revision":"claimed-revision", "state":"open"
            }]),
            serde_json::json!({"malformed":"metadata must not discard a real finding"}),
        ] {
            let mut finding = finding_json("injection", 0.9, "CWE-89");
            finding["provider_origins"] = supplied;
            let client =
                ScriptedClient::text(serde_json::json!({"findings":[finding]}).to_string());
            let findings = run(&client, None).await.unwrap();
            assert_eq!(findings.len(), 1);
            assert!(findings[0].provider_origins.is_empty());
            assert_eq!(findings[0].file, "a.py");
            assert_eq!(findings[0].cwe.as_deref(), Some("CWE-89"));
        }
    }

    #[tokio::test]
    async fn a_bare_top_level_array_is_also_accepted() {
        let body = serde_json::json!([finding_json("other", 0.5, "")]).to_string();
        let client = ScriptedClient::text(body);
        let findings = run(&client, None).await.unwrap();
        assert_eq!(findings.len(), 1);
    }

    /// A non-array `findings` is no longer read as a clean zero-finding
    /// run (upstream v1.4.0 `_findings_list`): it gets one repair, and a
    /// repair that answers the same shape again fails the run.
    #[tokio::test]
    async fn findings_key_present_but_not_an_array_fails_the_run_after_one_repair() {
        let body = serde_json::json!({"findings": "oops"}).to_string();
        let client = SeqClient::new(vec![Ok(body.clone()), Ok(body)]);
        let mut diag = crate::DeepdiveDiagnostics::default();
        let err = run_with(&client, 64_000, None, &mut diag)
            .await
            .unwrap_err();
        assert!(matches!(&err, RunError::Other(m) if m.contains("after one repair re-ask")));
        assert_eq!(diag.json_repairs_attempted, 1);
        assert_eq!(diag.json_repairs_succeeded, 0);
    }

    /// Replays `replies` in order and records every request's
    /// `max_tokens` and last-message text.
    struct SeqClient {
        replies: std::sync::Mutex<std::collections::VecDeque<Result<String, LlmError>>>,
        seen: std::sync::Mutex<Vec<(u32, String)>>,
    }

    impl SeqClient {
        fn new(replies: Vec<Result<String, LlmError>>) -> Self {
            SeqClient {
                replies: std::sync::Mutex::new(replies.into()),
                seen: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn seen(&self) -> Vec<(u32, String)> {
            self.seen.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl LlmClient for SeqClient {
        async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, LlmError> {
            // The Debug form, so no never-taken non-text arm is needed:
            // assertions match its escaped `\n` and `\"` spellings.
            let prompt = format!("{:?}", request.messages[0].content);
            self.seen.lock().unwrap().push((request.max_tokens, prompt));
            let text = self.replies.lock().unwrap().pop_front().unwrap()?;
            Ok(ChatResponse {
                content: vec![ContentBlock::Text(text)],
                stop_reason: StopReason::EndTurn,
                usage: Usage::default(),
            })
        }
    }

    async fn run_with(
        client: &dyn LlmClient,
        max_tokens: u32,
        cap: Option<usize>,
        diag: &mut crate::DeepdiveDiagnostics,
    ) -> Result<Vec<Finding>, RunError> {
        single_run(
            client,
            &chunk(),
            &prompt_for(&chunk(), "discover"),
            std::path::Path::new("."),
            "m",
            max_tokens,
            cap,
            0,
            std::time::Duration::ZERO,
            Sampling::default(),
            diag,
        )
        .await
    }

    #[tokio::test]
    async fn a_wrong_shape_reply_is_repaired_with_the_shape_prompt_and_a_capped_budget() {
        let good = serde_json::json!({"findings": [finding_json("injection", 0.9, "CWE-89")]});
        let client = SeqClient::new(vec![
            Ok(r#"{"findings": null}"#.to_string()),
            Ok(good.to_string()),
        ]);
        let mut diag = crate::DeepdiveDiagnostics::default();
        let findings = run_with(&client, 64_000, None, &mut diag).await.unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(diag.json_repairs_attempted, 1);
        assert_eq!(diag.json_repairs_succeeded, 1);
        let seen = client.seen();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0].0, 64_000);
        assert_eq!(seen[1].0, crate::repair::REPAIR_MAX_TOKENS);
        assert!(seen[1].1.contains("VALID JSON but the wrong shape"));
        assert!(seen[1]
            .1
            .contains(r#"PREVIOUS RESPONSE:\n{\"findings\": null}\n"#));
    }

    #[tokio::test]
    async fn a_syntax_error_is_repaired_with_the_syntax_prompt_and_a_smaller_budget_kept() {
        let client = SeqClient::new(vec![
            Ok("not json {{{".to_string()),
            Ok(r#"{"findings": []}"#.to_string()),
        ]);
        let mut diag = crate::DeepdiveDiagnostics::default();
        let findings = run_with(&client, 1000, None, &mut diag).await.unwrap();
        assert!(findings.is_empty());
        let seen = client.seen();
        assert_eq!(seen[1].0, 1000, "min(max_tokens, 12000)");
        assert!(seen[1].1.contains("Fix the JSON syntax only"));
    }

    #[tokio::test]
    async fn a_guardrail_block_on_the_repair_is_reported_as_a_guardrail_block() {
        let client = SeqClient::new(vec![
            Ok("{}".to_string()),
            Err(LlmError::GuardrailBlocked {
                message: "no".into(),
            }),
        ]);
        let mut diag = crate::DeepdiveDiagnostics::default();
        let err = run_with(&client, 1000, None, &mut diag).await.unwrap_err();
        assert_eq!(err, RunError::GuardrailBlocked("no".into()));
        assert_eq!(diag.json_repairs_attempted, 1);
    }

    #[tokio::test]
    async fn findings_past_the_cap_are_counted_as_truncated() {
        let body = serde_json::json!({"findings": [
            finding_json("injection", 0.9, ""),
            finding_json("injection", 0.8, ""),
            finding_json("injection", 0.7, ""),
        ]});
        let client = SeqClient::new(vec![Ok(body.to_string())]);
        let mut diag = crate::DeepdiveDiagnostics::default();
        let findings = run_with(&client, 1000, Some(1), &mut diag).await.unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(diag.findings_truncated, 2);
        assert_eq!(diag.json_repairs_attempted, 0);
    }

    // `single_run`'s only caller already filters `!item.is_object()` before
    // calling `coerce_item`, so this guard is unreachable via that call
    // path — whitebox-tested directly, since `coerce_item`'s own contract
    // ("any `Value`") is broader than its one current caller's.
    #[test]
    fn coerce_item_on_a_non_object_value_is_a_no_op() {
        let mut v = serde_json::json!("not an object");
        coerce_item(&mut v, "chunk-01");
        assert_eq!(v, serde_json::json!("not an object"));
    }

    #[tokio::test]
    async fn a_non_object_item_in_the_array_is_dropped() {
        let body =
            serde_json::json!({"findings": ["not-an-object", finding_json("other", 0.5, "")]})
                .to_string();
        let client = ScriptedClient::text(body);
        let findings = run(&client, None).await.unwrap();
        assert_eq!(findings.len(), 1);
    }

    #[tokio::test]
    async fn missing_vuln_class_drops_the_finding_entirely() {
        let mut item = finding_json("other", 0.5, "");
        item.as_object_mut().unwrap().remove("vuln_class");
        let body = serde_json::json!({"findings": [item]}).to_string();
        let client = ScriptedClient::text(body);
        let findings = run(&client, None).await.unwrap();
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn an_invalid_vuln_class_is_coerced_to_other() {
        let body = serde_json::json!({"findings": [finding_json("not-a-real-class", 0.5, "")]})
            .to_string();
        let client = ScriptedClient::text(body);
        let findings = run(&client, None).await.unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].vuln_class, bc_model::VulnClass::Other);
    }

    #[tokio::test]
    async fn cwe_normalization_handles_case_and_separator_variants() {
        let body = serde_json::json!({"findings": [
            finding_json("other", 0.5, "cwe-79"),
            finding_json("other", 0.5, "CWE 79"),
            finding_json("other", 0.5, "totally unrelated text"),
        ]})
        .to_string();
        let client = ScriptedClient::text(body);
        let findings = run(&client, None).await.unwrap();
        assert_eq!(findings[0].cwe.as_deref(), Some("CWE-79"));
        assert_eq!(findings[1].cwe.as_deref(), Some("CWE-79"));
        assert_eq!(findings[2].cwe, None);
    }

    #[tokio::test]
    async fn an_item_without_a_chunk_id_gets_the_chunks_id() {
        let mut item = finding_json("other", 0.5, "");
        item.as_object_mut().unwrap().remove("chunk_id");
        let body = serde_json::json!({"findings": [item]}).to_string();
        let client = ScriptedClient::text(body);
        let findings = run(&client, None).await.unwrap();
        assert_eq!(findings[0].chunk_id, "chunk-01");
    }

    #[tokio::test]
    async fn an_items_own_chunk_id_is_not_overwritten() {
        let mut item = finding_json("other", 0.5, "");
        item.as_object_mut()
            .unwrap()
            .insert("chunk_id".to_string(), "explicit".into());
        let body = serde_json::json!({"findings": [item]}).to_string();
        let client = ScriptedClient::text(body);
        let findings = run(&client, None).await.unwrap();
        assert_eq!(findings[0].chunk_id, "explicit");
    }

    #[tokio::test]
    async fn max_findings_per_run_caps_by_descending_confidence() {
        let body = serde_json::json!({"findings": [
            finding_json("other", 0.3, ""),
            finding_json("other", 0.9, ""),
            finding_json("other", 0.5, ""),
        ]})
        .to_string();
        let client = ScriptedClient::text(body);
        let findings = run(&client, Some(2)).await.unwrap();
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].confidence, 0.9);
        assert_eq!(findings[1].confidence, 0.5);
    }

    #[tokio::test]
    async fn a_finding_count_under_the_cap_is_left_unsorted_and_untouched() {
        let body = serde_json::json!({"findings": [finding_json("other", 0.3, "")]}).to_string();
        let client = ScriptedClient::text(body);
        let findings = run(&client, Some(5)).await.unwrap();
        assert_eq!(findings.len(), 1);
    }

    #[tokio::test]
    async fn a_guardrail_block_is_reported_distinctly() {
        let client = ScriptedClient::erroring(|| LlmError::GuardrailBlocked {
            message: "blocked".to_string(),
        });
        let err = run(&client, None).await.unwrap_err();
        assert_eq!(err, RunError::GuardrailBlocked("blocked".to_string()));
    }

    #[tokio::test]
    async fn a_non_guardrail_llm_error_is_reported_as_other() {
        let client = ScriptedClient::erroring(|| LlmError::ConnectionError {
            message: "down".to_string(),
        });
        let err = run(&client, None).await.unwrap_err();
        assert!(matches!(err, RunError::Other(_)));
    }

    /// Fails with a retryable error `fail_times` times, then succeeds
    /// with an empty-findings reply — exercises this crate's own
    /// `chat_with_retry` call site, not just `bc-llm-agentic`'s own unit
    /// tests.
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
                    serde_json::json!({"findings": []}).to_string(),
                )],
                stop_reason: StopReason::EndTurn,
                usage: Usage::default(),
            })
        }
    }

    #[tokio::test]
    async fn retries_a_transient_failure_then_succeeds() {
        let client = RetryingClient::new(2);
        let findings = single_run(
            &client,
            &chunk(),
            &prompt_for(&chunk(), "discover"),
            std::path::Path::new("."),
            "m",
            1000,
            None,
            4,
            std::time::Duration::ZERO,
            Sampling::default(),
            &mut crate::DeepdiveDiagnostics::default(),
        )
        .await
        .unwrap();
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn unparseable_json_is_reported_as_other() {
        let client = ScriptedClient::text("this is not json at all {{{");
        let err = run(&client, None).await.unwrap_err();
        assert!(matches!(err, RunError::Other(_)));
    }

    /// A provider quota failure is NOT laundered into `Other` — the
    /// caller reacts to it (stop the stage) rather than counting one more
    /// failed run, so the distinction has to survive the mapping.
    #[tokio::test]
    async fn a_quota_exhausted_error_is_reported_distinctly() {
        let client = ScriptedClient::erroring(|| LlmError::QuotaExhausted {
            message: "You exceeded your current quota".to_string(),
        });
        let err = run(&client, None).await.unwrap_err();
        assert_eq!(
            err,
            RunError::QuotaExhausted("You exceeded your current quota".to_string())
        );
    }

    #[test]
    fn run_error_display_formats_every_variant() {
        assert_eq!(
            RunError::GuardrailBlocked("x".to_string()).to_string(),
            "guardrail blocked: x"
        );
        assert_eq!(
            RunError::QuotaExhausted("no credits".to_string()).to_string(),
            "provider quota exhausted: no credits"
        );
        assert_eq!(RunError::Other("y".to_string()).to_string(), "y");
        assert_eq!(RunError::Halting("z".to_string()).to_string(), "z");
    }

    /// A rejected credential is not laundered into `Other` either: it
    /// stops the stage the way quota exhaustion does, carrying its code.
    #[tokio::test]
    async fn an_authentication_error_is_reported_as_halting() {
        let client = ScriptedClient::erroring(|| LlmError::Authentication {
            status: Some(401),
            message: "Incorrect API key provided".to_string(),
        });
        let err = run(&client, None).await.unwrap_err();
        assert!(matches!(&err, RunError::Halting(m) if m.starts_with("[VVAH-E001]")));
    }

    // -- taint_prompt_mode dispatch ---------------------------------------

    struct RoutingClient {
        router: Box<dyn Fn(&str) -> String + Send + Sync>,
    }

    #[async_trait]
    impl LlmClient for RoutingClient {
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
            Ok(ChatResponse {
                content: vec![ContentBlock::Text((self.router)(&text))],
                stop_reason: StopReason::EndTurn,
                usage: Usage::default(),
            })
        }
    }

    #[tokio::test]
    async fn routing_client_fixture_ignores_non_text_content_blocks() {
        // `single_run` only ever sends a single `Message::user_text(...)`
        // (never a tool result), so no real dispatch path exercises a
        // non-`Text` content block — exercised directly here against the
        // fixture itself instead, mirroring `bc-stage-s4::tests::
        // routed_client_fixture_ignores_non_text_content_blocks`.
        let client = RoutingClient {
            router: Box::new(|text| format!("echo:{text}")),
        };
        let request = ChatRequest {
            model: "m".to_string(),
            system: None,
            messages: vec![Message {
                role: bc_llm_client::Role::User,
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

    fn routed_by_prompt_kind() -> RoutingClient {
        RoutingClient {
            router: Box::new(|text| {
                let body = if text.contains("TASK: confirm or refute") {
                    serde_json::json!({"findings": []})
                } else {
                    serde_json::json!({"findings": [finding_json("other", 0.5, "")]})
                };
                body.to_string()
            }),
        }
    }

    #[tokio::test]
    async fn confirm_refute_mode_is_used_only_when_the_chunk_has_a_static_taint_path() {
        let client = routed_by_prompt_kind();
        let mut c = chunk();
        c.path_funcs = vec!["a.py::hop".to_string()];
        c.source_ref = "a.py::src".to_string();
        c.sink_ref = "a.py:1".to_string();
        let findings = single_run(
            &client,
            &c,
            &prompt_for(&c, "confirm_refute"),
            std::path::Path::new("."),
            "m",
            1000,
            None,
            0,
            std::time::Duration::ZERO,
            Sampling::default(),
            &mut crate::DeepdiveDiagnostics::default(),
        )
        .await
        .unwrap();
        // The confirm/refute prompt was sent (routed to the empty-findings
        // branch), proving the taint-first path was actually used.
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn discover_mode_ignores_path_funcs_and_always_uses_the_open_ended_prompt() {
        let client = routed_by_prompt_kind();
        let mut c = chunk();
        c.path_funcs = vec!["a.py::hop".to_string()];
        let findings = single_run(
            &client,
            &c,
            &prompt_for(&c, "discover"),
            std::path::Path::new("."),
            "m",
            1000,
            None,
            0,
            std::time::Duration::ZERO,
            Sampling::default(),
            &mut crate::DeepdiveDiagnostics::default(),
        )
        .await
        .unwrap();
        assert_eq!(findings.len(), 1);
    }

    #[tokio::test]
    async fn a_temporal_finding_is_re_anchored_before_it_is_returned() {
        // The wiring test for `reanchor`: the model answers with a
        // use-after-free anchored at the `free`, and what comes back out
        // of the parse loop spans the free and the later deref. Anything
        // downstream of here (the vote, dedup, SARIF, PR comments) sees
        // the corrected range and never the reported one.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("bug.c"),
            "void handle(void) {\n    char *p = malloc(16);\n    free(p);\n    printf(\"%s\", p);\n}\n",
        )
        .unwrap();
        let client = ScriptedClient::text(
            serde_json::json!({"findings": [{
                "file": "bug.c",
                "line_start": 3,
                "line_end": 3,
                "vuln_class": "use-after-free",
                "title": "t",
                "description": "d",
                "code_snippet": "free(p);",
                "confidence": 0.9,
                "cwe": "CWE-416",
            }]})
            .to_string(),
        );
        let findings = single_run(
            &client,
            &chunk(),
            &prompt_for(&chunk(), "discover"),
            dir.path(),
            "m",
            1000,
            None,
            0,
            std::time::Duration::ZERO,
            Sampling::default(),
            &mut crate::DeepdiveDiagnostics::default(),
        )
        .await
        .unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!((findings[0].line_start, findings[0].line_end), (3, 4));
        assert_eq!(findings[0].reanchored, vec!["line_end".to_string()]);
    }

    #[tokio::test]
    async fn confirm_refute_mode_with_no_path_funcs_still_uses_the_open_ended_prompt() {
        let client = routed_by_prompt_kind();
        let findings = single_run(
            &client,
            &chunk(),
            &prompt_for(&chunk(), "confirm_refute"),
            std::path::Path::new("."),
            "m",
            1000,
            None,
            0,
            std::time::Duration::ZERO,
            Sampling::default(),
            &mut crate::DeepdiveDiagnostics::default(),
        )
        .await
        .unwrap();
        assert_eq!(findings.len(), 1);
    }
}
