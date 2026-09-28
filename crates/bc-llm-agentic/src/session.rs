//! The multi-turn tool-use loop, ported from `backends/oai.py`'s/
//! `backends/sdk.py`'s `agentic()` — dialect-agnostic, driven purely
//! against the [`LlmClient`]/[`ToolExecutor`] trait seam so it runs
//! identically over either dialect (or a scripted test fake).

use std::collections::HashSet;
use std::time::Duration;

use bc_llm_client::{
    supported, ChatRequest, ChatResponse, LlmClient, LlmError, Message, StopReason, ToolExecutor,
    ToolSpec, Usage,
};

use crate::config::AgenticConfig;
use crate::pure::{cap_tool_result, shrink_history};
use crate::retry::RetryLadder;
use crate::truncation::{TruncationGuard, Verdict};

/// Send one request, retrying on a retryable transient [`LlmError`]
/// (backoff, capped at `max_transient_retries`) — the single-shot-call
/// counterpart to [`run_agentic`]'s own internal `send_turn`, for stages
/// (S2/S3/S4/S7/S8) that make exactly one `LlmClient::chat` call with no
/// tool-use turns or message history to shrink on a context-overflow
/// error, so only the transient-retry half of `send_turn`'s logic
/// applies. A non-retryable error (including `ContextOverflow`, which
/// single-shot callers have no history to evict from) always propagates
/// immediately.
///
/// Two narrower ladders ride alongside the transient one, both ported
/// from the Python original's `prompt()` loops:
///
/// * [`LlmError::Authentication`] is retried three times, after 2, 4 and
///   8 s (see `crate::retry`), then propagated, so a credential that is
///   mid-rotation survives and a wrong one halts the scan quickly.
/// * A reply cut off by its output budget (`StopReason::MaxTokens`) is
///   sent once more at double the budget. If that is cut off too, or the
///   provider refuses the doubled budget as over its cap, the result is
///   [`LlmError::Truncated`] (VVAH-E005) carrying the partial reply, and
///   the client's [`LlmClient::note_truncated_reply`] hook is told. The
///   doubled budget is uncapped here, as on Python's OpenAI route; see
///   [`chat_with_retry_capped`] for a ceiling.
pub async fn chat_with_retry(
    client: &dyn LlmClient,
    request: &ChatRequest,
    max_transient_retries: u32,
    retry_backoff_base: Duration,
) -> Result<ChatResponse, LlmError> {
    chat_with_retry_capped(
        client,
        request,
        max_transient_retries,
        retry_backoff_base,
        None,
    )
    .await
}

/// [`chat_with_retry`] with a ceiling on the truncation retry's doubled
/// output budget (Python's `truncation_retry_max(requested, cap=...)`,
/// which its Anthropic route passes the model's output cap). A request
/// already at the ceiling is not retried at all.
pub async fn chat_with_retry_capped(
    client: &dyn LlmClient,
    request: &ChatRequest,
    max_transient_retries: u32,
    retry_backoff_base: Duration,
    max_tokens_ceiling: Option<u32>,
) -> Result<ChatResponse, LlmError> {
    let mut ladder = RetryLadder::new(max_transient_retries, retry_backoff_base);
    let mut truncation = TruncationGuard::new(request.max_tokens, max_tokens_ceiling);
    // Cloned only once a truncation retry actually needs a larger
    // budget; every other attempt resends the caller's own request.
    let mut enlarged: Option<ChatRequest> = None;
    loop {
        let attempt = enlarged.as_ref().unwrap_or(request);
        match client.chat(attempt).await {
            Ok(response) => match truncation.on_response(response) {
                Verdict::Done(response) => return Ok(response),
                Verdict::Retry => {
                    let mut larger = request.clone();
                    larger.max_tokens = truncation.max_tokens();
                    enlarged = Some(larger);
                }
                Verdict::GiveUp(truncated) => return Err(give_up(client, truncated)),
            },
            Err(e) => {
                if let Some(truncated) = truncation.cap_rejection(&e) {
                    return Err(give_up(client, truncated));
                }
                let Some(delay) = ladder.delay_for(&e, "single-shot call") else {
                    return Err(e);
                };
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }
}

/// Report a confirmed truncation (VVAH-E005) to the client's metrics hook
/// and log it, then hand the error back for the caller to return.
fn give_up(client: &dyn LlmClient, truncated: LlmError) -> LlmError {
    client.note_truncated_reply();
    tracing::warn!(error = %truncated, "LLM reply still truncated; giving up on it");
    truncated
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopKind {
    /// The model returned a non-tool-use stop reason on its own.
    Finished,
    /// `max_turns` was reached before the model stopped calling tools; one
    /// additional no-tools request was sent asking for a final answer.
    MaxTurnsExhausted,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AgenticOutcome {
    pub final_text: String,
    pub turns_used: u32,
    pub tool_calls_total: u32,
    pub usage: Usage,
    pub stopped: StopKind,
}

/// Run one agentic session to completion: send `user_prompt`, execute any
/// tool calls the model makes via `tools`, and keep going until the model
/// stops calling tools or `config.max_turns` is reached.
pub async fn run_agentic(
    client: &dyn LlmClient,
    tools: &dyn ToolExecutor,
    user_prompt: &str,
    config: &AgenticConfig,
) -> Result<AgenticOutcome, LlmError> {
    let (ok_tools, missing) = supported(tools, &config.allowed_tools);
    if !missing.is_empty() {
        return Err(LlmError::InvalidRequest {
            message: format!(
                "tools not supported by this executor: {}",
                missing.join(", ")
            ),
        });
    }
    let available = tools.available_tools();
    let tool_specs: Vec<ToolSpec> = ok_tools
        .iter()
        .filter_map(|name| available.iter().find(|t| &t.name == name).cloned())
        .collect();
    let allowed_tool_names: HashSet<&str> = ok_tools.iter().map(String::as_str).collect();

    let mut messages = vec![Message::user_text(user_prompt)];
    let mut usage_total = Usage::default();
    let mut tool_calls_total = 0u32;

    for turn in 1..=config.max_turns {
        let response = send_turn(client, config, &mut messages, &tool_specs).await?;
        usage_total = add_usage(usage_total, response.usage);

        if response.stop_reason != StopReason::ToolUse {
            return Ok(AgenticOutcome {
                final_text: response.text(),
                turns_used: turn,
                tool_calls_total,
                usage: usage_total,
                stopped: StopKind::Finished,
            });
        }

        messages.push(Message::assistant(response.content.clone()));
        for (id, name, input) in response.tool_uses() {
            tool_calls_total += 1;
            if allowed_tool_names.contains(name) {
                let result = tools.execute(name, input);
                messages.push(Message::tool_result(id, cap_tool_result(&result), false));
            } else {
                messages.push(Message::tool_result(
                    id,
                    "ERROR: requested tool is not available in this session",
                    true,
                ));
            }
        }
    }

    messages.push(Message::user_text(
        "Tool budget exhausted. Reply now with your final answer based on what you have \
         read so far; do not call any tool.",
    ));
    let response = send_turn(client, config, &mut messages, &[]).await?;
    usage_total = add_usage(usage_total, response.usage);
    Ok(AgenticOutcome {
        final_text: response.text(),
        turns_used: config.max_turns,
        tool_calls_total,
        usage: usage_total,
        stopped: StopKind::MaxTurnsExhausted,
    })
}

/// Send one request, transparently retrying on a retryable transient error
/// (backoff, capped at `max_transient_retries`) or a context-overflow error
/// (evict the oldest oversized tool result from `messages` and retry,
/// capped at `max_context_shrinks`). Shrinks mutate `messages` in place so
/// they persist for every later turn, not just this retry.
///
/// Authentication failures and truncated replies get the same narrower
/// ladders [`chat_with_retry`] gives them. A truncated turn used to be
/// read as the model finishing (it is not `StopReason::ToolUse`), so a
/// half-written final answer came back as the session's result; it is
/// now retried once at double the budget (capped by
/// `AgenticConfig::max_tokens_ceiling`) and otherwise fails the session
/// with [`LlmError::Truncated`]. The larger budget applies to this turn
/// only.
async fn send_turn(
    client: &dyn LlmClient,
    config: &AgenticConfig,
    messages: &mut [Message],
    tools: &[ToolSpec],
) -> Result<ChatResponse, LlmError> {
    let mut ladder = RetryLadder::new(config.max_transient_retries, config.retry_backoff_base);
    let mut truncation = TruncationGuard::new(config.max_tokens, config.max_tokens_ceiling);
    let mut shrink_attempts = 0u32;

    loop {
        let mut request = build_request(config, messages, tools);
        request.max_tokens = truncation.max_tokens();
        match client.chat(&request).await {
            Ok(response) => match truncation.on_response(response) {
                Verdict::Done(response) => return Ok(response),
                Verdict::Retry => continue,
                Verdict::GiveUp(truncated) => return Err(give_up(client, truncated)),
            },
            Err(e) => {
                // Checked before the context-overflow arm: an overflow
                // that names the doubled budget is the cap, not history
                // to evict.
                if let Some(truncated) = truncation.cap_rejection(&e) {
                    return Err(give_up(client, truncated));
                }
                if let LlmError::ContextOverflow { .. } = e {
                    if shrink_attempts < config.max_context_shrinks {
                        if !shrink_history(messages) {
                            return Err(e);
                        }
                        shrink_attempts += 1;
                        continue;
                    }
                }
                let Some(delay) = ladder.delay_for(&e, "agentic turn") else {
                    return Err(e);
                };
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }
}

fn build_request(config: &AgenticConfig, messages: &[Message], tools: &[ToolSpec]) -> ChatRequest {
    ChatRequest {
        model: config.model.clone(),
        system: config.system_prompt.clone(),
        messages: messages.to_vec(),
        tools: tools.to_vec(),
        max_tokens: config.max_tokens,
        temperature: config.temperature,
        top_p: config.top_p,
        seed: config.seed,
        thinking_budget: config.thinking_budget,
        betas: config.betas.clone(),
        json_mode: config.json_mode,
        timeout: config.timeout_secs.map(Duration::from_secs),
        stream: false,
        reasoning_effort: config.reasoning_effort,
        openai_api: config.openai_api,
        cache_prefix: config.cache_prefix.clone(),
        cache_key: config.cache_key.clone(),
        // Stamped by `bc_llm_client::ApplyCachePolicy` where the client
        // is built; a session has no view on it.
        cache: bc_llm_client::CachePolicy::default(),
    }
}

fn add_usage(a: Usage, b: Usage) -> Usage {
    Usage {
        input_tokens: a.input_tokens + b.input_tokens,
        output_tokens: a.output_tokens + b.output_tokens,
        cache_creation_input_tokens: a.cache_creation_input_tokens + b.cache_creation_input_tokens,
        cache_read_input_tokens: a.cache_read_input_tokens + b.cache_read_input_tokens,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use bc_llm_client::ContentBlock;
    use serde_json::{json, Value};
    use std::sync::Mutex;
    use std::time::Duration;

    struct ScriptedClient {
        responses: Mutex<Vec<Result<ChatResponse, LlmError>>>,
        calls: Mutex<u32>,
        /// Every request's `max_tokens`, in send order.
        budgets: Mutex<Vec<u32>>,
        truncation_notes: Mutex<u32>,
    }

    impl ScriptedClient {
        fn new(responses: Vec<Result<ChatResponse, LlmError>>) -> Self {
            // Stored reversed so `pop()` (cheap, no shift) yields them in
            // the original script order.
            let mut responses = responses;
            responses.reverse();
            ScriptedClient {
                responses: Mutex::new(responses),
                calls: Mutex::new(0),
                budgets: Mutex::new(Vec::new()),
                truncation_notes: Mutex::new(0),
            }
        }

        fn call_count(&self) -> u32 {
            *self.calls.lock().unwrap()
        }

        fn budgets(&self) -> Vec<u32> {
            self.budgets.lock().unwrap().clone()
        }

        fn truncation_notes(&self) -> u32 {
            *self.truncation_notes.lock().unwrap()
        }
    }

    #[async_trait]
    impl LlmClient for ScriptedClient {
        async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, LlmError> {
            *self.calls.lock().unwrap() += 1;
            self.budgets.lock().unwrap().push(request.max_tokens);
            self.responses
                .lock()
                .unwrap()
                .pop()
                .expect("ScriptedClient ran out of scripted responses")
        }

        fn note_truncated_reply(&self) {
            *self.truncation_notes.lock().unwrap() += 1;
        }
    }

    struct FakeTools {
        next_result: Mutex<String>,
    }

    impl FakeTools {
        fn new() -> Self {
            FakeTools {
                next_result: Mutex::new("file contents".to_string()),
            }
        }

        fn returning(result: impl Into<String>) -> Self {
            FakeTools {
                next_result: Mutex::new(result.into()),
            }
        }
    }

    impl ToolExecutor for FakeTools {
        fn available_tools(&self) -> Vec<ToolSpec> {
            vec![ToolSpec {
                name: "Read".to_string(),
                description: "read a file".to_string(),
                parameters: json!({}),
            }]
        }

        fn execute(&self, _name: &str, _args: &Value) -> String {
            self.next_result.lock().unwrap().clone()
        }
    }

    /// Models the S10 executor: it can execute a mutation, but this
    /// particular session only advertises read access. The regression test
    /// below proves the session loop, not the backend, enforces that
    /// narrower per-session capability.
    struct WriteCapableTools {
        writes: Mutex<u32>,
    }

    impl WriteCapableTools {
        fn new() -> Self {
            Self {
                writes: Mutex::new(0),
            }
        }

        fn write_count(&self) -> u32 {
            *self.writes.lock().unwrap()
        }
    }

    impl ToolExecutor for WriteCapableTools {
        fn available_tools(&self) -> Vec<ToolSpec> {
            vec![
                ToolSpec {
                    name: "Read".to_string(),
                    description: "read a file".to_string(),
                    parameters: json!({}),
                },
                ToolSpec {
                    name: "Write".to_string(),
                    description: "write a file".to_string(),
                    parameters: json!({}),
                },
            ]
        }

        fn execute(&self, name: &str, _args: &Value) -> String {
            if name == "Write" {
                *self.writes.lock().unwrap() += 1;
                "write executed".to_string()
            } else {
                "file contents".to_string()
            }
        }
    }

    fn text_response(text: &str) -> ChatResponse {
        ChatResponse {
            content: vec![ContentBlock::text(text)],
            stop_reason: StopReason::EndTurn,
            usage: Usage::default(),
        }
    }

    fn tool_use_response(id: &str, name: &str) -> ChatResponse {
        ChatResponse {
            content: vec![ContentBlock::ToolUse {
                id: id.to_string(),
                name: name.to_string(),
                input: json!({}),
            }],
            stop_reason: StopReason::ToolUse,
            usage: Usage {
                input_tokens: 10,
                output_tokens: 5,
                ..Usage::default()
            },
        }
    }

    fn instant_config() -> AgenticConfig {
        let mut cfg = AgenticConfig::new("gpt-4o");
        cfg.retry_backoff_base = Duration::ZERO;
        cfg
    }

    #[tokio::test]
    async fn finishes_in_one_turn_with_no_tool_calls() {
        let client = ScriptedClient::new(vec![Ok(text_response("hello"))]);
        let tools = FakeTools::new();
        let outcome = run_agentic(&client, &tools, "hi", &instant_config())
            .await
            .unwrap();
        assert_eq!(outcome.final_text, "hello");
        assert_eq!(outcome.turns_used, 1);
        assert_eq!(outcome.tool_calls_total, 0);
        assert_eq!(outcome.stopped, StopKind::Finished);
        assert_eq!(client.call_count(), 1);
    }

    #[tokio::test]
    async fn executes_a_tool_call_then_finishes() {
        let client = ScriptedClient::new(vec![
            Ok(tool_use_response("call_1", "Read")),
            Ok(text_response("done")),
        ]);
        let mut cfg = instant_config();
        cfg.allowed_tools = vec!["Read".to_string()];
        let outcome = run_agentic(&client, &FakeTools::new(), "hi", &cfg)
            .await
            .unwrap();
        assert_eq!(outcome.final_text, "done");
        assert_eq!(outcome.turns_used, 2);
        assert_eq!(outcome.tool_calls_total, 1);
        assert_eq!(outcome.usage.input_tokens, 10);
        assert_eq!(outcome.stopped, StopKind::Finished);
    }

    #[tokio::test]
    async fn refuses_a_model_requested_tool_that_was_not_advertised_for_this_session() {
        let client = ScriptedClient::new(vec![
            Ok(tool_use_response("write_1", "Write")),
            Ok(text_response("done")),
        ]);
        let tools = WriteCapableTools::new();
        let mut cfg = instant_config();
        cfg.allowed_tools = vec!["Read".to_string()];

        let outcome = run_agentic(&client, &tools, "hi", &cfg).await.unwrap();

        assert_eq!(outcome.final_text, "done");
        assert_eq!(outcome.tool_calls_total, 1);
        assert_eq!(tools.write_count(), 0, "unadvertised Write was dispatched");
    }

    /// The control case for the refusal above. Without it, "the executor
    /// never wrote anything" would be satisfied by an executor that cannot
    /// write at all, and the refusal test would prove nothing about the
    /// session loop. The SAME double, driven by the SAME scripted turn,
    /// does perform the mutation once `Write` is advertised.
    #[tokio::test]
    async fn dispatches_an_advertised_tool_through_the_very_same_executor() {
        let client = ScriptedClient::new(vec![
            Ok(tool_use_response("write_1", "Write")),
            Ok(tool_use_response("read_1", "Read")),
            Ok(text_response("done")),
        ]);
        let tools = WriteCapableTools::new();
        let mut cfg = instant_config();
        cfg.allowed_tools = vec!["Read".to_string(), "Write".to_string()];

        let outcome = run_agentic(&client, &tools, "hi", &cfg).await.unwrap();

        assert_eq!(outcome.final_text, "done");
        assert_eq!(outcome.tool_calls_total, 2);
        assert_eq!(tools.write_count(), 1);
        assert_eq!(
            tools.execute("Read", &json!({})),
            "file contents",
            "the read branch answers without counting a write"
        );
        assert_eq!(tools.write_count(), 1);
    }

    #[tokio::test]
    async fn stops_at_max_turns_and_forces_a_final_answer() {
        let client = ScriptedClient::new(vec![
            Ok(tool_use_response("1", "Read")),
            Ok(tool_use_response("2", "Read")),
            Ok(text_response("forced final")),
        ]);
        let mut cfg = instant_config();
        cfg.max_turns = 2;
        cfg.allowed_tools = vec!["Read".to_string()];
        let outcome = run_agentic(&client, &FakeTools::new(), "hi", &cfg)
            .await
            .unwrap();
        assert_eq!(outcome.final_text, "forced final");
        assert_eq!(outcome.turns_used, 2);
        assert_eq!(outcome.tool_calls_total, 2);
        assert_eq!(outcome.stopped, StopKind::MaxTurnsExhausted);
        // 2 in-loop turns + 1 forced-final call.
        assert_eq!(client.call_count(), 3);
    }

    #[tokio::test]
    async fn retries_a_transient_error_then_succeeds() {
        let client = ScriptedClient::new(vec![
            Err(LlmError::ServerError {
                status: 503,
                message: "down".to_string(),
            }),
            Ok(text_response("recovered")),
        ]);
        let outcome = run_agentic(&client, &FakeTools::new(), "hi", &instant_config())
            .await
            .unwrap();
        assert_eq!(outcome.final_text, "recovered");
        assert_eq!(client.call_count(), 2);
    }

    #[tokio::test]
    async fn a_nonzero_backoff_base_actually_sleeps_between_retries() {
        let client = ScriptedClient::new(vec![
            Err(LlmError::ServerError {
                status: 503,
                message: "down".to_string(),
            }),
            Ok(text_response("recovered")),
        ]);
        let mut cfg = instant_config();
        cfg.retry_backoff_base = Duration::from_millis(1);
        let outcome = run_agentic(&client, &FakeTools::new(), "hi", &cfg)
            .await
            .unwrap();
        assert_eq!(outcome.final_text, "recovered");
    }

    #[tokio::test]
    async fn propagates_a_transient_error_once_retries_are_exhausted() {
        let mut cfg = instant_config();
        cfg.max_transient_retries = 1;
        let client = ScriptedClient::new(vec![
            Err(LlmError::ServerError {
                status: 503,
                message: "down".to_string(),
            }),
            Err(LlmError::ServerError {
                status: 503,
                message: "still down".to_string(),
            }),
        ]);
        let err = run_agentic(&client, &FakeTools::new(), "hi", &cfg)
            .await
            .unwrap_err();
        assert_eq!(
            err,
            LlmError::ServerError {
                status: 503,
                message: "still down".to_string()
            }
        );
        assert_eq!(client.call_count(), 2);
    }

    #[tokio::test]
    async fn a_non_retryable_error_propagates_immediately() {
        let client = ScriptedClient::new(vec![Err(LlmError::InvalidRequest {
            message: "bad".to_string(),
        })]);
        let err = run_agentic(&client, &FakeTools::new(), "hi", &instant_config())
            .await
            .unwrap_err();
        assert_eq!(
            err,
            LlmError::InvalidRequest {
                message: "bad".to_string()
            }
        );
        assert_eq!(client.call_count(), 1);
    }

    fn a_request() -> ChatRequest {
        ChatRequest {
            model: "gpt-4o".to_string(),
            system: None,
            messages: vec![Message::user_text("hi")],
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
        }
    }

    #[tokio::test]
    async fn chat_with_retry_retries_a_transient_error_then_succeeds() {
        let client = ScriptedClient::new(vec![
            Err(LlmError::ServerError {
                status: 503,
                message: "down".to_string(),
            }),
            Ok(text_response("recovered")),
        ]);
        let response = chat_with_retry(&client, &a_request(), 4, Duration::ZERO)
            .await
            .unwrap();
        assert_eq!(response.text(), "recovered");
        assert_eq!(client.call_count(), 2);
    }

    #[tokio::test]
    async fn chat_with_retry_propagates_a_transient_error_once_retries_are_exhausted() {
        let client = ScriptedClient::new(vec![
            Err(LlmError::ServerError {
                status: 503,
                message: "down".to_string(),
            }),
            Err(LlmError::ServerError {
                status: 503,
                message: "still down".to_string(),
            }),
        ]);
        let err = chat_with_retry(&client, &a_request(), 1, Duration::ZERO)
            .await
            .unwrap_err();
        assert_eq!(
            err,
            LlmError::ServerError {
                status: 503,
                message: "still down".to_string()
            }
        );
        assert_eq!(client.call_count(), 2);
    }

    #[tokio::test]
    async fn chat_with_retry_a_non_retryable_error_propagates_immediately() {
        let client = ScriptedClient::new(vec![Err(LlmError::InvalidRequest {
            message: "bad".to_string(),
        })]);
        let err = chat_with_retry(&client, &a_request(), 4, Duration::ZERO)
            .await
            .unwrap_err();
        assert_eq!(
            err,
            LlmError::InvalidRequest {
                message: "bad".to_string()
            }
        );
        assert_eq!(client.call_count(), 1);
    }

    #[tokio::test]
    async fn chat_with_retry_a_nonzero_backoff_base_actually_sleeps_between_retries() {
        let client = ScriptedClient::new(vec![
            Err(LlmError::ServerError {
                status: 503,
                message: "down".to_string(),
            }),
            Ok(text_response("recovered")),
        ]);
        let response = chat_with_retry(&client, &a_request(), 4, Duration::from_millis(1))
            .await
            .unwrap();
        assert_eq!(response.text(), "recovered");
    }

    #[tokio::test]
    async fn context_overflow_shrinks_history_and_retries() {
        let client = ScriptedClient::new(vec![
            Ok(tool_use_response("1", "Read")),
            Err(LlmError::ContextOverflow {
                message: "too long".to_string(),
            }),
            Ok(text_response("done after shrink")),
        ]);
        let mut cfg = instant_config();
        cfg.allowed_tools = vec!["Read".to_string()];
        let big_result = "x".repeat(2000);
        let tools = FakeTools::returning(big_result);
        let outcome = run_agentic(&client, &tools, "hi", &cfg).await.unwrap();
        assert_eq!(outcome.final_text, "done after shrink");
        assert_eq!(client.call_count(), 3);
    }

    #[tokio::test]
    async fn context_overflow_with_nothing_left_to_shrink_propagates() {
        let client = ScriptedClient::new(vec![Err(LlmError::ContextOverflow {
            message: "too long".to_string(),
        })]);
        let err = run_agentic(&client, &FakeTools::new(), "hi", &instant_config())
            .await
            .unwrap_err();
        assert_eq!(
            err,
            LlmError::ContextOverflow {
                message: "too long".to_string()
            }
        );
    }

    #[tokio::test]
    async fn context_overflow_retries_are_capped() {
        let mut cfg = instant_config();
        cfg.max_context_shrinks = 1;
        cfg.allowed_tools = vec!["Read".to_string()];
        let client = ScriptedClient::new(vec![
            Ok(tool_use_response("1", "Read")),
            Err(LlmError::ContextOverflow {
                message: "first".to_string(),
            }),
            Err(LlmError::ContextOverflow {
                message: "second".to_string(),
            }),
        ]);
        let big_result = "x".repeat(2000);
        let tools = FakeTools::returning(big_result);
        let err = run_agentic(&client, &tools, "hi", &cfg).await.unwrap_err();
        assert_eq!(
            err,
            LlmError::ContextOverflow {
                message: "second".to_string()
            }
        );
    }

    #[tokio::test]
    async fn requesting_an_unsupported_tool_fails_before_any_chat_call() {
        let client = ScriptedClient::new(vec![]);
        let mut cfg = instant_config();
        cfg.allowed_tools = vec!["Bash".to_string()];
        let err = run_agentic(&client, &FakeTools::new(), "hi", &cfg)
            .await
            .unwrap_err();
        assert!(matches!(err, LlmError::InvalidRequest { .. }));
        assert_eq!(client.call_count(), 0);
    }

    // ── truncation (VVAH-E005) ──────────────────────────────────────────

    fn truncated_response(text: &str) -> ChatResponse {
        ChatResponse {
            content: vec![ContentBlock::text(text)],
            stop_reason: StopReason::MaxTokens,
            usage: Usage::default(),
        }
    }

    fn cap_400() -> LlmError {
        LlmError::InvalidRequest {
            message: "max_tokens: 200 > 150, which is the maximum allowed".to_string(),
        }
    }

    fn auth_error() -> LlmError {
        LlmError::Authentication {
            status: Some(401),
            message: "invalid x-api-key".to_string(),
        }
    }

    #[tokio::test]
    async fn chat_with_retry_resends_a_truncated_reply_once_at_double_the_budget() {
        let client = ScriptedClient::new(vec![
            Ok(truncated_response("{\"findings\": [")),
            Ok(text_response("{\"findings\": []}")),
        ]);
        let response = chat_with_retry(&client, &a_request(), 4, Duration::ZERO)
            .await
            .unwrap();
        assert_eq!(response.text(), "{\"findings\": []}");
        assert_eq!(client.budgets(), vec![100, 200]);
        assert_eq!(
            client.truncation_notes(),
            0,
            "a recovered truncation is not counted"
        );
    }

    #[tokio::test]
    async fn chat_with_retry_gives_up_with_the_partial_after_a_second_truncation() {
        let client = ScriptedClient::new(vec![
            Ok(truncated_response("{\"a\":")),
            Ok(truncated_response("{\"a\": [1,")),
        ]);
        let err = chat_with_retry(&client, &a_request(), 4, Duration::ZERO)
            .await
            .unwrap_err();
        assert_eq!(
            err,
            LlmError::Truncated {
                requested: 100,
                retried_at: Some(200),
                partial: Box::new(truncated_response("{\"a\": [1,")),
            }
        );
        assert_eq!(err.code(), Some("VVAH-E005"));
        assert_eq!(client.truncation_notes(), 1);
    }

    /// The provider's 400 on the doubled budget IS its cap: the caller
    /// gets the first reply back as the partial, never the 400 about a
    /// request it did not make.
    #[tokio::test]
    async fn chat_with_retry_reads_a_budget_400_on_the_retry_as_the_providers_cap() {
        let client = ScriptedClient::new(vec![Ok(truncated_response("first")), Err(cap_400())]);
        let err = chat_with_retry(&client, &a_request(), 4, Duration::ZERO)
            .await
            .unwrap_err();
        assert_eq!(
            err,
            LlmError::Truncated {
                requested: 100,
                retried_at: Some(200),
                partial: Box::new(truncated_response("first")),
            }
        );
        assert_eq!(client.truncation_notes(), 1);
    }

    #[tokio::test]
    async fn chat_with_retry_keeps_the_doubled_budget_across_a_transient_retry() {
        let client = ScriptedClient::new(vec![
            Ok(truncated_response("{")),
            Err(LlmError::ServerError {
                status: 503,
                message: "down".to_string(),
            }),
            Ok(text_response("{}")),
        ]);
        let response = chat_with_retry(&client, &a_request(), 4, Duration::ZERO)
            .await
            .unwrap();
        assert_eq!(response.text(), "{}");
        assert_eq!(client.budgets(), vec![100, 200, 200]);
    }

    #[tokio::test]
    async fn chat_with_retry_capped_honors_the_ceiling() {
        let client =
            ScriptedClient::new(vec![Ok(truncated_response("{")), Ok(text_response("{}"))]);
        chat_with_retry_capped(&client, &a_request(), 4, Duration::ZERO, Some(150))
            .await
            .unwrap();
        assert_eq!(client.budgets(), vec![100, 150]);

        // Already at the ceiling: no retry at all.
        let client = ScriptedClient::new(vec![Ok(truncated_response("{"))]);
        let err = chat_with_retry_capped(&client, &a_request(), 4, Duration::ZERO, Some(100))
            .await
            .unwrap_err();
        assert_eq!(
            err,
            LlmError::Truncated {
                requested: 100,
                retried_at: None,
                partial: Box::new(truncated_response("{")),
            }
        );
        assert_eq!(client.call_count(), 1);
    }

    #[tokio::test]
    async fn chat_with_retry_retries_authentication_three_times_then_halts() {
        let client = ScriptedClient::new(vec![
            Err(auth_error()),
            Err(auth_error()),
            Err(auth_error()),
            Err(auth_error()),
        ]);
        let err = chat_with_retry(&client, &a_request(), 0, Duration::ZERO)
            .await
            .unwrap_err();
        assert_eq!(err, auth_error());
        assert!(err.halts_scan());
        assert_eq!(client.call_count(), 4);
    }

    #[tokio::test]
    async fn chat_with_retry_survives_a_credential_that_recovers() {
        let client = ScriptedClient::new(vec![Err(auth_error()), Ok(text_response("ok"))]);
        let response = chat_with_retry(&client, &a_request(), 0, Duration::ZERO)
            .await
            .unwrap();
        assert_eq!(response.text(), "ok");
    }

    /// The bug this closes: a turn cut off by its budget is not a tool
    /// call, so the loop used to hand the half-written text back as the
    /// session's final answer.
    #[tokio::test]
    async fn a_truncated_final_turn_is_retried_at_double_the_budget() {
        let client = ScriptedClient::new(vec![
            Ok(truncated_response("VERDICT: TRUE_POS")),
            Ok(text_response("VERDICT: TRUE_POSITIVE")),
        ]);
        let mut cfg = instant_config();
        cfg.max_tokens = 1000;
        let outcome = run_agentic(&client, &FakeTools::new(), "hi", &cfg)
            .await
            .unwrap();
        assert_eq!(outcome.final_text, "VERDICT: TRUE_POSITIVE");
        assert_eq!(client.budgets(), vec![1000, 2000]);
    }

    #[tokio::test]
    async fn a_session_whose_turn_stays_truncated_fails_with_the_partial() {
        let client = ScriptedClient::new(vec![
            Ok(truncated_response("VERDICT: TR")),
            Ok(truncated_response("VERDICT: TRUE_")),
        ]);
        let mut cfg = instant_config();
        cfg.max_tokens = 1000;
        cfg.max_tokens_ceiling = Some(1500);
        let err = run_agentic(&client, &FakeTools::new(), "hi", &cfg)
            .await
            .unwrap_err();
        assert_eq!(
            err,
            LlmError::Truncated {
                requested: 1000,
                retried_at: Some(1500),
                partial: Box::new(truncated_response("VERDICT: TRUE_")),
            }
        );
        assert_eq!(client.budgets(), vec![1000, 1500]);
        assert_eq!(client.truncation_notes(), 1);
    }

    /// An overflow naming the doubled budget is the provider's cap, not
    /// history to evict: nothing is shrunk and the first reply comes back.
    #[tokio::test]
    async fn an_agentic_budget_refusal_on_the_retry_is_the_cap_not_an_overflow() {
        let client = ScriptedClient::new(vec![
            Ok(truncated_response("partial")),
            Err(LlmError::ContextOverflow {
                message: "input length and `max_tokens` exceed context limit".to_string(),
            }),
        ]);
        let err = run_agentic(&client, &FakeTools::new(), "hi", &instant_config())
            .await
            .unwrap_err();
        assert_eq!(
            err,
            LlmError::Truncated {
                requested: 16_000,
                retried_at: Some(32_000),
                partial: Box::new(truncated_response("partial")),
            }
        );
        assert_eq!(client.call_count(), 2);
    }

    #[tokio::test]
    async fn an_agentic_turn_retries_authentication_before_halting() {
        let client = ScriptedClient::new(vec![Err(auth_error()), Ok(text_response("done"))]);
        let outcome = run_agentic(&client, &FakeTools::new(), "hi", &instant_config())
            .await
            .unwrap();
        assert_eq!(outcome.final_text, "done");
        assert_eq!(client.call_count(), 2);
    }
}
