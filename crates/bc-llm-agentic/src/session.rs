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

/// Send one request, retrying on a retryable transient [`LlmError`]
/// (backoff, capped at `max_transient_retries`) — the single-shot-call
/// counterpart to [`run_agentic`]'s own internal `send_turn`, for stages
/// (S2/S3/S4/S7/S8) that make exactly one `LlmClient::chat` call with no
/// tool-use turns or message history to shrink on a context-overflow
/// error, so only the transient-retry half of `send_turn`'s logic
/// applies. A non-retryable error (including `ContextOverflow`, which
/// single-shot callers have no history to evict from) always propagates
/// immediately.
pub async fn chat_with_retry(
    client: &dyn LlmClient,
    request: &ChatRequest,
    max_transient_retries: u32,
    retry_backoff_base: Duration,
) -> Result<ChatResponse, LlmError> {
    let mut attempts = 0u32;
    loop {
        match client.chat(request).await {
            Ok(response) => return Ok(response),
            Err(e) if e.is_retryable() && attempts < max_transient_retries => {
                attempts += 1;
                let delay = backoff_duration(&e, attempts, retry_backoff_base);
                // The only trace a stalled scan leaves. A 2026-09 CI run
                // spent 80 minutes retrying a provider error and emitted
                // nothing at all, so the first question ("is it working
                // or is it stuck?") had no answer anywhere. `WARN` is the
                // default level for both destinations precisely so this
                // line lands without anyone having to ask for it: see
                // `bc_cli::logging`, which streams to stderr whenever
                // stderr is not a terminal and so nothing is redrawing
                // there.
                // Bound outside the macro, not inline as a field value:
                // `tracing` only evaluates field expressions when a
                // subscriber is listening, so an inline call would be
                // dead code in every test (and this crate's coverage gate
                // is 100 %).
                let delay_secs = delay.as_secs_f64();
                tracing::warn!(
                    error = %e,
                    attempt = attempts,
                    max = max_transient_retries,
                    delay_secs,
                    "transient LLM error; retrying after backoff"
                );
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                continue;
            }
            Err(e) => return Err(e),
        }
    }
}

/// The delay before retry attempt `attempt` (1-indexed) after `err`.
/// `base == Duration::ZERO` is this codebase's established "disable all
/// real sleeping" switch (used pervasively in tests) and always wins,
/// short-circuiting before either the header check or the syscall
/// jitter needs — real callers always pass a non-zero base. Otherwise, a
/// [`LlmError::RateLimited`] carrying a real `Retry-After` value wins
/// outright (the provider's own stated wait time, un-jittered — jittering
/// it down risks re-triggering the same rate limit). Absent that, falls
/// back to `base * attempt` (linear backoff) with up to ±25% jitter, so
/// concurrent callers hitting the same transient failure at once (e.g.
/// S6's per-finding fan-out) don't all wake and retry in lockstep — the
/// thundering-herd risk a fixed schedule invites under real concurrency.
fn backoff_duration(err: &LlmError, attempt: u32, base: Duration) -> Duration {
    if base.is_zero() {
        return Duration::ZERO;
    }
    let scheduled = base.saturating_mul(attempt).mul_f64(jitter_factor());
    if let LlmError::RateLimited {
        retry_after_secs: Some(secs),
    } = err
    {
        // The server's hint is a MINIMUM, not a schedule. Honouring a 1 s
        // `Retry-After` verbatim on every attempt burns the whole retry
        // budget in a few seconds under sustained saturation: a live
        // 2026-09-06 scan lost 24 of 235 verifications to "rate limited
        // (retry after 1s)" that way, with five verifiers in flight.
        // Waiting at least as long as the growing schedule is always
        // allowed and is what actually lets the window recover.
        return Duration::from_secs(*secs).max(scheduled);
    }
    scheduled
}

/// A multiplier in `[0.75, 1.25)`, seeded from the low bits of the
/// current time — no RNG dependency needed for this purpose (avoiding
/// synchronized retries, not cryptographic unpredictability): concurrent
/// callers each read the clock at very slightly different instants, so
/// their jitter naturally decorrelates.
fn jitter_factor() -> f64 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    0.75 + (nanos % 1000) as f64 / 1000.0 * 0.5
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
async fn send_turn(
    client: &dyn LlmClient,
    config: &AgenticConfig,
    messages: &mut [Message],
    tools: &[ToolSpec],
) -> Result<ChatResponse, LlmError> {
    let mut transient_attempts = 0u32;
    let mut shrink_attempts = 0u32;

    loop {
        let request = build_request(config, messages, tools);
        match client.chat(&request).await {
            Ok(response) => return Ok(response),
            Err(LlmError::ContextOverflow { message })
                if shrink_attempts < config.max_context_shrinks =>
            {
                if shrink_history(messages) {
                    shrink_attempts += 1;
                    continue;
                }
                return Err(LlmError::ContextOverflow { message });
            }
            Err(e) if e.is_retryable() && transient_attempts < config.max_transient_retries => {
                transient_attempts += 1;
                let delay = backoff_duration(&e, transient_attempts, config.retry_backoff_base);
                // See `chat_with_retry`'s own note: an agentic session
                // retrying silently is indistinguishable from a hung one.
                let delay_secs = delay.as_secs_f64();
                tracing::warn!(
                    error = %e,
                    attempt = transient_attempts,
                    max = config.max_transient_retries,
                    delay_secs,
                    "transient LLM error in agentic turn; retrying after backoff"
                );
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                continue;
            }
            Err(e) => return Err(e),
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
            }
        }

        fn call_count(&self) -> u32 {
            *self.calls.lock().unwrap()
        }
    }

    #[async_trait]
    impl LlmClient for ScriptedClient {
        async fn chat(&self, _request: &ChatRequest) -> Result<ChatResponse, LlmError> {
            *self.calls.lock().unwrap() += 1;
            self.responses
                .lock()
                .unwrap()
                .pop()
                .expect("ScriptedClient ran out of scripted responses")
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

    // ── backoff_duration / jitter_factor ────────────────────────────────

    #[test]
    fn backoff_duration_is_zero_when_the_base_is_zero_even_for_a_real_retry_after() {
        let err = LlmError::RateLimited {
            retry_after_secs: Some(30),
        };
        assert_eq!(backoff_duration(&err, 1, Duration::ZERO), Duration::ZERO);
    }

    #[test]
    fn backoff_duration_honors_a_real_retry_after_value_unjittered() {
        let err = LlmError::RateLimited {
            retry_after_secs: Some(30),
        };
        // attempt 2 -> linear = 20s, jittered to within [15s, 25s), so the
        // 30s server hint dominates for every jitter value. Picking an
        // attempt whose jittered schedule could exceed the hint would make
        // this assertion pass only about half the time.
        assert_eq!(
            backoff_duration(&err, 2, Duration::from_secs(10)),
            Duration::from_secs(30)
        );
    }

    #[test]
    fn backoff_duration_waits_the_schedule_out_when_it_exceeds_retry_after() {
        // The 1s hint is the live case the schedule exists to defend
        // against: honoring it verbatim burns the retry budget in seconds.
        let err = LlmError::RateLimited {
            retry_after_secs: Some(1),
        };
        let got = backoff_duration(&err, 3, Duration::from_secs(10));
        // attempt 3 -> linear = 30s, jittered to within [22.5s, 37.5s),
        // every value of which outlasts the hint.
        assert!(got >= Duration::from_millis(22_500) && got < Duration::from_millis(37_500));
    }

    #[test]
    fn backoff_duration_falls_back_to_jittered_linear_backoff_without_a_retry_after_value() {
        let err = LlmError::RateLimited {
            retry_after_secs: None,
        };
        let base = Duration::from_secs(10);
        let got = backoff_duration(&err, 2, base);
        // attempt 2 -> linear = 20s, jittered to within [15s, 25s).
        assert!(got >= Duration::from_secs(15) && got < Duration::from_secs(25));
    }

    #[test]
    fn backoff_duration_jitters_a_non_rate_limited_retryable_error_too() {
        let err = LlmError::ServerError {
            status: 503,
            message: "down".to_string(),
        };
        let base = Duration::from_secs(10);
        let got = backoff_duration(&err, 1, base);
        assert!(got >= Duration::from_millis(7500) && got < Duration::from_millis(12500));
    }

    #[test]
    fn jitter_factor_is_always_within_the_documented_range() {
        for _ in 0..20 {
            let f = jitter_factor();
            assert!((0.75..1.25).contains(&f), "{f} out of range");
        }
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
}

#[cfg(test)]
mod retry_after_floor_tests {
    use super::*;

    #[test]
    fn a_small_retry_after_hint_does_not_shortcut_the_growing_schedule() {
        let err = LlmError::RateLimited {
            retry_after_secs: Some(1),
        };
        // attempt 3 at a 10 s base is ~30 s ± 25 % jitter — far more than the
        // 1 s hint, which is a floor and must not win.
        let d = backoff_duration(&err, 3, Duration::from_secs(10));
        assert!(d >= Duration::from_secs(22), "{d:?}");
    }

    #[test]
    fn a_large_retry_after_hint_is_honoured_as_the_floor() {
        let err = LlmError::RateLimited {
            retry_after_secs: Some(120),
        };
        let d = backoff_duration(&err, 1, Duration::from_secs(10));
        assert_eq!(d, Duration::from_secs(120));
    }

    #[test]
    fn a_zero_base_still_means_no_sleep_in_tests() {
        let err = LlmError::RateLimited {
            retry_after_secs: Some(5),
        };
        assert_eq!(backoff_duration(&err, 2, Duration::ZERO), Duration::ZERO);
    }
}
