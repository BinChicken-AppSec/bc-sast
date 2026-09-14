//! [`OpenAiClient`]: the `LlmClient` implementation for the OpenAI-compatible
//! chat-completions dialect, ported from `backends/oai.py`'s single-call
//! `prompt()`/`agentic()` request path. Makes exactly one HTTP attempt per
//! [`LlmClient::chat`] call for anything network-transient (rate limits,
//! server errors, connection failures) — that retry/backoff policy is
//! `bc-llm-agentic`'s job, not this crate's, so it applies uniformly
//! across dialects instead of being duplicated per backend the way
//! `backends/oai.py`/`backends/sdk.py` each do today.
//!
//! The one exception, [`adjust_for_unsupported_parameter`]: a bounded,
//! same-call self-correction for OpenAI request-shape assumptions that
//! don't hold for every model — two of them mirroring `backends/oai.py::
//! prompt`'s own retry-and-swap, two with no Python precedent at all (see
//! that function's own doc comment). This isn't resilience to transience
//! (the same request would fail again unmodified); it's correcting a
//! wrong guess about what shape a *specific model* accepts, discovered
//! only from that model's own rejection of the first attempt.

use async_trait::async_trait;
use bc_llm_client::{ChatRequest, ChatResponse, LlmClient, LlmError, SseDecoder};
use serde_json::Value;

use crate::request::build_request_body;
use crate::response::{classify_http_error, parse_response_body, parse_retry_after};
use crate::stream::StreamAssembler;

/// Talks to an OpenAI-compatible `/chat/completions` endpoint — either
/// `https://api.openai.com/v1` directly or an AI gateway (Bifrost, Portkey)
/// speaking the same dialect. The `reqwest::Client` is built and owned by
/// the caller (see `bc-gateway-http::build_client`) so this crate has no
/// TLS/proxy configuration of its own.
pub struct OpenAiClient {
    http: reqwest::Client,
    base_url: String,
    api_key: Option<String>,
}

impl OpenAiClient {
    pub fn new(
        http: reqwest::Client,
        base_url: impl Into<String>,
        api_key: Option<String>,
    ) -> Self {
        OpenAiClient {
            http,
            base_url: base_url.into(),
            api_key,
        }
    }
}

#[async_trait]
impl LlmClient for OpenAiClient {
    async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, LlmError> {
        let mut body = build_request_body(request);
        let url = format!("{}/chat/completions", self.base_url.trim_end_matches('/'));
        // At most 4 same-call corrections: max_tokens<->max_completion_tokens
        // swap once, a too-large completion-token budget clamped down once,
        // temperature removal once, reasoning_effort-to-"none" once. Each
        // mutates/removes (or bounds) the exact key it acts on, so the
        // identical correction can't legitimately fire twice — this only
        // bounds how many *distinct* rejections one call will self-correct,
        // not a generic retry budget.
        let mut retries_left = 4u8;

        loop {
            let mut req = self.http.post(&url).json(&body);
            if let Some(key) = &self.api_key {
                req = req.bearer_auth(key);
            }
            // Per-request deadline overriding the shared client's own
            // default (`bc_gateway_http::GatewayConfig::timeout`, 300 s),
            // mirroring `backends/oai.py:278`'s
            // `client.with_options(timeout=float(timeout))`. A stage
            // asking for 64k output tokens needs the per-step budget
            // (`step3/4/8.timeout`, 1800-3600 s), not the client default.
            if let Some(timeout) = request.timeout {
                req = req.timeout(timeout);
            }

            let mut resp = req.send().await.map_err(map_reqwest_error)?;
            let status = resp.status();
            let retry_after = parse_retry_after(resp.headers());

            // A non-2xx never has a stream body to read, whatever was
            // requested — providers answer a rejected request with an
            // ordinary JSON error document. Reading it whole keeps the
            // parameter-correction path below identical in both modes.
            if !status.is_success() {
                let text = resp.text().await.map_err(map_reqwest_error)?;
                if status.as_u16() == 400
                    && retries_left > 0
                    && adjust_for_unsupported_parameter(&mut body, &text)
                {
                    retries_left -= 1;
                    continue;
                }
                return Err(classify_http_error(status.as_u16(), &text, retry_after));
            }

            let parsed = if request.stream {
                read_stream(&mut resp).await?
            } else {
                let text = resp.text().await.map_err(map_reqwest_error)?;
                serde_json::from_str(&text).map_err(|e| LlmError::Other {
                    message: format!("invalid JSON response: {e}"),
                })?
            };
            return parse_response_body(&parsed);
        }
    }
}

/// Drains a `text/event-stream` response body into the non-streaming
/// response document it amounts to (see [`crate::stream`] for why the
/// reassembly targets the JSON body rather than a `ChatResponse`).
///
/// The whole drain runs inside the deadline the caller already set on
/// this request: `reqwest`'s per-request timeout is a TOTAL one, applied
/// "from when the request starts connecting until the response body has
/// finished" — so a stream that stalls halfway is bounded by exactly the
/// same `ChatRequest::timeout` a non-streamed call is, with no separate
/// idle timer to keep in sync.
async fn read_stream(resp: &mut reqwest::Response) -> Result<Value, LlmError> {
    let mut decoder = SseDecoder::new();
    let mut assembler = StreamAssembler::default();
    while let Some(chunk) = resp.chunk().await.map_err(map_reqwest_error)? {
        for payload in decoder.push(&chunk) {
            assembler.push(&payload)?;
        }
    }
    // A final event whose terminating blank line never arrived — for
    // this dialect that is the chunk carrying `finish_reason` and the
    // usage totals, so dropping it would silently downgrade an ordinary
    // response to "stop reason missing, zero tokens spent".
    if let Some(payload) = decoder.finish() {
        assembler.push(&payload)?;
    }
    Ok(assembler.finish())
}

/// Corrects `body` in place for a `400` whose text names one of three
/// known self-correctable OpenAI request-shape rejections. Returns `true`
/// (retry with the corrected body) when it recognized and applied one of
/// these; `false` (the caller should give up and propagate the original
/// error) for anything else — including a `body` that, despite the error
/// text matching, doesn't actually have the key being corrected (nothing
/// to fix, so nothing to gain by retrying):
///
/// - Swaps whichever of `max_tokens`/`max_completion_tokens` is currently
///   present for the other (a model rejecting one always names
///   `max_completion_tokens` somewhere in its error text, whichever
///   direction the rejection runs). Mirrors `backends/oai.py::prompt`'s
///   own retry-and-swap.
/// - Clamps whichever of `max_tokens`/`max_completion_tokens` is present
///   down to the model's own declared ceiling when OpenAI rejects the
///   value as too large (`"...supports at most N completion tokens..."`).
///   No Python precedent: this project's per-stage `max_tokens` defaults
///   (`bc-config`'s `step_defaults`) were ported verbatim from the Python
///   original, tuned for a larger-output backend (an AI gateway or Claude,
///   per the architecture plan) — talking to OpenAI's API directly can
///   request more than a given model actually allows. Parses the limit
///   straight out of OpenAI's own error text rather than hardcoding a
///   per-model table, so it tracks whatever the real API says today
///   instead of going stale as OpenAI's limits change.
/// - Drops `temperature` (reasoning-class models reject a non-default
///   value entirely). Also mirrored from `backends/oai.py::prompt`.
/// - Sets `reasoning_effort` to `"none"` (some reasoning-effort models
///   reject function/tool calls on the classic chat-completions endpoint
///   unless this is explicit) — a one-shot correction guarded by checking
///   it isn't already `"none"`, since setting it can't help twice. No
///   Python precedent: `reasoning_effort` doesn't exist anywhere in the
///   Python original, which predates this model class; found live against
///   a real OpenAI endpoint, not read out of `backends/oai.py`.
fn adjust_for_unsupported_parameter(body: &mut Value, error_text: &str) -> bool {
    let lower = error_text.to_ascii_lowercase();
    let Some(map) = body.as_object_mut() else {
        return false;
    };
    let max_tokens_swapped = lower.contains("max_completion_tokens")
        && (swap_key(map, "max_completion_tokens", "max_tokens")
            || swap_key(map, "max_tokens", "max_completion_tokens"));
    if max_tokens_swapped || (lower.contains("temperature") && map.remove("temperature").is_some())
    {
        return true;
    }
    if parse_completion_token_limit(&lower).is_some_and(|limit| clamp_max_tokens_key(map, limit)) {
        return true;
    }
    let already_none = map.get("reasoning_effort").and_then(Value::as_str) == Some("none");
    if lower.contains("reasoning_effort") && !already_none {
        map.insert(
            "reasoning_effort".to_string(),
            Value::String("none".to_string()),
        );
        return true;
    }
    false
}

/// Extracts `N` from an OpenAI rejection naming the model's actual
/// completion-token ceiling (`"...supports at most N completion
/// tokens..."`, case-insensitive — `error_text` is expected already
/// lowercased). `None` for any text that doesn't contain this exact
/// phrasing, including a `find` match with no digits following it.
fn parse_completion_token_limit(lower_error_text: &str) -> Option<u64> {
    let marker = "supports at most ";
    let idx = lower_error_text.find(marker)?;
    let rest = &lower_error_text[idx + marker.len()..];
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

/// Sets whichever of `max_completion_tokens`/`max_tokens` is present in
/// `map` to `limit`, returning whether either key was found. `chat()`
/// always sends exactly one of the two (`build_request_body`'s default,
/// or whatever `swap_key` last left behind), so in practice at most one
/// iteration ever matches.
fn clamp_max_tokens_key(map: &mut serde_json::Map<String, Value>, limit: u64) -> bool {
    for key in ["max_completion_tokens", "max_tokens"] {
        if map.contains_key(key) {
            map.insert(key.to_string(), Value::from(limit));
            return true;
        }
    }
    false
}

/// Moves `map[from]` to `map[to]` if present, returning whether it did.
fn swap_key(map: &mut serde_json::Map<String, Value>, from: &str, to: &str) -> bool {
    match map.remove(from) {
        Some(v) => {
            map.insert(to.to_string(), v);
            true
        }
        None => false,
    }
}

fn map_reqwest_error(e: reqwest::Error) -> LlmError {
    if e.is_timeout() || e.is_connect() {
        LlmError::ConnectionError {
            message: e.to_string(),
        }
    } else {
        LlmError::Other {
            message: e.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_llm_client::Message;
    use serde_json::json;
    use wiremock::matchers::{body_partial_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn client_for(server: &MockServer) -> OpenAiClient {
        OpenAiClient::new(
            reqwest::Client::new(),
            server.uri(),
            Some("test-key".to_string()),
        )
    }

    fn request() -> ChatRequest {
        ChatRequest::new("gpt-4o", vec![Message::user_text("hi")], 100)
    }

    #[tokio::test]
    async fn successful_text_response() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .and(header("authorization", "Bearer test-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "choices": [{"message": {"content": "hello back"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 5, "completion_tokens": 2},
            })))
            .mount(&server)
            .await;

        let resp = client_for(&server).chat(&request()).await.unwrap();
        assert_eq!(resp.text(), "hello back");
    }

    fn streaming_request() -> ChatRequest {
        let mut req = request();
        req.stream = true;
        req
    }

    /// Serves `events` as a real `text/event-stream` body.
    fn sse(events: &[&str]) -> ResponseTemplate {
        let body: String = events.iter().map(|e| format!("data: {e}\n\n")).collect();
        ResponseTemplate::new(200)
            .insert_header("content-type", "text/event-stream")
            .set_body_string(body)
    }

    #[tokio::test]
    async fn a_streamed_text_response_assembles_to_the_same_thing_as_a_whole_one() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .and(header("authorization", "Bearer test-key"))
            .and(body_partial_json(
                json!({"stream": true, "stream_options": {"include_usage": true}}),
            ))
            .respond_with(sse(&[
                r#"{"choices":[{"index":0,"delta":{"role":"assistant","content":"hello "}}]}"#,
                r#"{"choices":[{"index":0,"delta":{"content":"back"}}]}"#,
                r#"{"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#,
                r#"{"choices":[],"usage":{"prompt_tokens":5,"completion_tokens":2}}"#,
                "[DONE]",
            ]))
            .mount(&server)
            .await;

        let resp = client_for(&server)
            .chat(&streaming_request())
            .await
            .unwrap();
        assert_eq!(resp.text(), "hello back");
        assert_eq!(resp.stop_reason, bc_llm_client::StopReason::EndTurn);
        assert_eq!(resp.usage.input_tokens, 5);
        assert_eq!(resp.usage.output_tokens, 2);
    }

    #[tokio::test]
    async fn a_streamed_tool_call_reassembles_its_argument_fragments() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(sse(&[
                r#"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"Read","arguments":""}}]}}]}"#,
                r#"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"path\":"}}]}}]}"#,
                r#"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"a.rs\"}"}}]}}]}"#,
                r#"{"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}"#,
                "[DONE]",
            ]))
            .mount(&server)
            .await;

        let resp = client_for(&server)
            .chat(&streaming_request())
            .await
            .unwrap();
        assert_eq!(resp.stop_reason, bc_llm_client::StopReason::ToolUse);
        let calls = resp.tool_uses();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "call_1");
        assert_eq!(calls[0].1, "Read");
        assert_eq!(calls[0].2, &json!({"path": "a.rs"}));
    }

    #[tokio::test]
    async fn an_error_event_mid_stream_fails_the_call() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(sse(&[
                r#"{"choices":[{"index":0,"delta":{"content":"partial answ"}}]}"#,
                r#"{"error":{"type":"server_error","message":"upstream exploded"}}"#,
            ]))
            .mount(&server)
            .await;

        let err = client_for(&server)
            .chat(&streaming_request())
            .await
            .unwrap_err();
        assert!(
            matches!(err, LlmError::ServerError { status: 500, .. }),
            "a truncated answer must never be returned as a complete one: {err:?}"
        );
    }

    /// A rejected streaming request is answered with a plain JSON error
    /// document, not a stream — and must still get the same same-call
    /// parameter correction a non-streaming one does.
    #[tokio::test]
    async fn a_streaming_request_still_gets_the_temperature_drop_correction() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .and(body_partial_json(json!({"temperature": 0.2})))
            .respond_with(
                ResponseTemplate::new(400).set_body_string("unsupported value: 'temperature'"),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(sse(&[
                r#"{"choices":[{"index":0,"delta":{"content":"second try"},"finish_reason":"stop"}]}"#,
                "[DONE]",
            ]))
            .mount(&server)
            .await;

        let mut req = streaming_request();
        req.temperature = Some(0.2);
        let resp = client_for(&server).chat(&req).await.unwrap();
        assert_eq!(resp.text(), "second try");
    }

    #[tokio::test]
    async fn a_stream_whose_last_event_lacks_its_blank_line_is_still_read() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/event-stream")
                    .set_body_string(
                        "data: {\"choices\":[{\"delta\":{\"content\":\"x\"},\
                         \"finish_reason\":\"stop\"}]}\n",
                    ),
            )
            .mount(&server)
            .await;

        let resp = client_for(&server)
            .chat(&streaming_request())
            .await
            .unwrap();
        assert_eq!(resp.text(), "x");
        assert_eq!(resp.stop_reason, bc_llm_client::StopReason::EndTurn);
    }

    #[tokio::test]
    async fn request_without_an_api_key_sends_no_authorization_header() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
            })))
            .mount(&server)
            .await;

        let client = OpenAiClient::new(reqwest::Client::new(), server.uri(), None);
        let resp = client.chat(&request()).await.unwrap();
        assert_eq!(resp.text(), "ok");
    }

    #[tokio::test]
    async fn a_base_url_with_a_trailing_slash_does_not_produce_a_double_slash() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
            })))
            .mount(&server)
            .await;

        let mut base = server.uri();
        base.push('/');
        let client = OpenAiClient::new(reqwest::Client::new(), base, None);
        assert!(client.chat(&request()).await.is_ok());
    }

    #[tokio::test]
    async fn rate_limited_status_maps_to_llm_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(429).set_body_string("slow down"))
            .mount(&server)
            .await;

        let err = client_for(&server).chat(&request()).await.unwrap_err();
        assert_eq!(
            err,
            LlmError::RateLimited {
                retry_after_secs: None
            }
        );
    }

    #[tokio::test]
    async fn rate_limited_response_carries_the_real_retry_after_header_through() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("Retry-After", "30")
                    .set_body_string("slow down"),
            )
            .mount(&server)
            .await;

        let err = client_for(&server).chat(&request()).await.unwrap_err();
        assert_eq!(
            err,
            LlmError::RateLimited {
                retry_after_secs: Some(30)
            }
        );
    }

    #[tokio::test]
    async fn server_error_status_maps_to_llm_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(503).set_body_string("unavailable"))
            .mount(&server)
            .await;

        let err = client_for(&server).chat(&request()).await.unwrap_err();
        assert_eq!(
            err,
            LlmError::ServerError {
                status: 503,
                message: "unavailable".to_string()
            }
        );
    }

    #[tokio::test]
    async fn malformed_json_body_is_a_parse_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
            .mount(&server)
            .await;

        let err = client_for(&server).chat(&request()).await.unwrap_err();
        assert!(matches!(err, LlmError::Other { .. }));
    }

    #[tokio::test]
    async fn a_model_rejecting_max_completion_tokens_retries_with_legacy_max_tokens() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .and(body_partial_json(json!({"max_completion_tokens": 100})))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({
                "error": {
                    "message": "Unsupported parameter: 'max_completion_tokens' is not \
                        supported with this model. Use 'max_tokens' instead.",
                    "param": "max_completion_tokens",
                }
            })))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .and(body_partial_json(json!({"max_tokens": 100})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
            })))
            .mount(&server)
            .await;

        let resp = client_for(&server).chat(&request()).await.unwrap();
        assert_eq!(resp.text(), "ok");
    }

    #[tokio::test]
    async fn a_model_reporting_a_lower_completion_token_ceiling_retries_with_it_clamped() {
        // Mirrors a real rejection from `gpt-4o` when a stage's configured
        // `max_tokens` (this project's step defaults default to 64000,
        // tuned for a larger-output backend) exceeds what the model
        // actually allows on OpenAI's own chat-completions endpoint.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .and(body_partial_json(json!({"max_completion_tokens": 100})))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({
                "error": {
                    "message": "max_tokens is too large: 100. This model supports at \
                        most 16384 completion tokens, whereas you provided 100.",
                    "type": "invalid_request_error",
                    "param": "max_tokens",
                    "code": "invalid_value",
                }
            })))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .and(body_partial_json(json!({"max_completion_tokens": 16384})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
            })))
            .mount(&server)
            .await;

        let resp = client_for(&server).chat(&request()).await.unwrap();
        assert_eq!(resp.text(), "ok");
    }

    #[test]
    fn parse_completion_token_limit_extracts_the_digits_after_the_marker() {
        assert_eq!(
            parse_completion_token_limit(
                "this model supports at most 16384 completion tokens, whereas you provided 100."
            ),
            Some(16384)
        );
    }

    #[test]
    fn parse_completion_token_limit_is_none_without_the_marker_phrase() {
        assert_eq!(
            parse_completion_token_limit("rate limit exceeded, please slow down"),
            None
        );
    }

    #[test]
    fn parse_completion_token_limit_is_none_when_no_digits_follow_the_marker() {
        assert_eq!(
            parse_completion_token_limit("this model supports at most a lot of tokens"),
            None
        );
    }

    #[test]
    fn clamp_max_tokens_key_prefers_max_completion_tokens_when_both_are_absent_it_is_a_no_op() {
        let mut body = json!({"model": "gpt-4o"});
        let map = body.as_object_mut().unwrap();
        assert!(!clamp_max_tokens_key(map, 16384));
    }

    #[test]
    fn clamp_max_tokens_key_overwrites_the_legacy_max_tokens_key_when_present() {
        let mut body = json!({"model": "gpt-4o", "max_tokens": 64000});
        let map = body.as_object_mut().unwrap();
        assert!(clamp_max_tokens_key(map, 16384));
        assert_eq!(body["max_tokens"], 16384);
    }

    #[test]
    fn adjust_for_unsupported_parameter_clamps_a_too_large_legacy_max_tokens_value() {
        // Exercised directly (rather than only through the wiremock e2e
        // test above, which covers the default `max_completion_tokens`
        // key) so the legacy-key branch of `clamp_max_tokens_key` is
        // reachable without needing `build_request_body` to ever produce
        // that shape.
        let mut body = json!({"model": "gpt-4o", "max_tokens": 64000});
        let adjusted = adjust_for_unsupported_parameter(
            &mut body,
            "max_tokens is too large: 64000. This model supports at most 16384 \
             completion tokens, whereas you provided 64000.",
        );
        assert!(adjusted);
        assert_eq!(body["max_tokens"], 16384);
    }

    #[test]
    fn adjust_for_unsupported_parameter_on_a_non_object_body_is_a_no_op() {
        // `build_request_body` always produces a JSON object, so this
        // shape is unreachable through the normal `chat()` path — a
        // direct, whitebox test of the defensive fallback rather than
        // something contrived through the public API.
        let mut body = json!([1, 2, 3]);
        assert!(!adjust_for_unsupported_parameter(
            &mut body,
            "max_completion_tokens is not supported"
        ));
        assert_eq!(body, json!([1, 2, 3]));
    }

    #[test]
    fn a_model_requiring_max_completion_tokens_retries_when_max_tokens_was_sent() {
        // Only reachable if some future caller builds a request whose body
        // already carries the legacy `max_tokens` key instead of
        // `build_request_body`'s own `max_completion_tokens` default —
        // exercised directly against `adjust_for_unsupported_parameter`
        // rather than contriving that through `build_request_body`, which
        // has no way to produce this shape today.
        let mut body = json!({"model": "o1", "messages": [], "max_tokens": 100});
        let adjusted = adjust_for_unsupported_parameter(
            &mut body,
            "Unsupported parameter: 'max_tokens' is not supported with this model. \
             Use 'max_completion_tokens' instead.",
        );
        assert!(adjusted);
        assert_eq!(body["max_completion_tokens"], 100);
        assert!(body.get("max_tokens").is_none());
    }

    #[tokio::test]
    async fn a_reasoning_model_rejecting_temperature_retries_without_it() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .and(body_partial_json(json!({"temperature": 0.2})))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({
                "error": {
                    "message": "Unsupported value: 'temperature' does not support 0.2 \
                        with this model.",
                    "param": "temperature",
                }
            })))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
            })))
            .mount(&server)
            .await;

        let mut req = request();
        req.temperature = Some(0.2);
        let resp = client_for(&server).chat(&req).await.unwrap();
        assert_eq!(resp.text(), "ok");
    }

    #[tokio::test]
    async fn a_model_rejecting_function_tools_with_reasoning_effort_retries_with_it_disabled() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({
                "error": {
                    "message": "Function tools with reasoning_effort are not supported \
                        for gpt-5.6-luna in /v1/chat/completions. To use function tools, \
                        use /v1/responses or set reasoning_effort to 'none'.",
                    "param": "reasoning_effort",
                }
            })))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .and(body_partial_json(json!({"reasoning_effort": "none"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
            })))
            .mount(&server)
            .await;

        let resp = client_for(&server).chat(&request()).await.unwrap();
        assert_eq!(resp.text(), "ok");
    }

    #[test]
    fn adjust_for_unsupported_parameter_does_not_retry_when_reasoning_effort_is_already_none() {
        // Guards against an infinite retry loop against a server that
        // keeps rejecting on `reasoning_effort` for some other reason once
        // it's already been set to the one value this correction offers.
        let mut body = json!({"model": "x", "reasoning_effort": "none"});
        assert!(!adjust_for_unsupported_parameter(
            &mut body,
            "reasoning_effort is not supported"
        ));
    }

    #[tokio::test]
    async fn an_unrecognized_400_is_not_retried() {
        let server = MockServer::start().await;
        // No `up_to_n_times` limit: if the client *did* retry, this same
        // mock would serve the second attempt too, and the test would
        // still see a 400 either way. `expect(1)` on the mock (verified at
        // scope-exit) is what actually proves only one request was sent.
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(400).set_body_string("model not found"))
            .expect(1)
            .mount(&server)
            .await;

        let err = client_for(&server).chat(&request()).await.unwrap_err();
        assert_eq!(
            err,
            LlmError::InvalidRequest {
                message: "model not found".to_string()
            }
        );
    }

    #[tokio::test]
    async fn a_per_request_timeout_shorter_than_the_response_delay_fails_as_a_connection_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(std::time::Duration::from_millis(400))
                    .set_body_json(json!({
                        "choices": [{"message": {"content": "too late"}, "finish_reason": "stop"}],
                    })),
            )
            .mount(&server)
            .await;

        let mut req = request();
        req.timeout = Some(std::time::Duration::from_millis(50));
        let err = client_for(&server).chat(&req).await.unwrap_err();
        assert!(
            matches!(err, LlmError::ConnectionError { .. }),
            "unexpected error: {err:?}"
        );
    }

    #[tokio::test]
    async fn a_per_request_timeout_longer_than_the_response_delay_succeeds() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(std::time::Duration::from_millis(20))
                    .set_body_json(json!({
                        "choices": [{"message": {"content": "in time"}, "finish_reason": "stop"}],
                    })),
            )
            .mount(&server)
            .await;

        let mut req = request();
        req.timeout = Some(std::time::Duration::from_secs(30));
        let resp = client_for(&server).chat(&req).await.unwrap();
        assert_eq!(resp.text(), "in time");
    }

    #[tokio::test]
    async fn connection_failure_maps_to_connection_error() {
        // Port 0 never accepts a real connection; reqwest resolves the
        // request against it and gets a connect-level failure without any
        // network flakiness.
        let client = OpenAiClient::new(reqwest::Client::new(), "http://127.0.0.1:0", None);
        let err = client.chat(&request()).await.unwrap_err();
        assert!(matches!(err, LlmError::ConnectionError { .. }));
    }

    #[tokio::test]
    async fn a_send_error_that_is_neither_a_timeout_nor_a_connect_failure_is_other() {
        // A 308 redirecting to itself forever hits reqwest's default
        // max-redirects cap, producing a `send()`-level error that is
        // neither `is_timeout()` nor `is_connect()` (it's `is_redirect()`)
        // — deterministically exercising `map_reqwest_error`'s fallback
        // branch without any real network flakiness.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(308).insert_header("Location", "/chat/completions"))
            .mount(&server)
            .await;

        let err = client_for(&server).chat(&request()).await.unwrap_err();
        assert!(matches!(err, LlmError::Other { .. }));
    }
}
