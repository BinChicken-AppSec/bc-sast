//! [`AnthropicClient`]: the `LlmClient` implementation for the
//! Anthropic-compatible Messages API dialect, ported from
//! `backends/sdk.py`'s single-call agentic request path. Makes exactly one
//! HTTP attempt per [`LlmClient::chat`] call for anything network-transient
//! — see `bc_llm_openai::client`'s module doc for why retry/backoff policy
//! lives in `bc-llm-agentic` instead of here.
//!
//! The one exception mirrors that crate's own
//! `adjust_for_unsupported_parameter`: a bounded, same-call self-correction
//! for a model that rejects an explicit `temperature`. Some Messages API
//! models answer a request carrying `temperature` with a 400 naming that
//! parameter — `backends/sdk.py:294-313` handles exactly this, popping it
//! and resending, and memoizing the model in a module-level
//! `_NO_TEMP_MODELS` set so later calls skip the doomed first attempt.
//! [`AnthropicClient`] carries the same memo per client instance (the
//! pipeline shares one `Arc` of it, so that is the same scope in
//! practice).
//!
//! **Deliberately not ported**: `sdk.py`'s `_NO_TEMP_RX` model-name regex,
//! which guesses up-front from a model's NAME whether it accepts
//! `temperature`. Which models do is a moving target, and a hardcoded name
//! pattern goes stale the moment a family is renamed — while being wrong
//! in the "guessed unsupported, actually fine" direction silently discards
//! the operator's configured temperature, the very determinism knob this
//! change exists to deliver. The reactive memo above reaches the same
//! steady state from the provider's own answer instead, at a cost of one
//! rejected request per model per process.

use std::collections::HashSet;
use std::sync::Mutex;

use async_trait::async_trait;
use bc_llm_client::{ChatRequest, ChatResponse, LlmClient, LlmError, SseDecoder};
use serde_json::Value;

use crate::request::build_request_body;
use crate::response::{classify_http_error, parse_response_body, parse_retry_after};
use crate::stream::StreamAssembler;

const ANTHROPIC_VERSION: &str = "2023-06-01";

/// Talks to an Anthropic-compatible `/v1/messages` endpoint — either
/// `https://api.anthropic.com` directly or an AI gateway (Bifrost,
/// Portkey) exposing the same Messages API shape. The `reqwest::Client` is
/// built and owned by the caller (see `bc-gateway-http::build_client`).
pub struct AnthropicClient {
    http: reqwest::Client,
    base_url: String,
    api_key: Option<String>,
    /// Models this client has seen reject an explicit `temperature`, so
    /// the next call to the same model strips it before sending rather
    /// than spending a request discovering it again. Ported from
    /// `backends/sdk.py`'s module-level `_NO_TEMP_MODELS`.
    no_temperature_models: Mutex<HashSet<String>>,
}

impl AnthropicClient {
    pub fn new(
        http: reqwest::Client,
        base_url: impl Into<String>,
        api_key: Option<String>,
    ) -> Self {
        AnthropicClient {
            http,
            base_url: base_url.into(),
            api_key,
            no_temperature_models: Mutex::new(HashSet::new()),
        }
    }

    /// Whether a previous call already learned that `model` rejects
    /// `temperature`.
    fn temperature_known_unsupported(&self, model: &str) -> bool {
        self.no_temperature_models
            .lock()
            .expect("the temperature memo lock is never held across a panic")
            .contains(model)
    }

    /// Remove `temperature` from `body` for a 400 whose text names it,
    /// memoizing `model` so later calls skip the rejected attempt.
    /// Returns `true` (retry with the corrected body) only when the error
    /// actually matched AND `body` actually carried the key — a `false`
    /// means there is nothing to fix, so nothing to gain by resending.
    /// Mirrors `sdk.py:294-303`'s own `"temperature" in kw and
    /// "temperature" in low and status == 400` condition.
    fn drop_rejected_temperature(&self, model: &str, body: &mut Value, error_text: &str) -> bool {
        if !error_text.to_ascii_lowercase().contains("temperature") {
            return false;
        }
        let Some(map) = body.as_object_mut() else {
            return false;
        };
        if map.remove("temperature").is_none() {
            return false;
        }
        self.no_temperature_models
            .lock()
            .expect("the temperature memo lock is never held across a panic")
            .insert(model.to_string());
        tracing::warn!(
            "[anthropic] {model} rejected an explicit `temperature` — retrying without it, \
             and omitting it for this model from now on."
        );
        true
    }
}

#[async_trait]
impl LlmClient for AnthropicClient {
    async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, LlmError> {
        let mut body = build_request_body(request);
        if self.temperature_known_unsupported(&request.model) {
            if let Some(map) = body.as_object_mut() {
                map.remove("temperature");
            }
        }
        let url = format!("{}/v1/messages", self.base_url.trim_end_matches('/'));
        // Exactly one same-call correction is possible (dropping
        // `temperature`), and it removes the very key it acts on, so the
        // same correction can never fire twice.
        let mut retries_left = 1u8;

        loop {
            let mut req = self
                .http
                .post(&url)
                .header("anthropic-version", ANTHROPIC_VERSION)
                .json(&body);
            if let Some(key) = &self.api_key {
                req = req.header("x-api-key", key);
            }
            if !request.betas.is_empty() {
                req = req.header("anthropic-beta", request.betas.join(","));
            }
            // Per-request deadline overriding the shared client's own
            // default (`bc_gateway_http::GatewayConfig::timeout`, 300 s),
            // mirroring `backends/sdk.py:274`'s
            // `client.with_options(timeout=float(timeout))`.
            if let Some(timeout) = request.timeout {
                req = req.timeout(timeout);
            }

            let mut resp = req.send().await.map_err(map_reqwest_error)?;
            let status = resp.status();
            let retry_after = parse_retry_after(resp.headers());

            // A non-2xx never has a stream body to read, whatever was
            // requested — the API answers a rejected request with an
            // ordinary JSON error document. Reading it whole keeps the
            // `temperature`-drop correction below identical in both modes.
            if !status.is_success() {
                let text = resp.text().await.map_err(map_reqwest_error)?;
                if status.as_u16() == 400
                    && retries_left > 0
                    && self.drop_rejected_temperature(&request.model, &mut body, &text)
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
    // this dialect that can be the `message_delta` carrying the stop
    // reason and the output-token count, so dropping it would silently
    // downgrade an ordinary response to "stop reason missing, zero
    // tokens spent".
    if let Some(payload) = decoder.finish() {
        assembler.push(&payload)?;
    }
    Ok(assembler.finish())
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
    use wiremock::matchers::{body_partial_json, header, headers, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn client_for(server: &MockServer) -> AnthropicClient {
        AnthropicClient::new(
            reqwest::Client::new(),
            server.uri(),
            Some("test-key".to_string()),
        )
    }

    fn request() -> ChatRequest {
        ChatRequest::new("claude-opus-4-6", vec![Message::user_text("hi")], 100)
    }

    #[tokio::test]
    async fn successful_text_response() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .and(header("x-api-key", "test-key"))
            .and(header("anthropic-version", ANTHROPIC_VERSION))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "content": [{"type": "text", "text": "hello back"}],
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 5, "output_tokens": 2},
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

    /// Serves `events` as a real `text/event-stream` body, including the
    /// `event:` name line the Messages API sends (which this port
    /// deliberately ignores in favour of the payload's own `type`).
    fn sse(events: &[&str]) -> ResponseTemplate {
        let body: String = events
            .iter()
            .map(|e| {
                // The `event:` name the Messages API sends, echoed from
                // the payload's own `type`. Empty for a payload without
                // one — this port ignores the line entirely, so its
                // exact value is only realism, never behavior.
                let name = serde_json::from_str::<serde_json::Value>(e)
                    .ok()
                    .and_then(|v| v["type"].as_str().map(str::to_string))
                    .unwrap_or_default();
                format!("event: {name}\ndata: {e}\n\n")
            })
            .collect();
        ResponseTemplate::new(200)
            .insert_header("content-type", "text/event-stream")
            .set_body_string(body)
    }

    #[tokio::test]
    async fn a_streamed_text_response_assembles_to_the_same_thing_as_a_whole_one() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .and(header("x-api-key", "test-key"))
            .and(body_partial_json(json!({"stream": true})))
            .respond_with(sse(&[
                r#"{"type":"message_start","message":{"usage":{"input_tokens":5,"output_tokens":1}}}"#,
                r#"{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}"#,
                r#"{"type":"ping"}"#,
                r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hello "}}"#,
                r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"back"}}"#,
                r#"{"type":"content_block_stop","index":0}"#,
                r#"{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":2}}"#,
                r#"{"type":"message_stop"}"#,
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
    async fn a_streamed_tool_call_reassembles_its_partial_json() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(sse(&[
                r#"{"type":"message_start","message":{"usage":{"input_tokens":9}}}"#,
                r#"{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_1","name":"Read","input":{}}}"#,
                r#"{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"path\":"}}"#,
                r#"{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"\"a.rs\"}"}}"#,
                r#"{"type":"content_block_stop","index":0}"#,
                r#"{"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":11}}"#,
                r#"{"type":"message_stop"}"#,
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
        assert_eq!(calls[0].0, "toolu_1");
        assert_eq!(calls[0].1, "Read");
        assert_eq!(calls[0].2, &json!({"path": "a.rs"}));
    }

    #[tokio::test]
    async fn an_error_event_mid_stream_fails_the_call() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(sse(&[
                r#"{"type":"message_start","message":{"usage":{"input_tokens":9}}}"#,
                r#"{"type":"content_block_start","index":0,"content_block":{"type":"text","text":"partial answ"}}"#,
                r#"{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}"#,
            ]))
            .mount(&server)
            .await;

        let err = client_for(&server)
            .chat(&streaming_request())
            .await
            .unwrap_err();
        assert!(
            matches!(err, LlmError::ServerError { status: 529, .. }),
            "a truncated answer must never be returned as a complete one: {err:?}"
        );
    }

    /// A rejected streaming request is answered with a plain JSON error
    /// document, not a stream — and must still get the same same-call
    /// `temperature` drop (and the memo that skips it next time) a
    /// non-streaming one does.
    #[tokio::test]
    async fn a_streaming_request_still_gets_the_temperature_drop_correction() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .and(body_partial_json(json!({"temperature": 0.2})))
            .respond_with(ResponseTemplate::new(400).set_body_string(
                r#"{"error":{"message":"temperature is not supported for this model"}}"#,
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(sse(&[
                r#"{"type":"content_block_start","index":0,"content_block":{"type":"text","text":"second try"}}"#,
                r#"{"type":"content_block_stop","index":0}"#,
                r#"{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":2}}"#,
            ]))
            .mount(&server)
            .await;

        let client = client_for(&server);
        let mut req = streaming_request();
        req.temperature = Some(0.2);
        let resp = client.chat(&req).await.unwrap();
        assert_eq!(resp.text(), "second try");
        assert!(client.temperature_known_unsupported(&req.model));
    }

    #[tokio::test]
    async fn a_stream_whose_last_event_lacks_its_blank_line_is_still_read() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/event-stream")
                    .set_body_string(
                        "data: {\"type\":\"content_block_start\",\"index\":0,\
                         \"content_block\":{\"type\":\"text\",\"text\":\"x\"}}\n\n\
                         data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\
                         \"usage\":{\"output_tokens\":1}}\n",
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
        assert_eq!(resp.usage.output_tokens, 1);
    }

    #[tokio::test]
    async fn request_without_an_api_key_sends_no_x_api_key_header() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "content": [{"type": "text", "text": "ok"}],
                "stop_reason": "end_turn",
            })))
            .mount(&server)
            .await;

        let client = AnthropicClient::new(reqwest::Client::new(), server.uri(), None);
        let resp = client.chat(&request()).await.unwrap();
        assert_eq!(resp.text(), "ok");
    }

    #[tokio::test]
    async fn betas_are_sent_as_a_comma_joined_header() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            // wiremock's `headers()` matcher splits the actual header value
            // on `,` before comparing, so the expected list is the
            // individual betas, not the joined string this crate actually
            // sends — confirmed via the raw header value in
            // `the_beta_header_value_is_a_single_comma_joined_string` below.
            .and(headers("anthropic-beta", vec!["beta-one", "beta-two"]))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "content": [{"type": "text", "text": "ok"}],
                "stop_reason": "end_turn",
            })))
            .mount(&server)
            .await;

        let mut req = request();
        req.betas = vec!["beta-one".to_string(), "beta-two".to_string()];
        let resp = client_for(&server).chat(&req).await.unwrap();
        assert_eq!(resp.text(), "ok");
    }

    #[tokio::test]
    async fn the_beta_header_value_is_a_single_comma_joined_string() {
        // Anthropic's documented `anthropic-beta` header format is one
        // header line with comma-separated beta names, not repeated header
        // instances — assert the exact wire value directly via the
        // server's request log, since wiremock's matchers can't express
        // "one header, this literal value" for a comma-containing value
        // (see the matcher note above).
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "content": [{"type": "text", "text": "ok"}],
                "stop_reason": "end_turn",
            })))
            .mount(&server)
            .await;

        let mut req = request();
        req.betas = vec!["beta-one".to_string(), "beta-two".to_string()];
        client_for(&server).chat(&req).await.unwrap();

        let received = server.received_requests().await.unwrap();
        let value = received[0]
            .headers
            .get("anthropic-beta")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(value, "beta-one,beta-two");
    }

    #[tokio::test]
    async fn a_base_url_with_a_trailing_slash_does_not_produce_a_double_slash() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "content": [{"type": "text", "text": "ok"}],
                "stop_reason": "end_turn",
            })))
            .mount(&server)
            .await;

        let mut base = server.uri();
        base.push('/');
        let client = AnthropicClient::new(reqwest::Client::new(), base, None);
        assert!(client.chat(&request()).await.is_ok());
    }

    #[tokio::test]
    async fn rate_limited_status_maps_to_llm_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
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
            .and(path("/v1/messages"))
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
    async fn overloaded_status_maps_to_server_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(529).set_body_string("overloaded"))
            .mount(&server)
            .await;

        let err = client_for(&server).chat(&request()).await.unwrap_err();
        assert_eq!(
            err,
            LlmError::ServerError {
                status: 529,
                message: "overloaded".to_string()
            }
        );
    }

    #[tokio::test]
    async fn malformed_json_body_is_a_parse_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
            .mount(&server)
            .await;

        let err = client_for(&server).chat(&request()).await.unwrap_err();
        assert!(matches!(err, LlmError::Other { .. }));
    }

    #[tokio::test]
    async fn a_model_rejecting_temperature_retries_without_it() {
        // The 400 shape current Anthropic models return for an explicit
        // `temperature` — `sdk.py:294-303` detects it the same way (400 +
        // the word "temperature" anywhere in the body).
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .and(body_partial_json(json!({"temperature": 0.0})))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({
                "type": "error",
                "error": {
                    "type": "invalid_request_error",
                    "message": "`temperature` may only be set to 1 when thinking is enabled.",
                },
            })))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "content": [{"type": "text", "text": "ok"}],
                "stop_reason": "end_turn",
            })))
            .mount(&server)
            .await;

        let mut req = request();
        req.temperature = Some(0.0);
        let resp = client_for(&server).chat(&req).await.unwrap();
        assert_eq!(resp.text(), "ok");
    }

    #[tokio::test]
    async fn a_model_that_already_rejected_temperature_never_sends_it_again() {
        // The `_NO_TEMP_MODELS` memo: after the first rejection, the
        // SECOND call must not spend a request rediscovering it. The
        // rejecting mock is capped at one use, so a second doomed attempt
        // would fall through to the success mock and this assertion on
        // the server's request log would see 3 requests, not 2.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .and(body_partial_json(json!({"temperature": 0.0})))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({
                "error": {"message": "`temperature` is not supported for this model."},
            })))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "content": [{"type": "text", "text": "ok"}],
                "stop_reason": "end_turn",
            })))
            .mount(&server)
            .await;

        let client = client_for(&server);
        let mut req = request();
        req.temperature = Some(0.0);
        assert_eq!(client.chat(&req).await.unwrap().text(), "ok");
        assert!(client.temperature_known_unsupported(&req.model));
        assert_eq!(client.chat(&req).await.unwrap().text(), "ok");

        let received = server.received_requests().await.unwrap();
        assert_eq!(
            received.len(),
            3,
            "expected reject + retry + one clean send"
        );
        let last: serde_json::Value = serde_json::from_slice(&received[2].body).unwrap();
        assert!(last.get("temperature").is_none());
    }

    #[tokio::test]
    async fn a_400_naming_temperature_is_not_retried_when_none_was_sent() {
        // Guard against an unbounded retry against a server that keeps
        // saying "temperature" for some unrelated reason: with no
        // `temperature` key to remove, the correction declines and the
        // original error propagates after exactly one request.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(
                ResponseTemplate::new(400)
                    .set_body_string("temperature is not a valid field on this endpoint"),
            )
            .expect(1)
            .mount(&server)
            .await;

        let err = client_for(&server).chat(&request()).await.unwrap_err();
        assert!(matches!(err, LlmError::InvalidRequest { .. }));
    }

    #[tokio::test]
    async fn an_unrelated_400_is_not_retried() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
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

    #[test]
    fn drop_rejected_temperature_on_a_non_object_body_is_a_no_op() {
        // `build_request_body` always produces a JSON object, so this
        // shape is unreachable through `chat()` — a direct, whitebox test
        // of the defensive fallback.
        let client = AnthropicClient::new(reqwest::Client::new(), "http://127.0.0.1:0", None);
        let mut body = json!([1, 2, 3]);
        assert!(!client.drop_rejected_temperature("m", &mut body, "bad temperature"));
        assert_eq!(body, json!([1, 2, 3]));
    }

    #[tokio::test]
    async fn a_per_request_timeout_shorter_than_the_response_delay_fails_as_a_connection_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(std::time::Duration::from_millis(400))
                    .set_body_json(json!({
                        "content": [{"type": "text", "text": "too late"}],
                        "stop_reason": "end_turn",
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
            .and(path("/v1/messages"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(std::time::Duration::from_millis(20))
                    .set_body_json(json!({
                        "content": [{"type": "text", "text": "in time"}],
                        "stop_reason": "end_turn",
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
        let client = AnthropicClient::new(reqwest::Client::new(), "http://127.0.0.1:0", None);
        let err = client.chat(&request()).await.unwrap_err();
        assert!(matches!(err, LlmError::ConnectionError { .. }));
    }

    #[tokio::test]
    async fn a_send_error_that_is_neither_a_timeout_nor_a_connect_failure_is_other() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(308).insert_header("Location", "/v1/messages"))
            .mount(&server)
            .await;

        let err = client_for(&server).chat(&request()).await.unwrap_err();
        assert!(matches!(err, LlmError::Other { .. }));
    }
}
