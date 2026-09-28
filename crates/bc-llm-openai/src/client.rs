//! [`OpenAiClient`]: the `LlmClient` implementation for the OpenAI
//! dialect, speaking either Chat Completions (`/chat/completions`,
//! ported from `backends/oai.py`) or the Responses API (`/responses`,
//! ported from the Python original's DeepAgents route), per
//! [`OpenAiApi`].
//!
//! Makes one HTTP attempt per [`LlmClient::chat`] call for anything
//! network-transient (rate limits, server errors, connection failures):
//! that retry/backoff policy is `bc-llm-agentic`'s job, so it applies
//! uniformly across dialects.
//!
//! Two bounded exceptions, both about request SHAPE rather than
//! transience (the same request would fail again unmodified):
//!
//! - **Same-call corrections** ([`crate::quirks`]): a 400 naming a
//!   parameter this model rejects is corrected and resent, and the
//!   correction remembered for the model.
//! - **Transport fallback** ([`crate::transport`]): in
//!   [`OpenAiApi::Auto`], a Responses call the endpoint rejects on shape
//!   is retried once on Chat Completions (and the model remembered as
//!   Chat-only); a Chat Completions call rejected with "use
//!   /v1/responses" is retried once on the Responses API. If the second
//!   transport also fails, what was learned is undone and the ORIGINAL
//!   error returned.

use std::sync::Arc;

use async_trait::async_trait;
use bc_llm_client::capabilities::capabilities;
use bc_llm_client::{ChatRequest, ChatResponse, LlmClient, LlmError, OpenAiApi};

use crate::errors::classify_http_error;
use crate::http::{post, read_body, Rejected};
use crate::quirks::{degrade_reasoning_to_none, QuirkMemory, Shape};
use crate::transport::{
    responses_shape_rejection, route, wants_responses_api, ModelTransport, Route, ShapeRejection,
    TransportMemory,
};
use crate::{chat, responses};

/// At most this many same-call corrections per request. Each correction
/// removes, moves or lowers the key it acts on, so this only bounds how
/// many DISTINCT rejections one call will self-correct.
const MAX_CORRECTIONS: u8 = 6;

/// Everything this process has learned about individual models: which
/// transport each works on and which parameters each rejects. Shared by
/// every call through a client, and by several clients when handed the
/// same `Arc` ([`OpenAiClient::with_learned_models`]).
#[derive(Debug, Default)]
pub struct LearnedModels {
    transport: TransportMemory,
    quirks: QuirkMemory,
}

impl LearnedModels {
    pub fn new() -> Self {
        LearnedModels::default()
    }

    /// Per-model transport state, for diagnostics.
    pub fn transport(&self, model: &str) -> ModelTransport {
        self.transport.state(model)
    }

    /// How many Responses-to-Chat-Completions fallbacks this process has
    /// made, for the run manifest.
    pub fn responses_fallbacks(&self) -> u64 {
        self.transport.fallbacks()
    }
}

/// Talks to an OpenAI-compatible endpoint: `https://api.openai.com/v1`
/// directly or an AI gateway (Bifrost, Portkey) speaking the same
/// dialect. The `reqwest::Client` is built and owned by the caller (see
/// `bc-gateway-http::build_client`) so this crate has no TLS/proxy
/// configuration of its own.
pub struct OpenAiClient {
    http: reqwest::Client,
    base_url: String,
    api_key: Option<String>,
    api: OpenAiApi,
    learned: Arc<LearnedModels>,
}

/// Why one transport attempt failed, kept rich enough to decide whether
/// the OTHER transport is worth a try.
enum Failure {
    Rejected(Rejected),
    /// A 2xx from `/responses` that is not a Responses document.
    NoOutput,
    /// Chat Completions answered "use /v1/responses" in `Auto` mode.
    WantsResponses(Rejected),
    Error(LlmError),
}

impl From<LlmError> for Failure {
    fn from(e: LlmError) -> Self {
        Failure::Error(e)
    }
}

impl Failure {
    fn shape_rejection(&self) -> Option<ShapeRejection> {
        match self {
            Failure::Rejected(r) => responses_shape_rejection(r.status, &r.body),
            Failure::NoOutput => Some(ShapeRejection::NoOutput),
            Failure::WantsResponses(_) | Failure::Error(_) => None,
        }
    }

    fn into_error(self) -> LlmError {
        match self {
            Failure::Rejected(r) | Failure::WantsResponses(r) => {
                classify_http_error(r.status, &r.body, r.retry_after)
            }
            Failure::NoOutput => LlmError::Other {
                message: "the /responses endpoint answered without an `output` array".to_string(),
            },
            Failure::Error(e) => e,
        }
    }
}

impl OpenAiClient {
    /// A client speaking Chat Completions, the historical default.
    pub fn new(
        http: reqwest::Client,
        base_url: impl Into<String>,
        api_key: Option<String>,
    ) -> Self {
        OpenAiClient {
            http,
            base_url: base_url.into(),
            api_key,
            api: OpenAiApi::Chat,
            learned: Arc::new(LearnedModels::new()),
        }
    }

    /// Choose the API shape (`--openai-api`). A request's own
    /// [`ChatRequest::openai_api`] still wins for that request.
    pub fn with_api(mut self, api: OpenAiApi) -> Self {
        self.api = api;
        self
    }

    /// Share learned per-model state with other clients.
    pub fn with_learned_models(mut self, learned: Arc<LearnedModels>) -> Self {
        self.learned = learned;
        self
    }

    /// The configured API shape.
    pub fn api(&self) -> OpenAiApi {
        self.api
    }

    /// What this client has learned so far.
    pub fn learned_models(&self) -> &Arc<LearnedModels> {
        &self.learned
    }

    fn url(&self, path: &str) -> String {
        format!("{}/{path}", self.base_url.trim_end_matches('/'))
    }

    /// One Chat Completions call, with same-call corrections. With
    /// `auto`, a "use /v1/responses" rejection is handed back as
    /// [`Failure::WantsResponses`] instead of degrading reasoning.
    async fn send_chat(&self, request: &ChatRequest, auto: bool) -> Result<ChatResponse, Failure> {
        let model = request.model.as_str();
        let mut body = chat::request::build_request_body(request);
        self.learned
            .quirks
            .apply_learned(&mut body, Shape::Chat, model);
        let url = self.url("chat/completions");
        let mut corrections = MAX_CORRECTIONS;
        loop {
            match post(
                &self.http,
                &url,
                self.api_key.as_deref(),
                &body,
                request.timeout,
            )
            .await?
            {
                Ok(resp) => {
                    let value =
                        read_body::<chat::stream::StreamAssembler>(resp, request.stream).await?;
                    return Ok(chat::response::parse_response_body(&value)?);
                }
                Err(rejected) => {
                    if rejected.status == 400 && corrections > 0 {
                        let corrected = if wants_responses_api(&rejected.body) {
                            if auto {
                                return Err(Failure::WantsResponses(rejected));
                            }
                            degrade_reasoning_to_none(&mut body, model)
                        } else {
                            self.learned.quirks.correct(
                                &mut body,
                                Shape::Chat,
                                model,
                                &rejected.body,
                            )
                        };
                        if corrected {
                            corrections -= 1;
                            continue;
                        }
                    }
                    return Err(Failure::Rejected(rejected));
                }
            }
        }
    }

    /// One Responses API call, with same-call corrections.
    async fn send_responses(&self, request: &ChatRequest) -> Result<ChatResponse, Failure> {
        let model = request.model.as_str();
        let mut body = responses::request::build_request_body(request);
        self.learned
            .quirks
            .apply_learned(&mut body, Shape::Responses, model);
        let url = self.url("responses");
        let mut corrections = MAX_CORRECTIONS;
        loop {
            match post(
                &self.http,
                &url,
                self.api_key.as_deref(),
                &body,
                request.timeout,
            )
            .await?
            {
                Ok(resp) => {
                    let value =
                        read_body::<responses::stream::StreamAssembler>(resp, request.stream)
                            .await?;
                    if !responses::response::has_output(&value) {
                        return Err(Failure::NoOutput);
                    }
                    return Ok(responses::response::parse_response_body(&value)?);
                }
                Err(rejected) => {
                    if rejected.status == 400
                        && corrections > 0
                        && self.learned.quirks.correct(
                            &mut body,
                            Shape::Responses,
                            model,
                            &rejected.body,
                        )
                    {
                        corrections -= 1;
                        continue;
                    }
                    return Err(Failure::Rejected(rejected));
                }
            }
        }
    }

    /// A Responses call that may fall back to Chat Completions.
    async fn responses_then_chat(
        &self,
        request: &ChatRequest,
        may_fall_back: bool,
    ) -> Result<ChatResponse, LlmError> {
        let model = request.model.as_str();
        let transport = &self.learned.transport;
        let failure = match self.send_responses(request).await {
            Ok(resp) => {
                transport.mark_proven(model);
                return Ok(resp);
            }
            Err(failure) => failure,
        };
        let kind = match failure.shape_rejection() {
            Some(kind) if may_fall_back && transport.may_fall_back(model, kind) => kind,
            _ => return Err(failure.into_error()),
        };
        let original = failure.into_error();
        transport.learn_chat_only(model, kind);
        match self.send_chat(request, false).await {
            Ok(resp) => Ok(resp),
            Err(_) => {
                // Both transports failed, so the first rejection proved
                // nothing about the endpoint: un-learn it, and report the
                // error the operator's chosen transport actually hit.
                transport.forget(model);
                Err(original)
            }
        }
    }

    /// A Chat Completions call that, in `Auto` mode, moves to the
    /// Responses API when Chat Completions itself points there.
    async fn chat_then_responses(
        &self,
        request: &ChatRequest,
        auto: bool,
    ) -> Result<ChatResponse, LlmError> {
        let model = request.model.as_str();
        let transport = &self.learned.transport;
        let original = match self.send_chat(request, auto).await {
            Err(Failure::WantsResponses(rejected)) => Failure::Rejected(rejected).into_error(),
            other => return other.map_err(Failure::into_error),
        };
        let before = transport.state(model);
        match self.send_responses(request).await {
            Ok(resp) => {
                transport.mark_proven(model);
                Ok(resp)
            }
            Err(_) => {
                transport.restore(model, before);
                Err(original)
            }
        }
    }
}

#[async_trait]
impl LlmClient for OpenAiClient {
    async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, LlmError> {
        let model = request.model.as_str();
        let state = self.learned.transport.state(model);
        let reasoning = capabilities(model).is_reasoning();
        match route(self.api, request.openai_api, state, reasoning) {
            Route::Chat { auto } => self.chat_then_responses(request, auto).await,
            Route::Responses { may_fall_back } => {
                self.responses_then_chat(request, may_fall_back).await
            }
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
            .and(body_partial_json(json!({"max_completion_tokens": 64000})))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({
                "error": {
                    "message": "max_tokens is too large: 64000. This model supports at \
                        most 16384 completion tokens, whereas you provided 64000.",
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

        let mut req = request();
        req.max_tokens = 64_000;
        let resp = client_for(&server).chat(&req).await.unwrap();
        assert_eq!(resp.text(), "ok");
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
    async fn a_responses_connection_failure_is_a_connection_error_and_never_a_fallback() {
        let client = OpenAiClient::new(reqwest::Client::new(), "http://127.0.0.1:0", None)
            .with_api(OpenAiApi::Auto);
        let err = client.chat(&tool_request("gpt-5.1")).await.unwrap_err();
        assert!(matches!(err, LlmError::ConnectionError { .. }), "{err:?}");
        assert_eq!(
            client.learned_models().transport("gpt-5.1"),
            ModelTransport::Unknown
        );
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

    // ---- Responses API transport and learned fallback -----------------

    fn auto_client(server: &MockServer) -> OpenAiClient {
        client_for(server).with_api(OpenAiApi::Auto)
    }

    fn tool_request(model: &str) -> ChatRequest {
        let mut req = ChatRequest::new(model, vec![Message::user_text("find the bug")], 1000);
        req.tools.push(bc_llm_client::ToolSpec {
            name: "Read".into(),
            description: "read a file".into(),
            parameters: json!({"type": "object"}),
        });
        req
    }

    fn responses_ok(text: &str) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(json!({
            "status": "completed",
            "output": [{"type": "message", "role": "assistant",
                        "content": [{"type": "output_text", "text": text}]}],
            "usage": {"input_tokens": 10, "output_tokens": 2},
        }))
    }

    fn chat_ok(text: &str) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(json!({
            "choices": [{"message": {"content": text}, "finish_reason": "stop"}],
        }))
    }

    async fn mount(server: &MockServer, route: &str, reply: ResponseTemplate, times: u64) {
        Mock::given(method("POST"))
            .and(path(route))
            .respond_with(reply)
            .expect(times)
            .mount(server)
            .await;
    }

    #[test]
    fn a_new_client_speaks_chat_completions_until_told_otherwise() {
        let client = OpenAiClient::new(reqwest::Client::new(), "http://x", None);
        assert_eq!(client.api(), OpenAiApi::Chat);
        let shared = Arc::new(LearnedModels::new());
        let client = client
            .with_api(OpenAiApi::Auto)
            .with_learned_models(shared.clone());
        assert_eq!(client.api(), OpenAiApi::Auto);
        assert!(Arc::ptr_eq(client.learned_models(), &shared));
        assert_eq!(shared.responses_fallbacks(), 0);
    }

    /// The CLI default: `Auto` + gpt-5.6-luna + tools goes to the
    /// Responses API first, stateless and asking for encrypted reasoning.
    #[tokio::test]
    async fn auto_with_gpt_5_6_luna_and_tools_hits_responses_first() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/responses"))
            .and(header("authorization", "Bearer test-key"))
            .and(body_partial_json(json!({
                "model": "gpt-5.6-luna",
                "store": false,
                "include": ["reasoning.encrypted_content"],
            })))
            .respond_with(responses_ok("found it"))
            .expect(1)
            .mount(&server)
            .await;
        mount(&server, "/chat/completions", chat_ok("wrong"), 0).await;

        let client = auto_client(&server);
        let resp = client.chat(&tool_request("gpt-5.6-luna")).await.unwrap();
        assert_eq!(resp.text(), "found it");
        assert_eq!(
            client.learned_models().transport("gpt-5.6-luna"),
            ModelTransport::Proven
        );
    }

    #[tokio::test]
    async fn auto_starts_a_non_reasoning_model_on_chat_completions() {
        let server = MockServer::start().await;
        mount(&server, "/responses", responses_ok("wrong"), 0).await;
        mount(&server, "/chat/completions", chat_ok("chat"), 1).await;
        let resp = auto_client(&server)
            .chat(&tool_request("gpt-4o"))
            .await
            .unwrap();
        assert_eq!(resp.text(), "chat");
    }

    /// A 404 from `/responses` falls back to Chat Completions, and the
    /// second call goes straight there.
    #[tokio::test]
    async fn a_missing_responses_route_falls_back_and_is_remembered() {
        let server = MockServer::start().await;
        mount(
            &server,
            "/responses",
            ResponseTemplate::new(404).set_body_string("no such route"),
            1,
        )
        .await;
        mount(&server, "/chat/completions", chat_ok("via chat"), 2).await;

        let client = auto_client(&server);
        for _ in 0..2 {
            let resp = client.chat(&tool_request("gpt-5.1")).await.unwrap();
            assert_eq!(resp.text(), "via chat");
        }
        let learned = client.learned_models();
        assert_eq!(learned.transport("gpt-5.1"), ModelTransport::ChatOnly);
        assert_eq!(learned.responses_fallbacks(), 1);
    }

    #[tokio::test]
    async fn an_unknown_responses_parameter_or_a_non_responses_body_falls_back() {
        for reply in [
            ResponseTemplate::new(400).set_body_string("Unknown parameter: 'store'."),
            ResponseTemplate::new(200).set_body_json(json!({"choices": []})),
        ] {
            let server = MockServer::start().await;
            mount(&server, "/responses", reply, 1).await;
            mount(&server, "/chat/completions", chat_ok("via chat"), 1).await;
            let resp = auto_client(&server)
                .chat(&tool_request("gpt-5.1"))
                .await
                .unwrap();
            assert_eq!(resp.text(), "via chat");
        }
    }

    /// A transient failure says nothing about the endpoint's shape and
    /// must reach the retry layer unchanged.
    #[tokio::test]
    async fn rate_limits_server_errors_and_bad_bodies_never_fall_back() {
        let cases = [
            (
                ResponseTemplate::new(429).set_body_string("slow down"),
                "RateLimited",
            ),
            (
                ResponseTemplate::new(500).set_body_string("boom"),
                "ServerError",
            ),
            (
                ResponseTemplate::new(200).set_body_string("not json"),
                "Other",
            ),
        ];
        for (reply, kind) in cases {
            let server = MockServer::start().await;
            mount(&server, "/responses", reply, 1).await;
            mount(&server, "/chat/completions", chat_ok("wrong"), 0).await;
            let client = auto_client(&server);
            let err = client.chat(&tool_request("gpt-5.1")).await.unwrap_err();
            assert!(format!("{err:?}").starts_with(kind), "{err:?}");
            assert_eq!(
                client.learned_models().transport("gpt-5.1"),
                ModelTransport::Unknown
            );
        }
    }

    #[tokio::test]
    async fn when_both_transports_fail_the_model_is_unlearned_and_the_original_error_returned() {
        let server = MockServer::start().await;
        mount(
            &server,
            "/responses",
            ResponseTemplate::new(404).set_body_string("responses route missing"),
            1,
        )
        .await;
        mount(
            &server,
            "/chat/completions",
            ResponseTemplate::new(500).set_body_string("chat down"),
            1,
        )
        .await;
        let client = auto_client(&server);
        let err = client.chat(&tool_request("gpt-5.1")).await.unwrap_err();
        assert_eq!(
            err,
            LlmError::InvalidRequest {
                message: "responses route missing".into()
            }
        );
        assert_eq!(
            client.learned_models().transport("gpt-5.1"),
            ModelTransport::Unknown
        );
    }

    #[tokio::test]
    async fn a_pinned_transport_never_falls_back() {
        // Client-level pin.
        let server = MockServer::start().await;
        mount(&server, "/responses", ResponseTemplate::new(404), 2).await;
        mount(&server, "/chat/completions", chat_ok("wrong"), 0).await;
        let client = client_for(&server).with_api(OpenAiApi::Responses);
        assert!(client.chat(&tool_request("gpt-5.1")).await.is_err());
        // Per-request pin on an Auto client.
        let auto = auto_client(&server);
        let mut req = tool_request("gpt-5.1");
        req.openai_api = Some(OpenAiApi::Responses);
        assert!(auto.chat(&req).await.is_err());
    }

    #[tokio::test]
    async fn a_per_request_chat_pin_beats_an_auto_client() {
        let server = MockServer::start().await;
        mount(&server, "/responses", responses_ok("wrong"), 0).await;
        mount(&server, "/chat/completions", chat_ok("chat"), 1).await;
        let mut req = tool_request("gpt-5.6-luna");
        req.openai_api = Some(OpenAiApi::Chat);
        assert_eq!(
            auto_client(&server).chat(&req).await.unwrap().text(),
            "chat"
        );
    }

    #[tokio::test]
    async fn a_proven_model_does_not_fall_back_on_a_body_without_output() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/responses"))
            .respond_with(responses_ok("first"))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/responses"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"odd": true})))
            .mount(&server)
            .await;
        mount(&server, "/chat/completions", chat_ok("wrong"), 0).await;
        let client = auto_client(&server);
        client.chat(&tool_request("gpt-5.1")).await.unwrap();
        let err = client.chat(&tool_request("gpt-5.1")).await.unwrap_err();
        assert!(
            matches!(&err, LlmError::Other { message } if message.contains("output")),
            "{err:?}"
        );
    }

    /// A reasoning model behind a gateway alias starts on Chat
    /// Completions; its "use /v1/responses" rejection moves it over.
    #[tokio::test]
    async fn chat_pointing_at_responses_moves_an_auto_model_over_for_good() {
        let server = MockServer::start().await;
        mount(
            &server,
            "/chat/completions",
            ResponseTemplate::new(400).set_body_string(
                "Function tools with reasoning_effort are not supported for my-alias in \
                 /v1/chat/completions. To use function tools, use /v1/responses.",
            ),
            1,
        )
        .await;
        mount(&server, "/responses", responses_ok("moved"), 2).await;
        let client = auto_client(&server);
        for _ in 0..2 {
            let resp = client.chat(&tool_request("my-alias")).await.unwrap();
            assert_eq!(resp.text(), "moved");
        }
        assert_eq!(
            client.learned_models().transport("my-alias"),
            ModelTransport::Proven
        );
    }

    #[tokio::test]
    async fn a_failed_move_to_responses_restores_the_state_and_returns_the_chat_error() {
        let server = MockServer::start().await;
        mount(
            &server,
            "/chat/completions",
            ResponseTemplate::new(400).set_body_string("use /v1/responses"),
            1,
        )
        .await;
        mount(&server, "/responses", ResponseTemplate::new(503), 1).await;
        let client = auto_client(&server);
        let err = client.chat(&tool_request("my-alias")).await.unwrap_err();
        assert_eq!(
            err,
            LlmError::InvalidRequest {
                message: "use /v1/responses".into()
            }
        );
        assert_eq!(
            client.learned_models().transport("my-alias"),
            ModelTransport::Unknown
        );
    }

    #[tokio::test]
    async fn a_failed_move_keeps_a_chat_only_model_chat_only() {
        let server = MockServer::start().await;
        // Learn chat-only first.
        Mock::given(method("POST"))
            .and(path("/responses"))
            .respond_with(ResponseTemplate::new(404))
            .up_to_n_times(2)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(chat_ok("chat"))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(400).set_body_string("use /v1/responses"))
            .mount(&server)
            .await;
        let client = auto_client(&server);
        client.chat(&tool_request("gpt-5.1")).await.unwrap();
        assert_eq!(
            client.learned_models().transport("gpt-5.1"),
            ModelTransport::ChatOnly
        );
        assert!(client.chat(&tool_request("gpt-5.1")).await.is_err());
        assert_eq!(
            client.learned_models().transport("gpt-5.1"),
            ModelTransport::ChatOnly
        );
    }

    #[tokio::test]
    async fn a_streamed_responses_call_reads_the_terminal_event() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/responses"))
            .and(body_partial_json(json!({"stream": true})))
            .respond_with(sse(&[
                r#"{"type":"response.created","response":{}}"#,
                r#"{"type":"response.completed","response":{"status":"completed","output":[{"type":"message","content":[{"type":"output_text","text":"streamed"}]}],"usage":{"input_tokens":3,"output_tokens":1}}}"#,
            ]))
            .expect(1)
            .mount(&server)
            .await;
        let client = client_for(&server).with_api(OpenAiApi::Responses);
        let mut req = tool_request("gpt-5.1");
        req.stream = true;
        let resp = client.chat(&req).await.unwrap();
        assert_eq!(resp.text(), "streamed");
        assert_eq!(resp.usage.input_tokens, 3);
        let sent: serde_json::Value = server.received_requests().await.unwrap()[0]
            .body_json()
            .unwrap();
        assert!(sent.get("stream_options").is_none());
    }

    #[tokio::test]
    async fn the_responses_shape_gets_same_call_corrections_too() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/responses"))
            .and(body_partial_json(json!({"temperature": 0.3})))
            .respond_with(ResponseTemplate::new(400).set_body_string(
                "Unsupported parameter: 'temperature' is not supported with this model.",
            ))
            .expect(1)
            .mount(&server)
            .await;
        mount(&server, "/responses", responses_ok("ok"), 2).await;
        let client = client_for(&server).with_api(OpenAiApi::Responses);
        let mut req = tool_request("my-reasoning-alias");
        req.temperature = Some(0.3);
        for _ in 0..2 {
            assert_eq!(client.chat(&req).await.unwrap().text(), "ok");
        }
    }

    #[tokio::test]
    async fn an_unrecognized_responses_400_is_returned_as_is() {
        let server = MockServer::start().await;
        mount(
            &server,
            "/responses",
            ResponseTemplate::new(400).set_body_string("bad tool schema"),
            1,
        )
        .await;
        let client = client_for(&server).with_api(OpenAiApi::Responses);
        let err = client.chat(&tool_request("gpt-5.1")).await.unwrap_err();
        assert_eq!(
            err,
            LlmError::InvalidRequest {
                message: "bad tool schema".into()
            }
        );
    }

    /// A learned rejection is paid for once: the failing mock is hit
    /// exactly once across two calls.
    #[tokio::test]
    async fn a_learned_temperature_rejection_is_not_paid_twice() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .and(body_partial_json(json!({"temperature": 0.2})))
            .respond_with(
                ResponseTemplate::new(400).set_body_string("unsupported value: 'temperature'"),
            )
            .expect(1)
            .mount(&server)
            .await;
        mount(&server, "/chat/completions", chat_ok("ok"), 2).await;
        let client = client_for(&server);
        let mut req = request();
        req.temperature = Some(0.2);
        for _ in 0..2 {
            assert_eq!(client.chat(&req).await.unwrap().text(), "ok");
        }
    }

    #[tokio::test]
    async fn a_rejected_prompt_cache_key_is_dropped_and_remembered() {
        let server = MockServer::start().await;
        let mut req = ChatRequest::new("gpt-4o", vec![Message::user_text("x".repeat(6_000))], 100);
        req.cache_key = Some("s4:repo".into());
        let key = crate::cache_key::prompt_cache_key(&req).unwrap();
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .and(body_partial_json(json!({"prompt_cache_key": key})))
            .respond_with(
                ResponseTemplate::new(400)
                    .set_body_string("Unrecognized request argument supplied: prompt_cache_key"),
            )
            .expect(1)
            .mount(&server)
            .await;
        mount(&server, "/chat/completions", chat_ok("ok"), 2).await;
        let client = client_for(&server);
        for _ in 0..2 {
            assert_eq!(client.chat(&req).await.unwrap().text(), "ok");
        }
    }

    struct OneFile;

    impl bc_llm_client::ToolExecutor for OneFile {
        fn available_tools(&self) -> Vec<bc_llm_client::ToolSpec> {
            vec![bc_llm_client::ToolSpec {
                name: "Read".into(),
                description: "read a file".into(),
                parameters: json!({"type": "object"}),
            }]
        }

        fn execute(&self, _name: &str, _args: &serde_json::Value) -> String {
            "fn main() {}".into()
        }
    }

    /// End to end through `run_agentic`: the second request carries the
    /// first turn's reasoning item, then its function call, then the
    /// tool's output, in that order.
    #[tokio::test]
    async fn a_two_turn_agentic_run_replays_reasoning_before_its_function_call() {
        let reasoning = json!({
            "type": "reasoning", "id": "rs_1", "summary": [],
            "encrypted_content": "gAAAA-ciphertext",
        });
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/responses"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "status": "completed",
                "output": [
                    reasoning,
                    {"type": "function_call", "id": "fc_1", "call_id": "call_1",
                     "name": "Read", "arguments": "{\"path\":\"main.rs\"}"},
                ],
            })))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        mount(&server, "/responses", responses_ok("no bug"), 1).await;

        let client = auto_client(&server);
        let mut config = bc_llm_agentic::AgenticConfig::new("gpt-5.6-luna");
        config.allowed_tools = vec!["Read".into()];
        config.retry_backoff_base = std::time::Duration::ZERO;
        let outcome = bc_llm_agentic::run_agentic(&client, &OneFile, "find the bug", &config)
            .await
            .unwrap();
        assert_eq!(outcome.final_text, "no bug");

        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 2);
        let second: serde_json::Value = requests[1].body_json().unwrap();
        assert_eq!(
            second["input"],
            json!([
                {"role": "user", "content": "find the bug"},
                reasoning,
                {"type": "function_call", "call_id": "call_1", "name": "Read",
                 "arguments": "{\"path\":\"main.rs\"}"},
                {"type": "function_call_output", "call_id": "call_1", "output": "fn main() {}"},
            ])
        );
    }

    /// The cost of one cached call against one uncached call, computed
    /// from a real usage document through the whole pricing path, at the
    /// vendored gpt-5.6-luna rates.
    #[test]
    fn cached_and_uncached_calls_are_priced_at_their_own_rates() {
        let uncached = chat::response::parse_response_body(&json!({
            "choices": [{"message": {"content": "x"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 100_000, "completion_tokens": 1_000,
                      "prompt_tokens_details": {"cached_tokens": 0}},
        }))
        .unwrap()
        .usage;
        let cached = responses::response::parse_response_body(&json!({
            "output": [],
            "usage": {"input_tokens": 100_000, "output_tokens": 1_000,
                      "input_tokens_details": {"cached_tokens": 90_000}},
        }))
        .unwrap()
        .usage;
        let pricer = bc_pricing::Pricer::vendored();
        let price = |u: bc_llm_client::Usage| {
            let call = bc_pricing::Call::from_usage(
                u.input_tokens,
                u.output_tokens,
                u.cache_read_input_tokens,
                u.cache_creation_input_tokens,
            );
            let cost = pricer.price_call("openai", "gpt-5.6-luna", &call).unwrap();
            assert_eq!(cost.unrated_tokens, 0);
            cost.total()
        };
        let rates = pricer
            .resolve("openai", "gpt-5.6-luna")
            .unwrap()
            .price
            .clone();
        let input = u128::from(rates.input);
        let output = u128::from(rates.output);
        let read = u128::from(rates.cache_read.unwrap());
        assert!(read < input, "the cached-input rate is a discount");
        assert_eq!(
            price(uncached),
            bc_pricing::Money::from_picodollars(100_000 * input + 1_000 * output)
        );
        assert_eq!(
            price(cached),
            bc_pricing::Money::from_picodollars(10_000 * input + 90_000 * read + 1_000 * output)
        );
    }
}
