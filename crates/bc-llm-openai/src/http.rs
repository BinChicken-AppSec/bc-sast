//! The I/O both OpenAI API shapes share: one POST, and reading its body
//! whole or as a stream. Kept apart from the transport and correction
//! logic in [`crate::client`] so that logic reads as decisions, not
//! plumbing.

use std::time::Duration;

use bc_llm_client::{LlmError, SseDecoder};
use serde_json::Value;

use crate::errors::parse_retry_after;

/// A shape's stream reassembler (see `crate::chat::stream` and
/// `crate::responses::stream`).
pub(crate) trait Assembler: Default {
    fn push(&mut self, payload: &str) -> Result<(), LlmError>;
    fn finish(self) -> Value;
}

impl Assembler for crate::chat::stream::StreamAssembler {
    fn push(&mut self, payload: &str) -> Result<(), LlmError> {
        crate::chat::stream::StreamAssembler::push(self, payload)
    }
    fn finish(self) -> Value {
        crate::chat::stream::StreamAssembler::finish(self)
    }
}

impl Assembler for crate::responses::stream::StreamAssembler {
    fn push(&mut self, payload: &str) -> Result<(), LlmError> {
        crate::responses::stream::StreamAssembler::push(self, payload)
    }
    fn finish(self) -> Value {
        crate::responses::stream::StreamAssembler::finish(self)
    }
}

/// A non-2xx answer, read whole: providers answer a rejected request
/// with an ordinary JSON error document even when a stream was asked
/// for, which keeps the correction and fallback logic identical in both
/// modes.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Rejected {
    pub status: u16,
    pub body: String,
    pub retry_after: Option<u64>,
}

/// One POST of `body` to `url`. `Ok(Ok(response))` for a 2xx whose body
/// is still unread, `Ok(Err(rejected))` for any other status, and `Err`
/// only when no HTTP answer arrived at all.
pub(crate) async fn post(
    http: &reqwest::Client,
    url: &str,
    api_key: Option<&str>,
    body: &Value,
    timeout: Option<Duration>,
) -> Result<Result<reqwest::Response, Rejected>, LlmError> {
    let mut req = http.post(url).json(body);
    if let Some(key) = api_key {
        req = req.bearer_auth(key);
    }
    // Per-request deadline overriding the shared client's own default
    // (`bc_gateway_http::GatewayConfig::timeout`, 300 s), mirroring
    // `backends/oai.py:278`'s `client.with_options(timeout=...)`.
    if let Some(timeout) = timeout {
        req = req.timeout(timeout);
    }
    let resp = req.send().await.map_err(map_reqwest_error)?;
    let status = resp.status();
    if status.is_success() {
        return Ok(Ok(resp));
    }
    let retry_after = parse_retry_after(resp.headers());
    let body = resp.text().await.map_err(map_reqwest_error)?;
    Ok(Err(Rejected {
        status: status.as_u16(),
        body,
        retry_after,
    }))
}

/// Read a 2xx body into the (non-streamed) response document, draining
/// and reassembling it with `A` when `stream` is set.
///
/// The whole drain runs inside the deadline the caller already set on
/// this request: `reqwest`'s per-request timeout is a TOTAL one, so a
/// stream that stalls halfway is bounded by exactly the same
/// `ChatRequest::timeout` a non-streamed call is.
pub(crate) async fn read_body<A: Assembler>(
    mut resp: reqwest::Response,
    stream: bool,
) -> Result<Value, LlmError> {
    if !stream {
        let text = resp.text().await.map_err(map_reqwest_error)?;
        return serde_json::from_str(&text).map_err(|e| LlmError::Other {
            message: format!("invalid JSON response: {e}"),
        });
    }
    let mut decoder = SseDecoder::new();
    let mut assembler = A::default();
    while let Some(chunk) = resp.chunk().await.map_err(map_reqwest_error)? {
        for payload in decoder.push(&chunk) {
            assembler.push(&payload)?;
        }
    }
    // A final event whose terminating blank line never arrived: for
    // either shape that can be the event carrying the stop reason and
    // usage, so dropping it would silently downgrade an ordinary response.
    if let Some(payload) = decoder.finish() {
        assembler.push(&payload)?;
    }
    Ok(assembler.finish())
}

/// A proxy/TLS cause anywhere in the error chain is VVAH-E002; otherwise
/// a connect failure or timeout stays a retryable connection error. See
/// [`bc_llm_client::classify_transport_error`].
pub(crate) fn map_reqwest_error(e: reqwest::Error) -> LlmError {
    let connect_or_timeout = e.is_timeout() || e.is_connect();
    bc_llm_client::classify_transport_error(&e, connect_or_timeout)
}
