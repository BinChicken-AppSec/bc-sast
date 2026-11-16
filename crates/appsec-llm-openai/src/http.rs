use std::time::Duration;

use appsec_llm_client::{LlmError, SseDecoder};
use serde_json::Value;

use crate::errors::parse_retry_after;

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

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Rejected {
    pub status: u16,
    pub body: String,
    pub retry_after: Option<u64>,
}

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
    if let Some(payload) = decoder.finish() {
        assembler.push(&payload)?;
    }
    Ok(assembler.finish())
}

pub(crate) fn map_reqwest_error(e: reqwest::Error) -> LlmError {
    let connect_or_timeout = e.is_timeout() || e.is_connect();
    appsec_llm_client::classify_transport_error(&e, connect_or_timeout)
}
