//! The dialect-agnostic `LlmClient`/`ToolExecutor` trait boundary. Ported
//! from the shared contract implicit across `vvaharness/backends/oai.py`
//! and `vvaharness/backends/sdk.py` — both already normalize onto the same
//! request/response shape and Anthropic-named usage fields by hand; this
//! crate makes that normalization an explicit, typed seam instead.
//!
//! No HTTP, no provider SDK, no concrete dialect lives here — see
//! `bc-llm-openai`/`bc-llm-anthropic` for the two implementations and
//! `bc-sandbox-tools` for the local `ToolExecutor`.

mod chat;
mod client;
mod error;
mod message;
mod scrub;
mod sse;
mod tool;

pub use chat::{ChatRequest, ChatResponse, StopReason, Usage};
pub use client::{LlmClient, StreamLargeResponses, STREAM_LARGE_RESPONSE_TOKENS};
pub use error::LlmError;
pub use message::{ContentBlock, Message, Role};
pub use scrub::{sanitize_error_body, MAX_ERROR_BODY_CHARS};
pub use sse::SseDecoder;
pub use tool::{supported, ToolExecutor, ToolSpec};
