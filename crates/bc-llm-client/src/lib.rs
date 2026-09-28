//! The dialect-agnostic `LlmClient`/`ToolExecutor` trait boundary. Ported
//! from the shared contract implicit across `vvaharness/backends/oai.py`
//! and `vvaharness/backends/sdk.py` — both already normalize onto the same
//! request/response shape and Anthropic-named usage fields by hand; this
//! crate makes that normalization an explicit, typed seam instead.
//!
//! No HTTP, no provider SDK, no concrete dialect lives here — see
//! `bc-llm-openai`/`bc-llm-anthropic` for the two implementations and
//! `bc-sandbox-tools` for the local `ToolExecutor`.

mod cache;
mod cache_probe;
pub mod capabilities;
mod chat;
mod classify;
mod client;
mod effort;
mod error;
mod message;
mod openai_api;
mod scrub;
mod sse;
mod tool;

pub use cache::{
    anthropic_min_cacheable_tokens, estimate_tokens, ApplyCachePolicy, CachePolicy, CacheTtl,
    ANTHROPIC_MIN_TOKENS_FALLBACK, CACHE_EST_MARGIN_PERCENT, OPENAI_MIN_CACHEABLE_PROMPT_TOKENS,
};
pub use cache_probe::{
    cache_probe_filler, classify_cache_observations, classify_cache_probe, CacheDialect,
    CacheObservation, CacheProbeVerdict, CACHE_PROBE_FILLER_MIN_TOKENS, CACHE_PROBE_USER_A,
    CACHE_PROBE_USER_B,
};
pub use chat::{ChatRequest, ChatResponse, StopReason, Usage};
pub use classify::{
    classify_auth_or_proxy_status, classify_transport_error, classify_transport_text,
};
pub use client::{LlmClient, StreamLargeResponses, STREAM_LARGE_RESPONSE_TOKENS};
pub use effort::ReasoningEffort;
pub use error::{codes, LlmError};
pub use message::{ContentBlock, Message, OpaqueDialect, Role};
pub use openai_api::OpenAiApi;
pub use scrub::{sanitize_error_body, MAX_ERROR_BODY_CHARS};
pub use sse::SseDecoder;
pub use tool::{supported, ToolExecutor, ToolSpec};
