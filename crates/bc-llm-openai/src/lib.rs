//! The OpenAI-compatible `LlmClient` dialect. Speaks to
//! `https://api.openai.com/v1` or any gateway (Bifrost, Portkey) exposing
//! the same request/response shapes, over either of OpenAI's two APIs:
//!
//! - **Chat Completions** (`chat`), ported from
//!   `vvaharness/backends/oai.py`.
//! - **The Responses API** (`responses`), ported from the Python
//!   original's DeepAgents route (v1.3+), which is the only OpenAI
//!   endpoint that carries a reasoning model's chain of thought across
//!   tool calls.
//!
//! Which one a call uses is [`OpenAiApi`] (see [`transport`]); what each
//! model accepts comes from `bc_llm_client::capabilities` up front and
//! from [`quirks`] (learned rejections) as the backstop.
//!
//! No transient-status retry loop lives here: that is generic retry
//! policy, and belongs in `bc-llm-agentic` (operating on
//! [`bc_llm_client::LlmError::is_retryable`] uniformly across dialects)
//! rather than duplicated per backend.

mod cache_key;
mod chat;
mod client;
mod errors;
mod http;
mod params;
pub mod quirks;
mod responses;
pub mod transport;
mod usage;

pub use bc_llm_client::OpenAiApi;
pub use client::{LearnedModels, OpenAiClient};
pub use transport::ModelTransport;
