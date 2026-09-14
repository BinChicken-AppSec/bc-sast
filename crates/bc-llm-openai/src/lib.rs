//! The OpenAI-compatible chat-completions `LlmClient` dialect, ported from
//! `vvaharness/backends/oai.py`. Speaks to `https://api.openai.com/v1` or
//! any gateway (Bifrost, Portkey) exposing the same Chat Completions
//! request/response shape.
//!
//! Deliberately narrower than the Python original for now: no
//! parameter-drop retry (`temperature`/`max_tokens` rejection handling)
//! and no transient-status retry loop — those quirks are either dialect
//! request-shape corrections that need verifying against a real model
//! before porting, or generic retry policy that belongs in
//! `bc-llm-agentic` (operating on [`bc_llm_client::LlmError::is_retryable`]
//! uniformly across dialects) rather than duplicated per backend.

mod client;
mod request;
mod response;
mod stream;

pub use client::OpenAiClient;
