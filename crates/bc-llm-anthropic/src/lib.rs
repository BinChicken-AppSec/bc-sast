//! The Anthropic-compatible Messages API `LlmClient` dialect, ported from
//! `vvaharness/backends/sdk.py`. Speaks to `https://api.anthropic.com` or
//! any gateway (Bifrost, Portkey) exposing the same Messages API
//! request/response shape.
//!
//! Deliberately narrower than the Python original for now — see
//! `bc_llm_openai`'s crate doc for why parameter-drop and transient-status
//! retry logic are out of scope here (dialect quirks needing real-model
//! verification, or generic retry policy that belongs in
//! `bc-llm-agentic`).

mod client;
mod request;
mod response;
mod stream;

pub use client::AnthropicClient;
