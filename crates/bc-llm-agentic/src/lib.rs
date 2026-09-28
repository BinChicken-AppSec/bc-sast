//! The dialect-agnostic multi-turn tool-use loop, ported from the
//! `agentic()` functions duplicated across `vvaharness/backends/oai.py` and
//! `vvaharness/backends/sdk.py` — written once here against the
//! `bc-llm-client` trait seam so it runs identically over either dialect.
//!
//! Deliberately excludes the bounded-concurrency multi-session runner
//! (`tokio::task::JoinSet` + `Semaphore` + shared guardrail-abort) that S4/
//! S6 will need: that pattern is generic but its exact shape (what a
//! guardrail trip should look like, what per-session result type callers
//! need) is easier to get right once a concrete Tier-4 stage crate is
//! calling it, rather than guessed at now. Adding it is a small, additive
//! change to this crate when that need is concrete.

mod config;
mod pure;
mod retry;
mod session;
mod truncation;

pub use config::AgenticConfig;
pub use session::{chat_with_retry, chat_with_retry_capped, run_agentic, AgenticOutcome, StopKind};
pub use truncation::salvage_truncated;
