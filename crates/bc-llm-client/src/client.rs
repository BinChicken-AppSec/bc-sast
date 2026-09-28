//! The `LlmClient` trait — the seam every gateway dialect implementation
//! (`bc-llm-openai`, `bc-llm-anthropic`) and every consumer
//! (`bc-llm-agentic`, the stage crates' tests) is written against.
//!
//! Uses `async-trait` rather than native async-fn-in-trait because it is
//! genuinely `dyn`-dispatched: which dialect backs a given model role is
//! resolved from config at runtime (`bc-cli` builds an `Arc<dyn
//! LlmClient>` per role), unlike `PipelineStage` in `bc-pipeline-core`,
//! which the orchestrator calls in one fixed, compile-time-known sequence.

use std::sync::Arc;

use async_trait::async_trait;

use crate::chat::{ChatRequest, ChatResponse};
use crate::error::LlmError;

#[async_trait]
pub trait LlmClient: Send + Sync {
    async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, LlmError>;

    /// Told once for every confirmed truncation, the moment
    /// `bc-llm-agentic` gives up on a reply and returns
    /// [`LlmError::Truncated`] (VVAH-E005): the Rust counterpart of the
    /// Python original's `COUNTERS.bump("llm_truncated_replies")`. A
    /// truncation the doubled retry fixed is not counted, matching
    /// Python.
    ///
    /// A hook on the client rather than a counter threaded through every
    /// stage because the client is already the one object every call
    /// passes through: a metrics decorator wrapped around it (the
    /// orchestrator's usage tracker) sees every stage's truncations
    /// without any stage knowing it exists. The default is a no-op, and a
    /// decorator that wraps another client must forward it.
    fn note_truncated_reply(&self) {}
}

/// The output-token budget at or above which a request is worth
/// streaming.
///
/// 21,333 is not this project's number — it is the ceiling the official
/// Anthropic SDK itself refuses to send a NON-streaming request above,
/// derived from its own 10-minute default deadline and a conservative
/// tokens-per-second estimate. A request asking for more output than
/// that is one the SDK considers likely to outlive a single silent HTTP
/// response, which is exactly the condition streaming addresses.
///
/// Worth being precise about the Python original here, because it is
/// easy to misread: `backends/sdk.py` streams *unconditionally*
/// (`messages.stream(**kw)`, line 288-289), with the comment "Stream so
/// large max_tokens (64k) doesn't trip the HTTP timeout". It has no
/// threshold of its own — the 21,333 figure is the SDK's, and this port
/// adopts it as the point where the same reasoning starts to apply,
/// rather than streaming every 500-token call for no benefit.
pub const STREAM_LARGE_RESPONSE_TOKENS: u32 = 21_333;

/// Wraps any [`LlmClient`] so a request asking for at least
/// [`STREAM_LARGE_RESPONSE_TOKENS`] output tokens is sent as a stream.
///
/// **Why a wrapper and not a config field on each stage.** Whether a
/// call is large enough to be worth streaming is a transport question —
/// it depends only on `max_tokens`, which the request already carries —
/// and every stage would otherwise need an identical knob threaded
/// through its own config just to answer it the same way. One decorator
/// at the point the client is built (`bc-cli::build_llm_client`) applies
/// the policy to every stage, present and future, without any of them
/// knowing it exists.
///
/// A request that already asked to stream is passed through untouched:
/// this only ever turns streaming ON, never off.
pub struct StreamLargeResponses {
    inner: Arc<dyn LlmClient>,
    threshold: u32,
}

impl StreamLargeResponses {
    /// Wrap `inner`, streaming any request whose `max_tokens` is at
    /// least [`STREAM_LARGE_RESPONSE_TOKENS`].
    pub fn new(inner: Arc<dyn LlmClient>) -> Self {
        StreamLargeResponses {
            inner,
            threshold: STREAM_LARGE_RESPONSE_TOKENS,
        }
    }

    /// Same, with an explicit threshold — for tests, which would
    /// otherwise have to build a 21,333-token request to observe the
    /// wrapper doing anything.
    pub fn with_threshold(inner: Arc<dyn LlmClient>, threshold: u32) -> Self {
        StreamLargeResponses { inner, threshold }
    }
}

#[async_trait]
impl LlmClient for StreamLargeResponses {
    async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, LlmError> {
        if request.stream || request.max_tokens < self.threshold {
            return self.inner.chat(request).await;
        }
        // Cloned only on the branch that actually changes something. One
        // clone of a prompt is microseconds against a model call that
        // runs for minutes — which is the whole reason this request
        // qualified for streaming in the first place.
        let mut streamed = request.clone();
        streamed.stream = true;
        self.inner.chat(&streamed).await
    }

    fn note_truncated_reply(&self) {
        self.inner.note_truncated_reply();
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::chat::{StopReason, Usage};
    use crate::message::Message;

    struct EchoClient;

    #[async_trait]
    impl LlmClient for EchoClient {
        async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, LlmError> {
            Ok(ChatResponse {
                content: vec![crate::message::ContentBlock::text(format!(
                    "echo:{}",
                    request.model
                ))],
                stop_reason: StopReason::EndTurn,
                usage: Usage::default(),
            })
        }
    }

    struct FailingClient;

    #[async_trait]
    impl LlmClient for FailingClient {
        async fn chat(&self, _request: &ChatRequest) -> Result<ChatResponse, LlmError> {
            Err(LlmError::RateLimited {
                retry_after_secs: Some(1),
            })
        }
    }

    // A minimal poll-to-completion driver (std's built-in no-op waker,
    // stable since 1.85) so `async-trait`'s boxed futures can be exercised
    // end-to-end without pulling a real async runtime into this crate's
    // tests. Every fake `LlmClient` in this module resolves on its first
    // poll, so a single `poll()` call would suffice, but looping keeps this
    // driver correct if a future ever legitimately returns `Pending`.
    pub(crate) fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        use std::task::{Context, Poll, Waker};

        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut fut = Box::pin(fut);
        loop {
            if let Poll::Ready(val) = fut.as_mut().poll(&mut cx) {
                return val;
            }
        }
    }

    #[test]
    fn dyn_llm_client_chat_returns_ok() {
        let client: Box<dyn LlmClient> = Box::new(EchoClient);
        let req = ChatRequest::new("gpt-4o", vec![Message::user_text("hi")], 100);
        let resp = block_on(client.chat(&req)).unwrap();
        assert_eq!(resp.text(), "echo:gpt-4o");
    }

    struct PendOnce(std::cell::Cell<bool>, i32);

    impl std::future::Future for PendOnce {
        type Output = i32;
        fn poll(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<i32> {
            if self.0.get() {
                std::task::Poll::Ready(self.1)
            } else {
                self.0.set(true);
                cx.waker().wake_by_ref();
                std::task::Poll::Pending
            }
        }
    }

    #[test]
    fn block_on_loops_past_a_pending_poll() {
        // Every fake `LlmClient` above resolves on its first poll, so this
        // exercises the loop's continue-past-`Pending` path directly rather
        // than leaving it untested.
        assert_eq!(block_on(PendOnce(std::cell::Cell::new(false), 7)), 7);
    }

    /// Reports back whether the request it was handed asked to stream.
    struct StreamProbe(std::sync::Mutex<Option<bool>>);

    #[async_trait]
    impl LlmClient for StreamProbe {
        async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, LlmError> {
            *self.0.lock().unwrap() = Some(request.stream);
            Ok(ChatResponse {
                content: Vec::new(),
                stop_reason: StopReason::EndTurn,
                usage: Usage::default(),
            })
        }
    }

    fn saw_stream(threshold: u32, max_tokens: u32, already_streaming: bool) -> bool {
        let probe = std::sync::Arc::new(StreamProbe(std::sync::Mutex::new(None)));
        let client = StreamLargeResponses::with_threshold(probe.clone(), threshold);
        let mut req = ChatRequest::new("m", vec![Message::user_text("hi")], max_tokens);
        req.stream = already_streaming;
        block_on(client.chat(&req)).unwrap();
        let seen = *probe.0.lock().unwrap();
        seen.expect("the inner client was called")
    }

    #[test]
    fn a_request_at_or_above_the_threshold_is_streamed() {
        assert!(saw_stream(100, 100, false), "at the threshold");
        assert!(saw_stream(100, 101, false), "above it");
    }

    #[test]
    fn a_request_below_the_threshold_is_left_alone() {
        assert!(!saw_stream(100, 99, false));
    }

    #[test]
    fn a_request_that_already_asked_to_stream_is_passed_through() {
        assert!(saw_stream(100, 1, true), "the wrapper never turns it off");
    }

    #[test]
    fn the_default_threshold_is_the_anthropic_sdks_own_non_streaming_ceiling() {
        assert_eq!(STREAM_LARGE_RESPONSE_TOKENS, 21_333);
        let probe = std::sync::Arc::new(StreamProbe(std::sync::Mutex::new(None)));
        let client = StreamLargeResponses::new(probe.clone());
        let req = ChatRequest::new("m", vec![Message::user_text("hi")], 21_333);
        block_on(client.chat(&req)).unwrap();
        assert_eq!(*probe.0.lock().unwrap(), Some(true));
    }

    /// Counts the truncation notes it is handed.
    struct TruncationCounter(std::sync::atomic::AtomicU32);

    #[async_trait]
    impl LlmClient for TruncationCounter {
        async fn chat(&self, _request: &ChatRequest) -> Result<ChatResponse, LlmError> {
            Err(LlmError::Other {
                message: "not a real client".to_string(),
            })
        }

        fn note_truncated_reply(&self) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    #[test]
    fn the_default_truncation_note_is_a_harmless_no_op() {
        EchoClient.note_truncated_reply();
    }

    #[test]
    fn the_streaming_wrapper_forwards_a_truncation_note_to_the_client_it_wraps() {
        let counter = std::sync::Arc::new(TruncationCounter(std::sync::atomic::AtomicU32::new(0)));
        let client = StreamLargeResponses::new(counter.clone());
        client.note_truncated_reply();
        client.note_truncated_reply();
        assert_eq!(counter.0.load(std::sync::atomic::Ordering::Relaxed), 2);
        // Chatting through the wrapper is not a truncation note.
        let req = ChatRequest::new("m", vec![Message::user_text("hi")], 1);
        assert!(block_on(client.chat(&req)).is_err());
        assert_eq!(counter.0.load(std::sync::atomic::Ordering::Relaxed), 2);
    }

    #[test]
    fn the_wrapper_propagates_the_inner_clients_error() {
        let client = StreamLargeResponses::new(std::sync::Arc::new(FailingClient));
        let req = ChatRequest::new("m", vec![Message::user_text("hi")], 1);
        assert_eq!(
            block_on(client.chat(&req)).unwrap_err(),
            LlmError::RateLimited {
                retry_after_secs: Some(1)
            }
        );
    }

    #[test]
    fn dyn_llm_client_chat_propagates_errors() {
        let client: Box<dyn LlmClient> = Box::new(FailingClient);
        let req = ChatRequest::new("gpt-4o", vec![Message::user_text("hi")], 100);
        let err = block_on(client.chat(&req)).unwrap_err();
        assert_eq!(
            err,
            LlmError::RateLimited {
                retry_after_secs: Some(1)
            }
        );
    }
}
