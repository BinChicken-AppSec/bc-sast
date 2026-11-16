use std::sync::Arc;

use async_trait::async_trait;

use crate::chat::{ChatRequest, ChatResponse};
use crate::error::LlmError;

#[allow(clippy::double_must_use)]
#[async_trait]
pub trait LlmClient: Send + Sync {
    async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, LlmError>;

    fn note_truncated_reply(&self) {}
}

pub const STREAM_LARGE_RESPONSE_TOKENS: u32 = 21_333;

pub struct StreamLargeResponses {
    inner: Arc<dyn LlmClient>,
    threshold: u32,
}

impl StreamLargeResponses {
    pub fn new(inner: Arc<dyn LlmClient>) -> Self {
        StreamLargeResponses {
            inner,
            threshold: STREAM_LARGE_RESPONSE_TOKENS,
        }
    }

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
        assert_eq!(block_on(PendOnce(std::cell::Cell::new(false), 7)), 7);
    }

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
