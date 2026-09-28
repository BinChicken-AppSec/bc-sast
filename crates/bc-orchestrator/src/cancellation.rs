//! The orchestrator's half of cooperative Ctrl-C cancellation (the token
//! itself is [`bc_pipeline_core::CancelToken`]; `bc-cli` owns the signal).
//!
//! Three mechanisms, each for a different kind of work:
//!
//! * **Stage gates.** Every [`crate::SpendGate`] consults the token first,
//!   so S4/S6 (and S5/S7's semantic dedup) stop starting new chunks,
//!   sessions and calls exactly as they would for a spent budget, and
//!   in-flight work finishes.
//! * **Stage boundaries.** `run_scan` checks the token before each stage
//!   and records every stage it will no longer run as skipped
//!   ([`skip_stages`]), then falls through to the report tail with the
//!   partial state, as a budget stop does.
//! * **Refused model calls** ([`CancelAwareClient`]), for work that must
//!   not merely stop being *started* but must stop mid-flight: S8's chain
//!   call (so the report tail needs no model after a cancel) and S10/S11's
//!   agentic loops, whose own error paths roll back a partially written
//!   patch when a turn fails.

use std::sync::Arc;

use bc_llm_client::{ChatRequest, ChatResponse, LlmClient, LlmError};
use bc_pipeline_core::{CancelTokenRef, ProgressSink, StageStatus};

use crate::telemetry::{self, StageTimings};

/// Wraps a client so that, once the token is tripped, every NEW call fails
/// at once with a non-retryable error naming the cancellation, instead of
/// reaching the provider. A call already in flight is not interrupted.
///
/// `InvalidRequest` because it is the one existing variant that every
/// retry ladder treats as final: a retryable error would have the loop
/// back off and ask again, which is the opposite of stopping.
pub(crate) struct CancelAwareClient {
    inner: Arc<dyn LlmClient>,
    cancel: Option<CancelTokenRef>,
}

impl CancelAwareClient {
    /// `inner` unchanged in behavior when `cancel` is `None`.
    pub(crate) fn wrap(
        inner: Arc<dyn LlmClient>,
        cancel: Option<CancelTokenRef>,
    ) -> Arc<dyn LlmClient> {
        Arc::new(CancelAwareClient { inner, cancel })
    }
}

#[async_trait::async_trait]
impl LlmClient for CancelAwareClient {
    async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, LlmError> {
        if let Some(reason) = bc_pipeline_core::canceled(self.cancel.as_ref()) {
            return Err(LlmError::InvalidRequest {
                message: format!("{reason}: no new model calls are started"),
            });
        }
        self.inner.chat(request).await
    }

    fn note_truncated_reply(&self) {
        self.inner.note_truncated_reply();
    }
}

/// `llm`, refusing every new call once `cancel` trips (see
/// [`CancelAwareClient`]). Public for the work `bc-cli` runs around
/// remediation (target-test and API-specification generation), which must
/// not start a model session after a cancellation either.
pub fn cancel_aware_client(
    llm: Arc<dyn LlmClient>,
    cancel: Option<CancelTokenRef>,
) -> Arc<dyn LlmClient> {
    CancelAwareClient::wrap(llm, cancel)
}

/// The S1 context a run canceled before S1 carries into the report tail:
/// no files, so every count downstream is honestly zero, and the report
/// still names the repository it was pointed at.
pub(crate) fn empty_context(repo_root: &std::path::Path) -> bc_model::ContextPackage {
    bc_model::ContextPackage {
        repo_root: repo_root.to_string_lossy().into_owned(),
        ..bc_model::ContextPackage::default()
    }
}

/// The S3 manifest of a run canceled before S3: no chunks, so S4 has
/// nothing it could start.
pub(crate) fn empty_manifest() -> bc_model::TaskManifest {
    bc_model::TaskManifest {
        chunks: Vec::new(),
        rationale: String::new(),
        unreachable_files: Vec::new(),
    }
}

/// Marks the report's metrics as canceled when `reason` is `Some`. The
/// budget-stop line normally already names the stage the run stopped in;
/// a cancellation that landed after the last gated stage (during S7) left
/// none, so it is given one here and Scan Health can say where.
pub(crate) fn mark_canceled(metrics: &mut bc_model::ScanMetrics, reason: Option<String>) {
    let Some(reason) = reason else {
        return;
    };
    metrics.canceled = true;
    if metrics.budget_stop.is_empty() {
        metrics.budget_stop = format!("{reason}; stopped before S8");
    }
}

/// Closes every stage in `stages` as skipped because of the cancellation,
/// so the run manifest and the progress lines account for the stages the
/// run will no longer reach instead of silently omitting them.
pub(crate) fn skip_stages(
    progress: Option<&ProgressSink>,
    timings: &mut StageTimings,
    stages: &[&'static str],
    reason: &str,
) {
    for stage in stages {
        telemetry::record_unstarted(
            progress,
            timings,
            stage,
            StageStatus::Skipped,
            Some(reason.to_string()),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_llm_client::{ContentBlock, StopReason, Usage};
    use bc_pipeline_core::{CancelToken, ScanEvent};
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    struct Counting {
        calls: AtomicUsize,
        truncations: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl LlmClient for Counting {
        async fn chat(&self, _request: &ChatRequest) -> Result<ChatResponse, LlmError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(ChatResponse {
                content: vec![ContentBlock::Text("ok".to_string())],
                stop_reason: StopReason::EndTurn,
                usage: Usage::default(),
            })
        }

        fn note_truncated_reply(&self) {
            self.truncations.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn calls_pass_through_until_the_token_trips_then_fail_fast_and_final() {
        let inner = Arc::new(Counting::default());
        let token = CancelToken::new_ref();
        let client = CancelAwareClient::wrap(inner.clone(), Some(token.clone()));
        client.chat(&ChatRequest::default()).await.unwrap();
        client.note_truncated_reply();
        token.cancel(bc_pipeline_core::USER_CANCEL_REASON);
        let err = client.chat(&ChatRequest::default()).await.unwrap_err();
        assert!(!err.is_retryable());
        assert!(
            err.to_string().contains("canceled by user (Ctrl-C)"),
            "{err}"
        );
        assert_eq!(inner.calls.load(Ordering::SeqCst), 1);
        assert_eq!(inner.truncations.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn with_no_token_the_wrapper_never_refuses() {
        let inner = Arc::new(Counting::default());
        let client = CancelAwareClient::wrap(inner.clone(), None);
        client.chat(&ChatRequest::default()).await.unwrap();
        assert_eq!(inner.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn mark_canceled_sets_the_flag_and_fills_an_empty_stop_point_only() {
        let mut m = bc_model::ScanMetrics::default();
        mark_canceled(&mut m, None);
        assert!(!m.canceled);
        mark_canceled(&mut m, Some("why".to_string()));
        assert!(m.canceled);
        assert_eq!(m.budget_stop, "why; stopped before S8");
        m.budget_stop = "S6: why".to_string();
        mark_canceled(&mut m, Some("why".to_string()));
        assert_eq!(m.budget_stop, "S6: why");
    }

    #[test]
    fn the_empty_context_and_manifest_carry_nothing_but_the_repo() {
        let ctx = empty_context(std::path::Path::new("/r"));
        assert_eq!(ctx.repo_root, "/r");
        assert!(ctx.all_files.is_empty());
        assert!(empty_manifest().chunks.is_empty());
    }

    #[test]
    fn skip_stages_closes_each_stage_as_skipped_with_the_reason() {
        let (tx, rx) = std::sync::mpsc::channel();
        let mut timings = StageTimings::new();
        skip_stages(
            Some(&tx),
            &mut timings,
            &["s5-prefilter", "s6-verify"],
            "why",
        );
        drop(tx);
        let events: Vec<ScanEvent> = rx.iter().collect();
        assert_eq!(events.len(), 2);
        assert!(events.iter().all(|e| matches!(
            e,
            ScanEvent::StageFinished { status: StageStatus::Skipped, detail: Some(d), .. } if d == "why"
        )));
        assert_eq!(timings.len(), 2);
    }
}
