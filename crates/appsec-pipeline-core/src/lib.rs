use std::fmt;

mod cancel;
pub use cancel::{canceled, CancelToken, CancelTokenRef, USER_CANCEL_REASON};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StageOutcome<T> {
    Ok(T),
    Degraded { value: T, reason: String },
}

impl<T> StageOutcome<T> {
    pub fn is_degraded(&self) -> bool {
        matches!(self, StageOutcome::Degraded { .. })
    }

    pub fn reason(&self) -> Option<&str> {
        match self {
            StageOutcome::Ok(_) => None,
            StageOutcome::Degraded { reason, .. } => Some(reason.as_str()),
        }
    }

    pub fn into_value(self) -> T {
        match self {
            StageOutcome::Ok(v) => v,
            StageOutcome::Degraded { value, .. } => value,
        }
    }

    pub fn value(&self) -> &T {
        match self {
            StageOutcome::Ok(v) => v,
            StageOutcome::Degraded { value, .. } => value,
        }
    }

    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> StageOutcome<U> {
        match self {
            StageOutcome::Ok(v) => StageOutcome::Ok(f(v)),
            StageOutcome::Degraded { value, reason } => StageOutcome::Degraded {
                value: f(value),
                reason,
            },
        }
    }
}

#[derive(Debug)]
pub struct StageError {
    pub stage: &'static str,
    pub message: String,
}

impl StageError {
    pub fn new(stage: &'static str, message: impl Into<String>) -> Self {
        Self {
            stage,
            message: message.into(),
        }
    }
}

impl fmt::Display for StageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.stage, self.message)
    }
}

impl std::error::Error for StageError {}

pub trait PipelineStage {
    type Input;
    type Output;
    const NAME: &'static str;

    fn run(
        &self,
        input: Self::Input,
    ) -> impl std::future::Future<Output = Result<StageOutcome<Self::Output>, StageError>> + Send;
}

pub trait BudgetGate: std::fmt::Debug + Send + Sync {
    fn should_stop(&self) -> bool;

    fn stop_reason(&self) -> String;

    fn trip(&self, _reason: String) {}
}

pub type BudgetGateRef = std::sync::Arc<dyn BudgetGate>;

pub fn budget_allows(gate: Option<&BudgetGateRef>) -> bool {
    !gate.is_some_and(|g| g.should_stop())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StageStatus {
    Completed,
    CompletedWithErrors,
    Cached,
    Skipped,
    Disabled,
    Error,
}

impl StageStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            StageStatus::Completed => "completed",
            StageStatus::CompletedWithErrors => "completed_with_errors",
            StageStatus::Cached => "cached",
            StageStatus::Skipped => "skipped",
            StageStatus::Disabled => "disabled",
            StageStatus::Error => "error",
        }
    }

    pub fn from_degraded(degraded: bool) -> Self {
        if degraded {
            StageStatus::CompletedWithErrors
        } else {
            StageStatus::Completed
        }
    }

    pub fn is_timed(self) -> bool {
        matches!(
            self,
            StageStatus::Completed | StageStatus::CompletedWithErrors | StageStatus::Error
        )
    }
}

pub const STAGE_IDS: [&str; 12] = [
    "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11",
];

pub fn stage_id(name: &str) -> &str {
    name.split_once('-').map_or(name, |(id, _)| id)
}

pub fn stage_label(id: &str) -> Option<&'static str> {
    Some(match id {
        "s0" => "static seed",
        "s1" => "pre-process",
        "s2" => "threat model",
        "s3" => "decompose",
        "s4" => "deep-dive",
        "s5" => "pre-filter",
        "s6" => "verify",
        "s7" => "dedup",
        "s8" => "chain",
        "s9" => "report",
        "s10" => "remediate",
        "s11" => "validate",
        _ => return None,
    })
}

pub fn stage_number(id: &str) -> Option<usize> {
    STAGE_IDS.iter().position(|s| *s == id).map(|i| i + 1)
}

#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct StageUsage {
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    pub cache_read_tokens: i64,
    pub cache_write_tokens: i64,
    pub calls: i64,
    pub cost_usd: Option<f64>,
    pub unpriced_tokens: i64,
    pub truncated_replies: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ScanEvent {
    StageStarted {
        stage: &'static str,
    },
    StageFinished {
        stage: &'static str,
        status: StageStatus,
        duration: Option<std::time::Duration>,
        counts: Vec<(&'static str, u64)>,
        detail: Option<String>,
    },
    ChunkProgress {
        stage: &'static str,
        completed: usize,
        total: usize,
    },
    VerifyProgress {
        stage: &'static str,
        completed: usize,
        total: usize,
        outcome: Option<&'static str>,
    },
    FindingsCount {
        stage: &'static str,
        count: usize,
    },
    UsageUpdate {
        stage: &'static str,
        usage: StageUsage,
    },
}

pub type ProgressSink = std::sync::mpsc::Sender<ScanEvent>;

pub fn emit(sink: Option<&ProgressSink>, event: ScanEvent) {
    if let Some(sink) = sink {
        let _ = sink.send(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage_outcome_ok_reports_not_degraded_and_no_reason() {
        let o = StageOutcome::Ok(42);
        assert!(!o.is_degraded());
        assert_eq!(o.reason(), None);
        assert_eq!(*o.value(), 42);
        assert_eq!(o.into_value(), 42);
    }

    #[test]
    fn stage_outcome_degraded_reports_degraded_and_reason() {
        let o = StageOutcome::Degraded {
            value: 7,
            reason: "malformed LLM JSON".to_string(),
        };
        assert!(o.is_degraded());
        assert_eq!(o.reason(), Some("malformed LLM JSON"));
        assert_eq!(*o.value(), 7);
        assert_eq!(o.into_value(), 7);
    }

    fn double(v: i32) -> i32 {
        v * 2
    }

    #[test]
    fn stage_outcome_map_preserves_variant_and_reason() {
        let ok = StageOutcome::Ok(3).map(double);
        assert_eq!(ok, StageOutcome::Ok(6));

        let degraded = StageOutcome::Degraded {
            value: 3,
            reason: "r".to_string(),
        }
        .map(double);
        assert_eq!(
            degraded,
            StageOutcome::Degraded {
                value: 6,
                reason: "r".to_string()
            }
        );
    }

    #[test]
    fn stage_error_display_and_error_trait() {
        let e = StageError::new("s3-decompose", "chunk builder panicked");
        assert_eq!(e.to_string(), "s3-decompose: chunk builder panicked");
        let _: &dyn std::error::Error = &e;
    }

    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
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

    struct PendOnce(std::cell::Cell<bool>);

    impl std::future::Future for PendOnce {
        type Output = i32;
        fn poll(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<i32> {
            if self.0.get() {
                std::task::Poll::Ready(99)
            } else {
                self.0.set(true);
                cx.waker().wake_by_ref();
                std::task::Poll::Pending
            }
        }
    }

    #[test]
    fn block_on_loops_past_a_pending_poll() {
        assert_eq!(block_on(PendOnce(std::cell::Cell::new(false))), 99);
    }

    struct DoubleStage;

    impl PipelineStage for DoubleStage {
        type Input = i32;
        type Output = i32;
        const NAME: &'static str = "double";

        async fn run(&self, input: i32) -> Result<StageOutcome<i32>, StageError> {
            if input < 0 {
                return Err(StageError::new(Self::NAME, "negative input"));
            }
            if input == 0 {
                return Ok(StageOutcome::Degraded {
                    value: 0,
                    reason: "zero input, nothing to double".to_string(),
                });
            }
            Ok(StageOutcome::Ok(input * 2))
        }
    }

    #[test]
    fn pipeline_stage_trait_is_implementable_and_runnable() {
        assert_eq!(DoubleStage::NAME, "double");
        assert_eq!(block_on(DoubleStage.run(5)).unwrap(), StageOutcome::Ok(10));
        assert_eq!(
            block_on(DoubleStage.run(0)).unwrap(),
            StageOutcome::Degraded {
                value: 0,
                reason: "zero input, nothing to double".to_string()
            }
        );
        let err = block_on(DoubleStage.run(-1)).unwrap_err();
        assert_eq!(err.to_string(), "double: negative input");
    }

    #[test]
    fn emit_with_no_sink_is_a_silent_no_op() {
        emit(None, ScanEvent::StageStarted { stage: "s1" });
    }

    #[test]
    fn emit_with_a_sink_delivers_the_event() {
        let (tx, rx) = std::sync::mpsc::channel();
        emit(Some(&tx), ScanEvent::StageStarted { stage: "s1" });
        assert_eq!(rx.recv().unwrap(), ScanEvent::StageStarted { stage: "s1" });
    }

    #[test]
    fn emit_with_a_disconnected_receiver_is_silently_ignored() {
        let (tx, rx) = std::sync::mpsc::channel();
        drop(rx);
        emit(Some(&tx), ScanEvent::StageStarted { stage: "s1" });
    }

    #[test]
    fn stage_status_spells_pythons_outcome_strings() {
        let all = [
            (StageStatus::Completed, "completed", true),
            (
                StageStatus::CompletedWithErrors,
                "completed_with_errors",
                true,
            ),
            (StageStatus::Cached, "cached", false),
            (StageStatus::Skipped, "skipped", false),
            (StageStatus::Disabled, "disabled", false),
            (StageStatus::Error, "error", true),
        ];
        for (status, spelling, timed) in all {
            assert_eq!(status.as_str(), spelling);
            assert_eq!(status.is_timed(), timed, "{spelling}");
        }
    }

    #[test]
    fn a_degraded_stage_never_closes_as_plainly_completed() {
        assert_eq!(StageStatus::from_degraded(false), StageStatus::Completed);
        assert_eq!(
            StageStatus::from_degraded(true),
            StageStatus::CompletedWithErrors
        );
    }

    #[test]
    fn stage_id_strips_the_role_suffix_and_keeps_a_bare_id() {
        assert_eq!(stage_id("s4-deepdive"), "s4");
        assert_eq!(stage_id("s10-remediate"), "s10");
        assert_eq!(stage_id("s9"), "s9");
    }

    #[test]
    fn every_stage_id_has_a_label_and_a_position() {
        for (i, id) in STAGE_IDS.iter().enumerate() {
            assert!(stage_label(id).is_some(), "{id}");
            assert_eq!(stage_number(id), Some(i + 1));
        }
        assert_eq!(stage_label("s4"), Some("deep-dive"));
        assert_eq!(stage_label("s12"), None);
        assert_eq!(stage_number("s12"), None);
    }

    #[test]
    fn scan_event_variants_carry_their_own_fields() {
        let finished = ScanEvent::StageFinished {
            stage: "s4",
            status: StageStatus::CompletedWithErrors,
            duration: Some(std::time::Duration::from_millis(1500)),
            counts: vec![("findings", 3)],
            detail: Some("2 chunk(s) failed".to_string()),
        };
        assert_eq!(finished.clone(), finished);
        assert_eq!(
            ScanEvent::ChunkProgress {
                stage: "s4",
                completed: 3,
                total: 10
            },
            ScanEvent::ChunkProgress {
                stage: "s4",
                completed: 3,
                total: 10
            }
        );
        assert_eq!(
            ScanEvent::FindingsCount {
                stage: "s6",
                count: 5
            },
            ScanEvent::FindingsCount {
                stage: "s6",
                count: 5
            }
        );
        let usage = StageUsage {
            prompt_tokens: 100,
            completion_tokens: 50,
            cache_read_tokens: 7,
            cache_write_tokens: 3,
            calls: 2,
            cost_usd: Some(0.25),
            unpriced_tokens: 0,
            truncated_replies: 1,
        };
        assert_eq!(
            ScanEvent::UsageUpdate { stage: "s4", usage },
            ScanEvent::UsageUpdate { stage: "s4", usage }
        );
        assert_eq!(StageUsage::default().cost_usd, None);
        let verified = ScanEvent::VerifyProgress {
            stage: "s6",
            completed: 1,
            total: 2,
            outcome: Some("TRUE_POSITIVE"),
        };
        assert_eq!(verified.clone(), verified);
    }

    #[derive(Debug)]
    struct FixedGate(bool);

    impl BudgetGate for FixedGate {
        fn should_stop(&self) -> bool {
            self.0
        }
        fn stop_reason(&self) -> String {
            "token budget of 10 reached".to_string()
        }
    }

    #[test]
    fn budget_allows_when_there_is_no_gate_at_all() {
        assert!(budget_allows(None));
    }

    #[test]
    fn budget_allows_follows_the_gate_when_there_is_one() {
        let open: BudgetGateRef = std::sync::Arc::new(FixedGate(false));
        assert!(budget_allows(Some(&open)));
        let tripped: BudgetGateRef = std::sync::Arc::new(FixedGate(true));
        assert!(!budget_allows(Some(&tripped)));
        assert_eq!(tripped.stop_reason(), "token budget of 10 reached");
        assert!(format!("{tripped:?}").contains("FixedGate"));
    }

    #[test]
    fn tripping_a_gate_that_does_not_implement_trip_is_a_no_op() {
        let open: BudgetGateRef = std::sync::Arc::new(FixedGate(false));
        open.trip("provider quota exhausted — no credits".to_string());
        assert!(!open.should_stop(), "the default body changes nothing");
        assert!(budget_allows(Some(&open)));
    }
}
