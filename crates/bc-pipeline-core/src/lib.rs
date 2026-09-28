//! The shared `PipelineStage` contract every S1-S9 stage crate implements,
//! plus the outcome/error types that encode the Python original's
//! "S1/S3/S7/S8 degrade to a safe fallback rather than crash the whole scan"
//! policy as a type instead of a scattered try/except pattern. (S2 has no
//! such internal policy of its own — a bad LLM response there propagates
//! uncaught out of the stage, and it's the *orchestrator* that catches it
//! and falls back to no threat model at all; S2's own `Output` therefore
//! never needs `StageOutcome::Degraded`, only `Ok`/`Err`. S7's degrade is
//! narrower still: only its optional semantic-dedup LLM call can fail, and
//! only non-fatally — the deterministic pass's results are always a valid
//! fallback `Output`.)
//!
//! Each stage gets its own concrete `Input`/`Output` associated types
//! (not a homogeneous `enum StageOutput`) because the orchestrator calls
//! stages in one fixed, compile-time-known sequence — there is no
//! scenario needing dynamic dispatch across stages, so static typing is
//! strictly better here than re-deriving dynamic typing with match/unwrap
//! ceremony at every call site.

use std::fmt;

mod cancel;
pub use cancel::{canceled, CancelToken, CancelTokenRef, USER_CANCEL_REASON};

/// The result of running one pipeline stage: either it completed fully, or
/// it degraded to a safe fallback value for a documented, non-fatal reason
/// (mirroring the Python original's S1/S3/S8 behavior — a malformed LLM
/// response degrades that stage's output rather than aborting the run).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StageOutcome<T> {
    Ok(T),
    Degraded { value: T, reason: String },
}

impl<T> StageOutcome<T> {
    pub fn is_degraded(&self) -> bool {
        matches!(self, StageOutcome::Degraded { .. })
    }

    /// The degrade reason, if any.
    pub fn reason(&self) -> Option<&str> {
        match self {
            StageOutcome::Ok(_) => None,
            StageOutcome::Degraded { reason, .. } => Some(reason.as_str()),
        }
    }

    /// Discard the Ok/Degraded distinction and take the value either way —
    /// the orchestrator hands this straight to the next stage regardless
    /// of which variant produced it; only reporting/logging cares which.
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

/// A stage-level failure severe enough that the pipeline cannot continue
/// with a fallback and must propagate — as opposed to `StageOutcome::
/// Degraded`, which is the "continue anyway" path. Reserved for cases like
/// an unrecoverable I/O failure constructing the stage's own inputs, not
/// "the model returned unparseable JSON" (that degrades, per the Python
/// original's own policy for S1/S3/S8).
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

/// The contract every S1-S9 stage crate implements. `NAME` is used for
/// checkpoint keys and progress/log labeling.
pub trait PipelineStage {
    type Input;
    type Output;
    const NAME: &'static str;

    fn run(
        &self,
        input: Self::Input,
    ) -> impl std::future::Future<Output = Result<StageOutcome<Self::Output>, StageError>> + Send;
}

/// A cheap "may I keep spending?" question a long-running stage asks
/// **before starting each new unit of work** — one deep-dive chunk, one
/// verification session, one semantic-dedup call.
///
/// This exists because a stage-boundary check alone is not a budget. A
/// live 2026-09-06 Juice Shop scan was given `--max-tokens 3000000` and
/// spent 4,925,717: cumulative spend was ~1.53M entering S6, under the
/// cap, so S6 started — and then ran 1,881 verification sessions to
/// completion with nothing left to consult, spending 3.39M inside a
/// single stage boundary. S4 (444 chunks, 1.41M) has exactly the same
/// shape. Whatever caps a scan has to be readable from *inside* those
/// loops.
///
/// The contract is deliberately narrow so a stage crate can hold one
/// without gaining a dependency (this crate is Tier-0 and has none):
///
/// * **Cheap and non-blocking.** Called once per unit of work, on the
///   task that is about to do it; an implementation reads counters, it
///   does not do I/O or await.
/// * **Advisory, not an abort.** Tripping means *stop starting new work*;
///   in-flight work is left to finish, and the stage returns whatever it
///   already has, degraded, rather than erroring. A scan that hits its
///   budget still produces the best report available — the same
///   fall-through the stage-boundary check has always had.
/// * **Latching is the implementor's business.** Nothing here promises
///   `should_stop` stays `false` once it has been `true`, nor the
///   reverse; stages must treat each call as the current answer.
pub trait BudgetGate: std::fmt::Debug + Send + Sync {
    /// `true` once the scan has spent its budget. See the trait doc for
    /// what a stage is expected to do about it.
    fn should_stop(&self) -> bool;

    /// Which budget ran out, phrased to be read by a human in the
    /// report's `## Scan Health` section (e.g. `"token budget of
    /// 3000000 reached"`). Only meaningful right after [`should_stop`]
    /// returned `true`.
    ///
    /// [`should_stop`]: BudgetGate::should_stop
    fn stop_reason(&self) -> String;

    /// A stage learned from the provider that no more work can be funded
    /// (quota exhausted); a gate that can be tripped externally records
    /// the first reason and answers `should_stop() == true` from then on.
    ///
    /// The counterpart to the counter-driven half of the contract: a
    /// token or wall-clock cap is something the gate can compute for
    /// itself, but "the account has no credits left" is only ever learned
    /// by a stage actually making a call (see
    /// `bc_llm_client::LlmError::QuotaExhausted`). Without this, each of
    /// S6's ~250 verification sessions had to rediscover it
    /// independently — and, on the 2026-09 CI run that motivated this,
    /// retry it six times apiece first.
    ///
    /// Default is a deliberate no-op so a gate with nothing external to
    /// record (a pure counter, or a test fixture) needs no boilerplate,
    /// and so calling this is always safe: a stage trips the gate it was
    /// given without knowing which kind it is.
    fn trip(&self, _reason: String) {}
}

/// How a stage config carries a [`BudgetGate`]. `Arc` rather than `Box`
/// because one gate is shared by every task a stage spawns, and by
/// several stages within one scan.
pub type BudgetGateRef = std::sync::Arc<dyn BudgetGate>;

/// `true` when there is no gate at all (the default, fully-unbounded
/// scan) or the gate says to keep going — the one-liner every stage's
/// spawn loop asks, so none of them has to spell out the `Option`
/// handling or get the polarity backwards.
pub fn budget_allows(gate: Option<&BudgetGateRef>) -> bool {
    !gate.is_some_and(|g| g.should_stop())
}

/// How one pipeline stage ended, as the run manifest and the text
/// progress lines report it. Ported from the outcome strings the Python
/// original's `util/stage_telemetry.py` records (`completed`,
/// `completed_with_errors`, `cached`, `skipped`, `disabled`, `error`).
///
/// Named `StageStatus` rather than Python's `outcome` because
/// [`StageOutcome`] already names the Ok/Degraded value a stage returns;
/// the two are related (a degraded value closes its stage as
/// [`StageStatus::CompletedWithErrors`]) but not the same thing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StageStatus {
    /// The stage ran and produced a clean result.
    Completed,
    /// The stage ran to the end but degraded, lost work (a failed chunk,
    /// a budget stop) or recorded errors along the way.
    CompletedWithErrors,
    /// The stage was not run: its result was restored from a `--resume`
    /// checkpoint.
    Cached,
    /// The stage was switched off by configuration (`step0.enabled`,
    /// `step2.enabled: false`, `--no-threat-model`).
    Skipped,
    /// The stage could not, or was not asked to, run this time:
    /// remediation not requested or refused by its preflight, validation
    /// off.
    Disabled,
    /// The stage failed outright.
    Error,
}

impl StageStatus {
    /// The wire spelling, identical to the Python original's outcome
    /// strings so a manifest consumer can read either tool's output.
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

    /// The status a stage that actually ran closes with: degraded work is
    /// `CompletedWithErrors`, never a plain `Completed` that would make a
    /// fallback result look like a clean one.
    pub fn from_degraded(degraded: bool) -> Self {
        if degraded {
            StageStatus::CompletedWithErrors
        } else {
            StageStatus::Completed
        }
    }

    /// Whether a stage with this status ran a timed body. Cached, skipped
    /// and disabled stages did no work, so their duration is reported as
    /// unknown (`null` in the manifest) rather than as a misleading
    /// near-zero figure, matching Python's `STAGES.mark`.
    pub fn is_timed(self) -> bool {
        matches!(
            self,
            StageStatus::Completed | StageStatus::CompletedWithErrors | StageStatus::Error
        )
    }
}

/// Every pipeline stage id in run order, `s0` through `s11`. The Python
/// original's `_STAGE_ORDER` stops at `s10`, so its stage-only lines
/// number S11 as `?/11`; this list includes S11 on purpose.
pub const STAGE_IDS: [&str; 12] = [
    "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11",
];

/// The short stage id (`"s4"`) of a stage's event name (`"s4-deepdive"`,
/// or a bare `"s9"`): everything before the first `-`.
pub fn stage_id(name: &str) -> &str {
    name.split_once('-').map_or(name, |(id, _)| id)
}

/// A human label for a stage id, used by the text progress lines and the
/// run manifest. `None` for an id outside [`STAGE_IDS`].
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

/// A stage's 1-based position in [`STAGE_IDS`], or `None` for an unknown
/// id.
pub fn stage_number(id: &str) -> Option<usize> {
    STAGE_IDS.iter().position(|s| *s == id).map(|i| i + 1)
}

/// One stage's model spend, as [`ScanEvent::UsageUpdate`] carries it.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct StageUsage {
    /// Billable input: fresh input plus cache writes, the report's
    /// headline prompt figure.
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    pub cache_read_tokens: i64,
    pub cache_write_tokens: i64,
    pub calls: i64,
    /// US dollars for the calls that could be priced; `None` when none
    /// could. A lower bound whenever `unpriced_tokens` is non-zero.
    pub cost_usd: Option<f64>,
    pub unpriced_tokens: i64,
    /// Replies the transport gave up on as truncated (VVAH-E005).
    pub truncated_replies: u64,
}

/// Progress/observability events emitted while a scan runs, consumed by
/// `bc-cli`'s progress bar (task #75), its text progress lines, its run
/// manifest, or any other external observer. Deliberately plain data,
/// not tied to any particular renderer. The Python original has no event
/// stream as such; the start/finish pair carries what its
/// `ScanProgress.stage_started`/`stage_done` and `STAGES` recorder see.
#[derive(Debug, Clone, PartialEq)]
pub enum ScanEvent {
    /// A pipeline stage began running (the live path — a checkpoint-
    /// resumed stage still emits this, immediately followed by
    /// `StageFinished` with [`StageStatus::Cached`], so a progress bar
    /// sees a consistent start/finish pair either way rather than a stage
    /// silently never starting). A stage that never starts at all
    /// (skipped or disabled) emits `StageFinished` alone.
    StageStarted { stage: &'static str },
    /// A pipeline stage finished (live, resumed, skipped or disabled).
    StageFinished {
        stage: &'static str,
        status: StageStatus,
        /// Wall-clock time the stage body ran for; `None` for a status
        /// that ran no timed body (see [`StageStatus::is_timed`]).
        duration: Option<std::time::Duration>,
        /// Stable `name=value` counters describing what the stage did
        /// (`findings`, `kept`/`dropped`, S10's `attempted`/`fixed`/
        /// `not_fixed`/`failed`, S11's `validated`/`passed`/`failed`),
        /// in display order. Plain pairs rather than a typed struct per
        /// stage so a renderer needs no knowledge of any one stage.
        counts: Vec<(&'static str, u64)>,
        /// Free text: why a stage was skipped or disabled, or what went
        /// wrong. Already redacted by the emitter.
        detail: Option<String>,
    },
    /// One more unit of a stage's own internal work completed — currently
    /// only S4's per-chunk deep-dive loop reports this (S3's decompose is
    /// a single LLM call with no incremental sub-progress of its own to
    /// report).
    ChunkProgress {
        stage: &'static str,
        completed: usize,
        total: usize,
    },
    /// S6's verification loop, per finding (Python's `_S6Progress`, behind
    /// `--s6-progress-file`). Emitted once with `completed: 0` and
    /// `outcome: None` when the loop starts, announcing `total`, then once
    /// per finding that reaches an outcome, in completion order, with
    /// Python's outcome string (`TRUE_POSITIVE`, `FALSE_POSITIVE`,
    /// `UNCONFIRMED`, `VERIFY_ERROR`, `GUARDRAIL_BLOCKED`). A finding a
    /// budget stop or a cancellation kept from the verifier emits nothing,
    /// since nothing verified it, so `completed` can end below `total`.
    VerifyProgress {
        stage: &'static str,
        completed: usize,
        total: usize,
        outcome: Option<&'static str>,
    },
    /// The running count of findings on hand after a stage that changes
    /// it (S4 raises candidates, S6 verifies, S7 dedups, S8 finalizes).
    FindingsCount { stage: &'static str, count: usize },
    /// Model spend attributed to one stage, mirroring
    /// `bc_orchestrator::UsageTrackingClient`'s own per-phase tallying.
    UsageUpdate {
        stage: &'static str,
        usage: StageUsage,
    },
}

/// Where [`ScanEvent`]s are sent. A plain `std::sync::mpsc::Sender`, not
/// `tokio::sync::mpsc` — this crate is deliberately Tier-0 (see the
/// module doc comment's own reasoning for `PipelineStage::run`'s hand-
/// rolled `block_on` test driver) and pulls in no async-runtime
/// dependency; the standard library's synchronous channel sends without
/// blocking regardless of whether the caller is sync or async, so it
/// works equally well from `run_scan`'s own top level and from inside a
/// `tokio::task::JoinSet`-spawned chunk task.
pub type ProgressSink = std::sync::mpsc::Sender<ScanEvent>;

/// Sends `event` on `sink` if present. A full or disconnected receiver
/// (the progress-bar consumer exited, or was never started) is silently
/// ignored — progress reporting is best-effort observability, never
/// something a scan should fail or degrade over.
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

    // A shared named function (rather than two separate closure literals)
    // so both `.map()` call sites below monomorphize to the SAME generic
    // instantiation — each closure literal is its own distinct type in
    // Rust, which would otherwise split coverage of the Ok/Degraded match
    // arms across two separately-instrumented copies of `map`'s body.
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
        let _: &dyn std::error::Error = &e; // compiles => implements Error
    }

    // A minimal poll-to-completion driver (using std's built-in no-op
    // waker, stable since 1.85) so the trait's async fn can be exercised
    // end-to-end without pulling in an async runtime dependency into a
    // Tier-0 crate. Busy-polling in a loop (rather than a single
    // poll-or-panic) is legitimate here and genuinely exercised below by
    // `PendOnce` — no real wakeup delivery is needed for a future that
    // completes after a bounded number of polls regardless of whether
    // `wake()` was actually honored.
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
        // The `Debug` bound exists so a `Step*Config` holding one can
        // still derive `Debug`; exercise it rather than assume it.
        assert!(format!("{tripped:?}").contains("FixedGate"));
    }

    /// A gate with nothing external to record ignores `trip` entirely —
    /// the default body — so a stage can call it unconditionally on a
    /// quota failure without caring which gate implementation it holds.
    #[test]
    fn tripping_a_gate_that_does_not_implement_trip_is_a_no_op() {
        let open: BudgetGateRef = std::sync::Arc::new(FixedGate(false));
        open.trip("provider quota exhausted — no credits".to_string());
        assert!(!open.should_stop(), "the default body changes nothing");
        assert!(budget_allows(Some(&open)));
    }
}
