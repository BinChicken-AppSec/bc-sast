//! Stage lifecycle telemetry: the start/finish pair every stage emits,
//! the per-stage [`StageTiming`] record that goes into
//! `ScanMetrics::stage_timings`, and the S10/S11 counters.
//!
//! Ported from the Python original's `util/stage_telemetry.py` (the
//! `STAGES` recorder) and `orchestrator/scan.py`'s `_sp_start`/`_sp_done`
//! pair. Python keeps a process-wide singleton the manifest reads back at
//! exit; here the same facts travel on the scan's existing
//! [`ScanEvent`] stream (so any observer, including `bc-cli`'s run
//! manifest, sees them) and into the report's own metrics, with no shared
//! mutable state.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use bc_model::StageTiming;
use bc_pipeline_core::{emit, stage_id, ProgressSink, ScanEvent, StageStatus};

/// Per-stage outcome and duration, keyed by short stage id (`"s4"`).
pub(crate) type StageTimings = BTreeMap<String, StageTiming>;

/// One stage between its `StageStarted` and `StageFinished` events.
/// Holding the start instant here, rather than threading `Instant`s
/// through `run_scan`, keeps the timing and the event pair from drifting
/// apart at any one of the eleven call sites.
pub(crate) struct StageRun {
    stage: &'static str,
    started: Instant,
}

impl StageRun {
    /// Emits `StageStarted` and starts the clock.
    pub(crate) fn start(progress: Option<&ProgressSink>, stage: &'static str) -> Self {
        emit(progress, ScanEvent::StageStarted { stage });
        StageRun {
            stage,
            started: Instant::now(),
        }
    }

    /// Records the stage's timing and emits `StageFinished`. A status
    /// that ran no timed body (a checkpoint hit) reports no duration.
    pub(crate) fn finish(
        self,
        progress: Option<&ProgressSink>,
        timings: &mut StageTimings,
        status: StageStatus,
        counts: Vec<(&'static str, u64)>,
        detail: Option<String>,
    ) {
        let duration = status.is_timed().then(|| self.started.elapsed());
        finish_stage(
            progress, timings, self.stage, status, duration, counts, detail,
        );
    }
}

/// A stage that never started (switched off, or not asked for): only a
/// `StageFinished`, matching Python's `_sp_done(..., outcome="skipped")`
/// with no preceding `_sp_start`.
pub(crate) fn record_unstarted(
    progress: Option<&ProgressSink>,
    timings: &mut StageTimings,
    stage: &'static str,
    status: StageStatus,
    detail: Option<String>,
) {
    finish_stage(progress, timings, stage, status, None, Vec::new(), detail);
}

fn finish_stage(
    progress: Option<&ProgressSink>,
    timings: &mut StageTimings,
    stage: &'static str,
    status: StageStatus,
    duration: Option<Duration>,
    counts: Vec<(&'static str, u64)>,
    detail: Option<String>,
) {
    timings.insert(
        stage_id(stage).to_string(),
        StageTiming {
            outcome: status.as_str().to_string(),
            duration_sec: duration.map(|d| d.as_secs_f64()),
        },
    );
    emit(
        progress,
        ScanEvent::StageFinished {
            stage,
            status,
            duration,
            counts,
            detail,
        },
    );
}

/// `n` as a counter value. Every count here is a collection length, which
/// always fits.
pub(crate) fn count(n: usize) -> u64 {
    n as u64
}

/// S10's stage-done counters (Python `scan.py::_progress_detail`), from
/// [`bc_stage_s10::RemediationCounts`] so a progress line counts a fix
/// exactly as the summary and exit code do: `fixed` only when the verdict
/// is `Fixed`, the diff is non-empty and nothing rolled it back.
pub(crate) fn remediation_counts(
    outcomes: &[bc_stage_s10::RemediationOutcome],
) -> Vec<(&'static str, u64)> {
    let c = bc_stage_s10::RemediationCounts::from_outcomes(outcomes);
    vec![
        ("attempted", count(c.attempted)),
        ("fixed", count(c.fixed)),
        ("not_fixed", count(c.not_fixed)),
        ("failed", count(c.failed)),
    ]
}

/// S11's stage-done counters (Python `validation/cli::_record_progress`),
/// from [`bc_validation_scoring::ValidationCounts`] over the scores that
/// came back, plus the sessions that errored, which count as validated
/// and failed, so `validated == passed + failed + inconclusive`.
pub(crate) fn validation_counts(
    validations: &[Option<bc_validation_scoring::ValidationScore>],
    errored: usize,
) -> Vec<(&'static str, u64)> {
    let c = bc_validation_scoring::ValidationCounts::tally(
        validations.iter().flatten().map(|s| s.decision()),
    );
    vec![
        ("validated", count(c.validated + errored)),
        ("passed", count(c.passed)),
        ("failed", count(c.failed + errored)),
        ("inconclusive", count(c.inconclusive)),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn events(rx: &std::sync::mpsc::Receiver<ScanEvent>) -> Vec<ScanEvent> {
        rx.try_iter().collect()
    }

    #[test]
    fn a_timed_stage_emits_its_pair_and_records_a_duration() {
        let (tx, rx) = std::sync::mpsc::channel();
        let mut timings = StageTimings::new();
        let run = StageRun::start(Some(&tx), "s4-deepdive");
        run.finish(
            Some(&tx),
            &mut timings,
            StageStatus::CompletedWithErrors,
            vec![("findings", 2)],
            Some("1 chunk(s) failed".to_string()),
        );
        let got = events(&rx);
        assert_eq!(
            got[0],
            ScanEvent::StageStarted {
                stage: "s4-deepdive"
            }
        );
        assert!(matches!(
                &got[1],
                ScanEvent::StageFinished {
                    stage: "s4-deepdive",
                    status: StageStatus::CompletedWithErrors,
                    duration: Some(_),
                    counts,
                    detail: Some(detail),
                } if counts == &vec![("findings", 2)] && detail == "1 chunk(s) failed"
        ));
        let timing = &timings["s4"];
        assert_eq!(timing.outcome, "completed_with_errors");
        assert!(timing.duration_sec.is_some());
    }

    #[test]
    fn a_cached_stage_reports_no_duration() {
        let (tx, rx) = std::sync::mpsc::channel();
        let mut timings = StageTimings::new();
        StageRun::start(Some(&tx), "s1-preprocess").finish(
            Some(&tx),
            &mut timings,
            StageStatus::Cached,
            Vec::new(),
            None,
        );
        assert!(matches!(
            events(&rx)[1],
            ScanEvent::StageFinished { duration: None, .. }
        ));
        assert_eq!(timings["s1"].duration_sec, None);
        assert_eq!(timings["s1"].outcome, "cached");
    }

    #[test]
    fn an_unstarted_stage_emits_only_its_finish() {
        let (tx, rx) = std::sync::mpsc::channel();
        let mut timings = StageTimings::new();
        record_unstarted(
            Some(&tx),
            &mut timings,
            "s2-threatmodel",
            StageStatus::Skipped,
            Some("disabled in config".to_string()),
        );
        let got = events(&rx);
        assert_eq!(got.len(), 1);
        assert!(matches!(
            &got[0],
            ScanEvent::StageFinished { status: StageStatus::Skipped, detail: Some(d), .. }
                if d == "disabled in config"
        ));
        assert_eq!(timings["s2"].outcome, "skipped");
    }

    fn record(diff: Option<&str>) -> bc_stage_s10::RemediationOutcome {
        bc_stage_s10::RemediationOutcome::Processed(Box::new(bc_stage_s10::RemediationRecord {
            finding_index: 1,
            finding_id: "f1".to_string(),
            verdict: bc_stage_s10::RemediationVerdict {
                finding_index: 1,
                verdict: bc_stage_s10::Verdict::Fixed,
                gates: bc_stage_s10::Gates::default(),
                root_cause: String::new(),
                changes: Vec::new(),
                remaining_risks: Vec::new(),
                recommendations: Vec::new(),
                summary: String::new(),
            },
            policy_action: None,
            policy_reason: None,
            final_verdict: None,
            policy_reverted: Vec::new(),
            policy_matched_globs: Vec::new(),
            diff: diff.map(str::to_string),
        }))
    }

    #[test]
    fn remediation_counts_keep_attempted_equal_to_fixed_not_fixed_and_failed() {
        let outcomes = vec![
            record(Some("--- a\n+++ b\n")),
            record(None),
            bc_stage_s10::RemediationOutcome::Failed {
                finding_index: 3,
                error: "session failed".to_string(),
            },
        ];
        assert_eq!(
            remediation_counts(&outcomes),
            vec![
                ("attempted", 3),
                ("fixed", 1),
                ("not_fixed", 1),
                ("failed", 1)
            ]
        );
        assert_eq!(
            remediation_counts(&[]),
            vec![
                ("attempted", 0),
                ("fixed", 0),
                ("not_fixed", 0),
                ("failed", 0)
            ]
        );
    }

    #[test]
    fn an_errored_validation_session_counts_as_validated_and_failed() {
        assert_eq!(
            validation_counts(&[None, None], 2),
            vec![
                ("validated", 2),
                ("passed", 0),
                ("failed", 2),
                ("inconclusive", 0)
            ]
        );
    }
}
