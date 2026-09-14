//! The run's `invocations` entry and `run.properties`, ported from the
//! `scan_health`-driven logic in `enrich.py::generate_sarif` (lines
//! 994-1030) and its call site in `orchestrator/scan.py`.
//!
//! The Python source treats `scan_health` as optional (only the
//! standalone CLI path omits it); this crate has exactly one call path —
//! straight off a `FinalReport` — so an invocation is always built,
//! matching the pipeline path's actual (and only real-world) behavior.

use bc_model::{FinalReport, ScanMetrics};

use crate::types::{Invocation, MessageText, Notification, RunProperties};

/// Findings this run retained but never analyzed because their file was
/// outside a `--diff-scope` run's changed set (see
/// `bc_model::DropReason::OutOfDiffScope`).
///
/// They are deliberately NOT SARIF `results`: a result is something this
/// scan found in code it examined, and these are third-party reports about
/// code it did not. But a document that simply omitted them would let a
/// consumer reading only `report.sarif` conclude the vendor's findings
/// were resolved, which is the absence-as-evidence reading this project
/// refuses everywhere else — so they are surfaced the same way an absent
/// failed chunk's findings are, as a run-level notification.
pub fn out_of_diff_scope_count(report: &FinalReport) -> usize {
    report
        .dropped
        .iter()
        .filter(|d| d.reason == bc_model::DropReason::OutOfDiffScope)
        .count()
}

pub fn build_invocation(
    degraded: bool,
    metrics: Option<&ScanMetrics>,
    out_of_diff_scope: usize,
) -> Invocation {
    let mut notifications = Vec::new();

    if let Some(m) = metrics {
        // `errors_by_stage` is a `BTreeMap`, already in sorted-by-stage
        // order, matching Python's explicit `sorted(...items())`.
        for (stage, n) in &m.errors_by_stage {
            notifications.push(Notification {
                level: "warning".to_string(),
                message: MessageText {
                    text: format!("{stage}: {n} recoverable error(s) logged"),
                },
            });
        }
    }

    let chunks_failed = metrics.map(|m| m.chunks_failed).unwrap_or(0);
    if chunks_failed != 0 {
        notifications.push(Notification {
            level: "warning".to_string(),
            message: MessageText {
                text: format!(
                    "{chunks_failed} deep-dive chunk(s) failed or timed out; their findings are absent"
                ),
            },
        });
    }

    if out_of_diff_scope != 0 {
        notifications.push(Notification {
            level: "note".to_string(),
            message: MessageText {
                text: format!(
                    "{out_of_diff_scope} third-party finding(s) are outside this pull \
                     request's changed files; they were not analyzed, are not results \
                     here, and are listed in the report's Dropped Findings section"
                ),
            },
        });
    }

    if degraded {
        notifications.push(Notification {
            level: "warning".to_string(),
            message: MessageText {
                text: "Exploit-chain analysis could not be computed; findings are unranked"
                    .to_string(),
            },
        });
    }

    Invocation {
        execution_successful: !degraded,
        tool_execution_notifications: (!notifications.is_empty()).then_some(notifications),
    }
}

pub fn build_run_properties(report: &FinalReport) -> RunProperties {
    let (application_id, cmdb_source, application_name) = match &report.app_profile {
        Some(ap) => (
            ap.application_id.clone(),
            Some(ap.source.clone()),
            Some(ap.name.clone()),
        ),
        None => (String::new(), None, None),
    };
    RunProperties {
        application_id,
        cmdb_source,
        application_name,
        scan_degraded: report.degraded,
        unranked_fallback: report.degraded,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_model::AppProfile;

    fn app_profile() -> AppProfile {
        AppProfile {
            application_id: "APP1".to_string(),
            name: "My App".to_string(),
            externally_facing: true,
            pci_scoped: false,
            processes_pan: false,
            pii: false,
            source: "cmdb".to_string(),
        }
    }

    #[test]
    fn healthy_scan_has_no_notifications() {
        let inv = build_invocation(false, None, 0);
        assert!(inv.execution_successful);
        assert!(inv.tool_execution_notifications.is_none());
    }

    #[test]
    fn degraded_scan_marks_execution_unsuccessful_and_notifies() {
        let inv = build_invocation(true, None, 0);
        assert!(!inv.execution_successful);
        let notes = inv.tool_execution_notifications.unwrap();
        assert_eq!(notes.len(), 1);
        assert!(notes[0]
            .message
            .text
            .contains("Exploit-chain analysis could not be computed"));
        assert_eq!(notes[0].level, "warning");
    }

    #[test]
    fn failed_chunks_produce_a_notification() {
        let m = ScanMetrics {
            chunks_failed: 3,
            ..Default::default()
        };
        let inv = build_invocation(false, Some(&m), 0);
        let notes = inv.tool_execution_notifications.unwrap();
        assert_eq!(notes.len(), 1);
        assert!(notes[0]
            .message
            .text
            .contains("3 deep-dive chunk(s) failed"));
    }

    #[test]
    fn errors_by_stage_produce_one_sorted_notification_per_stage() {
        let mut errs = std::collections::BTreeMap::new();
        errs.insert("s4".to_string(), 3);
        errs.insert("s1".to_string(), 1);
        let m = ScanMetrics {
            errors_by_stage: errs,
            ..Default::default()
        };
        let inv = build_invocation(false, Some(&m), 0);
        let notes = inv.tool_execution_notifications.unwrap();
        assert_eq!(notes.len(), 2);
        assert!(notes[0].message.text.starts_with("s1: 1 recoverable"));
        assert!(notes[1].message.text.starts_with("s4: 3 recoverable"));
    }

    #[test]
    fn all_three_notification_kinds_combine() {
        let mut errs = std::collections::BTreeMap::new();
        errs.insert("s1".to_string(), 1);
        let m = ScanMetrics {
            errors_by_stage: errs,
            chunks_failed: 2,
            ..Default::default()
        };
        let inv = build_invocation(true, Some(&m), 0);
        assert_eq!(inv.tool_execution_notifications.unwrap().len(), 3);
    }

    #[test]
    fn out_of_diff_scope_retentions_produce_a_note_level_notification() {
        let inv = build_invocation(false, None, 2);
        let notes = inv.tool_execution_notifications.unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].level, "note");
        assert!(notes[0]
            .message
            .text
            .contains("2 third-party finding(s) are outside this pull request"));
        // A set-aside finding is not an execution failure.
        assert!(inv.execution_successful);
    }

    #[test]
    fn out_of_diff_scope_count_counts_only_that_drop_reason() {
        let mut report = minimal_report();
        report.dropped = vec![
            dropped(bc_model::DropReason::OutOfDiffScope),
            dropped(bc_model::DropReason::FalsePositive),
        ];
        assert_eq!(out_of_diff_scope_count(&report), 1);
        assert_eq!(out_of_diff_scope_count(&minimal_report()), 0);
    }

    fn dropped(reason: bc_model::DropReason) -> bc_model::DroppedFinding {
        bc_model::DroppedFinding {
            provider_origins: Vec::new(),
            verification: None,
            file: "vendor/old.py".to_string(),
            line: 1,
            vuln_class: bc_model::VulnClass::Other,
            title: "t".to_string(),
            chunk_id: "c".to_string(),
            reason,
            detail: String::new(),
            canonical_idx: None,
        }
    }

    #[test]
    fn no_metrics_and_not_degraded_has_no_notifications() {
        let inv = build_invocation(false, None, 0);
        assert!(inv.tool_execution_notifications.is_none());
    }

    fn minimal_report() -> FinalReport {
        FinalReport {
            provider_ledger: Default::default(),
            repo_root: "/r".to_string(),
            repo_name: None,
            git_sha: None,
            findings: Vec::new(),
            chains: Vec::new(),
            dropped: Vec::new(),
            raw_findings_count: 0,
            metrics: None,
            threat_model: None,
            app_profile: None,
            summary: "s".to_string(),
            degraded: false,
            degraded_reason: String::new(),
            unreachable_files: Vec::new(),
        }
    }

    #[test]
    fn run_properties_without_app_profile() {
        let props = build_run_properties(&minimal_report());
        assert_eq!(props.application_id, "");
        assert!(props.cmdb_source.is_none());
        assert!(props.application_name.is_none());
        assert!(!props.scan_degraded);
        assert!(!props.unranked_fallback);
    }

    #[test]
    fn run_properties_with_app_profile() {
        let mut r = minimal_report();
        r.app_profile = Some(app_profile());
        let props = build_run_properties(&r);
        assert_eq!(props.application_id, "APP1");
        assert_eq!(props.cmdb_source.as_deref(), Some("cmdb"));
        assert_eq!(props.application_name.as_deref(), Some("My App"));
    }

    #[test]
    fn run_properties_degraded_sets_both_flags() {
        let mut r = minimal_report();
        r.degraded = true;
        let props = build_run_properties(&r);
        assert!(props.scan_degraded);
        assert!(props.unranked_fallback);
    }
}
