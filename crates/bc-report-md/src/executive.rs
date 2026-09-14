//! The `## Executive Summary` section — a compact, non-technical-
//! stakeholder-facing readout: findings by severity, noise-reduction/
//! precision framing, LOC scanned, and true/false-positive counts. Not a
//! port — the Python original has no equivalent section. Deliberately
//! excludes any time-saved/ROI framing (an unsubstantiated claim this
//! pipeline has no basis to make — flagged as risky during scoping and
//! left out on purpose, not an oversight).

use bc_model::{DropReason, FinalReport, Severity};

use crate::metrics::with_commas;

#[derive(Default)]
struct SeverityCounts {
    critical: i64,
    high: i64,
    medium: i64,
    low: i64,
    info: i64,
}

impl SeverityCounts {
    fn total(&self) -> i64 {
        self.critical + self.high + self.medium + self.low + self.info
    }
}

fn count_by_severity(report: &FinalReport) -> SeverityCounts {
    let mut counts = SeverityCounts::default();
    for f in &report.findings {
        match f.severity {
            Severity::Critical => counts.critical += 1,
            Severity::High => counts.high += 1,
            Severity::Medium => counts.medium += 1,
            Severity::Low => counts.low += 1,
            Severity::Info => counts.info += 1,
        }
    }
    counts
}

pub fn render_executive_summary(report: &FinalReport) -> Vec<String> {
    let counts = count_by_severity(report);
    let tp = counts.total();
    let fp = report
        .dropped
        .iter()
        .filter(|d| d.reason == DropReason::FalsePositive)
        .count() as i64;
    // Over examined findings only — see `render_markdown`'s own note on
    // why the raw count is the wrong denominator once a budget can stop
    // verification early.
    let unverified = report
        .dropped
        .iter()
        .filter(|d| {
            // Only what a budget kept from the verifier. A low-confidence
            // verdict is also `Unconfirmed`, but that one WAS examined.
            d.reason == DropReason::Unconfirmed && d.detail.starts_with("not verified")
        })
        .count() as i64;
    let examined = tp + fp;
    let precision = if examined != 0 {
        tp as f64 / examined as f64 * 100.0
    } else {
        0.0
    };

    let mut lines = vec![
        "## Executive Summary".to_string(),
        String::new(),
        format!(
            "- **Findings confirmed**: {tp} ({} critical, {} high, {} medium, {} low, {} info)",
            counts.critical, counts.high, counts.medium, counts.low, counts.info
        ),
        format!(
            "- **Noise reduction**: {} candidate finding(s) were automatically reviewed — {tp} \
             confirmed real, {fp} ruled out as false positives ({precision:.1}% verification \
             precision among those examined).",
            report.raw_findings_count
        ),
    ];
    if unverified > 0 {
        // Name the actual reason when the metrics carry one. "A token or
        // time budget was reached" is a fair guess when nothing else is
        // known, but it is a *wrong* one for the case that motivated
        // this: a provider quota/billing failure stops the scan through
        // the same gate, and telling an operator to raise `--max-tokens`
        // when the real fix is to top up the account wastes the one
        // sentence they were going to read.
        let budget_stop = report
            .metrics
            .as_ref()
            .map(|m| m.budget_stop.as_str())
            .unwrap_or_default();
        lines.push(if budget_stop.is_empty() {
            format!(
                "- **Not examined**: {unverified} candidate finding(s) were never sent to the \
                 verifier because a token or time budget was reached — they are neither \
                 confirmed nor ruled out and are listed under Dropped Findings."
            )
        } else {
            format!(
                "- **Not examined**: {unverified} candidate finding(s) were never sent to the \
                 verifier because the scan stopped early ({budget_stop}) — they are neither \
                 confirmed nor ruled out and are listed under Dropped Findings."
            )
        });
    }

    if let Some(m) = &report.metrics {
        let total_loc: i64 = m.loc_scanned_by_language.values().sum();
        if total_loc > 0 {
            lines.push(format!(
                "- **Code scanned**: {} lines of code across {} language(s)",
                with_commas(total_loc),
                m.loc_scanned_by_language.len()
            ));
        }
    }
    lines.push(String::new());
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_model::{DroppedFinding, Finding, RankedFinding, ScanMetrics, VulnClass};
    use std::collections::BTreeMap;

    pub(super) fn minimal_report() -> FinalReport {
        FinalReport {
            provider_ledger: Default::default(),
            repo_root: "/repo".to_string(),
            repo_name: None,
            git_sha: None,
            findings: Vec::new(),
            chains: Vec::new(),
            dropped: Vec::new(),
            raw_findings_count: 0,
            metrics: None,
            threat_model: None,
            app_profile: None,
            summary: String::new(),
            degraded: false,
            degraded_reason: String::new(),
            unreachable_files: Vec::new(),
        }
    }

    fn finding(title: &str) -> Finding {
        Finding {
            provider_origins: Vec::new(),
            chunk_id: "c1".to_string(),
            file: "a.py".to_string(),
            line_start: 1,
            line_end: 1,
            vuln_class: VulnClass::Other,
            cwe: None,
            title: title.to_string(),
            impact: String::new(),
            description: "d".to_string(),
            exploit_scenario: String::new(),
            preconditions: Vec::new(),
            recommendation: String::new(),
            code_snippet: "x".to_string(),
            source_ref: None,
            sink_ref: None,
            backfilled_refs: Vec::new(),
            reanchored: Vec::new(),
            compliance_requirements: Vec::new(),
            confidence: 0.5,
            votes: 1,
            duplicates: Vec::new(),
            verdict: None,
            verdict_confidence: None,
            verdict_reason: String::new(),
            cvss_vector: None,
            cvss_score: None,
            cvss_rating: None,
            verifier_reasoning: String::new(),
            vsvs_vector: None,
            vsvs_score: None,
            vsvs_rating: None,
            offensive_priority: None,
            offensive_reason: String::new(),
            related_cwes: Vec::new(),
        }
    }

    pub(super) fn ranked(title: &str, severity: Severity) -> RankedFinding {
        RankedFinding {
            finding: finding(title),
            severity,
            exploitability_notes: String::new(),
        }
    }

    fn dropped(reason: DropReason) -> DroppedFinding {
        dropped_with(reason, "")
    }

    fn dropped_with(reason: DropReason, detail: &str) -> DroppedFinding {
        DroppedFinding {
            file: "a.py".to_string(),
            line: 1,
            vuln_class: VulnClass::Other,
            title: "t".to_string(),
            chunk_id: "c".to_string(),
            reason,
            detail: detail.to_string(),
            canonical_idx: None,
            provider_origins: Vec::new(),
            verification: None,
        }
    }

    #[test]
    fn empty_report_renders_zeroed_counts_without_a_divide_by_zero_panic() {
        let md = render_executive_summary(&minimal_report()).join("\n");
        assert!(md.contains("## Executive Summary"));
        assert!(md
            .contains("- **Findings confirmed**: 0 (0 critical, 0 high, 0 medium, 0 low, 0 info)"));
        assert!(md.contains(
            "- **Noise reduction**: 0 candidate finding(s) were automatically reviewed — 0 \
             confirmed real, 0 ruled out as false positives (0.0% verification precision among those examined)."
        ));
    }

    #[test]
    fn severity_breakdown_counts_each_bucket_independently() {
        let mut r = minimal_report();
        r.findings = vec![
            ranked("f1", Severity::Critical),
            ranked("f2", Severity::Critical),
            ranked("f3", Severity::High),
            ranked("f4", Severity::Medium),
            ranked("f5", Severity::Low),
            ranked("f6", Severity::Info),
        ];
        let md = render_executive_summary(&r).join("\n");
        assert!(md
            .contains("- **Findings confirmed**: 6 (2 critical, 1 high, 1 medium, 1 low, 1 info)"));
    }

    #[test]
    fn noise_reduction_line_computes_precision_over_examined_findings() {
        let mut r = minimal_report();
        r.raw_findings_count = 10;
        r.findings = vec![ranked("f1", Severity::High)];
        r.dropped = vec![
            dropped(DropReason::FalsePositive),
            dropped(DropReason::Duplicate),
        ];
        let md = render_executive_summary(&r).join("\n");
        assert!(md.contains(
            "- **Noise reduction**: 10 candidate finding(s) were automatically reviewed — 1 \
             confirmed real, 1 ruled out as false positives (50.0% verification precision among those examined)."
        ));
    }

    #[test]
    fn code_scanned_line_omitted_when_metrics_is_absent() {
        let md = render_executive_summary(&minimal_report()).join("\n");
        assert!(!md.contains("Code scanned"));
    }

    #[test]
    fn code_scanned_line_omitted_when_loc_scanned_is_empty() {
        let mut r = minimal_report();
        r.metrics = Some(ScanMetrics::default());
        let md = render_executive_summary(&r).join("\n");
        assert!(!md.contains("Code scanned"));
    }

    #[test]
    fn code_scanned_line_sums_loc_across_languages_with_thousands_separators() {
        let mut loc = BTreeMap::new();
        loc.insert("python".to_string(), 1500);
        loc.insert("rust".to_string(), 2500);
        let mut r = minimal_report();
        r.metrics = Some(ScanMetrics {
            loc_scanned_by_language: loc,
            ..Default::default()
        });
        let md = render_executive_summary(&r).join("\n");
        assert!(md.contains("- **Code scanned**: 4,000 lines of code across 2 language(s)"));
    }

    #[test]
    fn no_time_saved_or_roi_claims_are_ever_rendered() {
        let mut r = minimal_report();
        r.findings = vec![ranked("f1", Severity::High)];
        r.metrics = Some(ScanMetrics::default());
        let md = render_executive_summary(&r).join("\n").to_lowercase();
        assert!(!md.contains("time saved"));
        assert!(!md.contains("roi"));
        assert!(!md.contains("hours"));
    }
}

#[cfg(test)]
mod examined_precision_tests {
    use super::*;
    use bc_model::{DroppedFinding, ScanMetrics, Severity, VulnClass};

    fn dropped(reason: DropReason) -> DroppedFinding {
        dropped_with(reason, "")
    }

    fn dropped_with(reason: DropReason, detail: &str) -> DroppedFinding {
        DroppedFinding {
            file: "a.py".to_string(),
            line: 1,
            vuln_class: VulnClass::Injection,
            title: "t".to_string(),
            chunk_id: "c".to_string(),
            reason,
            detail: detail.to_string(),
            canonical_idx: None,
            provider_origins: Vec::new(),
            verification: None,
        }
    }

    #[test]
    fn precision_ignores_findings_the_budget_kept_from_the_verifier() {
        let mut r = tests::minimal_report();
        r.raw_findings_count = 10;
        r.findings.push(tests::ranked("t", Severity::High));
        r.dropped.push(dropped(DropReason::FalsePositive));
        for _ in 0..8 {
            r.dropped.push(dropped_with(
                DropReason::Unconfirmed,
                "not verified — token budget of 5 reached",
            ));
        }
        // A low-confidence verdict is Unconfirmed too, but it WAS examined
        // and must not be reported as budget-skipped.
        r.dropped.push(dropped_with(
            DropReason::Unconfirmed,
            "verifier confidence 6/10 below gate 7",
        ));
        let md = render_executive_summary(&r).join("\n");
        // 1 TP of 2 examined = 50 %, not 1 of 10 = 10 %.
        assert!(md.contains("50.0% verification precision"), "{md}");
        assert!(md.contains("**Not examined**: 8"), "{md}");
        // No metrics at all (and so no recorded reason): the generic
        // wording, which is the honest thing to say when the specific
        // budget is not on hand.
        assert!(
            md.contains("because a token or time budget was reached"),
            "{md}"
        );
    }

    /// When the metrics DO name why the scan stopped, the summary says
    /// so — the difference between an operator raising `--max-tokens`
    /// and an operator topping up a provider account.
    #[test]
    fn the_not_examined_line_names_the_recorded_budget_stop() {
        let mut r = tests::minimal_report();
        r.raw_findings_count = 3;
        r.findings.push(tests::ranked("t", Severity::High));
        r.dropped.push(dropped_with(
            DropReason::Unconfirmed,
            "not verified — provider quota exhausted — You exceeded your current quota",
        ));
        r.metrics = Some(ScanMetrics {
            budget_stop: "S6: provider quota exhausted — You exceeded your current quota — \
                          0 of 250 finding(s) verified, 250 left unverified"
                .to_string(),
            ..ScanMetrics::default()
        });
        let md = render_executive_summary(&r).join("\n");
        assert!(md.contains("**Not examined**: 1"), "{md}");
        assert!(
            md.contains("because the scan stopped early (S6: provider quota exhausted"),
            "{md}"
        );
        assert!(
            !md.contains("a token or time budget was reached"),
            "the generic wording must give way to the specific one: {md}"
        );
    }

    /// Metrics present but no budget stop recorded (the ordinary case for
    /// a scan whose unverified findings came from somewhere else): back
    /// to the generic wording rather than an empty pair of parentheses.
    #[test]
    fn the_not_examined_line_stays_generic_when_no_budget_stop_was_recorded() {
        let mut r = tests::minimal_report();
        r.raw_findings_count = 2;
        r.findings.push(tests::ranked("t", Severity::High));
        r.dropped.push(dropped_with(
            DropReason::Unconfirmed,
            "not verified — token budget of 5 reached",
        ));
        r.metrics = Some(ScanMetrics::default());
        let md = render_executive_summary(&r).join("\n");
        assert!(
            md.contains("because a token or time budget was reached"),
            "{md}"
        );
    }

    #[test]
    fn the_not_examined_line_is_absent_when_everything_was_verified() {
        let mut r = tests::minimal_report();
        r.raw_findings_count = 1;
        r.findings.push(tests::ranked("t", Severity::High));
        let md = render_executive_summary(&r).join("\n");
        assert!(!md.contains("Not examined"), "{md}");
        assert!(md.contains("100.0% verification precision"), "{md}");
    }
}
