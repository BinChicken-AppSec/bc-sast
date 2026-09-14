//! Markdown report renderer, ported from `models.py::FinalReport.to_markdown`
//! and its five `_render_*` helpers. Deliberately kept out of `bc-model`
//! (which owns only the report's typed data shape) so the DTO crate stays
//! low-branch-count and this crate can carry the anti-injection
//! sanitization and formatting logic on its own.

mod augment;
mod baseline;
mod chains;
mod dropped;
mod executive;
mod findings;
mod metrics;
mod sanitize;
mod threat_model;
mod unreachable;
mod wire;

use bc_model::FinalReport;

pub use augment::{augment_markdown, augment_markdown_with_remediation, RemediationView};
pub use baseline::{append_baseline_section, render_baseline_section, BaselineEntry, BaselineView};
pub use executive::render_executive_summary;
pub use findings::render_findings;
pub use sanitize::{demote_md_headings, md_cell, sanitize_title};

/// Render a `FinalReport` to the same Markdown shape as the Python
/// original's `to_markdown()`. See each submodule for the ported section.
pub fn render_markdown(report: &FinalReport) -> String {
    let tp = report.findings.len() as i64;
    let fp = report
        .dropped
        .iter()
        .filter(|d| d.reason == bc_model::DropReason::FalsePositive)
        .count() as i64;
    let dup = report
        .dropped
        .iter()
        .filter(|d| d.reason == bc_model::DropReason::Duplicate)
        .count() as i64;
    let verr = report
        .dropped
        .iter()
        .filter(|d| {
            matches!(
                d.reason,
                bc_model::DropReason::VerifyError | bc_model::DropReason::GuardrailBlocked
            )
        })
        .count() as i64;
    // Precision is measured over the findings the verifier actually
    // examined, not over every candidate. When a token or time budget
    // stops S6 early, the unexamined remainder is neither confirmed nor
    // refuted; dividing by the raw count charged each one against
    // precision as if it were a false positive (a 2026-09-06 capped scan
    // read 33.8% by that arithmetic and 74.8% by this one). This diverges
    // from `models.py::verification_precision_pct`, which divides by the
    // raw count — Python had no in-stage budget, so the two agreed there.
    let unverified = report
        .dropped
        .iter()
        .filter(|d| {
            // Only what a budget kept from the verifier. A low-confidence
            // verdict is also `Unconfirmed`, but that one WAS examined.
            d.reason == bc_model::DropReason::Unconfirmed && d.detail.starts_with("not verified")
        })
        .count() as i64;
    // Retained third-party findings from files this diff-scoped run never
    // analyzed. Counted on its own line and in NO other bucket: they are
    // not verdicts, so folding them into false positives, verifier errors
    // or the precision denominator would each claim this scan judged
    // something it never looked at. Always zero on a full-repo scan.
    let out_of_scope = report
        .dropped
        .iter()
        .filter(|d| d.reason == bc_model::DropReason::OutOfDiffScope)
        .count() as i64;
    let examined = tp + fp;
    let precision = if examined != 0 {
        tp as f64 / examined as f64 * 100.0
    } else {
        0.0
    };
    let safe_title = sanitize_title(
        report
            .repo_name
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or(&report.repo_root),
    );

    let mut out = vec![
        format!("# Agentic SAST — {safe_title}"),
        String::new(),
        "## Summary".to_string(),
        demote_md_headings(&report.summary),
        String::new(),
    ];

    out.extend(executive::render_executive_summary(report));
    if let Some(m) = &report.metrics {
        out.extend(metrics::render_metrics(m));
    }
    out.extend(metrics::render_scan_health(
        report.degraded,
        &report.degraded_reason,
        report.metrics.as_ref(),
    ));
    if let Some(tm) = &report.threat_model {
        out.extend(threat_model::render_threat_model(
            tm,
            report.app_profile.as_ref(),
        ));
    }

    out.extend([
        "## Verification".to_string(),
        format!(
            "- Raw findings (pre-verification): {}",
            report.raw_findings_count
        ),
        format!("- True positives (verified): {tp}"),
        format!("- False positives (dropped): {fp}"),
        format!("- Verifier errors (excluded — undetermined, not confirmed clean): {verr}"),
        format!("- Duplicates collapsed (all passes): {dup}"),
        format!("- Not verified (budget/time cap reached): {unverified}"),
    ]);
    // Conditional, unlike every line above it: a full-repo scan has no
    // diff to be outside of, and a permanent `: 0` line would invite the
    // reader to wonder which scans it applies to.
    if out_of_scope != 0 {
        out.push(format!(
            "- Outside the PR diff (third-party findings retained, not analyzed, \
             not remediated): {out_of_scope}"
        ));
    }
    out.extend([
        format!("- Verification precision (of findings examined): {precision:.1}%"),
        String::new(),
        format!("## Findings ({tp})"),
        String::new(),
    ]);

    out.extend(findings::render_findings(&report.findings));
    out.extend(chains::render_chains(
        &report.chains,
        &report.findings,
        report.degraded,
    ));
    out.extend(dropped::render_dropped(&report.dropped));

    if let Some(m) = &report.metrics {
        out.extend(metrics::render_scope_appendix(m));
    }
    if !report.unreachable_files.is_empty() {
        out.extend(unreachable::render_unreachable_appendix(
            &report.unreachable_files,
        ));
    }

    out.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_model::{DroppedFinding, Finding, RankedFinding, Severity, VulnClass};

    fn minimal_report() -> FinalReport {
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
            summary: "clean scan".to_string(),
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

    #[test]
    fn title_prefers_repo_name_over_repo_root() {
        let mut r = minimal_report();
        r.repo_name = Some("my-repo".to_string());
        r.repo_root = "/some/path".to_string();
        let md = render_markdown(&r);
        assert!(md.starts_with("# Agentic SAST — my-repo\n"));
    }

    #[test]
    fn title_falls_back_to_repo_root_when_repo_name_absent() {
        let r = minimal_report();
        let md = render_markdown(&r);
        assert!(md.starts_with("# Agentic SAST — /repo\n"));
    }

    #[test]
    fn title_is_sanitized() {
        let mut r = minimal_report();
        r.repo_name = Some("evil<script>`|[x]".to_string());
        let md = render_markdown(&r);
        assert!(md.starts_with("# Agentic SAST — evilscriptx\n"));
    }

    #[test]
    fn summary_is_demoted_for_injected_headings() {
        let mut r = minimal_report();
        r.summary = "## Fake\nreal summary".to_string();
        let md = render_markdown(&r);
        assert!(md.contains("## Summary\n**Fake**\nreal summary"));
    }

    #[test]
    fn no_metrics_omits_scan_metrics_and_appendix_sections() {
        let md = render_markdown(&minimal_report());
        assert!(!md.contains("## Scan Metrics"));
        assert!(!md.contains("## Appendix: Scan Scope"));
    }

    #[test]
    fn no_threat_model_omits_threat_model_section() {
        let md = render_markdown(&minimal_report());
        assert!(!md.contains("## Threat Model"));
    }

    #[test]
    fn healthy_scan_omits_scan_health_section() {
        let md = render_markdown(&minimal_report());
        assert!(!md.contains("## Scan Health"));
    }

    #[test]
    fn degraded_scan_shows_scan_health_section() {
        let mut r = minimal_report();
        r.degraded = true;
        r.degraded_reason = "chain pass failed".to_string();
        let md = render_markdown(&r);
        assert!(md.contains("## Scan Health"));
        assert!(md.contains("DEGRADED"));
        assert!(md.contains("chain pass failed"));
    }

    #[test]
    fn verification_section_computes_counts_and_precision() {
        let mut r = minimal_report();
        r.raw_findings_count = 10;
        r.findings = vec![RankedFinding {
            finding: finding("F1"),
            severity: Severity::High,
            exploitability_notes: String::new(),
        }];
        r.dropped = vec![
            DroppedFinding {
                file: "a.py".to_string(),
                line: 1,
                vuln_class: VulnClass::Other,
                title: "t".to_string(),
                chunk_id: "c".to_string(),
                reason: bc_model::DropReason::FalsePositive,
                detail: String::new(),
                canonical_idx: None,
                provider_origins: Vec::new(),
                verification: None,
            },
            DroppedFinding {
                file: "b.py".to_string(),
                line: 2,
                vuln_class: VulnClass::Other,
                title: "t".to_string(),
                chunk_id: "c".to_string(),
                reason: bc_model::DropReason::Duplicate,
                detail: String::new(),
                canonical_idx: None,
                provider_origins: Vec::new(),
                verification: None,
            },
        ];
        let md = render_markdown(&r);
        assert!(md.contains("- Raw findings (pre-verification): 10"));
        assert!(md.contains("- True positives (verified): 1"));
        assert!(md.contains("- False positives (dropped): 1"));
        assert!(md.contains("- Duplicates collapsed (all passes): 1"));
        assert!(md.contains("- Verification precision (of findings examined): 50.0%"));
        assert!(md.contains("- Not verified (budget/time cap reached): 0"));
        assert!(md.contains("## Findings (1)"));
    }

    #[test]
    fn zero_raw_findings_precision_is_zero_not_a_divide_by_zero_panic() {
        let md = render_markdown(&minimal_report());
        assert!(md.contains("- Verification precision (of findings examined): 0.0%"));
    }

    #[test]
    fn verifier_errors_counts_both_verify_error_and_guardrail_blocked() {
        let mut r = minimal_report();
        r.dropped = vec![
            DroppedFinding {
                file: "a.py".to_string(),
                line: 1,
                vuln_class: VulnClass::Other,
                title: "t".to_string(),
                chunk_id: "c".to_string(),
                reason: bc_model::DropReason::VerifyError,
                detail: String::new(),
                canonical_idx: None,
                provider_origins: Vec::new(),
                verification: None,
            },
            DroppedFinding {
                file: "b.py".to_string(),
                line: 2,
                vuln_class: VulnClass::Other,
                title: "t".to_string(),
                chunk_id: "c".to_string(),
                reason: bc_model::DropReason::GuardrailBlocked,
                detail: String::new(),
                canonical_idx: None,
                provider_origins: Vec::new(),
                verification: None,
            },
        ];
        let md = render_markdown(&r);
        assert!(md.contains("Verifier errors (excluded — undetermined, not confirmed clean): 2"));
    }

    /// An out-of-diff-scope retention is counted on its own line and
    /// nowhere else — not as a false positive, not as a verifier error,
    /// and not in the precision denominator.
    #[test]
    fn out_of_diff_scope_retentions_get_their_own_verification_line() {
        let mut r = minimal_report();
        r.findings = vec![RankedFinding {
            finding: finding("F1"),
            severity: Severity::High,
            exploitability_notes: String::new(),
        }];
        r.dropped = vec![DroppedFinding {
            file: "vendor/old.py".to_string(),
            line: 7,
            vuln_class: VulnClass::Other,
            title: "pre-existing".to_string(),
            chunk_id: "external:semgrep:x".to_string(),
            reason: bc_model::DropReason::OutOfDiffScope,
            detail: "outside the diff".to_string(),
            canonical_idx: None,
            provider_origins: Vec::new(),
            verification: None,
        }];
        let md = render_markdown(&r);
        assert!(md.contains(
            "- Outside the PR diff (third-party findings retained, not analyzed, not remediated): 1"
        ));
        assert!(md.contains("- False positives (dropped): 0"));
        assert!(md.contains("Verifier errors (excluded — undetermined, not confirmed clean): 0"));
        assert!(md.contains("- Verification precision (of findings examined): 100.0%"));
        assert!(md.contains("## Findings (1)"));
        // Retained, not vanished.
        assert!(md.contains("**[OUT OF DIFF SCOPE]**"));
        assert!(md.contains("vendor/old.py"));
    }

    /// The line is absent entirely from a scan that had no diff to be
    /// outside of, so a full-repo report reads exactly as it did before.
    #[test]
    fn a_report_with_no_out_of_scope_retentions_omits_the_line() {
        let md = render_markdown(&minimal_report());
        assert!(!md.contains("Outside the PR diff"));
    }

    #[test]
    fn zero_findings_still_renders_the_findings_heading() {
        let md = render_markdown(&minimal_report());
        assert!(md.contains("## Findings (0)"));
    }

    #[test]
    fn end_to_end_report_contains_all_sections_in_order() {
        let mut r = minimal_report();
        r.metrics = Some(bc_model::ScanMetrics {
            total_files_in_scope: 10,
            analyzed_files_unique: 5,
            ..Default::default()
        });
        r.threat_model = Some(bc_model::ThreatModel {
            system_context: "ctx".to_string(),
            ..Default::default()
        });
        r.findings = vec![RankedFinding {
            finding: finding("F1"),
            severity: Severity::High,
            exploitability_notes: String::new(),
        }];
        let md = render_markdown(&r);
        let pos = |s: &str| md.find(s).expect(s);
        let p_summary = pos("## Summary");
        let p_executive = pos("## Executive Summary");
        let p_metrics = pos("## Scan Metrics");
        let p_threat = pos("## Threat Model");
        let p_verification = pos("## Verification");
        let p_findings = pos("## Findings");
        let p_chains = pos("## Exploit Chains");
        let p_dropped = pos("## Dropped Findings");
        assert!(p_summary < p_executive);
        assert!(p_executive < p_metrics);
        assert!(p_metrics < p_threat);
        assert!(p_threat < p_verification);
        assert!(p_verification < p_findings);
        assert!(p_findings < p_chains);
        assert!(p_chains < p_dropped);
    }

    #[test]
    fn unreachable_appendix_is_absent_when_the_list_is_empty() {
        let md = render_markdown(&minimal_report());
        assert!(!md.contains("Files Not Sent for Catch-All Review"));
    }

    #[test]
    fn unreachable_appendix_renders_after_dropped_findings_when_populated() {
        let mut r = minimal_report();
        r.unreachable_files = vec!["unreached.py".to_string()];
        let md = render_markdown(&r);
        assert!(md.contains("Files Not Sent for Catch-All Review"));
        assert!(md.contains("- `unreached.py`"));
        let p_dropped = md.find("## Dropped Findings").unwrap();
        let p_unreachable = md.find("Files Not Sent for Catch-All Review").unwrap();
        assert!(p_dropped < p_unreachable);
    }
}
