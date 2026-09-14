//! Flat CSV export of scan findings — one row per finding, columns
//! matching the conventions industry SAST tools (Snyk, Semgrep,
//! Checkmarx) use for their own CSV exports, so a customer's existing
//! spreadsheet/BI/ticketing pipeline can consume this tool's output the
//! same way it already consumes those. Not a port — the Python original
//! never emitted CSV either; SARIF was (and remains) the only
//! machine-readable format either side produces.
//!
//! `id` reuses `bc-sarif`'s own stable per-finding fingerprint
//! ([`bc_sarif::finding_id`]) rather than minting a second, different
//! identity scheme, so a row here and a SARIF `result` for the same
//! finding carry the same id and a consumer can correlate the two
//! formats directly.

mod row;
mod wire;
mod writer;

use bc_model::FinalReport;

/// Renders `report.findings` as RFC4180-ish CSV text (header row first),
/// ready to write straight to a `.csv` file. Empty findings still produce
/// a header-only file, matching how `report.sarif` always emits a valid
/// (if empty) `results` array rather than omitting the file.
pub fn build_csv(report: &FinalReport) -> String {
    let mut out = writer::write_row(
        &row::HEADER
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>(),
    );
    for rf in &report.findings {
        out.push_str(&writer::write_row(&row::row_for(rf)));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_model::{Finding, RankedFinding, Severity, VulnClass};

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

    fn finding(overrides: impl FnOnce(&mut Finding)) -> Finding {
        let mut f = Finding {
            provider_origins: Vec::new(),
            chunk_id: "c1".to_string(),
            file: "app/login.py".to_string(),
            line_start: 10,
            line_end: 12,
            vuln_class: VulnClass::Injection,
            cwe: Some("CWE-89".to_string()),
            title: "SQL injection".to_string(),
            impact: String::new(),
            description: "user input reaches a raw query".to_string(),
            exploit_scenario: String::new(),
            preconditions: Vec::new(),
            recommendation: "use parameterized queries".to_string(),
            code_snippet: "query(x)".to_string(),
            source_ref: None,
            sink_ref: None,
            backfilled_refs: Vec::new(),
            reanchored: Vec::new(),
            compliance_requirements: Vec::new(),
            confidence: 0.9,
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
        };
        overrides(&mut f);
        f
    }

    #[test]
    fn empty_report_produces_header_only() {
        let csv = build_csv(&minimal_report());
        let header = row::HEADER.join(",");
        let lines: Vec<&str> = csv.split("\r\n").collect();
        assert_eq!(lines[0], header);
        // exactly one trailing empty element after the header's own CRLF
        assert_eq!(lines, vec![header.as_str(), ""]);
    }

    #[test]
    fn one_finding_produces_a_header_and_one_data_row() {
        let mut r = minimal_report();
        r.findings = vec![RankedFinding {
            finding: finding(|_| {}),
            severity: Severity::High,
            exploitability_notes: String::new(),
        }];
        let csv = build_csv(&r);
        let lines: Vec<&str> = csv.trim_end().split("\r\n").collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[1].contains("SQL injection"));
        assert!(lines[1].contains("HIGH"));
        assert!(lines[1].contains("CWE-89"));
    }

    #[test]
    fn findings_preserve_report_order() {
        let mut r = minimal_report();
        r.findings = vec![
            RankedFinding {
                finding: finding(|f| f.title = "Z finding".to_string()),
                severity: Severity::Low,
                exploitability_notes: String::new(),
            },
            RankedFinding {
                finding: finding(|f| f.title = "A finding".to_string()),
                severity: Severity::Critical,
                exploitability_notes: String::new(),
            },
        ];
        let csv = build_csv(&r);
        let z_idx = csv.find("Z finding").unwrap();
        let a_idx = csv.find("A finding").unwrap();
        assert!(z_idx < a_idx);
    }

    #[test]
    fn a_title_containing_a_comma_is_quoted_and_does_not_shift_columns() {
        let mut r = minimal_report();
        r.findings = vec![RankedFinding {
            finding: finding(|f| f.title = "SQL injection, unescaped".to_string()),
            severity: Severity::High,
            exploitability_notes: String::new(),
        }];
        let csv = build_csv(&r);
        let data_line = csv.trim_end().split("\r\n").nth(1).unwrap();
        assert!(data_line.starts_with(&format!(
            "{},HIGH,CWE-89",
            bc_sarif::finding_id(&r.findings[0].finding)
        )));
        assert!(data_line.contains("\"SQL injection, unescaped\""));
    }

    #[test]
    fn header_has_one_column_per_row_field() {
        let mut r = minimal_report();
        r.findings = vec![RankedFinding {
            finding: finding(|_| {}),
            severity: Severity::High,
            exploitability_notes: String::new(),
        }];
        let csv = build_csv(&r);
        let header_cols = csv.split("\r\n").next().unwrap().split(',').count();
        let data_line = csv.trim_end().split("\r\n").nth(1).unwrap();
        // A naive split(',') on the data row undercounts once a quoted
        // field's own embedded commas are involved, but this fixture's
        // fields are all comma-free, so a straight count is a valid check
        // here specifically.
        assert_eq!(data_line.split(',').count(), header_cols);
    }
}
