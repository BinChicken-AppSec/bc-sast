//! Per-finding CSV row construction. Columns follow the conventions of
//! industry SAST tool CSV exports (Snyk/Semgrep/Checkmarx-style: one row
//! per finding, severity/CWE/CVSS/file/line/status as flat columns) —
//! not a port, this tool's own feature; the Python original never
//! emitted CSV either.

use bc_model::RankedFinding;

use crate::wire::{severity_upper, verdict_str};

pub(crate) const HEADER: &[&str] = &[
    "id",
    "severity",
    "cwe",
    "cwe_name",
    "vuln_class",
    "title",
    "file",
    "line_start",
    "line_end",
    "cvss_score",
    "cvss_vector",
    "cvss_rating",
    "confidence",
    "votes",
    "verdict",
    "offensive_priority",
    "compliance_requirements",
    "description",
    "recommendation",
];

pub(crate) fn row_for(rf: &RankedFinding) -> Vec<String> {
    let f = &rf.finding;
    let cwe = bc_cwe::cwe_for(f.cwe.as_deref(), Some(f.vuln_class.as_str()));
    vec![
        bc_sarif::finding_id(f),
        severity_upper(rf.severity).to_string(),
        cwe.clone().unwrap_or_default(),
        bc_cwe::cwe_name(cwe.as_deref()).to_string(),
        f.vuln_class.as_str().to_string(),
        f.title.clone(),
        f.file.clone(),
        f.line_start.to_string(),
        f.line_end.to_string(),
        f.cvss_score.map(|s| format!("{s:.1}")).unwrap_or_default(),
        f.cvss_vector.clone().unwrap_or_default(),
        f.cvss_rating.clone().unwrap_or_default(),
        format!("{:.2}", f.confidence),
        f.votes.to_string(),
        f.verdict.map(verdict_str).unwrap_or_default().to_string(),
        f.offensive_priority.clone().unwrap_or_default(),
        f.compliance_requirements.join("; "),
        f.description.clone(),
        f.recommendation.clone(),
    ]
}

const _: () = {
    // Compile-time reminder to keep `row_for`'s output in lockstep with
    // `HEADER` — both are hand-maintained lists, not derived from one
    // shared source, since `RankedFinding`/`Finding` have far more
    // fields than belong in a flat CSV export.
    assert!(HEADER.len() == 19);
};

#[cfg(test)]
mod tests {
    use super::*;
    use bc_model::{Finding, Severity, Verdict, VulnClass};

    fn finding(overrides: impl FnOnce(&mut Finding)) -> Finding {
        let mut f = Finding {
            provider_origins: Vec::new(),
            chunk_id: "c1".to_string(),
            file: "app/login.py".to_string(),
            line_start: 10,
            line_end: 12,
            vuln_class: VulnClass::Injection,
            cwe: None,
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
            votes: 2,
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

    fn ranked(f: Finding, severity: Severity) -> RankedFinding {
        RankedFinding {
            finding: f,
            severity,
            exploitability_notes: String::new(),
        }
    }

    fn field(row: &[String], name: &str) -> String {
        let idx = HEADER.iter().position(|h| *h == name).unwrap();
        row[idx].clone()
    }

    #[test]
    fn row_matches_header_length() {
        let rf = ranked(finding(|_| {}), Severity::High);
        assert_eq!(row_for(&rf).len(), HEADER.len());
    }

    #[test]
    fn severity_is_uppercase() {
        let rf = ranked(finding(|_| {}), Severity::Critical);
        assert_eq!(field(&row_for(&rf), "severity"), "CRITICAL");
    }

    #[test]
    fn explicit_cwe_is_used_verbatim() {
        let rf = ranked(
            finding(|f| f.cwe = Some("CWE-89".to_string())),
            Severity::High,
        );
        let row = row_for(&rf);
        assert_eq!(field(&row, "cwe"), "CWE-89");
        assert_eq!(
            field(&row, "cwe_name"),
            "Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)"
        );
    }

    #[test]
    fn absent_cwe_falls_back_to_vuln_class() {
        let rf = ranked(
            finding(|f| f.vuln_class = VulnClass::UseAfterFree),
            Severity::High,
        );
        assert_eq!(field(&row_for(&rf), "cwe"), "CWE-416");
    }

    #[test]
    fn other_vuln_class_with_no_cwe_leaves_cwe_columns_blank() {
        let rf = ranked(finding(|f| f.vuln_class = VulnClass::Other), Severity::Low);
        let row = row_for(&rf);
        assert_eq!(field(&row, "cwe"), "");
        assert_eq!(field(&row, "cwe_name"), "");
    }

    #[test]
    fn cvss_fields_populated_when_present() {
        let rf = ranked(
            finding(|f| {
                f.cvss_score = Some(9.8);
                f.cvss_vector = Some("CVSS:3.1/AV:N".to_string());
                f.cvss_rating = Some("Critical".to_string());
            }),
            Severity::Critical,
        );
        let row = row_for(&rf);
        assert_eq!(field(&row, "cvss_score"), "9.8");
        assert_eq!(field(&row, "cvss_vector"), "CVSS:3.1/AV:N");
        assert_eq!(field(&row, "cvss_rating"), "Critical");
    }

    #[test]
    fn cvss_fields_blank_when_absent() {
        let rf = ranked(finding(|_| {}), Severity::Low);
        let row = row_for(&rf);
        assert_eq!(field(&row, "cvss_score"), "");
        assert_eq!(field(&row, "cvss_vector"), "");
        assert_eq!(field(&row, "cvss_rating"), "");
    }

    #[test]
    fn verdict_renders_the_wire_string_when_present() {
        let rf = ranked(
            finding(|f| f.verdict = Some(Verdict::TruePositive)),
            Severity::High,
        );
        assert_eq!(field(&row_for(&rf), "verdict"), "TRUE_POSITIVE");
    }

    #[test]
    fn verdict_blank_when_unverified() {
        let rf = ranked(finding(|_| {}), Severity::High);
        assert_eq!(field(&row_for(&rf), "verdict"), "");
    }

    #[test]
    fn offensive_priority_blank_when_absent() {
        let rf = ranked(finding(|_| {}), Severity::High);
        assert_eq!(field(&row_for(&rf), "offensive_priority"), "");
    }

    #[test]
    fn offensive_priority_present_when_set() {
        let rf = ranked(
            finding(|f| f.offensive_priority = Some("P1".to_string())),
            Severity::High,
        );
        assert_eq!(field(&row_for(&rf), "offensive_priority"), "P1");
    }

    #[test]
    fn compliance_requirements_joined_with_semicolons() {
        let rf = ranked(
            finding(|f| {
                f.compliance_requirements = vec!["V1.2.4".to_string(), "6.2.4".to_string()]
            }),
            Severity::High,
        );
        assert_eq!(
            field(&row_for(&rf), "compliance_requirements"),
            "V1.2.4; 6.2.4"
        );
    }

    #[test]
    fn compliance_requirements_blank_when_empty() {
        let rf = ranked(finding(|_| {}), Severity::High);
        assert_eq!(field(&row_for(&rf), "compliance_requirements"), "");
    }

    #[test]
    fn confidence_and_votes_are_formatted() {
        let rf = ranked(
            finding(|f| {
                f.confidence = 0.876;
                f.votes = 3;
            }),
            Severity::High,
        );
        let row = row_for(&rf);
        assert_eq!(field(&row, "confidence"), "0.88");
        assert_eq!(field(&row, "votes"), "3");
    }

    #[test]
    fn id_matches_the_sarif_finding_id_for_cross_format_correlation() {
        let f = finding(|_| {});
        let rf = ranked(f.clone(), Severity::High);
        assert_eq!(field(&row_for(&rf), "id"), bc_sarif::finding_id(&f));
    }
}
