//! Sonatype Lifecycle/IQ Server "raw report" JSON ingestion
//! (`GET /api/v2/applications/{id}/reports/{reportId}/raw` —
//! `components[].securityData.securityIssues[]`). The policy-violations
//! API and the Vulnerability Details API each use materially different,
//! only partially-overlapping shapes (richer CWE/remediation text lives
//! in the latter, a separate per-finding lookup this parser doesn't
//! make); the raw report is what an operator most plausibly has
//! archived from a CI run, so it's the only shape targeted here.
//!
//! This is a **component/dependency-level (SCA) format — there is no
//! source line, and no CWE at all in the base raw report** (CWE only
//! appears via a separate Vulnerability Details lookup or an opt-in
//! `customData` query param neither of which this parser reads).
//! Severity is a bare numeric CVSS score (0.0-10.0), not a word bucket —
//! mapped onto this crate's shared [`Severity`] via the standard CVSS
//! severity-rating thresholds (NVD's own bucketing: Critical 9.0-10.0,
//! High 7.0-8.9, Medium 4.0-6.9, Low 0.1-3.9, None/Info 0.0).
//!
//! Issues an operator has triaged out inside IQ Server itself — Sonatype's
//! `"Not Applicable"` status, the state its own policy conditions test as
//! `NOT_APPLICABLE` ("Security Vulnerability Status is not
//! NOT_APPLICABLE", quoted verbatim in the policy sample on
//! `help.sonatype.com/en/report-rest-api.html`) — are skipped, matching
//! how Checkmarx's `FalsePositive="True"` and Semgrep's `is_ignored`
//! results are treated: an explicit human triage decision shouldn't be
//! silently reintroduced here as a fresh, unreviewed finding.
//!
//! `dependencyData.directDependency` is surfaced in the description
//! because it is the single most decision-relevant fact about an SCA
//! finding that this report *does* carry: a vulnerable direct dependency
//! is the team's own to upgrade, whereas a transitive one usually is not,
//! and S6's verifier has no other way to tell them apart.

use serde::Deserialize;

use crate::{Severity, ThirdPartyFinding};

#[derive(Debug, Default, Deserialize)]
struct SonatypeReport {
    #[serde(default)]
    components: Vec<SonatypeComponent>,
}

#[derive(Debug, Default, Deserialize)]
struct SonatypeComponent {
    #[serde(default, rename = "componentIdentifier")]
    component_identifier: Option<ComponentIdentifier>,
    #[serde(default, rename = "packageUrl")]
    package_url: Option<String>,
    #[serde(default)]
    pathnames: Vec<String>,
    #[serde(default, rename = "securityData")]
    security_data: SecurityData,
    #[serde(default, rename = "dependencyData")]
    dependency_data: Option<DependencyData>,
}

#[derive(Debug, Deserialize)]
struct DependencyData {
    #[serde(default, rename = "directDependency")]
    direct_dependency: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct ComponentIdentifier {
    #[serde(default)]
    coordinates: Coordinates,
}

#[derive(Debug, Default, Deserialize)]
struct Coordinates {
    #[serde(default, rename = "groupId")]
    group_id: String,
    #[serde(default, rename = "artifactId")]
    artifact_id: String,
    #[serde(default)]
    version: String,
}

impl Coordinates {
    fn display(&self) -> Option<String> {
        if self.artifact_id.is_empty() {
            return None;
        }
        let mut s = if self.group_id.is_empty() {
            self.artifact_id.clone()
        } else {
            format!("{}:{}", self.group_id, self.artifact_id)
        };
        if !self.version.is_empty() {
            s.push('@');
            s.push_str(&self.version);
        }
        Some(s)
    }
}

#[derive(Debug, Default, Deserialize)]
struct SecurityData {
    #[serde(default, rename = "securityIssues")]
    security_issues: Vec<SecurityIssue>,
}

#[derive(Debug, Deserialize)]
struct SecurityIssue {
    #[serde(default)]
    source: String,
    #[serde(default)]
    reference: String,
    #[serde(default)]
    severity: f64,
    #[serde(default)]
    status: String,
    #[serde(default, rename = "threatCategory")]
    threat_category: String,
}

pub fn parse(text: &str) -> Result<Vec<ThirdPartyFinding>, String> {
    let report: SonatypeReport =
        serde_json::from_str(text).map_err(|e| format!("malformed Sonatype JSON: {e}"))?;

    let mut findings = Vec::new();
    for component in report.components {
        let coords = component
            .component_identifier
            .as_ref()
            .and_then(|ci| ci.coordinates.display());
        let file = component
            .pathnames
            .first()
            .cloned()
            .or_else(|| component.package_url.clone())
            .or_else(|| coords.clone())
            .unwrap_or_else(|| "(unknown component)".to_string());
        let component_label = coords
            .clone()
            .or_else(|| component.package_url.clone())
            .unwrap_or_else(|| file.clone());
        let dependency_note = component
            .dependency_data
            .as_ref()
            .and_then(|d| d.direct_dependency)
            .map(|direct| {
                if direct {
                    " Direct dependency."
                } else {
                    " Transitive dependency."
                }
            })
            .unwrap_or("");

        for issue in component.security_data.security_issues {
            if is_triaged_out(&issue.status) {
                continue;
            }
            let reference = if issue.reference.is_empty() {
                "unknown-vulnerability".to_string()
            } else {
                issue.reference.clone()
            };
            let title = format!("{component_label}: {reference}");
            let mut description = format!(
                "Sonatype ({}) flagged {component_label} for {reference}.",
                if issue.source.is_empty() {
                    "security scan"
                } else {
                    issue.source.as_str()
                }
            );
            if !issue.status.is_empty() {
                description.push_str(&format!(" Status: {}.", issue.status));
            }
            if !issue.threat_category.is_empty() {
                description.push_str(&format!(" Threat category: {}.", issue.threat_category));
            }
            description.push_str(dependency_note);
            findings.push(ThirdPartyFinding {
                provider_origins: vec![bc_model::ProviderOrigin {
                    provider: bc_model::ProviderKind::Sonatype,
                    source: bc_model::ProviderSource::File,
                    product: bc_model::ProviderProduct::Dependency,
                    ..Default::default()
                }],
                vendor: "sonatype",
                external_id: format!("{component_label}:{reference}"),
                title,
                file: file.clone(),
                line_start: 1,
                line_end: 1,
                cwe: None,
                severity: cvss_to_severity(issue.severity),
                description,
                recommendation: String::new(),
            });
        }
    }
    Ok(findings)
}

/// Sonatype writes this state as `"Not Applicable"` in the raw report and
/// as `NOT_APPLICABLE` in policy-condition text, so both spellings (and
/// any casing) are recognized.
fn is_triaged_out(status: &str) -> bool {
    status
        .trim()
        .replace(['_', '-'], " ")
        .eq_ignore_ascii_case("not applicable")
}

fn cvss_to_severity(score: f64) -> Severity {
    if score >= 9.0 {
        Severity::Critical
    } else if score >= 7.0 {
        Severity::High
    } else if score >= 4.0 {
        Severity::Medium
    } else if score > 0.0 {
        Severity::Low
    } else {
        Severity::Info
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_json() -> &'static str {
        r#"{
          "components": [
            {
              "componentIdentifier": {
                "format": "maven",
                "coordinates": {"groupId": "tomcat", "artifactId": "tomcat-util", "version": "5.5.23"}
              },
              "pathnames": ["sample-application.zip/tomcat-util-5.5.23.jar"],
              "securityData": {
                "securityIssues": [
                  {"source": "cve", "reference": "CVE-2007-3385", "severity": 4.3, "status": "Open", "threatCategory": "severe"}
                ]
              }
            },
            {
              "packageUrl": "pkg:npm/lodash@4.17.15",
              "securityData": {
                "securityIssues": [
                  {"reference": "CVE-2020-8203", "severity": 9.8}
                ]
              }
            }
          ]
        }"#
    }

    #[test]
    fn parses_every_security_issue_across_components() {
        assert_eq!(parse(sample_json()).unwrap().len(), 2);
    }

    #[test]
    fn maps_the_first_component_issue_fully() {
        let findings = parse(sample_json()).unwrap();
        let f = &findings[0];
        assert_eq!(f.file, "sample-application.zip/tomcat-util-5.5.23.jar");
        assert!(f.title.contains("tomcat:tomcat-util@5.5.23"));
        assert!(f.title.contains("CVE-2007-3385"));
        assert_eq!(f.line_start, 1);
        assert_eq!(f.line_end, 1);
        assert_eq!(f.cwe, None);
        assert_eq!(f.severity, Severity::Medium);
        assert!(f.description.contains("Open"));
        assert!(f.description.contains("severe"));
    }

    #[test]
    fn a_component_with_no_pathnames_falls_back_to_the_package_url() {
        let findings = parse(sample_json()).unwrap();
        assert_eq!(findings[1].file, "pkg:npm/lodash@4.17.15");
    }

    #[test]
    fn coordinates_with_no_artifact_id_are_not_used_as_the_component_label() {
        let json = r#"{"components": [{
            "componentIdentifier": {"format": "maven", "coordinates": {"version": "1.0"}},
            "packageUrl": "pkg:generic/x@1.0",
            "securityData": {"securityIssues": [{"reference": "CVE-1", "severity": 5.0}]}
        }]}"#;
        let findings = parse(json).unwrap();
        assert!(findings[0].title.contains("pkg:generic/x@1.0"));
    }

    #[test]
    fn coordinates_with_no_group_id_omit_the_group_prefix() {
        let json = r#"{"components": [{
            "componentIdentifier": {"format": "npm", "coordinates": {"artifactId": "requests", "version": "2.1.0"}},
            "securityData": {"securityIssues": [{"reference": "CVE-1", "severity": 5.0}]}
        }]}"#;
        let findings = parse(json).unwrap();
        assert_eq!(findings[0].title, "requests@2.1.0: CVE-1");
    }

    #[rstest::rstest]
    #[case(9.8, Severity::Critical)]
    #[case(9.0, Severity::Critical)]
    #[case(8.9, Severity::High)]
    #[case(7.0, Severity::High)]
    #[case(6.9, Severity::Medium)]
    #[case(4.0, Severity::Medium)]
    #[case(3.9, Severity::Low)]
    #[case(0.1, Severity::Low)]
    #[case(0.0, Severity::Info)]
    fn cvss_severity_bucketing(#[case] score: f64, #[case] expected: Severity) {
        assert_eq!(cvss_to_severity(score), expected);
    }

    #[test]
    fn a_missing_reference_falls_back_to_a_placeholder() {
        let json = r#"{"components": [{"packageUrl": "pkg:npm/x@1", "securityData": {"securityIssues": [{"severity": 1.0}]}}]}"#;
        let findings = parse(json).unwrap();
        assert!(findings[0].title.contains("unknown-vulnerability"));
    }

    #[test]
    fn a_component_with_no_issues_yields_no_findings() {
        let json = r#"{"components": [{"packageUrl": "pkg:npm/x@1", "securityData": {"securityIssues": []}}]}"#;
        assert!(parse(json).unwrap().is_empty());
    }

    #[test]
    fn empty_components_yields_no_findings() {
        assert!(parse(r#"{"components": []}"#).unwrap().is_empty());
    }

    #[test]
    fn missing_components_key_yields_no_findings() {
        assert!(parse("{}").unwrap().is_empty());
    }

    #[test]
    fn malformed_json_is_an_error() {
        assert!(parse("not json").is_err());
    }

    #[rstest::rstest]
    #[case("Not Applicable", true)]
    #[case("NOT_APPLICABLE", true)]
    #[case("not-applicable", true)]
    #[case("  Not Applicable  ", true)]
    #[case("Open", false)]
    #[case("Acknowledged", false)]
    #[case("", false)]
    fn triaged_out_status_recognition(#[case] status: &str, #[case] expected: bool) {
        assert_eq!(is_triaged_out(status), expected);
    }

    #[test]
    fn a_not_applicable_security_issue_is_skipped() {
        let json = r#"{"components": [{
            "packageUrl": "pkg:npm/x@1",
            "securityData": {"securityIssues": [
                {"reference": "CVE-1", "severity": 9.0, "status": "Not Applicable"},
                {"reference": "CVE-2", "severity": 9.0, "status": "Open"}
            ]}
        }]}"#;
        let findings = parse(json).unwrap();
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("CVE-2"));
    }

    #[test]
    fn a_direct_dependency_is_called_out_in_the_description() {
        let json = r#"{"components": [{
            "packageUrl": "pkg:maven/org.example/ACME-business@1.0",
            "securityData": {"securityIssues": [{"reference": "CVE-1", "severity": 5.0}]},
            "dependencyData": {"directDependency": true, "innerSource": false}
        }]}"#;
        let findings = parse(json).unwrap();
        assert!(findings[0].description.contains("Direct dependency."));
    }

    #[test]
    fn a_transitive_dependency_is_called_out_in_the_description() {
        let json = r#"{"components": [{
            "packageUrl": "pkg:maven/javax.inject/javax.inject@1",
            "securityData": {"securityIssues": [{"reference": "CVE-1", "severity": 5.0}]},
            "dependencyData": {"directDependency": false, "innerSource": false,
                               "parentComponentPurls": ["pkg:maven/org.example/ACME@1.0"]}
        }]}"#;
        let findings = parse(json).unwrap();
        assert!(findings[0].description.contains("Transitive dependency."));
    }

    #[test]
    fn a_component_with_no_dependency_data_says_nothing_about_directness() {
        let findings = parse(sample_json()).unwrap();
        assert!(!findings[0].description.contains("dependency."));
    }

    #[test]
    fn dependency_data_without_a_direct_dependency_flag_says_nothing_about_directness() {
        let json = r#"{"components": [{
            "packageUrl": "pkg:npm/x@1",
            "securityData": {"securityIssues": [{"reference": "CVE-1", "severity": 5.0}]},
            "dependencyData": {"innerSource": false}
        }]}"#;
        let findings = parse(json).unwrap();
        assert!(!findings[0].description.contains("dependency."));
    }

    #[test]
    fn a_component_with_neither_pathnames_coordinates_nor_package_url_falls_back() {
        let json = r#"{"components": [{"securityData": {"securityIssues": [{"reference": "CVE-1", "severity": 5.0}]}}]}"#;
        let findings = parse(json).unwrap();
        assert_eq!(findings[0].file, "(unknown component)");
    }
}
