use serde::Deserialize;

use crate::{Severity, ThirdPartyFinding};

const SKIPPED_ISSUE_TYPES: [&str; 5] = ["cloud", "eol", "license", "malware", "scm_security"];

#[derive(Debug, Deserialize)]
struct AikidoIssue {
    #[serde(default)]
    group_id: Option<serde_json::Value>,
    #[serde(default)]
    code_repo_id: Option<serde_json::Value>,
    #[serde(default)]
    status: Option<String>,
    id: serde_json::Value,
    #[serde(default)]
    rule: String,
    #[serde(default, rename = "type")]
    issue_type: String,
    #[serde(default)]
    severity: String,
    #[serde(default)]
    affected_file: Option<String>,
    #[serde(default)]
    start_line: Option<i64>,
    #[serde(default)]
    end_line: Option<i64>,
    #[serde(default)]
    cwe_classes: Option<Vec<String>>,
    #[serde(default)]
    affected_package: Option<String>,
    #[serde(default)]
    installed_version: Option<String>,
    #[serde(default)]
    patched_versions: Option<Vec<String>>,
    #[serde(default)]
    cve_id: Option<String>,
}

fn default_line() -> i64 {
    1
}

pub fn parse(text: &str) -> Result<Vec<ThirdPartyFinding>, String> {
    parse_with_count(text).map(|(findings, _)| findings)
}

pub fn parse_with_count(text: &str) -> Result<(Vec<ThirdPartyFinding>, usize), String> {
    let issues: Vec<AikidoIssue> =
        serde_json::from_str(text).map_err(|e| format!("malformed Aikido JSON: {e}"))?;
    let raw_count = issues.len();

    let findings = issues
        .into_iter()
        .filter(|issue| !is_skipped_type(&issue.issue_type))
        .map(to_finding)
        .collect();
    Ok((findings, raw_count))
}

fn is_skipped_type(issue_type: &str) -> bool {
    SKIPPED_ISSUE_TYPES
        .iter()
        .any(|t| issue_type.eq_ignore_ascii_case(t))
}

fn to_finding(issue: AikidoIssue) -> ThirdPartyFinding {
    let title = if issue.rule.is_empty() {
        "Aikido finding".to_string()
    } else {
        issue.rule.clone()
    };
    let external_id = value_to_id_string(&issue.id);
    let file = issue
        .affected_file
        .filter(|f| !f.trim().is_empty())
        .or_else(|| issue.affected_package.clone())
        .unwrap_or_else(|| title.clone());
    let cwe = issue
        .cwe_classes
        .as_ref()
        .and_then(|classes| classes.first())
        .map(|c| normalize_cwe(c));
    let line_start = issue.start_line.unwrap_or_else(default_line);
    let line_end = issue.end_line.unwrap_or(line_start);

    let mut description = format!(
        "Aikido ({}) flagged: {title}.",
        display_type(&issue.issue_type)
    );
    if let Some(pkg) = &issue.affected_package {
        description.push_str(&format!(" Affected package: {pkg}."));
    }
    if let Some(version) = non_empty(&issue.installed_version) {
        description.push_str(&format!(" Installed version: {version}."));
    }
    if let Some(patched) = &issue.patched_versions {
        if !patched.is_empty() {
            description.push_str(&format!(" Fixed in: {}.", patched.join(", ")));
        }
    }
    if let Some(cve) = non_empty(&issue.cve_id) {
        description.push_str(&format!(" {cve}."));
    }

    let component = non_empty(&issue.affected_package).map(|pkg| appsec_model::ComponentRef {
        name: pkg.to_string(),
        version: issue.installed_version.clone().unwrap_or_default(),
        purl: None,
        cves: non_empty(&issue.cve_id)
            .map(|c| vec![c.to_string()])
            .unwrap_or_default(),
        fixed_in: issue.patched_versions.clone().unwrap_or_default(),
        dependency_path: Vec::new(),
        direct: None,
    });
    ThirdPartyFinding {
        component,
        provider_origins: vec![appsec_model::ProviderOrigin {
            provider: appsec_model::ProviderKind::Aikido,
            product: match issue.issue_type.as_str() {
                "sast" | "iac" => appsec_model::ProviderProduct::Sast,
                "open_source" => appsec_model::ProviderProduct::Dependency,
                "leaked_secret" => appsec_model::ProviderProduct::Secret,
                _ => appsec_model::ProviderProduct::Unknown,
            },
            source: appsec_model::ProviderSource::File,
            native_ids: appsec_model::ProviderNativeIds {
                issue_id: scalar_id(&issue.id),
                group_id: issue.group_id.as_ref().and_then(scalar_id),
                ..Default::default()
            },
            repository_id: issue.code_repo_id.as_ref().and_then(scalar_id),
            state: issue.status.clone(),
            severity: Some(issue.severity.clone()),
            ..Default::default()
        }],
        vendor: "aikido",
        external_id,
        title,
        file,
        line_start,
        line_end,
        cwe,
        severity: parse_severity(&issue.severity),
        description,
        recommendation: String::new(),
    }
}

fn non_empty(value: &Option<String>) -> Option<&str> {
    value.as_deref().filter(|v| !v.trim().is_empty())
}

fn scalar_id(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) if !s.trim().is_empty() => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn value_to_id_string(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        _ => "unknown".to_string(),
    }
}

fn display_type(issue_type: &str) -> &str {
    if issue_type.is_empty() {
        "unclassified"
    } else {
        issue_type
    }
}

fn normalize_cwe(raw: &str) -> String {
    let trimmed = raw.trim();
    let stripped = trimmed
        .strip_prefix("CWE-")
        .or_else(|| trimmed.strip_prefix("cwe-"))
        .unwrap_or(trimmed);
    format!("CWE-{stripped}")
}

fn parse_severity(raw: &str) -> Severity {
    match raw.trim().to_ascii_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_json() -> &'static str {
        r#"[
          {
            "id": 12345,
            "group_id": 1,
            "type": "sast",
            "attack_surface": "backend",
            "status": "open",
            "rule": "SQL injection",
            "rule_id": "aik_sast_001",
            "severity": "high",
            "severity_score": 90,
            "affected_file": "src/db.py",
            "start_line": 42,
            "end_line": 44,
            "cwe_classes": ["CWE-89"],
            "first_detected_at": 1700489005
          },
          {
            "id": 67890,
            "group_id": 2,
            "type": "open_source",
            "attack_surface": "backend",
            "status": "open",
            "rule": "Prototype Pollution",
            "severity": "critical",
            "severity_score": 90,
            "affected_package": "minimist",
            "affected_file": null,
            "start_line": null,
            "end_line": null,
            "snooze_until": null,
            "ignored_at": null,
            "closed_at": null,
            "cwe_classes": ["CWE-1321"],
            "installed_version": "4.2.0",
            "patched_versions": ["4.2.1", "5.0.0"],
            "cve_id": "CVE-2024-8385",
            "first_detected_at": 1700489005
          }
        ]"#
    }

    #[test]
    fn parses_every_issue() {
        assert_eq!(parse(sample_json()).unwrap().len(), 2);
    }

    #[test]
    fn an_explicit_null_line_does_not_fail_the_whole_export() {
        let findings = parse(sample_json()).unwrap();
        assert_eq!(findings[1].line_start, 1);
        assert_eq!(findings[1].line_end, 1);
    }

    #[test]
    fn maps_the_first_sast_issue_fully() {
        let findings = parse(sample_json()).unwrap();
        let f = &findings[0];
        assert_eq!(f.external_id, "12345");
        assert_eq!(f.title, "SQL injection");
        assert_eq!(f.file, "src/db.py");
        assert_eq!(f.line_start, 42);
        assert_eq!(f.line_end, 44);
        assert_eq!(f.cwe, Some("CWE-89".to_string()));
        assert_eq!(f.severity, Severity::High);
    }

    #[test]
    fn an_open_source_issue_with_a_null_file_falls_back_to_the_package() {
        let findings = parse(sample_json()).unwrap();
        assert_eq!(findings[1].file, "minimist");
    }

    #[test]
    fn an_sca_description_carries_the_version_and_cve_evidence() {
        let findings = parse(sample_json()).unwrap();
        let description = &findings[1].description;
        assert!(description.contains("Affected package: minimist."));
        assert!(description.contains("Installed version: 4.2.0."));
        assert!(description.contains("Fixed in: 4.2.1, 5.0.0."));
        assert!(description.contains("CVE-2024-8385."));
    }

    #[test]
    fn description_is_synthesized_from_structured_fields() {
        let findings = parse(sample_json()).unwrap();
        assert!(findings[0].description.contains("sast"));
        assert!(findings[0].description.contains("SQL injection"));
    }

    #[test]
    fn recommendation_is_always_empty() {
        let findings = parse(sample_json()).unwrap();
        assert!(findings.iter().all(|f| f.recommendation.is_empty()));
    }

    #[test]
    fn a_null_cwe_classes_list_yields_no_cwe() {
        let json = r#"[{"id": 1, "rule": "x", "severity": "low", "cwe_classes": null}]"#;
        assert_eq!(parse(json).unwrap()[0].cwe, None);
    }

    #[test]
    fn an_empty_cwe_classes_list_yields_no_cwe() {
        let json = r#"[{"id": 1, "rule": "x", "severity": "low", "cwe_classes": []}]"#;
        assert_eq!(parse(json).unwrap()[0].cwe, None);
    }

    #[test]
    fn a_start_line_with_no_end_line_spans_a_single_line() {
        let json = r#"[{"id": 1, "type": "sast", "rule": "x", "start_line": 9, "end_line": null}]"#;
        let findings = parse(json).unwrap();
        assert_eq!(findings[0].line_start, 9);
        assert_eq!(findings[0].line_end, 9);
    }

    #[rstest::rstest]
    #[case("cloud")]
    #[case("eol")]
    #[case("license")]
    #[case("malware")]
    #[case("scm_security")]
    #[case("SCM_SECURITY")]
    fn non_code_issue_types_are_skipped(#[case] issue_type: &str) {
        let json =
            format!(r#"[{{"id": 1, "type": "{issue_type}", "rule": "x", "severity": "high"}}]"#);
        assert!(parse(&json).unwrap().is_empty());
    }

    #[rstest::rstest]
    #[case("sast")]
    #[case("open_source")]
    #[case("leaked_secret")]
    #[case("iac")]
    #[case("mobile")]
    #[case("surface_monitoring")]
    fn code_relevant_issue_types_are_kept(#[case] issue_type: &str) {
        let json =
            format!(r#"[{{"id": 1, "type": "{issue_type}", "rule": "x", "severity": "high"}}]"#);
        assert_eq!(parse(&json).unwrap().len(), 1);
    }

    #[test]
    fn parse_with_count_reports_the_raw_issue_count_including_skipped_ones() {
        let json = r#"[
            {"id": 1, "type": "sast", "rule": "kept"},
            {"id": 2, "type": "cloud", "rule": "skipped"},
            {"id": 3, "type": "license", "rule": "skipped"}
        ]"#;
        let (findings, raw_count) = parse_with_count(json).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(raw_count, 3);
    }

    #[test]
    fn a_missing_file_and_package_falls_back_to_the_rule_title() {
        let json = r#"[{"id": 1, "rule": "Something", "severity": "low"}]"#;
        let findings = parse(json).unwrap();
        assert_eq!(findings[0].file, "Something");
    }

    #[test]
    fn a_blank_affected_file_falls_back_to_the_package() {
        let json = r#"[{"id": 1, "rule": "x", "affected_file": "  ", "affected_package": "pkg"}]"#;
        assert_eq!(parse(json).unwrap()[0].file, "pkg");
    }

    #[test]
    fn a_missing_rule_falls_back_to_a_generic_title() {
        let json = r#"[{"id": 1, "severity": "low"}]"#;
        let findings = parse(json).unwrap();
        assert_eq!(findings[0].title, "Aikido finding");
    }

    #[test]
    fn a_missing_type_is_described_as_unclassified() {
        let json = r#"[{"id": 1, "rule": "x", "severity": "low"}]"#;
        assert!(parse(json).unwrap()[0].description.contains("unclassified"));
    }

    #[test]
    fn a_missing_cwe_yields_none() {
        let json = r#"[{"id": 1, "rule": "x", "severity": "low"}]"#;
        let findings = parse(json).unwrap();
        assert_eq!(findings[0].cwe, None);
    }

    #[test]
    fn a_cwe_with_no_prefix_at_all_is_still_normalized() {
        let json = r#"[{"id": 1, "rule": "x", "severity": "low", "cwe_classes": ["89"]}]"#;
        let findings = parse(json).unwrap();
        assert_eq!(findings[0].cwe, Some("CWE-89".to_string()));
    }

    #[test]
    fn a_lowercase_cwe_prefix_is_not_double_prefixed() {
        let json = r#"[{"id": 1, "rule": "x", "cwe_classes": ["cwe-79"]}]"#;
        assert_eq!(parse(json).unwrap()[0].cwe, Some("CWE-79".to_string()));
    }

    #[test]
    fn a_string_id_is_carried_through_as_is() {
        let json = r#"[{"id": "abc-123", "rule": "x", "severity": "low"}]"#;
        let findings = parse(json).unwrap();
        assert_eq!(findings[0].external_id, "abc-123");
    }

    #[test]
    fn a_non_string_non_number_id_falls_back_to_unknown() {
        let json = r#"[{"id": null, "rule": "x", "severity": "low"}]"#;
        let findings = parse(json).unwrap();
        assert_eq!(findings[0].external_id, "unknown");
    }

    #[test]
    fn blank_open_source_metadata_is_left_out_of_the_description() {
        let json = r#"[{"id": 1, "type": "open_source", "rule": "x",
                        "installed_version": "  ", "patched_versions": [], "cve_id": ""}]"#;
        let description = &parse(json).unwrap()[0].description;
        assert!(!description.contains("Installed version"));
        assert!(!description.contains("Fixed in"));
        assert_eq!(description, "Aikido (open_source) flagged: x.");
    }

    #[rstest::rstest]
    #[case("critical", Severity::Critical)]
    #[case("high", Severity::High)]
    #[case("medium", Severity::Medium)]
    #[case("low", Severity::Low)]
    #[case("weird", Severity::Info)]
    fn severity_mapping(#[case] raw: &str, #[case] expected: Severity) {
        let json = format!(r#"[{{"id": 1, "rule": "x", "severity": "{raw}"}}]"#);
        assert_eq!(parse(&json).unwrap()[0].severity, expected);
    }

    #[test]
    fn empty_array_yields_no_findings() {
        assert!(parse("[]").unwrap().is_empty());
    }

    #[test]
    fn malformed_json_is_an_error() {
        assert!(parse("not json").is_err());
    }

    #[test]
    fn a_non_array_top_level_value_is_an_error() {
        assert!(parse("{}").is_err());
    }
}

#[cfg(test)]
mod provenance_tests {
    use super::*;
    #[test]
    fn exported_identity_is_file_evidence_not_publication_authority() {
        let findings = parse(
            r#"[{"id":123,"group_id":456,"code_repo_id":789,"type":"sast","status":"open"}]"#,
        )
        .unwrap();
        let origin = &findings[0].provider_origins[0];
        assert_eq!(origin.native_ids.issue_id.as_deref(), Some("123"));
        assert_eq!(origin.native_ids.group_id.as_deref(), Some("456"));
        assert_eq!(origin.source, appsec_model::ProviderSource::File);
        assert_eq!(
            crate::to_finding(&findings[0]).provider_origins,
            findings[0].provider_origins
        );
        let missing = parse(r#"[{"id":null}]"#).unwrap();
        assert!(missing[0].provider_origins[0].native_ids.issue_id.is_none());
    }
}

#[cfg(test)]
mod iac_product_tests {
    use super::*;

    fn product_for(issue_type: &str) -> appsec_model::ProviderProduct {
        let json =
            format!(r#"[{{"id": 1, "type": "{issue_type}", "rule": "x", "severity": "high"}}]"#);
        parse(&json).unwrap()[0].provider_origins[0].product
    }

    #[test]
    fn iac_is_static_analysis_of_code_so_it_is_classified_as_sast() {
        assert_eq!(product_for("iac"), appsec_model::ProviderProduct::Sast);
        assert_eq!(product_for("sast"), appsec_model::ProviderProduct::Sast);
    }

    #[test]
    fn the_other_product_kinds_keep_their_own_classification() {
        assert_eq!(
            product_for("open_source"),
            appsec_model::ProviderProduct::Dependency
        );
        assert_eq!(
            product_for("leaked_secret"),
            appsec_model::ProviderProduct::Secret
        );
    }
}

#[cfg(test)]
mod component_tests {
    use super::*;

    #[test]
    fn an_open_source_issue_keeps_its_package_version_and_fix() {
        let json = r#"[{"id":1,"type":"open_source","rule":"x","severity":"high",
            "affected_package":"lodash","installed_version":"4.17.15",
            "patched_versions":["4.17.19"],"cve_id":"CVE-2020-8203"}]"#;
        let c = parse(json).unwrap()[0]
            .component
            .clone()
            .expect("component");
        assert_eq!(c.coordinate(), "lodash@4.17.15");
        assert_eq!(c.cves, vec!["CVE-2020-8203"]);
        assert_eq!(c.fixed_in, vec!["4.17.19"]);
    }

    #[test]
    fn a_sast_issue_has_no_component() {
        let json = r#"[{"id":1,"type":"sast","rule":"x","severity":"high"}]"#;
        assert!(parse(json).unwrap()[0].component.is_none());
    }
}
