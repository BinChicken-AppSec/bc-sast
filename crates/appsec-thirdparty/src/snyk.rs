use serde::Deserialize;

use crate::{Severity, ThirdPartyFinding};

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum SnykExport {
    Sarif(SarifLog),
    Multi(Vec<SnykReport>),
    Single(SnykReport),
}

#[derive(Debug, Default, Deserialize)]
struct SnykReport {
    #[serde(default)]
    vulnerabilities: Vec<SnykVuln>,
    #[serde(default, rename = "displayTargetFile")]
    display_target_file: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SnykVuln {
    id: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    severity: String,
    #[serde(default)]
    description: String,
    #[serde(default, rename = "packageName")]
    package_name: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    identifiers: SnykIdentifiers,
    #[serde(default, rename = "fixedIn")]
    fixed_in: Vec<String>,
    #[serde(default)]
    from: Vec<String>,
    #[serde(default, rename = "isTransitive")]
    is_transitive: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
struct SnykIdentifiers {
    #[serde(default, rename = "CWE")]
    cwe: Vec<String>,
    #[serde(default, rename = "CVE")]
    cve: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SarifLog {
    runs: Vec<SarifRun>,
}

#[derive(Debug, Deserialize)]
struct SarifRun {
    #[serde(default)]
    tool: SarifTool,
    #[serde(default)]
    results: Vec<SarifResult>,
}

#[derive(Debug, Default, Deserialize)]
struct SarifTool {
    #[serde(default)]
    driver: SarifDriver,
}

#[derive(Debug, Default, Deserialize)]
struct SarifDriver {
    #[serde(default)]
    rules: Vec<SarifRule>,
}

#[derive(Debug, Deserialize)]
struct SarifRule {
    #[serde(default)]
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    properties: SarifRuleProperties,
}

#[derive(Debug, Default, Deserialize)]
struct SarifRuleProperties {
    #[serde(default)]
    cwe: Vec<String>,
    #[serde(default)]
    tags: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SarifResult {
    #[serde(default, rename = "ruleId")]
    rule_id: String,
    #[serde(default)]
    level: String,
    #[serde(default)]
    message: SarifMessage,
    #[serde(default)]
    locations: Vec<SarifLocation>,
}

#[derive(Debug, Default, Deserialize)]
struct SarifMessage {
    #[serde(default)]
    text: String,
}

#[derive(Debug, Default, Deserialize)]
struct SarifLocation {
    #[serde(default, rename = "physicalLocation")]
    physical_location: SarifPhysicalLocation,
}

#[derive(Debug, Default, Deserialize)]
struct SarifPhysicalLocation {
    #[serde(default, rename = "artifactLocation")]
    artifact_location: SarifArtifactLocation,
    #[serde(default)]
    region: SarifRegion,
}

#[derive(Debug, Default, Deserialize)]
struct SarifArtifactLocation {
    #[serde(default)]
    uri: String,
}

#[derive(Debug, Deserialize)]
struct SarifRegion {
    #[serde(default = "default_line", rename = "startLine")]
    start_line: i64,
    #[serde(default, rename = "endLine")]
    end_line: Option<i64>,
}

impl Default for SarifRegion {
    fn default() -> Self {
        SarifRegion {
            start_line: default_line(),
            end_line: None,
        }
    }
}

fn default_line() -> i64 {
    1
}

pub fn parse(text: &str) -> Result<Vec<ThirdPartyFinding>, String> {
    let export: SnykExport =
        serde_json::from_str(text).map_err(|e| format!("malformed Snyk JSON: {e}"))?;
    Ok(match export {
        SnykExport::Sarif(log) => parse_sarif(log),
        SnykExport::Multi(reports) => reports.into_iter().flat_map(parse_report).collect(),
        SnykExport::Single(report) => parse_report(report),
    })
}

fn parse_report(report: SnykReport) -> Vec<ThirdPartyFinding> {
    let target_file = report.display_target_file.filter(|f| !f.trim().is_empty());

    report
        .vulnerabilities
        .into_iter()
        .map(|v| {
            let title = if v.title.is_empty() {
                v.id.clone()
            } else {
                v.title.clone()
            };
            let package = format_package(&v.package_name, &v.version, &title);
            let file = target_file.clone().unwrap_or_else(|| package.clone());
            let cwe = v.identifiers.cwe.first().map(|c| normalize_cwe(c));
            let recommendation = extract_remediation_section(&v.description);
            let description = if v.description.is_empty() {
                format!("Snyk flagged {package} for {title}.")
            } else {
                v.description
            };
            let direct = v
                .is_transitive
                .map(|t| !t)
                .or_else(|| (v.from.len() > 1).then_some(v.from.len() == 2));
            ThirdPartyFinding {
                provider_origins: vec![appsec_model::ProviderOrigin {
                    provider: appsec_model::ProviderKind::Snyk,
                    source: appsec_model::ProviderSource::File,
                    product: appsec_model::ProviderProduct::Dependency,
                    ..Default::default()
                }],
                component: Some(appsec_model::ComponentRef {
                    name: v.package_name.clone(),
                    version: v.version.clone(),
                    purl: None,
                    cves: v.identifiers.cve.clone(),
                    fixed_in: v.fixed_in.clone(),
                    dependency_path: v.from.clone(),
                    direct,
                }),
                vendor: "snyk",
                external_id: v.id,
                title,
                file,
                line_start: 1,
                line_end: 1,
                cwe,
                severity: parse_severity(&v.severity),
                description,
                recommendation,
            }
        })
        .collect()
}

fn parse_sarif(log: SarifLog) -> Vec<ThirdPartyFinding> {
    let mut findings = Vec::new();
    for run in log.runs {
        for result in run.results {
            let rule = run
                .tool
                .driver
                .rules
                .iter()
                .find(|r| r.id == result.rule_id);
            let location = result.locations.first();
            let file = location
                .map(|l| l.physical_location.artifact_location.uri.clone())
                .unwrap_or_default();
            let line_start = location.map_or(1, |l| l.physical_location.region.start_line);
            let line_end = location
                .and_then(|l| l.physical_location.region.end_line)
                .unwrap_or(line_start);
            let title = match rule.map(|r| r.name.as_str()).filter(|n| !n.is_empty()) {
                Some(name) => name.to_string(),
                None if result.rule_id.is_empty() => "Snyk Code finding".to_string(),
                None => result.rule_id.clone(),
            };
            let description = if result.message.text.is_empty() {
                format!("Snyk Code rule {title} matched.")
            } else {
                result.message.text.clone()
            };
            findings.push(ThirdPartyFinding {
                provider_origins: vec![appsec_model::ProviderOrigin {
                    provider: appsec_model::ProviderKind::Snyk,
                    source: appsec_model::ProviderSource::File,
                    product: appsec_model::ProviderProduct::Sast,
                    ..Default::default()
                }],
                component: None,
                vendor: "snyk",
                external_id: format!("{}:{file}:{line_start}", result.rule_id),
                title,
                file,
                line_start,
                line_end,
                cwe: rule.and_then(sarif_rule_cwe),
                severity: parse_sarif_level(&result.level),
                description,
                recommendation: String::new(),
            });
        }
    }
    findings
}

fn sarif_rule_cwe(rule: &SarifRule) -> Option<String> {
    rule.properties
        .cwe
        .first()
        .or_else(|| {
            rule.properties
                .tags
                .iter()
                .find(|t| t.trim().to_ascii_uppercase().starts_with("CWE-"))
        })
        .map(|c| normalize_cwe(c))
}

fn parse_sarif_level(raw: &str) -> Severity {
    match raw.trim().to_ascii_lowercase().as_str() {
        "error" => Severity::High,
        "warning" => Severity::Medium,
        "note" => Severity::Low,
        _ => Severity::Info,
    }
}

fn format_package(name: &str, version: &str, fallback: &str) -> String {
    if name.is_empty() {
        fallback.to_string()
    } else if version.is_empty() {
        name.to_string()
    } else {
        format!("{name}@{version}")
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

fn extract_remediation_section(markdown: &str) -> String {
    const HEADING: &str = "## Remediation";
    let Some(start) = markdown.find(HEADING) else {
        return String::new();
    };
    let after = &markdown[start + HEADING.len()..];
    let end = after.find("\n## ").unwrap_or(after.len());
    after[..end].trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_json() -> String {
        serde_json::json!({
          "displayTargetFile": "package.json",
          "vulnerabilities": [
            {
              "id": "SNYK-JS-LODASH-567746",
              "title": "Prototype Pollution",
              "severity": "high",
              "description": "## Overview\nBad stuff.\n## Remediation\nUpgrade to 4.17.19 or later.\n## References\nsee cve",
              "packageName": "lodash",
              "version": "4.17.15",
              "identifiers": { "CWE": ["CWE-1321"] }
            },
            {
              "id": "SNYK-PY-REQUESTS-1",
              "severity": "low",
              "packageName": "requests",
              "version": "2.1.0"
            }
          ]
        })
        .to_string()
    }

    fn sarif_json() -> String {
        serde_json::json!({
          "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
          "version": "2.1.0",
          "runs": [{
            "tool": {"driver": {
              "name": "SnykCode",
              "semanticVersion": "1.0.0",
              "rules": [
                {
                  "id": "javascript/HardcodedNonCryptoSecret",
                  "name": "HardcodedNonCryptoSecret",
                  "shortDescription": {"text": "Hardcoded Secret"},
                  "properties": {
                    "tags": ["javascript", "security", "CWE-798"],
                    "cwe": ["CWE-798"],
                    "precision": "very-high"
                  }
                },
                {
                  "id": "javascript/NoHardcodedPasswords",
                  "name": "NoHardcodedPasswords",
                  "properties": {"tags": ["javascript", "security", "CWE-259"]}
                }
              ]
            }},
            "results": [
              {
                "ruleId": "javascript/HardcodedNonCryptoSecret",
                "level": "warning",
                "message": {"text": "Avoid hardcoding values that are meant to be secret."},
                "locations": [{"physicalLocation": {
                  "artifactLocation": {"uri": "src/config.js", "uriBaseId": "%SRCROOT%"},
                  "region": {"startLine": 12, "endLine": 14, "startColumn": 9, "endColumn": 40}
                }}]
              },
              {
                "ruleId": "javascript/NoHardcodedPasswords",
                "level": "error",
                "message": {"text": "Do not hardcode passwords."},
                "locations": [{"physicalLocation": {
                  "artifactLocation": {"uri": "src/auth.js"},
                  "region": {"startLine": 7}
                }}]
              }
            ]
          }]
        })
        .to_string()
    }

    #[test]
    fn parses_every_vulnerability() {
        let findings = parse(&sample_json()).unwrap();
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn maps_the_first_vulnerability_fully() {
        let findings = parse(&sample_json()).unwrap();
        let f = &findings[0];
        assert_eq!(f.external_id, "SNYK-JS-LODASH-567746");
        assert_eq!(f.title, "Prototype Pollution");
        assert_eq!(f.file, "package.json");
        assert_eq!(f.line_start, 1);
        assert_eq!(f.line_end, 1);
        assert_eq!(f.cwe, Some("CWE-1321".to_string()));
        assert_eq!(f.severity, Severity::High);
    }

    #[test]
    fn extracts_the_remediation_section_from_the_markdown_description() {
        let findings = parse(&sample_json()).unwrap();
        assert_eq!(findings[0].recommendation, "Upgrade to 4.17.19 or later.");
    }

    #[test]
    fn description_keeps_the_full_markdown_text() {
        let findings = parse(&sample_json()).unwrap();
        assert!(findings[0].description.contains("## References"));
    }

    #[test]
    fn a_vuln_with_no_title_falls_back_to_its_id() {
        let findings = parse(&sample_json()).unwrap();
        assert_eq!(findings[1].title, "SNYK-PY-REQUESTS-1");
    }

    #[test]
    fn a_vuln_with_no_description_gets_a_synthesized_one() {
        let findings = parse(&sample_json()).unwrap();
        assert!(findings[1].description.contains("requests@2.1.0"));
    }

    #[test]
    fn a_vuln_with_no_cwe_yields_none() {
        let findings = parse(&sample_json()).unwrap();
        assert_eq!(findings[1].cwe, None);
    }

    #[test]
    fn missing_display_target_file_falls_back_to_package_at_version() {
        let json = r#"{"vulnerabilities": [{"id": "X", "packageName": "foo", "version": "1.0"}]}"#;
        let findings = parse(json).unwrap();
        assert_eq!(findings[0].file, "foo@1.0");
    }

    #[test]
    fn missing_package_name_falls_back_to_the_title() {
        let json = r#"{"vulnerabilities": [{"id": "X", "title": "Something Bad"}]}"#;
        let findings = parse(json).unwrap();
        assert_eq!(findings[0].file, "Something Bad");
    }

    #[test]
    fn a_package_name_with_no_version_omits_the_at_sign() {
        let json = r#"{"vulnerabilities": [{"id": "X", "packageName": "foo"}]}"#;
        let findings = parse(json).unwrap();
        assert_eq!(findings[0].file, "foo");
    }

    #[test]
    fn a_cwe_already_prefixed_is_not_double_prefixed() {
        let json = r#"{"vulnerabilities": [{"id": "X", "identifiers": {"CWE": ["CWE-79"]}}]}"#;
        let findings = parse(json).unwrap();
        assert_eq!(findings[0].cwe, Some("CWE-79".to_string()));
    }

    #[test]
    fn a_cwe_with_no_prefix_at_all_is_still_normalized() {
        let json = r#"{"vulnerabilities": [{"id": "X", "identifiers": {"CWE": ["79"]}}]}"#;
        let findings = parse(json).unwrap();
        assert_eq!(findings[0].cwe, Some("CWE-79".to_string()));
    }

    #[test]
    fn a_lowercase_cwe_prefix_is_not_double_prefixed() {
        let json = r#"{"vulnerabilities": [{"id": "X", "identifiers": {"CWE": ["cwe-79"]}}]}"#;
        let findings = parse(json).unwrap();
        assert_eq!(findings[0].cwe, Some("CWE-79".to_string()));
    }

    #[test]
    fn unrecognized_severity_falls_back_to_info() {
        let json = r#"{"vulnerabilities": [{"id": "X", "severity": "weird"}]}"#;
        let findings = parse(json).unwrap();
        assert_eq!(findings[0].severity, Severity::Info);
    }

    #[rstest::rstest]
    #[case("critical", Severity::Critical)]
    #[case("high", Severity::High)]
    #[case("medium", Severity::Medium)]
    #[case("low", Severity::Low)]
    fn severity_mapping(#[case] raw: &str, #[case] expected: Severity) {
        let json = format!(r#"{{"vulnerabilities": [{{"id": "X", "severity": "{raw}"}}]}}"#);
        assert_eq!(parse(&json).unwrap()[0].severity, expected);
    }

    #[test]
    fn a_description_without_a_remediation_heading_yields_no_recommendation() {
        let json = r#"{"vulnerabilities": [{"id": "X", "description": "just some text"}]}"#;
        let findings = parse(json).unwrap();
        assert_eq!(findings[0].recommendation, "");
    }

    #[test]
    fn a_remediation_section_ends_at_the_next_heading() {
        let json = serde_json::json!({"vulnerabilities": [{
            "id": "X",
            "description": "## Remediation\nUpgrade.\n## References\nlink"
        }]})
        .to_string();
        assert_eq!(parse(&json).unwrap()[0].recommendation, "Upgrade.");
    }

    #[test]
    fn empty_vulnerabilities_array_yields_no_findings() {
        assert!(parse(r#"{"vulnerabilities": []}"#).unwrap().is_empty());
    }

    #[test]
    fn missing_vulnerabilities_key_yields_no_findings() {
        assert!(parse("{}").unwrap().is_empty());
    }

    #[test]
    fn malformed_json_is_an_error() {
        assert!(parse("not json").is_err());
    }

    #[test]
    fn a_top_level_value_matching_no_supported_shape_is_an_error() {
        assert!(parse("123").is_err());
    }

    #[test]
    fn an_all_projects_array_is_parsed_across_every_project() {
        let json = serde_json::json!([
            {"displayTargetFile": "package.json",
             "vulnerabilities": [{"id": "SNYK-JS-1", "packageName": "lodash", "version": "1"}]},
            {"displayTargetFile": "requirements.txt",
             "vulnerabilities": [{"id": "SNYK-PY-1", "packageName": "requests", "version": "2"}]}
        ])
        .to_string();
        let findings = parse(&json).unwrap();
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].file, "package.json");
        assert_eq!(findings[1].file, "requirements.txt");
        assert_eq!(findings[1].external_id, "SNYK-PY-1");
    }

    #[test]
    fn an_empty_all_projects_array_yields_no_findings() {
        assert!(parse("[]").unwrap().is_empty());
    }

    #[test]
    fn a_sarif_log_parses_every_result() {
        assert_eq!(parse(&sarif_json()).unwrap().len(), 2);
    }

    #[test]
    fn a_sarif_result_maps_file_line_span_message_and_cwe() {
        let findings = parse(&sarif_json()).unwrap();
        let f = &findings[0];
        assert_eq!(f.vendor, "snyk");
        assert_eq!(f.title, "HardcodedNonCryptoSecret");
        assert_eq!(f.file, "src/config.js");
        assert_eq!(f.line_start, 12);
        assert_eq!(f.line_end, 14);
        assert_eq!(f.cwe, Some("CWE-798".to_string()));
        assert_eq!(f.severity, Severity::Medium);
        assert_eq!(
            f.description,
            "Avoid hardcoding values that are meant to be secret."
        );
        assert_eq!(
            f.external_id,
            "javascript/HardcodedNonCryptoSecret:src/config.js:12"
        );
    }

    #[test]
    fn a_sarif_rule_without_a_dedicated_cwe_list_falls_back_to_its_tags() {
        let findings = parse(&sarif_json()).unwrap();
        assert_eq!(findings[1].cwe, Some("CWE-259".to_string()));
    }

    #[test]
    fn a_sarif_region_with_no_end_line_uses_the_start_line_for_both() {
        let findings = parse(&sarif_json()).unwrap();
        assert_eq!(findings[1].line_start, 7);
        assert_eq!(findings[1].line_end, 7);
    }

    #[rstest::rstest]
    #[case("error", Severity::High)]
    #[case("warning", Severity::Medium)]
    #[case("note", Severity::Low)]
    #[case("none", Severity::Info)]
    #[case("", Severity::Info)]
    fn sarif_level_mapping(#[case] level: &str, #[case] expected: Severity) {
        let json = serde_json::json!({
            "runs": [{"results": [{"ruleId": "r", "level": level}]}]
        })
        .to_string();
        assert_eq!(parse(&json).unwrap()[0].severity, expected);
    }

    #[test]
    fn a_sarif_result_with_no_matching_rule_titles_itself_from_the_rule_id() {
        let json = serde_json::json!({
            "runs": [{"tool": {"driver": {"rules": []}},
                      "results": [{"ruleId": "java/Sqli", "level": "error",
                                   "message": {"text": "SQLi."}}]}]
        })
        .to_string();
        let findings = parse(&json).unwrap();
        assert_eq!(findings[0].title, "java/Sqli");
        assert_eq!(findings[0].cwe, None);
    }

    #[test]
    fn a_sarif_result_with_no_rule_id_at_all_gets_a_generic_title() {
        let json = serde_json::json!({"runs": [{"results": [{"level": "note"}]}]}).to_string();
        let findings = parse(&json).unwrap();
        assert_eq!(findings[0].title, "Snyk Code finding");
        assert!(findings[0].description.contains("Snyk Code finding"));
    }

    #[test]
    fn a_sarif_rule_with_an_empty_name_falls_back_to_the_rule_id() {
        let json = serde_json::json!({
            "runs": [{"tool": {"driver": {"rules": [{"id": "r", "name": ""}]}},
                      "results": [{"ruleId": "r"}]}]
        })
        .to_string();
        assert_eq!(parse(&json).unwrap()[0].title, "r");
    }

    #[test]
    fn a_sarif_result_with_no_location_defaults_to_line_one_and_an_empty_file() {
        let json = serde_json::json!({
            "runs": [{"results": [{"ruleId": "r", "message": {"text": "m"}}]}]
        })
        .to_string();
        let findings = parse(&json).unwrap();
        assert_eq!(findings[0].file, "");
        assert_eq!(findings[0].line_start, 1);
        assert_eq!(findings[0].line_end, 1);
    }

    #[test]
    fn a_sarif_result_with_no_region_defaults_to_line_one() {
        let json = serde_json::json!({
            "runs": [{"results": [{"ruleId": "r", "locations": [{"physicalLocation":
                {"artifactLocation": {"uri": "a.js"}}}]}]}]
        })
        .to_string();
        let findings = parse(&json).unwrap();
        assert_eq!(findings[0].file, "a.js");
        assert_eq!(findings[0].line_start, 1);
    }

    #[test]
    fn a_sarif_rule_tag_list_without_any_cwe_yields_none() {
        let json = serde_json::json!({
            "runs": [{"tool": {"driver": {"rules": [
                        {"id": "r", "name": "R", "properties": {"tags": ["security", "js"]}}]}},
                      "results": [{"ruleId": "r"}]}]
        })
        .to_string();
        assert_eq!(parse(&json).unwrap()[0].cwe, None);
    }

    #[test]
    fn a_sarif_log_with_no_runs_yields_no_findings() {
        assert!(parse(r#"{"runs": []}"#).unwrap().is_empty());
    }

    #[test]
    fn a_sarif_run_with_no_results_yields_no_findings() {
        assert!(parse(r#"{"runs": [{"tool": {"driver": {}}}]}"#)
            .unwrap()
            .is_empty());
    }
}

#[cfg(test)]
mod component_tests {
    use super::*;

    const SCA: &str = r#"{"vulnerabilities":[{
        "id":"SNYK-JS-LODASH-1","packageName":"lodash","version":"4.17.15",
        "title":"Prototype Pollution","severity":"high",
        "identifiers":{"CWE":["CWE-1321"],"CVE":["CVE-2020-8203"]},
        "fixedIn":["4.17.19"],
        "from":["app@1.0.0","express@4.17.1","lodash@4.17.15"],
        "isTransitive":true}]}"#;

    #[test]
    fn a_dependency_finding_keeps_the_component_the_advisory_is_about() {
        let c = parse(SCA).unwrap()[0].component.clone().expect("component");
        assert_eq!(c.name, "lodash");
        assert_eq!(c.version, "4.17.15");
        assert_eq!(c.coordinate(), "lodash@4.17.15");
    }

    #[test]
    fn the_cve_ids_survive_ingestion() {
        let c = parse(SCA).unwrap()[0].component.clone().expect("component");
        assert_eq!(c.cves, vec!["CVE-2020-8203"]);
        assert_eq!(
            c.fixed_in,
            vec!["4.17.19"],
            "the fix version is what makes the finding actionable"
        );
    }

    #[test]
    fn the_dependency_path_survives_because_it_is_what_makes_a_chain() {
        let c = parse(SCA).unwrap()[0].component.clone().expect("component");
        assert_eq!(
            c.dependency_path,
            vec!["app@1.0.0", "express@4.17.1", "lodash@4.17.15"]
        );
        assert_eq!(
            c.direct,
            Some(false),
            "isTransitive decides it; a transitive dep is not declared here"
        );
    }

    #[test]
    fn a_direct_dependency_is_marked_as_one() {
        let json = r#"{"vulnerabilities":[{"id":"X","packageName":"p","version":"1",
            "from":["app@1","p@1"],"isTransitive":false}]}"#;
        let c = parse(json).unwrap()[0]
            .component
            .clone()
            .expect("component");
        assert_eq!(c.direct, Some(true));
    }

    #[test]
    fn a_code_finding_carries_no_component_at_all() {
        let sarif = r#"{"runs":[{"tool":{"driver":{"rules":[]}},"results":[{"ruleId":"r",
            "locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.py"},
            "region":{"startLine":1}}}]}]}]}"#;
        assert!(
            parse(sarif).unwrap()[0].component.is_none(),
            "a SAST finding is about code, not a package"
        );
    }
}
