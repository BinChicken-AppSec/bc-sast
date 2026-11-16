use serde::Deserialize;

use crate::{Severity, ThirdPartyFinding};

#[derive(Debug, Default, Deserialize)]
struct SemgrepReport {
    #[serde(default)]
    results: Vec<SemgrepResult>,
}

#[derive(Debug, Deserialize)]
struct SemgrepResult {
    check_id: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    start: SemgrepPos,
    #[serde(default)]
    end: SemgrepPos,
    #[serde(default)]
    extra: SemgrepExtra,
}

#[derive(Debug, Deserialize)]
struct SemgrepPos {
    #[serde(default = "default_line")]
    line: i64,
}

impl Default for SemgrepPos {
    fn default() -> Self {
        SemgrepPos {
            line: default_line(),
        }
    }
}

fn default_line() -> i64 {
    1
}

#[derive(Debug, Default, Deserialize)]
struct SemgrepExtra {
    #[serde(default)]
    message: String,
    #[serde(default)]
    severity: String,
    #[serde(default)]
    metadata: SemgrepMetadata,
    #[serde(default)]
    fingerprint: String,
    #[serde(default)]
    fix: String,
    #[serde(default)]
    is_ignored: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
struct SemgrepMetadata {
    #[serde(default)]
    cwe: Option<CweField>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum CweField {
    One(String),
    Many(Vec<String>),
}

impl CweField {
    fn first(&self) -> Option<&str> {
        match self {
            CweField::One(s) => Some(s.as_str()),
            CweField::Many(v) => v.first().map(String::as_str),
        }
    }
}

pub fn parse(text: &str) -> Result<Vec<ThirdPartyFinding>, String> {
    let report: SemgrepReport =
        serde_json::from_str(text).map_err(|e| format!("malformed Semgrep JSON: {e}"))?;

    Ok(report
        .results
        .into_iter()
        .enumerate()
        .filter(|(_, r)| !r.extra.is_ignored.unwrap_or(false))
        .map(|(idx, r)| {
            let cwe = r
                .extra
                .metadata
                .cwe
                .as_ref()
                .and_then(CweField::first)
                .map(extract_cwe_id);
            let external_id = if r.extra.fingerprint.is_empty() {
                format!("{}:{}:{}", r.check_id, r.path, idx)
            } else {
                r.extra.fingerprint
            };
            let description = if r.extra.message.is_empty() {
                format!("Semgrep rule {} matched.", r.check_id)
            } else {
                r.extra.message
            };
            ThirdPartyFinding {
                provider_origins: vec![appsec_model::ProviderOrigin {
                    provider: appsec_model::ProviderKind::Semgrep,
                    source: appsec_model::ProviderSource::File,
                    product: appsec_model::ProviderProduct::Sast,
                    ..Default::default()
                }],
                component: None,
                vendor: "semgrep",
                external_id,
                title: r.check_id,
                file: r.path,
                line_start: r.start.line,
                line_end: r.end.line,
                cwe,
                severity: parse_severity(&r.extra.severity),
                description,
                recommendation: r.extra.fix,
            }
        })
        .collect())
}

fn extract_cwe_id(raw: &str) -> String {
    let id_part = raw.split(':').next().unwrap_or(raw).trim();
    let stripped = id_part
        .strip_prefix("CWE-")
        .or_else(|| id_part.strip_prefix("cwe-"))
        .unwrap_or(id_part);
    format!("CWE-{stripped}")
}

fn parse_severity(raw: &str) -> Severity {
    match raw.trim().to_ascii_uppercase().as_str() {
        "CRITICAL" => Severity::Critical,
        "HIGH" | "ERROR" => Severity::High,
        "MEDIUM" | "WARNING" => Severity::Medium,
        "LOW" | "INFO" => Severity::Low,
        _ => Severity::Info,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_json() -> &'static str {
        r#"{
          "results": [
            {
              "check_id": "javascript.lang.security.audit.xss.direct-response-write",
              "path": "src/app.js",
              "start": {"line": 18, "col": 9},
              "end": {"line": 18, "col": 82},
              "extra": {
                "message": "Detected XSS.",
                "severity": "ERROR",
                "metadata": {"cwe": ["CWE-79: Improper Neutralization of Input"]},
                "fingerprint": "abcd1234",
                "fix": "res.send(escapeHtml(x))"
              }
            },
            {
              "check_id": "python.lang.best-practice.unused-var",
              "path": "src/util.py",
              "extra": {"severity": "INFO"}
            }
          ]
        }"#
    }

    #[test]
    fn parses_every_result() {
        assert_eq!(parse(sample_json()).unwrap().len(), 2);
    }

    #[test]
    fn maps_the_first_result_fully() {
        let findings = parse(sample_json()).unwrap();
        let f = &findings[0];
        assert_eq!(
            f.title,
            "javascript.lang.security.audit.xss.direct-response-write"
        );
        assert_eq!(f.file, "src/app.js");
        assert_eq!(f.line_start, 18);
        assert_eq!(f.line_end, 18);
        assert_eq!(f.cwe, Some("CWE-79".to_string()));
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.description, "Detected XSS.");
        assert_eq!(f.recommendation, "res.send(escapeHtml(x))");
        assert_eq!(f.external_id, "abcd1234");
    }

    #[test]
    fn a_result_with_no_fingerprint_synthesizes_a_stable_id() {
        let findings = parse(sample_json()).unwrap();
        assert!(findings[1]
            .external_id
            .contains("python.lang.best-practice.unused-var"));
    }

    #[test]
    fn a_result_with_no_message_gets_a_synthesized_description() {
        let findings = parse(sample_json()).unwrap();
        assert!(findings[1]
            .description
            .contains("python.lang.best-practice.unused-var"));
    }

    #[test]
    fn missing_start_end_default_line_to_one() {
        let findings = parse(sample_json()).unwrap();
        assert_eq!(findings[1].line_start, 1);
        assert_eq!(findings[1].line_end, 1);
    }

    #[test]
    fn info_severity_maps_to_low() {
        let findings = parse(sample_json()).unwrap();
        assert_eq!(findings[1].severity, Severity::Low);
    }

    #[test]
    fn a_result_with_no_cwe_yields_none() {
        let findings = parse(sample_json()).unwrap();
        assert_eq!(findings[1].cwe, None);
    }

    #[rstest::rstest]
    #[case("CRITICAL", Severity::Critical)]
    #[case("HIGH", Severity::High)]
    #[case("MEDIUM", Severity::Medium)]
    #[case("LOW", Severity::Low)]
    #[case("ERROR", Severity::High)]
    #[case("WARNING", Severity::Medium)]
    #[case("INFO", Severity::Low)]
    #[case("EXPERIMENT", Severity::Info)]
    #[case("INVENTORY", Severity::Info)]
    #[case("WEIRD", Severity::Info)]
    #[case("critical", Severity::Critical)]
    fn severity_mapping_covers_both_semgrep_scales(#[case] raw: &str, #[case] expected: Severity) {
        let json =
            format!(r#"{{"results": [{{"check_id": "x", "extra": {{"severity": "{raw}"}}}}]}}"#);
        assert_eq!(parse(&json).unwrap()[0].severity, expected);
    }

    #[test]
    fn a_nosemgrep_suppressed_result_is_skipped() {
        let json = r#"{"results": [
            {"check_id": "kept", "extra": {"severity": "HIGH"}},
            {"check_id": "suppressed", "extra": {"severity": "HIGH", "is_ignored": true}}
        ]}"#;
        let findings = parse(json).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "kept");
    }

    #[test]
    fn an_explicitly_not_ignored_result_is_kept() {
        let json = r#"{"results": [{"check_id": "kept", "extra": {"is_ignored": false}}]}"#;
        assert_eq!(parse(json).unwrap().len(), 1);
    }

    #[test]
    fn skipping_a_suppressed_result_does_not_shift_the_ids_of_later_results() {
        let json = r#"{"results": [
            {"check_id": "a", "path": "a.py", "extra": {"is_ignored": true}},
            {"check_id": "b", "path": "b.py", "extra": {}}
        ]}"#;
        let findings = parse(json).unwrap();
        assert_eq!(findings[0].external_id, "b:b.py:1");
    }

    #[test]
    fn a_custom_rules_bare_string_cwe_is_accepted() {
        let json =
            r#"{"results": [{"check_id": "x", "extra": {"metadata": {"cwe": "CWE-89: SQLi"}}}]}"#;
        let findings = parse(json).unwrap();
        assert_eq!(findings[0].cwe, Some("CWE-89".to_string()));
    }

    #[test]
    fn a_bare_string_cwe_does_not_abort_the_rest_of_the_file() {
        let json = r#"{"results": [
            {"check_id": "custom", "extra": {"metadata": {"cwe": "CWE-89"}}},
            {"check_id": "registry", "extra": {"metadata": {"cwe": ["CWE-79: XSS"]}}}
        ]}"#;
        let findings = parse(json).unwrap();
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[1].cwe, Some("CWE-79".to_string()));
    }

    #[test]
    fn a_null_cwe_yields_none() {
        let json = r#"{"results": [{"check_id": "x", "extra": {"metadata": {"cwe": null}}}]}"#;
        assert_eq!(parse(json).unwrap()[0].cwe, None);
    }

    #[test]
    fn an_empty_cwe_list_yields_none() {
        let json = r#"{"results": [{"check_id": "x", "extra": {"metadata": {"cwe": []}}}]}"#;
        assert_eq!(parse(json).unwrap()[0].cwe, None);
    }

    #[test]
    fn empty_results_yields_no_findings() {
        assert!(parse(r#"{"results": []}"#).unwrap().is_empty());
    }

    #[test]
    fn missing_results_key_yields_no_findings() {
        assert!(parse("{}").unwrap().is_empty());
    }

    #[test]
    fn malformed_json_is_an_error() {
        assert!(parse("not json").is_err());
    }

    #[test]
    fn a_bare_numeric_cwe_without_a_colon_is_still_extracted() {
        let json =
            r#"{"results": [{"check_id": "x", "extra": {"metadata": {"cwe": ["CWE-89"]}}}]}"#;
        let findings = parse(json).unwrap();
        assert_eq!(findings[0].cwe, Some("CWE-89".to_string()));
    }

    #[test]
    fn a_cwe_with_no_prefix_at_all_still_gets_normalized() {
        let json = r#"{"results": [{"check_id": "x", "extra": {"metadata": {"cwe": ["89"]}}}]}"#;
        let findings = parse(json).unwrap();
        assert_eq!(findings[0].cwe, Some("CWE-89".to_string()));
    }

    #[test]
    fn a_lowercase_cwe_prefix_is_not_double_prefixed() {
        let json =
            r#"{"results": [{"check_id": "x", "extra": {"metadata": {"cwe": ["cwe-79: XSS"]}}}]}"#;
        let findings = parse(json).unwrap();
        assert_eq!(findings[0].cwe, Some("CWE-79".to_string()));
    }
}
