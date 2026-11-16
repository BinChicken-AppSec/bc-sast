use appsec_model::{
    ProviderKind, ProviderNativeIds, ProviderOrigin, ProviderProduct, ProviderSource,
};
use appsec_thirdparty::{Severity, ThirdPartyFinding};
use serde::Deserialize;

use crate::retry::send_with_retry;

const DEFAULT_BASE_URL: &str = "https://semgrep.dev/api/v1";
const PAGE_SIZE: u32 = 100;
const MAX_PAGES: u32 = 1000;

#[derive(Clone)]
pub struct SemgrepConfig {
    pub base_url: String,
    pub token: String,
    pub deployment_slug: String,
    pub repo: String,
    pub branch: Option<String>,
}

impl std::fmt::Debug for SemgrepConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SemgrepConfig")
            .field("base_url", &self.base_url)
            .field("token", &"<redacted>")
            .field("deployment_slug", &self.deployment_slug)
            .field("repo", &self.repo)
            .field("branch", &self.branch)
            .finish()
    }
}

impl SemgrepConfig {
    pub fn new(
        token: impl Into<String>,
        deployment_slug: impl Into<String>,
        repo: impl Into<String>,
    ) -> Self {
        SemgrepConfig {
            base_url: DEFAULT_BASE_URL.to_string(),
            token: token.into(),
            deployment_slug: deployment_slug.into(),
            repo: repo.into(),
            branch: None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SemgrepError {
    #[error("Semgrep API request failed: {message}")]
    Request { message: String },
    #[error("Semgrep API returned HTTP {status}: {message}")]
    Http { status: u16, message: String },
    #[error("failed to parse Semgrep API response: {message}")]
    Json { message: String },
}

pub struct SemgrepClient {
    http: reqwest::Client,
    config: SemgrepConfig,
}

impl SemgrepClient {
    pub fn new(http: reqwest::Client, config: SemgrepConfig) -> Self {
        SemgrepClient { http, config }
    }

    pub async fn fetch_findings(&self) -> Result<Vec<ThirdPartyFinding>, SemgrepError> {
        let mut all = Vec::new();
        for page in 0..MAX_PAGES {
            let response = self.fetch_page(page).await?;
            let count = response.findings.len();
            all.extend(response.findings.iter().map(|f| {
                let mut finding = to_third_party_finding(f);
                for origin in &mut finding.provider_origins {
                    origin.tenant_id = Some(self.config.deployment_slug.clone());
                    origin.repository_name = Some(self.config.repo.clone());
                }
                finding
            }));
            if count < PAGE_SIZE as usize {
                break;
            }
        }
        Ok(all)
    }

    async fn fetch_page(&self, page: u32) -> Result<FindingsResponse, SemgrepError> {
        let url = format!(
            "{}/deployments/{}/findings",
            self.config.base_url, self.config.deployment_slug
        );
        let mut query: Vec<(&str, String)> = vec![
            ("repos", self.config.repo.clone()),
            ("status", "open".to_string()),
            ("page", page.to_string()),
            ("page_size", PAGE_SIZE.to_string()),
        ];
        match &self.config.branch {
            Some(branch) => query.push(("ref", format!("refs/heads/{branch}"))),
            None => query.push(("dedup", "true".to_string())),
        }

        let resp = send_with_retry(|| {
            self.http
                .get(&url)
                .bearer_auth(&self.config.token)
                .query(&query)
        })
        .await
        .map_err(request_error)?;
        if !resp.status.is_success() {
            return Err(SemgrepError::Http {
                status: resp.status.as_u16(),
                message: resp.body,
            });
        }
        serde_json::from_str(&resp.body).map_err(|e| SemgrepError::Json {
            message: e.to_string(),
        })
    }
}

fn request_error(e: reqwest::Error) -> SemgrepError {
    SemgrepError::Request {
        message: e.to_string(),
    }
}

#[derive(Debug, Default, Deserialize)]
struct FindingsResponse {
    #[serde(default)]
    findings: Vec<SastFinding>,
}

#[derive(Debug, Default, Deserialize)]
struct SastFinding {
    #[serde(default, rename = "ref")]
    git_ref: Option<String>,
    #[serde(default)]
    triage_state: Option<String>,
    #[serde(default)]
    id: Option<i64>,
    #[serde(default)]
    match_based_id: String,
    #[serde(default)]
    rule: FindingRule,
    #[serde(default)]
    severity: String,
    #[serde(default)]
    location: FindingLocation,
}

#[derive(Debug, Default, Deserialize)]
struct FindingRule {
    #[serde(default)]
    name: String,
    #[serde(default)]
    message: String,
    #[serde(default)]
    cwe_names: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct FindingLocation {
    #[serde(default)]
    file_path: String,
    #[serde(default = "default_line")]
    line: i64,
    #[serde(default = "default_line")]
    end_line: i64,
}

impl Default for FindingLocation {
    fn default() -> Self {
        FindingLocation {
            file_path: String::new(),
            line: default_line(),
            end_line: default_line(),
        }
    }
}

fn default_line() -> i64 {
    1
}

fn to_third_party_finding(f: &SastFinding) -> ThirdPartyFinding {
    let title = if f.rule.name.is_empty() {
        "Semgrep finding".to_string()
    } else {
        f.rule.name.clone()
    };
    let description = if f.rule.message.is_empty() {
        format!("Semgrep rule {title} matched.")
    } else {
        f.rule.message.clone()
    };
    ThirdPartyFinding {
        component: None,
        provider_origins: vec![ProviderOrigin {
            provider: ProviderKind::Semgrep,
            product: ProviderProduct::Sast,
            source: ProviderSource::Api,
            native_ids: ProviderNativeIds {
                issue_id: f.id.map(|v| v.to_string()),
                match_based_id: (!f.match_based_id.is_empty()).then(|| f.match_based_id.clone()),
                ..Default::default()
            },
            git_ref: f.git_ref.clone(),
            state: f.triage_state.clone(),
            severity: Some(f.severity.clone()),
            ..Default::default()
        }],
        vendor: "semgrep",
        external_id: external_id(f, &title),
        title: title.clone(),
        file: f.location.file_path.clone(),
        line_start: f.location.line,
        line_end: f.location.end_line,
        cwe: f.rule.cwe_names.first().map(|s| extract_cwe_id(s)),
        severity: parse_severity(&f.severity),
        description,
        recommendation: String::new(),
    }
}

fn external_id(f: &SastFinding, title: &str) -> String {
    if !f.match_based_id.is_empty() {
        return f.match_based_id.clone();
    }
    match f.id {
        Some(id) => id.to_string(),
        None => format!("{title}:{}:{}", f.location.file_path, f.location.line),
    }
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
    use wiremock::matchers::{header, method, path, query_param, query_param_is_missing};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn config_for(server: &MockServer) -> SemgrepConfig {
        let mut cfg = SemgrepConfig::new("test-token", "my-deployment", "myorg/myrepo");
        cfg.base_url = server.uri();
        cfg
    }

    fn one_finding_page(count: usize) -> serde_json::Value {
        let findings: Vec<_> = (0..count)
            .map(|i| {
                serde_json::json!({
                    "id": 1000 + i as i64,
                    "match_based_id": format!("0f8c79a6f7e0ff2f908ff5bc366ae1548465069bae889_{i}"),
                    "syntactic_id": "440eeface888e78afceac3dc7d4cc2cf",
                    "ref": "refs/heads/main",
                    "state": "unresolved",
                    "status": "open",
                    "triage_state": "untriaged",
                    "repository": {"name": "myorg/myrepo"},
                    "rule": {
                        "name": "python.lang.security.sqli",
                        "message": "SQL injection risk.",
                        "confidence": "high",
                        "category": "security",
                        "cwe_names": ["CWE-89: Improper Neutralization of Special Elements used in an SQL Command"]
                    },
                    "severity": "high",
                    "location": {"file_path": "app.py", "line": 10, "column": 8, "end_line": 12, "end_column": 16}
                })
            })
            .collect();
        serde_json::json!({"findings": findings})
    }

    #[tokio::test]
    async fn fetch_findings_maps_a_single_page_result() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/deployments/my-deployment/findings"))
            .and(header("Authorization", "Bearer test-token"))
            .and(query_param("repos", "myorg/myrepo"))
            .and(query_param("status", "open"))
            .and(query_param("page", "0"))
            .and(query_param("dedup", "true"))
            .respond_with(ResponseTemplate::new(200).set_body_json(one_finding_page(1)))
            .mount(&server)
            .await;

        let client = SemgrepClient::new(reqwest::Client::new(), config_for(&server));
        let findings = client.fetch_findings().await.unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].vendor, "semgrep");
        assert_eq!(
            findings[0].external_id,
            "0f8c79a6f7e0ff2f908ff5bc366ae1548465069bae889_0"
        );
        assert_eq!(findings[0].title, "python.lang.security.sqli");
        assert_eq!(findings[0].file, "app.py");
        assert_eq!(findings[0].line_start, 10);
        assert_eq!(findings[0].line_end, 12);
        assert_eq!(findings[0].cwe, Some("CWE-89".to_string()));
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].description, "SQL injection risk.");
    }

    #[tokio::test]
    async fn fetch_findings_sends_the_branch_ref_filter_and_no_dedup_when_a_branch_is_set() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/deployments/my-deployment/findings"))
            .and(query_param("ref", "refs/heads/main"))
            .and(query_param_is_missing("dedup"))
            .respond_with(ResponseTemplate::new(200).set_body_json(one_finding_page(0)))
            .mount(&server)
            .await;

        let mut cfg = config_for(&server);
        cfg.branch = Some("main".to_string());
        let client = SemgrepClient::new(reqwest::Client::new(), cfg);
        client.fetch_findings().await.unwrap();
    }

    #[tokio::test]
    async fn fetch_findings_prefers_the_numeric_id_when_no_match_based_id_is_present() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/deployments/my-deployment/findings"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "findings": [{"id": 1234567, "severity": "low", "rule": {"name": "r"}}]
            })))
            .mount(&server)
            .await;

        let client = SemgrepClient::new(reqwest::Client::new(), config_for(&server));
        let findings = client.fetch_findings().await.unwrap();

        assert_eq!(findings[0].external_id, "1234567");
    }

    #[tokio::test]
    async fn fetch_findings_retries_a_rate_limited_page_rather_than_failing_the_vendor() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/deployments/my-deployment/findings"))
            .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "0"))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/deployments/my-deployment/findings"))
            .respond_with(ResponseTemplate::new(200).set_body_json(one_finding_page(1)))
            .mount(&server)
            .await;

        let client = SemgrepClient::new(reqwest::Client::new(), config_for(&server));
        let findings = client.fetch_findings().await.unwrap();

        assert_eq!(findings.len(), 1);
    }

    #[tokio::test]
    async fn fetch_findings_paginates_across_a_full_page_boundary() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/deployments/my-deployment/findings"))
            .and(query_param("page", "0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(one_finding_page(100)))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/deployments/my-deployment/findings"))
            .and(query_param("page", "1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(one_finding_page(1)))
            .mount(&server)
            .await;

        let client = SemgrepClient::new(reqwest::Client::new(), config_for(&server));
        let findings = client.fetch_findings().await.unwrap();

        assert_eq!(findings.len(), 101);
    }

    #[tokio::test]
    async fn fetch_findings_stops_at_a_partial_page() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/deployments/my-deployment/findings"))
            .respond_with(ResponseTemplate::new(200).set_body_json(one_finding_page(3)))
            .mount(&server)
            .await;

        let client = SemgrepClient::new(reqwest::Client::new(), config_for(&server));
        let findings = client.fetch_findings().await.unwrap();

        assert_eq!(findings.len(), 3);
    }

    #[tokio::test]
    async fn fetch_findings_propagates_a_non_success_status() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/deployments/my-deployment/findings"))
            .respond_with(ResponseTemplate::new(401).set_body_string("unauthorized"))
            .mount(&server)
            .await;

        let client = SemgrepClient::new(reqwest::Client::new(), config_for(&server));
        let err = client.fetch_findings().await.unwrap_err();

        assert!(matches!(err, SemgrepError::Http { status: 401, .. }));
    }

    #[tokio::test]
    async fn fetch_findings_propagates_a_malformed_response_body() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/deployments/my-deployment/findings"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
            .mount(&server)
            .await;

        let client = SemgrepClient::new(reqwest::Client::new(), config_for(&server));
        let err = client.fetch_findings().await.unwrap_err();

        assert!(matches!(err, SemgrepError::Json { .. }));
    }

    #[tokio::test]
    async fn fetch_findings_propagates_a_transport_failure() {
        let mut cfg = SemgrepConfig::new("t", "d", "o/r");
        cfg.base_url = "http://127.0.0.1:1".to_string();
        let client = SemgrepClient::new(reqwest::Client::new(), cfg);

        let err = client.fetch_findings().await.unwrap_err();

        assert!(matches!(err, SemgrepError::Request { .. }));
    }

    fn bare_finding() -> SastFinding {
        SastFinding {
            id: Some(1),
            severity: "low".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn a_finding_with_no_rule_name_falls_back_to_a_generic_title() {
        let tpf = to_third_party_finding(&bare_finding());
        assert_eq!(tpf.title, "Semgrep finding");
        assert!(tpf.description.contains("Semgrep finding"));
    }

    #[test]
    fn a_finding_with_no_cwe_names_yields_none() {
        assert_eq!(to_third_party_finding(&bare_finding()).cwe, None);
    }

    #[test]
    fn missing_location_defaults_line_to_one() {
        let tpf = to_third_party_finding(&bare_finding());
        assert_eq!(tpf.line_start, 1);
        assert_eq!(tpf.line_end, 1);
    }

    #[test]
    fn a_finding_with_neither_a_match_based_id_nor_a_numeric_id_gets_a_synthesized_one() {
        let f = SastFinding {
            id: None,
            rule: FindingRule {
                name: "rules.no-ids".to_string(),
                ..Default::default()
            },
            location: FindingLocation {
                file_path: "src/app.py".to_string(),
                line: 7,
                end_line: 9,
            },
            ..Default::default()
        };
        assert_eq!(
            to_third_party_finding(&f).external_id,
            "rules.no-ids:src/app.py:7"
        );
    }

    #[rstest::rstest]
    #[case("critical", Severity::Critical)]
    #[case("high", Severity::High)]
    #[case("medium", Severity::Medium)]
    #[case("low", Severity::Low)]
    #[case("weird", Severity::Info)]
    fn severity_mapping(#[case] raw: &str, #[case] expected: Severity) {
        assert_eq!(parse_severity(raw), expected);
    }

    #[test]
    fn extract_cwe_id_strips_the_descriptive_suffix() {
        assert_eq!(extract_cwe_id("CWE-89: Improper Neutralization"), "CWE-89");
    }

    #[test]
    fn extract_cwe_id_handles_a_bare_number() {
        assert_eq!(extract_cwe_id("89"), "CWE-89");
    }

    #[test]
    fn extract_cwe_id_does_not_double_prefix_a_lowercase_cwe() {
        assert_eq!(extract_cwe_id("cwe-79: XSS"), "CWE-79");
    }
}

#[cfg(test)]
mod provenance_tests {
    use super::*;
    #[test]
    fn native_identity_is_preserved_without_report_id_fallback() {
        let raw: SastFinding = serde_json::from_value(serde_json::json!({"id":123,"match_based_id":"fingerprint","ref":"refs/heads/develop","triage_state":"untriaged","severity":"high"})).unwrap();
        let finding = to_third_party_finding(&raw);
        let origin = &finding.provider_origins[0];
        assert_eq!(origin.native_ids.issue_id.as_deref(), Some("123"));
        assert_eq!(
            origin.native_ids.match_based_id.as_deref(),
            Some("fingerprint")
        );
        assert_eq!(origin.git_ref.as_deref(), Some("refs/heads/develop"));
        assert!(origin.revision.is_none());
        let missing = to_third_party_finding(&SastFinding::default());
        assert!(missing.provider_origins[0].native_ids.issue_id.is_none());
    }

    #[test]
    fn debug_redacts_the_token_but_keeps_the_rest() {
        let shown = format!(
            "{:?}",
            SemgrepConfig::new("sup3r-s3cret-cred-do-not-log", "slug", "own/repo")
        );
        assert!(
            !shown.contains("sup3r-s3cret-cred-do-not-log"),
            "the token reached a Debug rendering: {shown}"
        );
        assert!(shown.contains("<redacted>"), "{shown}");
        assert!(shown.contains("slug"), "{shown}");
        assert!(shown.contains("SemgrepConfig"), "{shown}");
    }
}
