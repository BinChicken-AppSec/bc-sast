use appsec_thirdparty::ThirdPartyFinding;
use serde::Deserialize;

use crate::oauth2::{CachedToken, TokenCache};
use crate::retry::send_with_retry;

const PAGE_SIZE: u32 = 5000;
const MAX_PAGES: u32 = 1000;

#[derive(Debug, Clone)]
pub struct AikidoConfig {
    pub base_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub code_repo_id: i64,
}

impl AikidoConfig {
    pub fn new(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        code_repo_id: i64,
    ) -> Self {
        AikidoConfig {
            base_url: "https://app.aikido.dev".to_string(),
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            code_repo_id,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AikidoError {
    #[error("Aikido API request failed: {message}")]
    Request { message: String },
    #[error("Aikido API returned HTTP {status}: {message}")]
    Http { status: u16, message: String },
    #[error("failed to parse the Aikido issues export response: {message}")]
    Json { message: String },
}

pub struct AikidoClient {
    http: reqwest::Client,
    config: AikidoConfig,
    tokens: TokenCache,
}

impl AikidoClient {
    pub fn new(http: reqwest::Client, config: AikidoConfig) -> Self {
        AikidoClient {
            http,
            config,
            tokens: TokenCache::new(),
        }
    }

    pub async fn fetch_findings(&self) -> Result<Vec<ThirdPartyFinding>, AikidoError> {
        let mut all = Vec::new();
        for page in 0..MAX_PAGES {
            let body = self.fetch_page(page).await?;
            let (mut page_findings, raw_count) = appsec_thirdparty::aikido::parse_with_count(&body)
                .map_err(|message| AikidoError::Json { message })?;
            for finding in &mut page_findings {
                for origin in &mut finding.provider_origins {
                    origin.source = appsec_model::ProviderSource::Api;
                    origin.repository_id = Some(self.config.code_repo_id.to_string());
                }
            }
            all.append(&mut page_findings);
            if (raw_count as u32) < PAGE_SIZE {
                break;
            }
        }
        Ok(all)
    }

    async fn fetch_page(&self, page: u32) -> Result<String, AikidoError> {
        let token = self.access_token().await?;
        let url = format!("{}/api/public/v1/issues/export", self.config.base_url);
        let query = [
            ("format", "json".to_string()),
            ("filter_status", "open".to_string()),
            ("filter_code_repo_id", self.config.code_repo_id.to_string()),
            ("page", page.to_string()),
            ("per_page", PAGE_SIZE.to_string()),
        ];
        let resp = send_with_retry(|| self.http.get(&url).bearer_auth(&token).query(&query))
            .await
            .map_err(request_error)?;
        if !resp.status.is_success() {
            return Err(AikidoError::Http {
                status: resp.status.as_u16(),
                message: resp.body,
            });
        }
        Ok(resp.body)
    }

    pub(crate) async fn access_token(&self) -> Result<String, AikidoError> {
        let config = &self.config;
        let http = &self.http;
        self.tokens
            .get_or_refresh(|| async move {
                let url = format!("{}/api/oauth/token", config.base_url);
                let resp = send_with_retry(|| {
                    http.post(&url)
                        .basic_auth(&config.client_id, Some(&config.client_secret))
                        .form(&[("grant_type", "client_credentials")])
                })
                .await
                .map_err(request_error)?;
                if !resp.status.is_success() {
                    return Err(AikidoError::Http {
                        status: resp.status.as_u16(),
                        message: resp.body,
                    });
                }
                let parsed: TokenResponse = serde_json::from_str(&resp.body).map_err(json_error)?;
                Ok(CachedToken::new(
                    parsed.access_token,
                    std::time::Duration::from_secs(parsed.expires_in),
                ))
            })
            .await
    }
}

fn request_error(e: reqwest::Error) -> AikidoError {
    AikidoError::Request {
        message: e.to_string(),
    }
}

fn json_error(e: serde_json::Error) -> AikidoError {
    AikidoError::Json {
        message: e.to_string(),
    }
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{basic_auth, header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn config_for(server: &MockServer) -> AikidoConfig {
        let mut cfg = AikidoConfig::new("client-id", "client-secret", 42);
        cfg.base_url = server.uri();
        cfg
    }

    async fn mount_token(server: &MockServer) {
        Mock::given(method("POST"))
            .and(path("/api/oauth/token"))
            .and(basic_auth("client-id", "client-secret"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "tok-1",
                "expires_in": 3600,
                "token_type": "bearer"
            })))
            .expect(1)
            .mount(server)
            .await;
    }

    fn one_issue(id: i64) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "group_id": 1,
            "rule": "Hardcoded secret",
            "rule_id": "aik_sast_001",
            "type": "sast",
            "attack_surface": "backend",
            "status": "open",
            "severity": "high",
            "severity_score": 90,
            "affected_file": "src/config.rs",
            "start_line": 10,
            "end_line": 10,
            "cwe_classes": ["CWE-798"],
            "first_detected_at": 1700489005
        })
    }

    fn one_skipped_issue(id: i64) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "group_id": 2,
            "rule": "S3 bucket is public",
            "type": "cloud",
            "attack_surface": "cloud",
            "status": "open",
            "severity": "critical",
            "affected_file": null,
            "start_line": null,
            "end_line": null,
            "cwe_classes": null,
            "first_detected_at": 1700489005
        })
    }

    #[tokio::test]
    async fn fetch_findings_authenticates_then_fetches_a_single_short_page() {
        let server = MockServer::start().await;
        mount_token(&server).await;
        Mock::given(method("GET"))
            .and(path("/api/public/v1/issues/export"))
            .and(query_param("filter_code_repo_id", "42"))
            .and(query_param("filter_status", "open"))
            .and(query_param("format", "json"))
            .and(header("Authorization", "Bearer tok-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(vec![one_issue(1)]))
            .mount(&server)
            .await;

        let client = AikidoClient::new(reqwest::Client::new(), config_for(&server));
        let findings = client.fetch_findings().await.unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].vendor, "aikido");
    }

    #[tokio::test]
    async fn fetch_findings_tolerates_an_issue_with_explicit_null_lines() {
        let server = MockServer::start().await;
        mount_token(&server).await;
        Mock::given(method("GET"))
            .and(path("/api/public/v1/issues/export"))
            .respond_with(ResponseTemplate::new(200).set_body_json(vec![
                one_issue(1),
                serde_json::json!({
                    "id": 2,
                    "type": "open_source",
                    "rule": "Prototype Pollution",
                    "severity": "critical",
                    "affected_package": "minimist",
                    "affected_file": null,
                    "start_line": null,
                    "end_line": null,
                    "installed_version": "4.2.0",
                    "patched_versions": ["4.2.1"],
                    "cve_id": "CVE-2024-8385"
                }),
            ]))
            .mount(&server)
            .await;

        let client = AikidoClient::new(reqwest::Client::new(), config_for(&server));
        let findings = client.fetch_findings().await.unwrap();

        assert_eq!(findings.len(), 2);
        assert_eq!(findings[1].file, "minimist");
        assert_eq!(findings[1].line_start, 1);
        assert!(findings[1].description.contains("CVE-2024-8385"));
    }

    #[tokio::test]
    async fn fetch_findings_reuses_the_cached_token_across_pages() {
        let server = MockServer::start().await;
        mount_token(&server).await;
        let mut full_page: Vec<_> = (0..PAGE_SIZE - 1).map(|i| one_issue(i as i64)).collect();
        full_page.push(one_skipped_issue(PAGE_SIZE as i64));
        Mock::given(method("GET"))
            .and(path("/api/public/v1/issues/export"))
            .and(query_param("page", "0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&full_page))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/public/v1/issues/export"))
            .and(query_param("page", "1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(vec![one_issue(999999)]))
            .mount(&server)
            .await;

        let client = AikidoClient::new(reqwest::Client::new(), config_for(&server));
        let findings = client.fetch_findings().await.unwrap();

        assert_eq!(findings.len() as u32, PAGE_SIZE);
    }

    #[tokio::test]
    async fn fetch_findings_retries_a_rate_limited_export_page() {
        let server = MockServer::start().await;
        mount_token(&server).await;
        Mock::given(method("GET"))
            .and(path("/api/public/v1/issues/export"))
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("Retry-After", "0")
                    .set_body_string("You have reached the maximum number of calls per minute."),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/public/v1/issues/export"))
            .respond_with(ResponseTemplate::new(200).set_body_json(vec![one_issue(1)]))
            .mount(&server)
            .await;

        let client = AikidoClient::new(reqwest::Client::new(), config_for(&server));

        assert_eq!(client.fetch_findings().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn fetch_findings_propagates_a_token_endpoint_failure() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/oauth/token"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "error": "invalid_client",
                "error_description": "bad credentials"
            })))
            .mount(&server)
            .await;

        let client = AikidoClient::new(reqwest::Client::new(), config_for(&server));
        let err = client.fetch_findings().await.unwrap_err();

        assert!(matches!(err, AikidoError::Http { status: 401, .. }));
    }

    #[tokio::test]
    async fn fetch_findings_propagates_a_malformed_token_response() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/oauth/token"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
            .mount(&server)
            .await;

        let client = AikidoClient::new(reqwest::Client::new(), config_for(&server));
        let err = client.fetch_findings().await.unwrap_err();

        assert!(matches!(err, AikidoError::Json { .. }));
    }

    #[tokio::test]
    async fn fetch_findings_propagates_a_non_success_status_on_the_export_call() {
        let server = MockServer::start().await;
        mount_token(&server).await;
        Mock::given(method("GET"))
            .and(path("/api/public/v1/issues/export"))
            .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
            .mount(&server)
            .await;

        let client = AikidoClient::new(reqwest::Client::new(), config_for(&server));
        let err = client.fetch_findings().await.unwrap_err();

        assert!(matches!(err, AikidoError::Http { status: 500, .. }));
    }

    #[tokio::test]
    async fn fetch_findings_propagates_a_malformed_export_response() {
        let server = MockServer::start().await;
        mount_token(&server).await;
        Mock::given(method("GET"))
            .and(path("/api/public/v1/issues/export"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
            .mount(&server)
            .await;

        let client = AikidoClient::new(reqwest::Client::new(), config_for(&server));
        let err = client.fetch_findings().await.unwrap_err();

        assert!(matches!(err, AikidoError::Json { .. }));
    }

    #[tokio::test]
    async fn fetch_findings_propagates_a_transport_failure_on_the_token_call() {
        let mut cfg = AikidoConfig::new("id", "secret", 1);
        cfg.base_url = "http://127.0.0.1:1".to_string();
        let client = AikidoClient::new(reqwest::Client::new(), cfg);

        let err = client.fetch_findings().await.unwrap_err();

        assert!(matches!(err, AikidoError::Request { .. }));
    }

    #[tokio::test]
    async fn fetch_findings_returns_empty_when_the_repo_has_no_issues() {
        let server = MockServer::start().await;
        mount_token(&server).await;
        Mock::given(method("GET"))
            .and(path("/api/public/v1/issues/export"))
            .respond_with(ResponseTemplate::new(200).set_body_json(Vec::<serde_json::Value>::new()))
            .mount(&server)
            .await;

        let client = AikidoClient::new(reqwest::Client::new(), config_for(&server));
        let findings = client.fetch_findings().await.unwrap();

        assert!(findings.is_empty());
    }
}
