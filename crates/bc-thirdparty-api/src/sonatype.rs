//! Sonatype Lifecycle/IQ Server API client — resolves the latest report
//! for an operator-supplied application + stage, then fetches its raw
//! report and hands the response body straight to
//! `bc_thirdparty::sonatype::parse` (same JSON shape as the file-based
//! parser targets: `components[].securityData.securityIssues[]`), so no
//! new response DTOs are needed here.
//!
//! **Auth**: HTTP Basic — either a real username:password, or a
//! generated "user token" (`userCode`:`passCode` pair) substituted into
//! the same Basic Auth slot, Sonatype's own recommended approach for
//! CI/service accounts (confirmed, `help.sonatype.com`).
//!
//! **Branch is not modeled by this API at all** (confirmed — no
//! `?branch=` filter exists anywhere in the reporting API). Sonatype's
//! real axis is "stage" (`build`, `stage-release`, `release`, `operate`,
//! etc.) — whichever branch a CI job scanned just overwrites that
//! stage's own report. So [`SonatypeConfig::stage`] is what an operator
//! configures in place of a branch, matching how this vendor's own data
//! model actually works, not a literal branch name.
//!
//! **There is no `reportId` field** in the report listing, which is what
//! this client used to require — a `serde` type error on every real
//! response, so the vendor produced nothing at all. Sonatype's own
//! documented sample for
//! `GET /api/v2/reports/applications/{applicationInternalId}`
//! (`help.sonatype.com/en/report-rest-api.html`) is an array of entries
//! carrying `stage`, `applicationId`, `evaluationDate`,
//! `latestReportHtmlUrl`, `reportHtmlUrl`, `embeddableReportHtmlUrl`,
//! `reportPdfUrl` and `reportDataUrl` — and nothing else. The report id
//! exists only *inside* those URLs, e.g.
//! `"reportDataUrl": "api/v2/applications/Test123/reports/474ca07881554f8fbec168ec25d9616a"`,
//! so [`report_id_from_data_url`] takes the segment after `/reports/`.
//! The sibling `/history` endpoint documents the same field ending in
//! `/raw` (and only *there* does an id-shaped `policyEvaluationId`/`scanId`
//! pair appear), so the trailing `/raw` is stripped too and this client
//! works against either listing.
//!
//! `evaluationDate` is compared with [`crate::timestamp`], not as a
//! string: Sonatype's own samples carry real UTC offsets
//! (`"2015-01-16T13:14:32.139-05:00"`), which a lexical `max` mis-orders.
//!
//! **Flagged uncertain**: whether the canonical SaaS hostname is
//! `{tenant}.sonatype.app` or `{tenant}.iq.sonatype.app` (Sonatype's own
//! docs use both inconsistently) — low-risk here since [`SonatypeConfig::base_url`]
//! is always operator-supplied in full, including for self-hosted
//! on-prem instances (the common real-world case for this vendor).

use bc_thirdparty::ThirdPartyFinding;
use serde::Deserialize;

use crate::retry::send_with_retry;
use crate::timestamp::chronological_key;

#[derive(Debug, Clone)]
pub struct SonatypeConfig {
    pub base_url: String,
    pub username: String,
    pub password: String,
    /// The application's `publicId` (Sonatype's human-chosen, mutable
    /// identifier), not its internal immutable ID — the internal ID is
    /// resolved automatically via `GET /applications?publicId=...`.
    pub application_public_id: String,
    /// Defaults to `"build"`, Sonatype's own default CI-scan stage.
    pub stage: String,
}

impl SonatypeConfig {
    pub fn new(
        base_url: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
        application_public_id: impl Into<String>,
    ) -> Self {
        SonatypeConfig {
            base_url: base_url.into(),
            username: username.into(),
            password: password.into(),
            application_public_id: application_public_id.into(),
            stage: "build".to_string(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SonatypeError {
    #[error("Sonatype API request failed: {message}")]
    Request { message: String },
    #[error("Sonatype API returned HTTP {status}: {message}")]
    Http { status: u16, message: String },
    #[error("failed to parse Sonatype API response: {message}")]
    Json { message: String },
    #[error("no application found with publicId {public_id}")]
    ApplicationNotFound { public_id: String },
    #[error("no report found for application {public_id}, stage {stage}")]
    ReportNotFound { public_id: String, stage: String },
    #[error("could not derive a report id from reportDataUrl {report_data_url:?}")]
    ReportIdNotDerivable { report_data_url: String },
    #[error("failed to parse the raw report body: {message}")]
    ParseReport { message: String },
}

pub struct SonatypeClient {
    http: reqwest::Client,
    config: SonatypeConfig,
}

impl SonatypeClient {
    pub fn new(http: reqwest::Client, config: SonatypeConfig) -> Self {
        SonatypeClient { http, config }
    }

    pub async fn fetch_findings(&self) -> Result<Vec<ThirdPartyFinding>, SonatypeError> {
        let internal_id = self.resolve_application_id().await?;
        let report_id = self.resolve_latest_report_id(&internal_id).await?;
        let body = self.fetch_raw_report(&report_id).await?;
        bc_thirdparty::sonatype::parse(&body)
            .map_err(|message| SonatypeError::ParseReport { message })
    }

    async fn get(&self, url: &str) -> Result<String, SonatypeError> {
        let resp = send_with_retry(|| {
            self.http
                .get(url)
                .basic_auth(&self.config.username, Some(&self.config.password))
        })
        .await
        .map_err(request_error)?;
        if !resp.status.is_success() {
            return Err(SonatypeError::Http {
                status: resp.status.as_u16(),
                message: resp.body,
            });
        }
        Ok(resp.body)
    }

    async fn resolve_application_id(&self) -> Result<String, SonatypeError> {
        let url = format!(
            "{}/api/v2/applications?publicId={}",
            self.config.base_url, self.config.application_public_id
        );
        let text = self.get(&url).await?;
        let parsed: ApplicationsResponse = serde_json::from_str(&text).map_err(json_error)?;
        parsed
            .applications
            .into_iter()
            .next()
            .map(|a| a.id)
            .ok_or_else(|| SonatypeError::ApplicationNotFound {
                public_id: self.config.application_public_id.clone(),
            })
    }

    async fn resolve_latest_report_id(
        &self,
        internal_application_id: &str,
    ) -> Result<String, SonatypeError> {
        let url = format!(
            "{}/api/v2/reports/applications/{}",
            self.config.base_url, internal_application_id
        );
        let text = self.get(&url).await?;
        let reports: Vec<ReportSummary> = serde_json::from_str(&text).map_err(json_error)?;
        let latest = reports
            .into_iter()
            .filter(|r| r.stage == self.config.stage)
            .max_by_key(|r| chronological_key(&r.evaluation_date))
            .ok_or_else(|| SonatypeError::ReportNotFound {
                public_id: self.config.application_public_id.clone(),
                stage: self.config.stage.clone(),
            })?;
        report_id_from_data_url(&latest.report_data_url)
            .map(str::to_string)
            .ok_or(SonatypeError::ReportIdNotDerivable {
                report_data_url: latest.report_data_url,
            })
    }

    async fn fetch_raw_report(&self, report_id: &str) -> Result<String, SonatypeError> {
        let url = format!(
            "{}/api/v2/applications/{}/reports/{}/raw",
            self.config.base_url, self.config.application_public_id, report_id
        );
        self.get(&url).await
    }
}

#[derive(Debug, Default, Deserialize)]
struct ApplicationsResponse {
    #[serde(default)]
    applications: Vec<ApplicationSummary>,
}

#[derive(Debug, Deserialize)]
struct ApplicationSummary {
    id: String,
}

#[derive(Debug, Deserialize)]
struct ReportSummary {
    #[serde(default)]
    stage: String,
    #[serde(default, rename = "evaluationDate")]
    evaluation_date: String,
    #[serde(default, rename = "reportDataUrl")]
    report_data_url: String,
}

/// Extracts the report id embedded in a `reportDataUrl`. Handles both
/// documented forms — `api/v2/applications/{publicId}/reports/{reportId}`
/// (the report listing) and `.../reports/{reportId}/raw` (the `/history`
/// listing) — plus a query string, and tolerates the leading-slash and
/// fully-absolute variants a future IQ Server release might emit, since it
/// anchors on the `/reports/` segment rather than on position.
fn report_id_from_data_url(url: &str) -> Option<&str> {
    let after = url.split("/reports/").nth(1)?;
    let end = after.find(['/', '?']).unwrap_or(after.len());
    let id = &after[..end];
    if id.is_empty() {
        return None;
    }
    Some(id)
}

fn request_error(e: reqwest::Error) -> SonatypeError {
    SonatypeError::Request {
        message: e.to_string(),
    }
}

fn json_error(e: serde_json::Error) -> SonatypeError {
    SonatypeError::Json {
        message: e.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{basic_auth, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn config_for(server: &MockServer) -> SonatypeConfig {
        SonatypeConfig::new(server.uri(), "user", "pass", "my-app")
    }

    fn raw_report_body() -> serde_json::Value {
        serde_json::json!({
            "components": [{
                "packageUrl": "pkg:npm/lodash@4.17.15",
                "securityData": {
                    "securityIssues": [{"reference": "CVE-2020-8203", "severity": 9.8}]
                }
            }]
        })
    }

    async fn mount_happy_path(server: &MockServer) {
        Mock::given(method("GET"))
            .and(path("/api/v2/applications"))
            .and(query_param("publicId", "my-app"))
            .and(basic_auth("user", "pass"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "applications": [{"id": "internal-id-1", "publicId": "my-app"}]
            })))
            .mount(server)
            .await;
        // Every field name below is copied from Sonatype's own documented
        // sample response for this endpoint — in particular there is no
        // `reportId`, and `evaluationDate` carries a real UTC offset.
        Mock::given(method("GET"))
            .and(path("/api/v2/reports/applications/internal-id-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {
                    "stage": "build",
                    "applicationId": "internal-id-1",
                    // 2026-06-01T05:00:00Z — LATER than the entry below in
                    // real time, but EARLIER lexically.
                    "evaluationDate": "2026-06-01T00:00:00-05:00",
                    "latestReportHtmlUrl": "ui/links/application/my-app/latestReport/build",
                    "reportHtmlUrl": "ui/links/application/my-app/report/new-report",
                    "embeddableReportHtmlUrl": "ui/links/application/my-app/report/new-report/embeddable",
                    "reportPdfUrl": "ui/links/application/my-app/report/new-report/pdf",
                    "reportDataUrl": "api/v2/applications/my-app/reports/new-report"
                },
                {
                    "stage": "build",
                    "applicationId": "internal-id-1",
                    "evaluationDate": "2026-06-01T02:00:00+02:00",
                    "reportHtmlUrl": "ui/links/application/my-app/report/old-report",
                    "reportDataUrl": "api/v2/applications/my-app/reports/old-report"
                },
                {
                    "stage": "release",
                    "applicationId": "internal-id-1",
                    "evaluationDate": "2026-09-01T00:00:00Z",
                    "reportDataUrl": "api/v2/applications/my-app/reports/release-report"
                }
            ])))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v2/applications/my-app/reports/new-report/raw"))
            .respond_with(ResponseTemplate::new(200).set_body_json(raw_report_body()))
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn fetch_findings_resolves_app_then_latest_report_then_parses_it() {
        let server = MockServer::start().await;
        mount_happy_path(&server).await;

        let client = SonatypeClient::new(reqwest::Client::new(), config_for(&server));
        let findings = client.fetch_findings().await.unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].vendor, "sonatype");
        assert_eq!(findings[0].file, "pkg:npm/lodash@4.17.15");
    }

    #[tokio::test]
    async fn fetch_findings_picks_the_chronologically_most_recent_report_for_the_stage() {
        // The happy path mounts an OLDER "build" report, a NEWER "build"
        // report whose `evaluationDate` sorts EARLIER as a plain string
        // (different UTC offsets), and a DIFFERENT-stage "release" report.
        // Only the correct report's /raw mock exists, so a lexical compare
        // — or a wrong-stage pick — fails this loudly with a 404.
        let server = MockServer::start().await;
        mount_happy_path(&server).await;
        let client = SonatypeClient::new(reqwest::Client::new(), config_for(&server));
        assert!(client.fetch_findings().await.is_ok());
    }

    #[rstest::rstest]
    // The report-listing form.
    #[case(
        "api/v2/applications/Test123/reports/474ca07881554f8fbec168ec25d9616a",
        Some("474ca07881554f8fbec168ec25d9616a")
    )]
    // The /history-listing form, which ends in /raw.
    #[case(
        "api/v2/applications/MyApplicationID/reports/53a99dd8b58e4d819c0791a8087df62c/raw",
        Some("53a99dd8b58e4d819c0791a8087df62c")
    )]
    // Leading-slash and fully-absolute variants.
    #[case("/api/v2/applications/a/reports/r1", Some("r1"))]
    #[case(
        "https://iq.example.com/api/v2/applications/a/reports/r1/raw",
        Some("r1")
    )]
    // A query string is not part of the id.
    #[case(
        "api/v2/applications/a/reports/r1/raw?includeCustomSecurityVulnerabilityData=true",
        Some("r1")
    )]
    #[case("api/v2/applications/a/reports/r1?x=1", Some("r1"))]
    // Nothing derivable.
    #[case("", None)]
    #[case("ui/links/application/Test123/latestReport/build", None)]
    #[case("api/v2/applications/a/reports/", None)]
    fn report_id_derivation(#[case] url: &str, #[case] expected: Option<&str>) {
        assert_eq!(report_id_from_data_url(url), expected);
    }

    #[tokio::test]
    async fn fetch_findings_errors_when_the_report_data_url_carries_no_derivable_id() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v2/applications"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "applications": [{"id": "internal-id-1", "publicId": "my-app"}]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v2/reports/applications/internal-id-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"stage": "build", "evaluationDate": "2026-01-01T00:00:00Z",
                 "reportDataUrl": "ui/links/application/my-app/latestReport/build"}
            ])))
            .mount(&server)
            .await;

        let client = SonatypeClient::new(reqwest::Client::new(), config_for(&server));
        let err = client.fetch_findings().await.unwrap_err();

        assert!(matches!(err, SonatypeError::ReportIdNotDerivable { .. }));
    }

    #[tokio::test]
    async fn fetch_findings_retries_a_rate_limited_applications_call() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v2/applications"))
            .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "0"))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        mount_happy_path(&server).await;

        let client = SonatypeClient::new(reqwest::Client::new(), config_for(&server));

        assert!(client.fetch_findings().await.is_ok());
    }

    #[tokio::test]
    async fn fetch_findings_errors_when_the_application_is_not_found() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v2/applications"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "applications": []
            })))
            .mount(&server)
            .await;

        let client = SonatypeClient::new(reqwest::Client::new(), config_for(&server));
        let err = client.fetch_findings().await.unwrap_err();

        assert!(matches!(err, SonatypeError::ApplicationNotFound { .. }));
    }

    #[tokio::test]
    async fn fetch_findings_errors_when_no_report_matches_the_configured_stage() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v2/applications"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "applications": [{"id": "internal-id-1", "publicId": "my-app"}]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v2/reports/applications/internal-id-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"stage": "release", "evaluationDate": "2026-01-01T00:00:00Z",
                 "reportDataUrl": "api/v2/applications/my-app/reports/r1"}
            ])))
            .mount(&server)
            .await;

        let client = SonatypeClient::new(reqwest::Client::new(), config_for(&server));
        let err = client.fetch_findings().await.unwrap_err();

        assert!(matches!(err, SonatypeError::ReportNotFound { .. }));
    }

    #[tokio::test]
    async fn fetch_findings_propagates_a_non_success_status_on_the_applications_call() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v2/applications"))
            .respond_with(ResponseTemplate::new(401).set_body_string("unauthorized"))
            .mount(&server)
            .await;

        let client = SonatypeClient::new(reqwest::Client::new(), config_for(&server));
        let err = client.fetch_findings().await.unwrap_err();

        assert!(matches!(err, SonatypeError::Http { status: 401, .. }));
    }

    #[tokio::test]
    async fn fetch_findings_propagates_a_malformed_applications_response() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v2/applications"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
            .mount(&server)
            .await;

        let client = SonatypeClient::new(reqwest::Client::new(), config_for(&server));
        let err = client.fetch_findings().await.unwrap_err();

        assert!(matches!(err, SonatypeError::Json { .. }));
    }

    #[tokio::test]
    async fn fetch_findings_propagates_a_malformed_raw_report_body() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v2/applications"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "applications": [{"id": "internal-id-1", "publicId": "my-app"}]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v2/reports/applications/internal-id-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"stage": "build", "evaluationDate": "2026-01-01T00:00:00Z",
                 "reportDataUrl": "api/v2/applications/my-app/reports/r1/raw"}
            ])))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v2/applications/my-app/reports/r1/raw"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
            .mount(&server)
            .await;

        let client = SonatypeClient::new(reqwest::Client::new(), config_for(&server));
        let err = client.fetch_findings().await.unwrap_err();

        assert!(matches!(err, SonatypeError::ParseReport { .. }));
    }

    #[tokio::test]
    async fn fetch_findings_propagates_a_transport_failure() {
        let mut cfg = SonatypeConfig::new("http://127.0.0.1:1", "u", "p", "app");
        cfg.base_url = "http://127.0.0.1:1".to_string();
        let client = SonatypeClient::new(reqwest::Client::new(), cfg);

        let err = client.fetch_findings().await.unwrap_err();

        assert!(matches!(err, SonatypeError::Request { .. }));
    }
}
