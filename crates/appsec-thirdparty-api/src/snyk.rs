use appsec_model::{
    ProviderKind, ProviderNativeIds, ProviderOrigin, ProviderProduct, ProviderSource,
};
use appsec_thirdparty::{Severity, ThirdPartyFinding};
use serde::Deserialize;

use crate::retry::send_with_retry;

const DEFAULT_BASE_URL: &str = "https://api.snyk.io/rest";
const DEFAULT_API_VERSION: &str = "2024-10-15";
const PAGE_LIMIT: u32 = 100;
const MAX_PAGES: u32 = 1000;

const SKIPPED_ISSUE_TYPES: [&str; 3] = ["license", "config", "cloud"];

#[derive(Clone)]
pub struct SnykConfig {
    pub base_url: String,
    pub token: String,
    pub api_version: String,
    pub org_id: String,
    pub project_id: String,
}

impl std::fmt::Debug for SnykConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnykConfig")
            .field("base_url", &self.base_url)
            .field("token", &"<redacted>")
            .field("api_version", &self.api_version)
            .field("org_id", &self.org_id)
            .field("project_id", &self.project_id)
            .finish()
    }
}

impl SnykConfig {
    pub fn new(
        token: impl Into<String>,
        org_id: impl Into<String>,
        project_id: impl Into<String>,
    ) -> Self {
        SnykConfig {
            base_url: DEFAULT_BASE_URL.to_string(),
            token: token.into(),
            api_version: DEFAULT_API_VERSION.to_string(),
            org_id: org_id.into(),
            project_id: project_id.into(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SnykError {
    #[error("Snyk API request failed: {message}")]
    Request { message: String },
    #[error("Snyk API returned HTTP {status}: {message}")]
    Http { status: u16, message: String },
    #[error("failed to parse Snyk API response: {message}")]
    Json { message: String },
}

pub struct SnykClient {
    http: reqwest::Client,
    config: SnykConfig,
}

impl SnykClient {
    pub fn new(http: reqwest::Client, config: SnykConfig) -> Self {
        SnykClient { http, config }
    }

    pub async fn fetch_findings(&self) -> Result<Vec<ThirdPartyFinding>, SnykError> {
        let mut all = Vec::new();
        let mut url = self.first_page_url();
        for _ in 0..MAX_PAGES {
            let page = self.fetch_url(&url).await?;
            all.extend(
                page.data
                    .iter()
                    .filter(|issue| !issue.is_skipped_type())
                    .map(|issue| {
                        let mut finding = to_third_party_finding(issue);
                        for origin in &mut finding.provider_origins {
                            origin.tenant_id = Some(self.config.org_id.clone());
                            origin.project_id = Some(self.config.project_id.clone());
                        }
                        finding
                    }),
            );
            match page.links.and_then(|l| l.next) {
                Some(next) if !next.href().is_empty() => {
                    url = resolve_next_url(&self.config.base_url, next.href());
                }
                _ => break,
            }
        }
        Ok(all)
    }

    fn first_page_url(&self) -> String {
        format!(
            "{}/orgs/{}/issues?version={}&scan_item.id={}&scan_item.type=project\
             &status=open&ignored=false&limit={}",
            self.config.base_url,
            self.config.org_id,
            self.config.api_version,
            self.config.project_id,
            PAGE_LIMIT
        )
    }

    async fn fetch_url(&self, url: &str) -> Result<IssuesResponse, SnykError> {
        let resp = send_with_retry(|| {
            self.http
                .get(url)
                .header("Authorization", format!("token {}", self.config.token))
        })
        .await
        .map_err(request_error)?;
        if !resp.status.is_success() {
            return Err(SnykError::Http {
                status: resp.status.as_u16(),
                message: resp.body,
            });
        }
        serde_json::from_str(&resp.body).map_err(|e| SnykError::Json {
            message: e.to_string(),
        })
    }
}

fn resolve_next_url(base_url: &str, next: &str) -> String {
    if next.starts_with("http://") || next.starts_with("https://") {
        return next.to_string();
    }
    let base = base_url.trim_end_matches('/');
    if next.starts_with("/rest/") {
        return format!("{}{}", origin_of(base), next);
    }
    format!("{base}/{}", next.trim_start_matches('/'))
}

fn origin_of(base_url: &str) -> &str {
    let after_scheme = match base_url.find("://") {
        Some(index) => index + 3,
        None => 0,
    };
    match base_url[after_scheme..].find('/') {
        Some(index) => &base_url[..after_scheme + index],
        None => base_url,
    }
}

fn request_error(e: reqwest::Error) -> SnykError {
    SnykError::Request {
        message: e.to_string(),
    }
}

#[derive(Debug, Deserialize)]
struct IssuesResponse {
    #[serde(default)]
    data: Vec<Issue>,
    #[serde(default)]
    links: Option<PaginatedLinks>,
}

#[derive(Debug, Default, Deserialize)]
struct PaginatedLinks {
    #[serde(default)]
    next: Option<LinkProperty>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum LinkProperty {
    Url(String),
    Object { href: String },
}

impl LinkProperty {
    fn href(&self) -> &str {
        match self {
            LinkProperty::Url(url) => url,
            LinkProperty::Object { href } => href,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
struct Issue {
    #[serde(default)]
    id: String,
    #[serde(default)]
    attributes: IssueAttributes,
}

impl Issue {
    fn is_skipped_type(&self) -> bool {
        SKIPPED_ISSUE_TYPES
            .iter()
            .any(|t| self.attributes.issue_type.eq_ignore_ascii_case(t))
    }
}

#[derive(Debug, Default, Deserialize)]
struct IssueAttributes {
    #[serde(default)]
    key_asset: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    key: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    effective_severity_level: String,
    #[serde(default, rename = "type")]
    issue_type: String,
    #[serde(default)]
    classes: Vec<IssueClass>,
    #[serde(default)]
    problems: Vec<Problem>,
    #[serde(default)]
    coordinates: Vec<Coordinate>,
}

#[derive(Debug, Deserialize)]
struct IssueClass {
    id: String,
    #[serde(default)]
    source: String,
}

#[derive(Debug, Deserialize)]
struct Problem {
    #[serde(default)]
    id: String,
}

fn component_of(attrs: &IssueAttributes) -> Option<appsec_model::ComponentRef> {
    let dependency = attrs
        .coordinates
        .iter()
        .flat_map(|c| &c.representations)
        .filter_map(|r| r.dependency.as_ref())
        .find(|d| !d.package_name.is_empty())?;
    let cves: Vec<String> = attrs
        .problems
        .iter()
        .map(|p| p.id.clone())
        .filter(|id| id.starts_with("CVE-"))
        .collect();
    Some(appsec_model::ComponentRef {
        name: dependency.package_name.clone(),
        version: dependency.package_version.clone(),
        purl: None,
        cves,
        fixed_in: Vec::new(),
        dependency_path: Vec::new(),
        direct: None,
    })
}

#[derive(Debug, Default, Deserialize)]
struct Coordinate {
    #[serde(default)]
    representations: Vec<Representation>,
}

#[derive(Debug, Default, Deserialize)]
struct Representation {
    #[serde(default, rename = "sourceLocation")]
    source_location: Option<SourceLocation>,
    #[serde(default)]
    dependency: Option<Dependency>,
}

#[derive(Debug, Deserialize)]
struct SourceLocation {
    #[serde(default)]
    file: String,
    #[serde(default)]
    region: Option<Region>,
}

#[derive(Debug, Deserialize)]
struct Region {
    #[serde(default)]
    start: Option<Point>,
    #[serde(default)]
    end: Option<Point>,
}

#[derive(Debug, Deserialize)]
struct Point {
    #[serde(default = "default_line")]
    line: i64,
}

fn default_line() -> i64 {
    1
}

#[derive(Debug, Deserialize)]
struct Dependency {
    #[serde(default)]
    package_name: String,
    #[serde(default)]
    package_version: String,
}

struct Location {
    file: String,
    line_start: i64,
    line_end: i64,
}

fn locate(attrs: &IssueAttributes) -> Option<Location> {
    let representations = || attrs.coordinates.iter().flat_map(|c| &c.representations);

    for source_location in representations().filter_map(|r| r.source_location.as_ref()) {
        if !source_location.file.is_empty() {
            let start = source_location
                .region
                .as_ref()
                .and_then(|r| r.start.as_ref())
                .map_or(1, |p| p.line);
            let end = source_location
                .region
                .as_ref()
                .and_then(|r| r.end.as_ref())
                .map_or(start, |p| p.line);
            return Some(Location {
                file: source_location.file.clone(),
                line_start: start,
                line_end: end,
            });
        }
    }
    for dependency in representations().filter_map(|r| r.dependency.as_ref()) {
        if !dependency.package_name.is_empty() {
            let file = if dependency.package_version.is_empty() {
                dependency.package_name.clone()
            } else {
                format!("{}@{}", dependency.package_name, dependency.package_version)
            };
            return Some(Location {
                file,
                line_start: 1,
                line_end: 1,
            });
        }
    }
    None
}

fn to_third_party_finding(issue: &Issue) -> ThirdPartyFinding {
    let title = if issue.attributes.title.is_empty() {
        issue.attributes.key.clone()
    } else {
        issue.attributes.title.clone()
    };
    let location = locate(&issue.attributes).unwrap_or_else(|| Location {
        file: if issue.attributes.key.is_empty() {
            title.clone()
        } else {
            issue.attributes.key.clone()
        },
        line_start: 1,
        line_end: 1,
    });
    let cwe = issue
        .attributes
        .classes
        .iter()
        .find(|c| c.source.eq_ignore_ascii_case("CWE"))
        .map(|c| c.id.clone());
    let external_id = issue
        .attributes
        .problems
        .iter()
        .map(|p| p.id.as_str())
        .find(|id| !id.is_empty())
        .unwrap_or(issue.id.as_str())
        .to_string();
    let description = issue
        .attributes
        .description
        .clone()
        .filter(|d| !d.is_empty())
        .unwrap_or_else(|| format!("Snyk flagged {} for {title}.", location.file));
    ThirdPartyFinding {
        component: component_of(&issue.attributes),
        provider_origins: vec![ProviderOrigin {
            provider: ProviderKind::Snyk,
            source: ProviderSource::Api,
            product: match issue.attributes.issue_type.as_str() {
                "code" => ProviderProduct::Sast,
                "package_vulnerability" => ProviderProduct::Dependency,
                _ => ProviderProduct::Unknown,
            },
            native_ids: ProviderNativeIds {
                issue_id: (!issue.id.is_empty()).then(|| issue.id.clone()),
                asset_finding_id: issue.attributes.key_asset.clone(),
                ..Default::default()
            },
            state: issue.attributes.status.clone(),
            severity: Some(issue.attributes.effective_severity_level.clone()),
            ..Default::default()
        }],
        vendor: "snyk",
        external_id,
        title,
        file: location.file,
        line_start: location.line_start,
        line_end: location.line_end,
        cwe,
        severity: parse_severity(&issue.attributes.effective_severity_level),
        description,
        recommendation: String::new(),
    }
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
    use wiremock::matchers::{header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn config_for(server: &MockServer) -> SnykConfig {
        let mut cfg = SnykConfig::new("test-token", "org-1", "proj-1");
        cfg.base_url = server.uri();
        cfg
    }

    fn package_issue_json(id: &str) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "type": "issue",
            "attributes": {
                "key": "npm:hoek:20180212:hoek:2.16.3",
                "title": "Hoek - Prototype Pollution",
                "type": "package_vulnerability",
                "effective_severity_level": "medium",
                "status": "open",
                "ignored": false,
                "created_at": "2022-09-27T20:09:05Z",
                "updated_at": "2022-09-27T20:09:05Z",
                "classes": [{"id": "CWE-190", "source": "CWE", "type": "weakness"}],
                "problems": [{"id": "SNYK-JS-HOEK-12345", "source": "snyk", "type": "rule"}],
                "coordinates": [{
                    "is_upgradeable": true,
                    "representations": [{"dependency": {
                        "package_name": "hoek",
                        "package_version": "2.16.3"
                    }}]
                }]
            },
            "relationships": {
                "scan_item": {"data": {"id": "proj-1", "type": "project"}}
            }
        })
    }

    fn code_issue_json(id: &str) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "type": "issue",
            "attributes": {
                "key": "24018479-6bb1-4196-a41b-e54c7c5dcc82:1c6ddc45:1",
                "title": "Insecure hash function used",
                "type": "code",
                "effective_severity_level": "high",
                "status": "open",
                "ignored": false,
                "classes": [{"id": "CWE-328", "source": "CWE", "type": "weakness"}],
                "problems": [{"id": "javascript/InsecureHash", "source": "snyk", "type": "rule"}],
                "coordinates": [{
                    "representations": [{"sourceLocation": {
                        "commit_id": "39f95450a7d4d70e54c9edbd109bed8210a36889",
                        "file": "src/crypto/hash.js",
                        "region": {
                            "start": {"line": 42, "column": 8},
                            "end": {"line": 44, "column": 16}
                        }
                    }}]
                }]
            }
        })
    }

    #[tokio::test]
    async fn fetch_findings_maps_a_package_vulnerability_to_its_dependency_coordinate() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/orgs/org-1/issues"))
            .and(header("Authorization", "token test-token"))
            .and(query_param("scan_item.id", "proj-1"))
            .and(query_param("scan_item.type", "project"))
            .and(query_param("status", "open"))
            .and(query_param("ignored", "false"))
            .and(query_param("limit", "100"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonapi": {"version": "1.0"},
                "data": [package_issue_json("d5b640e5-d88c-4c17-9bf0-93597b7a1ce2")]
            })))
            .mount(&server)
            .await;

        let client = SnykClient::new(reqwest::Client::new(), config_for(&server));
        let findings = client.fetch_findings().await.unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].vendor, "snyk");
        assert_eq!(findings[0].external_id, "SNYK-JS-HOEK-12345");
        assert_eq!(findings[0].title, "Hoek - Prototype Pollution");
        assert_eq!(findings[0].file, "hoek@2.16.3");
        assert_eq!(findings[0].line_start, 1);
        assert_eq!(findings[0].line_end, 1);
        assert_eq!(findings[0].cwe, Some("CWE-190".to_string()));
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[tokio::test]
    async fn fetch_findings_maps_a_code_issue_to_its_file_and_line_span() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/orgs/org-1/issues"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonapi": {"version": "1.0"},
                "data": [code_issue_json("id-1")]
            })))
            .mount(&server)
            .await;

        let client = SnykClient::new(reqwest::Client::new(), config_for(&server));
        let findings = client.fetch_findings().await.unwrap();

        assert_eq!(findings[0].file, "src/crypto/hash.js");
        assert_eq!(findings[0].line_start, 42);
        assert_eq!(findings[0].line_end, 44);
        assert_eq!(findings[0].external_id, "javascript/InsecureHash");
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[tokio::test]
    async fn fetch_findings_follows_a_relative_links_next_path() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/orgs/org-1/issues"))
            .and(query_param("scan_item.id", "proj-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonapi": {"version": "1.0"},
                "data": [package_issue_json("id-1")],
                "links": {
                    "next": "/orgs/org-1/issues?version=2024-10-15&starting_after=v1.eyJpZCI6Mz1zODQyMH0%3D"
                }
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/orgs/org-1/issues"))
            .and(query_param("starting_after", "v1.eyJpZCI6Mz1zODQyMH0="))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonapi": {"version": "1.0"},
                "data": [code_issue_json("id-2")]
            })))
            .mount(&server)
            .await;

        let client = SnykClient::new(reqwest::Client::new(), config_for(&server));
        let findings = client.fetch_findings().await.unwrap();

        assert_eq!(findings.len(), 2);
        assert_eq!(findings[1].file, "src/crypto/hash.js");
    }

    #[tokio::test]
    async fn fetch_findings_follows_a_links_next_that_already_carries_the_rest_prefix() {
        let server = MockServer::start().await;
        let mut cfg = config_for(&server);
        cfg.base_url = format!("{}/rest", server.uri());
        Mock::given(method("GET"))
            .and(path("/rest/orgs/org-1/issues"))
            .and(query_param("scan_item.id", "proj-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonapi": {"version": "1.0"},
                "data": [],
                "links": {"next": "/rest/orgs/org-1/issues?version=2024-10-15&starting_after=abc"}
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/rest/orgs/org-1/issues"))
            .and(query_param("starting_after", "abc"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonapi": {"version": "1.0"},
                "data": [package_issue_json("id-2")]
            })))
            .mount(&server)
            .await;

        let client = SnykClient::new(reqwest::Client::new(), cfg);
        let findings = client.fetch_findings().await.unwrap();

        assert_eq!(findings.len(), 1);
    }

    #[tokio::test]
    async fn fetch_findings_follows_a_links_next_object_with_an_href() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/orgs/org-1/issues"))
            .and(query_param("scan_item.id", "proj-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonapi": {"version": "1.0"},
                "data": [],
                "links": {"next": {"href": "/orgs/org-1/issues?starting_after=xyz",
                                   "meta": {"note": "free-form"}}}
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/orgs/org-1/issues"))
            .and(query_param("starting_after", "xyz"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonapi": {"version": "1.0"},
                "data": [package_issue_json("id-2")]
            })))
            .mount(&server)
            .await;

        let client = SnykClient::new(reqwest::Client::new(), config_for(&server));

        assert_eq!(client.fetch_findings().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn fetch_findings_stops_on_an_empty_links_next() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/orgs/org-1/issues"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonapi": {"version": "1.0"},
                "data": [package_issue_json("id-1")],
                "links": {"next": ""}
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = SnykClient::new(reqwest::Client::new(), config_for(&server));

        assert_eq!(client.fetch_findings().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn fetch_findings_skips_license_config_and_cloud_issue_types() {
        let server = MockServer::start().await;
        let skipped: Vec<_> = ["license", "config", "cloud"]
            .iter()
            .map(|t| {
                serde_json::json!({
                    "id": format!("id-{t}"),
                    "attributes": {"title": "irrelevant", "type": t,
                                   "effective_severity_level": "high"}
                })
            })
            .chain(std::iter::once(code_issue_json("kept")))
            .collect();
        Mock::given(method("GET"))
            .and(path("/orgs/org-1/issues"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonapi": {"version": "1.0"},
                "data": skipped
            })))
            .mount(&server)
            .await;

        let client = SnykClient::new(reqwest::Client::new(), config_for(&server));
        let findings = client.fetch_findings().await.unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].file, "src/crypto/hash.js");
    }

    #[tokio::test]
    async fn fetch_findings_stops_when_links_next_is_absent() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/orgs/org-1/issues"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonapi": {"version": "1.0"},
                "data": []
            })))
            .mount(&server)
            .await;

        let client = SnykClient::new(reqwest::Client::new(), config_for(&server));
        let findings = client.fetch_findings().await.unwrap();

        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn fetch_findings_propagates_a_non_success_status() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/orgs/org-1/issues"))
            .respond_with(ResponseTemplate::new(403).set_body_string("forbidden"))
            .mount(&server)
            .await;

        let client = SnykClient::new(reqwest::Client::new(), config_for(&server));
        let err = client.fetch_findings().await.unwrap_err();

        assert!(matches!(err, SnykError::Http { status: 403, .. }));
    }

    #[tokio::test]
    async fn fetch_findings_retries_a_rate_limited_page() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/orgs/org-1/issues"))
            .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "0"))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/orgs/org-1/issues"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonapi": {"version": "1.0"},
                "data": [package_issue_json("id-1")]
            })))
            .mount(&server)
            .await;

        let client = SnykClient::new(reqwest::Client::new(), config_for(&server));

        assert_eq!(client.fetch_findings().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn fetch_findings_propagates_a_malformed_response_body() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/orgs/org-1/issues"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
            .mount(&server)
            .await;

        let client = SnykClient::new(reqwest::Client::new(), config_for(&server));
        let err = client.fetch_findings().await.unwrap_err();

        assert!(matches!(err, SnykError::Json { .. }));
    }

    #[tokio::test]
    async fn fetch_findings_propagates_a_transport_failure() {
        let mut cfg = SnykConfig::new("t", "o", "p");
        cfg.base_url = "http://127.0.0.1:1".to_string();
        let client = SnykClient::new(reqwest::Client::new(), cfg);

        let err = client.fetch_findings().await.unwrap_err();

        assert!(matches!(err, SnykError::Request { .. }));
    }

    #[rstest::rstest]
    #[case(
        "https://api.snyk.io/rest",
        "https://api.eu.snyk.io/rest/orgs/o/issues?x=1",
        "https://api.eu.snyk.io/rest/orgs/o/issues?x=1"
    )]
    #[case(
        "https://api.snyk.io/rest",
        "http://example.com/x",
        "http://example.com/x"
    )]
    #[case(
        "https://api.snyk.io/rest",
        "/orgs/123/issues?version=2024-10-15&starting_after=abc",
        "https://api.snyk.io/rest/orgs/123/issues?version=2024-10-15&starting_after=abc"
    )]
    #[case(
        "https://api.snyk.io/rest",
        "/rest/orgs/123/issues?starting_after=abc",
        "https://api.snyk.io/rest/orgs/123/issues?starting_after=abc"
    )]
    #[case(
        "https://api.snyk.io/rest/",
        "orgs/123/issues",
        "https://api.snyk.io/rest/orgs/123/issues"
    )]
    #[case(
        "http://127.0.0.1:8080",
        "/orgs/123/issues",
        "http://127.0.0.1:8080/orgs/123/issues"
    )]
    #[case(
        "http://127.0.0.1:8080",
        "/rest/orgs/123/issues",
        "http://127.0.0.1:8080/rest/orgs/123/issues"
    )]
    fn next_url_resolution(#[case] base: &str, #[case] next: &str, #[case] expected: &str) {
        assert_eq!(resolve_next_url(base, next), expected);
    }

    #[test]
    fn origin_of_a_schemeless_host_only_base_is_the_whole_string() {
        assert_eq!(origin_of("api.snyk.io"), "api.snyk.io");
    }

    #[test]
    fn origin_of_a_schemeless_base_with_a_path_drops_the_path() {
        assert_eq!(origin_of("api.snyk.io/rest"), "api.snyk.io");
    }

    #[test]
    fn a_missing_title_falls_back_to_the_key() {
        let issue = Issue {
            id: "x".to_string(),
            attributes: IssueAttributes {
                key: "npm:foo:1.0".to_string(),
                ..Default::default()
            },
        };
        let tpf = to_third_party_finding(&issue);
        assert_eq!(tpf.title, "npm:foo:1.0");
        assert_eq!(tpf.file, "npm:foo:1.0");
    }

    #[test]
    fn an_issue_with_neither_a_coordinate_a_key_nor_a_title_falls_back_to_its_title() {
        let issue = Issue {
            id: "x".to_string(),
            attributes: IssueAttributes {
                title: "Something Bad".to_string(),
                ..Default::default()
            },
        };
        assert_eq!(to_third_party_finding(&issue).file, "Something Bad");
    }

    #[test]
    fn an_issue_with_no_problems_falls_back_to_the_json_api_resource_id() {
        let issue = Issue {
            id: "d5b640e5-d88c-4c17-9bf0-93597b7a1ce2".to_string(),
            attributes: IssueAttributes {
                title: "t".to_string(),
                problems: vec![Problem { id: String::new() }],
                ..Default::default()
            },
        };
        assert_eq!(
            to_third_party_finding(&issue).external_id,
            "d5b640e5-d88c-4c17-9bf0-93597b7a1ce2"
        );
    }

    #[test]
    fn a_missing_description_is_synthesized_from_the_resolved_location() {
        let issue = Issue {
            id: "x".to_string(),
            attributes: IssueAttributes {
                title: "Something Bad".to_string(),
                ..Default::default()
            },
        };
        let tpf = to_third_party_finding(&issue);
        assert!(tpf.description.contains("Something Bad"));
    }

    #[test]
    fn no_cwe_class_yields_none() {
        let issue = Issue {
            id: "x".to_string(),
            attributes: IssueAttributes {
                title: "t".to_string(),
                classes: vec![IssueClass {
                    id: "not-cwe".to_string(),
                    source: "OTHER".to_string(),
                }],
                ..Default::default()
            },
        };
        assert_eq!(to_third_party_finding(&issue).cwe, None);
    }

    fn attributes_with_representation(representation: serde_json::Value) -> IssueAttributes {
        serde_json::from_value(serde_json::json!({
            "coordinates": [{"representations": [representation]}]
        }))
        .unwrap()
    }

    #[test]
    fn a_source_location_with_no_region_defaults_to_line_one() {
        let attrs =
            attributes_with_representation(serde_json::json!({"sourceLocation": {"file": "a.py"}}));
        let location = locate(&attrs).unwrap();
        assert_eq!(location.file, "a.py");
        assert_eq!((location.line_start, location.line_end), (1, 1));
    }

    #[test]
    fn a_region_with_only_a_start_uses_it_for_both_ends() {
        let attrs = attributes_with_representation(serde_json::json!({
            "sourceLocation": {"file": "a.py", "region": {"start": {"line": 9, "column": 1}}}
        }));
        let location = locate(&attrs).unwrap();
        assert_eq!((location.line_start, location.line_end), (9, 9));
    }

    #[test]
    fn a_region_point_with_no_line_key_defaults_to_line_one() {
        let attrs = attributes_with_representation(serde_json::json!({
            "sourceLocation": {"file": "a.py", "region": {"start": {"column": 1},
                                                          "end": {"column": 4}}}
        }));
        let location = locate(&attrs).unwrap();
        assert_eq!((location.line_start, location.line_end), (1, 1));
    }

    #[test]
    fn a_source_location_with_an_empty_file_is_not_used() {
        let attrs =
            attributes_with_representation(serde_json::json!({"sourceLocation": {"file": ""}}));
        assert!(locate(&attrs).is_none());
    }

    #[test]
    fn a_dependency_with_no_version_uses_the_bare_package_name() {
        let attrs = attributes_with_representation(
            serde_json::json!({"dependency": {"package_name": "hoek", "package_version": ""}}),
        );
        assert_eq!(locate(&attrs).unwrap().file, "hoek");
    }

    #[test]
    fn a_dependency_with_no_package_name_is_not_used() {
        let attrs = attributes_with_representation(
            serde_json::json!({"dependency": {"package_name": "", "package_version": "1.0"}}),
        );
        assert!(locate(&attrs).is_none());
    }

    #[test]
    fn a_resource_path_representation_is_ignored_rather_than_failing() {
        let attrs =
            attributes_with_representation(serde_json::json!({"resourcePath": "some/opaque/path"}));
        assert!(locate(&attrs).is_none());
    }

    #[test]
    fn a_cloud_resource_representation_is_ignored_rather_than_failing() {
        let attrs = attributes_with_representation(serde_json::json!({
            "cloud_resource": {"environment": {"id": "4a18d42f-0706-4ad0-b127-24078731fbed",
                                               "type": "aws", "name": "prod"}}
        }));
        assert!(locate(&attrs).is_none());
    }

    #[test]
    fn a_source_location_wins_over_a_dependency_on_the_same_issue() {
        let attrs: IssueAttributes = serde_json::from_value(serde_json::json!({
            "coordinates": [
                {"representations": [{"dependency": {"package_name": "p", "package_version": "1"}}]},
                {"representations": [{"sourceLocation": {"file": "src/a.js",
                                                         "region": {"start": {"line": 3},
                                                                    "end": {"line": 4}}}}]}
            ]
        }))
        .unwrap();
        let location = locate(&attrs).unwrap();
        assert_eq!(location.file, "src/a.js");
        assert_eq!((location.line_start, location.line_end), (3, 4));
    }

    #[rstest::rstest]
    #[case("critical", Severity::Critical)]
    #[case("high", Severity::High)]
    #[case("medium", Severity::Medium)]
    #[case("low", Severity::Low)]
    #[case("info", Severity::Info)]
    #[case("weird", Severity::Info)]
    fn severity_mapping(#[case] raw: &str, #[case] expected: Severity) {
        assert_eq!(parse_severity(raw), expected);
    }
}

#[cfg(test)]
mod provenance_tests {
    use super::*;
    #[test]
    fn native_identity_is_preserved_without_report_id_fallback() {
        let raw: Issue=serde_json::from_value(serde_json::json!({"id":"instance","attributes":{"type":"code","key_asset":"asset-fingerprint","problems":[{"id":"shared-rule"}],"status":"open"}})).unwrap();
        let finding = to_third_party_finding(&raw);
        let origin = &finding.provider_origins[0];
        assert_eq!(finding.external_id, "shared-rule");
        assert_eq!(origin.native_ids.issue_id.as_deref(), Some("instance"));
        assert_eq!(
            origin.native_ids.asset_finding_id.as_deref(),
            Some("asset-fingerprint")
        );
        assert_eq!(origin.product, ProviderProduct::Sast);
        let missing = to_third_party_finding(&Issue::default());
        assert!(missing.provider_origins[0]
            .native_ids
            .asset_finding_id
            .is_none());
    }

    #[test]
    fn debug_redacts_the_token_but_keeps_the_rest() {
        let shown = format!(
            "{:?}",
            SnykConfig::new("sup3r-s3cret-cred-do-not-log", "org", "proj")
        );
        assert!(
            !shown.contains("sup3r-s3cret-cred-do-not-log"),
            "the token reached a Debug rendering: {shown}"
        );
        assert!(shown.contains("<redacted>"), "{shown}");
        assert!(shown.contains("org"), "{shown}");
        assert!(shown.contains("SnykConfig"), "{shown}");
    }
}
