//! Snyk REST API client (`GET /orgs/{org_id}/issues`), confirmed
//! directly against Snyk's own published OpenAPI 3.x REST spec (fetched
//! and parsed 2026-09, `api.snyk.io/rest/openapi/2024-10-15`) — the field
//! shapes below are verified specifically against API version
//! `2024-10-15`.
//!
//! **Project = branch, by Snyk's own data model.** Each branch of a repo
//! is a *separate* Snyk Project (all sharing one Target), not a filter
//! on one project — so unlike Semgrep/Checkmarx there's no separate
//! branch parameter here: the operator supplies the *exact* `project_id`
//! for the branch they want (Snyk's own UI presents projects this way
//! too), matching the confirmed "explicit per-vendor project ID config"
//! design.
//!
//! **Auth**: `Authorization: token <PAT>` — note the literal word
//! `"token"`, not `"Bearer"` (Snyk's own header format, confirmed in the
//! spec's security scheme and docs, for both the legacy v1 and REST
//! APIs alike).
//!
//! **Pagination follows a RELATIVE `links.next`.** This was previously
//! assigned verbatim as the next request URL, which made any project with
//! more than one page of issues fail on page two — reqwest rejects
//! `/orgs/<id>/issues?...` as not a URL. Snyk's own documentation
//! (`snyk/user-docs`, `about-the-rest-api.md`) shows exactly that shape:
//!
//! ```json
//! {"data": [], "links": {"next": "/orgs/123-abc-def-456/projects?version=2024-06-10&starting_after=v1.eyJ..."}}
//! ```
//!
//! and the documented regional base URLs all END in `/rest`
//! (`https://api.snyk.io/rest`, `api.eu.snyk.io/rest`, …), so
//! [`resolve_next_url`] joins the path onto the configured base — while
//! also handling the two other forms observed in the wild: an already-
//! absolute URL, and a path that already carries the `/rest` prefix
//! itself (which must be joined to the base's *origin*, not appended to a
//! base that already ends in `/rest`). `links.next` is additionally typed
//! in the spec as `LinkProperty`, a `oneOf` of a bare string **or** an
//! object `{href, meta}`, so both are accepted.
//!
//! **Filters**: `status=open` and `ignored=false` (both real, documented
//! query parameters) so a project's history of resolved and
//! human-suppressed issues isn't re-injected into the pipeline as fresh
//! findings.
//!
//! **Location** comes from `attributes.coordinates[].representations[]`,
//! never from `attributes.key` (an "opaque key used for uniquely
//! identifying this issue across test runs", which this client used to
//! hand S6/S7 as a file path — an unmatchable string like
//! `npm:hoek:20180212:hoek:2.16.3`). The spec's `representations` is a
//! `oneOf` of four shapes; the two that carry a real location are
//! `{"sourceLocation": {"file": ..., "region": {"start": {"line", "column"},
//! "end": {...}}}}` for Code issues and
//! `{"dependency": {"package_name", "package_version"}}` for
//! `package_vulnerability` issues. The other two (`resourcePath`,
//! `cloud_resource`) are parsed-and-ignored rather than being a hard
//! error.
//!
//! **Region note** (not yet wired as config here — flagged for a future
//! revision if needed): Snyk tokens are region-locked
//! (`api.snyk.io`/`api.us.snyk.io`/`api.eu.snyk.io`/`api.au.snyk.io`) —
//! a token minted in one region 401s against another region's base URL.
//! `base_url` is fully operator-configurable via [`SnykConfig`] for
//! exactly this reason.

use bc_model::{ProviderKind, ProviderNativeIds, ProviderOrigin, ProviderProduct, ProviderSource};
use bc_thirdparty::{Severity, ThirdPartyFinding};
use serde::Deserialize;

use crate::retry::send_with_retry;

const DEFAULT_BASE_URL: &str = "https://api.snyk.io/rest";
const DEFAULT_API_VERSION: &str = "2024-10-15";
/// The endpoint's documented maximum (`limit`: default 10, max 100).
const PAGE_LIMIT: u32 = 100;
const MAX_PAGES: u32 = 1000;

/// Issue types this pipeline has nothing useful to say about: `license`
/// is a compliance/legal finding with no vulnerability to verify, and
/// `config`/`cloud` describe deployed infrastructure rather than anything
/// in the repository S6 reads. Ingesting them would put findings in front
/// of the verifier that it can only ever mark unconfirmed.
const SKIPPED_ISSUE_TYPES: [&str; 3] = ["license", "config", "cloud"];

#[derive(Debug, Clone)]
pub struct SnykConfig {
    pub base_url: String,
    pub token: String,
    pub api_version: String,
    pub org_id: String,
    pub project_id: String,
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

    /// Fetches every open, non-ignored issue for the configured project,
    /// following `links.next` (JSON:API cursor pagination) until the
    /// response omits it.
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

/// Turns the `links.next` value into an absolute URL against `base_url`.
///
/// Three shapes are handled, because Snyk's documentation and its live
/// API disagree about the second one:
/// - an already-absolute `http(s)://…` URL — used as-is;
/// - a path that itself starts with `/rest/` — joined to the base's
///   *origin*, since the configured base already ends in `/rest` and
///   appending would produce `/rest/rest/…`;
/// - any other path — joined to the base.
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

/// `https://api.snyk.io/rest` -> `https://api.snyk.io`. Falls back to the
/// whole input when it has no path component to trim.
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

/// The spec's `LinkProperty`: `oneOf` a bare URL string or an object with
/// a required `href` (and an optional free-form `meta`).
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

/// "A list of details for vulnerability data, policy, etc that are the
/// source of this issue" — its `id` is the durable public identifier
/// (`SNYK-JS-LODASH-567746`, `CVE-2020-8203`), unlike the per-scan UUID in
/// the JSON:API `data[].id`.
#[derive(Debug, Deserialize)]
struct Problem {
    #[serde(default)]
    id: String,
}

#[derive(Debug, Default, Deserialize)]
struct Coordinate {
    #[serde(default)]
    representations: Vec<Representation>,
}

/// The spec models this as a `oneOf` of four mutually-exclusive shapes,
/// but a struct of optional keys reads them all without any variant
/// ordering subtleties: the two shapes this client can place in the
/// repository get a field, and the two it cannot (`resourcePath`,
/// `cloud_resource`) simply leave both `None` — parsed into nothing
/// rather than failing the whole page.
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

/// Where a finding lives, in the terms the rest of the pipeline uses.
struct Location {
    file: String,
    line_start: i64,
    line_end: i64,
}

/// A real source location wins over a dependency coordinate when an issue
/// somehow carries both, since a file+line is strictly more useful to S6's
/// verifier than a package name.
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
            // An SCA finding has no source line — see this crate's own
            // `ThirdPartyFinding::file` doc comment.
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
        // No coordinate at all: fall back to the opaque key (still better
        // than nothing in the report's audit trail) and then the title.
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

    /// Shaped from the spec's own `Issue`/`IssueAttributes`/`Problem`/
    /// `Class` schemas and its `OpenSourceListIssuesResponse20240123`
    /// example — `key`, `type` and `effective_severity_level` values are
    /// the documented ones.
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
                // Verbatim shape from Snyk's own pagination documentation.
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
        // A base that ends in /rest, exactly like the documented regional
        // base URLs — naive concatenation here would yield /rest/rest/…
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
    // Absolute URLs are used verbatim.
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
    // The documented relative form: joined onto the base (which ends in /rest).
    #[case(
        "https://api.snyk.io/rest",
        "/orgs/123/issues?version=2024-10-15&starting_after=abc",
        "https://api.snyk.io/rest/orgs/123/issues?version=2024-10-15&starting_after=abc"
    )]
    // A path that already carries /rest: joined onto the ORIGIN instead.
    #[case(
        "https://api.snyk.io/rest",
        "/rest/orgs/123/issues?starting_after=abc",
        "https://api.snyk.io/rest/orgs/123/issues?starting_after=abc"
    )]
    // A base with a trailing slash, and a relative path with no leading one.
    #[case(
        "https://api.snyk.io/rest/",
        "orgs/123/issues",
        "https://api.snyk.io/rest/orgs/123/issues"
    )]
    // A base that is a bare origin (how the tests above configure it).
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
        // `line` is declared required by the spec, so this is a
        // tolerate-the-server case rather than a documented one.
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
}
