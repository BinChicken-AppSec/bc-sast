//! Checkmarx One (SaaS/AST) live API client — lists scans for an
//! operator-supplied project + branch, picks the most recent `Completed`
//! one, paginates its SAST results, and converts each into a
//! `bc_thirdparty::ThirdPartyFinding`. This targets Checkmarx **One**
//! (the current SaaS/AST product's JSON REST API), a materially
//! different product/API from the classic on-prem CxSAST XML export
//! `bc_thirdparty::checkmarx` already parses — new DTOs, no shared code
//! with that module beyond the common `ThirdPartyFinding`/`Severity`
//! output shape.
//!
//! Checkmarx's own product documentation is a JS-rendered Stoplight site
//! that returns nothing usable to a plain HTTP fetch, so the field-level
//! source of truth used here is the set of OpenAPI documents Checkmarx
//! itself vendors into its SDK/CLI repositories, plus those tools'
//! working request code:
//! `checkmarx-ts/checkmarx-python-sdk` — `docs/swagger_yaml/CxOne/SAST_RESULTS.yaml`,
//! `SCANS.yaml`, `SCANNERS_RESULTS.yaml`, and `CxOne/dto/SastResult.py`'s
//! own `from_dict` field mapping — and `Checkmarx/ast-cli`'s
//! `internal/wrappers/results-http.go`.
//!
//! ## Why `/api/sast-results` and not `/api/results`
//!
//! Two endpoints return scan results, and the trade-off is real:
//! `/api/sast-results` is SAST-engine-only and returns typed
//! `SastResult` objects (`queryName`, `cweID`, `similarityID`, `nodes`)
//! with rich SAST-specific filters (`state`, `severity`, sink/source
//! file+line, CWE). `/api/results` is multi-engine (SAST **plus** KICS
//! /IaC, SCA, containers, secrets) but flattens every engine's payload
//! into one untyped `data` object whose contents "differ according to the
//! type of scanner", forcing per-engine reshaping and losing the typed
//! CWE field. This pipeline verifies source code, and the file-based
//! `bc_thirdparty::checkmarx` parser is likewise SAST-only, so the
//! narrower, better-typed endpoint is the right scope. The cost, stated
//! plainly: **IaC/SCA/secrets findings from a Checkmarx One scan are not
//! ingested at all by this client.**
//!
//! ## Auth
//!
//! OAuth2 `refresh_token` grant against a Keycloak-backed IAM host,
//! `POST {iam_url}/auth/realms/{tenant}/protocol/openid-connect/token`,
//! body `grant_type=refresh_token&client_id=ast-app&refresh_token=<api_key>`.
//! The "refresh token" here is really Checkmarx's long-lived,
//! regenerable API key (`docs.checkmarx.com` — "Generating a Refresh
//! Token (API Key)"), so it's reused as-is on every re-auth rather than
//! rotated; the standard Keycloak/OIDC token response
//! (`access_token`/`expires_in`/`token_type`) is used, other fields
//! ignored. Access tokens are short-lived (~300s), hence the shared
//! [`crate::oauth2::TokenCache`] — and, because a long results
//! pagination can outlive one anyway, a single `401` mid-pagination
//! invalidates the cache and retries once rather than failing the vendor.
//!
//! **IAM host is NOT derived from the data-plane host**, and the two are
//! per-region: EU is `eu.iam.checkmarx.net` for IAM against
//! `eu.ast.checkmarx.net` for data; `deu.iam.checkmarx.net` is the
//! *Germany* (DEU) region, not the EU one — an earlier version of this
//! comment claimed otherwise, and an operator copying it would have got
//! a 401 they'd have blamed on their API key. Others in the published
//! regional table: `iam.checkmarx.net` (US), `us.iam.checkmarx.net`
//! (US2), `eu-2.iam.checkmarx.net`, `anz.iam.checkmarx.net`,
//! `ind.iam.checkmarx.net`, `sng.iam.checkmarx.net`. [`CheckmarxConfig`]
//! takes both hosts separately rather than guessing one from the other.
//!
//! ## Results
//!
//! `GET {base_url}/api/sast-results`, `{totalCount, results: [...]}`,
//! paginated by incrementing `offset`. Sent with:
//! - `Accept: application/json; version=1.0` — the spec declares an
//!   `Accept` header parameter whose whole job is "the API version should
//!   be appended to this header" (its own example is `*/*; version=1.0`).
//!   It is marked `required: false`, so this is version-pinning
//!   insurance, not a hard requirement.
//! - `state=TO_VERIFY&state=CONFIRMED&state=URGENT` — the documented
//!   `state` filter is an array ("Must be an exact match, case
//!   insensitive") over the `StateEnum` `TO_VERIFY`,
//!   `NOT_EXPLOITABLE`, `PROPOSED_NOT_EXPLOITABLE`, `CONFIRMED`,
//!   `URGENT`. Results a human triaged as not-exploitable are ALSO
//!   dropped client-side, case-insensitively: `/api/results` types the
//!   same field as `oneOf [StateEnum, string]`, i.e. a tenant may define
//!   custom states, so the server-side filter alone is not something to
//!   rely on.
//! - `include-nodes=true` (the dataflow node array is only returned when
//!   asked for) and `apply-predicates=true` (so a triage change made in
//!   the Checkmarx UI is reflected in the returned `state`).
//!
//! **Field-name traps, all previously wrong here:** the CWE field is
//! `cweID`, not `cweId` (confirmed twice over — `SAST_RESULTS.yaml`'s
//! `SastResult` schema and the Python SDK's `item.get("cweID")`), so
//! every finding used to arrive with no CWE at all, which in turn meant
//! `VulnClass::Other` for every Checkmarx finding. The id field is `ID`
//! (uppercase) in the schema and is not required; the SDK ignores it
//! entirely and uses `resultHash`. This client prefers `similarityID`
//! over both, because that is the cross-scan-stable identity ("a value
//! assigned to a specific vulnerability instance in your scan, based on
//! the first and last nodes… enables CxAST to track that particular
//! instance in future scans") — the same identity the classic-XML parser
//! already keys on via `Path@SimilarityId`.
//!
//! **Paths are `/`-prefixed** (`"/src/app.py"`) in Checkmarx's node data;
//! the leading separator is stripped so S6/S7 see repo-relative paths
//! that match what this pipeline's own findings and file reads use.
//!
//! **Flagged uncertain** (kept from the original API research, still
//! genuinely unconfirmed pending a live account — Checkmarx remains the
//! one vendor with no available credentials to validate against):
//! - Whether `branch` on `/api/scans` does exact or fuzzy/case-insensitive
//!   matching against the scanned branch name.
//! - `sinkFileName`/`sinkLine`/`sourceFileName`/`sourceLine` are read
//!   opportunistically: they are documented as `/api/sast-results` *query
//!   filters* and as `visible-columns` values, but do **not** appear in
//!   the published `SastResult` response schema. They are used when
//!   present and ignored when not, with the dataflow `nodes` array as the
//!   real fallback.
//! - Data-flow node ordering within a `SastResult.nodes` array — the
//!   fallback uses the **last** node as the sink and the **first** as the
//!   source, the dataflow convention, but the schema doesn't state it.

use bc_model::{ProviderKind, ProviderNativeIds, ProviderOrigin, ProviderProduct, ProviderSource};
use bc_thirdparty::{Severity, ThirdPartyFinding};
use serde::Deserialize;

use crate::oauth2::{CachedToken, TokenCache};
use crate::retry::send_with_retry;
use crate::timestamp::chronological_key;

const RESULTS_PAGE_SIZE: u32 = 200;
const MAX_PAGES: u32 = 1000;
/// With `sort=-created_at` the newest completed scan is the first entry;
/// a small window is still requested (rather than 1) so the
/// chronological max below has something to be robust with if a future
/// API change ignores the sort.
const SCAN_LIST_LIMIT: u32 = 20;
/// The spec's `Accept` header parameter: "The API version should be
/// appended to this header."
const ACCEPT_VERSIONED_JSON: &str = "application/json; version=1.0";
/// `StateEnum` values that mean "a human looked at this and said no".
const TRIAGED_OUT_STATES: [&str; 2] = ["NOT_EXPLOITABLE", "PROPOSED_NOT_EXPLOITABLE"];
/// The complement of [`TRIAGED_OUT_STATES`], sent as a server-side filter.
const WANTED_STATES: [&str; 3] = ["TO_VERIFY", "CONFIRMED", "URGENT"];

#[derive(Debug, Clone)]
pub struct CheckmarxConfig {
    /// Data-plane host, e.g. `https://eu.ast.checkmarx.net`.
    pub base_url: String,
    /// IAM host, e.g. `https://eu.iam.checkmarx.net` — genuinely separate
    /// from `base_url`, see the module doc comment.
    pub iam_url: String,
    pub tenant: String,
    /// The long-lived API key generated in the Checkmarx One UI, used as
    /// the OAuth2 `refresh_token` grant's `refresh_token` value.
    pub api_key: String,
    pub project_id: String,
    pub branch: Option<String>,
}

impl CheckmarxConfig {
    pub fn new(
        base_url: impl Into<String>,
        iam_url: impl Into<String>,
        tenant: impl Into<String>,
        api_key: impl Into<String>,
        project_id: impl Into<String>,
    ) -> Self {
        CheckmarxConfig {
            base_url: base_url.into(),
            iam_url: iam_url.into(),
            tenant: tenant.into(),
            api_key: api_key.into(),
            project_id: project_id.into(),
            branch: None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CheckmarxError {
    #[error("Checkmarx One API request failed: {message}")]
    Request { message: String },
    #[error("Checkmarx One API returned HTTP {status}: {message}")]
    Http { status: u16, message: String },
    #[error("failed to parse Checkmarx One API response: {message}")]
    Json { message: String },
    #[error("no completed scan found for project {project_id}, branch {branch:?}")]
    ScanNotFound {
        project_id: String,
        branch: Option<String>,
    },
}

pub struct CheckmarxClient {
    http: reqwest::Client,
    config: CheckmarxConfig,
    tokens: TokenCache,
}

impl CheckmarxClient {
    pub fn new(http: reqwest::Client, config: CheckmarxConfig) -> Self {
        CheckmarxClient {
            http,
            config,
            tokens: TokenCache::new(),
        }
    }

    pub async fn fetch_findings(&self) -> Result<Vec<ThirdPartyFinding>, CheckmarxError> {
        let scan_id = self.resolve_latest_scan_id().await?;
        let results = self.fetch_all_results(&scan_id).await?;
        Ok(results
            .into_iter()
            .filter(|r| !is_triaged_out(&r.state))
            .map(|r| {
                let mut finding = to_third_party_finding(r, &scan_id);
                for origin in &mut finding.provider_origins {
                    origin.tenant_id = Some(self.config.tenant.clone());
                    origin.project_id = Some(self.config.project_id.clone());
                    origin.git_ref = self.config.branch.clone();
                }
                finding
            })
            .collect())
    }

    pub(crate) async fn access_token(&self) -> Result<String, CheckmarxError> {
        let config = &self.config;
        let http = &self.http;
        self.tokens
            .get_or_refresh(|| async move {
                let url = format!(
                    "{}/auth/realms/{}/protocol/openid-connect/token",
                    config.iam_url, config.tenant
                );
                let resp = send_with_retry(|| {
                    http.post(&url).form(&[
                        ("grant_type", "refresh_token"),
                        ("client_id", "ast-app"),
                        ("refresh_token", &config.api_key),
                    ])
                })
                .await
                .map_err(request_error)?;
                if !resp.status.is_success() {
                    return Err(CheckmarxError::Http {
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

    async fn get(&self, url: &str, query: &[(&str, String)]) -> Result<String, CheckmarxError> {
        let token = self.access_token().await?;
        let resp = send_with_retry(|| {
            self.http
                .get(url)
                .bearer_auth(&token)
                .header(reqwest::header::ACCEPT, ACCEPT_VERSIONED_JSON)
                .query(query)
        })
        .await
        .map_err(request_error)?;
        if !resp.status.is_success() {
            return Err(CheckmarxError::Http {
                status: resp.status.as_u16(),
                message: resp.body,
            });
        }
        Ok(resp.body)
    }

    /// As [`Self::get`], but a `401` invalidates the cached access token
    /// and retries once — see the module doc comment's auth section.
    async fn get_reauthenticating(
        &self,
        url: &str,
        query: &[(&str, String)],
    ) -> Result<String, CheckmarxError> {
        match self.get(url, query).await {
            Err(CheckmarxError::Http { status: 401, .. }) => {
                self.tokens.invalidate().await;
                self.get(url, query).await
            }
            other => other,
        }
    }

    async fn resolve_latest_scan_id(&self) -> Result<String, CheckmarxError> {
        let url = format!("{}/api/scans", self.config.base_url);
        let mut query = vec![
            ("project-id", self.config.project_id.clone()),
            ("statuses", "Completed".to_string()),
            ("sort", "-created_at".to_string()),
            ("limit", SCAN_LIST_LIMIT.to_string()),
        ];
        if let Some(branch) = &self.config.branch {
            query.push(("branch", branch.clone()));
        }
        let text = self.get_reauthenticating(&url, &query).await?;
        let parsed: ScansResponse = serde_json::from_str(&text).map_err(json_error)?;
        parsed
            .scans
            .into_iter()
            .max_by_key(|s| chronological_key(&s.created_at))
            .map(|s| s.id)
            .ok_or_else(|| CheckmarxError::ScanNotFound {
                project_id: self.config.project_id.clone(),
                branch: self.config.branch.clone(),
            })
    }

    async fn fetch_all_results(&self, scan_id: &str) -> Result<Vec<SastResult>, CheckmarxError> {
        let url = format!("{}/api/sast-results", self.config.base_url);
        let mut all = Vec::new();
        let mut offset = 0u32;
        for _ in 0..MAX_PAGES {
            let mut query = vec![
                ("scan-id", scan_id.to_string()),
                ("include-nodes", "true".to_string()),
                ("apply-predicates", "true".to_string()),
                ("offset", offset.to_string()),
                ("limit", RESULTS_PAGE_SIZE.to_string()),
            ];
            query.extend(WANTED_STATES.iter().map(|s| ("state", (*s).to_string())));
            let text = self.get_reauthenticating(&url, &query).await?;
            let parsed: SastResultsResponse = serde_json::from_str(&text).map_err(json_error)?;
            // The RAW page length drives pagination: triaged-out results
            // are dropped later, in `fetch_findings`, so a page that was
            // full never looks short here.
            let page_len = parsed.results.len() as u32;
            all.extend(parsed.results);
            offset += page_len;
            if page_len < RESULTS_PAGE_SIZE || offset >= parsed.total_count {
                break;
            }
        }
        Ok(all)
    }
}

fn request_error(e: reqwest::Error) -> CheckmarxError {
    CheckmarxError::Request {
        message: e.to_string(),
    }
}

fn json_error(e: serde_json::Error) -> CheckmarxError {
    CheckmarxError::Json {
        message: e.to_string(),
    }
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
}

#[derive(Debug, Default, Deserialize)]
struct ScansResponse {
    #[serde(default)]
    scans: Vec<ScanSummary>,
}

#[derive(Debug, Deserialize)]
struct ScanSummary {
    id: String,
    #[serde(default, rename = "createdAt")]
    created_at: String,
}

#[derive(Debug, Default, Deserialize)]
struct SastResultsResponse {
    #[serde(default)]
    results: Vec<SastResult>,
    #[serde(rename = "totalCount", default)]
    total_count: u32,
}

#[derive(Debug, Default, Deserialize)]
struct SastResult {
    #[serde(default, rename = "attackVectorId", alias = "attackVectorID")]
    attack_vector_id: Option<String>,
    /// `ID` in the published schema; `id` accepted as an alias because
    /// the multi-engine `/api/results` spells it lower-case. Not required
    /// by either.
    #[serde(default, rename = "ID", alias = "id")]
    id: Option<String>,
    #[serde(default, rename = "resultHash")]
    result_hash: Option<String>,
    /// Typed `integer` by `/api/sast-results` but accepted as a string
    /// too, since the value's only use here is as an opaque identity.
    #[serde(default, rename = "similarityID", alias = "similarityId")]
    similarity_id: Option<serde_json::Value>,
    #[serde(default, rename = "queryName")]
    query_name: String,
    #[serde(default, rename = "cweID", alias = "cweId")]
    cwe_id: Option<i64>,
    #[serde(default)]
    severity: String,
    #[serde(default)]
    state: String,
    #[serde(default)]
    nodes: Vec<ResultNode>,
    #[serde(default, rename = "sinkFileName")]
    sink_file_name: Option<String>,
    #[serde(default, rename = "sinkLine")]
    sink_line: Option<i64>,
    #[serde(default, rename = "sourceFileName")]
    source_file_name: Option<String>,
    #[serde(default, rename = "sourceLine")]
    source_line: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct ResultNode {
    #[serde(rename = "fileName", default)]
    file_name: String,
    #[serde(default = "default_line")]
    line: i64,
}

fn default_line() -> i64 {
    1
}

/// One end of a Checkmarx dataflow.
struct Endpoint {
    file: String,
    line: i64,
}

/// Checkmarx reports node paths absolute-from-repo-root (`"/src/app.py"`),
/// but every other producer and consumer in this pipeline — the LLM's own
/// findings, S6's file reads, S7's dedup keys — uses repo-relative paths.
fn repo_relative(path: &str) -> String {
    path.trim_start_matches('/').to_string()
}

fn endpoint_from(file: &Option<String>, line: &Option<i64>) -> Option<Endpoint> {
    let file = file.as_deref().filter(|f| !f.is_empty())?;
    Some(Endpoint {
        file: repo_relative(file),
        line: line.unwrap_or_else(default_line),
    })
}

fn endpoint_from_node(node: Option<&ResultNode>) -> Option<Endpoint> {
    let node = node.filter(|n| !n.file_name.is_empty())?;
    Some(Endpoint {
        file: repo_relative(&node.file_name),
        line: node.line,
    })
}

fn is_triaged_out(state: &str) -> bool {
    TRIAGED_OUT_STATES
        .iter()
        .any(|s| state.trim().eq_ignore_ascii_case(s))
}

/// `similarityID` (cross-scan stable) first, then `resultHash`, then the
/// schema's own `ID`.
fn external_id(result: &SastResult, sink: &Option<Endpoint>, title: &str) -> String {
    if let Some(id) = result.similarity_id.as_ref().and_then(scalar_to_string) {
        return id;
    }
    for candidate in [&result.result_hash, &result.id] {
        if let Some(id) = candidate.as_deref().filter(|c| !c.is_empty()) {
            return id.to_string();
        }
    }
    match sink {
        Some(endpoint) => format!("{title}:{}:{}", endpoint.file, endpoint.line),
        None => title.to_string(),
    }
}

fn scalar_to_string(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(s) if !s.is_empty() => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn to_third_party_finding(result: SastResult, scan_id: &str) -> ThirdPartyFinding {
    let title = if result.query_name.is_empty() {
        "Checkmarx finding".to_string()
    } else {
        result.query_name.clone()
    };
    // The sink is where the vulnerability manifests, so it is the
    // finding's location. Explicit sink fields win over the node array.
    let sink = endpoint_from(&result.sink_file_name, &result.sink_line)
        .or_else(|| endpoint_from_node(result.nodes.last()))
        .or_else(|| endpoint_from(&result.source_file_name, &result.source_line));
    let source = endpoint_from(&result.source_file_name, &result.source_line)
        .or_else(|| endpoint_from_node(result.nodes.first()));

    let mut description = format!("Checkmarx One detected a potential {title} (scan {scan_id}).");
    if let (Some(source), Some(sink)) = (&source, &sink) {
        description.push_str(&format!(
            " Data flow: {}:{} -> {}:{}.",
            source.file, source.line, sink.file, sink.line
        ));
    }
    if !result.state.is_empty() {
        description.push_str(&format!(" Triage state: {}.", result.state));
    }
    description.push_str(" Verify against the actual source.");

    ThirdPartyFinding {
        provider_origins: vec![ProviderOrigin {
            provider: ProviderKind::Checkmarx,
            product: ProviderProduct::Sast,
            source: ProviderSource::Api,
            native_ids: ProviderNativeIds {
                issue_id: result.id.clone(),
                similarity_id: result.similarity_id.as_ref().and_then(scalar_to_string),
                attack_vector_id: result.attack_vector_id.clone(),
                ..Default::default()
            },
            scan_id: Some(scan_id.to_string()),
            state: Some(result.state.clone()),
            severity: Some(result.severity.clone()),
            ..Default::default()
        }],
        vendor: "checkmarx",
        external_id: external_id(&result, &sink, &title),
        file: sink
            .as_ref()
            .map_or_else(|| title.clone(), |e| e.file.clone()),
        line_start: sink.as_ref().map_or(1, |e| e.line),
        line_end: sink.as_ref().map_or(1, |e| e.line),
        title,
        cwe: result.cwe_id.map(|id| format!("CWE-{id}")),
        severity: parse_severity(&result.severity),
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

    fn config_for(data: &MockServer, iam: &MockServer) -> CheckmarxConfig {
        let mut cfg = CheckmarxConfig::new(data.uri(), iam.uri(), "acme", "api-key", "proj-1");
        cfg.branch = Some("main".to_string());
        cfg
    }

    async fn mount_token(iam: &MockServer) {
        Mock::given(method("POST"))
            .and(path("/auth/realms/acme/protocol/openid-connect/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "tok-1",
                "expires_in": 300,
                "token_type": "bearer"
            })))
            // Exactly once, even though every successful fetch_findings()
            // calls access_token() at least twice (scans, then results):
            // proves the cached token is genuinely reused.
            .expect(1)
            .mount(iam)
            .await;
    }

    fn scan(id: &str, created_at: &str) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "status": "Completed",
            "projectId": "proj-1",
            "branch": "main",
            "createdAt": created_at
        })
    }

    /// Field names and casing taken from `SAST_RESULTS.yaml`'s own
    /// `SastResult`/`ResultNode` schemas: `cweID` and `similarityID` with
    /// that exact capitalization, `resultHash` rather than a required
    /// `id`, and node paths carrying Checkmarx's leading `/`.
    fn result(similarity_id: i64, file: &str, line: i64) -> serde_json::Value {
        serde_json::json!({
            "resultHash": format!("hash-{similarity_id}"),
            "queryID": 12345,
            "queryName": "SQL_Injection",
            "languageName": "Python",
            "group": "Python_High_Risk",
            "cweID": 89,
            "severity": "HIGH",
            "similarityID": similarity_id,
            "confidenceLevel": 0,
            "status": "NEW",
            "state": "TO_VERIFY",
            "nodes": [
                {"fileName": "/src/entry.py", "line": 1, "column": 3, "name": "request"},
                {"fileName": format!("/{file}"), "line": line, "column": 9, "name": "execute"}
            ]
        })
    }

    async fn mount_scan_list(data: &MockServer, scans: serde_json::Value) {
        Mock::given(method("GET"))
            .and(path("/api/scans"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"totalCount": 1, "scans": scans})),
            )
            .mount(data)
            .await;
    }

    #[tokio::test]
    async fn fetch_findings_picks_the_most_recently_created_completed_scan() {
        let data = MockServer::start().await;
        let iam = MockServer::start().await;
        mount_token(&iam).await;
        Mock::given(method("GET"))
            .and(path("/api/scans"))
            .and(query_param("project-id", "proj-1"))
            .and(query_param("branch", "main"))
            .and(query_param("statuses", "Completed"))
            .and(query_param("sort", "-created_at"))
            .and(header("Accept", ACCEPT_VERSIONED_JSON))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "totalCount": 2,
                "scans": [
                    // Newest first, as `sort=-created_at` asks for — but
                    // the second entry sorts LATER as a plain string, so a
                    // lexical max would pick the wrong scan.
                    scan("new-scan", "2026-06-01T00:00:00-05:00"),
                    scan("old-scan", "2026-06-01T02:00:00+02:00")
                ]
            })))
            .mount(&data)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/sast-results"))
            .and(query_param("scan-id", "new-scan"))
            .and(query_param("include-nodes", "true"))
            .and(query_param("apply-predicates", "true"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "totalCount": 1,
                "results": [result(9911, "src/app.py", 42)]
            })))
            .mount(&data)
            .await;

        let client = CheckmarxClient::new(reqwest::Client::new(), config_for(&data, &iam));
        let findings = client.fetch_findings().await.unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].vendor, "checkmarx");
        assert_eq!(findings[0].external_id, "9911");
        // Repo-relative: Checkmarx's own leading "/" is stripped.
        assert_eq!(findings[0].file, "src/app.py");
        assert_eq!(findings[0].line_start, 42);
        assert_eq!(findings[0].line_end, 42);
        assert_eq!(findings[0].cwe, Some("CWE-89".to_string()));
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0]
            .description
            .contains("Data flow: src/entry.py:1 -> src/app.py:42."));
        assert!(findings[0].description.contains("Triage state: TO_VERIFY."));
    }

    #[tokio::test]
    async fn fetch_findings_sends_the_wanted_state_filter() {
        let data = MockServer::start().await;
        let iam = MockServer::start().await;
        mount_token(&iam).await;
        mount_scan_list(
            &data,
            serde_json::json!([scan("s", "2026-01-01T00:00:00Z")]),
        )
        .await;
        Mock::given(method("GET"))
            .and(path("/api/sast-results"))
            .and(query_param("state", "TO_VERIFY"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"totalCount": 0, "results": []})),
            )
            .mount(&data)
            .await;

        let client = CheckmarxClient::new(reqwest::Client::new(), config_for(&data, &iam));

        assert!(client.fetch_findings().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn fetch_findings_drops_triaged_out_results_the_server_still_returned() {
        let data = MockServer::start().await;
        let iam = MockServer::start().await;
        mount_token(&iam).await;
        mount_scan_list(
            &data,
            serde_json::json!([scan("s", "2026-01-01T00:00:00Z")]),
        )
        .await;
        let mut not_exploitable = result(1, "src/a.py", 1);
        not_exploitable["state"] = serde_json::json!("not_exploitable");
        let mut proposed = result(2, "src/b.py", 2);
        proposed["state"] = serde_json::json!("Proposed_Not_Exploitable");
        Mock::given(method("GET"))
            .and(path("/api/sast-results"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "totalCount": 3,
                "results": [not_exploitable, proposed, result(3, "src/c.py", 3)]
            })))
            .mount(&data)
            .await;

        let client = CheckmarxClient::new(reqwest::Client::new(), config_for(&data, &iam));
        let findings = client.fetch_findings().await.unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].file, "src/c.py");
    }

    #[tokio::test]
    async fn fetch_findings_prefers_explicit_sink_and_source_fields_over_the_node_array() {
        let data = MockServer::start().await;
        let iam = MockServer::start().await;
        mount_token(&iam).await;
        mount_scan_list(
            &data,
            serde_json::json!([scan("s", "2026-01-01T00:00:00Z")]),
        )
        .await;
        let mut with_sink = result(7, "src/from-nodes.py", 99);
        with_sink["sinkFileName"] = serde_json::json!("/src/sink.py");
        with_sink["sinkLine"] = serde_json::json!(120);
        with_sink["sourceFileName"] = serde_json::json!("/src/source.py");
        with_sink["sourceLine"] = serde_json::json!(4);
        Mock::given(method("GET"))
            .and(path("/api/sast-results"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"totalCount": 1, "results": [with_sink]})),
            )
            .mount(&data)
            .await;

        let client = CheckmarxClient::new(reqwest::Client::new(), config_for(&data, &iam));
        let findings = client.fetch_findings().await.unwrap();

        assert_eq!(findings[0].file, "src/sink.py");
        assert_eq!(findings[0].line_start, 120);
        assert!(findings[0]
            .description
            .contains("Data flow: src/source.py:4 -> src/sink.py:120."));
    }

    #[tokio::test]
    async fn fetch_findings_reauthenticates_once_on_a_401_during_the_results_fetch() {
        let data = MockServer::start().await;
        let iam = MockServer::start().await;
        // Two token exchanges expected here, not one: the cached token is
        // invalidated by the 401 and re-fetched.
        Mock::given(method("POST"))
            .and(path("/auth/realms/acme/protocol/openid-connect/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "tok-1", "expires_in": 300, "token_type": "bearer"
            })))
            .expect(2)
            .mount(&iam)
            .await;
        mount_scan_list(
            &data,
            serde_json::json!([scan("s", "2026-01-01T00:00:00Z")]),
        )
        .await;
        Mock::given(method("GET"))
            .and(path("/api/sast-results"))
            .respond_with(ResponseTemplate::new(401).set_body_string("token expired"))
            .up_to_n_times(1)
            .mount(&data)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/sast-results"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "totalCount": 1,
                "results": [result(1, "src/app.py", 5)]
            })))
            .mount(&data)
            .await;

        let client = CheckmarxClient::new(reqwest::Client::new(), config_for(&data, &iam));
        let findings = client.fetch_findings().await.unwrap();

        assert_eq!(findings.len(), 1);
    }

    #[tokio::test]
    async fn fetch_findings_gives_up_on_a_second_consecutive_401() {
        let data = MockServer::start().await;
        let iam = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/auth/realms/acme/protocol/openid-connect/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "tok-1", "expires_in": 300, "token_type": "bearer"
            })))
            .mount(&iam)
            .await;
        mount_scan_list(
            &data,
            serde_json::json!([scan("s", "2026-01-01T00:00:00Z")]),
        )
        .await;
        Mock::given(method("GET"))
            .and(path("/api/sast-results"))
            .respond_with(ResponseTemplate::new(401).set_body_string("nope"))
            .mount(&data)
            .await;

        let client = CheckmarxClient::new(reqwest::Client::new(), config_for(&data, &iam));
        let err = client.fetch_findings().await.unwrap_err();

        assert!(matches!(err, CheckmarxError::Http { status: 401, .. }));
    }

    #[tokio::test]
    async fn fetch_findings_paginates_results_until_total_count_is_reached() {
        let data = MockServer::start().await;
        let iam = MockServer::start().await;
        mount_token(&iam).await;
        mount_scan_list(
            &data,
            serde_json::json!([scan("scan-1", "2026-01-01T00:00:00Z")]),
        )
        .await;
        let full_page: Vec<_> = (0..RESULTS_PAGE_SIZE)
            .map(|i| result(i as i64, "src/app.py", 1))
            .collect();
        Mock::given(method("GET"))
            .and(path("/api/sast-results"))
            .and(query_param("offset", "0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "totalCount": RESULTS_PAGE_SIZE + 1,
                "results": full_page
            })))
            .mount(&data)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/sast-results"))
            .and(query_param("offset", RESULTS_PAGE_SIZE.to_string()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "totalCount": RESULTS_PAGE_SIZE + 1,
                "results": [result(999_999, "src/app.py", 2)]
            })))
            .mount(&data)
            .await;

        let client = CheckmarxClient::new(reqwest::Client::new(), config_for(&data, &iam));
        let findings = client.fetch_findings().await.unwrap();

        assert_eq!(findings.len() as u32, RESULTS_PAGE_SIZE + 1);
    }

    #[tokio::test]
    async fn fetch_findings_errors_when_no_completed_scan_exists() {
        let data = MockServer::start().await;
        let iam = MockServer::start().await;
        mount_token(&iam).await;
        mount_scan_list(&data, serde_json::json!([])).await;

        let client = CheckmarxClient::new(reqwest::Client::new(), config_for(&data, &iam));
        let err = client.fetch_findings().await.unwrap_err();

        assert!(matches!(err, CheckmarxError::ScanNotFound { .. }));
    }

    #[tokio::test]
    async fn fetch_findings_propagates_a_token_endpoint_failure() {
        let data = MockServer::start().await;
        let iam = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/auth/realms/acme/protocol/openid-connect/token"))
            .respond_with(ResponseTemplate::new(401).set_body_string("invalid_grant"))
            .mount(&iam)
            .await;

        let client = CheckmarxClient::new(reqwest::Client::new(), config_for(&data, &iam));
        let err = client.fetch_findings().await.unwrap_err();

        assert!(matches!(err, CheckmarxError::Http { status: 401, .. }));
    }

    #[tokio::test]
    async fn fetch_findings_propagates_a_malformed_token_response() {
        let data = MockServer::start().await;
        let iam = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/auth/realms/acme/protocol/openid-connect/token"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
            .mount(&iam)
            .await;

        let client = CheckmarxClient::new(reqwest::Client::new(), config_for(&data, &iam));
        let err = client.fetch_findings().await.unwrap_err();

        assert!(matches!(err, CheckmarxError::Json { .. }));
    }

    #[tokio::test]
    async fn fetch_findings_propagates_a_non_success_status_on_the_scans_call() {
        let data = MockServer::start().await;
        let iam = MockServer::start().await;
        mount_token(&iam).await;
        Mock::given(method("GET"))
            .and(path("/api/scans"))
            .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
            .mount(&data)
            .await;

        let client = CheckmarxClient::new(reqwest::Client::new(), config_for(&data, &iam));
        let err = client.fetch_findings().await.unwrap_err();

        assert!(matches!(err, CheckmarxError::Http { status: 500, .. }));
    }

    #[tokio::test]
    async fn fetch_findings_propagates_a_malformed_scans_response() {
        let data = MockServer::start().await;
        let iam = MockServer::start().await;
        mount_token(&iam).await;
        Mock::given(method("GET"))
            .and(path("/api/scans"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
            .mount(&data)
            .await;

        let client = CheckmarxClient::new(reqwest::Client::new(), config_for(&data, &iam));
        let err = client.fetch_findings().await.unwrap_err();

        assert!(matches!(err, CheckmarxError::Json { .. }));
    }

    #[tokio::test]
    async fn fetch_findings_propagates_a_malformed_results_response() {
        let data = MockServer::start().await;
        let iam = MockServer::start().await;
        mount_token(&iam).await;
        mount_scan_list(
            &data,
            serde_json::json!([scan("scan-1", "2026-01-01T00:00:00Z")]),
        )
        .await;
        Mock::given(method("GET"))
            .and(path("/api/sast-results"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
            .mount(&data)
            .await;

        let client = CheckmarxClient::new(reqwest::Client::new(), config_for(&data, &iam));
        let err = client.fetch_findings().await.unwrap_err();

        assert!(matches!(err, CheckmarxError::Json { .. }));
    }

    #[tokio::test]
    async fn fetch_findings_propagates_a_transport_failure() {
        let mut cfg = CheckmarxConfig::new(
            "http://127.0.0.1:1",
            "http://127.0.0.1:1",
            "acme",
            "key",
            "proj",
        );
        cfg.branch = None;
        let client = CheckmarxClient::new(reqwest::Client::new(), cfg);

        let err = client.fetch_findings().await.unwrap_err();

        assert!(matches!(err, CheckmarxError::Request { .. }));
    }

    #[tokio::test]
    async fn a_result_with_no_query_name_or_location_falls_back_to_a_generic_title() {
        let data = MockServer::start().await;
        let iam = MockServer::start().await;
        mount_token(&iam).await;
        mount_scan_list(
            &data,
            serde_json::json!([scan("scan-1", "2026-01-01T00:00:00Z")]),
        )
        .await;
        Mock::given(method("GET"))
            .and(path("/api/sast-results"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "totalCount": 1,
                "results": [{"severity": "LOW", "nodes": []}]
            })))
            .mount(&data)
            .await;

        let client = CheckmarxClient::new(reqwest::Client::new(), config_for(&data, &iam));
        let findings = client.fetch_findings().await.unwrap();

        assert_eq!(findings[0].title, "Checkmarx finding");
        assert_eq!(findings[0].file, "Checkmarx finding");
        assert_eq!(findings[0].external_id, "Checkmarx finding");
        assert_eq!(findings[0].line_start, 1);
        assert_eq!(findings[0].cwe, None);
        assert_eq!(findings[0].severity, Severity::Low);
        assert!(!findings[0].description.contains("Data flow"));
        assert!(!findings[0].description.contains("Triage state"));
    }

    #[tokio::test]
    async fn a_node_missing_a_line_number_defaults_to_one_and_an_unrecognized_severity_maps_to_info(
    ) {
        let data = MockServer::start().await;
        let iam = MockServer::start().await;
        mount_token(&iam).await;
        mount_scan_list(
            &data,
            serde_json::json!([scan("scan-1", "2026-01-01T00:00:00Z")]),
        )
        .await;
        Mock::given(method("GET"))
            .and(path("/api/sast-results"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "totalCount": 1,
                "results": [{
                    "resultHash": "h1",
                    "queryName": "Weird_Finding",
                    "severity": "WEIRD",
                    "nodes": [{"fileName": "/src/app.py"}]
                }]
            })))
            .mount(&data)
            .await;

        let client = CheckmarxClient::new(reqwest::Client::new(), config_for(&data, &iam));
        let findings = client.fetch_findings().await.unwrap();

        assert_eq!(findings[0].line_start, 1);
        assert_eq!(findings[0].file, "src/app.py");
        assert_eq!(findings[0].external_id, "h1");
        assert_eq!(findings[0].severity, Severity::Info);
    }

    #[test]
    fn repo_relative_strips_a_leading_separator() {
        assert_eq!(repo_relative("/src/app.py"), "src/app.py");
        assert_eq!(repo_relative("src/app.py"), "src/app.py");
    }

    #[rstest::rstest]
    #[case("NOT_EXPLOITABLE", true)]
    #[case("not_exploitable", true)]
    #[case("PROPOSED_NOT_EXPLOITABLE", true)]
    #[case(" Proposed_Not_Exploitable ", true)]
    #[case("TO_VERIFY", false)]
    #[case("CONFIRMED", false)]
    #[case("URGENT", false)]
    #[case("some_tenant_custom_state", false)]
    #[case("", false)]
    fn triaged_out_state_recognition(#[case] state: &str, #[case] expected: bool) {
        assert_eq!(is_triaged_out(state), expected);
    }

    fn result_from(value: serde_json::Value) -> SastResult {
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn a_string_similarity_id_is_accepted_as_well_as_a_number() {
        let parsed = result_from(serde_json::json!({"similarityID": "-1234567"}));
        let tpf = to_third_party_finding(parsed, "scan");
        assert_eq!(tpf.external_id, "-1234567");
    }

    #[test]
    fn an_empty_string_similarity_id_falls_through_to_the_result_hash() {
        let parsed = result_from(serde_json::json!({"similarityID": "", "resultHash": "h"}));
        assert_eq!(to_third_party_finding(parsed, "scan").external_id, "h");
    }

    #[test]
    fn a_null_similarity_id_falls_through_to_the_result_hash() {
        let parsed = result_from(serde_json::json!({"similarityID": null, "resultHash": "h"}));
        assert_eq!(to_third_party_finding(parsed, "scan").external_id, "h");
    }

    #[test]
    fn an_empty_result_hash_falls_through_to_the_uppercase_id_field() {
        let parsed = result_from(serde_json::json!({"resultHash": "", "ID": "the-id"}));
        assert_eq!(to_third_party_finding(parsed, "scan").external_id, "the-id");
    }

    #[test]
    fn a_lowercase_id_field_is_accepted_as_an_alias() {
        let parsed = result_from(serde_json::json!({"id": "lower-id"}));
        assert_eq!(
            to_third_party_finding(parsed, "scan").external_id,
            "lower-id"
        );
    }

    #[test]
    fn a_result_with_no_id_of_any_kind_synthesizes_one_from_its_sink() {
        let parsed = result_from(serde_json::json!({
            "queryName": "SQL_Injection",
            "nodes": [{"fileName": "/src/app.py", "line": 42}]
        }));
        assert_eq!(
            to_third_party_finding(parsed, "scan").external_id,
            "SQL_Injection:src/app.py:42"
        );
    }

    #[test]
    fn a_lowercase_cwe_id_key_is_accepted_as_an_alias() {
        let parsed = result_from(serde_json::json!({"cweId": 79}));
        assert_eq!(
            to_third_party_finding(parsed, "scan").cwe,
            Some("CWE-79".to_string())
        );
    }

    #[test]
    fn an_empty_sink_file_name_falls_back_to_the_node_array() {
        let parsed = result_from(serde_json::json!({
            "sinkFileName": "",
            "sinkLine": 9,
            "nodes": [{"fileName": "/src/app.py", "line": 3}]
        }));
        let tpf = to_third_party_finding(parsed, "scan");
        assert_eq!(tpf.file, "src/app.py");
        assert_eq!(tpf.line_start, 3);
    }

    #[test]
    fn a_sink_file_name_with_no_sink_line_defaults_to_line_one() {
        let parsed = result_from(serde_json::json!({"sinkFileName": "/src/app.py"}));
        let tpf = to_third_party_finding(parsed, "scan");
        assert_eq!(tpf.file, "src/app.py");
        assert_eq!(tpf.line_start, 1);
    }

    #[test]
    fn a_result_with_only_source_fields_uses_them_as_its_location() {
        let parsed = result_from(serde_json::json!({
            "sourceFileName": "/src/input.py",
            "sourceLine": 12
        }));
        let tpf = to_third_party_finding(parsed, "scan");
        assert_eq!(tpf.file, "src/input.py");
        assert_eq!(tpf.line_start, 12);
        // Source and sink resolved to the same endpoint, so there is no
        // meaningful flow to describe — but both ends exist, so it is
        // still rendered honestly rather than suppressed.
        assert!(tpf
            .description
            .contains("Data flow: src/input.py:12 -> src/input.py:12."));
    }

    #[test]
    fn a_node_with_an_empty_file_name_is_not_used_as_an_endpoint() {
        let parsed = result_from(serde_json::json!({
            "queryName": "Q",
            "nodes": [{"fileName": "", "line": 3}]
        }));
        assert_eq!(to_third_party_finding(parsed, "scan").file, "Q");
    }
}

#[cfg(test)]
mod provenance_tests {
    use super::*;
    #[test]
    fn native_identity_is_preserved_without_report_id_fallback() {
        let raw: SastResult=serde_json::from_value(serde_json::json!({"ID":"instance","similarityID":123,"attackVectorId":"vector","severity":"HIGH","state":"TO_VERIFY"})).unwrap();
        let finding = to_third_party_finding(raw, "scan");
        let origin = &finding.provider_origins[0];
        assert_eq!(origin.native_ids.similarity_id.as_deref(), Some("123"));
        assert_eq!(
            origin.native_ids.attack_vector_id.as_deref(),
            Some("vector")
        );
        assert_eq!(origin.scan_id.as_deref(), Some("scan"));
        let missing = to_third_party_finding(SastResult::default(), "scan");
        assert!(missing.provider_origins[0]
            .native_ids
            .similarity_id
            .is_none());
    }
}
