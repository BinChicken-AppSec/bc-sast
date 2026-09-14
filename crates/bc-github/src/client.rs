//! Thin GitHub REST API wrapper — only the handful of endpoints needed to
//! fetch a PR's diff, list its existing comments, and post/update review
//! or issue comments. The `reqwest::Client` is built and owned by the
//! caller (matching `bc-gateway-http`'s convention), so this crate has no
//! TLS configuration of its own.

use crate::comment::{extract_loc_marker, extract_marker};
use crate::config::GithubConfig;
use crate::error::GithubError;
use crate::reconcile::{ExistingComment, ExistingKind, ReconcileAction};

const USER_AGENT: &str = "bc-github";

pub struct GithubClient {
    http: reqwest::Client,
    config: GithubConfig,
}

impl GithubClient {
    pub fn new(http: reqwest::Client, config: GithubConfig) -> Self {
        GithubClient { http, config }
    }

    fn repo_url(&self) -> String {
        format!(
            "{}/repos/{}/{}",
            self.config.api_base_url.trim_end_matches('/'),
            self.config.owner,
            self.config.repo
        )
    }

    /// The PR's unified diff, via the GitHub-specific
    /// `application/vnd.github.v3.diff` media type on the pull-request
    /// resource itself (no separate "compare" call needed).
    pub async fn fetch_diff(&self) -> Result<String, GithubError> {
        let url = format!("{}/pulls/{}", self.repo_url(), self.config.pr_number);
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&self.config.token)
            .header("Accept", "application/vnd.github.v3.diff")
            .header("User-Agent", USER_AGENT)
            .send()
            .await
            .map_err(map_reqwest_error)?;
        let status = resp.status();
        let text = resp.text().await.map_err(map_reqwest_error)?;
        if !status.is_success() {
            return Err(GithubError::Http {
                status: status.as_u16(),
                message: text,
            });
        }
        Ok(text)
    }

    /// The PR's head commit SHA — needed to anchor a NEW review comment
    /// (`create_review_comment`'s `commit_id`). A separate request from
    /// [`Self::fetch_diff`] despite hitting the same `/pulls/{n}`
    /// resource: GitHub's content negotiation returns either the raw
    /// diff text OR the full JSON representation per request, never
    /// both — there's no combined call.
    pub async fn fetch_head_sha(&self) -> Result<String, GithubError> {
        let url = format!("{}/pulls/{}", self.repo_url(), self.config.pr_number);
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&self.config.token)
            .header("User-Agent", USER_AGENT)
            .send()
            .await
            .map_err(map_reqwest_error)?;
        let status = resp.status();
        let text = resp.text().await.map_err(map_reqwest_error)?;
        if !status.is_success() {
            return Err(GithubError::Http {
                status: status.as_u16(),
                message: text,
            });
        }
        let value: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| GithubError::Json {
                message: e.to_string(),
            })?;
        value
            .get("head")
            .and_then(|h| h.get("sha"))
            .and_then(|s| s.as_str())
            .map(str::to_string)
            .ok_or_else(|| GithubError::Json {
                message: "PR response missing head.sha".to_string(),
            })
    }

    pub async fn list_review_comments(&self) -> Result<Vec<ExistingComment>, GithubError> {
        let url = format!(
            "{}/pulls/{}/comments",
            self.repo_url(),
            self.config.pr_number
        );
        self.list_comments(&url, ExistingKind::Review).await
    }

    pub async fn list_issue_comments(&self) -> Result<Vec<ExistingComment>, GithubError> {
        let url = format!(
            "{}/issues/{}/comments",
            self.repo_url(),
            self.config.pr_number
        );
        self.list_comments(&url, ExistingKind::Issue).await
    }

    async fn list_comments(
        &self,
        url: &str,
        kind: ExistingKind,
    ) -> Result<Vec<ExistingComment>, GithubError> {
        let resp = self
            .http
            .get(url)
            .bearer_auth(&self.config.token)
            .header("User-Agent", USER_AGENT)
            .send()
            .await
            .map_err(map_reqwest_error)?;
        let status = resp.status();
        let text = resp.text().await.map_err(map_reqwest_error)?;
        if !status.is_success() {
            return Err(GithubError::Http {
                status: status.as_u16(),
                message: text,
            });
        }
        let raw: Vec<serde_json::Value> =
            serde_json::from_str(&text).map_err(|e| GithubError::Json {
                message: e.to_string(),
            })?;
        Ok(raw
            .into_iter()
            .filter_map(|v| {
                let id = v.get("id")?.as_u64()?;
                let body = v.get("body")?.as_str()?;
                let finding_id = extract_marker(body)?;
                Some(ExistingComment {
                    id,
                    finding_id,
                    kind,
                    locator: extract_loc_marker(body),
                })
            })
            .collect())
    }

    /// Posts an inline review comment anchored to `start_line..=end_line`
    /// on `file`'s `RIGHT` (post-image) side. A single-line anchor
    /// (`start_line == end_line`) omits `start_line`/`start_side`
    /// entirely, matching this method's own pre-multi-line-anchor
    /// payload shape exactly — GitHub treats a comment with only `line`/
    /// `side` set as a single-line comment; adding `start_line`/
    /// `start_side` (even equal to `line`/`side`) makes it a multi-line
    /// one instead, which isn't necessary (or harmful) for a one-line
    /// anchor but is avoided here for the least surprising payload.
    pub async fn create_review_comment(
        &self,
        commit_sha: &str,
        file: &str,
        start_line: i64,
        end_line: i64,
        body: &str,
    ) -> Result<(), GithubError> {
        let url = format!(
            "{}/pulls/{}/comments",
            self.repo_url(),
            self.config.pr_number
        );
        let payload = review_comment_payload(commit_sha, file, start_line, end_line, body);
        self.post(&url, &payload).await
    }

    pub async fn update_review_comment(
        &self,
        comment_id: u64,
        body: &str,
    ) -> Result<(), GithubError> {
        let url = format!("{}/pulls/comments/{comment_id}", self.repo_url());
        self.patch(&url, &serde_json::json!({ "body": body })).await
    }

    pub async fn create_issue_comment(&self, body: &str) -> Result<(), GithubError> {
        let url = format!(
            "{}/issues/{}/comments",
            self.repo_url(),
            self.config.pr_number
        );
        self.post(&url, &serde_json::json!({ "body": body })).await
    }

    pub async fn update_issue_comment(
        &self,
        comment_id: u64,
        body: &str,
    ) -> Result<(), GithubError> {
        let url = format!("{}/issues/comments/{comment_id}", self.repo_url());
        self.patch(&url, &serde_json::json!({ "body": body })).await
    }

    async fn post(&self, url: &str, payload: &serde_json::Value) -> Result<(), GithubError> {
        let resp = self
            .http
            .post(url)
            .bearer_auth(&self.config.token)
            .header("User-Agent", USER_AGENT)
            .json(payload)
            .send()
            .await
            .map_err(map_reqwest_error)?;
        self.check_status(resp).await
    }

    async fn patch(&self, url: &str, payload: &serde_json::Value) -> Result<(), GithubError> {
        let resp = self
            .http
            .patch(url)
            .bearer_auth(&self.config.token)
            .header("User-Agent", USER_AGENT)
            .json(payload)
            .send()
            .await
            .map_err(map_reqwest_error)?;
        self.check_status(resp).await
    }

    async fn check_status(&self, resp: reqwest::Response) -> Result<(), GithubError> {
        let status = resp.status();
        if status.is_success() {
            Ok(())
        } else {
            let text = resp.text().await.map_err(map_reqwest_error)?;
            Err(GithubError::Http {
                status: status.as_u16(),
                message: text,
            })
        }
    }

    /// Dispatches a planned [`ReconcileAction`] to the matching API call.
    pub async fn apply(
        &self,
        action: &ReconcileAction,
        commit_sha: &str,
    ) -> Result<(), GithubError> {
        match action {
            ReconcileAction::CreateReview {
                file,
                start_line,
                end_line,
                body,
            } => {
                self.create_review_comment(commit_sha, file, *start_line, *end_line, body)
                    .await
            }
            ReconcileAction::UpdateReview { comment_id, body } => {
                self.update_review_comment(*comment_id, body).await
            }
            ReconcileAction::CreateIssue { body } => self.create_issue_comment(body).await,
            ReconcileAction::UpdateIssue { comment_id, body } => {
                self.update_issue_comment(*comment_id, body).await
            }
        }
    }
}

/// Builds `create_review_comment`'s own JSON payload — pulled out as a
/// pure function so the single-line-vs-multi-line shape is directly
/// unit-testable, without needing a mock server to assert on absence of
/// a field (`wiremock`'s own matcher API has no clean "field absent"
/// assertion to reach for otherwise).
fn review_comment_payload(
    commit_sha: &str,
    file: &str,
    start_line: i64,
    end_line: i64,
    body: &str,
) -> serde_json::Value {
    let mut payload = serde_json::json!({
        "commit_id": commit_sha,
        "path": file,
        "line": end_line,
        "side": "RIGHT",
        "body": body,
    });
    if start_line != end_line {
        payload["start_line"] = serde_json::json!(start_line);
        payload["start_side"] = serde_json::json!("RIGHT");
    }
    payload
}

fn map_reqwest_error(e: reqwest::Error) -> GithubError {
    GithubError::Request {
        message: e.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_string_contains, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn client_for(server: &MockServer, config_fn: impl FnOnce(&mut GithubConfig)) -> GithubClient {
        let mut config = GithubConfig::new("acme", "widgets", 42, "tok");
        config.api_base_url = server.uri();
        config_fn(&mut config);
        GithubClient::new(reqwest::Client::new(), config)
    }

    #[tokio::test]
    async fn fetch_diff_returns_the_response_body_on_success() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/pulls/42"))
            .and(header("Accept", "application/vnd.github.v3.diff"))
            .respond_with(ResponseTemplate::new(200).set_body_string("diff --git a/x b/x"))
            .mount(&server)
            .await;
        let client = client_for(&server, |_| {});
        let diff = client.fetch_diff().await.unwrap();
        assert_eq!(diff, "diff --git a/x b/x");
    }

    #[tokio::test]
    async fn fetch_diff_maps_a_non_success_status_to_http_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/pulls/42"))
            .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
            .mount(&server)
            .await;
        let client = client_for(&server, |_| {});
        let err = client.fetch_diff().await.unwrap_err();
        assert!(matches!(err, GithubError::Http { status: 404, .. }));
    }

    #[tokio::test]
    async fn fetch_diff_maps_a_transport_failure_to_request_error() {
        // Nothing is listening on this port.
        let mut config = GithubConfig::new("acme", "widgets", 42, "tok");
        config.api_base_url = "http://127.0.0.1:1".to_string();
        let client = GithubClient::new(reqwest::Client::new(), config);
        let err = client.fetch_diff().await.unwrap_err();
        assert!(matches!(err, GithubError::Request { .. }));
    }

    #[tokio::test]
    async fn fetch_head_sha_returns_the_head_commit_sha_on_success() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/pulls/42"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"head": {"sha": "abc123"}})),
            )
            .mount(&server)
            .await;
        let client = client_for(&server, |_| {});
        let sha = client.fetch_head_sha().await.unwrap();
        assert_eq!(sha, "abc123");
    }

    #[tokio::test]
    async fn fetch_head_sha_maps_a_non_success_status_to_http_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/pulls/42"))
            .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
            .mount(&server)
            .await;
        let client = client_for(&server, |_| {});
        let err = client.fetch_head_sha().await.unwrap_err();
        assert!(matches!(err, GithubError::Http { status: 404, .. }));
    }

    #[tokio::test]
    async fn fetch_head_sha_maps_malformed_json_to_a_json_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/pulls/42"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
            .mount(&server)
            .await;
        let client = client_for(&server, |_| {});
        let err = client.fetch_head_sha().await.unwrap_err();
        assert!(matches!(err, GithubError::Json { .. }));
    }

    #[tokio::test]
    async fn fetch_head_sha_maps_a_response_missing_head_sha_to_a_json_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/pulls/42"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&server)
            .await;
        let client = client_for(&server, |_| {});
        let err = client.fetch_head_sha().await.unwrap_err();
        assert!(matches!(err, GithubError::Json { .. }));
    }

    #[tokio::test]
    async fn list_review_comments_extracts_only_comments_with_a_marker() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/pulls/42/comments"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"id": 1, "body": format!("hello\n{}", crate::comment::marker("f1"))},
                {"id": 2, "body": "no marker here"},
            ])))
            .mount(&server)
            .await;
        let client = client_for(&server, |_| {});
        let comments = client.list_review_comments().await.unwrap();
        assert_eq!(comments.len(), 1);
        assert_eq!(comments[0].id, 1);
        assert_eq!(comments[0].finding_id, "f1");
        assert_eq!(comments[0].kind, ExistingKind::Review);
    }

    #[tokio::test]
    async fn list_issue_comments_uses_the_issues_endpoint_and_kind() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/issues/42/comments"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"id": 5, "body": crate::comment::marker("f9")},
            ])))
            .mount(&server)
            .await;
        let client = client_for(&server, |_| {});
        let comments = client.list_issue_comments().await.unwrap();
        assert_eq!(comments[0].kind, ExistingKind::Issue);
        assert_eq!(comments[0].finding_id, "f9");
    }

    #[tokio::test]
    async fn list_comments_propagates_a_non_success_status() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/pulls/42/comments"))
            .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
            .mount(&server)
            .await;
        let client = client_for(&server, |_| {});
        let err = client.list_review_comments().await.unwrap_err();
        assert!(matches!(err, GithubError::Http { status: 500, .. }));
    }

    #[tokio::test]
    async fn list_comments_rejects_malformed_json() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/pulls/42/comments"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
            .mount(&server)
            .await;
        let client = client_for(&server, |_| {});
        let err = client.list_review_comments().await.unwrap_err();
        assert!(matches!(err, GithubError::Json { .. }));
    }

    #[tokio::test]
    async fn list_comments_skips_entries_missing_id_or_body() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/pulls/42/comments"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"body": crate::comment::marker("no-id")},
                {"id": 3},
            ])))
            .mount(&server)
            .await;
        let client = client_for(&server, |_| {});
        let comments = client.list_review_comments().await.unwrap();
        assert!(comments.is_empty());
    }

    #[tokio::test]
    async fn create_review_comment_posts_the_expected_payload() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/repos/acme/widgets/pulls/42/comments"))
            .and(body_string_contains("\"line\":10"))
            .and(body_string_contains("\"side\":\"RIGHT\""))
            .respond_with(ResponseTemplate::new(201))
            .mount(&server)
            .await;
        let client = client_for(&server, |_| {});
        client
            .create_review_comment("sha123", "a.py", 10, 10, "body")
            .await
            .unwrap();
    }

    #[test]
    fn review_comment_payload_a_single_line_anchor_omits_start_line_and_start_side() {
        let payload = review_comment_payload("sha", "a.py", 10, 10, "body");
        assert_eq!(payload["line"], 10);
        assert_eq!(payload["side"], "RIGHT");
        assert!(payload.get("start_line").is_none());
        assert!(payload.get("start_side").is_none());
    }

    #[test]
    fn review_comment_payload_a_multi_line_anchor_includes_start_line_and_start_side() {
        let payload = review_comment_payload("sha", "a.py", 8, 12, "body");
        assert_eq!(payload["line"], 12);
        assert_eq!(payload["start_line"], 8);
        assert_eq!(payload["start_side"], "RIGHT");
    }

    #[tokio::test]
    async fn create_review_comment_a_multi_line_anchor_includes_start_line_and_start_side() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/repos/acme/widgets/pulls/42/comments"))
            .and(body_string_contains("\"line\":12"))
            .and(body_string_contains("\"start_line\":8"))
            .and(body_string_contains("\"start_side\":\"RIGHT\""))
            .respond_with(ResponseTemplate::new(201))
            .mount(&server)
            .await;
        let client = client_for(&server, |_| {});
        client
            .create_review_comment("sha123", "a.py", 8, 12, "body")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn update_review_comment_patches_the_expected_url() {
        let server = MockServer::start().await;
        Mock::given(method("PATCH"))
            .and(path("/repos/acme/widgets/pulls/comments/77"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let client = client_for(&server, |_| {});
        client
            .update_review_comment(77, "updated body")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn create_issue_comment_posts_to_the_issues_endpoint() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/repos/acme/widgets/issues/42/comments"))
            .respond_with(ResponseTemplate::new(201))
            .mount(&server)
            .await;
        let client = client_for(&server, |_| {});
        client.create_issue_comment("body").await.unwrap();
    }

    #[tokio::test]
    async fn update_issue_comment_patches_the_expected_url() {
        let server = MockServer::start().await;
        Mock::given(method("PATCH"))
            .and(path("/repos/acme/widgets/issues/comments/8"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let client = client_for(&server, |_| {});
        client.update_issue_comment(8, "body").await.unwrap();
    }

    #[tokio::test]
    async fn post_maps_a_non_success_status_to_http_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/repos/acme/widgets/issues/42/comments"))
            .respond_with(ResponseTemplate::new(422).set_body_string("invalid"))
            .mount(&server)
            .await;
        let client = client_for(&server, |_| {});
        let err = client.create_issue_comment("body").await.unwrap_err();
        assert!(matches!(err, GithubError::Http { status: 422, .. }));
    }

    #[tokio::test]
    async fn patch_maps_a_non_success_status_to_http_error() {
        let server = MockServer::start().await;
        Mock::given(method("PATCH"))
            .and(path("/repos/acme/widgets/issues/comments/8"))
            .respond_with(ResponseTemplate::new(403).set_body_string("forbidden"))
            .mount(&server)
            .await;
        let client = client_for(&server, |_| {});
        let err = client.update_issue_comment(8, "body").await.unwrap_err();
        assert!(matches!(err, GithubError::Http { status: 403, .. }));
    }

    #[tokio::test]
    async fn post_maps_a_transport_failure_to_request_error() {
        let mut config = GithubConfig::new("acme", "widgets", 42, "tok");
        config.api_base_url = "http://127.0.0.1:1".to_string();
        let client = GithubClient::new(reqwest::Client::new(), config);
        let err = client.create_issue_comment("body").await.unwrap_err();
        assert!(matches!(err, GithubError::Request { .. }));
    }

    #[tokio::test]
    async fn apply_dispatches_every_action_kind_to_the_right_call() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/repos/acme/widgets/pulls/42/comments"))
            .respond_with(ResponseTemplate::new(201))
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path("/repos/acme/widgets/pulls/comments/1"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/repos/acme/widgets/issues/42/comments"))
            .respond_with(ResponseTemplate::new(201))
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path("/repos/acme/widgets/issues/comments/2"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let client = client_for(&server, |_| {});

        client
            .apply(
                &ReconcileAction::CreateReview {
                    file: "a.py".to_string(),
                    start_line: 1,
                    end_line: 1,
                    body: "b".to_string(),
                },
                "sha",
            )
            .await
            .unwrap();
        client
            .apply(
                &ReconcileAction::UpdateReview {
                    comment_id: 1,
                    body: "b".to_string(),
                },
                "sha",
            )
            .await
            .unwrap();
        client
            .apply(
                &ReconcileAction::CreateIssue {
                    body: "b".to_string(),
                },
                "sha",
            )
            .await
            .unwrap();
        client
            .apply(
                &ReconcileAction::UpdateIssue {
                    comment_id: 2,
                    body: "b".to_string(),
                },
                "sha",
            )
            .await
            .unwrap();
    }
}
