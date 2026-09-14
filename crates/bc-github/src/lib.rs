//! Thin GitHub PR integration: posts one comment per finding (an inline
//! review comment on diff-touched lines, a fallback conversation comment
//! otherwise), idempotently updated across re-scans via a hidden
//! `<!-- bc:finding-id=<id> -->` marker keyed on the same stable id used
//! for SARIF `partialFingerprints` (see `bc_sarif::finding_id`) — so a
//! finding refers to the same identity everywhere it's surfaced.
//!
//! This crate has no opinion on *which* privileged workflow context calls
//! it — see `docs/github-action.md` for the two-workflow fork-PR-safe
//! pattern this is designed to slot into.

mod client;
mod comment;
mod config;
mod diff;
mod error;
mod fix_comment;
mod reconcile;

pub use client::GithubClient;
pub use comment::{
    extract_marker, marker, plan_comments, render_comment_body, Anchor, PlannedComment,
};
pub use config::GithubConfig;
pub use diff::{fully_diff_touched, parse_diff, parse_single_hunk_fix, SingleHunkFix};
pub use error::GithubError;
pub use fix_comment::{
    fix_marker_id, plan_fix_comments, render_fix_comment_body, render_suggestion_comment_body,
    FixSuggestion,
};
pub use reconcile::{reconcile, ExistingComment, ExistingKind, ReconcileAction};

use bc_model::Finding;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SyncSummary {
    pub created: usize,
    pub updated: usize,
}

/// Fetches the PR's diff and existing comments, plans one comment per
/// finding, reconciles against what's already posted, and applies the
/// resulting creates/updates. Stops at the first failing API call — this
/// is a thin delivery wrapper, not a pipeline stage with its own degrade
/// policy, so a partial-failure retry/continue strategy is left to the
/// caller (e.g. re-running the whole sync on the next scheduled scan).
///
/// `repo_root` is forwarded to [`comment::plan_comments`] so comments are
/// keyed on the code on disk rather than the model's quoted snippet —
/// see that function for why. `None` keeps the pre-existing v1 keying.
pub async fn sync_findings(
    client: &GithubClient,
    findings: &[Finding],
    commit_sha: &str,
    repo_root: Option<&std::path::Path>,
) -> Result<SyncSummary, GithubError> {
    let diff_text = client.fetch_diff().await?;
    let diff_lines = diff::parse_diff(&diff_text);
    let planned = comment::plan_comments(findings, &diff_lines, repo_root);

    let mut existing = client.list_review_comments().await?;
    existing.extend(client.list_issue_comments().await?);

    let actions = reconcile::reconcile(&planned, &existing);
    let mut summary = SyncSummary::default();
    for action in &actions {
        client.apply(action, commit_sha).await?;
        match action {
            ReconcileAction::CreateReview { .. } | ReconcileAction::CreateIssue { .. } => {
                summary.created += 1
            }
            ReconcileAction::UpdateReview { .. } | ReconcileAction::UpdateIssue { .. } => {
                summary.updated += 1
            }
        }
    }
    Ok(summary)
}

/// Posts/updates one fix-suggestion comment per [`FixSuggestion`],
/// idempotently across re-scans via the same marker/reconcile machinery
/// [`sync_findings`] uses — see [`fix_marker_id`] for why a `:fix`-suffixed
/// marker id is enough to keep these from colliding with a finding's own
/// description comment. Fetches the PR's own diff (same call
/// [`sync_findings`] makes) so [`fix_comment::plan_fix_comments`] can
/// anchor the subset of fixes that qualify as a native `\`\`\`suggestion`
/// review comment (`ReconcileAction::CreateReview`/`UpdateReview`) instead
/// of a plain conversation one — `commit_sha` (needed by a real
/// `CreateReview`, unlike the old always-issue-comment behavior) comes
/// from the same PR-head commit the diff itself was fetched against,
/// read off the PR resource's own `head.sha` field.
pub async fn sync_fixes(
    client: &GithubClient,
    fixes: &[FixSuggestion],
) -> Result<SyncSummary, GithubError> {
    let commit_sha = client.fetch_head_sha().await?;
    let diff_text = client.fetch_diff().await?;
    let diff_lines = diff::parse_diff(&diff_text);
    let planned = fix_comment::plan_fix_comments(fixes, &diff_lines);

    let mut existing = client.list_review_comments().await?;
    existing.extend(client.list_issue_comments().await?);

    let actions = reconcile::reconcile(&planned, &existing);
    let mut summary = SyncSummary::default();
    for action in &actions {
        client.apply(action, &commit_sha).await?;
        match action {
            ReconcileAction::CreateReview { .. } | ReconcileAction::CreateIssue { .. } => {
                summary.created += 1
            }
            ReconcileAction::UpdateReview { .. } | ReconcileAction::UpdateIssue { .. } => {
                summary.updated += 1
            }
        }
    }
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_model::VulnClass;
    use wiremock::matchers::{body_string_contains, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn finding(file: &str, line_start: i64) -> Finding {
        Finding {
            provider_origins: Vec::new(),
            chunk_id: "c1".to_string(),
            file: file.to_string(),
            line_start,
            line_end: line_start,
            vuln_class: VulnClass::Injection,
            cwe: None,
            title: "SQL injection".to_string(),
            impact: String::new(),
            description: "desc".to_string(),
            exploit_scenario: String::new(),
            preconditions: Vec::new(),
            recommendation: String::new(),
            code_snippet: "query(x)".to_string(),
            source_ref: None,
            sink_ref: None,
            backfilled_refs: Vec::new(),
            reanchored: Vec::new(),
            compliance_requirements: Vec::new(),
            confidence: 0.9,
            votes: 1,
            duplicates: Vec::new(),
            verdict: None,
            verdict_confidence: None,
            verdict_reason: String::new(),
            cvss_vector: None,
            cvss_score: None,
            cvss_rating: None,
            verifier_reasoning: String::new(),
            vsvs_vector: None,
            vsvs_score: None,
            vsvs_rating: None,
            offensive_priority: None,
            offensive_reason: String::new(),
            related_cwes: Vec::new(),
        }
    }

    fn client_for(server: &MockServer) -> GithubClient {
        let mut config = GithubConfig::new("acme", "widgets", 42, "tok");
        config.api_base_url = server.uri();
        GithubClient::new(reqwest::Client::new(), config)
    }

    // Built via `.join("\n")`, not a backslash-continued literal — see the
    // note in `diff.rs`'s test module on why leading whitespace matters
    // here and would otherwise be silently stripped.
    fn diff_fixture() -> String {
        [
            "diff --git a/app/login.py b/app/login.py",
            "--- a/app/login.py",
            "+++ b/app/login.py",
            "@@ -8,3 +8,4 @@",
            " line8",
            "+line9",
            " line10",
            " line11",
        ]
        .join("\n")
    }

    #[tokio::test]
    async fn sync_findings_creates_a_review_comment_for_a_diff_touched_finding() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/pulls/42"))
            .respond_with(ResponseTemplate::new(200).set_body_string(diff_fixture()))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/pulls/42/comments"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/issues/42/comments"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/repos/acme/widgets/pulls/42/comments"))
            .respond_with(ResponseTemplate::new(201))
            .mount(&server)
            .await;

        let client = client_for(&server);
        let findings = vec![finding("app/login.py", 9)];
        let summary = sync_findings(&client, &findings, "sha123", None)
            .await
            .unwrap();
        assert_eq!(
            summary,
            SyncSummary {
                created: 1,
                updated: 0
            }
        );
    }

    #[tokio::test]
    async fn sync_findings_creates_an_issue_comment_for_a_finding_off_the_diff() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/pulls/42"))
            .respond_with(ResponseTemplate::new(200).set_body_string(diff_fixture()))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/pulls/42/comments"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/issues/42/comments"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/repos/acme/widgets/issues/42/comments"))
            .respond_with(ResponseTemplate::new(201))
            .mount(&server)
            .await;

        let client = client_for(&server);
        // Line 500 is nowhere near the diff above.
        let findings = vec![finding("app/login.py", 500)];
        let summary = sync_findings(&client, &findings, "sha123", None)
            .await
            .unwrap();
        assert_eq!(
            summary,
            SyncSummary {
                created: 1,
                updated: 0
            }
        );
    }

    #[tokio::test]
    async fn sync_findings_updates_a_comment_that_was_already_posted() {
        let server = MockServer::start().await;
        let existing_id = bc_sarif::finding_id(&finding("app/login.py", 9));
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/pulls/42"))
            .respond_with(ResponseTemplate::new(200).set_body_string(diff_fixture()))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/pulls/42/comments"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"id": 55, "body": crate::marker(&existing_id)},
            ])))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/issues/42/comments"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path("/repos/acme/widgets/pulls/comments/55"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let client = client_for(&server);
        let findings = vec![finding("app/login.py", 9)];
        let summary = sync_findings(&client, &findings, "sha123", None)
            .await
            .unwrap();
        assert_eq!(
            summary,
            SyncSummary {
                created: 0,
                updated: 1
            }
        );
    }

    #[tokio::test]
    async fn sync_findings_propagates_a_diff_fetch_failure() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/pulls/42"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let client = client_for(&server);
        let err = sync_findings(&client, &[], "sha", None).await.unwrap_err();
        assert!(matches!(err, GithubError::Http { status: 500, .. }));
    }

    #[tokio::test]
    async fn sync_findings_propagates_a_comment_listing_failure() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/pulls/42"))
            .respond_with(ResponseTemplate::new(200).set_body_string(""))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/pulls/42/comments"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let client = client_for(&server);
        let err = sync_findings(&client, &[], "sha", None).await.unwrap_err();
        assert!(matches!(err, GithubError::Http { status: 500, .. }));
    }

    #[tokio::test]
    async fn sync_findings_propagates_an_apply_failure() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/pulls/42"))
            .respond_with(ResponseTemplate::new(200).set_body_string(""))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/pulls/42/comments"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/issues/42/comments"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/repos/acme/widgets/issues/42/comments"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let client = client_for(&server);
        let findings = vec![finding("app/login.py", 500)];
        let err = sync_findings(&client, &findings, "sha", None)
            .await
            .unwrap_err();
        assert!(matches!(err, GithubError::Http { status: 500, .. }));
    }

    #[tokio::test]
    async fn sync_findings_with_no_findings_and_nothing_posted_is_a_no_op() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/pulls/42"))
            .respond_with(ResponseTemplate::new(200).set_body_string(""))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/pulls/42/comments"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/issues/42/comments"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&server)
            .await;
        let client = client_for(&server);
        let summary = sync_findings(&client, &[], "sha", None).await.unwrap();
        assert_eq!(summary, SyncSummary::default());
    }

    fn fix(finding_id: &str) -> FixSuggestion {
        FixSuggestion {
            finding_id: finding_id.to_string(),
            diff: "diff --git a/x b/x\n+fixed".to_string(),
        }
    }

    /// Mocks the two GETs `sync_fixes` now makes against the PR resource
    /// itself before ever listing comments: `fetch_head_sha` (default
    /// JSON representation) and `fetch_diff` (the `.v3.diff` media type).
    async fn mount_pr_resource(server: &MockServer, head_sha: &str, diff: &str) {
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/pulls/42"))
            .and(header("Accept", "application/vnd.github.v3.diff"))
            .respond_with(ResponseTemplate::new(200).set_body_string(diff))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/pulls/42"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"head": {"sha": head_sha}})),
            )
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn sync_fixes_creates_an_issue_comment_for_a_new_fix() {
        let server = MockServer::start().await;
        mount_pr_resource(&server, "sha123", "").await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/pulls/42/comments"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/issues/42/comments"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/repos/acme/widgets/issues/42/comments"))
            .respond_with(ResponseTemplate::new(201))
            .mount(&server)
            .await;

        let client = client_for(&server);
        let summary = sync_fixes(&client, &[fix("f1")]).await.unwrap();
        assert_eq!(
            summary,
            SyncSummary {
                created: 1,
                updated: 0
            }
        );
    }

    #[tokio::test]
    async fn sync_fixes_updates_a_fix_comment_that_was_already_posted() {
        let server = MockServer::start().await;
        mount_pr_resource(&server, "sha123", "").await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/pulls/42/comments"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/issues/42/comments"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"id": 9, "body": crate::marker(&crate::fix_marker_id("f1"))},
            ])))
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path("/repos/acme/widgets/issues/comments/9"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let client = client_for(&server);
        let summary = sync_fixes(&client, &[fix("f1")]).await.unwrap();
        assert_eq!(
            summary,
            SyncSummary {
                created: 0,
                updated: 1
            }
        );
    }

    #[tokio::test]
    async fn sync_fixes_a_fix_comment_never_collides_with_that_finding_s_own_description_comment() {
        let server = MockServer::start().await;
        mount_pr_resource(&server, "sha123", "").await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/pulls/42/comments"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&server)
            .await;
        // An existing comment for the PLAIN finding id (its own
        // description comment, posted by `sync_findings`) must not be
        // mistaken for an existing fix comment.
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/issues/42/comments"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"id": 1, "body": crate::marker("f1")},
            ])))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/repos/acme/widgets/issues/42/comments"))
            .respond_with(ResponseTemplate::new(201))
            .mount(&server)
            .await;

        let client = client_for(&server);
        let summary = sync_fixes(&client, &[fix("f1")]).await.unwrap();
        assert_eq!(
            summary,
            SyncSummary {
                created: 1,
                updated: 0
            }
        );
    }

    #[tokio::test]
    async fn sync_fixes_anchors_a_single_hunk_fix_fully_covered_by_the_prs_own_diff() {
        let server = MockServer::start().await;
        // The PR's own diff touches app/login.py lines 8-11 — the fix
        // below replaces line 9 only, entirely inside that range.
        mount_pr_resource(&server, "sha123", &diff_fixture()).await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/pulls/42/comments"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/issues/42/comments"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/repos/acme/widgets/pulls/42/comments"))
            .and(body_string_contains("```suggestion"))
            .respond_with(ResponseTemplate::new(201))
            .mount(&server)
            .await;

        let client = client_for(&server);
        let anchored_fix = FixSuggestion {
            finding_id: "f1".to_string(),
            diff: [
                "diff --git a/app/login.py b/app/login.py",
                "--- a/app/login.py",
                "+++ b/app/login.py",
                "@@ -9,1 +9,1 @@",
                "+fixed_line9",
            ]
            .join("\n"),
        };
        let summary = sync_fixes(&client, &[anchored_fix]).await.unwrap();
        assert_eq!(
            summary,
            SyncSummary {
                created: 1,
                updated: 0
            }
        );
    }

    #[tokio::test]
    async fn sync_fixes_propagates_a_head_sha_fetch_failure() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/pulls/42"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let client = client_for(&server);
        let err = sync_fixes(&client, &[fix("f1")]).await.unwrap_err();
        assert!(matches!(err, GithubError::Http { status: 500, .. }));
    }

    #[tokio::test]
    async fn sync_fixes_propagates_a_comment_listing_failure() {
        let server = MockServer::start().await;
        mount_pr_resource(&server, "sha123", "").await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/pulls/42/comments"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let client = client_for(&server);
        let err = sync_fixes(&client, &[fix("f1")]).await.unwrap_err();
        assert!(matches!(err, GithubError::Http { status: 500, .. }));
    }

    #[tokio::test]
    async fn sync_fixes_propagates_an_apply_failure() {
        let server = MockServer::start().await;
        mount_pr_resource(&server, "sha123", "").await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/pulls/42/comments"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/issues/42/comments"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/repos/acme/widgets/issues/42/comments"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let client = client_for(&server);
        let err = sync_fixes(&client, &[fix("f1")]).await.unwrap_err();
        assert!(matches!(err, GithubError::Http { status: 500, .. }));
    }

    #[tokio::test]
    async fn sync_fixes_with_no_fixes_and_nothing_posted_is_a_no_op() {
        let server = MockServer::start().await;
        mount_pr_resource(&server, "sha123", "").await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/pulls/42/comments"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/issues/42/comments"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&server)
            .await;
        let client = client_for(&server);
        let summary = sync_fixes(&client, &[]).await.unwrap();
        assert_eq!(summary, SyncSummary::default());
    }
}
