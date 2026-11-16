use super::*;
#[tokio::test]
async fn resolve_diff_scope_is_a_no_op_when_the_flag_is_unset() {
    let out = resolve_diff_scope(false, None).await.unwrap();
    assert!(!out.active);
    assert!(out.changed_files.is_empty());
}
#[tokio::test]
async fn resolve_diff_scope_errors_without_a_github_client() {
    let message = resolve_diff_scope(true, None).await.err().unwrap();
    assert!(message.contains("--diff-scope requires"));
}
#[tokio::test]
async fn resolve_diff_scope_fetches_and_parses_the_pr_diff() {
    let server = diff_server("--- a/a.py\n+++ b/a.py\n@@ -1,1 +1,2 @@\n x = 1\n+y = 2\n").await;
    let github = github_client_for(&server);
    let out = resolve_diff_scope(true, Some(&github)).await.unwrap();
    assert!(out.active);
    assert_eq!(
        out.changed_files.get("a.py"),
        Some(&std::collections::BTreeSet::from([1i64, 2i64]))
    );
}
#[tokio::test]
async fn resolve_diff_scope_is_active_with_no_changed_files_for_a_rename_only_diff() {
    let diff = [
        "diff --git a/old_name.py b/new_name.py",
        "similarity index 100%",
        "rename from old_name.py",
        "rename to new_name.py",
    ]
    .join("\n");
    let server = diff_server(&diff).await;
    let github = github_client_for(&server);
    let out = resolve_diff_scope(true, Some(&github)).await.unwrap();
    assert!(out.active);
    assert!(out.changed_files.is_empty());
}
#[tokio::test]
async fn resolve_diff_scope_is_active_with_no_changed_files_for_an_empty_body() {
    let server = diff_server("").await;
    let github = github_client_for(&server);
    let out = resolve_diff_scope(true, Some(&github)).await.unwrap();
    assert!(out.active);
    assert!(out.changed_files.is_empty());
}
#[tokio::test]
async fn resolve_diff_scope_propagates_a_fetch_failure() {
    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/repos/acme/widgets/pulls/1"))
        .respond_with(wiremock::ResponseTemplate::new(500))
        .mount(&server)
        .await;
    let github = github_client_for(&server);
    let result = resolve_diff_scope(true, Some(&github)).await;
    assert!(result.is_err());
}

#[test]
fn pr_comments_defaults_to_off() {
    let cli = Cli::try_parse_from([
        "appsec-scan",
        "--repo",
        "/tmp/repo",
        "--gateway-base-url",
        "http://127.0.0.1:0",
    ])
    .unwrap();
    assert!(!cli.pr_comments);
}
#[test]
fn pr_comments_is_a_bare_opt_in_flag() {
    let cli = Cli::try_parse_from([
        "appsec-scan",
        "--repo",
        "/tmp/repo",
        "--gateway-base-url",
        "http://127.0.0.1:0",
        "--pr-comments",
        "--diff-scope",
    ])
    .unwrap();
    assert!(cli.pr_comments);
}
#[test]
fn batch_mode_refuses_diff_scope_rather_than_ignoring_it() {
    let mut c = cli(Path::new("/repo"));
    c.repo_file = Some(PathBuf::from("/manifest.csv"));
    c.diff_scope = true;
    let error = check_batch_diff_scope(&c).unwrap_err();
    assert!(
        error.contains("cannot be combined with --repo-file"),
        "{error}"
    );

    c.diff_scope = false;
    assert!(check_batch_diff_scope(&c).is_ok());

    c.repo_file = None;
    c.diff_scope = true;
    assert!(check_batch_diff_scope(&c).is_ok());
}
#[test]
fn check_pr_comment_scope_is_a_no_op_without_the_flag() {
    let mut c = cli(Path::new("/repo"));
    c.diff_scope = false;
    assert!(check_pr_comment_scope(&c).is_ok());
    c.diff_scope = true;
    assert!(check_pr_comment_scope(&c).is_ok());
}
#[test]
fn check_pr_comment_scope_rejects_the_flag_without_a_diff_scope() {
    let mut c = cli(Path::new("/repo"));
    c.pr_comments = true;
    let message = check_pr_comment_scope(&c).err().unwrap();
    assert!(message.contains("--pr-comments"), "{message}");
    assert!(message.contains("--diff-scope"), "{message}");
}
#[test]
fn check_pr_comment_scope_accepts_the_flag_with_a_diff_scope() {
    let mut c = cli(Path::new("/repo"));
    c.pr_comments = true;
    c.diff_scope = true;
    assert!(check_pr_comment_scope(&c).is_ok());
}
#[test]
fn diff_scope_boundary_follows_the_active_flag_not_the_file_count() {
    let inactive = DiffScope {
        active: false,
        changed_files: std::collections::BTreeMap::new(),
    };
    assert!(!inactive.boundary().is_active());
    assert!(inactive.boundary().allows("anything.py"));

    let renamed_only = DiffScope {
        active: true,
        changed_files: std::collections::BTreeMap::new(),
    };
    assert!(renamed_only.boundary().is_active());
    assert!(!renamed_only.boundary().allows("anything.py"));

    let scoped = DiffScope {
        active: true,
        changed_files: std::collections::BTreeMap::from([(
            "app.py".to_string(),
            std::collections::BTreeSet::from([1i64]),
        )]),
    };
    assert!(scoped.boundary().allows("app.py"));
    assert!(!scoped.boundary().allows("vendor/old.py"));
}
