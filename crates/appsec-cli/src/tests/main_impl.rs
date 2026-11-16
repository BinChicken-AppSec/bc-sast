use super::*;
#[tokio::test]
async fn main_impl_refuses_a_retired_model_before_any_spend() {
    let dir = tempfile::tempdir().unwrap();
    let mut c = cli(dir.path());
    c.model = "claude-2.1".to_string();
    c.skip_preflight = false;
    let err = main_impl(c).await.err().unwrap();
    assert!(err.contains("claude-2.1 is retired"), "{err}");
    assert!(err.contains("claude-sonnet-5"), "{err}");
}
#[test]
fn build_llm_client_constructs_an_anthropic_client() {
    let mut c = cli(Path::new("/repo"));
    c.dialect = Dialect::Anthropic;
    assert!(build_llm_client(&c).is_ok());
}
#[test]
fn build_llm_client_rejects_a_malformed_ca_cert() {
    let dir = tempfile::tempdir().unwrap();
    let bad_pem = dir.path().join("bad.pem");
    std::fs::write(&bad_pem, "not a pem file").unwrap();
    let mut c = cli(dir.path());
    c.ca_cert = Some(bad_pem);
    assert!(build_llm_client(&c).is_err());
}
#[test]
fn streaming_is_off_unless_asked_for() {
    assert!(!stream_large_responses(&cli(Path::new("/repo"))));
}
#[test]
fn the_flag_enables_streaming_on_its_own() {
    let mut c = cli(Path::new("/repo"));
    c.stream_large_responses = true;
    assert!(stream_large_responses(&c));
    assert!(build_llm_client(&c).is_ok());
}
#[test]
fn a_config_key_enables_streaming_without_the_flag() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("c.yaml");
    std::fs::write(&config, "llm:\n  stream_large_responses: true\n").unwrap();
    let mut c = cli(Path::new("/repo"));
    c.config = Some(config);
    assert!(stream_large_responses(&c));
}
#[test]
fn the_flag_wins_over_a_config_that_disables_streaming() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("c.yaml");
    std::fs::write(&config, "llm:\n  stream_large_responses: false\n").unwrap();
    let mut c = cli(Path::new("/repo"));
    c.config = Some(config.clone());
    assert!(!stream_large_responses(&c));
    c.stream_large_responses = true;
    assert!(stream_large_responses(&c));
}
#[test]
fn an_unloadable_config_is_read_as_no_opinion() {
    let mut c = cli(Path::new("/repo"));
    c.config = Some(PathBuf::from("/nonexistent/config.yaml"));
    assert!(!stream_large_responses(&c));
    assert!(build_llm_client(&c).is_ok());
}
#[test]
fn build_github_client_returns_none_when_args_are_absent() {
    assert!(build_github_client(&cli(Path::new("/repo")))
        .unwrap()
        .is_none());
}
#[test]
fn build_github_client_returns_none_when_only_some_args_are_present() {
    let mut c = cli(Path::new("/repo"));
    c.github_token = Some("tok".to_string());
    c.github_repo = Some("acme/widgets".to_string());
    assert!(build_github_client(&c).unwrap().is_none());
}
#[test]
fn build_github_client_builds_a_client_when_all_args_are_present() {
    let mut c = cli(Path::new("/repo"));
    c.github_token = Some("tok".to_string());
    c.github_repo = Some("acme/widgets".to_string());
    c.pr_number = Some(7);
    assert!(build_github_client(&c).unwrap().is_some());
}
#[test]
fn build_github_client_rejects_a_repo_without_an_owner_slash_name_separator() {
    let mut c = cli(Path::new("/repo"));
    c.github_token = Some("tok".to_string());
    c.github_repo = Some("not-owner-slash-name".to_string());
    c.pr_number = Some(7);
    assert!(build_github_client(&c).is_err());
}
#[tokio::test]
async fn main_impl_refuses_pr_comments_without_a_diff_scope_before_anything_else_runs() {
    let mut c = cli(Path::new("/repo"));
    c.pr_comments = true;
    c.gc = true;
    let message = main_impl(c).await.err().unwrap();
    assert!(
        message.contains("--pr-comments requires --diff-scope"),
        "{message}"
    );
}
#[test]
fn pr_comment_target_withholds_the_client_when_posting_was_not_requested() {
    let mut c = cli(Path::new("/repo"));
    c.github_token = Some("tok".to_string());
    c.github_repo = Some("acme/widgets".to_string());
    c.pr_number = Some(1);
    c.diff_scope = true;
    let github = build_github_client(&c).unwrap();
    assert!(github.is_some());
    assert!(pr_comment_target(&c, github).is_none());
}
#[test]
fn pr_comment_target_passes_the_client_through_once_posting_is_requested() {
    let mut c = cli(Path::new("/repo"));
    c.github_token = Some("tok".to_string());
    c.github_repo = Some("acme/widgets".to_string());
    c.pr_number = Some(1);
    c.diff_scope = true;
    c.pr_comments = true;
    let github = build_github_client(&c).unwrap();
    assert!(pr_comment_target(&c, github).is_some());
}
#[test]
fn pr_comment_target_has_nothing_to_pass_through_without_credentials() {
    let mut c = cli(Path::new("/repo"));
    c.pr_comments = true;
    c.diff_scope = true;
    assert!(pr_comment_target(&c, None).is_none());
}
#[tokio::test]
async fn main_impl_requires_github_args_for_post_fixes_from() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_remediation_export(
        dir.path(),
        &RemediationExport {
            totals: Default::default(),
            rollup: Default::default(),
            refused: None,
            results: Vec::new(),
        },
    );

    let mut c = cli(Path::new("/repo"));
    c.post_fixes_from = Some(path);
    let result = main_impl(c).await;
    assert!(result.unwrap_err().contains("--post-fixes-from requires"));
}
#[tokio::test]
async fn main_impl_requires_github_args_for_post_comments_from() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_export(
        dir.path(),
        &FindingsExport {
            commit_sha: "sha".to_string(),
            findings: Vec::new(),
        },
    );

    let mut c = cli(Path::new("/repo"));
    c.post_comments_from = Some(path);
    let result = main_impl(c).await;
    assert!(result
        .unwrap_err()
        .contains("--post-comments-from requires"));
}
#[tokio::test]
async fn main_impl_requires_github_args_for_diff_scope() {
    let mut c = cli(Path::new("/repo"));
    c.diff_scope = true;
    let result = main_impl(c).await;
    assert!(result.unwrap_err().contains("--diff-scope requires"));
}
#[tokio::test]
async fn main_impl_propagates_an_invalid_remediate_top_value() {
    let dir = tempfile::tempdir().unwrap();
    let mut c = cli(dir.path());
    c.remediate = true;
    c.top = Some("not-a-number".to_string());
    let result = main_impl(c).await;
    assert!(result.is_err());
}
#[test]
fn non_empty_treats_an_empty_string_as_absent() {
    assert_eq!(non_empty(""), None);
    assert_eq!(non_empty("s1"), Some("s1"));
}
#[test]
fn parse_stop_after_is_none_for_an_empty_string() {
    assert_eq!(parse_stop_after("").unwrap(), None);
}
#[test]
fn parse_stop_after_is_case_insensitive() {
    assert_eq!(parse_stop_after("s1").unwrap(), Some(StopAfterArg::S1));
    assert_eq!(parse_stop_after("S1").unwrap(), Some(StopAfterArg::S1));
    assert_eq!(parse_stop_after("s8").unwrap(), Some(StopAfterArg::S8));
    assert_eq!(parse_stop_after("S9").unwrap(), Some(StopAfterArg::S9));
}
#[test]
fn parse_stop_after_rejects_an_unrecognized_value() {
    assert!(parse_stop_after("s10").is_err());
}
#[tokio::test]
async fn main_impl_propagates_an_invalid_stop_after_value() {
    let dir = tempfile::tempdir().unwrap();
    let mut c = cli(dir.path());
    c.stop_after = "not-a-stage".to_string();
    let result = main_impl(c).await;
    assert!(result.unwrap_err().contains("invalid --stop-after"));
}
#[tokio::test]
async fn main_impl_treats_an_empty_stop_after_as_not_provided() {
    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::path("/chat/completions"))
        .respond_with(wiremock::ResponseTemplate::new(400).set_body_string("bad request"))
        .mount(&server)
        .await;

    let dir = setup_repo();
    let mut c = cli(dir.path());
    c.gateway_base_url = server.uri();
    c.stop_after = String::new();
    let result = main_impl(c).await;
    assert!(!result.unwrap_err().contains("invalid --stop-after"));
}
#[tokio::test]
async fn main_impl_propagates_a_malformed_scan_config() {
    let repo_dir = tempfile::tempdir().unwrap();
    let config_dir = tempfile::tempdir().unwrap();
    let config_path = config_dir.path().join("config.yaml");
    std::fs::write(&config_path, "not: [a, valid\n").unwrap();
    let mut c = cli(repo_dir.path());
    c.config = Some(config_path);
    let result = main_impl(c).await;
    assert!(result.is_err());
}
#[tokio::test]
async fn main_impl_propagates_a_malformed_ca_cert() {
    let dir = tempfile::tempdir().unwrap();
    let bad_pem = dir.path().join("bad.pem");
    std::fs::write(&bad_pem, "not a pem file").unwrap();
    let mut c = cli(dir.path());
    c.ca_cert = Some(bad_pem);
    let result = main_impl(c).await;
    assert!(result.is_err());
}
#[tokio::test]
async fn main_impl_propagates_a_malformed_github_repo_for_post_comments_from() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_export(
        dir.path(),
        &FindingsExport {
            commit_sha: "sha".to_string(),
            findings: Vec::new(),
        },
    );

    let mut c = cli(Path::new("/repo"));
    c.post_comments_from = Some(path);
    c.github_token = Some("tok".to_string());
    c.github_repo = Some("not-owner-slash-name".to_string());
    c.pr_number = Some(7);
    let result = main_impl(c).await;
    assert!(result.unwrap_err().contains("owner/name"));
}
#[tokio::test]
async fn main_impl_propagates_a_malformed_github_repo_on_the_scan_path() {
    let dir = tempfile::tempdir().unwrap();
    let mut c = cli(dir.path());
    c.github_token = Some("tok".to_string());
    c.github_repo = Some("not-owner-slash-name".to_string());
    c.pr_number = Some(7);
    let result = main_impl(c).await;
    assert!(result.unwrap_err().contains("owner/name"));
}
#[tokio::test]
async fn main_impl_runs_a_full_scan_against_a_wiremock_gateway() {
    let server = wiremock::MockServer::start().await;
    let openai_reply = |content: &str| serde_json::json!({"choices": [{"message": {"content": content}, "finish_reason": "stop"}]});
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::path("/chat/completions"))
        .and(wiremock::matchers::body_string_contains("security-focused codebase mapper"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(openai_reply(
            r#"{"language":"python","modules":[],"entry_points":[],"unsafe_sinks":[],"call_graph":{},"notes":""}"#,
        )))
        .mount(&server)
        .await;

    let dir = setup_repo();
    let mut c = cli(dir.path());
    c.gateway_base_url = server.uri();
    c.stop_after = "s1".to_string();

    let summary = main_impl(c).await.unwrap();
    assert_eq!(summary.stopped_after, Some(StopAfter::S1));
    let manifest: appsec_orchestrator::manifest::RunManifest = serde_json::from_str(
        &std::fs::read_to_string(dir.path().join("security-scan/run_manifest.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(manifest.exit_code, 0);
    let s1 = &manifest
        .stages
        .0
        .iter()
        .find(|(id, _)| id == "s1")
        .unwrap()
        .1;
    assert_eq!(s1.outcome, "completed");
    assert!(s1.duration_sec.is_some());
}
#[tokio::test]
async fn main_impl_writes_the_manifest_where_asked_even_for_a_failed_scan() {
    let server = wiremock::MockServer::start().await;
    let dir = setup_repo();
    let out = tempfile::tempdir().unwrap();
    let mut c = cli(dir.path());
    c.gateway_base_url = server.uri();
    c.stop_after = "s1".to_string();
    c.progress_style = Some(progress_lines::ProgressStyle::StageOnly);
    c.s6_progress_file = true;
    c.out_run_manifest = Some(out.path().join("m.json"));
    let _ = main_impl(c).await;
    let manifest: appsec_orchestrator::manifest::RunManifest =
        serde_json::from_str(&std::fs::read_to_string(out.path().join("m.json")).unwrap()).unwrap();
    assert!(manifest.stages.0.iter().any(|(id, _)| id == "s1"));
    assert!(!dir.path().join("security-scan/run_manifest.json").exists());
}
#[tokio::test]
async fn main_impl_writes_no_manifest_for_an_argument_error_or_a_utility_mode() {
    let dir = setup_repo();
    let mut c = cli(dir.path());
    c.stop_after = "s42".to_string();
    assert!(main_impl(c).await.is_err());
    let mut c = cli(dir.path());
    c.estimate = true;
    main_impl(c).await.unwrap();
    assert!(!dir.path().join("security-scan/run_manifest.json").exists());
}
#[tokio::test]
async fn main_impl_dispatches_to_batch_mode_when_repo_file_is_set() {
    let server = wiremock::MockServer::start().await;
    let openai_reply = |content: &str| serde_json::json!({"choices": [{"message": {"content": content}, "finish_reason": "stop"}]});
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::path("/chat/completions"))
        .and(wiremock::matchers::body_string_contains("security-focused codebase mapper"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(openai_reply(
            r#"{"language":"python","modules":[],"entry_points":[],"unsafe_sinks":[],"call_graph":{},"notes":""}"#,
        )))
        .mount(&server)
        .await;

    let repo_a = setup_repo();
    let repo_b = setup_repo();
    let manifest_dir = tempfile::tempdir().unwrap();
    let manifest = manifest_dir.path().join("manifest.txt");
    std::fs::write(
        &manifest,
        format!(
            "app1,repo-a,{}\napp2,repo-b,{}\n",
            repo_a.path().display(),
            repo_b.path().display(),
        ),
    )
    .unwrap();

    let mut c = cli(repo_a.path());
    c.repo = None;
    c.repo_file = Some(manifest);
    c.out_batch_summary = Some(manifest_dir.path().join("summary.md"));
    c.gateway_base_url = server.uri();
    c.stop_after = "s1".to_string();
    let shared = manifest_dir.path().join("shared-out");
    c.out_dir = Some(shared.clone());

    let _guard = ENV_LOCK.lock().await;
    let state_dir = tempfile::tempdir().unwrap();
    let prior = std::env::var("BC_STATE_DIR").ok();
    unsafe {
        std::env::set_var("BC_STATE_DIR", state_dir.path());
    }
    let summary = main_impl(c).await.unwrap();
    restore_env("BC_STATE_DIR", prior);

    let batch = summary.batch.unwrap();
    assert_eq!(batch.total, 2);
    assert_eq!(batch.completed, 2);
    assert_eq!(batch.failed, 0);
    assert!(batch.summary_path.is_file());
    assert!(!shared.exists(), "a shared --out-dir leaked into a batch");
    assert!(repo_a.path().join("security-scan").is_dir());
    assert!(repo_b.path().join("security-scan").is_dir());
}
#[tokio::test]
async fn main_impl_batch_mode_defaults_the_summary_path_when_out_batch_summary_is_unset() {
    let server = wiremock::MockServer::start().await;
    let openai_reply = |content: &str| serde_json::json!({"choices": [{"message": {"content": content}, "finish_reason": "stop"}]});
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::path("/chat/completions"))
        .and(wiremock::matchers::body_string_contains("security-focused codebase mapper"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(openai_reply(
            r#"{"language":"python","modules":[],"entry_points":[],"unsafe_sinks":[],"call_graph":{},"notes":""}"#,
        )))
        .mount(&server)
        .await;

    let repo_a = setup_repo();
    let manifest_dir = tempfile::tempdir().unwrap();
    let manifest = manifest_dir.path().join("manifest.txt");
    std::fs::write(
        &manifest,
        format!("app1,repo-a,{}\n", repo_a.path().display()),
    )
    .unwrap();

    let mut c = cli(repo_a.path());
    c.repo = None;
    c.repo_file = Some(manifest);
    c.out_batch_summary = None;
    c.gateway_base_url = server.uri();
    c.stop_after = "s1".to_string();

    let _guard = ENV_LOCK.lock().await;
    let state_dir = tempfile::tempdir().unwrap();
    let prior_state_dir = std::env::var("BC_STATE_DIR").ok();
    unsafe {
        std::env::set_var("BC_STATE_DIR", state_dir.path());
    }
    let cwd_dir = tempfile::tempdir().unwrap();
    let prior_cwd = std::env::current_dir().unwrap();
    std::env::set_current_dir(cwd_dir.path()).unwrap();
    let summary = main_impl(c).await.unwrap();
    std::env::set_current_dir(prior_cwd).unwrap();
    restore_env("BC_STATE_DIR", prior_state_dir);

    let batch = summary.batch.unwrap();
    assert_eq!(batch.summary_path, PathBuf::from("batch_summary.md"));
    assert!(cwd_dir.path().join("batch_summary.md").is_file());
}
#[tokio::test]
async fn main_impl_batch_mode_records_a_failing_entry_without_aborting_the_rest() {
    let server = wiremock::MockServer::start().await;
    let openai_reply = |content: &str| serde_json::json!({"choices": [{"message": {"content": content}, "finish_reason": "stop"}]});
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::path("/chat/completions"))
        .and(wiremock::matchers::body_string_contains("security-focused codebase mapper"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(openai_reply(
            r#"{"language":"python","modules":[],"entry_points":[],"unsafe_sinks":[],"call_graph":{},"notes":""}"#,
        )))
        .mount(&server)
        .await;

    let repo_a = setup_repo();
    let manifest_dir = tempfile::tempdir().unwrap();
    let bad_config = manifest_dir.path().join("missing-config.yaml");
    let manifest = manifest_dir.path().join("manifest.txt");
    std::fs::write(
        &manifest,
        format!("app1,repo-a,{}\n", repo_a.path().display()),
    )
    .unwrap();

    let mut c = cli(repo_a.path());
    c.repo = None;
    c.repo_file = Some(manifest);
    c.out_batch_summary = Some(manifest_dir.path().join("summary.md"));
    c.gateway_base_url = server.uri();
    c.config = Some(bad_config);

    let _guard = ENV_LOCK.lock().await;
    let state_dir = tempfile::tempdir().unwrap();
    let prior = std::env::var("BC_STATE_DIR").ok();
    unsafe {
        std::env::set_var("BC_STATE_DIR", state_dir.path());
    }
    let summary = main_impl(c).await.unwrap();
    restore_env("BC_STATE_DIR", prior);

    let batch = summary.batch.unwrap();
    assert_eq!(batch.total, 1);
    assert_eq!(batch.completed, 0);
    assert_eq!(batch.failed, 1);
    let text = std::fs::read_to_string(&batch.summary_path).unwrap();
    assert!(text.contains("## Failures"));
}
#[tokio::test]
async fn main_impl_propagates_a_gateway_error() {
    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::path("/chat/completions"))
        .respond_with(wiremock::ResponseTemplate::new(400).set_body_string("bad request"))
        .mount(&server)
        .await;

    let dir = setup_repo();
    let mut c = cli(dir.path());
    c.gateway_base_url = server.uri();
    let result = main_impl(c).await;
    assert!(result.is_err());
}
#[tokio::test]
async fn run_reports_a_successful_github_sync_when_the_scan_reaches_a_final_report() {
    let dir = git_repo();
    let github_server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/repos/acme/widgets/pulls/1"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_string(""))
        .mount(&github_server)
        .await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path(
            "/repos/acme/widgets/pulls/1/comments",
        ))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
        .mount(&github_server)
        .await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path(
            "/repos/acme/widgets/issues/1/comments",
        ))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
        .mount(&github_server)
        .await;

    let mut gh_config = appsec_github::GithubConfig::new("acme", "widgets", 1, "tok");
    gh_config.api_base_url = github_server.uri();
    let github_client = appsec_github::GithubClient::new(reqwest::Client::new(), gh_config);

    let paths = out_paths(&dir.path().join("out"));
    let summary = run(
        fast_input(dir.path()),
        fast_config(),
        None,
        &paths,
        empty_scan_client(),
        Arc::new(NoTools),
        Some(github_client),
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        summary.github_sync,
        Some(Ok(appsec_github::SyncSummary::default()))
    );
}
#[tokio::test]
async fn run_reports_a_failed_github_sync_without_failing_the_scan_itself() {
    let dir = git_repo();
    let github_server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/repos/acme/widgets/pulls/1"))
        .respond_with(wiremock::ResponseTemplate::new(500))
        .mount(&github_server)
        .await;

    let mut gh_config = appsec_github::GithubConfig::new("acme", "widgets", 1, "tok");
    gh_config.api_base_url = github_server.uri();
    let github_client = appsec_github::GithubClient::new(reqwest::Client::new(), gh_config);

    let paths = out_paths(&dir.path().join("out"));
    let summary = run(
        fast_input(dir.path()),
        fast_config(),
        None,
        &paths,
        empty_scan_client(),
        Arc::new(NoTools),
        Some(github_client),
        None,
        None,
    )
    .await
    .unwrap();
    assert_github_sync_failed(&summary);
    assert!(paths.markdown.is_file());
    assert!(paths.sarif.is_file());
}
#[tokio::test]
async fn run_skips_github_sync_when_the_scan_does_not_reach_a_final_report() {
    let dir = setup_repo();
    let client: Arc<dyn LlmClient> = Arc::new(RoutedClient {
        router: Box::new(|system| {
            Ok(route(
                system,
                &[(
                    "security-focused codebase mapper",
                    r#"{"language":"python","modules":[],"entry_points":[],"unsafe_sinks":[],"call_graph":{},"notes":""}"#,
                )],
            ))
        }),
    });
    let mut gh_config = appsec_github::GithubConfig::new("acme", "widgets", 1, "tok");
    gh_config.api_base_url = "http://127.0.0.1:1".to_string();
    let github_client = appsec_github::GithubClient::new(reqwest::Client::new(), gh_config);

    let paths = out_paths(&dir.path().join("None"));
    let summary = run(
        fast_input(dir.path()),
        fast_config(),
        Some(StopAfter::S1),
        &paths,
        client,
        Arc::new(NoTools),
        Some(github_client),
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(summary.github_sync, None);
}

#[test]
fn build_remediate_settings_without_config_uses_cli_model_and_no_policy() {
    let c = cli(Path::new("/tmp"));
    let settings = build_remediate_settings(&c).unwrap();
    assert_eq!(settings.config.step10.model, "m");
    assert!(settings.config.top.is_none());
    assert!(settings.config.top_default.is_none());
    assert!(!settings.config.force);
    assert!(settings.policy.is_none());
}
#[tokio::test]
async fn main_impl_refuses_an_unreadable_baseline_before_scanning() {
    let dir = tempfile::tempdir().unwrap();
    let mut c = cli(dir.path());
    c.baseline = Some(dir.path().join("does-not-exist.json"));
    let err = main_impl(c).await.unwrap_err();
    assert!(err.contains("cannot read baseline"), "{err}");
}
#[tokio::test]
async fn run_attempts_no_remediation_when_not_requested() {
    let dir = git_repo();
    let paths = out_paths(&dir.path().join("None"));
    let summary = run(
        fast_input(dir.path()),
        fast_config(),
        None,
        &paths,
        empty_scan_client(),
        Arc::new(NoTools),
        None,
        None,
        None,
    )
    .await
    .unwrap();
    assert!(summary.remediation.is_none());
}
#[tokio::test]
async fn run_remediates_the_one_finding_the_scan_produced() {
    let dir = git_repo();
    let paths = out_paths(&dir.path().join("out"));
    let remediate = RemediateRun {
        delivery: None,
        settings: RemediateSettings {
            target_tests: None,
            config: appsec_orchestrator::RemediateConfig {
                step10: fast_remediate_config(),
                top: None,
                top_default: None,
                force: false,
                resume: false,
                isolated: false,
            },
            policy: None,
            interactive: false,
            validate_enabled: false,
            step11: fast_step11_config(),
        },
        tools: Arc::new(SandboxTools::new_with_write(dir.path())),
        out_json: None,
        checkpoint: None,
        worktree: None,
    };
    let summary = run(
        fast_input(dir.path()),
        fast_config_no_semantic_dedup(),
        None,
        &paths,
        one_finding_client(),
        Arc::new(NoTools),
        None,
        Some(remediate),
        None,
    )
    .await
    .unwrap();
    let remediation = summary.remediation.unwrap();
    assert!(remediation.refused.is_none());
    assert_eq!(remediation.processed, 1);
    assert_eq!(remediation.failed, 0);
    assert!(remediation.validated.is_none());
}
#[tokio::test]
async fn zip_delivery_full_scan_without_git_keeps_original_source_and_exports_updated_copy() {
    for (with_target_tests, degraded) in [(false, false), (true, false), (false, true)] {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("app.py"), "old\n").unwrap();
        let mut c = cli(dir.path());
        c.remediate = true;
        c.remediation_delivery = delivery::DeliveryMode::Zip;
        let delivery = delivery::prepare(&c, dir.path()).unwrap();
        let snapshot_path = delivery
            .as_ref()
            .unwrap()
            .snapshot
            .as_ref()
            .unwrap()
            .path()
            .to_path_buf();
        let paths = out_paths(&dir.path().join("out"));
        struct CompleteScanClient(OneFindingClientWithValidation);
        #[async_trait]
        impl LlmClient for CompleteScanClient {
            async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, LlmError> {
                if request.system.as_deref().unwrap_or("").contains(S3_MARK) {
                    return Ok(ChatResponse {
                        content: vec![ContentBlock::Text(
                            r#"{"chunks":[],"rationale":"deterministic catchall"}"#.into(),
                        )],
                        stop_reason: StopReason::EndTurn,
                        usage: Usage::default(),
                    });
                }
                self.0.chat(request).await
            }
        }
        let writer = SandboxTools::new_with_write(snapshot_path.clone());
        let mut step10 = fast_remediate_config();
        step10.journal = Some(writer.journal());
        let remediate = RemediateRun {
            delivery,
            settings: RemediateSettings {
                target_tests: with_target_tests.then(target_testing::TargetTestingConfig::default),
                config: appsec_orchestrator::RemediateConfig {
                    step10,
                    top: None,
                    top_default: None,
                    force: false,
                    resume: false,
                    isolated: true,
                },
                policy: None,
                interactive: false,
                validate_enabled: false,
                step11: fast_step11_config(),
            },
            tools: Arc::new(writer),
            out_json: None,
            checkpoint: None,
            worktree: None,
        };
        let result = run(
            fast_input(dir.path()),
            fast_config_no_semantic_dedup(),
            None,
            &paths,
            if degraded {
                one_finding_client()
            } else {
                Arc::new(CompleteScanClient(OneFindingClientWithValidation::new()))
            },
            Arc::new(NoTools),
            None,
            Some(remediate),
            None,
        )
        .await;
        if degraded {
            assert!(result.unwrap_err().contains("completed full scan"));
            assert!(!dir
                .path()
                .join("security-scan/remediated-source.zip")
                .exists());
            continue;
        }
        let summary = result.unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.path().join("app.py")).unwrap(),
            "old\n"
        );
        assert!(dir
            .path()
            .join("security-scan/remediated-source.zip")
            .is_file());
        let archive =
            std::fs::read(dir.path().join("security-scan/remediated-source.zip")).unwrap();
        assert!(archive
            .windows(b"print('fixed')\n".len())
            .any(|w| w == b"print('fixed')\n"));
        assert!(!snapshot_path.exists());
        let receipt: serde_json::Value = serde_json::from_slice(
            &std::fs::read(dir.path().join("security-scan/delivery.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(receipt["mode"], "zip");
        let remediation = summary.remediation.unwrap();
        assert!(remediation.refused.is_none());
        assert_eq!(remediation.processed, 1);
        assert_eq!(remediation.failed, 0);
        assert!(remediation.validated.is_none());
    }
}
#[tokio::test]
async fn target_testing_refuses_an_in_place_remediation_rather_than_editing_the_users_tree() {
    let dir = git_repo();
    let run = isolated_remediate_run(
        dir.path(),
        Some(target_testing::TargetTestingConfig::default()),
        None,
        None,
    );
    let (result, patch) =
        dispatch(one_finding_client(), dir.path(), &one_finding_report(), run).await;
    assert_eq!(
        result.refused.unwrap(),
        "Target testing requires an isolated worktree; no in-place fallback is allowed"
    );
    assert!(result.outcomes.is_empty());
    assert!(result.validations.is_empty());
    assert!(patch.is_none());
    assert_eq!(
        std::fs::read_to_string(dir.path().join("app.py")).unwrap(),
        "print('hi')\n"
    );
}
#[tokio::test]
async fn target_testing_refuses_a_scan_that_did_not_finish() {
    let _lock = ENV_LOCK.lock().await;
    let state = tempfile::tempdir().unwrap();
    let prior = std::env::var("BC_STATE_DIR").ok();
    unsafe { std::env::set_var("BC_STATE_DIR", state.path()) };
    type Damage = fn(&mut appsec_model::FinalReport);
    let cases: [(&str, Damage); 4] = [
        ("degraded", |report| report.degraded = true),
        ("budget", |report| {
            report.metrics = Some(appsec_model::ScanMetrics {
                budget_stop: "S6: token budget reached".into(),
                ..Default::default()
            })
        }),
        ("chunks", |report| {
            report.metrics = Some(appsec_model::ScanMetrics {
                chunks_failed: 1,
                ..Default::default()
            })
        }),
        ("errors", |report| {
            report.metrics = Some(appsec_model::ScanMetrics {
                errors_by_stage: [("s4".to_string(), 1)].into_iter().collect(),
                ..Default::default()
            })
        }),
    ];
    for (name, damage) in cases {
        let dir = git_repo();
        let worktree = worktree::prepare(&cli(dir.path()), dir.path());
        assert!(worktree.is_some(), "{name}");
        let mut report = one_finding_report();
        damage(&mut report);
        let run = isolated_remediate_run(
            dir.path(),
            Some(target_testing::TargetTestingConfig::default()),
            None,
            worktree,
        );
        let (result, patch) = dispatch(one_finding_client(), dir.path(), &report, run).await;
        assert!(
            result
                .refused
                .as_deref()
                .is_some_and(|reason| reason.contains("requires a completed full scan")),
            "{name}: {:?}",
            result.refused
        );
        assert!(patch.is_none(), "{name}");
    }
    restore_env("BC_STATE_DIR", prior);
}
#[tokio::test]
async fn target_test_preparation_that_cannot_run_blocks_remediation_entirely() {
    let _lock = ENV_LOCK.lock().await;
    let state = tempfile::tempdir().unwrap();
    let prior = std::env::var("BC_STATE_DIR").ok();
    unsafe { std::env::set_var("BC_STATE_DIR", state.path()) };
    let dir = git_repo();
    std::fs::create_dir(dir.path().join("tests")).unwrap();
    std::fs::write(dir.path().join("tests/test_huge.py"), "x".repeat(1_000_001)).unwrap();
    for args in [
        &["add", "-A"][..],
        &[
            "-c",
            "user.email=t@t.invalid",
            "-c",
            "user.name=t",
            "commit",
            "-qm",
            "tests",
        ][..],
    ] {
        let out = std::process::Command::new("git")
            .arg("-C")
            .arg(dir.path())
            .args(args)
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
    }
    let worktree = worktree::prepare(&cli(dir.path()), dir.path());
    assert!(worktree.is_some());
    let run = isolated_remediate_run(
        dir.path(),
        Some(target_testing::TargetTestingConfig::default()),
        None,
        worktree,
    );
    let (result, patch) =
        dispatch(one_finding_client(), dir.path(), &one_finding_report(), run).await;
    restore_env("BC_STATE_DIR", prior);
    assert!(
        result
            .refused
            .as_deref()
            .is_some_and(|reason| reason.starts_with("Target test preparation blocked:")),
        "{:?}",
        result.refused
    );
    assert!(result.outcomes.is_empty());
    assert!(patch.is_none());
}
#[cfg(unix)]
#[tokio::test]
async fn target_test_evidence_that_escapes_the_repository_withholds_the_patch() {
    let _lock = ENV_LOCK.lock().await;
    let state = tempfile::tempdir().unwrap();
    let prior = std::env::var("BC_STATE_DIR").ok();
    unsafe { std::env::set_var("BC_STATE_DIR", state.path()) };
    let dir = git_repo();
    let outside = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(outside.path(), dir.path().join("security-scan")).unwrap();
    let worktree = worktree::prepare(&cli(dir.path()), dir.path());
    let run = isolated_remediate_run(
        dir.path(),
        Some(target_testing::TargetTestingConfig::default()),
        None,
        worktree,
    );
    let (result, patch) =
        dispatch(one_finding_client(), dir.path(), &one_finding_report(), run).await;
    restore_env("BC_STATE_DIR", prior);
    assert!(
        result
            .refused
            .as_deref()
            .is_some_and(|reason| reason.contains("Target-test evidence could not be saved")),
        "{:?}",
        result.refused
    );
    assert!(!outside.path().join("target-tests.json").exists());
    assert!(patch.is_none());
}
#[tokio::test]
async fn rejected_test_generation_downgrades_every_verdict_and_withholds_the_patch() {
    let _lock = ENV_LOCK.lock().await;
    let state = tempfile::tempdir().unwrap();
    let prior = std::env::var("BC_STATE_DIR").ok();
    unsafe { std::env::set_var("BC_STATE_DIR", state.path()) };
    let dir = git_repo();
    let worktree = worktree::prepare(&cli(dir.path()), dir.path());
    let worktree_path = worktree.as_ref().unwrap().path.clone();
    let run = isolated_remediate_run(
        &worktree_path,
        Some(target_testing::TargetTestingConfig {
            generate: true,
            ..Default::default()
        }),
        None,
        worktree,
    );
    let (result, patch) = dispatch(
        s10_client_with_an_unusable_generator(),
        dir.path(),
        &one_finding_report(),
        run,
    )
    .await;
    restore_env("BC_STATE_DIR", prior);
    assert_eq!(
        result.refused.as_deref(),
        Some(
            "Target-test validation blocked patch export; inspect security-scan/target-tests.json"
        )
    );
    assert!(result.validations.is_empty());
    let record = expect_processed(&result.outcomes[0]);
    assert!(record.diff.is_none());
    assert_eq!(
        record.verdict.verdict,
        appsec_stage_s10::Verdict::NeedsReview
    );
    assert_eq!(
        record.final_verdict.as_deref(),
        Some("Needs Review: target-test validation blocked export")
    );
    assert!(patch.is_none());
    let artifact: Value = serde_json::from_slice(
        &std::fs::read(dir.path().join("security-scan/target-tests.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(artifact["generation_state"], "blocked");
    assert_eq!(artifact["export_blocked"], true);
}
#[tokio::test]
async fn a_failed_independent_patch_review_is_not_replaced_by_target_tests() {
    let _lock = ENV_LOCK.lock().await;
    let state = tempfile::tempdir().unwrap();
    let prior = std::env::var("BC_STATE_DIR").ok();
    unsafe { std::env::set_var("BC_STATE_DIR", state.path()) };

    struct S11Fails(OneFindingClientWithValidation);
    #[async_trait]
    impl LlmClient for S11Fails {
        async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, LlmError> {
            let system = request.system.as_deref().unwrap_or("");
            if system.contains(S11_ARCHITECT_MARK) || system.contains(S11_PENTESTER_MARK) {
                return Err(LlmError::Other {
                    message: "independent review unavailable".into(),
                });
            }
            self.0.chat(request).await
        }
    }

    let dir = git_repo();
    let worktree = worktree::prepare(&cli(dir.path()), dir.path());
    let worktree_path = worktree.as_ref().unwrap().path.clone();
    let mut run = isolated_remediate_run(
        &worktree_path,
        Some(target_testing::TargetTestingConfig::default()),
        None,
        worktree,
    );
    run.settings.validate_enabled = true;
    let (result, patch) = dispatch(
        Arc::new(S11Fails(OneFindingClientWithValidation::new())),
        dir.path(),
        &one_finding_report(),
        run,
    )
    .await;
    restore_env("BC_STATE_DIR", prior);
    assert_eq!(result.validation_failures, 1);
    assert!(patch.is_none());
    let artifact: Value = serde_json::from_slice(
        &std::fs::read(dir.path().join("security-scan/target-tests.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(artifact["export_blocked"], true);
    assert!(artifact["remaining_gaps"]
        .as_array()
        .unwrap()
        .iter()
        .any(|gap| gap
            .as_str()
            .unwrap()
            .contains("Independent patch review failed")));
}
#[tokio::test]
async fn delivery_is_withheld_when_a_finding_was_never_fixed() {
    let dir = git_repo();
    let state = delivery::DeliveryState {
        mode: delivery::DeliveryMode::Zip,
        remote: None,
        branch: None,
        snapshot: None,
        output: dir.path().join("security-scan/remediated-source.zip"),
    };
    let failing: Arc<dyn LlmClient> = Arc::new(RoutedClient {
        router: Box::new(|_| {
            Err(LlmError::InvalidRequest {
                message: "the remediation model refused".into(),
            })
        }),
    });
    let run = isolated_remediate_run(dir.path(), None, Some(state), None);
    let (result, patch) = dispatch(failing, dir.path(), &one_finding_report(), run).await;
    assert!(matches!(
        result.outcomes[0],
        appsec_stage_s10::RemediationOutcome::Failed { .. }
    ));
    assert_eq!(
        result.refused.as_deref(),
        Some("Delivery withheld: remediation or validation needs review")
    );
    assert!(patch.is_none());
    assert!(!dir
        .path()
        .join("security-scan/remediated-source.zip")
        .exists());
}
#[tokio::test]
async fn a_failed_zip_delivery_retains_the_updated_snapshot_for_recovery() {
    let dir = git_repo();
    let snapshot = delivery_archive::create_snapshot(dir.path()).unwrap();
    let snapshot_path = snapshot.path().to_path_buf();
    let output = dir.path().join("prior-artifact.zip");
    std::fs::write(&output, b"an earlier run").unwrap();
    let state = delivery::DeliveryState {
        mode: delivery::DeliveryMode::Zip,
        remote: None,
        branch: None,
        snapshot: Some(snapshot),
        output: output.clone(),
    };
    let run = isolated_remediate_run(&snapshot_path, None, Some(state), None);
    let (result, patch) = dispatch(
        Arc::new(OneFindingClientWithValidation::new()),
        dir.path(),
        &one_finding_report(),
        run,
    )
    .await;
    assert!(
        result
            .refused
            .as_deref()
            .is_some_and(|reason| reason.starts_with("Delivery failed:")),
        "{:?}",
        result.refused
    );
    assert!(patch.is_none());
    assert_eq!(std::fs::read(&output).unwrap(), b"an earlier run");
    assert!(
        snapshot_path.is_dir(),
        "the updated snapshot must survive for recovery"
    );
    std::fs::remove_dir_all(&snapshot_path).unwrap();
}
#[tokio::test]
async fn a_delivered_zip_records_the_model_review_results_it_actually_has() {
    let dir = git_repo();
    let out = tempfile::tempdir().unwrap();
    let state = delivery::DeliveryState {
        mode: delivery::DeliveryMode::Zip,
        remote: None,
        branch: None,
        snapshot: None,
        output: out.path().join("remediated-source.zip"),
    };
    let mut run = isolated_remediate_run(dir.path(), None, Some(state), None);
    run.settings.validate_enabled = true;
    let (result, _patch) = dispatch(
        Arc::new(OneFindingClientWithValidation::new()),
        dir.path(),
        &one_finding_report(),
        run,
    )
    .await;
    assert_eq!(result.refused, None);
    assert_eq!(result.validation_failures, 0);
    assert!(out.path().join("remediated-source.zip").is_file());
    let receipt: Value = serde_json::from_slice(
        &std::fs::read(dir.path().join("security-scan/delivery.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(receipt["status"], "created");
    assert_eq!(receipt["validation"]["model_review_enabled"], true);
    assert_eq!(
        receipt["validation"]["model_review_results"],
        json!(["Fixed"])
    );
    assert_eq!(receipt["validation"]["target_test_status"], Value::Null);
    assert_eq!(receipt["validation"]["target_command_results"], 0);
}
#[tokio::test]
async fn a_failed_branch_delivery_retains_the_worktree_and_fails_the_run() {
    let _lock = ENV_LOCK.lock().await;
    let state_dir = tempfile::tempdir().unwrap();
    let prior = std::env::var("BC_STATE_DIR").ok();
    unsafe { std::env::set_var("BC_STATE_DIR", state_dir.path()) };
    let dir = git_repo();
    let worktree = worktree::prepare(&cli(dir.path()), dir.path());
    let worktree_path = worktree.as_ref().unwrap().path.clone();
    let run = isolated_remediate_run(
        &worktree_path,
        None,
        Some(delivery::DeliveryState {
            mode: delivery::DeliveryMode::Branch,
            remote: Some("origin".into()),
            branch: Some("bc-sast/fix".into()),
            snapshot: None,
            output: dir.path().join("security-scan/remediated-source.zip"),
        }),
        worktree,
    );
    let paths = out_paths(&dir.path().join("out"));
    let summary = run_scan_with_remediation(dir.path(), &paths, run).await;
    restore_env("BC_STATE_DIR", prior);
    let error = summary.unwrap_err();
    assert!(error.starts_with("Delivery failed:"), "{error}");
    assert!(
        worktree_path.is_dir(),
        "a failed publication must keep the proposal checkout"
    );
}
#[tokio::test]
async fn a_delivery_receipt_that_cannot_be_written_fails_the_run_after_publication() {
    let dir = git_repo();
    let outside = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(outside.path(), dir.path().join("security-scan")).unwrap();
    let out = tempfile::tempdir().unwrap();
    let state = delivery::DeliveryState {
        mode: delivery::DeliveryMode::Zip,
        remote: None,
        branch: None,
        snapshot: None,
        output: out.path().join("remediated-source.zip"),
    };
    let run = isolated_remediate_run(dir.path(), None, Some(state), None);
    let (result, _patch) = dispatch(
        Arc::new(OneFindingClientWithValidation::new()),
        dir.path(),
        &one_finding_report(),
        run,
    )
    .await;
    assert!(
        result.refused.as_deref().is_some_and(
            |reason| reason.starts_with("Delivery completed but receipt could not be saved")
        ),
        "{:?}",
        result.refused
    );
    assert!(out.path().join("remediated-source.zip").is_file());
    assert!(!outside.path().join("delivery.json").exists());
}
#[tokio::test]
async fn target_testing_and_delivery_both_refuse_a_partial_scan_before_any_work() {
    let dir = git_repo();
    let paths = out_paths(&dir.path().join("out"));
    for target_tests in [true, false] {
        let mut remediate = isolated_remediate_run(
            dir.path(),
            target_tests.then(target_testing::TargetTestingConfig::default),
            None,
            None,
        );
        if !target_tests {
            remediate.delivery = Some(delivery::DeliveryState {
                mode: delivery::DeliveryMode::Zip,
                remote: None,
                branch: None,
                snapshot: None,
                output: dir.path().join("security-scan/remediated-source.zip"),
            });
        }
        let error = run(
            fast_input(dir.path()),
            fast_config_no_semantic_dedup(),
            Some(StopAfter::S8),
            &paths,
            empty_scan_client(),
            Arc::new(NoTools),
            None,
            Some(remediate),
            None,
        )
        .await
        .unwrap_err();
        assert_eq!(
            error,
            "Target testing requires a full scan plus remediation"
        );
    }
}
#[test]
fn target_testing_requires_a_clean_committed_checkout_and_no_host_verify_command() {
    let dir = git_repo();
    let mut c = cli(dir.path());
    c.remediate = true;
    c.target_tests = Some("discover".into());
    c.verify_command = Some("cargo test".into());
    assert!(build_remediate_run(&c, dir.path())
        .err()
        .unwrap()
        .contains("Target testing requires fix mode without dry-run or a host verify_command"));

    c.verify_command = None;
    std::fs::write(dir.path().join("uncommitted.py"), "print('new')\n").unwrap();
    assert!(build_remediate_run(&c, dir.path())
        .err()
        .unwrap()
        .contains("requires a clean committed Git snapshot"));
    std::fs::remove_file(dir.path().join("uncommitted.py")).unwrap();
}
#[test]
fn a_repository_git_will_not_read_is_reported_as_unreadable_not_as_dirty() {
    let dir = tempfile::tempdir().unwrap();
    let mut c = cli(dir.path());
    c.remediate = true;
    c.target_tests = Some("discover".into());
    let error = build_remediate_run(&c, dir.path()).err().unwrap();
    assert!(
        error.contains("git refused"),
        "should name git's refusal, got: {error}"
    );
    assert!(
        error.contains("safe.directory"),
        "should name the remedy, got: {error}"
    );
    assert!(
        !error.contains("clean committed Git snapshot"),
        "must not blame a dirty tree, got: {error}"
    );
}
#[test]
fn zip_delivery_scans_the_isolated_snapshot_and_needs_no_git_worktree() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("app.py"), "print('hi')\n").unwrap();
    let mut c = cli(dir.path());
    c.remediate = true;
    c.target_tests = Some("discover".into());
    c.remediation_delivery = delivery::DeliveryMode::Zip;
    let prepared = build_remediate_run(&c, dir.path()).unwrap();
    assert!(prepared.worktree.is_none());
    assert!(prepared.settings.config.isolated);
    let snapshot = prepared
        .delivery
        .as_ref()
        .unwrap()
        .snapshot
        .as_ref()
        .unwrap();
    assert!(snapshot.path().join("app.py").is_file());
    assert_ne!(snapshot.path(), dir.path());
}
#[test]
fn target_testing_fails_closed_when_no_isolated_worktree_can_be_created() {
    let lock = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let _guard = lock.block_on(ENV_LOCK.lock());
    let unusable = tempfile::tempdir().unwrap();
    std::fs::write(unusable.path().join("remediation-worktrees"), "blocked\n").unwrap();
    let prior = std::env::var("BC_STATE_DIR").ok();
    unsafe { std::env::set_var("BC_STATE_DIR", unusable.path()) };
    let dir = git_repo();
    let mut c = cli(dir.path());
    c.remediate = true;
    c.target_tests = Some("discover".into());
    let outcome = build_remediate_run(&c, dir.path());
    restore_env("BC_STATE_DIR", prior);
    assert!(outcome
        .err()
        .unwrap()
        .contains("creation failed and in-place fallback is disabled"));
}
#[tokio::test]
async fn full_scan_remediation_writes_target_test_plan_without_extra_model_calls() {
    let _lock = ENV_LOCK.lock().await;
    let state = tempfile::tempdir().unwrap();
    let prior = std::env::var("BC_STATE_DIR").ok();
    unsafe { std::env::set_var("BC_STATE_DIR", state.path()) };
    let dir = git_repo();
    let mut c = cli(dir.path());
    c.remediate = true;
    let mut remediation = build_remediate_run(&c, dir.path()).unwrap();
    remediation.settings.target_tests = Some(target_testing::TargetTestingConfig::default());
    remediation.settings.validate_enabled = false;
    let client: Arc<dyn LlmClient> = Arc::new(RoutedClient {
        router: Box::new(|system| {
            Ok(route(
                system,
                &[
                    (S1_MARK, S1_JSON),
                    (
                        S2_MARK,
                        r#"{"system_context":"ctx","assets":[],"trust_boundaries":[],"threats":[],"open_questions":[]}"#,
                    ),
                    (
                        S3_MARK,
                        r#"{"chunks":[],"rationale":"deterministic catchall"}"#,
                    ),
                    (S4_MARK, r#"{"findings":[]}"#),
                ],
            ))
        }),
    });
    let paths = out_paths(&dir.path().join("out"));
    let result = run(
        fast_input(dir.path()),
        fast_config_no_semantic_dedup(),
        None,
        &paths,
        client,
        Arc::new(NoTools),
        None,
        Some(remediation),
        None,
    )
    .await;
    restore_env("BC_STATE_DIR", prior);
    let summary = result.unwrap();
    assert!(
        summary.remediation.as_ref().unwrap().refused.is_none(),
        "{:?}",
        summary.remediation
    );
    let artifact: Value = serde_json::from_slice(
        &std::fs::read(dir.path().join("security-scan/target-tests.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(artifact["generation_state"], "not_requested");
    assert_eq!(artifact["assurance_status"], "unverified");
    assert_eq!(artifact["execution"], json!([]));
    assert!(std::fs::read_to_string(&paths.markdown)
        .unwrap()
        .contains("Target repository testing"));
    let sarif: Value = serde_json::from_slice(&std::fs::read(&paths.sarif).unwrap()).unwrap();
    assert_eq!(
        sarif["runs"][0]["properties"]["targetTestAssurance"]["status"],
        "unverified"
    );
    assert!(summary.remediation_patch.is_none());
}
#[tokio::test]
async fn run_remediates_in_an_isolated_worktree_and_exports_a_patch() {
    let _lock = ENV_LOCK.lock().await;
    let state = tempfile::tempdir().unwrap();
    let prior = std::env::var("BC_STATE_DIR").ok();
    unsafe { std::env::set_var("BC_STATE_DIR", state.path()) };

    let dir = git_repo();
    let mut c = cli(dir.path());
    c.remediate = true;
    let mut remediate = build_remediate_run(&c, dir.path()).unwrap();
    remediate.settings.config.step10.model = fast_remediate_config().model.clone();
    remediate.settings.config.step10.max_turns = fast_remediate_config().max_turns;
    remediate.settings.config.step10.retry_backoff_base =
        fast_remediate_config().retry_backoff_base;
    remediate.settings.config.step10.max_transient_retries =
        fast_remediate_config().max_transient_retries;
    remediate.settings.validate_enabled = false;
    remediate.settings.step11 = fast_step11_config();
    let worktree_path = remediate
        .worktree
        .as_ref()
        .expect("a git repo remediates in a worktree by default")
        .path
        .clone();
    assert!(remediate.settings.config.isolated);
    assert_ne!(worktree_path, dir.path());

    let paths = out_paths(&dir.path().join("out"));
    let summary = run(
        fast_input(dir.path()),
        fast_config_no_semantic_dedup(),
        None,
        &paths,
        one_finding_client(),
        Arc::new(NoTools),
        None,
        Some(remediate),
        None,
    )
    .await
    .unwrap();
    restore_env("BC_STATE_DIR", prior);

    assert_eq!(summary.remediation.unwrap().processed, 1);
    assert!(!worktree_path.exists());
    assert!(summary.remediation_patch.is_none());
    assert!(!dir.path().join("security-scan/remediation.patch").exists());
}
#[tokio::test]
async fn run_validates_the_remediated_finding_when_validation_is_enabled() {
    let dir = git_repo();
    let paths = out_paths(&dir.path().join("out"));
    let out_json = dir.path().join("remediation.json");
    let remediate = RemediateRun {
        delivery: None,
        settings: RemediateSettings {
            target_tests: None,
            config: appsec_orchestrator::RemediateConfig {
                step10: fast_remediate_config(),
                top: None,
                top_default: None,
                force: false,
                resume: false,
                isolated: false,
            },
            policy: None,
            interactive: false,
            validate_enabled: true,
            step11: fast_step11_config(),
        },
        tools: Arc::new(SandboxTools::new_with_write(dir.path())),
        out_json: Some(out_json.clone()),
        checkpoint: None,
        worktree: None,
    };
    let summary = run(
        fast_input(dir.path()),
        fast_config_no_semantic_dedup(),
        None,
        &paths,
        Arc::new(OneFindingClientWithValidation::new()),
        Arc::new(NoTools),
        None,
        Some(remediate),
        None,
    )
    .await
    .unwrap();
    assert!(summary.to_string().contains("Validation: 1 fixed"));
    let remediation = summary.remediation.unwrap();
    assert_eq!(remediation.processed, 1);
    let tally = remediation.validated.unwrap();
    assert_eq!(tally.fixed, 1);
    assert_eq!(tally.partially_fixed, 0);

    let written: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out_json).unwrap()).unwrap();
    assert_eq!(written["results"][0]["validation"]["fix_status"], "Fixed");
    let gate = &written["results"][0]["validation"]["gate_results"][0];
    let evidence = &gate["evidence"][0];
    assert_eq!(evidence["file"], "app.py");
    assert_eq!(evidence["line"], 2);
    assert_eq!(gate["confidence"], "HIGH");
}
#[tokio::test]
async fn run_threads_a_checkpoint_store_through_to_the_orchestrator() {
    let dir = git_repo();
    let paths = out_paths(&dir.path().join("out"));
    let ckpt_dir = tempfile::tempdir().unwrap();
    let store: Arc<dyn appsec_checkpoint::CheckpointStore> = Arc::new(
        appsec_checkpoint::SqliteCheckpointStore::new(ckpt_dir.path().join("state.db")).unwrap(),
    );
    let remediate = RemediateRun {
        delivery: None,
        settings: RemediateSettings {
            target_tests: None,
            config: appsec_orchestrator::RemediateConfig {
                step10: fast_remediate_config(),
                top: None,
                top_default: None,
                force: false,
                resume: false,
                isolated: false,
            },
            policy: None,
            interactive: false,
            validate_enabled: false,
            step11: fast_step11_config(),
        },
        tools: Arc::new(SandboxTools::new_with_write(dir.path())),
        out_json: None,
        checkpoint: Some(store.clone()),
        worktree: None,
    };
    run(
        fast_input(dir.path()),
        fast_config_no_semantic_dedup(),
        None,
        &paths,
        one_finding_client(),
        Arc::new(NoTools),
        None,
        Some(remediate),
        None,
    )
    .await
    .unwrap();

    let run_id = appsec_checkpoint::run_id_for(dir.path());
    let saved = store.prune_stale(&run_id, appsec_stage_s10::REMEDIATE_STEP_PREFIX, &[]);
    assert_eq!(saved.len(), 1, "{saved:?}");
}
#[tokio::test]
async fn main_impl_stop_after_prevents_requested_remediation() {
    let dir = git_repo();
    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::path("/chat/completions"))
        .and(wiremock::matchers::body_string_contains(S1_MARK))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(
            serde_json::json!({"choices": [{"message": {"content": S1_JSON}, "finish_reason": "stop"}]}),
        ))
        .mount(&server)
        .await;

    let mut c = cli(dir.path());
    c.gateway_base_url = server.uri();
    c.stop_after = "s1".to_string();
    c.remediate = true;

    let _guard = ENV_LOCK.lock().await;
    let state_dir = tempfile::tempdir().unwrap();
    let prior = std::env::var("BC_STATE_DIR").ok();
    unsafe {
        std::env::set_var("BC_STATE_DIR", state_dir.path());
    }
    let summary = main_impl(c).await.unwrap();
    restore_env("BC_STATE_DIR", prior);

    assert_eq!(summary.stopped_after, Some(StopAfter::S1));
    assert!(summary.remediation.is_none());
}
#[test]
fn restore_env_restores_a_prior_value() {
    let _guard = ENV_LOCK.blocking_lock();
    unsafe {
        std::env::set_var("BC_CLI_TEST_ENV_VAR", "temp");
    }
    restore_env("BC_CLI_TEST_ENV_VAR", Some("prior".to_string()));
    assert_eq!(std::env::var("BC_CLI_TEST_ENV_VAR").unwrap(), "prior");
    unsafe {
        std::env::remove_var("BC_CLI_TEST_ENV_VAR");
    }
}
#[test]
fn restore_env_removes_the_var_when_there_was_no_prior_value() {
    let _guard = ENV_LOCK.blocking_lock();
    unsafe {
        std::env::set_var("BC_CLI_TEST_ENV_VAR", "temp");
    }
    restore_env("BC_CLI_TEST_ENV_VAR", None);
    assert!(std::env::var("BC_CLI_TEST_ENV_VAR").is_err());
}
#[test]
fn open_checkpoint_store_degrades_to_none_when_the_state_dir_cannot_be_created() {
    let _guard = ENV_LOCK.blocking_lock();
    let dir = tempfile::tempdir().unwrap();
    let blocker = dir.path().join("blocker");
    std::fs::write(&blocker, b"not a directory").unwrap();
    let prior = std::env::var("BC_STATE_DIR").ok();
    unsafe {
        std::env::set_var("BC_STATE_DIR", &blocker);
    }
    let store = open_checkpoint_store();
    restore_env("BC_STATE_DIR", prior);
    assert!(store.is_none());
}
#[test]
fn open_checkpoint_store_succeeds_at_a_usable_location() {
    let _guard = ENV_LOCK.blocking_lock();
    let dir = tempfile::tempdir().unwrap();
    let prior = std::env::var("BC_STATE_DIR").ok();
    unsafe {
        std::env::set_var("BC_STATE_DIR", dir.path());
    }
    let store = open_checkpoint_store();
    restore_env("BC_STATE_DIR", prior);
    assert!(store.is_some());
}

#[test]
fn gc_summary_display_dry_run_evict() {
    let gc = GcSummary::Evicted {
        path: PathBuf::from("/repo"),
        run_id: "abc123".to_string(),
        found: false,
        dry_run: true,
    };
    assert_eq!(
        gc.to_string(),
        "gc: [dry-run] would evict run abc123 for /repo"
    );
}
#[tokio::test]
async fn main_impl_dispatches_to_gc_when_only_gc_run_is_set() {
    let _guard = ENV_LOCK.lock().await;
    let state_dir = tempfile::tempdir().unwrap();
    let prior = std::env::var("BC_STATE_DIR").ok();
    unsafe {
        std::env::set_var("BC_STATE_DIR", state_dir.path());
    }
    let target = tempfile::tempdir().unwrap();
    let mut c = cli(Path::new("/unused"));
    c.gc_run = Some(target.path().to_path_buf());
    let summary = main_impl(c).await;
    restore_env("BC_STATE_DIR", prior);

    assert!(summary.unwrap().gc.is_some());
}
#[tokio::test]
async fn main_impl_dispatches_to_estimate_before_touching_the_llm_or_scan_path() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("main.py"), b"12345678").unwrap();
    let mut c = cli(dir.path());
    c.estimate = true;
    let summary = main_impl(c).await.unwrap();
    let estimate = summary.estimate.unwrap();
    assert_eq!(estimate.files, 1);
    assert_eq!(estimate.bytes, 8);
    assert!(summary.to_string().contains("scope estimate"));
}
#[tokio::test]
async fn every_non_scanning_mode_writes_no_reports() {
    assert_writes_no_reports("--estimate", |c| c.estimate = true).await;
    assert_writes_no_reports("--setup", |c| c.setup = true).await;
    assert_writes_no_reports("--post-comments-from", |c| {
        c.post_comments_from = Some(PathBuf::from("/does/not/exist.json"))
    })
    .await;
    assert_writes_no_reports("--post-fixes-from", |c| {
        c.post_fixes_from = Some(PathBuf::from("/does/not/exist.json"))
    })
    .await;
}
#[tokio::test]
async fn main_impl_estimate_propagates_a_missing_repo_error() {
    let mut c = cli(Path::new("/nonexistent/estimate/repo"));
    c.estimate = true;
    let err = main_impl(c).await.unwrap_err();
    assert!(err.contains("path does not exist"));
}
#[test]
fn doctor_summary_is_healthy_only_when_unblocked_and_the_probe_succeeded() {
    let ok_probe = environment::Check {
        name: "live probe".to_string(),
        status: environment::CheckStatus::Ok,
        detail: "m reachable".to_string(),
        required: false,
    };
    let healthy = DoctorSummary {
        checks_rendered: String::new(),
        blocking: 0,
        models_rendered: "  [model] m: family=(unknown".to_string(),
        probe: Some(ok_probe.clone()),
        cache_probe: None,
    };
    assert!(healthy.healthy());
    assert!(healthy.to_string().contains('\u{2713}'));
    assert!(healthy.to_string().contains("[model] m: family="));

    let failed_probe = DoctorSummary {
        checks_rendered: String::new(),
        blocking: 0,
        models_rendered: String::new(),
        probe: Some(environment::Check {
            name: "live probe".to_string(),
            status: environment::CheckStatus::Fail,
            detail: "connection refused".to_string(),
            required: false,
        }),
        cache_probe: None,
    };
    assert!(!failed_probe.healthy());
    assert!(failed_probe.to_string().contains('\u{2717}'));

    let unfinished_cache_probe = DoctorSummary {
        cache_probe: Some(cache_probe::CacheProbeOutcome::skipped("m")),
        ..healthy.clone()
    };
    assert!(!unfinished_cache_probe.healthy());
    assert!(unfinished_cache_probe
        .to_string()
        .ends_with("[cache-probe] \u{2717} skipped: the live probe did not reach the model"));
}
#[tokio::test]
async fn doctor_cache_probe_runs_through_the_real_client_after_the_live_probe() {
    let server = cache_probe_gateway(
        "/v1/messages",
        json!({
            "id": "msg_1", "type": "message", "role": "assistant",
            "model": "claude-opus-5",
            "content": [{"type": "text", "text": "PONG"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 12, "output_tokens": 2,
                      "cache_creation_input_tokens": 0,
                      "cache_read_input_tokens": 9000},
        }),
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let mut c = cli(dir.path());
    c.dialect = Dialect::Anthropic;
    c.gateway_base_url = server.uri();
    c.model = "claude-opus-5".to_string();
    c.doctor = true;
    c.cache_probe = true;
    let summary = run_doctor(&c).await;
    assert!(summary.healthy(), "{summary}");
    let outcome = summary.cache_probe.as_ref().unwrap();
    assert_eq!(
        outcome.result.as_ref().unwrap().verdict,
        appsec_llm_client::CacheProbeVerdict::AlreadyWarm
    );
    let text = summary.to_string();
    assert!(
        text.contains("[model] claude-opus-5: family=claude-opus-5"),
        "{text}"
    );
    assert!(text.contains("real tokens were spent"), "{text}");
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 3);
    let probe_body: Value = serde_json::from_slice(&requests[1].body).unwrap();
    assert!(
        probe_body.to_string().contains("cache_control"),
        "{probe_body}"
    );
}
#[tokio::test]
async fn doctor_skips_the_cache_probe_when_the_live_probe_fails_or_a_check_blocks() {
    let dir = tempfile::tempdir().unwrap();
    let mut c = cli(dir.path());
    c.doctor = true;
    c.cache_probe = true;
    let summary = run_doctor(&c).await;
    assert!(!summary.cache_probe.as_ref().unwrap().completed());

    let bad_pem = dir.path().join("bad.pem");
    std::fs::write(&bad_pem, "not a pem file").unwrap();
    c.ca_cert = Some(bad_pem);
    let summary = run_doctor(&c).await;
    assert!(summary.probe.is_none());
    assert!(!summary.cache_probe.as_ref().unwrap().completed());

    c.cache_probe = false;
    assert!(run_doctor(&c).await.cache_probe.is_none());
}
#[tokio::test]
async fn doctor_uses_an_openai_cache_dialect_for_the_openai_client() {
    let server = cache_probe_gateway(
        "/v1/chat/completions",
        json!({
            "id": "c1", "object": "chat.completion", "model": "gpt-4o",
            "choices": [{"index": 0, "finish_reason": "stop",
                         "message": {"role": "assistant", "content": "PONG"}}],
            "usage": {"prompt_tokens": 9000, "completion_tokens": 1,
                      "prompt_tokens_details": {"cached_tokens": 8000}},
        }),
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let mut c = cli(dir.path());
    c.gateway_base_url = format!("{}/v1", server.uri());
    c.model = "gpt-4o".to_string();
    c.doctor = true;
    c.cache_probe = true;
    let summary = run_doctor(&c).await;
    assert_eq!(
        summary.cache_probe.unwrap().result.unwrap().verdict,
        appsec_llm_client::CacheProbeVerdict::OpenAiImplicitWorking
    );
}
#[tokio::test]
async fn main_impl_dispatches_to_doctor_and_skips_the_probe_when_a_check_blocks() {
    let dir = tempfile::tempdir().unwrap();
    let bad_pem = dir.path().join("bad.pem");
    std::fs::write(&bad_pem, "not a pem file").unwrap();
    let mut c = cli(dir.path());
    c.ca_cert = Some(bad_pem);
    c.doctor = true;
    let summary = main_impl(c).await.unwrap();
    let text = summary.to_string();
    let doctor = summary.doctor.unwrap();
    assert_eq!(doctor.blocking, 1);
    assert!(doctor.probe.is_none());
    assert!(!doctor.healthy());
    assert!(text.contains("probe] skipped"));
}
#[tokio::test]
async fn main_impl_dispatches_to_doctor_and_runs_the_probe_when_nothing_blocks() {
    let dir = tempfile::tempdir().unwrap();
    let mut c = cli(dir.path());
    c.doctor = true;
    let summary = main_impl(c).await.unwrap();
    let text = summary.to_string();
    let doctor = summary.doctor.unwrap();
    assert_eq!(doctor.blocking, 0);
    assert!(doctor.probe.is_some());
    assert!(!doctor.healthy());
    assert!(text.contains("probe]"));
    assert!(!text.contains("skipped"));
}
#[test]
fn setup_summary_is_healthy_only_when_nothing_blocks() {
    let healthy = SetupSummary {
        checks_rendered: "  \u{2713} gateway client  ok".to_string(),
        blocking: 0,
    };
    assert!(healthy.healthy());
    assert_eq!(healthy.to_string(), healthy.checks_rendered);

    let blocked = SetupSummary {
        checks_rendered: "  \u{2717} gateway client  bad".to_string(),
        blocking: 1,
    };
    assert!(!blocked.healthy());
}
#[tokio::test]
async fn main_impl_dispatches_to_setup_and_never_touches_the_network() {
    let dir = tempfile::tempdir().unwrap();
    let bad_pem = dir.path().join("bad.pem");
    std::fs::write(&bad_pem, "not a pem file").unwrap();
    let mut c = cli(dir.path());
    c.ca_cert = Some(bad_pem);
    c.setup = true;
    let summary = main_impl(c).await.unwrap();
    let text = summary.to_string();
    let setup = summary.setup.unwrap();
    assert_eq!(setup.blocking, 1);
    assert!(!setup.healthy());
    assert!(text.contains("gateway client"));
    assert!(!text.contains("probe]"));
}
