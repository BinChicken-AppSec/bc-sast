use std::process::Command;

use wiremock::matchers::{body_string_contains, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn setup_repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("app.py"), "print('hi')\n").unwrap();
    dir
}

fn openai_reply(content: &str) -> serde_json::Value {
    serde_json::json!({
        "choices": [{"message": {"content": content}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5},
    })
}

#[tokio::test]
async fn a_scan_stopped_after_s4_succeeds_end_to_end_through_the_real_binary() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("security-focused codebase mapper"))
        .respond_with(ResponseTemplate::new(200).set_body_json(openai_reply(
            r#"{"language":"python","modules":[],"entry_points":[],"unsafe_sinks":[],"call_graph":{},"notes":""}"#,
        )))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("application-security threat modeler"))
        .respond_with(ResponseTemplate::new(200).set_body_json(openai_reply(
            r#"{"system_context":"ctx","assets":[],"trust_boundaries":[],"threats":[],"open_questions":[]}"#,
        )))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("vulnerability research strategist"))
        .respond_with(ResponseTemplate::new(200).set_body_json(openai_reply(
            "garbage, s3 degrades to its deterministic catchall sweep",
        )))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains(
            "security researcher performing deep code analysis",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(openai_reply(r#"{"findings": []}"#)))
        .mount(&server)
        .await;

    let dir = setup_repo();
    let state_dir = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_appsec-scan"))
        .arg("--repo")
        .arg(dir.path())
        .arg("--gateway-base-url")
        .arg(server.uri())
        .arg("--model")
        .arg("test-model")
        .arg("--stop-after")
        .arg("s4")
        .arg("--skip-preflight")
        .env("BC_STATE_DIR", state_dir.path())
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Scan stopped after S4"), "stdout: {stdout}");
}

#[tokio::test]
async fn a_batch_scan_with_repo_file_succeeds_end_to_end_through_the_real_binary() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("security-focused codebase mapper"))
        .respond_with(ResponseTemplate::new(200).set_body_json(openai_reply(
            r#"{"language":"python","modules":[],"entry_points":[],"unsafe_sinks":[],"call_graph":{},"notes":""}"#,
        )))
        .mount(&server)
        .await;

    let dir = setup_repo();
    let manifest_dir = tempfile::tempdir().unwrap();
    let manifest_path = manifest_dir.path().join("manifest.txt");
    std::fs::write(
        &manifest_path,
        format!("app1,repo-a,{}\n", dir.path().display()),
    )
    .unwrap();
    let summary_path = manifest_dir.path().join("nested").join("summary.md");
    let state_dir = tempfile::tempdir().unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_appsec-scan"))
        .arg("--repo-file")
        .arg(&manifest_path)
        .arg("--out-batch-summary")
        .arg(&summary_path)
        .arg("--gateway-base-url")
        .arg(server.uri())
        .arg("--model")
        .arg("test-model")
        .arg("--stop-after")
        .arg("s1")
        .env("BC_STATE_DIR", state_dir.path())
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Batch scan complete: 1/1 succeeded"),
        "stdout: {stdout}"
    );
    let text = std::fs::read_to_string(&summary_path).unwrap();
    assert!(text.contains("# Batch Scan Summary"));
    assert!(
        text.contains("| 1 | app1 | repo-a | OK |"),
        "summary: {text}"
    );
}

#[tokio::test]
async fn a_batch_scan_with_remediate_requested_succeeds_end_to_end_through_the_real_binary() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("security-focused codebase mapper"))
        .respond_with(ResponseTemplate::new(200).set_body_json(openai_reply(
            r#"{"language":"python","modules":[],"entry_points":[],"unsafe_sinks":[],"call_graph":{},"notes":""}"#,
        )))
        .mount(&server)
        .await;

    let dir = setup_repo();
    let manifest_dir = tempfile::tempdir().unwrap();
    let manifest_path = manifest_dir.path().join("manifest.txt");
    std::fs::write(
        &manifest_path,
        format!("app1,repo-a,{}\n", dir.path().display()),
    )
    .unwrap();
    let summary_path = manifest_dir.path().join("summary.md");
    let state_dir = tempfile::tempdir().unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_appsec-scan"))
        .arg("--repo-file")
        .arg(&manifest_path)
        .arg("--out-batch-summary")
        .arg(&summary_path)
        .arg("--gateway-base-url")
        .arg(server.uri())
        .arg("--model")
        .arg("test-model")
        .arg("--stop-after")
        .arg("s1")
        .arg("--remediate")
        .arg("--top")
        .arg("5")
        .env("BC_STATE_DIR", state_dir.path())
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Batch scan complete: 1/1 succeeded"),
        "stdout: {stdout}"
    );
}

#[tokio::test]
async fn a_batch_scan_clones_a_remote_style_entry_through_the_real_binary() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("security-focused codebase mapper"))
        .respond_with(ResponseTemplate::new(200).set_body_json(openai_reply(
            r#"{"language":"python","modules":[],"entry_points":[],"unsafe_sinks":[],"call_graph":{},"notes":""}"#,
        )))
        .mount(&server)
        .await;

    let (_source_guard, source_repo) = git_source_repo_ending_in_dot_git();
    let manifest_dir = tempfile::tempdir().unwrap();
    let manifest_path = manifest_dir.path().join("manifest.txt");
    std::fs::write(
        &manifest_path,
        format!("app1,repo-a,{}\n", source_repo.display()),
    )
    .unwrap();
    let workspace_dir = tempfile::tempdir().unwrap();
    let summary_path = manifest_dir.path().join("summary.md");
    let state_dir = tempfile::tempdir().unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_appsec-scan"))
        .arg("--repo-file")
        .arg(&manifest_path)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--out-batch-summary")
        .arg(&summary_path)
        .arg("--gateway-base-url")
        .arg(server.uri())
        .arg("--model")
        .arg("test-model")
        .arg("--stop-after")
        .arg("s1")
        .env("BC_STATE_DIR", state_dir.path())
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Batch scan complete: 1/1 succeeded"),
        "stdout: {stdout}"
    );
    assert!(!workspace_dir.path().join("repo-a").join("app.py").exists());
}

#[tokio::test]
async fn a_scan_with_config_requested_succeeds_end_to_end_through_the_real_binary() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("security-focused codebase mapper"))
        .respond_with(ResponseTemplate::new(200).set_body_json(openai_reply(
            r#"{"language":"python","modules":[],"entry_points":[],"unsafe_sinks":[],"call_graph":{},"notes":""}"#,
        )))
        .mount(&server)
        .await;

    let dir = setup_repo();
    let config_dir = tempfile::tempdir().unwrap();
    let config_path = config_dir.path().join("config.yaml");
    std::fs::write(&config_path, "step1:\n  max_turns: 5\n").unwrap();
    let state_dir = tempfile::tempdir().unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_appsec-scan"))
        .arg("--repo")
        .arg(dir.path())
        .arg("--gateway-base-url")
        .arg(server.uri())
        .arg("--model")
        .arg("test-model")
        .arg("--stop-after")
        .arg("s1")
        .arg("--config")
        .arg(&config_path)
        .arg("--skip-preflight")
        .env("BC_STATE_DIR", state_dir.path())
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Scan stopped after S1"), "stdout: {stdout}");
}

#[tokio::test]
async fn a_scan_with_remediate_requested_succeeds_end_to_end_through_the_real_binary() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("security-focused codebase mapper"))
        .respond_with(ResponseTemplate::new(200).set_body_json(openai_reply(
            r#"{"language":"python","modules":[],"entry_points":[],"unsafe_sinks":[],"call_graph":{},"notes":""}"#,
        )))
        .mount(&server)
        .await;

    let dir = setup_repo();
    let state_dir = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_appsec-scan"))
        .arg("--repo")
        .arg(dir.path())
        .arg("--gateway-base-url")
        .arg(server.uri())
        .arg("--model")
        .arg("test-model")
        .arg("--stop-after")
        .arg("s1")
        .arg("--remediate")
        .arg("--top")
        .arg("5")
        .arg("--skip-preflight")
        .env("BC_STATE_DIR", state_dir.path())
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Scan stopped after S1"), "stdout: {stdout}");
}

#[tokio::test]
async fn a_scan_with_remediate_given_an_explicit_value_succeeds_end_to_end_through_the_real_binary()
{
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("security-focused codebase mapper"))
        .respond_with(ResponseTemplate::new(200).set_body_json(openai_reply(
            r#"{"language":"python","modules":[],"entry_points":[],"unsafe_sinks":[],"call_graph":{},"notes":""}"#,
        )))
        .mount(&server)
        .await;

    let dir = setup_repo();
    let state_dir = tempfile::tempdir().unwrap();
    for value in ["true", "false"] {
        let output = Command::new(env!("CARGO_BIN_EXE_appsec-scan"))
            .arg("--repo")
            .arg(dir.path())
            .arg("--gateway-base-url")
            .arg(server.uri())
            .arg("--model")
            .arg("test-model")
            .arg("--stop-after")
            .arg("s1")
            .arg("--remediate")
            .arg(value)
            .arg("--skip-preflight")
            .env("BC_STATE_DIR", state_dir.path())
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "--remediate {value}: stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("Scan stopped after S1"),
            "--remediate {value}: stdout: {stdout}"
        );
    }
}

#[tokio::test]
async fn a_scan_with_resume_requested_succeeds_end_to_end_through_the_real_binary() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("security-focused codebase mapper"))
        .respond_with(ResponseTemplate::new(200).set_body_json(openai_reply(
            r#"{"language":"python","modules":[],"entry_points":[],"unsafe_sinks":[],"call_graph":{},"notes":""}"#,
        )))
        .mount(&server)
        .await;

    let dir = setup_repo();
    let state_dir = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_appsec-scan"))
        .arg("--repo")
        .arg(dir.path())
        .arg("--gateway-base-url")
        .arg(server.uri())
        .arg("--model")
        .arg("test-model")
        .arg("--stop-after")
        .arg("s1")
        .arg("--remediate")
        .arg("--resume")
        .arg("--skip-preflight")
        .env("BC_STATE_DIR", state_dir.path())
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Scan stopped after S1"), "stdout: {stdout}");
}

#[tokio::test]
async fn a_scan_with_interactive_requested_succeeds_end_to_end_through_the_real_binary() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("security-focused codebase mapper"))
        .respond_with(ResponseTemplate::new(200).set_body_json(openai_reply(
            r#"{"language":"python","modules":[],"entry_points":[],"unsafe_sinks":[],"call_graph":{},"notes":""}"#,
        )))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("application-security threat modeler"))
        .respond_with(ResponseTemplate::new(200).set_body_json(openai_reply(
            r#"{"system_context":"ctx","assets":[],"trust_boundaries":[],"threats":[],"open_questions":[]}"#,
        )))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("vulnerability research strategist"))
        .respond_with(ResponseTemplate::new(200).set_body_json(openai_reply(
            "garbage, s3 degrades to its deterministic catchall sweep",
        )))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains(
            "security researcher performing deep code analysis",
        ))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(openai_reply(
                &serde_json::json!({"findings": [{
                    "file": "app.py", "line_start": 2, "line_end": 3,
                    "vuln_class": "injection", "title": "SQL injection",
                    "description": "user input reaches a raw query",
                    "code_snippet": "cur.execute(q)", "confidence": 0.9,
                    "source_ref": "app.py:2", "sink_ref": "app.py:3",
                }]})
                .to_string(),
            )),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("second-opinion reviewer"))
        .respond_with(ResponseTemplate::new(200).set_body_json(openai_reply(
            "traced it\nVERDICT: TRUE_POSITIVE (confidence: 9/10) \u{2014} reachable\n\
             CVSS: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\n",
        )))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("exploit development strategist"))
        .respond_with(ResponseTemplate::new(200).set_body_json(openai_reply(
            &serde_json::json!({
                "summary": "One SQL injection finding.",
                "ranked_findings": [{"index": 0, "severity": "high", "exploitability_notes": "reachable"}],
                "chains": [],
            })
            .to_string(),
        )))
        .mount(&server)
        .await;

    let dir = finding_repo();
    let state_dir = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_appsec-scan"))
        .arg("--repo")
        .arg(dir.path())
        .arg("--gateway-base-url")
        .arg(server.uri())
        .arg("--model")
        .arg("test-model")
        .arg("--remediate")
        .arg("--interactive")
        .arg("--skip-preflight")
        .stdin(std::process::Stdio::null())
        .env("BC_STATE_DIR", state_dir.path())
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Remediation: 0 processed, 0 failed."),
        "stdout: {stdout}"
    );
}

#[tokio::test]
async fn a_non_retryable_gateway_error_on_the_first_call_exits_non_zero() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(400).set_body_string("bad request"))
        .mount(&server)
        .await;

    let dir = setup_repo();
    let state_dir = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_appsec-scan"))
        .arg("--repo")
        .arg(dir.path())
        .arg("--gateway-base-url")
        .arg(server.uri())
        .arg("--model")
        .arg("test-model")
        .env("BC_STATE_DIR", state_dir.path())
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("error:"), "stderr: {stderr}");
}

async fn empty_scan_gateway() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("security-focused codebase mapper"))
        .respond_with(ResponseTemplate::new(200).set_body_json(openai_reply(
            r#"{"language":"python","modules":[],"entry_points":[],"unsafe_sinks":[],"call_graph":{},"notes":""}"#,
        )))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("application-security threat modeler"))
        .respond_with(ResponseTemplate::new(200).set_body_json(openai_reply(
            r#"{"system_context":"ctx","assets":[],"trust_boundaries":[],"threats":[],"open_questions":[]}"#,
        )))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("vulnerability research strategist"))
        .respond_with(ResponseTemplate::new(200).set_body_json(openai_reply(
            "garbage, s3 degrades to its deterministic catchall sweep",
        )))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains(
            "security researcher performing deep code analysis",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(openai_reply(r#"{"findings": []}"#)))
        .mount(&server)
        .await;
    server
}

#[tokio::test]
async fn a_scan_with_no_output_flags_writes_every_report_to_the_default_out_dir() {
    let server = empty_scan_gateway().await;
    let dir = git_repo();
    let state_dir = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_appsec-scan"))
        .arg("--repo")
        .arg(dir.path())
        .arg("--gateway-base-url")
        .arg(server.uri())
        .arg("--model")
        .arg("test-model")
        .arg("--skip-preflight")
        .env("BC_STATE_DIR", state_dir.path())
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let out_dir = dir.path().join("security-scan");
    for name in ["report.md", "report.sarif", "report.csv", "findings.json"] {
        assert!(out_dir.join(name).is_file(), "{name} was not written");
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    for name in ["report.md", "report.sarif", "report.csv", "findings.json"] {
        assert!(stdout.contains(name), "stdout: {stdout}");
    }
}

#[tokio::test]
async fn an_out_flag_moves_only_its_own_format_through_the_real_binary() {
    let server = empty_scan_gateway().await;
    let dir = git_repo();
    let elsewhere = tempfile::tempdir().unwrap();
    let sarif = elsewhere.path().join("custom/report.sarif");
    let state_dir = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_appsec-scan"))
        .arg("--repo")
        .arg(dir.path())
        .arg("--gateway-base-url")
        .arg(server.uri())
        .arg("--model")
        .arg("test-model")
        .arg("--out-sarif")
        .arg(&sarif)
        .arg("--skip-preflight")
        .env("BC_STATE_DIR", state_dir.path())
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(sarif.is_file());
    let out_dir = dir.path().join("security-scan");
    assert!(!out_dir.join("report.sarif").exists());
    for name in ["report.md", "report.csv", "findings.json"] {
        assert!(out_dir.join(name).is_file(), "{name} was not written");
    }
}

#[tokio::test]
async fn out_findings_json_is_written_by_a_completed_scan_through_the_real_binary() {
    let server = empty_scan_gateway().await;
    let dir = git_repo();
    let findings_json = dir.path().join("out/findings.json");
    let state_dir = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_appsec-scan"))
        .arg("--repo")
        .arg(dir.path())
        .arg("--gateway-base-url")
        .arg(server.uri())
        .arg("--model")
        .arg("test-model")
        .arg("--out-findings-json")
        .arg(&findings_json)
        .arg("--skip-preflight")
        .env("BC_STATE_DIR", state_dir.path())
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(findings_json.is_file());
    let content = std::fs::read_to_string(&findings_json).unwrap();
    assert!(content.contains("\"commit_sha\""));
    assert!(content.contains("\"findings\""));
}

#[tokio::test]
async fn post_comments_from_posts_via_the_real_binary() {
    let github_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/widgets/pulls/1"))
        .respond_with(ResponseTemplate::new(200).set_body_string(""))
        .mount(&github_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/widgets/pulls/1/comments"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
        .mount(&github_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/widgets/issues/1/comments"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
        .mount(&github_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/repos/acme/widgets/issues/1/comments"))
        .respond_with(ResponseTemplate::new(201))
        .mount(&github_server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let findings_json = dir.path().join("findings.json");
    std::fs::write(
        &findings_json,
        serde_json::json!({
            "commit_sha": "sha123",
            "findings": [{
                "chunk_id": "c1", "file": "app.py", "line_start": 1, "line_end": 1,
                "vuln_class": "injection", "title": "t", "description": "d",
                "code_snippet": "x", "confidence": 0.9,
            }],
        })
        .to_string(),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_appsec-scan"))
        .arg("--repo")
        .arg(dir.path())
        .arg("--gateway-base-url")
        .arg("unused")
        .arg("--post-comments-from")
        .arg(&findings_json)
        .arg("--github-token")
        .arg("tok")
        .arg("--github-repo")
        .arg("acme/widgets")
        .arg("--pr-number")
        .arg("1")
        .arg("--github-api-base-url")
        .arg(github_server.uri())
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("1 created"), "stdout: {stdout}");
}

#[tokio::test]
async fn post_fixes_from_posts_via_the_real_binary() {
    let github_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/widgets/pulls/1"))
        .and(header("Accept", "application/vnd.github.v3.diff"))
        .respond_with(ResponseTemplate::new(200).set_body_string(""))
        .mount(&github_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/widgets/pulls/1"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"head": {"sha": "sha123"}})),
        )
        .mount(&github_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/widgets/pulls/1/comments"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
        .mount(&github_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/widgets/issues/1/comments"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
        .mount(&github_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/repos/acme/widgets/issues/1/comments"))
        .respond_with(ResponseTemplate::new(201))
        .mount(&github_server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let remediation_json = dir.path().join("remediation.json");
    std::fs::write(
        &remediation_json,
        serde_json::json!({
            "refused": null,
            "results": [{
                "status": "processed",
                "finding_index": 1,
                "finding_id": "fid1",
                "verdict": "fixed",
                "policy_action": null,
                "policy_reason": null,
                "final_verdict": null,
                "changes": [],
                "summary": "s",
                "diff": "diff --git a/x b/x\n+fixed",
            }],
        })
        .to_string(),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_appsec-scan"))
        .arg("--repo")
        .arg(dir.path())
        .arg("--gateway-base-url")
        .arg("unused")
        .arg("--post-fixes-from")
        .arg(&remediation_json)
        .arg("--github-token")
        .arg("tok")
        .arg("--github-repo")
        .arg("acme/widgets")
        .arg("--pr-number")
        .arg("1")
        .arg("--github-api-base-url")
        .arg(github_server.uri())
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("1 created"), "stdout: {stdout}");
}

#[test]
fn help_flag_prints_usage_and_exits_zero() {
    let output = Command::new(env!("CARGO_BIN_EXE_appsec-scan"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("Agentic SAST scanner"));
}

#[test]
fn missing_required_args_exits_non_zero_via_clap() {
    let output = Command::new(env!("CARGO_BIN_EXE_appsec-scan"))
        .output()
        .unwrap();
    assert!(!output.status.success());
}

#[tokio::test]
async fn a_scan_with_app_id_and_cmdb_csv_provided_succeeds_end_to_end_through_the_real_binary() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("security-focused codebase mapper"))
        .respond_with(ResponseTemplate::new(200).set_body_json(openai_reply(
            r#"{"language":"python","modules":[],"entry_points":[],"unsafe_sinks":[],"call_graph":{},"notes":""}"#,
        )))
        .mount(&server)
        .await;

    let dir = setup_repo();
    let cmdb_csv = dir.path().join("cmdb.csv");
    std::fs::write(&cmdb_csv, "application_id,name\n").unwrap();
    let state_dir = tempfile::tempdir().unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_appsec-scan"))
        .arg("--repo")
        .arg(dir.path())
        .arg("--gateway-base-url")
        .arg(server.uri())
        .arg("--model")
        .arg("test-model")
        .arg("--stop-after")
        .arg("s1")
        .arg("--app-id")
        .arg("42")
        .arg("--cmdb-csv")
        .arg(&cmdb_csv)
        .arg("--skip-preflight")
        .env("BC_STATE_DIR", state_dir.path())
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Scan stopped after S1"), "stdout: {stdout}");
}

#[test]
fn an_invalid_stop_after_value_exits_non_zero_through_the_real_binary() {
    let dir = setup_repo();
    let state_dir = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_appsec-scan"))
        .arg("--repo")
        .arg(dir.path())
        .arg("--gateway-base-url")
        .arg("unused")
        .arg("--stop-after")
        .arg("not-a-stage")
        .arg("--skip-preflight")
        .env("BC_STATE_DIR", state_dir.path())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid --stop-after"));
}

#[test]
fn doctor_with_a_blocking_check_exits_non_zero_through_the_real_binary() {
    let dir = setup_repo();
    let bad_pem = dir.path().join("bad.pem");
    std::fs::write(&bad_pem, "not a pem file").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_appsec-scan"))
        .arg("--repo")
        .arg(dir.path())
        .arg("--gateway-base-url")
        .arg("http://127.0.0.1:0")
        .arg("--ca-cert")
        .arg(&bad_pem)
        .arg("--doctor")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("gateway client"), "stdout: {stdout}");
    assert!(stdout.contains("probe] skipped"), "stdout: {stdout}");
}

#[test]
fn setup_with_a_blocking_check_exits_non_zero_through_the_real_binary() {
    let dir = setup_repo();
    let bad_pem = dir.path().join("bad.pem");
    std::fs::write(&bad_pem, "not a pem file").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_appsec-scan"))
        .arg("--repo")
        .arg(dir.path())
        .arg("--gateway-base-url")
        .arg("http://127.0.0.1:0")
        .arg("--ca-cert")
        .arg(&bad_pem)
        .arg("--setup")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("gateway client"), "stdout: {stdout}");
    assert!(!stdout.contains("probe]"), "stdout: {stdout}");
}

#[test]
fn preflight_blocks_a_scan_with_a_malformed_ca_cert_through_the_real_binary() {
    let dir = setup_repo();
    let bad_pem = dir.path().join("bad.pem");
    std::fs::write(&bad_pem, "not a pem file").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_appsec-scan"))
        .arg("--repo")
        .arg(dir.path())
        .arg("--gateway-base-url")
        .arg("http://127.0.0.1:0")
        .arg("--ca-cert")
        .arg(&bad_pem)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("preflight failed"), "stderr: {stderr}");
    assert!(stderr.contains("gateway client"), "stderr: {stderr}");
    assert!(stderr.contains("--skip-preflight"), "stderr: {stderr}");
}

#[tokio::test]
async fn preflight_allows_a_healthy_scan_through_end_to_end_through_the_real_binary() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("security-focused codebase mapper"))
        .respond_with(ResponseTemplate::new(200).set_body_json(openai_reply(
            r#"{"language":"python","modules":[],"entry_points":[],"unsafe_sinks":[],"call_graph":{},"notes":""}"#,
        )))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(openai_reply("pong")))
        .mount(&server)
        .await;

    let dir = setup_repo();
    let state_dir = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_appsec-scan"))
        .arg("--repo")
        .arg(dir.path())
        .arg("--gateway-base-url")
        .arg(server.uri())
        .arg("--model")
        .arg("test-model")
        .arg("--stop-after")
        .arg("s1")
        .env("BC_STATE_DIR", state_dir.path())
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Scan stopped after S1"), "stdout: {stdout}");
}

fn out_paths(dir: &std::path::Path) -> appsec_cli::OutputPaths {
    appsec_cli::OutputPaths {
        provider_writeback_plan: None,
        markdown: dir.join("report.md"),
        sarif: dir.join("report.sarif"),
        csv: dir.join("report.csv"),
        findings_json: dir.join("findings.json"),
    }
}

fn cli(repo: &std::path::Path, gateway_base_url: &str) -> appsec_cli::Cli {
    appsec_cli::Cli {
        context_dir: String::new(),
        context_mcp_server: String::new(),
        context_mcp_spaces: Vec::new(),
        context_mcp_label: String::new(),
        repo_key: String::new(),
        branch: String::new(),
        base_ref: String::new(),
        repo: Some(repo.to_path_buf()),
        repo_file: None,
        workspace: std::path::PathBuf::from("./batch-workspace"),
        keep_clones: false,
        git_token: None,
        out_batch_summary: None,
        repo_name: None,
        model: "m".to_string(),
        temperature: None,
        seed: None,
        top_p: None,
        step_timeout: None,
        reasoning_effort: None,
        openai_api: None,
        no_cache_markers: false,
        allow_unsupported_model: false,
        gateway_base_url: gateway_base_url.to_string(),
        gateway_api_key: None,
        ca_cert: None,
        client_cert: None,
        client_key: None,
        dialect: appsec_cli::Dialect::Openai,
        pricing_provider: None,
        stop_after: String::new(),
        context_files: Vec::new(),
        context_urls: Vec::new(),
        app_id: String::new(),
        cmdb_csv: String::new(),
        checkmarx_xml: Vec::new(),
        snyk_json: Vec::new(),
        semgrep_json: Vec::new(),
        aikido_json: Vec::new(),
        sonatype_json: Vec::new(),
        semgrep_token: None,
        semgrep_deployment_slug: None,
        semgrep_repo: None,
        semgrep_branch: None,
        semgrep_base_url: None,
        snyk_token: None,
        snyk_base_url: None,
        snyk_org_id: None,
        snyk_project_id: None,
        sonatype_base_url: None,
        sonatype_username: None,
        sonatype_password: None,
        sonatype_app_id: None,
        sonatype_stage: None,
        aikido_client_id: None,
        aikido_client_secret: None,
        aikido_repo_id: None,
        aikido_base_url: None,
        checkmarx_base_url: None,
        checkmarx_iam_url: None,
        checkmarx_tenant: None,
        checkmarx_api_key: None,
        checkmarx_project_id: None,
        checkmarx_branch: None,
        git_sha: String::new(),
        out_dir: None,
        out_md: None,
        out_sarif: None,
        out_csv: None,
        provider_publish: Default::default(),
        provider_writeback: "off".into(),
        no_threat_model: false,
        max_tokens: None,
        max_scan_seconds: None,
        github_token: None,
        github_repo: None,
        pr_number: None,
        pr_comments: false,
        diff_scope: false,
        compliance_policy: Vec::new(),
        compliance_preset: Vec::new(),
        compliance_scope: String::new(),
        github_api_base_url: "https://api.github.com".to_string(),
        out_findings_json: None,
        post_comments_from: None,
        baseline: None,
        config: None,
        remediate: false,
        validate: None,
        no_validate: false,
        remediation_exit_code: true,
        target_tests: None,
        api_spec: Default::default(),
        api_spec_formats: Vec::new(),
        top: None,
        interactive: false,
        force: false,
        resume: false,
        enforce_remediation_policy: false,
        remediation_policy: None,
        remediation_playbook: None,
        no_syntax_check: false,
        keep_unverified: false,
        max_diff_lines: None,
        max_files_touched: None,
        remediate_dry_run: false,
        verify_command: None,
        verify_timeout: None,
        remediate_in_place: false,
        remediation_delivery: appsec_cli::delivery::DeliveryMode::Patch,
        delivery_remote: None,
        delivery_branch: None,
        keep_remediation_worktree: false,
        out_remediation_json: None,
        post_fixes_from: None,
        remediate_from: None,
        gc: false,
        gc_keep_runs: 100,
        gc_max_age_days: 5,
        gc_run: None,
        gc_dry_run: false,
        estimate: false,
        log_file: None,
        log_stderr: false,
        verbose: 0,
        no_progress: true,
        progress_style: None,
        s6_progress_file: false,
        out_run_manifest: None,
        doctor: false,
        cache_probe: false,
        stream_large_responses: false,
        skip_preflight: true,
        setup: false,
        auto_step1: false,
        no_auto_step1: false,
    }
}

#[test]
fn public_helpers_work_when_linked_as_a_normal_dependency() {
    let dir = setup_repo();
    let c = cli(dir.path(), "http://127.0.0.1:0");

    assert!(appsec_cli::build_llm_client(&c).is_ok());

    let _config = appsec_cli::build_scan_config(&c).unwrap();
    let input = appsec_cli::build_scan_input(&c);
    assert_eq!(input.repo_root, dir.path());

    let paths = appsec_cli::resolve_output_paths(&c);
    assert_eq!(paths.markdown, dir.path().join("security-scan/report.md"));
    assert_eq!(
        paths.findings_json,
        dir.path().join("security-scan/findings.json")
    );
    let outcome = appsec_orchestrator::ScanOutcome {
        provider_writeback_plan: None,
        stopped_after: None,
        report: None,
        markdown: Some("# report".to_string()),
        sarif: Some("{}".to_string()),
    };
    appsec_cli::write_outputs(&outcome, &paths.markdown, &paths.sarif, &paths.csv).unwrap();
    assert!(paths.markdown.is_file());
    assert!(paths.sarif.is_file());
}

#[test]
fn build_scan_input_falls_back_to_repo_when_the_path_has_no_file_name() {
    let input = appsec_cli::build_scan_input(&cli(std::path::Path::new("/"), "http://127.0.0.1:0"));
    assert_eq!(input.repo_name, "repo");
}

#[test]
fn build_llm_client_rejects_a_malformed_ca_cert() {
    let dir = setup_repo();
    let bad_pem = dir.path().join("bad.pem");
    std::fs::write(&bad_pem, "not a pem file").unwrap();
    let mut c = cli(dir.path(), "http://127.0.0.1:0");
    c.ca_cert = Some(bad_pem);
    assert!(appsec_cli::build_llm_client(&c).is_err());
}

struct FakeClient;

#[async_trait::async_trait]
impl appsec_llm_client::LlmClient for FakeClient {
    async fn chat(
        &self,
        request: &appsec_llm_client::ChatRequest,
    ) -> Result<appsec_llm_client::ChatResponse, appsec_llm_client::LlmError> {
        let system = request.system.as_deref().unwrap_or("");
        let text = if system.contains("security-focused codebase mapper") {
            r#"{"language":"python","modules":[],"entry_points":[],"unsafe_sinks":[],"call_graph":{},"notes":""}"#
        } else if system.contains("application-security threat modeler") {
            r#"{"system_context":"ctx","assets":[],"trust_boundaries":[],"threats":[],"open_questions":[]}"#
        } else if system.contains("vulnerability research strategist") {
            "garbage, s3 degrades to its deterministic catchall sweep"
        } else if system.contains("security researcher performing deep code analysis") {
            r#"{"findings": []}"#
        } else {
            panic!("unrecognized system prompt in test fixture: {system}");
        };
        Ok(appsec_llm_client::ChatResponse {
            content: vec![appsec_llm_client::ContentBlock::Text(text.to_string())],
            stop_reason: appsec_llm_client::StopReason::EndTurn,
            usage: appsec_llm_client::Usage::default(),
        })
    }
}

struct FakeTools;
impl appsec_llm_client::ToolExecutor for FakeTools {
    fn available_tools(&self) -> Vec<appsec_llm_client::ToolSpec> {
        ["Read", "Glob", "Grep"]
            .iter()
            .map(|name| appsec_llm_client::ToolSpec {
                name: name.to_string(),
                description: String::new(),
                parameters: serde_json::json!({}),
            })
            .collect()
    }
    fn execute(&self, _name: &str, _args: &serde_json::Value) -> String {
        String::new()
    }
}

fn fast_config() -> appsec_orchestrator::ScanConfig {
    let mut step1 = appsec_stage_s1::Step1Config::new("m");
    step1.retry_backoff_base = std::time::Duration::ZERO;
    let mut step7 = appsec_stage_s7::Step7Config::new("m");
    step7.semantic = false;
    appsec_orchestrator::ScanConfig {
        autoexclude: Default::default(),
        cancel: None,
        step0_enabled: false,
        step0: appsec_stage_s0::Step0Config::new(),
        step1,
        step2_enabled: true,
        step2: appsec_stage_s2::Step2Config::new("m"),
        step3: appsec_stage_s3::Step3Config::new("m"),
        step4: appsec_stage_s4::Step4Config::new("m"),
        step5: appsec_stage_s5::Step5Config::new("m"),
        step6: appsec_stage_s6::Step6Config::new("m"),
        step7,
        step8: appsec_stage_s8::Step8Config::new("m"),
        tool_version: "test".to_string(),
        spend_cap: None,
        checkpoint: None,
        resume: false,
        emit_unreachable_appendix: false,
        progress: None,
        pricing: appsec_orchestrator::pricing::PricingConfig::default(),
    }
}

#[tokio::test]
async fn run_completes_a_full_scan_with_fakes_linked_as_a_normal_dependency() {
    let dir = setup_repo();
    let input = appsec_cli::build_scan_input(&cli(dir.path(), "unused"));
    let summary = appsec_cli::run(
        input,
        fast_config(),
        None,
        &out_paths(dir.path()),
        std::sync::Arc::new(FakeClient),
        std::sync::Arc::new(FakeTools),
        None,
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(summary.findings, 0);
    assert_eq!(summary.stopped_after, None);
}

#[cfg(unix)]
#[tokio::test]
async fn run_refuses_an_unwritable_output_directory_when_linked_as_a_normal_dependency() {
    let dir = setup_repo();
    let unwritable = dir.path().join("locked");
    std::fs::write(&unwritable, "not a directory").unwrap();

    let input = appsec_cli::build_scan_input(&cli(dir.path(), "unused"));
    let result = appsec_cli::run(
        input,
        fast_config(),
        None,
        &out_paths(&unwritable.join("nested")),
        std::sync::Arc::new(FakeClient),
        std::sync::Arc::new(FakeTools),
        None,
        None,
        None,
    )
    .await;

    let err = result.unwrap_err();
    assert!(err.contains("cannot create output directory"), "{err}");
}

struct FakeClientWithFinding;

#[async_trait::async_trait]
impl appsec_llm_client::LlmClient for FakeClientWithFinding {
    async fn chat(
        &self,
        request: &appsec_llm_client::ChatRequest,
    ) -> Result<appsec_llm_client::ChatResponse, appsec_llm_client::LlmError> {
        let system = request.system.as_deref().unwrap_or("");
        let text = if system.contains("security-focused codebase mapper") {
            r#"{"language":"python","modules":[],"entry_points":[],"unsafe_sinks":[],"call_graph":{},"notes":""}"#.to_string()
        } else if system.contains("application-security threat modeler") {
            r#"{"system_context":"ctx","assets":[],"trust_boundaries":[],"threats":[],"open_questions":[]}"#.to_string()
        } else if system.contains("vulnerability research strategist") {
            "not valid json at all, deliberately garbage so s3 degrades to its deterministic catchall sweep".to_string()
        } else if system.contains("security researcher performing deep code analysis") {
            serde_json::json!({"findings": [{
                "file": "app.py", "line_start": 2, "line_end": 3,
                "vuln_class": "injection", "title": "SQL injection",
                "description": "user input reaches a raw query",
                "code_snippet": "cur.execute(q)", "confidence": 0.9,
                "source_ref": "app.py:2", "sink_ref": "app.py:3",
            }]})
            .to_string()
        } else if system.contains("second-opinion reviewer") {
            "traced it\nVERDICT: TRUE_POSITIVE (confidence: 9/10) \u{2014} reachable\n\
             CVSS: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\n"
                .to_string()
        } else if system.contains("exploit development strategist") {
            serde_json::json!({
                "summary": "One SQL injection finding.",
                "ranked_findings": [{"index": 0, "severity": "high", "exploitability_notes": "reachable from an external request"}],
                "chains": [],
            })
            .to_string()
        } else if system.contains("REMEDIATION agent") {
            serde_json::json!({
                "finding_index": 1, "verdict": "Fixed",
                "gates": {"source": "pass", "sink": "pass", "missing_control": "pass"},
                "root_cause": "x",
                "changes": [{"file": "app.py", "summary": "patched"}],
                "remaining_risks": [], "recommendations": [], "summary": "s",
            })
            .to_string()
        } else {
            panic!("unrecognized system prompt in test fixture: {system}");
        };
        Ok(appsec_llm_client::ChatResponse {
            content: vec![appsec_llm_client::ContentBlock::Text(text)],
            stop_reason: appsec_llm_client::StopReason::EndTurn,
            usage: appsec_llm_client::Usage::default(),
        })
    }
}

fn finding_repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("app.py"),
        "def handler(request):\n    q = request.GET['q']\n    cur.execute(q)\n",
    )
    .unwrap();
    dir
}

fn git_repo() -> tempfile::TempDir {
    let dir = finding_repo();
    let run_git = |args: &[&str]| {
        std::process::Command::new("git")
            .arg("-C")
            .arg(dir.path())
            .args(args)
            .output()
            .unwrap()
    };
    run_git(&["init", "-q"]);
    run_git(&[
        "-c",
        "user.email=test@test.com",
        "-c",
        "user.name=test",
        "add",
        "-A",
    ]);
    run_git(&[
        "-c",
        "user.email=test@test.com",
        "-c",
        "user.name=test",
        "commit",
        "-q",
        "-m",
        "x",
    ]);
    dir
}

fn git_source_repo_ending_in_dot_git() -> (tempfile::TempDir, std::path::PathBuf) {
    let container = tempfile::tempdir().unwrap();
    let repo_path = container.path().join("origin.git");
    std::fs::create_dir(&repo_path).unwrap();
    std::fs::write(repo_path.join("app.py"), "print('hi')\n").unwrap();
    let run_git = |args: &[&str]| {
        let out = std::process::Command::new("git")
            .arg("-C")
            .arg(&repo_path)
            .args(args)
            .output()
            .unwrap();
        assert!(out.status.success(), "git {args:?}: {out:?}");
    };
    run_git(&["init", "-q", "-b", "main"]);
    run_git(&[
        "-c",
        "user.email=test@test.com",
        "-c",
        "user.name=test",
        "add",
        "-A",
    ]);
    run_git(&[
        "-c",
        "user.email=test@test.com",
        "-c",
        "user.name=test",
        "commit",
        "-q",
        "-m",
        "x",
    ]);
    (container, repo_path)
}

#[tokio::test]
async fn main_impl_dispatches_to_batch_mode_and_clones_a_remote_style_entry_when_linked_as_a_normal_dependency(
) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("security-focused codebase mapper"))
        .respond_with(ResponseTemplate::new(200).set_body_json(openai_reply(
            r#"{"language":"python","modules":[],"entry_points":[],"unsafe_sinks":[],"call_graph":{},"notes":""}"#,
        )))
        .mount(&server)
        .await;

    let (_source_guard, source_repo) = git_source_repo_ending_in_dot_git();
    let manifest_dir = tempfile::tempdir().unwrap();
    let manifest_path = manifest_dir.path().join("manifest.txt");
    std::fs::write(
        &manifest_path,
        format!("app1,repo-a,{}\n", source_repo.display()),
    )
    .unwrap();
    let workspace_dir = tempfile::tempdir().unwrap();

    let mut c = cli(std::path::Path::new("/unused"), &server.uri());
    c.repo = None;
    c.repo_file = Some(manifest_path);
    c.workspace = workspace_dir.path().to_path_buf();
    c.out_batch_summary = Some(manifest_dir.path().join("summary.md"));
    c.stop_after = "s1".to_string();

    let summary = appsec_cli::main_impl(c).await.unwrap();
    let batch = summary.batch.unwrap();
    assert_eq!(batch.completed, 1);
    assert_eq!(batch.failed, 0);
    assert!(!workspace_dir.path().join("repo-a").join("app.py").exists());
}

#[tokio::test]
async fn main_impl_records_a_failed_entry_when_a_remote_style_clone_fails_when_linked_as_a_normal_dependency(
) {
    let manifest_dir = tempfile::tempdir().unwrap();
    let manifest_path = manifest_dir.path().join("manifest.txt");
    std::fs::write(
        &manifest_path,
        "app1,repo-a,/nonexistent/unclonable/source/repo.git\n",
    )
    .unwrap();
    let workspace_dir = tempfile::tempdir().unwrap();

    let mut c = cli(std::path::Path::new("/unused"), "http://127.0.0.1:0");
    c.repo = None;
    c.repo_file = Some(manifest_path);
    c.workspace = workspace_dir.path().to_path_buf();
    c.out_batch_summary = Some(manifest_dir.path().join("summary.md"));

    let summary = appsec_cli::main_impl(c).await.unwrap();
    let batch = summary.batch.unwrap();
    assert_eq!(batch.completed, 0);
    assert_eq!(batch.failed, 1);
}

#[tokio::test]
async fn run_completes_a_full_scan_with_one_finding_and_syncs_it_to_github_when_linked_as_a_normal_dependency(
) {
    let dir = git_repo();
    let input = appsec_cli::build_scan_input(&cli(dir.path(), "unused"));

    let github_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/widgets/pulls/1"))
        .respond_with(ResponseTemplate::new(200).set_body_string(""))
        .mount(&github_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/widgets/pulls/1/comments"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
        .mount(&github_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/widgets/issues/1/comments"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
        .mount(&github_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/repos/acme/widgets/issues/1/comments"))
        .respond_with(ResponseTemplate::new(201))
        .mount(&github_server)
        .await;

    let mut gh_config = appsec_github::GithubConfig::new("acme", "widgets", 1, "tok");
    gh_config.api_base_url = github_server.uri();
    let github_client = appsec_github::GithubClient::new(reqwest::Client::new(), gh_config);

    let paths = out_paths(dir.path());
    let (md, sarif) = (paths.markdown.clone(), paths.sarif.clone());
    let summary = appsec_cli::run(
        input,
        fast_config(),
        None,
        &paths,
        std::sync::Arc::new(FakeClientWithFinding),
        std::sync::Arc::new(FakeTools),
        Some(github_client),
        None,
        None,
    )
    .await
    .unwrap();

    assert_eq!(summary.findings, 1);
    assert_eq!(
        summary.github_sync,
        Some(Ok(appsec_github::SyncSummary {
            created: 1,
            updated: 0
        }))
    );

    let md_text = std::fs::read_to_string(&md).unwrap();
    assert!(
        md_text.contains("### 1. [CRITICAL] SQL injection"),
        "report.md missing the finding heading: {md_text}"
    );
    assert!(
        md_text.contains("**CWE:** CWE-74:"),
        "report.md missing the CWE line: {md_text}"
    );
    assert!(
        md_text.contains("**File:** `app.py:2-3`"),
        "report.md missing the file:line line: {md_text}"
    );
    assert!(
        md_text.contains("## Findings (1)"),
        "report.md missing the findings-count heading: {md_text}"
    );

    let sarif_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&sarif).unwrap()).unwrap();
    let results = sarif_json["runs"][0]["results"].as_array().unwrap();
    assert_eq!(results.len(), 1, "sarif results: {sarif_json}");
    assert_eq!(results[0]["level"], "error", "sarif result: {}", results[0]);
    assert!(
        results[0]["message"]["text"]
            .as_str()
            .unwrap()
            .contains("SQL injection"),
        "sarif message: {}",
        results[0]["message"]
    );
    assert_eq!(
        results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "app.py",
        "sarif location: {}",
        results[0]["locations"]
    );
}

#[tokio::test]
async fn run_reports_a_github_sync_error_when_linked_as_a_normal_dependency() {
    let dir = git_repo();
    let input = appsec_cli::build_scan_input(&cli(dir.path(), "unused"));

    let github_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/widgets/pulls/1"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&github_server)
        .await;

    let mut gh_config = appsec_github::GithubConfig::new("acme", "widgets", 1, "tok");
    gh_config.api_base_url = github_server.uri();
    let github_client = appsec_github::GithubClient::new(reqwest::Client::new(), gh_config);

    let summary = appsec_cli::run(
        input,
        fast_config(),
        None,
        &out_paths(dir.path()),
        std::sync::Arc::new(FakeClientWithFinding),
        std::sync::Arc::new(FakeTools),
        Some(github_client),
        None,
        None,
    )
    .await
    .unwrap();

    assert!(matches!(summary.github_sync, Some(Err(_))));
}

#[test]
fn build_github_client_rejects_a_repo_without_an_owner_slash_name_separator_when_linked_as_a_normal_dependency(
) {
    let mut c = cli(std::path::Path::new("/repo"), "unused");
    c.github_token = Some("tok".to_string());
    c.github_repo = Some("not-owner-slash-name".to_string());
    c.pr_number = Some(7);
    assert!(appsec_cli::build_github_client(&c).is_err());
}

#[tokio::test]
async fn post_comments_only_posts_findings_when_linked_as_a_normal_dependency() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/widgets/pulls/1"))
        .respond_with(ResponseTemplate::new(200).set_body_string(""))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/widgets/pulls/1/comments"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/widgets/issues/1/comments"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/repos/acme/widgets/issues/1/comments"))
        .respond_with(ResponseTemplate::new(201))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("findings.json");
    std::fs::write(
        &path,
        serde_json::json!({
            "commit_sha": "sha123",
            "findings": [{
                "chunk_id": "c1", "file": "app.py", "line_start": 1, "line_end": 1,
                "vuln_class": "injection", "title": "t", "description": "d",
                "code_snippet": "x", "confidence": 0.9,
            }],
        })
        .to_string(),
    )
    .unwrap();

    let mut gh_config = appsec_github::GithubConfig::new("acme", "widgets", 1, "tok");
    gh_config.api_base_url = server.uri();
    let github_client = appsec_github::GithubClient::new(reqwest::Client::new(), gh_config);

    let summary = appsec_cli::post_comments_only(&github_client, &path, None)
        .await
        .unwrap();
    assert_eq!(summary.findings, 1);
    assert_eq!(
        summary.github_sync,
        Some(Ok(appsec_github::SyncSummary {
            created: 1,
            updated: 0
        }))
    );
}

#[tokio::test]
async fn post_fixes_only_posts_a_fix_suggestion_when_linked_as_a_normal_dependency() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/widgets/pulls/1"))
        .and(header("Accept", "application/vnd.github.v3.diff"))
        .respond_with(ResponseTemplate::new(200).set_body_string(""))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/widgets/pulls/1"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"head": {"sha": "sha123"}})),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/widgets/pulls/1/comments"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/widgets/issues/1/comments"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/repos/acme/widgets/issues/1/comments"))
        .respond_with(ResponseTemplate::new(201))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("remediation.json");
    std::fs::write(
        &path,
        serde_json::json!({
            "refused": null,
            "results": [{
                "status": "processed",
                "finding_index": 1,
                "finding_id": "fid1",
                "verdict": "fixed",
                "policy_action": null,
                "policy_reason": null,
                "final_verdict": null,
                "changes": [],
                "summary": "s",
                "diff": "diff --git a/x b/x\n+fixed",
            }],
        })
        .to_string(),
    )
    .unwrap();

    let mut gh_config = appsec_github::GithubConfig::new("acme", "widgets", 1, "tok");
    gh_config.api_base_url = server.uri();
    let github_client = appsec_github::GithubClient::new(reqwest::Client::new(), gh_config);

    let summary = appsec_cli::post_fixes_only(&github_client, &path)
        .await
        .unwrap();
    assert_eq!(summary.findings, 1);
    assert_eq!(
        summary.github_sync,
        Some(Ok(appsec_github::SyncSummary {
            created: 1,
            updated: 0
        }))
    );
}

#[tokio::test]
async fn main_impl_requires_github_args_for_post_comments_from_when_linked_as_a_normal_dependency()
{
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("findings.json");
    std::fs::write(
        &path,
        serde_json::json!({"commit_sha": "sha", "findings": []}).to_string(),
    )
    .unwrap();

    let mut c = cli(dir.path(), "unused");
    c.post_comments_from = Some(path);
    let result = appsec_cli::main_impl(c).await;
    assert!(result
        .unwrap_err()
        .contains("--post-comments-from requires"));
}

#[tokio::test]
async fn main_impl_requires_github_args_for_post_fixes_from_when_linked_as_a_normal_dependency() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("remediation.json");
    std::fs::write(
        &path,
        serde_json::json!({"refused": null, "results": []}).to_string(),
    )
    .unwrap();

    let mut c = cli(dir.path(), "unused");
    c.post_fixes_from = Some(path);
    let result = appsec_cli::main_impl(c).await;
    assert!(result.unwrap_err().contains("--post-fixes-from requires"));
}

#[test]
fn build_scan_config_propagates_a_malformed_config_file_when_linked_as_a_normal_dependency() {
    let repo_dir = tempfile::tempdir().unwrap();
    let config_dir = tempfile::tempdir().unwrap();
    let config_path = config_dir.path().join("config.yaml");
    std::fs::write(&config_path, "not: [a, valid\n").unwrap();
    let mut c = cli(repo_dir.path(), "unused");
    c.config = Some(config_path);
    assert!(appsec_cli::build_scan_config(&c).is_err());
}

#[test]
fn build_scan_config_rejects_a_config_resolved_inside_the_scan_target_when_linked_as_a_normal_dependency(
) {
    let repo_dir = tempfile::tempdir().unwrap();
    let config_path = repo_dir.path().join("config.yaml");
    std::fs::write(&config_path, "step1:\n  max_turns: 5\n").unwrap();
    let mut c = cli(repo_dir.path(), "unused");
    c.config = Some(config_path);
    assert!(appsec_cli::build_scan_config(&c).is_err());
}

#[test]
fn build_remediate_settings_loads_real_policy_and_playbook_files_when_linked_as_a_normal_dependency(
) {
    let dir = tempfile::tempdir().unwrap();
    let policy_path = dir.path().join("policy.yaml");
    std::fs::write(&policy_path, "default_action: allow\n").unwrap();
    let playbook_path = dir.path().join("playbook.yaml");
    std::fs::write(&playbook_path, "cwe: {}\n").unwrap();
    let mut c = cli(dir.path(), "unused");
    c.enforce_remediation_policy = true;
    c.remediation_policy = Some(policy_path);
    c.remediation_playbook = Some(playbook_path);
    let settings = appsec_cli::build_remediate_settings(&c).unwrap();
    assert!(settings.policy.is_some());
}

#[tokio::test]
async fn post_comments_only_propagates_malformed_json_when_linked_as_a_normal_dependency() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("findings.json");
    std::fs::write(&path, "not valid json").unwrap();

    let gh_config = appsec_github::GithubConfig::new("acme", "widgets", 1, "tok");
    let github_client = appsec_github::GithubClient::new(reqwest::Client::new(), gh_config);

    let result = appsec_cli::post_comments_only(&github_client, &path, None).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn post_comments_only_reports_a_github_sync_failure_when_linked_as_a_normal_dependency() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/widgets/pulls/1"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let findings_path = dir.path().join("findings.json");
    std::fs::write(
        &findings_path,
        serde_json::json!({
            "commit_sha": "sha123",
            "findings": [{
                "chunk_id": "c1", "file": "app.py", "line_start": 1, "line_end": 1,
                "vuln_class": "injection", "title": "t", "description": "d",
                "code_snippet": "x", "confidence": 0.9,
            }],
        })
        .to_string(),
    )
    .unwrap();

    let mut gh_config = appsec_github::GithubConfig::new("acme", "widgets", 1, "tok");
    gh_config.api_base_url = server.uri();
    let github_client = appsec_github::GithubClient::new(reqwest::Client::new(), gh_config);

    let summary = appsec_cli::post_comments_only(&github_client, &findings_path, None)
        .await
        .unwrap();
    assert!(matches!(summary.github_sync, Some(Err(_))));
}

fn sample_report(
    git_sha: Option<&str>,
    findings: Vec<appsec_model::Finding>,
) -> appsec_model::FinalReport {
    appsec_model::FinalReport {
        repo_identity: None,
        provider_ledger: Default::default(),
        repo_root: "/r".to_string(),
        repo_name: None,
        git_sha: git_sha.map(str::to_string),
        findings: findings
            .into_iter()
            .map(|finding| appsec_model::RankedFinding {
                finding,
                severity: appsec_model::Severity::High,
                exploitability_notes: String::new(),
            })
            .collect(),
        chains: Vec::new(),
        dropped: Vec::new(),
        raw_findings_count: 0,
        metrics: None,
        threat_model: None,
        app_profile: None,
        summary: String::new(),
        degraded: false,
        degraded_reason: String::new(),
        unreachable_files: Vec::new(),
    }
}

fn sample_finding() -> appsec_model::Finding {
    appsec_model::Finding {
        provider_origins: Vec::new(),
        component: None,
        chunk_id: "c1".to_string(),
        file: "app.py".to_string(),
        line_start: 1,
        line_end: 1,
        vuln_class: appsec_model::VulnClass::Injection,
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

fn fast_remediate_config() -> appsec_stage_s10::Step10Config {
    let mut step10 = appsec_stage_s10::Step10Config::new("m");
    step10.max_transient_retries = 0;
    step10.retry_backoff_base = std::time::Duration::ZERO;
    step10
}

fn fast_step11_config() -> appsec_stage_s11::Step11Config {
    let mut step11 = appsec_stage_s11::Step11Config::new("m");
    step11.max_transient_retries = 0;
    step11.retry_backoff_base = std::time::Duration::ZERO;
    step11
}

struct S10OnlyClient;

#[async_trait::async_trait]
impl appsec_llm_client::LlmClient for S10OnlyClient {
    async fn chat(
        &self,
        request: &appsec_llm_client::ChatRequest,
    ) -> Result<appsec_llm_client::ChatResponse, appsec_llm_client::LlmError> {
        let system = request.system.as_deref().unwrap_or("");
        assert!(
            system.contains("REMEDIATION agent"),
            "unexpected system prompt in test fixture: {system}"
        );
        let text = serde_json::json!({
            "finding_index": 1, "verdict": "Fixed",
            "gates": {"source": "pass", "sink": "pass", "missing_control": "pass"},
            "root_cause": "x", "changes": [], "remaining_risks": [],
            "recommendations": [], "summary": "s",
        })
        .to_string();
        Ok(appsec_llm_client::ChatResponse {
            content: vec![appsec_llm_client::ContentBlock::Text(text)],
            stop_reason: appsec_llm_client::StopReason::EndTurn,
            usage: appsec_llm_client::Usage::default(),
        })
    }
}

struct FakeTerminal {
    lines: std::collections::VecDeque<Option<String>>,
}

impl FakeTerminal {
    fn prompt(lines: Vec<Option<String>>) -> Self {
        FakeTerminal {
            lines: lines.into(),
        }
    }
}

impl appsec_interactive::BlockingInput for FakeTerminal {
    fn read_key(&mut self) -> std::io::Result<appsec_interactive::Key> {
        unreachable!("FakeTerminal::prompt never enters the tty loop")
    }
    fn read_line(&mut self, _prompt: &str) -> Option<String> {
        self.lines.pop_front().flatten()
    }
}

impl appsec_interactive::Terminal for FakeTerminal {
    fn is_tty(&self) -> bool {
        false
    }
    fn draw(&mut self, _frame: &str) -> std::io::Result<()> {
        unreachable!("FakeTerminal::prompt never enters the tty loop")
    }
    fn write_line(&mut self, _line: &str) {}
}

#[tokio::test]
async fn remediate_interactively_remediates_via_the_prompt_fallback_when_linked_as_a_normal_dependency(
) {
    let dir = git_repo();
    let report = sample_report(None, vec![sample_finding()]);
    let tools: std::sync::Arc<dyn appsec_llm_client::ToolExecutor> = std::sync::Arc::new(
        appsec_sandbox_tools::SandboxTools::new_with_write(dir.path()),
    );
    let config = appsec_orchestrator::RemediateConfig {
        step10: fast_remediate_config(),
        top: Some(appsec_stage_s10::TopSpec::N(1)),
        top_default: None,
        force: false,
        resume: false,
        isolated: false,
    };
    let mut term = FakeTerminal::prompt(vec![Some("all".to_string()), None]);

    let result = appsec_cli::remediate_interactively(
        std::sync::Arc::new(S10OnlyClient),
        tools,
        dir.path(),
        &report,
        &config,
        None,
        None,
        None,
        &mut term,
    )
    .await;

    assert!(result.refused.is_none());
    assert_eq!(result.outcomes.len(), 1);
}

#[tokio::test]
async fn run_remediates_and_exports_a_processed_record_when_linked_as_a_normal_dependency() {
    let dir = git_repo();
    let input = appsec_cli::build_scan_input(&cli(dir.path(), "unused"));
    let out_json = dir.path().join("remediation.json");
    let remediate = appsec_cli::RemediateRun {
        delivery: None,
        settings: appsec_cli::RemediateSettings {
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
        tools: std::sync::Arc::new(appsec_sandbox_tools::SandboxTools::new_with_write(
            dir.path(),
        )),
        out_json: Some(out_json.clone()),
        checkpoint: None,
        worktree: None,
    };

    let summary = appsec_cli::run(
        input,
        fast_config(),
        None,
        &out_paths(dir.path()),
        std::sync::Arc::new(FakeClientWithFinding),
        std::sync::Arc::new(FakeTools),
        None,
        Some(remediate),
        None,
    )
    .await
    .unwrap();

    let remediation = summary.remediation.unwrap();
    assert_eq!(remediation.processed, 1);
    assert_eq!(remediation.failed, 0);

    let written: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out_json).unwrap()).unwrap();
    assert_eq!(written["results"][0]["status"], "processed");
    assert_eq!(written["results"][0]["changes"][0]["file"], "app.py");
}

#[tokio::test]
async fn a_baseline_classifies_findings_end_to_end_through_the_real_binary() {
    let server = MockServer::start().await;
    for (marker, reply) in [
        (
            "security-focused codebase mapper",
            r#"{"language":"python","modules":[],"entry_points":[],"unsafe_sinks":[],"call_graph":{},"notes":""}"#,
        ),
        (
            "application-security threat modeler",
            r#"{"system_context":"ctx","assets":[],"trust_boundaries":[],"threats":[],"open_questions":[]}"#,
        ),
        (
            "vulnerability research strategist",
            "garbage, s3 degrades to its deterministic catchall sweep",
        ),
        (
            "security researcher performing deep code analysis",
            r#"{"findings": []}"#,
        ),
        ("exploit development strategist", r#"{"chains": []}"#),
    ] {
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .and(body_string_contains(marker))
            .respond_with(ResponseTemplate::new(200).set_body_json(openai_reply(reply)))
            .mount(&server)
            .await;
    }

    let dir = setup_repo();
    let baseline_path = dir.path().join("baseline.json");
    std::fs::write(
        &baseline_path,
        serde_json::json!({
            "commit_sha": "abc",
            "findings": [{
                "chunk_id": "c0", "file": "old.py", "line_start": 7, "line_end": 7,
                "vuln_class": "injection", "title": "Previously reported SQLi",
                "description": "d", "code_snippet": "x", "confidence": 0.9, "votes": 1,
                "cvss_score": 9.8, "cvss_rating": "Critical",
            }],
        })
        .to_string(),
    )
    .unwrap();
    let state_dir = tempfile::tempdir().unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_appsec-scan"))
        .arg("--repo")
        .arg(dir.path())
        .arg("--gateway-base-url")
        .arg(server.uri())
        .arg("--model")
        .arg("test-model")
        .arg("--baseline")
        .arg(&baseline_path)
        .arg("--skip-preflight")
        .env("BC_STATE_DIR", state_dir.path())
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Baseline: 0 new, 0 unchanged, 1 resolved."),
        "stdout: {stdout}"
    );
    let markdown = std::fs::read_to_string(dir.path().join("security-scan/report.md")).unwrap();
    assert!(markdown.contains("## Baseline Comparison"), "{markdown}");
    assert!(
        markdown.contains("Previously reported SQLi"),
        "the resolved finding is named: {markdown}"
    );
    let sarif: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(dir.path().join("security-scan/report.sarif")).unwrap(),
    )
    .unwrap();
    let results = sarif["runs"][0]["results"].as_array().unwrap();
    assert_eq!(results.len(), 1, "no current findings, one resolved");
    assert_eq!(results[0]["baselineState"], "absent");
    assert_eq!(results[0]["message"]["text"], "Previously reported SQLi");
    assert_eq!(results[0]["level"], "error");
    assert_eq!(results[0]["rank"], 98.0);
    assert_eq!(results[0]["properties"]["cvssScore"], 9.8);
}

#[tokio::test]
async fn stream_large_responses_streams_only_the_large_call_through_the_real_binary() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("security-focused codebase mapper"))
        .respond_with(ResponseTemplate::new(200).set_body_json(openai_reply(
            r#"{"language":"python","modules":[],"entry_points":[],"unsafe_sinks":[],"call_graph":{},"notes":""}"#,
        )))
        .mount(&server)
        .await;
    let threat_model = r#"{\"system_context\":\"ctx\",\"assets\":[],\"trust_boundaries\":[],\"threats\":[],\"open_questions\":[]}"#;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("application-security threat modeler"))
        .and(wiremock::matchers::body_partial_json(
            serde_json::json!({"stream": true, "stream_options": {"include_usage": true}}),
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(format!(
                    "data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"{threat_model}\"}}}}]}}\n\n\
                     data: {{\"choices\":[{{\"index\":0,\"delta\":{{}},\"finish_reason\":\"stop\"}}]}}\n\n\
                     data: {{\"choices\":[],\"usage\":{{\"prompt_tokens\":11,\"completion_tokens\":3}}}}\n\n\
                     data: [DONE]\n\n"
                )),
        )
        .expect(1)
        .mount(&server)
        .await;

    let dir = setup_repo();
    let state_dir = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_appsec-scan"))
        .arg("--repo")
        .arg(dir.path())
        .arg("--gateway-base-url")
        .arg(server.uri())
        .arg("--model")
        .arg("test-model")
        .arg("--stream-large-responses")
        .arg("--stop-after")
        .arg("s2")
        .arg("--skip-preflight")
        .env("BC_STATE_DIR", state_dir.path())
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Scan stopped after S2"), "stdout: {stdout}");
}

async fn mount_one_finding_scan(server: &MockServer) {
    for (marker, reply) in [
        (
            "security-focused codebase mapper",
            r#"{"language":"python","modules":[],"entry_points":[],"unsafe_sinks":[],"call_graph":{},"notes":""}"#.to_string(),
        ),
        (
            "application-security threat modeler",
            r#"{"system_context":"ctx","assets":[],"trust_boundaries":[],"threats":[],"open_questions":[]}"#.to_string(),
        ),
        (
            "vulnerability research strategist",
            "garbage, s3 degrades to its deterministic catchall sweep".to_string(),
        ),
        (
            "security researcher performing deep code analysis",
            serde_json::json!({"findings": [{
                "file": "app.py", "line_start": 2, "line_end": 3,
                "vuln_class": "injection", "title": "SQL injection",
                "description": "user input reaches a raw query",
                "code_snippet": "cur.execute(q)", "confidence": 0.9,
                "source_ref": "app.py:2", "sink_ref": "app.py:3",
            }]})
            .to_string(),
        ),
        (
            "second-opinion reviewer",
            "traced it\nVERDICT: TRUE_POSITIVE (confidence: 9/10) \u{2014} reachable\n\
             CVSS: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\n"
                .to_string(),
        ),
        (
            "exploit development strategist",
            serde_json::json!({
                "summary": "One SQL injection finding.",
                "ranked_findings": [{"index": 0, "severity": "high", "exploitability_notes": "reachable"}],
                "chains": [],
            })
            .to_string(),
        ),
        (
            "REMEDIATION agent",
            serde_json::json!({
                "finding_index": 1, "verdict": "Fixed",
                "gates": {"source": "pass", "sink": "pass", "missing_control": "pass"},
                "root_cause": "unparameterized query", "changes": [],
                "remaining_risks": [], "recommendations": [], "summary": "s",
            })
            .to_string(),
        ),
    ] {
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .and(body_string_contains(marker))
            .respond_with(ResponseTemplate::new(200).set_body_json(openai_reply(&reply)))
            .mount(server)
            .await;
    }
}

#[tokio::test]
async fn remediate_from_augments_the_prior_reports_through_the_real_binary() {
    let server = MockServer::start().await;
    mount_one_finding_scan(&server).await;

    let dir = git_repo();
    let source_before = std::fs::read(dir.path().join("app.py")).unwrap();
    let export = dir.path().join("findings.json");
    let state_dir = tempfile::tempdir().unwrap();
    let md_path = dir.path().join("security-scan/report.md");
    let sarif_path = dir.path().join("security-scan/report.sarif");

    let scan = Command::new(env!("CARGO_BIN_EXE_appsec-scan"))
        .arg("--repo")
        .arg(dir.path())
        .arg("--gateway-base-url")
        .arg(server.uri())
        .arg("--model")
        .arg("test-model")
        .arg("--out-findings-json")
        .arg(&export)
        .arg("--skip-preflight")
        .env("BC_STATE_DIR", state_dir.path())
        .output()
        .unwrap();
    assert!(
        scan.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&scan.stderr)
    );
    let before = std::fs::read_to_string(&md_path).unwrap();
    assert!(!before.contains("#### Remediation"), "{before}");

    let remediate = Command::new(env!("CARGO_BIN_EXE_appsec-scan"))
        .arg("--repo")
        .arg(dir.path())
        .arg("--gateway-base-url")
        .arg(server.uri())
        .arg("--model")
        .arg("test-model")
        .arg("--remediate-from")
        .arg(&export)
        .arg("--remediate-in-place")
        .arg("--skip-preflight")
        .env("BC_STATE_DIR", state_dir.path())
        .output()
        .unwrap();
    assert!(
        remediate.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&remediate.stderr)
    );

    let stdout = String::from_utf8_lossy(&remediate.stdout);
    assert!(
        stdout.contains(&format!("augmented {}", md_path.display())),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains(&format!("augmented {}", sarif_path.display())),
        "stdout: {stdout}"
    );

    let after = std::fs::read_to_string(&md_path).unwrap();
    assert!(after.contains("#### Remediation"), "{after}");
    assert!(after.contains("## Remediation Summary"), "{after}");
    assert!(after.contains("Needs Review"), "{after}");
    assert!(
        after.contains("no corresponding on-disk change was found"),
        "{after}"
    );
    assert_eq!(
        std::fs::read(dir.path().join("app.py")).unwrap(),
        source_before
    );
    assert!(after.contains("SQL injection"), "{after}");
    let sarif: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&sarif_path).unwrap()).unwrap();
    assert_eq!(
        sarif["runs"][0]["results"][0]["properties"]["remediationStatus"],
        "Needs Review"
    );
}

#[tokio::test]
async fn remediate_from_reports_a_missing_prior_report_through_the_real_binary() {
    let server = MockServer::start().await;
    mount_one_finding_scan(&server).await;

    let dir = git_repo();
    let sha = String::from_utf8_lossy(
        &std::process::Command::new("git")
            .arg("-C")
            .arg(dir.path())
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap()
            .stdout,
    )
    .trim()
    .to_string();
    let export = dir.path().join("findings.json");
    std::fs::write(
        &export,
        serde_json::json!({
            "commit_sha": sha,
            "findings": [{
                "chunk_id": "c0", "file": "app.py", "line_start": 2, "line_end": 3,
                "vuln_class": "injection", "title": "SQL injection", "description": "d",
                "code_snippet": "cur.execute(q)", "confidence": 0.9, "votes": 1,
                "cvss_rating": "High",
            }],
        })
        .to_string(),
    )
    .unwrap();
    let state_dir = tempfile::tempdir().unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_appsec-scan"))
        .arg("--repo")
        .arg(dir.path())
        .arg("--gateway-base-url")
        .arg(server.uri())
        .arg("--model")
        .arg("test-model")
        .arg("--remediate-from")
        .arg(&export)
        .arg("--remediate-in-place")
        .arg("--skip-preflight")
        .env("BC_STATE_DIR", state_dir.path())
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("no prior report at"), "stdout: {stdout}");
    assert!(
        !dir.path().join("security-scan/report.md").exists(),
        "nothing is created that wasn't already there"
    );
}

#[tokio::test]
async fn a_per_entry_manifest_baseline_reaches_the_batch_summary_through_the_real_binary() {
    let server = MockServer::start().await;
    for (marker, reply) in [
        (
            "security-focused codebase mapper",
            r#"{"language":"python","modules":[],"entry_points":[],"unsafe_sinks":[],"call_graph":{},"notes":""}"#,
        ),
        (
            "application-security threat modeler",
            r#"{"system_context":"ctx","assets":[],"trust_boundaries":[],"threats":[],"open_questions":[]}"#,
        ),
        (
            "vulnerability research strategist",
            "garbage, s3 degrades to its deterministic catchall sweep",
        ),
        (
            "security researcher performing deep code analysis",
            r#"{"findings": []}"#,
        ),
        ("exploit development strategist", r#"{"chains": []}"#),
    ] {
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .and(body_string_contains(marker))
            .respond_with(ResponseTemplate::new(200).set_body_json(openai_reply(reply)))
            .mount(&server)
            .await;
    }

    let dir = setup_repo();
    let manifest_dir = tempfile::tempdir().unwrap();
    std::fs::write(
        manifest_dir.path().join("base.json"),
        serde_json::json!({
            "commit_sha": "abc",
            "findings": [{
                "chunk_id": "c0", "file": "old.py", "line_start": 7, "line_end": 7,
                "vuln_class": "injection", "title": "Previously reported SQLi",
                "description": "d", "code_snippet": "x", "confidence": 0.9, "votes": 1,
            }],
        })
        .to_string(),
    )
    .unwrap();
    let manifest_path = manifest_dir.path().join("manifest.txt");
    std::fs::write(
        &manifest_path,
        format!("app1,repo-a,{},base.json\n", dir.path().display()),
    )
    .unwrap();
    let summary_path = manifest_dir.path().join("summary.md");
    let state_dir = tempfile::tempdir().unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_appsec-scan"))
        .arg("--repo-file")
        .arg(&manifest_path)
        .arg("--out-batch-summary")
        .arg(&summary_path)
        .arg("--gateway-base-url")
        .arg(server.uri())
        .arg("--model")
        .arg("test-model")
        .env("BC_STATE_DIR", state_dir.path())
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = std::fs::read_to_string(&summary_path).unwrap();
    assert!(
        text.contains("| 1 | app1 | repo-a | OK | 0 | 0 | 0 | 1 |"),
        "summary: {text}"
    );
    let markdown = std::fs::read_to_string(dir.path().join("security-scan/report.md")).unwrap();
    assert!(
        markdown.contains("Previously reported SQLi"),
        "the entry's own report carries the comparison too: {markdown}"
    );
}

#[tokio::test]
async fn a_top_level_baseline_with_repo_file_exits_non_zero_through_the_real_binary() {
    let dir = setup_repo();
    let manifest_path = dir.path().join("manifest.txt");
    std::fs::write(
        &manifest_path,
        format!("app1,repo-a,{}\n", dir.path().display()),
    )
    .unwrap();
    let state_dir = tempfile::tempdir().unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_appsec-scan"))
        .arg("--repo-file")
        .arg(&manifest_path)
        .arg("--gateway-base-url")
        .arg("http://127.0.0.1:1")
        .arg("--model")
        .arg("test-model")
        .arg("--baseline")
        .arg(dir.path().join("base.json"))
        .env("BC_STATE_DIR", state_dir.path())
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--baseline cannot be combined with --repo-file"),
        "stderr: {stderr}"
    );
}

#[tokio::test]
async fn a_missing_baseline_exits_non_zero_through_the_real_binary() {
    let dir = setup_repo();
    let state_dir = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_appsec-scan"))
        .arg("--repo")
        .arg(dir.path())
        .arg("--gateway-base-url")
        .arg("http://127.0.0.1:1")
        .arg("--model")
        .arg("test-model")
        .arg("--baseline")
        .arg(dir.path().join("nope.json"))
        .arg("--skip-preflight")
        .env("BC_STATE_DIR", state_dir.path())
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("cannot read baseline"), "stderr: {stderr}");
}

async fn slow_s3_gateway(delay: std::time::Duration) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("security-focused codebase mapper"))
        .respond_with(ResponseTemplate::new(200).set_body_json(openai_reply(
            r#"{"language":"python","modules":[],"entry_points":[],"unsafe_sinks":[],"call_graph":{},"notes":""}"#,
        )))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("application-security threat modeler"))
        .respond_with(ResponseTemplate::new(200).set_body_json(openai_reply(
            r#"{"system_context":"ctx","assets":[],"trust_boundaries":[],"threats":[],"open_questions":[]}"#,
        )))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("vulnerability research strategist"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(openai_reply(
                    "garbage, s3 degrades to its deterministic catchall sweep",
                ))
                .set_delay(delay),
        )
        .mount(&server)
        .await;
    server
}

async fn s3_call_arrived(server: &MockServer) -> bool {
    let requests = server.received_requests().await.unwrap_or_default();
    requests.iter().any(|request| {
        String::from_utf8_lossy(&request.body).contains("vulnerability research strategist")
    })
}

async fn scan_interrupted(
    server: &MockServer,
    repo: &std::path::Path,
    state: &std::path::Path,
    signals: usize,
) -> (std::process::Output, std::time::Duration) {
    let log_dir = tempfile::tempdir().unwrap();
    let stderr_path = log_dir.path().join("stderr.log");
    let stderr_file = std::fs::File::create(&stderr_path).unwrap();
    let started = std::time::Instant::now();
    let child = Command::new(env!("CARGO_BIN_EXE_appsec-scan"))
        .arg("--repo")
        .arg(repo)
        .arg("--gateway-base-url")
        .arg(server.uri())
        .arg("--model")
        .arg("test-model")
        .arg("--skip-preflight")
        .arg("--no-progress")
        .env("BC_STATE_DIR", state)
        .stdout(std::process::Stdio::piped())
        .stderr(stderr_file)
        .spawn()
        .unwrap();
    let limit = std::time::Duration::from_secs(60);
    let timed_out = format!("the scan never reached S3 within {limit:?}");
    while !s3_call_arrived(server).await {
        assert!(started.elapsed() < limit, "{timed_out}");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let unacknowledged = format!("a Ctrl-C went unacknowledged for {limit:?}");
    for sent in 1..=signals {
        let status = Command::new("kill")
            .arg("-INT")
            .arg(child.id().to_string())
            .status()
            .unwrap();
        assert!(status.success());
        while acknowledged_presses(&stderr_path) < sent {
            assert!(started.elapsed() < limit, "{unacknowledged}");
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }
    let mut output = child.wait_with_output().unwrap();
    output.stderr = std::fs::read(&stderr_path).unwrap();
    (output, started.elapsed())
}

fn acknowledged_presses(stderr_path: &std::path::Path) -> usize {
    let stderr = std::fs::read_to_string(stderr_path).unwrap();
    stderr.matches("[cancel] Ctrl-C:").count()
}

#[tokio::test]
async fn a_first_ctrl_c_cancels_the_scan_but_still_writes_a_marked_partial_report() {
    let server = slow_s3_gateway(std::time::Duration::from_secs(4)).await;
    let dir = setup_repo();
    let state = tempfile::tempdir().unwrap();
    let (output, _) = scan_interrupted(&server, dir.path(), state.path(), 1).await;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(130), "stderr: {stderr}");
    assert!(
        stderr.contains("[cancel] Ctrl-C: stopping"),
        "stderr: {stderr}"
    );
    let out_dir = dir.path().join("security-scan");
    let md = std::fs::read_to_string(out_dir.join("report.md")).unwrap();
    assert!(md.contains("**CANCELED**"), "{md}");
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(out_dir.join("run_manifest.json")).unwrap())
            .unwrap();
    assert_eq!(manifest["exit_code"], 130);
    assert_eq!(manifest["canceled"], true);
}

#[tokio::test]
async fn a_second_ctrl_c_exits_at_once() {
    let delay = std::time::Duration::from_secs(20);
    let server = slow_s3_gateway(delay).await;
    let dir = setup_repo();
    let state = tempfile::tempdir().unwrap();
    let (output, elapsed) = scan_interrupted(&server, dir.path(), state.path(), 2).await;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(130), "stderr: {stderr}");
    assert!(stderr.contains("exiting now"), "stderr: {stderr}");
    assert!(elapsed < delay, "took {elapsed:?}");
}
