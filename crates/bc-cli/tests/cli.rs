//! End-to-end tests of the actual compiled `bc-sast` binary against a local
//! `wiremock` gateway — the one piece of this crate's logic that can't be
//! exercised by `lib.rs`'s fake-`LlmClient` unit tests: `main.rs`'s own
//! body (parse real `argv`, print/exit on `main_impl`'s result) and
//! `main_impl`'s real, network-backed `build_llm_client`/
//! `SandboxTools::new` wiring.

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
    let output = Command::new(env!("CARGO_BIN_EXE_bc-sast"))
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

/// `--repo-file` batch mode through the REAL compiled binary — the same
/// dual/triple compilation gotcha noted below: `batch.rs`'s functions are
/// private, so the only way any test reaches them from `bc-cli`'s
/// `src/main.rs`/subprocess compilation unit (as opposed to `src/lib.rs`'s
/// own `#[cfg(test)] mod tests`, a separate compiled artifact) is a real
/// `--repo-file` flag through real `argv`.
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

    let output = Command::new(env!("CARGO_BIN_EXE_bc-sast"))
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

/// `--remediate` forwarded per batch entry (task #151) through the REAL
/// compiled binary — same rationale as
/// `a_scan_with_remediate_requested_succeeds_end_to_end_through_the_real_binary`:
/// `--stop-after s1` keeps the mocked scan trivial while still exercising
/// `run_one_entry`'s real `build_remediate_settings`/`RemediateRun`
/// construction; remediation itself is correctly skipped since the scan
/// never reaches a `FinalReport`.
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

    let output = Command::new(env!("CARGO_BIN_EXE_bc-sast"))
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

/// Batch mode's remote-clone path (task #150) through the REAL compiled
/// binary — same dual/triple-compilation rationale as every other
/// `..._through_the_real_binary` test in this file: `clone::acquire_repo`
/// and `clone::purge_clone`'s remote-clone branches are only reachable,
/// in the actual `bc-sast` executable's own compiled instance, through a
/// real `--repo-file` manifest whose entry is a git URL.
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

    let output = Command::new(env!("CARGO_BIN_EXE_bc-sast"))
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
    // `--keep-clones` was not passed: the cloned source is purged.
    assert!(!workspace_dir.path().join("repo-a").join("app.py").exists());
}

/// `--config` through the REAL compiled binary and real `argv` — the
/// dual/triple compilation gotcha (`feedback_coverage_tool_gotchas.md`
/// #4/#4b) means `getenv` (used internally by `bc_config::load` for
/// `${VAR}` expansion and the local-override opt-outs) is only ever
/// invoked, in the actual `bc-sast` executable's own compiled instance, by a
/// real `--config` flag reaching `main_impl` through real `argv` — no
/// in-process test (however it links `bc_cli`) can attribute coverage
/// back to THIS specific compiled artifact.
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
    // Kept outside `--repo` (a separate tempdir) so the in-scan-target
    // config-trust gate doesn't refuse it.
    let config_dir = tempfile::tempdir().unwrap();
    let config_path = config_dir.path().join("config.yaml");
    std::fs::write(&config_path, "step1:\n  max_turns: 5\n").unwrap();
    let state_dir = tempfile::tempdir().unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_bc-sast"))
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

/// `--remediate` through the REAL compiled binary and real `argv` — the
/// dual lib/bin compilation gotcha (see `feedback_coverage_tool_gotchas.md`
/// #4/#4b) means an in-process `main_impl` test alone doesn't reliably
/// attribute coverage back to the copy of `build_remediate_settings`/
/// `main_impl`'s remediate-wiring code linked into the actual `bc-sast`
/// executable. `--stop-after s1` keeps the mocked scan trivial (one
/// canned reply) while still exercising the real binary's `--remediate`
/// flag parsing and `RemediateRun` construction; remediation itself is
/// correctly skipped since the scan never reaches a `FinalReport` (proven
/// in isolation by `bc-cli`'s own in-process test suite).
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
    // `--remediate` makes the binary open a checkpoint DB at
    // `$BC_STATE_DIR` — redirect it to a throwaway tempdir so
    // this test never touches the real developer state dir.
    let state_dir = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_bc-sast"))
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

/// `--remediate`'s explicit-value forms (`--remediate true`/`--remediate
/// false`), through the REAL compiled binary — `action.yml` always
/// passes an explicit value (never the bare flag) since its static
/// `args:` array can't conditionally omit an element; this is exactly
/// the shape that broke once before (a custom `value_parser` panicking
/// at runtime on a real `argv`, see `feedback_coverage_tool_gotchas.md`
/// and this doc's own "Hit and recovered from a real clap regression"
/// history) and only a real-binary subprocess test would have caught.
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
        let output = Command::new(env!("CARGO_BIN_EXE_bc-sast"))
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

/// `--resume` through the REAL compiled binary and real `argv` — same
/// coverage-attribution rationale as the `--remediate` test above (a
/// brand-new flag needs its own real-binary exercise, gotcha #4b).
/// `--stop-after s1` again keeps remediation itself a no-op; this only
/// proves `--resume` parses and threads through `main_impl` without
/// error, including a real `open_checkpoint_store` call against an
/// isolated state dir.
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
    let output = Command::new(env!("CARGO_BIN_EXE_bc-sast"))
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

/// `--interactive` through the REAL compiled binary and real `argv` —
/// same dual-compilation rationale as the `--remediate`/`--resume` tests
/// above, but this one needs the scan to actually reach a `FinalReport`
/// (unlike those, which stop at S1) since `remediate_interactively` is
/// only ever called once one exists. The subprocess's OWN stdin is
/// explicitly `Stdio::null()` — `--interactive` degrades to the
/// numbered-prompt fallback against a non-TTY stream, and an
/// unredirected stdin could otherwise block waiting for a line that
/// never comes; `null()` makes `read_line` see EOF immediately, so the
/// picker exits after zero picks with no hang risk.
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
    let output = Command::new(env!("CARGO_BIN_EXE_bc-sast"))
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
    let output = Command::new(env!("CARGO_BIN_EXE_bc-sast"))
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

/// A gateway that answers every stage of a clean, finding-free scan:
/// enough for the binary to reach a `FinalReport` and write its reports.
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

/// Every report a completed scan writes, with no output flag passed at
/// all: the default out-dir is `<repo>/security-scan/`, and all four
/// artifacts land in it.
#[tokio::test]
async fn a_scan_with_no_output_flags_writes_every_report_to_the_default_out_dir() {
    let server = empty_scan_gateway().await;
    let dir = git_repo();
    let state_dir = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_bc-sast"))
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
    // And the summary line names them, so an operator can find them
    // without knowing the default.
    let stdout = String::from_utf8_lossy(&output.stdout);
    for name in ["report.md", "report.sarif", "report.csv", "findings.json"] {
        assert!(stdout.contains(name), "stdout: {stdout}");
    }
}

/// One `--out-*` flag moves ONLY its own format; the other three still
/// land in the out-dir. `--out-dir` itself moves the whole set.
#[tokio::test]
async fn an_out_flag_moves_only_its_own_format_through_the_real_binary() {
    let server = empty_scan_gateway().await;
    let dir = git_repo();
    let elsewhere = tempfile::tempdir().unwrap();
    let sarif = elsewhere.path().join("custom/report.sarif");
    let state_dir = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_bc-sast"))
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
    // Created on the way, not required to exist beforehand.
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
    let output = Command::new(env!("CARGO_BIN_EXE_bc-sast"))
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

    let output = Command::new(env!("CARGO_BIN_EXE_bc-sast"))
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

    let output = Command::new(env!("CARGO_BIN_EXE_bc-sast"))
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
    let output = Command::new(env!("CARGO_BIN_EXE_bc-sast"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("Agentic SAST scanner"));
}

#[test]
fn missing_required_args_exits_non_zero_via_clap() {
    let output = Command::new(env!("CARGO_BIN_EXE_bc-sast"))
        .output()
        .unwrap();
    assert!(!output.status.success());
}

/// `--stop-after`/`--app-id`/`--cmdb-csv` through the REAL compiled
/// binary — these became raw `String` fields (from `Option<T>`) so
/// `action.yml`'s static `args:` array can pass an empty-string default
/// for "not provided" (see `bc-cli/src/lib.rs`'s `non_empty`/
/// `parse_stop_after`); a real subprocess test is what would have caught
/// last time's clap regression on exactly this class of change (a custom
/// `value_parser` panicking at runtime on real `argv`, not just in-process
/// fakes).
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

    let output = Command::new(env!("CARGO_BIN_EXE_bc-sast"))
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
    let output = Command::new(env!("CARGO_BIN_EXE_bc-sast"))
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
    let output = Command::new(env!("CARGO_BIN_EXE_bc-sast"))
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

/// `--setup` (task #154) through the REAL compiled binary: a blocking
/// check exits non-zero, same as `--doctor`, but with no live probe (and
/// so no probe line at all) — this is the one assertion a real-binary
/// test needs to add over the in-process `main_impl` unit test above,
/// since `main.rs`'s own `summary.setup` exit-code branch is only
/// reachable through the compiled binary (see the dual-compilation
/// rationale on the other real-binary tests in this file).
#[test]
fn setup_with_a_blocking_check_exits_non_zero_through_the_real_binary() {
    let dir = setup_repo();
    let bad_pem = dir.path().join("bad.pem");
    std::fs::write(&bad_pem, "not a pem file").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_bc-sast"))
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

/// The automatic pre-scan preflight gate (task #147) blocks a real scan —
/// no `--doctor`, no `--skip-preflight` — before the gateway is ever hit
/// for the scan itself: a malformed `--ca-cert` fails `build_llm_client`,
/// which `environment::run_checks` reports as a blocking `gateway client`
/// check, and `preflight::run` turns that into a non-zero exit with a
/// pointer to `--skip-preflight`.
#[test]
fn preflight_blocks_a_scan_with_a_malformed_ca_cert_through_the_real_binary() {
    let dir = setup_repo();
    let bad_pem = dir.path().join("bad.pem");
    std::fs::write(&bad_pem, "not a pem file").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_bc-sast"))
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

/// The same gate lets a real scan through end-to-end when every check and
/// the live probe succeed — proving `preflight::run` reuses the client it
/// probed with rather than the real scan silently re-building a second
/// one (which would double the mocked gateway's expected call count).
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
    // The preflight probe: any other POST to /chat/completions (its
    // request has no `system` field at all, so it can't match the
    // `body_string_contains` matcher above).
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(openai_reply("pong")))
        .mount(&server)
        .await;

    let dir = setup_repo();
    let state_dir = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_bc-sast"))
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

/// The four report paths, all inside `dir`: what `resolve_output_paths`
/// itself builds for a scan whose `--out-dir` is left at its default,
/// spelled out here so a test can assert on one path directly.
fn out_paths(dir: &std::path::Path) -> bc_cli::OutputPaths {
    bc_cli::OutputPaths {
        provider_writeback_plan: None,
        markdown: dir.join("report.md"),
        sarif: dir.join("report.sarif"),
        csv: dir.join("report.csv"),
        findings_json: dir.join("findings.json"),
    }
}

fn cli(repo: &std::path::Path, gateway_base_url: &str) -> bc_cli::Cli {
    bc_cli::Cli {
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
        gateway_base_url: gateway_base_url.to_string(),
        gateway_api_key: None,
        ca_cert: None,
        dialect: bc_cli::Dialect::Openai,
        pricing_provider: None,
        stop_after: String::new(),
        cve_file: None,
        controls_file: None,
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
        target_tests: None,
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
        remediation_delivery: bc_cli::delivery::DeliveryMode::Patch,
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
        doctor: false,
        stream_large_responses: false,
        skip_preflight: true,
        setup: false,
        auto_step1: false,
        no_auto_step1: false,
    }
}

// A subprocess-invoked binary's own `main.rs` code is reliably attributed
// back to its coverage profile (see the two tests above), but calls made
// FROM that subprocess INTO the `bc_cli` library are not (a
// `cargo-llvm-cov` limitation around a package's dual test-mode/normal-
// mode library compilation: integration test files like this one link
// the same "normal" compiled `bc_cli` rlib the `bc-sast` binary itself
// does, which is a DIFFERENT compiled artifact than the one `src/lib.rs`'s
// own `#[cfg(test)]` unit tests exercise). Calling every public helper
// directly, in-process, from here closes that gap without relying on
// subprocess attribution at all.
#[test]
fn public_helpers_work_when_linked_as_a_normal_dependency() {
    let dir = setup_repo();
    let c = cli(dir.path(), "http://127.0.0.1:0");

    assert!(bc_cli::build_llm_client(&c).is_ok());

    let _config = bc_cli::build_scan_config(&c).unwrap();
    let input = bc_cli::build_scan_input(&c);
    assert_eq!(input.repo_root, dir.path());

    let paths = bc_cli::resolve_output_paths(&c);
    assert_eq!(paths.markdown, dir.path().join("security-scan/report.md"));
    assert_eq!(
        paths.findings_json,
        dir.path().join("security-scan/findings.json")
    );
    let outcome = bc_orchestrator::ScanOutcome {
        provider_writeback_plan: None,
        stopped_after: None,
        report: None,
        markdown: Some("# report".to_string()),
        sarif: Some("{}".to_string()),
    };
    bc_cli::write_outputs(&outcome, &paths.markdown, &paths.sarif, &paths.csv).unwrap();
    assert!(paths.markdown.is_file());
    assert!(paths.sarif.is_file());
}

#[test]
fn build_scan_input_falls_back_to_repo_when_the_path_has_no_file_name() {
    let input = bc_cli::build_scan_input(&cli(std::path::Path::new("/"), "http://127.0.0.1:0"));
    assert_eq!(input.repo_name, "repo");
}

#[test]
fn build_llm_client_rejects_a_malformed_ca_cert() {
    let dir = setup_repo();
    let bad_pem = dir.path().join("bad.pem");
    std::fs::write(&bad_pem, "not a pem file").unwrap();
    let mut c = cli(dir.path(), "http://127.0.0.1:0");
    c.ca_cert = Some(bad_pem);
    assert!(bc_cli::build_llm_client(&c).is_err());
}

// Fakes for `run()` (mirroring `src/lib.rs`'s own test fixtures) so this
// crate's "normal"-mode compiled `run` is exercised directly too — not
// just via the subprocess tests above, whose contribution to library-code
// coverage isn't reliably attributed (see the comment on
// `public_helpers_work_when_linked_as_a_normal_dependency`).
struct FakeClient;

#[async_trait::async_trait]
impl bc_llm_client::LlmClient for FakeClient {
    async fn chat(
        &self,
        request: &bc_llm_client::ChatRequest,
    ) -> Result<bc_llm_client::ChatResponse, bc_llm_client::LlmError> {
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
        Ok(bc_llm_client::ChatResponse {
            content: vec![bc_llm_client::ContentBlock::Text(text.to_string())],
            stop_reason: bc_llm_client::StopReason::EndTurn,
            usage: bc_llm_client::Usage::default(),
        })
    }
}

struct FakeTools;
impl bc_llm_client::ToolExecutor for FakeTools {
    fn available_tools(&self) -> Vec<bc_llm_client::ToolSpec> {
        ["Read", "Glob", "Grep"]
            .iter()
            .map(|name| bc_llm_client::ToolSpec {
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

fn fast_config() -> bc_orchestrator::ScanConfig {
    let mut step1 = bc_stage_s1::Step1Config::new("m");
    step1.retry_backoff_base = std::time::Duration::ZERO;
    let mut step7 = bc_stage_s7::Step7Config::new("m");
    step7.semantic = false;
    bc_orchestrator::ScanConfig {
        step0_enabled: false,
        step0: bc_stage_s0::Step0Config::new(),
        step1,
        step2_enabled: true,
        step2: bc_stage_s2::Step2Config::new("m"),
        step3: bc_stage_s3::Step3Config::new("m"),
        step4: bc_stage_s4::Step4Config::new("m"),
        step5: bc_stage_s5::Step5Config::new("m"),
        step6: bc_stage_s6::Step6Config::new("m"),
        step7,
        step8: bc_stage_s8::Step8Config::new("m"),
        tool_version: "test".to_string(),
        spend_cap: None,
        checkpoint: None,
        resume: false,
        emit_unreachable_appendix: false,
        progress: None,
        pricing: bc_orchestrator::pricing::PricingConfig::default(),
    }
}

#[tokio::test]
async fn run_completes_a_full_scan_with_fakes_linked_as_a_normal_dependency() {
    let dir = setup_repo();
    let input = bc_cli::build_scan_input(&cli(dir.path(), "unused"));
    let summary = bc_cli::run(
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
    use std::os::unix::fs::PermissionsExt;
    let dir = setup_repo();
    let unwritable = dir.path().join("locked");
    std::fs::create_dir(&unwritable).unwrap();
    std::fs::set_permissions(&unwritable, std::fs::Permissions::from_mode(0o000)).unwrap();

    let input = bc_cli::build_scan_input(&cli(dir.path(), "unused"));
    let result = bc_cli::run(
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

    std::fs::set_permissions(&unwritable, std::fs::Permissions::from_mode(0o755)).unwrap();
    let err = result.unwrap_err();
    assert!(err.contains("cannot create output directory"), "{err}");
}

// A finding-producing fake so `sync_github`'s `.map()`/`.map_err()` closures
// (over a non-empty `findings` slice and a real `sync_findings` call) are
// also exercised through the "normal"-mode compiled `bc_cli` instance, not
// just `src/lib.rs`'s own `#[cfg(test)]` unit tests (see the coverage-gap
// comment on `public_helpers_work_when_linked_as_a_normal_dependency`).
struct FakeClientWithFinding;

#[async_trait::async_trait]
impl bc_llm_client::LlmClient for FakeClientWithFinding {
    async fn chat(
        &self,
        request: &bc_llm_client::ChatRequest,
    ) -> Result<bc_llm_client::ChatResponse, bc_llm_client::LlmError> {
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
        Ok(bc_llm_client::ChatResponse {
            content: vec![bc_llm_client::ContentBlock::Text(text)],
            stop_reason: bc_llm_client::StopReason::EndTurn,
            usage: bc_llm_client::Usage::default(),
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

/// Like `finding_repo`, but a real git repo with one commit — needed so
/// `FinalReport.git_sha` resolves to `Some(_)`, the precondition
/// `sync_github` checks before attempting anything.
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

/// A real, committed git repo whose directory name ends in `.git` — the
/// one shape `clone::is_remote` treats as "clone this" (see that
/// function's own doc comment) even though `git clone` itself accepts a
/// plain local filesystem path as its source, no network involved. Lets
/// batch mode's remote-clone path (task #150) be exercised
/// deterministically and offline in tests, both in-process (linked as a
/// normal dependency) and through the real compiled binary.
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

/// Batch mode's remote-clone path (task #150), in-process (linked as a
/// normal dependency, not the subprocess-spawning style below) —
/// exercises `clone::acquire_repo`'s real `git clone` branch AND its
/// post-scan `purge_clone` cleanup (`--keep-clones` is NOT passed) from
/// THIS compiled test binary's own copy of `bc-cli`, distinct from the
/// lib crate's own unit-test binary and the real `bc-sast` binary — see
/// `public_helpers_work_when_linked_as_a_normal_dependency`'s own doc
/// comment for why that distinction matters for coverage attribution.
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

    let summary = bc_cli::main_impl(c).await.unwrap();
    let batch = summary.batch.unwrap();
    assert_eq!(batch.completed, 1);
    assert_eq!(batch.failed, 0);
    // `--keep-clones` was not passed: the cloned source is purged after
    // the scan, proving `purge_clone` actually ran.
    assert!(!workspace_dir.path().join("repo-a").join("app.py").exists());
}

/// The acquire-failure branch of `run_batch`'s per-entry loop (task
/// #150): a manifest entry that LOOKS remote (`.git` suffix) but whose
/// source doesn't exist is recorded as a failed entry — the batch itself
/// still completes rather than aborting. No LLM interaction is reached
/// (the entry never gets past `acquire_repo`), so this needs no mock
/// gateway.
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

    let summary = bc_cli::main_impl(c).await.unwrap();
    let batch = summary.batch.unwrap();
    assert_eq!(batch.completed, 0);
    assert_eq!(batch.failed, 1);
}

#[tokio::test]
async fn run_completes_a_full_scan_with_one_finding_and_syncs_it_to_github_when_linked_as_a_normal_dependency(
) {
    let dir = git_repo();
    let input = bc_cli::build_scan_input(&cli(dir.path(), "unused"));

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
    // The diff fetched above is empty, so the one finding here isn't
    // diff-touched and falls back to a plain issue comment.
    Mock::given(method("POST"))
        .and(path("/repos/acme/widgets/issues/1/comments"))
        .respond_with(ResponseTemplate::new(201))
        .mount(&github_server)
        .await;

    let mut gh_config = bc_github::GithubConfig::new("acme", "widgets", 1, "tok");
    gh_config.api_base_url = github_server.uri();
    let github_client = bc_github::GithubClient::new(reqwest::Client::new(), gh_config);

    let paths = out_paths(dir.path());
    let (md, sarif) = (paths.markdown.clone(), paths.sarif.clone());
    let summary = bc_cli::run(
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
        Some(Ok(bc_github::SyncSummary {
            created: 1,
            updated: 0
        }))
    );

    // Golden-file assertions on the ACTUAL rendered report content, not
    // just the finding count — this is what would catch a rendering
    // regression (a prompt-drift-class bug, or a broken template) that a
    // count-only assertion can't: `FakeClientWithFinding`'s S4 response
    // (`app.py:2-3`, "SQL injection", `vuln_class: "injection"`) and S6's
    // fixed CVSS vector are known, fixed inputs, so their rendered shape
    // is too — including the final displayed severity, which is
    // CVSS-score-derived (CRITICAL here) rather than S7's raw "high"
    // ranking input, and the CWE-74 auto-assigned from `vuln_class`.
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
    let input = bc_cli::build_scan_input(&cli(dir.path(), "unused"));

    let github_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/widgets/pulls/1"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&github_server)
        .await;

    let mut gh_config = bc_github::GithubConfig::new("acme", "widgets", 1, "tok");
    gh_config.api_base_url = github_server.uri();
    let github_client = bc_github::GithubClient::new(reqwest::Client::new(), gh_config);

    let summary = bc_cli::run(
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
    assert!(bc_cli::build_github_client(&c).is_err());
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

    let mut gh_config = bc_github::GithubConfig::new("acme", "widgets", 1, "tok");
    gh_config.api_base_url = server.uri();
    let github_client = bc_github::GithubClient::new(reqwest::Client::new(), gh_config);

    let summary = bc_cli::post_comments_only(&github_client, &path, None)
        .await
        .unwrap();
    assert_eq!(summary.findings, 1);
    assert_eq!(
        summary.github_sync,
        Some(Ok(bc_github::SyncSummary {
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

    let mut gh_config = bc_github::GithubConfig::new("acme", "widgets", 1, "tok");
    gh_config.api_base_url = server.uri();
    let github_client = bc_github::GithubClient::new(reqwest::Client::new(), gh_config);

    let summary = bc_cli::post_fixes_only(&github_client, &path)
        .await
        .unwrap();
    assert_eq!(summary.findings, 1);
    assert_eq!(
        summary.github_sync,
        Some(Ok(bc_github::SyncSummary {
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
    // No `--github-token`/`--github-repo`/`--pr-number` set — proves
    // `main_impl` catches this before ever calling `build_llm_client`.
    let result = bc_cli::main_impl(c).await;
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
    let result = bc_cli::main_impl(c).await;
    assert!(result.unwrap_err().contains("--post-fixes-from requires"));
}

// The tests below close coverage gaps specific to THIS file's "linked as
// a normal dependency" compiled instance of `bc_cli` (see the comment on
// `public_helpers_work_when_linked_as_a_normal_dependency`): each targets
// a function/closure that `src/lib.rs`'s own `#[cfg(test)]` unit tests
// already exercise in THEIR compiled instance, but that this crate's
// separately-compiled normal-dependency instance never reaches on its
// own.

#[test]
fn build_scan_config_propagates_a_malformed_config_file_when_linked_as_a_normal_dependency() {
    let repo_dir = tempfile::tempdir().unwrap();
    let config_dir = tempfile::tempdir().unwrap();
    let config_path = config_dir.path().join("config.yaml");
    std::fs::write(&config_path, "not: [a, valid\n").unwrap();
    let mut c = cli(repo_dir.path(), "unused");
    c.config = Some(config_path);
    assert!(bc_cli::build_scan_config(&c).is_err());
}

// `getenv` is only actually CALLED once a config file parses successfully
// (`bc_config::load` returns early on a parse error, before ever
// touching `getenv` — see the malformed-config test above, which does
// NOT exercise it) — `check_config_trust`'s own unconditional
// `is_set_and_nonempty(getenv, "BC_ALLOW_CWD_CONFIG")` check is
// the reliable way to reach it regardless of the file's own content. A
// config resolving *inside* the scan target hits exactly that check on
// its way to refusing the config, mirroring `src/lib.rs`'s own
// `build_scan_config_rejects_a_config_resolved_inside_the_scan_target`.
#[test]
fn build_scan_config_rejects_a_config_resolved_inside_the_scan_target_when_linked_as_a_normal_dependency(
) {
    let repo_dir = tempfile::tempdir().unwrap();
    let config_path = repo_dir.path().join("config.yaml");
    std::fs::write(&config_path, "step1:\n  max_turns: 5\n").unwrap();
    let mut c = cli(repo_dir.path(), "unused");
    c.config = Some(config_path);
    assert!(bc_cli::build_scan_config(&c).is_err());
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
    let settings = bc_cli::build_remediate_settings(&c).unwrap();
    assert!(settings.policy.is_some());
}

#[tokio::test]
async fn post_comments_only_propagates_malformed_json_when_linked_as_a_normal_dependency() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("findings.json");
    std::fs::write(&path, "not valid json").unwrap();

    let gh_config = bc_github::GithubConfig::new("acme", "widgets", 1, "tok");
    let github_client = bc_github::GithubClient::new(reqwest::Client::new(), gh_config);

    let result = bc_cli::post_comments_only(&github_client, &path, None).await;
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

    let mut gh_config = bc_github::GithubConfig::new("acme", "widgets", 1, "tok");
    gh_config.api_base_url = server.uri();
    let github_client = bc_github::GithubClient::new(reqwest::Client::new(), gh_config);

    let summary = bc_cli::post_comments_only(&github_client, &findings_path, None)
        .await
        .unwrap();
    assert!(matches!(summary.github_sync, Some(Err(_))));
}

fn sample_report(git_sha: Option<&str>, findings: Vec<bc_model::Finding>) -> bc_model::FinalReport {
    bc_model::FinalReport {
        provider_ledger: Default::default(),
        repo_root: "/r".to_string(),
        repo_name: None,
        git_sha: git_sha.map(str::to_string),
        findings: findings
            .into_iter()
            .map(|finding| bc_model::RankedFinding {
                finding,
                severity: bc_model::Severity::High,
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

fn sample_finding() -> bc_model::Finding {
    bc_model::Finding {
        provider_origins: Vec::new(),
        chunk_id: "c1".to_string(),
        file: "app.py".to_string(),
        line_start: 1,
        line_end: 1,
        vuln_class: bc_model::VulnClass::Injection,
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

fn fast_remediate_config() -> bc_stage_s10::Step10Config {
    let mut step10 = bc_stage_s10::Step10Config::new("m");
    step10.max_transient_retries = 0;
    step10.retry_backoff_base = std::time::Duration::ZERO;
    step10
}

fn fast_step11_config() -> bc_stage_s11::Step11Config {
    let mut step11 = bc_stage_s11::Step11Config::new("m");
    step11.max_transient_retries = 0;
    step11.retry_backoff_base = std::time::Duration::ZERO;
    step11
}

struct S10OnlyClient;

#[async_trait::async_trait]
impl bc_llm_client::LlmClient for S10OnlyClient {
    async fn chat(
        &self,
        request: &bc_llm_client::ChatRequest,
    ) -> Result<bc_llm_client::ChatResponse, bc_llm_client::LlmError> {
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
        Ok(bc_llm_client::ChatResponse {
            content: vec![bc_llm_client::ContentBlock::Text(text)],
            stop_reason: bc_llm_client::StopReason::EndTurn,
            usage: bc_llm_client::Usage::default(),
        })
    }
}

/// `bc_cli::remediate_interactively` is only ever reached, from `run()`,
/// through a hardcoded real `bc_interactive::RealTerminal` — not safe to
/// drive from a test (a real terminal blocks on actual keyboard input if
/// this test process's stdin/stderr happen to be a real tty). Calling the
/// function directly instead — it's `pub` specifically so it's testable
/// against a scripted fake — reaches the same "linked as a normal
/// dependency" compiled instance without ever touching a real terminal.
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

impl bc_interactive::BlockingInput for FakeTerminal {
    fn read_key(&mut self) -> std::io::Result<bc_interactive::Key> {
        unreachable!("FakeTerminal::prompt never enters the tty loop")
    }
    fn read_line(&mut self, _prompt: &str) -> Option<String> {
        self.lines.pop_front().flatten()
    }
}

impl bc_interactive::Terminal for FakeTerminal {
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
    let tools: std::sync::Arc<dyn bc_llm_client::ToolExecutor> =
        std::sync::Arc::new(bc_sandbox_tools::SandboxTools::new_with_write(dir.path()));
    // An explicit `top` (rather than `None`) so `select_top_by_cvss`
    // actually takes its CVSS-ranking path — `top: None` early-returns
    // every finding in report order without ever calling the
    // `cvss_score`/`severity_str` closures, leaving THIS compiled
    // instance's copies unexecuted even though a finding is remediated
    // (see the coverage-gap comment on
    // `public_helpers_work_when_linked_as_a_normal_dependency`).
    let config = bc_orchestrator::RemediateConfig {
        step10: fast_remediate_config(),
        top: Some(bc_stage_s10::TopSpec::N(1)),
        top_default: None,
        force: false,
        resume: false,
        isolated: false,
    };
    let mut term = FakeTerminal::prompt(vec![Some("all".to_string()), None]);

    let result = bc_cli::remediate_interactively(
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
    let input = bc_cli::build_scan_input(&cli(dir.path(), "unused"));
    let out_json = dir.path().join("remediation.json");
    let remediate = bc_cli::RemediateRun {
        delivery: None,
        settings: bc_cli::RemediateSettings {
            target_tests: None,
            config: bc_orchestrator::RemediateConfig {
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
        tools: std::sync::Arc::new(bc_sandbox_tools::SandboxTools::new_with_write(dir.path())),
        out_json: Some(out_json.clone()),
        checkpoint: None,
        worktree: None,
    };

    let summary = bc_cli::run(
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

/// `--cve-file` end-to-end: the loaded feed has to reach an actual PROMPT
/// BODY, not just `ScanInput`. Both consuming prompt sections were ported
/// long before anything filled `known_cves`, so a test that only checked
/// the struct would have passed happily while the plane stayed dead.
///
/// The S2 mock MATCHES ON the CVE id, so the mock only answers if the
/// injected feed actually reached the threat-model call — a scan that
/// dropped the feed gets no matching mock, S2 fails, and the assertion on
/// a successful `--stop-after s2` run fails with it.
#[tokio::test]
async fn a_cve_file_reaches_the_threat_model_prompt_through_the_real_binary() {
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
        // The exact line `prompts.rs`'s `cve_block` renders for an
        // unpatched CVE with no CVSS score.
        .and(body_string_contains(
            "CVE-2021-44228 (CVSS None, UNPATCHED): Log4Shell",
        ))
        .and(body_string_contains("RBAC on every route"))
        .respond_with(ResponseTemplate::new(200).set_body_json(openai_reply(
            r#"{"system_context":"ctx","assets":[],"trust_boundaries":[],"threats":[],"open_questions":[]}"#,
        )))
        // Load-bearing: S2 DEGRADES rather than failing when its call
        // errors, so a scan that dropped the feed would still exit 0 and
        // still print "Scan stopped after S2". The expectation is what
        // makes this test fail in that case — `MockServer` verifies it on
        // drop.
        .expect(1)
        .mount(&server)
        .await;

    let dir = setup_repo();
    let feed_dir = tempfile::tempdir().unwrap();
    let cve_path = feed_dir.path().join("known_cves.json");
    std::fs::write(
        &cve_path,
        r#"{"cves": [{"id": "CVE-2021-44228", "summary": "Log4Shell"}]}"#,
    )
    .unwrap();
    let controls_path = feed_dir.path().join("design_controls.yaml");
    std::fs::write(
        &controls_path,
        "controls:\n  - name: authz-gateway\n    kind: authz\n    notes: RBAC on every route\n",
    )
    .unwrap();
    let state_dir = tempfile::tempdir().unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_bc-sast"))
        .arg("--repo")
        .arg(dir.path())
        .arg("--gateway-base-url")
        .arg(server.uri())
        .arg("--model")
        .arg("test-model")
        .arg("--cve-file")
        .arg(&cve_path)
        .arg("--controls-file")
        .arg(&controls_path)
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

/// `--baseline` through the REAL binary: the flag, the loader's format
/// sniffing, the SARIF annotation and the summary line all in one pass.
///
/// The baseline is a hand-written findings export naming a finding this
/// scan does not produce, so the run has exactly one `new` and one
/// `resolved` — a comparison where every count is non-trivial.
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

    let output = Command::new(env!("CARGO_BIN_EXE_bc-sast"))
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
    // The resolved finding is re-emitted as a real `absent` SARIF result
    // even though the baseline was a findings JSON, so Code Scanning
    // closes the alert instead of leaving it open forever. Its `level`
    // and `rank` come from the export's own CVSS data.
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

/// `--stream-large-responses` through the REAL binary, and the threshold
/// applied selectively in one run: S1 asks for 16,000 output tokens and
/// must NOT stream (its mock returns an ordinary JSON body, which a
/// streaming client would read as an empty SSE stream), while S2 asks for
/// 64,000 and must — its mock demands `"stream": true` in the body and
/// answers with a real `text/event-stream`.
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
        // Load-bearing: S2 DEGRADES rather than failing when its call
        // errors, so without this expectation a run that never streamed
        // (and therefore never matched this mock) would still exit 0.
        .expect(1)
        .mount(&server)
        .await;

    let dir = setup_repo();
    let state_dir = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_bc-sast"))
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

/// Mounts the whole S1-S8 mock chain for a scan that finds exactly one
/// true-positive SQL injection in `finding_repo`'s `app.py`, plus a canned
/// S10 `Fixed` claim without any editing tool calls. Remediation must
/// downgrade that unsupported claim to `Needs Review` in its record.
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

/// `--remediate-from` augments the PRIOR run's reports in place, through
/// the REAL binary and two real invocations: scan-and-export first, then
/// remediate-from against that export. Proves the whole chain — the
/// default `security-scan/` paths being found, the Markdown sections and
/// the SARIF `remediationStatus` landing on the earlier run's own
/// documents, and stdout saying what was touched.
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

    let scan = Command::new(env!("CARGO_BIN_EXE_bc-sast"))
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

    let remediate = Command::new(env!("CARGO_BIN_EXE_bc-sast"))
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
    // The mock narrates a fix but never edits source. Reports must carry
    // S10's reconciled verdict and explain why its claim was rejected.
    assert!(after.contains("Needs Review"), "{after}");
    assert!(
        after.contains("no corresponding on-disk change was found"),
        "{after}"
    );
    assert_eq!(
        std::fs::read(dir.path().join("app.py")).unwrap(),
        source_before
    );
    // The scan's own content survives — this augments, never replaces.
    assert!(after.contains("SQL injection"), "{after}");
    let sarif: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&sarif_path).unwrap()).unwrap();
    assert_eq!(
        sarif["runs"][0]["results"][0]["properties"]["remediationStatus"],
        "Needs Review"
    );
}

/// With no prior report where a scan would have left one,
/// `--remediate-from` says so on stdout instead of silently doing
/// nothing — and creates nothing.
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

    let output = Command::new(env!("CARGO_BIN_EXE_bc-sast"))
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

/// The manifest's OWN per-entry baseline through the REAL binary: the
/// optional 4th `.txt` field is parsed, resolved relative to the
/// manifest's directory, loaded, applied to that entry's scan, and its
/// counts land in `batch_summary.md`'s new columns.
///
/// The same "private functions, separate compilation unit" reason the
/// plain batch test above exists applies here: the manifest parser is
/// only reachable from the binary through a real `--repo-file` argv.
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
    // Deliberately named by a BARE relative filename in the manifest, to
    // prove it resolves against the manifest's directory rather than the
    // test process's working directory.
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

    let output = Command::new(env!("CARGO_BIN_EXE_bc-sast"))
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
    // 0 new / 0 unchanged (this scan finds nothing) and 1 resolved (the
    // baseline's own finding is gone) — every column non-trivially placed.
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

/// A top-level `--baseline` cannot mean anything across several repos —
/// it is refused rather than silently comparing every entry against one
/// repository's history.
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

    let output = Command::new(env!("CARGO_BIN_EXE_bc-sast"))
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

/// An unreadable `--baseline` must fail the run BEFORE any scanning
/// happens — comparing against nothing would report every pre-existing
/// finding as newly introduced.
#[tokio::test]
async fn a_missing_baseline_exits_non_zero_through_the_real_binary() {
    let dir = setup_repo();
    let state_dir = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_bc-sast"))
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
