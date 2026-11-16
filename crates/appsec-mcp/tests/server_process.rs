use appsec_mcp::SearchQuery;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

fn working_env() -> Vec<(&'static str, &'static str)> {
    vec![
        ("BC_CONFLUENCE_BASE_URL", "https://example.atlassian.net"),
        ("BC_CONFLUENCE_EMAIL", "svc@example.com"),
        ("BC_CONFLUENCE_TOKEN", "test-token-never-sent-anywhere"),
        ("BC_CONFLUENCE_SPACES", "ENG"),
    ]
}

fn server(env: &[(&str, &str)]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_appsec-mcp"));
    cmd.env_clear();
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

#[test]
fn the_process_answers_a_request_on_stdout_and_exits_zero_at_eof() {
    let mut child = server(&working_env()).spawn().expect("the server starts");
    let mut stdin = child.stdin.take().expect("stdin");
    writeln!(stdin, r#"{{"jsonrpc":"2.0","id":1,"method":"tools/list"}}"#).expect("write");
    drop(stdin);

    let stdout = child.stdout.take().expect("stdout");
    let first = BufReader::new(stdout)
        .lines()
        .next()
        .expect("a response line")
        .expect("readable");
    let response: serde_json::Value = serde_json::from_str(&first).expect("valid JSON");

    assert_eq!(response["id"], 1);
    let tools = response["result"]["tools"]
        .as_array()
        .expect("a tools array");
    let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
    assert_eq!(names, ["context_search", "context_fetch"]);

    let status = child.wait().expect("the server exits");
    assert!(status.success(), "exited with {status}");
}

#[test]
fn a_misconfigured_process_fails_loudly_without_echoing_the_token() {
    let secret = "test-token-never-sent-anywhere";
    let env: Vec<(&str, &str)> = working_env()
        .into_iter()
        .filter(|(k, _)| *k != "BC_CONFLUENCE_SPACES")
        .collect();

    let out = server(&env)
        .spawn()
        .expect("spawns")
        .wait_with_output()
        .expect("runs");

    assert!(
        !out.status.success(),
        "a misconfigured server must not exit 0"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("BC_CONFLUENCE_SPACES"), "{stderr}");
    assert!(stderr.contains("appsec-mcp:"), "{stderr}");
    assert!(
        !stderr.contains(secret),
        "the token reached stderr: {stderr}"
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).is_empty(),
        "nothing should be served"
    );
}

#[test]
fn a_malformed_frame_is_answered_and_the_process_keeps_serving() {
    let mut child = server(&working_env()).spawn().expect("the server starts");
    let mut stdin = child.stdin.take().expect("stdin");
    writeln!(stdin, "{{not json").expect("write");
    writeln!(stdin, r#"{{"jsonrpc":"2.0","id":2,"method":"initialize"}}"#).expect("write");
    drop(stdin);

    let stdout = child.stdout.take().expect("stdout");
    let lines: Vec<String> = BufReader::new(stdout)
        .lines()
        .map(|l| l.expect("readable"))
        .collect();
    assert_eq!(lines.len(), 2, "{lines:?}");

    let parse_error: serde_json::Value = serde_json::from_str(&lines[0]).expect("valid JSON");
    assert_eq!(parse_error["error"]["code"], -32700);
    let second: serde_json::Value = serde_json::from_str(&lines[1]).expect("valid JSON");
    assert_eq!(second["id"], 2);

    assert!(child.wait().expect("exits").success());
}

#[test]
fn the_client_and_the_server_speak_the_same_protocol() {
    let env: Vec<(String, String)> = working_env()
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let mut session = appsec_mcp::client::Session::spawn(
        std::path::Path::new(env!("CARGO_BIN_EXE_appsec-mcp")),
        &env,
    )
    .expect("the server starts");

    assert_eq!(
        session.client.initialize().expect("initialize"),
        "appsec-mcp"
    );
    assert_eq!(
        session.client.tools().expect("tools/list"),
        ["context_search", "context_fetch"]
    );

    let status = session.shutdown().expect("the server exits");
    assert!(status.success(), "exited with {status}");
}

#[test]
fn an_unpermitted_space_is_refused_end_to_end_without_a_network_call() {
    let env: Vec<(String, String)> = working_env()
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let mut session = appsec_mcp::client::Session::spawn(
        std::path::Path::new(env!("CARGO_BIN_EXE_appsec-mcp")),
        &env,
    )
    .expect("the server starts");

    let err = session
        .client
        .search("FINANCE", &SearchQuery::default())
        .expect_err("an unconfigured space must be refused");
    assert!(err.contains("not permitted"), "{err}");
    assert!(
        err.contains("ENG"),
        "the refusal names what is configured: {err}"
    );

    assert_eq!(
        session.client.tools().expect("still serving"),
        ["context_search", "context_fetch"]
    );
    assert!(session.shutdown().expect("exits").success());
}
