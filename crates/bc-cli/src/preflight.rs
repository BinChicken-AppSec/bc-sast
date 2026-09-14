//! Automatic pre-scan readiness gate (task #117/#147) — mirrors Python's
//! `orchestrator/preflight.py::check_backends`/`probe_backends`, which
//! `entry.py` runs before every real scan unless `--skip-preflight` is
//! passed. Reuses [`crate::environment`]'s check engine (the same one
//! `--doctor` drives) rather than a second implementation, so a scan and
//! `--doctor` agree on what "ready" means.
//!
//! Scoped to the single, non-batch scan path — batch mode (`--repo-file`,
//! tasks #148-151) builds its own per-entry client and is not yet wired
//! through this gate.

use std::sync::Arc;

use bc_llm_client::LlmClient;

use crate::{environment, Cli};

/// Runs the static checks, then (only if none are blocking) one live
/// probe through the already-built client — matching Python's own
/// "skip the network probe if credentials/config are already known-bad"
/// short-circuit. Returns `Err` with the rendered checks and a pointer to
/// `--skip-preflight` on either kind of failure; `main_impl` propagates
/// that `Err` exactly like any other pre-scan setup failure (a plain
/// non-zero exit, matching Python's `check_backends() -> return 1`).
pub async fn run(
    cli: &Cli,
    client_result: &Result<Arc<dyn LlmClient>, String>,
) -> Result<(), String> {
    let checks = environment::run_checks(cli, client_result);
    let blocking = environment::n_blocking(&checks);
    if blocking > 0 {
        return Err(format!(
            "preflight failed:\n{}\n\nfix the above, or pass --skip-preflight to bypass.",
            environment::render(&checks)
        ));
    }
    let client = client_result
        .as_ref()
        .expect("blocking == 0 implies the gateway-client check already found this Ok");
    let probe = environment::probe_gateway(client.as_ref(), &cli.model).await;
    if probe.status == environment::CheckStatus::Fail {
        return Err(format!(
            "preflight failed:\n{}\n  {}\n\nfix the above, or pass --skip-preflight to bypass.",
            environment::render(&checks),
            probe.detail
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_llm_client::{ChatRequest, ChatResponse, ContentBlock, LlmError, StopReason, Usage};
    use std::path::Path;

    fn cli(dir: &Path) -> Cli {
        crate::test_support::minimal_cli(dir)
    }

    /// Persistently rate limited: the probe warns, preflight still passes.
    struct ThrottledClient;
    #[async_trait::async_trait]
    impl LlmClient for ThrottledClient {
        async fn chat(&self, _request: &ChatRequest) -> Result<ChatResponse, LlmError> {
            Err(LlmError::RateLimited {
                retry_after_secs: None,
            })
        }
    }

    #[tokio::test]
    async fn a_rate_limited_probe_does_not_fail_preflight() {
        let dir = tempfile::tempdir().unwrap();
        let client: Arc<dyn LlmClient> = Arc::new(ThrottledClient);
        assert!(run(&cli(dir.path()), &Ok(client)).await.is_ok());
    }

    struct FakeClient;
    #[async_trait::async_trait]
    impl LlmClient for FakeClient {
        async fn chat(&self, _request: &ChatRequest) -> Result<ChatResponse, LlmError> {
            Ok(ChatResponse {
                content: vec![ContentBlock::text("pong")],
                stop_reason: StopReason::EndTurn,
                usage: Usage::default(),
            })
        }
    }

    struct FailingClient;
    #[async_trait::async_trait]
    impl LlmClient for FailingClient {
        async fn chat(&self, _request: &ChatRequest) -> Result<ChatResponse, LlmError> {
            Err(LlmError::ConnectionError {
                message: "connection refused".to_string(),
            })
        }
    }

    #[tokio::test]
    async fn run_passes_when_checks_are_clean_and_the_probe_answers() {
        let dir = tempfile::tempdir().unwrap();
        let c = cli(dir.path());
        let client_result: Result<Arc<dyn LlmClient>, String> = Ok(Arc::new(FakeClient));
        assert!(run(&c, &client_result).await.is_ok());
    }

    #[tokio::test]
    async fn run_fails_without_probing_when_a_check_already_blocks() {
        let dir = tempfile::tempdir().unwrap();
        let c = cli(dir.path());
        let client_result: Result<Arc<dyn LlmClient>, String> =
            Err("boom: malformed ca cert".to_string());
        let err = run(&c, &client_result).await.unwrap_err();
        assert!(err.contains("boom: malformed ca cert"));
        assert!(err.contains("--skip-preflight"));
    }

    #[tokio::test]
    async fn run_fails_when_checks_pass_but_the_live_probe_is_unreachable() {
        let dir = tempfile::tempdir().unwrap();
        let c = cli(dir.path());
        let client_result: Result<Arc<dyn LlmClient>, String> = Ok(Arc::new(FailingClient));
        let err = run(&c, &client_result).await.unwrap_err();
        assert!(err.contains("connection refused"));
        assert!(err.contains("--skip-preflight"));
    }
}
