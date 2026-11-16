use std::sync::Arc;

use appsec_llm_client::LlmError;
use appsec_llm_client::{ChatRequest, LlmClient, Message};

use crate::{getenv, repo_path, Cli};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckStatus {
    Ok,
    Warn,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub name: String,
    pub status: CheckStatus,
    pub detail: String,
    pub required: bool,
}

impl Check {
    fn ok(name: &str, detail: impl Into<String>) -> Self {
        Check {
            name: name.to_string(),
            status: CheckStatus::Ok,
            detail: detail.into(),
            required: false,
        }
    }

    fn warn(name: &str, detail: impl Into<String>) -> Self {
        Check {
            name: name.to_string(),
            status: CheckStatus::Warn,
            detail: detail.into(),
            required: false,
        }
    }

    fn fail(name: &str, detail: impl Into<String>, required: bool) -> Self {
        Check {
            name: name.to_string(),
            status: CheckStatus::Fail,
            detail: detail.into(),
            required,
        }
    }
}

pub fn run_checks(cli: &Cli, client_result: &Result<Arc<dyn LlmClient>, String>) -> Vec<Check> {
    let mut checks = vec![
        check_gateway_client(cli, client_result),
        check_gateway_api_key(cli),
        check_git(cli.repo.as_deref()),
    ];
    if let Some(check) = check_client_identity(cli, client_result) {
        checks.push(check);
    }
    if cli.config.is_some() {
        checks.push(check_config_loads(cli));
    }
    checks.extend(check_model_lifecycles(
        cli,
        &appsec_llm_client::capabilities::today_utc(),
    ));
    checks
}

fn check_model_lifecycles(cli: &Cli, today: &str) -> Vec<Check> {
    let models =
        crate::model_policy::configured_models(&cli.model, &crate::lenient_config_data(cli));
    let report = crate::model_policy::check(&models, today, cli.allow_unsupported_model);
    if report.refused.is_empty() && report.warnings.is_empty() {
        return vec![Check::ok("models", models.join(", "))];
    }
    report
        .refused
        .into_iter()
        .map(|line| Check::fail("model lifecycle", line, true))
        .chain(
            report
                .warnings
                .into_iter()
                .map(|line| Check::warn("model lifecycle", line)),
        )
        .collect()
}

fn check_client_identity(
    cli: &Cli,
    client_result: &Result<Arc<dyn LlmClient>, String>,
) -> Option<Check> {
    let described = match (&cli.client_cert, &cli.client_key) {
        (None, None) => return None,
        (Some(cert), None) => cert.display().to_string(),
        (Some(cert), Some(key)) => format!("{} (key {})", cert.display(), key.display()),
        (None, Some(key)) => format!("key {} without --client-cert", key.display()),
    };
    Some(match client_result {
        Ok(_) => Check::ok("mTLS client certificate", described),
        Err(_) => Check::fail(
            "mTLS client certificate",
            format!("{described}: not loaded, see the gateway client check"),
            true,
        ),
    })
}

pub fn n_blocking(checks: &[Check]) -> usize {
    checks
        .iter()
        .filter(|c| c.required && c.status == CheckStatus::Fail)
        .count()
}

fn check_gateway_client(cli: &Cli, client_result: &Result<Arc<dyn LlmClient>, String>) -> Check {
    match client_result {
        Ok(_) => Check::ok(
            "gateway client",
            format!("{} ({:?} dialect)", cli.gateway_base_url, cli.dialect),
        ),
        Err(e) => Check::fail("gateway client", e.clone(), true),
    }
}

fn check_gateway_api_key(cli: &Cli) -> Check {
    if cli.gateway_api_key.is_some() {
        Check::ok("gateway API key", "set")
    } else {
        Check::warn(
            "gateway API key",
            "unset — export BC_GATEWAY_API_KEY or pass --gateway-api-key if your gateway \
             requires one",
        )
    }
}

fn check_git(repo: Option<&std::path::Path>) -> Check {
    let found = std::process::Command::new("git")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !found {
        return Check::warn(
            "git",
            "not found on PATH — HEAD sha detection will fail unless --git-sha is passed",
        );
    }
    let Some(repo) = repo else {
        return Check::ok("git", "found on PATH");
    };
    let probe = std::process::Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["rev-parse", "--git-dir"])
        .output();
    let repo = repo.display();
    match probe {
        Ok(out) if out.status.success() => {
            Check::ok("git", format!("found on PATH; {repo} is a usable worktree"))
        }
        Ok(out) if String::from_utf8_lossy(&out.stderr).contains("dubious ownership") => {
            Check::warn(
                "git",
                format!(
                    "found on PATH, but git refuses {repo}: detected dubious ownership \
                     (the repository is owned by another user). Commit-sha detection, \
                     remediation worktree isolation and the S10 git revert backstop all \
                     stay off until that is fixed. Either give the checkout to the uid \
                     running this scan, or mark this one path safe with \
                     GIT_CONFIG_COUNT=1, GIT_CONFIG_KEY_0=safe.directory, \
                     GIT_CONFIG_VALUE_0={repo}"
                ),
            )
        }
        _ => Check::ok(
            "git",
            format!(
                "found on PATH; {repo} is not a git worktree, so --git-sha is the only \
                 source for report.git_sha"
            ),
        ),
    }
}

fn check_config_loads(cli: &Cli) -> Check {
    let path = cli
        .config
        .as_deref()
        .expect("caller only invokes this when cli.config is Some");
    match crate::config_load::load(path)
        .map_err(|e| e.to_string())
        .and_then(|_| {
            appsec_config::check_config_trust(path, repo_path(cli), &getenv)
                .map_err(|e| e.to_string())
        }) {
        Ok(()) => Check::ok("--config", path.display().to_string()),
        Err(e) => Check::fail("--config", e, true),
    }
}

pub async fn probe_gateway(client: &dyn LlmClient, model: &str) -> Check {
    let request = ChatRequest {
        model: model.to_string(),
        system: None,
        messages: vec![Message::user_text("ping")],
        tools: Vec::new(),
        max_tokens: PROBE_MAX_TOKENS,
        temperature: None,
        top_p: None,
        seed: None,
        thinking_budget: None,
        betas: Vec::new(),
        json_mode: false,
        timeout: None,
        stream: false,
        ..ChatRequest::default()
    };
    let mut last_err = None;
    for attempt in 0..PROBE_ATTEMPTS {
        match client.chat(&request).await {
            Ok(_) | Err(LlmError::Truncated { .. }) => {
                return Check::ok("live probe", format!("{model} reachable"))
            }
            Err(e) if e.is_retryable() && attempt + 1 < PROBE_ATTEMPTS => {
                let delay = PROBE_BACKOFF_BASE * 2u32.pow(attempt);
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                last_err = Some(e);
            }
            Err(e) => {
                last_err = Some(e);
                break;
            }
        }
    }
    let e = last_err.expect("the loop ran at least once");
    if matches!(e, LlmError::RateLimited { .. }) {
        Check::warn(
            "live probe",
            format!("{e} — the scan's own retries handle this; continuing"),
        )
    } else {
        Check::fail("live probe", e.to_string(), false)
    }
}

const PROBE_ATTEMPTS: u32 = 3;

const PROBE_MAX_TOKENS: u32 = 256;
const PROBE_BACKOFF_BASE: std::time::Duration = std::time::Duration::from_secs(1);

pub fn render(checks: &[Check]) -> String {
    let mut out = Vec::with_capacity(checks.len() + 1);
    let mut ok = 0;
    let mut warn = 0;
    let mut fail = 0;
    for check in checks {
        let icon = match check.status {
            CheckStatus::Ok => {
                ok += 1;
                '\u{2713}'
            }
            CheckStatus::Warn => {
                warn += 1;
                '\u{26a0}'
            }
            CheckStatus::Fail => {
                fail += 1;
                '\u{2717}'
            }
        };
        out.push(format!("  {icon} {:<30} {}", check.name, check.detail));
    }
    out.push(format!(
        "  {ok} ok · {warn} warning(s) · {fail} blocking issue(s)"
    ));
    out.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn cli(dir: &Path) -> Cli {
        crate::test_support::minimal_cli(dir)
    }

    #[test]
    fn check_ok_warn_fail_set_the_expected_status_and_required_flag() {
        let ok = Check::ok("n", "d");
        assert_eq!(ok.status, CheckStatus::Ok);
        assert!(!ok.required);

        let warn = Check::warn("n", "d");
        assert_eq!(warn.status, CheckStatus::Warn);
        assert!(!warn.required);

        let fail_required = Check::fail("n", "d", true);
        assert_eq!(fail_required.status, CheckStatus::Fail);
        assert!(fail_required.required);

        let fail_optional = Check::fail("n", "d", false);
        assert!(!fail_optional.required);
    }

    #[test]
    fn n_blocking_counts_only_required_failures() {
        let checks = vec![
            Check::ok("a", "d"),
            Check::warn("b", "d"),
            Check::fail("c", "d", false),
            Check::fail("d", "d", true),
            Check::fail("e", "d", true),
        ];
        assert_eq!(n_blocking(&checks), 2);
    }

    #[test]
    fn check_gateway_client_ok_when_the_client_builds() {
        let dir = tempfile::tempdir().unwrap();
        let c = cli(dir.path());
        let result = crate::build_llm_client(&c);
        let check = check_gateway_client(&c, &result);
        assert_eq!(check.status, CheckStatus::Ok);
        assert!(!check.required);
    }

    #[test]
    fn check_gateway_client_fails_on_a_malformed_ca_cert() {
        let dir = tempfile::tempdir().unwrap();
        let bad_pem = dir.path().join("bad.pem");
        std::fs::write(&bad_pem, "not a pem file").unwrap();
        let mut c = cli(dir.path());
        c.ca_cert = Some(bad_pem);
        let result = crate::build_llm_client(&c);
        let check = check_gateway_client(&c, &result);
        assert_eq!(check.status, CheckStatus::Fail);
        assert!(check.required);
    }

    #[test]
    fn check_gateway_api_key_ok_when_set() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = cli(dir.path());
        c.gateway_api_key = Some("k".to_string());
        assert_eq!(check_gateway_api_key(&c).status, CheckStatus::Ok);
    }

    #[test]
    fn check_gateway_api_key_warns_when_unset() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = cli(dir.path());
        c.gateway_api_key = None;
        assert_eq!(check_gateway_api_key(&c).status, CheckStatus::Warn);
    }

    #[test]
    fn check_git_is_ok_on_a_dev_machine_with_git_installed() {
        assert_eq!(check_git(None).status, CheckStatus::Ok);
    }

    #[test]
    fn check_git_names_the_scan_target_when_it_is_a_usable_worktree() {
        let dir = tempfile::tempdir().unwrap();
        let init = std::process::Command::new("git")
            .arg("init")
            .arg(dir.path())
            .output()
            .unwrap();
        assert!(init.status.success(), "git init failed in a temp dir");
        let check = check_git(Some(dir.path()));
        assert_eq!(check.status, CheckStatus::Ok);
        assert!(check.detail.contains("usable worktree"), "{}", check.detail);
    }

    #[test]
    fn check_git_stays_ok_when_the_scan_target_is_not_a_worktree_at_all() {
        let dir = tempfile::tempdir().unwrap();
        let check = check_git(Some(dir.path()));
        assert_eq!(check.status, CheckStatus::Ok);
        assert!(check.detail.contains("--git-sha"), "{}", check.detail);
    }

    #[test]
    fn check_config_loads_ok_for_a_well_formed_config_outside_the_scan_target() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("repo")).unwrap();
        let config_path = dir.path().join("config.yaml");
        std::fs::write(&config_path, "step1:\n  model: m\n").unwrap();
        let mut c = cli(&dir.path().join("repo"));
        c.config = Some(config_path);
        let check = check_config_loads(&c);
        assert_eq!(check.status, CheckStatus::Ok);
    }

    #[test]
    fn check_config_loads_fails_for_malformed_yaml() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("repo")).unwrap();
        let config_path = dir.path().join("config.yaml");
        std::fs::write(&config_path, "not: [a, valid\n").unwrap();
        let mut c = cli(&dir.path().join("repo"));
        c.config = Some(config_path);
        let check = check_config_loads(&c);
        assert_eq!(check.status, CheckStatus::Fail);
        assert!(check.required);
    }

    #[test]
    fn check_config_loads_fails_when_the_config_resolves_inside_the_scan_target() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        std::fs::create_dir(&repo).unwrap();
        let config_path = repo.join("config.yaml");
        std::fs::write(&config_path, "step1:\n  model: m\n").unwrap();
        let mut c = cli(&repo);
        c.config = Some(config_path);
        let check = check_config_loads(&c);
        assert_eq!(check.status, CheckStatus::Fail);
    }

    #[test]
    fn run_checks_includes_config_check_only_when_config_is_set() {
        let dir = tempfile::tempdir().unwrap();
        let c = cli(dir.path());
        let result = crate::build_llm_client(&c);
        let without = run_checks(&c, &result);
        assert!(!without.iter().any(|c| c.name == "--config"));

        let config_path = dir.path().join("config.yaml");
        std::fs::write(&config_path, "step1:\n  model: m\n").unwrap();
        let mut c = cli(dir.path());
        c.config = Some(config_path);
        let result = crate::build_llm_client(&c);
        let with = run_checks(&c, &result);
        assert!(with.iter().any(|c| c.name == "--config"));
    }

    #[test]
    fn current_or_unknown_models_are_one_ok_line() {
        let dir = tempfile::tempdir().unwrap();
        let c = cli(dir.path());
        let checks = check_model_lifecycles(&c, "2026-09-25");
        assert_eq!(checks, [Check::ok("models", "m")]);
        let result = crate::build_llm_client(&c);
        assert!(run_checks(&c, &result).iter().any(|c| c.name == "models"));
    }

    #[test]
    fn a_retired_role_model_blocks_and_a_legacy_one_warns() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        std::fs::write(
            &config_path,
            "models:\n  verify:\n    id: claude-3-5-sonnet\n",
        )
        .unwrap();
        let mut c = cli(dir.path());
        c.model = "gpt-4o".to_string();
        c.config = Some(config_path);
        let checks = check_model_lifecycles(&c, "2026-09-25");
        assert_eq!(checks.len(), 2);
        assert_eq!(checks[0].status, CheckStatus::Fail);
        assert!(checks[0].required);
        assert!(checks[0].detail.contains("claude-3-5-sonnet is retired"));
        assert_eq!(checks[1].status, CheckStatus::Warn);
        assert!(checks[1].detail.contains("gpt-4o is legacy"));

        c.allow_unsupported_model = true;
        let checks = check_model_lifecycles(&c, "2026-09-25");
        assert_eq!(n_blocking(&checks), 0);
        assert!(checks.iter().all(|c| c.status == CheckStatus::Warn));
    }

    struct Identity {
        _dir: tempfile::TempDir,
        cert: std::path::PathBuf,
        key: std::path::PathBuf,
        combined: std::path::PathBuf,
    }

    fn identity() -> &'static Identity {
        static ONCE: std::sync::OnceLock<Identity> = std::sync::OnceLock::new();
        ONCE.get_or_init(|| {
            let dir = tempfile::tempdir().expect("a temporary directory");
            let cert = dir.path().join("client-cert.pem");
            let key = dir.path().join("client-key.pem");
            let combined = dir.path().join("client-combined.pem");
            let run = std::process::Command::new("openssl")
                .arg("req")
                .args(["-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1"])
                .args(["-subj", "/CN=bc-sast TEST ONLY client identity"])
                .arg("-keyout")
                .arg(&key)
                .arg("-out")
                .arg(&cert)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .expect("openssl must be on PATH to run this crate's tests");
            assert!(run.success(), "openssl could not generate a test identity");
            let mut both = std::fs::read(&cert).expect("the generated certificate");
            both.push(b'\n');
            both.extend(std::fs::read(&key).expect("the generated key"));
            std::fs::write(&combined, both).expect("the combined pem");
            Identity {
                _dir: dir,
                cert,
                key,
                combined,
            }
        })
    }

    #[test]
    fn no_client_identity_check_is_shown_when_mtls_is_not_configured() {
        let dir = tempfile::tempdir().unwrap();
        let c = cli(dir.path());
        let result = crate::build_llm_client(&c);
        assert!(check_client_identity(&c, &result).is_none());
        assert!(!run_checks(&c, &result)
            .iter()
            .any(|c| c.name == "mTLS client certificate"));
    }

    #[test]
    fn a_loadable_client_identity_is_reported_ok_with_both_files() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = cli(dir.path());
        c.client_cert = Some(identity().cert.clone());
        c.client_key = Some(identity().key.clone());
        let result = crate::build_llm_client(&c);
        let check = check_client_identity(&c, &result).unwrap();
        assert_eq!(check.status, CheckStatus::Ok);
        assert!(check.detail.contains("client-cert.pem"), "{}", check.detail);
        assert!(check.detail.contains("(key "), "{}", check.detail);

        c.client_key = None;
        c.client_cert = Some(identity().combined.clone());
        let result = crate::build_llm_client(&c);
        let check = check_client_identity(&c, &result).unwrap();
        assert_eq!(check.status, CheckStatus::Ok);
        assert!(
            check.detail.ends_with("client-combined.pem"),
            "{}",
            check.detail
        );
    }

    #[test]
    fn an_unloadable_client_identity_blocks() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = cli(dir.path());
        c.client_key = Some(identity().key.clone());
        let result = crate::build_llm_client(&c);
        let err = result.as_ref().err().expect("a key alone is refused");
        assert!(err.contains("without a client certificate"), "{err}");
        let checks = run_checks(&c, &result);
        let check = checks
            .iter()
            .find(|c| c.name == "mTLS client certificate")
            .unwrap();
        assert_eq!(check.status, CheckStatus::Fail);
        assert!(check.required);
        assert!(
            check.detail.contains("without --client-cert"),
            "{}",
            check.detail
        );
    }

    struct BudgetProbe {
        seen: std::sync::Mutex<Option<u32>>,
        reply: fn() -> Result<appsec_llm_client::ChatResponse, LlmError>,
    }

    #[async_trait::async_trait]
    impl LlmClient for BudgetProbe {
        async fn chat(
            &self,
            request: &ChatRequest,
        ) -> Result<appsec_llm_client::ChatResponse, LlmError> {
            *self.seen.lock().unwrap() = Some(request.max_tokens);
            (self.reply)()
        }
    }

    fn cut_off() -> appsec_llm_client::ChatResponse {
        appsec_llm_client::ChatResponse {
            content: vec![appsec_llm_client::ContentBlock::text("po")],
            stop_reason: appsec_llm_client::StopReason::MaxTokens,
            usage: appsec_llm_client::Usage::default(),
        }
    }

    #[tokio::test]
    async fn probe_gateway_asks_for_a_256_token_budget() {
        let client = BudgetProbe {
            seen: std::sync::Mutex::new(None),
            reply: || Ok(cut_off()),
        };
        let check = probe_gateway(&client, "m").await;
        assert_eq!(*client.seen.lock().unwrap(), Some(256));
        assert_eq!(
            check.status,
            CheckStatus::Ok,
            "a reply cut off by the budget still proves reachability"
        );
    }

    #[tokio::test]
    async fn probe_gateway_counts_a_truncated_reply_error_as_reachable() {
        let client = BudgetProbe {
            seen: std::sync::Mutex::new(None),
            reply: || {
                Err(LlmError::Truncated {
                    requested: 256,
                    retried_at: Some(512),
                    partial: Box::new(cut_off()),
                })
            },
        };
        let check = probe_gateway(&client, "m").await;
        assert_eq!(check.status, CheckStatus::Ok);
        assert_eq!(check.detail, "m reachable");
    }

    #[tokio::test]
    async fn probe_gateway_ok_when_the_fake_client_answers() {
        struct FakeClient;
        #[async_trait::async_trait]
        impl LlmClient for FakeClient {
            async fn chat(
                &self,
                _request: &ChatRequest,
            ) -> Result<appsec_llm_client::ChatResponse, appsec_llm_client::LlmError> {
                Ok(appsec_llm_client::ChatResponse {
                    content: vec![appsec_llm_client::ContentBlock::text("pong")],
                    stop_reason: appsec_llm_client::StopReason::EndTurn,
                    usage: appsec_llm_client::Usage::default(),
                })
            }
        }
        let check = probe_gateway(&FakeClient, "m").await;
        assert_eq!(check.status, CheckStatus::Ok);
    }

    #[tokio::test]
    async fn probe_gateway_retries_a_rate_limit_and_then_succeeds() {
        struct FlakyClient(std::sync::Mutex<u32>);
        #[async_trait::async_trait]
        impl LlmClient for FlakyClient {
            async fn chat(
                &self,
                _request: &ChatRequest,
            ) -> Result<appsec_llm_client::ChatResponse, appsec_llm_client::LlmError> {
                let mut n = self.0.lock().unwrap();
                *n += 1;
                if *n < 3 {
                    return Err(appsec_llm_client::LlmError::RateLimited {
                        retry_after_secs: None,
                    });
                }
                Ok(appsec_llm_client::ChatResponse {
                    content: vec![appsec_llm_client::ContentBlock::text("pong")],
                    stop_reason: appsec_llm_client::StopReason::EndTurn,
                    usage: appsec_llm_client::Usage::default(),
                })
            }
        }
        let check = probe_gateway(&FlakyClient(std::sync::Mutex::new(0)), "m").await;
        assert_eq!(check.status, CheckStatus::Ok);
    }

    #[tokio::test]
    async fn probe_gateway_warns_but_does_not_block_on_a_persistent_rate_limit() {
        struct ThrottledClient;
        #[async_trait::async_trait]
        impl LlmClient for ThrottledClient {
            async fn chat(
                &self,
                _request: &ChatRequest,
            ) -> Result<appsec_llm_client::ChatResponse, appsec_llm_client::LlmError> {
                Err(appsec_llm_client::LlmError::RateLimited {
                    retry_after_secs: Some(1),
                })
            }
        }
        let check = probe_gateway(&ThrottledClient, "m").await;
        assert_eq!(check.status, CheckStatus::Warn);
        assert!(!check.required);
        assert!(check.detail.contains("continuing"), "{}", check.detail);
    }

    #[tokio::test]
    async fn probe_gateway_fails_when_the_client_errors() {
        struct FailingClient;
        #[async_trait::async_trait]
        impl LlmClient for FailingClient {
            async fn chat(
                &self,
                _request: &ChatRequest,
            ) -> Result<appsec_llm_client::ChatResponse, appsec_llm_client::LlmError> {
                Err(appsec_llm_client::LlmError::ConnectionError {
                    message: "connection refused".to_string(),
                })
            }
        }
        let check = probe_gateway(&FailingClient, "m").await;
        assert_eq!(check.status, CheckStatus::Fail);
        assert!(!check.required);
    }

    #[test]
    fn render_shows_icons_per_status_and_a_summary_line() {
        let checks = vec![
            Check::ok("gateway client", "https://x"),
            Check::warn("git", "not found"),
            Check::fail("--config", "bad yaml", true),
        ];
        let text = render(&checks);
        assert!(text.contains('\u{2713}'));
        assert!(text.contains('\u{26a0}'));
        assert!(text.contains('\u{2717}'));
        assert!(text.contains("1 ok · 1 warning(s) · 1 blocking issue(s)"));
    }

    #[test]
    fn render_of_zero_checks_is_just_the_zeroed_summary_line() {
        let text = render(&[]);
        assert_eq!(text, "  0 ok · 0 warning(s) · 0 blocking issue(s)");
    }
}
