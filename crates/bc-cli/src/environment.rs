//! Shared environment-readiness checks engine (task #117/#153), consumed
//! by `--doctor` (task #145) and `--setup` (task #154) — mirrors Python's
//! `util/environment.py::run_checks`/`Check`, adapted to this port's own
//! architecture rather than a literal line-for-line port: Python's check
//! list spans four alternative LLM backends (`via:cli`/`via:sdk`/
//! `via:openai`/`via:deepagents`, each with its own credential-env
//! variable) and a Python-specific dependency/interpreter-version check
//! list, none of which exist here — this port has exactly one backend
//! shape (a gateway-mediated `LlmClient`, OpenAI- or Anthropic-dialect,
//! one API key). The checks below cover what's actually load-bearing for
//! *this* port's own readiness, not a re-creation of Python's unrelated
//! multi-backend surface.

use std::sync::Arc;

use bc_llm_client::LlmError;
use bc_llm_client::{ChatRequest, LlmClient, Message};

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
    /// A `Fail` on a `required` check blocks the live probe (nothing to
    /// probe if credentials/config are already known-bad) — mirrors
    /// Python's own `n_blocking` gate in `doctor`/`setup`.
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

/// The static (no-network) readiness checks, in display order. Pure/
/// side-effect-free beyond the `git --version` subprocess spawn and (if
/// `--config` is set) a config-file read — never touches the network,
/// never logs a credential value (only "set"/"unset"). Takes the
/// already-built gateway-client result (`crate::build_llm_client(cli)`)
/// rather than building it internally, so a caller that goes on to run
/// [`probe_gateway`] can reuse the SAME client instead of a second,
/// redundant build — and so the "was it Ok" question this function
/// already answers via its own `Check` never needs re-asking downstream.
pub fn run_checks(cli: &Cli, client_result: &Result<Arc<dyn LlmClient>, String>) -> Vec<Check> {
    let mut checks = vec![
        check_gateway_client(cli, client_result),
        check_gateway_api_key(cli),
        // `cli.repo` is `None` only in `--repo-file` batch mode, where
        // there is no single scan target to probe yet, so the check
        // narrows to "is git installed" rather than panicking through
        // `repo_path`.
        check_git(cli.repo.as_deref()),
    ];
    if cli.config.is_some() {
        checks.push(check_config_loads(cli));
    }
    checks
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

/// Is `git` installed, AND will it actually operate on the scan target?
///
/// Those are two different questions, and only the first one used to be
/// asked. The second one exists because git 2.35 and later refuse a
/// repository owned by a different user (`fatal: detected dubious
/// ownership`), which is the normal state of a bind-mounted CI checkout
/// inside this project's own nonroot (uid 65532) container image. Four
/// features probe for git rather than assuming it, so an ownership
/// refusal does not break a scan: `report.git_sha` detection,
/// `--remediate`'s worktree isolation, S10's git revert backstop, and
/// `--repo-file` clone entries all just quietly go back to their
/// pre-`git` behavior. Quietly is the problem. An operator who set up the
/// container specifically to get those has no way to tell that none of
/// them fired, so `--doctor`/`--setup` say it here instead.
///
/// A scan target that is simply not a git worktree at all is `Ok` with a
/// note, not a warning: scanning an unpacked source tree is a legitimate
/// and common way to run this, and nothing is misconfigured about it.
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
    // `rev-parse --git-dir` is the cheapest question that still forces
    // git to open the repository, so it is the one that trips the
    // ownership check. It touches no object database and needs no commit.
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
    match bc_config::load(path, &getenv)
        .map_err(|e| e.to_string())
        .and_then(|_| {
            bc_config::check_config_trust(path, repo_path(cli), &getenv).map_err(|e| e.to_string())
        }) {
        Ok(()) => Check::ok("--config", path.display().to_string()),
        Err(e) => Check::fail("--config", e, true),
    }
}

/// One minimal real request through the already-built gateway client —
/// catches bad credentials, an unreachable base URL, a TLS/proxy
/// misconfiguration, or an unknown model id *before* any real tokens are
/// spent on an actual scan. Mirrors Python's own `probe_backends`; only
/// `--doctor` calls this (never `--setup`, which is read-only by design —
/// see that command's own doc comment once task #154 lands).
pub async fn probe_gateway(client: &dyn LlmClient, model: &str) -> Check {
    let request = ChatRequest {
        model: model.to_string(),
        system: None,
        messages: vec![Message::user_text("ping")],
        tools: Vec::new(),
        max_tokens: 4,
        temperature: None,
        top_p: None,
        seed: None,
        thinking_budget: None,
        betas: Vec::new(),
        json_mode: false,
        timeout: None,
        stream: false,
    };
    // A transient error is retried a few times before it means anything:
    // eight scans starting at once on 2026-09-07 each got a 429 on this
    // one probe call and two of them refused to start, although the scan's
    // own retry loop would have sailed through it seconds later.
    let mut last_err = None;
    for attempt in 0..PROBE_ATTEMPTS {
        match client.chat(&request).await {
            Ok(_) => return Check::ok("live probe", format!("{model} reachable")),
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
        // The gateway is up and the key works — it just said "slow down".
        // Not blocking: the scan's retry loop handles exactly this.
        Check::warn(
            "live probe",
            format!("{e} — the scan's own retries handle this; continuing"),
        )
    } else {
        Check::fail("live probe", e.to_string(), false)
    }
}

/// Live-probe attempts before an error counts, and the backoff between
/// them (1 s, 2 s): long enough to outlive a burst 429, short enough not
/// to make `--doctor` feel broken.
const PROBE_ATTEMPTS: u32 = 3;
const PROBE_BACKOFF_BASE: std::time::Duration = std::time::Duration::from_secs(1);

/// `  {icon} {name:<30} {detail}` per check, plus a `N ok · M warning(s)
/// · K blocking issue(s)` summary line — the exact rendering `--doctor`
/// and `--setup` both reuse, matching Python's own shared display format
/// (`cli.py`'s `_ICON` map + summary line).
pub fn render(checks: &[Check]) -> String {
    let mut out = Vec::with_capacity(checks.len() + 1);
    let mut ok = 0;
    let mut warn = 0;
    let mut fail = 0;
    for check in checks {
        let icon = match check.status {
            CheckStatus::Ok => {
                ok += 1;
                '\u{2713}' // ✓
            }
            CheckStatus::Warn => {
                warn += 1;
                '\u{26a0}' // ⚠
            }
            CheckStatus::Fail => {
                fail += 1;
                '\u{2717}' // ✗
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
        // `required` is only consulted by `n_blocking` for a `Fail`
        // status (see its own doc comment) — an `Ok` check is never
        // blocking regardless of this flag, so `Check::ok` always
        // leaves it `false` rather than tracking a distinction that
        // never changes behavior.
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
        // Every machine this test suite runs on has git installed (the
        // whole workspace is a git checkout) — genuinely deterministic,
        // not environment-dependent the way `progress::should_render`'s
        // real-terminal check is.
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
        // Scanning an unpacked source tree is a supported way to run
        // this, so it must not read as a misconfiguration. It does say
        // what the consequence is.
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

    #[tokio::test]
    async fn probe_gateway_ok_when_the_fake_client_answers() {
        struct FakeClient;
        #[async_trait::async_trait]
        impl LlmClient for FakeClient {
            async fn chat(
                &self,
                _request: &ChatRequest,
            ) -> Result<bc_llm_client::ChatResponse, bc_llm_client::LlmError> {
                Ok(bc_llm_client::ChatResponse {
                    content: vec![bc_llm_client::ContentBlock::text("pong")],
                    stop_reason: bc_llm_client::StopReason::EndTurn,
                    usage: bc_llm_client::Usage::default(),
                })
            }
        }
        let check = probe_gateway(&FakeClient, "m").await;
        assert_eq!(check.status, CheckStatus::Ok);
    }

    /// A burst 429 on the single probe call must not refuse to start a
    /// scan whose own retry loop would sail through it seconds later.
    #[tokio::test]
    async fn probe_gateway_retries_a_rate_limit_and_then_succeeds() {
        struct FlakyClient(std::sync::Mutex<u32>);
        #[async_trait::async_trait]
        impl LlmClient for FlakyClient {
            async fn chat(
                &self,
                _request: &ChatRequest,
            ) -> Result<bc_llm_client::ChatResponse, bc_llm_client::LlmError> {
                let mut n = self.0.lock().unwrap();
                *n += 1;
                if *n < 3 {
                    return Err(bc_llm_client::LlmError::RateLimited {
                        retry_after_secs: None,
                    });
                }
                Ok(bc_llm_client::ChatResponse {
                    content: vec![bc_llm_client::ContentBlock::text("pong")],
                    stop_reason: bc_llm_client::StopReason::EndTurn,
                    usage: bc_llm_client::Usage::default(),
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
            ) -> Result<bc_llm_client::ChatResponse, bc_llm_client::LlmError> {
                Err(bc_llm_client::LlmError::RateLimited {
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
            ) -> Result<bc_llm_client::ChatResponse, bc_llm_client::LlmError> {
                Err(bc_llm_client::LlmError::ConnectionError {
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
