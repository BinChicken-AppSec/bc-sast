//! `bc-sast` binary: clap argument parsing, concrete `LlmClient`/`ToolExecutor`
//! wiring, and the glue that calls `bc_orchestrator::run_scan` and writes
//! its Markdown/SARIF output to disk.
//!
//! Kept in a `lib.rs` (not inline in `main.rs`) specifically so every
//! piece of real logic is unit-testable: `main.rs` itself is reduced to
//! parsing real `argv` and printing/exiting on [`main_impl`]'s result —
//! everything else here can be exercised directly, with fake
//! `LlmClient`/`ToolExecutor` implementations standing in for the real
//! network-backed ones the same way `bc-orchestrator`'s own tests do.
//!
//! **Deliberately not wired**:
//! - `--insecure` (disabling TLS verification) — `bc_gateway_http::
//!   GatewayConfig`'s `verify_tls` always stays at its default (`true`).
//!   `--ca-cert` (a custom trust anchor) IS wired, below.

mod args;
mod autoexclude;
mod baseline;
mod batch;
mod cache_probe;
pub mod cancel;
mod clone;
mod config_load;
mod config_overrides;
mod csv_parse;
pub mod delivery;
pub mod delivery_archive;
pub mod delivery_branch;
mod environment;
mod estimate;
mod llm_settings;
mod logging;
mod model_policy;
mod preflight;
mod progress;
mod progress_lines;
pub mod provider_publish;
mod run_manifest;
mod s6_progress;
pub mod target_executor;
pub mod target_testing;
mod worktree;

use std::path::{Path, PathBuf};
use std::sync::Arc;

#[cfg(test)]
pub(crate) use args::test_support;
pub use args::{Cli, Dialect, StopAfterArg};
pub use logging::init_logging;

use bc_llm_client::{LlmClient, ToolExecutor};
use bc_orchestrator::{ScanConfig, ScanInput, ScanOutcome, SpendCap, StopAfter};
use bc_sandbox_tools::SandboxTools;
use bc_stage_s0::Step0Config;
use bc_stage_s1::Step1Config;
use bc_stage_s2::Step2Config;
use bc_stage_s3::Step3Config;
use bc_stage_s4::Step4Config;
use bc_stage_s5::Step5Config;
use bc_stage_s6::Step6Config;
use bc_stage_s7::Step7Config;
use bc_stage_s8::Step8Config;
use serde::{Deserialize, Serialize};
use serde_json::Value;

fn getenv(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

/// `cli.repo`, unwrapped. Every function below that reads it runs only
/// after `cli.repo` is guaranteed `Some` — either clap's own
/// `required_unless_present = "repo_file"` for a normal single-repo
/// invocation, or `batch::run_batch` explicitly filling it in per manifest
/// entry before delegating to these same functions (see that module).
fn repo_path(cli: &Cli) -> &Path {
    cli.repo
        .as_deref()
        .expect("cli.repo is Some by the time any scan-path function reads it")
}

/// Every stage starts from `cli.model` plus its own already-verified
/// shipped default for everything else, exactly as before `--config`
/// existed. If `--config` is given, `bc_config::load` (YAML parse +
/// step-defaults deep-merge + `config.local.yaml` overlay + `${VAR}`
/// expansion) resolves the full merged tree, `check_config_trust` refuses
/// one that resolves inside `--repo` itself (fail-closed, matching the
/// project's config-loading invariant), and
/// `config_overrides::apply_overrides` projects every per-stage field and
/// `models.<role>` model-role override onto the already-constructed
/// config. Omitting `--config` entirely changes nothing from today's
/// behavior.
pub fn build_scan_config(cli: &Cli) -> Result<ScanConfig, String> {
    let mut config = ScanConfig {
        autoexclude: Default::default(),
        cancel: None,
        // Static detection uses the corpus embedded in this build. Runtime
        // configuration may toggle S0, but cannot replace its rule files.
        step0_enabled: true,
        step0: Step0Config::new(),
        step1: Step1Config::new(cli.model.clone()),
        step2_enabled: true,
        step2: Step2Config::new(cli.model.clone()),
        step3: Step3Config::new(cli.model.clone()),
        step4: Step4Config::new(cli.model.clone()),
        step5: Step5Config::new(cli.model.clone()),
        step6: Step6Config::new(cli.model.clone()),
        step7: Step7Config::new(cli.model.clone()),
        step8: Step8Config::new(cli.model.clone()),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        // `--max-tokens`/`--max-scan-seconds`-only, deliberately not
        // exposed via `--config`'s YAML tree — like
        // `Step1Config::retry_backoff_base` above, this is a Rust-only
        // knob with no Python-original config-schema equivalent for
        // `config_overrides.rs` to project onto.
        spend_cap: if cli.max_tokens.is_some() || cli.max_scan_seconds.is_some() {
            Some(SpendCap {
                max_total_tokens: cli.max_tokens,
                max_wall_clock: cli.max_scan_seconds.map(std::time::Duration::from_secs),
            })
        } else {
            None
        },
        // Left unset here deliberately — opening the state DB is a real
        // side effect (touches `$BC_STATE_DIR`/`$HOME` on disk), so it's
        // done by the caller (`run`, mirroring the `--remediate` path's
        // own `open_checkpoint_store()` call) rather than inside this
        // otherwise-pure config-assembly function; every direct unit
        // test of `build_scan_config` would otherwise touch the real
        // developer state dir on every `cargo test` run.
        checkpoint: None,
        resume: cli.resume,
        // Off by default, matching Python's own `output.emit_unreachable_
        // appendix` code default — only ever set to `true` via `--config`'s
        // `output.emit_unreachable_appendix` key (see
        // `config_overrides::apply_overrides`), never a CLI flag, matching
        // Python (which has no CLI flag for this either).
        emit_unreachable_appendix: false,
        // Wired by the caller (`run`), same reasoning as `checkpoint`
        // above — a progress sink is a real runtime collaborator (a
        // channel a consumer is draining), not config-assembly state.
        progress: None,
        // The baseline: whatever `--gateway-base-url`'s host settles.
        // `--config`'s `pricing.provider` (below) and then
        // `--pricing-provider` layer over it. An endpoint whose host
        // names no provider stays `None` and reports unpriced tokens
        // rather than a guessed dollar figure.
        pricing: bc_orchestrator::pricing::PricingConfig::for_provider(
            bc_orchestrator::pricing::infer_provider(&cli.gateway_base_url),
        ),
    };

    // Always run the projection, even with no `--config` — an absent
    // config is `Value::Null`, on which every `get` is `None`, so the
    // per-stage/per-role reads are exact no-ops and only the global
    // sampling flags below take effect. Doing it this way keeps
    // `--temperature`/`--seed`/`--top-p`/`--step-timeout` working
    // standalone rather than silently requiring a config file.
    let mut data = Value::Null;
    if let Some(path) = &cli.config {
        let loaded = config_load::load(path).map_err(stringify)?;
        bc_config::check_config_trust(path, repo_path(cli), &getenv).map_err(stringify)?;
        config_overrides::validate_model_roles(&loaded.data)?;
        config.step2_enabled =
            config_overrides::step2_enabled_override(&loaded.data).unwrap_or(config.step2_enabled);
        config.step0_enabled =
            config_overrides::step0_enabled_override(&loaded.data).unwrap_or(config.step0_enabled);
        data = loaded.data;
    }
    for key in ["sources_yaml", "sinks_yaml"] {
        if data
            .get("step0")
            .and_then(|s| s.get(key))
            .is_some_and(|v| !v.is_null())
        {
            return Err(format!("step0.{key} runtime rule files are no longer supported; edit crates/bc-stage-s0/corpus and rebuild"));
        }
    }
    config_overrides::apply_overrides(&mut config, &data, global_sampling(cli));
    // One-hour cache writes bill at their own rate. Only the Anthropic
    // dialect sends a lifetime at all; an OpenAI run keeps the default.
    if cli.dialect == Dialect::Anthropic {
        config.pricing.cache_ttl =
            llm_settings::resolve(cli.openai_api, cli.no_cache_markers, &data)?
                .cache
                .ttl;
    }
    if cli.no_threat_model {
        config.step2_enabled = false;
    }
    // After the config projection, so the flag wins: an operator naming a
    // provider on the command line is correcting the run in front of
    // them, the same way `--step-timeout` overrides a profile's own
    // `stepN.timeout`.
    if let Some(provider) = &cli.pricing_provider {
        config.pricing.provider = Some(provider.clone());
    }

    Ok(config)
}

/// Everything a `--remediate` run needs beyond the just-produced
/// `FinalReport`: the resolved [`bc_orchestrator::RemediateConfig`] plus
/// an optional [`bc_stage_s10::PolicyContext`] (built only when the
/// policy gate is actually enabled — `--enforce-remediation-policy`
/// and/or a truthy `step_remediate.enforce_policy` in `--config`).
pub struct RemediateSettings {
    pub target_tests: Option<target_testing::TargetTestingConfig>,
    pub config: bc_orchestrator::RemediateConfig,
    pub policy: Option<bc_stage_s10::PolicyContext>,
    /// `-i`/`--interactive`: dispatch through the arrow-key picker
    /// instead of the automatic top-N batch walk.
    pub interactive: bool,
    /// Whether Phase 3's S11 fix-validation panel runs right after each
    /// finding's remediation (both the batch walk and the `-i` picker).
    /// Defaults to `true` whenever `--remediate` is set: a deliberate
    /// divergence from vvaharness v1.4.0, which ships S11 off, because
    /// here S11's grade is what rolls back a patch it finds `Not Fixed` or
    /// `UNVERIFIABLE` (see docs/validation.md). Overridable by
    /// `--config`'s `step_validate.enabled`, and by `--validate`/
    /// `--no-validate`, which win over the config.
    pub validate_enabled: bool,
    pub step11: bc_stage_s11::Step11Config,
}

/// Mirrors [`build_scan_config`]'s own `--config` resolution (load, trust
/// check, project overrides) for S10's own settings — a separate
/// function since `RemediateConfig`/`PolicyContext` aren't part of
/// `ScanConfig`/the S1-S8 pipeline at all. Reads `--config` a second time
/// rather than threading `build_scan_config`'s already-loaded tree
/// through, trading a second small-file parse for two independently
/// testable, self-contained functions.
pub fn build_remediate_settings(cli: &Cli) -> Result<RemediateSettings, String> {
    let mut step10 = bc_stage_s10::Step10Config::new(cli.model.clone());
    let mut step11 = bc_stage_s11::Step11Config::new(cli.model.clone());
    // A repo-committed `inputs/validator_hints.yaml` is trusted under the
    // exact same opt-in that already lets an operator's own `config.yaml`
    // live inside the scan target — see `Step11Config::allow_repo_hints`'s
    // doc comment for the threat model.
    step11.allow_repo_hints = bc_config::check_config_trust(
        &bc_stage_s11::hints_path(repo_path(cli)),
        repo_path(cli),
        &getenv,
    )
    .is_ok();
    let mut top_default = None;
    let mut enforce_policy = cli.enforce_remediation_policy;
    let mut validate_enabled = true;
    // `step_remediate.policy_file`/`playbook_file`, resolved against the
    // `--config` file's own directory (see
    // `config_overrides::step_remediate_policy_paths`). Only consulted
    // when the corresponding `--remediation-policy`/`--remediation-
    // playbook` flag is absent, matching every other config-vs-flag pair
    // in this function.
    let mut policy_file = None;
    let mut playbook_file = None;

    if let Some(path) = &cli.config {
        let loaded = config_load::load(path).map_err(stringify)?;
        bc_config::check_config_trust(path, repo_path(cli), &getenv).map_err(stringify)?;
        config_overrides::validate_model_roles(&loaded.data)?;
        config_overrides::apply_step10_overrides(&mut step10, &loaded.data, global_sampling(cli));
        config_overrides::apply_step11_overrides(&mut step11, &loaded.data, global_sampling(cli));
        top_default = config_overrides::step_remediate_top_n_findings(&loaded.data);
        if let Some(e) = config_overrides::step_remediate_enforce_policy(&loaded.data) {
            enforce_policy = enforce_policy || e;
        }
        // `parent()` is `None` only for a bare root path, which can never
        // name a readable config file — an empty relative base then means
        // "resolve against the CWD", the same thing Python's own
        // `Path(cfg_dir)` degenerates to.
        let config_dir = path.parent().unwrap_or(Path::new(""));
        (policy_file, playbook_file) =
            config_overrides::step_remediate_policy_paths(&loaded.data, config_dir);
        // Reads `user_provided`, not `data`: `data` always has
        // `step_validate.enabled` present (from `bc_config::step_defaults()`'s
        // own bare-default `false`), so reading it here would silently
        // override this crate's own `true` default the moment ANY
        // `--config` is passed, even one that never mentions
        // `step_validate` at all — see `step_validate_enabled_override`'s
        // doc comment for why `true` is the intended baseline.
        validate_enabled = config_overrides::step_validate_enabled_override(&loaded.user_provided)
            .unwrap_or(validate_enabled);
    }
    // The explicit flags beat the config file, in either direction.
    if let Some(explicit) = cli.validate {
        validate_enabled = explicit;
    }
    if cli.no_validate {
        validate_enabled = false;
    }

    let top = cli
        .top
        .as_deref()
        .map(|s| bc_stage_s10::parse_top_spec(s, "--top"))
        .transpose()?;
    if cli.interactive && top.is_none() {
        // Interactive mode shows the FULL findings list unless the user
        // explicitly caps it this run — a profile-configured default
        // would otherwise silently hide findings from a menu they're
        // choosing from by hand (matches the Python original exactly).
        top_default = None;
    }

    if cli.config.is_none() {
        // Mirrors `build_scan_config`'s "project onto an empty tree"
        // call: with no config file there are no per-role knobs to read,
        // but the global flags still have to reach S10/S11.
        config_overrides::apply_step10_overrides(&mut step10, &Value::Null, global_sampling(cli));
        config_overrides::apply_step11_overrides(&mut step11, &Value::Null, global_sampling(cli));
    }
    apply_remediation_gate_flags(cli, &mut step10);
    // The dialect and gateway host are part of every S10/S11 `--resume`
    // checkpoint key, so a record produced by one endpoint is never
    // served as another's (see `bc_checkpoint::EngineKey`).
    let (dialect, base_host) = engine_identity(cli);
    step10.dialect.clone_from(&dialect);
    step10.base_host.clone_from(&base_host);
    step11.dialect = dialect;
    step11.base_host = base_host;

    let policy = enforce_policy.then(|| {
        let policy_path = cli.remediation_policy.clone().or(policy_file);
        let playbook_path = cli.remediation_playbook.clone().or(playbook_file);
        if policy_path.is_none() && playbook_path.is_none() {
            // Fail-closed is kept exactly as it was — with no policy data
            // every finding is denied a patch — but silently is the worst
            // way to do it: an operator who enabled the gate and got zero
            // patches has no way to tell "policy says no" from "you never
            // gave me a policy". Name the two keys that would fix it.
            eprintln!(
                "  [s10] ⚠ remediation policy enforcement is ON but neither \
                 --remediation-policy/step_remediate.policy_file nor \
                 --remediation-playbook/step_remediate.playbook_file is set; \
                 the gate fails closed, so EVERY finding will be guidance-only \
                 (no patches will be generated)"
            );
        }
        let gate = match &policy_path {
            Some(path) => bc_policy_gate::RemediationGate::load(path),
            None => bc_policy_gate::RemediationGate::new(None),
        };
        let playbook = playbook_path
            .as_deref()
            .map(bc_policy_gate::load_playbook)
            .unwrap_or_default();
        let frameworks = bc_policy_gate::detect_frameworks(repo_path(cli));
        bc_stage_s10::PolicyContext::new(gate, playbook, frameworks)
    });

    Ok(RemediateSettings {
        target_tests: target_testing::load_config(cli)?,
        config: bc_orchestrator::RemediateConfig {
            step10,
            top,
            top_default,
            force: cli.force,
            resume: cli.resume,
            isolated: false,
        },
        policy,
        interactive: cli.interactive,
        validate_enabled,
        step11,
    })
}

/// `(dialect, gateway host)` for the checkpoint engine key: the wire
/// dialect's lower-case name, and the host of `--gateway-base-url` (empty
/// when it does not parse, which still keys by model and version).
fn engine_identity(cli: &Cli) -> (String, String) {
    let dialect = match cli.dialect {
        Dialect::Openai => "openai",
        Dialect::Anthropic => "anthropic",
    };
    let host = reqwest::Url::parse(&cli.gateway_base_url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_default();
    (dialect.to_string(), host)
}

/// The global sampling/effort/timeout flags, bundled for the config
/// projection — see `config_overrides::GlobalSampling` for which side
/// wins against a per-role config value.
fn global_sampling(cli: &Cli) -> config_overrides::GlobalSampling {
    config_overrides::GlobalSampling {
        temperature: cli.temperature,
        top_p: cli.top_p,
        seed: cli.seed,
        reasoning_effort: cli.reasoning_effort,
        step_timeout_secs: cli.step_timeout,
    }
}

/// The safety-gate CLI flags, applied on top of whatever
/// `step_remediate.*` already set — a flag always wins over the config
/// file, matching every other flag/config pair in this crate.
///
/// The two booleans are one-directional switches (`--no-syntax-check`
/// can only turn the gate off, `--keep-unverified` can only turn the
/// rollback off), so an absent flag leaves the config value untouched
/// rather than forcing it back to a CLI default — the same shape
/// `--no-threat-model` already has against `step2.enabled`.
fn apply_remediation_gate_flags(cli: &Cli, step10: &mut bc_stage_s10::Step10Config) {
    if cli.no_syntax_check {
        step10.syntax_check = false;
    }
    if cli.keep_unverified {
        step10.keep_unverified = true;
    }
    if let Some(n) = cli.max_diff_lines {
        step10.max_diff_lines = n;
    }
    if let Some(n) = cli.max_files_touched {
        step10.max_files_touched = n;
    }
    if cli.remediate_dry_run {
        step10.dry_run = true;
    }
    if let Some(cmd) = &cli.verify_command {
        step10.verify_command = Some(cmd.clone());
    }
    if let Some(secs) = cli.verify_timeout {
        step10.verify_timeout_secs = secs;
    }
}

/// Loads `--cve-file`/`--controls-file` (or their `inject.cve_file`/
/// `inject.controls_file` config equivalents) into the two `ScanInput`
/// fields that were hard-coded empty since this crate was written.
///
/// Both feeds are pure prompt CONTEXT — S1 renders the CVEs as "Known
/// CVEs already filed" and S3 as "DO NOT REDISCOVER", and the controls
/// become S3's `DESIGN CONTROLS` block — so a load failure degrades to
/// "inject nothing" with a warning rather than failing the scan, matching
/// Python's own `[inject] WARN`-and-continue behavior in
/// `injectors/cve_feed.py`/`design_controls.py`. That is deliberately
/// unlike `--compliance-policy`, which fails hard: a compliance policy
/// can DROP findings from the report, so scanning without one silently
/// would change what the operator is told; injecting nothing only costs
/// the model some context it will re-derive.
///
/// A missing file is not a failure at all — both loaders return an empty
/// vec for a path that does not exist.
///
/// `data` is the already-loaded `--config` tree (`Value::Null` when there
/// is none) and `config_dir` its directory, since a relative
/// `inject.cve_file` resolves against the config file, not the CWD
/// (`orchestrator/scan.py:210-211`).
fn load_injected_context(
    cli: &Cli,
    data: &Value,
    config_dir: &Path,
) -> (Vec<bc_model::Cve>, Vec<bc_model::Control>) {
    let (config_cves, config_controls) = config_overrides::inject_paths(data, config_dir);
    let cve_path = cli.cve_file.clone().or(config_cves);
    let controls_path = cli.controls_file.clone().or(config_controls);
    let cves = cve_path
        .map(|p| load_or_warn(bc_orchestrator::inject::load_known_cves(&p), "CVE feed"))
        .unwrap_or_default();
    let controls = controls_path
        .map(|p| {
            load_or_warn(
                bc_orchestrator::inject::load_design_controls(&p),
                "design controls",
            )
        })
        .unwrap_or_default();
    (cves, controls)
}

/// One warn-and-continue for both loaders — a named function rather than
/// two identical closures, matching this module's own `extract_findings`/
/// `stringify` precedent.
fn load_or_warn<T>(result: Result<Vec<T>, String>, what: &str) -> Vec<T> {
    match result {
        Ok(items) => items,
        Err(e) => {
            eprintln!("  [inject] WARN: could not load the {what} ({e}); injecting nothing");
            Vec::new()
        }
    }
}

pub fn build_scan_input(cli: &Cli) -> ScanInput {
    let repo_name = cli.repo_name.clone().unwrap_or_else(|| {
        repo_path(cli)
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "repo".to_string())
    });
    // Re-reads `--config` rather than threading `build_scan_config`'s
    // already-parsed tree through, matching `build_remediate_settings`'s
    // own precedent: a second small-file parse buys two independently
    // testable, self-contained functions. Errors are swallowed to `Null`
    // here because `build_scan_config` has already loaded and
    // trust-checked the same path and propagated any failure — reaching
    // this function at all means the file parsed.
    let (data, config_dir) = match &cli.config {
        Some(path) => (
            config_load::load(path)
                .map(|l| l.data)
                .unwrap_or(Value::Null),
            path.parent().unwrap_or(Path::new("")).to_path_buf(),
        ),
        None => (Value::Null, PathBuf::new()),
    };
    let (known_cves, design_controls) = load_injected_context(cli, &data, &config_dir);
    ScanInput {
        repo_root: repo_path(cli).to_path_buf(),
        repo_name,
        known_cves,
        design_controls,
        application_id: non_empty(&cli.app_id).map(str::to_string),
        cmdb_path: non_empty(&cli.cmdb_csv).map(PathBuf::from),
        git_sha_override: non_empty(&cli.git_sha).map(str::to_string),
        changed_files: Default::default(),
        diff_scope_active: false,
        compliance: Vec::new(),
        checkmarx_xml: cli.checkmarx_xml.clone(),
        snyk_json: cli.snyk_json.clone(),
        semgrep_json: cli.semgrep_json.clone(),
        aikido_json: cli.aikido_json.clone(),
        sonatype_json: cli.sonatype_json.clone(),
        semgrep_live: build_semgrep_live_config(cli),
        snyk_live: build_snyk_live_config(cli),
        sonatype_live: build_sonatype_live_config(cli),
        aikido_live: build_aikido_live_config(cli),
        checkmarx_live: build_checkmarx_live_config(cli),
    }
}

/// `Some` only when every required `--semgrep-*` flag is present
/// (`--semgrep-token`/`--semgrep-deployment-slug`/`--semgrep-repo`) —
/// same all-or-nothing precondition style as [`build_github_client`].
/// `--semgrep-branch`/`--semgrep-base-url` are optional overrides on top.
fn build_semgrep_live_config(cli: &Cli) -> Option<bc_thirdparty_api::semgrep::SemgrepConfig> {
    let token = cli.semgrep_token.clone()?;
    let deployment_slug = cli.semgrep_deployment_slug.clone()?;
    let repo = cli.semgrep_repo.clone()?;
    let mut config = bc_thirdparty_api::semgrep::SemgrepConfig::new(token, deployment_slug, repo);
    config.branch = cli.semgrep_branch.clone();
    if let Some(base_url) = &cli.semgrep_base_url {
        config.base_url = base_url.clone();
    }
    Some(config)
}

/// `Some` only when every required `--snyk-*` flag is present
/// (`--snyk-token`/`--snyk-org-id`/`--snyk-project-id`) — see
/// [`build_semgrep_live_config`]'s own doc comment for the pattern.
fn build_snyk_live_config(cli: &Cli) -> Option<bc_thirdparty_api::snyk::SnykConfig> {
    let token = cli.snyk_token.clone()?;
    let org_id = cli.snyk_org_id.clone()?;
    let project_id = cli.snyk_project_id.clone()?;
    let mut config = bc_thirdparty_api::snyk::SnykConfig::new(token, org_id, project_id);
    if let Some(base_url) = &cli.snyk_base_url {
        config.base_url = base_url.clone();
    }
    Some(config)
}

/// `Some` only when every required `--sonatype-*` flag is present
/// (`--sonatype-base-url`/`--sonatype-username`/`--sonatype-password`/
/// `--sonatype-app-id`) — see [`build_semgrep_live_config`]'s own doc
/// comment for the pattern. `--sonatype-stage` is an optional override
/// on top (defaults to `"build"`).
fn build_sonatype_live_config(cli: &Cli) -> Option<bc_thirdparty_api::sonatype::SonatypeConfig> {
    let base_url = cli.sonatype_base_url.clone()?;
    let username = cli.sonatype_username.clone()?;
    let password = cli.sonatype_password.clone()?;
    let app_id = cli.sonatype_app_id.clone()?;
    let mut config =
        bc_thirdparty_api::sonatype::SonatypeConfig::new(base_url, username, password, app_id);
    if let Some(stage) = &cli.sonatype_stage {
        config.stage = stage.clone();
    }
    Some(config)
}

/// `Some` only when every required `--aikido-*` flag is present
/// (`--aikido-client-id`/`--aikido-client-secret`/`--aikido-repo-id`) —
/// see [`build_semgrep_live_config`]'s own doc comment for the pattern.
/// `--aikido-base-url` is an optional override on top (defaults to the
/// EU SaaS host).
fn build_aikido_live_config(cli: &Cli) -> Option<bc_thirdparty_api::aikido::AikidoConfig> {
    let client_id = cli.aikido_client_id.clone()?;
    let client_secret = cli.aikido_client_secret.clone()?;
    let repo_id = cli.aikido_repo_id?;
    let mut config =
        bc_thirdparty_api::aikido::AikidoConfig::new(client_id, client_secret, repo_id);
    if let Some(base_url) = &cli.aikido_base_url {
        config.base_url = base_url.clone();
    }
    Some(config)
}

/// `Some` only when every required `--checkmarx-*` flag is present
/// (`--checkmarx-base-url`/`--checkmarx-iam-url`/`--checkmarx-tenant`/
/// `--checkmarx-api-key`/`--checkmarx-project-id`) — see
/// [`build_semgrep_live_config`]'s own doc comment for the pattern.
/// `--checkmarx-branch` is an optional filter on top.
fn build_checkmarx_live_config(cli: &Cli) -> Option<bc_thirdparty_api::checkmarx::CheckmarxConfig> {
    let base_url = cli.checkmarx_base_url.clone()?;
    let iam_url = cli.checkmarx_iam_url.clone()?;
    let tenant = cli.checkmarx_tenant.clone()?;
    let api_key = cli.checkmarx_api_key.clone()?;
    let project_id = cli.checkmarx_project_id.clone()?;
    let mut config = bc_thirdparty_api::checkmarx::CheckmarxConfig::new(
        base_url, iam_url, tenant, api_key, project_id,
    );
    config.branch = cli.checkmarx_branch.clone();
    Some(config)
}

/// [`resolve_diff_scope`]'s answer, kept as a pair rather than a bare map
/// because an empty map is ambiguous on its own: `bc_github::parse_diff`
/// legitimately returns nothing for a diff made only of renames,
/// deletions, mode changes or binary files (its own tests assert exactly
/// that), and collapsing that into "no diff scope" fails open — the scan
/// would sweep the whole repository at full LLM spend and the report
/// would never say a scope had been asked for.
pub struct DiffScope {
    /// Whether `--diff-scope` was requested at all.
    pub active: bool,
    /// Repo-relative path -> changed line numbers. Empty is meaningful
    /// only in combination with `active`.
    pub changed_files: std::collections::BTreeMap<String, std::collections::BTreeSet<i64>>,
}

impl DiffScope {
    /// The same boundary in the shape S10's remediation refusal wants —
    /// the changed-file SET, without the per-file line numbers only the
    /// scan stages use.
    ///
    /// Built from `active`, never from `changed_files.is_empty()`, for the
    /// reason this struct is a pair in the first place: a rename-only pull
    /// request is legitimately scoped to nothing, and a boundary that read
    /// it as "no boundary" would let remediation edit the entire
    /// repository.
    pub fn boundary(&self) -> bc_model::DiffScope {
        bc_model::DiffScope::new(self.active, self.changed_files.keys())
    }
}

/// `--diff-scope`'s pre-scan fetch: an inactive, empty [`DiffScope`] (a
/// pure no-op) when the flag isn't set; otherwise requires `github`
/// (built by [`build_github_client`]) to be `Some` — same precondition
/// pattern as `--post-comments-from`/`--post-fixes-from` — then fetches
/// and parses the PR's diff. Fails hard on a fetch error rather than
/// silently falling back to a full-repo scan, since that would silently
/// burn the budget `--diff-scope` exists to avoid.
///
/// A diff that fetches fine but parses to zero changed files is NOT an
/// error: renames, deletions, mode changes and binary files all produce
/// one legitimately. It warns and scopes the scan to nothing, so CI stays
/// green on a rename-only PR instead of either going red or quietly
/// scanning everything.
pub async fn resolve_diff_scope(
    diff_scope: bool,
    github: Option<&bc_github::GithubClient>,
) -> Result<DiffScope, String> {
    if !diff_scope {
        return Ok(DiffScope {
            active: false,
            changed_files: std::collections::BTreeMap::new(),
        });
    }
    let client = github.ok_or_else(|| {
        "--diff-scope requires --github-token/--github-repo/--pr-number".to_string()
    })?;
    let diff_text = client.fetch_diff().await.map_err(stringify)?;
    let changed_files = bc_github::parse_diff(&diff_text);
    if changed_files.is_empty() {
        // `eprintln!`, matching `config_overrides`'s own pre-scan
        // warnings, NOT `tracing::warn!`. A `tracing` warning reaches a
        // CI console now that `logging::init_logging` streams to a
        // non-terminal stderr by default, but it is still discarded on
        // an interactive terminal without `--log-stderr`, and this
        // particular message (the scan was scoped to nothing) has to
        // reach every operator on every run. Stderr is safe to write
        // here because this runs before the scan, so neither the
        // progress bar nor `--interactive`'s picker owns the terminal
        // yet.
        eprintln!(
            "  [diff-scope] WARN: the PR diff fetched successfully but contains no \
             changed source lines; the likely cause is a diff of only renames, \
             deletions, mode changes or binary files. Scoping the scan to nothing \
             rather than falling back to the whole repository."
        );
    }
    Ok(DiffScope {
        active: true,
        changed_files,
    })
}

/// `--pr-comments`' pre-scan precondition check: `Ok(())` (a pure no-op)
/// unless the flag was passed without `--diff-scope`, which is a hard
/// error before anything else happens.
///
/// Checked up front, next to [`resolve_diff_scope`]'s own credential
/// requirement and [`load_compliance_policies`]'s missing-file refusal,
/// for the same reason both of those fail closed rather than late: the
/// alternative is a full scan at full LLM spend that ends by posting
/// exactly the review thread the operator was trying to avoid. Better to
/// spend a second saying so.
///
/// A pull request comment is only useful against the pull request's own
/// changes. A finding somewhere else in the repository has no line in the
/// diff to anchor to, so GitHub demotes it to a conversation comment, and
/// a fix suggestion for a line the diff never touched has no commit
/// button at all. Requiring the scan to be diff-scoped is what keeps
/// "post comments" from meaning "narrate the whole repository into a
/// review thread".
/// Refuses `--diff-scope` alongside `--repo-file`, because batch mode
/// never resolves a diff and would silently full-repo scan every entry.
///
/// A manifest names many repositories; a diff belongs to one pull request
/// on one of them, so there is no coherent scope to resolve. Accepting the
/// flag and ignoring it is the dangerous half: an operator asking for a
/// change-focused batch scan gets full-repo analysis, full-repo
/// remediation candidates, and no indication the scoping they asked for
/// never happened.
pub fn check_batch_diff_scope(cli: &Cli) -> Result<(), String> {
    if cli.repo_file.is_some() && cli.diff_scope {
        return Err(concat!(
            "--diff-scope cannot be combined with --repo-file: a manifest names many ",
            "repositories and a diff belongs to one pull request on one of them, so batch ",
            "mode has no single scope to resolve. Scan the one repository directly to use ",
            "--diff-scope",
        )
        .to_string());
    }
    Ok(())
}

pub fn check_pr_comment_scope(cli: &Cli) -> Result<(), String> {
    if cli.pr_comments && !cli.diff_scope {
        return Err(concat!(
            "--pr-comments requires --diff-scope: PR comments and fix suggestions only ",
            "anchor to lines the pull request actually changed, so a full-repo scan would ",
            "post most of its findings as unanchored conversation comments",
        )
        .to_string());
    }
    Ok(())
}

/// Where `run` should post PR comments, which is nowhere unless
/// `--pr-comments` asked for it.
///
/// Takes the client [`build_github_client`] already produced (the same
/// one [`resolve_diff_scope`] fetches the PR diff through) and hands it
/// on only when posting was requested, so the credentials keep doing
/// their read-only job while the write stays opt-in. Having ONE place
/// decide this is what stops the scan path and the batch path from
/// disagreeing about when a run is allowed to comment.
pub fn pr_comment_target(
    cli: &Cli,
    github: Option<bc_github::GithubClient>,
) -> Option<bc_github::GithubClient> {
    cli.pr_comments.then_some(github).flatten()
}

/// Load only policies embedded in this build. Runtime policy files are
/// rejected before any filesystem access; callers select named presets.
pub fn load_compliance_policies(cli: &Cli) -> Result<Vec<bc_compliance::CompliancePolicy>, String> {
    if !cli.compliance_policy.is_empty() {
        return Err("--compliance-policy runtime files are no longer supported; select --scan-framework NAME (or --compliance-preset NAME). Edit crates/bc-compliance/presets and rebuild to change scan rules".into());
    }
    let mut policies = Vec::with_capacity(cli.compliance_preset.len());
    for name in &cli.compliance_preset {
        policies.push(bc_compliance::preset(name)?);
    }
    if let Some(scope) = parse_compliance_scope(&cli.compliance_scope)? {
        for p in &mut policies {
            p.scope_mode = scope;
        }
    }
    Ok(policies)
}

/// `--compliance-scope`'s pre-scan parse: `None` when unset (empty
/// string, the default) — every loaded policy keeps its own declared
/// `scope_mode` unchanged. `Some(mode)` overrides every policy uniformly,
/// matching `parse_stop_after`'s case-insensitive-string-flag convention.
fn parse_compliance_scope(raw: &str) -> Result<Option<bc_compliance::ScopeMode>, String> {
    non_empty(raw)
        .map(|s| match s.to_ascii_lowercase().as_str() {
            "annotate" => Ok(bc_compliance::ScopeMode::Annotate),
            "filter" => Ok(bc_compliance::ScopeMode::Filter),
            other => Err(format!("invalid --compliance-scope value: {other:?}")),
        })
        .transpose()
}

/// The directory name `--out-dir` defaults to, inside `--repo`. Shared
/// with [`worktree::patch_path`] (`remediation.patch` sits alongside the
/// reports), and known by name to `clone::CLONE_KEEP_DEFAULT` (a batch
/// clone's source is purged after scanning, this directory is not) and
/// to `bc_repo_analysis`/`bc_stage_s1`'s walkers (which skip it, so a
/// scan never reads its own previous output back in as source). Moving
/// the default elsewhere would silently break all three.
const DEFAULT_OUT_DIR: &str = "security-scan";

/// Where this scan's four report artifacts go. Resolved once, before the
/// scan starts, so every mode that needs one of these paths agrees on
/// where it is.
///
/// All four are unconditional: a scan that reaches the stage producing
/// an artifact writes that artifact, with no flag needed to ask for it
/// (`findings.json` has the one extra precondition described on
/// [`write_findings_json`]). The `--out-*` flags only MOVE a file, they
/// never enable one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputPaths {
    pub provider_writeback_plan: Option<PathBuf>,
    pub markdown: PathBuf,
    pub sarif: PathBuf,
    pub csv: PathBuf,
    pub findings_json: PathBuf,
}

impl OutputPaths {
    /// Creates the directory each artifact will be written into.
    ///
    /// Called BEFORE the scan rather than at write time (where
    /// [`create_parent_dir`] still creates it too, harmlessly, for a
    /// caller that skipped this): an output directory that cannot be
    /// created is a run that has nowhere to put its results, and
    /// discovering that after a full scan would waste every token it
    /// spent. Same rationale as loading `--baseline` up front.
    ///
    /// The failure is a plain `Err` naming the directory and the OS
    /// reason, never a panic. The packaged image is read-only and runs
    /// as a non-root user, so "cannot create it" is an ordinary
    /// deployment mistake an operator has to be able to read and fix,
    /// not a bug.
    fn ensure_dirs(&self) -> Result<(), String> {
        let mut created: Vec<&Path> = Vec::new();
        for path in [&self.markdown, &self.sarif, &self.csv, &self.findings_json]
            .into_iter()
            .chain(self.provider_writeback_plan.iter())
        {
            // `Path::new("report.md").parent()` is `Some("")`. A bare
            // relative filename lands in the working directory, which
            // needs no creating.
            let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) else {
                continue;
            };
            if created.contains(&dir) {
                continue;
            }
            std::fs::create_dir_all(dir)
                .map_err(|e| format!("cannot create output directory {}: {e}", dir.display()))?;
            created.push(dir);
        }
        Ok(())
    }
}

/// Resolves every output path from `--out-dir` (default:
/// `<repo>/security-scan`, see [`DEFAULT_OUT_DIR`]) plus each format's
/// own `--out-*` override, which wins for that format alone and leaves
/// the rest in the out-dir.
pub fn resolve_output_paths(cli: &Cli) -> OutputPaths {
    let dir = cli
        .out_dir
        .clone()
        .unwrap_or_else(|| repo_path(cli).join(DEFAULT_OUT_DIR));
    OutputPaths {
        provider_writeback_plan: (cli.provider_writeback != "off")
            .then(|| dir.join("provider-writeback-plan.json")),
        markdown: cli.out_md.clone().unwrap_or_else(|| dir.join("report.md")),
        sarif: cli
            .out_sarif
            .clone()
            .unwrap_or_else(|| dir.join("report.sarif")),
        csv: cli
            .out_csv
            .clone()
            .unwrap_or_else(|| dir.join("report.csv")),
        findings_json: cli
            .out_findings_json
            .clone()
            .unwrap_or_else(|| dir.join("findings.json")),
    }
}

/// Build the concrete, network-backed `LlmClient` for `cli.dialect`; see
/// [`build_llm_stack`].
pub fn build_llm_client(cli: &Cli) -> Result<Arc<dyn LlmClient>, String> {
    build_llm_stack(cli).map(|stack| stack.client)
}

/// The configured client together with what was decided building it,
/// which the run manifest reports.
pub(crate) struct LlmStack {
    pub client: Arc<dyn LlmClient>,
    pub settings: llm_settings::TransportSettings,
    /// The OpenAI client's per-model learning, shared so the manifest
    /// can count the models that fell back from the Responses API.
    /// `None` on the Anthropic dialect.
    pub learned: Option<Arc<bc_llm_openai::LearnedModels>>,
}

impl LlmStack {
    /// How many models this process moved from the Responses API to Chat
    /// Completions; `None` on the Anthropic dialect, which has no such
    /// choice.
    pub(crate) fn responses_fallbacks(&self) -> Option<u64> {
        self.learned.as_ref().map(|l| l.responses_fallbacks())
    }
}

/// Build the concrete client for `cli.dialect`, speaking the OpenAI API
/// shape [`llm_settings::resolve`] settled on, wrapped in
/// [`bc_llm_client::ApplyCachePolicy`] (the operator's prompt-cache
/// policy) and, when streaming is enabled (see
/// [`stream_large_responses`]), [`bc_llm_client::StreamLargeResponses`].
///
/// The wrappers go HERE, not in a stage: whether to cache or stream is a
/// transport question, so one decorator at the single point every
/// stage's client comes from applies the policy everywhere without any
/// stage knowing it exists.
pub(crate) fn build_llm_stack(cli: &Cli) -> Result<LlmStack, String> {
    let settings = llm_settings::resolve(
        cli.openai_api,
        cli.no_cache_markers,
        &lenient_config_data(cli),
    )?;
    let mut gateway_config = bc_gateway_http::GatewayConfig::new(cli.gateway_base_url.clone());
    gateway_config.ca_cert_path = cli.ca_cert.clone();
    gateway_config.client_cert_path = cli.client_cert.clone();
    gateway_config.client_key_path = cli.client_key.clone();
    let http = bc_gateway_http::build_client(&gateway_config).map_err(|e| e.to_string())?;
    let (client, learned): (Arc<dyn LlmClient>, _) = match cli.dialect {
        Dialect::Openai => {
            let learned = Arc::new(bc_llm_openai::LearnedModels::new());
            let client = bc_llm_openai::OpenAiClient::new(
                http,
                cli.gateway_base_url.clone(),
                cli.gateway_api_key.clone(),
            )
            .with_api(settings.openai_api)
            .with_learned_models(learned.clone());
            (Arc::new(client), Some(learned))
        }
        Dialect::Anthropic => (
            Arc::new(bc_llm_anthropic::AnthropicClient::new(
                http,
                cli.gateway_base_url.clone(),
                cli.gateway_api_key.clone(),
            )),
            None,
        ),
    };
    let client: Arc<dyn LlmClient> =
        Arc::new(bc_llm_client::ApplyCachePolicy::new(client, settings.cache));
    let client = if stream_large_responses(cli) {
        Arc::new(bc_llm_client::StreamLargeResponses::new(client))
    } else {
        client
    };
    Ok(LlmStack {
        client,
        settings,
        learned,
    })
}

/// The merged `--config` tree for a reader that runs before (or beside)
/// `build_scan_config`, or `Value::Null` without a config or when it
/// fails to load: `build_scan_config` reports a bad config itself, once,
/// so every earlier reader treats it as "no opinion" (see
/// [`stream_large_responses`]).
fn lenient_config_data(cli: &Cli) -> Value {
    cli.config
        .as_ref()
        .and_then(|path| config_load::load(path).ok())
        .map(|loaded| loaded.data)
        .unwrap_or(Value::Null)
}

/// Whether large model calls should be streamed —
/// `--stream-large-responses`, or `llm.stream_large_responses: true` in a
/// `--config`.
///
/// The flag can only turn streaming ON; it never overrides a config that
/// already enabled it. Same shape as `--no-threat-model` against
/// `step2.enabled`: a bare boolean flag has no "explicitly off" spelling
/// to express the opposite with, so it can only add to the config's
/// answer, never contradict it.
///
/// A `--config` that fails to load is read as "no opinion" rather than as
/// an error, matching `build_scan_input`'s own second read of the same
/// file — except that this one can run BEFORE `build_scan_config` has
/// validated it (`main_impl` builds the client first). That is
/// deliberate: `build_scan_config` still fails the run on a malformed
/// config a moment later, so the error is reported once, by the function
/// whose job it is, instead of twice with different wording.
fn stream_large_responses(cli: &Cli) -> bool {
    if cli.stream_large_responses {
        return true;
    }
    cli.config
        .as_ref()
        .and_then(|path| config_load::load(path).ok())
        .and_then(|loaded| config_overrides::llm_stream_large_responses_override(&loaded.data))
        .unwrap_or(false)
}

/// Builds a `GithubClient` when `--github-token`/`--github-repo`/
/// `--pr-number` are all present; `Ok(None)` when any is absent (PR-comment
/// posting is opt-in). `Err` only for a malformed `--github-repo` (not
/// `owner/name`) or a client-builder failure — a plain reqwest client is
/// used, unlike the gateway's custom-CA-aware one, since GitHub's own API
/// is reached over the public/standard trust store. A bounded 30s timeout
/// (short REST calls — fetch diff, list/post comments — never the
/// minutes-long generations the gateway client's 300s default accounts
/// for) keeps a stalled `api.github.com` connection from hanging the scan
/// indefinitely.
pub fn build_github_client(cli: &Cli) -> Result<Option<bc_github::GithubClient>, String> {
    match (&cli.github_token, &cli.github_repo, cli.pr_number) {
        (Some(token), Some(repo), Some(pr_number)) => {
            let (owner, name) = repo
                .split_once('/')
                .ok_or_else(|| format!("--github-repo must be \"owner/name\", got {repo:?}"))?;
            let mut config = bc_github::GithubConfig::new(owner, name, pr_number, token.clone());
            config.api_base_url = cli.github_api_base_url.clone();
            let http = finish_github_http_client(
                reqwest::Client::builder().timeout(std::time::Duration::from_secs(30)),
            )?;
            Ok(Some(bc_github::GithubClient::new(http, config)))
        }
        _ => Ok(None),
    }
}

/// Split out from [`build_github_client`] so its `map_err` is directly
/// testable with a builder state [`build_github_client`]'s own config
/// surface (a timeout only) can never actually produce — matching
/// `bc-gateway-http::finish`'s same split, for the same reason.
fn finish_github_http_client(builder: reqwest::ClientBuilder) -> Result<reqwest::Client, String> {
    builder
        .build()
        .map_err(|e| format!("failed to build GitHub HTTP client: {e}"))
}

/// Interchange format for `--out-findings-json` / `--post-comments-from`:
/// carries exactly what `bc_github::sync_findings` needs, so a later,
/// separate (and possibly more privileged) invocation of `bc-sast` can post PR
/// comments without re-running the scan at all.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct FindingsExport {
    commit_sha: String,
    findings: Vec<bc_model::Finding>,
}

/// Shared by `write_findings_json` and `sync_github` — a named function
/// (rather than each call site writing its own `.map(|rf| rf.finding.clone())`
/// closure) so there's exactly one compiled instance instead of several
/// identical-body closures at different call sites.
fn extract_findings(report: &bc_model::FinalReport) -> Vec<bc_model::Finding> {
    report
        .findings
        .iter()
        .map(|rf| rf.finding.clone())
        .collect()
}

/// Shared `.map_err` target across this crate — same rationale as
/// [`extract_findings`]: one named function instead of several textually
/// identical `|e| e.to_string()` closures.
fn stringify<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

/// [`stringify`] for the sites that prefix the failing operation with its
/// own context. One shared closure body per error type, rather than a
/// fresh `|e| format!("...: {e}")` at every call site: textually distinct
/// closures compile to separate functions, so each one has to be reached
/// on its own before the crate's own coverage gate counts it.
fn context<E: std::fmt::Display>(what: &'static str) -> impl Fn(E) -> String {
    move |error| format!("{what}: {error}")
}

/// Treats an empty string as "not provided" — what `--stop-after`/
/// `--app-id`/`--cmdb-csv` (raw `String` fields, not `Option<T>` — see
/// their own doc comments on `Cli`) are normalized through right where
/// each is consumed.
fn non_empty(raw: &str) -> Option<&str> {
    (!raw.is_empty()).then_some(raw)
}

/// Parses `--stop-after`'s raw value: empty means "not provided"
/// (`Ok(None)`); a non-empty value must be one of `s1`..`s9`
/// (case-insensitive, matching `StopAfterArg`'s own `ValueEnum` parsing —
/// reused here directly rather than duplicating its variant list).
fn parse_stop_after(raw: &str) -> Result<Option<StopAfterArg>, String> {
    non_empty(raw)
        .map(|s| {
            <StopAfterArg as clap::ValueEnum>::from_str(s, true)
                .map_err(|_| format!("invalid --stop-after value: {s:?}"))
        })
        .transpose()
}

/// Writes the findings snapshot, if the scan reached a `FinalReport`
/// with a known git SHA, the same precondition `sync_github` itself
/// checks before attempting to post anything. A silent no-op otherwise,
/// matching `write_outputs`'s own "only write what the scan actually
/// produced" behavior.
///
/// No longer conditional on a flag: the path is always resolved (see
/// [`OutputPaths`]), so every scan that CAN produce this file does. The
/// git-SHA precondition stays, though, and is the one reason a completed
/// scan may still leave no `findings.json`: the commit is half of what
/// the export is for, and a copy without one would only fail later, in
/// the privileged job that consumes it.
///
/// Returns whether it actually wrote, so the caller can report the path
/// in the run summary only when there is a file at it.
fn write_findings_json(
    path: &Path,
    report: Option<&bc_model::FinalReport>,
) -> std::io::Result<bool> {
    let Some(report) = report else {
        return Ok(false);
    };
    let Some(commit_sha) = &report.git_sha else {
        return Ok(false);
    };
    let export = FindingsExport {
        commit_sha: commit_sha.clone(),
        findings: extract_findings(report),
    };
    let json = serde_json::to_string_pretty(&export)
        .expect("FindingsExport contains no non-serializable types");
    create_parent_dir(path)?;
    std::fs::write(path, json)?;
    Ok(true)
}

/// `--post-comments-from`'s entire job: read a `FindingsExport` written by
/// a prior `--out-findings-json` run and post/update GitHub PR comments
/// for it, without touching `--repo` or running any pipeline stage at all.
/// Takes an already-built `GithubClient` (mirroring `run()`'s own
/// dependency-injected `github` parameter) rather than building one
/// internally, so this is directly testable against a fake gateway.
/// Reuses `ScanSummary` (rather than a second output type) so `main.rs`'s
/// `Display`-and-exit handling doesn't need to branch on which mode ran.
pub async fn post_comments_only(
    github: &bc_github::GithubClient,
    findings_json_path: &Path,
    repo_root: Option<&Path>,
) -> Result<ScanSummary, String> {
    let bytes = std::fs::read(findings_json_path).map_err(stringify)?;
    let export: FindingsExport = serde_json::from_slice(&bytes).map_err(stringify)?;
    let sync_result =
        bc_github::sync_findings(github, &export.findings, &export.commit_sha, repo_root)
            .await
            .map_err(|e| e.to_string());
    Ok(ScanSummary {
        provider_publication: None,
        gc: None,
        cost: None,
        findings: export.findings.len(),
        markdown_path: None,
        sarif_path: None,
        csv_path: None,
        findings_json_path: None,
        stopped_after: None,
        github_sync: Some(sync_result),
        remediation: None,
        remediation_patch: None,
        baseline: None,
        batch: None,
        estimate: None,
        doctor: None,
        setup: None,
        augmented: None,
    })
}

/// `--post-fixes-from`'s entire job: read a `RemediationExport` written by
/// a prior `--out-remediation-json` run and post/update GitHub
/// fix-suggestion comments for it, without touching `--repo` or running
/// any pipeline stage (or the LLM) at all. Mirrors [`post_comments_only`]
/// exactly, down to reusing `ScanSummary` so `main.rs`'s `Display`-and-exit
/// handling needs no branching for this mode either.
pub async fn post_fixes_only(
    github: &bc_github::GithubClient,
    remediation_json_path: &Path,
) -> Result<ScanSummary, String> {
    let bytes = std::fs::read(remediation_json_path).map_err(stringify)?;
    let export: RemediationExport = serde_json::from_slice(&bytes).map_err(stringify)?;
    let fixes: Vec<bc_github::FixSuggestion> = export
        .results
        .into_iter()
        .filter_map(|r| match r {
            RemediationOutcomeExport::Processed(record) => {
                let diff = record.diff?;
                (!diff.is_empty()).then_some(bc_github::FixSuggestion {
                    finding_id: record.finding_id,
                    diff,
                })
            }
            RemediationOutcomeExport::Failed { .. } => None,
        })
        .collect();
    let sync_result = bc_github::sync_fixes(github, &fixes)
        .await
        .map_err(|e| e.to_string());
    Ok(ScanSummary {
        provider_publication: None,
        gc: None,
        cost: None,
        findings: fixes.len(),
        markdown_path: None,
        sarif_path: None,
        csv_path: None,
        findings_json_path: None,
        stopped_after: None,
        github_sync: Some(sync_result),
        remediation: None,
        remediation_patch: None,
        baseline: None,
        batch: None,
        estimate: None,
        doctor: None,
        setup: None,
        augmented: None,
    })
}

fn create_parent_dir(path: &Path) -> std::io::Result<()> {
    match path.parent() {
        Some(parent) => std::fs::create_dir_all(parent),
        None => Ok(()),
    }
}

/// Publish S9's Markdown/SARIF and its redacted report as CSV. An S8 stop
/// retains analysis in memory but must not create reporting artifacts.
pub fn write_outputs(
    outcome: &ScanOutcome,
    md_path: &Path,
    sarif_path: &Path,
    csv_path: &Path,
) -> std::io::Result<()> {
    if outcome.stopped_after == Some(StopAfter::S8) {
        return Ok(());
    }
    if let Some(md) = &outcome.markdown {
        create_parent_dir(md_path)?;
        std::fs::write(md_path, md)?;
    }
    if let Some(sarif) = &outcome.sarif {
        create_parent_dir(sarif_path)?;
        std::fs::write(sarif_path, sarif)?;
    }
    if let Some(report) = &outcome.report {
        create_parent_dir(csv_path)?;
        std::fs::write(csv_path, bc_csv::build_csv(report))?;
    }
    Ok(())
}

/// The process exit code for a finished `main_impl`, shared by `main.rs`
/// and the run manifest so the two can never disagree.
///
/// `1` for an error, or for a `--doctor`/`--setup` run that found the
/// environment unhealthy. A run that remediated reports how that went
/// ([`RemediationSummary::exit_code`]: `1` for an S10/S11 failure, `3`
/// when nothing validated as fixed) unless `remediation_exit_code` is
/// off. Everything else, a plain scan included, is `0`.
///
/// A run the operator canceled (Ctrl-C) is
/// [`cancel::CANCELED_EXIT_CODE`] (130) whatever else happened, an error
/// included: the error of a run that was told to stop is a consequence
/// of the stop, and a caller scripting around this tool needs to tell
/// "canceled" from "failed".
pub fn process_exit_code(
    result: &Result<ScanSummary, String>,
    remediation_exit_code: bool,
    canceled: bool,
) -> u8 {
    if canceled {
        return cancel::CANCELED_EXIT_CODE;
    }
    let Ok(summary) = result else {
        return 1;
    };
    let unhealthy = summary.doctor.as_ref().is_some_and(|d| !d.healthy())
        || summary.setup.as_ref().is_some_and(|s| !s.healthy());
    if unhealthy {
        return 1;
    }
    summary
        .remediation
        .as_ref()
        .filter(|_| remediation_exit_code)
        .map_or(0, RemediationSummary::exit_code)
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct ScanSummary {
    pub provider_publication: Option<String>,
    pub findings: usize,
    pub markdown_path: Option<PathBuf>,
    pub sarif_path: Option<PathBuf>,
    pub csv_path: Option<PathBuf>,
    /// `Some(path)` when the findings snapshot was actually written.
    /// `None` when [`write_findings_json`]'s precondition (a
    /// `FinalReport` carrying a git SHA) wasn't met, so the summary
    /// never names a file that isn't there.
    pub findings_json_path: Option<PathBuf>,
    pub stopped_after: Option<StopAfter>,
    /// `Some(Ok(_))` when PR-comment posting was attempted and succeeded,
    /// `Some(Err(_))` when it was attempted and failed, `None` when it
    /// wasn't attempted at all (no `--github-*`/`--pr-number` args, the
    /// scan didn't reach a `FinalReport`, or it has no `git_sha`). A
    /// posting failure never turns the scan itself into an `Err` — the
    /// Markdown/SARIF artifacts are the scan's real output; PR comments
    /// are a best-effort delivery layer on top.
    pub github_sync: Option<Result<bc_github::SyncSummary, String>>,
    /// `Some(_)` when `--remediate` was passed and the scan reached a
    /// `FinalReport`; `None` otherwise (remediation not requested, or
    /// nothing to remediate).
    pub remediation: Option<RemediationSummary>,
    /// `Some(_)` when `--baseline` was given and the scan reached a
    /// `FinalReport` — how this scan's findings compare to the prior
    /// run's. `None` when no baseline was requested.
    pub baseline: Option<BaselineTally>,
    /// `Some(path)` when remediation ran in an isolated worktree and the
    /// agent's edits were exported as a unified diff to
    /// `<repo>/security-scan/remediation.patch` (see `crate::worktree`).
    /// `None` for in-place remediation (the edits are already on disk, so
    /// there is no patch to apply) and for a worktree run that produced
    /// no changes at all.
    pub remediation_patch: Option<PathBuf>,
    /// `Some(_)` when `--gc`/`--gc-run` ran instead of a scan — every
    /// other field on this struct is left at its default in that case
    /// (`Display` returns early on `Some(gc)`, so they're never
    /// rendered).
    pub gc: Option<GcSummary>,
    /// `Some(_)` when `--repo-file` ran a batch scan instead of a single
    /// `--repo` scan — mirrors `gc`'s own "every other field stays at its
    /// default, `Display` returns early" contract.
    pub batch: Option<batch::BatchSummary>,
    /// `Some(_)` when `--estimate` ran instead of a scan — mirrors `gc`'s
    /// own "every other field stays at its default, `Display` returns
    /// early" contract.
    pub estimate: Option<estimate::EstimateSummary>,
    /// `Some(_)` when `--doctor` ran instead of a scan — mirrors `gc`'s
    /// own "every other field stays at its default, `Display` returns
    /// early" contract.
    pub doctor: Option<DoctorSummary>,
    /// `Some(_)` when `--setup` ran instead of a scan — mirrors `gc`'s
    /// own "every other field stays at its default, `Display` returns
    /// early" contract.
    pub setup: Option<SetupSummary>,
    /// What the run's model calls cost. `Some(_)` whenever the scan
    /// reached a `FinalReport` carrying metrics; `None` for a
    /// `--stop-after` run that never built one, and for every non-scan
    /// mode.
    pub cost: Option<CostSummary>,
    /// `Some(_)` only in `--remediate-from` mode: what became of the
    /// PRIOR run's `report.md`/`report.sarif`, which this mode augments
    /// in place rather than rewriting from scratch (see
    /// [`augment_prior_reports`]). `None` in every other mode, including
    /// an ordinary `--remediate` scan — there the reports belong to the
    /// run that just produced them and are reported through
    /// [`Self::markdown_path`]/[`Self::sarif_path`] instead.
    pub augmented: Option<AugmentedReports>,
}

/// What became of ONE prior report artifact that `--remediate-from`
/// tried to augment in place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AugmentOutcome {
    /// Rewritten in place with this run's remediation/validation results.
    Written,
    /// No readable file there — the prior scan wrote its reports
    /// somewhere else (`--out-md`/`--out-sarif`), or never got far enough
    /// to write them at all.
    NotFound,
    /// Present, and deliberately left byte-for-byte as it was.
    Unchanged,
}

/// `--remediate-from`'s report-augmentation outcome, carrying WHERE it
/// looked as well as what happened — "no prior report found" is only
/// actionable if the operator can see which path was checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AugmentedReports {
    pub markdown_path: PathBuf,
    pub markdown: AugmentOutcome,
    pub sarif_path: PathBuf,
    pub sarif: AugmentOutcome,
}

impl std::fmt::Display for AugmentedReports {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let describe = |outcome: AugmentOutcome, path: &Path| match outcome {
            AugmentOutcome::Written => format!("augmented {}", path.display()),
            AugmentOutcome::NotFound => {
                format!("no prior report at {} to augment", path.display())
            }
            AugmentOutcome::Unchanged => format!(
                "left {} unchanged (it already carries a remediation section, or its findings \
                 don't line up with this export)",
                path.display()
            ),
        };
        write!(
            f,
            " Reports: {}; {}.",
            describe(self.markdown, &self.markdown_path),
            describe(self.sarif, &self.sarif_path)
        )
    }
}

/// `--doctor`'s outcome: the rendered static-check table plus, when no
/// required check failed, the live-probe result — matching Python's own
/// `doctor` (`cli.py:29-56`): the probe is skipped entirely (not run and
/// reported as failed) when a blocking static check already means
/// there's nothing meaningful to probe.
#[derive(Debug, Clone, PartialEq)]
pub struct DoctorSummary {
    pub checks_rendered: String,
    pub blocking: usize,
    /// One capability row per configured model (lifecycle, effort tiers,
    /// sampling support, cache minimum), from
    /// `bc_llm_client::capabilities`.
    pub models_rendered: String,
    /// `None` when skipped (a blocking static check failed first).
    pub probe: Option<environment::Check>,
    /// `--cache-probe`'s result; `None` when it was not asked for.
    pub cache_probe: Option<cache_probe::CacheProbeOutcome>,
}

impl DoctorSummary {
    /// `true` when nothing here should fail the process: no blocking
    /// static check, and either the probe wasn't required to run
    /// (impossible given `blocking == 0` implies it ran) or it succeeded,
    /// and a requested cache probe reached a verdict (whichever verdict:
    /// a cache that does not work is a finding, not a broken doctor).
    pub fn healthy(&self) -> bool {
        self.blocking == 0
            && self
                .probe
                .as_ref()
                .is_some_and(|p| p.status == environment::CheckStatus::Ok)
            && self
                .cache_probe
                .as_ref()
                .is_none_or(cache_probe::CacheProbeOutcome::completed)
    }
}

impl std::fmt::Display for DoctorSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{}", self.checks_rendered)?;
        if !self.models_rendered.is_empty() {
            writeln!(f, "{}", self.models_rendered)?;
        }
        let probe_line = if self.blocking > 0 {
            "  [probe] skipped — fix the blocking item(s) above first".to_string()
        } else {
            let probe = self
                .probe
                .as_ref()
                .expect("blocking == 0 always means run_doctor ran the probe");
            let icon = if probe.status == environment::CheckStatus::Ok {
                '\u{2713}'
            } else {
                '\u{2717}'
            };
            format!("  [probe] {icon} {}", probe.detail)
        };
        match &self.cache_probe {
            Some(outcome) => write!(f, "{probe_line}\n{outcome}"),
            None => f.write_str(&probe_line),
        }
    }
}

/// `--setup`'s outcome — the static-check table [`DoctorSummary`] also
/// renders, WITHOUT a live probe: read-only by design (see `args.rs`'s
/// own `--setup` doc comment for why this is scoped down from Python's
/// `vvaharness setup` wizard).
#[derive(Debug, Clone, PartialEq)]
pub struct SetupSummary {
    pub checks_rendered: String,
    pub blocking: usize,
}

impl SetupSummary {
    pub fn healthy(&self) -> bool {
        self.blocking == 0
    }
}

impl std::fmt::Display for SetupSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.checks_rendered)
    }
}

/// `--gc`'s outcome — ported from `cli.py::_gc`'s two branches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GcSummary {
    /// `--gc-run <path>` targeted eviction.
    Evicted {
        path: PathBuf,
        run_id: String,
        /// Whether a `runs` row actually existed for this path.
        /// Meaningless (always `false`) when `dry_run` is set — matching
        /// the Python original's own dry-run branch, which reports
        /// "would evict" unconditionally without checking existence
        /// first; `Display` never reads this field in that case.
        found: bool,
        dry_run: bool,
    },
    /// Age/count-based pruning (`--gc` without `--gc-run`).
    Pruned {
        db_path: PathBuf,
        kept: usize,
        deleted: Vec<String>,
        dry_run: bool,
    },
}

impl std::fmt::Display for GcSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GcSummary::Evicted {
                path,
                run_id,
                dry_run: true,
                ..
            } => write!(
                f,
                "gc: [dry-run] would evict run {run_id} for {}",
                path.display()
            ),
            GcSummary::Evicted {
                path,
                run_id,
                found: true,
                dry_run: false,
            } => write!(f, "gc: evicted run {run_id} for {}", path.display()),
            GcSummary::Evicted {
                path,
                run_id,
                found: false,
                dry_run: false,
            } => write!(
                f,
                "gc: no run found for {} (run_id {run_id})",
                path.display()
            ),
            GcSummary::Pruned {
                db_path,
                kept,
                deleted,
                dry_run,
            } => {
                let tag = if *dry_run { "[dry-run] " } else { "" };
                let verb = if *dry_run { "would delete" } else { "deleted" };
                write!(
                    f,
                    "gc: {} — {tag}kept {kept} run(s), {verb} {}",
                    db_path.display(),
                    deleted.len()
                )?;
                for run_id in deleted {
                    write!(f, "\n    - {run_id}")?;
                }
                Ok(())
            }
        }
    }
}

/// The run's money, condensed to the one line the console prints.
///
/// `usd: None` is not zero. It means the run's tokens had no published
/// rate, and the summary says "unpriced" rather than a figure. A scan
/// against a model this build has no rates for did not cost nothing.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CostSummary {
    pub usd: Option<f64>,
    pub unpriced_tokens: i64,
}

impl CostSummary {
    /// `None` when the report carried no cost figure and no unpriced
    /// count at all, which is a scan whose backend never reported usage.
    /// There is nothing to say about the cost of that run, so the summary
    /// says nothing rather than "0".
    fn from_metrics(metrics: &bc_model::ScanMetrics) -> Option<Self> {
        (metrics.cost_usd.is_some() || metrics.unpriced_tokens.is_some()).then(|| CostSummary {
            usd: metrics.cost_usd,
            unpriced_tokens: metrics.unpriced_tokens.unwrap_or(0),
        })
    }
}

impl std::fmt::Display for CostSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.usd {
            Some(usd) => write!(f, " Cost (USD): {usd:.6}")?,
            None => write!(f, " Cost (USD): unpriced")?,
        }
        match self.unpriced_tokens {
            0 => write!(f, "."),
            n => write!(f, " ({n} token(s) had no published rate)."),
        }
    }
}

/// `--baseline`'s counts, in SARIF's own vocabulary (with `absent`
/// rendered as `resolved`, which is what it means to a human).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BaselineTally {
    pub new: usize,
    pub unchanged: usize,
    pub resolved: usize,
}

/// Phase 3's S11 tally, condensed the same way `RemediationSummary`
/// condenses S10's own outcomes — `Some(_)` on `RemediationSummary` only
/// when validation actually ran (`RemediateOutcome::validations` was
/// non-empty), never a zeroed-out struct standing in for "didn't run".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ValidationTally {
    pub fixed: usize,
    pub partially_fixed: usize,
    pub not_fixed: usize,
    pub unverifiable: usize,
}

/// A `--remediate` run's outcome, condensed to what `ScanSummary`'s
/// `Display` and the caller need — the full per-finding detail lives in
/// `--out-remediation-json`, not here.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct RemediationSummary {
    /// `Some(reason)` when the git-SHA staleness preflight refused to run
    /// remediation at all (see `bc_orchestrator::remediate`) — `processed`/
    /// `failed` are both 0 in that case.
    pub refused: Option<String>,
    pub processed: usize,
    pub failed: usize,
    /// Processed findings whose fix stands: verdict `Fixed`, a non-empty
    /// diff, and not rolled back by an S10 gate or by S11
    /// (`bc_stage_s10::is_kept_fix`). `processed` alone used to be the
    /// only success count, and it includes denials, no-op answers and
    /// rolled-back patches.
    pub fixed: usize,
    /// Processed findings that are not [`Self::fixed`].
    pub not_fixed: usize,
    /// Case-state and validator-decision counts, the shape vvaharness
    /// v1.4.0 writes into its run manifest (`case_rollup.py`). Counts
    /// only, never a title or path from the scanned target.
    pub rollup: bc_validation_scoring::Rollup,
    /// `Some(_)` when S11 validation ran at all this run (`--remediate`'s
    /// `validate_enabled`, batch path only — see `RemediateSettings`),
    /// regardless of how many findings actually got a score; `None` when
    /// it didn't run, so `ScanSummary`'s `Display` can tell "validation
    /// disabled" apart from "ran, found nothing to flag".
    pub validated: Option<ValidationTally>,
    /// How many validation attempts genuinely errored (an `LlmError`, not
    /// "wasn't selected for validation") — see
    /// `bc_orchestrator::RemediateOutcome::validation_failures`. Shown in
    /// `ScanSummary`'s `Display` so a validation failure isn't silently
    /// indistinguishable from a finding that was never selected at all.
    pub validation_failures: usize,
}

/// The process exit code for a run in which nothing S11 validated came
/// out fixed and at least one fix failed validation (vvaharness v1.4.0
/// `case_rollup.py::EXIT_NOT_REMEDIATED`). Distinct from `1`, which means
/// the tool itself failed.
pub const EXIT_NOT_REMEDIATED: u8 = 3;

impl RemediationSummary {
    /// The exit code this remediation outcome calls for, applied only when
    /// remediation actually ran (a plain scan's exit code is unchanged):
    ///
    /// - `1` when an S10 agentic call failed or an S11 validation errored:
    ///   the run is incomplete, which outranks anything it concluded
    ///   (Python's `rem_rc or val_rc`, and `failures` taking first claim
    ///   in `validation/cli/_run.py`);
    /// - [`EXIT_NOT_REMEDIATED`] when validation ran, validated nothing as
    ///   fixed, and failed at least one fix. An all-inconclusive run does
    ///   not trip it: inconclusive is "re-validate", not "failed";
    /// - `0` otherwise, including a refused run (the scan itself finished
    ///   and its output is valid).
    pub fn exit_code(&self) -> u8 {
        if self.failed > 0 || self.validation_failures > 0 {
            return 1;
        }
        let not_remediated = self
            .validated
            .is_some_and(|v| v.fixed == 0 && v.partially_fixed + v.not_fixed > 0);
        if not_remediated {
            EXIT_NOT_REMEDIATED
        } else {
            0
        }
    }
}

/// One case per processed finding: its validator decision when S11
/// scored it, else remediated (a patch stands) or declined (none does).
/// An S10 call that errored produced no case and is counted in `failed`
/// instead, as Python writes no case file for it.
fn remediation_rollup(
    outcome: &bc_orchestrator::RemediateOutcome,
) -> bc_validation_scoring::Rollup {
    use bc_validation_scoring::{verdict_state, CaseState};
    let cases = outcome.outcomes.iter().enumerate().filter_map(|(i, o)| {
        let bc_stage_s10::RemediationOutcome::Processed(record) = o else {
            return None;
        };
        let decision = outcome
            .validations
            .get(i)
            .and_then(Option::as_ref)
            .map(|s| s.decision());
        let state = match decision {
            Some(d) => verdict_state(d),
            None if record.diff.as_deref().is_some_and(|d| !d.trim().is_empty())
                && !bc_stage_s10::was_reverted(record) =>
            {
                CaseState::Remediated
            }
            None => CaseState::Declined,
        };
        Some((state, decision))
    });
    bc_validation_scoring::Rollup::tally(cases)
}

#[cfg(test)]
mod remediation_outcome_tests;

impl From<&bc_orchestrator::RemediateOutcome> for RemediationSummary {
    fn from(outcome: &bc_orchestrator::RemediateOutcome) -> Self {
        let counts = bc_stage_s10::RemediationCounts::from_outcomes(&outcome.outcomes);
        let processed = counts.fixed + counts.not_fixed;
        let validated = (!outcome.validations.is_empty()).then(|| {
            let mut tally = ValidationTally::default();
            for score in outcome.validations.iter().flatten() {
                match score.fix_status {
                    bc_validation_scoring::FixVerdict::Fixed => tally.fixed += 1,
                    bc_validation_scoring::FixVerdict::PartiallyFixed => tally.partially_fixed += 1,
                    bc_validation_scoring::FixVerdict::NotFixed => tally.not_fixed += 1,
                    bc_validation_scoring::FixVerdict::Unverifiable => tally.unverifiable += 1,
                }
            }
            tally
        });
        RemediationSummary {
            refused: outcome.refused.clone(),
            processed,
            failed: counts.failed,
            fixed: counts.fixed,
            not_fixed: counts.not_fixed,
            rollup: remediation_rollup(outcome),
            validated,
            validation_failures: outcome.validation_failures,
        }
    }
}

impl std::fmt::Display for ScanSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(result) = &self.provider_publication {
            if self.markdown_path.is_none() && self.findings_json_path.is_none() {
                return writeln!(f, "{result}");
            }
            write!(f, "{result} ")?;
        }
        if let Some(gc) = &self.gc {
            // `--gc`/`--gc-run` mode: none of the scan-shaped fields
            // below were ever populated (see the struct's own field
            // doc comment) — render only the gc outcome and return.
            return write!(f, "{gc}");
        }
        if let Some(estimate) = &self.estimate {
            return write!(f, "{estimate}");
        }
        if let Some(doctor) = &self.doctor {
            return write!(f, "{doctor}");
        }
        if let Some(setup) = &self.setup {
            return write!(f, "{setup}");
        }
        if let Some(b) = &self.batch {
            return write!(
                f,
                "Batch scan complete: {}/{} succeeded, {} failed. Summary: {}",
                b.completed,
                b.total,
                b.failed,
                b.summary_path.display()
            );
        }
        match self.stopped_after {
            Some(stop) => write!(f, "Scan stopped after {stop:?}.")?,
            None => write!(f, "Scan complete: {} finding(s).", self.findings)?,
        }
        // Beside the findings count rather than after the artifact paths:
        // it is a fact about the run, not about a file.
        if let Some(cost) = &self.cost {
            write!(f, "{cost}")?;
        }
        if let Some(p) = &self.markdown_path {
            write!(f, " Markdown: {}", p.display())?;
        }
        if let Some(p) = &self.sarif_path {
            write!(f, " SARIF: {}", p.display())?;
        }
        if let Some(p) = &self.csv_path {
            write!(f, " CSV: {}", p.display())?;
        }
        if let Some(p) = &self.findings_json_path {
            write!(f, " Findings JSON: {}", p.display())?;
        }
        match &self.github_sync {
            Some(Ok(s)) => write!(f, " GitHub: {} created, {} updated.", s.created, s.updated)?,
            Some(Err(e)) => write!(f, " GitHub sync failed: {e}")?,
            None => {}
        }
        match &self.remediation {
            Some(r) if r.refused.is_some() => {
                write!(f, " Remediation refused: {}", r.refused.as_deref().unwrap())?
            }
            Some(r) => {
                let msg = format!(
                    " Remediation: {} processed, {} failed. Outcome: {} fixed, {} not fixed.",
                    r.processed, r.failed, r.fixed, r.not_fixed
                );
                write!(f, "{msg}")?;
                r.validated.iter().try_for_each(|v| {
                    write!(
                        f,
                        " Validation: {} fixed, {} partially fixed, {} not fixed, {} unverifiable.",
                        v.fixed, v.partially_fixed, v.not_fixed, v.unverifiable
                    )
                })?;
                if r.validation_failures > 0 {
                    write!(f, " ({} validation error(s).)", r.validation_failures)?;
                }
                if r.exit_code() == EXIT_NOT_REMEDIATED {
                    let code = EXIT_NOT_REMEDIATED;
                    write!(f, " Nothing validated as fixed (exit code {code}).")?;
                }
            }
            None => {}
        }
        if let Some(a) = &self.augmented {
            write!(f, "{a}")?;
        }
        if let Some(b) = &self.baseline {
            write!(
                f,
                " Baseline: {} new, {} unchanged, {} resolved.",
                b.new, b.unchanged, b.resolved
            )?;
        }
        if let Some(p) = &self.remediation_patch {
            // Only ever set in worktree mode, where nothing was written
            // to the user's checkout — so this path is the ONLY way to
            // get the fix, and burying it would make the isolated default
            // look like remediation silently did nothing.
            write!(
                f,
                " Patch (worktree-isolated, apply with `git apply {}`): {}",
                p.display(),
                p.display()
            )?;
        }
        Ok(())
    }
}

/// Drives `-i`/`--interactive` remediation: the same staleness preflight
/// as the batch `--top` path ([`bc_orchestrator::remediate`]), but
/// findings are chosen live by the user through
/// [`bc_interactive::run_interactive`], rather than walked
/// automatically. Reuses [`bc_stage_s10::select_top_by_cvss`] for the
/// SAME CVSS-ranked-and-capped list an explicit `--top N` would produce
/// in batch mode (an unset `config.top` — the common case, since
/// `build_remediate_settings` already zeroes out any profile default for
/// interactive mode — skips straight to every finding, in report order,
/// no ranking needed).
///
/// `term` is dependency-injected (a real `bc_interactive::RealTerminal`
/// at the actual call site in [`run`], a scripted fake in tests) —
/// matching this crate's own `llm`/`tools` pattern — specifically so
/// this function is testable without ever touching a real terminal:
/// `bc_interactive::run_interactive` itself already fully proves the
/// picker's own logic against a fake, so this function only needs to
/// prove IT wires the staleness check, CVSS selection, and checkpoint/
/// run_id plumbing correctly.
#[allow(clippy::too_many_arguments)]
pub async fn remediate_interactively(
    llm: Arc<dyn LlmClient>,
    tools: Arc<dyn ToolExecutor>,
    repo: &Path,
    report: &bc_model::FinalReport,
    config: &bc_orchestrator::RemediateConfig,
    policy: Option<&bc_stage_s10::PolicyContext>,
    checkpoint: Option<Arc<dyn bc_checkpoint::CheckpointStore>>,
    validate: Option<bc_interactive::ValidateContext<'_>>,
    term: &mut dyn bc_interactive::Terminal,
) -> bc_orchestrator::RemediateOutcome {
    if let Some(reason) = bc_orchestrator::stale_refusal(report, repo, config.force) {
        return bc_orchestrator::RemediateOutcome {
            refused: Some(reason),
            outcomes: Vec::new(),
            validations: Vec::new(),
            validation_failures: 0,
        };
    }

    let top = if config.top.is_some() {
        bc_stage_s10::resolve_top(config.top, config.top_default)
    } else {
        None
    };
    let positions = bc_stage_s10::select_top_by_cvss(
        report.findings.len(),
        top,
        |i| report.findings[i].finding.cvss_score,
        |i| bc_orchestrator::severity_str(report.findings[i].severity),
    );
    let findings: Vec<bc_interactive::PickerFinding> = positions
        .into_iter()
        .map(|pos| bc_interactive::PickerFinding {
            finding_index: (pos + 1) as i64,
            finding: report.findings[pos].clone(),
        })
        .collect();

    let run_id = bc_checkpoint::run_id_for(repo);
    let ctx = bc_interactive::RemediationContext {
        client: llm.as_ref(),
        tools: tools.as_ref(),
        repo,
        config: &config.step10,
        policy,
        checkpoint: checkpoint.as_deref(),
        run_id: &run_id,
        validate,
    };
    let (outcomes, validations, validation_failures) =
        bc_interactive::run_interactive(&ctx, &findings, term).await;
    bc_orchestrator::redact_remediate_outcome(bc_orchestrator::RemediateOutcome {
        refused: None,
        outcomes,
        validations,
        validation_failures,
    })
}

/// `--remediate-from`'s entire job: rebuild a `FinalReport` from a prior
/// `--out-findings-json` export and remediate it, without re-running a
/// single pipeline stage.
///
/// The export is deliberately the input rather than a rendered report:
/// the Python original's standalone `remediate` command re-parses its own
/// Markdown, which this port never does (see `bc-stage-s10`'s crate doc
/// comment) — a typed export round-trips exactly.
///
/// **Severity is reconstructed, not stored.** The export carries bare
/// `Finding`s, and `--top N` ranks by CVSS with a severity-band fallback,
/// so a wrong severity here would remediate the wrong findings. It is
/// therefore rebuilt with `bc_stage_s8::final_severity` — the same
/// function S8 itself used when it assigned the severity in the first
/// place, reading the same `vsvs_rating`/`cvss_rating` bands the export
/// carries. `Severity::Info` is its last-resort argument (S8 passes the
/// chaining model's own qualitative label there, which an export does not
/// preserve); it only applies to a finding with no CVSS band at all,
/// which is also a finding with no CVSS score to rank by.
///
/// The staleness refusal is not re-implemented: `git_sha` is set from the
/// export's `commit_sha`, so `bc_orchestrator::remediate`'s existing
/// check compares it against the repository's current HEAD exactly as it
/// does after a live scan, and `--force` overrides it the same way.
///
/// **The prior run's reports are augmented in place** when they are
/// where a scan would have left them — see [`augment_prior_reports`] for
/// what is written and why it is stamped onto the existing documents
/// rather than rebuilt from the (deliberately thin) reconstructed
/// report. Nothing is created that wasn't already there.
pub async fn remediate_from(
    cli: &Cli,
    path: &Path,
    llm: Arc<dyn LlmClient>,
) -> Result<ScanSummary, String> {
    remediate_from_with_cancel(cli, path, llm, None).await
}

/// [`remediate_from`] under the run's Ctrl-C cancellation: once `cancel`
/// trips, no remediation, target-test or validation session starts, and
/// the one under way has its next model call refused (see
/// `bc_orchestrator::RemediateTelemetry::cancel`).
async fn remediate_from_with_cancel(
    cli: &Cli,
    path: &Path,
    llm: Arc<dyn LlmClient>,
    cancel: Option<bc_pipeline_core::CancelTokenRef>,
) -> Result<ScanSummary, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read findings export {}: {e}", path.display()))?;
    let export: FindingsExport = serde_json::from_str(&text)
        .map_err(|e| format!("{} is not a findings export: {e}", path.display()))?;

    let repo = repo_path(cli);
    let report = bc_model::FinalReport {
        provider_ledger: Default::default(),
        repo_root: repo.to_string_lossy().to_string(),
        repo_name: cli.repo_name.clone(),
        git_sha: Some(export.commit_sha),
        findings: export
            .findings
            .into_iter()
            .map(|finding| bc_model::RankedFinding {
                severity: bc_stage_s8::final_severity(&finding, bc_model::Severity::Info),
                finding,
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
    };

    let mut run = build_remediate_run(cli, repo)?;
    // `--diff-scope` used to be accepted here and silently ignored: this
    // mode returns from `main_impl` long before the scan path's own
    // `resolve_diff_scope` call, so a prior-report remediation asked to
    // stay inside a pull request would happily edit anything the export
    // named — and a findings export written by an earlier FULL scan is
    // precisely where out-of-diff-scope candidates come from. Resolve the
    // boundary here too, with the same hard credential requirement and the
    // same fail-hard-on-fetch-error posture the scan path has.
    run.settings.config.step10.diff_scope =
        resolve_diff_scope(cli.diff_scope, build_github_client(cli)?.as_ref())
            .await?
            .boundary();
    let out_json = run.out_json.clone();
    // The read-only executor S11 uses for an in-place run; the worktree
    // path builds its own (see `dispatch_remediation`).
    let read_tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new(repo.to_path_buf()));
    let (result, remediation_patch) = dispatch_remediation(
        llm,
        read_tools,
        repo,
        &report,
        run,
        bc_orchestrator::RemediateTelemetry {
            cancel,
            ..Default::default()
        },
    )
    .await;
    write_remediation_json(out_json.as_deref(), &result).map_err(stringify)?;

    // The prior run's own reports, augmented in place where they exist —
    // `--out-md`/`--out-sarif`/`--out-dir` when given, else the repo's
    // `security-scan/` default, exactly where a plain scan would have
    // put them. Resolved, never CREATED: this mode runs no scan, so
    // `OutputPaths::ensure_dirs` is deliberately not called and nothing
    // appears that wasn't already there. See `augment_prior_reports` for
    // why this reads and stamps rather than rebuilding.
    let paths = resolve_output_paths(cli);
    let augmented = augment_prior_reports(&paths.markdown, &paths.sarif, &report, &result)
        .map_err(stringify)?;

    Ok(ScanSummary {
        provider_publication: None,
        findings: report.findings.len(),
        remediation: Some(RemediationSummary::from(&result)),
        remediation_patch,
        augmented: Some(augmented),
        // Deliberately still `None`: these mean "this run PRODUCED these
        // artifacts", and this run produced no scan. What it did to the
        // prior run's reports is reported through `augmented` above.
        markdown_path: None,
        sarif_path: None,
        csv_path: None,
        findings_json_path: None,
        stopped_after: None,
        github_sync: None,
        gc: None,
        cost: None,
        batch: None,
        estimate: None,
        doctor: None,
        setup: None,
        baseline: None,
    })
}

/// The findings evidence target-test generation is given: exactly the
/// findings S10 is about to remediate, not every finding in the report.
///
/// [`bc_orchestrator::remediate`] picks its work with this same `--top N`
/// CVSS selection, so passing the whole report meant a run asking for two
/// fixes handed the generator every finding in the scan. That is a bigger
/// prompt, a bigger bill, and tests proposed for code this run will never
/// touch.
fn target_test_findings(
    report: &bc_model::FinalReport,
    config: &bc_orchestrator::RemediateConfig,
) -> String {
    let positions = bc_stage_s10::select_top_by_cvss(
        report.findings.len(),
        bc_stage_s10::resolve_top(config.top, config.top_default),
        |i| report.findings[i].finding.cvss_score,
        |i| bc_orchestrator::severity_str(report.findings[i].severity),
    );
    let selected: Vec<&bc_model::RankedFinding> =
        positions.iter().map(|&pos| &report.findings[pos]).collect();
    serde_json::to_string(&selected)
        .unwrap_or_else(|_| "Findings unavailable; record this coverage gap".into())
}

/// Runs S10 (and, when enabled, S11) for one already-built
/// `FinalReport`, then exports the patch and winds up any isolated
/// worktree. Returns the outcome and the exported patch path.
///
/// Shared by the post-scan `--remediate` path and the standalone
/// `--remediate-from` path, which differ only in where the report came
/// from — not in how remediation runs, which is the part with the
/// worktree/executor/validation invariants worth having in one place.
///
/// `scan_read_tools` is the read-only executor S11 uses for an IN-PLACE
/// run. In worktree mode it is replaced with one rooted at the throwaway
/// checkout: the write-capable executor is already rooted there, the
/// staleness preflight reads ITS `HEAD` (identical — the worktree is
/// detached at the parent's commit), and S11 has to follow or the panel
/// would grade the UNPATCHED files in the user's tree.
async fn dispatch_remediation(
    llm: Arc<dyn LlmClient>,
    scan_read_tools: Arc<dyn ToolExecutor>,
    repo_root: &Path,
    report: &bc_model::FinalReport,
    run: RemediateRun,
    // The scan's event sink and pricing, so S10/S11 report and are metered
    // as stages (see `bc_orchestrator::remediate_observed`).
    telemetry: bc_orchestrator::RemediateTelemetry,
) -> (bc_orchestrator::RemediateOutcome, Option<PathBuf>) {
    // Every model session this dispatch starts (target-test and API-spec
    // generation included, which run before S10) is refused once the run
    // is canceled.
    let llm = bc_orchestrator::cancel_aware_client(llm, telemetry.cancel.clone());
    let RemediateRun {
        mut settings,
        tools: write_tools,
        mut worktree,
        mut delivery,
        checkpoint,
        ..
    } = run;
    let (rem_root, validate_tools) =
        if let Some(snapshot) = delivery.as_ref().and_then(|d| d.snapshot.as_ref()) {
            (
                snapshot.path().to_path_buf(),
                Arc::new(SandboxTools::new(snapshot.path().to_path_buf())) as Arc<dyn ToolExecutor>,
            )
        } else {
            match &worktree {
                Some(w) => (
                    w.path.clone(),
                    Arc::new(SandboxTools::new(w.path.clone())) as Arc<dyn ToolExecutor>,
                ),
                None => (repo_root.to_path_buf(), scan_read_tools),
            }
        };
    if delivery.is_some()
        && (report.degraded
            || report.metrics.as_ref().is_some_and(|m| {
                !m.budget_stop.is_empty()
                    || m.chunks_failed > 0
                    || m.errors_by_stage.values().any(|n| *n > 0)
            }))
    {
        return (
            bc_orchestrator::RemediateOutcome {
                refused: Some("Delivery requires a completed full scan".into()),
                outcomes: Vec::new(),
                validations: Vec::new(),
                validation_failures: 0,
            },
            None,
        );
    }
    let mut assurance = None;
    if let Some(test_config) = &settings.target_tests {
        let refusal = if worktree.is_none()
            && delivery
                .as_ref()
                .and_then(|d| d.snapshot.as_ref())
                .is_none()
        {
            Some(
                "Target testing requires an isolated worktree; no in-place fallback is allowed"
                    .to_string(),
            )
        } else if report.degraded
            || report.metrics.as_ref().is_some_and(|m| {
                !m.budget_stop.is_empty()
                    || m.chunks_failed > 0
                    || m.errors_by_stage.values().any(|n| *n > 0)
            })
        {
            Some("Target testing requires a completed full scan; this report records degraded analysis or an exhausted budget".to_string())
        } else {
            None
        };
        if let Some(reason) = refusal {
            return (
                bc_orchestrator::RemediateOutcome {
                    refused: Some(reason),
                    outcomes: Vec::new(),
                    validations: Vec::new(),
                    validation_failures: 0,
                },
                None,
            );
        }
        let findings = target_test_findings(report, &settings.config);
        match target_testing::prepare(
            &rem_root,
            test_config,
            &settings.config.step10.model,
            llm.as_ref(),
            &findings,
        )
        .await
        {
            Ok(mut prepared) => {
                prepared.scan_revision = report.git_sha.clone();
                settings.config.step10.target_test_context =
                    Some(target_testing::remediation_context(&prepared));
                assurance = Some(prepared);
            }
            Err(e) => {
                return (
                    bc_orchestrator::RemediateOutcome {
                        refused: Some(format!("Target test preparation blocked: {e}")),
                        outcomes: Vec::new(),
                        validations: Vec::new(),
                        validation_failures: 0,
                    },
                    None,
                )
            }
        }
    }
    if !settings.validate_enabled {
        eprintln!(
            "  [s11] disabled (--no-validate or step_validate.enabled: false); S10 patches \
             are kept without an independent validation pass"
        );
    }
    let mut result = if settings.interactive {
        let mut term = bc_interactive::RealTerminal;
        let validate = settings
            .validate_enabled
            .then(|| bc_interactive::ValidateContext {
                step11: &settings.step11,
                tools: validate_tools.as_ref(),
            });
        remediate_interactively(
            llm,
            write_tools,
            &rem_root,
            report,
            &settings.config,
            settings.policy.as_ref(),
            checkpoint,
            validate,
            &mut term,
        )
        .await
    } else {
        let validate = settings
            .validate_enabled
            .then(|| bc_orchestrator::ValidateConfig {
                step11: &settings.step11,
                tools: validate_tools.as_ref(),
            });
        bc_orchestrator::remediate_observed(
            llm,
            write_tools,
            &rem_root,
            report,
            &settings.config,
            settings.policy.as_ref(),
            checkpoint,
            validate,
            &telemetry,
        )
        .await
    };
    // Export BEFORE the checkout is removed — `finish` does both, in that
    // order, and is the only thing that unregisters the worktree from the
    // parent repo's `.git/worktrees`.
    let mut block_export = false;
    if let (Some(test_config), Some(assurance)) = (&settings.target_tests, &mut assurance) {
        if result.validation_failures > 0 {
            assurance.export_blocked = true;
            assurance.remaining_gaps.push("Independent patch review failed; passing tests cannot replace the missing review. Export withheld.".into());
        }
        // No target-test process starts after a cancellation.
        if let Some(reason) = bc_pipeline_core::canceled(telemetry.cancel.as_ref()) {
            assurance.export_blocked = true;
            assurance.remaining_gaps.push(format!(
                "Target tests were not run: {reason}. Export withheld."
            ));
        } else {
            target_testing::finish(&rem_root, test_config, assurance).await;
        }
        block_export = assurance.export_blocked;
        let artifact = bc_pathjail::confine(repo_root, "security-scan/target-tests.json");
        let saved = artifact
            .as_ref()
            .ok_or_else(|| "Target-test artifact path escapes repository".to_string())
            .and_then(|path| target_testing::write_artifact(path, assurance));
        if let Err(e) = saved {
            block_export = true;
            result.refused = Some(format!(
                "Target-test evidence could not be saved; patch export withheld: {e}"
            ));
        }
        eprintln!(
            "  [target-tests] evidence: {} (generation: {}, review: {}; execution results: {}; environment blocked: {})",
            artifact
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "blocked path".into()),
            assurance.generation_state,
            assurance.review_state,
            assurance.execution.len(),
            assurance.environment_blocked
        );
    }
    if block_export {
        // JSON exports and later --post-fixes-from must obey the same gate
        // as the combined patch file.
        for outcome in &mut result.outcomes {
            if let bc_stage_s10::RemediationOutcome::Processed(record) = outcome {
                record.diff = None;
                record.verdict.verdict = bc_stage_s10::Verdict::NeedsReview;
                record.final_verdict =
                    Some("Needs Review: target-test validation blocked export".into());
            }
        }
        result.validations.clear();
        result.refused.get_or_insert_with(|| "Target-test validation blocked patch export; inspect security-scan/target-tests.json".into());
    }
    if let Some(state) = delivery.as_mut() {
        let rejected_review = result
            .validations
            .iter()
            .flatten()
            .any(|score| score.fix_status != bc_validation_scoring::FixVerdict::Fixed);
        let failed_fix = result.outcomes.iter().any(|outcome| match outcome {
            bc_stage_s10::RemediationOutcome::Processed(record) => {
                record.verdict.verdict == bc_stage_s10::Verdict::NeedsReview
            }
            _ => true,
        });
        if bc_pipeline_core::canceled(telemetry.cancel.as_ref()).is_some()
            || block_export
            || result.refused.is_some()
            || result.validation_failures > 0
            || rejected_review
            || failed_fix
        {
            result.refused.get_or_insert_with(|| {
                "Delivery withheld: remediation or validation needs review".into()
            });
            return (result, None);
        }
        match delivery::deliver(state, &rem_root).await {
            Ok(receipt) => {
                eprintln!(
                    "  [delivery] {} {}: {}",
                    receipt.mode, receipt.status, receipt.destination
                );
                let saved = bc_pathjail::confine(repo_root, "security-scan/delivery.json")
                    .ok_or_else(|| "Delivery receipt path escapes repository".to_string())
                    .and_then(|path| {
                        if let Some(parent) = path.parent() {
                            std::fs::create_dir_all(parent).map_err(stringify)?;
                        }
                        let mut json = serde_json::to_value(&receipt).map_err(stringify)?;
                        json["scan_revision"] = serde_json::json!(report.git_sha);
                        json["validation"] = serde_json::json!({
                            "model_review_enabled": settings.validate_enabled,
                            "model_review_results": result.validations.iter().flatten().map(|s| format!("{:?}", s.fix_status)).collect::<Vec<_>>(),
                            "target_test_status": assurance.as_ref().map(|a| &a.assurance_status),
                            "target_command_results": assurance.as_ref().map_or(0, |a| a.execution.len()),
                            "note": "Delivery is not proof of security or functional correctness; inspect scoped validation evidence and remaining gaps."
                        });
                        std::fs::write(
                            path,
                            serde_json::to_vec_pretty(&bc_redact::redact_tree(&json))
                                .map_err(stringify)?,
                        )
                        .map_err(stringify)
                    });
                if let Err(e) = saved {
                    result.refused = Some(format!("Delivery completed but receipt could not be saved: {e}; inspect the destination before retrying"));
                }
            }
            Err(e) => {
                if let Some(snapshot) = state.snapshot.take() {
                    eprintln!(
                        "  [delivery] failed; updated snapshot retained at {}",
                        snapshot.keep().display()
                    );
                }
                if let Some(w) = worktree.as_mut() {
                    w.keep = true;
                    eprintln!(
                        "  [delivery] failed; worktree retained at {}",
                        w.path.display()
                    );
                }
                result.refused = Some(format!("Delivery failed: {e}"));
            }
        }
        return (result, None);
    }
    let patch = if block_export {
        None
    } else {
        worktree.as_mut().and_then(worktree::finish)
    };
    (result, patch)
}

/// Run a scan with already-constructed `llm`/`tools`/`config`/`input`
/// (dependency-injected so this is directly unit-testable with fakes —
/// see the tests below — without needing a real gateway, and without
/// coupling to `build_scan_config`'s production defaults — e.g. a test
/// can hand `Step1Config` a zero retry backoff instead of the shipped
/// 10-second default).
#[allow(clippy::too_many_arguments)]
pub async fn run(
    input: ScanInput,
    config: ScanConfig,
    stop_after: Option<StopAfter>,
    paths: &OutputPaths,
    llm: Arc<dyn LlmClient>,
    tools: Arc<dyn ToolExecutor>,
    // Where to post PR comments, or `None` to post none. See
    // `pr_comment_target`, which is what every production caller builds
    // this from.
    github: Option<bc_github::GithubClient>,
    remediate: Option<RemediateRun>,
    baseline: Option<BaselineRun>,
) -> Result<ScanSummary, String> {
    run_with_publication(
        input, config, stop_after, paths, llm, tools, github, remediate, baseline, None,
    )
    .await
}

/// Run a scan and publish eligible provider assessments after S9 has persisted its artifacts.
#[allow(clippy::too_many_arguments)]
pub async fn run_with_publication(
    input: ScanInput,
    config: ScanConfig,
    stop_after: Option<StopAfter>,
    paths: &OutputPaths,
    llm: Arc<dyn LlmClient>,
    tools: Arc<dyn ToolExecutor>,
    github: Option<bc_github::GithubClient>,
    remediate: Option<RemediateRun>,
    baseline: Option<BaselineRun>,
    publication: Option<provider_publish::automatic::Run>,
) -> Result<ScanSummary, String> {
    if publication.is_some()
        && (input.diff_scope_active
            || config.resume
            || stop_after.is_some_and(|stop| stop != StopAfter::S9))
    {
        return Err("Automatic provider publication requires a full scan that reaches S9 without --resume or --diff-scope".into());
    }
    // FIRST, before a single token is spent: see `OutputPaths::
    // ensure_dirs`. Here rather than in `main_impl` so the `--repo-file`
    // batch path, which reaches `run` by its own route, gets the same
    // guarantee without repeating the call.
    if remediate
        .as_ref()
        .is_some_and(|r| r.settings.target_tests.is_some() || r.delivery.is_some())
        && (stop_after.is_some() || input.diff_scope_active)
    {
        return Err("Target testing requires a full scan plus remediation".into());
    }
    paths.ensure_dirs()?;
    let md_path = paths.markdown.as_path();
    let sarif_path = paths.sarif.as_path();
    let repo_root = input.repo_root.clone();
    let mut input = input;
    let scan_snapshot = remediate.as_ref().and_then(|r| {
        let delivery = r.delivery.as_ref()?;
        delivery
            .snapshot
            .as_ref()
            .map(|s| s.path().to_path_buf())
            .or_else(|| r.worktree.as_ref().map(|w| w.path.clone()))
    });
    let tools = if let Some(root) = scan_snapshot {
        input.repo_root = root.clone();
        Arc::new(SandboxTools::new(root)) as Arc<dyn ToolExecutor>
    } else {
        tools
    };

    // Cloned before `tools` moves into `run_scan` below — S11 validation
    // (see the remediate dispatch further down) needs its OWN read-only
    // executor reference, separate from S10's write-capable one
    // (`r.tools`), matching `bc_stage_s11::validate_finding`'s own
    // read-only contract. `Arc<dyn ToolExecutor>` clones cheaply
    // regardless of the concrete type behind it.
    let validate_tools = tools.clone();
    // Captured before `config` moves into `run_scan` below — needed again
    // afterward if validation runs, to re-build SARIF via
    // `bc_sarif::build_sarif_with_validations` (see the remediate
    // dispatch further down).
    let tool_version = config.tool_version.clone();
    // Captured before `config` moves into `run_scan`: the baseline's
    // fuzzy fallback reuses S7's own line tolerance, so "within N lines"
    // means the same thing across runs as it does within one.
    let line_tolerance = config.step7.line_tolerance;
    // Captured before `config` moves into `run_scan`: remediation reports
    // S10/S11 on the scan's own event stream, priced the same way.
    let remediation_telemetry = bc_orchestrator::RemediateTelemetry {
        progress: config.progress.clone(),
        pricing: config.pricing.clone(),
        cancel: config.cancel.clone(),
    };
    let outcome = bc_orchestrator::run_scan(llm.clone(), tools, input, config, stop_after)
        .await
        .map_err(stringify)?;
    // A canceled run keeps its local artifacts (the partial report says it
    // is partial) but takes no action outside this machine: nothing is
    // published, posted or remediated from a report the operator stopped.
    let canceled = bc_pipeline_core::canceled(remediation_telemetry.cancel.as_ref());
    let (publication, github, remediate) = if canceled.is_some() {
        (None, None, None)
    } else {
        (publication, github, remediate)
    };

    write_outputs(&outcome, md_path, sarif_path, &paths.csv).map_err(stringify)?;
    if let (Some(path), Some(plan)) = (
        &paths.provider_writeback_plan,
        &outcome.provider_writeback_plan,
    ) {
        std::fs::write(path, plan).map_err(stringify)?;
    }
    let published_report = if outcome.stopped_after == Some(StopAfter::S8) {
        None
    } else {
        outcome.report.as_ref()
    };
    let findings_json_written =
        write_findings_json(&paths.findings_json, published_report).map_err(stringify)?;

    let provider_publication = match (publication, published_report) {
        (Some(publication), Some(report)) if outcome.markdown.is_some() => {
            let plan = paths.provider_writeback_plan.as_ref().ok_or_else(|| {
                "Automatic publication requires a provider plan output path".to_string()
            })?;
            Some(
                publication
                    .publish(
                        report,
                        &plan.with_file_name("provider-writeback-results.json"),
                    )
                    .await?,
            )
        }
        _ => None,
    };

    let github_sync =
        sync_github(github.as_ref(), published_report, Some(repo_root.as_path())).await;

    let mut remediation_patch = None;
    let remediation = match (remediate, &outcome.report) {
        (Some(r), Some(report)) if outcome.stopped_after.is_none() => {
            let delivery_requested = r.delivery.is_some();
            let target_test_requested = r.settings.target_tests.is_some();
            let out_json = r.out_json.clone();
            let (result, patch) = dispatch_remediation(
                llm,
                validate_tools,
                &repo_root,
                report,
                r,
                remediation_telemetry.clone(),
            )
            .await;
            remediation_patch = patch;
            write_remediation_json(out_json.as_deref(), &result).map_err(stringify)?;
            if delivery_requested {
                if let Some(reason) = &result.refused {
                    return Err(reason.clone());
                }
            }
            augment_report_outputs(
                md_path,
                sarif_path,
                report,
                &tool_version,
                outcome.markdown.as_deref(),
                outcome.sarif.is_some(),
                &result,
            )
            .map_err(stringify)?;
            if target_test_requested && result.refused.is_none() {
                target_testing::annotate_outputs(&repo_root, md_path, sarif_path)?;
            }
            Some(RemediationSummary::from(&result))
        }
        _ => None,
    };
    // A full scan that did not remediate still closes S10/S11, as
    // Python's `_sp_done("s10", outcome="disabled")` does; a canceled one
    // closes them as skipped by the cancellation.
    let progress = remediation_telemetry.progress.as_ref();
    if let Some(reason) = &canceled {
        bc_orchestrator::remediation_canceled(progress, reason);
    } else if remediation.is_none() && outcome.report.is_some() && outcome.stopped_after.is_none() {
        bc_orchestrator::remediation_not_requested(progress);
    }
    drop(remediation_telemetry);

    // LAST, deliberately: `augment_report_outputs` above rebuilds
    // `report.sarif` from scratch and rewrites `report.md`, so anything
    // stamped on before remediation would be overwritten. Reading the
    // finished files back and annotating them in place is one extra pass
    // for a guarantee that holds no matter which of the earlier passes
    // ran.
    let baseline_tally = match (&baseline, published_report) {
        (Some(b), Some(report)) => Some(
            apply_baseline_outputs(
                md_path,
                sarif_path,
                report,
                b,
                &repo_root,
                line_tolerance,
                outcome.sarif.is_some(),
            )
            .map_err(stringify)?,
        ),
        _ => None,
    };

    Ok(ScanSummary {
        provider_publication,
        gc: None,
        // Straight off the report's own metrics, so the console line and
        // `report.md`'s `## Scan Metrics` can never disagree about what
        // the run cost.
        cost: outcome
            .report
            .as_ref()
            .and_then(|r| r.metrics.as_ref())
            .and_then(CostSummary::from_metrics),
        baseline: baseline_tally,
        findings: outcome.report.as_ref().map_or(0, |r| r.findings.len()),
        markdown_path: outcome.markdown.as_ref().map(|_| paths.markdown.clone()),
        sarif_path: outcome.sarif.as_ref().map(|_| paths.sarif.clone()),
        csv_path: published_report.map(|_| paths.csv.clone()),
        findings_json_path: findings_json_written.then(|| paths.findings_json.clone()),
        stopped_after: outcome.stopped_after,
        github_sync,
        remediation,
        remediation_patch,
        batch: None,
        estimate: None,
        doctor: None,
        setup: None,
        augmented: None,
    })
}

/// A loaded `--baseline`, plus the path it came from (echoed into
/// `report.md` so the comparison says what it was against).
pub struct BaselineRun {
    pub path: PathBuf,
    pub baseline: baseline::Baseline,
}

/// Appends `## Baseline Comparison` to `report.md` and stamps
/// `baselineState` onto `report.sarif`, reading both back off disk so
/// this is correct regardless of whether remediation already rewrote
/// them. Returns the counts for the run summary.
///
/// An unreadable/absent `report.md` is skipped rather than treated as an
/// error — a `--stop-after` run that never produced one still gets its
/// counts and its SARIF annotation.
#[allow(clippy::too_many_arguments)]
fn apply_baseline_outputs(
    md_path: &Path,
    sarif_path: &Path,
    report: &bc_model::FinalReport,
    run: &BaselineRun,
    repo_root: &Path,
    line_tolerance: i64,
    sarif_was_written: bool,
) -> std::io::Result<BaselineTally> {
    let comparison = baseline::compare(&report.findings, &run.baseline, repo_root, line_tolerance);
    if let Ok(markdown) = std::fs::read_to_string(md_path) {
        let view = baseline::view(&comparison, &report.findings, &run.path);
        create_parent_dir(md_path)?;
        std::fs::write(
            md_path,
            bc_report_md::append_baseline_section(&markdown, &view),
        )?;
    }
    if sarif_was_written {
        if let Ok(sarif) = std::fs::read_to_string(sarif_path) {
            let annotated = baseline::annotate_sarif(&sarif, &comparison);
            create_parent_dir(sarif_path)?;
            std::fs::write(sarif_path, annotated)?;
        }
    }
    Ok(BaselineTally {
        new: comparison.new_count(),
        unchanged: comparison.unchanged_count(),
        resolved: comparison.resolved_count(),
    })
}

/// Everything [`run`] needs to attempt remediation after the scan
/// completes — bundled so `run`'s own parameter list doesn't grow
/// further; built by [`main_impl`] only when `--remediate` was passed.
pub struct RemediateRun {
    pub delivery: Option<delivery::DeliveryState>,
    pub settings: RemediateSettings,
    /// MUST be write-capable (`SandboxTools::new_with_write`) — a
    /// deliberately separate executor instance from the scan's own
    /// read-only `tools`. In worktree mode it is rooted at
    /// [`RemediateRun::worktree`]'s checkout, not at `--repo`.
    pub tools: Arc<dyn ToolExecutor>,
    /// `Some(_)` when remediation runs against a throwaway detached
    /// checkout instead of the user's own files (the default for a git
    /// `--repo`; see `crate::worktree`). `None` means in-place.
    pub worktree: Option<worktree::RemediationWorktree>,
    pub out_json: Option<PathBuf>,
    /// `None` when the default-location checkpoint DB couldn't be opened
    /// (see [`main_impl`]) — `--resume` (and future runs' ability to
    /// resume from THIS run) simply has no effect in that case, rather
    /// than failing the whole `--remediate` invocation over what's a
    /// resume convenience, not a correctness requirement.
    pub checkpoint: Option<Arc<dyn bc_checkpoint::CheckpointStore>>,
}

/// Assembles a [`RemediateRun`]: the resolved settings, the ONE
/// write-capable executor S10 gets, and its write journal.
///
/// Two things have to happen together here, which is why this is a
/// function rather than a struct literal at each of its two call sites
/// (single-repo and batch):
///
/// 1. **Worktree first.** When remediation is isolated (the default for a
///    git `--repo`), the write-capable executor must be rooted at the
///    throwaway checkout, not at the user's files — deciding that after
///    building the executor would mean building it against the wrong root.
/// 2. **The journal comes from THAT executor instance.**
///    `SandboxTools::journal()` hands back a handle to the same
///    copy-on-first-write ledger the executor records into, so S10's
///    rollback gates see exactly the writes this agent made. A journal
///    taken from any other instance would always be empty, silently
///    degrading every gate to the `git status` fallback — the failure
///    mode is invisible, which is why the two are built in one place.
fn build_remediate_run(cli: &Cli, repo: &Path) -> Result<RemediateRun, String> {
    let mut settings = build_remediate_settings(cli)?;
    let delivery = delivery::prepare(cli, repo)?;
    let zip_mode = cli.remediation_delivery == delivery::DeliveryMode::Zip;
    if settings.target_tests.is_some() || delivery.is_some() {
        if settings.config.step10.verify_command.is_some()
            || settings.config.step10.dry_run
            || !settings.config.step10.fix_mode
        {
            return Err("Target testing requires fix mode without dry-run or a host verify_command; use execution.commands in the isolated target-test policy".into());
        }
        if !zip_mode {
            let status = std::process::Command::new("git")
                .arg("-C")
                .arg(repo)
                .args(["status", "--porcelain", "--untracked-files=all"])
                .output()
                .map_err(context("Target testing requires a clean Git snapshot"))?;
            // Two very different failures, reported separately. A
            // non-zero exit means git would not read the repository at
            // all, most often because the caller runs as a different uid
            // than the checkout's owner and git refuses it for dubious
            // ownership. That is a clean tree the tool cannot see, not a
            // dirty one, and telling an operator to commit their changes
            // sends them somewhere there is nothing to find.
            if !status.status.success() {
                let detail = String::from_utf8_lossy(&status.stderr);
                let detail = detail.trim();
                return Err(format!(
                    "Target testing needs to read {}'s Git status and git refused: {}. \
                     If the scanner runs as a different user than the checkout's owner, \
                     mark the path safe, for example by setting GIT_CONFIG_COUNT=1, \
                     GIT_CONFIG_KEY_0=safe.directory and GIT_CONFIG_VALUE_0={}.",
                    repo.display(),
                    if detail.is_empty() {
                        "no error output"
                    } else {
                        detail
                    },
                    repo.display()
                ));
            }
            if !status.stdout.is_empty() {
                return Err("Target testing requires a clean committed Git snapshot so scan, baseline and remediation inspect the same inputs".into());
            }
        }
    }
    let worktree = if zip_mode {
        None
    } else {
        worktree::prepare(cli, repo)
    };
    if (settings.target_tests.is_some() || delivery.is_some()) && !zip_mode && worktree.is_none() {
        return Err("Target testing requires an isolated worktree; creation failed and in-place fallback is disabled".into());
    }
    let root = delivery
        .as_ref()
        .and_then(|d| d.snapshot.as_ref())
        .map(|s| s.path().to_path_buf())
        .or_else(|| worktree.as_ref().map(|w| w.path.clone()))
        .unwrap_or_else(|| repo.to_path_buf());
    let tools = SandboxTools::new_with_write(root);
    settings.config.step10.journal = Some(tools.journal());
    settings.config.isolated = worktree.is_some() || zip_mode;
    Ok(RemediateRun {
        delivery,
        settings,
        tools: Arc::new(tools),
        worktree,
        out_json: cli.out_remediation_json.clone(),
        checkpoint: open_checkpoint_store(),
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChangeExport {
    file: String,
    summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EvidenceExport {
    file: String,
    line: Option<i64>,
    snippet: String,
}

impl From<&bc_validation_scoring::Evidence> for EvidenceExport {
    fn from(e: &bc_validation_scoring::Evidence) -> Self {
        EvidenceExport {
            file: e.file.clone(),
            line: e.line,
            snippet: e.snippet.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GateResultExport {
    gate_name: String,
    status: String,
    summary: String,
    evidence: Vec<EvidenceExport>,
    details: String,
    /// `"HIGH"`/`"SPLIT"`/`"FLAGGED"` (`bc_validation_scoring::
    /// SynthesisConfidence`) for a gate the S11 panel synthesized, so an
    /// operator triaging a withheld fix can see WHICH gate lacked
    /// consensus without parsing it out of the justification prose.
    /// Only `"FLAGGED"` withholds a verdict; `"SPLIT"` is a
    /// disagreement about how complete the fix is, scored normally and
    /// surfaced here for review.
    ///
    /// Additive and optional in both directions: absent from the JSON
    /// for a gate that never went through synthesis (rather than
    /// serialized as `null`), and defaulted when reading a
    /// `remediation.json` written before this field existed — which
    /// `--post-fixes-from` does, though it only reads `finding_id` and
    /// `diff` back out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    confidence: Option<String>,
}

impl From<&bc_validation_scoring::GateResult> for GateResultExport {
    fn from(g: &bc_validation_scoring::GateResult) -> Self {
        GateResultExport {
            gate_name: g.gate_name.as_str().to_string(),
            status: g.status.as_str().to_string(),
            summary: g.summary.clone(),
            evidence: g.evidence.iter().map(EvidenceExport::from).collect(),
            details: g.details.clone(),
            confidence: g.confidence.map(|c| c.as_str().to_string()),
        }
    }
}

/// Mirrors [`bc_validation_scoring::ValidationScore`] — that crate's own
/// types carry no `Serialize`/`Deserialize` (pure logic, no I/O), so
/// `--out-remediation-json`/`--post-fixes-from` need this string-based
/// export shape instead, same rationale as `ChangeExport`/
/// `RemediationRecordExport` mirroring `bc_stage_s10`'s own types.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ValidationScoreExport {
    /// The numeric score, `null` when the panel was inconclusive
    /// (`fix_status: "UNVERIFIABLE"`, `decision: "inconclusive"`): Python
    /// reports no score there, and the `0.0` this used to carry read as
    /// "scored and failed". A file written before this change carries a
    /// number here, which still reads back.
    raw_score: Option<f64>,
    /// `fixed`/`partially_fixed`/`not_fixed`/`inconclusive`
    /// (`bc_validation_scoring::Decision`), the label to branch on. Added
    /// beside `fix_status`, which keeps its historical values for existing
    /// consumers; defaulted (empty) when reading an older file.
    #[serde(default)]
    decision: String,
    fix_status: String,
    justification: String,
    gate_results: Vec<GateResultExport>,
    has_critical_failure: bool,
}

impl From<&bc_validation_scoring::ValidationScore> for ValidationScoreExport {
    fn from(v: &bc_validation_scoring::ValidationScore) -> Self {
        ValidationScoreExport {
            raw_score: v.score(),
            decision: v.decision().as_str().to_string(),
            fix_status: v.fix_status.as_str().to_string(),
            justification: v.justification.clone(),
            gate_results: v.gate_results.iter().map(GateResultExport::from).collect(),
            has_critical_failure: v.has_critical_failure,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RemediationRecordExport {
    finding_index: i64,
    /// The same stable, content-based finding identity used for SARIF
    /// `partialFingerprints` and the GitHub finding-comment marker (see
    /// `bc_stage_s10::RemediationRecord::finding_id`) — what
    /// `--post-fixes-from` correlates a fix back to a finding by.
    finding_id: String,
    verdict: String,
    policy_action: Option<String>,
    policy_reason: Option<String>,
    final_verdict: Option<String>,
    changes: Vec<ChangeExport>,
    summary: String,
    /// The unified diff of `changes`, or `None` when nothing was
    /// actually changed on disk (a pre-gate deny, or an agent run that
    /// made no edits) — what `--post-fixes-from` posts as a
    /// fix-suggestion comment.
    diff: Option<String>,
    /// Phase 3's S11 panel score, `Some(_)` only when validation ran for
    /// this finding (see `bc_orchestrator::RemediateOutcome::validations`'
    /// own doc comment for exactly when that is).
    validation: Option<ValidationScoreExport>,
}

impl RemediationRecordExport {
    fn from_parts(
        r: &bc_stage_s10::RemediationRecord,
        validation: Option<&bc_validation_scoring::ValidationScore>,
    ) -> Self {
        RemediationRecordExport {
            finding_index: r.finding_index,
            finding_id: r.finding_id.clone(),
            verdict: r.verdict.verdict.as_str().to_string(),
            policy_action: r.policy_action.clone(),
            policy_reason: r.policy_reason.clone(),
            final_verdict: r.final_verdict.clone(),
            changes: r
                .verdict
                .changes
                .iter()
                .map(|c| ChangeExport {
                    file: c.file.clone(),
                    summary: c.summary.clone(),
                })
                .collect(),
            summary: r.verdict.summary.clone(),
            diff: r.diff.clone(),
            validation: validation.map(ValidationScoreExport::from),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum RemediationOutcomeExport {
    Processed(Box<RemediationRecordExport>),
    Failed { finding_index: i64, error: String },
}

impl RemediationOutcomeExport {
    fn from_parts(
        o: &bc_stage_s10::RemediationOutcome,
        validation: Option<&bc_validation_scoring::ValidationScore>,
    ) -> Self {
        match o {
            bc_stage_s10::RemediationOutcome::Processed(r) => RemediationOutcomeExport::Processed(
                Box::new(RemediationRecordExport::from_parts(r.as_ref(), validation)),
            ),
            bc_stage_s10::RemediationOutcome::Failed {
                finding_index,
                error,
            } => RemediationOutcomeExport::Failed {
                finding_index: *finding_index,
                error: error.clone(),
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RemediationExport {
    refused: Option<String>,
    results: Vec<RemediationOutcomeExport>,
    /// Run-level counts and the exit code they imply. Defaulted when
    /// reading a file written before it existed.
    #[serde(default)]
    totals: RemediationTotalsExport,
    /// vvaharness v1.4.0's `rollup { cases, states, decisions }`.
    #[serde(default)]
    rollup: RollupExport,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct RemediationTotalsExport {
    attempted: usize,
    fixed: usize,
    not_fixed: usize,
    failed: usize,
    validation_failures: usize,
    exit_code: u8,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct RollupExport {
    cases: usize,
    states: std::collections::BTreeMap<String, usize>,
    decisions: std::collections::BTreeMap<String, usize>,
}

impl From<&RemediationSummary> for RemediationTotalsExport {
    fn from(s: &RemediationSummary) -> Self {
        RemediationTotalsExport {
            attempted: s.processed + s.failed,
            fixed: s.fixed,
            not_fixed: s.not_fixed,
            failed: s.failed,
            validation_failures: s.validation_failures,
            exit_code: s.exit_code(),
        }
    }
}

impl From<&bc_validation_scoring::Rollup> for RollupExport {
    fn from(r: &bc_validation_scoring::Rollup) -> Self {
        let owned = |m: &std::collections::BTreeMap<&'static str, usize>| {
            m.iter().map(|(k, v)| (k.to_string(), *v)).collect()
        };
        RollupExport {
            cases: r.cases,
            states: owned(&r.states),
            decisions: owned(&r.decisions),
        }
    }
}

/// Maps each `Some(_)` validation entry back to the stable finding id its
/// own remediated finding carries (`RemediationRecord::finding_id`) — the
/// same id `report.sarif`'s `partialFingerprints` are keyed by elsewhere
/// (see `bc_sarif::finding_id`), so a score can be matched back to the
/// finding it belongs to for report augmentation without needing the
/// original CVSS-ranked selection list `remediate()` itself used.
fn validations_by_finding_id(
    outcome: &bc_orchestrator::RemediateOutcome,
) -> std::collections::BTreeMap<String, bc_validation_scoring::ValidationScore> {
    outcome
        .outcomes
        .iter()
        .zip(&outcome.validations)
        .filter_map(|(o, validation)| {
            let bc_stage_s10::RemediationOutcome::Processed(record) = o else {
                return None;
            };
            Some((record.finding_id.clone(), validation.clone()?))
        })
        .collect()
}

/// Re-writes `report.md`/`report.sarif` with S11 validation results
/// folded in — a no-op when nothing actually ran validation
/// (`validations_by_finding_id` comes back empty: `--remediate` without
/// validation enabled, or every remediated finding had nothing to
/// validate). `report.md`/`report.sarif` are ALWAYS written once,
/// *before* remediation runs at all (see `write_outputs`'s own call
/// site in `run` below) — this is a deliberate SECOND pass, matching how
/// the Python original augments its own already-written report files in
/// place post-remediation (see `bc_stage_s11`'s own module doc comment
/// for the full ordering rationale). `sarif_was_written` mirrors
/// `write_outputs`'s own "only write what the scan actually reached"
/// precondition — re-writing a SARIF file that was never written in the
/// first place (e.g. a `--stop-after s8` run) would fabricate one that
/// was deliberately never produced.
fn augment_report_outputs(
    md_path: &Path,
    sarif_path: &Path,
    report: &bc_model::FinalReport,
    tool_version: &str,
    markdown: Option<&str>,
    sarif_was_written: bool,
    outcome: &bc_orchestrator::RemediateOutcome,
) -> std::io::Result<()> {
    let by_id = validations_by_finding_id(outcome);
    let views = remediation_views(report, outcome);
    if by_id.is_empty() && views.is_empty() {
        return Ok(());
    }
    markdown.into_iter().try_for_each(|md| {
        let aligned: Vec<Option<bc_validation_scoring::ValidationScore>> = report
            .findings
            .iter()
            .map(|rf| by_id.get(&bc_sarif::finding_id(&rf.finding)).cloned())
            .collect();
        // Remediation first, then validation: both append to the END of a
        // finding's section, so this is what puts `#### Remediation` above
        // the `#### Validation` that grades it — the order a reviewer
        // reads them in. `augment_markdown` matches `### N. [` headings
        // only, which the remediation block never introduces, so the
        // first pass cannot confuse the second.
        let with_remediation = bc_report_md::augment_markdown_with_remediation(md, &views);
        let augmented =
            bc_redact::redact(&bc_report_md::augment_markdown(&with_remediation, &aligned));
        create_parent_dir(md_path)?;
        std::fs::write(md_path, augmented)
    })?;
    sarif_was_written
        .then_some(())
        .into_iter()
        .try_for_each(|()| {
            let mut doc = bc_sarif::build_sarif_with_validations(report, tool_version, &by_id);
            apply_remediation_status(&mut doc, report, outcome);
            let json = serde_json::to_string_pretty(&doc).expect("SarifDocument always serializes");
            create_parent_dir(sarif_path)?;
            std::fs::write(sarif_path, json)
        })
}

/// The report-level heading `bc_report_md::
/// augment_markdown_with_remediation` appends. Used ONLY as an
/// "already augmented" marker by [`augment_prior_markdown`] — see there
/// for why that check exists on the `--remediate-from` path and not on
/// the ordinary `--remediate` one.
const REMEDIATION_SUMMARY_HEADING: &str = "\n## Remediation Summary\n";

/// Augments the PRIOR run's `report.md`/`report.sarif` in place with a
/// `--remediate-from` run's results — the same `#### Remediation` /
/// `#### Validation` / `## Remediation Summary` sections and the same
/// `validationStatus`/`remediationStatus` SARIF properties an ordinary
/// `--remediate` scan writes through [`augment_report_outputs`].
///
/// **Why this is not just a call to [`augment_report_outputs`].** That
/// function REBUILDS `report.sarif` from the `FinalReport` in hand. Here
/// the report in hand was reconstructed from a findings export, which
/// carries findings and nothing else — no app profile, no scan metrics,
/// no degraded flag. Rebuilding from it would silently drop the
/// `applicationId`, the invocation notifications and the run properties
/// the earlier scan actually computed, replacing a complete document
/// with a poorer one. So the prior document is read back, its results
/// matched by their own `bc/findingId/v1` fingerprint (not by position:
/// a `--baseline` run appends `absent` results, which would misalign a
/// positional zip), and only the remediation/validation keys are
/// stamped on. Everything else survives byte-for-byte.
///
/// A missing or unreadable artifact is [`AugmentOutcome::NotFound`], not
/// an error: this mode's own outputs are `--out-remediation-json` and
/// the exported patch, and a prior report that was written elsewhere (or
/// never written) is a normal thing to find.
fn augment_prior_reports(
    md_path: &Path,
    sarif_path: &Path,
    report: &bc_model::FinalReport,
    outcome: &bc_orchestrator::RemediateOutcome,
) -> std::io::Result<AugmentedReports> {
    Ok(AugmentedReports {
        markdown: augment_in_place(md_path, |text| {
            augment_prior_markdown(text, report, outcome)
        })?,
        markdown_path: md_path.to_path_buf(),
        sarif: augment_in_place(sarif_path, |text| augment_prior_sarif(text, outcome))?,
        sarif_path: sarif_path.to_path_buf(),
    })
}

/// Reads `path`, hands its contents to `augment`, and writes the result
/// back only when the augmenter actually produced one — a `None` leaves
/// the file untouched on disk, never rewritten with identical bytes.
fn augment_in_place(
    path: &Path,
    augment: impl FnOnce(&str) -> Option<String>,
) -> std::io::Result<AugmentOutcome> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Ok(AugmentOutcome::NotFound);
    };
    match augment(&text) {
        Some(augmented) => {
            std::fs::write(path, augmented)?;
            Ok(AugmentOutcome::Written)
        }
        None => Ok(AugmentOutcome::Unchanged),
    }
}

/// The Markdown half of [`augment_prior_reports`]. `None` means "leave
/// the file exactly as it is", for any of three reasons:
///
/// 1. It already carries a `## Remediation Summary`. Unlike the
///    `--remediate` path — which re-renders `report.md` from the scan's
///    own freshly rendered Markdown every time, and is therefore
///    naturally idempotent — this path appends to whatever is on disk,
///    so a second `--remediate-from` against the same report would stack
///    a second, contradicting remediation section under every finding.
///    Refusing is the fail-closed answer; the SARIF half needs no such
///    guard because stamping a property twice just overwrites it.
/// 2. Nothing to say: no remediation record and no validation score.
/// 3. The augmenters themselves failed closed — `bc_report_md` returns
///    the input unchanged when the `### N. [` heading count doesn't
///    match the export, rather than filing a fix under the wrong
///    finding (CWE-345). An unchanged result is passed straight through
///    as "left alone", which is exactly what it is.
fn augment_prior_markdown(
    markdown: &str,
    report: &bc_model::FinalReport,
    outcome: &bc_orchestrator::RemediateOutcome,
) -> Option<String> {
    if markdown.contains(REMEDIATION_SUMMARY_HEADING) {
        return None;
    }
    let by_id = validations_by_finding_id(outcome);
    let views = remediation_views(report, outcome);
    if by_id.is_empty() && views.is_empty() {
        return None;
    }
    let aligned: Vec<Option<bc_validation_scoring::ValidationScore>> = report
        .findings
        .iter()
        .map(|rf| by_id.get(&bc_sarif::finding_id(&rf.finding)).cloned())
        .collect();
    // Remediation before validation, for the same reason
    // `augment_report_outputs` does it in that order.
    let with_remediation = bc_report_md::augment_markdown_with_remediation(markdown, &views);
    let augmented = bc_redact::redact(&bc_report_md::augment_markdown(&with_remediation, &aligned));
    (augmented != markdown).then_some(augmented)
}

/// The SARIF half of [`augment_prior_reports`]: parse the prior
/// document, stamp `validationStatus`/`validationScore`/
/// `validationJustification`/`mergeReadiness` and `remediationStatus`
/// onto the results whose own v1 fingerprint names a finding this run
/// remediated, and re-serialize. `None` (leave the file alone) when the
/// document doesn't parse as this tool's own SARIF, when there is
/// nothing to stamp, or when no result matched — the prior document is
/// worth more than a partial annotation of it, the same trade
/// `baseline::annotate_sarif` already makes.
fn augment_prior_sarif(sarif: &str, outcome: &bc_orchestrator::RemediateOutcome) -> Option<String> {
    let validations = validations_by_finding_id(outcome);
    let statuses = remediation_statuses(outcome);
    if validations.is_empty() && statuses.is_empty() {
        return None;
    }
    let mut doc: bc_sarif::SarifDocument = serde_json::from_str(sarif).ok()?;
    let mut touched = false;
    for run in &mut doc.runs {
        for result in &mut run.results {
            // Cloned out before the mutable borrows below — and matched
            // on the fingerprint rather than on position, so an `absent`
            // result appended by a prior `--baseline` run can't shift
            // every later annotation onto the wrong finding.
            let Some(id) = result
                .partial_fingerprints
                .get(bc_sarif::FINGERPRINT_KEY)
                .cloned()
            else {
                continue;
            };
            if let Some(validation) = validations.get(&id) {
                bc_sarif::apply_validation(result, validation);
                touched = true;
            }
            if let Some(status) = statuses.get(&id) {
                result.properties.remediation_status = Some(status.clone());
                touched = true;
            }
        }
    }
    touched.then(|| serde_json::to_string_pretty(&doc).expect("SarifDocument always serializes"))
}

/// Projects every `Processed` remediation record onto the
/// [`bc_report_md::RemediationView`] the Markdown renderer wants,
/// resolving each record's position in `report.findings` through the
/// SAME stable `finding_id` the SARIF fingerprints and GitHub comment
/// markers use — `RemediationRecord::finding_index` is a 1-based
/// SELECTION ordinal (`--top N` picks findings by CVSS, not in report
/// order), so using it directly would file a fix under the wrong finding.
///
/// A record whose id matches no finding in the report is dropped rather
/// than guessed at; `augment_markdown_with_remediation` itself fails
/// closed on a duplicate or out-of-range index, so a report that somehow
/// carried two identical findings simply goes un-augmented instead of
/// rendering a fix under the wrong one (CWE-345).
fn remediation_views(
    report: &bc_model::FinalReport,
    outcome: &bc_orchestrator::RemediateOutcome,
) -> Vec<bc_report_md::RemediationView> {
    let positions: std::collections::BTreeMap<String, usize> = report
        .findings
        .iter()
        .enumerate()
        .map(|(i, rf)| (bc_sarif::finding_id(&rf.finding), i))
        .collect();
    outcome
        .outcomes
        .iter()
        .enumerate()
        .filter_map(|(i, o)| {
            let bc_stage_s10::RemediationOutcome::Processed(record) = o else {
                return None;
            };
            let finding_index = *positions.get(&record.finding_id)?;
            Some(bc_report_md::RemediationView {
                finding_index,
                // The policy gate's own capped verdict wins when it
                // overrode the agent's, matching what
                // `--out-remediation-json` reports as `final_verdict`.
                verdict: record
                    .final_verdict
                    .clone()
                    .unwrap_or_else(|| record.verdict.verdict.as_str().to_string()),
                summary: record.verdict.summary.clone(),
                root_cause: record.verdict.root_cause.clone(),
                remaining_risks: record.verdict.remaining_risks.clone(),
                recommendations: record.verdict.recommendations.clone(),
                changed_files: record
                    .verdict
                    .changes
                    .iter()
                    .map(|c| c.file.clone())
                    .collect(),
                has_diff: record.diff.is_some(),
                rollback_reason: bc_stage_s10::revert_reason(record).map(str::to_string),
                validation_status: outcome
                    .validations
                    .get(i)
                    .and_then(Option::as_ref)
                    .map(|v| v.fix_status.as_str().to_string()),
            })
        })
        .collect()
}

/// Every `Processed` record's final remediation verdict, keyed by the
/// stable `finding_id` the SARIF fingerprints and GitHub comment markers
/// also use. The policy gate's own capped verdict wins when it overrode
/// the agent's, matching what `--out-remediation-json` reports as
/// `final_verdict`.
///
/// Shared by [`apply_remediation_status`] (which stamps a
/// freshly-rebuilt document) and [`augment_prior_sarif`] (which stamps a
/// prior run's document read back off disk) so the two can't disagree
/// about which verdict a finding got.
fn remediation_statuses(
    outcome: &bc_orchestrator::RemediateOutcome,
) -> std::collections::BTreeMap<String, String> {
    outcome
        .outcomes
        .iter()
        .filter_map(|o| {
            let bc_stage_s10::RemediationOutcome::Processed(record) = o else {
                return None;
            };
            Some((
                record.finding_id.clone(),
                record
                    .final_verdict
                    .clone()
                    .unwrap_or_else(|| record.verdict.verdict.as_str().to_string()),
            ))
        })
        .collect()
}

/// Stamps each SARIF result with its finding's remediation verdict as a
/// `remediationStatus` property, so a Code Scanning consumer can tell an
/// alert that has an attempted fix from one that has not — the same
/// signal `report.md`'s `#### Remediation` block carries, in the machine
/// -readable artifact. Results with no remediation record are left
/// untouched (the property is `skip_serializing_if = "Option::is_none"`).
///
/// Matched by `finding_id`, not by index, for the same reason
/// [`remediation_views`] is.
fn apply_remediation_status(
    doc: &mut bc_sarif::SarifDocument,
    report: &bc_model::FinalReport,
    outcome: &bc_orchestrator::RemediateOutcome,
) {
    let by_id = remediation_statuses(outcome);
    if by_id.is_empty() {
        return;
    }
    // `build_sarif*` emits exactly one result per `report.findings` entry,
    // in order — the same invariant `augment_markdown`'s own
    // heading-count check relies on.
    for run in &mut doc.runs {
        for (result, rf) in run.results.iter_mut().zip(&report.findings) {
            if let Some(status) = by_id.get(&bc_sarif::finding_id(&rf.finding)) {
                result.properties.remediation_status = Some(status.clone());
            }
        }
    }
}

/// Writes `--out-remediation-json`'s output, if requested. A silent
/// no-op without a path, matching `write_findings_json`'s own
/// "only write what was actually asked for" behavior.
fn write_remediation_json(
    path: Option<&Path>,
    outcome: &bc_orchestrator::RemediateOutcome,
) -> std::io::Result<()> {
    let Some(path) = path else {
        return Ok(());
    };
    // `outcome.validations` is empty when S11 didn't run at all (see its
    // own doc comment) — treat that the same as "no score for anyone"
    // rather than a per-index zip mismatch.
    let results = outcome
        .outcomes
        .iter()
        .enumerate()
        .map(|(i, o)| {
            let validation = outcome.validations.get(i).and_then(Option::as_ref);
            RemediationOutcomeExport::from_parts(o, validation)
        })
        .collect();
    let summary = RemediationSummary::from(outcome);
    let export = RemediationExport {
        refused: outcome.refused.clone(),
        results,
        totals: RemediationTotalsExport::from(&summary),
        rollup: RollupExport::from(&summary.rollup),
    };
    let json = serde_json::to_string_pretty(&export)
        .expect("RemediationExport contains no non-serializable types");
    create_parent_dir(path)?;
    std::fs::write(path, json)
}

/// Posts/updates one PR comment per finding when `github` is `Some` and
/// the scan actually reached a `FinalReport` with a known `git_sha`
/// (needed to anchor review comments to a real commit). Returns `None`
/// rather than attempting anything when either precondition isn't met.
///
/// `github` being `Some` here means posting was explicitly requested, not
/// merely that credentials exist: [`pr_comment_target`] is what decides
/// that, and it hands this a client only under `--pr-comments`. A run
/// that has a token purely so `--diff-scope` can fetch the PR diff
/// arrives here with `None` and posts nothing.
async fn sync_github(
    github: Option<&bc_github::GithubClient>,
    report: Option<&bc_model::FinalReport>,
    repo_root: Option<&Path>,
) -> Option<Result<bc_github::SyncSummary, String>> {
    let client = github?;
    let report = report?;
    let commit_sha = report.git_sha.as_ref()?;
    let findings = extract_findings(report);
    Some(
        bc_github::sync_findings(client, &findings, commit_sha, repo_root)
            .await
            .map_err(stringify),
    )
}

/// Opens the default-location `SqliteCheckpointStore` (whatever
/// `$BC_STATE_DIR`/`$HOME` resolves to) for a `--remediate` run.
/// A failure (e.g. an unwritable state dir) degrades to `None` — printed
/// as a warning, not propagated as an error — since the checkpoint store
/// only enables `--resume`'s convenience, not remediation's own
/// correctness; a developer running with a broken `$HOME` shouldn't be
/// blocked from getting fixes applied.
fn open_checkpoint_store() -> Option<Arc<dyn bc_checkpoint::CheckpointStore>> {
    match bc_checkpoint::SqliteCheckpointStore::open_default() {
        Ok(store) => Some(Arc::new(store)),
        Err(e) => {
            eprintln!(
                "WARN: checkpoint store unavailable ({e}); --resume will have no effect this run"
            );
            None
        }
    }
}

/// `--gc`/`--gc-run`'s entire job: prune or evict run/checkpoint state
/// from the SQLite state DB, without touching `--repo`, the LLM gateway,
/// or GitHub at all — mirroring how `--post-comments-from` short-
/// circuits `main_impl` before any of that gets built. Ported from
/// `cli.py::_gc`'s two branches (targeted `--run` eviction vs. `--keep-
/// runs`/`--max-age-days` pruning).
///
/// Unlike [`open_checkpoint_store`] (which degrades a failure to `None`
/// since it only affects `--resume`'s convenience), a failure to open
/// the state DB here is a real `Err` — the operator explicitly asked to
/// touch it, so silently no-op-ing on a broken `$BC_STATE_DIR` would
/// hide exactly the failure they'd want to know about.
pub fn run_gc(cli: &Cli) -> Result<ScanSummary, String> {
    let store = bc_checkpoint::SqliteCheckpointStore::open_default().map_err(stringify)?;
    let gc = if let Some(path) = &cli.gc_run {
        let run_id = bc_checkpoint::run_id_for(path);
        let found = if cli.gc_dry_run {
            false
        } else {
            store.delete_run(&run_id).map_err(stringify)?
        };
        GcSummary::Evicted {
            path: path.clone(),
            run_id,
            found,
            dry_run: cli.gc_dry_run,
        }
    } else {
        let report = store
            .prune(cli.gc_keep_runs, cli.gc_max_age_days, cli.gc_dry_run)
            .map_err(stringify)?;
        GcSummary::Pruned {
            db_path: report.db_path,
            kept: report.kept,
            deleted: report.deleted,
            dry_run: cli.gc_dry_run,
        }
    };
    Ok(ScanSummary {
        provider_publication: None,
        gc: Some(gc),
        cost: None,
        findings: 0,
        markdown_path: None,
        sarif_path: None,
        csv_path: None,
        findings_json_path: None,
        stopped_after: None,
        github_sync: None,
        remediation: None,
        remediation_patch: None,
        baseline: None,
        batch: None,
        estimate: None,
        doctor: None,
        setup: None,
        augmented: None,
    })
}

/// `--doctor`: static checks first, then (only if none of them blocked)
/// one real live probe through the gateway — mirrors Python's own
/// `_doctor` (`cli.py:29-56`): the probe is worth nothing if credentials/
/// config are already known-bad, so it's skipped entirely rather than run
/// and reported as failed.
async fn run_doctor(cli: &Cli) -> DoctorSummary {
    let stack_result = build_llm_stack(cli);
    let client_result = stack_result
        .as_ref()
        .map(|stack| stack.client.clone())
        .map_err(Clone::clone);
    let checks = environment::run_checks(cli, &client_result);
    let blocking = environment::n_blocking(&checks);
    let checks_rendered = environment::render(&checks);
    let models = model_policy::configured_models(&cli.model, &lenient_config_data(cli));
    let models_rendered =
        model_policy::render_capabilities(&models, &bc_llm_client::capabilities::today_utc());
    let mut cache_probe = None;
    let probe = if blocking == 0 {
        // `blocking == 0` means every `required` check passed, including
        // the "gateway client" check `run_checks` derived from this SAME
        // `stack_result`, so it's provably `Ok` here.
        let stack = stack_result
            .expect("blocking == 0 implies the gateway-client check already found this Ok");
        let probe = environment::probe_gateway(stack.client.as_ref(), &cli.model).await;
        if cli.cache_probe {
            cache_probe = Some(if probe.status == environment::CheckStatus::Ok {
                let dialect = match cli.dialect {
                    Dialect::Openai => bc_llm_client::CacheDialect::OpenAi,
                    Dialect::Anthropic => bc_llm_client::CacheDialect::Anthropic,
                };
                cache_probe::run(
                    stack.client.as_ref(),
                    &cli.model,
                    dialect,
                    &stack.settings.cache,
                )
                .await
            } else {
                cache_probe::CacheProbeOutcome::skipped(&cli.model)
            });
        }
        Some(probe)
    } else {
        cache_probe = cli
            .cache_probe
            .then(|| cache_probe::CacheProbeOutcome::skipped(&cli.model));
        None
    };
    DoctorSummary {
        checks_rendered,
        blocking,
        models_rendered,
        probe,
        cache_probe,
    }
}

/// `--setup`'s implementation: the same static checks [`run_doctor`]
/// runs, rendered the same way, but WITHOUT the live probe — no network
/// access, no token spend. Synchronous (unlike `run_doctor`) precisely
/// because there's no `.await` left once the probe is removed.
fn run_setup(cli: &Cli) -> SetupSummary {
    let client_result = build_llm_client(cli);
    let checks = environment::run_checks(cli, &client_result);
    let blocking = environment::n_blocking(&checks);
    let checks_rendered = environment::render(&checks);
    SetupSummary {
        checks_rendered,
        blocking,
    }
}

fn check_automatic_publication_mode(cli: &Cli) -> Result<(), String> {
    if cli.provider_writeback == "apply"
        && (cli.diff_scope
            || cli.resume
            || parse_stop_after(&cli.stop_after)?
                .is_some_and(|stop| StopAfter::from(stop) != StopAfter::S9))
    {
        return Err("Automatic provider publication requires a full scan that reaches S9 without --resume or --diff-scope".into());
    }
    Ok(())
}

/// `main.rs`'s entire job: build the real network-backed `LlmClient` +
/// jailed `SandboxTools` and this scan's config/input/output-paths from
/// `cli`, then delegate to [`run`]. Split out from `main()` itself so an
/// integration test can drive it directly with real `argv`-parsed `Cli`
/// values, exercising the exact code path the compiled binary runs.
pub async fn main_impl(cli: Cli) -> Result<ScanSummary, String> {
    main_impl_with_cancel(cli, None).await
}

/// [`main_impl`] with the process's Ctrl-C [`cancel::Controller`]. A scan
/// (and the remediation that follows it) arms it, making the first Ctrl-C
/// a cooperative cancellation; every other mode leaves it unarmed, so a
/// Ctrl-C there exits at once. `None` is a run nothing can cancel.
pub async fn main_impl_with_cancel(
    cli: Cli,
    cancel: Option<cancel::Controller>,
) -> Result<ScanSummary, String> {
    if cli.provider_publish.publish_provider_plan.is_none() && cli.provider_publish.requires_plan()
    {
        return Err("Provider publication flags require --publish-provider-plan".into());
    }
    if cli.provider_publish.publish_provider_plan.is_some() {
        if cli.remediate
            || cli.remediate_from.is_some()
            || cli.repo_file.is_some()
            || cli.post_comments_from.is_some()
            || cli.post_fixes_from.is_some()
            || cli.gc
            || cli.gc_run.is_some()
            || cli.estimate
            || cli.doctor
            || cli.setup
            || cli.provider_writeback != "off"
            || !cli.stop_after.is_empty()
        {
            return Err("Provider publication is a separate operation; do not combine it with scan, remediation, posting, or utility modes".into());
        }
        let result = provider_publish::run(&cli).await?;
        return Ok(ScanSummary {
            provider_publication: Some(result),
            ..Default::default()
        });
    }
    if cli.provider_writeback != "off"
        && (cli.gc
            || cli.gc_run.is_some()
            || cli.estimate
            || cli.doctor
            || cli.setup
            || cli.post_comments_from.is_some()
            || cli.post_fixes_from.is_some()
            || cli.remediate_from.is_some())
    {
        return Err("--provider-writeback requires a scan that reaches S9; it cannot be used with standalone posting, prior-report remediation, or utility modes".into());
    }
    check_automatic_publication_mode(&cli)?;
    // FIRST, before any mode dispatch: an invalid flag combination is
    // invalid whichever mode it was handed to, and this one has to be
    // caught before a scan starts rather than after it (see
    // `check_pr_comment_scope`'s own doc comment).
    target_testing::check_mode(&cli)?;
    delivery::check_mode(&cli)?;
    check_batch_diff_scope(&cli)?;
    check_pr_comment_scope(&cli)?;
    if cli.gc || cli.gc_run.is_some() {
        return run_gc(&cli);
    }
    if cli.estimate {
        let summary = estimate::run_estimate(repo_path(&cli))?;
        return Ok(ScanSummary {
            provider_publication: None,
            findings: 0,
            markdown_path: None,
            sarif_path: None,
            csv_path: None,
            findings_json_path: None,
            stopped_after: None,
            github_sync: None,
            remediation: None,
            remediation_patch: None,
            baseline: None,
            gc: None,
            cost: None,
            batch: None,
            estimate: Some(summary),
            doctor: None,
            setup: None,
            augmented: None,
        });
    }
    if cli.doctor {
        let summary = run_doctor(&cli).await;
        return Ok(ScanSummary {
            provider_publication: None,
            findings: 0,
            markdown_path: None,
            sarif_path: None,
            csv_path: None,
            findings_json_path: None,
            stopped_after: None,
            github_sync: None,
            remediation: None,
            remediation_patch: None,
            baseline: None,
            gc: None,
            cost: None,
            batch: None,
            estimate: None,
            doctor: Some(summary),
            setup: None,
            augmented: None,
        });
    }
    if cli.setup {
        let summary = run_setup(&cli);
        return Ok(ScanSummary {
            provider_publication: None,
            findings: 0,
            markdown_path: None,
            sarif_path: None,
            csv_path: None,
            findings_json_path: None,
            stopped_after: None,
            github_sync: None,
            remediation: None,
            remediation_patch: None,
            baseline: None,
            gc: None,
            cost: None,
            batch: None,
            estimate: None,
            doctor: None,
            setup: Some(summary),
            augmented: None,
        });
    }
    if let Some(path) = cli.post_comments_from.clone() {
        let github = build_github_client(&cli)?.ok_or_else(|| {
            "--post-comments-from requires --github-token/--github-repo/--pr-number".to_string()
        })?;
        return post_comments_only(&github, &path, Some(repo_path(&cli))).await;
    }
    if let Some(path) = cli.post_fixes_from.clone() {
        let github = build_github_client(&cli)?.ok_or_else(|| {
            "--post-fixes-from requires --github-token/--github-repo/--pr-number".to_string()
        })?;
        return post_fixes_only(&github, &path).await;
    }
    // Every mode below calls a model: refuse a retired one before any
    // token is spent, the preflight probe's included. `--doctor` and
    // `--setup` report the same verdict as a check instead.
    model_policy::enforce(
        &cli.model,
        &lenient_config_data(&cli),
        cli.allow_unsupported_model,
    )?;
    if let Some(path) = cli.remediate_from.clone() {
        // Needs a real gateway (S10 is an agentic loop) but no scan, so
        // the preflight probe still applies — an unreachable gateway
        // should fail here, not three findings in.
        let client_result = build_llm_client(&cli);
        if !cli.skip_preflight {
            preflight::run(&cli, &client_result).await?;
        }
        let cancel = cancel.as_ref().map(cancel::Controller::arm);
        return remediate_from_with_cancel(&cli, &path, client_result?, cancel).await;
    }
    if let Some(manifest_path) = cli.repo_file.clone() {
        let summary = batch::run_batch(&cli, &manifest_path).await?;
        return Ok(ScanSummary {
            provider_publication: None,
            findings: 0,
            markdown_path: None,
            sarif_path: None,
            csv_path: None,
            findings_json_path: None,
            stopped_after: None,
            github_sync: None,
            remediation: None,
            remediation_patch: None,
            baseline: None,
            gc: None,
            cost: None,
            batch: Some(summary),
            estimate: None,
            doctor: None,
            setup: None,
            augmented: None,
        });
    }

    let publication = provider_publish::automatic::configure(&cli)?;
    let stack_result = build_llm_stack(&cli);
    let client_result = stack_result
        .as_ref()
        .map(|stack| stack.client.clone())
        .map_err(Clone::clone);
    if !cli.skip_preflight {
        preflight::run(&cli, &client_result).await?;
    }
    let stack = stack_result?;
    let llm = stack.client.clone();
    let tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new(repo_path(&cli).to_path_buf()));
    let github = build_github_client(&cli)?;
    let mut config = build_scan_config(&cli)?;
    autoexclude::maybe_apply(&cli, &llm, repo_path(&cli), &mut config).await;
    // Always attempts to open the state DB, matching the `--remediate`
    // path's own `open_checkpoint_store()` call just below — checkpoints
    // are written on every scan whenever a store is available (Python's
    // own always-checkpoint behavior); `--resume` only controls whether
    // S1-S7 consult them (see `ScanConfig::resume`'s own doc comment).
    // Degrades to `None` (a warning, not an error) if the state dir is
    // unavailable.
    config.checkpoint = open_checkpoint_store();
    let mut input = build_scan_input(&cli);
    let diff_scope = resolve_diff_scope(cli.diff_scope, github.as_ref()).await?;
    let remediation_boundary = diff_scope.boundary();
    input.diff_scope_active = diff_scope.active;
    input.changed_files = diff_scope.changed_files;
    input.compliance = load_compliance_policies(&cli)?;
    let stop_after = parse_stop_after(&cli.stop_after)?.map(StopAfter::from);
    let paths = resolve_output_paths(&cli);
    let mut remediate = (cli.remediate && stop_after.is_none())
        .then(|| build_remediate_run(&cli, repo_path(&cli)))
        .transpose()?;
    // S10's own hard refusal, independent of what the scan put in the
    // report: whatever assembled the candidate list (the `--top` walk, the
    // `-i` picker, a future caller), remediation must not edit a file the
    // pull request never touched. Inactive on a full-repo scan, which is
    // exactly the no-op it was before.
    if let Some(run) = remediate.as_mut() {
        run.settings.config.step10.diff_scope = remediation_boundary;
    }
    // Loaded BEFORE the scan starts, so a typo'd path fails in a second
    // instead of after a full run: an unusable baseline is a hard error
    // (see `baseline::load`), and discovering that at the end would waste
    // the scan it was meant to classify.
    let baseline = cli
        .baseline
        .as_ref()
        .map(|path| -> Result<BaselineRun, String> {
            Ok(BaselineRun {
                path: path.clone(),
                baseline: baseline::load(path, repo_path(&cli))?,
            })
        })
        .transpose()?;

    // Past every argument check and utility mode: a scan is about to
    // run, so it gets a run manifest (see `run_manifest`).
    let manifest = run_manifest::begin(
        &cli,
        &config,
        remediate.as_ref().map(|r| &r.settings),
        stack.settings.openai_api,
        &input.repo_name,
        std::env::args_os()
            .map(|a| a.to_string_lossy().into_owned())
            .collect(),
    );
    // The render thread always runs (the manifest's telemetry needs the
    // stream); the bar only when stdout is a terminal and `--no-progress`
    // is absent, and never together with text progress lines. Joined
    // AFTER `run` returns so the bar has already cleared itself before
    // the summary line prints below main_impl's own caller (`main.rs`'s
    // `println!("{summary}")`).
    let mut observers = progress::Observers::choose(
        progress::should_render(cli.no_progress),
        progress_lines::from_cli(&cli),
    );
    if cli.s6_progress_file || config.step6.progress_file {
        observers.s6_progress = s6_progress::resolve(repo_path(&cli));
    }
    let progress_handle = progress::wire(&mut config, observers);
    // Armed only now, with the run manifest begun: from here a Ctrl-C has
    // a partial report and a manifest worth waiting for.
    config.cancel = cancel.as_ref().map(cancel::Controller::arm);

    let result = run_with_publication(
        input,
        config,
        stop_after,
        &paths,
        llm,
        tools,
        pr_comment_target(&cli, github),
        remediate,
        baseline,
        publication,
    )
    .await;
    let telemetry = progress_handle.join().unwrap_or_default();
    let git_sha = non_empty(&cli.git_sha)
        .map(str::to_string)
        .or_else(|| bc_orchestrator::head_sha(repo_path(&cli)));
    let exit_code = i32::from(process_exit_code(
        &result,
        cli.remediation_exit_code,
        cancel.as_ref().is_some_and(cancel::Controller::is_canceled),
    ));
    run_manifest::finish(
        manifest,
        &telemetry,
        exit_code,
        git_sha,
        stack.responses_fallbacks(),
    );
    result
}

#[cfg(test)]
pub(crate) mod tests {
    /// Ctrl-C through the CLI's own scan and remediation wiring.
    mod cancel_run_tests;

    use async_trait::async_trait;
    use bc_llm_client::{
        ChatRequest, ChatResponse, ContentBlock, LlmError, StopReason, ToolSpec, Usage,
    };
    use clap::Parser;
    use serde_json::{json, Value};
    use tokio::sync::Mutex;

    use super::*;

    // `cargo test` runs a binary's tests on a thread pool by default, so
    // any test that mutates the process-global `BC_STATE_DIR` env
    // var (to keep `open_checkpoint_store` off the real developer state
    // dir) must serialize against every other such test. An
    // async-aware `Mutex` (not `std::sync::Mutex`) specifically because
    // one guarded test holds it across an `.await` (`main_impl` itself is
    // async) — `blocking_lock()` is used from the plain synchronous
    // tests instead of `.lock().await`.
    pub(crate) static ENV_LOCK: Mutex<()> = Mutex::const_new(());

    pub(crate) fn restore_env(name: &str, prior: Option<String>) {
        match prior {
            Some(v) => unsafe { std::env::set_var(name, v) },
            None => unsafe { std::env::remove_var(name) },
        }
    }

    /// The four report paths, all directly inside `dir`: the same set
    /// `resolve_output_paths` builds for a default `--out-dir`, spelled
    /// out here so a test can assert on one path directly.
    fn out_paths(dir: &Path) -> OutputPaths {
        OutputPaths {
            provider_writeback_plan: None,
            markdown: dir.join("report.md"),
            sarif: dir.join("report.sarif"),
            csv: dir.join("report.csv"),
            findings_json: dir.join("findings.json"),
        }
    }

    fn cli(repo: &Path) -> Cli {
        Cli {
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
            gateway_base_url: "http://127.0.0.1:0".to_string(),
            gateway_api_key: None,
            ca_cert: None,
            client_cert: None,
            client_key: None,
            dialect: Dialect::Openai,
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
            remediation_delivery: crate::delivery::DeliveryMode::Patch,
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

    // ── clap: --repo / --repo-file mutual exclusion ─────────────────────

    /// Every branch of the exit-code mapping `main.rs` and the run
    /// manifest share.
    #[test]
    fn process_exit_code_covers_errors_health_and_remediation() {
        let ok = |s: ScanSummary| -> Result<ScanSummary, String> { Ok(s) };
        assert_eq!(process_exit_code(&Err("boom".to_string()), true, false), 1);
        assert_eq!(
            process_exit_code(&ok(ScanSummary::default()), true, false),
            0
        );

        let unhealthy_doctor = ScanSummary {
            doctor: Some(DoctorSummary {
                checks_rendered: String::new(),
                blocking: 1,
                models_rendered: String::new(),
                probe: None,
                cache_probe: None,
            }),
            ..ScanSummary::default()
        };
        assert_eq!(process_exit_code(&ok(unhealthy_doctor), true, false), 1);
        let unhealthy_setup = ScanSummary {
            setup: Some(SetupSummary {
                checks_rendered: String::new(),
                blocking: 2,
            }),
            ..ScanSummary::default()
        };
        assert_eq!(process_exit_code(&ok(unhealthy_setup), true, false), 1);

        let failed_remediation = ScanSummary {
            remediation: Some(RemediationSummary {
                failed: 1,
                ..RemediationSummary::default()
            }),
            ..ScanSummary::default()
        };
        assert_eq!(
            process_exit_code(&ok(failed_remediation.clone()), true, false),
            1
        );
        // `--remediation-exit-code false` keeps the old always-0 behavior.
        assert_eq!(process_exit_code(&ok(failed_remediation), false, false), 0);
        // A canceled run is 130 whatever else happened, an error included.
        assert_eq!(
            process_exit_code(&ok(ScanSummary::default()), true, true),
            130
        );
        assert_eq!(process_exit_code(&Err("boom".to_string()), true, true), 130);
    }

    #[test]
    fn repo_alone_parses_fine() {
        let cli = Cli::try_parse_from([
            "bc-sast",
            "--repo",
            "/tmp/repo",
            "--gateway-base-url",
            "http://127.0.0.1:0",
        ])
        .unwrap();
        assert_eq!(cli.repo, Some(PathBuf::from("/tmp/repo")));
        assert!(cli.repo_file.is_none());
    }

    #[test]
    fn repo_file_alone_parses_fine_without_repo() {
        let cli = Cli::try_parse_from([
            "bc-sast",
            "--repo-file",
            "/tmp/manifest.txt",
            "--gateway-base-url",
            "http://127.0.0.1:0",
        ])
        .unwrap();
        assert!(cli.repo.is_none());
        assert_eq!(cli.repo_file, Some(PathBuf::from("/tmp/manifest.txt")));
    }

    #[test]
    fn neither_repo_nor_repo_file_fails_to_parse() {
        let result = Cli::try_parse_from(["bc-sast", "--gateway-base-url", "http://127.0.0.1:0"]);
        assert!(result.is_err());
    }

    #[test]
    fn both_repo_and_repo_file_fails_to_parse() {
        let result = Cli::try_parse_from([
            "bc-sast",
            "--repo",
            "/tmp/repo",
            "--repo-file",
            "/tmp/manifest.txt",
            "--gateway-base-url",
            "http://127.0.0.1:0",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn build_scan_config_disables_step2_when_no_threat_model_is_set() {
        let mut c = cli(Path::new("/tmp"));
        c.no_threat_model = true;
        assert!(!build_scan_config(&c).unwrap().step2_enabled);
    }

    #[test]
    fn build_scan_config_enables_step2_by_default() {
        assert!(
            build_scan_config(&cli(Path::new("/tmp")))
                .unwrap()
                .step2_enabled
        );
    }

    #[test]
    fn build_scan_config_leaves_spend_cap_unset_by_default() {
        assert!(build_scan_config(&cli(Path::new("/tmp")))
            .unwrap()
            .spend_cap
            .is_none());
    }

    #[test]
    fn build_scan_config_sets_a_spend_cap_from_max_tokens_alone() {
        let mut c = cli(Path::new("/tmp"));
        c.max_tokens = Some(50_000);
        let cap = build_scan_config(&c).unwrap().spend_cap.unwrap();
        assert_eq!(cap.max_total_tokens, Some(50_000));
        assert_eq!(cap.max_wall_clock, None);
    }

    #[test]
    fn build_scan_config_sets_a_spend_cap_from_max_scan_seconds_alone() {
        let mut c = cli(Path::new("/tmp"));
        c.max_scan_seconds = Some(120);
        let cap = build_scan_config(&c).unwrap().spend_cap.unwrap();
        assert_eq!(cap.max_total_tokens, None);
        assert_eq!(
            cap.max_wall_clock,
            Some(std::time::Duration::from_secs(120))
        );
    }

    #[test]
    fn build_scan_config_loads_and_applies_a_yaml_config() {
        let repo_dir = tempfile::tempdir().unwrap();
        let config_dir = tempfile::tempdir().unwrap(); // outside the scan target
        let config_path = config_dir.path().join("config.yaml");
        std::fs::write(
            &config_path,
            "models:\n  preprocess:\n    id: gpt-9\nstep1:\n  max_turns: 5\nstep2:\n  enabled: false\n",
        )
        .unwrap();
        let mut c = cli(repo_dir.path());
        c.config = Some(config_path);
        let config = build_scan_config(&c).unwrap();
        assert_eq!(config.step1.model, "gpt-9");
        assert_eq!(config.step1.max_turns, 5);
        assert!(!config.step2_enabled);
    }

    #[test]
    fn build_scan_config_infers_the_pricing_provider_from_the_gateway_host() {
        let mut c = cli(Path::new("/tmp"));
        c.gateway_base_url = "https://api.openai.com/v1".to_string();
        assert_eq!(
            build_scan_config(&c).unwrap().pricing.provider.as_deref(),
            Some("openai")
        );
    }

    #[test]
    fn build_scan_config_leaves_a_private_gateway_unpriced_rather_than_guessing() {
        // A host that names no provider is the common deployment, and a
        // guess here would produce a confident wrong invoice rather than
        // an approximate one.
        let mut c = cli(Path::new("/tmp"));
        c.gateway_base_url = "https://llm.corp.internal/v1".to_string();
        assert_eq!(build_scan_config(&c).unwrap().pricing.provider, None);
    }

    #[test]
    fn build_scan_config_pricing_provider_flag_overrides_the_inferred_host() {
        let mut c = cli(Path::new("/tmp"));
        c.gateway_base_url = "https://api.openai.com/v1".to_string();
        c.pricing_provider = Some("acme-gateway".to_string());
        assert_eq!(
            build_scan_config(&c).unwrap().pricing.provider.as_deref(),
            Some("acme-gateway")
        );
    }

    #[test]
    fn build_scan_config_pricing_provider_flag_wins_over_the_config_file() {
        let repo_dir = tempfile::tempdir().unwrap();
        let config_dir = tempfile::tempdir().unwrap();
        let config_path = config_dir.path().join("config.yaml");
        std::fs::write(&config_path, "pricing:\n  provider: from-config\n").unwrap();
        let mut c = cli(repo_dir.path());
        c.config = Some(config_path.clone());
        // Config alone wins over the inferred host.
        c.gateway_base_url = "https://api.openai.com/v1".to_string();
        assert_eq!(
            build_scan_config(&c).unwrap().pricing.provider.as_deref(),
            Some("from-config")
        );
        // The flag then wins over the config.
        c.pricing_provider = Some("from-flag".to_string());
        assert_eq!(
            build_scan_config(&c).unwrap().pricing.provider.as_deref(),
            Some("from-flag")
        );
    }

    #[test]
    fn build_scan_config_reads_negotiated_rates_from_the_config_file() {
        let repo_dir = tempfile::tempdir().unwrap();
        let config_dir = tempfile::tempdir().unwrap();
        let config_path = config_dir.path().join("config.yaml");
        std::fs::write(
            &config_path,
            "pricing:\n  provider: acme-gateway\n  rates:\n    acme-gateway:\n      \
             gpt-4o:\n        input: 250000\n        output: 1000000\n",
        )
        .unwrap();
        let mut c = cli(repo_dir.path());
        c.config = Some(config_path);
        let config = build_scan_config(&c).unwrap();
        let price = config
            .pricing
            .overrides
            .lookup("acme-gateway", "gpt-4o")
            .expect("the negotiated rate is in force");
        assert_eq!(price.input, 250_000);
        assert_eq!(price.output, 1_000_000);
    }

    /// The seed plane is on by default (Python ships it off): a 2026-09-07
    /// live sweep ran all day without a single framework route or seed
    /// taint path because nothing had turned it on.
    #[test]
    fn build_scan_config_step0_enabled_defaults_to_true() {
        assert!(
            build_scan_config(&cli(Path::new("/tmp")))
                .unwrap()
                .step0_enabled
        );
    }

    #[test]
    fn build_scan_config_step0_enabled_is_overridable_via_yaml_config() {
        let repo_dir = tempfile::tempdir().unwrap();
        let config_dir = tempfile::tempdir().unwrap();
        let config_path = config_dir.path().join("config.yaml");
        std::fs::write(&config_path, "step0:\n  enabled: false\n").unwrap();
        let mut c = cli(repo_dir.path());
        c.config = Some(config_path);
        let config = build_scan_config(&c).unwrap();
        // Overridable downward: the YAML turns the default-on plane off.
        assert!(!config.step0_enabled);
        assert!(!config.step0.enabled);
        assert!(config.step0.sources_yaml.is_none());
        assert!(config.step0.sinks_yaml.is_none());
    }

    #[test]
    fn build_scan_config_rejects_runtime_detection_rules_even_when_s0_disabled() {
        let repo = tempfile::tempdir().unwrap();
        let config_dir = tempfile::tempdir().unwrap();
        let path = config_dir.path().join("config.yaml");
        for key in ["sources_yaml", "sinks_yaml"] {
            std::fs::write(
                &path,
                format!("step0:\n  enabled: false\n  {key}: /rules/custom.yaml\n"),
            )
            .unwrap();
            let mut c = cli(repo.path());
            c.config = Some(path.clone());
            let err = build_scan_config(&c)
                .err()
                .expect("runtime rules must fail");
            assert!(err.contains("runtime rule files are no longer supported"));
            assert!(err.contains(key));
        }
    }

    #[test]
    fn build_scan_config_no_threat_model_wins_over_a_yaml_config_enabling_step2() {
        let repo_dir = tempfile::tempdir().unwrap();
        let config_dir = tempfile::tempdir().unwrap();
        let config_path = config_dir.path().join("config.yaml");
        std::fs::write(&config_path, "step2:\n  enabled: true\n").unwrap();
        let mut c = cli(repo_dir.path());
        c.config = Some(config_path);
        c.no_threat_model = true;
        let config = build_scan_config(&c).unwrap();
        assert!(!config.step2_enabled);
    }

    #[test]
    fn build_scan_config_rejects_a_config_resolved_inside_the_scan_target() {
        let repo_dir = tempfile::tempdir().unwrap();
        let config_path = repo_dir.path().join("config.yaml");
        std::fs::write(&config_path, "step1:\n  max_turns: 5\n").unwrap();
        let mut c = cli(repo_dir.path());
        c.config = Some(config_path);
        assert!(build_scan_config(&c).is_err());
    }

    #[test]
    fn build_scan_config_propagates_a_malformed_config_file() {
        let repo_dir = tempfile::tempdir().unwrap();
        let config_dir = tempfile::tempdir().unwrap();
        let config_path = config_dir.path().join("config.yaml");
        std::fs::write(&config_path, "not: [a, valid\n").unwrap();
        let mut c = cli(repo_dir.path());
        c.config = Some(config_path);
        assert!(build_scan_config(&c).is_err());
    }

    #[test]
    fn named_policy_flags_select_built_in_profiles() {
        use clap::Parser;
        let c = Cli::try_parse_from([
            "bc-sast",
            "--gateway-base-url",
            "http://127.0.0.1:1",
            "--repo",
            "/repo",
            "--scan-framework",
            "asvs",
            "--compliance-preset",
            "ssdf",
            "--remediate",
            "--target-tests",
            "generate",
        ])
        .unwrap();
        assert_eq!(c.compliance_preset, ["asvs", "ssdf"]);
        assert_eq!(c.target_tests.as_deref(), Some("generate"));
        assert!(c.compliance_policy.is_empty());
    }

    #[test]
    fn target_testing_toggle_defaults_to_comprehensive_and_accepts_level_alias() {
        use clap::Parser;
        let base = [
            "bc-sast",
            "--gateway-base-url",
            "http://127.0.0.1:1",
            "--repo",
            "/repo",
            "--remediate",
        ];
        let c = Cli::try_parse_from(base.into_iter().chain(["--target-tests"])).unwrap();
        assert_eq!(c.target_tests.as_deref(), Some("comprehensive"));
        let c = Cli::try_parse_from(base.into_iter().chain(["--testing-level", "integration"]))
            .unwrap();
        assert_eq!(c.target_tests.as_deref(), Some("integration"));
        let c = Cli::try_parse_from(base).unwrap();
        assert!(c.target_tests.is_none());
    }

    #[test]
    fn every_stop_after_arg_maps_to_its_orchestrator_variant() {
        assert_eq!(StopAfter::from(StopAfterArg::S1), StopAfter::S1);
        assert_eq!(StopAfter::from(StopAfterArg::S2), StopAfter::S2);
        assert_eq!(StopAfter::from(StopAfterArg::S3), StopAfter::S3);
        assert_eq!(StopAfter::from(StopAfterArg::S4), StopAfter::S4);
        assert_eq!(StopAfter::from(StopAfterArg::S5), StopAfter::S5);
        assert_eq!(StopAfter::from(StopAfterArg::S6), StopAfter::S6);
        assert_eq!(StopAfter::from(StopAfterArg::S7), StopAfter::S7);
        assert_eq!(StopAfter::from(StopAfterArg::S8), StopAfter::S8);
        assert_eq!(StopAfter::from(StopAfterArg::S9), StopAfter::S9);
    }

    #[test]
    fn build_scan_input_defaults_repo_name_to_the_repo_directory_name() {
        let input = build_scan_input(&cli(Path::new("/some/where/demo-repo")));
        assert_eq!(input.repo_name, "demo-repo");
    }

    #[test]
    fn build_scan_input_prefers_an_explicit_repo_name() {
        let mut c = cli(Path::new("/some/where/demo-repo"));
        c.repo_name = Some("Custom Name".to_string());
        assert_eq!(build_scan_input(&c).repo_name, "Custom Name");
    }

    #[test]
    fn build_scan_input_threads_cmdb_and_app_id_through() {
        let mut c = cli(Path::new("/repo"));
        c.app_id = "42".to_string();
        c.cmdb_csv = "/cmdb.csv".to_string();
        let input = build_scan_input(&c);
        assert_eq!(input.application_id.as_deref(), Some("42"));
        assert_eq!(input.cmdb_path.as_deref(), Some(Path::new("/cmdb.csv")));
    }

    #[test]
    fn build_scan_input_treats_an_empty_app_id_and_cmdb_csv_as_not_provided() {
        let c = cli(Path::new("/repo"));
        let input = build_scan_input(&c);
        assert!(input.application_id.is_none());
        assert!(input.cmdb_path.is_none());
    }

    #[test]
    fn build_scan_input_threads_an_explicit_git_sha_through() {
        let mut c = cli(Path::new("/repo"));
        c.git_sha = "deadbeef".to_string();
        let input = build_scan_input(&c);
        assert_eq!(input.git_sha_override.as_deref(), Some("deadbeef"));
    }

    #[test]
    fn build_scan_input_treats_an_empty_git_sha_as_not_provided() {
        let c = cli(Path::new("/repo"));
        let input = build_scan_input(&c);
        assert!(input.git_sha_override.is_none());
    }

    /// Every artifact, with no output flag passed at all: the shape a
    /// bare `bc-sast --repo <path>` gets.
    #[test]
    fn resolve_output_paths_defaults_every_artifact_under_the_repo() {
        let paths = resolve_output_paths(&cli(Path::new("/repo")));
        assert_eq!(paths.markdown, Path::new("/repo/security-scan/report.md"));
        assert_eq!(paths.sarif, Path::new("/repo/security-scan/report.sarif"));
        assert_eq!(paths.csv, Path::new("/repo/security-scan/report.csv"));
        assert_eq!(
            paths.findings_json,
            Path::new("/repo/security-scan/findings.json")
        );
    }

    #[test]
    fn resolve_output_paths_moves_every_artifact_with_out_dir() {
        let mut c = cli(Path::new("/repo"));
        c.out_dir = Some(PathBuf::from("/elsewhere"));
        let paths = resolve_output_paths(&c);
        assert_eq!(paths.markdown, Path::new("/elsewhere/report.md"));
        assert_eq!(paths.sarif, Path::new("/elsewhere/report.sarif"));
        assert_eq!(paths.csv, Path::new("/elsewhere/report.csv"));
        assert_eq!(paths.findings_json, Path::new("/elsewhere/findings.json"));
    }

    #[test]
    fn resolve_output_paths_prefers_explicit_overrides() {
        let mut c = cli(Path::new("/repo"));
        c.out_md = Some(PathBuf::from("/custom/out.md"));
        c.out_sarif = Some(PathBuf::from("/custom/out.sarif"));
        c.out_csv = Some(PathBuf::from("/custom/out.csv"));
        c.out_findings_json = Some(PathBuf::from("/custom/out.json"));
        let paths = resolve_output_paths(&c);
        assert_eq!(paths.markdown, Path::new("/custom/out.md"));
        assert_eq!(paths.sarif, Path::new("/custom/out.sarif"));
        assert_eq!(paths.csv, Path::new("/custom/out.csv"));
        assert_eq!(paths.findings_json, Path::new("/custom/out.json"));
    }

    /// Every path that was NOT the one moved is still in the out-dir.
    fn assert_the_others_stayed_in_the_out_dir(paths: &OutputPaths, moved: &Path) {
        let others: Vec<&Path> = [
            paths.markdown.as_path(),
            paths.sarif.as_path(),
            paths.csv.as_path(),
            paths.findings_json.as_path(),
        ]
        .into_iter()
        .filter(|p| *p != moved)
        .collect();
        assert_eq!(others.len(), 3, "{others:?}");
        assert!(
            others
                .iter()
                .all(|p| p.parent() == Some(Path::new("/elsewhere"))),
            "{others:?}"
        );
    }

    fn cli_with_out_dir() -> Cli {
        let mut c = cli(Path::new("/repo"));
        c.out_dir = Some(PathBuf::from("/elsewhere"));
        c
    }

    /// Each `--out-*` flag moves ONLY its own format; everything else
    /// stays in the out-dir. Proven one format at a time, so a flag that
    /// silently redirected a neighbor would fail here.
    #[test]
    fn each_out_flag_overrides_only_its_own_format() {
        let custom = PathBuf::from("/custom/x");

        let mut c = cli_with_out_dir();
        c.out_md = Some(custom.clone());
        let paths = resolve_output_paths(&c);
        assert_eq!(paths.markdown, custom);
        assert_the_others_stayed_in_the_out_dir(&paths, &custom);

        let mut c = cli_with_out_dir();
        c.out_sarif = Some(custom.clone());
        let paths = resolve_output_paths(&c);
        assert_eq!(paths.sarif, custom);
        assert_the_others_stayed_in_the_out_dir(&paths, &custom);

        let mut c = cli_with_out_dir();
        c.out_csv = Some(custom.clone());
        let paths = resolve_output_paths(&c);
        assert_eq!(paths.csv, custom);
        assert_the_others_stayed_in_the_out_dir(&paths, &custom);

        let mut c = cli_with_out_dir();
        c.out_findings_json = Some(custom.clone());
        let paths = resolve_output_paths(&c);
        assert_eq!(paths.findings_json, custom);
        assert_the_others_stayed_in_the_out_dir(&paths, &custom);
    }

    #[test]
    fn ensure_dirs_creates_every_missing_output_directory() {
        let dir = tempfile::tempdir().unwrap();
        let paths = OutputPaths {
            provider_writeback_plan: None,
            markdown: dir.path().join("reports/report.md"),
            sarif: dir.path().join("reports/report.sarif"),
            csv: dir.path().join("reports/report.csv"),
            findings_json: dir.path().join("exports/findings.json"),
        };
        paths.ensure_dirs().unwrap();
        assert!(dir.path().join("reports").is_dir());
        assert!(dir.path().join("exports").is_dir());
    }

    /// A bare relative filename's parent is `""`, which names the working
    /// directory and must not be handed to `create_dir_all`.
    #[test]
    fn ensure_dirs_skips_a_path_with_no_directory_component() {
        let paths = OutputPaths {
            provider_writeback_plan: None,
            markdown: PathBuf::from("report.md"),
            sarif: PathBuf::from("report.sarif"),
            csv: PathBuf::from("report.csv"),
            findings_json: PathBuf::from("findings.json"),
        };
        assert!(paths.ensure_dirs().is_ok());
        assert!(!Path::new("report.md").exists());
    }

    #[cfg(unix)]
    #[test]
    fn ensure_dirs_reports_a_directory_it_cannot_create() {
        // A path component is a regular file, so the directory cannot be
        // created (ENOTDIR) by any user. A mode 000 directory would not
        // stop root, which bypasses permission bits.
        let dir = tempfile::tempdir().unwrap();
        let unwritable = dir.path().join("locked");
        std::fs::write(&unwritable, "not a directory").unwrap();
        let paths = out_paths(&unwritable.join("nested"));

        let err = paths.ensure_dirs().unwrap_err();

        assert!(err.contains("cannot create output directory"), "{err}");
        assert!(err.contains("nested"), "{err}");
    }

    #[test]
    fn build_llm_client_constructs_an_openai_client_by_default() {
        assert!(build_llm_client(&cli(Path::new("/repo"))).is_ok());
    }

    #[test]
    fn the_model_default_is_the_reasoning_model_and_the_new_flags_parse() {
        let base = ["bc-sast", "--repo", "/r", "--gateway-base-url", "http://h"];
        let cli = Cli::try_parse_from(base).unwrap();
        assert_eq!(cli.model, "gpt-5.6-luna");
        assert_eq!(cli.reasoning_effort, None);
        assert!(!cli.no_cache_markers && !cli.allow_unsupported_model && !cli.cache_probe);

        let cli = Cli::try_parse_from(base.into_iter().chain([
            "--reasoning-effort",
            "XHigh",
            "--openai-api",
            "responses",
            "--no-cache-markers",
            "--allow-unsupported-model",
            "--doctor",
            "--cache-probe",
        ]))
        .unwrap();
        assert_eq!(
            cli.reasoning_effort,
            Some(bc_llm_client::ReasoningEffort::XHigh)
        );
        assert_eq!(cli.openai_api, Some(bc_llm_client::OpenAiApi::Responses));
        assert!(cli.no_cache_markers && cli.allow_unsupported_model && cli.cache_probe);

        for bad in [
            &["--reasoning-effort", "extreme"][..],
            &["--openai-api", "grpc"],
            // Spends tokens, so only ever as part of an explicit doctor run.
            &["--cache-probe"],
        ] {
            assert!(Cli::try_parse_from(base.into_iter().chain(bad.iter().copied())).is_err());
        }
    }

    #[test]
    fn bc_openai_api_is_read_from_the_environment_below_the_flag() {
        let _guard = ENV_LOCK.blocking_lock();
        let prior = std::env::var("BC_OPENAI_API").ok();
        std::env::set_var("BC_OPENAI_API", "chat");
        let base = ["bc-sast", "--repo", "/r", "--gateway-base-url", "http://h"];
        let from_env = Cli::try_parse_from(base).unwrap().openai_api;
        let from_flag = Cli::try_parse_from(base.into_iter().chain(["--openai-api", "auto"]))
            .unwrap()
            .openai_api;
        restore_env("BC_OPENAI_API", prior);
        assert_eq!(from_env, Some(bc_llm_client::OpenAiApi::Chat));
        assert_eq!(from_flag, Some(bc_llm_client::OpenAiApi::Auto));
    }

    #[test]
    fn build_llm_stack_resolves_the_transport_and_shares_the_openai_learning() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.yaml");
        std::fs::write(&config, "llm:\n  openai_api: chat\n  cache_ttl: 1h\n").unwrap();
        let mut c = cli(dir.path());
        c.config = Some(config.clone());
        let stack = build_llm_stack(&c).unwrap();
        assert_eq!(stack.settings.openai_api, bc_llm_client::OpenAiApi::Chat);
        assert_eq!(stack.settings.cache.ttl, bc_llm_client::CacheTtl::OneHour);
        assert_eq!(stack.responses_fallbacks(), Some(0));

        c.dialect = Dialect::Anthropic;
        assert_eq!(build_llm_stack(&c).unwrap().responses_fallbacks(), None);

        std::fs::write(&config, "llm:\n  cache_ttl: 2h\n").unwrap();
        let err = build_llm_stack(&c).err().unwrap();
        assert!(err.starts_with("llm.cache_ttl: "), "{err}");
    }

    #[test]
    fn build_scan_config_prices_one_hour_writes_only_on_the_anthropic_dialect() {
        let dir = tempfile::tempdir().unwrap();
        // Outside the scan target, or the trust gate refuses it.
        let config_dir = tempfile::tempdir().unwrap();
        let config = config_dir.path().join("config.yaml");
        std::fs::write(&config, "llm:\n  cache_ttl: 1h\n").unwrap();
        let mut c = cli(dir.path());
        c.config = Some(config);
        assert_eq!(
            build_scan_config(&c).unwrap().pricing.cache_ttl,
            bc_llm_client::CacheTtl::FiveMinutes
        );
        c.dialect = Dialect::Anthropic;
        assert_eq!(
            build_scan_config(&c).unwrap().pricing.cache_ttl,
            bc_llm_client::CacheTtl::OneHour
        );
    }

    #[test]
    fn a_misspelt_effort_in_the_config_fails_the_run_up_front() {
        let dir = tempfile::tempdir().unwrap();
        // Outside the scan target, or the trust gate refuses it.
        let config_dir = tempfile::tempdir().unwrap();
        let config = config_dir.path().join("config.yaml");
        std::fs::write(&config, "models:\n  deepdive:\n    effort: hihg\n").unwrap();
        let mut c = cli(dir.path());
        c.config = Some(config);
        let err = build_scan_config(&c).err().unwrap();
        assert!(err.contains("models.deepdive.effort"), "{err}");
        let err = build_remediate_settings(&c).err().unwrap();
        assert!(err.contains("models.deepdive.effort"), "{err}");
    }

    #[test]
    fn the_effort_flag_and_role_config_reach_the_scan_and_remediation_stages() {
        let dir = tempfile::tempdir().unwrap();
        // Outside the scan target, or the trust gate refuses it.
        let config_dir = tempfile::tempdir().unwrap();
        let config = config_dir.path().join("config.yaml");
        std::fs::write(
            &config,
            "models:\n  verify:\n    effort: max\n    use_responses_api: true\n",
        )
        .unwrap();
        let mut c = cli(dir.path());
        c.config = Some(config);
        c.reasoning_effort = Some(bc_llm_client::ReasoningEffort::Low);
        let scan = build_scan_config(&c).unwrap();
        assert_eq!(
            scan.step6.reasoning_effort,
            Some(bc_llm_client::ReasoningEffort::Max)
        );
        assert_eq!(
            scan.step6.openai_api,
            Some(bc_llm_client::OpenAiApi::Responses)
        );
        assert_eq!(
            scan.step4.reasoning_effort,
            Some(bc_llm_client::ReasoningEffort::Low)
        );
        let remediate = build_remediate_settings(&c).unwrap();
        assert_eq!(
            remediate.config.step10.reasoning_effort,
            Some(bc_llm_client::ReasoningEffort::Low)
        );
        assert_eq!(
            remediate.step11.reasoning_effort,
            Some(bc_llm_client::ReasoningEffort::Low)
        );
    }

    #[tokio::test]
    async fn main_impl_refuses_a_retired_model_before_any_spend() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = cli(dir.path());
        c.model = "claude-2.1".to_string();
        // Preflight on and a gateway that does not exist: the gate has to
        // refuse before the probe would have tried the network.
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
        // And the wrapper is actually installed, not just decided on.
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
        // A bare boolean flag has no "explicitly off" spelling, so it can
        // only ever add to the config's answer.
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("c.yaml");
        std::fs::write(&config, "llm:\n  stream_large_responses: false\n").unwrap();
        let mut c = cli(Path::new("/repo"));
        c.config = Some(config.clone());
        assert!(!stream_large_responses(&c));
        c.stream_large_responses = true;
        assert!(stream_large_responses(&c));
    }

    /// A `--config` that can't be loaded leaves streaming at the flag's
    /// answer rather than failing here — `build_scan_config` reports the
    /// malformed config a moment later, once, in its own words.
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
        // pr_number is still unset.
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

    #[test]
    fn build_semgrep_live_config_returns_none_when_args_are_absent() {
        assert!(build_semgrep_live_config(&cli(Path::new("/repo"))).is_none());
    }

    #[test]
    fn build_semgrep_live_config_returns_none_when_only_some_args_are_present() {
        let mut c = cli(Path::new("/repo"));
        c.semgrep_token = Some("tok".to_string());
        c.semgrep_deployment_slug = Some("deploy".to_string());
        // semgrep_repo is still unset.
        assert!(build_semgrep_live_config(&c).is_none());
    }

    #[test]
    fn build_semgrep_live_config_builds_a_config_when_all_required_args_are_present() {
        let mut c = cli(Path::new("/repo"));
        c.semgrep_token = Some("tok".to_string());
        c.semgrep_deployment_slug = Some("deploy".to_string());
        c.semgrep_repo = Some("org/repo".to_string());
        let config = build_semgrep_live_config(&c).unwrap();
        assert_eq!(config.token, "tok");
        assert_eq!(config.branch, None);
    }

    #[test]
    fn build_semgrep_live_config_applies_optional_branch_and_base_url_overrides() {
        let mut c = cli(Path::new("/repo"));
        c.semgrep_token = Some("tok".to_string());
        c.semgrep_deployment_slug = Some("deploy".to_string());
        c.semgrep_repo = Some("org/repo".to_string());
        c.semgrep_branch = Some("main".to_string());
        c.semgrep_base_url = Some("https://example.test".to_string());
        let config = build_semgrep_live_config(&c).unwrap();
        assert_eq!(config.branch, Some("main".to_string()));
        assert_eq!(config.base_url, "https://example.test");
    }

    #[test]
    fn build_snyk_live_config_returns_none_when_args_are_absent() {
        assert!(build_snyk_live_config(&cli(Path::new("/repo"))).is_none());
    }

    #[test]
    fn build_snyk_live_config_returns_none_when_only_some_args_are_present() {
        let mut c = cli(Path::new("/repo"));
        c.snyk_token = Some("tok".to_string());
        // snyk_org_id/snyk_project_id are still unset.
        assert!(build_snyk_live_config(&c).is_none());
    }

    #[test]
    fn build_snyk_live_config_builds_a_config_when_all_required_args_are_present() {
        let mut c = cli(Path::new("/repo"));
        c.snyk_token = Some("tok".to_string());
        c.snyk_org_id = Some("org-1".to_string());
        c.snyk_project_id = Some("proj-1".to_string());
        let config = build_snyk_live_config(&c).unwrap();
        assert_eq!(config.org_id, "org-1");
        assert_eq!(config.project_id, "proj-1");
    }

    #[test]
    fn build_sonatype_live_config_returns_none_when_args_are_absent() {
        assert!(build_sonatype_live_config(&cli(Path::new("/repo"))).is_none());
    }

    #[test]
    fn build_sonatype_live_config_returns_none_when_only_some_args_are_present() {
        let mut c = cli(Path::new("/repo"));
        c.sonatype_base_url = Some("https://sonatype.test".to_string());
        c.sonatype_username = Some("user".to_string());
        // sonatype_password/sonatype_app_id are still unset.
        assert!(build_sonatype_live_config(&c).is_none());
    }

    #[test]
    fn build_sonatype_live_config_builds_a_config_when_all_required_args_are_present() {
        let mut c = cli(Path::new("/repo"));
        c.sonatype_base_url = Some("https://sonatype.test".to_string());
        c.sonatype_username = Some("user".to_string());
        c.sonatype_password = Some("pass".to_string());
        c.sonatype_app_id = Some("my-app".to_string());
        let config = build_sonatype_live_config(&c).unwrap();
        assert_eq!(config.application_public_id, "my-app");
        assert_eq!(config.stage, "build");
    }

    #[test]
    fn build_sonatype_live_config_applies_an_optional_stage_override() {
        let mut c = cli(Path::new("/repo"));
        c.sonatype_base_url = Some("https://sonatype.test".to_string());
        c.sonatype_username = Some("user".to_string());
        c.sonatype_password = Some("pass".to_string());
        c.sonatype_app_id = Some("my-app".to_string());
        c.sonatype_stage = Some("release".to_string());
        let config = build_sonatype_live_config(&c).unwrap();
        assert_eq!(config.stage, "release");
    }

    #[test]
    fn build_aikido_live_config_returns_none_when_args_are_absent() {
        assert!(build_aikido_live_config(&cli(Path::new("/repo"))).is_none());
    }

    #[test]
    fn build_aikido_live_config_returns_none_when_only_some_args_are_present() {
        let mut c = cli(Path::new("/repo"));
        c.aikido_client_id = Some("id".to_string());
        c.aikido_client_secret = Some("secret".to_string());
        // aikido_repo_id is still unset.
        assert!(build_aikido_live_config(&c).is_none());
    }

    #[test]
    fn build_aikido_live_config_builds_a_config_when_all_required_args_are_present() {
        let mut c = cli(Path::new("/repo"));
        c.aikido_client_id = Some("id".to_string());
        c.aikido_client_secret = Some("secret".to_string());
        c.aikido_repo_id = Some(42);
        let config = build_aikido_live_config(&c).unwrap();
        assert_eq!(config.code_repo_id, 42);
    }

    #[test]
    fn build_aikido_live_config_applies_an_optional_base_url_override() {
        let mut c = cli(Path::new("/repo"));
        c.aikido_client_id = Some("id".to_string());
        c.aikido_client_secret = Some("secret".to_string());
        c.aikido_repo_id = Some(42);
        c.aikido_base_url = Some("https://example.test".to_string());
        let config = build_aikido_live_config(&c).unwrap();
        assert_eq!(config.base_url, "https://example.test");
    }

    #[test]
    fn build_checkmarx_live_config_returns_none_when_args_are_absent() {
        assert!(build_checkmarx_live_config(&cli(Path::new("/repo"))).is_none());
    }

    #[test]
    fn build_checkmarx_live_config_returns_none_when_only_some_args_are_present() {
        let mut c = cli(Path::new("/repo"));
        c.checkmarx_base_url = Some("https://ast.example.test".to_string());
        c.checkmarx_iam_url = Some("https://iam.example.test".to_string());
        // checkmarx_tenant/checkmarx_api_key/checkmarx_project_id are still unset.
        assert!(build_checkmarx_live_config(&c).is_none());
    }

    #[test]
    fn build_checkmarx_live_config_builds_a_config_when_all_required_args_are_present() {
        let mut c = cli(Path::new("/repo"));
        c.checkmarx_base_url = Some("https://ast.example.test".to_string());
        c.checkmarx_iam_url = Some("https://iam.example.test".to_string());
        c.checkmarx_tenant = Some("acme".to_string());
        c.checkmarx_api_key = Some("key".to_string());
        c.checkmarx_project_id = Some("proj-1".to_string());
        let config = build_checkmarx_live_config(&c).unwrap();
        assert_eq!(config.project_id, "proj-1");
        assert_eq!(config.branch, None);
    }

    #[test]
    fn build_checkmarx_live_config_applies_an_optional_branch_filter() {
        let mut c = cli(Path::new("/repo"));
        c.checkmarx_base_url = Some("https://ast.example.test".to_string());
        c.checkmarx_iam_url = Some("https://iam.example.test".to_string());
        c.checkmarx_tenant = Some("acme".to_string());
        c.checkmarx_api_key = Some("key".to_string());
        c.checkmarx_project_id = Some("proj-1".to_string());
        c.checkmarx_branch = Some("main".to_string());
        let config = build_checkmarx_live_config(&c).unwrap();
        assert_eq!(config.branch, Some("main".to_string()));
    }

    #[test]
    fn build_scan_input_wires_all_five_live_vendor_configs_through() {
        let mut c = cli(Path::new("/repo"));
        c.semgrep_token = Some("tok".to_string());
        c.semgrep_deployment_slug = Some("deploy".to_string());
        c.semgrep_repo = Some("org/repo".to_string());
        let input = build_scan_input(&c);
        assert!(input.semgrep_live.is_some());
        assert!(input.snyk_live.is_none());
        assert!(input.sonatype_live.is_none());
        assert!(input.aikido_live.is_none());
        assert!(input.checkmarx_live.is_none());
    }

    #[test]
    fn finish_github_http_client_surfaces_a_real_reqwest_builder_error() {
        // `build_github_client`'s own config surface (a timeout only) can
        // never make `.build()` fail, so this pokes `finish_github_http_client`
        // directly with a builder state (an invalid `user_agent` header
        // value) reqwest's own deferred-error slot does reject — matching
        // `bc-gateway-http::finish`'s identical test for the identical reason.
        let builder = reqwest::Client::builder().user_agent("bad\nvalue");
        let err = finish_github_http_client(builder).unwrap_err();
        assert!(err.contains("failed to build GitHub HTTP client"));
    }

    /// A 200 whose body is `diff`, served at the PR's diff endpoint.
    async fn diff_server(diff: &str) -> wiremock::MockServer {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/repos/acme/widgets/pulls/1"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string(diff))
            .mount(&server)
            .await;
        server
    }

    #[tokio::test]
    async fn resolve_diff_scope_is_a_no_op_when_the_flag_is_unset() {
        let out = resolve_diff_scope(false, None).await.unwrap();
        assert!(!out.active);
        assert!(out.changed_files.is_empty());
    }

    #[tokio::test]
    async fn resolve_diff_scope_errors_without_a_github_client() {
        // `.err().unwrap()` rather than `.unwrap_err()`: the latter needs
        // `DiffScope: Debug`, and a derived `Debug` here would be an
        // uncovered function in a crate held to a function-coverage gate.
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
        // Byte-for-byte the diff `bc_github::diff`'s own
        // `renamed_file_uses_the_post_image_path` test asserts parses to
        // an empty map. That empty map must NOT read as "diff scope was
        // never requested" — that is the fail-open the active flag exists
        // to close.
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

    // ── --pr-comments ───────────────────────────────────────────────

    #[test]
    fn pr_comments_defaults_to_off() {
        let cli = Cli::try_parse_from([
            "bc-sast",
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
            "bc-sast",
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
        // Batch mode never resolves a diff, so accepting the flag would
        // silently full-repo scan every manifest entry while the operator
        // believed the scan was change-focused. Refusing is the only
        // honest option, since there is no single pull request to scope to.
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

    #[tokio::test]
    async fn main_impl_refuses_pr_comments_without_a_diff_scope_before_anything_else_runs() {
        // `--gc` would otherwise short-circuit first: the check running
        // ahead of every mode dispatch is the point.
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
        // Full credentials, no `--pr-comments`: the client exists (the
        // diff fetch needs it) but nothing may be posted through it.
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

    #[test]
    fn load_compliance_policies_is_a_no_op_when_no_flags_are_set() {
        let c = cli(Path::new("/repo"));
        assert!(load_compliance_policies(&c).unwrap().is_empty());
    }

    #[test]
    fn load_compliance_policies_rejects_even_valid_runtime_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.yaml");
        std::fs::write(&path, "name: RuntimeOverride\nguidance: Override scanner\n").unwrap();
        let mut c = cli(Path::new("/repo"));
        c.compliance_policy = vec![path];
        c.compliance_preset = vec!["asvs".into()];
        let err = load_compliance_policies(&c).unwrap_err();
        assert!(err.contains("runtime files are no longer supported"));
    }

    #[test]
    fn load_compliance_policies_rejects_missing_runtime_file_without_loading() {
        let mut c = cli(Path::new("/repo"));
        c.compliance_policy = vec![PathBuf::from("/nonexistent/policy.yaml")];
        assert!(load_compliance_policies(&c).is_err());
    }

    #[test]
    fn load_compliance_policies_resolves_a_built_in_preset_by_name() {
        let mut c = cli(Path::new("/repo"));
        c.compliance_preset = vec!["asvs".to_string()];
        let policies = load_compliance_policies(&c).unwrap();
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0].name, "OWASP ASVS v5.0.0");
    }

    #[test]
    fn load_compliance_policies_propagates_an_unknown_preset_name() {
        let mut c = cli(Path::new("/repo"));
        c.compliance_preset = vec!["nonexistent-framework".to_string()];
        assert!(load_compliance_policies(&c).is_err());
    }

    #[test]
    fn load_compliance_policies_combines_built_in_presets_in_order() {
        let mut c = cli(Path::new("/repo"));
        c.compliance_preset = vec!["ssdf".into(), "asvs".into()];
        let policies = load_compliance_policies(&c).unwrap();
        assert_eq!(policies.len(), 2);
        assert_eq!(
            policies[0].name,
            bc_compliance::preset("ssdf").unwrap().name
        );
        assert_eq!(policies[1].name, "OWASP ASVS v5.0.0");
    }

    #[test]
    fn parse_compliance_scope_is_none_when_unset() {
        assert!(parse_compliance_scope("").unwrap().is_none());
    }

    #[test]
    fn parse_compliance_scope_is_case_insensitive() {
        assert_eq!(
            parse_compliance_scope("Filter").unwrap(),
            Some(bc_compliance::ScopeMode::Filter)
        );
        assert_eq!(
            parse_compliance_scope("ANNOTATE").unwrap(),
            Some(bc_compliance::ScopeMode::Annotate)
        );
    }

    #[test]
    fn parse_compliance_scope_rejects_an_unrecognized_value() {
        let err = parse_compliance_scope("strict").unwrap_err();
        assert!(err.contains("invalid --compliance-scope"));
    }

    #[test]
    fn load_compliance_policies_scope_override_applies_to_every_loaded_policy() {
        let mut c = cli(Path::new("/repo"));
        c.compliance_preset = vec!["ssdf".into(), "asvs".into()];
        c.compliance_scope = "filter".to_string();
        let policies = load_compliance_policies(&c).unwrap();
        assert_eq!(policies.len(), 2);
        assert!(policies
            .iter()
            .all(|p| p.scope_mode == bc_compliance::ScopeMode::Filter));
    }

    #[test]
    fn load_compliance_policies_propagates_an_invalid_scope_override() {
        let mut c = cli(Path::new("/repo"));
        c.compliance_scope = "strict".to_string();
        assert!(load_compliance_policies(&c).is_err());
    }

    #[tokio::test]
    async fn sync_github_returns_none_without_a_client() {
        assert!(sync_github(None, None, None).await.is_none());
    }

    #[tokio::test]
    async fn sync_github_returns_none_without_a_report() {
        let config = bc_github::GithubConfig::new("acme", "widgets", 1, "tok");
        let client = bc_github::GithubClient::new(reqwest::Client::new(), config);
        assert!(sync_github(Some(&client), None, None).await.is_none());
    }

    #[tokio::test]
    async fn sync_github_returns_none_without_a_git_sha() {
        let config = bc_github::GithubConfig::new("acme", "widgets", 1, "tok");
        let client = bc_github::GithubClient::new(reqwest::Client::new(), config);
        let report = bc_model::FinalReport {
            provider_ledger: Default::default(),
            repo_root: "/r".to_string(),
            repo_name: None,
            git_sha: None,
            findings: Vec::new(),
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
        };
        assert!(sync_github(Some(&client), Some(&report), None)
            .await
            .is_none());
    }

    fn sample_report(
        git_sha: Option<&str>,
        findings: Vec<bc_model::Finding>,
    ) -> bc_model::FinalReport {
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

    /// The PR-comment path and the `findings.json` export both read
    /// `report.findings` and nothing else, so a provider finding the
    /// orchestrator set aside as out of diff scope cannot reach either.
    /// `--pr-comments` requires `--diff-scope` precisely because an
    /// unanchorable comment is not worth posting; provider ingestion used
    /// to reintroduce exactly that through a side door.
    #[test]
    fn an_out_of_diff_scope_retention_reaches_neither_pr_comments_nor_findings_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("findings.json");
        let mut report = sample_report(Some("deadbeef"), vec![sample_finding()]);
        report.dropped.push(bc_model::DroppedFinding {
            provider_origins: vec![bc_model::ProviderOrigin::default()],
            verification: None,
            file: "vendor/old.py".to_string(),
            line: 7,
            vuln_class: bc_model::VulnClass::Injection,
            title: "Pre-existing".to_string(),
            chunk_id: "external:semgrep:1".to_string(),
            reason: bc_model::DropReason::OutOfDiffScope,
            detail: "outside the --diff-scope changed-file set".to_string(),
            canonical_idx: None,
        });

        // `sync_github` posts exactly `extract_findings(report)`.
        let posted = extract_findings(&report);
        assert_eq!(posted.len(), 1);
        assert!(posted.iter().all(|f| f.file != "vendor/old.py"));

        assert!(write_findings_json(&path, Some(&report)).unwrap());
        let export: FindingsExport =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(export.findings.len(), 1);
        assert!(export.findings.iter().all(|f| f.file != "vendor/old.py"));
    }

    /// `DiffScope::boundary` is what `main_impl` hands S10, and it must
    /// follow the `active` flag rather than the changed-file count.
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

    #[test]
    fn write_findings_json_is_a_no_op_without_a_report() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("findings.json");
        assert!(!write_findings_json(&path, None).unwrap());
        assert!(!path.exists());
    }

    #[test]
    fn write_findings_json_is_a_no_op_without_a_git_sha() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("findings.json");
        let report = sample_report(None, vec![sample_finding()]);
        assert!(!write_findings_json(&path, Some(&report)).unwrap());
        assert!(!path.exists());
    }

    #[test]
    fn write_findings_json_writes_findings_and_commit_sha() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/findings.json");
        let report = sample_report(Some("deadbeef"), vec![sample_finding()]);
        assert!(write_findings_json(&path, Some(&report)).unwrap());

        let bytes = std::fs::read(&path).unwrap();
        let export: FindingsExport = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(export.commit_sha, "deadbeef");
        assert_eq!(export.findings.len(), 1);
        assert_eq!(export.findings[0].file, "app.py");
    }

    #[cfg(unix)]
    #[test]
    fn write_findings_json_propagates_an_io_error() {
        // A path component is a regular file (ENOTDIR for every user; a
        // mode 000 directory would not stop root).
        let dir = tempfile::tempdir().unwrap();
        let unwritable = dir.path().join("locked");
        std::fs::write(&unwritable, "not a directory").unwrap();
        let path = unwritable.join("nested/findings.json");
        let report = sample_report(Some("sha"), vec![sample_finding()]);
        let result = write_findings_json(&path, Some(&report));
        assert!(result.is_err());
    }

    fn github_client_for(server: &wiremock::MockServer) -> bc_github::GithubClient {
        let mut cfg = bc_github::GithubConfig::new("acme", "widgets", 1, "tok");
        cfg.api_base_url = server.uri();
        bc_github::GithubClient::new(reqwest::Client::new(), cfg)
    }

    fn write_export(dir: &std::path::Path, export: &FindingsExport) -> PathBuf {
        let path = dir.join("findings.json");
        std::fs::write(&path, serde_json::to_string(export).unwrap()).unwrap();
        path
    }

    #[tokio::test]
    async fn post_comments_only_propagates_a_missing_findings_file() {
        let server = wiremock::MockServer::start().await;
        let github = github_client_for(&server);
        let result = post_comments_only(&github, Path::new("/does/not/exist.json"), None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn post_comments_only_propagates_malformed_json() {
        let server = wiremock::MockServer::start().await;
        let github = github_client_for(&server);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("findings.json");
        std::fs::write(&path, "not json").unwrap();
        let result = post_comments_only(&github, &path, None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn post_comments_only_posts_findings_and_reports_success() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/repos/acme/widgets/pulls/1"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string(""))
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(
                "/repos/acme/widgets/pulls/1/comments",
            ))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(
                "/repos/acme/widgets/issues/1/comments",
            ))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path(
                "/repos/acme/widgets/issues/1/comments",
            ))
            .respond_with(wiremock::ResponseTemplate::new(201))
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let path = write_export(
            dir.path(),
            &FindingsExport {
                commit_sha: "sha".to_string(),
                findings: vec![sample_finding()],
            },
        );

        let github = github_client_for(&server);
        let summary = post_comments_only(&github, &path, None).await.unwrap();
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
    async fn post_comments_only_reports_a_github_sync_failure_without_erroring() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/repos/acme/widgets/pulls/1"))
            .respond_with(wiremock::ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let path = write_export(
            dir.path(),
            &FindingsExport {
                commit_sha: "sha".to_string(),
                findings: Vec::new(),
            },
        );

        let github = github_client_for(&server);
        let summary = post_comments_only(&github, &path, None).await.unwrap();
        assert_github_sync_failed(&summary);
    }

    fn write_remediation_export(dir: &std::path::Path, export: &RemediationExport) -> PathBuf {
        let path = dir.join("remediation.json");
        std::fs::write(&path, serde_json::to_string(export).unwrap()).unwrap();
        path
    }

    fn processed_fix_outcome(finding_id: &str, diff: Option<&str>) -> RemediationOutcomeExport {
        RemediationOutcomeExport::Processed(Box::new(RemediationRecordExport {
            finding_index: 1,
            finding_id: finding_id.to_string(),
            verdict: "fixed".to_string(),
            policy_action: None,
            policy_reason: None,
            final_verdict: None,
            changes: Vec::new(),
            summary: "s".to_string(),
            diff: diff.map(str::to_string),
            validation: None,
        }))
    }

    #[tokio::test]
    async fn post_fixes_only_propagates_a_missing_remediation_file() {
        let server = wiremock::MockServer::start().await;
        let github = github_client_for(&server);
        let result = post_fixes_only(&github, Path::new("/does/not/exist.json")).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn post_fixes_only_propagates_malformed_json() {
        let server = wiremock::MockServer::start().await;
        let github = github_client_for(&server);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("remediation.json");
        std::fs::write(&path, "not json").unwrap();
        let result = post_fixes_only(&github, &path).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn post_fixes_only_posts_a_fix_suggestion_and_reports_success() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/repos/acme/widgets/pulls/1"))
            .and(wiremock::matchers::header(
                "Accept",
                "application/vnd.github.v3.diff",
            ))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string(""))
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/repos/acme/widgets/pulls/1"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"head": {"sha": "sha123"}})),
            )
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(
                "/repos/acme/widgets/pulls/1/comments",
            ))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(
                "/repos/acme/widgets/issues/1/comments",
            ))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path(
                "/repos/acme/widgets/issues/1/comments",
            ))
            .respond_with(wiremock::ResponseTemplate::new(201))
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let path = write_remediation_export(
            dir.path(),
            &RemediationExport {
                totals: Default::default(),
                rollup: Default::default(),
                refused: None,
                results: vec![
                    processed_fix_outcome("fid1", Some("diff --git a/x b/x\n+fixed")),
                    // A processed-but-diff-less record (nothing actually
                    // changed on disk) and a failed outcome both have
                    // nothing to post.
                    processed_fix_outcome("fid2", None),
                    RemediationOutcomeExport::Failed {
                        finding_index: 3,
                        error: "boom".to_string(),
                    },
                ],
            },
        );

        let github = github_client_for(&server);
        let summary = post_fixes_only(&github, &path).await.unwrap();
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
    async fn post_fixes_only_with_no_diffs_to_post_is_a_no_op() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/repos/acme/widgets/pulls/1"))
            .and(wiremock::matchers::header(
                "Accept",
                "application/vnd.github.v3.diff",
            ))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string(""))
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/repos/acme/widgets/pulls/1"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"head": {"sha": "sha123"}})),
            )
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(
                "/repos/acme/widgets/pulls/1/comments",
            ))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(
                "/repos/acme/widgets/issues/1/comments",
            ))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let path = write_remediation_export(
            dir.path(),
            &RemediationExport {
                totals: Default::default(),
                rollup: Default::default(),
                refused: None,
                results: vec![processed_fix_outcome("fid1", None)],
            },
        );

        let github = github_client_for(&server);
        let summary = post_fixes_only(&github, &path).await.unwrap();
        assert_eq!(summary.findings, 0);
        assert_eq!(
            summary.github_sync,
            Some(Ok(bc_github::SyncSummary::default()))
        );
    }

    #[tokio::test]
    async fn post_fixes_only_reports_a_github_sync_failure_without_erroring() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(
                "/repos/acme/widgets/pulls/1/comments",
            ))
            .respond_with(wiremock::ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let path = write_remediation_export(
            dir.path(),
            &RemediationExport {
                totals: Default::default(),
                rollup: Default::default(),
                refused: None,
                results: vec![processed_fix_outcome(
                    "fid1",
                    Some("diff --git a/x b/x\n+fixed"),
                )],
            },
        );

        let github = github_client_for(&server);
        let summary = post_fixes_only(&github, &path).await.unwrap();
        assert_github_sync_failed(&summary);
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
        // No `--github-token`/`--github-repo`/`--pr-number` set, and no
        // `--gateway-base-url` either — proves `main_impl` short-circuits
        // to the post-comments-only path before ever touching
        // `build_llm_client`, and that missing GitHub args are caught
        // there rather than inside `post_comments_only` itself.
        let result = main_impl(c).await;
        assert!(result
            .unwrap_err()
            .contains("--post-comments-from requires"));
    }

    #[tokio::test]
    async fn main_impl_requires_github_args_for_diff_scope() {
        let mut c = cli(Path::new("/repo"));
        c.diff_scope = true;
        // No `--github-token`/`--github-repo`/`--pr-number` set.
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
        // A non-retryable 400 (not a connection failure) so this stays
        // fast regardless of `Step1Config`'s shipped retry backoff — same
        // rationale as `main_impl_propagates_a_gateway_error` above.
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
        // An empty --stop-after must reach the real scan path (not be
        // rejected as a malformed value) — it fails downstream on the
        // gateway's 400 instead, proving `parse_stop_after` treated the
        // empty string as `None`, not a parse error.
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

    #[test]
    fn scan_summary_display_reports_a_successful_github_sync() {
        let s = ScanSummary {
            provider_publication: None,
            gc: None,
            cost: None,
            findings: 0,
            markdown_path: None,
            sarif_path: None,
            csv_path: None,
            findings_json_path: None,
            stopped_after: None,
            github_sync: Some(Ok(bc_github::SyncSummary {
                created: 2,
                updated: 1,
            })),
            remediation: None,
            remediation_patch: None,
            baseline: None,
            batch: None,
            estimate: None,
            doctor: None,
            setup: None,
            augmented: None,
        };
        assert!(s.to_string().contains("GitHub: 2 created, 1 updated."));
    }

    #[test]
    fn scan_summary_display_reports_a_failed_github_sync() {
        let s = ScanSummary {
            provider_publication: None,
            gc: None,
            cost: None,
            findings: 0,
            markdown_path: None,
            sarif_path: None,
            csv_path: None,
            findings_json_path: None,
            stopped_after: None,
            github_sync: Some(Err("boom".to_string())),
            remediation: None,
            remediation_patch: None,
            baseline: None,
            batch: None,
            estimate: None,
            doctor: None,
            setup: None,
            augmented: None,
        };
        assert!(s.to_string().contains("GitHub sync failed: boom"));
    }

    #[test]
    fn build_scan_input_falls_back_to_repo_when_the_path_has_no_file_name() {
        // `Path::new("/").file_name()` is `None` (unlike a bare relative
        // filename, whose parent/file_name both resolve normally) — the
        // one input that actually reaches the "repo" fallback.
        let input = build_scan_input(&cli(Path::new("/")));
        assert_eq!(input.repo_name, "repo");
    }

    #[test]
    fn create_parent_dir_of_a_path_with_no_parent_is_a_no_op() {
        // Unlike a bare relative filename (`Path::new("report.md").parent()
        // == Some("")`), only the root path or an empty path has no
        // parent at all.
        assert!(create_parent_dir(Path::new("/")).is_ok());
    }

    #[test]
    fn write_outputs_writes_only_the_files_the_scan_actually_reached() {
        let dir = tempfile::tempdir().unwrap();
        let md_path = dir.path().join("out/report.md");
        let sarif_path = dir.path().join("out/report.sarif");
        let csv_path = dir.path().join("out/report.csv");
        let outcome = ScanOutcome {
            provider_writeback_plan: None,
            stopped_after: None,
            report: None,
            markdown: Some("# report".to_string()),
            sarif: None,
        };
        write_outputs(&outcome, &md_path, &sarif_path, &csv_path).unwrap();
        assert!(md_path.is_file());
        assert!(!sarif_path.is_file());
        assert!(!csv_path.is_file());
    }

    #[test]
    fn write_outputs_writes_both_when_both_are_present() {
        let dir = tempfile::tempdir().unwrap();
        let md_path = dir.path().join("report.md");
        let sarif_path = dir.path().join("report.sarif");
        let csv_path = dir.path().join("report.csv");
        let outcome = ScanOutcome {
            provider_writeback_plan: None,
            stopped_after: None,
            report: None,
            markdown: Some("# report".to_string()),
            sarif: Some("{}".to_string()),
        };
        write_outputs(&outcome, &md_path, &sarif_path, &csv_path).unwrap();
        assert!(md_path.is_file());
        assert!(sarif_path.is_file());
    }

    #[test]
    fn write_outputs_writes_the_csv_when_the_report_is_present() {
        let dir = tempfile::tempdir().unwrap();
        let md_path = dir.path().join("report.md");
        let sarif_path = dir.path().join("report.sarif");
        let csv_path = dir.path().join("report.csv");
        let outcome = ScanOutcome {
            provider_writeback_plan: None,
            stopped_after: None,
            report: Some(bc_model::FinalReport {
                provider_ledger: Default::default(),
                repo_root: "/repo".to_string(),
                repo_name: None,
                git_sha: None,
                findings: Vec::new(),
                chains: Vec::new(),
                dropped: Vec::new(),
                raw_findings_count: 0,
                metrics: None,
                threat_model: None,
                app_profile: None,
                summary: "clean scan".to_string(),
                degraded: false,
                degraded_reason: String::new(),
                unreachable_files: Vec::new(),
            }),
            markdown: None,
            sarif: None,
        };
        write_outputs(&outcome, &md_path, &sarif_path, &csv_path).unwrap();
        assert!(csv_path.is_file());
        assert!(!md_path.is_file());
        assert!(!sarif_path.is_file());
    }

    #[test]
    fn write_outputs_fails_when_the_csv_write_itself_fails() {
        let dir = tempfile::tempdir().unwrap();
        let md_path = dir.path().join("report.md");
        let sarif_path = dir.path().join("report.sarif");
        let csv_path = dir.path().join("report.csv");
        std::fs::create_dir(&csv_path).unwrap();
        let outcome = ScanOutcome {
            provider_writeback_plan: None,
            stopped_after: None,
            report: Some(bc_model::FinalReport {
                provider_ledger: Default::default(),
                repo_root: "/repo".to_string(),
                repo_name: None,
                git_sha: None,
                findings: Vec::new(),
                chains: Vec::new(),
                dropped: Vec::new(),
                raw_findings_count: 0,
                metrics: None,
                threat_model: None,
                app_profile: None,
                summary: "clean scan".to_string(),
                degraded: false,
                degraded_reason: String::new(),
                unreachable_files: Vec::new(),
            }),
            markdown: None,
            sarif: None,
        };
        assert!(write_outputs(&outcome, &md_path, &sarif_path, &csv_path).is_err());
    }

    /// `md_path`'s parent dir creation succeeds (it already exists), but
    /// the write itself fails — `md_path` is an existing directory, so
    /// `std::fs::write` can't create a regular file there.
    #[test]
    fn write_outputs_fails_when_the_markdown_write_itself_fails() {
        let dir = tempfile::tempdir().unwrap();
        let md_path = dir.path().join("report.md");
        std::fs::create_dir(&md_path).unwrap();
        let sarif_path = dir.path().join("report.sarif");
        let csv_path = dir.path().join("report.csv");
        let outcome = ScanOutcome {
            provider_writeback_plan: None,
            stopped_after: None,
            report: None,
            markdown: Some("# report".to_string()),
            sarif: Some("{}".to_string()),
        };
        assert!(write_outputs(&outcome, &md_path, &sarif_path, &csv_path).is_err());
    }

    /// The markdown branch fully succeeds; `sarif_path`'s OWN parent dir
    /// creation fails because a plain FILE (not a directory) already
    /// occupies that exact path.
    #[test]
    fn write_outputs_fails_when_the_sarif_parent_dir_cannot_be_created() {
        let dir = tempfile::tempdir().unwrap();
        let md_path = dir.path().join("report.md");
        let blocker = dir.path().join("blocker");
        std::fs::write(&blocker, b"not a directory").unwrap();
        let sarif_path = blocker.join("nested/report.sarif");
        let csv_path = dir.path().join("report.csv");
        let outcome = ScanOutcome {
            provider_writeback_plan: None,
            stopped_after: None,
            report: None,
            markdown: Some("# report".to_string()),
            sarif: Some("{}".to_string()),
        };
        assert!(write_outputs(&outcome, &md_path, &sarif_path, &csv_path).is_err());
        assert!(md_path.is_file());
    }

    /// Markdown fully succeeds and `sarif_path`'s parent dir creation
    /// succeeds (it already exists); the SARIF write itself fails
    /// because `sarif_path` is an existing directory.
    #[test]
    fn write_outputs_fails_when_the_sarif_write_itself_fails() {
        let dir = tempfile::tempdir().unwrap();
        let md_path = dir.path().join("report.md");
        let sarif_path = dir.path().join("report.sarif");
        std::fs::create_dir(&sarif_path).unwrap();
        let csv_path = dir.path().join("report.csv");
        let outcome = ScanOutcome {
            provider_writeback_plan: None,
            stopped_after: None,
            report: None,
            markdown: Some("# report".to_string()),
            sarif: Some("{}".to_string()),
        };
        assert!(write_outputs(&outcome, &md_path, &sarif_path, &csv_path).is_err());
        assert!(md_path.is_file());
    }

    #[test]
    fn scan_summary_display_reports_a_stop_point() {
        let s = ScanSummary {
            provider_publication: None,
            gc: None,
            cost: None,
            findings: 0,
            markdown_path: None,
            sarif_path: None,
            csv_path: None,
            findings_json_path: None,
            stopped_after: Some(StopAfter::S3),
            github_sync: None,
            remediation: None,
            remediation_patch: None,
            baseline: None,
            batch: None,
            estimate: None,
            doctor: None,
            setup: None,
            augmented: None,
        };
        assert_eq!(s.to_string(), "Scan stopped after S3.");
    }

    #[test]
    fn scan_summary_display_reports_findings_and_paths_on_completion() {
        let s = ScanSummary {
            provider_publication: None,
            gc: None,
            cost: None,
            findings: 2,
            markdown_path: Some(PathBuf::from("/r/report.md")),
            sarif_path: Some(PathBuf::from("/r/report.sarif")),
            csv_path: None,
            findings_json_path: None,
            stopped_after: None,
            github_sync: None,
            remediation: None,
            remediation_patch: None,
            baseline: None,
            batch: None,
            estimate: None,
            doctor: None,
            setup: None,
            augmented: None,
        };
        let text = s.to_string();
        assert!(text.contains("2 finding(s)"));
        assert!(text.contains("/r/report.md"));
        assert!(text.contains("/r/report.sarif"));
        assert!(!text.contains("Cost"), "no metrics, no cost claim: {text}");
    }

    fn summary_with_cost(cost: Option<CostSummary>) -> ScanSummary {
        ScanSummary {
            provider_publication: None,
            gc: None,
            cost,
            findings: 2,
            markdown_path: None,
            sarif_path: None,
            csv_path: None,
            findings_json_path: None,
            stopped_after: None,
            github_sync: None,
            remediation: None,
            remediation_patch: None,
            baseline: None,
            batch: None,
            estimate: None,
            doctor: None,
            setup: None,
            augmented: None,
        }
    }

    #[test]
    fn scan_summary_display_reports_a_priced_run_beside_the_findings_count() {
        let s = summary_with_cost(Some(CostSummary {
            usd: Some(1.5),
            unpriced_tokens: 0,
        }));
        assert_eq!(
            s.to_string(),
            "Scan complete: 2 finding(s). Cost (USD): 1.500000."
        );
    }

    #[test]
    fn scan_summary_display_reports_an_unpriced_run_as_unpriced_never_as_zero() {
        let s = summary_with_cost(Some(CostSummary {
            usd: None,
            unpriced_tokens: 1_700,
        }));
        let text = s.to_string();
        assert!(text.contains("Cost (USD): unpriced"), "{text}");
        assert!(
            text.contains("(1700 token(s) had no published rate)"),
            "{text}"
        );
        assert!(!text.contains("0.000000"), "{text}");
    }

    #[test]
    fn scan_summary_display_flags_a_partly_priced_run_as_a_lower_bound() {
        let s = summary_with_cost(Some(CostSummary {
            usd: Some(0.25),
            unpriced_tokens: 300,
        }));
        assert_eq!(
            s.to_string(),
            "Scan complete: 2 finding(s). Cost (USD): 0.250000 (300 token(s) had no published \
             rate)."
        );
    }

    #[test]
    fn cost_summary_is_absent_when_the_metrics_carry_no_money_at_all() {
        assert_eq!(
            CostSummary::from_metrics(&bc_model::ScanMetrics::default()),
            None
        );
    }

    #[test]
    fn cost_summary_is_present_whenever_either_half_of_the_money_is() {
        let priced = bc_model::ScanMetrics {
            cost_usd: Some(2.0),
            unpriced_tokens: Some(0),
            ..Default::default()
        };
        assert_eq!(
            CostSummary::from_metrics(&priced),
            Some(CostSummary {
                usd: Some(2.0),
                unpriced_tokens: 0
            })
        );
        let unpriced = bc_model::ScanMetrics {
            cost_usd: None,
            unpriced_tokens: Some(9),
            ..Default::default()
        };
        let summary = CostSummary::from_metrics(&unpriced).unwrap();
        assert_eq!(summary.usd, None);
        assert_eq!(summary.unpriced_tokens, 9);
        assert_ne!(summary, CostSummary::from_metrics(&priced).unwrap());
        assert!(format!("{summary:?}").contains("CostSummary"));
        assert_eq!(Clone::clone(&summary), summary);
    }

    // ── `ScanSummary`'s `Display` impl propagates a write failure from
    // its `Formatter` sink at every `write!(...)?` — each of these is
    // only reachable if every EARLIER write in the same `fmt` call
    // already succeeded, so a writer that always errors immediately
    // could only ever exercise the very FIRST one. `ByteBudget` instead
    // fails once a fixed byte budget is exceeded, letting each test
    // allow exactly the known-length PRIOR text through (computed from
    // the literal expected string, not a hardcoded call count — far more
    // robust than counting `write_str` invocations, which varies with
    // how many segments the `write!` macro happens to split a given
    // format string into).
    struct ByteBudget {
        budget: usize,
        written: usize,
    }

    use std::fmt::Write as _;

    impl std::fmt::Write for ByteBudget {
        fn write_str(&mut self, s: &str) -> std::fmt::Result {
            if self.written + s.len() > self.budget {
                return Err(std::fmt::Error);
            }
            self.written += s.len();
            Ok(())
        }
    }

    #[test]
    fn scan_summary_display_propagates_a_write_failure_on_the_stop_line() {
        let s = ScanSummary {
            provider_publication: None,
            gc: None,
            cost: None,
            findings: 0,
            markdown_path: None,
            sarif_path: None,
            csv_path: None,
            findings_json_path: None,
            stopped_after: Some(StopAfter::S3),
            github_sync: None,
            remediation: None,
            remediation_patch: None,
            baseline: None,
            batch: None,
            estimate: None,
            doctor: None,
            setup: None,
            augmented: None,
        };
        let mut w = ByteBudget {
            budget: 0,
            written: 0,
        };
        assert!(write!(w, "{s}").is_err());
    }

    #[test]
    fn scan_summary_display_propagates_a_write_failure_on_the_findings_line() {
        let s = ScanSummary {
            provider_publication: None,
            gc: None,
            cost: None,
            findings: 0,
            markdown_path: None,
            sarif_path: None,
            csv_path: None,
            findings_json_path: None,
            stopped_after: None,
            github_sync: None,
            remediation: None,
            remediation_patch: None,
            baseline: None,
            batch: None,
            estimate: None,
            doctor: None,
            setup: None,
            augmented: None,
        };
        let mut w = ByteBudget {
            budget: 0,
            written: 0,
        };
        assert!(write!(w, "{s}").is_err());
    }

    #[test]
    fn scan_summary_display_propagates_a_write_failure_on_the_cost_line() {
        let s = summary_with_cost(Some(CostSummary {
            usd: Some(1.5),
            unpriced_tokens: 0,
        }));
        let prefix = "Scan complete: 2 finding(s).";
        let mut w = ByteBudget {
            budget: prefix.len(),
            written: 0,
        };
        assert!(write!(w, "{s}").is_err());
    }

    #[test]
    fn cost_summary_display_propagates_a_write_failure_on_its_own_first_write() {
        for usd in [Some(1.5), None] {
            let cost = CostSummary {
                usd,
                unpriced_tokens: 7,
            };
            let mut w = ByteBudget {
                budget: 0,
                written: 0,
            };
            assert!(write!(w, "{cost}").is_err());
        }
    }

    #[test]
    fn scan_summary_display_propagates_a_write_failure_on_the_markdown_path() {
        let s = ScanSummary {
            provider_publication: None,
            gc: None,
            cost: None,
            findings: 0,
            markdown_path: Some(PathBuf::from("/r/report.md")),
            sarif_path: None,
            csv_path: None,
            findings_json_path: None,
            stopped_after: None,
            github_sync: None,
            remediation: None,
            remediation_patch: None,
            baseline: None,
            batch: None,
            estimate: None,
            doctor: None,
            setup: None,
            augmented: None,
        };
        let prefix = "Scan complete: 0 finding(s).";
        let mut w = ByteBudget {
            budget: prefix.len(),
            written: 0,
        };
        assert!(write!(w, "{s}").is_err());
    }

    #[test]
    fn scan_summary_display_propagates_a_write_failure_on_the_sarif_path() {
        let s = ScanSummary {
            provider_publication: None,
            gc: None,
            cost: None,
            findings: 0,
            markdown_path: None,
            sarif_path: Some(PathBuf::from("/r/report.sarif")),
            csv_path: None,
            findings_json_path: None,
            stopped_after: None,
            github_sync: None,
            remediation: None,
            remediation_patch: None,
            baseline: None,
            batch: None,
            estimate: None,
            doctor: None,
            setup: None,
            augmented: None,
        };
        let prefix = "Scan complete: 0 finding(s).";
        let mut w = ByteBudget {
            budget: prefix.len(),
            written: 0,
        };
        assert!(write!(w, "{s}").is_err());
    }

    #[test]
    fn scan_summary_display_propagates_a_write_failure_on_a_successful_github_sync() {
        let s = ScanSummary {
            provider_publication: None,
            gc: None,
            cost: None,
            findings: 0,
            markdown_path: None,
            sarif_path: None,
            csv_path: None,
            findings_json_path: None,
            stopped_after: None,
            github_sync: Some(Ok(bc_github::SyncSummary::default())),
            remediation: None,
            remediation_patch: None,
            baseline: None,
            batch: None,
            estimate: None,
            doctor: None,
            setup: None,
            augmented: None,
        };
        let prefix = "Scan complete: 0 finding(s).";
        let mut w = ByteBudget {
            budget: prefix.len(),
            written: 0,
        };
        assert!(write!(w, "{s}").is_err());
    }

    #[test]
    fn scan_summary_display_propagates_a_write_failure_on_a_failed_github_sync() {
        let s = ScanSummary {
            provider_publication: None,
            gc: None,
            cost: None,
            findings: 0,
            markdown_path: None,
            sarif_path: None,
            csv_path: None,
            findings_json_path: None,
            stopped_after: None,
            github_sync: Some(Err("boom".to_string())),
            remediation: None,
            remediation_patch: None,
            baseline: None,
            batch: None,
            estimate: None,
            doctor: None,
            setup: None,
            augmented: None,
        };
        let prefix = "Scan complete: 0 finding(s).";
        let mut w = ByteBudget {
            budget: prefix.len(),
            written: 0,
        };
        assert!(write!(w, "{s}").is_err());
    }

    #[test]
    fn scan_summary_display_propagates_a_write_failure_on_a_refused_remediation() {
        let s = ScanSummary {
            provider_publication: None,
            gc: None,
            cost: None,
            findings: 0,
            markdown_path: None,
            sarif_path: None,
            csv_path: None,
            findings_json_path: None,
            stopped_after: None,
            github_sync: None,
            remediation: Some(RemediationSummary {
                validation_failures: 0,
                refused: Some("stale".to_string()),
                processed: 0,
                failed: 0,
                validated: None,
                ..Default::default()
            }),
            remediation_patch: None,
            baseline: None,
            batch: None,
            estimate: None,
            doctor: None,
            setup: None,
            augmented: None,
        };
        let prefix = "Scan complete: 0 finding(s).";
        let mut w = ByteBudget {
            budget: prefix.len(),
            written: 0,
        };
        assert!(write!(w, "{s}").is_err());
    }

    #[test]
    fn scan_summary_display_propagates_a_write_failure_on_remediation_counts() {
        let s = ScanSummary {
            provider_publication: None,
            gc: None,
            cost: None,
            findings: 0,
            markdown_path: None,
            sarif_path: None,
            csv_path: None,
            findings_json_path: None,
            stopped_after: None,
            github_sync: None,
            remediation: Some(RemediationSummary {
                validation_failures: 0,
                refused: None,
                processed: 1,
                failed: 2,
                validated: None,
                ..Default::default()
            }),
            remediation_patch: None,
            baseline: None,
            batch: None,
            estimate: None,
            doctor: None,
            setup: None,
            augmented: None,
        };
        let prefix = "Scan complete: 0 finding(s).";
        let mut w = ByteBudget {
            budget: prefix.len(),
            written: 0,
        };
        assert!(write!(w, "{s}").is_err());
    }

    // ── `run()` with fake LlmClient/ToolExecutor, mirroring bc-orchestrator's own test fixtures ──

    type Router = Box<dyn Fn(&str) -> Result<String, LlmError> + Send + Sync>;

    struct RoutedClient {
        router: Router,
    }

    #[async_trait]
    impl LlmClient for RoutedClient {
        async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, LlmError> {
            let system = request.system.as_deref().unwrap_or("");
            let text = (self.router)(system)?;
            Ok(ChatResponse {
                content: vec![ContentBlock::Text(text)],
                stop_reason: StopReason::EndTurn,
                usage: Usage::default(),
            })
        }
    }

    struct NoTools;
    impl ToolExecutor for NoTools {
        fn available_tools(&self) -> Vec<ToolSpec> {
            ["Read", "Glob", "Grep"]
                .iter()
                .map(|name| ToolSpec {
                    name: name.to_string(),
                    description: String::new(),
                    parameters: json!({}),
                })
                .collect()
        }
        fn execute(&self, _name: &str, _args: &Value) -> String {
            String::new()
        }
    }

    fn route(system: &str, table: &[(&str, &str)]) -> String {
        for (mark, reply) in table {
            if system.contains(mark) {
                return (*reply).to_string();
            }
        }
        panic!("unrecognized system prompt in test router: {system}");
    }

    #[test]
    #[should_panic(expected = "unrecognized system prompt")]
    fn route_panics_on_an_unrecognized_system_prompt() {
        route("zzz-totally-unmatched-zzz", &[("xyz-mark-xyz", "reply")]);
    }

    /// A single named function (not a `matches!(...)` repeated inline at
    /// each call site) specifically because a byte-identical assertion
    /// shape at more than one call site can have its coverage
    /// misattributed by `cargo-llvm-cov` (see `feedback_coverage_tool_
    /// gotchas.md` #5) — one shared function only needs covering once,
    /// regardless of how many tests call it.
    fn assert_github_sync_failed(summary: &ScanSummary) {
        match &summary.github_sync {
            Some(Err(_)) => {}
            other => panic!("expected Some(Err(_)), got {other:?}"),
        }
    }

    #[test]
    #[should_panic(expected = "expected Some(Err(_))")]
    fn assert_github_sync_failed_panics_when_it_did_not_fail() {
        assert_github_sync_failed(&ScanSummary {
            provider_publication: None,
            gc: None,
            cost: None,
            findings: 0,
            markdown_path: None,
            sarif_path: None,
            csv_path: None,
            findings_json_path: None,
            stopped_after: None,
            github_sync: None,
            remediation: None,
            remediation_patch: None,
            baseline: None,
            batch: None,
            estimate: None,
            doctor: None,
            setup: None,
            augmented: None,
        });
    }

    fn expect_processed(o: &bc_stage_s10::RemediationOutcome) -> &bc_stage_s10::RemediationRecord {
        match o {
            bc_stage_s10::RemediationOutcome::Processed(record) => record,
            other => panic!("expected Processed, got {other:?}"),
        }
    }

    #[test]
    #[should_panic(expected = "expected Processed")]
    fn expect_processed_panics_on_a_failed_outcome() {
        expect_processed(&bc_stage_s10::RemediationOutcome::Failed {
            finding_index: 1,
            error: "x".to_string(),
        });
    }

    fn assert_processed(o: &bc_stage_s10::RemediationOutcome) {
        match o {
            bc_stage_s10::RemediationOutcome::Processed(_) => {}
            other => panic!("expected Processed, got {other:?}"),
        }
    }

    #[test]
    #[should_panic(expected = "expected Processed")]
    fn assert_processed_panics_on_a_failed_outcome() {
        assert_processed(&bc_stage_s10::RemediationOutcome::Failed {
            finding_index: 1,
            error: "x".to_string(),
        });
    }

    #[test]
    fn no_tools_execute_returns_an_empty_string() {
        assert_eq!(NoTools.execute("Read", &json!({})), "");
    }

    fn empty_scan_client() -> Arc<dyn LlmClient> {
        Arc::new(RoutedClient {
            router: Box::new(|system| {
                Ok(route(
                    system,
                    &[
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
                    ],
                ))
            }),
        })
    }

    fn setup_repo() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("app.py"), "print('hi')\n").unwrap();
        dir
    }

    /// Like `setup_repo`, but a real git repo with one commit — needed so
    /// `bc_orchestrator::head_sha` (and therefore `FinalReport.git_sha`)
    /// resolves to `Some(_)`, the precondition `sync_github` checks before
    /// attempting anything.
    fn git_repo() -> tempfile::TempDir {
        let dir = setup_repo();
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

    /// A `ScanConfig` matching `build_scan_config`'s defaults except for a
    /// zero retry backoff — `Step1Config`'s shipped default starts
    /// exponential backoff at 10 seconds, which would make any test whose
    /// client errors (even non-retryably) needlessly slow to construct
    /// safely against future retry-classification changes.
    pub(crate) fn fast_config() -> ScanConfig {
        let mut step1 = Step1Config::new("m");
        step1.retry_backoff_base = std::time::Duration::ZERO;
        ScanConfig {
            autoexclude: Default::default(),
            cancel: None,
            step0_enabled: false,
            step0: Step0Config::new(),
            step1,
            step2_enabled: true,
            step2: Step2Config::new("m"),
            step3: Step3Config::new("m"),
            step4: Step4Config::new("m"),
            step5: Step5Config::new("m"),
            step6: Step6Config::new("m"),
            step7: Step7Config::new("m"),
            step8: Step8Config::new("m"),
            tool_version: "test".to_string(),
            spend_cap: None,
            checkpoint: None,
            resume: false,
            emit_unreachable_appendix: false,
            progress: None,
            pricing: bc_orchestrator::pricing::PricingConfig::default(),
        }
    }

    fn fast_input(dir: &Path) -> ScanInput {
        build_scan_input(&cli(dir))
    }

    // ── S10 remediation test fixtures ──────────────────────────────────

    const S1_MARK: &str = "security-focused codebase mapper";
    const S2_MARK: &str = "application-security threat modeler";
    const S3_MARK: &str = "vulnerability research strategist";
    const S4_MARK: &str = "security researcher performing deep code analysis";
    const S6_MARK: &str = "second-opinion reviewer";
    const S8_MARK: &str = "exploit development strategist";
    const S10_MARK: &str = "REMEDIATION agent";
    const GOOD_CVSS: &str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";

    fn s4_one_finding_json() -> String {
        json!({"findings": [{
            "file": "app.py", "line_start": 2, "line_end": 3,
            "vuln_class": "injection", "title": "SQL injection",
            "description": "user input reaches a raw query",
            "code_snippet": "cur.execute(q)", "confidence": 0.9,
            "source_ref": "app.py:2", "sink_ref": "app.py:3",
        }]})
        .to_string()
    }

    fn s6_true_positive_text() -> String {
        format!(
            "traced it\nVERDICT: TRUE_POSITIVE (confidence: 9/10) — reachable\nCVSS: {GOOD_CVSS}\n"
        )
    }

    fn s8_ranked_json() -> String {
        json!({
            "summary": "One SQL injection finding.",
            "ranked_findings": [{"index": 0, "severity": "high", "exploitability_notes": "reachable"}],
            "chains": [],
        })
        .to_string()
    }

    fn s10_verdict_json() -> String {
        json!({
            "finding_index": 1, "verdict": "Fixed",
            "gates": {"source": "pass", "sink": "pass", "missing_control": "pass"},
            "root_cause": "x", "changes": [], "remaining_risks": [],
            "recommendations": [], "summary": "s",
        })
        .to_string()
    }

    /// A scan client that produces exactly one true-positive finding
    /// through S1-S8, then — since `run()`'s remediate path reuses the
    /// SAME `llm` for S10 — also answers S10's own SYSTEM-prompt mark
    /// with a canned `Fixed` verdict.
    fn one_finding_client() -> Arc<dyn LlmClient> {
        let s4 = s4_one_finding_json();
        let s6 = s6_true_positive_text();
        let s8 = s8_ranked_json();
        let s10 = s10_verdict_json();
        Arc::new(RoutedClient {
            router: Box::new(move |system| {
                Ok(route(
                    system,
                    &[
                        (
                            S1_MARK,
                            r#"{"language":"python","modules":[],"entry_points":[],"unsafe_sinks":[],"call_graph":{},"notes":""}"#,
                        ),
                        (
                            S2_MARK,
                            r#"{"system_context":"ctx","assets":[],"trust_boundaries":[],"threats":[],"open_questions":[]}"#,
                        ),
                        (
                            S3_MARK,
                            "garbage, s3 degrades to its deterministic catchall sweep",
                        ),
                        (S4_MARK, &s4),
                        (S6_MARK, &s6),
                        (S8_MARK, &s8),
                        (S10_MARK, &s10),
                    ],
                ))
            }),
        })
    }

    /// A client that only ever answers S10's own SYSTEM-prompt mark —
    /// for tests that call `remediate_interactively`/S10 directly,
    /// without running the S1-S8 scan pipeline first.
    fn one_finding_client_s10_only() -> Arc<dyn LlmClient> {
        let s10 = s10_verdict_json();
        Arc::new(RoutedClient {
            router: Box::new(move |system| Ok(route(system, &[(S10_MARK, &s10)]))),
        })
    }

    const S11_ARCHITECT_MARK: &str = "security architect";
    const S11_PENTESTER_MARK: &str = "penetration tester";

    fn s11_all_pass_gates_json() -> String {
        json!({"gates": [
            {"gate_name": "root_cause", "status": "pass", "summary": "ok", "evidence": [{"file": "app.py", "line": 2, "snippet": "print('fixed')"}], "details": ""},
            {"gate_name": "instance_coverage", "status": "pass", "summary": "ok", "evidence": [], "details": ""},
            {"gate_name": "no_new_vulnerabilities", "status": "pass", "summary": "ok", "evidence": [], "details": ""},
            {"gate_name": "security_best_practices", "status": "pass", "summary": "ok", "evidence": [], "details": ""},
        ]})
        .to_string()
    }

    /// Like [`one_finding_client`], but S10's own mark actually issues a
    /// `Write` tool call on its FIRST turn (so `capture_diff` has a real,
    /// on-disk change to diff — `s10_verdict_json`'s plain-text-only reply
    /// never touches disk, so S11 would always see `diff.is_none()` and
    /// skip) before answering with the verdict text on the next turn;
    /// also answers S11's two persona system-prompt marks with a canned
    /// all-pass response — for `run()`-level tests proving the
    /// `validate_enabled` dispatch actually reaches S11 end to end.
    struct OneFindingClientWithValidation {
        remediate_turn: std::sync::atomic::AtomicU32,
    }

    impl OneFindingClientWithValidation {
        fn new() -> Self {
            OneFindingClientWithValidation {
                remediate_turn: std::sync::atomic::AtomicU32::new(0),
            }
        }
    }

    #[async_trait]
    impl LlmClient for OneFindingClientWithValidation {
        async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, LlmError> {
            let system = request.system.as_deref().unwrap_or("");
            if system.contains(S10_MARK) {
                let turn = self
                    .remediate_turn
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if turn == 0 {
                    return Ok(ChatResponse {
                        content: vec![ContentBlock::ToolUse {
                            id: "1".to_string(),
                            name: "Write".to_string(),
                            input: json!({"path": "app.py", "content": "print('fixed')\n"}),
                        }],
                        stop_reason: StopReason::ToolUse,
                        usage: Usage::default(),
                    });
                }
                let verdict = json!({
                    "finding_index": 1, "verdict": "Fixed",
                    "gates": {"source": "pass", "sink": "pass", "missing_control": "pass"},
                    "root_cause": "x",
                    "changes": [{"file": "app.py", "summary": "fixed it"}],
                    "remaining_risks": [], "recommendations": [], "summary": "s",
                })
                .to_string();
                return Ok(ChatResponse {
                    content: vec![ContentBlock::Text(verdict)],
                    stop_reason: StopReason::EndTurn,
                    usage: Usage::default(),
                });
            }
            let s4 = s4_one_finding_json();
            let s6 = s6_true_positive_text();
            let s8 = s8_ranked_json();
            let s11 = s11_all_pass_gates_json();
            let text = route(
                system,
                &[
                    (
                        S1_MARK,
                        r#"{"language":"python","modules":[],"entry_points":[],"unsafe_sinks":[],"call_graph":{},"notes":""}"#,
                    ),
                    (
                        S2_MARK,
                        r#"{"system_context":"ctx","assets":[],"trust_boundaries":[],"threats":[],"open_questions":[]}"#,
                    ),
                    (
                        S3_MARK,
                        "garbage, s3 degrades to its deterministic catchall sweep",
                    ),
                    (S4_MARK, &s4),
                    (S6_MARK, &s6),
                    (S8_MARK, &s8),
                    (S11_ARCHITECT_MARK, &s11),
                    (S11_PENTESTER_MARK, &s11),
                ],
            );
            Ok(ChatResponse {
                content: vec![ContentBlock::Text(text)],
                stop_reason: StopReason::EndTurn,
                usage: Usage::default(),
            })
        }
    }

    /// `fast_config()` with S7's semantic-dedup pass disabled — a single
    /// finding trivially dedups alone, so no canned semantic reply is
    /// needed either.
    fn fast_config_no_semantic_dedup() -> ScanConfig {
        let mut config = fast_config();
        config.step7.semantic = false;
        config
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

    #[test]
    fn target_test_generation_sees_only_the_findings_remediation_will_fix() {
        // The generator used to be handed every finding in the report,
        // so a run asking for one fix paid to describe all of them and
        // proposed tests for code it was never going to touch.
        let mut low = sample_finding();
        low.title = "low-ranked-finding".into();
        // No numeric score, so selection falls back to the severity band
        // the report ranked it in, exactly as S10's own selection does.
        low.cvss_score = None;
        let mut high = sample_finding();
        high.title = "high-ranked-finding".into();
        high.cvss_score = Some(9.4);
        let report = sample_report(None, vec![low, high]);
        let mut config = bc_orchestrator::RemediateConfig {
            step10: fast_remediate_config(),
            top: None,
            top_default: None,
            force: false,
            resume: false,
            isolated: true,
        };

        let everything = target_test_findings(&report, &config);
        assert!(everything.contains("low-ranked-finding"));
        assert!(everything.contains("high-ranked-finding"));

        config.top = Some(bc_stage_s10::TopSpec::N(1));
        let requested = target_test_findings(&report, &config);
        assert!(requested.contains("high-ranked-finding"));
        assert!(
            !requested.contains("low-ranked-finding"),
            "a --top 1 run must not describe the finding it will not fix"
        );
    }

    #[tokio::test]
    async fn run_writes_markdown_and_sarif_and_reports_a_summary() {
        let dir = setup_repo();
        let paths = out_paths(&dir.path().join("out"));
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
        assert_eq!(summary.findings, 0);
        assert_eq!(
            summary.markdown_path.as_deref(),
            Some(paths.markdown.as_path())
        );
        assert_eq!(summary.sarif_path.as_deref(), Some(paths.sarif.as_path()));
        assert!(paths.markdown.is_file());
        assert!(paths.sarif.is_file());
        assert_eq!(summary.stopped_after, None);
        // This backend reports no usage at all, so there is nothing to
        // say about the cost, including that it was zero.
        assert_eq!(summary.cost, None);
        assert!(!std::fs::read_to_string(&paths.markdown)
            .unwrap()
            .contains("Cost (USD)"));
    }

    /// [`fast_config`] pointed at a real provider with every stage on a
    /// real model. `gpt-4o` is the CLI's own default and a vendored entry:
    /// 2.50 USD per million input tokens, 10.00 per million output.
    fn priced_fast_config(model: &str) -> ScanConfig {
        let mut config = fast_config();
        config.pricing = bc_orchestrator::pricing::PricingConfig::for_provider(Some("openai"));
        config.step1.model = model.to_string();
        config.step2.model = model.to_string();
        config.step3.model = model.to_string();
        config.step4.model = model.to_string();
        config.step5.dedup.model = model.to_string();
        config.step6.model = model.to_string();
        config.step7.model = model.to_string();
        config.step8.model = model.to_string();
        config
    }

    /// Wraps a client to stamp the same usage on every reply, so a scan
    /// with fakes still bills something and can be priced.
    struct UsageInjectingClient {
        inner: Arc<dyn LlmClient>,
        usage: Usage,
    }

    #[async_trait]
    impl LlmClient for UsageInjectingClient {
        async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, LlmError> {
            let mut response = self.inner.chat(request).await?;
            response.usage = self.usage;
            Ok(response)
        }
    }

    /// The whole cost path end to end: a real scan, a real gateway
    /// provider, the vendored rates, and the two surfaces an operator
    /// actually reads.
    #[tokio::test]
    async fn run_prices_a_scan_and_says_so_in_both_the_summary_and_the_report() {
        let dir = setup_repo();
        let paths = out_paths(&dir.path().join("out"));
        // 200,000 input at 2.50 per million plus 50,000 output at 10.00
        // per million is exactly 1.00 USD per call.
        let config = priced_fast_config("gpt-4o");
        let client = Arc::new(UsageInjectingClient {
            inner: empty_scan_client(),
            usage: Usage {
                input_tokens: 200_000,
                output_tokens: 50_000,
                cache_creation_input_tokens: 0,
                cache_read_input_tokens: 0,
            },
        });
        let summary = run(
            fast_input(dir.path()),
            config,
            None,
            &paths,
            client,
            Arc::new(NoTools),
            None,
            None,
            None,
        )
        .await
        .unwrap();

        let cost = summary.cost.expect("a priced run reports its cost");
        let usd = cost.usd.expect("every call had a published rate");
        assert!(usd >= 1.0, "at least one call was billed: {usd}");
        assert_eq!(cost.unpriced_tokens, 0);
        assert!(
            summary
                .to_string()
                .contains(&format!("Cost (USD): {usd:.6}")),
            "{summary}"
        );

        let md = std::fs::read_to_string(&paths.markdown).unwrap();
        assert!(md.contains(&format!("- Cost (USD): {usd:.6}")), "{md}");
        assert!(md.contains("| Cost (USD) |"), "{md}");
        assert!(!md.contains("Unpriced tokens"), "{md}");
    }

    /// The same run against a model the table does not know: every token
    /// is still counted, and the money is reported as absent rather than
    /// as zero.
    #[tokio::test]
    async fn run_reports_an_unpriceable_scan_as_unpriced_in_both_places() {
        let dir = setup_repo();
        let paths = out_paths(&dir.path().join("out"));
        let mut config = priced_fast_config("gpt-4o");
        config.step1.model = "house-blend-9".to_string();
        let client = Arc::new(UsageInjectingClient {
            inner: empty_scan_client(),
            usage: Usage {
                input_tokens: 200_000,
                output_tokens: 50_000,
                cache_creation_input_tokens: 0,
                cache_read_input_tokens: 0,
            },
        });
        let summary = run(
            fast_input(dir.path()),
            config,
            None,
            &paths,
            client,
            Arc::new(NoTools),
            None,
            None,
            None,
        )
        .await
        .unwrap();

        let cost = summary.cost.expect("an unpriced run still reports");
        assert_eq!(cost.unpriced_tokens, 250_000);
        let text = summary.to_string();
        assert!(
            text.contains("250000 token(s) had no published rate"),
            "{text}"
        );

        let md = std::fs::read_to_string(&paths.markdown).unwrap();
        assert!(
            md.contains(
                "- Unpriced tokens: 250000 across 1 call(s) with no published rate \
                 (openai/house-blend-9); the cost above is a lower bound"
            ),
            "{md}"
        );
        assert!(md.contains("| unpriced |"), "{md}");
    }

    #[tokio::test]
    async fn run_with_stop_after_s1_writes_no_files() {
        let dir = setup_repo();
        let paths = out_paths(&dir.path().join("None"));
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
        let summary = run(
            fast_input(dir.path()),
            fast_config(),
            Some(StopAfter::S1),
            &paths,
            client,
            Arc::new(NoTools),
            None,
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(summary.stopped_after, Some(StopAfter::S1));
        assert!(summary.markdown_path.is_none());
        assert!(summary.sarif_path.is_none());
    }

    #[tokio::test]
    async fn run_propagates_a_hard_stage_failure_as_err() {
        let dir = setup_repo();
        let paths = out_paths(&dir.path().join("None"));
        let client: Arc<dyn LlmClient> = Arc::new(RoutedClient {
            router: Box::new(|_| {
                Err(LlmError::InvalidRequest {
                    message: "bad request".to_string(),
                })
            }),
        });
        let result = run(
            fast_input(dir.path()),
            fast_config(),
            None,
            &paths,
            client,
            Arc::new(NoTools),
            None,
            None,
            None,
        )
        .await;
        assert!(result.is_err());
    }

    /// The output directory exists and is writable, so `ensure_dirs`
    /// passes; the Markdown WRITE then fails because a directory already
    /// occupies the file's own path.
    #[tokio::test]
    async fn run_propagates_a_write_outputs_failure() {
        let dir = setup_repo();
        let paths = out_paths(&dir.path().join("out"));
        std::fs::create_dir_all(&paths.markdown).unwrap();

        let result = run(
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
        .await;

        assert!(result.is_err());
    }

    /// The reports have nowhere to go, so `ensure_dirs` refuses before
    /// `run_scan` starts. The error names the directory rather than
    /// surfacing as a bare io error from somewhere deep in the run, and
    /// the run never becomes a panic. (That it refuses BEFORE spending
    /// anything is `ensure_dirs`'s position at the top of `run`, proven
    /// by reading it; a fixture that could only prove it by never being
    /// called would itself be permanently uncovered code.)
    #[cfg(unix)]
    #[tokio::test]
    async fn run_refuses_an_output_directory_it_cannot_create_before_scanning() {
        // A path component is a regular file (ENOTDIR for every user; a
        // mode 000 directory would not stop root).
        let dir = setup_repo();
        let unwritable = dir.path().join("locked");
        std::fs::write(&unwritable, "not a directory").unwrap();
        let paths = out_paths(&unwritable.join("nested"));

        let result = run(
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
        .await;

        let err = result.unwrap_err();
        assert!(err.contains("cannot create output directory"), "{err}");
    }

    #[tokio::test]
    async fn run_propagates_a_write_findings_json_failure() {
        // A real git repo, so `report.git_sha` is `Some(_)` and
        // `write_findings_json` actually attempts to write instead of
        // no-op'ing before ever touching the filesystem. Its directory
        // is fine (`ensure_dirs` has to pass for the write to be reached
        // at all); the file's own path is an existing directory.
        let dir = git_repo();
        let paths = out_paths(&dir.path().join("out"));
        std::fs::create_dir_all(&paths.findings_json).unwrap();

        let result = run(
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
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn run_propagates_a_write_remediation_json_failure() {
        // A real git repo, so the scan reaches a `FinalReport` and `run()`'s
        // remediate branch actually calls `write_remediation_json` instead
        // of skipping it (matching `run_propagates_a_write_findings_json_
        // failure`'s rationale for its own target function). The output
        // path runs through a regular file, outside the scanned repo, so
        // its directory cannot be created (ENOTDIR) by any user; a mode
        // 000 directory would not stop root.
        let dir = git_repo();
        let elsewhere = tempfile::tempdir().unwrap();
        let unwritable = elsewhere.path().join("locked");
        std::fs::write(&unwritable, "not a directory").unwrap();
        let paths = out_paths(&dir.path().join("out"));
        let out_json = unwritable.join("nested/remediation.json");
        let remediate = RemediateRun {
            delivery: None,
            settings: RemediateSettings {
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
            tools: Arc::new(NoTools),
            out_json: Some(out_json),
            checkpoint: None,
            worktree: None,
        };

        let result = run(
            fast_input(dir.path()),
            fast_config(),
            None,
            &paths,
            empty_scan_client(),
            Arc::new(NoTools),
            None,
            Some(remediate),
            None,
        )
        .await;

        assert!(result.is_err());
    }

    // `tests/cli.rs` also drives `main_impl` end to end through the real
    // compiled binary (subprocess + wiremock) to prove the actual `bc-sast`
    // executable works — clap parsing, `--help`, process exit codes. That
    // subprocess's own execution isn't reliably attributed back to this
    // crate's in-process `--lib` coverage profile (a `cargo-llvm-cov`
    // subprocess-coverage limitation, not a gap in what's tested), so
    // `main_impl` is ALSO exercised directly, in-process, against a
    // `wiremock` server here — the two tests are complementary, not
    // redundant.
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
        // A scan ran, so it left a run manifest in the out-dir.
        let manifest: bc_orchestrator::manifest::RunManifest = serde_json::from_str(
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
        // No mock mounted: S1's model call fails and the scan errors out
        // after it started, which is still a run worth recording.
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
        let manifest: bc_orchestrator::manifest::RunManifest =
            serde_json::from_str(&std::fs::read_to_string(out.path().join("m.json")).unwrap())
                .unwrap();
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
        // A top-level `--out-dir` must NOT become one shared directory
        // every entry writes its reports into, where the last entry
        // would overwrite the rest: each falls back to its own
        // `<path>/security-scan/` (see `run_batch`'s per-entry reset).
        let shared = manifest_dir.path().join("shared-out");
        c.out_dir = Some(shared.clone());

        // Batch mode opens a checkpoint store per entry (real
        // `BC_STATE_DIR`/`$HOME` resolution) — redirect it to a throwaway
        // tempdir, matching every other test in this module that reaches
        // `open_checkpoint_store`.
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

        // `run_batch`'s default summary path (`./batch_summary.md`) is
        // relative to the process's CWD, and per-entry `open_checkpoint_store`
        // resolves `$HOME`/`BC_STATE_DIR` — both are global process state, so
        // this needs the same serialization every other env-mutating test in
        // this module uses, extended to cover the CWD swap too.
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
        // A `--config` pointing nowhere makes this specific entry fail
        // inside `build_scan_config`, without touching the network at
        // all — a fast, deterministic per-entry failure.
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
        // A non-retryable 400 (not a connection failure) so this stays
        // fast regardless of `Step1Config`'s shipped retry backoff —
        // `main_impl` builds its `ScanConfig` internally via
        // `build_scan_config` and has no way to inject a zero backoff.
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

        let mut gh_config = bc_github::GithubConfig::new("acme", "widgets", 1, "tok");
        gh_config.api_base_url = github_server.uri();
        let github_client = bc_github::GithubClient::new(reqwest::Client::new(), gh_config);

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
            Some(Ok(bc_github::SyncSummary::default()))
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

        let mut gh_config = bc_github::GithubConfig::new("acme", "widgets", 1, "tok");
        gh_config.api_base_url = github_server.uri();
        let github_client = bc_github::GithubClient::new(reqwest::Client::new(), gh_config);

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
        // The scan's own artifacts still got written despite the sync
        // failure — a delivery-layer error must not erase real scan output.
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
        let mut gh_config = bc_github::GithubConfig::new("acme", "widgets", 1, "tok");
        // Deliberately unreachable — proves `run()` never even tries to
        // call out when the scan stops before producing a `FinalReport`.
        gh_config.api_base_url = "http://127.0.0.1:1".to_string();
        let github_client = bc_github::GithubClient::new(reqwest::Client::new(), gh_config);

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

    // ── S10 remediation wiring ──────────────────────────────────────────

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

    #[test]
    fn build_remediate_settings_force_flag_is_threaded_through() {
        let mut c = cli(Path::new("/tmp"));
        c.force = true;
        let settings = build_remediate_settings(&c).unwrap();
        assert!(settings.config.force);
    }

    #[test]
    fn build_remediate_settings_top_flag_parses_a_top_spec() {
        let mut c = cli(Path::new("/tmp"));
        c.top = Some("3".to_string());
        let settings = build_remediate_settings(&c).unwrap();
        assert_eq!(settings.config.top, Some(bc_stage_s10::TopSpec::N(3)));
    }

    #[test]
    fn build_remediate_settings_propagates_an_invalid_top_value() {
        let mut c = cli(Path::new("/tmp"));
        c.top = Some("not-a-number".to_string());
        assert!(build_remediate_settings(&c).is_err());
    }

    #[test]
    fn build_remediate_settings_rejects_a_config_resolved_inside_the_scan_target() {
        let repo_dir = tempfile::tempdir().unwrap();
        let config_path = repo_dir.path().join("config.yaml");
        std::fs::write(&config_path, "step_remediate:\n  max_turns: 5\n").unwrap();
        let mut c = cli(repo_dir.path());
        c.config = Some(config_path);
        assert!(build_remediate_settings(&c).is_err());
    }

    #[tokio::test]
    async fn build_remediate_settings_defaults_allow_repo_hints_to_false() {
        let _guard = ENV_LOCK.lock().await;
        let prior = std::env::var("BC_ALLOW_CWD_CONFIG").ok();
        unsafe {
            std::env::remove_var("BC_ALLOW_CWD_CONFIG");
        }
        let dir = tempfile::tempdir().unwrap();
        let settings = build_remediate_settings(&cli(dir.path())).unwrap();
        assert!(!settings.step11.allow_repo_hints);
        restore_env("BC_ALLOW_CWD_CONFIG", prior);
    }

    #[tokio::test]
    async fn build_remediate_settings_allows_repo_hints_when_bc_allow_cwd_config_is_set() {
        let _guard = ENV_LOCK.lock().await;
        let prior = std::env::var("BC_ALLOW_CWD_CONFIG").ok();
        unsafe {
            std::env::set_var("BC_ALLOW_CWD_CONFIG", "1");
        }
        let dir = tempfile::tempdir().unwrap();
        let settings = build_remediate_settings(&cli(dir.path())).unwrap();
        assert!(settings.step11.allow_repo_hints);
        restore_env("BC_ALLOW_CWD_CONFIG", prior);
    }

    #[test]
    fn build_remediate_settings_propagates_a_malformed_config_file() {
        let repo_dir = tempfile::tempdir().unwrap();
        let config_dir = tempfile::tempdir().unwrap();
        let config_path = config_dir.path().join("config.yaml");
        std::fs::write(&config_path, "not: [a, valid\n").unwrap();
        let mut c = cli(repo_dir.path());
        c.config = Some(config_path);
        assert!(build_remediate_settings(&c).is_err());
    }

    #[test]
    fn build_remediate_settings_reads_the_remediate_model_role_and_top_n_default_from_config() {
        let repo_dir = tempfile::tempdir().unwrap();
        let config_dir = tempfile::tempdir().unwrap(); // outside the scan target
        let config_path = config_dir.path().join("config.yaml");
        std::fs::write(
            &config_path,
            "models:\n  remediate:\n    id: opus\nstep_remediate:\n  top_n_findings: 5\n  max_turns: 12\n",
        )
        .unwrap();
        let mut c = cli(repo_dir.path());
        c.config = Some(config_path);
        let settings = build_remediate_settings(&c).unwrap();
        assert_eq!(settings.config.step10.model, "opus");
        assert_eq!(settings.config.step10.max_turns, 12);
        assert_eq!(
            settings.config.top_default,
            Some(bc_stage_s10::TopSpec::N(5))
        );
    }

    #[test]
    fn build_remediate_settings_defaults_validation_on_without_a_config() {
        let dir = tempfile::tempdir().unwrap();
        let settings = build_remediate_settings(&cli(dir.path())).unwrap();
        assert!(settings.validate_enabled);
    }

    #[test]
    fn build_remediate_settings_reads_the_validate_model_role_and_step_validate_overrides() {
        let repo_dir = tempfile::tempdir().unwrap();
        let config_dir = tempfile::tempdir().unwrap(); // outside the scan target
        let config_path = config_dir.path().join("config.yaml");
        std::fs::write(
            &config_path,
            "models:\n  validate:\n    id: opus\nstep_validate:\n  max_turns: 12\n  allowed_tools: [Read]\n",
        )
        .unwrap();
        let mut c = cli(repo_dir.path());
        c.config = Some(config_path);
        let settings = build_remediate_settings(&c).unwrap();
        // A config that mentions step_validate but not step_validate.enabled
        // must NOT silently disable validation — see
        // `config_overrides::step_validate_enabled_override`'s doc comment.
        assert!(settings.validate_enabled);
        assert_eq!(settings.step11.model, "opus");
        assert_eq!(settings.step11.max_turns, 12);
        assert_eq!(settings.step11.allowed_tools, vec!["Read".to_string()]);
    }

    #[test]
    fn build_remediate_settings_can_disable_validation_via_config() {
        let repo_dir = tempfile::tempdir().unwrap();
        let config_dir = tempfile::tempdir().unwrap(); // outside the scan target
        let config_path = config_dir.path().join("config.yaml");
        std::fs::write(&config_path, "step_validate:\n  enabled: false\n").unwrap();
        let mut c = cli(repo_dir.path());
        c.config = Some(config_path);
        let settings = build_remediate_settings(&c).unwrap();
        assert!(!settings.validate_enabled);
    }

    #[test]
    fn build_remediate_settings_builds_a_policy_context_when_enforcement_is_on() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = cli(dir.path());
        c.enforce_remediation_policy = true;
        let settings = build_remediate_settings(&c).unwrap();
        assert!(settings.policy.is_some());
    }

    #[test]
    fn build_remediate_settings_enforce_policy_can_come_from_config_alone() {
        let repo_dir = tempfile::tempdir().unwrap();
        let config_dir = tempfile::tempdir().unwrap(); // outside the scan target
        let config_path = config_dir.path().join("config.yaml");
        std::fs::write(&config_path, "step_remediate:\n  enforce_policy: true\n").unwrap();
        let mut c = cli(repo_dir.path());
        c.config = Some(config_path);
        let settings = build_remediate_settings(&c).unwrap();
        assert!(settings.policy.is_some());
    }

    #[test]
    fn build_remediate_settings_loads_real_policy_and_playbook_files() {
        let dir = tempfile::tempdir().unwrap();
        let policy_path = dir.path().join("policy.yaml");
        std::fs::write(&policy_path, "default_action: allow\n").unwrap();
        let playbook_path = dir.path().join("playbook.yaml");
        std::fs::write(&playbook_path, "cwe: {}\n").unwrap();
        let mut c = cli(dir.path());
        c.enforce_remediation_policy = true;
        c.remediation_policy = Some(policy_path);
        c.remediation_playbook = Some(playbook_path);
        let settings = build_remediate_settings(&c).unwrap();
        let policy = settings.policy.unwrap();
        let decision = policy.gate.decide("CWE-89", "app.py", &|_| None);
        assert_eq!(decision.action, bc_policy_gate::Action::Patch);
    }

    #[test]
    fn remediation_summary_from_counts_processed_and_failed_outcomes() {
        let outcome = bc_orchestrator::RemediateOutcome {
            validation_failures: 0,
            refused: None,
            outcomes: vec![
                bc_stage_s10::RemediationOutcome::Processed(Box::new(
                    bc_stage_s10::RemediationRecord {
                        finding_index: 1,
                        finding_id: "fid1".to_string(),
                        verdict: bc_stage_s10::RemediationVerdict::denied(1, "x"),
                        policy_action: None,
                        policy_reason: None,
                        final_verdict: None,
                        policy_reverted: Vec::new(),
                        policy_matched_globs: Vec::new(),
                        diff: None,
                    },
                )),
                bc_stage_s10::RemediationOutcome::Failed {
                    finding_index: 2,
                    error: "boom".to_string(),
                },
            ],
            validations: Vec::new(),
        };
        let summary = RemediationSummary::from(&outcome);
        assert!(summary.refused.is_none());
        assert_eq!(summary.processed, 1);
        assert_eq!(summary.failed, 1);
        assert!(summary.validated.is_none());
    }

    #[test]
    fn validations_by_finding_id_skips_a_failed_outcome_but_keeps_a_processed_validated_one() {
        let outcome = bc_orchestrator::RemediateOutcome {
            validation_failures: 0,
            refused: None,
            outcomes: vec![
                bc_stage_s10::RemediationOutcome::Failed {
                    finding_index: 1,
                    error: "boom".to_string(),
                },
                bc_stage_s10::RemediationOutcome::Processed(Box::new(
                    bc_stage_s10::RemediationRecord {
                        finding_index: 2,
                        finding_id: "fid2".to_string(),
                        verdict: bc_stage_s10::RemediationVerdict::denied(2, "x"),
                        policy_action: None,
                        policy_reason: None,
                        final_verdict: None,
                        policy_reverted: Vec::new(),
                        policy_matched_globs: Vec::new(),
                        diff: Some("diff".to_string()),
                    },
                )),
            ],
            validations: vec![
                None,
                Some(validation_score(bc_validation_scoring::FixVerdict::Fixed)),
            ],
        };
        let by_id = validations_by_finding_id(&outcome);
        assert_eq!(by_id.len(), 1);
        assert!(by_id.contains_key("fid2"));
    }

    fn validation_score(
        fix_status: bc_validation_scoring::FixVerdict,
    ) -> bc_validation_scoring::ValidationScore {
        bc_validation_scoring::ValidationScore {
            raw_score: 1.0,
            fix_status,
            justification: String::new(),
            gate_results: Vec::new(),
            has_critical_failure: false,
        }
    }

    #[test]
    fn remediation_summary_from_tallies_every_fix_verdict_when_validation_ran() {
        let outcome = bc_orchestrator::RemediateOutcome {
            validation_failures: 0,
            refused: None,
            outcomes: Vec::new(),
            validations: vec![
                Some(validation_score(bc_validation_scoring::FixVerdict::Fixed)),
                Some(validation_score(
                    bc_validation_scoring::FixVerdict::PartiallyFixed,
                )),
                Some(validation_score(
                    bc_validation_scoring::FixVerdict::NotFixed,
                )),
                Some(validation_score(
                    bc_validation_scoring::FixVerdict::Unverifiable,
                )),
                None,
            ],
        };
        let summary = RemediationSummary::from(&outcome);
        let tally = summary.validated.unwrap();
        assert_eq!(tally.fixed, 1);
        assert_eq!(tally.partially_fixed, 1);
        assert_eq!(tally.not_fixed, 1);
        assert_eq!(tally.unverifiable, 1);
    }

    #[test]
    fn scan_summary_display_reports_a_refused_remediation() {
        let s = ScanSummary {
            provider_publication: None,
            gc: None,
            cost: None,
            findings: 1,
            markdown_path: None,
            sarif_path: None,
            csv_path: None,
            findings_json_path: None,
            stopped_after: None,
            github_sync: None,
            remediation: Some(RemediationSummary {
                validation_failures: 0,
                refused: Some("HEAD moved".to_string()),
                processed: 0,
                failed: 0,
                validated: None,
                ..Default::default()
            }),
            remediation_patch: None,
            baseline: None,
            batch: None,
            estimate: None,
            doctor: None,
            setup: None,
            augmented: None,
        };
        assert!(s.to_string().contains("Remediation refused: HEAD moved"));
    }

    #[test]
    fn scan_summary_display_reports_processed_and_failed_remediation_counts() {
        let s = ScanSummary {
            provider_publication: None,
            gc: None,
            cost: None,
            findings: 1,
            markdown_path: None,
            sarif_path: None,
            csv_path: None,
            findings_json_path: None,
            stopped_after: None,
            github_sync: None,
            remediation: Some(RemediationSummary {
                validation_failures: 0,
                refused: None,
                processed: 2,
                failed: 1,
                validated: None,
                ..Default::default()
            }),
            remediation_patch: None,
            baseline: None,
            batch: None,
            estimate: None,
            doctor: None,
            setup: None,
            augmented: None,
        };
        assert!(s
            .to_string()
            .contains("Remediation: 2 processed, 1 failed. Outcome: 0 fixed, 0 not fixed."));
    }

    #[test]
    fn scan_summary_display_reports_a_validation_tally_when_validation_ran() {
        let s = ScanSummary {
            provider_publication: None,
            gc: None,
            cost: None,
            findings: 1,
            markdown_path: None,
            sarif_path: None,
            csv_path: None,
            findings_json_path: None,
            stopped_after: None,
            github_sync: None,
            remediation: Some(RemediationSummary {
                validation_failures: 0,
                refused: None,
                processed: 4,
                failed: 0,
                validated: Some(ValidationTally {
                    fixed: 1,
                    partially_fixed: 2,
                    not_fixed: 1,
                    unverifiable: 0,
                }),
                ..Default::default()
            }),
            remediation_patch: None,
            baseline: None,
            batch: None,
            estimate: None,
            doctor: None,
            setup: None,
            augmented: None,
        };
        assert!(s
            .to_string()
            .contains("Validation: 1 fixed, 2 partially fixed, 1 not fixed, 0 unverifiable."));
    }

    #[test]
    fn scan_summary_display_reports_validation_failures_when_present() {
        let s = ScanSummary {
            provider_publication: None,
            gc: None,
            cost: None,
            findings: 1,
            markdown_path: None,
            sarif_path: None,
            csv_path: None,
            findings_json_path: None,
            stopped_after: None,
            github_sync: None,
            remediation: Some(RemediationSummary {
                validation_failures: 2,
                refused: None,
                processed: 3,
                failed: 0,
                validated: Some(ValidationTally {
                    fixed: 1,
                    partially_fixed: 0,
                    not_fixed: 0,
                    unverifiable: 0,
                }),
                ..Default::default()
            }),
            remediation_patch: None,
            baseline: None,
            batch: None,
            estimate: None,
            doctor: None,
            setup: None,
            augmented: None,
        };
        assert!(s.to_string().contains("(2 validation error(s).)"));
    }

    #[test]
    fn scan_summary_display_omits_the_validation_failures_note_when_there_are_none() {
        let s = ScanSummary {
            provider_publication: None,
            gc: None,
            cost: None,
            findings: 1,
            markdown_path: None,
            sarif_path: None,
            csv_path: None,
            findings_json_path: None,
            stopped_after: None,
            github_sync: None,
            remediation: Some(RemediationSummary {
                validation_failures: 0,
                refused: None,
                processed: 1,
                failed: 0,
                validated: Some(ValidationTally {
                    fixed: 1,
                    partially_fixed: 0,
                    not_fixed: 0,
                    unverifiable: 0,
                }),
                ..Default::default()
            }),
            remediation_patch: None,
            baseline: None,
            batch: None,
            estimate: None,
            doctor: None,
            setup: None,
            augmented: None,
        };
        assert!(!s.to_string().contains("validation error"));
    }

    #[test]
    fn scan_summary_display_omits_the_validation_line_when_validation_did_not_run() {
        let s = ScanSummary {
            provider_publication: None,
            gc: None,
            cost: None,
            findings: 1,
            markdown_path: None,
            sarif_path: None,
            csv_path: None,
            findings_json_path: None,
            stopped_after: None,
            github_sync: None,
            remediation: Some(RemediationSummary {
                validation_failures: 0,
                refused: None,
                processed: 1,
                failed: 0,
                validated: None,
                ..Default::default()
            }),
            remediation_patch: None,
            baseline: None,
            batch: None,
            estimate: None,
            doctor: None,
            setup: None,
            augmented: None,
        };
        assert!(!s.to_string().contains("Validation:"));
    }

    #[test]
    fn write_remediation_json_is_a_no_op_without_a_path() {
        let outcome = bc_orchestrator::RemediateOutcome::default();
        assert!(write_remediation_json(None, &outcome).is_ok());
    }

    #[test]
    fn write_remediation_json_propagates_an_io_error() {
        // A path component is a regular file (ENOTDIR for every user; a
        // mode 000 directory would not stop root).
        let dir = tempfile::tempdir().unwrap();
        let unwritable = dir.path().join("locked");
        std::fs::write(&unwritable, "not a directory").unwrap();
        let path = unwritable.join("nested/remediation.json");
        let outcome = bc_orchestrator::RemediateOutcome::default();
        let result = write_remediation_json(Some(&path), &outcome);
        assert!(result.is_err());
    }

    #[test]
    fn write_remediation_json_writes_the_refusal_reason_and_results() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out/remediation.json");
        let outcome = bc_orchestrator::RemediateOutcome {
            validation_failures: 0,
            refused: Some("stale".to_string()),
            outcomes: vec![bc_stage_s10::RemediationOutcome::Failed {
                finding_index: 1,
                error: "boom".to_string(),
            }],
            validations: Vec::new(),
        };
        write_remediation_json(Some(&path), &outcome).unwrap();
        let written: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(written["refused"], "stale");
        assert_eq!(written["results"][0]["status"], "failed");
        assert_eq!(written["results"][0]["finding_index"], 1);
    }

    #[test]
    fn write_remediation_json_serializes_a_processed_record_with_its_changes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("remediation.json");
        let mut verdict = bc_stage_s10::RemediationVerdict::denied(1, "x");
        verdict.changes.push(bc_stage_s10::Change {
            file: "app.py".to_string(),
            summary: "fixed it".to_string(),
        });
        let outcome = bc_orchestrator::RemediateOutcome {
            validation_failures: 0,
            refused: None,
            outcomes: vec![bc_stage_s10::RemediationOutcome::Processed(Box::new(
                bc_stage_s10::RemediationRecord {
                    finding_index: 1,
                    finding_id: "fid1".to_string(),
                    verdict,
                    policy_action: Some("patch".to_string()),
                    policy_reason: Some("allow_list".to_string()),
                    final_verdict: Some("ACCEPT".to_string()),
                    policy_reverted: Vec::new(),
                    policy_matched_globs: Vec::new(),
                    diff: Some("diff --git a/app.py b/app.py\n".to_string()),
                },
            ))],
            validations: Vec::new(),
        };
        write_remediation_json(Some(&path), &outcome).unwrap();
        let written: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(written["results"][0]["status"], "processed");
        assert_eq!(written["results"][0]["policy_action"], "patch");
        assert_eq!(written["results"][0]["changes"][0]["file"], "app.py");
        assert_eq!(written["results"][0]["finding_id"], "fid1");
        assert_eq!(
            written["results"][0]["diff"],
            "diff --git a/app.py b/app.py\n"
        );
    }

    /// A `Processed` record for `finding_id`, with just enough shape for
    /// the report-augmentation helpers under test.
    fn processed_record(
        finding_id: &str,
        verdict: bc_stage_s10::Verdict,
        diff: Option<&str>,
    ) -> bc_stage_s10::RemediationOutcome {
        let mut v = bc_stage_s10::RemediationVerdict::denied(1, "summary text");
        v.verdict = verdict;
        v.root_cause = "unsanitized input".to_string();
        v.remaining_risks = vec!["other call sites".to_string()];
        v.recommendations = vec!["add a test".to_string()];
        v.changes.push(bc_stage_s10::Change {
            file: "app.py".to_string(),
            summary: "parameterized the query".to_string(),
        });
        bc_stage_s10::RemediationOutcome::Processed(Box::new(bc_stage_s10::RemediationRecord {
            finding_index: 1,
            finding_id: finding_id.to_string(),
            verdict: v,
            policy_action: None,
            policy_reason: None,
            final_verdict: None,
            policy_reverted: Vec::new(),
            policy_matched_globs: Vec::new(),
            diff: diff.map(str::to_string),
        }))
    }

    /// A `ScanSummary` with every optional field empty — the base each
    /// `Display` test below varies exactly one field of.
    fn base_summary() -> ScanSummary {
        ScanSummary {
            provider_publication: None,
            gc: None,
            cost: None,
            findings: 0,
            markdown_path: None,
            sarif_path: None,
            csv_path: None,
            findings_json_path: None,
            stopped_after: None,
            github_sync: None,
            remediation: None,
            remediation_patch: None,
            baseline: None,
            batch: None,
            estimate: None,
            doctor: None,
            setup: None,
            augmented: None,
        }
    }

    #[test]
    fn injection_is_empty_without_a_flag_or_config_key() {
        let dir = tempfile::tempdir().unwrap();
        let input = build_scan_input(&cli(dir.path()));
        assert!(input.known_cves.is_empty());
        assert!(input.design_controls.is_empty());
    }

    #[test]
    fn cve_and_controls_flags_populate_the_scan_input() {
        let dir = tempfile::tempdir().unwrap();
        let cves = dir.path().join("cves.json");
        std::fs::write(
            &cves,
            r#"{"cves": [{"id": "CVE-2021-44228", "summary": "Log4Shell"}]}"#,
        )
        .unwrap();
        let controls = dir.path().join("controls.yaml");
        std::fs::write(
            &controls,
            "controls:\n  - name: C-1\n    kind: authz\n    notes: RBAC on every route\n",
        )
        .unwrap();
        let mut c = cli(dir.path());
        c.cve_file = Some(cves);
        c.controls_file = Some(controls);
        let input = build_scan_input(&c);
        assert_eq!(input.known_cves.len(), 1);
        assert_eq!(input.known_cves[0].id, "CVE-2021-44228");
        assert_eq!(input.design_controls.len(), 1);
        assert_eq!(input.design_controls[0].name, "C-1");
    }

    #[test]
    fn a_missing_injection_file_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = cli(dir.path());
        c.cve_file = Some(dir.path().join("nope.json"));
        c.controls_file = Some(dir.path().join("nope.yaml"));
        let input = build_scan_input(&c);
        assert!(input.known_cves.is_empty());
        assert!(input.design_controls.is_empty());
    }

    #[test]
    fn a_structurally_broken_injection_file_warns_and_injects_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let cves = dir.path().join("cves.json");
        std::fs::write(&cves, "{ not json at all").unwrap();
        let controls = dir.path().join("controls.yaml");
        std::fs::write(&controls, "controls:\n  - 7\n").unwrap();
        let mut c = cli(dir.path());
        c.cve_file = Some(cves);
        c.controls_file = Some(controls);
        // Warn and continue, not a hard error: these are prompt context,
        // and unlike a compliance policy they cannot change which
        // findings reach the report.
        let input = build_scan_input(&c);
        assert!(input.known_cves.is_empty());
        assert!(input.design_controls.is_empty());
    }

    #[test]
    fn inject_config_keys_resolve_against_the_config_files_own_directory() {
        let repo_dir = tempfile::tempdir().unwrap();
        let config_dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(config_dir.path().join("inputs")).unwrap();
        std::fs::write(
            config_dir.path().join("inputs/known_cves.json"),
            r#"[{"id": "CVE-2020-1", "summary": "from the profile directory"}]"#,
        )
        .unwrap();
        let config_path = config_dir.path().join("config.yaml");
        std::fs::write(
            &config_path,
            "inject:\n  cve_file: ./inputs/known_cves.json\n",
        )
        .unwrap();
        let mut c = cli(repo_dir.path());
        c.config = Some(config_path);
        let input = build_scan_input(&c);
        assert_eq!(input.known_cves.len(), 1);
        assert_eq!(input.known_cves[0].id, "CVE-2020-1");
    }

    #[test]
    fn an_explicit_cve_flag_wins_over_the_config_key() {
        let repo_dir = tempfile::tempdir().unwrap();
        let config_dir = tempfile::tempdir().unwrap();
        let flag_file = config_dir.path().join("flag.json");
        std::fs::write(&flag_file, r#"[{"id": "CVE-FLAG", "summary": "s"}]"#).unwrap();
        let config_path = config_dir.path().join("config.yaml");
        std::fs::write(&config_path, "inject:\n  cve_file: ./missing.json\n").unwrap();
        let mut c = cli(repo_dir.path());
        c.config = Some(config_path);
        c.cve_file = Some(flag_file);
        assert_eq!(build_scan_input(&c).known_cves[0].id, "CVE-FLAG");
    }

    #[test]
    fn global_sampling_flags_apply_without_a_config_file() {
        let mut c = cli(Path::new("/repo"));
        c.temperature = Some(0.0);
        c.top_p = Some(0.75);
        c.seed = Some(11);
        c.step_timeout = Some(45);
        let config = build_scan_config(&c).unwrap();
        assert_eq!(config.step4.temperature, Some(0.0));
        assert_eq!(config.step4.top_p, Some(0.75));
        assert_eq!(config.step4.seed, Some(11));
        // Overrides `Step4Config::new()`'s own shipped 1800 s default.
        assert_eq!(config.step4.timeout_secs, Some(45));
        assert_eq!(config.step1.temperature, Some(0.0));
        assert_eq!(config.step8.seed, Some(11));
    }

    #[test]
    fn without_the_flags_every_stage_keeps_its_own_shipped_timeout() {
        let config = build_scan_config(&cli(Path::new("/repo"))).unwrap();
        assert_eq!(config.step3.timeout_secs, Some(3600));
        assert_eq!(config.step4.timeout_secs, Some(1800));
        assert_eq!(config.step8.timeout_secs, Some(3600));
        assert_eq!(config.step2.timeout_secs, None);
        assert_eq!(config.step2.temperature, None);
    }

    #[test]
    fn global_sampling_flags_reach_s10_and_s11_without_a_config_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = cli(dir.path());
        c.temperature = Some(0.0);
        c.seed = Some(3);
        c.step_timeout = Some(30);
        let settings = build_remediate_settings(&c).unwrap();
        assert_eq!(settings.config.step10.temperature, Some(0.0));
        assert_eq!(settings.config.step10.seed, Some(3));
        assert_eq!(settings.config.step10.timeout_secs, Some(30));
        assert_eq!(settings.step11.temperature, Some(0.0));
        assert_eq!(settings.step11.seed, Some(3));
        assert_eq!(settings.step11.timeout_secs, Some(30));
    }

    #[test]
    fn a_config_files_per_role_sampling_wins_over_the_global_flag_for_s10() {
        let repo_dir = tempfile::tempdir().unwrap();
        let config_dir = tempfile::tempdir().unwrap();
        let config_path = config_dir.path().join("config.yaml");
        std::fs::write(
            &config_path,
            "models:\n  remediate:\n    id: opus\n    temperature: 0.4\n",
        )
        .unwrap();
        let mut c = cli(repo_dir.path());
        c.config = Some(config_path);
        c.temperature = Some(0.0);
        let settings = build_remediate_settings(&c).unwrap();
        assert_eq!(settings.config.step10.model, "opus");
        assert_eq!(settings.config.step10.temperature, Some(0.4));
    }

    #[test]
    fn remediation_gate_flags_override_the_config_values() {
        let mut c = cli(Path::new("/repo"));
        c.no_syntax_check = true;
        c.keep_unverified = true;
        c.max_diff_lines = Some(7);
        c.max_files_touched = Some(9);
        c.remediate_dry_run = true;
        c.verify_command = Some("make check".to_string());
        c.verify_timeout = Some(11);
        let mut step10 = bc_stage_s10::Step10Config::new("m");
        apply_remediation_gate_flags(&c, &mut step10);
        assert!(!step10.syntax_check);
        assert!(step10.keep_unverified);
        assert_eq!(step10.max_diff_lines, 7);
        assert_eq!(step10.max_files_touched, 9);
        assert!(step10.dry_run);
        assert_eq!(step10.verify_command.as_deref(), Some("make check"));
        assert_eq!(step10.verify_timeout_secs, 11);
    }

    #[test]
    fn absent_remediation_gate_flags_leave_every_configured_value_alone() {
        let c = cli(Path::new("/repo"));
        let mut step10 = bc_stage_s10::Step10Config::new("m");
        step10.syntax_check = false;
        step10.keep_unverified = true;
        step10.max_diff_lines = 5;
        step10.max_files_touched = 6;
        step10.dry_run = true;
        step10.verify_command = Some("configured".to_string());
        step10.verify_timeout_secs = 42;
        apply_remediation_gate_flags(&c, &mut step10);
        assert!(!step10.syntax_check);
        assert!(step10.keep_unverified);
        assert_eq!(step10.max_diff_lines, 5);
        assert_eq!(step10.max_files_touched, 6);
        assert!(step10.dry_run);
        assert_eq!(step10.verify_command.as_deref(), Some("configured"));
        assert_eq!(step10.verify_timeout_secs, 42);
    }

    #[test]
    fn build_remediate_settings_reads_policy_paths_from_config() {
        let repo_dir = tempfile::tempdir().unwrap();
        let config_dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(config_dir.path().join("inputs")).unwrap();
        std::fs::write(
            config_dir.path().join("inputs/policy.yaml"),
            "default_action: allow\n",
        )
        .unwrap();
        std::fs::write(config_dir.path().join("inputs/playbook.yaml"), "cwe: {}\n").unwrap();
        let config_path = config_dir.path().join("config.yaml");
        std::fs::write(
            &config_path,
            "step_remediate:\n  enforce_policy: true\n  \
             policy_file: ./inputs/policy.yaml\n  playbook_file: ./inputs/playbook.yaml\n",
        )
        .unwrap();
        let mut c = cli(repo_dir.path());
        c.config = Some(config_path);
        let settings = build_remediate_settings(&c).unwrap();
        let policy = settings.policy.expect("enforcement is on");
        // Proves the relative path actually resolved: a gate that failed
        // to load denies everything, `default_action: allow` patches.
        let decision = policy.gate.decide("CWE-89", "app.py", &|_| None);
        assert_eq!(decision.action, bc_policy_gate::Action::Patch);
    }

    #[test]
    fn an_explicit_policy_flag_wins_over_the_config_key() {
        let repo_dir = tempfile::tempdir().unwrap();
        let config_dir = tempfile::tempdir().unwrap();
        let flag_policy = config_dir.path().join("flag.yaml");
        std::fs::write(&flag_policy, "default_action: allow\n").unwrap();
        let config_path = config_dir.path().join("config.yaml");
        std::fs::write(
            &config_path,
            "step_remediate:\n  enforce_policy: true\n  policy_file: ./missing.yaml\n",
        )
        .unwrap();
        let mut c = cli(repo_dir.path());
        c.config = Some(config_path);
        c.remediation_policy = Some(flag_policy);
        let settings = build_remediate_settings(&c).unwrap();
        let policy = settings.policy.unwrap();
        assert_eq!(
            policy.gate.decide("CWE-89", "app.py", &|_| None).action,
            bc_policy_gate::Action::Patch
        );
    }

    #[test]
    fn build_remediate_settings_applies_the_gate_flags() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = cli(dir.path());
        c.remediate_dry_run = true;
        c.verify_command = Some("true".to_string());
        let settings = build_remediate_settings(&c).unwrap();
        assert!(settings.config.step10.dry_run);
        assert_eq!(
            settings.config.step10.verify_command.as_deref(),
            Some("true")
        );
    }

    #[test]
    fn build_remediate_run_attaches_the_executors_own_write_journal() {
        // A plain (non-git) directory: no worktree is possible, so this
        // exercises the in-place path and the journal wiring together.
        let dir = tempfile::tempdir().unwrap();
        let mut c = cli(dir.path());
        c.remediate = true;
        let run = build_remediate_run(&c, dir.path()).unwrap();
        assert!(run.worktree.is_none());
        assert!(!run.settings.config.isolated);
        assert!(
            run.settings.config.step10.journal.is_some(),
            "S10's rollback gates need the journal or they silently \
             degrade to the git-status fallback"
        );
    }

    #[test]
    fn remediation_views_map_records_onto_report_positions_by_finding_id() {
        let mut first = sample_finding();
        first.title = "First".to_string();
        let mut second = sample_finding();
        second.title = "Second".to_string();
        second.file = "other.py".to_string();
        let report = sample_report(None, vec![first, second.clone()]);
        let second_id = bc_sarif::finding_id(&second);
        let outcome = bc_orchestrator::RemediateOutcome {
            refused: None,
            outcomes: vec![
                bc_stage_s10::RemediationOutcome::Failed {
                    finding_index: 1,
                    error: "boom".to_string(),
                },
                processed_record(&second_id, bc_stage_s10::Verdict::Fixed, Some("diff")),
                // An id no finding in this report carries — dropped, not
                // guessed at.
                processed_record("orphan", bc_stage_s10::Verdict::Fixed, None),
            ],
            validations: vec![
                None,
                Some(validation_score(bc_validation_scoring::FixVerdict::Fixed)),
                None,
            ],
            validation_failures: 0,
        };
        let views = remediation_views(&report, &outcome);
        assert_eq!(views.len(), 1);
        assert_eq!(views[0].finding_index, 1, "the SECOND finding, 0-based");
        assert_eq!(views[0].verdict, "Fixed");
        assert!(views[0].has_diff);
        assert_eq!(views[0].changed_files, vec!["app.py".to_string()]);
        assert_eq!(views[0].root_cause, "unsanitized input");
        assert_eq!(views[0].validation_status.as_deref(), Some("Fixed"));
    }

    #[test]
    fn a_policy_capped_final_verdict_wins_in_the_view() {
        let finding = sample_finding();
        let id = bc_sarif::finding_id(&finding);
        let report = sample_report(None, vec![finding]);
        let mut outcome = bc_orchestrator::RemediateOutcome {
            refused: None,
            outcomes: vec![processed_record(&id, bc_stage_s10::Verdict::Fixed, None)],
            validations: Vec::new(),
            validation_failures: 0,
        };
        if let bc_stage_s10::RemediationOutcome::Processed(r) = &mut outcome.outcomes[0] {
            r.final_verdict = Some("Denied".to_string());
        }
        assert_eq!(remediation_views(&report, &outcome)[0].verdict, "Denied");
    }

    #[test]
    fn augment_report_outputs_writes_a_remediation_section_without_any_validation() {
        let dir = tempfile::tempdir().unwrap();
        let md_path = dir.path().join("report.md");
        let sarif_path = dir.path().join("report.sarif");
        let finding = sample_finding();
        let id = bc_sarif::finding_id(&finding);
        let report = sample_report(None, vec![finding]);
        let markdown = bc_report_md::render_markdown(&report);
        std::fs::write(&md_path, &markdown).unwrap();
        let outcome = bc_orchestrator::RemediateOutcome {
            refused: None,
            outcomes: vec![processed_record(
                &id,
                bc_stage_s10::Verdict::Fixed,
                Some("diff"),
            )],
            validations: Vec::new(),
            validation_failures: 0,
        };
        augment_report_outputs(
            &md_path,
            &sarif_path,
            &report,
            "test",
            Some(&markdown),
            true,
            &outcome,
        )
        .unwrap();
        let written = std::fs::read_to_string(&md_path).unwrap();
        assert!(written.contains("#### Remediation"), "{written}");
        assert!(written.contains("## Remediation Summary"), "{written}");
        assert!(!written.contains("#### Validation"));
        let sarif: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&sarif_path).unwrap()).unwrap();
        assert_eq!(
            sarif["runs"][0]["results"][0]["properties"]["remediationStatus"],
            "Fixed"
        );
    }

    #[test]
    fn augment_report_outputs_is_a_no_op_without_remediation_or_validation() {
        let dir = tempfile::tempdir().unwrap();
        let md_path = dir.path().join("report.md");
        let sarif_path = dir.path().join("report.sarif");
        let report = sample_report(None, vec![sample_finding()]);
        let outcome = bc_orchestrator::RemediateOutcome {
            refused: Some("stale".to_string()),
            outcomes: Vec::new(),
            validations: Vec::new(),
            validation_failures: 0,
        };
        augment_report_outputs(
            &md_path,
            &sarif_path,
            &report,
            "test",
            Some("# nothing\n"),
            true,
            &outcome,
        )
        .unwrap();
        assert!(!md_path.exists());
        assert!(!sarif_path.exists());
    }

    // ── `--remediate-from`'s in-place report augmentation ───────────────

    /// Writes a prior run's `report.md`/`report.sarif` for `report` into
    /// `dir`, exactly as a completed scan would have left them.
    fn write_prior_reports(dir: &Path, report: &bc_model::FinalReport) -> (PathBuf, PathBuf) {
        let md_path = dir.join("security-scan").join("report.md");
        let sarif_path = dir.join("security-scan").join("report.sarif");
        std::fs::create_dir_all(md_path.parent().unwrap()).unwrap();
        std::fs::write(&md_path, bc_report_md::render_markdown(report)).unwrap();
        std::fs::write(
            &sarif_path,
            serde_json::to_string_pretty(&bc_sarif::build_sarif(report, "test")).unwrap(),
        )
        .unwrap();
        (md_path, sarif_path)
    }

    fn validated_outcome(id: &str) -> bc_orchestrator::RemediateOutcome {
        bc_orchestrator::RemediateOutcome {
            refused: None,
            outcomes: vec![processed_record(
                id,
                bc_stage_s10::Verdict::Fixed,
                Some("d"),
            )],
            validations: vec![Some(bc_validation_scoring::ValidationScore {
                raw_score: 0.91,
                fix_status: bc_validation_scoring::FixVerdict::Fixed,
                justification: "the injection is parameterized now".to_string(),
                gate_results: Vec::new(),
                has_critical_failure: false,
            })],
            validation_failures: 0,
        }
    }

    #[test]
    fn augment_prior_reports_writes_both_artifacts_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let finding = sample_finding();
        let id = bc_sarif::finding_id(&finding);
        let report = sample_report(None, vec![finding]);
        let (md_path, sarif_path) = write_prior_reports(dir.path(), &report);
        let outcome = validated_outcome(&id);

        let augmented = augment_prior_reports(&md_path, &sarif_path, &report, &outcome).unwrap();
        assert_eq!(augmented.markdown, AugmentOutcome::Written);
        assert_eq!(augmented.sarif, AugmentOutcome::Written);

        let md = std::fs::read_to_string(&md_path).unwrap();
        assert!(md.contains("#### Remediation"), "{md}");
        assert!(md.contains("#### Validation"), "{md}");
        assert!(md.contains("## Remediation Summary"), "{md}");
        let sarif: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&sarif_path).unwrap()).unwrap();
        let props = &sarif["runs"][0]["results"][0]["properties"];
        assert_eq!(props["remediationStatus"], "Fixed");
        assert_eq!(props["validationStatus"], "Fixed");
        assert_eq!(props["validationScore"], 0.91);
        assert_eq!(props["mergeReadiness"], "Ready");
    }

    /// The whole reason this path stamps rather than rebuilds: a
    /// reconstructed report carries no app profile, so a rebuild would
    /// blank out the `applicationId` the earlier scan wrote.
    #[test]
    fn augment_prior_sarif_preserves_run_properties_the_export_cannot_carry() {
        let dir = tempfile::tempdir().unwrap();
        let finding = sample_finding();
        let id = bc_sarif::finding_id(&finding);
        let mut prior = sample_report(None, vec![finding.clone()]);
        prior.app_profile = Some(bc_model::AppProfile {
            application_id: "APP-42".to_string(),
            name: "Payments".to_string(),
            externally_facing: true,
            pci_scoped: false,
            processes_pan: false,
            pii: false,
            source: "cmdb".to_string(),
        });
        let (_, sarif_path) = write_prior_reports(dir.path(), &prior);
        // What `--remediate-from` reconstructs: findings only.
        let reconstructed = sample_report(None, vec![finding]);
        let md_path = dir.path().join("no-such-report.md");

        augment_prior_reports(
            &md_path,
            &sarif_path,
            &reconstructed,
            &validated_outcome(&id),
        )
        .unwrap();
        let sarif: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&sarif_path).unwrap()).unwrap();
        assert_eq!(sarif["runs"][0]["properties"]["applicationId"], "APP-42");
        assert_eq!(
            sarif["runs"][0]["results"][0]["properties"]["remediationStatus"],
            "Fixed"
        );
    }

    /// An `absent` result appended by a prior `--baseline` run makes the
    /// results array longer than the export's findings — fingerprint
    /// matching still puts each annotation on the right result, which a
    /// positional zip would not.
    #[test]
    fn augment_prior_sarif_matches_by_fingerprint_not_position() {
        let finding = sample_finding();
        let id = bc_sarif::finding_id(&finding);
        let report = sample_report(None, vec![finding]);
        let mut doc = bc_sarif::build_sarif(&report, "test");
        let resolved = doc.runs[0].results[0].clone().with_baseline_state("absent");
        // The stale `absent` result goes FIRST, so position 0 is no
        // longer this run's own finding.
        doc.runs[0].results.insert(0, resolved);
        doc.runs[0].results[0]
            .partial_fingerprints
            .insert(bc_sarif::FINGERPRINT_KEY.to_string(), "other".to_string());

        let augmented = augment_prior_sarif(
            &serde_json::to_string_pretty(&doc).unwrap(),
            &validated_outcome(&id),
        )
        .expect("one result matched");
        let parsed: serde_json::Value = serde_json::from_str(&augmented).unwrap();
        assert!(parsed["runs"][0]["results"][0]["properties"]["remediationStatus"].is_null());
        assert_eq!(
            parsed["runs"][0]["results"][1]["properties"]["remediationStatus"],
            "Fixed"
        );
    }

    /// A second `--remediate-from` against an already-augmented
    /// `report.md` must not stack a second, contradicting remediation
    /// section under every finding. The SARIF has no such hazard —
    /// stamping a property twice overwrites it.
    #[test]
    fn augment_prior_markdown_refuses_an_already_augmented_report() {
        let dir = tempfile::tempdir().unwrap();
        let finding = sample_finding();
        let id = bc_sarif::finding_id(&finding);
        let report = sample_report(None, vec![finding]);
        let (md_path, sarif_path) = write_prior_reports(dir.path(), &report);
        let outcome = validated_outcome(&id);

        augment_prior_reports(&md_path, &sarif_path, &report, &outcome).unwrap();
        let once = std::fs::read_to_string(&md_path).unwrap();
        let again = augment_prior_reports(&md_path, &sarif_path, &report, &outcome).unwrap();

        assert_eq!(again.markdown, AugmentOutcome::Unchanged);
        assert_eq!(again.sarif, AugmentOutcome::Written);
        assert_eq!(std::fs::read_to_string(&md_path).unwrap(), once);
        assert_eq!(once.matches("## Remediation Summary").count(), 1);
    }

    /// A `report.md` whose finding headings don't line up with the
    /// export leaves `bc_report_md`'s augmenters failing closed — which
    /// this path reports as "left unchanged" rather than as success.
    #[test]
    fn augment_prior_markdown_reports_a_fail_closed_augmenter_as_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let finding = sample_finding();
        let id = bc_sarif::finding_id(&finding);
        let report = sample_report(None, vec![finding]);
        let md_path = dir.path().join("report.md");
        // A report from some other scan entirely: no `### N. [` headings.
        std::fs::write(&md_path, "# Some other report\n\nnothing here\n").unwrap();
        let sarif_path = dir.path().join("report.sarif");

        let augmented =
            augment_prior_reports(&md_path, &sarif_path, &report, &validated_outcome(&id)).unwrap();
        assert_eq!(augmented.markdown, AugmentOutcome::Unchanged);
        assert_eq!(augmented.sarif, AugmentOutcome::NotFound);
        assert_eq!(
            std::fs::read_to_string(&md_path).unwrap(),
            "# Some other report\n\nnothing here\n"
        );
    }

    #[test]
    fn augment_prior_reports_reports_missing_artifacts_rather_than_creating_them() {
        let dir = tempfile::tempdir().unwrap();
        let finding = sample_finding();
        let id = bc_sarif::finding_id(&finding);
        let report = sample_report(None, vec![finding]);
        let md_path = dir.path().join("report.md");
        let sarif_path = dir.path().join("report.sarif");

        let augmented =
            augment_prior_reports(&md_path, &sarif_path, &report, &validated_outcome(&id)).unwrap();
        assert_eq!(augmented.markdown, AugmentOutcome::NotFound);
        assert_eq!(augmented.sarif, AugmentOutcome::NotFound);
        assert!(!md_path.exists(), "nothing is created that wasn't there");
        assert!(!sarif_path.exists());
    }

    /// Remediation that never produced a record (a refusal) has nothing
    /// to write, so both artifacts are left exactly as they were.
    #[test]
    fn augment_prior_reports_is_a_no_op_when_nothing_was_remediated() {
        let dir = tempfile::tempdir().unwrap();
        let report = sample_report(None, vec![sample_finding()]);
        let (md_path, sarif_path) = write_prior_reports(dir.path(), &report);
        let before_md = std::fs::read_to_string(&md_path).unwrap();
        let before_sarif = std::fs::read_to_string(&sarif_path).unwrap();
        let outcome = bc_orchestrator::RemediateOutcome {
            refused: Some("stale".to_string()),
            outcomes: Vec::new(),
            validations: Vec::new(),
            validation_failures: 0,
        };

        let augmented = augment_prior_reports(&md_path, &sarif_path, &report, &outcome).unwrap();
        assert_eq!(augmented.markdown, AugmentOutcome::Unchanged);
        assert_eq!(augmented.sarif, AugmentOutcome::Unchanged);
        assert_eq!(std::fs::read_to_string(&md_path).unwrap(), before_md);
        assert_eq!(std::fs::read_to_string(&sarif_path).unwrap(), before_sarif);
    }

    /// A `report.sarif` this tool didn't write (another scanner's, or a
    /// truncated one) is left alone rather than half-annotated.
    #[test]
    fn augment_prior_sarif_leaves_an_unparseable_document_alone() {
        let finding = sample_finding();
        let id = bc_sarif::finding_id(&finding);
        assert!(augment_prior_sarif("{ not sarif", &validated_outcome(&id)).is_none());
    }

    #[test]
    fn augmented_reports_display_names_every_outcome() {
        let mut s = base_summary();
        s.augmented = Some(AugmentedReports {
            markdown_path: PathBuf::from("/r/security-scan/report.md"),
            markdown: AugmentOutcome::Written,
            sarif_path: PathBuf::from("/r/security-scan/report.sarif"),
            sarif: AugmentOutcome::NotFound,
        });
        let rendered = s.to_string();
        assert!(
            rendered.contains("augmented /r/security-scan/report.md"),
            "{rendered}"
        );
        assert!(
            rendered.contains("no prior report at /r/security-scan/report.sarif to augment"),
            "{rendered}"
        );

        s.augmented = Some(AugmentedReports {
            markdown_path: PathBuf::from("/r/report.md"),
            markdown: AugmentOutcome::Unchanged,
            sarif_path: PathBuf::from("/r/report.sarif"),
            sarif: AugmentOutcome::Unchanged,
        });
        assert!(s.to_string().contains("left /r/report.md unchanged"), "{s}");
    }

    #[test]
    fn apply_remediation_status_leaves_a_document_alone_without_records() {
        let report = sample_report(None, vec![sample_finding()]);
        let mut doc = bc_sarif::build_sarif(&report, "test");
        let outcome = bc_orchestrator::RemediateOutcome {
            refused: None,
            outcomes: vec![bc_stage_s10::RemediationOutcome::Failed {
                finding_index: 1,
                error: "boom".to_string(),
            }],
            validations: Vec::new(),
            validation_failures: 0,
        };
        apply_remediation_status(&mut doc, &report, &outcome);
        assert!(doc.runs[0].results[0]
            .properties
            .remediation_status
            .is_none());
    }

    #[test]
    fn scan_summary_display_names_the_exported_patch() {
        let mut s = base_summary();
        s.remediation_patch = Some(PathBuf::from("/r/security-scan/remediation.patch"));
        let rendered = s.to_string();
        assert!(rendered.contains("remediation.patch"), "{rendered}");
        assert!(rendered.contains("git apply"), "{rendered}");
    }

    #[tokio::test]
    async fn remediate_from_refuses_an_unreadable_or_malformed_export() {
        let dir = git_repo();
        let llm = one_finding_client();
        let mut c = cli(dir.path());
        c.remediate_from = Some(dir.path().join("nope.json"));
        let err = remediate_from(&c, &c.remediate_from.clone().unwrap(), llm.clone())
            .await
            .unwrap_err();
        assert!(err.contains("cannot read findings export"), "{err}");

        let broken = dir.path().join("broken.json");
        std::fs::write(&broken, "{ not json").unwrap();
        let err = remediate_from(&c, &broken, llm).await.unwrap_err();
        assert!(err.contains("is not a findings export"), "{err}");
    }

    /// The export carries the commit it was produced from, so a
    /// repository that has moved on hits the SAME staleness refusal a
    /// live `--remediate` would — reusing `bc_orchestrator::remediate`'s
    /// own check rather than re-implementing it.
    #[tokio::test]
    async fn remediate_from_refuses_a_stale_export() {
        let dir = git_repo();
        let export = dir.path().join("findings.json");
        std::fs::write(
            &export,
            serde_json::json!({
                "commit_sha": "0000000000000000000000000000000000000000",
                "findings": [{
                    "chunk_id": "c0", "file": "app.py", "line_start": 1, "line_end": 1,
                    "vuln_class": "injection", "title": "SQLi", "description": "d",
                    "code_snippet": "x", "confidence": 0.9, "votes": 1,
                    "cvss_rating": "High",
                }],
            })
            .to_string(),
        )
        .unwrap();
        let mut c = cli(dir.path());
        c.remediate_from = Some(export.clone());
        c.remediate_in_place = true;

        let summary = remediate_from(&c, &export, one_finding_client())
            .await
            .unwrap();
        let remediation = summary.remediation.unwrap();
        let refused = remediation.refused.expect("HEAD has moved");
        assert!(refused.contains("HEAD moved since scan"), "{refused}");
        assert_eq!(summary.findings, 1);
    }

    #[tokio::test]
    async fn remediate_from_remediates_an_exported_finding_without_rescanning() {
        let dir = git_repo();
        let out_json = dir.path().join("remediation.json");
        let export = dir.path().join("findings.json");
        let head = std::process::Command::new("git")
            .current_dir(dir.path())
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap();
        let sha = String::from_utf8_lossy(&head.stdout).trim().to_string();
        std::fs::write(
            &export,
            serde_json::json!({
                "commit_sha": sha,
                "findings": [{
                    "chunk_id": "c0", "file": "app.py", "line_start": 1, "line_end": 1,
                    "vuln_class": "injection", "title": "SQLi", "description": "d",
                    "code_snippet": "x", "confidence": 0.9, "votes": 1,
                    "cvss_rating": "Critical",
                }],
            })
            .to_string(),
        )
        .unwrap();
        let mut c = cli(dir.path());
        c.remediate_from = Some(export.clone());
        c.remediate_in_place = true;
        c.out_remediation_json = Some(out_json.clone());

        let summary = remediate_from(&c, &export, one_finding_client())
            .await
            .unwrap();
        let remediation = summary.remediation.unwrap();
        assert!(remediation.refused.is_none(), "{remediation:?}");
        assert_eq!(remediation.processed, 1);
        // No scan ran, so no scan artifacts are claimed, and none are
        // created either: this mode augments a prior run's reports in
        // place where they exist, so `resolve_output_paths` is read but
        // `ensure_dirs` deliberately never runs.
        assert!(summary.markdown_path.is_none());
        assert!(summary.sarif_path.is_none());
        assert!(summary.findings_json_path.is_none());
        assert!(!dir.path().join("security-scan").exists());
        let written: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out_json).unwrap()).unwrap();
        assert_eq!(written["results"][0]["status"], "processed");
    }

    /// `--diff-scope` used to be accepted by this mode and silently
    /// ignored: `main_impl` returns here long before the scan path's own
    /// `resolve_diff_scope` call. It now carries the same hard credential
    /// requirement the scan path has.
    #[tokio::test]
    async fn remediate_from_requires_github_credentials_for_a_diff_scope() {
        let dir = git_repo();
        let export = write_export(
            dir.path(),
            &FindingsExport {
                commit_sha: "deadbeef".to_string(),
                findings: vec![sample_finding()],
            },
        );
        let mut c = cli(dir.path());
        c.remediate_from = Some(export.clone());
        c.remediate_in_place = true;
        c.diff_scope = true;

        let err = remediate_from(&c, &export, one_finding_client())
            .await
            .unwrap_err();
        assert!(err.contains("--diff-scope requires"), "{err}");
    }

    /// A findings export written by an earlier FULL scan is exactly where
    /// out-of-diff-scope remediation candidates come from. With
    /// `--diff-scope`, S10 must refuse the ones the pull request never
    /// touched — and still fix the ones it did.
    #[tokio::test]
    async fn remediate_from_refuses_a_candidate_outside_the_diff_scope() {
        let dir = git_repo();
        std::fs::write(dir.path().join("helper.py"), "print('helper')\n").unwrap();
        let head = std::process::Command::new("git")
            .current_dir(dir.path())
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap();
        let sha = String::from_utf8_lossy(&head.stdout).trim().to_string();
        let export = dir.path().join("findings.json");
        std::fs::write(
            &export,
            serde_json::json!({
                "commit_sha": sha,
                "findings": [{
                    "chunk_id": "external:semgrep:1", "file": "helper.py",
                    "line_start": 1, "line_end": 1, "vuln_class": "injection",
                    "title": "Pre-existing", "description": "d", "code_snippet": "x",
                    "confidence": 0.9, "votes": 1, "cvss_rating": "Critical",
                }],
            })
            .to_string(),
        )
        .unwrap();

        // The pull request touched `app.py` only; the export's finding is
        // in `helper.py`.
        let server =
            diff_server("--- a/app.py\n+++ b/app.py\n@@ -1,1 +1,2 @@\n x = 1\n+y = 2\n").await;
        let mut c = cli(dir.path());
        c.remediate_from = Some(export.clone());
        c.remediate_in_place = true;
        c.diff_scope = true;
        c.github_token = Some("tok".to_string());
        c.github_repo = Some("acme/widgets".to_string());
        c.pr_number = Some(1);
        c.github_api_base_url = server.uri();
        let out_json = dir.path().join("remediation.json");
        c.out_remediation_json = Some(out_json.clone());

        let summary = remediate_from(&c, &export, one_finding_client())
            .await
            .unwrap();
        let remediation = summary.remediation.unwrap();
        assert!(remediation.refused.is_none(), "{remediation:?}");
        let written: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out_json).unwrap()).unwrap();
        assert_eq!(
            written["results"][0]["policy_action"],
            bc_stage_s10::OUT_OF_DIFF_SCOPE_ACTION
        );
        // The working tree is untouched.
        assert_eq!(
            std::fs::read_to_string(dir.path().join("helper.py")).unwrap(),
            "print('helper')\n"
        );
    }

    /// The severity S8 would have assigned, rebuilt from the CVSS band
    /// the export carries — `--top N` ranks by it, so getting it wrong
    /// would remediate the wrong findings.
    #[test]
    fn the_exports_cvss_band_reconstructs_the_severity_s8_assigned() {
        let mut f = sample_finding();
        f.cvss_rating = Some("Critical".to_string());
        assert_eq!(
            bc_stage_s8::final_severity(&f, bc_model::Severity::Info),
            bc_model::Severity::Critical
        );
        f.cvss_rating = None;
        assert_eq!(
            bc_stage_s8::final_severity(&f, bc_model::Severity::Info),
            bc_model::Severity::Info
        );
    }

    #[test]
    fn scan_summary_display_reports_the_baseline_counts() {
        let mut s = base_summary();
        s.baseline = Some(BaselineTally {
            new: 2,
            unchanged: 5,
            resolved: 1,
        });
        assert!(s
            .to_string()
            .contains("Baseline: 2 new, 5 unchanged, 1 resolved."));
    }

    #[tokio::test]
    async fn run_annotates_both_reports_against_a_baseline() {
        let dir = git_repo();
        let paths = out_paths(&dir.path().join("out"));

        // A baseline whose one finding this scan does NOT produce, so the
        // run has exactly one `new` and one `resolved`.
        let baseline_path = dir.path().join("baseline.json");
        std::fs::write(
            &baseline_path,
            serde_json::json!({
                "commit_sha": "abc",
                "findings": [{
                    "chunk_id": "c0", "file": "old.py", "line_start": 1, "line_end": 1,
                    "vuln_class": "other", "title": "Gone finding", "description": "d",
                    "code_snippet": "x", "confidence": 0.5, "votes": 1,
                }],
            })
            .to_string(),
        )
        .unwrap();
        let baseline = BaselineRun {
            path: baseline_path.clone(),
            baseline: baseline::load(&baseline_path, dir.path()).unwrap(),
        };

        let summary = run(
            fast_input(dir.path()),
            fast_config_no_semantic_dedup(),
            None,
            &paths,
            one_finding_client(),
            Arc::new(NoTools),
            None,
            None,
            Some(baseline),
        )
        .await
        .unwrap();

        let tally = summary.baseline.expect("--baseline was given");
        assert_eq!(tally.new, 1);
        assert_eq!(tally.unchanged, 0);
        assert_eq!(tally.resolved, 1);

        let markdown = std::fs::read_to_string(&paths.markdown).unwrap();
        assert!(markdown.contains("## Baseline Comparison"), "{markdown}");
        assert!(markdown.contains("### New findings"), "{markdown}");
        assert!(markdown.contains("Gone finding"), "{markdown}");

        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&paths.sarif).unwrap()).unwrap();
        assert_eq!(doc["runs"][0]["results"][0]["baselineState"], "new");
        // A findings-JSON baseline carries the whole typed `Finding`, so
        // the resolved one is re-emitted as a real `absent` result —
        // level and rank derived, never fabricated — and Code Scanning
        // can close the alert it opened last run.
        let results = doc["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[1]["baselineState"], "absent");
        assert_eq!(results[1]["message"]["text"], "Gone finding");
        assert_eq!(results[1]["ruleId"], "other");
    }

    #[tokio::test]
    async fn a_baseline_matching_this_scan_reports_everything_unchanged() {
        let dir = git_repo();
        let paths = out_paths(&dir.path().join("out"));

        // First run with no baseline, exporting its findings. Every
        // run writes one, at `paths.findings_json`, with no flag asked
        // for.
        let findings_json = paths.findings_json.clone();
        run(
            fast_input(dir.path()),
            fast_config_no_semantic_dedup(),
            None,
            &paths,
            one_finding_client(),
            Arc::new(NoTools),
            None,
            None,
            None,
        )
        .await
        .unwrap();
        assert!(
            findings_json.is_file(),
            "the export needs a git sha, which `git_repo()` provides"
        );

        // Second, identical run against that export.
        let baseline = BaselineRun {
            path: findings_json.clone(),
            baseline: baseline::load(&findings_json, dir.path()).unwrap(),
        };
        let summary = run(
            fast_input(dir.path()),
            fast_config_no_semantic_dedup(),
            None,
            &paths,
            one_finding_client(),
            Arc::new(NoTools),
            None,
            None,
            Some(baseline),
        )
        .await
        .unwrap();
        let tally = summary.baseline.unwrap();
        assert_eq!((tally.new, tally.unchanged, tally.resolved), (0, 1, 0));
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
                    target_tests: with_target_tests
                        .then(target_testing::TargetTestingConfig::default),
                    config: bc_orchestrator::RemediateConfig {
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

    /// A remediation run wired for the isolation-and-delivery paths: the
    /// journal comes from the same write-capable executor S10 gets, the
    /// way `build_remediate_run` builds it in production.
    fn isolated_remediate_run(
        root: &Path,
        target_tests: Option<target_testing::TargetTestingConfig>,
        delivery: Option<delivery::DeliveryState>,
        worktree: Option<worktree::RemediationWorktree>,
    ) -> RemediateRun {
        let tools = SandboxTools::new_with_write(root.to_path_buf());
        let mut step10 = fast_remediate_config();
        step10.journal = Some(tools.journal());
        RemediateRun {
            delivery,
            settings: RemediateSettings {
                target_tests,
                config: bc_orchestrator::RemediateConfig {
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
            tools: Arc::new(tools),
            out_json: None,
            checkpoint: None,
            worktree,
        }
    }

    async fn dispatch(
        llm: Arc<dyn LlmClient>,
        repo: &Path,
        report: &bc_model::FinalReport,
        run: RemediateRun,
    ) -> (bc_orchestrator::RemediateOutcome, Option<PathBuf>) {
        let read_tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new(repo.to_path_buf()));
        dispatch_remediation(
            llm,
            read_tools,
            repo,
            report,
            run,
            bc_orchestrator::RemediateTelemetry::default(),
        )
        .await
    }

    /// No `git_sha`, so `stale_refusal` never pre-empts the isolation and
    /// delivery gates these tests are about.
    fn one_finding_report() -> bc_model::FinalReport {
        sample_report(None, vec![sample_finding()])
    }

    /// A scan that completes cleanly and finds nothing: enough for the
    /// delivery dispatch, without a degraded report pre-empting it.
    fn complete_scan_no_findings_client() -> Arc<dyn LlmClient> {
        Arc::new(RoutedClient {
            router: Box::new(|system| {
                Ok(route(
                    system,
                    &[
                        (
                            S1_MARK,
                            r#"{"language":"python","modules":[],"entry_points":[],"unsafe_sinks":[],"call_graph":{},"notes":""}"#,
                        ),
                        (
                            S2_MARK,
                            r#"{"system_context":"ctx","assets":[],"trust_boundaries":[],"threats":[],"open_questions":[]}"#,
                        ),
                        (
                            S3_MARK,
                            r#"{"chunks":[],"rationale":"deterministic catchall"}"#,
                        ),
                        (S4_MARK, r#"{"findings": []}"#),
                    ],
                ))
            }),
        })
    }

    /// Answers S10 exactly as `one_finding_client` does, and hands every
    /// other role text no JSON parser will accept — the target-test
    /// generator included.
    fn s10_client_with_an_unusable_generator() -> Arc<dyn LlmClient> {
        let s10 = s10_verdict_json();
        Arc::new(RoutedClient {
            router: Box::new(move |system| {
                Ok(if system.contains(S10_MARK) {
                    s10.clone()
                } else {
                    "not-json".to_string()
                })
            }),
        })
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
        type Damage = fn(&mut bc_model::FinalReport);
        let cases: [(&str, Damage); 4] = [
            ("degraded", |report| report.degraded = true),
            ("budget", |report| {
                report.metrics = Some(bc_model::ScanMetrics {
                    budget_stop: "S6: token budget reached".into(),
                    ..Default::default()
                })
            }),
            ("chunks", |report| {
                report.metrics = Some(bc_model::ScanMetrics {
                    chunks_failed: 1,
                    ..Default::default()
                })
            }),
            ("errors", |report| {
                report.metrics = Some(bc_model::ScanMetrics {
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
        // A planted `security-scan` symlink must not redirect the
        // evidence file out of the repository.
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
            Some("Target-test validation blocked patch export; inspect security-scan/target-tests.json")
        );
        assert!(result.validations.is_empty());
        let record = expect_processed(&result.outcomes[0]);
        assert!(record.diff.is_none());
        assert_eq!(record.verdict.verdict, bc_stage_s10::Verdict::NeedsReview);
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

        /// Writes a real fix for S10, then errors for S11's personas.
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
            bc_stage_s10::RemediationOutcome::Failed { .. }
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

    /// `run()` with a scan that finds nothing, so the delivery dispatch is
    /// the only interesting part.
    async fn run_scan_with_remediation(
        repo: &Path,
        paths: &OutputPaths,
        remediate: RemediateRun,
    ) -> Result<ScanSummary, String> {
        run(
            fast_input(repo),
            fast_config_no_semantic_dedup(),
            None,
            paths,
            complete_scan_no_findings_client(),
            Arc::new(NoTools),
            None,
            Some(remediate),
            None,
        )
        .await
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
            result
                .refused
                .as_deref()
                .is_some_and(|reason| reason
                    .starts_with("Delivery completed but receipt could not be saved")),
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
        // A non-zero `git status` exit and a non-empty one mean opposite
        // things. Telling an operator whose tree is clean to commit their
        // changes sends them looking for something that is not there; the
        // real cause is usually that the scanner runs as a different uid
        // than the checkout's owner and git refuses the path outright.
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
        // A regular file where the worktree root would go: `git worktree
        // add`'s parent directory can never be created.
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
        // Keep the real worktree (which is what this test is about) but
        // swap the model/step configs for the fast in-process fakes the
        // other remediation tests use.
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
        // The throwaway checkout is gone, and the user's own tree was
        // never the thing being edited.
        assert!(!worktree_path.exists());
        // `one_finding_client`'s S10 turn reports a fix without actually
        // writing anything, so there is no diff to export — which is
        // exactly the "nothing changed, write no patch" contract.
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
        // Every gate the panel synthesized carries its consensus label.
        // A score of `Fixed` is only reachable when they are all `HIGH`,
        // so this also pins that the label survives the export intact
        // rather than defaulting.
        assert_eq!(gate["confidence"], "HIGH");
    }

    #[tokio::test]
    async fn run_threads_a_checkpoint_store_through_to_the_orchestrator() {
        let dir = git_repo();
        let paths = out_paths(&dir.path().join("out"));
        let ckpt_dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn bc_checkpoint::CheckpointStore> = Arc::new(
            bc_checkpoint::SqliteCheckpointStore::new(ckpt_dir.path().join("state.db")).unwrap(),
        );
        let remediate = RemediateRun {
            delivery: None,
            settings: RemediateSettings {
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

        let run_id = bc_checkpoint::run_id_for(dir.path());
        // Steps are engine-keyed digests, so count the S10 rows instead of
        // naming one: pruning against an empty live set returns them all.
        let saved = store.prune_stale(&run_id, bc_stage_s10::REMEDIATE_STEP_PREFIX, &[]);
        assert_eq!(saved.len(), 1, "{saved:?}");
    }

    // ── `-i`/`--interactive` dispatch (`remediate_interactively`) ───────
    //
    // A scripted `Terminal`/`BlockingInput` fake — an arrow-key session
    // feeding a fixed sequence of keys, always reporting `is_tty() ==
    // true`. `bc-interactive`'s own test suite already proves the
    // picker's decision logic thoroughly against a fake exactly like
    // this one; this crate's tests only need enough of a fake to prove
    // `remediate_interactively` wires everything through correctly.
    //
    // Reused (not re-invented as a separate "must never be touched"
    // fixture) for the stale-refusal/no-findings tests below too — like
    // `bc-orchestrator`'s own `remediate_refuses_when_head_has_moved_
    // since_the_scan`, which reuses its ordinary `S10Client` rather than
    // a dedicated panic-on-call guard, correctness there is proven by
    // asserting `result.refused`/`result.outcomes` directly; a client/
    // terminal fixture whose OWN body can only ever be proven correct by
    // NEVER executing it is exactly the kind of contrived, permanently-
    // uncovered test code this project avoids elsewhere.
    struct FakeTerminal {
        tty: bool,
        keys: std::collections::VecDeque<std::io::Result<bc_interactive::Key>>,
        lines: std::collections::VecDeque<Option<String>>,
    }

    impl FakeTerminal {
        fn tty(keys: Vec<std::io::Result<bc_interactive::Key>>) -> Self {
            FakeTerminal {
                tty: true,
                keys: keys.into(),
                lines: std::collections::VecDeque::new(),
            }
        }

        fn prompt(lines: Vec<Option<String>>) -> Self {
            FakeTerminal {
                tty: false,
                keys: std::collections::VecDeque::new(),
                lines: lines.into(),
            }
        }
    }

    impl bc_interactive::BlockingInput for FakeTerminal {
        fn read_key(&mut self) -> std::io::Result<bc_interactive::Key> {
            self.keys
                .pop_front()
                .unwrap_or(Ok(bc_interactive::Key::Quit))
        }
        fn read_line(&mut self, _prompt: &str) -> Option<String> {
            self.lines.pop_front().flatten()
        }
    }

    impl bc_interactive::Terminal for FakeTerminal {
        fn is_tty(&self) -> bool {
            self.tty
        }
        fn draw(&mut self, _frame: &str) -> std::io::Result<()> {
            Ok(())
        }
        fn write_line(&mut self, _line: &str) {}
    }

    fn remediate_config_no_cap() -> bc_orchestrator::RemediateConfig {
        bc_orchestrator::RemediateConfig {
            step10: fast_remediate_config(),
            top: None,
            top_default: None,
            force: false,
            resume: false,
            isolated: false,
        }
    }

    #[tokio::test]
    async fn remediate_interactively_refuses_when_head_has_moved_since_the_scan() {
        let dir = git_repo();
        let report = sample_report(
            Some("stale0000000000000000000000000000000000"),
            vec![sample_finding()],
        );
        let tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));
        let mut term = FakeTerminal::tty(vec![Ok(bc_interactive::Key::Quit)]);

        let result = remediate_interactively(
            one_finding_client_s10_only(),
            tools,
            dir.path(),
            &report,
            &remediate_config_no_cap(),
            None,
            None,
            None,
            &mut term,
        )
        .await;

        assert!(result.refused.unwrap().contains("HEAD moved since scan"));
        assert!(result.outcomes.is_empty());
    }

    #[tokio::test]
    async fn remediate_interactively_with_no_findings_is_a_no_op() {
        let dir = git_repo();
        let report = sample_report(None, Vec::new());
        let tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));
        let mut term = FakeTerminal::tty(vec![Ok(bc_interactive::Key::Quit)]);

        let result = remediate_interactively(
            one_finding_client_s10_only(),
            tools,
            dir.path(),
            &report,
            &remediate_config_no_cap(),
            None,
            None,
            None,
            &mut term,
        )
        .await;

        assert!(result.refused.is_none());
        assert!(result.outcomes.is_empty());
    }

    #[tokio::test]
    async fn remediate_interactively_remediates_the_finding_the_user_selects() {
        let dir = git_repo();
        std::fs::write(dir.path().join("app.py"), "query(x)\n").unwrap();
        let report = sample_report(None, vec![sample_finding()]);
        let tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));
        let mut term = FakeTerminal::tty(vec![
            Ok(bc_interactive::Key::Enter),
            Ok(bc_interactive::Key::Quit),
        ]);

        let result = remediate_interactively(
            one_finding_client_s10_only(),
            tools,
            dir.path(),
            &report,
            &remediate_config_no_cap(),
            None,
            None,
            None,
            &mut term,
        )
        .await;

        assert!(result.refused.is_none());
        assert_eq!(result.outcomes.len(), 1);
        assert_processed(&result.outcomes[0]);
    }

    #[tokio::test]
    async fn remediate_interactively_validates_the_finding_the_user_selects_when_validation_is_enabled(
    ) {
        let dir = git_repo();
        std::fs::write(dir.path().join("app.py"), "query(x)\n").unwrap();
        let report = sample_report(None, vec![sample_finding()]);
        let tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));
        let validate_tools = SandboxTools::new(dir.path());
        let step11 = fast_step11_config();
        let mut term = FakeTerminal::tty(vec![
            Ok(bc_interactive::Key::Enter),
            Ok(bc_interactive::Key::Quit),
        ]);

        let result = remediate_interactively(
            Arc::new(OneFindingClientWithValidation::new()),
            tools,
            dir.path(),
            &report,
            &remediate_config_no_cap(),
            None,
            None,
            Some(bc_interactive::ValidateContext {
                step11: &step11,
                tools: &validate_tools,
            }),
            &mut term,
        )
        .await;

        assert!(result.refused.is_none());
        assert_eq!(result.outcomes.len(), 1);
        assert_processed(&result.outcomes[0]);
        assert_eq!(result.validations.len(), 1);
        assert_eq!(
            result.validations[0].as_ref().unwrap().fix_status,
            bc_validation_scoring::FixVerdict::Fixed
        );
    }

    #[tokio::test]
    async fn remediate_interactively_with_an_explicit_top_cap_cvss_ranks_the_menu() {
        let dir = git_repo();
        std::fs::write(dir.path().join("app.py"), "query(x)\n").unwrap();
        let report = sample_report(None, vec![sample_finding(), sample_finding()]);
        let tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));
        let mut term = FakeTerminal::tty(vec![Ok(bc_interactive::Key::Quit)]);
        let mut config = remediate_config_no_cap();
        config.top = Some(bc_stage_s10::TopSpec::N(1));

        let result = remediate_interactively(
            one_finding_client_s10_only(),
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
        assert!(result.outcomes.is_empty());
    }

    #[tokio::test]
    async fn remediate_interactively_via_the_prompt_fallback_selects_and_remediates() {
        let dir = git_repo();
        std::fs::write(dir.path().join("app.py"), "query(x)\n").unwrap();
        let report = sample_report(None, vec![sample_finding()]);
        let tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));
        let mut term = FakeTerminal::prompt(vec![Some("all".to_string()), Some("q".to_string())]);

        let result = remediate_interactively(
            one_finding_client_s10_only(),
            tools,
            dir.path(),
            &report,
            &remediate_config_no_cap(),
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
    async fn run_skips_remediation_when_the_scan_stops_before_a_final_report() {
        let dir = git_repo();
        let paths = out_paths(&dir.path().join("None"));
        let client: Arc<dyn LlmClient> = Arc::new(RoutedClient {
            router: Box::new(|system| Ok(route(system, &[(S1_MARK, S1_JSON)]))),
        });
        let remediate = RemediateRun {
            delivery: None,
            settings: RemediateSettings {
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
            tools: Arc::new(SandboxTools::new_with_write(dir.path())),
            out_json: None,
            checkpoint: None,
            worktree: None,
        };
        let summary = run(
            fast_input(dir.path()),
            fast_config(),
            Some(StopAfter::S1),
            &paths,
            client,
            Arc::new(NoTools),
            None,
            Some(remediate),
            None,
        )
        .await
        .unwrap();
        assert!(summary.remediation.is_none());
    }

    #[tokio::test]
    async fn reporting_boundaries_control_exports_and_always_prevent_remediation() {
        for stop in [StopAfter::S8, StopAfter::S9] {
            let dir = git_repo();
            let mut paths = out_paths(&dir.path().join("out"));
            paths.findings_json = dir.path().join("out/findings.json");
            paths.provider_writeback_plan =
                Some(dir.path().join("out/provider-writeback-plan.json"));
            let client = one_finding_client();
            let remediate = RemediateRun {
                delivery: None,
                settings: RemediateSettings {
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
                tools: Arc::new(SandboxTools::new_with_write(dir.path())),
                out_json: None,
                checkpoint: None,
                worktree: None,
            };
            let summary = run(
                fast_input(dir.path()),
                fast_config_no_semantic_dedup(),
                Some(stop),
                &paths,
                client,
                Arc::new(NoTools),
                None,
                Some(remediate),
                None,
            )
            .await
            .unwrap();
            assert!(summary.remediation.is_none());
            assert_eq!(summary.stopped_after, Some(stop));
            let proposal = paths.provider_writeback_plan.as_ref().unwrap();
            assert_eq!(proposal.exists(), stop == StopAfter::S9);
            if proposal.exists() {
                let value: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(proposal).unwrap()).unwrap();
                assert_eq!(value["plan"]["apply_enabled"], false);
            }
            for path in [
                &paths.markdown,
                &paths.sarif,
                &paths.csv,
                &paths.findings_json,
            ] {
                assert_eq!(path.exists(), stop == StopAfter::S9, "{}", path.display());
            }
        }
    }

    #[test]
    fn provider_proposals_are_opt_in_and_apply_retains_the_plan() {
        use clap::Parser;
        let mut c = cli(Path::new("/repo"));
        assert!(resolve_output_paths(&c).provider_writeback_plan.is_none());
        c.provider_writeback = "plan".into();
        assert_eq!(
            resolve_output_paths(&c).provider_writeback_plan,
            Some(PathBuf::from(
                "/repo/security-scan/provider-writeback-plan.json"
            ))
        );
        c.provider_writeback = "apply".into();
        assert!(resolve_output_paths(&c).provider_writeback_plan.is_some());
        let parsed = Cli::try_parse_from([
            "bc-sast",
            "--repo",
            "/repo",
            "--gateway-base-url",
            "http://unused.invalid",
            "--provider-writeback",
            "apply",
        ])
        .unwrap();
        assert_eq!(parsed.provider_writeback, "apply");
        assert!(Cli::try_parse_from([
            "bc-sast",
            "--repo",
            "/repo",
            "--provider-writeback",
            "apply"
        ])
        .is_err());
    }

    struct PublicationBeforeRemediationClient {
        receipt: PathBuf,
        artifacts: Vec<PathBuf>,
        remediation_calls: std::sync::atomic::AtomicUsize,
        inner: Arc<dyn LlmClient>,
    }

    #[async_trait]
    impl LlmClient for PublicationBeforeRemediationClient {
        async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, LlmError> {
            if request.system.as_deref().unwrap_or("").contains(S10_MARK) {
                let receipt: Value =
                    serde_json::from_slice(&std::fs::read(&self.receipt).unwrap()).unwrap();
                assert_eq!(receipt["complete"], true);
                assert!(self.artifacts.iter().all(|path| path.is_file()));
                self.remediation_calls
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            self.inner.chat(request).await
        }
    }

    #[tokio::test]
    async fn automatic_publication_persists_s9_receipt_before_remediation() {
        for mode in 0..3 {
            let stop = (mode == 1).then_some(StopAfter::S9);
            let dir = git_repo();
            let state = tempfile::tempdir().unwrap();
            let mut c = cli(dir.path());
            c.provider_writeback = "apply".into();
            c.git_sha =
                bc_orchestrator::head_sha(dir.path()).expect("fixture has a committed HEAD");
            let publication =
                provider_publish::automatic::configure_at(&c, state.path().join("private"))
                    .unwrap();
            let paths = resolve_output_paths(&c);
            let receipt = paths
                .provider_writeback_plan
                .as_ref()
                .unwrap()
                .with_file_name("provider-writeback-results.json");
            if mode == 2 {
                std::fs::create_dir_all(&receipt).unwrap();
            }
            let client = Arc::new(PublicationBeforeRemediationClient {
                receipt: receipt.clone(),
                artifacts: vec![
                    paths.markdown.clone(),
                    paths.findings_json.clone(),
                    paths.provider_writeback_plan.clone().unwrap(),
                ],
                remediation_calls: std::sync::atomic::AtomicUsize::new(0),
                inner: one_finding_client(),
            });
            let remediate = RemediateRun {
                delivery: None,
                settings: RemediateSettings {
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
                tools: Arc::new(SandboxTools::new_with_write(dir.path())),
                out_json: None,
                checkpoint: None,
                worktree: None,
            };
            let result = run_with_publication(
                build_scan_input(&c),
                fast_config_no_semantic_dedup(),
                stop,
                &paths,
                client.clone(),
                Arc::new(NoTools),
                None,
                Some(remediate),
                None,
                publication,
            )
            .await;
            if mode == 2 {
                assert!(result.is_err());
                assert!(client.artifacts.iter().all(|path| path.is_file()));
                assert_eq!(
                    client
                        .remediation_calls
                        .load(std::sync::atomic::Ordering::SeqCst),
                    0
                );
                continue;
            }
            let summary = result.unwrap();
            let value: Value = serde_json::from_slice(&std::fs::read(receipt).unwrap()).unwrap();
            assert_eq!(value["complete"], true);
            assert_eq!(value["entries"], json!([]));
            assert!(summary.provider_publication.is_some());
            assert_eq!(summary.remediation.is_some(), stop.is_none());
            assert_eq!(
                client
                    .remediation_calls
                    .load(std::sync::atomic::Ordering::SeqCst)
                    > 0,
                stop.is_none()
            );
            assert!(summary.to_string().contains("Markdown:"));
        }
    }

    #[tokio::test]
    async fn automatic_publication_injected_run_rejects_partial_analysis() {
        let dir = git_repo();
        let state = tempfile::tempdir().unwrap();
        let mut c = cli(dir.path());
        c.provider_writeback = "apply".into();
        c.git_sha = bc_orchestrator::head_sha(dir.path()).expect("fixture has a committed HEAD");
        for mode in 0..3 {
            let publication =
                provider_publish::automatic::configure_at(&c, state.path().join("private"))
                    .unwrap();
            let mut input = build_scan_input(&c);
            let mut config = fast_config();
            input.diff_scope_active = mode == 0;
            config.resume = mode == 1;
            let paths = resolve_output_paths(&c);
            let error = run_with_publication(
                input,
                config,
                (mode == 2).then_some(StopAfter::S8),
                &paths,
                one_finding_client(),
                Arc::new(NoTools),
                None,
                None,
                None,
                publication,
            )
            .await
            .unwrap_err();
            assert!(error.contains("full scan"));
            assert!(!paths.markdown.exists());
        }
    }

    #[test]
    fn automatic_publication_allows_only_full_scans_through_s9() {
        let mut c = cli(Path::new("/unused"));
        c.provider_writeback = "apply".into();
        assert!(check_automatic_publication_mode(&c).is_ok());
        c.stop_after = "s9".into();
        assert!(check_automatic_publication_mode(&c).is_ok());
        for stop in ["s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8"] {
            c.stop_after = stop.into();
            assert!(check_automatic_publication_mode(&c).is_err(), "{stop}");
        }
        c.stop_after = "invalid".into();
        assert!(check_automatic_publication_mode(&c)
            .unwrap_err()
            .contains("invalid --stop-after"));
        c.stop_after.clear();
        c.resume = true;
        assert!(check_automatic_publication_mode(&c).is_err());
        c.resume = false;
        c.diff_scope = true;
        assert!(check_automatic_publication_mode(&c).is_err());
        c.provider_writeback = "plan".into();
        assert!(check_automatic_publication_mode(&c).is_ok());
    }

    #[test]
    fn automatic_publication_has_no_state_directory_flag() {
        use clap::Parser;
        assert!(Cli::try_parse_from([
            "bc-sast",
            "--provider-writeback",
            "apply",
            "--provider-writeback-state-dir",
            "/unused/state"
        ])
        .is_err());
    }

    #[tokio::test]
    async fn automatic_publication_invalid_modes_fail_before_model_setup() {
        for mode in 0..11 {
            let mut c = cli(Path::new("/unused"));
            c.provider_writeback = "apply".into();
            c.gateway_base_url = "not a URL".into();
            match mode {
                0 => c.gc = true,
                1 => c.gc_run = Some("unused".into()),
                2 => c.estimate = true,
                3 => c.doctor = true,
                4 => c.setup = true,
                5 => c.post_comments_from = Some("unused".into()),
                6 => c.post_fixes_from = Some("unused".into()),
                7 => c.remediate_from = Some("unused".into()),
                8 => c.resume = true,
                9 => c.diff_scope = true,
                _ => c.stop_after = "s8".into(),
            }
            assert!(main_impl(c)
                .await
                .unwrap_err()
                .contains("scan that reaches S9"));
        }
    }

    #[test]
    fn automatic_publication_summary_preserves_scan_and_remediation_results() {
        let summary = ScanSummary {
            provider_publication: Some("Provider publication: 1 updated".into()),
            findings: 2,
            markdown_path: Some("out/report.md".into()),
            findings_json_path: Some("out/findings.json".into()),
            remediation: Some(RemediationSummary {
                processed: 1,
                refused: None,
                failed: 0,
                validated: None,
                validation_failures: 0,
                ..Default::default()
            }),
            ..Default::default()
        }
        .to_string();
        for expected in [
            "Provider publication: 1 updated",
            "Scan complete: 2 finding(s)",
            "out/report.md",
            "out/findings.json",
            "Remediation: 1 processed",
        ] {
            assert!(summary.contains(expected), "{summary}");
        }
        let summary = ScanSummary {
            provider_publication: Some("Provider publication: 0 updated".into()),
            findings_json_path: Some("out/findings.json".into()),
            ..Default::default()
        }
        .to_string();
        assert!(summary.contains("Scan complete"));
    }

    #[tokio::test]
    async fn provider_proposals_reject_modes_without_s9_before_side_effects() {
        for mode in 0..8 {
            let mut c = cli(Path::new("/unused"));
            c.provider_writeback = "plan".into();
            match mode {
                0 => c.gc = true,
                1 => c.gc_run = Some("unused".into()),
                2 => c.estimate = true,
                3 => c.doctor = true,
                4 => c.setup = true,
                5 => c.post_comments_from = Some("unused".into()),
                6 => c.post_fixes_from = Some("unused".into()),
                _ => c.remediate_from = Some("unused".into()),
            }
            assert!(main_impl(c)
                .await
                .unwrap_err()
                .contains("requires a scan that reaches S9"));
        }
    }

    const S1_JSON: &str = r#"{"language":"python","modules":[],"entry_points":[],"unsafe_sinks":[],"call_graph":{},"notes":""}"#;

    #[tokio::test]
    async fn main_impl_stop_after_prevents_requested_remediation() {
        // An explicit stop boundary must override --remediate, including
        // worktree preparation. The full remediation path is exercised by
        // run_remediates_the_one_finding_the_scan_produced against fakes.
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

        // `cli.remediate` also makes `main_impl` call
        // `open_checkpoint_store` (real `BC_STATE_DIR`/`$HOME`
        // resolution) — redirect it to a throwaway tempdir so this test
        // never touches the real developer state dir.
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

    // ── `GcSummary::Display` ─────────────────────────────────────────

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

    #[test]
    fn gc_summary_display_evict_found() {
        let gc = GcSummary::Evicted {
            path: PathBuf::from("/repo"),
            run_id: "abc123".to_string(),
            found: true,
            dry_run: false,
        };
        assert_eq!(gc.to_string(), "gc: evicted run abc123 for /repo");
    }

    #[test]
    fn gc_summary_display_evict_not_found() {
        let gc = GcSummary::Evicted {
            path: PathBuf::from("/repo"),
            run_id: "abc123".to_string(),
            found: false,
            dry_run: false,
        };
        assert_eq!(gc.to_string(), "gc: no run found for /repo (run_id abc123)");
    }

    #[test]
    fn gc_summary_display_pruned_lists_deleted_runs() {
        let gc = GcSummary::Pruned {
            db_path: PathBuf::from("/state/bc-sast.db"),
            kept: 2,
            deleted: vec!["run1".to_string(), "run2".to_string()],
            dry_run: false,
        };
        assert_eq!(
            gc.to_string(),
            "gc: /state/bc-sast.db — kept 2 run(s), deleted 2\n    - run1\n    - run2"
        );
    }

    #[test]
    fn gc_summary_display_pruned_dry_run_with_no_deletions() {
        let gc = GcSummary::Pruned {
            db_path: PathBuf::from("/state/bc-sast.db"),
            kept: 5,
            deleted: vec![],
            dry_run: true,
        };
        assert_eq!(
            gc.to_string(),
            "gc: /state/bc-sast.db — [dry-run] kept 5 run(s), would delete 0"
        );
    }

    // ── `run_gc` ──────────────────────────────────────────────────────

    fn register_run_at(state_dir: &Path, target: &Path) -> String {
        let run_id = bc_checkpoint::run_id_for(target);
        let store: Arc<dyn bc_checkpoint::CheckpointStore> = Arc::new(
            bc_checkpoint::SqliteCheckpointStore::new(state_dir.join("bc-sast.db")).unwrap(),
        );
        store.register_run(&run_id, &target.display().to_string(), None, None);
        run_id
    }

    #[test]
    fn run_gc_run_evicts_a_registered_run() {
        let _guard = ENV_LOCK.blocking_lock();
        let state_dir = tempfile::tempdir().unwrap();
        let prior = std::env::var("BC_STATE_DIR").ok();
        unsafe {
            std::env::set_var("BC_STATE_DIR", state_dir.path());
        }
        let target = tempfile::tempdir().unwrap();
        let run_id = register_run_at(state_dir.path(), target.path());

        let mut c = cli(Path::new("/unused"));
        c.gc_run = Some(target.path().to_path_buf());
        let summary = run_gc(&c);
        restore_env("BC_STATE_DIR", prior);

        let summary = summary.unwrap();
        assert_eq!(summary.findings, 0);
        match summary.gc {
            Some(GcSummary::Evicted {
                found: true,
                dry_run: false,
                run_id: got,
                ..
            }) => assert_eq!(got, run_id),
            other => panic!("unexpected gc summary: {other:?}"),
        }
    }

    #[test]
    fn run_gc_run_reports_not_found_when_no_run_is_registered() {
        let _guard = ENV_LOCK.blocking_lock();
        let state_dir = tempfile::tempdir().unwrap();
        let prior = std::env::var("BC_STATE_DIR").ok();
        unsafe {
            std::env::set_var("BC_STATE_DIR", state_dir.path());
        }
        let target = tempfile::tempdir().unwrap();

        let mut c = cli(Path::new("/unused"));
        c.gc_run = Some(target.path().to_path_buf());
        let summary = run_gc(&c);
        restore_env("BC_STATE_DIR", prior);

        match summary.unwrap().gc {
            Some(GcSummary::Evicted {
                found: false,
                dry_run: false,
                ..
            }) => {}
            other => panic!("unexpected gc summary: {other:?}"),
        }
    }

    #[test]
    fn run_gc_run_dry_run_never_touches_the_database() {
        let _guard = ENV_LOCK.blocking_lock();
        let state_dir = tempfile::tempdir().unwrap();
        let prior = std::env::var("BC_STATE_DIR").ok();
        unsafe {
            std::env::set_var("BC_STATE_DIR", state_dir.path());
        }
        let target = tempfile::tempdir().unwrap();
        let run_id = register_run_at(state_dir.path(), target.path());

        let mut c = cli(Path::new("/unused"));
        c.gc_run = Some(target.path().to_path_buf());
        c.gc_dry_run = true;
        let summary = run_gc(&c).unwrap();

        // The row must still be there: a real (non-dry-run) delete_run
        // call against it should report `true`.
        let store = bc_checkpoint::SqliteCheckpointStore::open_default().unwrap();
        let still_there = store.delete_run(&run_id).unwrap();
        restore_env("BC_STATE_DIR", prior);

        match summary.gc {
            Some(GcSummary::Evicted {
                found: false,
                dry_run: true,
                ..
            }) => {}
            other => panic!("unexpected gc summary: {other:?}"),
        }
        assert!(
            still_there,
            "dry run must not have actually evicted the registered run"
        );
    }

    #[test]
    fn run_gc_prunes_all_runs_when_keep_runs_is_zero() {
        let _guard = ENV_LOCK.blocking_lock();
        let state_dir = tempfile::tempdir().unwrap();
        let prior = std::env::var("BC_STATE_DIR").ok();
        unsafe {
            std::env::set_var("BC_STATE_DIR", state_dir.path());
        }
        let target = tempfile::tempdir().unwrap();
        let run_id = register_run_at(state_dir.path(), target.path());

        let mut c = cli(Path::new("/unused"));
        c.gc_keep_runs = 0;
        c.gc_max_age_days = 365;
        let summary = run_gc(&c);
        restore_env("BC_STATE_DIR", prior);

        match summary.unwrap().gc {
            Some(GcSummary::Pruned {
                kept: 0,
                deleted,
                dry_run: false,
                ..
            }) => assert_eq!(deleted, vec![run_id]),
            other => panic!("unexpected gc summary: {other:?}"),
        }
    }

    #[test]
    fn run_gc_prune_dry_run_reports_victims_without_deleting() {
        let _guard = ENV_LOCK.blocking_lock();
        let state_dir = tempfile::tempdir().unwrap();
        let prior = std::env::var("BC_STATE_DIR").ok();
        unsafe {
            std::env::set_var("BC_STATE_DIR", state_dir.path());
        }
        let target = tempfile::tempdir().unwrap();
        let run_id = register_run_at(state_dir.path(), target.path());

        let mut c = cli(Path::new("/unused"));
        c.gc_keep_runs = 0;
        c.gc_max_age_days = 365;
        c.gc_dry_run = true;
        let summary = run_gc(&c).unwrap();

        let store = bc_checkpoint::SqliteCheckpointStore::open_default().unwrap();
        let still_there = store.delete_run(&run_id).unwrap();
        restore_env("BC_STATE_DIR", prior);

        match summary.gc {
            Some(GcSummary::Pruned {
                deleted,
                dry_run: true,
                ..
            }) => assert_eq!(deleted, vec![run_id]),
            other => panic!("unexpected gc summary: {other:?}"),
        }
        assert!(
            still_there,
            "dry run must not have actually pruned the registered run"
        );
    }

    #[test]
    fn run_gc_propagates_an_error_when_the_state_dir_is_unusable() {
        let _guard = ENV_LOCK.blocking_lock();
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("blocker");
        std::fs::write(&blocker, b"not a directory").unwrap();
        let prior = std::env::var("BC_STATE_DIR").ok();
        unsafe {
            std::env::set_var("BC_STATE_DIR", &blocker);
        }

        let c = cli(Path::new("/unused"));
        let result = run_gc(&c);
        restore_env("BC_STATE_DIR", prior);

        assert!(result.is_err());
    }

    // ── `main_impl` gc dispatch ──────────────────────────────────────

    #[tokio::test]
    async fn main_impl_dispatches_to_gc_when_the_flag_is_set() {
        let _guard = ENV_LOCK.lock().await;
        let state_dir = tempfile::tempdir().unwrap();
        let prior = std::env::var("BC_STATE_DIR").ok();
        unsafe {
            std::env::set_var("BC_STATE_DIR", state_dir.path());
        }
        let mut c = cli(Path::new("/unused"));
        c.gc = true;
        let summary = main_impl(c).await;
        restore_env("BC_STATE_DIR", prior);

        assert!(summary.unwrap().gc.is_some());
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

    /// One non-scanning mode: it returns without creating the default
    /// out-dir, let alone writing a report into it. `Ok` or `Err` is
    /// that mode's own business (the two `--post-*-from` modes refuse
    /// without `--github-token`); what matters is that neither outcome
    /// leaves an output directory behind.
    async fn assert_writes_no_reports(mode: &str, apply: impl FnOnce(&mut Cli)) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("main.py"), b"x").unwrap();
        let mut c = cli(dir.path());
        apply(&mut c);
        let _ = main_impl(c).await;
        assert!(
            !dir.path().join("security-scan").exists(),
            "{mode} created an output directory"
        );
    }

    /// Every mode `main_impl` dispatches BEFORE a scan writes nothing.
    /// The reports belong to a scan; a mode that runs none has nothing
    /// to put in them, and materializing an empty `security-scan/` in
    /// somebody's checkout would be a lie about what just happened.
    ///
    /// `--gc`/`--gc-run` are covered by their own tests above (they need
    /// the process-global `BC_STATE_DIR`, so they can't join this list),
    /// `--doctor` by its own (it probes the network), and
    /// `--remediate-from` by `remediate_from_remediates_an_exported_
    /// finding_without_rescanning` above.
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

        // A cache probe that could not reach a verdict fails the doctor;
        // one that did is healthy whatever the verdict says.
        let unfinished_cache_probe = DoctorSummary {
            cache_probe: Some(cache_probe::CacheProbeOutcome::skipped("m")),
            ..healthy.clone()
        };
        assert!(!unfinished_cache_probe.healthy());
        assert!(unfinished_cache_probe
            .to_string()
            .ends_with("[cache-probe] \u{2717} skipped: the live probe did not reach the model"));
    }

    /// A gateway that answers every call with the same cache accounting:
    /// what `--doctor --cache-probe` reads back through the real client.
    async fn cache_probe_gateway(dialect_path: &str, body: Value) -> wiremock::MockServer {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path(dialect_path))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;
        server
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
            bc_llm_client::CacheProbeVerdict::AlreadyWarm
        );
        let text = summary.to_string();
        assert!(
            text.contains("[model] claude-opus-5: family=claude-opus-5"),
            "{text}"
        );
        assert!(text.contains("real tokens were spent"), "{text}");
        // The live probe plus the probe's two calls, each carrying the
        // cache policy's marker on the filler system prompt.
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
        // Nothing listens on port 0: the live probe fails.
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

        // Not asked for: nothing is reported either way.
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
            bc_llm_client::CacheProbeVerdict::OpenAiImplicitWorking
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
        // `cli()`'s own default `gateway_base_url` (`http://127.0.0.1:0`)
        // never accepts a real connection — the probe fails fast and
        // locally, no external network dependency, exercising the
        // "ran, but the endpoint itself was unreachable" branch distinct
        // from the "skipped because a static check already blocked"
        // branch covered above.
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
        // No probe line — `--setup` is read-only by design (see its own
        // doc comment), so this run never had to know or care whether the
        // static check would have blocked a live probe.
        assert!(!text.contains("probe]"));
    }
}
