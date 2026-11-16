use super::*;
pub fn build_scan_config(cli: &Cli) -> Result<ScanConfig, String> {
    let mut config = ScanConfig {
        autoexclude: Default::default(),
        cancel: None,
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
        spend_cap: if cli.max_tokens.is_some() || cli.max_scan_seconds.is_some() {
            Some(SpendCap {
                max_total_tokens: cli.max_tokens,
                max_wall_clock: cli.max_scan_seconds.map(std::time::Duration::from_secs),
            })
        } else {
            None
        },
        checkpoint: None,
        resume: cli.resume,
        emit_unreachable_appendix: false,
        progress: None,
        pricing: appsec_orchestrator::pricing::PricingConfig::for_provider(
            appsec_orchestrator::pricing::infer_provider(&cli.gateway_base_url),
        ),
    };

    let mut data = Value::Null;
    if let Some(path) = &cli.config {
        let loaded = config_load::load(path).map_err(stringify)?;
        appsec_config::check_config_trust(path, repo_path(cli), &getenv).map_err(stringify)?;
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
            return Err(format!("step0.{key} runtime rule files are no longer supported; edit crates/appsec-stage-s0/corpus and rebuild"));
        }
    }
    config_overrides::apply_overrides(&mut config, &data, global_sampling(cli));
    if cli.dialect == Dialect::Anthropic {
        config.pricing.cache_ttl =
            llm_settings::resolve(cli.openai_api, cli.no_cache_markers, &data)?
                .cache
                .ttl;
    }
    if cli.no_threat_model {
        config.step2_enabled = false;
    }
    if let Some(provider) = &cli.pricing_provider {
        config.pricing.provider = Some(provider.clone());
    }

    Ok(config)
}

pub struct RemediateSettings {
    pub target_tests: Option<target_testing::TargetTestingConfig>,
    pub config: appsec_orchestrator::RemediateConfig,
    pub policy: Option<appsec_stage_s10::PolicyContext>,
    pub interactive: bool,
    pub validate_enabled: bool,
    pub step11: appsec_stage_s11::Step11Config,
}

pub fn build_remediate_settings(cli: &Cli) -> Result<RemediateSettings, String> {
    let mut step10 = appsec_stage_s10::Step10Config::new(cli.model.clone());
    let mut step11 = appsec_stage_s11::Step11Config::new(cli.model.clone());
    step11.allow_repo_hints = appsec_config::check_config_trust(
        &appsec_stage_s11::hints_path(repo_path(cli)),
        repo_path(cli),
        &getenv,
    )
    .is_ok();
    let mut top_default = None;
    let mut enforce_policy = cli.enforce_remediation_policy;
    let mut validate_enabled = true;
    let mut policy_file = None;
    let mut playbook_file = None;

    if let Some(path) = &cli.config {
        let loaded = config_load::load(path).map_err(stringify)?;
        appsec_config::check_config_trust(path, repo_path(cli), &getenv).map_err(stringify)?;
        config_overrides::validate_model_roles(&loaded.data)?;
        config_overrides::apply_step10_overrides(&mut step10, &loaded.data, global_sampling(cli));
        config_overrides::apply_step11_overrides(&mut step11, &loaded.data, global_sampling(cli));
        top_default = config_overrides::step_remediate_top_n_findings(&loaded.data);
        if let Some(e) = config_overrides::step_remediate_enforce_policy(&loaded.data) {
            enforce_policy = enforce_policy || e;
        }
        let config_dir = path.parent().unwrap_or(Path::new(""));
        (policy_file, playbook_file) =
            config_overrides::step_remediate_policy_paths(&loaded.data, config_dir);
        validate_enabled = config_overrides::step_validate_enabled_override(&loaded.user_provided)
            .unwrap_or(validate_enabled);
    }
    if let Some(explicit) = cli.validate {
        validate_enabled = explicit;
    }
    if cli.no_validate {
        validate_enabled = false;
    }

    let top = cli
        .top
        .as_deref()
        .map(|s| appsec_stage_s10::parse_top_spec(s, "--top"))
        .transpose()?;
    if cli.interactive && top.is_none() {
        top_default = None;
    }

    if cli.config.is_none() {
        config_overrides::apply_step10_overrides(&mut step10, &Value::Null, global_sampling(cli));
        config_overrides::apply_step11_overrides(&mut step11, &Value::Null, global_sampling(cli));
    }
    apply_remediation_gate_flags(cli, &mut step10);
    let (dialect, base_host) = engine_identity(cli);
    step10.dialect.clone_from(&dialect);
    step10.base_host.clone_from(&base_host);
    step11.dialect = dialect;
    step11.base_host = base_host;

    let policy = enforce_policy.then(|| {
        let policy_path = cli.remediation_policy.clone().or(policy_file);
        let playbook_path = cli.remediation_playbook.clone().or(playbook_file);
        if policy_path.is_none() && playbook_path.is_none() {
            eprintln!(
                "  [s10] ⚠ remediation policy enforcement is ON but neither \
                 --remediation-policy/step_remediate.policy_file nor \
                 --remediation-playbook/step_remediate.playbook_file is set; \
                 the gate fails closed, so EVERY finding will be guidance-only \
                 (no patches will be generated)"
            );
        }
        let gate = match &policy_path {
            Some(path) => appsec_policy_gate::RemediationGate::load(path),
            None => appsec_policy_gate::RemediationGate::new(None),
        };
        let playbook = playbook_path
            .as_deref()
            .map(appsec_policy_gate::load_playbook)
            .unwrap_or_default();
        let frameworks = appsec_policy_gate::detect_frameworks(repo_path(cli));
        appsec_stage_s10::PolicyContext::new(gate, playbook, frameworks)
    });

    Ok(RemediateSettings {
        target_tests: target_testing::load_config(cli)?,
        config: appsec_orchestrator::RemediateConfig {
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

pub(super) fn engine_identity(cli: &Cli) -> (String, String) {
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

pub(super) fn global_sampling(cli: &Cli) -> config_overrides::GlobalSampling {
    config_overrides::GlobalSampling {
        temperature: cli.temperature,
        top_p: cli.top_p,
        seed: cli.seed,
        reasoning_effort: cli.reasoning_effort,
        step_timeout_secs: cli.step_timeout,
    }
}

pub(super) fn apply_remediation_gate_flags(cli: &Cli, step10: &mut appsec_stage_s10::Step10Config) {
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

pub fn build_scan_input(cli: &Cli) -> ScanInput {
    let repo_name = cli.repo_name.clone().unwrap_or_else(|| {
        repo_path(cli)
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "repo".to_string())
    });
    ScanInput {
        repo_root: repo_path(cli).to_path_buf(),
        repo_name,
        application_id: non_empty(&cli.app_id).map(str::to_string),
        cmdb_path: non_empty(&cli.cmdb_csv).map(PathBuf::from),
        context_dir: non_empty(&cli.context_dir).map(PathBuf::from),
        context_mcp_server: non_empty(&cli.context_mcp_server).map(PathBuf::from),
        context_mcp_spaces: cli.context_mcp_spaces.clone(),
        context_mcp_label: non_empty(&cli.context_mcp_label).map(str::to_owned),
        context_files: cli.context_files.clone(),
        context_urls: cli.context_urls.clone(),
        git_sha_override: non_empty(&cli.git_sha).map(str::to_string),
        repo_key_override: non_empty(&cli.repo_key).map(str::to_string),
        repo_key_env: std::env::var("BC_REPO_KEY")
            .ok()
            .as_deref()
            .and_then(non_empty)
            .map(str::to_string),
        branch_override: non_empty(&cli.branch).map(str::to_string),
        base_ref: non_empty(&cli.base_ref).map(str::to_string),
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

pub(super) fn build_semgrep_live_config(
    cli: &Cli,
) -> Option<appsec_thirdparty_api::semgrep::SemgrepConfig> {
    let token = cli.semgrep_token.clone()?;
    let deployment_slug = cli.semgrep_deployment_slug.clone()?;
    let repo = cli.semgrep_repo.clone()?;
    let mut config =
        appsec_thirdparty_api::semgrep::SemgrepConfig::new(token, deployment_slug, repo);
    config.branch = cli.semgrep_branch.clone();
    if let Some(base_url) = &cli.semgrep_base_url {
        config.base_url = base_url.clone();
    }
    Some(config)
}

pub(super) fn build_snyk_live_config(cli: &Cli) -> Option<appsec_thirdparty_api::snyk::SnykConfig> {
    let token = cli.snyk_token.clone()?;
    let org_id = cli.snyk_org_id.clone()?;
    let project_id = cli.snyk_project_id.clone()?;
    let mut config = appsec_thirdparty_api::snyk::SnykConfig::new(token, org_id, project_id);
    if let Some(base_url) = &cli.snyk_base_url {
        config.base_url = base_url.clone();
    }
    Some(config)
}

pub(super) fn build_sonatype_live_config(
    cli: &Cli,
) -> Option<appsec_thirdparty_api::sonatype::SonatypeConfig> {
    let base_url = cli.sonatype_base_url.clone()?;
    let username = cli.sonatype_username.clone()?;
    let password = cli.sonatype_password.clone()?;
    let app_id = cli.sonatype_app_id.clone()?;
    let mut config =
        appsec_thirdparty_api::sonatype::SonatypeConfig::new(base_url, username, password, app_id);
    if let Some(stage) = &cli.sonatype_stage {
        config.stage = stage.clone();
    }
    Some(config)
}

pub(super) fn build_aikido_live_config(
    cli: &Cli,
) -> Option<appsec_thirdparty_api::aikido::AikidoConfig> {
    let client_id = cli.aikido_client_id.clone()?;
    let client_secret = cli.aikido_client_secret.clone()?;
    let repo_id = cli.aikido_repo_id?;
    let mut config =
        appsec_thirdparty_api::aikido::AikidoConfig::new(client_id, client_secret, repo_id);
    if let Some(base_url) = &cli.aikido_base_url {
        config.base_url = base_url.clone();
    }
    Some(config)
}

pub(super) fn build_checkmarx_live_config(
    cli: &Cli,
) -> Option<appsec_thirdparty_api::checkmarx::CheckmarxConfig> {
    let base_url = cli.checkmarx_base_url.clone()?;
    let iam_url = cli.checkmarx_iam_url.clone()?;
    let tenant = cli.checkmarx_tenant.clone()?;
    let api_key = cli.checkmarx_api_key.clone()?;
    let project_id = cli.checkmarx_project_id.clone()?;
    let mut config = appsec_thirdparty_api::checkmarx::CheckmarxConfig::new(
        base_url, iam_url, tenant, api_key, project_id,
    );
    config.branch = cli.checkmarx_branch.clone();
    Some(config)
}
