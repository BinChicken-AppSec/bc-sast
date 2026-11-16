use super::*;

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
    assert_eq!(process_exit_code(&ok(failed_remediation), false, false), 0);
    assert_eq!(
        process_exit_code(&ok(ScanSummary::default()), true, true),
        130
    );
    assert_eq!(process_exit_code(&Err("boom".to_string()), true, true), 130);
}
#[test]
fn repo_alone_parses_fine() {
    let cli = Cli::try_parse_from([
        "appsec-scan",
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
        "appsec-scan",
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
    let result = Cli::try_parse_from(["appsec-scan", "--gateway-base-url", "http://127.0.0.1:0"]);
    assert!(result.is_err());
}
#[test]
fn both_repo_and_repo_file_fails_to_parse() {
    let result = Cli::try_parse_from([
        "appsec-scan",
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
    let config_dir = tempfile::tempdir().unwrap();
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
    c.gateway_base_url = "https://api.openai.com/v1".to_string();
    assert_eq!(
        build_scan_config(&c).unwrap().pricing.provider.as_deref(),
        Some("from-config")
    );
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
        "appsec-scan",
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
        "appsec-scan",
        "--gateway-base-url",
        "http://127.0.0.1:1",
        "--repo",
        "/repo",
        "--remediate",
    ];
    let c = Cli::try_parse_from(base.into_iter().chain(["--target-tests"])).unwrap();
    assert_eq!(c.target_tests.as_deref(), Some("comprehensive"));
    let c =
        Cli::try_parse_from(base.into_iter().chain(["--testing-level", "integration"])).unwrap();
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
#[test]
fn a_symlinked_output_directory_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let real = tmp.path().join("elsewhere");
    std::fs::create_dir(&real).unwrap();
    let link = tmp.path().join("security-scan");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&real, &link).unwrap();
    #[cfg(not(unix))]
    return;
    let err = reject_unsafe_output_dir(&link).unwrap_err();
    assert!(err.contains("symbolic link"), "{err}");
}
#[test]
fn an_output_directory_reached_through_a_linked_parent_is_allowed() {
    let tmp = tempfile::tempdir().unwrap();
    let real_parent = tmp.path().join("real");
    std::fs::create_dir_all(real_parent.join("out")).unwrap();
    let linked_parent = tmp.path().join("linked");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&real_parent, &linked_parent).unwrap();
    #[cfg(not(unix))]
    return;
    let through = linked_parent.join("out");
    assert!(reject_unsafe_output_dir(&through).is_ok());
}
#[test]
fn an_ordinary_output_directory_is_accepted() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("security-scan");
    std::fs::create_dir(&dir).unwrap();
    assert!(reject_unsafe_output_dir(&dir).is_ok());
}
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
    let base = [
        "appsec-scan",
        "--repo",
        "/r",
        "--gateway-base-url",
        "http://h",
    ];
    let cli = Cli::try_parse_from(base).unwrap();
    assert_eq!(cli.model, "gpt-6-luna");
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
        Some(appsec_llm_client::ReasoningEffort::XHigh)
    );
    assert_eq!(
        cli.openai_api,
        Some(appsec_llm_client::OpenAiApi::Responses)
    );
    assert!(cli.no_cache_markers && cli.allow_unsupported_model && cli.cache_probe);

    for bad in [
        &["--reasoning-effort", "extreme"][..],
        &["--openai-api", "grpc"],
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
    let base = [
        "appsec-scan",
        "--repo",
        "/r",
        "--gateway-base-url",
        "http://h",
    ];
    let from_env = Cli::try_parse_from(base).unwrap().openai_api;
    let from_flag = Cli::try_parse_from(base.into_iter().chain(["--openai-api", "auto"]))
        .unwrap()
        .openai_api;
    restore_env("BC_OPENAI_API", prior);
    assert_eq!(from_env, Some(appsec_llm_client::OpenAiApi::Chat));
    assert_eq!(from_flag, Some(appsec_llm_client::OpenAiApi::Auto));
}
#[test]
fn build_llm_stack_resolves_the_transport_and_shares_the_openai_learning() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.yaml");
    std::fs::write(&config, "llm:\n  openai_api: chat\n  cache_ttl: 1h\n").unwrap();
    let mut c = cli(dir.path());
    c.config = Some(config.clone());
    let stack = build_llm_stack(&c).unwrap();
    assert_eq!(
        stack.settings.openai_api,
        appsec_llm_client::OpenAiApi::Chat
    );
    assert_eq!(
        stack.settings.cache.ttl,
        appsec_llm_client::CacheTtl::OneHour
    );
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
    let config_dir = tempfile::tempdir().unwrap();
    let config = config_dir.path().join("config.yaml");
    std::fs::write(&config, "llm:\n  cache_ttl: 1h\n").unwrap();
    let mut c = cli(dir.path());
    c.config = Some(config);
    assert_eq!(
        build_scan_config(&c).unwrap().pricing.cache_ttl,
        appsec_llm_client::CacheTtl::FiveMinutes
    );
    c.dialect = Dialect::Anthropic;
    assert_eq!(
        build_scan_config(&c).unwrap().pricing.cache_ttl,
        appsec_llm_client::CacheTtl::OneHour
    );
}
#[test]
fn a_misspelt_effort_in_the_config_fails_the_run_up_front() {
    let dir = tempfile::tempdir().unwrap();
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
    let config_dir = tempfile::tempdir().unwrap();
    let config = config_dir.path().join("config.yaml");
    std::fs::write(
        &config,
        "models:\n  verify:\n    effort: max\n    use_responses_api: true\n",
    )
    .unwrap();
    let mut c = cli(dir.path());
    c.config = Some(config);
    c.reasoning_effort = Some(appsec_llm_client::ReasoningEffort::Low);
    let scan = build_scan_config(&c).unwrap();
    assert_eq!(
        scan.step6.reasoning_effort,
        Some(appsec_llm_client::ReasoningEffort::Max)
    );
    assert_eq!(
        scan.step6.openai_api,
        Some(appsec_llm_client::OpenAiApi::Responses)
    );
    assert_eq!(
        scan.step4.reasoning_effort,
        Some(appsec_llm_client::ReasoningEffort::Low)
    );
    let remediate = build_remediate_settings(&c).unwrap();
    assert_eq!(
        remediate.config.step10.reasoning_effort,
        Some(appsec_llm_client::ReasoningEffort::Low)
    );
    assert_eq!(
        remediate.step11.reasoning_effort,
        Some(appsec_llm_client::ReasoningEffort::Low)
    );
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
    let builder = reqwest::Client::builder().user_agent("bad\nvalue");
    let err = finish_github_http_client(builder).unwrap_err();
    assert!(err.contains("failed to build GitHub HTTP client"));
}
#[test]
fn build_scan_input_falls_back_to_repo_when_the_path_has_no_file_name() {
    let input = build_scan_input(&cli(Path::new("/")));
    assert_eq!(input.repo_name, "repo");
}
#[test]
fn create_parent_dir_of_a_path_with_no_parent_is_a_no_op() {
    assert!(create_parent_dir(Path::new("/")).is_ok());
}
