use super::*;
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
        Some(Ok(appsec_github::SyncSummary {
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
        Some(Ok(appsec_github::SyncSummary::default()))
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
    assert_eq!(settings.config.top, Some(appsec_stage_s10::TopSpec::N(3)));
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
    let config_dir = tempfile::tempdir().unwrap();
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
        Some(appsec_stage_s10::TopSpec::N(5))
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
    let config_dir = tempfile::tempdir().unwrap();
    let config_path = config_dir.path().join("config.yaml");
    std::fs::write(
        &config_path,
        "models:\n  validate:\n    id: opus\nstep_validate:\n  max_turns: 12\n  allowed_tools: [Read]\n",
    )
    .unwrap();
    let mut c = cli(repo_dir.path());
    c.config = Some(config_path);
    let settings = build_remediate_settings(&c).unwrap();
    assert!(settings.validate_enabled);
    assert_eq!(settings.step11.model, "opus");
    assert_eq!(settings.step11.max_turns, 12);
    assert_eq!(settings.step11.allowed_tools, vec!["Read".to_string()]);
}
#[test]
fn build_remediate_settings_can_disable_validation_via_config() {
    let repo_dir = tempfile::tempdir().unwrap();
    let config_dir = tempfile::tempdir().unwrap();
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
    let config_dir = tempfile::tempdir().unwrap();
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
    assert_eq!(decision.action, appsec_policy_gate::Action::Patch);
}
#[test]
fn remediation_summary_from_counts_processed_and_failed_outcomes() {
    let outcome = appsec_orchestrator::RemediateOutcome {
        validation_failures: 0,
        refused: None,
        outcomes: vec![
            appsec_stage_s10::RemediationOutcome::Processed(Box::new(
                appsec_stage_s10::RemediationRecord {
                    finding_index: 1,
                    finding_id: "fid1".to_string(),
                    verdict: appsec_stage_s10::RemediationVerdict::denied(1, "x"),
                    policy_action: None,
                    policy_reason: None,
                    final_verdict: None,
                    policy_reverted: Vec::new(),
                    policy_matched_globs: Vec::new(),
                    diff: None,
                },
            )),
            appsec_stage_s10::RemediationOutcome::Failed {
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
    let outcome = appsec_orchestrator::RemediateOutcome {
        validation_failures: 0,
        refused: None,
        outcomes: vec![
            appsec_stage_s10::RemediationOutcome::Failed {
                finding_index: 1,
                error: "boom".to_string(),
            },
            appsec_stage_s10::RemediationOutcome::Processed(Box::new(
                appsec_stage_s10::RemediationRecord {
                    finding_index: 2,
                    finding_id: "fid2".to_string(),
                    verdict: appsec_stage_s10::RemediationVerdict::denied(2, "x"),
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
            Some(validation_score(
                appsec_validation_scoring::FixVerdict::Fixed,
            )),
        ],
    };
    let by_id = validations_by_finding_id(&outcome);
    assert_eq!(by_id.len(), 1);
    assert!(by_id.contains_key("fid2"));
}
#[test]
fn remediation_summary_from_tallies_every_fix_verdict_when_validation_ran() {
    let outcome = appsec_orchestrator::RemediateOutcome {
        validation_failures: 0,
        refused: None,
        outcomes: Vec::new(),
        validations: vec![
            Some(validation_score(
                appsec_validation_scoring::FixVerdict::Fixed,
            )),
            Some(validation_score(
                appsec_validation_scoring::FixVerdict::PartiallyFixed,
            )),
            Some(validation_score(
                appsec_validation_scoring::FixVerdict::NotFixed,
            )),
            Some(validation_score(
                appsec_validation_scoring::FixVerdict::Unverifiable,
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
fn write_remediation_json_is_a_no_op_without_a_path() {
    let outcome = appsec_orchestrator::RemediateOutcome::default();
    assert!(write_remediation_json(None, &outcome).is_ok());
}
#[test]
fn write_remediation_json_propagates_an_io_error() {
    let dir = tempfile::tempdir().unwrap();
    let unwritable = dir.path().join("locked");
    std::fs::write(&unwritable, "not a directory").unwrap();
    let path = unwritable.join("nested/remediation.json");
    let outcome = appsec_orchestrator::RemediateOutcome::default();
    let result = write_remediation_json(Some(&path), &outcome);
    assert!(result.is_err());
}
#[test]
fn write_remediation_json_writes_the_refusal_reason_and_results() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("out/remediation.json");
    let outcome = appsec_orchestrator::RemediateOutcome {
        validation_failures: 0,
        refused: Some("stale".to_string()),
        outcomes: vec![appsec_stage_s10::RemediationOutcome::Failed {
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
    let mut verdict = appsec_stage_s10::RemediationVerdict::denied(1, "x");
    verdict.changes.push(appsec_stage_s10::Change {
        file: "app.py".to_string(),
        summary: "fixed it".to_string(),
    });
    let outcome = appsec_orchestrator::RemediateOutcome {
        validation_failures: 0,
        refused: None,
        outcomes: vec![appsec_stage_s10::RemediationOutcome::Processed(Box::new(
            appsec_stage_s10::RemediationRecord {
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
    let mut step10 = appsec_stage_s10::Step10Config::new("m");
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
    let mut step10 = appsec_stage_s10::Step10Config::new("m");
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
    let decision = policy.gate.decide("CWE-89", "app.py", &|_| None);
    assert_eq!(decision.action, appsec_policy_gate::Action::Patch);
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
        appsec_policy_gate::Action::Patch
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
    let second_id = appsec_sarif::finding_id(&second);
    let outcome = appsec_orchestrator::RemediateOutcome {
        refused: None,
        outcomes: vec![
            appsec_stage_s10::RemediationOutcome::Failed {
                finding_index: 1,
                error: "boom".to_string(),
            },
            processed_record(&second_id, appsec_stage_s10::Verdict::Fixed, Some("diff")),
            processed_record("orphan", appsec_stage_s10::Verdict::Fixed, None),
        ],
        validations: vec![
            None,
            Some(validation_score(
                appsec_validation_scoring::FixVerdict::Fixed,
            )),
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
    let id = appsec_sarif::finding_id(&finding);
    let report = sample_report(None, vec![finding]);
    let mut outcome = appsec_orchestrator::RemediateOutcome {
        refused: None,
        outcomes: vec![processed_record(
            &id,
            appsec_stage_s10::Verdict::Fixed,
            None,
        )],
        validations: Vec::new(),
        validation_failures: 0,
    };
    if let appsec_stage_s10::RemediationOutcome::Processed(r) = &mut outcome.outcomes[0] {
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
    let id = appsec_sarif::finding_id(&finding);
    let report = sample_report(None, vec![finding]);
    let markdown = appsec_report_md::render_markdown(&report);
    std::fs::write(&md_path, &markdown).unwrap();
    let outcome = appsec_orchestrator::RemediateOutcome {
        refused: None,
        outcomes: vec![processed_record(
            &id,
            appsec_stage_s10::Verdict::Fixed,
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
    let outcome = appsec_orchestrator::RemediateOutcome {
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
    assert!(summary.markdown_path.is_none());
    assert!(summary.sarif_path.is_none());
    assert!(summary.findings_json_path.is_none());
    assert!(!dir.path().join("security-scan").exists());
    let written: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out_json).unwrap()).unwrap();
    assert_eq!(written["results"][0]["status"], "processed");
}
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

    let server = diff_server("--- a/app.py\n+++ b/app.py\n@@ -1,1 +1,2 @@\n x = 1\n+y = 2\n").await;
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
        appsec_stage_s10::OUT_OF_DIFF_SCOPE_ACTION
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join("helper.py")).unwrap(),
        "print('helper')\n"
    );
}
#[test]
fn the_exports_cvss_band_reconstructs_the_severity_s8_assigned() {
    let mut f = sample_finding();
    f.cvss_rating = Some("Critical".to_string());
    assert_eq!(
        appsec_stage_s8::final_severity(&f, appsec_model::Severity::Info),
        appsec_model::Severity::Critical
    );
    f.cvss_rating = None;
    assert_eq!(
        appsec_stage_s8::final_severity(&f, appsec_model::Severity::Info),
        appsec_model::Severity::Info
    );
}
#[tokio::test]
async fn remediate_interactively_refuses_when_head_has_moved_since_the_scan() {
    let dir = git_repo();
    let report = sample_report(
        Some("stale0000000000000000000000000000000000"),
        vec![sample_finding()],
    );
    let tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));
    let mut term = FakeTerminal::tty(vec![Ok(appsec_interactive::Key::Quit)]);

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
    let mut term = FakeTerminal::tty(vec![Ok(appsec_interactive::Key::Quit)]);

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
        Ok(appsec_interactive::Key::Enter),
        Ok(appsec_interactive::Key::Quit),
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
async fn remediate_interactively_validates_the_finding_the_user_selects_when_validation_is_enabled()
{
    let dir = git_repo();
    std::fs::write(dir.path().join("app.py"), "query(x)\n").unwrap();
    let report = sample_report(None, vec![sample_finding()]);
    let tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));
    let validate_tools = SandboxTools::new(dir.path());
    let step11 = fast_step11_config();
    let mut term = FakeTerminal::tty(vec![
        Ok(appsec_interactive::Key::Enter),
        Ok(appsec_interactive::Key::Quit),
    ]);

    let result = remediate_interactively(
        Arc::new(OneFindingClientWithValidation::new()),
        tools,
        dir.path(),
        &report,
        &remediate_config_no_cap(),
        None,
        None,
        Some(appsec_interactive::ValidateContext {
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
        appsec_validation_scoring::FixVerdict::Fixed
    );
}
#[tokio::test]
async fn remediate_interactively_with_an_explicit_top_cap_cvss_ranks_the_menu() {
    let dir = git_repo();
    std::fs::write(dir.path().join("app.py"), "query(x)\n").unwrap();
    let report = sample_report(None, vec![sample_finding(), sample_finding()]);
    let tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));
    let mut term = FakeTerminal::tty(vec![Ok(appsec_interactive::Key::Quit)]);
    let mut config = remediate_config_no_cap();
    config.top = Some(appsec_stage_s10::TopSpec::N(1));

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
        paths.provider_writeback_plan = Some(dir.path().join("out/provider-writeback-plan.json"));
        let client = one_finding_client();
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
        "appsec-scan",
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
        "appsec-scan",
        "--repo",
        "/repo",
        "--provider-writeback",
        "apply"
    ])
    .is_err());
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
            appsec_orchestrator::head_sha(dir.path()).expect("fixture has a committed HEAD");
        let publication =
            provider_publish::automatic::configure_at(&c, state.path().join("private")).unwrap();
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
    c.git_sha = appsec_orchestrator::head_sha(dir.path()).expect("fixture has a committed HEAD");
    for mode in 0..3 {
        let publication =
            provider_publish::automatic::configure_at(&c, state.path().join("private")).unwrap();
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
        "appsec-scan",
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
