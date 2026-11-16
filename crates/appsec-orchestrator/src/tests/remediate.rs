use super::*;
#[tokio::test]
async fn remediate_processes_every_finding_when_the_repo_is_not_a_git_target() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("app.py"), "print(1)\n").unwrap();
    let report = s10_report(dir.path(), vec![s10_ranked(Some(7.0))], None);
    let llm: Arc<dyn LlmClient> = Arc::new(S10Client);
    let tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));

    let outcome = remediate(
        llm,
        tools,
        dir.path(),
        &report,
        &s10_config(),
        None,
        None,
        None,
    )
    .await;

    assert!(outcome.refused.is_none());
    assert_eq!(outcome.outcomes.len(), 1);
    let _ = expect_processed(&outcome.outcomes[0]);
    assert!(outcome.validations.is_empty());
}
#[tokio::test]
async fn remediate_announces_a_dry_run_differently_from_fix_mode() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("app.py"), "print(1)\n").unwrap();
    let report = s10_report(dir.path(), vec![s10_ranked(Some(7.0))], None);
    let llm: Arc<dyn LlmClient> = Arc::new(S10Client);
    let tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));
    let mut config = s10_config();
    config.step10.dry_run = true;

    let outcome = remediate(llm, tools, dir.path(), &report, &config, None, None, None).await;

    assert!(outcome.refused.is_none());
    assert_eq!(outcome.outcomes.len(), 1);
}
#[tokio::test]
async fn remediate_announces_an_isolated_run_without_the_fix_mode_warning() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("app.py"), "print(1)\n").unwrap();
    let report = s10_report(dir.path(), vec![s10_ranked(Some(7.0))], None);
    let llm: Arc<dyn LlmClient> = Arc::new(S10Client);
    let tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));
    let mut config = s10_config();
    config.isolated = true;

    let outcome = remediate(llm, tools, dir.path(), &report, &config, None, None, None).await;

    assert!(outcome.refused.is_none());
    assert_eq!(outcome.outcomes.len(), 1);
}
#[tokio::test]
async fn remediate_of_a_report_with_no_findings_warns_about_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let report = s10_report(dir.path(), Vec::new(), None);
    let llm: Arc<dyn LlmClient> = Arc::new(S10Client);
    let tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));

    let outcome = remediate(
        llm,
        tools,
        dir.path(),
        &report,
        &s10_config(),
        None,
        None,
        None,
    )
    .await;

    assert!(outcome.refused.is_none());
    assert!(outcome.outcomes.is_empty());
}
#[tokio::test]
async fn remediate_rolls_a_failed_validation_back_end_to_end_without_git() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("app.py"), "print(1)\n").unwrap();
    assert!(!is_git_worktree(dir.path()));
    let report = s10_report(dir.path(), vec![s10_ranked(Some(7.0))], None);
    let llm: Arc<dyn LlmClient> = Arc::new(S10SucceedsS11GradesNotFixedClient {
        remediate_turn: Mutex::new(0),
    });
    let tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));
    let read_only_tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new(dir.path()));
    let step11 = s11_config();

    let outcome = remediate(
        llm,
        tools,
        dir.path(),
        &report,
        &s10_config(),
        None,
        None,
        Some(ValidateConfig {
            step11: &step11,
            tools: read_only_tools.as_ref(),
        }),
    )
    .await;

    assert_eq!(
        outcome.validations[0].as_ref().map(|v| v.fix_status),
        Some(appsec_validation_scoring::FixVerdict::NotFixed)
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join("app.py")).unwrap(),
        "print(1)\n"
    );
    let record = expect_processed(&outcome.outcomes[0]);
    assert!(appsec_stage_s10::was_reverted(record));
    assert_eq!(record.diff, None);
}
#[tokio::test]
async fn remediate_with_validation_enabled_caps_to_max_findings_by_cvss() {
    let dir = tempfile::tempdir().unwrap();
    let report = s10_report(
        dir.path(),
        vec![
            s10_ranked(Some(1.0)),
            s10_ranked(Some(9.0)),
            s10_ranked(Some(5.0)),
        ],
        None,
    );
    let llm: Arc<dyn LlmClient> = Arc::new(MultiFindingClient::new());
    let tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));
    let read_only_tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new(dir.path()));
    let mut step11 = s11_config();
    step11.max_findings = Some(2);

    let outcome = remediate(
        llm,
        tools,
        dir.path(),
        &report,
        &s10_config(),
        None,
        None,
        Some(ValidateConfig {
            step11: &step11,
            tools: read_only_tools.as_ref(),
        }),
    )
    .await;

    assert_eq!(outcome.outcomes.len(), 3);
    for o in &outcome.outcomes {
        assert!(expect_processed(o).diff.is_some());
    }
    assert_eq!(outcome.validations.len(), 3);
    assert!(outcome.validations[0].is_none());
    assert!(outcome.validations[1].is_some());
    assert!(outcome.validations[2].is_some());
}
#[tokio::test]
async fn remediate_with_validation_enabled_and_no_cap_validates_every_validatable_finding() {
    let dir = tempfile::tempdir().unwrap();
    let report = s10_report(
        dir.path(),
        vec![s10_ranked(Some(1.0)), s10_ranked(Some(9.0))],
        None,
    );
    let llm: Arc<dyn LlmClient> = Arc::new(MultiFindingClient::new());
    let tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));
    let read_only_tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new(dir.path()));
    let mut step11 = s11_config();
    step11.max_findings = None;

    let outcome = remediate(
        llm,
        tools,
        dir.path(),
        &report,
        &s10_config(),
        None,
        None,
        Some(ValidateConfig {
            step11: &step11,
            tools: read_only_tools.as_ref(),
        }),
    )
    .await;

    assert_eq!(outcome.validations.len(), 2);
    assert!(outcome.validations[0].is_some());
    assert!(outcome.validations[1].is_some());
}
#[tokio::test]
async fn remediate_with_validation_enabled_caps_falls_back_to_the_severity_band_when_a_finding_has_no_numeric_cvss_score(
) {
    let dir = tempfile::tempdir().unwrap();
    let report = s10_report(
        dir.path(),
        vec![s10_ranked(None), s10_ranked(Some(9.0))],
        None,
    );
    let llm: Arc<dyn LlmClient> = Arc::new(MultiFindingClient::new());
    let tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));
    let read_only_tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new(dir.path()));
    let mut step11 = s11_config();
    step11.max_findings = Some(1);

    let outcome = remediate(
        llm,
        tools,
        dir.path(),
        &report,
        &s10_config(),
        None,
        None,
        Some(ValidateConfig {
            step11: &step11,
            tools: read_only_tools.as_ref(),
        }),
    )
    .await;

    assert_eq!(outcome.validations.len(), 2);
    assert!(outcome.validations[0].is_none());
    assert!(outcome.validations[1].is_some());
}
#[test]
fn redact_remediate_outcome_scrubs_every_string_a_remediation_carries() {
    const PAN: &str = "4111111111111111";
    let record = appsec_stage_s10::RemediationRecord {
        finding_index: 1,
        finding_id: "abc123".to_string(),
        verdict: appsec_stage_s10::RemediationVerdict {
            finding_index: 1,
            verdict: appsec_stage_s10::Verdict::Fixed,
            gates: appsec_stage_s10::Gates::default(),
            root_cause: format!("hardcoded secret {PAN} removed"),
            changes: vec![appsec_stage_s10::Change {
                file: "app.py".to_string(),
                summary: format!("replaced {PAN} with an env var"),
            }],
            remaining_risks: vec![format!("audit log may still show {PAN}")],
            recommendations: vec![format!("rotate {PAN}")],
            summary: format!("fixed; old value was {PAN}"),
        },
        policy_action: None,
        policy_reason: Some(format!("matched deny rule near {PAN}")),
        final_verdict: None,
        policy_reverted: Vec::new(),
        policy_matched_globs: Vec::new(),
        diff: Some(format!("-KEY = \"{PAN}\"\n+KEY = os.environ[\"KEY\"]\n")),
    };
    let outcome = appsec_orchestrator_remediate_outcome_fixture(record, PAN);

    let redacted = redact_remediate_outcome(outcome);

    let record = expect_processed(&redacted.outcomes[0]);
    let record_json = serde_json::to_string(record).unwrap();
    assert!(!record_json.contains(PAN), "record still contains PAN");

    assert!(!expect_failed(&redacted.outcomes[1]).contains(PAN));

    let score = redacted.validations[0].as_ref().unwrap();
    assert!(!score.justification.contains(PAN));
    assert!(!score.gate_results[0].summary.contains(PAN));
    assert!(!score.gate_results[0].details.contains(PAN));
    assert!(!score.gate_results[0].evidence[0].snippet.contains(PAN));
}
#[tokio::test]
async fn remediate_with_validation_enabled_populates_the_validations_vector() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("app.py"), "print(1)\n").unwrap();
    let report = s10_report(dir.path(), vec![s10_ranked(Some(7.0))], None);
    let llm: Arc<dyn LlmClient> = Arc::new(S10AndS11Client::new());
    let tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));
    let read_only_tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new(dir.path()));
    let step11 = s11_config();

    let outcome = remediate(
        llm,
        tools,
        dir.path(),
        &report,
        &s10_config(),
        None,
        None,
        Some(ValidateConfig {
            step11: &step11,
            tools: read_only_tools.as_ref(),
        }),
    )
    .await;

    assert_eq!(outcome.outcomes.len(), 1);
    let record = expect_processed(&outcome.outcomes[0]);
    assert!(record.diff.is_some());
    assert_eq!(outcome.validations.len(), 1);
    let score = outcome.validations[0]
        .as_ref()
        .expect("a diffed Processed finding should have been validated");
    assert_eq!(
        score.fix_status,
        appsec_validation_scoring::FixVerdict::Fixed
    );
}
#[tokio::test]
async fn remediate_counts_and_surfaces_a_genuine_validation_error() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("app.py"), "print(1)\n").unwrap();
    let report = s10_report(dir.path(), vec![s10_ranked(Some(7.0))], None);
    let llm: Arc<dyn LlmClient> = Arc::new(S10SucceedsS11FailsClient::new());
    let tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));
    let read_only_tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new(dir.path()));
    let step11 = s11_config();

    let outcome = remediate(
        llm,
        tools,
        dir.path(),
        &report,
        &s10_config(),
        None,
        None,
        Some(ValidateConfig {
            step11: &step11,
            tools: read_only_tools.as_ref(),
        }),
    )
    .await;

    let record = expect_processed(&outcome.outcomes[0]);
    assert!(record.diff.is_some());
    assert_eq!(outcome.validations, vec![None]);
    assert_eq!(outcome.validation_failures, 1);
}
#[tokio::test]
async fn remediate_with_validation_enabled_skips_a_failed_outcome() {
    let dir = tempfile::tempdir().unwrap();
    let report = s10_report(dir.path(), vec![s10_ranked(Some(7.0))], None);
    let llm: Arc<dyn LlmClient> = Arc::new(FailingClient);
    let tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));
    let read_only_tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new(dir.path()));
    let step11 = s11_config();

    let outcome = remediate(
        llm,
        tools,
        dir.path(),
        &report,
        &s10_config(),
        None,
        None,
        Some(ValidateConfig {
            step11: &step11,
            tools: read_only_tools.as_ref(),
        }),
    )
    .await;

    assert_eq!(outcome.outcomes.len(), 1);
    assert!(matches!(
        outcome.outcomes[0],
        appsec_stage_s10::RemediationOutcome::Failed { .. }
    ));
    assert_eq!(outcome.validations, vec![None]);
}
#[tokio::test]
async fn remediate_with_validation_enabled_skips_a_processed_finding_with_no_diff() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("app.py"), "print(1)\n").unwrap();
    let report = s10_report(dir.path(), vec![s10_ranked(Some(7.0))], None);
    let llm: Arc<dyn LlmClient> = Arc::new(S10Client);
    let tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));
    let read_only_tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new(dir.path()));
    let step11 = s11_config();

    let outcome = remediate(
        llm,
        tools,
        dir.path(),
        &report,
        &s10_config(),
        None,
        None,
        Some(ValidateConfig {
            step11: &step11,
            tools: read_only_tools.as_ref(),
        }),
    )
    .await;

    let record = expect_processed(&outcome.outcomes[0]);
    assert!(record.diff.is_none());
    assert_eq!(outcome.validations, vec![None]);
}
#[tokio::test]
async fn remediate_refuses_when_head_has_moved_since_the_scan() {
    let dir = tempfile::tempdir().unwrap();
    std::process::Command::new("git")
        .arg("-C")
        .arg(dir.path())
        .args(["init", "-q"])
        .output()
        .unwrap();
    std::fs::write(dir.path().join("app.py"), "print(1)\n").unwrap();
    std::process::Command::new("git")
        .arg("-C")
        .arg(dir.path())
        .args(["add", "-A"])
        .output()
        .unwrap();
    std::process::Command::new("git")
        .arg("-C")
        .arg(dir.path())
        .args([
            "-c",
            "user.email=test@test.com",
            "-c",
            "user.name=test",
            "commit",
            "-q",
            "-m",
            "x",
        ])
        .output()
        .unwrap();
    let report = s10_report(
        dir.path(),
        vec![s10_ranked(Some(7.0))],
        Some("stale0000000000000000000000000000000000".to_string()),
    );
    let llm: Arc<dyn LlmClient> = Arc::new(S10Client);
    let tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));

    let outcome = remediate(
        llm,
        tools,
        dir.path(),
        &report,
        &s10_config(),
        None,
        None,
        None,
    )
    .await;

    assert!(outcome.refused.unwrap().contains("HEAD moved since scan"));
    assert!(outcome.outcomes.is_empty());
}
#[tokio::test]
async fn remediate_force_overrides_the_git_sha_staleness_refusal() {
    let dir = tempfile::tempdir().unwrap();
    std::process::Command::new("git")
        .arg("-C")
        .arg(dir.path())
        .args(["init", "-q"])
        .output()
        .unwrap();
    std::fs::write(dir.path().join("app.py"), "print(1)\n").unwrap();
    std::process::Command::new("git")
        .arg("-C")
        .arg(dir.path())
        .args(["add", "-A"])
        .output()
        .unwrap();
    std::process::Command::new("git")
        .arg("-C")
        .arg(dir.path())
        .args([
            "-c",
            "user.email=test@test.com",
            "-c",
            "user.name=test",
            "commit",
            "-q",
            "-m",
            "x",
        ])
        .output()
        .unwrap();
    let report = s10_report(
        dir.path(),
        vec![s10_ranked(Some(7.0))],
        Some("stale0000000000000000000000000000000000".to_string()),
    );
    let llm: Arc<dyn LlmClient> = Arc::new(S10Client);
    let tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));
    let mut cfg = s10_config();
    cfg.force = true;

    let outcome = remediate(llm, tools, dir.path(), &report, &cfg, None, None, None).await;

    assert!(outcome.refused.is_none());
    assert_eq!(outcome.outcomes.len(), 1);
}
#[test]
fn severity_str_maps_every_variant() {
    assert_eq!(severity_str(Severity::Critical), "CRITICAL");
    assert_eq!(severity_str(Severity::High), "HIGH");
    assert_eq!(severity_str(Severity::Medium), "MEDIUM");
    assert_eq!(severity_str(Severity::Low), "LOW");
    assert_eq!(severity_str(Severity::Info), "INFO");
}
#[tokio::test]
async fn remediate_falls_back_to_the_severity_band_when_a_finding_has_no_numeric_cvss_score() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("app.py"), "print(1)\n").unwrap();
    let report = s10_report(dir.path(), vec![s10_ranked(None)], None);
    let llm: Arc<dyn LlmClient> = Arc::new(S10Client);
    let tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));
    let mut cfg = s10_config();
    cfg.top = Some(appsec_stage_s10::TopSpec::N(1));

    let outcome = remediate(llm, tools, dir.path(), &report, &cfg, None, None, None).await;

    assert_eq!(outcome.outcomes.len(), 1);
}
#[tokio::test]
async fn remediate_selects_only_the_top_n_findings_by_cvss() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("app.py"), "print(1)\n").unwrap();
    let report = s10_report(
        dir.path(),
        vec![
            s10_ranked(Some(1.0)),
            s10_ranked(Some(9.0)),
            s10_ranked(Some(5.0)),
        ],
        None,
    );
    let llm: Arc<dyn LlmClient> = Arc::new(S10Client);
    let tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));
    let mut cfg = s10_config();
    cfg.top = Some(appsec_stage_s10::TopSpec::N(1));

    let outcome = remediate(llm, tools, dir.path(), &report, &cfg, None, None, None).await;

    assert_eq!(outcome.outcomes.len(), 1);
    assert_eq!(expect_processed(&outcome.outcomes[0]).finding_index, 2);
}
#[tokio::test]
async fn remediate_with_a_checkpoint_store_saves_a_checkpoint_for_each_processed_finding() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("app.py"), "print(1)\n").unwrap();
    let report = s10_report(dir.path(), vec![s10_ranked(Some(7.0))], None);
    let llm: Arc<dyn LlmClient> = Arc::new(S10Client);
    let tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));
    let ckpt_dir = tempfile::tempdir().unwrap();
    let store: Arc<dyn appsec_checkpoint::CheckpointStore> = Arc::new(
        appsec_checkpoint::SqliteCheckpointStore::new(ckpt_dir.path().join("state.db")).unwrap(),
    );

    let outcome = remediate(
        llm,
        tools,
        dir.path(),
        &report,
        &s10_config(),
        None,
        Some(store.clone()),
        None,
    )
    .await;

    assert_eq!(outcome.outcomes.len(), 1);
    let run_id = appsec_checkpoint::run_id_for(dir.path());
    let step = appsec_stage_s10::remediation_step_key(&s10_config().step10, 1, &report.findings[0]);
    assert!(store.load(&run_id, &step).is_some());
}
#[tokio::test]
async fn remediate_with_resume_serves_a_cached_verdict_instead_of_the_fresh_client_response() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("app.py"), "print(1)\n").unwrap();
    let report = s10_report(dir.path(), vec![s10_ranked(Some(7.0))], None);
    let ckpt_dir = tempfile::tempdir().unwrap();
    let store: Arc<dyn appsec_checkpoint::CheckpointStore> = Arc::new(
        appsec_checkpoint::SqliteCheckpointStore::new(ckpt_dir.path().join("state.db")).unwrap(),
    );
    let mut cfg = s10_config();
    cfg.resume = true;

    let first_tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));
    let first = remediate(
        Arc::new(S10EditingClient::new()),
        first_tools,
        dir.path(),
        &report,
        &cfg,
        None,
        Some(store.clone()),
        None,
    )
    .await;
    assert_eq!(
        expect_processed(&first.outcomes[0]).verdict.verdict,
        appsec_stage_s10::Verdict::Fixed
    );

    let second_tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));
    let second = remediate(
        Arc::new(S10AltClient),
        second_tools,
        dir.path(),
        &report,
        &cfg,
        None,
        Some(store),
        None,
    )
    .await;

    assert_eq!(
        expect_processed(&second.outcomes[0]).verdict.verdict,
        appsec_stage_s10::Verdict::Fixed
    );
}
#[tokio::test]
async fn remediate_without_resume_ignores_an_existing_matching_checkpoint() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("app.py"), "print(1)\n").unwrap();
    let report = s10_report(dir.path(), vec![s10_ranked(Some(7.0))], None);
    let ckpt_dir = tempfile::tempdir().unwrap();
    let store: Arc<dyn appsec_checkpoint::CheckpointStore> = Arc::new(
        appsec_checkpoint::SqliteCheckpointStore::new(ckpt_dir.path().join("state.db")).unwrap(),
    );
    let mut cfg = s10_config();
    cfg.resume = true;

    let first_tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));
    remediate(
        Arc::new(S10Client),
        first_tools,
        dir.path(),
        &report,
        &cfg,
        None,
        Some(store.clone()),
        None,
    )
    .await;

    cfg.resume = false;
    let second_tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));
    let second = remediate(
        Arc::new(S10AltClient),
        second_tools,
        dir.path(),
        &report,
        &cfg,
        None,
        Some(store),
        None,
    )
    .await;

    assert_eq!(
        expect_processed(&second.outcomes[0]).verdict.verdict,
        appsec_stage_s10::Verdict::NotFixed
    );
}
#[tokio::test]
async fn remediate_registers_the_run_with_a_checkpoint_store() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("app.py"), "print(1)\n").unwrap();
    let report = s10_report(dir.path(), vec![s10_ranked(Some(7.0))], None);
    let ckpt_dir = tempfile::tempdir().unwrap();
    let db_path = ckpt_dir.path().join("state.db");
    let store: Arc<dyn appsec_checkpoint::CheckpointStore> =
        Arc::new(appsec_checkpoint::SqliteCheckpointStore::new(&db_path).unwrap());
    let tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));

    remediate(
        Arc::new(S10Client),
        tools,
        dir.path(),
        &report,
        &s10_config(),
        None,
        Some(store),
        None,
    )
    .await;

    let inspector = appsec_checkpoint::SqliteCheckpointStore::new(&db_path).unwrap();
    let report = inspector.prune(100, 5, true).unwrap();
    assert_eq!(report.kept, 1);
    assert!(report.deleted.is_empty());
}
#[tokio::test]
async fn remediate_registers_the_report_s_application_id_when_an_app_profile_is_present() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("app.py"), "print(1)\n").unwrap();
    let mut report = s10_report(dir.path(), vec![s10_ranked(Some(7.0))], None);
    report.app_profile = Some(AppProfile {
        exposure: String::new(),
        reaches: Vec::new(),
        reached_by: Vec::new(),
        application_id: "42".to_string(),
        name: String::new(),
        externally_facing: false,
        pci_scoped: false,
        processes_pan: false,
        pii: false,
        source: String::new(),
    });
    let spy = Arc::new(SpyCheckpointStore::default());
    let store: Arc<dyn appsec_checkpoint::CheckpointStore> = spy.clone();
    let tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));
    let mut config = s10_config();
    config.resume = true;

    remediate(
        Arc::new(S10Client),
        tools,
        dir.path(),
        &report,
        &config,
        None,
        Some(store),
        None,
    )
    .await;

    assert_eq!(
        *spy.registered_app_id.lock().unwrap(),
        Some(Some("42".to_string()))
    );
}
#[tokio::test]
async fn remediate_without_resume_clears_stale_checkpoints_via_reset_run() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("app.py"), "print(1)\n").unwrap();
    let report = s10_report(dir.path(), vec![s10_ranked(Some(7.0))], None);
    let ckpt_dir = tempfile::tempdir().unwrap();
    let db_path = ckpt_dir.path().join("state.db");
    let store: Arc<dyn appsec_checkpoint::CheckpointStore> =
        Arc::new(appsec_checkpoint::SqliteCheckpointStore::new(&db_path).unwrap());
    let run_id = appsec_checkpoint::run_id_for(dir.path());
    store.save(&run_id, "remediate_99", b"stale").unwrap();

    let mut cfg = s10_config();
    cfg.resume = false;
    let tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));
    remediate(
        Arc::new(S10Client),
        tools,
        dir.path(),
        &report,
        &cfg,
        None,
        Some(store.clone()),
        None,
    )
    .await;

    assert_eq!(store.load(&run_id, "remediate_99"), None);
}
#[tokio::test]
async fn remediate_with_resume_does_not_clear_stale_checkpoints() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("app.py"), "print(1)\n").unwrap();
    let report = s10_report(dir.path(), vec![s10_ranked(Some(7.0))], None);
    let ckpt_dir = tempfile::tempdir().unwrap();
    let db_path = ckpt_dir.path().join("state.db");
    let store: Arc<dyn appsec_checkpoint::CheckpointStore> =
        Arc::new(appsec_checkpoint::SqliteCheckpointStore::new(&db_path).unwrap());
    let run_id = appsec_checkpoint::run_id_for(dir.path());
    store.save(&run_id, "s1", b"stale").unwrap();

    let mut cfg = s10_config();
    cfg.resume = true;
    let tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));
    remediate(
        Arc::new(S10Client),
        tools,
        dir.path(),
        &report,
        &cfg,
        None,
        Some(store.clone()),
        None,
    )
    .await;

    assert_eq!(store.load(&run_id, "s1"), Some(b"stale".to_vec()));
}
#[test]
fn a_not_fixed_validation_rolls_the_patch_back() {
    for status in [
        appsec_validation_scoring::FixVerdict::NotFixed,
        appsec_validation_scoring::FixVerdict::Unverifiable,
    ] {
        let dir = patched_git_repo();
        let record = run_rollback(
            dir.path(),
            &["app.py"],
            None,
            status,
            &appsec_stage_s10::Step10Config::new("m"),
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("app.py")).unwrap(),
            "print('original')\n"
        );
        assert!(appsec_stage_s10::was_reverted(&record));
        assert_eq!(record.diff, None);
    }
}
#[test]
fn a_not_fixed_validation_rolls_back_from_the_baseline_with_no_git_at_all() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("app.py"), "print('a bad fix')\n").unwrap();
    let baseline = baseline_of("app.py", "print('original')\n");
    let record = run_rollback(
        dir.path(),
        &["app.py"],
        Some(&baseline),
        appsec_validation_scoring::FixVerdict::NotFixed,
        &appsec_stage_s10::Step10Config::new("m"),
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join("app.py")).unwrap(),
        "print('original')\n"
    );
    assert!(appsec_stage_s10::was_reverted(&record));
    assert_eq!(record.diff, None);
}
#[test]
fn a_baseline_rollback_restores_a_file_the_record_never_claimed() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("app.py"), "bad\n").unwrap();
    std::fs::write(dir.path().join("helper.py"), "also bad\n").unwrap();
    let mut baseline = baseline_of("app.py", "good\n");
    baseline.merge_originals([("helper.py".to_string(), Some(b"also good\n".to_vec()))]);
    run_rollback(
        dir.path(),
        &["app.py"],
        Some(&baseline),
        appsec_validation_scoring::FixVerdict::NotFixed,
        &appsec_stage_s10::Step10Config::new("m"),
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join("helper.py")).unwrap(),
        "also good\n"
    );
}
#[test]
fn a_baseline_rollback_will_not_destroy_a_later_findings_kept_fix() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("app.py"), "finding 7's good fix\n").unwrap();
    let baseline = baseline_of("app.py", "before finding 1\n");
    let mut record = validated_record(&["app.py"]);
    let protected = BTreeMap::from([("app.py".to_string(), 7i64)]);
    revert_if_validation_failed(
        dir.path(),
        &mut record,
        Some(&baseline),
        &protected,
        &score_of(appsec_validation_scoring::FixVerdict::NotFixed),
        &appsec_stage_s10::Step10Config::new("m"),
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join("app.py")).unwrap(),
        "finding 7's good fix\n"
    );
    assert_eq!(record.diff.as_deref(), Some("d"));
    assert!(record.verdict.summary.contains("LEFT APPLIED"));
    assert!(record.verdict.summary.contains("app.py (finding 7)"));
}
#[test]
fn a_passing_validation_leaves_the_patch_alone() {
    let dir = patched_git_repo();
    for status in [
        appsec_validation_scoring::FixVerdict::Fixed,
        appsec_validation_scoring::FixVerdict::PartiallyFixed,
    ] {
        let baseline = baseline_of("app.py", "print('original')\n");
        let record = run_rollback(
            dir.path(),
            &["app.py"],
            Some(&baseline),
            status,
            &appsec_stage_s10::Step10Config::new("m"),
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("app.py")).unwrap(),
            "print('a bad fix')\n"
        );
        assert!(!appsec_stage_s10::was_reverted(&record));
    }
}
#[test]
fn keep_unverified_opts_out_of_the_post_validation_rollback() {
    let dir = patched_git_repo();
    let mut step10 = appsec_stage_s10::Step10Config::new("m");
    step10.keep_unverified = true;
    let baseline = baseline_of("app.py", "print('original')\n");
    run_rollback(
        dir.path(),
        &["app.py"],
        Some(&baseline),
        appsec_validation_scoring::FixVerdict::NotFixed,
        &step10,
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join("app.py")).unwrap(),
        "print('a bad fix')\n"
    );
}
#[test]
fn a_record_claiming_nothing_needs_no_rollback() {
    let dir = patched_git_repo();
    let record = run_rollback(
        dir.path(),
        &[],
        None,
        appsec_validation_scoring::FixVerdict::NotFixed,
        &appsec_stage_s10::Step10Config::new("m"),
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join("app.py")).unwrap(),
        "print('a bad fix')\n"
    );
    assert!(!appsec_stage_s10::was_reverted(&record));
}
#[test]
fn a_non_git_target_without_a_baseline_warns_instead_of_rolling_back() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("app.py"), "print('a bad fix')\n").unwrap();
    let record = run_rollback(
        dir.path(),
        &["app.py"],
        None,
        appsec_validation_scoring::FixVerdict::NotFixed,
        &appsec_stage_s10::Step10Config::new("m"),
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join("app.py")).unwrap(),
        "print('a bad fix')\n"
    );
    assert!(!appsec_stage_s10::was_reverted(&record));
    assert_eq!(record.diff.as_deref(), Some("d"));
}
