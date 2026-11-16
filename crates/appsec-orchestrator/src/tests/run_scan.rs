use super::*;
#[test]
#[should_panic(expected = "unrecognized system prompt")]
fn route_panics_on_an_unrecognized_system_prompt() {
    route("zzz-totally-unmatched-zzz", &[("xyz-mark-xyz", "reply")]);
}
#[test]
fn no_tools_execute_returns_an_empty_string() {
    assert_eq!(NoTools.execute("Read", &json!({})), "");
}
#[tokio::test]
async fn a_full_run_with_zero_findings_reaches_sarif() {
    let dir = setup_repo();
    let outcome = run_scan(
        empty_findings_client(),
        Arc::new(NoTools),
        scan_input(dir.path()),
        scan_config(),
        None,
    )
    .await
    .unwrap();
    assert_eq!(outcome.stopped_after, None);
    let report = outcome.report.unwrap();
    assert!(report.findings.is_empty());
    assert!(!outcome.markdown.unwrap().is_empty());
    assert!(outcome.sarif.unwrap().contains("\"version\": \"2.1.0\""));
}
#[tokio::test]
async fn imported_negative_assessment_survives_the_real_pipeline_into_s9() {
    let dir = setup_repo();
    let export = dir.path().join("vendor.json");
    std::fs::write(&export, r#"{"results":[{"check_id":"rule","path":"app.py","start":{"line":1},"end":{"line":1},"extra":{"message":"candidate","severity":"ERROR"}}]}"#).unwrap();
    let mut input = scan_input(dir.path());
    input.semgrep_json.push(export);
    let outcome = run_scan(
        client_with(full_table(
            S4_EMPTY,
            "Traced the input guard.\nVERDICT: FALSE_POSITIVE (confidence: 9/10) - bounded input\n",
            "",
        )),
        Arc::new(NoTools),
        input,
        scan_config(),
        None,
    )
    .await
    .unwrap();
    let report = outcome.report.unwrap();
    assert!(report.findings.is_empty());
    assert_eq!(report.provider_ledger.assessments.len(), 1);
    let record = &report.provider_ledger.assessments[0];
    assert_eq!(record.drop_reason, Some(DropReason::FalsePositive));
    assert_eq!(record.verification.as_ref().unwrap().confidence, 9);
    let plan: serde_json::Value =
        serde_json::from_str(&outcome.provider_writeback_plan.unwrap()).unwrap();
    assert_eq!(plan["plan"]["entries"][0]["outcome"], "false_positive");
    assert_eq!(plan["plan"]["apply_enabled"], false);
    assert_eq!(plan["ingestion"][0]["imported_count"], 1);
    assert_eq!(plan["assessments"].as_array().unwrap().len(), 1);
}
#[tokio::test]
async fn a_diff_scoped_run_retains_an_out_of_scope_provider_finding_instead_of_reporting_it() {
    let dir = setup_repo();
    let export = dir.path().join("vendor.json");
    std::fs::write(
        &export,
        r#"{"results":[
            {"check_id":"rule-a","path":"app.py","start":{"line":1},"end":{"line":1},
             "extra":{"message":"in the PR","severity":"ERROR"}},
            {"check_id":"rule-b","path":"vendor/old.py","start":{"line":7},"end":{"line":7},
             "extra":{"message":"pre-existing","severity":"ERROR"}}]}"#,
    )
    .unwrap();
    let mut input = scan_input(dir.path());
    input.semgrep_json.push(export);
    input.diff_scope_active = true;
    input.changed_files = BTreeMap::from([("app.py".to_string(), BTreeSet::from([1i64, 2, 3]))]);

    let outcome = run_scan(
        client_with(full_table(
            S4_EMPTY,
            &s6_true_positive_text(),
            &s8_ranked_json(),
        )),
        Arc::new(NoTools),
        input,
        scan_config(),
        None,
    )
    .await
    .unwrap();
    let report = outcome.report.unwrap();

    assert_eq!(report.findings.len(), 1);
    assert!(report
        .findings
        .iter()
        .all(|f| f.finding.file != "vendor/old.py"));

    let retained: Vec<_> = report
        .dropped
        .iter()
        .filter(|d| d.reason == DropReason::OutOfDiffScope)
        .collect();
    assert_eq!(retained.len(), 1);
    assert_eq!(retained[0].file, "vendor/old.py");
    assert_eq!(retained[0].line, 7);
    assert!(retained[0].detail.contains("--diff-scope"));
    assert!(retained[0].verification.is_none());
    assert!(!retained[0].provider_origins.is_empty());

    assert_eq!(report.findings[0].finding.file, "app.py");
    assert_eq!(
        report.findings[0].finding.verdict,
        Some(appsec_model::Verdict::TruePositive)
    );

    assert_eq!(report.provider_ledger.assessments.len(), 2);
    let set_aside = report
        .provider_ledger
        .assessments
        .iter()
        .find(|a| a.file == "vendor/old.py")
        .unwrap();
    assert_eq!(set_aside.drop_reason, Some(DropReason::OutOfDiffScope));
    assert!(set_aside.verification.is_none());
    assert_eq!(set_aside.limitations.len(), 1);
    assert!(set_aside.limitations[0].contains("--diff-scope"));

    assert!(!report.provider_ledger.full_scan);
    let plan: serde_json::Value =
        serde_json::from_str(&outcome.provider_writeback_plan.unwrap()).unwrap();
    assert_eq!(plan["plan"]["apply_enabled"], false);
    let blocked = plan["plan"]["entries"][0]["blocking_reasons"].to_string();
    assert!(blocked.contains("full_scan_required"), "{blocked}");

    let sarif: serde_json::Value = serde_json::from_str(&outcome.sarif.unwrap()).unwrap();
    let notes = sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"].to_string();
    assert!(notes.contains("outside this pull request"), "{notes}");
    assert!(sarif["runs"][0]["results"]
        .to_string()
        .find("vendor/old.py")
        .is_none());

    let markdown = outcome.markdown.unwrap();
    assert!(markdown.contains("**[OUT OF DIFF SCOPE]**"), "{markdown}");
    assert!(markdown.contains("vendor/old.py"));
    assert!(markdown.contains(
        "- Outside the PR diff (third-party findings retained, not analyzed, not remediated): 1"
    ));
}
#[tokio::test]
async fn without_a_diff_scope_every_provider_finding_is_still_ingested_and_verified() {
    let dir = setup_repo();
    let export = dir.path().join("vendor.json");
    std::fs::write(
        &export,
        r#"{"results":[
            {"check_id":"rule-a","path":"app.py","start":{"line":1},"end":{"line":1},
             "extra":{"message":"in the PR","severity":"ERROR"}},
            {"check_id":"rule-b","path":"vendor/old.py","start":{"line":7},"end":{"line":7},
             "extra":{"message":"pre-existing","severity":"ERROR"}}]}"#,
    )
    .unwrap();
    let mut input = scan_input(dir.path());
    input.semgrep_json.push(export);

    let outcome = run_scan(
        client_with(full_table(
            S4_EMPTY,
            "Traced the input guard.\nVERDICT: FALSE_POSITIVE (confidence: 9/10) - bounded input\n",
            "",
        )),
        Arc::new(NoTools),
        input,
        scan_config(),
        None,
    )
    .await
    .unwrap();
    let report = outcome.report.unwrap();

    assert!(report
        .dropped
        .iter()
        .all(|d| d.reason != DropReason::OutOfDiffScope));
    assert_eq!(
        report
            .dropped
            .iter()
            .filter(|d| d.reason == DropReason::FalsePositive)
            .count(),
        2
    );
    assert!(report.provider_ledger.full_scan);
    assert!(!outcome.markdown.unwrap().contains("Outside the PR diff"));
}
#[tokio::test]
async fn a_full_run_with_step0_enabled_reaches_sarif() {
    let dir = setup_repo();
    let mut config = scan_config();
    config.step0_enabled = true;
    let outcome = run_scan(
        empty_findings_client(),
        Arc::new(NoTools),
        scan_input(dir.path()),
        config,
        None,
    )
    .await
    .unwrap();
    assert_eq!(outcome.stopped_after, None);
    assert!(outcome.report.is_some());
}
#[tokio::test]
async fn git_sha_override_is_used_verbatim_instead_of_shelling_out_to_git() {
    let dir = setup_repo();
    let mut input = scan_input(dir.path());
    input.git_sha_override = Some("override-sha".to_string());
    let outcome = run_scan(
        empty_findings_client(),
        Arc::new(NoTools),
        input,
        scan_config(),
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        outcome.report.unwrap().git_sha,
        Some("override-sha".to_string())
    );
}
#[tokio::test]
async fn a_non_git_target_reports_an_identity_with_no_key_rather_than_inventing_one() {
    let dir = setup_repo();
    let outcome = run_scan(
        empty_findings_client(),
        Arc::new(NoTools),
        scan_input(dir.path()),
        scan_config(),
        None,
    )
    .await
    .unwrap();
    let identity = outcome.report.unwrap().repo_identity.unwrap();
    assert!(identity.key.is_none(), "{identity:?}");
    assert!(identity.root_commit.is_none(), "{identity:?}");
    assert!(!identity.worktree_dirty, "{identity:?}");
}
#[tokio::test]
async fn an_explicit_repo_key_and_branch_reach_the_report() {
    let dir = setup_repo();
    let mut input = scan_input(dir.path());
    input.repo_key_override = Some("chosen/key".to_string());
    input.branch_override = Some("feature/x".to_string());
    let outcome = run_scan(
        empty_findings_client(),
        Arc::new(NoTools),
        input,
        scan_config(),
        None,
    )
    .await
    .unwrap();
    let markdown = outcome.markdown.clone().unwrap();
    assert!(markdown.contains("## Repository"), "{markdown}");
    assert!(
        markdown.contains("- Repository key: `chosen/key` (from explicit)"),
        "{markdown}"
    );
    assert!(markdown.contains("- Branch: `feature/x`"), "{markdown}");

    let identity = outcome.report.unwrap().repo_identity.unwrap();
    let key = identity.key.unwrap();
    assert_eq!(key.value, "chosen/key");
    assert_eq!(key.source, appsec_model::RepoKeySource::Explicit);
    assert_eq!(identity.branch.as_deref(), Some("feature/x"));
}
#[tokio::test]
async fn two_scans_of_one_repo_never_share_a_uuid() {
    let dir = setup_repo();
    let mut uuids = Vec::new();
    for _ in 0..2 {
        let outcome = run_scan(
            empty_findings_client(),
            Arc::new(NoTools),
            scan_input(dir.path()),
            scan_config(),
            None,
        )
        .await
        .unwrap();
        let m = outcome.report.unwrap().metrics.unwrap();
        assert!(!m.scan_uuid.is_empty());
        uuids.push(m.scan_uuid);
    }
    assert_ne!(uuids[0], uuids[1]);
}
#[tokio::test]
async fn without_an_override_git_sha_falls_back_to_the_shell_out_and_is_none_for_a_non_git_dir() {
    let dir = setup_repo();
    let outcome = run_scan(
        empty_findings_client(),
        Arc::new(NoTools),
        scan_input(dir.path()),
        scan_config(),
        None,
    )
    .await
    .unwrap();
    assert_eq!(outcome.report.unwrap().git_sha, None);
}
#[tokio::test]
async fn a_real_finding_survives_s4_through_s8_and_appears_in_the_report_and_sarif() {
    let dir = setup_repo();
    let outcome = run_scan(
        one_finding_client(),
        Arc::new(NoTools),
        scan_input(dir.path()),
        scan_config(),
        None,
    )
    .await
    .unwrap();
    let report = outcome.report.unwrap();
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].finding.file, "app.py");
    let md = outcome.markdown.unwrap();
    assert!(md.contains("SQL injection"));
    let sarif = outcome.sarif.unwrap();
    assert!(sarif.contains("app.py"));
}
#[tokio::test]
async fn a_secret_in_a_finding_is_redacted_from_the_report_sarif_and_markdown_alike() {
    let dir = setup_repo();
    let s4 = json!({"findings": [{
        "file": "app.py", "line_start": 10, "line_end": 12,
        "vuln_class": "injection", "title": "SQL injection",
        "description": "user input reaches a raw query",
        "code_snippet": "cur.execute(q)  # 4111111111111111", "confidence": 0.9,
        "source_ref": "app.py:10", "sink_ref": "app.py:12",
    }]})
    .to_string();
    let client = client_with(full_table(&s4, &s6_true_positive_text(), &s8_ranked_json()));
    let outcome = run_scan(
        client,
        Arc::new(NoTools),
        scan_input(dir.path()),
        scan_config(),
        None,
    )
    .await
    .unwrap();

    let report = outcome.report.unwrap();
    assert_eq!(report.findings.len(), 1);
    assert!(!report.findings[0]
        .finding
        .code_snippet
        .contains("4111111111111111"));

    assert!(!outcome.markdown.unwrap().contains("4111111111111111"));
    assert!(!outcome.sarif.unwrap().contains("4111111111111111"));
}
#[tokio::test]
async fn run_scan_records_real_stage_degrades_in_errors_by_stage() {
    let dir = setup_repo();
    std::fs::write(dir.path().join("other.py"), "cur2.execute(q2)\n").unwrap();

    let s6 = s6_true_positive_text();
    let s8 = s8_two_ranked_json();
    let table: Vec<(&'static str, String)> = vec![
        (S1_SYSTEM_MARK, S3_GARBAGE.to_string()),
        (S2_SYSTEM_MARK, S2_JSON.to_string()),
        (S3_SYSTEM_MARK, S3_GARBAGE.to_string()),
        (S4_SYSTEM_MARK, s4_two_findings_json()),
        (S6_SYSTEM_MARK, s6),
        (S8_SYSTEM_MARK, s8),
    ];
    let client = Arc::new(RoutedClient::new(move |system: &str| {
        if system.contains(SEMANTIC_DEDUP_MARK) {
            return Err(LlmError::ConnectionError {
                message: "provider down".to_string(),
            });
        }
        let owned: Vec<(&str, &str)> = table.iter().map(|(m, r)| (*m, r.as_str())).collect();
        Ok(route(system, &owned))
    }));

    let mut config = scan_config();
    config.step5.pre_verify_threshold = 2;
    config.step5.dedup.semantic = true;
    config.step7.semantic = true;

    let outcome = run_scan(
        client,
        Arc::new(NoTools),
        scan_input(dir.path()),
        config,
        None,
    )
    .await
    .unwrap();
    let report = outcome.report.unwrap();
    assert_eq!(report.findings.len(), 2);
    let metrics = report.metrics.unwrap();
    assert_eq!(metrics.errors_by_stage.get("s1"), Some(&1));
    assert_eq!(metrics.errors_by_stage.get("s5"), Some(&1));
    assert_eq!(metrics.errors_by_stage.get("s7"), Some(&1));
    assert_eq!(metrics.errors_by_stage.get("s3"), Some(&1));
    assert!(!metrics.errors_by_stage.contains_key("s2"));
    assert!(!metrics.errors_by_stage.contains_key("s4"));
}
#[tokio::test]
async fn a_false_positive_verdict_is_dropped_and_counted_in_metrics() {
    let dir = setup_repo();
    let s6_false_positive = format!(
        "traced it\nVERDICT: FALSE_POSITIVE (confidence: 9/10) — input is sanitized\nCVSS: {GOOD_CVSS}\n"
    );
    let s8_no_findings = json!({
        "summary": "No confirmed findings.",
        "ranked_findings": [],
        "chains": [],
    })
    .to_string();
    let client = client_with(full_table(
        &s4_one_finding_json(),
        &s6_false_positive,
        &s8_no_findings,
    ));
    let outcome = run_scan(
        client,
        Arc::new(NoTools),
        scan_input(dir.path()),
        scan_config(),
        None,
    )
    .await
    .unwrap();
    let report = outcome.report.unwrap();
    assert!(report.findings.is_empty());
    let metrics = report.metrics.unwrap();
    assert_eq!(metrics.raw_findings_count, 1);
    assert_eq!(metrics.true_positive_count, 0);
    assert_eq!(metrics.false_positive_count, 1);
    assert_eq!(metrics.duplicate_count, 0);
}
#[tokio::test]
async fn stage2_llm_failure_is_caught_and_the_scan_continues_without_a_threat_model() {
    let dir = setup_repo();
    let client: Arc<dyn LlmClient> = Arc::new(RoutedClient::new(move |system: &str| {
        if system.contains(S2_SYSTEM_MARK) {
            Err(LlmError::ConnectionError {
                message: "s2 down".to_string(),
            })
        } else {
            Ok(route(
                system,
                &[
                    (S1_SYSTEM_MARK, S1_JSON),
                    (S3_SYSTEM_MARK, S3_GARBAGE),
                    (S4_SYSTEM_MARK, S4_EMPTY),
                ],
            ))
        }
    }));
    let outcome = run_scan(
        client,
        Arc::new(NoTools),
        scan_input(dir.path()),
        scan_config(),
        None,
    )
    .await
    .unwrap();
    let report = outcome.report.unwrap();
    assert!(report.threat_model.is_none());
}
#[tokio::test]
async fn step2_disabled_by_config_skips_the_llm_call_entirely() {
    let dir = setup_repo();
    let client = client_with(vec![
        (S1_SYSTEM_MARK, S1_JSON.to_string()),
        (S3_SYSTEM_MARK, S3_GARBAGE.to_string()),
        (S4_SYSTEM_MARK, S4_EMPTY.to_string()),
    ]);
    let mut cfg = scan_config();
    cfg.step2_enabled = false;
    let outcome = run_scan(client, Arc::new(NoTools), scan_input(dir.path()), cfg, None)
        .await
        .unwrap();
    assert!(outcome.report.unwrap().threat_model.is_none());
}
#[tokio::test]
async fn run_scan_registers_the_run_with_a_checkpoint_store() {
    let dir = setup_repo();
    let ckpt_dir = tempfile::tempdir().unwrap();
    let db_path = ckpt_dir.path().join("state.db");
    let store: Arc<dyn appsec_checkpoint::CheckpointStore> =
        Arc::new(appsec_checkpoint::SqliteCheckpointStore::new(&db_path).unwrap());
    let mut config = scan_config();
    config.checkpoint = Some(store);
    run_scan(
        empty_findings_client(),
        Arc::new(NoTools),
        scan_input(dir.path()),
        config,
        None,
    )
    .await
    .unwrap();

    let inspector = appsec_checkpoint::SqliteCheckpointStore::new(&db_path).unwrap();
    let report = inspector.prune(100, 5, true).unwrap();
    assert_eq!(report.kept, 1);
    assert!(report.deleted.is_empty());
}
#[tokio::test]
async fn run_scan_saves_a_checkpoint_for_every_stage_that_actually_ran() {
    let dir = setup_repo();
    let ckpt_dir = tempfile::tempdir().unwrap();
    let store: Arc<dyn appsec_checkpoint::CheckpointStore> = Arc::new(
        appsec_checkpoint::SqliteCheckpointStore::new(ckpt_dir.path().join("state.db")).unwrap(),
    );
    let mut config = scan_config();
    config.checkpoint = Some(store.clone());
    run_scan(
        one_finding_client(),
        Arc::new(NoTools),
        scan_input(dir.path()),
        config,
        None,
    )
    .await
    .unwrap();

    let run_id = appsec_checkpoint::run_id_for(dir.path());
    for step in ["s1", "s2", "s3", "s4", "s5", "s6", "s7"] {
        assert!(
            store.load(&run_id, step).is_some(),
            "missing checkpoint for {step}"
        );
    }
    assert!(store.load(&run_id, "s8").is_none());
}
#[tokio::test]
async fn run_scan_without_resume_clears_every_stale_checkpoint_before_running() {
    let dir = setup_repo();
    let ckpt_dir = tempfile::tempdir().unwrap();
    let store: Arc<dyn appsec_checkpoint::CheckpointStore> = Arc::new(
        appsec_checkpoint::SqliteCheckpointStore::new(ckpt_dir.path().join("state.db")).unwrap(),
    );
    let run_id = appsec_checkpoint::run_id_for(dir.path());
    store
        .save(&run_id, "stale_leftover", b"from a discarded prior run")
        .unwrap();

    let mut config = scan_config();
    config.checkpoint = Some(store.clone());
    let outcome = run_scan(
        empty_findings_client(),
        Arc::new(NoTools),
        scan_input(dir.path()),
        config,
        None,
    )
    .await
    .unwrap();

    assert!(outcome.report.is_some());
    assert_eq!(store.load(&run_id, "stale_leftover"), None);
}
#[tokio::test]
async fn run_scan_with_resume_uses_a_cached_ctx_and_skips_s1_s_llm_call() {
    let dir = setup_repo();
    let ckpt_dir = tempfile::tempdir().unwrap();
    let store: Arc<dyn appsec_checkpoint::CheckpointStore> = Arc::new(
        appsec_checkpoint::SqliteCheckpointStore::new(ckpt_dir.path().join("state.db")).unwrap(),
    );
    let run_id = appsec_checkpoint::run_id_for(dir.path());
    let cached_ctx = ContextPackage {
        language: "python".to_string(),
        all_files: vec!["a.py".to_string(), "b.py".to_string(), "c.py".to_string()],
        ..ContextPackage::default()
    };
    store
        .save(
            &run_id,
            "s1",
            &serde_json::to_vec(&Step1Checkpoint {
                ctx: cached_ctx,
                degraded: false,
            })
            .unwrap(),
        )
        .unwrap();

    let client = client_with(vec![
        (S2_SYSTEM_MARK, S2_JSON.to_string()),
        (S3_SYSTEM_MARK, S3_GARBAGE.to_string()),
        (S4_SYSTEM_MARK, S4_EMPTY.to_string()),
    ]);
    let mut config = scan_config();
    config.checkpoint = Some(store);
    config.resume = true;

    let outcome = run_scan(
        client,
        Arc::new(NoTools),
        scan_input(dir.path()),
        config,
        None,
    )
    .await
    .unwrap();

    let metrics = outcome.report.unwrap().metrics.unwrap();
    assert_eq!(metrics.total_files_in_scope, 3);
}
#[tokio::test]
async fn run_scan_with_resume_falls_back_to_a_live_run_when_the_cached_checkpoint_is_corrupt() {
    let dir = setup_repo();
    let ckpt_dir = tempfile::tempdir().unwrap();
    let store: Arc<dyn appsec_checkpoint::CheckpointStore> = Arc::new(
        appsec_checkpoint::SqliteCheckpointStore::new(ckpt_dir.path().join("state.db")).unwrap(),
    );
    let run_id = appsec_checkpoint::run_id_for(dir.path());
    store.save(&run_id, "s1", b"not valid json").unwrap();

    let mut config = scan_config();
    config.checkpoint = Some(store);
    config.resume = true;
    let outcome = run_scan(
        one_finding_client(),
        Arc::new(NoTools),
        scan_input(dir.path()),
        config,
        None,
    )
    .await
    .unwrap();
    assert_eq!(outcome.report.unwrap().findings.len(), 1);
}
#[tokio::test]
async fn run_scan_resume_without_a_checkpoint_store_behaves_like_a_normal_scan() {
    let dir = setup_repo();
    let mut config = scan_config();
    config.resume = true;
    let outcome = run_scan(
        one_finding_client(),
        Arc::new(NoTools),
        scan_input(dir.path()),
        config,
        None,
    )
    .await
    .unwrap();
    assert_eq!(outcome.report.unwrap().findings.len(), 1);
}
#[tokio::test]
async fn run_scan_with_resume_serves_every_stage_from_a_fully_populated_cache() {
    let dir = setup_repo();
    let ckpt_dir = tempfile::tempdir().unwrap();
    let store: Arc<dyn appsec_checkpoint::CheckpointStore> = Arc::new(
        appsec_checkpoint::SqliteCheckpointStore::new(ckpt_dir.path().join("state.db")).unwrap(),
    );

    let mut first_config = scan_config();
    first_config.checkpoint = Some(store.clone());
    let first = run_scan(
        one_finding_client(),
        Arc::new(NoTools),
        scan_input(dir.path()),
        first_config,
        None,
    )
    .await
    .unwrap();
    let first_report = first.report.unwrap();

    let second_client = client_with(vec![(S8_SYSTEM_MARK, s8_ranked_json())]);
    let mut second_config = scan_config();
    second_config.checkpoint = Some(store);
    second_config.resume = true;
    let second = run_scan(
        second_client,
        Arc::new(NoTools),
        scan_input(dir.path()),
        second_config,
        None,
    )
    .await
    .unwrap();
    let second_report = second.report.unwrap();

    assert_eq!(second_report.findings.len(), first_report.findings.len());
    assert_eq!(
        second_report.metrics.unwrap().true_positive_count,
        first_report.metrics.unwrap().true_positive_count
    );
}
#[tokio::test]
async fn run_scan_with_resume_records_errors_by_stage_from_a_degraded_cached_checkpoint() {
    let dir = setup_repo();
    let ckpt_dir = tempfile::tempdir().unwrap();
    let store: Arc<dyn appsec_checkpoint::CheckpointStore> = Arc::new(
        appsec_checkpoint::SqliteCheckpointStore::new(ckpt_dir.path().join("state.db")).unwrap(),
    );
    let run_id = appsec_checkpoint::run_id_for(dir.path());

    let ctx = ContextPackage {
        all_files: vec!["app.py".to_string()],
        ..ContextPackage::default()
    };
    store
        .save(
            &run_id,
            "s1",
            &serde_json::to_vec(&Step1Checkpoint {
                ctx,
                degraded: true,
            })
            .unwrap(),
        )
        .unwrap();
    store
        .save(
            &run_id,
            "s2",
            &serde_json::to_vec(&Step2Checkpoint {
                threat_model: None,
                degraded: true,
            })
            .unwrap(),
        )
        .unwrap();
    store
        .save(
            &run_id,
            "s3",
            &serde_json::to_vec(&Step3Checkpoint {
                manifest: TaskManifest {
                    chunks: Vec::new(),
                    rationale: String::new(),
                    unreachable_files: Vec::new(),
                },
                degraded: false,
            })
            .unwrap(),
        )
        .unwrap();
    let finding = s10_finding(Some(7.0));
    store
        .save(
            &run_id,
            "s4",
            &serde_json::to_vec(&Step4Checkpoint {
                findings: vec![finding.clone()],
                outcomes: BTreeMap::new(),
            })
            .unwrap(),
        )
        .unwrap();
    store
        .save(
            &run_id,
            "s5",
            &serde_json::to_vec(&Step5Checkpoint {
                findings: vec![finding.clone()],
                dropped: Vec::new(),
                degraded: true,
            })
            .unwrap(),
        )
        .unwrap();
    store
        .save(
            &run_id,
            "s6",
            &serde_json::to_vec(&Step6Checkpoint {
                verified: vec![finding.clone()],
                dropped: Vec::new(),
            })
            .unwrap(),
        )
        .unwrap();
    store
        .save(
            &run_id,
            "s7",
            &serde_json::to_vec(&Step7Checkpoint {
                findings: vec![finding],
                dropped: Vec::new(),
                degraded: true,
            })
            .unwrap(),
        )
        .unwrap();

    let client = client_with(vec![(S8_SYSTEM_MARK, s8_ranked_json())]);
    let mut config = scan_config();
    config.checkpoint = Some(store);
    config.resume = true;

    let outcome = run_scan(
        client,
        Arc::new(NoTools),
        scan_input(dir.path()),
        config,
        None,
    )
    .await
    .unwrap();

    let metrics = outcome.report.unwrap().metrics.unwrap();
    assert_eq!(metrics.errors_by_stage.get("s1"), Some(&1));
    assert_eq!(metrics.errors_by_stage.get("s2"), Some(&1));
    assert_eq!(metrics.errors_by_stage.get("s5"), Some(&1));
    assert_eq!(metrics.errors_by_stage.get("s7"), Some(&1));
}
#[tokio::test]
async fn a_stage1_llm_failure_propagates_as_err() {
    let dir = setup_repo();
    let client: Arc<dyn LlmClient> = Arc::new(RoutedClient::new(|_| {
        Err(LlmError::ConnectionError {
            message: "down".to_string(),
        })
    }));
    let result = run_scan(
        client,
        Arc::new(NoTools),
        scan_input(dir.path()),
        scan_config(),
        None,
    )
    .await;
    assert!(result.is_err());
}
#[test]
fn head_sha_is_none_for_a_non_git_directory() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(head_sha(dir.path()), None);
}
#[test]
fn head_sha_returns_the_commit_hash_for_a_real_repo() {
    let dir = tempfile::tempdir().unwrap();
    let run = |args: &[&str]| {
        std::process::Command::new("git")
            .arg("-C")
            .arg(dir.path())
            .args(args)
            .output()
            .unwrap()
    };
    run(&["init", "-q"]);
    run(&[
        "-c",
        "user.email=test@test.com",
        "-c",
        "user.name=test",
        "commit",
        "--allow-empty",
        "-q",
        "-m",
        "x",
    ]);
    let sha = head_sha(dir.path());
    assert_eq!(sha.as_ref().map(String::len), Some(40));
}
#[tokio::test]
async fn run_scan_merges_a_third_party_finding_into_the_final_report() {
    let dir = setup_repo();
    let checkmarx_path = dir.path().join("checkmarx.xml");
    std::fs::write(
        &checkmarx_path,
        r#"<CxXMLResults><Query cweId="89" name="SQLi from Checkmarx"><Result FileName="app.py" Line="2"/></Query></CxXMLResults>"#,
    )
    .unwrap();
    let mut input = scan_input(dir.path());
    input.checkmarx_xml = vec![checkmarx_path];

    let outcome = run_scan(
        third_party_only_client(),
        Arc::new(NoTools),
        input,
        scan_config(),
        None,
    )
    .await
    .unwrap();

    let report = outcome.report.unwrap();
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].finding.title, "SQLi from Checkmarx");
    assert!(report.findings[0]
        .finding
        .chunk_id
        .starts_with("external:checkmarx:"));
}
#[test]
fn outcome_str_maps_every_variant() {
    assert_eq!(
        outcome_str(appsec_stage_s4::ChunkOutcome::Completed),
        "completed"
    );
    assert_eq!(outcome_str(appsec_stage_s4::ChunkOutcome::Error), "error");
    assert_eq!(
        outcome_str(appsec_stage_s4::ChunkOutcome::Guardrail),
        "guardrail"
    );
}
#[test]
fn the_label_collides_on_one_second_where_the_uuid_does_not() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = ContextPackage::default();
    let manifest = TaskManifest {
        chunks: Vec::new(),
        rationale: String::new(),
        unreachable_files: Vec::new(),
    };
    let of = |uuid: &str| {
        build_metrics(
            &ctx,
            &manifest,
            dir.path(),
            "demo",
            uuid,
            "2024-01-01T00:00:00Z",
            "2024-01-01T00:00:00Z",
            0,
            0,
            0,
            0,
            &BTreeMap::new(),
            &BTreeMap::new(),
            Vec::new(),
            BTreeMap::new(),
            None,
        )
    };
    let a = of("01932f1a-7c3d-7000-8000-000000000001");
    let b = of("01932f1a-7c3d-7000-8000-000000000002");
    assert_eq!(a.scan_id, b.scan_id);
    assert_ne!(a.scan_uuid, b.scan_uuid);
}
