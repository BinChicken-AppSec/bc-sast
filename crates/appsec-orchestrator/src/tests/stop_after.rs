use super::*;
#[tokio::test]
async fn stop_after_s1_returns_early_with_no_report() {
    let dir = setup_repo();
    let client = client_with(vec![(S1_SYSTEM_MARK, S1_JSON.to_string())]);
    let outcome = run_scan(
        client,
        Arc::new(NoTools),
        scan_input(dir.path()),
        scan_config(),
        Some(StopAfter::S1),
    )
    .await
    .unwrap();
    assert_eq!(outcome.stopped_after, Some(StopAfter::S1));
    assert!(outcome.report.is_none());
}
#[tokio::test]
async fn stop_after_s2_returns_early() {
    let dir = setup_repo();
    let client = client_with(vec![
        (S1_SYSTEM_MARK, S1_JSON.to_string()),
        (S2_SYSTEM_MARK, S2_JSON.to_string()),
    ]);
    let outcome = run_scan(
        client,
        Arc::new(NoTools),
        scan_input(dir.path()),
        scan_config(),
        Some(StopAfter::S2),
    )
    .await
    .unwrap();
    assert_eq!(outcome.stopped_after, Some(StopAfter::S2));
}
#[tokio::test]
async fn stop_after_s3_returns_early() {
    let dir = setup_repo();
    let client = client_with(vec![
        (S1_SYSTEM_MARK, S1_JSON.to_string()),
        (S2_SYSTEM_MARK, S2_JSON.to_string()),
        (S3_SYSTEM_MARK, S3_GARBAGE.to_string()),
    ]);
    let outcome = run_scan(
        client,
        Arc::new(NoTools),
        scan_input(dir.path()),
        scan_config(),
        Some(StopAfter::S3),
    )
    .await
    .unwrap();
    assert_eq!(outcome.stopped_after, Some(StopAfter::S3));
}
#[tokio::test]
async fn stop_after_s4_returns_early() {
    let dir = setup_repo();
    let outcome = run_scan(
        empty_findings_client(),
        Arc::new(NoTools),
        scan_input(dir.path()),
        scan_config(),
        Some(StopAfter::S4),
    )
    .await
    .unwrap();
    assert_eq!(outcome.stopped_after, Some(StopAfter::S4));
}
#[tokio::test]
async fn stop_after_s5_returns_early() {
    let dir = setup_repo();
    let outcome = run_scan(
        empty_findings_client(),
        Arc::new(NoTools),
        scan_input(dir.path()),
        scan_config(),
        Some(StopAfter::S5),
    )
    .await
    .unwrap();
    assert_eq!(outcome.stopped_after, Some(StopAfter::S5));
}
#[tokio::test]
async fn stop_after_s6_returns_early() {
    let dir = setup_repo();
    let outcome = run_scan(
        empty_findings_client(),
        Arc::new(NoTools),
        scan_input(dir.path()),
        scan_config(),
        Some(StopAfter::S6),
    )
    .await
    .unwrap();
    assert_eq!(outcome.stopped_after, Some(StopAfter::S6));
}
#[tokio::test]
async fn stop_after_s7_returns_early() {
    let dir = setup_repo();
    let outcome = run_scan(
        empty_findings_client(),
        Arc::new(NoTools),
        scan_input(dir.path()),
        scan_config(),
        Some(StopAfter::S7),
    )
    .await
    .unwrap();
    assert_eq!(outcome.stopped_after, Some(StopAfter::S7));
}
#[tokio::test]
async fn stop_after_s9_renders_reports_and_emits_its_own_stage_events() {
    let dir = setup_repo();
    let (tx, rx) = std::sync::mpsc::channel();
    let mut config = scan_config();
    config.progress = Some(tx);
    let outcome = run_scan(
        empty_findings_client(),
        Arc::new(NoTools),
        scan_input(dir.path()),
        config,
        Some(StopAfter::S9),
    )
    .await
    .unwrap();
    assert_eq!(outcome.stopped_after, Some(StopAfter::S9));
    assert!(outcome.report.is_some());
    assert!(outcome.markdown.is_some());
    let sarif: serde_json::Value = serde_json::from_str(outcome.sarif.as_ref().unwrap()).unwrap();
    assert_eq!(sarif["version"], "2.1.0");
    let events: Vec<_> = rx.try_iter().collect();
    assert_eq!(
        events[events.len() - 2],
        appsec_pipeline_core::ScanEvent::StageStarted { stage: "s9" }
    );
    assert!(matches!(
        &events[events.len() - 1],
        appsec_pipeline_core::ScanEvent::StageFinished {
            stage: "s9",
            status: StageStatus::Completed,
            duration: Some(_),
            ..
        }
    ));
}
#[tokio::test]
async fn a_full_scan_closes_every_stage_with_a_status_and_its_counters() {
    let dir = setup_repo();
    let (tx, rx) = std::sync::mpsc::channel();
    let mut config = scan_config();
    config.progress = Some(tx);
    let outcome = run_scan(
        one_finding_client(),
        Arc::new(NoTools),
        scan_input(dir.path()),
        config,
        None,
    )
    .await
    .unwrap();
    let events: Vec<_> = rx.try_iter().collect();
    let stages: Vec<&str> = finished_stages(&events).iter().map(|(s, _)| *s).collect();
    assert_eq!(
        stages,
        [
            "s0-seed",
            "s1-preprocess",
            "s2-threatmodel",
            "s3-decompose",
            "s4-deepdive",
            "s5-prefilter",
            "s6-verify",
            "s7-dedup",
            "s8-chain",
            "s9"
        ]
    );
    assert_eq!(
        finished_counts(&events, "s6-verify"),
        vec![("verified", 1), ("dropped", 0)]
    );
    assert_eq!(finished_counts(&events, "s8-chain")[0], ("findings", 1));
    let timings = outcome.report.unwrap().metrics.unwrap().stage_timings;
    assert_eq!(
        timings.keys().map(String::as_str).collect::<Vec<_>>(),
        ["s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8"]
    );
    assert_eq!(timings["s0"].outcome, "skipped");
    assert_eq!(timings["s0"].duration_sec, None);
    assert!(timings
        .iter()
        .filter(|(id, _)| *id != "s0")
        .all(|(_, t)| t.duration_sec.is_some()));
    assert!(events.iter().any(|e| matches!(
        e,
        appsec_pipeline_core::ScanEvent::UsageUpdate {
            stage: "s8-chain",
            ..
        }
    )));
}
#[tokio::test]
async fn switched_off_stages_close_as_skipped_without_starting() {
    let dir = setup_repo();
    let (tx, rx) = std::sync::mpsc::channel();
    let mut config = scan_config();
    config.progress = Some(tx);
    config.step0_enabled = false;
    config.step2_enabled = false;
    run_scan(
        empty_findings_client(),
        Arc::new(NoTools),
        scan_input(dir.path()),
        config,
        Some(StopAfter::S2),
    )
    .await
    .unwrap();
    let events: Vec<_> = rx.try_iter().collect();
    assert_eq!(
        finished_stages(&events),
        [
            ("s0-seed", StageStatus::Skipped),
            ("s1-preprocess", StageStatus::Completed),
            ("s2-threatmodel", StageStatus::Skipped),
        ]
    );
    assert!(
        !events.contains(&appsec_pipeline_core::ScanEvent::StageStarted {
            stage: "s2-threatmodel"
        })
    );
}
#[tokio::test]
async fn stop_after_s8_returns_analysis_without_rendered_reports() {
    let dir = setup_repo();
    let outcome = run_scan(
        empty_findings_client(),
        Arc::new(NoTools),
        scan_input(dir.path()),
        scan_config(),
        Some(StopAfter::S8),
    )
    .await
    .unwrap();
    assert_eq!(outcome.stopped_after, Some(StopAfter::S8));
    assert!(outcome.report.is_some());
    assert!(outcome.markdown.is_none());
    assert!(outcome.sarif.is_none());
}
#[tokio::test]
async fn unreachable_files_never_reach_the_report_when_emit_unreachable_appendix_is_off() {
    let dir = setup_repo();
    let mut config = scan_config();
    config.step3.catchall_mode = "reachable_only".to_string();
    assert!(!config.emit_unreachable_appendix);
    let outcome = run_scan(
        empty_findings_client(),
        Arc::new(NoTools),
        scan_input(dir.path()),
        config,
        None,
    )
    .await
    .unwrap();
    assert!(outcome.report.unwrap().unreachable_files.is_empty());
}
#[tokio::test]
async fn unreachable_files_reach_the_report_when_emit_unreachable_appendix_is_on() {
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
                degraded: false,
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
                degraded: false,
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
                    unreachable_files: vec!["orphan.py".to_string()],
                },
                degraded: false,
            })
            .unwrap(),
        )
        .unwrap();
    store
        .save(
            &run_id,
            "s4",
            &serde_json::to_vec(&Step4Checkpoint {
                findings: Vec::new(),
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
                findings: Vec::new(),
                dropped: Vec::new(),
                degraded: false,
            })
            .unwrap(),
        )
        .unwrap();
    store
        .save(
            &run_id,
            "s6",
            &serde_json::to_vec(&Step6Checkpoint {
                verified: Vec::new(),
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
                findings: Vec::new(),
                dropped: Vec::new(),
                degraded: false,
            })
            .unwrap(),
        )
        .unwrap();

    let mut config = scan_config();
    config.checkpoint = Some(store);
    config.resume = true;
    config.emit_unreachable_appendix = true;

    let outcome = run_scan(
        empty_findings_client(),
        Arc::new(NoTools),
        scan_input(dir.path()),
        config,
        None,
    )
    .await
    .unwrap();
    let report = outcome.report.unwrap();
    assert_eq!(report.unreachable_files, vec!["orphan.py".to_string()]);
}
#[test]
fn budget_skip_reason_recognizes_only_a_budget_stop() {
    assert_eq!(
        budget_skip_reason(
            "S7",
            Some("semantic dedup skipped: token budget of 100 reached (120 spent)")
        ),
        Some("S7: semantic dedup skipped: token budget of 100 reached (120 spent)".to_string())
    );
    assert_eq!(
        budget_skip_reason("S5", Some("semantic dedup call failed (non-fatal): boom")),
        None
    );
    assert_eq!(budget_skip_reason("S5", None), None);
}
