//! Ctrl-C through `bc-cli`: a canceled scan still writes its partial
//! report and run manifest, takes no outward action, never starts
//! remediation or a target-test process, and exits 130. (The orchestrator's
//! own tests prove a canceled run makes no model call.)

use super::*;
use bc_pipeline_core::{CancelToken, USER_CANCEL_REASON};

fn tripped() -> bc_pipeline_core::CancelTokenRef {
    let token = CancelToken::new_ref();
    token.cancel(USER_CANCEL_REASON);
    token
}

#[tokio::test]
async fn a_canceled_scan_writes_its_partial_report_and_never_starts_remediation() {
    let _lock = ENV_LOCK.lock().await;
    let state = tempfile::tempdir().unwrap();
    let prior = std::env::var("BC_STATE_DIR").ok();
    unsafe { std::env::set_var("BC_STATE_DIR", state.path()) };
    let dir = git_repo();
    let mut c = cli(dir.path());
    c.remediate = true;
    let remediation = build_remediate_run(&c, dir.path()).unwrap();
    let mut config = fast_config();
    config.cancel = Some(tripped());
    let (tx, rx) = std::sync::mpsc::channel();
    config.progress = Some(tx);
    let paths = out_paths(&dir.path().join("out"));
    let result = run(
        fast_input(dir.path()),
        config,
        None,
        &paths,
        empty_scan_client(),
        Arc::new(NoTools),
        None,
        Some(remediation),
        None,
    )
    .await;
    restore_env("BC_STATE_DIR", prior);

    let summary = result.unwrap();
    assert!(summary.remediation.is_none(), "{:?}", summary.remediation);
    let md = std::fs::read_to_string(&paths.markdown).unwrap();
    assert!(md.contains("**CANCELED**"), "{md}");
    assert!(paths.sarif.is_file());
    let events: Vec<bc_pipeline_core::ScanEvent> = rx.try_iter().collect();
    for stage in [bc_orchestrator::S10_STAGE, bc_orchestrator::S11_STAGE] {
        assert!(
            events.iter().any(|e| matches!(
                e,
                bc_pipeline_core::ScanEvent::StageFinished {
                    stage: s,
                    status: bc_pipeline_core::StageStatus::Skipped,
                    ..
                } if *s == stage
            )),
            "{stage} was not closed as skipped: {events:?}"
        );
    }
}

#[tokio::test]
async fn after_a_cancel_no_target_test_runs_and_export_is_withheld() {
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
    let report = sample_report(None, vec![sample_finding()]);
    let read_tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new(dir.path().to_path_buf()));
    let (outcome, patch) = dispatch_remediation(
        empty_scan_client(),
        read_tools,
        dir.path(),
        &report,
        remediation,
        bc_orchestrator::RemediateTelemetry {
            cancel: Some(tripped()),
            ..Default::default()
        },
    )
    .await;
    restore_env("BC_STATE_DIR", prior);

    assert_eq!(outcome.refused.as_deref(), Some(USER_CANCEL_REASON));
    assert!(outcome.outcomes.is_empty());
    assert!(patch.is_none());
    let artifact: Value = serde_json::from_slice(
        &std::fs::read(dir.path().join("security-scan/target-tests.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(artifact["execution"], json!([]));
    assert!(
        artifact["remaining_gaps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|g| g
                .as_str()
                .unwrap()
                .contains("Target tests were not run: canceled by user (Ctrl-C)")),
        "{artifact}"
    );
}

#[tokio::test]
async fn main_impl_with_a_canceled_controller_exits_130_and_marks_the_manifest() {
    let _lock = ENV_LOCK.lock().await;
    let state = tempfile::tempdir().unwrap();
    let prior = std::env::var("BC_STATE_DIR").ok();
    unsafe { std::env::set_var("BC_STATE_DIR", state.path()) };
    let dir = setup_repo();
    let c = cli(dir.path());
    let controller = cancel::Controller::new();
    controller.arm();
    assert_eq!(controller.on_signal(), cancel::SignalAction::Cancel);
    let result = main_impl_with_cancel(c, Some(controller.clone())).await;
    restore_env("BC_STATE_DIR", prior);

    assert_eq!(
        process_exit_code(&result, true, controller.is_canceled()),
        130
    );
    let manifest: bc_orchestrator::manifest::RunManifest = serde_json::from_str(
        &std::fs::read_to_string(dir.path().join("security-scan/run_manifest.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(manifest.exit_code, 130);
    assert!(manifest.canceled);
    let md = std::fs::read_to_string(dir.path().join("security-scan/report.md")).unwrap();
    assert!(md.contains("**CANCELED**"), "{md}");
}
