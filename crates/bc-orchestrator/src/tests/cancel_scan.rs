//! Cooperative Ctrl-C through the real pipeline: where a cancellation
//! lands decides what still runs, and every case still hands back a
//! report that says it was canceled. Also the pipeline diagnostics'
//! journey from each stage into `ScanMetrics`.

use super::*;
use bc_pipeline_core::{CancelToken, CancelTokenRef, ScanEvent, USER_CANCEL_REASON};

/// A routed client that trips `token` the first time it is asked a
/// question whose system prompt contains `trip_mark`, then answers it.
/// Any stage whose mark is missing from `table` panics if called, which
/// is how these tests assert that a stage made no model call at all.
fn tripping_client(
    table: Vec<(&'static str, String)>,
    trip_mark: &'static str,
    token: CancelTokenRef,
) -> Arc<dyn LlmClient> {
    Arc::new(RoutedClient::new(move |system: &str| {
        if system.contains(trip_mark) {
            token.cancel(USER_CANCEL_REASON);
        }
        let owned: Vec<(&str, &str)> = table.iter().map(|(m, r)| (*m, r.as_str())).collect();
        Ok(route(system, &owned))
    }))
}

fn store_in(dir: &Path) -> Arc<dyn bc_checkpoint::CheckpointStore> {
    Arc::new(bc_checkpoint::SqliteCheckpointStore::new(dir.join("state.db")).unwrap())
}

fn detail_of(events: &[ScanEvent], wanted: &str) -> Option<String> {
    events.iter().find_map(|e| match e {
        ScanEvent::StageFinished { stage, detail, .. } if *stage == wanted => detail.clone(),
        _ => None,
    })
}

#[tokio::test]
async fn a_run_canceled_before_it_starts_skips_every_stage_and_calls_no_model() {
    let dir = setup_repo();
    let token = CancelToken::new_ref();
    token.cancel(USER_CANCEL_REASON);
    let (tx, rx) = std::sync::mpsc::channel();
    let mut config = scan_config();
    config.step0_enabled = true;
    config.cancel = Some(token);
    config.progress = Some(tx);
    // An empty table: any model call at all panics.
    let outcome = run_scan(
        client_with(Vec::new()),
        Arc::new(NoTools),
        scan_input(dir.path()),
        config,
        None,
    )
    .await
    .unwrap();

    let events: Vec<ScanEvent> = rx.try_iter().collect();
    let stages = finished_stages(&events);
    for stage in [
        Stage0::NAME,
        Stage1::NAME,
        Stage2::NAME,
        Stage3::NAME,
        Stage5::NAME,
        Stage6::NAME,
        Stage7::NAME,
    ] {
        assert!(
            stages.contains(&(stage, StageStatus::Skipped)),
            "{stage}: {stages:?}"
        );
        assert_eq!(
            detail_of(&events, stage).as_deref(),
            Some(USER_CANCEL_REASON)
        );
    }
    let report = outcome.report.unwrap();
    assert_eq!(report.repo_root, dir.path().to_string_lossy());
    let metrics = report.metrics.clone().unwrap();
    assert!(metrics.canceled);
    assert_eq!(
        metrics.budget_stop,
        "canceled by user (Ctrl-C); stopped before S5"
    );
    assert_eq!(metrics.chunks_total, 0);
    assert!(outcome.markdown.unwrap().contains("**CANCELED**"));
    assert!(outcome.sarif.is_some());
}

#[tokio::test]
async fn a_cancel_before_s4_attempts_no_chunk_and_writes_a_canceled_report() {
    let dir = setup_repo();
    let ckpt = tempfile::tempdir().unwrap();
    let store = store_in(ckpt.path());
    let token = CancelToken::new_ref();
    let mut config = scan_config();
    config.cancel = Some(token.clone());
    config.checkpoint = Some(store.clone());
    // Trips during S3; S4/S6/S8 are absent from the table, so any chunk
    // or verification or chain call would panic.
    let table = vec![
        (S1_SYSTEM_MARK, S1_JSON.to_string()),
        (S2_SYSTEM_MARK, S2_JSON.to_string()),
        (S3_SYSTEM_MARK, S3_GARBAGE.to_string()),
    ];
    let outcome = run_scan(
        tripping_client(table, S3_SYSTEM_MARK, token),
        Arc::new(NoTools),
        scan_input(dir.path()),
        config,
        None,
    )
    .await
    .unwrap();

    let metrics = outcome.report.unwrap().metrics.unwrap();
    assert!(metrics.canceled);
    assert!(metrics.chunks_total > 0);
    assert_eq!(metrics.chunks_attempted, 0);
    assert_eq!(metrics.chunks_failed, 0);
    assert!(
        metrics
            .budget_stop
            .starts_with("S4: canceled by user (Ctrl-C)"),
        "{}",
        metrics.budget_stop
    );
    assert!(outcome.markdown.unwrap().contains("PARTIAL report"));
    // Complete stages are still checkpointed; the cut-short S4 is not, so
    // a later `--resume` runs it in full.
    let run_id = bc_checkpoint::run_id_for(dir.path());
    for step in ["s1", "s3"] {
        assert!(store.load(&run_id, step).is_some(), "{step}");
    }
    assert!(store.load(&run_id, "s4").is_none());
}

#[tokio::test]
async fn a_cancel_during_s6_leaves_the_rest_unverified_and_makes_no_chain_call() {
    let dir = setup_repo();
    std::fs::write(dir.path().join("other.py"), "cur2.execute(q2)\n").unwrap();
    let ckpt = tempfile::tempdir().unwrap();
    let store = store_in(ckpt.path());
    let token = CancelToken::new_ref();
    let (tx, rx) = std::sync::mpsc::channel();
    let mut config = scan_config();
    config.step6.parallel = 1;
    config.cancel = Some(token.clone());
    config.checkpoint = Some(store.clone());
    config.progress = Some(tx);
    // No S8 mark: the chain call must be refused before it reaches the
    // provider.
    let table = vec![
        (S1_SYSTEM_MARK, S1_JSON.to_string()),
        (S2_SYSTEM_MARK, S2_JSON.to_string()),
        (S3_SYSTEM_MARK, S3_GARBAGE.to_string()),
        (S4_SYSTEM_MARK, s4_two_findings_json()),
        (S6_SYSTEM_MARK, s6_true_positive_text()),
    ];
    let outcome = run_scan(
        tripping_client(table, S6_SYSTEM_MARK, token),
        Arc::new(NoTools),
        scan_input(dir.path()),
        config,
        None,
    )
    .await
    .unwrap();

    let report = outcome.report.unwrap();
    let metrics = report.metrics.clone().unwrap();
    assert!(metrics.canceled);
    assert_eq!(metrics.true_positive_count, 1);
    assert!(
        metrics
            .budget_stop
            .starts_with("S6: canceled by user (Ctrl-C)")
            && metrics
                .budget_stop
                .ends_with("1 of 2 finding(s) verified, 1 left unverified"),
        "{}",
        metrics.budget_stop
    );
    let unverified: Vec<&DroppedFinding> = report
        .dropped
        .iter()
        .filter(|d| d.reason == DropReason::Unconfirmed)
        .collect();
    assert_eq!(unverified.len(), 1);
    assert_eq!(
        unverified[0].detail,
        "not verified — canceled by user (Ctrl-C)"
    );
    assert!(
        report
            .summary
            .contains("canceled by user (Ctrl-C): no new model calls are started"),
        "{}",
        report.summary
    );
    let events: Vec<ScanEvent> = rx.try_iter().collect();
    assert!(finished_stages(&events).contains(&(Stage7::NAME, StageStatus::Skipped)));
    let run_id = bc_checkpoint::run_id_for(dir.path());
    assert!(store.load(&run_id, "s5").is_some());
    assert!(store.load(&run_id, "s6").is_none());
    assert!(store.load(&run_id, "s7").is_none());
}

#[test]
fn a_spend_gate_reports_the_cancellation_ahead_of_its_own_budget_and_trips() {
    let tracker = Arc::new(UsageTrackingClient::new(
        client_with(Vec::new()),
        &pricing::PricingConfig::default(),
    ));
    let token = CancelToken::new_ref();
    let cap = SpendCap {
        max_total_tokens: Some(0),
        max_wall_clock: None,
    };
    let gate = budget_gate(
        Some(&cap),
        &tracker,
        &BTreeMap::new(),
        std::time::Instant::now(),
        Some(&token),
    )
    .unwrap();
    gate.trip("provider quota exhausted".to_string());
    assert_eq!(gate.stop_reason(), "provider quota exhausted");
    token.cancel(USER_CANCEL_REASON);
    assert!(gate.should_stop());
    assert_eq!(gate.stop_reason(), USER_CANCEL_REASON);
    assert!(format!("{gate:?}").contains("cancel"));
}

#[test]
fn a_boundary_stop_names_the_cancellation_before_the_spend_cap() {
    let token = CancelToken::new_ref();
    let cap = SpendCap {
        max_total_tokens: Some(0),
        max_wall_clock: None,
    };
    let start = std::time::Instant::now();
    let reason = boundary_stop(Some(&token), Some(&cap), &BTreeMap::new(), start).unwrap();
    assert!(reason.starts_with("token budget of 0"), "{reason}");
    token.cancel(USER_CANCEL_REASON);
    assert_eq!(
        boundary_stop(Some(&token), Some(&cap), &BTreeMap::new(), start).as_deref(),
        Some(USER_CANCEL_REASON)
    );
    assert_eq!(boundary_stop(None, None, &BTreeMap::new(), start), None);
}

fn cancellable(
    progress: std::sync::mpsc::Sender<ScanEvent>,
    token: &CancelTokenRef,
) -> RemediateTelemetry {
    RemediateTelemetry {
        progress: Some(progress),
        pricing: pricing::PricingConfig::default(),
        cancel: Some(token.clone()),
    }
}

#[tokio::test]
async fn remediation_never_starts_after_a_cancel() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("app.py"), "print(1)\n").unwrap();
    let report = s10_report(dir.path(), vec![s10_ranked(Some(7.0))], None);
    let tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));
    let token = CancelToken::new_ref();
    token.cancel(USER_CANCEL_REASON);
    let (tx, rx) = std::sync::mpsc::channel();
    // `client_with(Vec::new())` panics on any model call.
    let outcome = remediate_observed(
        client_with(Vec::new()),
        tools,
        dir.path(),
        &report,
        &s10_config(),
        None,
        None,
        None,
        &cancellable(tx, &token),
    )
    .await;
    assert_eq!(outcome.refused.as_deref(), Some(USER_CANCEL_REASON));
    assert!(outcome.outcomes.is_empty());
    let events: Vec<ScanEvent> = rx.try_iter().collect();
    assert_eq!(
        finished_stages(&events),
        [
            (S10_STAGE, StageStatus::Skipped),
            (S11_STAGE, StageStatus::Skipped)
        ]
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join("app.py")).unwrap(),
        "print(1)\n"
    );
}

/// Trips the token on the first S10 call and then answers as
/// [`S10AndS11Client`] would: the agent's write lands, and its next turn
/// is the one the cancellation refuses.
struct TripOnFirstCall {
    inner: S10AndS11Client,
    token: CancelTokenRef,
}

#[async_trait]
impl LlmClient for TripOnFirstCall {
    async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, LlmError> {
        self.token.cancel(USER_CANCEL_REASON);
        self.inner.chat(request).await
    }
}

#[tokio::test]
async fn a_cancel_during_s10_stops_the_agent_rolls_its_edit_back_and_skips_s11() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("app.py"), "print(1)\n").unwrap();
    let report = s10_report(dir.path(), vec![s10_ranked(Some(7.0))], None);
    // Journaled, as the CLI wires it: the ledger is how S10 knows what an
    // interrupted agent wrote on a target with no VCS.
    let write_tools = SandboxTools::new_with_write(dir.path());
    let mut config = s10_config();
    config.step10.journal = Some(write_tools.journal());
    let tools: Arc<dyn ToolExecutor> = Arc::new(write_tools);
    let read_only: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new(dir.path()));
    let step11 = s11_config();
    let token = CancelToken::new_ref();
    let (tx, rx) = std::sync::mpsc::channel();
    let outcome = remediate_observed(
        Arc::new(TripOnFirstCall {
            inner: S10AndS11Client::new(),
            token: token.clone(),
        }),
        tools,
        dir.path(),
        &report,
        &config,
        None,
        None,
        Some(ValidateConfig {
            step11: &step11,
            tools: read_only.as_ref(),
        }),
        &cancellable(tx, &token),
    )
    .await;

    assert!(
        matches!(outcome.outcomes.as_slice(),
            [bc_stage_s10::RemediationOutcome::Failed { error, .. }]
                if error.contains("canceled by user (Ctrl-C)")),
        "{:?}",
        outcome.outcomes
    );
    assert!(outcome.validations.is_empty());
    assert_eq!(
        std::fs::read_to_string(dir.path().join("app.py")).unwrap(),
        "print(1)\n",
        "the agent's half-finished edit must be rolled back"
    );
    let events: Vec<ScanEvent> = rx.try_iter().collect();
    assert!(finished_stages(&events).contains(&(S11_STAGE, StageStatus::Skipped)));
    assert!(!events.contains(&ScanEvent::StageStarted { stage: S11_STAGE }));
}

/// Trips the token on the first S11 call only, after S10 has finished.
struct TripOnValidation {
    inner: S10AndS11Client,
    token: CancelTokenRef,
}

#[async_trait]
impl LlmClient for TripOnValidation {
    async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, LlmError> {
        if !request
            .system
            .as_deref()
            .unwrap_or("")
            .contains("REMEDIATION agent")
        {
            self.token.cancel(USER_CANCEL_REASON);
        }
        self.inner.chat(request).await
    }
}

#[tokio::test]
async fn a_cancel_during_s11_starts_no_further_validation() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("app.py"), "print(1)\n").unwrap();
    let report = s10_report(dir.path(), vec![s10_ranked(Some(7.0))], None);
    let tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));
    let read_only: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new(dir.path()));
    let step11 = s11_config();
    let token = CancelToken::new_ref();
    let (tx, _rx) = std::sync::mpsc::channel();
    let outcome = remediate_observed(
        Arc::new(TripOnValidation {
            inner: S10AndS11Client::new(),
            token: token.clone(),
        }),
        tools,
        dir.path(),
        &report,
        &s10_config(),
        None,
        None,
        Some(ValidateConfig {
            step11: &step11,
            tools: read_only.as_ref(),
        }),
        &cancellable(tx, &token),
    )
    .await;
    // The one validation that was already under way when the token
    // tripped either finished or failed on a refused call; nothing more
    // was started.
    assert_eq!(outcome.validations.len(), 1);
    assert!(token.is_canceled());
}

#[tokio::test]
async fn every_stage_s_diagnostics_reach_the_report_metrics() {
    let dir = setup_repo();
    let mut config = scan_config();
    config.autoexclude = autoexclude_counts(&bc_stage_s1::AutoExcludeDiagnostics {
        vetoed: vec![".py".to_string()],
        files_before: 3,
        files_after: 3,
        discarded_empty_scope: false,
        aggressive: false,
    });
    let outcome = run_scan(
        one_finding_client(),
        Arc::new(NoTools),
        scan_input(dir.path()),
        config,
        None,
    )
    .await
    .unwrap();
    let metrics = outcome.report.unwrap().metrics.unwrap();
    let d = &metrics.pipeline_diagnostics;
    assert!(d.autoexclude.ran);
    assert_eq!(d.autoexclude.vetoed, vec![".py".to_string()]);
    // `S2_JSON` names no threats: S2's degraded flag says so.
    assert!(d.threat_model.degraded);
    assert!(!d.threat_model.agentic);
    // S3 degraded to its deterministic sweep, which still counts chunks.
    assert!(d.decompose.catchall_chunks > 0, "{:?}", d.decompose);
    assert!(!metrics.canceled);
    assert!(outcome
        .markdown
        .unwrap()
        .contains("### Pipeline Diagnostics"));
}

#[tokio::test]
async fn an_agentic_threat_model_runs_with_the_scan_s_read_only_tools() {
    let dir = setup_repo();
    let mut config = scan_config();
    config.step2.agentic = true;
    let outcome = run_scan(
        one_finding_client(),
        Arc::new(NoTools),
        scan_input(dir.path()),
        config,
        Some(StopAfter::S8),
    )
    .await
    .unwrap();
    let metrics = outcome.report.unwrap().metrics.unwrap();
    assert!(metrics.pipeline_diagnostics.threat_model.agentic);
}
