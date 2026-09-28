//! Resume chaining, per-stage telemetry and S10/S11 metering tests.
//! A child of `lib.rs`'s `tests` module, so every fixture there
//! (`scan_config`, `client_with`, `s10_report`, the fake clients) is in
//! scope through `super::*`.

use super::*;
use bc_pipeline_core::ScanEvent;

fn store(dir: &tempfile::TempDir) -> Arc<dyn bc_checkpoint::CheckpointStore> {
    Arc::new(bc_checkpoint::SqliteCheckpointStore::new(dir.path().join("state.db")).unwrap())
}

fn save<T: Serialize>(
    store: &Arc<dyn bc_checkpoint::CheckpointStore>,
    run_id: &str,
    step: &str,
    value: &T,
) {
    store
        .save(run_id, step, &serde_json::to_vec(value).unwrap())
        .unwrap();
}

/// S1-S3 rows a resumed scan can start from without calling a model.
fn seed_upstream(store: &Arc<dyn bc_checkpoint::CheckpointStore>, run_id: &str) {
    save(
        store,
        run_id,
        "s1",
        &Step1Checkpoint {
            ctx: ContextPackage {
                all_files: vec!["app.py".to_string()],
                ..ContextPackage::default()
            },
            degraded: false,
        },
    );
    save(
        store,
        run_id,
        "s2",
        &Step2Checkpoint {
            threat_model: None,
            degraded: false,
        },
    );
    save(
        store,
        run_id,
        "s3",
        &Step3Checkpoint {
            manifest: TaskManifest {
                chunks: Vec::new(),
                rationale: String::new(),
                unreachable_files: Vec::new(),
            },
            degraded: false,
        },
    );
}

fn resumed_config(store: Arc<dyn bc_checkpoint::CheckpointStore>) -> ScanConfig {
    let mut config = scan_config();
    config.checkpoint = Some(store);
    config.resume = true;
    config
}

fn status_of(events: &[ScanEvent], wanted: &str) -> StageStatus {
    finished_stages(events)
        .into_iter()
        .find(|(stage, _)| *stage == wanted)
        .map(|(_, status)| status)
        .unwrap_or_else(|| panic!("no StageFinished for {wanted}"))
}

/// The bug this closes: S5/S6/S7 rows were loaded independently, so a
/// stale downstream row from an earlier run was applied on top of an S4
/// that had just re-run. With S4's row missing, every later stage must
/// re-run, and the stale finding in the old S7 row must not appear.
#[tokio::test]
async fn a_missing_s4_row_makes_every_downstream_row_stale() {
    let dir = setup_repo();
    let ckpt = tempfile::tempdir().unwrap();
    let store = store(&ckpt);
    let run_id = bc_checkpoint::run_id_for(dir.path());
    seed_upstream(&store, &run_id);
    let stale = vec![s10_finding(Some(9.0))];
    save(
        &store,
        &run_id,
        "s5",
        &Step5Checkpoint {
            findings: stale.clone(),
            dropped: Vec::new(),
            degraded: false,
        },
    );
    save(
        &store,
        &run_id,
        "s6",
        &Step6Checkpoint {
            verified: stale.clone(),
            dropped: Vec::new(),
        },
    );
    save(
        &store,
        &run_id,
        "s7",
        &Step7Checkpoint {
            findings: stale,
            dropped: Vec::new(),
            degraded: false,
        },
    );

    let (tx, rx) = std::sync::mpsc::channel();
    let mut config = resumed_config(store);
    config.progress = Some(tx);
    let outcome = run_scan(
        empty_findings_client(),
        Arc::new(NoTools),
        scan_input(dir.path()),
        config,
        None,
    )
    .await
    .unwrap();

    assert!(outcome.report.unwrap().findings.is_empty());
    let events: Vec<_> = rx.try_iter().collect();
    assert_eq!(status_of(&events, "s3-decompose"), StageStatus::Cached);
    for stage in ["s4-deepdive", "s5-prefilter", "s6-verify", "s7-dedup"] {
        assert_eq!(status_of(&events, stage), StageStatus::Completed, "{stage}");
    }
}

/// A resumed S5 that was followed by a live S6 must not reuse S7.
#[tokio::test]
async fn a_missing_s6_row_makes_the_s7_row_stale() {
    let dir = setup_repo();
    let ckpt = tempfile::tempdir().unwrap();
    let store = store(&ckpt);
    let run_id = bc_checkpoint::run_id_for(dir.path());
    seed_upstream(&store, &run_id);
    save(
        &store,
        &run_id,
        "s4",
        &Step4Checkpoint {
            findings: Vec::new(),
            outcomes: BTreeMap::new(),
        },
    );
    save(
        &store,
        &run_id,
        "s5",
        &Step5Checkpoint {
            findings: Vec::new(),
            dropped: Vec::new(),
            degraded: false,
        },
    );
    save(
        &store,
        &run_id,
        "s7",
        &Step7Checkpoint {
            findings: vec![s10_finding(Some(9.0))],
            dropped: Vec::new(),
            degraded: false,
        },
    );
    let (tx, rx) = std::sync::mpsc::channel();
    let mut config = resumed_config(store);
    config.progress = Some(tx);
    let outcome = run_scan(
        empty_findings_client(),
        Arc::new(NoTools),
        scan_input(dir.path()),
        config,
        None,
    )
    .await
    .unwrap();
    assert!(outcome.report.unwrap().findings.is_empty());
    let events: Vec<_> = rx.try_iter().collect();
    assert_eq!(status_of(&events, "s5-prefilter"), StageStatus::Cached);
    assert_eq!(status_of(&events, "s6-verify"), StageStatus::Completed);
    assert_eq!(status_of(&events, "s7-dedup"), StageStatus::Completed);
}

/// The whole chain restored end to end reports every stage as cached,
/// with no duration, in the stream and in the report's own timings.
#[tokio::test]
async fn a_fully_populated_cache_resumes_the_whole_chain() {
    let dir = setup_repo();
    let ckpt = tempfile::tempdir().unwrap();
    let store = store(&ckpt);
    let mut first = scan_config();
    first.checkpoint = Some(store.clone());
    run_scan(
        one_finding_client(),
        Arc::new(NoTools),
        scan_input(dir.path()),
        first,
        None,
    )
    .await
    .unwrap();

    let (tx, rx) = std::sync::mpsc::channel();
    let mut second = resumed_config(store);
    second.progress = Some(tx);
    let outcome = run_scan(
        client_with(vec![(S8_SYSTEM_MARK, s8_ranked_json())]),
        Arc::new(NoTools),
        scan_input(dir.path()),
        second,
        None,
    )
    .await
    .unwrap();
    let events: Vec<_> = rx.try_iter().collect();
    for stage in [
        "s1-preprocess",
        "s2-threatmodel",
        "s3-decompose",
        "s4-deepdive",
        "s5-prefilter",
        "s6-verify",
        "s7-dedup",
    ] {
        assert_eq!(status_of(&events, stage), StageStatus::Cached, "{stage}");
    }
    let timings = outcome.report.unwrap().metrics.unwrap().stage_timings;
    assert_eq!(timings["s4"].outcome, "cached");
    assert_eq!(timings["s4"].duration_sec, None);
}

/// S4's checkpoint used to drop its chunk outcomes, so a resumed scan
/// claimed a clean S4 even when chunks had failed.
#[tokio::test]
async fn a_resumed_s4_still_reports_the_chunks_it_lost() {
    let dir = setup_repo();
    let ckpt = tempfile::tempdir().unwrap();
    let store = store(&ckpt);
    let run_id = bc_checkpoint::run_id_for(dir.path());
    seed_upstream(&store, &run_id);
    let outcomes = BTreeMap::from([
        ("chunk-1".to_string(), CheckpointChunkOutcome::Error),
        ("chunk-2".to_string(), CheckpointChunkOutcome::Completed),
        ("chunk-3".to_string(), CheckpointChunkOutcome::Guardrail),
        ("chunk-4".to_string(), CheckpointChunkOutcome::Skipped),
    ]);
    save(
        &store,
        &run_id,
        "s4",
        &Step4Checkpoint {
            findings: Vec::new(),
            outcomes,
        },
    );
    let (tx, rx) = std::sync::mpsc::channel();
    let mut config = resumed_config(store);
    config.progress = Some(tx);
    let outcome = run_scan(
        empty_findings_client(),
        Arc::new(NoTools),
        scan_input(dir.path()),
        config,
        None,
    )
    .await
    .unwrap();
    let metrics = outcome.report.unwrap().metrics.unwrap();
    assert_eq!(metrics.chunks_failed, 2);
    assert_eq!(metrics.errors_by_stage.get("s4"), Some(&2));
    let events: Vec<_> = rx.try_iter().collect();
    assert_eq!(
        finished_counts(&events, "s4-deepdive"),
        vec![
            ("findings", 0),
            ("chunks", 4),
            ("chunks_failed", 2),
            ("chunks_skipped", 1)
        ]
    );
}

/// A row written before outcomes were checkpointed still resumes, as
/// Python's legacy bare-list S4 row does, with no outcomes.
#[test]
fn a_findings_only_s4_row_still_loads() {
    let row: Step4Checkpoint = serde_json::from_str(r#"{"findings": []}"#).unwrap();
    assert!(row.outcomes.is_empty());
}

#[test]
fn checkpoint_chunk_outcomes_round_trip_through_the_stage_type() {
    for outcome in [
        bc_stage_s4::ChunkOutcome::Completed,
        bc_stage_s4::ChunkOutcome::Error,
        bc_stage_s4::ChunkOutcome::Guardrail,
        bc_stage_s4::ChunkOutcome::Skipped,
    ] {
        let mirrored = CheckpointChunkOutcome::from(outcome);
        // Spelled exactly like `outcome_str`, Python's own vocabulary.
        assert_eq!(
            serde_json::to_value(mirrored).unwrap(),
            json!(outcome_str(outcome))
        );
        assert_eq!(bc_stage_s4::ChunkOutcome::from(mirrored), outcome);
    }
}

/// A live S4 run's outcomes are what its checkpoint row now carries.
#[tokio::test]
async fn a_live_s4_run_checkpoints_its_chunk_outcomes() {
    let dir = setup_repo();
    let ckpt = tempfile::tempdir().unwrap();
    let store = store(&ckpt);
    let mut config = scan_config();
    config.checkpoint = Some(store.clone());
    run_scan(
        empty_findings_client(),
        Arc::new(NoTools),
        scan_input(dir.path()),
        config,
        Some(StopAfter::S4),
    )
    .await
    .unwrap();
    let run_id = bc_checkpoint::run_id_for(dir.path());
    let row: Step4Checkpoint = serde_json::from_slice(&store.load(&run_id, "s4").unwrap()).unwrap();
    assert!(!row.outcomes.is_empty());
    assert!(row
        .outcomes
        .values()
        .all(|o| *o == CheckpointChunkOutcome::Completed));
}

/// Python never checkpoints an empty threat model: `--resume` would
/// inherit it forever and S2 would never re-run.
#[tokio::test]
async fn an_empty_threat_model_is_not_checkpointed() {
    let dir = setup_repo();
    let ckpt = tempfile::tempdir().unwrap();
    let store = store(&ckpt);
    let mut config = scan_config();
    config.checkpoint = Some(store.clone());
    let empty_model = r#"{"system_context":"ctx","assets":[],"trust_boundaries":[],"threats":[],"open_questions":[]}"#;
    run_scan(
        client_with(vec![
            (S1_SYSTEM_MARK, S1_JSON.to_string()),
            (S2_SYSTEM_MARK, empty_model.to_string()),
        ]),
        Arc::new(NoTools),
        scan_input(dir.path()),
        config,
        Some(StopAfter::S2),
    )
    .await
    .unwrap();
    let run_id = bc_checkpoint::run_id_for(dir.path());
    assert!(store.load(&run_id, "s1").is_some());
    assert!(store.load(&run_id, "s2").is_none());
}

/// A failed S2 is not checkpointed either, and closes as `error` with the
/// (redacted) reason rather than as a quietly completed stage.
#[tokio::test]
async fn a_failed_threat_model_is_not_checkpointed_and_reports_an_error() {
    let dir = setup_repo();
    let ckpt = tempfile::tempdir().unwrap();
    let store = store(&ckpt);
    let (tx, rx) = std::sync::mpsc::channel();
    let mut config = scan_config();
    config.checkpoint = Some(store.clone());
    config.progress = Some(tx);
    let client: Arc<dyn LlmClient> = Arc::new(RoutedClient::new(|system: &str| {
        if system.contains(S2_SYSTEM_MARK) {
            Err(LlmError::ConnectionError {
                message: "s2 down, token=abcdef123456".to_string(),
            })
        } else {
            Ok(route(system, &[(S1_SYSTEM_MARK, S1_JSON)]))
        }
    }));
    run_scan(
        client,
        Arc::new(NoTools),
        scan_input(dir.path()),
        config,
        Some(StopAfter::S2),
    )
    .await
    .unwrap();
    let run_id = bc_checkpoint::run_id_for(dir.path());
    assert!(store.load(&run_id, "s2").is_none());
    let events: Vec<_> = rx.try_iter().collect();
    let detail = events
        .iter()
        .find_map(|e| match e {
            ScanEvent::StageFinished {
                stage: "s2-threatmodel",
                status: StageStatus::Error,
                detail,
                ..
            } => detail.clone(),
            _ => None,
        })
        .expect("S2 closes as an error with a reason");
    assert!(detail.contains("s2 down"), "{detail}");
    assert!(!detail.contains("abcdef123456"), "{detail}");
}

/// Counts and reports every truncation through to the wrapped client.
struct TruncationCountingClient {
    noted: std::sync::atomic::AtomicU64,
}

#[async_trait]
impl LlmClient for TruncationCountingClient {
    async fn chat(&self, _request: &ChatRequest) -> Result<ChatResponse, LlmError> {
        unreachable!("only the truncation hook is exercised")
    }

    fn note_truncated_reply(&self) {
        self.noted
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

#[test]
fn the_usage_tracker_counts_truncations_per_phase_and_forwards_them() {
    let inner = Arc::new(TruncationCountingClient {
        noted: std::sync::atomic::AtomicU64::new(0),
    });
    let tracker = UsageTrackingClient::new(inner.clone(), &pricing::PricingConfig::default());
    tracker.note_truncated_reply();
    tracker.note_truncated_reply();
    assert_eq!(tracker.take().truncated_replies, 2);
    // `take` resets it with the rest of the phase's bucket.
    assert_eq!(tracker.take().truncated_replies, 0);
    // A decorator must forward, or a client further in never hears of it.
    assert_eq!(inner.noted.load(std::sync::atomic::Ordering::Relaxed), 2);
}

#[test]
fn build_metrics_totals_cache_tokens_and_truncations_across_phases() {
    let dir = tempfile::tempdir().unwrap();
    let mut tokens_by_phase = BTreeMap::new();
    let mut s4 = phase_usage(Usage {
        input_tokens: 10,
        output_tokens: 5,
        cache_creation_input_tokens: 3,
        cache_read_input_tokens: 100,
    });
    s4.truncated_replies = 2;
    tokens_by_phase.insert("s4".to_string(), s4);
    let mut s6 = phase_usage(Usage {
        input_tokens: 1,
        output_tokens: 1,
        cache_creation_input_tokens: 4,
        cache_read_input_tokens: 50,
    });
    s6.truncated_replies = 1;
    tokens_by_phase.insert("s6".to_string(), s6);
    let metrics = build_metrics(
        &ContextPackage::default(),
        &TaskManifest {
            chunks: Vec::new(),
            rationale: String::new(),
            unreachable_files: Vec::new(),
        },
        dir.path(),
        "demo",
        "2026-01-01T00:00:00Z",
        "2026-01-01T00:00:10Z",
        0,
        0,
        0,
        0,
        &BTreeMap::new(),
        &tokens_by_phase,
        Vec::new(),
        BTreeMap::new(),
        None,
    );
    assert_eq!(metrics.cache_read_tokens, Some(150));
    assert_eq!(metrics.cache_write_tokens, Some(7));
    assert_eq!(metrics.llm_truncated_replies, 3);
    // Cache reads stay out of the headline, cache writes stay in it.
    assert_eq!(metrics.prompt_tokens, Some(18));
}

#[test]
fn stage_usage_mirrors_the_report_arithmetic() {
    let mut phase = priced_phase(
        Some("anthropic"),
        "claude-sonnet-4-5",
        Usage {
            input_tokens: 1000,
            output_tokens: 100,
            cache_creation_input_tokens: 10,
            cache_read_input_tokens: 500,
        },
    );
    phase.truncated_replies = 1;
    let usage = stage_usage(phase);
    assert_eq!(usage.prompt_tokens, 1010);
    assert_eq!(usage.completion_tokens, 100);
    assert_eq!(usage.cache_read_tokens, 500);
    assert_eq!(usage.cache_write_tokens, 10);
    assert_eq!(usage.calls, 1);
    assert!(usage.cost_usd.is_some_and(|c| c > 0.0));
    assert_eq!(usage.truncated_replies, 1);
    // Nothing priced is `None`, never a truthful-looking zero.
    assert_eq!(stage_usage(PhaseUsage::default()).cost_usd, None);
}

fn usage_for(events: &[ScanEvent], wanted: &str) -> bc_pipeline_core::StageUsage {
    events
        .iter()
        .find_map(|e| match e {
            ScanEvent::UsageUpdate { stage, usage } if *stage == wanted => Some(*usage),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no UsageUpdate for {wanted}"))
}

fn observed(progress: std::sync::mpsc::Sender<ScanEvent>) -> RemediateTelemetry {
    RemediateTelemetry {
        progress: Some(progress),
        pricing: pricing::PricingConfig::for_provider(Some("anthropic")),
        cancel: None,
    }
}

/// S10 and S11 are metered as phases of their own: every call either
/// stage makes is attributed to it, instead of going unrecorded.
#[tokio::test]
async fn remediation_and_validation_spend_is_attributed_to_s10_and_s11() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("app.py"), "print(1)\n").unwrap();
    let report = s10_report(dir.path(), vec![s10_ranked(Some(7.0))], None);
    let llm: Arc<dyn LlmClient> = Arc::new(UsageInjectingClient {
        inner: Arc::new(S10AndS11Client::new()),
        usage: Usage {
            input_tokens: 100,
            output_tokens: 10,
            cache_creation_input_tokens: 0,
            cache_read_input_tokens: 7,
        },
    });
    let tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));
    let read_only: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new(dir.path()));
    let step11 = s11_config();
    let (tx, rx) = std::sync::mpsc::channel();

    let outcome = remediate_observed(
        llm,
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
        &observed(tx),
    )
    .await;
    assert_eq!(outcome.validations.len(), 1);

    let events: Vec<_> = rx.try_iter().collect();
    assert_eq!(
        finished_stages(&events),
        [
            (S10_STAGE, StageStatus::Completed),
            (S11_STAGE, StageStatus::Completed)
        ]
    );
    let s10 = usage_for(&events, S10_STAGE);
    let s11 = usage_for(&events, S11_STAGE);
    // S10 is a two-turn agentic session; S11 runs two personas.
    assert_eq!(s10.calls, 2);
    assert_eq!(s11.calls, 2);
    assert_eq!(s10.prompt_tokens, 200);
    assert_eq!(s11.cache_read_tokens, 14);
    assert_eq!(
        finished_counts(&events, S10_STAGE),
        vec![
            ("attempted", 1),
            ("fixed", 1),
            ("not_fixed", 0),
            ("failed", 0)
        ]
    );
    assert_eq!(
        finished_counts(&events, S11_STAGE),
        vec![
            ("validated", 1),
            ("passed", 1),
            ("failed", 0),
            ("inconclusive", 0)
        ]
    );
}

#[tokio::test]
async fn validation_off_closes_s11_as_disabled() {
    let dir = tempfile::tempdir().unwrap();
    let report = s10_report(dir.path(), vec![s10_ranked(Some(7.0))], None);
    let tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));
    let (tx, rx) = std::sync::mpsc::channel();
    remediate_observed(
        Arc::new(FailingClient),
        tools,
        dir.path(),
        &report,
        &s10_config(),
        None,
        None,
        None,
        &observed(tx),
    )
    .await;
    let events: Vec<_> = rx.try_iter().collect();
    // A session that errored is lost work, not a verdict.
    assert_eq!(
        finished_stages(&events),
        [
            (S10_STAGE, StageStatus::CompletedWithErrors),
            (S11_STAGE, StageStatus::Disabled)
        ]
    );
    assert_eq!(
        finished_counts(&events, S10_STAGE),
        vec![
            ("attempted", 1),
            ("fixed", 0),
            ("not_fixed", 0),
            ("failed", 1)
        ]
    );
    assert!(!events.contains(&ScanEvent::StageStarted { stage: S11_STAGE }));
}

#[tokio::test]
async fn a_validation_session_that_errors_closes_s11_with_errors() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("app.py"), "print(1)\n").unwrap();
    let report = s10_report(dir.path(), vec![s10_ranked(Some(7.0))], None);
    let tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));
    let read_only: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new(dir.path()));
    let step11 = s11_config();
    let (tx, rx) = std::sync::mpsc::channel();
    remediate_observed(
        Arc::new(S10SucceedsS11FailsClient::new()),
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
        &observed(tx),
    )
    .await;
    let events: Vec<_> = rx.try_iter().collect();
    assert_eq!(
        status_of(&events, S11_STAGE),
        StageStatus::CompletedWithErrors
    );
    assert_eq!(
        finished_counts(&events, S11_STAGE),
        vec![
            ("validated", 1),
            ("passed", 0),
            ("failed", 1),
            ("inconclusive", 0)
        ]
    );
}

#[test]
fn a_scan_without_remediation_closes_both_stages_as_disabled() {
    let (tx, rx) = std::sync::mpsc::channel();
    remediation_not_requested(Some(&tx));
    let events: Vec<_> = rx.try_iter().collect();
    assert_eq!(
        finished_stages(&events),
        [
            (S10_STAGE, StageStatus::Disabled),
            (S11_STAGE, StageStatus::Disabled)
        ]
    );
}

#[tokio::test]
async fn nothing_to_remediate_disables_both_stages() {
    let dir = tempfile::tempdir().unwrap();
    let report = s10_report(dir.path(), Vec::new(), None);
    let tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));
    let (tx, rx) = std::sync::mpsc::channel();
    remediate_observed(
        Arc::new(S10Client),
        tools,
        dir.path(),
        &report,
        &s10_config(),
        None,
        None,
        None,
        &observed(tx),
    )
    .await;
    let events: Vec<_> = rx.try_iter().collect();
    assert_eq!(
        finished_stages(&events),
        [
            (S10_STAGE, StageStatus::Disabled),
            (S11_STAGE, StageStatus::Disabled)
        ]
    );
    assert!(!events
        .iter()
        .any(|e| matches!(e, ScanEvent::StageStarted { .. })));
}
