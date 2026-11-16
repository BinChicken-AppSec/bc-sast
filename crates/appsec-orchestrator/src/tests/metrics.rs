use super::*;
#[test]
fn build_metrics_does_not_count_a_budget_skipped_chunks_files_as_analyzed() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("reviewed.py"), "a\nb\n").unwrap();
    std::fs::write(dir.path().join("skipped.py"), "c\nd\n").unwrap();

    let ctx = ContextPackage {
        all_files: vec!["reviewed.py".to_string(), "skipped.py".to_string()],
        ..Default::default()
    };
    let manifest = TaskManifest {
        chunks: vec![
            chunk("risk-001", &["reviewed.py"], None),
            chunk("risk-002", &["skipped.py"], None),
        ],
        rationale: String::new(),
        unreachable_files: Vec::new(),
    };
    let mut chunk_outcomes = BTreeMap::new();
    chunk_outcomes.insert(
        "risk-001".to_string(),
        appsec_stage_s4::ChunkOutcome::Completed,
    );
    chunk_outcomes.insert(
        "risk-002".to_string(),
        appsec_stage_s4::ChunkOutcome::Skipped,
    );

    let metrics = build_metrics(
        &ctx,
        &manifest,
        dir.path(),
        "demo",
        "01932f1a-7c3d-7000-8000-0123456789ab",
        "2024-01-01T00:00:00Z",
        "2024-01-01T00:00:10Z",
        0,
        0,
        0,
        0,
        &chunk_outcomes,
        &BTreeMap::new(),
        Vec::new(),
        BTreeMap::new(),
        Some("S4: token budget reached".to_string()),
    );

    assert_eq!(metrics.total_files_in_scope, 2);
    assert_eq!(metrics.analyzed_files_unique, 1);
    assert_eq!(metrics.loc_in_scope_by_language.get("python"), Some(&4));
    assert_eq!(metrics.loc_scanned_by_language.get("python"), Some(&2));
    assert_eq!(metrics.chunks_failed, 0);
    assert!(metrics.errors_by_stage.is_empty());
    assert_eq!(metrics.budget_stop, "S4: token budget reached");
    assert_eq!(metrics.scope.len(), 2);
}
#[test]
fn build_metrics_classifies_every_chunk_kind_and_aggregates_loc_by_language() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("app.py"), "a\nb\n\nc\n").unwrap();
    std::fs::write(dir.path().join("unscanned.py"), "x\ny\n").unwrap();
    std::fs::write(dir.path().join("app.rs"), "fn main() {}\n").unwrap();

    let ctx = ContextPackage {
        all_files: vec![
            "app.py".to_string(),
            "unscanned.py".to_string(),
            "app.rs".to_string(),
        ],
        ..Default::default()
    };
    let manifest = TaskManifest {
        chunks: vec![
            chunk("risk-001", &["app.py"], None),
            chunk("catchall-002", &["app.rs"], None),
            chunk("specialist-003", &["app.py"], Some("iac")),
        ],
        rationale: String::new(),
        unreachable_files: Vec::new(),
    };
    let mut chunk_outcomes = BTreeMap::new();
    chunk_outcomes.insert(
        "risk-001".to_string(),
        appsec_stage_s4::ChunkOutcome::Completed,
    );
    chunk_outcomes.insert(
        "catchall-002".to_string(),
        appsec_stage_s4::ChunkOutcome::Error,
    );
    chunk_outcomes.insert(
        "specialist-003".to_string(),
        appsec_stage_s4::ChunkOutcome::Guardrail,
    );

    let mut tokens_by_phase = BTreeMap::new();
    tokens_by_phase.insert(
        "s1".to_string(),
        phase_usage(Usage {
            input_tokens: 100,
            output_tokens: 20,
            cache_creation_input_tokens: 5,
            cache_read_input_tokens: 3,
            reasoning_output_tokens: 0,
        }),
    );
    tokens_by_phase.insert(
        "s3".to_string(),
        phase_usage(Usage {
            input_tokens: 50,
            output_tokens: 10,
            ..Usage::default()
        }),
    );
    let metrics = build_metrics(
        &ctx,
        &manifest,
        dir.path(),
        "demo",
        "01932f1a-7c3d-7000-8000-0123456789ab",
        "2024-01-01T00:00:00Z",
        "2024-01-01T00:00:10Z",
        5,
        3,
        1,
        1,
        &chunk_outcomes,
        &tokens_by_phase,
        Vec::new(),
        BTreeMap::new(),
        None,
    );

    assert_eq!(metrics.scan_id, "2024-01-01T00:00:00Z__demo");
    assert_eq!(metrics.module_name, "demo");
    assert_eq!(metrics.duration_sec, 10.0);
    assert_eq!(metrics.total_files_in_scope, 3);
    assert_eq!(metrics.analyzed_files_unique, 1);
    assert_eq!(metrics.chunks_total, 3);
    assert_eq!(metrics.chunks_risk, 1);
    assert_eq!(metrics.chunks_catchall, 1);
    assert_eq!(metrics.chunks_specialist, 1);
    assert_eq!(metrics.chunks_attempted, 3);
    assert_eq!(metrics.chunks_failed, 2);
    assert_eq!(metrics.raw_findings_count, 5);
    assert_eq!(metrics.true_positive_count, 3);
    assert_eq!(metrics.false_positive_count, 1);
    assert_eq!(metrics.duplicate_count, 1);
    assert_eq!(metrics.prompt_tokens, Some(155));
    assert_eq!(metrics.completion_tokens, Some(30));
    assert_eq!(metrics.total_tokens, Some(185));
    let phases = metrics.tokens_by_phase.as_ref().unwrap();
    assert_eq!(phases["s1"]["prompt"], 105);
    assert_eq!(phases["s1"]["completion"], 20);
    assert_eq!(phases["s1"]["cache_read"], 3);
    assert_eq!(phases["s1"]["cache_write"], 5);
    assert_eq!(phases["s1"]["calls"], 1);
    assert_eq!(phases["s3"]["prompt"], 50);
    assert_eq!(metrics.errors_by_stage.get("s4"), Some(&2));
    assert_eq!(metrics.errors_by_stage.len(), 1);
    assert_eq!(metrics.loc_in_scope_by_language.get("python"), Some(&5));
    assert_eq!(metrics.loc_scanned_by_language.get("python"), Some(&3));
    assert_eq!(metrics.loc_in_scope_by_language.get("rust"), Some(&1));
    assert_eq!(metrics.loc_scanned_by_language.get("rust"), None);
    assert_eq!(metrics.folders_scanned, vec!["."]);
    assert_eq!(metrics.scope.len(), 3);
    let risk_entry = metrics.scope.iter().find(|s| s.name == "risk-001").unwrap();
    assert_eq!(risk_entry.kind, ScopeKind::Risk);
    let catchall_entry = metrics
        .scope
        .iter()
        .find(|s| s.name == "catchall-002")
        .unwrap();
    assert_eq!(catchall_entry.kind, ScopeKind::Catchall);
    let specialist_entry = metrics
        .scope
        .iter()
        .find(|s| s.name == "specialist-003")
        .unwrap();
    assert_eq!(specialist_entry.kind, ScopeKind::Specialist);
}
#[test]
fn build_metrics_reports_token_usage_as_unavailable_when_no_call_carried_any() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = ContextPackage::default();
    let manifest = TaskManifest {
        chunks: Vec::new(),
        rationale: String::new(),
        unreachable_files: Vec::new(),
    };
    let mut tokens_by_phase = BTreeMap::new();
    tokens_by_phase.insert(
        "s1".to_string(),
        PhaseUsage {
            usage: Usage::default(),
            calls: 3,
            calls_with_usage: 0,
            cost: pricing::PhaseCost::default(),
            truncated_replies: 0,
        },
    );
    let metrics = build_metrics(
        &ctx,
        &manifest,
        dir.path(),
        "demo",
        "01932f1a-7c3d-7000-8000-0123456789ab",
        "2024-01-01T00:00:00Z",
        "2024-01-01T00:00:10Z",
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
    assert_eq!(metrics.prompt_tokens, None);
    assert_eq!(metrics.completion_tokens, None);
    assert_eq!(metrics.total_tokens, None);
    assert_eq!(metrics.tokens_by_phase, None);
    assert_eq!(metrics.cost_usd, None);
    assert_eq!(metrics.unpriced_tokens, None);
    assert_eq!(metrics.unpriced_calls, None);
    assert!(metrics.unpriced_models.is_empty());
}
#[test]
fn build_metrics_sums_every_phase_cost_into_one_run_total() {
    let dir = tempfile::tempdir().unwrap();
    let tokens_by_phase = BTreeMap::from([
        (
            "s1".to_string(),
            priced_phase(Some("openai"), "gpt-4o", one_dollar_of_gpt_4o()),
        ),
        (
            "s4".to_string(),
            priced_phase(Some("openai"), "gpt-4o", one_dollar_of_gpt_4o()),
        ),
    ]);
    let metrics = cost_metrics(dir.path(), &tokens_by_phase, Vec::new());

    assert_eq!(metrics.cost_usd, Some(2.0));
    assert_eq!(metrics.unpriced_tokens, Some(0));
    assert_eq!(metrics.unpriced_calls, Some(0));
    assert!(metrics.unpriced_models.is_empty());
    let phases = metrics.tokens_by_phase.as_ref().unwrap();
    assert_eq!(phases["s1"]["cost_usd"], 1.0);
    assert_eq!(phases["s4"]["cost_usd"], 1.0);
    assert_eq!(phases["s1"]["unpriced_tokens"], 0);
}
#[test]
fn build_metrics_reports_an_unpriceable_run_as_unpriced_not_free() {
    let dir = tempfile::tempdir().unwrap();
    let tokens_by_phase = BTreeMap::from([(
        "s1".to_string(),
        priced_phase(Some("openai"), "house-blend-9", one_dollar_of_gpt_4o()),
    )]);
    let metrics = cost_metrics(
        dir.path(),
        &tokens_by_phase,
        vec!["openai/house-blend-9".to_string()],
    );

    assert_eq!(metrics.cost_usd, None);
    assert_ne!(metrics.cost_usd, Some(0.0));
    assert_eq!(metrics.unpriced_tokens, Some(250_000));
    assert_eq!(metrics.unpriced_calls, Some(1));
    assert_eq!(metrics.unpriced_models, ["openai/house-blend-9"]);
    assert_eq!(metrics.total_tokens, Some(250_000));
    let phases = metrics.tokens_by_phase.as_ref().unwrap();
    assert_eq!(phases["s1"]["cost_usd"], serde_json::Value::Null);
    assert_eq!(phases["s1"]["unpriced_tokens"], 250_000);
}
#[test]
fn build_metrics_reports_a_mixed_run_as_a_lower_bound() {
    let dir = tempfile::tempdir().unwrap();
    let tokens_by_phase = BTreeMap::from([
        (
            "s1".to_string(),
            priced_phase(Some("openai"), "gpt-4o", one_dollar_of_gpt_4o()),
        ),
        (
            "s4".to_string(),
            priced_phase(Some("openai"), "house-blend-9", one_dollar_of_gpt_4o()),
        ),
    ]);
    let metrics = cost_metrics(
        dir.path(),
        &tokens_by_phase,
        vec!["openai/house-blend-9".to_string()],
    );

    assert_eq!(metrics.cost_usd, Some(1.0));
    assert_eq!(metrics.unpriced_tokens, Some(250_000));
    assert_eq!(metrics.unpriced_calls, Some(1));
    let phases = metrics.tokens_by_phase.as_ref().unwrap();
    assert_eq!(phases["s1"]["cost_usd"], 1.0);
    assert_eq!(phases["s4"]["cost_usd"], serde_json::Value::Null);
}
#[test]
fn build_metrics_counts_a_model_with_no_cache_write_rate_as_partly_unpriced() {
    let dir = tempfile::tempdir().unwrap();
    let usage = Usage {
        input_tokens: 200_000,
        output_tokens: 50_000,
        cache_creation_input_tokens: 1_000,
        cache_read_input_tokens: 800_000,
        reasoning_output_tokens: 0,
    };
    let tokens_by_phase = BTreeMap::from([(
        "s1".to_string(),
        priced_phase(Some("openai"), "gpt-4o", usage),
    )]);
    let metrics = cost_metrics(dir.path(), &tokens_by_phase, Vec::new());

    assert_eq!(metrics.cost_usd, Some(2.0));
    assert_eq!(metrics.unpriced_tokens, Some(1_000));
    assert_eq!(metrics.unpriced_calls, Some(0));
    assert!(metrics.unpriced_models.is_empty());
}
#[tokio::test]
async fn a_scan_on_a_priced_model_reports_what_it_cost() {
    let dir = setup_repo();
    let client = Arc::new(UsageInjectingClient {
        inner: empty_findings_client(),
        usage: one_dollar_of_gpt_4o(),
    });
    let outcome = run_scan(
        client,
        Arc::new(NoTools),
        scan_input(dir.path()),
        priced_scan_config(Some("openai"), "gpt-4o"),
        None,
    )
    .await
    .unwrap();
    let metrics = outcome.report.unwrap().metrics.unwrap();
    let phases = metrics.tokens_by_phase.as_ref().unwrap();
    let calls: i64 = phases.values().map(|b| b["calls"].as_i64().unwrap()).sum();
    assert!(calls > 1, "the fixture scan makes several calls");
    assert_eq!(metrics.cost_usd, Some(calls as f64));
    assert_eq!(metrics.unpriced_tokens, Some(0));
    assert!(metrics.unpriced_models.is_empty());
    assert_eq!(phases["s1"]["cost_usd"], 1.0);
}
#[tokio::test]
async fn a_scan_on_a_model_no_table_knows_reports_unpriced_and_names_it() {
    let dir = setup_repo();
    let client = Arc::new(UsageInjectingClient {
        inner: empty_findings_client(),
        usage: one_dollar_of_gpt_4o(),
    });
    let outcome = run_scan(
        client,
        Arc::new(NoTools),
        scan_input(dir.path()),
        priced_scan_config(Some("openai"), "m"),
        None,
    )
    .await
    .unwrap();
    let metrics = outcome.report.unwrap().metrics.unwrap();
    assert_eq!(metrics.cost_usd, None);
    assert!(metrics.total_tokens.unwrap() > 0, "tokens were still spent");
    assert!(metrics.unpriced_tokens.unwrap() > 0);
    assert_eq!(metrics.unpriced_models, ["openai/m"]);
}
#[tokio::test]
async fn a_scan_with_no_identified_provider_prices_nothing_and_says_so() {
    let dir = setup_repo();
    let client = Arc::new(UsageInjectingClient {
        inner: empty_findings_client(),
        usage: one_dollar_of_gpt_4o(),
    });
    let outcome = run_scan(
        client,
        Arc::new(NoTools),
        scan_input(dir.path()),
        priced_scan_config(None, "gpt-4o"),
        None,
    )
    .await
    .unwrap();
    let metrics = outcome.report.unwrap().metrics.unwrap();
    assert_eq!(metrics.cost_usd, None);
    assert_eq!(
        metrics.unpriced_models,
        [format!("{}/gpt-4o", pricing::UNKNOWN_PROVIDER)]
    );
}
#[tokio::test]
async fn a_scan_whose_gateway_is_on_negotiated_rates_uses_the_override() {
    let dir = setup_repo();
    let client = Arc::new(UsageInjectingClient {
        inner: empty_findings_client(),
        usage: one_dollar_of_gpt_4o(),
    });
    let mut config = priced_scan_config(Some("openai"), "gpt-4o");
    let mut overrides = appsec_pricing::PriceTable::default();
    overrides.insert(
        "openai",
        "gpt-4o",
        appsec_pricing::ModelPrice::flat(250_000, 1_000_000),
    );
    config.pricing.overrides = overrides;
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
    let phases = metrics.tokens_by_phase.as_ref().unwrap();
    let calls: i64 = phases.values().map(|b| b["calls"].as_i64().unwrap()).sum();
    assert_eq!(metrics.cost_usd, Some(calls as f64 / 10.0));
}
#[tokio::test]
async fn a_scan_whose_backend_reports_usage_records_calls_and_bills_cache_writes_only() {
    let dir = setup_repo();
    let client = Arc::new(UsageInjectingClient {
        inner: empty_findings_client(),
        usage: Usage {
            input_tokens: 10,
            output_tokens: 2,
            cache_creation_input_tokens: 4,
            cache_read_input_tokens: 1_000,
            reasoning_output_tokens: 0,
        },
    });
    let outcome = run_scan(
        client,
        Arc::new(NoTools),
        scan_input(dir.path()),
        scan_config(),
        None,
    )
    .await
    .unwrap();
    let metrics = outcome.report.unwrap().metrics.unwrap();
    let phases = metrics.tokens_by_phase.as_ref().unwrap();
    let s1 = &phases["s1"];
    assert_eq!(s1["calls"], 1);
    assert_eq!(s1["prompt"], 14);
    assert_eq!(s1["completion"], 2);
    assert_eq!(s1["cache_read"], 1_000);
    assert_eq!(s1["cache_write"], 4);
    let sum = |key: &str| -> i64 {
        phases
            .values()
            .map(|b| b[key].as_i64().unwrap())
            .sum::<i64>()
    };
    assert_eq!(metrics.prompt_tokens, Some(sum("prompt")));
    assert_eq!(metrics.completion_tokens, Some(sum("completion")));
    assert_eq!(
        metrics.total_tokens,
        Some(sum("prompt") + sum("completion"))
    );
    assert!(sum("cache_read") > metrics.total_tokens.unwrap());
    assert_eq!(sum("prompt"), 14 * sum("calls"));
}
#[test]
fn build_metrics_threads_the_diff_scope_changed_file_count() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = ContextPackage {
        all_files: vec!["a.py".to_string(), "b.py".to_string()],
        diff_scope_active: true,
        changed_files: BTreeMap::from([("a.py".to_string(), BTreeSet::from([1]))]),
        ..Default::default()
    };
    let manifest = TaskManifest {
        chunks: Vec::new(),
        rationale: String::new(),
        unreachable_files: Vec::new(),
    };
    let metrics = build_metrics(
        &ctx,
        &manifest,
        dir.path(),
        "demo",
        "01932f1a-7c3d-7000-8000-0123456789ab",
        "2024-01-01T00:00:00Z",
        "2024-01-01T00:00:10Z",
        0,
        0,
        0,
        0,
        &BTreeMap::new(),
        &BTreeMap::new(),
        Vec::new(),
        BTreeMap::new(),
        None,
    );
    assert_eq!(metrics.changed_files_count, 1);
    assert!(metrics.diff_scope_active);
}
#[test]
fn build_metrics_reports_diff_scope_active_with_a_zero_changed_file_count() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = ContextPackage {
        all_files: vec!["a.py".to_string(), "b.py".to_string()],
        diff_scope_active: true,
        ..Default::default()
    };
    let manifest = TaskManifest {
        chunks: Vec::new(),
        rationale: String::new(),
        unreachable_files: Vec::new(),
    };
    let metrics = build_metrics(
        &ctx,
        &manifest,
        dir.path(),
        "demo",
        "01932f1a-7c3d-7000-8000-0123456789ab",
        "2024-01-01T00:00:00Z",
        "2024-01-01T00:00:10Z",
        0,
        0,
        0,
        0,
        &BTreeMap::new(),
        &BTreeMap::new(),
        Vec::new(),
        BTreeMap::new(),
        None,
    );
    assert_eq!(metrics.changed_files_count, 0);
    assert!(metrics.diff_scope_active);
}
#[test]
fn build_metrics_changed_file_count_is_zero_without_diff_scope() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = ContextPackage {
        all_files: vec!["a.py".to_string()],
        ..Default::default()
    };
    let manifest = TaskManifest {
        chunks: Vec::new(),
        rationale: String::new(),
        unreachable_files: Vec::new(),
    };
    let metrics = build_metrics(
        &ctx,
        &manifest,
        dir.path(),
        "demo",
        "01932f1a-7c3d-7000-8000-0123456789ab",
        "2024-01-01T00:00:00Z",
        "2024-01-01T00:00:10Z",
        0,
        0,
        0,
        0,
        &BTreeMap::new(),
        &BTreeMap::new(),
        Vec::new(),
        BTreeMap::new(),
        None,
    );
    assert_eq!(metrics.changed_files_count, 0);
    assert!(!metrics.diff_scope_active);
}
#[test]
fn build_metrics_treats_an_unreadable_file_as_zero_loc() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = ContextPackage {
        all_files: vec!["missing.py".to_string()],
        ..Default::default()
    };
    let manifest = TaskManifest {
        chunks: Vec::new(),
        rationale: String::new(),
        unreachable_files: Vec::new(),
    };
    let metrics = build_metrics(
        &ctx,
        &manifest,
        dir.path(),
        "demo",
        "01932f1a-7c3d-7000-8000-0123456789ab",
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
    );
    assert_eq!(metrics.loc_in_scope_by_language.get("python"), Some(&0));
    assert_eq!(metrics.chunks_total, 0);
    assert_eq!(metrics.chunks_failed, 0);
    assert_eq!(metrics.prompt_tokens, None);
    assert_eq!(metrics.completion_tokens, None);
    assert_eq!(metrics.total_tokens, None);
    assert_eq!(metrics.tokens_by_phase, None);
    assert!(metrics.errors_by_stage.is_empty());
}
#[test]
fn build_metrics_treats_a_path_that_escapes_the_repo_root_as_zero_loc() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = ContextPackage {
        all_files: vec!["../outside.py".to_string()],
        ..Default::default()
    };
    let manifest = TaskManifest {
        chunks: Vec::new(),
        rationale: String::new(),
        unreachable_files: Vec::new(),
    };
    let metrics = build_metrics(
        &ctx,
        &manifest,
        dir.path(),
        "demo",
        "01932f1a-7c3d-7000-8000-0123456789ab",
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
    );
    assert_eq!(metrics.loc_in_scope_by_language.get("python"), Some(&0));
}
#[test]
#[should_panic(expected = "expected Failed")]
fn expect_failed_panics_on_a_processed_outcome() {
    expect_failed(&appsec_stage_s10::RemediationOutcome::Processed(Box::new(
        appsec_stage_s10::RemediationRecord {
            finding_index: 1,
            finding_id: "x".to_string(),
            verdict: appsec_stage_s10::RemediationVerdict {
                finding_index: 1,
                verdict: appsec_stage_s10::Verdict::Fixed,
                gates: appsec_stage_s10::Gates::default(),
                root_cause: String::new(),
                changes: Vec::new(),
                remaining_risks: Vec::new(),
                recommendations: Vec::new(),
                summary: String::new(),
            },
            policy_action: None,
            policy_reason: None,
            final_verdict: None,
            policy_reverted: Vec::new(),
            policy_matched_globs: Vec::new(),
            diff: None,
        },
    )));
}
#[test]
#[should_panic(expected = "expected Processed")]
fn expect_processed_panics_on_a_failed_outcome() {
    expect_processed(&appsec_stage_s10::RemediationOutcome::Failed {
        finding_index: 1,
        error: "x".to_string(),
    });
}
