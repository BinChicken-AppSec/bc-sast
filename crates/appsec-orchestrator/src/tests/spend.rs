use super::*;
#[test]
fn spend_gate_adds_the_running_stage_s_spend_to_the_recorded_baseline() {
    let tracker = Arc::new(UsageTrackingClient::new(
        client_with(Vec::new()),
        &pricing::PricingConfig::default(),
    ));
    let mut tokens_by_phase = BTreeMap::new();
    tokens_by_phase.insert(
        "s1".to_string(),
        phase_usage(Usage {
            input_tokens: 40,
            ..Usage::default()
        }),
    );
    let cap = SpendCap {
        max_total_tokens: Some(100),
        max_wall_clock: None,
    };
    let gate = budget_gate(
        Some(&cap),
        &tracker,
        &tokens_by_phase,
        std::time::Instant::now(),
        None,
    )
    .unwrap();
    assert!(!gate.should_stop(), "40 of 100 recorded, nothing live yet");

    {
        let mut total = tracker.total.lock().unwrap();
        total.usage.input_tokens += 60;
    }
    assert!(gate.should_stop());
    assert_eq!(
        gate.stop_reason(),
        "token budget of 100 reached (100 spent)"
    );
    assert_eq!(tracker.take().usage.input_tokens, 60);
}
#[test]
fn spend_gate_also_trips_on_wall_clock_and_debug_prints_its_cap() {
    let tracker = Arc::new(UsageTrackingClient::new(
        client_with(Vec::new()),
        &pricing::PricingConfig::default(),
    ));
    let cap = SpendCap {
        max_total_tokens: None,
        max_wall_clock: Some(std::time::Duration::ZERO),
    };
    let gate = budget_gate(
        Some(&cap),
        &tracker,
        &BTreeMap::new(),
        std::time::Instant::now(),
        None,
    )
    .unwrap();
    assert!(gate.should_stop());
    assert!(gate.stop_reason().starts_with("time budget of 0s reached"));
    let rendered = format!("{gate:?}");
    assert!(rendered.starts_with("SpendGate"), "{rendered}");
    assert!(rendered.contains("baseline_tokens: 0"), "{rendered}");
}
#[test]
fn a_scan_with_no_cap_builds_an_idle_gate_that_only_an_external_trip_can_stop() {
    let tracker = Arc::new(UsageTrackingClient::new(
        client_with(Vec::new()),
        &pricing::PricingConfig::default(),
    ));
    let gate = budget_gate(
        None,
        &tracker,
        &BTreeMap::new(),
        std::time::Instant::now(),
        None,
    )
    .expect("an uncapped scan still gets a gate");
    assert!(
        !gate.should_stop(),
        "nothing caps it and nothing tripped it"
    );
    assert_eq!(gate.stop_reason(), "spend cap reached");

    gate.trip("provider quota exhausted — no credits left".to_string());
    assert!(gate.should_stop());
    assert_eq!(
        gate.stop_reason(),
        "provider quota exhausted — no credits left"
    );
}
#[test]
fn a_second_trip_does_not_overwrite_the_first_reason() {
    let tracker = Arc::new(UsageTrackingClient::new(
        client_with(Vec::new()),
        &pricing::PricingConfig::default(),
    ));
    let gate = budget_gate(
        None,
        &tracker,
        &BTreeMap::new(),
        std::time::Instant::now(),
        None,
    )
    .unwrap();
    gate.trip("provider quota exhausted — first".to_string());
    gate.trip("provider quota exhausted — second".to_string());
    assert_eq!(gate.stop_reason(), "provider quota exhausted — first");
    assert!(
        format!("{gate:?}").contains("provider quota exhausted — first"),
        "{gate:?}"
    );
}
#[test]
fn an_external_trip_outranks_a_cap_that_has_also_been_reached() {
    let tracker = Arc::new(UsageTrackingClient::new(
        client_with(Vec::new()),
        &pricing::PricingConfig::default(),
    ));
    let cap = SpendCap {
        max_total_tokens: None,
        max_wall_clock: Some(std::time::Duration::ZERO),
    };
    let gate = budget_gate(
        Some(&cap),
        &tracker,
        &BTreeMap::new(),
        std::time::Instant::now(),
        None,
    )
    .unwrap();
    assert!(gate.stop_reason().starts_with("time budget of 0s reached"));
    gate.trip("provider quota exhausted — no credits left".to_string());
    assert!(gate.should_stop());
    assert_eq!(
        gate.stop_reason(),
        "provider quota exhausted — no credits left"
    );
}
#[test]
fn an_untripped_spend_gate_still_answers_the_reason_question() {
    let tracker = Arc::new(UsageTrackingClient::new(
        client_with(Vec::new()),
        &pricing::PricingConfig::default(),
    ));
    let cap = SpendCap {
        max_total_tokens: Some(100),
        max_wall_clock: None,
    };
    let gate = budget_gate(
        Some(&cap),
        &tracker,
        &BTreeMap::new(),
        std::time::Instant::now(),
        None,
    )
    .unwrap();
    assert!(!gate.should_stop());
    assert_eq!(gate.stop_reason(), "spend cap reached");
}
#[test]
fn spend_cap_exceeded_is_none_when_no_cap_is_set() {
    assert!(spend_cap_exceeded(None, &BTreeMap::new(), std::time::Instant::now()).is_none());
}
#[test]
fn spend_cap_exceeded_trips_when_total_tokens_reach_the_limit() {
    let cap = SpendCap {
        max_total_tokens: Some(100),
        max_wall_clock: None,
    };
    let mut tokens_by_phase = BTreeMap::new();
    tokens_by_phase.insert(
        "s4".to_string(),
        phase_usage(Usage {
            input_tokens: 60,
            output_tokens: 40,
            ..Usage::default()
        }),
    );
    let reason =
        spend_cap_exceeded(Some(&cap), &tokens_by_phase, std::time::Instant::now()).unwrap();
    assert_eq!(reason, "token budget of 100 reached (100 spent)");
}
#[test]
fn spend_cap_exceeded_is_none_when_under_the_token_limit() {
    let cap = SpendCap {
        max_total_tokens: Some(100),
        max_wall_clock: None,
    };
    let mut tokens_by_phase = BTreeMap::new();
    tokens_by_phase.insert(
        "s4".to_string(),
        phase_usage(Usage {
            input_tokens: 10,
            output_tokens: 10,
            ..Usage::default()
        }),
    );
    assert!(spend_cap_exceeded(Some(&cap), &tokens_by_phase, std::time::Instant::now()).is_none());
}
#[test]
fn spend_cap_exceeded_trips_when_wall_clock_is_exceeded() {
    let cap = SpendCap {
        max_total_tokens: None,
        max_wall_clock: Some(std::time::Duration::ZERO),
    };
    let reason =
        spend_cap_exceeded(Some(&cap), &BTreeMap::new(), std::time::Instant::now()).unwrap();
    assert!(reason.starts_with("time budget of 0s reached"), "{reason}");
}
#[tokio::test]
async fn the_seed_plane_walks_the_survey_scope_not_the_whole_repo() {
    let dir = setup_repo();
    std::fs::create_dir_all(dir.path().join("vendor")).unwrap();
    std::fs::write(
        dir.path().join("vendor/lib.py"),
        "def helper(x):\n    return x\n\n\ndef other(y):\n    return y\n",
    )
    .unwrap();
    let mut config = scan_config();
    config.step0_enabled = true;
    config.step1.walk.exclude_dirs.push("vendor".to_string());
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
    assert_eq!(metrics.loc_in_scope_by_language.get("python"), Some(&3));
}
#[tokio::test]
async fn a_token_cap_already_spent_before_s4_skips_every_chunk_and_still_reports() {
    let dir = setup_repo();
    let client = Arc::new(UsageInjectingClient {
        inner: one_finding_client(),
        usage: Usage {
            input_tokens: 1000,
            ..Usage::default()
        },
    });
    let mut config = scan_config();
    config.spend_cap = Some(SpendCap {
        max_total_tokens: Some(1),
        max_wall_clock: None,
    });
    let outcome = run_scan(
        client,
        Arc::new(NoTools),
        scan_input(dir.path()),
        config,
        None,
    )
    .await
    .unwrap();
    assert_eq!(outcome.stopped_after, None);
    let report = outcome.report.unwrap();
    assert!(report.findings.is_empty());
    let metrics = report.metrics.clone().unwrap();
    assert_eq!(metrics.raw_findings_count, 0);
    assert_eq!(metrics.true_positive_count, 0);
    assert_eq!(metrics.false_positive_count, 0);
    assert_eq!(metrics.duplicate_count, 0);
    assert_eq!(metrics.chunks_attempted, 0);
    assert_eq!(metrics.chunks_failed, 0);
    assert!(!metrics.errors_by_stage.contains_key("s4"));
    assert!(
        metrics
            .budget_stop
            .starts_with("S4: token budget of 1 reached"),
        "{}",
        metrics.budget_stop
    );
    assert!(
        metrics
            .budget_stop
            .contains("0 of 3 deep-dive chunk(s) analyzed, 3 skipped"),
        "{}",
        metrics.budget_stop
    );
    let md = appsec_report_md::render_markdown(&report);
    assert!(md.contains("## Scan Health"), "{md}");
    assert!(md.contains("**BUDGET REACHED**"), "{md}");
}
#[tokio::test]
async fn a_zero_wall_clock_cap_skips_every_chunk_and_still_produces_a_report() {
    let dir = setup_repo();
    let mut config = scan_config();
    config.spend_cap = Some(SpendCap {
        max_total_tokens: None,
        max_wall_clock: Some(std::time::Duration::ZERO),
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
    assert_eq!(outcome.stopped_after, None);
    let report = outcome.report.unwrap();
    assert!(report.findings.is_empty());
    let metrics = report.metrics.unwrap();
    assert_eq!(metrics.true_positive_count, 0);
    assert!(
        metrics
            .budget_stop
            .starts_with("S4: time budget of 0s reached"),
        "{}",
        metrics.budget_stop
    );
}
#[tokio::test]
async fn a_token_cap_tripped_by_s5_s_own_semantic_pass_stops_the_scan_after_s5() {
    let dir = setup_repo();
    std::fs::write(dir.path().join("other.py"), "cur2.execute(q2)\n").unwrap();
    let client = Arc::new(MarkedUsageClient {
        inner: client_with(vec![
            (S1_SYSTEM_MARK, S1_JSON.to_string()),
            (S2_SYSTEM_MARK, S2_JSON.to_string()),
            (S3_SYSTEM_MARK, S3_GARBAGE.to_string()),
            (S4_SYSTEM_MARK, s4_two_findings_json()),
            (SEMANTIC_DEDUP_MARK, S3_GARBAGE.to_string()),
            (S8_SYSTEM_MARK, s8_two_ranked_json()),
        ]),
        mark: SEMANTIC_DEDUP_MARK,
        usage: Usage {
            input_tokens: 1000,
            ..Usage::default()
        },
    });
    let mut config = scan_config();
    config.step5.pre_verify_threshold = 2;
    config.step5.dedup.semantic = true;
    config.spend_cap = Some(SpendCap {
        max_total_tokens: Some(1),
        max_wall_clock: None,
    });
    let outcome = run_scan(
        client,
        Arc::new(NoTools),
        scan_input(dir.path()),
        config,
        None,
    )
    .await
    .unwrap();
    assert_eq!(outcome.stopped_after, None);
    let report = outcome.report.unwrap();
    assert!(report.findings.is_empty());
    let metrics = report.metrics.clone().unwrap();
    assert_eq!(metrics.raw_findings_count, 2);
    assert_eq!(metrics.true_positive_count, 0);
    assert_eq!(metrics.duplicate_count, 0);
    let unverified: Vec<_> = report
        .dropped
        .iter()
        .filter(|d| d.reason == DropReason::Unconfirmed && d.detail.starts_with("not verified"))
        .collect();
    let dropped_dbg = format!("{:?}", report.dropped);
    assert_eq!(unverified.len(), 2, "{dropped_dbg}");
    let detail = unverified[0].detail.clone();
    assert!(detail.contains("token budget"), "{detail}");
}
#[tokio::test]
async fn a_token_cap_reached_inside_s4_stops_starting_new_chunks() {
    let dir = setup_repo();
    std::fs::write(dir.path().join("other.py"), "cur2.execute(q2)\n").unwrap();
    let client = Arc::new(MarkedUsageClient {
        inner: client_with(full_table(
            &s4_two_findings_json(),
            &s6_true_positive_text(),
            &s8_two_ranked_json(),
        )),
        mark: S4_SYSTEM_MARK,
        usage: Usage {
            input_tokens: 1000,
            ..Usage::default()
        },
    });
    let mut config = scan_config();
    config.step4.parallel = 1;
    config.spend_cap = Some(SpendCap {
        max_total_tokens: Some(500),
        max_wall_clock: None,
    });
    let outcome = run_scan(
        client,
        Arc::new(NoTools),
        scan_input(dir.path()),
        config,
        None,
    )
    .await
    .unwrap();

    assert_eq!(outcome.stopped_after, None);
    let report = outcome.report.unwrap();
    let metrics = report.metrics.clone().unwrap();
    assert!(
        metrics
            .budget_stop
            .starts_with("S4: token budget of 500 reached"),
        "{}",
        metrics.budget_stop
    );
    assert!(
        metrics
            .budget_stop
            .ends_with("1 of 3 deep-dive chunk(s) analyzed, 2 skipped"),
        "{}",
        metrics.budget_stop
    );
    assert_eq!(
        metrics.chunks_attempted, 1,
        "the skipped chunk was never attempted"
    );
    assert_eq!(metrics.chunks_failed, 0, "and it did not fail");
    assert!(appsec_report_md::render_markdown(&report).contains("**BUDGET REACHED**"));
}
#[tokio::test]
async fn a_token_cap_reached_inside_s6_leaves_the_rest_unverified_and_says_so() {
    let dir = setup_repo();
    std::fs::write(dir.path().join("other.py"), "cur2.execute(q2)\n").unwrap();
    let client = Arc::new(MarkedUsageClient {
        inner: client_with(full_table(
            &s4_two_findings_json(),
            &s6_true_positive_text(),
            &s8_ranked_json(),
        )),
        mark: S6_SYSTEM_MARK,
        usage: Usage {
            input_tokens: 1000,
            ..Usage::default()
        },
    });
    let mut config = scan_config();
    config.step6.parallel = 1;
    config.spend_cap = Some(SpendCap {
        max_total_tokens: Some(500),
        max_wall_clock: None,
    });
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
    let metrics = report.metrics.clone().unwrap();
    assert!(
        metrics
            .budget_stop
            .starts_with("S6: token budget of 500 reached"),
        "{}",
        metrics.budget_stop
    );
    assert!(
        metrics
            .budget_stop
            .ends_with("1 of 2 finding(s) verified, 1 left unverified"),
        "{}",
        metrics.budget_stop
    );
    assert_eq!(metrics.true_positive_count, 1);
    assert_eq!(metrics.raw_findings_count, 2);
    let unverified: Vec<&DroppedFinding> = report
        .dropped
        .iter()
        .filter(|d| d.reason == DropReason::Unconfirmed)
        .collect();
    assert_eq!(unverified.len(), 1);
    let detail = unverified[0].detail.clone();
    assert!(
        detail.starts_with("not verified — token budget of 500 reached"),
        "{detail}"
    );
    let md = appsec_report_md::render_markdown(&report);
    assert!(md.contains("**BUDGET REACHED**"), "{md}");
    assert!(md.contains("[UNCONFIRMED]"), "{md}");
}
#[tokio::test]
async fn a_token_cap_tripped_by_s6_s_own_verify_call_stops_the_scan_after_s6() {
    let dir = setup_repo();
    let client = Arc::new(MarkedUsageClient {
        inner: one_finding_client(),
        mark: S6_SYSTEM_MARK,
        usage: Usage {
            input_tokens: 1000,
            ..Usage::default()
        },
    });
    let mut config = scan_config();
    config.spend_cap = Some(SpendCap {
        max_total_tokens: Some(1),
        max_wall_clock: None,
    });
    let outcome = run_scan(
        client,
        Arc::new(NoTools),
        scan_input(dir.path()),
        config,
        None,
    )
    .await
    .unwrap();
    assert_eq!(outcome.stopped_after, None);
    let report = outcome.report.unwrap();
    assert_eq!(report.findings.len(), 1);
    let metrics = report.metrics.unwrap();
    assert_eq!(metrics.true_positive_count, 1);
    assert_eq!(metrics.false_positive_count, 0);
    assert_eq!(metrics.duplicate_count, 0);
}
#[tokio::test]
async fn a_generous_spend_cap_lets_the_scan_complete_normally() {
    let dir = setup_repo();
    let mut config = scan_config();
    config.spend_cap = Some(SpendCap {
        max_total_tokens: Some(u64::MAX),
        max_wall_clock: Some(std::time::Duration::from_secs(3600)),
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
    assert_eq!(outcome.stopped_after, None);
    let report = outcome.report.unwrap();
    assert_eq!(report.findings.len(), 1);
    let metrics = report.metrics.unwrap();
    assert_eq!(metrics.true_positive_count, 1);
    assert_eq!(metrics.false_positive_count, 0);
    assert!(outcome.sarif.is_some());
}
