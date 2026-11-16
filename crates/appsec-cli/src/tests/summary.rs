use super::*;
#[test]
fn scan_summary_display_reports_a_successful_github_sync() {
    let s = ScanSummary {
        github_sync: Some(Ok(appsec_github::SyncSummary {
            created: 2,
            updated: 1,
        })),
        ..Default::default()
    };
    assert!(s.to_string().contains("GitHub: 2 created, 1 updated."));
}
#[test]
fn scan_summary_display_reports_a_failed_github_sync() {
    let s = ScanSummary {
        github_sync: Some(Err("boom".to_string())),
        ..Default::default()
    };
    assert!(s.to_string().contains("GitHub sync failed: boom"));
}
#[test]
fn scan_summary_display_reports_a_stop_point() {
    let s = ScanSummary {
        stopped_after: Some(StopAfter::S3),
        ..Default::default()
    };
    assert_eq!(s.to_string(), "Scan stopped after S3.");
}
#[test]
fn scan_summary_display_reports_findings_and_paths_on_completion() {
    let s = ScanSummary {
        findings: 2,
        markdown_path: Some(PathBuf::from("/r/report.md")),
        sarif_path: Some(PathBuf::from("/r/report.sarif")),
        ..Default::default()
    };
    let text = s.to_string();
    assert!(text.contains("2 finding(s)"));
    assert!(text.contains("/r/report.md"));
    assert!(text.contains("/r/report.sarif"));
    assert!(!text.contains("Cost"), "no metrics, no cost claim: {text}");
}
#[test]
fn scan_summary_display_reports_a_priced_run_beside_the_findings_count() {
    let s = summary_with_cost(Some(CostSummary {
        usd: Some(1.5),
        unpriced_tokens: 0,
    }));
    assert_eq!(
        s.to_string(),
        "Scan complete: 2 finding(s). Cost (USD): 1.500000."
    );
}
#[test]
fn scan_summary_display_reports_an_unpriced_run_as_unpriced_never_as_zero() {
    let s = summary_with_cost(Some(CostSummary {
        usd: None,
        unpriced_tokens: 1_700,
    }));
    let text = s.to_string();
    assert!(text.contains("Cost (USD): unpriced"), "{text}");
    assert!(
        text.contains("(1700 token(s) had no published rate)"),
        "{text}"
    );
    assert!(!text.contains("0.000000"), "{text}");
}
#[test]
fn scan_summary_display_flags_a_partly_priced_run_as_a_lower_bound() {
    let s = summary_with_cost(Some(CostSummary {
        usd: Some(0.25),
        unpriced_tokens: 300,
    }));
    assert_eq!(
        s.to_string(),
        "Scan complete: 2 finding(s). Cost (USD): 0.250000 (300 token(s) had no published \
         rate)."
    );
}
#[test]
fn cost_summary_is_absent_when_the_metrics_carry_no_money_at_all() {
    assert_eq!(
        CostSummary::from_metrics(&appsec_model::ScanMetrics::default()),
        None
    );
}
#[test]
fn cost_summary_is_present_whenever_either_half_of_the_money_is() {
    let priced = appsec_model::ScanMetrics {
        cost_usd: Some(2.0),
        unpriced_tokens: Some(0),
        ..Default::default()
    };
    assert_eq!(
        CostSummary::from_metrics(&priced),
        Some(CostSummary {
            usd: Some(2.0),
            unpriced_tokens: 0
        })
    );
    let unpriced = appsec_model::ScanMetrics {
        cost_usd: None,
        unpriced_tokens: Some(9),
        ..Default::default()
    };
    let summary = CostSummary::from_metrics(&unpriced).unwrap();
    assert_eq!(summary.usd, None);
    assert_eq!(summary.unpriced_tokens, 9);
    assert_ne!(summary, CostSummary::from_metrics(&priced).unwrap());
    assert!(format!("{summary:?}").contains("CostSummary"));
    assert_eq!(Clone::clone(&summary), summary);
}
#[test]
fn scan_summary_display_propagates_a_write_failure_on_the_stop_line() {
    let s = ScanSummary {
        stopped_after: Some(StopAfter::S3),
        ..Default::default()
    };
    let mut w = ByteBudget {
        budget: 0,
        written: 0,
    };
    assert!(write!(w, "{s}").is_err());
}
#[test]
fn scan_summary_display_propagates_a_write_failure_on_the_findings_line() {
    let s = ScanSummary {
        ..Default::default()
    };
    let mut w = ByteBudget {
        budget: 0,
        written: 0,
    };
    assert!(write!(w, "{s}").is_err());
}
#[test]
fn scan_summary_display_propagates_a_write_failure_on_the_cost_line() {
    let s = summary_with_cost(Some(CostSummary {
        usd: Some(1.5),
        unpriced_tokens: 0,
    }));
    let prefix = "Scan complete: 2 finding(s).";
    let mut w = ByteBudget {
        budget: prefix.len(),
        written: 0,
    };
    assert!(write!(w, "{s}").is_err());
}
#[test]
fn cost_summary_display_propagates_a_write_failure_on_its_own_first_write() {
    for usd in [Some(1.5), None] {
        let cost = CostSummary {
            usd,
            unpriced_tokens: 7,
        };
        let mut w = ByteBudget {
            budget: 0,
            written: 0,
        };
        assert!(write!(w, "{cost}").is_err());
    }
}
#[test]
fn scan_summary_display_propagates_a_write_failure_on_the_markdown_path() {
    let s = ScanSummary {
        markdown_path: Some(PathBuf::from("/r/report.md")),
        ..Default::default()
    };
    let prefix = "Scan complete: 0 finding(s).";
    let mut w = ByteBudget {
        budget: prefix.len(),
        written: 0,
    };
    assert!(write!(w, "{s}").is_err());
}
#[test]
fn scan_summary_display_propagates_a_write_failure_on_the_sarif_path() {
    let s = ScanSummary {
        sarif_path: Some(PathBuf::from("/r/report.sarif")),
        ..Default::default()
    };
    let prefix = "Scan complete: 0 finding(s).";
    let mut w = ByteBudget {
        budget: prefix.len(),
        written: 0,
    };
    assert!(write!(w, "{s}").is_err());
}
#[test]
fn scan_summary_display_propagates_a_write_failure_on_a_successful_github_sync() {
    let s = ScanSummary {
        github_sync: Some(Ok(appsec_github::SyncSummary::default())),
        ..Default::default()
    };
    let prefix = "Scan complete: 0 finding(s).";
    let mut w = ByteBudget {
        budget: prefix.len(),
        written: 0,
    };
    assert!(write!(w, "{s}").is_err());
}
#[test]
fn scan_summary_display_propagates_a_write_failure_on_a_failed_github_sync() {
    let s = ScanSummary {
        github_sync: Some(Err("boom".to_string())),
        ..Default::default()
    };
    let prefix = "Scan complete: 0 finding(s).";
    let mut w = ByteBudget {
        budget: prefix.len(),
        written: 0,
    };
    assert!(write!(w, "{s}").is_err());
}
#[test]
fn scan_summary_display_propagates_a_write_failure_on_a_refused_remediation() {
    let s = ScanSummary {
        provider_publication: None,
        gc: None,
        cost: None,
        findings: 0,
        markdown_path: None,
        sarif_path: None,
        csv_path: None,
        findings_json_path: None,
        stopped_after: None,
        github_sync: None,
        remediation: Some(RemediationSummary {
            validation_failures: 0,
            refused: Some("stale".to_string()),
            processed: 0,
            failed: 0,
            validated: None,
            ..Default::default()
        }),
        remediation_patch: None,
        baseline: None,
        batch: None,
        estimate: None,
        doctor: None,
        setup: None,
        augmented: None,
    };
    let prefix = "Scan complete: 0 finding(s).";
    let mut w = ByteBudget {
        budget: prefix.len(),
        written: 0,
    };
    assert!(write!(w, "{s}").is_err());
}
#[test]
fn scan_summary_display_propagates_a_write_failure_on_remediation_counts() {
    let s = ScanSummary {
        provider_publication: None,
        gc: None,
        cost: None,
        findings: 0,
        markdown_path: None,
        sarif_path: None,
        csv_path: None,
        findings_json_path: None,
        stopped_after: None,
        github_sync: None,
        remediation: Some(RemediationSummary {
            validation_failures: 0,
            refused: None,
            processed: 1,
            failed: 2,
            validated: None,
            ..Default::default()
        }),
        remediation_patch: None,
        baseline: None,
        batch: None,
        estimate: None,
        doctor: None,
        setup: None,
        augmented: None,
    };
    let prefix = "Scan complete: 0 finding(s).";
    let mut w = ByteBudget {
        budget: prefix.len(),
        written: 0,
    };
    assert!(write!(w, "{s}").is_err());
}
#[test]
#[should_panic(expected = "unrecognized system prompt")]
fn route_panics_on_an_unrecognized_system_prompt() {
    route("zzz-totally-unmatched-zzz", &[("xyz-mark-xyz", "reply")]);
}
#[test]
#[should_panic(expected = "expected Some(Err(_))")]
fn assert_github_sync_failed_panics_when_it_did_not_fail() {
    assert_github_sync_failed(&ScanSummary {
        ..Default::default()
    });
}
#[test]
#[should_panic(expected = "expected Processed")]
fn expect_processed_panics_on_a_failed_outcome() {
    expect_processed(&appsec_stage_s10::RemediationOutcome::Failed {
        finding_index: 1,
        error: "x".to_string(),
    });
}
#[test]
#[should_panic(expected = "expected Processed")]
fn assert_processed_panics_on_a_failed_outcome() {
    assert_processed(&appsec_stage_s10::RemediationOutcome::Failed {
        finding_index: 1,
        error: "x".to_string(),
    });
}
#[test]
fn no_tools_execute_returns_an_empty_string() {
    assert_eq!(NoTools.execute("Read", &json!({})), "");
}
#[test]
fn target_test_generation_sees_only_the_findings_remediation_will_fix() {
    let mut low = sample_finding();
    low.title = "low-ranked-finding".into();
    low.cvss_score = None;
    let mut high = sample_finding();
    high.title = "high-ranked-finding".into();
    high.cvss_score = Some(9.4);
    let report = sample_report(None, vec![low, high]);
    let mut config = appsec_orchestrator::RemediateConfig {
        step10: fast_remediate_config(),
        top: None,
        top_default: None,
        force: false,
        resume: false,
        isolated: true,
    };

    let everything = target_test_findings(&report, &config);
    assert!(everything.contains("low-ranked-finding"));
    assert!(everything.contains("high-ranked-finding"));

    config.top = Some(appsec_stage_s10::TopSpec::N(1));
    let requested = target_test_findings(&report, &config);
    assert!(requested.contains("high-ranked-finding"));
    assert!(
        !requested.contains("low-ranked-finding"),
        "a --top 1 run must not describe the finding it will not fix"
    );
}
#[tokio::test]
async fn run_writes_markdown_and_sarif_and_reports_a_summary() {
    let dir = setup_repo();
    let paths = out_paths(&dir.path().join("out"));
    let summary = run(
        fast_input(dir.path()),
        fast_config(),
        None,
        &paths,
        empty_scan_client(),
        Arc::new(NoTools),
        None,
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(summary.findings, 0);
    assert_eq!(
        summary.markdown_path.as_deref(),
        Some(paths.markdown.as_path())
    );
    assert_eq!(summary.sarif_path.as_deref(), Some(paths.sarif.as_path()));
    assert!(paths.markdown.is_file());
    assert!(paths.sarif.is_file());
    assert_eq!(summary.stopped_after, None);
    assert_eq!(summary.cost, None);
    assert!(!std::fs::read_to_string(&paths.markdown)
        .unwrap()
        .contains("Cost (USD)"));
}
#[tokio::test]
async fn run_prices_a_scan_and_says_so_in_both_the_summary_and_the_report() {
    let dir = setup_repo();
    let paths = out_paths(&dir.path().join("out"));
    let config = priced_fast_config("gpt-4o");
    let client = Arc::new(UsageInjectingClient {
        inner: empty_scan_client(),
        usage: Usage {
            input_tokens: 200_000,
            output_tokens: 50_000,
            cache_creation_input_tokens: 0,
            cache_read_input_tokens: 0,
            reasoning_output_tokens: 0,
        },
    });
    let summary = run(
        fast_input(dir.path()),
        config,
        None,
        &paths,
        client,
        Arc::new(NoTools),
        None,
        None,
        None,
    )
    .await
    .unwrap();

    let cost = summary.cost.expect("a priced run reports its cost");
    let usd = cost.usd.expect("every call had a published rate");
    assert!(usd >= 1.0, "at least one call was billed: {usd}");
    assert_eq!(cost.unpriced_tokens, 0);
    assert!(
        summary
            .to_string()
            .contains(&format!("Cost (USD): {usd:.6}")),
        "{summary}"
    );

    let md = std::fs::read_to_string(&paths.markdown).unwrap();
    assert!(md.contains(&format!("- Cost (USD): {usd:.6}")), "{md}");
    assert!(md.contains("| Cost (USD) |"), "{md}");
    assert!(!md.contains("Unpriced tokens"), "{md}");
}
#[tokio::test]
async fn run_reports_an_unpriceable_scan_as_unpriced_in_both_places() {
    let dir = setup_repo();
    let paths = out_paths(&dir.path().join("out"));
    let mut config = priced_fast_config("gpt-4o");
    config.step1.model = "house-blend-9".to_string();
    let client = Arc::new(UsageInjectingClient {
        inner: empty_scan_client(),
        usage: Usage {
            input_tokens: 200_000,
            output_tokens: 50_000,
            cache_creation_input_tokens: 0,
            cache_read_input_tokens: 0,
            reasoning_output_tokens: 0,
        },
    });
    let summary = run(
        fast_input(dir.path()),
        config,
        None,
        &paths,
        client,
        Arc::new(NoTools),
        None,
        None,
        None,
    )
    .await
    .unwrap();

    let cost = summary.cost.expect("an unpriced run still reports");
    assert_eq!(cost.unpriced_tokens, 250_000);
    let text = summary.to_string();
    assert!(
        text.contains("250000 token(s) had no published rate"),
        "{text}"
    );

    let md = std::fs::read_to_string(&paths.markdown).unwrap();
    assert!(
        md.contains(
            "- Unpriced tokens: 250000 across 1 call(s) with no published rate \
             (openai/house-blend-9); the cost above is a lower bound"
        ),
        "{md}"
    );
    assert!(md.contains("| unpriced |"), "{md}");
}
#[tokio::test]
async fn run_with_stop_after_s1_writes_no_files() {
    let dir = setup_repo();
    let paths = out_paths(&dir.path().join("None"));
    let client: Arc<dyn LlmClient> = Arc::new(RoutedClient {
        router: Box::new(|system| {
            Ok(route(
                system,
                &[(
                    "security-focused codebase mapper",
                    r#"{"language":"python","modules":[],"entry_points":[],"unsafe_sinks":[],"call_graph":{},"notes":""}"#,
                )],
            ))
        }),
    });
    let summary = run(
        fast_input(dir.path()),
        fast_config(),
        Some(StopAfter::S1),
        &paths,
        client,
        Arc::new(NoTools),
        None,
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(summary.stopped_after, Some(StopAfter::S1));
    assert!(summary.markdown_path.is_none());
    assert!(summary.sarif_path.is_none());
}
#[tokio::test]
async fn run_propagates_a_hard_stage_failure_as_err() {
    let dir = setup_repo();
    let paths = out_paths(&dir.path().join("None"));
    let client: Arc<dyn LlmClient> = Arc::new(RoutedClient {
        router: Box::new(|_| {
            Err(LlmError::InvalidRequest {
                message: "bad request".to_string(),
            })
        }),
    });
    let result = run(
        fast_input(dir.path()),
        fast_config(),
        None,
        &paths,
        client,
        Arc::new(NoTools),
        None,
        None,
        None,
    )
    .await;
    assert!(result.is_err());
}
#[tokio::test]
async fn run_propagates_a_write_outputs_failure() {
    let dir = setup_repo();
    let paths = out_paths(&dir.path().join("out"));
    std::fs::create_dir_all(&paths.markdown).unwrap();

    let result = run(
        fast_input(dir.path()),
        fast_config(),
        None,
        &paths,
        empty_scan_client(),
        Arc::new(NoTools),
        None,
        None,
        None,
    )
    .await;

    assert!(result.is_err());
}
#[cfg(unix)]
#[tokio::test]
async fn run_refuses_an_output_directory_it_cannot_create_before_scanning() {
    let dir = setup_repo();
    let unwritable = dir.path().join("locked");
    std::fs::write(&unwritable, "not a directory").unwrap();
    let paths = out_paths(&unwritable.join("nested"));

    let result = run(
        fast_input(dir.path()),
        fast_config(),
        None,
        &paths,
        empty_scan_client(),
        Arc::new(NoTools),
        None,
        None,
        None,
    )
    .await;

    let err = result.unwrap_err();
    assert!(err.contains("cannot create output directory"), "{err}");
}
#[tokio::test]
async fn run_propagates_a_write_findings_json_failure() {
    let dir = git_repo();
    let paths = out_paths(&dir.path().join("out"));
    std::fs::create_dir_all(&paths.findings_json).unwrap();

    let result = run(
        fast_input(dir.path()),
        fast_config(),
        None,
        &paths,
        empty_scan_client(),
        Arc::new(NoTools),
        None,
        None,
        None,
    )
    .await;

    assert!(result.is_err());
}
#[tokio::test]
async fn run_propagates_a_write_remediation_json_failure() {
    let dir = git_repo();
    let elsewhere = tempfile::tempdir().unwrap();
    let unwritable = elsewhere.path().join("locked");
    std::fs::write(&unwritable, "not a directory").unwrap();
    let paths = out_paths(&dir.path().join("out"));
    let out_json = unwritable.join("nested/remediation.json");
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
        tools: Arc::new(NoTools),
        out_json: Some(out_json),
        checkpoint: None,
        worktree: None,
    };

    let result = run(
        fast_input(dir.path()),
        fast_config(),
        None,
        &paths,
        empty_scan_client(),
        Arc::new(NoTools),
        None,
        Some(remediate),
        None,
    )
    .await;

    assert!(result.is_err());
}
#[test]
fn scan_summary_display_reports_a_refused_remediation() {
    let s = ScanSummary {
        provider_publication: None,
        gc: None,
        cost: None,
        findings: 1,
        markdown_path: None,
        sarif_path: None,
        csv_path: None,
        findings_json_path: None,
        stopped_after: None,
        github_sync: None,
        remediation: Some(RemediationSummary {
            validation_failures: 0,
            refused: Some("HEAD moved".to_string()),
            processed: 0,
            failed: 0,
            validated: None,
            ..Default::default()
        }),
        remediation_patch: None,
        baseline: None,
        batch: None,
        estimate: None,
        doctor: None,
        setup: None,
        augmented: None,
    };
    assert!(s.to_string().contains("Remediation refused: HEAD moved"));
}
#[test]
fn scan_summary_display_reports_processed_and_failed_remediation_counts() {
    let s = ScanSummary {
        provider_publication: None,
        gc: None,
        cost: None,
        findings: 1,
        markdown_path: None,
        sarif_path: None,
        csv_path: None,
        findings_json_path: None,
        stopped_after: None,
        github_sync: None,
        remediation: Some(RemediationSummary {
            validation_failures: 0,
            refused: None,
            processed: 2,
            failed: 1,
            validated: None,
            ..Default::default()
        }),
        remediation_patch: None,
        baseline: None,
        batch: None,
        estimate: None,
        doctor: None,
        setup: None,
        augmented: None,
    };
    assert!(s
        .to_string()
        .contains("Remediation: 2 processed, 1 failed. Outcome: 0 fixed, 0 not fixed."));
}
#[test]
fn scan_summary_display_reports_a_validation_tally_when_validation_ran() {
    let s = ScanSummary {
        provider_publication: None,
        gc: None,
        cost: None,
        findings: 1,
        markdown_path: None,
        sarif_path: None,
        csv_path: None,
        findings_json_path: None,
        stopped_after: None,
        github_sync: None,
        remediation: Some(RemediationSummary {
            validation_failures: 0,
            refused: None,
            processed: 4,
            failed: 0,
            validated: Some(ValidationTally {
                fixed: 1,
                partially_fixed: 2,
                not_fixed: 1,
                unverifiable: 0,
            }),
            ..Default::default()
        }),
        remediation_patch: None,
        baseline: None,
        batch: None,
        estimate: None,
        doctor: None,
        setup: None,
        augmented: None,
    };
    assert!(s
        .to_string()
        .contains("Validation: 1 fixed, 2 partially fixed, 1 not fixed, 0 unverifiable."));
}
#[test]
fn scan_summary_display_reports_validation_failures_when_present() {
    let s = ScanSummary {
        provider_publication: None,
        gc: None,
        cost: None,
        findings: 1,
        markdown_path: None,
        sarif_path: None,
        csv_path: None,
        findings_json_path: None,
        stopped_after: None,
        github_sync: None,
        remediation: Some(RemediationSummary {
            validation_failures: 2,
            refused: None,
            processed: 3,
            failed: 0,
            validated: Some(ValidationTally {
                fixed: 1,
                partially_fixed: 0,
                not_fixed: 0,
                unverifiable: 0,
            }),
            ..Default::default()
        }),
        remediation_patch: None,
        baseline: None,
        batch: None,
        estimate: None,
        doctor: None,
        setup: None,
        augmented: None,
    };
    assert!(s.to_string().contains("(2 validation error(s).)"));
}
#[test]
fn scan_summary_display_omits_the_validation_failures_note_when_there_are_none() {
    let s = ScanSummary {
        provider_publication: None,
        gc: None,
        cost: None,
        findings: 1,
        markdown_path: None,
        sarif_path: None,
        csv_path: None,
        findings_json_path: None,
        stopped_after: None,
        github_sync: None,
        remediation: Some(RemediationSummary {
            validation_failures: 0,
            refused: None,
            processed: 1,
            failed: 0,
            validated: Some(ValidationTally {
                fixed: 1,
                partially_fixed: 0,
                not_fixed: 0,
                unverifiable: 0,
            }),
            ..Default::default()
        }),
        remediation_patch: None,
        baseline: None,
        batch: None,
        estimate: None,
        doctor: None,
        setup: None,
        augmented: None,
    };
    assert!(!s.to_string().contains("validation error"));
}
#[test]
fn scan_summary_display_omits_the_validation_line_when_validation_did_not_run() {
    let s = ScanSummary {
        provider_publication: None,
        gc: None,
        cost: None,
        findings: 1,
        markdown_path: None,
        sarif_path: None,
        csv_path: None,
        findings_json_path: None,
        stopped_after: None,
        github_sync: None,
        remediation: Some(RemediationSummary {
            validation_failures: 0,
            refused: None,
            processed: 1,
            failed: 0,
            validated: None,
            ..Default::default()
        }),
        remediation_patch: None,
        baseline: None,
        batch: None,
        estimate: None,
        doctor: None,
        setup: None,
        augmented: None,
    };
    assert!(!s.to_string().contains("Validation:"));
}
#[test]
fn scan_summary_display_names_the_exported_patch() {
    let mut s = base_summary();
    s.remediation_patch = Some(PathBuf::from("/r/security-scan/remediation.patch"));
    let rendered = s.to_string();
    assert!(rendered.contains("remediation.patch"), "{rendered}");
    assert!(rendered.contains("git apply"), "{rendered}");
}
#[test]
fn scan_summary_display_reports_the_baseline_counts() {
    let mut s = base_summary();
    s.baseline = Some(BaselineTally {
        new: 2,
        unchanged: 5,
        resolved: 1,
    });
    assert!(s
        .to_string()
        .contains("Baseline: 2 new, 5 unchanged, 1 resolved."));
}
#[tokio::test]
async fn run_annotates_both_reports_against_a_baseline() {
    let dir = git_repo();
    let paths = out_paths(&dir.path().join("out"));

    let baseline_path = dir.path().join("baseline.json");
    std::fs::write(
        &baseline_path,
        serde_json::json!({
            "commit_sha": "abc",
            "findings": [{
                "chunk_id": "c0", "file": "old.py", "line_start": 1, "line_end": 1,
                "vuln_class": "other", "title": "Gone finding", "description": "d",
                "code_snippet": "x", "confidence": 0.5, "votes": 1,
            }],
        })
        .to_string(),
    )
    .unwrap();
    let baseline = BaselineRun {
        path: baseline_path.clone(),
        baseline: baseline::load(&baseline_path, dir.path()).unwrap(),
    };

    let summary = run(
        fast_input(dir.path()),
        fast_config_no_semantic_dedup(),
        None,
        &paths,
        one_finding_client(),
        Arc::new(NoTools),
        None,
        None,
        Some(baseline),
    )
    .await
    .unwrap();

    let tally = summary.baseline.expect("--baseline was given");
    assert_eq!(tally.new, 1);
    assert_eq!(tally.unchanged, 0);
    assert_eq!(tally.resolved, 1);

    let markdown = std::fs::read_to_string(&paths.markdown).unwrap();
    assert!(markdown.contains("## Baseline Comparison"), "{markdown}");
    assert!(markdown.contains("### New findings"), "{markdown}");
    assert!(markdown.contains("Gone finding"), "{markdown}");

    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&paths.sarif).unwrap()).unwrap();
    assert_eq!(doc["runs"][0]["results"][0]["baselineState"], "new");
    let results = doc["runs"][0]["results"].as_array().unwrap();
    assert_eq!(results.len(), 2);
    assert_eq!(results[1]["baselineState"], "absent");
    assert_eq!(results[1]["message"]["text"], "Gone finding");
    assert_eq!(results[1]["ruleId"], "other");
}
#[tokio::test]
async fn a_baseline_matching_this_scan_reports_everything_unchanged() {
    let dir = git_repo();
    let paths = out_paths(&dir.path().join("out"));

    let findings_json = paths.findings_json.clone();
    run(
        fast_input(dir.path()),
        fast_config_no_semantic_dedup(),
        None,
        &paths,
        one_finding_client(),
        Arc::new(NoTools),
        None,
        None,
        None,
    )
    .await
    .unwrap();
    assert!(
        findings_json.is_file(),
        "the export needs a git sha, which `git_repo()` provides"
    );

    let baseline = BaselineRun {
        path: findings_json.clone(),
        baseline: baseline::load(&findings_json, dir.path()).unwrap(),
    };
    let summary = run(
        fast_input(dir.path()),
        fast_config_no_semantic_dedup(),
        None,
        &paths,
        one_finding_client(),
        Arc::new(NoTools),
        None,
        None,
        Some(baseline),
    )
    .await
    .unwrap();
    let tally = summary.baseline.unwrap();
    assert_eq!((tally.new, tally.unchanged, tally.resolved), (0, 1, 0));
}
#[test]
fn gc_summary_display_evict_found() {
    let gc = GcSummary::Evicted {
        path: PathBuf::from("/repo"),
        run_id: "abc123".to_string(),
        found: true,
        dry_run: false,
    };
    assert_eq!(gc.to_string(), "gc: evicted run abc123 for /repo");
}
#[test]
fn gc_summary_display_evict_not_found() {
    let gc = GcSummary::Evicted {
        path: PathBuf::from("/repo"),
        run_id: "abc123".to_string(),
        found: false,
        dry_run: false,
    };
    assert_eq!(gc.to_string(), "gc: no run found for /repo (run_id abc123)");
}
#[test]
fn gc_summary_display_pruned_lists_deleted_runs() {
    let gc = GcSummary::Pruned {
        db_path: PathBuf::from("/state/bc-sast.db"),
        kept: 2,
        deleted: vec!["run1".to_string(), "run2".to_string()],
        dry_run: false,
    };
    assert_eq!(
        gc.to_string(),
        "gc: /state/bc-sast.db — kept 2 run(s), deleted 2\n    - run1\n    - run2"
    );
}
#[test]
fn gc_summary_display_pruned_dry_run_with_no_deletions() {
    let gc = GcSummary::Pruned {
        db_path: PathBuf::from("/state/bc-sast.db"),
        kept: 5,
        deleted: vec![],
        dry_run: true,
    };
    assert_eq!(
        gc.to_string(),
        "gc: /state/bc-sast.db — [dry-run] kept 5 run(s), would delete 0"
    );
}
