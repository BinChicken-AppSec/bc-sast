use super::*;
#[test]
fn write_findings_json_is_a_no_op_without_a_report() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("findings.json");
    assert!(!write_findings_json(&path, None).unwrap());
    assert!(!path.exists());
}
#[test]
fn write_findings_json_is_a_no_op_without_a_git_sha() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("findings.json");
    let report = sample_report(None, vec![sample_finding()]);
    assert!(!write_findings_json(&path, Some(&report)).unwrap());
    assert!(!path.exists());
}
#[test]
fn write_findings_json_writes_findings_and_commit_sha() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nested/findings.json");
    let report = sample_report(Some("deadbeef"), vec![sample_finding()]);
    assert!(write_findings_json(&path, Some(&report)).unwrap());

    let bytes = std::fs::read(&path).unwrap();
    let export: FindingsExport = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(export.commit_sha, "deadbeef");
    assert_eq!(export.findings.len(), 1);
    assert_eq!(export.findings[0].file, "app.py");
}
#[cfg(unix)]
#[test]
fn write_findings_json_propagates_an_io_error() {
    let dir = tempfile::tempdir().unwrap();
    let unwritable = dir.path().join("locked");
    std::fs::write(&unwritable, "not a directory").unwrap();
    let path = unwritable.join("nested/findings.json");
    let report = sample_report(Some("sha"), vec![sample_finding()]);
    let result = write_findings_json(&path, Some(&report));
    assert!(result.is_err());
}
#[tokio::test]
async fn post_comments_only_propagates_a_missing_findings_file() {
    let server = wiremock::MockServer::start().await;
    let github = github_client_for(&server);
    let result = post_comments_only(&github, Path::new("/does/not/exist.json"), None).await;
    assert!(result.is_err());
}
#[tokio::test]
async fn post_comments_only_propagates_malformed_json() {
    let server = wiremock::MockServer::start().await;
    let github = github_client_for(&server);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("findings.json");
    std::fs::write(&path, "not json").unwrap();
    let result = post_comments_only(&github, &path, None).await;
    assert!(result.is_err());
}
#[tokio::test]
async fn post_comments_only_posts_findings_and_reports_success() {
    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/repos/acme/widgets/pulls/1"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_string(""))
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
    let path = write_export(
        dir.path(),
        &FindingsExport {
            commit_sha: "sha".to_string(),
            findings: vec![sample_finding()],
        },
    );

    let github = github_client_for(&server);
    let summary = post_comments_only(&github, &path, None).await.unwrap();
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
async fn post_comments_only_reports_a_github_sync_failure_without_erroring() {
    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/repos/acme/widgets/pulls/1"))
        .respond_with(wiremock::ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let path = write_export(
        dir.path(),
        &FindingsExport {
            commit_sha: "sha".to_string(),
            findings: Vec::new(),
        },
    );

    let github = github_client_for(&server);
    let summary = post_comments_only(&github, &path, None).await.unwrap();
    assert_github_sync_failed(&summary);
}
#[test]
fn write_outputs_writes_only_the_files_the_scan_actually_reached() {
    let dir = tempfile::tempdir().unwrap();
    let md_path = dir.path().join("out/report.md");
    let sarif_path = dir.path().join("out/report.sarif");
    let csv_path = dir.path().join("out/report.csv");
    let outcome = ScanOutcome {
        provider_writeback_plan: None,
        stopped_after: None,
        report: None,
        markdown: Some("# report".to_string()),
        sarif: None,
    };
    write_outputs(&outcome, &md_path, &sarif_path, &csv_path).unwrap();
    assert!(md_path.is_file());
    assert!(!sarif_path.is_file());
    assert!(!csv_path.is_file());
}
#[test]
fn write_outputs_writes_both_when_both_are_present() {
    let dir = tempfile::tempdir().unwrap();
    let md_path = dir.path().join("report.md");
    let sarif_path = dir.path().join("report.sarif");
    let csv_path = dir.path().join("report.csv");
    let outcome = ScanOutcome {
        provider_writeback_plan: None,
        stopped_after: None,
        report: None,
        markdown: Some("# report".to_string()),
        sarif: Some("{}".to_string()),
    };
    write_outputs(&outcome, &md_path, &sarif_path, &csv_path).unwrap();
    assert!(md_path.is_file());
    assert!(sarif_path.is_file());
}
#[test]
fn write_outputs_writes_the_csv_when_the_report_is_present() {
    let dir = tempfile::tempdir().unwrap();
    let md_path = dir.path().join("report.md");
    let sarif_path = dir.path().join("report.sarif");
    let csv_path = dir.path().join("report.csv");
    let outcome = ScanOutcome {
        provider_writeback_plan: None,
        stopped_after: None,
        report: Some(appsec_model::FinalReport {
            repo_identity: None,
            provider_ledger: Default::default(),
            repo_root: "/repo".to_string(),
            repo_name: None,
            git_sha: None,
            findings: Vec::new(),
            chains: Vec::new(),
            dropped: Vec::new(),
            raw_findings_count: 0,
            metrics: None,
            threat_model: None,
            app_profile: None,
            summary: "clean scan".to_string(),
            degraded: false,
            degraded_reason: String::new(),
            unreachable_files: Vec::new(),
        }),
        markdown: None,
        sarif: None,
    };
    write_outputs(&outcome, &md_path, &sarif_path, &csv_path).unwrap();
    assert!(csv_path.is_file());
    assert!(!md_path.is_file());
    assert!(!sarif_path.is_file());
}
#[test]
fn write_outputs_fails_when_the_csv_write_itself_fails() {
    let dir = tempfile::tempdir().unwrap();
    let md_path = dir.path().join("report.md");
    let sarif_path = dir.path().join("report.sarif");
    let csv_path = dir.path().join("report.csv");
    std::fs::create_dir(&csv_path).unwrap();
    let outcome = ScanOutcome {
        provider_writeback_plan: None,
        stopped_after: None,
        report: Some(appsec_model::FinalReport {
            repo_identity: None,
            provider_ledger: Default::default(),
            repo_root: "/repo".to_string(),
            repo_name: None,
            git_sha: None,
            findings: Vec::new(),
            chains: Vec::new(),
            dropped: Vec::new(),
            raw_findings_count: 0,
            metrics: None,
            threat_model: None,
            app_profile: None,
            summary: "clean scan".to_string(),
            degraded: false,
            degraded_reason: String::new(),
            unreachable_files: Vec::new(),
        }),
        markdown: None,
        sarif: None,
    };
    assert!(write_outputs(&outcome, &md_path, &sarif_path, &csv_path).is_err());
}
#[test]
fn write_outputs_fails_when_the_markdown_write_itself_fails() {
    let dir = tempfile::tempdir().unwrap();
    let md_path = dir.path().join("report.md");
    std::fs::create_dir(&md_path).unwrap();
    let sarif_path = dir.path().join("report.sarif");
    let csv_path = dir.path().join("report.csv");
    let outcome = ScanOutcome {
        provider_writeback_plan: None,
        stopped_after: None,
        report: None,
        markdown: Some("# report".to_string()),
        sarif: Some("{}".to_string()),
    };
    assert!(write_outputs(&outcome, &md_path, &sarif_path, &csv_path).is_err());
}
#[test]
fn write_outputs_fails_when_the_sarif_parent_dir_cannot_be_created() {
    let dir = tempfile::tempdir().unwrap();
    let md_path = dir.path().join("report.md");
    let blocker = dir.path().join("blocker");
    std::fs::write(&blocker, b"not a directory").unwrap();
    let sarif_path = blocker.join("nested/report.sarif");
    let csv_path = dir.path().join("report.csv");
    let outcome = ScanOutcome {
        provider_writeback_plan: None,
        stopped_after: None,
        report: None,
        markdown: Some("# report".to_string()),
        sarif: Some("{}".to_string()),
    };
    assert!(write_outputs(&outcome, &md_path, &sarif_path, &csv_path).is_err());
    assert!(md_path.is_file());
}
#[test]
fn write_outputs_fails_when_the_sarif_write_itself_fails() {
    let dir = tempfile::tempdir().unwrap();
    let md_path = dir.path().join("report.md");
    let sarif_path = dir.path().join("report.sarif");
    std::fs::create_dir(&sarif_path).unwrap();
    let csv_path = dir.path().join("report.csv");
    let outcome = ScanOutcome {
        provider_writeback_plan: None,
        stopped_after: None,
        report: None,
        markdown: Some("# report".to_string()),
        sarif: Some("{}".to_string()),
    };
    assert!(write_outputs(&outcome, &md_path, &sarif_path, &csv_path).is_err());
    assert!(md_path.is_file());
}
#[test]
fn augment_prior_reports_writes_both_artifacts_in_place() {
    let dir = tempfile::tempdir().unwrap();
    let finding = sample_finding();
    let id = appsec_sarif::finding_id(&finding);
    let report = sample_report(None, vec![finding]);
    let (md_path, sarif_path) = write_prior_reports(dir.path(), &report);
    let outcome = validated_outcome(&id);

    let augmented = augment_prior_reports(&md_path, &sarif_path, &report, &outcome).unwrap();
    assert_eq!(augmented.markdown, AugmentOutcome::Written);
    assert_eq!(augmented.sarif, AugmentOutcome::Written);

    let md = std::fs::read_to_string(&md_path).unwrap();
    assert!(md.contains("#### Remediation"), "{md}");
    assert!(md.contains("#### Validation"), "{md}");
    assert!(md.contains("## Remediation Summary"), "{md}");
    let sarif: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&sarif_path).unwrap()).unwrap();
    let props = &sarif["runs"][0]["results"][0]["properties"];
    assert_eq!(props["remediationStatus"], "Fixed");
    assert_eq!(props["validationStatus"], "Fixed");
    assert_eq!(props["validationScore"], 0.91);
    assert_eq!(props["mergeReadiness"], "Ready");
}
#[test]
fn augment_prior_sarif_preserves_run_properties_the_export_cannot_carry() {
    let dir = tempfile::tempdir().unwrap();
    let finding = sample_finding();
    let id = appsec_sarif::finding_id(&finding);
    let mut prior = sample_report(None, vec![finding.clone()]);
    prior.app_profile = Some(appsec_model::AppProfile {
        exposure: String::new(),
        reaches: Vec::new(),
        reached_by: Vec::new(),
        application_id: "APP-42".to_string(),
        name: "Payments".to_string(),
        externally_facing: true,
        pci_scoped: false,
        processes_pan: false,
        pii: false,
        source: "cmdb".to_string(),
    });
    let (_, sarif_path) = write_prior_reports(dir.path(), &prior);
    let reconstructed = sample_report(None, vec![finding]);
    let md_path = dir.path().join("no-such-report.md");

    augment_prior_reports(
        &md_path,
        &sarif_path,
        &reconstructed,
        &validated_outcome(&id),
    )
    .unwrap();
    let sarif: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&sarif_path).unwrap()).unwrap();
    assert_eq!(sarif["runs"][0]["properties"]["applicationId"], "APP-42");
    assert_eq!(
        sarif["runs"][0]["results"][0]["properties"]["remediationStatus"],
        "Fixed"
    );
}
#[test]
fn augment_prior_sarif_matches_by_fingerprint_not_position() {
    let finding = sample_finding();
    let id = appsec_sarif::finding_id(&finding);
    let report = sample_report(None, vec![finding]);
    let mut doc = appsec_sarif::build_sarif(&report, "test");
    let resolved = doc.runs[0].results[0].clone().with_baseline_state("absent");
    doc.runs[0].results.insert(0, resolved);
    doc.runs[0].results[0].partial_fingerprints.insert(
        appsec_sarif::FINGERPRINT_KEY.to_string(),
        "other".to_string(),
    );

    let augmented = augment_prior_sarif(
        &serde_json::to_string_pretty(&doc).unwrap(),
        &validated_outcome(&id),
    )
    .expect("one result matched");
    let parsed: serde_json::Value = serde_json::from_str(&augmented).unwrap();
    assert!(parsed["runs"][0]["results"][0]["properties"]["remediationStatus"].is_null());
    assert_eq!(
        parsed["runs"][0]["results"][1]["properties"]["remediationStatus"],
        "Fixed"
    );
}
#[test]
fn augment_prior_markdown_refuses_an_already_augmented_report() {
    let dir = tempfile::tempdir().unwrap();
    let finding = sample_finding();
    let id = appsec_sarif::finding_id(&finding);
    let report = sample_report(None, vec![finding]);
    let (md_path, sarif_path) = write_prior_reports(dir.path(), &report);
    let outcome = validated_outcome(&id);

    augment_prior_reports(&md_path, &sarif_path, &report, &outcome).unwrap();
    let once = std::fs::read_to_string(&md_path).unwrap();
    let again = augment_prior_reports(&md_path, &sarif_path, &report, &outcome).unwrap();

    assert_eq!(again.markdown, AugmentOutcome::Unchanged);
    assert_eq!(again.sarif, AugmentOutcome::Written);
    assert_eq!(std::fs::read_to_string(&md_path).unwrap(), once);
    assert_eq!(once.matches("## Remediation Summary").count(), 1);
}
#[test]
fn augment_prior_markdown_reports_a_fail_closed_augmenter_as_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let finding = sample_finding();
    let id = appsec_sarif::finding_id(&finding);
    let report = sample_report(None, vec![finding]);
    let md_path = dir.path().join("report.md");
    std::fs::write(&md_path, "# Some other report\n\nnothing here\n").unwrap();
    let sarif_path = dir.path().join("report.sarif");

    let augmented =
        augment_prior_reports(&md_path, &sarif_path, &report, &validated_outcome(&id)).unwrap();
    assert_eq!(augmented.markdown, AugmentOutcome::Unchanged);
    assert_eq!(augmented.sarif, AugmentOutcome::NotFound);
    assert_eq!(
        std::fs::read_to_string(&md_path).unwrap(),
        "# Some other report\n\nnothing here\n"
    );
}
#[test]
fn augment_prior_reports_reports_missing_artifacts_rather_than_creating_them() {
    let dir = tempfile::tempdir().unwrap();
    let finding = sample_finding();
    let id = appsec_sarif::finding_id(&finding);
    let report = sample_report(None, vec![finding]);
    let md_path = dir.path().join("report.md");
    let sarif_path = dir.path().join("report.sarif");

    let augmented =
        augment_prior_reports(&md_path, &sarif_path, &report, &validated_outcome(&id)).unwrap();
    assert_eq!(augmented.markdown, AugmentOutcome::NotFound);
    assert_eq!(augmented.sarif, AugmentOutcome::NotFound);
    assert!(!md_path.exists(), "nothing is created that wasn't there");
    assert!(!sarif_path.exists());
}
#[test]
fn augment_prior_reports_is_a_no_op_when_nothing_was_remediated() {
    let dir = tempfile::tempdir().unwrap();
    let report = sample_report(None, vec![sample_finding()]);
    let (md_path, sarif_path) = write_prior_reports(dir.path(), &report);
    let before_md = std::fs::read_to_string(&md_path).unwrap();
    let before_sarif = std::fs::read_to_string(&sarif_path).unwrap();
    let outcome = appsec_orchestrator::RemediateOutcome {
        refused: Some("stale".to_string()),
        outcomes: Vec::new(),
        validations: Vec::new(),
        validation_failures: 0,
    };

    let augmented = augment_prior_reports(&md_path, &sarif_path, &report, &outcome).unwrap();
    assert_eq!(augmented.markdown, AugmentOutcome::Unchanged);
    assert_eq!(augmented.sarif, AugmentOutcome::Unchanged);
    assert_eq!(std::fs::read_to_string(&md_path).unwrap(), before_md);
    assert_eq!(std::fs::read_to_string(&sarif_path).unwrap(), before_sarif);
}
#[test]
fn augment_prior_sarif_leaves_an_unparseable_document_alone() {
    let finding = sample_finding();
    let id = appsec_sarif::finding_id(&finding);
    assert!(augment_prior_sarif("{ not sarif", &validated_outcome(&id)).is_none());
}
#[test]
fn augmented_reports_display_names_every_outcome() {
    let mut s = base_summary();
    s.augmented = Some(AugmentedReports {
        markdown_path: PathBuf::from("/r/security-scan/report.md"),
        markdown: AugmentOutcome::Written,
        sarif_path: PathBuf::from("/r/security-scan/report.sarif"),
        sarif: AugmentOutcome::NotFound,
    });
    let rendered = s.to_string();
    assert!(
        rendered.contains("augmented /r/security-scan/report.md"),
        "{rendered}"
    );
    assert!(
        rendered.contains("no prior report at /r/security-scan/report.sarif to augment"),
        "{rendered}"
    );

    s.augmented = Some(AugmentedReports {
        markdown_path: PathBuf::from("/r/report.md"),
        markdown: AugmentOutcome::Unchanged,
        sarif_path: PathBuf::from("/r/report.sarif"),
        sarif: AugmentOutcome::Unchanged,
    });
    assert!(s.to_string().contains("left /r/report.md unchanged"), "{s}");
}
#[test]
fn apply_remediation_status_leaves_a_document_alone_without_records() {
    let report = sample_report(None, vec![sample_finding()]);
    let mut doc = appsec_sarif::build_sarif(&report, "test");
    let outcome = appsec_orchestrator::RemediateOutcome {
        refused: None,
        outcomes: vec![appsec_stage_s10::RemediationOutcome::Failed {
            finding_index: 1,
            error: "boom".to_string(),
        }],
        validations: Vec::new(),
        validation_failures: 0,
    };
    apply_remediation_status(&mut doc, &report, &outcome);
    assert!(doc.runs[0].results[0]
        .properties
        .remediation_status
        .is_none());
}
