use super::*;
#[tokio::test]
async fn diff_scope_excludes_off_diff_findings_end_to_end_and_is_a_no_op_when_unset() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("changed.py"),
        "def handler(request):\n    q = request.GET['q']\n    cur.execute(q)\n",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("unchanged.py"),
        "def other(request):\n    q2 = request.GET['q2']\n    cur.execute(q2)\n",
    )
    .unwrap();

    let client = client_with(full_table(
        &s4_finding_on("unchanged.py"),
        &s6_true_positive_text(),
        &s8_ranked_json(),
    ));

    let mut input_on = scan_input(dir.path());
    input_on.diff_scope_active = true;
    input_on.changed_files = BTreeMap::from([("changed.py".to_string(), BTreeSet::from([1i64]))]);
    let outcome_on = run_scan(
        client.clone(),
        Arc::new(NoTools),
        input_on,
        scan_config(),
        None,
    )
    .await
    .unwrap();
    let report_on = outcome_on.report.unwrap();
    assert!(
        report_on.findings.is_empty(),
        "an off-diff finding must never reach the report when diff-scope is active"
    );

    let outcome_off = run_scan(
        client,
        Arc::new(NoTools),
        scan_input(dir.path()),
        scan_config(),
        None,
    )
    .await
    .unwrap();
    let report_off = outcome_off.report.unwrap();
    assert_eq!(report_off.findings.len(), 1);
    assert_eq!(report_off.findings[0].finding.file, "unchanged.py");
}
#[tokio::test]
async fn diff_scope_with_an_empty_changed_set_scans_nothing_and_says_so_in_the_report() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("changed.py"),
        "def handler(request):\n    q = request.GET['q']\n    cur.execute(q)\n",
    )
    .unwrap();

    let client = client_with(full_table(
        &s4_finding_on("changed.py"),
        &s6_true_positive_text(),
        &s8_ranked_json(),
    ));

    let mut input = scan_input(dir.path());
    input.diff_scope_active = true;
    assert!(input.changed_files.is_empty());
    let outcome = run_scan(client, Arc::new(NoTools), input, scan_config(), None)
        .await
        .unwrap();

    let report = outcome.report.unwrap();
    assert!(
        report.findings.is_empty(),
        "a diff-scoped scan of zero files must analyze nothing, not everything"
    );
    let metrics = report.metrics.unwrap();
    assert!(metrics.diff_scope_active);
    assert_eq!(metrics.changed_files_count, 0);
    assert_eq!(metrics.analyzed_files_unique, 0);
    assert!(outcome
        .markdown
        .unwrap()
        .contains("- Scope: PR diff (0 of "));
}
#[tokio::test]
async fn compliance_annotate_mode_tags_matching_findings_and_is_a_no_op_when_unset() {
    let dir = setup_repo();

    let mut input_with = scan_input(dir.path());
    input_with.compliance = vec![compliance_policy(
        "TEST-FRAMEWORK",
        "REQ-1",
        appsec_compliance::ScopeMode::Annotate,
        &["injection"],
    )];
    let outcome_with = run_scan(
        one_finding_client(),
        Arc::new(NoTools),
        input_with,
        scan_config(),
        None,
    )
    .await
    .unwrap();
    let report_with = outcome_with.report.unwrap();
    assert_eq!(report_with.findings.len(), 1);
    assert_eq!(
        report_with.findings[0].finding.compliance_requirements,
        vec!["REQ-1".to_string()]
    );

    let outcome_without = run_scan(
        one_finding_client(),
        Arc::new(NoTools),
        scan_input(dir.path()),
        scan_config(),
        None,
    )
    .await
    .unwrap();
    let report_without = outcome_without.report.unwrap();
    assert_eq!(report_without.findings.len(), 1);
    assert!(report_without.findings[0]
        .finding
        .compliance_requirements
        .is_empty());
}
#[tokio::test]
async fn compliance_filter_mode_drops_non_matching_findings_out_of_the_report() {
    let dir = setup_repo();
    let mut input = scan_input(dir.path());
    input.compliance = vec![compliance_policy(
        "TEST-FRAMEWORK",
        "REQ-1",
        appsec_compliance::ScopeMode::Filter,
        &["xss"],
    )];
    let outcome = run_scan(
        one_finding_client(),
        Arc::new(NoTools),
        input,
        scan_config(),
        None,
    )
    .await
    .unwrap();
    let report = outcome.report.unwrap();
    assert!(
        report.findings.is_empty(),
        "a finding matching no requirement must be dropped in Filter mode"
    );
    assert_eq!(report.dropped.len(), 1);
    assert_eq!(report.dropped[0].reason, DropReason::Excluded);
}
#[tokio::test]
async fn compliance_combines_a_preset_and_a_custom_policy_with_or_across_filters() {
    let dir = setup_repo();
    let mut input = scan_input(dir.path());
    input.compliance = vec![
        compliance_policy(
            "ASVS",
            "V5.3.2",
            appsec_compliance::ScopeMode::Filter,
            &["xss"],
        ),
        compliance_policy(
            "Custom-PCI",
            "6.2.4",
            appsec_compliance::ScopeMode::Filter,
            &["injection"],
        ),
    ];
    let outcome = run_scan(
        one_finding_client(),
        Arc::new(NoTools),
        input,
        scan_config(),
        None,
    )
    .await
    .unwrap();
    let report = outcome.report.unwrap();
    assert_eq!(report.findings.len(), 1);
    assert_eq!(
        report.findings[0].finding.compliance_requirements,
        vec!["6.2.4".to_string()]
    );
    assert!(report.dropped.is_empty());
}
