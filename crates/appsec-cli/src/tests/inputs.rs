use super::*;
#[test]
fn build_semgrep_live_config_returns_none_when_args_are_absent() {
    assert!(build_semgrep_live_config(&cli(Path::new("/repo"))).is_none());
}
#[test]
fn build_semgrep_live_config_returns_none_when_only_some_args_are_present() {
    let mut c = cli(Path::new("/repo"));
    c.semgrep_token = Some("tok".to_string());
    c.semgrep_deployment_slug = Some("deploy".to_string());
    assert!(build_semgrep_live_config(&c).is_none());
}
#[test]
fn build_semgrep_live_config_builds_a_config_when_all_required_args_are_present() {
    let mut c = cli(Path::new("/repo"));
    c.semgrep_token = Some("tok".to_string());
    c.semgrep_deployment_slug = Some("deploy".to_string());
    c.semgrep_repo = Some("org/repo".to_string());
    let config = build_semgrep_live_config(&c).unwrap();
    assert_eq!(config.token, "tok");
    assert_eq!(config.branch, None);
}
#[test]
fn build_semgrep_live_config_applies_optional_branch_and_base_url_overrides() {
    let mut c = cli(Path::new("/repo"));
    c.semgrep_token = Some("tok".to_string());
    c.semgrep_deployment_slug = Some("deploy".to_string());
    c.semgrep_repo = Some("org/repo".to_string());
    c.semgrep_branch = Some("main".to_string());
    c.semgrep_base_url = Some("https://example.test".to_string());
    let config = build_semgrep_live_config(&c).unwrap();
    assert_eq!(config.branch, Some("main".to_string()));
    assert_eq!(config.base_url, "https://example.test");
}
#[test]
fn build_snyk_live_config_returns_none_when_args_are_absent() {
    assert!(build_snyk_live_config(&cli(Path::new("/repo"))).is_none());
}
#[test]
fn build_snyk_live_config_returns_none_when_only_some_args_are_present() {
    let mut c = cli(Path::new("/repo"));
    c.snyk_token = Some("tok".to_string());
    assert!(build_snyk_live_config(&c).is_none());
}
#[test]
fn build_snyk_live_config_builds_a_config_when_all_required_args_are_present() {
    let mut c = cli(Path::new("/repo"));
    c.snyk_token = Some("tok".to_string());
    c.snyk_org_id = Some("org-1".to_string());
    c.snyk_project_id = Some("proj-1".to_string());
    let config = build_snyk_live_config(&c).unwrap();
    assert_eq!(config.org_id, "org-1");
    assert_eq!(config.project_id, "proj-1");
}
#[test]
fn build_sonatype_live_config_returns_none_when_args_are_absent() {
    assert!(build_sonatype_live_config(&cli(Path::new("/repo"))).is_none());
}
#[test]
fn build_sonatype_live_config_returns_none_when_only_some_args_are_present() {
    let mut c = cli(Path::new("/repo"));
    c.sonatype_base_url = Some("https://sonatype.test".to_string());
    c.sonatype_username = Some("user".to_string());
    assert!(build_sonatype_live_config(&c).is_none());
}
#[test]
fn build_sonatype_live_config_builds_a_config_when_all_required_args_are_present() {
    let mut c = cli(Path::new("/repo"));
    c.sonatype_base_url = Some("https://sonatype.test".to_string());
    c.sonatype_username = Some("user".to_string());
    c.sonatype_password = Some("pass".to_string());
    c.sonatype_app_id = Some("my-app".to_string());
    let config = build_sonatype_live_config(&c).unwrap();
    assert_eq!(config.application_public_id, "my-app");
    assert_eq!(config.stage, "build");
}
#[test]
fn build_sonatype_live_config_applies_an_optional_stage_override() {
    let mut c = cli(Path::new("/repo"));
    c.sonatype_base_url = Some("https://sonatype.test".to_string());
    c.sonatype_username = Some("user".to_string());
    c.sonatype_password = Some("pass".to_string());
    c.sonatype_app_id = Some("my-app".to_string());
    c.sonatype_stage = Some("release".to_string());
    let config = build_sonatype_live_config(&c).unwrap();
    assert_eq!(config.stage, "release");
}
#[test]
fn build_aikido_live_config_returns_none_when_args_are_absent() {
    assert!(build_aikido_live_config(&cli(Path::new("/repo"))).is_none());
}
#[test]
fn build_aikido_live_config_returns_none_when_only_some_args_are_present() {
    let mut c = cli(Path::new("/repo"));
    c.aikido_client_id = Some("id".to_string());
    c.aikido_client_secret = Some("secret".to_string());
    assert!(build_aikido_live_config(&c).is_none());
}
#[test]
fn build_aikido_live_config_builds_a_config_when_all_required_args_are_present() {
    let mut c = cli(Path::new("/repo"));
    c.aikido_client_id = Some("id".to_string());
    c.aikido_client_secret = Some("secret".to_string());
    c.aikido_repo_id = Some(42);
    let config = build_aikido_live_config(&c).unwrap();
    assert_eq!(config.code_repo_id, 42);
}
#[test]
fn build_aikido_live_config_applies_an_optional_base_url_override() {
    let mut c = cli(Path::new("/repo"));
    c.aikido_client_id = Some("id".to_string());
    c.aikido_client_secret = Some("secret".to_string());
    c.aikido_repo_id = Some(42);
    c.aikido_base_url = Some("https://example.test".to_string());
    let config = build_aikido_live_config(&c).unwrap();
    assert_eq!(config.base_url, "https://example.test");
}
#[test]
fn build_checkmarx_live_config_returns_none_when_args_are_absent() {
    assert!(build_checkmarx_live_config(&cli(Path::new("/repo"))).is_none());
}
#[test]
fn build_checkmarx_live_config_returns_none_when_only_some_args_are_present() {
    let mut c = cli(Path::new("/repo"));
    c.checkmarx_base_url = Some("https://ast.example.test".to_string());
    c.checkmarx_iam_url = Some("https://iam.example.test".to_string());
    assert!(build_checkmarx_live_config(&c).is_none());
}
#[test]
fn build_checkmarx_live_config_builds_a_config_when_all_required_args_are_present() {
    let mut c = cli(Path::new("/repo"));
    c.checkmarx_base_url = Some("https://ast.example.test".to_string());
    c.checkmarx_iam_url = Some("https://iam.example.test".to_string());
    c.checkmarx_tenant = Some("acme".to_string());
    c.checkmarx_api_key = Some("key".to_string());
    c.checkmarx_project_id = Some("proj-1".to_string());
    let config = build_checkmarx_live_config(&c).unwrap();
    assert_eq!(config.project_id, "proj-1");
    assert_eq!(config.branch, None);
}
#[test]
fn build_checkmarx_live_config_applies_an_optional_branch_filter() {
    let mut c = cli(Path::new("/repo"));
    c.checkmarx_base_url = Some("https://ast.example.test".to_string());
    c.checkmarx_iam_url = Some("https://iam.example.test".to_string());
    c.checkmarx_tenant = Some("acme".to_string());
    c.checkmarx_api_key = Some("key".to_string());
    c.checkmarx_project_id = Some("proj-1".to_string());
    c.checkmarx_branch = Some("main".to_string());
    let config = build_checkmarx_live_config(&c).unwrap();
    assert_eq!(config.branch, Some("main".to_string()));
}
#[test]
fn load_compliance_policies_is_a_no_op_when_no_flags_are_set() {
    let c = cli(Path::new("/repo"));
    assert!(load_compliance_policies(&c).unwrap().is_empty());
}
#[test]
fn load_compliance_policies_rejects_even_valid_runtime_yaml() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("policy.yaml");
    std::fs::write(&path, "name: RuntimeOverride\nguidance: Override scanner\n").unwrap();
    let mut c = cli(Path::new("/repo"));
    c.compliance_policy = vec![path];
    c.compliance_preset = vec!["asvs".into()];
    let err = load_compliance_policies(&c).unwrap_err();
    assert!(err.contains("runtime files are no longer supported"));
}
#[test]
fn load_compliance_policies_rejects_missing_runtime_file_without_loading() {
    let mut c = cli(Path::new("/repo"));
    c.compliance_policy = vec![PathBuf::from("/nonexistent/policy.yaml")];
    assert!(load_compliance_policies(&c).is_err());
}
#[test]
fn load_compliance_policies_resolves_a_built_in_preset_by_name() {
    let mut c = cli(Path::new("/repo"));
    c.compliance_preset = vec!["asvs".to_string()];
    let policies = load_compliance_policies(&c).unwrap();
    assert_eq!(policies.len(), 1);
    assert_eq!(policies[0].name, "OWASP ASVS v5.0.0");
}
#[test]
fn load_compliance_policies_propagates_an_unknown_preset_name() {
    let mut c = cli(Path::new("/repo"));
    c.compliance_preset = vec!["nonexistent-framework".to_string()];
    assert!(load_compliance_policies(&c).is_err());
}
#[test]
fn load_compliance_policies_combines_built_in_presets_in_order() {
    let mut c = cli(Path::new("/repo"));
    c.compliance_preset = vec!["ssdf".into(), "asvs".into()];
    let policies = load_compliance_policies(&c).unwrap();
    assert_eq!(policies.len(), 2);
    assert_eq!(
        policies[0].name,
        appsec_compliance::preset("ssdf").unwrap().name
    );
    assert_eq!(policies[1].name, "OWASP ASVS v5.0.0");
}
#[test]
fn parse_compliance_scope_is_none_when_unset() {
    assert!(parse_compliance_scope("").unwrap().is_none());
}
#[test]
fn parse_compliance_scope_is_case_insensitive() {
    assert_eq!(
        parse_compliance_scope("Filter").unwrap(),
        Some(appsec_compliance::ScopeMode::Filter)
    );
    assert_eq!(
        parse_compliance_scope("ANNOTATE").unwrap(),
        Some(appsec_compliance::ScopeMode::Annotate)
    );
}
#[test]
fn parse_compliance_scope_rejects_an_unrecognized_value() {
    let err = parse_compliance_scope("strict").unwrap_err();
    assert!(err.contains("invalid --compliance-scope"));
}
#[test]
fn load_compliance_policies_scope_override_applies_to_every_loaded_policy() {
    let mut c = cli(Path::new("/repo"));
    c.compliance_preset = vec!["ssdf".into(), "asvs".into()];
    c.compliance_scope = "filter".to_string();
    let policies = load_compliance_policies(&c).unwrap();
    assert_eq!(policies.len(), 2);
    assert!(policies
        .iter()
        .all(|p| p.scope_mode == appsec_compliance::ScopeMode::Filter));
}
#[test]
fn load_compliance_policies_propagates_an_invalid_scope_override() {
    let mut c = cli(Path::new("/repo"));
    c.compliance_scope = "strict".to_string();
    assert!(load_compliance_policies(&c).is_err());
}
#[tokio::test]
async fn sync_github_returns_none_without_a_client() {
    assert!(sync_github(None, None, None).await.is_none());
}
#[tokio::test]
async fn sync_github_returns_none_without_a_report() {
    let config = appsec_github::GithubConfig::new("acme", "widgets", 1, "tok");
    let client = appsec_github::GithubClient::new(reqwest::Client::new(), config);
    assert!(sync_github(Some(&client), None, None).await.is_none());
}
#[tokio::test]
async fn sync_github_returns_none_without_a_git_sha() {
    let config = appsec_github::GithubConfig::new("acme", "widgets", 1, "tok");
    let client = appsec_github::GithubClient::new(reqwest::Client::new(), config);
    let report = appsec_model::FinalReport {
        repo_identity: None,
        provider_ledger: Default::default(),
        repo_root: "/r".to_string(),
        repo_name: None,
        git_sha: None,
        findings: Vec::new(),
        chains: Vec::new(),
        dropped: Vec::new(),
        raw_findings_count: 0,
        metrics: None,
        threat_model: None,
        app_profile: None,
        summary: String::new(),
        degraded: false,
        degraded_reason: String::new(),
        unreachable_files: Vec::new(),
    };
    assert!(sync_github(Some(&client), Some(&report), None)
        .await
        .is_none());
}
#[test]
fn an_out_of_diff_scope_retention_reaches_neither_pr_comments_nor_findings_json() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("findings.json");
    let mut report = sample_report(Some("deadbeef"), vec![sample_finding()]);
    report.dropped.push(appsec_model::DroppedFinding {
        provider_origins: vec![appsec_model::ProviderOrigin::default()],
        verification: None,
        file: "vendor/old.py".to_string(),
        line: 7,
        vuln_class: appsec_model::VulnClass::Injection,
        title: "Pre-existing".to_string(),
        chunk_id: "external:semgrep:1".to_string(),
        reason: appsec_model::DropReason::OutOfDiffScope,
        detail: "outside the --diff-scope changed-file set".to_string(),
        canonical_idx: None,
    });

    let posted = extract_findings(&report);
    assert_eq!(posted.len(), 1);
    assert!(posted.iter().all(|f| f.file != "vendor/old.py"));

    assert!(write_findings_json(&path, Some(&report)).unwrap());
    let export: FindingsExport = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(export.findings.len(), 1);
    assert!(export.findings.iter().all(|f| f.file != "vendor/old.py"));
}
