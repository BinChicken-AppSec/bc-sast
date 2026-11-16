mod cancel_run_tests;

mod diff_scope;
mod gc;
mod inputs;
mod main_impl;
mod outputs;
mod remediate;
mod scan_config;
mod summary;

use appsec_llm_client::{
    ChatRequest, ChatResponse, ContentBlock, LlmError, StopReason, ToolSpec, Usage,
};
use async_trait::async_trait;
use clap::Parser;
use serde_json::{json, Value};
use tokio::sync::Mutex;

use super::*;

pub(crate) static ENV_LOCK: Mutex<()> = Mutex::const_new(());

pub(crate) fn restore_env(name: &str, prior: Option<String>) {
    match prior {
        Some(v) => unsafe { std::env::set_var(name, v) },
        None => unsafe { std::env::remove_var(name) },
    }
}

fn out_paths(dir: &Path) -> OutputPaths {
    OutputPaths {
        provider_writeback_plan: None,
        markdown: dir.join("report.md"),
        sarif: dir.join("report.sarif"),
        csv: dir.join("report.csv"),
        findings_json: dir.join("findings.json"),
    }
}

fn cli(repo: &Path) -> Cli {
    Cli {
        context_dir: String::new(),
        context_mcp_server: String::new(),
        context_mcp_spaces: Vec::new(),
        context_mcp_label: String::new(),
        repo_key: String::new(),
        branch: String::new(),
        base_ref: String::new(),
        repo: Some(repo.to_path_buf()),
        repo_file: None,
        workspace: std::path::PathBuf::from("./batch-workspace"),
        keep_clones: false,
        git_token: None,
        out_batch_summary: None,
        repo_name: None,
        model: "m".to_string(),
        temperature: None,
        seed: None,
        top_p: None,
        step_timeout: None,
        reasoning_effort: None,
        openai_api: None,
        no_cache_markers: false,
        allow_unsupported_model: false,
        gateway_base_url: "http://127.0.0.1:0".to_string(),
        gateway_api_key: None,
        ca_cert: None,
        client_cert: None,
        client_key: None,
        dialect: Dialect::Openai,
        pricing_provider: None,
        stop_after: String::new(),
        context_files: Vec::new(),
        context_urls: Vec::new(),
        app_id: String::new(),
        cmdb_csv: String::new(),
        checkmarx_xml: Vec::new(),
        snyk_json: Vec::new(),
        semgrep_json: Vec::new(),
        aikido_json: Vec::new(),
        sonatype_json: Vec::new(),
        semgrep_token: None,
        semgrep_deployment_slug: None,
        semgrep_repo: None,
        semgrep_branch: None,
        semgrep_base_url: None,
        snyk_token: None,
        snyk_base_url: None,
        snyk_org_id: None,
        snyk_project_id: None,
        sonatype_base_url: None,
        sonatype_username: None,
        sonatype_password: None,
        sonatype_app_id: None,
        sonatype_stage: None,
        aikido_client_id: None,
        aikido_client_secret: None,
        aikido_repo_id: None,
        aikido_base_url: None,
        checkmarx_base_url: None,
        checkmarx_iam_url: None,
        checkmarx_tenant: None,
        checkmarx_api_key: None,
        checkmarx_project_id: None,
        checkmarx_branch: None,
        git_sha: String::new(),
        out_dir: None,
        out_md: None,
        out_sarif: None,
        out_csv: None,
        provider_publish: Default::default(),
        provider_writeback: "off".into(),
        no_threat_model: false,
        max_tokens: None,
        max_scan_seconds: None,
        github_token: None,
        github_repo: None,
        pr_number: None,
        pr_comments: false,
        diff_scope: false,
        compliance_policy: Vec::new(),
        compliance_preset: Vec::new(),
        compliance_scope: String::new(),
        github_api_base_url: "https://api.github.com".to_string(),
        out_findings_json: None,
        post_comments_from: None,
        baseline: None,
        config: None,
        remediate: false,
        validate: None,
        no_validate: false,
        remediation_exit_code: true,
        target_tests: None,
        api_spec: Default::default(),
        api_spec_formats: Vec::new(),
        top: None,
        interactive: false,
        force: false,
        resume: false,
        enforce_remediation_policy: false,
        remediation_policy: None,
        remediation_playbook: None,
        no_syntax_check: false,
        keep_unverified: false,
        max_diff_lines: None,
        max_files_touched: None,
        remediate_dry_run: false,
        verify_command: None,
        verify_timeout: None,
        remediate_in_place: false,
        remediation_delivery: crate::delivery::DeliveryMode::Patch,
        delivery_remote: None,
        delivery_branch: None,
        keep_remediation_worktree: false,
        out_remediation_json: None,
        post_fixes_from: None,
        remediate_from: None,
        gc: false,
        gc_keep_runs: 100,
        gc_max_age_days: 5,
        gc_run: None,
        gc_dry_run: false,
        estimate: false,
        log_file: None,
        log_stderr: false,
        verbose: 0,
        no_progress: true,
        progress_style: None,
        s6_progress_file: false,
        out_run_manifest: None,
        doctor: false,
        cache_probe: false,
        stream_large_responses: false,
        skip_preflight: true,
        setup: false,
        auto_step1: false,
        no_auto_step1: false,
    }
}

fn assert_the_others_stayed_in_the_out_dir(paths: &OutputPaths, moved: &Path) {
    let others: Vec<&Path> = [
        paths.markdown.as_path(),
        paths.sarif.as_path(),
        paths.csv.as_path(),
        paths.findings_json.as_path(),
    ]
    .into_iter()
    .filter(|p| *p != moved)
    .collect();
    assert_eq!(others.len(), 3, "{others:?}");
    assert!(
        others
            .iter()
            .all(|p| p.parent() == Some(Path::new("/elsewhere"))),
        "{others:?}"
    );
}

fn cli_with_out_dir() -> Cli {
    let mut c = cli(Path::new("/repo"));
    c.out_dir = Some(PathBuf::from("/elsewhere"));
    c
}

async fn diff_server(diff: &str) -> wiremock::MockServer {
    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/repos/acme/widgets/pulls/1"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_string(diff))
        .mount(&server)
        .await;
    server
}

fn sample_report(
    git_sha: Option<&str>,
    findings: Vec<appsec_model::Finding>,
) -> appsec_model::FinalReport {
    appsec_model::FinalReport {
        repo_identity: None,
        provider_ledger: Default::default(),
        repo_root: "/r".to_string(),
        repo_name: None,
        git_sha: git_sha.map(str::to_string),
        findings: findings
            .into_iter()
            .map(|finding| appsec_model::RankedFinding {
                finding,
                severity: appsec_model::Severity::High,
                exploitability_notes: String::new(),
            })
            .collect(),
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
    }
}

fn sample_finding() -> appsec_model::Finding {
    appsec_model::Finding {
        provider_origins: Vec::new(),
        component: None,
        chunk_id: "c1".to_string(),
        file: "app.py".to_string(),
        line_start: 1,
        line_end: 1,
        vuln_class: appsec_model::VulnClass::Injection,
        cwe: None,
        title: "SQL injection".to_string(),
        impact: String::new(),
        description: "desc".to_string(),
        exploit_scenario: String::new(),
        preconditions: Vec::new(),
        recommendation: String::new(),
        code_snippet: "query(x)".to_string(),
        source_ref: None,
        sink_ref: None,
        backfilled_refs: Vec::new(),
        reanchored: Vec::new(),
        compliance_requirements: Vec::new(),
        confidence: 0.9,
        votes: 1,
        duplicates: Vec::new(),
        verdict: None,
        verdict_confidence: None,
        verdict_reason: String::new(),
        cvss_vector: None,
        cvss_score: None,
        cvss_rating: None,
        verifier_reasoning: String::new(),
        vsvs_vector: None,
        vsvs_score: None,
        vsvs_rating: None,
        offensive_priority: None,
        offensive_reason: String::new(),
        related_cwes: Vec::new(),
    }
}

fn github_client_for(server: &wiremock::MockServer) -> appsec_github::GithubClient {
    let mut cfg = appsec_github::GithubConfig::new("acme", "widgets", 1, "tok");
    cfg.api_base_url = server.uri();
    appsec_github::GithubClient::new(reqwest::Client::new(), cfg)
}

fn write_export(dir: &std::path::Path, export: &FindingsExport) -> PathBuf {
    let path = dir.join("findings.json");
    std::fs::write(&path, serde_json::to_string(export).unwrap()).unwrap();
    path
}

fn write_remediation_export(dir: &std::path::Path, export: &RemediationExport) -> PathBuf {
    let path = dir.join("remediation.json");
    std::fs::write(&path, serde_json::to_string(export).unwrap()).unwrap();
    path
}

fn processed_fix_outcome(finding_id: &str, diff: Option<&str>) -> RemediationOutcomeExport {
    RemediationOutcomeExport::Processed(Box::new(RemediationRecordExport {
        finding_index: 1,
        finding_id: finding_id.to_string(),
        verdict: "fixed".to_string(),
        policy_action: None,
        policy_reason: None,
        final_verdict: None,
        changes: Vec::new(),
        summary: "s".to_string(),
        diff: diff.map(str::to_string),
        validation: None,
    }))
}

fn summary_with_cost(cost: Option<CostSummary>) -> ScanSummary {
    ScanSummary {
        provider_publication: None,
        gc: None,
        cost,
        findings: 2,
        markdown_path: None,
        sarif_path: None,
        csv_path: None,
        findings_json_path: None,
        stopped_after: None,
        github_sync: None,
        remediation: None,
        remediation_patch: None,
        baseline: None,
        batch: None,
        estimate: None,
        doctor: None,
        setup: None,
        augmented: None,
    }
}

struct ByteBudget {
    budget: usize,
    written: usize,
}

use std::fmt::Write as _;

impl std::fmt::Write for ByteBudget {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        if self.written + s.len() > self.budget {
            return Err(std::fmt::Error);
        }
        self.written += s.len();
        Ok(())
    }
}

type Router = Box<dyn Fn(&str) -> Result<String, LlmError> + Send + Sync>;

struct RoutedClient {
    router: Router,
}

#[async_trait]
impl LlmClient for RoutedClient {
    async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, LlmError> {
        let system = request.system.as_deref().unwrap_or("");
        let text = (self.router)(system)?;
        Ok(ChatResponse {
            content: vec![ContentBlock::Text(text)],
            stop_reason: StopReason::EndTurn,
            usage: Usage::default(),
        })
    }
}

struct NoTools;
impl ToolExecutor for NoTools {
    fn available_tools(&self) -> Vec<ToolSpec> {
        ["Read", "Glob", "Grep"]
            .iter()
            .map(|name| ToolSpec {
                name: name.to_string(),
                description: String::new(),
                parameters: json!({}),
            })
            .collect()
    }
    fn execute(&self, _name: &str, _args: &Value) -> String {
        String::new()
    }
}

fn route(system: &str, table: &[(&str, &str)]) -> String {
    for (mark, reply) in table {
        if system.contains(mark) {
            return (*reply).to_string();
        }
    }
    panic!("unrecognized system prompt in test router: {system}");
}

fn assert_github_sync_failed(summary: &ScanSummary) {
    match &summary.github_sync {
        Some(Err(_)) => {}
        other => panic!("expected Some(Err(_)), got {other:?}"),
    }
}

fn expect_processed(
    o: &appsec_stage_s10::RemediationOutcome,
) -> &appsec_stage_s10::RemediationRecord {
    match o {
        appsec_stage_s10::RemediationOutcome::Processed(record) => record,
        other => panic!("expected Processed, got {other:?}"),
    }
}

fn assert_processed(o: &appsec_stage_s10::RemediationOutcome) {
    match o {
        appsec_stage_s10::RemediationOutcome::Processed(_) => {}
        other => panic!("expected Processed, got {other:?}"),
    }
}

fn empty_scan_client() -> Arc<dyn LlmClient> {
    Arc::new(RoutedClient {
        router: Box::new(|system| {
            Ok(route(
                system,
                &[
                    (
                        "security-focused codebase mapper",
                        r#"{"language":"python","modules":[],"entry_points":[],"unsafe_sinks":[],"call_graph":{},"notes":""}"#,
                    ),
                    (
                        "application-security threat modeler",
                        r#"{"system_context":"ctx","assets":[],"trust_boundaries":[],"threats":[],"open_questions":[]}"#,
                    ),
                    (
                        "vulnerability research strategist",
                        "garbage, s3 degrades to its deterministic catchall sweep",
                    ),
                    (
                        "security researcher performing deep code analysis",
                        r#"{"findings": []}"#,
                    ),
                ],
            ))
        }),
    })
}

fn setup_repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("app.py"), "print('hi')\n").unwrap();
    dir
}

fn git_repo() -> tempfile::TempDir {
    let dir = setup_repo();
    let run_git = |args: &[&str]| {
        std::process::Command::new("git")
            .arg("-C")
            .arg(dir.path())
            .args(args)
            .output()
            .unwrap()
    };
    run_git(&["init", "-q"]);
    run_git(&[
        "-c",
        "user.email=test@test.com",
        "-c",
        "user.name=test",
        "add",
        "-A",
    ]);
    run_git(&[
        "-c",
        "user.email=test@test.com",
        "-c",
        "user.name=test",
        "commit",
        "-q",
        "-m",
        "x",
    ]);
    dir
}

pub(crate) fn fast_config() -> ScanConfig {
    let mut step1 = Step1Config::new("m");
    step1.retry_backoff_base = std::time::Duration::ZERO;
    ScanConfig {
        autoexclude: Default::default(),
        cancel: None,
        step0_enabled: false,
        step0: Step0Config::new(),
        step1,
        step2_enabled: true,
        step2: Step2Config::new("m"),
        step3: Step3Config::new("m"),
        step4: Step4Config::new("m"),
        step5: Step5Config::new("m"),
        step6: Step6Config::new("m"),
        step7: Step7Config::new("m"),
        step8: Step8Config::new("m"),
        tool_version: "test".to_string(),
        spend_cap: None,
        checkpoint: None,
        resume: false,
        emit_unreachable_appendix: false,
        progress: None,
        pricing: appsec_orchestrator::pricing::PricingConfig::default(),
    }
}

fn fast_input(dir: &Path) -> ScanInput {
    build_scan_input(&cli(dir))
}

const S1_MARK: &str = "security-focused codebase mapper";
const S2_MARK: &str = "application-security threat modeler";
const S3_MARK: &str = "vulnerability research strategist";
const S4_MARK: &str = "security researcher performing deep code analysis";
const S6_MARK: &str = "second-opinion reviewer";
const S8_MARK: &str = "exploit development strategist";
const S10_MARK: &str = "REMEDIATION agent";
const GOOD_CVSS: &str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";

fn s4_one_finding_json() -> String {
    json!({"findings": [{
        "file": "app.py", "line_start": 2, "line_end": 3,
        "vuln_class": "injection", "title": "SQL injection",
        "description": "user input reaches a raw query",
        "code_snippet": "cur.execute(q)", "confidence": 0.9,
        "source_ref": "app.py:2", "sink_ref": "app.py:3",
    }]})
    .to_string()
}

fn s6_true_positive_text() -> String {
    format!("traced it\nVERDICT: TRUE_POSITIVE (confidence: 9/10) — reachable\nCVSS: {GOOD_CVSS}\n")
}

fn s8_ranked_json() -> String {
    json!({
        "summary": "One SQL injection finding.",
        "ranked_findings": [{"index": 0, "severity": "high", "exploitability_notes": "reachable"}],
        "chains": [],
    })
    .to_string()
}

fn s10_verdict_json() -> String {
    json!({
        "finding_index": 1, "verdict": "Fixed",
        "gates": {"source": "pass", "sink": "pass", "missing_control": "pass"},
        "root_cause": "x", "changes": [], "remaining_risks": [],
        "recommendations": [], "summary": "s",
    })
    .to_string()
}

fn one_finding_client() -> Arc<dyn LlmClient> {
    let s4 = s4_one_finding_json();
    let s6 = s6_true_positive_text();
    let s8 = s8_ranked_json();
    let s10 = s10_verdict_json();
    Arc::new(RoutedClient {
        router: Box::new(move |system| {
            Ok(route(
                system,
                &[
                    (
                        S1_MARK,
                        r#"{"language":"python","modules":[],"entry_points":[],"unsafe_sinks":[],"call_graph":{},"notes":""}"#,
                    ),
                    (
                        S2_MARK,
                        r#"{"system_context":"ctx","assets":[],"trust_boundaries":[],"threats":[],"open_questions":[]}"#,
                    ),
                    (
                        S3_MARK,
                        "garbage, s3 degrades to its deterministic catchall sweep",
                    ),
                    (S4_MARK, &s4),
                    (S6_MARK, &s6),
                    (S8_MARK, &s8),
                    (S10_MARK, &s10),
                ],
            ))
        }),
    })
}

fn one_finding_client_s10_only() -> Arc<dyn LlmClient> {
    let s10 = s10_verdict_json();
    Arc::new(RoutedClient {
        router: Box::new(move |system| Ok(route(system, &[(S10_MARK, &s10)]))),
    })
}

const S11_ARCHITECT_MARK: &str = "security architect";
const S11_PENTESTER_MARK: &str = "penetration tester";

fn s11_all_pass_gates_json() -> String {
    json!({"gates": [
        {"gate_name": "root_cause", "status": "pass", "summary": "ok", "evidence": [{"file": "app.py", "line": 2, "snippet": "print('fixed')"}], "details": ""},
        {"gate_name": "instance_coverage", "status": "pass", "summary": "ok", "evidence": [], "details": ""},
        {"gate_name": "no_new_vulnerabilities", "status": "pass", "summary": "ok", "evidence": [], "details": ""},
        {"gate_name": "security_best_practices", "status": "pass", "summary": "ok", "evidence": [], "details": ""},
    ]})
    .to_string()
}

struct OneFindingClientWithValidation {
    remediate_turn: std::sync::atomic::AtomicU32,
}

impl OneFindingClientWithValidation {
    fn new() -> Self {
        OneFindingClientWithValidation {
            remediate_turn: std::sync::atomic::AtomicU32::new(0),
        }
    }
}

#[async_trait]
impl LlmClient for OneFindingClientWithValidation {
    async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, LlmError> {
        let system = request.system.as_deref().unwrap_or("");
        if system.contains(S10_MARK) {
            let turn = self
                .remediate_turn
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if turn == 0 {
                return Ok(ChatResponse {
                    content: vec![ContentBlock::ToolUse {
                        id: "1".to_string(),
                        name: "Write".to_string(),
                        input: json!({"path": "app.py", "content": "print('fixed')\n"}),
                    }],
                    stop_reason: StopReason::ToolUse,
                    usage: Usage::default(),
                });
            }
            let verdict = json!({
                "finding_index": 1, "verdict": "Fixed",
                "gates": {"source": "pass", "sink": "pass", "missing_control": "pass"},
                "root_cause": "x",
                "changes": [{"file": "app.py", "summary": "fixed it"}],
                "remaining_risks": [], "recommendations": [], "summary": "s",
            })
            .to_string();
            return Ok(ChatResponse {
                content: vec![ContentBlock::Text(verdict)],
                stop_reason: StopReason::EndTurn,
                usage: Usage::default(),
            });
        }
        let s4 = s4_one_finding_json();
        let s6 = s6_true_positive_text();
        let s8 = s8_ranked_json();
        let s11 = s11_all_pass_gates_json();
        let text = route(
            system,
            &[
                (
                    S1_MARK,
                    r#"{"language":"python","modules":[],"entry_points":[],"unsafe_sinks":[],"call_graph":{},"notes":""}"#,
                ),
                (
                    S2_MARK,
                    r#"{"system_context":"ctx","assets":[],"trust_boundaries":[],"threats":[],"open_questions":[]}"#,
                ),
                (
                    S3_MARK,
                    "garbage, s3 degrades to its deterministic catchall sweep",
                ),
                (S4_MARK, &s4),
                (S6_MARK, &s6),
                (S8_MARK, &s8),
                (S11_ARCHITECT_MARK, &s11),
                (S11_PENTESTER_MARK, &s11),
            ],
        );
        Ok(ChatResponse {
            content: vec![ContentBlock::Text(text)],
            stop_reason: StopReason::EndTurn,
            usage: Usage::default(),
        })
    }
}

fn fast_config_no_semantic_dedup() -> ScanConfig {
    let mut config = fast_config();
    config.step7.semantic = false;
    config
}

fn fast_remediate_config() -> appsec_stage_s10::Step10Config {
    let mut step10 = appsec_stage_s10::Step10Config::new("m");
    step10.max_transient_retries = 0;
    step10.retry_backoff_base = std::time::Duration::ZERO;
    step10
}

fn fast_step11_config() -> appsec_stage_s11::Step11Config {
    let mut step11 = appsec_stage_s11::Step11Config::new("m");
    step11.max_transient_retries = 0;
    step11.retry_backoff_base = std::time::Duration::ZERO;
    step11
}

fn priced_fast_config(model: &str) -> ScanConfig {
    let mut config = fast_config();
    config.pricing = appsec_orchestrator::pricing::PricingConfig::for_provider(Some("openai"));
    config.step1.model = model.to_string();
    config.step2.model = model.to_string();
    config.step3.model = model.to_string();
    config.step4.model = model.to_string();
    config.step5.dedup.model = model.to_string();
    config.step6.model = model.to_string();
    config.step7.model = model.to_string();
    config.step8.model = model.to_string();
    config
}

struct UsageInjectingClient {
    inner: Arc<dyn LlmClient>,
    usage: Usage,
}

#[async_trait]
impl LlmClient for UsageInjectingClient {
    async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, LlmError> {
        let mut response = self.inner.chat(request).await?;
        response.usage = self.usage;
        Ok(response)
    }
}

fn validation_score(
    fix_status: appsec_validation_scoring::FixVerdict,
) -> appsec_validation_scoring::ValidationScore {
    appsec_validation_scoring::ValidationScore {
        raw_score: 1.0,
        fix_status,
        justification: String::new(),
        gate_results: Vec::new(),
        has_critical_failure: false,
    }
}

fn processed_record(
    finding_id: &str,
    verdict: appsec_stage_s10::Verdict,
    diff: Option<&str>,
) -> appsec_stage_s10::RemediationOutcome {
    let mut v = appsec_stage_s10::RemediationVerdict::denied(1, "summary text");
    v.verdict = verdict;
    v.root_cause = "unsanitized input".to_string();
    v.remaining_risks = vec!["other call sites".to_string()];
    v.recommendations = vec!["add a test".to_string()];
    v.changes.push(appsec_stage_s10::Change {
        file: "app.py".to_string(),
        summary: "parameterized the query".to_string(),
    });
    appsec_stage_s10::RemediationOutcome::Processed(Box::new(appsec_stage_s10::RemediationRecord {
        finding_index: 1,
        finding_id: finding_id.to_string(),
        verdict: v,
        policy_action: None,
        policy_reason: None,
        final_verdict: None,
        policy_reverted: Vec::new(),
        policy_matched_globs: Vec::new(),
        diff: diff.map(str::to_string),
    }))
}

fn base_summary() -> ScanSummary {
    ScanSummary {
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
        remediation: None,
        remediation_patch: None,
        baseline: None,
        batch: None,
        estimate: None,
        doctor: None,
        setup: None,
        augmented: None,
    }
}

fn write_prior_reports(dir: &Path, report: &appsec_model::FinalReport) -> (PathBuf, PathBuf) {
    let md_path = dir.join("security-scan").join("report.md");
    let sarif_path = dir.join("security-scan").join("report.sarif");
    std::fs::create_dir_all(md_path.parent().unwrap()).unwrap();
    std::fs::write(&md_path, appsec_report_md::render_markdown(report)).unwrap();
    std::fs::write(
        &sarif_path,
        serde_json::to_string_pretty(&appsec_sarif::build_sarif(report, "test")).unwrap(),
    )
    .unwrap();
    (md_path, sarif_path)
}

fn validated_outcome(id: &str) -> appsec_orchestrator::RemediateOutcome {
    appsec_orchestrator::RemediateOutcome {
        refused: None,
        outcomes: vec![processed_record(
            id,
            appsec_stage_s10::Verdict::Fixed,
            Some("d"),
        )],
        validations: vec![Some(appsec_validation_scoring::ValidationScore {
            raw_score: 0.91,
            fix_status: appsec_validation_scoring::FixVerdict::Fixed,
            justification: "the injection is parameterized now".to_string(),
            gate_results: Vec::new(),
            has_critical_failure: false,
        })],
        validation_failures: 0,
    }
}

fn isolated_remediate_run(
    root: &Path,
    target_tests: Option<target_testing::TargetTestingConfig>,
    delivery: Option<delivery::DeliveryState>,
    worktree: Option<worktree::RemediationWorktree>,
) -> RemediateRun {
    let tools = SandboxTools::new_with_write(root.to_path_buf());
    let mut step10 = fast_remediate_config();
    step10.journal = Some(tools.journal());
    RemediateRun {
        delivery,
        settings: RemediateSettings {
            target_tests,
            config: appsec_orchestrator::RemediateConfig {
                step10,
                top: None,
                top_default: None,
                force: false,
                resume: false,
                isolated: true,
            },
            policy: None,
            interactive: false,
            validate_enabled: false,
            step11: fast_step11_config(),
        },
        tools: Arc::new(tools),
        out_json: None,
        checkpoint: None,
        worktree,
    }
}

async fn dispatch(
    llm: Arc<dyn LlmClient>,
    repo: &Path,
    report: &appsec_model::FinalReport,
    run: RemediateRun,
) -> (appsec_orchestrator::RemediateOutcome, Option<PathBuf>) {
    let read_tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new(repo.to_path_buf()));
    dispatch_remediation(
        llm,
        read_tools,
        repo,
        report,
        run,
        appsec_orchestrator::RemediateTelemetry::default(),
    )
    .await
}

fn one_finding_report() -> appsec_model::FinalReport {
    sample_report(None, vec![sample_finding()])
}

fn complete_scan_no_findings_client() -> Arc<dyn LlmClient> {
    Arc::new(RoutedClient {
        router: Box::new(|system| {
            Ok(route(
                system,
                &[
                    (
                        S1_MARK,
                        r#"{"language":"python","modules":[],"entry_points":[],"unsafe_sinks":[],"call_graph":{},"notes":""}"#,
                    ),
                    (
                        S2_MARK,
                        r#"{"system_context":"ctx","assets":[],"trust_boundaries":[],"threats":[],"open_questions":[]}"#,
                    ),
                    (
                        S3_MARK,
                        r#"{"chunks":[],"rationale":"deterministic catchall"}"#,
                    ),
                    (S4_MARK, r#"{"findings": []}"#),
                ],
            ))
        }),
    })
}

fn s10_client_with_an_unusable_generator() -> Arc<dyn LlmClient> {
    let s10 = s10_verdict_json();
    Arc::new(RoutedClient {
        router: Box::new(move |system| {
            Ok(if system.contains(S10_MARK) {
                s10.clone()
            } else {
                "not-json".to_string()
            })
        }),
    })
}

async fn run_scan_with_remediation(
    repo: &Path,
    paths: &OutputPaths,
    remediate: RemediateRun,
) -> Result<ScanSummary, String> {
    run(
        fast_input(repo),
        fast_config_no_semantic_dedup(),
        None,
        paths,
        complete_scan_no_findings_client(),
        Arc::new(NoTools),
        None,
        Some(remediate),
        None,
    )
    .await
}

struct FakeTerminal {
    tty: bool,
    keys: std::collections::VecDeque<std::io::Result<appsec_interactive::Key>>,
    lines: std::collections::VecDeque<Option<String>>,
}

impl FakeTerminal {
    fn tty(keys: Vec<std::io::Result<appsec_interactive::Key>>) -> Self {
        FakeTerminal {
            tty: true,
            keys: keys.into(),
            lines: std::collections::VecDeque::new(),
        }
    }

    fn prompt(lines: Vec<Option<String>>) -> Self {
        FakeTerminal {
            tty: false,
            keys: std::collections::VecDeque::new(),
            lines: lines.into(),
        }
    }
}

impl appsec_interactive::BlockingInput for FakeTerminal {
    fn read_key(&mut self) -> std::io::Result<appsec_interactive::Key> {
        self.keys
            .pop_front()
            .unwrap_or(Ok(appsec_interactive::Key::Quit))
    }
    fn read_line(&mut self, _prompt: &str) -> Option<String> {
        self.lines.pop_front().flatten()
    }
}

impl appsec_interactive::Terminal for FakeTerminal {
    fn is_tty(&self) -> bool {
        self.tty
    }
    fn draw(&mut self, _frame: &str) -> std::io::Result<()> {
        Ok(())
    }
    fn write_line(&mut self, _line: &str) {}
}

fn remediate_config_no_cap() -> appsec_orchestrator::RemediateConfig {
    appsec_orchestrator::RemediateConfig {
        step10: fast_remediate_config(),
        top: None,
        top_default: None,
        force: false,
        resume: false,
        isolated: false,
    }
}

struct PublicationBeforeRemediationClient {
    receipt: PathBuf,
    artifacts: Vec<PathBuf>,
    remediation_calls: std::sync::atomic::AtomicUsize,
    inner: Arc<dyn LlmClient>,
}

#[async_trait]
impl LlmClient for PublicationBeforeRemediationClient {
    async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, LlmError> {
        if request.system.as_deref().unwrap_or("").contains(S10_MARK) {
            let receipt: Value =
                serde_json::from_slice(&std::fs::read(&self.receipt).unwrap()).unwrap();
            assert_eq!(receipt["complete"], true);
            assert!(self.artifacts.iter().all(|path| path.is_file()));
            self.remediation_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        self.inner.chat(request).await
    }
}

const S1_JSON: &str = r#"{"language":"python","modules":[],"entry_points":[],"unsafe_sinks":[],"call_graph":{},"notes":""}"#;

fn register_run_at(state_dir: &Path, target: &Path) -> String {
    let run_id = appsec_checkpoint::run_id_for(target);
    let store: Arc<dyn appsec_checkpoint::CheckpointStore> = Arc::new(
        appsec_checkpoint::SqliteCheckpointStore::new(state_dir.join("bc-sast.db")).unwrap(),
    );
    store.register_run(&run_id, &target.display().to_string(), None, None);
    run_id
}

async fn assert_writes_no_reports(mode: &str, apply: impl FnOnce(&mut Cli)) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("main.py"), b"x").unwrap();
    let mut c = cli(dir.path());
    apply(&mut c);
    let _ = main_impl(c).await;
    assert!(
        !dir.path().join("security-scan").exists(),
        "{mode} created an output directory"
    );
}

async fn cache_probe_gateway(dialect_path: &str, body: Value) -> wiremock::MockServer {
    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::path(dialect_path))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(body))
        .mount(&server)
        .await;
    server
}

#[test]
fn the_context_mcp_flags_reach_the_scan_input() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut c = cli(dir.path());
    c.context_mcp_server = "/opt/bc/appsec-mcp".to_string();
    c.context_mcp_spaces = vec!["ENG".to_string(), "SEC".to_string()];
    c.context_mcp_label = "architecture".to_string();

    let input = build_scan_input(&c);
    assert_eq!(
        input.context_mcp_server.as_deref(),
        Some(std::path::Path::new("/opt/bc/appsec-mcp"))
    );
    assert_eq!(input.context_mcp_spaces, ["ENG", "SEC"]);
    assert_eq!(input.context_mcp_label.as_deref(), Some("architecture"));
}

#[test]
fn the_context_mcp_flags_default_to_off() {
    let dir = tempfile::tempdir().expect("tempdir");
    let input = build_scan_input(&cli(dir.path()));
    assert!(input.context_mcp_server.is_none());
    assert!(input.context_mcp_spaces.is_empty());
    assert!(input.context_mcp_label.is_none());
}
