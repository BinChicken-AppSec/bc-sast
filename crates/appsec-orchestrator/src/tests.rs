use std::sync::Mutex;

use appsec_stage_s0::Stage0;
use appsec_stage_s1::Stage1;
use appsec_stage_s2::Stage2;
use appsec_stage_s3::Stage3;

use appsec_llm_client::{
    ChatRequest, ChatResponse, ContentBlock, LlmError, StopReason, ToolSpec, Usage,
};
use async_trait::async_trait;
use serde_json::{json, Value};

use super::*;

mod cancel_scan;
mod run_telemetry;

type Router = Box<dyn Fn(&str) -> Result<String, LlmError> + Send + Sync>;

struct RoutedClient {
    router: Router,
}

impl RoutedClient {
    fn new(router: impl Fn(&str) -> Result<String, LlmError> + Send + Sync + 'static) -> Self {
        RoutedClient {
            router: Box::new(router),
        }
    }
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

fn phase_usage(usage: Usage) -> PhaseUsage {
    PhaseUsage {
        usage,
        calls: 1,
        calls_with_usage: 1,
        cost: pricing::PhaseCost::default(),
        truncated_replies: 0,
    }
}

fn priced_phase(provider: Option<&str>, model: &str, usage: Usage) -> PhaseUsage {
    let mut phase = phase_usage(usage);
    let config = pricing::PricingConfig::for_provider(provider);
    phase
        .cost
        .record_call(&config.pricer(), provider, model, usage, config.cache_ttl);
    phase
}

fn priced_scan_config(provider: Option<&str>, model: &str) -> ScanConfig {
    let mut config = scan_config();
    config.pricing = pricing::PricingConfig::for_provider(provider);
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

const S1_SYSTEM_MARK: &str = "security-focused codebase mapper";
const S2_SYSTEM_MARK: &str = "application-security threat modeler";
const S3_SYSTEM_MARK: &str = "vulnerability research strategist";
const S4_SYSTEM_MARK: &str = "security researcher performing deep code analysis";
const S6_SYSTEM_MARK: &str = "second-opinion reviewer";
const S8_SYSTEM_MARK: &str = "exploit development strategist";

const S1_JSON: &str = r#"{"language":"python","modules":[],"entry_points":[],"unsafe_sinks":[],"call_graph":{},"notes":""}"#;
const S2_JSON: &str = r#"{"system_context":"ctx","assets":[{"name":"user records"}],"trust_boundaries":[],"threats":[],"open_questions":[]}"#;
const S3_GARBAGE: &str = "not valid json at all, deliberately garbage so s3 degrades to its deterministic catchall sweep";
const S4_EMPTY: &str = r#"{"findings": []}"#;
const GOOD_CVSS: &str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";

fn route(system: &str, table: &[(&str, &str)]) -> String {
    for (mark, reply) in table {
        if system.contains(mark) {
            return (*reply).to_string();
        }
    }
    panic!("unrecognized system prompt in test router: {system}");
}

fn s4_one_finding_json() -> String {
    json!({"findings": [{
        "file": "app.py", "line_start": 10, "line_end": 12,
        "vuln_class": "injection", "title": "SQL injection", "description": "user input reaches a raw query",
        "code_snippet": "cur.execute(q)", "confidence": 0.9,
        "source_ref": "app.py:10", "sink_ref": "app.py:12",
    }]})
    .to_string()
}

fn s4_finding_on(file: &str) -> String {
    json!({"findings": [{
        "file": file, "line_start": 10, "line_end": 12,
        "vuln_class": "injection", "title": "SQL injection", "description": "user input reaches a raw query",
        "code_snippet": "cur.execute(q)", "confidence": 0.9,
        "source_ref": format!("{file}:10"), "sink_ref": format!("{file}:12"),
    }]})
    .to_string()
}

fn s6_true_positive_text() -> String {
    format!("traced it\nVERDICT: TRUE_POSITIVE (confidence: 9/10) — reachable\nCVSS: {GOOD_CVSS}\n")
}

fn s8_ranked_json() -> String {
    json!({
        "summary": "One SQL injection finding.",
        "ranked_findings": [{"index": 0, "severity": "high", "exploitability_notes": "reachable from an external request"}],
        "chains": [],
    })
    .to_string()
}

fn client_with(table: Vec<(&'static str, String)>) -> Arc<dyn LlmClient> {
    Arc::new(RoutedClient::new(move |system: &str| {
        let owned: Vec<(&str, &str)> = table.iter().map(|(m, r)| (*m, r.as_str())).collect();
        Ok(route(system, &owned))
    }))
}

fn full_table(s4: &str, s6: &str, s8: &str) -> Vec<(&'static str, String)> {
    vec![
        (S1_SYSTEM_MARK, S1_JSON.to_string()),
        (S2_SYSTEM_MARK, S2_JSON.to_string()),
        (S3_SYSTEM_MARK, S3_GARBAGE.to_string()),
        (S4_SYSTEM_MARK, s4.to_string()),
        (S6_SYSTEM_MARK, s6.to_string()),
        (S8_SYSTEM_MARK, s8.to_string()),
    ]
}

fn empty_findings_client() -> Arc<dyn LlmClient> {
    client_with(full_table(S4_EMPTY, "", ""))
}

fn one_finding_client() -> Arc<dyn LlmClient> {
    let s6 = s6_true_positive_text();
    let s8 = s8_ranked_json();
    client_with(full_table(&s4_one_finding_json(), &s6, &s8))
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

struct MarkedUsageClient {
    inner: Arc<dyn LlmClient>,
    mark: &'static str,
    usage: Usage,
}

#[async_trait]
impl LlmClient for MarkedUsageClient {
    async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, LlmError> {
        let mut response = self.inner.chat(request).await?;
        if request.system.as_deref().unwrap_or("").contains(self.mark) {
            response.usage = self.usage;
        }
        Ok(response)
    }
}

fn setup_repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("app.py"),
        "def handler(request):\n    q = request.GET['q']\n    cur.execute(q)\n",
    )
    .unwrap();
    dir
}

fn scan_input(dir: &std::path::Path) -> ScanInput {
    ScanInput {
        context_dir: None,
        context_mcp_server: None,
        context_mcp_spaces: Vec::new(),
        context_mcp_label: None,
        context_files: Vec::new(),
        context_urls: Vec::new(),
        repo_root: dir.to_path_buf(),
        repo_name: "demo".to_string(),
        application_id: None,
        cmdb_path: None,
        git_sha_override: None,
        repo_key_override: None,
        repo_key_env: None,
        branch_override: None,
        base_ref: None,
        changed_files: BTreeMap::new(),
        diff_scope_active: false,
        compliance: Vec::new(),
        checkmarx_xml: Vec::new(),
        snyk_json: Vec::new(),
        semgrep_json: Vec::new(),
        aikido_json: Vec::new(),
        sonatype_json: Vec::new(),
        semgrep_live: None,
        snyk_live: None,
        sonatype_live: None,
        aikido_live: None,
        checkmarx_live: None,
    }
}

fn scan_config() -> ScanConfig {
    let mut step7 = Step7Config::new("m");
    step7.semantic = false;
    step7.retry_backoff_base = std::time::Duration::ZERO;
    let mut step1 = Step1Config::new("m");
    step1.retry_backoff_base = std::time::Duration::ZERO;
    let mut step2 = Step2Config::new("m");
    step2.retry_backoff_base = std::time::Duration::ZERO;
    let mut step3 = Step3Config::new("m");
    step3.retry_backoff_base = std::time::Duration::ZERO;
    let mut step4 = Step4Config::new("m");
    step4.retry_backoff_base = std::time::Duration::ZERO;
    let mut step5 = Step5Config::new("m");
    step5.dedup.retry_backoff_base = std::time::Duration::ZERO;
    let mut step8 = Step8Config::new("m");
    step8.retry_backoff_base = std::time::Duration::ZERO;
    ScanConfig {
        autoexclude: Default::default(),
        cancel: None,
        step0_enabled: false,
        step0: Step0Config::new(),
        step1,
        step2_enabled: true,
        step2,
        step3,
        step4,
        step5,
        step6: Step6Config::new("m"),
        step7,
        step8,
        tool_version: "0.1.0-test".to_string(),
        spend_cap: None,
        checkpoint: None,
        resume: false,
        emit_unreachable_appendix: false,
        progress: None,
        pricing: pricing::PricingConfig::default(),
    }
}

fn compliance_policy(
    name: &str,
    req_id: &str,
    scope_mode: appsec_compliance::ScopeMode,
    vuln_classes: &[&str],
) -> appsec_compliance::CompliancePolicy {
    appsec_compliance::CompliancePolicy {
        name: name.to_string(),
        guidance: String::new(),
        scope_mode,
        requirements: vec![appsec_compliance::Requirement {
            id: req_id.to_string(),
            title: "Injection controls".to_string(),
            cwes: Vec::new(),
            vuln_classes: vuln_classes.iter().map(|s| s.to_string()).collect(),
        }],
    }
}

const SEMANTIC_DEDUP_MARK: &str = "collapsing overlapping SAST findings";

fn s4_two_findings_json() -> String {
    json!({"findings": [
        {
            "file": "app.py", "line_start": 10, "line_end": 12,
            "vuln_class": "injection", "title": "SQL injection A", "description": "user input reaches a raw query",
            "code_snippet": "cur.execute(q)", "confidence": 0.9,
            "source_ref": "app.py:10", "sink_ref": "app.py:12",
        },
        {
            "file": "other.py", "line_start": 20, "line_end": 22,
            "vuln_class": "injection", "title": "SQL injection B", "description": "a second, unrelated raw query",
            "code_snippet": "cur2.execute(q2)", "confidence": 0.9,
            "source_ref": "other.py:20", "sink_ref": "other.py:22",
        },
    ]})
    .to_string()
}

fn s8_two_ranked_json() -> String {
    json!({
        "summary": "Two SQL injection findings.",
        "ranked_findings": [
            {"index": 0, "severity": "high", "exploitability_notes": "reachable"},
            {"index": 1, "severity": "high", "exploitability_notes": "reachable"},
        ],
        "chains": [],
    })
    .to_string()
}

fn finished_stages(events: &[appsec_pipeline_core::ScanEvent]) -> Vec<(&'static str, StageStatus)> {
    events
        .iter()
        .filter_map(|e| match e {
            appsec_pipeline_core::ScanEvent::StageFinished { stage, status, .. } => {
                Some((*stage, *status))
            }
            _ => None,
        })
        .collect()
}

fn finished_counts(
    events: &[appsec_pipeline_core::ScanEvent],
    wanted: &str,
) -> Vec<(&'static str, u64)> {
    let missing = format!("no StageFinished for {wanted}");
    events
        .iter()
        .find_map(|e| match e {
            appsec_pipeline_core::ScanEvent::StageFinished { stage, counts, .. }
                if *stage == wanted =>
            {
                Some(counts.clone())
            }
            _ => None,
        })
        .expect(&missing)
}

fn third_party_input(set: impl FnOnce(&mut ScanInput)) -> ScanInput {
    let mut input = scan_input(Path::new("/unused"));
    set(&mut input);
    input
}

fn third_party_only_client() -> Arc<dyn LlmClient> {
    let s6 = s6_true_positive_text();
    let s8 = s8_ranked_json();
    client_with(full_table(S4_EMPTY, &s6, &s8))
}

fn chunk(id: &str, files: &[&str], specialist: Option<&str>) -> Chunk {
    Chunk {
        id: id.to_string(),
        size: appsec_model::ChunkSize::Medium,
        risk_rank: 1,
        files: files.iter().map(|f| f.to_string()).collect(),
        focus_entry_points: Vec::new(),
        hypothesis: String::new(),
        related_cves: Vec::new(),
        threat_id: None,
        languages: Vec::new(),
        specialist: specialist.map(str::to_string),
        path_funcs: Vec::new(),
        source_ref: String::new(),
        sink_ref: String::new(),
        sink_cwe: Vec::new(),
        shard_id: String::new(),
    }
}

fn one_dollar_of_gpt_4o() -> Usage {
    Usage {
        input_tokens: 200_000,
        output_tokens: 50_000,
        cache_creation_input_tokens: 0,
        cache_read_input_tokens: 0,
        reasoning_output_tokens: 0,
    }
}

fn empty_metrics_inputs() -> (ContextPackage, TaskManifest) {
    (
        ContextPackage::default(),
        TaskManifest {
            chunks: Vec::new(),
            rationale: String::new(),
            unreachable_files: Vec::new(),
        },
    )
}

fn cost_metrics(
    repo_root: &Path,
    tokens_by_phase: &BTreeMap<String, PhaseUsage>,
    unpriced_models: Vec<String>,
) -> ScanMetrics {
    let (ctx, manifest) = empty_metrics_inputs();
    build_metrics(
        &ctx,
        &manifest,
        repo_root,
        "demo",
        "01932f1a-7c3d-7000-8000-0123456789ab",
        "2024-01-01T00:00:00Z",
        "2024-01-01T00:00:10Z",
        0,
        0,
        0,
        0,
        &BTreeMap::new(),
        tokens_by_phase,
        unpriced_models,
        BTreeMap::new(),
        None,
    )
}

use appsec_model::{Finding, RankedFinding as RF, Severity, VulnClass};
use appsec_sandbox_tools::SandboxTools;

mod app_profile;
mod diff_scope;
mod metrics;
mod remediate;
mod run_scan;
mod spend;
mod stop_after;
mod third_party;

fn s10_finding(cvss: Option<f64>) -> Finding {
    Finding {
        provider_origins: Vec::new(),
        component: None,
        chunk_id: "chunk-01".to_string(),
        file: "app.py".to_string(),
        line_start: 1,
        line_end: 2,
        vuln_class: VulnClass::Injection,
        cwe: Some("CWE-89".to_string()),
        title: "SQLi".to_string(),
        impact: String::new(),
        description: "desc".to_string(),
        exploit_scenario: String::new(),
        preconditions: Vec::new(),
        recommendation: String::new(),
        code_snippet: "x = 1".to_string(),
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
        cvss_score: cvss,
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

fn s10_ranked(cvss: Option<f64>) -> RF {
    RF {
        finding: s10_finding(cvss),
        severity: Severity::High,
        exploitability_notes: String::new(),
    }
}

fn s10_report(repo: &Path, findings: Vec<RF>, git_sha: Option<String>) -> FinalReport {
    FinalReport {
        repo_identity: None,
        provider_ledger: Default::default(),
        repo_root: repo.display().to_string(),
        repo_name: None,
        git_sha,
        findings,
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

fn s10_verdict_json() -> String {
    json!({
        "finding_index": 1, "verdict": "Fixed",
        "gates": {"source": "pass", "sink": "pass", "missing_control": "pass"},
        "root_cause": "x", "changes": [], "remaining_risks": [],
        "recommendations": [], "summary": "s",
    })
    .to_string()
}

struct S10Client;
#[async_trait]
impl LlmClient for S10Client {
    async fn chat(&self, _request: &ChatRequest) -> Result<ChatResponse, LlmError> {
        Ok(ChatResponse {
            content: vec![ContentBlock::Text(s10_verdict_json())],
            stop_reason: StopReason::EndTurn,
            usage: Usage::default(),
        })
    }
}

struct FailingClient;
#[async_trait]
impl LlmClient for FailingClient {
    async fn chat(&self, _request: &ChatRequest) -> Result<ChatResponse, LlmError> {
        Err(LlmError::ConnectionError {
            message: "provider down".to_string(),
        })
    }
}

fn s10_config() -> RemediateConfig {
    let mut step10 = appsec_stage_s10::Step10Config::new("test-model");
    step10.max_transient_retries = 0;
    step10.retry_backoff_base = std::time::Duration::ZERO;
    RemediateConfig {
        step10,
        top: None,
        top_default: None,
        force: false,
        resume: false,
        isolated: false,
    }
}

fn expect_processed(
    o: &appsec_stage_s10::RemediationOutcome,
) -> &appsec_stage_s10::RemediationRecord {
    match o {
        appsec_stage_s10::RemediationOutcome::Processed(r) => r,
        other => panic!("expected Processed, got {other:?}"),
    }
}

fn expect_failed(o: &appsec_stage_s10::RemediationOutcome) -> &str {
    match o {
        appsec_stage_s10::RemediationOutcome::Failed { error, .. } => error,
        other => panic!("expected Failed, got {other:?}"),
    }
}

struct S10AndS11Client {
    remediate_turn: Mutex<u32>,
}

impl S10AndS11Client {
    fn new() -> Self {
        S10AndS11Client {
            remediate_turn: Mutex::new(0),
        }
    }
}

fn s11_all_pass_gates_json() -> String {
    json!({
        "gates": [
            {"gate_name": "root_cause", "status": "pass", "summary": "ok"},
            {"gate_name": "instance_coverage", "status": "pass", "summary": "ok"},
            {"gate_name": "no_new_vulnerabilities", "status": "pass", "summary": "ok"},
            {"gate_name": "security_best_practices", "status": "pass", "summary": "ok"},
        ]
    })
    .to_string()
}

#[async_trait]
impl LlmClient for S10AndS11Client {
    async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, LlmError> {
        let system = request.system.as_deref().unwrap_or("");
        if system.contains("REMEDIATION agent") {
            let mut turn = self.remediate_turn.lock().unwrap();
            *turn += 1;
            if *turn == 1 {
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
        Ok(ChatResponse {
            content: vec![ContentBlock::Text(s11_all_pass_gates_json())],
            stop_reason: StopReason::EndTurn,
            usage: Usage::default(),
        })
    }
}

struct S10SucceedsS11GradesNotFixedClient {
    remediate_turn: Mutex<u32>,
}

#[async_trait]
impl LlmClient for S10SucceedsS11GradesNotFixedClient {
    async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, LlmError> {
        let system = request.system.as_deref().unwrap_or("");
        if system.contains("REMEDIATION agent") {
            let mut turn = self.remediate_turn.lock().unwrap();
            *turn += 1;
            if *turn == 1 {
                return Ok(ChatResponse {
                    content: vec![ContentBlock::ToolUse {
                        id: "1".to_string(),
                        name: "Write".to_string(),
                        input: json!({"path": "app.py", "content": "print('bad fix')\n"}),
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
        let failed = json!({
            "gates": [
                {"gate_name": "root_cause", "status": "fail", "summary": "not addressed"},
                {"gate_name": "instance_coverage", "status": "fail", "summary": "missed"},
                {"gate_name": "no_new_vulnerabilities", "status": "fail", "summary": "worse"},
                {"gate_name": "security_best_practices", "status": "fail", "summary": "no"},
            ]
        })
        .to_string();
        Ok(ChatResponse {
            content: vec![ContentBlock::Text(failed)],
            stop_reason: StopReason::EndTurn,
            usage: Usage::default(),
        })
    }
}

fn is_git_worktree(root: &Path) -> bool {
    std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["rev-parse", "--is-inside-work-tree"])
        .output()
        .is_ok_and(|out| out.status.success())
}

struct S10SucceedsS11FailsClient {
    remediate_turn: Mutex<u32>,
}

impl S10SucceedsS11FailsClient {
    fn new() -> Self {
        S10SucceedsS11FailsClient {
            remediate_turn: Mutex::new(0),
        }
    }
}

#[async_trait]
impl LlmClient for S10SucceedsS11FailsClient {
    async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, LlmError> {
        let system = request.system.as_deref().unwrap_or("");
        if system.contains("REMEDIATION agent") {
            let mut turn = self.remediate_turn.lock().unwrap();
            *turn += 1;
            if *turn == 1 {
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
        Err(LlmError::ConnectionError {
            message: "s11 down".to_string(),
        })
    }
}

fn s11_config() -> appsec_stage_s11::Step11Config {
    let mut cfg = appsec_stage_s11::Step11Config::new("test-model");
    cfg.max_transient_retries = 0;
    cfg.retry_backoff_base = std::time::Duration::ZERO;
    cfg
}

struct MultiFindingClient {
    write_count: Mutex<u32>,
}

impl MultiFindingClient {
    fn new() -> Self {
        MultiFindingClient {
            write_count: Mutex::new(0),
        }
    }
}

#[async_trait]
impl LlmClient for MultiFindingClient {
    async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, LlmError> {
        let system = request.system.as_deref().unwrap_or("");
        if system.contains("REMEDIATION agent") {
            let already_wrote = request.messages.iter().any(|m| {
                m.content
                    .iter()
                    .any(|c| matches!(c, ContentBlock::ToolResult { .. }))
            });
            if !already_wrote {
                let mut n = self.write_count.lock().unwrap();
                *n += 1;
                return Ok(ChatResponse {
                    content: vec![ContentBlock::ToolUse {
                        id: "1".to_string(),
                        name: "Write".to_string(),
                        input: json!({
                            "path": "app.py",
                            "content": format!("print({n})\n"),
                        }),
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
        Ok(ChatResponse {
            content: vec![ContentBlock::Text(s11_all_pass_gates_json())],
            stop_reason: StopReason::EndTurn,
            usage: Usage::default(),
        })
    }
}

fn appsec_orchestrator_remediate_outcome_fixture(
    record: appsec_stage_s10::RemediationRecord,
    pan: &str,
) -> RemediateOutcome {
    RemediateOutcome {
        refused: None,
        outcomes: vec![
            appsec_stage_s10::RemediationOutcome::Processed(Box::new(record)),
            appsec_stage_s10::RemediationOutcome::Failed {
                finding_index: 2,
                error: format!("tool output leaked {pan}"),
            },
        ],
        validations: vec![Some(appsec_validation_scoring::ValidationScore {
            raw_score: 1.0,
            fix_status: appsec_validation_scoring::FixVerdict::Fixed,
            justification: format!("confirmed fix; saw {pan} in the old diff"),
            gate_results: vec![appsec_validation_scoring::GateResult {
                gate_name: appsec_validation_scoring::GateName::RootCause,
                status: appsec_validation_scoring::GateStatus::Pass,
                summary: format!("root cause addressed, old value {pan}"),
                details: format!("full detail mentioning {pan}"),
                evidence: vec![appsec_validation_scoring::Evidence {
                    file: "app.py".to_string(),
                    line: Some(10),
                    snippet: format!("KEY = \"{pan}\""),
                }],
                confidence: Some(appsec_validation_scoring::SynthesisConfidence::High),
            }],
            has_critical_failure: false,
        })],
        validation_failures: 0,
    }
}

struct S10AltClient;
#[async_trait]
impl LlmClient for S10AltClient {
    async fn chat(&self, _request: &ChatRequest) -> Result<ChatResponse, LlmError> {
        let verdict = json!({
            "finding_index": 1, "verdict": "Not Fixed",
            "gates": {"source": "fail", "sink": "fail", "missing_control": "fail"},
            "root_cause": "x", "changes": [], "remaining_risks": [],
            "recommendations": [], "summary": "s",
        })
        .to_string();
        Ok(ChatResponse {
            content: vec![ContentBlock::Text(verdict)],
            stop_reason: StopReason::EndTurn,
            usage: Usage::default(),
        })
    }
}

struct S10EditingClient {
    turn: Mutex<u32>,
}

impl S10EditingClient {
    fn new() -> Self {
        S10EditingClient {
            turn: Mutex::new(0),
        }
    }
}

#[async_trait]
impl LlmClient for S10EditingClient {
    async fn chat(&self, _request: &ChatRequest) -> Result<ChatResponse, LlmError> {
        let mut turn = self.turn.lock().unwrap();
        *turn += 1;
        if *turn == 1 {
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
        Ok(ChatResponse {
            content: vec![ContentBlock::Text(verdict)],
            stop_reason: StopReason::EndTurn,
            usage: Usage::default(),
        })
    }
}

#[derive(Default)]
struct SpyCheckpointStore {
    registered_app_id: Mutex<Option<Option<String>>>,
}

impl appsec_checkpoint::CheckpointStore for SpyCheckpointStore {
    fn save(
        &self,
        _run_id: &str,
        _step: &str,
        _payload: &[u8],
    ) -> Result<(), appsec_checkpoint::CheckpointError> {
        Ok(())
    }

    fn load(&self, _run_id: &str, _step: &str) -> Option<Vec<u8>> {
        None
    }

    fn register_run(
        &self,
        _run_id: &str,
        _repo_root: &str,
        _repo_name: Option<&str>,
        app_id: Option<&str>,
    ) {
        *self.registered_app_id.lock().unwrap() = Some(app_id.map(str::to_string));
    }
}

fn patched_git_repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let run = |args: &[&str]| {
        std::process::Command::new("git")
            .arg("-C")
            .arg(dir.path())
            .args(args)
            .output()
            .unwrap()
    };
    run(&["init", "-q"]);
    std::fs::write(dir.path().join("app.py"), "print('original')\n").unwrap();
    run(&["add", "-A"]);
    run(&[
        "-c",
        "user.email=test@test.com",
        "-c",
        "user.name=test",
        "commit",
        "-q",
        "-m",
        "x",
    ]);
    std::fs::write(dir.path().join("app.py"), "print('a bad fix')\n").unwrap();
    dir
}

fn validated_record(files: &[&str]) -> appsec_stage_s10::RemediationRecord {
    appsec_stage_s10::RemediationRecord {
        finding_index: 1,
        finding_id: "abc123".to_string(),
        verdict: appsec_stage_s10::RemediationVerdict {
            finding_index: 1,
            verdict: appsec_stage_s10::Verdict::Fixed,
            gates: appsec_stage_s10::Gates::default(),
            root_cause: String::new(),
            changes: files
                .iter()
                .map(|f| appsec_stage_s10::Change {
                    file: (*f).to_string(),
                    summary: "s".to_string(),
                })
                .collect(),
            remaining_risks: Vec::new(),
            recommendations: Vec::new(),
            summary: String::new(),
        },
        policy_action: None,
        policy_reason: None,
        final_verdict: None,
        policy_reverted: Vec::new(),
        policy_matched_globs: Vec::new(),
        diff: Some("d".to_string()),
    }
}

fn score_of(
    status: appsec_validation_scoring::FixVerdict,
) -> appsec_validation_scoring::ValidationScore {
    appsec_validation_scoring::ValidationScore {
        raw_score: 0.0,
        fix_status: status,
        justification: String::new(),
        gate_results: Vec::new(),
        has_critical_failure: false,
    }
}

fn baseline_of(file: &str, content: &str) -> appsec_stage_s10::Baseline {
    let mut baseline = appsec_stage_s10::Baseline::default();
    baseline.merge_originals([(file.to_string(), Some(content.as_bytes().to_vec()))]);
    baseline
}

fn run_rollback(
    repo: &Path,
    files: &[&str],
    baseline: Option<&appsec_stage_s10::Baseline>,
    status: appsec_validation_scoring::FixVerdict,
    step10: &appsec_stage_s10::Step10Config,
) -> appsec_stage_s10::RemediationRecord {
    let mut record = validated_record(files);
    revert_if_validation_failed(
        repo,
        &mut record,
        baseline,
        &BTreeMap::new(),
        &score_of(status),
        step10,
    );
    record
}
