use appsec_llm_client::{ChatRequest, ChatResponse, ContentBlock, LlmError, StopReason, Usage};
use appsec_model::{Finding, Severity, VulnClass};
use appsec_sandbox_tools::SandboxTools;
use async_trait::async_trait;
use serde_json::json;

use super::*;

fn finding(title: &str, cwe: Option<&str>, cvss_rating: Option<&str>) -> RankedFinding {
    RankedFinding {
        finding: Finding {
            provider_origins: Vec::new(),
            component: None,
            chunk_id: "c1".to_string(),
            file: "app.py".to_string(),
            line_start: 1,
            line_end: 1,
            vuln_class: VulnClass::Injection,
            cwe: cwe.map(str::to_string),
            title: title.to_string(),
            impact: String::new(),
            description: "user input reaches a raw query".to_string(),
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
            cvss_rating: cvss_rating.map(str::to_string),
            verifier_reasoning: String::new(),
            vsvs_vector: None,
            vsvs_score: None,
            vsvs_rating: None,
            offensive_priority: None,
            offensive_reason: String::new(),
            related_cwes: Vec::new(),
        },
        severity: Severity::High,
        exploitability_notes: String::new(),
    }
}

fn record(diff: Option<&str>) -> RemediationRecord {
    RemediationRecord {
        finding_index: 1,
        finding_id: "fid1".to_string(),
        verdict: appsec_stage_s10::RemediationVerdict::denied(1, "n/a"),
        policy_action: None,
        policy_reason: None,
        final_verdict: None,
        policy_reverted: Vec::new(),
        policy_matched_globs: Vec::new(),
        diff: diff.map(str::to_string),
    }
}

fn config() -> Step11Config {
    let mut cfg = Step11Config::new("test-model");
    cfg.max_transient_retries = 0;
    cfg.retry_backoff_base = std::time::Duration::ZERO;
    cfg
}

fn all_pass_gates_json() -> String {
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

struct RoutedClient {
    architect_reply: String,
    pentester_reply: String,
    cross_repo_reply: Option<String>,
}

impl RoutedClient {
    fn two_persona(architect_reply: impl Into<String>, pentester_reply: impl Into<String>) -> Self {
        RoutedClient {
            architect_reply: architect_reply.into(),
            pentester_reply: pentester_reply.into(),
            cross_repo_reply: None,
        }
    }

    fn three_persona(
        architect_reply: impl Into<String>,
        pentester_reply: impl Into<String>,
        cross_repo_reply: impl Into<String>,
    ) -> Self {
        RoutedClient {
            architect_reply: architect_reply.into(),
            pentester_reply: pentester_reply.into(),
            cross_repo_reply: Some(cross_repo_reply.into()),
        }
    }
}

#[async_trait]
impl LlmClient for RoutedClient {
    async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, LlmError> {
        let system = request.system.as_deref().unwrap_or("");
        let text = if system.contains("security architect") {
            self.architect_reply.clone()
        } else if system.contains("penetration tester") {
            self.pentester_reply.clone()
        } else if system.contains("cross-repository consistency") {
            self.cross_repo_reply
                .clone()
                .expect("cross-repo-analyzer prompt reached but no cross_repo_reply configured")
        } else {
            panic!("unrecognized system prompt in test fixture: {system}");
        };
        Ok(ChatResponse {
            content: vec![ContentBlock::Text(text)],
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

#[test]
fn step11_config_new_has_documented_defaults() {
    let cfg = Step11Config::new("gpt-x");
    assert_eq!(cfg.model, "gpt-x");
    assert_eq!(cfg.max_turns, 50);
    assert_eq!(
        cfg.allowed_tools,
        vec![
            "Read",
            "Glob",
            "Grep",
            "DiffTouched",
            "ChangedLines",
            "DiffImpactMap",
            "PatternScan",
            "TestInventory"
        ]
    );
    assert_eq!(cfg.max_transient_retries, 4);
    assert_eq!(cfg.max_context_shrinks, 16);
    assert_eq!(cfg.retry_backoff_base, std::time::Duration::from_secs(10));
    assert_eq!(cfg.max_findings, Some(20));
    assert!(!cfg.allow_repo_hints);
    assert_eq!(cfg.security_architect_model, None);
    assert_eq!(cfg.penetration_tester_model, None);
    assert_eq!(cfg.cross_repo_analyzer_model, None);
    assert!(!cfg.cross_repo_analyzer);
    assert!(cfg.fact_tools);
}

#[test]
fn agentic_config_forwards_every_retry_and_shrink_knob() {
    let mut cfg = Step11Config::new("gpt-x");
    cfg.max_turns = 7;
    cfg.max_transient_retries = 8;
    cfg.max_context_shrinks = 9;
    cfg.retry_backoff_base = std::time::Duration::from_secs(11);
    let built = agentic_config(&cfg, "sys prompt".to_string(), None);
    assert_eq!(built.model, "gpt-x");
    assert_eq!(built.system_prompt, Some("sys prompt".to_string()));
    assert_eq!(built.max_turns, 7);
    assert_eq!(built.max_transient_retries, 8);
    assert_eq!(built.max_context_shrinks, 9);
    assert_eq!(built.retry_backoff_base, std::time::Duration::from_secs(11));
}

#[test]
fn agentic_config_uses_the_persona_model_override_when_set() {
    let cfg = Step11Config::new("shared-model");
    let built = agentic_config(&cfg, "sys prompt".to_string(), Some("persona-model"));
    assert_eq!(built.model, "persona-model");
}

#[test]
fn agentic_config_falls_back_to_the_shared_model_when_no_override_is_set() {
    let cfg = Step11Config::new("shared-model");
    let built = agentic_config(&cfg, "sys prompt".to_string(), None);
    assert_eq!(built.model, "shared-model");
}

struct PromptCapturingClient {
    seen: std::sync::Mutex<Vec<String>>,
}

#[async_trait]
impl LlmClient for PromptCapturingClient {
    async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, LlmError> {
        let mut user = String::new();
        for m in &request.messages {
            for block in &m.content {
                if let ContentBlock::Text(t) = block {
                    user.push_str(t);
                }
            }
        }
        self.seen.lock().unwrap().push(user);
        Ok(ChatResponse {
            content: vec![ContentBlock::Text(all_pass_gates_json())],
            stop_reason: StopReason::EndTurn,
            usage: Usage::default(),
        })
    }
}

#[tokio::test]
async fn every_persona_is_told_the_full_finding_and_the_remediators_unverified_claim() {
    let dir = tempfile::tempdir().unwrap();
    let client = PromptCapturingClient {
        seen: std::sync::Mutex::new(Vec::new()),
    };
    let tools = SandboxTools::new(dir.path());

    let mut f = finding("SQLi", Some("CWE-89"), Some("HIGH"));
    f.finding.impact = "full database read".to_string();
    f.finding.exploit_scenario = "send q=' OR 1=1".to_string();
    f.finding.preconditions = vec!["reachable unauthenticated".to_string()];
    f.finding.recommendation = "use a parameterized query".to_string();
    f.finding.cvss_score = Some(8.1);
    f.finding.cvss_vector = Some("CVSS:3.1/AV:N".to_string());
    f.finding.line_start = 42;

    let mut r = record(Some("diff --git a/app.py b/app.py\n+fixed"));
    r.verdict.root_cause = "string-concatenated SQL".to_string();
    r.verdict.remaining_risks = vec!["sibling handler untouched".to_string()];
    r.verdict.changes = vec![
        appsec_stage_s10::Change {
            file: "app.py".to_string(),
            summary: "parameterized".to_string(),
        },
        appsec_stage_s10::Change {
            file: "db.py".to_string(),
            summary: "helper".to_string(),
        },
    ];

    validate_finding(&client, &tools, dir.path(), &f, &r, &config())
        .await
        .unwrap();

    let seen = client.seen.lock().unwrap();
    assert_eq!(seen.len(), 2, "both personas must be prompted");
    for prompt in seen.iter() {
        assert!(prompt.contains("Source: app.py:42"), "{prompt}");
        assert!(prompt.contains("CVSS: 8.1 (CVSS:3.1/AV:N)"), "{prompt}");
        assert!(prompt.contains("Affected files: app.py, db.py"), "{prompt}");
        assert!(prompt.contains("Impact: full database read"), "{prompt}");
        assert!(
            prompt.contains("Exploit scenario: send q=' OR 1=1"),
            "{prompt}"
        );
        assert!(prompt.contains("reachable unauthenticated"), "{prompt}");
        assert!(
            prompt.contains("Original recommendation: use a parameterized query"),
            "{prompt}"
        );
        assert!(
            prompt.contains("REMEDIATOR'S UNVERIFIED CLAIM (context only, NOT evidence)"),
            "{prompt}"
        );
        assert!(
            prompt.contains("Stated root cause: string-concatenated SQL"),
            "{prompt}"
        );
        assert!(prompt.contains("sibling handler untouched"), "{prompt}");
        assert!(!prompt.contains("Denied"), "{prompt}");
    }
}

#[tokio::test]
async fn the_penetration_tester_gets_the_built_in_bypass_hints_with_no_setup() {
    let dir = tempfile::tempdir().unwrap();
    let client = PromptCapturingClient {
        seen: std::sync::Mutex::new(Vec::new()),
    };
    let tools = SandboxTools::new(dir.path());
    let f = finding("SQLi", Some("CWE-89"), None);
    let r = record(Some("diff"));

    validate_finding(&client, &tools, dir.path(), &f, &r, &config())
        .await
        .unwrap();

    let seen = client.seen.lock().unwrap();
    let with_hints: Vec<&String> = seen
        .iter()
        .filter(|p| p.contains("ADVERSARIAL BYPASS HINTS FOR THIS CWE"))
        .collect();
    assert_eq!(
        with_hints.len(),
        1,
        "exactly the penetration-tester gets hints: {seen:?}"
    );
    assert!(with_hints[0].contains("stacked queries"), "{with_hints:?}");
}

#[tokio::test]
async fn validate_finding_with_both_personas_agreeing_scores_fixed() {
    let dir = tempfile::tempdir().unwrap();
    let client = RoutedClient::two_persona(all_pass_gates_json(), all_pass_gates_json());
    let tools = SandboxTools::new(dir.path());
    let f = finding("SQLi", Some("CWE-89"), Some("HIGH"));
    let r = record(Some("diff --git a/app.py b/app.py\n+fixed"));

    let score = validate_finding(&client, &tools, dir.path(), &f, &r, &config())
        .await
        .unwrap();

    assert_eq!(
        score.fix_status,
        appsec_validation_scoring::FixVerdict::Fixed
    );
}

#[tokio::test]
async fn validate_finding_with_disagreeing_personas_takes_the_conservative_status() {
    let dir = tempfile::tempdir().unwrap();
    let disagreement = json!({
        "gates": [
            {"gate_name": "root_cause", "status": "pass", "summary": "architect: ok"},
            {"gate_name": "instance_coverage", "status": "pass", "summary": "ok"},
            {"gate_name": "no_new_vulnerabilities", "status": "pass", "summary": "ok"},
            {"gate_name": "security_best_practices", "status": "pass", "summary": "ok"},
        ]
    })
    .to_string();
    let pentester_disagrees = json!({
        "gates": [
            {"gate_name": "root_cause", "status": "fail", "summary": "pentester: bypass found"},
            {"gate_name": "instance_coverage", "status": "pass", "summary": "ok"},
            {"gate_name": "no_new_vulnerabilities", "status": "pass", "summary": "ok"},
            {"gate_name": "security_best_practices", "status": "pass", "summary": "ok"},
        ]
    })
    .to_string();
    let client = RoutedClient::two_persona(disagreement, pentester_disagrees);
    let tools = SandboxTools::new(dir.path());
    let f = finding("SQLi", Some("CWE-89"), None);
    let r = record(Some("diff"));

    let score = validate_finding(&client, &tools, dir.path(), &f, &r, &config())
        .await
        .unwrap();

    let root_cause = score
        .gate_results
        .iter()
        .find(|g| g.gate_name == GateName::RootCause)
        .unwrap();
    assert_eq!(root_cause.status, GateStatus::Fail);
    assert_eq!(root_cause.summary, "pentester: bypass found");
    assert_eq!(
        score.fix_status,
        appsec_validation_scoring::FixVerdict::Unverifiable
    );
    assert_eq!(score.raw_score, 0.0);
}

fn one_partial_gates_json(partial_gate: &str) -> String {
    let gates: Vec<serde_json::Value> = [
        "root_cause",
        "instance_coverage",
        "no_new_vulnerabilities",
        "security_best_practices",
    ]
    .into_iter()
    .map(|name| {
        if name == partial_gate {
            json!({"gate_name": name, "status": "partial", "summary": "no tests to verify the fix"})
        } else {
            json!({"gate_name": name, "status": "pass", "summary": "ok"})
        }
    })
    .collect();
    json!({ "gates": gates }).to_string()
}

#[tokio::test]
async fn validate_finding_scores_a_split_on_a_non_critical_gate_rather_than_withholding_it() {
    let dir = tempfile::tempdir().unwrap();
    let client = RoutedClient::two_persona(
        all_pass_gates_json(),
        one_partial_gates_json("instance_coverage"),
    );
    let tools = SandboxTools::new(dir.path());
    let f = finding("SQLi", Some("CWE-89"), Some("HIGH"));
    let r = record(Some("diff --git a/app.py b/app.py\n+fixed"));

    let score = validate_finding(&client, &tools, dir.path(), &f, &r, &config())
        .await
        .unwrap();

    let coverage = score
        .gate_results
        .iter()
        .find(|g| g.gate_name == GateName::InstanceCoverage)
        .unwrap();
    assert_eq!(coverage.status, GateStatus::Partial);
    assert_eq!(coverage.summary, "no tests to verify the fix");
    assert_eq!(coverage.confidence, Some(SynthesisConfidence::Split));
    assert_eq!(
        score.fix_status,
        appsec_validation_scoring::FixVerdict::Fixed
    );
    assert!(score.raw_score >= 0.80, "{}", score.raw_score);
}

#[tokio::test]
async fn validate_finding_caps_a_split_on_a_critical_gate_instead_of_withholding_it() {
    let dir = tempfile::tempdir().unwrap();
    let client = RoutedClient::two_persona(
        all_pass_gates_json(),
        one_partial_gates_json("no_new_vulnerabilities"),
    );
    let tools = SandboxTools::new(dir.path());
    let f = finding("SQLi", Some("CWE-89"), Some("HIGH"));
    let r = record(Some("diff"));

    let score = validate_finding(&client, &tools, dir.path(), &f, &r, &config())
        .await
        .unwrap();

    let critical = score
        .gate_results
        .iter()
        .find(|g| g.gate_name == GateName::NoNewVulnerabilities)
        .unwrap();
    assert_eq!(critical.status, GateStatus::Partial);
    assert_eq!(critical.confidence, Some(SynthesisConfidence::Split));
    assert!(score.raw_score >= 0.80, "{}", score.raw_score);
    assert!(score.has_critical_failure);
    assert_eq!(
        score.fix_status,
        appsec_validation_scoring::FixVerdict::PartiallyFixed
    );
}

#[tokio::test]
async fn validate_finding_propagates_an_llm_error() {
    let dir = tempfile::tempdir().unwrap();
    let tools = SandboxTools::new(dir.path());
    let f = finding("SQLi", None, None);
    let r = record(None);

    let result = validate_finding(&FailingClient, &tools, dir.path(), &f, &r, &config()).await;

    assert!(result.is_err());
}

#[tokio::test]
async fn validate_finding_reports_the_one_persona_that_parsed_but_cannot_verdict_on_it() {
    let dir = tempfile::tempdir().unwrap();
    let client = RoutedClient::two_persona("not json at all", all_pass_gates_json());
    let tools = SandboxTools::new(dir.path());
    let f = finding("SQLi", None, None);
    let r = record(Some("diff"));

    let score = validate_finding(&client, &tools, dir.path(), &f, &r, &config())
        .await
        .unwrap();

    assert_eq!(
        score.fix_status,
        appsec_validation_scoring::FixVerdict::Unverifiable
    );
    assert_eq!(score.raw_score, 0.0);
    assert!(
        score
            .justification
            .contains("Insufficient persona consensus"),
        "{}",
        score.justification
    );
    assert!(score
        .gate_results
        .iter()
        .all(|g| g.status == GateStatus::Pass));
}

#[tokio::test]
async fn validate_finding_is_unverifiable_when_neither_persona_parses() {
    let dir = tempfile::tempdir().unwrap();
    let client = RoutedClient::two_persona("not json", "also not json");
    let tools = SandboxTools::new(dir.path());
    let f = finding("SQLi", None, None);
    let r = record(Some("diff"));

    let score = validate_finding(&client, &tools, dir.path(), &f, &r, &config())
        .await
        .unwrap();

    assert_eq!(
        score.fix_status,
        appsec_validation_scoring::FixVerdict::Unverifiable
    );
}

#[tokio::test]
async fn validate_finding_with_no_diff_still_runs_the_panel() {
    let dir = tempfile::tempdir().unwrap();
    let client = RoutedClient::two_persona(all_pass_gates_json(), all_pass_gates_json());
    let tools = SandboxTools::new(dir.path());
    let f = finding("SQLi", None, None);
    let r = record(None);

    let score = validate_finding(&client, &tools, dir.path(), &f, &r, &config())
        .await
        .unwrap();

    assert_eq!(
        score.fix_status,
        appsec_validation_scoring::FixVerdict::Fixed
    );
}

#[tokio::test]
async fn validate_finding_runs_the_cross_repo_analyzer_persona_when_enabled() {
    let dir = tempfile::tempdir().unwrap();
    let cross_repo_gates = json!({
        "gates": [
            {"gate_name": "root_cause", "status": "pass", "summary": "cross-repo: consistent"},
            {"gate_name": "instance_coverage", "status": "pass", "summary": "ok"},
            {"gate_name": "no_new_vulnerabilities", "status": "skip", "summary": "n/a"},
            {"gate_name": "security_best_practices", "status": "skip", "summary": "n/a"},
        ]
    })
    .to_string();
    let client = RoutedClient::three_persona(
        all_pass_gates_json(),
        all_pass_gates_json(),
        cross_repo_gates,
    );
    let tools = SandboxTools::new(dir.path());
    let f = finding("SQLi", None, None);
    let r = record(Some("diff"));

    let mut cfg = config();
    cfg.cross_repo_analyzer = true;

    let score = validate_finding(&client, &tools, dir.path(), &f, &r, &cfg)
        .await
        .unwrap();

    assert_eq!(
        score.fix_status,
        appsec_validation_scoring::FixVerdict::Fixed
    );
}

#[tokio::test]
async fn validate_finding_cross_repo_analyzer_disagreement_pulls_the_verdict_down() {
    let dir = tempfile::tempdir().unwrap();
    let cross_repo_gates = json!({
        "gates": [
            {"gate_name": "root_cause", "status": "fail", "summary": "cross-repo: diverges in the other service"},
            {"gate_name": "instance_coverage", "status": "pass", "summary": "ok"},
            {"gate_name": "no_new_vulnerabilities", "status": "skip", "summary": "n/a"},
            {"gate_name": "security_best_practices", "status": "skip", "summary": "n/a"},
        ]
    })
    .to_string();
    let client = RoutedClient::three_persona(
        all_pass_gates_json(),
        all_pass_gates_json(),
        cross_repo_gates,
    );
    let tools = SandboxTools::new(dir.path());
    let f = finding("SQLi", None, None);
    let r = record(Some("diff"));

    let mut cfg = config();
    cfg.cross_repo_analyzer = true;

    let score = validate_finding(&client, &tools, dir.path(), &f, &r, &cfg)
        .await
        .unwrap();

    let root_cause = score
        .gate_results
        .iter()
        .find(|g| g.gate_name == GateName::RootCause)
        .unwrap();
    assert_eq!(root_cause.status, GateStatus::Pass);
}

struct ModelCapturingClient {
    seen: std::sync::Mutex<Vec<(String, String)>>,
}

#[async_trait]
impl LlmClient for ModelCapturingClient {
    async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, LlmError> {
        let system = request.system.as_deref().unwrap_or("");
        let persona = if system.contains("security architect") {
            "architect"
        } else if system.contains("penetration tester") {
            "pentester"
        } else if system.contains("cross-repository consistency") {
            "cross-repo"
        } else {
            panic!("unrecognized system prompt in test fixture: {system}");
        };
        self.seen
            .lock()
            .unwrap()
            .push((persona.to_string(), request.model.clone()));
        Ok(ChatResponse {
            content: vec![ContentBlock::Text(all_pass_gates_json())],
            stop_reason: StopReason::EndTurn,
            usage: Usage::default(),
        })
    }
}

#[tokio::test]
async fn validate_finding_routes_each_persona_to_its_own_model_override() {
    let dir = tempfile::tempdir().unwrap();
    let client = ModelCapturingClient {
        seen: std::sync::Mutex::new(Vec::new()),
    };
    let tools = SandboxTools::new(dir.path());
    let f = finding("SQLi", None, None);
    let r = record(Some("diff"));

    let mut cfg = config();
    cfg.cross_repo_analyzer = true;
    cfg.security_architect_model = Some("architect-model".to_string());
    cfg.penetration_tester_model = Some("pentester-model".to_string());

    validate_finding(&client, &tools, dir.path(), &f, &r, &cfg)
        .await
        .unwrap();

    let seen = client.seen.lock().unwrap();
    let model_for = |persona: &str| {
        seen.iter()
            .find(|(p, _)| p == persona)
            .map(|(_, m)| m.clone())
    };
    assert_eq!(model_for("architect"), Some("architect-model".to_string()));
    assert_eq!(model_for("pentester"), Some("pentester-model".to_string()));
    assert_eq!(model_for("cross-repo"), Some("test-model".to_string()));
}

struct EffortCapturingClient {
    seen: std::sync::Mutex<Vec<(Option<ReasoningEffortArg>, Option<OpenAiApiArg>)>>,
}

type ReasoningEffortArg = appsec_llm_client::ReasoningEffort;
type OpenAiApiArg = appsec_llm_client::OpenAiApi;

#[async_trait]
impl LlmClient for EffortCapturingClient {
    async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, LlmError> {
        self.seen
            .lock()
            .unwrap()
            .push((request.reasoning_effort, request.openai_api));
        Ok(ChatResponse {
            content: vec![ContentBlock::Text(all_pass_gates_json())],
            stop_reason: StopReason::EndTurn,
            usage: Usage::default(),
        })
    }
}

#[test]
fn the_panel_defaults_to_pythons_high_effort() {
    assert_eq!(
        Step11Config::new("m").reasoning_effort,
        Some(ReasoningEffortArg::High)
    );
    assert_eq!(Step11Config::new("m").openai_api, None);
}

#[tokio::test]
async fn every_persona_carries_the_configured_effort_and_transport_pin() {
    let dir = tempfile::tempdir().unwrap();
    let client = EffortCapturingClient {
        seen: std::sync::Mutex::new(Vec::new()),
    };
    let tools = SandboxTools::new(dir.path());
    let mut cfg = config();
    cfg.reasoning_effort = Some(ReasoningEffortArg::XHigh);
    cfg.openai_api = Some(OpenAiApiArg::Chat);

    validate_finding(
        &client,
        &tools,
        dir.path(),
        &finding("SQLi", None, None),
        &record(Some("diff")),
        &cfg,
    )
    .await
    .unwrap();

    let seen = client.seen.lock().unwrap();
    assert!(!seen.is_empty());
    assert!(seen
        .iter()
        .all(|s| *s == (Some(ReasoningEffortArg::XHigh), Some(OpenAiApiArg::Chat))));
}

struct ScriptedClient {
    architect: Vec<String>,
    pentester: Vec<String>,
    calls: std::sync::Mutex<Vec<&'static str>>,
}

impl ScriptedClient {
    fn new(architect: Vec<String>, pentester: Vec<String>) -> Self {
        ScriptedClient {
            architect,
            pentester,
            calls: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn calls_to(&self, persona: &str) -> usize {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|p| **p == persona)
            .count()
    }
}

#[async_trait]
impl LlmClient for ScriptedClient {
    async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, LlmError> {
        let system = request.system.as_deref().unwrap_or("");
        let (persona, script) = if system.contains("security architect") {
            ("architect", &self.architect)
        } else if system.contains("penetration tester") {
            ("pentester", &self.pentester)
        } else {
            panic!("unrecognized system prompt in test fixture: {system}");
        };
        let mut calls = self.calls.lock().unwrap();
        let nth = calls.iter().filter(|p| **p == persona).count();
        calls.push(persona);
        drop(calls);
        let text = script[nth.min(script.len() - 1)].clone();
        Ok(ChatResponse {
            content: vec![ContentBlock::Text(text)],
            stop_reason: StopReason::EndTurn,
            usage: Usage::default(),
        })
    }
}

#[tokio::test]
async fn a_persona_whose_first_reply_is_unparseable_is_retried_and_the_panel_recovers() {
    let dir = tempfile::tempdir().unwrap();
    let client = ScriptedClient::new(
        vec!["not json at all".to_string(), all_pass_gates_json()],
        vec![all_pass_gates_json()],
    );
    let tools = SandboxTools::new(dir.path());
    let f = finding("SQLi", None, None);
    let r = record(Some("diff"));

    let score = validate_finding(&client, &tools, dir.path(), &f, &r, &config())
        .await
        .unwrap();

    assert_eq!(
        score.fix_status,
        appsec_validation_scoring::FixVerdict::Fixed
    );
    assert_eq!(client.calls_to("architect"), 2, "the architect is retried");
    assert_eq!(
        client.calls_to("pentester"),
        1,
        "one persona's retry never re-runs the rest of the panel"
    );
}

#[tokio::test]
async fn a_persona_whose_reply_parses_but_names_no_known_gate_is_retried_too() {
    let dir = tempfile::tempdir().unwrap();
    let gateless = json!({
        "gates": [{"gate_name": "made_up_gate", "status": "pass", "summary": "ok"}]
    })
    .to_string();
    let client = ScriptedClient::new(
        vec![all_pass_gates_json()],
        vec![gateless, all_pass_gates_json()],
    );
    let tools = SandboxTools::new(dir.path());
    let f = finding("SQLi", None, None);
    let r = record(Some("diff"));

    let score = validate_finding(&client, &tools, dir.path(), &f, &r, &config())
        .await
        .unwrap();

    assert_eq!(
        score.fix_status,
        appsec_validation_scoring::FixVerdict::Fixed
    );
    assert_eq!(client.calls_to("pentester"), 2);
    assert_eq!(client.calls_to("architect"), 1);
}

#[tokio::test]
async fn a_persona_that_fails_twice_is_not_asked_a_third_time_and_still_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let client = ScriptedClient::new(
        vec!["not json at all".to_string()],
        vec![all_pass_gates_json()],
    );
    let tools = SandboxTools::new(dir.path());
    let f = finding("SQLi", None, None);
    let r = record(Some("diff"));

    let score = validate_finding(&client, &tools, dir.path(), &f, &r, &config())
        .await
        .unwrap();

    assert_eq!(
        score.fix_status,
        appsec_validation_scoring::FixVerdict::Unverifiable
    );
    assert_eq!(
        client.calls_to("architect"),
        2,
        "one retry, then the persona is left out of the panel"
    );
}

#[tokio::test]
async fn a_persona_that_parses_first_time_is_called_exactly_once() {
    let dir = tempfile::tempdir().unwrap();
    let client = ScriptedClient::new(vec![all_pass_gates_json()], vec![all_pass_gates_json()]);
    let tools = SandboxTools::new(dir.path());
    let f = finding("SQLi", None, None);
    let r = record(Some("diff"));

    let score = validate_finding(&client, &tools, dir.path(), &f, &r, &config())
        .await
        .unwrap();

    assert_eq!(
        score.fix_status,
        appsec_validation_scoring::FixVerdict::Fixed
    );
    assert_eq!(client.calls_to("architect"), 1);
    assert_eq!(client.calls_to("pentester"), 1);
}

struct ArchitectFailsOnRetryClient {
    architect_calls: std::sync::Mutex<usize>,
}

#[async_trait]
impl LlmClient for ArchitectFailsOnRetryClient {
    async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, LlmError> {
        let system = request.system.as_deref().unwrap_or("");
        let text = if system.contains("security architect") {
            let mut calls = self.architect_calls.lock().unwrap();
            *calls += 1;
            let nth = *calls;
            drop(calls);
            if nth > 1 {
                return Err(LlmError::ConnectionError {
                    message: "provider down mid-retry".to_string(),
                });
            }
            "not json at all".to_string()
        } else {
            all_pass_gates_json()
        };
        Ok(ChatResponse {
            content: vec![ContentBlock::Text(text)],
            stop_reason: StopReason::EndTurn,
            usage: Usage::default(),
        })
    }
}

#[tokio::test]
async fn an_llm_error_raised_by_the_retry_itself_is_propagated_not_swallowed() {
    let dir = tempfile::tempdir().unwrap();
    let client = ArchitectFailsOnRetryClient {
        architect_calls: std::sync::Mutex::new(0),
    };
    let tools = SandboxTools::new(dir.path());
    let f = finding("SQLi", None, None);
    let r = record(Some("diff"));

    let result = validate_finding(&client, &tools, dir.path(), &f, &r, &config()).await;

    assert!(matches!(result, Err(LlmError::ConnectionError { .. })));
}

#[test]
fn coerce_gates_drops_an_entry_with_an_unrecognized_gate_name() {
    let data = json!({"gates": [
        {"gate_name": "branch_targeting", "status": "pass"},
        {"gate_name": "root_cause", "status": "pass", "summary": "ok"},
    ]});
    let gates = coerce_gates(&data);
    assert_eq!(gates.len(), 1);
    assert_eq!(gates[0].gate_name, GateName::RootCause);
}

#[test]
fn coerce_gates_of_a_non_object_response_is_empty() {
    assert!(coerce_gates(&json!("not an object")).is_empty());
}

#[test]
fn coerce_gates_of_a_missing_gates_field_is_empty() {
    assert!(coerce_gates(&json!({})).is_empty());
}

#[test]
fn coerce_gates_parses_evidence_entries() {
    let data = json!({"gates": [
        {"gate_name": "root_cause", "status": "pass", "evidence": [
            {"file": "a.py", "line": 10, "snippet": "x"},
            "not a mapping",
        ]},
    ]});
    let gates = coerce_gates(&data);
    assert_eq!(gates[0].evidence.len(), 1);
    assert_eq!(gates[0].evidence[0].file, "a.py");
    assert_eq!(gates[0].evidence[0].line, Some(10));
}

fn gate_result(name: GateName, status: GateStatus, summary: &str) -> GateResult {
    GateResult {
        gate_name: name,
        status,
        summary: summary.to_string(),
        evidence: Vec::new(),
        details: String::new(),
        confidence: None,
    }
}

fn persona_gates_listing(target: GateName, statuses: &[GateStatus]) -> Vec<GateResult> {
    GateName::ALL
        .into_iter()
        .flat_map(|name| {
            if name == target {
                statuses
                    .iter()
                    .map(|status| gate_result(name, *status, "target"))
                    .collect::<Vec<_>>()
            } else {
                vec![gate_result(name, GateStatus::Pass, "ok")]
            }
        })
        .collect()
}

fn persona_gates(target: GateName, status: GateStatus) -> Vec<GateResult> {
    persona_gates_listing(target, &[status])
}

#[test]
fn synthesize_one_gate_prefers_the_more_conservative_status_on_a_two_way_tie() {
    let pass = gate_result(GateName::RootCause, GateStatus::Pass, "a");
    let fail = gate_result(GateName::RootCause, GateStatus::Fail, "b");
    for merged in [
        synthesize_one_gate(&[&pass, &fail]),
        synthesize_one_gate(&[&fail, &pass]),
    ] {
        assert_eq!(merged.status, GateStatus::Fail);
        assert_eq!(merged.confidence, Some(SynthesisConfidence::Flagged));
    }
}

#[test]
fn synthesize_one_gate_keeps_the_shared_status_when_both_agree() {
    let a = gate_result(GateName::RootCause, GateStatus::Pass, "a");
    let b = gate_result(GateName::RootCause, GateStatus::Pass, "b");
    let merged = synthesize_one_gate(&[&a, &b]);
    assert_eq!(merged.status, GateStatus::Pass);
    assert_eq!(merged.summary, "a");
    assert_eq!(merged.confidence, Some(SynthesisConfidence::High));
}

#[test]
fn synthesize_one_gate_a_majority_of_two_wins_over_a_lone_dissenter() {
    let a = gate_result(GateName::RootCause, GateStatus::Pass, "architect");
    let b = gate_result(GateName::RootCause, GateStatus::Pass, "pentester");
    let c = gate_result(GateName::RootCause, GateStatus::Fail, "cross-repo");
    let merged = synthesize_one_gate(&[&a, &b, &c]);
    assert_eq!(merged.status, GateStatus::Pass);
    assert_eq!(merged.confidence, Some(SynthesisConfidence::High));
}

#[test]
fn synthesize_one_gate_a_strict_majority_beats_a_smaller_conservative_bloc() {
    let pass = gate_result(GateName::RootCause, GateStatus::Pass, "p");
    let fail = gate_result(GateName::RootCause, GateStatus::Fail, "f");
    let merged = synthesize_one_gate(&[&fail, &fail, &pass, &pass, &pass]);
    assert_eq!(merged.status, GateStatus::Pass);
    assert_eq!(merged.confidence, Some(SynthesisConfidence::High));
}

#[test]
fn synthesize_one_gate_three_way_disagreement_falls_back_to_the_most_conservative() {
    let a = gate_result(GateName::RootCause, GateStatus::Pass, "architect");
    let b = gate_result(GateName::RootCause, GateStatus::Partial, "pentester");
    let c = gate_result(GateName::RootCause, GateStatus::Fail, "cross-repo");
    let merged = synthesize_one_gate(&[&a, &b, &c]);
    assert_eq!(merged.status, GateStatus::Fail);
    assert_eq!(merged.confidence, Some(SynthesisConfidence::Flagged));
}

#[test]
fn synthesize_one_gate_a_pass_partial_tie_is_a_split_not_a_contradiction() {
    let pass = gate_result(GateName::RootCause, GateStatus::Pass, "architect");
    let partial = gate_result(GateName::RootCause, GateStatus::Partial, "pentester");
    for merged in [
        synthesize_one_gate(&[&pass, &partial]),
        synthesize_one_gate(&[&partial, &pass]),
    ] {
        assert_eq!(merged.status, GateStatus::Partial);
        assert_eq!(merged.summary, "pentester");
        assert_eq!(merged.confidence, Some(SynthesisConfidence::Split));
    }
}

#[test]
fn synthesize_one_gate_a_partial_fail_tie_is_also_a_split() {
    let partial = gate_result(GateName::RootCause, GateStatus::Partial, "architect");
    let fail = gate_result(GateName::RootCause, GateStatus::Fail, "pentester");
    for merged in [
        synthesize_one_gate(&[&partial, &fail]),
        synthesize_one_gate(&[&fail, &partial]),
    ] {
        assert_eq!(merged.status, GateStatus::Fail);
        assert_eq!(merged.summary, "pentester");
        assert_eq!(merged.confidence, Some(SynthesisConfidence::Split));
    }
}

#[test]
fn synthesize_one_gate_a_third_personas_skip_does_not_turn_a_split_into_a_tie() {
    let pass = gate_result(GateName::RootCause, GateStatus::Pass, "architect");
    let partial = gate_result(GateName::RootCause, GateStatus::Partial, "pentester");
    let skip = gate_result(GateName::RootCause, GateStatus::Skip, "cross-repo");
    let merged = synthesize_one_gate(&[&pass, &partial, &skip]);
    assert_eq!(merged.status, GateStatus::Partial);
    assert_eq!(merged.confidence, Some(SynthesisConfidence::Split));
}

#[test]
fn synthesize_one_gate_a_tie_against_a_garbled_report_is_not_a_split() {
    let pass = gate_result(GateName::RootCause, GateStatus::Pass, "architect");
    let invalid = gate_result(GateName::RootCause, GateStatus::Invalid, "pentester");
    let merged = synthesize_one_gate(&[&pass, &invalid]);
    assert_eq!(merged.status, GateStatus::Pass);
    assert_eq!(merged.confidence, Some(SynthesisConfidence::Flagged));
}

#[test]
fn synthesize_one_gate_treats_skip_as_an_abstention_not_a_vote() {
    let a = gate_result(GateName::RootCause, GateStatus::Pass, "architect");
    let b = gate_result(GateName::RootCause, GateStatus::Pass, "pentester");
    let skip = gate_result(GateName::RootCause, GateStatus::Skip, "cross-repo");
    let merged = synthesize_one_gate(&[&a, &b, &skip]);
    assert_eq!(merged.status, GateStatus::Pass);
    assert_eq!(merged.confidence, Some(SynthesisConfidence::High));
}

#[test]
fn synthesize_one_gate_flags_a_lone_evaluated_vote() {
    let only = gate_result(GateName::RootCause, GateStatus::Pass, "architect");
    let skip = gate_result(GateName::RootCause, GateStatus::Skip, "cross-repo");
    let merged = synthesize_one_gate(&[&only, &skip]);
    assert_eq!(merged.status, GateStatus::Pass);
    assert_eq!(merged.summary, "architect");
    assert_eq!(merged.confidence, Some(SynthesisConfidence::Flagged));
}

#[test]
fn synthesize_one_gate_all_skip_returns_skip() {
    let a = gate_result(
        GateName::NoNewVulnerabilities,
        GateStatus::Skip,
        "architect",
    );
    let b = gate_result(
        GateName::NoNewVulnerabilities,
        GateStatus::Skip,
        "cross-repo",
    );
    let merged = synthesize_one_gate(&[&a, &b]);
    assert_eq!(merged.status, GateStatus::Skip);
    assert_eq!(merged.confidence, Some(SynthesisConfidence::Flagged));
}

#[test]
fn one_pass_and_two_skips_cannot_validate_a_fix() {
    let merged = synthesize_n(&[
        persona_gates(GateName::RootCause, GateStatus::Pass),
        persona_gates(GateName::RootCause, GateStatus::Skip),
        persona_gates(GateName::RootCause, GateStatus::Skip),
    ]);
    let root_cause = merged
        .iter()
        .find(|g| g.gate_name == GateName::RootCause)
        .expect("root_cause was reported by every persona");
    assert_eq!(root_cause.status, GateStatus::Pass);
    assert_eq!(root_cause.confidence, Some(SynthesisConfidence::Flagged));

    let score = score_fix(&merged);
    assert_eq!(
        score.fix_status,
        appsec_validation_scoring::FixVerdict::Unverifiable
    );
    assert_eq!(score.raw_score, 0.0);
    assert!(
        score
            .justification
            .contains("Insufficient persona consensus"),
        "{}",
        score.justification
    );
}

#[test]
fn one_fail_and_two_skips_is_also_inconclusive() {
    let merged = synthesize_n(&[
        persona_gates(GateName::RootCause, GateStatus::Fail),
        persona_gates(GateName::RootCause, GateStatus::Skip),
        persona_gates(GateName::RootCause, GateStatus::Skip),
    ]);
    let score = score_fix(&merged);
    assert_eq!(
        score.fix_status,
        appsec_validation_scoring::FixVerdict::Unverifiable
    );
    assert_eq!(score.raw_score, 0.0);
    assert_eq!(
        score
            .gate_results
            .iter()
            .find(|g| g.gate_name == GateName::RootCause)
            .expect("root_cause survives into the result")
            .status,
        GateStatus::Fail
    );
}

#[test]
fn a_persona_listing_one_gate_twice_still_votes_once_at_its_most_conservative() {
    for statuses in [
        [GateStatus::Fail, GateStatus::Pass],
        [GateStatus::Pass, GateStatus::Fail],
    ] {
        let merged = synthesize_n(&[
            persona_gates_listing(GateName::NoNewVulnerabilities, &statuses),
            persona_gates(GateName::NoNewVulnerabilities, GateStatus::Pass),
        ]);
        let gate = merged
            .iter()
            .find(|g| g.gate_name == GateName::NoNewVulnerabilities)
            .expect("both personas reported no_new_vulnerabilities");
        assert_eq!(gate.status, GateStatus::Fail, "listed {statuses:?}");
        assert_eq!(
            gate.confidence,
            Some(SynthesisConfidence::Flagged),
            "listed {statuses:?}"
        );
    }
}

#[test]
fn a_duplicated_gate_cannot_manufacture_the_second_vote_that_clears_consensus() {
    let merged = synthesize_n(&[
        persona_gates_listing(
            GateName::NoNewVulnerabilities,
            &[GateStatus::Pass, GateStatus::Fail],
        ),
        persona_gates(GateName::NoNewVulnerabilities, GateStatus::Pass),
    ]);
    let score = score_fix(&merged);
    assert_eq!(
        score.fix_status,
        appsec_validation_scoring::FixVerdict::Unverifiable
    );
    assert_eq!(score.raw_score, 0.0);
    assert!(
        score
            .justification
            .contains("Insufficient persona consensus"),
        "{}",
        score.justification
    );
    assert_eq!(
        score
            .gate_results
            .iter()
            .find(|g| g.gate_name == GateName::NoNewVulnerabilities)
            .expect("no_new_vulnerabilities survives into the result")
            .status,
        GateStatus::Fail
    );
}

#[test]
fn folding_a_duplicate_prefers_an_evaluated_status_over_the_personas_own_skip() {
    let merged = synthesize_n(&[
        persona_gates_listing(GateName::RootCause, &[GateStatus::Skip, GateStatus::Pass]),
        persona_gates(GateName::RootCause, GateStatus::Pass),
    ]);
    let gate = merged
        .iter()
        .find(|g| g.gate_name == GateName::RootCause)
        .expect("both personas reported root_cause");
    assert_eq!(gate.status, GateStatus::Pass);
    assert_eq!(gate.confidence, Some(SynthesisConfidence::High));
}

#[test]
fn a_full_panel_agreeing_on_every_gate_still_scores_normally() {
    let merged = synthesize_n(&[
        persona_gates(GateName::RootCause, GateStatus::Pass),
        persona_gates(GateName::RootCause, GateStatus::Pass),
    ]);
    assert!(merged
        .iter()
        .all(|g| g.confidence == Some(SynthesisConfidence::High)));
    assert_eq!(
        score_fix(&merged).fix_status,
        appsec_validation_scoring::FixVerdict::Fixed
    );
}

#[test]
fn a_third_persona_skipping_two_gates_does_not_block_a_verdict() {
    let cross_repo: Vec<GateResult> = GateName::ALL
        .into_iter()
        .map(|name| {
            let status = match name {
                GateName::NoNewVulnerabilities | GateName::SecurityBestPractices => {
                    GateStatus::Skip
                }
                _ => GateStatus::Pass,
            };
            gate_result(name, status, "cross-repo")
        })
        .collect();
    let merged = synthesize_n(&[
        persona_gates(GateName::RootCause, GateStatus::Pass),
        persona_gates(GateName::RootCause, GateStatus::Pass),
        cross_repo,
    ]);
    assert!(merged
        .iter()
        .all(|g| g.confidence == Some(SynthesisConfidence::High)));
    assert_eq!(
        score_fix(&merged).fix_status,
        appsec_validation_scoring::FixVerdict::Fixed
    );
}

#[test]
fn synthesize_n_matches_gates_by_name_across_all_lists() {
    let architect = vec![gate_result(GateName::RootCause, GateStatus::Pass, "a")];
    let pentester = vec![gate_result(
        GateName::InstanceCoverage,
        GateStatus::Fail,
        "b",
    )];
    let merged = synthesize_n(&[architect, pentester]);
    assert_eq!(merged.len(), 2);
    assert!(merged.iter().any(|g| g.gate_name == GateName::RootCause));
    assert!(merged
        .iter()
        .any(|g| g.gate_name == GateName::InstanceCoverage));
}

#[test]
fn synthesize_n_a_gate_only_the_third_persona_reported_passes_through() {
    let architect: Vec<GateResult> = Vec::new();
    let pentester: Vec<GateResult> = Vec::new();
    let cross_repo = vec![gate_result(GateName::RootCause, GateStatus::Partial, "c")];
    let merged = synthesize_n(&[architect, pentester, cross_repo]);
    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].status, GateStatus::Partial);
    assert_eq!(merged[0].confidence, Some(SynthesisConfidence::Flagged));
}

#[test]
fn vote_lines_record_every_personas_vote_beside_the_panels_own_answer() {
    let panel = [
        persona_gates(GateName::RootCause, GateStatus::Pass),
        persona_gates(GateName::RootCause, GateStatus::Partial),
    ];
    let synthesized = synthesize_n(&panel);
    let lines = vote_lines(
        &[SECURITY_ARCHITECT, PENETRATION_TESTER],
        &panel,
        &synthesized,
    );

    assert_eq!(lines.len(), 4);
    assert!(
        lines.contains(
            &"[s11] root_cause: security-architect=pass penetration-tester=partial \
              -> partial (SPLIT)"
                .to_string()
        ),
        "{lines:?}"
    );
    assert!(
        lines.contains(
            &"[s11] instance_coverage: security-architect=pass penetration-tester=pass \
              -> pass (HIGH)"
                .to_string()
        ),
        "{lines:?}"
    );
}

#[test]
fn vote_lines_call_a_persona_that_never_reported_the_gate_absent_not_skipped() {
    let panel = [
        vec![gate_result(GateName::RootCause, GateStatus::Pass, "a")],
        Vec::new(),
    ];
    let synthesized = synthesize_n(&panel);
    let lines = vote_lines(
        &[SECURITY_ARCHITECT, PENETRATION_TESTER],
        &panel,
        &synthesized,
    );
    assert_eq!(
        lines,
        vec![
            "[s11] root_cause: security-architect=pass penetration-tester=absent \
             -> pass (FLAGGED)"
        ]
    );
}

#[test]
fn only_an_agreed_gates_vote_line_is_quiet_enough_for_info() {
    let mut gate = gate_result(GateName::RootCause, GateStatus::Pass, "a");
    gate.confidence = Some(SynthesisConfidence::High);
    assert!(!lacks_consensus(&gate));

    for label in [SynthesisConfidence::Split, SynthesisConfidence::Flagged] {
        gate.confidence = Some(label);
        assert!(lacks_consensus(&gate), "{label:?}");
    }

    gate.confidence = None;
    assert!(lacks_consensus(&gate));
}

#[test]
fn severity_rank_matches_pythons_conservative_order() {
    let ordered = [
        GateStatus::Fail,
        GateStatus::Partial,
        GateStatus::Pass,
        GateStatus::Skip,
        GateStatus::Invalid,
    ];
    for pair in ordered.windows(2) {
        assert!(
            severity_rank(pair[0]) < severity_rank(pair[1]),
            "{:?} must rank more conservative than {:?}",
            pair[0],
            pair[1]
        );
    }
}

struct ToolCapturingClient {
    seen: std::sync::Mutex<Vec<Vec<String>>>,
}

impl ToolCapturingClient {
    fn new() -> Self {
        ToolCapturingClient {
            seen: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn offered(&self) -> Vec<String> {
        let seen = self
            .seen
            .lock()
            .expect("no test thread panics while holding this");
        assert!(!seen.is_empty(), "no persona call was made");
        for names in seen.iter() {
            assert_eq!(names, &seen[0], "personas were offered different tool sets");
        }
        seen[0].clone()
    }
}

#[async_trait]
impl LlmClient for ToolCapturingClient {
    async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, LlmError> {
        self.seen
            .lock()
            .expect("no test thread panics while holding this")
            .push(request.tools.iter().map(|t| t.name.clone()).collect());
        Ok(ChatResponse {
            content: vec![ContentBlock::Text(all_pass_gates_json())],
            stop_reason: StopReason::EndTurn,
            usage: Usage::default(),
        })
    }
}

struct ToolCallingClient {
    tool: String,
    args: serde_json::Value,
    observed: std::sync::Mutex<Vec<String>>,
}

impl ToolCallingClient {
    fn new(tool: &str, args: serde_json::Value) -> Self {
        ToolCallingClient {
            tool: tool.to_string(),
            args,
            observed: std::sync::Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl LlmClient for ToolCallingClient {
    async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, LlmError> {
        for m in &request.messages {
            for block in &m.content {
                if let ContentBlock::ToolResult { content, .. } = block {
                    self.observed
                        .lock()
                        .expect("no test thread panics while holding this")
                        .push(content.clone());
                }
            }
        }
        if request.messages.iter().any(|m| {
            m.content
                .iter()
                .any(|b| matches!(b, ContentBlock::ToolResult { .. }))
        }) {
            return Ok(ChatResponse {
                content: vec![ContentBlock::Text(all_pass_gates_json())],
                stop_reason: StopReason::EndTurn,
                usage: Usage::default(),
            });
        }
        Ok(ChatResponse {
            content: vec![ContentBlock::ToolUse {
                id: "t1".to_string(),
                name: self.tool.clone(),
                input: self.args.clone(),
            }],
            stop_reason: StopReason::ToolUse,
            usage: Usage::default(),
        })
    }
}

const FIX_DIFF: &str = "\
diff --git a/app/auth.py b/app/auth.py
--- a/app/auth.py
+++ b/app/auth.py
@@ -1,3 +1,4 @@
 def login(u):
-    return query(\"SELECT \" + u)
+    return query(\"SELECT ?\", u)
+    # validated
";

#[test]
fn effective_allowed_tools_keeps_the_fact_tools_when_the_toggle_is_on() {
    let cfg = Step11Config::new("m");
    assert_eq!(effective_allowed_tools(&cfg), cfg.allowed_tools);
}

#[test]
fn effective_allowed_tools_strips_the_fact_tools_when_the_toggle_is_off() {
    let mut cfg = Step11Config::new("m");
    cfg.fact_tools = false;
    assert_eq!(effective_allowed_tools(&cfg), vec!["Read", "Glob", "Grep"]);
}

#[test]
fn effective_allowed_tools_honors_an_explicit_list_rather_than_re_adding_defaults() {
    let mut cfg = Step11Config::new("m");
    cfg.allowed_tools = vec!["Read".to_string(), "DiffImpactMap".to_string()];
    assert_eq!(effective_allowed_tools(&cfg), vec!["Read", "DiffImpactMap"]);
    cfg.fact_tools = false;
    assert_eq!(effective_allowed_tools(&cfg), vec!["Read"]);
}

#[tokio::test]
async fn every_persona_session_is_offered_the_five_fact_tools() {
    let dir = tempfile::tempdir().unwrap();
    let client = ToolCapturingClient::new();
    let tools = SandboxTools::new(dir.path());
    let mut cfg = config();
    cfg.cross_repo_analyzer = true;
    validate_finding(
        &client,
        &tools,
        dir.path(),
        &finding("SQLi", Some("CWE-89"), Some("HIGH")),
        &record(Some(FIX_DIFF)),
        &cfg,
    )
    .await
    .expect("panel succeeds");
    assert_eq!(
        client.offered(),
        vec![
            "Read",
            "Glob",
            "Grep",
            "DiffTouched",
            "ChangedLines",
            "DiffImpactMap",
            "PatternScan",
            "TestInventory"
        ]
    );
}

#[tokio::test]
async fn turning_the_toggle_off_leaves_a_persona_with_only_the_three_readers() {
    let dir = tempfile::tempdir().unwrap();
    let client = ToolCapturingClient::new();
    let tools = SandboxTools::new(dir.path());
    let mut cfg = config();
    cfg.fact_tools = false;
    validate_finding(
        &client,
        &tools,
        dir.path(),
        &finding("SQLi", Some("CWE-89"), Some("HIGH")),
        &record(Some(FIX_DIFF)),
        &cfg,
    )
    .await
    .expect("panel still succeeds without the fact tools");
    assert_eq!(client.offered(), vec!["Read", "Glob", "Grep"]);
}

#[tokio::test]
async fn a_persona_calling_diff_touched_gets_this_findings_own_diff() {
    let dir = tempfile::tempdir().unwrap();
    let client = ToolCallingClient::new("DiffTouched", json!({"file_path": "app/auth.py"}));
    let tools = SandboxTools::new(dir.path());
    validate_finding(
        &client,
        &tools,
        dir.path(),
        &finding("SQLi", Some("CWE-89"), Some("HIGH")),
        &record(Some(FIX_DIFF)),
        &config(),
    )
    .await
    .expect("panel succeeds");
    let observed = client.observed.lock().unwrap().clone();
    assert!(!observed.is_empty(), "no tool result reached the model");
    for result in observed {
        assert_eq!(result, r#"{"added_ranges":[[2,2]],"touched":true}"#);
    }
}

#[tokio::test]
async fn a_persona_calling_pattern_scan_sees_the_real_repository() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("conf.yaml"), "debug: true\n").unwrap();
    let client = ToolCallingClient::new("PatternScan", json!({"pattern_set": "insecure_value"}));
    let tools = SandboxTools::new(dir.path());
    validate_finding(
        &client,
        &tools,
        dir.path(),
        &finding("Config", Some("CWE-489"), Some("LOW")),
        &record(Some(FIX_DIFF)),
        &config(),
    )
    .await
    .expect("panel succeeds");
    let observed = client.observed.lock().unwrap().clone();
    assert!(!observed.is_empty(), "no tool result reached the model");
    for result in observed {
        assert!(result.contains(r#""file":"conf.yaml""#), "{result}");
    }
}

#[tokio::test]
async fn a_finding_with_no_diff_still_answers_every_fact_tool() {
    let dir = tempfile::tempdir().unwrap();
    let client = ToolCallingClient::new("DiffImpactMap", json!({}));
    let tools = SandboxTools::new(dir.path());
    validate_finding(
        &client,
        &tools,
        dir.path(),
        &finding("SQLi", Some("CWE-89"), Some("HIGH")),
        &record(None),
        &config(),
    )
    .await
    .expect("panel succeeds");
    for result in client.observed.lock().unwrap().iter() {
        assert_eq!(
            result,
            r#"{"files_changed":[],"trust_boundary_touched":false}"#
        );
    }
}

#[test]
fn every_persona_prompt_names_the_fact_tools_when_they_are_on() {
    for sys in [
        prompts::security_architect_system(true),
        prompts::penetration_tester_system(true),
        prompts::cross_repo_analyzer_system(true),
    ] {
        assert!(sys.contains("DETERMINISTIC FACTS FIRST"), "{sys}");
        for name in appsec_sandbox_tools::FACT_TOOL_NAMES {
            assert!(sys.contains(name), "{name} missing from: {sys}");
        }
    }
}

#[test]
fn no_persona_prompt_names_a_fact_tool_it_was_not_given() {
    for sys in [
        prompts::security_architect_system(false),
        prompts::penetration_tester_system(false),
        prompts::cross_repo_analyzer_system(false),
    ] {
        assert!(!sys.contains("DETERMINISTIC FACTS FIRST"), "{sys}");
        for name in appsec_sandbox_tools::FACT_TOOL_NAMES {
            assert!(!sys.contains(name), "{name} named but not offered: {sys}");
        }
        assert!(sys.contains("EVIDENCE:"), "{sys}");
        assert!(sys.contains("SIGNAL-TO-NOISE"), "{sys}");
    }
}

const SECRET_DIFF: &str = "\
--- a/app.py
+++ b/app.py
@@ -1 +1 @@
-password = \"hunter2hunter2\"
+password = os.environ[\"DB_PASSWORD\"]
";

#[tokio::test]
async fn the_panel_only_ever_sees_the_redacted_diff() {
    let dir = tempfile::tempdir().unwrap();
    let client = PromptCapturingClient {
        seen: std::sync::Mutex::new(Vec::new()),
    };
    let tools = SandboxTools::new(dir.path());
    validate_finding(
        &client,
        &tools,
        dir.path(),
        &finding("Hardcoded password", Some("CWE-798"), None),
        &record(Some(SECRET_DIFF)),
        &config(),
    )
    .await
    .unwrap();
    let seen = client.seen.lock().unwrap();
    assert!(!seen.is_empty());
    for prompt in seen.iter() {
        assert!(!prompt.contains("hunter2"), "{prompt}");
        assert!(
            prompt.contains("+password = os.environ[\"DB_PASSWORD\"]"),
            "{prompt}"
        );
    }
}

#[tokio::test]
async fn a_checkpointed_score_is_reused_on_resume_without_running_the_panel() {
    let dir = tempfile::tempdir().unwrap();
    let ckpt = tempfile::tempdir().unwrap();
    let store =
        appsec_checkpoint::SqliteCheckpointStore::new(ckpt.path().join("state.db")).unwrap();
    let tools = SandboxTools::new(dir.path());
    let f = finding("SQLi", Some("CWE-89"), None);
    let rec = record(Some("+fixed\n"));

    let fresh = validate_finding_checkpointed(
        &RoutedClient::two_persona(all_pass_gates_json(), all_pass_gates_json()),
        &tools,
        dir.path(),
        &f,
        &rec,
        &config(),
        Some(&store),
        "run1",
        false,
    )
    .await
    .unwrap();
    assert_eq!(
        fresh.fix_status,
        appsec_validation_scoring::FixVerdict::Fixed
    );

    let resumed = validate_finding_checkpointed(
        &FailingClient,
        &tools,
        dir.path(),
        &f,
        &rec,
        &config(),
        Some(&store),
        "run1",
        true,
    )
    .await
    .unwrap();
    assert_eq!(resumed, fresh);

    let mut other = config();
    other.model = "another-model".to_string();
    let err = validate_finding_checkpointed(
        &FailingClient,
        &tools,
        dir.path(),
        &f,
        &rec,
        &other,
        Some(&store),
        "run1",
        true,
    )
    .await;
    assert!(err.is_err());

    let err = validate_finding_checkpointed(
        &FailingClient,
        &tools,
        dir.path(),
        &f,
        &rec,
        &config(),
        Some(&store),
        "run1",
        false,
    )
    .await;
    assert!(err.is_err());

    let plain = validate_finding_checkpointed(
        &RoutedClient::two_persona(all_pass_gates_json(), all_pass_gates_json()),
        &tools,
        dir.path(),
        &f,
        &rec,
        &config(),
        None,
        "run1",
        true,
    )
    .await
    .unwrap();
    assert_eq!(
        plain.fix_status,
        appsec_validation_scoring::FixVerdict::Fixed
    );
}

#[test]
fn the_tie_policy_keeps_split_by_default_and_flags_it_when_switched_off() {
    let split = with_confidence(
        &gate_result(GateName::RootCause, GateStatus::Partial, "s"),
        SynthesisConfidence::Split,
    );
    let high = with_confidence(
        &gate_result(GateName::InstanceCoverage, GateStatus::Pass, "s"),
        SynthesisConfidence::High,
    );
    let gates = vec![split.clone(), high.clone()];
    assert_eq!(apply_tie_policy(gates.clone(), true), gates);
    let flagged = apply_tie_policy(gates, false);
    assert_eq!(flagged[0].confidence, Some(SynthesisConfidence::Flagged));
    assert_eq!(flagged[0].status, GateStatus::Partial);
    assert_eq!(flagged[1], high);
    assert!(Step11Config::new("m").split_ties_score);
}
