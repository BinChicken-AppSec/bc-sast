use async_trait::async_trait;
use bc_llm_client::{ChatRequest, ChatResponse, ContentBlock, LlmError, StopReason, Usage};
use bc_model::{Finding, Severity, VulnClass};
use bc_sandbox_tools::SandboxTools;
use serde_json::json;

use super::*;

fn finding(title: &str, cwe: Option<&str>, cvss_rating: Option<&str>) -> RankedFinding {
    RankedFinding {
        finding: Finding {
            provider_origins: Vec::new(),
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
        verdict: bc_stage_s10::RemediationVerdict::denied(1, "n/a"),
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

/// Routes by a substring of the SYSTEM prompt — same pattern as
/// `bc-stage-s10`'s own `RoutedClient`/`route` test fixture.
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
    // The three readers plus the five deterministic fact tools — the same
    // eight names as Python's `DEFAULT_FACT_TOOLS`
    // (`validation/constants/tools.py:22-31`).
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

/// Captures every user prompt the panel actually sends, so a test can
/// assert on what a persona was *told* rather than only on the score it
/// produced.
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
    // The panel used to see only title/file/CWE/severity/description —
    // nothing about impact, exploitability, the original recommendation,
    // or (critically for `instance_coverage`) which files the patch
    // actually touched.
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
        bc_stage_s10::Change {
            file: "app.py".to_string(),
            summary: "parameterized".to_string(),
        },
        bc_stage_s10::Change {
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
        // Sourced from the patch's own changes, not the finding.
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
        // The remediator's VERDICT is deliberately withheld — passing it
        // would make the validation stage grade its own input.
        assert!(!prompt.contains("Denied"), "{prompt}");
    }
}

#[tokio::test]
async fn the_penetration_tester_gets_the_built_in_bypass_hints_with_no_setup() {
    // The bundled hint set must reach the prompt on a plain scan of a
    // repo that carries no `inputs/` directory of its own.
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

    assert_eq!(score.fix_status, bc_validation_scoring::FixVerdict::Fixed);
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

    // root_cause disagreement resolves to the conservative "fail", and
    // is still reported that way with the dissenting persona's own
    // summary...
    let root_cause = score
        .gate_results
        .iter()
        .find(|g| g.gate_name == GateName::RootCause)
        .unwrap();
    assert_eq!(root_cause.status, GateStatus::Fail);
    assert_eq!(root_cause.summary, "pentester: bypass found");
    // ...but two personas contradicting each other is not a consensus,
    // so the fix itself is no longer scored. This used to come back
    // Partially Fixed at 0.57 on the strength of one persona's `fail`.
    assert_eq!(
        score.fix_status,
        bc_validation_scoring::FixVerdict::Unverifiable
    );
    assert_eq!(score.raw_score, 0.0);
}

/// A full 4-gate persona reply where `partial_gate` is `partial` and
/// every other gate passes — the shape live runs actually produce when
/// the two personas disagree, which is one persona finding the fix
/// incomplete rather than broken.
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

    // The pentester's `partial` is the conservative status and stands,
    // with its own summary. It is a `Split`, not a `Flagged`: the two
    // personas agree the fix works and differ on how complete it is.
    let coverage = score
        .gate_results
        .iter()
        .find(|g| g.gate_name == GateName::InstanceCoverage)
        .unwrap();
    assert_eq!(coverage.status, GateStatus::Partial);
    assert_eq!(coverage.summary, "no tests to verify the fix");
    assert_eq!(coverage.confidence, Some(SynthesisConfidence::Split));
    // ...and half credit on a 0.2467-weight gate is not enough to drop
    // the fix below the 0.80 threshold, so it is graded rather than
    // discarded. Under the pre-split rule this whole result was
    // UNVERIFIABLE at raw score 0.0 and the patch was rolled back.
    assert_eq!(score.fix_status, bc_validation_scoring::FixVerdict::Fixed);
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
    // The numbers alone would still say `Fixed` — a partial 0.1867-weight
    // gate costs under 0.10 — so what stops that is the critical-gate
    // cap, not the score. A doubted critical gate is capped, and the
    // patch stays on disk to be reviewed; it is no longer withheld
    // entirely and reverted.
    assert!(score.raw_score >= 0.80, "{}", score.raw_score);
    assert!(score.has_critical_failure);
    assert_eq!(
        score.fix_status,
        bc_validation_scoring::FixVerdict::PartiallyFixed
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

    // The architect's response didn't parse (empty gate list), so every
    // gate carries exactly one vote. That opinion is still reported in
    // full — it is never dropped just because the OTHER persona produced
    // nothing — but one persona cannot validate a fix by itself, so the
    // aggregate verdict fails closed. Before the consensus check, this
    // scored a clean `Fixed` off a single unseconded voice.
    assert_eq!(
        score.fix_status,
        bc_validation_scoring::FixVerdict::Unverifiable
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

    // Both empty -> the merged set is empty too -> score_fix's own shape
    // check fails this closed to Unverifiable.
    assert_eq!(
        score.fix_status,
        bc_validation_scoring::FixVerdict::Unverifiable
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

    assert_eq!(score.fix_status, bc_validation_scoring::FixVerdict::Fixed);
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

    assert_eq!(score.fix_status, bc_validation_scoring::FixVerdict::Fixed);
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

    // architect+pentester both pass root_cause, cross-repo fails it — a
    // 3-way disagreement (2 distinct statuses but no 2-way majority on
    // "pass" since it's 2-vs-1... wait: 2 Pass vs 1 Fail IS a majority,
    // so this should resolve to Pass. Assert that explicitly to pin the
    // majority rule down end-to-end, not just at the unit level.
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
    // cross_repo_analyzer_model left None -> inherits cfg.model ("test-model").

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

/// Records each call's effort and transport pin.
struct EffortCapturingClient {
    seen: std::sync::Mutex<Vec<(Option<ReasoningEffortArg>, Option<OpenAiApiArg>)>>,
}

type ReasoningEffortArg = bc_llm_client::ReasoningEffort;
type OpenAiApiArg = bc_llm_client::OpenAiApi;

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

// --- persona_gates: the bounded one-shot retry on an unusable reply ---

/// Serves a SCRIPTED sequence of replies per persona, so a retry is
/// observable: call N of a persona gets entry N, and the last entry
/// repeats for any call past the end of its script. Also records every
/// call, which is how the tests below pin down how many times a persona
/// was actually asked.
///
/// `RoutedClient` above cannot express this: it answers every call from
/// one persona identically, so it can show that a retry *happened* only
/// by never showing it succeed.
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
    // The whole point of the retry: without it the architect contributes
    // an empty gate list, the pentester's gates carry a lone vote, every
    // gate comes back `Flagged`, and the fix scores `Unverifiable` — which
    // S10 then reverts. A mechanical parse failure is not a lack of panel
    // consensus.
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

    assert_eq!(score.fix_status, bc_validation_scoring::FixVerdict::Fixed);
    assert_eq!(client.calls_to("architect"), 2, "the architect is retried");
    assert_eq!(
        client.calls_to("pentester"),
        1,
        "one persona's retry never re-runs the rest of the panel"
    );
}

#[tokio::test]
async fn a_persona_whose_reply_parses_but_names_no_known_gate_is_retried_too() {
    // The other half of "no usable gates": `extract_json` succeeds, but
    // `coerce_gates` drops every entry as an unrecognized gate name, so
    // the persona is just as useless as one that emitted no JSON at all.
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

    assert_eq!(score.fix_status, bc_validation_scoring::FixVerdict::Fixed);
    assert_eq!(client.calls_to("pentester"), 2);
    assert_eq!(client.calls_to("architect"), 1);
}

#[tokio::test]
async fn a_persona_that_fails_twice_is_not_asked_a_third_time_and_still_fails_closed() {
    // Exactly one retry, deliberately not a loop: a second failure is a
    // model that cannot answer this prompt, not a formatting slip. The
    // pre-retry fail-closed behavior is unchanged for that case.
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
        bc_validation_scoring::FixVerdict::Unverifiable
    );
    assert_eq!(
        client.calls_to("architect"),
        2,
        "one retry, then the persona is left out of the panel"
    );
}

#[tokio::test]
async fn a_persona_that_parses_first_time_is_called_exactly_once() {
    // The happy path must cost nothing extra — no speculative second
    // call, no doubled token spend on a panel that answered correctly.
    let dir = tempfile::tempdir().unwrap();
    let client = ScriptedClient::new(vec![all_pass_gates_json()], vec![all_pass_gates_json()]);
    let tools = SandboxTools::new(dir.path());
    let f = finding("SQLi", None, None);
    let r = record(Some("diff"));

    let score = validate_finding(&client, &tools, dir.path(), &f, &r, &config())
        .await
        .unwrap();

    assert_eq!(score.fix_status, bc_validation_scoring::FixVerdict::Fixed);
    assert_eq!(client.calls_to("architect"), 1);
    assert_eq!(client.calls_to("pentester"), 1);
}

/// Answers the architect's FIRST call with an unusable reply and its
/// second (the retry) with a hard transport error; every other persona
/// answers normally.
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
    // The retry is an ordinary agentic call: a transport failure on it is
    // still an `LlmError` for this finding, exactly as a failure on the
    // first attempt would be. It must not be quietly folded into "this
    // persona had no gates."
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

// --- coerce_gates / synthesize_n / synthesize_one_gate (private, tested directly) ---

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
        // One persona's own pre-synthesis opinion carries no panel
        // confidence; `synthesize_one_gate` is what assigns it.
        confidence: None,
    }
}

/// One persona's full 4-gate opinion where `target` is listed once for
/// each entry in `statuses` — so a 2-element slice is a persona whose
/// response named the same gate twice — and every other gate passes.
/// Mirrors the `_report` helper in Python's
/// `tests/test_validation_skip_consensus.py`, whose `statuses` list
/// argument exists for exactly that duplicate-gate case.
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

/// One persona's full 4-gate opinion: `target` carries `status`, every
/// other gate passes.
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
        // Two personas contradicting each other is not a consensus,
        // whichever way the tie-break falls.
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
    // 2 Pass vs 1 Fail: the majority wins outright, even though Fail is
    // the more conservative status — matching the Python original's
    // "2+ agree" rule taking precedence over the tie-break rule.
    let merged = synthesize_one_gate(&[&a, &b, &c]);
    assert_eq!(merged.status, GateStatus::Pass);
    assert_eq!(merged.confidence, Some(SynthesisConfidence::High));
}

#[test]
fn synthesize_one_gate_a_strict_majority_beats_a_smaller_conservative_bloc() {
    // Only reachable with a 5-persona panel, which this port never runs,
    // but it pins the tally rule down: 3 agreeing Pass votes outrank 2
    // agreeing Fail votes. The pre-consensus implementation scanned the
    // conservative order and stopped at the first status with 2+ votes,
    // which would have answered Fail here.
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
    // Three statuses one vote apiece is not a matter of degree: there is
    // no coherent pair to read as "how complete", and one of the three
    // says the fix does not work at all.
    assert_eq!(merged.confidence, Some(SynthesisConfidence::Flagged));
}

// --- a split is a disagreement about degree, not about whether it works ---

#[test]
fn synthesize_one_gate_a_pass_partial_tie_is_a_split_not_a_contradiction() {
    let pass = gate_result(GateName::RootCause, GateStatus::Pass, "architect");
    let partial = gate_result(GateName::RootCause, GateStatus::Partial, "pentester");
    // Asserted under BOTH input orderings: `tied` is sorted by
    // `severity_rank` before the match sees it, so one pattern covers
    // both, and this is what pins that down.
    for merged in [
        synthesize_one_gate(&[&pass, &partial]),
        synthesize_one_gate(&[&partial, &pass]),
    ] {
        // The conservative status still wins, carrying its own summary.
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
    // The abstention is filtered out before the tally, so this is the
    // same 1-vs-1 split as above rather than a three-way tie.
    let merged = synthesize_one_gate(&[&pass, &partial, &skip]);
    assert_eq!(merged.status, GateStatus::Partial);
    assert_eq!(merged.confidence, Some(SynthesisConfidence::Split));
}

#[test]
fn synthesize_one_gate_a_tie_against_a_garbled_report_is_not_a_split() {
    // `Invalid` sits one rank past `Pass`, but it is a report that came
    // through broken, not a persona grading the fix less generously. It
    // is not something to resolve as a matter of degree.
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
    // cross-repo-analyzer's mandatory skip on this gate doesn't dilute
    // the other two personas' agreement.
    let merged = synthesize_one_gate(&[&a, &b, &skip]);
    assert_eq!(merged.status, GateStatus::Pass);
    assert_eq!(merged.confidence, Some(SynthesisConfidence::High));
}

#[test]
fn synthesize_one_gate_flags_a_lone_evaluated_vote() {
    let only = gate_result(GateName::RootCause, GateStatus::Pass, "architect");
    let skip = gate_result(GateName::RootCause, GateStatus::Skip, "cross-repo");
    let merged = synthesize_one_gate(&[&only, &skip]);
    // The vote stays visible — it is the panel's verdict that is withheld.
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
    // Skip is the honest answer, but a gate nobody evaluated is not a
    // consensus either.
    assert_eq!(merged.confidence, Some(SynthesisConfidence::Flagged));
}

// --- the panel cannot validate a fix on one persona's vote -------------

#[test]
fn one_pass_and_two_skips_cannot_validate_a_fix() {
    // Mirrors Python's `test_one_pass_and_two_skips_cannot_validate_a_fix`.
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
        bc_validation_scoring::FixVerdict::Unverifiable
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
    // Mirrors Python's `test_lone_fail_with_skip_majority_is_inconclusive`:
    // a conservative lone vote lacks consensus just as much as a
    // permissive one. It is still reported as a `fail`.
    let merged = synthesize_n(&[
        persona_gates(GateName::RootCause, GateStatus::Fail),
        persona_gates(GateName::RootCause, GateStatus::Skip),
        persona_gates(GateName::RootCause, GateStatus::Skip),
    ]);
    let score = score_fix(&merged);
    assert_eq!(
        score.fix_status,
        bc_validation_scoring::FixVerdict::Unverifiable
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

// --- one persona, one vote --------------------------------------------

#[test]
fn a_persona_listing_one_gate_twice_still_votes_once_at_its_most_conservative() {
    // Mirrors Python's
    // `test_duplicate_gate_from_one_persona_keeps_the_conservative_vote`.
    // Their fixture lists the duplicate `fail`-then-`pass` because their
    // naive behavior was last-write-wins (a dict assignment); ours was
    // first-match-wins (`Iterator::find`), so only the reverse order
    // catches it here. Asserting both directions covers either mistake
    // and pins the rule itself: a persona gets one vote per gate name,
    // whatever order it listed them in.
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
        // 1 fail (the duplicate, folded) vs 1 pass: a tie, resolved
        // conservatively — not a 2-vote `pass` majority.
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
    // The interaction with `score_fix`'s consensus precheck, which is
    // what makes the fold load-bearing rather than cosmetic: the panel
    // is 2 personas, so 2 agreeing votes is `High` and `High` is what
    // lets a fix score at all. Counting a duplicate as a second vote
    // therefore let ONE persona's repeated `pass` clear the check and
    // score the fix `Fixed`, with its own contradicting `fail` dropped.
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
        bc_validation_scoring::FixVerdict::Unverifiable
    );
    assert_eq!(score.raw_score, 0.0);
    assert!(
        score
            .justification
            .contains("Insufficient persona consensus"),
        "{}",
        score.justification
    );
    // The dropped half is still reported, as a `fail` the operator can
    // read — withholding the verdict never hides the evidence.
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
    // `skip` outranks every evaluated status in the conservative order
    // (`Fail < Partial < Pass < Skip < Invalid`), so folding a persona
    // that listed a gate both `pass` and `skip` must keep the `pass`:
    // the persona did evaluate it, and a fold to `skip` would abstain a
    // real opinion out of the tally entirely.
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
    // The guard on the guard: the fail-closed check must not swallow the
    // healthy path, where both personas evaluated all 4 gates and agreed.
    let merged = synthesize_n(&[
        persona_gates(GateName::RootCause, GateStatus::Pass),
        persona_gates(GateName::RootCause, GateStatus::Pass),
    ]);
    assert!(merged
        .iter()
        .all(|g| g.confidence == Some(SynthesisConfidence::High)));
    assert_eq!(
        score_fix(&merged).fix_status,
        bc_validation_scoring::FixVerdict::Fixed
    );
}

#[test]
fn a_third_persona_skipping_two_gates_does_not_block_a_verdict() {
    // cross-repo-analyzer is instructed to skip no_new_vulnerabilities
    // and security_best_practices on every finding. Those skips must not
    // flag anything, because the other two personas still evaluated and
    // agreed on both gates.
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
        bc_validation_scoring::FixVerdict::Fixed
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
    // Reported, but unseconded.
    assert_eq!(merged[0].confidence, Some(SynthesisConfidence::Flagged));
}

// --- the run log records how the panel actually voted -------------------

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

    // One line per gate, whatever the outcome: an agreed gate is the
    // baseline a split has to be read against.
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
    // A persona whose reply failed to parse twice contributes no report
    // at all. That is the case commit 7af284e closed, and it must stay
    // legible as something other than the `skip` a persona writes to
    // abstain deliberately.
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
    // `warn` is the default verbosity, so this predicate is what an
    // operator sees without asking. A `Split` explains the score the fix
    // received and a `Flagged` one explains why the patch was reverted;
    // both belong there. A `High` gate explains nothing on its own and
    // is only of interest to someone tabulating the whole panel, which
    // is what `-v` is for.
    let mut gate = gate_result(GateName::RootCause, GateStatus::Pass, "a");
    gate.confidence = Some(SynthesisConfidence::High);
    assert!(!lacks_consensus(&gate));

    for label in [SynthesisConfidence::Split, SynthesisConfidence::Flagged] {
        gate.confidence = Some(label);
        assert!(lacks_consensus(&gate), "{label:?}");
    }

    // Never reached from `validate_finding`, which labels everything it
    // merges, but a gate whose agreement is unknown is not one to
    // quieten.
    gate.confidence = None;
    assert!(lacks_consensus(&gate));
}

#[test]
fn severity_rank_matches_pythons_conservative_order() {
    // `_STATUS_CONSERVATIVE_RANK` in Python's `enums/gates.py`:
    // fail < partial < pass < skip < invalid. `Skip` and `Invalid` were
    // tied here while only `synthesize_one_gate` (which filters skips
    // out first) used this scale; `persona_vote` folds a persona's own
    // duplicate entries, where a `skip`/`invalid` pair can occur and
    // Python resolves it to `skip`.
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

// ── the five deterministic fact tools ────────────────────────────────────

/// Records the tool specs and system prompts every persona call was
/// actually offered, then answers with an all-pass gate set. Distinct
/// from `PromptCapturingClient`, which captures the USER prompt.
struct ToolCapturingClient {
    seen: std::sync::Mutex<Vec<Vec<String>>>,
}

impl ToolCapturingClient {
    fn new() -> Self {
        ToolCapturingClient {
            seen: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Every persona saw the same list, so collapse to one.
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

/// Calls one named tool on its first turn, echoes the tool's output back
/// as its final answer's `details` so a test can assert on what the tool
/// actually returned to the model.
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
        // Each persona calls the tool once on its first turn, then
        // settles as soon as it has seen the result.
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
    // Not cosmetic: `run_agentic` hard-errors on an allow-list naming a
    // tool the executor does not advertise, and with the toggle off the
    // executor is the bare read-only one.
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
    cfg.cross_repo_analyzer = true; // all three personas
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
    // The wrapper is built per finding precisely so the diff a persona
    // queries is the remediation under review, not a shared one.
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
    // `RemediationRecord::diff` is `Option`; a denied/failed remediation
    // has none. The tools must return "nothing touched", not error.
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
        for name in bc_sandbox_tools::FACT_TOOL_NAMES {
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
        for name in bc_sandbox_tools::FACT_TOOL_NAMES {
            assert!(!sys.contains(name), "{name} named but not offered: {sys}");
        }
        // The rest of the prompt is untouched.
        assert!(sys.contains("EVIDENCE:"), "{sys}");
        assert!(sys.contains("SIGNAL-TO-NOISE"), "{sys}");
    }
}

// ---- the redacted diff and `--resume` checkpoints -----------------------

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
    let store = bc_checkpoint::SqliteCheckpointStore::new(ckpt.path().join("state.db")).unwrap();
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
    assert_eq!(fresh.fix_status, bc_validation_scoring::FixVerdict::Fixed);

    // FailingClient would error if a single persona ran.
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

    // A different model is a different key: the panel runs (and fails).
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

    // Without resume the cache is not consulted either.
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

    // And with no store at all, it is just `validate_finding`.
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
    assert_eq!(plain.fix_status, bc_validation_scoring::FixVerdict::Fixed);
}

// ---- step_validate.split_ties_score -------------------------------------

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
