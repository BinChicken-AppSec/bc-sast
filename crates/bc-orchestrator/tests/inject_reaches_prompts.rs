//! End-to-end proof that injected external context actually *reaches the
//! prompts*, not just the `ScanInput` struct.
//!
//! Every consuming prompt section was ported long before anything filled
//! `ScanInput::known_cves` / `design_controls`, so a unit test of
//! `bc_orchestrator::inject` alone would have passed just as happily while
//! the whole plane stayed dead. This test closes that loop: it writes a
//! real CVE feed and controls file, loads them through the public loaders,
//! runs a full scan against a recording LLM client, and asserts the exact
//! strings the Python original renders appear in the prompts that were
//! actually sent — S1's "Known CVEs already filed" block
//! (`s1_preprocess.py:1144`), and S3's `KNOWN CVEs … DO NOT REDISCOVER` /
//! `DESIGN CONTROLS` context blocks (`models.py:925-932`).

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bc_llm_client::{
    ChatRequest, ChatResponse, ContentBlock, LlmClient, LlmError, StopReason, ToolExecutor,
    ToolSpec, Usage,
};
use bc_orchestrator::inject::{load_design_controls, load_known_cves};
use bc_orchestrator::{run_scan, ScanConfig, ScanInput};
use bc_stage_s0::Step0Config;
use bc_stage_s1::Step1Config;
use bc_stage_s2::Step2Config;
use bc_stage_s3::Step3Config;
use bc_stage_s4::Step4Config;
use bc_stage_s5::Step5Config;
use bc_stage_s6::Step6Config;
use bc_stage_s7::Step7Config;
use bc_stage_s8::Step8Config;
use serde_json::{json, Value};

/// Records the concatenated user-message text of every request, keyed by
/// nothing at all — the assertions search the whole transcript, since the
/// point is "did this string reach *some* model call", and which stage
/// emitted it is already pinned by the surrounding block text.
struct RecordingClient {
    seen: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl LlmClient for RecordingClient {
    async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, LlmError> {
        let mut user_text = String::new();
        for m in &request.messages {
            for block in &m.content {
                if let ContentBlock::Text(t) = block {
                    user_text.push_str(t);
                    user_text.push('\n');
                }
            }
        }
        self.seen.lock().unwrap().push(user_text);

        // Deliberately garbage for every stage: S1 and S3 both degrade to
        // their deterministic fallbacks, which is fine — the prompt was
        // still *built and sent*, which is the whole assertion. Returning
        // a valid S1 ContextPackage instead would only add coupling to
        // schemas this test does not care about.
        let system = request.system.as_deref().unwrap_or("");
        let text = if system.contains("second-opinion reviewer") {
            "no verdict".to_string()
        } else {
            "{}".to_string()
        };
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
                name: (*name).to_string(),
                description: String::new(),
                parameters: json!({}),
            })
            .collect()
    }
    fn execute(&self, _name: &str, _args: &Value) -> String {
        String::new()
    }
}

fn scan_config() -> ScanConfig {
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
    let mut step7 = Step7Config::new("m");
    step7.semantic = false;
    step7.retry_backoff_base = std::time::Duration::ZERO;
    let mut step8 = Step8Config::new("m");
    step8.retry_backoff_base = std::time::Duration::ZERO;
    ScanConfig {
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
        pricing: bc_orchestrator::pricing::PricingConfig::default(),
    }
}

fn scan_input(
    repo: &std::path::Path,
    cves: Vec<bc_model::Cve>,
    controls: Vec<bc_model::Control>,
) -> ScanInput {
    ScanInput {
        repo_root: repo.to_path_buf(),
        repo_name: "demo".to_string(),
        known_cves: cves,
        design_controls: controls,
        application_id: None,
        cmdb_path: None,
        git_sha_override: None,
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

#[tokio::test]
async fn loaded_cves_and_controls_render_into_the_prompts_that_are_actually_sent() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("app.py"),
        "def handler(request):\n    q = request.GET['q']\n    cur.execute(q)\n",
    )
    .unwrap();

    let feed = dir.path().join("known_cves.json");
    std::fs::write(
        &feed,
        r#"{"cves":[{"id":"CVE-2024-EXAMPLE","summary":"Heap overflow in parse_header()"}]}"#,
    )
    .unwrap();
    let controls_file = dir.path().join("design_controls.yaml");
    std::fs::write(
        &controls_file,
        "controls:\n  - name: api-gateway-auth\n    kind: auth\n    protects:\n      - \"src/handlers/**\"\n    notes: JWT at the edge.\n",
    )
    .unwrap();

    let cves = load_known_cves(&feed).unwrap();
    let controls = load_design_controls(&controls_file).unwrap();
    assert_eq!(cves.len(), 1);
    assert_eq!(controls.len(), 1);

    let seen = Arc::new(Mutex::new(Vec::new()));
    let client = Arc::new(RecordingClient {
        seen: Arc::clone(&seen),
    });
    run_scan(
        client,
        Arc::new(NoTools),
        scan_input(dir.path(), cves, controls),
        scan_config(),
        None,
    )
    .await
    .unwrap();

    let transcript = seen.lock().unwrap().join("\n----\n");

    // S1's repo-mapping prompt (`s1_preprocess.py:1144`).
    assert!(
        transcript.contains("Known CVEs already filed"),
        "S1 prompt missing the known-CVE block:\n{transcript}"
    );
    assert!(
        transcript.contains("  - CVE-2024-EXAMPLE: Heap overflow in parse_header()"),
        "the loaded CVE never reached a prompt:\n{transcript}"
    );

    // S3's context block (`models.py:925-932`) — proves the value survives
    // S1's ContextPackage assembly, not just S1's own prompt.
    assert!(
        transcript.contains("KNOWN CVEs (1) — DO NOT REDISCOVER:"),
        "S3 context block missing the known-CVE section:\n{transcript}"
    );
    assert!(
        transcript.contains("DESIGN CONTROLS (1):"),
        "S3 context block missing the design-controls section:\n{transcript}"
    );
    assert!(
        transcript.contains("api-gateway-auth"),
        "the loaded control never reached a prompt:\n{transcript}"
    );
}
