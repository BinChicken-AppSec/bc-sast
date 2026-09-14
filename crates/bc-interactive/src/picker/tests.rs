use std::collections::VecDeque;
use std::sync::Mutex;

use async_trait::async_trait;
use bc_checkpoint::SqliteCheckpointStore;
use bc_llm_client::{ChatRequest, ChatResponse, ContentBlock, LlmError, StopReason, Usage};
use bc_model::{Finding, RankedFinding, Severity, VulnClass};
use bc_sandbox_tools::SandboxTools;
use serde_json::json;

use crate::BlockingInput;

use super::*;

fn finding(title: &str, file: &str, severity: Severity) -> RankedFinding {
    RankedFinding {
        finding: Finding {
            provider_origins: Vec::new(),
            chunk_id: "chunk-01".to_string(),
            file: file.to_string(),
            line_start: 1,
            line_end: 2,
            vuln_class: VulnClass::Injection,
            cwe: Some("CWE-89".to_string()),
            title: title.to_string(),
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
            cvss_score: None,
            cvss_rating: None,
            verifier_reasoning: String::new(),
            vsvs_vector: None,
            vsvs_score: None,
            vsvs_rating: None,
            offensive_priority: None,
            offensive_reason: String::new(),
            related_cwes: Vec::new(),
        },
        severity,
        exploitability_notes: String::new(),
    }
}

fn verdict_json(verdict: &str) -> String {
    json!({
        "finding_index": 1,
        "verdict": verdict,
        "gates": {"source": "pass", "sink": "pass", "missing_control": "pass"},
        "root_cause": "root cause",
        "changes": [],
        "remaining_risks": [],
        "recommendations": [],
        "summary": "a summary",
    })
    .to_string()
}

struct ScriptedClient {
    replies: Mutex<VecDeque<String>>,
}

impl ScriptedClient {
    fn new(replies: Vec<String>) -> Self {
        ScriptedClient {
            replies: Mutex::new(replies.into()),
        }
    }
}

#[async_trait]
impl LlmClient for ScriptedClient {
    async fn chat(&self, _request: &ChatRequest) -> Result<ChatResponse, LlmError> {
        let text = self.replies.lock().unwrap().pop_front().unwrap_or_default();
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

fn s11_all_pass_gates_json() -> String {
    json!({"gates": [
        {"gate_name": "root_cause", "status": "pass", "summary": "ok"},
        {"gate_name": "instance_coverage", "status": "pass", "summary": "ok"},
        {"gate_name": "no_new_vulnerabilities", "status": "pass", "summary": "ok"},
        {"gate_name": "security_best_practices", "status": "pass", "summary": "ok"},
    ]})
    .to_string()
}

/// Answers S10's own SYSTEM-prompt mark with a real `Write` tool call on
/// its FIRST turn (so `capture_diff` has something real to diff — a
/// plain-text-only verdict reply, like [`ScriptedClient`]'s, never
/// touches disk) before answering with the verdict text on the next
/// turn; answers S11's two persona marks with a canned all-pass
/// response — for tests proving the picker's own `validate_enabled`
/// dispatch end to end. Mirrors the identically-shaped fixture already
/// established in `bc-orchestrator`/`bc-cli`'s own test suites.
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
                        input: json!({"path": "a.py", "content": "print('fixed')\n"}),
                    }],
                    stop_reason: StopReason::ToolUse,
                    usage: Usage::default(),
                });
            }
            let verdict = json!({
                "finding_index": 1, "verdict": "Fixed",
                "gates": {"source": "pass", "sink": "pass", "missing_control": "pass"},
                "root_cause": "x",
                "changes": [{"file": "a.py", "summary": "fixed it"}],
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

/// Same remediation behavior as [`S10AndS11Client`], but S11 fails every
/// gate, so the fix is graded `Not Fixed` — the shape the picker's
/// post-validation rollback exists for.
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
                        input: json!({"path": "a.py", "content": "print('a bad fix')\n"}),
                    }],
                    stop_reason: StopReason::ToolUse,
                    usage: Usage::default(),
                });
            }
            let verdict = json!({
                "finding_index": 1, "verdict": "Fixed",
                "gates": {"source": "pass", "sink": "pass", "missing_control": "pass"},
                "root_cause": "x",
                "changes": [{"file": "a.py", "summary": "fixed it"}],
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

/// Same remediation behavior as [`S10AndS11Client`], but the S11
/// validation call always errors — for proving a genuine validation
/// failure is counted/surfaced rather than silently indistinguishable
/// from "not selected for validation".
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
                        input: json!({"path": "a.py", "content": "print('fixed')\n"}),
                    }],
                    stop_reason: StopReason::ToolUse,
                    usage: Usage::default(),
                });
            }
            let verdict = json!({
                "finding_index": 1, "verdict": "Fixed",
                "gates": {"source": "pass", "sink": "pass", "missing_control": "pass"},
                "root_cause": "x",
                "changes": [{"file": "a.py", "summary": "fixed it"}],
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

fn s11_config() -> bc_stage_s11::Step11Config {
    let mut cfg = bc_stage_s11::Step11Config::new("test-model");
    cfg.max_transient_retries = 0;
    cfg.retry_backoff_base = std::time::Duration::ZERO;
    cfg
}

fn config() -> Step10Config {
    let mut cfg = Step10Config::new("test-model");
    cfg.max_transient_retries = 0;
    cfg.retry_backoff_base = std::time::Duration::ZERO;
    cfg
}

struct FakeTerminal {
    tty: bool,
    keys: VecDeque<std::io::Result<Key>>,
    lines: VecDeque<Option<String>>,
    frames: Vec<String>,
    written: Vec<String>,
}

impl FakeTerminal {
    fn tty(keys: Vec<std::io::Result<Key>>) -> Self {
        FakeTerminal {
            tty: true,
            keys: keys.into(),
            lines: VecDeque::new(),
            frames: Vec::new(),
            written: Vec::new(),
        }
    }

    fn prompt(lines: Vec<Option<String>>) -> Self {
        FakeTerminal {
            tty: false,
            keys: VecDeque::new(),
            lines: lines.into(),
            frames: Vec::new(),
            written: Vec::new(),
        }
    }
}

fn io_err() -> std::io::Error {
    std::io::Error::other("no more keys")
}

impl BlockingInput for FakeTerminal {
    fn read_key(&mut self) -> std::io::Result<Key> {
        self.keys.pop_front().unwrap_or_else(|| Err(io_err()))
    }

    fn read_line(&mut self, _prompt: &str) -> Option<String> {
        self.lines.pop_front().flatten()
    }
}

impl Terminal for FakeTerminal {
    fn is_tty(&self) -> bool {
        self.tty
    }

    fn draw(&mut self, frame: &str) -> std::io::Result<()> {
        self.frames.push(frame.to_string());
        Ok(())
    }

    fn write_line(&mut self, line: &str) {
        self.written.push(line.to_string());
    }
}

fn outcome_index(o: &RemediationOutcome) -> i64 {
    match o {
        RemediationOutcome::Processed(r) => r.finding_index,
        RemediationOutcome::Failed { finding_index, .. } => *finding_index,
    }
}

#[test]
fn severity_label_maps_every_variant() {
    assert_eq!(severity_label(Severity::Critical), "CRITICAL");
    assert_eq!(severity_label(Severity::High), "HIGH");
    assert_eq!(severity_label(Severity::Medium), "MEDIUM");
    assert_eq!(severity_label(Severity::Low), "LOW");
    assert_eq!(severity_label(Severity::Info), "INFO");
}

#[tokio::test]
async fn run_interactive_of_an_empty_list_is_a_no_op_and_never_touches_the_terminal() {
    let dir = tempfile::tempdir().unwrap();
    let tools = SandboxTools::new_with_write(dir.path());
    let client = FailingClient;
    let ctx = RemediationContext {
        client: &client,
        tools: &tools,
        repo: dir.path(),
        config: &config(),
        policy: None,
        checkpoint: None,
        run_id: "run1",
        validate: None,
    };
    let mut term = FakeTerminal::tty(vec![]);
    let (outcomes, _validations, _validation_failures) =
        run_interactive(&ctx, &[], &mut term).await;
    assert!(outcomes.is_empty());
    assert!(term.frames.is_empty());
}

#[tokio::test]
async fn tty_quit_immediately_exits_with_no_outcomes() {
    let dir = tempfile::tempdir().unwrap();
    let tools = SandboxTools::new_with_write(dir.path());
    let client = FailingClient;
    let findings = vec![PickerFinding {
        finding_index: 1,
        finding: finding("A", "a.py", Severity::High),
    }];
    let ctx = RemediationContext {
        client: &client,
        tools: &tools,
        repo: dir.path(),
        config: &config(),
        policy: None,
        checkpoint: None,
        run_id: "run1",
        validate: None,
    };
    let mut term = FakeTerminal::tty(vec![Ok(Key::Quit)]);
    let (outcomes, _validations, _validation_failures) =
        run_interactive(&ctx, &findings, &mut term).await;
    assert!(outcomes.is_empty());
    assert_eq!(term.frames.len(), 1);
}

#[tokio::test]
async fn tty_up_and_down_wrap_the_cursor_around_the_list() {
    let dir = tempfile::tempdir().unwrap();
    let tools = SandboxTools::new_with_write(dir.path());
    let client = FailingClient;
    let findings = vec![
        PickerFinding {
            finding_index: 1,
            finding: finding("A", "a.py", Severity::High),
        },
        PickerFinding {
            finding_index: 2,
            finding: finding("B", "b.py", Severity::Low),
        },
    ];
    let ctx = RemediationContext {
        client: &client,
        tools: &tools,
        repo: dir.path(),
        config: &config(),
        policy: None,
        checkpoint: None,
        run_id: "run1",
        validate: None,
    };
    // Up from position 0 wraps to the last row; Down from there wraps
    // back to 0; an unrelated key is a no-op; then quit.
    let mut term = FakeTerminal::tty(vec![
        Ok(Key::Up),
        Ok(Key::Down),
        Ok(Key::Other),
        Ok(Key::Quit),
    ]);
    let (outcomes, _validations, _validation_failures) =
        run_interactive(&ctx, &findings, &mut term).await;
    assert!(outcomes.is_empty());
    assert_eq!(term.frames.len(), 4);
}

#[tokio::test]
async fn tty_enter_remediates_the_highlighted_finding_and_marks_it_done() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.py"), "1\n").unwrap();
    let tools = SandboxTools::new_with_write(dir.path());
    let client = ScriptedClient::new(vec![verdict_json("Fixed")]);
    let findings = vec![PickerFinding {
        finding_index: 1,
        finding: finding("A", "a.py", Severity::High),
    }];
    let ctx = RemediationContext {
        client: &client,
        tools: &tools,
        repo: dir.path(),
        config: &config(),
        policy: None,
        checkpoint: None,
        run_id: "run1",
        validate: None,
    };
    let mut term = FakeTerminal::tty(vec![Ok(Key::Enter), Ok(Key::Quit)]);
    let (outcomes, _validations, _validation_failures) =
        run_interactive(&ctx, &findings, &mut term).await;
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcome_index(&outcomes[0]), 1);
    // The second frame (drawn just before the Quit key) must show the
    // ✅ now that the finding succeeded.
    assert!(term.frames[1].contains('\u{2705}'));
}

/// The `-i` picker reaches the remediation loop through
/// `remediate_one_checkpointed`, the same door the batch `--top` walk
/// uses — so S10's `--diff-scope` refusal covers it without the picker
/// itself knowing the boundary exists. `FailingClient` would error if the
/// agent were reached at all, which is the point: the outcome is a
/// refusal, not a failure.
#[tokio::test]
async fn tty_enter_on_a_finding_outside_the_diff_scope_refuses_instead_of_remediating() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("vendor.py"), "1\n").unwrap();
    let tools = SandboxTools::new_with_write(dir.path());
    let client = FailingClient;
    let findings = vec![PickerFinding {
        finding_index: 1,
        finding: finding("Pre-existing", "vendor.py", Severity::High),
    }];
    let mut cfg = config();
    cfg.diff_scope = bc_model::DiffScope::active(["a.py"]);
    let ctx = RemediationContext {
        client: &client,
        tools: &tools,
        repo: dir.path(),
        config: &cfg,
        policy: None,
        checkpoint: None,
        run_id: "run1",
        validate: None,
    };
    let mut term = FakeTerminal::tty(vec![Ok(Key::Enter), Ok(Key::Quit)]);
    let (outcomes, _validations, _validation_failures) =
        run_interactive(&ctx, &findings, &mut term).await;

    assert_eq!(outcomes.len(), 1);
    match &outcomes[0] {
        RemediationOutcome::Processed(record) => {
            assert!(bc_stage_s10::was_out_of_diff_scope(record));
            assert!(record.diff.is_none());
        }
        other => panic!("expected a Processed refusal, got {other:?}"),
    }
    assert_eq!(
        std::fs::read_to_string(dir.path().join("vendor.py")).unwrap(),
        "1\n"
    );
}

#[tokio::test]
async fn tty_enter_on_a_failed_remediation_does_not_mark_it_done() {
    let dir = tempfile::tempdir().unwrap();
    let tools = SandboxTools::new_with_write(dir.path());
    let client = FailingClient;
    let findings = vec![PickerFinding {
        finding_index: 1,
        finding: finding("A", "a.py", Severity::High),
    }];
    let ctx = RemediationContext {
        client: &client,
        tools: &tools,
        repo: dir.path(),
        config: &config(),
        policy: None,
        checkpoint: None,
        run_id: "run1",
        validate: None,
    };
    let mut term = FakeTerminal::tty(vec![Ok(Key::Enter), Ok(Key::Quit)]);
    let (outcomes, _validations, _validation_failures) =
        run_interactive(&ctx, &findings, &mut term).await;
    assert_eq!(outcomes.len(), 1);
    assert!(matches!(outcomes[0], RemediationOutcome::Failed { .. }));
    assert!(!term.frames[1].contains('\u{2705}'));
}

#[tokio::test]
async fn losing_the_tty_mid_session_falls_back_to_the_prompt_loop() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.py"), "1\n").unwrap();
    let tools = SandboxTools::new_with_write(dir.path());
    let client = ScriptedClient::new(vec![verdict_json("Fixed")]);
    let findings = vec![PickerFinding {
        finding_index: 1,
        finding: finding("A", "a.py", Severity::High),
    }];
    let ctx = RemediationContext {
        client: &client,
        tools: &tools,
        repo: dir.path(),
        config: &config(),
        policy: None,
        checkpoint: None,
        run_id: "run1",
        validate: None,
    };
    // First `read_key()` call errors (TTY lost) — falls back to the
    // prompt loop, which then picks finding 1 and quits.
    let mut term = FakeTerminal::tty(vec![Err(io_err())]);
    term.lines = vec![Some("1".to_string()), Some("q".to_string())].into();
    let (outcomes, _validations, _validation_failures) =
        run_interactive(&ctx, &findings, &mut term).await;
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcome_index(&outcomes[0]), 1);
}

#[tokio::test]
async fn prompt_mode_eof_on_read_line_exits_with_no_outcomes() {
    let dir = tempfile::tempdir().unwrap();
    let tools = SandboxTools::new_with_write(dir.path());
    let client = FailingClient;
    let findings = vec![PickerFinding {
        finding_index: 1,
        finding: finding("A", "a.py", Severity::High),
    }];
    let ctx = RemediationContext {
        client: &client,
        tools: &tools,
        repo: dir.path(),
        config: &config(),
        policy: None,
        checkpoint: None,
        run_id: "run1",
        validate: None,
    };
    let mut term = FakeTerminal::prompt(vec![None]);
    let (outcomes, _validations, _validation_failures) =
        run_interactive(&ctx, &findings, &mut term).await;
    assert!(outcomes.is_empty());
    assert_eq!(term.written.len(), 1);
}

#[tokio::test]
async fn prompt_mode_q_exits_with_no_outcomes() {
    let dir = tempfile::tempdir().unwrap();
    let tools = SandboxTools::new_with_write(dir.path());
    let client = FailingClient;
    let findings = vec![PickerFinding {
        finding_index: 1,
        finding: finding("A", "a.py", Severity::High),
    }];
    let ctx = RemediationContext {
        client: &client,
        tools: &tools,
        repo: dir.path(),
        config: &config(),
        policy: None,
        checkpoint: None,
        run_id: "run1",
        validate: None,
    };
    let mut term = FakeTerminal::prompt(vec![Some("q".to_string())]);
    let (outcomes, _validations, _validation_failures) =
        run_interactive(&ctx, &findings, &mut term).await;
    assert!(outcomes.is_empty());
}

#[tokio::test]
async fn prompt_mode_selects_multiple_findings_then_loops_back_for_more_input() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.py"), "1\n").unwrap();
    std::fs::write(dir.path().join("b.py"), "2\n").unwrap();
    let tools = SandboxTools::new_with_write(dir.path());
    let client = ScriptedClient::new(vec![verdict_json("Fixed"), verdict_json("Fixed")]);
    let findings = vec![
        PickerFinding {
            finding_index: 1,
            finding: finding("A", "a.py", Severity::High),
        },
        PickerFinding {
            finding_index: 2,
            finding: finding("B", "b.py", Severity::Low),
        },
    ];
    let ctx = RemediationContext {
        client: &client,
        tools: &tools,
        repo: dir.path(),
        config: &config(),
        policy: None,
        checkpoint: None,
        run_id: "run1",
        validate: None,
    };
    // First input picks both via "all", then the loop comes back around
    // for a second prompt and this time quits.
    let mut term = FakeTerminal::prompt(vec![Some("all".to_string()), Some("q".to_string())]);
    let (outcomes, _validations, _validation_failures) =
        run_interactive(&ctx, &findings, &mut term).await;
    assert_eq!(outcomes.len(), 2);
    assert_eq!(outcome_index(&outcomes[0]), 1);
    assert_eq!(outcome_index(&outcomes[1]), 2);
    // Rows were printed twice (once per prompt iteration), 2 rows each.
    assert_eq!(term.written.len(), 4);
}

#[tokio::test]
async fn a_checkpointed_finding_shows_as_done_from_the_start() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.py"), "1\n").unwrap();
    let tools = SandboxTools::new_with_write(dir.path());
    let ckpt_dir = tempfile::tempdir().unwrap();
    let store = SqliteCheckpointStore::new(ckpt_dir.path().join("state.db")).unwrap();
    let f = finding("A", "a.py", Severity::High);

    // Pre-populate the checkpoint by remediating once for real.
    {
        let client = ScriptedClient::new(vec![verdict_json("Fixed")]);
        let ctx = RemediationContext {
            client: &client,
            tools: &tools,
            repo: dir.path(),
            config: &config(),
            policy: None,
            checkpoint: Some(&store),
            run_id: "run1",
            validate: None,
        };
        let findings = vec![PickerFinding {
            finding_index: 1,
            finding: f.clone(),
        }];
        let mut term = FakeTerminal::tty(vec![Ok(Key::Enter), Ok(Key::Quit)]);
        run_interactive(&ctx, &findings, &mut term).await;
    }

    // A fresh picker session, built with a client that errors if ever
    // invoked: the checkmark on the very FIRST drawn frame (before any
    // key at all) must come from the pre-existing checkpoint, not from
    // remediating again.
    let panic_client = FailingClient;
    let findings = vec![PickerFinding {
        finding_index: 1,
        finding: f,
    }];
    let ctx = RemediationContext {
        client: &panic_client,
        tools: &tools,
        repo: dir.path(),
        config: &config(),
        policy: None,
        checkpoint: Some(&store),
        run_id: "run1",
        validate: None,
    };
    let mut term = FakeTerminal::tty(vec![Ok(Key::Quit)]);
    run_interactive(&ctx, &findings, &mut term).await;
    assert!(term.frames[0].contains('\u{2705}'));
}

#[tokio::test]
async fn tty_enter_with_validation_enabled_populates_the_validations_vector() {
    let dir = tempfile::tempdir().unwrap();
    let tools = SandboxTools::new_with_write(dir.path());
    let client = S10AndS11Client::new();
    let validate_tools = SandboxTools::new(dir.path());
    let step11 = s11_config();
    let findings = vec![PickerFinding {
        finding_index: 1,
        finding: finding("A", "a.py", Severity::High),
    }];
    let ctx = RemediationContext {
        client: &client,
        tools: &tools,
        repo: dir.path(),
        config: &config(),
        policy: None,
        checkpoint: None,
        run_id: "run1",
        validate: Some(ValidateContext {
            step11: &step11,
            tools: &validate_tools,
        }),
    };
    let mut term = FakeTerminal::tty(vec![Ok(Key::Enter), Ok(Key::Quit)]);
    let (outcomes, validations, _validation_failures) =
        run_interactive(&ctx, &findings, &mut term).await;
    assert_eq!(outcomes.len(), 1);
    assert_eq!(validations.len(), 1);
    assert_eq!(
        validations[0].as_ref().unwrap().fix_status,
        bc_validation_scoring::FixVerdict::Fixed
    );
}

#[tokio::test]
async fn tty_enter_rolls_a_failed_validation_back_end_to_end_without_git() {
    // The picker's whole S11-rollback path on a NON-git tempdir: S10
    // applies a fix, S11 grades it `Not Fixed`, and the file goes back
    // byte-for-byte with no `git` involved. Before the per-finding
    // baseline was carried out of S10, the git-only backstop could only
    // warn here and leave the bad fix applied.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.py"), "print('original')\n").unwrap();
    let tools = SandboxTools::new_with_write(dir.path());
    let mut cfg = config();
    cfg.journal = Some(tools.journal());
    let client = S10SucceedsS11GradesNotFixedClient {
        remediate_turn: Mutex::new(0),
    };
    let validate_tools = SandboxTools::new(dir.path());
    let step11 = s11_config();
    let findings = vec![PickerFinding {
        finding_index: 1,
        finding: finding("A", "a.py", Severity::High),
    }];
    let ctx = RemediationContext {
        client: &client,
        tools: &tools,
        repo: dir.path(),
        config: &cfg,
        policy: None,
        checkpoint: None,
        run_id: "run1",
        validate: Some(ValidateContext {
            step11: &step11,
            tools: &validate_tools,
        }),
    };
    let mut term = FakeTerminal::tty(vec![Ok(Key::Enter), Ok(Key::Quit)]);

    let (outcomes, validations, _failures) = run_interactive(&ctx, &findings, &mut term).await;

    assert_eq!(
        validations[0].as_ref().map(|v| v.fix_status),
        Some(bc_validation_scoring::FixVerdict::NotFixed)
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join("a.py")).unwrap(),
        "print('original')\n"
    );
    let RemediationOutcome::Processed(record) = &outcomes[0] else {
        panic!("expected a processed outcome");
    };
    assert!(bc_stage_s10::was_reverted(record));
    // No diff, so `--post-fixes-from` cannot suggest a patch that is no
    // longer on disk.
    assert_eq!(record.diff, None);
}

#[tokio::test]
async fn tty_enter_counts_and_surfaces_a_genuine_validation_error() {
    let dir = tempfile::tempdir().unwrap();
    let tools = SandboxTools::new_with_write(dir.path());
    let client = S10SucceedsS11FailsClient::new();
    let validate_tools = SandboxTools::new(dir.path());
    let step11 = s11_config();
    let findings = vec![PickerFinding {
        finding_index: 1,
        finding: finding("A", "a.py", Severity::High),
    }];
    let ctx = RemediationContext {
        client: &client,
        tools: &tools,
        repo: dir.path(),
        config: &config(),
        policy: None,
        checkpoint: None,
        run_id: "run1",
        validate: Some(ValidateContext {
            step11: &step11,
            tools: &validate_tools,
        }),
    };
    let mut term = FakeTerminal::tty(vec![Ok(Key::Enter), Ok(Key::Quit)]);
    let (outcomes, validations, validation_failures) =
        run_interactive(&ctx, &findings, &mut term).await;
    assert_eq!(outcomes.len(), 1);
    assert_eq!(validations, vec![None]);
    assert_eq!(validation_failures, 1);
}

#[tokio::test]
async fn tty_enter_with_validation_enabled_skips_a_processed_finding_with_no_diff() {
    let dir = tempfile::tempdir().unwrap();
    let tools = SandboxTools::new_with_write(dir.path());
    let client = ScriptedClient::new(vec![verdict_json("Fixed")]);
    let validate_tools = SandboxTools::new(dir.path());
    let step11 = s11_config();
    let findings = vec![PickerFinding {
        finding_index: 1,
        finding: finding("A", "a.py", Severity::High),
    }];
    let ctx = RemediationContext {
        client: &client,
        tools: &tools,
        repo: dir.path(),
        config: &config(),
        policy: None,
        checkpoint: None,
        run_id: "run1",
        validate: Some(ValidateContext {
            step11: &step11,
            tools: &validate_tools,
        }),
    };
    let mut term = FakeTerminal::tty(vec![Ok(Key::Enter), Ok(Key::Quit)]);
    let (outcomes, validations, _validation_failures) =
        run_interactive(&ctx, &findings, &mut term).await;
    assert_eq!(outcomes.len(), 1);
    assert_eq!(validations, vec![None]);
}

#[tokio::test]
async fn prompt_mode_with_validation_enabled_skips_a_failed_remediation() {
    let dir = tempfile::tempdir().unwrap();
    let tools = SandboxTools::new_with_write(dir.path());
    let client = FailingClient;
    let validate_tools = SandboxTools::new(dir.path());
    let step11 = s11_config();
    let findings = vec![PickerFinding {
        finding_index: 1,
        finding: finding("A", "a.py", Severity::High),
    }];
    let ctx = RemediationContext {
        client: &client,
        tools: &tools,
        repo: dir.path(),
        config: &config(),
        policy: None,
        checkpoint: None,
        run_id: "run1",
        validate: Some(ValidateContext {
            step11: &step11,
            tools: &validate_tools,
        }),
    };
    let mut term = FakeTerminal::prompt(vec![Some("1".to_string()), Some("q".to_string())]);
    let (outcomes, validations, _validation_failures) =
        run_interactive(&ctx, &findings, &mut term).await;
    assert_eq!(outcomes.len(), 1);
    assert!(matches!(outcomes[0], RemediationOutcome::Failed { .. }));
    assert_eq!(validations, vec![None]);
}

// ---- S11's post-validation rollback ---------------------------------

/// A git repo with `app.py` committed, then modified as a remediation
/// would have modified it — the state `revert_if_validation_failed`
/// exists to undo.
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

fn validated_record(files: &[&str]) -> bc_stage_s10::RemediationRecord {
    bc_stage_s10::RemediationRecord {
        finding_index: 1,
        finding_id: "abc123".to_string(),
        verdict: bc_stage_s10::RemediationVerdict {
            finding_index: 1,
            verdict: bc_stage_s10::Verdict::Fixed,
            gates: bc_stage_s10::Gates::default(),
            root_cause: String::new(),
            changes: files
                .iter()
                .map(|f| bc_stage_s10::Change {
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

fn score_of(status: bc_validation_scoring::FixVerdict) -> bc_validation_scoring::ValidationScore {
    bc_validation_scoring::ValidationScore {
        raw_score: 0.0,
        fix_status: status,
        justification: String::new(),
        gate_results: Vec::new(),
        has_critical_failure: false,
    }
}

/// One finding's pre-remediation baseline, built the way
/// `remediate_finding_with_baseline` builds one — the picker gets this
/// handed back from `remediate_one_checkpointed` and never constructs it.
fn baseline_of(file: &str, content: &str) -> bc_stage_s10::Baseline {
    let mut baseline = bc_stage_s10::Baseline::default();
    baseline.merge_originals([(file.to_string(), Some(content.as_bytes().to_vec()))]);
    baseline
}

/// Exercises the picker's rollback helper against `repo` with `config`,
/// returning the record so a caller can assert on what was recorded.
fn run_rollback(
    repo: &Path,
    config: &Step10Config,
    status: bc_validation_scoring::FixVerdict,
    baseline: Option<&bc_stage_s10::Baseline>,
) -> bc_stage_s10::RemediationRecord {
    let dir = tempfile::tempdir().unwrap();
    let tools = SandboxTools::new_with_write(dir.path());
    let client = FailingClient;
    let ctx = RemediationContext {
        client: &client,
        tools: &tools,
        repo,
        config,
        policy: None,
        checkpoint: None,
        run_id: "run1",
        validate: None,
    };
    let mut record = validated_record(&["app.py"]);
    revert_if_validation_failed(&ctx, &mut record, baseline, &score_of(status));
    record
}

#[test]
fn the_picker_rolls_back_a_fix_s11_could_not_confirm() {
    for status in [
        bc_validation_scoring::FixVerdict::NotFixed,
        bc_validation_scoring::FixVerdict::Unverifiable,
    ] {
        let dir = patched_git_repo();
        run_rollback(dir.path(), &config(), status, None);
        assert_eq!(
            std::fs::read_to_string(dir.path().join("app.py")).unwrap(),
            "print('original')\n"
        );
    }
}

#[test]
fn the_picker_rolls_back_from_the_baseline_on_a_target_with_no_git_at_all() {
    // A target with no `.git` at all, where the git-only backstop can
    // only warn while leaving a fix S11 had just graded `Not Fixed`
    // sitting on disk. The old `distroless/cc` runtime shipped no `git`
    // either, so every containerized run behaved this way. With the
    // finding's own baseline in hand, the restore is byte-exact and needs
    // no VCS.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("app.py"), "print('a bad fix')\n").unwrap();
    let baseline = baseline_of("app.py", "print('original')\n");
    let record = run_rollback(
        dir.path(),
        &config(),
        bc_validation_scoring::FixVerdict::NotFixed,
        Some(&baseline),
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join("app.py")).unwrap(),
        "print('original')\n"
    );
    assert!(bc_stage_s10::was_reverted(&record));
    // No diff, so `--post-fixes-from` cannot suggest a patch that is no
    // longer applied.
    assert_eq!(record.diff, None);
}

#[test]
fn the_picker_leaves_a_confirmed_fix_alone() {
    for status in [
        bc_validation_scoring::FixVerdict::Fixed,
        bc_validation_scoring::FixVerdict::PartiallyFixed,
    ] {
        let dir = patched_git_repo();
        let baseline = baseline_of("app.py", "print('original')\n");
        let record = run_rollback(dir.path(), &config(), status, Some(&baseline));
        assert_eq!(
            std::fs::read_to_string(dir.path().join("app.py")).unwrap(),
            "print('a bad fix')\n"
        );
        assert!(!bc_stage_s10::was_reverted(&record));
        assert_eq!(record.diff.as_deref(), Some("d"));
    }
}

#[test]
fn the_pickers_rollback_respects_keep_unverified() {
    let dir = patched_git_repo();
    let mut cfg = config();
    cfg.keep_unverified = true;
    let baseline = baseline_of("app.py", "print('original')\n");
    run_rollback(
        dir.path(),
        &cfg,
        bc_validation_scoring::FixVerdict::NotFixed,
        Some(&baseline),
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join("app.py")).unwrap(),
        "print('a bad fix')\n"
    );
}

#[test]
fn the_pickers_rollback_of_a_record_claiming_nothing_is_a_no_op() {
    let dir = patched_git_repo();
    let holder = tempfile::tempdir().unwrap();
    let tools = SandboxTools::new_with_write(holder.path());
    let client = FailingClient;
    let cfg = config();
    let ctx = RemediationContext {
        client: &client,
        tools: &tools,
        repo: dir.path(),
        config: &cfg,
        policy: None,
        checkpoint: None,
        run_id: "run1",
        validate: None,
    };
    revert_if_validation_failed(
        &ctx,
        &mut validated_record(&[]),
        None,
        &score_of(bc_validation_scoring::FixVerdict::NotFixed),
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join("app.py")).unwrap(),
        "print('a bad fix')\n"
    );
}

#[test]
fn the_pickers_rollback_warns_instead_of_acting_without_a_baseline_on_a_non_git_target() {
    // The remaining gap, kept honest: a `--resume`d record's baseline
    // lives in the process that created it, so this path really does have
    // nothing to restore from and says so rather than pretending.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("app.py"), "print('a bad fix')\n").unwrap();
    let record = run_rollback(
        dir.path(),
        &config(),
        bc_validation_scoring::FixVerdict::NotFixed,
        None,
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join("app.py")).unwrap(),
        "print('a bad fix')\n"
    );
    // Nothing was undone, so nothing claims it was.
    assert!(!bc_stage_s10::was_reverted(&record));
    assert_eq!(record.diff.as_deref(), Some("d"));
}

#[test]
fn the_pickers_rollback_ignores_an_empty_baseline_and_falls_back_to_git() {
    // An empty baseline means "the agent touched nothing", not "no
    // baseline was carried" — treating it as a usable baseline would
    // silently skip the git fallback for a record that does claim files.
    let dir = patched_git_repo();
    let record = run_rollback(
        dir.path(),
        &config(),
        bc_validation_scoring::FixVerdict::NotFixed,
        Some(&bc_stage_s10::Baseline::default()),
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join("app.py")).unwrap(),
        "print('original')\n"
    );
    assert!(bc_stage_s10::was_reverted(&record));
    assert_eq!(record.diff, None);
}
