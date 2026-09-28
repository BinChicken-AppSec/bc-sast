//! Stage-level tests for request-side prompt caching: what reaches each
//! `ChatRequest` (cache prefix, cache key, user text) and how shard
//! gating schedules the calls. Kept out of `lib.rs`'s own test module,
//! which is already long. Timing tests run on a paused tokio clock, so the
//! 15 s and 240 s caps cost nothing.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use bc_llm_client::{
    ChatRequest, ChatResponse, ContentBlock, LlmClient, LlmError, StopReason, Usage,
};
use bc_model::{
    AppProfile, Chunk, ChunkSize, ContextPackage, EntryPoint, EntryPointKind, ThreatModel,
};
use tokio::time::Instant;

use crate::shared_context::shared_context_block;
use crate::{run_deepdive, ChunkOutcome, DeepdiveOutput, Step4Config, Step4Input};

fn chunk(id: &str, rank: i64, shard: &str, specialist: Option<&str>) -> Chunk {
    Chunk {
        id: id.to_string(),
        size: ChunkSize::Small,
        risk_rank: rank,
        files: vec!["a.py".to_string()],
        focus_entry_points: Vec::new(),
        hypothesis: format!("{id} hypothesis"),
        related_cves: Vec::new(),
        threat_id: None,
        languages: vec!["python".to_string()],
        specialist: specialist.map(str::to_string),
        path_funcs: Vec::new(),
        source_ref: String::new(),
        sink_ref: String::new(),
        sink_cwe: Vec::new(),
        shard_id: shard.to_string(),
    }
}

fn lens(id: &str, rank: i64, shard: &str) -> Chunk {
    chunk(id, rank, shard, Some("crypto"))
}

fn rich_ctx(repo_root: &str) -> ContextPackage {
    ContextPackage {
        repo_root: repo_root.to_string(),
        app_profile: Some(AppProfile {
            application_id: "APP-9".to_string(),
            name: "Payments".to_string(),
            externally_facing: true,
            pci_scoped: true,
            processes_pan: false,
            pii: false,
            source: "application".to_string(),
        }),
        threat_model: Some(ThreatModel {
            system_context: "Card payments.".to_string(),
            ..Default::default()
        }),
        entry_points: vec![EntryPoint {
            file: "a.py".to_string(),
            function: "handler".to_string(),
            kind: EntryPointKind::Network,
            reachable_from_unauth: true,
        }],
        ..Default::default()
    }
}

/// The chunk id a request belongs to: the `CHUNK:` header of the
/// open-ended prompts, or `taint` for the confirm/refute prompt.
fn chunk_id_of(user: &str) -> String {
    user.split_once("CHUNK: ")
        .and_then(|(_, rest)| rest.split_once("  SIZE"))
        .map_or_else(|| "taint".to_string(), |(id, _)| id.to_string())
}

fn user_text(request: &ChatRequest) -> String {
    request.messages[0]
        .content
        .iter()
        .filter_map(|c| match c {
            ContentBlock::Text(t) => Some(t.as_str()),
            _ => None,
        })
        .collect()
}

/// A client that records every request and when each call started and
/// ended, sleeps per chunk to simulate call latency, and fails the calls
/// of the chunks listed in `fail`.
#[derive(Default)]
struct TimedClient {
    delays: HashMap<String, Duration>,
    fail: Vec<String>,
    requests: Mutex<Vec<(String, ChatRequest)>>,
    spans: Mutex<BTreeMap<String, (Duration, Duration)>>,
    in_flight: AtomicUsize,
    max_in_flight: AtomicUsize,
    epoch: Option<Instant>,
}

impl TimedClient {
    fn new(delays: &[(&str, u64)]) -> Self {
        TimedClient {
            delays: delays
                .iter()
                .map(|(id, secs)| (id.to_string(), Duration::from_secs(*secs)))
                .collect(),
            epoch: Some(Instant::now()),
            ..Default::default()
        }
    }

    fn span(&self, id: &str) -> (Duration, Duration) {
        self.spans.lock().unwrap()[id]
    }

    fn request(&self, id: &str) -> ChatRequest {
        let requests = self.requests.lock().unwrap();
        requests.iter().find(|(i, _)| i == id).unwrap().1.clone()
    }
}

#[async_trait]
impl LlmClient for TimedClient {
    async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, LlmError> {
        let id = chunk_id_of(&user_text(request));
        let epoch = self.epoch.expect("built with new()");
        let start = epoch.elapsed();
        let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_in_flight.fetch_max(now, Ordering::SeqCst);
        self.requests
            .lock()
            .unwrap()
            .push((id.clone(), request.clone()));
        let delay = self
            .delays
            .get(&id)
            .copied()
            .unwrap_or(Duration::from_secs(1));
        tokio::time::sleep(delay).await;
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
        self.spans
            .lock()
            .unwrap()
            .insert(id.clone(), (start, epoch.elapsed()));
        if self.fail.contains(&id) {
            return Err(LlmError::Other {
                message: "leader failed".into(),
            });
        }
        Ok(ChatResponse {
            content: vec![ContentBlock::Text(r#"{"findings": []}"#.to_string())],
            stop_reason: StopReason::EndTurn,
            usage: Usage::default(),
        })
    }
}

async fn run(client: Arc<TimedClient>, chunks: Vec<Chunk>, cfg: &Step4Config) -> DeepdiveOutput {
    let input = Step4Input {
        chunks,
        ctx: ContextPackage::default(),
    };
    // A deadlock would park every task with no timer left, so the paused
    // clock would jump straight to this bound and fail the test instead
    // of hanging it.
    tokio::time::timeout(
        Duration::from_secs(100_000),
        run_deepdive(client, input, cfg),
    )
    .await
    .expect("the stage must never deadlock")
    .unwrap()
}

fn config(parallel: usize) -> Step4Config {
    let mut cfg = Step4Config::new("m");
    cfg.parallel = parallel;
    cfg.max_transient_retries = 0;
    cfg.retry_backoff_base = Duration::ZERO;
    cfg
}

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

// ── what reaches the request ────────────────────────────────────────────

#[tokio::test(start_paused = true)]
async fn each_prompt_layout_reaches_the_request_with_its_prefix_and_key() {
    let ctx = rich_ctx("/nonexistent-repo-root");
    let shared = shared_context_block(&ctx);
    let mut taint = chunk("t1", 4, "", None);
    taint.path_funcs = vec!["a.py::src".to_string(), "a.py::sink".to_string()];
    taint.source_ref = "a.py::src".to_string();
    taint.sink_ref = "a.py:3".to_string();
    let client = Arc::new(TimedClient::new(&[]));
    let mut cfg = config(5);
    cfg.taint_prompt_mode = "confirm_refute".to_string();
    let chunks = vec![
        chunk("risk-01", 1, "", None),
        lens("spec-crypto-01", 2, "shard-01"),
        chunk("spec-logic-bug-01", 3, "shard-01", Some("logic-bug")),
        taint,
    ];
    let input = Step4Input { chunks, ctx };
    let out = run_deepdive(client.clone(), input, &cfg).await.unwrap();
    assert!(out.outcomes.values().all(|o| *o == ChunkOutcome::Completed));

    // Normal chunk: shared block in the prefix, code in the user text.
    let risk = client.request("risk-01");
    assert_eq!(risk.cache_prefix, Some(format!("{shared}\n\n")));
    assert_eq!(risk.cache_key.as_deref(), Some("s4:shared"));
    let risk_user = user_text(&risk);
    assert!(risk_user.contains("SOURCE CODE:\n"));
    assert!(!risk_user.contains("TRUST RULE"));
    assert!(!risk_user.contains("CMDB APPLICATION PROFILE"));

    // Shard lenses: one byte-identical prefix carrying the shard source.
    let a = client.request("spec-crypto-01");
    let b = client.request("spec-logic-bug-01");
    assert_eq!(a.cache_prefix, b.cache_prefix);
    let prefix = a.cache_prefix.clone().unwrap();
    assert!(prefix.starts_with(&format!("{shared}\n\nSOURCE CODE:\n")));
    assert!(prefix.ends_with("\n\n"));
    assert_eq!(a.cache_key.as_deref(), Some("s4:shard-01"));
    assert_eq!(b.cache_key.as_deref(), Some("s4:shard-01"));
    for lens_req in [&a, &b] {
        let user = user_text(lens_req);
        assert!(user.starts_with("RESEARCH LENS:\n"));
        assert!(!user.contains("SOURCE CODE:"));
    }
    assert_ne!(user_text(&a), user_text(&b));

    // Confirm/refute: no prefix, the stage key only.
    let t = client.request("taint");
    assert_eq!(t.cache_prefix, None);
    assert_eq!(t.cache_key.as_deref(), Some("s4:shared"));
    assert!(!user_text(&t).contains("TRUST RULE"));
}

#[tokio::test(start_paused = true)]
async fn the_shared_block_is_byte_identical_in_every_prefixed_request() {
    let ctx = rich_ctx("/nonexistent-repo-root");
    let shared = shared_context_block(&ctx);
    let client = Arc::new(TimedClient::new(&[]));
    let chunks = vec![
        chunk("r1", 1, "", None),
        chunk("r2", 2, "", Some("injection")),
        lens("s1", 3, "shard-01"),
        lens("s2", 4, "shard-02"),
    ];
    run_deepdive(client.clone(), Step4Input { chunks, ctx }, &config(2))
        .await
        .unwrap();
    let requests = client.requests.lock().unwrap();
    assert_eq!(requests.len(), 4);
    for (id, request) in requests.iter() {
        let prefix = request.cache_prefix.as_deref().unwrap();
        assert!(prefix.starts_with(&format!("{shared}\n\n")), "{id}");
    }
}

/// The shard prefix only ever matches if every lens on a shard assembles
/// the same `code`, neighbor context included. Loading reads only the
/// fields S3 copies from the shard to each lens, so two lenses that
/// differ in id, specialist and hypothesis must still agree byte for byte.
#[tokio::test(start_paused = true)]
async fn shard_lenses_assemble_byte_identical_code() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("a.py"),
        "def handler(x):\n    return helper(x)\n",
    )
    .unwrap();
    std::fs::write(dir.path().join("b.py"), "def helper(x):\n    return x\n").unwrap();
    let mut ctx = rich_ctx(dir.path().to_str().unwrap());
    ctx.call_graph.insert(
        "a.py::handler".to_string(),
        vec!["b.py::helper".to_string()],
    );
    let client = Arc::new(TimedClient::new(&[]));
    let mut first = lens("spec-crypto-01", 1, "shard-01");
    first.focus_entry_points = vec!["handler".to_string()];
    let mut second = chunk("spec-injection-01", 2, "shard-01", Some("injection"));
    second.focus_entry_points = first.focus_entry_points.clone();
    let chunks = vec![first, second];
    run_deepdive(client.clone(), Step4Input { chunks, ctx }, &config(2))
        .await
        .unwrap();
    let a = client.request("spec-crypto-01").cache_prefix.unwrap();
    let b = client.request("spec-injection-01").cache_prefix.unwrap();
    assert!(a.contains("def handler(x):"));
    assert!(
        a.contains("NEIGHBOR CONTEXT"),
        "neighbor context must be in the shared code"
    );
    assert_eq!(a, b);
}

// ── shard gating ────────────────────────────────────────────────────────

/// Upstream gates by default; `bc_config::step_defaults` carries the
/// same `true`.
#[test]
fn shard_cache_gating_is_on_by_default() {
    assert!(Step4Config::new("m").shard_cache_gating);
}

#[tokio::test(start_paused = true)]
async fn siblings_start_after_their_leader_returns_and_other_chunks_do_not_wait() {
    let client = Arc::new(TimedClient::new(&[("lead", 30)]));
    let chunks = vec![
        lens("lead", 1, "shard-01"),
        lens("sib-1", 2, "shard-01"),
        lens("sib-2", 3, "shard-01"),
        chunk("risk", 4, "", None),
    ];
    let out = run(client.clone(), chunks, &config(5)).await;
    assert!(out.outcomes.values().all(|o| *o == ChunkOutcome::Completed));
    assert_eq!(client.span("lead"), (secs(0), secs(30)));
    assert_eq!(client.span("sib-1").0, secs(30));
    assert_eq!(client.span("sib-2").0, secs(30));
    // Not in a shard group, so never parked: it ran beside the leader.
    assert_eq!(client.span("risk").0, secs(0));
    assert_eq!(out.diagnostics.sibling_parked_ms, 60_000);
    assert_eq!(out.diagnostics.gate_cap_expired, 0);
    assert_eq!(out.diagnostics.leader_start_cap_expired, 0);
}

#[tokio::test(start_paused = true)]
async fn a_failing_leader_releases_its_siblings_when_it_fails() {
    let client = Arc::new(TimedClient {
        fail: vec!["lead".to_string()],
        ..TimedClient::new(&[("lead", 5)])
    });
    let chunks = vec![lens("lead", 1, "shard-01"), lens("sib", 2, "shard-01")];
    let out = run(client.clone(), chunks, &config(5)).await;
    assert_eq!(out.outcomes["lead"], ChunkOutcome::Error);
    assert_eq!(out.outcomes["sib"], ChunkOutcome::Completed);
    assert_eq!(client.span("sib").0, secs(5));
    assert_eq!(out.diagnostics.sibling_parked_ms, 5_000);
    assert_eq!(out.diagnostics.gate_cap_expired, 0);
}

#[tokio::test(start_paused = true)]
async fn a_leader_past_the_done_cap_releases_its_siblings_and_is_counted() {
    let client = Arc::new(TimedClient::new(&[("lead", 300)]));
    let chunks = vec![lens("lead", 1, "shard-01"), lens("sib", 2, "shard-01")];
    let out = run(client.clone(), chunks, &config(5)).await;
    assert_eq!(client.span("sib").0, crate::shard_gate::LEADER_DONE_CAP);
    assert_eq!(out.diagnostics.gate_cap_expired, 1);
    assert_eq!(out.diagnostics.sibling_parked_ms, 240_000);
    assert!(out.outcomes.values().all(|o| *o == ChunkOutcome::Completed));
}

/// With one permit a parked sibling holding it would starve its own
/// leader; siblings park without it, so the run completes, serially.
#[tokio::test(start_paused = true)]
async fn parallel_one_never_deadlocks_and_never_runs_two_calls_at_once() {
    let client = Arc::new(TimedClient::new(&[("lead", 10)]));
    let chunks = vec![
        lens("lead", 1, "shard-01"),
        lens("sib-1", 2, "shard-01"),
        chunk("risk", 3, "", None),
        lens("sib-2", 4, "shard-01"),
        lens("other-lead", 5, "shard-02"),
        lens("other-sib", 6, "shard-02"),
    ];
    let out = run(client.clone(), chunks, &config(1)).await;
    assert_eq!(out.outcomes.len(), 6);
    assert!(out.outcomes.values().all(|o| *o == ChunkOutcome::Completed));
    assert_eq!(client.max_in_flight.load(Ordering::SeqCst), 1);
    assert!(client.span("sib-1").0 >= client.span("lead").1);
    assert!(client.span("sib-2").0 >= client.span("lead").1);
    assert!(client.span("other-sib").0 >= client.span("other-lead").1);
    assert_eq!(out.diagnostics.gate_cap_expired, 0);
    assert_eq!(out.diagnostics.leader_start_cap_expired, 0);
}

#[tokio::test(start_paused = true)]
async fn parked_siblings_never_push_in_flight_calls_past_parallel() {
    let client = Arc::new(TimedClient::new(&[("lead", 20)]));
    let mut chunks = vec![lens("lead", 1, "shard-01")];
    for i in 0..6 {
        chunks.push(lens(&format!("sib-{i}"), 2 + i, "shard-01"));
    }
    let out = run(client.clone(), chunks, &config(2)).await;
    assert!(out.outcomes.values().all(|o| *o == ChunkOutcome::Completed));
    assert_eq!(client.max_in_flight.load(Ordering::SeqCst), 2);
}

#[tokio::test(start_paused = true)]
async fn gating_off_lets_siblings_run_beside_their_leader() {
    let client = Arc::new(TimedClient::new(&[("lead", 30)]));
    let mut cfg = config(5);
    cfg.shard_cache_gating = false;
    let chunks = vec![lens("lead", 1, "shard-01"), lens("sib", 2, "shard-01")];
    let out = run(client.clone(), chunks, &cfg).await;
    assert_eq!(client.span("sib").0, secs(0));
    assert_eq!(out.diagnostics.sibling_parked_ms, 0);
}

#[tokio::test(start_paused = true)]
async fn confirm_refute_shard_chunks_carry_no_prefix_and_are_not_gated() {
    let client = Arc::new(TimedClient::new(&[("lead", 30)]));
    let mut cfg = config(5);
    cfg.taint_prompt_mode = "confirm_refute".to_string();
    let mut lead = lens("lead", 1, "shard-01");
    lead.path_funcs = vec!["a.py::f".to_string()];
    let mut sib = lens("sib", 2, "shard-01");
    sib.path_funcs = vec!["a.py::g".to_string()];
    let out = run(client.clone(), vec![lead, sib], &cfg).await;
    // Both went to the confirm/refute prompt (no CHUNK header), at once.
    let requests = client.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests
        .iter()
        .all(|(id, r)| id == "taint" && r.cache_prefix.is_none()));
    assert_eq!(out.diagnostics.sibling_parked_ms, 0);
}

/// Stops after `allowance` checks and counts every check, so the test can
/// hold the gate to "asked exactly once per chunk" through parking.
#[derive(Debug)]
struct CountingGate {
    allowance: usize,
    asked: AtomicUsize,
}

impl bc_pipeline_core::BudgetGate for CountingGate {
    fn should_stop(&self) -> bool {
        self.asked.fetch_add(1, Ordering::SeqCst) >= self.allowance
    }

    fn stop_reason(&self) -> String {
        "token budget spent".to_string()
    }
}

#[tokio::test(start_paused = true)]
async fn a_budget_that_runs_out_while_siblings_park_skips_them_asking_once_each() {
    let gate = Arc::new(CountingGate {
        allowance: 1,
        asked: AtomicUsize::new(0),
    });
    let client = Arc::new(TimedClient::new(&[("lead", 30)]));
    let mut cfg = config(5);
    cfg.budget_gate = Some(gate.clone());
    let chunks = vec![
        lens("lead", 1, "shard-01"),
        lens("sib-1", 2, "shard-01"),
        lens("sib-2", 3, "shard-01"),
    ];
    let out = run(client.clone(), chunks, &cfg).await;
    assert_eq!(out.outcomes["lead"], ChunkOutcome::Completed);
    assert_eq!(out.outcomes["sib-1"], ChunkOutcome::Skipped);
    assert_eq!(out.outcomes["sib-2"], ChunkOutcome::Skipped);
    assert_eq!(gate.asked.load(Ordering::SeqCst), 3);
    // The parking is still reported for the skipped siblings.
    assert_eq!(out.diagnostics.sibling_parked_ms, 60_000);
    assert!(out.budget_stop.unwrap().starts_with("token budget spent"));
}

#[tokio::test(start_paused = true)]
async fn a_budget_stopped_leader_still_releases_its_siblings() {
    let gate = Arc::new(CountingGate {
        allowance: 0,
        asked: AtomicUsize::new(0),
    });
    let client = Arc::new(TimedClient::new(&[]));
    let mut cfg = config(5);
    cfg.budget_gate = Some(gate.clone());
    let chunks = vec![lens("lead", 1, "shard-01"), lens("sib", 2, "shard-01")];
    let out = run(client.clone(), chunks, &cfg).await;
    assert!(out.outcomes.values().all(|o| *o == ChunkOutcome::Skipped));
    assert_eq!(gate.asked.load(Ordering::SeqCst), 2);
    assert_eq!(out.diagnostics.gate_cap_expired, 0);
    assert!(client.requests.lock().unwrap().is_empty());
}

#[test]
fn record_park_counts_each_cap_and_sums_the_parked_time() {
    use crate::shard_gate::ParkReport;
    let mut diag = crate::DeepdiveDiagnostics::default();
    diag.record_park(
        ParkReport {
            start_cap_expired: true,
            done_cap_expired: false,
            parked: Duration::from_millis(15_000),
        },
        "sib",
        "lead",
    );
    diag.record_park(
        ParkReport {
            start_cap_expired: false,
            done_cap_expired: true,
            parked: Duration::from_millis(240_000),
        },
        "sib",
        "lead",
    );
    diag.record_park(
        ParkReport {
            parked: Duration::from_millis(7),
            ..ParkReport::default()
        },
        "sib",
        "lead",
    );
    assert_eq!(diag.leader_start_cap_expired, 1);
    assert_eq!(diag.gate_cap_expired, 1);
    assert_eq!(diag.sibling_parked_ms, 255_007);
    let mut total = crate::DeepdiveDiagnostics::default();
    total.absorb(diag);
    total.absorb(diag);
    assert_eq!(total.sibling_parked_ms, 510_014);
    assert_eq!(total.leader_start_cap_expired, 2);
    assert_eq!(total.gate_cap_expired, 2);
}
