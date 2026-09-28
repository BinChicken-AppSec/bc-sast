//! S7 — Deduplication: collapses verified findings (post-S6) that describe
//! the same underlying vulnerability. Two passes: a deterministic
//! same-file/vuln-class/line-tolerance pre-filter (7a, shared with S5 via
//! [`prefilter`] — mirroring the Python original's `s5_prefilter.py`
//! importing `s7_dedup` directly rather than duplicating its logic), then
//! an optional single-shot semantic LLM pass (7b) for whatever the
//! pre-filter didn't resolve. Ported from
//! `vvaharness/pipeline/stages/s7_dedup.py`.
//!
//! Like S1/S3/S8, this stage has a genuine **internal** degrade policy:
//! `s7_dedup.py::_semantic_dedup` catches its own LLM-call failure and
//! returns no additional merges rather than raising — `run()` never fails
//! because of it, it just proceeds with fewer (or zero) semantic merges on
//! top of the deterministic pass. This port mirrors that with
//! `StageOutcome::Degraded` carrying the failure reason, rather than
//! propagating an `Err` — the deterministic 7a results are still a valid,
//! usable `DedupOutput`.

mod clustering;
mod parse;
mod semantic;

use std::collections::HashMap;

use bc_dedup_core::CanonicalOf;
use bc_llm_client::LlmClient;
use bc_model::{ContextPackage, DropReason, DroppedFinding, Finding};
use bc_pipeline_core::{PipelineStage, StageError, StageOutcome};

pub use clustering::prefilter;

pub struct Step7Input {
    pub findings: Vec<Finding>,
    pub ctx: ContextPackage,
}

pub struct Step7Config {
    pub model: String,
    pub line_tolerance: i64,
    pub semantic: bool,
    /// Whether the deterministic pass also merges two findings on the
    /// EXACTLY equal `(line_start, line_end)` range of one file that were
    /// reported under different CWEs — one code range seen through
    /// several lenses. `true` by default; set
    /// `step7_dedup.merge_same_range_cwes: false` to keep every lens as
    /// its own finding. See `bc_dedup_core::collapse_same_range_cwes`.
    pub merge_same_range_cwes: bool,
    /// Collapse two findings that share a normalized `sink_ref` under an
    /// explicit, equal CWE even when their `source_ref`s or anchor files
    /// differ — one fix site reported from two hops of the same flow.
    /// See `bc_dedup_core::collapse_trivial`. `step7_dedup.merge_same_sink:
    /// false` restores "same source AND sink, or nothing".
    pub merge_same_sink: bool,
    pub max_tokens: u32,
    /// How many times the single semantic-dedup call retries after a
    /// retryable [`bc_llm_client::LlmError`] (429/5xx/connection failure)
    /// before giving up and propagating it — see
    /// [`bc_llm_agentic::chat_with_retry`].
    pub max_transient_retries: u32,
    /// Base delay before a transient-retry attempt; the actual delay is
    /// `retry_backoff_base * attempt_number` (linear backoff).
    pub retry_backoff_base: std::time::Duration,
    /// Sampling temperature for this stage's LLM call(s). `None` (the
    /// default) sends no `temperature` at all, leaving the provider's own
    /// default — which for both dialects is `1.0`, i.e. maximally
    /// divergent between two scans of the same repo. Ported from the
    /// Python original's per-role `models.<role>.temperature`
    /// (`backends/llm.py::resolve`), which this port had dropped.
    pub temperature: Option<f64>,
    /// Nucleus-sampling cutoff, forwarded to
    /// [`bc_llm_client::ChatRequest::top_p`]. `None` (the default) sends
    /// none — net-new versus Python, which exposes only `temperature`.
    /// The Anthropic dialect drops it when `temperature` is also set, as
    /// the Messages API rejects the pair.
    pub top_p: Option<f64>,
    /// Deterministic-sampling seed, forwarded to
    /// [`bc_llm_client::ChatRequest::seed`] (OpenAI dialect only — see
    /// that field). `None` (the default) sends no seed. Net-new versus
    /// Python.
    pub seed: Option<u64>,
    /// Reasoning-effort tier for this stage's calls (the Python
    /// original's `models.<role>.effort`, else `--reasoning-effort`),
    /// forwarded to [`bc_llm_client::ChatRequest::reasoning_effort`].
    /// `None` (the default) sends none, leaving the provider's default.
    pub reasoning_effort: Option<bc_llm_client::ReasoningEffort>,
    /// Per-role OpenAI transport pin (Python's
    /// `models.<role>.use_responses_api`), forwarded to
    /// [`bc_llm_client::ChatRequest::openai_api`]. `None` (the default)
    /// keeps the client-wide `--openai-api` choice.
    pub openai_api: Option<bc_llm_client::OpenAiApi>,
    /// Per-call wall-clock deadline in seconds for the semantic-dedup
    /// call, overriding the shared gateway client's own 300 s default.
    /// `None` (the default) keeps that default — matching Python's
    /// `_STEP_DEFAULTS`, which has no `step7_dedup.timeout` key.
    pub timeout_secs: Option<u64>,
    /// Consulted immediately before the one semantic-dedup LLM call — see
    /// [`bc_pipeline_core::BudgetGate`]. `None` (the default) is
    /// unbounded. This config is shared with S5's inline pre-verify dedup
    /// pass (`Step5Config::dedup`), which is where the gate matters most:
    /// that call happens mid-S5, well after the last stage-boundary
    /// check.
    pub budget_gate: Option<bc_pipeline_core::BudgetGateRef>,
}

impl Step7Config {
    pub fn new(model: impl Into<String>) -> Self {
        Step7Config {
            model: model.into(),
            line_tolerance: 3,
            semantic: true,
            merge_same_range_cwes: true,
            merge_same_sink: true,
            max_tokens: 64_000,
            max_transient_retries: 4,
            retry_backoff_base: std::time::Duration::from_secs(10),
            temperature: None,
            top_p: None,
            seed: None,
            reasoning_effort: None,
            openai_api: None,
            timeout_secs: None,
            budget_gate: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct DedupOutput {
    pub findings: Vec<Finding>,
    pub dropped: Vec<DroppedFinding>,
}

/// Order `findings` so that "lowest index wins" — the invariant
/// `bc_dedup_core::collapse_trivial` and `partition` are built on — means
/// something stable, rather than meaning "whichever verification session
/// the network answered first".
///
/// Net-new versus `s7_dedup.py`, which dedups in arrival order. That was
/// a live nondeterminism: S6 pushed verified findings in COMPLETION order,
/// so for two findings that dedup together, which one survived as
/// canonical — and therefore the reported line, code snippet, CVSS vector
/// and SARIF fingerprint — flipped between two runs of the same scan.
/// S6 now emits input order (see `bc_stage_s6::run_verify`), and this
/// makes the choice explicit and content-derived rather than
/// order-inherited: sink-anchored findings first, then earliest position
/// in the file, then the most severe, and among findings still tied the
/// most specific CWE lens (see [`cwe_rank`]), then the best-evidenced one
/// — highest verifier confidence (`verdict_confidence`, unset last), then
/// highest S4 confidence, then title as a total-order backstop so the
/// sort has no ties left to break.
///
/// **Why the CWE key sits before the confidence keys.** Two lenses on one
/// range (`CWE-22` and `CWE-639` on the same `download_report` lines, in
/// a 2026-09-07 Flask field case) tie on everything above, and the S4
/// confidence that would then decide is a model output that moves from
/// run to run — so the survivor's CWE, and with it the finding's
/// identity, flipped between two scans of the same commit. The CWE
/// itself is content: a specific weakness beats an umbrella one, and the
/// lower number wins among specifics, the same way every time.
///
/// **Why sink-anchoredness leads.** A cross-file flow-identity collapse
/// (`bc_dedup_core::collapse_trivial`) pairs two findings whose anchor
/// *files* differ, so the `file` key would otherwise decide the survivor
/// alphabetically — in the 2026-09-06 Flask field case that meant
/// `handlers.py` (the source end) beating `shell.py` (the sink end)
/// purely on the letter `h`. The sink is where the fix goes and what S10
/// edits, so it has to win. This key only distinguishes findings that
/// carry BOTH refs and whose anchor file is their own sink's file —
/// everything without a full dataflow ties here and is ordered exactly as
/// before.
///
/// **Why severity outranks the class/confidence keys.** When two findings
/// share a code range, [`crate::clustering::deterministic_passes`] may
/// merge them across CWEs, and the survivor's CWE, class and CVSS become
/// the cluster's. The most severe lens must therefore be the one that
/// survives. `cvss_score` is the severity signal available at S7 —
/// `Severity` itself is not computed until S8 (`bc_stage_s8::
/// final_severity`) — and is unset before S6, where this key is
/// simply inert.
pub(crate) fn sort_for_stable_canonical(findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        sink_anchor_rank(a)
            .cmp(&sink_anchor_rank(b))
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.line_start.cmp(&b.line_start))
            // Reversed (b vs a): higher sorts EARLIER, so it wins the
            // lowest-index-is-canonical race. `None` sorts last under
            // `Option`'s own ordering, which is what we want for an
            // unscored finding competing with a scored one.
            .then_with(|| severity_key(b).cmp(&severity_key(a)))
            .then_with(|| a.vuln_class.as_str().cmp(b.vuln_class.as_str()))
            .then_with(|| cwe_rank(a).cmp(&cwe_rank(b)))
            .then_with(|| b.verdict_confidence.cmp(&a.verdict_confidence))
            .then_with(|| b.confidence.total_cmp(&a.confidence))
            .then_with(|| a.title.cmp(&b.title))
    });
}

/// Umbrella CWEs a model reaches for when it has not named the concrete
/// weakness. They rank after any specific CWE so a same-range merge keeps
/// the specific lens as the survivor.
const GENERIC_CWES: &[u32] = &[
    20, 74, 200, 284, 285, 664, 682, 691, 693, 697, 703, 707, 710,
];

/// `(umbrella?, number)`, a missing or unparseable CWE last: the
/// content-derived key that decides between two CWE lenses on one range
/// before the model-dependent confidence keys get a say. See
/// [`sort_for_stable_canonical`].
fn cwe_rank(f: &Finding) -> (u8, u32) {
    match bc_dedup_core::cwe_number(f.cwe.as_deref()) {
        Some(n) => (u8::from(GENERIC_CWES.contains(&n)), n),
        None => (2, u32::MAX),
    }
}

/// `0` for a finding anchored at its own flow's sink, `1` otherwise — so
/// ascending order puts the sink-anchored one first. Requires BOTH refs,
/// i.e. exactly the findings that can take part in a flow-identity
/// collapse; see [`sort_for_stable_canonical`].
fn sink_anchor_rank(f: &Finding) -> u8 {
    let (Some(_), Some(sink)) = (
        bc_dedup_core::normalize_ref(f.source_ref.as_deref()),
        bc_dedup_core::normalize_ref(f.sink_ref.as_deref()),
    ) else {
        return 1;
    };
    // `file:line` — everything before the LAST colon is the path, so a
    // Windows drive letter in the path survives. A ref with no colon at
    // all is taken as a bare path.
    let sink_file = sink.rsplit_once(':').map_or(sink.as_str(), |(p, _)| p);
    match bc_dedup_core::normalize_ref(Some(sink_file)) {
        Some(sink_file)
            if Some(&sink_file) == bc_dedup_core::normalize_ref(Some(&f.file)).as_ref() =>
        {
            0
        }
        _ => 1,
    }
}

/// The severity of a finding as of S7, in a totally-ordered form: the
/// CVSS base score scaled to hundredths so it can be an integer (`f64`
/// has no `Ord`), or `None` when S6 computed no score.
fn severity_key(f: &Finding) -> Option<i64> {
    f.cvss_score.map(|s| (s * 100.0).round() as i64)
}

/// The full two-pass dedup (S7's `run()`, and what S5 calls for its
/// above-threshold semantic pre-verify pass): deterministic pre-filter,
/// then — if 2+ findings remain unresolved and `config.semantic` is on —
/// one semantic LLM call to merge root-cause duplicates the pre-filter
/// couldn't see. Returns the resulting `DedupOutput` plus `Some(reason)`
/// when the semantic call failed and was skipped (non-fatal).
pub async fn run_dedup(
    client: &dyn LlmClient,
    verified: &[Finding],
    config: &Step7Config,
    ctx: &ContextPackage,
) -> (DedupOutput, Option<String>) {
    if verified.len() <= 1 {
        return (
            DedupOutput {
                findings: verified.to_vec(),
                dropped: Vec::new(),
            },
            None,
        );
    }

    let mut findings = verified.to_vec();
    sort_for_stable_canonical(&mut findings);
    let (mut canonical_of, mut reasoning): (CanonicalOf, HashMap<usize, String>) =
        clustering::deterministic_passes(
            &findings,
            config.line_tolerance,
            config.merge_same_range_cwes,
            config.merge_same_sink,
        );

    let unresolved: Vec<usize> = (0..findings.len())
        .filter(|i| !canonical_of.contains_key(i))
        .collect();
    let mut degraded_reason = None;

    let budget_stop = config
        .budget_gate
        .as_ref()
        .filter(|gate| gate.should_stop())
        .map(|gate| gate.stop_reason());

    if unresolved.len() >= 2 && config.semantic && budget_stop.is_none() {
        // Built once per call, not once per finding — see
        // `bc_repo_analysis::GraphView`'s own docs.
        let view = bc_repo_analysis::GraphView::new(ctx);
        match semantic::semantic_dedup(client, &findings, &unresolved, config, ctx, &view).await {
            Ok(merges) => {
                for (local_idx, local_canon, why) in merges {
                    let g_idx = unresolved[local_idx];
                    let g_canon = unresolved[local_canon];
                    if !canonical_of.contains_key(&g_idx) && g_canon < g_idx {
                        canonical_of.insert(g_idx, g_canon);
                        reasoning.insert(g_idx, why);
                    }
                }
            }
            Err(e) => {
                degraded_reason = Some(format!("semantic dedup call failed (non-fatal): {e}"));
            }
        }
    } else if let Some(reason) = budget_stop {
        // Only worth saying when the call would otherwise have happened —
        // a one-finding or `semantic: false` run skips it anyway and has
        // nothing to report.
        if unresolved.len() >= 2 && config.semantic {
            degraded_reason = Some(format!("semantic dedup skipped: {reason}"));
        }
    }

    clustering::attach_duplicates(&mut findings, &canonical_of, &reasoning);

    let partition = bc_dedup_core::partition(findings.len(), &canonical_of);
    let canonical: Vec<Finding> = partition
        .kept_indices
        .iter()
        .map(|&i| findings[i].clone())
        .collect();
    let dropped: Vec<DroppedFinding> = partition
        .dropped_indices
        .iter()
        .map(|&i| {
            let r = bc_dedup_core::root(&canonical_of, i);
            DroppedFinding {
                file: findings[i].file.clone(),
                line: findings[i].line_start,
                vuln_class: findings[i].vuln_class,
                title: findings[i].title.clone(),
                chunk_id: findings[i].chunk_id.clone(),
                reason: DropReason::Duplicate,
                // Every key ever inserted into `canonical_of` (either the
                // initial 7a pass, keyed off the very `canonical_of` this
                // `reasoning` map was seeded from, or a 7b merge, which
                // inserts both maps in the same `if` body above) has a
                // matching `reasoning` entry by construction — no fallback
                // branch needed (faithfully dropping the Python original's
                // own always-satisfied `reasoning.get(i, "duplicate")`
                // default).
                detail: reasoning[&i].clone(),
                canonical_idx: partition.new_index_of.get(&r).map(|&x| x as i64),
                provider_origins: findings[i].provider_origins.clone(),
                verification: bc_model::VerificationEvidence::from_finding(&findings[i]),
            }
        })
        .collect();

    (
        DedupOutput {
            findings: canonical,
            dropped,
        },
        degraded_reason,
    )
}

pub struct Stage7 {
    client: std::sync::Arc<dyn LlmClient>,
    config: Step7Config,
}

impl Stage7 {
    pub fn new(client: std::sync::Arc<dyn LlmClient>, config: Step7Config) -> Self {
        Stage7 { client, config }
    }
}

impl PipelineStage for Stage7 {
    type Input = Step7Input;
    type Output = DedupOutput;
    const NAME: &'static str = "s7-dedup";

    async fn run(&self, input: Step7Input) -> Result<StageOutcome<DedupOutput>, StageError> {
        let (output, degraded_reason) = run_dedup(
            self.client.as_ref(),
            &input.findings,
            &self.config,
            &input.ctx,
        )
        .await;
        match degraded_reason {
            Some(reason) => Ok(StageOutcome::Degraded {
                value: output,
                reason,
            }),
            None => Ok(StageOutcome::Ok(output)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use bc_llm_client::{ChatRequest, ChatResponse, ContentBlock, LlmError, StopReason, Usage};
    use bc_model::VulnClass;

    struct ScriptedClient {
        reply: String,
    }

    #[async_trait]
    impl LlmClient for ScriptedClient {
        async fn chat(&self, _request: &ChatRequest) -> Result<ChatResponse, LlmError> {
            Ok(ChatResponse {
                content: vec![ContentBlock::Text(self.reply.clone())],
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
                message: "boom".to_string(),
            })
        }
    }

    /// Fails with a retryable error `fail_times` times, then succeeds
    /// with an empty (no-merges) reply — exercises this crate's own
    /// `chat_with_retry` call site, not just `bc-llm-agentic`'s own unit
    /// tests.
    struct RetryingClient {
        fail_times: std::sync::atomic::AtomicU32,
    }

    impl RetryingClient {
        fn new(fail_times: u32) -> Self {
            RetryingClient {
                fail_times: std::sync::atomic::AtomicU32::new(fail_times),
            }
        }
    }

    #[async_trait]
    impl LlmClient for RetryingClient {
        async fn chat(&self, _request: &ChatRequest) -> Result<ChatResponse, LlmError> {
            if self.fail_times.load(std::sync::atomic::Ordering::SeqCst) > 0 {
                self.fail_times
                    .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                return Err(LlmError::ServerError {
                    status: 503,
                    message: "down".to_string(),
                });
            }
            Ok(ChatResponse {
                content: vec![ContentBlock::Text(String::new())],
                stop_reason: StopReason::EndTurn,
                usage: Usage::default(),
            })
        }
    }

    fn finding(file: &str, line: i64, vc: VulnClass, title: &str) -> Finding {
        Finding {
            provider_origins: Vec::new(),
            chunk_id: "c".to_string(),
            file: file.to_string(),
            line_start: line,
            line_end: line,
            vuln_class: vc,
            cwe: None,
            title: title.to_string(),
            impact: String::new(),
            description: "d".to_string(),
            exploit_scenario: String::new(),
            preconditions: Vec::new(),
            recommendation: String::new(),
            code_snippet: "x".to_string(),
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

    /// The 2026-09-06 Juice Shop field case, verbatim: one function in
    /// `routes/continueCode.ts` reported four times over — `CWE-798`
    /// "Hardcoded salt" at line 13, then `CWE-345` / `CWE-284` /
    /// `CWE-200` all on the identical range 12-21. Three lenses on one
    /// range become one finding; the line-13 one keeps its own entry.
    #[tokio::test]
    async fn one_range_under_several_cwes_becomes_one_finding_carrying_the_others() {
        let mut hardcoded = finding(
            "routes/continueCode.ts",
            13,
            VulnClass::Other,
            "Hardcoded salt",
        );
        hardcoded.line_end = 13;
        hardcoded.cwe = Some("CWE-798".to_string());
        let mut inconsistent = finding(
            "routes/continueCode.ts",
            12,
            VulnClass::Other,
            "Inconsistent salt",
        );
        inconsistent.line_end = 21;
        inconsistent.cwe = Some("CWE-345".to_string());
        let mut authz = finding(
            "routes/continueCode.ts",
            12,
            VulnClass::Other,
            "Missing authorization",
        );
        authz.line_end = 21;
        authz.cwe = Some("CWE-284".to_string());
        let mut exposure = finding(
            "routes/continueCode.ts",
            12,
            VulnClass::InfoLeak,
            "Information exposure",
        );
        exposure.line_end = 21;
        exposure.cwe = Some("CWE-200".to_string());
        // The most severe lens, so it must be the survivor whichever
        // order the four arrive in.
        exposure.cvss_score = Some(7.5);

        let mut cfg = Step7Config::new("m");
        cfg.semantic = false;
        let (out, _) = run_dedup(
            &FailingClient,
            &[hardcoded, inconsistent, authz, exposure],
            &cfg,
            &ContextPackage::default(),
        )
        .await;

        assert_eq!(out.findings.len(), 2, "4 findings become 2");
        let merged = out
            .findings
            .iter()
            .find(|f| f.line_end == 21)
            .expect("the 12-21 cluster survives");
        assert_eq!(merged.cwe.as_deref(), Some("CWE-200"));
        assert_eq!(merged.title, "Information exposure");
        assert_eq!(merged.vuln_class, VulnClass::InfoLeak);
        assert_eq!(
            merged.related_cwes,
            vec!["CWE-345".to_string(), "CWE-284".to_string()],
            "no lens is lost"
        );
        // The line-13 finding is a different range, so exact-equality
        // never touches it.
        assert!(out
            .findings
            .iter()
            .any(|f| f.cwe.as_deref() == Some("CWE-798") && f.related_cwes.is_empty()));
        assert_eq!(out.dropped.len(), 2);
        assert!(out
            .dropped
            .iter()
            .all(|d| d.detail == clustering::SAME_RANGE_CWE_REASON));
    }

    #[tokio::test]
    async fn the_same_range_cwe_merge_can_be_switched_off() {
        let mut a = finding("routes/continueCode.ts", 12, VulnClass::Other, "a");
        a.line_end = 21;
        a.cwe = Some("CWE-345".to_string());
        let mut b = finding("routes/continueCode.ts", 12, VulnClass::Other, "b");
        b.line_end = 21;
        b.cwe = Some("CWE-284".to_string());

        let mut cfg = Step7Config::new("m");
        cfg.semantic = false;
        cfg.merge_same_range_cwes = false;
        let (out, _) = run_dedup(&FailingClient, &[a, b], &cfg, &ContextPackage::default()).await;
        assert_eq!(out.findings.len(), 2);
        assert!(out.findings.iter().all(|f| f.related_cwes.is_empty()));
    }

    /// The 2026-09-06 Flask field case, verbatim: ONE command injection
    /// reported twice — anchored at the source end (`handlers.py:37-39`)
    /// and at the sink end (`shell.py:5-6`) — with identical
    /// `source_ref`/`sink_ref`. Different anchor files, so no same-file
    /// rule could see it, and the duplicate cost a whole remediation
    /// cycle. The SINK-anchored copy must be the survivor: that is where
    /// the fix goes and what S10 edits.
    #[tokio::test]
    async fn one_flow_reported_from_both_ends_collapses_onto_the_sink_anchored_copy() {
        let mut source_end = finding("handlers.py", 37, VulnClass::Injection, "cmdi at source");
        source_end.line_end = 39;
        source_end.cwe = Some("CWE-78".to_string());
        source_end.source_ref = Some("handlers.py:38".to_string());
        source_end.sink_ref = Some("shell.py:6".to_string());
        let mut sink_end = finding("shell.py", 5, VulnClass::Injection, "cmdi at sink");
        sink_end.line_end = 6;
        sink_end.cwe = Some("CWE-78".to_string());
        sink_end.source_ref = Some("handlers.py:38".to_string());
        sink_end.sink_ref = Some("shell.py:6".to_string());

        let mut cfg = Step7Config::new("m");
        cfg.semantic = false;

        // Both arrival orders, since the whole point is that the survivor
        // is content-derived rather than order-inherited.
        for input in [
            vec![source_end.clone(), sink_end.clone()],
            vec![sink_end.clone(), source_end.clone()],
        ] {
            let (out, _) =
                run_dedup(&FailingClient, &input, &cfg, &ContextPackage::default()).await;
            assert_eq!(out.findings.len(), 1, "one flow, one finding");
            assert_eq!(out.findings[0].file, "shell.py", "the sink end survives");
            assert_eq!(out.dropped.len(), 1);
            assert_eq!(out.dropped[0].file, "handlers.py");
            assert_eq!(out.dropped[0].detail, clustering::FLOW_REASON);
            // Different files, so this is a second location worth listing
            // rather than a re-detection of one site.
            assert_eq!(out.findings[0].duplicates.len(), 1);
            assert_eq!(out.findings[0].duplicates[0].file, "handlers.py");
        }
    }

    #[test]
    fn sink_anchor_rank_needs_both_refs_and_a_matching_anchor_file() {
        let mut f = finding("shell.py", 5, VulnClass::Injection, "t");
        assert_eq!(sink_anchor_rank(&f), 1, "no refs at all");
        f.sink_ref = Some("shell.py:6".to_string());
        assert_eq!(sink_anchor_rank(&f), 1, "sink alone is not a flow");
        f.source_ref = Some("handlers.py:38".to_string());
        assert_eq!(sink_anchor_rank(&f), 0);
        // Normalization applies to both halves of the comparison.
        f.sink_ref = Some("./shell.py:6".to_string());
        assert_eq!(sink_anchor_rank(&f), 0);
        f.file = "./shell.py".to_string();
        assert_eq!(sink_anchor_rank(&f), 0);
        // A ref with no line at all is taken as a bare path.
        f.sink_ref = Some("shell.py".to_string());
        assert_eq!(sink_anchor_rank(&f), 0);
        // Anchored somewhere the flow does not end.
        f.sink_ref = Some("other.py:6".to_string());
        assert_eq!(sink_anchor_rank(&f), 1);
        // A blank ref is an absent ref.
        f.sink_ref = Some("   ".to_string());
        assert_eq!(sink_anchor_rank(&f), 1);
    }

    #[test]
    fn severity_key_scales_the_cvss_score_to_an_orderable_integer() {
        let mut f = finding("a.rs", 1, VulnClass::Injection, "t");
        assert_eq!(severity_key(&f), None);
        f.cvss_score = Some(9.85);
        assert_eq!(severity_key(&f), Some(985));
        f.cvss_score = Some(0.0);
        assert_eq!(severity_key(&f), Some(0));
        // `None` must lose to any score, including 0.0.
        assert!(severity_key(&f) > None);
    }

    #[test]
    fn stable_canonical_sort_puts_the_most_severe_of_one_range_first() {
        let mut low = finding("a.rs", 10, VulnClass::Injection, "low");
        low.cvss_score = Some(4.0);
        let mut high = finding("a.rs", 10, VulnClass::Other, "high");
        high.cvss_score = Some(9.1);
        let unscored = finding("a.rs", 10, VulnClass::HeapOverflow, "unscored");

        let mut findings = vec![unscored, low, high];
        sort_for_stable_canonical(&mut findings);
        let titles: Vec<&str> = findings.iter().map(|f| f.title.as_str()).collect();
        assert_eq!(titles, vec!["high", "low", "unscored"]);
    }

    #[test]
    fn stable_canonical_sort_orders_by_file_then_line_then_class() {
        let mut findings = vec![
            finding("b.rs", 1, VulnClass::Injection, "t"),
            finding("a.rs", 50, VulnClass::Injection, "t"),
            finding("a.rs", 5, VulnClass::Other, "t"),
            finding("a.rs", 5, VulnClass::Injection, "t"),
        ];
        sort_for_stable_canonical(&mut findings);
        let key: Vec<(&str, i64, &str)> = findings
            .iter()
            .map(|f| (f.file.as_str(), f.line_start, f.vuln_class.as_str()))
            .collect();
        assert_eq!(
            key,
            vec![
                ("a.rs", 5, VulnClass::Injection.as_str()),
                ("a.rs", 5, VulnClass::Other.as_str()),
                ("a.rs", 50, VulnClass::Injection.as_str()),
                ("b.rs", 1, VulnClass::Injection.as_str()),
            ]
        );
    }

    #[test]
    fn stable_canonical_sort_puts_the_best_evidenced_duplicate_first() {
        // Same file/line/class: verifier confidence decides, then S4
        // confidence, then title — so the survivor of the dedup below is
        // content-derived, never arrival-ordered.
        let mut weak = finding("a.rs", 10, VulnClass::Injection, "weak");
        weak.verdict_confidence = Some(6);
        let mut strong = finding("a.rs", 10, VulnClass::Injection, "strong");
        strong.verdict_confidence = Some(9);
        let mut unverified = finding("a.rs", 10, VulnClass::Injection, "unverified");
        unverified.verdict_confidence = None;

        let mut findings = vec![unverified, weak, strong];
        sort_for_stable_canonical(&mut findings);
        let titles: Vec<&str> = findings.iter().map(|f| f.title.as_str()).collect();
        assert_eq!(titles, vec!["strong", "weak", "unverified"]);
    }

    #[test]
    fn stable_canonical_sort_prefers_the_specific_then_lower_cwe_lens() {
        // Same file/line/class: the CWE decides before confidence does,
        // so the survivor of a same-range merge cannot flip with the
        // model's confidence from one run to the next.
        let mut umbrella = finding("a.py", 28, VulnClass::Injection, "input validation");
        umbrella.cwe = Some("CWE-20".to_string());
        umbrella.confidence = 0.95;
        let mut sqli = finding("a.py", 28, VulnClass::Injection, "sqli");
        sqli.cwe = Some("CWE-89".to_string());
        sqli.confidence = 0.5;
        let mut idor = finding("a.py", 28, VulnClass::Injection, "idor");
        idor.cwe = Some("CWE-639".to_string());
        idor.confidence = 0.9;
        let mut traversal = finding("a.py", 28, VulnClass::Injection, "traversal");
        traversal.cwe = Some("CWE-22".to_string());
        traversal.confidence = 0.6;
        let mut unclassed = finding("a.py", 28, VulnClass::Injection, "no cwe");
        unclassed.confidence = 0.99;

        for order in [[0, 1, 2, 3, 4], [4, 3, 2, 1, 0], [2, 4, 0, 3, 1]] {
            let pool = [&umbrella, &sqli, &idor, &traversal, &unclassed];
            let mut findings: Vec<Finding> = order.iter().map(|&i| pool[i].clone()).collect();
            sort_for_stable_canonical(&mut findings);
            let titles: Vec<&str> = findings.iter().map(|f| f.title.as_str()).collect();
            assert_eq!(
                titles,
                vec!["traversal", "sqli", "idor", "input validation", "no cwe"]
            );
        }
    }

    #[test]
    fn stable_canonical_sort_breaks_a_full_tie_on_confidence_then_title() {
        let mut low = finding("a.rs", 10, VulnClass::Injection, "zzz");
        low.confidence = 0.2;
        let mut high_b = finding("a.rs", 10, VulnClass::Injection, "bbb");
        high_b.confidence = 0.8;
        let mut high_a = finding("a.rs", 10, VulnClass::Injection, "aaa");
        high_a.confidence = 0.8;

        let mut findings = vec![low, high_b, high_a];
        sort_for_stable_canonical(&mut findings);
        let titles: Vec<&str> = findings.iter().map(|f| f.title.as_str()).collect();
        assert_eq!(titles, vec!["aaa", "bbb", "zzz"]);
    }

    #[tokio::test]
    async fn two_permutations_of_the_same_input_dedup_identically() {
        // The determinism property the pre-sort exists for: whichever
        // order S6 hands findings over in, the same finding must survive
        // as canonical, carrying the same line/snippet (and therefore the
        // same SARIF fingerprint).
        let mut early = finding("a.rs", 10, VulnClass::Injection, "early");
        early.verdict_confidence = Some(9);
        early.code_snippet = "the canonical snippet".to_string();
        let mut late = finding("a.rs", 12, VulnClass::Injection, "late");
        late.verdict_confidence = Some(8);
        late.code_snippet = "the duplicate snippet".to_string();
        let other = finding("z.rs", 99, VulnClass::Other, "unrelated");

        let mut cfg = Step7Config::new("m");
        cfg.line_tolerance = 3;
        cfg.semantic = false;

        let forward = vec![early.clone(), late.clone(), other.clone()];
        let reversed = vec![other, late, early];

        let (out_a, _) =
            run_dedup(&FailingClient, &forward, &cfg, &ContextPackage::default()).await;
        let (out_b, _) =
            run_dedup(&FailingClient, &reversed, &cfg, &ContextPackage::default()).await;

        assert_eq!(out_a, out_b);
        assert_eq!(out_a.findings.len(), 2);
        assert_eq!(out_a.findings[0].title, "early");
        assert_eq!(out_a.findings[0].code_snippet, "the canonical snippet");
        assert_eq!(out_a.dropped.len(), 1);
        assert_eq!(out_a.dropped[0].title, "late");
    }

    #[tokio::test]
    async fn single_finding_short_circuits_with_no_dedup() {
        let findings = vec![finding("a.rs", 10, VulnClass::Injection, "t")];
        let (out, reason) = run_dedup(
            &ScriptedClient {
                reply: String::new(),
            },
            &findings,
            &Step7Config::new("m"),
            &ContextPackage::default(),
        )
        .await;
        assert_eq!(out.findings.len(), 1);
        assert!(out.dropped.is_empty());
        assert!(reason.is_none());
    }

    #[tokio::test]
    async fn trivial_duplicates_collapse_without_any_llm_call() {
        // Two findings within line tolerance collapse in 7a; `unresolved`
        // then has < 2 entries so 7b is never attempted — the
        // FailingClient here would error if it were ever called.
        let findings = vec![
            finding("a.rs", 10, VulnClass::Injection, "t1"),
            finding("a.rs", 11, VulnClass::Injection, "t2"),
        ];
        let mut cfg = Step7Config::new("m");
        cfg.line_tolerance = 3;
        let (out, reason) =
            run_dedup(&FailingClient, &findings, &cfg, &ContextPackage::default()).await;
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.dropped.len(), 1);
        assert_eq!(out.dropped[0].reason, DropReason::Duplicate);
        assert!(reason.is_none());
    }

    #[tokio::test]
    async fn semantic_pass_merges_distinct_findings_the_prefilter_missed() {
        let findings = vec![
            finding("a.rs", 10, VulnClass::Injection, "t1"),
            finding("b.rs", 500, VulnClass::Injection, "t2"),
            finding("c.rs", 900, VulnClass::Other, "t3"),
        ];
        let reply = "index=0 is_duplicate=false canonical=-1 reasoning=\"x\"\n\
                     index=1 is_duplicate=true canonical=0 reasoning=\"shared helper\"\n\
                     index=2 is_duplicate=false canonical=-1 reasoning=\"y\"\n";
        let (out, reason) = run_dedup(
            &ScriptedClient {
                reply: reply.to_string(),
            },
            &findings,
            &Step7Config::new("m"),
            &ContextPackage::default(),
        )
        .await;
        assert_eq!(out.findings.len(), 2);
        assert_eq!(out.dropped.len(), 1);
        assert_eq!(out.dropped[0].detail, "shared helper");
        assert!(reason.is_none());
    }

    #[tokio::test]
    async fn semantic_call_failure_degrades_to_deterministic_only_results() {
        let findings = vec![
            finding("a.rs", 10, VulnClass::Injection, "t1"),
            finding("b.rs", 500, VulnClass::Injection, "t2"),
            finding("c.rs", 900, VulnClass::Other, "t3"),
        ];
        let mut cfg = Step7Config::new("m");
        cfg.retry_backoff_base = std::time::Duration::ZERO;
        let (out, reason) =
            run_dedup(&FailingClient, &findings, &cfg, &ContextPackage::default()).await;
        assert_eq!(out.findings.len(), 3);
        assert!(out.dropped.is_empty());
        assert!(reason.unwrap().contains("semantic dedup call failed"));
    }

    #[tokio::test]
    async fn semantic_call_retries_a_transient_failure_then_succeeds() {
        let findings = vec![
            finding("a.rs", 10, VulnClass::Injection, "t1"),
            finding("b.rs", 500, VulnClass::Injection, "t2"),
            finding("c.rs", 900, VulnClass::Other, "t3"),
        ];
        let mut cfg = Step7Config::new("m");
        cfg.retry_backoff_base = std::time::Duration::ZERO;
        let client = RetryingClient::new(2);
        let (out, reason) = run_dedup(&client, &findings, &cfg, &ContextPackage::default()).await;
        assert_eq!(out.findings.len(), 3);
        assert!(reason.is_none());
    }

    #[tokio::test]
    async fn a_second_semantic_merge_targeting_an_already_resolved_index_is_ignored() {
        // Two merge lines both name global index 2 (a malformed-but-plausible
        // model response). The first resolves it against 0; the second,
        // processed in the same loop, must be skipped since index 2 is now
        // already a `canonical_of` key — exercises that guard's false path.
        let findings = vec![
            finding("a.rs", 10, VulnClass::Injection, "t1"),
            finding("b.rs", 500, VulnClass::Injection, "t2"),
            finding("c.rs", 900, VulnClass::Other, "t3"),
        ];
        let reply = "index=2 is_duplicate=true canonical=0 reasoning=\"first\"\n\
                     index=2 is_duplicate=true canonical=1 reasoning=\"second\"\n";
        let (out, _) = run_dedup(
            &ScriptedClient {
                reply: reply.to_string(),
            },
            &findings,
            &Step7Config::new("m"),
            &ContextPackage::default(),
        )
        .await;
        assert_eq!(out.dropped.len(), 1);
        assert_eq!(out.dropped[0].detail, "first");
        assert_eq!(out.dropped[0].canonical_idx, Some(0));
    }

    /// A gate stuck in one position, for the S7 case where the question
    /// is asked exactly once.
    #[derive(Debug)]
    struct FixedGate(bool);

    impl bc_pipeline_core::BudgetGate for FixedGate {
        fn should_stop(&self) -> bool {
            self.0
        }
        fn stop_reason(&self) -> String {
            "token budget of 3000000 reached (3012044 spent)".to_string()
        }
    }

    #[tokio::test]
    async fn a_tripped_budget_gate_skips_the_semantic_call_and_degrades() {
        // `FailingClient` would error if the call were made at all.
        let findings = vec![
            finding("a.rs", 10, VulnClass::Injection, "t1"),
            finding("b.rs", 500, VulnClass::Injection, "t2"),
            finding("c.rs", 900, VulnClass::Other, "t3"),
        ];
        let mut cfg = Step7Config::new("m");
        cfg.budget_gate = Some(std::sync::Arc::new(FixedGate(true)));
        let (out, reason) =
            run_dedup(&FailingClient, &findings, &cfg, &ContextPackage::default()).await;
        // The deterministic pass still ran and its results still stand.
        assert_eq!(out.findings.len(), 3);
        assert_eq!(
            reason.unwrap(),
            "semantic dedup skipped: token budget of 3000000 reached (3012044 spent)"
        );
    }

    #[tokio::test]
    async fn an_untripped_budget_gate_lets_the_semantic_call_happen() {
        let findings = vec![
            finding("a.rs", 10, VulnClass::Injection, "t1"),
            finding("b.rs", 500, VulnClass::Injection, "t2"),
            finding("c.rs", 900, VulnClass::Other, "t3"),
        ];
        let mut cfg = Step7Config::new("m");
        cfg.budget_gate = Some(std::sync::Arc::new(FixedGate(false)));
        let reply = "index=1 is_duplicate=true canonical=0 reasoning=\"shared helper\"\n";
        let (out, reason) = run_dedup(
            &ScriptedClient {
                reply: reply.to_string(),
            },
            &findings,
            &cfg,
            &ContextPackage::default(),
        )
        .await;
        assert_eq!(out.findings.len(), 2);
        assert!(reason.is_none());
    }

    #[tokio::test]
    async fn a_tripped_gate_says_nothing_when_the_call_would_not_have_happened_anyway() {
        // `semantic: false` already skips the call, so there is no
        // budget-skipped work to report and nothing to degrade over.
        let findings = vec![
            finding("a.rs", 10, VulnClass::Injection, "t1"),
            finding("b.rs", 500, VulnClass::Injection, "t2"),
            finding("c.rs", 900, VulnClass::Other, "t3"),
        ];
        let mut cfg = Step7Config::new("m");
        cfg.semantic = false;
        cfg.budget_gate = Some(std::sync::Arc::new(FixedGate(true)));
        let (_, reason) =
            run_dedup(&FailingClient, &findings, &cfg, &ContextPackage::default()).await;
        assert!(reason.is_none());
    }

    #[tokio::test]
    async fn semantic_disabled_skips_the_llm_call_entirely() {
        let findings = vec![
            finding("a.rs", 10, VulnClass::Injection, "t1"),
            finding("b.rs", 500, VulnClass::Injection, "t2"),
            finding("c.rs", 900, VulnClass::Other, "t3"),
        ];
        let mut cfg = Step7Config::new("m");
        cfg.semantic = false;
        let (out, reason) =
            run_dedup(&FailingClient, &findings, &cfg, &ContextPackage::default()).await;
        assert_eq!(out.findings.len(), 3);
        assert!(reason.is_none());
    }

    #[tokio::test]
    async fn stage7_run_wraps_a_successful_dedup_as_ok() {
        let findings = vec![
            finding("a.rs", 10, VulnClass::Injection, "t1"),
            finding("a.rs", 11, VulnClass::Injection, "t2"),
        ];
        let stage = Stage7::new(
            std::sync::Arc::new(ScriptedClient {
                reply: String::new(),
            }),
            Step7Config::new("m"),
        );
        let outcome = stage
            .run(Step7Input {
                findings,
                ctx: ContextPackage::default(),
            })
            .await
            .unwrap();
        assert!(!outcome.is_degraded());
        assert_eq!(outcome.into_value().findings.len(), 1);
    }

    #[tokio::test]
    async fn stage7_run_wraps_a_semantic_failure_as_degraded() {
        let findings = vec![
            finding("a.rs", 10, VulnClass::Injection, "t1"),
            finding("b.rs", 500, VulnClass::Injection, "t2"),
            finding("c.rs", 900, VulnClass::Other, "t3"),
        ];
        let mut cfg = Step7Config::new("m");
        cfg.retry_backoff_base = std::time::Duration::ZERO;
        let stage = Stage7::new(std::sync::Arc::new(FailingClient), cfg);
        let outcome = stage
            .run(Step7Input {
                findings,
                ctx: ContextPackage::default(),
            })
            .await
            .unwrap();
        assert!(outcome.is_degraded());
        assert!(outcome
            .reason()
            .unwrap()
            .contains("semantic dedup call failed"));
    }
}
