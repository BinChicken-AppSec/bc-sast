//! S4 — Deep-dive: N sequential single-shot LLM calls per chunk,
//! majority-voted within the chunk, then collapsed again across chunks.
//! Ported from `vvaharness/pipeline/stages/s4_deepdive.py`.
//!
//! Like `bc-stage-s6`, this stage has **no internal degrade-and-continue
//! policy** at the `StageOutcome` level: a per-chunk outcome
//! (`Completed`/`Error`/`Guardrail`) is DATA carried on
//! `DeepdiveOutput.outcomes`, not a stage-level degrade — `Stage4::run`
//! only ever returns `Ok` or `Err`. The one genuinely fatal path is the
//! guardrail-abort gate below.
//!
//! **Fixes a real bug in the Python original rather than reproducing
//! it.** The Python `run()` has a `guardrail_hits >= guardrail_gate and
//! successes == 0` fail-fast check — but it can never fire. Every run
//! inside `_deepdive_chunk` is wrapped in a bare `except Exception`,
//! which catches `GuardrailBlocked` right along with everything else and
//! discards its type; if *every* run in a chunk fails this way,
//! `_deepdive_chunk` re-raises a generic `RuntimeError`, which no longer
//! `isinstance`-matches `run()`'s `except GuardrailBlocked` handler. So
//! `guardrail_hits` never increments, no matter how many chunks were
//! actually guardrail-blocked. This port's `single_run::RunError` keeps
//! the guardrail/non-guardrail distinction alive through
//! [`ChunkError::AllRunsGuardrailBlocked`] vs. [`ChunkError::AllRunsFailed`]
//! specifically so the outer gate (mirroring `bc-stage-s6`'s already
//! correct one) can actually trip.
//!
//! Concurrency mirrors `bc-stage-s6`: `config.parallel` chunks in flight
//! via a `tokio::sync::Semaphore`, drained in completion order via
//! `tokio::task::JoinSet` (matching Python's `as_completed`), then
//! reassembled in risk-rank order before the final cross-chunk collapse —
//! matching the Python original's own `for chunk in chunks:
//! all_findings.extend(...)` reassembly.
//!
//! **Deliberately not ported**: `_effective_runs`'s CLI/SDK backend-
//! *detection* branches — there is no CLI-subprocess backend in this port
//! (see `bc-llm-client::LlmError::GuardrailBlocked`'s own docs); every
//! call goes through the same gateway-mediated `LlmClient`, so which
//! backend a role resolves to isn't something this stage can or needs to
//! detect. Everything else in `_effective_runs` DOES survive, in
//! [`effective_runs`]: an invalid `runs < 1` degrades to `1/1` with a
//! warning (matching Python's own `if runs < 1` branch — a misconfigured
//! `step4.runs: 0` must not silently complete a chunk having made zero
//! LLM calls); `runs > 1` at an explicit `temperature: 0` also collapses
//! to `1/1`, since greedy samples of one prompt cannot diverge and voting
//! over N identical answers just costs N×; and a `vote_threshold` above
//! the actual run count is clamped down to reachable.
//!
//! **Deliberately not ported**: every `print(..., file=sys.stderr)`
//! diagnostic (`_label`, per-run/per-chunk progress lines, the
//! cross-chunk-collapse count) — pure diagnostics with no other side
//! effect, dropped per this project's established convention. Also not
//! ported: `cli.aborted()`/`KeyboardInterrupt` handling, the same
//! process-lifetime concern already deferred by `bc-stage-s6`.
//!
//! **Net-new versus Python**: [`reanchor`] deterministically corrects the
//! anchor of a temporal C/C++ finding (use-after-free, double-free,
//! TOCTOU) that the model reported at the `free`/`delete` instead of at
//! the later unsafe use the reply schema asks for — before the finding is
//! voted on, so the vote, S7's dedup, the SARIF fingerprint and any PR
//! comment all key on the corrected range. The Python original carries
//! the same schema instruction and enforces it nowhere.
//!
//! The `step4.timeout` key IS ported, as [`Step4Config::timeout_secs`] —
//! see `bc-stage-s3`'s module doc for why the earlier "no per-call
//! timeout field" reasoning was wrong about the Python original.

mod code_loading;
mod cwe_kb;
mod hints;
mod neighbor;
mod prompts;
mod reanchor;
mod redact_source;
mod single_run;
mod slice;
mod vote;
mod wire;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use bc_llm_client::LlmClient;
use bc_model::{Chunk, ContextPackage, Finding};
use bc_pipeline_core::{PipelineStage, StageError, StageOutcome};

#[derive(Debug, Clone)]
pub struct Step4Config {
    pub model: String,
    pub parallel: usize,
    pub max_tokens: u32,
    pub max_findings_per_run: Option<usize>,
    pub neighbor_context_lines: i64,
    pub neighbor_context_max: usize,
    pub runs: usize,
    pub vote_threshold: usize,
    pub specialist_runs: usize,
    pub line_bucket: i64,
    /// `"discover"` (default, matches Python) always uses the open-ended
    /// hunt prompt. `"confirm_refute"` switches chunks carrying a static
    /// taint path (`chunk.path_funcs` non-empty) to the taint-first
    /// confirm/refute prompt instead — see `prompts::build_confirm_refute_prompt`.
    pub taint_prompt_mode: String,
    /// Overrides `runs`/`vote_threshold` for a taint chunk specifically
    /// (`chunk.path_funcs` non-empty) — confirm/refute is a binary
    /// question, so voting across multiple runs adds no signal the way
    /// it does for the open-ended discover prompt. `None` (default)
    /// falls through to the global `runs`/`vote_threshold` unchanged,
    /// matching `default.yaml`'s own unset `taint_runs`; ignored
    /// entirely for a specialist chunk, which already forces
    /// `specialist_runs`/threshold `1` regardless.
    pub taint_runs: Option<usize>,
    /// How many times each single deep-dive call retries after a
    /// retryable [`bc_llm_client::LlmError`] (429/5xx/connection failure)
    /// before giving up and propagating it — see
    /// [`bc_llm_agentic::chat_with_retry`].
    pub max_transient_retries: u32,
    /// Base delay before a transient-retry attempt; the actual delay is
    /// `retry_backoff_base * attempt_number` (linear backoff).
    pub retry_backoff_base: std::time::Duration,
    /// Sampling temperature for every deep-dive call. `None` (the
    /// default) sends no `temperature` at all, leaving the provider's own
    /// default — which for both dialects is `1.0`, i.e. maximally
    /// divergent between two scans of the same repo. Ported from the
    /// Python original's per-role `models.<role>.temperature`
    /// (`backends/llm.py::resolve`), which this port had dropped.
    ///
    /// Interacts with [`Self::runs`]: `Some(0.0)` makes N samples
    /// identical by construction, so [`effective_runs`] clamps `runs` to
    /// `1` rather than paying N× for N copies of one answer.
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
    ///
    /// Note this is a per-*stage* seed, not per-run: with `runs > 1` every
    /// run of a chunk sends the SAME seed, so a provider that honours it
    /// makes the vote unanimous by construction. Set a seed or set
    /// `runs > 1`, not both.
    pub seed: Option<u64>,
    /// Per-call wall-clock deadline in seconds, overriding the shared
    /// gateway client's own 300 s default. Ported from `step4.timeout`
    /// (`_STEP_DEFAULTS`' `1800`, matched by every shipped profile), which
    /// this port previously had no home for — see this crate's module doc
    /// for the correction.
    pub timeout_secs: Option<u64>,
    /// `"file"` (the default) loads a chunk's files whole (or in sliding
    /// windows when it is LARGE). `"function"` ships only the functions
    /// the chunk is actually about — the def-span of each hop on the
    /// taint path, or the highest-ranked call-graph/entry-point/sink
    /// spans for a non-taint chunk — plus a few context lines either
    /// side. See [`crate::slice`] for the two tiers and their per-file
    /// fallbacks.
    ///
    /// Ported from `_slice_mode` (`s4_deepdive.py:993-1007`). Python
    /// declares the shipped key as `step3.taint_chunk_slice`
    /// (`_STEP_DEFAULTS`' `"file"`, raised to `"function"` by
    /// `profiles/taint.yaml` alone) with an optional
    /// `step4.taint_chunk_slice` override that no shipped profile sets;
    /// this port collapses the two into this one field and resolves the
    /// step4-then-step3 precedence once, at config load
    /// (`bc_cli::config_overrides`). **The default is `"file"`, so
    /// nothing changes for an existing config** — verified against
    /// `_STEP_DEFAULTS`, not assumed.
    pub taint_chunk_slice: String,
    /// Consulted once per chunk, on that chunk's own task, immediately
    /// before its first LLM call — see [`bc_pipeline_core::BudgetGate`]
    /// for why a stage-boundary check alone is not enough. `None` (the
    /// default) is an unbounded stage, exactly as before this existed.
    ///
    /// The check deliberately lives inside the task rather than in the
    /// spawn loop: every chunk is spawned up-front and `parallel` is
    /// enforced by a semaphore permit acquired *inside* the task, so a
    /// pre-spawn check would run 444 times in a burst before a single
    /// token had been spent and could never trip.
    pub budget_gate: Option<bc_pipeline_core::BudgetGateRef>,
    /// How many def-spans the `function`-mode graph slice may take from
    /// any one file before shipping that file whole instead. Ported from
    /// `_STEP_DEFAULTS`' `step4.frontier_max_funcs_per_file` (`24`), read
    /// by `_load_graph_slice` (`s4_deepdive.py:1022`). Only consulted
    /// when [`Self::taint_chunk_slice`] is `"function"`.
    pub frontier_max_funcs_per_file: usize,
}

impl Step4Config {
    /// `neighbor_context_lines: 20`/`neighbor_context_max: 40` here (vs.
    /// `25`/`50` in `bc_config::step_defaults()`) is deliberate, not
    /// drift — this mirrors `config/profiles/default.yaml`'s own
    /// override of `_STEP_DEFAULTS`' shipped `25`/`50`, since that's the
    /// profile Python actually loads when no `--config` is passed at
    /// all. See `bc_config::step_defaults`'s own module doc comment for
    /// the full explanation (verified against the real Python source,
    /// not assumed).
    pub fn new(model: impl Into<String>) -> Self {
        Step4Config {
            model: model.into(),
            parallel: 5,
            max_tokens: 64_000,
            max_findings_per_run: Some(10),
            neighbor_context_lines: 20,
            neighbor_context_max: 40,
            runs: 1,
            vote_threshold: 1,
            specialist_runs: 1,
            line_bucket: 10,
            taint_prompt_mode: "discover".to_string(),
            taint_runs: None,
            max_transient_retries: 4,
            retry_backoff_base: std::time::Duration::from_secs(10),
            temperature: None,
            top_p: None,
            seed: None,
            timeout_secs: Some(1800),
            taint_chunk_slice: "file".to_string(),
            budget_gate: None,
            frontier_max_funcs_per_file: 24,
        }
    }
}

pub struct Step4Input {
    pub chunks: Vec<Chunk>,
    pub ctx: ContextPackage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkOutcome {
    Completed,
    Error,
    Guardrail,
    /// Never analysed at all: the scan's token or wall-clock budget was
    /// already spent when this chunk's turn came up. Distinct from
    /// `Error` on purpose — nothing went wrong, the work simply was not
    /// bought, and a reader (and `bc_orchestrator::build_metrics`) must
    /// be able to tell "we tried and failed" from "we never tried".
    Skipped,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct DeepdiveOutput {
    pub findings: Vec<Finding>,
    pub outcomes: BTreeMap<String, ChunkOutcome>,
    /// `Some(reason)` when [`Step4Config::budget_gate`] tripped part-way
    /// through, naming the budget and how far the stage got. The findings
    /// present are still valid; the chunks marked
    /// [`ChunkOutcome::Skipped`] simply were not analysed.
    pub budget_stop: Option<String>,
}

/// `(runs, vote_threshold)`, ported from `_effective_runs`
/// (`pipeline/stages/s4_deepdive.py:166-217`): `runs=0` degrades to `1/1`
/// with a warning — matching Python's own `if runs < 1` branch — rather
/// than silently completing a chunk with zero LLM calls and reporting it
/// as scanned; and a `temperature` of exactly `0` collapses `runs` to `1`,
/// because N greedy samples of one prompt cannot diverge, so the extra
/// N-1 calls buy nothing but N× the cost and latency. That second clamp
/// is Python's own `_effective_runs` guard, restored here: an earlier
/// revision of this crate's module doc dismissed the whole function as
/// unportable because its CLI/SDK *temperature-support* branches have no
/// analogue in this port — but the temperature-0 collapse is not one of
/// those branches, it's a plain arithmetic fact about greedy decoding
/// that holds for every backend. Otherwise the threshold is clamped so it
/// can always be reached.
fn effective_runs(runs: usize, vote_threshold: usize, temperature: Option<f64>) -> (usize, usize) {
    if runs < 1 {
        tracing::warn!("[s4] invalid runs={runs}; forcing runs=1, vote_threshold=1.");
        return (1, 1);
    }
    if runs > 1 && temperature == Some(0.0) {
        tracing::warn!(
            "[s4] runs={runs} with temperature=0 cannot produce divergent samples to vote \
             over; forcing runs=1, vote_threshold=1. Raise the temperature or set runs=1."
        );
        return (1, 1);
    }
    (runs, vote_threshold.clamp(1, runs))
}

/// Why every run in a chunk failed — distinguished so the outer gate can
/// count only genuine guardrail exhaustion (see module docs).
pub enum ChunkError {
    AllRunsGuardrailBlocked,
    AllRunsFailed,
    /// Not a failure: the budget gate said stop before this chunk's first
    /// LLM call was ever made. Carries the gate's reason so the stage can
    /// report which budget ran out.
    BudgetStopped(String),
}

/// Ported from `_deepdive_chunk`: load the chunk's code (plus any
/// out-of-chunk neighbor context), run `runs_n` sequential single-shot
/// calls, and majority-vote the survivors. A specialist chunk always
/// overrides to `specialist_runs`/threshold `1` — it's a different lens,
/// not a consistency probe (s6 adversarial verification is the FP filter
/// for those).
async fn deepdive_chunk(
    client: &dyn LlmClient,
    chunk: &Chunk,
    ctx: &ContextPackage,
    repo_root: &Path,
    config: &Step4Config,
) -> Result<Vec<Finding>, ChunkError> {
    let (mut code, sliced) = code_loading::load_chunk_code(chunk, ctx, repo_root, config);
    code.push_str(&neighbor::neighbor_context(
        chunk,
        ctx,
        repo_root,
        config.neighbor_context_lines,
        config.neighbor_context_max,
    ));

    let (runs_n, threshold) = if chunk.specialist.is_some() {
        (config.specialist_runs, 1)
    } else {
        let (mut runs_n, mut threshold) =
            effective_runs(config.runs, config.vote_threshold, config.temperature);
        if !chunk.path_funcs.is_empty() {
            if let Some(taint_runs) = config.taint_runs {
                runs_n = taint_runs.max(1);
                threshold = threshold.min(runs_n).max(1);
            }
        }
        (runs_n, threshold)
    };

    let mut runs: Vec<Vec<Finding>> = Vec::with_capacity(runs_n);
    let mut runs_ok = 0usize;
    let mut all_guardrail = true;

    for _ in 0..runs_n {
        match single_run::single_run(
            client,
            chunk,
            ctx,
            &code,
            repo_root,
            &config.model,
            config.max_tokens,
            config.max_findings_per_run,
            &config.taint_prompt_mode,
            sliced,
            config.max_transient_retries,
            config.retry_backoff_base,
            single_run::Sampling::from_config(config),
        )
        .await
        {
            Ok(mut findings) => {
                runs_ok += 1;
                all_guardrail = false;
                // Diff-scope active: `neighbor_context` above splices in
                // read-only excerpts of files outside this (already
                // diff-trimmed) chunk, explicitly labeled "do NOT report
                // findings in these files" — but that's only a prompt
                // instruction. This is the code-level backstop: a model
                // that reports on one of those files anyway (S4's own
                // system prompt pushes it to examine every line it can
                // see, so this is a routine failure mode, not an edge
                // case) gets silently dropped here rather than
                // round-tripping to `report.sarif`/a PR comment for a
                // file the PR never touched.
                // Gated on `diff_scope_active`, not on the changed set
                // being non-empty: the backstop has to hold for a
                // diff-scoped scan of zero files too.
                if ctx.diff_scope_active {
                    findings.retain(|f| chunk.files.contains(&f.file));
                }
                runs.push(findings);
            }
            Err(single_run::RunError::QuotaExhausted(message)) => {
                // Not a per-chunk failure to absorb and retry past: the
                // provider has said the account cannot fund anything
                // more, so the remaining runs of this chunk and every
                // chunk after it would fail identically. Trip the shared
                // gate so the chunks still queued behind this one skip
                // straight past their own LLM calls, and hand the same
                // reason back through the ordinary budget-stop path —
                // the outer loop turns it into `ChunkOutcome::Skipped`
                // plus a `budget_stop` line in Scan Health.
                let reason = format!("provider quota exhausted — {message}");
                if let Some(gate) = &config.budget_gate {
                    gate.trip(reason.clone());
                }
                return Err(ChunkError::BudgetStopped(reason));
            }
            Err(single_run::RunError::GuardrailBlocked(_)) => {
                runs.push(Vec::new());
            }
            Err(single_run::RunError::Other(_)) => {
                all_guardrail = false;
                runs.push(Vec::new());
            }
        }
    }

    if runs_n > 0 && runs_ok == 0 {
        return Err(if all_guardrail {
            ChunkError::AllRunsGuardrailBlocked
        } else {
            ChunkError::AllRunsFailed
        });
    }

    Ok(vote::vote_within_chunk(
        &runs,
        config.line_bucket,
        threshold,
    ))
}

/// Deep-dive every chunk. Bounded to `config.parallel` concurrent chunks;
/// returns as soon as either every chunk has an outcome or the cumulative
/// guardrail-abort gate trips (see module docs). A thin wrapper over
/// [`run_deepdive_with_progress`] with no progress sink, so every existing
/// caller (including the ~16 tests below) keeps working unchanged —
/// [`Stage4::run`] is the only caller that needs chunk-progress reporting.
pub async fn run_deepdive(
    client: Arc<dyn LlmClient>,
    input: Step4Input,
    config: &Step4Config,
) -> Result<DeepdiveOutput, StageError> {
    run_deepdive_with_progress(client, input, config, None).await
}

/// Same as [`run_deepdive`], plus a [`bc_pipeline_core::ScanEvent::ChunkProgress`]
/// emission every time one more chunk reaches an outcome — the only stage
/// with real intra-stage sub-progress to report (S3's decompose is a
/// single LLM call, not a per-chunk loop).
async fn run_deepdive_with_progress(
    client: Arc<dyn LlmClient>,
    input: Step4Input,
    config: &Step4Config,
    progress: Option<&bc_pipeline_core::ProgressSink>,
) -> Result<DeepdiveOutput, StageError> {
    if input.chunks.is_empty() {
        return Ok(DeepdiveOutput::default());
    }

    let mut chunks = input.chunks;
    chunks.sort_by_key(|c| c.risk_rank);
    let total = chunks.len();

    let repo_root: Arc<PathBuf> = Arc::new(Path::new(&input.ctx.repo_root).to_path_buf());
    let ctx = Arc::new(input.ctx);
    let config = Arc::new(config.clone());
    let semaphore = Arc::new(Semaphore::new(config.parallel.max(1)));
    let guardrail_gate = config.parallel.max(3);

    let mut set: JoinSet<(Chunk, Result<Vec<Finding>, ChunkError>)> = JoinSet::new();
    for chunk in &chunks {
        let chunk = chunk.clone();
        let sem = semaphore.clone();
        let client = client.clone();
        let ctx = ctx.clone();
        let repo_root = repo_root.clone();
        let config = config.clone();
        set.spawn(async move {
            let _permit = sem
                .acquire_owned()
                .await
                .expect("semaphore is never closed");
            // Asked here, holding the permit, rather than before the
            // spawn: see `Step4Config::budget_gate`.
            if let Some(gate) = &config.budget_gate {
                if gate.should_stop() {
                    return (chunk, Err(ChunkError::BudgetStopped(gate.stop_reason())));
                }
            }
            let result = deepdive_chunk(
                client.as_ref(),
                &chunk,
                ctx.as_ref(),
                repo_root.as_path(),
                config.as_ref(),
            )
            .await;
            (chunk, result)
        });
    }

    let mut results: BTreeMap<String, Vec<Finding>> = BTreeMap::new();
    let mut outcomes: BTreeMap<String, ChunkOutcome> = BTreeMap::new();
    let mut guardrail_hits = 0usize;
    let mut successes = 0usize;
    let mut completed = 0usize;
    let mut skipped = 0usize;
    let mut budget_reason: Option<String> = None;

    while let Some(joined) = set.join_next().await {
        let (chunk, result) = joined.expect("deepdive task panicked");
        completed += 1;
        bc_pipeline_core::emit(
            progress,
            bc_pipeline_core::ScanEvent::ChunkProgress {
                stage: Stage4::NAME,
                completed,
                total,
            },
        );
        match result {
            Ok(findings) => {
                successes += 1;
                results.insert(chunk.id.clone(), findings);
                outcomes.insert(chunk.id.clone(), ChunkOutcome::Completed);
            }
            Err(ChunkError::AllRunsGuardrailBlocked) => {
                guardrail_hits += 1;
                outcomes.insert(chunk.id.clone(), ChunkOutcome::Guardrail);
                if guardrail_hits >= guardrail_gate && successes == 0 {
                    set.abort_all();
                    return Err(StageError::new(
                        Stage4::NAME,
                        format!("{guardrail_hits} guardrail blocks with zero successful chunks — aborting run."),
                    ));
                }
            }
            Err(ChunkError::AllRunsFailed) => {
                outcomes.insert(chunk.id.clone(), ChunkOutcome::Error);
            }
            Err(ChunkError::BudgetStopped(reason)) => {
                skipped += 1;
                outcomes.insert(chunk.id.clone(), ChunkOutcome::Skipped);
                budget_reason.get_or_insert(reason);
            }
        }
    }

    let mut all_findings = Vec::new();
    for chunk in &chunks {
        if let Some(findings) = results.get(&chunk.id) {
            all_findings.extend(findings.iter().cloned());
        }
    }
    let findings = vote::collapse_across_chunks(all_findings, config.line_bucket);

    let budget_stop = budget_reason.map(|reason| {
        format!(
            "{reason} — {} of {total} deep-dive chunk(s) analysed, {skipped} skipped",
            total - skipped
        )
    });

    Ok(DeepdiveOutput {
        findings,
        outcomes,
        budget_stop,
    })
}

pub struct Stage4 {
    client: Arc<dyn LlmClient>,
    config: Step4Config,
    progress: Option<bc_pipeline_core::ProgressSink>,
}

impl Stage4 {
    pub fn new(client: Arc<dyn LlmClient>, config: Step4Config) -> Self {
        Stage4 {
            client,
            config,
            progress: None,
        }
    }

    /// Opts into per-chunk [`bc_pipeline_core::ScanEvent::ChunkProgress`]
    /// reporting — `None` (the [`Stage4::new`] default) matches every
    /// caller's behavior before this existed.
    pub fn with_progress(mut self, progress: Option<bc_pipeline_core::ProgressSink>) -> Self {
        self.progress = progress;
        self
    }
}

impl PipelineStage for Stage4 {
    type Input = Step4Input;
    type Output = DeepdiveOutput;
    const NAME: &'static str = "s4-deepdive";

    async fn run(&self, input: Step4Input) -> Result<StageOutcome<DeepdiveOutput>, StageError> {
        let output = run_deepdive_with_progress(
            self.client.clone(),
            input,
            &self.config,
            self.progress.as_ref(),
        )
        .await?;
        match output.budget_stop.clone() {
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
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;
    use bc_llm_client::{ChatRequest, ChatResponse, ContentBlock, LlmError, StopReason, Usage};
    use bc_model::ChunkSize;

    use super::*;

    fn chunk(id: &str, risk_rank: i64, specialist: Option<&str>) -> Chunk {
        Chunk {
            id: id.to_string(),
            size: ChunkSize::Small,
            risk_rank,
            files: Vec::new(),
            focus_entry_points: Vec::new(),
            hypothesis: String::new(),
            related_cves: Vec::new(),
            threat_id: None,
            languages: Vec::new(),
            specialist: specialist.map(String::from),
            path_funcs: Vec::new(),
            source_ref: String::new(),
            sink_ref: String::new(),
            sink_cwe: Vec::new(),
        }
    }

    fn finding_body(file: &str, line: i64, confidence: f64) -> String {
        serde_json::json!({"findings": [{
            "file": file, "line_start": line, "line_end": line,
            "vuln_class": "injection", "title": "t", "description": "d",
            "code_snippet": "x", "confidence": confidence,
        }]})
        .to_string()
    }

    fn empty_body() -> String {
        serde_json::json!({"findings": []}).to_string()
    }

    fn ctx_with_changed_file(file: &str, line: i64) -> ContextPackage {
        ContextPackage {
            diff_scope_active: true,
            changed_files: std::collections::BTreeMap::from([(
                file.to_string(),
                std::collections::BTreeSet::from([line]),
            )]),
            ..Default::default()
        }
    }

    // Boxed trait object (not a generic type param) so every test's
    // closure shares one compiled `chat` body — see
    // `feedback_coverage_tool_gotchas.md` on generic-fixture coverage
    // splitting.
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
            let user_text = request
                .messages
                .last()
                .map(|m| {
                    m.content
                        .iter()
                        .filter_map(|c| match c {
                            ContentBlock::Text(t) => Some(t.as_str()),
                            _ => None,
                        })
                        .collect::<String>()
                })
                .unwrap_or_default();
            let reply = (self.router)(&user_text)?;
            Ok(ChatResponse {
                content: vec![ContentBlock::Text(reply)],
                stop_reason: StopReason::EndTurn,
                usage: Usage::default(),
            })
        }
    }

    fn client_for(reply: String) -> Arc<dyn LlmClient> {
        Arc::new(RoutedClient::new(move |_| Ok(reply.clone())))
    }

    #[tokio::test]
    async fn routed_client_fixture_ignores_non_text_content_blocks() {
        // S4 only ever sends a single `Message::user_text(...)` (never a
        // tool result), so no real deepdive call path exercises a
        // non-`Text` content block — exercised directly here against the
        // fixture itself instead.
        let client = RoutedClient::new(|text| Ok(format!("echo:{text}")));
        let request = ChatRequest {
            model: "m".to_string(),
            system: None,
            messages: vec![bc_llm_client::Message {
                role: bc_llm_client::Role::User,
                content: vec![
                    ContentBlock::ToolResult {
                        tool_use_id: "1".to_string(),
                        content: "ignored".to_string(),
                        is_error: false,
                    },
                    ContentBlock::Text("hello".to_string()),
                ],
            }],
            tools: Vec::new(),
            max_tokens: 100,
            temperature: None,
            top_p: None,
            seed: None,
            thinking_budget: None,
            betas: Vec::new(),
            json_mode: false,
            timeout: None,
            stream: false,
        };
        let response = client.chat(&request).await.unwrap();
        assert_eq!(response.text(), "echo:hello");
    }

    /// A gate that allows exactly `allowance` units of work and then
    /// stays shut — the deterministic stand-in for a real
    /// `bc_orchestrator::SpendGate` whose counters happen to cross the
    /// cap part-way through a stage.
    #[derive(Debug)]
    struct AfterNGate {
        remaining: AtomicUsize,
    }

    impl AfterNGate {
        fn allowing(allowance: usize) -> bc_pipeline_core::BudgetGateRef {
            std::sync::Arc::new(AfterNGate {
                remaining: AtomicUsize::new(allowance),
            })
        }
    }

    impl bc_pipeline_core::BudgetGate for AfterNGate {
        fn should_stop(&self) -> bool {
            // Consulted exactly once per unit of work, so one allowance
            // per call; saturating so it never wraps once exhausted.
            self.remaining
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                    Some(n.saturating_sub(1))
                })
                .expect("the closure always returns Some")
                == 0
        }

        fn stop_reason(&self) -> String {
            "token budget of 3000000 reached (3012044 spent)".to_string()
        }
    }

    /// The 2026-09-06 Juice Shop shape in miniature: the cap is reached
    /// part-way through a 444-chunk deep-dive, and the stage must stop
    /// starting chunks rather than run every one of them and only notice
    /// at the boundary afterwards.
    #[tokio::test]
    async fn a_budget_gate_that_trips_part_way_stops_starting_new_chunks() {
        let client = client_for(finding_body("a.py", 10, 0.9));
        let mut cfg = Step4Config::new("m");
        // One chunk at a time, so "two allowed" means exactly the first
        // two chunks reach an LLM call.
        cfg.parallel = 1;
        cfg.budget_gate = Some(AfterNGate::allowing(2));
        let chunks = (0..5)
            .map(|i| chunk(&format!("c{i}"), i, None))
            .collect::<Vec<_>>();
        let out = run_deepdive(
            client,
            Step4Input {
                chunks,
                ctx: ContextPackage::default(),
            },
            &cfg,
        )
        .await
        .unwrap();

        let completed = out
            .outcomes
            .values()
            .filter(|o| **o == ChunkOutcome::Completed)
            .count();
        let skipped = out
            .outcomes
            .values()
            .filter(|o| **o == ChunkOutcome::Skipped)
            .count();
        assert_eq!(completed, 2);
        assert_eq!(skipped, 3);
        // Every chunk still has an outcome — a skipped chunk is reported,
        // never silently missing.
        assert_eq!(out.outcomes.len(), 5);
        let reason = out.budget_stop.unwrap();
        assert!(
            reason.starts_with("token budget of 3000000 reached"),
            "{reason}"
        );
        assert!(
            reason.ends_with("2 of 5 deep-dive chunk(s) analysed, 3 skipped"),
            "{reason}"
        );
    }

    /// A gate nothing computes for itself — it is shut only once a stage
    /// tells it to be, which is exactly the shape a quota failure needs
    /// (and the shape `bc_orchestrator::SpendGate` takes on a scan with
    /// no `--max-tokens`/`--max-scan-seconds` at all).
    #[derive(Debug, Default)]
    struct TrippableGate {
        reason: std::sync::Mutex<Option<String>>,
    }

    impl TrippableGate {
        fn untripped() -> bc_pipeline_core::BudgetGateRef {
            std::sync::Arc::new(TrippableGate::default())
        }
    }

    impl bc_pipeline_core::BudgetGate for TrippableGate {
        fn should_stop(&self) -> bool {
            self.reason.lock().unwrap().is_some()
        }

        fn stop_reason(&self) -> String {
            self.reason.lock().unwrap().clone().unwrap_or_default()
        }

        fn trip(&self, reason: String) {
            self.reason.lock().unwrap().get_or_insert(reason);
        }
    }

    fn quota_exhausted(_: &str) -> Result<String, LlmError> {
        Err(LlmError::QuotaExhausted {
            message: "You exceeded your current quota".to_string(),
        })
    }

    /// The 2026-09 CI failure at S4: an OpenAI account with no credits
    /// answers every call with a 429 `insufficient_quota`. The first
    /// chunk to hear it must stop the whole stage — not absorb it as one
    /// more failed run and let all 444 chunks discover it independently.
    #[tokio::test]
    async fn a_quota_exhausted_reply_trips_the_gate_and_skips_every_remaining_chunk() {
        let client: Arc<dyn LlmClient> = Arc::new(RoutedClient::new(quota_exhausted));
        let mut cfg = Step4Config::new("m");
        // One chunk at a time, so the first chunk's trip is visible to
        // every chunk behind it.
        cfg.parallel = 1;
        cfg.budget_gate = Some(TrippableGate::untripped());
        let chunks = (0..4)
            .map(|i| chunk(&format!("c{i}"), i, None))
            .collect::<Vec<_>>();
        let out = run_deepdive(
            client,
            Step4Input {
                chunks,
                ctx: ContextPackage::default(),
            },
            &cfg,
        )
        .await
        .unwrap();

        // Every chunk accounted for, and none of them as `Error`: nothing
        // went wrong with the code, the work simply was not bought.
        assert_eq!(out.outcomes.len(), 4);
        assert!(
            out.outcomes.values().all(|o| *o == ChunkOutcome::Skipped),
            "{:?}",
            out.outcomes
        );
        assert!(out.findings.is_empty());
        let reason = out.budget_stop.unwrap();
        assert!(
            reason.starts_with("provider quota exhausted — You exceeded your current quota"),
            "{reason}"
        );
        assert!(
            reason.ends_with("0 of 4 deep-dive chunk(s) analysed, 4 skipped"),
            "{reason}"
        );
    }

    /// Without a gate configured there is nothing to trip, but the stage
    /// must still stop this chunk rather than burn `runs` calls on an
    /// account that has already said no.
    #[tokio::test]
    async fn a_quota_exhausted_reply_without_a_gate_still_stops_the_chunk() {
        let client: Arc<dyn LlmClient> = Arc::new(RoutedClient::new(quota_exhausted));
        let mut cfg = Step4Config::new("m");
        cfg.parallel = 1;
        assert!(cfg.budget_gate.is_none());
        let out = run_deepdive(
            client,
            Step4Input {
                chunks: vec![chunk("c0", 0, None)],
                ctx: ContextPackage::default(),
            },
            &cfg,
        )
        .await
        .unwrap();
        assert_eq!(out.outcomes["c0"], ChunkOutcome::Skipped);
        assert!(out
            .budget_stop
            .unwrap()
            .starts_with("provider quota exhausted —"));
    }

    #[tokio::test]
    async fn a_budget_gate_that_never_trips_changes_nothing() {
        let client = client_for(finding_body("a.py", 10, 0.9));
        let mut cfg = Step4Config::new("m");
        cfg.budget_gate = Some(AfterNGate::allowing(usize::MAX));
        let out = run_deepdive(
            client,
            Step4Input {
                chunks: vec![chunk("c1", 1, None)],
                ctx: ContextPackage::default(),
            },
            &cfg,
        )
        .await
        .unwrap();
        assert_eq!(out.outcomes["c1"], ChunkOutcome::Completed);
        assert!(out.budget_stop.is_none());
        assert_eq!(out.findings.len(), 1);
    }

    #[tokio::test]
    async fn stage4_run_reports_a_budget_stop_as_degraded() {
        let client = client_for(finding_body("a.py", 10, 0.9));
        let mut cfg = Step4Config::new("m");
        cfg.budget_gate = Some(AfterNGate::allowing(0));
        let outcome = Stage4::new(client, cfg)
            .run(Step4Input {
                chunks: vec![chunk("c1", 1, None)],
                ctx: ContextPackage::default(),
            })
            .await
            .unwrap();
        assert!(outcome.is_degraded());
        assert!(outcome
            .reason()
            .unwrap()
            .contains("0 of 1 deep-dive chunk(s) analysed"));
        assert!(outcome.into_value().findings.is_empty());
    }

    #[tokio::test]
    async fn stage4_run_without_a_budget_stop_is_not_degraded() {
        let client = client_for(finding_body("a.py", 10, 0.9));
        let outcome = Stage4::new(client, Step4Config::new("m"))
            .run(Step4Input {
                chunks: vec![chunk("c1", 1, None)],
                ctx: ContextPackage::default(),
            })
            .await
            .unwrap();
        assert!(!outcome.is_degraded());
    }

    #[tokio::test]
    async fn empty_chunks_short_circuits() {
        let out = run_deepdive(
            client_for(empty_body()),
            Step4Input {
                chunks: Vec::new(),
                ctx: ContextPackage::default(),
            },
            &Step4Config::new("m"),
        )
        .await
        .unwrap();
        assert!(out.findings.is_empty());
        assert!(out.outcomes.is_empty());
    }

    #[tokio::test]
    async fn a_single_successful_chunk_produces_a_finding_and_a_completed_outcome() {
        let client = client_for(finding_body("a.py", 10, 0.9));
        let out = run_deepdive(
            client,
            Step4Input {
                chunks: vec![chunk("c1", 1, None)],
                ctx: ContextPackage::default(),
            },
            &Step4Config::new("m"),
        )
        .await
        .unwrap();
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.outcomes.get("c1"), Some(&ChunkOutcome::Completed));
    }

    #[tokio::test]
    async fn diff_scope_drops_a_finding_on_a_file_outside_the_chunk() {
        // The model reported a finding in "neighbor.py", which
        // `neighbor_context` spliced in as read-only, out-of-chunk
        // context — `chunk.files` only ever contained "a.py". With
        // diff-scope active this must be dropped, not round-tripped.
        let client = client_for(finding_body("neighbor.py", 10, 0.9));
        let mut c = chunk("c1", 1, None);
        c.files = vec!["a.py".to_string()];
        let out = run_deepdive(
            client,
            Step4Input {
                chunks: vec![c],
                ctx: ctx_with_changed_file("a.py", 10),
            },
            &Step4Config::new("m"),
        )
        .await
        .unwrap();
        assert!(out.findings.is_empty());
        assert_eq!(out.outcomes.get("c1"), Some(&ChunkOutcome::Completed));
    }

    #[tokio::test]
    async fn diff_scope_keeps_a_finding_on_a_file_inside_the_chunk() {
        let client = client_for(finding_body("a.py", 10, 0.9));
        let mut c = chunk("c1", 1, None);
        c.files = vec!["a.py".to_string()];
        let out = run_deepdive(
            client,
            Step4Input {
                chunks: vec![c],
                ctx: ctx_with_changed_file("a.py", 10),
            },
            &Step4Config::new("m"),
        )
        .await
        .unwrap();
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.outcomes.get("c1"), Some(&ChunkOutcome::Completed));
    }

    #[tokio::test]
    async fn diff_scope_active_with_an_empty_changed_set_still_applies_the_backstop() {
        // A rename-only PR reaching S4 (a chunk survived from a cached
        // S1/S3 checkpoint, say): the changed set is empty but scoping IS
        // in effect, so the out-of-chunk finding must still be dropped.
        // Keyed on the empty map, this backstop silently switched off.
        let client = client_for(finding_body("neighbor.py", 10, 0.9));
        let mut c = chunk("c1", 1, None);
        c.files = vec!["a.py".to_string()];
        let ctx = ContextPackage {
            diff_scope_active: true,
            ..Default::default()
        };
        assert!(ctx.changed_files.is_empty());
        let out = run_deepdive(
            client,
            Step4Input {
                chunks: vec![c],
                ctx,
            },
            &Step4Config::new("m"),
        )
        .await
        .unwrap();
        assert!(out.findings.is_empty());
    }

    #[tokio::test]
    async fn without_diff_scope_a_finding_outside_chunk_files_still_survives() {
        // No `changed_files` set: this is the pre-diff-scope status quo —
        // the new filter must be a strict no-op so a full-repo scan is
        // byte-for-byte unaffected.
        let client = client_for(finding_body("neighbor.py", 10, 0.9));
        let mut c = chunk("c1", 1, None);
        c.files = vec!["a.py".to_string()];
        let out = run_deepdive(
            client,
            Step4Input {
                chunks: vec![c],
                ctx: ContextPackage::default(),
            },
            &Step4Config::new("m"),
        )
        .await
        .unwrap();
        assert_eq!(out.findings.len(), 1);
    }

    #[tokio::test]
    async fn step4_runs_zero_still_makes_a_real_call_instead_of_scanning_nothing() {
        // End-to-end regression for effective_runs' `runs < 1` fix: a
        // misconfigured `step4.runs: 0` must still make (at least) one
        // real LLM call and surface its finding, not silently complete
        // the chunk having scanned zero times.
        let client = client_for(finding_body("a.py", 10, 0.9));
        let mut cfg = Step4Config::new("m");
        cfg.runs = 0;
        let out = run_deepdive(
            client,
            Step4Input {
                chunks: vec![chunk("c1", 1, None)],
                ctx: ContextPackage::default(),
            },
            &cfg,
        )
        .await
        .unwrap();
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.outcomes.get("c1"), Some(&ChunkOutcome::Completed));
    }

    #[tokio::test]
    async fn every_run_failing_for_a_non_guardrail_reason_marks_the_chunk_as_error() {
        let client: Arc<dyn LlmClient> = Arc::new(RoutedClient::new(|_| {
            Err(LlmError::ConnectionError {
                message: "down".to_string(),
            })
        }));
        let mut cfg = Step4Config::new("m");
        cfg.runs = 2;
        cfg.max_transient_retries = 0;
        let out = run_deepdive(
            client,
            Step4Input {
                chunks: vec![chunk("c1", 1, None)],
                ctx: ContextPackage::default(),
            },
            &cfg,
        )
        .await
        .unwrap();
        assert!(out.findings.is_empty());
        assert_eq!(out.outcomes.get("c1"), Some(&ChunkOutcome::Error));
    }

    #[tokio::test]
    async fn a_guardrail_blocked_chunk_among_a_successful_one_is_recorded_not_aborted() {
        let client: Arc<dyn LlmClient> = Arc::new(RoutedClient::new(|text| {
            if text.contains("CHUNK: blocked") {
                Err(LlmError::GuardrailBlocked {
                    message: "nope".to_string(),
                })
            } else {
                Ok(finding_body("a.py", 10, 0.9))
            }
        }));
        let mut cfg = Step4Config::new("m");
        cfg.parallel = 1;
        let out = run_deepdive(
            client,
            Step4Input {
                chunks: vec![chunk("blocked", 1, None), chunk("ok", 2, None)],
                ctx: ContextPackage::default(),
            },
            &cfg,
        )
        .await
        .unwrap();
        assert_eq!(out.outcomes.get("blocked"), Some(&ChunkOutcome::Guardrail));
        assert_eq!(out.outcomes.get("ok"), Some(&ChunkOutcome::Completed));
    }

    #[tokio::test]
    async fn guardrail_gate_aborts_when_every_chunk_is_blocked_with_zero_successes() {
        let client: Arc<dyn LlmClient> = Arc::new(RoutedClient::new(|_| {
            Err(LlmError::GuardrailBlocked {
                message: "nope".to_string(),
            })
        }));
        let mut cfg = Step4Config::new("m");
        cfg.parallel = 3;
        let chunks = (0..3).map(|i| chunk(&format!("c{i}"), i, None)).collect();
        let result = run_deepdive(
            client,
            Step4Input {
                chunks,
                ctx: ContextPackage::default(),
            },
            &cfg,
        )
        .await;
        let err = result.unwrap_err();
        assert!(err.to_string().contains("guardrail"));
    }

    #[tokio::test]
    async fn a_finding_below_the_vote_threshold_does_not_survive_but_the_chunk_still_completes() {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = calls.clone();
        let client: Arc<dyn LlmClient> = Arc::new(RoutedClient::new(move |_| {
            let n = calls_clone.fetch_add(1, Ordering::SeqCst);
            Ok(if n == 0 {
                finding_body("a.py", 10, 0.9)
            } else {
                empty_body()
            })
        }));
        let mut cfg = Step4Config::new("m");
        cfg.runs = 2;
        cfg.vote_threshold = 2;
        let out = run_deepdive(
            client,
            Step4Input {
                chunks: vec![chunk("c1", 1, None)],
                ctx: ContextPackage::default(),
            },
            &cfg,
        )
        .await
        .unwrap();
        assert!(out.findings.is_empty());
        assert_eq!(out.outcomes.get("c1"), Some(&ChunkOutcome::Completed));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_finding_agreed_on_by_every_run_survives_with_the_true_vote_count() {
        let client = client_for(finding_body("a.py", 10, 0.9));
        let mut cfg = Step4Config::new("m");
        cfg.runs = 3;
        cfg.vote_threshold = 3;
        let out = run_deepdive(
            client,
            Step4Input {
                chunks: vec![chunk("c1", 1, None)],
                ctx: ContextPackage::default(),
            },
            &cfg,
        )
        .await
        .unwrap();
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].votes, 3);
    }

    #[tokio::test]
    async fn a_specialist_chunk_ignores_runs_and_vote_threshold_and_calls_only_once() {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = calls.clone();
        let client: Arc<dyn LlmClient> = Arc::new(RoutedClient::new(move |_| {
            calls_clone.fetch_add(1, Ordering::SeqCst);
            Ok(finding_body("a.py", 10, 0.9))
        }));
        let mut cfg = Step4Config::new("m");
        cfg.runs = 5;
        cfg.vote_threshold = 5;
        cfg.specialist_runs = 1;
        let out = run_deepdive(
            client,
            Step4Input {
                chunks: vec![chunk("c1", 1, Some("crypto"))],
                ctx: ContextPackage::default(),
            },
            &cfg,
        )
        .await
        .unwrap();
        assert_eq!(out.findings.len(), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn cross_chunk_collapse_merges_the_same_bug_and_keeps_the_higher_confidence() {
        let client: Arc<dyn LlmClient> = Arc::new(RoutedClient::new(|text| {
            if text.contains("CHUNK: c1") {
                Ok(finding_body("a.py", 142, 0.6))
            } else {
                Ok(finding_body("a.py", 145, 0.9))
            }
        }));
        let out = run_deepdive(
            client,
            Step4Input {
                chunks: vec![chunk("c1", 1, None), chunk("c2", 2, None)],
                ctx: ContextPackage::default(),
            },
            &Step4Config::new("m"),
        )
        .await
        .unwrap();
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].confidence, 0.9);
    }

    #[tokio::test]
    async fn stage4_run_wraps_success_as_ok() {
        let stage = Stage4::new(
            client_for(finding_body("a.py", 10, 0.9)),
            Step4Config::new("m"),
        );
        let outcome = stage
            .run(Step4Input {
                chunks: vec![chunk("c1", 1, None)],
                ctx: ContextPackage::default(),
            })
            .await
            .unwrap();
        assert!(!outcome.is_degraded());
        assert_eq!(outcome.into_value().findings.len(), 1);
    }

    #[tokio::test]
    async fn stage4_run_propagates_the_guardrail_abort_as_err() {
        let client: Arc<dyn LlmClient> = Arc::new(RoutedClient::new(|_| {
            Err(LlmError::GuardrailBlocked {
                message: "nope".to_string(),
            })
        }));
        let mut cfg = Step4Config::new("m");
        cfg.parallel = 3;
        let chunks = (0..3).map(|i| chunk(&format!("c{i}"), i, None)).collect();
        let stage = Stage4::new(client, cfg);
        let result = stage
            .run(Step4Input {
                chunks,
                ctx: ContextPackage::default(),
            })
            .await;
        assert!(result.is_err());
    }

    #[test]
    fn effective_runs_clamps_a_too_high_threshold_down_to_the_run_count() {
        assert_eq!(effective_runs(3, 5, None), (3, 3));
    }

    #[test]
    fn effective_runs_clamps_a_sub_one_threshold_up_to_one() {
        assert_eq!(effective_runs(3, 0, None), (3, 1));
    }

    #[test]
    fn effective_runs_with_zero_runs_forces_one_run_and_one_vote() {
        // Regression: a `step4.runs: 0` misconfiguration must not
        // silently complete a chunk having made zero LLM calls —
        // matches Python's own `_effective_runs`'s `if runs < 1` branch.
        assert_eq!(effective_runs(0, 0, None), (1, 1));
        assert_eq!(effective_runs(0, 5, None), (1, 1));
    }

    #[test]
    fn effective_runs_leaves_an_already_reachable_threshold_untouched() {
        assert_eq!(effective_runs(5, 2, None), (5, 2));
    }

    #[test]
    fn effective_runs_collapses_multiple_runs_at_temperature_zero() {
        // Ported from `_effective_runs` (`s4_deepdive.py:166-217`): N
        // greedy samples of one prompt are N copies of one answer, so the
        // extra calls buy nothing but cost.
        assert_eq!(effective_runs(3, 2, Some(0.0)), (1, 1));
    }

    #[test]
    fn effective_runs_keeps_multiple_runs_at_a_nonzero_temperature() {
        assert_eq!(effective_runs(3, 2, Some(0.4)), (3, 2));
    }

    #[test]
    fn effective_runs_at_temperature_zero_with_a_single_run_is_untouched() {
        // The clamp only fires for `runs > 1`; a single greedy run is the
        // normal, fully-supported deterministic configuration.
        assert_eq!(effective_runs(1, 1, Some(0.0)), (1, 1));
    }

    #[test]
    fn step4_config_defaults_to_discover_taint_prompt_mode() {
        assert_eq!(Step4Config::new("m").taint_prompt_mode, "discover");
        assert_eq!(Step4Config::new("m").taint_runs, None);
    }

    #[tokio::test]
    async fn confirm_refute_taint_prompt_mode_is_threaded_through_from_step4_config() {
        // Only the confirm/refute prompt yields a finding — a chunk with a
        // static taint path (`c1`) gets it and produces one; a chunk with
        // no `path_funcs` (`c2`) still gets the open-ended prompt under
        // the same config and produces none, proving the switch is
        // per-chunk, not a blanket config-level override.
        let client: Arc<dyn LlmClient> = Arc::new(RoutedClient::new(|text| {
            if text.contains("TASK: confirm or refute") {
                Ok(finding_body("a.py", 1, 0.9))
            } else {
                Ok(empty_body())
            }
        }));
        let mut c1 = chunk("c1", 1, None);
        c1.path_funcs = vec!["a.py::hop".to_string()];
        c1.source_ref = "a.py::src".to_string();
        c1.sink_ref = "a.py:1".to_string();
        c1.files = vec!["a.py".to_string()];
        let c2 = chunk("c2", 2, None);
        let mut cfg = Step4Config::new("m");
        cfg.taint_prompt_mode = "confirm_refute".to_string();
        let out = run_deepdive(
            client,
            Step4Input {
                chunks: vec![c1, c2],
                ctx: ContextPackage::default(),
            },
            &cfg,
        )
        .await
        .unwrap();
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].file, "a.py");
    }

    #[tokio::test]
    async fn a_taint_chunk_uses_taint_runs_instead_of_the_global_runs_count() {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = calls.clone();
        let client: Arc<dyn LlmClient> = Arc::new(RoutedClient::new(move |_| {
            calls_clone.fetch_add(1, Ordering::SeqCst);
            Ok(empty_body())
        }));
        let mut c1 = chunk("c1", 1, None);
        c1.path_funcs = vec!["a.py::hop".to_string()];
        let mut cfg = Step4Config::new("m");
        cfg.runs = 3;
        cfg.vote_threshold = 3;
        cfg.taint_runs = Some(1);
        run_deepdive(
            client,
            Step4Input {
                chunks: vec![c1],
                ctx: ContextPackage::default(),
            },
            &cfg,
        )
        .await
        .unwrap();
        // The global `runs=3` would call three times; `taint_runs=1`
        // overrides it for this taint chunk specifically.
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_taint_chunk_with_no_taint_runs_set_falls_through_to_the_global_runs_count() {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = calls.clone();
        let client: Arc<dyn LlmClient> = Arc::new(RoutedClient::new(move |_| {
            calls_clone.fetch_add(1, Ordering::SeqCst);
            Ok(empty_body())
        }));
        let mut c1 = chunk("c1", 1, None);
        c1.path_funcs = vec!["a.py::hop".to_string()];
        let mut cfg = Step4Config::new("m");
        cfg.runs = 3;
        cfg.vote_threshold = 3;
        // cfg.taint_runs stays None — matches `default.yaml`'s own unset value.
        run_deepdive(
            client,
            Step4Input {
                chunks: vec![c1],
                ctx: ContextPackage::default(),
            },
            &cfg,
        )
        .await
        .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    // ── progress reporting ───────────────────────────────────────────────

    #[tokio::test]
    async fn stage4_run_with_no_progress_sink_emits_nothing() {
        let stage = Stage4::new(
            client_for(finding_body("a.py", 10, 0.9)),
            Step4Config::new("m"),
        );
        stage
            .run(Step4Input {
                chunks: vec![chunk("c1", 1, None)],
                ctx: ContextPackage::default(),
            })
            .await
            .unwrap();
        // No sink wired — nothing to assert beyond "didn't panic"; the real
        // assertion is `with_progress` below, which proves the sink path
        // itself works when present.
    }

    #[tokio::test]
    async fn stage4_run_with_progress_emits_one_chunk_progress_event_per_completed_chunk() {
        let (tx, rx) = std::sync::mpsc::channel();
        let stage = Stage4::new(
            client_for(finding_body("a.py", 10, 0.9)),
            Step4Config::new("m"),
        )
        .with_progress(Some(tx));
        stage
            .run(Step4Input {
                chunks: vec![chunk("c1", 1, None), chunk("c2", 2, None)],
                ctx: ContextPackage::default(),
            })
            .await
            .unwrap();

        let mut events: Vec<_> = rx.try_iter().collect();
        assert_eq!(events.len(), 2);
        // Completion order across concurrently-spawned chunks isn't
        // deterministic — sort by the wire-formatted event before
        // asserting the exact (completed, total) pairs seen, so no
        // exhaustive-match/`unreachable!()` arm is needed just to extract
        // a sort key from an enum with only one variant here.
        events.sort_by_key(|e| format!("{e:?}"));
        assert_eq!(
            events[0],
            bc_pipeline_core::ScanEvent::ChunkProgress {
                stage: "s4-deepdive",
                completed: 1,
                total: 2,
            }
        );
        assert_eq!(
            events[1],
            bc_pipeline_core::ScanEvent::ChunkProgress {
                stage: "s4-deepdive",
                completed: 2,
                total: 2,
            }
        );
    }

    #[tokio::test]
    async fn empty_chunks_emits_no_progress_events() {
        let (tx, rx) = std::sync::mpsc::channel();
        let stage =
            Stage4::new(client_for(empty_body()), Step4Config::new("m")).with_progress(Some(tx));
        stage
            .run(Step4Input {
                chunks: Vec::new(),
                ctx: ContextPackage::default(),
            })
            .await
            .unwrap();
        assert_eq!(rx.try_iter().count(), 0);
    }
}
