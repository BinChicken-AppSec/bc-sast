//! The interactive remediation loop, ported from
//! `remediation_agent/interactive/loop.py`'s `run_interactive`/
//! `_loop_tty`/`_loop_prompt`. Both the arrow-key UI and the numbered-
//! prompt fallback funnel every selected finding through the SAME
//! per-finding checkpointed remediation ([`bc_stage_s10::
//! remediate_one_checkpointed`]) — matching Python's own "one runner,
//! two input modes" structure.

use std::path::Path;

use bc_checkpoint::CheckpointStore;
use bc_llm_client::{LlmClient, ToolExecutor};
use bc_model::{RankedFinding, Severity};
use bc_stage_s10::{
    checkpoint_done, remediate_one_checkpointed, PolicyContext, RemediationOutcome, Step10Config,
};

use crate::keys::Key;
use crate::render::{parse_selection, render_frame, render_rows, Row};
use crate::terminal::Terminal;

/// One finding as offered to the picker, alongside its 1-based
/// `finding_index` — matching `bc_stage_s10::run_remediation`'s own
/// `(i64, RankedFinding)` pairing (the same shape `bc_orchestrator`
/// already produces via CVSS-based selection, reused here unmodified).
pub struct PickerFinding {
    pub finding_index: i64,
    pub finding: RankedFinding,
}

/// Everything the picker needs to actually remediate a selected finding,
/// bundled so the loop functions below don't each take a dozen separate
/// parameters.
pub struct RemediationContext<'a> {
    pub client: &'a dyn LlmClient,
    pub tools: &'a dyn ToolExecutor,
    pub repo: &'a Path,
    pub config: &'a Step10Config,
    pub policy: Option<&'a PolicyContext>,
    pub checkpoint: Option<&'a dyn CheckpointStore>,
    pub run_id: &'a str,
    /// `Some(_)` to run Phase 3's S11 validation panel right after each
    /// successfully-remediated (`Processed`, real diff) finding — mirrors
    /// `bc_orchestrator::remediate`'s own `ValidateConfig`, extended to
    /// this picker-driven path. `None` (the common case today, since
    /// `bc-cli` only wires this on request) means S11 never runs here
    /// and the second element of [`run_interactive`]'s return stays
    /// empty, matching `RemediateOutcome::validations`'s own "empty means
    /// disabled" convention.
    pub validate: Option<ValidateContext<'a>>,
}

/// `RemediationContext::validate`'s payload: S11's own config plus a
/// READ-ONLY tool executor, deliberately separate from
/// `RemediationContext::tools` (write-capable, S10's own) — matching
/// `bc_stage_s11::validate_finding`'s read-only contract.
pub struct ValidateContext<'a> {
    pub step11: &'a bc_stage_s11::Step11Config,
    pub tools: &'a dyn ToolExecutor,
}

fn severity_label(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "CRITICAL",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
        Severity::Info => "INFO",
    }
}

fn build_rows(ctx: &RemediationContext<'_>, findings: &[PickerFinding]) -> Vec<Row> {
    findings
        .iter()
        .map(|pf| Row {
            finding_index: pf.finding_index,
            severity: severity_label(pf.finding.severity).to_string(),
            title: pf.finding.finding.title.clone(),
            file: pf.finding.finding.file.clone(),
            done: checkpoint_done(
                ctx.checkpoint,
                ctx.run_id,
                ctx.config,
                pf.finding_index,
                &pf.finding,
            ),
        })
        .collect()
}

/// Runs the interactive picker over `findings` until the user quits (or
/// runs out of input on the prompt fallback). Uses the arrow-key UI on
/// a real terminal, else the numbered-prompt fallback — mirroring
/// Python's `interactive_tty` check. Returns every finding actually
/// remediated this session, in the order picked, alongside a SECOND
/// vec of S11 scores aligned 1:1 with the first (`RemediateOutcome
/// ::validations`'s own convention) — empty when `ctx.validate` is
/// `None`, one entry per outcome otherwise — and a THIRD count of how
/// many validation attempts genuinely failed (an `LlmError`, not "no
/// diff to validate"), matching `RemediateOutcome::validation_failures`.
/// An empty `findings` list is a no-op, matching `run_remediation`'s own
/// precedent.
///
/// Every selection — TTY Enter or a prompt-mode pick — always attempts
/// the agent (`resume: false` internally), even for a finding already
/// marked done: the ✅ is informational (from [`checkpoint_done`]), not
/// a skip gate, exactly matching Python's own behavior (`_remediate_one`
/// is unconditional on `finding.done`).
pub async fn run_interactive(
    ctx: &RemediationContext<'_>,
    findings: &[PickerFinding],
    term: &mut dyn Terminal,
) -> (
    Vec<RemediationOutcome>,
    Vec<Option<bc_validation_scoring::ValidationScore>>,
    usize,
) {
    if findings.is_empty() {
        return (Vec::new(), Vec::new(), 0);
    }
    let mut rows = build_rows(ctx, findings);
    if term.is_tty() {
        loop_tty(ctx, findings, term, &mut rows).await
    } else {
        loop_prompt(ctx, findings, term, &mut rows).await
    }
}

/// Runs S11 validation for one just-remediated finding when `ctx.validate`
/// is configured — `None` for a disabled config, a `Failed` outcome, or a
/// `Processed` record with no actual diff. A genuine `LlmError` is also
/// `None` here (a transient validation failure never takes down the
/// picker session, matching `bc_orchestrator::remediate`'s own
/// validation-skip rules) but is surfaced loudly to stderr and counted
/// in `*failures`, rather than being silently indistinguishable from
/// "wasn't selected for validation" — matches Python's own
/// `FAILED: {id} — {reason}` line (`validation/cli/_run.py::_run_reports`).
async fn validate_row(
    ctx: &RemediationContext<'_>,
    finding: &RankedFinding,
    outcome: &mut RemediationOutcome,
    baseline: Option<&bc_stage_s10::Baseline>,
    failures: &mut usize,
) -> Option<bc_validation_scoring::ValidationScore> {
    let validate = ctx.validate.as_ref()?;
    let RemediationOutcome::Processed(record) = outcome else {
        return None;
    };
    record.diff.as_ref()?;
    match bc_stage_s11::validate_finding(
        ctx.client,
        validate.tools,
        ctx.repo,
        finding,
        record,
        validate.step11,
    )
    .await
    {
        Ok(score) => {
            revert_if_validation_failed(ctx, record, baseline, &score);
            Some(score)
        }
        Err(e) => {
            eprintln!(
                "  [s11] FAILED: validation error for finding {}: {e}",
                record.finding_id
            );
            *failures += 1;
            None
        }
    }
}

/// Rolls a just-remediated finding back when S11 graded it `Not Fixed` or
/// `UNVERIFIABLE` — the picker's half of the shared
/// `bc_stage_s10::revert_after_failed_validation`, so a fix picked by hand
/// is held to exactly the same standard as one picked by `--top`.
///
/// `baseline` is this finding's own pre-remediation bytes, carried out of
/// `remediate_one_checkpointed`; with it the rollback is byte-exact and
/// needs no `git`, which is the only way it does anything at all against
/// a target that is not a checkout.
///
/// The "protected files" map the batch path has to build is empty here,
/// and that is a property of the picker rather than an omission: S11 runs
/// immediately after each individual pick, so at this instant no LATER
/// finding has been remediated at all and there is no kept fix to
/// preserve. An EARLIER pick's kept fix is safe by construction — this
/// baseline was captured after it, so restoring to it keeps that fix.
fn revert_if_validation_failed(
    ctx: &RemediationContext<'_>,
    record: &mut bc_stage_s10::RemediationRecord,
    baseline: Option<&bc_stage_s10::Baseline>,
    score: &bc_validation_scoring::ValidationScore,
) {
    use bc_validation_scoring::FixVerdict;
    if ctx.config.keep_unverified
        || !matches!(
            score.fix_status,
            FixVerdict::NotFixed | FixVerdict::Unverifiable
        )
    {
        return;
    }
    let report = bc_stage_s10::revert_after_failed_validation(
        ctx.repo,
        record,
        baseline,
        &std::collections::BTreeMap::new(),
        score.fix_status.as_str(),
    );
    for warning in &report.warnings {
        eprintln!("  [s11] WARNING: {warning}");
    }
    if let Some(line) = &report.restored {
        eprintln!("  [s11] {line}");
    }
}

async fn remediate_row(
    ctx: &RemediationContext<'_>,
    findings: &[PickerFinding],
    rows: &mut [Row],
    pos: usize,
    failures: &mut usize,
) -> (
    RemediationOutcome,
    Option<bc_validation_scoring::ValidationScore>,
) {
    let pf = &findings[pos];
    let (mut outcome, baseline) = remediate_one_checkpointed(
        ctx.client,
        ctx.tools,
        ctx.repo,
        pf.finding_index,
        &pf.finding,
        ctx.config,
        ctx.policy,
        ctx.checkpoint,
        ctx.run_id,
        false,
    )
    .await;
    if matches!(outcome, RemediationOutcome::Processed(_)) {
        rows[pos].done = true;
    }
    let validation =
        validate_row(ctx, &pf.finding, &mut outcome, baseline.as_ref(), failures).await;
    (outcome, validation)
}

async fn loop_tty(
    ctx: &RemediationContext<'_>,
    findings: &[PickerFinding],
    term: &mut dyn Terminal,
    rows: &mut [Row],
) -> (
    Vec<RemediationOutcome>,
    Vec<Option<bc_validation_scoring::ValidationScore>>,
    usize,
) {
    let mut cursor = 0usize;
    let mut outcomes = Vec::new();
    let mut validations = Vec::new();
    let mut failures = 0usize;
    loop {
        let frame = render_frame(rows, cursor);
        let _ = term.draw(&frame);
        let key = match term.read_key() {
            Ok(k) => k,
            // Lost the raw TTY mid-session — degrade to the prompt path,
            // matching Python's `except RuntimeError` fallback.
            Err(_) => {
                let (o, v, f) = loop_prompt(ctx, findings, term, rows).await;
                outcomes.extend(o);
                validations.extend(v);
                failures += f;
                return (outcomes, validations, failures);
            }
        };
        match key {
            Key::Quit => return (outcomes, validations, failures),
            Key::Up => cursor = (cursor + rows.len() - 1) % rows.len(),
            Key::Down => cursor = (cursor + 1) % rows.len(),
            Key::Enter => {
                let (outcome, validation) =
                    remediate_row(ctx, findings, rows, cursor, &mut failures).await;
                outcomes.push(outcome);
                if ctx.validate.is_some() {
                    validations.push(validation);
                }
            }
            Key::Other => {}
        }
    }
}

async fn loop_prompt(
    ctx: &RemediationContext<'_>,
    findings: &[PickerFinding],
    term: &mut dyn Terminal,
    rows: &mut [Row],
) -> (
    Vec<RemediationOutcome>,
    Vec<Option<bc_validation_scoring::ValidationScore>>,
    usize,
) {
    let mut outcomes = Vec::new();
    let mut validations = Vec::new();
    let mut failures = 0usize;
    loop {
        for row in render_rows(rows, None) {
            term.write_line(&row);
        }
        let Some(raw) = term.read_line("  Select issues (e.g. 1,3-5 | all | pending | q): ") else {
            return (outcomes, validations, failures);
        };
        let Some(picks) = parse_selection(&raw, rows) else {
            return (outcomes, validations, failures);
        };
        for pos in picks {
            let (outcome, validation) =
                remediate_row(ctx, findings, rows, pos, &mut failures).await;
            outcomes.push(outcome);
            if ctx.validate.is_some() {
                validations.push(validation);
            }
        }
    }
}

#[cfg(test)]
mod tests;
