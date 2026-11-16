use std::path::Path;

use appsec_checkpoint::CheckpointStore;
use appsec_llm_client::{LlmClient, ToolExecutor};
use appsec_model::{RankedFinding, Severity};
use appsec_stage_s10::{
    checkpoint_done, remediate_one_checkpointed, PolicyContext, RemediationOutcome, Step10Config,
};

use crate::keys::Key;
use crate::render::{parse_selection, render_frame, render_rows, Row};
use crate::terminal::Terminal;

pub struct PickerFinding {
    pub finding_index: i64,
    pub finding: RankedFinding,
}

pub struct RemediationContext<'a> {
    pub client: &'a dyn LlmClient,
    pub tools: &'a dyn ToolExecutor,
    pub repo: &'a Path,
    pub config: &'a Step10Config,
    pub policy: Option<&'a PolicyContext>,
    pub checkpoint: Option<&'a dyn CheckpointStore>,
    pub run_id: &'a str,
    pub validate: Option<ValidateContext<'a>>,
}

pub struct ValidateContext<'a> {
    pub step11: &'a appsec_stage_s11::Step11Config,
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

pub async fn run_interactive(
    ctx: &RemediationContext<'_>,
    findings: &[PickerFinding],
    term: &mut dyn Terminal,
) -> (
    Vec<RemediationOutcome>,
    Vec<Option<appsec_validation_scoring::ValidationScore>>,
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

async fn validate_row(
    ctx: &RemediationContext<'_>,
    finding: &RankedFinding,
    outcome: &mut RemediationOutcome,
    baseline: Option<&appsec_stage_s10::Baseline>,
    failures: &mut usize,
) -> Option<appsec_validation_scoring::ValidationScore> {
    let validate = ctx.validate.as_ref()?;
    let RemediationOutcome::Processed(record) = outcome else {
        return None;
    };
    record.diff.as_ref()?;
    match appsec_stage_s11::validate_finding(
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

fn revert_if_validation_failed(
    ctx: &RemediationContext<'_>,
    record: &mut appsec_stage_s10::RemediationRecord,
    baseline: Option<&appsec_stage_s10::Baseline>,
    score: &appsec_validation_scoring::ValidationScore,
) {
    use appsec_validation_scoring::FixVerdict;
    if ctx.config.keep_unverified
        || !matches!(
            score.fix_status,
            FixVerdict::NotFixed | FixVerdict::Unverifiable
        )
    {
        return;
    }
    let report = appsec_stage_s10::revert_after_failed_validation(
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
    Option<appsec_validation_scoring::ValidationScore>,
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
    Vec<Option<appsec_validation_scoring::ValidationScore>>,
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
    Vec<Option<appsec_validation_scoring::ValidationScore>>,
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
