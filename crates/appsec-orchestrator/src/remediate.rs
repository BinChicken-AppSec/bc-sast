use super::*;
pub struct RemediateConfig {
    pub step10: appsec_stage_s10::Step10Config,
    pub top: Option<appsec_stage_s10::TopSpec>,
    pub top_default: Option<appsec_stage_s10::TopSpec>,
    pub force: bool,
    pub resume: bool,
    pub isolated: bool,
}

#[derive(Debug, Default)]
pub struct RemediateOutcome {
    pub refused: Option<String>,
    pub outcomes: Vec<appsec_stage_s10::RemediationOutcome>,
    pub validations: Vec<Option<appsec_validation_scoring::ValidationScore>>,
    pub validation_failures: usize,
}

pub fn redact_remediate_outcome(mut outcome: RemediateOutcome) -> RemediateOutcome {
    for o in &mut outcome.outcomes {
        match o {
            appsec_stage_s10::RemediationOutcome::Processed(record) => {
                **record = redact_remediation_record(record);
            }
            appsec_stage_s10::RemediationOutcome::Failed { error, .. } => {
                *error = appsec_redact::redact(error);
            }
        }
    }
    for score in outcome.validations.iter_mut().flatten() {
        redact_validation_score(score);
    }
    outcome
}

pub(super) fn redact_remediation_record(
    record: &appsec_stage_s10::RemediationRecord,
) -> appsec_stage_s10::RemediationRecord {
    let json = serde_json::to_value(record).expect("RemediationRecord always serializes");
    let mut redacted: appsec_stage_s10::RemediationRecord =
        serde_json::from_value(appsec_redact::redact_tree(&json))
            .expect("redact_tree preserves JSON shape, so RemediationRecord deserializes back");
    redacted.diff = record.diff.as_deref().map(appsec_redact::redact_diff);
    redacted
}

pub(super) fn redact_validation_score(score: &mut appsec_validation_scoring::ValidationScore) {
    score.justification = appsec_redact::redact(&score.justification);
    for gate in &mut score.gate_results {
        gate.summary = appsec_redact::redact(&gate.summary);
        gate.details = appsec_redact::redact(&gate.details);
        for evidence in &mut gate.evidence {
            evidence.snippet = appsec_redact::redact(&evidence.snippet);
        }
    }
}

pub fn severity_str(s: appsec_model::Severity) -> &'static str {
    match s {
        appsec_model::Severity::Critical => "CRITICAL",
        appsec_model::Severity::High => "HIGH",
        appsec_model::Severity::Medium => "MEDIUM",
        appsec_model::Severity::Low => "LOW",
        appsec_model::Severity::Info => "INFO",
    }
}

pub fn stale_refusal(report: &FinalReport, repo: &Path, force: bool) -> Option<String> {
    let (Some(report_sha), Some(current_sha)) = (&report.git_sha, head_sha(repo)) else {
        return None;
    };
    if report_sha == &current_sha || force {
        return None;
    }
    Some(format!(
        "HEAD moved since scan ({} -> {}); pass --force to override",
        &report_sha[..report_sha.len().min(8)],
        &current_sha[..current_sha.len().min(8)],
    ))
}

pub(super) fn revert_if_validation_failed(
    repo: &Path,
    record: &mut appsec_stage_s10::RemediationRecord,
    baseline: Option<&appsec_stage_s10::Baseline>,
    protected: &BTreeMap<String, i64>,
    score: &appsec_validation_scoring::ValidationScore,
    step10: &appsec_stage_s10::Step10Config,
) {
    use appsec_validation_scoring::FixVerdict;
    if step10.keep_unverified
        || !matches!(
            score.fix_status,
            FixVerdict::NotFixed | FixVerdict::Unverifiable
        )
    {
        return;
    }
    let report = appsec_stage_s10::revert_after_failed_validation(
        repo,
        record,
        baseline,
        protected,
        score.fix_status.as_str(),
    );
    for warning in &report.warnings {
        eprintln!("  [s11] WARNING: {warning}");
    }
    if let Some(line) = &report.restored {
        eprintln!("  [s11] {line}");
    }
}

pub struct ValidateConfig<'a> {
    pub step11: &'a appsec_stage_s11::Step11Config,
    pub tools: &'a dyn ToolExecutor,
}

#[allow(clippy::too_many_arguments)]
pub async fn remediate(
    llm: Arc<dyn LlmClient>,
    tools: Arc<dyn ToolExecutor>,
    repo: &Path,
    report: &FinalReport,
    config: &RemediateConfig,
    policy: Option<&appsec_stage_s10::PolicyContext>,
    checkpoint: Option<Arc<dyn appsec_checkpoint::CheckpointStore>>,
    validate: Option<ValidateConfig<'_>>,
) -> RemediateOutcome {
    remediate_observed(
        llm,
        tools,
        repo,
        report,
        config,
        policy,
        checkpoint,
        validate,
        &RemediateTelemetry::default(),
    )
    .await
}

pub const S10_STAGE: &str = "s10-remediate";

pub const S11_STAGE: &str = "s11-validate";

#[derive(Debug, Clone, Default)]
pub struct RemediateTelemetry {
    pub progress: Option<appsec_pipeline_core::ProgressSink>,
    pub pricing: pricing::PricingConfig,
    pub cancel: Option<appsec_pipeline_core::CancelTokenRef>,
}

pub fn remediation_canceled(progress: Option<&appsec_pipeline_core::ProgressSink>, reason: &str) {
    cancellation::skip_stages(
        progress,
        &mut telemetry::StageTimings::new(),
        &[S10_STAGE, S11_STAGE],
        reason,
    );
}

pub fn remediation_not_requested(progress: Option<&appsec_pipeline_core::ProgressSink>) {
    let mut timings = telemetry::StageTimings::new();
    for stage in [S10_STAGE, S11_STAGE] {
        telemetry::record_unstarted(
            progress,
            &mut timings,
            stage,
            StageStatus::Disabled,
            Some("remediation not requested".to_string()),
        );
    }
}

pub(super) fn emit_usage(
    progress: Option<&appsec_pipeline_core::ProgressSink>,
    stage: &'static str,
    usage: PhaseUsage,
) {
    appsec_pipeline_core::emit(
        progress,
        appsec_pipeline_core::ScanEvent::UsageUpdate {
            stage,
            usage: stage_usage(usage),
        },
    );
}

#[allow(clippy::too_many_arguments)]
pub async fn remediate_observed(
    llm: Arc<dyn LlmClient>,
    tools: Arc<dyn ToolExecutor>,
    repo: &Path,
    report: &FinalReport,
    config: &RemediateConfig,
    policy: Option<&appsec_stage_s10::PolicyContext>,
    checkpoint: Option<Arc<dyn appsec_checkpoint::CheckpointStore>>,
    validate: Option<ValidateConfig<'_>>,
    telemetry: &RemediateTelemetry,
) -> RemediateOutcome {
    let progress = telemetry.progress.as_ref();
    let mut timings = telemetry::StageTimings::new();
    let disable_both = |timings: &mut telemetry::StageTimings, reason: &str| {
        telemetry::record_unstarted(
            progress,
            timings,
            S10_STAGE,
            StageStatus::Disabled,
            Some(appsec_redact::redact(reason)),
        );
        telemetry::record_unstarted(
            progress,
            timings,
            S11_STAGE,
            StageStatus::Disabled,
            Some("remediation did not run".to_string()),
        );
    };
    if let Some(reason) = appsec_pipeline_core::canceled(telemetry.cancel.as_ref()) {
        remediation_canceled(progress, &reason);
        return RemediateOutcome {
            refused: Some(reason),
            ..RemediateOutcome::default()
        };
    }
    if let Some(reason) = stale_refusal(report, repo, config.force) {
        disable_both(&mut timings, &reason);
        return RemediateOutcome {
            refused: Some(reason),
            outcomes: Vec::new(),
            validations: Vec::new(),
            validation_failures: 0,
        };
    }

    let top = appsec_stage_s10::resolve_top(config.top, config.top_default);
    let positions = appsec_stage_s10::select_top_by_cvss(
        report.findings.len(),
        top,
        |i| report.findings[i].finding.cvss_score,
        |i| severity_str(report.findings[i].severity),
    );
    let selected: Vec<(i64, appsec_model::RankedFinding)> = positions
        .into_iter()
        .map(|pos| ((pos + 1) as i64, report.findings[pos].clone()))
        .collect();
    let nothing_selected = selected.is_empty();
    if nothing_selected {
        disable_both(&mut timings, "no findings selected for remediation");
    }

    if !selected.is_empty() {
        if config.isolated {
            eprintln!(
                "  [s10] remediating in an isolated worktree at {}; your \
                 checkout is not modified",
                repo.display()
            );
        } else {
            let mode = if config.step10.dry_run {
                "DRY RUN — will edit and then roll back every change in"
            } else {
                "FIX MODE — about to EDIT source files in"
            };
            eprintln!(
                "  [s10] ⚠ {mode} {}; rerun with --stop-after s9 to scan without \
                 modifying the target",
                repo.display()
            );
        }
    }

    let run_id = appsec_checkpoint::run_id_for(repo);
    if let Some(cp) = &checkpoint {
        cp.register_run(
            &run_id,
            &report.repo_root,
            report.repo_name.as_deref(),
            report
                .app_profile
                .as_ref()
                .map(|ap| ap.application_id.as_str()),
        );
        if !config.resume {
            cp.reset_run(&run_id);
        }
    }
    let tracker = Arc::new(UsageTrackingClient::new(llm, &telemetry.pricing));
    let llm = cancel_aware_client(tracker.clone(), telemetry.cancel.clone());
    let mut step10 = config.step10.clone();
    step10.cancel = telemetry.cancel.clone();
    let s10_run = (!nothing_selected).then(|| StageRun::start(progress, S10_STAGE));
    let appsec_stage_s10::RemediationRun {
        mut outcomes,
        baselines,
    } = appsec_stage_s10::run_remediation(
        llm.as_ref(),
        tools.as_ref(),
        repo,
        &selected,
        &step10,
        policy,
        checkpoint.as_deref(),
        &run_id,
        config.resume,
    )
    .await;
    if let Some(run) = s10_run {
        emit_usage(progress, S10_STAGE, tracker.take());
        let counts = telemetry::remediation_counts(&outcomes);
        let failed = outcomes
            .iter()
            .any(|o| matches!(o, appsec_stage_s10::RemediationOutcome::Failed { .. }));
        run.finish(
            progress,
            &mut timings,
            StageStatus::from_degraded(failed),
            counts,
            None,
        );
    }

    let s11_cancel = appsec_pipeline_core::canceled(telemetry.cancel.as_ref())
        .filter(|_| validate.is_some() && !nothing_selected);
    let validate = validate.filter(|_| s11_cancel.is_none());
    if let Some(reason) = &s11_cancel {
        cancellation::skip_stages(progress, &mut timings, &[S11_STAGE], reason);
    }
    let s11_run = match (&validate, nothing_selected || s11_cancel.is_some()) {
        (Some(_), false) => Some(StageRun::start(progress, S11_STAGE)),
        (None, false) => {
            telemetry::record_unstarted(
                progress,
                &mut timings,
                S11_STAGE,
                StageStatus::Disabled,
                Some("validation disabled".to_string()),
            );
            None
        }
        (_, true) => None,
    };
    let mut validations = Vec::new();
    let mut validation_failures = 0usize;
    if let Some(v) = validate {
        validations = vec![None; outcomes.len()];
        let validatable: Vec<(usize, appsec_stage_s10::RemediationRecord)> = outcomes
            .iter()
            .enumerate()
            .filter_map(|(i, outcome)| {
                let appsec_stage_s10::RemediationOutcome::Processed(record) = outcome else {
                    return None;
                };
                record.diff.is_some().then(|| (i, record.as_ref().clone()))
            })
            .collect();
        let chosen_positions: BTreeSet<usize> = appsec_stage_s10::select_top_by_cvss(
            validatable.len(),
            v.step11.max_findings,
            |pos| selected[validatable[pos].0].1.finding.cvss_score,
            |pos| severity_str(selected[validatable[pos].0].1.severity),
        )
        .into_iter()
        .collect();

        for (pos, (i, record)) in validatable.iter().enumerate() {
            let canceled = appsec_pipeline_core::canceled(telemetry.cancel.as_ref()).is_some();
            if canceled || !chosen_positions.contains(&pos) {
                continue;
            }
            let i = *i;
            let finding = &selected[i].1;
            match appsec_stage_s11::validate_finding_checkpointed(
                llm.as_ref(),
                v.tools,
                repo,
                finding,
                record,
                v.step11,
                checkpoint.as_deref(),
                &run_id,
                config.resume,
            )
            .await
            {
                Ok(score) => {
                    let protected =
                        appsec_stage_s10::files_kept_by_later_findings(&outcomes, &baselines, i);
                    let mut updated = record.clone();
                    revert_if_validation_failed(
                        repo,
                        &mut updated,
                        baselines[i].as_ref(),
                        &protected,
                        &score,
                        &config.step10,
                    );
                    outcomes[i] =
                        appsec_stage_s10::RemediationOutcome::Processed(Box::new(updated));
                    validations[i] = Some(score);
                }
                Err(e) => {
                    eprintln!(
                        "  [s11] FAILED: validation error for finding {}: {e}",
                        record.finding_id
                    );
                    validation_failures += 1;
                }
            }
        }
    }
    if let Some(run) = s11_run {
        emit_usage(progress, S11_STAGE, tracker.take());
        run.finish(
            progress,
            &mut timings,
            StageStatus::from_degraded(validation_failures > 0),
            telemetry::validation_counts(&validations, validation_failures),
            (validation_failures > 0)
                .then(|| format!("{validation_failures} validation session(s) errored")),
        );
    }

    redact_remediate_outcome(RemediateOutcome {
        refused: None,
        outcomes,
        validations,
        validation_failures,
    })
}
