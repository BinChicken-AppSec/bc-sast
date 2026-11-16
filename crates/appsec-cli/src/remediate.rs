use super::*;
#[allow(clippy::too_many_arguments)]
pub async fn remediate_interactively(
    llm: Arc<dyn LlmClient>,
    tools: Arc<dyn ToolExecutor>,
    repo: &Path,
    report: &appsec_model::FinalReport,
    config: &appsec_orchestrator::RemediateConfig,
    policy: Option<&appsec_stage_s10::PolicyContext>,
    checkpoint: Option<Arc<dyn appsec_checkpoint::CheckpointStore>>,
    validate: Option<appsec_interactive::ValidateContext<'_>>,
    term: &mut dyn appsec_interactive::Terminal,
) -> appsec_orchestrator::RemediateOutcome {
    if let Some(reason) = appsec_orchestrator::stale_refusal(report, repo, config.force) {
        return appsec_orchestrator::RemediateOutcome {
            refused: Some(reason),
            outcomes: Vec::new(),
            validations: Vec::new(),
            validation_failures: 0,
        };
    }

    let top = if config.top.is_some() {
        appsec_stage_s10::resolve_top(config.top, config.top_default)
    } else {
        None
    };
    let positions = appsec_stage_s10::select_top_by_cvss(
        report.findings.len(),
        top,
        |i| report.findings[i].finding.cvss_score,
        |i| appsec_orchestrator::severity_str(report.findings[i].severity),
    );
    let findings: Vec<appsec_interactive::PickerFinding> = positions
        .into_iter()
        .map(|pos| appsec_interactive::PickerFinding {
            finding_index: (pos + 1) as i64,
            finding: report.findings[pos].clone(),
        })
        .collect();

    let run_id = appsec_checkpoint::run_id_for(repo);
    let ctx = appsec_interactive::RemediationContext {
        client: llm.as_ref(),
        tools: tools.as_ref(),
        repo,
        config: &config.step10,
        policy,
        checkpoint: checkpoint.as_deref(),
        run_id: &run_id,
        validate,
    };
    let (outcomes, validations, validation_failures) =
        appsec_interactive::run_interactive(&ctx, &findings, term).await;
    appsec_orchestrator::redact_remediate_outcome(appsec_orchestrator::RemediateOutcome {
        refused: None,
        outcomes,
        validations,
        validation_failures,
    })
}

pub async fn remediate_from(
    cli: &Cli,
    path: &Path,
    llm: Arc<dyn LlmClient>,
) -> Result<ScanSummary, String> {
    remediate_from_with_cancel(cli, path, llm, None).await
}

pub(super) async fn remediate_from_with_cancel(
    cli: &Cli,
    path: &Path,
    llm: Arc<dyn LlmClient>,
    cancel: Option<appsec_pipeline_core::CancelTokenRef>,
) -> Result<ScanSummary, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read findings export {}: {e}", path.display()))?;
    let export: FindingsExport = serde_json::from_str(&text)
        .map_err(|e| format!("{} is not a findings export: {e}", path.display()))?;

    let repo = repo_path(cli);
    let report = appsec_model::FinalReport {
        provider_ledger: Default::default(),
        repo_root: repo.to_string_lossy().to_string(),
        repo_name: cli.repo_name.clone(),
        git_sha: Some(export.commit_sha),
        repo_identity: None,
        findings: export
            .findings
            .into_iter()
            .map(|finding| appsec_model::RankedFinding {
                severity: appsec_stage_s8::final_severity(&finding, appsec_model::Severity::Info),
                finding,
                exploitability_notes: String::new(),
            })
            .collect(),
        chains: Vec::new(),
        dropped: Vec::new(),
        raw_findings_count: 0,
        metrics: None,
        threat_model: None,
        app_profile: None,
        summary: String::new(),
        degraded: false,
        degraded_reason: String::new(),
        unreachable_files: Vec::new(),
    };

    let mut run = build_remediate_run(cli, repo)?;
    run.settings.config.step10.diff_scope =
        resolve_diff_scope(cli.diff_scope, build_github_client(cli)?.as_ref())
            .await?
            .boundary();
    let out_json = run.out_json.clone();
    let read_tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new(repo.to_path_buf()));
    let (result, remediation_patch) = dispatch_remediation(
        llm,
        read_tools,
        repo,
        &report,
        run,
        appsec_orchestrator::RemediateTelemetry {
            cancel,
            ..Default::default()
        },
    )
    .await;
    write_remediation_json(out_json.as_deref(), &result).map_err(stringify)?;

    let paths = resolve_output_paths(cli);
    let augmented = augment_prior_reports(&paths.markdown, &paths.sarif, &report, &result)
        .map_err(stringify)?;

    Ok(ScanSummary {
        findings: report.findings.len(),
        remediation: Some(RemediationSummary::from(&result)),
        remediation_patch,
        augmented: Some(augmented),
        markdown_path: None,
        ..Default::default()
    })
}

pub(super) fn target_test_findings(
    report: &appsec_model::FinalReport,
    config: &appsec_orchestrator::RemediateConfig,
) -> String {
    let positions = appsec_stage_s10::select_top_by_cvss(
        report.findings.len(),
        appsec_stage_s10::resolve_top(config.top, config.top_default),
        |i| report.findings[i].finding.cvss_score,
        |i| appsec_orchestrator::severity_str(report.findings[i].severity),
    );
    let selected: Vec<&appsec_model::RankedFinding> =
        positions.iter().map(|&pos| &report.findings[pos]).collect();
    serde_json::to_string(&selected)
        .unwrap_or_else(|_| "Findings unavailable; record this coverage gap".into())
}

pub(super) async fn dispatch_remediation(
    llm: Arc<dyn LlmClient>,
    scan_read_tools: Arc<dyn ToolExecutor>,
    repo_root: &Path,
    report: &appsec_model::FinalReport,
    run: RemediateRun,
    telemetry: appsec_orchestrator::RemediateTelemetry,
) -> (appsec_orchestrator::RemediateOutcome, Option<PathBuf>) {
    let llm = appsec_orchestrator::cancel_aware_client(llm, telemetry.cancel.clone());
    let RemediateRun {
        mut settings,
        tools: write_tools,
        mut worktree,
        mut delivery,
        checkpoint,
        ..
    } = run;
    let (rem_root, validate_tools) =
        if let Some(snapshot) = delivery.as_ref().and_then(|d| d.snapshot.as_ref()) {
            (
                snapshot.path().to_path_buf(),
                Arc::new(SandboxTools::new(snapshot.path().to_path_buf())) as Arc<dyn ToolExecutor>,
            )
        } else {
            match &worktree {
                Some(w) => (
                    w.path.clone(),
                    Arc::new(SandboxTools::new(w.path.clone())) as Arc<dyn ToolExecutor>,
                ),
                None => (repo_root.to_path_buf(), scan_read_tools),
            }
        };
    if delivery.is_some()
        && (report.degraded
            || report.metrics.as_ref().is_some_and(|m| {
                !m.budget_stop.is_empty()
                    || m.chunks_failed > 0
                    || m.errors_by_stage.values().any(|n| *n > 0)
            }))
    {
        return (
            appsec_orchestrator::RemediateOutcome {
                refused: Some("Delivery requires a completed full scan".into()),
                outcomes: Vec::new(),
                validations: Vec::new(),
                validation_failures: 0,
            },
            None,
        );
    }
    let mut assurance = None;
    if let Some(test_config) = &settings.target_tests {
        let refusal = if worktree.is_none()
            && delivery
                .as_ref()
                .and_then(|d| d.snapshot.as_ref())
                .is_none()
        {
            Some(
                "Target testing requires an isolated worktree; no in-place fallback is allowed"
                    .to_string(),
            )
        } else if report.degraded
            || report.metrics.as_ref().is_some_and(|m| {
                !m.budget_stop.is_empty()
                    || m.chunks_failed > 0
                    || m.errors_by_stage.values().any(|n| *n > 0)
            })
        {
            Some("Target testing requires a completed full scan; this report records degraded analysis or an exhausted budget".to_string())
        } else {
            None
        };
        if let Some(reason) = refusal {
            return (
                appsec_orchestrator::RemediateOutcome {
                    refused: Some(reason),
                    outcomes: Vec::new(),
                    validations: Vec::new(),
                    validation_failures: 0,
                },
                None,
            );
        }
        let findings = target_test_findings(report, &settings.config);
        match target_testing::prepare(
            &rem_root,
            test_config,
            &settings.config.step10.model,
            llm.as_ref(),
            &findings,
        )
        .await
        {
            Ok(mut prepared) => {
                prepared.scan_revision = report.git_sha.clone();
                settings.config.step10.target_test_context =
                    Some(target_testing::remediation_context(&prepared));
                assurance = Some(prepared);
            }
            Err(e) => {
                return (
                    appsec_orchestrator::RemediateOutcome {
                        refused: Some(format!("Target test preparation blocked: {e}")),
                        outcomes: Vec::new(),
                        validations: Vec::new(),
                        validation_failures: 0,
                    },
                    None,
                )
            }
        }
    }
    if !settings.validate_enabled {
        eprintln!(
            "  [s11] disabled (--no-validate or step_validate.enabled: false); S10 patches \
             are kept without an independent validation pass"
        );
    }
    let mut result = if settings.interactive {
        let mut term = appsec_interactive::RealTerminal;
        let validate = settings
            .validate_enabled
            .then(|| appsec_interactive::ValidateContext {
                step11: &settings.step11,
                tools: validate_tools.as_ref(),
            });
        remediate_interactively(
            llm,
            write_tools,
            &rem_root,
            report,
            &settings.config,
            settings.policy.as_ref(),
            checkpoint,
            validate,
            &mut term,
        )
        .await
    } else {
        let validate = settings
            .validate_enabled
            .then(|| appsec_orchestrator::ValidateConfig {
                step11: &settings.step11,
                tools: validate_tools.as_ref(),
            });
        appsec_orchestrator::remediate_observed(
            llm,
            write_tools,
            &rem_root,
            report,
            &settings.config,
            settings.policy.as_ref(),
            checkpoint,
            validate,
            &telemetry,
        )
        .await
    };
    let mut block_export = false;
    if let (Some(test_config), Some(assurance)) = (&settings.target_tests, &mut assurance) {
        if result.validation_failures > 0 {
            assurance.export_blocked = true;
            assurance.remaining_gaps.push("Independent patch review failed; passing tests cannot replace the missing review. Export withheld.".into());
        }
        if let Some(reason) = appsec_pipeline_core::canceled(telemetry.cancel.as_ref()) {
            assurance.export_blocked = true;
            assurance.remaining_gaps.push(format!(
                "Target tests were not run: {reason}. Export withheld."
            ));
        } else {
            target_testing::finish(&rem_root, test_config, assurance).await;
        }
        block_export = assurance.export_blocked;
        let artifact = appsec_pathjail::confine(repo_root, "security-scan/target-tests.json");
        let saved = artifact
            .as_ref()
            .ok_or_else(|| "Target-test artifact path escapes repository".to_string())
            .and_then(|path| target_testing::write_artifact(path, assurance));
        if let Err(e) = saved {
            block_export = true;
            result.refused = Some(format!(
                "Target-test evidence could not be saved; patch export withheld: {e}"
            ));
        }
        eprintln!(
            "  [target-tests] evidence: {} (generation: {}, review: {}; execution results: {}; environment blocked: {})",
            artifact
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "blocked path".into()),
            assurance.generation_state,
            assurance.review_state,
            assurance.execution.len(),
            assurance.environment_blocked
        );
    }
    if block_export {
        for outcome in &mut result.outcomes {
            if let appsec_stage_s10::RemediationOutcome::Processed(record) = outcome {
                record.diff = None;
                record.verdict.verdict = appsec_stage_s10::Verdict::NeedsReview;
                record.final_verdict =
                    Some("Needs Review: target-test validation blocked export".into());
            }
        }
        result.validations.clear();
        result.refused.get_or_insert_with(|| "Target-test validation blocked patch export; inspect security-scan/target-tests.json".into());
    }
    if let Some(state) = delivery.as_mut() {
        let rejected_review = result
            .validations
            .iter()
            .flatten()
            .any(|score| score.fix_status != appsec_validation_scoring::FixVerdict::Fixed);
        let failed_fix = result.outcomes.iter().any(|outcome| match outcome {
            appsec_stage_s10::RemediationOutcome::Processed(record) => {
                record.verdict.verdict == appsec_stage_s10::Verdict::NeedsReview
            }
            _ => true,
        });
        if appsec_pipeline_core::canceled(telemetry.cancel.as_ref()).is_some()
            || block_export
            || result.refused.is_some()
            || result.validation_failures > 0
            || rejected_review
            || failed_fix
        {
            result.refused.get_or_insert_with(|| {
                "Delivery withheld: remediation or validation needs review".into()
            });
            return (result, None);
        }
        match delivery::deliver(state, &rem_root).await {
            Ok(receipt) => {
                eprintln!(
                    "  [delivery] {} {}: {}",
                    receipt.mode, receipt.status, receipt.destination
                );
                let saved = appsec_pathjail::confine(repo_root, "security-scan/delivery.json")
                    .ok_or_else(|| "Delivery receipt path escapes repository".to_string())
                    .and_then(|path| {
                        if let Some(parent) = path.parent() {
                            std::fs::create_dir_all(parent).map_err(stringify)?;
                        }
                        let mut json = serde_json::to_value(&receipt).map_err(stringify)?;
                        json["scan_revision"] = serde_json::json!(report.git_sha);
                        json["validation"] = serde_json::json!({
                            "model_review_enabled": settings.validate_enabled,
                            "model_review_results": result.validations.iter().flatten().map(|s| format!("{:?}", s.fix_status)).collect::<Vec<_>>(),
                            "target_test_status": assurance.as_ref().map(|a| &a.assurance_status),
                            "target_command_results": assurance.as_ref().map_or(0, |a| a.execution.len()),
                            "note": "Delivery is not proof of security or functional correctness; inspect scoped validation evidence and remaining gaps."
                        });
                        std::fs::write(
                            path,
                            serde_json::to_vec_pretty(&appsec_redact::redact_tree(&json))
                                .map_err(stringify)?,
                        )
                        .map_err(stringify)
                    });
                if let Err(e) = saved {
                    result.refused = Some(format!("Delivery completed but receipt could not be saved: {e}; inspect the destination before retrying"));
                }
            }
            Err(e) => {
                if let Some(snapshot) = state.snapshot.take() {
                    eprintln!(
                        "  [delivery] failed; updated snapshot retained at {}",
                        snapshot.keep().display()
                    );
                }
                if let Some(w) = worktree.as_mut() {
                    w.keep = true;
                    eprintln!(
                        "  [delivery] failed; worktree retained at {}",
                        w.path.display()
                    );
                }
                result.refused = Some(format!("Delivery failed: {e}"));
            }
        }
        return (result, None);
    }
    let patch = if block_export {
        None
    } else {
        worktree.as_mut().and_then(worktree::finish)
    };
    (result, patch)
}

pub struct RemediateRun {
    pub delivery: Option<delivery::DeliveryState>,
    pub settings: RemediateSettings,
    pub tools: Arc<dyn ToolExecutor>,
    pub worktree: Option<worktree::RemediationWorktree>,
    pub out_json: Option<PathBuf>,
    pub checkpoint: Option<Arc<dyn appsec_checkpoint::CheckpointStore>>,
}

pub(super) fn build_remediate_run(cli: &Cli, repo: &Path) -> Result<RemediateRun, String> {
    let mut settings = build_remediate_settings(cli)?;
    let delivery = delivery::prepare(cli, repo)?;
    let zip_mode = cli.remediation_delivery == delivery::DeliveryMode::Zip;
    if settings.target_tests.is_some() || delivery.is_some() {
        if settings.config.step10.verify_command.is_some()
            || settings.config.step10.dry_run
            || !settings.config.step10.fix_mode
        {
            return Err("Target testing requires fix mode without dry-run or a host verify_command; use execution.commands in the isolated target-test policy".into());
        }
        if !zip_mode {
            let status = std::process::Command::new("git")
                .arg("-C")
                .arg(repo)
                .args(["status", "--porcelain", "--untracked-files=all"])
                .output()
                .map_err(context("Target testing requires a clean Git snapshot"))?;
            if !status.status.success() {
                let detail = String::from_utf8_lossy(&status.stderr);
                let detail = detail.trim();
                return Err(format!(
                    "Target testing needs to read {}'s Git status and git refused: {}. \
                     If the scanner runs as a different user than the checkout's owner, \
                     mark the path safe, for example by setting GIT_CONFIG_COUNT=1, \
                     GIT_CONFIG_KEY_0=safe.directory and GIT_CONFIG_VALUE_0={}.",
                    repo.display(),
                    if detail.is_empty() {
                        "no error output"
                    } else {
                        detail
                    },
                    repo.display()
                ));
            }
            if !status.stdout.is_empty() {
                return Err("Target testing requires a clean committed Git snapshot so scan, baseline and remediation inspect the same inputs".into());
            }
        }
    }
    let worktree = if zip_mode {
        None
    } else {
        worktree::prepare(cli, repo)
    };
    if (settings.target_tests.is_some() || delivery.is_some()) && !zip_mode && worktree.is_none() {
        return Err("Target testing requires an isolated worktree; creation failed and in-place fallback is disabled".into());
    }
    let root = delivery
        .as_ref()
        .and_then(|d| d.snapshot.as_ref())
        .map(|s| s.path().to_path_buf())
        .or_else(|| worktree.as_ref().map(|w| w.path.clone()))
        .unwrap_or_else(|| repo.to_path_buf());
    let tools = SandboxTools::new_with_write(root);
    settings.config.step10.journal = Some(tools.journal());
    settings.config.isolated = worktree.is_some() || zip_mode;
    Ok(RemediateRun {
        delivery,
        settings,
        tools: Arc::new(tools),
        worktree,
        out_json: cli.out_remediation_json.clone(),
        checkpoint: open_checkpoint_store(),
    })
}

pub(super) fn remediation_views(
    report: &appsec_model::FinalReport,
    outcome: &appsec_orchestrator::RemediateOutcome,
) -> Vec<appsec_report_md::RemediationView> {
    let positions: std::collections::BTreeMap<String, usize> = report
        .findings
        .iter()
        .enumerate()
        .map(|(i, rf)| (appsec_sarif::finding_id(&rf.finding), i))
        .collect();
    outcome
        .outcomes
        .iter()
        .enumerate()
        .filter_map(|(i, o)| {
            let appsec_stage_s10::RemediationOutcome::Processed(record) = o else {
                return None;
            };
            let finding_index = *positions.get(&record.finding_id)?;
            Some(appsec_report_md::RemediationView {
                finding_index,
                verdict: record
                    .final_verdict
                    .clone()
                    .unwrap_or_else(|| record.verdict.verdict.as_str().to_string()),
                summary: record.verdict.summary.clone(),
                root_cause: record.verdict.root_cause.clone(),
                remaining_risks: record.verdict.remaining_risks.clone(),
                recommendations: record.verdict.recommendations.clone(),
                changed_files: record
                    .verdict
                    .changes
                    .iter()
                    .map(|c| c.file.clone())
                    .collect(),
                has_diff: record.diff.is_some(),
                rollback_reason: appsec_stage_s10::revert_reason(record).map(str::to_string),
                validation_status: outcome
                    .validations
                    .get(i)
                    .and_then(Option::as_ref)
                    .map(|v| v.fix_status.as_str().to_string()),
            })
        })
        .collect()
}

pub(super) fn remediation_statuses(
    outcome: &appsec_orchestrator::RemediateOutcome,
) -> std::collections::BTreeMap<String, String> {
    outcome
        .outcomes
        .iter()
        .filter_map(|o| {
            let appsec_stage_s10::RemediationOutcome::Processed(record) = o else {
                return None;
            };
            Some((
                record.finding_id.clone(),
                record
                    .final_verdict
                    .clone()
                    .unwrap_or_else(|| record.verdict.verdict.as_str().to_string()),
            ))
        })
        .collect()
}

pub(super) fn apply_remediation_status(
    doc: &mut appsec_sarif::SarifDocument,
    report: &appsec_model::FinalReport,
    outcome: &appsec_orchestrator::RemediateOutcome,
) {
    let by_id = remediation_statuses(outcome);
    if by_id.is_empty() {
        return;
    }
    for run in &mut doc.runs {
        for (result, rf) in run.results.iter_mut().zip(&report.findings) {
            if let Some(status) = by_id.get(&appsec_sarif::finding_id(&rf.finding)) {
                result.properties.remediation_status = Some(status.clone());
            }
        }
    }
}

pub(super) fn write_remediation_json(
    path: Option<&Path>,
    outcome: &appsec_orchestrator::RemediateOutcome,
) -> std::io::Result<()> {
    let Some(path) = path else {
        return Ok(());
    };
    let results = outcome
        .outcomes
        .iter()
        .enumerate()
        .map(|(i, o)| {
            let validation = outcome.validations.get(i).and_then(Option::as_ref);
            RemediationOutcomeExport::from_parts(o, validation)
        })
        .collect();
    let summary = RemediationSummary::from(outcome);
    let export = RemediationExport {
        refused: outcome.refused.clone(),
        results,
        totals: RemediationTotalsExport::from(&summary),
        rollup: RollupExport::from(&summary.rollup),
    };
    let json = serde_json::to_string_pretty(&export)
        .expect("RemediationExport contains no non-serializable types");
    create_parent_dir(path)?;
    std::fs::write(path, json)
}
