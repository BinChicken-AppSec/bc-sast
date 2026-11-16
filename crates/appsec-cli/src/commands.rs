use super::*;
pub async fn post_comments_only(
    github: &appsec_github::GithubClient,
    findings_json_path: &Path,
    repo_root: Option<&Path>,
) -> Result<ScanSummary, String> {
    let bytes = std::fs::read(findings_json_path).map_err(stringify)?;
    let export: FindingsExport = serde_json::from_slice(&bytes).map_err(stringify)?;
    let sync_result =
        appsec_github::sync_findings(github, &export.findings, &export.commit_sha, repo_root)
            .await
            .map_err(|e| e.to_string());
    Ok(ScanSummary {
        findings: export.findings.len(),
        github_sync: Some(sync_result),
        ..Default::default()
    })
}

pub async fn post_fixes_only(
    github: &appsec_github::GithubClient,
    remediation_json_path: &Path,
) -> Result<ScanSummary, String> {
    let bytes = std::fs::read(remediation_json_path).map_err(stringify)?;
    let export: RemediationExport = serde_json::from_slice(&bytes).map_err(stringify)?;
    let fixes: Vec<appsec_github::FixSuggestion> = export
        .results
        .into_iter()
        .filter_map(|r| match r {
            RemediationOutcomeExport::Processed(record) => {
                let diff = record.diff?;
                (!diff.is_empty()).then_some(appsec_github::FixSuggestion {
                    finding_id: record.finding_id,
                    diff,
                })
            }
            RemediationOutcomeExport::Failed { .. } => None,
        })
        .collect();
    let sync_result = appsec_github::sync_fixes(github, &fixes)
        .await
        .map_err(|e| e.to_string());
    Ok(ScanSummary {
        findings: fixes.len(),
        github_sync: Some(sync_result),
        ..Default::default()
    })
}

pub(super) async fn sync_github(
    github: Option<&appsec_github::GithubClient>,
    report: Option<&appsec_model::FinalReport>,
    repo_root: Option<&Path>,
) -> Option<Result<appsec_github::SyncSummary, String>> {
    let client = github?;
    let report = report?;
    let commit_sha = report.git_sha.as_ref()?;
    let findings = extract_findings(report);
    Some(
        appsec_github::sync_findings(client, &findings, commit_sha, repo_root)
            .await
            .map_err(stringify),
    )
}

pub(super) fn open_checkpoint_store() -> Option<Arc<dyn appsec_checkpoint::CheckpointStore>> {
    match appsec_checkpoint::SqliteCheckpointStore::open_default() {
        Ok(store) => Some(Arc::new(store)),
        Err(e) => {
            eprintln!(
                "WARN: checkpoint store unavailable ({e}); --resume will have no effect this run"
            );
            None
        }
    }
}

pub fn run_gc(cli: &Cli) -> Result<ScanSummary, String> {
    let store = appsec_checkpoint::SqliteCheckpointStore::open_default().map_err(stringify)?;
    let gc = if let Some(path) = &cli.gc_run {
        let run_id = appsec_checkpoint::run_id_for(path);
        let found = if cli.gc_dry_run {
            false
        } else {
            store.delete_run(&run_id).map_err(stringify)?
        };
        GcSummary::Evicted {
            path: path.clone(),
            run_id,
            found,
            dry_run: cli.gc_dry_run,
        }
    } else {
        let report = store
            .prune(cli.gc_keep_runs, cli.gc_max_age_days, cli.gc_dry_run)
            .map_err(stringify)?;
        GcSummary::Pruned {
            db_path: report.db_path,
            kept: report.kept,
            deleted: report.deleted,
            dry_run: cli.gc_dry_run,
        }
    };
    Ok(ScanSummary {
        gc: Some(gc),
        ..Default::default()
    })
}

pub(super) async fn run_doctor(cli: &Cli) -> DoctorSummary {
    let stack_result = build_llm_stack(cli);
    let client_result = stack_result
        .as_ref()
        .map(|stack| stack.client.clone())
        .map_err(Clone::clone);
    let checks = environment::run_checks(cli, &client_result);
    let blocking = environment::n_blocking(&checks);
    let checks_rendered = environment::render(&checks);
    let models = model_policy::configured_models(&cli.model, &lenient_config_data(cli));
    let models_rendered =
        model_policy::render_capabilities(&models, &appsec_llm_client::capabilities::today_utc());
    let mut cache_probe = None;
    let probe = if blocking == 0 {
        let stack = stack_result
            .expect("blocking == 0 implies the gateway-client check already found this Ok");
        let probe = environment::probe_gateway(stack.client.as_ref(), &cli.model).await;
        if cli.cache_probe {
            cache_probe = Some(if probe.status == environment::CheckStatus::Ok {
                let dialect = match cli.dialect {
                    Dialect::Openai => appsec_llm_client::CacheDialect::OpenAi,
                    Dialect::Anthropic => appsec_llm_client::CacheDialect::Anthropic,
                };
                cache_probe::run(
                    stack.client.as_ref(),
                    &cli.model,
                    dialect,
                    &stack.settings.cache,
                )
                .await
            } else {
                cache_probe::CacheProbeOutcome::skipped(&cli.model)
            });
        }
        Some(probe)
    } else {
        cache_probe = cli
            .cache_probe
            .then(|| cache_probe::CacheProbeOutcome::skipped(&cli.model));
        None
    };
    DoctorSummary {
        checks_rendered,
        blocking,
        models_rendered,
        probe,
        cache_probe,
    }
}

pub(super) fn run_setup(cli: &Cli) -> SetupSummary {
    let client_result = build_llm_client(cli);
    let checks = environment::run_checks(cli, &client_result);
    let blocking = environment::n_blocking(&checks);
    let checks_rendered = environment::render(&checks);
    SetupSummary {
        checks_rendered,
        blocking,
    }
}

pub(super) fn check_automatic_publication_mode(cli: &Cli) -> Result<(), String> {
    if cli.provider_writeback == "apply"
        && (cli.diff_scope
            || cli.resume
            || parse_stop_after(&cli.stop_after)?
                .is_some_and(|stop| StopAfter::from(stop) != StopAfter::S9))
    {
        return Err("Automatic provider publication requires a full scan that reaches S9 without --resume or --diff-scope".into());
    }
    Ok(())
}
