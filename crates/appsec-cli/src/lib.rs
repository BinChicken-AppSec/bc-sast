mod args;
mod augment;
mod autoexclude;
mod baseline;
mod batch;
mod cache_probe;
pub mod cancel;
mod clients;
mod commands;
mod outputs;
mod remediate;
mod remediation_export;
mod scope;
mod settings;
mod summary;

use augment::*;
pub use clients::*;
pub use commands::*;
pub use outputs::*;
pub use remediate::*;
use remediation_export::*;
pub use scope::*;
pub use settings::*;
pub use summary::*;
mod clone;
mod config_load;
mod config_overrides;
mod csv_parse;
pub mod delivery;
pub mod delivery_archive;
pub mod delivery_branch;
mod environment;
mod estimate;
mod llm_settings;
mod logging;
mod model_policy;
mod preflight;
mod progress;
mod progress_lines;
pub mod provider_publish;
mod run_manifest;
mod s6_progress;
pub mod target_executor;
pub mod target_testing;
mod worktree;

use std::path::{Path, PathBuf};
use std::sync::Arc;

#[cfg(test)]
pub(crate) use args::test_support;
pub use args::{Cli, Dialect, StopAfterArg};
pub use logging::init_logging;

use appsec_llm_client::{LlmClient, ToolExecutor};
use appsec_orchestrator::{ScanConfig, ScanInput, ScanOutcome, SpendCap, StopAfter};
use appsec_sandbox_tools::SandboxTools;
use appsec_stage_s0::Step0Config;
use appsec_stage_s1::Step1Config;
use appsec_stage_s2::Step2Config;
use appsec_stage_s3::Step3Config;
use appsec_stage_s4::Step4Config;
use appsec_stage_s5::Step5Config;
use appsec_stage_s6::Step6Config;
use appsec_stage_s7::Step7Config;
use appsec_stage_s8::Step8Config;
use serde::{Deserialize, Serialize};
use serde_json::Value;

fn getenv(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

fn repo_path(cli: &Cli) -> &Path {
    cli.repo
        .as_deref()
        .expect("cli.repo is Some by the time any scan-path function reads it")
}

fn stringify<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

fn context<E: std::fmt::Display>(what: &'static str) -> impl Fn(E) -> String {
    move |error| format!("{what}: {error}")
}

fn non_empty(raw: &str) -> Option<&str> {
    (!raw.is_empty()).then_some(raw)
}

fn parse_stop_after(raw: &str) -> Result<Option<StopAfterArg>, String> {
    non_empty(raw)
        .map(|s| {
            <StopAfterArg as clap::ValueEnum>::from_str(s, true)
                .map_err(|_| format!("invalid --stop-after value: {s:?}"))
        })
        .transpose()
}

#[cfg(test)]
mod remediation_outcome_tests;

#[allow(clippy::too_many_arguments)]
pub async fn run(
    input: ScanInput,
    config: ScanConfig,
    stop_after: Option<StopAfter>,
    paths: &OutputPaths,
    llm: Arc<dyn LlmClient>,
    tools: Arc<dyn ToolExecutor>,
    github: Option<appsec_github::GithubClient>,
    remediate: Option<RemediateRun>,
    baseline: Option<BaselineRun>,
) -> Result<ScanSummary, String> {
    run_with_publication(
        input, config, stop_after, paths, llm, tools, github, remediate, baseline, None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn run_with_publication(
    input: ScanInput,
    config: ScanConfig,
    stop_after: Option<StopAfter>,
    paths: &OutputPaths,
    llm: Arc<dyn LlmClient>,
    tools: Arc<dyn ToolExecutor>,
    github: Option<appsec_github::GithubClient>,
    remediate: Option<RemediateRun>,
    baseline: Option<BaselineRun>,
    publication: Option<provider_publish::automatic::Run>,
) -> Result<ScanSummary, String> {
    if publication.is_some()
        && (input.diff_scope_active
            || config.resume
            || stop_after.is_some_and(|stop| stop != StopAfter::S9))
    {
        return Err("Automatic provider publication requires a full scan that reaches S9 without --resume or --diff-scope".into());
    }
    if remediate
        .as_ref()
        .is_some_and(|r| r.settings.target_tests.is_some() || r.delivery.is_some())
        && (stop_after.is_some() || input.diff_scope_active)
    {
        return Err("Target testing requires a full scan plus remediation".into());
    }
    paths.ensure_dirs()?;
    let md_path = paths.markdown.as_path();
    let sarif_path = paths.sarif.as_path();
    let repo_root = input.repo_root.clone();
    let mut input = input;
    let scan_snapshot = remediate.as_ref().and_then(|r| {
        let delivery = r.delivery.as_ref()?;
        delivery
            .snapshot
            .as_ref()
            .map(|s| s.path().to_path_buf())
            .or_else(|| r.worktree.as_ref().map(|w| w.path.clone()))
    });
    let tools = if let Some(root) = scan_snapshot {
        input.repo_root = root.clone();
        Arc::new(SandboxTools::new(root)) as Arc<dyn ToolExecutor>
    } else {
        tools
    };

    let validate_tools = tools.clone();
    let tool_version = config.tool_version.clone();
    let line_tolerance = config.step7.line_tolerance;
    let remediation_telemetry = appsec_orchestrator::RemediateTelemetry {
        progress: config.progress.clone(),
        pricing: config.pricing.clone(),
        cancel: config.cancel.clone(),
    };
    let outcome = appsec_orchestrator::run_scan(llm.clone(), tools, input, config, stop_after)
        .await
        .map_err(stringify)?;
    let canceled = appsec_pipeline_core::canceled(remediation_telemetry.cancel.as_ref());
    let (publication, github, remediate) = if canceled.is_some() {
        (None, None, None)
    } else {
        (publication, github, remediate)
    };

    write_outputs(&outcome, md_path, sarif_path, &paths.csv).map_err(stringify)?;
    if let (Some(path), Some(plan)) = (
        &paths.provider_writeback_plan,
        &outcome.provider_writeback_plan,
    ) {
        std::fs::write(path, plan).map_err(stringify)?;
    }
    let published_report = if outcome.stopped_after == Some(StopAfter::S8) {
        None
    } else {
        outcome.report.as_ref()
    };
    let findings_json_written =
        write_findings_json(&paths.findings_json, published_report).map_err(stringify)?;

    let provider_publication = match (publication, published_report) {
        (Some(publication), Some(report)) if outcome.markdown.is_some() => {
            let plan = paths.provider_writeback_plan.as_ref().ok_or_else(|| {
                "Automatic publication requires a provider plan output path".to_string()
            })?;
            Some(
                publication
                    .publish(
                        report,
                        &plan.with_file_name("provider-writeback-results.json"),
                    )
                    .await?,
            )
        }
        _ => None,
    };

    let github_sync =
        sync_github(github.as_ref(), published_report, Some(repo_root.as_path())).await;

    let mut remediation_patch = None;
    let remediation = match (remediate, &outcome.report) {
        (Some(r), Some(report)) if outcome.stopped_after.is_none() => {
            let delivery_requested = r.delivery.is_some();
            let target_test_requested = r.settings.target_tests.is_some();
            let out_json = r.out_json.clone();
            let (result, patch) = dispatch_remediation(
                llm,
                validate_tools,
                &repo_root,
                report,
                r,
                remediation_telemetry.clone(),
            )
            .await;
            remediation_patch = patch;
            write_remediation_json(out_json.as_deref(), &result).map_err(stringify)?;
            if delivery_requested {
                if let Some(reason) = &result.refused {
                    return Err(reason.clone());
                }
            }
            augment_report_outputs(
                md_path,
                sarif_path,
                report,
                &tool_version,
                outcome.markdown.as_deref(),
                outcome.sarif.is_some(),
                &result,
            )
            .map_err(stringify)?;
            if target_test_requested && result.refused.is_none() {
                target_testing::annotate_outputs(&repo_root, md_path, sarif_path)?;
            }
            Some(RemediationSummary::from(&result))
        }
        _ => None,
    };
    let progress = remediation_telemetry.progress.as_ref();
    if let Some(reason) = &canceled {
        appsec_orchestrator::remediation_canceled(progress, reason);
    } else if remediation.is_none() && outcome.report.is_some() && outcome.stopped_after.is_none() {
        appsec_orchestrator::remediation_not_requested(progress);
    }
    drop(remediation_telemetry);

    let baseline_tally = match (&baseline, published_report) {
        (Some(b), Some(report)) => Some(
            apply_baseline_outputs(
                md_path,
                sarif_path,
                report,
                b,
                &repo_root,
                line_tolerance,
                outcome.sarif.is_some(),
            )
            .map_err(stringify)?,
        ),
        _ => None,
    };

    Ok(ScanSummary {
        provider_publication,
        cost: outcome
            .report
            .as_ref()
            .and_then(|r| r.metrics.as_ref())
            .and_then(CostSummary::from_metrics),
        baseline: baseline_tally,
        findings: outcome.report.as_ref().map_or(0, |r| r.findings.len()),
        markdown_path: outcome.markdown.as_ref().map(|_| paths.markdown.clone()),
        sarif_path: outcome.sarif.as_ref().map(|_| paths.sarif.clone()),
        csv_path: published_report.map(|_| paths.csv.clone()),
        findings_json_path: findings_json_written.then(|| paths.findings_json.clone()),
        stopped_after: outcome.stopped_after,
        github_sync,
        remediation,
        remediation_patch,
        ..Default::default()
    })
}

pub struct BaselineRun {
    pub path: PathBuf,
    pub baseline: baseline::Baseline,
}

#[allow(clippy::too_many_arguments)]
fn apply_baseline_outputs(
    md_path: &Path,
    sarif_path: &Path,
    report: &appsec_model::FinalReport,
    run: &BaselineRun,
    repo_root: &Path,
    line_tolerance: i64,
    sarif_was_written: bool,
) -> std::io::Result<BaselineTally> {
    let renames = run
        .baseline
        .commit_sha
        .as_deref()
        .map(|sha| appsec_diffcapture::renames_between(repo_root, sha))
        .unwrap_or_default();
    let comparison = baseline::compare(
        &report.findings,
        &run.baseline,
        repo_root,
        line_tolerance,
        &renames,
    );
    if let Ok(markdown) = std::fs::read_to_string(md_path) {
        let view = baseline::view(&comparison, &report.findings, &run.path);
        create_parent_dir(md_path)?;
        std::fs::write(
            md_path,
            appsec_report_md::append_baseline_section(&markdown, &view),
        )?;
    }
    if sarif_was_written {
        if let Ok(sarif) = std::fs::read_to_string(sarif_path) {
            let annotated = baseline::annotate_sarif(&sarif, &comparison);
            create_parent_dir(sarif_path)?;
            std::fs::write(sarif_path, annotated)?;
        }
    }
    Ok(BaselineTally {
        new: comparison.new_count(),
        unchanged: comparison.unchanged_count(),
        resolved: comparison.resolved_count(),
    })
}

pub async fn main_impl(cli: Cli) -> Result<ScanSummary, String> {
    main_impl_with_cancel(cli, None).await
}

pub async fn main_impl_with_cancel(
    cli: Cli,
    cancel: Option<cancel::Controller>,
) -> Result<ScanSummary, String> {
    if cli.provider_publish.publish_provider_plan.is_none() && cli.provider_publish.requires_plan()
    {
        return Err("Provider publication flags require --publish-provider-plan".into());
    }
    if cli.provider_publish.publish_provider_plan.is_some() {
        if cli.remediate
            || cli.remediate_from.is_some()
            || cli.repo_file.is_some()
            || cli.post_comments_from.is_some()
            || cli.post_fixes_from.is_some()
            || cli.gc
            || cli.gc_run.is_some()
            || cli.estimate
            || cli.doctor
            || cli.setup
            || cli.provider_writeback != "off"
            || !cli.stop_after.is_empty()
        {
            return Err("Provider publication is a separate operation; do not combine it with scan, remediation, posting, or utility modes".into());
        }
        let result = provider_publish::run(&cli).await?;
        return Ok(ScanSummary {
            provider_publication: Some(result),
            ..Default::default()
        });
    }
    if cli.provider_writeback != "off"
        && (cli.gc
            || cli.gc_run.is_some()
            || cli.estimate
            || cli.doctor
            || cli.setup
            || cli.post_comments_from.is_some()
            || cli.post_fixes_from.is_some()
            || cli.remediate_from.is_some())
    {
        return Err("--provider-writeback requires a scan that reaches S9; it cannot be used with standalone posting, prior-report remediation, or utility modes".into());
    }
    check_automatic_publication_mode(&cli)?;
    target_testing::check_mode(&cli)?;
    delivery::check_mode(&cli)?;
    check_batch_diff_scope(&cli)?;
    check_pr_comment_scope(&cli)?;
    if cli.gc || cli.gc_run.is_some() {
        return run_gc(&cli);
    }
    if cli.estimate {
        let summary = estimate::run_estimate(repo_path(&cli))?;
        return Ok(ScanSummary {
            estimate: Some(summary),
            ..Default::default()
        });
    }
    if cli.doctor {
        let summary = run_doctor(&cli).await;
        return Ok(ScanSummary {
            doctor: Some(summary),
            ..Default::default()
        });
    }
    if cli.setup {
        let summary = run_setup(&cli);
        return Ok(ScanSummary {
            setup: Some(summary),
            ..Default::default()
        });
    }
    if let Some(path) = cli.post_comments_from.clone() {
        let github = build_github_client(&cli)?.ok_or_else(|| {
            "--post-comments-from requires --github-token/--github-repo/--pr-number".to_string()
        })?;
        return post_comments_only(&github, &path, Some(repo_path(&cli))).await;
    }
    if let Some(path) = cli.post_fixes_from.clone() {
        let github = build_github_client(&cli)?.ok_or_else(|| {
            "--post-fixes-from requires --github-token/--github-repo/--pr-number".to_string()
        })?;
        return post_fixes_only(&github, &path).await;
    }
    if let Some(dir) = non_empty(&cli.context_dir) {
        let target = cli.repo.clone().unwrap_or_default();
        appsec_context::load(std::path::Path::new(dir), &target, &|k| {
            std::env::var(k).ok()
        })
        .map_err(|e| format!("deployment context: {e}"))?;
    }
    model_policy::enforce(
        &cli.model,
        &lenient_config_data(&cli),
        cli.allow_unsupported_model,
    )?;
    if let Some(path) = cli.remediate_from.clone() {
        let client_result = build_llm_client(&cli);
        if !cli.skip_preflight {
            preflight::run(&cli, &client_result).await?;
        }
        let cancel = cancel.as_ref().map(cancel::Controller::arm);
        return remediate_from_with_cancel(&cli, &path, client_result?, cancel).await;
    }
    if let Some(manifest_path) = cli.repo_file.clone() {
        let summary = batch::run_batch(&cli, &manifest_path).await?;
        return Ok(ScanSummary {
            batch: Some(summary),
            ..Default::default()
        });
    }

    let publication = provider_publish::automatic::configure(&cli)?;
    let stack_result = build_llm_stack(&cli);
    let client_result = stack_result
        .as_ref()
        .map(|stack| stack.client.clone())
        .map_err(Clone::clone);
    if !cli.skip_preflight {
        preflight::run(&cli, &client_result).await?;
    }
    let stack = stack_result?;
    let llm = stack.client.clone();
    let tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new(repo_path(&cli).to_path_buf()));
    let github = build_github_client(&cli)?;
    let mut config = build_scan_config(&cli)?;
    autoexclude::maybe_apply(&cli, &llm, repo_path(&cli), &mut config).await;
    config.checkpoint = open_checkpoint_store();
    let mut input = build_scan_input(&cli);
    let diff_scope = resolve_diff_scope(cli.diff_scope, github.as_ref()).await?;
    let remediation_boundary = diff_scope.boundary();
    input.diff_scope_active = diff_scope.active;
    input.changed_files = diff_scope.changed_files;
    input.compliance = load_compliance_policies(&cli)?;
    let stop_after = parse_stop_after(&cli.stop_after)?.map(StopAfter::from);
    let paths = resolve_output_paths(&cli);
    let mut remediate = (cli.remediate && stop_after.is_none())
        .then(|| build_remediate_run(&cli, repo_path(&cli)))
        .transpose()?;
    if let Some(run) = remediate.as_mut() {
        run.settings.config.step10.diff_scope = remediation_boundary;
    }
    let baseline = cli
        .baseline
        .as_ref()
        .map(|path| -> Result<BaselineRun, String> {
            Ok(BaselineRun {
                path: path.clone(),
                baseline: baseline::load(path, repo_path(&cli))?,
            })
        })
        .transpose()?;

    let manifest = run_manifest::begin(
        &cli,
        &config,
        remediate.as_ref().map(|r| &r.settings),
        stack.settings.openai_api,
        &input.repo_name,
        std::env::args_os()
            .map(|a| a.to_string_lossy().into_owned())
            .collect(),
    );
    let mut observers = progress::Observers::choose(
        progress::should_render(cli.no_progress),
        progress_lines::from_cli(&cli),
    );
    if cli.s6_progress_file || config.step6.progress_file {
        observers.s6_progress = s6_progress::resolve(repo_path(&cli));
    }
    let progress_handle = progress::wire(&mut config, observers);
    config.cancel = cancel.as_ref().map(cancel::Controller::arm);

    let result = run_with_publication(
        input,
        config,
        stop_after,
        &paths,
        llm,
        tools,
        pr_comment_target(&cli, github),
        remediate,
        baseline,
        publication,
    )
    .await;
    let telemetry = progress_handle.join().unwrap_or_default();
    let git_sha = non_empty(&cli.git_sha)
        .map(str::to_string)
        .or_else(|| appsec_orchestrator::head_sha(repo_path(&cli)));
    let exit_code = i32::from(process_exit_code(
        &result,
        cli.remediation_exit_code,
        cancel.as_ref().is_some_and(cancel::Controller::is_canceled),
    ));
    run_manifest::finish(
        manifest,
        &telemetry,
        exit_code,
        git_sha,
        stack.responses_fallbacks(),
        |model| stack.resolved_transport(model),
    );
    result
}

#[cfg(test)]
#[cfg(test)]
pub(crate) mod tests;
