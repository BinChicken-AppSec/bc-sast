mod diagnostics;
pub use diagnostics::autoexclude_counts;
mod cancellation;
mod checkpoints;
mod config;
mod metrics;
mod providers;
mod remediate;
mod spend;
mod stages;
mod usage;

use checkpoints::*;
pub use config::*;
use metrics::*;
use providers::*;
pub use remediate::*;
pub use spend::*;
use usage::*;
mod coverage;
pub use cancellation::cancel_aware_client;
pub mod manifest;
mod provider_assessment;
pub mod reporting;
mod telemetry;
use appsec_pipeline_core::StageStatus;
use reporting::Stage9;
use telemetry::StageRun;

pub mod pricing;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use appsec_checkpoint::CheckpointStore;
use appsec_llm_client::{ChatRequest, ChatResponse, LlmClient, LlmError, ToolExecutor, Usage};
use appsec_model::{
    AppProfile, Chunk, ContextPackage, Control, DropReason, DroppedFinding, FinalReport, Finding,
    ScanMetrics, ScopeEntry, ScopeKind, TaskManifest,
};
use appsec_pipeline_core::{PipelineStage, StageError};
use appsec_stage_s0::Step0Config;
use appsec_stage_s1::Step1Config;
use appsec_stage_s2::Step2Config;
use appsec_stage_s3::Step3Config;
use appsec_stage_s4::{Stage4, Step4Config, Step4Input};
use appsec_stage_s5::{Stage5, Step5Config, Step5Input};
use appsec_stage_s6::{Stage6, Step6Config, Step6Input};
use appsec_stage_s7::{Stage7, Step7Config, Step7Input};
use appsec_stage_s8::{Stage8, Step8Config, Step8Input};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

fn unverified_by_budget(candidates: &mut Vec<Finding>, reason: &str) -> Vec<DroppedFinding> {
    let detail = format!("not verified — {reason}");
    candidates
        .drain(..)
        .map(|f| DroppedFinding {
            file: f.file,
            line: f.line_start,
            vuln_class: f.vuln_class,
            title: f.title,
            chunk_id: f.chunk_id,
            reason: DropReason::Unconfirmed,
            detail: detail.clone(),
            canonical_idx: None,
            provider_origins: f.provider_origins,
            verification: None,
        })
        .collect()
}

pub fn head_sha(repo: &Path) -> Option<String> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(repo)
        .arg("rev-parse")
        .arg("HEAD")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

pub async fn run_scan(
    llm: Arc<dyn LlmClient>,
    tools: Arc<dyn ToolExecutor>,
    mut input: ScanInput,
    config: ScanConfig,
    stop_after: Option<StopAfter>,
) -> Result<ScanOutcome, StageError> {
    let start_ts = appsec_metrics::now_iso();
    let scan_uuid = appsec_metrics::scan_uuid();
    let scan_start = std::time::Instant::now();
    let tracker = Arc::new(UsageTrackingClient::new(llm, &config.pricing));
    let gathered = providers::gather_all(tracker.as_ref(), &mut input).await?;

    let run_id = appsec_checkpoint::run_id_for(&input.repo_root);
    if let Some(cp) = &config.checkpoint {
        cp.register_run(
            &run_id,
            &input.repo_root.to_string_lossy(),
            Some(input.repo_name.as_str()),
            input.application_id.as_deref(),
        );
        if !config.resume {
            cp.reset_run(&run_id);
        }
    }
    let cancel = config.cancel.clone();
    let mut p = stages::Pipeline {
        llm: tracker.clone(),
        tracker: tracker.clone(),
        progress: config.progress.as_ref(),
        checkpoint: config.checkpoint.as_deref(),
        cancel: cancel.clone(),
        run_id: run_id.clone(),
        resume: config.resume,
        scan_start,
        stage_timings: telemetry::StageTimings::new(),
        tokens_by_phase: BTreeMap::new(),
        errors_by_stage: BTreeMap::new(),
        diag: diagnostics::seeded(&config.autoexclude),
    };

    let seed = stages::step0(
        &mut p,
        config.step0,
        config.step1.walk.clone(),
        config.step0_enabled,
        &input.repo_root,
    )
    .await?;
    let digest = gathered.imported.digest.clone();
    let mut ctx = stages::step1(&mut p, config.step1, tools.clone(), &input, seed, digest).await?;
    providers::attach_gathered_context(&mut ctx, &gathered);

    if stop_after == Some(StopAfter::S1) {
        return Ok(stopped(StopAfter::S1));
    }
    let threat_model = stages::step2(
        &mut p,
        config.step2,
        config.step2_enabled,
        tools.clone(),
        &input,
        &ctx,
        gathered.app_profile.clone(),
    )
    .await;
    ctx.threat_model = threat_model.clone();
    if stop_after == Some(StopAfter::S2) {
        return Ok(stopped(StopAfter::S2));
    }
    let manifest = stages::step3(&mut p, config.step3, &ctx).await?;
    if stop_after == Some(StopAfter::S3) {
        return Ok(stopped(StopAfter::S3));
    }
    let raw_findings_count: i64;
    let chunk_outcomes: BTreeMap<String, appsec_stage_s4::ChunkOutcome>;
    let mut true_positive_count: i64 = 0;
    let mut false_positive_count: i64 = 0;
    let mut duplicate_count: i64 = 0;
    let mut canonical: Vec<Finding>;
    let mut all_dropped: Vec<DroppedFinding> = Vec::new();
    let mut provider_ledger = appsec_model::ProviderLedger {
        full_scan: !input.diff_scope_active,
        resumed: config.resume,
        ..Default::default()
    };
    let diff_scope =
        appsec_model::DiffScope::new(input.diff_scope_active, input.changed_files.keys());
    let mut budget_stop: Option<String> = None;

    'pipeline: {
        let s4_run = StageRun::start(p.progress, Stage4::NAME);
        let s4_checkpoint = p.load::<Step4Checkpoint>("s4");
        let s4_resumed = s4_checkpoint.is_some();
        let deepdive_findings: Vec<Finding> = if let Some(cached) = s4_checkpoint {
            chunk_outcomes = cached
                .outcomes
                .into_iter()
                .map(|(id, outcome)| (id, outcome.into()))
                .collect();
            s4_run.finish(
                p.progress,
                &mut p.stage_timings,
                StageStatus::Cached,
                s4_counts(cached.findings.len(), &chunk_outcomes),
                None,
            );
            cached.findings
        } else {
            let mut step4 = config.step4;
            step4.budget_gate = budget_gate(
                config.spend_cap.as_ref(),
                &p.tracker,
                &p.tokens_by_phase,
                p.scan_start,
                cancel.as_ref(),
            );
            let stage4 = Stage4::new(p.llm.clone(), step4).with_progress(p.progress.cloned());
            let chunks: Vec<Chunk> = manifest.sorted_chunks().into_iter().cloned().collect();
            let deepdive = stage4
                .run(Step4Input {
                    chunks,
                    ctx: ctx.clone(),
                })
                .await?
                .into_value();
            if let Some(reason) = deepdive.budget_stop.clone() {
                budget_stop.get_or_insert(format!("S4: {reason}"));
            }
            p.diag.deepdive = diagnostics::deepdive_counts(&deepdive.diagnostics);
            chunk_outcomes = deepdive.outcomes.clone();
            p.save_live(
                "s4",
                &Step4Checkpoint {
                    findings: deepdive.findings.clone(),
                    outcomes: chunk_outcomes
                        .iter()
                        .map(|(id, outcome)| (id.clone(), (*outcome).into()))
                        .collect(),
                },
            );
            let counts = s4_counts(deepdive.findings.len(), &chunk_outcomes);
            let lost_chunks = counts
                .iter()
                .any(|(name, n)| *name == "chunks_failed" && *n > 0);
            s4_run.finish(
                p.progress,
                &mut p.stage_timings,
                StageStatus::from_degraded(lost_chunks || deepdive.budget_stop.is_some()),
                counts,
                deepdive.budget_stop.as_deref().map(appsec_redact::redact),
            );
            deepdive.findings
        };
        raw_findings_count = deepdive_findings.len() as i64;
        canonical = deepdive_findings.clone();
        p.record_usage("s4", Stage4::NAME);
        appsec_pipeline_core::emit(
            p.progress,
            appsec_pipeline_core::ScanEvent::FindingsCount {
                stage: Stage4::NAME,
                count: deepdive_findings.len(),
            },
        );
        if stop_after == Some(StopAfter::S4) {
            return Ok(stopped(StopAfter::S4));
        }
        if let Some(reason) = boundary_stop(
            cancel.as_ref(),
            config.spend_cap.as_ref(),
            &p.tokens_by_phase,
            p.scan_start,
        ) {
            budget_stop.get_or_insert(format!("{reason}; stopped before S5"));
            all_dropped.extend(unverified_by_budget(&mut canonical, &reason));
            cancellation::skip_stages(
                p.progress,
                &mut p.stage_timings,
                &[Stage5::NAME, Stage6::NAME, Stage7::NAME],
                &reason,
            );
            break 'pipeline;
        }

        let s5_run = StageRun::start(p.progress, Stage5::NAME);
        let s5_checkpoint =
            load_checkpoint::<Step5Checkpoint>(p.checkpoint, s4_resumed, &run_id, "s5");
        let s5_resumed = s5_checkpoint.is_some();
        let (mut prefiltered_findings, prefiltered_dropped): (Vec<Finding>, Vec<DroppedFinding>) =
            if let Some(cached) = s5_checkpoint {
                if cached.degraded {
                    p.note_error("s5");
                }
                s5_run.finish(
                    p.progress,
                    &mut p.stage_timings,
                    StageStatus::Cached,
                    kept_dropped_counts("kept", &cached.findings, &cached.dropped),
                    None,
                );
                (cached.findings, cached.dropped)
            } else {
                let mut step5 = config.step5;
                step5.dedup.budget_gate = budget_gate(
                    config.spend_cap.as_ref(),
                    &p.tracker,
                    &p.tokens_by_phase,
                    p.scan_start,
                    cancel.as_ref(),
                );
                let s5_input = Step5Input {
                    findings: deepdive_findings,
                    ctx: ctx.clone(),
                };
                let (prefiltered, s5_reason, s5_diag) =
                    appsec_stage_s5::run_prefilter_with_diagnostics(
                        p.llm.as_ref(),
                        &s5_input,
                        &step5,
                    )
                    .await;
                p.diag.prefilter = diagnostics::prefilter_counts(&s5_diag);
                let degraded = s5_reason.is_some();
                if degraded {
                    p.note_error("s5");
                    budget_stop = budget_stop
                        .take()
                        .or_else(|| budget_skip_reason("S5", s5_reason.as_deref()));
                }
                p.save_live(
                    "s5",
                    &Step5Checkpoint {
                        findings: prefiltered.findings.clone(),
                        dropped: prefiltered.dropped.clone(),
                        degraded,
                    },
                );
                s5_run.finish(
                    p.progress,
                    &mut p.stage_timings,
                    StageStatus::from_degraded(degraded),
                    kept_dropped_counts("kept", &prefiltered.findings, &prefiltered.dropped),
                    None,
                );
                (prefiltered.findings, prefiltered.dropped)
            };
        provider_ledger.ingestion = gathered.imported.ingestion;
        provider_ledger.assessments = provider_assessment::unassessed(&gathered.imported.findings);
        let (in_scope, out_of_diff_scope) =
            split_provider_findings_by_diff_scope(gathered.imported.findings, &diff_scope);
        let set_aside = out_of_diff_scope.len();
        if set_aside != 0 {
            tracing::info!("[s5] {set_aside} third-party finding(s) are outside the --diff-scope changed-file set; retained in the report as out of scope, not verified and not remediated");
        }
        provider_assessment::mark_out_of_diff_scope(&mut provider_ledger, &out_of_diff_scope);
        all_dropped.extend(out_of_diff_scope.iter().cloned());
        prefiltered_findings.extend(in_scope);
        canonical = prefiltered_findings.clone();
        p.record_usage("s5", Stage5::NAME);
        if stop_after == Some(StopAfter::S5) {
            return Ok(stopped(StopAfter::S5));
        }
        if let Some(reason) = boundary_stop(
            cancel.as_ref(),
            config.spend_cap.as_ref(),
            &p.tokens_by_phase,
            p.scan_start,
        ) {
            budget_stop.get_or_insert(format!("{reason}; stopped before S6"));
            all_dropped.extend(prefiltered_dropped);
            all_dropped.extend(unverified_by_budget(&mut canonical, &reason));
            cancellation::skip_stages(
                p.progress,
                &mut p.stage_timings,
                &[Stage6::NAME, Stage7::NAME],
                &reason,
            );
            break 'pipeline;
        }

        let s6_run = StageRun::start(p.progress, Stage6::NAME);
        let s6_checkpoint =
            load_checkpoint::<Step6Checkpoint>(p.checkpoint, s5_resumed, &run_id, "s6");
        let s6_resumed = s6_checkpoint.is_some();
        let mut s6_status = StageStatus::Cached;
        let mut s6_detail = None;
        let (verified_findings, verified_dropped): (Vec<Finding>, Vec<DroppedFinding>) =
            if let Some(cached) = s6_checkpoint {
                (cached.verified, cached.dropped)
            } else {
                let mut step6 = config.step6;
                step6.budget_gate = budget_gate(
                    config.spend_cap.as_ref(),
                    &p.tracker,
                    &p.tokens_by_phase,
                    p.scan_start,
                    cancel.as_ref(),
                );
                let stage6 = Stage6::new(p.llm.clone(), tools.clone(), step6)
                    .with_progress(p.progress.cloned());
                let s6_input = Step6Input {
                    findings: prefiltered_findings,
                    ctx: ctx.clone(),
                };
                let verified = stage6.run(s6_input).await?.into_value();
                s6_status = StageStatus::from_degraded(verified.budget_stop.is_some());
                s6_detail = verified.budget_stop.as_deref().map(appsec_redact::redact);
                if let Some(reason) = verified.budget_stop.clone() {
                    budget_stop.get_or_insert(format!("S6: {reason}"));
                }
                p.diag.verify = diagnostics::verify_counts(&verified.diagnostics);
                p.save_live(
                    "s6",
                    &Step6Checkpoint {
                        verified: verified.verified.clone(),
                        dropped: verified.dropped.clone(),
                    },
                );
                (verified.verified, verified.dropped)
            };
        provider_assessment::record_verification(
            &mut provider_ledger,
            &verified_findings,
            &verified_dropped,
        );
        provider_assessment::mark_out_of_diff_scope(&mut provider_ledger, &out_of_diff_scope);
        s6_run.finish(
            p.progress,
            &mut p.stage_timings,
            s6_status,
            kept_dropped_counts("verified", &verified_findings, &verified_dropped),
            s6_detail,
        );
        appsec_pipeline_core::emit(
            p.progress,
            appsec_pipeline_core::ScanEvent::FindingsCount {
                stage: Stage6::NAME,
                count: verified_findings.len(),
            },
        );
        p.record_usage("s6", Stage6::NAME);
        if stop_after == Some(StopAfter::S6) {
            return Ok(stopped(StopAfter::S6));
        }

        true_positive_count = verified_findings.len() as i64;
        false_positive_count = verified_dropped
            .iter()
            .filter(|d| d.reason == DropReason::FalsePositive)
            .count() as i64;
        canonical = verified_findings.clone();
        if let Some(reason) = boundary_stop(
            cancel.as_ref(),
            config.spend_cap.as_ref(),
            &p.tokens_by_phase,
            p.scan_start,
        ) {
            budget_stop.get_or_insert(format!("{reason}; stopped before S7"));
            all_dropped.extend(prefiltered_dropped);
            all_dropped.extend(verified_dropped);
            cancellation::skip_stages(p.progress, &mut p.stage_timings, &[Stage7::NAME], &reason);
            break 'pipeline;
        }

        let s7_run = StageRun::start(p.progress, Stage7::NAME);
        let s7_counts = |kept: &[Finding], dropped: &[DroppedFinding]| {
            vec![
                ("canonical", telemetry::count(kept.len())),
                ("dup_dropped", telemetry::count(dropped.len())),
            ]
        };
        let (deduped_findings, deduped_dropped): (Vec<Finding>, Vec<DroppedFinding>) =
            if let Some(cached) =
                load_checkpoint::<Step7Checkpoint>(p.checkpoint, s6_resumed, &run_id, "s7")
            {
                if cached.degraded {
                    p.note_error("s7");
                }
                s7_run.finish(
                    p.progress,
                    &mut p.stage_timings,
                    StageStatus::Cached,
                    s7_counts(&cached.findings, &cached.dropped),
                    None,
                );
                (cached.findings, cached.dropped)
            } else {
                let mut step7 = config.step7;
                step7.budget_gate = budget_gate(
                    config.spend_cap.as_ref(),
                    &p.tracker,
                    &p.tokens_by_phase,
                    p.scan_start,
                    cancel.as_ref(),
                );
                let stage7 = Stage7::new(p.llm.clone(), step7);
                let s7_outcome = stage7
                    .run(Step7Input {
                        findings: verified_findings,
                        ctx: ctx.clone(),
                    })
                    .await?;
                let degraded = s7_outcome.is_degraded();
                if degraded {
                    p.note_error("s7");
                    budget_stop = budget_stop
                        .take()
                        .or_else(|| budget_skip_reason("S7", s7_outcome.reason()));
                }
                let deduped = s7_outcome.into_value();
                p.save_live(
                    "s7",
                    &Step7Checkpoint {
                        findings: deduped.findings.clone(),
                        dropped: deduped.dropped.clone(),
                        degraded,
                    },
                );
                s7_run.finish(
                    p.progress,
                    &mut p.stage_timings,
                    StageStatus::from_degraded(degraded),
                    s7_counts(&deduped.findings, &deduped.dropped),
                    None,
                );
                (deduped.findings, deduped.dropped)
            };
        duplicate_count = deduped_dropped.len() as i64;
        appsec_pipeline_core::emit(
            p.progress,
            appsec_pipeline_core::ScanEvent::FindingsCount {
                stage: Stage7::NAME,
                count: deduped_findings.len(),
            },
        );
        p.record_usage("s7", Stage7::NAME);

        all_dropped.extend(prefiltered_dropped);
        all_dropped.extend(verified_dropped);
        all_dropped.extend(deduped_dropped);
        canonical = deduped_findings;

        appsec_enrich::enrich_findings(&mut canonical, gathered.app_info.as_ref());

        appsec_compliance::apply_to_findings(&input.compliance, &mut canonical, &mut all_dropped);

        if stop_after == Some(StopAfter::S7) {
            return Ok(stopped(StopAfter::S7));
        }
    }

    let end_ts = appsec_metrics::now_iso();
    let canceled_at_report = p.canceled();
    let diag = std::mem::take(&mut p.diag);
    let mut metrics = build_metrics(
        &ctx,
        &manifest,
        &input.repo_root,
        &input.repo_name,
        &scan_uuid,
        &start_ts,
        &end_ts,
        raw_findings_count,
        true_positive_count,
        false_positive_count,
        duplicate_count,
        &chunk_outcomes,
        &p.tokens_by_phase,
        p.tracker.unpriced_models.snapshot(),
        std::mem::take(&mut p.errors_by_stage),
        budget_stop,
    );
    metrics.pipeline_diagnostics = diag;
    cancellation::mark_canceled(&mut metrics, canceled_at_report);

    let s8_run = StageRun::start(p.progress, Stage8::NAME);
    let stage8 = Stage8::new(
        cancellation::CancelAwareClient::wrap(p.llm.clone(), cancel.clone()),
        config.step8,
    );
    let s8_input = Step8Input {
        findings: canonical,
        ctx: ctx.clone(),
        dropped: all_dropped,
        raw_findings_count,
        metrics: Some(metrics),
    };
    let s8_outcome = stage8.run(s8_input).await?;
    let s8_degraded = s8_outcome.is_degraded();
    let mut report = s8_outcome.into_value();
    let s8_usage = p.tracker.take();
    record_usage(
        &mut p.tokens_by_phase,
        p.progress,
        "s8",
        Stage8::NAME,
        s8_usage,
    );
    s8_run.finish(
        p.progress,
        &mut p.stage_timings,
        StageStatus::from_degraded(s8_degraded),
        vec![
            ("findings", telemetry::count(report.findings.len())),
            ("chains", telemetry::count(report.chains.len())),
        ],
        None,
    );
    if let Some(metrics) = report.metrics.as_mut() {
        metrics.llm_truncated_replies += s8_usage.truncated_replies as i64;
        metrics.stage_timings = p.stage_timings;
    }
    appsec_pipeline_core::emit(
        p.progress,
        appsec_pipeline_core::ScanEvent::FindingsCount {
            stage: Stage8::NAME,
            count: report.findings.len(),
        },
    );
    provider_ledger.analysis_complete = !report.degraded
        && report
            .metrics
            .as_ref()
            .is_some_and(|m| m.errors_by_stage.is_empty() && m.budget_stop.is_empty());
    report.provider_ledger = provider_ledger;
    report.repo_name = Some(input.repo_name.clone());
    report.threat_model = threat_model;
    report.app_profile = gathered.app_profile;
    if config.emit_unreachable_appendix {
        report.unreachable_files = manifest.unreachable_files.clone();
    }
    report.git_sha = input
        .git_sha_override
        .clone()
        .or_else(|| head_sha(&input.repo_root));
    report.repo_identity = Some(appsec_repo_identity::resolve(
        &input.repo_root,
        &appsec_repo_identity::Overrides {
            repo_key: input.repo_key_override.as_deref(),
            env_repo_key: input.repo_key_env.as_deref(),
            branch: input.branch_override.as_deref(),
            base_ref: input.base_ref.as_deref(),
        },
    ));

    if stop_after == Some(StopAfter::S8) {
        return Ok(ScanOutcome {
            provider_writeback_plan: None,
            stopped_after: Some(StopAfter::S8),
            report: Some(reporting::redact_report(&report)?),
            markdown: None,
            sarif: None,
        });
    }

    let s9_run = StageRun::start(p.progress, Stage9::NAME);
    let rendered = Stage9 {
        tool_version: config.tool_version.clone(),
    }
    .run(report)
    .await?
    .into_value();
    s9_run.finish(
        p.progress,
        &mut telemetry::StageTimings::new(),
        StageStatus::Completed,
        vec![("findings", telemetry::count(rendered.report.findings.len()))],
        None,
    );
    Ok(ScanOutcome {
        provider_writeback_plan: Some(rendered.provider_writeback_plan),
        stopped_after: (stop_after == Some(StopAfter::S9)).then_some(StopAfter::S9),
        report: Some(rendered.report),
        markdown: Some(rendered.markdown),
        sarif: Some(rendered.sarif),
    })
}

#[cfg(test)]
mod tests;
