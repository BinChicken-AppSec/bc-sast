use std::collections::BTreeMap;
use std::sync::Arc;

use appsec_checkpoint::CheckpointStore;
use appsec_llm_client::LlmClient;
use appsec_model::{ContextPackage, TaskManifest};
use appsec_pipeline_core::{PipelineStage, StageError, StageStatus};
use appsec_stage_s0::{Stage0, Step0Config, Step0Input};
use appsec_stage_s3::{Stage3, Step3Config, Step3Input};
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::checkpoints::{
    load_checkpoint, record_usage, save_checkpoint, Step1Checkpoint, Step2Checkpoint,
    Step3Checkpoint,
};
use crate::telemetry::{self, StageRun};
use crate::usage::{PhaseUsage, UsageTrackingClient};
use crate::{cancellation, diagnostics};

pub(crate) struct Pipeline<'a> {
    pub(crate) llm: Arc<dyn LlmClient>,
    pub(crate) tracker: Arc<UsageTrackingClient>,
    pub(crate) progress: Option<&'a appsec_pipeline_core::ProgressSink>,
    pub(crate) checkpoint: Option<&'a dyn CheckpointStore>,
    pub(crate) cancel: Option<appsec_pipeline_core::CancelTokenRef>,
    pub(crate) run_id: String,
    pub(crate) resume: bool,
    pub(crate) scan_start: std::time::Instant,
    pub(crate) stage_timings: telemetry::StageTimings,
    pub(crate) tokens_by_phase: BTreeMap<String, PhaseUsage>,
    pub(crate) errors_by_stage: BTreeMap<String, i64>,
    pub(crate) diag: appsec_model::PipelineDiagnostics,
}

impl Pipeline<'_> {
    pub(crate) fn canceled(&self) -> Option<String> {
        appsec_pipeline_core::canceled(self.cancel.as_ref())
    }

    pub(crate) fn live_checkpoint(&self) -> Option<&dyn CheckpointStore> {
        self.checkpoint.filter(|_| self.canceled().is_none())
    }

    pub(crate) fn note_error(&mut self, stage: &str) {
        self.errors_by_stage.insert(stage.to_string(), 1);
    }

    pub(crate) fn record_usage(&mut self, key: &str, stage: &'static str) {
        let usage = self.tracker.take();
        record_usage(&mut self.tokens_by_phase, self.progress, key, stage, usage);
    }

    pub(crate) fn load<T: DeserializeOwned>(&self, step: &str) -> Option<T> {
        load_checkpoint(self.checkpoint, self.resume, &self.run_id, step)
    }

    pub(crate) fn save<T: Serialize>(&self, step: &str, value: &T) {
        save_checkpoint(self.checkpoint, &self.run_id, step, value);
    }

    pub(crate) fn save_live<T: Serialize>(&self, step: &str, value: &T) {
        save_checkpoint(self.live_checkpoint(), &self.run_id, step, value);
    }
}

pub(crate) async fn step0(
    p: &mut Pipeline<'_>,
    mut step0: Step0Config,
    walk: appsec_repo_analysis::WalkConfig,
    enabled: bool,
    repo_root: &std::path::Path,
) -> Result<Option<appsec_stage_s0::SeedPackage>, StageError> {
    let skip = p
        .canceled()
        .or_else(|| (!enabled).then(|| "disabled in config".to_string()));
    if let Some(reason) = skip {
        telemetry::record_unstarted(
            p.progress,
            &mut p.stage_timings,
            Stage0::NAME,
            StageStatus::Skipped,
            Some(reason),
        );
        return Ok(None);
    }
    let run = StageRun::start(p.progress, Stage0::NAME);
    step0.walk = walk;
    let stage = Stage0::new(step0, Some(p.llm.clone()));
    let outcome = stage
        .run(Step0Input {
            repo_root: repo_root.to_path_buf(),
        })
        .await?
        .into_value();
    p.record_usage("s0", Stage0::NAME);
    run.finish(
        p.progress,
        &mut p.stage_timings,
        StageStatus::Completed,
        vec![
            ("entry_points", telemetry::count(outcome.entry_points.len())),
            ("sinks", telemetry::count(outcome.unsafe_sinks.len())),
        ],
        None,
    );
    Ok(Some(outcome))
}

pub(crate) async fn step3(
    p: &mut Pipeline<'_>,
    config: Step3Config,
    ctx: &ContextPackage,
) -> Result<TaskManifest, StageError> {
    let manifest = if let Some(reason) = p.canceled() {
        cancellation::skip_stages(p.progress, &mut p.stage_timings, &[Stage3::NAME], &reason);
        cancellation::empty_manifest()
    } else {
        let run = StageRun::start(p.progress, Stage3::NAME);
        if let Some(cached) = p.load::<Step3Checkpoint>("s3") {
            if cached.degraded {
                p.note_error("s3");
            }
            run.finish(
                p.progress,
                &mut p.stage_timings,
                StageStatus::Cached,
                vec![("chunks", telemetry::count(cached.manifest.chunks.len()))],
                None,
            );
            cached.manifest
        } else {
            let stage = Stage3::new(p.llm.clone(), config);
            let (outcome, diag) = stage
                .run_with_diagnostics(Step3Input { ctx: ctx.clone() })
                .await?;
            p.diag.decompose = diagnostics::decompose_counts(&diag);
            let degraded = outcome.is_degraded();
            if degraded {
                p.note_error("s3");
            }
            let manifest = outcome.into_value();
            p.save(
                "s3",
                &Step3Checkpoint {
                    manifest: manifest.clone(),
                    degraded,
                },
            );
            run.finish(
                p.progress,
                &mut p.stage_timings,
                StageStatus::from_degraded(degraded),
                vec![("chunks", telemetry::count(manifest.chunks.len()))],
                None,
            );
            manifest
        }
    };
    p.record_usage("s3", Stage3::NAME);
    Ok(manifest)
}

pub(crate) async fn step1(
    p: &mut Pipeline<'_>,
    config: appsec_stage_s1::Step1Config,
    tools: Arc<dyn appsec_llm_client::ToolExecutor>,
    input: &crate::ScanInput,
    seed: Option<appsec_stage_s0::SeedPackage>,
    provider_digest: appsec_model::ProviderDigest,
) -> Result<ContextPackage, StageError> {
    use appsec_stage_s1::{Stage1, Step1Input};

    if let Some(reason) = p.canceled() {
        cancellation::skip_stages(p.progress, &mut p.stage_timings, &[Stage1::NAME], &reason);
        let ctx = cancellation::empty_context(&input.repo_root);
        p.record_usage("s1", Stage1::NAME);
        return Ok(ctx);
    }
    let run = StageRun::start(p.progress, Stage1::NAME);
    let ctx = if let Some(cached) = p.load::<Step1Checkpoint>("s1") {
        if cached.degraded {
            p.note_error("s1");
        }
        run.finish(
            p.progress,
            &mut p.stage_timings,
            StageStatus::Cached,
            vec![("files", telemetry::count(cached.ctx.all_files.len()))],
            None,
        );
        cached.ctx
    } else {
        let stage = Stage1::new(p.llm.clone(), tools, config);
        let outcome = stage
            .run(Step1Input {
                repo_root: input.repo_root.clone(),
                provider_digest,
                changed_files: input.changed_files.clone(),
                diff_scope_active: input.diff_scope_active,
                compliance_guidance: appsec_compliance::combined_guidance(&input.compliance),
                seed,
            })
            .await?;
        let degraded = outcome.is_degraded();
        if degraded {
            p.note_error("s1");
        }
        let ctx = outcome.into_value();
        p.save(
            "s1",
            &Step1Checkpoint {
                ctx: ctx.clone(),
                degraded,
            },
        );
        run.finish(
            p.progress,
            &mut p.stage_timings,
            StageStatus::from_degraded(degraded),
            vec![("files", telemetry::count(ctx.all_files.len()))],
            None,
        );
        ctx
    };
    p.record_usage("s1", Stage1::NAME);
    Ok(ctx)
}

pub(crate) async fn step2(
    p: &mut Pipeline<'_>,
    config: appsec_stage_s2::Step2Config,
    enabled: bool,
    tools: Arc<dyn appsec_llm_client::ToolExecutor>,
    input: &crate::ScanInput,
    ctx: &ContextPackage,
    app_profile: Option<appsec_model::AppProfile>,
) -> Option<appsec_model::ThreatModel> {
    use appsec_stage_s2::{Stage2, Step2Input};

    let threat_model = if let Some(reason) = p.canceled() {
        cancellation::skip_stages(p.progress, &mut p.stage_timings, &[Stage2::NAME], &reason);
        None
    } else if !enabled {
        telemetry::record_unstarted(
            p.progress,
            &mut p.stage_timings,
            Stage2::NAME,
            StageStatus::Skipped,
            Some("disabled in config".to_string()),
        );
        None
    } else {
        let s2_run = StageRun::start(p.progress, Stage2::NAME);
        if let Some(cached) = p.load::<Step2Checkpoint>("s2") {
            if cached.degraded {
                p.note_error("s2");
            }
            s2_run.finish(
                p.progress,
                &mut p.stage_timings,
                StageStatus::Cached,
                crate::metrics::threat_model_counts(cached.threat_model.as_ref()),
                None,
            );
            cached.threat_model
        } else {
            let stage2 = Stage2::new(p.llm.clone(), config).with_tools(tools);
            let s2_input = Step2Input {
                repo_root: input.repo_root.clone(),
                repo_name: input.repo_name.clone(),
                ctx: ctx.clone(),
                app_profile: app_profile.clone(),
                provider_digest: ctx.provider_digest.clone().unwrap_or_default(),
            };
            let s2_result = stage2.run_detailed(s2_input).await;
            let degraded = s2_result.is_err();
            if degraded {
                p.note_error("s2");
            }
            let (status, detail) = match &s2_result {
                Ok(_) => (StageStatus::Completed, None),
                Err(e) => (
                    StageStatus::Error,
                    Some(appsec_redact::redact(&e.to_string())),
                ),
            };
            let (threat_model, s2_diag) = match s2_result {
                Ok((tm, diag)) => (Some(tm), diag),
                Err(_) => (None, appsec_stage_s2::ThreatModelDiagnostics::default()),
            };
            p.diag.threat_model = diagnostics::threat_model_counts(
                &s2_diag,
                threat_model.as_ref().is_none_or(|tm| tm.threats.is_empty()),
            );
            if !degraded
                && threat_model
                    .as_ref()
                    .is_some_and(crate::metrics::threat_model_has_content)
            {
                p.save(
                    "s2",
                    &Step2Checkpoint {
                        threat_model: threat_model.clone(),
                        degraded,
                    },
                );
            }
            s2_run.finish(
                p.progress,
                &mut p.stage_timings,
                status,
                crate::metrics::threat_model_counts(threat_model.as_ref()),
                detail,
            );
            threat_model
        }
    };
    p.record_usage("s2", Stage2::NAME);
    threat_model
}
