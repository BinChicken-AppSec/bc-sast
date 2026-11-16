use super::*;
pub(super) fn load_checkpoint<T: DeserializeOwned>(
    checkpoint: Option<&dyn CheckpointStore>,
    resume: bool,
    run_id: &str,
    step: &str,
) -> Option<T> {
    if !resume {
        return None;
    }
    let bytes = checkpoint?.load(run_id, step)?;
    serde_json::from_slice(&bytes).ok()
}

pub(super) fn save_checkpoint<T: Serialize>(
    checkpoint: Option<&dyn CheckpointStore>,
    run_id: &str,
    step: &str,
    value: &T,
) {
    let Some(store) = checkpoint else {
        return;
    };
    if let Ok(bytes) = serde_json::to_vec(value) {
        let _ = store.save(run_id, step, &bytes);
    }
}

pub(super) fn record_usage(
    tokens_by_phase: &mut BTreeMap<String, PhaseUsage>,
    progress: Option<&appsec_pipeline_core::ProgressSink>,
    checkpoint_key: &str,
    stage: &'static str,
    usage: PhaseUsage,
) {
    tokens_by_phase.insert(checkpoint_key.to_string(), usage);
    appsec_pipeline_core::emit(
        progress,
        appsec_pipeline_core::ScanEvent::UsageUpdate {
            stage,
            usage: stage_usage(usage),
        },
    );
}

#[derive(Serialize, Deserialize)]
pub(super) struct Step1Checkpoint {
    pub(super) ctx: ContextPackage,
    pub(super) degraded: bool,
}

#[derive(Serialize, Deserialize)]
pub(super) struct Step2Checkpoint {
    pub(super) threat_model: Option<appsec_model::ThreatModel>,
    pub(super) degraded: bool,
}

#[derive(Serialize, Deserialize)]
pub(super) struct Step3Checkpoint {
    pub(super) manifest: TaskManifest,
    pub(super) degraded: bool,
}

#[derive(Serialize, Deserialize)]
pub(super) struct Step4Checkpoint {
    pub(super) findings: Vec<Finding>,
    #[serde(default)]
    pub(super) outcomes: BTreeMap<String, CheckpointChunkOutcome>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum CheckpointChunkOutcome {
    Completed,
    Error,
    Guardrail,
    Skipped,
}

impl From<appsec_stage_s4::ChunkOutcome> for CheckpointChunkOutcome {
    fn from(outcome: appsec_stage_s4::ChunkOutcome) -> Self {
        match outcome {
            appsec_stage_s4::ChunkOutcome::Completed => CheckpointChunkOutcome::Completed,
            appsec_stage_s4::ChunkOutcome::Error => CheckpointChunkOutcome::Error,
            appsec_stage_s4::ChunkOutcome::Guardrail => CheckpointChunkOutcome::Guardrail,
            appsec_stage_s4::ChunkOutcome::Skipped => CheckpointChunkOutcome::Skipped,
        }
    }
}

impl From<CheckpointChunkOutcome> for appsec_stage_s4::ChunkOutcome {
    fn from(outcome: CheckpointChunkOutcome) -> Self {
        match outcome {
            CheckpointChunkOutcome::Completed => appsec_stage_s4::ChunkOutcome::Completed,
            CheckpointChunkOutcome::Error => appsec_stage_s4::ChunkOutcome::Error,
            CheckpointChunkOutcome::Guardrail => appsec_stage_s4::ChunkOutcome::Guardrail,
            CheckpointChunkOutcome::Skipped => appsec_stage_s4::ChunkOutcome::Skipped,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub(super) struct Step5Checkpoint {
    pub(super) findings: Vec<Finding>,
    pub(super) dropped: Vec<DroppedFinding>,
    pub(super) degraded: bool,
}

#[derive(Serialize, Deserialize)]
pub(super) struct Step6Checkpoint {
    pub(super) verified: Vec<Finding>,
    pub(super) dropped: Vec<DroppedFinding>,
}

#[derive(Serialize, Deserialize)]
pub(super) struct Step7Checkpoint {
    pub(super) findings: Vec<Finding>,
    pub(super) dropped: Vec<DroppedFinding>,
    pub(super) degraded: bool,
}
