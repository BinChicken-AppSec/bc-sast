use appsec_checkpoint::{CheckpointStore, EngineKey};
use appsec_model::RankedFinding;
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};

use crate::{render_finding_body, RemediationRecord, Step10Config};

pub const REMEDIATE_STEP_PREFIX: &str = "remediate_";

const ENGINE_ID: &str = "bc-sast.s10";

pub fn finding_identity(finding_index: i64, finding: &RankedFinding) -> String {
    let mut hasher = Sha1::new();
    for part in [
        finding_index.to_string(),
        finding.finding.title.clone(),
        finding.finding.file.clone(),
        render_finding_body(finding),
    ] {
        hasher.update(part.as_bytes());
        hasher.update([0u8]);
    }
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

impl Step10Config {
    pub fn engine_key(&self) -> EngineKey {
        EngineKey {
            engine_id: ENGINE_ID.to_string(),
            engine_version: env!("CARGO_PKG_VERSION").to_string(),
            model: self.model.clone(),
            dialect: self.dialect.clone(),
            base_host: self.base_host.clone(),
        }
    }
}

pub fn remediation_step_key(
    config: &Step10Config,
    finding_index: i64,
    finding: &RankedFinding,
) -> String {
    appsec_checkpoint::step_key_for(
        REMEDIATE_STEP_PREFIX,
        &config.engine_key(),
        &finding_identity(finding_index, finding),
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct EngineRecord {
    engine_id: String,
    engine_version: String,
    model: String,
    dialect: String,
    base_host: String,
}

impl From<EngineKey> for EngineRecord {
    fn from(k: EngineKey) -> Self {
        EngineRecord {
            engine_id: k.engine_id,
            engine_version: k.engine_version,
            model: k.model,
            dialect: k.dialect,
            base_host: k.base_host,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct CheckpointPayload {
    finding_id: String,
    #[serde(default)]
    engine: Option<EngineRecord>,
    record: RemediationRecord,
}

pub(crate) fn load_cached_record(
    store: &dyn CheckpointStore,
    run_id: &str,
    step: &str,
    fid: &str,
    config: &Step10Config,
) -> Option<RemediationRecord> {
    let bytes = store.load(run_id, step)?;
    let payload: CheckpointPayload = serde_json::from_slice(&bytes).ok()?;
    let engine = Some(EngineRecord::from(config.engine_key()));
    (payload.finding_id == fid && payload.engine == engine).then_some(payload.record)
}

pub(crate) fn save_checkpoint(
    store: &dyn CheckpointStore,
    run_id: &str,
    step: &str,
    fid: &str,
    config: &Step10Config,
    record: &RemediationRecord,
) {
    let mut record = record.clone();
    record.diff = record.diff.as_deref().map(appsec_redact::redact_diff);
    let payload = CheckpointPayload {
        finding_id: fid.to_string(),
        engine: Some(config.engine_key().into()),
        record,
    };
    let bytes = serde_json::to_vec(&payload).expect("CheckpointPayload always serializes");
    let _ = store.save(run_id, step, &bytes);
}

pub fn checkpoint_done(
    checkpoint: Option<&dyn CheckpointStore>,
    run_id: &str,
    config: &Step10Config,
    finding_index: i64,
    finding: &RankedFinding,
) -> bool {
    let Some(store) = checkpoint else {
        return false;
    };
    let step = remediation_step_key(config, finding_index, finding);
    let fid = finding_identity(finding_index, finding);
    load_cached_record(store, run_id, &step, &fid, config).is_some()
}
