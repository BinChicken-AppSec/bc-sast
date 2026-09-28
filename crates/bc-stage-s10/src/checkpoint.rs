//! S10's `--resume` checkpoints: the step key, the payload, and loading
//! and saving it. Ported from `remediation_agent/runner.py::remediate_one`'s
//! `_finding_identity` check plus `orchestrator/checkpoints.py::
//! step_key_for` (vvaharness v1.3.0).
//!
//! **What changed.** The step used to be `remediate_<index>`, validated
//! only by the finding's content hash, so a checkpoint written under one
//! model was served as the result of a run under another. The key now
//! also hashes the engine that produced the record
//! ([`bc_checkpoint::EngineKey`]: this stage, this release, the model, the
//! API dialect and the gateway host), and the payload carries the same
//! engine fields so a row whose key somehow matched is still refused if
//! they differ. Rows under the old key format are never found again and
//! are cleared by [`bc_checkpoint::CheckpointStore::prune_stale`].

use bc_checkpoint::{CheckpointStore, EngineKey};
use bc_model::RankedFinding;
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};

use crate::{render_finding_body, RemediationRecord, Step10Config};

/// The prefix every S10 checkpoint step starts with, and what a prune
/// sweeps.
pub const REMEDIATE_STEP_PREFIX: &str = "remediate_";

/// This stage's engine id, hashed into every step key.
const ENGINE_ID: &str = "bc-sast.s10";

/// A stable content identity for one finding at one position, ported
/// from `remediation_agent/runner.py::_finding_identity`: SHA-1 (not
/// Python's SHA-256; see [`bc_checkpoint::step_key_for`] for why) hex
/// digest of `finding_index`, `title`, `file`, and the finding's rendered
/// body, NUL-separated. Not a security control, just staleness detection
/// for `--resume`: a rescan that reorders or replaces findings must not
/// silently reuse a checkpoint for a different one.
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
    /// The producer identity this configuration's results are
    /// checkpointed under. The model comes from [`Self::model`] itself
    /// (never a copy of it), so a `--config` override applied after
    /// construction is always the model that is keyed.
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

/// The checkpoint step for this finding under this configuration.
pub fn remediation_step_key(
    config: &Step10Config,
    finding_index: i64,
    finding: &RankedFinding,
) -> String {
    bc_checkpoint::step_key_for(
        REMEDIATE_STEP_PREFIX,
        &config.engine_key(),
        &finding_identity(finding_index, finding),
    )
}

/// The engine half of a payload, a serde mirror of [`EngineKey`] (which
/// lives in a crate with no serde dependency).
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

/// The on-disk shape of one checkpoint. `engine` is optional only so a
/// payload written before it existed still deserializes, and is then
/// refused as a mismatch rather than trusted.
#[derive(Serialize, Deserialize)]
struct CheckpointPayload {
    finding_id: String,
    #[serde(default)]
    engine: Option<EngineRecord>,
    record: RemediationRecord,
}

/// The cached record for `step`, or `None` on a miss, an unparseable
/// payload, a different finding (`fid`), or a different engine.
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

/// Saves `record` under `step`. The diff goes through
/// [`bc_redact::redact_diff`] first: a checkpoint is a file on disk that
/// outlives the run, and the diff of a hardcoded-secret fix contains the
/// secret it removed. Everything a resumed record is used for (S11, the
/// report, `--out-remediation-json`) already receives the redacted diff.
/// Failures are swallowed, matching `save_ckpt`'s log-and-continue
/// posture: a checkpoint is a resume convenience, never a correctness
/// requirement of the current run.
pub(crate) fn save_checkpoint(
    store: &dyn CheckpointStore,
    run_id: &str,
    step: &str,
    fid: &str,
    config: &Step10Config,
    record: &RemediationRecord,
) {
    let mut record = record.clone();
    record.diff = record.diff.as_deref().map(bc_redact::redact_diff);
    let payload = CheckpointPayload {
        finding_id: fid.to_string(),
        engine: Some(config.engine_key().into()),
        record,
    };
    let bytes = serde_json::to_vec(&payload).expect("CheckpointPayload always serializes");
    let _ = store.save(run_id, step, &bytes);
}

/// `true` iff `checkpoint` already holds a record for this finding, under
/// this configuration's engine, whose identity matches the finding as it
/// stands now. Exposed for UIs (the `-i` picker) that show a finding's
/// done/pending status regardless of whether this run uses `--resume`.
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
