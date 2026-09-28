//! S11 `--resume` checkpoints. Python checkpoints every validated case
//! (`validate_<digest>` steps, `orchestrator/checkpoints.py`); this port
//! had none, so a resumed run re-ran the whole persona panel for every
//! fix, paying for two or three agentic sessions per finding to recompute
//! a score it already had.
//!
//! The step is engine-keyed ([`bc_checkpoint::step_key_for`]) over the
//! finding id, a digest of the diff the panel judged, and every persona
//! model plus the panel's shape (cross-repo persona on or off, fact tools
//! on or off), so a changed fix, a changed model or a changed panel never
//! reuses an old score. The payload is a serde mirror of
//! [`ValidationScore`] (whose crate deliberately has no serde), with every
//! free-text field redacted before it is written.

use bc_checkpoint::{CheckpointStore, EngineKey};
use bc_stage_s10::RemediationRecord;
use bc_validation_scoring::{
    Evidence, FixVerdict, GateName, GateResult, GateStatus, SynthesisConfidence, ValidationScore,
};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};

use crate::Step11Config;

/// The prefix every S11 checkpoint step starts with, and what a prune
/// sweeps.
pub const VALIDATE_STEP_PREFIX: &str = "validate_";

/// This stage's engine id, hashed into every step key.
const ENGINE_ID: &str = "bc-sast.s11";

impl Step11Config {
    /// The producer identity this panel's scores are checkpointed under.
    /// The "model" is the whole panel: each persona's effective model and
    /// whether the optional persona and the fact tools took part.
    pub fn engine_key(&self) -> EngineKey {
        let persona = |m: &Option<String>| m.clone().unwrap_or_else(|| self.model.clone());
        let cross_repo = if self.cross_repo_analyzer {
            persona(&self.cross_repo_analyzer_model)
        } else {
            "off".to_string()
        };
        EngineKey {
            engine_id: ENGINE_ID.to_string(),
            engine_version: env!("CARGO_PKG_VERSION").to_string(),
            model: format!(
                "security-architect={};penetration-tester={};cross-repo-analyzer={cross_repo};\
                 fact-tools={};split-ties-score={}",
                persona(&self.security_architect_model),
                persona(&self.penetration_tester_model),
                self.fact_tools,
                self.split_ties_score,
            ),
            dialect: self.dialect.clone(),
            base_host: self.base_host.clone(),
        }
    }
}

/// The checkpoint step for validating `record` under `config`. The diff
/// is digested in its redacted form, which is exactly what the panel
/// sees (see `crate::validate_finding`).
pub fn validation_step_key(config: &Step11Config, record: &RemediationRecord) -> String {
    let diff = bc_redact::redact_diff(record.diff.as_deref().unwrap_or(""));
    let diff_digest: String = Sha1::digest(diff.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    bc_checkpoint::step_key_for(
        VALIDATE_STEP_PREFIX,
        &config.engine_key(),
        &format!("{}\n{diff_digest}", record.finding_id),
    )
}

#[derive(Debug, Serialize, Deserialize)]
struct EvidenceRecord {
    file: String,
    line: Option<i64>,
    snippet: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct GateRecord {
    gate_name: String,
    status: String,
    summary: String,
    evidence: Vec<EvidenceRecord>,
    details: String,
    confidence: Option<String>,
}

/// The serde mirror of [`ValidationScore`].
#[derive(Debug, Serialize, Deserialize)]
struct ScoreRecord {
    raw_score: f64,
    fix_status: String,
    justification: String,
    gate_results: Vec<GateRecord>,
    has_critical_failure: bool,
}

impl ScoreRecord {
    /// The persisted form of `score`, every free-text field redacted: a
    /// checkpoint is a file that outlives the run, and a justification can
    /// quote what a persona read.
    fn redacted(score: &ValidationScore) -> Self {
        ScoreRecord {
            raw_score: score.raw_score,
            fix_status: score.fix_status.as_str().to_string(),
            justification: bc_redact::redact(&score.justification),
            gate_results: score
                .gate_results
                .iter()
                .map(|g| GateRecord {
                    gate_name: g.gate_name.as_str().to_string(),
                    status: g.status.as_str().to_string(),
                    summary: bc_redact::redact(&g.summary),
                    evidence: g
                        .evidence
                        .iter()
                        .map(|e| EvidenceRecord {
                            file: e.file.clone(),
                            line: e.line,
                            snippet: bc_redact::redact(&e.snippet),
                        })
                        .collect(),
                    details: bc_redact::redact(&g.details),
                    confidence: g.confidence.map(|c| c.as_str().to_string()),
                })
                .collect(),
            has_critical_failure: score.has_critical_failure,
        }
    }

    /// Back to a [`ValidationScore`]; `None` when any label is not one
    /// this build knows, so a corrupt or foreign row is a miss, never a
    /// guess.
    fn into_score(self) -> Option<ValidationScore> {
        let gate_results = self
            .gate_results
            .into_iter()
            .map(|g| {
                let confidence = match g.confidence {
                    Some(label) => Some(SynthesisConfidence::parse(&label)?),
                    None => None,
                };
                Some(GateResult {
                    gate_name: GateName::parse(&g.gate_name)?,
                    status: GateStatus::parse(&g.status),
                    summary: g.summary,
                    evidence: g
                        .evidence
                        .into_iter()
                        .map(|e| Evidence {
                            file: e.file,
                            line: e.line,
                            snippet: e.snippet,
                        })
                        .collect(),
                    details: g.details,
                    confidence,
                })
            })
            .collect::<Option<Vec<_>>>()?;
        Some(ValidationScore {
            raw_score: self.raw_score,
            fix_status: FixVerdict::parse(&self.fix_status)?,
            justification: self.justification,
            gate_results,
            has_critical_failure: self.has_critical_failure,
        })
    }
}

/// The cached score for `step`, or `None` on a miss or an unusable row.
pub(crate) fn load_score(
    store: &dyn CheckpointStore,
    run_id: &str,
    step: &str,
) -> Option<ValidationScore> {
    let bytes = store.load(run_id, step)?;
    serde_json::from_slice::<ScoreRecord>(&bytes)
        .ok()?
        .into_score()
}

/// Saves `score` under `step`, redacted. Best effort: a failed write never
/// fails the validation it records.
pub(crate) fn save_score(
    store: &dyn CheckpointStore,
    run_id: &str,
    step: &str,
    score: &ValidationScore,
) {
    let bytes =
        serde_json::to_vec(&ScoreRecord::redacted(score)).expect("ScoreRecord always serializes");
    let _ = store.save(run_id, step, &bytes);
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_checkpoint::SqliteCheckpointStore;

    fn score() -> ValidationScore {
        ValidationScore {
            raw_score: 0.75,
            fix_status: FixVerdict::PartiallyFixed,
            justification: "token = \"abcdefghijklmnop\" still present".to_string(),
            gate_results: vec![GateResult {
                gate_name: GateName::RootCause,
                status: GateStatus::Partial,
                summary: "s".to_string(),
                evidence: vec![Evidence {
                    file: "a.py".to_string(),
                    line: Some(3),
                    snippet: "x".to_string(),
                }],
                details: "d".to_string(),
                confidence: Some(SynthesisConfidence::Split),
            }],
            has_critical_failure: true,
        }
    }

    fn store() -> (tempfile::TempDir, SqliteCheckpointStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteCheckpointStore::new(dir.path().join("state.db")).unwrap();
        (dir, store)
    }

    #[test]
    fn a_saved_score_round_trips_with_its_prose_redacted() {
        let (_dir, store) = store();
        save_score(&store, "run1", "validate_x", &score());
        let loaded = load_score(&store, "run1", "validate_x").unwrap();
        let mut expected = score();
        expected.justification = bc_redact::redact(&expected.justification);
        assert_eq!(loaded, expected);
        assert!(!loaded.justification.contains("abcdefghijklmnop"));
    }

    #[test]
    fn an_unknown_label_or_garbage_is_a_miss() {
        let (_dir, store) = store();
        assert!(load_score(&store, "run1", "missing").is_none());
        store.save("run1", "garbage", b"not json").unwrap();
        assert!(load_score(&store, "run1", "garbage").is_none());
        for (field, value) in [
            ("fix_status", "Mostly Fixed"),
            ("gate_name", "vibes"),
            ("confidence", "LOW"),
        ] {
            let mut json = serde_json::to_value(ScoreRecord::redacted(&score())).unwrap();
            match field {
                "fix_status" => json[field] = value.into(),
                _ => json["gate_results"][0][field] = value.into(),
            }
            store
                .save("run1", field, json.to_string().as_bytes())
                .unwrap();
            assert!(load_score(&store, "run1", field).is_none(), "{field}");
        }
        let mut json = serde_json::to_value(ScoreRecord::redacted(&score())).unwrap();
        json["gate_results"][0]["confidence"] = serde_json::Value::Null;
        store
            .save("run1", "no-confidence", json.to_string().as_bytes())
            .unwrap();
        assert_eq!(
            load_score(&store, "run1", "no-confidence")
                .unwrap()
                .gate_results[0]
                .confidence,
            None
        );
    }

    fn record(diff: Option<&str>) -> RemediationRecord {
        RemediationRecord {
            finding_index: 1,
            finding_id: "fid".to_string(),
            verdict: bc_stage_s10::RemediationVerdict::denied(1, "x"),
            policy_action: None,
            policy_reason: None,
            final_verdict: None,
            policy_reverted: Vec::new(),
            policy_matched_globs: Vec::new(),
            diff: diff.map(str::to_string),
        }
    }

    #[test]
    fn the_step_key_tracks_the_diff_and_the_whole_panel() {
        let base_cfg = Step11Config::new("m");
        let base = validation_step_key(&base_cfg, &record(Some("+a\n")));
        assert!(base.starts_with(VALIDATE_STEP_PREFIX));
        assert_eq!(base, validation_step_key(&base_cfg, &record(Some("+a\n"))));
        assert_ne!(base, validation_step_key(&base_cfg, &record(Some("+b\n"))));
        assert_ne!(base, validation_step_key(&base_cfg, &record(None)));

        let mut changes: Vec<Step11Config> = Vec::new();
        let mut c = base_cfg.clone();
        c.model = "other".to_string();
        changes.push(c);
        let mut c = base_cfg.clone();
        c.security_architect_model = Some("sa".to_string());
        changes.push(c);
        let mut c = base_cfg.clone();
        c.penetration_tester_model = Some("pt".to_string());
        changes.push(c);
        let mut c = base_cfg.clone();
        c.cross_repo_analyzer = true;
        changes.push(c.clone());
        c.cross_repo_analyzer_model = Some("cra".to_string());
        changes.push(c);
        let mut c = base_cfg.clone();
        c.fact_tools = false;
        changes.push(c);
        let mut c = base_cfg.clone();
        c.split_ties_score = false;
        changes.push(c);
        let mut c = base_cfg.clone();
        c.dialect = "anthropic".to_string();
        changes.push(c);
        let mut c = base_cfg.clone();
        c.base_host = "gw.example".to_string();
        changes.push(c);
        let keys: std::collections::BTreeSet<String> = changes
            .iter()
            .map(|c| validation_step_key(c, &record(Some("+a\n"))))
            .chain([base.clone()])
            .collect();
        assert_eq!(keys.len(), changes.len() + 1);

        // A cross-repo MODEL without the persona switched on changes nothing.
        let mut c = base_cfg.clone();
        c.cross_repo_analyzer_model = Some("cra".to_string());
        assert_eq!(validation_step_key(&c, &record(Some("+a\n"))), base);
    }
}
