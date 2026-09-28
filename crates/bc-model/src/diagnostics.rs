//! Per-stage pipeline counters carried on [`crate::ScanMetrics`], the
//! typed counterpart of the flat `s2_*`/`s3_*`/`s4_*` fields the Python
//! original keeps on its own `ScanMetrics` (`models/_scan.py`) and fills
//! from a process-global counter sink.
//!
//! This port keeps no global counters: each stage returns its own typed
//! diagnostics and the orchestrator folds them into one
//! [`PipelineDiagnostics`] per scan, so two scans in one process can never
//! mix their numbers. Every field defaults to zero/empty (and every struct
//! is `#[serde(default)]`), so a report written before these existed still
//! deserializes, and a stage that never ran (switched off, or restored from
//! a `--resume` checkpoint, which does not carry its counters) simply
//! contributes nothing.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Everything the pipeline's guards, repairs and caps did during one scan.
/// Rendered by `bc_report_md` as `### Pipeline Diagnostics`, and only when
/// at least one of these says something (see [`Self::is_noteworthy`]).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PipelineDiagnostics {
    pub autoexclude: AutoExcludeCounts,
    pub threat_model: ThreatModelCounts,
    pub decompose: DecomposeCounts,
    pub deepdive: DeepdiveCounts,
    pub prefilter: PrefilterCounts,
    pub verify: VerifyCounts,
}

/// What the `--auto-step1` overlay guards decided (`bc_stage_s1::
/// AutoExcludeDiagnostics`). `ran` distinguishes "the survey ran and
/// changed nothing" from "no survey ran at all".
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AutoExcludeCounts {
    pub ran: bool,
    /// Model-proposed entries vetoed because each would have removed a
    /// whole scanner-known language from scope. Model-authored text: a
    /// renderer must neutralize it.
    pub vetoed: Vec<String>,
    pub files_before: u64,
    pub files_after: u64,
    pub discarded_empty_scope: bool,
    pub aggressive: bool,
}

/// S2's counters (`bc_stage_s2::ThreatModelDiagnostics`), plus whether the
/// stage degraded or failed (Python's `s2_degraded`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ThreatModelCounts {
    pub degraded: bool,
    pub agentic: bool,
    pub parse_repair_attempted: bool,
    pub parse_repair_recovered: bool,
    pub threats_raw: u64,
    pub threats_truncated: u64,
    pub threats_promoted: u64,
    pub repo_kinds: Vec<String>,
    pub baseline_undisposed: Vec<String>,
}

/// S3's counters (`bc_stage_s3::DecomposeDiagnostics`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct DecomposeCounts {
    pub llm_chunks: u64,
    pub taint_chunks: u64,
    pub catchall_chunks: u64,
    pub specialist_chunks: u64,
    pub fallback_chunks: u64,
    pub lens_chunks: BTreeMap<String, u64>,
    pub gated_off_lenses: Vec<String>,
    pub forced_coverage_files: u64,
    pub unreachable_files: u64,
    pub invalid_chunks_dropped: u64,
    pub empty_chunks_dropped: u64,
    pub unknown_file_ids: u64,
    pub relocated_paths: u64,
    pub dropped_paths: u64,
    pub fallback_chunks_capped: u64,
    pub fallback_files_trimmed: u64,
    pub threats_covered: u64,
    pub threats_counted: u64,
    pub no_threats_prompt: bool,
}

/// S4's counters (`bc_stage_s4::DeepdiveDiagnostics`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct DeepdiveCounts {
    pub json_repairs_attempted: u64,
    pub json_repairs_succeeded: u64,
    pub findings_truncated: u64,
    pub vote_threshold_clamped: u64,
    pub empty_chunks_skipped: u64,
    /// Shard siblings that stopped waiting for their leader to start and
    /// ran ungated (the shard's cache prefix may have been written twice).
    pub leader_start_cap_expired: u64,
    /// Shard siblings whose leader was still running at the done cap.
    pub gate_cap_expired: u64,
    /// Total milliseconds shard siblings spent parked behind their leader:
    /// context (the latency side of the gating trade), not a problem.
    pub sibling_parked_ms: u64,
}

/// S5's counters (`bc_stage_s5::PrefilterDiagnostics`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PrefilterCounts {
    pub evidence_exempted: u64,
}

/// S6's counters (`bc_stage_s6::VerifyDiagnostics`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct VerifyCounts {
    pub verdict_repairs_attempted: u64,
    pub verdict_repairs_adopted: u64,
}

impl PipelineDiagnostics {
    /// Whether anything here is worth a reader's attention: a repair, a
    /// cap that cut real output, a guard that fired, a coverage gap or a
    /// specialist lens breakdown. Context alone (which repository kinds
    /// were detected, whether S2 ran agentically, how many chunks the
    /// strategist produced) is not, so a clean run renders no section.
    pub fn is_noteworthy(&self) -> bool {
        let ae = &self.autoexclude;
        let tm = &self.threat_model;
        let dc = &self.decompose;
        let dd = &self.deepdive;
        !ae.vetoed.is_empty()
            || ae.discarded_empty_scope
            || ae.aggressive
            || tm.degraded
            || tm.parse_repair_attempted
            || tm.threats_truncated > 0
            || tm.threats_promoted > 0
            || !tm.baseline_undisposed.is_empty()
            || !dc.lens_chunks.is_empty()
            || !dc.gated_off_lenses.is_empty()
            || dc.forced_coverage_files > 0
            || dc.unreachable_files > 0
            || dc.invalid_chunks_dropped > 0
            || dc.empty_chunks_dropped > 0
            || dc.unknown_file_ids > 0
            || dc.relocated_paths > 0
            || dc.dropped_paths > 0
            || dc.fallback_chunks > 0
            || dc.fallback_chunks_capped > 0
            || dc.fallback_files_trimmed > 0
            || dc.threats_covered < dc.threats_counted
            || dd.json_repairs_attempted > 0
            || dd.findings_truncated > 0
            || dd.vote_threshold_clamped > 0
            || dd.empty_chunks_skipped > 0
            || dd.leader_start_cap_expired > 0
            || dd.gate_cap_expired > 0
            || self.prefilter.evidence_exempted > 0
            || self.verify.verdict_repairs_attempted > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_default_set_of_counters_is_not_noteworthy() {
        assert!(!PipelineDiagnostics::default().is_noteworthy());
    }

    #[test]
    fn context_only_counters_are_not_noteworthy() {
        let mut d = PipelineDiagnostics::default();
        d.autoexclude.ran = true;
        d.autoexclude.files_before = 10;
        d.autoexclude.files_after = 9;
        d.threat_model.agentic = true;
        d.threat_model.threats_raw = 12;
        d.threat_model.repo_kinds = vec!["web".to_string()];
        d.decompose.llm_chunks = 4;
        d.decompose.taint_chunks = 1;
        d.decompose.catchall_chunks = 2;
        d.decompose.specialist_chunks = 0;
        d.decompose.threats_covered = 3;
        d.decompose.threats_counted = 3;
        d.decompose.no_threats_prompt = true;
        d.deepdive.json_repairs_succeeded = 0;
        d.deepdive.sibling_parked_ms = 1500;
        d.verify.verdict_repairs_adopted = 0;
        assert!(!d.is_noteworthy());
    }

    #[test]
    fn every_noteworthy_counter_on_its_own_makes_the_set_noteworthy() {
        let setters: Vec<fn(&mut PipelineDiagnostics)> = vec![
            |d| d.autoexclude.vetoed.push(".py".to_string()),
            |d| d.autoexclude.discarded_empty_scope = true,
            |d| d.autoexclude.aggressive = true,
            |d| d.threat_model.degraded = true,
            |d| d.threat_model.parse_repair_attempted = true,
            |d| d.threat_model.threats_truncated = 1,
            |d| d.threat_model.threats_promoted = 1,
            |d| d.threat_model.baseline_undisposed.push("B1".to_string()),
            |d| {
                d.decompose.lens_chunks.insert("authz".to_string(), 1);
            },
            |d| d.decompose.gated_off_lenses.push("crypto".to_string()),
            |d| d.decompose.forced_coverage_files = 1,
            |d| d.decompose.unreachable_files = 1,
            |d| d.decompose.invalid_chunks_dropped = 1,
            |d| d.decompose.empty_chunks_dropped = 1,
            |d| d.decompose.unknown_file_ids = 1,
            |d| d.decompose.relocated_paths = 1,
            |d| d.decompose.dropped_paths = 1,
            |d| d.decompose.fallback_chunks = 1,
            |d| d.decompose.fallback_chunks_capped = 1,
            |d| d.decompose.fallback_files_trimmed = 1,
            |d| d.decompose.threats_counted = 1,
            |d| d.deepdive.json_repairs_attempted = 1,
            |d| d.deepdive.findings_truncated = 1,
            |d| d.deepdive.vote_threshold_clamped = 1,
            |d| d.deepdive.empty_chunks_skipped = 1,
            |d| d.deepdive.leader_start_cap_expired = 1,
            |d| d.deepdive.gate_cap_expired = 1,
            |d| d.prefilter.evidence_exempted = 1,
            |d| d.verify.verdict_repairs_attempted = 1,
        ];
        for (i, set) in setters.into_iter().enumerate() {
            let mut d = PipelineDiagnostics::default();
            set(&mut d);
            assert!(d.is_noteworthy(), "setter {i} should be noteworthy");
        }
    }

    #[test]
    fn an_empty_object_deserializes_to_the_defaults() {
        let d: PipelineDiagnostics = serde_json::from_str("{}").unwrap();
        assert_eq!(d, PipelineDiagnostics::default());
        let d: PipelineDiagnostics =
            serde_json::from_str(r#"{"deepdive":{"findings_truncated":2}}"#).unwrap();
        assert_eq!(d.deepdive.findings_truncated, 2);
        let back: PipelineDiagnostics =
            serde_json::from_str(&serde_json::to_string(&d).unwrap()).unwrap();
        assert_eq!(back, d);
    }
}
