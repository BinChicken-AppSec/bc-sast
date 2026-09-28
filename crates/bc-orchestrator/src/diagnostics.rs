//! Folds each stage crate's own typed diagnostics into the report's one
//! [`PipelineDiagnostics`] (`ScanMetrics::pipeline_diagnostics`).
//!
//! The stage crates return their counters as plain data on their outputs
//! (never process-global state), and `bc-model` cannot depend on them, so
//! the conversion lives here: the orchestrator is the one crate that sees
//! every stage. Each function is a straight field copy with `usize -> u64`
//! widening, kept separate per stage so a counter added to a stage crate
//! has exactly one place to be wired.

use bc_model::{
    AutoExcludeCounts, DecomposeCounts, DeepdiveCounts, PipelineDiagnostics, PrefilterCounts,
    ThreatModelCounts, VerifyCounts,
};

fn n(v: usize) -> u64 {
    v as u64
}

/// The `--auto-step1` guards' decisions. Public because the survey runs in
/// `bc-cli`, before the scan, and reaches it through
/// [`crate::ScanConfig::autoexclude`].
pub fn autoexclude_counts(d: &bc_stage_s1::AutoExcludeDiagnostics) -> AutoExcludeCounts {
    AutoExcludeCounts {
        ran: true,
        vetoed: d.vetoed.clone(),
        files_before: n(d.files_before),
        files_after: n(d.files_after),
        discarded_empty_scope: d.discarded_empty_scope,
        aggressive: d.aggressive,
    }
}

/// S2's counters. `degraded` is Python's `s2_degraded`: the stage failed
/// outright or returned a model with no threats, so ranking and baseline
/// coverage fell back to the deterministic passes.
pub(crate) fn threat_model_counts(
    d: &bc_stage_s2::ThreatModelDiagnostics,
    degraded: bool,
) -> ThreatModelCounts {
    ThreatModelCounts {
        degraded,
        agentic: d.agentic,
        parse_repair_attempted: d.parse_repair_attempted,
        parse_repair_recovered: d.parse_repair_recovered,
        threats_raw: n(d.threats.raw),
        threats_truncated: n(d.threats.truncated),
        threats_promoted: n(d.threats.promoted),
        repo_kinds: d.repo_kinds.clone(),
        baseline_undisposed: d.baseline_undisposed.clone(),
    }
}

pub(crate) fn decompose_counts(d: &bc_stage_s3::DecomposeDiagnostics) -> DecomposeCounts {
    DecomposeCounts {
        llm_chunks: n(d.llm_chunks),
        taint_chunks: n(d.taint_chunks),
        catchall_chunks: n(d.catchall_chunks),
        specialist_chunks: n(d.specialist_chunks),
        fallback_chunks: n(d.fallback_chunks),
        lens_chunks: d
            .lens_chunks
            .iter()
            .map(|(lens, count)| (lens.clone(), n(*count)))
            .collect(),
        gated_off_lenses: d.gated_off_lenses.clone(),
        forced_coverage_files: n(d.forced_coverage_files),
        unreachable_files: n(d.unreachable_files),
        invalid_chunks_dropped: n(d.invalid_chunks_dropped),
        empty_chunks_dropped: n(d.empty_chunks_dropped),
        unknown_file_ids: n(d.unknown_file_ids),
        relocated_paths: n(d.relocated_paths),
        dropped_paths: n(d.dropped_paths),
        fallback_chunks_capped: n(d.fallback_chunks_capped),
        fallback_files_trimmed: n(d.fallback_files_trimmed),
        threats_covered: n(d.threats_covered),
        threats_counted: n(d.threats_counted),
        no_threats_prompt: d.no_threats_prompt,
    }
}

pub(crate) fn deepdive_counts(d: &bc_stage_s4::DeepdiveDiagnostics) -> DeepdiveCounts {
    DeepdiveCounts {
        json_repairs_attempted: n(d.json_repairs_attempted),
        json_repairs_succeeded: n(d.json_repairs_succeeded),
        findings_truncated: n(d.findings_truncated),
        vote_threshold_clamped: n(d.vote_threshold_clamped),
        empty_chunks_skipped: n(d.empty_chunks_skipped),
        leader_start_cap_expired: n(d.leader_start_cap_expired),
        gate_cap_expired: n(d.gate_cap_expired),
        sibling_parked_ms: d.sibling_parked_ms,
    }
}

pub(crate) fn prefilter_counts(d: &bc_stage_s5::PrefilterDiagnostics) -> PrefilterCounts {
    PrefilterCounts {
        evidence_exempted: n(d.evidence_exempted),
    }
}

pub(crate) fn verify_counts(d: &bc_stage_s6::VerifyDiagnostics) -> VerifyCounts {
    VerifyCounts {
        verdict_repairs_attempted: n(d.verdict_repairs_attempted),
        verdict_repairs_adopted: n(d.verdict_repairs_adopted),
    }
}

/// A fresh accumulator seeded with the pre-scan auto-exclude counts, the
/// one set of diagnostics produced before `run_scan` starts.
pub(crate) fn seeded(autoexclude: &AutoExcludeCounts) -> PipelineDiagnostics {
    PipelineDiagnostics {
        autoexclude: autoexclude.clone(),
        ..PipelineDiagnostics::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn autoexclude_counts_marks_the_survey_as_run_and_copies_every_guard() {
        let d = bc_stage_s1::AutoExcludeDiagnostics {
            vetoed: vec![".py".to_string()],
            files_before: 10,
            files_after: 0,
            discarded_empty_scope: true,
            aggressive: false,
        };
        let c = autoexclude_counts(&d);
        assert!(c.ran);
        assert_eq!(c.vetoed, vec![".py".to_string()]);
        assert_eq!((c.files_before, c.files_after), (10, 0));
        assert!(c.discarded_empty_scope && !c.aggressive);
        assert_eq!(seeded(&c).autoexclude, c);
    }

    #[test]
    fn threat_model_counts_copies_every_field() {
        let mut d = bc_stage_s2::ThreatModelDiagnostics {
            parse_repair_attempted: true,
            parse_repair_recovered: true,
            repo_kinds: vec!["web".to_string()],
            baseline_undisposed: vec!["B1".to_string()],
            agentic: true,
            ..Default::default()
        };
        d.threats.raw = 7;
        d.threats.truncated = 2;
        d.threats.promoted = 1;
        let c = threat_model_counts(&d, true);
        assert!(c.degraded && c.agentic && c.parse_repair_attempted && c.parse_repair_recovered);
        assert_eq!(
            (c.threats_raw, c.threats_truncated, c.threats_promoted),
            (7, 2, 1)
        );
        assert_eq!(c.repo_kinds, vec!["web".to_string()]);
        assert_eq!(c.baseline_undisposed, vec!["B1".to_string()]);
    }

    #[test]
    fn decompose_counts_copies_every_field() {
        let mut d = bc_stage_s3::DecomposeDiagnostics {
            llm_chunks: 1,
            taint_chunks: 2,
            catchall_chunks: 3,
            specialist_chunks: 4,
            fallback_chunks: 5,
            gated_off_lenses: vec!["ssrf".to_string()],
            forced_coverage_files: 6,
            unreachable_files: 7,
            invalid_chunks_dropped: 8,
            empty_chunks_dropped: 9,
            unknown_file_ids: 10,
            relocated_paths: 11,
            dropped_paths: 12,
            fallback_chunks_capped: 13,
            fallback_files_trimmed: 14,
            threats_covered: 15,
            threats_counted: 16,
            no_threats_prompt: true,
            ..Default::default()
        };
        d.lens_chunks.insert("authz".to_string(), 4);
        let c = decompose_counts(&d);
        assert_eq!(
            [
                c.llm_chunks,
                c.taint_chunks,
                c.catchall_chunks,
                c.specialist_chunks,
                c.fallback_chunks,
                c.forced_coverage_files,
                c.unreachable_files,
                c.invalid_chunks_dropped,
                c.empty_chunks_dropped,
                c.unknown_file_ids,
                c.relocated_paths,
                c.dropped_paths,
                c.fallback_chunks_capped,
                c.fallback_files_trimmed,
                c.threats_covered,
                c.threats_counted,
            ],
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
        );
        assert_eq!(c.lens_chunks["authz"], 4);
        assert_eq!(c.gated_off_lenses, vec!["ssrf".to_string()]);
        assert!(c.no_threats_prompt);
    }

    #[test]
    fn the_later_stages_counters_are_copied() {
        let dd = deepdive_counts(&bc_stage_s4::DeepdiveDiagnostics {
            json_repairs_attempted: 1,
            json_repairs_succeeded: 2,
            findings_truncated: 3,
            vote_threshold_clamped: 4,
            empty_chunks_skipped: 5,
            leader_start_cap_expired: 6,
            gate_cap_expired: 7,
            sibling_parked_ms: 8,
        });
        assert_eq!(
            [
                dd.json_repairs_attempted,
                dd.json_repairs_succeeded,
                dd.findings_truncated,
                dd.vote_threshold_clamped,
                dd.empty_chunks_skipped,
                dd.leader_start_cap_expired,
                dd.gate_cap_expired,
                dd.sibling_parked_ms
            ],
            [1, 2, 3, 4, 5, 6, 7, 8]
        );
        let pf = prefilter_counts(&bc_stage_s5::PrefilterDiagnostics {
            evidence_exempted: 6,
        });
        assert_eq!(pf.evidence_exempted, 6);
        let v = verify_counts(&bc_stage_s6::VerifyDiagnostics {
            verdict_repairs_attempted: 7,
            verdict_repairs_adopted: 8,
        });
        assert_eq!(
            (v.verdict_repairs_attempted, v.verdict_repairs_adopted),
            (7, 8)
        );
    }
}
