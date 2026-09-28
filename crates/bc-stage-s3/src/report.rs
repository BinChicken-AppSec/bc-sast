//! Threat-coverage bookkeeping, ported from `s3_decompose.py::
//! _report_threat_coverage` — keeping only its real side effect (nulling
//! out a chunk's `threat_id` when it doesn't name a real threat), not its
//! stderr summary print (not ported anywhere in this project, per the
//! established "stderr diagnostics aren't ported" convention).

use std::collections::HashSet;

use bc_model::{Chunk, ContextPackage};

/// Any chunk whose `threat_id` doesn't match a real `ThreatModel` threat
/// id has it cleared. No-op when there's no threat model, or it has no
/// threats.
pub fn drop_unknown_threat_ids(chunks: &mut [Chunk], ctx: &ContextPackage) {
    let Some(tm) = &ctx.threat_model else {
        return;
    };
    if tm.threats.is_empty() {
        return;
    }
    let valid: HashSet<&str> = tm.threats.iter().map(|t| t.id.as_str()).collect();
    for c in chunks.iter_mut() {
        if c.threat_id
            .as_deref()
            .is_some_and(|tid| !valid.contains(tid))
        {
            c.threat_id = None;
        }
    }
}

/// `(covered, counted)`: how many threats have at least one chunk citing
/// them, over how many count toward coverage at all. Baseline dispositions
/// that name no code surface are left out of both, as upstream v1.3's
/// `_report_threat_coverage` does, so one never reads as permanently
/// uncovered. Call after [`drop_unknown_threat_ids`].
pub fn threat_coverage(chunks: &[Chunk], ctx: &ContextPackage) -> (usize, usize) {
    let Some(tm) = &ctx.threat_model else {
        return (0, 0);
    };
    let all_files: HashSet<&str> = ctx.all_files.iter().map(String::as_str).collect();
    let counted: HashSet<&str> = tm
        .threats
        .iter()
        .filter(|t| !crate::fallback::is_unmatched_baseline_threat(t, &all_files))
        .map(|t| t.id.as_str())
        .collect();
    let covered: HashSet<&str> = chunks
        .iter()
        .filter_map(|c| c.threat_id.as_deref())
        .filter(|id| counted.contains(id))
        .collect();
    (covered.len(), counted.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_model::{Actor, ChunkSize, Impact, Likelihood, Threat, ThreatModel};

    fn ctx_with_threats(threats: Vec<Threat>) -> ContextPackage {
        ContextPackage {
            seed_taint_paths: Default::default(),
            seed_taint_evidence: Default::default(),
            def_spans: Default::default(),
            repo_root: "/repo".to_string(),
            language: "python".to_string(),
            call_graph: Default::default(),
            call_graph_files: Default::default(),
            entry_points: Vec::new(),
            unsafe_sinks: Vec::new(),
            modules: Vec::new(),
            all_files: Vec::new(),
            excluded: Default::default(),
            known_cves: Vec::new(),
            design_controls: Vec::new(),
            changed_files: Default::default(),
            diff_scope_active: false,
            app_profile: None,
            threat_model: Some(ThreatModel {
                threats,
                ..Default::default()
            }),
            notes: String::new(),
            compliance_guidance: String::new(),
        }
    }

    fn threat(id: &str) -> Threat {
        Threat {
            id: id.to_string(),
            threat: "t".to_string(),
            actor: Actor::RemoteUnauth,
            surface: "s".to_string(),
            asset: "a".to_string(),
            impact: Impact::High,
            likelihood: Likelihood::Likely,
            controls: String::new(),
            evidence: String::new(),
        }
    }

    fn chunk(threat_id: Option<&str>) -> Chunk {
        Chunk {
            id: "c1".to_string(),
            size: ChunkSize::Medium,
            risk_rank: 1,
            files: Vec::new(),
            focus_entry_points: Vec::new(),
            hypothesis: String::new(),
            related_cves: Vec::new(),
            threat_id: threat_id.map(String::from),
            languages: Vec::new(),
            specialist: None,
            path_funcs: Vec::new(),
            source_ref: String::new(),
            sink_ref: String::new(),
            sink_cwe: Vec::new(),
            shard_id: String::new(),
        }
    }

    #[test]
    fn no_threat_model_is_a_noop() {
        let ctx = ContextPackage {
            seed_taint_paths: Default::default(),
            seed_taint_evidence: Default::default(),
            def_spans: Default::default(),
            repo_root: "/repo".to_string(),
            language: "python".to_string(),
            call_graph: Default::default(),
            call_graph_files: Default::default(),
            entry_points: Vec::new(),
            unsafe_sinks: Vec::new(),
            modules: Vec::new(),
            all_files: Vec::new(),
            excluded: Default::default(),
            known_cves: Vec::new(),
            design_controls: Vec::new(),
            changed_files: Default::default(),
            diff_scope_active: false,
            app_profile: None,
            threat_model: None,
            notes: String::new(),
            compliance_guidance: String::new(),
        };
        let mut chunks = vec![chunk(Some("T99"))];
        drop_unknown_threat_ids(&mut chunks, &ctx);
        assert_eq!(chunks[0].threat_id, Some("T99".to_string()));
    }

    #[test]
    fn empty_threats_list_is_a_noop() {
        let ctx = ctx_with_threats(Vec::new());
        let mut chunks = vec![chunk(Some("T99"))];
        drop_unknown_threat_ids(&mut chunks, &ctx);
        assert_eq!(chunks[0].threat_id, Some("T99".to_string()));
    }

    #[test]
    fn unknown_threat_id_is_cleared() {
        let ctx = ctx_with_threats(vec![threat("T1")]);
        let mut chunks = vec![chunk(Some("T99"))];
        drop_unknown_threat_ids(&mut chunks, &ctx);
        assert_eq!(chunks[0].threat_id, None);
    }

    #[test]
    fn known_threat_id_is_kept() {
        let ctx = ctx_with_threats(vec![threat("T1")]);
        let mut chunks = vec![chunk(Some("T1"))];
        drop_unknown_threat_ids(&mut chunks, &ctx);
        assert_eq!(chunks[0].threat_id, Some("T1".to_string()));
    }

    #[test]
    fn chunk_with_no_threat_id_is_untouched() {
        let ctx = ctx_with_threats(vec![threat("T1")]);
        let mut chunks = vec![chunk(None)];
        drop_unknown_threat_ids(&mut chunks, &ctx);
        assert_eq!(chunks[0].threat_id, None);
    }

    #[test]
    fn threat_coverage_excludes_unmatched_baseline_threats_from_both_sides() {
        let mut filler = threat("T2");
        filler.evidence = "baseline: BL-DEP-01".to_string();
        filler.surface = "npm dependencies".to_string();
        let ctx = ctx_with_threats(vec![threat("T1"), filler, threat("T3")]);
        let chunks = vec![chunk(Some("T1")), chunk(Some("T2")), chunk(None)];
        assert_eq!(threat_coverage(&chunks, &ctx), (1, 2));
    }

    #[test]
    fn threat_coverage_is_zero_over_zero_without_a_threat_model() {
        let mut ctx = ctx_with_threats(Vec::new());
        ctx.threat_model = None;
        assert_eq!(threat_coverage(&[chunk(Some("T1"))], &ctx), (0, 0));
    }
}
