//! Merges `bc-repo-analysis`'s pure `add_taint_chunks` result into a
//! manifest's chunk list — the rank-shift/append logic
//! `bc_repo_analysis::taint`'s own doc comment explicitly defers to "the
//! eventual S3 stage crate."
//!
//! Ported from the surrounding bookkeeping in `s3_decompose.py::
//! _add_taint_chunks` (the BFS/matching core itself is already ported as
//! `bc_repo_analysis::add_taint_chunks`): taint chunks are the
//! highest-signal work, so every *existing* chunk's `risk_rank` is shifted
//! up by `taint_max_chunks` — but only when at least one taint chunk was
//! actually found; the Python original shifts unconditionally then undoes
//! the shift on zero results, which nets to the same "no shift on empty"
//! outcome this port reaches directly. New taint chunks are **appended**
//! to the chunk list (not prepended) with `risk_rank` `1..N` — they sort
//! first via `TaskManifest::sorted_chunks()` regardless of their list
//! position, since sorting is by rank, not vector order.

use std::path::Path;

use bc_model::{Chunk, ContextPackage};
use bc_repo_analysis::TaintChunkConfig;

use crate::Step3Config;

pub fn merge_taint_chunks(
    chunks: Vec<Chunk>,
    ctx: &ContextPackage,
    config: &Step3Config,
) -> Vec<Chunk> {
    let taint_config = TaintChunkConfig {
        enabled: config.taint_chunks,
        max_hops: config.taint_max_hops,
        max_chunks: config.taint_max_chunks,
        files_per_hop: config.taint_files_per_hop,
    };
    let repo_root = Path::new(&ctx.repo_root);
    let threats: &[bc_model::Threat] = ctx
        .threat_model
        .as_ref()
        .map(|tm| tm.threats.as_slice())
        .unwrap_or(&[]);
    let result = bc_repo_analysis::add_taint_chunks(
        ctx,
        &ctx.entry_points,
        &ctx.unsafe_sinks,
        threats,
        &ctx.call_graph,
        &ctx.all_files,
        repo_root,
        &taint_config,
    );

    if result.chunks.is_empty() {
        return chunks;
    }

    let shift = config.taint_max_chunks as i64;
    let mut shifted: Vec<Chunk> = chunks
        .into_iter()
        .map(|mut c| {
            c.risk_rank += shift;
            c
        })
        .collect();
    shifted.extend(result.chunks);
    shifted
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_model::{Chunk, ChunkSize, EntryPoint, EntryPointKind, Sink};

    fn ctx_with_root(root: &Path) -> ContextPackage {
        ContextPackage {
            seed_taint_paths: Default::default(),
            seed_taint_evidence: Default::default(),
            def_spans: Default::default(),
            repo_root: root.to_string_lossy().to_string(),
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
        }
    }

    fn chunk(id: &str, risk_rank: i64) -> Chunk {
        Chunk {
            id: id.to_string(),
            size: ChunkSize::Medium,
            risk_rank,
            files: Vec::new(),
            focus_entry_points: Vec::new(),
            hypothesis: String::new(),
            related_cves: Vec::new(),
            threat_id: None,
            languages: Vec::new(),
            specialist: None,
            path_funcs: Vec::new(),
            source_ref: String::new(),
            sink_ref: String::new(),
            sink_cwe: Vec::new(),
        }
    }

    #[test]
    fn no_entry_points_or_sinks_leaves_chunks_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_with_root(dir.path());
        let cfg = Step3Config::new("m");
        let chunks = vec![chunk("c1", 1)];
        let out = merge_taint_chunks(chunks.clone(), &ctx, &cfg);
        assert_eq!(out, chunks);
    }

    #[test]
    fn taint_chunks_disabled_leaves_chunks_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let mut ctx = ctx_with_root(dir.path());
        ctx.entry_points = vec![EntryPoint {
            file: "a.py".to_string(),
            function: "handler".to_string(),
            kind: EntryPointKind::Network,
            reachable_from_unauth: true,
        }];
        ctx.unsafe_sinks = vec![Sink {
            file: "a.py".to_string(),
            line: 1,
            function: "sink".to_string(),
            snippet: String::new(),
            cwe: Vec::new(),
        }];
        let mut cfg = Step3Config::new("m");
        cfg.taint_chunks = false;
        let chunks = vec![chunk("c1", 1)];
        let out = merge_taint_chunks(chunks.clone(), &ctx, &cfg);
        assert_eq!(out, chunks);
    }

    #[test]
    fn a_direct_entry_to_sink_path_shifts_existing_ranks_and_appends() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "def handler():\n    sink()\n").unwrap();
        let mut ctx = ctx_with_root(dir.path());
        ctx.all_files = vec!["a.py".to_string()];
        ctx.entry_points = vec![EntryPoint {
            file: "a.py".to_string(),
            function: "handler".to_string(),
            kind: EntryPointKind::Network,
            reachable_from_unauth: true,
        }];
        ctx.unsafe_sinks = vec![Sink {
            file: "a.py".to_string(),
            line: 2,
            function: "sink".to_string(),
            snippet: String::new(),
            cwe: Vec::new(),
        }];
        let mut cfg = Step3Config::new("m");
        cfg.taint_max_chunks = 60;
        let chunks = vec![chunk("c1", 1)];
        let out = merge_taint_chunks(chunks, &ctx, &cfg);
        // Original chunk shifted by max_chunks; taint chunk appended at rank 1.
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].id, "c1");
        assert_eq!(out[0].risk_rank, 61);
        assert_eq!(out[1].id, "taint-01");
        assert_eq!(out[1].risk_rank, 1);
    }

    #[test]
    fn zero_reachable_paths_leaves_chunks_untouched() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "def handler():\n    pass\n").unwrap();
        let mut ctx = ctx_with_root(dir.path());
        ctx.all_files = vec!["a.py".to_string(), "b.py".to_string()];
        ctx.entry_points = vec![EntryPoint {
            file: "a.py".to_string(),
            function: "handler".to_string(),
            kind: EntryPointKind::Network,
            reachable_from_unauth: true,
        }];
        // Sink lives in a totally disconnected file with no graph edge and
        // no direct same-file co-location with the entry point.
        ctx.unsafe_sinks = vec![Sink {
            file: "b.py".to_string(),
            line: 1,
            function: "sink".to_string(),
            snippet: String::new(),
            cwe: Vec::new(),
        }];
        let cfg = Step3Config::new("m");
        let chunks = vec![chunk("c1", 1)];
        let out = merge_taint_chunks(chunks.clone(), &ctx, &cfg);
        assert_eq!(out, chunks);
    }
}
