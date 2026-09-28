//! `--diff-scope`'s final scoping pass — a Rust-only feature, not ported
//! from the Python original (which has no scan-time scoping at all).
//!
//! Runs last, after every other S3 pass (taint-merge, oversize-split,
//! catch-all, specialist, language-tagging, threat-id cleanup) so each of
//! those still sees the chunk's full intended file set — this matters most
//! for taint-merge, which needs the complete call graph to build accurate
//! multi-file chains before anything gets narrowed here.
//!
//! No-op when `ctx.diff_scope_active` is `false`, so a scan without
//! `--diff-scope` is byte-for-byte unaffected. When it IS active every
//! chunk is trimmed even if `ctx.changed_files` is empty — a diff of only
//! renames/deletions/mode changes/binary files legitimately parses to no
//! changed lines, and that scan must analyze nothing rather than
//! everything.

use std::path::Path;

use bc_model::{Chunk, ContextPackage};

/// Trim every chunk's `files` to its intersection with `ctx.changed_files`,
/// dropping any chunk that becomes empty and recomputing `languages` for
/// the ones that survive (the pre-trim value, set earlier in
/// `run_decompose`, may reference languages that no longer appear once
/// unchanged files are trimmed out).
///
/// Cross-file context for whatever gets trimmed out isn't lost: it's still
/// available to S4 via `bc_stage_s4::neighbor::neighbor_context`, which
/// splices in read-only excerpts of call-graph-adjacent files outside a
/// chunk — trimming a file out of `chunk.files` here is exactly what makes
/// it "outside the chunk" from that mechanism's perspective.
pub fn trim_chunks_to_diff_scope(
    chunks: Vec<Chunk>,
    ctx: &ContextPackage,
    repo_root: &Path,
) -> Vec<Chunk> {
    if !ctx.diff_scope_active {
        return chunks;
    }
    chunks
        .into_iter()
        .filter_map(|mut c| {
            c.files.retain(|f| ctx.changed_files.contains_key(f));
            if c.files.is_empty() {
                return None;
            }
            c.languages = bc_repo_analysis::detect_languages(&c.files, Some(repo_root))
                .into_iter()
                .map(String::from)
                .collect();
            Some(c)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_model::ChunkSize;
    use std::collections::BTreeSet;

    /// A diff-scope-ACTIVE context. `changed_files` may legitimately be
    /// empty here (a rename-only PR); see [`inactive_ctx`] for the
    /// flag-not-passed case.
    fn ctx_with_root(root: &Path, changed_files: Vec<&str>) -> ContextPackage {
        ContextPackage {
            diff_scope_active: true,
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
            changed_files: changed_files
                .into_iter()
                .map(|f| (f.to_string(), BTreeSet::from([1i64])))
                .collect(),
            app_profile: None,
            threat_model: None,
            notes: String::new(),
            compliance_guidance: String::new(),
        }
    }

    fn chunk(id: &str, files: Vec<&str>) -> Chunk {
        Chunk {
            id: id.to_string(),
            size: ChunkSize::Small,
            risk_rank: 1,
            files: files.into_iter().map(String::from).collect(),
            focus_entry_points: Vec::new(),
            hypothesis: String::new(),
            related_cves: Vec::new(),
            threat_id: None,
            languages: vec!["stale-lang".to_string()],
            specialist: None,
            path_funcs: Vec::new(),
            source_ref: String::new(),
            sink_ref: String::new(),
            sink_cwe: Vec::new(),
            shard_id: String::new(),
        }
    }

    /// `--diff-scope` was never passed: the flag is off and the changed
    /// set is empty for the uninteresting reason.
    fn inactive_ctx(root: &Path) -> ContextPackage {
        ContextPackage {
            diff_scope_active: false,
            ..ctx_with_root(root, vec![])
        }
    }

    #[test]
    fn diff_scope_inactive_is_a_byte_for_byte_no_op() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = inactive_ctx(dir.path());
        let chunks = vec![chunk("c1", vec!["a.py", "b.py"])];
        let out = trim_chunks_to_diff_scope(chunks.clone(), &ctx, dir.path());
        assert_eq!(out, chunks);
    }

    #[test]
    fn diff_scope_active_with_an_empty_changed_set_drops_every_chunk() {
        // A rename-only/delete-only PR: the diff parsed fine, it just has
        // no changed source lines. Scoping to nothing is the point — the
        // pre-fix code returned every chunk untrimmed here, i.e. a full
        // repo scan at full LLM spend.
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_with_root(dir.path(), vec![]);
        let chunks = vec![chunk("c1", vec!["a.py", "b.py"]), chunk("c2", vec!["c.py"])];
        let out = trim_chunks_to_diff_scope(chunks, &ctx, dir.path());
        assert!(out.is_empty());
    }

    #[test]
    fn chunk_fully_outside_changed_files_is_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_with_root(dir.path(), vec!["a.py"]);
        let chunks = vec![chunk("c1", vec!["b.py", "c.py"])];
        let out = trim_chunks_to_diff_scope(chunks, &ctx, dir.path());
        assert!(out.is_empty());
    }

    #[test]
    fn chunk_partially_overlapping_is_trimmed_not_dropped() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "x = 1\n").unwrap();
        let ctx = ctx_with_root(dir.path(), vec!["a.py"]);
        let chunks = vec![chunk("c1", vec!["a.py", "b.py"])];
        let out = trim_chunks_to_diff_scope(chunks, &ctx, dir.path());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].files, vec!["a.py".to_string()]);
    }

    #[test]
    fn languages_are_recomputed_after_trimming() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "x = 1\n").unwrap();
        let ctx = ctx_with_root(dir.path(), vec!["a.py"]);
        let chunks = vec![chunk("c1", vec!["a.py", "b.rs"])];
        let out = trim_chunks_to_diff_scope(chunks, &ctx, dir.path());
        assert_eq!(out.len(), 1);
        assert_ne!(out[0].languages, vec!["stale-lang".to_string()]);
    }

    #[test]
    fn a_fully_covered_chunk_is_unchanged_besides_language_recompute() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "x = 1\n").unwrap();
        let ctx = ctx_with_root(dir.path(), vec!["a.py"]);
        let chunks = vec![chunk("c1", vec!["a.py"])];
        let out = trim_chunks_to_diff_scope(chunks, &ctx, dir.path());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].files, vec!["a.py".to_string()]);
    }
}
