use std::path::Path;

use appsec_model::{Chunk, ContextPackage};

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
            c.languages = appsec_repo_analysis::detect_languages(&c.files, Some(repo_root))
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
    use appsec_model::ChunkSize;
    use std::collections::BTreeSet;

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
            design_controls: Vec::new(),
            changed_files: changed_files
                .into_iter()
                .map(|f| (f.to_string(), BTreeSet::from([1i64])))
                .collect(),
            app_profile: None,
            threat_model: None,
            provider_digest: None,
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
