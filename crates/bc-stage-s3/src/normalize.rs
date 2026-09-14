//! Ground-truth file-path normalization, ported from
//! `s3_decompose.py::_normalize_chunk_files`.

use std::collections::HashMap;
use std::path::Path;

use bc_model::TaskManifest;

/// Map model-emitted paths onto `all_files` (ground truth); drop anything
/// that doesn't exist. Exact match wins; otherwise, if exactly one
/// `all_files` entry shares the candidate's basename, substitute it —
/// else drop it. Dedupes each chunk's file list while preserving
/// first-seen order.
pub fn normalize_chunk_files(manifest: &mut TaskManifest, all_files: &[String]) {
    let truth: std::collections::HashSet<&str> = all_files.iter().map(String::as_str).collect();
    let mut by_name: HashMap<&str, Vec<&str>> = HashMap::new();
    for f in all_files {
        let name = Path::new(f)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(f.as_str());
        by_name.entry(name).or_default().push(f.as_str());
    }

    for chunk in &mut manifest.chunks {
        let mut fixed: Vec<String> = Vec::new();
        for f in &chunk.files {
            let mut cand = f.replace('\\', "/");
            while let Some(stripped) = cand.strip_prefix("./") {
                cand = stripped.to_string();
            }
            if truth.contains(cand.as_str()) {
                fixed.push(cand);
                continue;
            }
            let name = Path::new(&cand)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(cand.as_str());
            let matches = by_name.get(name).map(Vec::as_slice).unwrap_or(&[]);
            if matches.len() == 1 {
                fixed.push(matches[0].to_string());
            }
            // Zero or >1 basename matches: drop (matches Python's stderr-log-
            // and-drop behavior; the log line itself isn't ported, per this
            // project's established "stderr diagnostics aren't ported"
            // convention — only the side effect on `chunk.files` matters).
        }
        let mut seen = std::collections::HashSet::new();
        chunk.files = fixed
            .into_iter()
            .filter(|f| seen.insert(f.clone()))
            .collect();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_model::{Chunk, ChunkSize};

    fn chunk(id: &str, files: Vec<&str>) -> Chunk {
        Chunk {
            id: id.to_string(),
            size: ChunkSize::Medium,
            risk_rank: 1,
            files: files.into_iter().map(String::from).collect(),
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

    fn manifest(chunks: Vec<Chunk>) -> TaskManifest {
        TaskManifest {
            chunks,
            rationale: String::new(),
            unreachable_files: Vec::new(),
        }
    }

    #[test]
    fn exact_match_is_kept_as_is() {
        let all_files = vec!["src/app.py".to_string()];
        let mut m = manifest(vec![chunk("c1", vec!["src/app.py"])]);
        normalize_chunk_files(&mut m, &all_files);
        assert_eq!(m.chunks[0].files, vec!["src/app.py".to_string()]);
    }

    #[test]
    fn backslashes_are_normalized_to_forward_slashes() {
        let all_files = vec!["src/app.py".to_string()];
        let mut m = manifest(vec![chunk("c1", vec![r"src\app.py"])]);
        normalize_chunk_files(&mut m, &all_files);
        assert_eq!(m.chunks[0].files, vec!["src/app.py".to_string()]);
    }

    #[test]
    fn leading_dot_slash_is_stripped_repeatedly() {
        let all_files = vec!["src/app.py".to_string()];
        let mut m = manifest(vec![chunk("c1", vec!["././src/app.py"])]);
        normalize_chunk_files(&mut m, &all_files);
        assert_eq!(m.chunks[0].files, vec!["src/app.py".to_string()]);
    }

    #[test]
    fn unique_basename_match_substitutes_the_real_path() {
        let all_files = vec!["src/nested/app.py".to_string()];
        let mut m = manifest(vec![chunk("c1", vec!["app.py"])]);
        normalize_chunk_files(&mut m, &all_files);
        assert_eq!(m.chunks[0].files, vec!["src/nested/app.py".to_string()]);
    }

    #[test]
    fn ambiguous_basename_match_is_dropped() {
        let all_files = vec!["a/app.py".to_string(), "b/app.py".to_string()];
        let mut m = manifest(vec![chunk("c1", vec!["app.py"])]);
        normalize_chunk_files(&mut m, &all_files);
        assert!(m.chunks[0].files.is_empty());
    }

    #[test]
    fn no_basename_match_is_dropped() {
        let all_files = vec!["src/app.py".to_string()];
        let mut m = manifest(vec![chunk("c1", vec!["hallucinated.py"])]);
        normalize_chunk_files(&mut m, &all_files);
        assert!(m.chunks[0].files.is_empty());
    }

    #[test]
    fn duplicates_are_removed_preserving_first_seen_order() {
        let all_files = vec!["src/app.py".to_string(), "src/util.py".to_string()];
        let mut m = manifest(vec![chunk(
            "c1",
            vec!["src/app.py", "src/util.py", "src/app.py"],
        )]);
        normalize_chunk_files(&mut m, &all_files);
        assert_eq!(
            m.chunks[0].files,
            vec!["src/app.py".to_string(), "src/util.py".to_string()]
        );
    }

    #[test]
    fn multiple_chunks_are_each_normalized_independently() {
        let all_files = vec!["a.py".to_string(), "b.py".to_string()];
        let mut m = manifest(vec![
            chunk("c1", vec!["a.py"]),
            chunk("c2", vec!["b.py", "ghost.py"]),
        ]);
        normalize_chunk_files(&mut m, &all_files);
        assert_eq!(m.chunks[0].files, vec!["a.py".to_string()]);
        assert_eq!(m.chunks[1].files, vec!["b.py".to_string()]);
    }
}
