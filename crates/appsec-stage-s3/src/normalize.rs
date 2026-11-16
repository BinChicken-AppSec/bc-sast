use std::collections::HashSet;

use appsec_model::TaskManifest;

use crate::inventory::IdInventory;
use crate::response::Shape;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NormalizeStats {
    pub unknown_file_ids: usize,
    pub relocated_paths: usize,
    pub dropped_paths: usize,
}

fn clean(raw: &str) -> String {
    let mut cand = raw.replace('\\', "/");
    while let Some(stripped) = cand.strip_prefix("./") {
        cand = stripped.to_string();
    }
    cand
}

fn resolve_ids(ids: &[String], inv: &IdInventory, stats: &mut NormalizeStats) -> Vec<String> {
    ids.iter()
        .filter_map(|fid| {
            let path = inv.files.get(fid).cloned();
            if path.is_none() {
                stats.unknown_file_ids += 1;
            }
            path
        })
        .collect()
}

fn resolve_paths(
    paths: &[String],
    all_files: &[String],
    truth: &HashSet<&str>,
    stats: &mut NormalizeStats,
) -> Vec<String> {
    let mut out = Vec::new();
    for raw in paths {
        let cand = clean(raw);
        if truth.contains(cand.as_str()) {
            out.push(cand);
            continue;
        }
        let suffix = format!("/{cand}");
        let mut matches = all_files
            .iter()
            .filter(|t| t.ends_with(&suffix) || cand.ends_with(&format!("/{t}")));
        match (matches.next(), matches.next()) {
            (Some(only), None) => {
                stats.relocated_paths += 1;
                out.push(only.clone());
            }
            _ => stats.dropped_paths += 1,
        }
    }
    out
}

pub fn normalize_chunk_files(
    manifest: &mut TaskManifest,
    all_files: &[String],
    inv: &IdInventory,
    shapes: &[Shape],
    raw_paths: &[Vec<String>],
) -> NormalizeStats {
    let truth: HashSet<&str> = all_files.iter().map(String::as_str).collect();
    let mut stats = NormalizeStats::default();
    for (i, chunk) in manifest.chunks.iter_mut().enumerate() {
        let fixed = match shapes.get(i).copied().unwrap_or(Shape::Paths) {
            Shape::Mixed => {
                let mut v = resolve_ids(&chunk.files, inv, &mut stats);
                let raw = raw_paths.get(i).map(Vec::as_slice).unwrap_or(&[]);
                v.extend(resolve_paths(raw, all_files, &truth, &mut stats));
                v
            }
            Shape::Ids => resolve_ids(&chunk.files, inv, &mut stats),
            Shape::Paths | Shape::None => {
                resolve_paths(&chunk.files, all_files, &truth, &mut stats)
            }
        };
        let mut seen = HashSet::new();
        chunk.files = fixed
            .into_iter()
            .filter(|f| seen.insert(f.clone()))
            .collect();
    }
    stats
}

pub fn drop_empty_chunks(manifest: &mut TaskManifest) -> usize {
    let before = manifest.chunks.len();
    manifest.chunks.retain(|c| !c.files.is_empty());
    before - manifest.chunks.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use appsec_model::{Chunk, ChunkSize, ContextPackage};

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
            shard_id: String::new(),
        }
    }

    fn manifest(chunks: Vec<Chunk>) -> TaskManifest {
        TaskManifest {
            chunks,
            rationale: String::new(),
            unreachable_files: Vec::new(),
        }
    }

    fn strs(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|s| s.to_string()).collect()
    }

    fn inv(files: &[&str]) -> IdInventory {
        let ctx = ContextPackage {
            all_files: strs(files),
            ..ContextPackage::default()
        };
        IdInventory::build(&ctx)
    }

    fn by_paths(all: &[&str], files: Vec<&str>) -> (Vec<String>, NormalizeStats) {
        let all = strs(all);
        let mut m = manifest(vec![chunk("c1", files)]);
        let stats = normalize_chunk_files(&mut m, &all, &inv(&[]), &[Shape::Paths], &[]);
        (m.chunks.remove(0).files, stats)
    }

    #[test]
    fn exact_match_is_kept_as_is() {
        assert_eq!(
            by_paths(&["src/app.py"], vec!["src/app.py"]).0,
            strs(&["src/app.py"])
        );
    }

    #[test]
    fn backslashes_and_leading_dot_slashes_are_normalized() {
        assert_eq!(
            by_paths(&["src/app.py"], vec![r"src\app.py"]).0,
            strs(&["src/app.py"])
        );
        assert_eq!(
            by_paths(&["src/app.py"], vec!["././src/app.py"]).0,
            strs(&["src/app.py"])
        );
    }

    #[test]
    fn a_unique_suffix_match_recovers_dropped_leading_directories() {
        let (files, stats) = by_paths(&["app/core/utils.py"], vec!["core/utils.py"]);
        assert_eq!(files, strs(&["app/core/utils.py"]));
        assert_eq!(stats.relocated_paths, 1);
    }

    #[test]
    fn a_spurious_leading_directory_is_also_recovered() {
        let (files, _) = by_paths(&["server.ts"], vec!["src/server.ts"]);
        assert_eq!(files, strs(&["server.ts"]));
    }

    #[test]
    fn a_bare_basename_match_across_directories_is_no_longer_relocated() {
        let (files, stats) = by_paths(
            &["foo/repo/UserService.java"],
            vec!["service/UserService.java"],
        );
        assert!(files.is_empty());
        assert_eq!(stats.dropped_paths, 1);
    }

    #[test]
    fn a_partial_file_name_is_not_a_suffix_match() {
        assert!(by_paths(&["src/oauth.py"], vec!["auth.py"]).0.is_empty());
    }

    #[test]
    fn an_ambiguous_suffix_match_is_dropped() {
        let (files, stats) = by_paths(&["a/app.py", "b/app.py"], vec!["app.py"]);
        assert!(files.is_empty());
        assert_eq!(stats.dropped_paths, 1);
    }

    #[test]
    fn duplicates_are_removed_preserving_first_seen_order() {
        let (files, _) = by_paths(
            &["src/app.py", "src/util.py"],
            vec!["src/app.py", "src/util.py", "src/app.py"],
        );
        assert_eq!(files, strs(&["src/app.py", "src/util.py"]));
    }

    #[test]
    fn ids_resolve_through_the_inventory_and_unknown_ids_are_counted() {
        let all = strs(&["a.py", "b.py"]);
        let inventory = inv(&["a.py", "b.py"]);
        let mut m = manifest(vec![chunk("c1", vec!["F002", "F999", "F001"])]);
        let stats = normalize_chunk_files(&mut m, &all, &inventory, &[Shape::Ids], &[]);
        assert_eq!(m.chunks[0].files, strs(&["b.py", "a.py"]));
        assert_eq!(stats.unknown_file_ids, 1);
    }

    #[test]
    fn a_mixed_chunk_takes_the_union_of_ids_and_raw_paths() {
        let all = strs(&["a.py", "lib/b.py"]);
        let inventory = inv(&["a.py", "lib/b.py"]);
        let mut m = manifest(vec![chunk("c1", vec!["F001"]), chunk("c2", vec![])]);
        let stats = normalize_chunk_files(
            &mut m,
            &all,
            &inventory,
            &[Shape::Mixed, Shape::Mixed],
            &[vec!["b.py".to_string(), "a.py".to_string()]],
        );
        assert_eq!(m.chunks[0].files, strs(&["a.py", "lib/b.py"]));
        assert!(m.chunks[1].files.is_empty());
        assert_eq!(stats.relocated_paths, 1);
    }

    #[test]
    fn a_chunk_without_a_recorded_shape_resolves_as_paths() {
        let all = strs(&["a.py"]);
        let mut m = manifest(vec![chunk("c1", vec!["a.py"]), chunk("c2", vec!["a.py"])]);
        normalize_chunk_files(&mut m, &all, &inv(&[]), &[Shape::None], &[]);
        assert_eq!(m.chunks[0].files, strs(&["a.py"]));
        assert_eq!(m.chunks[1].files, strs(&["a.py"]));
    }

    #[test]
    fn drop_empty_chunks_removes_only_empty_ones_and_counts_them() {
        let mut m = manifest(vec![chunk("c1", vec![]), chunk("c2", vec!["a.py"])]);
        assert_eq!(drop_empty_chunks(&mut m), 1);
        assert_eq!(m.chunks.len(), 1);
        assert_eq!(m.chunks[0].id, "c2");
    }
}
