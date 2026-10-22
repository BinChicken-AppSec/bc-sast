//! The `Glob` tool, ported from `backends/localtools.py`'s `_glob`.

use std::path::Path;

use crate::walk::glob_jailed_files;

const MAX_GLOB: usize = 500;

pub fn glob(root: &Path, pattern: &str) -> String {
    let hits: Vec<String> = glob_jailed_files(root, pattern)
        .into_iter()
        .filter_map(|p| {
            p.strip_prefix(root)
                .ok()
                .map(|rel| rel.to_string_lossy().replace('\\', "/"))
        })
        .collect();

    if hits.is_empty() {
        return "No files found".to_string();
    }
    if hits.len() > MAX_GLOB {
        let shown = hits[..MAX_GLOB].join("\n");
        return format!("{shown}\n... ({} more)", hits.len() - MAX_GLOB);
    }
    hits.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, rel: &str) {
        let path = dir.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "").unwrap();
    }

    #[test]
    fn finds_matching_files_sorted() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "b.rs");
        write(dir.path(), "a.rs");
        assert_eq!(glob(dir.path(), "*.rs"), "a.rs\nb.rs");
    }

    #[test]
    fn recursive_pattern_finds_nested_files() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "sub/nested.rs");
        assert_eq!(glob(dir.path(), "**/*.rs"), "sub/nested.rs");
    }

    #[test]
    fn no_matches_is_reported_explicitly() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(glob(dir.path(), "*.nomatch"), "No files found");
    }

    #[test]
    fn results_are_capped_with_a_remainder_count() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..(MAX_GLOB + 5) {
            write(dir.path(), &format!("f{i:04}.txt"));
        }
        let out = glob(dir.path(), "*.txt");
        assert!(out.ends_with("... (5 more)"));
        assert_eq!(out.lines().count(), MAX_GLOB + 1);
    }
}
