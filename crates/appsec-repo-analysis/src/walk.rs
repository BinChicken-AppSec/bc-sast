use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

use crate::fnmatch::{default_exclude_globs, glob_hit};

pub const DEFAULT_EXCLUDE_DIRS: &[&str] = &[
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "dist",
    "build",
    ".idea",
    ".vscode",
    "target",
    "vendor",
    ".terraform",
    ".next",
    ".nuxt",
    "coverage",
    ".pytest_cache",
    ".mypy_cache",
    "test",
    "tests",
    "__tests__",
    "__test__",
    "e2e",
    "testdata",
    "fixtures",
    "__fixtures__",
    "mocks",
    "__mocks__",
    "stubs",
    "checkpoints",
    "security-scan",
];

pub const DEFAULT_EXCLUDE_EXTS: &[&str] = &[
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".pdf", ".zip", ".gz", ".tar", ".7z", ".jar",
    ".war", ".class", ".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a", ".obj", ".pyc", ".pyo",
    ".pkl", ".lock", ".min.js", ".map", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".wav",
];

#[derive(Debug, Clone, PartialEq)]
pub struct WalkConfig {
    pub exclude_dirs: Vec<String>,
    pub exclude_exts: Vec<String>,
    pub exclude_globs: Vec<String>,
    pub max_file_kb: u64,
}

impl WalkConfig {
    pub fn new() -> Self {
        WalkConfig {
            exclude_dirs: Vec::new(),
            exclude_exts: Vec::new(),
            exclude_globs: Vec::new(),
            max_file_kb: 1024,
        }
    }
}

impl Default for WalkConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct ExclusionReport {
    pub dirs: BTreeMap<String, u64>,
    pub exts: BTreeMap<String, u64>,
    pub globs: BTreeMap<String, u64>,
    pub oversize: u64,
    pub oversize_files: Vec<(String, u64)>,
    pub symlinks: BTreeMap<String, u64>,
}

pub fn walk_repo(root: &Path, config: &WalkConfig) -> (Vec<String>, ExclusionReport) {
    let root_resolved = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());

    let exclude_dirs: HashSet<String> = DEFAULT_EXCLUDE_DIRS
        .iter()
        .map(|s| s.to_string())
        .chain(config.exclude_dirs.iter().map(|s| s.to_lowercase()))
        .collect();
    let exclude_exts: HashSet<String> = DEFAULT_EXCLUDE_EXTS
        .iter()
        .map(|s| s.to_string())
        .chain(config.exclude_exts.iter().cloned())
        .collect();
    let exclude_globs: Vec<String> = default_exclude_globs()
        .iter()
        .cloned()
        .chain(config.exclude_globs.iter().cloned())
        .collect();
    let max_bytes = config.max_file_kb * 1024;

    let mut candidates = Vec::new();
    collect_files(root, &mut candidates);

    let mut out = Vec::new();
    let mut report = ExclusionReport::default();

    for path in candidates {
        let rel = relativize(&path, root).expect("candidate path always starts with root");

        let is_symlink = path
            .symlink_metadata()
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false);
        if is_symlink && symlink_escapes(&path, &root_resolved) {
            *report.symlinks.entry(rel).or_insert(0) += 1;
            continue;
        }

        let rel_parts: Vec<&str> = rel.split('/').collect();
        let hit_dir_idx = rel_parts[..rel_parts.len().saturating_sub(1)]
            .iter()
            .position(|part| exclude_dirs.contains(&part.to_lowercase()));
        if let Some(idx) = hit_dir_idx {
            let prefix = rel_parts[..=idx].join("/");
            *report.dirs.entry(prefix).or_insert(0) += 1;
            continue;
        }

        let name = rel_parts.last().copied().unwrap_or("").to_lowercase();
        let suffix_dot = path
            .extension()
            .map(|e| format!(".{}", e.to_string_lossy().to_lowercase()))
            .unwrap_or_default();
        let hit_ext = exclude_exts
            .iter()
            .find(|e| suffix_dot == **e || name.ends_with(e.as_str()));
        if let Some(hit) = hit_ext {
            *report.exts.entry(hit.clone()).or_insert(0) += 1;
            continue;
        }

        if let Some(hit) = glob_hit(&rel, &exclude_globs) {
            *report.globs.entry(hit.to_string()).or_insert(0) += 1;
            continue;
        }

        let Some(size) = file_size(&path) else {
            continue;
        };
        if size > max_bytes {
            report.oversize_files.push((rel, size));
            continue;
        }

        out.push(rel);
    }

    out.sort();
    report
        .oversize_files
        .sort_by_key(|b| std::cmp::Reverse(b.1));
    report.oversize = report.oversize_files.len() as u64;
    (out, report)
}

fn relativize(path: &Path, root: &Path) -> Option<String> {
    let rel = path.strip_prefix(root).ok()?;
    Some(rel.to_string_lossy().replace('\\', "/"))
}

fn symlink_escapes(path: &Path, root_resolved: &Path) -> bool {
    match path.canonicalize() {
        Ok(target) => !target.starts_with(root_resolved),
        Err(_) => true,
    }
}

fn file_size(path: &Path) -> Option<u64> {
    path.metadata().ok().map(|m| m.len())
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = entries.flatten().collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let path = entry.path();
        let file_type = entry.file_type().ok();
        if file_type.is_some_and(|t| t.is_symlink()) {
            if path.is_file() {
                out.push(path);
            }
            continue;
        }
        if file_type.is_some_and(|t| t.is_dir()) {
            collect_files(&path, out);
        } else if file_type.is_some_and(|t| t.is_file()) {
            out.push(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, rel: &str, contents: &str) {
        let path = dir.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }

    #[test]
    fn finds_ordinary_files_sorted() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "b.rs", "");
        write(dir.path(), "a.rs", "");
        let (files, report) = walk_repo(dir.path(), &WalkConfig::new());
        assert_eq!(files, vec!["a.rs", "b.rs"]);
        assert!(report.dirs.is_empty());
    }

    #[test]
    fn excludes_default_dirs_at_any_depth() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "src/main.rs", "");
        write(dir.path(), "node_modules/pkg/index.js", "");
        let (files, report) = walk_repo(dir.path(), &WalkConfig::new());
        assert_eq!(files, vec!["src/main.rs"]);
        assert_eq!(report.dirs.get("node_modules").copied(), Some(1));
    }

    #[test]
    fn dir_exclusion_is_case_insensitive() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "NODE_MODULES/pkg/index.js", "");
        let (files, _) = walk_repo(dir.path(), &WalkConfig::new());
        assert!(files.is_empty());
    }

    #[test]
    fn excludes_default_extensions() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "logo.png", "");
        write(dir.path(), "main.rs", "");
        let (files, report) = walk_repo(dir.path(), &WalkConfig::new());
        assert_eq!(files, vec!["main.rs"]);
        assert_eq!(report.exts.get(".png").copied(), Some(1));
    }

    #[test]
    fn excludes_multi_dot_extensions_via_suffix_match() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "bundle.min.js", "");
        let (files, report) = walk_repo(dir.path(), &WalkConfig::new());
        assert!(files.is_empty());
        assert_eq!(report.exts.get(".min.js").copied(), Some(1));
    }

    #[test]
    fn excludes_default_globs_including_root_level_files() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "LICENSE", "");
        write(dir.path(), "src/test_foo.py", "");
        let (files, report) = walk_repo(dir.path(), &WalkConfig::new());
        assert!(files.is_empty());
        assert_eq!(report.globs.get("**/LICENSE").copied(), Some(1));
        assert_eq!(report.globs.get("**/test_*.py").copied(), Some(1));
    }

    #[test]
    fn excludes_oversize_files_sorted_by_size_descending() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "small.rs", "x");
        write(dir.path(), "big.rs", &"x".repeat(4000));
        write(dir.path(), "huge.rs", &"x".repeat(8000));
        let mut config = WalkConfig::new();
        config.max_file_kb = 1;
        let (files, report) = walk_repo(dir.path(), &config);
        assert_eq!(files, vec!["small.rs"]);
        assert_eq!(report.oversize, 2);
        assert_eq!(report.oversize_files[0].0, "huge.rs");
        assert_eq!(report.oversize_files[1].0, "big.rs");
    }

    #[test]
    fn config_supplied_exclusions_are_additive_not_replacing() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "custom_dir/a.rs", "");
        write(dir.path(), "node_modules/b.js", "");
        let mut config = WalkConfig::new();
        config.exclude_dirs = vec!["custom_dir".to_string()];
        let (files, _) = walk_repo(dir.path(), &config);
        assert!(files.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_file_whose_target_is_in_tree_is_followed() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "real.rs", "content");
        std::os::unix::fs::symlink(dir.path().join("real.rs"), dir.path().join("link.rs")).unwrap();
        let (files, report) = walk_repo(dir.path(), &WalkConfig::new());
        assert_eq!(files, vec!["link.rs", "real.rs"]);
        assert!(report.symlinks.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_file_whose_target_escapes_root_is_dropped() {
        let base = tempfile::tempdir().unwrap();
        let root = base.path().join("root");
        std::fs::create_dir(&root).unwrap();
        let outside = base.path().join("secret.txt");
        std::fs::write(&outside, "ssh key or similar").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("link.txt")).unwrap();
        let (files, report) = walk_repo(&root, &WalkConfig::new());
        assert!(files.is_empty());
        assert_eq!(report.symlinks.get("link.txt").copied(), Some(1));
    }

    #[cfg(unix)]
    #[test]
    fn a_broken_symlink_is_silently_excluded_not_counted() {
        let dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(
            dir.path().join("does_not_exist"),
            dir.path().join("broken.rs"),
        )
        .unwrap();
        let (files, report) = walk_repo(dir.path(), &WalkConfig::new());
        assert!(files.is_empty());
        assert!(report.symlinks.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_directory_is_neither_recursed_into_nor_collected() {
        let base = tempfile::tempdir().unwrap();
        let root = base.path().join("root");
        std::fs::create_dir(&root).unwrap();
        let outside_dir = base.path().join("outside_dir");
        std::fs::create_dir(&outside_dir).unwrap();
        std::fs::write(outside_dir.join("secret.rs"), "").unwrap();
        std::os::unix::fs::symlink(&outside_dir, root.join("link_dir")).unwrap();
        let (files, _) = walk_repo(&root, &WalkConfig::new());
        assert!(files.is_empty());
    }

    #[test]
    fn walk_config_default_matches_new() {
        assert_eq!(WalkConfig::default(), WalkConfig::new());
    }

    #[test]
    fn a_nonexistent_root_yields_no_files_without_panicking() {
        let (files, report) = walk_repo(Path::new("/does/not/exist_xyz_bc"), &WalkConfig::new());
        assert!(files.is_empty());
        assert!(report.dirs.is_empty());
    }

    #[test]
    fn relativize_is_none_when_path_shares_no_prefix_with_root() {
        assert_eq!(
            relativize(Path::new("/unrelated"), Path::new("/root")),
            None
        );
    }

    #[test]
    fn symlink_escapes_is_true_when_the_target_cannot_be_resolved() {
        assert!(symlink_escapes(
            Path::new("/does/not/exist_xyz_bc"),
            Path::new("/root")
        ));
    }

    #[test]
    fn file_size_is_none_for_a_nonexistent_path() {
        assert_eq!(file_size(Path::new("/does/not/exist_xyz_bc")), None);
    }

    #[cfg(target_os = "linux")]
    fn bury_near_path_max(staged: &Path) -> PathBuf {
        const TARGET: usize = 4096 - 100;
        let mut deep = staged.parent().unwrap().canonicalize().unwrap();
        while TARGET.saturating_sub(deep.as_os_str().len() + 1) > 255 {
            deep.push("d".repeat(200));
        }
        std::fs::create_dir_all(&deep).unwrap();
        let buried = deep.join("r".repeat(TARGET - deep.as_os_str().len() - 1));
        std::fs::rename(staged, &buried).unwrap();
        buried
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_listed_file_that_can_no_longer_be_stat_ed_is_silently_skipped() {
        let base = tempfile::tempdir().unwrap();
        let staged = base.path().join("staged");
        std::fs::create_dir(&staged).unwrap();
        std::fs::write(staged.join("ok.txt"), "hello").unwrap();
        std::fs::write(staged.join("f".repeat(200)), "hello").unwrap();
        let root = bury_near_path_max(&staged);
        let (files, report) = walk_repo(&root, &WalkConfig::new());
        assert_eq!(files, vec!["ok.txt".to_string()]);
        assert_eq!(report, ExclusionReport::default());
    }
}
