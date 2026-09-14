//! The deterministic repo walk, ported from
//! `s1_preprocess.py::_walk_repo`/`_exclusion_sets` — guarantees every
//! later stage sees every source file regardless of what an agentic
//! exploration happened to look at.

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

/// `step1.{exclude_dirs,exclude_exts,exclude_globs,max_file_kb}` — additive
/// on top of the built-in defaults above (dirs/exts unioned, globs
/// appended), matching `_exclusion_sets`.
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
    /// Sorted by size descending, matching
    /// `sorted(skipped_size, key=lambda kv: -kv[1])`.
    pub oversize_files: Vec<(String, u64)>,
    pub symlinks: BTreeMap<String, u64>,
}

/// Walk `root`, returning (sorted repo-relative POSIX file paths, exclusion
/// stats). A symlink whose target resolves outside `root` is dropped
/// unconditionally — not configurable — since following it would pull
/// arbitrary host file content into the inventory and LLM prompts.
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
        // Infallible here: every `path` came from `collect_files(root,
        // ...)` moments ago, which only ever builds paths as literal
        // extensions of `root` itself — no filesystem race can change
        // that (unlike `symlink_escapes`/`file_size` below, which re-stat
        // the path and so can genuinely observe a TOCTOU change).
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

/// `path`'s location relative to `root`, POSIX-separated. Split out from
/// `walk_repo`'s loop so its `None` case — genuinely unreachable through
/// the real call path, since every candidate comes from
/// `collect_files(root, ...)`, which only ever builds paths as literal
/// extensions of `root` itself — is directly testable instead of left as
/// an untested "just in case" branch.
fn relativize(path: &Path, root: &Path) -> Option<String> {
    let rel = path.strip_prefix(root).ok()?;
    Some(rel.to_string_lossy().replace('\\', "/"))
}

/// Whether `path` (already known to be a symlink) resolves outside
/// `root_resolved`. A `canonicalize` failure (the target vanishing between
/// `collect_files`'s own `is_file()` check and this call — a TOCTOU race)
/// is treated as an escape, fail-closed; not reachable through a normal,
/// non-racing call path, so exercised directly with a path that never
/// existed at all.
fn symlink_escapes(path: &Path, root_resolved: &Path) -> bool {
    match path.canonicalize() {
        Ok(target) => !target.starts_with(root_resolved),
        Err(_) => true,
    }
}

/// `path`'s size in bytes, or `None` if it can no longer be stat'd (same
/// TOCTOU-race reasoning as [`symlink_escapes`] — `collect_files` already
/// confirmed it was a file moments earlier).
fn file_size(path: &Path) -> Option<u64> {
    path.metadata().ok().map(|m| m.len())
}

/// Files reachable under `dir`: regular files (recursing into real
/// subdirectories) and symlinks-to-files, matching `Path.rglob("*")` +
/// `is_file()`. A symlinked *directory* is neither recursed into nor
/// itself collected — `rglob` does not follow directory symlinks during
/// recursion, so its contents are invisible to the walk entirely, same as
/// the Python original observes.
fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = entries.flatten().collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let path = entry.path();
        // `entry.file_type()` is a cheap dirent-cached read needing no
        // extra permission on `dir` (unlike a full `metadata()`/`stat`
        // call, which needs search/execute permission to resolve the
        // path — see `file_size` above, which genuinely can and does
        // observe that difference). Collapsed via `.ok()`/`unwrap_or`
        // rather than an explicit `continue` on `Err` — a failure here
        // (the entry vanishing between being listed and typed, on a
        // filesystem without cached dirent types) then simply matches
        // none of the checks below, which is the same "skip it" outcome
        // without a distinct branch that's this hard to exercise.
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
        assert!(files.is_empty()); // both the built-in AND the custom dir are excluded
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
        // Matches Python: `Path.is_file()` follows symlinks and is False
        // for a broken one, so `_walk_repo`'s very first `if not
        // p.is_file(): continue` drops it before ever reaching the
        // symlink-escape check — it never increments `skipped_symlinks`
        // either.
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

    #[cfg(unix)]
    #[test]
    fn a_file_whose_directory_loses_search_permission_is_silently_skipped() {
        // `DirEntry::file_type()` (used by `collect_files` to identify a
        // regular file) is a cheap dirent-type read that needs only
        // *read* permission on the containing directory, but a full
        // `metadata()` call needs *execute* (search) permission to
        // resolve the path — so a directory with read-but-not-execute
        // permissions lets a file be discovered as a candidate and then
        // genuinely fail to stat, a real (if unusual) misconfiguration
        // rather than a contrived race.
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(sub.join("file.txt"), "hello").unwrap();
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o444)).unwrap();
        let (files, _) = walk_repo(dir.path(), &WalkConfig::new());
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(files.is_empty(), "unexpected files: {files:?}");
    }
}
