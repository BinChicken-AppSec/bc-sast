//! The post-gate's bounded, no-follow worktree walk, ported from
//! `remediation_agent/policy/postgate.py::worktree_forbidden_matches`
//! (v1.4.0).
//!
//! **Why this is its own module.** The walk it replaces descended into
//! every directory `Path::is_dir` reported, and `is_dir` follows symlinks:
//! a scanned repository containing `loop -> .` recursed until the path
//! grew past `ENAMETOOLONG`, and one containing `root -> /` walked the
//! whole host filesystem. It also collected the complete file list before
//! the file cap was consulted, so the cap bounded only how many results
//! were *kept*, not how much work was done. The scanned repository is
//! untrusted input, so both are a denial of service any hostile checkout
//! can trigger.
//!
//! This walk never descends into a symlinked directory (the same guarantee
//! Python gets from `os.walk(followlinks=False)`), counts directories and
//! files against separate caps, and stops the moment either is exceeded.

use std::path::Path;

/// Files examined before the walk gives up, ported from
/// `_WORKTREE_SCAN_MAX`. Only regular files count, so a vendored
/// `node_modules/` full of directories cannot use the budget up on its own.
pub(crate) const WORKTREE_SCAN_MAX: usize = 20_000;

/// Directories visited before the walk gives up, ported from
/// `_WORKTREE_DIR_MAX`. Bounds a merely huge (non-cyclic) tree the same way
/// [`WORKTREE_SCAN_MAX`] bounds the file count; a cyclic one is already
/// impossible because symlinked directories are never entered.
pub(crate) const WORKTREE_DIR_MAX: usize = 20_000;

/// Repo-relative POSIX paths of files in `repo`'s working tree that match
/// any of `patterns` (via [`bc_policy_gate::glob_match`]). The non-git
/// fallback ground truth for the post-gate, and the pre-agent snapshot's
/// target list. Best effort: an unreadable directory is skipped, never an
/// error.
pub(crate) fn worktree_forbidden_matches(repo: &Path, patterns: &[String]) -> Vec<String> {
    worktree_forbidden_matches_capped(repo, patterns, WORKTREE_SCAN_MAX, WORKTREE_DIR_MAX)
}

/// [`worktree_forbidden_matches`] with injectable caps, so a test can hit
/// each one without building a 20,000-entry tree.
pub(crate) fn worktree_forbidden_matches_capped(
    repo: &Path,
    patterns: &[String],
    max_files: usize,
    max_dirs: usize,
) -> Vec<String> {
    let mut out = Vec::new();
    if patterns.is_empty() {
        return out;
    }
    let mut files_seen = 0usize;
    let mut dirs_seen = 0usize;
    let mut stack = vec![repo.to_path_buf()];
    while let Some(dir) = stack.pop() {
        dirs_seen += 1;
        if dirs_seen > max_dirs {
            break;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        // `DirEntry::file_type` does NOT follow symlinks, which is the
        // whole point: a symlinked directory reports as a symlink here and
        // is never pushed onto the stack. An entry whose type cannot be
        // read is skipped like an unreadable directory.
        let typed = entries
            .flatten()
            .filter_map(|e| Some((e.file_type().ok()?, e.path())));
        for (kind, path) in typed {
            if kind.is_dir() {
                stack.push(path);
                continue;
            }
            // A symlink to a regular file counts as a file, exactly as
            // Python's `Path.is_file()` (which follows) counts it. Only its
            // NAME is matched here; any later read goes through
            // `bc_pathjail::confine`, so a link pointing out of the repo is
            // never opened on the strength of this list.
            let is_file = kind.is_file() || (kind.is_symlink() && path.is_file());
            if !is_file {
                continue;
            }
            files_seen += 1;
            if files_seen > max_files {
                return out;
            }
            let rel = path
                .strip_prefix(repo)
                .expect("the walk only yields paths nested under repo")
                .to_string_lossy()
                .replace('\\', "/");
            if patterns.iter().any(|p| bc_policy_gate::glob_match(&rel, p)) {
                out.push(rel);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(root: &Path, rel: &str) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "x").unwrap();
    }

    fn patterns(p: &[&str]) -> Vec<String> {
        p.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn empty_patterns_walk_nothing() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), ".env");
        assert!(worktree_forbidden_matches(dir.path(), &[]).is_empty());
    }

    #[test]
    fn matches_nested_files_by_glob() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), ".github/workflows/ci.yml");
        write(dir.path(), "src/app.py");
        let mut hits = worktree_forbidden_matches(dir.path(), &patterns(&[".github/**"]));
        hits.sort();
        assert_eq!(hits, vec![".github/workflows/ci.yml".to_string()]);
    }

    #[test]
    fn an_unreadable_start_directory_yields_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing");
        assert!(worktree_forbidden_matches(&missing, &patterns(&["**"])).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_loop_is_never_descended() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a/secret.pem");
        std::os::unix::fs::symlink(dir.path(), dir.path().join("a/loop")).unwrap();
        std::os::unix::fs::symlink(".", dir.path().join("self")).unwrap();
        let hits = worktree_forbidden_matches(dir.path(), &patterns(&["**/*.pem"]));
        assert_eq!(hits, vec!["a/secret.pem".to_string()]);
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_to_a_directory_outside_the_repo_is_not_walked() {
        let base = tempfile::tempdir().unwrap();
        let repo = base.path().join("repo");
        let outside = base.path().join("outside");
        write(&outside, "leak.pem");
        std::fs::create_dir_all(&repo).unwrap();
        std::os::unix::fs::symlink(&outside, repo.join("out")).unwrap();
        std::os::unix::fs::symlink("/", repo.join("root")).unwrap();
        assert!(worktree_forbidden_matches(&repo, &patterns(&["**"])).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_to_a_file_counts_by_name_but_a_dangling_one_does_not() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "real.txt");
        std::os::unix::fs::symlink(dir.path().join("real.txt"), dir.path().join(".env")).unwrap();
        std::os::unix::fs::symlink(dir.path().join("gone"), dir.path().join("dangling.env"))
            .unwrap();
        let hits = worktree_forbidden_matches(dir.path(), &patterns(&["*.env", ".env"]));
        assert_eq!(hits, vec![".env".to_string()]);
    }

    #[test]
    fn the_file_cap_stops_the_walk_early() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..5 {
            write(dir.path(), &format!("f{i}.pem"));
        }
        let hits = worktree_forbidden_matches_capped(dir.path(), &patterns(&["*.pem"]), 2, 100);
        assert_eq!(hits.len(), 2);
    }

    #[test]
    fn the_directory_cap_stops_the_walk_early() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a/x.pem");
        write(dir.path(), "b/x.pem");
        write(dir.path(), "c/x.pem");
        // One directory allowed: only the root is visited, and the root
        // holds no files, so nothing matches however many there are below.
        let hits = worktree_forbidden_matches_capped(dir.path(), &patterns(&["**"]), 100, 1);
        assert!(hits.is_empty());
        let hits = worktree_forbidden_matches_capped(dir.path(), &patterns(&["**"]), 100, 2);
        assert_eq!(hits.len(), 1);
    }
}
