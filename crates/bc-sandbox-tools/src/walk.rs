//! Shared jailed file-listing helpers used by both the `Glob` tool
//! ([`crate::glob`]) and the whole-repo/glob-restricted branches of the
//! `Grep` tool ([`crate::grep`]), ported from the file-collection halves of
//! `backends/localtools.py`'s `_glob`/`_grep`.

use std::path::{Path, PathBuf};

/// Every file reachable via a glob `pattern` rooted at `root`, confined and
/// sorted. Mirrors `root.glob(pattern)` filtered through `_jail` in the
/// Python original.
pub fn glob_jailed_files(root: &Path, pattern: &str) -> Vec<PathBuf> {
    let pattern = pattern.trim_start_matches(['/', '\\']);
    let full_pattern = root.join(pattern);
    let Some(full_pattern) = full_pattern.to_str() else {
        return Vec::new();
    };
    let Ok(entries) = glob::glob(full_pattern) else {
        return Vec::new();
    };
    let mut hits: Vec<PathBuf> = entries.flatten().filter(|p| jailed_file(root, p)).collect();
    hits.sort();
    hits
}

/// Every file under `dir` (which must itself be inside `root`), confined
/// and sorted, walked recursively. Mirrors `dir.rglob("*")` filtered
/// through `_jail` in the Python original.
pub fn walk_jailed_files(root: &Path, dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    walk_into(root, dir, &mut out);
    out.sort();
    out
}

fn walk_into(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !jailed_file_or_dir(root, &path) {
            continue;
        }
        if path.is_dir() {
            walk_into(root, &path, out);
        } else if path.is_file() {
            out.push(path);
        }
    }
}

/// Re-confine `path` (already discovered on disk under `root`) against
/// `root` — a defense-in-depth symlink-escape guard, same spirit as the
/// Python original's `_jail(root, str(p)) is not None` re-check on every
/// discovered entry rather than trusting the walk/glob call alone.
fn jailed_file(root: &Path, path: &Path) -> bool {
    path.is_file() && rel_confined(root, path)
}

fn jailed_file_or_dir(root: &Path, path: &Path) -> bool {
    rel_confined(root, path)
}

fn rel_confined(root: &Path, path: &Path) -> bool {
    let Ok(rel) = path.strip_prefix(root) else {
        return false;
    };
    let rel_str = rel.to_string_lossy().replace('\\', "/");
    bc_pathjail::confine(root, &rel_str).is_some()
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
    fn glob_jailed_files_finds_matches_recursively() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.rs", "");
        write(dir.path(), "sub/b.rs", "");
        write(dir.path(), "sub/c.txt", "");
        let mut hits = glob_jailed_files(dir.path(), "**/*.rs");
        hits.sort();
        assert_eq!(
            hits,
            vec![dir.path().join("a.rs"), dir.path().join("sub/b.rs")]
        );
    }

    #[test]
    fn glob_jailed_files_strips_a_leading_slash_from_the_pattern() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.rs", "");
        assert_eq!(
            glob_jailed_files(dir.path(), "/*.rs"),
            vec![dir.path().join("a.rs")]
        );
    }

    #[test]
    fn glob_jailed_files_with_an_invalid_pattern_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(glob_jailed_files(dir.path(), "[").is_empty());
    }

    #[test]
    fn glob_jailed_files_ignores_directories() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "sub/b.rs", "");
        let hits = glob_jailed_files(dir.path(), "*");
        assert!(hits.is_empty()); // "sub" itself is a directory, not a file
    }

    #[test]
    fn walk_jailed_files_walks_recursively_and_sorts() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "b.txt", "");
        write(dir.path(), "sub/a.txt", "");
        assert_eq!(
            walk_jailed_files(dir.path(), dir.path()),
            vec![dir.path().join("b.txt"), dir.path().join("sub/a.txt")]
        );
    }

    #[test]
    fn walk_jailed_files_on_a_nonexistent_directory_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(walk_jailed_files(dir.path(), &dir.path().join("missing")).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn glob_jailed_files_with_a_non_utf8_root_is_empty() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let dir = tempfile::tempdir().unwrap();
        let bad_root = dir.path().join(OsStr::from_bytes(&[0xff, 0xfe]));
        assert!(glob_jailed_files(&bad_root, "*.txt").is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn walk_jailed_files_does_not_follow_a_symlink_that_escapes_root() {
        let base = tempfile::tempdir().unwrap();
        let root = base.path().join("root");
        std::fs::create_dir(&root).unwrap();
        write(&root, "inside.txt", "");
        let outside = base.path().join("outside.txt");
        std::fs::write(&outside, "").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("escape_link")).unwrap();

        assert_eq!(
            walk_jailed_files(&root, &root),
            vec![root.join("inside.txt")]
        );
    }

    #[test]
    fn rel_confined_is_false_when_path_shares_no_prefix_with_root() {
        // Genuinely unreachable via `walk_into`/`glob_jailed_files`'s real
        // call sites, which only ever construct `path` as a literal
        // extension of `root`'s own components (even a `..`-containing
        // glob match still retains `root` as a literal prefix, so
        // `strip_prefix` always succeeds there) — exercised directly
        // instead of left as an untested "just in case" branch.
        assert!(!rel_confined(
            Path::new("/root/a"),
            Path::new("/unrelated/b")
        ));
    }
}
