//! Shared jailed file-listing helpers used by both the `Glob` tool
//! ([`crate::glob`]) and the whole-repo/glob-restricted branches of the
//! `Grep` tool ([`crate::grep`]), ported from the file-collection halves of
//! `backends/localtools.py`'s `_glob`/`_grep`.

use std::path::{Path, PathBuf};

/// Every file reachable via a glob `pattern` rooted at `root`, confined and
/// sorted. Mirrors `root.glob(pattern)` filtered through `_jail` in the
/// Python original.
///
/// Matched against the same no-follow walk as [`walk_jailed_files`]
/// rather than through `glob::glob`, which expands `**` by following
/// symlinked directories: a repository containing `ln -s . x` made a
/// single `Glob("**/*.rs")` call enumerate every `x/x/x/...` path until
/// `ELOOP`, exponentially with several such links. The walk starts at the
/// pattern's literal leading directories (confined, so a `link/*` whose
/// `link` points out of the repo finds nothing) and, when the pattern has
/// no `**`, descends only as deep as the pattern can match.
pub fn glob_jailed_files(root: &Path, pattern: &str) -> Vec<PathBuf> {
    let pattern = pattern.trim_start_matches(['/', '\\']);
    let Ok(matcher) = glob::Pattern::new(pattern) else {
        return Vec::new();
    };
    let components: Vec<&str> = pattern.split('/').collect();
    let literal = components[..components.len() - 1]
        .iter()
        .take_while(|c| !c.contains(['*', '?', '[']))
        .count();
    let prefix = components[..literal].join("/");
    let start = root.join(&prefix);
    if !prefix.is_empty() && bc_pathjail::confine(root, &prefix).is_none() {
        return Vec::new();
    }
    let max_depth = (!pattern.contains("**")).then(|| components.len() - literal);
    let options = glob::MatchOptions {
        case_sensitive: true,
        require_literal_separator: true,
        require_literal_leading_dot: false,
    };
    walk(root, &start, &|_| false, max_depth)
        .into_iter()
        .filter(|path| {
            path.strip_prefix(root)
                .is_ok_and(|rel| matcher.matches_path_with(rel, options))
        })
        .collect()
}

/// Every file under `dir` (which must itself be inside `root`), confined
/// and sorted, walked recursively. Mirrors `dir.rglob("*")` filtered
/// through `_jail` in the Python original, minus its one hazard: see
/// [`walk_jailed_files_pruned`].
pub fn walk_jailed_files(root: &Path, dir: &Path) -> Vec<PathBuf> {
    walk_jailed_files_pruned(root, dir, &|_| false)
}

/// [`walk_jailed_files`], additionally never entering a directory whose
/// bare name `prune` accepts, so an excluded `node_modules/` costs one
/// `read_dir` entry rather than a walk of everything under it (ported from
/// `validation/tools/_scope.py`'s in-place `dir_names[:]` filter).
///
/// **Symlinked directories are never entered**, the guarantee Python's
/// `os.walk(followlinks=False)` gives. The walk this replaced asked
/// `Path::is_dir`, which follows links, so a repository containing
/// `loop -> .` recursed until the path hit `ELOOP`, and several such links
/// made that exponential: a denial of service any scanned checkout could
/// trigger through a single `Grep` call. A symlinked FILE is still listed,
/// but only when it resolves inside `root` (Python's
/// `_escapes_workspace`), so a link to `/etc/shadow` never reaches a
/// reader. A plain file needs no such check: it was reached without
/// crossing a link, so it is inside `root` by construction.
///
/// Iterative rather than recursive, so a pathologically deep tree cannot
/// exhaust the thread's stack either.
pub(crate) fn walk_jailed_files_pruned(
    root: &Path,
    dir: &Path,
    prune: &dyn Fn(&str) -> bool,
) -> Vec<PathBuf> {
    walk(root, dir, prune, None)
}

/// The walk itself. `max_depth` (when set) is the deepest level a file
/// may sit at, counting a file directly in `dir` as level 1: directories
/// that could only hold deeper files are not entered.
fn walk(
    root: &Path,
    dir: &Path,
    prune: &dyn Fn(&str) -> bool,
    max_depth: Option<usize>,
) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![(dir.to_path_buf(), 0usize)];
    while let Some((current, level)) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&current) else {
            continue;
        };
        // `DirEntry::file_type` does not follow symlinks. An entry whose
        // type cannot be read is skipped, like an unreadable directory.
        let typed = entries
            .flatten()
            .filter_map(|e| Some((e.file_type().ok()?, e.path(), e.file_name())));
        for (kind, path, name) in typed {
            if kind.is_dir() {
                let deeper = max_depth.is_none_or(|max| level + 1 < max);
                if deeper && !prune(&name.to_string_lossy()) {
                    stack.push((path, level + 1));
                }
            } else if kind.is_file() || (kind.is_symlink() && jailed_file(root, &path)) {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

/// Re-confine `path` (already discovered on disk under `root`) against
/// `root` — a defense-in-depth symlink-escape guard, same spirit as the
/// Python original's `_jail(root, str(p)) is not None` re-check on every
/// discovered entry rather than trusting the walk/glob call alone.
fn jailed_file(root: &Path, path: &Path) -> bool {
    path.is_file() && rel_confined(root, path)
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

    #[cfg(unix)]
    #[test]
    fn walk_jailed_files_never_descends_a_symlink_loop() {
        // `ln -s . x` three times over: the old `is_dir`-following walk
        // recursed through every combination until ELOOP.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        write(&root, "a.txt", "");
        write(&root, "sub/b.txt", "");
        for link in ["x", "y", "sub/z"] {
            std::os::unix::fs::symlink(".", root.join(link)).unwrap();
        }
        std::os::unix::fs::symlink(&root, root.join("sub/back")).unwrap();
        assert_eq!(
            walk_jailed_files(&root, &root),
            vec![root.join("a.txt"), root.join("sub/b.txt")]
        );
    }

    #[cfg(unix)]
    #[test]
    fn walk_jailed_files_does_not_enter_a_symlink_to_a_directory_outside_root() {
        let base = tempfile::tempdir().unwrap();
        let base = base.path().canonicalize().unwrap();
        let root = base.join("root");
        write(&base, "outside/secret.txt", "");
        std::fs::create_dir(&root).unwrap();
        std::os::unix::fs::symlink(base.join("outside"), root.join("out")).unwrap();
        std::os::unix::fs::symlink("/", root.join("slash")).unwrap();
        assert!(walk_jailed_files(&root, &root).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn walk_jailed_files_keeps_a_symlinked_file_that_stays_inside_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        write(&root, "real.txt", "");
        std::os::unix::fs::symlink(root.join("real.txt"), root.join("alias.txt")).unwrap();
        assert_eq!(
            walk_jailed_files(&root, &root),
            vec![root.join("alias.txt"), root.join("real.txt")]
        );
    }

    #[test]
    fn walk_jailed_files_pruned_skips_a_pruned_directory_without_entering_it() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "keep/a.txt", "");
        write(dir.path(), "node_modules/b.txt", "");
        let hits = walk_jailed_files_pruned(dir.path(), dir.path(), &|name| name == "node_modules");
        assert_eq!(hits, vec![dir.path().join("keep/a.txt")]);
    }

    #[cfg(unix)]
    #[test]
    fn glob_jailed_files_never_expands_through_a_symlink_loop() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        write(&root, "a.rs", "");
        write(&root, "sub/b.rs", "");
        for link in ["x", "y", "sub/z"] {
            std::os::unix::fs::symlink(".", root.join(link)).unwrap();
        }
        assert_eq!(
            glob_jailed_files(&root, "**/*.rs"),
            vec![root.join("a.rs"), root.join("sub/b.rs")]
        );
    }

    #[cfg(unix)]
    #[test]
    fn glob_jailed_files_through_a_literal_symlink_prefix_stays_confined() {
        let base = tempfile::tempdir().unwrap();
        let base = base.path().canonicalize().unwrap();
        let root = base.join("root");
        write(&base, "outside/secret.rs", "");
        write(&root, "real/inner.rs", "");
        std::os::unix::fs::symlink(base.join("outside"), root.join("out")).unwrap();
        std::os::unix::fs::symlink(root.join("real"), root.join("alias")).unwrap();
        assert!(glob_jailed_files(&root, "out/*.rs").is_empty());
        assert_eq!(
            glob_jailed_files(&root, "alias/*.rs"),
            vec![root.join("alias/inner.rs")]
        );
    }

    #[test]
    fn glob_jailed_files_matches_literal_paths_and_respects_separators() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "src/main.rs", "");
        write(dir.path(), "src/deep/lib.rs", "");
        write(dir.path(), "top.rs", "");
        assert_eq!(
            glob_jailed_files(dir.path(), "src/main.rs"),
            vec![dir.path().join("src/main.rs")]
        );
        // A single `*` never crosses a `/`, as with `glob::glob`.
        assert_eq!(
            glob_jailed_files(dir.path(), "*.rs"),
            vec![dir.path().join("top.rs")]
        );
        assert_eq!(
            glob_jailed_files(dir.path(), "src/*.rs"),
            vec![dir.path().join("src/main.rs")]
        );
        assert_eq!(
            glob_jailed_files(dir.path(), "*/*/*.rs"),
            vec![dir.path().join("src/deep/lib.rs")]
        );
        assert!(glob_jailed_files(dir.path(), "missing/*.rs").is_empty());
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
