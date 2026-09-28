//! The fact tools' scan scope: which files `PatternScan` and
//! `TestInventory` may look at, ported from `validation/tools/_scope.py`
//! (vvaharness v1.4.0).
//!
//! Three rules, all applied during the walk rather than after it:
//! - infra/vendor directories ([`bc_repo_analysis::DEFAULT_EXCLUDE_DIRS`]
//!   minus the test directories) are pruned before they are entered, and
//!   the test directories too unless tests are wanted;
//! - binary/media extensions are skipped;
//! - when tests are excluded, S1's own test-file and repository-metadata
//!   globs ([`bc_repo_analysis::default_exclude_globs`]) are applied as
//!   well, so a root-level `test_login.py` or a `LICENSE` is not scanned as
//!   production surface.
//!
//! Symlink handling (never entering a linked directory, dropping a linked
//! file that escapes the root) is [`crate::walk::walk_jailed_files_pruned`]'s.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;

use crate::walk::walk_jailed_files_pruned;

/// The production exclude set mixes infra/vendor dirs with test dirs. The
/// secret scan wants both gone (tests are not production surface); the
/// test inventory needs the test dirs kept. This is the test half of that
/// partition (`validation/tools/_scope.py:36-39`); the infra half is
/// whatever remains of [`bc_repo_analysis::DEFAULT_EXCLUDE_DIRS`].
pub(crate) const TEST_DIRS: [&str; 11] = [
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
];

pub(crate) static INFRA_DIRS: LazyLock<BTreeSet<String>> = LazyLock::new(|| {
    bc_repo_analysis::DEFAULT_EXCLUDE_DIRS
        .iter()
        .map(|d| d.to_lowercase())
        .filter(|d| !TEST_DIRS.contains(&d.as_str()))
        .collect()
});

static EXCLUDE_EXTS: LazyLock<Vec<String>> = LazyLock::new(|| {
    bc_repo_analysis::DEFAULT_EXCLUDE_EXTS
        .iter()
        .map(|e| e.to_lowercase())
        .collect()
});

/// `true` when a directory named `name` is outside the scan scope.
fn excluded_dir(name: &str, include_tests: bool) -> bool {
    let lowered = name.to_lowercase();
    INFRA_DIRS.contains(&lowered) || (!include_tests && TEST_DIRS.contains(&lowered.as_str()))
}

/// `true` when the file at repo-relative `rel` is outside the scan scope,
/// ported from `_excluded_file`.
fn excluded_file(rel: &str, include_tests: bool) -> bool {
    let name = rel.rsplit('/').next().unwrap_or(rel).to_lowercase();
    if EXCLUDE_EXTS.iter().any(|ext| name.ends_with(ext)) {
        return true;
    }
    !include_tests && S1_EXCLUDE_GLOBS.iter().any(|g| g.hits(rel))
}

/// One of S1's default exclude globs, compiled once.
///
/// `bc_repo_analysis::glob_hit` is the semantic reference (fnmatch, where
/// `*` also crosses `/`, plus a `**/x` pattern matching a root-level `x`),
/// but it translates the pattern to a fresh regex on every call: tens of
/// thousands of compilations for one scan of a large tree, which made a
/// 10,000-file `PatternScan` take over a minute. The default list only
/// uses `*` and literal characters, so the same translation is done once
/// here; `compiled_globs_agree_with_glob_hit` pins the two together.
struct CompiledGlob {
    full: Regex,
    /// For a `**/x` pattern, `x` alone, matched against the file name.
    name: Option<Regex>,
}

impl CompiledGlob {
    fn new(pattern: &str) -> Self {
        CompiledGlob {
            full: fnmatch_regex(pattern),
            name: pattern.strip_prefix("**/").map(fnmatch_regex),
        }
    }

    fn hits(&self, rel: &str) -> bool {
        let name = rel.rsplit('/').next().unwrap_or(rel);
        self.full.is_match(rel) || self.name.as_ref().is_some_and(|n| n.is_match(name))
    }
}

/// fnmatch's translation for the `*`/`?`/literal subset: `*` is `.*`
/// (crossing `/`, as fnmatch does), `?` is `.`, anything else literal.
fn fnmatch_regex(pattern: &str) -> Regex {
    let mut out = String::from("(?s)^");
    for c in pattern.chars() {
        match c {
            '*' => out.push_str(".*"),
            '?' => out.push('.'),
            c => out.push_str(&regex::escape(&c.to_string())),
        }
    }
    out.push('$');
    Regex::new(&out).expect("an escaped fnmatch translation is always a valid regex")
}

static S1_EXCLUDE_GLOBS: LazyLock<Vec<CompiledGlob>> = LazyLock::new(|| {
    bc_repo_analysis::default_exclude_globs()
        .iter()
        .map(|g| CompiledGlob::new(g))
        .collect()
});

/// Every file under `root` within the production scan scope, as
/// `(repo-relative POSIX path, absolute path)` pairs sorted by absolute
/// path, ported from `iter_in_scope_files`.
pub(crate) fn iter_in_scope_files(root: &Path, include_tests: bool) -> Vec<(String, PathBuf)> {
    let prune = |name: &str| excluded_dir(name, include_tests);
    walk_jailed_files_pruned(root, root, &prune)
        .into_iter()
        .filter_map(|path| {
            // The walk only ever builds paths by extending `root`, so
            // `strip_prefix` cannot fail; `ok()?` keeps that fact from
            // becoming an untested error arm.
            let rel = path
                .strip_prefix(root)
                .ok()?
                .to_string_lossy()
                .replace('\\', "/");
            (!excluded_file(&rel, include_tests)).then_some((rel, path))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(root: &Path, rel: &str) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "x").unwrap();
    }

    fn rels(root: &Path, include_tests: bool) -> Vec<String> {
        iter_in_scope_files(root, include_tests)
            .into_iter()
            .map(|(rel, _)| rel)
            .collect()
    }

    #[test]
    fn test_dirs_are_a_subset_of_the_production_exclude_set() {
        // Python raises at import time if this drifts; a test is the
        // equivalent tripwire here.
        let production: BTreeSet<String> = bc_repo_analysis::DEFAULT_EXCLUDE_DIRS
            .iter()
            .map(|d| d.to_lowercase())
            .collect();
        for dir in TEST_DIRS {
            assert!(
                production.contains(dir),
                "{dir} missing from production set"
            );
        }
    }

    #[test]
    fn excluded_directories_extensions_and_globs_follow_include_tests() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "src/app.py");
        write(dir.path(), "node_modules/lib.js");
        write(dir.path(), "tests/test_app.py");
        write(dir.path(), "test_root.py");
        write(dir.path(), "LICENSE");
        write(dir.path(), "logo.png");
        assert_eq!(rels(dir.path(), false), vec!["src/app.py".to_string()]);
        assert_eq!(
            rels(dir.path(), true),
            vec![
                "LICENSE".to_string(),
                "src/app.py".to_string(),
                "test_root.py".to_string(),
                "tests/test_app.py".to_string(),
            ]
        );
    }

    #[test]
    fn compiled_globs_agree_with_glob_hit() {
        let globs = bc_repo_analysis::default_exclude_globs();
        assert!(
            globs.iter().all(|g| !g.contains('[')),
            "a default glob now uses a character class; extend fnmatch_regex"
        );
        let samples = [
            "test_x.py",
            "pkg/test_x.py",
            "pkg/test_dir/x.py",
            "a/b/c_test.go",
            "LICENSE",
            "LICENSE.md",
            "docs/LICENSE.txt",
            "src/app.py",
            "src/FooTest.java",
            "web/app.spec.tsx",
            ".gitignore",
            "x/.DS_Store",
            "NOTICE",
            "notice",
            "src/main.rs",
        ];
        for rel in samples {
            assert_eq!(
                S1_EXCLUDE_GLOBS.iter().any(|g| g.hits(rel)),
                bc_repo_analysis::glob_hit(rel, globs).is_some(),
                "{rel}"
            );
        }
        assert!(fnmatch_regex("a?c").is_match("abc"));
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_loop_inside_the_scope_is_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        write(&root, "src/app.py");
        std::os::unix::fs::symlink(".", root.join("src/again")).unwrap();
        std::os::unix::fs::symlink("..", root.join("src/up")).unwrap();
        assert_eq!(rels(&root, false), vec!["src/app.py".to_string()]);
    }
}
