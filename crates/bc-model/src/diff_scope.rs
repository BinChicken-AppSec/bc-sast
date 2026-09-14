//! The changed-file boundary a `--diff-scope` run is confined to, in the
//! one shape every consumer of that boundary can share.
//!
//! `ScanInput.changed_files`/`ContextPackage.changed_files` are the raw
//! fetched diff (path -> changed line numbers) and stay that way: S3's
//! chunk trimming and S4's per-finding backstop both need the map itself.
//! What the *other* consumers need — the provider-ingestion merge point in
//! `bc-orchestrator`, S10's remediation refusal, and anything downstream of
//! either — is only the question "may this file be acted on at all", asked
//! about a path that did not come from this repository's own file walk.
//! Answering it consistently is what this type is for; answering it
//! ad hoc at each site is how a boundary ends up enforced in one place and
//! not the next.
//!
//! Two rules the type enforces on every caller:
//!
//! 1. **`active` is the flag, never `files.is_empty()`.** A pull request of
//!    only renames, deletions, mode changes or binary files parses to zero
//!    changed lines and is still legitimately diff-scoped; such a run must
//!    act on nothing rather than on everything. See `ScanInput`'s own
//!    `changed_files`/`diff_scope_active` doc comments.
//! 2. **An unrecognized path is out of scope.** [`DiffScope::allows`] is a
//!    safety boundary, so it answers `false` for anything it cannot match
//!    exactly after normalization. Third-party vendor reports carry paths
//!    this tool never produced, and guessing (suffix matching, basename
//!    matching) would let a vendor finding in `vendor/lib/app.py` pass for
//!    a changed `src/app.py`.

use std::collections::BTreeSet;

/// The set of files a diff-scoped run is allowed to act on, plus whether
/// scoping is in effect at all.
///
/// [`DiffScope::default`] (and [`DiffScope::inactive`]) is the
/// not-diff-scoped state, which [`DiffScope::allows`] answers `true` for
/// unconditionally — so a full-repo scan behaves exactly as it did before
/// this type existed, and a consumer that simply never sets one is not
/// silently fenced off from its own repository.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DiffScope {
    active: bool,
    files: BTreeSet<String>,
}

/// Repo-relative, forward-slashed, no leading `./` or `/`.
///
/// Deliberately not case-folded, matching `bc_dedup_core::normalize_ref`'s
/// own reasoning: the platforms these scans run on have case-sensitive
/// paths, and folding them would let `Auth.ts` pass for a changed
/// `auth.ts`.
fn normalize(path: &str) -> String {
    let mut normalized = path.trim().replace('\\', "/");
    while let Some(rest) = normalized.strip_prefix("./") {
        normalized = rest.to_string();
    }
    while let Some(rest) = normalized.strip_prefix('/') {
        normalized = rest.to_string();
    }
    normalized
}

impl DiffScope {
    /// No scoping: every file is in scope. The state every caller that
    /// was not passed `--diff-scope` is in.
    pub fn inactive() -> Self {
        DiffScope::default()
    }

    /// An ACTIVE scope over `files`. An empty iterator is a real,
    /// supported state (the rename-only pull request), not a synonym for
    /// [`DiffScope::inactive`].
    pub fn active<I, S>(files: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        DiffScope {
            active: true,
            files: files.into_iter().map(|f| normalize(f.as_ref())).collect(),
        }
    }

    /// [`DiffScope::active`] or [`DiffScope::inactive`], chosen by a flag
    /// the caller already has — the shape every real call site wants,
    /// since each one holds a `diff_scope_active` boolean next to its
    /// changed-file map.
    pub fn new<I, S>(active: bool, files: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        if active {
            DiffScope::active(files)
        } else {
            DiffScope::inactive()
        }
    }

    /// Whether scoping is in effect. `true` with an empty file set is the
    /// rename-only pull request, and acts on nothing.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Whether `file` is one of the diff's changed files, regardless of
    /// whether scoping is active. [`DiffScope::allows`] is what a gate
    /// should ask; this is the raw membership test behind it.
    pub fn contains(&self, file: &str) -> bool {
        self.files.contains(&normalize(file))
    }

    /// The gate: `true` when `file` may be acted on. Always `true` while
    /// scoping is inactive; otherwise exactly [`DiffScope::contains`], so
    /// an unmatched or unnormalizable vendor path fails closed.
    pub fn allows(&self, file: &str) -> bool {
        !self.active || self.contains(file)
    }

    /// `None` when [`DiffScope::allows`] would say yes; otherwise the
    /// operator-facing reason this file is off limits, naming the file and
    /// the flag that fenced it off.
    ///
    /// One shared sentence rather than one per call site: the same refusal
    /// reaches a remediation record, a dropped-finding detail line and a
    /// provider assessment limitation, and three spellings of it would
    /// read as three different rules.
    pub fn refusal(&self, file: &str) -> Option<String> {
        if self.allows(file) {
            return None;
        }
        let shown = if file.trim().is_empty() {
            "<no file>"
        } else {
            file
        };
        Some(format!(
            "{shown} is outside the --diff-scope changed-file set ({} changed file(s)); \
             this run did not analyze it and must not modify it",
            self.files.len()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_inactive_scope_allows_every_file() {
        let scope = DiffScope::inactive();
        assert!(!scope.is_active());
        assert!(scope.allows("anything/at/all.py"));
        assert!(scope.refusal("anything/at/all.py").is_none());
    }

    #[test]
    fn the_default_is_the_inactive_scope() {
        assert_eq!(DiffScope::default(), DiffScope::inactive());
    }

    #[test]
    fn an_active_scope_allows_only_its_own_files() {
        let scope = DiffScope::active(["src/app.py", "src/other.py"]);
        assert!(scope.is_active());
        assert!(scope.allows("src/app.py"));
        assert!(scope.contains("src/other.py"));
        assert!(!scope.allows("vendor/lib.py"));
    }

    /// The rename-only pull request: active, zero files, and therefore
    /// scoped to nothing rather than to everything.
    #[test]
    fn an_active_scope_with_no_files_allows_nothing() {
        let scope = DiffScope::active(Vec::<String>::new());
        assert!(scope.is_active());
        assert!(!scope.allows("src/app.py"));
    }

    #[test]
    fn new_selects_active_or_inactive_from_the_flag() {
        assert!(!DiffScope::new(false, ["src/app.py"]).is_active());
        assert!(DiffScope::new(false, ["src/app.py"]).allows("vendor/lib.py"));
        assert!(DiffScope::new(true, ["src/app.py"]).is_active());
        assert!(!DiffScope::new(true, ["src/app.py"]).allows("vendor/lib.py"));
    }

    #[test]
    fn paths_are_normalized_on_both_sides_of_the_comparison() {
        let scope = DiffScope::active(["./src/app.py", "/src/abs.py", "src\\win.py"]);
        assert!(scope.allows("src/app.py"));
        assert!(scope.allows("./src/app.py"));
        assert!(scope.allows("/src/app.py"));
        assert!(scope.allows("src/abs.py"));
        assert!(scope.allows("src\\win.py"));
        assert!(scope.allows("  src/win.py  "));
        assert!(scope.allows(".//src/app.py"));
    }

    /// No suffix or basename matching: a vendor path that merely ENDS with
    /// a changed file's path is a different file.
    #[test]
    fn a_path_that_only_ends_with_a_changed_file_is_out_of_scope() {
        let scope = DiffScope::active(["src/app.py"]);
        assert!(!scope.allows("vendor/copy/src/app.py"));
        assert!(!scope.allows("app.py"));
    }

    #[test]
    fn refusal_names_the_file_the_flag_and_the_changed_file_count() {
        let scope = DiffScope::active(["src/app.py"]);
        let reason = scope.refusal("vendor/lib.py").unwrap();
        assert!(reason.contains("vendor/lib.py"), "{reason}");
        assert!(reason.contains("--diff-scope"), "{reason}");
        assert!(reason.contains("1 changed file(s)"), "{reason}");
    }

    /// A finding with no file at all cannot be shown to be in scope, so it
    /// is refused — and the message still reads as a sentence.
    #[test]
    fn refusal_of_an_empty_path_is_still_readable() {
        let scope = DiffScope::active(["src/app.py"]);
        let reason = scope.refusal("   ").unwrap();
        assert!(reason.contains("<no file>"), "{reason}");
    }
}
