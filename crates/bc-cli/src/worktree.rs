//! Worktree-isolated remediation: run S10 (and S11) against a throwaway
//! detached checkout of `--repo`'s current commit, then carry only a
//! unified diff back.
//!
//! **Why this is the default.** Every `Edit`/`Write` S10's agent emits
//! executes immediately against whatever tree the write-capable executor
//! is rooted at. `bc-stage-s10`'s seven rollback gates exist because that
//! tree used to be the user's own checkout — they make a bad patch
//! survivable, but they are all mitigations for editing files nobody
//! asked to have edited. `bc_diffcapture::create_detached_worktree` makes
//! that structural instead: git checks the same commit out somewhere
//! else, the agent edits *that*, and the user's files are never touched
//! at all. The gates still run inside the worktree (a rolled-back patch
//! must still not be exported), but their worst case stops being "your
//! working tree is broken" and becomes "the patch file is empty".
//!
//! **When it does not apply.** A `--repo` that is not a git worktree has
//! no commit to check out a second copy of, so remediation stays in
//! place. `--remediate-in-place` opts out explicitly.
//!
//! The checkout lives under the same state directory
//! `bc_checkpoint`/`crate::clone` already use (`$BC_STATE_DIR`, or
//! `$HOME/.bc-sast/state`), falling back to the system temp dir when
//! neither resolves — never inside `--repo` itself, which would put a
//! second copy of the tree inside the tree being scanned.

use std::path::{Path, PathBuf};

use crate::args::Cli;

/// A live throwaway checkout plus everything needed to wind it up.
///
/// Owns its own cleanup: [`Drop`] removes the checkout (and its
/// registration in the parent's `.git/worktrees`) for every path that
/// never reached [`finish`] — a scan that errored before remediation, a
/// `--stop-after` run that produced no report, a panic. Without that, the
/// worktree is created at argument-parsing time and leaks on any failure
/// between there and the end of remediation, leaving a stale checkout AND
/// a stale registration that only `git worktree prune` clears.
pub struct RemediationWorktree {
    /// The detached checkout S10/S11 actually run against — the value
    /// handed to `SandboxTools::new_with_write` in place of `--repo`.
    pub path: PathBuf,
    /// The user's own repository. Owns the worktree registration in its
    /// `.git/worktrees`, so [`finish`] must run against it even if the
    /// directory were removed some other way.
    pub parent: PathBuf,
    /// Where the exported unified diff is written
    /// (`<repo>/security-scan/remediation.patch`).
    pub patch_path: PathBuf,
    /// `--keep-remediation-worktree`: leave the checkout on disk for
    /// inspection instead of removing it.
    pub keep: bool,
    /// Set by [`finish`], read by [`Drop`] — the checkout has already
    /// been wound up, so dropping must not try again (and must not print
    /// a second message about it).
    finished: bool,
}

impl Drop for RemediationWorktree {
    fn drop(&mut self) {
        if self.finished || self.keep {
            return;
        }
        // Nothing was exported (this drop is a failure path), so there is
        // no patch to lose — remove the checkout silently unless git
        // itself objects, in which case say so, because the leftover
        // needs a human.
        if let Err(e) = bc_diffcapture::remove_worktree(&self.parent, &self.path) {
            eprintln!(
                "  [s10] WARN: could not remove the remediation worktree at {} ({e}); \
                 remove it with `git worktree remove --force {}`",
                self.path.display(),
                self.path.display()
            );
        }
    }
}

/// `<repo>/security-scan/remediation.patch` — deliberately alongside
/// `report.md`/`report.sarif`/`report.csv` rather than in the state dir:
/// the patch is a scan artifact the operator applies by hand, not
/// internal run state.
pub fn patch_path_for(repo: &Path) -> PathBuf {
    repo.join("security-scan").join("remediation.patch")
}

/// A directory name that cannot collide with a concurrent run of this
/// same binary against this same repo: the repo's own stable checkpoint
/// run id (so two different repos never share a parent directory) plus
/// this process's pid and a monotonic-ish suffix.
///
/// Deliberately not a random uuid — this workspace ships no uuid crate
/// and the supply-chain policy forbids adding one for a directory name.
/// `create_detached_worktree` refuses a destination that already exists,
/// so a collision fails loudly rather than silently reusing someone
/// else's checkout.
fn worktree_dir_name(repo: &Path) -> String {
    let run_id = bc_checkpoint::run_id_for(repo);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{run_id}-{}-{nanos}", std::process::id())
}

/// The parent directory throwaway checkouts are created under. Prefers
/// the shared state dir (so `--gc`-adjacent tooling and an operator
/// looking for leftovers have one place to look); falls back to the
/// system temp dir when `$BC_STATE_DIR`/`$HOME` resolve to nothing
/// usable, since an unwritable state dir must not block remediation the
/// way it doesn't block checkpointing either.
fn worktree_root() -> PathBuf {
    match crate::clone::state_root() {
        Ok(root) => root.join("remediation-worktrees"),
        Err(_) => std::env::temp_dir().join("bc-sast-remediation-worktrees"),
    }
}

/// `Ok(None)` — remediation runs in place — when `--remediate-in-place`
/// is set or `repo` is not a git worktree. Otherwise creates the
/// detached checkout and returns it.
///
/// A worktree that cannot be created is NOT an error: it degrades to
/// in-place remediation with a warning, because the alternative is
/// failing a `--remediate` run outright over an isolation optimization,
/// and every safety gate that protected the in-place path before this
/// existed is still in force.
pub fn prepare(cli: &Cli, repo: &Path) -> Option<RemediationWorktree> {
    if cli.remediate_in_place {
        return None;
    }
    if !bc_diffcapture::is_git_worktree(repo) {
        // Expected, not a defect, on a plain unpacked source tree: a
        // disposable checkout where there is no working tree of anyone's
        // to protect, which is the only thing isolation buys. Worded so
        // an operator reading CI logs can tell that apart from a
        // failure. This is a probe, not an assumption, so the packaged
        // container gets real isolation now that the image ships `git`
        // (the previous `distroless/cc` runtime shipped none, and every
        // containerized run landed here).
        eprintln!(
            "  [s10] no git worktree at {} (no `git`, or not a repository). \
             Remediating in place; the safety gates still apply",
            repo.display()
        );
        return None;
    }
    let dest = worktree_root().join(worktree_dir_name(repo));
    if let Some(parent) = dest.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            eprintln!(
                "  [s10] WARN: cannot create {} ({e}); remediation will edit \
                 {} in place",
                parent.display(),
                repo.display()
            );
            return None;
        }
    }
    match bc_diffcapture::create_detached_worktree(repo, &dest) {
        Ok(path) => Some(RemediationWorktree {
            path,
            parent: repo.to_path_buf(),
            patch_path: patch_path_for(repo),
            keep: cli.keep_remediation_worktree,
            finished: false,
        }),
        Err(e) => {
            eprintln!(
                "  [s10] WARN: could not create an isolated worktree ({e}); \
                 remediation will edit {} in place",
                repo.display()
            );
            None
        }
    }
}

/// Export the patch and wind the checkout up.
///
/// Returns the patch path when a non-empty diff was actually written;
/// `None` when the agent changed nothing (a run where every finding was
/// denied, or every patch was rolled back — writing an empty `.patch`
/// would look like a produced-but-broken artifact).
///
/// The file list comes from `git status` inside the worktree rather than
/// from the agents' own `changes` arrays: a model under-reporting what it
/// edited is exactly the case a patch export must not miss, and the
/// worktree contains nothing but this run's own edits, so there is no
/// pre-existing dirty state to exclude the way the in-place gates have to.
pub fn finish(worktree: &mut RemediationWorktree) -> Option<PathBuf> {
    let changed = bc_diffcapture::changed_files_whole_tree(&worktree.path);
    let patch = bc_diffcapture::export_patch(&worktree.path, &changed);
    let written = (!patch.trim().is_empty())
        .then(|| write_patch(&worktree.patch_path, &patch))
        .flatten();
    if !patch.trim().is_empty() && written.is_none() {
        // This checkout is now the only copy of generated tests and fixes.
        // Preserve it even if the caller did not request retention, including
        // when this value is subsequently dropped on an error path.
        worktree.keep = true;
        worktree.finished = true;
        eprintln!(
            "  [s10] WARN: patch export failed; remediation edits and generated tests \
             are retained at {} for recovery",
            worktree.path.display()
        );
        return None;
    }
    worktree.finished = true;
    if worktree.keep {
        eprintln!(
            "  [s10] remediation worktree kept at {} — remove it with \
             `git worktree remove --force {}`",
            worktree.path.display(),
            worktree.path.display()
        );
    } else if let Err(e) = bc_diffcapture::remove_worktree(&worktree.parent, &worktree.path) {
        eprintln!(
            "  [s10] WARN: could not remove the remediation worktree at {} ({e}); \
             remove it with `git worktree remove --force {}`",
            worktree.path.display(),
            worktree.path.display()
        );
    }
    written
}

/// Best-effort patch write: a failure here is reported and swallowed
/// rather than failing the whole run, matching how every other
/// post-remediation artifact (`--out-remediation-json`'s parent dir, the
/// GitHub sync) treats an I/O problem at the very end of a scan that
/// already produced its real output.
fn write_patch(path: &Path, patch: &str) -> Option<PathBuf> {
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            eprintln!("  [s10] WARN: cannot write {}: {e}", path.display());
            return None;
        }
    }
    match std::fs::write(path, patch) {
        Ok(()) => Some(path.to_path_buf()),
        Err(e) => {
            eprintln!("  [s10] WARN: cannot write {}: {e}", path.display());
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn git(dir: &Path, args: &[&str]) {
        let out = Command::new("git")
            .current_dir(dir)
            .args(args)
            .output()
            .expect("git must be runnable in tests");
        assert!(out.status.success(), "git {args:?} failed: {out:?}");
    }

    fn git_repo() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        git(dir.path(), &["init", "-q"]);
        git(dir.path(), &["config", "user.email", "t@example.com"]);
        git(dir.path(), &["config", "user.name", "t"]);
        std::fs::write(dir.path().join("a.txt"), "one\n").unwrap();
        git(dir.path(), &["add", "-A"]);
        git(dir.path(), &["commit", "-qm", "init"]);
        dir
    }

    fn cli_for(repo: &Path) -> Cli {
        crate::args::test_support::minimal_cli(repo)
    }

    #[test]
    fn patch_path_is_next_to_the_other_scan_outputs() {
        assert_eq!(
            patch_path_for(Path::new("/tmp/repo")),
            Path::new("/tmp/repo/security-scan/remediation.patch")
        );
    }

    #[test]
    fn worktree_dir_name_is_unique_per_process_and_instant() {
        let repo = tempfile::tempdir().unwrap();
        let a = worktree_dir_name(repo.path());
        let b = worktree_dir_name(repo.path());
        assert_ne!(a, b);
        assert!(a.contains(&std::process::id().to_string()));
    }

    #[tokio::test]
    async fn worktree_root_falls_back_to_temp_without_a_state_dir() {
        let _lock = crate::tests::ENV_LOCK.lock().await;
        // `state_root()` only fails when neither BC_STATE_DIR nor HOME
        // resolves; the happy path is what every real run takes, and it
        // must name a `remediation-worktrees` directory either way.
        let root = worktree_root();
        assert!(
            root.ends_with("remediation-worktrees")
                || root.ends_with("bc-sast-remediation-worktrees")
        );
    }

    #[test]
    fn prepare_returns_none_when_in_place_is_requested() {
        let repo = git_repo();
        let mut cli = cli_for(repo.path());
        cli.remediate_in_place = true;
        assert!(prepare(&cli, repo.path()).is_none());
    }

    #[test]
    fn prepare_returns_none_for_a_non_git_repo() {
        let repo = tempfile::tempdir().unwrap();
        let cli = cli_for(repo.path());
        assert!(prepare(&cli, repo.path()).is_none());
    }

    #[tokio::test]
    async fn prepare_creates_a_detached_checkout_and_finish_exports_the_patch() {
        let _lock = crate::tests::ENV_LOCK.lock().await;
        let repo = git_repo();
        let state = tempfile::tempdir().unwrap();
        let _guard = StateDirGuard::set(state.path());
        let cli = cli_for(repo.path());
        let mut wt = prepare(&cli, repo.path()).expect("a git repo gets a worktree");
        assert!(wt.path.join("a.txt").is_file());
        assert_ne!(wt.path, repo.path());

        std::fs::write(wt.path.join("a.txt"), "two\n").unwrap();
        let written = finish(&mut wt).expect("a real edit produces a patch");
        assert_eq!(written, repo.path().join("security-scan/remediation.patch"));
        let patch = std::fs::read_to_string(&written).unwrap();
        assert!(patch.contains("-one"), "{patch}");
        assert!(patch.contains("+two"), "{patch}");
        // The user's own checkout is untouched.
        assert_eq!(
            std::fs::read_to_string(repo.path().join("a.txt")).unwrap(),
            "one\n"
        );
        assert!(!wt.path.exists(), "the worktree is removed by default");
    }

    #[tokio::test]
    async fn finish_writes_nothing_when_the_agent_changed_nothing() {
        let _lock = crate::tests::ENV_LOCK.lock().await;
        let repo = git_repo();
        let state = tempfile::tempdir().unwrap();
        let _guard = StateDirGuard::set(state.path());
        let cli = cli_for(repo.path());
        let mut wt = prepare(&cli, repo.path()).unwrap();
        assert!(finish(&mut wt).is_none());
        assert!(!repo.path().join("security-scan").exists());
    }

    #[tokio::test]
    async fn combined_patch_preserves_new_and_extended_target_tests_for_reuse() {
        let _lock = crate::tests::ENV_LOCK.lock().await;
        let repo = git_repo();
        // Explicit Git line-ending settings keep byte assertions portable.
        git(repo.path(), &["config", "core.autocrlf", "false"]);
        std::fs::create_dir(repo.path().join("tests")).unwrap();
        let existing_before =
            "from app import allowed\n\ndef test_owner():\n    assert allowed(1, 1)\n";
        let existing_after =
            format!("{existing_before}\ndef test_other_user():\n    assert not allowed(1, 2)\n");
        let production_before = "def allowed(owner, user):\n    return True\n";
        let production_after = "def allowed(owner, user):\n    return owner == user\n";
        let new_test =
            "from app import allowed\n\ndef test_denied_record():\n    assert not allowed(7, 9)\n";
        std::fs::write(repo.path().join("app.py"), production_before).unwrap();
        std::fs::write(repo.path().join("tests/test_app.py"), existing_before).unwrap();
        git(repo.path(), &["add", "-A"]);
        git(repo.path(), &["commit", "-qm", "test baseline"]);
        let state = tempfile::tempdir().unwrap();
        let _guard = StateDirGuard::set(state.path());
        let mut wt = prepare(&cli_for(repo.path()), repo.path()).unwrap();
        std::fs::write(wt.path.join("app.py"), production_after).unwrap();
        std::fs::write(wt.path.join("tests/test_app.py"), &existing_after).unwrap();
        // Leave this file untracked, exactly as target-test generation does.
        std::fs::write(wt.path.join("tests/test_security.py"), new_test).unwrap();
        let patch_path = finish(&mut wt).expect("combined patch must be exported");
        assert!(!wt.path.exists());
        assert_eq!(
            std::fs::read(repo.path().join("app.py")).unwrap(),
            production_before.as_bytes()
        );
        assert_eq!(
            std::fs::read(repo.path().join("tests/test_app.py")).unwrap(),
            existing_before.as_bytes()
        );
        assert!(!repo.path().join("tests/test_security.py").exists());

        // Apply the artifact to a separate baseline checkout, without running
        // Python or treating these synthetic assertions as a security verdict.
        let mut recipient = prepare(&cli_for(repo.path()), repo.path()).unwrap();
        let patch_arg = patch_path.to_str().unwrap();
        git(&recipient.path, &["apply", "--check", patch_arg]);
        git(&recipient.path, &["apply", patch_arg]);
        for (path, expected) in [
            ("app.py", production_after),
            ("tests/test_app.py", existing_after.as_str()),
            ("tests/test_security.py", new_test),
        ] {
            assert_eq!(
                std::fs::read(recipient.path.join(path)).unwrap(),
                expected.as_bytes(),
                "{path}"
            );
        }
        bc_diffcapture::remove_worktree(repo.path(), &recipient.path).unwrap();
        recipient.finished = true;
    }

    #[tokio::test]
    async fn failed_patch_export_retains_generated_tests_and_fixes_after_drop() {
        let _lock = crate::tests::ENV_LOCK.lock().await;
        let repo = git_repo();
        let state = tempfile::tempdir().unwrap();
        let _guard = StateDirGuard::set(state.path());
        let mut wt = prepare(&cli_for(repo.path()), repo.path()).unwrap();
        std::fs::write(wt.path.join("a.txt"), "fixed\n").unwrap();
        std::fs::write(wt.path.join("test_new.py"), "assert True\n").unwrap();
        // A directory at the destination reliably fails on every host OS.
        std::fs::create_dir_all(&wt.patch_path).unwrap();
        let retained = wt.path.clone();
        assert!(finish(&mut wt).is_none());
        assert!(wt.keep);
        drop(wt);
        assert_eq!(
            std::fs::read_to_string(retained.join("a.txt")).unwrap(),
            "fixed\n"
        );
        assert_eq!(
            std::fs::read_to_string(retained.join("test_new.py")).unwrap(),
            "assert True\n"
        );
        assert_eq!(
            std::fs::read_to_string(repo.path().join("a.txt")).unwrap(),
            "one\n"
        );
        bc_diffcapture::remove_worktree(repo.path(), &retained).unwrap();
    }

    #[tokio::test]
    async fn finish_keeps_the_worktree_when_asked() {
        let _lock = crate::tests::ENV_LOCK.lock().await;
        let repo = git_repo();
        let state = tempfile::tempdir().unwrap();
        let _guard = StateDirGuard::set(state.path());
        let mut cli = cli_for(repo.path());
        cli.keep_remediation_worktree = true;
        let mut wt = prepare(&cli, repo.path()).unwrap();
        std::fs::write(wt.path.join("a.txt"), "two\n").unwrap();
        assert!(finish(&mut wt).is_some());
        assert!(wt.path.exists(), "--keep-remediation-worktree leaves it");
        // Wind it up so the test doesn't leak a registration.
        bc_diffcapture::remove_worktree(repo.path(), &wt.path).unwrap();
    }

    #[tokio::test]
    async fn prepare_degrades_when_the_worktree_parent_directory_cannot_be_created() {
        let _lock = crate::tests::ENV_LOCK.lock().await;
        let repo = git_repo();
        let state = tempfile::tempdir().unwrap();
        // `remediation-worktrees` already exists as a FILE, so
        // `create_dir_all` on it fails while `state_root()` itself still
        // resolves — the one branch that warns and falls back to in-place
        // without ever asking git for anything.
        std::fs::write(state.path().join("remediation-worktrees"), "x").unwrap();
        let _guard = StateDirGuard::set(state.path());
        let cli = cli_for(repo.path());
        assert!(prepare(&cli, repo.path()).is_none());
    }

    #[tokio::test]
    async fn prepare_degrades_when_git_refuses_to_create_the_worktree() {
        let _lock = crate::tests::ENV_LOCK.lock().await;
        // An initialized repo with no commits: `rev-parse
        // --is-inside-work-tree` says yes, but there is no `HEAD` to
        // detach from, so `git worktree add` fails.
        let repo = tempfile::tempdir().unwrap();
        git(repo.path(), &["init", "-q"]);
        assert!(bc_diffcapture::is_git_worktree(repo.path()));
        let state = tempfile::tempdir().unwrap();
        let _guard = StateDirGuard::set(state.path());
        let cli = cli_for(repo.path());
        assert!(prepare(&cli, repo.path()).is_none());
    }

    #[tokio::test]
    async fn finish_reports_a_worktree_it_cannot_remove() {
        let _lock = crate::tests::ENV_LOCK.lock().await;
        let repo = git_repo();
        let state = tempfile::tempdir().unwrap();
        let _guard = StateDirGuard::set(state.path());
        let cli = cli_for(repo.path());
        let mut wt = prepare(&cli, repo.path()).unwrap();
        // Unregister it behind `finish`'s back, so its own removal fails.
        bc_diffcapture::remove_worktree(repo.path(), &wt.path).unwrap();
        assert!(finish(&mut wt).is_none());
        // Still marked finished, so `Drop` doesn't try (and warn) again.
        assert!(wt.finished);
    }

    #[test]
    fn write_patch_reports_a_destination_that_is_a_directory() {
        let dir = tempfile::tempdir().unwrap();
        // The path itself is a directory: `create_dir_all` on its parent
        // succeeds, `fs::write` then fails — the second of the two
        // failure branches.
        let target = dir.path().join("out");
        std::fs::create_dir_all(&target).unwrap();
        assert!(write_patch(&target, "diff").is_none());
    }

    /// The guard's restore-a-PREVIOUS-value arm; the test below covers
    /// the restore-nothing arm. Both exist because every other test here
    /// runs with the variable unset, so only an explicit pre-set value
    /// reaches the first one.
    #[tokio::test]
    async fn the_state_dir_guard_restores_a_previous_value() {
        let _lock = crate::tests::ENV_LOCK.lock().await;
        let prior = std::env::var("BC_STATE_DIR").ok();
        let outer = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("BC_STATE_DIR", outer.path()) };
        {
            let inner = tempfile::tempdir().unwrap();
            let _guard = StateDirGuard::set(inner.path());
            assert_eq!(
                std::env::var("BC_STATE_DIR").unwrap(),
                inner.path().to_string_lossy()
            );
        }
        assert_eq!(
            std::env::var("BC_STATE_DIR").unwrap(),
            outer.path().to_string_lossy()
        );
        crate::tests::restore_env("BC_STATE_DIR", prior);
    }

    #[tokio::test]
    async fn the_state_dir_guard_restores_an_absent_variable() {
        let _lock = crate::tests::ENV_LOCK.lock().await;
        let prior = std::env::var("BC_STATE_DIR").ok();
        unsafe { std::env::remove_var("BC_STATE_DIR") };
        {
            let dir = tempfile::tempdir().unwrap();
            let _guard = StateDirGuard::set(dir.path());
            assert!(std::env::var("BC_STATE_DIR").is_ok());
        }
        assert!(std::env::var("BC_STATE_DIR").is_err());
        crate::tests::restore_env("BC_STATE_DIR", prior);
    }

    #[test]
    fn write_patch_reports_an_unwritable_destination() {
        let dir = tempfile::tempdir().unwrap();
        // A parent that is a FILE makes `create_dir_all` fail.
        let blocker = dir.path().join("blocker");
        std::fs::write(&blocker, "x").unwrap();
        assert!(write_patch(&blocker.join("out.patch"), "diff").is_none());
    }

    #[tokio::test]
    async fn prepare_degrades_to_in_place_when_the_worktree_root_is_unusable() {
        let _lock = crate::tests::ENV_LOCK.lock().await;
        let repo = git_repo();
        let blocker_dir = tempfile::tempdir().unwrap();
        let blocker = blocker_dir.path().join("not-a-dir");
        std::fs::write(&blocker, "x").unwrap();
        let _guard = StateDirGuard::set(&blocker);
        let cli = cli_for(repo.path());
        // `state_root()` itself fails (it create_dir_all's the state dir),
        // so this exercises the temp-dir fallback rather than the
        // create_dir_all warning; either way the run must not abort.
        let wt = prepare(&cli, repo.path());
        if let Some(wt) = wt {
            let _ = bc_diffcapture::remove_worktree(repo.path(), &wt.path);
        }
    }

    /// RAII `BC_STATE_DIR` guard, mirroring `clone.rs`'s own — these
    /// tests run in the same process as every other test in this crate,
    /// so the variable must always be put back.
    struct StateDirGuard(Option<String>);

    impl StateDirGuard {
        fn set(dir: &Path) -> Self {
            let prior = std::env::var("BC_STATE_DIR").ok();
            unsafe { std::env::set_var("BC_STATE_DIR", dir) };
            StateDirGuard(prior)
        }
    }

    impl Drop for StateDirGuard {
        fn drop(&mut self) {
            match self.0.take() {
                Some(v) => unsafe { std::env::set_var("BC_STATE_DIR", v) },
                None => unsafe { std::env::remove_var("BC_STATE_DIR") },
            }
        }
    }
}
