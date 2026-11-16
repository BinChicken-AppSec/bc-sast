use std::path::{Path, PathBuf};

use crate::args::Cli;

pub struct RemediationWorktree {
    pub path: PathBuf,
    pub parent: PathBuf,
    pub patch_path: PathBuf,
    pub keep: bool,
    finished: bool,
}

impl Drop for RemediationWorktree {
    fn drop(&mut self) {
        if self.finished || self.keep {
            return;
        }
        if let Err(e) = appsec_diffcapture::remove_worktree(&self.parent, &self.path) {
            eprintln!(
                "  [s10] WARN: could not remove the remediation worktree at {} ({e}); \
                 remove it with `git worktree remove --force {}`",
                self.path.display(),
                self.path.display()
            );
        }
    }
}

pub fn patch_path_for(repo: &Path) -> PathBuf {
    repo.join("security-scan").join("remediation.patch")
}

fn worktree_dir_name(repo: &Path) -> String {
    let run_id = appsec_checkpoint::run_id_for(repo);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{run_id}-{}-{nanos}", std::process::id())
}

fn worktree_root() -> PathBuf {
    match crate::clone::state_root() {
        Ok(root) => root.join("remediation-worktrees"),
        Err(_) => std::env::temp_dir().join("bc-sast-remediation-worktrees"),
    }
}

pub fn prepare(cli: &Cli, repo: &Path) -> Option<RemediationWorktree> {
    if cli.remediate_in_place {
        return None;
    }
    if !appsec_diffcapture::is_git_worktree(repo) {
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
    match appsec_diffcapture::create_detached_worktree(repo, &dest) {
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

pub fn finish(worktree: &mut RemediationWorktree) -> Option<PathBuf> {
    let changed = appsec_diffcapture::changed_files_whole_tree(&worktree.path);
    let patch = appsec_diffcapture::export_patch(&worktree.path, &changed);
    let written = (!patch.trim().is_empty())
        .then(|| write_patch(&worktree.patch_path, &patch))
        .flatten();
    if !patch.trim().is_empty() && written.is_none() {
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
    } else if let Err(e) = appsec_diffcapture::remove_worktree(&worktree.parent, &worktree.path) {
        eprintln!(
            "  [s10] WARN: could not remove the remediation worktree at {} ({e}); \
             remove it with `git worktree remove --force {}`",
            worktree.path.display(),
            worktree.path.display()
        );
    }
    written
}

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
        appsec_diffcapture::remove_worktree(repo.path(), &recipient.path).unwrap();
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
        appsec_diffcapture::remove_worktree(repo.path(), &retained).unwrap();
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
        appsec_diffcapture::remove_worktree(repo.path(), &wt.path).unwrap();
    }

    #[tokio::test]
    async fn prepare_degrades_when_the_worktree_parent_directory_cannot_be_created() {
        let _lock = crate::tests::ENV_LOCK.lock().await;
        let repo = git_repo();
        let state = tempfile::tempdir().unwrap();
        std::fs::write(state.path().join("remediation-worktrees"), "x").unwrap();
        let _guard = StateDirGuard::set(state.path());
        let cli = cli_for(repo.path());
        assert!(prepare(&cli, repo.path()).is_none());
    }

    #[tokio::test]
    async fn prepare_degrades_when_git_refuses_to_create_the_worktree() {
        let _lock = crate::tests::ENV_LOCK.lock().await;
        let repo = tempfile::tempdir().unwrap();
        git(repo.path(), &["init", "-q"]);
        assert!(appsec_diffcapture::is_git_worktree(repo.path()));
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
        appsec_diffcapture::remove_worktree(repo.path(), &wt.path).unwrap();
        assert!(finish(&mut wt).is_none());
        assert!(wt.finished);
    }

    #[test]
    fn write_patch_reports_a_destination_that_is_a_directory() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("out");
        std::fs::create_dir_all(&target).unwrap();
        assert!(write_patch(&target, "diff").is_none());
    }

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
        let wt = prepare(&cli, repo.path());
        if let Some(wt) = wt {
            let _ = appsec_diffcapture::remove_worktree(repo.path(), &wt.path);
        }
    }

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
