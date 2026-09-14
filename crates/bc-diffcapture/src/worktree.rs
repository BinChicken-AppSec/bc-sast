//! Throwaway git worktrees for remediation.
//!
//! **Why this exists.** Today the write-capable executor S10 hands to the
//! agent is rooted at the user's own `--repo` checkout, so every `Edit`
//! the model emits lands in the tree the user is working in — the reason
//! a bad fix "breaks the codebase" rather than merely producing a bad
//! patch. The structural answer is to run the agent against a detached
//! worktree of the same commit, throw it away afterwards, and carry only
//! the patch back. Every gate in `bc-stage-s10` (snapshot/revert, syntax,
//! verify command, diff caps) is a mitigation for editing the real tree;
//! this module is the way to stop editing it at all.
//!
//! This crate only PROVIDES the primitives — nothing in the pipeline
//! creates a worktree yet, because choosing when to do so, where to put
//! it, and how to hand the resulting patch back is a CLI-layer decision
//! (which flag, which temp dir, what to do with the patch). Kept here
//! rather than in `bc-stage-s10` because it is the same "shell out to git,
//! carefully, about a path we do not trust" concern the rest of this crate
//! already owns.
//!
//! A worktree shares the parent's object database, so creating one is
//! cheap (a checkout, not a clone) — but it is a real second checkout on
//! disk, and `git worktree` records it in the parent's `.git/worktrees`
//! metadata, so [`remove_worktree`] must be called even if the directory
//! is deleted by other means (or the parent keeps a stale registration
//! until someone runs `git worktree prune`).

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::capture_git_diff;

/// `git worktree add --detach <dest> HEAD`: a second checkout of `repo`'s
/// current commit at `dest`, on no branch at all.
///
/// Detached deliberately — a worktree on a branch would (a) refuse if that
/// branch is already checked out in the parent, which is exactly the
/// common case, and (b) let a commit made inside the throwaway tree move a
/// real branch. Detached HEAD can do neither.
///
/// `dest` should be absolute and must not exist yet — git refuses an
/// occupied destination anyway, but silently reusing a stale directory
/// would mean the agent edits leftovers from a previous run, so it is
/// checked here for a clearer message. Returns `dest` as given on success.
/// Errors as `Err(String)` carrying git's own stderr: a non-git `repo`, a
/// `repo` with no commits yet (no `HEAD` to detach from), an occupied
/// `dest`, or `git` not being runnable at all.
pub fn create_detached_worktree(repo: &Path, dest: &Path) -> Result<PathBuf, String> {
    if dest.exists() {
        return Err(format!(
            "cannot create a worktree: {} already exists",
            dest.display()
        ));
    }
    // `current_dir` rather than `-C`: it makes a `repo` that isn't a
    // directory at all fail at spawn time with a real `io::Error`, which
    // is a materially better message than git's own "not a git
    // repository" for that case.
    let out = Command::new("git")
        .current_dir(repo)
        .args(["worktree", "add", "--detach"])
        .arg(dest)
        .arg("HEAD")
        .output();
    match out {
        Ok(o) if o.status.success() => Ok(dest.to_path_buf()),
        Ok(o) => Err(format!(
            "git worktree add failed: {}",
            String::from_utf8_lossy(&o.stderr).trim()
        )),
        Err(e) => Err(format!("cannot run git in {}: {e}", repo.display())),
    }
}

/// `git worktree remove --force <dest>`: deletes the checkout AND drops
/// its registration from `repo`'s `.git/worktrees`.
///
/// `--force` because the whole point of the throwaway tree is that it is
/// full of uncommitted agent edits; without it git refuses to remove a
/// dirty worktree, which would be a guaranteed failure on every run that
/// actually did something. Whatever was worth keeping has already been
/// exported as a patch by then ([`export_patch`]).
pub fn remove_worktree(repo: &Path, dest: &Path) -> Result<(), String> {
    let out = Command::new("git")
        .current_dir(repo)
        .args(["worktree", "remove", "--force"])
        .arg(dest)
        .output();
    match out {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => Err(format!(
            "git worktree remove failed: {}",
            String::from_utf8_lossy(&o.stderr).trim()
        )),
        Err(e) => Err(format!("cannot run git in {}: {e}", repo.display())),
    }
}

/// The unified diff of `files` inside `worktree`, as a plain `String` —
/// the "carry the result back" half of the throwaway-worktree flow, so the
/// patch outlives the checkout that produced it.
///
/// Thin by design: [`capture_git_diff`] already does the `git add -N`
/// intent-to-add dance (so a brand-new file shows up), the `norm_path`
/// cleaning, and the `bc_pathjail` confinement that keeps an
/// LLM-controlled path out of a git pathspec. This exists so callers say
/// what they mean and get a `String` rather than an `Option` they have to
/// decide about: a worktree that produced nothing, and a git invocation
/// that failed, are both "no patch to carry back".
pub fn export_patch(worktree: &Path, files: &[String]) -> String {
    capture_git_diff(worktree, files).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn git_repo() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let run = |args: &[&str]| {
            Command::new("git")
                .arg("-C")
                .arg(dir.path())
                .args(args)
                .output()
                .unwrap()
        };
        run(&["init", "-q"]);
        std::fs::write(dir.path().join("app.py"), "print('hi')\n").unwrap();
        run(&["add", "-A"]);
        run(&[
            "-c",
            "user.email=test@test.com",
            "-c",
            "user.name=test",
            "commit",
            "-q",
            "-m",
            "x",
        ]);
        dir
    }

    #[test]
    fn create_detached_worktree_checks_out_head_at_dest() {
        let repo = git_repo();
        let holder = tempfile::tempdir().unwrap();
        let dest = holder.path().join("wt");
        let made = create_detached_worktree(repo.path(), &dest).unwrap();
        assert_eq!(made, dest);
        assert_eq!(
            std::fs::read_to_string(dest.join("app.py")).unwrap(),
            "print('hi')\n"
        );
        // Detached: no branch is checked out in the new tree.
        let head = Command::new("git")
            .arg("-C")
            .arg(&dest)
            .args(["symbolic-ref", "-q", "HEAD"])
            .output()
            .unwrap();
        assert!(
            !head.status.success(),
            "worktree should be on a detached HEAD"
        );
    }

    #[test]
    fn create_detached_worktree_leaves_the_parent_tree_untouched() {
        let repo = git_repo();
        let holder = tempfile::tempdir().unwrap();
        let dest = holder.path().join("wt");
        create_detached_worktree(repo.path(), &dest).unwrap();
        std::fs::write(dest.join("app.py"), "print('agent was here')\n").unwrap();
        assert_eq!(
            std::fs::read_to_string(repo.path().join("app.py")).unwrap(),
            "print('hi')\n"
        );
    }

    #[test]
    fn create_detached_worktree_of_a_non_git_directory_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let holder = tempfile::tempdir().unwrap();
        let err = create_detached_worktree(dir.path(), &holder.path().join("wt")).unwrap_err();
        assert!(
            err.starts_with("git worktree add failed:"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn create_detached_worktree_reports_a_repo_that_cannot_even_be_entered() {
        let holder = tempfile::tempdir().unwrap();
        let err = create_detached_worktree(Path::new("/does/not/exist"), &holder.path().join("wt"))
            .unwrap_err();
        assert!(err.starts_with("cannot run git in"), "unexpected: {err}");
    }

    #[test]
    fn remove_worktree_reports_a_repo_that_cannot_even_be_entered() {
        let holder = tempfile::tempdir().unwrap();
        let err =
            remove_worktree(Path::new("/does/not/exist"), &holder.path().join("wt")).unwrap_err();
        assert!(err.starts_with("cannot run git in"), "unexpected: {err}");
    }

    #[test]
    fn create_detached_worktree_refuses_an_existing_destination() {
        let repo = git_repo();
        let holder = tempfile::tempdir().unwrap();
        let err = create_detached_worktree(repo.path(), holder.path()).unwrap_err();
        assert!(err.contains("already exists"), "unexpected: {err}");
    }

    #[test]
    fn create_detached_worktree_surfaces_gits_own_failure() {
        // A repo with no commits at all has no HEAD to detach from, so git
        // itself refuses — the error text must reach the caller rather
        // than being flattened into a generic message.
        let dir = tempfile::tempdir().unwrap();
        Command::new("git")
            .arg("-C")
            .arg(dir.path())
            .args(["init", "-q"])
            .output()
            .unwrap();
        let holder = tempfile::tempdir().unwrap();
        let err = create_detached_worktree(dir.path(), &holder.path().join("wt")).unwrap_err();
        assert!(
            err.starts_with("git worktree add failed:"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn remove_worktree_deletes_the_checkout_and_its_registration() {
        let repo = git_repo();
        let holder = tempfile::tempdir().unwrap();
        let dest = holder.path().join("wt");
        create_detached_worktree(repo.path(), &dest).unwrap();
        remove_worktree(repo.path(), &dest).unwrap();
        assert!(!dest.exists());
        let list = Command::new("git")
            .arg("-C")
            .arg(repo.path())
            .args(["worktree", "list", "--porcelain"])
            .output()
            .unwrap();
        let listed = String::from_utf8_lossy(&list.stdout);
        assert!(
            !listed.contains(&dest.display().to_string()),
            "stale registration: {listed}"
        );
    }

    #[test]
    fn remove_worktree_forces_past_uncommitted_agent_edits() {
        let repo = git_repo();
        let holder = tempfile::tempdir().unwrap();
        let dest = holder.path().join("wt");
        create_detached_worktree(repo.path(), &dest).unwrap();
        std::fs::write(dest.join("app.py"), "print('dirty')\n").unwrap();
        std::fs::write(dest.join("brand-new.py"), "print('new')\n").unwrap();
        remove_worktree(repo.path(), &dest).unwrap();
        assert!(!dest.exists());
    }

    #[test]
    fn remove_worktree_of_something_that_is_not_a_worktree_is_an_error() {
        let repo = git_repo();
        let holder = tempfile::tempdir().unwrap();
        let err = remove_worktree(repo.path(), &holder.path().join("never-made")).unwrap_err();
        assert!(
            err.starts_with("git worktree remove failed:"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn export_patch_carries_the_worktrees_changes_back_as_text() {
        let repo = git_repo();
        let holder = tempfile::tempdir().unwrap();
        let dest = holder.path().join("wt");
        create_detached_worktree(repo.path(), &dest).unwrap();
        std::fs::write(dest.join("app.py"), "print('fixed')\n").unwrap();
        std::fs::write(dest.join("added.py"), "print('added')\n").unwrap();
        let patch = export_patch(&dest, &["app.py".to_string(), "added.py".to_string()]);
        assert!(patch.contains("-print('hi')"), "missing removal: {patch}");
        assert!(
            patch.contains("+print('fixed')"),
            "missing addition: {patch}"
        );
        assert!(
            patch.contains("+print('added')"),
            "missing new file: {patch}"
        );
    }

    #[test]
    fn export_patch_of_an_unchanged_worktree_is_empty() {
        let repo = git_repo();
        let holder = tempfile::tempdir().unwrap();
        let dest = holder.path().join("wt");
        create_detached_worktree(repo.path(), &dest).unwrap();
        assert_eq!(export_patch(&dest, &["app.py".to_string()]), "");
    }

    #[test]
    fn export_patch_of_a_non_git_directory_is_empty_rather_than_an_error() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "x\n").unwrap();
        assert_eq!(export_patch(dir.path(), &["a.py".to_string()]), "");
    }
}
