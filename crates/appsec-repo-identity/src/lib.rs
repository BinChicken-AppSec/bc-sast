mod origin;
pub use origin::{parse_origin, Origin};

use std::path::Path;
use std::process::Command;

use appsec_model::{RepoIdentity, RepoKey, RepoKeySource};

#[derive(Debug, Clone, Copy, Default)]
pub struct Overrides<'a> {
    pub repo_key: Option<&'a str>,
    pub env_repo_key: Option<&'a str>,
    pub branch: Option<&'a str>,
    pub base_ref: Option<&'a str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootCommitVerdict {
    Match,
    Mismatch,
    Unverifiable,
}

pub fn same_repository(
    stored: Option<&str>,
    stored_verified: bool,
    current: &RepoIdentity,
) -> RootCommitVerdict {
    match (stored, current.root_commit.as_deref()) {
        (Some(a), Some(b)) if stored_verified && current.root_commit_verified => {
            if a == b {
                RootCommitVerdict::Match
            } else {
                RootCommitVerdict::Mismatch
            }
        }
        _ => RootCommitVerdict::Unverifiable,
    }
}

pub fn resolve(repo_root: &Path, overrides: &Overrides) -> RepoIdentity {
    let origin = git(repo_root, &["remote", "get-url", "origin"])
        .as_deref()
        .and_then(parse_origin);
    let subtree = git(repo_root, &["rev-parse", "--show-prefix"])
        .map(|p| p.trim_matches('/').to_string())
        .unwrap_or_default();

    let key = resolve_key(overrides, origin.as_ref(), &subtree);

    let shallow = git(repo_root, &["rev-parse", "--is-shallow-repository"])
        .map(|v| v != "false")
        .unwrap_or(true);
    let root_commit = root_commits(repo_root);

    RepoIdentity {
        key,
        origin_display: origin.map(|o| o.display),
        subtree,
        root_commit_verified: root_commit.is_some() && !shallow,
        root_commit,
        branch: nonempty(overrides.branch)
            .map(str::to_string)
            .or_else(|| git(repo_root, &["symbolic-ref", "-q", "--short", "HEAD"])),
        merge_base: nonempty(overrides.base_ref)
            .and_then(|base| git(repo_root, &["merge-base", "HEAD", base])),
        worktree_dirty: worktree_dirty(repo_root),
    }
}

fn resolve_key(overrides: &Overrides, origin: Option<&Origin>, subtree: &str) -> Option<RepoKey> {
    if let Some(value) = nonempty(overrides.repo_key) {
        return Some(RepoKey {
            value: value.to_string(),
            source: RepoKeySource::Explicit,
        });
    }
    if let Some(value) = nonempty(overrides.env_repo_key) {
        return Some(RepoKey {
            value: value.to_string(),
            source: RepoKeySource::Environment,
        });
    }
    let origin = origin?;
    Some(RepoKey {
        value: if subtree.is_empty() {
            origin.key.clone()
        } else {
            format!("{}#{subtree}", origin.key)
        },
        source: RepoKeySource::Derived,
    })
}

fn nonempty(raw: Option<&str>) -> Option<&str> {
    raw.map(str::trim).filter(|v| !v.is_empty())
}

fn root_commits(repo_root: &Path) -> Option<String> {
    let out = git(repo_root, &["rev-list", "--max-parents=0", "HEAD"])?;
    let mut roots: Vec<&str> = out
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    roots.sort_unstable();
    (!roots.is_empty()).then(|| roots.join(","))
}

fn worktree_dirty(repo_root: &Path) -> bool {
    git(
        repo_root,
        &["status", "--porcelain", "--untracked-files=all"],
    )
    .is_some_and(|out| !out.is_empty())
}

fn git(repo_root: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(args)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    Some(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct Repo {
        dir: tempfile::TempDir,
    }

    impl Repo {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let repo = Repo { dir };
            repo.run(&["init", "--initial-branch=main"]);
            repo.run(&["config", "user.email", "t@example.invalid"]);
            repo.run(&["config", "user.name", "T"]);
            repo.run(&["config", "commit.gpgsign", "false"]);
            repo.write("app.py", "x = 1\n");
            repo.run(&["add", "-A"]);
            repo.run(&["commit", "-m", "first"]);
            repo
        }

        fn path(&self) -> &Path {
            self.dir.path()
        }

        fn run(&self, args: &[&str]) -> String {
            let out = Command::new("git")
                .arg("-C")
                .arg(self.path())
                .args(args)
                .output()
                .expect("git must be on PATH for these tests");
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(out.status.success(), "git {args:?} failed: {stderr}");
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        }

        fn write(&self, rel: &str, body: &str) -> PathBuf {
            let p = self.path().join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, body).unwrap();
            p
        }

        fn set_origin(&self, url: &str) {
            self.run(&["remote", "add", "origin", url]);
        }
    }

    fn resolved(root: &Path) -> RepoIdentity {
        resolve(root, &Overrides::default())
    }

    #[test]
    fn a_normal_clone_derives_its_key_from_the_origin() {
        let repo = Repo::new();
        repo.set_origin("https://github.com/org/repo.git");
        let id = resolved(repo.path());
        let key = id.key.unwrap();
        assert_eq!(key.value, "github.com/org/repo");
        assert_eq!(key.source, RepoKeySource::Derived);
        assert_eq!(id.origin_display.unwrap(), "https://github.com/org/repo");
        assert_eq!(id.subtree, "");
    }

    #[test]
    fn two_subtrees_of_one_repository_get_different_keys() {
        let repo = Repo::new();
        repo.set_origin("https://github.com/org/mono.git");
        repo.write("services/a/app.py", "x = 1\n");
        repo.write("services/b/app.py", "x = 1\n");
        repo.run(&["add", "-A"]);
        repo.run(&["commit", "-m", "services"]);

        let a = resolved(&repo.path().join("services/a")).key.unwrap().value;
        let b = resolved(&repo.path().join("services/b")).key.unwrap().value;
        assert_eq!(a, "github.com/org/mono#services/a");
        assert_eq!(b, "github.com/org/mono#services/b");
        assert_ne!(a, b);
        assert_eq!(
            resolved(repo.path()).key.unwrap().value,
            "github.com/org/mono"
        );
    }

    #[test]
    fn a_ci_token_in_the_origin_reaches_no_field_and_does_not_change_the_key() {
        let repo = Repo::new();
        repo.set_origin("https://x-access-token:ghs_SuperSecretValue@github.com/org/repo.git");
        let id = resolved(repo.path());
        assert_eq!(id.key.as_ref().unwrap().value, "github.com/org/repo");
        let rendered = format!("{id:?}");
        assert!(!rendered.contains("ghs_"), "{rendered}");
        assert!(!rendered.contains("x-access-token"), "{rendered}");
    }

    #[test]
    fn an_explicit_key_wins_over_the_origin_and_the_environment() {
        let repo = Repo::new();
        repo.set_origin("https://github.com/org/repo.git");
        let id = resolve(
            repo.path(),
            &Overrides {
                repo_key: Some("chosen/key"),
                env_repo_key: Some("env/key"),
                ..Default::default()
            },
        );
        let key = id.key.unwrap();
        assert_eq!(key.value, "chosen/key");
        assert_eq!(key.source, RepoKeySource::Explicit);
    }

    #[test]
    fn the_environment_wins_over_derivation_but_not_over_the_flag() {
        let repo = Repo::new();
        repo.set_origin("https://github.com/org/repo.git");
        let id = resolve(
            repo.path(),
            &Overrides {
                env_repo_key: Some("env/key"),
                ..Default::default()
            },
        );
        let key = id.key.unwrap();
        assert_eq!(key.value, "env/key");
        assert_eq!(key.source, RepoKeySource::Environment);
    }

    #[test]
    fn an_empty_override_falls_through_instead_of_becoming_the_key() {
        let repo = Repo::new();
        repo.set_origin("https://github.com/org/repo.git");
        let id = resolve(
            repo.path(),
            &Overrides {
                repo_key: Some("   "),
                env_repo_key: Some(""),
                ..Default::default()
            },
        );
        assert_eq!(id.key.unwrap().source, RepoKeySource::Derived);
    }

    #[test]
    fn a_repository_with_no_usable_remote_gets_no_key_rather_than_a_guess() {
        let repo = Repo::new();
        assert!(resolved(repo.path()).key.is_none());

        let local = Repo::new();
        local.set_origin(&format!("{}", repo.path().display()));
        let id = resolved(local.path());
        assert!(id.key.is_none(), "{id:?}");
        assert!(id.origin_display.is_none(), "{id:?}");
    }

    #[test]
    fn a_directory_that_is_not_a_worktree_yields_an_empty_identity() {
        let dir = tempfile::tempdir().unwrap();
        let id = resolved(dir.path());
        assert_eq!(id, RepoIdentity::default());
    }

    #[test]
    fn a_full_clone_records_a_verified_root_commit() {
        let repo = Repo::new();
        let expected = repo.run(&["rev-list", "--max-parents=0", "HEAD"]);
        let id = resolved(repo.path());
        assert_eq!(id.root_commit.as_deref(), Some(expected.as_str()));
        assert!(id.root_commit_verified);
    }

    #[test]
    fn a_shallow_clone_records_an_unverified_root_commit() {
        let origin = Repo::new();
        origin.write("app.py", "x = 2\n");
        origin.run(&["add", "-A"]);
        origin.run(&["commit", "-m", "second"]);
        let true_root = origin.run(&["rev-list", "--max-parents=0", "HEAD"]);

        let dest = tempfile::tempdir().unwrap();
        let clone = dest.path().join("shallow");
        let out = Command::new("git")
            .args(["clone", "--depth=1", "--no-local"])
            .arg(format!("file://{}", origin.path().display()))
            .arg(&clone)
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "git clone failed: {stderr}");

        let id = resolved(&clone);
        assert!(
            !id.root_commit_verified,
            "a shallow clone must not claim a verified root: {id:?}"
        );
        assert_ne!(
            id.root_commit.as_deref(),
            Some(true_root.as_str()),
            "this test is only meaningful while the shallow root differs"
        );
    }

    #[test]
    fn an_untracked_file_makes_the_worktree_dirty() {
        let repo = Repo::new();
        assert!(!resolved(repo.path()).worktree_dirty);
        repo.write("scratch.py", "junk\n");
        assert!(resolved(repo.path()).worktree_dirty);
    }

    #[test]
    fn an_ignored_file_does_not_make_the_worktree_dirty() {
        let repo = Repo::new();
        repo.write(".gitignore", "build/\n");
        repo.run(&["add", "-A"]);
        repo.run(&["commit", "-m", "ignore"]);
        repo.write("build/out.o", "binary\n");
        assert!(!resolved(repo.path()).worktree_dirty);
    }

    #[test]
    fn the_branch_is_detected_and_the_override_wins() {
        let repo = Repo::new();
        assert_eq!(resolved(repo.path()).branch.as_deref(), Some("main"));
        let id = resolve(
            repo.path(),
            &Overrides {
                branch: Some("feature/x"),
                ..Default::default()
            },
        );
        assert_eq!(id.branch.as_deref(), Some("feature/x"));
    }

    #[test]
    fn a_detached_head_reports_no_branch() {
        let repo = Repo::new();
        let sha = repo.run(&["rev-parse", "HEAD"]);
        repo.run(&["checkout", "--detach", &sha]);
        assert_eq!(resolved(repo.path()).branch, None);
    }

    #[test]
    fn the_merge_base_is_the_fork_point_not_the_branch_tip() {
        let repo = Repo::new();
        let fork_point = repo.run(&["rev-parse", "HEAD"]);
        repo.run(&["checkout", "-b", "feature"]);
        repo.write("feature.py", "f = 1\n");
        repo.run(&["add", "-A"]);
        repo.run(&["commit", "-m", "feature work"]);
        repo.run(&["checkout", "main"]);
        repo.write("other.py", "o = 1\n");
        repo.run(&["add", "-A"]);
        repo.run(&["commit", "-m", "unrelated"]);
        repo.run(&["checkout", "feature"]);

        let id = resolve(
            repo.path(),
            &Overrides {
                base_ref: Some("main"),
                ..Default::default()
            },
        );
        assert_eq!(
            id.merge_base.as_deref(),
            Some(fork_point.as_str()),
            "comparing against main's tip would attribute the unrelated commit's findings here"
        );
    }

    #[test]
    fn a_base_ref_that_is_not_present_locally_is_absent_not_fatal() {
        let repo = Repo::new();
        let id = resolve(
            repo.path(),
            &Overrides {
                base_ref: Some("origin/does-not-exist"),
                ..Default::default()
            },
        );
        assert_eq!(id.merge_base, None);
    }

    #[test]
    fn same_repository_only_claims_a_mismatch_when_both_sides_are_verified() {
        let verified = RepoIdentity {
            root_commit: Some("aaa".into()),
            root_commit_verified: true,
            ..Default::default()
        };
        let unverified = RepoIdentity {
            root_commit: Some("bbb".into()),
            root_commit_verified: false,
            ..Default::default()
        };
        assert_eq!(
            same_repository(Some("aaa"), true, &verified),
            RootCommitVerdict::Match
        );
        assert_eq!(
            same_repository(Some("bbb"), true, &verified),
            RootCommitVerdict::Mismatch
        );
        assert_eq!(
            same_repository(Some("aaa"), false, &verified),
            RootCommitVerdict::Unverifiable
        );
        assert_eq!(
            same_repository(Some("aaa"), true, &unverified),
            RootCommitVerdict::Unverifiable
        );
        assert_eq!(
            same_repository(None, true, &verified),
            RootCommitVerdict::Unverifiable
        );
    }
}
