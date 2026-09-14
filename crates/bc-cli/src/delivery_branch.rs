//! Explicit, create-only publication of an approved detached remediation snapshot.
//! Plumbing avoids repository hooks and clean filters. The empty push lease is
//! an atomic requirement that the destination does not exist, never permission
//! to replace an existing branch.

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

const OUTPUT_LIMIT: usize = 4 * 1024 * 1024;
const FILE_LIMIT: u64 = 32 * 1024 * 1024;
const TOTAL_LIMIT: u64 = 256 * 1024 * 1024;

#[derive(Debug, Serialize)]
pub struct BranchReceipt {
    pub remote: String,
    pub branch: String,
    pub commit: String,
    /// False when the approved snapshot has no content changes.
    pub published: bool,
}

pub fn validate_selection(remote: &str, branch: &str) -> Result<(), String> {
    if remote.is_empty()
        || remote.len() > 128
        || !remote
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        || !remote.as_bytes()[0].is_ascii_alphanumeric()
        || matches!(remote, "." | "..")
    {
        return Err("delivery remote must be a named Git remote, not a URL or option".into());
    }
    if branch.is_empty()
        || branch.len() > 240
        || branch.starts_with('-')
        || branch.contains("..")
        || branch.contains("@{")
        || !branch
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'/'))
        || branch
            .split('/')
            .any(|s| s.is_empty() || s.starts_with('.') || s.ends_with('.') || s.ends_with(".lock"))
        || branch == "HEAD"
    {
        return Err("delivery branch must be a valid new branch name".into());
    }
    Ok(())
}

async fn read_bounded(mut reader: impl AsyncRead + Unpin) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut buf = [0_u8; 8192];
    let mut overflow = false;
    loop {
        let n = reader
            .read(&mut buf)
            .await
            .map_err(|_| "cannot read Git output")?;
        if n == 0 {
            break;
        }
        if out.len() + n <= OUTPUT_LIMIT {
            out.extend_from_slice(&buf[..n]);
        } else {
            overflow = true;
        }
    }
    if overflow {
        Err("Git output exceeded publication limit".into())
    } else {
        Ok(out)
    }
}

/// Suppress raw Git errors: remote URLs and credential-bearing HTTP headers
/// must not leak into the report. Authentication is deliberately noninteractive.
async fn git(
    root: &Path,
    filters: &[String],
    index: Option<&Path>,
    args: &[&str],
    input: Option<&[u8]>,
) -> Result<Vec<u8>, String> {
    let mut cmd = Command::new("git");
    cmd.current_dir(root)
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "credential.helper=",
            "-c",
            "core.sshCommand=ssh",
            "-c",
            "protocol.allow=never",
            "-c",
            "protocol.https.allow=always",
            "-c",
            "protocol.ssh.allow=always",
            "-c",
            "protocol.file.allow=always",
            "-c",
            "push.followTags=false",
            "-c",
            "push.recurseSubmodules=no",
            "-c",
            "status.renames=false",
            "-c",
            "push.gpgsign=false",
        ])
        .args(filters)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("GIT_") {
            cmd.env_remove(key);
        }
    }
    cmd.env_remove("SSH_ASKPASS")
        .env("SSH_ASKPASS_REQUIRE", "never")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_LITERAL_PATHSPECS", "1")
        .env("GIT_SSH_COMMAND", "ssh -oBatchMode=yes");
    if let Some(index) = index {
        cmd.env("GIT_INDEX_FILE", index);
    }
    let mut child = cmd
        .spawn()
        .map_err(|_| "cannot start Git for branch delivery")?;
    let stdout = child.stdout.take().ok_or("missing Git stdout")?;
    let stderr = child.stderr.take().ok_or("missing Git stderr")?;
    let mut stdin = child.stdin.take().ok_or("missing Git stdin")?;
    let operation = async {
        let writer = async {
            if let Some(bytes) = input {
                stdin
                    .write_all(bytes)
                    .await
                    .map_err(|_| "cannot send snapshot to Git")?;
            }
            drop(stdin);
            Ok::<(), String>(())
        };
        let (write, out, err, status) = tokio::join!(
            writer,
            read_bounded(stdout),
            read_bounded(stderr),
            child.wait()
        );
        write?;
        let out = out?;
        err?;
        if !status.map_err(|_| "cannot wait for Git")?.success() {
            return Err(format!(
                "Git {} failed; publication was not confirmed (raw output withheld)",
                args.first().unwrap_or(&"operation")
            ));
        }
        Ok(out)
    };
    match tokio::time::timeout(Duration::from_secs(120), operation).await {
        Ok(result) => result,
        Err(_) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            Err("Git branch delivery timed out; inspect the remote before retrying".into())
        }
    }
}

fn text(bytes: Vec<u8>) -> Result<String, String> {
    String::from_utf8(bytes)
        .map(|s| s.trim().to_owned())
        .map_err(|_| "Git returned non-UTF-8 metadata".into())
}

fn validate_path(path: &str) -> Result<(), String> {
    let blocked = path.is_empty()
        || path.contains('\\')
        || path.contains(':')
        || path.split('/').any(|part| {
            let p = part.to_ascii_lowercase();
            part.is_empty()
                || matches!(part, "." | "..")
                || part.chars().any(char::is_control)
                || matches!(
                    p.as_str(),
                    ".git"
                        | "security-scan"
                        | ".ssh"
                        | ".aws"
                        | ".kube"
                        | "node_modules"
                        | "target"
                        | "id_rsa"
                        | "id_ed25519"
                        | "credentials"
                )
                || p == ".env"
                || p.starts_with(".env.")
                || p.ends_with(".pem")
                || p.ends_with(".key")
                || p.ends_with(".p12")
                || p.ends_with(".pfx")
        });
    if blocked {
        Err("branch snapshot contains a prohibited or ambiguous changed path".into())
    } else {
        Ok(())
    }
}

/// Called only after the scan/remediation/assurance gates allow publication.
/// The caller must retain the worktree if this returns an error.
pub async fn publish(worktree: &Path, remote: &str, branch: &str) -> Result<BranchReceipt, String> {
    validate_selection(remote, branch)?;
    // Even `status` can invoke clean/process filters. Enumerate configuration
    // without executing it, then disable every configured filter for this run.
    // Values can contain credentials and are never logged or returned.
    let configuration = git(worktree, &[], None, &["config", "--null", "--list"], None).await?;
    let mut names = std::collections::BTreeSet::new();
    for entry in configuration.split(|b| *b == 0) {
        let key = entry.split(|b| *b == b'\n').next().unwrap_or_default();
        let key = std::str::from_utf8(key).map_err(|_| "Git configuration keys must be UTF-8")?;
        if let Some(rest) = key.strip_prefix("filter.") {
            if let Some((name, field)) = rest.rsplit_once('.') {
                if matches!(field, "clean" | "process" | "required") {
                    names.insert(name.to_owned());
                }
            }
        }
    }
    let mut filters = Vec::new();
    for name in names {
        for (field, value) in [("clean", ""), ("process", ""), ("required", "false")] {
            filters.push("-c".to_owned());
            filters.push(format!("filter.{name}.{field}={value}"));
        }
    }
    // Require affirmative detached-HEAD evidence; command errors never grant
    // permission to update HEAD on an attached user branch.
    let head_kind = text(
        git(
            worktree,
            &filters,
            None,
            &["rev-parse", "--abbrev-ref", "HEAD"],
            None,
        )
        .await
        .map_err(|_| "branch delivery requires an isolated detached worktree")?,
    )?;
    if head_kind != "HEAD" {
        return Err("branch delivery requires an isolated detached worktree".into());
    }
    let parent = text(
        git(
            worktree,
            &filters,
            None,
            &["rev-parse", "--verify", "HEAD^{commit}"],
            None,
        )
        .await?,
    )?;
    // Resolve only an already configured remote; never accept a command/URL here.
    let destinations = text(
        git(
            worktree,
            &filters,
            None,
            &["remote", "get-url", "--push", "--all", remote],
            None,
        )
        .await?,
    )?;
    if destinations.lines().count() != 1 {
        return Err("branch delivery requires exactly one configured push destination".into());
    }
    let reference = format!("refs/heads/{branch}");
    if git(
        worktree,
        &filters,
        None,
        &["show-ref", "--verify", "--quiet", &reference],
        None,
    )
    .await
    .is_ok()
    {
        return Err("delivery branch already exists locally; choose a new branch".into());
    }
    let status = git(
        worktree,
        &filters,
        None,
        &[
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--ignore-submodules=none",
        ],
        None,
    )
    .await?;
    let mut changes = Vec::new();
    for record in status.split(|b| *b == 0).filter(|s| !s.is_empty()) {
        if record.len() < 4
            || record[2] != b' '
            || record[..2].iter().any(|b| !b" MAD?".contains(b))
        {
            return Err("snapshot has unresolved or unsupported Git changes".into());
        }
        let path = std::str::from_utf8(&record[3..]).map_err(|_| "snapshot paths must be UTF-8")?;
        validate_path(path)?;
        changes.push(path.to_owned());
    }
    if changes.is_empty() {
        return Ok(BranchReceipt {
            remote: remote.into(),
            branch: branch.into(),
            commit: parent,
            published: false,
        });
    }
    if changes.len() > 10_000 {
        return Err("snapshot exceeds changed-file limit".into());
    }
    changes.sort();
    changes.dedup();
    let temp = tempfile::tempdir().map_err(|_| "cannot create private publication index")?;
    let index = temp.path().join("index");
    git(
        worktree,
        &filters,
        Some(&index),
        &["read-tree", &parent],
        None,
    )
    .await?;
    let mut total = 0;
    for path in changes {
        let full = worktree.join(&path);
        // Check every parent component too; a symlink directory must not expose
        // files outside the approved worktree.
        let mut prefix = worktree.to_path_buf();
        for part in path.split('/') {
            prefix.push(part);
            match std::fs::symlink_metadata(&prefix) {
                Ok(m) if m.file_type().is_symlink() => {
                    return Err("snapshot contains a changed symlink".into())
                }
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err("cannot inspect snapshot path".into()),
            }
        }
        let metadata = match std::fs::symlink_metadata(&full) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                git(
                    worktree,
                    &filters,
                    Some(&index),
                    &["update-index", "--force-remove", "--", &path],
                    None,
                )
                .await?;
                continue;
            }
            Err(_) => return Err("cannot inspect changed file".into()),
        };
        if !metadata.is_file() {
            return Err("changed directories/submodules cannot be published".into());
        }
        total += metadata.len();
        if metadata.len() > FILE_LIMIT || total > TOTAL_LIMIT {
            return Err("snapshot exceeds publication size limit".into());
        }
        let bytes = std::fs::read(&full).map_err(|_| "cannot read changed file")?;
        if bytes.len() as u64 > FILE_LIMIT {
            return Err("changed file grew beyond publication limit".into());
        }
        if let Ok(content) = std::str::from_utf8(&bytes) {
            if bc_redact::redact(content) != content {
                return Err(
                    "changed file contains a recognised sensitive value; publication blocked"
                        .into(),
                );
            }
        }
        let blob = text(
            git(
                worktree,
                &filters,
                Some(&index),
                &["hash-object", "-w", "--no-filters", "--stdin"],
                Some(&bytes),
            )
            .await?,
        )?;
        #[cfg(unix)]
        let mode = {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o111 != 0 {
                "100755"
            } else {
                "100644"
            }
        };
        #[cfg(not(unix))]
        let mode = {
            // Windows filesystem permissions do not encode Git executable bits.
            let tracked = git(
                worktree,
                &filters,
                None,
                &["ls-files", "--stage", "-z", "--", &path],
                None,
            )
            .await?;
            if tracked.starts_with(b"100755 ") {
                "100755"
            } else {
                "100644"
            }
        };
        git(
            worktree,
            &filters,
            Some(&index),
            &["update-index", "--add", "--cacheinfo", mode, &blob, &path],
            None,
        )
        .await?;
    }
    let tree = text(git(worktree, &filters, Some(&index), &["write-tree"], None).await?)?;
    let old_tree = text(
        git(
            worktree,
            &filters,
            None,
            &["rev-parse", "HEAD^{tree}"],
            None,
        )
        .await?,
    )?;
    if tree == old_tree {
        return Ok(BranchReceipt {
            remote: remote.into(),
            branch: branch.into(),
            commit: parent,
            published: false,
        });
    }
    let commit = text(
        git(
            worktree,
            &filters,
            None,
            &[
                "commit-tree",
                &tree,
                "-p",
                &parent,
                "-m",
                "Apply BC SAST remediation and target tests",
            ],
            None,
        )
        .await?,
    )?;
    // Empty old value guarantees local create-only, including concurrent callers.
    git(
        worktree,
        &filters,
        None,
        &["update-ref", &reference, &commit, ""],
        None,
    )
    .await?;
    // HEAD is detached: this cannot move the user's original branch.
    git(
        worktree,
        &filters,
        None,
        &["update-ref", "HEAD", &commit, &parent],
        None,
    )
    .await?;
    let lease = format!("--force-with-lease={reference}:");
    let refspec = format!("HEAD:{reference}");
    git(
        worktree,
        &filters,
        None,
        &[
            "push",
            "--porcelain",
            "--no-verify",
            "--receive-pack=git-receive-pack",
            &lease,
            "--",
            remote,
            &refspec,
        ],
        None,
    )
    .await?;
    Ok(BranchReceipt {
        remote: remote.into(),
        branch: branch.into(),
        commit,
        published: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn local_git(root: &Path, args: &[&str]) -> String {
        let out = std::process::Command::new("git")
            .current_dir(root)
            .args(args)
            .output()
            .unwrap();
        assert!(out.status.success(), "synthetic Git setup failed: {out:?}");
        String::from_utf8(out.stdout).unwrap().trim().into()
    }
    #[test]
    fn selection_rejects_urls_options_and_invalid_refs() {
        for (r, b) in [
            ("https://example.com/repo", "fix"),
            ("--mirror", "fix"),
            ("origin", "../main"),
            ("origin", "x.lock"),
            ("origin", "x//y"),
            ("origin", "HEAD"),
        ] {
            assert!(validate_selection(r, b).is_err());
        }
        assert!(validate_selection("origin", "bc-sast/fix-123").is_ok());
    }
    #[tokio::test]
    async fn publishes_one_commit_with_new_tests_and_refuses_existing_remote() {
        let repo = tempfile::tempdir().unwrap();
        let remote = tempfile::tempdir().unwrap();
        local_git(remote.path(), &["init", "--bare", "-q"]);
        local_git(repo.path(), &["init", "-q"]);
        local_git(
            repo.path(),
            &["config", "user.email", "test@example.invalid"],
        );
        local_git(repo.path(), &["config", "user.name", "BC SAST test"]);
        std::fs::write(repo.path().join("app.txt"), "before\n").unwrap();
        local_git(repo.path(), &["add", "app.txt"]);
        local_git(repo.path(), &["commit", "-qm", "baseline"]);
        let baseline = local_git(repo.path(), &["rev-parse", "HEAD"]);
        local_git(repo.path(), &["checkout", "--detach", "-q"]);
        local_git(
            repo.path(),
            &["remote", "add", "origin", remote.path().to_str().unwrap()],
        );
        let unchanged = publish(repo.path(), "origin", "bc-sast/noop")
            .await
            .unwrap();
        assert!(!unchanged.published);
        assert_eq!(unchanged.commit, baseline);
        assert_eq!(local_git(repo.path(), &["rev-parse", "HEAD"]), baseline);
        assert!(local_git(repo.path(), &["for-each-ref", "refs/heads/bc-sast/noop"]).is_empty());
        assert!(local_git(remote.path(), &["for-each-ref", "refs/heads/bc-sast/noop"]).is_empty());
        std::fs::write(repo.path().join("app.txt"), "after\n").unwrap();
        std::fs::create_dir(repo.path().join("tests")).unwrap();
        std::fs::write(repo.path().join("tests/regression.txt"), "test fixture\n").unwrap();
        std::fs::write(repo.path().join(".gitattributes"), "*.txt filter=blocked\n").unwrap();
        local_git(
            repo.path(),
            &[
                "config",
                "filter.blocked.clean",
                "bc-sast-must-never-execute-this-filter",
            ],
        );
        local_git(repo.path(), &["config", "filter.blocked.required", "true"]);
        let receipt = publish(repo.path(), "origin", "bc-sast/fix").await.unwrap();
        assert!(receipt.published);
        assert_eq!(
            local_git(remote.path(), &["rev-parse", "bc-sast/fix^"]),
            baseline
        );
        assert_eq!(
            local_git(remote.path(), &["show", "bc-sast/fix:app.txt"]),
            "after"
        );
        assert_eq!(
            local_git(remote.path(), &["show", "bc-sast/fix:tests/regression.txt"]),
            "test fixture"
        );
        // Remove only the synthetic local ref; an existing remote must still
        // reject the empty lease even when local collision checks cannot see it.
        local_git(repo.path(), &["update-ref", "-d", "refs/heads/bc-sast/fix"]);
        std::fs::write(repo.path().join("app.txt"), "another\n").unwrap();
        assert!(publish(repo.path(), "origin", "bc-sast/fix").await.is_err());
        assert_eq!(
            local_git(remote.path(), &["rev-parse", "bc-sast/fix"]),
            receipt.commit
        );
    }
    #[tokio::test]
    async fn refuses_attached_checkout() {
        let repo = tempfile::tempdir().unwrap();
        local_git(repo.path(), &["init", "-q"]);
        let error = publish(repo.path(), "origin", "bc-sast/fix")
            .await
            .unwrap_err();
        assert!(error.contains("detached"));
    }

    fn repo_with_remote() -> (tempfile::TempDir, tempfile::TempDir, String) {
        let repo = tempfile::tempdir().unwrap();
        let remote = tempfile::tempdir().unwrap();
        local_git(remote.path(), &["init", "--bare", "-q"]);
        local_git(repo.path(), &["init", "-q"]);
        local_git(
            repo.path(),
            &["config", "user.email", "test@example.invalid"],
        );
        local_git(repo.path(), &["config", "user.name", "BC SAST test"]);
        std::fs::write(repo.path().join("app.txt"), "before\n").unwrap();
        std::fs::create_dir(repo.path().join("tests")).unwrap();
        std::fs::write(repo.path().join("tests/existing.txt"), "kept\n").unwrap();
        local_git(repo.path(), &["add", "-A"]);
        local_git(repo.path(), &["commit", "-qm", "baseline"]);
        let baseline = local_git(repo.path(), &["rev-parse", "HEAD"]);
        local_git(repo.path(), &["checkout", "--detach", "-q"]);
        local_git(
            repo.path(),
            &["remote", "add", "origin", remote.path().to_str().unwrap()],
        );
        (repo, remote, baseline)
    }

    async fn refuses(repo: &Path) -> String {
        publish(repo, "origin", "bc-sast/fix").await.unwrap_err()
    }

    #[tokio::test]
    async fn git_output_and_metadata_that_exceed_their_bounds_are_refused() {
        let bounded = read_bounded(&b"receipt"[..]).await.unwrap();
        assert_eq!(bounded, b"receipt");
        let oversized = vec![b'x'; OUTPUT_LIMIT + 1];
        assert_eq!(
            read_bounded(&oversized[..]).await.unwrap_err(),
            "Git output exceeded publication limit"
        );
        assert_eq!(text(b"  abc \n".to_vec()).unwrap(), "abc");
        assert_eq!(
            text(vec![0xff, 0xfe]).unwrap_err(),
            "Git returned non-UTF-8 metadata"
        );
    }

    #[tokio::test]
    async fn publication_requires_a_head_that_resolves_to_a_real_commit() {
        let (repo, _remote, _baseline) = repo_with_remote();
        local_git(repo.path(), &["checkout", "-q", "-"]);
        assert!(refuses(repo.path()).await.contains("detached"));

        local_git(repo.path(), &["checkout", "--detach", "-q"]);
        let tree = local_git(repo.path(), &["rev-parse", "HEAD^{tree}"]);
        std::fs::write(repo.path().join(".git/HEAD"), format!("{tree}\n")).unwrap();
        assert!(refuses(repo.path()).await.contains("rev-parse"));
    }

    #[tokio::test]
    async fn a_remote_must_resolve_to_exactly_one_configured_push_destination() {
        let (repo, remote, _baseline) = repo_with_remote();
        assert!(publish(repo.path(), "upstream", "bc-sast/fix")
            .await
            .unwrap_err()
            .contains("Git remote failed"));
        for _ in 0..2 {
            local_git(
                repo.path(),
                &[
                    "remote",
                    "set-url",
                    "--add",
                    "--push",
                    "origin",
                    remote.path().to_str().unwrap(),
                ],
            );
        }
        assert_eq!(
            refuses(repo.path()).await,
            "branch delivery requires exactly one configured push destination"
        );
    }

    #[tokio::test]
    async fn an_existing_local_branch_is_never_reused_as_the_delivery_destination() {
        let (repo, _remote, baseline) = repo_with_remote();
        local_git(
            repo.path(),
            &["update-ref", "refs/heads/bc-sast/fix", &baseline],
        );
        assert_eq!(
            refuses(repo.path()).await,
            "delivery branch already exists locally; choose a new branch"
        );
    }

    #[tokio::test]
    async fn a_snapshot_git_cannot_classify_is_never_published() {
        let (repo, _remote, _baseline) = repo_with_remote();
        std::fs::remove_file(repo.path().join("app.txt")).unwrap();
        std::os::unix::fs::symlink("tests/existing.txt", repo.path().join("app.txt")).unwrap();
        assert_eq!(
            refuses(repo.path()).await,
            "snapshot has unresolved or unsupported Git changes"
        );
    }

    #[tokio::test]
    async fn a_snapshot_with_more_changed_files_than_the_limit_is_refused() {
        let (repo, _remote, _baseline) = repo_with_remote();
        for index in 0..10_001 {
            std::fs::write(repo.path().join(format!("new{index}.txt")), "x").unwrap();
        }
        assert_eq!(
            refuses(repo.path()).await,
            "snapshot exceeds changed-file limit"
        );
    }

    #[tokio::test]
    async fn changed_paths_the_publisher_cannot_vouch_for_stop_the_whole_commit() {
        let (repo, _remote, _baseline) = repo_with_remote();
        std::os::unix::fs::symlink("/etc/hosts", repo.path().join("alias.txt")).unwrap();
        assert_eq!(
            refuses(repo.path()).await,
            "snapshot contains a changed symlink"
        );
        std::fs::remove_file(repo.path().join("alias.txt")).unwrap();

        // A tracked file replaced by a directory: Git reports the file as
        // deleted, but its path is no longer a file the commit can carry.
        std::fs::remove_file(repo.path().join("app.txt")).unwrap();
        std::fs::create_dir(repo.path().join("app.txt")).unwrap();
        std::fs::write(repo.path().join("app.txt/inner.txt"), "x").unwrap();
        assert_eq!(
            refuses(repo.path()).await,
            "changed directories/submodules cannot be published"
        );
        std::fs::remove_dir_all(repo.path().join("app.txt")).unwrap();

        std::fs::write(
            repo.path().join("tests/leaked.txt"),
            "aws_key = AKIAIOSFODNN7EXAMPLE\n",
        )
        .unwrap();
        assert_eq!(
            refuses(repo.path()).await,
            "changed file contains a recognised sensitive value; publication blocked"
        );
        std::fs::remove_file(repo.path().join("tests/leaked.txt")).unwrap();

        let oversized = std::fs::File::create(repo.path().join("tests/huge.bin")).unwrap();
        oversized.set_len(FILE_LIMIT + 1).unwrap();
        drop(oversized);
        assert_eq!(
            refuses(repo.path()).await,
            "snapshot exceeds publication size limit"
        );
    }

    #[tokio::test]
    async fn a_changed_path_whose_parent_is_no_longer_a_directory_is_refused() {
        let (repo, _remote, _baseline) = repo_with_remote();
        // Ignoring `tests` keeps the replacement file itself out of the
        // change list, leaving only the tracked path underneath it.
        std::fs::write(repo.path().join(".gitignore"), "/tests\n").unwrap();
        local_git(repo.path(), &["add", ".gitignore"]);
        local_git(
            repo.path(),
            &["commit", "-qm", "ignore the tests directory"],
        );
        std::fs::remove_dir_all(repo.path().join("tests")).unwrap();
        std::fs::write(repo.path().join("tests"), "not a directory\n").unwrap();
        assert_eq!(refuses(repo.path()).await, "cannot inspect snapshot path");
    }

    #[tokio::test]
    async fn a_deleted_test_is_removed_from_the_published_commit() {
        let (repo, remote, baseline) = repo_with_remote();
        std::fs::remove_file(repo.path().join("tests/existing.txt")).unwrap();
        std::fs::write(repo.path().join("tests/replacement.txt"), "new coverage\n").unwrap();
        let receipt = publish(repo.path(), "origin", "bc-sast/fix").await.unwrap();
        assert!(receipt.published);
        assert_eq!(
            local_git(remote.path(), &["rev-parse", "bc-sast/fix^"]),
            baseline
        );
        assert_eq!(
            local_git(
                remote.path(),
                &["ls-tree", "--name-only", "bc-sast/fix", "tests/"]
            ),
            "tests/replacement.txt"
        );
    }

    #[tokio::test]
    async fn binary_and_executable_changes_keep_their_bytes_and_mode() {
        use std::os::unix::fs::PermissionsExt;
        let (repo, remote, _baseline) = repo_with_remote();
        let binary = repo.path().join("tests/fixture.bin");
        std::fs::write(&binary, [0xff, 0x00, 0xfe]).unwrap();
        let script = repo.path().join("tests/run.sh");
        std::fs::write(&script, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            publish(repo.path(), "origin", "bc-sast/fix")
                .await
                .unwrap()
                .published
        );
        let listing = local_git(remote.path(), &["ls-tree", "bc-sast/fix", "tests/"]);
        assert!(listing.contains("100755"), "{listing}");
        assert!(listing.contains("tests/run.sh"));
        assert!(listing.contains("tests/fixture.bin"));
    }

    #[tokio::test]
    async fn a_snapshot_whose_content_matches_head_publishes_no_commit() {
        // Git reports staged and untracked records for the same unchanged
        // bytes; the resulting tree is identical, so nothing is published.
        let (repo, remote, baseline) = repo_with_remote();
        local_git(repo.path(), &["rm", "-q", "--cached", "app.txt"]);
        let receipt = publish(repo.path(), "origin", "bc-sast/quiet")
            .await
            .unwrap();
        assert!(!receipt.published);
        assert_eq!(receipt.commit, baseline);
        assert!(local_git(remote.path(), &["for-each-ref", "refs/heads/"]).is_empty());
    }

    #[tokio::test]
    async fn a_configuration_key_git_cannot_render_as_utf8_stops_publication() {
        let (repo, _remote, _baseline) = repo_with_remote();
        let config = repo.path().join(".git/config");
        let mut raw = std::fs::read(&config).unwrap();
        // A `filter.<key>` with no subsection at all must be skipped, not
        // mistaken for a named filter to disable.
        raw.extend_from_slice(b"[filter]\n\tclean = cat\n");
        raw.extend_from_slice(b"[filter \"");
        raw.extend_from_slice(&[0xff, 0xfe]);
        raw.extend_from_slice(b"\"]\n\tclean = cat\n");
        std::fs::write(&config, raw).unwrap();
        assert_eq!(
            refuses(repo.path()).await,
            "Git configuration keys must be UTF-8"
        );
    }

    #[test]
    fn changed_secret_and_artifact_paths_are_not_silently_published() {
        for p in [
            ".env",
            "sub/.git/config",
            "security-scan/report.md",
            "../outside",
            "x\\y",
            "keys/a.pem",
        ] {
            assert!(validate_path(p).is_err());
        }
        assert!(validate_path("tests/security_regression.rs").is_ok());
    }
}
