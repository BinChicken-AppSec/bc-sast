use std::path::{Path, PathBuf};
use std::time::Duration;

use sha1::{Digest, Sha1};

pub(crate) fn is_remote(reference: &str) -> bool {
    reference.starts_with("http://")
        || reference.starts_with("https://")
        || reference.starts_with("git@")
        || reference.starts_with("ssh://")
        || reference.ends_with(".git")
}

pub(crate) fn scrub_url_secrets(s: &str) -> String {
    if s.is_empty() {
        return s.to_string();
    }
    let re = regex::Regex::new(r"(\w[\w+.\-]*://)[^/@\s]+@")
        .expect("hand-written pattern is a valid, fixed regex");
    re.replace_all(s, "$1***@").into_owned()
}

fn with_token(url: &str, token: Option<&str>) -> String {
    let Some(token) = token.filter(|t| !t.is_empty()) else {
        return url.to_string();
    };
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return url.to_string();
    }
    let (scheme, rest) = url
        .split_once("://")
        .expect("already checked url starts with http:// or https://");
    if rest.split('/').next().unwrap_or("").contains('@') {
        return url.to_string();
    }
    format!("{scheme}://x-access-token:{token}@{rest}")
}

fn module_name_from(reference: &str) -> String {
    let trimmed = reference.trim_end_matches('/');
    let tail = trimmed.rsplit('/').next().unwrap_or(trimmed);
    let tail = tail.strip_suffix(".git").unwrap_or(tail);
    if tail.is_empty() {
        "repo".to_string()
    } else {
        tail.to_string()
    }
}

fn safe_dest_name(candidate: &str) -> Result<String, String> {
    let safe: String = candidate
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if safe == "." || safe == ".." || safe.chars().all(|c| c == '.') {
        return Err(format!(
            "refusing unsafe clone dest name {safe:?} derived from {candidate:?}: \
             '.'/'..' would escape the workspace"
        ));
    }
    Ok(safe)
}

fn sha1_hex32(input: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(input.as_bytes());
    let digest: String = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    digest[..32].to_string()
}

pub(crate) fn state_root() -> Result<PathBuf, String> {
    let db_path = appsec_checkpoint::default_db_path().map_err(|e| e.to_string())?;
    Ok(db_path
        .parent()
        .expect("default_db_path always returns a file inside a directory")
        .to_path_buf())
}

fn stage_marker_dir() -> Result<PathBuf, String> {
    Ok(state_root()?.join("stage-markers"))
}

fn stage_marker_path(dest: &Path) -> Result<PathBuf, String> {
    let key = sha1_hex32(&dest.to_string_lossy());
    Ok(stage_marker_dir()?.join(format!("{key}.json")))
}

fn write_stage_marker(dest: &Path, reference: &str) {
    let (Ok(dir), Ok(marker_path)) = (stage_marker_dir(), stage_marker_path(dest)) else {
        return;
    };
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let body = serde_json::json!({"v": 1, "ref_id": sha1_hex32(reference)}).to_string();
    if let Err(e) = std::fs::write(&marker_path, body) {
        eprintln!(
            "  [batch] WARN: could not write stage marker for {}: {e}",
            dest.display()
        );
    }
}

fn stage_dir_bound(dest: &Path, reference: &str) -> bool {
    let Ok(marker_path) = stage_marker_path(dest) else {
        return false;
    };
    let Ok(text) = std::fs::read_to_string(&marker_path) else {
        return false;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
        return false;
    };
    value.get("ref_id").and_then(|v| v.as_str()) == Some(sha1_hex32(reference).as_str())
}

fn has_non_git_content(dest: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(dest) else {
        return false;
    };
    entries
        .flatten()
        .any(|e| e.file_name() != std::ffi::OsStr::new(".git"))
}

pub(crate) async fn acquire_repo(
    reference: &str,
    workspace: &Path,
    dest_name_hint: &str,
    git_token: Option<&str>,
) -> Result<PathBuf, String> {
    if !is_remote(reference) {
        let p = PathBuf::from(reference);
        if !p.is_dir() {
            return Err(format!("local path does not exist: {reference}"));
        }
        return Ok(p);
    }

    std::fs::create_dir_all(workspace)
        .map_err(|e| format!("cannot create workspace {}: {e}", workspace.display()))?;
    let hint = if dest_name_hint.trim().is_empty() {
        module_name_from(reference)
    } else {
        dest_name_hint.to_string()
    };
    let safe = safe_dest_name(&hint)?;
    let dest = workspace.join(&safe);

    if dest.exists() {
        if has_non_git_content(&dest) && stage_dir_bound(&dest, reference) {
            eprintln!("  [batch] reusing verified checkout {}", dest.display());
            return Ok(dest);
        }
        let reason = if has_non_git_content(&dest) {
            "unverified (no matching stage marker — stale, foreign, or pre-seeded)"
        } else {
            "empty"
        };
        eprintln!(
            "  [batch] {reason} dir at {} — removing and re-cloning",
            dest.display()
        );
        let _ = std::fs::remove_dir_all(&dest);
        if dest.exists() {
            eprintln!(
                "  [batch] could not remove {}; reusing as-is",
                dest.display()
            );
            return Ok(dest);
        }
    }

    let clone_url = with_token(reference, git_token);
    eprintln!(
        "  [batch] git clone {} -> {}",
        scrub_url_secrets(reference),
        dest.display()
    );
    let output = run_bounded_clone("git", CLONE_TIMEOUT, &clone_url, &dest, reference).await?;

    if !output.status.success() {
        return Err(clone_failure_message(&output, git_token));
    }
    write_stage_marker(&dest, reference);
    Ok(dest)
}

pub(crate) const CLONE_TIMEOUT: Duration = Duration::from_secs(600);

async fn run_bounded_clone(
    program: &str,
    timeout: Duration,
    clone_url: &str,
    dest: &Path,
    reference: &str,
) -> Result<std::process::Output, String> {
    let mut cmd = tokio::process::Command::new(program);
    cmd.args([
        "-c",
        "core.longpaths=true",
        "clone",
        "--depth",
        "1",
        "--",
        clone_url,
    ])
    .arg(dest)
    .env("GIT_TERMINAL_PROMPT", "0");

    tokio::time::timeout(timeout, cmd.output())
        .await
        .map_err(|_| {
            format!(
                "git clone timed out after {}s: {reference} (network stall or unresponsive remote)",
                timeout.as_secs()
            )
        })?
        .map_err(|e| format!("failed to run git: {e}"))
}

fn clone_failure_message(output: &std::process::Output, git_token: Option<&str>) -> String {
    let mut err = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if err.is_empty() {
        err = String::from_utf8_lossy(&output.stdout).trim().to_string();
    }
    if let Some(t) = git_token.filter(|t| !t.is_empty()) {
        err = err.replace(t, "***");
    }
    format!("git clone failed: {}", scrub_url_secrets(&err))
}

pub(crate) const CLONE_KEEP_DEFAULT: &[&str] = &["security-scan"];

pub(crate) fn purge_clone(root: &Path, keep: &[&str]) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        if keep.iter().any(|k| name == std::ffi::OsStr::new(*k)) {
            continue;
        }
        let path = entry.path();
        if path.is_dir() {
            let _ = std::fs::remove_dir_all(&path);
        } else {
            let _ = std::fs::remove_file(&path);
        }
    }
    let Ok(remaining) = std::fs::read_dir(root) else {
        return;
    };
    let leftover: Vec<String> = remaining
        .flatten()
        .filter(|e| {
            !keep
                .iter()
                .any(|k| e.file_name() == std::ffi::OsStr::new(*k))
        })
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    if !leftover.is_empty() {
        eprintln!(
            "  [cleanup] WARN: {} item(s) survived purge under {}: {}",
            leftover.len(),
            root.display(),
            leftover.join(", ")
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_remote_recognizes_every_supported_url_shape() {
        assert!(is_remote("https://example.com/org/repo.git"));
        assert!(is_remote("http://example.com/org/repo.git"));
        assert!(is_remote("git@github.com:org/repo.git"));
        assert!(is_remote("ssh://git@example.com/org/repo.git"));
        assert!(is_remote("https://example.com/org/repo-without-suffix.git"));
    }

    #[test]
    fn is_remote_is_false_for_a_plain_local_path() {
        assert!(!is_remote("/home/user/repos/app"));
        assert!(!is_remote("./relative/path"));
    }

    #[test]
    fn scrub_url_secrets_masks_inline_userinfo() {
        let scrubbed = scrub_url_secrets("https://x-access-token:ghp_abc123@github.com/o/r.git");
        assert_eq!(scrubbed, "https://***@github.com/o/r.git");
        assert!(!scrubbed.contains("ghp_abc123"));
    }

    #[test]
    fn scrub_url_secrets_is_a_no_op_without_userinfo() {
        assert_eq!(
            scrub_url_secrets("https://github.com/o/r.git"),
            "https://github.com/o/r.git"
        );
    }

    #[test]
    fn scrub_url_secrets_handles_an_empty_string() {
        assert_eq!(scrub_url_secrets(""), "");
    }

    #[test]
    fn with_token_injects_x_access_token_into_a_bare_https_url() {
        assert_eq!(
            with_token("https://github.com/o/r.git", Some("tok")),
            "https://x-access-token:tok@github.com/o/r.git"
        );
    }

    #[test]
    fn with_token_is_a_no_op_without_a_token() {
        assert_eq!(
            with_token("https://github.com/o/r.git", None),
            "https://github.com/o/r.git"
        );
    }

    #[test]
    fn with_token_is_a_no_op_for_a_non_http_url() {
        assert_eq!(
            with_token("git@github.com:o/r.git", Some("tok")),
            "git@github.com:o/r.git"
        );
    }

    #[test]
    fn with_token_is_a_no_op_when_the_url_already_carries_userinfo() {
        assert_eq!(
            with_token("https://user:pass@github.com/o/r.git", Some("tok")),
            "https://user:pass@github.com/o/r.git"
        );
    }

    #[test]
    fn module_name_from_strips_a_trailing_slash_and_git_suffix() {
        assert_eq!(
            module_name_from("https://example.com/org/repo.git/"),
            "repo"
        );
        assert_eq!(module_name_from("https://example.com/org/repo"), "repo");
    }

    #[test]
    fn module_name_from_falls_back_to_repo_when_the_tail_is_empty() {
        assert_eq!(module_name_from(""), "repo");
        assert_eq!(module_name_from("/"), "repo");
    }

    #[test]
    fn safe_dest_name_replaces_unsafe_characters() {
        assert_eq!(safe_dest_name("org/repo name!").unwrap(), "org_repo_name_");
    }

    #[test]
    fn safe_dest_name_refuses_dot_and_dot_dot() {
        assert!(safe_dest_name(".").is_err());
        assert!(safe_dest_name("..").is_err());
        assert!(safe_dest_name("...").is_err());
    }

    #[test]
    fn safe_dest_name_allows_a_name_with_a_literal_dot() {
        assert_eq!(safe_dest_name("my.repo").unwrap(), "my.repo");
    }

    struct StateDirGuard {
        prior: Option<String>,
    }

    impl Drop for StateDirGuard {
        fn drop(&mut self) {
            match self.prior.take() {
                Some(v) => unsafe { std::env::set_var("BC_STATE_DIR", v) },
                None => unsafe { std::env::remove_var("BC_STATE_DIR") },
            }
        }
    }

    fn set_state_dir(dir: &Path) -> StateDirGuard {
        let prior = std::env::var("BC_STATE_DIR").ok();
        unsafe {
            std::env::set_var("BC_STATE_DIR", dir);
        }
        StateDirGuard { prior }
    }

    #[tokio::test]
    async fn a_dir_with_no_marker_is_not_bound() {
        let _lock = crate::tests::ENV_LOCK.lock().await;
        let state_dir = tempfile::tempdir().unwrap();
        let _guard = set_state_dir(state_dir.path());
        let dest = tempfile::tempdir().unwrap();
        assert!(!stage_dir_bound(dest.path(), "https://example.com/o/r.git"));
    }

    #[tokio::test]
    async fn write_then_check_round_trips_for_the_same_ref() {
        let _lock = crate::tests::ENV_LOCK.lock().await;
        let state_dir = tempfile::tempdir().unwrap();
        let _guard = set_state_dir(state_dir.path());
        let dest = tempfile::tempdir().unwrap();
        write_stage_marker(dest.path(), "https://example.com/o/r.git");
        assert!(stage_dir_bound(dest.path(), "https://example.com/o/r.git"));
        assert!(!stage_dir_bound(
            dest.path(),
            "https://example.com/o/other.git"
        ));
    }

    #[test]
    fn has_non_git_content_ignores_a_bare_dot_git_dir() {
        let dest = tempfile::tempdir().unwrap();
        std::fs::create_dir(dest.path().join(".git")).unwrap();
        assert!(!has_non_git_content(dest.path()));
        std::fs::write(dest.path().join("README.md"), "hi").unwrap();
        assert!(has_non_git_content(dest.path()));
    }

    #[tokio::test]
    async fn acquire_repo_returns_an_existing_local_directory_as_is() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let got = acquire_repo(
            &dir.path().display().to_string(),
            workspace.path(),
            "hint",
            None,
        )
        .await
        .unwrap();
        assert_eq!(got, dir.path());
    }

    #[tokio::test]
    async fn acquire_repo_rejects_a_missing_local_path() {
        let workspace = tempfile::tempdir().unwrap();
        let err = acquire_repo("/nonexistent/local/path", workspace.path(), "hint", None)
            .await
            .unwrap_err();
        assert!(err.contains("does not exist"));
    }

    fn init_source_repo(dir: &Path) {
        let run = |args: &[&str]| {
            let status = std::process::Command::new("git")
                .args(args)
                .current_dir(dir)
                .env("GIT_AUTHOR_NAME", "t")
                .env("GIT_AUTHOR_EMAIL", "t@t")
                .env("GIT_COMMITTER_NAME", "t")
                .env("GIT_COMMITTER_EMAIL", "t@t")
                .output()
                .unwrap();
            assert!(status.status.success(), "git {args:?}: {status:?}");
        };
        run(&["init", "-q", "-b", "main"]);
        std::fs::write(dir.join("app.py"), "print('hi')\n").unwrap();
        run(&["add", "."]);
        run(&["commit", "-q", "-m", "init"]);
    }

    #[tokio::test]
    async fn acquire_repo_clones_a_remote_style_ref_into_the_workspace() {
        let _lock = crate::tests::ENV_LOCK.lock().await;
        let state_dir = tempfile::tempdir().unwrap();
        let _guard = set_state_dir(state_dir.path());
        let source = tempfile::tempdir().unwrap();
        let source_repo = source.path().join("origin.git");
        std::fs::create_dir(&source_repo).unwrap();
        init_source_repo(&source_repo);

        let workspace = tempfile::tempdir().unwrap();
        let dest = acquire_repo(
            &source_repo.display().to_string(),
            workspace.path(),
            "origin",
            None,
        )
        .await
        .unwrap();
        assert!(dest.starts_with(workspace.path()));
        assert!(dest.join("app.py").is_file());
    }

    #[tokio::test]
    async fn acquire_repo_reuses_a_verified_checkout_on_the_second_call() {
        let _lock = crate::tests::ENV_LOCK.lock().await;
        let state_dir = tempfile::tempdir().unwrap();
        let _guard = set_state_dir(state_dir.path());
        let source = tempfile::tempdir().unwrap();
        let source_repo = source.path().join("origin.git");
        std::fs::create_dir(&source_repo).unwrap();
        init_source_repo(&source_repo);

        let workspace = tempfile::tempdir().unwrap();
        let reference = source_repo.display().to_string();
        let first = acquire_repo(&reference, workspace.path(), "origin", None)
            .await
            .unwrap();
        std::fs::write(first.join("marker.txt"), "kept").unwrap();
        let second = acquire_repo(&reference, workspace.path(), "origin", None)
            .await
            .unwrap();
        assert_eq!(first, second);
        assert!(
            second.join("marker.txt").is_file(),
            "expected reuse, not a re-clone"
        );
    }

    #[tokio::test]
    async fn acquire_repo_re_clones_an_unverified_dir_at_the_same_destination() {
        let _lock = crate::tests::ENV_LOCK.lock().await;
        let state_dir = tempfile::tempdir().unwrap();
        let _guard = set_state_dir(state_dir.path());
        let source = tempfile::tempdir().unwrap();
        let source_repo = source.path().join("origin.git");
        std::fs::create_dir(&source_repo).unwrap();
        init_source_repo(&source_repo);

        let workspace = tempfile::tempdir().unwrap();
        let dest = workspace.path().join("origin");
        std::fs::create_dir(&dest).unwrap();
        std::fs::write(dest.join("intruder.txt"), "not from git").unwrap();

        let reference = source_repo.display().to_string();
        let got = acquire_repo(&reference, workspace.path(), "origin", None)
            .await
            .unwrap();
        assert_eq!(got, dest);
        assert!(!dest.join("intruder.txt").exists());
        assert!(dest.join("app.py").is_file());
    }

    #[tokio::test]
    async fn acquire_repo_fails_on_an_unclonable_ref() {
        let workspace = tempfile::tempdir().unwrap();
        let err = acquire_repo(
            "/nonexistent/source/repo.git",
            workspace.path(),
            "repo",
            None,
        )
        .await
        .unwrap_err();
        assert!(err.contains("git clone failed"));
    }

    #[tokio::test]
    async fn acquire_repo_scrubs_a_configured_token_out_of_a_clone_failure_error() {
        let workspace = tempfile::tempdir().unwrap();
        let err = acquire_repo(
            "/nonexistent/source/repo.git",
            workspace.path(),
            "repo",
            Some("s3cr3t-token"),
        )
        .await
        .unwrap_err();
        assert!(!err.contains("s3cr3t-token"), "err: {err}");
    }

    #[tokio::test]
    async fn acquire_repo_derives_a_dest_name_from_the_reference_when_the_hint_is_blank() {
        let source = tempfile::tempdir().unwrap();
        let source_repo = source.path().join("origin.git");
        std::fs::create_dir(&source_repo).unwrap();
        init_source_repo(&source_repo);

        let workspace = tempfile::tempdir().unwrap();
        let dest = acquire_repo(
            &source_repo.display().to_string(),
            workspace.path(),
            "",
            None,
        )
        .await
        .unwrap();
        assert_eq!(dest, workspace.path().join("origin"));
    }

    #[tokio::test]
    async fn acquire_repo_re_clones_a_pre_existing_empty_directory() {
        let _lock = crate::tests::ENV_LOCK.lock().await;
        let state_dir = tempfile::tempdir().unwrap();
        let _guard = set_state_dir(state_dir.path());
        let source = tempfile::tempdir().unwrap();
        let source_repo = source.path().join("origin.git");
        std::fs::create_dir(&source_repo).unwrap();
        init_source_repo(&source_repo);

        let workspace = tempfile::tempdir().unwrap();
        let dest = workspace.path().join("origin");
        std::fs::create_dir(&dest).unwrap();

        let got = acquire_repo(
            &source_repo.display().to_string(),
            workspace.path(),
            "origin",
            None,
        )
        .await
        .unwrap();
        assert_eq!(got, dest);
        assert!(dest.join("app.py").is_file());
    }

    #[tokio::test]
    async fn stage_dir_bound_is_false_for_a_corrupt_marker_file() {
        let _lock = crate::tests::ENV_LOCK.lock().await;
        let state_dir = tempfile::tempdir().unwrap();
        let _guard = set_state_dir(state_dir.path());
        let dest = tempfile::tempdir().unwrap();
        let reference = "https://example.com/o/r.git";
        let marker_path = stage_marker_path(dest.path()).unwrap();
        std::fs::create_dir_all(marker_path.parent().unwrap()).unwrap();
        std::fs::write(&marker_path, "not valid json").unwrap();
        assert!(!stage_dir_bound(dest.path(), reference));
    }

    #[test]
    fn purge_clone_removes_everything_except_the_kept_names() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("app.py"), "x").unwrap();
        std::fs::create_dir(root.path().join("security-scan")).unwrap();
        std::fs::write(root.path().join("security-scan").join("report.md"), "x").unwrap();

        purge_clone(root.path(), CLONE_KEEP_DEFAULT);

        assert!(!root.path().join("app.py").exists());
        assert!(root
            .path()
            .join("security-scan")
            .join("report.md")
            .is_file());
    }

    #[test]
    fn purge_clone_is_a_no_op_on_a_missing_root() {
        purge_clone(Path::new("/nonexistent/purge/target"), CLONE_KEEP_DEFAULT);
    }

    #[test]
    fn purge_clone_warns_about_anything_that_survived() {
        let root = tempfile::tempdir().unwrap();
        let locked = root.path().join("locked");
        std::fs::create_dir(&locked).unwrap();
        std::fs::write(locked.join("app.py"), "x").unwrap();
        let mut perms = std::fs::metadata(&locked).unwrap().permissions();
        perms.set_readonly(true);
        std::fs::set_permissions(&locked, perms).unwrap();
        let stubborn = root.path().join("stubborn");
        std::fs::create_dir(&stubborn).unwrap();
        std::fs::write(stubborn.join("inner"), "x").unwrap();
        let mut perms = std::fs::metadata(&stubborn).unwrap().permissions();
        perms.set_readonly(true);
        std::fs::set_permissions(&stubborn, perms).unwrap();

        purge_clone(root.path(), CLONE_KEEP_DEFAULT);

        for dir in [&locked, &stubborn] {
            if dir.exists() {
                let mut perms = std::fs::metadata(dir).unwrap().permissions();
                #[allow(clippy::permissions_set_readonly_false)]
                perms.set_readonly(false);
                std::fs::set_permissions(dir, perms).unwrap();
            }
        }
    }

    #[tokio::test]
    async fn an_unusable_state_dir_makes_both_marker_helpers_give_up() {
        let _lock = crate::tests::ENV_LOCK.lock().await;
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("not-a-dir");
        std::fs::write(&blocker, "x").unwrap();
        let _guard = set_state_dir(&blocker);
        write_stage_marker(dir.path(), "https://example.com/o/r.git");
        assert!(!stage_dir_bound(dir.path(), "https://example.com/o/r.git"));
    }

    #[tokio::test]
    async fn a_marker_directory_that_cannot_be_created_is_survivable() {
        let _lock = crate::tests::ENV_LOCK.lock().await;
        let state_dir = tempfile::tempdir().unwrap();
        std::fs::write(state_dir.path().join("stage-markers"), "x").unwrap();
        let _guard = set_state_dir(state_dir.path());
        let dest = tempfile::tempdir().unwrap();
        write_stage_marker(dest.path(), "https://example.com/o/r.git");
        assert!(!stage_dir_bound(dest.path(), "https://example.com/o/r.git"));
    }

    #[tokio::test]
    async fn a_marker_path_that_cannot_be_written_warns_and_continues() {
        let _lock = crate::tests::ENV_LOCK.lock().await;
        let state_dir = tempfile::tempdir().unwrap();
        let _guard = set_state_dir(state_dir.path());
        let dest = tempfile::tempdir().unwrap();
        let marker = stage_marker_path(dest.path()).unwrap();
        std::fs::create_dir_all(&marker).unwrap();
        write_stage_marker(dest.path(), "https://example.com/o/r.git");
        assert!(marker.is_dir(), "still a directory — nothing was written");
    }

    #[tokio::test]
    async fn a_corrupt_marker_is_not_bound() {
        let _lock = crate::tests::ENV_LOCK.lock().await;
        let state_dir = tempfile::tempdir().unwrap();
        let _guard = set_state_dir(state_dir.path());
        let dest = tempfile::tempdir().unwrap();
        let marker = stage_marker_path(dest.path()).unwrap();
        std::fs::create_dir_all(marker.parent().unwrap()).unwrap();
        std::fs::write(&marker, "{ not json").unwrap();
        assert!(!stage_dir_bound(dest.path(), "https://example.com/o/r.git"));
    }

    #[tokio::test]
    async fn an_unremovable_destination_is_reused_as_is() {
        let _lock = crate::tests::ENV_LOCK.lock().await;
        let state_dir = tempfile::tempdir().unwrap();
        let _guard = set_state_dir(state_dir.path());
        let workspace = tempfile::tempdir().unwrap();
        let dest = workspace.path().join("repo-a");
        std::fs::write(&dest, "not a directory").unwrap();

        let got = acquire_repo(
            "https://example.com/o/repo-a.git",
            workspace.path(),
            "repo-a",
            None,
        )
        .await
        .unwrap();
        assert_eq!(got, dest);
    }

    #[test]
    fn the_production_call_site_uses_the_real_timeout() {
        assert_eq!(CLONE_TIMEOUT, Duration::from_secs(600));
    }

    #[tokio::test]
    async fn a_clone_that_outlives_its_deadline_is_reported_as_a_timeout() {
        let dest = tempfile::tempdir().unwrap();
        let err = run_bounded_clone(
            "git",
            Duration::ZERO,
            "https://example.invalid/o/r.git",
            &dest.path().join("out"),
            "https://example.invalid/o/r.git",
        )
        .await
        .unwrap_err();
        assert!(err.contains("git clone timed out after 0s"), "{err}");
        assert!(err.contains("network stall"), "{err}");
    }

    #[tokio::test]
    async fn a_git_binary_that_cannot_be_run_is_reported_as_such() {
        let dest = tempfile::tempdir().unwrap();
        let err = run_bounded_clone(
            "definitely-not-a-real-git-binary",
            CLONE_TIMEOUT,
            "https://example.invalid/o/r.git",
            &dest.path().join("out"),
            "https://example.invalid/o/r.git",
        )
        .await
        .unwrap_err();
        assert!(err.contains("failed to run git"), "{err}");
    }

    fn failed_output(stderr: &str, stdout: &str) -> std::process::Output {
        std::process::Output {
            status: std::process::Command::new("false")
                .status()
                .expect("`false` exists on every supported platform"),
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    #[test]
    fn a_clone_failure_message_prefers_stderr() {
        let out = failed_output("fatal: repository not found", "noise on stdout");
        assert_eq!(
            clone_failure_message(&out, None),
            "git clone failed: fatal: repository not found"
        );
    }

    #[test]
    fn a_clone_failure_message_falls_back_to_stdout_when_stderr_is_empty() {
        let out = failed_output("   \n ", "fatal: could not read Username");
        assert_eq!(
            clone_failure_message(&out, None),
            "git clone failed: fatal: could not read Username"
        );
    }

    #[test]
    fn a_clone_failure_message_redacts_the_git_token_and_url_secrets() {
        let out = failed_output(
            "fatal: auth failed for https://x-access-token:s3cret@example.com/o/r.git \
             (token s3cret)",
            "",
        );
        let msg = clone_failure_message(&out, Some("s3cret"));
        assert!(!msg.contains("s3cret"), "{msg}");
        assert!(msg.contains("***"), "{msg}");
    }

    #[test]
    fn an_empty_git_token_is_not_treated_as_a_secret_to_redact() {
        let out = failed_output("fatal: nope", "");
        assert_eq!(
            clone_failure_message(&out, Some("")),
            "git clone failed: fatal: nope"
        );
    }

    #[tokio::test]
    async fn the_state_dir_guard_restores_a_previous_value() {
        let _lock = crate::tests::ENV_LOCK.lock().await;
        let prior = std::env::var("BC_STATE_DIR").ok();
        let outer = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("BC_STATE_DIR", outer.path()) };
        {
            let inner = tempfile::tempdir().unwrap();
            let _guard = set_state_dir(inner.path());
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
}
