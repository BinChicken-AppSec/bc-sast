//! Explicit delivery of full-scan remediation. Selection is authorization;
//! all scan, patch-review and target-test gates still run before delivery.
use crate::args::Cli;
use serde::Serialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum DeliveryMode {
    #[default]
    Patch,
    Branch,
    Zip,
}

pub struct DeliveryState {
    pub mode: DeliveryMode,
    pub remote: Option<String>,
    pub branch: Option<String>,
    pub snapshot: Option<crate::delivery_archive::Snapshot>,
    pub output: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DeliveryReceipt {
    pub status: String,
    pub mode: String,
    pub destination: String,
    pub detail: String,
    pub excluded_paths: Vec<String>,
}

pub fn check_mode(cli: &Cli) -> Result<(), String> {
    if cli.remediation_delivery == DeliveryMode::Patch {
        if cli.delivery_remote.is_some() || cli.delivery_branch.is_some() {
            return Err(
                "--delivery-remote and --delivery-branch require --remediation-delivery branch"
                    .into(),
            );
        }
        return Ok(());
    }
    if !cli.remediate
        || cli.diff_scope
        || !cli.stop_after.is_empty()
        || cli.remediate_from.is_some()
        || cli.interactive
        || cli.remediate_in_place
        || cli.resume
        || cli.remediate_dry_run
        || cli.estimate
        || cli.doctor
        || cli.setup
        || cli.gc
        || cli.gc_run.is_some()
        || cli.post_fixes_from.is_some()
        || cli.post_comments_from.is_some()
    {
        return Err(
            "Branch/ZIP delivery requires a full scan with non-interactive isolated remediation"
                .into(),
        );
    }
    match cli.remediation_delivery {
        DeliveryMode::Branch => crate::delivery_branch::validate_selection(
            cli.delivery_remote
                .as_deref()
                .ok_or("Branch delivery requires --delivery-remote")?,
            cli.delivery_branch
                .as_deref()
                .ok_or("Branch delivery requires --delivery-branch")?,
        ),
        DeliveryMode::Zip if cli.delivery_remote.is_some() || cli.delivery_branch.is_some() => {
            Err("ZIP delivery does not accept Git destination flags".into())
        }
        _ => Ok(()),
    }
}

pub fn prepare(cli: &Cli, repo: &Path) -> Result<Option<DeliveryState>, String> {
    check_mode(cli)?;
    if cli.remediation_delivery == DeliveryMode::Patch {
        return Ok(None);
    }
    let snapshot = if cli.remediation_delivery == DeliveryMode::Zip {
        Some(crate::delivery_archive::create_snapshot(repo)?)
    } else {
        None
    };
    let output = bc_pathjail::confine(repo, "security-scan/remediated-source.zip")
        .ok_or("Delivery output escapes target repository")?;
    if cli.remediation_delivery == DeliveryMode::Zip && output.exists() {
        return Err("ZIP output already exists; use a fresh CI checkout or retain the prior artifact elsewhere".into());
    }
    Ok(Some(DeliveryState {
        mode: cli.remediation_delivery,
        remote: cli.delivery_remote.clone(),
        branch: cli.delivery_branch.clone(),
        snapshot,
        output,
    }))
}

pub async fn deliver(state: &DeliveryState, root: &Path) -> Result<DeliveryReceipt, String> {
    match state.mode {
        DeliveryMode::Branch => {
            let receipt = crate::delivery_branch::publish(
                root,
                state.remote.as_deref().ok_or("Missing remote")?,
                state.branch.as_deref().ok_or("Missing branch")?,
            )
            .await?;
            Ok(DeliveryReceipt {
                status: if receipt.published {
                    "pushed"
                } else {
                    "no_changes"
                }
                .into(),
                mode: "branch".into(),
                destination: state.branch.clone().unwrap_or_default(),
                detail: serde_json::to_string(&receipt).map_err(crate::stringify)?,
                excluded_paths: Vec::new(),
            })
        }
        DeliveryMode::Zip => {
            if let Some(parent) = state.output.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(crate::context("Cannot create ZIP output directory"))?;
            }
            crate::delivery_archive::export_zip(root, &state.output)?;
            Ok(DeliveryReceipt { status: "created".into(), mode: "zip".into(), destination: state.output.display().to_string(),
                detail: "Updated source snapshot; upload with your CI artifact mechanism. Generation and model review are not test-execution evidence.".into(),
                excluded_paths: state.snapshot.as_ref().map(|s| s.excluded_paths.clone()).unwrap_or_default() })
        }
        DeliveryMode::Patch => Err("Patch delivery uses the existing worktree exporter".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn runtime_flags_choose_each_delivery_mode() {
        use clap::Parser;
        let base = [
            "bc-sast",
            "--repo",
            "/repo",
            "--gateway-base-url",
            "http://127.0.0.1:1",
            "--remediate",
        ];
        let cli = Cli::try_parse_from(base.into_iter().chain([
            "--remediation-delivery",
            "branch",
            "--delivery-remote",
            "origin",
            "--delivery-branch",
            "bc-sast/run-123",
        ]))
        .unwrap();
        assert_eq!(cli.remediation_delivery, DeliveryMode::Branch);
        assert!(check_mode(&cli).is_ok());
        let cli =
            Cli::try_parse_from(base.into_iter().chain(["--remediation-delivery", "zip"])).unwrap();
        assert_eq!(cli.remediation_delivery, DeliveryMode::Zip);
        assert!(check_mode(&cli).is_ok());
        assert_eq!(
            Cli::try_parse_from(base).unwrap().remediation_delivery,
            DeliveryMode::Patch
        );
    }

    #[test]
    fn delivery_selection_requires_explicit_full_scan_and_destination() {
        let mut cli = crate::args::test_support::minimal_cli(Path::new("/repo"));
        cli.remediation_delivery = DeliveryMode::Branch;
        assert!(check_mode(&cli).is_err());
        cli.remediate = true;
        assert!(check_mode(&cli).is_err());
        cli.delivery_remote = Some("origin".into());
        cli.delivery_branch = Some("bc-sast/fix".into());
        assert!(check_mode(&cli).is_ok());
        cli.diff_scope = true;
        assert!(check_mode(&cli).is_err());
        cli.diff_scope = false;
        cli.remediation_delivery = DeliveryMode::Zip;
        assert!(check_mode(&cli).is_err());
        cli.delivery_remote = None;
        cli.delivery_branch = None;
        assert!(check_mode(&cli).is_ok());
        cli.stop_after = "s9".into();
        assert!(check_mode(&cli).is_err());
    }

    fn git(root: &Path, args: &[&str]) {
        let out = std::process::Command::new("git")
            .current_dir(root)
            .args(args)
            .output()
            .unwrap();
        assert!(out.status.success(), "synthetic Git setup failed: {out:?}");
    }

    fn detached_repo_with_remote() -> (tempfile::TempDir, tempfile::TempDir) {
        let repo = tempfile::tempdir().unwrap();
        let remote = tempfile::tempdir().unwrap();
        git(remote.path(), &["init", "--bare", "-q"]);
        git(repo.path(), &["init", "-q"]);
        git(
            repo.path(),
            &["config", "user.email", "test@example.invalid"],
        );
        git(repo.path(), &["config", "user.name", "BC SAST test"]);
        std::fs::write(repo.path().join("app.txt"), "before\n").unwrap();
        git(repo.path(), &["add", "-A"]);
        git(repo.path(), &["commit", "-qm", "baseline"]);
        git(repo.path(), &["checkout", "--detach", "-q"]);
        git(
            repo.path(),
            &["remote", "add", "origin", remote.path().to_str().unwrap()],
        );
        (repo, remote)
    }

    fn state(mode: DeliveryMode, output: PathBuf) -> DeliveryState {
        DeliveryState {
            mode,
            remote: Some("origin".into()),
            branch: Some("bc-sast/fix".into()),
            snapshot: None,
            output,
        }
    }

    #[test]
    fn patch_delivery_refuses_a_git_destination_it_would_never_use() {
        let mut cli = crate::args::test_support::minimal_cli(Path::new("/repo"));
        cli.delivery_remote = Some("origin".into());
        assert_eq!(
            check_mode(&cli).unwrap_err(),
            "--delivery-remote and --delivery-branch require --remediation-delivery branch"
        );
        cli.delivery_remote = None;
        cli.delivery_branch = Some("bc-sast/fix".into());
        assert!(check_mode(&cli).is_err());
        cli.delivery_branch = None;
        assert!(check_mode(&cli).is_ok());
        assert!(prepare(&cli, Path::new("/repo")).unwrap().is_none());
    }

    #[test]
    fn branch_delivery_prepares_a_destination_without_copying_the_source() {
        let repo = tempfile::tempdir().unwrap();
        let mut cli = crate::args::test_support::minimal_cli(repo.path());
        cli.remediate = true;
        cli.remediation_delivery = DeliveryMode::Branch;
        cli.delivery_remote = Some("origin".into());
        cli.delivery_branch = Some("bc-sast/fix".into());
        let prepared = prepare(&cli, repo.path()).unwrap().unwrap();
        assert_eq!(prepared.mode, DeliveryMode::Branch);
        assert!(prepared.snapshot.is_none());
        assert_eq!(prepared.remote.as_deref(), Some("origin"));
        assert_eq!(prepared.branch.as_deref(), Some("bc-sast/fix"));
        assert!(prepared
            .output
            .ends_with("security-scan/remediated-source.zip"));
    }

    #[test]
    fn zip_delivery_never_overwrites_an_artifact_from_an_earlier_run() {
        let repo = tempfile::tempdir().unwrap();
        std::fs::create_dir(repo.path().join("security-scan")).unwrap();
        std::fs::write(
            repo.path().join("security-scan/remediated-source.zip"),
            b"earlier run",
        )
        .unwrap();
        let mut cli = crate::args::test_support::minimal_cli(repo.path());
        cli.remediate = true;
        cli.remediation_delivery = DeliveryMode::Zip;
        assert!(prepare(&cli, repo.path())
            .err()
            .unwrap()
            .contains("ZIP output already exists"));
        assert_eq!(
            std::fs::read(repo.path().join("security-scan/remediated-source.zip")).unwrap(),
            b"earlier run"
        );
    }

    #[tokio::test]
    async fn patch_delivery_is_never_published_through_this_path() {
        let out = tempfile::tempdir().unwrap();
        assert_eq!(
            deliver(
                &state(DeliveryMode::Patch, out.path().join("source.zip")),
                out.path()
            )
            .await
            .unwrap_err(),
            "Patch delivery uses the existing worktree exporter"
        );
    }

    #[tokio::test]
    async fn branch_delivery_records_the_pushed_commit_and_its_scope() {
        let (repo, remote) = detached_repo_with_remote();
        std::fs::create_dir(repo.path().join("tests")).unwrap();
        std::fs::write(repo.path().join("tests/regression.txt"), "coverage\n").unwrap();
        let out = repo.path().join("security-scan/remediated-source.zip");
        let receipt = deliver(&state(DeliveryMode::Branch, out.clone()), repo.path())
            .await
            .unwrap();
        assert_eq!(receipt.status, "pushed");
        assert_eq!(receipt.mode, "branch");
        assert_eq!(receipt.destination, "bc-sast/fix");
        assert!(receipt.excluded_paths.is_empty());
        let detail: serde_json::Value = serde_json::from_str(&receipt.detail).unwrap();
        assert_eq!(detail["branch"], "bc-sast/fix");
        assert_eq!(detail["published"], true);
        let published = std::process::Command::new("git")
            .current_dir(remote.path())
            .args(["show", "bc-sast/fix:tests/regression.txt"])
            .output()
            .unwrap();
        assert_eq!(published.stdout, b"coverage\n");

        // A second run against an unchanged snapshot records no publication.
        let quiet = deliver(
            &DeliveryState {
                branch: Some("bc-sast/quiet".into()),
                ..state(DeliveryMode::Branch, out)
            },
            repo.path(),
        )
        .await
        .unwrap();
        assert_eq!(quiet.status, "no_changes");
    }

    #[tokio::test]
    async fn branch_delivery_without_a_destination_is_refused_rather_than_guessed() {
        let (repo, _remote) = detached_repo_with_remote();
        let out = repo.path().join("security-scan/remediated-source.zip");
        let no_remote = DeliveryState {
            remote: None,
            ..state(DeliveryMode::Branch, out.clone())
        };
        assert_eq!(
            deliver(&no_remote, repo.path()).await.unwrap_err(),
            "Missing remote"
        );
        let no_branch = DeliveryState {
            branch: None,
            ..state(DeliveryMode::Branch, out)
        };
        assert_eq!(
            deliver(&no_branch, repo.path()).await.unwrap_err(),
            "Missing branch"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_zip_output_directory_that_cannot_be_created_fails_the_delivery() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let locked = root.path().join("locked");
        std::fs::create_dir(&locked).unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o555)).unwrap();
        let outcome = deliver(
            &state(DeliveryMode::Zip, locked.join("security-scan/source.zip")),
            root.path(),
        )
        .await;
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(outcome
            .unwrap_err()
            .contains("Cannot create ZIP output directory"));
    }
}
