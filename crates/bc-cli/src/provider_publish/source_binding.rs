//! Bind automatic publication to a committed local source tree without invoking filters.
use bc_model::FinalReport;
use sha1::{Digest, Sha1};
use std::collections::BTreeSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

pub(super) struct SourceBinding {
    root: PathBuf,
    revision: String,
    artifacts: BTreeSet<PathBuf>,
    digest: Vec<u8>,
}

fn git(root: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    let output = Command::new("git")
        .args([
            "--no-pager",
            "--no-optional-locks",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.untrackedCache=false",
            "-c",
            "diff.external=",
            "-c",
            "core.pager=cat",
            "-c",
            "protocol.allow=never",
            "-c",
            "credential.helper=",
            "-C",
        ])
        .arg(root)
        .args(args)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_EXTERNAL_DIFF")
        .env_remove("GIT_CONFIG_COUNT")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_NO_LAZY_FETCH", "1")
        .output()
        .map_err(|_| "Automatic publication cannot inspect local Git source".to_string())?;
    if !output.status.success() {
        return Err(
            "Automatic publication requires an accessible committed Git source tree".into(),
        );
    }
    Ok(output.stdout)
}

fn text(bytes: Vec<u8>) -> Result<String, String> {
    String::from_utf8(bytes)
        .map(|s| s.trim_end_matches(['\r', '\n']).to_string())
        .map_err(|_| "Automatic publication requires UTF-8 Git paths and identities".into())
}

fn absolute(path: &Path) -> Result<PathBuf, String> {
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(super::error_message)?
            .join(path)
    };
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            std::path::Component::CurDir => {}
            _ => normalized.push(component),
        }
    }
    let mut existing = normalized.as_path();
    let mut missing = Vec::new();
    while !existing.exists() {
        missing.push(
            existing
                .file_name()
                .ok_or("Output path has no existing ancestor")?
                .to_os_string(),
        );
        existing = existing
            .parent()
            .ok_or("Output path has no existing ancestor")?;
    }
    let mut resolved = existing.canonicalize().map_err(super::error_message)?;
    for component in missing.into_iter().rev() {
        resolved.push(component);
    }
    Ok(resolved)
}

pub(super) fn capture(cli: &crate::Cli) -> Result<SourceBinding, String> {
    let root = crate::repo_path(cli)
        .canonicalize()
        .map_err(super::error_message)?;
    let git_root = PathBuf::from(text(git(&root, &["rev-parse", "--show-toplevel"])?)?);
    if git_root.canonicalize().map_err(super::error_message)? != root {
        return Err("Automatic publication requires the complete Git repository root".into());
    }
    let revision = text(git(&root, &["rev-parse", "--verify", "HEAD"])?)?;
    if !cli.git_sha.is_empty() && cli.git_sha != revision {
        return Err("--git-sha does not match the actual scanned Git HEAD".into());
    }
    let paths = crate::resolve_output_paths(cli);
    let mut artifacts = BTreeSet::new();
    for path in [paths.markdown, paths.sarif, paths.csv, paths.findings_json]
        .into_iter()
        .chain(paths.provider_writeback_plan.clone())
        .chain(
            paths
                .provider_writeback_plan
                .map(|p| p.with_file_name("provider-writeback-results.json")),
        )
    {
        artifacts.insert(absolute(&path)?);
    }
    if let Ok(db) = bc_checkpoint::default_db_path() {
        if let Some(parent) = db.parent() {
            artifacts.insert(absolute(
                &parent
                    .join("checkpoints")
                    .join(bc_checkpoint::run_id_for(&root))
                    .join("step1.yaml"),
            )?);
        }
    }
    let mut binding = SourceBinding {
        root,
        revision,
        artifacts,
        digest: Vec::new(),
    };
    binding.digest = binding.inspect()?;
    Ok(binding)
}

impl SourceBinding {
    fn allowed_untracked(&self, relative: &str) -> bool {
        self.artifacts.contains(&self.root.join(relative))
            || Path::new(relative).parent().is_some_and(|parent| {
                parent.components().any(|part| {
                    bc_repo_analysis::DEFAULT_EXCLUDE_DIRS.contains(
                        &part
                            .as_os_str()
                            .to_string_lossy()
                            .to_ascii_lowercase()
                            .as_str(),
                    )
                })
            })
    }
    fn inspect(&self) -> Result<Vec<u8>, String> {
        if text(git(&self.root, &["rev-parse", "--verify", "HEAD"])?)? != self.revision {
            return Err("Scanned Git HEAD changed; automatic publication refused".into());
        }
        // Inspect the index without asking Git to refresh worktree content,
        // which could invoke a repository-configured clean filter.
        if !git(
            &self.root,
            &[
                "diff-index",
                "--cached",
                "--name-only",
                "--no-ext-diff",
                "HEAD",
                "--",
            ],
        )?
        .is_empty()
        {
            return Err("Tracked index differs from HEAD; automatic publication refused".into());
        }
        // S1's repository walk does not universally honor Git ignore rules.
        // Ignored source is therefore not silently considered revision-bound.
        for entry in git(&self.root, &["ls-files", "--others", "-z"])?
            .split(|b| *b == 0)
            .filter(|s| !s.is_empty())
        {
            let relative =
                std::str::from_utf8(entry).map_err(|_| "Non-UTF-8 untracked source path")?;
            if !self.allowed_untracked(relative) {
                return Err(
                    "Uncommitted or ignored files are not bound to the scanned revision".into(),
                );
            }
        }
        self.source_digest(&self.root)
    }

    fn source_digest(&self, source: &Path) -> Result<Vec<u8>, String> {
        let tree = git(&self.root, &["ls-tree", "-r", "-z", "HEAD"])?;
        let mut digest = Sha1::new();
        for entry in tree.split(|b| *b == 0).filter(|s| !s.is_empty()) {
            let entry = std::str::from_utf8(entry).map_err(|_| "Non-UTF-8 tracked source path")?;
            let (header, relative) = entry.split_once('\t').ok_or("Malformed Git tree entry")?;
            let fields: Vec<_> = header.split_whitespace().collect();
            if fields.len() != 3 || !matches!(fields[0], "100644" | "100755") || fields[1] != "blob"
            {
                return Err(
                    "Automatic source binding does not support symlinks or submodules".into(),
                );
            }
            let path = source.join(relative);
            if !std::fs::symlink_metadata(&path)
                .map_err(super::error_message)?
                .is_file()
                || path.canonicalize().map_err(super::error_message)? != path
            {
                return Err("Tracked source is not an ordinary contained file".into());
            }
            let mut file = std::fs::File::open(path).map_err(super::error_message)?;
            let length = file.metadata().map_err(super::error_message)?.len();
            let mut blob = Sha1::new();
            blob.update(format!("blob {length}\0").as_bytes());
            digest.update(entry.as_bytes());
            digest.update([0]);
            let mut buffer = [0u8; 65536];
            loop {
                let count = file.read(&mut buffer).map_err(super::error_message)?;
                if count == 0 {
                    break;
                }
                blob.update(&buffer[..count]);
                digest.update(&buffer[..count]);
            }
            let blob_id: String = blob.finalize().iter().map(|b| format!("{b:02x}")).collect();
            if blob_id != fields[2] {
                return Err("Source bytes differ from committed blobs (including filtered or line-ending-converted files); automatic publication refused".into());
            }
        }
        Ok(digest.finalize().to_vec())
    }

    pub(super) fn verify(&self, report: &FinalReport) -> Result<(), String> {
        if report.git_sha.as_deref() != Some(self.revision.as_str()) {
            return Err("Reported revision does not match captured source revision".into());
        }
        if self.inspect()? != self.digest {
            return Err("Scanned source changed before automatic publication".into());
        }
        let scanned = Path::new(&report.repo_root)
            .canonicalize()
            .map_err(super::error_message)?;
        if scanned != self.root && self.source_digest(&scanned)? != self.digest {
            return Err("Scanned delivery snapshot differs from the captured source".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn command(root: &Path, args: &[&str]) {
        let status = Command::new("git")
            .arg("-C")
            .arg(root)
            .args([
                "-c",
                "user.name=BC Test",
                "-c",
                "user.email=bc-test@example.invalid",
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(args)
            .output()
            .unwrap();
        assert!(status.status.success(), "fixture Git command failed");
    }
    fn fixture() -> (tempfile::TempDir, crate::Cli) {
        let dir = tempfile::tempdir().unwrap();
        command(dir.path(), &["init"]);
        std::fs::write(dir.path().join("app.rs"), "fn main() {}\n").unwrap();
        command(dir.path(), &["add", "app.rs"]);
        command(dir.path(), &["commit", "-m", "fixture"]);
        let cli = crate::args::test_support::minimal_cli(dir.path());
        (dir, cli)
    }
    fn report(binding: &SourceBinding) -> FinalReport {
        serde_json::from_value(serde_json::json!({"repo_root":binding.root,"git_sha":binding.revision,"findings":[],"chains":[],"summary":""})).unwrap()
    }
    #[test]
    fn clean_source_and_exact_output_artifacts_are_accepted() {
        let (dir, mut cli) = fixture();
        cli.provider_writeback = "apply".into();
        let binding = capture(&cli).unwrap();
        let paths = crate::resolve_output_paths(&cli);
        std::fs::create_dir_all(paths.markdown.parent().unwrap()).unwrap();
        std::fs::write(&paths.markdown, "report").unwrap();
        std::fs::write(paths.provider_writeback_plan.unwrap(), "{}").unwrap();
        binding.verify(&report(&binding)).unwrap();
        std::fs::create_dir(dir.path().join("node_modules")).unwrap();
        std::fs::write(dir.path().join("node_modules/dependency.js"), "code").unwrap();
        binding.verify(&report(&binding)).unwrap();
        std::fs::write(dir.path().join("unreviewed.rs"), "code").unwrap();
        assert!(binding.verify(&report(&binding)).is_err());
    }
    #[test]
    fn dirty_fix_staged_changes_untracked_and_override_are_rejected() {
        let (dir, mut cli) = fixture();
        cli.git_sha = "wrong".into();
        assert!(capture(&cli).err().unwrap().contains("--git-sha"));
        cli.git_sha.clear();
        std::fs::write(dir.path().join("app.rs"), "fixed\n").unwrap();
        assert!(capture(&cli).is_err());
        command(dir.path(), &["add", "app.rs"]);
        assert!(capture(&cli).is_err());
        command(dir.path(), &["commit", "-m", "fixed fixture"]);
        std::fs::write(dir.path().join("new.rs"), "new").unwrap();
        assert!(capture(&cli).is_err());
    }
    #[test]
    fn midrun_content_revision_and_report_revision_changes_are_rejected() {
        let (dir, cli) = fixture();
        let binding = capture(&cli).unwrap();
        let mut result = report(&binding);
        result.git_sha = None;
        assert!(binding.verify(&result).is_err());
        std::fs::write(dir.path().join("app.rs"), "changed\n").unwrap();
        assert!(binding.verify(&report(&binding)).is_err());
        command(dir.path(), &["add", "app.rs"]);
        command(dir.path(), &["commit", "-m", "changed fixture"]);
        assert!(binding
            .verify(&report(&binding))
            .err()
            .unwrap()
            .contains("HEAD changed"));
    }
    #[test]
    fn ignored_source_and_assume_unchanged_edits_are_rejected() {
        let (dir, cli) = fixture();
        std::fs::write(dir.path().join(".gitignore"), "ignored.rs\n").unwrap();
        command(dir.path(), &["add", ".gitignore"]);
        command(dir.path(), &["commit", "-m", "ignore fixture"]);
        std::fs::write(dir.path().join("ignored.rs"), "source").unwrap();
        assert!(capture(&cli).err().unwrap().contains("ignored"));
        std::fs::remove_file(dir.path().join("ignored.rs")).unwrap();
        command(
            dir.path(),
            &["update-index", "--assume-unchanged", "app.rs"],
        );
        std::fs::write(dir.path().join("app.rs"), "hidden change\n").unwrap();
        assert!(capture(&cli).is_err());
    }
    #[test]
    fn snapshot_bytes_are_checked_without_requiring_git_in_snapshot() {
        let (_dir, cli) = fixture();
        let binding = capture(&cli).unwrap();
        let snapshot = tempfile::tempdir().unwrap();
        std::fs::copy(binding.root.join("app.rs"), snapshot.path().join("app.rs")).unwrap();
        let mut result = report(&binding);
        result.repo_root = snapshot.path().to_string_lossy().into_owned();
        binding.verify(&result).unwrap();
        std::fs::write(snapshot.path().join("app.rs"), "wrong snapshot").unwrap();
        assert!(binding.verify(&result).is_err());
    }
    #[test]
    fn nongit_nested_and_tracked_output_changes_are_rejected() {
        let empty = tempfile::tempdir().unwrap();
        assert!(capture(&crate::args::test_support::minimal_cli(empty.path())).is_err());
        let (dir, mut cli) = fixture();
        std::fs::create_dir(dir.path().join("nested")).unwrap();
        let nested = crate::args::test_support::minimal_cli(&dir.path().join("nested"));
        assert!(capture(&nested).is_err());
        cli.out_md = Some(dir.path().join("app.rs"));
        let binding = capture(&cli).unwrap();
        std::fs::write(dir.path().join("app.rs"), "output overwrote source").unwrap();
        assert!(binding.verify(&report(&binding)).is_err());
    }
    #[test]
    fn paths_encoding_custom_outputs_and_line_endings_are_checked() {
        assert!(text(vec![255]).is_err());
        assert_eq!(text(b"identity\r\n".to_vec()).unwrap(), "identity");
        let cwd = std::env::current_dir().unwrap();
        assert_eq!(
            absolute(Path::new("./one/../two")).unwrap(),
            cwd.join("two")
        );
        let (dir, mut cli) = fixture();
        let custom = dir.path().join("custom");
        std::fs::create_dir(&custom).unwrap();
        cli.out_md = Some(custom.join("report.md"));
        let binding = capture(&cli).unwrap();
        std::fs::write(custom.join("report.md"), "report").unwrap();
        binding.verify(&report(&binding)).unwrap();
        std::fs::write(custom.join("source.rs"), "source").unwrap();
        assert!(binding.verify(&report(&binding)).is_err());
        std::fs::remove_file(custom.join("source.rs")).unwrap();
        command(
            dir.path(),
            &["update-index", "--assume-unchanged", "app.rs"],
        );
        std::fs::write(dir.path().join("app.rs"), "fn main() {}\r\n").unwrap();
        assert!(binding
            .verify(&report(&binding))
            .err()
            .unwrap()
            .contains("Source bytes"));
    }
    #[cfg(unix)]
    #[test]
    fn tracked_symlinks_are_refused() {
        let (dir, cli) = fixture();
        std::os::unix::fs::symlink("app.rs", dir.path().join("link.rs")).unwrap();
        command(dir.path(), &["add", "link.rs"]);
        command(dir.path(), &["commit", "-m", "link fixture"]);
        assert!(capture(&cli).err().unwrap().contains("symlinks"));
    }
}
