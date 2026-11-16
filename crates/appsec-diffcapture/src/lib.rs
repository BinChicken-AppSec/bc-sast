use std::collections::BTreeMap;
use std::path::{Component, Path};

mod synth;
mod worktree;

pub use synth::{synth_unified_diff, SYNTH_HEADER};
pub use worktree::{create_detached_worktree, export_patch, remove_worktree};

pub fn norm_path(raw: &str) -> String {
    let trimmed = raw.trim();
    let Some(colon) = trimmed.rfind(':') else {
        return trimmed.to_string();
    };
    let suffix = &trimmed[colon + 1..];
    let all_digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    let is_line_suffix = match suffix.split_once('-') {
        Some((start, end)) => all_digits(start) && all_digits(end),
        None => all_digits(suffix),
    };
    if is_line_suffix {
        trimmed[..colon].to_string()
    } else {
        trimmed.to_string()
    }
}

pub fn canonical_repo_path(root: &Path, raw: &str) -> Option<String> {
    let normalized = norm_path(raw);
    let resolved = appsec_pathjail::confine(root, &normalized)?;
    let root_resolved = appsec_pathjail::confine(root, ".")?;
    let relative = resolved.strip_prefix(root_resolved).ok()?;
    let components: Vec<String> = relative
        .components()
        .map(|component| match component {
            Component::Normal(name) => Some(name.to_string_lossy().into_owned()),
            Component::CurDir
            | Component::ParentDir
            | Component::RootDir
            | Component::Prefix(_) => None,
        })
        .collect::<Option<_>>()?;
    (!components.is_empty()).then(|| components.join("/"))
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Snapshot {
    contents: BTreeMap<String, Option<Vec<u8>>>,
}

impl Snapshot {
    pub fn get(&self, file: &str) -> Option<&Option<Vec<u8>>> {
        self.contents.get(file)
    }

    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.contents.keys()
    }

    pub fn subset(&self, files: &[String]) -> Snapshot {
        let mut contents = BTreeMap::new();
        for file in files {
            let rel = norm_path(file);
            if let Some(content) = self.contents.get(&rel) {
                contents.insert(rel, content.clone());
            }
        }
        Snapshot { contents }
    }

    pub fn is_empty(&self) -> bool {
        self.contents.is_empty()
    }

    pub fn merge_originals(
        &mut self,
        originals: impl IntoIterator<Item = (String, Option<Vec<u8>>)>,
    ) {
        for (file, content) in originals {
            self.contents.entry(norm_path(&file)).or_insert(content);
        }
    }
}

pub fn snapshot_files(root: &Path, files: &[String]) -> Snapshot {
    let mut contents = BTreeMap::new();
    for file in files {
        let Some(rel) = canonical_repo_path(root, file) else {
            continue;
        };
        let Some(resolved) = appsec_pathjail::confine(root, &rel) else {
            continue;
        };
        if !resolved.exists() {
            contents.insert(rel, None);
            continue;
        }
        if let Ok(bytes) = std::fs::read(&resolved) {
            contents.insert(rel, Some(bytes));
        }
    }
    Snapshot { contents }
}

pub fn revert(root: &Path, files: &[String], snapshot: &Snapshot) -> Result<Vec<String>, String> {
    let is_git = is_git_worktree(root);
    let mut reverted = Vec::new();
    for file in files {
        let Some(rel) = canonical_repo_path(root, file) else {
            return Err(format!(
                "cannot revert '{file}': outside the repository root"
            ));
        };
        let Some(resolved) = appsec_pathjail::confine(root, &rel) else {
            return Err(format!("cannot revert '{file}': repository path changed"));
        };
        match snapshot.contents.get(&rel) {
            Some(Some(content)) => {
                std::fs::write(&resolved, content)
                    .map_err(|e| format!("cannot revert {file}: {e}"))?;
                reverted.push(rel);
            }
            Some(None) => {
                if resolved.exists() {
                    std::fs::remove_file(&resolved)
                        .map_err(|e| format!("cannot remove {file}: {e}"))?;
                }
                reverted.push(rel);
            }
            None if is_git => {
                if is_tracked(root, &rel) {
                    let checkout = std::process::Command::new("git")
                        .arg("-C")
                        .arg(root)
                        .args(["checkout", "--"])
                        .arg(&rel)
                        .output()
                        .map_err(|e| format!("cannot run git checkout for {rel}: {e}"))?;
                    if !checkout.status.success() {
                        return Err(format!(
                            "git checkout failed for {rel}: {}",
                            String::from_utf8_lossy(&checkout.stderr).trim()
                        ));
                    }
                } else if resolved.exists() {
                    std::fs::remove_file(&resolved)
                        .map_err(|e| format!("cannot remove {file}: {e}"))?;
                }
                reverted.push(rel);
            }
            None => {}
        }
    }
    Ok(reverted)
}

pub fn revert_all(root: &Path, files: &[String], snapshot: &Snapshot) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    let mut restored = Vec::new();
    for file in files {
        let Some(rel) = canonical_repo_path(root, file) else {
            continue;
        };
        if !seen.insert(rel.clone()) {
            continue;
        }
        if let Ok(done) = revert(root, std::slice::from_ref(&rel), snapshot) {
            restored.extend(done);
        }
    }
    restored
}

pub fn is_git_worktree(root: &Path) -> bool {
    std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["rev-parse", "--is-inside-work-tree"])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .is_some_and(|out| String::from_utf8_lossy(&out.stdout).trim() == "true")
}

fn is_tracked(root: &Path, rel: &str) -> bool {
    std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["ls-files", "--error-unmatch", "--"])
        .arg(rel)
        .output()
        .ok()
        .is_some_and(|out| out.status.success())
}

pub fn capture_git_diff(root: &Path, files: &[String]) -> Option<String> {
    let safe = confine_all(root, files);
    if safe.is_empty() {
        return Some(String::new());
    }
    let present: Vec<&String> = safe
        .iter()
        .filter(|path| std::fs::symlink_metadata(root.join(path)).is_ok())
        .collect();
    let add = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .arg("add")
        .arg("-N")
        .arg("--")
        .args(&present)
        .output()
        .ok()?;
    if !add.status.success() {
        return None;
    }
    let diff = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .arg("diff")
        .arg("--")
        .args(&safe)
        .output()
        .ok()?;
    if !diff.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&diff.stdout).into_owned())
}

fn confine_all(root: &Path, files: &[String]) -> Vec<String> {
    files
        .iter()
        .filter_map(|f| canonical_repo_path(root, f))
        .collect()
}

pub fn changed_files_whole_tree(root: &Path) -> Vec<String> {
    std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["status", "--porcelain", "-z", "--untracked-files=all"])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| parse_porcelain_z(&String::from_utf8_lossy(&out.stdout)))
        .unwrap_or_default()
}

fn parse_porcelain_z(stdout: &str) -> Vec<String> {
    let records: Vec<&str> = stdout.split('\0').collect();
    let mut out = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut add = |p: &str| {
        if !p.is_empty() && seen.insert(p.to_string()) {
            out.push(p.to_string());
        }
    };
    let mut i = 0;
    while i < records.len() {
        let rec = records[i];
        i += 1;
        if rec.is_empty() {
            continue;
        }
        add(if rec.len() > 3 { &rec[3..] } else { "" });
        let status_chars = &rec[..rec.len().min(2)];
        if (status_chars.contains('R') || status_chars.contains('C')) && i < records.len() {
            add(records[i]);
            i += 1;
        }
    }
    out
}

pub fn renames_between(root: &Path, from_rev: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    if from_rev.trim().is_empty() {
        return out;
    }
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["diff", "--name-status", "-M", "-z", from_rev, "HEAD"])
        .output();
    let Ok(output) = output else { return out };
    if !output.status.success() {
        return out;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut fields = text.split('\0').filter(|f| !f.is_empty());
    while let Some(status) = fields.next() {
        let renamed = status.starts_with('R');
        let Some(first) = fields.next() else { break };
        if !renamed {
            continue;
        }
        let Some(second) = fields.next() else { break };
        out.insert(norm_path(first), norm_path(second));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn norm_path_leaves_a_plain_path_unchanged() {
        assert_eq!(norm_path("app.py"), "app.py");
    }

    #[test]
    fn norm_path_trims_whitespace() {
        assert_eq!(norm_path("  app.py  "), "app.py");
    }

    #[test]
    fn norm_path_strips_a_single_line_suffix() {
        assert_eq!(norm_path("routers/jira.py:174"), "routers/jira.py");
    }

    #[test]
    fn norm_path_strips_a_line_range_suffix() {
        assert_eq!(norm_path("routers/jira.py:174-180"), "routers/jira.py");
    }

    #[test]
    fn norm_path_leaves_a_windows_drive_letter_colon_untouched() {
        assert_eq!(norm_path(r"C:\repo\app.py"), r"C:\repo\app.py");
    }

    #[test]
    fn norm_path_leaves_a_non_numeric_colon_suffix_untouched() {
        assert_eq!(norm_path("app.py:not-a-line"), "app.py:not-a-line");
    }

    #[test]
    fn norm_path_leaves_a_malformed_range_suffix_untouched() {
        assert_eq!(norm_path("app.py:1-"), "app.py:1-");
        assert_eq!(norm_path("app.py:-1"), "app.py:-1");
    }

    fn git_repo() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let run = |args: &[&str]| {
            std::process::Command::new("git")
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

    fn commit_all(dir: &Path, msg: &str) -> String {
        let run = |args: &[&str]| {
            std::process::Command::new("git")
                .arg("-C")
                .arg(dir)
                .args(args)
                .output()
                .unwrap()
        };
        run(&["add", "-A"]);
        run(&[
            "-c",
            "user.email=test@test.com",
            "-c",
            "user.name=test",
            "commit",
            "-q",
            "-m",
            msg,
        ]);
        let out = run(&["rev-parse", "HEAD"]);
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    #[test]
    fn a_plain_rename_is_reported_as_old_to_new() {
        let dir = git_repo();
        let base = commit_all(dir.path(), "base");
        std::fs::rename(dir.path().join("app.py"), dir.path().join("handler.py")).unwrap();
        commit_all(dir.path(), "rename");

        let renames = renames_between(dir.path(), &base);
        assert_eq!(
            renames.get("app.py").map(String::as_str),
            Some("handler.py")
        );
    }

    #[test]
    fn a_directory_rename_maps_every_file_under_it() {
        let dir = git_repo();
        std::fs::create_dir_all(dir.path().join("src/old")).unwrap();
        for n in ["a.py", "b.py", "c.py"] {
            std::fs::write(
                dir.path().join("src/old").join(n),
                format!("def {}():\n    return 1\n", n.trim_end_matches(".py")),
            )
            .unwrap();
        }
        let base = commit_all(dir.path(), "add dir");
        std::fs::rename(dir.path().join("src/old"), dir.path().join("src/new")).unwrap();
        commit_all(dir.path(), "move dir");

        let renames = renames_between(dir.path(), &base);
        for n in ["a.py", "b.py", "c.py"] {
            assert_eq!(
                renames.get(&format!("src/old/{n}")).map(String::as_str),
                Some(format!("src/new/{n}").as_str()),
                "{n} was not mapped: {renames:?}"
            );
        }
    }

    #[test]
    fn a_rename_with_an_edit_still_pairs() {
        let dir = git_repo();
        std::fs::write(
            dir.path().join("big.py"),
            (0..40).map(|i| format!("x{i} = {i}\n")).collect::<String>(),
        )
        .unwrap();
        let base = commit_all(dir.path(), "base");
        std::fs::rename(dir.path().join("big.py"), dir.path().join("moved.py")).unwrap();
        std::fs::write(
            dir.path().join("moved.py"),
            (0..40)
                .map(|i| {
                    if i == 7 {
                        "changed = 1\n".to_string()
                    } else {
                        format!("x{i} = {i}\n")
                    }
                })
                .collect::<String>(),
        )
        .unwrap();
        commit_all(dir.path(), "move and edit");

        assert_eq!(
            renames_between(dir.path(), &base)
                .get("big.py")
                .map(String::as_str),
            Some("moved.py")
        );
    }

    #[test]
    fn edits_additions_and_deletions_are_not_mistaken_for_renames() {
        let dir = git_repo();
        std::fs::write(dir.path().join("kept.py"), "a = 1\n").unwrap();
        std::fs::write(dir.path().join("doomed.py"), "b = 2\n").unwrap();
        let base = commit_all(dir.path(), "base");
        std::fs::write(dir.path().join("kept.py"), "a = 2\n").unwrap();
        std::fs::remove_file(dir.path().join("doomed.py")).unwrap();
        std::fs::write(dir.path().join("fresh.py"), "c = 3\n").unwrap();
        std::fs::rename(dir.path().join("app.py"), dir.path().join("renamed.py")).unwrap();
        commit_all(dir.path(), "mixed");

        let renames = renames_between(dir.path(), &base);
        assert_eq!(
            renames.get("app.py").map(String::as_str),
            Some("renamed.py"),
            "{renames:?}"
        );
        assert_eq!(
            renames.len(),
            1,
            "only the rename belongs here: {renames:?}"
        );
    }

    #[test]
    fn an_unusable_revision_or_directory_yields_no_renames() {
        let dir = git_repo();
        assert!(renames_between(dir.path(), "deadbeefdeadbeefdeadbeef").is_empty());
        assert!(renames_between(dir.path(), "").is_empty());
        assert!(renames_between(dir.path(), "   ").is_empty());
        let plain = tempfile::tempdir().unwrap();
        assert!(renames_between(plain.path(), "HEAD").is_empty());
    }

    #[test]
    fn snapshot_captures_existing_file_content() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "before\n").unwrap();
        let snap = snapshot_files(dir.path(), &["a.py".to_string()]);
        assert_eq!(snap.get("a.py"), Some(&Some(b"before\n".to_vec())));
    }

    #[test]
    fn canonical_repo_path_collapses_absolute_and_relative_in_root_aliases() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        std::fs::write(dir.path().join("src/app.rs"), "before\n").unwrap();
        let absolute = dir.path().join("src/app.rs").to_string_lossy().into_owned();

        assert_eq!(
            canonical_repo_path(dir.path(), "src/../src/app.rs"),
            Some("src/app.rs".into())
        );
        assert_eq!(
            canonical_repo_path(dir.path(), &absolute),
            Some("src/app.rs".into())
        );
    }

    #[test]
    fn absolute_in_root_snapshot_reverts_the_file_the_write_resolved_to() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("helper.py");
        std::fs::write(&target, "before\n").unwrap();
        let absolute = target.to_string_lossy().into_owned();

        let snap = snapshot_files(dir.path(), std::slice::from_ref(&absolute));
        assert_eq!(snap.get("helper.py"), Some(&Some(b"before\n".to_vec())));
        std::fs::write(&target, "agent edit\n").unwrap();

        assert_eq!(
            revert(dir.path(), std::slice::from_ref(&absolute), &snap).unwrap(),
            vec!["helper.py".to_string()]
        );
        assert_eq!(std::fs::read_to_string(target).unwrap(), "before\n");
    }

    #[cfg(unix)]
    #[test]
    fn symlink_aliases_share_one_snapshot_identity() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("real")).unwrap();
        std::fs::write(dir.path().join("real/helper.py"), "before\n").unwrap();
        symlink(dir.path().join("real"), dir.path().join("alias")).unwrap();

        let snap = snapshot_files(
            dir.path(),
            &["real/helper.py".to_string(), "alias/helper.py".to_string()],
        );
        assert_eq!(snap.keys().collect::<Vec<_>>(), vec!["real/helper.py"]);
        std::fs::write(dir.path().join("real/helper.py"), "agent edit\n").unwrap();
        revert(dir.path(), &["alias/helper.py".to_string()], &snap).unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.path().join("real/helper.py")).unwrap(),
            "before\n"
        );
    }

    #[test]
    fn snapshot_captures_a_binary_file_verbatim_instead_of_calling_it_absent() {
        let dir = tempfile::tempdir().unwrap();
        let raw = [0x00u8, 0xff, 0xfe, 0x41];
        std::fs::write(dir.path().join("blob.bin"), raw).unwrap();
        let files = vec!["blob.bin".to_string()];
        let snap = snapshot_files(dir.path(), &files);
        assert_eq!(snap.get("blob.bin"), Some(&Some(raw.to_vec())));
        std::fs::write(dir.path().join("blob.bin"), b"clobbered").unwrap();
        revert(dir.path(), &files, &snap).unwrap();
        assert_eq!(
            std::fs::read(dir.path().join("blob.bin")).unwrap(),
            raw.to_vec()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn snapshot_skips_an_existing_file_it_cannot_read_rather_than_calling_it_absent() {
        let root = Path::new("/proc/sys/vm");
        let files = ["drop_caches".to_string(), "no-such-sysctl".to_string()];
        let snap = snapshot_files(root, &files);
        assert_eq!(snap.get("drop_caches"), None);
        assert_eq!(snap.get("no-such-sysctl"), Some(&None));
    }

    #[test]
    fn merge_originals_fills_in_paths_the_snapshot_never_saw() {
        let dir = tempfile::tempdir().unwrap();
        let mut snap = snapshot_files(dir.path(), &[]);
        snap.merge_originals([
            ("helper.py".to_string(), Some(b"was here\n".to_vec())),
            ("brand-new.py".to_string(), None),
        ]);
        assert_eq!(snap.get("helper.py"), Some(&Some(b"was here\n".to_vec())));
        assert_eq!(snap.get("brand-new.py"), Some(&None));
    }

    #[test]
    fn merge_originals_never_overwrites_an_earlier_capture() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "pristine\n").unwrap();
        let mut snap = snapshot_files(dir.path(), &["a.py".to_string()]);
        snap.merge_originals([("a.py".to_string(), Some(b"half-patched\n".to_vec()))]);
        assert_eq!(snap.get("a.py"), Some(&Some(b"pristine\n".to_vec())));
    }

    #[test]
    fn subset_keeps_only_the_named_captures() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "a\n").unwrap();
        std::fs::write(dir.path().join("b.py"), "b\n").unwrap();
        let snap = snapshot_files(
            dir.path(),
            &[
                "a.py".to_string(),
                "b.py".to_string(),
                "gone.py".to_string(),
            ],
        );
        let only_a = snap.subset(&["a.py".to_string()]);
        assert_eq!(only_a.get("a.py"), Some(&Some(b"a\n".to_vec())));
        assert_eq!(only_a.get("b.py"), None);
        assert_eq!(only_a.get("gone.py"), None);
    }

    #[test]
    fn subset_normalizes_its_lookups_and_drops_uncaptured_paths() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "a\n").unwrap();
        let snap = snapshot_files(dir.path(), &["a.py".to_string()]);
        let picked = snap.subset(&["a.py:17-19".to_string(), "never.py".to_string()]);
        let keys: Vec<&String> = picked.keys().collect();
        assert_eq!(keys, vec!["a.py"]);
    }

    #[test]
    fn is_empty_distinguishes_a_captured_baseline_from_no_baseline_at_all() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "a\n").unwrap();
        assert!(Snapshot::default().is_empty());
        assert!(!snapshot_files(dir.path(), &["a.py".to_string()]).is_empty());
        assert!(snapshot_files(dir.path(), &["a.py".to_string()])
            .subset(&[])
            .is_empty());
    }

    #[test]
    fn merge_originals_normalizes_its_keys() {
        let dir = tempfile::tempdir().unwrap();
        let mut snap = snapshot_files(dir.path(), &[]);
        snap.merge_originals([("a.py:12-14".to_string(), Some(b"x\n".to_vec()))]);
        assert_eq!(snap.get("a.py"), Some(&Some(b"x\n".to_vec())));
    }

    #[test]
    fn revert_all_restores_every_named_path_including_journal_supplied_ones() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "before a\n").unwrap();
        std::fs::write(dir.path().join("b.py"), "before b\n").unwrap();
        let mut snap = snapshot_files(dir.path(), &["a.py".to_string()]);
        snap.merge_originals([
            ("b.py".to_string(), Some(b"before b\n".to_vec())),
            ("c.py".to_string(), None),
        ]);
        std::fs::write(dir.path().join("a.py"), "agent a\n").unwrap();
        std::fs::write(dir.path().join("b.py"), "agent b\n").unwrap();
        std::fs::write(dir.path().join("c.py"), "agent c\n").unwrap();

        let reverted = revert_all(
            dir.path(),
            &["a.py".to_string(), "b.py".to_string(), "c.py".to_string()],
            &snap,
        );

        assert_eq!(
            reverted,
            vec!["a.py".to_string(), "b.py".to_string(), "c.py".to_string()]
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("a.py")).unwrap(),
            "before a\n"
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("b.py")).unwrap(),
            "before b\n"
        );
        assert!(!dir.path().join("c.py").exists());
    }

    #[test]
    fn revert_all_drops_duplicates_and_empty_entries() {
        let dir = git_repo();
        std::fs::write(dir.path().join("evil.py"), "malicious\n").unwrap();
        let snap = Snapshot::default();

        let reverted = revert_all(
            dir.path(),
            &[
                "evil.py".to_string(),
                "evil.py".to_string(),
                String::new(),
                "  ".to_string(),
            ],
            &snap,
        );

        assert_eq!(reverted, vec!["evil.py".to_string()]);
        assert!(!dir.path().join("evil.py").exists());
    }

    #[test]
    fn revert_all_keeps_going_past_a_path_revert_itself_would_refuse() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "before\n").unwrap();
        let snap = snapshot_files(dir.path(), &["a.py".to_string()]);
        std::fs::write(dir.path().join("a.py"), "agent\n").unwrap();

        let reverted = revert_all(
            dir.path(),
            &["../outside.py".to_string(), "a.py".to_string()],
            &snap,
        );

        assert_eq!(reverted, vec!["a.py".to_string()]);
        assert_eq!(
            std::fs::read_to_string(dir.path().join("a.py")).unwrap(),
            "before\n"
        );
    }

    #[test]
    fn revert_all_of_nothing_is_a_no_op() {
        let dir = tempfile::tempdir().unwrap();
        assert!(revert_all(dir.path(), &[], &Snapshot::default()).is_empty());
    }

    #[test]
    fn is_git_worktree_distinguishes_a_repo_from_a_plain_directory() {
        assert!(is_git_worktree(git_repo().path()));
        assert!(!is_git_worktree(tempfile::tempdir().unwrap().path()));
    }

    #[test]
    fn snapshot_records_none_for_a_file_that_does_not_exist_yet() {
        let dir = tempfile::tempdir().unwrap();
        let snap = snapshot_files(dir.path(), &["new.py".to_string()]);
        assert_eq!(snap.get("new.py"), Some(&None));
    }

    #[test]
    fn snapshot_keys_are_every_captured_path() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "x\n").unwrap();
        let snap = snapshot_files(dir.path(), &["a.py".to_string(), "new.py".to_string()]);
        let keys: Vec<&String> = snap.keys().collect();
        assert_eq!(keys, vec!["a.py", "new.py"]);
    }

    #[test]
    fn snapshot_skips_a_path_that_escapes_the_root() {
        let dir = tempfile::tempdir().unwrap();
        let snap = snapshot_files(dir.path(), &["../outside.py".to_string()]);
        assert_eq!(snap.get("../outside.py"), None);
    }

    #[test]
    fn get_returns_none_for_a_file_never_snapshotted() {
        let snap = Snapshot::default();
        assert_eq!(snap.get("never-captured.py"), None);
    }

    #[test]
    fn revert_restores_previously_captured_content() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "before\n").unwrap();
        let files = vec!["a.py".to_string()];
        let snap = snapshot_files(dir.path(), &files);
        std::fs::write(dir.path().join("a.py"), "changed by the agent\n").unwrap();
        revert(dir.path(), &files, &snap).unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.path().join("a.py")).unwrap(),
            "before\n"
        );
    }

    #[test]
    fn revert_deletes_a_file_that_did_not_exist_before_the_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let files = vec!["new.py".to_string()];
        let snap = snapshot_files(dir.path(), &files);
        std::fs::write(dir.path().join("new.py"), "created by the agent\n").unwrap();
        revert(dir.path(), &files, &snap).unwrap();
        assert!(!dir.path().join("new.py").exists());
    }

    #[test]
    fn revert_of_a_nonexistent_file_that_never_existed_is_a_no_op() {
        let dir = tempfile::tempdir().unwrap();
        let files = vec!["never.py".to_string()];
        let snap = snapshot_files(dir.path(), &files);
        revert(dir.path(), &files, &snap).unwrap();
        assert!(!dir.path().join("never.py").exists());
    }

    #[test]
    fn revert_of_a_file_never_snapshotted_at_all_is_untouched() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("untracked.py"), "leave me alone\n").unwrap();
        let empty_snapshot = Snapshot::default();
        let reverted = revert(dir.path(), &["untracked.py".to_string()], &empty_snapshot).unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.path().join("untracked.py")).unwrap(),
            "leave me alone\n"
        );
        assert!(reverted.is_empty());
    }

    #[test]
    fn revert_returns_the_files_it_actually_touched() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "before\n").unwrap();
        let files = vec!["a.py".to_string()];
        let snap = snapshot_files(dir.path(), &files);
        std::fs::write(dir.path().join("a.py"), "changed\n").unwrap();
        let reverted = revert(dir.path(), &files, &snap).unwrap();
        assert_eq!(reverted, vec!["a.py".to_string()]);
    }

    #[test]
    fn revert_falls_back_to_git_checkout_for_a_tracked_file_never_snapshotted() {
        let dir = git_repo();
        std::fs::write(dir.path().join("app.py"), "print('forbidden edit')\n").unwrap();
        let empty_snapshot = Snapshot::default();
        let reverted = revert(dir.path(), &["app.py".to_string()], &empty_snapshot).unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.path().join("app.py")).unwrap(),
            "print('hi')\n"
        );
        assert_eq!(reverted, vec!["app.py".to_string()]);
    }

    #[test]
    fn revert_deletes_an_untracked_file_the_agent_created_but_never_snapshotted() {
        let dir = git_repo();
        std::fs::write(dir.path().join("evil.py"), "malicious\n").unwrap();
        let empty_snapshot = Snapshot::default();
        let reverted = revert(dir.path(), &["evil.py".to_string()], &empty_snapshot).unwrap();
        assert!(!dir.path().join("evil.py").exists());
        assert_eq!(reverted, vec!["evil.py".to_string()]);
    }

    #[test]
    fn revert_tier_2_is_a_no_op_when_the_file_never_existed_and_is_untracked() {
        let dir = git_repo();
        let empty_snapshot = Snapshot::default();
        let reverted = revert(
            dir.path(),
            &["never-existed.py".to_string()],
            &empty_snapshot,
        )
        .unwrap();
        assert!(!dir.path().join("never-existed.py").exists());
        assert_eq!(reverted, vec!["never-existed.py".to_string()]);
    }

    #[test]
    fn revert_of_a_path_escaping_the_root_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let snap = Snapshot::default();
        let err = revert(dir.path(), &["../outside.py".to_string()], &snap).unwrap_err();
        assert!(err.contains("outside the repository root"));
    }

    #[cfg(unix)]
    #[test]
    fn revert_restoring_content_propagates_a_write_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.py");
        std::fs::write(&path, "before\n").unwrap();
        let files = vec!["a.py".to_string()];
        let snap = snapshot_files(dir.path(), &files);
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        let err = revert(dir.path(), &files, &snap).unwrap_err();
        assert!(err.starts_with("cannot revert a.py:"), "unexpected: {err}");
    }

    #[cfg(unix)]
    #[test]
    fn revert_deleting_a_new_file_propagates_a_removal_error() {
        let dir = tempfile::tempdir().unwrap();
        let files = vec!["new.py".to_string()];
        let snap = snapshot_files(dir.path(), &files);
        std::fs::create_dir(dir.path().join("new.py")).unwrap();
        std::fs::write(dir.path().join("new.py/inner"), "created by the agent\n").unwrap();
        let err = revert(dir.path(), &files, &snap).unwrap_err();
        assert!(
            err.starts_with("cannot remove new.py:"),
            "unexpected: {err}"
        );
        assert!(dir.path().join("new.py/inner").exists());
    }

    #[cfg(unix)]
    #[test]
    fn revert_tier_2_untracked_removal_propagates_an_error() {
        let dir = git_repo();
        std::fs::create_dir(dir.path().join("evil.py")).unwrap();
        std::fs::write(dir.path().join("evil.py/payload"), "malicious\n").unwrap();
        let empty_snapshot = Snapshot::default();
        let err = revert(dir.path(), &["evil.py".to_string()], &empty_snapshot).unwrap_err();
        assert!(
            err.starts_with("cannot remove evil.py:"),
            "unexpected: {err}"
        );
        assert!(dir.path().join("evil.py/payload").exists());
    }

    #[test]
    fn capture_git_diff_of_an_empty_file_list_is_a_trivial_empty_diff() {
        let dir = git_repo();
        assert_eq!(capture_git_diff(dir.path(), &[]), Some(String::new()));
    }

    #[test]
    fn capture_git_diff_shows_a_modified_files_change() {
        let dir = git_repo();
        std::fs::write(dir.path().join("app.py"), "print('bye')\n").unwrap();
        let diff = capture_git_diff(dir.path(), &["app.py".to_string()]).unwrap();
        assert!(diff.contains("-print('hi')"));
        assert!(diff.contains("+print('bye')"));
    }

    #[test]
    fn capture_git_diff_shows_a_brand_new_file_via_intent_to_add() {
        let dir = git_repo();
        std::fs::write(dir.path().join("new.py"), "print('new')\n").unwrap();
        let diff = capture_git_diff(dir.path(), &["new.py".to_string()]).unwrap();
        assert!(diff.contains("+print('new')"));
    }

    #[test]
    fn capture_git_diff_exports_a_deleted_file_and_pairs_a_move_as_a_rename() {
        let dir = git_repo();
        std::fs::create_dir(dir.path().join("moved")).unwrap();
        std::fs::rename(dir.path().join("app.py"), dir.path().join("moved/app.py")).unwrap();
        let files = ["app.py".to_string(), "moved/app.py".to_string()];
        let diff = capture_git_diff(dir.path(), &files).unwrap();
        assert!(diff.contains("rename from app.py"), "{diff}");
        assert!(diff.contains("rename to moved/app.py"), "{diff}");
        let dir = git_repo();
        std::fs::remove_file(dir.path().join("app.py")).unwrap();
        let diff = capture_git_diff(dir.path(), &["app.py".to_string()]).unwrap();
        assert!(diff.contains("deleted file mode"), "{diff}");
        assert!(diff.contains("-print('hi')"), "{diff}");
    }

    #[test]
    fn capture_git_diff_of_a_repo_where_diff_itself_fails_is_none() {
        let dir = git_repo();
        std::fs::write(dir.path().join("app.py"), "print('bye')\n").unwrap();
        std::process::Command::new("git")
            .arg("-C")
            .arg(dir.path())
            .args(["config", "diff.algorithm", "bogus-algorithm-value"])
            .output()
            .unwrap();
        assert_eq!(capture_git_diff(dir.path(), &["app.py".to_string()]), None);
    }

    #[test]
    fn capture_git_diff_of_a_non_git_directory_is_none() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "x\n").unwrap();
        assert_eq!(capture_git_diff(dir.path(), &["a.py".to_string()]), None);
    }

    #[test]
    fn capture_git_diff_of_a_nonexistent_root_is_none() {
        assert_eq!(
            capture_git_diff(Path::new("/does/not/exist"), &["a.py".to_string()]),
            None
        );
    }

    #[test]
    fn capture_git_diff_silently_drops_a_path_escaping_the_root() {
        let dir = git_repo();
        assert_eq!(
            capture_git_diff(dir.path(), &["../outside.py".to_string()]),
            Some(String::new())
        );
    }

    #[test]
    fn capture_git_diff_scopes_to_only_the_paths_that_stay_inside_the_root() {
        let dir = git_repo();
        std::fs::write(dir.path().join("app.py"), "print('bye')\n").unwrap();
        let diff = capture_git_diff(
            dir.path(),
            &["app.py".to_string(), "../outside.py".to_string()],
        )
        .unwrap();
        assert!(diff.contains("+print('bye')"));
    }

    #[test]
    fn changed_files_whole_tree_of_a_non_git_directory_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(changed_files_whole_tree(dir.path()).is_empty());
    }

    #[test]
    fn changed_files_whole_tree_of_a_nonexistent_root_is_empty() {
        assert!(changed_files_whole_tree(Path::new("/does/not/exist")).is_empty());
    }

    #[test]
    fn changed_files_whole_tree_lists_a_modified_tracked_file() {
        let dir = git_repo();
        std::fs::write(dir.path().join("app.py"), "print('bye')\n").unwrap();
        assert_eq!(
            changed_files_whole_tree(dir.path()),
            vec!["app.py".to_string()]
        );
    }

    #[test]
    fn changed_files_whole_tree_lists_an_untracked_file_without_touching_the_index() {
        let dir = git_repo();
        std::fs::write(dir.path().join("new.py"), "print('new')\n").unwrap();
        assert_eq!(
            changed_files_whole_tree(dir.path()),
            vec!["new.py".to_string()]
        );
        let status = std::process::Command::new("git")
            .arg("-C")
            .arg(dir.path())
            .args(["status", "--porcelain"])
            .output()
            .unwrap();
        assert!(String::from_utf8_lossy(&status.stdout).contains("?? new.py"));
    }

    #[test]
    fn changed_files_whole_tree_is_empty_with_a_clean_working_tree() {
        let dir = git_repo();
        assert!(changed_files_whole_tree(dir.path()).is_empty());
    }

    #[test]
    fn changed_files_whole_tree_lists_a_renamed_files_new_path() {
        let dir = git_repo();
        std::process::Command::new("git")
            .arg("-C")
            .arg(dir.path())
            .args(["mv", "app.py", "renamed.py"])
            .output()
            .unwrap();
        let changed = changed_files_whole_tree(dir.path());
        assert!(changed.contains(&"renamed.py".to_string()));
    }

    #[cfg(unix)]
    #[test]
    fn a_repo_file_named_like_a_unc_path_is_skipped_and_refused_by_revert() {
        let dir = tempfile::tempdir().unwrap();
        let absolute = format!("{}/{}", dir.path().display(), r"\\share");
        let odd = std::path::PathBuf::from(&absolute);
        std::fs::write(&odd, "before\n").unwrap();

        assert_eq!(
            canonical_repo_path(dir.path(), &absolute),
            Some(r"\\share".to_string()),
            "the identity itself resolves; only re-confining it must refuse"
        );

        let snap = snapshot_files(dir.path(), std::slice::from_ref(&absolute));
        assert_eq!(snap.keys().count(), 0);

        let error = revert(dir.path(), std::slice::from_ref(&absolute), &snap).unwrap_err();
        assert!(
            error.contains("repository path changed"),
            "unexpected error: {error}"
        );
        assert_eq!(std::fs::read_to_string(&odd).unwrap(), "before\n");
    }

    #[test]
    fn a_failing_git_checkout_is_reported_instead_of_being_swallowed() {
        let dir = git_repo();
        std::fs::write(dir.path().join("app.py"), "agent edit\n").unwrap();
        let objects = dir.path().join(".git/objects");
        std::fs::remove_dir_all(&objects).unwrap();
        std::fs::create_dir_all(&objects).unwrap();

        let error = revert(dir.path(), &["app.py".to_string()], &Snapshot::default()).unwrap_err();

        assert!(
            error.starts_with("git checkout failed for app.py:"),
            "unexpected error: {error}"
        );
        assert!(!error.ends_with(':'), "stderr was dropped: {error}");
    }
}
