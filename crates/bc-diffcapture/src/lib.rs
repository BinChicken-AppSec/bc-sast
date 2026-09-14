//! Pre-edit snapshotting, post-edit revert, and git-diff capture for
//! Phase 2's S10 remediation stage, ported from `remediation_agent/
//! artifacts/diff/{snapshot,gitcapture,synth,paths}.py` + `policy/revert.py`.
//! Every path this crate touches is confined via `bc_pathjail::confine`
//! first (after [`norm_path`] strips a trailing `:line`/`:start-end`
//! location suffix a finding/verdict reference may carry) — an
//! LLM-controlled `verdict.changes[].file` must never be trusted
//! directly, matching the Python original's own `_safe_repo_path`/
//! `_within_repo` guards (a CWE-22 defense; the Python original cites a
//! concrete escape scenario for why: a `\\host\share` UNC path handed to
//! `git` could leak a Windows NetNTLMv2 hash).

use std::collections::BTreeMap;
use std::path::{Component, Path};

mod synth;
mod worktree;

pub use synth::{synth_unified_diff, SYNTH_HEADER};
pub use worktree::{create_detached_worktree, export_patch, remove_worktree};

/// Normalizes a finding/verdict file reference to a clean repo-relative
/// path: strips a trailing `:<line>` or `:<start>-<end>` location suffix
/// (e.g. `routers/jira.py:174-174` -> `routers/jira.py`) and trims
/// whitespace. Ported from `artifacts/diff/paths.py::_norm_path`. A
/// Windows drive-letter colon (`C:\...`) is left untouched, since the
/// text after it is never itself digits-shaped.
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

/// Resolves an untrusted file reference and returns its canonical identity
/// relative to `root`.  The identity, rather than the spelling supplied by
/// a finding or tool call, is the only key used for snapshots, rollback, and
/// Git pathspecs.  This matters for absolute in-root paths and aliases such
/// as `src/../src/app.py`: `bc_pathjail::confine` quite correctly accepts
/// both, but using their original spelling would make a baseline impossible
/// to find later.
///
/// The returned string uses `/` between native path components, which keeps
/// identities portable for Git and matches the write journal. A backslash is
/// still an ordinary character in a Unix file name because splitting happens
/// through [`Path::components`], not lexical string replacement.
pub fn canonical_repo_path(root: &Path, raw: &str) -> Option<String> {
    let normalized = norm_path(raw);
    let resolved = bc_pathjail::confine(root, &normalized)?;
    let root_resolved = bc_pathjail::confine(root, ".")?;
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

/// Pre-edit file contents, captured before S10's agentic tool loop runs.
/// `None` for a path that didn't exist yet (a brand-new file the agent
/// might create) — [`revert`] deletes such a file if it needs to be
/// undone, rather than trying to "restore" nothing.
///
/// Contents are raw BYTES, not `String`. The earlier `read_to_string`
/// capture had two failure modes that both ended in a corrupted or
/// destroyed file: a non-UTF-8 file was captured as `None` ("didn't
/// exist"), so reverting it DELETED it, and any restore of one would have
/// gone through a lossy conversion. Reading bytes makes both impossible;
/// the only place text is required is [`synth_unified_diff`], which
/// simply skips a file whose baseline isn't valid UTF-8 (exactly what it
/// already did for a binary file it couldn't read).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Snapshot {
    contents: BTreeMap<String, Option<Vec<u8>>>,
}

impl Snapshot {
    /// The captured content for `file`, if it was part of the snapshot at
    /// all. `Some(None)` means "captured, and it didn't exist yet";
    /// `None` means "never captured" (not in the `files` list
    /// `snapshot_files` was given).
    pub fn get(&self, file: &str) -> Option<&Option<Vec<u8>>> {
        self.contents.get(file)
    }

    /// Every path this snapshot captured (whether or not it existed at
    /// snapshot time) — [`synth_unified_diff`](crate::synth_unified_diff)'s
    /// own default scope before adding any caller-supplied `extra_files`.
    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.contents.keys()
    }

    /// A copy of this snapshot restricted to `files` (each
    /// [`norm_path`]-cleaned), silently dropping any path this snapshot
    /// never captured.
    ///
    /// Exists so S10 can hand ONE self-contained value — "the bytes of
    /// exactly the files this finding's agent touched, as of the moment
    /// before it ran" — forward to Phase 3's S11 rollback, which runs long
    /// after `remediate_finding` has returned and dropped its own working
    /// state. Carrying the *full* pre-agent snapshot instead would be
    /// actively wrong: it also holds the finding's own file and the policy
    /// gate's forbidden-glob sweep, paths the agent may never have written,
    /// and an entry captured as `Some(None)` ("did not exist yet") tells
    /// [`revert`] to DELETE that file. "Put this finding's patch back" must
    /// not mean "delete every file that happened to be missing when the
    /// run started".
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

    /// `true` when nothing was captured at all — the condition that tells
    /// a caller holding a per-finding baseline that there is none, and it
    /// must fall back to a VCS-based rollback (or warn that it cannot).
    pub fn is_empty(&self) -> bool {
        self.contents.is_empty()
    }

    /// Folds in baselines captured somewhere OTHER than
    /// [`snapshot_files`] — in practice `bc_sandbox_tools::WriteJournal`'s
    /// copy-on-first-write ledger, which is the only component that sees a
    /// file the agent decided to edit but nobody predicted in advance.
    ///
    /// An entry already in this snapshot always wins: it was captured
    /// before the agent ran at all, which is at least as early as any
    /// journal entry and therefore at least as pristine. Keys are
    /// [`norm_path`]-cleaned so they line up with everything else here.
    pub fn merge_originals(
        &mut self,
        originals: impl IntoIterator<Item = (String, Option<Vec<u8>>)>,
    ) {
        for (file, content) in originals {
            self.contents.entry(norm_path(&file)).or_insert(content);
        }
    }
}

/// Captures the current on-disk content of every entry in `files` (or
/// `None` if it doesn't exist yet), confined to `root`. Each reference is
/// first converted to its [`canonical_repo_path`] (which also strips a
/// trailing `:line` location suffix) — the [`Snapshot`]'s own keys, and
/// every later `revert`/`capture_git_diff` lookup, use that same identity.
/// A path that escapes the jail is silently
/// skipped, not an error — the same "not part of this repo, not this
/// crate's concern" stance `bc-pathjail` establishes elsewhere.
///
/// A file that exists but cannot be READ (permissions) is deliberately
/// left out of the snapshot entirely rather than recorded as `None`:
/// `None` means "delete me on revert", which would be a catastrophic
/// misreading of "I couldn't open it".
pub fn snapshot_files(root: &Path, files: &[String]) -> Snapshot {
    let mut contents = BTreeMap::new();
    for file in files {
        let Some(rel) = canonical_repo_path(root, file) else {
            continue;
        };
        let Some(resolved) = bc_pathjail::confine(root, &rel) else {
            // `rel` came from a successful `confine` above.  Keep this
            // defensive guard in case the filesystem changes underneath a
            // live target between identity calculation and opening it.
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

/// Reverts every entry in `files` back to its pre-edit [`Snapshot`]
/// state, returning the subset that was actually touched (content
/// restored, deleted, or git-checked-out) — NOT simply an echo of
/// `files`, since a caller that inferred "everything was reverted" from
/// a bare `Ok(())` would silently over-report: a file never captured by
/// [`snapshot_files`] (e.g. one the agent CREATED, so it was never
/// among the finding-scoped files snapshotted before the agent ran) used
/// to hit a silent no-op here while the caller still recorded it as
/// rolled back. Three tiers, ported from `policy/revert.py::revert_files`:
///   1. Snapshotted: restore the saved content, or delete the file if
///      the snapshot recorded it as not having existed yet.
///   2. Not snapshotted, but `root` is a git worktree: `git checkout --`
///      if the file is tracked, delete it if untracked and present.
///   3. Otherwise: no baseline to revert to at all — left untouched, not
///      reported, matching Python's own tier 3.
pub fn revert(root: &Path, files: &[String], snapshot: &Snapshot) -> Result<Vec<String>, String> {
    let is_git = is_git_worktree(root);
    let mut reverted = Vec::new();
    for file in files {
        let Some(rel) = canonical_repo_path(root, file) else {
            return Err(format!(
                "cannot revert '{file}': outside the repository root"
            ));
        };
        let Some(resolved) = bc_pathjail::confine(root, &rel) else {
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

/// The all-or-as-much-as-possible sibling of [`revert`]: rolls every entry
/// in `files` back, one at a time, and returns only what was genuinely
/// restored — never an error.
///
/// This is what S10's safety gates actually call. [`revert`] stops at the
/// first unrestorable path (one that escapes the jail, a read-only file),
/// which is right for the policy post-gate's one-file-at-a-time audit but
/// wrong for "put the whole tree back": a rollback that abandons every
/// remaining file because of one problem leaves a half-undone patch, which
/// is worse than either extreme. Duplicate and empty entries are dropped,
/// so a file named by both the write journal and `git status` is restored
/// (and reported) exactly once.
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

/// `true` when `root` sits inside a git working tree — the condition
/// [`revert`]'s tier 2 (`git checkout --` / unlink-untracked) depends on.
/// Public so a caller can tell "reverted nothing because there was nothing
/// to revert" apart from "reverted nothing because this target has no VCS
/// baseline at all" and warn accordingly.
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

/// Shells out to `git diff` scoped to `files`, after `git add -N`
/// (intent-to-add, so a brand-new file shows up in the diff too —
/// matching the Python original exactly). Every entry in `files` is
/// converted to a [`canonical_repo_path`] first (an
/// LLM-controlled `verdict.changes[].file` must never reach a git
/// pathspec directly — see the module doc comment); an entry that
/// escapes the jail is silently dropped rather than erroring, the same
/// "not part of this repo" stance `snapshot_files` takes. Returns `None`
/// if `git` isn't on `PATH`, `root` isn't a git repository, or either
/// command fails for any reason — the caller falls back to
/// [`synth_unified_diff`] in that case. An empty (or entirely
/// jail-escaping) `files` list is a trivial `Some("")`, no process
/// spawned.
pub fn capture_git_diff(root: &Path, files: &[String]) -> Option<String> {
    let safe = confine_all(root, files);
    if safe.is_empty() {
        return Some(String::new());
    }
    let add = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .arg("add")
        .arg("-N")
        .arg("--")
        .args(&safe)
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

/// The canonical, repo-relative subset of `files` that resolve inside
/// `root`, in order — `capture_git_diff`'s jailing helper.
fn confine_all(root: &Path, files: &[String]) -> Vec<String> {
    files
        .iter()
        .filter_map(|f| canonical_repo_path(root, f))
        .collect()
}

/// Every changed path in `root`'s working tree (repo-relative):
/// modified, added, deleted, AND untracked files, via
/// `git status --porcelain -z --untracked-files=all` — unlike
/// [`capture_git_diff`], this is not scoped to a caller-supplied file
/// list, and (deliberately, matching the Python original) never runs
/// `git add -N` first, so it has zero index side effects. Ported from
/// `artifacts/diff/gitcapture.py::changed_files_whole_tree`: the ground
/// truth the S10 post-gate needs so a forbidden edit the agent made but
/// omitted from its own reported `changes` is still discovered. Returns
/// an empty list for a non-git target, when `git` is unavailable, or on
/// any error — never panics.
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

/// Parses `git status --porcelain -z` output structurally. Each record
/// is `XY <path>` (2 status chars + a space + the exact, unquoted path —
/// strip the 3-char prefix). A rename/copy record (`X` or `Y` is `R`/`C`)
/// is followed by a SECOND, bare NUL-delimited token holding the
/// ORIGINAL path with no `XY ` prefix at all: it must be consumed
/// verbatim, since applying the 3-char strip to that bare token would
/// mangle an original path whose 3rd character happens to be a space.
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
        // The Write tool accepts an absolute path when it remains inside
        // the root.  Its journal and this snapshot must use the same
        // canonical repo-relative key, otherwise a non-git rollback misses
        // the actual modified file.
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
        // The `read_to_string` capture this replaced recorded a non-UTF-8
        // file as `None` ("didn't exist"), so reverting it DELETED it.
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

    #[cfg(unix)]
    #[test]
    fn snapshot_skips_an_existing_file_it_cannot_read_rather_than_calling_it_absent() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.py");
        std::fs::write(&path, "x\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        let snap = snapshot_files(dir.path(), &["secret.py".to_string()]);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        // Not `Some(&None)`: that would mean "delete me on revert".
        assert_eq!(snap.get("secret.py"), None);
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
        // The pre-agent snapshot is at least as pristine as any journal
        // entry, which was only captured once the agent decided to write.
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
        // Critically NOT carried: `gone.py` was captured as "did not
        // exist", which a revert reads as "delete me".
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
        // `b.py`/`c.py` arrive the way the agent's journal supplies them:
        // nobody predicted those edits, so they were never in the
        // pre-agent file list.
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
        // `revert` aborts the whole list on a jail escape; `revert_all`
        // must still restore everything after it, or one bad entry from an
        // LLM-authored `changes[]` would leave a half-undone patch.
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
        // Never created at all — the agent didn't touch it.
        revert(dir.path(), &files, &snap).unwrap();
        assert!(!dir.path().join("never.py").exists());
    }

    #[test]
    fn revert_of_a_file_never_snapshotted_at_all_is_untouched() {
        // Non-git tempdir -- tier 3, no baseline at all.
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
        // The regression this port once had: a file the agent modified
        // but that was never in the finding-scoped snapshot list (e.g.
        // it was outside the original snapshot scope) must still be
        // rolled back, not silently left as-is while still being
        // reported as reverted by a caller that only checks `Ok`.
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
        // The exact scenario the review flagged: a forbidden file the
        // agent CREATED was never part of the pre-edit snapshot (only
        // files the finding named were snapshotted before the agent
        // ran), so it must be discovered and removed via git's
        // untracked-file fallback, not silently reported as reverted
        // while still sitting on disk.
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
        // Matches Python: `reverted.append(rel)` happens unconditionally
        // once `is_git` is true, even when neither the checkout nor the
        // unlink branch actually did anything.
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
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.py");
        std::fs::write(&path, "before\n").unwrap();
        let files = vec!["a.py".to_string()];
        let snap = snapshot_files(dir.path(), &files);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        let err = revert(dir.path(), &files, &snap).unwrap_err();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(err.starts_with("cannot revert a.py:"), "unexpected: {err}");
    }

    #[cfg(unix)]
    #[test]
    fn revert_deleting_a_new_file_propagates_a_removal_error() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let files = vec!["new.py".to_string()];
        let snap = snapshot_files(dir.path(), &files); // records None (didn't exist)
        std::fs::write(dir.path().join("new.py"), "created by the agent\n").unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
        let err = revert(dir.path(), &files, &snap).unwrap_err();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            err.starts_with("cannot remove new.py:"),
            "unexpected: {err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn revert_tier_2_untracked_removal_propagates_an_error() {
        use std::os::unix::fs::PermissionsExt;
        let dir = git_repo();
        std::fs::write(dir.path().join("evil.py"), "malicious\n").unwrap();
        let empty_snapshot = Snapshot::default();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
        let err = revert(dir.path(), &["evil.py".to_string()], &empty_snapshot).unwrap_err();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            err.starts_with("cannot remove evil.py:"),
            "unexpected: {err}"
        );
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
    fn capture_git_diff_of_a_repo_where_diff_itself_fails_is_none() {
        let dir = git_repo();
        std::fs::write(dir.path().join("app.py"), "print('bye')\n").unwrap();
        // `add -N` never invokes the diff engine, so a bad `diff.algorithm`
        // lets it succeed while the second `git diff` command fails.
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
        // Every entry escapes the jail, so no git process is even spawned —
        // an LLM-controlled `verdict.changes[].file` must never reach a git
        // pathspec directly.
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
        // No index side effects: the file is still untracked (`??`), not
        // staged as intent-to-add.
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

    /// The one input shape that actually reaches the "re-confining the
    /// canonical identity failed" guards in `snapshot_files`/`revert`: a
    /// repository file whose own NAME begins with two backslashes. The
    /// absolute spelling the caller supplies is not a UNC path, so the
    /// identity resolves; the repo-relative identity it yields IS one, and
    /// `bc_pathjail::confine` refuses it before any filesystem touch (see
    /// that crate's SMB/NTLMv2 note). The file is therefore left out of the
    /// snapshot entirely rather than captured under a key that later
    /// resolves to nothing.
    #[cfg(unix)]
    #[test]
    fn a_repo_file_named_like_a_unc_path_is_skipped_and_refused_by_revert() {
        let dir = tempfile::tempdir().unwrap();
        // Built by hand rather than with `Path::join`: `join` (and
        // clippy's `join_absolute_paths` lint) treats a leading backslash
        // as a separator, but on Unix this really is one ordinary file
        // name inside the temporary directory.
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
        // Refused, not silently mangled: the file is still on disk intact.
        assert_eq!(std::fs::read_to_string(&odd).unwrap(), "before\n");
    }

    #[test]
    fn a_failing_git_checkout_is_reported_instead_of_being_swallowed() {
        // Tier 2 of `revert`: the file is tracked but was never
        // snapshotted, so the only baseline is git's own. Emptying the
        // object store (while leaving `.git` itself a valid work tree, so
        // `is_git_worktree`/`is_tracked` still answer truthfully) makes
        // `git checkout --` fail for a reason no caller can compensate
        // for. Reporting it is the whole point of the change from the
        // previous `let _ = ...`: a revert that silently did nothing used
        // to be indistinguishable from one that worked.
        let dir = git_repo();
        std::fs::write(dir.path().join("app.py"), "agent edit\n").unwrap();
        // Replace the object store wholesale rather than walking it and
        // deleting file by file. Git's on-disk layout under `.git/objects`
        // varies by version (loose objects, packs, `info`, and on newer
        // git a commit-graph), so enumerating it and calling `remove_file`
        // on every entry fails the moment one of them is not a plain
        // removable file. What this test needs is simply an empty store.
        let objects = dir.path().join(".git/objects");
        std::fs::remove_dir_all(&objects).unwrap();
        std::fs::create_dir_all(&objects).unwrap();

        let error = revert(dir.path(), &["app.py".to_string()], &Snapshot::default()).unwrap_err();

        assert!(
            error.starts_with("git checkout failed for app.py:"),
            "unexpected error: {error}"
        );
        // The reported stderr is git's, not an invented message.
        assert!(!error.ends_with(':'), "stderr was dropped: {error}");
    }
}
