//! [`WriteJournal`]: the copy-on-first-write ledger every write-capable
//! [`crate::SandboxTools`] keeps of the files the agent actually mutated.
//!
//! **Why this exists.** S10's pre-agent snapshot
//! (`bc_stage_s10::remediate_finding` -> `bc_diffcapture::snapshot_files`)
//! only ever covered the finding's OWN file (plus, under policy
//! enforcement, the forbidden-glob sweep). Every `Edit`/`Write` the model
//! emits executes immediately, mid-loop, against the real working tree —
//! so a fix that also rewrote a helper module three directories away left
//! that second file with no captured baseline at all, and the only way
//! back was `git checkout` (wrong on a non-git target, and destructive
//! for a file the user already had uncommitted edits in). This journal
//! closes that gap at the only place that actually knows: the tool
//! executor itself, one instruction before the bytes hit the disk.
//!
//! **Copy-on-FIRST-write** is the whole contract: the very first time a
//! path is seen, its current on-disk bytes (or "did not exist yet") are
//! captured and never replaced. A second `Edit` to the same file must not
//! overwrite that capture with the already-half-patched content, or the
//! "original" the revert path restores would itself be broken code.
//!
//! Bytes, not `String`: a revert that round-tripped through lossy UTF-8
//! would silently corrupt any non-text file the agent touched.
//!
//! The handle is `Arc`-backed and `Clone`, so the executor and the stage
//! that drives it (`bc-stage-s10`) can both hold the same ledger without
//! either owning the other — see [`crate::SandboxTools::journal`].

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::control_path::{canonical_relative_path, is_git_control_path};

/// A shared, cloneable ledger of "what did the agent write, and what was
/// there before". See the module doc comment for the copy-on-first-write
/// contract.
#[derive(Debug, Clone, Default)]
pub struct WriteJournal {
    entries: Arc<Mutex<BTreeMap<String, Option<Vec<u8>>>>>,
}

impl WriteJournal {
    pub fn new() -> Self {
        WriteJournal::default()
    }

    /// Captures `path`'s pre-write state, if this is the first time it has
    /// been seen. Called by [`crate::SandboxTools::execute`] BEFORE the
    /// `Write`/`Edit` handler runs, so the bytes recorded are genuinely
    /// the ones about to be overwritten.
    ///
    /// Three deliberate non-recordings, all of which leave the path with
    /// no journal baseline so the revert path falls through to
    /// `bc_diffcapture`'s git tier instead of acting on a wrong one:
    /// a path that normalizes to nothing, a path that escapes the jail,
    /// Git control metadata (all are refused before mutation), and a file
    /// that exists but cannot be read (deleting it as if it "did not
    /// exist" would be strictly worse than leaving it alone).
    #[cfg(test)]
    pub(crate) fn record(&self, root: &Path, path: &str) {
        let _ = self.prepare_write(root, path);
    }

    /// Capture the baseline and return the very same resolved identity the
    /// writer must use. Refuse mutations whose original bytes cannot be read.
    pub(crate) fn prepare_write(&self, root: &Path, path: &str) -> Result<String, String> {
        let key = canonical_relative_path(root, path)
            .ok_or("ERROR: invalid or outside-root write path")?;
        if is_git_control_path(root, path) {
            return Err("ERROR: writes to Git control paths are not permitted".into());
        }
        let mut entries = self.lock();
        if entries.contains_key(&key) {
            return Ok(key);
        }
        let resolved = bc_pathjail::confine(root, &key).ok_or("ERROR: write path escaped root")?;
        let original = match std::fs::read(&resolved) {
            Ok(bytes) => Some(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(format!("ERROR: cannot capture pre-write baseline: {e}")),
        };
        entries.insert(key.clone(), original);
        Ok(key)
    }

    /// Every repo-relative path the agent wrote to, in sorted order.
    pub fn touched(&self) -> Vec<String> {
        self.lock().keys().cloned().collect()
    }

    /// The captured pre-write content of every [`Self::touched`] path —
    /// `None` for one that did not exist before the agent created it, so a
    /// revert deletes it rather than "restoring" emptiness.
    pub fn originals(&self) -> BTreeMap<String, Option<Vec<u8>>> {
        self.lock().clone()
    }

    /// `true` when the agent has not written anything (yet).
    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    /// Drops every entry — called between findings, since S10 processes
    /// them strictly sequentially and each one's gates must only ever see
    /// its OWN writes.
    pub fn clear(&self) {
        self.lock().clear();
    }

    /// Every critical section here is a couple of `BTreeMap` calls with no
    /// user code in between, so the mutex can only be poisoned by a panic
    /// that cannot originate inside one — treating that as unreachable is
    /// honest, rather than a swallowed error that hides a real bug.
    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Option<Vec<u8>>>> {
        self.entries
            .lock()
            .expect("the write journal is never locked across a panic")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_uses_a_canonical_repo_relative_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a/b/app.py");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "before\n").unwrap();
        let journal = WriteJournal::new();
        journal.record(dir.path(), path.to_str().unwrap());
        assert_eq!(journal.touched(), vec!["a/b/app.py".to_string()]);
    }

    #[test]
    fn record_does_not_capture_a_git_control_path() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".git")).unwrap();
        std::fs::write(dir.path().join(".git/config"), "[core]\n").unwrap();
        let journal = WriteJournal::new();
        journal.record(dir.path(), ".git/config");
        assert!(journal.is_empty());
    }

    #[test]
    fn a_fresh_journal_is_empty() {
        let journal = WriteJournal::new();
        assert!(journal.is_empty());
        assert!(journal.touched().is_empty());
        assert!(journal.originals().is_empty());
    }

    #[test]
    fn record_captures_an_existing_files_bytes() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "before\n").unwrap();
        let journal = WriteJournal::new();
        journal.record(dir.path(), "a.py");
        assert_eq!(journal.touched(), vec!["a.py".to_string()]);
        assert_eq!(
            journal.originals().get("a.py"),
            Some(&Some(b"before\n".to_vec()))
        );
        assert!(!journal.is_empty());
    }

    #[test]
    fn record_captures_non_utf8_bytes_verbatim() {
        // A lossy String round-trip here would silently corrupt the file
        // the revert path later restores.
        let dir = tempfile::tempdir().unwrap();
        let raw = [0x00u8, 0xff, 0xfe, 0x41];
        std::fs::write(dir.path().join("blob.bin"), raw).unwrap();
        let journal = WriteJournal::new();
        journal.record(dir.path(), "blob.bin");
        assert_eq!(
            journal.originals().get("blob.bin"),
            Some(&Some(raw.to_vec()))
        );
    }

    #[test]
    fn record_marks_a_brand_new_file_as_not_having_existed() {
        let dir = tempfile::tempdir().unwrap();
        let journal = WriteJournal::new();
        journal.record(dir.path(), "new.py");
        assert_eq!(journal.originals().get("new.py"), Some(&None));
    }

    #[test]
    fn a_second_write_never_replaces_the_first_capture() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "pristine\n").unwrap();
        let journal = WriteJournal::new();
        journal.record(dir.path(), "a.py");
        std::fs::write(dir.path().join("a.py"), "half-patched\n").unwrap();
        journal.record(dir.path(), "./a.py");
        assert_eq!(journal.touched(), vec!["a.py".to_string()]);
        assert_eq!(
            journal.originals().get("a.py"),
            Some(&Some(b"pristine\n".to_vec()))
        );
    }

    #[test]
    fn writer_refuses_ambiguous_or_unreadable_baselines() {
        let dir = tempfile::tempdir().unwrap();
        let journal = WriteJournal::new();
        std::fs::create_dir(dir.path().join("directory")).unwrap();
        assert!(journal.prepare_write(dir.path(), "directory").is_err());
        assert!(journal.prepare_write(dir.path(), " app.py ").is_err());
        assert!(journal.prepare_write(dir.path(), "app.py:123").is_err());
        assert!(journal.is_empty());
    }

    #[test]
    fn a_path_that_normalizes_to_nothing_is_not_recorded() {
        let dir = tempfile::tempdir().unwrap();
        let journal = WriteJournal::new();
        journal.record(dir.path(), "  ");
        assert!(journal.is_empty());
    }

    #[test]
    fn a_path_escaping_the_root_is_not_recorded() {
        let dir = tempfile::tempdir().unwrap();
        let journal = WriteJournal::new();
        journal.record(dir.path(), "../outside.py");
        assert!(journal.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn an_unreadable_existing_file_is_not_recorded_as_nonexistent() {
        // `drop_caches` is a regular file nobody can open for reading. The
        // kernel checks a sysctl's mode bits itself, without the
        // CAP_DAC_OVERRIDE bypass a chmod 000 file gets, so the read fails
        // for root as well. Its directory stands in for the repository.
        // Only the read is attempted: nothing is ever written to it.
        let root = Path::new("/proc/sys/vm");
        let journal = WriteJournal::new();
        journal.record(root, "drop_caches");
        // Recording it as `None` would make a later revert DELETE a file
        // whose content was never captured.
        assert!(journal.is_empty());
        let refused = journal.prepare_write(root, "drop_caches").unwrap_err();
        assert!(
            refused.starts_with("ERROR: cannot capture pre-write baseline:"),
            "{refused}"
        );
        assert!(journal.is_empty());
    }

    #[test]
    fn clear_drops_every_entry() {
        let dir = tempfile::tempdir().unwrap();
        let journal = WriteJournal::new();
        journal.record(dir.path(), "new.py");
        journal.clear();
        assert!(journal.is_empty());
    }

    #[test]
    fn a_cloned_handle_shares_one_ledger() {
        let dir = tempfile::tempdir().unwrap();
        let journal = WriteJournal::new();
        let handle = journal.clone();
        handle.record(dir.path(), "new.py");
        assert_eq!(journal.touched(), vec!["new.py".to_string()]);
    }
}
