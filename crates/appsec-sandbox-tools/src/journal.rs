use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::control_path::{canonical_relative_path, is_git_control_path};

#[derive(Debug, Clone, Default)]
pub struct WriteJournal {
    entries: Arc<Mutex<BTreeMap<String, Option<Vec<u8>>>>>,
}

impl WriteJournal {
    pub fn new() -> Self {
        WriteJournal::default()
    }

    #[cfg(test)]
    pub(crate) fn record(&self, root: &Path, path: &str) {
        let _ = self.prepare_write(root, path);
    }

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
        let resolved =
            appsec_pathjail::confine(root, &key).ok_or("ERROR: write path escaped root")?;
        let original = match std::fs::read(&resolved) {
            Ok(bytes) => Some(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(format!("ERROR: cannot capture pre-write baseline: {e}")),
        };
        entries.insert(key.clone(), original);
        Ok(key)
    }

    pub fn touched(&self) -> Vec<String> {
        self.lock().keys().cloned().collect()
    }

    pub fn originals(&self) -> BTreeMap<String, Option<Vec<u8>>> {
        self.lock().clone()
    }

    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    pub fn clear(&self) {
        self.lock().clear();
    }

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
        let root = Path::new("/proc/sys/vm");
        let journal = WriteJournal::new();
        journal.record(root, "drop_caches");
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
