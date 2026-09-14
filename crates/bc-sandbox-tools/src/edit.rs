//! The `Edit` tool — a targeted string replacement, offered under the
//! same `new_with_write` gate as [`crate::write::write_file`]. Requires
//! `old_string` to occur exactly once in the file, matching Claude's own
//! Edit tool semantics: an edit that could apply to more than one
//! location (or none at all) is refused rather than guessed at.

use std::path::Path;

use crate::control_path::is_git_control_path;

pub fn edit_file(root: &Path, path: &str, old_string: &str, new_string: &str) -> String {
    let Some(resolved) = bc_pathjail::confine(root, path) else {
        return format!("ERROR: path '{path}' is outside the repository root");
    };
    if is_git_control_path(root, path) {
        return "ERROR: writes to Git control paths are not permitted".to_string();
    }
    if old_string == new_string {
        return "ERROR: old_string and new_string are identical".to_string();
    }
    let content = match std::fs::read_to_string(&resolved) {
        Ok(c) => c,
        Err(e) => return format!("ERROR: cannot read {path}: {e}"),
    };
    let occurrences = content.matches(old_string).count();
    if occurrences == 0 {
        return format!("ERROR: old_string not found in {path}");
    }
    if occurrences > 1 {
        return format!(
            "ERROR: old_string is not unique in {path} ({occurrences} occurrences) — add more surrounding context"
        );
    }
    let updated = content.replacen(old_string, new_string, 1);
    match std::fs::write(&resolved, updated) {
        Ok(()) => format!("Edited {path}"),
        Err(e) => format!("ERROR: cannot write {path}: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_a_unique_occurrence() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "query(x)\n").unwrap();
        let out = edit_file(dir.path(), "a.py", "query(x)", "query(x, params)");
        assert_eq!(out, "Edited a.py");
        assert_eq!(
            std::fs::read_to_string(dir.path().join("a.py")).unwrap(),
            "query(x, params)\n"
        );
    }

    #[test]
    fn errors_when_old_string_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "print(1)\n").unwrap();
        let out = edit_file(dir.path(), "a.py", "missing", "x");
        assert_eq!(out, "ERROR: old_string not found in a.py");
    }

    #[test]
    fn errors_when_old_string_is_ambiguous() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "x = 1\nx = 1\n").unwrap();
        let out = edit_file(dir.path(), "a.py", "x = 1", "x = 2");
        assert_eq!(
            out,
            "ERROR: old_string is not unique in a.py (2 occurrences) — add more surrounding context"
        );
    }

    #[test]
    fn errors_when_old_and_new_are_identical() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "x = 1\n").unwrap();
        let out = edit_file(dir.path(), "a.py", "x = 1", "x = 1");
        assert_eq!(out, "ERROR: old_string and new_string are identical");
    }

    #[test]
    fn errors_when_the_file_does_not_exist() {
        let dir = tempfile::tempdir().unwrap();
        let out = edit_file(dir.path(), "missing.py", "a", "b");
        assert!(
            out.starts_with("ERROR: cannot read missing.py:"),
            "unexpected: {out}"
        );
    }

    #[test]
    fn escaping_the_root_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let out = edit_file(dir.path(), "../outside.py", "a", "b");
        assert_eq!(
            out,
            "ERROR: path '../outside.py' is outside the repository root"
        );
    }

    #[test]
    fn refuses_to_edit_a_git_control_path() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".git")).unwrap();
        let config = dir.path().join(".git/config");
        std::fs::write(&config, "bare = false\n").unwrap();
        let out = edit_file(dir.path(), ".git/config", "false", "true");
        assert_eq!(out, "ERROR: writes to Git control paths are not permitted");
        assert_eq!(std::fs::read_to_string(config).unwrap(), "bare = false\n");
    }

    #[cfg(unix)]
    #[test]
    fn an_unwritable_file_is_reported_as_an_io_error_after_a_valid_match() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.py");
        std::fs::write(&path, "x = 1\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        let out = edit_file(dir.path(), "a.py", "x = 1", "x = 2");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            out.starts_with("ERROR: cannot write a.py:"),
            "unexpected: {out}"
        );
    }
}
