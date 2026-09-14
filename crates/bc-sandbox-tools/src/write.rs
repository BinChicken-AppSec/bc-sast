//! The `Write` tool — creates or overwrites a file. Only offered when a
//! [`crate::SandboxTools`] is constructed via `new_with_write` (Phase 2's
//! S10 remediation stage); every other consumer of this crate never sees
//! it in `available_tools()` at all.

use std::path::Path;

use crate::control_path::is_git_control_path;

pub fn write_file(root: &Path, path: &str, content: &str) -> String {
    let Some(resolved) = bc_pathjail::confine(root, path) else {
        return format!("ERROR: path '{path}' is outside the repository root");
    };
    if is_git_control_path(root, path) {
        return "ERROR: writes to Git control paths are not permitted".to_string();
    }
    if let Some(Err(e)) = resolved.parent().map(std::fs::create_dir_all) {
        return format!("ERROR: cannot create directory for {path}: {e}");
    }
    match std::fs::write(&resolved, content) {
        Ok(()) => format!("Wrote {} bytes to {path}", content.len()),
        Err(e) => format!("ERROR: cannot write {path}: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_a_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let out = write_file(dir.path(), "new.txt", "hello\n");
        assert_eq!(out, "Wrote 6 bytes to new.txt");
        assert_eq!(
            std::fs::read_to_string(dir.path().join("new.txt")).unwrap(),
            "hello\n"
        );
    }

    #[test]
    fn overwrites_an_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "old").unwrap();
        write_file(dir.path(), "a.txt", "new");
        assert_eq!(
            std::fs::read_to_string(dir.path().join("a.txt")).unwrap(),
            "new"
        );
    }

    #[test]
    fn creates_missing_parent_directories() {
        let dir = tempfile::tempdir().unwrap();
        let out = write_file(dir.path(), "nested/dir/file.txt", "x");
        assert_eq!(out, "Wrote 1 bytes to nested/dir/file.txt");
        assert!(dir.path().join("nested/dir/file.txt").is_file());
    }

    #[test]
    fn escaping_the_root_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let out = write_file(dir.path(), "../outside.txt", "x");
        assert_eq!(
            out,
            "ERROR: path '../outside.txt' is outside the repository root"
        );
        assert!(!dir.path().join("../outside.txt").exists());
    }

    #[test]
    fn refuses_to_write_a_git_control_path() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".git")).unwrap();
        let config = dir.path().join(".git/config");
        std::fs::write(&config, "[core]\n").unwrap();
        let out = write_file(dir.path(), ".git/config", "changed\n");
        assert_eq!(out, "ERROR: writes to Git control paths are not permitted");
        assert_eq!(std::fs::read_to_string(config).unwrap(), "[core]\n");
    }

    #[cfg(unix)]
    #[test]
    fn refuses_a_git_control_path_reached_through_an_in_repo_symlink() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".git")).unwrap();
        let config = dir.path().join(".git/config");
        std::fs::write(&config, "[core]\n").unwrap();
        symlink(dir.path().join(".git"), dir.path().join("metadata")).unwrap();

        let out = write_file(dir.path(), "metadata/config", "changed\n");

        assert_eq!(out, "ERROR: writes to Git control paths are not permitted");
        assert_eq!(std::fs::read_to_string(config).unwrap(), "[core]\n");
    }

    #[cfg(unix)]
    #[test]
    fn an_unwritable_directory_is_reported_as_an_io_error() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
        let out = write_file(dir.path(), "a.txt", "x");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            out.starts_with("ERROR: cannot write a.txt:"),
            "unexpected: {out}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn an_uncreatable_parent_directory_is_reported_as_an_io_error() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
        let out = write_file(dir.path(), "nested/file.txt", "x");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            out.starts_with("ERROR: cannot create directory for nested/file.txt:"),
            "unexpected: {out}"
        );
    }
}
