//! Protections for repository metadata that an S10 remediation must never
//! mutate. The target's Git control directory is part of the harness's
//! execution boundary, not source code the model may repair.

use std::path::{Component, Path};

/// Resolve a caller-supplied path and return its canonical, repository-relative
/// identity. This deliberately accepts an absolute path only when
/// `bc_pathjail::confine` proves that it is inside `root`; callers must use the
/// returned identity rather than the supplied spelling when correlating files.
pub(crate) fn canonical_relative_path(root: &Path, path: &str) -> Option<String> {
    if path != path.trim() {
        return None;
    }
    let resolved = bc_pathjail::confine(root, path)?;
    let root = bc_pathjail::confine(root, ".")?;
    let relative = resolved.strip_prefix(root).ok()?;
    let components: Vec<String> = relative
        .components()
        .map(|component| match component {
            Component::Normal(name) => {
                let name = name.to_str()?;
                if name.contains(':') || name != name.trim() {
                    return None;
                }
                Some(name.to_owned())
            }
            // `confine` returns a path within the canonical root, so these
            // components cannot identify a writable file safely.
            Component::CurDir
            | Component::ParentDir
            | Component::RootDir
            | Component::Prefix(_) => None,
        })
        .collect::<Option<_>>()?;
    (!components.is_empty()).then(|| components.join("/"))
}

/// True when `path` resolves into Git's control directory. Resolve before
/// comparing so lexical aliases such as `./.git/config` and an in-repository
/// symlink to `.git` cannot bypass the protection. Case-insensitive comparison
/// also covers Windows filesystems that resolve `.GIT` to `.git`.
pub(crate) fn is_git_control_path(root: &Path, path: &str) -> bool {
    canonical_relative_path(root, path).is_some_and(|path| {
        path.split('/')
            .any(|part| part.eq_ignore_ascii_case(".git"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_relative_path_normalizes_an_absolute_in_root_path() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("src/app.rs");
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, "fn main() {}\n").unwrap();
        assert_eq!(
            canonical_relative_path(dir.path(), file.to_str().unwrap()),
            Some("src/app.rs".to_string())
        );
    }

    #[test]
    fn git_control_paths_are_detected_after_resolution() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".git")).unwrap();
        std::fs::write(dir.path().join(".git/config"), "[core]\n").unwrap();
        assert!(is_git_control_path(dir.path(), ".git/config"));
        assert!(is_git_control_path(dir.path(), "./.git/config"));
        assert!(!is_git_control_path(dir.path(), "src/.gitignore"));
    }

    #[cfg(unix)]
    #[test]
    fn git_control_paths_are_detected_through_an_in_repo_symlink() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".git")).unwrap();
        std::fs::write(dir.path().join(".git/config"), "[core]\n").unwrap();
        symlink(dir.path().join(".git"), dir.path().join("metadata")).unwrap();
        assert!(is_git_control_path(dir.path(), "metadata/config"));
    }
}
