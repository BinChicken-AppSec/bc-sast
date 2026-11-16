use std::path::{Component, Path};

pub(crate) fn canonical_relative_path(root: &Path, path: &str) -> Option<String> {
    if path != path.trim() {
        return None;
    }
    let resolved = appsec_pathjail::confine(root, path)?;
    let root = appsec_pathjail::confine(root, ".")?;
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
            Component::CurDir
            | Component::ParentDir
            | Component::RootDir
            | Component::Prefix(_) => None,
        })
        .collect::<Option<_>>()?;
    (!components.is_empty()).then(|| components.join("/"))
}

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
