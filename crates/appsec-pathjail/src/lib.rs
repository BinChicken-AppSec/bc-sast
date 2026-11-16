use std::path::{Path, PathBuf};

pub fn is_network_path(path: &str) -> bool {
    let s = path.trim();
    s.starts_with(r"\\") || s.starts_with("//")
}

pub fn confine(root: &Path, candidate: &str) -> Option<PathBuf> {
    if candidate.is_empty() || is_network_path(candidate) {
        return None;
    }
    let candidate_path = Path::new(candidate);
    let joined = if candidate_path.is_absolute() {
        candidate_path.to_path_buf()
    } else {
        root.join(candidate_path)
    };
    let resolved = resolve_best_effort(&joined)?;
    let root_resolved = resolve_best_effort(root)?;
    if resolved.starts_with(&root_resolved) {
        Some(resolved)
    } else {
        None
    }
}

pub fn is_within(root: &Path, candidate: &Path) -> bool {
    if is_network_path(&candidate.to_string_lossy()) {
        return false;
    }
    match (resolve_best_effort(root), resolve_best_effort(candidate)) {
        (Some(r), Some(c)) => c.starts_with(&r),
        _ => false,
    }
}

fn resolve_best_effort(path: &Path) -> Option<PathBuf> {
    if let Ok(p) = path.canonicalize() {
        return Some(p);
    }
    use std::path::Component;

    let mut current = PathBuf::new();
    let mut missing = false;
    for comp in path.components() {
        match comp {
            Component::Prefix(_) | Component::RootDir => current.push(comp.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                current.pop();
            }
            Component::Normal(name) => {
                if missing {
                    current.push(name);
                    continue;
                }
                let candidate = current.join(name);
                match candidate.canonicalize() {
                    Ok(resolved) => current = resolved,
                    Err(_) => {
                        missing = true;
                        current.push(name);
                    }
                }
            }
        }
    }
    if current.as_os_str().is_empty() {
        return None;
    }
    Some(current)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(r"\\attacker\share\x.yaml")]
    #[case("//attacker/share/x.yaml")]
    #[case(r"\\?\UNC\attacker\share\x")]
    #[case(r"\\127.0.0.1\c$\x.yaml")]
    fn network_paths_are_detected(#[case] p: &str) {
        assert!(is_network_path(p), "{p:?} should be a network path");
    }

    #[rstest]
    #[case(r"C:\Users\me\step1.yaml")]
    #[case("step1.yaml")]
    #[case("./inputs/known_cves.json")]
    #[case("/home/me/step1.yaml")]
    fn local_paths_are_not_network_paths(#[case] p: &str) {
        assert!(!is_network_path(p), "{p:?} should not be a network path");
    }

    #[test]
    fn network_path_with_surrounding_whitespace_is_still_detected() {
        assert!(is_network_path("  \\\\attacker\\share\\x  "));
    }

    #[test]
    fn empty_string_is_not_a_network_path() {
        assert!(!is_network_path(""));
    }

    #[test]
    fn confine_rejects_empty_candidate() {
        let root = std::env::temp_dir();
        assert!(confine(&root, "").is_none());
    }

    #[test]
    fn confine_rejects_a_network_path_candidate() {
        let root = std::env::temp_dir();
        assert!(confine(&root, r"\\attacker\share\x.yaml").is_none());
    }

    #[test]
    fn confine_allows_plain_relative_path_inside_root() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), b"hi").unwrap();
        let got = confine(dir.path(), "a.txt").unwrap();
        assert_eq!(got, dir.path().canonicalize().unwrap().join("a.txt"));
    }

    #[test]
    fn confine_allows_nested_relative_path_that_does_not_exist_yet() {
        let dir = tempfile::tempdir().unwrap();
        let got = confine(dir.path(), "nested/does-not-exist.txt").unwrap();
        assert_eq!(
            got,
            dir.path()
                .canonicalize()
                .unwrap()
                .join("nested")
                .join("does-not-exist.txt")
        );
    }

    #[test]
    fn confine_rejects_dotdot_traversal_out_of_root() {
        let dir = tempfile::tempdir().unwrap();
        assert!(confine(dir.path(), "../escape.txt").is_none());
    }

    #[test]
    fn confine_rejects_dotdot_traversal_even_when_it_lands_back_inside() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), b"hi").unwrap();
        let got = confine(dir.path(), "sub/../a.txt");
        assert_eq!(got, Some(dir.path().canonicalize().unwrap().join("a.txt")));
    }

    #[test]
    fn confine_rejects_absolute_path_override() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let abs = outside.path().join("secret.txt");
        std::fs::write(&abs, b"nope").unwrap();
        assert!(confine(dir.path(), abs.to_str().unwrap()).is_none());
    }

    #[test]
    fn confine_allows_root_itself() {
        let dir = tempfile::tempdir().unwrap();
        let got = confine(dir.path(), ".").unwrap();
        assert_eq!(got, dir.path().canonicalize().unwrap());
    }

    #[test]
    fn is_within_true_for_nested_path() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a").join("b.txt");
        assert!(is_within(dir.path(), &nested));
    }

    #[test]
    fn is_within_false_for_sibling_path() {
        let dir = tempfile::tempdir().unwrap();
        let sibling = tempfile::tempdir().unwrap();
        assert!(!is_within(dir.path(), sibling.path()));
    }

    #[test]
    fn is_within_false_for_a_network_path_candidate() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!is_within(
            dir.path(),
            Path::new(r"\\attacker\share\x.yaml")
        ));
    }

    #[test]
    fn is_within_false_for_unresolvable_root() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!is_within(Path::new(""), dir.path()));
    }

    #[test]
    fn confine_handles_nonexistent_nested_tail() {
        let dir = tempfile::tempdir().unwrap();
        let got = confine(dir.path(), "missing/x.txt").unwrap();
        assert_eq!(
            got,
            dir.path()
                .canonicalize()
                .unwrap()
                .join("missing")
                .join("x.txt")
        );
    }

    #[test]
    fn resolve_best_effort_handles_leading_curdir_component() {
        let got = resolve_best_effort(Path::new("./appsec-pathjail-does-not-exist-xyz"));
        assert_eq!(
            got,
            Some(PathBuf::from("appsec-pathjail-does-not-exist-xyz"))
        );
    }

    #[test]
    fn is_within_false_when_root_does_not_exist() {
        let missing = std::env::temp_dir().join("appsec-pathjail-does-not-exist-xyz");
        let dir = tempfile::tempdir().unwrap();
        assert!(!is_within(&missing, dir.path()));
    }

    proptest::proptest! {
        #[test]
        fn confine_never_escapes_root(candidate in "[a-zA-Z0-9_./-]{0,64}") {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path().canonicalize().unwrap();
            if let Some(resolved) = confine(&root, &candidate) {
                proptest::prop_assert!(resolved.starts_with(&root));
            }
        }
    }
}
