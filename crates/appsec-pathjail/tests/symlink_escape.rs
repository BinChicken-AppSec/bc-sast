#[cfg(unix)]
#[test]
fn confine_rejects_symlink_that_resolves_outside_root() {
    use std::os::unix::fs::symlink;

    let root_dir = tempfile::tempdir().unwrap();
    let outside_dir = tempfile::tempdir().unwrap();
    let secret = outside_dir.path().join("secret.txt");
    std::fs::write(&secret, b"top secret").unwrap();

    let link = root_dir.path().join("escape-link");
    symlink(&secret, &link).unwrap();

    assert!(
        appsec_pathjail::confine(root_dir.path(), "escape-link").is_none(),
        "a symlink resolving outside root must be rejected"
    );
}

#[cfg(unix)]
#[test]
fn confine_rejects_symlink_then_dotdot_escape() {
    use std::os::unix::fs::symlink;

    let root_dir = tempfile::tempdir().unwrap();
    let outside_dir = tempfile::tempdir().unwrap();
    let link = root_dir.path().join("evil_symlink");
    symlink(outside_dir.path(), &link).unwrap();

    if let Some(resolved) = appsec_pathjail::confine(root_dir.path(), "evil_symlink/../a.txt") {
        assert!(
            resolved.starts_with(root_dir.path().canonicalize().unwrap()),
            "resolved {resolved:?} escaped root via symlink+.. traversal"
        );
    }
}

#[cfg(unix)]
#[test]
fn confine_allows_symlink_that_resolves_inside_root() {
    use std::os::unix::fs::symlink;

    let root_dir = tempfile::tempdir().unwrap();
    let real = root_dir.path().join("real.txt");
    std::fs::write(&real, b"fine").unwrap();
    let link = root_dir.path().join("inside-link");
    symlink(&real, &link).unwrap();

    let got = appsec_pathjail::confine(root_dir.path(), "inside-link");
    assert_eq!(got, Some(real.canonicalize().unwrap()));
}
