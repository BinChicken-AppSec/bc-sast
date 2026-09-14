//! Symlink-escape regression test. This needs a real filesystem (symlink
//! creation + `canonicalize` following it), so it lives as an integration
//! test rather than inline — the one place `confine` genuinely needs real
//! syscalls; everything else about jail *rejection* is pure path
//! arithmetic and is covered by the unit tests in `src/lib.rs`.

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
        bc_pathjail::confine(root_dir.path(), "escape-link").is_none(),
        "a symlink resolving outside root must be rejected"
    );
}

#[cfg(unix)]
#[test]
fn confine_rejects_symlink_then_dotdot_escape() {
    // A path like "root/evil_symlink/../a.txt" where evil_symlink points
    // outside root must NOT be treated as if the ".." simply cancelled the
    // symlink lexically back to "root/a.txt" — real filesystem semantics
    // resolve the symlink first, so ".." lands in the symlink target's
    // parent, which is outside root. This is the classic naive
    // lexical-normalization bypass; confine must resolve component-by-
    // component instead.
    use std::os::unix::fs::symlink;

    let root_dir = tempfile::tempdir().unwrap();
    let outside_dir = tempfile::tempdir().unwrap();
    let link = root_dir.path().join("evil_symlink");
    symlink(outside_dir.path(), &link).unwrap();

    // Whatever this resolves to, it must stay confined to root — either
    // None (rejected) or a path that is still inside root. It must NEVER
    // silently resolve to something under outside_dir.
    if let Some(resolved) = bc_pathjail::confine(root_dir.path(), "evil_symlink/../a.txt") {
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

    let got = bc_pathjail::confine(root_dir.path(), "inside-link");
    assert_eq!(got, Some(real.canonicalize().unwrap()));
}
