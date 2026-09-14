//! Shared path-safety primitives.
//!
//! Every path that originates from an LLM, a config file, a plugin, or any
//! other untrusted source must be confined to a known root before it is
//! read, globbed, or used to build a `git` pathspec. Two independent
//! failure modes are guarded against here:
//!
//! - **Escape**: `..`, an absolute path, or a symlink that resolves outside
//!   the root — [`confine`] and [`is_within`] reject these (CWE-22).
//! - **SMB/UNC redirection**: on Windows, merely *touching* a
//!   `\\host\share\...` path triggers an SMB handshake that leaks the
//!   caller's NTLMv2 hash to the (possibly attacker-controlled) host —
//!   [`is_network_path`] rejects these *before* any filesystem access, and
//!   is evaluated identically regardless of the host OS, so a POSIX CI
//!   runner still blocks a Windows-style UNC path before it ever reaches a
//!   `git` pathspec or a file read.

use std::path::{Path, PathBuf};

/// True if `path` is a UNC / network location (`\\host\share` or
/// `//host/share`), including extended-length UNC device paths
/// (`\\?\UNC\host\share\...`) and admin shares by IP (`\\1.2.3.4\c$\...`).
///
/// Every real UNC spelling begins with two consecutive path separators
/// (backslash or forward slash) — Windows will not perform SMB redirection
/// for anything else — so a simple prefix check is both necessary and
/// sufficient, and (crucially) doesn't require Windows-specific path
/// parsing to be correct on every host OS.
pub fn is_network_path(path: &str) -> bool {
    let s = path.trim();
    s.starts_with(r"\\") || s.starts_with("//")
}

/// Resolve `candidate` (relative to `root` if it isn't already absolute)
/// and confine it to `root`. Returns `None` if the candidate escapes `root`
/// via `..`, an absolute-path override, or a symlink, or is itself a
/// network (UNC/`\\host\share`) path — the caller should treat `None` as
/// "inaccessible", never fall back to using the unconfined path. The
/// network-path check runs before any filesystem touch (including the
/// `canonicalize()` calls below), since merely *resolving* such a path
/// would trigger Windows' SMB handshake and leak the caller's NTLMv2 hash
/// to a malicious host.
///
/// `root` itself is resolved (not merely trusted as already-canonical), so
/// callers may pass an un-canonicalized root safely.
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

/// True if `candidate` resolves to a location inside (or equal to) `root`.
/// The inverse-flavoured sibling of [`confine`], used by the config
/// trust-gate to ask "does this file live inside the scan target?" without
/// needing the caller to join a relative fragment first. A network
/// (UNC/`\\host\share`) `candidate` is always `false`, checked before any
/// filesystem touch for the same reason [`confine`] checks it first.
pub fn is_within(root: &Path, candidate: &Path) -> bool {
    if is_network_path(&candidate.to_string_lossy()) {
        return false;
    }
    match (resolve_best_effort(root), resolve_best_effort(candidate)) {
        (Some(r), Some(c)) => c.starts_with(&r),
        _ => false,
    }
}

/// Best-effort canonicalization that also works for paths whose final
/// component(s) don't exist yet. Walks the path component-by-component
/// from the front: while each component still exists on disk, it is
/// resolved with a real `canonicalize()` call (so a symlink component is
/// followed exactly like the OS would); the moment a component is missing,
/// every remaining component (including any further `..`) is applied
/// lexically instead, since there is no real filesystem entity left to
/// resolve. This ordering matters for correctness, not just existence: a
/// naive whole-path lexical normalization (collapsing `a/../b` before
/// checking `a` on disk) would be exploitable when `a` is a symlink to
/// somewhere else — `..` after a resolved symlink must go to *that
/// target's* parent, not lexically cancel the symlink out.
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

    // Every spelling of "go off-box" that Windows would dial over SMB —
    // ported from tests/test_unc_path_guard.py::NETWORK_PATHS.
    #[rstest]
    #[case(r"\\attacker\share\x.yaml")]
    #[case("//attacker/share/x.yaml")]
    #[case(r"\\?\UNC\attacker\share\x")]
    #[case(r"\\127.0.0.1\c$\x.yaml")]
    fn network_paths_are_detected(#[case] p: &str) {
        assert!(is_network_path(p), "{p:?} should be a network path");
    }

    // Paths that must keep working — ported from
    // tests/test_unc_path_guard.py::LOCAL_PATHS.
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
        // "a/../a.txt" never leaves root, so this must be ALLOWED —
        // the guard cares about the final resolved location, not whether
        // ".." appeared in the input.
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
        // An empty path has no components at all, so the fallback walk in
        // resolve_best_effort never accumulates anything and returns None —
        // exercises the `_ => false` arm (as opposed to the Some/Some
        // starts_with comparison the other is_within tests exercise).
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
        // `Path::components()` only preserves a "." as a real CurDir
        // component when it's the very first thing in the path — once
        // joined onto an absolute root it gets normalized away, so this
        // arm is only reachable by calling the (crate-private) resolver
        // directly with a leading-"./" relative path.
        let got = resolve_best_effort(Path::new("./bc-pathjail-does-not-exist-xyz"));
        assert_eq!(got, Some(PathBuf::from("bc-pathjail-does-not-exist-xyz")));
    }

    #[test]
    fn is_within_false_when_root_does_not_exist() {
        let missing = std::env::temp_dir().join("bc-pathjail-does-not-exist-xyz");
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
