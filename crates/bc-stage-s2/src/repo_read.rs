//! The single chokepoint for every on-disk read S2 performs, ported from
//! upstream v1.4.0 `s2_threatmodel.py::_contained`/`_read_capped`/
//! `_cap_text`: containment-checked, then length-capped.
//!
//! Containment goes through [`bc_pathjail::confine`], which resolves the
//! candidate (following symlinks the way the OS would) and refuses anything
//! that lands outside the repository root. A symlink committed to an
//! untrusted clone therefore cannot pull a host file into the prompt.
//!
//! **Bounded reads, a deliberate divergence.** Upstream reads the whole
//! file and then slices. Here at most `4 * cap + 4` bytes are ever read: a
//! UTF-8 character is at most four bytes, so a file longer than that is
//! certainly longer than `cap` characters, and a multi-gigabyte blob in the
//! repository can no longer be pulled into memory just to be cut down.
//! The one visible consequence is the truncation notice's total, which is
//! the file's byte length (not its character count) when the read stopped
//! at that bound; for the ASCII that dominates docs and manifests the two
//! are equal.

use std::io::Read;
use std::path::Path;

/// Cut `txt` to `cap_chars` characters, appending upstream's notice naming
/// the total so the model knows content was removed. `total` is the full
/// length to report (see the module docs for when it is a byte count).
pub(crate) fn cap_text_with_total(txt: &str, cap_chars: usize, total: usize) -> String {
    if total > cap_chars {
        let kept: String = txt.chars().take(cap_chars).collect();
        format!("{kept}\n…(truncated, {total} chars total)")
    } else {
        txt.to_string()
    }
}

/// [`cap_text_with_total`] for text already fully in memory.
pub(crate) fn cap_text(txt: &str, cap_chars: usize) -> String {
    cap_text_with_total(txt, cap_chars, txt.chars().count())
}

/// Read `rel` (relative to `root`) through the containment check, capped
/// at `cap_chars`. `""` when the path escapes the root, does not exist, is
/// not a readable file, or (with `whole_or_nothing`) is longer than
/// `cap_chars`: a caller that redacts the result must never receive a
/// truncated prefix, since a cut can bisect a secret so that its surviving
/// half matches no redaction pattern.
pub(crate) fn read_contained(
    root: &Path,
    rel: &str,
    cap_chars: usize,
    whole_or_nothing: bool,
) -> String {
    let Some(path) = bc_pathjail::confine(root, rel) else {
        // The guard working as designed: off-root content is something this
        // stage must never deliver into a prompt, so its absence is policy,
        // not loss.
        tracing::debug!("[s2] refused to read outside the repository root: {rel:?}");
        return String::new();
    };
    let Ok(file) = std::fs::File::open(&path) else {
        return String::new();
    };
    let byte_len = file.metadata().map(|m| m.len()).unwrap_or(0);
    let limit = (cap_chars as u64).saturating_mul(4).saturating_add(4);
    let mut bytes = Vec::new();
    if file.take(limit).read_to_end(&mut bytes).is_err() {
        return String::new();
    }
    let txt = String::from_utf8_lossy(&bytes);
    let complete = (bytes.len() as u64) < limit;
    let total = if complete {
        txt.chars().count()
    } else {
        usize::try_from(byte_len).unwrap_or(usize::MAX)
    };
    if whole_or_nothing && total > cap_chars {
        return String::new();
    }
    cap_text_with_total(&txt, cap_chars, total)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, rel: &str, contents: &[u8]) {
        let path = dir.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }

    #[test]
    fn cap_text_appends_the_total_only_when_cutting() {
        assert_eq!(cap_text("abc", 3), "abc");
        assert_eq!(cap_text("abcdef", 2), "ab\n…(truncated, 6 chars total)");
        assert_eq!(cap_text("abc", 0), "\n…(truncated, 3 chars total)");
    }

    #[test]
    fn a_small_file_is_read_whole() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a/b.txt", "héllo".as_bytes());
        assert_eq!(read_contained(dir.path(), "a/b.txt", 100, false), "héllo");
        assert_eq!(read_contained(dir.path(), "a/b.txt", 100, true), "héllo");
    }

    #[test]
    fn a_long_file_is_capped_or_refused_whole() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "f.txt", b"0123456789");
        assert_eq!(
            read_contained(dir.path(), "f.txt", 4, false),
            "0123\n…(truncated, 10 chars total)"
        );
        assert_eq!(read_contained(dir.path(), "f.txt", 4, true), "");
    }

    #[test]
    fn a_file_past_the_byte_bound_reports_its_byte_length() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "big.txt", &[b'x'; 100]);
        // cap 2: at most 12 bytes are read, so the total comes from the
        // file's metadata rather than a full read.
        assert_eq!(
            read_contained(dir.path(), "big.txt", 2, false),
            "xx\n…(truncated, 100 chars total)"
        );
        assert_eq!(read_contained(dir.path(), "big.txt", 2, true), "");
    }

    #[test]
    fn missing_paths_directories_and_escapes_read_as_empty() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        assert_eq!(read_contained(dir.path(), "nope.txt", 10, false), "");
        assert_eq!(read_contained(dir.path(), "sub", 10, false), "");
        assert_eq!(read_contained(dir.path(), "../x", 10, false), "");
        assert_eq!(read_contained(dir.path(), "", 10, false), "");
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_resolving_outside_the_repo_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        write(outside.path(), "secret.txt", b"host secret");
        std::os::unix::fs::symlink(
            outside.path().join("secret.txt"),
            dir.path().join("README.md"),
        )
        .unwrap();
        assert_eq!(read_contained(dir.path(), "README.md", 100, false), "");
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_resolving_inside_the_repo_is_followed() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "docs/real.md", b"inside");
        std::os::unix::fs::symlink(
            dir.path().join("docs/real.md"),
            dir.path().join("README.md"),
        )
        .unwrap();
        assert_eq!(
            read_contained(dir.path(), "README.md", 100, false),
            "inside"
        );
    }
}
