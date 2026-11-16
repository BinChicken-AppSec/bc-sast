use std::io::Read;
use std::path::Path;

pub(crate) fn cap_text_with_total(txt: &str, cap_chars: usize, total: usize) -> String {
    if total > cap_chars {
        let kept: String = txt.chars().take(cap_chars).collect();
        format!("{kept}\n…(truncated, {total} chars total)")
    } else {
        txt.to_string()
    }
}

pub(crate) fn cap_text(txt: &str, cap_chars: usize) -> String {
    cap_text_with_total(txt, cap_chars, txt.chars().count())
}

pub(crate) fn read_contained(
    root: &Path,
    rel: &str,
    cap_chars: usize,
    whole_or_nothing: bool,
) -> String {
    let Some(path) = appsec_pathjail::confine(root, rel) else {
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
