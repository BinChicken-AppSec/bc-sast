//! The `Read` tool, ported from `backends/localtools.py`'s `_read`.

use std::io::Read as _;
use std::path::Path;

const MAX_CHARS: usize = 200_000;
/// Safety bound on the raw bytes pulled off disk before decoding/slicing,
/// independent of `offset`/`limit` — a caller asking for line 5 of a 2GB
/// file shouldn't buffer the whole thing first.
const MAX_READ_BYTES: u64 = (MAX_CHARS * 4) as u64;

pub fn read(root: &Path, path: &str, offset: i64, limit: i64) -> String {
    let Some(resolved) = bc_pathjail::confine(root, path) else {
        return format!("ERROR: path '{path}' is outside the repository root");
    };
    if !resolved.is_file() {
        return format!("ERROR: file not found: {path}");
    }
    let buf = match open_and_read(&resolved) {
        Ok(buf) => buf,
        Err(e) => return format!("ERROR: cannot read {path}: {e}"),
    };
    let text = String::from_utf8_lossy(&buf);
    let lines: Vec<&str> = text.lines().collect();

    let start = offset.max(0) as usize;
    let span = limit.max(1) as usize;
    let mut body = String::new();
    for (i, line) in lines.iter().enumerate().skip(start).take(span) {
        if !body.is_empty() {
            body.push('\n');
        }
        body.push_str(&format!("{}\t{line}", i + 1));
    }

    if body.chars().count() > MAX_CHARS {
        let truncated: String = body.chars().take(MAX_CHARS).collect();
        body = format!("{truncated}\n... [truncated]");
    }
    if body.is_empty() {
        body = "(file is empty or offset past EOF)".to_string();
    }
    body
}

fn open_and_read(resolved: &Path) -> std::io::Result<Vec<u8>> {
    let file = std::fs::File::open(resolved)?;
    read_bounded(file)
}

/// Split out from [`open_and_read`] so a read failure mid-stream (as
/// opposed to `File::open` itself failing) is directly testable against a
/// mock reader — a real file that opens successfully but then errors on
/// `read()` isn't something a portable, deterministic test can construct.
fn read_bounded(mut source: impl std::io::Read) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    source.by_ref().take(MAX_READ_BYTES).read_to_end(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_numbered_lines() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "one\ntwo\nthree\n").unwrap();
        assert_eq!(
            read(dir.path(), "a.txt", 0, 2000),
            "1\tone\n2\ttwo\n3\tthree"
        );
    }

    #[test]
    fn respects_offset_and_limit() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "one\ntwo\nthree\nfour\n").unwrap();
        assert_eq!(read(dir.path(), "a.txt", 1, 2), "2\ttwo\n3\tthree");
    }

    #[test]
    fn negative_offset_clamps_to_zero() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "one\ntwo\n").unwrap();
        assert_eq!(read(dir.path(), "a.txt", -5, 2000), "1\tone\n2\ttwo");
    }

    #[test]
    fn non_positive_limit_still_returns_at_least_one_line() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "one\ntwo\n").unwrap();
        assert_eq!(read(dir.path(), "a.txt", 0, 0), "1\tone");
    }

    #[test]
    fn offset_past_eof_reports_empty() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "one\n").unwrap();
        assert_eq!(
            read(dir.path(), "a.txt", 50, 10),
            "(file is empty or offset past EOF)"
        );
    }

    #[test]
    fn missing_file_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            read(dir.path(), "missing.txt", 0, 10),
            "ERROR: file not found: missing.txt"
        );
    }

    #[test]
    fn escaping_the_root_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            read(dir.path(), "../outside.txt", 0, 10),
            "ERROR: path '../outside.txt' is outside the repository root"
        );
    }

    #[test]
    fn a_directory_is_not_a_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        assert_eq!(read(dir.path(), "sub", 0, 10), "ERROR: file not found: sub");
    }

    #[test]
    fn large_output_is_truncated() {
        let dir = tempfile::tempdir().unwrap();
        let content = "x".repeat(10) + "\n";
        let content = content.repeat(30_000); // well over MAX_CHARS once numbered
        std::fs::write(dir.path().join("big.txt"), &content).unwrap();
        let out = read(dir.path(), "big.txt", 0, 1_000_000);
        assert!(out.ends_with("... [truncated]"));
        assert!(out.chars().count() <= MAX_CHARS + "\n... [truncated]".chars().count());
    }

    #[test]
    fn invalid_utf8_bytes_are_replaced_not_fatal() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("bin.dat"), [0xff, 0xfe, b'\n']).unwrap();
        let out = read(dir.path(), "bin.dat", 0, 10);
        assert!(out.starts_with('1'));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unreadable_file_permissions_are_reported_as_an_io_error() {
        // `drop_caches` is a regular file nobody can open for reading. The
        // kernel checks a sysctl's mode bits itself, without the
        // CAP_DAC_OVERRIDE bypass a chmod 000 file gets, so the open fails
        // for root as well. Its directory stands in for the repository.
        let out = read(Path::new("/proc/sys/vm"), "drop_caches", 0, 10);
        assert!(
            out.starts_with("ERROR: cannot read drop_caches: Permission denied"),
            "unexpected: {out}"
        );
    }

    struct FailingReader;

    impl std::io::Read for FailingReader {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("disk exploded"))
        }
    }

    #[test]
    fn read_bounded_propagates_a_read_error() {
        let err = read_bounded(FailingReader).unwrap_err();
        assert_eq!(err.to_string(), "disk exploded");
    }
}
