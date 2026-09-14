//! `--estimate`: a rough, no-network, no-LLM-call scope preview. Ported
//! from `cli.py::_estimate` (`cli.py:59-94`) — walks `--repo`, counts files
//! matching a fixed source-code extension set, sums their bytes, and
//! divides by 4 for a crude token estimate. Deliberately does NOT compute a
//! dollar figure (Python's own design choice — cost is model-dependent,
//! this only projects scope) and makes no API calls of any kind.

use std::path::Path;

/// Python's own fixed extension allowlist (`cli.py:75-77`), transcribed
/// verbatim — NOT `bc_repo_analysis::lang::EXT_TO_LANG` (132 entries),
/// which would change the file/byte counts and break parity with this
/// command's "rough scope preview" contract.
const ESTIMATE_EXTENSIONS: &[&str] = &[
    ".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".cs", ".c", ".cpp", ".h", ".kt", ".scala",
    ".rs", ".sql", ".yaml", ".yml", ".json", ".tf", ".sh",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EstimateSummary {
    pub files: i64,
    pub bytes: i64,
}

impl EstimateSummary {
    pub fn approx_tokens(&self) -> i64 {
        self.bytes / 4
    }
}

/// `1234567` -> `"1,234,567"` — a deliberate small duplicate of
/// `bc_report_md::metrics`'s own `with_commas` (that one is crate-private
/// to `bc-report-md`; pulling in a whole rendering crate for one helper
/// isn't worth it here). `pub(crate)` since `progress.rs`'s token-spend
/// display reuses this exact copy rather than growing a third one within
/// the same crate.
pub(crate) fn with_commas(n: i64) -> String {
    let (sign, digits) = if n < 0 {
        ("-", n.unsigned_abs().to_string())
    } else {
        ("", n.to_string())
    };
    let mut grouped = String::new();
    for (i, c) in digits.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            grouped.push(',');
        }
        grouped.push(c);
    }
    format!("{sign}{}", grouped.chars().rev().collect::<String>())
}

fn has_estimate_extension(path: &Path) -> bool {
    let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
        return false;
    };
    let dotted = format!(".{}", ext.to_ascii_lowercase());
    ESTIMATE_EXTENSIONS.contains(&dotted.as_str())
}

/// Recursively walks `repo`, tallying files/bytes for every file whose
/// extension is in [`ESTIMATE_EXTENSIONS`]. Unreadable individual entries
/// (a permission error, a broken symlink) are silently skipped — matching
/// Python's own tolerant `except OSError: continue` per-file handling
/// (`cli.py:82-84`); this is a rough preview, not a scan, so one bad file
/// shouldn't abort it.
fn walk_and_tally(repo: &Path) -> EstimateSummary {
    let mut files = 0i64;
    let mut bytes = 0i64;
    let mut stack = vec![repo.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_dir() {
                stack.push(path);
            } else if file_type.is_file() && has_estimate_extension(&path) {
                if let Ok(metadata) = entry.metadata() {
                    files += 1;
                    bytes += metadata.len() as i64;
                }
            }
        }
    }
    EstimateSummary { files, bytes }
}

/// `Err` mirrors Python's exit-2 (missing `--repo`, checked upstream by
/// clap's own `required_unless_present`) and exit-1 (`--repo` doesn't
/// exist) cases — the caller surfaces this the same way any other
/// `main_impl` error is surfaced.
pub fn run_estimate(repo: &Path) -> Result<EstimateSummary, String> {
    if !repo.exists() {
        return Err(format!("{}: path does not exist", repo.display()));
    }
    Ok(walk_and_tally(repo))
}

impl std::fmt::Display for EstimateSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "scope estimate\n  code files       : {}\n  bytes            : {}\n  ~input tokens    : \
             {} (rough, bytes/4)\n  note: the pipeline reads each file across several stages; \
             expect\n  total token usage to be a multiple of the above. Cost depends on\n  the \
             model in config.yaml. Use --stop-after s3 for an exact scope.",
            with_commas(self.files),
            with_commas(self.bytes),
            with_commas(self.approx_tokens())
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn write(dir: &Path, rel: &str, contents: &[u8]) {
        let p = dir.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(p, contents).unwrap();
    }

    #[test]
    fn missing_repo_path_is_an_error() {
        let err = run_estimate(Path::new("/nonexistent/repo/path")).unwrap_err();
        assert!(err.contains("path does not exist"));
    }

    #[test]
    fn counts_only_files_with_recognized_extensions() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "main.py", b"1234");
        write(dir.path(), "README.md", b"ignored entirely");
        write(dir.path(), "image.png", b"ignored entirely too");
        let summary = run_estimate(dir.path()).unwrap();
        assert_eq!(summary.files, 1);
        assert_eq!(summary.bytes, 4);
    }

    #[test]
    fn walks_nested_directories() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.rs", b"12345678");
        write(dir.path(), "sub/b.ts", b"1234");
        write(dir.path(), "sub/deeper/c.go", b"12");
        let summary = run_estimate(dir.path()).unwrap();
        assert_eq!(summary.files, 3);
        assert_eq!(summary.bytes, 14);
    }

    #[test]
    fn extension_matching_is_case_insensitive() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "Main.PY", b"123");
        let summary = run_estimate(dir.path()).unwrap();
        assert_eq!(summary.files, 1);
    }

    #[test]
    fn a_file_with_no_extension_at_all_is_skipped() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "Makefile", b"123");
        let summary = run_estimate(dir.path()).unwrap();
        assert_eq!(summary.files, 0);
    }

    #[test]
    fn empty_repo_yields_zero_counts() {
        let dir = tempfile::tempdir().unwrap();
        let summary = run_estimate(dir.path()).unwrap();
        assert_eq!(summary.files, 0);
        assert_eq!(summary.bytes, 0);
    }

    #[test]
    fn approx_tokens_is_bytes_divided_by_four() {
        let s = EstimateSummary {
            files: 1,
            bytes: 4001,
        };
        assert_eq!(s.approx_tokens(), 1000);
    }

    #[test]
    fn display_renders_every_line_with_thousands_separators() {
        let s = EstimateSummary {
            files: 1500,
            bytes: 4_000_000,
        };
        let text = s.to_string();
        assert!(text.contains("scope estimate"));
        assert!(text.contains("code files       : 1,500"));
        assert!(text.contains("bytes            : 4,000,000"));
        assert!(text.contains("~input tokens    : 1,000,000 (rough, bytes/4)"));
        assert!(text.contains("--stop-after s3"));
    }

    #[rstest]
    #[case(0, "0")]
    #[case(999, "999")]
    #[case(1000, "1,000")]
    #[case(1234567, "1,234,567")]
    #[case(-1234, "-1,234")]
    fn with_commas_cases(#[case] n: i64, #[case] expected: &str) {
        assert_eq!(with_commas(n), expected);
    }

    #[test]
    fn a_repo_path_that_is_a_plain_file_not_a_directory_yields_zero_counts() {
        // `run_estimate` only checks `repo.exists()`, not `is_dir()` — a
        // file path passes that check, then `walk_and_tally`'s `read_dir`
        // call fails on it (not a directory), hitting the same tolerant
        // skip-and-continue path a permission error would.
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("not_a_directory.py");
        std::fs::write(&file_path, b"12345").unwrap();
        let summary = run_estimate(&file_path).unwrap();
        assert_eq!(summary.files, 0);
        assert_eq!(summary.bytes, 0);
    }
}
