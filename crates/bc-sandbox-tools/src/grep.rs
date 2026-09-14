//! The `Grep` tool, ported from `backends/localtools.py`'s `_grep`.

use std::path::{Path, PathBuf};

use regex::RegexBuilder;

use crate::walk::{glob_jailed_files, walk_jailed_files};

const MAX_MATCHES: usize = 200;
const MAX_CHARS: usize = 200_000;
/// Per-line ceiling for the regex scan. The pattern is model-supplied, so a
/// pathological line (e.g. a multi-KB minified blob) fed to a backtracking
/// regex could pin a worker thread. Bounding the chars the regex sees per
/// line caps that work; the cap is high enough that normal source lines
/// are unaffected.
const MAX_GREP_LINE: usize = 50_000;

#[allow(clippy::too_many_arguments)]
pub fn grep(
    root: &Path,
    pattern: &str,
    path: Option<&str>,
    glob_pattern: Option<&str>,
    ignore_case: bool,
    context: i64,
) -> String {
    let rx = match RegexBuilder::new(pattern)
        .case_insensitive(ignore_case)
        .build()
    {
        Ok(rx) => rx,
        Err(e) => return format!("ERROR: invalid regex '{pattern}': {e}"),
    };

    let files = match resolve_files(root, path, glob_pattern) {
        Ok(files) => files,
        Err(message) => return message,
    };

    let ctx = context.clamp(0, 200) as usize;
    let mut out: Vec<String> = Vec::new();
    let mut matches = 0usize;

    for file in files {
        let Ok(text) = std::fs::read_to_string(&file) else {
            continue;
        };
        let text: String = if text.chars().count() > MAX_CHARS * 8 {
            text.chars().take(MAX_CHARS * 8).collect()
        } else {
            text
        };
        let lines: Vec<&str> = text.lines().collect();
        let Ok(rel) = file.strip_prefix(root) else {
            continue;
        };
        let rel = rel.to_string_lossy().replace('\\', "/");

        for (i, line) in lines.iter().enumerate() {
            let searchable: String = line.chars().take(MAX_GREP_LINE).collect();
            if !rx.is_match(&searchable) {
                continue;
            }
            if ctx > 0 {
                let lo = i.saturating_sub(ctx);
                let hi = (i + ctx + 1).min(lines.len());
                for (j, ctx_line) in lines.iter().enumerate().take(hi).skip(lo) {
                    let mark = if j == i { ':' } else { '-' };
                    out.push(format!("{rel}:{}{mark}{}", j + 1, clip(ctx_line)));
                }
                out.push("--".to_string());
            } else {
                out.push(format!("{rel}:{}:{}", i + 1, clip(line)));
            }
            matches += 1;
            if matches >= MAX_MATCHES {
                out.push(format!("... (stopped at {MAX_MATCHES} matches)"));
                return out.join("\n");
            }
        }
    }

    if out.is_empty() {
        "No matches found".to_string()
    } else {
        out.join("\n")
    }
}

fn resolve_files(
    root: &Path,
    path: Option<&str>,
    glob_pattern: Option<&str>,
) -> Result<Vec<PathBuf>, String> {
    if let Some(p) = path {
        // `confine` is used purely as the security gate here (does `p`
        // escape `root`?) — its *canonicalized* return value is
        // deliberately discarded in favor of the natural, un-canonicalized
        // `root`-prefixed path, so the result stays comparable via
        // `strip_prefix(root)` against `root` exactly as passed in (`walk`/
        // `glob` already preserve paths this way; using `confine`'s
        // resolved path here instead would silently break that whenever
        // `root` itself needs symlink resolution, e.g. macOS's `/tmp` ->
        // `/private/tmp`).
        if bc_pathjail::confine(root, p).is_none() {
            return Err(format!("ERROR: path '{p}' is outside the repository root"));
        }
        let natural = if Path::new(p).is_absolute() {
            PathBuf::from(p)
        } else {
            root.join(p)
        };
        return Ok(if natural.is_file() {
            vec![natural]
        } else {
            walk_jailed_files(root, &natural)
        });
    }
    if let Some(g) = glob_pattern {
        return Ok(glob_jailed_files(root, g));
    }
    Ok(walk_jailed_files(root, root))
}

fn clip(line: &str) -> String {
    if line.chars().count() <= MAX_GREP_LINE {
        line.to_string()
    } else {
        let head: String = line.chars().take(MAX_GREP_LINE).collect();
        format!("{head} …[line clipped]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, rel: &str, contents: &str) {
        let path = dir.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }

    #[test]
    fn finds_matches_across_the_whole_repo() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.txt", "hello\nworld\n");
        write(dir.path(), "sub/b.txt", "goodbye\n");
        assert_eq!(
            grep(dir.path(), "hello", None, None, false, 0),
            "a.txt:1:hello"
        );
    }

    #[test]
    fn no_matches_is_reported_explicitly() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.txt", "hello\n");
        assert_eq!(
            grep(dir.path(), "nomatch", None, None, false, 0),
            "No matches found"
        );
    }

    #[test]
    fn invalid_regex_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let err = grep(dir.path(), "(unclosed", None, None, false, 0);
        assert!(err.starts_with("ERROR: invalid regex"));
    }

    #[test]
    fn ignore_case_matches_regardless_of_case() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.txt", "HELLO\n");
        assert_eq!(
            grep(dir.path(), "hello", None, None, true, 0),
            "a.txt:1:HELLO"
        );
        assert_eq!(
            grep(dir.path(), "hello", None, None, false, 0),
            "No matches found"
        );
    }

    #[test]
    fn restricting_to_a_single_file_via_path() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.txt", "needle\n");
        write(dir.path(), "b.txt", "needle\n");
        assert_eq!(
            grep(dir.path(), "needle", Some("a.txt"), None, false, 0),
            "a.txt:1:needle"
        );
    }

    #[test]
    fn restricting_to_a_directory_via_path_walks_it_recursively() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "sub/a.txt", "needle\n");
        write(dir.path(), "other.txt", "needle\n");
        assert_eq!(
            grep(dir.path(), "needle", Some("sub"), None, false, 0),
            "sub/a.txt:1:needle"
        );
    }

    #[test]
    fn path_outside_the_root_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let err = grep(dir.path(), "x", Some("../outside"), None, false, 0);
        assert_eq!(
            err,
            "ERROR: path '../outside' is outside the repository root"
        );
    }

    #[cfg(unix)]
    #[test]
    fn an_absolute_path_arg_restricts_to_that_file() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.txt", "needle\n");
        // Pass `root` in its own canonical form (mirroring
        // `SandboxTools::new`, which resolves `root` up front) so it
        // shares a literal prefix with the canonical absolute `path` arg
        // regardless of whether this OS's temp dir itself needs symlink
        // resolution (e.g. macOS's `/tmp` -> `/private/tmp`).
        let canonical_root = dir.path().canonicalize().unwrap();
        let absolute = canonical_root.join("a.txt");
        assert_eq!(
            grep(
                &canonical_root,
                "needle",
                Some(absolute.to_str().unwrap()),
                None,
                false,
                0
            ),
            "a.txt:1:needle"
        );
    }

    #[cfg(unix)]
    #[test]
    fn an_absolute_path_arg_whose_literal_form_bypasses_roots_own_prefix_is_skipped() {
        // `root` is passed here in its *symlinked* form while the absolute
        // `path` argument resolves through the real (non-symlinked)
        // target — `confine` canonicalizes both sides and accepts it (it
        // genuinely IS inside root), but the file's literal path can no
        // longer be stripped of `root`'s literal (symlinked) prefix. This
        // is the same class of mismatch as macOS's `/tmp` ->
        // `/private/tmp`, reproduced portably with a symlink this test
        // controls instead of relying on that OS-specific detail.
        let base = tempfile::tempdir().unwrap();
        let real_root = base.path().join("real_root");
        std::fs::create_dir(&real_root).unwrap();
        write(&real_root, "a.txt", "needle\n");
        let link_root = base.path().join("link_root");
        std::os::unix::fs::symlink(&real_root, &link_root).unwrap();

        let absolute_real_path = real_root.canonicalize().unwrap().join("a.txt");
        let out = grep(
            &link_root,
            "needle",
            Some(absolute_real_path.to_str().unwrap()),
            None,
            false,
            0,
        );
        assert_eq!(out, "No matches found");
    }

    #[test]
    fn restricting_via_glob() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.rs", "needle\n");
        write(dir.path(), "a.txt", "needle\n");
        assert_eq!(
            grep(dir.path(), "needle", None, Some("*.rs"), false, 0),
            "a.rs:1:needle"
        );
    }

    #[test]
    fn context_lines_are_included_with_a_separator() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.txt", "one\ntwo\nneedle\nfour\nfive\n");
        let out = grep(dir.path(), "needle", None, None, false, 1);
        assert_eq!(out, "a.txt:2-two\na.txt:3:needle\na.txt:4-four\n--");
    }

    #[test]
    fn context_is_clamped_to_200() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.txt", "needle\n");
        // A negative context must not underflow/panic; clamps to 0.
        let out = grep(dir.path(), "needle", None, None, false, -5);
        assert_eq!(out, "a.txt:1:needle");
    }

    #[test]
    fn matches_are_capped() {
        let dir = tempfile::tempdir().unwrap();
        let content = "needle\n".repeat(MAX_MATCHES + 5);
        write(dir.path(), "a.txt", &content);
        let out = grep(dir.path(), "needle", None, None, false, 0);
        assert!(out.ends_with(&format!("... (stopped at {MAX_MATCHES} matches)")));
        assert_eq!(out.lines().count(), MAX_MATCHES + 1);
    }

    #[test]
    fn a_very_long_line_is_clipped_in_the_output() {
        let dir = tempfile::tempdir().unwrap();
        let long_line = format!("needle{}", "x".repeat(MAX_GREP_LINE + 10));
        write(dir.path(), "a.txt", &long_line);
        let out = grep(dir.path(), "needle", None, None, false, 0);
        assert!(out.ends_with("…[line clipped]"));
    }

    #[test]
    fn a_file_far_larger_than_the_whole_file_bound_is_truncated_before_scanning() {
        let dir = tempfile::tempdir().unwrap();
        // One giant single line, well over MAX_CHARS * 8, with the needle
        // placed past that cutoff -- if the whole-file truncation didn't
        // happen, this would still match.
        let padding = "x".repeat(MAX_CHARS * 8 + 100);
        write(dir.path(), "big.txt", &format!("{padding}needle\n"));
        assert_eq!(
            grep(dir.path(), "needle", None, None, false, 0),
            "No matches found"
        );
    }

    #[test]
    fn a_file_that_cannot_be_read_as_utf8_is_skipped_not_fatal() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("bin.dat"), [0xff, 0xfe]).unwrap();
        write(dir.path(), "a.txt", "needle\n");
        assert_eq!(
            grep(dir.path(), "needle", None, None, false, 0),
            "a.txt:1:needle"
        );
    }
}
