//! Stable per-finding fingerprints, net-new versus the Python source
//! (which has no `partialFingerprints` at all — see the architecture
//! plan). Two schemes are emitted side by side, which is exactly what
//! `partialFingerprints` is for: a consumer matches on ANY key it
//! recognizes, so publishing both lets alerts already posted under v1
//! keep matching while new ones gain the more stable v2 identity.
//!
//! **v1** (`bc/findingId/v1`, [`finding_fingerprint`]) hashes `ruleId` +
//! normalized repo-relative path + the normalized `code_snippet`, omitting
//! the line number so a force-push that shifts lines doesn't mint a
//! duplicate alert.
//!
//! **v2** (`bc/findingId/v2`, [`finding_fingerprint_v2`]) fixes two real
//! sources of churn in v1, without breaking it:
//!
//! - v1's snippet comes from the MODEL, quoted back into its JSON reply.
//!   The same bug quoted as one line in one run and three in the next
//!   hashes differently, so a re-scan opens a fresh Code Scanning alert
//!   for a finding that was already triaged. v2 reads the region
//!   `line_start..=line_end` from the repo instead, so the input is the
//!   actual source, byte-identical across runs of the same commit.
//! - v1 keys on `ruleId` (the `vuln_class`), so a model that reclassifies
//!   the same defect (`injection` one run, `logic_flaw` the next) also
//!   mints a new alert. v2 leaves the class out: the identity of a finding
//!   is *where* it is, not what this run decided to call it.
//!
//! v2 is best-effort — it needs the repo on disk at the recorded lines, so
//! it is absent whenever the file can't be read or the range is out of
//! bounds (a stale `report.json` re-serialized elsewhere, a deleted file).
//! v1 is never dropped, and [`crate::finding_id`] still returns v1: it is
//! the within-run correlation key that `bc-stage-s10`'s remediation
//! checkpoints and the validation map are already keyed by.

use std::path::Path;

use bc_model::Finding;
use sha1::{Digest, Sha1};

pub const FINGERPRINT_KEY: &str = "bc/findingId/v1";
pub const FINGERPRINT_KEY_V2: &str = "bc/findingId/v2";

/// Collapse all whitespace runs (including newlines) to a single space,
/// then trim — so re-indentation or a trailing-newline change doesn't
/// mint a new fingerprint for the same underlying finding.
fn normalize_snippet(snippet: &str) -> String {
    snippet.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn normalize_path(file: &str) -> &str {
    file.strip_prefix("./").unwrap_or(file)
}

/// Hex-encoded SHA-1 over `rule_id`, the normalized path, and the
/// normalized snippet, NUL-separated so no field can be confused with an
/// adjacent one (e.g. a file named after another finding's rule id).
pub fn finding_fingerprint(rule_id: &str, file: &str, code_snippet: &str) -> String {
    let input = format!(
        "{rule_id}\0{}\0{}",
        normalize_path(file),
        normalize_snippet(code_snippet)
    );
    let mut hasher = Sha1::new();
    hasher.update(input.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Hex-encoded SHA-1 over the normalized path and the whitespace-
/// normalized ON-DISK text of the finding's line range, NUL-separated for
/// the same field-confusion reason as [`finding_fingerprint`]. No
/// `rule_id` — see this module's docs on why the vulnerability class is
/// deliberately not part of the v2 identity.
pub fn finding_fingerprint_v2(file: &str, on_disk_text: &str) -> String {
    let input = format!(
        "{}\0{}",
        normalize_path(file),
        normalize_snippet(on_disk_text)
    );
    let mut hasher = Sha1::new();
    hasher.update(input.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The v2 id for `finding`, reading its `line_start..=line_end` region out
/// of `repo_root`. `None` — meaning "emit v1 only" — when the file is
/// outside `repo_root`, unreadable, or the range starts past end of file.
///
/// Path resolution goes through [`bc_pathjail::confine`]: `f.file` is
/// model-authored text, so a `../../etc/passwd` or an absolute path must
/// resolve to "inaccessible" rather than reading (and hashing, and
/// implicitly confirming the existence of) a file outside the scan target.
pub fn finding_id_v2(repo_root: &Path, f: &Finding) -> Option<String> {
    let text = read_line_range(repo_root, &f.file, f.line_start, f.line_end)?;
    Some(finding_fingerprint_v2(&f.file, &text))
}

/// The 1-based, inclusive `[line_start, line_end]` slice of `file`, joined
/// with `\n`. A `line_end` below `line_start` (or zero, the common
/// "unknown end" encoding in this model) degrades to the single start
/// line rather than erroring; a `line_end` past EOF is clamped, so a
/// finding whose end line drifted past a shrunken file still fingerprints
/// off the lines that do exist.
fn read_line_range(repo_root: &Path, file: &str, line_start: i64, line_end: i64) -> Option<String> {
    if line_start < 1 {
        return None;
    }
    let path = bc_pathjail::confine(repo_root, normalize_path(file))?;
    let contents = std::fs::read_to_string(path).ok()?;
    let lines: Vec<&str> = contents.lines().collect();
    let start = usize::try_from(line_start).ok()?;
    if start > lines.len() {
        return None;
    }
    let end = usize::try_from(line_end.max(line_start))
        .ok()?
        .min(lines.len());
    Some(lines[start - 1..end].join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_model::VulnClass;

    fn finding_at(file: &str, line_start: i64, line_end: i64) -> Finding {
        Finding {
            provider_origins: Vec::new(),
            chunk_id: "c1".to_string(),
            file: file.to_string(),
            line_start,
            line_end,
            vuln_class: VulnClass::Injection,
            cwe: None,
            title: "t".to_string(),
            impact: String::new(),
            description: "d".to_string(),
            exploit_scenario: String::new(),
            preconditions: Vec::new(),
            recommendation: String::new(),
            code_snippet: "whatever the model quoted".to_string(),
            source_ref: None,
            sink_ref: None,
            backfilled_refs: Vec::new(),
            reanchored: Vec::new(),
            compliance_requirements: Vec::new(),
            confidence: 0.9,
            votes: 1,
            duplicates: Vec::new(),
            verdict: None,
            verdict_confidence: None,
            verdict_reason: String::new(),
            cvss_vector: None,
            cvss_score: None,
            cvss_rating: None,
            verifier_reasoning: String::new(),
            vsvs_vector: None,
            vsvs_score: None,
            vsvs_rating: None,
            offensive_priority: None,
            offensive_reason: String::new(),
            related_cwes: Vec::new(),
        }
    }

    /// A repo with `app.py` holding five numbered lines.
    fn repo() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("app.py"), "one\ntwo\nthree\nfour\nfive\n").unwrap();
        dir
    }

    #[test]
    fn v2_hashes_the_on_disk_lines_not_the_model_quoted_snippet() {
        let dir = repo();
        let mut f = finding_at("app.py", 2, 3);
        let a = finding_id_v2(dir.path(), &f).unwrap();
        // Re-quoting the snippet differently must not change the id — the
        // exact churn v2 exists to eliminate.
        f.code_snippet = "a completely different quote".to_string();
        assert_eq!(finding_id_v2(dir.path(), &f).unwrap(), a);
        assert_eq!(a, finding_fingerprint_v2("app.py", "two\nthree"));
    }

    #[test]
    fn v2_ignores_the_vuln_class() {
        let dir = repo();
        let mut f = finding_at("app.py", 2, 3);
        let a = finding_id_v2(dir.path(), &f).unwrap();
        f.vuln_class = VulnClass::LogicFlaw;
        assert_eq!(finding_id_v2(dir.path(), &f).unwrap(), a);
    }

    #[test]
    fn v2_differs_for_a_different_line_range() {
        let dir = repo();
        let a = finding_id_v2(dir.path(), &finding_at("app.py", 2, 3)).unwrap();
        let b = finding_id_v2(dir.path(), &finding_at("app.py", 4, 5)).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn v2_is_a_40_char_hex_string() {
        let dir = repo();
        let id = finding_id_v2(dir.path(), &finding_at("app.py", 1, 1)).unwrap();
        assert_eq!(id.len(), 40);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn v2_normalizes_whitespace_so_reindentation_does_not_change_it() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("app.py"), "if x:\n    run(y)\n").unwrap();
        let tight = finding_id_v2(dir.path(), &finding_at("app.py", 1, 2)).unwrap();

        let dir2 = tempfile::tempdir().unwrap();
        std::fs::write(dir2.path().join("app.py"), "if x:\n        run(y)\n").unwrap();
        let loose = finding_id_v2(dir2.path(), &finding_at("app.py", 1, 2)).unwrap();
        assert_eq!(tight, loose);
    }

    #[test]
    fn v2_clamps_a_line_end_past_the_end_of_file() {
        let dir = repo();
        let clamped = finding_id_v2(dir.path(), &finding_at("app.py", 4, 999)).unwrap();
        assert_eq!(clamped, finding_fingerprint_v2("app.py", "four\nfive"));
    }

    #[test]
    fn v2_treats_a_zero_line_end_as_the_single_start_line() {
        let dir = repo();
        let id = finding_id_v2(dir.path(), &finding_at("app.py", 3, 0)).unwrap();
        assert_eq!(id, finding_fingerprint_v2("app.py", "three"));
    }

    #[test]
    fn v2_is_none_for_a_missing_file() {
        let dir = repo();
        assert!(finding_id_v2(dir.path(), &finding_at("gone.py", 1, 1)).is_none());
    }

    #[test]
    fn v2_is_none_when_the_range_starts_past_the_end_of_file() {
        let dir = repo();
        assert!(finding_id_v2(dir.path(), &finding_at("app.py", 99, 100)).is_none());
    }

    #[test]
    fn v2_is_none_for_a_non_positive_start_line() {
        let dir = repo();
        assert!(finding_id_v2(dir.path(), &finding_at("app.py", 0, 1)).is_none());
        assert!(finding_id_v2(dir.path(), &finding_at("app.py", -5, 1)).is_none());
    }

    #[test]
    fn v2_refuses_to_read_outside_the_repo_root() {
        // `f.file` is model-authored: a traversal must be inaccessible,
        // not merely relative.
        let outer = tempfile::tempdir().unwrap();
        std::fs::write(outer.path().join("secret.txt"), "top secret\n").unwrap();
        let inner = outer.path().join("repo");
        std::fs::create_dir(&inner).unwrap();
        std::fs::write(inner.join("app.py"), "one\n").unwrap();

        assert!(finding_id_v2(&inner, &finding_at("../secret.txt", 1, 1)).is_none());
        assert!(finding_id_v2(
            &inner,
            &finding_at(&outer.path().join("secret.txt").to_string_lossy(), 1, 1)
        )
        .is_none());
    }

    #[test]
    fn v2_is_none_for_an_empty_file_path() {
        let dir = repo();
        assert!(finding_id_v2(dir.path(), &finding_at("", 1, 1)).is_none());
    }

    #[test]
    fn v2_resolves_a_leading_dot_slash_path_the_same_as_a_bare_one() {
        let dir = repo();
        let bare = finding_id_v2(dir.path(), &finding_at("app.py", 1, 1)).unwrap();
        let dotted = finding_id_v2(dir.path(), &finding_at("./app.py", 1, 1)).unwrap();
        assert_eq!(bare, dotted);
    }

    #[test]
    fn v2_differs_between_two_files_with_identical_content() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "run(x)\n").unwrap();
        std::fs::write(dir.path().join("b.py"), "run(x)\n").unwrap();
        let a = finding_id_v2(dir.path(), &finding_at("a.py", 1, 1)).unwrap();
        let b = finding_id_v2(dir.path(), &finding_at("b.py", 1, 1)).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn v2_adjacent_field_confusion_is_avoided_by_nul_separation() {
        assert_ne!(
            finding_fingerprint_v2("ab", "c"),
            finding_fingerprint_v2("a", "bc")
        );
    }

    #[test]
    fn v1_and_v2_of_the_same_finding_are_different_ids() {
        // They must never collide: a consumer matching on either key has
        // to be able to tell which scheme it matched.
        let dir = repo();
        let f = finding_at("app.py", 1, 1);
        let v1 = finding_fingerprint("injection", &f.file, &f.code_snippet);
        let v2 = finding_id_v2(dir.path(), &f).unwrap();
        assert_ne!(v1, v2);
    }

    #[test]
    fn same_inputs_produce_the_same_fingerprint() {
        let a = finding_fingerprint("injection", "app.py", "run(x)");
        let b = finding_fingerprint("injection", "app.py", "run(x)");
        assert_eq!(a, b);
    }

    #[test]
    fn different_rule_ids_produce_different_fingerprints() {
        let a = finding_fingerprint("injection", "app.py", "run(x)");
        let b = finding_fingerprint("other", "app.py", "run(x)");
        assert_ne!(a, b);
    }

    #[test]
    fn different_files_produce_different_fingerprints() {
        let a = finding_fingerprint("injection", "app.py", "run(x)");
        let b = finding_fingerprint("injection", "other.py", "run(x)");
        assert_ne!(a, b);
    }

    #[test]
    fn different_snippets_produce_different_fingerprints() {
        let a = finding_fingerprint("injection", "app.py", "run(x)");
        let b = finding_fingerprint("injection", "app.py", "run(y)");
        assert_ne!(a, b);
    }

    #[test]
    fn reformatted_snippet_whitespace_does_not_change_the_fingerprint() {
        let a = finding_fingerprint("injection", "app.py", "run(x)\n  more(y)");
        let b = finding_fingerprint("injection", "app.py", "run(x) more(y)");
        assert_eq!(a, b);
    }

    #[test]
    fn leading_dot_slash_path_prefix_is_normalized() {
        let a = finding_fingerprint("injection", "./app.py", "run(x)");
        let b = finding_fingerprint("injection", "app.py", "run(x)");
        assert_eq!(a, b);
    }

    #[test]
    fn fingerprint_is_a_40_char_hex_string() {
        let f = finding_fingerprint("injection", "app.py", "run(x)");
        assert_eq!(f.len(), 40);
        assert!(f.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn adjacent_field_confusion_is_avoided_by_nul_separation() {
        // Without a separator, ("ab", "c") and ("a", "bc") would collide.
        let a = finding_fingerprint("ab", "c", "");
        let b = finding_fingerprint("a", "bc", "");
        assert_ne!(a, b);
    }
}
