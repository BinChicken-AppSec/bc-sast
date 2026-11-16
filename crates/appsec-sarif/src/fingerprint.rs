use std::path::Path;

use appsec_model::Finding;
use sha1::{Digest, Sha1};

pub const FINGERPRINT_KEY: &str = "bc/findingId/v1";
pub const FINGERPRINT_KEY_V2: &str = "bc/findingId/v2";
pub const FINGERPRINT_KEY_V3: &str = "bc/findingId/v3";

fn normalize_snippet(snippet: &str) -> String {
    snippet.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn strip_whitespace(snippet: &str) -> String {
    snippet.chars().filter(|c| !c.is_whitespace()).collect()
}

fn normalize_path(file: &str) -> &str {
    file.strip_prefix("./").unwrap_or(file)
}

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

pub fn finding_fingerprint_v3(file: &str, on_disk_text: &str) -> String {
    let input = format!(
        "{}\0{}",
        normalize_path(file),
        strip_whitespace(on_disk_text)
    );
    let mut hasher = Sha1::new();
    hasher.update(input.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub fn finding_id_v3(repo_root: &Path, f: &Finding) -> Option<String> {
    let text = line_range_text(repo_root, &f.file, f.line_start, f.line_end)?;
    Some(finding_fingerprint_v3(&f.file, &text))
}

pub fn finding_id_v2(repo_root: &Path, f: &Finding) -> Option<String> {
    let text = line_range_text(repo_root, &f.file, f.line_start, f.line_end)?;
    Some(finding_fingerprint_v2(&f.file, &text))
}

pub fn line_range_text(
    repo_root: &Path,
    file: &str,
    line_start: i64,
    line_end: i64,
) -> Option<String> {
    if line_start < 1 {
        return None;
    }
    let path = appsec_pathjail::confine(repo_root, normalize_path(file))?;
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
    use appsec_model::VulnClass;

    fn finding_at(file: &str, line_start: i64, line_end: i64) -> Finding {
        Finding {
            provider_origins: Vec::new(),
            component: None,
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
        f.code_snippet = "a completely different quote".to_string();
        assert_eq!(finding_id_v2(dir.path(), &f).unwrap(), a);
        assert_eq!(a, finding_fingerprint_v2("app.py", "two\nthree"));
    }

    #[test]
    fn a_formatters_spacing_change_breaks_v2_and_not_v3() {
        let before = "result = foo( a, b )";
        let after = "result = foo(a, b)";
        assert_ne!(
            finding_fingerprint_v2("app.py", before),
            finding_fingerprint_v2("app.py", after),
            "this test is only meaningful while v2 does break here"
        );
        assert_eq!(
            finding_fingerprint_v3("app.py", before),
            finding_fingerprint_v3("app.py", after)
        );
    }

    #[test]
    fn re_indentation_survives_both_schemes() {
        let flat = "if x:\nreturn 1";
        let indented = "    if x:\n        return 1";
        assert_eq!(
            finding_fingerprint_v2("app.py", flat),
            finding_fingerprint_v2("app.py", indented)
        );
        assert_eq!(
            finding_fingerprint_v3("app.py", flat),
            finding_fingerprint_v3("app.py", indented)
        );
    }

    #[test]
    fn v3_still_changes_with_the_path() {
        assert_ne!(
            finding_fingerprint_v3("old/app.py", "x = 1"),
            finding_fingerprint_v3("new/app.py", "x = 1")
        );
    }

    #[test]
    fn v3_separates_genuinely_different_code() {
        assert_ne!(
            finding_fingerprint_v3("app.py", "query(user_input)"),
            finding_fingerprint_v3("app.py", "query(escaped)")
        );
    }

    #[test]
    fn v3_reads_the_on_disk_lines_like_v2_does() {
        let dir = repo();
        let f = finding_at("app.py", 2, 3);
        assert_eq!(
            finding_id_v3(dir.path(), &f).unwrap(),
            finding_fingerprint_v3("app.py", "two\nthree")
        );
    }

    #[test]
    fn v3_is_absent_for_an_unreadable_region() {
        let dir = repo();
        assert_eq!(
            finding_id_v3(dir.path(), &finding_at("missing.py", 1, 1)),
            None
        );
        assert_eq!(
            finding_id_v3(dir.path(), &finding_at("app.py", 99, 99)),
            None
        );
        assert_eq!(
            finding_id_v3(dir.path(), &finding_at("../outside.py", 1, 1)),
            None
        );
    }

    #[test]
    fn line_range_text_is_the_inclusive_slice_both_schemes_hash() {
        let dir = repo();
        assert_eq!(
            line_range_text(dir.path(), "app.py", 2, 3).unwrap(),
            "two\nthree"
        );
        assert_eq!(line_range_text(dir.path(), "app.py", 1, 0).unwrap(), "one");
        assert_eq!(
            line_range_text(dir.path(), "app.py", 4, 99).unwrap(),
            "four\nfive"
        );
        assert_eq!(line_range_text(dir.path(), "app.py", 0, 1), None);
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
        let a = finding_fingerprint("ab", "c", "");
        let b = finding_fingerprint("a", "bc", "");
        assert_ne!(a, b);
    }
}
