//! Shared semantic-family, CWE and language vocabulary for the S0
//! call-graph engine, ported from `vvaharness/rules/families.py`.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;

/// Sink families whose taint paths survive per-family pruning: reaching
/// any of them is on its own worth reporting, so path-budget trimming
/// must not drop the last one.
pub const PROTECTED_SEMANTIC_FAMILIES: &[&str] = &[
    "html-response",
    "command-exec",
    "sql-exec",
    "url-fetch",
    "file-io",
    "deserialization",
];

/// Family set used by callgraph planning/gating; anything else collapses
/// to `"other"`.
pub const CANONICAL_FAMILIES: &[&str] = &[
    "html-response",
    "command-exec",
    "sql-exec",
    "url-fetch",
    "file-io",
    "deserialization",
    "credentials",
    "other",
];

const DEFAULT_OWASP: &[&str] = &["A03:2025-Injection"];

/// OWASP Top 10 2025 categories per semantic family. Families absent here
/// fall back to [`DEFAULT_OWASP`] (Injection), the modal category for a
/// taint sink.
fn owasp_2025_by_semantic(family: &str) -> &'static [&'static str] {
    match family {
        "html-response" => &["A03:2025-Injection"],
        "command-exec" => &["A03:2025-Injection"],
        "sql-exec" => &["A03:2025-Injection"],
        "url-fetch" => &["A10:2025-SSRF", "A03:2025-Injection"],
        "file-io" => &["A01:2025-Broken-Access-Control", "A03:2025-Injection"],
        "deserialization" => &["A08:2025-Software-and-Data-Integrity-Failures"],
        "template-render" => &["A03:2025-Injection"],
        "credentials" => &["A02:2025-Cryptographic-Failures"],
        _ => DEFAULT_OWASP,
    }
}

/// Languages this engine can parse — the extractor registry `scan`
/// provides. The last four carry framework entry points and a call
/// graph but no taint facts; see `scan/lite.rs`.
pub const VVAH_LANGUAGES: &[&str] = &[
    "python",
    "java",
    "javascript",
    "typescript",
    "go",
    "csharp",
    "php",
    "ruby",
    "kotlin",
    "rust",
    "c-cpp",
];

/// Spellings operators and rule packs use, mapped to a canonical language
/// key. Mirrors `_SEMGREP_TO_VVAH` in `callgraph_engine/_rules.py`, plus
/// common aliases.
fn lang_alias(key: &str) -> Option<&'static str> {
    Some(match key {
        "python" | "py" | "python3" => "python",
        "java" => "java",
        "javascript" | "js" | "node" => "javascript",
        "typescript" | "ts" => "typescript",
        "go" | "golang" => "go",
        "csharp" | "c#" | "cs" | "dotnet" => "csharp",
        "kotlin" | "kt" => "kotlin",
        "scala" => "scala",
        "ruby" | "rb" => "ruby",
        "php" => "php",
        "rust" | "rs" => "rust",
        "c" | "cpp" | "c++" | "cxx" => "c-cpp",
        _ => return None,
    })
}

static CWE_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)CWE[-_ ]?0*(\d{1,4})").unwrap());

/// Canonicalize a CWE reference: `"cwe_089"`, `"CWE-0089"`, `"89"` ->
/// `"CWE-89"`.
pub fn norm_cwe(value: &str) -> Option<String> {
    let caps = CWE_RE.captures(value)?;
    let digits: i64 = caps[1].parse().ok()?;
    Some(format!("CWE-{digits}"))
}

/// Collapse `value` to a canonical family, or `"other"`.
pub fn canonical_family(value: &str) -> &'static str {
    CANONICAL_FAMILIES
        .iter()
        .find(|&&f| f == value)
        .copied()
        .unwrap_or("other")
}

/// OWASP-2025 label list for a semantic family (default: Injection).
pub fn owasp_labels(semantic_family: &str) -> &'static [&'static str] {
    owasp_2025_by_semantic(semantic_family)
}

/// Resolve a rule's semantic family, corpus value first.
///
/// The rule corpus is the single source of truth: `build_kb` writes a
/// clamped `metadata.semantic_family` per rule. Scan-time loaders read
/// that stored value rather than re-deriving it. When the field is
/// absent (older corpora, LLM-annotated rules), fall back to the
/// caller's derivation. The result is always clamped to the canonical
/// vocabulary.
pub fn resolve_semantic_family(meta: Option<&Value>, fallback: &str) -> &'static str {
    let stored = meta
        .and_then(Value::as_object)
        .and_then(|m| m.get("semantic_family"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty());
    match stored {
        Some(s) => canonical_family(&s.to_lowercase()),
        None => canonical_family(fallback),
    }
}

/// Normalize a language spelling to its canonical key.
///
/// Unknown spellings are returned lowercased rather than mapped to a
/// default: the caller warns when the result is outside
/// [`VVAH_LANGUAGES`], and silently rewriting a typo to a real language
/// would narrow scan scope without saying so.
pub fn canonical_lang(value: &str) -> String {
    let key = value.trim().to_lowercase();
    match lang_alias(&key) {
        Some(canon) => canon.to_string(),
        None => key,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn norm_cwe_requires_the_literal_cwe_prefix_bare_digits_are_not_enough() {
        // Matches the Python original's own `_CWE_RE` exactly: bare
        // digits with no "CWE" substring never match.
        assert_eq!(norm_cwe("89"), None);
    }

    #[test]
    fn norm_cwe_strips_leading_zeros_and_separators() {
        assert_eq!(norm_cwe("cwe_0089").as_deref(), Some("CWE-89"));
        assert_eq!(norm_cwe("CWE-0089").as_deref(), Some("CWE-89"));
        assert_eq!(norm_cwe("CWE 89").as_deref(), Some("CWE-89"));
    }

    #[test]
    fn norm_cwe_is_case_insensitive() {
        assert_eq!(norm_cwe("cWe-89").as_deref(), Some("CWE-89"));
    }

    #[test]
    fn norm_cwe_none_for_unrecognized_text() {
        assert_eq!(norm_cwe("not a cwe"), None);
        assert_eq!(norm_cwe(""), None);
    }

    #[test]
    fn canonical_family_passes_through_known_families() {
        assert_eq!(canonical_family("sql-exec"), "sql-exec");
        assert_eq!(canonical_family("credentials"), "credentials");
    }

    #[test]
    fn canonical_family_collapses_unknown_to_other() {
        assert_eq!(canonical_family("frobnicate"), "other");
        assert_eq!(canonical_family(""), "other");
    }

    #[test]
    fn owasp_labels_known_family() {
        assert_eq!(
            owasp_labels("url-fetch"),
            &["A10:2025-SSRF", "A03:2025-Injection"]
        );
    }

    #[test]
    fn owasp_labels_defaults_to_injection_for_unknown_family() {
        assert_eq!(owasp_labels("nonsense"), &["A03:2025-Injection"]);
    }

    #[test]
    fn resolve_semantic_family_prefers_the_stored_corpus_value() {
        let meta = serde_json::json!({"semantic_family": "sql-exec"});
        assert_eq!(resolve_semantic_family(Some(&meta), "other"), "sql-exec");
    }

    #[test]
    fn resolve_semantic_family_clamps_a_stored_unknown_value_to_other() {
        let meta = serde_json::json!({"semantic_family": "bogus"});
        assert_eq!(resolve_semantic_family(Some(&meta), "sql-exec"), "other");
    }

    #[test]
    fn resolve_semantic_family_falls_back_when_absent() {
        let meta = serde_json::json!({});
        assert_eq!(resolve_semantic_family(Some(&meta), "sql-exec"), "sql-exec");
    }

    #[test]
    fn resolve_semantic_family_falls_back_when_blank() {
        let meta = serde_json::json!({"semantic_family": "   "});
        assert_eq!(resolve_semantic_family(Some(&meta), "sql-exec"), "sql-exec");
    }

    #[test]
    fn resolve_semantic_family_falls_back_when_no_meta_at_all() {
        assert_eq!(resolve_semantic_family(None, "sql-exec"), "sql-exec");
    }

    #[test]
    fn resolve_semantic_family_falls_back_when_meta_is_not_an_object() {
        let meta = serde_json::json!("not an object");
        assert_eq!(resolve_semantic_family(Some(&meta), "sql-exec"), "sql-exec");
    }

    #[test]
    fn canonical_lang_maps_common_aliases() {
        assert_eq!(canonical_lang("py"), "python");
        assert_eq!(canonical_lang("JS"), "javascript");
        assert_eq!(canonical_lang("c#"), "csharp");
        assert_eq!(canonical_lang("golang"), "go");
        assert_eq!(canonical_lang("C++"), "c-cpp");
        assert_eq!(canonical_lang("rs"), "rust");
    }

    #[test]
    fn canonical_lang_passes_through_canonical_spellings() {
        assert_eq!(canonical_lang("python"), "python");
    }

    #[test]
    fn canonical_lang_lowercases_an_unrecognized_spelling_without_mapping_it() {
        assert_eq!(canonical_lang("Fortran"), "fortran");
    }

    #[test]
    fn vvah_languages_contains_every_supported_language() {
        assert_eq!(VVAH_LANGUAGES.len(), 11);
        assert!(VVAH_LANGUAGES.contains(&"python"));
        assert!(VVAH_LANGUAGES.contains(&"csharp"));
        assert!(VVAH_LANGUAGES.contains(&"rust"));
        // C and C++ share one key, because `ext_to_lang` maps every
        // extension of both onto it.
        assert!(VVAH_LANGUAGES.contains(&"c-cpp"));
    }

    #[test]
    fn protected_semantic_families_and_canonical_families_agree_except_credentials_other() {
        for f in PROTECTED_SEMANTIC_FAMILIES {
            assert!(CANONICAL_FAMILIES.contains(f));
        }
    }
}
