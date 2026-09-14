//! A scoped port of Python's `fnmatch.translate`/`fnmatch.fnmatchcase`,
//! covering `*`, `?`, and `[seq]`/`[!seq]` character classes — the subset
//! `s1_preprocess.py`'s `glob_hit` actually exercises (its own default
//! pattern list, `_DEFAULT_EXCLUDE_GLOBS`, only ever uses `*`). Exotic
//! bracket-expression edge cases CPython's translator also handles (a
//! leading `]` inside a class, escaping `&`/`~`/`|` for forward
//! compatibility with future set-operator syntax) are deliberately not
//! replicated — real config-supplied glob patterns don't use them.

use std::sync::LazyLock;

use regex::Regex;

/// True if `rel` (a repo-relative POSIX path) matches `pattern` under
/// fnmatch semantics: `.` (DOTALL) matches any character including `/` —
/// fnmatch has no concept of path separators, unlike shell globbing.
pub fn fnmatch(rel: &str, pattern: &str) -> bool {
    match translate(pattern) {
        Some(rx) => rx.is_match(rel),
        None => false,
    }
}

fn translate(pattern: &str) -> Option<Regex> {
    let mut out = String::from("(?s)^");
    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '*' => {
                out.push_str(".*");
                i += 1;
            }
            '?' => {
                out.push('.');
                i += 1;
            }
            '[' => {
                let mut j = i + 1;
                if j < chars.len() && chars[j] == '!' {
                    j += 1;
                }
                if j < chars.len() && chars[j] == ']' {
                    j += 1;
                }
                while j < chars.len() && chars[j] != ']' {
                    j += 1;
                }
                if j >= chars.len() {
                    // Unterminated '[' — fnmatch treats it as a literal.
                    out.push_str("\\[");
                    i += 1;
                } else {
                    let body: String = chars[i + 1..j].iter().collect();
                    let body = if let Some(rest) = body.strip_prefix('!') {
                        format!("^{rest}")
                    } else {
                        body
                    };
                    out.push('[');
                    out.push_str(&body);
                    out.push(']');
                    i = j + 1;
                }
            }
            c => {
                out.push_str(&regex::escape(&c.to_string()));
                i += 1;
            }
        }
    }
    out.push('$');
    Regex::new(&out).ok()
}

/// Ported from `s1_preprocess.py::glob_hit`. Returns the first pattern in
/// `globs` that excludes `rel`, or `None`. A `**/x` pattern also matches a
/// repo-root `x` — plain `fnmatch` alone requires a literal `/` before the
/// final segment, which would let root-level files (`LICENSE`,
/// `test_*.py`) escape the exclusion the pattern clearly intends.
pub fn glob_hit<'a>(rel: &str, globs: &'a [String]) -> Option<&'a str> {
    let name = rel.rsplit('/').next().unwrap_or(rel);
    globs
        .iter()
        .find(|g| fnmatch(rel, g) || (g.starts_with("**/") && fnmatch(name, &g[3..])))
        .map(String::as_str)
}

static DEFAULT_EXCLUDE_GLOBS_LIST: LazyLock<Vec<String>> = LazyLock::new(|| {
    DEFAULT_EXCLUDE_GLOBS
        .iter()
        .map(|s| s.to_string())
        .collect()
});

pub fn default_exclude_globs() -> &'static [String] {
    &DEFAULT_EXCLUDE_GLOBS_LIST
}

pub const DEFAULT_EXCLUDE_GLOBS: &[&str] = &[
    "**/test_*.py",
    "**/*_test.py",
    "**/conftest.py",
    "**/*_test.go",
    "**/*.test.js",
    "**/*.test.ts",
    "**/*.test.jsx",
    "**/*.test.tsx",
    "**/*.spec.js",
    "**/*.spec.ts",
    "**/*.spec.jsx",
    "**/*.spec.tsx",
    "**/*Test.java",
    "**/*Tests.java",
    "**/*IT.java",
    "**/*Test.cs",
    "**/*Tests.cs",
    "**/*Test.kt",
    "**/.gitignore",
    "**/.gitattributes",
    "**/.gitmodules",
    "**/.gitkeep",
    "**/.editorconfig",
    "**/.dockerignore",
    "**/.npmignore",
    "**/.eslintignore",
    "**/.prettierignore",
    "**/.mailmap",
    "**/CODEOWNERS",
    "**/.DS_Store",
    "**/LICENSE",
    "**/LICENSE.*",
    "**/NOTICE",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn star_matches_across_slashes_like_python_fnmatch() {
        assert!(fnmatch("a/b/c.py", "*.py"));
        assert!(fnmatch("a/b/c.py", "a*.py"));
    }

    #[test]
    fn question_mark_matches_exactly_one_char() {
        assert!(fnmatch("a.py", "?.py"));
        assert!(!fnmatch("ab.py", "?.py"));
    }

    #[test]
    fn character_class_matches_a_set() {
        assert!(fnmatch("a.py", "[ab].py"));
        assert!(fnmatch("b.py", "[ab].py"));
        assert!(!fnmatch("c.py", "[ab].py"));
    }

    #[test]
    fn a_class_starting_with_a_literal_close_bracket() {
        // "[]]" is the fnmatch idiom for "a class containing only ']'" —
        // the first ']' right after '[' (or after '[!') is a literal
        // member, not the class terminator.
        assert!(fnmatch("]", "[]]"));
        assert!(!fnmatch("x", "[]]"));
    }

    #[test]
    fn negated_character_class() {
        assert!(fnmatch("c.py", "[!ab].py"));
        assert!(!fnmatch("a.py", "[!ab].py"));
    }

    #[test]
    fn unterminated_bracket_is_a_literal() {
        assert!(fnmatch("[.py", "[.py"));
    }

    #[test]
    fn full_match_is_required_not_a_substring() {
        assert!(!fnmatch("prefix_a.py", "a.py"));
    }

    #[test]
    fn an_invalid_character_range_degrades_to_no_match_rather_than_panicking() {
        // "[z-a]" is a syntactically well-formed *fnmatch* class but an
        // invalid *regex* range (start > end) once translated — a
        // misconfigured `exclude_globs` entry a user could genuinely
        // write. Exercises `translate`'s `None` fallback for real, rather
        // than panicking on the malformed pattern.
        assert!(!fnmatch("anything", "[z-a]"));
    }

    #[test]
    fn glob_hit_matches_a_root_level_file_against_a_double_star_pattern() {
        let globs = vec!["**/LICENSE".to_string()];
        assert_eq!(glob_hit("LICENSE", &globs), Some("**/LICENSE"));
    }

    #[test]
    fn glob_hit_matches_a_nested_file_against_a_double_star_pattern() {
        let globs = vec!["**/test_*.py".to_string()];
        assert_eq!(glob_hit("a/b/test_foo.py", &globs), Some("**/test_*.py"));
    }

    #[test]
    fn glob_hit_returns_none_when_nothing_matches() {
        let globs = vec!["**/LICENSE".to_string()];
        assert_eq!(glob_hit("src/main.rs", &globs), None);
    }

    #[test]
    fn default_exclude_globs_is_non_empty_and_cached() {
        assert!(!default_exclude_globs().is_empty());
        assert_eq!(default_exclude_globs().len(), DEFAULT_EXCLUDE_GLOBS.len());
    }
}
