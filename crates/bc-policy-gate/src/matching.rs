//! Glob matching helpers, ported from `policy_gate/matching.py`. Shared by
//! the gate's own `deny_paths` check and the S10 post-gate's diff-scanning.

/// `fnmatch` with a `**/` prefix fallback so a bare root-level path (e.g.
/// `setup.py`) still matches a `**/setup.py`-style glob: `fnmatch`'s `*`
/// matches across `/` already, but a pattern that requires a *literal* `/`
/// right before its final segment (e.g. `**/auth/**` translating to a
/// regex that needs `/auth/` as a substring) can't match a path with
/// nothing before that segment at all. Retrying against the pattern with
/// `**/` stripped (matched against the SAME, unpadded path) catches that
/// case without changing the meaning of every other pattern — padding the
/// path itself (an earlier, incorrect fix attempt) broke matching for any
/// literal, non-`**/`-prefixed pattern anchored at the repo root.
pub fn glob_match(path: &str, pattern: &str) -> bool {
    if bc_repo_analysis::fnmatch(path, pattern) {
        return true;
    }
    if let Some(stripped) = pattern.strip_prefix("**/") {
        return bc_repo_analysis::fnmatch(path, stripped);
    }
    false
}

/// The first pattern in `patterns` that `file` matches, in `patterns`
/// order, or `None`.
pub fn first_match(files: &[String], patterns: &[String]) -> Option<String> {
    for f in files {
        let nf = f.replace('\\', "/");
        if nf.is_empty() {
            continue;
        }
        for pat in patterns {
            if glob_match(&nf, pat) {
                return Some(pat.clone());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_direct_fnmatch_hit_matches_without_needing_the_prefix_fallback() {
        assert!(glob_match("auth/login.py", "auth/*"));
    }

    #[test]
    fn a_double_star_prefixed_pattern_matches_a_nested_path_directly() {
        assert!(glob_match("src/auth/login.py", "**/auth/**"));
    }

    #[test]
    fn a_double_star_prefixed_pattern_also_matches_a_root_level_path() {
        assert!(glob_match("auth/login.py", "**/auth/**"));
    }

    #[test]
    fn a_root_anchored_pattern_still_matches_the_root_level_path_it_names() {
        // Regression: an earlier fix padded every path with a leading "/"
        // before matching, which broke this exact case (the padded path no
        // longer started with the pattern's own literal "auth/" prefix).
        assert!(glob_match("auth/login.py", "auth/*"));
    }

    #[test]
    fn a_root_anchored_pattern_does_not_match_a_nested_path() {
        assert!(!glob_match("src/auth/login.py", "auth/*"));
    }

    #[test]
    fn a_pattern_with_no_double_star_prefix_never_uses_the_fallback() {
        assert!(!glob_match("x/y.py", "y.py"));
    }

    #[test]
    fn first_match_returns_none_for_an_empty_file_list() {
        assert_eq!(first_match(&[], &["*.env".to_string()]), None);
    }

    #[test]
    fn first_match_skips_a_blank_file_entry() {
        assert_eq!(first_match(&["".to_string()], &["*.env".to_string()]), None);
    }

    #[test]
    fn first_match_normalizes_backslashes_before_matching() {
        assert_eq!(
            first_match(&["auth\\login.py".to_string()], &["**/auth/**".to_string()]),
            Some("**/auth/**".to_string())
        );
    }

    #[test]
    fn first_match_returns_the_first_pattern_hit_in_pattern_order() {
        let patterns = vec!["*.env".to_string(), "auth/*".to_string()];
        assert_eq!(
            first_match(&["auth/login.py".to_string()], &patterns),
            Some("auth/*".to_string())
        );
    }

    #[test]
    fn first_match_returns_none_when_nothing_matches() {
        assert_eq!(
            first_match(&["readme.md".to_string()], &["*.env".to_string()]),
            None
        );
    }
}
