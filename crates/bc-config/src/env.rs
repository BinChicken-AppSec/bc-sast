//! `${VAR}` / `${VAR:-default}` placeholder expansion, ported from
//! `vvaharness/config/__init__.py`'s `_expand_env`/`_expand`.
//!
//! Takes the environment lookup as a parameter (`&dyn Fn(&str) ->
//! Option<String>`) rather than calling `std::env::var` directly, so the
//! whole recursive expansion is a pure function — trivially testable
//! without mutating the real process environment (which would make tests
//! order-dependent/flaky, the same concern the Python original's
//! `conftest.py` calls out for its own process-global test isolation).

use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;

static ENV_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\$\{([A-Z_][A-Z0-9_]*)(?::-([^}]*))?\}").unwrap());

/// Expand every `${VAR}`/`${VAR:-default}` placeholder in every string
/// leaf of `value` (recursing through objects and arrays; non-string
/// scalars pass through unchanged).
///
/// POSIX `${VAR:-default}` semantics: the default is used when `VAR` is
/// *unset or set-but-empty* (not just unset) — an env var explicitly set
/// to `""` still falls back to the default, matching the Python
/// original's `if val: return val` (empty string is falsy in Python).
pub fn expand(value: &Value, getenv: &dyn Fn(&str) -> Option<String>) -> Value {
    match value {
        Value::String(s) => Value::String(expand_str(s, getenv)),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), expand(v, getenv)))
                .collect(),
        ),
        Value::Array(arr) => Value::Array(arr.iter().map(|v| expand(v, getenv)).collect()),
        other => other.clone(),
    }
}

fn expand_str(s: &str, getenv: &dyn Fn(&str) -> Option<String>) -> String {
    ENV_PATTERN
        .replace_all(s, |caps: &regex::Captures| {
            let name = &caps[1];
            let default = caps.get(2).map(|m| m.as_str());
            match getenv(name) {
                Some(val) if !val.is_empty() => val,
                _ => default.unwrap_or("").to_string(),
            }
        })
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use serde_json::json;
    use std::collections::HashMap;

    fn env_from<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        let map: HashMap<&str, &str> = pairs.iter().copied().collect();
        move |name: &str| map.get(name).map(|s| s.to_string())
    }

    #[rstest]
    #[case("${FOO}", &[("FOO", "bar")], "bar")]
    #[case("${FOO:-fallback}", &[("FOO", "bar")], "bar")] // set and non-empty wins over default
    #[case("${FOO:-fallback}", &[], "fallback")] // unset -> default
    #[case("${FOO:-fallback}", &[("FOO", "")], "fallback")] // set-but-empty -> default (POSIX rule)
    #[case("${FOO}", &[], "")] // unset, no default -> empty
    #[case("${FOO}", &[("FOO", "")], "")] // set-but-empty, no default -> empty
    #[case("plain text, no placeholder", &[], "plain text, no placeholder")]
    #[case("prefix-${FOO}-suffix", &[("FOO", "X")], "prefix-X-suffix")]
    fn expand_str_cases(#[case] input: &str, #[case] env: &[(&str, &str)], #[case] expected: &str) {
        assert_eq!(expand_str(input, &env_from(env)), expected);
    }

    #[test]
    fn expand_multiple_placeholders_in_one_string() {
        let env = env_from(&[("A", "1"), ("B", "2")]);
        assert_eq!(expand_str("${A}-${B}", &env), "1-2");
    }

    #[test]
    fn expand_default_stops_at_first_closing_brace() {
        // Matches the Python original's `[^}]*` group exactly: the default
        // capture is greedy but can't consume a literal '}', so it stops
        // right before the FIRST one. For "${FOO:-a{b}c}": the default
        // group captures "a{b" and the whole `${...}` match ends at that
        // first '}' (right after "b") — the placeholder match is exactly
        // "${FOO:-a{b}", leaving the trailing "c}" as ordinary, unmatched
        // text appended after the substituted default. This is a known,
        // deliberate scope limitation (a default containing '}' is not
        // fully supported), not a bug.
        let env = env_from(&[]);
        assert_eq!(expand_str("${FOO:-a{b}c}", &env), "a{bc}");
    }

    #[test]
    fn expand_recurses_through_nested_objects_and_arrays() {
        let env = env_from(&[("KEY", "secret123")]);
        let input = json!({
            "sdk": {"api_key": "${KEY}", "verify_ssl": true},
            "list": ["${KEY}", "plain", 42, null],
        });
        let expanded = expand(&input, &env);
        assert_eq!(
            expanded,
            json!({
                "sdk": {"api_key": "secret123", "verify_ssl": true},
                "list": ["secret123", "plain", 42, null],
            })
        );
    }

    #[test]
    fn expand_non_string_scalars_pass_through_unchanged() {
        let env = env_from(&[]);
        assert_eq!(expand(&json!(42), &env), json!(42));
        assert_eq!(expand(&json!(true), &env), json!(true));
        assert_eq!(expand(&json!(null), &env), json!(null));
    }
}
