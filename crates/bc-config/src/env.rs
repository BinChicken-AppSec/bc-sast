//! `${VAR}` / `${VAR:-default}` placeholder expansion, ported from
//! `vvaharness/config/__init__.py`'s `_expand_env`/`_expand`, including its
//! v1.3.0 secret-name policy (see [`crate::policy`]).
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

use crate::{policy, ConfigError};

static ENV_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\$\{([A-Z_][A-Z0-9_]*)(?::-([^}]*))?\}").unwrap());

/// Expand every `${VAR}`/`${VAR:-default}` placeholder in every string
/// leaf of `value` (recursing through objects and arrays; non-string
/// scalars pass through unchanged).
///
/// `key_path` is the dotted config key `value` sits at (`""` for the
/// root); each object key recursed into is appended to it, array items
/// keep their parent's path (as in Python). A secret-named variable
/// (see [`policy::is_secret_var_name`]) interpolated into a key outside
/// [`policy::CREDENTIAL_DESTINATIONS`] is refused with
/// [`ConfigError::SecretInterpolation`], whether or not it is set.
///
/// POSIX `${VAR:-default}` semantics: the default is used when `VAR` is
/// *unset or set-but-empty* (not just unset) — an env var explicitly set
/// to `""` still falls back to the default, matching the Python
/// original's `if val: return val` (empty string is falsy in Python).
pub fn expand(
    value: &Value,
    key_path: &str,
    getenv: &dyn Fn(&str) -> Option<String>,
) -> Result<Value, ConfigError> {
    match value {
        Value::String(s) => expand_str(s, key_path, getenv).map(Value::String),
        Value::Object(map) => map
            .iter()
            .map(|(k, v)| Ok((k.clone(), expand(v, &child_path(key_path, k), getenv)?)))
            .collect::<Result<serde_json::Map<_, _>, ConfigError>>()
            .map(Value::Object),
        Value::Array(arr) => arr
            .iter()
            .map(|v| expand(v, key_path, getenv))
            .collect::<Result<Vec<_>, ConfigError>>()
            .map(Value::Array),
        other => Ok(other.clone()),
    }
}

fn child_path(parent: &str, key: &str) -> String {
    if parent.is_empty() {
        key.to_string()
    } else {
        format!("{parent}.{key}")
    }
}

fn expand_str(
    s: &str,
    key_path: &str,
    getenv: &dyn Fn(&str) -> Option<String>,
) -> Result<String, ConfigError> {
    // Checked over every placeholder BEFORE any lookup, so a refused
    // variable is never even read from the environment.
    if let Some(var) = ENV_PATTERN
        .captures_iter(s)
        .map(|caps| caps[1].to_string())
        .find(|name| !policy::may_interpolate(key_path, name))
    {
        return Err(ConfigError::SecretInterpolation {
            key_path: key_path.to_string(),
            var,
        });
    }
    Ok(ENV_PATTERN
        .replace_all(s, |caps: &regex::Captures| {
            let name = &caps[1];
            let default = caps.get(2).map(|m| m.as_str());
            match getenv(name) {
                Some(val) if !val.is_empty() => val,
                _ => default.unwrap_or("").to_string(),
            }
        })
        .into_owned())
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
        assert_eq!(expand_str(input, "k", &env_from(env)).unwrap(), expected);
    }

    #[test]
    fn expand_multiple_placeholders_in_one_string() {
        let env = env_from(&[("A", "1"), ("B", "2")]);
        assert_eq!(expand_str("${A}-${B}", "k", &env).unwrap(), "1-2");
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
        assert_eq!(expand_str("${FOO:-a{b}c}", "k", &env).unwrap(), "a{bc}");
    }

    #[test]
    fn expand_recurses_through_nested_objects_and_arrays() {
        let env = env_from(&[("KEY", "secret123")]);
        let input = json!({
            "sdk": {"api_key": "${KEY}", "verify_ssl": true},
            "list": ["${KEY}", "plain", 42, null],
        });
        let expanded = expand(&input, "", &env).unwrap();
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
        assert_eq!(expand(&json!(42), "", &env).unwrap(), json!(42));
        assert_eq!(expand(&json!(true), "", &env).unwrap(), json!(true));
        assert_eq!(expand(&json!(null), "", &env).unwrap(), json!(null));
    }

    fn refusal(key_path: &str, var: &str) -> ConfigError {
        ConfigError::SecretInterpolation {
            key_path: key_path.to_string(),
            var: var.to_string(),
        }
    }

    #[test]
    fn a_secret_named_variable_is_refused_with_its_dotted_key_path() {
        let env = env_from(&[("GITHUB_TOKEN", "ghp_live")]);
        let input = json!({"step_remediate": {"verify_command": "make test T=${GITHUB_TOKEN}"}});
        assert_eq!(
            expand(&input, "", &env).unwrap_err(),
            refusal("step_remediate.verify_command", "GITHUB_TOKEN")
        );
    }

    #[test]
    fn a_secret_named_variable_is_refused_even_when_unset_or_defaulted() {
        let env = env_from(&[]);
        let err = expand(&json!({"a": "${DB_PASSWORD:-hunter2}"}), "", &env).unwrap_err();
        assert_eq!(err, refusal("a", "DB_PASSWORD"));
    }

    #[test]
    fn a_refused_variable_is_never_looked_up() {
        let looked_up = std::cell::Cell::new(false);
        let env = |_: &str| {
            looked_up.set(true);
            Some("x".to_string())
        };
        assert!(expand_str("${PLAIN}${API_TOKEN}", "k", &env).is_err());
        assert!(!looked_up.get());
        // The same lookup does run once nothing is refused.
        assert_eq!(expand_str("${PLAIN}", "k", &env).unwrap(), "x");
        assert!(looked_up.get());
    }

    #[test]
    fn array_items_keep_their_parents_key_path_and_a_prefix_is_honored() {
        let env = env_from(&[]);
        let err = expand(
            &json!({"exclude_dirs": ["ok", "${MY_SECRET}"]}),
            "step1",
            &env,
        )
        .unwrap_err();
        assert_eq!(err, refusal("step1.exclude_dirs", "MY_SECRET"));
    }

    #[test]
    fn a_refusal_at_the_root_has_an_empty_key_path() {
        let err = expand(&json!("${API_KEY}"), "", &env_from(&[])).unwrap_err();
        assert_eq!(err, refusal("", "API_KEY"));
    }
}
