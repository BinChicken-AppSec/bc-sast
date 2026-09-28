//! The secret-name interpolation policy, ported from
//! `vvaharness/config/constants.py` (`SECRET_NAME_PATTERNS`,
//! `SECRET_SEGMENT_PATTERNS`, `CREDENTIAL_DESTINATIONS`,
//! `is_secret_var_name`) and the refusal in `config/__init__.py`'s
//! `_expand_env`.
//!
//! A shared profile that writes `${GITHUB_TOKEN}` into, say,
//! `step_remediate.verify_command` would copy a credential into a shell
//! command line, and from there into process listings and logs. The
//! refusal is decided on the variable's NAME alone, set or unset, so a
//! profile fails the same way on every machine instead of only on the ones
//! where the secret happens to be present.

/// Uppercase substrings that mark an environment-variable name as
/// secret-bearing.
pub const SECRET_NAME_PATTERNS: &[&str] = &[
    "API_KEY",
    "APIKEY",
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "CREDENTIAL",
    "PRIVATE_KEY",
];

/// Matched as the suffix of one `_`-separated segment rather than as a
/// substring: `OAUTH` and `X_AUTH` count, `AUTHOR` does not.
pub const SECRET_SEGMENT_PATTERNS: &[&str] = &["AUTH"];

/// The only dotted key paths a secret-named variable may expand into.
///
/// Deliberately empty, unlike Python's `sdk.api_key`, `openai.api_key`,
/// `batch.git_token` and `output.ingest_token`: this port reads no
/// credential from `config.yaml` at all (the gateway key arrives through
/// `--gateway-api-key`/`BC_GATEWAY_API_KEY`, the git token through
/// `--git-token`), so none of those four keys is read by anything here.
/// Allowing a secret into a key nobody reads buys nothing and still puts
/// the secret into the merged tree, so every secret-named interpolation is
/// refused. A future config key that genuinely carries a credential is
/// added here, and the overlay banner then reports it as `set`/`unset`.
pub const CREDENTIAL_DESTINATIONS: &[&str] = &[];

/// True when `name` matches a secret substring or segment pattern.
pub fn is_secret_var_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    SECRET_NAME_PATTERNS.iter().any(|pat| upper.contains(pat))
        || upper
            .split('_')
            .any(|seg| SECRET_SEGMENT_PATTERNS.iter().any(|pat| seg.ends_with(pat)))
}

/// Whether `var` may be interpolated into the config key at `key_path`.
pub fn may_interpolate(key_path: &str, var: &str) -> bool {
    !is_secret_var_name(var) || CREDENTIAL_DESTINATIONS.contains(&key_path)
}

/// The "may expand only into ..." clause of the refusal message. Takes the
/// list as a parameter so both shapes are testable while
/// [`CREDENTIAL_DESTINATIONS`] itself is empty.
pub(crate) fn describe_destinations(destinations: &[&str]) -> String {
    if destinations.is_empty() {
        return "no config key (this build reads no credential from config)".to_string();
    }
    let mut sorted = destinations.to_vec();
    sorted.sort_unstable();
    sorted.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("GITHUB_TOKEN", true)]
    #[case("OPENAI_API_KEY", true)]
    #[case("MYAPIKEY", true)]
    #[case("DB_PASSWORD", true)]
    #[case("FTP_PASSWD", true)]
    #[case("AWS_SECRET_ACCESS_KEY", true)]
    #[case("GCP_CREDENTIALS", true)]
    #[case("SSH_PRIVATE_KEY", true)]
    #[case("GH_OAUTH", true)] // segment ends in AUTH
    #[case("X_AUTH_HEADER", true)] // a whole AUTH segment
    #[case("github_token", true)] // case-insensitive, like Python's .upper()
    #[case("AUTHOR_NAME", false)] // AUTHOR does not end in AUTH
    #[case("BC_DEEPDIVE_MODEL", false)]
    #[case("MY_KEY", false)]
    #[case("HOME", false)]
    fn is_secret_var_name_cases(#[case] name: &str, #[case] expected: bool) {
        assert_eq!(is_secret_var_name(name), expected);
    }

    #[test]
    fn a_plain_variable_may_go_anywhere() {
        assert!(may_interpolate("models.deepdive.id", "BC_DEEPDIVE_MODEL"));
        assert!(may_interpolate("", "HOME"));
    }

    #[test]
    fn a_secret_named_variable_is_refused_everywhere_while_no_destination_exists() {
        assert!(!may_interpolate(
            "step_remediate.verify_command",
            "GITHUB_TOKEN"
        ));
        // Python's own credential keys are inert here, so they are refused
        // too (see CREDENTIAL_DESTINATIONS).
        assert!(!may_interpolate("sdk.api_key", "ANTHROPIC_SDK_API_KEY"));
    }

    #[test]
    fn describe_destinations_names_the_empty_case_and_sorts_a_real_list() {
        assert!(describe_destinations(&[]).contains("no config key"));
        assert_eq!(
            describe_destinations(&["sdk.api_key", "batch.git_token"]),
            "batch.git_token, sdk.api_key"
        );
    }
}
