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

pub const SECRET_SEGMENT_PATTERNS: &[&str] = &["AUTH"];

pub const CREDENTIAL_DESTINATIONS: &[&str] = &[];

pub fn is_secret_var_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    SECRET_NAME_PATTERNS.iter().any(|pat| upper.contains(pat))
        || upper
            .split('_')
            .any(|seg| SECRET_SEGMENT_PATTERNS.iter().any(|pat| seg.ends_with(pat)))
}

pub fn may_interpolate(key_path: &str, var: &str) -> bool {
    !is_secret_var_name(var) || CREDENTIAL_DESTINATIONS.contains(&key_path)
}

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
    #[case("GH_OAUTH", true)]
    #[case("X_AUTH_HEADER", true)]
    #[case("github_token", true)]
    #[case("AUTHOR_NAME", false)]
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
