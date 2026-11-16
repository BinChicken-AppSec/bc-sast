#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    pub key: String,
    pub display: String,
}

pub fn parse_origin(raw: &str) -> Option<Origin> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }

    let (scheme, authority, path) = match raw.split_once("://") {
        Some((scheme, rest)) => {
            let scheme = scheme.to_ascii_lowercase();
            if scheme == "file" {
                return None;
            }
            let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
            (scheme, authority, path)
        }
        None => {
            let (authority, path) = scp_parts(raw)?;
            ("ssh".to_string(), authority, path)
        }
    };

    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = strip_port(authority);
    if host.is_empty() {
        return None;
    }

    let path = path.trim_matches('/');
    let path = path.strip_suffix(".git").unwrap_or(path).trim_matches('/');
    if path.is_empty() {
        return None;
    }

    Some(Origin {
        key: format!(
            "{}/{}",
            host.to_ascii_lowercase(),
            path.to_ascii_lowercase()
        ),
        display: format!("{scheme}://{host}/{path}"),
    })
}

fn scp_parts(raw: &str) -> Option<(&str, &str)> {
    let (authority, path) = raw.split_once(':')?;
    if authority.is_empty() || path.is_empty() {
        return None;
    }
    if path.starts_with('/') {
        return None;
    }
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    if host.len() <= 1 {
        return None;
    }
    Some((authority, path))
}

fn strip_port(authority: &str) -> &str {
    match authority.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => host,
        _ => authority,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("https://github.com/org/repo.git", "github.com/org/repo")]
    #[case("https://github.com/org/repo", "github.com/org/repo")]
    #[case("git@github.com:org/repo.git", "github.com/org/repo")]
    #[case("ssh://git@github.com/org/repo.git", "github.com/org/repo")]
    #[case("ssh://git@github.com:22/org/repo.git", "github.com/org/repo")]
    #[case("git://github.com/org/repo.git", "github.com/org/repo")]
    #[case("https://GitHub.COM/Org/Repo.git", "github.com/org/repo")]
    #[case(
        "https://gitlab.example.com/group/sub/repo.git",
        "gitlab.example.com/group/sub/repo"
    )]
    #[case("  https://github.com/org/repo.git  ", "github.com/org/repo")]
    #[case("https://github.com/org/repo.git/", "github.com/org/repo")]
    fn accepted_forms_normalize_to_one_key(#[case] raw: &str, #[case] key: &str) {
        assert_eq!(parse_origin(raw).unwrap().key, key);
    }

    #[rstest]
    #[case("https://x-access-token:ghs_16CharsOfSecret@github.com/org/repo.git")]
    #[case("https://oauth2:glpat-SomeSecretValue@github.com/org/repo.git")]
    #[case("https://user:p%40ssw%40rd@github.com/org/repo.git")]
    #[case("https://justauser@github.com/org/repo.git")]
    #[case("ssh://git@github.com/org/repo.git")]
    fn credentials_are_stripped_from_both_fields(#[case] raw: &str) {
        let origin = parse_origin(raw).unwrap();
        assert_eq!(origin.key, "github.com/org/repo");
        for secret in ["ghs_", "glpat-", "p%40ssw", "x-access-token", "oauth2"] {
            assert!(
                !origin.key.contains(secret) && !origin.display.contains(secret),
                "{secret:?} survived into {origin:?}"
            );
        }
        assert!(!origin.display.contains('@'), "{origin:?}");
    }

    #[test]
    fn a_token_containing_an_at_sign_still_leaves_the_host_as_the_host() {
        let origin = parse_origin("https://user:tok@en@github.com/org/repo.git").unwrap();
        assert_eq!(origin.key, "github.com/org/repo");
        assert_eq!(origin.display, "https://github.com/org/repo");
    }

    #[rstest]
    #[case("")]
    #[case("   ")]
    #[case("/srv/git/repo.git")]
    #[case("./repo")]
    #[case("../sibling-repo")]
    #[case("file:///srv/git/repo.git")]
    #[case("C:\\work\\repo")]
    #[case("https://github.com")]
    #[case("https://github.com/")]
    #[case("https://github.com/.git")]
    #[case("git@github.com:")]
    #[case("github.com:/srv/git/repo.git")]
    #[case("https:///org/repo.git")]
    #[case("https://:22/org/repo.git")]
    fn unusable_forms_are_refused_rather_than_guessed(#[case] raw: &str) {
        assert_eq!(parse_origin(raw), None, "{raw:?} should not have parsed");
    }

    #[test]
    fn display_keeps_the_path_case_the_key_folds() {
        let origin = parse_origin("https://github.com/Org/RepoName.git").unwrap();
        assert_eq!(origin.key, "github.com/org/reponame");
        assert_eq!(origin.display, "https://github.com/Org/RepoName");
    }
}
