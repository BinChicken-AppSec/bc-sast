#[derive(Clone, PartialEq, Eq)]
pub struct GithubConfig {
    pub api_base_url: String,
    pub owner: String,
    pub repo: String,
    pub pr_number: u64,
    pub token: String,
}

impl std::fmt::Debug for GithubConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GithubConfig")
            .field("api_base_url", &self.api_base_url)
            .field("owner", &self.owner)
            .field("repo", &self.repo)
            .field("pr_number", &self.pr_number)
            .field("token", &"<redacted>")
            .finish()
    }
}

impl GithubConfig {
    pub fn new(
        owner: impl Into<String>,
        repo: impl Into<String>,
        pr_number: u64,
        token: impl Into<String>,
    ) -> Self {
        GithubConfig {
            api_base_url: "https://api.github.com".to_string(),
            owner: owner.into(),
            repo: repo.into(),
            pr_number,
            token: token.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_defaults_to_the_real_github_api() {
        let cfg = GithubConfig::new("acme", "widgets", 42, "tok");
        assert_eq!(cfg.api_base_url, "https://api.github.com");
        assert_eq!(cfg.owner, "acme");
        assert_eq!(cfg.repo, "widgets");
        assert_eq!(cfg.pr_number, 42);
        assert_eq!(cfg.token, "tok");
    }

    #[test]
    fn debug_redacts_the_token_but_keeps_the_rest() {
        let shown = format!(
            "{:?}",
            GithubConfig::new("acme", "widgets", 7, "sup3r-s3cret-cred-do-not-log")
        );
        assert!(
            !shown.contains("sup3r-s3cret-cred-do-not-log"),
            "the token reached a Debug rendering: {shown}"
        );
        assert!(shown.contains("<redacted>"), "{shown}");
        assert!(shown.contains("widgets"), "{shown}");
        assert!(shown.contains("GithubConfig"), "{shown}");
    }
}
