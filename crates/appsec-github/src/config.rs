/// Connection details for a single pull request. `api_base_url` is
/// overridable (rather than a hardcoded constant) so tests can point it at
/// a local `wiremock` server instead of `https://api.github.com`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GithubConfig {
    pub api_base_url: String,
    pub owner: String,
    pub repo: String,
    pub pr_number: u64,
    pub token: String,
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
}
