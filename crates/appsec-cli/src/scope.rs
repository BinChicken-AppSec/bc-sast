use super::*;
pub struct DiffScope {
    pub active: bool,
    pub changed_files: std::collections::BTreeMap<String, std::collections::BTreeSet<i64>>,
}

impl DiffScope {
    pub fn boundary(&self) -> appsec_model::DiffScope {
        appsec_model::DiffScope::new(self.active, self.changed_files.keys())
    }
}

pub async fn resolve_diff_scope(
    diff_scope: bool,
    github: Option<&appsec_github::GithubClient>,
) -> Result<DiffScope, String> {
    if !diff_scope {
        return Ok(DiffScope {
            active: false,
            changed_files: std::collections::BTreeMap::new(),
        });
    }
    let client = github.ok_or_else(|| {
        "--diff-scope requires --github-token/--github-repo/--pr-number".to_string()
    })?;
    let diff_text = client.fetch_diff().await.map_err(stringify)?;
    let changed_files = appsec_github::parse_diff(&diff_text);
    if changed_files.is_empty() {
        eprintln!(
            "  [diff-scope] WARN: the PR diff fetched successfully but contains no \
             changed source lines; the likely cause is a diff of only renames, \
             deletions, mode changes or binary files. Scoping the scan to nothing \
             rather than falling back to the whole repository."
        );
    }
    Ok(DiffScope {
        active: true,
        changed_files,
    })
}

pub fn check_batch_diff_scope(cli: &Cli) -> Result<(), String> {
    if cli.repo_file.is_some() && cli.diff_scope {
        return Err(concat!(
            "--diff-scope cannot be combined with --repo-file: a manifest names many ",
            "repositories and a diff belongs to one pull request on one of them, so batch ",
            "mode has no single scope to resolve. Scan the one repository directly to use ",
            "--diff-scope",
        )
        .to_string());
    }
    Ok(())
}

pub fn check_pr_comment_scope(cli: &Cli) -> Result<(), String> {
    if cli.pr_comments && !cli.diff_scope {
        return Err(concat!(
            "--pr-comments requires --diff-scope: PR comments and fix suggestions only ",
            "anchor to lines the pull request actually changed, so a full-repo scan would ",
            "post most of its findings as unanchored conversation comments",
        )
        .to_string());
    }
    Ok(())
}

pub fn pr_comment_target(
    cli: &Cli,
    github: Option<appsec_github::GithubClient>,
) -> Option<appsec_github::GithubClient> {
    cli.pr_comments.then_some(github).flatten()
}

pub fn load_compliance_policies(
    cli: &Cli,
) -> Result<Vec<appsec_compliance::CompliancePolicy>, String> {
    if !cli.compliance_policy.is_empty() {
        return Err("--compliance-policy runtime files are no longer supported; select --scan-framework NAME (or --compliance-preset NAME). Edit crates/appsec-compliance/presets and rebuild to change scan rules".into());
    }
    let mut policies = Vec::with_capacity(cli.compliance_preset.len());
    for name in &cli.compliance_preset {
        policies.push(appsec_compliance::preset(name)?);
    }
    if let Some(scope) = parse_compliance_scope(&cli.compliance_scope)? {
        for p in &mut policies {
            p.scope_mode = scope;
        }
    }
    Ok(policies)
}

pub(super) fn parse_compliance_scope(
    raw: &str,
) -> Result<Option<appsec_compliance::ScopeMode>, String> {
    non_empty(raw)
        .map(|s| match s.to_ascii_lowercase().as_str() {
            "annotate" => Ok(appsec_compliance::ScopeMode::Annotate),
            "filter" => Ok(appsec_compliance::ScopeMode::Filter),
            other => Err(format!("invalid --compliance-scope value: {other:?}")),
        })
        .transpose()
}
