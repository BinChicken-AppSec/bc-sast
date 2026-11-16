#[cfg(test)]
use std::path::Path;
use std::path::PathBuf;

use appsec_orchestrator::StopAfter;
use clap::{Parser, ValueEnum};

#[derive(Debug, Clone, Parser)]
#[command(name = "appsec-scan", version, about = "Agentic SAST scanner")]
pub struct Cli {
    #[command(flatten)]
    pub provider_publish: crate::provider_publish::ProviderPublishArgs,
    #[arg(long, required_unless_present = "repo_file")]
    pub repo: Option<PathBuf>,

    #[arg(long, conflicts_with = "repo")]
    pub repo_file: Option<PathBuf>,

    #[arg(long, default_value = "./batch-workspace")]
    pub workspace: PathBuf,

    #[arg(long)]
    pub keep_clones: bool,

    #[arg(long, env = "BC_GIT_TOKEN")]
    pub git_token: Option<String>,

    #[arg(long)]
    pub out_batch_summary: Option<PathBuf>,

    #[arg(long)]
    pub repo_name: Option<String>,

    #[arg(long, default_value = DEFAULT_MODEL)]
    pub model: String,

    #[arg(long)]
    pub temperature: Option<f64>,

    #[arg(long)]
    pub seed: Option<u64>,

    #[arg(long)]
    pub top_p: Option<f64>,

    #[arg(long)]
    pub step_timeout: Option<u64>,

    #[arg(long, value_name = "TIER", value_parser = parse_reasoning_effort)]
    pub reasoning_effort: Option<appsec_llm_client::ReasoningEffort>,

    #[arg(
        long,
        env = "BC_GATEWAY_BASE_URL",
        required = false,
        required_unless_present = "publish_provider_plan",
        default_value_if("publish_provider_plan", clap::builder::ArgPredicate::IsPresent, "")
    )]
    pub gateway_base_url: String,

    #[arg(long, env = "BC_GATEWAY_API_KEY")]
    pub gateway_api_key: Option<String>,

    #[arg(long)]
    pub ca_cert: Option<PathBuf>,

    #[arg(long, env = "BC_GATEWAY_CLIENT_CERT")]
    pub client_cert: Option<PathBuf>,

    #[arg(long, env = "BC_GATEWAY_CLIENT_KEY")]
    pub client_key: Option<PathBuf>,

    #[arg(long, value_enum, default_value_t = Dialect::Openai)]
    pub dialect: Dialect,

    #[arg(long, env = "BC_OPENAI_API", value_name = "API", value_parser = parse_openai_api)]
    pub openai_api: Option<appsec_llm_client::OpenAiApi>,

    #[arg(long)]
    pub no_cache_markers: bool,

    #[arg(long)]
    pub allow_unsupported_model: bool,

    #[arg(long)]
    pub pricing_provider: Option<String>,

    #[arg(long, default_value = "")]
    pub stop_after: String,

    #[arg(long = "context-file")]
    pub context_files: Vec<PathBuf>,

    #[arg(long = "context-url")]
    pub context_urls: Vec<String>,

    #[arg(long, default_value = "")]
    pub app_id: String,

    #[arg(long, default_value = "")]
    pub cmdb_csv: String,

    #[arg(long, default_value = "")]
    pub context_dir: String,

    #[arg(long, default_value = "")]
    pub context_mcp_server: String,

    #[arg(long = "context-mcp-space")]
    pub context_mcp_spaces: Vec<String>,

    #[arg(long, default_value = "")]
    pub context_mcp_label: String,

    #[arg(long)]
    pub checkmarx_xml: Vec<PathBuf>,

    #[arg(long)]
    pub snyk_json: Vec<PathBuf>,

    #[arg(long)]
    pub semgrep_json: Vec<PathBuf>,

    #[arg(long)]
    pub aikido_json: Vec<PathBuf>,

    #[arg(long)]
    pub sonatype_json: Vec<PathBuf>,

    #[arg(long, env = "SEMGREP_TOKEN")]
    pub semgrep_token: Option<String>,
    #[arg(long)]
    pub semgrep_deployment_slug: Option<String>,
    #[arg(long)]
    pub semgrep_repo: Option<String>,
    #[arg(long)]
    pub semgrep_branch: Option<String>,
    #[arg(long)]
    pub semgrep_base_url: Option<String>,

    #[arg(long, env = "SNYK_TOKEN")]
    pub snyk_token: Option<String>,
    #[arg(long)]
    pub snyk_base_url: Option<String>,
    #[arg(long)]
    pub snyk_org_id: Option<String>,
    #[arg(long)]
    pub snyk_project_id: Option<String>,

    #[arg(long)]
    pub sonatype_base_url: Option<String>,
    #[arg(long)]
    pub sonatype_username: Option<String>,
    #[arg(long, env = "SONATYPE_PASSWORD")]
    pub sonatype_password: Option<String>,
    #[arg(long)]
    pub sonatype_app_id: Option<String>,
    #[arg(long)]
    pub sonatype_stage: Option<String>,

    #[arg(long)]
    pub aikido_client_id: Option<String>,
    #[arg(long, env = "AIKIDO_CLIENT_SECRET")]
    pub aikido_client_secret: Option<String>,
    #[arg(long)]
    pub aikido_repo_id: Option<i64>,
    #[arg(long)]
    pub aikido_base_url: Option<String>,

    #[arg(long)]
    pub checkmarx_base_url: Option<String>,
    #[arg(long)]
    pub checkmarx_iam_url: Option<String>,
    #[arg(long)]
    pub checkmarx_tenant: Option<String>,
    #[arg(long, env = "CHECKMARX_API_KEY")]
    pub checkmarx_api_key: Option<String>,
    #[arg(long)]
    pub checkmarx_project_id: Option<String>,
    #[arg(long)]
    pub checkmarx_branch: Option<String>,

    #[arg(long, default_value = "")]
    pub git_sha: String,

    #[arg(long, default_value = "")]
    pub repo_key: String,

    #[arg(long, default_value = "")]
    pub branch: String,

    #[arg(long, default_value = "")]
    pub base_ref: String,

    #[arg(long)]
    pub out_dir: Option<PathBuf>,

    #[arg(long)]
    pub out_md: Option<PathBuf>,

    #[arg(long)]
    pub out_sarif: Option<PathBuf>,

    #[arg(long)]
    pub out_csv: Option<PathBuf>,

    #[arg(long, default_value = "off", value_parser = ["off", "plan", "apply"])]
    pub provider_writeback: String,

    #[arg(long)]
    pub no_threat_model: bool,

    #[arg(long)]
    pub max_tokens: Option<u64>,

    #[arg(long)]
    pub max_scan_seconds: Option<u64>,

    #[arg(long, env = "GITHUB_TOKEN")]
    pub github_token: Option<String>,

    #[arg(long)]
    pub github_repo: Option<String>,

    #[arg(long)]
    pub pr_number: Option<u64>,

    #[arg(long)]
    pub pr_comments: bool,

    #[arg(long)]
    pub diff_scope: bool,

    #[arg(long, hide = true)]
    pub compliance_policy: Vec<PathBuf>,

    #[arg(long, visible_alias = "scan-framework", value_name = "NAME")]
    pub compliance_preset: Vec<String>,

    #[arg(long, default_value = "")]
    pub compliance_scope: String,

    #[arg(long, env = "GITHUB_API_URL", default_value = "https://api.github.com")]
    pub github_api_base_url: String,

    #[arg(long)]
    pub out_findings_json: Option<PathBuf>,

    #[arg(long)]
    pub post_comments_from: Option<PathBuf>,

    #[arg(long)]
    pub baseline: Option<PathBuf>,

    #[arg(long)]
    pub config: Option<PathBuf>,

    #[arg(
        long,
        num_args = 0..=1,
        default_value_t = false,
        default_missing_value = "true",
        action = clap::ArgAction::Set
    )]
    pub remediate: bool,

    #[arg(
        long,
        num_args = 0..=1,
        default_missing_value = "true",
        action = clap::ArgAction::Set,
        conflicts_with = "no_validate"
    )]
    pub validate: Option<bool>,

    #[arg(long)]
    pub no_validate: bool,

    #[arg(
        long,
        num_args = 0..=1,
        default_value_t = true,
        default_missing_value = "true",
        action = clap::ArgAction::Set
    )]
    pub remediation_exit_code: bool,

    #[arg(long, visible_alias = "testing-level", value_name = "LEVEL", num_args = 0..=1, default_missing_value = "comprehensive", requires = "remediate", conflicts_with_all = ["remediate_from", "diff_scope", "stop_after", "interactive", "remediate_in_place", "resume"])]
    pub target_tests: Option<String>,

    #[arg(long, value_enum, value_name = "MODE", default_value = "auto")]
    pub api_spec: crate::target_testing::ApiSpecMode,

    #[arg(long, value_name = "LIST", value_delimiter = ',', value_parser = crate::target_testing::parse_api_spec_format)]
    pub api_spec_formats: Vec<appsec_api_spec::FormatId>,

    #[arg(long, value_enum, default_value = "patch")]
    pub remediation_delivery: crate::delivery::DeliveryMode,
    #[arg(long, requires = "delivery_branch")]
    pub delivery_remote: Option<String>,
    #[arg(long, requires = "delivery_remote")]
    pub delivery_branch: Option<String>,

    #[arg(long)]
    pub top: Option<String>,

    #[arg(long, short = 'i')]
    pub interactive: bool,

    #[arg(long)]
    pub force: bool,

    #[arg(long)]
    pub resume: bool,

    #[arg(long, conflicts_with = "no_auto_step1")]
    pub auto_step1: bool,

    #[arg(long)]
    pub no_auto_step1: bool,

    #[arg(long)]
    pub enforce_remediation_policy: bool,

    #[arg(long)]
    pub remediation_policy: Option<PathBuf>,

    #[arg(long)]
    pub remediation_playbook: Option<PathBuf>,

    #[arg(long)]
    pub no_syntax_check: bool,

    #[arg(long)]
    pub keep_unverified: bool,

    #[arg(long)]
    pub max_diff_lines: Option<usize>,

    #[arg(long)]
    pub max_files_touched: Option<usize>,

    #[arg(long)]
    pub remediate_dry_run: bool,

    #[arg(long)]
    pub verify_command: Option<String>,

    #[arg(long)]
    pub verify_timeout: Option<u64>,

    #[arg(long)]
    pub remediate_in_place: bool,

    #[arg(long)]
    pub keep_remediation_worktree: bool,

    #[arg(long)]
    pub out_remediation_json: Option<PathBuf>,

    #[arg(long)]
    pub post_fixes_from: Option<PathBuf>,

    #[arg(long, conflicts_with = "remediate")]
    pub remediate_from: Option<PathBuf>,

    #[arg(long)]
    pub gc: bool,

    #[arg(long, default_value_t = 100)]
    pub gc_keep_runs: usize,

    #[arg(long, default_value_t = 5)]
    pub gc_max_age_days: i64,

    #[arg(long)]
    pub gc_run: Option<PathBuf>,

    #[arg(long)]
    pub gc_dry_run: bool,

    #[arg(long)]
    pub estimate: bool,

    #[arg(long)]
    pub log_file: Option<PathBuf>,

    #[arg(long)]
    pub log_stderr: bool,

    #[arg(long, short = 'v', action = clap::ArgAction::Count)]
    pub verbose: u8,

    #[arg(long)]
    pub no_progress: bool,

    #[arg(long, value_enum)]
    pub progress_style: Option<crate::progress_lines::ProgressStyle>,

    #[arg(long)]
    pub s6_progress_file: bool,

    #[arg(long)]
    pub out_run_manifest: Option<PathBuf>,

    #[arg(long)]
    pub doctor: bool,

    #[arg(long, requires = "doctor")]
    pub cache_probe: bool,

    #[arg(long)]
    pub stream_large_responses: bool,

    #[arg(long)]
    pub skip_preflight: bool,

    #[arg(long)]
    pub setup: bool,
}

pub const DEFAULT_MODEL: &str = "gpt-6-luna";

fn parse_reasoning_effort(raw: &str) -> Result<appsec_llm_client::ReasoningEffort, String> {
    raw.parse()
}

fn parse_openai_api(raw: &str) -> Result<appsec_llm_client::OpenAiApi, String> {
    raw.parse()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Dialect {
    Openai,
    Anthropic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum StopAfterArg {
    S1,
    S2,
    S3,
    S4,
    S5,
    S6,
    S7,
    S8,
    S9,
}

impl From<StopAfterArg> for StopAfter {
    fn from(a: StopAfterArg) -> Self {
        match a {
            StopAfterArg::S1 => StopAfter::S1,
            StopAfterArg::S2 => StopAfter::S2,
            StopAfterArg::S3 => StopAfter::S3,
            StopAfterArg::S4 => StopAfter::S4,
            StopAfterArg::S5 => StopAfter::S5,
            StopAfterArg::S6 => StopAfter::S6,
            StopAfterArg::S7 => StopAfter::S7,
            StopAfterArg::S8 => StopAfter::S8,
            StopAfterArg::S9 => StopAfter::S9,
        }
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    #[cfg(unix)]
    pub(crate) fn permissions_enforced(test: &str) -> bool {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let probe = dir.path().join("probe");
        std::fs::write(&probe, "x").unwrap();
        std::fs::set_permissions(&probe, std::fs::Permissions::from_mode(0o000)).unwrap();
        let enforced = std::fs::read(&probe).is_err();
        let notes = [
            format!("SKIPPED (permissions not enforced for this user): {test}\n"),
            String::new(),
        ];
        eprint!("{}", notes[usize::from(enforced)]);
        enforced
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn bury_near_path_max(staged: &Path) -> PathBuf {
        const TARGET: usize = 4096 - 100;
        let mut deep = staged.parent().unwrap().canonicalize().unwrap();
        while TARGET.saturating_sub(deep.as_os_str().len() + 1) > 255 {
            deep.push("d".repeat(200));
        }
        std::fs::create_dir_all(&deep).unwrap();
        let buried = deep.join("r".repeat(TARGET - deep.as_os_str().len() - 1));
        std::fs::rename(staged, &buried).unwrap();
        buried
    }

    #[cfg(target_os = "linux")]
    pub(crate) const UNREADABLE_FILE: &str = "/proc/sys/vm/drop_caches";

    pub(crate) fn minimal_cli(repo: &Path) -> Cli {
        Cli {
            context_dir: String::new(),
            context_mcp_server: String::new(),
            context_mcp_spaces: Vec::new(),
            context_mcp_label: String::new(),
            repo: Some(repo.to_path_buf()),
            repo_file: None,
            workspace: std::path::PathBuf::from("./batch-workspace"),
            keep_clones: false,
            git_token: None,
            out_batch_summary: None,
            repo_name: None,
            model: "m".to_string(),
            temperature: None,
            seed: None,
            top_p: None,
            step_timeout: None,
            reasoning_effort: None,
            openai_api: None,
            no_cache_markers: false,
            allow_unsupported_model: false,
            gateway_base_url: "http://127.0.0.1:0".to_string(),
            gateway_api_key: None,
            ca_cert: None,
            client_cert: None,
            client_key: None,
            dialect: Dialect::Openai,
            pricing_provider: None,
            stop_after: String::new(),
            context_files: Vec::new(),
            context_urls: Vec::new(),
            app_id: String::new(),
            cmdb_csv: String::new(),
            checkmarx_xml: Vec::new(),
            snyk_json: Vec::new(),
            semgrep_json: Vec::new(),
            aikido_json: Vec::new(),
            sonatype_json: Vec::new(),
            semgrep_token: None,
            semgrep_deployment_slug: None,
            semgrep_repo: None,
            semgrep_branch: None,
            semgrep_base_url: None,
            snyk_token: None,
            snyk_base_url: None,
            snyk_org_id: None,
            snyk_project_id: None,
            sonatype_base_url: None,
            sonatype_username: None,
            sonatype_password: None,
            sonatype_app_id: None,
            sonatype_stage: None,
            aikido_client_id: None,
            aikido_client_secret: None,
            aikido_repo_id: None,
            aikido_base_url: None,
            checkmarx_base_url: None,
            checkmarx_iam_url: None,
            checkmarx_tenant: None,
            checkmarx_api_key: None,
            checkmarx_project_id: None,
            checkmarx_branch: None,
            git_sha: String::new(),
            repo_key: String::new(),
            branch: String::new(),
            base_ref: String::new(),
            out_dir: None,
            out_md: None,
            out_sarif: None,
            out_csv: None,
            provider_publish: Default::default(),
            provider_writeback: "off".into(),
            no_threat_model: false,
            max_tokens: None,
            max_scan_seconds: None,
            github_token: None,
            github_repo: None,
            pr_number: None,
            pr_comments: false,
            diff_scope: false,
            compliance_policy: Vec::new(),
            compliance_preset: Vec::new(),
            compliance_scope: String::new(),
            github_api_base_url: "https://api.github.com".to_string(),
            out_findings_json: None,
            post_comments_from: None,
            baseline: None,
            config: None,
            remediate: false,
            validate: None,
            no_validate: false,
            remediation_exit_code: true,
            target_tests: None,
            api_spec: Default::default(),
            api_spec_formats: Vec::new(),
            top: None,
            interactive: false,
            force: false,
            resume: false,
            enforce_remediation_policy: false,
            remediation_policy: None,
            remediation_playbook: None,
            no_syntax_check: false,
            keep_unverified: false,
            max_diff_lines: None,
            max_files_touched: None,
            remediate_dry_run: false,
            verify_command: None,
            verify_timeout: None,
            remediate_in_place: false,
            remediation_delivery: crate::delivery::DeliveryMode::Patch,
            delivery_remote: None,
            delivery_branch: None,
            keep_remediation_worktree: false,
            out_remediation_json: None,
            post_fixes_from: None,
            remediate_from: None,
            gc: false,
            gc_keep_runs: 100,
            gc_max_age_days: 5,
            gc_run: None,
            gc_dry_run: false,
            estimate: false,
            log_file: None,
            log_stderr: false,
            verbose: 0,
            no_progress: true,
            progress_style: None,
            s6_progress_file: false,
            out_run_manifest: None,
            doctor: false,
            cache_probe: false,
            stream_large_responses: false,
            skip_preflight: true,
            setup: false,
            auto_step1: false,
            no_auto_step1: false,
        }
    }
}
