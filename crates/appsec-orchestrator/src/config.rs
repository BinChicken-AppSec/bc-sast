use super::*;
pub struct ScanConfig {
    pub step0_enabled: bool,
    pub step0: Step0Config,
    pub step1: Step1Config,
    pub step2_enabled: bool,
    pub step2: Step2Config,
    pub step3: Step3Config,
    pub step4: Step4Config,
    pub step5: Step5Config,
    pub step6: Step6Config,
    pub step7: Step7Config,
    pub step8: Step8Config,
    pub tool_version: String,
    pub spend_cap: Option<SpendCap>,
    pub checkpoint: Option<Arc<dyn appsec_checkpoint::CheckpointStore>>,
    pub resume: bool,
    pub emit_unreachable_appendix: bool,
    pub progress: Option<appsec_pipeline_core::ProgressSink>,
    pub pricing: pricing::PricingConfig,
    pub autoexclude: appsec_model::AutoExcludeCounts,
    pub cancel: Option<appsec_pipeline_core::CancelTokenRef>,
}

pub struct ScanInput {
    pub repo_root: PathBuf,
    pub repo_name: String,
    pub application_id: Option<String>,
    pub cmdb_path: Option<PathBuf>,
    pub context_dir: Option<PathBuf>,
    pub context_mcp_server: Option<PathBuf>,
    pub context_mcp_spaces: Vec<String>,
    pub context_mcp_label: Option<String>,
    pub context_files: Vec<PathBuf>,
    pub context_urls: Vec<String>,
    pub git_sha_override: Option<String>,
    pub repo_key_override: Option<String>,
    pub repo_key_env: Option<String>,
    pub branch_override: Option<String>,
    pub base_ref: Option<String>,
    pub changed_files: BTreeMap<String, BTreeSet<i64>>,
    pub diff_scope_active: bool,
    pub compliance: Vec<appsec_compliance::CompliancePolicy>,
    pub checkmarx_xml: Vec<PathBuf>,
    pub snyk_json: Vec<PathBuf>,
    pub semgrep_json: Vec<PathBuf>,
    pub aikido_json: Vec<PathBuf>,
    pub sonatype_json: Vec<PathBuf>,
    pub semgrep_live: Option<appsec_thirdparty_api::semgrep::SemgrepConfig>,
    pub snyk_live: Option<appsec_thirdparty_api::snyk::SnykConfig>,
    pub sonatype_live: Option<appsec_thirdparty_api::sonatype::SonatypeConfig>,
    pub aikido_live: Option<appsec_thirdparty_api::aikido::AikidoConfig>,
    pub checkmarx_live: Option<appsec_thirdparty_api::checkmarx::CheckmarxConfig>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopAfter {
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

#[derive(Debug, Clone, PartialEq, Default)]
pub struct ScanOutcome {
    pub provider_writeback_plan: Option<String>,
    pub stopped_after: Option<StopAfter>,
    pub report: Option<FinalReport>,
    pub markdown: Option<String>,
    pub sarif: Option<String>,
}

pub(super) fn stopped(stop_after: StopAfter) -> ScanOutcome {
    ScanOutcome {
        provider_writeback_plan: None,
        stopped_after: Some(stop_after),
        report: None,
        markdown: None,
        sarif: None,
    }
}
