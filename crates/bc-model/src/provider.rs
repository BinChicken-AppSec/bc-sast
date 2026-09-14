//! Provider-supplied provenance. Missing identity is never inferred from report IDs.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    Checkmarx,
    Semgrep,
    Snyk,
    Aikido,
    Sonatype,
    #[default]
    Unknown,
}
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProduct {
    Sast,
    Dependency,
    Secret,
    Other,
    #[default]
    Unknown,
}
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderSource {
    Api,
    File,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(default)]
pub struct ProviderNativeIds {
    pub issue_id: Option<String>,
    pub match_based_id: Option<String>,
    pub similarity_id: Option<String>,
    pub attack_vector_id: Option<String>,
    pub asset_finding_id: Option<String>,
    pub group_id: Option<String>,
}

/// Observed identity and state, not authorization to mutate a provider.
/// File imports and missing revision bindings require independent reconciliation.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(default)]
pub struct ProviderOrigin {
    pub provider: ProviderKind,
    pub product: ProviderProduct,
    pub source: ProviderSource,
    pub native_ids: ProviderNativeIds,
    pub tenant_id: Option<String>,
    pub project_id: Option<String>,
    pub repository_id: Option<String>,
    pub repository_name: Option<String>,
    pub git_ref: Option<String>,
    pub revision: Option<String>,
    pub scan_id: Option<String>,
    pub state: Option<String>,
    pub severity: Option<String>,
}
