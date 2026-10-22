//! SARIF 2.1.0 schema types, scoped to exactly the fields this crate
//! emits (not a general-purpose SARIF library). Ported from the shape
//! `vvaharness/report/enrich.py::generate_sarif` builds by hand as plain
//! dicts, typed here instead so a malformed document is a compile error,
//! not a silent typo in a dict key.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SarifDocument {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub version: String,
    pub runs: Vec<Run>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Run {
    pub tool: Tool,
    pub results: Vec<SarifResult>,
    pub taxonomies: Vec<Taxonomy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invocations: Option<Vec<Invocation>>,
    pub properties: RunProperties,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Tool {
    pub driver: Driver,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Driver {
    pub name: String,
    pub version: String,
    pub rules: Vec<Rule>,
    #[serde(rename = "supportedTaxonomies")]
    pub supported_taxonomies: Vec<TaxonomyRef>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TaxonomyRef {
    pub guid: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    #[serde(rename = "shortDescription", skip_serializing_if = "Option::is_none")]
    pub short_description: Option<MessageText>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MessageText {
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Taxonomy {
    pub guid: String,
    pub name: String,
    pub organization: String,
    #[serde(rename = "shortDescription")]
    pub short_description: MessageText,
    #[serde(rename = "informationUri")]
    pub information_uri: String,
    pub taxa: Vec<Taxon>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Taxon {
    pub id: String,
    #[serde(rename = "helpUri")]
    pub help_uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "shortDescription", skip_serializing_if = "Option::is_none")]
    pub short_description: Option<MessageText>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArtifactLocation {
    pub uri: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Region {
    #[serde(rename = "startLine")]
    pub start_line: i64,
    #[serde(rename = "endLine", skip_serializing_if = "Option::is_none")]
    pub end_line: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PhysicalLocation {
    #[serde(rename = "artifactLocation")]
    pub artifact_location: ArtifactLocation,
    pub region: Region,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Location {
    #[serde(rename = "physicalLocation")]
    pub physical_location: PhysicalLocation,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RelatedLocation {
    #[serde(rename = "physicalLocation")]
    pub physical_location: PhysicalLocation,
    pub message: MessageText,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolComponentRef {
    pub name: String,
    pub guid: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TaxonRef {
    #[serde(rename = "toolComponent")]
    pub tool_component: ToolComponentRef,
    pub id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ResultProperties {
    pub severity: String,
    #[serde(rename = "security-severity")]
    pub security_severity: String,
    #[serde(rename = "cvssRating")]
    pub cvss_rating: String,
    pub category: String,
    #[serde(rename = "cvssVector", skip_serializing_if = "Option::is_none")]
    pub cvss_vector: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwe: Option<String>,
    #[serde(rename = "cweId", skip_serializing_if = "Option::is_none")]
    pub cwe_id: Option<String>,
    #[serde(rename = "cweName", skip_serializing_if = "Option::is_none")]
    pub cwe_name: Option<String>,
    #[serde(rename = "cvssScore", skip_serializing_if = "Option::is_none")]
    pub cvss_score: Option<f64>,
    #[serde(
        rename = "vulContextSeverityVector",
        skip_serializing_if = "Option::is_none"
    )]
    pub vul_context_severity_vector: Option<String>,
    #[serde(
        rename = "vulContextSeverityScore",
        skip_serializing_if = "Option::is_none"
    )]
    pub vul_context_severity_score: Option<f64>,
    #[serde(
        rename = "vulContextSeverityRating",
        skip_serializing_if = "Option::is_none"
    )]
    pub vul_context_severity_rating: Option<String>,
    #[serde(rename = "offensivePriority", skip_serializing_if = "Option::is_none")]
    pub offensive_priority: Option<String>,
    #[serde(
        rename = "offensivePriorityLabel",
        skip_serializing_if = "Option::is_none"
    )]
    pub offensive_priority_label: Option<String>,
    #[serde(
        rename = "offensivePriorityReason",
        skip_serializing_if = "Option::is_none"
    )]
    pub offensive_priority_reason: Option<String>,
    pub confidence: f64,
    pub votes: i64,
    pub description: String,
    #[serde(
        rename = "dedupRelatedLocationCount",
        skip_serializing_if = "Option::is_none"
    )]
    pub dedup_related_location_count: Option<usize>,
    /// Phase 3's S11 panel verdict (`"Fixed"`/`"Partially Fixed"`/
    /// `"Not Fixed"`/`"UNVERIFIABLE"`) for this finding's remediation, if
    /// validation ran for it — see [`crate::build_sarif_with_validations`].
    #[serde(rename = "validationStatus", skip_serializing_if = "Option::is_none")]
    pub validation_status: Option<String>,
    #[serde(rename = "validationScore", skip_serializing_if = "Option::is_none")]
    pub validation_score: Option<f64>,
    #[serde(
        rename = "validationJustification",
        skip_serializing_if = "Option::is_none"
    )]
    pub validation_justification: Option<String>,
    #[serde(rename = "mergeReadiness", skip_serializing_if = "Option::is_none")]
    pub merge_readiness: Option<String>,
    /// Phase 2's S10 verdict for this finding (`"Fixed"`/`"Not Fixed"`/
    /// `"Denied"`/…, or the policy gate's own capped `final_verdict` when
    /// it overrode the agent's), when remediation ran for it.
    ///
    /// Distinct from [`Self::validation_status`]: that is S11's
    /// independent grade OF a fix, this is what the remediator itself
    /// concluded. A consumer needs both to tell "no fix was attempted"
    /// from "a fix was attempted and rejected" — the second is a triage
    /// signal, the first is a work item. Set by the CLI's report
    /// augmentation pass, not by `build_result`, which has no remediation
    /// data in scope.
    #[serde(rename = "remediationStatus", skip_serializing_if = "Option::is_none")]
    pub remediation_status: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SarifResult {
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    pub level: String,
    pub message: MessageText,
    pub locations: Vec<Location>,
    #[serde(
        rename = "relatedLocations",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub related_locations: Vec<RelatedLocation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rank: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub taxa: Option<Vec<TaxonRef>>,
    #[serde(rename = "partialFingerprints")]
    pub partial_fingerprints: BTreeMap<String, String>,
    /// SARIF's own baseline-comparison field: `"new"` / `"unchanged"` /
    /// `"updated"` / `"absent"`, set by comparing this run's results
    /// against a baseline run. Omitted entirely when unset, which is what
    /// every consumer treats as "no baseline information" — so emitting it
    /// is purely additive for anything already reading these documents.
    ///
    /// Populated by the later baseline-diff feature (a scan run with a
    /// `--baseline report.sarif`), which matches results across runs by
    /// `partialFingerprints` — see [`crate::FINGERPRINT_KEY_V2`], the
    /// stable-across-re-scans identity that makes such a comparison
    /// meaningful in the first place. Nothing in the pipeline sets it yet;
    /// [`SarifResult::with_baseline_state`] is the entry point when it
    /// does.
    #[serde(
        rename = "baselineState",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub baseline_state: Option<String>,
    pub properties: ResultProperties,
}

impl SarifResult {
    /// Tag this result with a SARIF `baselineState`. Consuming/returning
    /// `self` so a baseline-diff pass can map over freshly built results
    /// (`results.into_iter().map(|r| r.with_baseline_state(...))`) without
    /// having to make the whole vector mutable.
    pub fn with_baseline_state(mut self, state: impl Into<String>) -> Self {
        self.baseline_state = Some(state.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Notification {
    pub level: String,
    pub message: MessageText,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Invocation {
    #[serde(rename = "executionSuccessful")]
    pub execution_successful: bool,
    #[serde(
        rename = "toolExecutionNotifications",
        skip_serializing_if = "Option::is_none"
    )]
    pub tool_execution_notifications: Option<Vec<Notification>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct RunProperties {
    #[serde(rename = "applicationId")]
    pub application_id: String,
    #[serde(rename = "cmdbSource", skip_serializing_if = "Option::is_none")]
    pub cmdb_source: Option<String>,
    #[serde(rename = "applicationName", skip_serializing_if = "Option::is_none")]
    pub application_name: Option<String>,
    #[serde(rename = "scanDegraded")]
    pub scan_degraded: bool,
    #[serde(rename = "unrankedFallback")]
    pub unranked_fallback: bool,
}
