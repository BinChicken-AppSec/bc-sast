use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::finding::{Finding, VulnClass};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationEvidence {
    pub verdict: crate::Verdict,
    pub confidence: i64,
    pub reason: String,
    pub reasoning: String,
    #[serde(default)]
    pub cvss_vector: Option<String>,
}

impl VerificationEvidence {
    pub fn from_finding(finding: &Finding) -> Option<Self> {
        Some(Self {
            verdict: finding.verdict?,
            confidence: finding.verdict_confidence?,
            reason: finding.verdict_reason.clone(),
            reasoning: finding.verifier_reasoning.clone(),
            cvss_vector: finding.cvss_vector.clone(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

pub fn offensive_label(tier: &str) -> Option<&'static str> {
    match tier {
        "P1" => Some("Externally Exploitable, No Auth"),
        "P2" => Some("Externally Exploitable, Obtainable Auth"),
        "P3" => Some("Internal Network / Privileged Position"),
        "P4" => Some("Code-Knowledge / Insider Dependent"),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Chain {
    pub title: String,
    pub steps: Vec<i64>,
    pub severity: Severity,
    #[serde(default)]
    pub blocked_by_controls: Vec<String>,
    pub narrative: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RankedFinding {
    pub finding: Finding,
    pub severity: Severity,
    pub exploitability_notes: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DropReason {
    FalsePositive,
    VerifyError,
    Duplicate,
    Unconfirmed,
    Excluded,
    GuardrailBlocked,
    OutOfDiffScope,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DroppedFinding {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provider_origins: Vec<crate::ProviderOrigin>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification: Option<VerificationEvidence>,
    pub file: String,
    pub line: i64,
    pub vuln_class: VulnClass,
    pub title: String,
    pub chunk_id: String,
    pub reason: DropReason,
    #[serde(default)]
    pub detail: String,
    #[serde(default)]
    pub canonical_idx: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeKind {
    Risk,
    Catchall,
    Specialist,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScopeEntry {
    pub name: String,
    pub kind: ScopeKind,
    pub files: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct StageTiming {
    pub outcome: String,
    #[serde(default)]
    pub duration_sec: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ScanMetrics {
    #[serde(default)]
    pub scan_id: String,
    #[serde(default)]
    pub scan_uuid: String,
    #[serde(default)]
    pub module_name: String,
    #[serde(default)]
    pub start_ts: String,
    #[serde(default)]
    pub end_ts: String,
    #[serde(default)]
    pub duration_sec: f64,
    #[serde(default)]
    pub total_files_in_scope: i64,
    #[serde(default)]
    pub analyzed_files_unique: i64,
    #[serde(default)]
    pub chunks_total: i64,
    #[serde(default)]
    pub chunks_risk: i64,
    #[serde(default)]
    pub chunks_catchall: i64,
    #[serde(default)]
    pub chunks_specialist: i64,
    #[serde(default)]
    pub chunks_attempted: i64,
    #[serde(default)]
    pub chunks_failed: i64,
    #[serde(default)]
    pub errors_by_stage: BTreeMap<String, i64>,
    #[serde(default)]
    pub errors_log_path: String,
    #[serde(default)]
    pub budget_stop: String,
    #[serde(default)]
    pub canceled: bool,
    #[serde(default)]
    pub files_by_disposition: BTreeMap<String, i64>,
    #[serde(default)]
    pub files_not_reviewed: BTreeMap<String, crate::FileDisposition>,
    #[serde(default)]
    pub loc_in_scope_by_language: BTreeMap<String, i64>,
    #[serde(default)]
    pub loc_scanned_by_language: BTreeMap<String, i64>,
    #[serde(default)]
    pub raw_findings_count: i64,
    #[serde(default)]
    pub true_positive_count: i64,
    #[serde(default)]
    pub false_positive_count: i64,
    #[serde(default)]
    pub duplicate_count: i64,
    #[serde(default)]
    pub prompt_tokens: Option<i64>,
    #[serde(default)]
    pub completion_tokens: Option<i64>,
    #[serde(default)]
    pub total_tokens: Option<i64>,
    #[serde(default)]
    pub cache_read_tokens: Option<i64>,
    #[serde(default)]
    pub cache_write_tokens: Option<i64>,
    #[serde(default)]
    pub tokens_by_phase: Option<BTreeMap<String, Value>>,
    #[serde(default)]
    pub llm_truncated_replies: i64,
    #[serde(default)]
    pub pipeline_diagnostics: crate::PipelineDiagnostics,
    #[serde(default)]
    pub stage_timings: BTreeMap<String, StageTiming>,
    #[serde(default)]
    pub cost_usd: Option<f64>,
    #[serde(default)]
    pub unpriced_tokens: Option<i64>,
    #[serde(default)]
    pub unpriced_calls: Option<i64>,
    #[serde(default)]
    pub unpriced_models: Vec<String>,
    #[serde(default)]
    pub folders_scanned: Vec<String>,
    #[serde(default)]
    pub scope: Vec<ScopeEntry>,
    #[serde(default)]
    pub excluded: BTreeMap<String, Value>,
    #[serde(default)]
    pub changed_files_count: i64,
    #[serde(default)]
    pub diff_scope_active: bool,
}

impl ScanMetrics {
    pub fn coverage_pct(&self) -> f64 {
        if self.total_files_in_scope == 0 {
            0.0
        } else {
            self.analyzed_files_unique as f64 / self.total_files_in_scope as f64 * 100.0
        }
    }

    pub fn verification_precision_pct(&self) -> f64 {
        if self.raw_findings_count == 0 {
            0.0
        } else {
            self.true_positive_count as f64 / self.raw_findings_count as f64 * 100.0
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FinalReport {
    #[serde(default)]
    pub provider_ledger: crate::ProviderLedger,
    pub repo_root: String,
    #[serde(default)]
    pub repo_name: Option<String>,
    #[serde(default)]
    pub git_sha: Option<String>,
    #[serde(default)]
    pub repo_identity: Option<crate::RepoIdentity>,
    pub findings: Vec<RankedFinding>,
    pub chains: Vec<Chain>,
    #[serde(default)]
    pub dropped: Vec<DroppedFinding>,
    #[serde(default)]
    pub raw_findings_count: i64,
    #[serde(default)]
    pub metrics: Option<ScanMetrics>,
    #[serde(default)]
    pub threat_model: Option<crate::context::ThreatModel>,
    #[serde(default)]
    pub app_profile: Option<crate::context::AppProfile>,
    pub summary: String,
    #[serde(default)]
    pub degraded: bool,
    #[serde(default)]
    pub degraded_reason: String,
    #[serde(default)]
    pub unreachable_files: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("P1", Some("Externally Exploitable, No Auth"))]
    #[case("P2", Some("Externally Exploitable, Obtainable Auth"))]
    #[case("P3", Some("Internal Network / Privileged Position"))]
    #[case("P4", Some("Code-Knowledge / Insider Dependent"))]
    #[case("P5", None)]
    #[case("", None)]
    fn offensive_label_cases(#[case] tier: &str, #[case] expected: Option<&str>) {
        assert_eq!(offensive_label(tier), expected);
    }

    #[rstest]
    #[case(Severity::Critical, "critical")]
    #[case(Severity::High, "high")]
    #[case(Severity::Medium, "medium")]
    #[case(Severity::Low, "low")]
    #[case(Severity::Info, "info")]
    fn severity_wire_format(#[case] s: Severity, #[case] wire: &str) {
        assert_eq!(serde_json::to_value(s).unwrap(), serde_json::json!(wire));
        let back: Severity = serde_json::from_value(serde_json::json!(wire)).unwrap();
        assert_eq!(back, s);
    }

    #[rstest]
    #[case(DropReason::FalsePositive, "FALSE_POSITIVE")]
    #[case(DropReason::VerifyError, "VERIFY_ERROR")]
    #[case(DropReason::Duplicate, "DUPLICATE")]
    #[case(DropReason::Unconfirmed, "UNCONFIRMED")]
    #[case(DropReason::Excluded, "EXCLUDED")]
    #[case(DropReason::GuardrailBlocked, "GUARDRAIL_BLOCKED")]
    #[case(DropReason::OutOfDiffScope, "OUT_OF_DIFF_SCOPE")]
    fn drop_reason_wire_format(#[case] r: DropReason, #[case] wire: &str) {
        assert_eq!(serde_json::to_value(r).unwrap(), serde_json::json!(wire));
        let back: DropReason = serde_json::from_value(serde_json::json!(wire)).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn dropped_finding_defaults() {
        let d: DroppedFinding = serde_json::from_value(serde_json::json!({
            "file": "a.py", "line": 1, "vuln_class": "other",
            "title": "t", "chunk_id": "c1", "reason": "DUPLICATE"
        }))
        .unwrap();
        assert_eq!(d.detail, "");
        assert_eq!(d.canonical_idx, None);
    }

    #[test]
    fn scan_metrics_telemetry_fields_default_when_absent_and_round_trip() {
        let old: ScanMetrics = serde_json::from_value(serde_json::json!({})).unwrap();
        assert_eq!(old.cache_read_tokens, None);
        assert_eq!(old.llm_truncated_replies, 0);
        assert!(old.stage_timings.is_empty());

        let mut m = ScanMetrics {
            cache_read_tokens: Some(9),
            cache_write_tokens: Some(4),
            llm_truncated_replies: 2,
            ..Default::default()
        };
        m.stage_timings.insert(
            "s4".to_string(),
            StageTiming {
                outcome: "completed".to_string(),
                duration_sec: Some(1.5),
            },
        );
        let json = serde_json::to_value(&m).unwrap();
        assert_eq!(json["stage_timings"]["s4"]["duration_sec"], 1.5);
        let back: ScanMetrics = serde_json::from_value(json).unwrap();
        assert_eq!(back, m);
        let timing: StageTiming =
            serde_json::from_value(serde_json::json!({"outcome": "cached"})).unwrap();
        assert_eq!(timing.duration_sec, None);
    }

    #[test]
    fn scan_metrics_coverage_pct_zero_when_no_files_in_scope() {
        let m = ScanMetrics::default();
        assert_eq!(m.coverage_pct(), 0.0);
    }

    #[test]
    fn scan_metrics_coverage_pct_computed() {
        let m = ScanMetrics {
            total_files_in_scope: 200,
            analyzed_files_unique: 50,
            ..Default::default()
        };
        assert_eq!(m.coverage_pct(), 25.0);
    }

    #[test]
    fn scan_metrics_verification_precision_pct_zero_when_no_raw_findings() {
        let m = ScanMetrics::default();
        assert_eq!(m.verification_precision_pct(), 0.0);
    }

    #[test]
    fn scan_metrics_verification_precision_pct_computed() {
        let m = ScanMetrics {
            raw_findings_count: 10,
            true_positive_count: 3,
            ..Default::default()
        };
        assert_eq!(m.verification_precision_pct(), 30.0);
    }

    #[test]
    fn scope_entry_kind_wire_format() {
        let e: ScopeEntry = serde_json::from_value(serde_json::json!({
            "name": "chunk-01", "kind": "catchall", "files": ["a.py"]
        }))
        .unwrap();
        assert_eq!(e.kind, ScopeKind::Catchall);
    }

    #[test]
    fn final_report_round_trips_and_defaults() {
        let report = FinalReport {
            repo_identity: None,
            provider_ledger: Default::default(),
            repo_root: "/r".to_string(),
            repo_name: None,
            git_sha: None,
            findings: vec![],
            chains: vec![],
            dropped: vec![],
            raw_findings_count: 0,
            metrics: None,
            threat_model: None,
            app_profile: None,
            summary: "clean scan".to_string(),
            degraded: false,
            degraded_reason: String::new(),
            unreachable_files: Vec::new(),
        };
        let v = serde_json::to_value(&report).unwrap();
        let back: FinalReport = serde_json::from_value(v).unwrap();
        assert_eq!(report, back);
    }

    #[test]
    fn final_report_missing_optional_fields_default_correctly() {
        let r: FinalReport = serde_json::from_value(serde_json::json!({
            "repo_root": "/r",
            "findings": [],
            "chains": [],
            "summary": "s",
        }))
        .unwrap();
        assert!(r.dropped.is_empty());
        assert_eq!(r.raw_findings_count, 0);
        assert!(!r.degraded);
        assert_eq!(r.degraded_reason, "");
    }
}

#[cfg(test)]
mod verification_evidence_compatibility_tests {
    use super::*;

    #[test]
    fn old_dropped_records_remain_unverified_without_inventing_provider_origins() {
        let record: DroppedFinding = serde_json::from_value(serde_json::json!({
            "file":"a.rs", "line":10, "vuln_class":"injection", "title":"candidate",
            "chunk_id":"c", "reason":"FALSE_POSITIVE", "detail":"legacy reason"
        }))
        .unwrap();
        assert!(record.provider_origins.is_empty());
        assert!(record.verification.is_none());
    }

    #[test]
    fn dropped_evidence_roundtrips_without_changing_the_gate_disposition() {
        let record: DroppedFinding = serde_json::from_value(serde_json::json!({
            "file":"a.rs", "line":10, "vuln_class":"injection", "title":"candidate",
            "chunk_id":"c", "reason":"UNCONFIRMED", "detail":"below confidence gate",
            "verification": {"verdict":"TRUE_POSITIVE", "confidence":4,
                "reason":"supported but uncertain reachability", "reasoning":"original trace", "cvss_vector":null}
        })).unwrap();
        let decoded: DroppedFinding =
            serde_json::from_str(&serde_json::to_string(&record).unwrap()).unwrap();
        assert_eq!(record, decoded);
        assert_eq!(decoded.reason, DropReason::Unconfirmed);
        assert_eq!(
            decoded.verification.unwrap().verdict,
            crate::Verdict::TruePositive
        );
    }
}
