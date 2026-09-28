//! Step 8 output: the final report's data shape — `FinalReport` itself
//! minus its `to_markdown()` renderer (see the crate-level doc comment).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::finding::{Finding, VulnClass};

/// The verifier's assessment of this individual candidate, before deduplication.
/// This is model evidence, not a provider state or proof of remediation.
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
    /// Snapshot only an actual completed assessment; never synthesize one from
    /// another member of a deduplication cluster.
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

/// P1-P4 offensive-exploitability tier labels.
pub fn offensive_label(tier: &str) -> Option<&'static str> {
    match tier {
        "P1" => Some("Externally Exploitable, No Auth"),
        "P2" => Some("Externally Exploitable, Obtainable Auth"),
        "P3" => Some("Internal Network / Privileged Position"),
        "P4" => Some("Code-Knowledge / Insider Dependent"),
        _ => None,
    }
}

/// Multi-step exploit path that combines several findings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Chain {
    pub title: String,
    /// Indices into `FinalReport.findings`.
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
    /// Chain-pass LLM commentary, including mitigations.
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
    /// Retained-but-not-reported: a finding whose file is outside a
    /// `--diff-scope` run's changed-file set. Distinct from every reason
    /// above because nothing was *judged* here — the finding was never
    /// analyzed by this scan at all, so calling it a false positive, an
    /// exclusion or a guardrail block would each be a claim this run has
    /// no evidence for.
    ///
    /// Produced at the third-party provider merge point (see
    /// `bc_orchestrator::run_scan`): a vendor's pre-existing finding in an
    /// untouched file is real information about the repository and is kept
    /// verbatim in [`FinalReport::dropped`], but it is not this pull
    /// request's responsibility, is not counted as a finding, is never
    /// posted as a PR comment, and is never a remediation candidate.
    OutOfDiffScope,
}

/// Audit-trail entry for a finding removed before the final report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DroppedFinding {
    /// Original provider identities, independent of a canonical finding's verdict.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provider_origins: Vec<crate::ProviderOrigin>,
    /// Absent for skipped, malformed, failed or otherwise unverified sessions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification: Option<VerificationEvidence>,
    pub file: String,
    pub line: i64,
    pub vuln_class: VulnClass,
    pub title: String,
    pub chunk_id: String,
    pub reason: DropReason,
    /// Verdict reason / error text / dedup reasoning.
    #[serde(default)]
    pub detail: String,
    /// For `Duplicate`: index into `FinalReport.findings`.
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

/// One analysis unit (chunk) in the scope appendix.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScopeEntry {
    pub name: String,
    pub kind: ScopeKind,
    pub files: Vec<String>,
}

/// One stage's terminal outcome and how long its body ran, mirroring a
/// Python `StageRecord` (`util/stage_telemetry.py`) minus the label.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct StageTiming {
    /// `completed`, `completed_with_errors`, `cached`, `skipped`,
    /// `disabled` or `error` (`bc_pipeline_core::StageStatus::as_str`).
    pub outcome: String,
    /// `None` for a stage that ran no timed body (cached, skipped,
    /// disabled): an unknown duration, not a zero one.
    #[serde(default)]
    pub duration_sec: Option<f64>,
}

/// Coverage + verification stats rendered at the top of the report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ScanMetrics {
    #[serde(default)]
    pub scan_id: String,
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
    /// Coarser than Python's own `util/errlog`-backed per-record tally
    /// (that's a file-backed JSONL log this port doesn't have) — see
    /// `bc_orchestrator::build_metrics`'s own doc comment for exactly
    /// what does and doesn't get counted here.
    #[serde(default)]
    pub errors_by_stage: BTreeMap<String, i64>,
    /// Always empty — no file-backed error log exists in this port (see
    /// `errors_by_stage`'s own doc comment).
    #[serde(default)]
    pub errors_log_path: String,
    /// Non-empty when `--max-tokens`/`--max-scan-seconds` ran out: which
    /// budget it was and how far the scan got before it stopped starting
    /// new work (e.g. `"S6: token budget of 3000000 reached (3012044
    /// spent) — 412 of 1881 finding(s) verified, 1469 left unverified"`).
    /// Rendered by `bc_report_md`'s `## Scan Health` section.
    ///
    /// Net-new versus Python, which has no budget knob at all. Empty is
    /// the normal case: the scan finished everything it set out to do.
    #[serde(default)]
    pub budget_stop: String,
    /// `true` when the operator canceled the run (Ctrl-C) and the scan
    /// stopped starting new work, the same fall-through a budget stop
    /// takes. [`ScanMetrics::budget_stop`] then names the point it
    /// stopped at. Rendered by `bc_report_md`'s `## Scan Health` as a
    /// cancellation rather than a budget, so a partial report is never
    /// mistaken for a finished one. Net-new versus Python, whose Ctrl-C
    /// abandons the run and writes no report.
    #[serde(default)]
    pub canceled: bool,
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
    /// Cache-read tokens summed over every phase. Kept out of
    /// `prompt_tokens`/`total_tokens` (`util/tokens.py:54-61`: a cache
    /// read is ~10% of the input rate and would otherwise dominate the
    /// headline) but reported here so the run total is not silently
    /// smaller than the per-phase `cache_read` buckets add up to. `None`
    /// when no backend reported usage at all.
    #[serde(default)]
    pub cache_read_tokens: Option<i64>,
    /// Cache-write tokens summed over every phase. Already included in
    /// `prompt_tokens` (they are billable input), broken out here so a
    /// reader can see how much of the prompt figure they are. `None` when
    /// no backend reported usage at all.
    #[serde(default)]
    pub cache_write_tokens: Option<i64>,
    #[serde(default)]
    pub tokens_by_phase: Option<BTreeMap<String, Value>>,
    /// Model replies the transport gave up on as truncated (VVAH-E005)
    /// across the scan: the Rust counterpart of Python's
    /// `COUNTERS["llm_truncated_replies"]`. A truncation the doubled-
    /// budget retry fixed is not counted. Each one is a chunk or session
    /// whose result was lost, so a non-zero value explains a gap.
    #[serde(default)]
    pub llm_truncated_replies: i64,
    /// What the pipeline's guards, repairs and caps did, stage by stage
    /// (see [`crate::PipelineDiagnostics`]). Rendered as `### Pipeline
    /// Diagnostics` only when something in it is noteworthy.
    #[serde(default)]
    pub pipeline_diagnostics: crate::PipelineDiagnostics,
    /// Per-stage outcome and wall-clock duration for the stages that ran
    /// before this report was assembled (S0-S8), keyed by stage id
    /// (`"s4"`). Ported from Python's `STAGES` recorder
    /// (`util/stage_telemetry.py`). S9-S11 run after the report exists,
    /// so their timings are in the run manifest only.
    #[serde(default)]
    pub stage_timings: BTreeMap<String, StageTiming>,
    /// What this run's model calls cost, in US dollars, summed one
    /// already-priced call at a time (see `bc_orchestrator::pricing` for
    /// why per call and not per phase). A lower bound whenever
    /// [`ScanMetrics::unpriced_tokens`] is non-zero.
    ///
    /// `None` means no figure can honestly be given: either no backend
    /// reported usage at all, or nothing this run called had a published
    /// rate. `Some(0.0)` is reserved for a run that really was priced and
    /// really was free. `f64` rather than an exact integer because this
    /// is the reporting surface, not the arithmetic: the sum itself is
    /// computed in exact integer picodollars and converted once, here, so
    /// it does not depend on the order the phases finished in.
    ///
    /// Net-new versus Python, which reports tokens and no money at all.
    #[serde(default)]
    pub cost_usd: Option<f64>,
    /// Tokens that contributed nothing to [`ScanMetrics::cost_usd`],
    /// because no rate was published for them: every billable token of a
    /// call whose provider and model resolved to nothing, plus the
    /// individually unrated tokens of a call that priced but whose model
    /// publishes no cache rate. Non-zero means the cost is a lower bound
    /// and the report says so. `None` when no usage was recorded at all.
    #[serde(default)]
    pub unpriced_tokens: Option<i64>,
    /// How many calls could not be priced at all, the call-count
    /// counterpart of [`ScanMetrics::unpriced_tokens`]. `None` when no
    /// usage was recorded at all.
    #[serde(default)]
    pub unpriced_calls: Option<i64>,
    /// The distinct `provider/model` pairs this run could not price, in
    /// sorted order. These are the exact keys an operator would add to
    /// `pricing.rates` in `--config` to close the gap. Empty on a fully
    /// priced run.
    #[serde(default)]
    pub unpriced_models: Vec<String>,
    #[serde(default)]
    pub folders_scanned: Vec<String>,
    #[serde(default)]
    pub scope: Vec<ScopeEntry>,
    #[serde(default)]
    pub excluded: BTreeMap<String, Value>,
    /// `--diff-scope`'s changed-file count. `0` is ambiguous on its own —
    /// it is equally "no diff scoping" and "diff scoping that matched
    /// nothing" — so pair it with [`ScanMetrics::diff_scope_active`],
    /// which is what `bc-report-md` branches on.
    /// `analyzed_files_unique`/`total_files_in_scope` alone can't tell a
    /// reader "intentional diff-scope, 3 of 2000 files" apart from "the
    /// scan silently failed"; this field is what lets `bc-report-md`
    /// render an explicit scope line instead of leaving the coverage
    /// line to speak for itself.
    #[serde(default)]
    pub changed_files_count: i64,
    /// Whether `--diff-scope` was in effect for this run. Carried
    /// separately from `changed_files_count` so the scope line still
    /// renders for a legitimately empty diff (a rename-only PR), where a
    /// bare `changed_files_count > 0` test would silently drop the one
    /// line telling the reader why almost nothing was analyzed.
    /// `false` (the default) means a full-repo scan.
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

    /// Ported from `ScanMetrics.verification_precision_pct`
    /// (`models.py:1391-1394`) for 1:1 parity with the Python class's full
    /// API surface — genuinely unrendered/unreferenced in the Python
    /// original itself (grep confirms zero callers there too, not just in
    /// this port), so kept rather than deleted despite having no current
    /// Rust caller either: dropping a faithfully-ported method the source
    /// class still defines would be a parity regression, not a cleanup.
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
    /// Pre-filter provider assessment inventory, independent of ranked findings.
    #[serde(default)]
    pub provider_ledger: crate::ProviderLedger,
    pub repo_root: String,
    /// Used for the report title; from `repos.txt`/`.csv`.
    #[serde(default)]
    pub repo_name: Option<String>,
    /// HEAD at scan time; step 10 refuses to remediate on a mismatch.
    #[serde(default)]
    pub git_sha: Option<String>,
    pub findings: Vec<RankedFinding>,
    pub chains: Vec<Chain>,
    #[serde(default)]
    pub dropped: Vec<DroppedFinding>,
    /// Pre-verification count.
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
    /// `step3.catchall_mode=reachable_only` — files NOT reviewed because
    /// they weren't on any entry→…→sink call-graph path. Rendered as an
    /// appendix so the report never silently truncates coverage. Always
    /// empty unless BOTH that mode and `output.emit_unreachable_appendix`
    /// are set (`taint.yaml` only — never `default.yaml`). Ported from
    /// `models.py::FinalReport.unreachable_files`.
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
        // A report written before these fields existed still loads.
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
