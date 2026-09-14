//! S9: deterministic report generation from S8's structured findings.
//! The CLI publishes these artifacts and the same redacted report as CSV/JSON.
use bc_model::FinalReport;
use bc_pipeline_core::{PipelineStage, StageError, StageOutcome};

pub struct ReportingOutput {
    pub report: FinalReport,
    pub provider_writeback_plan: String,
    pub markdown: String,
    pub sarif: String,
}

pub struct Stage9 {
    pub tool_version: String,
}

pub(super) fn redact_report(report: &FinalReport) -> Result<FinalReport, StageError> {
    let value = serde_json::to_value(report).map_err(|e| StageError::new("s9", e.to_string()))?;
    serde_json::from_value(bc_redact::redact_tree(&value))
        .map_err(|e| StageError::new("s9", e.to_string()))
}

impl PipelineStage for Stage9 {
    type Input = FinalReport;
    type Output = ReportingOutput;
    const NAME: &'static str = "s9";

    async fn run(&self, input: FinalReport) -> Result<StageOutcome<ReportingOutput>, StageError> {
        let report = redact_report(&input)?;
        let provider_writeback_plan = render_provider_plan(&report)?;
        let markdown = bc_report_md::render_markdown(&report);
        let sarif =
            serde_json::to_string_pretty(&bc_sarif::build_sarif(&report, &self.tool_version))
                .map_err(|e| StageError::new(Self::NAME, e.to_string()))?;
        Ok(StageOutcome::Ok(ReportingOutput {
            report,
            provider_writeback_plan,
            markdown,
            sarif,
        }))
    }
}

/// Build proposals from the pre-filter ledger, never from absent final findings.
fn render_provider_plan(report: &FinalReport) -> Result<String, StageError> {
    use bc_thirdparty_api::writeback::{
        plan_updates, AssessmentInput, AssessmentOutcome, PlanningContext,
    };
    let ledger = &report.provider_ledger;
    let assessments: Vec<_> = ledger
        .assessments
        .iter()
        .map(|record| {
            let outcome = match (&record.verification, record.drop_reason) {
                (Some(_), _) if !record.limitations.is_empty() => AssessmentOutcome::Inconclusive,
                (Some(v), None) if v.verdict == bc_model::Verdict::TruePositive => {
                    AssessmentOutcome::Confirmed
                }
                (Some(v), Some(bc_model::DropReason::FalsePositive))
                    if v.verdict == bc_model::Verdict::FalsePositive =>
                {
                    AssessmentOutcome::FalsePositive
                }
                (None, _) => AssessmentOutcome::Unassessed,
                _ => AssessmentOutcome::Inconclusive,
            };
            AssessmentInput {
                origin: record.origin.clone(),
                outcome,
                confidence: record
                    .verification
                    .as_ref()
                    .map(|v| v.confidence as f64 / 10.0),
                evidence: record
                    .verification
                    .as_ref()
                    .filter(|v| !v.reason.trim().is_empty() || !v.reasoning.trim().is_empty())
                    .map(|v| {
                        vec![
                            format!("{}:{} {}", record.file, record.line, record.title),
                            v.reason.clone(),
                            v.reasoning.clone(),
                        ]
                    })
                    .unwrap_or_default(),
                assessed_severity: None,
                independent_review: false,
            }
        })
        .collect();
    let origins: Vec<_> = assessments.iter().map(|a| a.origin.clone()).collect();
    let plan = plan_updates(
        &origins,
        &assessments,
        &PlanningContext {
            full_scan: ledger.full_scan && !ledger.resumed,
            scan_complete: ledger.analysis_complete && !report.degraded,
            // Current clients cannot enumerate provider-side filtered/skipped items.
            inventory_complete: !ledger.ingestion.is_empty()
                && ledger
                    .ingestion
                    .iter()
                    .all(|source| source.completed && source.limitations.is_empty()),
            git_ref: None,
            revision: report.git_sha.clone(),
        },
    );
    // Include ingestion errors even when no provider findings were returned.
    let value = serde_json::json!({"plan": plan, "ingestion": ledger.ingestion, "assessments": ledger.assessments,
        "scan": {"git_sha": report.git_sha, "full_scan": ledger.full_scan,
            "resumed": ledger.resumed, "analysis_complete": ledger.analysis_complete},
        "limitations": ["Automatic publication uses --provider-writeback apply and records native outcomes separately",
            "Branch and provider inventory completeness require trusted reconciliation"]});
    serde_json::to_string_pretty(&bc_redact::redact_tree(&value))
        .map_err(|e| StageError::new("s9", e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_model::ScanMetrics;

    /// The one report shape that really cannot survive the redaction round
    /// trip: a non-finite float. JSON has no spelling for it, so
    /// `serde_json::to_value` writes `null`, and `duration_sec: f64`
    /// refuses `null` on the way back (`#[serde(default)]` fills in a
    /// *missing* field, never an explicit null one).
    ///
    /// This is why S9 returns a `StageError` here rather than the
    /// `.expect("redact_tree preserves JSON shape, so FinalReport
    /// deserializes back")` that used to live inline in `run_scan`: an
    /// unrepresentable duration is a bad number, not a reason to abort a
    /// scan that has already done all of its work.
    fn report_with_an_unrepresentable_metric() -> FinalReport {
        FinalReport {
            provider_ledger: Default::default(),
            repo_root: "/repo".to_string(),
            repo_name: None,
            git_sha: None,
            findings: Vec::new(),
            chains: Vec::new(),
            dropped: Vec::new(),
            raw_findings_count: 0,
            metrics: Some(ScanMetrics {
                duration_sec: f64::NAN,
                ..ScanMetrics::default()
            }),
            threat_model: None,
            app_profile: None,
            summary: String::new(),
            degraded: false,
            degraded_reason: String::new(),
            unreachable_files: Vec::new(),
        }
    }

    #[test]
    fn a_report_that_cannot_survive_the_redaction_round_trip_is_a_stage_error() {
        let error = redact_report(&report_with_an_unrepresentable_metric()).unwrap_err();

        assert_eq!(error.stage, "s9");
        assert_eq!(error.message, "invalid type: null, expected f64");
    }

    #[tokio::test]
    async fn the_stage_surfaces_that_failure_instead_of_rendering_a_half_report() {
        let stage = Stage9 {
            tool_version: "0.0.0-test".to_string(),
        };

        // `ReportingOutput` is deliberately not `Debug` (it carries a
        // whole rendered report), so this asserts on the discriminant
        // rather than unwrapping. The stage label itself is checked
        // directly on `redact_report` above.
        let outcome = stage.run(report_with_an_unrepresentable_metric()).await;

        assert!(
            outcome.is_err(),
            "S9 must not render a report it could not redact"
        );
    }

    fn provider_record(
        id: &str,
        verification: Option<bc_model::VerificationEvidence>,
        drop_reason: Option<bc_model::DropReason>,
    ) -> bc_model::ProviderAssessmentRecord {
        bc_model::ProviderAssessmentRecord {
            origin: bc_model::ProviderOrigin {
                provider: bc_model::ProviderKind::Semgrep,
                product: bc_model::ProviderProduct::Sast,
                source: bc_model::ProviderSource::Api,
                native_ids: bc_model::ProviderNativeIds {
                    issue_id: Some(id.into()),
                    ..Default::default()
                },
                tenant_id: Some("deployment".into()),
                git_ref: Some("main".into()),
                revision: Some("commit".into()),
                state: Some("open".into()),
                ..Default::default()
            },
            file: "src/app.rs".into(),
            line: 10,
            title: format!("candidate {id}"),
            verification,
            drop_reason,
            limitations: Vec::new(),
        }
    }

    fn evidence(verdict: bc_model::Verdict, confidence: i64) -> bc_model::VerificationEvidence {
        bc_model::VerificationEvidence {
            verdict,
            confidence,
            reason: "Concrete code preconditions and applicable control".into(),
            reasoning: "Inspected the input binding and sink implementation".into(),
            cvss_vector: None,
        }
    }

    fn provider_report(records: Vec<bc_model::ProviderAssessmentRecord>) -> FinalReport {
        let mut report = report_with_an_unrepresentable_metric();
        report.metrics = None;
        report.git_sha = Some("commit".into());
        report.provider_ledger = bc_model::ProviderLedger {
            assessments: records,
            ingestion: vec![bc_model::ProviderIngestionRecord {
                source: "semgrep".into(),
                imported_count: 1,
                completed: true,
                limitations: Vec::new(),
            }],
            full_scan: true,
            resumed: false,
            analysis_complete: true,
        };
        report
    }

    #[tokio::test]
    async fn filtered_final_findings_do_not_erase_the_original_false_positive_ledger() {
        let record = provider_record(
            "123",
            Some(evidence(bc_model::Verdict::FalsePositive, 9)),
            Some(bc_model::DropReason::FalsePositive),
        );
        // The report represents a framework-filtered output with zero final
        // findings. Publication decisions must still use the pre-filter ledger.
        let report = provider_report(vec![record.clone()]);
        assert!(report.findings.is_empty());
        let output = Stage9 {
            tool_version: "test".into(),
        }
        .run(report)
        .await
        .unwrap()
        .into_value();
        assert_eq!(output.report.provider_ledger.assessments, [record]);
        let plan: serde_json::Value =
            serde_json::from_str(&output.provider_writeback_plan).unwrap();
        assert_eq!(plan["plan"]["entries"].as_array().unwrap().len(), 1);
        assert_eq!(plan["plan"]["entries"][0]["outcome"], "false_positive");
        assert_eq!(plan["plan"]["apply_enabled"], false);
        assert_eq!(plan["plan"]["entries"][0]["apply_enabled"], false);
        assert!(plan["plan"]["entries"][0]["blocking_reasons"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("publication_requires_approval")));
    }

    #[test]
    fn failure_and_guardrail_ledger_records_remain_unassessed_with_no_payload() {
        for reason in [
            bc_model::DropReason::VerifyError,
            bc_model::DropReason::GuardrailBlocked,
            bc_model::DropReason::Unconfirmed,
        ] {
            let report = provider_report(vec![provider_record("123", None, Some(reason))]);
            let plan: serde_json::Value =
                serde_json::from_str(&render_provider_plan(&report).unwrap()).unwrap();
            let entry = &plan["plan"]["entries"][0];
            assert_eq!(entry["outcome"], "unassessed");
            assert_eq!(entry["apply_enabled"], false);
            assert!(entry["payload_previews"].as_array().unwrap().is_empty());
        }
    }

    #[test]
    fn low_confidence_or_unknown_assessments_never_become_executable_provider_updates() {
        let records = vec![
            provider_record(
                "101",
                Some(evidence(bc_model::Verdict::FalsePositive, 9)),
                Some(bc_model::DropReason::FalsePositive),
            ),
            provider_record(
                "102",
                Some(evidence(bc_model::Verdict::FalsePositive, 4)),
                Some(bc_model::DropReason::FalsePositive),
            ),
            provider_record(
                "103",
                Some(evidence(bc_model::Verdict::TruePositive, 4)),
                Some(bc_model::DropReason::Unconfirmed),
            ),
            provider_record("104", None, None),
        ];
        let plan: serde_json::Value =
            serde_json::from_str(&render_provider_plan(&provider_report(records)).unwrap())
                .unwrap();
        let entries = plan["plan"]["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 4);
        for entry in entries {
            assert_eq!(entry["apply_enabled"], false);
        }
        assert_eq!(entries[0]["outcome"], "false_positive");
        assert!(entries[1]["blocking_reasons"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("false_positive_confidence_insufficient")));
        assert_eq!(entries[2]["outcome"], "inconclusive");
        assert_eq!(entries[3]["outcome"], "unassessed");
        assert!(entries[2]["payload_previews"]
            .as_array()
            .unwrap()
            .is_empty());
        assert!(entries[3]["payload_previews"]
            .as_array()
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn provider_metadata_ledger_and_dropped_evidence_are_redacted_in_every_s9_artifact() {
        const CANARY: &str = "AKIAIOSFODNN7EXAMPLE";
        let mut record = provider_record(
            "123",
            Some(evidence(bc_model::Verdict::FalsePositive, 9)),
            Some(bc_model::DropReason::FalsePositive),
        );
        record.origin.repository_name = Some(CANARY.into());
        record.verification.as_mut().unwrap().reason = format!("Found credential {CANARY}");
        record.verification.as_mut().unwrap().reasoning = CANARY.into();
        record.limitations.push(CANARY.into());
        let mut report = provider_report(vec![record.clone()]);
        report.provider_ledger.ingestion[0]
            .limitations
            .push(format!("provider error {CANARY}"));
        report.dropped.push(bc_model::DroppedFinding {
            file: record.file,
            line: record.line,
            title: record.title,
            vuln_class: bc_model::VulnClass::Other,
            chunk_id: "imported".into(),
            reason: bc_model::DropReason::FalsePositive,
            detail: CANARY.into(),
            canonical_idx: None,
            provider_origins: vec![record.origin],
            verification: record.verification,
        });
        // The standalone renderer also redacts its output, rather than depending
        // solely on the Stage9 caller having already scrubbed the report.
        assert!(!render_provider_plan(&report).unwrap().contains(CANARY));
        let output = Stage9 {
            tool_version: "test".into(),
        }
        .run(report)
        .await
        .unwrap()
        .into_value();
        for artifact in [
            serde_json::to_string(&output.report).unwrap(),
            output.provider_writeback_plan,
            output.markdown,
            output.sarif,
        ] {
            assert!(!artifact.contains(CANARY));
        }
        assert_eq!(
            output.report.provider_ledger.assessments[0]
                .verification
                .as_ref()
                .unwrap()
                .verdict,
            bc_model::Verdict::FalsePositive
        );
    }

    #[test]
    fn ingestion_failure_with_no_findings_remains_visible_without_synthesized_triage() {
        let mut report = provider_report(Vec::new());
        report.provider_ledger.ingestion[0].completed = false;
        report.provider_ledger.ingestion[0]
            .limitations
            .push("provider unavailable".into());
        let plan: serde_json::Value =
            serde_json::from_str(&render_provider_plan(&report).unwrap()).unwrap();
        assert!(plan["plan"]["entries"].as_array().unwrap().is_empty());
        assert_eq!(plan["plan"]["apply_enabled"], false);
        assert_eq!(plan["ingestion"][0]["completed"], false);
        assert_eq!(
            plan["ingestion"][0]["limitations"][0],
            "provider unavailable"
        );
    }
}
