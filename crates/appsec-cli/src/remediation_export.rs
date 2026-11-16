use super::*;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct ChangeExport {
    pub(super) file: String,
    pub(super) summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct EvidenceExport {
    pub(super) file: String,
    pub(super) line: Option<i64>,
    pub(super) snippet: String,
}

impl From<&appsec_validation_scoring::Evidence> for EvidenceExport {
    fn from(e: &appsec_validation_scoring::Evidence) -> Self {
        EvidenceExport {
            file: e.file.clone(),
            line: e.line,
            snippet: e.snippet.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct GateResultExport {
    pub(super) gate_name: String,
    pub(super) status: String,
    pub(super) summary: String,
    pub(super) evidence: Vec<EvidenceExport>,
    pub(super) details: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) confidence: Option<String>,
}

impl From<&appsec_validation_scoring::GateResult> for GateResultExport {
    fn from(g: &appsec_validation_scoring::GateResult) -> Self {
        GateResultExport {
            gate_name: g.gate_name.as_str().to_string(),
            status: g.status.as_str().to_string(),
            summary: g.summary.clone(),
            evidence: g.evidence.iter().map(EvidenceExport::from).collect(),
            details: g.details.clone(),
            confidence: g.confidence.map(|c| c.as_str().to_string()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct ValidationScoreExport {
    pub(super) raw_score: Option<f64>,
    #[serde(default)]
    pub(super) decision: String,
    pub(super) fix_status: String,
    pub(super) justification: String,
    pub(super) gate_results: Vec<GateResultExport>,
    pub(super) has_critical_failure: bool,
}

impl From<&appsec_validation_scoring::ValidationScore> for ValidationScoreExport {
    fn from(v: &appsec_validation_scoring::ValidationScore) -> Self {
        ValidationScoreExport {
            raw_score: v.score(),
            decision: v.decision().as_str().to_string(),
            fix_status: v.fix_status.as_str().to_string(),
            justification: v.justification.clone(),
            gate_results: v.gate_results.iter().map(GateResultExport::from).collect(),
            has_critical_failure: v.has_critical_failure,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct RemediationRecordExport {
    pub(super) finding_index: i64,
    pub(super) finding_id: String,
    pub(super) verdict: String,
    pub(super) policy_action: Option<String>,
    pub(super) policy_reason: Option<String>,
    pub(super) final_verdict: Option<String>,
    pub(super) changes: Vec<ChangeExport>,
    pub(super) summary: String,
    pub(super) diff: Option<String>,
    pub(super) validation: Option<ValidationScoreExport>,
}

impl RemediationRecordExport {
    pub(super) fn from_parts(
        r: &appsec_stage_s10::RemediationRecord,
        validation: Option<&appsec_validation_scoring::ValidationScore>,
    ) -> Self {
        RemediationRecordExport {
            finding_index: r.finding_index,
            finding_id: r.finding_id.clone(),
            verdict: r.verdict.verdict.as_str().to_string(),
            policy_action: r.policy_action.clone(),
            policy_reason: r.policy_reason.clone(),
            final_verdict: r.final_verdict.clone(),
            changes: r
                .verdict
                .changes
                .iter()
                .map(|c| ChangeExport {
                    file: c.file.clone(),
                    summary: c.summary.clone(),
                })
                .collect(),
            summary: r.verdict.summary.clone(),
            diff: r.diff.clone(),
            validation: validation.map(ValidationScoreExport::from),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub(super) enum RemediationOutcomeExport {
    Processed(Box<RemediationRecordExport>),
    Failed { finding_index: i64, error: String },
}

impl RemediationOutcomeExport {
    pub(super) fn from_parts(
        o: &appsec_stage_s10::RemediationOutcome,
        validation: Option<&appsec_validation_scoring::ValidationScore>,
    ) -> Self {
        match o {
            appsec_stage_s10::RemediationOutcome::Processed(r) => {
                RemediationOutcomeExport::Processed(Box::new(RemediationRecordExport::from_parts(
                    r.as_ref(),
                    validation,
                )))
            }
            appsec_stage_s10::RemediationOutcome::Failed {
                finding_index,
                error,
            } => RemediationOutcomeExport::Failed {
                finding_index: *finding_index,
                error: error.clone(),
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct RemediationExport {
    pub(super) refused: Option<String>,
    pub(super) results: Vec<RemediationOutcomeExport>,
    #[serde(default)]
    pub(super) totals: RemediationTotalsExport,
    #[serde(default)]
    pub(super) rollup: RollupExport,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(super) struct RemediationTotalsExport {
    pub(super) attempted: usize,
    pub(super) fixed: usize,
    pub(super) not_fixed: usize,
    pub(super) failed: usize,
    pub(super) validation_failures: usize,
    pub(super) exit_code: u8,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(super) struct RollupExport {
    pub(super) cases: usize,
    pub(super) states: std::collections::BTreeMap<String, usize>,
    pub(super) decisions: std::collections::BTreeMap<String, usize>,
}

impl From<&RemediationSummary> for RemediationTotalsExport {
    fn from(s: &RemediationSummary) -> Self {
        RemediationTotalsExport {
            attempted: s.processed + s.failed,
            fixed: s.fixed,
            not_fixed: s.not_fixed,
            failed: s.failed,
            validation_failures: s.validation_failures,
            exit_code: s.exit_code(),
        }
    }
}

impl From<&appsec_validation_scoring::Rollup> for RollupExport {
    fn from(r: &appsec_validation_scoring::Rollup) -> Self {
        let owned = |m: &std::collections::BTreeMap<&'static str, usize>| {
            m.iter().map(|(k, v)| (k.to_string(), *v)).collect()
        };
        RollupExport {
            cases: r.cases,
            states: owned(&r.states),
            decisions: owned(&r.decisions),
        }
    }
}
