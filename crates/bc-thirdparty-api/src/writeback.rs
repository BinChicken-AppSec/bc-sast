//! Pure, proposal-only provider reconciliation. This module has no HTTP client.
//!
//! Payloads describe reviewed API shapes, not authorization to send them. Every
//! entry remains blocked pending account pilots, trusted publication policy,
//! fresh provider state, and evidence covering the actual mutation scope.
use bc_model::{ProviderKind, ProviderOrigin, ProviderProduct, ProviderSource};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssessmentOutcome {
    Confirmed,
    FalsePositive,
    Inconclusive,
    Unassessed,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssessmentInput {
    pub origin: ProviderOrigin,
    pub outcome: AssessmentOutcome,
    pub confidence: Option<f64>,
    pub evidence: Vec<String>,
    pub assessed_severity: Option<String>,
    pub independent_review: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PlanningContext {
    pub full_scan: bool,
    pub scan_complete: bool,
    pub inventory_complete: bool,
    pub git_ref: Option<String>,
    pub revision: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockReason {
    #[serde(alias = "publication_not_implemented")]
    PublicationRequiresApproval,
    ProviderBaselineNotRevalidated,
    MutationScopeAndAffectedInstancesUnverified,
    FullScanRequired,
    IncompleteScan,
    IncompleteInventory,
    RevisionMissingOrMismatched,
    RefMissingOrMismatched,
    ApiIdentityRequired,
    UnsupportedProduct,
    AssessmentMissing,
    AssessmentConflict,
    InconclusiveAssessment,
    EvidenceMissing,
    IndependentReviewRequired,
    FalsePositiveConfidenceInsufficient,
    NativeIdentityMissingOrInvalid,
    OriginalStateMissing,
    ExistingHumanDisposition,
    UnsupportedProvider,
    UnsupportedAction,
    UnsupportedSeverity,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PayloadPreview {
    pub proposal_only: bool,
    pub method: String,
    /// Relative vendor API path. Never an endpoint or credential destination.
    pub path: String,
    pub content_type: String,
    pub body: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlannedUpdate {
    pub origin: ProviderOrigin,
    pub outcome: AssessmentOutcome,
    pub apply_enabled: bool,
    pub blocking_reasons: Vec<BlockReason>,
    pub payload_previews: Vec<PayloadPreview>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WritebackPlan {
    pub schema_version: u32,
    pub mode: String,
    pub apply_enabled: bool,
    pub entries: Vec<PlannedUpdate>,
}

/// One deterministic entry per exact origin. Missing assessments remain visible;
/// report filtering, ordering, and deduplication never imply a false positive.
pub fn plan_updates(
    origins: &[ProviderOrigin],
    assessments: &[AssessmentInput],
    context: &PlanningContext,
) -> WritebackPlan {
    let mut sorted = origins.to_vec();
    sorted.sort();
    sorted.dedup();
    let entries = sorted
        .into_iter()
        .map(|origin| plan_origin(origin, assessments, context))
        .collect();
    WritebackPlan {
        schema_version: 1,
        mode: "proposal_only".into(),
        apply_enabled: false,
        entries,
    }
}

fn plan_origin(
    origin: ProviderOrigin,
    assessments: &[AssessmentInput],
    context: &PlanningContext,
) -> PlannedUpdate {
    let mut reasons = vec![
        BlockReason::PublicationRequiresApproval,
        BlockReason::ProviderBaselineNotRevalidated,
        BlockReason::MutationScopeAndAffectedInstancesUnverified,
    ];
    if !context.full_scan {
        reasons.push(BlockReason::FullScanRequired);
    }
    if !context.scan_complete {
        reasons.push(BlockReason::IncompleteScan);
    }
    if !context.inventory_complete {
        reasons.push(BlockReason::IncompleteInventory);
    }
    if !same_nonempty(&origin.revision, &context.revision) {
        reasons.push(BlockReason::RevisionMissingOrMismatched);
    }
    if !same_nonempty(&origin.git_ref, &context.git_ref) {
        reasons.push(BlockReason::RefMissingOrMismatched);
    }
    if origin.source != ProviderSource::Api {
        reasons.push(BlockReason::ApiIdentityRequired);
    }
    if origin.product != ProviderProduct::Sast {
        reasons.push(BlockReason::UnsupportedProduct);
    }
    if origin.state.as_deref().is_none_or(|v| v.trim().is_empty()) {
        reasons.push(BlockReason::OriginalStateMissing);
    }
    if origin.state.as_deref().is_some_and(human_disposition) {
        reasons.push(BlockReason::ExistingHumanDisposition);
    }
    let matches: Vec<_> = assessments.iter().filter(|a| a.origin == origin).collect();
    let mut outcome = AssessmentOutcome::Unassessed;
    let mut previews = vec![];
    if let Some(assessment) = matches.first() {
        outcome = assessment.outcome;
        if matches.iter().skip(1).any(|a| *a != *assessment) {
            outcome = AssessmentOutcome::Inconclusive;
            reasons.push(BlockReason::AssessmentConflict);
        } else if matches!(
            outcome,
            AssessmentOutcome::Unassessed | AssessmentOutcome::Inconclusive
        ) {
            reasons.push(BlockReason::InconclusiveAssessment);
        } else {
            let evidence = assessment.evidence.iter().any(|e| !e.trim().is_empty());
            if !evidence {
                reasons.push(BlockReason::EvidenceMissing);
            }
            if !assessment.independent_review {
                reasons.push(BlockReason::IndependentReviewRequired);
            }
            if outcome == AssessmentOutcome::FalsePositive
                && !assessment
                    .confidence
                    .is_some_and(|c| c.is_finite() && (0.9..=1.0).contains(&c))
            {
                reasons.push(BlockReason::FalsePositiveConfidenceInsufficient);
            }
            // Even a preview needs a real API identity and an evidenced decision.
            // It is not executable authorization, regardless of these checks.
            if origin.source == ProviderSource::Api
                && origin.product == ProviderProduct::Sast
                && evidence
            {
                match payloads(&origin, assessment) {
                    Ok(p) => previews = p,
                    Err(reason) => reasons.push(reason),
                }
            }
        }
    } else {
        reasons.push(BlockReason::AssessmentMissing);
    }
    PlannedUpdate {
        origin,
        outcome,
        apply_enabled: false,
        blocking_reasons: reasons,
        payload_previews: previews,
    }
}

fn same_nonempty(a: &Option<String>, b: &Option<String>) -> bool {
    a.as_deref()
        .zip(b.as_deref())
        .is_some_and(|(a, b)| !a.trim().is_empty() && a == b)
}

fn human_disposition(state: &str) -> bool {
    matches!(
        state.trim().to_ascii_lowercase().as_str(),
        "ignored"
            | "not_exploitable"
            | "proposed_not_exploitable"
            | "resolved"
            | "fixed"
            | "closed"
    )
}

fn required(value: &Option<String>) -> Result<&str, BlockReason> {
    value
        .as_deref()
        .filter(|v| !v.trim().is_empty() && v.len() <= 1024 && !v.chars().any(char::is_control))
        .ok_or(BlockReason::NativeIdentityMissingOrInvalid)
}

fn segment(value: &Option<String>) -> Result<&str, BlockReason> {
    let value = required(value)?;
    if value
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    {
        Ok(value)
    } else {
        Err(BlockReason::NativeIdentityMissingOrInvalid)
    }
}

fn number(value: &Option<String>) -> Result<u64, BlockReason> {
    required(value)?
        .parse::<u64>()
        .ok()
        .filter(|v| *v > 0 && *v <= i64::MAX as u64)
        .ok_or(BlockReason::NativeIdentityMissingOrInvalid)
}

fn preview(method: &str, path: String, body: Value) -> PayloadPreview {
    PayloadPreview {
        proposal_only: true,
        method: method.into(),
        path,
        content_type: "application/json".into(),
        body,
    }
}

fn payloads(
    origin: &ProviderOrigin,
    assessment: &AssessmentInput,
) -> Result<Vec<PayloadPreview>, BlockReason> {
    // Do not copy arbitrary source/evidence into outbound previews. Full evidence
    // stays in the separately redacted ledger. A future publisher must attach a
    // trusted assessment ID and approved bounded rationale, not this placeholder.
    let note = match assessment.outcome {
        AssessmentOutcome::FalsePositive => "BC SAST proposes false-positive triage. Proposal only; independent evidence and affected-scope approval must be reviewed before publication.",
        _ => "BC SAST supports this finding. Proposal only; review the associated assessment evidence before publication.",
    };
    let reject = assessment.outcome == AssessmentOutcome::FalsePositive;
    let severity = assessment
        .assessed_severity
        .as_deref()
        .map(str::to_ascii_lowercase);
    match origin.provider {
        ProviderKind::Semgrep => {
            if !reject && severity.is_some() {
                return Err(BlockReason::UnsupportedAction);
            }
            let deployment = segment(&origin.tenant_id)?;
            let id = number(&origin.native_ids.issue_id)?;
            let mut body = json!({"deployment_slug": deployment, "issue_ids":[id], "issue_type":"sast", "new_note":note});
            if reject {
                body["new_triage_state"] = json!("ignored");
                body["new_triage_reason"] = json!("false_positive");
            }
            Ok(vec![preview(
                "POST",
                format!("/api/v1/deployments/{deployment}/triage"),
                body,
            )])
        }
        ProviderKind::Checkmarx => {
            let project = segment(&origin.project_id)?;
            let similarity = required(&origin.native_ids.similarity_id)?;
            let mut body = json!({"projectId":project, "similarityId":similarity, "comment":note});
            if origin.scan_id.is_some() {
                body["scanId"] = json!(segment(&origin.scan_id)?);
            }
            if reject {
                body["state"] = json!("NOT_EXPLOITABLE");
            } else {
                body["state"] = json!("CONFIRMED");
                if let Some(s) = severity {
                    if !["critical", "high", "medium", "low", "info"].contains(&s.as_str()) {
                        return Err(BlockReason::UnsupportedSeverity);
                    }
                    body["severity"] = json!(s.to_ascii_uppercase());
                }
            }
            // Grouping is not inferred from an ID's presence. This is explicitly
            // a similarity-mode preview; unknown tenant grouping blocks all apply.
            Ok(vec![preview(
                "POST",
                "/api/sast-results-predicates/".into(),
                json!([body]),
            )])
        }
        ProviderKind::Snyk => {
            if !reject {
                return Err(BlockReason::UnsupportedAction);
            }
            let org = segment(&origin.tenant_id)?;
            let key = required(&origin.native_ids.asset_finding_id)?;
            let body = json!({"data":{"type":"policy","attributes":{"name":"BC SAST assessment proposal","source":"api","action_type":"ignore","action":{"data":{"ignore_type":"not-vulnerable","reason":note}},"conditions_group":{"logical_operator":"and","conditions":[{"field":"snyk/asset/finding/v1","operator":"includes","value":key}]}}}});
            let mut p = preview(
                "POST",
                format!("/rest/orgs/{org}/policies?version=2024-10-15"),
                body,
            );
            p.content_type = "application/vnd.api+json".into();
            Ok(vec![p])
        }
        ProviderKind::Aikido => {
            let id = number(&origin.native_ids.issue_id)?;
            if reject {
                return Ok(vec![preview(
                    "PUT",
                    format!("/api/public/v1/issues/{id}/ignore"),
                    json!({"reason":note,"apply_for_all_tags":false}),
                )]);
            }
            if let Some(s) = severity {
                if !["critical", "high", "medium", "low"].contains(&s.as_str()) {
                    return Err(BlockReason::UnsupportedSeverity);
                }
                return Ok(vec![preview(
                    "POST",
                    format!("/api/public/v1/issues/{id}/severity/adjust"),
                    json!({"adjusted_severity":s,"reason":note}),
                )]);
            }
            // Group notes have a wider scope than a single issue; defer until
            // account pilots establish group membership and safe note semantics.
            Err(BlockReason::UnsupportedAction)
        }
        _ => Err(BlockReason::UnsupportedProvider),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_model::ProviderNativeIds;

    fn origin(provider: ProviderKind) -> ProviderOrigin {
        ProviderOrigin {
            provider,
            product: ProviderProduct::Sast,
            source: ProviderSource::Api,
            native_ids: ProviderNativeIds {
                issue_id: Some("42".into()),
                similarity_id: Some("similar-1".into()),
                asset_finding_id: Some("asset:finding".into()),
                ..Default::default()
            },
            tenant_id: Some("tenant-1".into()),
            project_id: Some("project-1".into()),
            git_ref: Some("main".into()),
            revision: Some("commit-1".into()),
            state: Some("TO_VERIFY".into()),
            ..Default::default()
        }
    }
    fn assessment(origin: &ProviderOrigin) -> AssessmentInput {
        AssessmentInput {
            origin: origin.clone(),
            outcome: AssessmentOutcome::FalsePositive,
            confidence: Some(0.99),
            evidence: vec!["A documented guard excludes the claimed input.".into()],
            assessed_severity: None,
            independent_review: true,
        }
    }
    fn context() -> PlanningContext {
        PlanningContext {
            full_scan: true,
            scan_complete: true,
            inventory_complete: true,
            git_ref: Some("main".into()),
            revision: Some("commit-1".into()),
        }
    }
    fn entry(origin: ProviderOrigin, a: AssessmentInput) -> PlannedUpdate {
        plan_updates(&[origin], &[a], &context()).entries.remove(0)
    }

    #[test]
    fn all_payloads_are_proposals_with_native_identifiers_and_no_authority() {
        for provider in [
            ProviderKind::Semgrep,
            ProviderKind::Checkmarx,
            ProviderKind::Snyk,
            ProviderKind::Aikido,
        ] {
            let o = origin(provider);
            let a = assessment(&o);
            let e = entry(o, a);
            assert!(!e.apply_enabled);
            assert!(e
                .blocking_reasons
                .contains(&BlockReason::MutationScopeAndAffectedInstancesUnverified));
            assert_eq!(e.payload_previews.len(), 1);
            let p = &e.payload_previews[0];
            assert!(p.proposal_only);
            assert!(p.path.starts_with('/'));
            match provider {
                ProviderKind::Semgrep => {
                    assert_eq!(p.body["issue_ids"], json!([42]));
                    assert_eq!(p.body["deployment_slug"], "tenant-1");
                    assert_eq!(p.body["new_triage_reason"], "false_positive");
                }
                ProviderKind::Checkmarx => {
                    assert_eq!(p.body[0]["similarityId"], "similar-1");
                    assert_eq!(p.body[0]["state"], "NOT_EXPLOITABLE");
                }
                ProviderKind::Snyk => {
                    assert_eq!(p.content_type, "application/vnd.api+json");
                    assert_eq!(
                        p.body["data"]["attributes"]["conditions_group"]["conditions"][0]["value"],
                        "asset:finding"
                    );
                    assert_eq!(
                        p.body["data"]["attributes"]["action"]["data"]["ignore_type"],
                        "not-vulnerable"
                    );
                }
                ProviderKind::Aikido => {
                    assert_eq!(p.method, "PUT");
                    assert_eq!(p.body["apply_for_all_tags"], false);
                }
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn missing_assessment_and_framework_omission_never_become_false_positive() {
        let o = origin(ProviderKind::Semgrep);
        let p = plan_updates(&[o.clone(), o], &[], &context());
        assert_eq!(p.entries.len(), 1);
        assert_eq!(p.entries[0].outcome, AssessmentOutcome::Unassessed);
        assert_eq!(p.entries[0].payload_previews.len(), 0);
        assert!(p.entries[0]
            .blocking_reasons
            .contains(&BlockReason::AssessmentMissing));
    }

    #[test]
    fn wrong_revision_ref_incomplete_inventory_and_nonfull_scan_remain_blocked() {
        let o = origin(ProviderKind::Checkmarx);
        let a = assessment(&o);
        let p = plan_updates(&[o], &[a], &PlanningContext::default());
        for r in [
            BlockReason::FullScanRequired,
            BlockReason::IncompleteScan,
            BlockReason::IncompleteInventory,
            BlockReason::RevisionMissingOrMismatched,
            BlockReason::RefMissingOrMismatched,
        ] {
            assert!(p.entries[0].blocking_reasons.contains(&r));
        }
    }

    #[test]
    fn false_positive_without_review_confidence_or_evidence_is_blocked() {
        let o = origin(ProviderKind::Checkmarx);
        let mut a = assessment(&o);
        a.independent_review = false;
        a.confidence = None;
        a.evidence.clear();
        let e = entry(o, a);
        for r in [
            BlockReason::IndependentReviewRequired,
            BlockReason::FalsePositiveConfidenceInsufficient,
            BlockReason::EvidenceMissing,
        ] {
            assert!(e.blocking_reasons.contains(&r));
        }
        assert!(e.payload_previews.is_empty());
    }

    #[test]
    fn invalid_confidence_cannot_pass_the_negative_gate() {
        for confidence in [f64::NAN, f64::INFINITY, -1.0, 0.89, 1.01] {
            let o = origin(ProviderKind::Aikido);
            let mut a = assessment(&o);
            a.confidence = Some(confidence);
            assert!(entry(o, a)
                .blocking_reasons
                .contains(&BlockReason::FalsePositiveConfidenceInsufficient));
        }
    }

    #[test]
    fn native_id_missing_or_invalid_cannot_use_other_ids_as_fallback() {
        for provider in [
            ProviderKind::Semgrep,
            ProviderKind::Checkmarx,
            ProviderKind::Snyk,
            ProviderKind::Aikido,
        ] {
            let mut o = origin(provider);
            o.native_ids = ProviderNativeIds::default();
            let a = assessment(&o);
            let e = entry(o, a);
            assert!(e.payload_previews.is_empty());
            assert!(e
                .blocking_reasons
                .contains(&BlockReason::NativeIdentityMissingOrInvalid));
        }
        for invalid in ["../evil", "a?token=x", "https://evil.test", "a/b", ""] {
            let mut o = origin(ProviderKind::Snyk);
            o.tenant_id = Some(invalid.into());
            let a = assessment(&o);
            assert!(entry(o, a).payload_previews.is_empty());
        }
        for invalid in ["-1", "0", "9223372036854775808"] {
            let mut o = origin(ProviderKind::Aikido);
            o.native_ids.issue_id = Some(invalid.into());
            let a = assessment(&o);
            assert!(entry(o, a).payload_previews.is_empty());
        }
    }

    #[test]
    fn unresolved_or_conflicting_assessments_do_not_generate_mutation_previews() {
        for outcome in [
            AssessmentOutcome::Inconclusive,
            AssessmentOutcome::Unassessed,
        ] {
            let o = origin(ProviderKind::Semgrep);
            let mut a = assessment(&o);
            a.outcome = outcome;
            let e = entry(o, a);
            assert!(e.payload_previews.is_empty());
            assert!(e
                .blocking_reasons
                .contains(&BlockReason::InconclusiveAssessment));
        }
        let o = origin(ProviderKind::Semgrep);
        let a = assessment(&o);
        let mut b = a.clone();
        b.outcome = AssessmentOutcome::Confirmed;
        let p = plan_updates(&[o], &[a, b], &context());
        assert!(p.entries[0].payload_previews.is_empty());
        assert!(p.entries[0]
            .blocking_reasons
            .contains(&BlockReason::AssessmentConflict));
    }

    #[test]
    fn file_ingestion_and_non_sast_findings_cannot_generate_payloads() {
        let mut o = origin(ProviderKind::Semgrep);
        o.source = ProviderSource::File;
        let a = assessment(&o);
        let e = entry(o, a);
        assert!(e.payload_previews.is_empty());
        assert!(e
            .blocking_reasons
            .contains(&BlockReason::ApiIdentityRequired));
        let mut o = origin(ProviderKind::Snyk);
        o.product = ProviderProduct::Dependency;
        let a = assessment(&o);
        let e = entry(o, a);
        assert!(e.payload_previews.is_empty());
        assert!(e
            .blocking_reasons
            .contains(&BlockReason::UnsupportedProduct));
    }

    #[test]
    fn existing_human_decision_and_unknown_original_state_are_blockers() {
        for state in [Some("ignored".into()), Some("NOT_EXPLOITABLE".into()), None] {
            let mut o = origin(ProviderKind::Aikido);
            o.state = state;
            let a = assessment(&o);
            let e = entry(o, a);
            assert!(
                e.blocking_reasons
                    .contains(&BlockReason::ExistingHumanDisposition)
                    || e.blocking_reasons
                        .contains(&BlockReason::OriginalStateMissing)
            );
        }
    }

    #[test]
    fn supported_severity_previews_do_not_offer_unsupported_vendor_actions() {
        for provider in [
            ProviderKind::Semgrep,
            ProviderKind::Checkmarx,
            ProviderKind::Snyk,
            ProviderKind::Aikido,
        ] {
            let o = origin(provider);
            let mut a = assessment(&o);
            a.outcome = AssessmentOutcome::Confirmed;
            a.assessed_severity = Some("low".into());
            let e = entry(o, a);
            if matches!(provider, ProviderKind::Semgrep | ProviderKind::Snyk) {
                assert!(e.blocking_reasons.contains(&BlockReason::UnsupportedAction));
                assert!(e.payload_previews.is_empty());
            } else {
                assert_eq!(e.payload_previews.len(), 1);
            }
        }
        for provider in [ProviderKind::Checkmarx, ProviderKind::Aikido] {
            let o = origin(provider);
            let mut a = assessment(&o);
            a.outcome = AssessmentOutcome::Confirmed;
            a.assessed_severity = Some("invented".into());
            assert!(entry(o, a)
                .blocking_reasons
                .contains(&BlockReason::UnsupportedSeverity));
        }
    }

    #[test]
    fn plan_order_is_stable_and_original_evidence_is_not_copied_to_payloads() {
        let a = origin(ProviderKind::Semgrep);
        let b = origin(ProviderKind::Aikido);
        let aa = assessment(&a);
        let ab = assessment(&b);
        let x = plan_updates(
            &[a.clone(), b.clone()],
            &[aa.clone(), ab.clone()],
            &context(),
        );
        let y = plan_updates(&[b, a], &[ab, aa], &context());
        assert_eq!(x, y);
        assert!(!serde_json::to_string(&x.entries[0].payload_previews)
            .unwrap()
            .contains("documented guard"));
    }

    #[test]
    fn unsupported_providers_and_note_only_operations_are_explicit() {
        let o = origin(ProviderKind::Sonatype);
        let a = assessment(&o);
        assert!(entry(o, a)
            .blocking_reasons
            .contains(&BlockReason::UnsupportedProvider));
        let o = origin(ProviderKind::Aikido);
        let mut a = assessment(&o);
        a.outcome = AssessmentOutcome::Confirmed;
        assert!(entry(o, a)
            .blocking_reasons
            .contains(&BlockReason::UnsupportedAction));
        let o = origin(ProviderKind::Semgrep);
        let mut a = assessment(&o);
        a.outcome = AssessmentOutcome::Confirmed;
        let e = entry(o, a);
        assert!(e.payload_previews[0].body.get("new_triage_state").is_none());
        let mut o = origin(ProviderKind::Checkmarx);
        o.scan_id = Some("scan-1".into());
        let mut a = assessment(&o);
        a.outcome = AssessmentOutcome::Confirmed;
        let e = entry(o, a);
        assert_eq!(e.payload_previews[0].body[0]["scanId"], "scan-1");
    }
}
