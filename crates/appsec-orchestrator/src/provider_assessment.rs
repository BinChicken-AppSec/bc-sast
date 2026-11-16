use appsec_model::{
    DroppedFinding, Finding, ProviderAssessmentRecord, ProviderLedger, VerificationEvidence,
};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy)]
enum Candidate<'a> {
    Verified(&'a Finding),
    Dropped(&'a DroppedFinding),
}

pub(super) fn unassessed(findings: &[Finding]) -> Vec<ProviderAssessmentRecord> {
    findings
        .iter()
        .flat_map(|finding| {
            finding
                .provider_origins
                .iter()
                .map(|origin| ProviderAssessmentRecord {
                    origin: origin.clone(),
                    file: finding.file.clone(),
                    line: finding.line_start,
                    title: finding.title.clone(),
                    verification: None,
                    drop_reason: None,
                    limitations: vec!["No completed verification for this imported finding".into()],
                })
        })
        .collect()
}

pub(super) fn mark_out_of_diff_scope(ledger: &mut ProviderLedger, retained: &[DroppedFinding]) {
    for record in &mut ledger.assessments {
        let Some(entry) = retained.iter().find(|d| {
            d.provider_origins.contains(&record.origin)
                && d.file == record.file
                && d.line == record.line
                && d.title == record.title
        }) else {
            continue;
        };
        record.verification = None;
        record.drop_reason = Some(entry.reason);
        record.limitations = vec![entry.detail.clone()];
    }
}

pub(super) fn record_verification(
    ledger: &mut ProviderLedger,
    verified: &[Finding],
    dropped: &[DroppedFinding],
) {
    let mut candidates = BTreeMap::new();
    let positives = verified.iter().map(|f| {
        (
            f.provider_origins.as_slice(),
            f.file.as_str(),
            f.line_start,
            f.title.as_str(),
            Candidate::Verified(f),
        )
    });
    let negatives = dropped.iter().map(|f| {
        (
            f.provider_origins.as_slice(),
            f.file.as_str(),
            f.line,
            f.title.as_str(),
            Candidate::Dropped(f),
        )
    });
    for (origins, file, line, title, candidate) in positives.chain(negatives) {
        for origin in origins.iter().collect::<BTreeSet<_>>() {
            candidates
                .entry((origin, file, line, title))
                .and_modify(|existing| *existing = None)
                .or_insert(Some(candidate));
        }
    }
    for record in &mut ledger.assessments {
        record.verification = None;
        record.drop_reason = None;
        record.limitations = vec!["No completed verification for this imported finding".into()];
        let key = (
            &record.origin,
            record.file.as_str(),
            record.line,
            record.title.as_str(),
        );
        let Some(Some(candidate)) = candidates.get(&key) else {
            record
                .limitations
                .push("Missing or ambiguous verification association".into());
            continue;
        };
        match candidate {
            Candidate::Verified(f) => {
                record.verification = VerificationEvidence::from_finding(f);
            }
            Candidate::Dropped(f) => {
                record.verification = f.verification.clone();
                record.drop_reason = Some(f.reason);
            }
        }
        if record.verification.is_some() {
            record.limitations.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use appsec_model::{DropReason, ProviderOrigin, Verdict};
    fn finding() -> Finding {
        let mut f: Finding = serde_json::from_value(serde_json::json!({
            "chunk_id":"external:x", "file":"src/app.rs", "line_start":1,
            "line_end":1, "vuln_class":"other", "title":"case",
            "description":"claim", "code_snippet":"", "confidence":0.5
        }))
        .unwrap();
        f.provider_origins.push(ProviderOrigin::default());
        f
    }
    #[test]
    fn retains_each_origin_without_inventing_a_verdict() {
        let f = finding();
        let mut ledger = ProviderLedger {
            assessments: unassessed(std::slice::from_ref(&f)),
            ..Default::default()
        };
        record_verification(&mut ledger, &[], &[]);
        assert!(ledger.assessments[0].verification.is_none());
        assert_eq!(ledger.assessments[0].limitations.len(), 2);
        record_verification(&mut ledger, &[f.clone(), f], &[]);
        assert!(ledger.assessments[0].verification.is_none());
    }
    #[test]
    fn captures_positive_and_negative_evidence_before_report_filtering() {
        let mut f = finding();
        let mut ledger = ProviderLedger {
            assessments: unassessed(std::slice::from_ref(&f)),
            ..Default::default()
        };
        f.verdict = Some(Verdict::TruePositive);
        f.verdict_confidence = Some(8);
        f.verdict_reason = "Reachable operation".into();
        record_verification(&mut ledger, std::slice::from_ref(&f), &[]);
        assert_eq!(
            ledger.assessments[0]
                .verification
                .as_ref()
                .unwrap()
                .confidence,
            8
        );
        assert!(ledger.assessments[0].limitations.is_empty());
        let d = DroppedFinding {
            file: f.file,
            line: f.line_start,
            title: f.title,
            chunk_id: f.chunk_id,
            vuln_class: f.vuln_class,
            reason: DropReason::FalsePositive,
            detail: "Bounded input".into(),
            canonical_idx: None,
            provider_origins: f.provider_origins,
            verification: Some(VerificationEvidence {
                verdict: Verdict::FalsePositive,
                confidence: 9,
                reason: "Bounded input".into(),
                reasoning: "Code evidence".into(),
                cvss_vector: None,
            }),
        };
        record_verification(&mut ledger, &[], std::slice::from_ref(&d));
        assert_eq!(
            ledger.assessments[0].drop_reason,
            Some(DropReason::FalsePositive)
        );
        assert_eq!(ledger.assessments[0].verification, d.verification);
    }
    #[test]
    fn completed_transport_without_parsed_verdict_stays_unassessed() {
        let f = finding();
        let mut ledger = ProviderLedger {
            assessments: unassessed(std::slice::from_ref(&f)),
            ..Default::default()
        };
        record_verification(&mut ledger, &[f], &[]);
        assert!(ledger.assessments[0].verification.is_none());
        assert!(!ledger.assessments[0].limitations.is_empty());
    }

    #[test]
    fn missing_reassessment_clears_stale_false_positive_evidence() {
        let f = finding();
        let mut ledger = ProviderLedger {
            assessments: unassessed(std::slice::from_ref(&f)),
            ..Default::default()
        };
        ledger.assessments[0].verification = Some(VerificationEvidence {
            verdict: Verdict::FalsePositive,
            confidence: 10,
            reason: "previous run".into(),
            reasoning: "stale assessment".into(),
            cvss_vector: None,
        });
        ledger.assessments[0].drop_reason = Some(DropReason::FalsePositive);
        ledger.assessments[0].limitations.clear();

        record_verification(&mut ledger, &[], &[]);

        assert!(ledger.assessments[0].verification.is_none());
        assert!(ledger.assessments[0].drop_reason.is_none());
        assert!(ledger.assessments[0]
            .limitations
            .iter()
            .any(|limitation| limitation.contains("Missing or ambiguous")));
    }

    #[test]
    fn repeated_origin_metadata_is_one_candidate_but_duplicate_candidates_are_ambiguous() {
        let mut f = finding();
        f.verdict = Some(Verdict::TruePositive);
        f.verdict_confidence = Some(9);
        let mut ledger = ProviderLedger {
            assessments: unassessed(std::slice::from_ref(&f)),
            ..Default::default()
        };
        f.provider_origins.push(f.provider_origins[0].clone());
        record_verification(&mut ledger, std::slice::from_ref(&f), &[]);
        assert_eq!(
            ledger.assessments[0].verification.as_ref().unwrap().verdict,
            Verdict::TruePositive
        );

        record_verification(&mut ledger, &[f.clone(), f], &[]);
        assert!(ledger.assessments[0].verification.is_none());
        assert!(ledger.assessments[0]
            .limitations
            .iter()
            .any(|limitation| limitation.contains("Missing or ambiguous")));
    }

    #[test]
    fn indexed_associations_preserve_exact_locations_and_do_not_reuse_a_shared_origin_verdict() {
        let first = finding();
        let mut second = first.clone();
        second.line_start = 99;
        let mut ledger = ProviderLedger {
            assessments: unassessed(&[first.clone(), second.clone()]),
            ..Default::default()
        };
        let mut verified = first;
        verified.verdict = Some(Verdict::TruePositive);
        verified.verdict_confidence = Some(8);
        record_verification(&mut ledger, &[verified], &[]);
        assert!(ledger.assessments[0].verification.is_some());
        assert!(ledger.assessments[1].verification.is_none());
        assert_eq!(ledger.assessments[1].line, second.line_start);
    }
}
