//! Build-owned automatic decisions from the pre-filter assessment ledger.
use bc_model::{
    DropReason, FinalReport, ProviderAssessmentRecord, ProviderKind, ProviderOrigin,
    ProviderProduct, ProviderSource, Verdict,
};
use bc_thirdparty_api::publish::ApprovedAction;
use serde_json::json;

pub(super) fn scope_key(origin: &ProviderOrigin) -> String {
    let ids = &origin.native_ids;
    let group = match origin.provider {
        ProviderKind::Semgrep => json!([origin.repository_name, ids.match_based_id]),
        ProviderKind::Snyk => json!([ids.asset_finding_id]),
        ProviderKind::Checkmarx => {
            json!([origin.project_id, ids.similarity_id, ids.attack_vector_id])
        }
        ProviderKind::Aikido => json!([origin.repository_id, ids.issue_id]),
        _ => json!([origin.project_id, origin.repository_id, ids]),
    };
    json!([origin.provider, origin.tenant_id, group]).to_string()
}

pub(super) fn scope_description(provider: ProviderKind) -> &'static str {
    match provider {
        ProviderKind::Semgrep => "Matching Semgrep fingerprints can propagate across repository refs and future scans",
        ProviderKind::Checkmarx => "Checkmarx predicates can affect grouped results across branches and configured project/application scope",
        ProviderKind::Snyk => "Snyk Code asset ignores can span projects, integrations, branches and future scans",
        ProviderKind::Aikido => "Aikido uses its monitored repository branch; notes have issue-group scope and ignore propagation follows provider settings",
        _ => "Provider mutation scope is unsupported",
    }
}

fn nonempty(value: &Option<String>) -> bool {
    value.as_deref().is_some_and(|s| !s.trim().is_empty())
}
fn identity_valid(origin: &ProviderOrigin) -> bool {
    let ids = &origin.native_ids;
    match origin.provider {
        ProviderKind::Semgrep => {
            nonempty(&origin.tenant_id)
                && nonempty(&origin.repository_name)
                && nonempty(&ids.issue_id)
                && nonempty(&ids.match_based_id)
        }
        ProviderKind::Checkmarx => {
            nonempty(&origin.tenant_id)
                && nonempty(&origin.project_id)
                && nonempty(&origin.scan_id)
                && nonempty(&ids.similarity_id)
        }
        ProviderKind::Snyk => {
            nonempty(&origin.tenant_id)
                && nonempty(&origin.project_id)
                && nonempty(&ids.issue_id)
                && nonempty(&ids.asset_finding_id)
        }
        ProviderKind::Aikido => nonempty(&origin.repository_id) && nonempty(&ids.issue_id),
        _ => false,
    }
}
fn supported_fp(record: &ProviderAssessmentRecord) -> bool {
    record.limitations.is_empty()
        && record.drop_reason == Some(DropReason::FalsePositive)
        && record.verification.as_ref().is_some_and(|v| {
            v.verdict == Verdict::FalsePositive
                && (9..=10).contains(&v.confidence)
                && !v.reason.trim().is_empty()
                && !v.reasoning.trim().is_empty()
        })
}
fn same_rejection_scope(a: &ProviderOrigin, b: &ProviderOrigin) -> bool {
    if scope_key(a) == scope_key(b) {
        return true;
    }
    // The operation key stays project-specific; rejection conflicts must account
    // for Checkmarx tenants that propagate predicates across applications.
    if a.provider == ProviderKind::Checkmarx
        && b.provider == ProviderKind::Checkmarx
        && a.tenant_id == b.tenant_id
    {
        let same = |a: &Option<String>, b: &Option<String>| nonempty(a) && a == b;
        return same(&a.native_ids.similarity_id, &b.native_ids.similarity_id)
            || same(
                &a.native_ids.attack_vector_id,
                &b.native_ids.attack_vector_id,
            );
    }
    false
}

pub(super) fn select(
    report: &FinalReport,
    record: &ProviderAssessmentRecord,
) -> Result<ApprovedAction, String> {
    let ledger = &report.provider_ledger;
    if !ledger.full_scan
        || ledger.resumed
        || !ledger.analysis_complete
        || report.degraded
        || !nonempty(&report.git_sha)
    {
        return Err(
            "Automatic publication requires a completed full scan with a source revision".into(),
        );
    }
    if record.origin.source != ProviderSource::Api
        || record.origin.product != ProviderProduct::Sast
        || !identity_valid(&record.origin)
    {
        return Err("Automatic publication requires supported native API SAST identity".into());
    }
    if record
        .origin
        .revision
        .as_ref()
        .is_some_and(|r| Some(r) != report.git_sha.as_ref())
    {
        return Err("Provider revision does not match the assessed source revision".into());
    }
    let matches: Vec<_> = ledger
        .assessments
        .iter()
        .filter(|a| a.origin == record.origin)
        .collect();
    if matches.is_empty() || matches.iter().any(|a| *a != record) {
        return Err(
            "Assessment is missing or conflicts with another record for the same origin".into(),
        );
    }
    if !record.limitations.is_empty() {
        return Err("Assessment has unresolved limitations".into());
    }
    let evidence = record
        .verification
        .as_ref()
        .ok_or("No completed provider finding verification")?;
    if evidence.reason.trim().is_empty() || evidence.reasoning.trim().is_empty() {
        return Err("Verification evidence is incomplete".into());
    }
    let reason = reason(report, record);
    match evidence.verdict {
        Verdict::FalsePositive if supported_fp(record) => {
            if ledger.assessments.iter().any(|other| same_rejection_scope(&record.origin,&other.origin) && !supported_fp(other)) {
                return Err("An affected mutation group contains a true positive, unresolved or incompatible assessment".into());
            }
            Ok(ApprovedAction::FalsePositive{reason})
        }
        Verdict::TruePositive if record.drop_reason.is_none() && (6..=10).contains(&evidence.confidence) => {
            match record.origin.provider {
                ProviderKind::Semgrep => Ok(ApprovedAction::Note{reason}),
                ProviderKind::Checkmarx => Ok(ApprovedAction::Confirmed{reason,severity:severity(report,record)}),
                ProviderKind::Aikido => match severity(report,record) {
                    Some(severity)=>Ok(ApprovedAction::Confirmed{reason,severity:Some(severity)}),
                    None=>Ok(ApprovedAction::Note{reason}),
                },
                ProviderKind::Snyk => Err("Snyk Code does not support true-positive notes or severity mutation".into()),
                _=>Err("Provider action is unsupported".into()),
            }
        }
        _=>Err("Unresolved, excluded or insufficient-confidence assessment leaves provider finding unchanged".into()),
    }
}

fn bounded(value: &str, limit: usize) -> String {
    value
        .chars()
        .scan(0, |bytes, ch| {
            *bytes += ch.len_utf8();
            Some((*bytes, ch))
        })
        .take_while(|(bytes, _)| *bytes <= limit)
        .map(|(_, ch)| if ch.is_control() { ' ' } else { ch })
        .collect()
}
fn reason(report: &FinalReport, record: &ProviderAssessmentRecord) -> String {
    let evidence = record
        .verification
        .as_ref()
        .expect("select requires evidence");
    let text = format!(
        "BC SAST {:?}, confidence {}/10. Repository {}, ref {}, revision {}. Evidence {}:{}; {}",
        evidence.verdict,
        evidence.confidence,
        bounded(
            record
                .origin
                .repository_name
                .as_deref()
                .or(report.repo_name.as_deref())
                .unwrap_or("provider-bound repository"),
            80
        ),
        bounded(
            record
                .origin
                .git_ref
                .as_deref()
                .unwrap_or("provider scope; ref unknown"),
            80
        ),
        bounded(report.git_sha.as_deref().unwrap_or("unknown"), 64),
        bounded(&record.file, 120),
        record.line,
        bounded(&evidence.reason, 400)
    );
    bounded(&bc_redact::redact(&text), 900)
}

fn severity(report: &FinalReport, record: &ProviderAssessmentRecord) -> Option<String> {
    let vector = record.verification.as_ref()?.cvss_vector.as_deref()?;
    // The shared calculator accepts substrings. Require one complete base vector
    // here rather than accepting embedded prose or environmental extensions.
    let parts: Vec<_> = vector.split('/').collect();
    if parts.len() != 9
        || !matches!(parts[0], "CVSS:3.0" | "CVSS:3.1")
        || !matches!(parts[1], "AV:N" | "AV:A" | "AV:L" | "AV:P")
        || !matches!(parts[2], "AC:L" | "AC:H")
        || !matches!(parts[3], "PR:N" | "PR:L" | "PR:H")
        || !matches!(parts[4], "UI:N" | "UI:R")
        || !matches!(parts[5], "S:U" | "S:C")
        || !matches!(parts[6], "C:N" | "C:L" | "C:H")
        || !matches!(parts[7], "I:N" | "I:L" | "I:H")
        || !matches!(parts[8], "A:N" | "A:L" | "A:H")
    {
        return None;
    }
    let score = bc_cvss::score(Some(vector))?;
    let rating = bc_cvss::rating(Some(score)).to_ascii_lowercase();
    if !matches!(rating.as_str(), "low" | "medium" | "high" | "critical") {
        return None;
    }
    let candidates: Vec<_> = report
        .findings
        .iter()
        .map(|r| &r.finding)
        .filter(|f| {
            f.provider_origins.as_slice() == std::slice::from_ref(&record.origin)
                && f.file == record.file
                && f.line_start == record.line
                && f.title == record.title
                && f.cvss_vector.as_deref() == Some(vector)
                && f.cvss_rating
                    .as_ref()
                    .is_some_and(|r| r.eq_ignore_ascii_case(&rating))
                && f.duplicates.is_empty()
        })
        .collect();
    (candidates.len() == 1).then_some(rating)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_model::{ProviderNativeIds, VerificationEvidence};
    fn record(provider: ProviderKind, verdict: Verdict) -> ProviderAssessmentRecord {
        ProviderAssessmentRecord {
            origin: ProviderOrigin {
                provider,
                product: ProviderProduct::Sast,
                source: ProviderSource::Api,
                tenant_id: Some("tenant".into()),
                project_id: Some("project".into()),
                repository_id: Some("repo-id".into()),
                repository_name: Some("owner/repo".into()),
                git_ref: Some("refs/heads/main".into()),
                scan_id: Some("scan".into()),
                native_ids: ProviderNativeIds {
                    issue_id: Some("1".into()),
                    match_based_id: Some("fingerprint".into()),
                    similarity_id: Some("similarity".into()),
                    attack_vector_id: Some("attack".into()),
                    asset_finding_id: Some("asset".into()),
                    group_id: Some("group".into()),
                },
                ..Default::default()
            },
            file: "src/app.rs".into(),
            line: 10,
            title: "candidate".into(),
            verification: Some(VerificationEvidence {
                verdict,
                confidence: 9,
                reason: "input is bounded by the checked guard".into(),
                reasoning: "inspected the source and boundary".into(),
                cvss_vector: None,
            }),
            drop_reason: (verdict == Verdict::FalsePositive).then_some(DropReason::FalsePositive),
            limitations: vec![],
        }
    }
    fn report(record: &ProviderAssessmentRecord) -> FinalReport {
        let mut report:FinalReport=serde_json::from_value(json!({"repo_root":"/repo","git_sha":"revision","findings":[],"chains":[],"summary":""})).unwrap();
        report.provider_ledger.full_scan = true;
        report.provider_ledger.analysis_complete = true;
        report.provider_ledger.assessments = vec![record.clone()];
        report
    }
    #[test]
    fn explicit_false_positive_maps_to_each_native_adapter_without_report_presence() {
        for provider in [
            ProviderKind::Semgrep,
            ProviderKind::Checkmarx,
            ProviderKind::Snyk,
            ProviderKind::Aikido,
        ] {
            let r = record(provider, Verdict::FalsePositive);
            let report = report(&r);
            assert!(report.findings.is_empty());
            let action = select(&report, &r).unwrap();
            assert!(matches!(action, ApprovedAction::FalsePositive { .. }));
            assert!(action.reason().contains("FalsePositive"));
            assert!(action.reason().contains("revision"));
            assert!(action.reason().contains("src/app.rs:10"));
            assert!(!scope_description(provider).is_empty());
        }
        for provider in [ProviderKind::Unknown, ProviderKind::Sonatype] {
            let r = record(provider, Verdict::FalsePositive);
            assert!(select(&report(&r), &r).is_err());
            assert!(scope_description(provider).contains("unsupported"));
        }
    }
    #[test]
    fn supported_true_positives_keep_actionable_without_inventing_severity() {
        for provider in [
            ProviderKind::Semgrep,
            ProviderKind::Checkmarx,
            ProviderKind::Snyk,
            ProviderKind::Aikido,
        ] {
            let r = record(provider, Verdict::TruePositive);
            let result = select(&report(&r), &r);
            match provider {
                ProviderKind::Checkmarx => assert!(matches!(
                    result.unwrap(),
                    ApprovedAction::Confirmed { severity: None, .. }
                )),
                ProviderKind::Snyk => assert!(result.unwrap_err().contains("does not support")),
                _ => assert!(matches!(result.unwrap(), ApprovedAction::Note { .. })),
            }
        }
    }
    #[test]
    fn incomplete_runs_and_missing_or_conflicting_assessments_never_select_a_write() {
        let r = record(ProviderKind::Semgrep, Verdict::FalsePositive);
        for variant in 0..8 {
            let mut report = report(&r);
            match variant {
                0 => report.provider_ledger.full_scan = false,
                1 => report.provider_ledger.resumed = true,
                2 => report.provider_ledger.analysis_complete = false,
                3 => report.degraded = true,
                4 => report.git_sha = None,
                5 => report.provider_ledger.assessments.clear(),
                6 => {
                    let mut conflict = r.clone();
                    conflict.verification = None;
                    report.provider_ledger.assessments.push(conflict);
                }
                _ => report.git_sha = Some(" ".into()),
            }
            assert!(select(&report, &r).is_err());
        }
        for variant in 0..10 {
            let mut r = r.clone();
            match variant {
                0 => r.origin.source = ProviderSource::File,
                1 => r.origin.product = ProviderProduct::Dependency,
                2 => r.origin.native_ids.issue_id = None,
                3 => r.origin.revision = Some("other".into()),
                4 => r.limitations.push("budget exhausted".into()),
                5 => r.verification = None,
                6 => r.verification.as_mut().unwrap().reason.clear(),
                7 => r.verification.as_mut().unwrap().reasoning.clear(),
                8 => r.verification.as_mut().unwrap().confidence = 8,
                _ => r.verification.as_mut().unwrap().confidence = 11,
            }
            assert!(select(&report(&r), &r).is_err());
        }
    }
    #[test]
    fn framework_exclusions_and_unconfirmed_verdicts_are_not_false_positives() {
        for drop in [
            DropReason::Excluded,
            DropReason::Unconfirmed,
            DropReason::VerifyError,
            DropReason::Duplicate,
            DropReason::GuardrailBlocked,
        ] {
            let mut r = record(ProviderKind::Semgrep, Verdict::FalsePositive);
            r.drop_reason = Some(drop);
            assert!(select(&report(&r), &r).is_err());
        }
        let mut r = record(ProviderKind::Semgrep, Verdict::TruePositive);
        r.verification.as_mut().unwrap().confidence = 5;
        assert!(select(&report(&r), &r).is_err());
    }
    #[test]
    fn mutation_groups_cannot_hide_unresolved_or_positive_members() {
        for provider in [
            ProviderKind::Semgrep,
            ProviderKind::Snyk,
            ProviderKind::Checkmarx,
            ProviderKind::Aikido,
        ] {
            for unresolved in [true, false] {
                let r = record(provider, Verdict::FalsePositive);
                let mut other = r.clone();
                other.origin.git_ref = Some("refs/heads/develop".into());
                if unresolved {
                    other.verification = None;
                } else {
                    other.verification.as_mut().unwrap().verdict = Verdict::TruePositive;
                    other.drop_reason = None;
                }
                let mut report = report(&r);
                report.provider_ledger.assessments.push(other);
                assert!(select(&report, &r).unwrap_err().contains("mutation group"));
            }
        }
        let r = record(ProviderKind::Checkmarx, Verdict::FalsePositive);
        let mut other = r.clone();
        other.origin.project_id = Some("other-project".into());
        other.verification = None;
        assert_ne!(scope_key(&r.origin), scope_key(&other.origin));
        let mut report = report(&r);
        report.provider_ledger.assessments.push(other);
        assert!(select(&report, &r).is_err());
    }
    #[test]
    fn operation_keys_ignore_mutable_state_and_separate_native_targets() {
        for provider in [
            ProviderKind::Semgrep,
            ProviderKind::Snyk,
            ProviderKind::Checkmarx,
            ProviderKind::Aikido,
            ProviderKind::Unknown,
        ] {
            let r = record(provider, Verdict::FalsePositive);
            let mut o = r.origin.clone();
            o.state = Some("ignored".into());
            o.severity = Some("low".into());
            o.git_ref = None;
            o.revision = Some("new".into());
            assert_eq!(scope_key(&r.origin), scope_key(&o));
            o.tenant_id = Some("other-tenant".into());
            assert_ne!(scope_key(&r.origin), scope_key(&o));
        }
    }
    #[test]
    fn reasons_are_bounded_valid_utf8_and_redacted() {
        let mut r = record(ProviderKind::Semgrep, Verdict::FalsePositive);
        r.file = "é".repeat(1000);
        r.verification.as_mut().unwrap().reason =
            format!("AKIAIOSFODNN7EXAMPLE {}", "é".repeat(1000));
        let action = select(&report(&r), &r).unwrap();
        assert!(action.reason().len() <= 900);
        assert!(!action.reason().contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(!action.reason().chars().any(char::is_control));
        assert_eq!(bounded("é\nZ", 3), "é ");
    }
    fn add_individual(
        report: &mut FinalReport,
        r: &ProviderAssessmentRecord,
        vector: &str,
        rating: &str,
    ) {
        let mut finding:bc_model::Finding=serde_json::from_value(json!({"chunk_id":"external","file":r.file,"line_start":r.line,"line_end":r.line,"vuln_class":"other","title":r.title,"description":"claim","code_snippet":"","confidence":0.5})).unwrap();
        finding.provider_origins = vec![r.origin.clone()];
        finding.cvss_vector = Some(vector.into());
        finding.cvss_rating = Some(rating.into());
        report.findings.push(bc_model::RankedFinding {
            finding,
            severity: bc_model::Severity::Low,
            exploitability_notes: "chain severity is unrelated".into(),
        });
    }
    #[test]
    fn severity_requires_matching_standalone_vector_not_chain_or_framework_rank() {
        const VECTOR: &str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
        for provider in [ProviderKind::Aikido, ProviderKind::Checkmarx] {
            let mut r = record(provider, Verdict::TruePositive);
            r.verification.as_mut().unwrap().cvss_vector = Some(VECTOR.into());
            let mut report = report(&r);
            add_individual(&mut report, &r, VECTOR, "Critical");
            assert!(
                matches!(select(&report,&r).unwrap(),ApprovedAction::Confirmed{severity:Some(s),..} if s=="critical")
            );
            report.findings[0].finding.cvss_rating = Some("Low".into());
            assert!(severity(&report, &r).is_none());
            report.findings[0].finding.cvss_rating = Some("Critical".into());
            report.findings.push(report.findings[0].clone());
            assert!(severity(&report, &r).is_none());
            report.findings.pop();
            report.findings[0]
                .finding
                .provider_origins
                .push(ProviderOrigin::default());
            assert!(severity(&report, &r).is_none());
        }
        for vector in [
            "bad",
            "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:HH",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H ",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/I:H",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/X:H",
            "CVSS:3.1/AC:L/AV:N/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS:3.1/AV:N/AC:X/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS:3.1/AV:N/AC:L/PR:X/UI:N/S:U/C:H/I:H/A:H",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:X/S:U/C:H/I:H/A:H",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:X/C:H/I:H/A:H",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:X/I:H/A:H",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:X/A:H",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
        ] {
            let mut r = record(ProviderKind::Checkmarx, Verdict::TruePositive);
            r.verification.as_mut().unwrap().cvss_vector = Some(vector.into());
            let mut report = report(&r);
            add_individual(&mut report, &r, vector, "Critical");
            assert!(severity(&report, &r).is_none());
        }
    }
}
