//! CWE/vuln-class matching between findings and a compliance policy's
//! requirements, plus the report-time tag/filter step this module's
//! whole purpose builds toward.

use bc_model::{DropReason, DroppedFinding, Finding};

use crate::types::{CompliancePolicy, ScopeMode};

/// IDs of every requirement `cwe`/`vuln_class` satisfies (a finding can
/// match more than one requirement — e.g. a single CWE mapped under both
/// an injection-flaws requirement and a broader secure-coding one).
pub fn matching_requirement_ids(
    policy: &CompliancePolicy,
    cwe: Option<&str>,
    vuln_class: &str,
) -> Vec<String> {
    policy
        .requirements
        .iter()
        .filter(|r| {
            let cwe_match = cwe.is_some_and(|c| r.cwes.iter().any(|x| x == c));
            let vc_match = r.vuln_classes.iter().any(|v| v == vuln_class);
            cwe_match || vc_match
        })
        .map(|r| r.id.clone())
        .collect()
}

/// Tags every finding with the union of requirement IDs it satisfies
/// across every active policy (`Finding.compliance_requirements`); a
/// policy with empty `requirements` (a pure-guidance policy) contributes
/// no tags and never causes a drop, regardless of its `scope_mode`.
///
/// Multiple [`ScopeMode::Filter`] policies combine with OR semantics: a
/// finding is dropped only when it fails to match EVERY `Filter`-mode
/// policy active this run (i.e. matching just one of several combined
/// frameworks — say, ASVS or a custom PCI rules file — is enough to keep
/// it). `Annotate`-mode policies never cause a drop. A no-op when no
/// policy has any requirements at all.
///
/// Deliberately runs on the plain `Vec<Finding>` assembled just before
/// S8, not on `FinalReport.findings` after S8 runs: `Chain.steps`
/// references findings by index, so removing findings *after* chains
/// are built would desync every chain's step indices. Filtering here
/// means S8 never even builds a chain step for an out-of-scope finding
/// in the first place.
pub fn apply_to_findings(
    policies: &[CompliancePolicy],
    findings: &mut Vec<Finding>,
    dropped: &mut Vec<DroppedFinding>,
) {
    let active: Vec<&CompliancePolicy> = policies
        .iter()
        .filter(|p| !p.requirements.is_empty())
        .collect();
    if active.is_empty() {
        return;
    }
    let filter_names: Vec<&str> = active
        .iter()
        .filter(|p| p.scope_mode == ScopeMode::Filter)
        .map(|p| p.name.as_str())
        .collect();

    let mut kept = Vec::with_capacity(findings.len());
    for mut f in std::mem::take(findings) {
        let mut ids: Vec<String> = Vec::new();
        let mut satisfied_a_filter = false;
        for p in &active {
            let matched = matching_requirement_ids(p, f.cwe.as_deref(), f.vuln_class.as_str());
            if !matched.is_empty() && p.scope_mode == ScopeMode::Filter {
                satisfied_a_filter = true;
            }
            for id in matched {
                if !ids.contains(&id) {
                    ids.push(id);
                }
            }
        }
        if !filter_names.is_empty() && !satisfied_a_filter {
            dropped.push(DroppedFinding {
                file: f.file.clone(),
                line: f.line_start,
                vuln_class: f.vuln_class,
                title: f.title.clone(),
                chunk_id: f.chunk_id.clone(),
                reason: DropReason::Excluded,
                detail: format!("outside compliance scope: {}", filter_names.join(", ")),
                canonical_idx: None,
                provider_origins: f.provider_origins.clone(),
                verification: bc_model::VerificationEvidence::from_finding(&f),
            });
            continue;
        }
        f.compliance_requirements = ids;
        kept.push(f);
    }
    *findings = kept;
}

/// Concatenates every active policy's non-empty `guidance` text under its
/// own `## <name>` header, in order — this is the string threaded into
/// `ContextPackage.compliance_guidance` and spliced into S1/S3/S4/S6/S8's
/// prompts. Empty when `policies` is empty or every policy's guidance is
/// empty — a full no-op for every prompt splice.
pub fn combined_guidance(policies: &[CompliancePolicy]) -> String {
    let parts: Vec<String> = policies
        .iter()
        .filter(|p| !p.guidance.is_empty())
        .map(|p| format!("## {}\n{}", p.name, p.guidance))
        .collect();
    parts.join("\n\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_model::VulnClass;

    fn requirement(id: &str, cwes: &[&str], vuln_classes: &[&str]) -> crate::types::Requirement {
        crate::types::Requirement {
            id: id.to_string(),
            title: String::new(),
            cwes: cwes.iter().map(|s| s.to_string()).collect(),
            vuln_classes: vuln_classes.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn policy(
        scope_mode: ScopeMode,
        requirements: Vec<crate::types::Requirement>,
    ) -> CompliancePolicy {
        CompliancePolicy {
            name: "test policy".to_string(),
            guidance: String::new(),
            scope_mode,
            requirements,
        }
    }

    fn finding(cwe: Option<&str>, vuln_class: VulnClass) -> Finding {
        Finding {
            provider_origins: Vec::new(),
            chunk_id: "c".to_string(),
            file: "a.py".to_string(),
            line_start: 10,
            line_end: 10,
            vuln_class,
            cwe: cwe.map(str::to_string),
            title: "t".to_string(),
            impact: String::new(),
            description: "d".to_string(),
            exploit_scenario: String::new(),
            preconditions: Vec::new(),
            recommendation: String::new(),
            code_snippet: "x".to_string(),
            source_ref: None,
            sink_ref: None,
            backfilled_refs: Vec::new(),
            reanchored: Vec::new(),
            compliance_requirements: Vec::new(),
            confidence: 0.9,
            votes: 1,
            duplicates: Vec::new(),
            verdict: None,
            verdict_confidence: None,
            verdict_reason: String::new(),
            cvss_vector: None,
            cvss_score: None,
            cvss_rating: None,
            verifier_reasoning: String::new(),
            vsvs_vector: None,
            vsvs_score: None,
            vsvs_rating: None,
            offensive_priority: None,
            offensive_reason: String::new(),
            related_cwes: Vec::new(),
        }
    }

    // ── matching_requirement_ids ─────────────────────────────────────

    #[test]
    fn matches_by_cwe() {
        let p = policy(
            ScopeMode::Annotate,
            vec![requirement("R1", &["CWE-89"], &[])],
        );
        let ids = matching_requirement_ids(&p, Some("CWE-89"), "injection");
        assert_eq!(ids, vec!["R1".to_string()]);
    }

    #[test]
    fn matches_by_vuln_class_when_cwe_is_absent() {
        let p = policy(
            ScopeMode::Annotate,
            vec![requirement("R1", &[], &["injection"])],
        );
        let ids = matching_requirement_ids(&p, None, "injection");
        assert_eq!(ids, vec!["R1".to_string()]);
    }

    #[test]
    fn a_finding_can_match_multiple_requirements() {
        let p = policy(
            ScopeMode::Annotate,
            vec![
                requirement("R1", &["CWE-89"], &[]),
                requirement("R2", &[], &["injection"]),
            ],
        );
        let ids = matching_requirement_ids(&p, Some("CWE-89"), "injection");
        assert_eq!(ids, vec!["R1".to_string(), "R2".to_string()]);
    }

    #[test]
    fn no_match_when_neither_cwe_nor_vuln_class_line_up() {
        let p = policy(
            ScopeMode::Annotate,
            vec![requirement("R1", &["CWE-89"], &["injection"])],
        );
        let ids = matching_requirement_ids(&p, Some("CWE-79"), "other");
        assert!(ids.is_empty());
    }

    // ── apply_to_findings ─────────────────────────────────────────────

    #[test]
    fn a_pure_guidance_policy_with_no_requirements_is_a_no_op() {
        let p = policy(ScopeMode::Filter, Vec::new());
        let mut findings = vec![finding(None, VulnClass::Other)];
        let mut dropped = Vec::new();
        apply_to_findings(&[p], &mut findings, &mut dropped);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].compliance_requirements.is_empty());
        assert!(dropped.is_empty());
    }

    #[test]
    fn annotate_mode_tags_matches_and_keeps_non_matches() {
        let p = policy(
            ScopeMode::Annotate,
            vec![requirement("R1", &["CWE-89"], &[])],
        );
        let mut findings = vec![
            finding(Some("CWE-89"), VulnClass::Injection),
            finding(Some("CWE-79"), VulnClass::Other),
        ];
        let mut dropped = Vec::new();
        apply_to_findings(&[p], &mut findings, &mut dropped);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].compliance_requirements, vec!["R1".to_string()]);
        assert!(findings[1].compliance_requirements.is_empty());
        assert!(dropped.is_empty());
    }

    #[test]
    fn filter_mode_drops_non_matches_and_keeps_matches_tagged() {
        let p = policy(ScopeMode::Filter, vec![requirement("R1", &["CWE-89"], &[])]);
        let mut findings = vec![
            finding(Some("CWE-89"), VulnClass::Injection),
            finding(Some("CWE-79"), VulnClass::Other),
        ];
        let mut dropped = Vec::new();
        apply_to_findings(&[p], &mut findings, &mut dropped);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].compliance_requirements, vec!["R1".to_string()]);
        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0].reason, DropReason::Excluded);
        assert!(dropped[0].detail.contains("test policy"));
    }

    #[test]
    fn filter_mode_preserves_findings_original_order_among_survivors() {
        let p = policy(ScopeMode::Filter, vec![requirement("R1", &["CWE-89"], &[])]);
        let mut a = finding(Some("CWE-89"), VulnClass::Injection);
        a.title = "first".to_string();
        let mut b = finding(Some("CWE-79"), VulnClass::Other);
        b.title = "dropped".to_string();
        let mut c = finding(Some("CWE-89"), VulnClass::Injection);
        c.title = "second".to_string();
        let mut findings = vec![a, b, c];
        let mut dropped = Vec::new();
        apply_to_findings(&[p], &mut findings, &mut dropped);
        assert_eq!(
            findings
                .iter()
                .map(|f| f.title.as_str())
                .collect::<Vec<_>>(),
            vec!["first", "second"]
        );
    }

    #[test]
    fn no_active_policies_is_a_no_op() {
        let mut findings = vec![finding(Some("CWE-89"), VulnClass::Injection)];
        let mut dropped = Vec::new();
        apply_to_findings(&[], &mut findings, &mut dropped);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].compliance_requirements.is_empty());
        assert!(dropped.is_empty());
    }

    #[test]
    fn a_finding_is_tagged_with_the_union_of_every_active_policys_matches() {
        let asvs = {
            let mut p = policy(
                ScopeMode::Annotate,
                vec![requirement("V5.3.2", &["CWE-89"], &[])],
            );
            p.name = "ASVS".to_string();
            p
        };
        let pci = {
            let mut p = policy(
                ScopeMode::Annotate,
                vec![requirement("6.2.4", &[], &["injection"])],
            );
            p.name = "PCI".to_string();
            p
        };
        let mut findings = vec![finding(Some("CWE-89"), VulnClass::Injection)];
        let mut dropped = Vec::new();
        apply_to_findings(&[asvs, pci], &mut findings, &mut dropped);
        assert_eq!(
            findings[0].compliance_requirements,
            vec!["V5.3.2".to_string(), "6.2.4".to_string()]
        );
    }

    #[test]
    fn matching_the_same_requirement_via_two_policies_is_not_duplicated() {
        let a = {
            let mut p = policy(
                ScopeMode::Annotate,
                vec![requirement("R1", &["CWE-89"], &[])],
            );
            p.name = "A".to_string();
            p
        };
        let b = {
            let mut p = policy(
                ScopeMode::Annotate,
                vec![requirement("R1", &[], &["injection"])],
            );
            p.name = "B".to_string();
            p
        };
        let mut findings = vec![finding(Some("CWE-89"), VulnClass::Injection)];
        let mut dropped = Vec::new();
        apply_to_findings(&[a, b], &mut findings, &mut dropped);
        assert_eq!(findings[0].compliance_requirements, vec!["R1".to_string()]);
    }

    #[test]
    fn filter_policies_combine_with_or_semantics_across_frameworks() {
        // A finding matching ONLY the second of two Filter-mode policies
        // must still survive — combining ASVS + a custom PCI rules file
        // should widen what's kept, not require matching every framework
        // at once.
        let asvs = {
            let mut p = policy(
                ScopeMode::Filter,
                vec![requirement("V5.3.2", &["CWE-22"], &[])],
            );
            p.name = "ASVS".to_string();
            p
        };
        let pci = {
            let mut p = policy(
                ScopeMode::Filter,
                vec![requirement("6.2.4", &["CWE-89"], &[])],
            );
            p.name = "PCI".to_string();
            p
        };
        let mut findings = vec![finding(Some("CWE-89"), VulnClass::Injection)];
        let mut dropped = Vec::new();
        apply_to_findings(&[asvs, pci], &mut findings, &mut dropped);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].compliance_requirements,
            vec!["6.2.4".to_string()]
        );
        assert!(dropped.is_empty());
    }

    #[test]
    fn a_finding_matching_no_filter_policy_at_all_is_dropped_once_naming_every_policy() {
        let asvs = {
            let mut p = policy(
                ScopeMode::Filter,
                vec![requirement("V5.3.2", &["CWE-22"], &[])],
            );
            p.name = "ASVS".to_string();
            p
        };
        let pci = {
            let mut p = policy(
                ScopeMode::Filter,
                vec![requirement("6.2.4", &["CWE-89"], &[])],
            );
            p.name = "PCI".to_string();
            p
        };
        let mut findings = vec![finding(Some("CWE-79"), VulnClass::Other)];
        let mut dropped = Vec::new();
        apply_to_findings(&[asvs, pci], &mut findings, &mut dropped);
        assert!(findings.is_empty());
        assert_eq!(dropped.len(), 1);
        assert!(dropped[0].detail.contains("ASVS"));
        assert!(dropped[0].detail.contains("PCI"));
    }

    #[test]
    fn an_annotate_policy_never_causes_a_drop_even_when_combined_with_a_filter_policy() {
        let annotate_only = {
            let mut p = policy(
                ScopeMode::Annotate,
                vec![requirement("R1", &["CWE-79"], &[])],
            );
            p.name = "Annotate-only".to_string();
            p
        };
        let filter_only = {
            let mut p = policy(ScopeMode::Filter, vec![requirement("R2", &["CWE-89"], &[])]);
            p.name = "Filter-only".to_string();
            p
        };
        // Matches the Annotate policy but NOT the Filter policy — must
        // still be dropped, since at least one Filter policy is active
        // and this finding satisfies none of them.
        let mut findings = vec![finding(Some("CWE-79"), VulnClass::Other)];
        let mut dropped = Vec::new();
        apply_to_findings(&[annotate_only, filter_only], &mut findings, &mut dropped);
        assert!(findings.is_empty());
        assert_eq!(dropped.len(), 1);
    }

    #[test]
    fn a_pure_guidance_policy_mixed_in_contributes_no_tags_and_never_drops() {
        let guidance_only = policy(ScopeMode::Filter, Vec::new());
        let real = {
            let mut p = policy(
                ScopeMode::Annotate,
                vec![requirement("R1", &["CWE-89"], &[])],
            );
            p.name = "Real".to_string();
            p
        };
        let mut findings = vec![finding(Some("CWE-89"), VulnClass::Injection)];
        let mut dropped = Vec::new();
        apply_to_findings(&[guidance_only, real], &mut findings, &mut dropped);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].compliance_requirements, vec!["R1".to_string()]);
        assert!(dropped.is_empty());
    }

    // ── combined_guidance ───────────────────────────────────────────────

    #[test]
    fn combined_guidance_is_empty_for_no_policies() {
        assert_eq!(combined_guidance(&[]), "");
    }

    #[test]
    fn combined_guidance_joins_named_headers_in_order() {
        let mut a = policy(ScopeMode::Annotate, Vec::new());
        a.name = "ASVS".to_string();
        a.guidance = "Prioritize injection.".to_string();
        let mut b = policy(ScopeMode::Annotate, Vec::new());
        b.name = "Custom".to_string();
        b.guidance = "Also check auth flows.".to_string();
        let out = combined_guidance(&[a, b]);
        assert_eq!(
            out,
            "## ASVS\nPrioritize injection.\n\n## Custom\nAlso check auth flows."
        );
    }

    #[test]
    fn combined_guidance_skips_policies_with_empty_guidance() {
        let mut a = policy(ScopeMode::Annotate, Vec::new());
        a.name = "Silent".to_string();
        let mut b = policy(ScopeMode::Annotate, Vec::new());
        b.name = "Vocal".to_string();
        b.guidance = "text".to_string();
        let out = combined_guidance(&[a, b]);
        assert_eq!(out, "## Vocal\ntext");
    }
}
