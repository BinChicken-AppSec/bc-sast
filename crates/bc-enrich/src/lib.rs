//! Post-S7 finding enrichment: CMDB-driven environmental CVSS
//! ("VulContextSeverity") + OffensivePriority (P1-P4), ported from
//! `orchestrator/enrich_findings.py::_enrich_findings` plus its
//! `report/enrich.py` dependencies (`AppInfo`/CMDB lookup, `vsvs_score`,
//! `offensive_priority_for`).
//!
//! **Deliberately not ported**: `_enrich_findings`'s `path_prefix`
//! parameter (batch/`--group-by-app` multi-repo scanning, prefixing every
//! finding's `file`/`source_ref`/`sink_ref`) — this port's orchestrator
//! scans one repo per invocation (the GitHub Action's own unit of work),
//! so there is no multi-repo output layout to prefix into.

mod cmdb;
mod csv_parse;
mod offensive;
mod vsvs;

pub use cmdb::{load_cmdb_csv, lookup_app, normalize_app_id, AppInfo};
pub use offensive::{offensive_label, offensive_priority_for};
pub use vsvs::{vsvs_score, VsvsResult};

use bc_model::Finding;

/// Post-S7: attach `vsvs_vector`/`vsvs_score`/`vsvs_rating` (only when the
/// finding has a base CVSS vector and `app` resolved) and
/// `offensive_priority`/`offensive_reason` (always, `app` gracefully
/// optional) to every verified finding, so S8/the renderer can surface
/// them natively — ported from `_enrich_findings`.
pub fn enrich_findings(findings: &mut [Finding], app: Option<&AppInfo>) {
    for f in findings {
        if let (Some(vector), Some(app)) = (f.cvss_vector.as_deref(), app) {
            if let Some(vr) = vsvs_score(Some(vector), app) {
                f.vsvs_vector = Some(vr.vector);
                f.vsvs_score = Some(vr.score);
                f.vsvs_rating = Some(vr.rating);
            }
        }
        let (priority, reason) = offensive_priority_for(
            &f.title,
            f.vuln_class.as_str(),
            &f.description,
            f.cvss_vector.as_deref(),
            app,
        );
        f.offensive_priority = Some(priority);
        f.offensive_reason = reason;
    }
}

#[cfg(test)]
mod tests {
    use bc_model::VulnClass;

    use super::*;

    fn finding(cvss_vector: Option<&str>) -> Finding {
        Finding {
            provider_origins: Vec::new(),
            chunk_id: "c".to_string(),
            file: "a.py".to_string(),
            line_start: 1,
            line_end: 1,
            vuln_class: VulnClass::Injection,
            cwe: None,
            title: "unauthenticated access".to_string(),
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
            cvss_vector: cvss_vector.map(String::from),
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

    #[test]
    fn offensive_priority_is_always_set_even_with_no_app_and_no_vector() {
        let mut findings = vec![finding(None)];
        enrich_findings(&mut findings, None);
        assert!(findings[0].offensive_priority.is_some());
    }

    #[test]
    fn vsvs_fields_stay_empty_without_a_cvss_vector() {
        let app = AppInfo {
            externally_facing: true,
            ..Default::default()
        };
        let mut findings = vec![finding(None)];
        enrich_findings(&mut findings, Some(&app));
        assert_eq!(findings[0].vsvs_score, None);
        assert!(findings[0].offensive_priority.is_some());
    }

    #[test]
    fn vsvs_fields_stay_empty_without_an_app() {
        let mut findings = vec![finding(Some(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        ))];
        enrich_findings(&mut findings, None);
        assert_eq!(findings[0].vsvs_score, None);
    }

    #[test]
    fn vsvs_fields_are_populated_with_both_vector_and_app() {
        let app = AppInfo {
            externally_facing: true,
            pci_scoped: true,
            ..Default::default()
        };
        let mut findings = vec![finding(Some(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        ))];
        enrich_findings(&mut findings, Some(&app));
        assert!(findings[0].vsvs_score.is_some());
        assert!(findings[0].vsvs_rating.is_some());
        assert!(findings[0].vsvs_vector.is_some());
    }

    #[test]
    fn every_finding_in_the_slice_is_enriched() {
        let mut findings = vec![finding(None), finding(None)];
        enrich_findings(&mut findings, None);
        assert!(findings.iter().all(|f| f.offensive_priority.is_some()));
    }
}
