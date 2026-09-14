//! Driver `rules` catalog and the CWE `taxonomies` component, ported from
//! `enrich.py::_driver_rules`/`_cwe_taxonomy`.

use std::collections::HashSet;

use bc_model::RankedFinding;

use crate::result::rule_id_for;
use crate::types::{MessageText, Taxon, Taxonomy};
use crate::CWE_TAXONOMY_GUID;

/// One rule per distinct `VulnClass` (this port's rule-dedup key —
/// see [`rule_id_for`]), in first-seen order across `findings`. Each
/// rule's `shortDescription` borrows the CWE name of the first finding in
/// that bucket that resolves one, if any.
pub fn build_rules(findings: &[RankedFinding]) -> Vec<crate::types::Rule> {
    let mut order: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut rep_name: std::collections::HashMap<String, String> = std::collections::HashMap::new();

    for rf in findings {
        let f = &rf.finding;
        let rid = rule_id_for(f).to_string();
        if seen.insert(rid.clone()) {
            order.push(rid.clone());
        }
        if !rep_name.contains_key(&rid) {
            if let Some(cwe) = bc_cwe::cwe_for(f.cwe.as_deref(), Some(f.vuln_class.as_str())) {
                let name = bc_cwe::cwe_name(Some(&cwe));
                if !name.is_empty() {
                    rep_name.insert(rid.clone(), name.to_string());
                }
            }
        }
    }

    order
        .into_iter()
        .map(|rid| {
            let short_description = rep_name.get(&rid).map(|n| MessageText { text: n.clone() });
            crate::types::Rule {
                id: rid.clone(),
                name: rid,
                short_description,
            }
        })
        .collect()
}

/// The single CWE taxonomy component, `taxa` deduplicated and sorted
/// ascending by CWE number (the one array in this builder NOT kept in
/// first-seen order, matching the Python source).
pub fn build_taxonomy(findings: &[RankedFinding]) -> Taxonomy {
    let mut cwes: HashSet<String> = HashSet::new();
    for rf in findings {
        let f = &rf.finding;
        if let Some(cwe) = bc_cwe::cwe_for(f.cwe.as_deref(), Some(f.vuln_class.as_str())) {
            cwes.insert(cwe);
        }
        // The CWE lenses S7 merged into this finding also appear as
        // `result.taxa` refs (see `bc_sarif::result::build_result`), and
        // a SARIF `taxa` ref that names no `taxonomy.taxa` entry is a
        // dangling pointer a consumer may reject outright.
        for cwe in &f.related_cwes {
            if let Some(cwe) = bc_cwe::cwe_for(Some(cwe), None) {
                cwes.insert(cwe);
            }
        }
    }
    let mut sorted: Vec<String> = cwes.into_iter().collect();
    sorted.sort_by_key(|c| {
        c.strip_prefix("CWE-")
            .and_then(|n| n.parse::<u64>().ok())
            .unwrap_or(0)
    });

    let taxa: Vec<Taxon> = sorted
        .into_iter()
        .map(|cwe| {
            let name = bc_cwe::cwe_name(Some(&cwe));
            let number = cwe.strip_prefix("CWE-").unwrap_or(&cwe).to_string();
            Taxon {
                id: cwe,
                help_uri: format!("https://cwe.mitre.org/data/definitions/{number}.html"),
                name: (!name.is_empty()).then(|| name.to_string()),
                short_description: (!name.is_empty()).then(|| MessageText {
                    text: name.to_string(),
                }),
            }
        })
        .collect();

    Taxonomy {
        guid: CWE_TAXONOMY_GUID.to_string(),
        name: "CWE".to_string(),
        organization: "MITRE".to_string(),
        short_description: MessageText {
            text: "The MITRE Common Weakness Enumeration".to_string(),
        },
        information_uri: "https://cwe.mitre.org/".to_string(),
        taxa,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_model::{Finding, Severity, VulnClass};

    fn finding(vuln_class: VulnClass, cwe: Option<&str>) -> RankedFinding {
        RankedFinding {
            finding: Finding {
                provider_origins: Vec::new(),
                chunk_id: "c1".to_string(),
                file: "a.py".to_string(),
                line_start: 1,
                line_end: 1,
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
                confidence: 0.5,
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
            },
            severity: Severity::High,
            exploitability_notes: String::new(),
        }
    }

    #[test]
    fn one_rule_per_distinct_vuln_class_in_first_seen_order() {
        let findings = vec![
            finding(VulnClass::Injection, None),
            finding(VulnClass::UseAfterFree, None),
            finding(VulnClass::Injection, None),
        ];
        let rules = build_rules(&findings);
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].id, "injection");
        assert_eq!(rules[1].id, "use-after-free");
    }

    #[test]
    fn rule_name_equals_id() {
        let rules = build_rules(&[finding(VulnClass::Injection, None)]);
        assert_eq!(rules[0].name, rules[0].id);
    }

    #[test]
    fn rule_short_description_borrows_resolved_cwe_name() {
        let rules = build_rules(&[finding(VulnClass::UseAfterFree, None)]);
        assert_eq!(
            rules[0].short_description.as_ref().unwrap().text,
            "Use After Free"
        );
    }

    #[test]
    fn rule_short_description_absent_when_no_cwe_resolves() {
        let rules = build_rules(&[finding(VulnClass::Other, None)]);
        assert!(rules[0].short_description.is_none());
    }

    #[test]
    fn empty_findings_yields_no_rules() {
        assert!(build_rules(&[]).is_empty());
    }

    #[test]
    fn taxonomy_has_the_fixed_guid_and_mitre_metadata() {
        let taxonomy = build_taxonomy(&[finding(VulnClass::UseAfterFree, None)]);
        assert_eq!(taxonomy.guid, "b7c8d9e0-1f2a-3b4c-5d6e-7f8090a1b2c3");
        assert_eq!(taxonomy.name, "CWE");
        assert_eq!(taxonomy.organization, "MITRE");
        assert_eq!(taxonomy.information_uri, "https://cwe.mitre.org/");
    }

    #[test]
    fn taxonomy_taxa_deduplicated_and_sorted_numerically_ascending() {
        let findings = vec![
            finding(VulnClass::UseAfterFree, None), // CWE-416
            finding(VulnClass::Injection, None),    // CWE-74
            finding(VulnClass::UseAfterFree, None), // duplicate CWE-416
        ];
        let taxonomy = build_taxonomy(&findings);
        assert_eq!(taxonomy.taxa.len(), 2);
        assert_eq!(taxonomy.taxa[0].id, "CWE-74");
        assert_eq!(taxonomy.taxa[1].id, "CWE-416");
    }

    #[test]
    fn taxon_help_uri_and_name() {
        let taxonomy = build_taxonomy(&[finding(VulnClass::UseAfterFree, None)]);
        assert_eq!(
            taxonomy.taxa[0].help_uri,
            "https://cwe.mitre.org/data/definitions/416.html"
        );
        assert_eq!(taxonomy.taxa[0].name.as_deref(), Some("Use After Free"));
        assert_eq!(
            taxonomy.taxa[0].short_description.as_ref().unwrap().text,
            "Use After Free"
        );
    }

    #[test]
    fn taxon_unknown_cwe_has_no_name_or_short_description() {
        let findings = vec![finding(VulnClass::Other, Some("CWE-999999"))];
        let taxonomy = build_taxonomy(&findings);
        assert_eq!(taxonomy.taxa.len(), 1);
        assert!(taxonomy.taxa[0].name.is_none());
        assert!(taxonomy.taxa[0].short_description.is_none());
    }

    #[test]
    fn merged_cwe_lenses_are_declared_in_the_taxonomy_too() {
        // `build_result` emits a `taxa` ref per merged lens, and a ref
        // naming no taxonomy entry is a dangling pointer.
        let mut rf = finding(VulnClass::Other, Some("CWE-200"));
        rf.finding.related_cwes = vec!["CWE-284".to_string()];
        let taxonomy = build_taxonomy(&[rf]);
        let ids: Vec<&str> = taxonomy.taxa.iter().map(|t| t.id.as_str()).collect();
        // Sorted numerically by `build_taxonomy`.
        assert_eq!(ids, vec!["CWE-200", "CWE-284"]);
    }

    #[test]
    fn no_resolvable_cwes_yields_an_empty_taxa_array_not_an_absent_taxonomy() {
        let taxonomy = build_taxonomy(&[finding(VulnClass::Other, None)]);
        assert!(taxonomy.taxa.is_empty());
        assert_eq!(taxonomy.guid, "b7c8d9e0-1f2a-3b4c-5d6e-7f8090a1b2c3");
    }
}
