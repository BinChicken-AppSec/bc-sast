use appsec_model::{DupLocation, Finding, RankedFinding};
use appsec_validation_scoring::ValidationScore;

use crate::fingerprint::{
    finding_fingerprint, FINGERPRINT_KEY, FINGERPRINT_KEY_V2, FINGERPRINT_KEY_V3,
};
use crate::severity::{cvss_rating, rank, round1, round2, sarif_level, security_severity};
use crate::types::{
    ArtifactLocation, Location, MessageText, PhysicalLocation, Region, RelatedLocation,
    ResultProperties, SarifResult, TaxonRef, ToolComponentRef,
};
use crate::CWE_TAXONOMY_GUID;

const DUP_LOCATION_MESSAGE: &str = "Additional call site — collapsed during dedup; same root \
                                     cause as the primary location and needs the same fix.";

pub fn rule_id_for(f: &Finding) -> &'static str {
    f.vuln_class.as_str()
}

fn message(f: &Finding) -> MessageText {
    let text = match f.cvss_vector.as_deref().filter(|v| !v.is_empty()) {
        Some(vector) => match f.cvss_score.filter(|s| *s >= 0.0) {
            Some(score) => format!("{}  [CVSS {score:.1}: {vector}]", f.title),
            None => format!("{}  [CVSS: {vector}]", f.title),
        },
        None => f.title.clone(),
    };
    MessageText { text }
}

fn region_for(start_line: i64, end_line: i64) -> Region {
    let end = if end_line != 0 && end_line != start_line {
        Some(end_line)
    } else {
        None
    };
    Region {
        start_line,
        end_line: end,
    }
}

fn primary_location(f: &Finding) -> Location {
    let uri = if f.file.is_empty() {
        "unknown".to_string()
    } else {
        f.file.clone()
    };
    Location {
        physical_location: PhysicalLocation {
            artifact_location: ArtifactLocation { uri },
            region: region_for(f.line_start, f.line_end),
        },
    }
}

fn related_location(d: &DupLocation) -> RelatedLocation {
    RelatedLocation {
        physical_location: PhysicalLocation {
            artifact_location: ArtifactLocation {
                uri: d.file.clone(),
            },
            region: region_for(d.line_start, d.line_end),
        },
        message: MessageText {
            text: DUP_LOCATION_MESSAGE.to_string(),
        },
    }
}

fn truncate_description(description: &str) -> String {
    if description.chars().count() > 4000 {
        let mut truncated: String = description.chars().take(4000).collect();
        truncated.push('…');
        truncated
    } else {
        description.to_string()
    }
}

fn set_validation(props: &mut ResultProperties, v: &ValidationScore) {
    props.validation_status = Some(v.fix_status.as_str().to_string());
    props.validation_score = v.score();
    props.validation_justification = Some(v.justification.clone());
    props.merge_readiness = Some(
        appsec_validation_scoring::derive_merge_readiness(v.fix_status)
            .as_str()
            .to_string(),
    );
}

pub fn apply_validation(result: &mut SarifResult, validation: &ValidationScore) {
    set_validation(&mut result.properties, validation);
}

fn properties(
    rf: &RankedFinding,
    eff_cwe: Option<&str>,
    related_count: usize,
    validation: Option<&ValidationScore>,
) -> ResultProperties {
    let f = &rf.finding;
    let cwe_name = {
        let n = appsec_cwe::cwe_name(eff_cwe);
        (!n.is_empty()).then(|| n.to_string())
    };
    let (vul_vector, vul_score, vul_rating) = match f.vsvs_score.filter(|s| *s >= 0.0) {
        Some(s) => (
            f.vsvs_vector.clone(),
            Some(round1(s)),
            f.vsvs_rating.clone(),
        ),
        None => (None, None, None),
    };
    let mut props = ResultProperties {
        severity: crate::wire::severity_lower(rf.severity).to_string(),
        security_severity: security_severity(rf.severity, f.cvss_score),
        cvss_rating: cvss_rating(rf.severity, f.cvss_score).to_string(),
        category: rule_id_for(f).to_string(),
        cvss_vector: f.cvss_vector.clone().filter(|v| !v.is_empty()),
        cwe: eff_cwe.map(|c| appsec_cwe::cwe_label(Some(c))),
        cwe_id: eff_cwe.map(str::to_string),
        cwe_name,
        cvss_score: f.cvss_score.filter(|s| *s >= 0.0).map(round1),
        vul_context_severity_vector: vul_vector,
        vul_context_severity_score: vul_score,
        vul_context_severity_rating: vul_rating,
        offensive_priority: f.offensive_priority.clone().filter(|p| !p.is_empty()),
        offensive_priority_label: f
            .offensive_priority
            .as_deref()
            .filter(|p| !p.is_empty())
            .and_then(appsec_model::offensive_label)
            .map(str::to_string),
        offensive_priority_reason: f
            .offensive_priority
            .as_deref()
            .filter(|p| !p.is_empty())
            .map(|_| f.offensive_reason.clone()),
        confidence: round2(f.confidence),
        votes: f.votes,
        description: truncate_description(&f.description),
        dedup_related_location_count: (related_count > 0).then_some(related_count),
        validation_status: None,
        validation_score: None,
        validation_justification: None,
        merge_readiness: None,
        remediation_status: None,
    };
    if let Some(v) = validation {
        set_validation(&mut props, v);
    }
    props
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Fingerprints {
    pub v2: Option<String>,
    pub v3: Option<String>,
}

pub fn build_result(
    rf: &RankedFinding,
    validation: Option<&ValidationScore>,
    fingerprints: Fingerprints,
) -> SarifResult {
    let f = &rf.finding;
    let rule_id = rule_id_for(f).to_string();
    let eff_cwe = appsec_cwe::cwe_for(f.cwe.as_deref(), Some(f.vuln_class.as_str()));

    let related_locations: Vec<RelatedLocation> =
        f.duplicates.iter().map(related_location).collect();
    let props = properties(rf, eff_cwe.as_deref(), related_locations.len(), validation);

    let mut taxon_ids: Vec<String> = eff_cwe.iter().cloned().collect();
    for cwe in &f.related_cwes {
        if let Some(cwe) = appsec_cwe::cwe_for(Some(cwe), None) {
            if !taxon_ids.contains(&cwe) {
                taxon_ids.push(cwe);
            }
        }
    }
    let taxa = (!taxon_ids.is_empty()).then(|| {
        taxon_ids
            .into_iter()
            .map(|cwe| TaxonRef {
                tool_component: ToolComponentRef {
                    name: "CWE".to_string(),
                    guid: CWE_TAXONOMY_GUID.to_string(),
                },
                id: cwe,
            })
            .collect()
    });

    let mut partial_fingerprints = std::collections::BTreeMap::new();
    partial_fingerprints.insert(
        FINGERPRINT_KEY.to_string(),
        finding_fingerprint(&rule_id, &f.file, &f.code_snippet),
    );
    if let Some(v2) = fingerprints.v2 {
        partial_fingerprints.insert(FINGERPRINT_KEY_V2.to_string(), v2);
    }
    if let Some(v3) = fingerprints.v3 {
        partial_fingerprints.insert(FINGERPRINT_KEY_V3.to_string(), v3);
    }

    SarifResult {
        rule_id,
        level: sarif_level(rf.severity).to_string(),
        message: message(f),
        locations: vec![primary_location(f)],
        related_locations,
        rank: rank(f.cvss_score),
        taxa,
        partial_fingerprints,
        baseline_state: None,
        properties: props,
    }
}

pub fn build_absent_result(rf: &RankedFinding, fingerprints: Fingerprints) -> SarifResult {
    build_result(rf, None, fingerprints).with_baseline_state("absent")
}

#[cfg(test)]
mod tests {
    use super::*;
    use appsec_model::{Severity, VulnClass};

    fn finding(overrides: impl FnOnce(&mut Finding)) -> Finding {
        let mut f = Finding {
            provider_origins: Vec::new(),
            component: None,
            chunk_id: "c1".to_string(),
            file: "a.py".to_string(),
            line_start: 1,
            line_end: 1,
            vuln_class: VulnClass::Other,
            cwe: None,
            title: "Some finding".to_string(),
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
        };
        overrides(&mut f);
        f
    }

    fn ranked(f: Finding) -> RankedFinding {
        RankedFinding {
            finding: f,
            severity: Severity::High,
            exploitability_notes: String::new(),
        }
    }

    #[test]
    fn message_no_vector_is_bare_title() {
        let f = finding(|_| {});
        assert_eq!(message(&f).text, "Some finding");
    }

    #[test]
    fn message_vector_and_score_includes_both() {
        let f = finding(|f| {
            f.cvss_vector = Some("CVSS:3.1/AV:N".to_string());
            f.cvss_score = Some(9.8);
        });
        assert_eq!(message(&f).text, "Some finding  [CVSS 9.8: CVSS:3.1/AV:N]");
    }

    #[test]
    fn message_vector_without_score_omits_the_number() {
        let f = finding(|f| f.cvss_vector = Some("CVSS:3.1/AV:N".to_string()));
        assert_eq!(message(&f).text, "Some finding  [CVSS: CVSS:3.1/AV:N]");
    }

    #[test]
    fn message_empty_vector_string_is_treated_as_absent() {
        let f = finding(|f| f.cvss_vector = Some(String::new()));
        assert_eq!(message(&f).text, "Some finding");
    }

    #[test]
    fn taxa_carry_the_primary_cwe_then_every_merged_lens() {
        let f = finding(|f| {
            f.cwe = Some("CWE-200".to_string());
            f.related_cwes = vec![
                "CWE-345".to_string(),
                "CWE-284".to_string(),
                "CWE-345".to_string(),
            ];
        });
        let taxa = build_result(&ranked(f), None, Fingerprints::default())
            .taxa
            .unwrap();
        let ids: Vec<&str> = taxa.iter().map(|t| t.id.as_str()).collect();
        assert_eq!(ids, vec!["CWE-200", "CWE-345", "CWE-284"]);
        assert!(taxa.iter().all(|t| t.tool_component.name == "CWE"));
    }

    #[test]
    fn a_blank_merged_lens_contributes_no_taxon() {
        let f = finding(|f| {
            f.cwe = Some("CWE-200".to_string());
            f.related_cwes = vec![String::new(), "   ".to_string()];
        });
        let taxa = build_result(&ranked(f), None, Fingerprints::default())
            .taxa
            .unwrap();
        assert_eq!(taxa.len(), 1);
        assert_eq!(taxa[0].id, "CWE-200");
    }

    #[test]
    fn a_merged_lens_alone_is_enough_to_produce_taxa() {
        let f = finding(|f| f.related_cwes = vec!["CWE-284".to_string()]);
        let taxa = build_result(&ranked(f), None, Fingerprints::default())
            .taxa
            .unwrap();
        let ids: Vec<&str> = taxa.iter().map(|t| t.id.as_str()).collect();
        assert_eq!(ids, vec!["CWE-284"]);
    }

    #[test]
    fn no_cwe_and_no_merged_lens_omits_taxa_entirely() {
        let f = finding(|_| {});
        assert!(build_result(&ranked(f), None, Fingerprints::default())
            .taxa
            .is_none());
    }

    #[test]
    fn truncate_description_under_limit_is_unchanged() {
        assert_eq!(truncate_description("short"), "short");
    }

    #[test]
    fn truncate_description_over_limit_is_cut_with_ellipsis() {
        let long = "a".repeat(4001);
        let truncated = truncate_description(&long);
        assert_eq!(truncated.chars().count(), 4001);
        assert!(truncated.ends_with('…'));
        assert_eq!(truncated.chars().filter(|&c| c == 'a').count(), 4000);
    }

    #[test]
    fn truncate_description_at_exactly_4000_is_unchanged() {
        let exact = "a".repeat(4000);
        assert_eq!(truncate_description(&exact), exact);
    }

    #[test]
    fn properties_vsvs_score_present_populates_vul_context_fields() {
        let f = finding(|f| {
            f.vsvs_score = Some(7.5);
            f.vsvs_vector = Some("CR:H".to_string());
            f.vsvs_rating = Some("High".to_string());
        });
        let props = properties(&ranked(f), None, 0, None);
        assert_eq!(props.vul_context_severity_score, Some(7.5));
        assert_eq!(props.vul_context_severity_vector.as_deref(), Some("CR:H"));
        assert_eq!(props.vul_context_severity_rating.as_deref(), Some("High"));
    }

    #[test]
    fn properties_vsvs_score_absent_leaves_vul_context_fields_none() {
        let f = finding(|_| {});
        let props = properties(&ranked(f), None, 0, None);
        assert!(props.vul_context_severity_score.is_none());
        assert!(props.vul_context_severity_vector.is_none());
        assert!(props.vul_context_severity_rating.is_none());
    }

    #[test]
    fn properties_negative_vsvs_score_is_treated_as_unknown() {
        let f = finding(|f| f.vsvs_score = Some(-1.0));
        let props = properties(&ranked(f), None, 0, None);
        assert!(props.vul_context_severity_score.is_none());
    }

    #[test]
    fn properties_offensive_priority_known_tier_populates_label_and_reason() {
        let f = finding(|f| {
            f.offensive_priority = Some("P1".to_string());
            f.offensive_reason = "internet-facing".to_string();
        });
        let props = properties(&ranked(f), None, 0, None);
        assert_eq!(props.offensive_priority.as_deref(), Some("P1"));
        assert_eq!(
            props.offensive_priority_label.as_deref(),
            Some("Externally Exploitable, No Auth")
        );
        assert_eq!(
            props.offensive_priority_reason.as_deref(),
            Some("internet-facing")
        );
    }

    #[test]
    fn properties_offensive_priority_unknown_tier_has_no_label() {
        let f = finding(|f| f.offensive_priority = Some("P9".to_string()));
        let props = properties(&ranked(f), None, 0, None);
        assert!(props.offensive_priority_label.is_none());
    }

    #[test]
    fn properties_empty_offensive_priority_is_treated_as_absent() {
        let f = finding(|f| f.offensive_priority = Some(String::new()));
        let props = properties(&ranked(f), None, 0, None);
        assert!(props.offensive_priority.is_none());
        assert!(props.offensive_priority_label.is_none());
        assert!(props.offensive_priority_reason.is_none());
    }

    #[test]
    fn properties_dedup_count_zero_is_none() {
        let f = finding(|_| {});
        let props = properties(&ranked(f), None, 0, None);
        assert!(props.dedup_related_location_count.is_none());
    }

    fn validation_score(fix_status: appsec_validation_scoring::FixVerdict) -> ValidationScore {
        ValidationScore {
            raw_score: 0.9,
            fix_status,
            justification: "fix verified".to_string(),
            gate_results: Vec::new(),
            has_critical_failure: false,
        }
    }

    #[test]
    fn properties_no_validation_leaves_every_validation_field_none() {
        let f = finding(|_| {});
        let props = properties(&ranked(f), None, 0, None);
        assert!(props.validation_status.is_none());
        assert!(props.validation_score.is_none());
        assert!(props.validation_justification.is_none());
        assert!(props.merge_readiness.is_none());
    }

    #[test]
    fn properties_populates_every_validation_field_when_present() {
        let f = finding(|_| {});
        let score = validation_score(appsec_validation_scoring::FixVerdict::Fixed);
        let props = properties(&ranked(f), None, 0, Some(&score));
        assert_eq!(props.validation_status.as_deref(), Some("Fixed"));
        assert_eq!(props.validation_score, Some(0.9));
        assert_eq!(
            props.validation_justification.as_deref(),
            Some("fix verified")
        );
        assert_eq!(props.merge_readiness.as_deref(), Some("Ready"));
    }

    #[test]
    fn an_unverifiable_score_is_omitted_rather_than_written_as_zero() {
        let f = finding(|_| {});
        let score = validation_score(appsec_validation_scoring::FixVerdict::Unverifiable);
        let props = properties(&ranked(f), None, 0, Some(&score));
        assert_eq!(props.validation_status.as_deref(), Some("UNVERIFIABLE"));
        assert_eq!(props.validation_score, None);
        let json = serde_json::to_value(&props).unwrap();
        assert!(json.get("validationScore").is_none(), "{json}");
    }

    #[test]
    fn build_absent_result_is_a_normal_result_tagged_absent() {
        let rf = ranked(finding(|f| f.cvss_score = Some(9.8)));
        let mut expected = build_result(
            &rf,
            None,
            Fingerprints {
                v2: Some("v2".to_string()),
                v3: None,
            },
        );
        expected.baseline_state = Some("absent".to_string());
        let absent = build_absent_result(
            &rf,
            Fingerprints {
                v2: Some("v2".to_string()),
                v3: None,
            },
        );
        assert_eq!(absent, expected);
        assert_eq!(absent.level, "error");
        assert_eq!(absent.rank, Some(98.0));
        assert_eq!(absent.properties.security_severity, "9.8");
        assert_eq!(
            absent.partial_fingerprints.get(FINGERPRINT_KEY_V2),
            Some(&"v2".to_string())
        );
    }

    #[test]
    fn build_absent_result_omits_the_v2_fingerprint_when_none_is_known() {
        let absent = build_absent_result(&ranked(finding(|_| {})), Fingerprints::default());
        assert!(!absent.partial_fingerprints.contains_key(FINGERPRINT_KEY_V2));
        assert!(absent.partial_fingerprints.contains_key(FINGERPRINT_KEY));
        assert!(absent.properties.validation_status.is_none());
    }

    #[test]
    fn apply_validation_matches_building_the_result_with_the_score_in_hand() {
        let score = validation_score(appsec_validation_scoring::FixVerdict::PartiallyFixed);
        let built = build_result(
            &ranked(finding(|_| {})),
            Some(&score),
            Fingerprints::default(),
        );
        let mut stamped = build_result(&ranked(finding(|_| {})), None, Fingerprints::default());
        apply_validation(&mut stamped, &score);
        assert_eq!(stamped, built);
    }

    #[test]
    fn apply_validation_overwrites_an_earlier_score_rather_than_appending() {
        let mut result = build_result(
            &ranked(finding(|_| {})),
            Some(&validation_score(
                appsec_validation_scoring::FixVerdict::Fixed,
            )),
            Fingerprints::default(),
        );
        apply_validation(
            &mut result,
            &validation_score(appsec_validation_scoring::FixVerdict::NotFixed),
        );
        assert_eq!(
            result.properties.validation_status.as_deref(),
            Some("Not Fixed")
        );
        assert_eq!(
            result.properties.merge_readiness.as_deref(),
            Some("Not Ready")
        );
    }

    #[test]
    fn properties_merge_readiness_reflects_a_not_ready_verdict() {
        let f = finding(|_| {});
        let score = validation_score(appsec_validation_scoring::FixVerdict::NotFixed);
        let props = properties(&ranked(f), None, 0, Some(&score));
        assert_eq!(props.validation_status.as_deref(), Some("Not Fixed"));
        assert_eq!(props.merge_readiness.as_deref(), Some("Not Ready"));
    }

    #[test]
    fn region_for_omits_end_line_when_zero_or_equal_to_start() {
        assert_eq!(region_for(5, 0).end_line, None);
        assert_eq!(region_for(5, 5).end_line, None);
        assert_eq!(region_for(5, 8).end_line, Some(8));
    }

    #[test]
    fn primary_location_empty_file_is_unknown() {
        let f = finding(|f| f.file = String::new());
        assert_eq!(
            primary_location(&f).physical_location.artifact_location.uri,
            "unknown"
        );
    }

    #[test]
    fn related_location_uses_the_fixed_dedup_message() {
        let d = appsec_model::DupLocation {
            file: "b.py".to_string(),
            line_start: 1,
            line_end: 1,
            vuln_class: VulnClass::Other,
            title: String::new(),
            chunk_id: String::new(),
            source_ref: None,
            sink_ref: None,
            reasoning: String::new(),
        };
        assert_eq!(related_location(&d).message.text, DUP_LOCATION_MESSAGE);
    }
}
