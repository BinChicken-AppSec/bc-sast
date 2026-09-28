//! Builds one `SarifResult` per `RankedFinding`, ported from the
//! per-finding loop in `enrich.py::generate_sarif` (lines 892-971) —
//! adapted to read straight off typed `bc-model` data instead of a
//! regex-reparsed Markdown `Finding`.
//!
//! One deliberate divergence throughout: where the Python source always
//! sets an optional property key (even to JSON `null`) because it's
//! building a plain dict, this builder omits the key entirely when the
//! value is unknown — an absent key and an explicit `null` mean the same
//! thing to any real SARIF consumer, and omission matches this crate's
//! typed `Option<T>` fields more naturally than emitting `null`.

use bc_model::{DupLocation, Finding, RankedFinding};
use bc_validation_scoring::ValidationScore;

use crate::fingerprint::{finding_fingerprint, FINGERPRINT_KEY, FINGERPRINT_KEY_V2};
use crate::severity::{cvss_rating, rank, round1, round2, sarif_level, security_severity};
use crate::types::{
    ArtifactLocation, Location, MessageText, PhysicalLocation, Region, RelatedLocation,
    ResultProperties, SarifResult, TaxonRef, ToolComponentRef,
};
use crate::CWE_TAXONOMY_GUID;

const DUP_LOCATION_MESSAGE: &str = "Additional call site — collapsed during dedup; same root \
                                     cause as the primary location and needs the same fix.";

/// The distinct-rule dedup key: one SARIF rule per `VulnClass`, matching
/// the Python source's `f.category or f.severity.lower()` fallback (this
/// port's typed `vuln_class` is always populated, so no fallback needed).
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

/// Truncate by Unicode scalar count (not bytes, matching Python's
/// codepoint-based string slicing) to 4000 chars + a trailing ellipsis.
fn truncate_description(description: &str) -> String {
    if description.chars().count() > 4000 {
        let mut truncated: String = description.chars().take(4000).collect();
        truncated.push('…');
        truncated
    } else {
        description.to_string()
    }
}

/// The four S11-derived property keys, written onto an EXISTING
/// properties bag rather than built into a fresh one.
///
/// Shared by [`properties`] (which has the score in hand at build time)
/// and by [`apply_validation`], which stamps a score onto a result read
/// back off a PRIOR run's `report.sarif` — see `bc-cli`'s
/// `--remediate-from`, where rebuilding the document from scratch would
/// discard everything the earlier scan knew (its app profile, its
/// invocation notifications, its metrics) and this run does not.
fn set_validation(props: &mut ResultProperties, v: &ValidationScore) {
    props.validation_status = Some(v.fix_status.as_str().to_string());
    // `None` (so `validationScore` is omitted) for an inconclusive panel:
    // `UNVERIFIABLE` carries no score, and the `0.0` it used to write read
    // as "scored zero" to any consumer that did not also check the status.
    props.validation_score = v.score();
    props.validation_justification = Some(v.justification.clone());
    props.merge_readiness = Some(
        bc_validation_scoring::derive_merge_readiness(v.fix_status)
            .as_str()
            .to_string(),
    );
}

/// Folds one finding's S11 validation score into an already-built
/// result, in place — exactly the keys [`build_result`] would have set
/// had the score been known when the result was first built, so a
/// document augmented this way is indistinguishable from one built with
/// the score in hand.
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
        let n = bc_cwe::cwe_name(eff_cwe);
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
        cwe: eff_cwe.map(|c| bc_cwe::cwe_label(Some(c))),
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
            .and_then(bc_model::offensive_label)
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
        // Set below, through the same `set_validation` the in-place
        // augmentation path uses, so the two can never drift apart.
        validation_status: None,
        validation_score: None,
        validation_justification: None,
        merge_readiness: None,
        // Filled in afterwards by the CLI's post-remediation augmentation
        // pass — this builder is given a validation score but never a
        // remediation record (S10's outcomes aren't part of the
        // `FinalReport` a SARIF document is built from).
        remediation_status: None,
    };
    if let Some(v) = validation {
        set_validation(&mut props, v);
    }
    props
}

/// `validation`, when `Some`, is this finding's own S11 panel score (keyed
/// by [`crate::finding_id`] by the caller — see
/// [`crate::build_sarif_with_validations`]) — `None` both when validation
/// never ran at all and when it ran but this particular finding has no
/// score (e.g. its remediation made no actual change on disk).
///
/// `fingerprint_v2`, when `Some`, is emitted ALONGSIDE the v1
/// fingerprint rather than instead of it: `partialFingerprints` is a bag
/// of alternative identities and a consumer matches on whichever key it
/// knows, so publishing both keeps Code Scanning alerts already posted
/// under v1 matched while new ones gain v2's stability. `None` (the repo
/// wasn't available to read, see [`crate::finding_id_v2`]) simply omits
/// the key.
pub fn build_result(
    rf: &RankedFinding,
    validation: Option<&ValidationScore>,
    fingerprint_v2: Option<String>,
) -> SarifResult {
    let f = &rf.finding;
    let rule_id = rule_id_for(f).to_string();
    let eff_cwe = bc_cwe::cwe_for(f.cwe.as_deref(), Some(f.vuln_class.as_str()));

    let related_locations: Vec<RelatedLocation> =
        f.duplicates.iter().map(related_location).collect();
    let props = properties(rf, eff_cwe.as_deref(), related_locations.len(), validation);

    // The primary CWE first, then every other lens S7 merged into this
    // finding (`Finding::related_cwes`) — `taxa` is a list precisely so
    // one result can carry several classifications, and dropping the
    // merged-away ones would make the SARIF claim less than the Markdown
    // report does. Order is primary-then-first-seen, and a lens equal to
    // the primary or already listed is skipped.
    let mut taxon_ids: Vec<String> = eff_cwe.iter().cloned().collect();
    for cwe in &f.related_cwes {
        if let Some(cwe) = bc_cwe::cwe_for(Some(cwe), None) {
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
    if let Some(v2) = fingerprint_v2 {
        partial_fingerprints.insert(FINGERPRINT_KEY_V2.to_string(), v2);
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

/// The SARIF `absent` result for a finding a PRIOR run reported and this
/// one no longer does — a resolved alert, which is what lets a Code
/// Scanning consumer actually close it rather than leave it open forever.
///
/// Built through [`build_result`] rather than hand-rolled, so a resolved
/// finding's `level`, `rank`, `security-severity`, CWE taxa and
/// fingerprints are computed by exactly the same code as a live one's —
/// the alternative, synthesizing a partial result, would report a
/// fabricated severity for an alert someone is about to close on the
/// strength of it.
///
/// `validation` is deliberately not a parameter: an S11 score grades a
/// fix made during THIS run, and this run has no such finding to fix.
///
/// `fingerprint_v2` follows [`build_result`]'s own contract — `None`
/// simply omits the key. A caller reconstructing an absent result from a
/// findings export passes whatever v2 it could compute against the
/// current tree (see `bc-cli`'s baseline loader); one re-emitting a prior
/// SARIF document's own result should clone that result instead of
/// calling this, since it already carries the fingerprints the earlier
/// run actually computed.
pub fn build_absent_result(rf: &RankedFinding, fingerprint_v2: Option<String>) -> SarifResult {
    build_result(rf, None, fingerprint_v2).with_baseline_state("absent")
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_model::{Severity, VulnClass};

    fn finding(overrides: impl FnOnce(&mut Finding)) -> Finding {
        let mut f = Finding {
            provider_origins: Vec::new(),
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
        // The 2026-09-06 Juice Shop field case after S7's same-range
        // merge: one result, four classifications.
        let f = finding(|f| {
            f.cwe = Some("CWE-200".to_string());
            f.related_cwes = vec![
                "CWE-345".to_string(),
                "CWE-284".to_string(),
                // A repeat is not listed twice.
                "CWE-345".to_string(),
            ];
        });
        let taxa = build_result(&ranked(f), None, None).taxa.unwrap();
        let ids: Vec<&str> = taxa.iter().map(|t| t.id.as_str()).collect();
        assert_eq!(ids, vec!["CWE-200", "CWE-345", "CWE-284"]);
        assert!(taxa.iter().all(|t| t.tool_component.name == "CWE"));
    }

    #[test]
    fn a_blank_merged_lens_contributes_no_taxon() {
        // S7 only ever writes canonical `CWE-<n>` tokens, but a
        // `FinalReport` read back off disk carries whatever was in the
        // JSON, and a blank id would be an invalid taxon reference.
        let f = finding(|f| {
            f.cwe = Some("CWE-200".to_string());
            f.related_cwes = vec![String::new(), "   ".to_string()];
        });
        let taxa = build_result(&ranked(f), None, None).taxa.unwrap();
        assert_eq!(taxa.len(), 1);
        assert_eq!(taxa[0].id, "CWE-200");
    }

    #[test]
    fn a_merged_lens_alone_is_enough_to_produce_taxa() {
        // `vuln_class: Other` resolves to no fallback CWE, so without the
        // merged lens there would be no `taxa` at all.
        let f = finding(|f| f.related_cwes = vec!["CWE-284".to_string()]);
        let taxa = build_result(&ranked(f), None, None).taxa.unwrap();
        let ids: Vec<&str> = taxa.iter().map(|t| t.id.as_str()).collect();
        assert_eq!(ids, vec!["CWE-284"]);
    }

    #[test]
    fn no_cwe_and_no_merged_lens_omits_taxa_entirely() {
        let f = finding(|_| {});
        assert!(build_result(&ranked(f), None, None).taxa.is_none());
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

    fn validation_score(fix_status: bc_validation_scoring::FixVerdict) -> ValidationScore {
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
        let score = validation_score(bc_validation_scoring::FixVerdict::Fixed);
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
        let score = validation_score(bc_validation_scoring::FixVerdict::Unverifiable);
        let props = properties(&ranked(f), None, 0, Some(&score));
        assert_eq!(props.validation_status.as_deref(), Some("UNVERIFIABLE"));
        assert_eq!(props.validation_score, None);
        let json = serde_json::to_value(&props).unwrap();
        assert!(json.get("validationScore").is_none(), "{json}");
    }

    #[test]
    fn build_absent_result_is_a_normal_result_tagged_absent() {
        let rf = ranked(finding(|f| f.cvss_score = Some(9.8)));
        let mut expected = build_result(&rf, None, Some("v2".to_string()));
        expected.baseline_state = Some("absent".to_string());
        let absent = build_absent_result(&rf, Some("v2".to_string()));
        assert_eq!(absent, expected);
        // The severity-derived fields a hand-rolled result would have to
        // fabricate are all really computed.
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
        let absent = build_absent_result(&ranked(finding(|_| {})), None);
        assert!(!absent.partial_fingerprints.contains_key(FINGERPRINT_KEY_V2));
        assert!(absent.partial_fingerprints.contains_key(FINGERPRINT_KEY));
        assert!(absent.properties.validation_status.is_none());
    }

    /// `apply_validation` on an already-built result must produce
    /// exactly what `build_result` would have produced had the score
    /// been available up front — that equivalence is the whole point of
    /// the in-place path (`--remediate-from`).
    #[test]
    fn apply_validation_matches_building_the_result_with_the_score_in_hand() {
        let score = validation_score(bc_validation_scoring::FixVerdict::PartiallyFixed);
        let built = build_result(&ranked(finding(|_| {})), Some(&score), None);
        let mut stamped = build_result(&ranked(finding(|_| {})), None, None);
        apply_validation(&mut stamped, &score);
        assert_eq!(stamped, built);
    }

    #[test]
    fn apply_validation_overwrites_an_earlier_score_rather_than_appending() {
        let mut result = build_result(
            &ranked(finding(|_| {})),
            Some(&validation_score(bc_validation_scoring::FixVerdict::Fixed)),
            None,
        );
        apply_validation(
            &mut result,
            &validation_score(bc_validation_scoring::FixVerdict::NotFixed),
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
        let score = validation_score(bc_validation_scoring::FixVerdict::NotFixed);
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
        let d = bc_model::DupLocation {
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
