use super::*;

fn gate(name: GateName, status: GateStatus, summary: &str) -> GateResult {
    GateResult {
        gate_name: name,
        status,
        summary: summary.to_string(),
        evidence: Vec::new(),
        details: String::new(),
        confidence: None,
    }
}

fn flagged(mut gate: GateResult) -> GateResult {
    gate.confidence = Some(SynthesisConfidence::Flagged);
    gate
}

fn all_pass() -> Vec<GateResult> {
    vec![
        gate(
            GateName::RootCause,
            GateStatus::Pass,
            "Root cause addressed",
        ),
        gate(
            GateName::InstanceCoverage,
            GateStatus::Pass,
            "All instances covered",
        ),
        gate(
            GateName::NoNewVulnerabilities,
            GateStatus::Pass,
            "No new vulns",
        ),
        gate(
            GateName::SecurityBestPractices,
            GateStatus::Pass,
            "Best practices met",
        ),
    ]
}

fn all_fail() -> Vec<GateResult> {
    vec![
        gate(
            GateName::RootCause,
            GateStatus::Fail,
            "Root cause not fixed",
        ),
        gate(
            GateName::InstanceCoverage,
            GateStatus::Fail,
            "Instances missed",
        ),
        gate(
            GateName::NoNewVulnerabilities,
            GateStatus::Fail,
            "New vulns introduced",
        ),
        gate(
            GateName::SecurityBestPractices,
            GateStatus::Fail,
            "Best practices ignored",
        ),
    ]
}

fn partial_fixture() -> Vec<GateResult> {
    vec![
        gate(
            GateName::RootCause,
            GateStatus::Pass,
            "Root cause addressed",
        ),
        gate(
            GateName::InstanceCoverage,
            GateStatus::Partial,
            "Some instances covered",
        ),
        gate(
            GateName::NoNewVulnerabilities,
            GateStatus::Pass,
            "No new vulns",
        ),
        gate(
            GateName::SecurityBestPractices,
            GateStatus::Fail,
            "Practices missing",
        ),
    ]
}

fn approx_eq(a: f64, b: f64) -> bool {
    (a - b).abs() < 1e-4
}

#[test]
fn gate_name_parse_round_trips_every_canonical_value() {
    for name in GateName::ALL {
        assert_eq!(GateName::parse(name.as_str()), Some(name));
    }
}

#[test]
fn gate_name_parse_rejects_an_unrecognized_string() {
    assert_eq!(GateName::parse("branch_targeting"), None);
    assert_eq!(GateName::parse(""), None);
}

#[test]
fn gate_status_parse_canonical_values() {
    assert_eq!(GateStatus::parse("pass"), GateStatus::Pass);
    assert_eq!(GateStatus::parse("partial"), GateStatus::Partial);
    assert_eq!(GateStatus::parse("fail"), GateStatus::Fail);
    assert_eq!(GateStatus::parse("skip"), GateStatus::Skip);
}

#[test]
fn gate_status_parse_tolerates_case_and_whitespace() {
    assert_eq!(GateStatus::parse("PASS"), GateStatus::Pass);
    assert_eq!(GateStatus::parse(" Pass "), GateStatus::Pass);
}

#[test]
fn gate_status_parse_unknown_token_is_invalid() {
    assert_eq!(GateStatus::parse("verified"), GateStatus::Invalid);
}

#[test]
fn gate_status_as_str_round_trips_through_parse() {
    for status in [
        GateStatus::Pass,
        GateStatus::Partial,
        GateStatus::Fail,
        GateStatus::Skip,
        GateStatus::Invalid,
    ] {
        assert_eq!(GateStatus::parse(status.as_str()), status);
    }
}

#[test]
fn all_pass_is_fixed() {
    let result = score_fix(&all_pass());
    assert_eq!(result.fix_status, FixVerdict::Fixed);
    assert!(approx_eq(result.raw_score, 1.0));
    assert!(!result.has_critical_failure);
}

#[test]
fn all_fail_is_not_fixed() {
    let result = score_fix(&all_fail());
    assert_eq!(result.fix_status, FixVerdict::NotFixed);
    assert_eq!(result.raw_score, 0.0);
}

#[test]
fn partial_gates_produce_a_fractional_score() {
    let result = score_fix(&partial_fixture());
    let expected = 0.43 * 1.0 + 0.2467 * 0.5 + 0.1867 * 1.0 + 0.1366 * 0.0;
    assert!(approx_eq(result.raw_score, expected));
    assert_eq!(result.fix_status, FixVerdict::PartiallyFixed);
}

#[test]
fn missing_criteria_returns_unverifiable() {
    let gates = vec![gate(GateName::RootCause, GateStatus::Pass, "")];
    let result = score_fix(&gates);
    assert_eq!(result.fix_status, FixVerdict::Unverifiable);
    assert_eq!(result.raw_score, 0.0);
    assert!(result.justification.contains("Missing criterion"));
}

#[test]
fn duplicate_criterion_returns_unverifiable() {
    let gates = vec![
        gate(GateName::RootCause, GateStatus::Pass, ""),
        gate(GateName::RootCause, GateStatus::Pass, ""),
        gate(GateName::InstanceCoverage, GateStatus::Pass, ""),
        gate(GateName::NoNewVulnerabilities, GateStatus::Fail, ""),
        gate(GateName::SecurityBestPractices, GateStatus::Pass, ""),
    ];
    let result = score_fix(&gates);
    assert_eq!(result.fix_status, FixVerdict::Unverifiable);
    assert_eq!(result.raw_score, 0.0);
    assert!(result.justification.contains("Duplicate criterion"));
    assert!(result.justification.contains("root_cause"));
}

#[test]
fn skip_on_non_critical_gates_is_weight_neutral() {
    let gates = vec![
        gate(GateName::RootCause, GateStatus::Pass, "ok"),
        gate(GateName::InstanceCoverage, GateStatus::Skip, "n/a"),
        gate(GateName::NoNewVulnerabilities, GateStatus::Pass, "ok"),
        gate(GateName::SecurityBestPractices, GateStatus::Skip, "n/a"),
    ];
    let result = score_fix(&gates);
    assert!(approx_eq(result.raw_score, 1.0));
    assert_eq!(result.fix_status, FixVerdict::Fixed);
}

#[test]
fn root_cause_skip_is_unverifiable_not_silently_fixed() {
    let gates = vec![
        gate(GateName::RootCause, GateStatus::Skip, ""),
        gate(GateName::InstanceCoverage, GateStatus::Pass, "ok"),
        gate(GateName::NoNewVulnerabilities, GateStatus::Pass, "ok"),
        gate(GateName::SecurityBestPractices, GateStatus::Pass, "ok"),
    ];
    let result = score_fix(&gates);
    assert_eq!(result.fix_status, FixVerdict::Unverifiable);
    assert_eq!(result.raw_score, 0.0);
    assert!(result.justification.contains("root_cause"));
}

#[test]
fn all_skip_is_unverifiable_via_the_critical_gate_check() {
    let gates = vec![
        gate(GateName::RootCause, GateStatus::Skip, ""),
        gate(GateName::InstanceCoverage, GateStatus::Skip, ""),
        gate(GateName::NoNewVulnerabilities, GateStatus::Skip, ""),
        gate(GateName::SecurityBestPractices, GateStatus::Skip, ""),
    ];
    let result = score_fix(&gates);
    assert_eq!(result.fix_status, FixVerdict::Unverifiable);
    assert_eq!(result.raw_score, 0.0);
}

#[test]
fn renormalized_score_guards_a_zero_weight_input_directly() {
    let gates = vec![gate(GateName::SecurityBestPractices, GateStatus::Skip, "")];
    let err = renormalized_score(&gates).unwrap_err();
    assert_eq!(err.fix_status, FixVerdict::Unverifiable);
    assert!(err.justification.contains("no gates were evaluated"));
}

#[test]
fn a_weights_misconfiguration_would_be_clamped_to_one() {
    let result = score_fix(&all_pass());
    assert!(result.raw_score <= 1.0);
}

#[test]
fn critical_gate_skip_is_unverifiable() {
    let gates = vec![
        gate(GateName::RootCause, GateStatus::Pass, ""),
        gate(GateName::InstanceCoverage, GateStatus::Pass, ""),
        gate(GateName::NoNewVulnerabilities, GateStatus::Skip, ""),
        gate(GateName::SecurityBestPractices, GateStatus::Pass, ""),
    ];
    let result = score_fix(&gates);
    assert_eq!(result.fix_status, FixVerdict::Unverifiable);
    assert_eq!(result.raw_score, 0.0);
}

#[test]
fn critical_gate_invalid_is_unverifiable() {
    let gates = vec![
        gate(GateName::RootCause, GateStatus::Pass, ""),
        gate(GateName::InstanceCoverage, GateStatus::Pass, ""),
        gate(GateName::NoNewVulnerabilities, GateStatus::Invalid, ""),
        gate(GateName::SecurityBestPractices, GateStatus::Pass, ""),
    ];
    let result = score_fix(&gates);
    assert_eq!(result.fix_status, FixVerdict::Unverifiable);
}

#[test]
fn critical_gate_fail_caps_the_verdict_below_fixed() {
    let gates = vec![
        gate(GateName::RootCause, GateStatus::Pass, ""),
        gate(GateName::InstanceCoverage, GateStatus::Pass, ""),
        gate(GateName::NoNewVulnerabilities, GateStatus::Fail, ""),
        gate(GateName::SecurityBestPractices, GateStatus::Pass, ""),
    ];
    let result = score_fix(&gates);
    assert!(approx_eq(result.raw_score, 0.8133));
    assert_eq!(result.fix_status, FixVerdict::PartiallyFixed);
}

#[test]
fn critical_gate_partial_caps_the_verdict_below_fixed() {
    let gates = vec![
        gate(GateName::RootCause, GateStatus::Pass, ""),
        gate(GateName::InstanceCoverage, GateStatus::Pass, ""),
        gate(GateName::NoNewVulnerabilities, GateStatus::Partial, ""),
        gate(GateName::SecurityBestPractices, GateStatus::Pass, ""),
    ];
    let result = score_fix(&gates);
    assert!(approx_eq(result.raw_score, 0.9066));
    assert_eq!(result.fix_status, FixVerdict::PartiallyFixed);
}

#[test]
fn non_critical_invalid_stays_in_the_denominator() {
    let gates = vec![
        gate(GateName::RootCause, GateStatus::Pass, ""),
        gate(GateName::InstanceCoverage, GateStatus::Pass, ""),
        gate(GateName::NoNewVulnerabilities, GateStatus::Pass, ""),
        gate(GateName::SecurityBestPractices, GateStatus::Invalid, ""),
    ];
    let result = score_fix(&gates);
    assert!(approx_eq(result.raw_score, 0.8634));
    assert_eq!(result.fix_status, FixVerdict::Fixed);
    assert!(!result.has_critical_failure);
}

#[test]
fn score_fix_tolerates_an_unknown_status_without_panicking() {
    let gates = vec![
        gate(GateName::RootCause, GateStatus::parse("totally-bogus"), ""),
        gate(GateName::InstanceCoverage, GateStatus::Pass, ""),
        gate(GateName::NoNewVulnerabilities, GateStatus::Pass, ""),
        gate(GateName::SecurityBestPractices, GateStatus::Pass, ""),
    ];
    let result = score_fix(&gates);
    assert_eq!(result.gate_results.len(), gates.len());
    let root = result
        .gate_results
        .iter()
        .find(|g| g.gate_name == GateName::RootCause)
        .unwrap();
    assert_eq!(root.status, GateStatus::Invalid);
}

#[rstest::rstest]
#[case::fail(GateStatus::Fail, true)]
#[case::partial(GateStatus::Partial, true)]
#[case::pass(GateStatus::Pass, false)]
fn has_critical_failure_tracks_a_not_clean_critical_gate(
    #[case] nnv: GateStatus,
    #[case] expected: bool,
) {
    let gates = vec![
        gate(GateName::RootCause, GateStatus::Pass, ""),
        gate(GateName::InstanceCoverage, GateStatus::Pass, ""),
        gate(GateName::NoNewVulnerabilities, nnv, ""),
        gate(GateName::SecurityBestPractices, GateStatus::Pass, ""),
    ];
    assert_eq!(score_fix(&gates).has_critical_failure, expected);
}

#[test]
fn a_single_flagged_gate_fails_the_whole_score_closed() {
    let mut gates = all_pass();
    gates[0] = flagged(gates[0].clone());
    let result = score_fix(&gates);
    assert_eq!(result.fix_status, FixVerdict::Unverifiable);
    assert_eq!(result.raw_score, 0.0);
    assert_eq!(
        result.justification,
        "UNVERIFIABLE: Insufficient persona consensus for gate(s): root_cause."
    );
    assert_eq!(result.gate_results[0].status, GateStatus::Pass);
}

#[test]
fn several_flagged_gates_are_named_alphabetically_in_one_message() {
    let gates: Vec<GateResult> = all_pass().into_iter().map(flagged).collect();
    let result = score_fix(&gates);
    assert_eq!(
        result.justification,
        "UNVERIFIABLE: Insufficient persona consensus for gate(s): \
         instance_coverage, no_new_vulnerabilities, root_cause, \
         security_best_practices."
    );
}

#[test]
fn high_confidence_gates_score_exactly_as_unlabeled_ones_do() {
    let labeled: Vec<GateResult> = all_pass()
        .into_iter()
        .map(|mut g| {
            g.confidence = Some(SynthesisConfidence::High);
            g
        })
        .collect();
    let result = score_fix(&labeled);
    assert_eq!(result.fix_status, FixVerdict::Fixed);
    assert_eq!(score_fix(&all_pass()).raw_score, result.raw_score);
}

#[test]
fn split_confidence_gates_score_exactly_as_unlabeled_ones_do() {
    let labeled: Vec<GateResult> = all_pass()
        .into_iter()
        .map(|mut g| {
            g.confidence = Some(SynthesisConfidence::Split);
            g
        })
        .collect();
    assert!(consensus_error(&labeled).is_none());
    let result = score_fix(&labeled);
    let unlabeled = score_fix(&all_pass());
    assert_eq!(result.fix_status, unlabeled.fix_status);
    assert_eq!(result.raw_score, unlabeled.raw_score);
    assert_eq!(result.justification, unlabeled.justification);
}

#[test]
fn an_unlabeled_gate_set_never_trips_the_consensus_check() {
    assert!(consensus_error(&all_pass()).is_none());
}

#[test]
fn a_malformed_gate_set_is_reported_as_malformed_before_consensus() {
    let gates = vec![flagged(gate(GateName::RootCause, GateStatus::Pass, ""))];
    let result = score_fix(&gates);
    assert!(result.justification.contains("Missing criterion"));
}

#[test]
fn a_gate_the_whole_panel_skipped_is_reported_as_missing_consensus() {
    let mut gates = all_pass();
    gates[0].status = GateStatus::Skip;
    gates[0] = flagged(gates[0].clone());
    let result = score_fix(&gates);
    assert_eq!(result.fix_status, FixVerdict::Unverifiable);
    assert!(result
        .justification
        .contains("Insufficient persona consensus"));
    assert!(!result.justification.contains("was not evaluated"));
}

#[test]
fn fix_verdict_as_str_matches_the_wire_vocabulary() {
    assert_eq!(FixVerdict::Fixed.as_str(), "Fixed");
    assert_eq!(FixVerdict::PartiallyFixed.as_str(), "Partially Fixed");
    assert_eq!(FixVerdict::NotFixed.as_str(), "Not Fixed");
    assert_eq!(FixVerdict::Unverifiable.as_str(), "UNVERIFIABLE");
}

#[test]
fn synthesis_confidence_as_str_matches_the_wire_vocabulary() {
    assert_eq!(SynthesisConfidence::High.as_str(), "HIGH");
    assert_eq!(SynthesisConfidence::Split.as_str(), "SPLIT");
    assert_eq!(SynthesisConfidence::Flagged.as_str(), "FLAGGED");
}

#[rstest::rstest]
#[case::fixed(FixVerdict::Fixed, MergeReadiness::Ready)]
#[case::partial(FixVerdict::PartiallyFixed, MergeReadiness::ReadyWithConditions)]
#[case::not_fixed(FixVerdict::NotFixed, MergeReadiness::NotReady)]
#[case::unverifiable(FixVerdict::Unverifiable, MergeReadiness::NotReady)]
fn derive_merge_readiness_maps_every_verdict(
    #[case] verdict: FixVerdict,
    #[case] expected: MergeReadiness,
) {
    assert_eq!(derive_merge_readiness(verdict), expected);
}

#[test]
fn merge_readiness_as_str_matches_the_wire_vocabulary() {
    assert_eq!(MergeReadiness::Ready.as_str(), "Ready");
    assert_eq!(
        MergeReadiness::ReadyWithConditions.as_str(),
        "Ready with Conditions"
    );
    assert_eq!(MergeReadiness::NotReady.as_str(), "Not Ready");
}

#[test]
fn fixed_justification_contains_confidence_and_evidence() {
    let mut gates = all_pass();
    gates[0].evidence.push(Evidence {
        file: "a.py".to_string(),
        line: Some(5),
        snippet: String::new(),
    });
    let result = score_fix(&gates);
    assert!(result.justification.contains("Fix verified:"));
    assert!(result.justification.contains("100%"));
    assert!(result.justification.contains("Evidence:"));
    assert!(result.justification.contains("a.py:5"));
}

#[test]
fn partially_fixed_justification_contains_gaps_and_files() {
    let mut gates = partial_fixture();
    gates[3].evidence.push(Evidence {
        file: "b.py".to_string(),
        line: None,
        snippet: String::new(),
    });
    let result = score_fix(&gates);
    assert!(result.justification.contains("Partial fix:"));
    assert!(result.justification.contains("Gaps:"));
    assert!(result.justification.contains("Files needing fixes: b.py"));
}

#[test]
fn partially_fixed_justification_reports_n_a_when_no_files_have_evidence() {
    let result = score_fix(&partial_fixture());
    assert!(result.justification.contains("Files needing fixes: N/A"));
}

#[test]
fn not_fixed_justification_contains_recommended_actions() {
    let result = score_fix(&all_fail());
    assert!(result.justification.contains("Fix insufficient:"));
    assert!(result.justification.contains("Recommended action:"));
    assert!(result.justification.contains("affected files"));
}

#[test]
fn not_fixed_justification_falls_back_when_no_gate_is_a_clean_fail() {
    let gates = vec![
        gate(GateName::RootCause, GateStatus::Partial, ""),
        gate(GateName::InstanceCoverage, GateStatus::Invalid, ""),
        gate(GateName::NoNewVulnerabilities, GateStatus::Pass, "ok"),
        gate(GateName::SecurityBestPractices, GateStatus::Invalid, ""),
    ];
    let result = score_fix(&gates);
    assert_eq!(result.fix_status, FixVerdict::NotFixed);
    assert!(result
        .justification
        .contains("Review all failing gates and apply fixes"));
}

#[test]
fn not_fixed_justification_names_affected_files_when_evidence_exists() {
    let mut gates = all_fail();
    gates[0].evidence.push(Evidence {
        file: "c.py".to_string(),
        line: None,
        snippet: String::new(),
    });
    let result = score_fix(&gates);
    assert!(result.justification.contains("remains in c.py"));
}

#[test]
fn evidence_anchors_are_capped_at_five() {
    let mut gates = all_pass();
    for i in 0..7 {
        gates[0].evidence.push(Evidence {
            file: format!("f{i}.py"),
            line: None,
            snippet: String::new(),
        });
    }
    let result = score_fix(&gates);
    assert!(result.justification.contains("f4.py"));
    assert!(!result.justification.contains("f5.py"));
    assert!(!result.justification.contains("f6.py"));
}

#[test]
fn fix_verdict_and_synthesis_confidence_parse_their_own_wire_labels() {
    for v in [
        FixVerdict::Fixed,
        FixVerdict::PartiallyFixed,
        FixVerdict::NotFixed,
        FixVerdict::Unverifiable,
    ] {
        assert_eq!(FixVerdict::parse(v.as_str()), Some(v));
    }
    assert_eq!(FixVerdict::parse("fixed"), None);
    for c in [
        SynthesisConfidence::High,
        SynthesisConfidence::Split,
        SynthesisConfidence::Flagged,
    ] {
        assert_eq!(SynthesisConfidence::parse(c.as_str()), Some(c));
    }
    assert_eq!(SynthesisConfidence::parse("high"), None);
}

#[test]
fn a_huge_files_needing_fixes_list_is_capped_with_a_marker() {
    let mut gates = all_fail();
    gates[0].evidence = (0..2000)
        .map(|i| Evidence {
            file: format!("src/module_{i:04}.py"),
            line: None,
            snippet: String::new(),
        })
        .collect();
    let result = score_fix(&gates);
    assert!(result.justification.contains(TRUNCATION_MARKER));
    assert!(result.justification.len() < MAX_FILES_NEEDING_FIXES_CHARS + 1000);
    assert_eq!(joined_files(&["a".to_string(), "b".to_string()]), "a, b");
}
