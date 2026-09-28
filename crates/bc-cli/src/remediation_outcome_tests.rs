//! Tests for the remediation outcome surface: `RemediationSummary`'s
//! counts, rollup and exit code, the `--out-remediation-json` additions
//! (`decision`, a null score for an inconclusive panel, `totals`,
//! `rollup`), and the `--validate`/`--no-validate` override. Kept in their
//! own file rather than the crate's main test module so the outcome logic
//! and its tests can be read together.

use super::*;
use bc_validation_scoring::FixVerdict;

fn record(verdict: bc_stage_s10::Verdict, diff: Option<&str>) -> bc_stage_s10::RemediationOutcome {
    let mut v = bc_stage_s10::RemediationVerdict::denied(1, "x");
    v.verdict = verdict;
    bc_stage_s10::RemediationOutcome::Processed(Box::new(bc_stage_s10::RemediationRecord {
        finding_index: 1,
        finding_id: "fid".to_string(),
        verdict: v,
        policy_action: None,
        policy_reason: None,
        final_verdict: None,
        policy_reverted: Vec::new(),
        policy_matched_globs: Vec::new(),
        diff: diff.map(str::to_string),
    }))
}

fn reverted(mut outcome: bc_stage_s10::RemediationOutcome) -> bc_stage_s10::RemediationOutcome {
    if let bc_stage_s10::RemediationOutcome::Processed(r) = &mut outcome {
        bc_stage_s10::note_record_reverted(r, "test", false);
    }
    outcome
}

fn failed() -> bc_stage_s10::RemediationOutcome {
    bc_stage_s10::RemediationOutcome::Failed {
        finding_index: 9,
        error: "boom".to_string(),
    }
}

fn score(fix_status: FixVerdict, raw_score: f64) -> bc_validation_scoring::ValidationScore {
    bc_validation_scoring::ValidationScore {
        raw_score,
        fix_status,
        justification: String::new(),
        gate_results: Vec::new(),
        has_critical_failure: false,
    }
}

fn outcome(
    outcomes: Vec<bc_stage_s10::RemediationOutcome>,
    validations: Vec<Option<bc_validation_scoring::ValidationScore>>,
    validation_failures: usize,
) -> bc_orchestrator::RemediateOutcome {
    bc_orchestrator::RemediateOutcome {
        refused: None,
        outcomes,
        validations,
        validation_failures,
    }
}

const DIFF: &str = "--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n";

#[test]
fn fixed_counts_only_a_kept_fixed_diff() {
    let summary = RemediationSummary::from(&outcome(
        vec![
            record(bc_stage_s10::Verdict::Fixed, Some(DIFF)),
            record(bc_stage_s10::Verdict::Fixed, None),
            reverted(record(bc_stage_s10::Verdict::Fixed, Some(DIFF))),
            record(bc_stage_s10::Verdict::NotFixed, None),
            failed(),
        ],
        Vec::new(),
        0,
    ));
    assert_eq!(
        (
            summary.processed,
            summary.fixed,
            summary.not_fixed,
            summary.failed
        ),
        (4, 1, 3, 1)
    );
}

#[test]
fn the_rollup_uses_the_decision_when_validated_else_what_is_on_disk() {
    let summary = RemediationSummary::from(&outcome(
        vec![
            record(bc_stage_s10::Verdict::Fixed, Some(DIFF)),
            record(bc_stage_s10::Verdict::Fixed, Some(DIFF)),
            record(bc_stage_s10::Verdict::PartiallyFixed, Some(DIFF)),
            record(bc_stage_s10::Verdict::Denied, None),
            reverted(record(bc_stage_s10::Verdict::Fixed, Some(DIFF))),
            failed(),
        ],
        vec![
            Some(score(FixVerdict::Fixed, 0.9)),
            Some(score(FixVerdict::Unverifiable, 0.0)),
            None,
            None,
            None,
            None,
        ],
        0,
    ));
    let rollup = &summary.rollup;
    assert_eq!(rollup.cases, 5);
    assert_eq!(
        rollup.states,
        std::collections::BTreeMap::from([
            ("declined", 2),
            ("open", 1),
            ("remediated", 1),
            ("validated", 1)
        ])
    );
    assert_eq!(
        rollup.decisions,
        std::collections::BTreeMap::from([("fixed", 1), ("inconclusive", 1)])
    );
}

#[test]
fn the_exit_code_follows_python_precedence() {
    let tally = |fixed, partially_fixed, not_fixed, unverifiable| ValidationTally {
        fixed,
        partially_fixed,
        not_fixed,
        unverifiable,
    };
    let base = RemediationSummary::default();
    assert_eq!(base.exit_code(), 0);
    // A failed S10 call or an errored validation is `1`, whatever else.
    let s10_failed = RemediationSummary {
        failed: 1,
        validated: Some(tally(0, 0, 1, 0)),
        ..base.clone()
    };
    assert_eq!(s10_failed.exit_code(), 1);
    let s11_errored = RemediationSummary {
        validation_failures: 1,
        ..base.clone()
    };
    assert_eq!(s11_errored.exit_code(), 1);
    // Nothing validated and something failed: 3.
    for failing in [tally(0, 0, 1, 0), tally(0, 1, 0, 2)] {
        let s = RemediationSummary {
            validated: Some(failing),
            ..base.clone()
        };
        assert_eq!(s.exit_code(), EXIT_NOT_REMEDIATED);
    }
    // One validated fix clears it; all-inconclusive never trips it.
    for passing in [tally(1, 0, 3, 0), tally(0, 0, 0, 2), tally(0, 0, 0, 0)] {
        let s = RemediationSummary {
            validated: Some(passing),
            ..base.clone()
        };
        assert_eq!(s.exit_code(), 0);
    }
}

#[test]
fn the_summary_line_names_outcomes_and_a_not_remediated_run() {
    let summary = RemediationSummary::from(&outcome(
        vec![record(bc_stage_s10::Verdict::Fixed, Some(DIFF))],
        vec![Some(score(FixVerdict::NotFixed, 0.2))],
        0,
    ));
    let s = ScanSummary {
        provider_publication: None,
        gc: None,
        cost: None,
        findings: 1,
        markdown_path: None,
        sarif_path: None,
        csv_path: None,
        findings_json_path: None,
        stopped_after: None,
        github_sync: None,
        remediation: Some(summary),
        remediation_patch: None,
        baseline: None,
        batch: None,
        estimate: None,
        doctor: None,
        setup: None,
        augmented: None,
    };
    let text = s.to_string();
    assert!(
        text.contains("Remediation: 1 processed, 0 failed. Outcome: 1 fixed, 0 not fixed."),
        "{text}"
    );
    assert!(
        text.contains("Nothing validated as fixed (exit code 3)."),
        "{text}"
    );
}

#[test]
fn the_json_export_carries_decision_null_score_totals_and_rollup() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("remediation.json");
    let run = outcome(
        vec![
            record(bc_stage_s10::Verdict::Fixed, Some(DIFF)),
            record(bc_stage_s10::Verdict::Fixed, Some(DIFF)),
        ],
        vec![
            Some(score(FixVerdict::Unverifiable, 0.0)),
            Some(score(FixVerdict::NotFixed, 0.25)),
        ],
        0,
    );
    write_remediation_json(Some(&path), &run).unwrap();
    let written: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let first = &written["results"][0]["validation"];
    assert_eq!(first["raw_score"], serde_json::Value::Null);
    assert_eq!(first["decision"], "inconclusive");
    assert_eq!(first["fix_status"], "UNVERIFIABLE");
    let second = &written["results"][1]["validation"];
    assert_eq!(second["raw_score"], 0.25);
    assert_eq!(second["decision"], "not_fixed");
    assert_eq!(
        written["totals"],
        serde_json::json!({
            "attempted": 2,
            "fixed": 2,
            "not_fixed": 0,
            "failed": 0,
            "validation_failures": 0,
            "exit_code": 3,
        })
    );
    assert_eq!(
        written["rollup"],
        serde_json::json!({
            "cases": 2,
            "states": {"failed": 1, "open": 1},
            "decisions": {"inconclusive": 1, "not_fixed": 1},
        })
    );

    // A file written before these fields existed still reads back.
    let legacy = r#"{"refused":null,"results":[{"status":"processed","finding_index":1,
        "finding_id":"f","verdict":"Fixed","policy_action":null,"policy_reason":null,
        "final_verdict":null,"changes":[],"summary":"","diff":null,"validation":
        {"raw_score":0.0,"fix_status":"UNVERIFIABLE","justification":"",
        "gate_results":[],"has_critical_failure":false}}]}"#;
    let parsed: RemediationExport = serde_json::from_str(legacy).unwrap();
    assert_eq!(parsed.totals.attempted, 0);
    assert_eq!(parsed.rollup.cases, 0);
}

#[test]
fn validate_flags_override_the_config_file() {
    let repo = tempfile::tempdir().unwrap();
    let config_dir = tempfile::tempdir().unwrap();
    let config_path = config_dir.path().join("config.yaml");
    std::fs::write(&config_path, "step_validate:\n  enabled: false\n").unwrap();

    let mut c = crate::test_support::minimal_cli(repo.path());
    assert!(build_remediate_settings(&c).unwrap().validate_enabled);
    c.config = Some(config_path);
    assert!(!build_remediate_settings(&c).unwrap().validate_enabled);
    c.validate = Some(true);
    assert!(build_remediate_settings(&c).unwrap().validate_enabled);
    c.config = None;
    c.validate = Some(false);
    assert!(!build_remediate_settings(&c).unwrap().validate_enabled);
    c.validate = None;
    c.no_validate = true;
    assert!(!build_remediate_settings(&c).unwrap().validate_enabled);
}

#[test]
fn validate_flag_parses_bare_explicit_and_negated_forms() {
    use clap::Parser;
    let parse = |extra: &[&str]| {
        let mut argv = vec![
            "bc-sast",
            "--gateway-base-url",
            "http://gw.example",
            "--repo",
            ".",
        ];
        argv.extend_from_slice(extra);
        Cli::try_parse_from(argv)
    };
    assert_eq!(parse(&[]).unwrap().validate, None);
    assert_eq!(parse(&["--validate"]).unwrap().validate, Some(true));
    assert_eq!(
        parse(&["--validate", "false"]).unwrap().validate,
        Some(false)
    );
    assert!(parse(&["--no-validate"]).unwrap().no_validate);
    assert!(parse(&["--validate", "--no-validate"]).is_err());
}

#[test]
fn remediation_exit_code_defaults_on_and_takes_an_explicit_value() {
    use clap::Parser;
    let parse = |extra: &[&str]| {
        let mut argv = vec![
            "bc-sast",
            "--gateway-base-url",
            "http://gw.example",
            "--repo",
            ".",
        ];
        argv.extend_from_slice(extra);
        Cli::try_parse_from(argv).unwrap().remediation_exit_code
    };
    assert!(parse(&[]));
    assert!(parse(&["--remediation-exit-code"]));
    assert!(!parse(&["--remediation-exit-code", "false"]));
}

#[test]
fn the_engine_identity_is_the_dialect_and_gateway_host() {
    let repo = tempfile::tempdir().unwrap();
    let mut c = crate::test_support::minimal_cli(repo.path());
    c.gateway_base_url = "https://gw.example:8443/v1".to_string();
    c.dialect = Dialect::Anthropic;
    assert_eq!(
        engine_identity(&c),
        ("anthropic".to_string(), "gw.example".to_string())
    );
    c.gateway_base_url = "not a url".to_string();
    c.dialect = Dialect::Openai;
    assert_eq!(engine_identity(&c), ("openai".to_string(), String::new()));

    c.gateway_base_url = "https://gw.example".to_string();
    let settings = build_remediate_settings(&c).unwrap();
    assert_eq!(settings.config.step10.dialect, "openai");
    assert_eq!(settings.config.step10.base_host, "gw.example");
    assert_eq!(settings.step11.dialect, "openai");
    assert_eq!(settings.step11.base_host, "gw.example");
}
