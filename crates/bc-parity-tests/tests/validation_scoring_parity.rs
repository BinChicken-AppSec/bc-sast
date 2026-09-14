//! Exhaustively cross-checks `bc_validation_scoring::score_fix` +
//! `derive_merge_readiness` against the real, shipped
//! `vvaharness.validation.scoring.score_fix` (via
//! `parity/oracles/validation_scoring_oracle.py` — the package's own
//! `__main__.py` CLI entrypoint this test used to shell out to no longer
//! exists) over every combination of the 4 gates x 5 statuses (5^4 = 625
//! — small enough to enumerate fully), plus the two shape-error cases
//! (missing gate, duplicate gate).
//!
//! Only `fix_status` and `raw_score` (and, for the full combo sweep,
//! `merge_readiness`) are compared — `justification` is free-form prose
//! this port intentionally rephrased, not a wire-format contract; the
//! oracle doesn't emit `has_critical_failure` at all for the same reason.

mod support;

use bc_validation_scoring::{derive_merge_readiness, score_fix, GateName, GateResult, GateStatus};

const STATUSES: [&str; 5] = ["pass", "partial", "fail", "skip", "invalid"];
const GATE_NAMES: [&str; 4] = [
    "root_cause",
    "instance_coverage",
    "no_new_vulnerabilities",
    "security_best_practices",
];

fn gate(gate_name: GateName, status: GateStatus) -> GateResult {
    GateResult {
        gate_name,
        status,
        summary: String::new(),
        evidence: Vec::new(),
        details: String::new(),
        // The oracle's own gate dicts carry no `confidence` key either,
        // so both sides run with Python's `RawCriterion.confidence`
        // default of `""` — the synthesis-consensus check is off for
        // this sweep, which is about the scoring arithmetic.
        confidence: None,
    }
}

fn build_gates(statuses: [&str; 4]) -> Vec<GateResult> {
    GateName::ALL
        .into_iter()
        .zip(statuses)
        .map(|(name, s)| gate(name, GateStatus::parse(s)))
        .collect()
}

fn oracle_finding(id: &str, pairs: &[(&str, &str)]) -> serde_json::Value {
    let gates: Vec<serde_json::Value> = pairs
        .iter()
        .map(|(name, status)| serde_json::json!({"gate_name": name, "status": status}))
        .collect();
    serde_json::json!({"tracking_id": id, "gates": gates})
}

#[test]
fn score_fix_matches_the_python_scoring_cli_across_every_gate_status_combination() {
    let Some(py) = support::resolve() else {
        return;
    };

    let mut combos: Vec<[&str; 4]> = Vec::with_capacity(625);
    for a in STATUSES {
        for b in STATUSES {
            for c in STATUSES {
                for d in STATUSES {
                    combos.push([a, b, c, d]);
                }
            }
        }
    }
    assert_eq!(combos.len(), 625);

    let mut findings: Vec<serde_json::Value> = combos
        .iter()
        .enumerate()
        .map(|(i, combo)| {
            let pairs: Vec<(&str, &str)> = GATE_NAMES
                .iter()
                .copied()
                .zip(combo.iter().copied())
                .collect();
            oracle_finding(&i.to_string(), &pairs)
        })
        .collect();
    findings.push(oracle_finding(
        "missing",
        &[
            ("root_cause", "pass"),
            ("instance_coverage", "pass"),
            ("no_new_vulnerabilities", "pass"),
        ],
    ));
    findings.push(oracle_finding(
        "duplicate",
        &[
            ("root_cause", "pass"),
            ("root_cause", "fail"),
            ("instance_coverage", "pass"),
            ("no_new_vulnerabilities", "pass"),
            ("security_best_practices", "pass"),
        ],
    ));

    let batch = serde_json::json!({"findings": findings});
    let out = py.run_oracle("validation_scoring_oracle.py", &batch);
    let out_findings = out
        .get("findings")
        .and_then(|v| v.as_array())
        .expect("CLI returns a findings array");
    assert_eq!(out_findings.len(), findings.len());

    let mut mismatches = Vec::new();
    for (i, combo) in combos.iter().enumerate() {
        let gates = build_gates(*combo);
        let score = score_fix(&gates);
        let readiness = derive_merge_readiness(score.fix_status).as_str();

        let py_entry = &out_findings[i];
        let py_status = py_entry.get("fix_status").unwrap().as_str().unwrap();
        let py_score = py_entry.get("raw_score").unwrap().as_f64().unwrap();
        let py_readiness = py_entry.get("merge_readiness").unwrap().as_str().unwrap();

        let matches = score.fix_status.as_str() == py_status
            && (score.raw_score - py_score).abs() < 1e-9
            && readiness == py_readiness;
        if !matches {
            mismatches.push(format!(
                "combo {combo:?}: rust=({}, {}, {readiness}) python=({py_status}, {py_score}, {py_readiness})",
                score.fix_status.as_str(),
                score.raw_score,
            ));
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} of {} combos mismatched (showing up to 20):\n{}",
        mismatches.len(),
        combos.len(),
        mismatches
            .iter()
            .take(20)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );

    let missing_gates = vec![
        gate(GateName::RootCause, GateStatus::Pass),
        gate(GateName::InstanceCoverage, GateStatus::Pass),
        gate(GateName::NoNewVulnerabilities, GateStatus::Pass),
    ];
    let missing_score = score_fix(&missing_gates);
    let py_missing = &out_findings[combos.len()];
    assert_eq!(
        missing_score.fix_status.as_str(),
        py_missing.get("fix_status").unwrap().as_str().unwrap(),
        "missing-gate case"
    );
    assert_eq!(
        missing_score.raw_score,
        py_missing.get("raw_score").unwrap().as_f64().unwrap(),
        "missing-gate case"
    );

    let duplicate_gates = vec![
        gate(GateName::RootCause, GateStatus::Pass),
        gate(GateName::RootCause, GateStatus::Fail),
        gate(GateName::InstanceCoverage, GateStatus::Pass),
        gate(GateName::NoNewVulnerabilities, GateStatus::Pass),
        gate(GateName::SecurityBestPractices, GateStatus::Pass),
    ];
    let duplicate_score = score_fix(&duplicate_gates);
    let py_duplicate = &out_findings[combos.len() + 1];
    assert_eq!(
        duplicate_score.fix_status.as_str(),
        py_duplicate.get("fix_status").unwrap().as_str().unwrap(),
        "duplicate-gate case"
    );
    assert_eq!(
        duplicate_score.raw_score,
        py_duplicate.get("raw_score").unwrap().as_f64().unwrap(),
        "duplicate-gate case"
    );
}
