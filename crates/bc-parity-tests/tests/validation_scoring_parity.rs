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

/// This port and upstream name the same four outcomes differently: ours are
/// report labels (`Fixed`, `UNVERIFIABLE`), upstream's v1.4.0 `Decision` are
/// wire identifiers (`fixed`, `inconclusive`). Neither spelling is wrong, so
/// the comparison happens in upstream's space and this table is the only
/// place the difference lives. A new variant on either side fails to compile
/// or fails the match rather than silently comparing unequal strings.
fn upstream_decision(verdict: bc_validation_scoring::FixVerdict) -> &'static str {
    use bc_validation_scoring::FixVerdict;
    match verdict {
        FixVerdict::Fixed => "fixed",
        FixVerdict::PartiallyFixed => "partially_fixed",
        FixVerdict::NotFixed => "not_fixed",
        // Upstream renamed this outcome to `inconclusive` in v1.4.0; the
        // report label here stays `UNVERIFIABLE`, which is what operators
        // and the SARIF output already say.
        FixVerdict::Unverifiable => "inconclusive",
    }
}

/// The same translation for `MergeReadiness`, whose upstream values became
/// snake_case identifiers in v1.4.0 where v1.2.0 rendered display strings.
fn upstream_readiness(readiness: bc_validation_scoring::MergeReadiness) -> &'static str {
    use bc_validation_scoring::MergeReadiness;
    match readiness {
        MergeReadiness::Ready => "ready",
        MergeReadiness::ReadyWithConditions => "ready_with_conditions",
        MergeReadiness::NotReady => "not_ready",
    }
}

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
        let verdict = upstream_decision(score.fix_status);
        let readiness = upstream_readiness(derive_merge_readiness(score.fix_status));

        let py_entry = &out_findings[i];
        let py_decision = py_entry.get("decision").unwrap().as_str().unwrap();
        let py_score = py_entry.get("raw_score").unwrap().as_f64().unwrap();
        let py_readiness = py_entry.get("merge_readiness").unwrap().as_str().unwrap();

        let matches = verdict == py_decision
            && (score.raw_score - py_score).abs() < 1e-9
            && readiness == py_readiness;
        if !matches {
            mismatches.push(format!(
                "combo {combo:?}: rust=({verdict}, {}, {readiness}) python=({py_decision}, {py_score}, {py_readiness})",
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
        upstream_decision(missing_score.fix_status),
        py_missing.get("decision").unwrap().as_str().unwrap(),
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
        upstream_decision(duplicate_score.fix_status),
        py_duplicate.get("decision").unwrap().as_str().unwrap(),
        "duplicate-gate case"
    );
    assert_eq!(
        duplicate_score.raw_score,
        py_duplicate.get("raw_score").unwrap().as_f64().unwrap(),
        "duplicate-gate case"
    );
}
