//! The run-outcome vocabulary a remediation run is summarized in, ported
//! from `models/vocab.py` (`Decision`, `CaseState`), `models/derive.py`
//! (`verdict_state`) and `orchestrator/case_rollup.py` (`rc_for_verdicts`,
//! the rollup shape) in vvaharness v1.4.0.
//!
//! **Why a second vocabulary next to [`FixVerdict`].** `FixVerdict` is the
//! scorer's own output and keeps its historical wire label
//! `UNVERIFIABLE`. A [`Decision`] is what a consumer branches on: the same
//! four outcomes, with the one that is not a verdict at all named for what
//! it is (`inconclusive`: the panel could not decide, re-validate). A
//! [`CaseState`] is where a finding stands after the run, and is what the
//! exit code and the rollup key on, so that "partially fixed" (mergeable
//! with conditions, but not validated) and "inconclusive" (not a failure)
//! each land where Python puts them.

use std::collections::BTreeMap;

use crate::{FixVerdict, ValidationScore};

/// A validator's conclusion about whether a remediation worked
/// (`models/vocab.py::Decision`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Decision {
    Fixed,
    PartiallyFixed,
    NotFixed,
    /// The panel reached no usable verdict (`FixVerdict::Unverifiable`).
    /// Carries no score: see [`ValidationScore::score`].
    Inconclusive,
}

impl Decision {
    /// Python's wire values, lower snake case.
    pub fn as_str(self) -> &'static str {
        match self {
            Decision::Fixed => "fixed",
            Decision::PartiallyFixed => "partially_fixed",
            Decision::NotFixed => "not_fixed",
            Decision::Inconclusive => "inconclusive",
        }
    }
}

impl From<FixVerdict> for Decision {
    fn from(v: FixVerdict) -> Self {
        match v {
            FixVerdict::Fixed => Decision::Fixed,
            FixVerdict::PartiallyFixed => Decision::PartiallyFixed,
            FixVerdict::NotFixed => Decision::NotFixed,
            FixVerdict::Unverifiable => Decision::Inconclusive,
        }
    }
}

/// Where one finding stands after the run (`models/vocab.py::CaseState`).
/// Never stored; always derived.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CaseState {
    /// Nothing settled: never attempted, or validated inconclusively (so
    /// re-validating is the answer).
    Open,
    /// A patch is applied (or proposed) but nobody validated it.
    Remediated,
    /// Validated as fixed.
    Validated,
    /// Validated as not (fully) fixed.
    Failed,
    /// No patch was produced or kept: policy denial, out of scope, a
    /// declined or rolled-back attempt.
    Declined,
    /// Handed to a ticket. Part of Python's vocabulary for completeness;
    /// this port has no ticketing step, so nothing derives it yet.
    Pending,
}

impl CaseState {
    pub fn as_str(self) -> &'static str {
        match self {
            CaseState::Open => "open",
            CaseState::Remediated => "remediated",
            CaseState::Validated => "validated",
            CaseState::Failed => "failed",
            CaseState::Declined => "declined",
            CaseState::Pending => "pending",
        }
    }
}

/// The case state a validator decision implies (`derive.py::
/// verdict_state`'s `_DECISION_STATE`). `PartiallyFixed` is `Failed`:
/// merge readiness may call it conditionally acceptable, but that is the
/// operator's policy, not the engine's verdict. `Inconclusive` is `Open`,
/// never `Failed`, because the fix was not shown to be bad.
pub fn verdict_state(decision: Decision) -> CaseState {
    match decision {
        Decision::Fixed => CaseState::Validated,
        Decision::PartiallyFixed | Decision::NotFixed => CaseState::Failed,
        Decision::Inconclusive => CaseState::Open,
    }
}

/// `true` when the run validated nothing and at least one fix failed
/// validation: the condition for `EXIT_NOT_REMEDIATED`
/// (`case_rollup.py::rc_for_verdicts`).
///
/// Deliberately narrow, as Python explains: any single validated fix
/// clears it, and an all-inconclusive run does not trip it (inconclusive
/// derives to `Open`, not `Failed`), because a signal that is red on most
/// mixed runs gets wrapped in `|| true` and stops being a signal.
pub fn not_remediated(decisions: impl IntoIterator<Item = Decision>) -> bool {
    let states: Vec<CaseState> = decisions.into_iter().map(verdict_state).collect();
    !states.contains(&CaseState::Validated) && states.contains(&CaseState::Failed)
}

impl ValidationScore {
    /// This score's [`Decision`].
    pub fn decision(&self) -> Decision {
        self.fix_status.into()
    }

    /// The numeric score, or `None` for an inconclusive panel. Python
    /// reports no score for `INCONCLUSIVE`; this port's `raw_score` is
    /// `0.0` there, which reads as "scored and failed" to anything that
    /// does not also check the status, so consumers should prefer this.
    pub fn score(&self) -> Option<f64> {
        (self.fix_status != FixVerdict::Unverifiable).then_some(self.raw_score)
    }
}

/// Counts of case states and validator decisions for one run, the shape
/// `case_rollup.py::_shaped` writes into the run manifest. Counts only: a
/// title or path from the scanned target never reaches it. Only observed
/// names appear, so a consumer reads a missing key as zero.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Rollup {
    pub cases: usize,
    pub states: BTreeMap<&'static str, usize>,
    pub decisions: BTreeMap<&'static str, usize>,
}

impl Rollup {
    /// Tallies `(state, decision)` pairs, one per case. A case nobody
    /// validated contributes its state and no decision.
    pub fn tally(cases: impl IntoIterator<Item = (CaseState, Option<Decision>)>) -> Self {
        let mut rollup = Rollup::default();
        for (state, decision) in cases {
            rollup.cases += 1;
            *rollup.states.entry(state.as_str()).or_default() += 1;
            if let Some(decision) = decision {
                *rollup.decisions.entry(decision.as_str()).or_default() += 1;
            }
        }
        rollup
    }
}

/// How one S11 pass turned out, in the terms a progress line needs:
/// how many fixes got a score, how many of those validated, how many
/// failed, and how many the panel could not decide. Keyed on
/// [`verdict_state`], so a partially fixed patch counts as failed here
/// exactly as it does for the exit code.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ValidationCounts {
    pub validated: usize,
    pub passed: usize,
    pub failed: usize,
    pub inconclusive: usize,
}

impl ValidationCounts {
    pub fn tally(decisions: impl IntoIterator<Item = Decision>) -> Self {
        let mut counts = ValidationCounts::default();
        for decision in decisions {
            counts.validated += 1;
            match verdict_state(decision) {
                CaseState::Validated => counts.passed += 1,
                CaseState::Failed => counts.failed += 1,
                _ => counts.inconclusive += 1,
            }
        }
        counts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn score(fix_status: FixVerdict, raw_score: f64) -> ValidationScore {
        ValidationScore {
            raw_score,
            fix_status,
            justification: String::new(),
            gate_results: Vec::new(),
            has_critical_failure: false,
        }
    }

    #[test]
    fn wire_labels_match_python() {
        let decisions = [
            (Decision::Fixed, "fixed"),
            (Decision::PartiallyFixed, "partially_fixed"),
            (Decision::NotFixed, "not_fixed"),
            (Decision::Inconclusive, "inconclusive"),
        ];
        for (d, label) in decisions {
            assert_eq!(d.as_str(), label);
        }
        let states = [
            (CaseState::Open, "open"),
            (CaseState::Remediated, "remediated"),
            (CaseState::Validated, "validated"),
            (CaseState::Failed, "failed"),
            (CaseState::Declined, "declined"),
            (CaseState::Pending, "pending"),
        ];
        for (s, label) in states {
            assert_eq!(s.as_str(), label);
        }
    }

    #[test]
    fn a_fix_verdict_maps_to_its_decision_and_state() {
        let cases = [
            (FixVerdict::Fixed, Decision::Fixed, CaseState::Validated),
            (
                FixVerdict::PartiallyFixed,
                Decision::PartiallyFixed,
                CaseState::Failed,
            ),
            (FixVerdict::NotFixed, Decision::NotFixed, CaseState::Failed),
            (
                FixVerdict::Unverifiable,
                Decision::Inconclusive,
                CaseState::Open,
            ),
        ];
        for (verdict, decision, state) in cases {
            assert_eq!(Decision::from(verdict), decision);
            assert_eq!(verdict_state(decision), state);
        }
    }

    #[test]
    fn not_remediated_needs_a_failure_and_no_validated_fix() {
        use Decision::*;
        assert!(!not_remediated([]));
        assert!(!not_remediated([Inconclusive, Inconclusive]));
        assert!(!not_remediated([Fixed, NotFixed]));
        assert!(!not_remediated([Fixed]));
        assert!(not_remediated([NotFixed]));
        assert!(not_remediated([PartiallyFixed, Inconclusive]));
    }

    #[test]
    fn validation_counts_follow_the_case_state() {
        use Decision::*;
        assert_eq!(
            ValidationCounts::tally([Fixed, PartiallyFixed, NotFixed, Inconclusive, Fixed]),
            ValidationCounts {
                validated: 5,
                passed: 2,
                failed: 2,
                inconclusive: 1,
            }
        );
        assert_eq!(ValidationCounts::tally([]), ValidationCounts::default());
    }

    #[test]
    fn an_inconclusive_score_has_no_number() {
        assert_eq!(score(FixVerdict::Unverifiable, 0.0).score(), None);
        assert_eq!(
            score(FixVerdict::Unverifiable, 0.0).decision(),
            Decision::Inconclusive
        );
        assert_eq!(score(FixVerdict::NotFixed, 0.2).score(), Some(0.2));
    }

    #[test]
    fn the_rollup_counts_states_and_only_observed_decisions() {
        let rollup = Rollup::tally([
            (CaseState::Validated, Some(Decision::Fixed)),
            (CaseState::Failed, Some(Decision::NotFixed)),
            (CaseState::Failed, Some(Decision::PartiallyFixed)),
            (CaseState::Declined, None),
        ]);
        assert_eq!(rollup.cases, 4);
        assert_eq!(
            rollup.states,
            BTreeMap::from([("declined", 1), ("failed", 2), ("validated", 1)])
        );
        assert_eq!(
            rollup.decisions,
            BTreeMap::from([("fixed", 1), ("not_fixed", 1), ("partially_fixed", 1)])
        );
        assert_eq!(Rollup::tally([]), Rollup::default());
    }
}
