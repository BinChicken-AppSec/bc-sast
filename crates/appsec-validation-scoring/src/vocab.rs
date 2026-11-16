use std::collections::BTreeMap;

use crate::{FixVerdict, ValidationScore};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Decision {
    Fixed,
    PartiallyFixed,
    NotFixed,
    Inconclusive,
}

impl Decision {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CaseState {
    Open,
    Remediated,
    Validated,
    Failed,
    Declined,
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

pub fn verdict_state(decision: Decision) -> CaseState {
    match decision {
        Decision::Fixed => CaseState::Validated,
        Decision::PartiallyFixed | Decision::NotFixed => CaseState::Failed,
        Decision::Inconclusive => CaseState::Open,
    }
}

pub fn not_remediated(decisions: impl IntoIterator<Item = Decision>) -> bool {
    let states: Vec<CaseState> = decisions.into_iter().map(verdict_state).collect();
    !states.contains(&CaseState::Validated) && states.contains(&CaseState::Failed)
}

impl ValidationScore {
    pub fn decision(&self) -> Decision {
        self.fix_status.into()
    }

    pub fn score(&self) -> Option<f64> {
        (self.fix_status != FixVerdict::Unverifiable).then_some(self.raw_score)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Rollup {
    pub cases: usize,
    pub states: BTreeMap<&'static str, usize>,
    pub decisions: BTreeMap<&'static str, usize>,
}

impl Rollup {
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
