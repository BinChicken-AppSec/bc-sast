//! Local wire-string mappings for the `ControlKind`/`Sensitivity`/`Actor`/
//! `Impact`/`Likelihood` enums, matching the exact `Literal[...]`/`str`-enum
//! wire values `s8_chain.py`'s f-strings interpolate directly.

use bc_model::{Actor, ControlKind, Impact, Likelihood, Sensitivity, Verdict};

pub fn control_kind_str(kind: ControlKind) -> &'static str {
    match kind {
        ControlKind::Auth => "auth",
        ControlKind::Sandbox => "sandbox",
        ControlKind::InputValidation => "input-validation",
        ControlKind::Aslr => "aslr",
        ControlKind::Cfi => "cfi",
        ControlKind::Other => "other",
    }
}

pub fn sensitivity_str(s: Sensitivity) -> &'static str {
    match s {
        Sensitivity::Low => "low",
        Sensitivity::Medium => "medium",
        Sensitivity::High => "high",
        Sensitivity::Critical => "critical",
    }
}

pub fn actor_str(a: Actor) -> &'static str {
    match a {
        Actor::RemoteUnauth => "remote_unauth",
        Actor::RemoteAuth => "remote_auth",
        Actor::AdjacentNetwork => "adjacent_network",
        Actor::LocalUser => "local_user",
        Actor::LocalAdmin => "local_admin",
        Actor::SupplyChain => "supply_chain",
        Actor::Insider => "insider",
    }
}

pub fn impact_str(i: Impact) -> &'static str {
    match i {
        Impact::Low => "low",
        Impact::Medium => "medium",
        Impact::High => "high",
        Impact::Critical => "critical",
        Impact::Existential => "existential",
    }
}

pub fn likelihood_str(l: Likelihood) -> &'static str {
    match l {
        Likelihood::VeryRare => "very_rare",
        Likelihood::Rare => "rare",
        Likelihood::Possible => "possible",
        Likelihood::Likely => "likely",
        Likelihood::AlmostCertain => "almost_certain",
    }
}

pub fn verdict_str(v: Verdict) -> &'static str {
    match v {
        Verdict::TruePositive => "TRUE_POSITIVE",
        Verdict::FalsePositive => "FALSE_POSITIVE",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(ControlKind::Auth, "auth")]
    #[case(ControlKind::Sandbox, "sandbox")]
    #[case(ControlKind::InputValidation, "input-validation")]
    #[case(ControlKind::Aslr, "aslr")]
    #[case(ControlKind::Cfi, "cfi")]
    #[case(ControlKind::Other, "other")]
    fn control_kind_wire_strings(#[case] kind: ControlKind, #[case] expected: &str) {
        assert_eq!(control_kind_str(kind), expected);
    }

    #[rstest]
    #[case(Sensitivity::Low, "low")]
    #[case(Sensitivity::Medium, "medium")]
    #[case(Sensitivity::High, "high")]
    #[case(Sensitivity::Critical, "critical")]
    fn sensitivity_wire_strings(#[case] s: Sensitivity, #[case] expected: &str) {
        assert_eq!(sensitivity_str(s), expected);
    }

    #[rstest]
    #[case(Actor::RemoteUnauth, "remote_unauth")]
    #[case(Actor::RemoteAuth, "remote_auth")]
    #[case(Actor::AdjacentNetwork, "adjacent_network")]
    #[case(Actor::LocalUser, "local_user")]
    #[case(Actor::LocalAdmin, "local_admin")]
    #[case(Actor::SupplyChain, "supply_chain")]
    #[case(Actor::Insider, "insider")]
    fn actor_wire_strings(#[case] a: Actor, #[case] expected: &str) {
        assert_eq!(actor_str(a), expected);
    }

    #[rstest]
    #[case(Impact::Low, "low")]
    #[case(Impact::Medium, "medium")]
    #[case(Impact::High, "high")]
    #[case(Impact::Critical, "critical")]
    #[case(Impact::Existential, "existential")]
    fn impact_wire_strings(#[case] i: Impact, #[case] expected: &str) {
        assert_eq!(impact_str(i), expected);
    }

    #[rstest]
    #[case(Likelihood::VeryRare, "very_rare")]
    #[case(Likelihood::Rare, "rare")]
    #[case(Likelihood::Possible, "possible")]
    #[case(Likelihood::Likely, "likely")]
    #[case(Likelihood::AlmostCertain, "almost_certain")]
    fn likelihood_wire_strings(#[case] l: Likelihood, #[case] expected: &str) {
        assert_eq!(likelihood_str(l), expected);
    }

    #[rstest]
    #[case(Verdict::TruePositive, "TRUE_POSITIVE")]
    #[case(Verdict::FalsePositive, "FALSE_POSITIVE")]
    fn verdict_wire_strings(#[case] v: Verdict, #[case] expected: &str) {
        assert_eq!(verdict_str(v), expected);
    }
}
