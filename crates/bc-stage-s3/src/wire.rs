//! Local wire-string mappings for `EntryPointKind`/`ControlKind`/
//! `Sensitivity`/`Actor`/`Impact`/`Likelihood`, matching the exact
//! `Literal[...]`/`str`-enum wire values `models.py`'s f-strings
//! interpolate directly (the Python fields are plain string literals, not
//! enums, so the raw value IS the wire string).

use bc_model::{Actor, ControlKind, EntryPointKind, Impact, Likelihood, Sensitivity};

pub fn ep_kind_str(kind: EntryPointKind) -> &'static str {
    match kind {
        EntryPointKind::Network => "network",
        EntryPointKind::Ipc => "ipc",
        EntryPointKind::File => "file",
        EntryPointKind::Cli => "cli",
        EntryPointKind::Deserialization => "deserialization",
        EntryPointKind::Framework => "framework",
        EntryPointKind::Other => "other",
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ep_kind_wire_strings() {
        assert_eq!(ep_kind_str(EntryPointKind::Network), "network");
        assert_eq!(ep_kind_str(EntryPointKind::Ipc), "ipc");
        assert_eq!(ep_kind_str(EntryPointKind::File), "file");
        assert_eq!(ep_kind_str(EntryPointKind::Cli), "cli");
        assert_eq!(
            ep_kind_str(EntryPointKind::Deserialization),
            "deserialization"
        );
        assert_eq!(ep_kind_str(EntryPointKind::Framework), "framework");
        assert_eq!(ep_kind_str(EntryPointKind::Other), "other");
    }

    #[test]
    fn control_kind_wire_strings() {
        assert_eq!(control_kind_str(ControlKind::Auth), "auth");
        assert_eq!(control_kind_str(ControlKind::Sandbox), "sandbox");
        assert_eq!(
            control_kind_str(ControlKind::InputValidation),
            "input-validation"
        );
        assert_eq!(control_kind_str(ControlKind::Aslr), "aslr");
        assert_eq!(control_kind_str(ControlKind::Cfi), "cfi");
        assert_eq!(control_kind_str(ControlKind::Other), "other");
    }

    #[test]
    fn sensitivity_wire_strings() {
        assert_eq!(sensitivity_str(Sensitivity::Low), "low");
        assert_eq!(sensitivity_str(Sensitivity::Medium), "medium");
        assert_eq!(sensitivity_str(Sensitivity::High), "high");
        assert_eq!(sensitivity_str(Sensitivity::Critical), "critical");
    }

    #[test]
    fn actor_wire_strings() {
        assert_eq!(actor_str(Actor::RemoteUnauth), "remote_unauth");
        assert_eq!(actor_str(Actor::RemoteAuth), "remote_auth");
        assert_eq!(actor_str(Actor::AdjacentNetwork), "adjacent_network");
        assert_eq!(actor_str(Actor::LocalUser), "local_user");
        assert_eq!(actor_str(Actor::LocalAdmin), "local_admin");
        assert_eq!(actor_str(Actor::SupplyChain), "supply_chain");
        assert_eq!(actor_str(Actor::Insider), "insider");
    }

    #[test]
    fn impact_wire_strings() {
        assert_eq!(impact_str(Impact::Low), "low");
        assert_eq!(impact_str(Impact::Medium), "medium");
        assert_eq!(impact_str(Impact::High), "high");
        assert_eq!(impact_str(Impact::Critical), "critical");
        assert_eq!(impact_str(Impact::Existential), "existential");
    }

    #[test]
    fn likelihood_wire_strings() {
        assert_eq!(likelihood_str(Likelihood::VeryRare), "very_rare");
        assert_eq!(likelihood_str(Likelihood::Rare), "rare");
        assert_eq!(likelihood_str(Likelihood::Possible), "possible");
        assert_eq!(likelihood_str(Likelihood::Likely), "likely");
        assert_eq!(likelihood_str(Likelihood::AlmostCertain), "almost_certain");
    }
}
