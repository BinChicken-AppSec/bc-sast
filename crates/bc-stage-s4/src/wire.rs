//! Local wire-string mappings for `ChunkSize` and the context enums the
//! shared deep-dive context renders, matching this project's established
//! convention (e.g. `bc-stage-s6`/`bc-stage-s3`'s own `wire.rs`) of
//! keeping enum-to-Python-`Literal`-string mappings local to the consuming
//! crate rather than growing `bc-model` per caller.

use bc_model::{Actor, ChunkSize, EntryPointKind, Impact, Likelihood, Sensitivity};

pub fn chunk_size_str(size: ChunkSize) -> &'static str {
    match size {
        ChunkSize::Small => "small",
        ChunkSize::Medium => "medium",
        ChunkSize::Large => "large",
    }
}

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
    use serde_json::{to_value, Value};

    #[test]
    fn every_variant_maps_to_its_python_literal_string() {
        assert_eq!(chunk_size_str(ChunkSize::Small), "small");
        assert_eq!(chunk_size_str(ChunkSize::Medium), "medium");
        assert_eq!(chunk_size_str(ChunkSize::Large), "large");
    }

    /// Each string must be what serde writes for the variant, which is the
    /// Python `Literal` value the upstream f-strings interpolate.
    #[test]
    fn context_enum_strings_match_their_serde_wire_values() {
        for k in [
            EntryPointKind::Network,
            EntryPointKind::Ipc,
            EntryPointKind::File,
            EntryPointKind::Cli,
            EntryPointKind::Deserialization,
            EntryPointKind::Framework,
            EntryPointKind::Other,
        ] {
            assert_eq!(Value::from(ep_kind_str(k)), to_value(k).unwrap());
        }
        for s in [
            Sensitivity::Low,
            Sensitivity::Medium,
            Sensitivity::High,
            Sensitivity::Critical,
        ] {
            assert_eq!(Value::from(sensitivity_str(s)), to_value(s).unwrap());
        }
        for a in [
            Actor::RemoteUnauth,
            Actor::RemoteAuth,
            Actor::AdjacentNetwork,
            Actor::LocalUser,
            Actor::LocalAdmin,
            Actor::SupplyChain,
            Actor::Insider,
        ] {
            assert_eq!(Value::from(actor_str(a)), to_value(a).unwrap());
        }
        for i in [
            Impact::Low,
            Impact::Medium,
            Impact::High,
            Impact::Critical,
            Impact::Existential,
        ] {
            assert_eq!(Value::from(impact_str(i)), to_value(i).unwrap());
        }
        for l in [
            Likelihood::VeryRare,
            Likelihood::Rare,
            Likelihood::Possible,
            Likelihood::Likely,
            Likelihood::AlmostCertain,
        ] {
            assert_eq!(Value::from(likelihood_str(l)), to_value(l).unwrap());
        }
    }
}
