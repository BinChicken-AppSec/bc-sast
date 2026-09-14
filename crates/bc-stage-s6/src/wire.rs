//! Local wire-string mappings for `EntryPointKind`/`ControlKind`, matching
//! the exact `Literal[...]` string values `s6_verify.py`'s f-strings
//! interpolate (`f"{e.kind}"` / `f"[{c.kind}]"`) — the Python fields are
//! plain string literals, not enums, so the raw value IS the wire string.

use bc_model::{ControlKind, EntryPointKind};

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

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(EntryPointKind::Network, "network")]
    #[case(EntryPointKind::Ipc, "ipc")]
    #[case(EntryPointKind::File, "file")]
    #[case(EntryPointKind::Cli, "cli")]
    #[case(EntryPointKind::Deserialization, "deserialization")]
    #[case(EntryPointKind::Framework, "framework")]
    #[case(EntryPointKind::Other, "other")]
    fn ep_kind_wire_strings(#[case] kind: EntryPointKind, #[case] expected: &str) {
        assert_eq!(ep_kind_str(kind), expected);
    }

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
}
