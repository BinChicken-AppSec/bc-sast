//! Wire-string forms for `bc-model` enums this crate displays verbatim in
//! prompt text, matching the established pattern in `bc-report-md`/
//! `bc-sarif`'s own `wire.rs` modules (kept local rather than added to
//! `bc-model`).

use bc_model::ControlKind;

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
