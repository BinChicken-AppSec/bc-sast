/// Whether a finding may get an actual patch generated, or only
/// non-mutating guidance. Strictly binary — ported from
/// `policy_gate/action.py`'s own explicit "there is no 'auto' vs
/// 'suggest' autonomy mode" — that distinction lives only in the
/// playbook's advisory `confidence` field, never in the gate's decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Patch,
    GuidanceOnly,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variants_are_distinct() {
        assert_ne!(Action::Patch, Action::GuidanceOnly);
    }
}
