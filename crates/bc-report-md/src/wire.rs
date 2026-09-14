//! Wire-string forms for `bc-model` enums the renderer displays verbatim
//! (matching the raw `Literal[...]` string value Python renders, not a
//! humanized/titlecased label). Kept local to this crate rather than added
//! to `bc-model` itself, matching this project's convention of not
//! reopening an already-verified crate for one consumer's formatting need.

use bc_model::{Actor, DropReason, Impact, Likelihood, Sensitivity, Severity, Verdict};

/// `f.severity.value.upper()` — the Python source upper-cases the wire
/// value inline rather than defining a separate display form, so this
/// returns the already-uppercased literal directly.
pub fn severity_upper(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "CRITICAL",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
        Severity::Info => "INFO",
    }
}

/// `Finding.verdict` is a plain `Literal["TRUE_POSITIVE", "FALSE_POSITIVE"]`
/// in the Python model (not an `Enum`), so f-string interpolation renders
/// the raw literal as-is — this returns that same wire string.
pub fn verdict_str(v: Verdict) -> &'static str {
    match v {
        Verdict::TruePositive => "TRUE_POSITIVE",
        Verdict::FalsePositive => "FALSE_POSITIVE",
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

pub fn sensitivity_str(s: Sensitivity) -> &'static str {
    match s {
        Sensitivity::Low => "low",
        Sensitivity::Medium => "medium",
        Sensitivity::High => "high",
        Sensitivity::Critical => "critical",
    }
}

/// `_tag`/`DUP of #N` mapping from `models.py::to_markdown`'s Dropped
/// Findings loop. Unlike the Python source (whose `Literal["...", ...]`
/// type can't statically rule out an unlisted string reaching the
/// `_tag.get(d.reason, d.reason)` fallback), Rust's enum is exhaustively
/// matched, so that defensive fallback arm has no equivalent here — every
/// variant is handled explicitly.
pub fn drop_tag(reason: DropReason, canonical_idx: Option<i64>) -> String {
    match reason {
        DropReason::Duplicate => match canonical_idx {
            Some(idx) => format!("DUP of #{}", idx + 1),
            None => "DUP (pre-verify)".to_string(),
        },
        DropReason::FalsePositive => "FP".to_string(),
        DropReason::Unconfirmed => "UNCONFIRMED".to_string(),
        DropReason::VerifyError => "VERIFY-ERR".to_string(),
        DropReason::Excluded => "EXCLUDED".to_string(),
        DropReason::GuardrailBlocked => "GUARDRAIL".to_string(),
        // Net-new versus Python, which has no diff scoping at all. Spelled
        // out rather than abbreviated: this tag says "this scan never
        // looked at that file", which is the one drop reason a reader must
        // not mistake for a verdict.
        DropReason::OutOfDiffScope => "OUT OF DIFF SCOPE".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(Severity::Critical, "CRITICAL")]
    #[case(Severity::High, "HIGH")]
    #[case(Severity::Medium, "MEDIUM")]
    #[case(Severity::Low, "LOW")]
    #[case(Severity::Info, "INFO")]
    fn severity_upper_cases(#[case] s: Severity, #[case] expected: &str) {
        assert_eq!(severity_upper(s), expected);
    }

    #[rstest]
    #[case(Verdict::TruePositive, "TRUE_POSITIVE")]
    #[case(Verdict::FalsePositive, "FALSE_POSITIVE")]
    fn verdict_wire_strings(#[case] v: Verdict, #[case] expected: &str) {
        assert_eq!(verdict_str(v), expected);
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
    #[case(Sensitivity::Low, "low")]
    #[case(Sensitivity::Medium, "medium")]
    #[case(Sensitivity::High, "high")]
    #[case(Sensitivity::Critical, "critical")]
    fn sensitivity_wire_strings(#[case] s: Sensitivity, #[case] expected: &str) {
        assert_eq!(sensitivity_str(s), expected);
    }

    #[test]
    fn drop_tag_duplicate_with_canonical_idx() {
        assert_eq!(drop_tag(DropReason::Duplicate, Some(2)), "DUP of #3");
    }

    #[test]
    fn drop_tag_duplicate_without_canonical_idx() {
        assert_eq!(drop_tag(DropReason::Duplicate, None), "DUP (pre-verify)");
    }

    #[rstest]
    #[case(DropReason::FalsePositive, "FP")]
    #[case(DropReason::Unconfirmed, "UNCONFIRMED")]
    #[case(DropReason::VerifyError, "VERIFY-ERR")]
    #[case(DropReason::Excluded, "EXCLUDED")]
    #[case(DropReason::GuardrailBlocked, "GUARDRAIL")]
    #[case(DropReason::OutOfDiffScope, "OUT OF DIFF SCOPE")]
    fn drop_tag_non_duplicate_reasons(#[case] reason: DropReason, #[case] expected: &str) {
        assert_eq!(drop_tag(reason, None), expected);
    }
}
