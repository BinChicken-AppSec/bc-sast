//! CWE-id normalization for compliance-policy requirement lists.
//!
//! A small, deliberate duplicate of `bc-policy-gate::cwe::norm_cwe` (a
//! faithful port of `remediation_agent/policy_gate/loader.py::_norm_cwe`
//! — upper-case first, strip a literal `CWE-` prefix, require the
//! remainder all-ASCII-digits, re-render verbatim with no leading-zero
//! stripping) — not shared cross-crate since this crate has no other
//! reason to depend on `bc-policy-gate` (a different concern: S10
//! remediation gating, not compliance reporting) and the function is ten
//! lines. Not itself a port of anything — `bc-compliance` has no Python
//! original — but it must produce exactly the same canonical shape
//! `Finding.cwe` already carries by the time `matching_requirement_ids`
//! plain-string-compares against it (see `types.rs`'s own doc comment),
//! and every producer of that field already uses this exact shape.

/// Normalizes a CWE identifier to canonical `CWE-<digits>` form, or
/// `None` if it isn't recognizably a CWE id at all.
pub fn norm_cwe(s: &str) -> Option<String> {
    let upper = s.trim().to_uppercase();
    let digits = upper.strip_prefix("CWE-").unwrap_or(&upper);
    if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some(format!("CWE-{digits}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("CWE-89", Some("CWE-89"))]
    #[case("cwe-89", Some("CWE-89"))]
    #[case("Cwe-89", Some("CWE-89"))]
    #[case("cWe-89", Some("CWE-89"))]
    #[case("CwE-89", Some("CWE-89"))]
    #[case("  CWE-89  ", Some("CWE-89"))]
    #[case("89", Some("CWE-89"))]
    #[case("CWE-0089", Some("CWE-0089"))]
    #[case("cwe_0089", None)]
    #[case("CWE 89", None)]
    #[case("see CWE-89 here", None)]
    #[case("CWE-", None)]
    #[case("", None)]
    #[case("CWE-89a", None)]
    #[case("not-a-cwe", None)]
    fn norm_cwe_cases(#[case] input: &str, #[case] expected: Option<&str>) {
        assert_eq!(norm_cwe(input), expected.map(str::to_string));
    }
}
