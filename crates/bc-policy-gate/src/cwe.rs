//! CWE-id normalization shared by the gate and the playbook resolver.
//!
//! A faithful port of `remediation_agent/policy_gate/loader.py::_norm_cwe`:
//! upper-case the whole trimmed string first (so every case spelling of
//! `cwe-`/`Cwe-`/`CWE-`/etc. is accepted, not just three hardcoded ones),
//! strip a literal `CWE-` prefix if present, then require the remainder
//! to be all-ASCII-digits and re-render as `CWE-<digits>` — digits kept
//! verbatim, no leading-zero stripping (Python never parses them as an
//! int here, only calls `.isdigit()`). Anything else (empty, non-numeric,
//! e.g. a made-up id) normalizes to `None`, which the gate treats as
//! `"unmapped_cwe"` — the same fail-closed-to-guidance-only outcome a
//! genuinely-unrecognized CWE gets in the Python original.

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
