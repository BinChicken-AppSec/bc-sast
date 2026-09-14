//! Wire-string forms for `bc-model` enums this crate displays verbatim,
//! matching the pattern established in `bc-report-md`'s own `wire.rs`
//! (kept local rather than added to `bc-model`).

use bc_model::Severity;

/// `properties.severity` — the lowercase severity token, matching
/// Python's `f.severity.lower()`.
pub fn severity_lower(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(Severity::Critical, "critical")]
    #[case(Severity::High, "high")]
    #[case(Severity::Medium, "medium")]
    #[case(Severity::Low, "low")]
    #[case(Severity::Info, "info")]
    fn severity_lower_cases(#[case] s: Severity, #[case] expected: &str) {
        assert_eq!(severity_lower(s), expected);
    }
}
