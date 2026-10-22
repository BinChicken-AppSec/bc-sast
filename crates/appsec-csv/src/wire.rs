//! Wire-string forms for `appsec-model` enums this crate displays verbatim,
//! matching the pattern established in `appsec-report-md`'s and `appsec-sarif`'s
//! own `wire.rs` (kept local rather than added to `appsec-model`).

use appsec_model::{Severity, Verdict};

/// Matches `appsec-report-md`'s own `severity_upper` casing, so a finding's
/// severity reads identically across `report.md` and `report.csv`.
pub fn severity_upper(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "CRITICAL",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
        Severity::Info => "INFO",
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
    fn verdict_str_cases(#[case] v: Verdict, #[case] expected: &str) {
        assert_eq!(verdict_str(v), expected);
    }
}
