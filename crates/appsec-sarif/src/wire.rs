use appsec_model::Severity;

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
