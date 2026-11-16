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
