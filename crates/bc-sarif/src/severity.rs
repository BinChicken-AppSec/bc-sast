//! Severity/CVSS-derived SARIF fields, ported from
//! `enrich.py::_sarif_level`/`_security_severity`/`_cvss_rating` and the
//! inline `rank` computation in `generate_sarif`.

use bc_model::Severity;

/// CRITICAL/HIGH -> `error`, MEDIUM -> `warning`, else (LOW/INFO) -> `note`.
pub fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

/// GitHub code-scanning's qualitative CVSS band for a numeric score.
fn qualitative(score: f64) -> &'static str {
    if score >= 9.0 {
        "Critical"
    } else if score >= 7.0 {
        "High"
    } else if score >= 4.0 {
        "Medium"
    } else if score >= 0.1 {
        "Low"
    } else {
        "None"
    }
}

/// Fallback numeric severity when no CVSS score is known, keyed by the
/// finding's own severity rating.
fn severity_fallback_score(severity: Severity) -> f64 {
    match severity {
        Severity::Critical => 9.0,
        Severity::High => 7.0,
        Severity::Medium => 4.0,
        Severity::Low => 0.1,
        Severity::Info => 0.0,
    }
}

/// `properties["security-severity"]` — the CVSS score verbatim (as a
/// string, per the SARIF/GitHub convention) when known, else the
/// severity-keyed fallback table.
pub fn security_severity(severity: Severity, cvss_score: Option<f64>) -> String {
    match cvss_score.filter(|s| *s >= 0.0) {
        Some(s) => format!("{s:.1}"),
        None => format!("{:.1}", severity_fallback_score(severity)),
    }
}

/// `properties["cvssRating"]` — qualitative band for the same score used
/// by [`security_severity`] (real score if known, else the fallback).
pub fn cvss_rating(severity: Severity, cvss_score: Option<f64>) -> &'static str {
    let score = cvss_score
        .filter(|s| *s >= 0.0)
        .unwrap_or_else(|| severity_fallback_score(severity));
    qualitative(score)
}

/// Round to 1 decimal place.
pub fn round1(x: f64) -> f64 {
    (x * 10.0).round() / 10.0
}

/// Round to 2 decimal places (`properties.confidence`'s precision).
pub fn round2(x: f64) -> f64 {
    (x * 100.0).round() / 100.0
}

/// `result.rank` — `cvss_score * 10` on SARIF's 0-100 scale, only present
/// when a genuine non-negative score is known.
pub fn rank(cvss_score: Option<f64>) -> Option<f64> {
    cvss_score.filter(|s| *s >= 0.0).map(|s| round1(s * 10.0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(Severity::Critical, "error")]
    #[case(Severity::High, "error")]
    #[case(Severity::Medium, "warning")]
    #[case(Severity::Low, "note")]
    #[case(Severity::Info, "note")]
    fn sarif_level_mapping(#[case] sev: Severity, #[case] expected: &str) {
        assert_eq!(sarif_level(sev), expected);
    }

    #[test]
    fn security_severity_uses_real_score_when_present() {
        assert_eq!(security_severity(Severity::Low, Some(9.8)), "9.8");
    }

    #[rstest]
    #[case(Severity::Critical, "9.0")]
    #[case(Severity::High, "7.0")]
    #[case(Severity::Medium, "4.0")]
    #[case(Severity::Low, "0.1")]
    #[case(Severity::Info, "0.0")]
    fn security_severity_fallback_table(#[case] sev: Severity, #[case] expected: &str) {
        assert_eq!(security_severity(sev, None), expected);
    }

    #[test]
    fn security_severity_negative_score_is_treated_as_unknown() {
        assert_eq!(security_severity(Severity::High, Some(-1.0)), "7.0");
    }

    #[test]
    fn cvss_rating_uses_real_score_when_present() {
        assert_eq!(cvss_rating(Severity::Low, Some(9.8)), "Critical");
    }

    #[test]
    fn cvss_rating_falls_back_to_severity_when_no_score() {
        assert_eq!(cvss_rating(Severity::Critical, None), "Critical");
        assert_eq!(cvss_rating(Severity::High, None), "High");
        assert_eq!(cvss_rating(Severity::Medium, None), "Medium");
        assert_eq!(cvss_rating(Severity::Low, None), "Low");
        assert_eq!(cvss_rating(Severity::Info, None), "None");
    }

    #[rstest]
    #[case(0.0, "None")]
    #[case(0.05, "None")]
    #[case(0.1, "Low")]
    #[case(3.9, "Low")]
    #[case(4.0, "Medium")]
    #[case(6.9, "Medium")]
    #[case(7.0, "High")]
    #[case(8.9, "High")]
    #[case(9.0, "Critical")]
    #[case(10.0, "Critical")]
    fn qualitative_boundaries(#[case] score: f64, #[case] expected: &str) {
        assert_eq!(qualitative(score), expected);
    }

    #[test]
    fn round1_rounds_to_one_decimal_place() {
        assert_eq!(round1(9.83), 9.8);
        assert_eq!(round1(9.85), 9.9);
        assert_eq!(round1(0.0), 0.0);
    }

    #[test]
    fn round2_rounds_to_two_decimal_places() {
        assert_eq!(round2(0.9231), 0.92);
        assert_eq!(round2(0.9251), 0.93);
        assert_eq!(round2(1.0), 1.0);
    }

    #[test]
    fn rank_is_score_times_ten() {
        assert_eq!(rank(Some(9.8)), Some(98.0));
        assert_eq!(rank(Some(10.0)), Some(100.0));
        assert_eq!(rank(Some(0.0)), Some(0.0));
    }

    #[test]
    fn rank_is_none_when_score_absent_or_negative() {
        assert_eq!(rank(None), None);
        assert_eq!(rank(Some(-1.0)), None);
    }
}
