use appsec_model::ScanMetrics;

const ERR_CAP_CHARS: usize = 400;

pub const EMPTY_SCOPE_SUMMARY: &str = "0 files analyzed: no conclusion can be drawn about this \
     repository; check the S1 file inventory and exclusions.";

pub const EMPTY_SCOPE_REASON: &str = "scope was empty: 0 files reached analysis";

pub fn scope_was_empty(metrics: Option<&ScanMetrics>) -> bool {
    metrics.is_some_and(|m| m.total_files_in_scope == 0)
}

pub fn redacted_err(err: &dyn std::fmt::Display) -> String {
    appsec_redact::redact(&err.to_string())
        .chars()
        .take(ERR_CAP_CHARS)
        .collect()
}

pub fn redacted_head_tail(raw: &str) -> (String, String) {
    let safe: Vec<char> = appsec_redact::redact(raw).chars().collect();
    let head: String = safe.iter().take(500).collect();
    let tail: String = safe[safe.len().saturating_sub(200)..].iter().collect();
    (head.replace('\n', "\\n"), tail.replace('\n', "\\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_key() -> String {
        format!("AKIA{}", "ABCDEFGHIJKLMNOP")
    }

    #[test]
    fn redacted_err_redacts_before_capping_a_straddling_secret() {
        let msg = format!("{} {}", "x".repeat(389), fake_key());
        let out = redacted_err(&msg);
        assert!(!out.contains("AKIAABCD"), "{out}");
        assert!(out.chars().count() <= ERR_CAP_CHARS);
    }

    #[test]
    fn redacted_err_keeps_short_benign_text() {
        assert_eq!(redacted_err(&"provider down"), "provider down");
    }

    #[test]
    fn head_tail_are_redacted_bounded_and_single_line() {
        let raw = format!("a\nb {} {}", fake_key(), "y".repeat(800));
        let (head, tail) = redacted_head_tail(&raw);
        assert!(head.starts_with("a\\nb "));
        assert!(!head.contains(&fake_key()));
        assert_eq!(head.chars().count(), 501);
        assert_eq!(tail, "y".repeat(200));
        let (h, t) = redacted_head_tail("short");
        assert_eq!((h.as_str(), t.as_str()), ("short", "short"));
    }

    #[test]
    fn scope_was_empty_needs_metrics_reporting_zero_files() {
        assert!(!scope_was_empty(None));
        let mut m = ScanMetrics::default();
        assert!(scope_was_empty(Some(&m)));
        m.total_files_in_scope = 3;
        assert!(!scope_was_empty(Some(&m)));
    }
}
