//! Text shaping for S8's degraded paths: the summary strings that ship in
//! the delivered report and the raw-response excerpts that go to the log.
//! Ported from the v1.4.0 `s8_chain.py` additions (`_redacted_err`, the
//! empty-scope summary and the redact-then-slice raw excerpts).

use bc_model::ScanMetrics;

/// Cap on provider/parse error text embedded in a report summary. Mirrors
/// the upstream `_redacted_err(e, cap=400)`.
const ERR_CAP_CHARS: usize = 400;

/// Summary for a scan whose scope was empty: "read nothing" and "found
/// nothing" are opposite states and must not share a summary.
pub const EMPTY_SCOPE_SUMMARY: &str = "0 files analyzed: no conclusion can be drawn about this \
     repository; check the S1 file inventory and exclusions.";

/// `degraded_reason` paired with [`EMPTY_SCOPE_SUMMARY`].
pub const EMPTY_SCOPE_REASON: &str = "scope was empty: 0 files reached analysis";

/// True when metrics were supplied and say no file was ever in scope. A
/// run without metrics is not assumed empty (the upstream check is
/// `metrics is not None and not metrics.total_files_in_scope`).
pub fn scope_was_empty(metrics: Option<&ScanMetrics>) -> bool {
    metrics.is_some_and(|m| m.total_files_in_scope == 0)
}

/// Error text destined for the DELIVERED report summary. A provider error
/// body can quote request fragments (repository source or
/// credential-shaped material) and the summary lands in the customer
/// artifact, so the FULL text is redacted first and only then truncated:
/// truncating first could bisect a secret so its pattern no longer
/// matches.
pub fn redacted_err(err: &dyn std::fmt::Display) -> String {
    bc_redact::redact(&err.to_string())
        .chars()
        .take(ERR_CAP_CHARS)
        .collect()
}

/// First 500 and last 200 characters of an unparseable reply for the log,
/// taken from the redacted FULL text (same bisected-secret rationale as
/// [`redacted_err`]), with newlines escaped so each lands on one log line.
pub fn redacted_head_tail(raw: &str) -> (String, String) {
    let safe: Vec<char> = bc_redact::redact(raw).chars().collect();
    let head: String = safe.iter().take(500).collect();
    let tail: String = safe[safe.len().saturating_sub(200)..].iter().collect();
    (head.replace('\n', "\\n"), tail.replace('\n', "\\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // A synthetic AWS-style access key id: 20 chars, which `bc_redact`
    // recognizes. Built at runtime so the source never carries the literal.
    fn fake_key() -> String {
        format!("AKIA{}", "ABCDEFGHIJKLMNOP")
    }

    #[test]
    fn redacted_err_redacts_before_capping_a_straddling_secret() {
        // Place the key so the 400-char cap would cut it in half: slicing
        // first would leave an unrecognizable (so unredacted) prefix.
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
        assert_eq!(head.chars().count(), 501); // 500 chars, one '\n' -> "\\n"
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
