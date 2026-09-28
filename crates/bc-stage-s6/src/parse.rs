//! Plain-text VERDICT:/CVSS: two-line-tail parser for the verifier's
//! agentic reply — not JSON. Ported from `s6_verify.py`'s `_CVSS_RE` /
//! `_VERDICT_RE` / `_parse_verdict`.

use std::sync::LazyLock;

use bc_model::Verdict;
use regex::Regex;

/// Case-sensitive (no `(?i)`, matching the Python original exactly) —
/// letter codes are always emitted uppercase by a well-formed reply, and a
/// lowercase `av:n` is not a vector this scorer should treat as valid.
/// Accepts both `CVSS:3.0` and `CVSS:3.1`, matching `bc_cvss`'s own
/// `3\.[01]` acceptance.
static CVSS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"CVSS:3\.[01]/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH]")
        .unwrap()
});

static VERDICT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)VERDICT:\s*(TRUE_POSITIVE|FALSE_POSITIVE)\s*\(confidence:\s*(\d{1,2})\s*/\s*10\)\s*[—\-–]?\s*(.*)").unwrap()
});

#[derive(Debug, Clone, PartialEq)]
pub struct ParsedVerdict {
    pub verdict: Verdict,
    pub confidence: i64,
    pub reason: String,
    pub cvss: Option<String>,
    pub reasoning: String,
}

/// Scans lines bottom-up for the last `VERDICT:` line (a model that
/// second-guesses itself mid-reply has its FINAL word win), then looks for
/// a CVSS vector on the tail from that line onward, falling back to the
/// last CVSS vector anywhere in the raw text if none follows the verdict.
/// Everything before the verdict line becomes `reasoning`. No `VERDICT:`
/// line at all defaults to `FalsePositive`/confidence 0/`"verifier output
/// unparseable"` — an undetermined result, not a confirmed false positive
/// (the caller is responsible for not laundering this into the FP bucket).
pub fn parse_verdict(raw: &str) -> ParsedVerdict {
    let lines: Vec<&str> = raw.trim().lines().collect();

    let mut verdict = Verdict::FalsePositive;
    let mut confidence = 0i64;
    let mut reason = "verifier output unparseable".to_string();
    let mut verdict_line_idx = lines.len();

    for i in (0..lines.len()).rev() {
        if let Some(caps) = VERDICT_RE.captures(lines[i]) {
            verdict = if caps[1].eq_ignore_ascii_case("TRUE_POSITIVE") {
                Verdict::TruePositive
            } else {
                Verdict::FalsePositive
            };
            confidence = caps[2].parse::<i64>().unwrap_or(0).clamp(0, 10);
            let r = caps[3].trim();
            reason = if r.is_empty() {
                "(no reason given)".to_string()
            } else {
                r.to_string()
            };
            verdict_line_idx = i;
            break;
        }
    }

    let tail = lines[verdict_line_idx..].join("\n");
    let cvss = CVSS_RE
        .find(&tail)
        .map(|m| m.as_str().to_string())
        .or_else(|| {
            CVSS_RE
                .find_iter(raw)
                .last()
                .map(|m| m.as_str().to_string())
        });

    let reasoning = lines[..verdict_line_idx].join("\n").trim().to_string();

    ParsedVerdict {
        verdict,
        confidence,
        reason,
        cvss,
        reasoning,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD_CVSS: &str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";

    #[test]
    fn cvss_re_accepts_31() {
        assert!(CVSS_RE.is_match("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"));
    }

    #[test]
    fn cvss_re_accepts_30() {
        assert!(CVSS_RE.is_match("CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:N/A:H"));
    }

    #[test]
    fn cvss_re_rejects_20() {
        assert!(!CVSS_RE.is_match("CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P"));
        assert!(!CVSS_RE.is_match("CVSS:2.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"));
    }

    #[test]
    fn cvss_re_rejects_malformed_metric() {
        assert!(!CVSS_RE.is_match("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"));
    }

    #[test]
    fn parse_verdict_true_positive_with_cvss() {
        let raw = format!(
            "I read the file and traced callers.\nThe route is unauthenticated.\nVERDICT: TRUE_POSITIVE (confidence: 9/10) — reachable from unauth route\nCVSS: {GOOD_CVSS}\n"
        );
        let p = parse_verdict(&raw);
        assert_eq!(p.verdict, Verdict::TruePositive);
        assert_eq!(p.confidence, 9);
        assert_eq!(p.reason, "reachable from unauth route");
        assert_eq!(p.cvss.as_deref(), Some(GOOD_CVSS));
        assert!(p.reasoning.contains("traced callers"));
        assert!(!p.reasoning.contains("VERDICT"));
    }

    #[test]
    fn parse_verdict_false_positive() {
        let raw = format!("Analysis body.\nVERDICT: FALSE_POSITIVE (confidence: 8/10) — upstream allow-list neutralizes input\nCVSS: {GOOD_CVSS}\n");
        let p = parse_verdict(&raw);
        assert_eq!(p.verdict, Verdict::FalsePositive);
        assert_eq!(p.confidence, 8);
        assert_eq!(p.reason, "upstream allow-list neutralizes input");
        assert_eq!(p.cvss.as_deref(), Some(GOOD_CVSS));
    }

    #[test]
    fn parse_verdict_unparseable_defaults_to_false_positive() {
        let raw = "The model rambled and never emitted a verdict line.\n";
        let p = parse_verdict(raw);
        assert_eq!(p.verdict, Verdict::FalsePositive);
        assert_eq!(p.confidence, 0);
        assert_eq!(p.reason, "verifier output unparseable");
        assert!(p.cvss.is_none());
    }

    #[test]
    fn parse_verdict_confidence_clamped_to_10() {
        let raw = format!(
            "VERDICT: TRUE_POSITIVE (confidence: 99/10) — over the top\nCVSS: {GOOD_CVSS}\n"
        );
        assert_eq!(parse_verdict(&raw).confidence, 10);
    }

    #[test]
    fn parse_verdict_reads_last_verdict_line() {
        let raw = format!(
            "VERDICT: FALSE_POSITIVE (confidence: 3/10) — early draft\n...more analysis...\nVERDICT: TRUE_POSITIVE (confidence: 10/10) — final answer\nCVSS: {GOOD_CVSS}\n"
        );
        let p = parse_verdict(&raw);
        assert_eq!(p.verdict, Verdict::TruePositive);
        assert_eq!(p.confidence, 10);
        assert_eq!(p.reason, "final answer");
    }

    #[test]
    fn parse_verdict_prefers_cvss_after_verdict_line() {
        let decoy = "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:L";
        let raw = format!("Earlier I considered: {decoy}\nVERDICT: TRUE_POSITIVE (confidence: 8/10) — confirmed\nCVSS: {GOOD_CVSS}\n");
        let p = parse_verdict(&raw);
        assert_eq!(p.cvss.as_deref(), Some(GOOD_CVSS));
        assert_ne!(p.cvss.as_deref(), Some(decoy));
    }

    #[test]
    fn parse_verdict_falls_back_to_last_cvss_when_none_after_verdict() {
        let raw =
            format!("Body mentions {GOOD_CVSS} up here.\nVERDICT: TRUE_POSITIVE (confidence: 7/10) — confirmed\n(no cvss on the next line)\n");
        let p = parse_verdict(&raw);
        assert_eq!(p.cvss.as_deref(), Some(GOOD_CVSS));
    }

    #[test]
    fn parse_verdict_accepts_30_vector() {
        let v30 = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
        let raw = format!("VERDICT: TRUE_POSITIVE (confidence: 9/10) — ok\nCVSS: {v30}\n");
        assert_eq!(parse_verdict(&raw).cvss.as_deref(), Some(v30));
    }

    #[test]
    fn no_reason_given_falls_back_to_placeholder() {
        let raw = "VERDICT: TRUE_POSITIVE (confidence: 9/10)\n";
        assert_eq!(parse_verdict(raw).reason, "(no reason given)");
    }

    #[test]
    fn lowercase_verdict_keyword_is_still_matched_and_normalized() {
        let raw = "verdict: true_positive (confidence: 9/10) — ok\n";
        assert_eq!(parse_verdict(raw).verdict, Verdict::TruePositive);
    }
}
