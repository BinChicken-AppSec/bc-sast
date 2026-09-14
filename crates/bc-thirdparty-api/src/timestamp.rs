//! Chronological ordering of the RFC 3339 timestamps two vendors use to
//! answer "which is the *latest* scan/report?".
//!
//! Both Sonatype's `evaluationDate` and Checkmarx One's `createdAt` are
//! RFC 3339 strings that carry a real UTC offset rather than always being
//! normalized to `Z` — Sonatype's own documented sample is
//! `"2015-01-16T13:14:32.139-05:00"`
//! (`help.sonatype.com/en/report-rest-api.html`) and Checkmarx's is
//! `"2021-06-02T12:14:18.028555Z"` (the `SCANS.yaml` spec vendored in
//! `checkmarx-ts/checkmarx-python-sdk`). A `str`-on-`str` comparison of
//! those two forms is not a chronological one: `2015-01-16T13:00:00-05:00`
//! (18:00 UTC) sorts *before* `2015-01-16T14:00:00+02:00` (12:00 UTC), so
//! a lexical "max" can silently select an older report and hand the
//! operator stale findings.
//!
//! Sub-second precision differs between the two vendors as well (millis vs
//! micros), which a lexical compare also gets wrong.

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// A sort key that orders vendor timestamps chronologically.
///
/// Unparseable (or absent, i.e. empty) timestamps sort *below* every
/// parseable one via the leading `false`, so a single malformed entry can
/// never win a `max_by_key` and hijack "the latest scan"; if *every* entry
/// is unparseable the caller still gets one back rather than an error,
/// which keeps a vendor whose timestamp format drifts degraded rather than
/// broken.
pub(crate) fn chronological_key(raw: &str) -> (bool, i128) {
    match OffsetDateTime::parse(raw, &Rfc3339) {
        Ok(parsed) => (true, parsed.unix_timestamp_nanos()),
        Err(_) => (false, 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_later_utc_timestamp_sorts_above_an_earlier_one() {
        assert!(
            chronological_key("2026-06-01T00:00:00Z") > chronological_key("2026-01-01T00:00:00Z")
        );
    }

    #[test]
    fn offsets_are_normalized_rather_than_compared_as_text() {
        // 18:00 UTC vs 12:00 UTC: the first is genuinely later, but sorts
        // FIRST lexically because '1' < '4' at the hour position.
        let earlier_looking = "2015-01-16T13:00:00-05:00";
        let later_looking = "2015-01-16T14:00:00+02:00";
        assert!(
            earlier_looking < later_looking,
            "precondition: lexical order"
        );
        assert!(chronological_key(earlier_looking) > chronological_key(later_looking));
    }

    #[test]
    fn sub_second_precision_differences_are_compared_numerically() {
        assert!(
            chronological_key("2021-06-02T12:14:18.9Z")
                > chronological_key("2021-06-02T12:14:18.028555Z")
        );
    }

    #[test]
    fn an_unparseable_timestamp_sorts_below_every_parseable_one() {
        assert!(chronological_key("not a date") < chronological_key("1970-01-01T00:00:00Z"));
    }

    #[test]
    fn an_empty_timestamp_sorts_below_every_parseable_one() {
        assert!(chronological_key("") < chronological_key("1970-01-01T00:00:00Z"));
    }

    #[test]
    fn two_unparseable_timestamps_compare_equal() {
        assert_eq!(chronological_key("nope"), chronological_key("also nope"));
    }
}
