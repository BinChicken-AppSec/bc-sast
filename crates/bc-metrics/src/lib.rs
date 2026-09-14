//! Pure building blocks for assembling `ScanMetrics`, ported from the
//! Python reference's `util/metrics.py::build()`.
//!
//! `build()` itself concretely depends on `ContextPackage`/`TaskManifest`/
//! `ScanMetrics`/`ScopeEntry` (defined in the higher-tier `bc-model`
//! crate) and reads real files off disk for LOC counts — none of that
//! belongs in a dependency-free Tier-0 crate. What's ported here is
//! everything about that function that *is* pure logic: timestamp
//! formatting/parsing, non-blank line counting, the "folders scanned"
//! derivation, chunk-kind classification, and the failed-chunk count. The
//! orchestrator (once built) assembles the concrete `ScanMetrics` from
//! these plus the model-shaped data it already has in scope.
//!
//! Deliberate deviation from the Python original: no global `TOKENS`
//! accumulator dependency here at all — token totals are threaded through
//! as plain values by whichever higher-tier code builds the final
//! `ScanMetrics`, per the port's "no shared mutable singleton" design.

use std::collections::BTreeSet;

use time::macros::format_description;
use time::{OffsetDateTime, PrimitiveDateTime};

const TIMESTAMP_FORMAT: &[time::format_description::FormatItem] =
    format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z");

/// Current UTC timestamp in the pipeline's canonical format,
/// `%Y-%m-%dT%H:%M:%SZ`. Uses `PrimitiveDateTime` (no offset component) to
/// format/parse, since the trailing `Z` in [`TIMESTAMP_FORMAT`] is matched
/// as literal text rather than a recognized offset marker — UTC is
/// implied by convention throughout this codebase, not carried in the
/// value itself.
pub fn now_iso() -> String {
    let now = OffsetDateTime::now_utc();
    PrimitiveDateTime::new(now.date(), now.time())
        .format(TIMESTAMP_FORMAT)
        .unwrap_or_default()
}

/// Duration in seconds between two timestamps in the canonical format.
/// Fails safe to `0.0` (never panics/errors) if either fails to parse,
/// matching the Python original's broad try/except fallback.
pub fn duration_seconds(start_iso: &str, end_iso: &str) -> f64 {
    let parse = |s: &str| PrimitiveDateTime::parse(s, TIMESTAMP_FORMAT).ok();
    match (parse(start_iso), parse(end_iso)) {
        (Some(s), Some(e)) => (e - s).as_seconds_f64(),
        _ => 0.0,
    }
}

/// Count non-blank (post-trim) lines in `content`.
pub fn count_nonblank_lines(content: &str) -> usize {
    content.lines().filter(|l| !l.trim().is_empty()).count()
}

/// Derive the sorted, deduplicated set of "folders scanned" from a set of
/// forward- or backslash-separated relative file paths: every path's
/// parent directory (normalized to forward slashes), plus `"."` always
/// included. Files with no separator at all (top-level) contribute
/// nothing beyond the always-present `"."`.
///
/// Assumes repo-relative paths (never a leading `/` or drive letter) —
/// matching how this is actually called (`ContextPackage::all_files` is
/// always repo-relative) — so this does not attempt to replicate
/// `pathlib`'s absolute-path parent semantics.
pub fn folders_scanned<'a>(files: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let mut set: BTreeSet<String> = BTreeSet::new();
    set.insert(".".to_string());
    for f in files {
        if !(f.contains('/') || f.contains('\\')) {
            continue;
        }
        let normalized = f.replace('\\', "/");
        let parent = normalized.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
        set.insert(if parent.is_empty() {
            ".".to_string()
        } else {
            parent.to_string()
        });
    }
    set.into_iter().collect()
}

/// A chunk's classification for its `ScopeEntry.kind`, mirroring the S3
/// decompose stage's own specialist/catchall/risk labelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkKind {
    Risk,
    Catchall,
    Specialist,
}

impl ChunkKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ChunkKind::Risk => "risk",
            ChunkKind::Catchall => "catchall",
            ChunkKind::Specialist => "specialist",
        }
    }
}

/// Classify a chunk: specialist chunks are flagged explicitly; among the
/// rest, an id starting with `"catchall-"` is the coverage-sweep kind;
/// everything else is a risk-ranked chunk.
pub fn chunk_kind(chunk_id: &str, specialist: bool) -> ChunkKind {
    if specialist {
        ChunkKind::Specialist
    } else if chunk_id.starts_with("catchall-") {
        ChunkKind::Catchall
    } else {
        ChunkKind::Risk
    }
}

/// Count of chunk outcomes that are anything other than `"completed"`.
/// Matches the Python original's "absent entirely (legacy --resume) counts
/// as zero failed, not a false alarm" behaviour by construction — an
/// absent chunk simply isn't in the iterator at all.
pub fn count_failed_chunks<'a>(outcomes: impl IntoIterator<Item = &'a str>) -> usize {
    outcomes.into_iter().filter(|&v| v != "completed").count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[test]
    fn now_iso_produces_the_canonical_format() {
        let ts = now_iso();
        // 2024-01-01T00:00:00Z shape: 20 chars, 'T' at 10, 'Z' at end.
        assert_eq!(ts.len(), 20);
        assert_eq!(ts.as_bytes()[10], b'T');
        assert!(ts.ends_with('Z'));
        // Round-trips through duration_seconds as a sanity check that the
        // format this function emits is exactly what the parser accepts.
        assert_eq!(duration_seconds(&ts, &ts), 0.0);
    }

    #[rstest]
    #[case("2024-01-01T00:00:00Z", "2024-01-01T00:00:10Z", 10.0)]
    #[case("2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z", 0.0)]
    #[case("2024-01-01T23:59:50Z", "2024-01-02T00:00:10Z", 20.0)] // crosses midnight
    #[case("2000-01-01T00:00:00Z", "2000-03-01T00:00:00Z", 60.0 * 60.0 * 24.0 * 60.0)] // Jan+Feb in a leap year = 60 days
    fn duration_seconds_known_pairs(#[case] start: &str, #[case] end: &str, #[case] expected: f64) {
        assert_eq!(duration_seconds(start, end), expected);
    }

    #[test]
    fn duration_seconds_negative_when_end_before_start() {
        assert_eq!(
            duration_seconds("2024-01-01T00:00:10Z", "2024-01-01T00:00:00Z"),
            -10.0
        );
    }

    #[test]
    fn duration_seconds_fails_safe_to_zero_on_malformed_input() {
        assert_eq!(
            duration_seconds("not a timestamp", "2024-01-01T00:00:00Z"),
            0.0
        );
        assert_eq!(
            duration_seconds("2024-01-01T00:00:00Z", "also not one"),
            0.0
        );
        assert_eq!(duration_seconds("garbage", "also garbage"), 0.0);
        assert_eq!(duration_seconds("", ""), 0.0);
    }

    #[rstest]
    #[case("", 0)]
    #[case("   \n\t  \n", 0)]
    #[case("a\nb\nc", 3)]
    #[case("a\n\nb\n  \nc", 3)]
    #[case("single line no trailing newline", 1)]
    fn count_nonblank_lines_cases(#[case] content: &str, #[case] expected: usize) {
        assert_eq!(count_nonblank_lines(content), expected);
    }

    #[test]
    fn folders_scanned_always_includes_dot() {
        assert_eq!(folders_scanned(std::iter::empty()), vec!["."]);
        assert_eq!(folders_scanned(["top_level.rs"]), vec!["."]);
    }

    #[test]
    fn folders_scanned_derives_and_dedupes_parents() {
        let files = ["src/a.rs", "src/b.rs", "src/nested/c.rs", "README.md"];
        assert_eq!(
            folders_scanned(files),
            vec![".".to_string(), "src".to_string(), "src/nested".to_string()]
        );
    }

    #[test]
    fn folders_scanned_normalizes_backslashes() {
        let files = [r"src\windows\a.rs"];
        assert_eq!(
            folders_scanned(files),
            vec![".".to_string(), "src/windows".to_string()]
        );
    }

    #[test]
    fn folders_scanned_top_level_separator_yields_dot() {
        // A single leading separator with nothing before it (e.g. a
        // repo-relative "./x" written without the dot, just "/x") should
        // fall back to "." rather than an empty string.
        let files = ["/x.rs"];
        assert_eq!(folders_scanned(files), vec!["."]);
    }

    #[rstest]
    #[case("risk-001", false, ChunkKind::Risk)]
    #[case("catchall-002", false, ChunkKind::Catchall)]
    #[case("anything", true, ChunkKind::Specialist)]
    #[case("catchall-but-specialist", true, ChunkKind::Specialist)] // specialist wins
    fn chunk_kind_classification(
        #[case] id: &str,
        #[case] specialist: bool,
        #[case] expected: ChunkKind,
    ) {
        assert_eq!(chunk_kind(id, specialist), expected);
    }

    #[test]
    fn chunk_kind_as_str() {
        assert_eq!(ChunkKind::Risk.as_str(), "risk");
        assert_eq!(ChunkKind::Catchall.as_str(), "catchall");
        assert_eq!(ChunkKind::Specialist.as_str(), "specialist");
    }

    #[test]
    fn count_failed_chunks_counts_non_completed() {
        assert_eq!(count_failed_chunks(["completed", "completed"]), 0);
        assert_eq!(
            count_failed_chunks(["completed", "guardrail_blocked", "error"]),
            2
        );
        assert_eq!(count_failed_chunks(std::iter::empty()), 0);
    }
}
