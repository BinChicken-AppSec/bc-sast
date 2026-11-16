use std::collections::BTreeSet;

use time::macros::format_description;
use time::{OffsetDateTime, PrimitiveDateTime};

const TIMESTAMP_FORMAT: &[time::format_description::FormatItem] =
    format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z");

pub fn now_iso() -> String {
    let now = OffsetDateTime::now_utc();
    PrimitiveDateTime::new(now.date(), now.time())
        .format(TIMESTAMP_FORMAT)
        .unwrap_or_default()
}

pub fn duration_seconds(start_iso: &str, end_iso: &str) -> f64 {
    let parse = |s: &str| PrimitiveDateTime::parse(s, TIMESTAMP_FORMAT).ok();
    match (parse(start_iso), parse(end_iso)) {
        (Some(s), Some(e)) => (e - s).as_seconds_f64(),
        _ => 0.0,
    }
}

pub fn count_nonblank_lines(content: &str) -> usize {
    content.lines().filter(|l| !l.trim().is_empty()).count()
}

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

pub fn chunk_kind(chunk_id: &str, specialist: bool) -> ChunkKind {
    if specialist {
        ChunkKind::Specialist
    } else if chunk_id.starts_with("catchall-") {
        ChunkKind::Catchall
    } else {
        ChunkKind::Risk
    }
}

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
        assert_eq!(ts.len(), 20);
        assert_eq!(ts.as_bytes()[10], b'T');
        assert!(ts.ends_with('Z'));
        assert_eq!(duration_seconds(&ts, &ts), 0.0);
    }

    #[rstest]
    #[case("2024-01-01T00:00:00Z", "2024-01-01T00:00:10Z", 10.0)]
    #[case("2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z", 0.0)]
    #[case("2024-01-01T23:59:50Z", "2024-01-02T00:00:10Z", 20.0)]
    #[case("2000-01-01T00:00:00Z", "2000-03-01T00:00:00Z", 60.0 * 60.0 * 24.0 * 60.0)]
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
        let files = ["/x.rs"];
        assert_eq!(folders_scanned(files), vec!["."]);
    }

    #[rstest]
    #[case("risk-001", false, ChunkKind::Risk)]
    #[case("catchall-002", false, ChunkKind::Catchall)]
    #[case("anything", true, ChunkKind::Specialist)]
    #[case("catchall-but-specialist", true, ChunkKind::Specialist)]
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

pub fn scan_uuid() -> String {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::OnceLock;
    use std::time::{SystemTime, UNIX_EPOCH};

    static COUNTER: AtomicU64 = AtomicU64::new(0);
    static SEED: OnceLock<RandomState> = OnceLock::new();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let ms = now.as_millis() as u64;
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);

    let mut hasher = SEED.get_or_init(RandomState::new).build_hasher();
    hasher.write_u64(counter);
    hasher.write_u128(now.as_nanos());
    hasher.write_u32(std::process::id());
    let rand_b = hasher.finish() & ((1u64 << 62) - 1);
    let rand_a = (counter & 0x0fff) as u16;

    let mut bytes = [0u8; 16];
    bytes[0..6].copy_from_slice(&ms.to_be_bytes()[2..8]);
    bytes[6] = 0x70 | ((rand_a >> 8) as u8 & 0x0f);
    bytes[7] = (rand_a & 0xff) as u8;
    bytes[8] = 0x80 | ((rand_b >> 56) as u8 & 0x3f);
    bytes[9..16].copy_from_slice(&rand_b.to_be_bytes()[1..8]);

    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

#[cfg(test)]
mod scan_uuid_tests {
    use super::scan_uuid;
    use std::collections::BTreeSet;

    #[test]
    fn is_a_well_formed_uuid_version_7_variant_10() {
        let id = scan_uuid();
        let groups: Vec<&str> = id.split('-').collect();
        assert_eq!(
            groups.iter().map(|g| g.len()).collect::<Vec<_>>(),
            vec![8, 4, 4, 4, 12],
            "{id}"
        );
        assert!(
            id.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
                && id.chars().all(|c| !c.is_ascii_uppercase()),
            "{id}"
        );
        assert_eq!(groups[2].chars().next().unwrap(), '7', "{id}");
        assert!(
            matches!(groups[3].chars().next().unwrap(), '8' | '9' | 'a' | 'b'),
            "{id}"
        );
    }

    #[test]
    fn ten_thousand_ids_minted_in_a_tight_loop_are_all_distinct() {
        let ids: BTreeSet<String> = (0..10_000).map(|_| scan_uuid()).collect();
        assert_eq!(ids.len(), 10_000);
    }

    #[test]
    fn the_timestamp_prefix_never_goes_backwards() {
        let stamps: Vec<String> = (0..500)
            .map(|_| scan_uuid().replace('-', "")[0..12].to_string())
            .collect();
        let mut sorted = stamps.clone();
        sorted.sort();
        assert_eq!(stamps, sorted, "v7 ids must sort in creation order");
    }
}
