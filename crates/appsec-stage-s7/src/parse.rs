use std::sync::LazyLock;

use regex::Regex;

static LINE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)index\s*=\s*(\d+)\s+is_duplicate\s*=\s*(true|false)\s+canonical\s*=\s*(-?\d+)\s+reasoning\s*=\s*"([^"]*)""#,
    )
    .unwrap()
});

pub fn parse_dedup_output(raw: &str, n: usize) -> Vec<(usize, usize, String)> {
    let mut out = Vec::new();
    for cap in LINE_RE.captures_iter(raw) {
        let is_dup = cap[2].eq_ignore_ascii_case("true");
        if !is_dup {
            continue;
        }
        let idx: i64 = cap[1].parse().unwrap_or(-1);
        let canon: i64 = cap[3].parse().unwrap_or(-1);
        let why = cap[4].trim().to_string();
        if canon >= 0 && canon < idx && idx < n as i64 {
            out.push((idx as usize, canon as usize, why));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_well_formed_duplicate_line() {
        let raw = r#"index=1 is_duplicate=true canonical=0 reasoning="same root cause""#;
        let out = parse_dedup_output(raw, 2);
        assert_eq!(out, vec![(1, 0, "same root cause".to_string())]);
    }

    #[test]
    fn is_duplicate_false_is_skipped() {
        let raw = r#"index=1 is_duplicate=false canonical=-1 reasoning="distinct""#;
        assert!(parse_dedup_output(raw, 2).is_empty());
    }

    #[test]
    fn canonical_not_lower_than_index_is_rejected() {
        let raw = r#"index=1 is_duplicate=true canonical=1 reasoning="x""#;
        assert!(parse_dedup_output(raw, 5).is_empty());
    }

    #[test]
    fn canonical_greater_than_index_is_rejected() {
        let raw = r#"index=0 is_duplicate=true canonical=3 reasoning="x""#;
        assert!(parse_dedup_output(raw, 5).is_empty());
    }

    #[test]
    fn index_out_of_bounds_n_is_rejected() {
        let raw = r#"index=9 is_duplicate=true canonical=0 reasoning="x""#;
        assert!(parse_dedup_output(raw, 5).is_empty());
    }

    #[test]
    fn negative_canonical_is_rejected() {
        let raw = r#"index=2 is_duplicate=true canonical=-1 reasoning="x""#;
        assert!(parse_dedup_output(raw, 5).is_empty());
    }

    #[test]
    fn multiple_lines_ascending_are_all_parsed() {
        let raw = "index=1 is_duplicate=true canonical=0 reasoning=\"a\"\n\
                    index=2 is_duplicate=false canonical=-1 reasoning=\"b\"\n\
                    index=3 is_duplicate=true canonical=1 reasoning=\"c\"\n";
        let out = parse_dedup_output(raw, 5);
        assert_eq!(out, vec![(1, 0, "a".to_string()), (3, 1, "c".to_string())]);
    }

    #[test]
    fn case_insensitive_keywords_and_true_value_are_accepted() {
        let raw = r#"INDEX=1 IS_DUPLICATE=TRUE CANONICAL=0 REASONING="ok""#;
        assert_eq!(parse_dedup_output(raw, 2), vec![(1, 0, "ok".to_string())]);
    }

    #[test]
    fn garbage_input_yields_no_matches() {
        assert!(parse_dedup_output("not the grammar at all", 5).is_empty());
        assert!(parse_dedup_output("", 5).is_empty());
    }

    #[test]
    fn oversized_digit_run_fails_to_parse_and_is_rejected() {
        let raw =
            r#"index=999999999999999999999999999999 is_duplicate=true canonical=0 reasoning="x""#;
        assert!(parse_dedup_output(raw, 5).is_empty());
    }
}
