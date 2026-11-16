use std::collections::BinaryHeap;

pub fn band_score(severity: &str) -> f64 {
    match severity.trim().to_uppercase().as_str() {
        "CRITICAL" => 9.0,
        "HIGH" => 7.0,
        "MEDIUM" => 4.0,
        "LOW" => 1.0,
        "INFO" => 0.0,
        _ => 0.0,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TopSpec {
    N(usize),
    All,
}

pub fn parse_top_spec(raw: &str, source: &str) -> Result<TopSpec, String> {
    let token = raw.trim().to_lowercase();
    if token == "all" || token == "*" {
        return Ok(TopSpec::All);
    }
    match token.parse::<usize>() {
        Ok(n) if n > 0 => Ok(TopSpec::N(n)),
        _ => Err(format!(
            "{source} expects a positive integer or 'all'/'*', got {raw:?}"
        )),
    }
}

pub fn resolve_top(cli: Option<TopSpec>, cfg_default: Option<TopSpec>) -> Option<usize> {
    match cli.or(cfg_default) {
        Some(TopSpec::N(n)) => Some(n),
        Some(TopSpec::All) | None => None,
    }
}

#[derive(PartialEq)]
struct HeapEntry {
    score: f64,
    index: usize,
}

impl Eq for HeapEntry {}

impl PartialOrd for HeapEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for HeapEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.score
            .partial_cmp(&other.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| other.index.cmp(&self.index))
    }
}

pub fn select_top_by_cvss(
    len: usize,
    n: Option<usize>,
    score_of: impl Fn(usize) -> Option<f64>,
    severity_of: impl Fn(usize) -> &'static str,
) -> Vec<usize> {
    let Some(n) = n.filter(|&n| n > 0) else {
        return (0..len).collect();
    };
    let mut heap: BinaryHeap<HeapEntry> = (0..len)
        .map(|index| {
            let score = score_of(index).unwrap_or_else(|| band_score(severity_of(index)));
            HeapEntry { score, index }
        })
        .collect();
    let mut out = Vec::with_capacity(n.min(len));
    for _ in 0..n.min(len) {
        let top = heap
            .pop()
            .expect("loop bound never exceeds the heap's size");
        out.push(top.index);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn band_score_maps_every_known_band() {
        assert_eq!(band_score("CRITICAL"), 9.0);
        assert_eq!(band_score("HIGH"), 7.0);
        assert_eq!(band_score("MEDIUM"), 4.0);
        assert_eq!(band_score("LOW"), 1.0);
        assert_eq!(band_score("INFO"), 0.0);
    }

    #[test]
    fn band_score_is_case_insensitive_and_trims_whitespace() {
        assert_eq!(band_score(" critical "), 9.0);
    }

    #[test]
    fn band_score_of_an_unknown_band_is_zero() {
        assert_eq!(band_score("WHATEVER"), 0.0);
    }

    fn fixture_score(i: usize) -> Option<f64> {
        const SCORES: [f64; 4] = [1.0, 9.0, 5.0, 7.0];
        Some(SCORES[i])
    }

    fn low(_: usize) -> &'static str {
        "LOW"
    }

    #[test]
    fn n_absent_returns_every_index_unchanged() {
        let out = select_top_by_cvss(3, None, fixture_score, low);
        assert_eq!(out, vec![0, 1, 2]);
    }

    #[test]
    fn n_zero_or_negative_is_a_no_op() {
        let out = select_top_by_cvss(3, Some(0), fixture_score, low);
        assert_eq!(out, vec![0, 1, 2]);
    }

    #[test]
    fn selects_the_top_n_highest_scores_in_order() {
        let out = select_top_by_cvss(4, Some(2), fixture_score, low);
        assert_eq!(out, vec![1, 3]);
    }

    #[test]
    fn n_exceeding_the_item_count_reorders_without_dropping_anything() {
        let out = select_top_by_cvss(3, Some(10), fixture_score, low);
        assert_eq!(out, vec![1, 2, 0]);
    }

    #[test]
    fn ties_break_by_stable_original_index() {
        let out = select_top_by_cvss(3, Some(3), |_| Some(5.0), low);
        assert_eq!(out, vec![0, 1, 2]);
    }

    #[test]
    fn falls_back_to_band_score_when_no_numeric_score_is_available() {
        let out = select_top_by_cvss(
            2,
            Some(2),
            |_| None,
            |i| {
                if i == 0 {
                    "CRITICAL"
                } else {
                    "LOW"
                }
            },
        );
        assert_eq!(out, vec![0, 1]);
    }

    fn no_numeric_score(_: usize) -> Option<f64> {
        None
    }

    #[test]
    fn an_empty_item_set_selects_nothing() {
        let out: Vec<usize> = select_top_by_cvss(0, Some(5), no_numeric_score, low);
        assert!(out.is_empty());
    }

    #[test]
    fn every_item_missing_a_numeric_score_bands_them_all_the_same_way() {
        let out = select_top_by_cvss(3, Some(3), no_numeric_score, low);
        assert_eq!(out, vec![0, 1, 2]);
    }

    #[test]
    fn parse_top_spec_accepts_a_positive_integer() {
        assert_eq!(parse_top_spec("5", "--top"), Ok(TopSpec::N(5)));
    }

    #[test]
    fn parse_top_spec_accepts_all_and_the_star_wildcard_case_insensitively() {
        assert_eq!(parse_top_spec("ALL", "--top"), Ok(TopSpec::All));
        assert_eq!(parse_top_spec("*", "--top"), Ok(TopSpec::All));
    }

    #[test]
    fn parse_top_spec_trims_whitespace() {
        assert_eq!(parse_top_spec(" 5 ", "--top"), Ok(TopSpec::N(5)));
    }

    #[test]
    fn parse_top_spec_rejects_zero() {
        assert!(parse_top_spec("0", "--top").is_err());
    }

    #[test]
    fn parse_top_spec_rejects_a_negative_number() {
        assert!(parse_top_spec("-1", "--top").is_err());
    }

    #[test]
    fn parse_top_spec_rejects_garbage_and_names_the_source_in_the_error() {
        let err = parse_top_spec("banana", "--top").unwrap_err();
        assert!(err.contains("--top"));
        assert!(err.contains("banana"));
    }

    #[test]
    fn resolve_top_prefers_the_cli_value_over_the_config_default() {
        assert_eq!(
            resolve_top(Some(TopSpec::N(5)), Some(TopSpec::N(20))),
            Some(5)
        );
    }

    #[test]
    fn resolve_top_falls_back_to_the_config_default_when_cli_is_absent() {
        assert_eq!(resolve_top(None, Some(TopSpec::N(20))), Some(20));
    }

    #[test]
    fn resolve_top_is_uncapped_when_neither_source_is_set() {
        assert_eq!(resolve_top(None, None), None);
    }

    #[test]
    fn resolve_top_cli_all_overrides_a_numeric_config_default() {
        assert_eq!(resolve_top(Some(TopSpec::All), Some(TopSpec::N(20))), None);
    }

    #[test]
    fn resolve_top_config_all_is_uncapped() {
        assert_eq!(resolve_top(None, Some(TopSpec::All)), None);
    }
}
