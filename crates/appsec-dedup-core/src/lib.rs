use std::collections::{HashMap, HashSet};

pub trait DedupKey {
    fn file(&self) -> &str;
    fn vuln_class(&self) -> &str;
    fn line_start(&self) -> i64;
    fn line_end(&self) -> i64;
    fn cwe(&self) -> Option<&str>;
    fn source_ref(&self) -> Option<&str> {
        None
    }
    fn sink_ref(&self) -> Option<&str> {
        None
    }
}

pub type CanonicalOf = HashMap<usize, usize>;

pub fn cwe_number(raw: Option<&str>) -> Option<u32> {
    let token = raw?.trim();
    let digits = match token.get(..4) {
        Some(prefix) if prefix.eq_ignore_ascii_case("cwe-") => &token[4..],
        _ => token,
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

pub fn normalize_ref(raw: Option<&str>) -> Option<String> {
    let token = raw?.trim();
    if token.is_empty() {
        return None;
    }
    let mut normalized = token.replace('\\', "/");
    while let Some(rest) = normalized.strip_prefix("./") {
        normalized = rest.to_string();
    }
    if normalized.is_empty() {
        return None;
    }
    Some(normalized)
}

fn flow_identity<T: DedupKey>(item: &T) -> Option<(String, String)> {
    Some((
        normalize_ref(item.source_ref())?,
        normalize_ref(item.sink_ref())?,
    ))
}

fn sink_identity<T: DedupKey>(item: &T) -> Option<String> {
    normalize_ref(item.sink_ref())
}

pub fn collapse_trivial<T: DedupKey>(
    items: &[T],
    line_tolerance: i64,
    strict_cwe_classes: &HashSet<&str>,
    merge_same_sink: bool,
) -> CanonicalOf {
    let flows: Vec<Option<(String, String)>> = items.iter().map(flow_identity).collect();
    let sinks: Vec<Option<String>> = items.iter().map(sink_identity).collect();
    let mut canonical_of = CanonicalOf::new();
    for j in 0..items.len() {
        for i in 0..j {
            if canonical_of.contains_key(&i) {
                continue;
            }
            let a = &items[i];
            let b = &items[j];
            let same_flow = match (&flows[i], &flows[j]) {
                (Some(x), Some(y)) => x == y,
                _ => false,
            };
            let same_sink_ref =
                merge_same_sink && matches!((&sinks[i], &sinks[j]), (Some(x), Some(y)) if x == y);
            let same_file = a.file() == b.file();
            if !same_flow && !same_sink_ref && !same_file {
                continue;
            }
            let (ca, cb) = (cwe_number(a.cwe()), cwe_number(b.cwe()));
            let cwe_agrees = matches!((ca, cb), (Some(x), Some(y)) if x == y);
            let same_sink = same_sink_ref && cwe_agrees;
            let strict = strict_cwe_classes.contains(a.vuln_class())
                || strict_cwe_classes.contains(b.vuln_class());
            if strict {
                if !cwe_agrees {
                    continue;
                }
            } else if !cwe_agrees {
                if a.vuln_class() != b.vuln_class() {
                    continue;
                }
                if ca.is_some() && cb.is_some() {
                    continue;
                }
            }
            let close = (a.line_start() - b.line_start()).abs() <= line_tolerance;
            let overlap = a.line_start() <= b.line_end() && b.line_start() <= a.line_end();
            let colocated = same_file && (close || overlap);
            if same_flow || same_sink || colocated {
                canonical_of.insert(j, i);
                break;
            }
        }
    }
    canonical_of
}

pub fn collapse_same_range_cwes<T: DedupKey>(
    items: &[T],
    canonical_of: &mut CanonicalOf,
    strict_cwe_classes: &HashSet<&str>,
) -> Vec<(usize, usize)> {
    let mut merged = Vec::new();
    for j in 0..items.len() {
        if canonical_of.contains_key(&j) {
            continue;
        }
        for i in 0..j {
            if canonical_of.contains_key(&i) {
                continue;
            }
            let a = &items[i];
            let b = &items[j];
            if a.file() != b.file() {
                continue;
            }
            if a.line_start() < 1 || a.line_start() != b.line_start() {
                continue;
            }
            if a.line_end() != b.line_end() {
                continue;
            }
            if strict_cwe_classes.contains(a.vuln_class())
                || strict_cwe_classes.contains(b.vuln_class())
            {
                continue;
            }
            let (Some(ca), Some(cb)) = (cwe_number(a.cwe()), cwe_number(b.cwe())) else {
                continue;
            };
            if ca == cb {
                continue;
            }
            canonical_of.insert(j, i);
            merged.push((j, i));
            break;
        }
    }
    merged
}

pub fn root(canonical_of: &CanonicalOf, mut i: usize) -> usize {
    let mut seen = HashSet::new();
    while let Some(&parent) = canonical_of.get(&i) {
        if !seen.insert(i) {
            break;
        }
        i = parent;
    }
    i
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DupRelation {
    pub duplicate_idx: usize,
    pub canonical_idx: usize,
    pub same_site: bool,
}

pub fn resolve_relations<T: DedupKey>(items: &[T], canonical_of: &CanonicalOf) -> Vec<DupRelation> {
    let mut dup_indices: Vec<usize> = canonical_of.keys().copied().collect();
    dup_indices.sort_unstable();
    dup_indices
        .into_iter()
        .map(|j| {
            let parent = canonical_of[&j];
            let r = root(canonical_of, parent);
            let dj = &items[j];
            let rf = &items[r];
            let same_site = dj.file() == rf.file()
                && dj.line_start() <= rf.line_end()
                && rf.line_start() <= dj.line_end();
            DupRelation {
                duplicate_idx: j,
                canonical_idx: r,
                same_site,
            }
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Partition {
    pub kept_indices: Vec<usize>,
    pub new_index_of: HashMap<usize, usize>,
    pub dropped_indices: Vec<usize>,
}

pub fn partition(len: usize, canonical_of: &CanonicalOf) -> Partition {
    let mut kept_indices = Vec::new();
    let mut new_index_of = HashMap::new();
    let mut dropped_indices = Vec::new();
    for i in 0..len {
        if canonical_of.contains_key(&i) {
            dropped_indices.push(i);
        } else {
            new_index_of.insert(i, kept_indices.len());
            kept_indices.push(i);
        }
    }
    Partition {
        kept_indices,
        new_index_of,
        dropped_indices,
    }
}

pub fn ref_file_line(raw: Option<&str>) -> Option<(String, i64)> {
    let reference = normalize_ref(raw)?;
    let (file, line) = reference.rsplit_once(':')?;
    let line: i64 = line.trim().parse().ok()?;
    if line < 1 {
        return None;
    }
    Some((normalize_ref(Some(file))?, line))
}

fn cluster_sinks<T: DedupKey>(items: &[T], members: &[usize]) -> Vec<(String, i64)> {
    let mut sinks: Vec<(String, i64)> = Vec::new();
    for &m in members {
        if let Some(sink) = ref_file_line(items[m].sink_ref()) {
            if !sinks.contains(&sink) {
                sinks.push(sink);
            }
        }
    }
    sinks
}

fn anchor_rank<T: DedupKey>(item: &T, sinks: &[(String, i64)]) -> (u8, i64) {
    const UNSCOREABLE: (u8, i64) = (1, 0);
    if item.line_start() < 1 {
        return UNSCOREABLE;
    }
    let Some(file) = normalize_ref(Some(item.file())) else {
        return UNSCOREABLE;
    };
    let end = item.line_end().max(item.line_start());
    let mut nearest: Option<i64> = None;
    for (sink_file, sink_line) in sinks {
        if *sink_file != file {
            continue;
        }
        let distance = if *sink_line < item.line_start() {
            item.line_start() - *sink_line
        } else if *sink_line > end {
            *sink_line - end
        } else {
            0
        };
        nearest = Some(match nearest {
            Some(best) => best.min(distance),
            None => distance,
        });
    }
    match nearest {
        Some(distance) => (0, distance),
        None => UNSCOREABLE,
    }
}

fn clusters(len: usize, canonical_of: &CanonicalOf) -> Vec<Vec<usize>> {
    let mut slot_of: HashMap<usize, usize> = HashMap::new();
    let mut grouped: Vec<Vec<usize>> = Vec::new();
    for i in 0..len {
        let r = root(canonical_of, i);
        let slot = match slot_of.get(&r) {
            Some(&slot) => slot,
            None => {
                grouped.push(Vec::new());
                slot_of.insert(r, grouped.len() - 1);
                grouped.len() - 1
            }
        };
        grouped[slot].push(i);
    }
    grouped
}

pub fn representative_swaps<T: DedupKey>(
    items: &[T],
    canonical_of: &CanonicalOf,
) -> Vec<(usize, usize)> {
    let mut swaps = Vec::new();
    for members in clusters(items.len(), canonical_of) {
        if members.len() < 2 {
            continue;
        }
        let sinks = cluster_sinks(items, &members);
        let mut best = members[0];
        let mut best_rank = anchor_rank(&items[best], &sinks);
        for &m in &members[1..] {
            let rank = anchor_rank(&items[m], &sinks);
            if rank < best_rank {
                best = m;
                best_rank = rank;
            }
        }
        if best != members[0] {
            swaps.push((members[0], best));
        }
    }
    swaps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone)]
    struct Item {
        file: &'static str,
        vuln_class: &'static str,
        line_start: i64,
        line_end: i64,
        cwe: Option<&'static str>,
        source_ref: Option<&'static str>,
        sink_ref: Option<&'static str>,
    }

    impl Item {
        fn new(
            file: &'static str,
            vuln_class: &'static str,
            line_start: i64,
            line_end: i64,
        ) -> Self {
            Self {
                file,
                vuln_class,
                line_start,
                line_end,
                cwe: None,
                source_ref: None,
                sink_ref: None,
            }
        }

        fn with_cwe(mut self, cwe: &'static str) -> Self {
            self.cwe = Some(cwe);
            self
        }

        fn with_flow(mut self, source_ref: &'static str, sink_ref: &'static str) -> Self {
            self.source_ref = Some(source_ref);
            self.sink_ref = Some(sink_ref);
            self
        }

        fn with_sink(mut self, sink_ref: &'static str) -> Self {
            self.sink_ref = Some(sink_ref);
            self
        }
    }

    impl DedupKey for Item {
        fn file(&self) -> &str {
            self.file
        }
        fn vuln_class(&self) -> &str {
            self.vuln_class
        }
        fn line_start(&self) -> i64 {
            self.line_start
        }
        fn line_end(&self) -> i64 {
            self.line_end
        }
        fn cwe(&self) -> Option<&str> {
            self.cwe
        }
        fn source_ref(&self) -> Option<&str> {
            self.source_ref
        }
        fn sink_ref(&self) -> Option<&str> {
            self.sink_ref
        }
    }

    struct RefLessItem;

    impl DedupKey for RefLessItem {
        fn file(&self) -> &str {
            "a.rs"
        }
        fn vuln_class(&self) -> &str {
            "injection"
        }
        fn line_start(&self) -> i64 {
            1
        }
        fn line_end(&self) -> i64 {
            1
        }
        fn cwe(&self) -> Option<&str> {
            None
        }
    }

    fn no_strict_classes() -> HashSet<&'static str> {
        HashSet::new()
    }

    #[test]
    fn empty_and_single_item_produce_no_duplicates() {
        assert_eq!(
            collapse_trivial::<Item>(&[], 5, &no_strict_classes(), true),
            CanonicalOf::new()
        );
        let one = [Item::new("a.rs", "injection", 10, 10)];
        assert_eq!(
            collapse_trivial(&one, 5, &no_strict_classes(), true),
            CanonicalOf::new()
        );
    }

    #[test]
    fn different_file_or_class_never_collapses() {
        let items = [
            Item::new("a.rs", "injection", 10, 10),
            Item::new("b.rs", "injection", 10, 10),
            Item::new("a.rs", "xss", 10, 10),
        ];
        assert!(collapse_trivial(&items, 100, &no_strict_classes(), true).is_empty());
    }

    #[test]
    fn close_line_start_within_tolerance_collapses() {
        let items = [
            Item::new("a.rs", "injection", 10, 10),
            Item::new("a.rs", "injection", 12, 12),
        ];
        let c = collapse_trivial(&items, 3, &no_strict_classes(), true);
        assert_eq!(c.get(&1), Some(&0));
    }

    #[test]
    fn line_start_beyond_tolerance_does_not_collapse() {
        let items = [
            Item::new("a.rs", "injection", 10, 10),
            Item::new("a.rs", "injection", 20, 20),
        ];
        assert!(collapse_trivial(&items, 3, &no_strict_classes(), true).is_empty());
    }

    #[test]
    fn overlapping_ranges_collapse_even_beyond_line_start_tolerance() {
        let items = [
            Item::new("a.rs", "injection", 10, 30),
            Item::new("a.rs", "injection", 25, 40),
        ];
        let c = collapse_trivial(&items, 3, &no_strict_classes(), true);
        assert_eq!(c.get(&1), Some(&0));
    }

    #[test]
    fn non_strict_class_an_explicit_cwe_mismatch_blocks_the_collapse() {
        let items = [
            Item::new("a.rs", "injection", 10, 10).with_cwe("CWE-89"),
            Item::new("a.rs", "injection", 11, 11).with_cwe("CWE-90"),
        ];
        assert!(collapse_trivial(&items, 3, &no_strict_classes(), true).is_empty());
    }

    #[test]
    fn non_strict_class_an_explicit_cwe_match_still_collapses() {
        let items = [
            Item::new("a.rs", "injection", 10, 10).with_cwe("CWE-89"),
            Item::new("a.rs", "injection", 11, 11).with_cwe("CWE-89"),
        ];
        let c = collapse_trivial(&items, 3, &no_strict_classes(), true);
        assert_eq!(c.get(&1), Some(&0));
    }

    #[test]
    fn non_strict_class_a_missing_cwe_on_either_side_does_not_block_the_collapse() {
        let items = [
            Item::new("a.rs", "injection", 10, 10).with_cwe("CWE-89"),
            Item::new("a.rs", "injection", 11, 11),
            Item::new("a.rs", "injection", 12, 12).with_cwe("CWE-89"),
        ];
        let c = collapse_trivial(&items, 3, &no_strict_classes(), true);
        assert_eq!(c.get(&1), Some(&0));
    }

    #[test]
    fn strict_class_requires_an_explicit_equal_cwe_on_both_sides() {
        let strict: HashSet<&str> = HashSet::from(["logic-flaw"]);
        let items = [
            Item::new("a.rs", "logic-flaw", 10, 10).with_cwe("CWE-840"),
            Item::new("a.rs", "logic-flaw", 11, 11).with_cwe("CWE-840"),
        ];
        let c = collapse_trivial(&items, 3, &strict, true);
        assert_eq!(c.get(&1), Some(&0));
    }

    #[test]
    fn strict_class_a_missing_cwe_on_either_side_blocks_the_collapse() {
        let strict: HashSet<&str> = HashSet::from(["logic-flaw"]);
        let items = [
            Item::new("a.rs", "logic-flaw", 10, 10).with_cwe("CWE-840"),
            Item::new("a.rs", "logic-flaw", 11, 11),
        ];
        assert!(collapse_trivial(&items, 3, &strict, true).is_empty());
    }

    #[test]
    fn strict_class_a_cwe_mismatch_blocks_the_collapse() {
        let strict: HashSet<&str> = HashSet::from(["logic-flaw"]);
        let items = [
            Item::new("a.rs", "logic-flaw", 10, 10).with_cwe("CWE-840"),
            Item::new("a.rs", "logic-flaw", 11, 11).with_cwe("CWE-841"),
        ];
        assert!(collapse_trivial(&items, 3, &strict, true).is_empty());
    }

    #[test]
    fn an_already_collapsed_item_cannot_be_matched_against() {
        let items = [
            Item::new("a.rs", "injection", 10, 10),
            Item::new("a.rs", "injection", 12, 12),
            Item::new("a.rs", "injection", 14, 14),
        ];
        let c = collapse_trivial(&items, 2, &no_strict_classes(), true);
        assert_eq!(c.get(&1), Some(&0));
        assert_eq!(c.get(&2), None);
    }

    #[test]
    fn generous_tolerance_collapses_all_directly_onto_the_first() {
        let items = [
            Item::new("a.rs", "injection", 10, 10),
            Item::new("a.rs", "injection", 12, 12),
            Item::new("a.rs", "injection", 14, 14),
        ];
        let c = collapse_trivial(&items, 4, &no_strict_classes(), true);
        assert_eq!(c.get(&1), Some(&0));
        assert_eq!(c.get(&2), Some(&0));
    }

    #[test]
    fn root_resolves_a_two_level_chain() {
        let mut c = CanonicalOf::new();
        c.insert(2, 1);
        c.insert(1, 0);
        assert_eq!(root(&c, 2), 0);
        assert_eq!(root(&c, 1), 0);
        assert_eq!(root(&c, 0), 0);
    }

    #[test]
    fn root_cycle_guard_terminates_on_a_malformed_map() {
        let mut c = CanonicalOf::new();
        c.insert(0, 1);
        c.insert(1, 0);
        let r = root(&c, 0);
        assert!(r == 0 || r == 1);
    }

    #[test]
    fn resolve_relations_reports_same_site_for_overlapping_ranges() {
        let items = [
            Item::new("a.rs", "injection", 10, 30),
            Item::new("a.rs", "injection", 25, 40),
        ];
        let c = collapse_trivial(&items, 3, &no_strict_classes(), true);
        let rels = resolve_relations(&items, &c);
        assert_eq!(
            rels,
            vec![DupRelation {
                duplicate_idx: 1,
                canonical_idx: 0,
                same_site: true,
            }]
        );
    }

    #[test]
    fn resolve_relations_reports_not_same_site_for_disjoint_ranges_within_tolerance() {
        let items = [
            Item::new("a.rs", "injection", 10, 10),
            Item::new("a.rs", "injection", 12, 12),
        ];
        let c = collapse_trivial(&items, 3, &no_strict_classes(), true);
        let rels = resolve_relations(&items, &c);
        assert_eq!(
            rels,
            vec![DupRelation {
                duplicate_idx: 1,
                canonical_idx: 0,
                same_site: false,
            }]
        );
    }

    #[test]
    fn resolve_relations_resolves_through_a_chain_added_by_the_caller() {
        let items = [
            Item::new("a.rs", "injection", 10, 10),
            Item::new("b.rs", "injection", 50, 50),
            Item::new("c.rs", "injection", 90, 90),
        ];
        let mut c = CanonicalOf::new();
        c.insert(1, 0);
        c.insert(2, 1);
        let rels = resolve_relations(&items, &c);
        assert_eq!(rels.len(), 2);
        assert_eq!(rels[0].duplicate_idx, 1);
        assert_eq!(rels[0].canonical_idx, 0);
        assert_eq!(rels[1].duplicate_idx, 2);
        assert_eq!(rels[1].canonical_idx, 0);
    }

    #[test]
    fn partition_splits_kept_and_dropped_preserving_order_and_remaps_indices() {
        let mut c = CanonicalOf::new();
        c.insert(2, 0);
        c.insert(4, 1);
        let p = partition(5, &c);
        assert_eq!(p.kept_indices, vec![0, 1, 3]);
        assert_eq!(p.dropped_indices, vec![2, 4]);
        assert_eq!(p.new_index_of.get(&0), Some(&0));
        assert_eq!(p.new_index_of.get(&1), Some(&1));
        assert_eq!(p.new_index_of.get(&3), Some(&2));
        assert_eq!(p.new_index_of.len(), 3);
    }

    #[test]
    fn partition_of_zero_length_is_empty() {
        let p = partition(0, &CanonicalOf::new());
        assert_eq!(p.kept_indices, Vec::<usize>::new());
        assert_eq!(p.dropped_indices, Vec::<usize>::new());
        assert!(p.new_index_of.is_empty());
    }

    #[test]
    fn partition_with_no_duplicates_keeps_everything_in_order() {
        let p = partition(3, &CanonicalOf::new());
        assert_eq!(p.kept_indices, vec![0, 1, 2]);
        assert!(p.dropped_indices.is_empty());
    }

    #[test]
    fn end_to_end_three_near_identical_findings_collapse_to_one() {
        let items = [
            Item::new("auth.rs", "sqli", 100, 100),
            Item::new("auth.rs", "sqli", 102, 102),
            Item::new("auth.rs", "sqli", 104, 104),
            Item::new("other.rs", "sqli", 5, 5),
        ];
        let c = collapse_trivial(&items, 4, &no_strict_classes(), true);
        let p = partition(items.len(), &c);
        assert_eq!(p.kept_indices, vec![0, 3]);
        assert_eq!(p.dropped_indices, vec![1, 2]);
        let rels = resolve_relations(&items, &c);
        assert!(rels.iter().all(|r| r.canonical_idx == 0));
    }

    #[test]
    fn cwe_number_normalizes_case_prefix_and_zero_padding() {
        assert_eq!(cwe_number(Some("CWE-89")), Some(89));
        assert_eq!(cwe_number(Some("cwe-89")), Some(89));
        assert_eq!(cwe_number(Some("CWE-0089")), Some(89));
        assert_eq!(cwe_number(Some("  CWE-89  ")), Some(89));
        assert_eq!(cwe_number(Some("89")), Some(89));
    }

    #[test]
    fn cwe_number_rejects_anything_that_is_not_a_plain_number() {
        for raw in [
            None,
            Some(""),
            Some("CWE-"),
            Some("CWE-injection"),
            Some("CWE-89a"),
            Some("Ω"),
            Some("CWE-99999999999"),
        ] {
            assert_eq!(cwe_number(raw), None, "expected None for {raw:?}");
        }
    }

    #[test]
    fn same_cwe_collapses_across_disagreeing_class_labels() {
        let items = [
            Item::new("app.py", "other", 14, 22).with_cwe("CWE-89"),
            Item::new("app.py", "injection", 17, 21).with_cwe("CWE-89"),
            Item::new("app.py", "race-condition", 25, 29).with_cwe("CWE-22"),
            Item::new("app.py", "other", 32, 37).with_cwe("CWE-78"),
            Item::new("app.py", "injection", 36, 36).with_cwe("CWE-78"),
        ];
        let c = collapse_trivial(&items, 2, &no_strict_classes(), true);
        assert_eq!(c.get(&1), Some(&0), "the SQLi pair collapses");
        assert_eq!(c.get(&4), Some(&3), "the command-injection pair collapses");
        let p = partition(items.len(), &c);
        assert_eq!(p.kept_indices, vec![0, 2, 3], "5 findings become 3");
        assert_eq!(p.dropped_indices, vec![1, 4]);
    }

    #[test]
    fn zero_padded_and_lower_case_cwe_spellings_still_collapse() {
        let items = [
            Item::new("a.py", "other", 10, 12).with_cwe("CWE-89"),
            Item::new("a.py", "injection", 11, 13).with_cwe("cwe-0089"),
        ];
        assert_eq!(
            collapse_trivial(&items, 2, &no_strict_classes(), true).get(&1),
            Some(&0)
        );
    }

    #[test]
    fn differing_classes_without_an_agreeing_cwe_still_do_not_collapse() {
        let items = [
            Item::new("a.py", "other", 10, 12).with_cwe("CWE-89"),
            Item::new("a.py", "injection", 11, 13),
        ];
        assert!(collapse_trivial(&items, 2, &no_strict_classes(), true).is_empty());
    }

    #[test]
    fn same_class_but_conflicting_explicit_cwes_still_do_not_collapse() {
        let items = [
            Item::new("a.py", "injection", 10, 12).with_cwe("CWE-89"),
            Item::new("a.py", "injection", 11, 13).with_cwe("CWE-78"),
        ];
        assert!(collapse_trivial(&items, 2, &no_strict_classes(), true).is_empty());
    }

    #[test]
    fn an_unparseable_cwe_is_treated_as_absent_not_as_a_match() {
        let items = [
            Item::new("a.py", "other", 10, 12).with_cwe("CWE-unknown"),
            Item::new("a.py", "injection", 11, 13).with_cwe("CWE-unknown"),
        ];
        assert!(collapse_trivial(&items, 2, &no_strict_classes(), true).is_empty());
    }

    #[test]
    fn the_default_source_and_sink_refs_are_absent() {
        assert_eq!(RefLessItem.source_ref(), None);
        assert_eq!(RefLessItem.sink_ref(), None);
        let items = [RefLessItem, RefLessItem];
        assert_eq!(
            collapse_trivial(&items, 0, &no_strict_classes(), true).get(&1),
            Some(&0)
        );
    }

    #[test]
    fn one_flow_reported_from_both_ends_collapses_across_anchor_files() {
        let items = [
            Item::new("handlers.py", "injection", 37, 39)
                .with_cwe("CWE-78")
                .with_flow("handlers.py:38", "shell.py:6"),
            Item::new("shell.py", "injection", 5, 6)
                .with_cwe("CWE-78")
                .with_flow("handlers.py:38", "shell.py:6"),
        ];
        let c = collapse_trivial(&items, 3, &no_strict_classes(), true);
        assert_eq!(c.get(&1), Some(&0));
        let p = partition(items.len(), &c);
        assert_eq!(p.kept_indices, vec![0]);
    }

    #[test]
    fn a_shared_sink_under_one_cwe_is_one_finding_even_with_the_source_missing() {
        let mut b = Item::new("shell.py", "injection", 5, 6).with_cwe("CWE-78");
        b.sink_ref = Some("shell.py:6");
        let items = [
            Item::new("handlers.py", "injection", 37, 39)
                .with_cwe("CWE-78")
                .with_flow("handlers.py:38", "shell.py:6"),
            b,
        ];
        let c = collapse_trivial(&items, 3, &no_strict_classes(), true);
        assert_eq!(c.get(&1), Some(&0));
        assert!(collapse_trivial(&items, 3, &no_strict_classes(), false).is_empty());
    }

    #[test]
    fn a_differing_sink_is_never_the_same_flow_and_a_shared_sink_needs_the_cwe() {
        let items = [
            Item::new("handlers.py", "injection", 37, 39)
                .with_cwe("CWE-78")
                .with_flow("handlers.py:38", "shell.py:6"),
            Item::new("other.py", "injection", 5, 6)
                .with_cwe("CWE-78")
                .with_flow("other.py:2", "shell.py:6"),
            Item::new("elsewhere.py", "injection", 5, 6)
                .with_cwe("CWE-78")
                .with_flow("handlers.py:38", "eval.py:9"),
            Item::new("another.py", "injection", 5, 6)
                .with_cwe("CWE-77")
                .with_flow("another.py:2", "shell.py:6"),
        ];
        let c = collapse_trivial(&items, 3, &no_strict_classes(), true);
        assert_eq!(c.get(&1), Some(&0));
        assert!(!c.contains_key(&2));
        assert!(!c.contains_key(&3));
        assert!(collapse_trivial(&items, 3, &no_strict_classes(), false).is_empty());
    }

    #[test]
    fn flow_identity_still_honors_the_cwe_and_class_guards() {
        let items = [
            Item::new("handlers.py", "injection", 37, 39)
                .with_cwe("CWE-78")
                .with_flow("handlers.py:38", "shell.py:6"),
            Item::new("shell.py", "injection", 5, 6)
                .with_cwe("CWE-77")
                .with_flow("handlers.py:38", "shell.py:6"),
        ];
        assert!(collapse_trivial(&items, 3, &no_strict_classes(), true).is_empty());

        let strict = HashSet::from(["logic-flaw"]);
        let items = [
            Item::new("handlers.py", "logic-flaw", 37, 39).with_flow("h.py:38", "s.py:6"),
            Item::new("shell.py", "logic-flaw", 5, 6).with_flow("h.py:38", "s.py:6"),
        ];
        assert!(collapse_trivial(&items, 3, &strict, true).is_empty());
    }

    #[test]
    fn refs_are_normalized_before_they_are_compared() {
        let items = [
            Item::new("handlers.py", "injection", 37, 39)
                .with_cwe("CWE-78")
                .with_flow("handlers.py:38", "lib/shell.py:6"),
            Item::new("shell.py", "injection", 5, 6)
                .with_cwe("CWE-78")
                .with_flow("  ./handlers.py:38 ", "lib\\shell.py:6"),
        ];
        assert_eq!(
            collapse_trivial(&items, 3, &no_strict_classes(), true).get(&1),
            Some(&0)
        );
    }

    #[test]
    fn normalize_ref_strips_whitespace_dot_slash_and_backslashes() {
        assert_eq!(normalize_ref(Some("a.py:1")).as_deref(), Some("a.py:1"));
        assert_eq!(normalize_ref(Some("  a.py:1 ")).as_deref(), Some("a.py:1"));
        assert_eq!(normalize_ref(Some("./a.py:1")).as_deref(), Some("a.py:1"));
        assert_eq!(normalize_ref(Some("././a.py:1")).as_deref(), Some("a.py:1"));
        assert_eq!(
            normalize_ref(Some("../a.py:1")).as_deref(),
            Some("../a.py:1")
        );
        assert_eq!(
            normalize_ref(Some("lib\\a.py:1")).as_deref(),
            Some("lib/a.py:1")
        );
        assert_eq!(
            normalize_ref(Some(".\\./a.py:1")).as_deref(),
            Some("a.py:1")
        );
        assert_eq!(normalize_ref(None), None);
        assert_eq!(normalize_ref(Some("")), None);
        assert_eq!(normalize_ref(Some("   ")), None);
        assert_eq!(normalize_ref(Some("./")), None);
        assert_eq!(
            normalize_ref(Some("Auth.ts:6")).as_deref(),
            Some("Auth.ts:6")
        );
    }

    #[test]
    fn flow_identity_is_none_unless_both_refs_survive_normalization() {
        assert_eq!(
            flow_identity(&Item::new("a", "b", 1, 1).with_flow("s.py:1", "k.py:2")),
            Some(("s.py:1".to_string(), "k.py:2".to_string()))
        );
        let mut blank = Item::new("a", "b", 1, 1).with_flow("  ", "k.py:2");
        assert_eq!(flow_identity(&blank), None);
        blank.source_ref = Some("s.py:1");
        blank.sink_ref = Some("");
        assert_eq!(flow_identity(&blank), None);
        assert_eq!(flow_identity(&Item::new("a", "b", 1, 1)), None);
    }

    #[test]
    fn one_range_reported_under_several_cwes_merges_into_one() {
        let items = [
            Item::new("routes/continueCode.ts", "other", 13, 13).with_cwe("CWE-798"),
            Item::new("routes/continueCode.ts", "other", 12, 21).with_cwe("CWE-345"),
            Item::new("routes/continueCode.ts", "logic-flaw", 12, 21).with_cwe("CWE-284"),
            Item::new("routes/continueCode.ts", "info-leak", 12, 21).with_cwe("CWE-200"),
        ];
        let strict = no_strict_classes();
        let mut canonical_of = collapse_trivial(&items, 3, &strict, true);
        assert!(canonical_of.is_empty());
        let merged = collapse_same_range_cwes(&items, &mut canonical_of, &strict);
        assert_eq!(merged, vec![(2, 1), (3, 1)]);
        let p = partition(items.len(), &canonical_of);
        assert_eq!(p.kept_indices, vec![0, 1], "4 findings become 2");
    }

    #[test]
    fn same_range_merge_needs_an_exact_range_match_not_a_tolerance() {
        let items = [
            Item::new("a.ts", "other", 12, 21).with_cwe("CWE-345"),
            Item::new("a.ts", "other", 12, 22).with_cwe("CWE-284"),
            Item::new("a.ts", "other", 13, 21).with_cwe("CWE-200"),
        ];
        let mut canonical_of = CanonicalOf::new();
        assert!(
            collapse_same_range_cwes(&items, &mut canonical_of, &no_strict_classes()).is_empty()
        );
    }

    #[test]
    fn same_range_merge_needs_two_explicit_and_different_cwes() {
        let strict = no_strict_classes();
        let equal = [
            Item::new("a.ts", "other", 12, 21).with_cwe("CWE-345"),
            Item::new("a.ts", "injection", 12, 21).with_cwe("cwe-0345"),
        ];
        let mut c = CanonicalOf::new();
        assert!(collapse_same_range_cwes(&equal, &mut c, &strict).is_empty());
        let missing = [
            Item::new("a.ts", "other", 12, 21).with_cwe("CWE-345"),
            Item::new("a.ts", "injection", 12, 21),
        ];
        let mut c = CanonicalOf::new();
        assert!(collapse_same_range_cwes(&missing, &mut c, &strict).is_empty());
        let junk = [
            Item::new("a.ts", "other", 12, 21).with_cwe("CWE-345"),
            Item::new("a.ts", "injection", 12, 21).with_cwe("CWE-unknown"),
        ];
        let mut c = CanonicalOf::new();
        assert!(collapse_same_range_cwes(&junk, &mut c, &strict).is_empty());
    }

    #[test]
    fn same_range_merge_respects_the_file_the_strict_guard_and_unlocated_findings() {
        let strict: HashSet<&str> = HashSet::from(["logic-flaw"]);
        let other_file = [
            Item::new("a.ts", "other", 12, 21).with_cwe("CWE-345"),
            Item::new("b.ts", "other", 12, 21).with_cwe("CWE-284"),
        ];
        let mut c = CanonicalOf::new();
        assert!(collapse_same_range_cwes(&other_file, &mut c, &strict).is_empty());
        let logic = [
            Item::new("a.ts", "logic-flaw", 12, 21).with_cwe("CWE-345"),
            Item::new("a.ts", "other", 12, 21).with_cwe("CWE-284"),
        ];
        let mut c = CanonicalOf::new();
        assert!(collapse_same_range_cwes(&logic, &mut c, &strict).is_empty());
        let logic_second = [
            Item::new("a.ts", "other", 12, 21).with_cwe("CWE-345"),
            Item::new("a.ts", "logic-flaw", 12, 21).with_cwe("CWE-284"),
        ];
        let mut c = CanonicalOf::new();
        assert!(collapse_same_range_cwes(&logic_second, &mut c, &strict).is_empty());
        let unlocated = [
            Item::new("a.ts", "other", 0, 0).with_cwe("CWE-345"),
            Item::new("a.ts", "other", 0, 0).with_cwe("CWE-284"),
        ];
        let mut c = CanonicalOf::new();
        assert!(collapse_same_range_cwes(&unlocated, &mut c, &strict).is_empty());
    }

    #[test]
    fn same_range_merge_skips_indices_already_resolved_by_the_first_pass() {
        let items = [
            Item::new("a.ts", "other", 12, 21).with_cwe("CWE-345"),
            Item::new("a.ts", "other", 12, 21),
            Item::new("a.ts", "info-leak", 12, 21).with_cwe("CWE-200"),
        ];
        let strict = no_strict_classes();
        let mut canonical_of = collapse_trivial(&items, 3, &strict, true);
        assert_eq!(canonical_of.get(&1), Some(&0));
        let merged = collapse_same_range_cwes(&items, &mut canonical_of, &strict);
        assert_eq!(merged, vec![(2, 0)]);
        assert_eq!(canonical_of.get(&2), Some(&0));
    }

    #[test]
    fn same_range_merge_never_makes_an_already_resolved_duplicate_a_canonical() {
        let items = [
            Item::new("a.ts", "other", 30, 31).with_cwe("CWE-345"),
            Item::new("a.ts", "other", 30, 40),
            Item::new("a.ts", "other", 30, 40).with_cwe("CWE-200"),
        ];
        let strict = no_strict_classes();
        let mut canonical_of = collapse_trivial(&items, 2, &strict, true);
        assert_eq!(canonical_of.get(&1), Some(&0));
        assert_eq!(canonical_of.get(&2), None);
        assert!(collapse_same_range_cwes(&items, &mut canonical_of, &strict).is_empty());
        assert_eq!(canonical_of.get(&2), None, "2 stays its own canonical");
    }

    #[test]
    fn same_range_merge_on_an_empty_or_single_item_list_does_nothing() {
        let mut c = CanonicalOf::new();
        assert!(collapse_same_range_cwes::<Item>(&[], &mut c, &no_strict_classes()).is_empty());
        let one = [Item::new("a.ts", "other", 1, 2).with_cwe("CWE-1")];
        assert!(collapse_same_range_cwes(&one, &mut c, &no_strict_classes()).is_empty());
        assert!(c.is_empty());
    }

    #[test]
    fn the_strict_class_guard_applies_to_either_side_of_the_pair() {
        let strict = HashSet::from(["logic-flaw"]);
        let items = [
            Item::new("a.py", "other", 10, 12),
            Item::new("a.py", "logic-flaw", 11, 13),
        ];
        assert!(collapse_trivial(&items, 2, &strict, true).is_empty());
        let items = [
            Item::new("a.py", "other", 10, 12).with_cwe("CWE-20"),
            Item::new("a.py", "logic-flaw", 11, 13).with_cwe("CWE-20"),
        ];
        assert_eq!(collapse_trivial(&items, 2, &strict, true).get(&1), Some(&0));
    }

    #[test]
    fn ref_file_line_splits_a_reference_into_a_normalized_path_and_a_line() {
        assert_eq!(
            ref_file_line(Some(" ./src\\report.c:61 ")),
            Some(("src/report.c".to_string(), 61))
        );
        assert_eq!(
            ref_file_line(Some("C:/src/report.c:61")),
            Some(("C:/src/report.c".to_string(), 61))
        );
    }

    #[test]
    fn ref_file_line_is_none_without_a_usable_path_and_positive_line() {
        assert_eq!(ref_file_line(None), None);
        assert_eq!(ref_file_line(Some("  ")), None);
        assert_eq!(ref_file_line(Some("report.c")), None);
        assert_eq!(ref_file_line(Some("report.c:sixty")), None);
        assert_eq!(ref_file_line(Some("report.c:")), None);
        assert_eq!(ref_file_line(Some("report.c:0")), None);
        assert_eq!(ref_file_line(Some("report.c:-3")), None);
        assert_eq!(ref_file_line(Some(":61")), None);
    }

    fn pair_swaps(a: Item, b: Item) -> Vec<(usize, usize)> {
        representative_swaps(&[a, b], &CanonicalOf::from([(1, 0)]))
    }

    #[test]
    fn the_member_sitting_on_the_clusters_sink_becomes_the_survivor() {
        let swaps = pair_swaps(
            Item::new("main.c", "format-string", 35, 39)
                .with_cwe("CWE-134")
                .with_flow("main.c:37", "report.c:61"),
            Item::new("report.c", "format-string", 59, 63)
                .with_cwe("CWE-134")
                .with_sink("report.c:61"),
        );
        assert_eq!(swaps, [(0, 1)]);
    }

    #[test]
    fn a_member_already_on_the_sink_is_left_where_it_is() {
        let swaps = pair_swaps(
            Item::new("report.c", "format-string", 59, 63).with_sink("report.c:61"),
            Item::new("main.c", "format-string", 35, 39).with_flow("main.c:37", "report.c:61"),
        );
        assert!(swaps.is_empty());
    }

    #[test]
    fn distance_to_the_sink_decides_between_two_members_in_its_own_file() {
        let swaps = pair_swaps(
            Item::new("report.c", "format-string", 80, 90).with_sink("report.c:61"),
            Item::new("report.c", "format-string", 55, 58).with_sink("report.c:61"),
        );
        assert_eq!(swaps, [(0, 1)]);
    }

    #[test]
    fn a_member_with_no_sink_of_its_own_is_scored_against_the_clusters() {
        let swaps = pair_swaps(
            Item::new("replay.c", "use-after-free", 40, 44).with_sink("replay.c:46"),
            Item::new("replay.c", "use-after-free", 45, 47),
        );
        assert_eq!(swaps, [(0, 1)]);
    }

    #[test]
    fn a_cluster_that_names_no_sink_is_left_exactly_as_clustering_left_it() {
        let swaps = pair_swaps(
            Item::new("a.py", "injection", 40, 44),
            Item::new("a.py", "injection", 41, 45),
        );
        assert!(swaps.is_empty());
    }

    #[test]
    fn an_unlocated_member_never_wins_however_close_its_lines_look() {
        let swaps = pair_swaps(
            Item::new("report.c", "format-string", 59, 63).with_sink("report.c:61"),
            Item::new("report.c", "format-string", 0, 70).with_sink("report.c:61"),
        );
        assert!(swaps.is_empty());
    }

    #[test]
    fn a_member_with_no_file_is_unscoreable() {
        let swaps = pair_swaps(
            Item::new("report.c", "format-string", 59, 63).with_sink("report.c:61"),
            Item::new("  ", "format-string", 60, 62).with_sink("report.c:61"),
        );
        assert!(swaps.is_empty());
    }

    #[test]
    fn an_unknown_line_end_is_read_as_the_single_start_line() {
        let swaps = pair_swaps(
            Item::new("report.c", "format-string", 50, 55).with_sink("report.c:61"),
            Item::new("report.c", "format-string", 61, 0).with_sink("report.c:61"),
        );
        assert_eq!(swaps, [(0, 1)]);
    }

    #[test]
    fn a_sink_in_another_file_cannot_score_a_member() {
        let swaps = pair_swaps(
            Item::new("a.py", "injection", 10, 12).with_sink("elsewhere.py:900"),
            Item::new("a.py", "injection", 11, 13).with_sink("elsewhere.py:900"),
        );
        assert!(swaps.is_empty());
    }

    #[test]
    fn the_nearest_of_several_sinks_the_cluster_names_is_the_one_scored() {
        let swaps = representative_swaps(
            &[
                Item::new("report.c", "injection", 50, 55).with_sink("report.c:58"),
                Item::new("report.c", "injection", 60, 69).with_sink("report.c:70"),
            ],
            &CanonicalOf::from([(1, 0)]),
        );
        assert_eq!(swaps, [(0, 1)]);
    }

    #[test]
    fn duplicate_sinks_across_members_are_pooled_once() {
        let items = [
            Item::new("report.c", "injection", 10, 12).with_sink("./report.c:61"),
            Item::new("report.c", "injection", 11, 13).with_sink("report.c:61"),
        ];
        assert_eq!(
            cluster_sinks(&items, &[0, 1]),
            [("report.c".to_string(), 61)]
        );
    }

    #[test]
    fn a_chained_cluster_is_grouped_under_its_root_and_repicked_once() {
        let items = [
            Item::new("report.c", "injection", 10, 12).with_sink("report.c:61"),
            Item::new("report.c", "injection", 30, 32).with_sink("report.c:61"),
            Item::new("report.c", "injection", 60, 62).with_sink("report.c:61"),
        ];
        let canonical_of = CanonicalOf::from([(1, 0), (2, 1)]);
        assert_eq!(clusters(items.len(), &canonical_of), [vec![0, 1, 2]]);
        assert_eq!(representative_swaps(&items, &canonical_of), [(0, 2)]);
    }

    #[test]
    fn singleton_clusters_and_an_empty_input_produce_no_swaps() {
        let items = [
            Item::new("a.py", "injection", 10, 12).with_sink("a.py:11"),
            Item::new("b.py", "injection", 90, 92).with_sink("b.py:200"),
        ];
        assert_eq!(
            clusters(items.len(), &CanonicalOf::new()),
            [vec![0], vec![1]]
        );
        assert!(representative_swaps(&items, &CanonicalOf::new()).is_empty());
        let empty: [Item; 0] = [];
        assert!(representative_swaps(&empty, &CanonicalOf::new()).is_empty());
    }

    #[test]
    fn swaps_are_emitted_in_ascending_root_order_for_several_clusters() {
        let items = [
            Item::new("a.c", "injection", 10, 12).with_sink("a.c:61"),
            Item::new("a.c", "injection", 60, 62).with_sink("a.c:61"),
            Item::new("b.c", "injection", 10, 12).with_sink("b.c:61"),
            Item::new("b.c", "injection", 60, 62).with_sink("b.c:61"),
        ];
        let canonical_of = CanonicalOf::from([(1, 0), (3, 2)]);
        for _ in 0..8 {
            assert_eq!(
                representative_swaps(&items, &canonical_of),
                [(0, 1), (2, 3)]
            );
        }
    }

    #[test]
    fn repicking_the_representative_cannot_change_how_many_findings_survive() {
        let items = [
            Item::new("main.c", "format-string", 35, 39).with_flow("main.c:37", "report.c:61"),
            Item::new("report.c", "format-string", 59, 63).with_sink("report.c:61"),
            Item::new("other.c", "injection", 5, 6),
        ];
        let canonical_of = CanonicalOf::from([(1, 0)]);
        let before = partition(items.len(), &canonical_of);
        let swaps = representative_swaps(&items, &canonical_of);
        assert_eq!(swaps, [(0, 1)]);
        assert_eq!(partition(items.len(), &canonical_of), before);
        assert_eq!(before.kept_indices, [0, 2]);
    }
}
