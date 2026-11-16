use std::collections::{HashMap, HashSet};

use appsec_model::Finding;

fn cwe_number(raw: Option<&str>) -> Option<u32> {
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

fn same_bug(a: &Finding, b: &Finding, line_tolerance: i64) -> bool {
    if a.file != b.file {
        return false;
    }
    let (ca, cb) = (cwe_number(a.cwe.as_deref()), cwe_number(b.cwe.as_deref()));
    let cwe_agrees = matches!((ca, cb), (Some(x), Some(y)) if x == y);
    if !cwe_agrees {
        if a.vuln_class != b.vuln_class {
            return false;
        }
        if ca.is_some() && cb.is_some() {
            return false;
        }
    }
    let close = (a.line_start - b.line_start).abs() <= line_tolerance;
    let overlap = a.line_start <= b.line_end && b.line_start <= a.line_end;
    close || overlap
}

fn cluster_roots(items: &[&Finding], line_tolerance: i64) -> Vec<usize> {
    let mut roots: Vec<usize> = (0..items.len()).collect();
    for j in 0..items.len() {
        for i in 0..j {
            if roots[i] != i {
                continue;
            }
            if same_bug(items[i], items[j], line_tolerance) {
                roots[j] = i;
                break;
            }
        }
    }
    roots
}

pub fn vote_within_chunk(
    runs: &[Vec<Finding>],
    line_bucket: i64,
    threshold: usize,
) -> Vec<Finding> {
    let flat: Vec<(usize, &Finding)> = runs
        .iter()
        .enumerate()
        .flat_map(|(run_idx, findings)| findings.iter().map(move |f| (run_idx, f)))
        .collect();
    let items: Vec<&Finding> = flat.iter().map(|(_, f)| *f).collect();
    let roots = cluster_roots(&items, line_bucket.max(0));

    let mut voters: HashMap<usize, HashSet<usize>> = HashMap::new();
    let mut best: HashMap<usize, &Finding> = HashMap::new();
    let mut order: Vec<usize> = Vec::new();

    for (k, (run_idx, f)) in flat.iter().enumerate() {
        let root = roots[k];
        if !voters.contains_key(&root) {
            order.push(root);
        }
        voters.entry(root).or_default().insert(*run_idx);
        let is_better = best
            .get(&root)
            .is_none_or(|prev| f.confidence > prev.confidence);
        if is_better {
            best.insert(root, f);
        }
    }

    order
        .into_iter()
        .filter_map(|root| {
            let n = voters[&root].len();
            if n < threshold {
                return None;
            }
            let mut f = best[&root].clone();
            f.votes = n as i64;
            Some(f)
        })
        .collect()
}

pub fn collapse_across_chunks(findings: Vec<Finding>, line_bucket: i64) -> Vec<Finding> {
    let items: Vec<&Finding> = findings.iter().collect();
    let roots = cluster_roots(&items, line_bucket.max(0));

    let mut best: HashMap<usize, usize> = HashMap::new();
    let mut order: Vec<usize> = Vec::new();

    for (k, f) in findings.iter().enumerate() {
        let root = roots[k];
        match best.get(&root) {
            None => {
                order.push(root);
                best.insert(root, k);
            }
            Some(&prev) if f.confidence > findings[prev].confidence => {
                best.insert(root, k);
            }
            Some(_) => {}
        }
    }

    order
        .into_iter()
        .map(|root| findings[best[&root]].clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use appsec_model::VulnClass;

    fn finding(file: &str, line_start: i64, vuln_class: VulnClass, confidence: f64) -> Finding {
        Finding {
            provider_origins: Vec::new(),
            component: None,
            chunk_id: "c".to_string(),
            file: file.to_string(),
            line_start,
            line_end: line_start,
            vuln_class,
            cwe: None,
            title: "t".to_string(),
            impact: String::new(),
            description: "d".to_string(),
            exploit_scenario: String::new(),
            preconditions: Vec::new(),
            recommendation: String::new(),
            code_snippet: "x".to_string(),
            source_ref: None,
            sink_ref: None,
            backfilled_refs: Vec::new(),
            reanchored: Vec::new(),
            compliance_requirements: Vec::new(),
            confidence,
            votes: 1,
            duplicates: Vec::new(),
            verdict: None,
            verdict_confidence: None,
            verdict_reason: String::new(),
            cvss_vector: None,
            cvss_score: None,
            cvss_rating: None,
            verifier_reasoning: String::new(),
            vsvs_vector: None,
            vsvs_score: None,
            vsvs_rating: None,
            offensive_priority: None,
            offensive_reason: String::new(),
            related_cwes: Vec::new(),
        }
    }

    #[test]
    fn a_finding_appearing_in_every_run_survives_with_full_vote_count() {
        let f = finding("a.py", 10, VulnClass::Injection, 0.8);
        let runs = vec![vec![f.clone()], vec![f.clone()], vec![f]];
        let survivors = vote_within_chunk(&runs, 10, 3);
        assert_eq!(survivors.len(), 1);
        assert_eq!(survivors[0].votes, 3);
    }

    #[test]
    fn a_finding_below_threshold_is_dropped() {
        let f = finding("a.py", 10, VulnClass::Injection, 0.8);
        let runs = vec![vec![f.clone()], vec![], vec![]];
        let survivors = vote_within_chunk(&runs, 10, 2);
        assert!(survivors.is_empty());
    }

    #[test]
    fn threshold_of_one_keeps_every_distinct_key() {
        let a = finding("a.py", 10, VulnClass::Injection, 0.8);
        let b = finding("b.py", 20, VulnClass::Other, 0.5);
        let runs = vec![vec![a, b]];
        let survivors = vote_within_chunk(&runs, 10, 1);
        assert_eq!(survivors.len(), 2);
    }

    #[test]
    fn lines_within_the_same_bucket_are_treated_as_the_same_finding() {
        let a = finding("a.py", 142, VulnClass::Injection, 0.7);
        let b = finding("a.py", 145, VulnClass::Injection, 0.9);
        let runs = vec![vec![a], vec![b]];
        let survivors = vote_within_chunk(&runs, 10, 2);
        assert_eq!(survivors.len(), 1);
        assert_eq!(survivors[0].confidence, 0.9);
        assert_eq!(survivors[0].votes, 2);
    }

    #[test]
    fn different_vuln_class_at_the_same_line_bucket_is_a_distinct_key() {
        let a = finding("a.py", 142, VulnClass::Injection, 0.7);
        let b = finding("a.py", 142, VulnClass::LogicFlaw, 0.7);
        let runs = vec![vec![a, b]];
        let survivors = vote_within_chunk(&runs, 10, 1);
        assert_eq!(survivors.len(), 2);
    }

    #[test]
    fn cwe_number_handles_every_token_shape() {
        assert_eq!(cwe_number(Some("CWE-89")), Some(89));
        assert_eq!(cwe_number(Some("cwe-0089")), Some(89));
        assert_eq!(cwe_number(Some("89")), Some(89));
        for raw in [None, Some(""), Some("CWE-"), Some("nope"), Some("\u{3a9}")] {
            assert_eq!(cwe_number(raw), None, "expected None for {raw:?}");
        }
    }

    fn with_cwe(mut f: Finding, cwe: &str) -> Finding {
        f.cwe = Some(cwe.to_string());
        f
    }

    #[test]
    fn a_relabeled_finding_still_votes_for_the_same_bug() {
        let a = with_cwe(finding("a.py", 142, VulnClass::Injection, 0.8), "CWE-89");
        let b = with_cwe(finding("a.py", 143, VulnClass::Other, 0.7), "cwe-0089");
        let runs = vec![vec![a], vec![b]];
        let survivors = vote_within_chunk(&runs, 10, 2);
        assert_eq!(survivors.len(), 1);
        assert_eq!(survivors[0].votes, 2);
        assert_eq!(survivors[0].vuln_class, VulnClass::Injection);
    }

    #[test]
    fn an_explicit_cwe_mismatch_keeps_two_same_class_findings_apart() {
        let a = with_cwe(finding("a.py", 142, VulnClass::Injection, 0.8), "CWE-89");
        let b = with_cwe(finding("a.py", 142, VulnClass::Injection, 0.7), "CWE-78");
        let runs = vec![vec![a, b]];
        assert_eq!(vote_within_chunk(&runs, 10, 1).len(), 2);
    }

    #[test]
    fn an_unparseable_cwe_falls_back_to_the_class_label() {
        let a = with_cwe(finding("a.py", 142, VulnClass::Injection, 0.8), "CWE-???");
        let b = with_cwe(finding("a.py", 142, VulnClass::Other, 0.7), "CWE-???");
        let runs = vec![vec![a, b]];
        assert_eq!(vote_within_chunk(&runs, 10, 1).len(), 2);
    }

    #[test]
    fn duplicate_findings_within_one_run_are_counted_only_once() {
        let a1 = finding("a.py", 10, VulnClass::Injection, 0.5);
        let a2 = finding("a.py", 11, VulnClass::Injection, 0.9);
        let runs = vec![vec![a1, a2]];
        let survivors = vote_within_chunk(&runs, 10, 1);
        assert_eq!(survivors.len(), 1);
        assert_eq!(survivors[0].votes, 1);
        assert_eq!(survivors[0].confidence, 0.9);
    }

    #[test]
    fn a_tie_in_confidence_keeps_the_first_seen_finding() {
        let mut a = finding("a.py", 10, VulnClass::Injection, 0.5);
        a.title = "first".to_string();
        let mut b = finding("a.py", 10, VulnClass::Injection, 0.5);
        b.title = "second".to_string();
        let runs = vec![vec![a], vec![b]];
        let survivors = vote_within_chunk(&runs, 10, 1);
        assert_eq!(survivors[0].title, "first");
    }

    #[test]
    fn empty_runs_produce_no_survivors() {
        let runs: Vec<Vec<Finding>> = vec![vec![], vec![], vec![]];
        assert!(vote_within_chunk(&runs, 10, 1).is_empty());
    }

    #[test]
    fn no_runs_at_all_produces_no_survivors() {
        assert!(vote_within_chunk(&[], 10, 1).is_empty());
    }

    #[test]
    fn survivor_order_matches_first_occurrence_across_runs() {
        let a = finding("a.py", 10, VulnClass::Injection, 0.9);
        let b = finding("b.py", 20, VulnClass::Other, 0.9);
        let runs = vec![vec![b, a]];
        let survivors = vote_within_chunk(&runs, 10, 1);
        assert_eq!(survivors[0].file, "b.py");
        assert_eq!(survivors[1].file, "a.py");
    }

    #[test]
    fn collapse_across_chunks_merges_the_same_bug_from_different_chunks() {
        let mut a = finding("a.py", 142, VulnClass::Injection, 0.6);
        a.chunk_id = "chunk-01".to_string();
        let mut b = finding("a.py", 145, VulnClass::Injection, 0.9);
        b.chunk_id = "spec-crypto-01".to_string();
        let collapsed = collapse_across_chunks(vec![a, b], 10);
        assert_eq!(collapsed.len(), 1);
        assert_eq!(collapsed[0].confidence, 0.9);
    }

    #[test]
    fn collapse_across_chunks_keeps_distinct_findings_separate() {
        let a = finding("a.py", 10, VulnClass::Injection, 0.6);
        let b = finding("b.py", 20, VulnClass::Other, 0.9);
        let collapsed = collapse_across_chunks(vec![a, b], 10);
        assert_eq!(collapsed.len(), 2);
    }

    #[test]
    fn collapse_across_chunks_preserves_the_winners_own_vote_count() {
        let mut a = finding("a.py", 142, VulnClass::Injection, 0.9);
        a.votes = 5;
        let collapsed = collapse_across_chunks(vec![a], 10);
        assert_eq!(collapsed[0].votes, 5);
    }

    #[test]
    fn collapse_across_chunks_of_empty_input_is_empty() {
        assert!(collapse_across_chunks(Vec::new(), 10).is_empty());
    }

    #[test]
    fn line_jitter_across_a_bucket_boundary_no_longer_splits_the_vote() {
        let a = finding("a.py", 149, VulnClass::Injection, 0.7);
        let b = finding("a.py", 151, VulnClass::Injection, 0.9);
        let runs = vec![vec![a], vec![b]];
        let survivors = vote_within_chunk(&runs, 10, 2);
        assert_eq!(survivors.len(), 1);
        assert_eq!(survivors[0].votes, 2);
        assert_eq!(survivors[0].confidence, 0.9);
    }

    #[test]
    fn lines_further_apart_than_the_tolerance_stay_distinct() {
        let a = finding("a.py", 141, VulnClass::Injection, 0.7);
        let b = finding("a.py", 149, VulnClass::Injection, 0.9);
        let runs = vec![vec![a], vec![b]];
        let survivors = vote_within_chunk(&runs, 3, 1);
        assert_eq!(survivors.len(), 2);
    }

    #[test]
    fn overlapping_ranges_merge_even_beyond_the_line_tolerance() {
        let mut a = finding("a.py", 100, VulnClass::Injection, 0.5);
        a.line_end = 200;
        let b = finding("a.py", 180, VulnClass::Injection, 0.9);
        let runs = vec![vec![a], vec![b]];
        let survivors = vote_within_chunk(&runs, 3, 2);
        assert_eq!(survivors.len(), 1);
        assert_eq!(survivors[0].votes, 2);
    }

    #[test]
    fn a_zero_line_bucket_still_merges_an_exact_line_match() {
        let a = finding("a.py", 10, VulnClass::Injection, 0.5);
        let b = finding("a.py", 10, VulnClass::Injection, 0.9);
        let runs = vec![vec![a], vec![b]];
        let survivors = vote_within_chunk(&runs, 0, 2);
        assert_eq!(survivors.len(), 1);
    }

    #[test]
    fn a_zero_line_bucket_keeps_adjacent_lines_distinct() {
        let a = finding("a.py", 10, VulnClass::Injection, 0.5);
        let b = finding("a.py", 11, VulnClass::Injection, 0.9);
        let runs = vec![vec![a], vec![b]];
        let survivors = vote_within_chunk(&runs, 0, 1);
        assert_eq!(survivors.len(), 2);
    }

    #[test]
    fn a_negative_line_bucket_is_clamped_to_zero_rather_than_merging_everything() {
        let a = finding("a.py", 10, VulnClass::Injection, 0.5);
        let b = finding("a.py", 40, VulnClass::Injection, 0.9);
        let runs = vec![vec![a], vec![b]];
        assert_eq!(vote_within_chunk(&runs, -5, 1).len(), 2);
    }

    #[test]
    fn a_single_run_with_one_finding_is_unchanged() {
        let a = finding("a.py", 42, VulnClass::Injection, 0.75);
        let survivors = vote_within_chunk(&[vec![a]], 10, 1);
        assert_eq!(survivors.len(), 1);
        assert_eq!(survivors[0].line_start, 42);
        assert_eq!(survivors[0].votes, 1);
    }

    #[test]
    fn clustering_does_not_chain_transitively_beyond_the_tolerance() {
        let a = finding("a.py", 10, VulnClass::Injection, 0.5);
        let b = finding("a.py", 18, VulnClass::Injection, 0.6);
        let c = finding("a.py", 26, VulnClass::Injection, 0.9);
        let survivors = vote_within_chunk(&[vec![a], vec![b], vec![c]], 10, 2);
        assert_eq!(survivors.len(), 1);
        assert_eq!(survivors[0].votes, 2);
        assert_eq!(survivors[0].confidence, 0.6);
    }

    #[test]
    fn collapse_across_chunks_merges_boundary_jitter_too() {
        let mut a = finding("a.py", 149, VulnClass::Injection, 0.6);
        a.chunk_id = "chunk-01".to_string();
        let mut b = finding("a.py", 151, VulnClass::Injection, 0.9);
        b.chunk_id = "spec-crypto-01".to_string();
        let collapsed = collapse_across_chunks(vec![a, b], 10);
        assert_eq!(collapsed.len(), 1);
        assert_eq!(collapsed[0].confidence, 0.9);
    }

    #[test]
    fn collapse_across_chunks_tie_keeps_the_first_seen_finding() {
        let mut a = finding("a.py", 10, VulnClass::Injection, 0.5);
        a.title = "first".to_string();
        let mut b = finding("a.py", 10, VulnClass::Injection, 0.5);
        b.title = "second".to_string();
        let collapsed = collapse_across_chunks(vec![a, b], 10);
        assert_eq!(collapsed[0].title, "first");
    }
}
