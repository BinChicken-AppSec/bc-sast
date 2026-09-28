//! Majority-vote intersection (within one chunk's N runs) and the
//! separate cross-chunk collapse pass, ported from `s4_deepdive.py`'s
//! `_deepdive_chunk`'s vote block and `_collapse_across_chunks`.
//!
//! **Identity is tolerance+overlap clustering, not bucket equality.**
//! Both Python and an earlier revision of this port grouped by
//! `line_start.div_euclid(line_bucket)` (`Finding::canonical_key`), which
//! is a *fixed grid*: with the shipped `line_bucket: 10`, lines 149 and
//! 151 land in buckets 14 and 15 and never vote together, while 141 and
//! 149 — twice as far apart — do. A model re-describing the same bug two
//! lines lower across two runs therefore split its own vote purely on
//! where the grid boundary happened to fall, and with `vote_threshold >=
//! 2` that silently dropped a real finding. This module instead groups on
//! the same rule `bc_dedup_core::collapse_trivial` (and hence S5/S7)
//! already uses — same file, same `vuln_class`, and either `line_start`s
//! within `line_bucket` of each other or overlapping `[line_start,
//! line_end]` ranges — so "within N lines" actually means within N lines.
//! This is a fix, not a port: the Python original has the same grid bug.
//!
//! The CWE guard `collapse_trivial` applies is deliberately NOT reused
//! here: at S4 a finding's `cwe` is frequently still unset (S4 is what
//! sets it, per-run and unreliably), so requiring CWE agreement would
//! block exactly the merges this vote exists to make. The geometric half
//! of the rule is reimplemented locally rather than depending on
//! `bc-dedup-core` for that one predicate.
//!
//! Iteration order here is deliberately the *first-occurrence* order
//! across the flattened `(run, finding)` sequence — the Python original's
//! intended order is "the order runs were processed, then the order
//! findings were iterated within a run," but its actual mechanism (a
//! `set` per run, then `Counter` over those sets) is itself
//! hash-randomization-dependent and not stably reproducible across Python
//! process runs either; this port reaches the *intended* order directly
//! and deterministically, without depending on any hash-iteration
//! accident.

use std::collections::{HashMap, HashSet};

use bc_model::Finding;

/// The CWE's numeric identity, or `None` when absent or unparseable —
/// see `bc_dedup_core::cwe_number`, of which this is the same deliberate
/// small local copy (that crate keeps it private, and this one is not a
/// dependency of it).
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

/// Whether `a` and `b` describe the same bug for voting purposes.
/// Mirrors `bc_dedup_core::collapse_trivial`'s predicate minus its
/// strict-class guard (see the module docs): same file, same
/// vulnerability, and either close starts or overlapping ranges.
///
/// "Same vulnerability" accepts an explicit, equal CWE even when the
/// `vuln_class` strings disagree, for the reason spelled out in
/// `bc_dedup_core::collapse_trivial`: the model relabels the same
/// vulnerability across chunks, and it does so across RUNS too, which at
/// `runs > 1` splits one bug's votes between two keys and can sink both
/// below `vote_threshold`. The CWE is the dependable half of the pair.
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
        // Both CWEs present while `cwe_agrees` is false means they
        // disagree, so their presence alone vetoes the class match.
        if ca.is_some() && cb.is_some() {
            return false;
        }
    }
    let close = (a.line_start - b.line_start).abs() <= line_tolerance;
    let overlap = a.line_start <= b.line_end && b.line_start <= a.line_end;
    close || overlap
}

/// For each item, the index of the cluster it belongs to — always the
/// LOWEST index in that cluster, so cluster ids are themselves stable
/// under the input order. Structurally identical to
/// `bc_dedup_core::collapse_trivial`'s loop (each item joins the first
/// still-canonical earlier item it matches), expressed as a
/// `root[i] == i` vector rather than a sparse map because every caller
/// here needs a total assignment.
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

/// Vote across one chunk's `runs_n` runs (one `Vec<Finding>` per run — a
/// failed run and a run that genuinely found nothing both contribute an
/// empty `Vec`, exactly like the Python original's `set()`). A cluster
/// surviving with `>= threshold` votes — one vote per RUN that contains
/// any member of it, so two near-identical hits inside one run still
/// count once — is returned exactly once, carrying the
/// highest-confidence `Finding` seen for that cluster across every run
/// (ties keep the first-seen finding), with `.votes` overwritten to the
/// true tally.
///
/// `line_bucket` is the line tolerance (see the module docs); a negative
/// value is clamped to `0`, which then means "same start line, or
/// overlapping ranges".
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

/// Per-chunk voting can't see that two different chunks both flagged the
/// same underlying bug (e.g. a risk chunk and a specialist chunk covering
/// overlapping files). Collapse with the same clustering rule globally,
/// across the union of every chunk's survivors, keeping the
/// highest-confidence representative (ties keep the first-seen finding) —
/// unlike the per-chunk vote, this pass does not re-tally `.votes`; the
/// winner keeps whatever vote count it already carried from its own chunk.
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
    use bc_model::VulnClass;

    fn finding(file: &str, line_start: i64, vuln_class: VulnClass, confidence: f64) -> Finding {
        Finding {
            provider_origins: Vec::new(),
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
        // Higher-confidence run's finding wins as the representative.
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
        // Prefixed, bare, padded and mis-cased all reduce to the number.
        assert_eq!(cwe_number(Some("CWE-89")), Some(89));
        assert_eq!(cwe_number(Some("cwe-0089")), Some(89));
        assert_eq!(cwe_number(Some("89")), Some(89));
        // Anything that is not a plain number is "no CWE", never a match.
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
        // Two runs of the same chunk, same bug, same CWE — but the model
        // called it `injection` once and `other` the next time. Keyed on
        // the class alone that is one vote each, so at
        // `vote_threshold: 2` the real finding vanishes entirely.
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
        let a2 = finding("a.py", 11, VulnClass::Injection, 0.9); // same bucket, same run
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
        // The regression this module's clustering rewrite exists for: with
        // `line_bucket: 10`, 149 and 151 used to land in grid buckets 14
        // and 15 and never vote together, so `vote_threshold: 2` silently
        // dropped a finding both runs actually agreed on.
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
        // The other half of the same property: 141 and 149 shared a grid
        // bucket under the old scheme despite being 8 lines apart; with a
        // tolerance of 3 they must now stay separate.
        let a = finding("a.py", 141, VulnClass::Injection, 0.7);
        let b = finding("a.py", 149, VulnClass::Injection, 0.9);
        let runs = vec![vec![a], vec![b]];
        let survivors = vote_within_chunk(&runs, 3, 1);
        assert_eq!(survivors.len(), 2);
    }

    #[test]
    fn overlapping_ranges_merge_even_beyond_the_line_tolerance() {
        // `bc_dedup_core::collapse_trivial`'s second arm: the same region
        // re-detected with different boundaries.
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
        // `runs = 1` / `line_bucket = 0` behavior is unchanged from the
        // exact-line-equality it had under `canonical_key`.
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
        // Defensive: a misconfigured `step4.line_bucket: -5` must not
        // silently collapse unrelated findings (nor panic).
        let a = finding("a.py", 10, VulnClass::Injection, 0.5);
        let b = finding("a.py", 40, VulnClass::Injection, 0.9);
        let runs = vec![vec![a], vec![b]];
        assert_eq!(vote_within_chunk(&runs, -5, 1).len(), 2);
    }

    #[test]
    fn a_single_run_with_one_finding_is_unchanged() {
        // The `runs = 1` default path, spelled out explicitly.
        let a = finding("a.py", 42, VulnClass::Injection, 0.75);
        let survivors = vote_within_chunk(&[vec![a]], 10, 1);
        assert_eq!(survivors.len(), 1);
        assert_eq!(survivors[0].line_start, 42);
        assert_eq!(survivors[0].votes, 1);
    }

    #[test]
    fn clustering_does_not_chain_transitively_beyond_the_tolerance() {
        // 10 → 18 → 26 with tolerance 10: 18 joins 10, but 26 is 16 lines
        // from that cluster's root and only 8 from 18 — which is no longer
        // canonical. `cluster_roots` matches against still-canonical
        // earlier items ONLY, exactly like
        // `bc_dedup_core::collapse_trivial`, so 26 starts its own cluster
        // instead of transitively dragging the group across an unbounded
        // span. Two clusters, so a 2-of-3 vote keeps only the first.
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
