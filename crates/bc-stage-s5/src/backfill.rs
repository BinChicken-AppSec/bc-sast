//! AST/call-graph evidence backfill, ported from
//! `s5_prefilter.py::_ast_backfill_evidence`. Runs only on findings that
//! already survived every deterministic gate — it decorates kept findings
//! with a best-effort `source_ref`/`sink_ref` when S4 omitted one, but
//! never satisfies [`crate::gates::apply_gates`]'s own evidence gate for a
//! finding that arrived without evidence (that gate runs first, against
//! the finding's own unbackfilled refs).

use std::collections::{BTreeMap, BTreeSet};

use bc_model::{Finding, VulnClass};

/// `(entry_anchors, seed_idx)` computed once per run from `ctx`, matching
/// Python's `entry_anchors = entry_anchor_lines(ctx)` / `seed_idx =
/// seed_paths_by_file(ctx.seed_taint_paths)` computed once before the
/// per-finding loop.
pub struct BackfillIndex {
    entry_anchors: BTreeMap<String, Vec<i64>>,
    seed_idx: BTreeMap<String, Vec<Vec<String>>>,
}

impl BackfillIndex {
    pub fn new(ctx: &bc_model::ContextPackage) -> Self {
        BackfillIndex {
            entry_anchors: bc_repo_analysis::entry_anchor_lines(ctx),
            seed_idx: bc_repo_analysis::seed_paths_by_file(&ctx.seed_taint_paths),
        }
    }
}

/// Best-effort `source_ref`/`sink_ref` backfill for one finding. Returns
/// `None` when nothing changed (both refs already had content) — matching
/// Python's `(f, False)` early return, just via `Option` instead of a
/// changed-flag tuple.
///
/// Resolution order: `sink_ref` first (falls back to `file:line_start`
/// unconditionally when missing), then `source_ref` — `INFO_LEAK` findings
/// reuse the (possibly just-backfilled) sink as their source, everything
/// else tries the nearest entry-point anchor in the same file, then falls
/// back to the first seed-taint-path source touching that file.
pub fn ast_backfill_evidence(f: &Finding, index: &BackfillIndex) -> Option<Finding> {
    let mut src = f.source_ref.as_deref().unwrap_or("").trim().to_string();
    let mut sink = f.sink_ref.as_deref().unwrap_or("").trim().to_string();
    let mut changed = false;
    let mut backfilled: Vec<&str> = Vec::new();

    if sink.is_empty() {
        sink = format!("{}:{}", f.file, f.line_start.max(1));
        changed = true;
        backfilled.push("sink_ref");
    }

    if src.is_empty() {
        if f.vuln_class == VulnClass::InfoLeak {
            src = sink.clone();
            changed = true;
            backfilled.push("source_ref");
        } else if let Some(anchors) = index.entry_anchors.get(&f.file) {
            // `anchors` is sorted ascending (see `entry_anchor_lines`), so
            // `min_by_key`'s first-on-tie rule matches Python's `min()`
            // over the same sorted list.
            if let Some(&best) = anchors.iter().min_by_key(|&&ln| (ln - f.line_start).abs()) {
                src = format!("{}:{}", f.file, best);
                changed = true;
                backfilled.push("source_ref");
            }
        } else if let Some(seed_src) = index
            .seed_idx
            .get(&f.file)
            .and_then(|paths| bc_repo_analysis::best_source_from_seed(paths))
        {
            src = seed_src;
            changed = true;
            backfilled.push("source_ref");
        }
    }

    if !changed {
        return None;
    }

    let mut merged: BTreeSet<String> = f.backfilled_refs.iter().cloned().collect();
    merged.extend(backfilled.into_iter().map(String::from));

    let mut out = f.clone();
    out.source_ref = if src.is_empty() { None } else { Some(src) };
    out.sink_ref = if sink.is_empty() { None } else { Some(sink) };
    out.backfilled_refs = merged.into_iter().collect();
    Some(out)
}

/// Backfill every finding in place, matching the count Python reports as
/// `backfilled` (findings actually changed, not the total count).
pub fn backfill_all(findings: &mut [Finding], index: &BackfillIndex) -> usize {
    let mut count = 0;
    for f in findings.iter_mut() {
        if let Some(updated) = ast_backfill_evidence(f, index) {
            *f = updated;
            count += 1;
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_model::ContextPackage;

    fn finding(file: &str, line_start: i64, vuln_class: VulnClass) -> Finding {
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
            confidence: 0.9,
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

    fn index(entry_anchors: &[(&str, &[i64])], seed_paths: &[Vec<&str>]) -> BackfillIndex {
        BackfillIndex {
            entry_anchors: entry_anchors
                .iter()
                .map(|(f, lines)| (f.to_string(), lines.to_vec()))
                .collect(),
            seed_idx: bc_repo_analysis::seed_paths_by_file(
                &seed_paths
                    .iter()
                    .map(|p| p.iter().map(|s| s.to_string()).collect())
                    .collect::<Vec<Vec<String>>>(),
            ),
        }
    }

    #[test]
    fn a_finding_with_both_refs_already_present_is_unchanged() {
        let mut f = finding("a.py", 10, VulnClass::Injection);
        f.source_ref = Some("a.py:5".to_string());
        f.sink_ref = Some("a.py:10".to_string());
        let idx = index(&[], &[]);
        assert!(ast_backfill_evidence(&f, &idx).is_none());
    }

    #[test]
    fn missing_sink_ref_falls_back_to_the_findings_own_file_and_line() {
        let mut f = finding("a.py", 10, VulnClass::Injection);
        f.source_ref = Some("a.py:1".to_string());
        let idx = index(&[], &[]);
        let out = ast_backfill_evidence(&f, &idx).unwrap();
        assert_eq!(out.sink_ref, Some("a.py:10".to_string()));
        assert_eq!(out.backfilled_refs, vec!["sink_ref".to_string()]);
    }

    #[test]
    fn missing_sink_ref_clamps_a_non_positive_line_start_up_to_one() {
        let mut f = finding("a.py", 0, VulnClass::Injection);
        f.source_ref = Some("a.py:1".to_string());
        let idx = index(&[], &[]);
        let out = ast_backfill_evidence(&f, &idx).unwrap();
        assert_eq!(out.sink_ref, Some("a.py:1".to_string()));
    }

    #[test]
    fn info_leak_missing_source_reuses_the_sink_value() {
        let mut f = finding("a.py", 10, VulnClass::InfoLeak);
        f.sink_ref = Some("a.py:10".to_string());
        let idx = index(&[], &[]);
        let out = ast_backfill_evidence(&f, &idx).unwrap();
        assert_eq!(out.source_ref, Some("a.py:10".to_string()));
        assert_eq!(out.backfilled_refs, vec!["source_ref".to_string()]);
    }

    #[test]
    fn info_leak_missing_both_reuses_the_freshly_backfilled_sink() {
        let f = finding("a.py", 10, VulnClass::InfoLeak);
        let idx = index(&[], &[]);
        let out = ast_backfill_evidence(&f, &idx).unwrap();
        assert_eq!(out.sink_ref, Some("a.py:10".to_string()));
        assert_eq!(out.source_ref, Some("a.py:10".to_string()));
        let mut refs = out.backfilled_refs.clone();
        refs.sort();
        assert_eq!(refs, vec!["sink_ref".to_string(), "source_ref".to_string()]);
    }

    #[test]
    fn non_info_leak_missing_source_uses_the_nearest_entry_anchor() {
        let mut f = finding("a.py", 50, VulnClass::Injection);
        f.sink_ref = Some("a.py:50".to_string());
        let idx = index(&[("a.py", &[1, 40, 100])], &[]);
        let out = ast_backfill_evidence(&f, &idx).unwrap();
        // |40-50|=10 is closer than |1-50|=49 or |100-50|=50.
        assert_eq!(out.source_ref, Some("a.py:40".to_string()));
    }

    #[test]
    fn nearest_entry_anchor_tie_keeps_the_earlier_sorted_anchor() {
        let mut f = finding("a.py", 50, VulnClass::Injection);
        f.sink_ref = Some("a.py:50".to_string());
        // |40-50| == |60-50| == 10: Python's min() (and this port's
        // min_by_key over the same ascending-sorted list) keeps the first.
        let idx = index(&[("a.py", &[40, 60])], &[]);
        let out = ast_backfill_evidence(&f, &idx).unwrap();
        assert_eq!(out.source_ref, Some("a.py:40".to_string()));
    }

    #[test]
    fn non_info_leak_missing_source_with_no_entry_anchor_falls_back_to_seed_path() {
        let mut f = finding("a.py", 10, VulnClass::Injection);
        f.sink_ref = Some("a.py:10".to_string());
        let idx = index(&[], &[vec!["a.py:3", "a.py:10"]]);
        let out = ast_backfill_evidence(&f, &idx).unwrap();
        assert_eq!(out.source_ref, Some("a.py:3".to_string()));
    }

    #[test]
    fn non_info_leak_missing_source_with_no_anchor_and_no_seed_path_stays_unbackfilled() {
        let mut f = finding("a.py", 10, VulnClass::Injection);
        // sink already present so only the source-backfill branch is under test.
        f.sink_ref = Some("a.py:10".to_string());
        let idx = index(&[], &[]);
        assert!(ast_backfill_evidence(&f, &idx).is_none());
    }

    #[test]
    fn a_whitespace_only_ref_is_normalized_to_none_as_a_side_effect_of_any_other_change() {
        let mut f = finding("a.py", 10, VulnClass::Injection);
        f.source_ref = Some("   ".to_string());
        // No entry anchor and no seed path for source, so only sink gets
        // backfilled — but source_ref must still be renormalized from
        // whitespace to None, matching Python's `src or None`.
        let idx = index(&[], &[]);
        let out = ast_backfill_evidence(&f, &idx).unwrap();
        assert_eq!(out.source_ref, None);
        assert_eq!(out.backfilled_refs, vec!["sink_ref".to_string()]);
    }

    #[test]
    fn backfilled_refs_is_a_deduped_union_with_the_findings_existing_value() {
        let mut f = finding("a.py", 10, VulnClass::Injection);
        f.backfilled_refs = vec!["sink_ref".to_string()];
        // sink already present (so no NEW sink_ref backfill), source missing
        // with a seed path available.
        f.sink_ref = Some("a.py:10".to_string());
        let idx = index(&[], &[vec!["a.py:1"]]);
        let out = ast_backfill_evidence(&f, &idx).unwrap();
        let mut refs = out.backfilled_refs.clone();
        refs.sort();
        assert_eq!(refs, vec!["sink_ref".to_string(), "source_ref".to_string()]);
    }

    #[test]
    fn backfill_all_reports_only_the_changed_count() {
        let mut findings = vec![finding("a.py", 10, VulnClass::Injection), {
            let mut f = finding("b.py", 5, VulnClass::Injection);
            f.source_ref = Some("b.py:1".to_string());
            f.sink_ref = Some("b.py:5".to_string());
            f
        }];
        let idx = index(&[], &[]);
        let n = backfill_all(&mut findings, &idx);
        assert_eq!(n, 1);
        assert_eq!(findings[0].sink_ref, Some("a.py:10".to_string()));
        assert_eq!(findings[1].source_ref, Some("b.py:1".to_string()));
    }

    #[test]
    fn backfill_index_new_builds_from_a_context_package() {
        let ctx = ContextPackage::default();
        let idx = BackfillIndex::new(&ctx);
        assert!(idx.entry_anchors.is_empty());
        assert!(idx.seed_idx.is_empty());
    }
}
