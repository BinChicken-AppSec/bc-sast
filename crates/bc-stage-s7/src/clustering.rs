//! Deterministic-dedup bookkeeping: wraps `bc-dedup-core`'s generic
//! clustering with `Finding`-shaped `DupLocation`/`DroppedFinding`
//! construction, ported from `s7_dedup.py`'s `_make_dup_location`/
//! `_dedup_locations`/`_attach_duplicates`/`_collapse_trivial`/`prefilter`.

use std::collections::{HashMap, HashSet};

use bc_dedup_core::{CanonicalOf, DedupKey};
use bc_model::{DropReason, DroppedFinding, DupLocation, Finding, VulnClass};

pub const TRIVIAL_REASON: &str = "trivial: same file/class within line tolerance";
/// The reason a cross-file collapse earns: it can only have come from
/// `bc_dedup_core::collapse_trivial`'s flow-identity tier, since every
/// other arm of that function requires an equal `file`.
pub const FLOW_REASON: &str =
    "same data flow: identical sink_ref (and source_ref when both carry one) under one CWE";
pub const SAME_RANGE_CWE_REASON: &str = "same code range, reported under a different CWE";

/// A borrowed view over `Finding` implementing `bc-dedup-core`'s
/// `DedupKey` — required rather than `impl DedupKey for Finding` directly
/// since neither this crate nor `bc-dedup-core` owns `Finding` (Rust's
/// orphan rule), and `bc-dedup-core` deliberately stays dependency-free
/// of `bc-model` (see its own doc comment). This is exactly the
/// "lightweight view" its trait doc anticipates callers building.
pub struct FindingRef<'a>(pub &'a Finding);

impl DedupKey for FindingRef<'_> {
    fn file(&self) -> &str {
        &self.0.file
    }
    fn vuln_class(&self) -> &str {
        self.0.vuln_class.as_str()
    }
    fn line_start(&self) -> i64 {
        self.0.line_start
    }
    fn line_end(&self) -> i64 {
        self.0.line_end
    }
    fn cwe(&self) -> Option<&str> {
        self.0.cwe.as_deref()
    }
    fn source_ref(&self) -> Option<&str> {
        self.0.source_ref.as_deref()
    }
    fn sink_ref(&self) -> Option<&str> {
        self.0.sink_ref.as_deref()
    }
}

/// `vuln_class`es that require an explicit, equal CWE on both sides before
/// `bc_dedup_core::collapse_trivial` will collapse two findings — ported
/// from `s7_dedup.py::_STRICT_CWE_CLASS`. Missing CWE is common this early
/// in a real run, and collapsing two logic-bug findings pre-S6 purely on
/// file+line proximity risks silently hiding a true positive.
fn strict_cwe_classes() -> HashSet<&'static str> {
    HashSet::from([VulnClass::LogicFlaw.as_str()])
}

/// Both deterministic passes plus the per-duplicate reason string each
/// collapse earned: `bc_dedup_core::collapse_trivial` (same file + line
/// proximity, or flow identity across files), then — when
/// `merge_same_range_cwes` is on — `collapse_same_range_cwes` for the
/// one-range-many-CWE-lenses shape the first pass deliberately vetoes.
///
/// Running the narrow same-range pass SECOND is load-bearing: the first
/// pass's matches are the higher-confidence ones, and letting them claim
/// their canonicals first means the same-range pass can only ever join
/// clusters that nothing else explained.
pub fn deterministic_passes(
    findings: &[Finding],
    line_tolerance: i64,
    merge_same_range_cwes: bool,
    merge_same_sink: bool,
) -> (CanonicalOf, HashMap<usize, String>) {
    let keys: Vec<FindingRef> = findings.iter().map(FindingRef).collect();
    let strict = strict_cwe_classes();
    let mut canonical_of =
        bc_dedup_core::collapse_trivial(&keys, line_tolerance, &strict, merge_same_sink);
    let mut reasoning: HashMap<usize, String> = canonical_of
        .iter()
        .map(|(&dup, &canon)| {
            // Only the flow-identity tier can pair two different files.
            let reason = if findings[dup].file == findings[canon].file {
                TRIVIAL_REASON
            } else {
                FLOW_REASON
            };
            (dup, reason.to_string())
        })
        .collect();
    if merge_same_range_cwes {
        for (dup, _) in bc_dedup_core::collapse_same_range_cwes(&keys, &mut canonical_of, &strict) {
            reasoning.insert(dup, SAME_RANGE_CWE_REASON.to_string());
        }
    }
    (canonical_of, reasoning)
}

fn make_dup_location(f: &Finding, reasoning: String) -> DupLocation {
    DupLocation {
        file: f.file.clone(),
        line_start: f.line_start,
        line_end: f.line_end,
        vuln_class: f.vuln_class,
        title: f.title.clone(),
        chunk_id: f.chunk_id.clone(),
        source_ref: f.source_ref.clone(),
        sink_ref: f.sink_ref.clone(),
        reasoning,
    }
}

fn dedup_locations(locs: Vec<DupLocation>) -> Vec<DupLocation> {
    let mut seen = HashSet::new();
    locs.into_iter()
        .filter(|d| seen.insert((d.file.clone(), d.line_start, d.line_end)))
        .collect()
}

/// Fold a merged-away duplicate's CWE into the canonical's
/// `related_cwes`, keeping first-seen order and never recording the
/// canonical's own CWE or a repeat. A class-derived fallback CWE is
/// deliberately NOT synthesized here: only a CWE the model actually
/// asserted for that member is a genuine second lens on the range; a
/// fallback would just restate the `vuln_class` the merge already keeps.
fn merge_related_cwe(canon: &mut Finding, dup: &Finding) {
    let canonical_number = |raw: Option<&str>| bc_dedup_core::cwe_number(raw);
    let own = canonical_number(canon.cwe.as_deref());
    let mut incoming: Vec<String> = Vec::new();
    if let Some(cwe) = dup.cwe.as_deref() {
        incoming.push(cwe.to_string());
    }
    incoming.extend(dup.related_cwes.iter().cloned());
    for cwe in incoming {
        // An unparseable token has no identity to compare, so it can
        // neither collide with the canonical's own CWE nor be recognized
        // as already present — drop it rather than accumulate noise.
        let Some(number) = canonical_number(Some(&cwe)) else {
            continue;
        };
        if own == Some(number) {
            continue;
        }
        // Stored in the canonical `CWE-<n>` spelling rather than whatever
        // the model wrote, so the report and SARIF consumers of this list
        // can compare and render entries without re-normalizing (and so
        // `cwe-0200` never appears alongside `CWE-200`).
        let canonical_spelling = format!("CWE-{number}");
        if canon.related_cwes.contains(&canonical_spelling) {
            continue;
        }
        canon.related_cwes.push(canonical_spelling);
    }
}

/// For every entry in `canonical_of`, append a `DupLocation` snapshot of
/// the duplicate onto its (transitively-resolved) canonical finding —
/// unless the two occupy the same call site (overlapping ranges), in
/// which case it's a re-detection, not an additional site. Also carries
/// forward any `DupLocation`s already attached to the duplicate (so a
/// deterministic pass followed by a semantic pass doesn't lose dups
/// attached in the earlier pass), then de-dupes each canonical's location
/// list. Ported from `_attach_duplicates`.
///
/// Net-new on top of the port: a duplicate whose CWE differs from the
/// canonical's contributes it to the canonical's `related_cwes`, so a
/// merge across CWE lenses (see [`deterministic_passes`]) loses no
/// classification. This is written generically rather than only for the
/// same-range pass because a semantic (7b) merge can pair two CWEs too,
/// and the same "nothing is lost, just one entry per code range"
/// guarantee should hold there.
pub fn attach_duplicates(
    findings: &mut [Finding],
    canonical_of: &CanonicalOf,
    reasoning: &HashMap<usize, String>,
) {
    let relations = {
        let keys: Vec<FindingRef> = findings.iter().map(FindingRef).collect();
        bc_dedup_core::resolve_relations(&keys, canonical_of)
    };

    let mut roots: HashSet<usize> = HashSet::new();
    for rel in &relations {
        roots.insert(rel.canonical_idx);
        let reason = reasoning
            .get(&rel.duplicate_idx)
            .cloned()
            .unwrap_or_else(|| "duplicate".to_string());
        // `canonical_idx` is always strictly lower than `duplicate_idx`
        // (every canonical_of mapping points to a strictly lower index),
        // so split_at_mut gives two genuinely disjoint mutable borrows.
        let (canon_part, dup_part) = findings.split_at_mut(rel.duplicate_idx);
        let canon_finding = &mut canon_part[rel.canonical_idx];
        let dup_finding = &mut dup_part[0];
        // Two findings can now cluster on an equal CWE alone, with
        // different `vuln_class` strings (see
        // `bc_dedup_core::collapse_trivial`). When the survivor is the
        // one the model labeled with the generic fallback and the
        // duplicate carries a specific class, adopt the specific one:
        // the cluster's class is the best label any member had, not
        // whichever member happened to sort first. Without this, the
        // SARIF `ruleId` for a collapsed pair can read `other` while a
        // discarded member said `injection`.
        if canon_finding.vuln_class == VulnClass::Other
            && dup_finding.vuln_class != VulnClass::Other
        {
            canon_finding.vuln_class = dup_finding.vuln_class;
        }
        merge_related_cwe(canon_finding, dup_finding);
        // Provenance is a union, never permission to reuse the canonical's
        // verifier verdict for the incoming provider origin. Original member
        // assessments are retained independently before this merge.
        canon_finding
            .provider_origins
            .extend(dup_finding.provider_origins.iter().cloned());
        canon_finding.provider_origins.sort();
        canon_finding.provider_origins.dedup();
        if !rel.same_site {
            canon_finding
                .duplicates
                .push(make_dup_location(dup_finding, reason));
        }
        if !dup_finding.duplicates.is_empty() {
            let carried = std::mem::take(&mut dup_finding.duplicates);
            canon_finding.duplicates.extend(carried);
        }
    }
    for r in roots {
        findings[r].duplicates = dedup_locations(std::mem::take(&mut findings[r].duplicates));
    }
}

/// Deterministic dedup only (S7's "7a" pass): same file + same vuln_class +
/// `|line diff| <= line_tolerance` (or overlapping ranges), plus the
/// flow-identity and (optional) same-range-different-CWE tiers. No model
/// call — safe to run before S6 verify to avoid verifying the same bug N
/// times, and the CWE-lens merge in particular is worth the most here,
/// where it saves a whole verification session per merged lens.
/// Ported from `s7_dedup.py::prefilter`.
///
/// The pre-sort is net-new versus that original (and versus this port's
/// own earlier shape, where only `run_dedup` sorted): without it the
/// survivor of a cross-file flow-identity collapse would be whichever end
/// S4 happened to emit first, when it must be the sink-anchored one — see
/// [`crate::sort_for_stable_canonical`].
pub fn prefilter(
    findings: &[Finding],
    line_tolerance: i64,
    merge_same_range_cwes: bool,
    merge_same_sink: bool,
) -> (Vec<Finding>, Vec<DroppedFinding>) {
    if findings.len() <= 1 {
        return (findings.to_vec(), Vec::new());
    }

    let mut findings = findings.to_vec();
    crate::sort_for_stable_canonical(&mut findings);
    let (canonical_of, reasoning) = deterministic_passes(
        &findings,
        line_tolerance,
        merge_same_range_cwes,
        merge_same_sink,
    );
    attach_duplicates(&mut findings, &canonical_of, &reasoning);

    let partition = bc_dedup_core::partition(findings.len(), &canonical_of);
    let dropped = partition
        .dropped_indices
        .iter()
        .map(|&i| DroppedFinding {
            file: findings[i].file.clone(),
            line: findings[i].line_start,
            vuln_class: findings[i].vuln_class,
            title: findings[i].title.clone(),
            chunk_id: findings[i].chunk_id.clone(),
            reason: DropReason::Duplicate,
            detail: reasoning[&i].clone(),
            canonical_idx: None,
            provider_origins: findings[i].provider_origins.clone(),
            verification: bc_model::VerificationEvidence::from_finding(&findings[i]),
        })
        .collect();
    let keep = partition
        .kept_indices
        .iter()
        .map(|&i| findings[i].clone())
        .collect();
    (keep, dropped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_model::VulnClass;

    /// The first deterministic pass on its own, which is what most of
    /// the tests below exercise — `deterministic_passes` with the
    /// same-range CWE merge deliberately off.
    fn collapse_trivial(findings: &[Finding], line_tolerance: i64) -> CanonicalOf {
        deterministic_passes(findings, line_tolerance, false, true).0
    }

    fn f(file: &str, ls: i64, le: i64, vc: VulnClass) -> Finding {
        Finding {
            provider_origins: Vec::new(),
            chunk_id: "c".to_string(),
            file: file.to_string(),
            line_start: ls,
            line_end: le,
            vuln_class: vc,
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

    #[test]
    fn finding_ref_exposes_the_underlying_fields() {
        let mut a = f("a.rs", 10, 20, VulnClass::Injection);
        a.cwe = Some("CWE-89".to_string());
        let r = FindingRef(&a);
        assert_eq!(r.file(), "a.rs");
        assert_eq!(r.vuln_class(), "injection");
        assert_eq!(r.line_start(), 10);
        assert_eq!(r.line_end(), 20);
        assert_eq!(r.cwe(), Some("CWE-89"));
    }

    #[test]
    fn merging_unions_origins_without_transferring_the_canonicals_verdict() {
        let origin = |id: &str| bc_model::ProviderOrigin {
            provider: bc_model::ProviderKind::Semgrep,
            native_ids: bc_model::ProviderNativeIds {
                issue_id: Some(id.into()),
                ..Default::default()
            },
            ..Default::default()
        };
        let mut canonical = f("a.rs", 10, 20, VulnClass::Injection);
        canonical.provider_origins = vec![origin("z"), origin("z")];
        canonical.verdict = Some(bc_model::Verdict::TruePositive);
        canonical.verdict_confidence = Some(9);
        canonical.verdict_reason = "canonical evidence".into();
        let mut duplicate = canonical.clone();
        duplicate.provider_origins = vec![origin("a")];
        duplicate.verdict = Some(bc_model::Verdict::FalsePositive);
        duplicate.verdict_confidence = Some(8);
        duplicate.verdict_reason = "different original assessment".into();
        let mut findings = vec![canonical, duplicate];
        let map = CanonicalOf::from([(1, 0)]);
        attach_duplicates(
            &mut findings,
            &map,
            &HashMap::from([(1, "same site".into())]),
        );
        assert_eq!(findings[0].provider_origins, [origin("a"), origin("z")]);
        assert_eq!(findings[1].provider_origins, [origin("a")]);
        assert_eq!(findings[0].verdict, Some(bc_model::Verdict::TruePositive));
        assert_eq!(findings[1].verdict, Some(bc_model::Verdict::FalsePositive));
        assert_eq!(findings[1].verdict_reason, "different original assessment");
    }

    #[test]
    fn duplicate_audit_keeps_the_members_evidence_and_original_origin_only() {
        let mut first = f("a.rs", 10, 20, VulnClass::Injection);
        first.verdict = Some(bc_model::Verdict::TruePositive);
        first.verdict_confidence = Some(9);
        let mut second = first.clone();
        second.verdict_confidence = Some(7);
        second.verdict_reason = "individual source trace".into();
        second.verifier_reasoning = "actual member reasoning".into();
        let origin = bc_model::ProviderOrigin {
            native_ids: bc_model::ProviderNativeIds {
                issue_id: Some("second".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        second.provider_origins.push(origin.clone());
        let (kept, dropped) = prefilter(&[first, second], 3, false, false);
        assert_eq!(kept.len(), 1);
        assert_eq!(dropped.len(), 1);
        assert_eq!(
            kept[0].provider_origins.as_slice(),
            std::slice::from_ref(&origin)
        );
        assert_eq!(dropped[0].provider_origins, [origin]);
        let evidence = dropped[0].verification.as_ref().unwrap();
        assert_eq!(evidence.confidence, 7);
        assert_eq!(evidence.reason, "individual source trace");
        assert_eq!(evidence.reasoning, "actual member reasoning");
    }

    #[test]
    fn finding_ref_cwe_is_none_when_unset() {
        let a = f("a.rs", 10, 20, VulnClass::Injection);
        assert_eq!(FindingRef(&a).cwe(), None);
    }

    #[test]
    fn a_generic_canonical_adopts_a_collapsed_duplicates_specific_class() {
        // The 2026-09-03 field case: the survivor was the `other`-classed
        // copy, so without this the SARIF ruleId for a real SQL injection
        // read `other`.
        let mut a = f("app.py", 14, 22, VulnClass::Other);
        a.cwe = Some("CWE-89".to_string());
        let mut b = f("app.py", 17, 21, VulnClass::Injection);
        b.cwe = Some("CWE-89".to_string());
        let mut findings = vec![a, b];
        let canonical_of = collapse_trivial(&findings, 2);
        assert_eq!(canonical_of.get(&1), Some(&0));
        attach_duplicates(&mut findings, &canonical_of, &HashMap::new());
        assert_eq!(findings[0].vuln_class, VulnClass::Injection);
        // 17-21 is nested inside 14-22, so this is the same site
        // re-detected rather than a second call site — no `Also at:`
        // entry, matching `resolve_relations`' `same_site` rule.
        assert!(findings[0].duplicates.is_empty());
    }

    #[test]
    fn a_disjoint_duplicate_of_the_same_cwe_is_recorded_as_another_call_site() {
        let mut a = f("app.py", 14, 15, VulnClass::Other);
        a.cwe = Some("CWE-89".to_string());
        let mut b = f("app.py", 18, 19, VulnClass::Injection);
        b.cwe = Some("CWE-89".to_string());
        let mut findings = vec![a, b];
        let canonical_of = collapse_trivial(&findings, 5);
        attach_duplicates(&mut findings, &canonical_of, &HashMap::new());
        assert_eq!(findings[0].vuln_class, VulnClass::Injection);
        assert_eq!(findings[0].duplicates.len(), 1);
        assert_eq!(findings[0].duplicates[0].line_start, 18);
    }

    #[test]
    fn a_specific_canonical_class_is_never_downgraded_by_a_generic_duplicate() {
        let mut a = f("app.py", 14, 22, VulnClass::Injection);
        a.cwe = Some("CWE-89".to_string());
        let mut b = f("app.py", 17, 21, VulnClass::Other);
        b.cwe = Some("CWE-89".to_string());
        let mut findings = vec![a, b];
        let canonical_of = collapse_trivial(&findings, 2);
        attach_duplicates(&mut findings, &canonical_of, &HashMap::new());
        assert_eq!(findings[0].vuln_class, VulnClass::Injection);
    }

    #[test]
    fn strict_cwe_classes_contains_exactly_logic_flaw() {
        let classes = strict_cwe_classes();
        assert!(classes.contains(VulnClass::LogicFlaw.as_str()));
        assert!(!classes.contains(VulnClass::Injection.as_str()));
        assert_eq!(classes.len(), 1);
    }

    #[test]
    fn collapse_trivial_merges_overlapping_ranges() {
        let findings = vec![
            f("a.py", 10, 20, VulnClass::Other),
            f("a.py", 15, 25, VulnClass::Other),
        ];
        let canon = collapse_trivial(&findings, 3);
        assert_eq!(canon.get(&1), Some(&0));
    }

    #[test]
    fn collapse_trivial_keeps_disjoint_ranges_separate() {
        let findings = vec![
            f("a.py", 10, 12, VulnClass::Other),
            f("a.py", 80, 82, VulnClass::Other),
        ];
        assert!(collapse_trivial(&findings, 3).is_empty());
    }

    #[test]
    fn collapse_trivial_blocks_on_an_explicit_cwe_mismatch() {
        let mut a = f("a.py", 10, 10, VulnClass::Injection);
        a.cwe = Some("CWE-89".to_string());
        let mut b = f("a.py", 11, 11, VulnClass::Injection);
        b.cwe = Some("CWE-90".to_string());
        assert!(collapse_trivial(&[a, b], 3).is_empty());
    }

    #[test]
    fn collapse_trivial_requires_an_explicit_cwe_for_logic_flaw_findings() {
        // Neither side has a CWE — the strict-CWE-class guard blocks the
        // collapse even though file/vuln_class/line proximity all match.
        let findings = vec![
            f("a.py", 10, 10, VulnClass::LogicFlaw),
            f("a.py", 11, 11, VulnClass::LogicFlaw),
        ];
        assert!(collapse_trivial(&findings, 3).is_empty());
    }

    #[test]
    fn collapse_trivial_collapses_logic_flaw_findings_with_a_matching_explicit_cwe() {
        let mut a = f("a.py", 10, 10, VulnClass::LogicFlaw);
        a.cwe = Some("CWE-840".to_string());
        let mut b = f("a.py", 11, 11, VulnClass::LogicFlaw);
        b.cwe = Some("CWE-840".to_string());
        let canon = collapse_trivial(&[a, b], 3);
        assert_eq!(canon.get(&1), Some(&0));
    }

    #[test]
    fn attach_duplicates_skips_same_site_overlap() {
        let mut findings = vec![
            f("a.py", 10, 20, VulnClass::Other),
            f("a.py", 15, 25, VulnClass::Other),
        ];
        let mut canonical_of = CanonicalOf::new();
        canonical_of.insert(1, 0);
        let reasoning: HashMap<usize, String> = [(1, "dup".to_string())].into();
        attach_duplicates(&mut findings, &canonical_of, &reasoning);
        assert!(findings[0].duplicates.is_empty());
    }

    #[test]
    fn attach_duplicates_records_disjoint_site() {
        let mut findings = vec![
            f("a.py", 10, 12, VulnClass::Other),
            f("b.py", 50, 52, VulnClass::Other),
        ];
        let mut canonical_of = CanonicalOf::new();
        canonical_of.insert(1, 0);
        let reasoning: HashMap<usize, String> = [(1, "dup".to_string())].into();
        attach_duplicates(&mut findings, &canonical_of, &reasoning);
        assert_eq!(findings[0].duplicates.len(), 1);
        assert_eq!(findings[0].duplicates[0].file, "b.py");
        assert_eq!(findings[0].duplicates[0].reasoning, "dup");
    }

    #[test]
    fn attach_duplicates_falls_back_to_a_default_reason_when_none_supplied() {
        let mut findings = vec![
            f("a.py", 10, 12, VulnClass::Other),
            f("b.py", 50, 52, VulnClass::Other),
        ];
        let mut canonical_of = CanonicalOf::new();
        canonical_of.insert(1, 0);
        attach_duplicates(&mut findings, &canonical_of, &HashMap::new());
        assert_eq!(findings[0].duplicates[0].reasoning, "duplicate");
    }

    #[test]
    fn attach_duplicates_dedupes_identical_locations() {
        let mut findings = vec![
            f("a.py", 10, 12, VulnClass::Other),
            f("b.py", 50, 52, VulnClass::Other),
            f("b.py", 50, 52, VulnClass::Other),
        ];
        let mut canonical_of = CanonicalOf::new();
        canonical_of.insert(1, 0);
        canonical_of.insert(2, 0);
        let reasoning: HashMap<usize, String> = [(1, "d".to_string()), (2, "d".to_string())].into();
        attach_duplicates(&mut findings, &canonical_of, &reasoning);
        assert_eq!(findings[0].duplicates.len(), 1);
    }

    #[test]
    fn attach_duplicates_carries_forward_dups_already_on_the_duplicate() {
        // Simulates a deterministic pass followed by a semantic pass: item 1
        // already has a DupLocation attached (from an earlier pass) before
        // becoming a duplicate of item 0 itself.
        let mut findings = vec![
            f("a.py", 10, 12, VulnClass::Other),
            f("b.py", 50, 52, VulnClass::Other),
        ];
        findings[1].duplicates.push(DupLocation {
            file: "c.py".to_string(),
            line_start: 1,
            line_end: 1,
            vuln_class: VulnClass::Other,
            title: String::new(),
            chunk_id: String::new(),
            source_ref: None,
            sink_ref: None,
            reasoning: "earlier".to_string(),
        });
        let mut canonical_of = CanonicalOf::new();
        canonical_of.insert(1, 0);
        let reasoning: HashMap<usize, String> = [(1, "dup".to_string())].into();
        attach_duplicates(&mut findings, &canonical_of, &reasoning);
        assert_eq!(findings[0].duplicates.len(), 2);
        assert!(findings[0].duplicates.iter().any(|d| d.file == "b.py"));
        assert!(findings[0].duplicates.iter().any(|d| d.file == "c.py"));
        assert!(findings[1].duplicates.is_empty());
    }

    #[test]
    fn prefilter_of_a_single_finding_short_circuits() {
        let findings = vec![f("a.py", 10, 10, VulnClass::Other)];
        let (keep, dropped) = prefilter(&findings, 3, false, true);
        assert_eq!(keep.len(), 1);
        assert!(dropped.is_empty());
    }

    #[test]
    fn prefilter_of_zero_findings_short_circuits() {
        let (keep, dropped) = prefilter(&[], 3, false, true);
        assert!(keep.is_empty());
        assert!(dropped.is_empty());
    }

    #[test]
    fn prefilter_collapses_trivial_duplicates_and_reports_them_without_a_canonical_idx() {
        let findings = vec![
            f("a.py", 10, 10, VulnClass::Other),
            f("a.py", 11, 11, VulnClass::Other),
        ];
        let (keep, dropped) = prefilter(&findings, 3, false, true);
        assert_eq!(keep.len(), 1);
        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0].reason, DropReason::Duplicate);
        assert_eq!(dropped[0].detail, TRIVIAL_REASON);
        assert_eq!(dropped[0].canonical_idx, None);
    }

    #[test]
    fn deterministic_passes_labels_a_cross_file_collapse_as_a_flow_match() {
        let mut source_end = f("handlers.py", 37, 39, VulnClass::Injection);
        source_end.cwe = Some("CWE-78".to_string());
        source_end.source_ref = Some("handlers.py:38".to_string());
        source_end.sink_ref = Some("shell.py:6".to_string());
        let mut sink_end = f("shell.py", 5, 6, VulnClass::Injection);
        sink_end.cwe = Some("CWE-78".to_string());
        sink_end.source_ref = Some("handlers.py:38".to_string());
        sink_end.sink_ref = Some("shell.py:6".to_string());
        let (canon, reasoning) = deterministic_passes(&[source_end, sink_end], 3, false, true);
        assert_eq!(canon.get(&1), Some(&0));
        assert_eq!(reasoning[&1], FLOW_REASON);
    }

    /// The 2026-09-07 rust-axum shape: one command injection reported from
    /// the handler (source = the request field) and again from the service
    /// it calls (source = that method's parameter), same sink, same CWE.
    #[test]
    fn deterministic_passes_collapses_a_shared_sink_reported_from_two_hops() {
        let mut handler_hop = f("src/handlers.rs", 38, 44, VulnClass::Injection);
        handler_hop.cwe = Some("CWE-78".to_string());
        handler_hop.source_ref = Some("src/handlers.rs:40".to_string());
        handler_hop.sink_ref = Some("src/store.rs:123".to_string());
        let mut service_hop = f("src/service.rs", 45, 50, VulnClass::Injection);
        service_hop.cwe = Some("CWE-78".to_string());
        service_hop.source_ref = Some("src/service.rs:47".to_string());
        service_hop.sink_ref = Some("src/store.rs:123".to_string());
        let findings = vec![handler_hop, service_hop];
        let (canon, reasoning) = deterministic_passes(&findings, 3, false, true);
        assert_eq!(canon.get(&1), Some(&0));
        assert_eq!(reasoning[&1], FLOW_REASON);
        // The knob off restores the strict "same source AND sink" contract.
        assert!(deterministic_passes(&findings, 3, false, false)
            .0
            .is_empty());
    }

    #[test]
    fn deterministic_passes_labels_a_same_file_collapse_as_trivial() {
        let findings = vec![
            f("a.py", 10, 10, VulnClass::Other),
            f("a.py", 11, 11, VulnClass::Other),
        ];
        let (_, reasoning) = deterministic_passes(&findings, 3, false, true);
        assert_eq!(reasoning[&1], TRIVIAL_REASON);
    }

    #[test]
    fn deterministic_passes_labels_the_second_pass_and_only_runs_it_when_asked() {
        let mut a = f("a.ts", 12, 21, VulnClass::Other);
        a.cwe = Some("CWE-345".to_string());
        let mut b = f("a.ts", 12, 21, VulnClass::InfoLeak);
        b.cwe = Some("CWE-200".to_string());
        let findings = vec![a, b];
        assert!(deterministic_passes(&findings, 3, false, true).0.is_empty());
        let (canon, reasoning) = deterministic_passes(&findings, 3, true, true);
        assert_eq!(canon.get(&1), Some(&0));
        assert_eq!(reasoning[&1], SAME_RANGE_CWE_REASON);
    }

    #[test]
    fn merge_related_cwe_records_only_new_and_parseable_lenses() {
        let mut canon = f("a.ts", 12, 21, VulnClass::Other);
        canon.cwe = Some("CWE-345".to_string());
        let mut dup = f("a.ts", 12, 21, VulnClass::InfoLeak);
        dup.cwe = Some("CWE-200".to_string());
        merge_related_cwe(&mut canon, &dup);
        assert_eq!(canon.related_cwes, vec!["CWE-200".to_string()]);
        // The same lens twice, in any spelling, is recorded once.
        dup.cwe = Some("cwe-0200".to_string());
        merge_related_cwe(&mut canon, &dup);
        assert_eq!(canon.related_cwes, vec!["CWE-200".to_string()]);
        // The canonical's own CWE is never listed as an "also".
        dup.cwe = Some("CWE-345".to_string());
        merge_related_cwe(&mut canon, &dup);
        assert_eq!(canon.related_cwes, vec!["CWE-200".to_string()]);
        // Neither is an absent or unparseable one.
        dup.cwe = None;
        merge_related_cwe(&mut canon, &dup);
        dup.cwe = Some("CWE-unknown".to_string());
        merge_related_cwe(&mut canon, &dup);
        assert_eq!(canon.related_cwes, vec!["CWE-200".to_string()]);
    }

    #[test]
    fn merge_related_cwe_carries_forward_a_duplicates_own_related_list() {
        // A three-way cluster: the middle member already absorbed a lens
        // before itself being merged, and that lens must survive.
        let mut canon = f("a.ts", 12, 21, VulnClass::Other);
        canon.cwe = Some("CWE-345".to_string());
        let mut dup = f("a.ts", 12, 21, VulnClass::InfoLeak);
        dup.cwe = Some("CWE-200".to_string());
        dup.related_cwes = vec!["CWE-284".to_string(), "CWE-345".to_string()];
        merge_related_cwe(&mut canon, &dup);
        assert_eq!(
            canon.related_cwes,
            vec!["CWE-200".to_string(), "CWE-284".to_string()],
            "the carried CWE-345 is the canonical's own and is skipped"
        );
    }

    #[test]
    fn attach_duplicates_records_a_differing_cwe_as_a_related_lens() {
        let mut a = f("a.ts", 12, 21, VulnClass::Other);
        a.cwe = Some("CWE-345".to_string());
        let mut b = f("a.ts", 12, 21, VulnClass::InfoLeak);
        b.cwe = Some("CWE-200".to_string());
        let mut findings = vec![a, b];
        let (canonical_of, reasoning) = deterministic_passes(&findings, 3, true, true);
        attach_duplicates(&mut findings, &canonical_of, &reasoning);
        assert_eq!(findings[0].related_cwes, vec!["CWE-200".to_string()]);
    }

    #[test]
    fn prefilter_merges_cwe_lenses_only_when_enabled() {
        let mut a = f("a.ts", 12, 21, VulnClass::Other);
        a.cwe = Some("CWE-345".to_string());
        let mut b = f("a.ts", 12, 21, VulnClass::InfoLeak);
        b.cwe = Some("CWE-200".to_string());
        let findings = vec![a, b];
        let (keep, dropped) = prefilter(&findings, 3, true, true);
        assert_eq!(keep.len(), 1);
        // Neither member is CVSS-scored this early (S6 has not run), so
        // the pre-sort's later `vuln_class` key decides — `info-leak`
        // before `other` — and the surviving lens is CWE-200.
        assert_eq!(keep[0].cwe.as_deref(), Some("CWE-200"));
        assert_eq!(keep[0].related_cwes, vec!["CWE-345".to_string()]);
        assert_eq!(dropped[0].detail, SAME_RANGE_CWE_REASON);
        let (keep, dropped) = prefilter(&findings, 3, false, true);
        assert_eq!(keep.len(), 2);
        assert!(dropped.is_empty());
    }

    #[test]
    fn prefilter_survivor_of_a_cross_file_flow_is_the_sink_anchored_one() {
        let mut source_end = f("handlers.py", 37, 39, VulnClass::Injection);
        source_end.cwe = Some("CWE-78".to_string());
        source_end.source_ref = Some("handlers.py:38".to_string());
        source_end.sink_ref = Some("shell.py:6".to_string());
        let mut sink_end = f("shell.py", 5, 6, VulnClass::Injection);
        sink_end.cwe = Some("CWE-78".to_string());
        sink_end.source_ref = Some("handlers.py:38".to_string());
        sink_end.sink_ref = Some("shell.py:6".to_string());
        // `handlers.py` sorts before `shell.py` alphabetically, so only
        // the sink-anchor key can produce this result.
        let (keep, dropped) = prefilter(&[source_end, sink_end], 3, false, true);
        assert_eq!(keep.len(), 1);
        assert_eq!(keep[0].file, "shell.py");
        assert_eq!(dropped[0].file, "handlers.py");
        assert_eq!(dropped[0].detail, FLOW_REASON);
    }

    #[test]
    fn prefilter_keeps_unrelated_findings_untouched() {
        let findings = vec![
            f("a.py", 10, 10, VulnClass::Other),
            f("b.py", 900, 900, VulnClass::Injection),
        ];
        let (keep, dropped) = prefilter(&findings, 3, false, true);
        assert_eq!(keep.len(), 2);
        assert!(dropped.is_empty());
    }
}
