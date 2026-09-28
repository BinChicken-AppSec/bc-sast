//! Trivial same-file + same-vuln-class + line-tolerance duplicate
//! clustering, ported from the Python reference's `s7_dedup.py::
//! _collapse_trivial` / `_attach_duplicates` / `run()`. Deliberately
//! **generic over a minimal [`DedupKey`] trait rather than a concrete
//! `Finding` type** — the finding data model lives in `bc-model` (a
//! higher tier), and this crate needs to stay dependency-free so both the
//! pre-verify (S5) and post-verify (S7) stages can share it without either
//! depending on the other or pulling in the whole domain-model crate for
//! what is, underneath, pure index arithmetic.
//!
//! What this crate does NOT own: attaching a `DupLocation` onto a
//! `Finding`, choosing reasoning text, or building a `DroppedFinding` — all
//! of that is concrete-model bookkeeping that belongs to whichever stage
//! crate has `bc-model` in scope. This crate hands that caller exactly
//! the relationships and index bookkeeping it needs to do so
//! ([`resolve_relations`], [`partition`]).

use std::collections::{HashMap, HashSet};

/// The minimal shape the clustering algorithm needs from a finding-like
/// item. Implement this for `Finding` (or a lightweight view over it) at
/// the call site — this crate never needs to know the rest of the shape.
pub trait DedupKey {
    fn file(&self) -> &str;
    fn vuln_class(&self) -> &str;
    fn line_start(&self) -> i64;
    fn line_end(&self) -> i64;
    /// `None` when the CWE wasn't determined yet (common pre-S6) — see
    /// `collapse_trivial`'s own doc comment for how that's treated
    /// differently from an explicit mismatch.
    fn cwe(&self) -> Option<&str>;
    /// Where the tainted data enters, as a `file:line` string. Optional:
    /// the default `None` keeps every pre-existing implementor compiling
    /// and simply opts that implementor out of the flow-identity tier
    /// (see [`collapse_trivial`]).
    fn source_ref(&self) -> Option<&str> {
        None
    }
    /// Where it reaches the dangerous operation, as a `file:line` string.
    /// See [`DedupKey::source_ref`].
    fn sink_ref(&self) -> Option<&str> {
        None
    }
}

/// `duplicate_index -> canonical_index` (direct, single-level — may need
/// [`root`] to resolve a chain if a later pass, e.g. semantic dedup, adds
/// entries on top of this one). The canonical is always the lower index.
pub type CanonicalOf = HashMap<usize, usize>;

/// The CWE's numeric identity (`CWE-89`, `cwe-89` and `CWE-0089` all
/// yield `89`), or `None` when the token is absent, empty, or not a
/// recognizable `CWE-<digits>` / `<digits>` shape.
///
/// A deliberate small local copy of the normalization
/// `bc-compliance/src/cwe.rs`, `bc-policy-gate/src/cwe.rs` and
/// `bc-stage-s4/src/cwe_kb.rs` already share — this crate is
/// dependency-free on purpose (see the module doc), and one bounded
/// integer parse is not worth coupling it to the domain-model tier.
/// Comparing the parsed number rather than the rendered string is what
/// makes the zero-padded and lower-case spellings compare equal.
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

/// A `file:line` reference reduced to a comparable form: surrounding
/// whitespace gone, Windows separators folded to `/`, and any number of
/// leading `./` segments stripped, so `./lib/shell.py:6`, `lib\shell.py:6`
/// and ` lib/shell.py:6 ` are one reference. `None` for an absent or
/// (after trimming) empty token — an unset ref must never compare equal to
/// another unset ref, or every finding without dataflow refs would
/// suddenly share a "flow".
///
/// Deliberately NOT case-folded: paths are case-sensitive on the platform
/// the scanner actually runs its repos on, and folding them would let
/// `Auth.ts:6` and `auth.ts:6` claim to be the same sink.
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

/// `(source_ref, sink_ref)` normalized, and only when BOTH are present —
/// the identity of a dataflow, or `None` when this item doesn't carry one.
fn flow_identity<T: DedupKey>(item: &T) -> Option<(String, String)> {
    Some((
        normalize_ref(item.source_ref())?,
        normalize_ref(item.sink_ref())?,
    ))
}

/// The normalized `sink_ref` alone — the identity of a *fix site*, which
/// is what [`collapse_trivial`]'s same-sink tier keys on.
fn sink_identity<T: DedupKey>(item: &T) -> Option<String> {
    normalize_ref(item.sink_ref())
}

/// Deterministic dedup pass: two items are duplicates when they describe
/// the same vulnerability (see below), pass the CWE guard, and are
/// co-located — either by **flow identity** (both carry the same
/// `source_ref` *and* the same `sink_ref`, in which case the `file` need
/// not match at all), by **sink identity** when `merge_same_sink` is on
/// (the same normalized `sink_ref` under an explicit, equal CWE — see
/// below), or by sharing a `file` and having `line_start`
/// values within `line_tolerance` or overlapping
/// `[line_start, line_end]` ranges (re-detection of the same region at
/// slightly different boundaries across runs). For each item
/// (in order), the first still-canonical earlier item it matches becomes
/// its canonical; no model call, no allocation beyond the returned map
/// and one normalized ref pair per item.
///
/// **Flow identity.** Net-new versus `s7_dedup.py`, which keys everything
/// off the anchor file and therefore cannot see this shape at all. A live
/// 2026-09-06 scan of a 5-file Flask app reported ONE command injection
/// twice: once anchored at the source end (`handlers.py:37-39`) and once
/// at the sink end (`shell.py:5-6`), with byte-identical
/// `source_ref` (`handlers.py:38`) and `sink_ref` (`shell.py:6`), the
/// same `CWE-78` and the same class. Because the two anchor *files*
/// differ, no same-file rule can ever collapse them, and the second copy
/// burned a whole S10 remediation cycle. Two findings that agree on both
/// ends of the flow ARE the same flow; the anchor is just which end the
/// model chose to report from. The same-vulnerability test and the CWE
/// guard below still apply on this path — an equal flow reported under
/// two genuinely different CWEs is two lenses on one flow, not one
/// finding, and is left to
/// [`collapse_same_range_cwes`]/the verifier to reconcile.
///
/// **Sink identity** (`merge_same_sink`). Also net-new. A live 2026-09-07
/// polyglot run reported one command injection twice on `rust-axum`: once
/// anchored on the handler (`source_ref` = the request field) and once on
/// the service method it calls (`source_ref` = that method's parameter),
/// both with `sink_ref` `src/store.rs:123` and `CWE-78`. The model
/// labels the "source" at whichever hop it is looking at, so the full
/// `(source, sink)` pair differs for what is one flow with one fix site.
/// Two findings with the same normalized `sink_ref` and an explicit,
/// equal CWE are therefore one finding; the merged-away copy keeps its
/// own `source_ref` in the survivor's duplicate list, so a genuinely
/// second tainted input reaching the same call is recorded, not lost.
/// The CWE must agree explicitly here — class-string agreement is not
/// enough to override two different anchor files.
///
/// **Same-vulnerability test.** An explicit, equal CWE on both sides is
/// sufficient on its own; otherwise the `vuln_class` strings must match.
///
/// This is a deliberate divergence from `s7_dedup.py::_collapse_trivial`,
/// which gates on `a.vuln_class != b.vuln_class` alone and therefore
/// never collapses the case below. A live scan of a Flask app on
/// 2026-09-03 reported one SQL injection twice — `app.py:14-22` classed
/// `other` and `app.py:17-21` classed `injection`, both `CWE-89`, ranges
/// nested — and one command injection twice the same way, because the
/// model labels the same vulnerability differently in different chunks
/// while getting the CWE right. Each duplicate then burned a whole S10
/// remediation cycle that concluded "already fixed". The CWE is the
/// reliable identity here; the class string is not.
///
/// **CWE guard**, ported from that same function's `_STRICT_CWE_CLASS`
/// handling: for a `vuln_class` in `strict_cwe_classes` (the Python
/// original hardcodes just the logic-bug class here — missing CWE is
/// common at this point in a real run, and collapsing two logic-bug
/// findings pre-S6 purely on file+line proximity risks hiding a true
/// positive), a collapse requires an EXPLICIT, EQUAL CWE on both sides —
/// either side missing it blocks the collapse. Checked against BOTH
/// sides' classes, since the relaxation above means the two can now
/// differ. For every other class, only an explicit *mismatch* blocks a
/// collapse; a missing CWE on either or both sides doesn't, and falls
/// through to the line-proximity check as before.
pub fn collapse_trivial<T: DedupKey>(
    items: &[T],
    line_tolerance: i64,
    strict_cwe_classes: &HashSet<&str>,
    merge_same_sink: bool,
) -> CanonicalOf {
    // Normalized once per item rather than once per candidate pair: the
    // loop below is O(n²) and `normalize_ref` allocates.
    let flows: Vec<Option<(String, String)>> = items.iter().map(flow_identity).collect();
    let sinks: Vec<Option<String>> = items.iter().map(sink_identity).collect();
    let mut canonical_of = CanonicalOf::new();
    for j in 0..items.len() {
        // No "if j already canonical, skip" guard here (unlike the inner
        // loop's `i` check below, which is load-bearing): `canonical_of`
        // can only ever gain a key equal to the *current* j, inserted
        // later in this same iteration, so a fresh outer j can never
        // already be a key when the loop reaches it.
        for i in 0..j {
            if canonical_of.contains_key(&i) {
                continue;
            }
            let a = &items[i];
            let b = &items[j];
            // Flow identity substitutes for BOTH the same-file requirement
            // and the line-proximity test below: the two anchors are by
            // construction at opposite ends of one flow, so neither their
            // files nor their line numbers can be expected to agree.
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
            // Sink identity needs the explicit CWE agreement: it is the
            // only tier that can pair two anchor files on one ref.
            let same_sink = same_sink_ref && cwe_agrees;
            let strict = strict_cwe_classes.contains(a.vuln_class())
                || strict_cwe_classes.contains(b.vuln_class());
            if strict {
                // Logic-bug bucket: an explicit, equal CWE is mandatory,
                // whichever side carries the strict class.
                if !cwe_agrees {
                    continue;
                }
            } else if !cwe_agrees {
                // No CWE agreement to lean on, so fall back to the class
                // string — and let an explicit CWE mismatch veto it.
                if a.vuln_class() != b.vuln_class() {
                    continue;
                }
                // Two CWEs that are both present but do not agree is
                // exactly what reaching here with both set means, so
                // their presence alone is the veto.
                if ca.is_some() && cb.is_some() {
                    continue;
                }
            }
            let close = (a.line_start() - b.line_start()).abs() <= line_tolerance;
            let overlap = a.line_start() <= b.line_end() && b.line_start() <= a.line_end();
            // Line proximity only ever means anything within one file.
            let colocated = same_file && (close || overlap);
            if same_flow || same_sink || colocated {
                canonical_of.insert(j, i);
                break;
            }
        }
    }
    canonical_of
}

/// A second, deliberately narrower deterministic pass: collapse two
/// findings that describe **the exact same code range under two different
/// CWEs**, adding to (never removing from) `canonical_of` and returning
/// the `(duplicate_idx, canonical_idx)` pairs it added so the caller can
/// record the merged-away CWE on the survivor.
///
/// Net-new versus `s7_dedup.py`, which has no equivalent: there, a CWE
/// *mismatch* is an outright veto (see [`collapse_trivial`]'s CWE guard),
/// so the same lines reported under four CWEs stay four findings forever.
/// A live 2026-09-06 scan of OWASP Juice Shop produced 11 findings for 3
/// near-identical functions in `routes/continueCode.ts` — for each one,
/// `CWE-798` "Hardcoded salt" on line 13 plus `CWE-345`, `CWE-284` and
/// `CWE-200` all on lines 12-21: one code range seen through four
/// lenses, each costing its own verification call, its own report entry
/// and its own remediation attempt.
///
/// The rule is deliberately much stricter than [`collapse_trivial`]'s:
///
/// * same `file`;
/// * **exactly equal** `(line_start, line_end)` — not "within tolerance",
///   not "overlapping". Two lenses on one range agree on the range
///   precisely because they are looking at the same lines; a tolerance
///   here would start merging genuinely adjacent-but-distinct bugs that
///   only the differing CWE distinguishes;
/// * `line_start >= 1`, so two findings the model failed to locate at all
///   (both at line 0) are never merged into each other;
/// * an explicit, *parseable*, *different* CWE on **both** sides. Equal
///   CWEs are already [`collapse_trivial`]'s job, and a missing CWE on
///   either side leaves nothing to justify overriding its veto;
/// * neither side's `vuln_class` is in `strict_cwe_classes` — the
///   logic-flaw guard stands unchanged, and by construction this pass can
///   never satisfy its "explicit, EQUAL CWE" requirement anyway.
///
/// `vuln_class` is deliberately *not* compared: the whole point is that
/// the four lenses in the field case labeled the same lines
/// `other`/`info-leak`/`logic-flaw`-ish differently.
///
/// Like [`collapse_trivial`], an index already present as a key is a
/// resolved duplicate and is skipped on both sides, so the "lowest index
/// wins" invariant [`partition`] and [`resolve_relations`] rely on holds
/// for the combined map.
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

/// Resolve `i` through `canonical_of` to its ultimate root. Cycle-guarded
/// even though a cycle can't arise from legitimate input (every mapping
/// this crate or the semantic-dedup caller adds points to a strictly lower
/// index, so a cycle is mathematically impossible) — kept as a normal,
/// directly-testable safety net rather than an unguarded loop.
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

/// One resolved duplicate relationship, with the duplicate's canonical
/// fully resolved through any transitive chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DupRelation {
    pub duplicate_idx: usize,
    pub canonical_idx: usize,
    /// True when the duplicate's and canonical's `[line_start, line_end]`
    /// ranges overlap — a re-detection of the same call site, not an
    /// additional one. The caller uses this to decide whether the
    /// duplicate should be recorded as an extra location on the canonical
    /// (only when `!same_site`), matching the Python original's
    /// `_attach_duplicates` behavior.
    pub same_site: bool,
}

/// For every entry in `canonical_of`, resolve its root and classify the
/// site relationship, in ascending duplicate-index order (matching the
/// Python original's dict-iteration-plus-root-resolution shape closely
/// enough to be a drop-in for a caller building `DupLocation`s from it).
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

/// The result of splitting `0..len` into surviving (canonical) indices and
/// dropped (duplicate) indices, with a remapping from each surviving
/// original index to its position in the compacted `kept_indices` list —
/// exactly what a caller needs to build the new canonical `Vec<Finding>`
/// and each `DroppedFinding.canonical_idx` pointer into it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Partition {
    pub kept_indices: Vec<usize>,
    pub new_index_of: HashMap<usize, usize>,
    pub dropped_indices: Vec<usize>,
}

/// Split `0..len` by `canonical_of` (any index present as a *key* is a
/// duplicate and is dropped; everything else survives), in original
/// order.
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

    /// An implementor that takes the `DedupKey` default `source_ref`/
    /// `sink_ref` bodies — the compatibility promise those defaults exist
    /// for, exercised rather than assumed.
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
            Item::new("b.rs", "injection", 10, 10), // different file
            Item::new("a.rs", "xss", 10, 10),       // different class
        ];
        assert!(collapse_trivial(&items, 100, &no_strict_classes(), true).is_empty());
    }

    #[test]
    fn close_line_start_within_tolerance_collapses() {
        let items = [
            Item::new("a.rs", "injection", 10, 10),
            Item::new("a.rs", "injection", 12, 12), // diff 2, tol 3
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
        // line_start diff is 15 (beyond a tol of 3), but the ranges overlap.
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
            Item::new("a.rs", "injection", 11, 11), // no CWE at all
            Item::new("a.rs", "injection", 12, 12).with_cwe("CWE-89"),
        ];
        // Item 1 (no CWE) collapses onto item 0 by proximity alone.
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
            Item::new("a.rs", "logic-flaw", 11, 11), // no CWE
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
        // Three findings at 10, 12, 14 with tol=2: item 1 (line 12) matches
        // item 0 (line 10) directly (diff 2) and collapses onto it. Item 2
        // (line 14) is then checked against i=0 (diff 4, exceeds tol, no
        // overlap for point ranges) and i=1 — but i=1 is SKIPPED because
        // it is itself already a duplicate (a key in canonical_of), not a
        // still-canonical item. So item 2 does NOT chain onto item 1 by
        // proximity to it; it stays independent. (This is why "transitive
        // chain resolution" — see `root` — matters for the *combination*
        // of this deterministic pass with a later semantic pass that might
        // add a second-level mapping, not for this pass alone.)
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
        // With tol=4, item 2 (line 14) matches item 0 (line 10, diff 4)
        // directly on the FIRST comparison attempt (i=0 is tried before
        // i=1), so both 1 and 2 collapse straight onto 0 without ever
        // needing to go through item 1.
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
        assert_eq!(root(&c, 0), 0); // not a key at all — root of itself
    }

    #[test]
    fn root_cycle_guard_terminates_on_a_malformed_map() {
        // Can't arise from collapse_trivial's own output (every mapping
        // points strictly lower), but root() must still terminate rather
        // than loop forever if handed a malformed map from elsewhere.
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
        // Simulate a semantic-dedup pass adding a second-level mapping on
        // top of the deterministic one: 2 -> 1 -> 0.
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
        assert_eq!(rels[1].canonical_idx, 0); // resolved through the chain
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

    // End-to-end scenario mirroring the Python docstring's worked example:
    // three near-identical findings collapse to one canonical.
    #[test]
    fn end_to_end_three_near_identical_findings_collapse_to_one() {
        let items = [
            Item::new("auth.rs", "sqli", 100, 100),
            Item::new("auth.rs", "sqli", 102, 102),
            Item::new("auth.rs", "sqli", 104, 104),
            Item::new("other.rs", "sqli", 5, 5),
        ];
        // tol=4 so all three match directly against index 0 (see
        // `generous_tolerance_collapses_all_directly_onto_the_first` for
        // why a tighter tolerance would leave item 2 independent instead).
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
        // No `rstest` here: this crate is deliberately dependency-free,
        // dev-dependencies included.
        for raw in [
            None,
            Some(""),
            Some("CWE-"),
            Some("CWE-injection"),
            Some("CWE-89a"),
            // Multi-byte and shorter than the prefix — `get(..4)` must
            // not panic on a non-char-boundary slice.
            Some("Ω"),
            Some("CWE-99999999999"), // overflows u32
        ] {
            assert_eq!(cwe_number(raw), None, "expected None for {raw:?}");
        }
    }

    // The field case this relaxation exists for, verbatim from a live
    // 2026-09-03 scan of a Flask app: one SQL injection and one command
    // injection each reported twice, differing only in the model's
    // `vuln_class` label, with equal CWEs and nested line ranges. Before
    // the CWE-first identity test, this collapsed nothing at all.
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
        // One side's CWE is missing, so there is nothing to agree on and
        // the class strings have to carry the decision — as before.
        let items = [
            Item::new("a.py", "other", 10, 12).with_cwe("CWE-89"),
            Item::new("a.py", "injection", 11, 13),
        ];
        assert!(collapse_trivial(&items, 2, &no_strict_classes(), true).is_empty());
    }

    #[test]
    fn same_class_but_conflicting_explicit_cwes_still_do_not_collapse() {
        // The class strings agree, so the fallback path is taken, but the
        // two explicit CWEs disagree — that veto predates the CWE-first
        // relaxation and must survive it.
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

    // ── Flow identity (source_ref + sink_ref) ───────────────────────

    #[test]
    fn the_default_source_and_sink_refs_are_absent() {
        assert_eq!(RefLessItem.source_ref(), None);
        assert_eq!(RefLessItem.sink_ref(), None);
        // And a list of them collapses purely on the file/line rules,
        // never on a phantom "both flows are None" equality.
        let items = [RefLessItem, RefLessItem];
        assert_eq!(
            collapse_trivial(&items, 0, &no_strict_classes(), true).get(&1),
            Some(&0)
        );
    }

    /// The 2026-09-06 field case, verbatim: a 5-file Flask app reported
    /// ONE command injection twice — once anchored at the source end
    /// (`handlers.py:37-39`) and once at the sink end (`shell.py:5-6`) —
    /// with identical `source_ref`/`sink_ref`, the same `CWE-78` and the
    /// same class. Different anchor files, so no same-file rule could
    /// ever see it, and the copy cost a whole wasted remediation cycle.
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
        // Only the sink matches; the source is missing on one side. Flow
        // identity says nothing, but the sink tier does: one fix site,
        // one CWE.
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
        // With the sink tier off, the differing files veto as before.
        assert!(collapse_trivial(&items, 3, &no_strict_classes(), false).is_empty());
    }

    #[test]
    fn a_differing_sink_is_never_the_same_flow_and_a_shared_sink_needs_the_cwe() {
        let items = [
            Item::new("handlers.py", "injection", 37, 39)
                .with_cwe("CWE-78")
                .with_flow("handlers.py:38", "shell.py:6"),
            // Same sink, different source, same CWE: the 2026-09-07
            // rust-axum shape — one command injection reported from the
            // handler and again from the service it calls. One fix site.
            Item::new("other.py", "injection", 5, 6)
                .with_cwe("CWE-78")
                .with_flow("other.py:2", "shell.py:6"),
            // Same source, different sink: two fix sites, two findings.
            Item::new("elsewhere.py", "injection", 5, 6)
                .with_cwe("CWE-78")
                .with_flow("handlers.py:38", "eval.py:9"),
            // Same sink, different CWE: two lenses, left to the verifier.
            Item::new("another.py", "injection", 5, 6)
                .with_cwe("CWE-77")
                .with_flow("another.py:2", "shell.py:6"),
        ];
        let c = collapse_trivial(&items, 3, &no_strict_classes(), true);
        assert_eq!(c.get(&1), Some(&0));
        assert!(!c.contains_key(&2));
        assert!(!c.contains_key(&3));
        // The old contract, still available: sink tier off.
        assert!(collapse_trivial(&items, 3, &no_strict_classes(), false).is_empty());
    }

    #[test]
    fn flow_identity_still_honors_the_cwe_and_class_guards() {
        // Same flow, but the two CWEs are explicit and disagree: two
        // lenses on one flow, not one finding.
        let items = [
            Item::new("handlers.py", "injection", 37, 39)
                .with_cwe("CWE-78")
                .with_flow("handlers.py:38", "shell.py:6"),
            Item::new("shell.py", "injection", 5, 6)
                .with_cwe("CWE-77")
                .with_flow("handlers.py:38", "shell.py:6"),
        ];
        assert!(collapse_trivial(&items, 3, &no_strict_classes(), true).is_empty());

        // Strict class with no CWE at all: still blocked.
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
        // Only a LEADING `./` is redundant — `../` means something and is
        // left exactly as it is.
        assert_eq!(
            normalize_ref(Some("../a.py:1")).as_deref(),
            Some("../a.py:1")
        );
        assert_eq!(
            normalize_ref(Some("lib\\a.py:1")).as_deref(),
            Some("lib/a.py:1")
        );
        // Repeated `./` segments, and a `.\` that only becomes one after
        // the separator fold.
        assert_eq!(
            normalize_ref(Some(".\\./a.py:1")).as_deref(),
            Some("a.py:1")
        );
        assert_eq!(normalize_ref(None), None);
        assert_eq!(normalize_ref(Some("")), None);
        assert_eq!(normalize_ref(Some("   ")), None);
        // Nothing but separators: normalizes away to nothing.
        assert_eq!(normalize_ref(Some("./")), None);
        // Case is preserved — paths are case-sensitive.
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

    // ── Same range, different CWEs ──────────────────────────────────

    /// The 2026-09-06 Juice Shop field case, verbatim: one function in
    /// `routes/continueCode.ts` reported four times — `CWE-798`
    /// "Hardcoded salt" on line 13 and `CWE-345`/`CWE-284`/`CWE-200` all
    /// on lines 12-21. Only the three that share an *exact* range merge;
    /// the line-13 one keeps its own entry because its range differs.
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
        // Nothing collapses on the existing rules: every pair either
        // disagrees on an explicit CWE or is out of range.
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
        // Equal CWEs are `collapse_trivial`'s business, not this pass's.
        let equal = [
            Item::new("a.ts", "other", 12, 21).with_cwe("CWE-345"),
            Item::new("a.ts", "injection", 12, 21).with_cwe("cwe-0345"),
        ];
        let mut c = CanonicalOf::new();
        assert!(collapse_same_range_cwes(&equal, &mut c, &strict).is_empty());
        // A missing CWE on either side leaves nothing to justify the merge.
        let missing = [
            Item::new("a.ts", "other", 12, 21).with_cwe("CWE-345"),
            Item::new("a.ts", "injection", 12, 21),
        ];
        let mut c = CanonicalOf::new();
        assert!(collapse_same_range_cwes(&missing, &mut c, &strict).is_empty());
        // As does an unparseable one.
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
        // Different files.
        let other_file = [
            Item::new("a.ts", "other", 12, 21).with_cwe("CWE-345"),
            Item::new("b.ts", "other", 12, 21).with_cwe("CWE-284"),
        ];
        let mut c = CanonicalOf::new();
        assert!(collapse_same_range_cwes(&other_file, &mut c, &strict).is_empty());
        // Strict class on either side.
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
        // Two findings the model never located (line 0) are not "the same
        // range" in any meaningful sense.
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
            // Collapses onto 0 in the first pass (same class, no CWE).
            Item::new("a.ts", "other", 12, 21),
            Item::new("a.ts", "info-leak", 12, 21).with_cwe("CWE-200"),
        ];
        let strict = no_strict_classes();
        let mut canonical_of = collapse_trivial(&items, 3, &strict, true);
        assert_eq!(canonical_of.get(&1), Some(&0));
        let merged = collapse_same_range_cwes(&items, &mut canonical_of, &strict);
        // 2 merges onto 0, never onto the already-duplicate 1.
        assert_eq!(merged, vec![(2, 0)]);
        assert_eq!(canonical_of.get(&2), Some(&0));
    }

    #[test]
    fn same_range_merge_never_makes_an_already_resolved_duplicate_a_canonical() {
        let items = [
            // Not the same range as item 2, so it cannot absorb it.
            Item::new("a.ts", "other", 30, 31).with_cwe("CWE-345"),
            // Collapses onto 0 in the first pass (same class, no CWE of
            // its own, ranges overlap) — so it is a duplicate, not a
            // candidate canonical, even though its range matches item 2's
            // exactly.
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
        // Strict class on the SECOND item only; no CWE to satisfy the
        // guard with, so the relaxation must not let this through.
        let items = [
            Item::new("a.py", "other", 10, 12),
            Item::new("a.py", "logic-flaw", 11, 13),
        ];
        assert!(collapse_trivial(&items, 2, &strict, true).is_empty());
        // With an explicit, equal CWE the guard is satisfied.
        let items = [
            Item::new("a.py", "other", 10, 12).with_cwe("CWE-20"),
            Item::new("a.py", "logic-flaw", 11, 13).with_cwe("CWE-20"),
        ];
        assert_eq!(collapse_trivial(&items, 2, &strict, true).get(&1), Some(&0));
    }
}
