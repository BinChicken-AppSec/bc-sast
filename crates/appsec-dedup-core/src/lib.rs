//! Trivial same-file + same-vuln-class + line-tolerance duplicate
//! clustering, ported from the Python reference's `s7_dedup.py::
//! _collapse_trivial` / `_attach_duplicates` / `run()`. Deliberately
//! **generic over a minimal [`DedupKey`] trait rather than a concrete
//! `Finding` type** — the finding data model lives in `appsec-model` (a
//! higher tier), and this crate needs to stay dependency-free so both the
//! pre-verify (S5) and post-verify (S7) stages can share it without either
//! depending on the other or pulling in the whole domain-model crate for
//! what is, underneath, pure index arithmetic.
//!
//! What this crate does NOT own: attaching a `DupLocation` onto a
//! `Finding`, choosing reasoning text, or building a `DroppedFinding` — all
//! of that is concrete-model bookkeeping that belongs to whichever stage
//! crate has `appsec-model` in scope. This crate hands that caller exactly
//! the relationships and index bookkeeping it needs to do so
//! ([`resolve_relations`], [`partition`], [`representative_swaps`]).

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
/// `appsec-compliance/src/cwe.rs`, `appsec-policy-gate/src/cwe.rs` and
/// `appsec-stage-s4/src/cwe_kb.rs` already share — this crate is
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

/// A `file:line` reference split into its normalized path and its 1-based
/// line, or `None` when either half is missing or unusable.
///
/// Splitting on the LAST colon is what keeps a Windows drive letter
/// (`C:/src/app.c:61`) in the path rather than parsing `/src/app.c:61` as
/// a line number. A reference with no colon at all, or whose tail is not a
/// positive integer, carries no line to compare against and is `None` —
/// a line of 0 is this model's "could not locate it" encoding (the same
/// one [`collapse_same_range_cwes`] guards against with `line_start >=
/// 1`), so it is no more comparable than a missing line.
pub fn ref_file_line(raw: Option<&str>) -> Option<(String, i64)> {
    let reference = normalize_ref(raw)?;
    let (file, line) = reference.rsplit_once(':')?;
    let line: i64 = line.trim().parse().ok()?;
    if line < 1 {
        return None;
    }
    Some((normalize_ref(Some(file))?, line))
}

/// Every fix site the members of one cluster name, normalized and
/// de-duplicated, in ascending member order. Deliberately the union
/// rather than a majority vote: the two tiers that can pair anchors in
/// DIFFERENT files ([`collapse_trivial`]'s flow- and sink-identity arms)
/// require byte-identical `sink_ref`s, so a cluster with a disagreement
/// can only have come from the line-proximity, same-range or semantic
/// tiers — where every member is within a few lines of every other
/// anyway, and counting votes would buy nothing for the extra code.
///
/// Pooling the cluster's sinks rather than judging each member only by
/// its OWN `sink_ref` is what handles a member that carries no ref at
/// all: in the `c-cli` `uaf-1` shape the member sitting astride the sink
/// is precisely the one that never traced a flow, and its cluster-mate's
/// ref is the only evidence that it is the better anchor.
///
/// `source_ref` is deliberately NOT pooled in here. The fix goes at the
/// sink, which is also what `appsec_stage_s10` edits — the same reason
/// `appsec_stage_s7::sort_for_stable_canonical` already leads on
/// sink-anchoredness. Admitting source refs as candidates would let a
/// source-anchored member tie a sink-anchored one at distance 0, and the
/// tie-break (lowest index) would then be arbitrary again, which is the
/// exact defect this pass exists to remove. The benchmark scorer does
/// credit a hit near the source too, but only for ground truth that
/// records a source line at all, so preferring it would trade a certain
/// hit for a conditional one.
///
/// A ref that `appsec_stage_s5::backfill` synthesized (it fills an empty
/// `sink_ref` with the finding's own `file:line_start`) is NOT filtered
/// out, even though `Finding::backfilled_refs` records exactly which ones
/// those are, because it would cost a new [`DedupKey`] method for no
/// measured case. Such a ref makes its own member trivially distance 0,
/// which can only ever TIE a genuinely sink-anchored member and so
/// degrades this pass to "change nothing" rather than to a wrong choice —
/// and the two tiers that cluster distant or cross-file anchors both
/// require an explicit, EQUAL `sink_ref`, which a synthesized one can
/// only match on a member that already shares the line. The gap is
/// therefore limited to a semantic (7b) merge where one member's sink was
/// synthesized and another's was real.
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

/// How well `item`'s own reported range anchors one of `sinks`, as an
/// ascending sort key: `(0, distance_in_lines)` when at least one sink
/// lands in `item`'s file — distance 0 meaning the range *contains* that
/// sink line — and `(1, 0)` when none does, so an unscoreable member
/// always ranks after every scoreable one.
///
/// The distance is to the nearest end of `[line_start, line_end]`, with a
/// `line_end` below `line_start` (this model's common "unknown end"
/// encoding) read as the single start line — the same degradation
/// `appsec_sarif::fingerprint`'s `read_line_range` already applies to the
/// same two fields.
///
/// An item whose own `line_start` is below 1 is unscoreable whatever the
/// sinks say: the model failed to locate it, so its "distance" to
/// anything is noise. Same guard, same reason as
/// [`collapse_same_range_cwes`]'s.
fn anchor_rank<T: DedupKey>(item: &T, sinks: &[(String, i64)]) -> (u8, i64) {
    /// No sink to measure against. The `0` is a filler, never compared
    /// against a scoreable member's distance because the tier differs.
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

/// Group `0..len` into clusters by [`root`], each cluster's members in
/// ascending index order and therefore with its root first (every
/// `canonical_of` mapping points to a strictly lower index, so a
/// cluster's root is its minimum member). Returned in ascending-root
/// order, which is what makes [`representative_swaps`]' output
/// deterministic despite `canonical_of` being a `HashMap`.
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

/// For each cluster with more than one member, the `(root_index,
/// better_anchored_index)` pair whose exchange would put the
/// best-anchored member at the cluster's root — i.e. make it the
/// survivor, since every consumer of [`partition`] keeps the indices that
/// are not `canonical_of` keys. Clusters already represented by their
/// best-anchored member contribute nothing.
///
/// **Why this is a separate post-pass and not a better pre-sort.** The
/// caller already orders findings so that "lowest index wins" is
/// content-derived rather than arrival-derived
/// (`appsec_stage_s7::sort_for_stable_canonical`), and sharpening THAT key
/// looks like the smaller change. It is not safe: duplicate-ness here is
/// not transitive, so the input order decides how many clusters form.
/// Three findings on `app.py` lines 10, 13 and 16 under one CWE at
/// `line_tolerance` 3 collapse to TWO survivors in the order 10, 13, 16
/// (13 takes 10 as canonical; 16 is 6 lines from 10 and matches nothing
/// still canonical) and to ONE in the order 13, 10, 16 (both 10 and 16
/// are within 3 of 13) — measured, not reasoned. A re-sort therefore
/// changes the finding COUNT, which is a precision change; this pass
/// cannot, because it runs after clustering and never touches
/// `canonical_of`.
///
/// **Why it returns swaps instead of re-pointing `canonical_of`.**
/// Re-labelling the map so a higher index becomes a canonical would break
/// the "canonical is always the lower index" invariant that
/// [`CanonicalOf`], [`root`]'s acyclicity argument and
/// `appsec_stage_s7::clustering::attach_duplicates`' `split_at_mut` all rest
/// on. Exchanging the two findings' positions instead leaves every index
/// relationship exactly as clustering left it: the cluster still owns the
/// same index set, the same index is still its root, and the same indices
/// are still `canonical_of` keys — so the surviving COUNT is identical by
/// construction and only the content at the root index changes.
///
/// Exchanging positions also means the merged-away member inherits the
/// `reasoning` entry recorded for the index it moves into. That is
/// correct rather than merely convenient: every tier that can cluster two
/// findings is symmetric in them (an identical `sink_ref`, an identical
/// range, overlapping ranges, "the same data flow"), so the recorded
/// reason describes the pair, not a direction.
///
/// Ties keep the root, because `members` is in ascending index order and
/// only a strictly better rank displaces the incumbent. A cluster whose
/// members name no sink at all therefore comes out exactly as clustering
/// left it — no churn where there is no evidence to act on.
pub fn representative_swaps<T: DedupKey>(
    items: &[T],
    canonical_of: &CanonicalOf,
) -> Vec<(usize, usize)> {
    let mut swaps = Vec::new();
    for members in clusters(items.len(), canonical_of) {
        // A cluster of one is the overwhelming majority of clusters and
        // has no choice to make.
        if members.len() < 2 {
            continue;
        }
        let sinks = cluster_sinks(items, &members);
        let mut best = members[0];
        let mut best_rank = anchor_rank(&items[best], &sinks);
        for &m in &members[1..] {
            let rank = anchor_rank(&items[m], &sinks);
            // Strictly better only — see the tie rule in the docs above.
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

        /// A sink with no source — the shape `sink_anchor_rank` demotes
        /// and the one the `c-cli` field case turned on.
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

    #[test]
    fn ref_file_line_splits_a_reference_into_a_normalized_path_and_a_line() {
        assert_eq!(
            ref_file_line(Some(" ./src\\report.c:61 ")),
            Some(("src/report.c".to_string(), 61))
        );
        // Last colon wins, so a Windows drive letter stays in the path.
        assert_eq!(
            ref_file_line(Some("C:/src/report.c:61")),
            Some(("C:/src/report.c".to_string(), 61))
        );
    }

    #[test]
    fn ref_file_line_is_none_without_a_usable_path_and_positive_line() {
        // Absent, and empty after trimming — `normalize_ref`'s own cases.
        assert_eq!(ref_file_line(None), None);
        assert_eq!(ref_file_line(Some("  ")), None);
        // No colon at all: a bare path names no line.
        assert_eq!(ref_file_line(Some("report.c")), None);
        // A tail that is not a plain number.
        assert_eq!(ref_file_line(Some("report.c:sixty")), None);
        assert_eq!(ref_file_line(Some("report.c:")), None);
        // Line 0 is this model's "could not locate it" encoding, which is
        // no more comparable than a missing line.
        assert_eq!(ref_file_line(Some("report.c:0")), None);
        assert_eq!(ref_file_line(Some("report.c:-3")), None);
        // A line with no path left to attach it to.
        assert_eq!(ref_file_line(Some(":61")), None);
    }

    /// Two members, one cluster, `canonical_of` written by hand so the
    /// pass is exercised independently of which tier formed the cluster.
    fn pair_swaps(a: Item, b: Item) -> Vec<(usize, usize)> {
        representative_swaps(&[a, b], &CanonicalOf::from([(1, 0)]))
    }

    #[test]
    fn the_member_sitting_on_the_clusters_sink_becomes_the_survivor() {
        // The measured `c-cli` `fmtstr-1` shape: ground truth at
        // `report.c:61`, the incumbent canonical anchored in another file
        // entirely because it carries the flow's source end.
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
        // Same pair, already in the right order: no swap, no churn.
        let swaps = pair_swaps(
            Item::new("report.c", "format-string", 59, 63).with_sink("report.c:61"),
            Item::new("main.c", "format-string", 35, 39).with_flow("main.c:37", "report.c:61"),
        );
        assert!(swaps.is_empty());
    }

    #[test]
    fn distance_to_the_sink_decides_between_two_members_in_its_own_file() {
        // Both anchored in the sink's file, so a file-level test ties and
        // only the line distance separates them. Sink ABOVE one range and
        // BELOW the other, so both distance arms are exercised.
        let swaps = pair_swaps(
            Item::new("report.c", "format-string", 80, 90).with_sink("report.c:61"),
            Item::new("report.c", "format-string", 55, 58).with_sink("report.c:61"),
        );
        assert_eq!(swaps, [(0, 1)]);
    }

    #[test]
    fn a_member_with_no_sink_of_its_own_is_scored_against_the_clusters() {
        // `replay.c:45-47` names no sink, but its cluster does, and it is
        // the member that contains it. The incumbent's own sink is what
        // reveals that — the whole point of pooling the cluster's sinks
        // rather than judging each member only by its own ref.
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
        // `line_start` 0 is "the model could not locate this" — the same
        // guard, and the same reason, as `collapse_same_range_cwes`'.
        // Without it, a 0..=70 range would "contain" the sink at 61.
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
        // `line_end` 0 against `line_start` 61 must not make the range
        // empty-or-inverted: it degrades to line 61 alone, which IS the
        // sink, so this member wins. Same degradation
        // `appsec_sarif::fingerprint`'s `read_line_range` applies.
        let swaps = pair_swaps(
            Item::new("report.c", "format-string", 50, 55).with_sink("report.c:61"),
            Item::new("report.c", "format-string", 61, 0).with_sink("report.c:61"),
        );
        assert_eq!(swaps, [(0, 1)]);
    }

    #[test]
    fn a_sink_in_another_file_cannot_score_a_member() {
        // The only sink the cluster names lives somewhere neither member
        // is anchored, so nothing is scoreable and nothing moves.
        let swaps = pair_swaps(
            Item::new("a.py", "injection", 10, 12).with_sink("elsewhere.py:900"),
            Item::new("a.py", "injection", 11, 13).with_sink("elsewhere.py:900"),
        );
        assert!(swaps.is_empty());
    }

    #[test]
    fn the_nearest_of_several_sinks_the_cluster_names_is_the_one_scored() {
        // Members disagree on the sink, so the union holds two. The
        // second member is 1 line from `report.c:70` even though it is 11
        // from `report.c:58`, and taking the nearest is what lets it win.
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
        // Both spellings normalize to one reference, so the pool holds a
        // single entry rather than two copies of it.
        assert_eq!(
            cluster_sinks(&items, &[0, 1]),
            [("report.c".to_string(), 61)]
        );
    }

    #[test]
    fn a_chained_cluster_is_grouped_under_its_root_and_repicked_once() {
        // 2 -> 1 -> 0, the shape a caller's semantic pass can build on
        // top of the deterministic one. All three are one cluster, and
        // the best-anchored member is the last.
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
        // `canonical_of` is a `HashMap`, so this is the determinism the
        // ascending-root grouping exists to guarantee.
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
        // The guarantee the pass is built to make: it returns POSITIONS to
        // exchange and never touches `canonical_of`, so the key set
        // `partition` splits on is untouched whatever the swaps say.
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
