//! Deterministic fix-validation scoring engine, ported from
//! `vvaharness/validation/scoring/` (`_engine.py`, `_justify.py`,
//! `_configs.py`, `constants/scoring.py`, `models/scoring.py`,
//! `enums/{gates,verdicts,readiness}.py`). Grades one already-remediated
//! finding against 4 weighted gates and derives a Fixed/Partially Fixed/
//! Not Fixed/UNVERIFIABLE verdict.
//!
//! Pure logic, no I/O — `bc-stage-s11` runs the 2-persona LLM panel that
//! produces the [`GateResult`]s this crate scores, and synthesizes a
//! single set from their two independent opinions before calling
//! [`score_fix`].
//!
//! **Scoped from the Python original**: the Python engine is a generic,
//! reusable scoring config (`ScoringConfig`) shared across multiple
//! scoring paths in that codebase; this port only ever needs the ONE
//! "fix validation" shape (4 gates, `no_new_vulnerabilities` +
//! `root_cause` critical — see [`CRITICAL_GATES`]), so that one shape is
//! hardcoded here rather than re-built as a pluggable abstraction with a
//! single caller.

use std::collections::BTreeSet;

mod vocab;

pub use vocab::{not_remediated, verdict_state, CaseState, Decision, Rollup, ValidationCounts};

/// The 4 gates a fix is scored against — the Python original's 5th gate
/// (`branch_targeting`) was already dropped upstream of this port ("Four
/// renormalized gates (branch_targeting dropped...)",
/// `constants/scoring.py`), so there is nothing further to drop here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GateName {
    RootCause,
    InstanceCoverage,
    NoNewVulnerabilities,
    SecurityBestPractices,
}

impl GateName {
    pub const ALL: [GateName; 4] = [
        GateName::RootCause,
        GateName::InstanceCoverage,
        GateName::NoNewVulnerabilities,
        GateName::SecurityBestPractices,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            GateName::RootCause => "root_cause",
            GateName::InstanceCoverage => "instance_coverage",
            GateName::NoNewVulnerabilities => "no_new_vulnerabilities",
            GateName::SecurityBestPractices => "security_best_practices",
        }
    }

    /// `None` for anything not one of the 4 canonical names — the caller
    /// (`bc-stage-s11`, parsing agent JSON) drops an entry it can't name
    /// rather than passing a placeholder through, so an unrecognized gate
    /// name naturally shows up as a *missing* gate to [`score_fix`]'s
    /// shape check (fail-closed to `Unverifiable`) instead of ever
    /// panicking on an unmappable value.
    pub fn parse(s: &str) -> Option<GateName> {
        match s {
            "root_cause" => Some(GateName::RootCause),
            "instance_coverage" => Some(GateName::InstanceCoverage),
            "no_new_vulnerabilities" => Some(GateName::NoNewVulnerabilities),
            "security_best_practices" => Some(GateName::SecurityBestPractices),
            _ => None,
        }
    }

    fn weight(self) -> f64 {
        match self {
            GateName::RootCause => 0.43,
            GateName::InstanceCoverage => 0.2467,
            GateName::NoNewVulnerabilities => 0.1867,
            GateName::SecurityBestPractices => 0.1366,
        }
    }
}

/// The critical gates: neither can be skipped/garbled (→ `Unverifiable`),
/// and either being not-clean caps the verdict below `Fixed`, regardless
/// of the numeric score. `RootCause` joined `NoNewVulnerabilities` here
/// upstream in Python (`_configs.py`'s `FIX_CONFIG.critical_criteria`):
/// leaving `root_cause` unevaluated strands 43% of the score, so without
/// this a fix nobody assessed could still read as `Fixed` on the
/// remaining gates.
pub const CRITICAL_GATES: [GateName; 2] = [GateName::NoNewVulnerabilities, GateName::RootCause];

/// Per-gate evaluation outcome reported by the scoring agent(s).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateStatus {
    Pass,
    Partial,
    Fail,
    Skip,
    /// A non-recognized status — scored `0.0` and (unlike `Skip`) kept in
    /// the renormalization denominator, so a garbled report drags the
    /// score down rather than vanishing. Never something a well-formed
    /// agent response is expected to emit intentionally; it's the
    /// fail-closed target of [`GateStatus::parse`].
    Invalid,
}

impl GateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            GateStatus::Pass => "pass",
            GateStatus::Partial => "partial",
            GateStatus::Fail => "fail",
            GateStatus::Skip => "skip",
            GateStatus::Invalid => "invalid",
        }
    }

    /// Case/whitespace-tolerant; anything out of vocabulary fails closed
    /// to `Invalid` — never silently treated as `Skip` (which would drop
    /// it from scoring entirely instead of penalizing it).
    pub fn parse(s: &str) -> GateStatus {
        match s.trim().to_ascii_lowercase().as_str() {
            "pass" => GateStatus::Pass,
            "partial" => GateStatus::Partial,
            "fail" => GateStatus::Fail,
            "skip" => GateStatus::Skip,
            _ => GateStatus::Invalid,
        }
    }

    fn multiplier(self) -> f64 {
        match self {
            GateStatus::Pass => 1.0,
            GateStatus::Partial => 0.5,
            GateStatus::Fail | GateStatus::Skip | GateStatus::Invalid => 0.0,
        }
    }
}

/// How strongly the persona panel agreed on one *synthesized* gate.
///
/// Ported from `vvaharness/validation/enums/synthesis.py::
/// SynthesisConfidence`. Deliberately **not** the same concept as this
/// module's private `confidence(raw_score)` helper, which is the numeric
/// percentage printed in justification prose — this one is a
/// panel-agreement label, and only [`SynthesisConfidence::Flagged`] has
/// any effect on scoring (see [`consensus_error`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SynthesisConfidence {
    /// Two or more personas independently reported the same non-`Skip`
    /// status for this gate.
    High,
    /// The top-voted statuses tied one step apart on the severity scale
    /// (`pass` against `partial`, or `partial` against `fail`). The
    /// conservative status stands and scores normally.
    ///
    /// This is not consensus, but it is not a contradiction about
    /// whether the fix works either: the personas agree the change does
    /// something and differ only on how complete it is, which is the
    /// disagreement the scoring rules were built to express — `Partial`
    /// already earns half credit, and a partial critical gate is already
    /// capped out of `Fixed`. Failing the whole fix closed on it instead
    /// would discard the very verdict those rules exist to produce.
    Split,
    /// No panel consensus: a contradiction about whether the fix works
    /// (`pass` against `fail`), any tie involving `Invalid`, a
    /// three-way tie, exactly one non-`Skip` vote, or every persona
    /// skipping the gate.
    Flagged,
}

impl SynthesisConfidence {
    /// The wire form. `HIGH`/`FLAGGED` match Python's
    /// `constants/synthesis.py` `CONFIDENCE_HIGH`/`CONFIDENCE_FLAGGED`
    /// exactly; `SPLIT` is this port's own, with no Python counterpart.
    /// All three reach `remediation.json` through `bc-cli`'s export
    /// shape.
    pub fn as_str(self) -> &'static str {
        match self {
            SynthesisConfidence::High => "HIGH",
            SynthesisConfidence::Split => "SPLIT",
            SynthesisConfidence::Flagged => "FLAGGED",
        }
    }

    /// The inverse of [`Self::as_str`], for reading a persisted score back
    /// (an S11 `--resume` checkpoint). Exact match only.
    pub fn parse(s: &str) -> Option<SynthesisConfidence> {
        [
            SynthesisConfidence::High,
            SynthesisConfidence::Split,
            SynthesisConfidence::Flagged,
        ]
        .into_iter()
        .find(|c| c.as_str() == s)
    }
}

/// A file/line/snippet reference pinning a gate verdict to source
/// evidence.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Evidence {
    pub file: String,
    pub line: Option<i64>,
    pub snippet: String,
}

/// One gate's evaluation, as reported (post-synthesis, for the fix path)
/// or as scored — this crate reuses the same shape for both input and
/// output, matching the Python original's own `RawCriterion`/`GateResult`
/// duality.
#[derive(Debug, Clone, PartialEq)]
pub struct GateResult {
    pub gate_name: GateName,
    pub status: GateStatus,
    pub summary: String,
    pub evidence: Vec<Evidence>,
    pub details: String,
    /// Panel agreement on this gate, assigned by the synthesis step
    /// (`bc_stage_s11::synthesize_one_gate`) and read here by
    /// [`consensus_error`].
    ///
    /// `None` means "not synthesized": one persona's raw, pre-synthesis
    /// entry, or a gate set built by hand. It mirrors the Python
    /// original's own `RawCriterion.confidence: str = ""` default
    /// (`models/scoring.py`), which likewise only ever trips the
    /// consensus check on an explicit `FLAGGED` — an absent label is
    /// never treated as a failed consensus, only as an unasked question.
    pub confidence: Option<SynthesisConfidence>,
}

/// Outcome of validating a remediation patch against its finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixVerdict {
    Fixed,
    PartiallyFixed,
    NotFixed,
    Unverifiable,
}

impl FixVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            FixVerdict::Fixed => "Fixed",
            FixVerdict::PartiallyFixed => "Partially Fixed",
            FixVerdict::NotFixed => "Not Fixed",
            FixVerdict::Unverifiable => "UNVERIFIABLE",
        }
    }

    /// The inverse of [`Self::as_str`], for reading a persisted score back
    /// (an S11 `--resume` checkpoint). Exact match only.
    pub fn parse(s: &str) -> Option<FixVerdict> {
        [
            FixVerdict::Fixed,
            FixVerdict::PartiallyFixed,
            FixVerdict::NotFixed,
            FixVerdict::Unverifiable,
        ]
        .into_iter()
        .find(|v| v.as_str() == s)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeReadiness {
    Ready,
    ReadyWithConditions,
    NotReady,
}

impl MergeReadiness {
    /// Matches `vvaharness.validation.enums.readiness.MergeReadiness`'s
    /// exact wire strings (`"Ready"` / `"Ready with Conditions"` /
    /// `"Not Ready"`) — spaced, not `PascalCase`.
    pub fn as_str(self) -> &'static str {
        match self {
            MergeReadiness::Ready => "Ready",
            MergeReadiness::ReadyWithConditions => "Ready with Conditions",
            MergeReadiness::NotReady => "Not Ready",
        }
    }
}

pub fn derive_merge_readiness(verdict: FixVerdict) -> MergeReadiness {
    match verdict {
        FixVerdict::Fixed => MergeReadiness::Ready,
        FixVerdict::PartiallyFixed => MergeReadiness::ReadyWithConditions,
        FixVerdict::NotFixed | FixVerdict::Unverifiable => MergeReadiness::NotReady,
    }
}

/// Aggregate scoring output for one fix-validation run.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidationScore {
    pub raw_score: f64,
    pub fix_status: FixVerdict,
    pub justification: String,
    pub gate_results: Vec<GateResult>,
    pub has_critical_failure: bool,
}

const THRESHOLD_FIXED: f64 = 0.80;
const THRESHOLD_PARTIAL: f64 = 0.50;
const SCORE_PRECISION: i32 = 4;
const CONFIDENCE_PERCENT_SCALE: f64 = 100.0;
const MAX_EVIDENCE_ANCHORS: usize = 5;

/// Matches Python's `round(x, decimals)` exactly: both resolve to a
/// correctly-rounded decimal conversion of `x`'s true binary value
/// (ties-to-even), not a "multiply, round the binary result, divide"
/// approximation. The naive `(x * 10^decimals).round() / 10^decimals` form
/// introduces its own floating-point error in the multiply step — e.g. the
/// true value of `earned / active_weight` for gates
/// `[Pass, Pass, Partial, Pass]` is `0.8766499999999999...`, correctly
/// rounding to `0.8766`, but multiplying by `10000.0` first rounds the
/// *intermediate* product up to exactly `8766.5`, which then rounds away
/// from zero to `8767` — silently drifting the reported score.
fn round_to(x: f64, decimals: i32) -> f64 {
    format!("{x:.*}", decimals as usize)
        .parse()
        .expect("a fixed-precision float formatting always parses back")
}

fn unverifiable(justification: String, gates: &[GateResult]) -> ValidationScore {
    ValidationScore {
        raw_score: 0.0,
        fix_status: FixVerdict::Unverifiable,
        justification,
        gate_results: gates.to_vec(),
        has_critical_failure: has_critical_failure(gates),
    }
}

fn has_critical_failure(gates: &[GateResult]) -> bool {
    gates.iter().any(|g| {
        CRITICAL_GATES.contains(&g.gate_name)
            && matches!(g.status, GateStatus::Partial | GateStatus::Fail)
    })
}

/// Gate names as the wire strings, sorted ALPHABETICALLY rather than by
/// [`GateName`]'s own declaration order — every fail-closed message this
/// module emits names its gates the way Python's `sorted(...)` over the
/// same string set does.
fn names_by_str(set: &BTreeSet<GateName>) -> Vec<&'static str> {
    let mut v: Vec<&'static str> = set.iter().map(|g| g.as_str()).collect();
    v.sort_unstable();
    v
}

/// `Unverifiable` when the gate-name set doesn't exactly match the 4
/// expected names (missing) or a name repeats (duplicate).
fn shape_error(gates: &[GateResult]) -> Option<ValidationScore> {
    let names: Vec<GateName> = gates.iter().map(|g| g.gate_name).collect();
    let provided: BTreeSet<GateName> = names.iter().copied().collect();
    let expected: BTreeSet<GateName> = GateName::ALL.into_iter().collect();
    if provided != expected {
        let missing: BTreeSet<GateName> = expected.difference(&provided).copied().collect();
        return Some(unverifiable(
            format!(
                "UNVERIFIABLE: Missing criterion evaluations: {}.",
                names_by_str(&missing).join(", ")
            ),
            gates,
        ));
    }
    if names.len() != provided.len() {
        let mut seen: BTreeSet<GateName> = BTreeSet::new();
        let mut dupes: BTreeSet<GateName> = BTreeSet::new();
        for n in &names {
            if !seen.insert(*n) {
                dupes.insert(*n);
            }
        }
        return Some(unverifiable(
            format!(
                "UNVERIFIABLE: Duplicate criterion evaluations: {}.",
                names_by_str(&dupes).join(", ")
            ),
            gates,
        ));
    }
    None
}

/// `Unverifiable` when ANY gate came out of synthesis without panel
/// consensus ([`SynthesisConfidence::Flagged`]).
///
/// This is the fail-closed half of the consensus fix: `synthesize_one_gate`
/// still reports the gate's own most-conservative status and evidence
/// (nothing is hidden), but a status only one persona actually voted for
/// — or that two personas contradicted each other on, or that every
/// persona abstained from — must not become a host verdict on its own.
/// Before this existed, a lone non-abstaining vote decided a whole fix.
///
/// A gate whose `confidence` is `None` (never synthesized) is not
/// flagged: see [`GateResult::confidence`].
///
/// The filter is an equality test against `Flagged` specifically, not
/// "anything that is not `High`", which is what lets
/// [`SynthesisConfidence::Split`] score exactly as `High` does without
/// this function needing to know the variant exists. Only a
/// disagreement about whether the fix *works* stops the score; a
/// disagreement about how complete it is resolves conservatively and
/// scores on.
fn consensus_error(gates: &[GateResult]) -> Option<ValidationScore> {
    let flagged: BTreeSet<GateName> = gates
        .iter()
        .filter(|g| g.confidence == Some(SynthesisConfidence::Flagged))
        .map(|g| g.gate_name)
        .collect();
    if flagged.is_empty() {
        return None;
    }
    Some(unverifiable(
        format!(
            "UNVERIFIABLE: Insufficient persona consensus for gate(s): {}.",
            names_by_str(&flagged).join(", ")
        ),
        gates,
    ))
}

/// `Unverifiable` when a critical gate was never evaluated (`Skip`) or
/// came through garbled (`Invalid`) — this cannot be waived by a high
/// score elsewhere, and runs before the coverage check below.
fn critical_gate_error(gates: &[GateResult]) -> Option<ValidationScore> {
    for g in gates {
        if CRITICAL_GATES.contains(&g.gate_name)
            && matches!(g.status, GateStatus::Skip | GateStatus::Invalid)
        {
            return Some(unverifiable(
                format!(
                    "UNVERIFIABLE: critical gate '{}' was not evaluated (status '{}').",
                    g.gate_name.as_str(),
                    g.status.as_str()
                ),
                gates,
            ));
        }
    }
    None
}

/// Weighted score over evaluated (non-`Skip`) gates. A skip is dropped
/// from both the numerator and denominator — weight-neutral, never an
/// implicit failure. Coverage policy proper belongs to
/// [`critical_gate_error`]: either critical gate being skipped/invalid
/// already short-circuits to `Unverifiable` before this runs, which is a
/// stronger guarantee than any aggregate weight threshold — so the
/// `active_weight <= 0.0` check below is purely the divide-by-zero guard,
/// reachable only when every non-critical gate is also skipped.
fn renormalized_score(gates: &[GateResult]) -> Result<f64, ValidationScore> {
    let mut earned = 0.0;
    let mut active_weight = 0.0;
    for g in gates {
        if g.status == GateStatus::Skip {
            continue;
        }
        active_weight += g.gate_name.weight();
        earned += g.gate_name.weight() * g.status.multiplier();
    }
    if active_weight <= 0.0 {
        return Err(unverifiable(
            "UNVERIFIABLE: no gates were evaluated.".to_string(),
            gates,
        ));
    }
    // Clamp: a weights misconfiguration must never push the score above 1.0.
    Ok(round_to((earned / active_weight).min(1.0), SCORE_PRECISION))
}

/// The verdict once the shape check and the critical gates have all
/// passed — deliberately excludes `Unverifiable` at the type level (every
/// path that would produce it already returned early above), so the rest
/// of the pipeline can't accidentally need to handle an impossible case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScoredVerdict {
    Fixed,
    PartiallyFixed,
    NotFixed,
}

impl From<ScoredVerdict> for FixVerdict {
    fn from(v: ScoredVerdict) -> Self {
        match v {
            ScoredVerdict::Fixed => FixVerdict::Fixed,
            ScoredVerdict::PartiallyFixed => FixVerdict::PartiallyFixed,
            ScoredVerdict::NotFixed => FixVerdict::NotFixed,
        }
    }
}

fn apply_verdicts(raw_score: f64) -> ScoredVerdict {
    if raw_score >= THRESHOLD_FIXED {
        ScoredVerdict::Fixed
    } else if raw_score >= THRESHOLD_PARTIAL {
        ScoredVerdict::PartiallyFixed
    } else {
        ScoredVerdict::NotFixed
    }
}

/// Caps a `Fixed` verdict down to `PartiallyFixed` when either critical
/// gate isn't clean (`Partial`/`Fail`) — a partial critical gate earns
/// half credit numerically, so on its own it can't drop a fix below the
/// `Fixed` threshold; this label cap is what makes both gates genuinely
/// non-waivable rather than just heavily-weighted.
fn cap_critical_fail(gates: &[GateResult], verdict: ScoredVerdict) -> ScoredVerdict {
    if verdict != ScoredVerdict::Fixed {
        return verdict;
    }
    if has_critical_failure(gates) {
        ScoredVerdict::PartiallyFixed
    } else {
        verdict
    }
}

fn confidence(raw_score: f64) -> i64 {
    (raw_score * CONFIDENCE_PERCENT_SCALE).round() as i64
}

fn anchors_str(gates: &[GateResult]) -> String {
    let mut anchors = Vec::new();
    for g in gates {
        for e in &g.evidence {
            anchors.push(match e.line {
                Some(line) => format!("{}:{line}", e.file),
                None => e.file.clone(),
            });
        }
    }
    anchors.truncate(MAX_EVIDENCE_ANCHORS);
    anchors.join("; ")
}

/// Longest the joined "files needing fixes" list may be in a
/// justification. Each file is model-written evidence (already capped per
/// entry by `bc-stage-s11`), and the list is repeated into
/// `remediation.json`, the report and SARIF, so its total is bounded too.
pub const MAX_FILES_NEEDING_FIXES_CHARS: usize = 4096;

/// Appended where a justification field was cut short.
pub const TRUNCATION_MARKER: &str = "...[truncated]";

/// `files` joined with `, `, capped at [`MAX_FILES_NEEDING_FIXES_CHARS`]
/// characters plus [`TRUNCATION_MARKER`].
fn joined_files(files: &[String]) -> String {
    let joined = files.join(", ");
    if joined.chars().count() <= MAX_FILES_NEEDING_FIXES_CHARS {
        return joined;
    }
    let kept: String = joined.chars().take(MAX_FILES_NEEDING_FIXES_CHARS).collect();
    format!("{kept}{TRUNCATION_MARKER}")
}

fn files_needing_fixes(gates: &[GateResult]) -> Vec<String> {
    let mut files: BTreeSet<String> = BTreeSet::new();
    for g in gates {
        if matches!(g.status, GateStatus::Fail | GateStatus::Partial) {
            for e in &g.evidence {
                if !e.file.is_empty() {
                    files.insert(e.file.clone());
                }
            }
        }
    }
    files.into_iter().collect()
}

fn recommended_actions(gates: &[GateResult]) -> Vec<String> {
    let actions: Vec<String> = gates
        .iter()
        .filter(|g| g.status == GateStatus::Fail)
        .map(|g| format!("Address {}: {}", g.gate_name.as_str(), g.summary))
        .collect();
    if actions.is_empty() {
        vec!["Review all failing gates and apply fixes".to_string()]
    } else {
        actions
    }
}

fn fixed_text(raw_score: f64, gates: &[GateResult]) -> String {
    let passing: Vec<&str> = gates
        .iter()
        .filter(|g| g.status == GateStatus::Pass)
        .map(|g| g.summary.as_str())
        .collect();
    format!(
        "Fix verified: {}. Fix confidence: {}%. Evidence: {}.",
        passing.join("; "),
        confidence(raw_score),
        anchors_str(gates)
    )
}

fn partial_text(raw_score: f64, gates: &[GateResult]) -> String {
    let passing: Vec<&str> = gates
        .iter()
        .filter(|g| g.status == GateStatus::Pass)
        .map(|g| g.summary.as_str())
        .collect();
    let gaps: Vec<&str> = gates
        .iter()
        .filter(|g| matches!(g.status, GateStatus::Fail | GateStatus::Partial))
        .map(|g| g.summary.as_str())
        .collect();
    let files = files_needing_fixes(gates);
    format!(
        "Partial fix: {}. Gaps: {}. Fix confidence: {}%. Files needing fixes: {}.",
        passing.join("; "),
        gaps.join("; "),
        confidence(raw_score),
        if files.is_empty() {
            "N/A".to_string()
        } else {
            joined_files(&files)
        }
    )
}

fn not_fixed_text(raw_score: f64, gates: &[GateResult]) -> String {
    let failed: Vec<&str> = gates
        .iter()
        .filter(|g| g.status == GateStatus::Fail)
        .map(|g| g.summary.as_str())
        .collect();
    let files = files_needing_fixes(gates);
    let actions = recommended_actions(gates);
    format!(
        "Fix insufficient: {}. Vulnerable pattern remains in {}. Fix confidence: {}%. Recommended action: {}.",
        failed.join("; "),
        if files.is_empty() {
            "affected files".to_string()
        } else {
            joined_files(&files)
        },
        confidence(raw_score),
        actions.join("; ")
    )
}

fn justify(verdict: ScoredVerdict, raw_score: f64, gates: &[GateResult]) -> String {
    match verdict {
        ScoredVerdict::Fixed => fixed_text(raw_score, gates),
        ScoredVerdict::PartiallyFixed => partial_text(raw_score, gates),
        ScoredVerdict::NotFixed => not_fixed_text(raw_score, gates),
    }
}

/// Scores a synthesized set of gate evaluations for one remediated
/// finding. Ported 1:1 from `scoring/_engine.py::score` +
/// `scoring/__init__.py::score_fix`, hardcoded to this port's one
/// scoring shape (4 fix-validation gates, `no_new_vulnerabilities`
/// critical) — see this module's own doc comment for why a pluggable
/// `ScoringConfig` abstraction isn't ported.
pub fn score_fix(gates: &[GateResult]) -> ValidationScore {
    // Order matters and matches Python's `_precheck`: shape, then
    // consensus, then critical gates. A panel that never reached
    // consensus on a gate is reported as such even when that same gate
    // is also an unevaluated critical one — the missing consensus is the
    // more specific diagnosis of the two.
    if let Some(result) = shape_error(gates) {
        return result;
    }
    if let Some(result) = consensus_error(gates) {
        return result;
    }
    if let Some(result) = critical_gate_error(gates) {
        return result;
    }
    let raw_score = match renormalized_score(gates) {
        Ok(score) => score,
        Err(result) => return result,
    };
    let verdict = cap_critical_fail(gates, apply_verdicts(raw_score));
    let justification = justify(verdict, raw_score, gates);
    ValidationScore {
        raw_score,
        fix_status: verdict.into(),
        justification,
        gate_results: gates.to_vec(),
        has_critical_failure: has_critical_failure(gates),
    }
}

#[cfg(test)]
mod tests;
