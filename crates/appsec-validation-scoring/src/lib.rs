use std::collections::BTreeSet;

mod vocab;

pub use vocab::{not_remediated, verdict_state, CaseState, Decision, Rollup, ValidationCounts};

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

pub const CRITICAL_GATES: [GateName; 2] = [GateName::NoNewVulnerabilities, GateName::RootCause];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateStatus {
    Pass,
    Partial,
    Fail,
    Skip,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SynthesisConfidence {
    High,
    Split,
    Flagged,
}

impl SynthesisConfidence {
    pub fn as_str(self) -> &'static str {
        match self {
            SynthesisConfidence::High => "HIGH",
            SynthesisConfidence::Split => "SPLIT",
            SynthesisConfidence::Flagged => "FLAGGED",
        }
    }

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

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Evidence {
    pub file: String,
    pub line: Option<i64>,
    pub snippet: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GateResult {
    pub gate_name: GateName,
    pub status: GateStatus,
    pub summary: String,
    pub evidence: Vec<Evidence>,
    pub details: String,
    pub confidence: Option<SynthesisConfidence>,
}

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

fn names_by_str(set: &BTreeSet<GateName>) -> Vec<&'static str> {
    let mut v: Vec<&'static str> = set.iter().map(|g| g.as_str()).collect();
    v.sort_unstable();
    v
}

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
    Ok(round_to((earned / active_weight).min(1.0), SCORE_PRECISION))
}

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

pub const MAX_FILES_NEEDING_FIXES_CHARS: usize = 4096;

pub const TRUNCATION_MARKER: &str = "...[truncated]";

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

pub fn score_fix(gates: &[GateResult]) -> ValidationScore {
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
