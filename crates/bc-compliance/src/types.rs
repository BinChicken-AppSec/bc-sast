//! Data shapes for a compliance policy: free-text guidance spliced into
//! stage prompts to steer prioritization, plus an optional set of named
//! requirements (a CWE/vuln-class crosswalk) used to tag or filter
//! findings at report time. Deliberately not a port of anything — this
//! feature has no Python-original counterpart.

/// How findings that match none of a policy's [`Requirement`]s are
/// treated at report time. Irrelevant when `requirements` is empty (a
/// pure-guidance custom rules file never tags or drops anything).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeMode {
    /// Tag matching findings with the requirement IDs they satisfy;
    /// every finding still reaches the report. The default — a
    /// compliance profile should widen what a reviewer notices, not
    /// silently narrow the scan's own coverage guarantee.
    Annotate,
    /// Tag matching findings the same way, but drop non-matching ones
    /// into `FinalReport.dropped` (`DropReason::Excluded`) instead of
    /// the report's findings list.
    Filter,
}

/// One named requirement from a framework (or a user's own ad-hoc
/// grouping): an id/title plus the CWE ids and/or `VulnClass` wire
/// strings that satisfy it. A finding matches a requirement when its
/// own CWE or vuln class appears in either list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Requirement {
    pub id: String,
    pub title: String,
    /// Canonical `"CWE-<digits>"` form — normalized at load time via
    /// [`crate::cwe::norm_cwe`], so matching is a plain string compare
    /// against `Finding.cwe`, which is already canonical by the time S4
    /// sets it.
    pub cwes: Vec<String>,
    /// `VulnClass::as_str()` wire strings, e.g. `"injection"`.
    pub vuln_classes: Vec<String>,
}

/// A loaded, ready-to-use compliance policy — either a user's own
/// custom rules file (Phase 1) or, later, a built-in verified framework
/// preset (Phase 2), both produced by the same [`crate::load`]/
/// [`crate::parse_policy`] entry points and consumed identically from
/// here on.
#[derive(Debug, Clone, PartialEq)]
pub struct CompliancePolicy {
    pub name: String,
    /// Free text spliced into S3/S4/S6/S8's prompts to steer what gets
    /// prioritized — not a filter by itself; only [`Self::requirements`]
    /// plus [`Self::scope_mode`] change what actually reaches the
    /// report. Capped at load time (see [`crate::loader::MAX_GUIDANCE_CHARS`])
    /// so one long rules file can't blow out every stage's prompt
    /// budget at once.
    pub guidance: String,
    pub scope_mode: ScopeMode,
    /// Empty for a pure-guidance policy — [`crate::matching::apply_to_findings`]
    /// is then a no-op regardless of `scope_mode`.
    pub requirements: Vec<Requirement>,
}
