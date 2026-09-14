//! Compliance policy: a user-supplied (Phase 1) or built-in verified
//! (Phase 2) rules file that steers what S3/S4/S6/S8 prioritize via
//! free-text guidance spliced into their prompts, and tags or filters
//! findings at report time by matching each one's CWE/vuln-class against
//! named requirements (a lightweight CWE-to-framework-requirement
//! crosswalk). Not a port of anything in the Python original — this
//! feature has no upstream counterpart.
//!
//! Phase 1 shipped the plumbing: schema, loader, matcher, and
//! prompt/report wiring, all end-to-end and combinable (a custom rules
//! file plus zero or more built-in presets active in the same run — see
//! [`apply_to_findings`]'s multi-policy OR-across-Filter semantics).
//! Phase 2 adds built-in, verified framework content — OWASP ASVS first
//! ([`presets::preset`]) — with the same sourced-primary-citation rigor as
//! `docs/compliance/CONTROL_MAPPING.md` (a *different* document, mapping
//! this tool's own security posture, not detected findings — cited here
//! only for its rigor bar; see `crates/bc-compliance/presets/*.yaml` for
//! each preset's own citation notes). A user's own custom rules file
//! needs no such verification; it's self-authored, so [`load`]/
//! [`parse_policy`] accept any well-formed policy YAML.

mod cwe;
mod loader;
mod matching;
mod presets;
mod types;

pub use cwe::norm_cwe;
pub use loader::{load, parse_policy, MAX_GUIDANCE_CHARS};
pub use matching::{apply_to_findings, combined_guidance, matching_requirement_ids};
pub use presets::preset;
pub use types::{CompliancePolicy, Requirement, ScopeMode};
