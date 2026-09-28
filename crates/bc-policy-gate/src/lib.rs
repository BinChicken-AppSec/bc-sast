//! The deterministic, no-LLM remediation eligibility gate, ported from
//! `remediation_agent/policy_gate/`. Deliberately excludes the S10
//! remediation stage's own LLM/agentic logic, prompt text, and diff
//! capture/revert mechanics — this crate is only "given a CWE and a file
//! path, may a patch be generated for it, and why."
//!
//! **Shipped-file discrepancy worth carrying into any deployment of this
//! port**: the Python original's *default* policy file
//! (`inputs/remediation_policy.yaml`) ships essentially empty
//! (`default_action: allow`, no deny/allow entries, no path guards) — the
//! richly-populated policy living in `remediation_policy.yaml.example` is
//! **not** loaded unless an operator explicitly points at it. A caller of
//! this crate that wants the strict, documented-in-most-places behavior
//! needs to load a real policy file, not assume one exists.

mod action;
mod cwe;
mod diffscan;
mod frameworks;
mod gate;
mod loader;
mod matching;
mod playbook;
mod types;
mod workflow_refs;

pub use action::Action;
pub use cwe::norm_cwe;
pub use diffscan::{cap_verdict, inspect_diff};
pub use frameworks::{detect_frameworks, language_for};
pub use gate::RemediationGate;
pub use loader::parse_policy;
pub use matching::{first_match, glob_match};
pub use playbook::{load_playbook, parse_playbook, Playbook, Strategy};
pub use types::{Decision, PolicyData};
pub use workflow_refs::{
    introduced_unsafe_workflow_refs, is_full_sha, is_nonplaceholder_sha, is_workflow_path,
    unsafe_reason, workflow_references, MAX_PLACEHOLDER_PERIOD, WORKFLOW_PREFIX,
};

impl Decision {
    /// Whether the caller may invoke the patch agent for this finding.
    /// Ported from `Decision.may_generate_patch`.
    pub fn may_generate_patch(&self) -> bool {
        self.action == Action::Patch
    }
}
