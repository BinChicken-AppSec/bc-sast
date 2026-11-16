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
    pub fn may_generate_patch(&self) -> bool {
        self.action == Action::Patch
    }
}
