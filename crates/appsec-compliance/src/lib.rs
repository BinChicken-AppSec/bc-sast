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
