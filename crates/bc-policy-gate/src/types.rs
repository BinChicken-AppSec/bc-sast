use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use crate::action::Action;

/// A fully-parsed policy file. `deny` already has every declared
/// `descendants` entry expanded into the flat map (each mapped to its
/// parent's `reason`) — matching the Python original's own "explicit
/// list, no runtime CWE-graph lookup" design.
#[derive(Debug, Clone, PartialEq)]
pub struct PolicyData {
    pub deny: BTreeMap<String, String>,
    pub allow: BTreeSet<String>,
    pub deny_paths: Vec<String>,
    pub forbid_patch_paths: Vec<String>,
    pub kill_env: Option<String>,
    pub kill_file: Option<PathBuf>,
    pub default_action: Action,
}

/// The outcome of [`crate::gate::RemediationGate::decide`], with the
/// reason and (when a specific rule fired rather than the fall-through
/// default) which rule matched — surfaced in the synthesized
/// `Denied`/guidance-only verdict text so a human reviewing the report
/// can see exactly why a finding didn't get a patch attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub action: Action,
    pub reason: String,
    pub matched_rule: Option<String>,
}
