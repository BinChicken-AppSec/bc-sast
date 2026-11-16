use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use crate::action::Action;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub action: Action,
    pub reason: String,
    pub matched_rule: Option<String>,
}
