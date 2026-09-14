//! Parses a `remediation_policy.yaml`-shaped file, ported from
//! `policy_gate/loader.py::parse_policy`. Schema (see the module's own
//! shipped example for the canonical reference):
//!
//! ```yaml
//! schema_version: "1.0"
//! default_action: allow|deny
//! kill_switch:
//!   env_var: BC_REMEDIATE_DISABLE
//!   file: ./.bc-remediate-off
//! deny:
//!   - id: CWE-284
//!     reason: "..."
//!     descendants: [CWE-285, CWE-639]
//! allow:
//!   - { id: CWE-89 }
//! deny_paths: ["**/auth/**"]
//! forbid_patch_paths: ["**/setup.py"]
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use serde_json::Value;

use crate::action::Action;
use crate::cwe::norm_cwe;
use crate::types::PolicyData;

fn as_str_vec(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Parses YAML policy text into [`PolicyData`]. A missing
/// `default_action` (or one that's neither `"allow"` nor `"deny"`)
/// resolves to `GuidanceOnly` — deliberately fail-closed at the
/// field level, matching this project's config-loading invariant,
/// even though the Python original's own default in this specific
/// case wasn't confirmed by direct source inspection.
pub fn parse_policy(yaml_text: &str) -> Result<PolicyData, String> {
    let value = bc_yaml::parse(yaml_text).map_err(|e| e.to_string())?;

    let default_action = match value.get("default_action").and_then(Value::as_str) {
        Some("allow") => Action::Patch,
        _ => Action::GuidanceOnly,
    };

    let (kill_env, kill_file) = match value.get("kill_switch") {
        Some(ks) => (
            ks.get("env_var")
                .and_then(Value::as_str)
                .map(str::to_string),
            ks.get("file").and_then(Value::as_str).map(PathBuf::from),
        ),
        None => (None, None),
    };

    let mut deny: BTreeMap<String, String> = BTreeMap::new();
    if let Some(entries) = value.get("deny").and_then(Value::as_array) {
        for entry in entries {
            let Some(id) = entry.get("id").and_then(Value::as_str).and_then(norm_cwe) else {
                continue;
            };
            let reason = entry
                .get("reason")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            for descendant in as_str_vec(entry.get("descendants")) {
                if let Some(d) = norm_cwe(&descendant) {
                    deny.insert(d, reason.clone());
                }
            }
            deny.insert(id, reason);
        }
    }

    let mut allow: BTreeSet<String> = BTreeSet::new();
    if let Some(entries) = value.get("allow").and_then(Value::as_array) {
        for entry in entries {
            if let Some(id) = entry.get("id").and_then(Value::as_str).and_then(norm_cwe) {
                allow.insert(id);
            }
        }
    }

    Ok(PolicyData {
        deny,
        allow,
        deny_paths: as_str_vec(value.get("deny_paths")),
        forbid_patch_paths: as_str_vec(value.get("forbid_patch_paths")),
        kill_env,
        kill_file,
        default_action,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_full_policy() {
        let yaml = r#"
schema_version: "1.0"
default_action: allow
kill_switch:
  env_var: BC_REMEDIATE_DISABLE
  file: ./.bc-remediate-off
deny:
  - id: CWE-284
    reason: "access control issues are too risky to auto-patch"
    descendants: [CWE-285, CWE-639]
allow:
  - { id: CWE-89 }
  - { id: CWE-78 }
deny_paths: ["**/auth/**", "**/*crypto*"]
forbid_patch_paths: ["**/setup.py", "**/Dockerfile*"]
"#;
        let policy = parse_policy(yaml).unwrap();
        assert_eq!(policy.default_action, Action::Patch);
        assert_eq!(policy.kill_env.as_deref(), Some("BC_REMEDIATE_DISABLE"));
        assert_eq!(policy.kill_file, Some(PathBuf::from("./.bc-remediate-off")));
        assert_eq!(
            policy.deny.get("CWE-284").map(String::as_str),
            Some("access control issues are too risky to auto-patch")
        );
        assert_eq!(
            policy.deny.get("CWE-285").map(String::as_str),
            Some("access control issues are too risky to auto-patch")
        );
        assert_eq!(
            policy.deny.get("CWE-639").map(String::as_str),
            Some("access control issues are too risky to auto-patch")
        );
        assert!(policy.allow.contains("CWE-89"));
        assert!(policy.allow.contains("CWE-78"));
        assert_eq!(policy.deny_paths, vec!["**/auth/**", "**/*crypto*"]);
        assert_eq!(
            policy.forbid_patch_paths,
            vec!["**/setup.py", "**/Dockerfile*"]
        );
    }

    #[test]
    fn missing_default_action_fails_closed_to_guidance_only() {
        let policy = parse_policy("deny: []\n").unwrap();
        assert_eq!(policy.default_action, Action::GuidanceOnly);
    }

    #[test]
    fn an_unrecognized_default_action_value_fails_closed() {
        let policy = parse_policy("default_action: maybe\n").unwrap();
        assert_eq!(policy.default_action, Action::GuidanceOnly);
    }

    #[test]
    fn deny_action_parses_to_guidance_only() {
        let policy = parse_policy("default_action: deny\n").unwrap();
        assert_eq!(policy.default_action, Action::GuidanceOnly);
    }

    #[test]
    fn absent_sections_default_to_empty() {
        let policy = parse_policy("default_action: allow\n").unwrap();
        assert!(policy.deny.is_empty());
        assert!(policy.allow.is_empty());
        assert!(policy.deny_paths.is_empty());
        assert!(policy.forbid_patch_paths.is_empty());
        assert_eq!(policy.kill_env, None);
        assert_eq!(policy.kill_file, None);
    }

    #[test]
    fn a_deny_entry_with_an_unrecognized_id_is_skipped() {
        let yaml = "deny:\n  - id: not-a-cwe\n    reason: irrelevant\n";
        let policy = parse_policy(yaml).unwrap();
        assert!(policy.deny.is_empty());
    }

    #[test]
    fn a_deny_entry_with_an_unrecognized_descendant_id_skips_only_that_descendant() {
        let yaml = "deny:\n  - id: CWE-1\n    reason: r\n    descendants: [not-a-cwe, CWE-2]\n";
        let policy = parse_policy(yaml).unwrap();
        assert_eq!(policy.deny.get("CWE-1").map(String::as_str), Some("r"));
        assert_eq!(policy.deny.get("CWE-2").map(String::as_str), Some("r"));
        assert_eq!(policy.deny.len(), 2);
    }

    #[test]
    fn an_allow_entry_with_an_unrecognized_id_is_skipped() {
        let yaml = "allow:\n  - { id: not-a-cwe }\n";
        let policy = parse_policy(yaml).unwrap();
        assert!(policy.allow.is_empty());
    }

    #[test]
    fn a_deny_entry_missing_a_reason_defaults_to_empty_string() {
        let yaml = "deny:\n  - id: CWE-1\n";
        let policy = parse_policy(yaml).unwrap();
        assert_eq!(policy.deny.get("CWE-1").map(String::as_str), Some(""));
    }

    #[test]
    fn malformed_yaml_is_a_parse_error() {
        assert!(parse_policy("not: [a, valid\n").is_err());
    }
}
