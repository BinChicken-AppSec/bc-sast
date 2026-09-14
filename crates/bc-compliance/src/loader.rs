//! Parses a compliance-policy YAML file. Schema:
//!
//! ```yaml
//! name: "PCI focus"
//! guidance: |
//!   Prioritize findings that could expose cardholder data: injection
//!   flaws, broken authentication, insecure cryptographic storage.
//! scope_mode: annotate   # or "filter"; anything else defaults to annotate
//! requirements:
//!   - id: "6.2.4"
//!     title: "Injection flaws"
//!     cwes: ["CWE-89", "CWE-79"]
//!     vuln_classes: ["injection"]
//! ```
//!
//! Mirrors `bc-policy-gate::loader::parse_policy`'s style: manual,
//! lenient `serde_json::Value` field-walking rather than a `Deserialize`
//! derive, so one malformed entry (a missing `id`, an unrecognized CWE)
//! is skipped rather than failing the whole file — matching this
//! project's convention for user-authored policy YAML (as opposed to
//! `bc-model`'s own DTOs, which stay strict).

use std::path::Path;

use serde_json::Value;

use crate::cwe::norm_cwe;
use crate::types::{CompliancePolicy, Requirement, ScopeMode};

/// Guidance text is capped at load time so one long rules file can't
/// blow out every stage's prompt budget at once — this feature has no
/// Python original to inherit a cap from, so the number is a fresh,
/// deliberately generous choice (a genuine compliance-scoping paragraph
/// is a few hundred words at most).
pub const MAX_GUIDANCE_CHARS: usize = 4000;

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

/// Recognized `VulnClass` wire strings only — an unrecognized entry
/// (typo, or a value from some other taxonomy) is silently skipped
/// rather than kept as dead weight that can never match a real finding.
fn as_vuln_classes(value: Option<&Value>) -> Vec<String> {
    as_str_vec(value)
        .into_iter()
        .filter_map(|s| {
            serde_json::from_value::<bc_model::VulnClass>(Value::String(s))
                .ok()
                .map(|vc| vc.as_str().to_string())
        })
        .collect()
}

/// Parses YAML policy text into a [`CompliancePolicy`]. Never errors on
/// a malformed individual field — only on YAML that doesn't parse at
/// all, or that isn't a mapping (surfaced by [`bc_yaml::parse`] itself).
pub fn parse_policy(yaml_text: &str) -> Result<CompliancePolicy, String> {
    let value = bc_yaml::parse(yaml_text).map_err(|e| e.to_string())?;

    let name = value
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();

    let guidance_raw = value
        .get("guidance")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    let guidance: String = guidance_raw.chars().take(MAX_GUIDANCE_CHARS).collect();

    let scope_mode = match value.get("scope_mode").and_then(Value::as_str) {
        Some("filter") => ScopeMode::Filter,
        _ => ScopeMode::Annotate,
    };

    let mut requirements = Vec::new();
    if let Some(entries) = value.get("requirements").and_then(Value::as_array) {
        for entry in entries {
            let Some(id) = entry
                .get("id")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
            else {
                continue;
            };
            let title = entry
                .get("title")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim()
                .to_string();
            let cwes: Vec<String> = as_str_vec(entry.get("cwes"))
                .iter()
                .filter_map(|s| norm_cwe(s))
                .collect();
            let vuln_classes = as_vuln_classes(entry.get("vuln_classes"));
            requirements.push(Requirement {
                id: id.to_string(),
                title,
                cwes,
                vuln_classes,
            });
        }
    }

    Ok(CompliancePolicy {
        name,
        guidance,
        scope_mode,
        requirements,
    })
}

/// Loads and parses a compliance-policy file. Fail-closed on either a
/// missing/unreadable file or malformed YAML — matching `bc-config`'s
/// own loading convention (a hard error the CLI surfaces immediately,
/// never a silent fall-back to "no policy"). Rejected before any
/// filesystem touch when `path` is a network (UNC/`\\host\share`) path —
/// even a failed read would trigger Windows' SMB handshake and leak the
/// caller's NTLMv2 hash to a malicious host.
pub fn load(path: &Path) -> Result<CompliancePolicy, String> {
    if bc_pathjail::is_network_path(&path.to_string_lossy()) {
        return Err(format!("{}: network paths are not allowed", path.display()));
    }
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    parse_policy(&text).map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_full_policy() {
        let yaml = r#"
name: "PCI focus"
guidance: |
  Prioritize injection and broken auth.
scope_mode: filter
requirements:
  - id: "6.2.4"
    title: "Injection flaws"
    cwes: ["CWE-89", "cwe-79"]
    vuln_classes: ["injection", "other"]
"#;
        let policy = parse_policy(yaml).unwrap();
        assert_eq!(policy.name, "PCI focus");
        assert_eq!(policy.guidance, "Prioritize injection and broken auth.");
        assert_eq!(policy.scope_mode, ScopeMode::Filter);
        assert_eq!(policy.requirements.len(), 1);
        assert_eq!(policy.requirements[0].id, "6.2.4");
        assert_eq!(policy.requirements[0].title, "Injection flaws");
        assert_eq!(
            policy.requirements[0].cwes,
            vec!["CWE-89".to_string(), "CWE-79".to_string()]
        );
        assert_eq!(
            policy.requirements[0].vuln_classes,
            vec!["injection".to_string(), "other".to_string()]
        );
    }

    #[test]
    fn absent_sections_default_to_empty_and_annotate() {
        let policy = parse_policy("name: bare\n").unwrap();
        assert_eq!(policy.guidance, "");
        assert_eq!(policy.scope_mode, ScopeMode::Annotate);
        assert!(policy.requirements.is_empty());
    }

    #[test]
    fn a_missing_name_defaults_to_empty_string() {
        let policy = parse_policy("guidance: g\n").unwrap();
        assert_eq!(policy.name, "");
    }

    #[test]
    fn an_unrecognized_scope_mode_value_defaults_to_annotate() {
        let policy = parse_policy("scope_mode: strict\n").unwrap();
        assert_eq!(policy.scope_mode, ScopeMode::Annotate);
    }

    #[test]
    fn guidance_is_truncated_at_the_char_cap() {
        let yaml = format!("guidance: \"{}\"\n", "a".repeat(MAX_GUIDANCE_CHARS + 500));
        let policy = parse_policy(&yaml).unwrap();
        assert_eq!(policy.guidance.chars().count(), MAX_GUIDANCE_CHARS);
    }

    #[test]
    fn a_requirement_missing_an_id_is_skipped() {
        let yaml = "requirements:\n  - title: no id here\n";
        let policy = parse_policy(yaml).unwrap();
        assert!(policy.requirements.is_empty());
    }

    #[test]
    fn a_requirement_with_a_blank_id_is_skipped() {
        let yaml = "requirements:\n  - id: \"   \"\n    title: t\n";
        let policy = parse_policy(yaml).unwrap();
        assert!(policy.requirements.is_empty());
    }

    #[test]
    fn a_requirement_missing_a_title_defaults_to_empty_string() {
        let yaml = "requirements:\n  - id: \"R1\"\n";
        let policy = parse_policy(yaml).unwrap();
        assert_eq!(policy.requirements[0].title, "");
    }

    #[test]
    fn an_unrecognized_cwe_in_a_requirement_is_skipped() {
        let yaml = "requirements:\n  - id: R1\n    cwes: [\"not-a-cwe\", \"CWE-89\"]\n";
        let policy = parse_policy(yaml).unwrap();
        assert_eq!(policy.requirements[0].cwes, vec!["CWE-89".to_string()]);
    }

    #[test]
    fn an_unrecognized_vuln_class_in_a_requirement_is_skipped() {
        let yaml =
            "requirements:\n  - id: R1\n    vuln_classes: [\"not-a-real-class\", \"injection\"]\n";
        let policy = parse_policy(yaml).unwrap();
        assert_eq!(
            policy.requirements[0].vuln_classes,
            vec!["injection".to_string()]
        );
    }

    #[test]
    fn malformed_yaml_is_a_parse_error() {
        assert!(parse_policy("not: [a, valid\n").is_err());
    }

    #[test]
    fn load_reads_and_parses_a_real_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.yaml");
        std::fs::write(&path, "name: from-disk\n").unwrap();
        let policy = load(&path).unwrap();
        assert_eq!(policy.name, "from-disk");
    }

    #[test]
    fn load_missing_file_is_an_error_naming_the_path() {
        let err = load(Path::new("/does/not/exist.yaml")).unwrap_err();
        assert!(err.contains("does/not/exist.yaml"));
    }

    #[test]
    fn load_malformed_yaml_is_an_error_naming_the_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.yaml");
        std::fs::write(&path, "not: [a, valid\n").unwrap();
        let err = load(&path).unwrap_err();
        assert!(err.contains("bad.yaml"));
    }

    #[test]
    fn load_refuses_a_network_path_without_touching_the_filesystem() {
        let err = load(Path::new(r"\\attacker\share\policy.yaml")).unwrap_err();
        assert!(err.contains("network paths are not allowed"));
    }
}
