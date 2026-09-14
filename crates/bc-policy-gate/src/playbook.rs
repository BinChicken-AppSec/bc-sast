//! Fix-strategy resolution, ported from `remediation_agent/playbook.py`.
//! Only `max_diff_lines`/`max_files_touched` (of the playbook's global
//! `policy:` block) are actually read anywhere in the Python original's
//! agentic implementation — `candidates_per_finding`/`forbid_patterns`/
//! `never_autofix_cwes` are declared in the shipped YAML but are
//! genuinely unused dead configuration there too (per the Python
//! module's own comment: "the agentic Remediation Agent injects the
//! resolved strategy text into its own prompt rather than rendering this
//! whole template") — not ported here for the same reason. `guidance_for`
//! (prose-only advice for a policy-denied finding) is similarly confirmed
//! unused by the actual denial path (`policy.decide.guidance_verdict`
//! builds a bare "Denied by policy" summary, never calling it) — not
//! ported.

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::{Map, Value};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Strategy {
    pub name: String,
    pub instruction: String,
    pub cwe: String,
    pub cwe_title: String,
    /// `auto` | `suggest` | `guidance` — advisory only, not enforced
    /// anywhere in the agentic loop (matches the Python original).
    pub confidence: String,
    pub example_before: String,
    pub example_after: String,
    pub allowed_deps: Vec<String>,
    /// `sink` | `source` | `trust_boundary`.
    pub fix_location: String,
    pub notes: String,
}

impl Strategy {
    /// Renders the strategy as an authoritative prompt section the agent
    /// must follow, ported from `Strategy.as_prompt_block`. Kept compact
    /// so it's cheap on every backend.
    pub fn as_prompt_block(&self) -> String {
        let mut lines = vec![format!("## Required fix strategy: {}", self.name)];
        if self.cwe_title.is_empty() {
            lines.push(format!("CWE: {}", self.cwe));
        } else {
            lines.push(format!("CWE: {} — {}", self.cwe, self.cwe_title));
        }
        lines.push(format!("Fix location: {}", self.fix_location));
        lines.push(String::new());
        let instruction = self.instruction.trim();
        lines.push(if instruction.is_empty() {
            "(no specific instruction)".to_string()
        } else {
            instruction.to_string()
        });
        if !self.example_after.is_empty() {
            lines.push(String::new());
            lines.push("Reference pattern (the shape your fix should take):".to_string());
            lines.push("```".to_string());
            lines.push(self.example_after.trim().to_string());
            lines.push("```".to_string());
        }
        let deps = if self.allowed_deps.is_empty() {
            "(none)".to_string()
        } else {
            self.allowed_deps.join(", ")
        };
        lines.push(String::new());
        lines.push(format!("Allowed new dependencies: {deps}."));
        lines.push("Select THIS strategy; do not invent an alternative approach.".to_string());
        lines.join("\n")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CweEntry {
    title: String,
    /// Entry-level default; a resolved node's own `confidence` overrides
    /// this when present.
    confidence: String,
    fix_location: String,
    notes: String,
    /// Raw `strategies` block — kept untyped because a language key's
    /// value is EITHER a framework map (`{django: {...}, default: {...}}`)
    /// OR a bare strategy node directly (`{name: ..., instruction: ...}`,
    /// used by language-agnostic CWEs like SSRF/open-redirect), and only
    /// a runtime "does this look like a strategy node" check can tell the
    /// two apart — matching the Python original's own duck-typing rather
    /// than forcing a clean-but-unfaithful Rust shape.
    strategies: Value,
    fallback: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Playbook {
    pub max_diff_lines: i64,
    pub max_files_touched: i64,
    cwe: BTreeMap<String, CweEntry>,
}

fn str_field(node: &Value, key: &str) -> Option<String> {
    node.get(key).and_then(Value::as_str).map(str::to_string)
}

impl Playbook {
    /// CWE -> language -> framework -> language's own `default` -> the
    /// CWE-level `fallback` -> `None`, ported from `Playbook.resolve`.
    /// Unlike the policy gate, this does NOT normalize `cwe` — the
    /// Python original looks the raw string up directly against the raw
    /// YAML keys, so a caller must pass the same canonical form
    /// (`"CWE-89"`) the playbook file itself uses.
    pub fn resolve(&self, cwe: &str, language: &str, frameworks: &[String]) -> Option<Strategy> {
        let entry = self.cwe.get(cwe)?;
        let strategies = entry.strategies.as_object();
        let lang_block: Option<&Value> =
            strategies.and_then(|s| s.get(language).or_else(|| s.get("default")));

        let mut node: Option<&Value> = None;
        if let Some(block @ Value::Object(map)) = lang_block {
            for fw in frameworks {
                if let Some(v) = map.get(fw) {
                    node = Some(v);
                    break;
                }
            }
            if node.is_none() {
                node = map
                    .get("default")
                    .or_else(|| map.contains_key("name").then_some(block));
            }
        }
        let node = node.or(entry.fallback.as_ref())?;

        Some(Strategy {
            name: str_field(node, "name").unwrap_or_else(|| "unnamed".to_string()),
            instruction: str_field(node, "instruction")
                .unwrap_or_default()
                .trim()
                .to_string(),
            cwe: cwe.to_string(),
            cwe_title: entry.title.clone(),
            confidence: str_field(node, "confidence").unwrap_or_else(|| entry.confidence.clone()),
            example_before: str_field(node, "example_before")
                .unwrap_or_default()
                .trim()
                .to_string(),
            example_after: str_field(node, "example_after")
                .unwrap_or_default()
                .trim()
                .to_string(),
            allowed_deps: node
                .get("allowed_deps")
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default(),
            fix_location: entry.fix_location.clone(),
            notes: entry.notes.clone(),
        })
    }
}

/// Parses a `remediation_playbook.yaml`-shaped file. An entry keyed by an
/// unrecognized CWE id is still recorded verbatim (the raw YAML key,
/// unlike the policy gate which normalizes) since `resolve` looks up the
/// same raw string a caller would pass.
pub fn parse_playbook(yaml_text: &str) -> Result<Playbook, String> {
    let value = bc_yaml::parse(yaml_text).map_err(|e| e.to_string())?;

    let policy_block = value.get("policy");
    let max_diff_lines = policy_block
        .and_then(|p| p.get("max_diff_lines"))
        .and_then(Value::as_i64)
        .unwrap_or(40);
    let max_files_touched = policy_block
        .and_then(|p| p.get("max_files_touched"))
        .and_then(Value::as_i64)
        .unwrap_or(2);

    let empty_map = Map::new();
    let mut cwe = BTreeMap::new();
    let cwe_map = value
        .get("cwe")
        .and_then(Value::as_object)
        .unwrap_or(&empty_map);
    for (id, entry_value) in cwe_map {
        cwe.insert(
            id.clone(),
            CweEntry {
                title: str_field(entry_value, "title").unwrap_or_default(),
                confidence: str_field(entry_value, "confidence")
                    .unwrap_or_else(|| "suggest".to_string()),
                fix_location: str_field(entry_value, "fix_location")
                    .unwrap_or_else(|| "sink".to_string()),
                notes: str_field(entry_value, "notes").unwrap_or_default(),
                strategies: entry_value
                    .get("strategies")
                    .cloned()
                    .unwrap_or(Value::Null),
                fallback: entry_value.get("fallback").cloned(),
            },
        );
    }

    Ok(Playbook {
        max_diff_lines,
        max_files_touched,
        cwe,
    })
}

/// Loads and parses a `--remediation-playbook` file from disk. A missing
/// file, an unreadable one, a network (UNC/`\\host\share`) path, or a
/// parse failure all silently resolve to `Playbook::default()` — matching
/// [`RemediationGate::load`](crate::RemediationGate::load)'s own
/// fail-closed-without-a-separate-load-error convention for this same
/// `--remediation-*` flag family. The network-path check runs before any
/// filesystem touch (even a missing-file check would trigger Windows' SMB
/// handshake and leak the caller's NTLMv2 hash to a malicious UNC host).
pub fn load_playbook(path: &Path) -> Playbook {
    if bc_pathjail::is_network_path(&path.to_string_lossy()) {
        return Playbook::default();
    }
    std::fs::read_to_string(path)
        .ok()
        .and_then(|text| parse_playbook(&text).ok())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    const YAML: &str = r#"
policy:
  max_diff_lines: 40
  max_files_touched: 2
cwe:
  CWE-89:
    title: SQL Injection
    confidence: auto
    fix_location: sink
    strategies:
      python:
        django:
          name: use-orm
          instruction: use the Django ORM instead of raw SQL
          allowed_deps: []
        default:
          name: parameterize
          instruction: use parameterized queries
          example_before: "query('SELECT * FROM x WHERE y=' + y)"
          example_after: "query('SELECT * FROM x WHERE y=%s', (y,))"
    fallback:
      name: generic-fallback
      instruction: consult a security engineer
  CWE-918:
    title: SSRF
    confidence: suggest
    fix_location: trust_boundary
    strategies:
      default:
        name: url-allowlist
        instruction: enforce a host allowlist
  CWE-916:
    title: Weak Password Hashing
    confidence: guidance
    notes: requires data migration
"#;

    #[test]
    fn parses_policy_block_defaults() {
        let pb = parse_playbook(YAML).unwrap();
        assert_eq!(pb.max_diff_lines, 40);
        assert_eq!(pb.max_files_touched, 2);
    }

    #[test]
    fn missing_policy_block_uses_defaults() {
        let pb = parse_playbook("cwe: {}\n").unwrap();
        assert_eq!(pb.max_diff_lines, 40);
        assert_eq!(pb.max_files_touched, 2);
    }

    #[test]
    fn a_language_entry_that_is_not_a_mapping_is_skipped() {
        let yaml = "cwe:\n  CWE-89:\n    strategies:\n      python: not-a-mapping\n";
        let pb = parse_playbook(yaml).unwrap();
        assert!(pb.resolve("CWE-89", "python", &[]).is_none());
    }

    #[test]
    fn a_framework_node_missing_its_own_name_field_defaults_to_unnamed() {
        let yaml =
            "cwe:\n  CWE-89:\n    strategies:\n      python:\n        django:\n          instruction: do X\n";
        let pb = parse_playbook(yaml).unwrap();
        let s = pb
            .resolve("CWE-89", "python", &["django".to_string()])
            .unwrap();
        assert_eq!(s.name, "unnamed");
    }

    #[test]
    fn resolve_prefers_the_matching_framework_over_default() {
        let pb = parse_playbook(YAML).unwrap();
        let s = pb
            .resolve("CWE-89", "python", &["django".to_string()])
            .unwrap();
        assert_eq!(s.name, "use-orm");
        assert_eq!(s.cwe, "CWE-89");
        assert_eq!(s.cwe_title, "SQL Injection");
        assert_eq!(s.fix_location, "sink");
    }

    #[test]
    fn resolve_falls_back_to_the_languages_default_strategy() {
        let pb = parse_playbook(YAML).unwrap();
        let s = pb
            .resolve("CWE-89", "python", &["flask".to_string()])
            .unwrap();
        assert_eq!(s.name, "parameterize");
        assert_eq!(s.example_before, "query('SELECT * FROM x WHERE y=' + y)");
    }

    #[test]
    fn resolve_falls_back_to_the_cwe_level_fallback_when_the_language_is_unknown() {
        let pb = parse_playbook(YAML).unwrap();
        let s = pb.resolve("CWE-89", "rust", &[]).unwrap();
        assert_eq!(s.name, "generic-fallback");
    }

    #[test]
    fn a_language_agnostic_bare_default_strategy_resolves_for_any_language() {
        // CWE-918's `strategies` has no language keys at all — just a bare
        // `default: {name: ..., instruction: ...}` node directly under
        // `strategies`, exercising the "lang_block IS the strategy node
        // itself" duality (`"name" in lang_block`).
        let pb = parse_playbook(YAML).unwrap();
        let s = pb.resolve("CWE-918", "python", &[]).unwrap();
        assert_eq!(s.name, "url-allowlist");
        assert_eq!(s.fix_location, "trust_boundary");
    }

    #[test]
    fn confidence_defaults_to_the_entry_level_value_when_the_node_has_none() {
        let pb = parse_playbook(YAML).unwrap();
        let s = pb.resolve("CWE-918", "python", &[]).unwrap();
        assert_eq!(s.confidence, "suggest");
    }

    #[test]
    fn a_node_level_confidence_overrides_the_entry_level_default() {
        let yaml = r#"
cwe:
  CWE-89:
    title: SQL Injection
    confidence: auto
    strategies:
      default:
        name: x
        confidence: suggest
"#;
        let pb = parse_playbook(yaml).unwrap();
        let s = pb.resolve("CWE-89", "python", &[]).unwrap();
        assert_eq!(s.confidence, "suggest");
    }

    #[test]
    fn resolve_returns_none_for_a_cwe_with_no_strategies_or_fallback() {
        let pb = parse_playbook(YAML).unwrap();
        assert!(pb.resolve("CWE-916", "python", &[]).is_none());
    }

    #[test]
    fn resolve_returns_none_for_an_unknown_cwe() {
        let pb = parse_playbook(YAML).unwrap();
        assert!(pb.resolve("CWE-999", "python", &[]).is_none());
    }

    #[test]
    fn resolve_does_not_normalize_the_cwe_argument() {
        // Unlike the policy gate, playbook resolution is a raw string
        // lookup against the YAML's own keys.
        let pb = parse_playbook(YAML).unwrap();
        assert!(pb.resolve("89", "python", &[]).is_none());
        assert!(pb.resolve("cwe-89", "python", &[]).is_none());
    }

    #[test]
    fn malformed_yaml_is_a_parse_error() {
        assert!(parse_playbook("not: [a, valid\n").is_err());
    }

    #[test]
    fn load_playbook_reads_and_parses_a_real_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("playbook.yaml");
        std::fs::write(&path, YAML).unwrap();
        let pb = load_playbook(&path);
        assert_eq!(pb.max_diff_lines, 40);
    }

    #[test]
    fn load_playbook_missing_file_falls_back_to_default() {
        let pb = load_playbook(Path::new("/does/not/exist.yaml"));
        assert_eq!(pb, Playbook::default());
    }

    #[test]
    fn load_playbook_malformed_yaml_falls_back_to_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.yaml");
        std::fs::write(&path, "not: [a, valid\n").unwrap();
        let pb = load_playbook(&path);
        assert_eq!(pb, Playbook::default());
    }

    #[test]
    fn load_playbook_network_path_falls_back_to_default_without_touching_the_filesystem() {
        let pb = load_playbook(Path::new(r"\\attacker\share\playbook.yaml"));
        assert_eq!(pb, Playbook::default());
    }

    #[test]
    fn as_prompt_block_renders_every_section() {
        let pb = parse_playbook(YAML).unwrap();
        let s = pb
            .resolve("CWE-89", "python", &["django".to_string()])
            .unwrap();
        let block = s.as_prompt_block();
        assert!(block.contains("## Required fix strategy: use-orm"));
        assert!(block.contains("CWE: CWE-89 — SQL Injection"));
        assert!(block.contains("Fix location: sink"));
        assert!(block.contains("use the Django ORM instead of raw SQL"));
        assert!(block.contains("Allowed new dependencies: (none)."));
        assert!(block.contains("Select THIS strategy"));
    }

    #[test]
    fn as_prompt_block_includes_a_reference_pattern_when_example_after_is_set() {
        let pb = parse_playbook(YAML).unwrap();
        let s = pb
            .resolve("CWE-89", "python", &["flask".to_string()])
            .unwrap();
        let block = s.as_prompt_block();
        assert!(block.contains("Reference pattern"));
        assert!(block.contains("query('SELECT * FROM x WHERE y=%s', (y,))"));
    }

    #[test]
    fn as_prompt_block_lists_allowed_dependencies_when_present() {
        let yaml = r#"
cwe:
  CWE-79:
    title: XSS
    strategies:
      default:
        name: sanitize
        instruction: sanitize output
        allowed_deps: [bleach, dompurify]
"#;
        let pb = parse_playbook(yaml).unwrap();
        let s = pb.resolve("CWE-79", "python", &[]).unwrap();
        assert!(s.as_prompt_block().contains("bleach, dompurify"));
    }

    #[test]
    fn as_prompt_block_omits_the_cwe_title_separator_when_title_is_empty() {
        let yaml = "cwe:\n  CWE-79:\n    strategies:\n      default:\n        name: x\n        instruction: y\n";
        let pb = parse_playbook(yaml).unwrap();
        let s = pb.resolve("CWE-79", "python", &[]).unwrap();
        let block = s.as_prompt_block();
        assert!(block.contains("CWE: CWE-79\n"));
        assert!(!block.contains("—"));
    }

    #[test]
    fn as_prompt_block_falls_back_to_a_placeholder_for_a_blank_instruction() {
        let yaml = "cwe:\n  CWE-79:\n    strategies:\n      default:\n        name: x\n";
        let pb = parse_playbook(yaml).unwrap();
        let s = pb.resolve("CWE-79", "python", &[]).unwrap();
        assert!(s.as_prompt_block().contains("(no specific instruction)"));
    }
}
