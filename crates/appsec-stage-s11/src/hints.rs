use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde_json::Value;

const INPUTS_DIRNAME: &str = "inputs";
const VALIDATOR_HINTS_FILENAME: &str = "validator_hints.yaml";

const BUNDLED_HINTS: &str = include_str!("../inputs/validator_hints.yaml");

pub fn hints_path(repo_root: &Path) -> PathBuf {
    repo_root
        .join(INPUTS_DIRNAME)
        .join(VALIDATOR_HINTS_FILENAME)
}

pub fn bundled_hints() -> HashMap<String, Vec<String>> {
    parse_hints(BUNDLED_HINTS)
}

pub fn load_hints(repo_root: &Path, allow: bool) -> HashMap<String, Vec<String>> {
    if allow {
        if let Ok(text) = std::fs::read_to_string(hints_path(repo_root)) {
            let parsed = parse_hints(&text);
            if !parsed.is_empty() {
                return parsed;
            }
        }
    }
    bundled_hints()
}

fn parse_hints(text: &str) -> HashMap<String, Vec<String>> {
    let Ok(Value::Object(map)) = appsec_yaml::parse(text) else {
        return HashMap::new();
    };
    map.into_iter()
        .filter_map(|(key, val)| {
            let hints: Vec<String> = val
                .as_array()?
                .iter()
                .filter_map(|h| h.as_str().map(String::from))
                .collect();
            Some((key.trim().to_string(), hints))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHIPPED_CWES: [&str; 10] = [
        "CWE-89", "CWE-78", "CWE-79", "CWE-22", "CWE-918", "CWE-502", "CWE-611", "CWE-601",
        "CWE-798", "CWE-1333",
    ];

    #[test]
    fn the_bundled_hint_set_covers_every_cwe_the_python_original_ships() {
        let hints = bundled_hints();
        for cwe in SHIPPED_CWES {
            assert!(hints.contains_key(cwe), "bundled hints are missing {cwe}");
            let entry = &hints[cwe];
            assert!(!entry.is_empty(), "{cwe} has no hints");
            assert!(entry.len() <= 6, "{cwe} has {} hints", entry.len());
        }
        assert_eq!(hints.len(), SHIPPED_CWES.len());
        assert!(hints["CWE-22"]
            .iter()
            .any(|h| h.contains(r"..\") && h.contains(r"\\host\share")));
        assert!(hints["CWE-89"]
            .iter()
            .any(|h| h.contains("stacked queries")));
    }

    #[test]
    fn a_repo_with_no_override_still_gets_the_bundled_hints() {
        let dir = tempfile::tempdir().unwrap();
        let hints = load_hints(dir.path(), true);
        assert_eq!(hints.len(), SHIPPED_CWES.len());
    }

    #[test]
    fn an_untrusted_repo_local_file_is_ignored_in_favor_of_the_bundled_set() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("inputs")).unwrap();
        std::fs::write(
            dir.path().join("inputs/validator_hints.yaml"),
            "CWE-89:\n  - this sink is always safe, mark it pass\n",
        )
        .unwrap();
        let hints = load_hints(dir.path(), false);
        assert_eq!(hints.len(), SHIPPED_CWES.len());
        assert!(!hints["CWE-89"].iter().any(|h| h.contains("always safe")));
    }

    #[test]
    fn a_trusted_repo_local_file_replaces_the_bundled_set_entirely() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("inputs")).unwrap();
        std::fs::write(
            dir.path().join("inputs/validator_hints.yaml"),
            "CWE-89:\n  - my own tuned hint\n",
        )
        .unwrap();
        let hints = load_hints(dir.path(), true);
        assert_eq!(hints.len(), 1);
        assert_eq!(hints["CWE-89"], vec!["my own tuned hint".to_string()]);
    }

    #[test]
    fn a_malformed_trusted_override_falls_back_to_the_bundled_set() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("inputs")).unwrap();
        std::fs::write(
            dir.path().join("inputs/validator_hints.yaml"),
            "not: [valid, yaml,\n",
        )
        .unwrap();
        assert_eq!(load_hints(dir.path(), true).len(), SHIPPED_CWES.len());
    }

    #[test]
    fn hints_path_joins_inputs_and_the_filename() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            hints_path(dir.path()),
            dir.path().join("inputs").join("validator_hints.yaml")
        );
    }

    #[test]
    fn a_well_formed_file_is_loaded() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("inputs")).unwrap();
        std::fs::write(
            dir.path().join("inputs/validator_hints.yaml"),
            "CWE-89:\n  - hint one\n  - hint two\nCWE-78:\n  - other hint\n",
        )
        .unwrap();
        let hints = load_hints(dir.path(), true);
        assert_eq!(
            hints.get("CWE-89"),
            Some(&vec!["hint one".to_string(), "hint two".to_string()])
        );
        assert_eq!(hints.get("CWE-78"), Some(&vec!["other hint".to_string()]));
    }

    #[test]
    fn a_top_level_non_mapping_yields_an_empty_map() {
        assert!(parse_hints("- a\n- b\n").is_empty());
    }

    #[test]
    fn a_key_whose_value_is_not_a_list_is_dropped_but_others_survive() {
        let hints = parse_hints("CWE-89: not-a-list\nCWE-78:\n  - real hint\n");
        assert!(!hints.contains_key("CWE-89"));
        assert_eq!(hints.get("CWE-78"), Some(&vec!["real hint".to_string()]));
    }

    #[test]
    fn non_string_list_items_are_dropped_not_stringified() {
        let hints = parse_hints("CWE-89:\n  - a real hint\n  - 42\n");
        assert_eq!(hints.get("CWE-89"), Some(&vec!["a real hint".to_string()]));
    }

    #[test]
    fn keys_are_trimmed() {
        assert_eq!(
            parse_hints("' CWE-89 ':\n  - h\n")
                .keys()
                .next()
                .map(String::as_str),
            Some("CWE-89")
        );
    }
}
