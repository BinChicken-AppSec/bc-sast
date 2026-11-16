use super::{PolicyIdentity, TargetTestingConfig};

struct BuiltinProfile {
    name: &'static str,
    version: u32,
    json: &'static str,
}

const PROFILES: &[BuiltinProfile] = &[
    BuiltinProfile {
        name: "discovered-offline",
        version: 3,
        json: include_str!("policies/discovered-offline.json"),
    },
    BuiltinProfile {
        name: "discover",
        version: 1,
        json: include_str!("policies/discover.json"),
    },
    BuiltinProfile {
        name: "generate",
        version: 3,
        json: include_str!("policies/generate.json"),
    },
    BuiltinProfile {
        name: "unit",
        version: 1,
        json: include_str!("policies/unit.json"),
    },
    BuiltinProfile {
        name: "integration",
        version: 2,
        json: include_str!("policies/integration.json"),
    },
    BuiltinProfile {
        name: "e2e",
        version: 2,
        json: include_str!("policies/comprehensive.json"),
    },
    BuiltinProfile {
        name: "comprehensive",
        version: 2,
        json: include_str!("policies/comprehensive.json"),
    },
];

pub(super) fn load(name: &str) -> Result<TargetTestingConfig, String> {
    let profile = PROFILES.iter().find(|profile| profile.name == name).ok_or_else(|| {
        let available = PROFILES.iter().map(|profile| profile.name).collect::<Vec<_>>().join(", ");
        format!("unknown built-in target-test profile {name:?}; available: {available}. Policy files and runtime overrides are unsupported; edit the source registry and rebuild to add a profile")
    })?;
    let mut config: TargetTestingConfig = serde_json::from_str(profile.json)
        .map_err(|e| format!("invalid built-in target-test profile {name:?}: {e}"))?;
    if let Some(execution) = &config.execution {
        execution.validate()?;
    }
    if let Some(api_spec) = &config.api_spec {
        api_spec.validate()?;
    }
    if let Some(catalog) = &config.discovered_execution {
        super::discovered_execution::validate_catalog(catalog)?;
        if config.execution.is_some() {
            return Err("literal and discovered execution policies are mutually exclusive".into());
        }
    }
    config.profile = Some(PolicyIdentity {
        name: profile.name.into(),
        version: profile.version,
    });
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_compiled_profiles_have_unique_names_and_valid_policies() {
        let mut names = std::collections::BTreeSet::new();
        for profile in PROFILES {
            assert!(names.insert(profile.name));
            assert!(profile.version > 0);
            let config = load(profile.name).unwrap();
            let identity = config.profile.unwrap();
            assert_eq!(identity.name, profile.name);
            assert_eq!(identity.version, profile.version);
        }
        assert!(!load("discover").unwrap().generate);
        assert!(load("generate").unwrap().generate);
        assert!(load("discover").unwrap().execution.is_none());
        assert!(load("generate").unwrap().execution.is_none());
        for name in [
            "discover",
            "generate",
            "unit",
            "integration",
            "e2e",
            "comprehensive",
        ] {
            let config = load(name).unwrap();
            assert!(config.execution.is_none());
            assert!(config.discovered_execution.is_none());
        }
        for (name, enabled) in [
            ("discover", false),
            ("unit", false),
            ("integration", true),
            ("comprehensive", true),
            ("e2e", true),
            ("generate", true),
            ("discovered-offline", true),
        ] {
            assert_eq!(load(name).unwrap().api_spec.is_some(), enabled, "{name}");
        }
        let config = load("discovered-offline").unwrap();
        assert_eq!(config.profile.unwrap().version, 3);
        for ecosystem in config.discovered_execution.unwrap() {
            ecosystem.validate().unwrap();
            assert!(!ecosystem.provisioning.argv.is_empty());
            assert!(!ecosystem.provisioning.pins.is_empty());
        }
    }

    #[test]
    fn unknown_names_and_policy_paths_fail_closed_even_when_the_file_exists() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("policy.json");
        std::fs::write(&file, r#"{"generate": true}"#).unwrap();
        for name in [
            "unknown",
            "GENERATE",
            "../generate",
            "./generate",
            "policy.json",
            file.to_str().unwrap(),
        ] {
            assert!(load(name).unwrap_err().contains("unknown built-in"));
        }
    }

    #[test]
    fn embedded_policy_schema_rejects_unknown_fields() {
        assert!(serde_json::from_str::<TargetTestingConfig>(
            r#"{"generate":true,"allow_host_execution":true}"#
        )
        .is_err());
    }
}
