//! Build-owned target-testing policy registry. Adding or changing authorization
//! requires editing these sources and rebuilding; there is no runtime override.
use super::{PolicyIdentity, TargetTestingConfig};

struct BuiltinProfile {
    name: &'static str,
    version: u32,
    json: &'static str,
}

// Add vetted execution profiles here with include_str! and a unique name.
// Their images and argv must be reviewed for the intended target environment.
// Bump the profile version whenever its authorization or behavior changes.
// discovered-offline image pins were read from public registry metadata on
// 2026-09-10: Docker Official Images node:22-bookworm-slim, rust:1-bookworm,
// python:3.12-slim-bookworm, golang:1-bookworm, maven:3-eclipse-temurin-21,
// and Microsoft's dotnet/sdk:8.0-bookworm-slim. These multi-platform digests
// pin upstream toolchains; the target's own dependencies are installed by that
// profile's per-ecosystem provisioning command, from the target's lockfile,
// in the run's single networked container. See target-testing.md for what each
// ecosystem installs and the registry endpoints used to verify the pins.
const PROFILES: &[BuiltinProfile] = &[
    BuiltinProfile {
        name: "discovered-offline",
        // v2 added lockfile-pinned dependency provisioning; a package with no
        // pin the build can install from is now refused rather than tested
        // against an empty dependency tree.
        version: 2,
        json: include_str!("policies/discovered-offline.json"),
    },
    BuiltinProfile {
        name: "discover",
        version: 1,
        json: include_str!("policies/discover.json"),
    },
    BuiltinProfile {
        name: "generate",
        version: 2,
        json: include_str!("policies/generate.json"),
    },
    BuiltinProfile {
        name: "unit",
        version: 1,
        json: include_str!("policies/unit.json"),
    },
    BuiltinProfile {
        name: "integration",
        version: 1,
        json: include_str!("policies/integration.json"),
    },
    // E2E is the cumulative full-scope alias, not an instruction to add every test type.
    BuiltinProfile {
        name: "e2e",
        version: 1,
        json: include_str!("policies/comprehensive.json"),
    },
    BuiltinProfile {
        name: "comprehensive",
        version: 1,
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
        // No generic target image or commands can be safely assumed.
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
        let config = load("discovered-offline").unwrap();
        assert_eq!(config.profile.unwrap().version, 2);
        for ecosystem in config.discovered_execution.unwrap() {
            ecosystem.validate().unwrap();
            // Every executable ecosystem carries an install the build owns.
            // Authorizing a suite without one would mean running it against
            // dependencies nothing put there.
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
