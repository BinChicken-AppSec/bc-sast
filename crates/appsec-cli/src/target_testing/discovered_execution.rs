use std::collections::BTreeSet;

use appsec_target_tests::{PackageTestEnvironment, TargetTestPlan};
use serde::{Deserialize, Serialize};

use crate::target_executor::{CommandKind, ContainerPolicy, TestCommand};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProvisioningPolicy {
    pub pins: Vec<String>,
    pub argv: Vec<String>,
    pub scripts_disabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EcosystemPolicy {
    pub language: String,
    pub image: String,
    pub allowed_argv: Vec<Vec<String>>,
    pub provisioning: ProvisioningPolicy,
}

impl EcosystemPolicy {
    pub fn validate(&self) -> Result<(), String> {
        if self.language.trim().is_empty() {
            return Err("discovered execution requires a nonempty language".into());
        }
        if self.allowed_argv.is_empty() || self.allowed_argv.len() > 63 {
            return Err(format!(
                "{}: discovered execution requires 1 to 63 allowed argv alternatives beside its provisioning command",
                self.language
            ));
        }
        if self.provisioning.pins.is_empty() || self.provisioning.pins.len() > 16 {
            return Err(format!(
                "{}: provisioning requires 1 to 16 dependency pins",
                self.language
            ));
        }
        if let Some(pin) =
            self.provisioning.pins.iter().find(|pin| {
                pin.is_empty() || pin.contains('/') || pin.contains('\\') || pin == &"."
            })
        {
            return Err(format!(
                "{}: dependency pin {pin:?} must be a plain file name beside the manifest",
                self.language
            ));
        }
        ContainerPolicy {
            image: self.image.clone(),
            commands: std::iter::once(command(
                0,
                ".",
                &self.provisioning.argv,
                CommandKind::Provision,
            ))
            .chain(
                self.allowed_argv
                    .iter()
                    .enumerate()
                    .map(|(index, argv)| command(index + 1, ".", argv, CommandKind::Existing)),
            )
            .collect(),
        }
        .validate()
    }
}

fn command(id: usize, cwd: &str, argv: &[String], kind: CommandKind) -> TestCommand {
    TestCommand {
        id: match kind {
            CommandKind::Provision => format!("provision-{id}"),
            _ => format!("discovered-{id}"),
        },
        cwd: cwd.into(),
        argv: argv.to_vec(),
        kind,
        expected_failure_contains: None,
    }
}

pub fn validate_catalog(catalog: &[EcosystemPolicy]) -> Result<(), String> {
    if catalog.is_empty() || catalog.len() > 64 {
        return Err("discovered execution requires 1 to 64 ecosystem policies".into());
    }
    let mut languages = BTreeSet::new();
    for policy in catalog {
        if !languages.insert(&policy.language) {
            return Err(format!(
                "duplicate execution ecosystem: {}",
                policy.language
            ));
        }
        policy.validate()?;
    }
    Ok(())
}

#[derive(Debug, Default, PartialEq)]
pub struct Resolution {
    pub policies: Vec<ContainerPolicy>,
    pub refusals: Vec<String>,
    pub notes: Vec<String>,
}

fn file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn pin_for<'a>(
    package: &PackageTestEnvironment,
    approved: &'a ProvisioningPolicy,
) -> Option<&'a str> {
    approved
        .pins
        .iter()
        .find(|pin| {
            file_name(&package.manifest) == pin.as_str()
                || package
                    .lockfiles
                    .iter()
                    .any(|lockfile| file_name(lockfile) == pin.as_str())
        })
        .map(String::as_str)
}

pub fn resolve(plan: &TargetTestPlan, catalog: &[EcosystemPolicy]) -> Resolution {
    let mut resolution = Resolution::default();
    if let Err(error) = validate_catalog(catalog) {
        resolution
            .refusals
            .push(format!("Execution refused: {error}"));
        return resolution;
    }
    let mut seen = BTreeSet::new();
    let mut issued = 0usize;
    let mut packages: Vec<_> = plan.packages.iter().collect();
    packages.sort_by_key(|p| (&p.root, &p.language, &p.manifest));
    if packages.is_empty() {
        resolution.refusals.push(format!("Execution refused: no recognized package ecosystem among {} inspected entries; discovered test paths: {:?}; project evidence: {:?}", plan.entries_inspected, plan.test_artifacts.iter().map(|t| &t.path).collect::<Vec<_>>(), plan.expectation_sources));
    }
    for package in packages {
        let Some(approved) = catalog.iter().find(|p| p.language == package.language) else {
            resolution.refusals.push(format!(
                "Execution refused for {} ({}): ecosystem {:?} has no build-owned image/allowlist",
                package.root, package.manifest, package.language
            ));
            continue;
        };
        if package.command_suggestions.is_empty() {
            resolution.refusals.push(format!(
                "Execution refused for {} ({}): no test command was discovered for {}",
                package.root, package.manifest, package.language
            ));
            continue;
        }
        let Some(pin) = pin_for(package, &approved.provisioning) else {
            resolution.refusals.push(format!(
                "Execution refused for {} ({}): dependency provisioning for {} requires one of {:?} beside the manifest; discovered pins: {:?}. Without one, an install would resolve versions from the network and the suite would run against no dependencies, so this package's tests are not executed",
                package.root, package.manifest, package.language, approved.provisioning.pins, package.lockfiles
            ));
            continue;
        };
        let mut commands = vec![command(
            issued,
            &package.root,
            &approved.provisioning.argv,
            CommandKind::Provision,
        )];
        let mut suggestions: Vec<_> = package.command_suggestions.iter().collect();
        suggestions.sort_by_key(|s| (&s.cwd, &s.argv, &s.evidence_path));
        for suggestion in suggestions {
            let reason =
                if suggestion.cwd != package.root || suggestion.evidence_path != package.manifest {
                    Some("suggestion cwd/evidence does not match its discovered package")
                } else if !approved.allowed_argv.contains(&suggestion.argv) {
                    Some("argv does not match a build-owned allowlist entry")
                } else {
                    None
                };
            if let Some(reason) = reason {
                resolution.refusals.push(format!(
                    "Execution refused for {}: {:?}: {reason}",
                    package.manifest, suggestion.argv
                ));
                continue;
            }
            let key = (&package.language, &suggestion.cwd, &suggestion.argv);
            if !seen.insert(key) {
                continue;
            }
            if issued + commands.len() >= 64 {
                resolution.refusals.push(format!(
                    "Execution refused for {}: total command cap of 64 exceeded",
                    package.manifest
                ));
                continue;
            }
            commands.push(command(
                issued + commands.len(),
                &suggestion.cwd,
                &suggestion.argv,
                CommandKind::Existing,
            ));
        }
        if commands.len() == 1 {
            continue;
        }
        let policy = ContainerPolicy {
            image: approved.image.clone(),
            commands,
        };
        match policy.validate() {
            Ok(()) => {
                resolution.notes.push(format!(
                    "{} ({}): dependencies are installed once with {:?}, pinned by {pin}, in the only container that has a network. Install-time scripts are {}.",
                    package.root,
                    package.language,
                    approved.provisioning.argv,
                    if approved.provisioning.scripts_disabled {
                        "disabled by that command"
                    } else {
                        "not controlled by this ecosystem, so package-supplied build logic can run during the install"
                    }
                ));
                issued += policy.commands.len();
                resolution.policies.push(policy);
            }
            Err(error) => resolution.refusals.push(format!(
                "Execution refused for {}: {error}",
                package.manifest
            )),
        }
    }
    resolution
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target_testing::builtin_profiles;

    fn catalog() -> Vec<EcosystemPolicy> {
        builtin_profiles::load("discovered-offline")
            .unwrap()
            .discovered_execution
            .unwrap()
    }

    fn plan() -> (tempfile::TempDir, TargetTestPlan) {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join("package.json"),
            r#"{"scripts":{"test":"node --test"}}"#,
        )
        .unwrap();
        std::fs::write(root.path().join("package-lock.json"), "{}").unwrap();
        let plan = appsec_target_tests::discover(root.path()).unwrap();
        (root, plan)
    }

    fn as_ecosystem(plan: &mut TargetTestPlan, entry: &EcosystemPolicy) {
        let package = &mut plan.packages[0];
        package.language.clone_from(&entry.language);
        package.lockfiles = vec![entry.provisioning.pins[0].clone()];
        package.command_suggestions[0]
            .argv
            .clone_from(&entry.allowed_argv[0]);
    }

    #[test]
    fn discovered_suite_is_authorized_and_each_ecosystem_uses_its_own_image() {
        let (_, mut plan) = plan();
        let catalog = catalog();
        let mut images = BTreeSet::new();
        for entry in &catalog {
            as_ecosystem(&mut plan, entry);
            let resolved = resolve(&plan, &catalog);
            assert!(resolved.refusals.is_empty(), "{:?}", resolved.refusals);
            assert_eq!(resolved.policies.len(), 1);
            resolved.policies[0].validate().unwrap();
            assert_eq!(resolved.policies[0].image, entry.image);
            assert!(images.insert(entry.image.clone()));
            let commands = &resolved.policies[0].commands;
            assert_eq!(commands.len(), 2);
            assert_eq!(commands[0].kind, CommandKind::Provision);
            assert_eq!(commands[0].argv, entry.provisioning.argv);
            assert_eq!(commands[0].cwd, ".");
            assert_eq!(commands[1].kind, CommandKind::Existing);
            assert_eq!(commands[1].argv, entry.allowed_argv[0]);
            assert_eq!(commands[1].cwd, ".");
            assert!(commands
                .iter()
                .all(|c| c.expected_failure_contains.is_none()));
            assert_eq!(resolved.notes.len(), 1);
            assert!(
                resolved.notes[0].contains(if entry.provisioning.scripts_disabled {
                    "disabled by that command"
                } else {
                    "not controlled by this ecosystem"
                })
            );
        }
    }

    #[test]
    fn a_package_with_no_dependency_pin_is_refused_instead_of_resolved_or_run_unprovisioned() {
        let (_, mut plan) = plan();
        let catalog = catalog();
        plan.packages[0].lockfiles.clear();
        let resolved = resolve(&plan, &catalog);
        assert!(resolved.policies.is_empty());
        assert!(resolved.notes.is_empty());
        assert_eq!(resolved.refusals.len(), 1);
        let refusal = &resolved.refusals[0];
        assert!(refusal.contains("package.json"));
        assert!(refusal.contains("package-lock.json"));
        assert!(refusal.contains("resolve versions from the network"));
        assert!(refusal.contains("tests are not executed"));
        plan.packages[0].lockfiles = vec!["pnpm-lock.yaml".into()];
        let refusal = resolve(&plan, &catalog).refusals.remove(0);
        assert!(refusal.contains("pnpm-lock.yaml"), "{refusal}");
        plan.packages[0].language = "Python".into();
        plan.packages[0].manifest = "requirements.txt".into();
        plan.packages[0].lockfiles.clear();
        plan.packages[0].command_suggestions[0].evidence_path = "requirements.txt".into();
        plan.packages[0].command_suggestions[0].argv =
            vec!["python".into(), "-m".into(), "pytest".into()];
        let resolved = resolve(&plan, &catalog);
        assert!(resolved.refusals.is_empty(), "{:?}", resolved.refusals);
        assert_eq!(resolved.policies.len(), 1);
    }

    #[test]
    fn mismatches_unknown_ecosystems_and_missing_commands_are_explicit_refusals() {
        let (_, mut plan) = plan();
        let catalog = catalog();
        plan.packages[0].command_suggestions[0]
            .argv
            .push("--unsafe".into());
        let resolved = resolve(&plan, &catalog);
        assert!(resolved.policies.is_empty());
        assert!(resolved.notes.is_empty());
        assert!(resolved.refusals[0].contains("allowlist"));
        assert!(resolved.refusals[0].contains("package.json"));
        plan.packages[0].language = "COBOL".into();
        assert!(resolve(&plan, &catalog).refusals[0].contains("COBOL"));
        plan.packages[0].language = "Python".into();
        plan.packages[0].command_suggestions.clear();
        assert!(resolve(&plan, &catalog).refusals[0]
            .contains("no test command was discovered for Python"));
        plan.packages.clear();
        assert!(resolve(&plan, &catalog).refusals[0].contains("no recognized package ecosystem"));
    }

    #[test]
    fn evidence_and_paths_are_checked_and_total_commands_are_bounded() {
        let (_, mut plan) = plan();
        let catalog = catalog();
        plan.packages[0].command_suggestions[0].cwd = "elsewhere".into();
        assert!(resolve(&plan, &catalog).refusals[0].contains("cwd/evidence"));
        plan.packages[0].command_suggestions[0].cwd = ".".into();
        plan.packages[0].command_suggestions[0].evidence_path = "other.json".into();
        assert!(resolve(&plan, &catalog).refusals[0].contains("cwd/evidence"));
        plan.packages[0].command_suggestions[0].evidence_path = "package.json".into();
        plan.packages[0].root = "../escape".into();
        plan.packages[0].command_suggestions[0].cwd = "../escape".into();
        assert!(resolve(&plan, &catalog).refusals[0].contains("invalid target-test command cwd"));
        let template = plan.packages[0].clone();
        plan.packages.clear();
        for i in 0..33 {
            let mut package = template.clone();
            package.root = format!("pkg{i:03}");
            package.manifest = format!("{}/package.json", package.root);
            package.lockfiles = vec![format!("{}/package-lock.json", package.root)];
            package.command_suggestions[0].cwd.clone_from(&package.root);
            package.command_suggestions[0]
                .evidence_path
                .clone_from(&package.manifest);
            package
                .command_suggestions
                .push(package.command_suggestions[0].clone());
            plan.packages.push(package);
        }
        let resolved = resolve(&plan, &catalog);
        assert_eq!(resolved.policies.len(), 32);
        assert_eq!(
            resolved
                .policies
                .iter()
                .map(|policy| policy.commands.len())
                .sum::<usize>(),
            64
        );
        let ids: BTreeSet<_> = resolved
            .policies
            .iter()
            .flat_map(|policy| policy.commands.iter().map(|command| &command.id))
            .collect();
        assert_eq!(ids.len(), 64, "command ids must be unique across policies");
        assert_eq!(resolved.refusals.len(), 1);
        assert!(resolved.refusals[0].contains("cap of 64"));
        plan.packages.reverse();
        assert_eq!(resolve(&plan, &catalog), resolved);
    }

    #[test]
    fn invalid_catalogs_fail_closed_without_relaxing_executor_validation() {
        let (_, plan) = plan();
        let mut catalog = catalog();
        catalog[0].image = "rust:latest".into();
        assert!(validate_catalog(&catalog).unwrap_err().contains("sha256"));
        assert!(resolve(&plan, &catalog).refusals[0].contains("sha256"));
        let mut entry = catalog.pop().unwrap();
        entry.language.clear();
        assert!(entry.validate().unwrap_err().contains("nonempty"));
        entry.language = "test".into();
        entry.allowed_argv.clear();
        assert!(entry.validate().unwrap_err().contains("1 to 63"));
        entry.allowed_argv = vec![vec!["sh".into(), "-c".into(), "test".into()]];
        assert!(entry.validate().unwrap_err().contains("shell interpreter"));
        entry.allowed_argv = vec![vec!["cargo".into(), "test".into()]];
        entry.provisioning.argv = vec!["sh".into(), "-c".into(), "curl | sh".into()];
        assert!(entry.validate().unwrap_err().contains("shell interpreter"));
        entry.provisioning.argv = vec!["cargo".into(), "fetch".into(), "--locked".into()];
        entry.provisioning.pins.clear();
        assert!(entry
            .validate()
            .unwrap_err()
            .contains("1 to 16 dependency pins"));
        for pin in ["../Cargo.lock", "vendor/Cargo.lock", "", "."] {
            entry.provisioning.pins = vec![pin.into()];
            assert!(entry
                .validate()
                .unwrap_err()
                .contains("plain file name beside the manifest"));
        }
        entry.provisioning.pins = vec!["Cargo.lock".into()];
        entry.validate().unwrap();
        assert!(validate_catalog(&[]).is_err());
        assert!(validate_catalog(&vec![entry.clone(); 65]).is_err());
        assert!(validate_catalog(&[entry.clone(), entry])
            .unwrap_err()
            .contains("duplicate"));
    }
}
