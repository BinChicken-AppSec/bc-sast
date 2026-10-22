//! Deciding which documents of one standard a run works on.
//!
//! Every existing document is assessed where it is. A service with surface
//! for the standard and no document of its own gets a new one at its
//! convention's location, when the standard allows creation. An existing
//! document is proposed for relocation only when nothing about ownership
//! is in doubt: exactly one owning service, exactly one document, owned by
//! that service, whose convention is confident and not already satisfied.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::format::{Capabilities, Owner, Syntax};
use crate::frameworks::WebFramework;
use crate::location::{conventional_path, is_accepted, relative_to, Convention};

/// A package discovery found HTTP frameworks in.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpService {
    /// Repository-relative directory, `.` for the root.
    pub root: String,
    pub manifests: Vec<String>,
    pub frameworks: BTreeSet<WebFramework>,
}

/// An existing candidate the caller has read and classified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FoundSpec {
    pub path: String,
    /// Readable and repairable here, as opposed to unverifiable.
    pub usable: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    /// No document exists for the service; create one here.
    Create { path: String, syntax: Syntax },
    /// Assess (and repair if needed) an existing document, moving it to
    /// `relocate_to` if that is set.
    Existing {
        path: String,
        relocate_to: Option<String>,
    },
    /// An existing document that must not be touched.
    Unverifiable { path: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unit {
    /// The owning service's root, `.` when no service contains the file.
    pub service_root: String,
    /// The owner's frameworks and libraries, as reported.
    pub frameworks: Vec<String>,
    pub target: Target,
    /// Why the convention used for this unit applies.
    pub convention_basis: &'static str,
    /// The owner's framework builds this document from code.
    pub code_first: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Plan {
    pub units: Vec<Unit>,
    /// Decisions a reader should see: skipped creations, relocations not
    /// considered, and units beyond the cap.
    pub notes: Vec<String>,
}

/// Plan the units for `owners` and the existing `specs`, keeping at most
/// `max_units` of them. `fallback` is the convention for a document no
/// owner contains, and `capabilities` says whether documents may be
/// created or relocated at all.
pub fn plan(
    owners: &[Owner],
    fallback: &Convention,
    specs: &[FoundSpec],
    max_units: usize,
    capabilities: Capabilities,
) -> Plan {
    let mut result = Plan::default();
    let owner = |path: &str| {
        owners
            .iter()
            .filter(|owner| relative_to(&owner.root, path).is_some())
            .max_by_key(|owner| owner.root.len())
    };
    let unambiguous = owners.len() == 1 && specs.len() == 1;
    let mut owned_roots = BTreeSet::new();
    let mut unowned = Vec::new();
    for spec in specs {
        let service = owner(&spec.path);
        let frameworks = service.map(|s| s.stack.clone()).unwrap_or_default();
        let root = service.map_or(".".to_string(), |s| s.root.clone());
        match service {
            Some(service) => {
                owned_roots.insert(service.root.clone());
            }
            None => unowned.push(spec.path.clone()),
        }
        let chosen = service.map_or(*fallback, |s| s.convention);
        let target = if !spec.usable {
            Target::Unverifiable {
                path: spec.path.clone(),
            }
        } else {
            let misplaced = capabilities.relocate
                && service.is_some()
                && !is_accepted(&chosen, &root, &spec.path);
            let relocate_to = if misplaced && unambiguous {
                let syntax = Syntax::from_path(&spec.path).unwrap_or(chosen.syntax);
                Some(conventional_path(&chosen, &root, syntax))
            } else {
                if misplaced {
                    result.notes.push(format!(
                        "{} is outside the conventional location for its framework ({}), but \
                         relocation is only proposed for a single service with a single \
                         specification; it is assessed in place",
                        spec.path, chosen.path
                    ));
                }
                None
            };
            Target::Existing {
                path: spec.path.clone(),
                relocate_to,
            }
        };
        result.units.push(Unit {
            service_root: root,
            frameworks,
            target,
            convention_basis: chosen.basis,
            code_first: chosen.code_first,
        });
    }
    // A standard that repairs but never creates (OData) says so for each
    // service it found without a document, so the reason is on record.
    let repair_only = capabilities.repair && !capabilities.create;
    for service in owners.iter().filter(|_| repair_only) {
        if !owned_roots.contains(&service.root) {
            result.notes.push(format!(
                "No document is created for the service at {}: {}",
                service.root, service.convention.basis
            ));
        }
    }
    for service in owners.iter().filter(|_| capabilities.create) {
        if owned_roots.contains(&service.root) {
            continue;
        }
        if !unowned.is_empty() {
            result.notes.push(format!(
                "No specification was created for the service at {}: existing specification(s) \
                 {unowned:?} sit outside every service root and may already document it",
                service.root
            ));
            continue;
        }
        let chosen = service.convention;
        result.units.push(Unit {
            service_root: service.root.clone(),
            frameworks: service.stack.clone(),
            target: Target::Create {
                path: conventional_path(&chosen, &service.root, chosen.syntax),
                syntax: chosen.syntax,
            },
            convention_basis: chosen.basis,
            code_first: chosen.code_first,
        });
    }
    if result.units.len() > max_units {
        let skipped: Vec<String> = result.units[max_units..]
            .iter()
            .map(|unit| match &unit.target {
                Target::Create { path, .. }
                | Target::Existing { path, .. }
                | Target::Unverifiable { path } => path.clone(),
            })
            .collect();
        result.notes.push(format!(
            "{} specification document(s) beyond the per-run cap of {max_units} were not \
             assessed: {skipped:?}",
            skipped.len()
        ));
        result.units.truncate(max_units);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::SpecFormat;
    use crate::openapi::OPENAPI;
    use WebFramework::*;

    /// The OpenAPI plan for `services`, as the step makes it.
    fn plan(services: &[HttpService], specs: &[FoundSpec], max_units: usize) -> Plan {
        let owners = OPENAPI.owners(services, &[]);
        super::plan(
            &owners,
            &OPENAPI.fallback(),
            specs,
            max_units,
            Capabilities::FULL,
        )
    }

    fn service(root: &str, frameworks: &[WebFramework]) -> HttpService {
        HttpService {
            root: root.into(),
            manifests: vec![format!("{root}/pom.xml")],
            frameworks: frameworks.iter().copied().collect(),
        }
    }

    fn spec(path: &str, usable: bool) -> FoundSpec {
        FoundSpec {
            path: path.into(),
            usable,
        }
    }

    #[test]
    fn a_service_without_a_specification_gets_one_at_its_convention() {
        let result = plan(&[service(".", &[SpringBoot])], &[], 4);
        assert_eq!(
            result.units[0].target,
            Target::Create {
                path: "src/main/resources/static/openapi.yaml".into(),
                syntax: Syntax::Yaml
            }
        );
        assert!(result.units[0].convention_basis.contains("Spring"));
        let monorepo = plan(
            &[
                service("svc/a", &[Express]),
                service("svc/b", &[AspNetCore]),
            ],
            &[],
            4,
        );
        let paths: Vec<_> = monorepo
            .units
            .iter()
            .map(|unit| unit.target.clone())
            .collect();
        assert_eq!(
            paths,
            [
                Target::Create {
                    path: "svc/a/docs/api/openapi.yaml".into(),
                    syntax: Syntax::Yaml
                },
                Target::Create {
                    path: "svc/b/wwwroot/swagger/v1/swagger.json".into(),
                    syntax: Syntax::Json
                },
            ]
        );
    }

    #[test]
    fn a_single_misplaced_specification_is_proposed_for_relocation() {
        let result = plan(
            &[service(".", &[SpringBoot])],
            &[spec("openapi.yaml", true)],
            4,
        );
        assert_eq!(
            result.units[0].target,
            Target::Existing {
                path: "openapi.yaml".into(),
                relocate_to: Some("src/main/resources/static/openapi.yaml".into())
            }
        );
        assert!(result.notes.is_empty());
        let json = plan(
            &[service(".", &[SpringBoot])],
            &[spec("docs/swagger.json", true)],
            4,
        );
        assert_eq!(
            json.units[0].target,
            Target::Existing {
                path: "docs/swagger.json".into(),
                relocate_to: Some("src/main/resources/static/openapi.json".into())
            }
        );
    }

    #[test]
    fn accepted_locations_unknown_frameworks_and_ambiguity_never_relocate() {
        for (services, specs) in [
            (
                vec![service(".", &[SpringBoot])],
                vec![spec("src/main/resources/openapi.yaml", true)],
            ),
            (
                vec![service(".", &[Express])],
                vec![spec("openapi.yaml", true)],
            ),
            (
                vec![service(".", &[SpringBoot])],
                vec![spec("openapi.yaml", false)],
            ),
        ] {
            let result = plan(&services, &specs, 4);
            let kept = matches!(
                &result.units[0].target,
                Target::Existing {
                    relocate_to: None,
                    ..
                } | Target::Unverifiable { .. }
            );
            assert!(kept);
            assert!(result.notes.is_empty());
        }
        let two_specs = plan(
            &[service(".", &[SpringBoot])],
            &[
                spec("openapi.yaml", true),
                spec("src/main/resources/static/swagger.json", true),
            ],
            4,
        );
        assert!(two_specs.units.iter().all(|unit| matches!(
            unit.target,
            Target::Existing {
                relocate_to: None,
                ..
            }
        )));
        assert!(two_specs.notes[0].contains("assessed in place"));
    }

    #[test]
    fn specifications_are_owned_by_the_deepest_service_root() {
        let result = plan(
            &[service(".", &[Express]), service("svc", &[Rails])],
            &[spec("svc/swagger/v1/swagger.yaml", true)],
            4,
        );
        assert_eq!(result.units[0].service_root, "svc");
        assert_eq!(
            result.units[1].target,
            Target::Create {
                path: "docs/api/openapi.yaml".into(),
                syntax: Syntax::Yaml
            }
        );
    }

    #[test]
    fn a_specification_outside_every_service_blocks_creation() {
        let result = plan(
            &[service("svc", &[Flask])],
            &[spec("docs/openapi.yaml", true)],
            4,
        );
        assert_eq!(result.units.len(), 1);
        assert_eq!(result.units[0].service_root, ".");
        assert!(result.notes[0].contains("outside every service root"));
        // With no services at all, existing specifications are still assessed.
        let result = plan(&[], &[spec("openapi.json", true)], 4);
        assert_eq!(
            result.units[0].target,
            Target::Existing {
                path: "openapi.json".into(),
                relocate_to: None
            }
        );
        assert!(plan(&[], &[], 4).units.is_empty());
    }

    #[test]
    fn units_beyond_the_cap_are_named_rather_than_dropped_silently() {
        let services: Vec<_> = (0..3).map(|i| service(&format!("s{i}"), &[Gin])).collect();
        let result = plan(&services, &[], 2);
        assert_eq!(result.units.len(), 2);
        let note = result.notes.last().unwrap();
        assert!(
            note.contains("s2/api/openapi.yaml") && note.contains("cap of 2"),
            "{note}"
        );
        let unverifiable_capped = plan(
            &[],
            &[spec("a/openapi.yaml", true), spec("b/openapi.yaml", false)],
            1,
        );
        assert!(unverifiable_capped.notes[0].contains("b/openapi.yaml"));
        let existing_capped = plan(
            &[],
            &[spec("a/openapi.yaml", false), spec("b/openapi.yaml", true)],
            1,
        );
        assert!(existing_capped.notes[0].contains("b/openapi.yaml"));
    }
}

#[cfg(test)]
mod capability_tests {
    use super::*;
    use crate::format::SpecFormat;
    use crate::openapi::OPENAPI;

    #[test]
    fn a_check_only_standard_never_creates_or_relocates() {
        let services = [HttpService {
            root: ".".into(),
            manifests: vec!["pom.xml".into()],
            frameworks: [WebFramework::SpringBoot].into_iter().collect(),
        }];
        let owners = OPENAPI.owners(&services, &[]);
        let spec = FoundSpec {
            path: "openapi.yaml".into(),
            usable: true,
        };
        let only = plan(
            &owners,
            &OPENAPI.fallback(),
            &[spec],
            4,
            Capabilities::CHECK_ONLY,
        );
        assert_eq!(
            only.units[0].target,
            Target::Existing {
                path: "openapi.yaml".into(),
                relocate_to: None
            }
        );
        assert!(only.notes.is_empty());
        let none = plan(
            &owners,
            &OPENAPI.fallback(),
            &[],
            4,
            Capabilities::CHECK_ONLY,
        );
        assert!(none.units.is_empty());
        assert!(none.notes.is_empty());
    }

    #[test]
    fn a_repair_only_standard_notes_services_it_does_not_create_for() {
        use crate::libraries::{ApiLibrary, ApiSurface};
        use crate::odata::ODATA;
        let surfaces = [ApiSurface {
            root: "srv".into(),
            manifests: vec!["srv/package.json".into()],
            libraries: [ApiLibrary::SapCap].into_iter().collect(),
        }];
        let owners = ODATA.owners(&[], &surfaces);
        let capabilities = ODATA.capabilities();
        let none = plan(&owners, &ODATA.fallback(), &[], 4, capabilities);
        assert!(none.units.is_empty());
        assert_eq!(none.notes.len(), 1);
        assert!(none.notes[0].starts_with("No document is created for the service at srv: SAP CAP"));
        let spec = FoundSpec {
            path: "srv/$metadata.xml".into(),
            usable: true,
        };
        let owned = plan(&owners, &ODATA.fallback(), &[spec], 4, capabilities);
        assert_eq!(owned.units.len(), 1);
        assert!(owned.notes.is_empty());
    }
}
