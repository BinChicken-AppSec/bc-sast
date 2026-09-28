//! OData CSDL: the `$metadata` of an OData service, as XML (EDMX) or
//! CSDL JSON.
//!
//! Documents are `*.edmx`, `$metadata`, `$metadata.xml` and
//! `$metadata.json`, `*.csdl.xml` and `*.csdl.json`, and XML or JSON
//! files whose name mentions metadata, EDMX, CSDL or OData when their
//! content is CSDL. XML is read with `bc_xml` (DOCTYPE refused, bounded),
//! JSON with `serde_json`, both into the model in [`model`].
//!
//! OData version 4 (OASIS namespaces, CSDL JSON) is validated and
//! repaired. Versions 2 and 3 (Microsoft EDMX namespaces) are legacy: they
//! are validated and reported, never rewritten. Nothing is ever created
//! or moved: ASP.NET Core OData, SAP CAP and Olingo generate CSDL from
//! the model at run time, and none reads a static file from a
//! conventional place (see [`location`]).
//!
//! Operations are what a client addresses: `entity_set`, `singleton`,
//! `action` and `function`, each with its simple name. Owners are
//! services with an OData server library.

pub mod location;
pub mod model;
pub mod validate;

#[cfg(test)]
mod tests;

use std::collections::BTreeSet;

use serde_json::Value;

use crate::diagnostic::Diagnostic;
use crate::format::{
    name_of, Candidate, Capabilities, FormatId, NameStrength, Owner, Peer, SpecFormat, SpecVersion,
    Syntax,
};
use crate::inventory::{CitedOperation, Completeness, Operation};
use crate::libraries::{ApiFamily, ApiSurface};
use crate::location::Convention;
use crate::parse::ParseFailure;
use crate::plan::HttpService;
use crate::xml_preserve::{kept_values, sections, touched, Member, Section};
use validate::{list, name, simple};

/// OData CSDL.
pub struct OData;

/// The registered instance.
pub static ODATA: OData = OData;

/// Repairs OData 4 documents; never creates or moves one.
const CAPABILITIES: Capabilities = Capabilities {
    create: false,
    repair: true,
    relocate: false,
};

const KINDS: [&str; 4] = ["entity_set", "singleton", "action", "function"];

const NEVER_CREATED: &str = "OData CSDL documents are never created by this step: the framework \
                             generates them from its model at run time";

const SECTIONS: [Section; 4] = [
    Section {
        key: "schemas",
        pointer: "schemas",
        noun: "schema",
        members: &[],
    },
    Section {
        key: "types",
        pointer: "types",
        noun: "type",
        members: &[
            Member {
                key: "properties",
                pointer: "properties",
                noun: "property",
            },
            Member {
                key: "navigation",
                pointer: "navigation",
                noun: "navigation property",
            },
            Member {
                key: "members",
                pointer: "members",
                noun: "enum member",
            },
        ],
    },
    Section {
        key: "operations",
        pointer: "operations",
        noun: "operation",
        members: &[],
    },
    Section {
        key: "containers",
        pointer: "containers",
        noun: "entity container",
        members: &[
            Member {
                key: "entitySets",
                pointer: "entitySets",
                noun: "entity set",
            },
            Member {
                key: "singletons",
                pointer: "singletons",
                noun: "singleton",
            },
            Member {
                key: "actionImports",
                pointer: "actionImports",
                noun: "action import",
            },
            Member {
                key: "functionImports",
                pointer: "functionImports",
                noun: "function import",
            },
        ],
    },
];

fn declared_version(model: &Value) -> Option<SpecVersion> {
    match model::major(model) {
        Some(2) => Some(SpecVersion::Odata2),
        Some(3) => Some(SpecVersion::Odata3),
        Some(4) => Some(SpecVersion::Odata4),
        _ => None,
    }
}

/// Whether `text` is an OData simple identifier.
fn is_identifier(text: &str) -> bool {
    let mut characters = text.chars();
    text.chars().count() <= 128
        && characters
            .next()
            .is_some_and(|c| c == '_' || c.is_alphabetic())
        && characters.all(|c| c == '_' || c.is_alphanumeric())
}

fn declared_operations(model: &Value) -> BTreeSet<Operation> {
    let mut operations = BTreeSet::new();
    for container in list(model, "containers") {
        for (key, kind) in [("entitySets", "entity_set"), ("singletons", "singleton")] {
            for child in list(container, key) {
                operations.insert(Operation::new(kind, name(child)));
            }
        }
        // A legacy function import is the operation itself.
        for import in list(container, "functionImports") {
            if import["function"].is_null() {
                operations.insert(Operation::new("function", name(import)));
            }
        }
    }
    for operation in list(model, "operations") {
        let kind = operation["kind"]
            .as_str()
            .unwrap_or_default()
            .to_ascii_lowercase();
        operations.insert(Operation::new(kind, simple(name(operation))));
    }
    operations.retain(|operation| !operation.path.is_empty());
    operations
}

fn violations(original: &Value, repaired: &Value, before: &[Diagnostic]) -> Vec<String> {
    let mut out = Vec::new();
    if original["odata"] != repaired["odata"] || original["format"] != repaired["format"] {
        out.push(
            "the repair changed the OData version or CSDL syntax; repairs keep the author's"
                .to_string(),
        );
        return out;
    }
    if original["version"] != repaired["version"] && !touched(before, "/version") {
        out.push("changed the CSDL version, which had no diagnostics".to_string());
    }
    if original["entityContainer"] != repaired["entityContainer"]
        && !touched(before, "/entityContainer")
    {
        out.push("changed $EntityContainer, which had no diagnostics".to_string());
    }
    out.extend(kept_values(
        original,
        repaired,
        "references",
        "/references",
        before,
        |reference| {
            format!(
                "removed or changed the reference to `{}`",
                reference["uri"].as_str().unwrap_or_default()
            )
        },
    ));
    out.extend(sections(original, repaired, &SECTIONS, before));
    out
}

/// Whether `path` names a JSON document, or `text` looks like one for a
/// name without an extension (`$metadata`).
fn syntax_of(path: &str, text: &str) -> Syntax {
    let lower = path.to_ascii_lowercase();
    if lower.ends_with(".json") || (!lower.ends_with(".xml") && text.trim_start().starts_with('{'))
    {
        Syntax::Json
    } else {
        Syntax::Xml
    }
}

impl SpecFormat for OData {
    fn id(&self) -> FormatId {
        FormatId::OData
    }

    fn name(&self) -> &'static str {
        "OData CSDL"
    }

    fn capabilities(&self) -> Capabilities {
        CAPABILITIES
    }

    fn document_capabilities(&self, version: Option<SpecVersion>) -> Capabilities {
        match version {
            Some(SpecVersion::Odata2 | SpecVersion::Odata3) => Capabilities::CHECK_ONLY,
            _ => CAPABILITIES,
        }
    }

    fn candidate_strength(&self, path: &str) -> Option<NameStrength> {
        let lower = path.to_ascii_lowercase();
        let name = lower.rsplit('/').next().unwrap_or_default();
        if matches!(name, "$metadata" | "$metadata.xml" | "$metadata.json")
            || name.ends_with(".edmx")
            || name.ends_with(".csdl.xml")
            || name.ends_with(".csdl.json")
        {
            return Some(NameStrength::Strong);
        }
        let stem = name
            .strip_suffix(".xml")
            .or_else(|| name.strip_suffix(".json"))?;
        ["metadata", "edmx", "csdl", "odata"]
            .iter()
            .any(|word| stem.contains(word))
            .then_some(NameStrength::Weak)
    }

    fn classify(&self, path: &str, bytes: &[u8], max_bytes: usize) -> Candidate {
        let Some(strength) = self.candidate_strength(path) else {
            return Candidate::NotASpec;
        };
        let strong = strength == NameStrength::Strong;
        let claims = |text: &str| {
            strong
                || text.contains(model::EDMX4)
                || text.contains(model::EDMX_LEGACY)
                || text.contains("\"$Version\"")
        };
        let unreadable = |text: &str, reason: String| {
            if claims(text) {
                Candidate::Unverifiable { reason }
            } else {
                Candidate::NotASpec
            }
        };
        if bytes.len() > max_bytes {
            let lossy = String::from_utf8_lossy(&bytes[..max_bytes]);
            return unreadable(
                &lossy,
                format!("larger than the {max_bytes}-byte specification cap"),
            );
        }
        let Ok(text) = std::str::from_utf8(bytes) else {
            return unreadable("", "not UTF-8 text".into());
        };
        let syntax = syntax_of(path, text);
        let spec = |model: Value| Candidate::Spec {
            syntax,
            version: declared_version(&model),
            document: model,
        };
        let not_csdl = |reason: &str| {
            if strong {
                Candidate::Unverifiable {
                    reason: reason.into(),
                }
            } else {
                Candidate::NotASpec
            }
        };
        if syntax == Syntax::Json {
            return match crate::parse::parse(text, syntax) {
                Ok(document) => model::from_json(&document).map_or_else(
                    || not_csdl("a JSON document without $Version is not CSDL"),
                    spec,
                ),
                // Only a file literally named for CSDL that is not JSON at
                // all may be replaced wholesale.
                Err(ParseFailure::Malformed(reason)) if strong => {
                    Candidate::Malformed { syntax, reason }
                }
                Err(ParseFailure::Malformed(reason) | ParseFailure::Unverifiable(reason)) => {
                    unreadable(text, reason)
                }
            };
        }
        let document = match crate::xml::read(text) {
            Ok(document) => document,
            Err(reason) => return unreadable(text, reason),
        };
        let root = &document.root;
        let entity_framework = root.name.local == "Edmx"
            && root
                .namespace
                .as_deref()
                .is_some_and(|namespace| model::EDMX_ENTITY_FRAMEWORK.contains(&namespace));
        match model::from_xml(&document) {
            Some(model) => spec(model),
            // An Entity Framework designer model is not OData metadata.
            None if entity_framework => Candidate::NotASpec,
            None => not_csdl("the root element is not an OData edmx:Edmx"),
        }
    }

    fn parse(&self, text: &str, syntax: Syntax) -> Result<Value, ParseFailure> {
        if syntax == Syntax::Json {
            let document = crate::parse::parse(text, Syntax::Json)?;
            return model::from_json(&document).ok_or_else(|| {
                ParseFailure::Malformed(
                    "the JSON document has no $Version, so it is not CSDL".into(),
                )
            });
        }
        let document = crate::xml::read_for_parse(text)?;
        model::from_xml(&document).ok_or_else(|| {
            ParseFailure::Malformed("the root element is not an OData edmx:Edmx".into())
        })
    }

    fn version(&self, document: &Value) -> Option<SpecVersion> {
        declared_version(document)
    }

    fn validate(&self, document: &Value, peers: &[Peer<'_>]) -> Vec<Diagnostic> {
        validate::validate(document, peers)
    }

    fn operations(&self, document: &Value) -> Vec<Operation> {
        declared_operations(document).into_iter().collect()
    }

    fn compare(
        &self,
        document: &Value,
        peers: &[Peer<'_>],
        inventory: &[Operation],
    ) -> Completeness {
        let own = declared_operations(document);
        let mut documented = own.clone();
        for peer in peers {
            documented.extend(declared_operations(peer.document));
        }
        let served: BTreeSet<&Operation> = inventory.iter().collect();
        let missing: BTreeSet<Operation> = inventory
            .iter()
            .filter(|operation| !documented.contains(*operation))
            .cloned()
            .collect();
        Completeness {
            missing: missing.into_iter().collect(),
            unverified: own
                .into_iter()
                .filter(|operation| !served.contains(operation))
                .collect(),
        }
    }

    fn preservation(
        &self,
        original: &Value,
        repaired: &Value,
        before: &[Diagnostic],
    ) -> Vec<String> {
        violations(original, repaired, before)
    }

    fn inventory_operation(&self, method: &str, path: &str) -> Result<Operation, String> {
        let method = method.trim().to_ascii_lowercase();
        if !KINDS.contains(&method.as_str()) {
            return Err(format!(
                "inventory method {method:?} is not entity_set, singleton, action or function"
            ));
        }
        let path = path.trim();
        if !is_identifier(path) {
            return Err(format!(
                "inventory path {path:?} is not an OData simple identifier"
            ));
        }
        Ok(Operation::new(method, path))
    }

    fn emit(&self, _: &Value, _: Syntax) -> Result<String, String> {
        Err(NEVER_CREATED.into())
    }

    fn new_document_problems(&self, _: &Value) -> Vec<String> {
        vec![NEVER_CREATED.into()]
    }

    fn owners(&self, _: &[HttpService], surfaces: &[ApiSurface]) -> Vec<Owner> {
        surfaces
            .iter()
            .filter_map(|surface| {
                let libraries = surface.of(ApiFamily::OData);
                (!libraries.is_empty()).then(|| Owner {
                    root: surface.root.clone(),
                    stack: libraries.iter().map(name_of).collect(),
                    convention: location::convention_for(&libraries),
                })
            })
            .collect()
    }

    fn fallback(&self) -> Convention {
        location::FALLBACK
    }

    fn scans_source(&self) -> bool {
        false
    }

    fn scan_source(&self, _: &str, _: &str) -> Vec<CitedOperation> {
        Vec::new()
    }
}
