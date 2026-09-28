//! WSDL: SOAP services described by WSDL 1.1 or 2.0, with XML Schema
//! types embedded in `types` or imported from `.xsd` files.
//!
//! Documents are `*.wsdl` files, and `*.xml` files named for WSDL or SOAP
//! whose root is a WSDL description. `*.xsd` files are read too, as
//! supporting documents: the schemas a WSDL imports, checked for the
//! imports and types that span files but never assessed or written
//! themselves. Everything is read with `bc_xml` (DOCTYPE refused, bounded)
//! into the model in [`model`], and no import is ever fetched: a URL is
//! reported as unverifiable (see [`validate`]).
//!
//! Operations are port type (WSDL 2.0: interface) operations: `method` is
//! `operation` and `path` is `PortType/operation`, or just the operation
//! name to match it in any port type. Owners are services with a SOAP
//! server library. A new document is WSDL 1.1, document/literal wrapped,
//! the most interoperable style; a repair keeps the version, prefixes and
//! definitions the author wrote.

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
use validate::{list, name};

/// WSDL.
pub struct Wsdl;

/// The registered instance.
pub static WSDL: Wsdl = Wsdl;

/// The inventory kind of every WSDL operation.
const METHOD: &str = "operation";

const BINDING_OPERATIONS: Member = Member {
    key: "operations",
    pointer: "operations",
    noun: "binding operation",
};
const MESSAGES: Section = Section {
    key: "messages",
    pointer: "messages",
    noun: "message",
    members: &[Member {
        key: "parts",
        pointer: "parts",
        noun: "part",
    }],
};
const SECTIONS_11: [Section; 4] = [
    MESSAGES,
    Section {
        key: "interfaces",
        pointer: "portTypes",
        noun: "portType",
        members: &[Member {
            key: "operations",
            pointer: "operations",
            noun: "operation",
        }],
    },
    Section {
        key: "bindings",
        pointer: "bindings",
        noun: "binding",
        members: &[BINDING_OPERATIONS],
    },
    Section {
        key: "services",
        pointer: "services",
        noun: "service",
        members: &[Member {
            key: "endpoints",
            pointer: "ports",
            noun: "port",
        }],
    },
];
const SECTIONS_20: [Section; 3] = [
    Section {
        key: "interfaces",
        pointer: "interfaces",
        noun: "interface",
        members: &[Member {
            key: "operations",
            pointer: "operations",
            noun: "operation",
        }],
    },
    Section {
        key: "bindings",
        pointer: "bindings",
        noun: "binding",
        members: &[BINDING_OPERATIONS],
    },
    Section {
        key: "services",
        pointer: "services",
        noun: "service",
        members: &[Member {
            key: "endpoints",
            pointer: "endpoints",
            noun: "endpoint",
        }],
    },
];

fn is_ncname(text: &str) -> bool {
    bc_xml::is_ncname(text)
}

/// The version a model declares.
fn declared_version(model: &Value) -> Option<SpecVersion> {
    match model["version"].as_str() {
        Some("1.1") => Some(SpecVersion::Wsdl11),
        Some("2.0") => Some(SpecVersion::Wsdl20),
        _ => None,
    }
}

/// Every operation `model` declares, as `PortType/operation`.
fn declared_operations(model: &Value) -> BTreeSet<Operation> {
    list(model, "interfaces")
        .iter()
        .flat_map(|interface| {
            list(interface, "operations")
                .iter()
                .map(move |operation| (name(interface), name(operation)))
        })
        .filter(|(interface, operation)| !interface.is_empty() && !operation.is_empty())
        .map(|(interface, operation)| Operation::new(METHOD, format!("{interface}/{operation}")))
        .collect()
}

/// Whether a documented `PortType/operation` is the inventory's `served`,
/// which may leave the port type out.
fn matches(documented: &Operation, served: &Operation) -> bool {
    documented.path == served.path
        || (!served.path.contains('/')
            && documented
                .path
                .rsplit_once('/')
                .is_some_and(|(_, operation)| operation == served.path))
}

/// Schema declarations as `{namespace}name` labels, by kind.
fn declarations(model: &Value) -> BTreeSet<String> {
    list(model, "schemas")
        .iter()
        .flat_map(|schema| {
            let namespace = schema["targetNamespace"].as_str().unwrap_or_default();
            ["elements", "types"].into_iter().flat_map(move |key| {
                list(schema, key).iter().map(move |declared| {
                    format!(
                        "{} `{{{namespace}}}{}`",
                        &key[..key.len() - 1],
                        declared.as_str().unwrap_or_default()
                    )
                })
            })
        })
        .collect()
}

/// Every way `repaired` fails to keep what `original` declared.
fn violations(original: &Value, repaired: &Value, before: &[Diagnostic]) -> Vec<String> {
    let mut out = Vec::new();
    if original["version"] != repaired["version"] {
        out.push(
            "the repair changed the WSDL version; repairs keep the author's version (1.1 stays \
             1.1)"
                .to_string(),
        );
        return out;
    }
    if original["targetNamespace"] != repaired["targetNamespace"]
        && !touched(before, "/targetNamespace")
    {
        out.push("changed the targetNamespace, which had no diagnostics".to_string());
    }
    for (prefix, uri) in original["namespaces"].as_object().into_iter().flatten() {
        if repaired["namespaces"].get(prefix) != Some(uri) {
            out.push(format!(
                "removed or rebound the namespace prefix `{prefix}`; repairs keep the author's \
                 prefixes"
            ));
        }
    }
    out.extend(kept_values(
        original,
        repaired,
        "imports",
        "/imports",
        before,
        |import| {
            format!(
                "removed the import of `{}`",
                import["location"].as_str().unwrap_or_default()
            )
        },
    ));
    let now = declarations(repaired);
    for declared in declarations(original) {
        if !now.contains(&declared) {
            out.push(format!("removed schema {declared}"));
        }
    }
    let sections_for_version: &[Section] = if original["version"] == "2.0" {
        &SECTIONS_20
    } else {
        &SECTIONS_11
    };
    out.extend(sections(original, repaired, sections_for_version, before));
    out
}

/// Why a parsed new document is not a WSDL 1.1 document/literal wrapped
/// description.
fn new_document_problems(model: &Value) -> Vec<String> {
    let mut out = Vec::new();
    if model["version"] != "1.1" {
        out.push("a new WSDL document must be WSDL 1.1 (http://schemas.xmlsoap.org/wsdl/)".into());
        return out;
    }
    if model["targetNamespace"].is_null() {
        out.push("a new WSDL document needs a targetNamespace".into());
    }
    if list(model, "bindings").is_empty() || list(model, "services").is_empty() {
        out.push("a new WSDL document needs a binding and a service with a port".into());
    }
    for binding in list(model, "bindings") {
        let binding_name = name(binding);
        if !matches!(binding["protocol"].as_str(), Some("soap11" | "soap12")) {
            out.push(format!("binding `{binding_name}` must be a SOAP binding"));
        }
        let document_style = list(binding, "operations").iter().all(|operation| {
            operation["style"]
                .as_str()
                .or(binding["style"].as_str())
                .is_none_or(|style| style == "document")
        });
        let literal = list(binding, "operations")
            .iter()
            .flat_map(|operation| list(operation, "uses"))
            .all(|used| used == "literal");
        if !document_style || !literal {
            out.push(format!(
                "binding `{binding_name}` must be document/literal: style document and \
                 use literal throughout"
            ));
        }
    }
    for message in list(model, "messages") {
        let parts = list(message, "parts");
        if parts.len() != 1 || parts[0]["element"].is_null() {
            out.push(format!(
                "message `{}` must have exactly one part that references an element \
                 (document/literal wrapped)",
                name(message)
            ));
        }
    }
    out
}

impl SpecFormat for Wsdl {
    fn id(&self) -> FormatId {
        FormatId::Wsdl
    }

    fn name(&self) -> &'static str {
        "WSDL"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::FULL
    }

    fn candidate_strength(&self, path: &str) -> Option<NameStrength> {
        let lower = path.to_ascii_lowercase();
        let name = lower.rsplit('/').next().unwrap_or_default();
        let (stem, extension) = name.rsplit_once('.')?;
        match extension {
            "wsdl" => Some(NameStrength::Strong),
            "xsd" => Some(NameStrength::Weak),
            "xml" if stem.contains("wsdl") || stem.contains("soap") => Some(NameStrength::Weak),
            _ => None,
        }
    }

    fn classify(&self, path: &str, bytes: &[u8], max_bytes: usize) -> Candidate {
        let Some(strength) = self.candidate_strength(path) else {
            return Candidate::NotASpec;
        };
        let strong = strength == NameStrength::Strong;
        // A weakly named file counts only when its text names a WSDL
        // namespace; any other XML is not this step's business.
        let claims =
            |text: &str| strong || text.contains(model::WSDL11) || text.contains(model::WSDL20);
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
        let document = match crate::xml::read(text) {
            Ok(document) => document,
            Err(reason) => return unreadable(text, reason),
        };
        match model::model(&document) {
            Some(model) => Candidate::Spec {
                syntax: Syntax::Xml,
                version: declared_version(&model),
                document: model,
            },
            None if strong => Candidate::Unverifiable {
                reason: "the root element is not a WSDL 1.1 definitions, a WSDL 2.0 description \
                         or an XML Schema"
                    .into(),
            },
            None => Candidate::NotASpec,
        }
    }

    fn parse(&self, text: &str, _: Syntax) -> Result<Value, ParseFailure> {
        let document = crate::xml::read_for_parse(text)?;
        model::model(&document).ok_or_else(|| {
            ParseFailure::Malformed(
                "the root element is not a WSDL 1.1 definitions or WSDL 2.0 description".into(),
            )
        })
    }

    fn version(&self, document: &Value) -> Option<SpecVersion> {
        declared_version(document)
    }

    fn supporting(&self, document: &Value) -> bool {
        document["kind"] == "xsd"
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
        let missing: BTreeSet<Operation> = inventory
            .iter()
            .filter(|served| !documented.iter().any(|op| matches(op, served)))
            .cloned()
            .collect();
        Completeness {
            missing: missing.into_iter().collect(),
            unverified: own
                .into_iter()
                .filter(|op| !inventory.iter().any(|served| matches(op, served)))
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
        if !method.trim().eq_ignore_ascii_case(METHOD) {
            return Err(format!("inventory method {method:?} is not operation"));
        }
        let path = path.trim();
        let valid = match path.split_once('/') {
            Some((interface, operation)) => is_ncname(interface) && is_ncname(operation),
            None => is_ncname(path),
        };
        if !valid {
            return Err(format!(
                "inventory path {path:?} is not `PortType/operation` or an operation name"
            ));
        }
        Ok(Operation::new(METHOD, path))
    }

    fn emit(&self, document: &Value, _: Syntax) -> Result<String, String> {
        let Some(text) = document.as_str() else {
            return Err("a WSDL create decision needs `document` as the WSDL text".into());
        };
        Ok(format!("{}\n", text.trim_end()))
    }

    fn new_document_problems(&self, document: &Value) -> Vec<String> {
        new_document_problems(document)
    }

    fn owners(&self, _: &[HttpService], surfaces: &[ApiSurface]) -> Vec<Owner> {
        surfaces
            .iter()
            .filter_map(|surface| {
                let libraries = surface.of(ApiFamily::Soap);
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
