//! Static API description support for target testing: a multi-format
//! framework ([`format::SpecFormat`]) with one module per standard, and
//! the machinery they share: placement, parsing, deterministic emission,
//! completeness against a cited inventory, secret hygiene, minimal repair
//! edits, preservation checks and reference rewriting for relocation.
//!
//! Everything here is pure. The caller reads files (bounded and jailed)
//! and passes their contents in; nothing in this crate touches the file
//! system, a network, a broker or a running application. A specification
//! is a document proposed for review, never something this tool sends
//! traffic with.

pub mod asyncapi;
pub mod blueprint;
pub mod diagnostic;
pub mod edits;
pub mod emit;
pub mod format;
pub mod frameworks;
pub mod graphql;
pub mod hygiene;
pub mod inventory;
pub mod libraries;
pub mod location;
pub mod odata;
pub mod openapi;
pub mod openrpc;
pub mod parse;
pub mod plan;
pub mod protobuf;
pub mod raml;
pub mod references;
pub mod refs;
pub mod tree;
pub mod tree_checks;
pub mod wsdl;
mod xml;
mod xml_preserve;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use diagnostic::{Diagnostic, Severity};
pub use format::{
    format, registry, Candidate, Capabilities, FormatId, NameStrength, Peer, SpecFormat,
    SpecVersion, Syntax,
};
pub use frameworks::WebFramework;
pub use inventory::{CitedOperation, Operation};
pub use libraries::{ApiFamily, ApiLibrary, ApiSurface};
pub use plan::HttpService;

/// The deterministic verdict on a proposed document.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Assessment {
    pub diagnostics: Vec<Diagnostic>,
    /// Served by the code (per the cited inventory) but not documented.
    pub missing: Vec<Operation>,
    /// Documented but not in the inventory.
    pub unverified: Vec<Operation>,
    /// Operations the proposal added that no inventory entry supports.
    pub invented: Vec<Operation>,
    /// Ways a repair failed to keep the author's content.
    pub preservation: Vec<String>,
}

impl Assessment {
    /// Problems that must be fixed before a proposal can be written, as
    /// readable sentences suitable for feeding back to a generator.
    pub fn blocking(&self) -> Vec<String> {
        let mut problems: Vec<String> = self
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.severity == Severity::Error)
            .map(|diagnostic| format!("{} at `{}`", diagnostic.message, diagnostic.pointer))
            .collect();
        problems.extend(self.missing.iter().map(|operation| {
            format!(
                "{} {} is served by the code but not documented",
                operation.method.to_uppercase(),
                operation.path
            )
        }));
        problems.extend(self.invented.iter().map(|operation| {
            format!(
                "{} {} was added without a cited handler in the inventory",
                operation.method.to_uppercase(),
                operation.path
            )
        }));
        problems.extend(self.preservation.iter().cloned());
        problems
    }
}

/// Assess `candidate`, a document of `format`, against an `inventory`,
/// with the standard's other documents as `peers`. `original` is the
/// document being repaired and its diagnostics before the repair, or
/// `None` when the candidate is a new document.
///
/// A new document may only contain cited operations. A repair may keep
/// documented operations the inventory does not show (they are reported
/// as unverified, never deleted) but may only add cited ones.
pub fn assess(
    format: &dyn SpecFormat,
    candidate: &Value,
    peers: &[Peer<'_>],
    inventory: &[Operation],
    original: Option<(&Value, &[Diagnostic])>,
) -> Assessment {
    let completeness = format.compare(candidate, peers, inventory);
    let existing: Vec<Operation> = original
        .map(|(document, _)| format.operations(document))
        .unwrap_or_default();
    let invented = completeness
        .unverified
        .iter()
        .filter(|operation| !existing.contains(operation))
        .cloned()
        .collect();
    let preservation = original
        .map(|(document, before)| format.preservation(document, candidate, before))
        .unwrap_or_default();
    Assessment {
        diagnostics: format.validate(candidate, peers),
        missing: completeness.missing,
        unverified: completeness.unverified,
        invented,
        preservation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openapi::OPENAPI;
    use serde_json::json;

    fn assess(
        candidate: &Value,
        inventory: &[Operation],
        original: Option<(&Value, &[Diagnostic])>,
    ) -> Assessment {
        super::assess(&OPENAPI, candidate, &[], inventory, original)
    }

    fn document(paths: Value) -> Value {
        json!({"openapi": "3.1.0", "info": {"title": "t", "version": "1"}, "paths": paths})
    }

    fn op(method: &str, path: &str) -> Operation {
        Operation {
            method: method.into(),
            path: path.into(),
        }
    }

    #[test]
    fn a_new_document_must_be_valid_complete_and_cited() {
        let ok = document(json!({"/a": {"get": {"responses": {"200": {"description": "ok"}}}}}));
        let assessment = assess(&ok, &[op("GET", "/a")], None);
        assert_eq!(assessment.blocking(), Vec::<String>::new());
        let invented = assess(&ok, &[], None);
        assert_eq!(invented.invented, [op("get", "/a")]);
        assert!(invented.blocking()[0].contains("without a cited handler"));
        let missing = assess(&ok, &[op("get", "/a"), op("post", "/b")], None);
        assert!(missing.blocking()[0].contains("POST /b is served"));
        let mut invalid = document(json!({"/a": {"get": {}}}));
        invalid["openapi"] = json!("3.0.3");
        let invalid = assess(&invalid, &[op("get", "/a")], None);
        assert!(invalid.blocking()[0].contains("at `/paths/~1a/get`"));
        // Warnings are reported but never block.
        let external = document(json!({"/a": {"get": {"responses": {"200": {"$ref": "x.yaml"}}}}}));
        let assessment = assess(&external, &[op("get", "/a")], None);
        assert_eq!(assessment.diagnostics.len(), 1);
        assert!(assessment.blocking().is_empty());
    }

    #[test]
    fn a_repair_keeps_unverified_operations_and_its_authors_content() {
        let original =
            document(json!({"/old": {"get": {"responses": {"200": {"description": "ok"}}}}}));
        let mut repaired = original.clone();
        repaired["paths"]["/new"] =
            json!({"post": {"responses": {"201": {"description": "made"}}}});
        let assessment = assess(&repaired, &[op("post", "/new")], Some((&original, &[])));
        assert_eq!(assessment.unverified, [op("get", "/old")]);
        assert!(assessment.invented.is_empty());
        assert!(assessment.blocking().is_empty());
        repaired["info"]["title"] = json!("renamed");
        let changed = assess(&repaired, &[op("post", "/new")], Some((&original, &[])));
        assert_eq!(
            changed.blocking(),
            ["changed or removed `info`, which had no diagnostics"]
        );
    }
}
