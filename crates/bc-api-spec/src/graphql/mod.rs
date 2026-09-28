//! GraphQL schema definition language: `schema.graphql`, `*.graphqls`,
//! `schema.gql` and other SDL files. Operations are root fields (`query`,
//! `mutation` or `subscription`, and the field name); owners are services
//! with a GraphQL server library.

pub mod lexer;
pub mod location;
pub mod parser;
pub mod preserve;
pub mod validate;

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
use parser::ParseError;
use validate::{entries, text, Symbols};

/// GraphQL SDL.
pub struct Graphql;

/// The registered instance.
pub static GRAPHQL: Graphql = Graphql;

const ROOT_OPERATIONS: [&str; 3] = ["query", "mutation", "subscription"];

fn is_name(text: &str) -> bool {
    let mut characters = text.chars();
    characters
        .next()
        .is_some_and(|c| c == '_' || c.is_ascii_alphabetic())
        && characters.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

/// Root fields of `document`, with root types resolved by `symbols`.
fn root_fields(document: &Value, symbols: &Symbols) -> Vec<Operation> {
    let mut operations = BTreeSet::new();
    for operation in ROOT_OPERATIONS {
        let Some(root) = symbols.root(operation) else {
            continue;
        };
        for entry in entries(document, "types") {
            if text(entry, "name") == root && text(entry, "kind") == "object" {
                for field in entries(entry, "fields") {
                    operations.insert(Operation::new(operation, text(field, "name")));
                }
            }
        }
    }
    operations.into_iter().collect()
}

impl SpecFormat for Graphql {
    fn id(&self) -> FormatId {
        FormatId::Graphql
    }

    fn name(&self) -> &'static str {
        "GraphQL"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::FULL
    }

    fn candidate_strength(&self, path: &str) -> Option<NameStrength> {
        let lower = path.to_ascii_lowercase();
        let name = lower.rsplit('/').next().unwrap_or_default();
        let (stem, extension) = name.rsplit_once('.')?;
        match extension {
            "graphqls" | "gqls" => Some(NameStrength::Strong),
            "graphql" | "gql" if stem == "schema" => Some(NameStrength::Strong),
            "graphql" | "gql" => Some(NameStrength::Weak),
            _ => None,
        }
    }

    fn classify(&self, path: &str, bytes: &[u8], max_bytes: usize) -> Candidate {
        let Some(strength) = self.candidate_strength(path) else {
            return Candidate::NotASpec;
        };
        // A weakly named file that cannot be read is most likely a client
        // query document, which is not this step's business.
        let unreadable = |reason: String| {
            if strength == NameStrength::Strong {
                Candidate::Unverifiable { reason }
            } else {
                Candidate::NotASpec
            }
        };
        if bytes.len() > max_bytes {
            return unreadable(format!(
                "larger than the {max_bytes}-byte specification cap"
            ));
        }
        let Ok(text) = std::str::from_utf8(bytes) else {
            return unreadable("not UTF-8 text".into());
        };
        match self.parse(text, Syntax::Graphql) {
            Ok(document)
                if !entries(&document, "types").is_empty()
                    || !entries(&document, "schema").is_empty()
                    || !entries(&document, "directives").is_empty() =>
            {
                Candidate::Spec {
                    syntax: Syntax::Graphql,
                    version: None,
                    document,
                }
            }
            Ok(_) | Err(ParseFailure::Malformed(_)) => Candidate::NotASpec,
            Err(ParseFailure::Unverifiable(reason)) => unreadable(reason),
        }
    }

    fn parse(&self, text: &str, _: Syntax) -> Result<Value, ParseFailure> {
        parser::parse(text).map_err(|error| match error {
            // The parser is this crate's own, so a text it refuses is never
            // treated as definitely broken: it is left untouched.
            ParseError::Syntax { line, message } => ParseFailure::Unverifiable(format!(
                "could not be read by the built-in GraphQL parser (line {line}: {message})"
            )),
            ParseError::Executable { line } => ParseFailure::Malformed(format!(
                "line {line} starts an operation or fragment; a schema holds only type system \
                 definitions"
            )),
        })
    }

    fn version(&self, _: &Value) -> Option<SpecVersion> {
        // The GraphQL specification is versioned by edition, and a schema
        // document does not declare one.
        None
    }

    fn validate(&self, document: &Value, peers: &[Peer<'_>]) -> Vec<Diagnostic> {
        validate::validate(document, peers)
    }

    fn operations(&self, document: &Value) -> Vec<Operation> {
        root_fields(document, &Symbols::of(document, &[]))
    }

    fn compare(
        &self,
        document: &Value,
        peers: &[Peer<'_>],
        inventory: &[Operation],
    ) -> Completeness {
        let symbols = Symbols::of(document, peers);
        let own = root_fields(document, &symbols);
        let mut documented: BTreeSet<Operation> = own.iter().cloned().collect();
        for peer in peers {
            documented.extend(root_fields(peer.document, &symbols));
        }
        let served: BTreeSet<&Operation> = inventory.iter().collect();
        let missing: BTreeSet<Operation> = inventory
            .iter()
            .filter(|operation| !documented.contains(operation))
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
        preserve::violations(original, repaired, before)
    }

    fn inventory_operation(&self, method: &str, path: &str) -> Result<Operation, String> {
        let method = method.trim().to_ascii_lowercase();
        if !ROOT_OPERATIONS.contains(&method.as_str()) {
            return Err(format!(
                "inventory method {method:?} is not query, mutation or subscription"
            ));
        }
        if !is_name(path) {
            return Err(format!(
                "inventory path {path:?} is not a GraphQL field name"
            ));
        }
        Ok(Operation::new(method, path))
    }

    fn emit(&self, document: &Value, _: Syntax) -> Result<String, String> {
        let Some(text) = document.as_str() else {
            return Err("a GraphQL create decision needs `document` as the SDL text".into());
        };
        Ok(format!("{}\n", text.trim_end()))
    }

    fn new_document_problems(&self, document: &Value) -> Vec<String> {
        if entries(document, "types").is_empty() {
            vec!["a new schema must define at least one type".into()]
        } else {
            Vec::new()
        }
    }

    fn owners(&self, _: &[HttpService], surfaces: &[ApiSurface]) -> Vec<Owner> {
        surfaces
            .iter()
            .filter_map(|surface| {
                let libraries = surface.of(ApiFamily::Graphql);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::libraries::ApiLibrary;
    use serde_json::json;

    #[test]
    fn names_nominate_schema_files() {
        for (path, strength) in [
            ("schema.graphql", Some(NameStrength::Strong)),
            (
                "src/main/resources/graphql/users.graphqls",
                Some(NameStrength::Strong),
            ),
            ("a/b.gqls", Some(NameStrength::Strong)),
            ("SCHEMA.GQL", Some(NameStrength::Strong)),
            ("queries/me.graphql", Some(NameStrength::Weak)),
            ("me.gql", Some(NameStrength::Weak)),
            ("schema.json", None),
            ("graphql", None),
        ] {
            assert_eq!(GRAPHQL.candidate_strength(path), strength, "{path}");
        }
    }

    #[test]
    fn content_decides_what_a_candidate_is() {
        let schema = b"type Query { a: Int }";
        assert!(matches!(
            GRAPHQL.classify("schema.graphql", schema, 1024),
            Candidate::Spec {
                syntax: Syntax::Graphql,
                version: None,
                ..
            }
        ));
        assert!(matches!(
            GRAPHQL.classify("x.graphql", b"directive @a on FIELD", 1024),
            Candidate::Spec { .. }
        ));
        assert!(matches!(
            GRAPHQL.classify("x.graphql", b"schema { query: Q }", 1024),
            Candidate::Spec { .. }
        ));
        // A client query file is not a schema, whatever its name.
        for path in ["me.graphql", "schema.graphql"] {
            assert_eq!(
                GRAPHQL.classify(path, b"query Me { me { id } }", 1024),
                Candidate::NotASpec
            );
        }
        assert_eq!(
            GRAPHQL.classify("schema.graphql", b"# empty", 1024),
            Candidate::NotASpec
        );
        assert_eq!(
            GRAPHQL.classify("schema.json", schema, 1024),
            Candidate::NotASpec
        );
        // What the parser cannot read is left alone under a strong name.
        let broken = GRAPHQL.classify("schema.graphqls", b"type {", 1024);
        assert!(
            matches!(&broken, Candidate::Unverifiable { reason } if reason.contains("line 1: expected a name"))
        );
        assert_eq!(
            GRAPHQL.classify("me.graphql", b"type {", 1024),
            Candidate::NotASpec
        );
        assert!(matches!(
            GRAPHQL.classify("schema.graphql", schema, 4),
            Candidate::Unverifiable { .. }
        ));
        assert!(matches!(
            GRAPHQL.classify("schema.graphql", &[0xff], 4),
            Candidate::Unverifiable { .. }
        ));
        assert_eq!(
            GRAPHQL.classify("me.graphql", &[0xff], 4),
            Candidate::NotASpec
        );
    }

    #[test]
    fn root_fields_are_the_operations() {
        let document = GRAPHQL
            .parse(
                "type Query { me: Int }\nextend type Query { you: Int }\ntype Mutation { set: Int }\ninput Subscription { x: Int }",
                Syntax::Graphql,
            )
            .unwrap();
        assert_eq!(
            GRAPHQL.operations(&document),
            [
                Operation::new("mutation", "set"),
                Operation::new("query", "me"),
                Operation::new("query", "you"),
            ]
        );
        assert_eq!(GRAPHQL.version(&document), None);
        let custom = GRAPHQL
            .parse(
                "schema { query: Root }\ntype Root { a: Int }",
                Syntax::Graphql,
            )
            .unwrap();
        assert_eq!(GRAPHQL.operations(&custom), [Operation::new("query", "a")]);
    }

    #[test]
    fn completeness_counts_peer_documents_as_documented() {
        let own = GRAPHQL
            .parse("extend type Query { me: Int stale: Int }", Syntax::Graphql)
            .unwrap();
        let other = GRAPHQL
            .parse("type Query { you: Int }", Syntax::Graphql)
            .unwrap();
        let peers = [Peer {
            path: "other.graphqls",
            document: &other,
        }];
        let inventory = [
            Operation::new("query", "me"),
            Operation::new("query", "you"),
            Operation::new("mutation", "set"),
        ];
        let result = GRAPHQL.compare(&own, &peers, &inventory);
        assert_eq!(result.missing, [Operation::new("mutation", "set")]);
        assert_eq!(result.unverified, [Operation::new("query", "stale")]);
        assert!(GRAPHQL.validate(&own, &peers).is_empty());
    }

    #[test]
    fn inventory_entries_are_root_fields() {
        assert_eq!(
            GRAPHQL.inventory_operation(" Query ", "me").unwrap(),
            Operation::new("query", "me")
        );
        assert!(GRAPHQL
            .inventory_operation("get", "me")
            .unwrap_err()
            .contains("not query, mutation or subscription"));
        for path in ["", "1a", "a.b", "/me"] {
            assert!(GRAPHQL
                .inventory_operation("query", path)
                .unwrap_err()
                .contains("not a GraphQL field name"));
        }
    }

    #[test]
    fn new_documents_are_sdl_text_with_at_least_one_type() {
        assert_eq!(
            GRAPHQL
                .emit(&json!("type Query { a: Int }\n\n"), Syntax::Graphql)
                .unwrap(),
            "type Query { a: Int }\n"
        );
        assert!(GRAPHQL
            .emit(&json!({"types": []}), Syntax::Graphql)
            .unwrap_err()
            .contains("SDL text"));
        let empty = GRAPHQL
            .parse("directive @a on FIELD", Syntax::Graphql)
            .unwrap();
        assert_eq!(
            GRAPHQL.new_document_problems(&empty),
            ["a new schema must define at least one type"]
        );
        let schema = GRAPHQL
            .parse("type Query { a: Int }", Syntax::Graphql)
            .unwrap();
        assert!(GRAPHQL.new_document_problems(&schema).is_empty());
        assert!(GRAPHQL.preservation(&schema, &schema, &[]).is_empty());
        let executable = GRAPHQL.parse("{ a }", Syntax::Graphql).unwrap_err();
        assert!(
            matches!(executable, ParseFailure::Malformed(m) if m.contains("operation or fragment"))
        );
    }

    #[test]
    fn owners_are_services_with_a_graphql_server() {
        let surfaces = [
            ApiSurface {
                root: "api".into(),
                manifests: vec!["api/pom.xml".into()],
                libraries: [ApiLibrary::SpringGraphql, ApiLibrary::Kafka]
                    .into_iter()
                    .collect(),
            },
            ApiSurface {
                root: "events".into(),
                manifests: vec![],
                libraries: [ApiLibrary::Kafka].into_iter().collect(),
            },
        ];
        let owners = GRAPHQL.owners(&[], &surfaces);
        assert_eq!(owners.len(), 1);
        assert_eq!(owners[0].stack, ["spring_graphql"]);
        assert!(owners[0].convention.confident);
        assert_eq!(GRAPHQL.fallback().path, "schema.graphql");
        assert_eq!(GRAPHQL.name(), "GraphQL");
        assert_eq!(GRAPHQL.capabilities(), Capabilities::FULL);
    }
}
