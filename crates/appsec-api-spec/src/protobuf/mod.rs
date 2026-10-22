//! Protocol Buffers service definitions (`.proto`, proto2, proto3 and
//! editions) for gRPC: checked and reported, never written.
//!
//! A `.proto` file is normally the source of truth that client and server
//! code is generated from, so this step never generates one from code or
//! edits one. It validates each file (see [`validate`]) and compares the
//! services the files define with the gRPC server registrations the code
//! makes (see [`registrations`]): a registered service no file defines is
//! a finding, and a defined service with no registration found is
//! reported as unverified (it may be client-only, or registered in a way
//! the scan does not recognize).

pub mod parser;
pub mod registrations;
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
use validate::{list, package_prefix, text};

/// Protocol Buffers.
pub struct Protobuf;

/// The registered instance.
pub static PROTOBUF: Protobuf = Protobuf;

const NEVER_WRITTEN: &str =
    "Protocol Buffers definitions are the source of truth and are never written by this step";

const CONVENTION: Convention = Convention {
    path: "proto/service.proto",
    syntax: Syntax::Protobuf,
    confident: false,
    accepted_directories: &[],
    basis: "gRPC definitions usually live under proto/ or api/proto/; this step checks them \
            where they are and never creates or moves one",
    code_first: false,
};

/// The unqualified name a registration or definition is compared by.
fn simple(name: &str) -> &str {
    name.rsplit('.').next().unwrap_or(name)
}

/// Every service a document defines, fully qualified.
fn services(document: &Value) -> Vec<Operation> {
    let package = package_prefix(document);
    list(document, "services")
        .iter()
        .map(|service| Operation::new("service", format!("{package}{}", text(service, "name"))))
        .collect()
}

impl SpecFormat for Protobuf {
    fn id(&self) -> FormatId {
        FormatId::Protobuf
    }

    fn name(&self) -> &'static str {
        "Protocol Buffers"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::CHECK_ONLY
    }

    fn candidate_strength(&self, path: &str) -> Option<NameStrength> {
        path.to_ascii_lowercase()
            .ends_with(".proto")
            .then_some(NameStrength::Strong)
    }

    fn classify(&self, path: &str, bytes: &[u8], max_bytes: usize) -> Candidate {
        if self.candidate_strength(path).is_none() {
            return Candidate::NotASpec;
        }
        if bytes.len() > max_bytes {
            return Candidate::Unverifiable {
                reason: format!("larger than the {max_bytes}-byte specification cap"),
            };
        }
        let Ok(text) = std::str::from_utf8(bytes) else {
            return Candidate::Unverifiable {
                reason: "not UTF-8 text".into(),
            };
        };
        match self.parse(text, Syntax::Protobuf) {
            Ok(document) => Candidate::Spec {
                syntax: Syntax::Protobuf,
                version: self.version(&document),
                document,
            },
            Err(ParseFailure::Unverifiable(reason) | ParseFailure::Malformed(reason)) => {
                Candidate::Unverifiable { reason }
            }
        }
    }

    fn parse(&self, text: &str, _: Syntax) -> Result<Value, ParseFailure> {
        parser::parse(text).map_err(|error| {
            ParseFailure::Unverifiable(format!(
                "could not be read by the built-in Protocol Buffers parser (line {}: {})",
                error.line, error.message
            ))
        })
    }

    fn version(&self, document: &Value) -> Option<SpecVersion> {
        Some(match document.get("syntax").and_then(Value::as_str) {
            Some("proto3") => SpecVersion::Proto3,
            Some("editions") => SpecVersion::ProtoEditions,
            _ => SpecVersion::Proto2,
        })
    }

    fn validate(&self, document: &Value, peers: &[Peer<'_>]) -> Vec<Diagnostic> {
        validate::validate(document, peers)
    }

    fn operations(&self, document: &Value) -> Vec<Operation> {
        services(document)
    }

    fn compare(
        &self,
        document: &Value,
        peers: &[Peer<'_>],
        inventory: &[Operation],
    ) -> Completeness {
        let registered: BTreeSet<&str> = inventory.iter().map(|op| simple(&op.path)).collect();
        let own = services(document);
        let mut defined: BTreeSet<String> =
            own.iter().map(|op| simple(&op.path).to_string()).collect();
        for peer in peers {
            defined.extend(
                services(peer.document)
                    .iter()
                    .map(|op| simple(&op.path).to_string()),
            );
        }
        let missing: BTreeSet<Operation> = inventory
            .iter()
            .filter(|op| !defined.contains(simple(&op.path)))
            .cloned()
            .collect();
        Completeness {
            missing: missing.into_iter().collect(),
            unverified: own
                .into_iter()
                .filter(|op| !registered.contains(simple(&op.path)))
                .collect(),
        }
    }

    fn preservation(&self, _: &Value, _: &Value, _: &[Diagnostic]) -> Vec<String> {
        vec![NEVER_WRITTEN.into()]
    }

    fn inventory_operation(&self, method: &str, path: &str) -> Result<Operation, String> {
        let valid = !path.is_empty()
            && path.split('.').all(|part| {
                !part.is_empty() && part.chars().all(|c| c == '_' || c.is_ascii_alphanumeric())
            });
        if method != "service" || !valid {
            return Err(format!(
                "inventory entry {method:?} {path:?} is not a gRPC service"
            ));
        }
        Ok(Operation::new(method, path))
    }

    fn emit(&self, _: &Value, _: Syntax) -> Result<String, String> {
        Err(NEVER_WRITTEN.into())
    }

    fn new_document_problems(&self, _: &Value) -> Vec<String> {
        vec![NEVER_WRITTEN.into()]
    }

    fn owners(&self, _: &[HttpService], surfaces: &[ApiSurface]) -> Vec<Owner> {
        surfaces
            .iter()
            .filter_map(|surface| {
                let libraries = surface.of(ApiFamily::Grpc);
                (!libraries.is_empty()).then(|| Owner {
                    root: surface.root.clone(),
                    stack: libraries.iter().map(name_of).collect(),
                    convention: CONVENTION,
                })
            })
            .collect()
    }

    fn fallback(&self) -> Convention {
        CONVENTION
    }

    fn scans_source(&self) -> bool {
        true
    }

    fn scan_source(&self, path: &str, text: &str) -> Vec<CitedOperation> {
        registrations::registrations(path, text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::libraries::ApiLibrary;

    const ORDERS: &str = "syntax = \"proto3\";\npackage shop.v1;\nmessage M { int32 a = 1; }\nservice Orders { rpc Get (M) returns (M); }\nservice Admin { rpc Ping (M) returns (M); }\n";

    #[test]
    fn proto_files_are_recognized_and_parsed() {
        assert_eq!(
            PROTOBUF.candidate_strength("api/proto/Orders.PROTO"),
            Some(NameStrength::Strong)
        );
        assert_eq!(
            PROTOBUF.classify("orders.json", b"", 10),
            Candidate::NotASpec
        );
        assert!(matches!(
            PROTOBUF.classify("orders.proto", ORDERS.as_bytes(), 1 << 20),
            Candidate::Spec {
                version: Some(SpecVersion::Proto3),
                syntax: Syntax::Protobuf,
                ..
            }
        ));
        for (bytes, reason) in [
            (ORDERS.as_bytes(), "cap"),
            (&[0xff][..], "UTF-8"),
            (&b"message {"[..], "line 1: expected a name"),
        ] {
            let classified = PROTOBUF.classify("orders.proto", bytes, 64);
            assert!(
                matches!(&classified, Candidate::Unverifiable { reason: r } if r.contains(reason)),
                "{classified:?}"
            );
        }
        let proto2 = PROTOBUF
            .parse("message A { optional int32 a = 1; }", Syntax::Protobuf)
            .unwrap();
        assert_eq!(PROTOBUF.version(&proto2), Some(SpecVersion::Proto2));
        let editions = PROTOBUF
            .parse("edition = \"2023\";", Syntax::Protobuf)
            .unwrap();
        assert_eq!(
            PROTOBUF.version(&editions),
            Some(SpecVersion::ProtoEditions)
        );
        assert!(PROTOBUF.validate(&proto2, &[]).is_empty());
    }

    #[test]
    fn services_are_compared_with_registrations_by_simple_name() {
        let document = PROTOBUF.parse(ORDERS, Syntax::Protobuf).unwrap();
        assert_eq!(
            PROTOBUF.operations(&document),
            [
                Operation::new("service", "shop.v1.Orders"),
                Operation::new("service", "shop.v1.Admin"),
            ]
        );
        let peer_document = PROTOBUF
            .parse("service Billing {}", Syntax::Protobuf)
            .unwrap();
        let peers = [Peer {
            path: "billing.proto",
            document: &peer_document,
        }];
        let inventory = [
            Operation::new("service", "Orders"),
            Operation::new("service", "Billing"),
            Operation::new("service", "Shipping"),
        ];
        let result = PROTOBUF.compare(&document, &peers, &inventory);
        assert_eq!(result.missing, [Operation::new("service", "Shipping")]);
        assert_eq!(
            result.unverified,
            [Operation::new("service", "shop.v1.Admin")]
        );
    }

    #[test]
    fn nothing_is_ever_written() {
        let document = PROTOBUF.parse(ORDERS, Syntax::Protobuf).unwrap();
        assert_eq!(PROTOBUF.capabilities(), Capabilities::CHECK_ONLY);
        assert!(PROTOBUF
            .emit(&document, Syntax::Protobuf)
            .unwrap_err()
            .contains("never written"));
        assert_eq!(PROTOBUF.new_document_problems(&document), [NEVER_WRITTEN]);
        assert_eq!(
            PROTOBUF.preservation(&document, &document, &[]),
            [NEVER_WRITTEN]
        );
        assert_eq!(
            PROTOBUF
                .inventory_operation("service", "shop.v1.Orders")
                .unwrap(),
            Operation::new("service", "shop.v1.Orders")
        );
        for (method, path) in [
            ("rpc", "Orders"),
            ("service", ""),
            ("service", "a..b"),
            ("service", "a-b"),
        ] {
            assert!(
                PROTOBUF.inventory_operation(method, path).is_err(),
                "{method} {path}"
            );
        }
    }

    #[test]
    fn owners_are_services_with_grpc() {
        let surfaces = [ApiSurface {
            root: "rpc".into(),
            manifests: vec![],
            libraries: [ApiLibrary::Grpc].into_iter().collect(),
        }];
        let owners = PROTOBUF.owners(&[], &surfaces);
        assert_eq!(owners[0].stack, ["grpc"]);
        assert!(PROTOBUF.owners(&[], &[]).is_empty());
        assert!(!PROTOBUF.fallback().confident);
        assert_eq!(PROTOBUF.name(), "Protocol Buffers");
    }
}
