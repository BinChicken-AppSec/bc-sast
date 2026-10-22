//! AsyncAPI 2.x and 3.x, in JSON or YAML: message-driven APIs (Kafka,
//! AMQP, MQTT, NATS, SQS and SNS, Redis pub/sub, WebSocket, Socket.IO).
//! Operations are what the application does on a channel, `send` or
//! `receive`, and the channel address; owners are services with a
//! messaging client library.
//!
//! AsyncAPI 2.x names operations from the other side of the channel: a
//! channel's `subscribe` operation is one the application sends on, and
//! `publish` one it receives. They are mapped to the 3.x actions so an
//! inventory reads the same for both versions.

pub mod validate;

use std::collections::BTreeSet;

use serde_json::Value;

use crate::diagnostic::Diagnostic;
use crate::format::{
    name_of, Candidate, Capabilities, FormatId, NameStrength, Owner, Peer, SpecFormat, SpecVersion,
    Syntax,
};
use crate::inventory::{compare_by_key, CitedOperation, Completeness, Operation};
use crate::libraries::{ApiFamily, ApiSurface};
use crate::location::Convention;
use crate::parse::ParseFailure;
use crate::plan::HttpService;
use crate::tree::TreeRules;
use crate::tree_checks::{normalize_address, Surface};

/// AsyncAPI.
pub struct AsyncApi;

/// The registered instance.
pub static ASYNCAPI: AsyncApi = AsyncApi;

/// The declared version, read leniently like OpenAPI's.
pub fn declared_version(document: &Value) -> Option<SpecVersion> {
    let declared = document
        .get("asyncapi")
        .and_then(crate::openapi::detect::scalar_text)?;
    let mut parts = declared.split('.');
    match (parts.next(), parts.next()) {
        (Some("3"), Some("0")) => Some(SpecVersion::AsyncApi3),
        (Some(major), Some(minor)) if validate::supported(major, minor) => {
            Some(SpecVersion::AsyncApi2)
        }
        _ => None,
    }
}

const RULES: TreeRules = TreeRules {
    markers: &["asyncapi"],
    shape: &["info", "channels", "operations"],
    foreign: &["openapi", "swagger", "openrpc"],
    version: declared_version,
};

/// Key order for a generated document; the first keys keep the redactor
/// from reading a schema property named like a secret as a credential
/// (see [`crate::emit::OPENAPI_ORDER`]).
const ORDER: &[&str] = &[
    "$ref",
    "type",
    "allOf",
    "oneOf",
    "anyOf",
    "asyncapi",
    "id",
    "info",
    "title",
    "version",
    "description",
    "defaultContentType",
    "servers",
    "host",
    "pathname",
    "url",
    "protocol",
    "protocolVersion",
    "channels",
    "address",
    "operations",
    "action",
    "channel",
    "messages",
    "name",
    "summary",
    "contentType",
    "headers",
    "payload",
    "parameters",
    "properties",
    "items",
    "required",
    "bindings",
    "security",
    "components",
];

const SURFACES: [Surface; 2] = [
    Surface {
        key: "channels",
        noun: "channel",
        by: None,
    },
    Surface {
        key: "operations",
        noun: "operation",
        by: None,
    },
];

/// A 3.x operation's channel address: the channel's `address`, or its
/// key when the address is null or absent (dynamic addresses).
fn address(document: &Value, operation: &Value) -> Option<String> {
    let target = operation.get("channel")?.get("$ref")?.as_str()?;
    let channel = crate::refs::lookup(document, target)?;
    Some(match channel.get("address").and_then(Value::as_str) {
        Some(address) => address.to_string(),
        None => target
            .rsplit('/')
            .next()
            .unwrap_or_default()
            .replace("~1", "/"),
    })
}

fn key(operation: &Operation) -> (String, String) {
    (operation.method.clone(), normalize_address(&operation.path))
}

impl SpecFormat for AsyncApi {
    fn id(&self) -> FormatId {
        FormatId::AsyncApi
    }

    fn name(&self) -> &'static str {
        "AsyncAPI"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::FULL
    }

    fn candidate_strength(&self, path: &str) -> Option<NameStrength> {
        crate::tree_checks::candidate_strength(path, "asyncapi")
    }

    fn classify(&self, path: &str, bytes: &[u8], max_bytes: usize) -> Candidate {
        crate::tree::classify(
            path,
            bytes,
            max_bytes,
            self.candidate_strength(path),
            &RULES,
        )
    }

    fn parse(&self, text: &str, syntax: Syntax) -> Result<Value, ParseFailure> {
        crate::parse::parse(text, syntax)
    }

    fn version(&self, document: &Value) -> Option<SpecVersion> {
        declared_version(document)
    }

    fn validate(&self, document: &Value, _: &[Peer<'_>]) -> Vec<Diagnostic> {
        validate::validate(document)
    }

    fn operations(&self, document: &Value) -> Vec<Operation> {
        let mut operations = BTreeSet::new();
        if declared_version(document) == Some(SpecVersion::AsyncApi3) {
            for operation in document
                .get("operations")
                .and_then(Value::as_object)
                .into_iter()
                .flat_map(|map| map.values())
            {
                let action = operation.get("action").and_then(Value::as_str);
                if let (Some(action @ ("send" | "receive")), Some(address)) =
                    (action, address(document, operation))
                {
                    operations.insert(Operation::new(action, address));
                }
            }
        } else {
            for (name, item) in document
                .get("channels")
                .and_then(Value::as_object)
                .into_iter()
                .flatten()
            {
                for (field, action) in [("subscribe", "send"), ("publish", "receive")] {
                    if item.get(field).is_some() {
                        operations.insert(Operation::new(action, name.as_str()));
                    }
                }
            }
        }
        operations.into_iter().collect()
    }

    fn compare(&self, document: &Value, _: &[Peer<'_>], inventory: &[Operation]) -> Completeness {
        let documented = self
            .operations(document)
            .into_iter()
            .map(|operation| {
                let keys = vec![key(&operation)];
                (operation, keys)
            })
            .collect();
        compare_by_key(documented, inventory, key)
    }

    fn preservation(
        &self,
        original: &Value,
        repaired: &Value,
        before: &[Diagnostic],
    ) -> Vec<String> {
        crate::tree_checks::violations(
            original,
            repaired,
            before,
            declared_version,
            &["asyncapi"],
            &SURFACES,
        )
    }

    fn inventory_operation(&self, method: &str, path: &str) -> Result<Operation, String> {
        let method = method.trim().to_ascii_lowercase();
        if !matches!(method.as_str(), "send" | "receive") {
            return Err(format!(
                "inventory method {method:?} is not send or receive"
            ));
        }
        if path.trim().is_empty() {
            return Err("inventory path must be the channel address".into());
        }
        Ok(Operation::new(method, path))
    }

    fn emit(&self, document: &Value, syntax: Syntax) -> Result<String, String> {
        if !document.is_object() {
            return Err("a create decision needs `document` as a mapping".into());
        }
        match syntax {
            Syntax::Json => Ok(crate::emit::to_json_ordered(document, ORDER)),
            _ => crate::emit::to_yaml_ordered(document, ORDER),
        }
    }

    fn new_document_problems(&self, document: &Value) -> Vec<String> {
        if document.get("asyncapi").and_then(Value::as_str) == Some("3.0.0") {
            Vec::new()
        } else {
            vec!["a new document must declare asyncapi: \"3.0.0\"".into()]
        }
    }

    fn owners(&self, _: &[HttpService], surfaces: &[ApiSurface]) -> Vec<Owner> {
        surfaces
            .iter()
            .filter_map(|surface| {
                let libraries = surface.of(ApiFamily::Messaging);
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
        false
    }

    fn scan_source(&self, _: &str, _: &str) -> Vec<CitedOperation> {
        Vec::new()
    }
}

/// No messaging library reads a static AsyncAPI document from a fixed
/// place, so the one convention is not confident: any location is
/// accepted and nothing is ever moved.
const CONVENTION: Convention = Convention {
    path: "asyncapi.yaml",
    syntax: Syntax::Yaml,
    confident: false,
    accepted_directories: &[],
    basis: "no messaging library reads a static AsyncAPI document from a fixed place; \
            asyncapi.yaml at the service root is the usual name",
    code_first: false,
};

#[cfg(test)]
mod tests;
