//! Structural validation of AsyncAPI 2.0 to 2.6 and 3.x documents,
//! implemented from the specifications' own rules: the version and
//! `info`, servers (a URL or host, a protocol, no embedded credentials),
//! channels and their parameters, operations (2.x `publish`/`subscribe`
//! with unique `operationId`s; 3.x `action`, a channel reference and
//! messages of that channel), security schemes and local `$ref`s.
//!
//! No broker is contacted: a server entry is a description, never an
//! address this step connects to.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

use crate::diagnostic::{escape, Code, Diagnostic};
use crate::format::SpecVersion;
use crate::tree_checks::{embeds_credentials, info, template_parameters, version_field};

/// Protocols the AsyncAPI bindings registry names. Another value is
/// legal but unusual, so it is a warning.
const PROTOCOLS: [&str; 26] = [
    "amqp",
    "amqps",
    "http",
    "https",
    "ibmmq",
    "jms",
    "kafka",
    "kafka-secure",
    "anypointmq",
    "mqtt",
    "secure-mqtt",
    "mqtt5",
    "solace",
    "stomp",
    "stomps",
    "ws",
    "wss",
    "mercure",
    "googlepubsub",
    "pulsar",
    "nats",
    "redis",
    "sns",
    "sqs",
    "socketio",
    "sse",
];

const SCHEME_TYPES: [&str; 13] = [
    "userPassword",
    "apiKey",
    "X509",
    "symmetricEncryption",
    "asymmetricEncryption",
    "httpApiKey",
    "http",
    "oauth2",
    "openIdConnect",
    "plain",
    "scramSha256",
    "scramSha512",
    "gssapi",
];

/// Channel item fields of AsyncAPI 2.x; the object admits no others.
const CHANNEL_ITEM_FIELDS: [&str; 7] = [
    "$ref",
    "description",
    "servers",
    "subscribe",
    "publish",
    "parameters",
    "bindings",
];

pub(super) fn supported(major: &str, minor: &str) -> bool {
    matches!(
        (major, minor),
        ("2", "0" | "1" | "2" | "3" | "4" | "5" | "6") | ("3", "0")
    )
}

/// Validate `document`.
pub fn validate(document: &Value) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    let Some(root) = document.as_object() else {
        out.push(Diagnostic::error(
            Code::NotAnObject,
            "",
            "the document root must be a mapping",
        ));
        return out;
    };
    version_field(root, "asyncapi", supported, "3.0.0", &mut out);
    info(root, &mut out);
    let v3 = super::declared_version(document) == Some(SpecVersion::AsyncApi3);
    servers(root, v3, &mut out);
    let schemes = security_schemes(root, &mut out);
    if v3 {
        channels_v3(root, &mut out);
        operations_v3(document, root, &mut out);
    } else {
        channels_v2(root, &schemes, &mut out);
    }
    out.extend(crate::refs::check(
        document,
        &["examples", "example", "default", "enum", "const"],
    ));
    out
}

fn mapping<'a>(
    root: &'a Map<String, Value>,
    key: &str,
    required: bool,
    out: &mut Vec<Diagnostic>,
) -> Option<&'a Map<String, Value>> {
    let pointer = format!("/{key}");
    match root.get(key) {
        None if required => {
            out.push(Diagnostic::error(
                Code::MissingField,
                &pointer,
                format!("missing the required `{key}` object"),
            ));
            None
        }
        None => None,
        Some(Value::Object(map)) => Some(map),
        Some(_) => {
            out.push(Diagnostic::error(
                Code::InvalidType,
                &pointer,
                format!("`{key}` must be a mapping"),
            ));
            None
        }
    }
}

fn servers(root: &Map<String, Value>, v3: bool, out: &mut Vec<Diagnostic>) {
    let Some(servers) = mapping(root, "servers", false, out) else {
        return;
    };
    let location = if v3 { "host" } else { "url" };
    for (name, server) in servers {
        let pointer = format!("/servers/{}", escape(name));
        if server.get("$ref").is_some() {
            continue;
        }
        let text = |key: &str| server.get(key).and_then(Value::as_str);
        match text(location) {
            Some(address) if !address.trim().is_empty() => {
                if embeds_credentials(address) {
                    out.push(Diagnostic::error(
                        Code::InvalidServer,
                        format!("{pointer}/{location}"),
                        "a server must not embed credentials",
                    ));
                }
            }
            _ => out.push(Diagnostic::error(
                Code::InvalidServer,
                &pointer,
                format!("a server needs a non-empty `{location}` string"),
            )),
        }
        match text("protocol") {
            Some(protocol) if PROTOCOLS.contains(&protocol) => {}
            Some(protocol) => out.push(Diagnostic::warning(
                Code::InvalidServer,
                format!("{pointer}/protocol"),
                format!("protocol `{protocol}` is not one the AsyncAPI bindings registry names"),
            )),
            None => out.push(Diagnostic::error(
                Code::InvalidServer,
                &pointer,
                "a server needs a `protocol` string",
            )),
        }
    }
}

/// Defined security scheme names; each scheme needs a known `type`.
fn security_schemes(root: &Map<String, Value>, out: &mut Vec<Diagnostic>) -> BTreeSet<String> {
    let mut defined = BTreeSet::new();
    let schemes = root
        .get("components")
        .and_then(|components| components.get("securitySchemes"))
        .and_then(Value::as_object);
    for (name, scheme) in schemes.into_iter().flatten() {
        defined.insert(name.clone());
        if scheme.get("$ref").is_some() {
            continue;
        }
        let kind = scheme
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !SCHEME_TYPES.contains(&kind) {
            out.push(Diagnostic::error(
                Code::InvalidSecurityScheme,
                format!("/components/securitySchemes/{}", escape(name)),
                format!("security scheme type `{kind}` is not an AsyncAPI scheme type"),
            ));
        }
    }
    defined
}

/// Declared parameters must appear in the address; an undeclared
/// expression is only unusual.
fn parameters(address: &str, channel: &Value, pointer: &str, out: &mut Vec<Diagnostic>) {
    let template = template_parameters(address);
    let declared: BTreeSet<String> = channel
        .get("parameters")
        .and_then(Value::as_object)
        .map(|map| map.keys().cloned().collect())
        .unwrap_or_default();
    for name in declared.difference(&template) {
        out.push(Diagnostic::error(
            Code::UnknownPathParameter,
            format!("{pointer}/parameters/{}", escape(name)),
            format!("parameter `{name}` does not appear in the channel address"),
        ));
    }
    for name in template.difference(&declared) {
        out.push(Diagnostic::warning(
            Code::UndeclaredPathParameter,
            pointer,
            format!("address expression `{{{name}}}` has no parameter definition"),
        ));
    }
}

fn channels_v2(root: &Map<String, Value>, schemes: &BTreeSet<String>, out: &mut Vec<Diagnostic>) {
    let Some(channels) = mapping(root, "channels", true, out) else {
        return;
    };
    let mut operation_ids: BTreeMap<&str, String> = BTreeMap::new();
    for (name, channel) in channels {
        let pointer = format!("/channels/{}", escape(name));
        let Some(item) = channel.as_object() else {
            out.push(Diagnostic::error(
                Code::InvalidType,
                &pointer,
                "a channel item must be a mapping",
            ));
            continue;
        };
        parameters(name, channel, &pointer, out);
        for (key, value) in item {
            let field = format!("{pointer}/{}", escape(key));
            if !CHANNEL_ITEM_FIELDS.contains(&key.as_str()) && !key.starts_with("x-") {
                out.push(Diagnostic::error(
                    Code::UnknownField,
                    &field,
                    format!("`{key}` is not a channel item field of AsyncAPI 2.x"),
                ));
            }
            if !matches!(key.as_str(), "publish" | "subscribe") {
                continue;
            }
            let Some(operation) = value.as_object() else {
                out.push(Diagnostic::error(
                    Code::InvalidType,
                    &field,
                    "an operation must be a mapping",
                ));
                continue;
            };
            if let Some(id) = operation.get("operationId").and_then(Value::as_str) {
                if let Some(first) = operation_ids.get(id) {
                    out.push(Diagnostic::error(
                        Code::DuplicateOperationId,
                        format!("{field}/operationId"),
                        format!("operationId `{id}` is already used at {first}"),
                    ));
                } else {
                    operation_ids.insert(id, field.clone());
                }
            }
            for (index, requirement) in operation
                .get("security")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .enumerate()
            {
                for scheme in requirement.as_object().into_iter().flat_map(Map::keys) {
                    if !schemes.contains(scheme) {
                        out.push(Diagnostic::error(
                            Code::UndefinedSecurityScheme,
                            format!("{field}/security/{index}/{}", escape(scheme)),
                            format!("security scheme `{scheme}` is not defined"),
                        ));
                    }
                }
            }
        }
    }
}

fn channels_v3(root: &Map<String, Value>, out: &mut Vec<Diagnostic>) {
    let Some(channels) = mapping(root, "channels", false, out) else {
        return;
    };
    for (name, channel) in channels {
        let pointer = format!("/channels/{}", escape(name));
        match channel.get("address") {
            None | Some(Value::Null) => {}
            Some(Value::String(address)) => parameters(address, channel, &pointer, out),
            Some(_) => out.push(Diagnostic::error(
                Code::InvalidType,
                format!("{pointer}/address"),
                "`address` must be a string or null",
            )),
        }
    }
}

fn operations_v3(document: &Value, root: &Map<String, Value>, out: &mut Vec<Diagnostic>) {
    let Some(operations) = mapping(root, "operations", false, out) else {
        return;
    };
    for (name, operation) in operations {
        let pointer = format!("/operations/{}", escape(name));
        if !matches!(
            operation.get("action").and_then(Value::as_str),
            Some("send" | "receive")
        ) {
            out.push(Diagnostic::error(
                Code::InvalidMethod,
                format!("{pointer}/action"),
                "an operation's `action` must be send or receive",
            ));
        }
        let channel = operation
            .get("channel")
            .and_then(|channel| channel.get("$ref"))
            .and_then(Value::as_str)
            .filter(|target| target.starts_with("#/channels/"));
        let Some(channel) = channel else {
            out.push(Diagnostic::error(
                Code::MissingField,
                format!("{pointer}/channel"),
                "an operation needs `channel` as a reference to #/channels/...",
            ));
            continue;
        };
        for (index, message) in operation
            .get("messages")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .enumerate()
        {
            let target = message
                .get("$ref")
                .and_then(Value::as_str)
                .unwrap_or_default();
            // An unresolvable target is reported by the reference walk.
            if !target.starts_with(&format!("{channel}/messages/"))
                && crate::refs::lookup(document, target).is_some()
            {
                out.push(Diagnostic::error(
                    Code::UnresolvedRef,
                    format!("{pointer}/messages/{index}"),
                    format!("an operation's messages must be messages of its channel `{channel}`"),
                ));
            }
        }
    }
}
