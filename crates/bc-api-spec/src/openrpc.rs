//! OpenRPC 1.x: JSON-RPC 2.0 services. Operations are method calls
//! (`call` and the method name); owners are services with a JSON-RPC
//! server library.
//!
//! Validation follows the OpenRPC 1.3 specification: the version and
//! `info`, servers with a credential-free URL, and methods with a unique,
//! non-reserved name, `params` (content descriptors with a unique name and
//! a schema), an optional `paramStructure`, a `result` (absent only for a
//! notification, which is legal but worth a look) and well-formed
//! `errors`, plus local `$ref`s.

use std::collections::BTreeSet;

use serde_json::{Map, Value};

use crate::diagnostic::{Code, Diagnostic};
use crate::format::{
    name_of, Candidate, Capabilities, FormatId, NameStrength, Owner, Peer, SpecFormat, SpecVersion,
    Syntax,
};
use crate::inventory::{compare_by_key, CitedOperation, Completeness, Operation};
use crate::libraries::{ApiFamily, ApiSurface};
use crate::location::Convention;
use crate::parse::ParseFailure;
use crate::plan::HttpService;
use crate::refs::resolve;
use crate::tree::TreeRules;
use crate::tree_checks::{embeds_credentials, info, version_field, Surface};

/// OpenRPC.
pub struct OpenRpc;

/// The registered instance.
pub static OPENRPC: OpenRpc = OpenRpc;

/// The version a new document declares.
const NEW_VERSION: &str = "1.3.2";

pub fn declared_version(document: &Value) -> Option<SpecVersion> {
    let declared = document
        .get("openrpc")
        .and_then(crate::openapi::detect::scalar_text)?;
    (declared.split('.').next() == Some("1")).then_some(SpecVersion::OpenRpc1)
}

const RULES: TreeRules = TreeRules {
    markers: &["openrpc"],
    shape: &["info", "methods"],
    foreign: &["openapi", "swagger", "asyncapi"],
    version: declared_version,
};

const ORDER: &[&str] = &[
    "$ref",
    "type",
    "allOf",
    "oneOf",
    "anyOf",
    "openrpc",
    "info",
    "title",
    "version",
    "description",
    "servers",
    "url",
    "methods",
    "name",
    "summary",
    "tags",
    "paramStructure",
    "params",
    "required",
    "schema",
    "properties",
    "items",
    "result",
    "errors",
    "code",
    "message",
    "examples",
    "components",
];

const SURFACES: [Surface; 1] = [Surface {
    key: "methods",
    noun: "method",
    by: Some("name"),
}];

const CONVENTION: Convention = Convention {
    path: "openrpc.json",
    syntax: Syntax::Json,
    confident: false,
    accepted_directories: &[],
    basis: "OpenRPC services serve the document through rpc.discover; openrpc.json at the \
            service root is the usual static name",
    code_first: false,
};

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
    version_field(
        root,
        "openrpc",
        |major, _| major == "1",
        NEW_VERSION,
        &mut out,
    );
    info(root, &mut out);
    servers(root, &mut out);
    match root.get("methods") {
        None => out.push(Diagnostic::error(
            Code::MissingField,
            "/methods",
            "missing the required `methods` list",
        )),
        Some(Value::Array(methods)) => {
            let mut names = BTreeSet::new();
            for (index, method) in methods.iter().enumerate() {
                // An unresolvable reference is reported by the reference walk.
                if let Some(method) = resolve(document, method) {
                    self::method(
                        document,
                        method,
                        &format!("/methods/{index}"),
                        &mut names,
                        &mut out,
                    );
                }
            }
        }
        Some(_) => out.push(Diagnostic::error(
            Code::InvalidType,
            "/methods",
            "`methods` must be a sequence",
        )),
    }
    out.extend(crate::refs::check(
        document,
        &["examples", "example", "default", "enum", "const", "value"],
    ));
    out
}

fn servers(root: &Map<String, Value>, out: &mut Vec<Diagnostic>) {
    for (index, server) in root
        .get("servers")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        let pointer = format!("/servers/{index}");
        match server.get("url").and_then(Value::as_str) {
            Some(url) if embeds_credentials(url) => out.push(Diagnostic::error(
                Code::InvalidServer,
                format!("{pointer}/url"),
                "a server URL must not embed credentials",
            )),
            Some(url) if !url.trim().is_empty() => {}
            _ => out.push(Diagnostic::error(
                Code::InvalidServer,
                &pointer,
                "a server needs a non-empty `url` string",
            )),
        }
    }
}

/// A content descriptor: a mapping with a `name` string and a `schema`.
fn descriptor(
    document: &Value,
    value: &Value,
    pointer: &str,
    out: &mut Vec<Diagnostic>,
) -> Option<String> {
    let value = resolve(document, value)?;
    let name = value.get("name").and_then(Value::as_str);
    if name.is_none_or(|name| name.is_empty()) || value.get("schema").is_none() {
        out.push(Diagnostic::error(
            Code::InvalidParameter,
            pointer,
            "a content descriptor needs a non-empty `name` and a `schema`",
        ));
    }
    name.map(str::to_string)
}

fn method(
    document: &Value,
    method: &Value,
    pointer: &str,
    names: &mut BTreeSet<String>,
    out: &mut Vec<Diagnostic>,
) {
    let Some(method) = method.as_object() else {
        out.push(Diagnostic::error(
            Code::InvalidType,
            pointer,
            "a method must be a mapping",
        ));
        return;
    };
    match method.get("name").and_then(Value::as_str) {
        Some(name) if !name.is_empty() => {
            if name.starts_with("rpc.") {
                out.push(Diagnostic::error(
                    Code::ReservedName,
                    format!("{pointer}/name"),
                    format!("method `{name}`: names starting with rpc. are reserved"),
                ));
            }
            if !names.insert(name.to_string()) {
                out.push(Diagnostic::error(
                    Code::DuplicateOperationId,
                    format!("{pointer}/name"),
                    format!("method `{name}` is declared more than once"),
                ));
            }
        }
        _ => out.push(Diagnostic::error(
            Code::MissingField,
            format!("{pointer}/name"),
            "a method needs a non-empty `name`",
        )),
    }
    match method.get("params") {
        Some(Value::Array(params)) => {
            let mut seen = BTreeSet::new();
            for (index, param) in params.iter().enumerate() {
                let param_pointer = format!("{pointer}/params/{index}");
                if let Some(name) = descriptor(document, param, &param_pointer, out) {
                    if !seen.insert(name.clone()) {
                        out.push(Diagnostic::error(
                            Code::DuplicateParameter,
                            &param_pointer,
                            format!("parameter `{name}` is declared twice"),
                        ));
                    }
                }
            }
        }
        None => out.push(Diagnostic::error(
            Code::MissingField,
            format!("{pointer}/params"),
            "a method needs a `params` list (empty when it takes none)",
        )),
        Some(_) => out.push(Diagnostic::error(
            Code::InvalidType,
            format!("{pointer}/params"),
            "`params` must be a sequence",
        )),
    }
    if let Some(structure) = method.get("paramStructure") {
        if !matches!(
            structure.as_str(),
            Some("by-name" | "by-position" | "either")
        ) {
            out.push(Diagnostic::error(
                Code::InvalidType,
                format!("{pointer}/paramStructure"),
                "`paramStructure` must be by-name, by-position or either",
            ));
        }
    }
    match method.get("result") {
        Some(result) => {
            descriptor(document, result, &format!("{pointer}/result"), out);
        }
        None => out.push(Diagnostic::warning(
            Code::MissingField,
            format!("{pointer}/result"),
            "the method declares no result, which makes it a notification",
        )),
    }
    for (index, error) in method
        .get("errors")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        let Some(error) = resolve(document, error) else {
            continue;
        };
        if !error.get("code").is_some_and(Value::is_i64)
            || !error.get("message").is_some_and(Value::is_string)
        {
            out.push(Diagnostic::error(
                Code::InvalidType,
                format!("{pointer}/errors/{index}"),
                "an error needs an integer `code` and a `message` string",
            ));
        }
    }
}

fn key(operation: &Operation) -> (String, String) {
    (operation.method.clone(), operation.path.clone())
}

impl SpecFormat for OpenRpc {
    fn id(&self) -> FormatId {
        FormatId::OpenRpc
    }

    fn name(&self) -> &'static str {
        "OpenRPC"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::FULL
    }

    fn candidate_strength(&self, path: &str) -> Option<NameStrength> {
        crate::tree_checks::candidate_strength(path, "openrpc")
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
        validate(document)
    }

    fn operations(&self, document: &Value) -> Vec<Operation> {
        let names: BTreeSet<&str> = document
            .get("methods")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|method| resolve(document, method)?.get("name")?.as_str())
            .collect();
        names
            .into_iter()
            .map(|name| Operation::new("call", name))
            .collect()
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
            &["openrpc"],
            &SURFACES,
        )
    }

    fn inventory_operation(&self, method: &str, path: &str) -> Result<Operation, String> {
        if !method.trim().eq_ignore_ascii_case("call") {
            return Err(format!("inventory method {method:?} is not call"));
        }
        if path.is_empty() || path.contains(char::is_whitespace) {
            return Err(format!(
                "inventory path {path:?} is not a JSON-RPC method name"
            ));
        }
        Ok(Operation::new("call", path))
    }

    fn emit(&self, document: &Value, syntax: Syntax) -> Result<String, String> {
        if !document.is_object() {
            return Err("a create decision needs `document` as a mapping".into());
        }
        match syntax {
            Syntax::Yaml => crate::emit::to_yaml_ordered(document, ORDER),
            _ => Ok(crate::emit::to_json_ordered(document, ORDER)),
        }
    }

    fn new_document_problems(&self, document: &Value) -> Vec<String> {
        if document.get("openrpc").and_then(Value::as_str) == Some(NEW_VERSION) {
            Vec::new()
        } else {
            vec![format!(
                "a new document must declare openrpc: \"{NEW_VERSION}\""
            )]
        }
    }

    fn owners(&self, _: &[HttpService], surfaces: &[ApiSurface]) -> Vec<Owner> {
        surfaces
            .iter()
            .filter_map(|surface| {
                let libraries = surface.of(ApiFamily::JsonRpc);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnostic::Severity;
    use crate::libraries::ApiLibrary;
    use serde_json::json;

    fn document() -> Value {
        json!({
            "openrpc": "1.3.2",
            "info": {"title": "Pets", "version": "1.0.0"},
            "servers": [{"url": "https://rpc.example.invalid"}],
            "methods": [
                {
                    "name": "pet_get",
                    "params": [{"$ref": "#/components/contentDescriptors/Id"}],
                    "paramStructure": "by-name",
                    "result": {"name": "pet", "schema": {"type": "object"}},
                    "errors": [{"code": -32001, "message": "not found"}, {"$ref": "#/components/errors/Busy"}],
                    "examples": [{"name": "e", "params": [], "result": {"value": {"$ref": "not a ref"}}}],
                },
                {"$ref": "#/components/methods/Notify"},
            ],
            "components": {
                "contentDescriptors": {"Id": {"name": "id", "schema": {"type": "string"}}},
                "errors": {"Busy": {"code": 1, "message": "busy"}},
                "methods": {"Notify": {"name": "pet_notify", "params": [], "result": {"name": "ok", "schema": {}}}},
            },
        })
    }

    fn found(document: &Value) -> Vec<(Severity, Code, String)> {
        validate(document)
            .into_iter()
            .map(|d| (d.severity, d.code, d.pointer))
            .collect()
    }

    #[test]
    fn a_valid_document_has_no_diagnostics() {
        assert_eq!(found(&document()), []);
        assert_eq!(declared_version(&document()), Some(SpecVersion::OpenRpc1));
        assert_eq!(declared_version(&json!({"openrpc": "2.0.0"})), None);
    }

    #[test]
    fn methods_params_results_and_errors_are_checked() {
        let mut bad = document();
        bad["openrpc"] = json!("1.3");
        bad["servers"] = json!([{"url": "https://u:p@rpc.invalid"}, {}]);
        bad["methods"] = json!([
            {"name": "rpc.discover", "params": [{"name": "a", "schema": {}}, {"name": "a", "schema": {}}, {"schema": {}}], "result": {"name": "r"}},
            {"name": "rpc.discover", "params": {}, "paramStructure": "sideways", "errors": [{"code": "x"}, {"$ref": "#/nowhere"}]},
            {"params": []},
            "text",
            {"$ref": "#/nowhere"},
        ]);
        let expected = [
            (Severity::Error, Code::InvalidVersion, "/openrpc"),
            (Severity::Error, Code::InvalidServer, "/servers/0/url"),
            (Severity::Error, Code::InvalidServer, "/servers/1"),
            (Severity::Error, Code::ReservedName, "/methods/0/name"),
            (
                Severity::Error,
                Code::DuplicateParameter,
                "/methods/0/params/1",
            ),
            (
                Severity::Error,
                Code::InvalidParameter,
                "/methods/0/params/2",
            ),
            (Severity::Error, Code::InvalidParameter, "/methods/0/result"),
            (Severity::Error, Code::ReservedName, "/methods/1/name"),
            (
                Severity::Error,
                Code::DuplicateOperationId,
                "/methods/1/name",
            ),
            (Severity::Error, Code::InvalidType, "/methods/1/params"),
            (
                Severity::Error,
                Code::InvalidType,
                "/methods/1/paramStructure",
            ),
            (Severity::Warning, Code::MissingField, "/methods/1/result"),
            (Severity::Error, Code::InvalidType, "/methods/1/errors/0"),
            (Severity::Error, Code::MissingField, "/methods/2/name"),
            (Severity::Warning, Code::MissingField, "/methods/2/result"),
            (Severity::Error, Code::InvalidType, "/methods/3"),
            (
                Severity::Error,
                Code::UnresolvedRef,
                "/methods/1/errors/1/$ref",
            ),
            (Severity::Error, Code::UnresolvedRef, "/methods/4/$ref"),
        ];
        let expected: Vec<_> = expected
            .into_iter()
            .map(|(s, c, p)| (s, c, p.to_string()))
            .collect();
        assert_eq!(found(&bad), expected);
        let mut missing = document();
        missing.as_object_mut().unwrap().remove("methods");
        assert_eq!(
            found(&missing),
            [(Severity::Error, Code::MissingField, "/methods".into())]
        );
        missing["methods"] = json!({});
        missing["params"] = json!(null);
        assert_eq!(
            found(&missing),
            [(Severity::Error, Code::InvalidType, "/methods".into())]
        );
        missing["methods"] = json!([{"name": "m"}]);
        assert_eq!(
            found(&missing),
            [
                (
                    Severity::Error,
                    Code::MissingField,
                    "/methods/0/params".into()
                ),
                (
                    Severity::Warning,
                    Code::MissingField,
                    "/methods/0/result".into()
                ),
            ]
        );
        assert_eq!(
            found(&json!(1)),
            [(Severity::Error, Code::NotAnObject, String::new())]
        );
    }

    #[test]
    fn operations_are_method_calls() {
        assert_eq!(
            OPENRPC.operations(&document()),
            [
                Operation::new("call", "pet_get"),
                Operation::new("call", "pet_notify")
            ]
        );
        let result = OPENRPC.compare(
            &document(),
            &[],
            &[
                Operation::new("call", "pet_get"),
                Operation::new("call", "pet_put"),
            ],
        );
        assert_eq!(result.missing, [Operation::new("call", "pet_put")]);
        assert_eq!(result.unverified, [Operation::new("call", "pet_notify")]);
        assert_eq!(
            OPENRPC.inventory_operation(" CALL ", "pet_put").unwrap(),
            Operation::new("call", "pet_put")
        );
        assert!(OPENRPC
            .inventory_operation("get", "a")
            .unwrap_err()
            .contains("not call"));
        assert!(OPENRPC
            .inventory_operation("call", "a b")
            .unwrap_err()
            .contains("method name"));
        assert!(OPENRPC.inventory_operation("call", "").is_err());
    }

    #[test]
    fn repairs_keep_every_documented_method() {
        let original = document();
        let mut repaired = original.clone();
        repaired["methods"][0]["summary"] = json!("added");
        assert!(OPENRPC.preservation(&original, &repaired, &[]).is_empty());
        repaired["methods"] = json!([]);
        assert_eq!(
            OPENRPC.preservation(&original, &repaired, &[]),
            ["removed documented method `pet_get`"]
        );
    }

    #[test]
    fn candidates_emission_and_owners() {
        assert_eq!(
            OPENRPC.candidate_strength("openrpc.json"),
            Some(NameStrength::Strong)
        );
        assert_eq!(
            OPENRPC.candidate_strength("rpc/my-openrpc.yaml"),
            Some(NameStrength::Weak)
        );
        let text = serde_json::to_vec(&document()).unwrap();
        assert!(matches!(
            OPENRPC.classify("openrpc.json", &text, 1 << 20),
            Candidate::Spec {
                version: Some(SpecVersion::OpenRpc1),
                ..
            }
        ));
        let parsed = OPENRPC
            .parse("{\"openrpc\": \"1.0.0\"}", Syntax::Json)
            .unwrap();
        assert_eq!(OPENRPC.version(&parsed), Some(SpecVersion::OpenRpc1));
        assert!(OPENRPC.validate(&document(), &[]).is_empty());
        let json = OPENRPC.emit(&document(), Syntax::Json).unwrap();
        assert!(
            json.starts_with("{\n  \"openrpc\": \"1.3.2\",\n  \"info\""),
            "{json}"
        );
        let yaml = OPENRPC.emit(&document(), Syntax::Yaml).unwrap();
        assert_eq!(bc_yaml::parse_strict(&yaml).unwrap(), document());
        assert!(OPENRPC.emit(&json!("x"), Syntax::Json).is_err());
        assert!(OPENRPC.new_document_problems(&document()).is_empty());
        assert_eq!(
            OPENRPC.new_document_problems(&json!({"openrpc": "1.0.0"})),
            ["a new document must declare openrpc: \"1.3.2\""]
        );
        let surfaces = [ApiSurface {
            root: "rpc".into(),
            manifests: vec![],
            libraries: [ApiLibrary::JsonRpc, ApiLibrary::Kafka]
                .into_iter()
                .collect(),
        }];
        let owners = OPENRPC.owners(&[], &surfaces);
        assert_eq!(owners[0].stack, ["json_rpc"]);
        assert!(OPENRPC.owners(&[], &[]).is_empty());
        assert_eq!(OPENRPC.fallback().path, "openrpc.json");
        assert_eq!(OPENRPC.name(), "OpenRPC");
        assert_eq!(OPENRPC.capabilities(), Capabilities::FULL);
    }
}
