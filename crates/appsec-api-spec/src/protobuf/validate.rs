//! Validation of a `.proto` file over the tree [`super::parser`]
//! produces, following the Protocol Buffers language specifications for
//! proto2, proto3 and editions:
//!
//! - `syntax` is proto2 or proto3 (editions are read, their label rules
//!   are not checked);
//! - names are unique within their scope, and field and enum value
//!   numbers within their message or enum (enum aliases need
//!   `allow_alias`);
//! - field numbers lie in 1 to 2^29 - 1 outside 19000 to 19999, which the
//!   implementation reserves, and conflict with no `reserved` number,
//!   range or name and no `extensions` range;
//! - labels suit the syntax: proto3 has no `required` and no groups,
//!   proto2 fields outside a `oneof` or map carry a label, and `oneof` and
//!   map fields carry none;
//! - a proto3 enum's first value is zero, and no enum is empty;
//! - imports resolve within the repository (or are well-known types),
//!   and every field and RPC type resolves, by protobuf's scoping rules,
//!   to a message or enum defined here, in another `.proto` file of the
//!   repository, or among the well-known types. When an import did not
//!   resolve, an unknown type may come from it, so it is a warning.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use super::parser::MAX_FIELD_NUMBER;
use crate::diagnostic::{escape, Code, Diagnostic};
use crate::format::Peer;

const SCALARS: [&str; 15] = [
    "double", "float", "int32", "int64", "uint32", "uint64", "sint32", "sint64", "fixed32",
    "fixed64", "sfixed32", "sfixed64", "bool", "string", "bytes",
];

/// Message and enum types `google/protobuf/*.proto` define.
const WELL_KNOWN: [&str; 19] = [
    "Any",
    "Api",
    "BoolValue",
    "BytesValue",
    "DoubleValue",
    "Duration",
    "Empty",
    "FieldMask",
    "FloatValue",
    "Int32Value",
    "Int64Value",
    "ListValue",
    "NullValue",
    "StringValue",
    "Struct",
    "Timestamp",
    "UInt32Value",
    "UInt64Value",
    "Value",
];

pub(super) fn list<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

pub(super) fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or_default()
}

fn number(value: &Value) -> i64 {
    value
        .get("number")
        .and_then(Value::as_i64)
        .unwrap_or_default()
}

fn ranges(value: &Value, key: &str) -> Vec<(i64, i64)> {
    list(value, key)
        .iter()
        .filter_map(|range| Some((range.get(0)?.as_i64()?, range.get(1)?.as_i64()?)))
        .collect()
}

/// The file's package with a trailing `.`, or nothing.
pub(super) fn package_prefix(document: &Value) -> String {
    match document.get("package").and_then(Value::as_str) {
        Some(package) => format!("{package}."),
        None => String::new(),
    }
}

/// Every fully qualified message and enum name `document` defines.
fn defined_types(document: &Value, out: &mut BTreeSet<String>) {
    fn walk(value: &Value, scope: &str, out: &mut BTreeSet<String>) {
        for message in list(value, "messages") {
            let name = format!("{scope}{}", text(message, "name"));
            walk(message, &format!("{name}."), out);
            out.insert(name);
        }
        for enumeration in list(value, "enums") {
            out.insert(format!("{scope}{}", text(enumeration, "name")));
        }
    }
    walk(document, &package_prefix(document), out);
}

/// Whether an import names a file of the repository or a well-known type.
fn import_resolves(import: &str, peers: &[Peer<'_>]) -> bool {
    import.starts_with("google/protobuf/")
        || peers
            .iter()
            .any(|peer| peer.path == import || peer.path.ends_with(&format!("/{import}")))
}

struct Context {
    known: BTreeSet<String>,
    /// An import did not resolve, so an unknown type may come from it.
    lenient: bool,
    proto3: bool,
    proto2: bool,
}

impl Context {
    /// Resolve `name` from `scope` (a fully qualified message name, or the
    /// package) the way protoc does: innermost scope first.
    fn resolves(&self, name: &str, scope: &str) -> bool {
        if SCALARS.contains(&name) {
            return true;
        }
        if let Some(qualified) = name.strip_prefix('.') {
            return self.known.contains(qualified);
        }
        let parts: Vec<&str> = scope.split('.').filter(|part| !part.is_empty()).collect();
        (0..=parts.len()).rev().any(|depth| {
            let prefix = parts[..depth].join(".");
            let candidate = if prefix.is_empty() {
                name.to_string()
            } else {
                format!("{prefix}.{name}")
            };
            self.known.contains(&candidate)
        })
    }

    fn type_check(&self, name: &str, scope: &str, pointer: &str, out: &mut Vec<Diagnostic>) {
        if self.resolves(name, scope) {
            return;
        }
        let message = format!("type `{name}` is not defined in this repository");
        out.push(if self.lenient {
            Diagnostic::warning(
                Code::UnknownType,
                pointer,
                format!("{message}; it may come from an import that did not resolve"),
            )
        } else {
            Diagnostic::error(Code::UnknownType, pointer, message)
        });
    }
}

/// Validate `document`, with the repository's other `.proto` files as
/// `peers` for imports and types.
pub fn validate(document: &Value, peers: &[Peer<'_>]) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    let syntax = document.get("syntax").and_then(Value::as_str);
    match syntax {
        None | Some("proto2" | "proto3" | "editions") => {}
        Some(other) => out.push(Diagnostic::error(
            Code::InvalidVersion,
            "/syntax",
            format!("syntax `{other}` is not proto2 or proto3"),
        )),
    }
    let mut lenient = false;
    for import in list(document, "imports") {
        let path = text(import, "path");
        if !import_resolves(path, peers) {
            lenient = true;
            out.push(Diagnostic::warning(
                Code::UnresolvedRef,
                format!("/imports/{}", escape(path)),
                format!(
                    "import `{path}` was not found in the repository; it may come from a \
                     dependency such as a buf module or googleapis"
                ),
            ));
        }
    }
    let mut known: BTreeSet<String> = WELL_KNOWN
        .iter()
        .map(|name| format!("google.protobuf.{name}"))
        .collect();
    defined_types(document, &mut known);
    for peer in peers {
        defined_types(peer.document, &mut known);
    }
    let context = Context {
        known,
        lenient,
        // A file without `syntax` is proto2.
        proto3: syntax == Some("proto3"),
        proto2: syntax.is_none_or(|syntax| syntax == "proto2"),
    };
    let package = package_prefix(document);
    scope(document, &package, "", &context, &mut out);
    let mut services = BTreeSet::new();
    for service in list(document, "services") {
        let name = text(service, "name");
        let pointer = format!("/services/{}", escape(name));
        if !services.insert(name) {
            out.push(Diagnostic::error(
                Code::DuplicateDefinition,
                &pointer,
                format!("service `{name}` is defined more than once"),
            ));
        }
        let mut rpcs = BTreeSet::new();
        for rpc in list(service, "rpcs") {
            let rpc_name = text(rpc, "name");
            let rpc_pointer = format!("{pointer}/rpcs/{}", escape(rpc_name));
            if !rpcs.insert(rpc_name) {
                out.push(Diagnostic::error(
                    Code::DuplicateField,
                    &rpc_pointer,
                    format!("rpc `{name}.{rpc_name}` is defined more than once"),
                ));
            }
            for side in ["input", "output"] {
                context.type_check(text(rpc, side), &package, &rpc_pointer, &mut out);
            }
        }
    }
    out
}

/// Messages and enums of one scope (the file or a message), recursively.
fn scope(
    value: &Value,
    scope_name: &str,
    pointer: &str,
    context: &Context,
    out: &mut Vec<Diagnostic>,
) {
    let mut names = BTreeSet::new();
    for (kind, key) in [("message", "messages"), ("enum", "enums")] {
        for definition in list(value, key) {
            let name = text(definition, "name");
            let definition_pointer = format!("{pointer}/{key}/{}", escape(name));
            if !names.insert(name) {
                out.push(Diagnostic::error(
                    Code::DuplicateDefinition,
                    &definition_pointer,
                    format!("{kind} `{name}` is defined more than once in its scope"),
                ));
            }
            if key == "messages" {
                let qualified = format!("{scope_name}{name}");
                message(definition, &qualified, &definition_pointer, context, out);
                self::scope(
                    definition,
                    &format!("{qualified}."),
                    &definition_pointer,
                    context,
                    out,
                );
            } else {
                enumeration(definition, &definition_pointer, context, out);
            }
        }
    }
    for extend in list(value, "extends") {
        for field in list(extend, "fields") {
            let field_pointer = format!("{pointer}/extends/{}", escape(text(field, "name")));
            context.type_check(text(field, "type"), scope_name, &field_pointer, out);
        }
    }
}

fn reserved_conflicts(
    definition: &Value,
    name: &str,
    number: i64,
    pointer: &str,
    what: &str,
    out: &mut Vec<Diagnostic>,
) {
    if ranges(definition, "reserved_numbers")
        .iter()
        .any(|(low, high)| (*low..=*high).contains(&number))
    {
        out.push(Diagnostic::error(
            Code::ReservedConflict,
            pointer,
            format!("{what} `{name}` uses reserved number {number}"),
        ));
    }
    if list(definition, "reserved_names")
        .iter()
        .any(|reserved| reserved.as_str() == Some(name))
    {
        out.push(Diagnostic::error(
            Code::ReservedConflict,
            pointer,
            format!("{what} name `{name}` is reserved"),
        ));
    }
}

fn message(
    message: &Value,
    qualified: &str,
    pointer: &str,
    context: &Context,
    out: &mut Vec<Diagnostic>,
) {
    let mut names = BTreeSet::new();
    let mut numbers: BTreeMap<i64, &str> = BTreeMap::new();
    let extensions = ranges(message, "extensions");
    for field in list(message, "fields") {
        let name = text(field, "name");
        let number = number(field);
        let field_pointer = format!("{pointer}/fields/{}", escape(name));
        if !names.insert(name) {
            out.push(Diagnostic::error(
                Code::DuplicateField,
                &field_pointer,
                format!("field `{name}` is declared more than once"),
            ));
        }
        if let Some(first) = numbers.insert(number, name) {
            out.push(Diagnostic::error(
                Code::DuplicateFieldNumber,
                &field_pointer,
                format!("field `{name}` reuses number {number} of `{first}`"),
            ));
        }
        if !(1..=MAX_FIELD_NUMBER).contains(&number) || (19_000..=19_999).contains(&number) {
            out.push(Diagnostic::error(
                Code::InvalidFieldNumber,
                &field_pointer,
                format!(
                    "field number {number} is outside 1 to {MAX_FIELD_NUMBER} or inside the \
                     implementation's reserved 19000 to 19999"
                ),
            ));
        }
        reserved_conflicts(message, name, number, &field_pointer, "field", out);
        if extensions
            .iter()
            .any(|(low, high)| (*low..=*high).contains(&number))
        {
            out.push(Diagnostic::error(
                Code::ReservedConflict,
                &field_pointer,
                format!("field number {number} lies inside an extensions range"),
            ));
        }
        label(field, &field_pointer, context, out);
        let is_map = field.get("key").is_some_and(|key| !key.is_null());
        if is_map {
            context.type_check(text(field, "value"), qualified, &field_pointer, out);
        } else if field.get("group") != Some(&Value::Bool(true)) {
            context.type_check(text(field, "type"), qualified, &field_pointer, out);
        }
    }
}

fn label(field: &Value, pointer: &str, context: &Context, out: &mut Vec<Diagnostic>) {
    let name = text(field, "name");
    let label = field.get("label").and_then(Value::as_str);
    let in_oneof = field.get("oneof").is_some_and(|oneof| !oneof.is_null());
    let is_map = field.get("key").is_some_and(|key| !key.is_null());
    let problem = if (in_oneof || is_map) && label.is_some() {
        Some(format!(
            "`{name}` is a oneof or map field and takes no label"
        ))
    } else if context.proto3 && label == Some("required") {
        Some(format!("`{name}`: proto3 has no required fields"))
    } else if context.proto3 && field.get("group") == Some(&Value::Bool(true)) {
        Some(format!("`{name}`: proto3 has no groups"))
    } else if context.proto2 && label.is_none() && !in_oneof && !is_map {
        Some(format!(
            "`{name}`: proto2 fields need optional, required or repeated"
        ))
    } else {
        None
    };
    if let Some(problem) = problem {
        out.push(Diagnostic::error(Code::InvalidLabel, pointer, problem));
    }
}

fn enumeration(enumeration: &Value, pointer: &str, context: &Context, out: &mut Vec<Diagnostic>) {
    let values = list(enumeration, "values");
    let name = text(enumeration, "name");
    match values.first() {
        None => out.push(Diagnostic::error(
            Code::EmptyType,
            pointer,
            format!("enum `{name}` must declare at least one value"),
        )),
        Some(first) if context.proto3 && number(first) != 0 => out.push(Diagnostic::error(
            Code::InvalidEnumValue,
            pointer,
            format!("the first value of proto3 enum `{name}` must be zero"),
        )),
        Some(_) => {}
    }
    let alias = enumeration.get("allow_alias") == Some(&Value::Bool(true));
    let mut names = BTreeSet::new();
    let mut numbers = BTreeSet::new();
    for value in values {
        let value_name = text(value, "name");
        let value_number = number(value);
        let value_pointer = format!("{pointer}/values/{}", escape(value_name));
        if !names.insert(value_name) {
            out.push(Diagnostic::error(
                Code::DuplicateField,
                &value_pointer,
                format!("enum value `{value_name}` is declared more than once"),
            ));
        }
        if !numbers.insert(value_number) && !alias {
            out.push(Diagnostic::error(
                Code::DuplicateFieldNumber,
                &value_pointer,
                format!(
                    "enum value `{value_name}` reuses number {value_number} without \
                     `option allow_alias = true`"
                ),
            ));
        }
        reserved_conflicts(
            enumeration,
            value_name,
            value_number,
            &value_pointer,
            "enum value",
            out,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protobuf::parser::parse;

    fn found(text: &str, peers: &[(&str, &str)]) -> Vec<(Code, String)> {
        let document = parse(text).unwrap();
        let parsed: Vec<(&str, Value)> = peers
            .iter()
            .map(|(path, text)| (*path, parse(text).unwrap()))
            .collect();
        let peers: Vec<Peer<'_>> = parsed
            .iter()
            .map(|(path, document)| Peer { path, document })
            .collect();
        validate(&document, &peers)
            .into_iter()
            .map(|diagnostic| (diagnostic.code, diagnostic.pointer))
            .collect()
    }

    const VALID: &str = r#"
syntax = "proto3";
package shop.v1;
import "google/protobuf/timestamp.proto";
import "shop/v1/common.proto";
message Order {
  string id = 1;
  repeated Item items = 2;
  map<string, Item> by_sku = 3;
  oneof payment { string card = 4; Money wallet = 5; }
  google.protobuf.Timestamp created = 6;
  .shop.v1.Order.Kind kind = 7;
  optional Order parent = 8;
  message Item { string sku = 1; Kind kind = 2; }
  enum Kind { KIND_UNSPECIFIED = 0; }
  reserved 9, 20 to 30;
  reserved "legacy";
}
service Orders { rpc Get (Order) returns (Order.Item); rpc Watch (stream Order) returns (google.protobuf.Empty); }
"#;
    const COMMON: &str =
        "syntax = \"proto3\";\npackage shop.v1;\nmessage Money { int64 cents = 1; }";

    #[test]
    fn a_valid_file_with_its_peers_has_no_diagnostics() {
        assert_eq!(found(VALID, &[("proto/shop/v1/common.proto", COMMON)]), []);
        // Without its peer the import and the type it defines are open.
        assert_eq!(
            found(VALID, &[]),
            [
                (
                    Code::UnresolvedRef,
                    "/imports/shop~1v1~1common.proto".into()
                ),
                (Code::UnknownType, "/messages/Order/fields/wallet".into()),
            ]
        );
        let document = parse(VALID).unwrap();
        let diagnostics = validate(&document, &[]);
        assert!(diagnostics
            .iter()
            .all(|d| d.severity == crate::diagnostic::Severity::Warning));
    }

    #[test]
    fn numbers_names_and_reserved_ranges_are_checked() {
        let text = "syntax = \"proto3\";\nmessage A {\n  int32 a = 1;\n  int32 a = 2;\n  int32 b = 1;\n  int32 c = 0;\n  int32 d = 19000;\n  int32 e = 536870912;\n  int32 f = 5;\n  int32 old = 7;\n  int32 g = 150;\n  reserved 5;\n  reserved \"old\";\n  extensions 100 to 199;\n}\nmessage A { int32 x = 1; }\nenum A { Z = 0; }\n";
        assert_eq!(
            found(text, &[]),
            [
                (Code::DuplicateField, "/messages/A/fields/a".into()),
                (Code::DuplicateFieldNumber, "/messages/A/fields/b".into()),
                (Code::InvalidFieldNumber, "/messages/A/fields/c".into()),
                (Code::InvalidFieldNumber, "/messages/A/fields/d".into()),
                (Code::InvalidFieldNumber, "/messages/A/fields/e".into()),
                (Code::ReservedConflict, "/messages/A/fields/f".into()),
                (Code::ReservedConflict, "/messages/A/fields/old".into()),
                (Code::ReservedConflict, "/messages/A/fields/g".into()),
                (Code::DuplicateDefinition, "/messages/A".into()),
                (Code::DuplicateDefinition, "/enums/A".into()),
            ]
        );
    }

    #[test]
    fn labels_suit_the_syntax() {
        let proto3 = "syntax = \"proto3\";\nmessage A {\n  required int32 a = 1;\n  oneof o { optional int32 b = 2; }\n  repeated group G = 3 { }\n}\n";
        assert_eq!(
            found(proto3, &[]),
            [
                (Code::InvalidLabel, "/messages/A/fields/a".into()),
                (Code::InvalidLabel, "/messages/A/fields/b".into()),
                (Code::InvalidLabel, "/messages/A/fields/G".into()),
            ]
        );
        let proto2 = "message A {\n  int32 a = 1;\n  optional int32 b = 2;\n  map<string, int32> m = 3;\n  oneof o { int32 c = 4; }\n  optional group G = 5 { optional int32 x = 1; }\n}\n";
        assert_eq!(
            found(proto2, &[]),
            [(Code::InvalidLabel, "/messages/A/fields/a".into())]
        );
        assert_eq!(
            found("edition = \"2023\";\nmessage A { int32 a = 1; }", &[]),
            []
        );
        assert_eq!(
            found("syntax = \"proto4\";", &[]),
            [(Code::InvalidVersion, "/syntax".into())]
        );
    }

    #[test]
    fn enums_need_values_a_zero_first_value_and_aliases_declared() {
        let text = "syntax = \"proto3\";\nenum E { A = 1; B = 1; B = 2; C = 3; reserved 3; }\nenum F { option allow_alias = true; X = 0; Y = 0; }\nenum G { reserved 1; }\n";
        assert_eq!(
            found(text, &[]),
            [
                (Code::InvalidEnumValue, "/enums/E".into()),
                (Code::DuplicateFieldNumber, "/enums/E/values/B".into()),
                (Code::DuplicateField, "/enums/E/values/B".into()),
                (Code::ReservedConflict, "/enums/E/values/C".into()),
                (Code::EmptyType, "/enums/G".into()),
            ]
        );
    }

    #[test]
    fn services_rpcs_and_extensions_resolve_their_types() {
        let text = "syntax = \"proto3\";\npackage p;\nmessage M { int32 a = 1; message Inner { Missing m = 1; } }\nservice S { rpc A (M) returns (Nope); rpc A (M) returns (M.Inner); }\nservice S {}\nextend M { .p.M extra = 100; Other other = 101; }\n";
        assert_eq!(
            found(text, &[]),
            [
                (
                    Code::UnknownType,
                    "/messages/M/messages/Inner/fields/m".into()
                ),
                (Code::UnknownType, "/extends/other".into()),
                (Code::UnknownType, "/services/S/rpcs/A".into()),
                (Code::DuplicateField, "/services/S/rpcs/A".into()),
                (Code::DuplicateDefinition, "/services/S".into()),
            ]
        );
        // A peer in another package is reachable only by its full name.
        let peer = (
            "api/other.proto",
            "syntax = \"proto3\";\npackage q;\nmessage Q { int32 a = 1; }",
        );
        assert_eq!(
            found(
                "syntax = \"proto3\";\npackage p;\nimport \"other.proto\";\nmessage M { q.Q a = 1; Q b = 2; }",
                &[peer]
            ),
            [(Code::UnknownType, "/messages/M/fields/b".into())]
        );
    }

    #[test]
    fn helpers_read_odd_shapes() {
        assert!(list(&Value::Null, "messages").is_empty());
        assert_eq!(package_prefix(&serde_json::json!({})), "");
        assert!(ranges(&serde_json::json!({"extensions": [[1], "x"]}), "extensions").is_empty());
    }
}
