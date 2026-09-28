//! Deterministic serialization of a generated document.
//!
//! Generated YAML uses a deliberately small subset: block mappings and
//! sequences indented by two spaces, every string and key double-quoted,
//! `{}` and `[]` for empty collections, and plain `null`, booleans and
//! numbers. Every construct in it is one `bc_yaml::parse_strict` reads
//! exactly, so a generated file is always verifiable by this crate on a
//! later run, and the round trip is tested rather than assumed.
//!
//! `serde_json`'s map is ordered alphabetically in this workspace, which
//! would put `components` before `info` and `openapi`. Keys are emitted in
//! the standard's conventional reading order instead (OpenAPI's by
//! default), then alphabetically.

use serde_json::{Map, Value};

/// Keys in the order a reader of an OpenAPI or Swagger document expects,
/// across every object kind. A key's position in this list is its rank;
/// unlisted keys follow in alphabetical order.
///
/// `$ref`, `type` and the composition keywords come first for a reason
/// beyond convention. The redactor that guards delivered files matches a
/// secret-named key followed, across whitespace, by a long value, so a
/// block-YAML property named `password` whose first nested line is
/// `"description": ...` reads as a password. Leading with a short keyword
/// keeps an ordinary schema from looking like a credential.
pub const OPENAPI_ORDER: &[&str] = &[
    "$ref",
    "type",
    "allOf",
    "oneOf",
    "anyOf",
    "openapi",
    "swagger",
    "info",
    "jsonSchemaDialect",
    "host",
    "basePath",
    "schemes",
    "consumes",
    "produces",
    "servers",
    "name",
    "in",
    "title",
    "summary",
    "description",
    "termsOfService",
    "contact",
    "license",
    "version",
    "tags",
    "operationId",
    "format",
    "required",
    "parameters",
    "requestBody",
    "properties",
    "items",
    "enum",
    "schema",
    "content",
    "responses",
    "callbacks",
    "deprecated",
    "security",
    "paths",
    "get",
    "put",
    "post",
    "delete",
    "options",
    "head",
    "patch",
    "trace",
    "webhooks",
    "components",
    "definitions",
    "securityDefinitions",
    "externalDocs",
];

fn ordered<'a>(map: &'a Map<String, Value>, order: &[&str]) -> Vec<(&'a String, &'a Value)> {
    let rank = |key: &str| {
        order
            .iter()
            .position(|preferred| *preferred == key)
            .unwrap_or(order.len())
    };
    let mut entries: Vec<_> = map.iter().collect();
    // Stable, and the map already iterates alphabetically.
    entries.sort_by_key(|(key, _)| rank(key));
    entries
}

/// `value` as YAML in the subset described in the module comment. Fails
/// only for an integer above `i64::MAX`, which the YAML reader would read
/// back as a string.
pub fn to_yaml(value: &Value) -> Result<String, String> {
    to_yaml_ordered(value, OPENAPI_ORDER)
}

/// [`to_yaml`] with keys ranked by `order` instead of OpenAPI's order.
pub fn to_yaml_ordered(value: &Value, order: &[&str]) -> Result<String, String> {
    let mut out = String::new();
    match value {
        Value::Object(map) if !map.is_empty() => yaml_mapping(map, 0, order, &mut out)?,
        Value::Array(items) if !items.is_empty() => yaml_sequence(items, 0, order, &mut out)?,
        other => {
            out.push_str(&yaml_scalar(other)?);
            out.push('\n');
        }
    }
    Ok(out)
}

fn yaml_mapping(
    map: &Map<String, Value>,
    indent: usize,
    order: &[&str],
    out: &mut String,
) -> Result<(), String> {
    for (key, value) in ordered(map, order) {
        out.push_str(&" ".repeat(indent));
        out.push_str(&quote(key));
        out.push(':');
        yaml_child(value, indent, order, out)?;
    }
    Ok(())
}

fn yaml_sequence(
    items: &[Value],
    indent: usize,
    order: &[&str],
    out: &mut String,
) -> Result<(), String> {
    for item in items {
        out.push_str(&" ".repeat(indent));
        out.push('-');
        yaml_child(item, indent, order, out)?;
    }
    Ok(())
}

/// The value after a `key:` or `-` written at `indent`. Collections start
/// on the next line, two spaces deeper, which the reader handles the same
/// way under a key and under a dash.
fn yaml_child(
    value: &Value,
    indent: usize,
    order: &[&str],
    out: &mut String,
) -> Result<(), String> {
    match value {
        Value::Object(map) if !map.is_empty() => {
            out.push('\n');
            yaml_mapping(map, indent + 2, order, out)
        }
        Value::Array(items) if !items.is_empty() => {
            out.push('\n');
            yaml_sequence(items, indent + 2, order, out)
        }
        other => {
            out.push(' ');
            out.push_str(&yaml_scalar(other)?);
            out.push('\n');
            Ok(())
        }
    }
}

fn yaml_scalar(value: &Value) -> Result<String, String> {
    match value {
        Value::String(text) => Ok(quote(text)),
        Value::Number(number) if number.is_u64() && !number.is_i64() => Err(format!(
            "integer {number} is outside the range the YAML reader represents"
        )),
        Value::Object(_) => Ok("{}".into()),
        Value::Array(_) => Ok("[]".into()),
        // null, booleans and numbers print as the reader resolves them.
        other => Ok(other.to_string()),
    }
}

/// A double-quoted YAML scalar using only escapes the reader decodes.
fn quote(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            control if (control as u32) < 0x20 || control == '\u{7f}' => {
                out.push_str(&format!("\\x{:02x}", control as u32));
            }
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

/// `value` as two-space indented JSON in the same key order as
/// [`to_yaml`], with a trailing newline.
pub fn to_json(value: &Value) -> String {
    to_json_ordered(value, OPENAPI_ORDER)
}

/// [`to_json`] with keys ranked by `order` instead of OpenAPI's order.
pub fn to_json_ordered(value: &Value, order: &[&str]) -> String {
    let mut out = String::new();
    json_value(value, 0, order, &mut out);
    out.push('\n');
    out
}

fn json_value(value: &Value, indent: usize, order: &[&str], out: &mut String) {
    let pad = " ".repeat(indent + 2);
    match value {
        Value::Object(map) if !map.is_empty() => {
            out.push_str("{\n");
            for (index, (key, child)) in ordered(map, order).into_iter().enumerate() {
                if index > 0 {
                    out.push_str(",\n");
                }
                out.push_str(&pad);
                out.push_str(&Value::String(key.clone()).to_string());
                out.push_str(": ");
                json_value(child, indent + 2, order, out);
            }
            out.push('\n');
            out.push_str(&" ".repeat(indent));
            out.push('}');
        }
        Value::Array(items) if !items.is_empty() => {
            out.push_str("[\n");
            for (index, child) in items.iter().enumerate() {
                if index > 0 {
                    out.push_str(",\n");
                }
                out.push_str(&pad);
                json_value(child, indent + 2, order, out);
            }
            out.push('\n');
            out.push_str(&" ".repeat(indent));
            out.push(']');
        }
        other => out.push_str(&other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample() -> Value {
        json!({
            "paths": {
                "/pets/{id}": {
                    "get": {
                        "responses": {"200": {"description": "A pet: with # and \"quotes\""}},
                        "parameters": [{"required": true, "in": "path", "name": "id", "schema": {"type": "string"}}],
                        "operationId": "getPet",
                        "tags": ["pets", ""],
                    }
                }
            },
            "info": {"version": "1.0.0", "title": "Pets\nline two\ttab\r\u{1}\u{7f} \\ back"},
            "openapi": "3.1.0",
            "components": {"schemas": {}, "examples": []},
            "x-numbers": [0, -7, 9_223_372_036_854_775_807i64, 1.5, -0.25, 1e21, 1e-7, true, false, null],
            "x-nested": [[1, [2]], [{"a": {"b": []}}], {}],
            "": "empty key",
            "key: with colon": "- dash",
            "&anchor": "*alias",
        })
    }

    #[test]
    fn every_emitted_yaml_document_reads_back_to_the_same_value() {
        for value in [
            sample(),
            json!({}),
            json!([]),
            json!("scalar"),
            json!(42),
            json!(null),
            json!([{"a": 1}, [], "x"]),
        ] {
            let yaml = to_yaml(&value).unwrap();
            assert_eq!(bc_yaml::parse_strict(&yaml).unwrap(), value, "{yaml}");
        }
    }

    #[test]
    fn keys_follow_the_conventional_reading_order() {
        let yaml = to_yaml(&sample()).unwrap();
        let openapi = yaml.find("\"openapi\"").unwrap();
        let info = yaml.find("\"info\"").unwrap();
        let paths = yaml.find("\"paths\"").unwrap();
        let components = yaml.find("\"components\"").unwrap();
        assert!(openapi < info && info < paths && paths < components);
        assert!(yaml.find("\"title\"").unwrap() < yaml.find("\"version\"").unwrap());
        assert!(yaml.find("\"name\"").unwrap() < yaml.find("\"in\"").unwrap());
        assert!(yaml.starts_with("\"openapi\": \"3.1.0\"\n"));
    }

    #[test]
    fn secret_named_properties_do_not_read_as_credentials() {
        let value = json!({"properties": {
            "password": {"description": "The account password", "format": "password", "type": "string"},
            "access_token": {"description": "Issued token", "$ref": "#/components/schemas/Token"},
        }});
        let yaml = to_yaml(&value).unwrap();
        assert_eq!(bc_redact::redact(&yaml), yaml);
        assert!(crate::hygiene::credential_lines(&yaml).is_empty());
    }

    #[test]
    fn integers_the_reader_cannot_hold_are_refused() {
        let error = to_yaml(&json!({"big": u64::MAX})).unwrap_err();
        assert!(error.contains("outside the range"));
        assert!(to_yaml(&json!([u64::MAX])).is_err());
        assert!(to_yaml(&json!({"a": {"b": [u64::MAX]}})).is_err());
    }

    #[test]
    fn json_output_is_ordered_indented_and_round_trips() {
        let value = sample();
        let text = to_json(&value);
        assert_eq!(serde_json::from_str::<Value>(&text).unwrap(), value);
        assert!(text.starts_with("{\n  \"openapi\": \"3.1.0\",\n  \"info\": {\n"));
        assert!(text.ends_with("}\n"));
        assert_eq!(to_json(&json!({})), "{}\n");
        assert_eq!(to_json(&json!([1, 2])), "[\n  1,\n  2\n]\n");
    }

    #[test]
    fn empty_collections_are_flow_scalars() {
        assert_eq!(yaml_scalar(&json!({})).unwrap(), "{}");
        assert_eq!(yaml_scalar(&json!([])).unwrap(), "[]");
    }
}
