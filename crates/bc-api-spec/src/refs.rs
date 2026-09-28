//! Local `$ref` resolution for the JSON and YAML standards (OpenAPI,
//! AsyncAPI, OpenRPC), which share the JSON Reference convention.

use serde_json::Value;

use crate::diagnostic::{escape, Code, Diagnostic};

/// Nesting beyond this is not walked for references. Both parsers already
/// refuse deeper documents; this keeps the walk bounded for any caller.
pub(crate) const MAX_WALK_DEPTH: usize = 256;

/// Every `$ref` in `document` that does not resolve within it (an error),
/// points outside it (a warning: it was not verified), or is not a string.
/// Values under `data_keys` (examples, defaults and the like) and under
/// `x-` extensions are data, not document structure, and may legitimately
/// contain a `$ref` key, so they are not walked.
pub fn check(document: &Value, data_keys: &[&str]) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    walk(document, document, String::new(), 0, data_keys, &mut out);
    out
}

fn walk(
    document: &Value,
    value: &Value,
    pointer: String,
    depth: usize,
    data_keys: &[&str],
    out: &mut Vec<Diagnostic>,
) {
    if depth > MAX_WALK_DEPTH {
        return;
    }
    match value {
        Value::Object(map) => {
            if let Some(reference) = map.get("$ref") {
                let reference_pointer = format!("{pointer}/$ref");
                match reference.as_str() {
                    Some(target) if target.starts_with('#') => {
                        if lookup(document, target).is_none() {
                            out.push(Diagnostic::error(
                                Code::UnresolvedRef,
                                reference_pointer,
                                format!("`{target}` does not resolve within this document"),
                            ));
                        }
                    }
                    Some(target) => out.push(Diagnostic::warning(
                        Code::ExternalRef,
                        reference_pointer,
                        format!("external reference `{target}` was not verified"),
                    )),
                    None => out.push(Diagnostic::error(
                        Code::InvalidType,
                        reference_pointer,
                        "`$ref` must be a string",
                    )),
                }
            }
            for (key, child) in map {
                if data_keys.contains(&key.as_str()) || key.starts_with("x-") {
                    continue;
                }
                let child_pointer = format!("{pointer}/{}", escape(key));
                walk(document, child, child_pointer, depth + 1, data_keys, out);
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                let child_pointer = format!("{pointer}/{index}");
                walk(document, child, child_pointer, depth + 1, data_keys, out);
            }
        }
        _ => {}
    }
}

/// Follow a local `$ref` (up to eight hops) to the value it names. A value
/// without a `$ref` is returned as is; an unresolvable one yields `None`.
pub fn resolve<'a>(document: &'a Value, value: &'a Value) -> Option<&'a Value> {
    let mut current = value;
    for _ in 0..8 {
        match current.get("$ref").and_then(Value::as_str) {
            Some(target) if target.starts_with('#') => current = lookup(document, target)?,
            _ => return Some(current),
        }
    }
    None
}

/// Resolve a `#/...` reference within `document`, decoding the URI
/// fragment's percent escapes before the JSON pointer's own.
pub fn lookup<'a>(document: &'a Value, reference: &str) -> Option<&'a Value> {
    let fragment = reference.strip_prefix('#')?;
    document.pointer(&percent_decode(fragment))
}

pub(crate) fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let decoded = (bytes[index] == b'%')
            .then(|| text.get(index + 1..index + 3))
            .flatten()
            .and_then(|hex| u8::from_str_radix(hex, 16).ok());
        match decoded {
            Some(byte) => {
                out.push(byte);
                index += 3;
            }
            None => {
                out.push(bytes[index]);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}
