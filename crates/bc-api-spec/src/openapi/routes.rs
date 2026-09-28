//! Comparing a specification's operations with the routes the code serves.
//!
//! Frameworks spell path parameters differently: Express `:id`, OpenAPI,
//! Spring and ASP.NET `{id}` (with optional constraints such as
//! `{id:int}` or catch-alls such as `{*slug}`), Flask and Django `<id>` or
//! `<int:id>`, Next.js `[id]` and `[...slug]`, Django regular expressions
//! `(?P<id>...)`, and wildcards `*` or `*path`. Parameter names are
//! irrelevant to whether two routes are the same operation, so every
//! parameter normalizes to `{}` and names are dropped.

use std::collections::BTreeSet;

use serde_json::Value;

use super::validate::METHODS;
use crate::inventory::{Completeness, Operation};

/// The lower-case method name, if it is an HTTP method a specification
/// documents.
pub fn normalize_method(method: &str) -> Option<String> {
    let lower = method.trim().to_ascii_lowercase();
    METHODS.contains(&lower.as_str()).then_some(lower)
}

/// `path` with its query and fragment removed, duplicate and trailing
/// slashes collapsed, and every path parameter spelled `{}`.
pub fn normalize_path(path: &str) -> String {
    // A `?` inside a Django `(?P<...>)` group is not a query string.
    let mut depth = 0usize;
    let mut end = path.len();
    for (index, character) in path.char_indices() {
        match character {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            '?' | '#' if depth == 0 => {
                end = index;
                break;
            }
            _ => {}
        }
    }
    let path = &path[..end];
    let segments: Vec<String> = path
        .split('/')
        .filter(|segment| !segment.trim().is_empty())
        .map(|segment| normalize_segment(segment.trim()))
        .collect();
    format!("/{}", segments.join("/"))
}

fn normalize_segment(segment: &str) -> String {
    let whole = |open: &str, close: char| segment.starts_with(open) && segment.ends_with(close);
    if segment.starts_with(':')
        || segment.starts_with('*')
        || segment.starts_with("(?P<")
        || whole("<", '>')
        || whole("[", ']')
    {
        return "{}".into();
    }
    // Brace parameters may share a segment with literal text, as in
    // `{name}.json`, so each braced run is replaced where it stands.
    let mut out = String::new();
    let mut rest = segment;
    while let Some(start) = rest.find('{') {
        let Some(length) = rest[start..].find('}') else {
            break;
        };
        out.push_str(&rest[..start]);
        out.push_str("{}");
        rest = &rest[start + length + 1..];
    }
    out.push_str(rest);
    out
}

/// Every operation a document declares under `paths`, in document order.
pub fn spec_operations(document: &Value) -> Vec<Operation> {
    let mut operations = Vec::new();
    let Some(paths) = document.get("paths").and_then(Value::as_object) else {
        return operations;
    };
    for (path, item) in paths {
        let Some(item) = item.as_object() else {
            continue;
        };
        for method in item.keys() {
            if METHODS.contains(&method.as_str()) {
                operations.push(Operation {
                    method: method.clone(),
                    path: path.clone(),
                });
            }
        }
    }
    operations
}

/// Path prefixes the document's servers add in front of every path: the
/// Swagger 2.0 `basePath`, and the path part of each OpenAPI server URL.
pub fn base_paths(document: &Value) -> Vec<String> {
    let mut bases = BTreeSet::new();
    if let Some(base) = document.get("basePath").and_then(Value::as_str) {
        bases.insert(normalize_path(base));
    }
    for server in document
        .get("servers")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(url) = server.get("url").and_then(Value::as_str) else {
            continue;
        };
        let path = match url.split_once("://") {
            Some((_, rest)) => rest.find('/').map_or("", |start| &rest[start..]),
            None => url,
        };
        bases.insert(normalize_path(path));
    }
    bases.remove("/");
    bases.into_iter().collect()
}

/// Compare `document` with `inventory`, matching each documented path both
/// as written and with every server base path in front of it.
pub fn compare(document: &Value, inventory: &[Operation]) -> Completeness {
    let bases = base_paths(document);
    let documented: Vec<(Operation, Vec<(String, String)>)> = spec_operations(document)
        .into_iter()
        .map(|operation| {
            let mut keys = vec![(operation.method.clone(), normalize_path(&operation.path))];
            for base in &bases {
                let joined = format!("{base}/{}", operation.path);
                keys.push((operation.method.clone(), normalize_path(&joined)));
            }
            (operation, keys)
        })
        .collect();
    let documented_keys: BTreeSet<&(String, String)> =
        documented.iter().flat_map(|(_, keys)| keys).collect();
    let served: BTreeSet<(String, String)> = inventory
        .iter()
        .filter_map(|operation| {
            Some((
                normalize_method(&operation.method)?,
                normalize_path(&operation.path),
            ))
        })
        .collect();
    let missing: BTreeSet<Operation> = inventory
        .iter()
        .filter(|operation| {
            let key = (
                normalize_method(&operation.method).unwrap_or_default(),
                normalize_path(&operation.path),
            );
            !documented_keys.contains(&key)
        })
        .cloned()
        .collect();
    let unverified: BTreeSet<Operation> = documented
        .into_iter()
        .filter(|(_, keys)| !keys.iter().any(|key| served.contains(key)))
        .map(|(operation, _)| operation)
        .collect();
    Completeness {
        missing: missing.into_iter().collect(),
        unverified: unverified.into_iter().collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn op(method: &str, path: &str) -> Operation {
        Operation {
            method: method.into(),
            path: path.into(),
        }
    }

    #[test]
    fn methods_are_lower_cased_and_restricted() {
        assert_eq!(normalize_method(" GET "), Some("get".into()));
        assert_eq!(normalize_method("TRACE"), Some("trace".into()));
        assert_eq!(normalize_method("ANY"), None);
    }

    #[test]
    fn parameter_styles_normalize_to_one_spelling() {
        for path in [
            "/users/:id",
            "/users/{id}",
            "/users/{id:int}",
            "/users/<int:id>",
            "/users/<id>",
            "/users/[id]",
            "/users/[...slug]",
            "/users/*",
            "/users/*rest",
            "/users/(?P<id>[0-9]+)",
            "users//{userId}/",
            "/users/{id}?expand=true",
            "/users/{id}#fragment",
        ] {
            assert_eq!(normalize_path(path), "/users/{}", "{path}");
        }
        assert_eq!(normalize_path("/files/{name}.json"), "/files/{}.json");
        assert_eq!(normalize_path("/a/{x}-{y}/{open"), "/a/{}-{}/{open");
        assert_eq!(normalize_path(""), "/");
        assert_eq!(normalize_path("/"), "/");
    }

    #[test]
    fn operations_are_read_from_paths_only() {
        let document = json!({"paths": {
            "/a": {"get": {}, "post": {}, "parameters": [], "x-y": {}},
            "/b": "not an item",
        }});
        assert_eq!(
            spec_operations(&document),
            [op("get", "/a"), op("post", "/a")]
        );
        assert!(spec_operations(&json!({})).is_empty());
    }

    #[test]
    fn server_urls_and_base_paths_contribute_prefixes() {
        let document = json!({
            "basePath": "/v2",
            "servers": [
                {"url": "https://api.example.invalid/api/v1/"},
                {"url": "https://api.example.invalid"},
                {"url": "/relative"},
                {"description": "no url"},
            ],
        });
        assert_eq!(base_paths(&document), ["/api/v1", "/relative", "/v2"]);
        assert!(base_paths(&json!({})).is_empty());
    }

    #[test]
    fn completeness_reports_missing_and_unverified_operations() {
        let document = json!({
            "servers": [{"url": "https://x.invalid/api"}],
            "paths": {
                "/users/{userId}": {"get": {}, "delete": {}},
                "/health": {"get": {}},
            }
        });
        let inventory = [
            op("GET", "/api/users/:id"),
            op("get", "/health/"),
            op("post", "/users"),
            op("FETCH", "/odd"),
        ];
        let result = compare(&document, &inventory);
        assert_eq!(result.missing, [op("FETCH", "/odd"), op("post", "/users")]);
        assert_eq!(result.unverified, [op("delete", "/users/{userId}")]);
        assert!(!result.is_complete());
        assert!(compare(&document, &[]).is_complete());
    }
}
