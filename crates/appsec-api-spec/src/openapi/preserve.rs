//! Checking that a repair kept what the author wrote.
//!
//! A repair may fix what a diagnostic points at and add what is missing.
//! It may not change the specification version, delete a documented path
//! or operation, or alter content that had no diagnostics. The check is
//! made on parsed values, so it holds whatever edits produced the text.

use serde_json::{Map, Value};

use super::detect::declared_version;
use super::validate::{escape, Diagnostic, METHODS};

/// Top-level containers of named entries. A repair may add entries to
/// them; each existing entry is compared on its own.
const NAMED_CONTAINERS: [&str; 5] = [
    "definitions",
    "parameters",
    "responses",
    "securityDefinitions",
    "webhooks",
];

/// Every way `repaired` fails to preserve `original`, given the
/// diagnostics `original` had before the repair.
pub fn violations(original: &Value, repaired: &Value, before: &[Diagnostic]) -> Vec<String> {
    let mut out = Vec::new();
    let touched = |pointer: &str| {
        before.iter().any(|diagnostic| {
            diagnostic.pointer == pointer || diagnostic.pointer.starts_with(&format!("{pointer}/"))
        })
    };
    let original_version = declared_version(original);
    if original_version.is_some() && declared_version(repaired) != original_version {
        out.push(
            "the repair changed the specification version; repairs keep the author's version"
                .to_string(),
        );
    }
    let (Some(original), Some(repaired)) = (original.as_object(), repaired.as_object()) else {
        return out;
    };
    for (key, value) in original {
        let pointer = format!("/{}", escape(key));
        let after = repaired.get(key);
        match key.as_str() {
            "openapi" | "swagger" => {}
            "paths" => paths(value, after, before, &touched, &mut out),
            "components" => {
                for (kind, entries) in value.as_object().into_iter().flatten() {
                    let later = after.and_then(|components| components.get(kind));
                    let pointer = format!("/components/{}", escape(kind));
                    entries_kept(entries, later, &pointer, &touched, &mut out);
                }
            }
            "tags" if !touched(&pointer) => {
                let kept = value.as_array().into_iter().flatten().all(|tag| {
                    after
                        .and_then(Value::as_array)
                        .is_some_and(|later| later.contains(tag))
                });
                if !kept {
                    out.push("removed or changed an existing entry of `tags`".into());
                }
            }
            name if NAMED_CONTAINERS.contains(&name) => {
                entries_kept(value, after, &pointer, &touched, &mut out);
            }
            _ if touched(&pointer) => {}
            _ if after != Some(value) => {
                out.push(format!(
                    "changed or removed `{key}`, which had no diagnostics"
                ));
            }
            _ => {}
        }
    }
    out
}

/// Each named entry of `original` that had no diagnostics is unchanged.
pub(crate) fn entries_kept(
    original: &Value,
    repaired: Option<&Value>,
    pointer: &str,
    touched: &dyn Fn(&str) -> bool,
    out: &mut Vec<String>,
) {
    let Some(entries) = original.as_object() else {
        return;
    };
    for (name, value) in entries {
        let entry = format!("{pointer}/{}", escape(name));
        if !touched(&entry) && repaired.and_then(|later| later.get(name)) != Some(value) {
            out.push(format!(
                "changed or removed `{entry}`, which had no diagnostics"
            ));
        }
    }
}

fn paths(
    original: &Value,
    repaired: Option<&Value>,
    before: &[Diagnostic],
    touched: &dyn Fn(&str) -> bool,
    out: &mut Vec<String>,
) {
    let empty = Map::new();
    let Some(original) = original.as_object() else {
        return;
    };
    let repaired = repaired.and_then(Value::as_object).unwrap_or(&empty);
    for (path, item) in original {
        let pointer = format!("/paths/{}", escape(path));
        let Some(later) = repaired.get(path) else {
            out.push(format!("removed documented path `{path}`"));
            continue;
        };
        let Some(item) = item.as_object() else {
            continue;
        };
        // A diagnostic on the path item itself (a bad key, say) opens every
        // operation under it to change; one on an operation opens only it.
        let item_diagnosed = before
            .iter()
            .any(|diagnostic| diagnostic.pointer == pointer);
        for (key, value) in item {
            let field = format!("{pointer}/{}", escape(key));
            let after = later.get(key);
            if METHODS.contains(&key.as_str()) {
                if after.is_none() {
                    out.push(format!(
                        "removed documented operation {} {path}",
                        key.to_uppercase()
                    ));
                } else if !item_diagnosed && !touched(&field) && after != Some(value) {
                    out.push(format!(
                        "changed operation {} {path}, which had no diagnostics",
                        key.to_uppercase()
                    ));
                }
            } else if !touched(&pointer) && after != Some(value) {
                out.push(format!(
                    "changed or removed `{field}`, which had no diagnostics"
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnostic::{Code, Severity};
    use serde_json::json;

    fn diagnostic(pointer: &str) -> Diagnostic {
        Diagnostic {
            severity: Severity::Error,
            code: Code::InvalidType,
            pointer: pointer.into(),
            message: String::new(),
        }
    }

    fn original() -> Value {
        json!({
            "openapi": "3.0.3",
            "info": {"title": "t", "version": "1"},
            "tags": [{"name": "pets"}],
            "paths": {
                "/pets": {"summary": "s", "get": {"responses": {}}, "post": {"x": 1}},
                "/odd": "text",
            },
            "components": {"schemas": {"Pet": {"type": "object"}}, "odd": 1},
            "definitions": {"Old": {}},
        })
    }

    #[test]
    fn additions_and_fixes_under_diagnostics_are_allowed() {
        let before = [
            diagnostic("/paths/~1pets/get/responses"),
            diagnostic("/info/version"),
        ];
        let mut repaired = original();
        repaired["paths"]["/pets"]["get"]["responses"] = json!({"200": {"description": "ok"}});
        repaired["info"]["version"] = json!("1.0");
        repaired["paths"]["/new"] = json!({"get": {}});
        repaired["components"]["schemas"]["New"] = json!({});
        repaired["tags"] = json!([{"name": "pets"}, {"name": "new"}]);
        repaired["x-added"] = json!(true);
        assert_eq!(
            violations(&original(), &repaired, &before),
            Vec::<String>::new()
        );
    }

    #[test]
    fn deletions_and_untouched_changes_are_violations() {
        let mut repaired = original();
        repaired["openapi"] = json!("3.1.0");
        repaired["info"]["title"] = json!("changed");
        repaired["tags"] = json!([]);
        repaired["paths"]["/pets"]
            .as_object_mut()
            .unwrap()
            .remove("post");
        repaired["paths"]["/pets"]["get"] = json!({"responses": {"200": {}}});
        repaired["paths"]["/pets"]["summary"] = json!("changed");
        repaired["paths"].as_object_mut().unwrap().remove("/odd");
        repaired["components"]["schemas"]["Pet"] = json!({});
        repaired.as_object_mut().unwrap().remove("definitions");
        let found = violations(&original(), &repaired, &[]);
        assert_eq!(
            found,
            [
                "the repair changed the specification version; repairs keep the author's version",
                "changed or removed `/components/schemas/Pet`, which had no diagnostics",
                "changed or removed `/definitions/Old`, which had no diagnostics",
                "changed or removed `info`, which had no diagnostics",
                "removed documented path `/odd`",
                "changed operation GET /pets, which had no diagnostics",
                "removed documented operation POST /pets",
                "changed or removed `/paths/~1pets/summary`, which had no diagnostics",
                "removed or changed an existing entry of `tags`",
            ]
        );
    }

    #[test]
    fn touched_regions_may_change_but_documented_operations_may_not_vanish() {
        let before = [
            diagnostic("/paths/~1pets"),
            diagnostic("/tags"),
            diagnostic("/info"),
        ];
        let mut repaired = original();
        repaired["paths"]["/pets"] = json!({"get": {"changed": true}});
        repaired["tags"] = json!("x");
        repaired["info"] = json!({});
        assert_eq!(
            violations(&original(), &repaired, &before),
            ["removed documented operation POST /pets"]
        );
    }

    #[test]
    fn missing_or_odd_shapes_are_handled() {
        let mut repaired = original();
        repaired["paths"] = json!([]);
        assert_eq!(
            violations(&original(), &repaired, &[]),
            [
                "removed documented path `/odd`",
                "removed documented path `/pets`"
            ]
        );
        // A broken original with no version and a non-object repair.
        assert!(violations(&json!({"info": {}}), &json!([]), &[]).is_empty());
        assert!(violations(&json!({"paths": []}), &json!({}), &[]).is_empty());
    }
}
