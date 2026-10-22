//! Checks shared by the newer JSON and YAML standards (AsyncAPI and
//! OpenRPC): naming, the `info` object, version strings, credential-free
//! URLs, address templates and preservation of what a document declared.
//! OpenAPI keeps its own, older implementations of the same ideas.

use std::collections::BTreeSet;

use serde_json::{Map, Value};

use crate::diagnostic::{escape, Code, Diagnostic};
use crate::format::{NameStrength, SpecVersion, Syntax};

/// A JSON or YAML file named `<standard>.*` or `*.<standard>.*` is
/// strongly nominated; one whose name merely contains the standard's name
/// weakly.
pub(crate) fn candidate_strength(path: &str, standard: &str) -> Option<NameStrength> {
    Syntax::from_path(path)?;
    let lower = path.to_ascii_lowercase();
    let name = lower.rsplit('/').next().unwrap_or_default();
    // The extension check above guarantees a dot.
    let stem = name.rsplit_once('.').map_or(name, |(stem, _)| stem);
    if stem == standard || stem.ends_with(&format!(".{standard}")) {
        Some(NameStrength::Strong)
    } else if stem.contains(standard) {
        Some(NameStrength::Weak)
    } else {
        None
    }
}

/// `info.title` (a non-empty string) and `info.version` (a string).
pub(crate) fn info(root: &Map<String, Value>, out: &mut Vec<Diagnostic>) {
    let Some(info) = root.get("info") else {
        out.push(Diagnostic::error(
            Code::MissingField,
            "/info",
            "missing the required `info` object",
        ));
        return;
    };
    let Some(info) = info.as_object() else {
        out.push(Diagnostic::error(
            Code::InvalidType,
            "/info",
            "`info` must be a mapping",
        ));
        return;
    };
    match info.get("title") {
        Some(Value::String(title)) if !title.trim().is_empty() => {}
        None => out.push(Diagnostic::error(
            Code::MissingField,
            "/info/title",
            "missing `info.title`",
        )),
        Some(_) => out.push(Diagnostic::error(
            Code::InvalidType,
            "/info/title",
            "`info.title` must be a non-empty string",
        )),
    }
    match info.get("version") {
        Some(Value::String(_)) => {}
        None => out.push(Diagnostic::error(
            Code::MissingField,
            "/info/version",
            "missing `info.version`",
        )),
        Some(_) => out.push(Diagnostic::error(
            Code::InvalidType,
            "/info/version",
            "`info.version` must be a string; quote it",
        )),
    }
}

/// The `key` version field: a quoted `major.minor.patch` string whose
/// major and minor versions `supported` accepts.
pub(crate) fn version_field(
    root: &Map<String, Value>,
    key: &str,
    supported: fn(&str, &str) -> bool,
    example: &str,
    out: &mut Vec<Diagnostic>,
) {
    let pointer = format!("/{key}");
    let Some(value) = root.get(key) else {
        out.push(Diagnostic::error(
            Code::MissingVersion,
            "",
            format!("missing the `{key}` version field"),
        ));
        return;
    };
    let valid = value.as_str().is_some_and(|text| {
        let parts: Vec<&str> = text.split('.').collect();
        parts.len() == 3
            && parts
                .iter()
                .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()))
            && supported(parts[0], parts[1])
    });
    if !valid {
        out.push(Diagnostic::error(
            Code::InvalidVersion,
            &pointer,
            format!("`{key}` must be a supported, quoted version string such as \"{example}\""),
        ));
    }
}

/// Whether a URL (or host) carries `user:password@` credentials.
pub(crate) fn embeds_credentials(url: &str) -> bool {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    rest.split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .contains('@')
}

/// `{name}` expressions of an address template.
pub(crate) fn template_parameters(address: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let mut rest = address;
    while let Some(start) = rest.find('{') {
        let after = &rest[start + 1..];
        let Some(end) = after.find('}') else {
            break;
        };
        names.insert(after[..end].to_string());
        rest = &after[end + 1..];
    }
    names
}

/// An address with every `{name}` spelled `{}` and one leading `/`
/// dropped, for comparing a documented address with a cited one.
pub(crate) fn normalize_address(address: &str) -> String {
    let mut out = String::new();
    let mut rest = address.trim();
    rest = rest.strip_prefix('/').unwrap_or(rest);
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

/// A documented part of the API: a mapping of named entries (`by` is
/// `None`) or a sequence of objects named by their `by` field.
pub(crate) struct Surface {
    pub key: &'static str,
    pub noun: &'static str,
    pub by: Option<&'static str>,
}

/// Every way `repaired` fails to preserve `original`, given the
/// diagnostics `original` had before the repair. The version must not
/// change. A documented surface entry may gain fields but never lose one,
/// and never disappear; its existing fields and every other top-level
/// value may change only where a diagnostic pointed. Entries of each
/// `components` kind may change only where a diagnostic pointed.
pub(crate) fn violations(
    original: &Value,
    repaired: &Value,
    before: &[Diagnostic],
    version: fn(&Value) -> Option<SpecVersion>,
    markers: &[&str],
    surfaces: &[Surface],
) -> Vec<String> {
    let touched = |pointer: &str| {
        before.iter().any(|diagnostic| {
            diagnostic.pointer == pointer || diagnostic.pointer.starts_with(&format!("{pointer}/"))
        })
    };
    let mut out = Vec::new();
    let original_version = version(original);
    if original_version.is_some() && version(repaired) != original_version {
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
        if markers.contains(&key.as_str()) {
            continue;
        }
        if let Some(surface) = surfaces.iter().find(|surface| surface.key == key) {
            for (name, entry, entry_pointer) in named(value, surface.by, &pointer) {
                let later = after.and_then(|after| find(after, surface.by, &name));
                entry_kept(
                    surface.noun,
                    &name,
                    entry,
                    later,
                    &entry_pointer,
                    &touched,
                    &mut out,
                );
            }
        } else if key == "components" {
            for (kind, entries) in value.as_object().into_iter().flatten() {
                let kind_pointer = format!("/components/{}", escape(kind));
                for (name, entry) in entries.as_object().into_iter().flatten() {
                    let entry_pointer = format!("{kind_pointer}/{}", escape(name));
                    let later = after.and_then(|after| after.get(kind)?.get(name));
                    if !touched(&entry_pointer) && later != Some(entry) {
                        out.push(format!(
                            "changed or removed `{entry_pointer}`, which had no diagnostics"
                        ));
                    }
                }
            }
        } else if !touched(&pointer) && after != Some(value) {
            out.push(format!(
                "changed or removed `{key}`, which had no diagnostics"
            ));
        }
    }
    out
}

/// Named entries of a surface value with their pointers.
fn named<'a>(
    value: &'a Value,
    by: Option<&str>,
    pointer: &str,
) -> Vec<(String, &'a Value, String)> {
    match (value, by) {
        (Value::Object(map), None) => map
            .iter()
            .map(|(name, entry)| (name.clone(), entry, format!("{pointer}/{}", escape(name))))
            .collect(),
        (Value::Array(items), Some(field)) => items
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| {
                let name = entry.get(field)?.as_str()?.to_string();
                Some((name, entry, format!("{pointer}/{index}")))
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn find<'a>(value: &'a Value, by: Option<&str>, name: &str) -> Option<&'a Value> {
    match by {
        None => value.get(name),
        Some(field) => value
            .as_array()?
            .iter()
            .find(|entry| entry.get(field).and_then(Value::as_str) == Some(name)),
    }
}

fn entry_kept(
    noun: &str,
    name: &str,
    entry: &Value,
    later: Option<&Value>,
    pointer: &str,
    touched: &dyn Fn(&str) -> bool,
    out: &mut Vec<String>,
) {
    let Some(later) = later else {
        out.push(format!("removed documented {noun} `{name}`"));
        return;
    };
    let unchanged = match (entry.as_object(), later.as_object()) {
        // Fields may be added; each existing one is kept unless a
        // diagnostic pointed at it or at the entry.
        (Some(fields), Some(now)) => fields.iter().all(|(field, value)| {
            now.get(field) == Some(value)
                || (now.contains_key(field)
                    && (touched(pointer) || touched(&format!("{pointer}/{}", escape(field)))))
        }),
        _ => entry == later || touched(pointer),
    };
    if !unchanged {
        out.push(format!(
            "changed or removed part of {noun} `{name}`, which had no diagnostics"
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn names_nominate_candidates() {
        assert_eq!(
            candidate_strength("asyncapi.yaml", "asyncapi"),
            Some(NameStrength::Strong)
        );
        assert_eq!(
            candidate_strength("docs/orders.asyncapi.json", "asyncapi"),
            Some(NameStrength::Strong)
        );
        assert_eq!(
            candidate_strength("docs/my-asyncapi-v2.yml", "asyncapi"),
            Some(NameStrength::Weak)
        );
        assert_eq!(candidate_strength("asyncapi.md", "asyncapi"), None);
        assert_eq!(candidate_strength("events.yaml", "asyncapi"), None);
    }

    fn diagnostics(root: Value) -> Vec<(Code, String)> {
        let mut out = Vec::new();
        info(root.as_object().unwrap(), &mut out);
        version_field(
            root.as_object().unwrap(),
            "v",
            |major, _| major == "1",
            "1.0.0",
            &mut out,
        );
        out.into_iter().map(|d| (d.code, d.pointer)).collect()
    }

    #[test]
    fn info_and_versions_are_checked() {
        assert!(
            diagnostics(json!({"v": "1.2.3", "info": {"title": "t", "version": "1"}})).is_empty()
        );
        assert_eq!(
            diagnostics(json!({"v": 1.2, "info": {"title": " ", "version": 1}})),
            [
                (Code::InvalidType, "/info/title".into()),
                (Code::InvalidType, "/info/version".into()),
                (Code::InvalidVersion, "/v".into()),
            ]
        );
        assert_eq!(
            diagnostics(json!({"v": "2.0.0", "info": {}})),
            [
                (Code::MissingField, "/info/title".into()),
                (Code::MissingField, "/info/version".into()),
                (Code::InvalidVersion, "/v".into()),
            ]
        );
        assert_eq!(
            diagnostics(json!({"info": []})),
            [
                (Code::InvalidType, "/info".into()),
                (Code::MissingVersion, "".into())
            ]
        );
        assert_eq!(
            diagnostics(json!({"v": "1.x.0"})),
            [
                (Code::MissingField, "/info".into()),
                (Code::InvalidVersion, "/v".into())
            ]
        );
    }

    #[test]
    fn urls_templates_and_addresses() {
        assert!(embeds_credentials("amqp://user:pw@broker.invalid/vhost"));
        assert!(embeds_credentials("user@broker.invalid"));
        assert!(!embeds_credentials("kafka://broker.invalid:9092"));
        assert!(!embeds_credentials("/ws?to=a@b"));
        assert_eq!(
            template_parameters("user/{id}/{event}/{open")
                .into_iter()
                .collect::<Vec<_>>(),
            ["event", "id"]
        );
        assert_eq!(
            normalize_address(" /user/{userId}/signup "),
            "user/{}/signup"
        );
        assert_eq!(normalize_address("a.{x}.b{"), "a.{}.b{");
    }

    fn version(document: &Value) -> Option<SpecVersion> {
        (document.get("v") == Some(&json!(1))).then_some(SpecVersion::OpenApi31)
    }

    const SURFACES: [Surface; 2] = [
        Surface {
            key: "channels",
            noun: "channel",
            by: None,
        },
        Surface {
            key: "methods",
            noun: "method",
            by: Some("name"),
        },
    ];

    fn original() -> Value {
        json!({
            "v": 1,
            "info": {"title": "t"},
            "channels": {"a": {"publish": {"x": 1}}, "b": 1},
            "methods": [{"name": "m", "params": []}, {"name": "n", "params": [1]}, {"no": "name"}],
            "components": {"schemas": {"S": {}}, "odd": 1},
        })
    }

    fn check(repaired: Value, before: &[&str]) -> Vec<String> {
        let before: Vec<Diagnostic> = before
            .iter()
            .map(|pointer| Diagnostic::error(Code::InvalidType, *pointer, ""))
            .collect();
        violations(&original(), &repaired, &before, version, &["v"], &SURFACES)
    }

    #[test]
    fn additions_and_diagnosed_fixes_are_allowed() {
        let mut repaired = original();
        repaired["channels"]["a"]["subscribe"] = json!({});
        repaired["channels"]["c"] = json!({});
        repaired["methods"][0]["result"] = json!({});
        repaired["methods"][1]["params"] = json!([2]);
        repaired["components"]["schemas"]["T"] = json!({});
        repaired["info"]["title"] = json!("fixed");
        repaired["channels"]["b"] = json!(2);
        assert_eq!(
            check(repaired, &["/info", "/methods/1/params", "/channels/b"]),
            Vec::<String>::new()
        );
    }

    #[test]
    fn removals_and_untouched_changes_are_violations() {
        let mut repaired = original();
        repaired["v"] = json!(2);
        repaired["info"] = json!({});
        repaired["channels"]["a"] = json!({});
        repaired["channels"]["b"] = json!(2);
        repaired["methods"] = json!([{"name": "m", "params": [9]}]);
        repaired["components"]["schemas"] = json!({});
        assert_eq!(
            check(repaired, &[]),
            [
                "the repair changed the specification version; repairs keep the author's version",
                "changed or removed part of channel `a`, which had no diagnostics",
                "changed or removed part of channel `b`, which had no diagnostics",
                "changed or removed `/components/schemas/S`, which had no diagnostics",
                "changed or removed `info`, which had no diagnostics",
                "changed or removed part of method `m`, which had no diagnostics",
                "removed documented method `n`",
            ]
        );
        let mut gone = original();
        gone["channels"] = json!([]);
        assert_eq!(
            check(gone, &[]),
            [
                "removed documented channel `a`",
                "removed documented channel `b`"
            ]
        );
        assert!(violations(&json!([]), &json!({}), &[], version, &[], &SURFACES).is_empty());
        // A surface in an unexpected shape declares nothing to keep.
        let odd = json!({"methods": {"m": {}}});
        assert!(violations(&odd, &json!({}), &[], version, &[], &SURFACES).is_empty());
    }
}
