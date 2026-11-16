use std::collections::BTreeMap;

use serde_json::{Map, Value};

use crate::diagnostic::{escape, Diagnostic};

pub(crate) struct Member {
    pub key: &'static str,
    pub pointer: &'static str,
    pub noun: &'static str,
}

pub(crate) struct Section {
    pub key: &'static str,
    pub pointer: &'static str,
    pub noun: &'static str,
    pub members: &'static [Member],
}

pub(crate) fn touched(before: &[Diagnostic], pointer: &str) -> bool {
    before.iter().any(|diagnostic| {
        diagnostic.pointer == pointer || diagnostic.pointer.starts_with(&format!("{pointer}/"))
    })
}

fn named<'a>(value: &'a Value, key: &str) -> Vec<(&'a str, &'a Value)> {
    value[key]
        .as_array()
        .into_iter()
        .flatten()
        .map(|entry| (entry["name"].as_str().unwrap_or_default(), entry))
        .collect()
}

fn index<'a>(value: &'a Value, key: &str) -> BTreeMap<&'a str, &'a Value> {
    let mut map = BTreeMap::new();
    for (name, entry) in named(value, key) {
        map.entry(name).or_insert(entry);
    }
    map
}

fn own(entry: &Value, members: &[Member]) -> Map<String, Value> {
    let mut map = entry.as_object().cloned().unwrap_or_default();
    for member in members {
        map.remove(member.key);
    }
    map
}

pub(crate) fn sections(
    original: &Value,
    repaired: &Value,
    sections: &[Section],
    before: &[Diagnostic],
) -> Vec<String> {
    let mut out = Vec::new();
    for section in sections {
        let now = index(repaired, section.key);
        for (name, entry) in named(original, section.key) {
            let pointer = format!("/{}/{}", section.pointer, escape(name));
            let noun = section.noun;
            let Some(&later) = now.get(name) else {
                out.push(format!("removed documented {noun} `{name}`"));
                continue;
            };
            if own(entry, section.members) != own(later, section.members)
                && !touched(before, &pointer)
            {
                out.push(format!("changed {noun} `{name}`, which had no diagnostics"));
            }
            for member in section.members {
                let members_now = index(later, member.key);
                for (member_name, value) in named(entry, member.key) {
                    let member_pointer =
                        format!("{pointer}/{}/{}", member.pointer, escape(member_name));
                    let noun = member.noun;
                    match members_now.get(member_name) {
                        None => {
                            out.push(format!("removed documented {noun} `{name}.{member_name}`"))
                        }
                        Some(&now) if now != value && !touched(before, &member_pointer) => out
                            .push(format!(
                                "changed {noun} `{name}.{member_name}`, which had no diagnostics"
                            )),
                        Some(_) => {}
                    }
                }
            }
        }
    }
    out
}

pub(crate) fn kept_values(
    original: &Value,
    repaired: &Value,
    key: &str,
    pointer: &str,
    before: &[Diagnostic],
    label: fn(&Value) -> String,
) -> Vec<String> {
    if touched(before, pointer) {
        return Vec::new();
    }
    let now: Vec<&Value> = repaired[key].as_array().into_iter().flatten().collect();
    original[key]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|value| !now.contains(value))
        .map(label)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnostic::Code;
    use serde_json::json;

    const SECTIONS: &[Section] = &[Section {
        key: "things",
        pointer: "things",
        noun: "thing",
        members: &[Member {
            key: "parts",
            pointer: "parts",
            noun: "part",
        }],
    }];

    fn model(things: Value) -> Value {
        json!({"things": things, "list": ["a", "b"]})
    }

    fn at(pointer: &str) -> Diagnostic {
        Diagnostic::error(Code::MissingField, pointer, "")
    }

    #[test]
    fn additions_are_allowed_and_removals_are_not() {
        let original = model(json!([{"name": "a", "x": 1, "parts": [{"name": "p", "y": 1}]}]));
        let added = model(json!([
            {"name": "a", "x": 1, "parts": [{"name": "p", "y": 1}, {"name": "q"}]},
            {"name": "b"},
        ]));
        assert!(sections(&original, &added, SECTIONS, &[]).is_empty());
        let removed = model(json!([{"name": "a", "x": 1, "parts": []}]));
        assert_eq!(
            sections(&original, &removed, SECTIONS, &[]),
            ["removed documented part `a.p`"]
        );
        assert_eq!(
            sections(&original, &model(json!([])), SECTIONS, &[]),
            ["removed documented thing `a`"]
        );
    }

    #[test]
    fn changes_are_allowed_only_where_a_diagnostic_pointed() {
        let original = model(json!([{"name": "a/b", "x": 1, "parts": [{"name": "p", "y": 1}]}]));
        let changed = model(json!([{"name": "a/b", "x": 2, "parts": [{"name": "p", "y": 2}]}]));
        assert_eq!(
            sections(&original, &changed, SECTIONS, &[]),
            [
                "changed thing `a/b`, which had no diagnostics",
                "changed part `a/b.p`, which had no diagnostics",
            ]
        );
        assert_eq!(
            sections(&original, &changed, SECTIONS, &[at("/things/a~1b")]),
            ["changed part `a/b.p`, which had no diagnostics"]
        );
        assert!(sections(&original, &changed, SECTIONS, &[at("/things/a~1b/parts/p")]).is_empty());
        assert!(touched(&[at("/x/y")], "/x"));
        assert!(!touched(&[at("/xy")], "/x"));
    }

    #[test]
    fn listed_values_are_kept_unless_diagnosed() {
        let original = model(json!([]));
        let repaired = json!({"list": ["b", "c"]});
        let label = |value: &Value| format!("dropped {value}");
        assert_eq!(
            kept_values(&original, &repaired, "list", "/list", &[], label),
            ["dropped \"a\""]
        );
        assert!(kept_values(
            &original,
            &repaired,
            "list",
            "/list",
            &[at("/list/a")],
            label
        )
        .is_empty());
    }
}
