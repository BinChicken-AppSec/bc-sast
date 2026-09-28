//! Checking that a repair kept what the author's schema documented.
//!
//! A repair may fix what a diagnostic points at and add types, fields,
//! enum values and union members. It may not remove a documented type,
//! field or directive definition, or change one that had no diagnostics.
//! A type's definition and its extensions in the document are compared
//! together, so moving a field between them is not a change.

use std::collections::BTreeMap;

use serde_json::Value;

use super::validate::{entries, text, type_pointer};
use crate::diagnostic::{escape, Diagnostic};

/// Every entry (definition and extensions) of each type, by name.
fn by_name(document: &Value) -> BTreeMap<&str, Vec<&Value>> {
    let mut types: BTreeMap<&str, Vec<&Value>> = BTreeMap::new();
    for entry in entries(document, "types") {
        types.entry(text(entry, "name")).or_default().push(entry);
    }
    types
}

/// The first member called `name` in `list` across `entries`.
fn member<'a>(entries: &[&'a Value], list: &str, name: &str) -> Option<&'a Value> {
    entries
        .iter()
        .flat_map(|entry| super::validate::entries(entry, list))
        .find(|member| text(member, "name") == name)
}

/// Every value of `key` across `entries`, flattened.
fn all<'a>(entries: &[&'a Value], key: &str) -> Vec<&'a Value> {
    entries
        .iter()
        .flat_map(|entry| match &entry[key] {
            Value::Array(items) => items.iter().collect(),
            Value::Null => Vec::new(),
            other => vec![other],
        })
        .collect()
}

/// Every way `repaired` fails to preserve `original`, given the
/// diagnostics `original` had before the repair.
pub fn violations(original: &Value, repaired: &Value, before: &[Diagnostic]) -> Vec<String> {
    let touched = |pointer: &str| {
        before.iter().any(|diagnostic| {
            diagnostic.pointer == pointer || diagnostic.pointer.starts_with(&format!("{pointer}/"))
        })
    };
    let mut out = Vec::new();
    let after = by_name(repaired);
    for (name, entries) in by_name(original) {
        let Some(later) = after.get(name) else {
            out.push(format!("removed documented type `{name}`"));
            continue;
        };
        let pointer = type_pointer(name);
        // Type-level content: every earlier value is still there.
        let kept = [
            "kind",
            "description",
            "directives",
            "interfaces",
            "members",
            "values",
        ]
        .iter()
        .all(|key| {
            let now = all(later, key);
            all(&entries, key).iter().all(|value| now.contains(value))
        });
        if !kept && !touched(&pointer) {
            out.push(format!(
                "changed `{name}` (its kind, description, directives, interfaces, members or \
                 values), which had no diagnostics"
            ));
        }
        for field in entries
            .iter()
            .flat_map(|entry| super::validate::entries(entry, "fields"))
        {
            let field_name = text(field, "name");
            let field_pointer = format!("{pointer}/fields/{}", escape(field_name));
            match member(later, "fields", field_name) {
                None => out.push(format!("removed documented field `{name}.{field_name}`")),
                Some(now) if now != field && !touched(&field_pointer) => out.push(format!(
                    "changed field `{name}.{field_name}`, which had no diagnostics"
                )),
                Some(_) => {}
            }
        }
    }
    let schema_now = super::validate::entries(repaired, "schema");
    let schema_kept = super::validate::entries(original, "schema")
        .iter()
        .all(|definition| schema_now.contains(definition));
    if !schema_kept && !touched("/schema") {
        out.push("changed or removed the schema definition, which had no diagnostics".into());
    }
    let directives_now = super::validate::entries(repaired, "directives");
    for directive in super::validate::entries(original, "directives") {
        let name = text(directive, "name");
        let now = directives_now
            .iter()
            .find(|later| text(later, "name") == name);
        let pointer = format!("/directives/{}", escape(name));
        match now {
            None => out.push(format!("removed documented directive `@{name}`")),
            Some(now) if now != directive && !touched(&pointer) => out.push(format!(
                "changed directive `@{name}`, which had no diagnostics"
            )),
            Some(_) => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnostic::Code;
    use crate::graphql::parser::parse;

    const ORIGINAL: &str = "schema { query: Query }\n\"Users\" type User { id: ID! name: String }\nextend type User { email: String }\nenum Role { A }\ntype Query { me: User }\ndirective @auth on FIELD_DEFINITION";

    fn check(repaired: &str, before: &[&str]) -> Vec<String> {
        let before: Vec<Diagnostic> = before
            .iter()
            .map(|pointer| Diagnostic::error(Code::UnknownType, *pointer, ""))
            .collect();
        violations(
            &parse(ORIGINAL).unwrap(),
            &parse(repaired).unwrap(),
            &before,
        )
    }

    #[test]
    fn additions_and_moves_between_extensions_are_allowed() {
        let repaired = "schema { query: Query }\n\"Users\" type User { id: ID! name: String email: String }\ntype Post { id: ID! }\nenum Role { A B }\ntype Query { me: User post: Post }\ndirective @auth on FIELD_DEFINITION";
        assert_eq!(check(repaired, &[]), Vec::<String>::new());
    }

    #[test]
    fn removals_and_untouched_changes_are_violations() {
        let repaired = "schema { query: Query mutation: Query }\ntype User { id: ID name: String }\nenum Role { B }\ndirective @auth on FIELD";
        assert_eq!(
            check(repaired, &[]),
            [
                "removed documented type `Query`",
                "changed `Role` (its kind, description, directives, interfaces, members or values), which had no diagnostics",
                "changed `User` (its kind, description, directives, interfaces, members or values), which had no diagnostics",
                "changed field `User.id`, which had no diagnostics",
                "removed documented field `User.email`",
                "changed or removed the schema definition, which had no diagnostics",
                "changed directive `@auth`, which had no diagnostics",
            ]
        );
        assert_eq!(
            check("type Query { me: User }", &[]).last().unwrap(),
            "removed documented directive `@auth`"
        );
    }

    #[test]
    fn diagnosed_parts_may_change() {
        let repaired = "schema { query: Query }\ntype User { id: ID name: String email: String }\nenum Role { A }\ntype Query { me: User }\ndirective @auth on FIELD";
        assert_eq!(
            check(
                repaired,
                &["/types/User", "/types/User/fields/id", "/directives/auth"]
            ),
            Vec::<String>::new()
        );
    }
}
