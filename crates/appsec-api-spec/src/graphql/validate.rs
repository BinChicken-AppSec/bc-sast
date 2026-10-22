//! Validation of a GraphQL schema document (October 2021 specification,
//! section 3 "Type System" and its validation rules), over the tree
//! [`super::parser`] produces.
//!
//! A schema is often split across files (Spring for GraphQL and gqlgen
//! read every schema file of a directory, and `extend type Query` in a
//! second file is idiomatic), so types, directives and root operation
//! types defined in the standard's other documents (`peers`) count as
//! known. Duplicates are checked within the document only: two services
//! in one repository may each define their own `Query`.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use crate::diagnostic::{escape, Code, Diagnostic};
use crate::format::Peer;

pub(super) const BUILT_IN_SCALARS: [&str; 5] = ["Int", "Float", "String", "Boolean", "ID"];
const BUILT_IN_DIRECTIVES: [&str; 5] = ["skip", "include", "deprecated", "specifiedBy", "oneOf"];
const LOCATIONS: [&str; 19] = [
    "QUERY",
    "MUTATION",
    "SUBSCRIPTION",
    "FIELD",
    "FRAGMENT_DEFINITION",
    "FRAGMENT_SPREAD",
    "INLINE_FRAGMENT",
    "VARIABLE_DEFINITION",
    "SCHEMA",
    "SCALAR",
    "OBJECT",
    "FIELD_DEFINITION",
    "ARGUMENT_DEFINITION",
    "INTERFACE",
    "UNION",
    "ENUM",
    "ENUM_VALUE",
    "INPUT_OBJECT",
    "INPUT_FIELD_DEFINITION",
];

/// Entries of one of the tree's top-level lists.
pub(super) fn entries<'a>(document: &'a Value, list: &str) -> &'a [Value] {
    document
        .get(list)
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

pub(super) fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or_default()
}

pub(super) fn is_extension(value: &Value) -> bool {
    value.get("extension").and_then(Value::as_bool) == Some(true)
}

/// The named type inside a type reference: `[User!]!` names `User`.
pub(super) fn named_type(reference: &str) -> &str {
    reference.trim_matches(|c| matches!(c, '[' | ']' | '!'))
}

pub(super) fn type_pointer(name: &str) -> String {
    format!("/types/{}", escape(name))
}

/// What the document and its peers define.
pub(super) struct Symbols {
    /// Type name to kind, from definitions (built-in scalars included).
    pub kinds: BTreeMap<String, String>,
    /// Type name to every field name its definitions and extensions give.
    pub fields: BTreeMap<String, BTreeSet<String>>,
    pub directives: BTreeSet<String>,
    /// Root operation types named by schema definitions and extensions.
    pub roots: BTreeMap<String, String>,
    /// Whether any schema definition or extension exists.
    pub schema_defined: bool,
}

impl Symbols {
    pub(super) fn of(document: &Value, peers: &[Peer<'_>]) -> Self {
        let mut symbols = Symbols {
            kinds: BUILT_IN_SCALARS
                .iter()
                .map(|name| (name.to_string(), "scalar".to_string()))
                .collect(),
            fields: BTreeMap::new(),
            directives: BUILT_IN_DIRECTIVES.iter().map(|d| d.to_string()).collect(),
            roots: BTreeMap::new(),
            schema_defined: false,
        };
        for source in std::iter::once(document).chain(peers.iter().map(|peer| peer.document)) {
            for entry in entries(source, "types") {
                let name = text(entry, "name").to_string();
                if !is_extension(entry) {
                    symbols
                        .kinds
                        .entry(name.clone())
                        .or_insert_with(|| text(entry, "kind").to_string());
                }
                let names = entries(entry, "fields")
                    .iter()
                    .map(|f| text(f, "name").to_string());
                symbols.fields.entry(name).or_default().extend(names);
            }
            for directive in entries(source, "directives") {
                symbols
                    .directives
                    .insert(text(directive, "name").to_string());
            }
            for schema in entries(source, "schema") {
                symbols.schema_defined = true;
                for operation in entries(schema, "operations") {
                    symbols
                        .roots
                        .entry(text(operation, "operation").to_string())
                        .or_insert_with(|| text(operation, "type").to_string());
                }
            }
        }
        symbols
    }

    /// The root type of `operation`: the schema's, or the default name
    /// when no schema definition exists anywhere.
    pub(super) fn root(&self, operation: &str) -> Option<String> {
        if let Some(root) = self.roots.get(operation) {
            return Some(root.clone());
        }
        (!self.schema_defined).then(|| {
            let mut name = operation.to_string();
            name[..1].make_ascii_uppercase();
            name
        })
    }
}

/// Validate `document` with the other documents of the schema.
pub fn validate(document: &Value, peers: &[Peer<'_>]) -> Vec<Diagnostic> {
    let symbols = Symbols::of(document, peers);
    let mut out = Vec::new();
    definitions(document, &symbols, &mut out);
    schema(document, &symbols, &mut out);
    directive_definitions(document, &symbols, &mut out);
    out
}

fn reserved(name: &str, pointer: &str, out: &mut Vec<Diagnostic>) {
    if name.starts_with("__") {
        out.push(Diagnostic::error(
            Code::ReservedName,
            pointer,
            format!("`{name}` starts with `__`, which introspection reserves"),
        ));
    }
}

fn applied(directives: &Value, pointer: &str, symbols: &Symbols, out: &mut Vec<Diagnostic>) {
    for directive in directives.as_array().into_iter().flatten() {
        let text = directive.as_str().unwrap_or_default();
        let name = text
            .trim_start_matches('@')
            .split('(')
            .next()
            .unwrap_or_default();
        if !symbols.directives.contains(name) {
            out.push(Diagnostic::warning(
                Code::UnknownDirective,
                pointer,
                format!(
                    "directive `@{name}` is not defined here; it may come from a gateway or \
                     federation specification"
                ),
            ));
        }
    }
}

fn definitions(document: &Value, symbols: &Symbols, out: &mut Vec<Diagnostic>) {
    let mut defined = BTreeSet::new();
    // Per type name: members already seen across its definition and
    // extensions in this document.
    let mut seen_fields: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut seen_values: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for entry in entries(document, "types") {
        let name = text(entry, "name");
        let kind = text(entry, "kind");
        let pointer = type_pointer(name);
        reserved(name, &pointer, out);
        if is_extension(entry) {
            match symbols.kinds.get(name) {
                None => out.push(Diagnostic::error(
                    Code::UnknownType,
                    &pointer,
                    format!("extends `{name}`, which is not defined"),
                )),
                Some(defined_kind) if defined_kind != kind => out.push(Diagnostic::error(
                    Code::InvalidExtension,
                    &pointer,
                    format!("extends `{name}` as {kind}, but it is defined as {defined_kind}"),
                )),
                Some(_) => {}
            }
        } else if !defined.insert(name) {
            out.push(Diagnostic::error(
                Code::DuplicateDefinition,
                &pointer,
                format!("type `{name}` is defined more than once"),
            ));
        }
        applied(&entry["directives"], &pointer, symbols, out);
        for interface in entries(entry, "interfaces") {
            let interface = interface.as_str().unwrap_or_default();
            if symbols.kinds.get(interface).map(String::as_str) != Some("interface") {
                out.push(Diagnostic::error(
                    Code::InvalidInterface,
                    &pointer,
                    format!("`{name}` implements `{interface}`, which is not a defined interface"),
                ));
            }
        }
        for member in entries(entry, "members") {
            let member = member.as_str().unwrap_or_default();
            if symbols.kinds.get(member).map(String::as_str) != Some("object") {
                out.push(Diagnostic::error(
                    Code::InvalidUnionMember,
                    &pointer,
                    format!("union member `{member}` is not a defined object type"),
                ));
            }
        }
        let seen = seen_fields.entry(name.to_string()).or_default();
        for field in entries(entry, "fields") {
            let field_name = text(field, "name");
            let field_pointer = format!("{pointer}/fields/{}", escape(field_name));
            if !seen.insert(field_name.to_string()) {
                out.push(Diagnostic::error(
                    Code::DuplicateField,
                    &field_pointer,
                    format!("`{name}.{field_name}` is declared more than once"),
                ));
            }
            member(field, &field_pointer, kind == "input", symbols, out);
            let mut arguments = BTreeSet::new();
            for argument in entries(field, "arguments") {
                let argument_name = text(argument, "name");
                let argument_pointer =
                    format!("{field_pointer}/arguments/{}", escape(argument_name));
                if !arguments.insert(argument_name) {
                    out.push(Diagnostic::error(
                        Code::DuplicateArgument,
                        &argument_pointer,
                        format!("argument `{argument_name}` is declared more than once"),
                    ));
                }
                member(argument, &argument_pointer, true, symbols, out);
            }
        }
        let values = seen_values.entry(name.to_string()).or_default();
        for value in entries(entry, "values") {
            let value_name = text(value, "name");
            let value_pointer = format!("{pointer}/values/{}", escape(value_name));
            if matches!(value_name, "true" | "false" | "null") {
                out.push(Diagnostic::error(
                    Code::ReservedName,
                    &value_pointer,
                    format!("`{value_name}` cannot be an enum value"),
                ));
            }
            if !values.insert(value_name.to_string()) {
                out.push(Diagnostic::error(
                    Code::DuplicateField,
                    &value_pointer,
                    format!("enum value `{name}.{value_name}` is declared more than once"),
                ));
            }
            applied(&value["directives"], &value_pointer, symbols, out);
        }
    }
    completeness(document, symbols, &defined, out);
}

/// A field, argument or input field: a known type of the right kind.
fn member(value: &Value, pointer: &str, input: bool, symbols: &Symbols, out: &mut Vec<Diagnostic>) {
    let name = text(value, "name");
    reserved(name, pointer, out);
    applied(&value["directives"], pointer, symbols, out);
    let named = named_type(text(value, "type"));
    match symbols.kinds.get(named).map(String::as_str) {
        None => out.push(Diagnostic::error(
            Code::UnknownType,
            pointer,
            format!("`{name}` has type `{named}`, which is not defined"),
        )),
        Some("object" | "interface" | "union") if input => out.push(Diagnostic::error(
            Code::InvalidInputType,
            pointer,
            format!("`{name}` is an input, but `{named}` is an output type"),
        )),
        Some("input") if !input => out.push(Diagnostic::error(
            Code::InvalidOutputType,
            pointer,
            format!("`{name}` is an output field, but `{named}` is an input type"),
        )),
        Some(_) => {}
    }
}

/// Rules over a type's definition and all its extensions together.
fn completeness(
    document: &Value,
    symbols: &Symbols,
    defined: &BTreeSet<&str>,
    out: &mut Vec<Diagnostic>,
) {
    for name in defined {
        let pointer = type_pointer(name);
        let own: Vec<&Value> = entries(document, "types")
            .iter()
            .filter(|entry| text(entry, "name") == *name)
            .collect();
        let kind = symbols.kinds[*name].as_str();
        let count = |list: &str| {
            own.iter()
                .map(|entry| entries(entry, list).len())
                .sum::<usize>()
        };
        let fields = symbols.fields.get(*name).map_or(0, BTreeSet::len);
        let empty = match kind {
            "object" | "interface" | "input" => fields == 0,
            "union" => count("members") == 0,
            "enum" => count("values") == 0,
            _ => false,
        };
        if empty {
            out.push(Diagnostic::error(
                Code::EmptyType,
                &pointer,
                format!("{kind} `{name}` must declare at least one member"),
            ));
        }
        let interfaces: BTreeSet<&str> = own
            .iter()
            .flat_map(|entry| entries(entry, "interfaces"))
            .filter_map(Value::as_str)
            // A name that is not an interface is reported where it is used.
            .filter(|interface| {
                symbols.kinds.get(*interface).map(String::as_str) == Some("interface")
            })
            .collect();
        let empty_set = BTreeSet::new();
        let have = symbols.fields.get(*name).unwrap_or(&empty_set);
        for interface in interfaces {
            let required = symbols.fields.get(interface).unwrap_or(&empty_set);
            for field in required.difference(have) {
                out.push(Diagnostic::error(
                    Code::MissingInterfaceField,
                    &pointer,
                    format!("`{name}` implements `{interface}` but has no field `{field}`"),
                ));
            }
        }
    }
}

fn schema(document: &Value, symbols: &Symbols, out: &mut Vec<Diagnostic>) {
    let definitions = entries(document, "schema");
    if definitions
        .iter()
        .filter(|entry| !is_extension(entry))
        .count()
        > 1
    {
        out.push(Diagnostic::error(
            Code::DuplicateDefinition,
            "/schema",
            "the schema is defined more than once",
        ));
    }
    let mut operations = BTreeSet::new();
    for definition in definitions {
        applied(&definition["directives"], "/schema", symbols, out);
        for operation in entries(definition, "operations") {
            let kind = text(operation, "operation");
            let root = text(operation, "type");
            if !operations.insert(kind) {
                out.push(Diagnostic::error(
                    Code::DuplicateField,
                    "/schema",
                    format!("the {kind} root operation type is declared more than once"),
                ));
            }
            if symbols.kinds.get(root).map(String::as_str) != Some("object") {
                out.push(Diagnostic::error(
                    Code::InvalidRootType,
                    "/schema",
                    format!("the {kind} root `{root}` is not a defined object type"),
                ));
            }
        }
    }
    let query = symbols.root("query");
    let known = query
        .as_ref()
        .is_some_and(|root| symbols.kinds.get(root).map(String::as_str) == Some("object"));
    // Without a schema definition a `Query` object type is the root; its
    // absence is reported once, not per missing reference.
    if !known && (symbols.schema_defined || !symbols.kinds.contains_key("Query")) {
        let message = match query {
            Some(root) if symbols.schema_defined => {
                format!("the query root `{root}` is not a defined object type")
            }
            _ if symbols.schema_defined => {
                "the schema definition names no query root operation type".to_string()
            }
            _ => "the schema defines no `Query` type and no schema definition naming a query \
                  root"
                .to_string(),
        };
        out.push(Diagnostic::error(Code::MissingQueryRoot, "", message));
    }
}

fn directive_definitions(document: &Value, symbols: &Symbols, out: &mut Vec<Diagnostic>) {
    let mut defined = BTreeSet::new();
    for directive in entries(document, "directives") {
        let name = text(directive, "name");
        let pointer = format!("/directives/{}", escape(name));
        reserved(name, &pointer, out);
        if !defined.insert(name) || BUILT_IN_DIRECTIVES.contains(&name) {
            out.push(Diagnostic::error(
                Code::DuplicateDefinition,
                &pointer,
                format!("directive `@{name}` is defined more than once"),
            ));
        }
        for argument in entries(directive, "arguments") {
            let argument_pointer =
                format!("{pointer}/arguments/{}", escape(text(argument, "name")));
            member(argument, &argument_pointer, true, symbols, out);
        }
        for location in entries(directive, "locations") {
            let location = location.as_str().unwrap_or_default();
            if !LOCATIONS.contains(&location) {
                out.push(Diagnostic::error(
                    Code::InvalidLocation,
                    &pointer,
                    format!("`{location}` is not a directive location"),
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graphql::parser::parse;

    fn found(text: &str, peers: &[&str]) -> Vec<(Code, String)> {
        let document = parse(text).unwrap();
        let parsed: Vec<Value> = peers.iter().map(|peer| parse(peer).unwrap()).collect();
        let peers: Vec<Peer<'_>> = parsed
            .iter()
            .map(|document| Peer {
                path: "peer.graphqls",
                document,
            })
            .collect();
        validate(&document, &peers)
            .into_iter()
            .map(|diagnostic| (diagnostic.code, diagnostic.pointer))
            .collect()
    }

    fn codes(text: &str) -> Vec<Code> {
        found(text, &[]).into_iter().map(|(code, _)| code).collect()
    }

    const VALID: &str = r#"
schema { query: Query mutation: Mutation }
directive @auth(role: Role = ADMIN) on FIELD_DEFINITION | OBJECT
interface Node { id: ID! }
type User implements Node @auth { id: ID! name: String posts(first: Int): [Post!]! }
type Post implements Node { id: ID! title: String @deprecated(reason: "x") }
union SearchResult = User | Post
enum Role { ADMIN USER }
input NewPost { title: String! role: Role = USER }
scalar DateTime
type Query { me: User search(q: String!): [SearchResult!]! }
type Mutation { post(input: NewPost!): Post @auth(role: USER) }
extend type Query { now: DateTime }
"#;

    #[test]
    fn a_valid_schema_has_no_diagnostics() {
        assert_eq!(found(VALID, &[]), []);
        // Without a schema definition, `Query` is the default root.
        assert_eq!(codes("type Query { a: Int }"), []);
    }

    #[test]
    fn duplicates_are_reported_where_they_occur() {
        let text = "type Query { a: Int a: String b(x: Int, x: Int): Int }\ntype Query { c: Int }\nextend type Query { b: Int }\nenum E { A A }\ndirective @d on FIELD\ndirective @d on FIELD\ndirective @skip on FIELD\nschema { query: Query query: Query }\nschema { query: Query }";
        assert_eq!(
            found(text, &[]),
            [
                (Code::DuplicateField, "/types/Query/fields/a".into()),
                (
                    Code::DuplicateArgument,
                    "/types/Query/fields/b/arguments/x".into()
                ),
                (Code::DuplicateDefinition, "/types/Query".into()),
                (Code::DuplicateField, "/types/Query/fields/b".into()),
                (Code::DuplicateField, "/types/E/values/A".into()),
                (Code::DuplicateDefinition, "/schema".into()),
                // Both schema definitions name a second query root.
                (Code::DuplicateField, "/schema".into()),
                (Code::DuplicateField, "/schema".into()),
                (Code::DuplicateDefinition, "/directives/d".into()),
                (Code::DuplicateDefinition, "/directives/skip".into()),
            ]
        );
    }

    #[test]
    fn references_must_name_types_of_the_right_kind() {
        let text = "type Query { a: Missing b(i: Out): Int c: In u: U }\ntype Out { x: Int }\ninput In { o: Out }\nunion U = In | Out\ntype T implements Out { x: Int }\nextend type Nope { a: Int }\nextend input Out { y: Int }";
        assert_eq!(
            found(text, &[]),
            [
                (Code::UnknownType, "/types/Query/fields/a".into()),
                (
                    Code::InvalidInputType,
                    "/types/Query/fields/b/arguments/i".into()
                ),
                (Code::InvalidOutputType, "/types/Query/fields/c".into()),
                (Code::InvalidInputType, "/types/In/fields/o".into()),
                (Code::InvalidUnionMember, "/types/U".into()),
                (Code::InvalidInterface, "/types/T".into()),
                (Code::UnknownType, "/types/Nope".into()),
                (Code::InvalidExtension, "/types/Out".into()),
            ]
        );
    }

    #[test]
    fn types_need_members_and_objects_need_their_interface_fields() {
        let text = "type Query { a: Int }\ntype Empty\ninterface I { x: Int y: Int }\ntype T implements I { x: Int }\nunion U\nenum E\ninput In\nscalar S";
        assert_eq!(
            found(text, &[]),
            [
                (Code::EmptyType, "/types/E".into()),
                (Code::EmptyType, "/types/Empty".into()),
                (Code::EmptyType, "/types/In".into()),
                (Code::MissingInterfaceField, "/types/T".into()),
                (Code::EmptyType, "/types/U".into()),
            ]
        );
    }

    #[test]
    fn roots_must_exist_as_object_types() {
        assert_eq!(codes("type A { a: Int }"), [Code::MissingQueryRoot]);
        assert_eq!(
            codes("schema { query: Q mutation: M }\ninput Q { a: Int }"),
            [
                Code::InvalidRootType,
                Code::InvalidRootType,
                Code::MissingQueryRoot
            ]
        );
        assert_eq!(
            codes("schema { mutation: M }\ntype M { a: Int }"),
            [Code::MissingQueryRoot]
        );
        assert_eq!(
            codes("extend schema @d\ntype Query { a: Int }"),
            [Code::UnknownDirective, Code::MissingQueryRoot]
        );
        let document = parse("schema { query: Q }\ninput Q { a: Int }").unwrap();
        let message = &validate(&document, &[])[1].message;
        assert!(message.contains("query root `Q`"), "{message}");
    }

    #[test]
    fn peers_contribute_types_directives_and_roots() {
        let peer =
            "type Query { a: Int }\ntype User { id: ID! }\ndirective @auth on FIELD_DEFINITION";
        assert_eq!(found("extend type Query { me: User @auth }", &[peer]), []);
        assert_eq!(
            found(
                "type Other { x: Int }",
                &["schema { query: Root }\ntype Root { a: Int }"]
            ),
            []
        );
        // An interface defined elsewhere still requires its fields here.
        assert_eq!(
            found(
                "type T implements I { a: Int }",
                &["type Query { t: T }\ninterface I { a: Int b: Int }"]
            ),
            [(Code::MissingInterfaceField, "/types/T".into())]
        );
    }

    #[test]
    fn reserved_names_locations_and_unknown_directives_are_reported() {
        let text = "type Query { __a: Int @unknown b: Int }\ntype __T { a: Int }\nenum E { true B @x }\ndirective @__d(__x: Int, y: Query) on FIELD | NOWHERE\nschema @s { query: Query }";
        let found = found(text, &[]);
        let codes: Vec<Code> = found.iter().map(|(code, _)| *code).collect();
        assert_eq!(
            codes,
            [
                Code::ReservedName,
                Code::UnknownDirective,
                Code::ReservedName,
                Code::ReservedName,
                Code::UnknownDirective,
                Code::UnknownDirective,
                Code::ReservedName,
                Code::ReservedName,
                Code::InvalidInputType,
                Code::InvalidLocation,
            ]
        );
    }

    #[test]
    fn helpers_read_odd_shapes_leniently() {
        assert!(entries(&serde_json::json!({}), "types").is_empty());
        assert_eq!(named_type("[[A!]]!"), "A");
        let symbols = Symbols::of(&serde_json::json!({"schema": [{"operations": []}]}), &[]);
        assert_eq!(symbols.root("mutation"), None);
        let symbols = Symbols::of(&serde_json::json!({}), &[]);
        assert_eq!(symbols.root("subscription"), Some("Subscription".into()));
    }
}
