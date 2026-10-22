//! The OData CSDL rules, read from OData CSDL XML and JSON 4.01 (and,
//! where they apply, the earlier Microsoft CSDL of OData 2 and 3).
//!
//! - The version: `Version` (XML) or `$Version` (JSON) is `4.0` or
//!   `4.01`. Versions 2 and 3 are legacy: a warning says so, and the
//!   document is validated and reported but never rewritten.
//! - References: a relative URI must name a CSDL file of the repository.
//!   A URL is never fetched: a warning (none for the OASIS vocabularies
//!   under `Org.OData.`, whose namespaces are well known), and the types
//!   of its included namespaces are not checked.
//! - Schemas have a unique namespace and alias, none of them reserved
//!   (`Edm`, `odata`, `System`, `Transient`).
//! - Names are unique: types, operations and containers within the
//!   document (actions and functions may be overloaded), members within a
//!   type, and children within a container. A document has at most one
//!   entity container, and a JSON `$EntityContainer` names it.
//! - An entity type has a key unless it is abstract or derived; every key
//!   property exists (declared or inherited) and should not be nullable.
//! - Every type reference resolves, through aliases, to a primitive
//!   `Edm` type or a declared type of the right kind: a base type of the
//!   same kind, structural properties of primitive, complex, enum or
//!   type-definition type, navigation properties of an entity type, and
//!   a navigation partner that the target type declares.
//! - Entity sets and singletons reference entity types, navigation
//!   bindings target entity sets or singletons, action and function
//!   imports reference unbound actions and functions, and a function has
//!   a return type and a bound operation a binding parameter.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use super::model::major;
use crate::diagnostic::{escape, Code, Diagnostic};
use crate::format::Peer;
use crate::xml::{is_remote, locate, Location};

/// The primitive types of OData 4.01.
const PRIMITIVES: &[&str] = &[
    "Binary",
    "Boolean",
    "Byte",
    "Date",
    "DateTimeOffset",
    "Decimal",
    "Double",
    "Duration",
    "Guid",
    "Int16",
    "Int32",
    "Int64",
    "SByte",
    "Single",
    "Stream",
    "String",
    "TimeOfDay",
    "Geography",
    "GeographyPoint",
    "GeographyLineString",
    "GeographyPolygon",
    "GeographyMultiPoint",
    "GeographyMultiLineString",
    "GeographyMultiPolygon",
    "GeographyCollection",
    "Geometry",
    "GeometryPoint",
    "GeometryLineString",
    "GeometryPolygon",
    "GeometryMultiPoint",
    "GeometryMultiLineString",
    "GeometryMultiPolygon",
    "GeometryCollection",
    "Untyped",
    "PrimitiveType",
    "ComplexType",
    "EntityType",
    "AnnotationPath",
    "PropertyPath",
    "NavigationPropertyPath",
    "AnyPropertyPath",
    "ModelElementPath",
];
/// Primitive types OData 2 and 3 had and 4 dropped.
const LEGACY_PRIMITIVES: [&str; 2] = ["DateTime", "Time"];
const RESERVED_NAMESPACES: [&str; 4] = ["Edm", "odata", "System", "Transient"];
/// The OASIS vocabularies' namespace prefix.
const VOCABULARIES: &str = "Org.OData.";

pub(super) fn list<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value[key].as_array().map_or(&[], Vec::as_slice)
}

pub(super) fn name(value: &Value) -> &str {
    value["name"].as_str().unwrap_or_default()
}

/// The type a `Collection(...)` wraps, or `text` itself.
fn element_type(text: &str) -> &str {
    text.strip_prefix("Collection(")
        .and_then(|inner| inner.strip_suffix(')'))
        .unwrap_or(text)
}

/// The last segment of a qualified name.
pub(super) fn simple(qualified: &str) -> &str {
    qualified.rsplit('.').next().unwrap_or(qualified)
}

struct Symbols<'a> {
    /// Alias to namespace.
    aliases: BTreeMap<&'a str, &'a str>,
    /// Qualified type name to its entry.
    types: BTreeMap<String, &'a Value>,
    /// Qualified operation name to its entries (an action and a function
    /// may not share a name, but a document may still try).
    operations: BTreeMap<String, Vec<&'a Value>>,
    /// Entity set and singleton names of every container.
    targets: BTreeSet<&'a str>,
    /// Namespaces whose definitions cannot be checked.
    open: BTreeSet<&'a str>,
    legacy: bool,
}

impl<'a> Symbols<'a> {
    fn of(model: &'a Value, peers: &[Peer<'a>]) -> Self {
        let mut symbols = Self {
            aliases: BTreeMap::new(),
            types: BTreeMap::new(),
            operations: BTreeMap::new(),
            targets: BTreeSet::new(),
            open: BTreeSet::new(),
            legacy: major(model).is_some_and(|major| major < 4),
        };
        let sources: Vec<&'a Value> = std::iter::once(model)
            .chain(peers.iter().map(|peer| peer.document))
            .collect();
        for source in &sources {
            for schema in list(source, "schemas") {
                if let (Some(alias), Some(namespace)) =
                    (schema["alias"].as_str(), schema["name"].as_str())
                {
                    symbols.aliases.entry(alias).or_insert(namespace);
                }
            }
        }
        for reference in list(model, "references") {
            let readable = reference["uri"]
                .as_str()
                .is_some_and(|uri| matches!(locate(uri, peers), Location::Local(_)));
            for include in list(reference, "includes") {
                let Some(namespace) = include["namespace"].as_str() else {
                    continue;
                };
                if let Some(alias) = include["alias"].as_str() {
                    symbols.aliases.entry(alias).or_insert(namespace);
                }
                if !readable {
                    symbols.open.insert(namespace);
                }
            }
        }
        for source in sources {
            for entry in list(source, "types") {
                let qualified = symbols.qualify(name(entry));
                symbols.types.entry(qualified).or_insert(entry);
            }
            for entry in list(source, "operations") {
                let qualified = symbols.qualify(name(entry));
                symbols.operations.entry(qualified).or_default().push(entry);
            }
            for container in list(source, "containers") {
                for key in ["entitySets", "singletons"] {
                    symbols
                        .targets
                        .extend(list(container, key).iter().map(name));
                }
            }
        }
        symbols
    }

    /// `name` with an alias qualifier replaced by its namespace.
    fn qualify(&self, qualified: &str) -> String {
        match qualified.rsplit_once('.') {
            Some((qualifier, local)) => match self.aliases.get(qualifier) {
                Some(namespace) => format!("{namespace}.{local}"),
                None => qualified.to_string(),
            },
            None => qualified.to_string(),
        }
    }

    /// Whether `qualified`'s namespace cannot be checked here.
    fn is_open(&self, qualified: &str) -> bool {
        let namespace = qualified
            .rsplit_once('.')
            .map_or("", |(namespace, _)| namespace);
        namespace.starts_with(VOCABULARIES) || self.open.contains(namespace)
    }
}

struct Checker<'a> {
    symbols: Symbols<'a>,
    out: Vec<Diagnostic>,
}

impl Checker<'_> {
    fn error(&mut self, code: Code, pointer: &str, message: String) {
        self.out.push(Diagnostic::error(code, pointer, message));
    }

    fn warning(&mut self, code: Code, pointer: &str, message: String) {
        self.out.push(Diagnostic::warning(code, pointer, message));
    }

    /// Check that `written` resolves to a primitive type or, when it is
    /// not one, a declared type of one of `kinds`. `what` names the use.
    fn type_reference(&mut self, written: &Value, kinds: &[&str], what: &str, pointer: &str) {
        let Some(written) = written.as_str().filter(|text| !text.is_empty()) else {
            self.error(Code::MissingField, pointer, format!("{what} needs a type"));
            return;
        };
        let inner = element_type(written);
        if let Some(primitive) = inner.strip_prefix("Edm.") {
            let known = PRIMITIVES.contains(&primitive)
                || (self.symbols.legacy && LEGACY_PRIMITIVES.contains(&primitive));
            if kinds.contains(&"primitive") && !known {
                self.error(
                    Code::UnknownType,
                    pointer,
                    format!("`{inner}` is not an OData primitive type"),
                );
            } else if !kinds.contains(&"primitive") {
                self.error(
                    Code::InvalidType,
                    pointer,
                    format!("{what} cannot be of the primitive type `{inner}`"),
                );
            }
            return;
        }
        let qualified = self.symbols.qualify(inner);
        if self.symbols.is_open(&qualified) {
            return;
        }
        match self.symbols.types.get(&qualified) {
            None => self.error(
                Code::UnknownType,
                pointer,
                format!("type `{inner}` is not declared in this document or the repository"),
            ),
            Some(entry) if !kinds.contains(&entry["kind"].as_str().unwrap_or_default()) => self
                .error(
                    Code::InvalidType,
                    pointer,
                    format!(
                        "{what} cannot be of type `{inner}`, which is a {}",
                        entry["kind"].as_str().unwrap_or_default()
                    ),
                ),
            Some(_) => {}
        }
    }
}

/// Report entries of `entries` that share a name or have none.
fn unique<'e>(
    names: impl Iterator<Item = &'e str>,
    prefix: &str,
    noun: &str,
    code: Code,
    checker: &mut Checker<'_>,
) {
    let mut seen = BTreeSet::new();
    for entry_name in names {
        let pointer = format!("{prefix}/{}", escape(entry_name));
        if entry_name.is_empty() || entry_name.ends_with('.') {
            checker.error(
                Code::MissingField,
                &pointer,
                format!("a {noun} needs a name"),
            );
        } else if !seen.insert(entry_name) {
            checker.error(
                code,
                &pointer,
                format!("{noun} `{entry_name}` is defined more than once"),
            );
        }
    }
}

/// Validate `model` with the standard's other documents as `peers`.
pub fn validate(model: &Value, peers: &[Peer<'_>]) -> Vec<Diagnostic> {
    let mut checker = Checker {
        symbols: Symbols::of(model, peers),
        out: Vec::new(),
    };
    version(model, &mut checker);
    references(model, peers, &mut checker);
    schemas(model, &mut checker);
    types(model, &mut checker);
    operations(model, &mut checker);
    containers(model, &mut checker);
    checker.out
}

fn version(model: &Value, checker: &mut Checker<'_>) {
    let pointer = "/version";
    match (major(model), model["version"].as_str()) {
        (Some(4), Some("4.0" | "4.01")) => {}
        (Some(4), None) => checker.error(
            Code::MissingVersion,
            pointer,
            "the document needs a CSDL version, 4.0 or 4.01".into(),
        ),
        (Some(4), Some(other)) => checker.error(
            Code::InvalidVersion,
            pointer,
            format!("CSDL version `{other}` is not 4.0 or 4.01"),
        ),
        (major, _) => checker.warning(
            Code::LegacyVersion,
            pointer,
            format!(
                "OData version {} metadata (Microsoft EDMX namespaces) is legacy: it is validated \
                 and reported, never rewritten",
                major.unwrap_or_default()
            ),
        ),
    }
}

fn references(model: &Value, peers: &[Peer<'_>], checker: &mut Checker<'_>) {
    for reference in list(model, "references") {
        let uri = reference["uri"].as_str().unwrap_or_default();
        let pointer = format!("/references/{}", escape(uri));
        let includes = list(reference, "includes");
        if includes
            .iter()
            .any(|include| include["namespace"].is_null())
        {
            checker.error(
                Code::MissingField,
                &pointer,
                "an include needs a namespace".into(),
            );
        }
        let vocabulary = !includes.is_empty()
            && includes.iter().all(|include| {
                include["namespace"]
                    .as_str()
                    .is_some_and(|namespace| namespace.starts_with(VOCABULARIES))
            });
        if uri.is_empty() {
            checker.error(
                Code::MissingField,
                &pointer,
                "a reference needs a URI".into(),
            );
        } else if is_remote(uri) {
            if !vocabulary {
                checker.warning(
                    Code::ExternalRef,
                    &pointer,
                    format!(
                        "`{uri}` is outside the repository and was not fetched; the types it \
                         declares are unverified"
                    ),
                );
            }
        } else if locate(uri, peers) == Location::Missing {
            checker.error(
                Code::UnresolvedRef,
                &pointer,
                format!("`{uri}` was not found among the repository's readable CSDL files"),
            );
        }
    }
}

fn schemas(model: &Value, checker: &mut Checker<'_>) {
    let entries = list(model, "schemas");
    if entries.is_empty() {
        checker.error(
            Code::MissingField,
            "/schemas",
            "the document declares no schema".into(),
        );
    }
    unique(
        entries.iter().map(name),
        "/schemas",
        "schema namespace",
        Code::DuplicateDefinition,
        checker,
    );
    let aliases = entries.iter().filter_map(|schema| schema["alias"].as_str());
    unique(
        aliases,
        "/schemas",
        "schema alias",
        Code::DuplicateDefinition,
        checker,
    );
    for schema in entries {
        for written in [name(schema), schema["alias"].as_str().unwrap_or_default()] {
            if RESERVED_NAMESPACES.contains(&written) {
                checker.error(
                    Code::ReservedName,
                    &format!("/schemas/{}", escape(name(schema))),
                    format!("`{written}` is reserved and cannot name a schema or alias"),
                );
            }
        }
    }
}

/// Every property (own and inherited) of an entity or complex type,
/// following `baseType` at most once per declared type.
fn all_properties<'a>(entry: &'a Value, symbols: &Symbols<'a>) -> Vec<&'a str> {
    let mut names = Vec::new();
    let mut current = Some(entry);
    let mut steps = 0;
    while let Some(entry) = current {
        steps += 1;
        if steps > symbols.types.len() + 1 {
            break;
        }
        names.extend(list(entry, "properties").iter().map(name));
        names.extend(list(entry, "navigation").iter().map(name));
        current = entry["baseType"]
            .as_str()
            .and_then(|base| symbols.types.get(&symbols.qualify(base)).copied());
    }
    names
}

fn types(model: &Value, checker: &mut Checker<'_>) {
    let entries = list(model, "types");
    let names = entries.iter().map(name);
    unique(names, "/types", "type", Code::DuplicateDefinition, checker);
    for entry in entries {
        let pointer = format!("/types/{}", escape(name(entry)));
        let kind = entry["kind"].as_str().unwrap_or_default();
        if let Some(base) = entry["baseType"].as_str() {
            checker.type_reference(&Value::from(base), &[kind], "the base type", &pointer);
        }
        let members = list(entry, "properties")
            .iter()
            .chain(list(entry, "navigation"))
            .chain(list(entry, "members"))
            .map(name);
        unique(members, &pointer, "member", Code::DuplicateField, checker);
        for property in list(entry, "properties") {
            let property_pointer = format!("{pointer}/properties/{}", escape(name(property)));
            checker.type_reference(
                &property["type"],
                &["primitive", "ComplexType", "EnumType", "TypeDefinition"],
                &format!("property `{}`", name(property)),
                &property_pointer,
            );
        }
        if !checker.symbols.legacy {
            navigation(entry, &pointer, checker);
        }
        if kind == "EntityType" {
            key(entry, &pointer, checker);
        }
    }
}

fn navigation(entry: &Value, pointer: &str, checker: &mut Checker<'_>) {
    for navigation in list(entry, "navigation") {
        let navigation_pointer = format!("{pointer}/navigation/{}", escape(name(navigation)));
        checker.type_reference(
            &navigation["type"],
            &["EntityType"],
            &format!("navigation property `{}`", name(navigation)),
            &navigation_pointer,
        );
        let Some(partner) = navigation["partner"].as_str() else {
            continue;
        };
        let target = navigation["type"]
            .as_str()
            .map(|written| checker.symbols.qualify(element_type(written)))
            .and_then(|qualified| checker.symbols.types.get(&qualified).copied());
        let Some(target) = target else {
            continue;
        };
        if !all_properties(target, &checker.symbols).contains(&partner) {
            checker.error(
                Code::UnresolvedRef,
                &navigation_pointer,
                format!(
                    "partner `{partner}` is not a navigation property of `{}`",
                    name(target)
                ),
            );
        }
    }
}

fn key(entry: &Value, pointer: &str, checker: &mut Checker<'_>) {
    let Some(key) = entry["key"].as_array() else {
        if !entry["abstract"].as_bool().unwrap_or_default() && entry["baseType"].is_null() {
            checker.error(
                Code::MissingKey,
                pointer,
                format!(
                    "entity type `{}` needs a key: it is neither abstract nor derived",
                    name(entry)
                ),
            );
        }
        return;
    };
    let declared = all_properties(entry, &checker.symbols);
    for part in key {
        let path = part.as_str().unwrap_or_default();
        let first = path.split('/').next().unwrap_or_default();
        if !declared.contains(&first) {
            checker.error(
                Code::InvalidKey,
                pointer,
                format!(
                    "key property `{path}` is not a property of `{}`",
                    name(entry)
                ),
            );
            continue;
        }
        let nullable = list(entry, "properties")
            .iter()
            .any(|property| name(property) == path && property["nullable"] == true);
        if nullable {
            checker.warning(
                Code::InvalidKey,
                pointer,
                format!("key property `{path}` is nullable; key properties must not be null"),
            );
        }
    }
}

fn operations(model: &Value, checker: &mut Checker<'_>) {
    let mut kinds: BTreeMap<&str, &str> = BTreeMap::new();
    for operation in list(model, "operations") {
        let operation_name = name(operation);
        let pointer = format!("/operations/{}", escape(operation_name));
        let kind = operation["kind"].as_str().unwrap_or_default();
        let clashes = list(model, "types")
            .iter()
            .chain(list(model, "containers"))
            .any(|entry| name(entry) == operation_name);
        if clashes
            || kinds
                .insert(operation_name, kind)
                .is_some_and(|other| other != kind)
        {
            checker.error(
                Code::DuplicateDefinition,
                &pointer,
                format!("`{operation_name}` names more than one kind of definition"),
            );
        }
        for overload in list(operation, "overloads") {
            let bound = overload["bound"].as_bool().unwrap_or_default();
            let parameters = list(overload, "parameters");
            if bound && parameters.is_empty() {
                checker.error(
                    Code::MissingField,
                    &pointer,
                    format!("bound {kind} `{operation_name}` needs a binding parameter"),
                );
            }
            for parameter in parameters {
                checker.type_reference(
                    &parameter["type"],
                    &[
                        "primitive",
                        "EntityType",
                        "ComplexType",
                        "EnumType",
                        "TypeDefinition",
                    ],
                    &format!("parameter `{}`", name(parameter)),
                    &pointer,
                );
            }
            match &overload["returnType"] {
                Value::Null if kind == "Function" => checker.error(
                    Code::MissingField,
                    &pointer,
                    format!("function `{operation_name}` needs a return type"),
                ),
                Value::Null => {}
                returned => checker.type_reference(
                    returned,
                    &[
                        "primitive",
                        "EntityType",
                        "ComplexType",
                        "EnumType",
                        "TypeDefinition",
                    ],
                    "the return type",
                    &pointer,
                ),
            }
        }
    }
}

fn containers(model: &Value, checker: &mut Checker<'_>) {
    let entries = list(model, "containers");
    if entries.len() > 1 {
        checker.error(
            Code::DuplicateDefinition,
            "/containers",
            "a CSDL document declares at most one entity container".into(),
        );
    }
    if let Some(declared) = model["entityContainer"].as_str() {
        let qualified = checker.symbols.qualify(declared);
        let found = entries
            .iter()
            .any(|container| checker.symbols.qualify(name(container)) == qualified);
        if !found {
            checker.error(
                Code::UnresolvedRef,
                "/entityContainer",
                format!("$EntityContainer `{declared}` names no entity container of the document"),
            );
        }
    }
    for container in entries {
        let pointer = format!("/containers/{}", escape(name(container)));
        let children = [
            "entitySets",
            "singletons",
            "actionImports",
            "functionImports",
        ]
        .into_iter()
        .flat_map(|key| list(container, key))
        .map(name);
        unique(
            children,
            &pointer,
            "container child",
            Code::DuplicateDefinition,
            checker,
        );
        let sets: Vec<&str> = list(container, "entitySets").iter().map(name).collect();
        for (key, field) in [("entitySets", "entityType"), ("singletons", "type")] {
            for child in list(container, key) {
                let child_pointer = format!("{pointer}/{key}/{}", escape(name(child)));
                checker.type_reference(
                    &child[field],
                    &["EntityType"],
                    &format!("`{}`", name(child)),
                    &child_pointer,
                );
                for binding in list(child, "bindings") {
                    let target = binding["target"].as_str().unwrap_or_default();
                    let last = target.rsplit('/').next().unwrap_or_default();
                    if !checker.symbols.targets.contains(last) {
                        checker.error(
                            Code::UnresolvedRef,
                            &child_pointer,
                            format!(
                                "navigation binding target `{target}` is not an entity set or \
                                 singleton"
                            ),
                        );
                    }
                }
            }
        }
        for (key, field, kind) in [
            ("actionImports", "action", "Action"),
            ("functionImports", "function", "Function"),
        ] {
            for import in list(container, key) {
                let import_pointer = format!("{pointer}/{key}/{}", escape(name(import)));
                import_checks(import, field, kind, &sets, &import_pointer, checker);
            }
        }
    }
}

fn import_checks(
    import: &Value,
    field: &str,
    kind: &str,
    sets: &[&str],
    pointer: &str,
    checker: &mut Checker<'_>,
) {
    if let Some(set) = import["entitySet"].as_str() {
        if !sets.contains(&simple_path(set)) {
            checker.error(
                Code::UnresolvedRef,
                pointer,
                format!("entity set `{set}` is not an entity set of the container"),
            );
        }
    }
    // A legacy function import names no function: it is the operation.
    let Some(target) = import[field].as_str() else {
        return;
    };
    let qualified = checker.symbols.qualify(target);
    if checker.symbols.is_open(&qualified) {
        return;
    }
    let unbound = checker
        .symbols
        .operations
        .get(&qualified)
        .into_iter()
        .flatten()
        .filter(|operation| operation["kind"] == kind)
        .flat_map(|operation| list(operation, "overloads"))
        .any(|overload| overload["bound"] != true);
    if !unbound {
        checker.error(
            Code::UnresolvedRef,
            pointer,
            format!(
                "`{target}` names no unbound {} in this document or the repository",
                kind.to_ascii_lowercase()
            ),
        );
    }
}

/// The last segment of a target path (`Container/Set` or `Set`).
fn simple_path(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}
