//! The WSDL rules, read from WSDL 1.1 (with its SOAP 1.1, SOAP 1.2 and
//! HTTP bindings), WSDL 2.0 and the WS-I Basic Profile.
//!
//! - WSDL 2.0 requires a `targetNamespace`; its absence in WSDL 1.1 is a
//!   warning, since the definitions then live in no namespace.
//! - Imports (`wsdl:import`, `wsdl:include`, `xsd:import`, `xsd:include`)
//!   must name a file of the repository. A URL or absolute path is never
//!   fetched: it is a warning that what it declares is unverified, and
//!   references into its namespace are not checked. A relative location
//!   no readable file matches is an error.
//! - Names are unique per kind: messages, port types or interfaces,
//!   bindings, services, and within them parts, operations and ports.
//!   Overloaded WSDL 1.1 operations are legal but a warning, since the
//!   Basic Profile forbids them.
//! - A message part names exactly one of an element and a type, which
//!   must be declared by a schema of the document or the repository, or
//!   be an XML Schema built-in type.
//! - Operations name existing messages (1.1) or schema elements (2.0);
//!   WSDL 2.0 fault references name faults of the interface.
//! - A binding references an existing port type or interface and binds
//!   only its operations. A WSDL 1.1 binding declares a SOAP 1.1, SOAP 1.2
//!   or HTTP binding; a SOAP binding has a transport, a `document` or
//!   `rpc` style (a warning when none is given, since `document` is then
//!   assumed), and `use="encoded"` is a warning. A WSDL 2.0 binding has a
//!   `type`, and a SOAP one a `wsoap:protocol`.
//! - Every port or endpoint references an existing binding; a WSDL 1.1
//!   port has an address; an address carries no credentials; a WSDL 2.0
//!   endpoint's binding is for its service's interface.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use super::model::{is_xsd, SOAP_ENCODING, WSOAP};
use crate::diagnostic::{escape, Code, Diagnostic};
use crate::format::Peer;
use crate::tree_checks::embeds_credentials;
use crate::xml::{describe, expanded, locate, Location};

/// The primitive and derived types XML Schema 1.1 builds in.
const BUILT_IN_TYPES: &[&str] = &[
    "anyType",
    "anySimpleType",
    "anyAtomicType",
    "string",
    "boolean",
    "decimal",
    "float",
    "double",
    "duration",
    "dateTime",
    "time",
    "date",
    "gYearMonth",
    "gYear",
    "gMonthDay",
    "gDay",
    "gMonth",
    "hexBinary",
    "base64Binary",
    "anyURI",
    "QName",
    "NOTATION",
    "normalizedString",
    "token",
    "language",
    "NMTOKEN",
    "NMTOKENS",
    "Name",
    "NCName",
    "ID",
    "IDREF",
    "IDREFS",
    "ENTITY",
    "ENTITIES",
    "integer",
    "nonPositiveInteger",
    "negativeInteger",
    "long",
    "int",
    "short",
    "byte",
    "nonNegativeInteger",
    "unsignedLong",
    "unsignedInt",
    "unsignedShort",
    "unsignedByte",
    "positiveInteger",
    "dateTimeStamp",
    "yearMonthDuration",
    "dayTimeDuration",
];

/// Namespaces nobody declares with a schema of their own.
const KNOWN_NAMESPACES: [&str; 2] = ["http://www.w3.org/XML/1998/namespace", SOAP_ENCODING];

pub(super) fn list<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value[key].as_array().map_or(&[], Vec::as_slice)
}

pub(super) fn name(value: &Value) -> &str {
    value["name"].as_str().unwrap_or_default()
}

/// Pointer segments and nouns, which differ between the versions.
pub(super) struct Nouns {
    pub interfaces: &'static str,
    pub interface: &'static str,
    pub endpoints: &'static str,
    pub endpoint: &'static str,
    pub interface_attribute: &'static str,
}

pub(super) fn nouns(model: &Value) -> Nouns {
    if model["version"] == "2.0" {
        Nouns {
            interfaces: "interfaces",
            interface: "interface",
            endpoints: "endpoints",
            endpoint: "endpoint",
            interface_attribute: "interface",
        }
    } else {
        Nouns {
            interfaces: "portTypes",
            interface: "portType",
            endpoints: "ports",
            endpoint: "port",
            interface_attribute: "type",
        }
    }
}

type Key<'a> = (&'static str, Option<&'a str>, &'a str);

/// What the document and its peers declare.
struct Symbols<'a> {
    /// WSDL components by kind (`message`, `interface`, `binding`), target
    /// namespace and name.
    components: BTreeMap<Key<'a>, &'a Value>,
    /// Schema declarations by kind (`element`, `type`), target namespace
    /// and name.
    declarations: BTreeSet<Key<'a>>,
    /// Target namespaces some schema declares.
    schema_namespaces: BTreeSet<Option<&'a str>>,
    /// Namespaces imported from somewhere that could not be read, whose
    /// definitions are therefore not checked.
    open: BTreeSet<Option<&'a str>>,
}

impl<'a> Symbols<'a> {
    fn of(model: &'a Value, peers: &[Peer<'a>]) -> Self {
        let mut symbols = Self {
            components: BTreeMap::new(),
            declarations: BTreeSet::new(),
            schema_namespaces: BTreeSet::new(),
            open: BTreeSet::new(),
        };
        let sources: Vec<&'a Value> = std::iter::once(model)
            .chain(peers.iter().map(|peer| peer.document))
            .collect();
        for source in &sources {
            for schema in list(source, "schemas") {
                symbols
                    .schema_namespaces
                    .insert(schema["targetNamespace"].as_str());
            }
        }
        // An import makes its namespace unverifiable when what it names
        // could not be read here: a location outside the repository or not
        // found in it, or no location for a namespace no schema declares.
        let unreadable =
            |import: &Value, declared: &BTreeSet<Option<&str>>| match import["location"].as_str() {
                Some(location) => !matches!(locate(location, peers), Location::Local(_)),
                None => !declared.contains(&import["namespace"].as_str()),
            };
        for source in sources {
            let namespace = source["targetNamespace"].as_str();
            for (key, kind) in [
                ("messages", "message"),
                ("interfaces", "interface"),
                ("bindings", "binding"),
            ] {
                for entry in list(source, key) {
                    symbols
                        .components
                        .entry((kind, namespace, name(entry)))
                        .or_insert(entry);
                }
            }
            let imports = list(source, "imports").iter().chain(
                list(source, "schemas")
                    .iter()
                    .flat_map(|s| list(s, "imports")),
            );
            for import in imports {
                if unreadable(import, &symbols.schema_namespaces) {
                    symbols.open.insert(import["namespace"].as_str());
                }
            }
            for schema in list(source, "schemas") {
                let schema_namespace = schema["targetNamespace"].as_str();
                for (key, kind) in [("elements", "element"), ("types", "type")] {
                    for declared in list(schema, key) {
                        let declared = declared.as_str().unwrap_or_default();
                        symbols
                            .declarations
                            .insert((kind, schema_namespace, declared));
                    }
                }
            }
        }
        symbols
    }

    /// Whether a schema declares `kind` `local` in `namespace`, or it is
    /// built in. A schema with no target namespace may be included into
    /// any namespace (a chameleon include), so its declarations match any.
    fn declared(&self, kind: &'static str, namespace: Option<&str>, local: &str) -> bool {
        if is_xsd(namespace) {
            return kind == "type" && BUILT_IN_TYPES.contains(&local);
        }
        namespace == Some(SOAP_ENCODING)
            || self.declarations.contains(&(kind, namespace, local))
            || self.declarations.contains(&(kind, None, local))
    }

    fn component(&self, kind: &'static str, reference: &Value) -> Option<&'a Value> {
        let (namespace, local) = expanded(reference)?;
        self.components.get(&(kind, namespace, local)).copied()
    }
}

struct Checker<'a, 'b> {
    symbols: Symbols<'a>,
    peers: &'b [Peer<'a>],
    nouns: Nouns,
    wsdl20: bool,
    out: Vec<Diagnostic>,
}

impl<'a> Checker<'a, '_> {
    fn error(&mut self, code: Code, pointer: &str, message: String) {
        self.out.push(Diagnostic::error(code, pointer, message));
    }

    fn warning(&mut self, code: Code, pointer: &str, message: String) {
        self.out.push(Diagnostic::warning(code, pointer, message));
    }

    /// Report a reference that is missing or not a declared qualified
    /// name. `Some` with its parts when it is one.
    fn qualified<'r>(
        &mut self,
        reference: &'r Value,
        pointer: &str,
    ) -> Option<(Option<&'r str>, &'r str)> {
        let parts = expanded(reference);
        if reference.is_null() {
            self.error(
                Code::MissingField,
                pointer,
                "a required qualified-name reference is missing".into(),
            );
        } else if parts.is_none() {
            self.error(
                Code::UnresolvedRef,
                pointer,
                format!(
                    "`{}` is not a qualified name whose prefix is declared",
                    describe(reference)
                ),
            );
        }
        parts
    }

    /// Check a reference to a schema element or type.
    fn schema_reference(&mut self, kind: &'static str, reference: &Value, pointer: &str) {
        let Some((namespace, local)) = self.qualified(reference, pointer) else {
            return;
        };
        if !self.symbols.declared(kind, namespace, local) && !self.symbols.open.contains(&namespace)
        {
            self.error(
                Code::UnknownType,
                pointer,
                format!(
                    "{kind} `{}` is not declared by any schema of this document or the \
                     repository, and is not an XML Schema built-in",
                    describe(reference)
                ),
            );
        }
    }

    /// Check a reference to a WSDL component, returning it when found.
    fn component_reference(
        &mut self,
        kind: &'static str,
        noun: &str,
        reference: &Value,
        pointer: &str,
    ) -> Option<&'a Value> {
        let (namespace, _) = self.qualified(reference, pointer)?;
        let found = self.symbols.component(kind, reference);
        if found.is_none() && !self.symbols.open.contains(&namespace) {
            self.error(
                Code::UnresolvedRef,
                pointer,
                format!(
                    "`{}` names no {noun} in this document or the repository's other WSDL files",
                    describe(reference)
                ),
            );
        }
        found
    }

    fn import(&mut self, import: &Value, pointer: &str, schema_level: bool) {
        let namespace = import["namespace"].as_str();
        match import["location"].as_str() {
            Some(location) => match locate(location, self.peers) {
                Location::Local(_) => {}
                Location::Remote => self.warning(
                    Code::ExternalRef,
                    pointer,
                    format!(
                        "`{location}` is outside the repository and was not fetched; what it \
                         declares is unverified"
                    ),
                ),
                Location::Missing => self.error(
                    Code::UnresolvedRef,
                    pointer,
                    format!(
                        "`{location}` was not found among the repository's readable WSDL and \
                         XML Schema files"
                    ),
                ),
            },
            None if !schema_level => self.error(
                Code::MissingField,
                pointer,
                "a WSDL import needs a location".into(),
            ),
            None => {
                let known = namespace.is_some_and(|namespace| {
                    is_xsd(Some(namespace)) || KNOWN_NAMESPACES.contains(&namespace)
                });
                if !known && !self.symbols.schema_namespaces.contains(&namespace) {
                    self.warning(
                        Code::UnresolvedRef,
                        pointer,
                        format!(
                            "namespace `{}` is imported without a schemaLocation, and no schema \
                             of this document or the repository declares it",
                            namespace.unwrap_or_default()
                        ),
                    );
                }
            }
        }
    }

    /// Report entries of `entries` that share a name or have none.
    fn unique(&mut self, entries: &[Value], prefix: &str, noun: &str, severity_error: bool) {
        let mut seen = BTreeSet::new();
        for entry in entries {
            let entry_name = name(entry);
            let pointer = format!("{prefix}/{}", escape(entry_name));
            if entry_name.is_empty() {
                self.error(
                    Code::MissingField,
                    &pointer,
                    format!("a {noun} needs a name"),
                );
            } else if !seen.insert(entry_name) {
                let message = format!("{noun} `{entry_name}` is defined more than once");
                if severity_error {
                    self.error(Code::DuplicateDefinition, &pointer, message);
                } else {
                    self.warning(
                        Code::DuplicateDefinition,
                        &pointer,
                        format!("{message}; the WS-I Basic Profile forbids overloading"),
                    );
                }
            }
        }
    }
}

/// Validate `model` with the standard's other documents as `peers`.
pub fn validate(model: &Value, peers: &[Peer<'_>]) -> Vec<Diagnostic> {
    let mut checker = Checker {
        symbols: Symbols::of(model, peers),
        peers,
        nouns: nouns(model),
        wsdl20: model["version"] == "2.0",
        out: Vec::new(),
    };
    header(model, &mut checker);
    messages(model, &mut checker);
    interfaces(model, &mut checker);
    bindings(model, &mut checker);
    services(model, &mut checker);
    checker.out
}

fn header(model: &Value, checker: &mut Checker<'_, '_>) {
    if model["kind"] == "wsdl" && model["targetNamespace"].is_null() {
        let pointer = "/targetNamespace";
        if checker.wsdl20 {
            checker.error(
                Code::MissingField,
                pointer,
                "a WSDL 2.0 description needs a targetNamespace".into(),
            );
        } else {
            checker.warning(
                Code::MissingField,
                pointer,
                "without a targetNamespace the definitions are in no namespace, which toolkits \
                 handle inconsistently"
                    .into(),
            );
        }
    }
    for import in list(model, "imports") {
        let at = import["location"]
            .as_str()
            .or(import["namespace"].as_str())
            .unwrap_or_default();
        checker.import(import, &format!("/imports/{}", escape(at)), false);
    }
    for (index, schema) in list(model, "schemas").iter().enumerate() {
        for import in list(schema, "imports") {
            let at = import["location"]
                .as_str()
                .or(import["namespace"].as_str())
                .unwrap_or_default();
            let pointer = format!("/schemas/{index}/imports/{}", escape(at));
            checker.import(import, &pointer, true);
        }
    }
    if model["kind"] == "wsdl" && list(model, "interfaces").is_empty() {
        let noun = checker.nouns.interface;
        checker.warning(
            Code::EmptyType,
            &format!("/{}", checker.nouns.interfaces),
            format!("the description declares no {noun}, so it describes no operation"),
        );
    }
}

fn messages(model: &Value, checker: &mut Checker<'_, '_>) {
    let entries = list(model, "messages");
    checker.unique(entries, "/messages", "message", true);
    for message in entries {
        let pointer = format!("/messages/{}", escape(name(message)));
        let parts = list(message, "parts");
        checker.unique(parts, &format!("{pointer}/parts"), "part", true);
        for part in parts {
            let part_pointer = format!("{pointer}/parts/{}", escape(name(part)));
            match (&part["element"], &part["type"]) {
                (Value::Null, Value::Null) => checker.error(
                    Code::MissingField,
                    &part_pointer,
                    format!("part `{}` needs an element or a type", name(part)),
                ),
                (Value::Null, reference) => {
                    checker.schema_reference("type", reference, &part_pointer)
                }
                (reference, Value::Null) => {
                    checker.schema_reference("element", reference, &part_pointer)
                }
                _ => checker.error(
                    Code::InvalidType,
                    &part_pointer,
                    format!("part `{}` names both an element and a type", name(part)),
                ),
            }
        }
    }
}

/// Every operation and fault name `interface` has, with those of the
/// interfaces it extends (one level of `extends` per step, bounded by the
/// number of interfaces so a cycle cannot loop).
fn members<'a>(interface: &'a Value, symbols: &Symbols<'a>) -> (Vec<&'a str>, Vec<&'a str>) {
    let mut operations = Vec::new();
    let mut faults = Vec::new();
    let mut pending = vec![interface];
    let mut visited = 0;
    while let Some(current) = pending.pop() {
        visited += 1;
        if visited > symbols.components.len() + 1 {
            break;
        }
        operations.extend(list(current, "operations").iter().map(name));
        faults.extend(list(current, "faults").iter().map(name));
        pending.extend(
            list(current, "extends")
                .iter()
                .filter_map(|reference| symbols.component("interface", reference)),
        );
    }
    (operations, faults)
}

fn interfaces(model: &Value, checker: &mut Checker<'_, '_>) {
    let segment = checker.nouns.interfaces;
    let noun = checker.nouns.interface;
    let entries = list(model, "interfaces");
    checker.unique(entries, &format!("/{segment}"), noun, true);
    for interface in entries {
        let pointer = format!("/{segment}/{}", escape(name(interface)));
        for reference in list(interface, "extends") {
            checker.component_reference("interface", "interface", reference, &pointer);
        }
        for fault in list(interface, "faults") {
            let fault_pointer = format!("{pointer}/faults/{}", escape(name(fault)));
            message_reference(&fault["message"], &fault_pointer, checker);
        }
        let operations = list(interface, "operations");
        let wsdl20 = checker.wsdl20;
        checker.unique(
            operations,
            &format!("{pointer}/operations"),
            "operation",
            wsdl20,
        );
        let (_, faults) = members(interface, &checker.symbols);
        for operation in operations {
            let op_pointer = format!("{pointer}/operations/{}", escape(name(operation)));
            if operation["input"].is_null() && operation["output"].is_null() {
                checker.error(
                    Code::MissingField,
                    &op_pointer,
                    format!(
                        "operation `{}` has neither an input nor an output",
                        name(operation)
                    ),
                );
            }
            for io in [&operation["input"], &operation["output"]] {
                message_reference(io, &op_pointer, checker);
            }
            for fault in list(operation, "faults") {
                if !checker.wsdl20 {
                    message_reference(fault, &op_pointer, checker);
                    continue;
                }
                let Some((_, local)) = checker.qualified(&fault["ref"], &op_pointer) else {
                    continue;
                };
                if !faults.contains(&local) {
                    checker.error(
                        Code::UnresolvedRef,
                        &op_pointer,
                        format!(
                            "fault reference `{local}` names no fault of interface `{}`",
                            name(interface)
                        ),
                    );
                }
            }
        }
    }
}

/// An operation's input, output or fault: a message (WSDL 1.1), a schema
/// element or a token (WSDL 2.0), or nothing.
fn message_reference(io: &Value, pointer: &str, checker: &mut Checker<'_, '_>) {
    if let Some(message) = io.get("message") {
        checker.component_reference("message", "message", message, pointer);
    } else if let Some(element) = io.get("element") {
        checker.schema_reference("element", element, pointer);
    }
}

fn bindings(model: &Value, checker: &mut Checker<'_, '_>) {
    let entries = list(model, "bindings");
    checker.unique(entries, "/bindings", "binding", true);
    for binding in entries {
        let pointer = format!("/bindings/{}", escape(name(binding)));
        let interface = match &binding["interface"] {
            Value::Null => {
                let attribute = checker.nouns.interface_attribute;
                checker.error(
                    Code::MissingField,
                    &pointer,
                    format!(
                        "binding `{}` needs a `{attribute}` attribute",
                        name(binding)
                    ),
                );
                None
            }
            reference => {
                let noun = checker.nouns.interface;
                checker.component_reference("interface", noun, reference, &pointer)
            }
        };
        if checker.wsdl20 {
            binding20(binding, &pointer, checker);
        } else {
            binding11(binding, &pointer, checker);
        }
        let operations = list(binding, "operations");
        let wsdl20 = checker.wsdl20;
        checker.unique(
            operations,
            &format!("{pointer}/operations"),
            "binding operation",
            wsdl20,
        );
        let Some(interface) = interface else {
            continue;
        };
        let (known, _) = members(interface, &checker.symbols);
        for operation in operations {
            let op_name = name(operation);
            let op_pointer = format!("{pointer}/operations/{}", escape(op_name));
            // A nameless operation was reported above, and an unresolved
            // reference names nothing to look up.
            if op_name.is_empty()
                || (checker.wsdl20 && checker.qualified(&operation["ref"], &op_pointer).is_none())
            {
                continue;
            }
            if !known.contains(&op_name) {
                checker.error(
                    Code::UnresolvedRef,
                    &op_pointer,
                    format!(
                        "`{}` is not an operation of {} `{}`",
                        name(operation),
                        checker.nouns.interface,
                        name(interface)
                    ),
                );
            }
        }
        let bound: BTreeSet<&str> = operations.iter().map(name).collect();
        let declared: BTreeSet<&str> = list(interface, "operations").iter().map(name).collect();
        for unbound in declared {
            if !bound.contains(unbound) {
                checker.warning(
                    Code::MissingField,
                    &pointer,
                    format!(
                        "operation `{unbound}` of {} `{}` is not bound",
                        checker.nouns.interface,
                        name(interface)
                    ),
                );
            }
        }
    }
}

fn binding11(binding: &Value, pointer: &str, checker: &mut Checker<'_, '_>) {
    let binding_name = name(binding);
    match binding["protocol"].as_str() {
        None => checker.error(
            Code::InvalidBinding,
            pointer,
            format!("binding `{binding_name}` declares no SOAP 1.1, SOAP 1.2 or HTTP binding"),
        ),
        Some("http") => {
            if binding["verb"].is_null() {
                checker.error(
                    Code::InvalidBinding,
                    pointer,
                    format!("HTTP binding `{binding_name}` needs a verb"),
                );
            }
        }
        Some(_) => soap_binding(binding, pointer, checker),
    }
}

fn soap_binding(binding: &Value, pointer: &str, checker: &mut Checker<'_, '_>) {
    let binding_name = name(binding);
    if binding["transport"].is_null() {
        checker.error(
            Code::InvalidBinding,
            pointer,
            format!("SOAP binding `{binding_name}` needs a transport"),
        );
    }
    let operations = list(binding, "operations");
    let styles = std::iter::once(&binding["style"])
        .chain(operations.iter().map(|operation| &operation["style"]));
    for style in styles.filter_map(Value::as_str) {
        if !matches!(style, "document" | "rpc") {
            checker.error(
                Code::InvalidBinding,
                pointer,
                format!("style `{style}` is neither document nor rpc"),
            );
        }
    }
    if binding["style"].is_null()
        && operations
            .iter()
            .any(|operation| operation["style"].is_null())
    {
        checker.warning(
            Code::InvalidBinding,
            pointer,
            format!("SOAP binding `{binding_name}` gives no style, so document is assumed"),
        );
    }
    let encoded = operations
        .iter()
        .flat_map(|operation| list(operation, "uses"))
        .any(|used| used == "encoded");
    if encoded {
        checker.warning(
            Code::InvalidBinding,
            pointer,
            format!(
                "SOAP binding `{binding_name}` uses encoded bodies, which the WS-I Basic Profile \
                 forbids; literal is interoperable"
            ),
        );
    }
}

fn binding20(binding: &Value, pointer: &str, checker: &mut Checker<'_, '_>) {
    match binding["type"].as_str() {
        None => checker.error(
            Code::MissingField,
            pointer,
            format!("binding `{}` needs a `type`", name(binding)),
        ),
        Some(WSOAP) if binding["protocol"].is_null() => checker.error(
            Code::InvalidBinding,
            pointer,
            format!("SOAP binding `{}` needs a wsoap:protocol", name(binding)),
        ),
        Some(_) => {}
    }
}

fn services(model: &Value, checker: &mut Checker<'_, '_>) {
    let entries = list(model, "services");
    checker.unique(entries, "/services", "service", true);
    let segment = checker.nouns.endpoints;
    for service in entries {
        let pointer = format!("/services/{}", escape(name(service)));
        let interface = &service["interface"];
        if checker.wsdl20 {
            if interface.is_null() {
                checker.error(
                    Code::MissingField,
                    &pointer,
                    format!("service `{}` needs an `interface`", name(service)),
                );
            } else {
                checker.component_reference("interface", "interface", interface, &pointer);
            }
        }
        let endpoints = list(service, "endpoints");
        let noun = checker.nouns.endpoint;
        checker.unique(endpoints, &format!("{pointer}/{segment}"), noun, true);
        for endpoint in endpoints {
            let endpoint_pointer = format!("{pointer}/{segment}/{}", escape(name(endpoint)));
            endpoint_checks(endpoint, interface, &endpoint_pointer, checker);
        }
    }
}

fn endpoint_checks(
    endpoint: &Value,
    interface: &Value,
    pointer: &str,
    checker: &mut Checker<'_, '_>,
) {
    let noun = checker.nouns.endpoint;
    let binding = if endpoint["binding"].is_null() {
        checker.error(
            Code::MissingField,
            pointer,
            format!("{noun} `{}` needs a binding", name(endpoint)),
        );
        None
    } else {
        checker.component_reference("binding", "binding", &endpoint["binding"], pointer)
    };
    let bound_interface = binding.map(|binding| &binding["interface"]);
    if checker.wsdl20 && bound_interface.is_some_and(|bound| bound != interface) {
        checker.error(
            Code::InvalidBinding,
            pointer,
            format!(
                "endpoint `{}` uses a binding of another interface than its service's",
                name(endpoint)
            ),
        );
    }
    match endpoint["address"].as_str() {
        None if !checker.wsdl20 => checker.error(
            Code::MissingField,
            pointer,
            format!("port `{}` needs an address location", name(endpoint)),
        ),
        Some(address) if embeds_credentials(address) => checker.error(
            Code::InvalidServer,
            pointer,
            format!(
                "the address of {noun} `{}` embeds credentials",
                name(endpoint)
            ),
        ),
        _ => {}
    }
}
