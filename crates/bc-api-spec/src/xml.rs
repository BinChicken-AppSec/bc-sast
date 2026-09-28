//! Reading the XML standards (WSDL, XML Schema, OData CSDL in EDMX) with
//! `bc_xml`, and the conventions they share: resolved qualified-name
//! references in the models they build, and import locations that are
//! matched within the repository and never fetched.
//!
//! `bc_xml` refuses any DOCTYPE, so no entity is ever declared, expanded
//! or fetched, and bounds the input, nesting, attributes, nodes and
//! namespace bindings. A text it refuses is unverifiable here, never
//! malformed: it is this project's own reader, so its refusal is not
//! proof that somebody's working file is broken.

use bc_xml::{Document, Element, Limits};
use serde_json::{json, Value};

use crate::format::Peer;
use crate::parse::ParseFailure;

/// Largest XML text read, whatever the caller's cap (which it applies
/// first). Matches the ceiling a compiled policy may set.
pub(crate) const MAX_XML_BYTES: usize = 4 * 1024 * 1024;

/// The bounds one parse runs under. WSDL, XML Schema and CSDL nest a few
/// levels deep; 128 leaves room for deeply nested inline schemas.
pub(crate) fn limits() -> Limits {
    Limits {
        max_depth: 128,
        ..Limits::new(MAX_XML_BYTES)
    }
}

/// Parse `text`, or say why the built-in reader refused it.
pub(crate) fn read(text: &str) -> Result<Document, String> {
    bc_xml::parse_str(text, &limits())
        .map_err(|error| format!("could not be read by the built-in XML reader ({error})"))
}

/// Parse `text` for a standard's `parse`: a refusal is unverifiable.
pub(crate) fn read_for_parse(text: &str) -> Result<Document, ParseFailure> {
    read(text).map_err(ParseFailure::Unverifiable)
}

/// A qualified-name reference (`tns:GetQuote`) written on `element`,
/// resolved against the namespaces in scope there: `{"ns", "local"}`, or
/// `{"unresolved"}` with the text as written when it is not a qualified
/// name or its prefix is not declared.
pub(crate) fn reference(element: &Element, value: &str) -> Value {
    match element.resolve_qname_value(value) {
        Some(name) => json!({"ns": name.namespace, "local": name.local}),
        None => json!({"unresolved": value}),
    }
}

/// The reference `attribute` of `element` holds, or null.
pub(crate) fn reference_attribute(element: &Element, attribute: &str) -> Value {
    element
        .attribute(attribute)
        .map_or(Value::Null, |value| reference(element, value))
}

/// An attribute's value as a JSON string, or null.
pub(crate) fn attribute(element: &Element, name: &str) -> Value {
    element
        .attribute(name)
        .map_or(Value::Null, |value| json!(value))
}

/// The namespace declarations on `element`, by prefix (`""` for the
/// default namespace).
pub(crate) fn declarations(element: &Element) -> Value {
    let map: serde_json::Map<String, Value> = element
        .attributes
        .iter()
        .filter(|attribute| attribute.is_namespace_declaration())
        .map(|attribute| {
            let prefix = match attribute.name.prefix {
                Some(_) => attribute.name.local.clone(),
                None => String::new(),
            };
            (prefix, json!(attribute.value))
        })
        .collect();
    Value::Object(map)
}

/// A resolved reference's namespace and local name, when it resolved.
pub(crate) fn expanded(reference: &Value) -> Option<(Option<&str>, &str)> {
    let local = reference.get("local")?.as_str()?;
    Some((reference["ns"].as_str(), local))
}

/// How a reference reads in a message: `{namespace}local`, or as written.
pub(crate) fn describe(reference: &Value) -> String {
    match expanded(reference) {
        Some((Some(namespace), local)) => format!("{{{namespace}}}{local}"),
        Some((None, local)) => local.to_string(),
        None => reference["unresolved"].as_str().unwrap_or_default().into(),
    }
}

/// Where an import location points.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Location<'a> {
    /// Another file of the repository, the peer it matched.
    Local(&'a str),
    /// A URL or absolute path: never fetched, so what it declares is
    /// unverified.
    Remote,
    /// A relative path no readable peer matches.
    Missing,
}

/// Whether `location` names something outside the repository: a URL or
/// any other `scheme:` form (including a Windows drive), or an absolute
/// or network path.
pub(crate) fn is_remote(location: &str) -> bool {
    let location = location.trim();
    let before_slash = location.split(['/', '\\']).next().unwrap_or_default();
    before_slash.contains(':') || location.starts_with(['/', '\\'])
}

/// Resolve an import `location` against the repository's `peers`. The
/// importing file's own path is not known here, so a relative location
/// matches a peer whose path ends with it once `./` and `../` segments
/// are dropped, the same suffix rule Protocol Buffers imports use.
pub(crate) fn locate<'a>(location: &str, peers: &[Peer<'a>]) -> Location<'a> {
    if is_remote(location) {
        return Location::Remote;
    }
    let without_query = location.split(['?', '#']).next().unwrap_or_default();
    let segments: Vec<&str> = without_query
        .split(['/', '\\'])
        .filter(|segment| !matches!(*segment, "" | "." | ".."))
        .collect();
    if segments.is_empty() {
        return Location::Missing;
    }
    let suffix = segments.join("/");
    peers
        .iter()
        .find(|peer| peer.path == suffix || peer.path.ends_with(&format!("/{suffix}")))
        .map_or(Location::Missing, |peer| Location::Local(peer.path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doctype_and_malformed_text_are_unverifiable() {
        for text in [
            "<!DOCTYPE d [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><d>&x;</d>",
            "<a><b></a>",
        ] {
            let refused = read_for_parse(text).unwrap_err();
            let expected = "could not be read by the built-in XML reader (line 1";
            assert!(
                matches!(&refused, ParseFailure::Unverifiable(reason) if reason.starts_with(expected))
            );
        }
        assert!(read("<a/>").is_ok());
        assert_eq!(limits().max_input_bytes, MAX_XML_BYTES);
    }

    #[test]
    fn references_resolve_against_the_scope_they_are_written_in() {
        let document =
            read(r#"<r xmlns="urn:d" xmlns:t="urn:t" a="t:X" b="Y" c="u:Z" d="1"/>"#).unwrap();
        let root = &document.root;
        assert_eq!(
            reference_attribute(root, "a"),
            json!({"ns": "urn:t", "local": "X"})
        );
        assert_eq!(
            reference_attribute(root, "b"),
            json!({"ns": "urn:d", "local": "Y"})
        );
        assert_eq!(reference_attribute(root, "c"), json!({"unresolved": "u:Z"}));
        assert_eq!(reference_attribute(root, "e"), Value::Null);
        assert_eq!(attribute(root, "d"), json!("1"));
        assert_eq!(attribute(root, "e"), Value::Null);
        assert_eq!(declarations(root), json!({"": "urn:d", "t": "urn:t"}));
        assert_eq!(describe(&reference_attribute(root, "a")), "{urn:t}X");
        assert_eq!(describe(&json!({"ns": null, "local": "X"})), "X");
        assert_eq!(describe(&reference_attribute(root, "c")), "u:Z");
        assert_eq!(expanded(&json!({"unresolved": "u:Z"})), None);
    }

    #[test]
    fn locations_resolve_by_suffix_and_are_never_fetched() {
        let document = json!({});
        let peers = [
            Peer {
                path: "svc/src/main/resources/xsd/common.xsd",
                document: &document,
            },
            Peer {
                path: "types.xsd",
                document: &document,
            },
        ];
        assert_eq!(
            locate("../xsd/common.xsd", &peers),
            Location::Local("svc/src/main/resources/xsd/common.xsd")
        );
        assert_eq!(
            locate("./types.xsd?x#y", &peers),
            Location::Local("types.xsd")
        );
        assert_eq!(locate("other.xsd", &peers), Location::Missing);
        assert_eq!(locate("../", &peers), Location::Missing);
        for remote in [
            "https://example.com/common.xsd",
            "http://example.com/a.wsdl",
            "file:///etc/passwd",
            "C:\\schemas\\a.xsd",
            "/etc/common.xsd",
            "//host/share/a.xsd",
            "urn:x:y",
        ] {
            assert_eq!(locate(remote, &peers), Location::Remote, "{remote}");
        }
    }
}
