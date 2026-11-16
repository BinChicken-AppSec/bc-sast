use appsec_xml::{Document, Element, Limits};
use serde_json::{json, Value};

use crate::format::Peer;
use crate::parse::ParseFailure;

pub(crate) const MAX_XML_BYTES: usize = 4 * 1024 * 1024;

pub(crate) fn limits() -> Limits {
    Limits {
        max_depth: 128,
        ..Limits::new(MAX_XML_BYTES)
    }
}

pub(crate) fn read(text: &str) -> Result<Document, String> {
    appsec_xml::parse_str(text, &limits())
        .map_err(|error| format!("could not be read by the built-in XML reader ({error})"))
}

pub(crate) fn read_for_parse(text: &str) -> Result<Document, ParseFailure> {
    read(text).map_err(ParseFailure::Unverifiable)
}

pub(crate) fn reference(element: &Element, value: &str) -> Value {
    match element.resolve_qname_value(value) {
        Some(name) => json!({"ns": name.namespace, "local": name.local}),
        None => json!({"unresolved": value}),
    }
}

pub(crate) fn reference_attribute(element: &Element, attribute: &str) -> Value {
    element
        .attribute(attribute)
        .map_or(Value::Null, |value| reference(element, value))
}

pub(crate) fn attribute(element: &Element, name: &str) -> Value {
    element
        .attribute(name)
        .map_or(Value::Null, |value| json!(value))
}

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

pub(crate) fn expanded(reference: &Value) -> Option<(Option<&str>, &str)> {
    let local = reference.get("local")?.as_str()?;
    Some((reference["ns"].as_str(), local))
}

pub(crate) fn describe(reference: &Value) -> String {
    match expanded(reference) {
        Some((Some(namespace), local)) => format!("{{{namespace}}}{local}"),
        Some((None, local)) => local.to_string(),
        None => reference["unresolved"].as_str().unwrap_or_default().into(),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Location<'a> {
    Local(&'a str),
    Remote,
    Missing,
}

pub(crate) fn is_remote(location: &str) -> bool {
    let location = location.trim();
    let before_slash = location.split(['/', '\\']).next().unwrap_or_default();
    before_slash.contains(':') || location.starts_with(['/', '\\'])
}

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
