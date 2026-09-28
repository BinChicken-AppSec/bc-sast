//! Namespace scopes and the Namespaces in XML 1.0 declaration constraints.

use std::sync::Arc;

/// The namespace the `xml` prefix is permanently bound to.
pub const XML_NAMESPACE: &str = "http://www.w3.org/XML/1998/namespace";
/// The namespace of `xmlns` and `xmlns:*` declaration attributes.
pub const XMLNS_NAMESPACE: &str = "http://www.w3.org/2000/xmlns/";

type Binding = (Option<Arc<str>>, Arc<str>);

/// The namespace bindings in scope at one element, flattened so a lookup
/// never walks the ancestor chain. Elements that declare nothing share
/// their parent's scope through the `Arc`, and the reader bounds the
/// number of bindings, so both the copy on a new declaration and every
/// lookup are bounded too. An empty URI records an undeclared default
/// namespace (`xmlns=""`).
#[derive(Clone, Debug, Default)]
pub(crate) struct Scope(Arc<Vec<Binding>>);

impl Scope {
    /// The scope of a child that makes `declarations`, which the reader
    /// has already checked with [`check_declaration`].
    pub(crate) fn declare(&self, declarations: Vec<(Option<String>, String)>) -> Self {
        if declarations.is_empty() {
            return self.clone();
        }
        let mut bindings: Vec<Binding> = self
            .0
            .iter()
            .filter(|(prefix, _)| {
                !declarations
                    .iter()
                    .any(|(declared, _)| declared.as_deref() == prefix.as_deref())
            })
            .cloned()
            .collect();
        bindings.extend(
            declarations
                .into_iter()
                .map(|(prefix, uri)| (prefix.map(Arc::from), Arc::from(uri))),
        );
        Self(Arc::new(bindings))
    }

    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    /// The URI `prefix` (`None` for the default namespace) is bound to.
    pub(crate) fn lookup(&self, prefix: Option<&str>) -> Option<&str> {
        if prefix == Some("xml") {
            return Some(XML_NAMESPACE);
        }
        self.0
            .iter()
            .find(|(bound, _)| bound.as_deref() == prefix)
            .map(|(_, uri)| &**uri)
            .filter(|uri| !uri.is_empty())
    }

    /// A prefix bound to `uri` (`Some(None)` for the default namespace).
    pub(crate) fn prefix_for(&self, uri: &str) -> Option<Option<&str>> {
        if uri == XML_NAMESPACE {
            return Some(Some("xml"));
        }
        self.0
            .iter()
            .find(|(_, bound)| !uri.is_empty() && &**bound == uri)
            .map(|(prefix, _)| prefix.as_deref())
    }
}

/// Check one `xmlns`/`xmlns:prefix` declaration against the reserved
/// prefix and namespace rules. Undeclaring a prefix (`xmlns:p=""`) is an
/// XML 1.1 feature and is refused here.
pub(crate) fn check_declaration(prefix: Option<&str>, uri: &str) -> Result<(), String> {
    match prefix {
        Some("xmlns") => Err("the xmlns prefix cannot be declared".into()),
        Some("xml") if uri != XML_NAMESPACE => {
            Err("the xml prefix cannot be bound to another namespace".into())
        }
        Some("xml") => Ok(()),
        _ if uri == XML_NAMESPACE => {
            Err("only the xml prefix may be bound to the XML namespace".into())
        }
        _ if uri == XMLNS_NAMESPACE => Err("the xmlns namespace cannot be bound".into()),
        Some(p) if uri.is_empty() => Err(format!("prefix {p:?} cannot be undeclared in XML 1.0")),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decl(prefix: Option<&str>, uri: &str) -> (Option<String>, String) {
        (prefix.map(str::to_string), uri.to_string())
    }

    #[test]
    fn inner_declarations_shadow_outer_ones_and_empty_undeclares_the_default() {
        let outer = Scope::default().declare(vec![decl(None, "urn:d"), decl(Some("a"), "urn:a")]);
        assert_eq!(outer.lookup(None), Some("urn:d"));
        assert_eq!(outer.lookup(Some("a")), Some("urn:a"));
        assert_eq!(outer.lookup(Some("xml")), Some(XML_NAMESPACE));
        assert_eq!(outer.lookup(Some("b")), None);
        let inner = outer.declare(vec![decl(None, ""), decl(Some("a"), "urn:a2")]);
        assert_eq!(inner.len(), 2);
        assert_eq!(inner.lookup(None), None);
        assert_eq!(inner.lookup(Some("a")), Some("urn:a2"));
        assert_eq!(inner.prefix_for("urn:a2"), Some(Some("a")));
        assert_eq!(inner.prefix_for("urn:a"), None);
        assert_eq!(inner.prefix_for(""), None);
        assert_eq!(outer.prefix_for("urn:d"), Some(None));
        assert_eq!(outer.prefix_for(XML_NAMESPACE), Some(Some("xml")));
        let same = inner.declare(Vec::new());
        assert!(Arc::ptr_eq(&same.0, &inner.0));
    }

    #[test]
    fn reserved_prefixes_and_namespaces_are_enforced() {
        assert!(check_declaration(Some("xmlns"), "urn:x").is_err());
        assert!(check_declaration(Some("xml"), "urn:x").is_err());
        assert!(check_declaration(Some("xml"), XML_NAMESPACE).is_ok());
        assert!(check_declaration(Some("x"), XML_NAMESPACE).is_err());
        assert!(check_declaration(None, XML_NAMESPACE).is_err());
        assert!(check_declaration(Some("x"), XMLNS_NAMESPACE).is_err());
        assert!(check_declaration(None, XMLNS_NAMESPACE).is_err());
        assert!(check_declaration(Some("x"), "")
            .unwrap_err()
            .contains("undeclared"));
        assert!(check_declaration(None, "").is_ok());
        assert!(check_declaration(Some("x"), "urn:x").is_ok());
    }
}
