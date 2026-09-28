//! Small read-only helpers for walking a tree by namespace and local name.
//!
//! Every namespace argument is the URI, never a prefix: a WSDL may spell
//! the WSDL namespace `wsdl:`, `w:` or leave it as the default, and code
//! that matches on prefixes would treat those as different documents.

use crate::tree::{Element, ExpandedName, Node, QName};

impl Element {
    /// Whether this element is `local` in `namespace` (`None` for no
    /// namespace).
    pub fn is_named(&self, namespace: Option<&str>, local: &str) -> bool {
        self.namespace.as_deref() == namespace && self.name.local == local
    }

    /// The child elements, in document order.
    pub fn child_elements(&self) -> impl Iterator<Item = &Element> {
        self.children.iter().filter_map(Node::as_element)
    }

    /// The child elements named `local` in `namespace`.
    pub fn children_named<'a>(
        &'a self,
        namespace: Option<&'a str>,
        local: &'a str,
    ) -> impl Iterator<Item = &'a Element> + 'a {
        self.child_elements()
            .filter(move |child| child.is_named(namespace, local))
    }

    /// The first child element named `local` in `namespace`.
    pub fn first_child_named(&self, namespace: Option<&str>, local: &str) -> Option<&Element> {
        self.child_elements()
            .find(|child| child.is_named(namespace, local))
    }

    /// Every element below this one (not including it), depth first in
    /// document order. Iterative, so a deep tree cannot overflow the stack.
    pub fn descendants(&self) -> Descendants<'_> {
        Descendants {
            stack: vec![self.children.iter()],
        }
    }

    /// The descendants named `local` in `namespace`.
    pub fn descendants_named<'a>(
        &'a self,
        namespace: Option<&'a str>,
        local: &'a str,
    ) -> impl Iterator<Item = &'a Element> + 'a {
        self.descendants()
            .filter(move |element| element.is_named(namespace, local))
    }

    /// The value of the attribute written as `qualified_name` (for
    /// example `name` or `xml:lang`).
    pub fn attribute(&self, qualified_name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|attribute| attribute.name.matches(qualified_name))
            .map(|attribute| attribute.value.as_str())
    }

    /// The value of the attribute `local` in `namespace`. Unprefixed
    /// attributes are in no namespace, so pass `None` for them.
    pub fn attribute_ns(&self, namespace: Option<&str>, local: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|attribute| {
                attribute.namespace.as_deref() == namespace && attribute.name.local == local
            })
            .map(|attribute| attribute.value.as_str())
    }

    /// The text and CDATA content of the direct children, concatenated.
    pub fn text(&self) -> String {
        self.children
            .iter()
            .filter_map(|child| match child {
                Node::Text(text) | Node::CData(text) => Some(text.as_str()),
                _ => None,
            })
            .collect()
    }

    /// The namespace URI `prefix` is bound to at this element (`None` for
    /// the default namespace). Reflects the source as parsed; for an
    /// element built in code only the `xml` prefix is known.
    pub fn lookup_namespace(&self, prefix: Option<&str>) -> Option<&str> {
        self.scope.lookup(prefix)
    }

    /// A prefix bound to `namespace` at this element: `Some(None)` when it
    /// is the default namespace, `None` when nothing is bound to it. Use
    /// it to spell a name in a fragment that will be inserted here.
    pub fn lookup_prefix(&self, namespace: &str) -> Option<Option<&str>> {
        self.scope.prefix_for(namespace)
    }

    /// Resolve a QName-valued attribute value or text (such as WSDL's
    /// `message="tns:GetQuote"` or XSD's `type="xsd:string"`) against the
    /// namespaces in scope here. Surrounding whitespace is ignored, as XSD
    /// collapses it; an unprefixed value takes the default namespace, as
    /// XSD specifies. `None` if the value is not a QName or its prefix is
    /// unbound.
    pub fn resolve_qname_value<'a>(&'a self, value: &'a str) -> Option<ExpandedName<'a>> {
        let value = value.trim_matches(crate::chars::is_whitespace);
        let name = QName::parse(value)?;
        let namespace = match name.prefix {
            Some(ref prefix) => Some(self.scope.lookup(Some(prefix))?),
            None => self.scope.lookup(None),
        };
        let local = &value[value.len() - name.local.len()..];
        Some(ExpandedName { namespace, local })
    }
}

/// Pre-order iterator over an element's descendants; see
/// [`Element::descendants`].
pub struct Descendants<'a> {
    stack: Vec<std::slice::Iter<'a, Node>>,
}

impl<'a> Iterator for Descendants<'a> {
    type Item = &'a Element;

    fn next(&mut self) -> Option<&'a Element> {
        loop {
            let top = self.stack.last_mut()?;
            match top.next() {
                Some(Node::Element(element)) => {
                    self.stack.push(element.children.iter());
                    return Some(element);
                }
                Some(_) => {}
                None => {
                    self.stack.pop();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{parse_str, Limits};

    const DOC: &str = r#"<d:root xmlns:d="urn:d" xmlns="urn:default" xml:lang="en" plain="p">
  <d:item name="one">a<![CDATA[b]]><!--c-->d</d:item>
  <item name="two"><d:item name="three"/></item>
  <d:other xmlns="" ref=" d:thing " bare="thing" bad="z:thing" not="1a"/>
</d:root>"#;

    fn doc() -> crate::Document {
        parse_str(DOC, &Limits::new(4096)).unwrap()
    }

    #[test]
    fn children_are_found_by_namespace_and_local_name() {
        let doc = doc();
        let root = &doc.root;
        assert!(root.is_named(Some("urn:d"), "root"));
        assert!(!root.is_named(None, "root"));
        assert_eq!(root.child_elements().count(), 3);
        let items: Vec<_> = root
            .children_named(Some("urn:d"), "item")
            .map(|e| e.attribute("name").unwrap())
            .collect();
        assert_eq!(items, ["one"]);
        let two = root.first_child_named(Some("urn:default"), "item").unwrap();
        assert_eq!(two.attribute("name"), Some("two"));
        assert!(root.first_child_named(None, "item").is_none());
        assert!(root.first_child_named(None, "other").is_none());
        assert!(root.first_child_named(Some("urn:d"), "other").is_some());
    }

    #[test]
    fn descendants_walk_depth_first_in_document_order() {
        let doc = doc();
        let names: Vec<_> = doc
            .root
            .descendants()
            .map(|e| e.attribute("name").unwrap_or("-"))
            .collect();
        assert_eq!(names, ["one", "two", "three", "-"]);
        let named: Vec<_> = doc
            .root
            .descendants_named(Some("urn:d"), "item")
            .map(|e| e.attribute("name").unwrap())
            .collect();
        assert_eq!(named, ["one", "three"]);
    }

    #[test]
    fn attributes_are_found_by_qualified_or_expanded_name() {
        let doc = doc();
        let root = &doc.root;
        assert_eq!(root.attribute("xml:lang"), Some("en"));
        assert_eq!(root.attribute("lang"), None);
        assert_eq!(
            root.attribute_ns(Some(crate::XML_NAMESPACE), "lang"),
            Some("en")
        );
        assert_eq!(root.attribute_ns(None, "plain"), Some("p"));
        assert_eq!(root.attribute_ns(Some("urn:d"), "plain"), None);
        assert_eq!(
            root.attribute_ns(Some(crate::XMLNS_NAMESPACE), "d"),
            Some("urn:d")
        );
    }

    #[test]
    fn text_concatenates_text_and_cdata_children() {
        let doc = doc();
        let one = doc.root.first_child_named(Some("urn:d"), "item").unwrap();
        assert_eq!(one.text(), "abd");
    }

    #[test]
    fn namespaces_and_qname_values_resolve_against_the_source_scope() {
        let doc = doc();
        let root = &doc.root;
        assert_eq!(root.lookup_namespace(None), Some("urn:default"));
        assert_eq!(root.lookup_prefix("urn:d"), Some(Some("d")));
        assert_eq!(root.lookup_prefix("urn:default"), Some(None));
        assert_eq!(root.lookup_prefix("urn:none"), None);
        let other = root.first_child_named(Some("urn:d"), "other").unwrap();
        assert_eq!(other.lookup_namespace(None), None);
        let resolved = other
            .resolve_qname_value(other.attribute("ref").unwrap())
            .unwrap();
        assert_eq!(
            (resolved.namespace, resolved.local),
            (Some("urn:d"), "thing")
        );
        let bare = other.resolve_qname_value("thing").unwrap();
        assert_eq!((bare.namespace, bare.local), (None, "thing"));
        let defaulted = root.resolve_qname_value("thing").unwrap();
        assert_eq!(defaulted.namespace, Some("urn:default"));
        assert_eq!(other.resolve_qname_value("z:thing"), None);
        assert_eq!(other.resolve_qname_value("1a"), None);
        let built = crate::Element::new(crate::QName::new(None, "x"));
        assert_eq!(
            built.lookup_namespace(Some("xml")),
            Some(crate::XML_NAMESPACE)
        );
        assert_eq!(built.lookup_namespace(None), None);
    }
}
