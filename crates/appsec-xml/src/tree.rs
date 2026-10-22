//! The owned document tree.
//!
//! Equality compares content, not provenance: two trees are equal when
//! they describe the same document, whatever byte offsets they were read
//! from. That is what makes `parse(write(parse(x))) == parse(x)` a
//! meaningful round-trip check even though the writer does not reproduce
//! the original bytes (quote style, whitespace inside tags and character
//! references are not kept).

use std::fmt;
use std::ops::Range;

use crate::chars::is_ncname;
use crate::namespace::{Scope, XMLNS_NAMESPACE};

/// A half-open byte range in the text a tree was parsed from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    pub fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    /// An empty span at `offset`, the target of an insertion.
    pub fn at(offset: usize) -> Self {
        Self::new(offset, offset)
    }

    pub fn range(self) -> Range<usize> {
        self.start..self.end
    }

    /// The spanned text, or `None` if the span is not inside `text` or
    /// does not fall on character boundaries.
    pub fn slice(self, text: &str) -> Option<&str> {
        text.get(self.range())
    }
}

/// Where an element's tags sit in the source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ElementSpan {
    /// `<name ...>` or, for a self-closing element, `<name .../>`.
    pub start_tag: Span,
    /// `</name>`; `None` for a self-closing element.
    pub end_tag: Option<Span>,
}

impl ElementSpan {
    /// The whole element, from `<` of the start tag to `>` of the end tag.
    pub fn outer(&self) -> Span {
        let end = self.end_tag.map_or(self.start_tag.end, |tag| tag.end);
        Span::new(self.start_tag.start, end)
    }

    /// Everything between the tags; `None` for a self-closing element.
    pub fn content(&self) -> Option<Span> {
        self.end_tag
            .map(|tag| Span::new(self.start_tag.end, tag.start))
    }
}

/// Where an attribute sits in the source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttributeSpan {
    /// `name="value"`, quotes included.
    pub whole: Span,
    /// The raw value between the quotes, references not yet decoded.
    pub value: Span,
}

/// A qualified name split at its colon.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct QName {
    pub prefix: Option<String>,
    pub local: String,
}

impl QName {
    pub fn new(prefix: Option<&str>, local: &str) -> Self {
        Self {
            prefix: prefix.map(str::to_string),
            local: local.to_string(),
        }
    }

    /// Split `text` as a qualified name: one optional `prefix:` and a
    /// local part, both NCNames. `None` if it is not one.
    pub fn parse(text: &str) -> Option<Self> {
        match text.split_once(':') {
            Some((prefix, local)) if is_ncname(prefix) && is_ncname(local) => {
                Some(Self::new(Some(prefix), local))
            }
            None if is_ncname(text) => Some(Self::new(None, text)),
            _ => None,
        }
    }

    /// Whether both parts are NCNames, which the writer requires.
    pub fn is_valid(&self) -> bool {
        self.prefix.as_deref().is_none_or(is_ncname) && is_ncname(&self.local)
    }

    /// Whether this is the qualified name `text`, compared without
    /// allocating.
    pub fn matches(&self, text: &str) -> bool {
        match (&self.prefix, text.split_once(':')) {
            (Some(prefix), Some((p, local))) => prefix == p && self.local == local,
            (None, None) => self.local == text,
            _ => false,
        }
    }
}

impl fmt::Display for QName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.prefix {
            Some(prefix) => write!(f, "{prefix}:{}", self.local),
            None => f.write_str(&self.local),
        }
    }
}

/// A namespace URI and local name, the identity namespace-aware code
/// should compare on (prefixes are only the author's shorthand).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ExpandedName<'a> {
    pub namespace: Option<&'a str>,
    pub local: &'a str,
}

#[derive(Clone, Debug)]
pub struct Attribute {
    pub name: QName,
    /// The resolved namespace URI. `None` for an unprefixed attribute
    /// (the default namespace never applies to attributes);
    /// [`XMLNS_NAMESPACE`] for a namespace declaration.
    pub namespace: Option<String>,
    /// The decoded, normalized value.
    pub value: String,
    /// `None` for an attribute that was not read from source text.
    pub span: Option<AttributeSpan>,
}

impl Attribute {
    /// An attribute with no namespace and no source position.
    pub fn new(name: QName, value: impl Into<String>) -> Self {
        Self {
            name,
            namespace: None,
            value: value.into(),
            span: None,
        }
    }

    /// Whether this is an `xmlns` or `xmlns:prefix` declaration.
    pub fn is_namespace_declaration(&self) -> bool {
        self.namespace.as_deref() == Some(XMLNS_NAMESPACE)
    }
}

impl PartialEq for Attribute {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.namespace == other.namespace && self.value == other.value
    }
}

impl Eq for Attribute {}

#[derive(Clone, Debug)]
pub struct Element {
    pub name: QName,
    /// The resolved namespace URI, `None` when no namespace applies.
    pub namespace: Option<String>,
    /// In document order, namespace declarations included.
    pub attributes: Vec<Attribute>,
    pub children: Vec<Node>,
    /// Whether the source wrote this element as `<name/>`. The writer
    /// keeps that form when the element still has no children.
    pub self_closing: bool,
    /// `None` for an element that was not read from source text.
    pub span: Option<ElementSpan>,
    /// The namespace bindings in scope where the element was read. Kept
    /// private because it is derived from the source: editing
    /// `attributes` does not update it.
    pub(crate) scope: Scope,
}

impl Element {
    /// An empty element with no namespace and no source position. It is
    /// written as `<name></name>` unless `self_closing` is set.
    pub fn new(name: QName) -> Self {
        Self {
            name,
            namespace: None,
            attributes: Vec::new(),
            children: Vec::new(),
            self_closing: false,
            span: None,
            scope: Scope::default(),
        }
    }
}

impl PartialEq for Element {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
            && self.namespace == other.namespace
            && self.attributes == other.attributes
            && self.children == other.children
            && self.self_closing == other.self_closing
    }
}

impl Eq for Element {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessingInstruction {
    pub target: String,
    /// Everything after the whitespace that follows the target.
    pub data: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Node {
    Element(Element),
    /// Character data with references decoded and line ends normalized.
    /// Whitespace-only text is kept, so indentation survives a round trip.
    Text(String),
    CData(String),
    Comment(String),
    ProcessingInstruction(ProcessingInstruction),
}

impl Node {
    pub fn as_element(&self) -> Option<&Element> {
        match self {
            Self::Element(element) => Some(element),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XmlDeclaration {
    pub version: String,
    pub encoding: Option<String>,
    pub standalone: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Document {
    /// Whether the input started with a UTF-8 byte order mark.
    pub byte_order_mark: bool,
    pub declaration: Option<XmlDeclaration>,
    /// Comments, processing instructions and whitespace before the root.
    pub prolog: Vec<Node>,
    pub root: Element,
    /// Comments, processing instructions and whitespace after the root.
    pub epilog: Vec<Node>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spans_expose_ranges_slices_and_element_parts() {
        let span = Span::new(1, 3);
        assert_eq!(span.range(), 1..3);
        assert_eq!(span.slice("abcd"), Some("bc"));
        assert_eq!(Span::new(2, 9).slice("abcd"), None);
        assert_eq!(Span::at(4), Span::new(4, 4));
        let open = ElementSpan {
            start_tag: Span::new(0, 3),
            end_tag: Some(Span::new(5, 9)),
        };
        assert_eq!(open.outer(), Span::new(0, 9));
        assert_eq!(open.content(), Some(Span::new(3, 5)));
        let closed = ElementSpan {
            start_tag: Span::new(2, 6),
            end_tag: None,
        };
        assert_eq!(closed.outer(), Span::new(2, 6));
        assert_eq!(closed.content(), None);
    }

    #[test]
    fn qualified_names_parse_validate_match_and_display() {
        assert_eq!(QName::parse("a:b"), Some(QName::new(Some("a"), "b")));
        assert_eq!(QName::parse("b"), Some(QName::new(None, "b")));
        for bad in ["a:b:c", ":b", "a:", "1a", "", "a:1"] {
            assert_eq!(QName::parse(bad), None, "{bad}");
        }
        assert!(QName::new(Some("a"), "b").is_valid());
        assert!(!QName::new(Some("1"), "b").is_valid());
        assert!(!QName::new(None, "a:b").is_valid());
        let name = QName::new(Some("wsdl"), "types");
        assert!(name.matches("wsdl:types"));
        assert!(!name.matches("xsd:types"));
        assert!(!name.matches("wsdl:type"));
        assert!(!name.matches("types"));
        assert!(QName::new(None, "types").matches("types"));
        assert!(!QName::new(None, "types").matches("x:types"));
        assert_eq!(name.to_string(), "wsdl:types");
        assert_eq!(QName::new(None, "types").to_string(), "types");
    }

    #[test]
    fn equality_ignores_source_positions() {
        let mut a = Element::new(QName::new(None, "a"));
        let mut attribute = Attribute::new(QName::new(None, "x"), "1");
        assert!(!attribute.is_namespace_declaration());
        a.attributes.push(attribute.clone());
        let mut b = a.clone();
        b.span = Some(ElementSpan {
            start_tag: Span::new(0, 1),
            end_tag: None,
        });
        attribute.span = Some(AttributeSpan {
            whole: Span::new(0, 1),
            value: Span::new(0, 1),
        });
        b.attributes[0] = attribute;
        assert_eq!(a, b);
        b.self_closing = true;
        assert_ne!(a, b);
        assert_eq!(Node::Text("t".into()).as_element(), None);
        assert_eq!(Node::Element(a.clone()).as_element(), Some(&a));
    }
}
