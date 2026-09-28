//! A small, purpose-built XML 1.0 reader and writer for validating and
//! repairing SOAP/WSDL 1.1 and 2.0, XML Schema and OData CSDL documents
//! found in a target repository. It is **not** a general XML processor.
//!
//! Same reasoning as `bc-yaml`: these files come from repositories this
//! tool scans, so they are untrusted input, and XML parsers have a long
//! history of exactly the vulnerabilities this tool looks for (XXE,
//! entity expansion, unbounded recursion). The supply-chain policy
//! in `docs/supply-chain.md` makes a new third-party parser expensive, and
//! the subset these formats need is small enough to own and audit, so
//! this crate has no dependencies at all.
//!
//! # What it reads
//!
//! Well-formed XML 1.0 in UTF-8 with Namespaces in XML 1.0, into an owned
//! tree ([`Document`], [`Element`], [`Node`]): elements with their
//! qualified names split into prefix and local part and resolved to a
//! namespace URI; attributes in document order; text with the five
//! predefined entities and character references decoded; CDATA sections,
//! comments and processing instructions kept as nodes; the XML
//! declaration. Whitespace-only text is kept too, so a document survives
//! `parse`, [`write_document`], `parse` unchanged.
//!
//! # Security posture (fail closed)
//!
//! Every refusal below is an error, never a best-effort parse:
//!
//! - **No DTDs.** Any `<!DOCTYPE` is refused outright, with or without an
//!   internal subset. With no DTD there is nothing that can declare an
//!   entity, so external entities (XXE) and nested expansion ("billion
//!   laughs") cannot happen, and any entity reference other than `&amp;`,
//!   `&lt;`, `&gt;`, `&apos;` and `&quot;` is an undefined-entity error.
//!   Nothing is ever fetched, included or resolved from outside the input.
//! - **Bounded work.** [`Limits`] caps the input size (chosen by the
//!   caller), element nesting depth, attributes per element, total nodes
//!   and namespace bindings in scope. The reader and writer are iterative,
//!   so depth is a policy limit and never a stack overflow.
//! - **Strict characters.** Invalid UTF-8 and any character XML 1.0 does
//!   not allow (C0 controls other than tab, newline and carriage return,
//!   U+FFFE, U+FFFF), whether literal or as a character reference, are
//!   errors. A declared encoding other than UTF-8 is accepted only for a
//!   few ASCII-compatible labels, and only when the input is pure ASCII.
//! - **Namespaces are checked.** An unbound prefix, a duplicate attribute
//!   (by qualified name or by namespace and local name), and misuse of the
//!   reserved `xml`/`xmlns` prefixes and namespaces are errors.
//!
//! Well-formedness errors are typed ([`ErrorKind`]) and carry a line and
//! column ([`XmlError`]).
//!
//! # Out of scope
//!
//! XML 1.1, encodings other than UTF-8, DTD validation, default attribute
//! values, XInclude, XML Schema validation and anything XPath-shaped. The
//! query helpers on [`Element`] cover walking by namespace URI and local
//! name, which is what WSDL/XSD/CSDL checks need.
//!
//! # Repairs as minimal diffs
//!
//! Every parsed element and attribute records its byte [`Span`] in the
//! input, and [`SpanEdit`] turns those into targeted insertions and
//! replacements applied by [`apply_span_edits`], so a repair changes only
//! the bytes it has to (see the `edits` module docs).

mod chars;
mod edits;
mod error;
mod escape;
mod namespace;
mod query;
mod reader;
mod tree;
mod writer;

pub use chars::is_ncname;
pub use edits::{apply_span_edits, EditError, SpanEdit, MAX_EDITS};
pub use error::{ErrorKind, WriteError, XmlError};
pub use escape::{escape_attribute, escape_text};
pub use namespace::{XMLNS_NAMESPACE, XML_NAMESPACE};
pub use query::Descendants;
pub use tree::{
    Attribute, AttributeSpan, Document, Element, ElementSpan, ExpandedName, Node,
    ProcessingInstruction, QName, Span, XmlDeclaration,
};
pub use writer::{write_document, write_element};

/// Resource bounds for one parse. Exceeding any of them is an error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Largest input accepted, in bytes. Checked before anything else.
    pub max_input_bytes: usize,
    /// Deepest element nesting; the root element is depth 1.
    pub max_depth: usize,
    /// Most attributes on one element, namespace declarations included.
    pub max_attributes: usize,
    /// Most nodes in the document: elements, text runs, CDATA sections,
    /// comments and processing instructions, inside and outside the root.
    pub max_nodes: usize,
    /// Most distinct prefixes (and the default namespace) bound at once.
    /// Bounds the cost of every namespace lookup.
    pub max_namespaces_in_scope: usize,
}

impl Limits {
    pub const DEFAULT_MAX_DEPTH: usize = 256;
    pub const DEFAULT_MAX_ATTRIBUTES: usize = 256;
    pub const DEFAULT_MAX_NODES: usize = 500_000;
    pub const DEFAULT_MAX_NAMESPACES_IN_SCOPE: usize = 256;

    /// The default bounds with the caller's input size limit. There is no
    /// default for that one: the right size depends on what is being read.
    pub const fn new(max_input_bytes: usize) -> Self {
        Self {
            max_input_bytes,
            max_depth: Self::DEFAULT_MAX_DEPTH,
            max_attributes: Self::DEFAULT_MAX_ATTRIBUTES,
            max_nodes: Self::DEFAULT_MAX_NODES,
            max_namespaces_in_scope: Self::DEFAULT_MAX_NAMESPACES_IN_SCOPE,
        }
    }
}

/// Parse a UTF-8 document (a leading byte order mark is allowed).
pub fn parse(input: &[u8], limits: &Limits) -> Result<Document, XmlError> {
    if input.len() > limits.max_input_bytes {
        let kind = ErrorKind::InputTooLarge {
            limit: limits.max_input_bytes,
            actual: input.len(),
        };
        return Err(XmlError::at("", 0, 0, kind));
    }
    let text = std::str::from_utf8(input).map_err(|error| {
        let valid = error.valid_up_to();
        let prefix = std::str::from_utf8(&input[..valid]).expect("a valid UTF-8 prefix");
        let body_start = if prefix.starts_with('\u{FEFF}') { 3 } else { 0 };
        XmlError::at(prefix, body_start, valid, ErrorKind::InvalidUtf8)
    })?;
    reader::parse_document(text, limits)
}

/// Parse a document that is already a string.
pub fn parse_str(input: &str, limits: &Limits) -> Result<Document, XmlError> {
    parse(input.as_bytes(), limits)
}

#[cfg(test)]
mod reader_tests;
#[cfg(test)]
mod writer_tests;
