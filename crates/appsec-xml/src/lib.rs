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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_input_bytes: usize,
    pub max_depth: usize,
    pub max_attributes: usize,
    pub max_nodes: usize,
    pub max_namespaces_in_scope: usize,
}

impl Limits {
    pub const DEFAULT_MAX_DEPTH: usize = 256;
    pub const DEFAULT_MAX_ATTRIBUTES: usize = 256;
    pub const DEFAULT_MAX_NODES: usize = 500_000;
    pub const DEFAULT_MAX_NAMESPACES_IN_SCOPE: usize = 256;

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

pub fn parse_str(input: &str, limits: &Limits) -> Result<Document, XmlError> {
    parse(input.as_bytes(), limits)
}

#[cfg(test)]
mod reader_tests;
#[cfg(test)]
mod writer_tests;
