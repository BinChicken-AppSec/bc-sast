//! Typed parse and write errors.

use std::fmt;

/// Why a document was refused. Every variant is a hard failure: the reader
/// never recovers and never returns a partial tree.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The input is larger than [`Limits::max_input_bytes`](crate::Limits).
    InputTooLarge { limit: usize, actual: usize },
    /// The input is not valid UTF-8.
    InvalidUtf8,
    /// A character XML 1.0 does not allow anywhere in a document, such as
    /// a C0 control other than tab, newline and carriage return.
    InvalidChar(char),
    /// The XML declaration names an encoding this reader does not decode.
    UnsupportedEncoding(String),
    /// The XML declaration names a version other than `1.0`.
    UnsupportedVersion(String),
    /// The XML declaration is malformed; the text says how.
    InvalidXmlDeclaration(&'static str),
    /// A `<!DOCTYPE`. Refused outright: no internal subset, no external
    /// entities, no entity expansion of any kind.
    DoctypeForbidden,
    /// An entity reference to anything but the five predefined entities.
    UndefinedEntity(String),
    /// An `&` that does not start a well-formed `&name;` or `&#...;`.
    InvalidReference,
    /// A character reference to a code point XML 1.0 does not allow; the
    /// payload is the text between `&` and `;`.
    InvalidCharReference(String),
    /// More nested elements than [`Limits::max_depth`](crate::Limits).
    DepthLimitExceeded { limit: usize },
    /// More attributes on one element than
    /// [`Limits::max_attributes`](crate::Limits).
    AttributeLimitExceeded { limit: usize },
    /// More nodes in the document than [`Limits::max_nodes`](crate::Limits).
    NodeLimitExceeded { limit: usize },
    /// More namespace bindings in scope at one element than
    /// [`Limits::max_namespaces_in_scope`](crate::Limits).
    NamespaceLimitExceeded { limit: usize },
    /// The input ended while `expected` was still required.
    UnexpectedEof { expected: &'static str },
    /// `found` appeared where `expected` was required.
    Unexpected { found: char, expected: &'static str },
    /// A name that is not a valid qualified name (or, for a processing
    /// instruction target, not a valid NCName).
    InvalidName(String),
    /// An end tag that does not close the innermost open element.
    MismatchedEndTag { expected: String, found: String },
    /// The same attribute twice on one element, by qualified name or by
    /// namespace URI and local name.
    DuplicateAttribute(String),
    /// A prefix used on an element or attribute with no `xmlns:` binding
    /// in scope.
    UnboundPrefix(String),
    /// A namespace declaration the Namespaces in XML 1.0 constraints
    /// forbid; the text says which one.
    InvalidNamespaceDeclaration(String),
    /// The document has no root element.
    MissingRoot,
    /// Text or a second element outside the root element.
    ContentOutsideRoot,
    /// The literal `]]>` in character data.
    CdataEndInText,
    /// `--` inside a comment (including a comment ending in `--->`).
    DoubleHyphenInComment,
    /// A processing instruction whose target is `xml` in any letter case,
    /// which also catches an XML declaration that is not at the very start.
    ReservedPiTarget(String),
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLarge { limit, actual } => {
                write!(f, "input is {actual} bytes, over the {limit}-byte limit")
            }
            Self::InvalidUtf8 => f.write_str("input is not valid UTF-8"),
            Self::InvalidChar(c) => {
                write!(f, "character U+{:04X} is not allowed in XML 1.0", *c as u32)
            }
            Self::UnsupportedEncoding(e) => write!(f, "unsupported encoding {e:?}"),
            Self::UnsupportedVersion(v) => {
                write!(f, "unsupported XML version {v:?}; only 1.0 is read")
            }
            Self::InvalidXmlDeclaration(why) => write!(f, "invalid XML declaration: {why}"),
            Self::DoctypeForbidden => f.write_str("DOCTYPE declarations are not accepted"),
            Self::UndefinedEntity(name) => write!(f, "undefined entity &{name};"),
            Self::InvalidReference => f.write_str("malformed entity or character reference"),
            Self::InvalidCharReference(body) => {
                write!(
                    f,
                    "character reference &{body}; is not an allowed character"
                )
            }
            Self::DepthLimitExceeded { limit } => {
                write!(f, "elements nest deeper than the limit of {limit}")
            }
            Self::AttributeLimitExceeded { limit } => {
                write!(f, "element has more than the limit of {limit} attributes")
            }
            Self::NodeLimitExceeded { limit } => {
                write!(f, "document has more than the limit of {limit} nodes")
            }
            Self::NamespaceLimitExceeded { limit } => {
                write!(
                    f,
                    "more than the limit of {limit} namespace bindings are in scope"
                )
            }
            Self::UnexpectedEof { expected } => {
                write!(f, "unexpected end of input, expected {expected}")
            }
            Self::Unexpected { found, expected } => {
                write!(f, "unexpected {found:?}, expected {expected}")
            }
            Self::InvalidName(name) => write!(f, "invalid name {name:?}"),
            Self::MismatchedEndTag { expected, found } => {
                write!(f, "end tag </{found}> does not match <{expected}>")
            }
            Self::DuplicateAttribute(name) => write!(f, "duplicate attribute {name:?}"),
            Self::UnboundPrefix(prefix) => write!(f, "namespace prefix {prefix:?} is not bound"),
            Self::InvalidNamespaceDeclaration(why) => {
                write!(f, "invalid namespace declaration: {why}")
            }
            Self::MissingRoot => f.write_str("document has no root element"),
            Self::ContentOutsideRoot => f.write_str("content outside the root element"),
            Self::CdataEndInText => f.write_str("\"]]>\" is not allowed in character data"),
            Self::DoubleHyphenInComment => f.write_str("\"--\" is not allowed inside a comment"),
            Self::ReservedPiTarget(target) => {
                write!(f, "processing instruction target {target:?} is reserved")
            }
        }
    }
}

/// A parse failure with the position it was detected at. `line` and
/// `column` are 1-based; `column` counts Unicode scalar values, and a
/// leading byte order mark is not counted. `offset` is the byte offset in
/// the input as given.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XmlError {
    pub kind: ErrorKind,
    pub line: usize,
    pub column: usize,
    pub offset: usize,
}

impl XmlError {
    /// Locate `offset` (a char boundary of `src`) by counting line breaks
    /// from `body_start`. Only runs on the error path, so the reader does
    /// not pay for position tracking on every character.
    pub(crate) fn at(src: &str, body_start: usize, offset: usize, kind: ErrorKind) -> Self {
        let (mut line, mut column) = (1, 1);
        let mut chars = src[body_start..offset].chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\r' || c == '\n' {
                if c == '\r' && chars.peek() == Some(&'\n') {
                    chars.next();
                }
                line += 1;
                column = 1;
            } else {
                column += 1;
            }
        }
        Self {
            kind,
            line,
            column,
            offset,
        }
    }
}

impl fmt::Display for XmlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "line {}, column {}: {}",
            self.line, self.column, self.kind
        )
    }
}

impl std::error::Error for XmlError {}

/// Why a tree could not be serialized. The writer refuses anything whose
/// output would not be well-formed rather than emitting it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum WriteError {
    /// An element or attribute name that is not a valid qualified name.
    InvalidName(String),
    /// A character XML 1.0 cannot represent, even as a reference.
    InvalidChar(char),
    /// A comment containing `--` or ending in `-`.
    InvalidComment(String),
    /// A CDATA section containing `]]>`.
    InvalidCData(String),
    /// A processing instruction with an invalid or reserved target, or
    /// data containing `?>`.
    InvalidProcessingInstruction(String),
    /// A node that may not appear outside the root element: an element, a
    /// CDATA section, or text that is not all whitespace.
    InvalidMisc,
    /// An XML declaration with a version other than `1.0`, or an encoding
    /// label that does not describe the output; the text says which.
    InvalidDeclaration(String),
}

impl fmt::Display for WriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidName(name) => write!(f, "invalid name {name:?}"),
            Self::InvalidChar(c) => {
                write!(f, "character U+{:04X} cannot be written in XML 1.0", *c as u32)
            }
            Self::InvalidComment(text) => write!(f, "comment {text:?} cannot be written"),
            Self::InvalidCData(text) => write!(f, "CDATA section {text:?} contains \"]]>\""),
            Self::InvalidProcessingInstruction(target) => {
                write!(f, "processing instruction {target:?} cannot be written")
            }
            Self::InvalidMisc => {
                f.write_str("only comments, processing instructions and whitespace may appear outside the root element")
            }
            Self::InvalidDeclaration(why) => write!(f, "invalid XML declaration: {why}"),
        }
    }
}

impl std::error::Error for WriteError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn positions_count_lines_and_columns_after_the_body_start() {
        let src = "\u{FEFF}ab\ncd\r\nef\rgh";
        let error = XmlError::at(src, 3, src.len(), ErrorKind::MissingRoot);
        assert_eq!((error.line, error.column, error.offset), (4, 3, src.len()));
        let first = XmlError::at(src, 3, 5, ErrorKind::MissingRoot);
        assert_eq!((first.line, first.column), (1, 3));
        let wide = XmlError::at("\u{e9}\u{e9}x", 0, 4, ErrorKind::MissingRoot);
        assert_eq!(wide.column, 3);
    }

    #[test]
    fn every_parse_error_kind_has_a_message() {
        let cases: Vec<(ErrorKind, &str)> = vec![
            (
                ErrorKind::InputTooLarge {
                    limit: 1,
                    actual: 2,
                },
                "2 bytes, over the 1-byte",
            ),
            (ErrorKind::InvalidUtf8, "UTF-8"),
            (ErrorKind::InvalidChar('\u{1}'), "U+0001"),
            (
                ErrorKind::UnsupportedEncoding("EBCDIC".into()),
                "\"EBCDIC\"",
            ),
            (ErrorKind::UnsupportedVersion("1.1".into()), "only 1.0"),
            (ErrorKind::InvalidXmlDeclaration("why"), "declaration: why"),
            (ErrorKind::DoctypeForbidden, "DOCTYPE"),
            (ErrorKind::UndefinedEntity("x".into()), "&x;"),
            (ErrorKind::InvalidReference, "malformed"),
            (ErrorKind::InvalidCharReference("#0".into()), "&#0;"),
            (
                ErrorKind::DepthLimitExceeded { limit: 3 },
                "deeper than the limit of 3",
            ),
            (
                ErrorKind::AttributeLimitExceeded { limit: 4 },
                "limit of 4 attributes",
            ),
            (
                ErrorKind::NodeLimitExceeded { limit: 5 },
                "limit of 5 nodes",
            ),
            (
                ErrorKind::NamespaceLimitExceeded { limit: 6 },
                "limit of 6 namespace",
            ),
            (
                ErrorKind::UnexpectedEof { expected: "'>'" },
                "end of input, expected '>'",
            ),
            (
                ErrorKind::Unexpected {
                    found: 'x',
                    expected: "'='",
                },
                "unexpected 'x', expected '='",
            ),
            (ErrorKind::InvalidName("a:b:c".into()), "\"a:b:c\""),
            (
                ErrorKind::MismatchedEndTag {
                    expected: "a".into(),
                    found: "b".into(),
                },
                "</b> does not match <a>",
            ),
            (
                ErrorKind::DuplicateAttribute("id".into()),
                "duplicate attribute \"id\"",
            ),
            (ErrorKind::UnboundPrefix("p".into()), "\"p\" is not bound"),
            (
                ErrorKind::InvalidNamespaceDeclaration("why".into()),
                "declaration: why",
            ),
            (ErrorKind::MissingRoot, "no root"),
            (ErrorKind::ContentOutsideRoot, "outside the root"),
            (ErrorKind::CdataEndInText, "]]>"),
            (ErrorKind::DoubleHyphenInComment, "\"--\""),
            (
                ErrorKind::ReservedPiTarget("XML".into()),
                "\"XML\" is reserved",
            ),
        ];
        for (kind, expected) in cases {
            let text = kind.to_string();
            assert!(text.contains(expected), "{text} lacks {expected}");
        }
        let error = XmlError::at("a\nbc", 0, 3, ErrorKind::MissingRoot);
        assert_eq!(
            error.to_string(),
            "line 2, column 2: document has no root element"
        );
        let _: &dyn std::error::Error = &error;
    }

    #[test]
    fn every_write_error_has_a_message() {
        let cases: Vec<(WriteError, &str)> = vec![
            (WriteError::InvalidName("1a".into()), "\"1a\""),
            (WriteError::InvalidChar('\0'), "U+0000"),
            (WriteError::InvalidComment("a--b".into()), "\"a--b\""),
            (WriteError::InvalidCData("]]>".into()), "contains"),
            (
                WriteError::InvalidProcessingInstruction("xml".into()),
                "\"xml\"",
            ),
            (WriteError::InvalidMisc, "outside the root"),
            (
                WriteError::InvalidDeclaration("why".into()),
                "declaration: why",
            ),
        ];
        for (error, expected) in cases {
            let text = error.to_string();
            assert!(text.contains(expected), "{text} lacks {expected}");
        }
        let _: &dyn std::error::Error = &WriteError::InvalidMisc;
    }
}
