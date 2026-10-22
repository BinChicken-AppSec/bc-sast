//! The well-formedness and namespace checking reader.
//!
//! Elements are read with an explicit stack rather than recursion, so the
//! depth limit is a policy choice and never the thing standing between a
//! hostile document and a stack overflow. Positions are byte offsets into
//! the input; line and column are only computed when an error is built.

use crate::chars::{is_name_char, is_name_start_char, is_whitespace, is_xml_char};
use crate::error::{ErrorKind, XmlError};
use crate::escape::{decode, normalize_newlines};
use crate::namespace::{check_declaration, Scope, XMLNS_NAMESPACE};
use crate::tree::{
    Attribute, AttributeSpan, Document, Element, ElementSpan, Node, ProcessingInstruction, QName,
    Span, XmlDeclaration,
};
use crate::Limits;

type Result<T> = std::result::Result<T, XmlError>;

/// Encodings besides UTF-8 that a declaration may name, accepted only
/// when the whole input is ASCII, where they decode identically.
const ASCII_COMPATIBLE: [&str; 4] = ["US-ASCII", "ASCII", "ISO-8859-1", "WINDOWS-1252"];

pub(crate) fn is_utf8_label(label: &str) -> bool {
    label.eq_ignore_ascii_case("UTF-8")
}

pub(crate) fn is_ascii_compatible_label(label: &str) -> bool {
    ASCII_COMPATIBLE
        .iter()
        .any(|known| label.eq_ignore_ascii_case(known))
}

const BYTE_ORDER_MARK: char = '\u{FEFF}';

pub(crate) fn parse_document(src: &str, limits: &Limits) -> Result<Document> {
    let byte_order_mark = src.starts_with(BYTE_ORDER_MARK);
    let body_start = if byte_order_mark {
        BYTE_ORDER_MARK.len_utf8()
    } else {
        0
    };
    let mut reader = Reader {
        src,
        pos: body_start,
        body_start,
        limits,
        nodes: 0,
    };
    // One pass up front, so no later branch has to remember to check.
    if let Some((offset, c)) = src.char_indices().find(|&(_, c)| !is_xml_char(c)) {
        return Err(reader.error(offset, ErrorKind::InvalidChar(c)));
    }
    let declaration = if reader.starts_with("<?xml")
        && src[reader.pos + 5..]
            .chars()
            .next()
            .is_some_and(is_whitespace)
    {
        Some(reader.declaration()?)
    } else {
        None
    };
    let prolog = reader.misc()?;
    match reader.peek() {
        None => return Err(reader.error(reader.pos, ErrorKind::MissingRoot)),
        Some('<') => {}
        Some(_) => return Err(reader.error(reader.pos, ErrorKind::ContentOutsideRoot)),
    }
    let root = reader.root()?;
    let epilog = reader.misc()?;
    if reader.pos < src.len() {
        return Err(reader.error(reader.pos, ErrorKind::ContentOutsideRoot));
    }
    Ok(Document {
        byte_order_mark,
        declaration,
        prolog,
        root,
        epilog,
    })
}

struct Reader<'a> {
    src: &'a str,
    pos: usize,
    body_start: usize,
    limits: &'a Limits,
    nodes: usize,
}

impl<'a> Reader<'a> {
    fn error(&self, offset: usize, kind: ErrorKind) -> XmlError {
        XmlError::at(self.src, self.body_start, offset, kind)
    }

    fn unexpected_at(&self, offset: usize, expected: &'static str) -> XmlError {
        let kind = match self.src[offset..].chars().next() {
            Some(found) => ErrorKind::Unexpected { found, expected },
            None => ErrorKind::UnexpectedEof { expected },
        };
        self.error(offset, kind)
    }

    fn unexpected(&self, expected: &'static str) -> XmlError {
        self.unexpected_at(self.pos, expected)
    }

    fn eof(&self, expected: &'static str) -> XmlError {
        self.error(self.src.len(), ErrorKind::UnexpectedEof { expected })
    }

    fn rest(&self) -> &'a str {
        &self.src[self.pos..]
    }

    fn peek(&self) -> Option<char> {
        self.rest().chars().next()
    }

    fn starts_with(&self, literal: &str) -> bool {
        self.rest().starts_with(literal)
    }

    fn expect(&mut self, literal: &'static str, expected: &'static str) -> Result<()> {
        if !self.starts_with(literal) {
            return Err(self.unexpected(expected));
        }
        self.pos += literal.len();
        Ok(())
    }

    fn skip_whitespace(&mut self) -> bool {
        let start = self.pos;
        while let Some(c) = self.peek().filter(|&c| is_whitespace(c)) {
            self.pos += c.len_utf8();
        }
        self.pos > start
    }

    fn count_node(&mut self, offset: usize) -> Result<()> {
        self.nodes += 1;
        if self.nodes > self.limits.max_nodes {
            let limit = self.limits.max_nodes;
            return Err(self.error(offset, ErrorKind::NodeLimitExceeded { limit }));
        }
        Ok(())
    }

    /// Read a `Name` and return its span.
    fn name(&mut self, expected: &'static str) -> Result<Span> {
        let start = self.pos;
        if !self.peek().is_some_and(is_name_start_char) {
            return Err(self.unexpected(expected));
        }
        while let Some(c) = self.peek().filter(|&c| is_name_char(c)) {
            self.pos += c.len_utf8();
        }
        Ok(Span::new(start, self.pos))
    }

    fn qname(&mut self, expected: &'static str) -> Result<QName> {
        let span = self.name(expected)?;
        let raw = &self.src[span.range()];
        QName::parse(raw).ok_or_else(|| self.error(span.start, ErrorKind::InvalidName(raw.into())))
    }

    /// `<?xml version="1.0" encoding="..." standalone="..."?>`, in that
    /// order, with only `version` required.
    fn declaration(&mut self) -> Result<XmlDeclaration> {
        self.pos += "<?xml".len();
        let Some((at, version)) = self.pseudo_attribute("version")? else {
            let why = "the version must come first";
            return Err(self.error(self.pos, ErrorKind::InvalidXmlDeclaration(why)));
        };
        if version != "1.0" {
            return Err(self.error(at, ErrorKind::UnsupportedVersion(version.into())));
        }
        let encoding = match self.pseudo_attribute("encoding")? {
            Some((at, label)) => {
                let ascii = is_ascii_compatible_label(label) && self.src.is_ascii();
                if !is_utf8_label(label) && !ascii {
                    return Err(self.error(at, ErrorKind::UnsupportedEncoding(label.into())));
                }
                Some(label.to_string())
            }
            None => None,
        };
        let standalone = match self.pseudo_attribute("standalone")? {
            Some((_, "yes")) => Some(true),
            Some((_, "no")) => Some(false),
            Some((at, _)) => {
                let why = "standalone must be \"yes\" or \"no\"";
                return Err(self.error(at, ErrorKind::InvalidXmlDeclaration(why)));
            }
            None => None,
        };
        self.skip_whitespace();
        self.expect("?>", "'?>'")?;
        Ok(XmlDeclaration {
            version: version.into(),
            encoding,
            standalone,
        })
    }

    /// One `S name = "value"` of the XML declaration, or `None` (with
    /// nothing consumed) if `name` is not next.
    fn pseudo_attribute(&mut self, name: &'static str) -> Result<Option<(usize, &'a str)>> {
        let save = self.pos;
        if !self.skip_whitespace() || !self.starts_with(name) {
            self.pos = save;
            return Ok(None);
        }
        self.pos += name.len();
        self.skip_whitespace();
        self.expect("=", "'='")?;
        self.skip_whitespace();
        let (start, end) = self.quoted()?;
        Ok(Some((start, &self.src[start..end])))
    }

    /// A quoted value; returns the span between the quotes.
    fn quoted(&mut self) -> Result<(usize, usize)> {
        let quote = match self.peek() {
            Some(q @ ('"' | '\'')) => q,
            _ => return Err(self.unexpected("a quoted value")),
        };
        let start = self.pos + 1;
        let len = self.src[start..]
            .find(quote)
            .ok_or_else(|| self.eof("the closing quote"))?;
        self.pos = start + len + 1;
        Ok((start, start + len))
    }

    /// Comments, processing instructions and whitespace outside the root.
    fn misc(&mut self) -> Result<Vec<Node>> {
        let mut nodes = Vec::new();
        loop {
            let start = self.pos;
            if self.skip_whitespace() {
                self.count_node(start)?;
                nodes.push(Node::Text(normalize_newlines(&self.src[start..self.pos])));
            } else if self.starts_with("<!--") {
                nodes.push(self.comment()?);
            } else if self.starts_with("<?") {
                nodes.push(self.processing_instruction()?);
            } else if self.starts_with("<!") {
                return Err(self.markup_declaration("a comment"));
            } else {
                return Ok(nodes);
            }
        }
    }

    /// The error for a `<!` that is not a comment (or, in content, a CDATA
    /// section). A DOCTYPE gets its own error so the refusal is explicit.
    fn markup_declaration(&self, expected: &'static str) -> XmlError {
        if self.starts_with("<!DOCTYPE") {
            return self.error(self.pos, ErrorKind::DoctypeForbidden);
        }
        self.unexpected_at(self.pos + 2, expected)
    }

    fn comment(&mut self) -> Result<Node> {
        self.count_node(self.pos)?;
        let body = self.pos + "<!--".len();
        let len = self.src[body..]
            .find("--")
            .ok_or_else(|| self.eof("'-->'"))?;
        if !self.src[body + len..].starts_with("-->") {
            return Err(self.error(body + len, ErrorKind::DoubleHyphenInComment));
        }
        self.pos = body + len + "-->".len();
        Ok(Node::Comment(normalize_newlines(
            &self.src[body..body + len],
        )))
    }

    fn cdata(&mut self) -> Result<Node> {
        self.count_node(self.pos)?;
        let body = self.pos + "<![CDATA[".len();
        let len = self.src[body..]
            .find("]]>")
            .ok_or_else(|| self.eof("']]>'"))?;
        self.pos = body + len + "]]>".len();
        Ok(Node::CData(normalize_newlines(&self.src[body..body + len])))
    }

    fn processing_instruction(&mut self) -> Result<Node> {
        self.count_node(self.pos)?;
        self.pos += "<?".len();
        let span = self.name("a processing instruction target")?;
        let target = &self.src[span.range()];
        if target.eq_ignore_ascii_case("xml") {
            return Err(self.error(span.start, ErrorKind::ReservedPiTarget(target.into())));
        }
        if target.contains(':') {
            return Err(self.error(span.start, ErrorKind::InvalidName(target.into())));
        }
        let data = if self.starts_with("?>") {
            ""
        } else {
            if !self.skip_whitespace() {
                return Err(self.unexpected("whitespace or '?>'"));
            }
            let len = self.rest().find("?>").ok_or_else(|| self.eof("'?>'"))?;
            &self.src[self.pos..self.pos + len]
        };
        self.pos += data.len() + "?>".len();
        Ok(Node::ProcessingInstruction(ProcessingInstruction {
            target: target.into(),
            data: normalize_newlines(data),
        }))
    }

    fn text(&mut self) -> Result<Node> {
        let start = self.pos;
        let end = self
            .rest()
            .find('<')
            .map_or(self.src.len(), |len| start + len);
        if let Some(len) = self.src[start..end].find("]]>") {
            return Err(self.error(start + len, ErrorKind::CdataEndInText));
        }
        self.count_node(start)?;
        let text =
            decode(self.src, start, end, false).map_err(|(at, kind)| self.error(at, kind))?;
        self.pos = end;
        Ok(Node::Text(text))
    }

    /// The root element and everything inside it.
    fn root(&mut self) -> Result<Element> {
        let mut stack: Vec<Element> = Vec::new();
        let mut opened = self.start_tag(&Scope::default(), 1)?;
        loop {
            let mut finished = if opened.self_closing {
                Some(opened)
            } else {
                stack.push(opened);
                None
            };
            // Read content until the next start tag, attaching each
            // finished element to its parent as it closes.
            loop {
                if let Some(element) = finished.take() {
                    match stack.last_mut() {
                        Some(parent) => parent.children.push(Node::Element(element)),
                        None => return Ok(element),
                    }
                }
                let node = if self.starts_with("</") {
                    let open = stack.pop().expect("an element is open");
                    finished = Some(self.end_tag(open)?);
                    continue;
                } else if self.starts_with("<!--") {
                    self.comment()?
                } else if self.starts_with("<![CDATA[") {
                    self.cdata()?
                } else if self.starts_with("<?") {
                    self.processing_instruction()?
                } else if self.starts_with("<!") {
                    return Err(self.markup_declaration("a comment or CDATA section"));
                } else if self.starts_with("<") {
                    break;
                } else if self.pos == self.src.len() {
                    return Err(self.eof("an end tag"));
                } else {
                    self.text()?
                };
                let parent = stack.last_mut().expect("an element is open");
                parent.children.push(node);
            }
            let parent = stack.last().expect("an element is open");
            opened = self.start_tag(&parent.scope, stack.len() + 1)?;
        }
    }

    fn start_tag(&mut self, parent_scope: &Scope, depth: usize) -> Result<Element> {
        let start = self.pos;
        if depth > self.limits.max_depth {
            let limit = self.limits.max_depth;
            return Err(self.error(start, ErrorKind::DepthLimitExceeded { limit }));
        }
        self.count_node(start)?;
        self.pos += 1;
        let name = self.qname("an element name")?;
        let mut attributes: Vec<Attribute> = Vec::new();
        let mut declarations = Vec::new();
        let self_closing = loop {
            let separated = self.skip_whitespace();
            if self.starts_with("/>") || self.starts_with(">") {
                let self_closing = self.starts_with("/>");
                self.pos += if self_closing { 2 } else { 1 };
                break self_closing;
            }
            if !separated {
                return Err(self.unexpected("whitespace, '>' or '/>'"));
            }
            if attributes.len() == self.limits.max_attributes {
                let limit = self.limits.max_attributes;
                return Err(self.error(self.pos, ErrorKind::AttributeLimitExceeded { limit }));
            }
            let attribute = self.attribute()?;
            let at = attribute.span.expect("read from source").whole.start;
            if attributes.iter().any(|a| a.name == attribute.name) {
                let name = attribute.name.to_string();
                return Err(self.error(at, ErrorKind::DuplicateAttribute(name)));
            }
            let declared = match (&attribute.name.prefix, attribute.name.local.as_str()) {
                (Some(p), local) if p == "xmlns" => Some(Some(local.to_string())),
                (None, "xmlns") => Some(None),
                _ => None,
            };
            if let Some(prefix) = declared {
                check_declaration(prefix.as_deref(), &attribute.value)
                    .map_err(|why| self.error(at, ErrorKind::InvalidNamespaceDeclaration(why)))?;
                declarations.push((prefix, attribute.value.clone()));
            }
            attributes.push(attribute);
        };
        let scope = parent_scope.declare(declarations);
        if scope.len() > self.limits.max_namespaces_in_scope {
            let limit = self.limits.max_namespaces_in_scope;
            return Err(self.error(start, ErrorKind::NamespaceLimitExceeded { limit }));
        }
        let namespace = self.resolve(&scope, name.prefix.as_deref(), start)?;
        for index in 0..attributes.len() {
            let attribute = &attributes[index];
            let at = attribute.span.expect("read from source").whole.start;
            let namespace = match attribute.name.prefix.as_deref() {
                Some("xmlns") => Some(XMLNS_NAMESPACE.to_string()),
                None if attribute.name.local == "xmlns" => Some(XMLNS_NAMESPACE.to_string()),
                None => None,
                prefix => self.resolve(&scope, prefix, at)?,
            };
            // Two prefixes bound to one URI make `a:x` and `b:x` the same
            // attribute, which the qualified-name check above cannot see.
            if namespace.is_some()
                && attributes[..index]
                    .iter()
                    .any(|a| a.namespace == namespace && a.name.local == attribute.name.local)
            {
                let name = attribute.name.to_string();
                return Err(self.error(at, ErrorKind::DuplicateAttribute(name)));
            }
            attributes[index].namespace = namespace;
        }
        let mut element = Element::new(name);
        element.namespace = namespace;
        element.attributes = attributes;
        element.self_closing = self_closing;
        element.span = Some(ElementSpan {
            start_tag: Span::new(start, self.pos),
            end_tag: None,
        });
        element.scope = scope;
        Ok(element)
    }

    /// The namespace of a name with `prefix`; an unprefixed name takes
    /// the default namespace, which only elements call this for.
    fn resolve(&self, scope: &Scope, prefix: Option<&str>, at: usize) -> Result<Option<String>> {
        match (prefix, scope.lookup(prefix)) {
            (Some(prefix), None) => Err(self.error(at, ErrorKind::UnboundPrefix(prefix.into()))),
            (_, uri) => Ok(uri.map(str::to_string)),
        }
    }

    fn attribute(&mut self) -> Result<Attribute> {
        let start = self.pos;
        let name = self.qname("an attribute name, '>' or '/>'")?;
        self.skip_whitespace();
        self.expect("=", "'='")?;
        self.skip_whitespace();
        let (value_start, value_end) = self.quoted()?;
        if let Some(len) = self.src[value_start..value_end].find('<') {
            return Err(self.unexpected_at(value_start + len, "an attribute value character"));
        }
        let value = decode(self.src, value_start, value_end, true)
            .map_err(|(at, kind)| self.error(at, kind))?;
        let mut attribute = Attribute::new(name, value);
        attribute.span = Some(AttributeSpan {
            whole: Span::new(start, self.pos),
            value: Span::new(value_start, value_end),
        });
        Ok(attribute)
    }

    fn end_tag(&mut self, mut open: Element) -> Result<Element> {
        let start = self.pos;
        self.pos += "</".len();
        let span = self.name("the element name")?;
        let found = &self.src[span.range()];
        if !open.name.matches(found) {
            let expected = open.name.to_string();
            let found = found.to_string();
            return Err(self.error(span.start, ErrorKind::MismatchedEndTag { expected, found }));
        }
        self.skip_whitespace();
        self.expect(">", "'>'")?;
        if let Some(span) = open.span.as_mut() {
            span.end_tag = Some(Span::new(start, self.pos));
        }
        Ok(open)
    }
}
