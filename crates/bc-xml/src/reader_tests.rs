//! Reader tests: the accepted syntax, positions and spans, and one or more
//! cases for every error class and limit.

use crate::*;

fn limits() -> Limits {
    Limits::new(1 << 20)
}

fn ok(text: &str) -> Document {
    parse_str(text, &limits()).unwrap_or_else(|error| panic!("{error}: {text:?}"))
}

fn err(text: &str) -> XmlError {
    err_with(text, &limits())
}

fn err_with(text: &str, limits: &Limits) -> XmlError {
    match parse_str(text, limits) {
        Ok(document) => panic!("parsed {text:?} as {document:?}"),
        Err(error) => error,
    }
}

fn kind(text: &str) -> ErrorKind {
    err(text).kind
}

fn eof(expected: &'static str) -> ErrorKind {
    ErrorKind::UnexpectedEof { expected }
}

fn unexpected(found: char, expected: &'static str) -> ErrorKind {
    ErrorKind::Unexpected { found, expected }
}

fn text(value: &str) -> Node {
    Node::Text(value.into())
}

#[test]
fn a_full_document_reads_into_the_tree() {
    let doc = ok(concat!(
        "<?xml version=\"1.0\" encoding='utf-8' standalone = \"yes\" ?>\n",
        "<!-- head -->\n",
        "<?xml-stylesheet href=\"s.xsl\"?>\n",
        "<root a=\"1\" b='&lt;&#x41;'>",
        "t&amp;x<![CDATA[<raw>]]><!--c--><?pi data here?><?bare?>",
        "<child/><other></other >",
        "</root >\n",
        "<!-- tail -->",
    ));
    assert!(!doc.byte_order_mark);
    assert_eq!(
        doc.declaration,
        Some(XmlDeclaration {
            version: "1.0".into(),
            encoding: Some("utf-8".into()),
            standalone: Some(true),
        })
    );
    assert_eq!(
        doc.prolog,
        [
            text("\n"),
            Node::Comment(" head ".into()),
            text("\n"),
            Node::ProcessingInstruction(ProcessingInstruction {
                target: "xml-stylesheet".into(),
                data: "href=\"s.xsl\"".into(),
            }),
            text("\n"),
        ]
    );
    assert_eq!(doc.epilog, [text("\n"), Node::Comment(" tail ".into())]);
    let root = &doc.root;
    assert_eq!(root.name, QName::new(None, "root"));
    assert_eq!(root.namespace, None);
    assert!(!root.self_closing);
    let attributes: Vec<_> = root
        .attributes
        .iter()
        .map(|a| (a.name.to_string(), a.value.as_str(), a.namespace.clone()))
        .collect();
    assert_eq!(
        attributes,
        [("a".to_string(), "1", None), ("b".to_string(), "<A", None)]
    );
    let mut child = Element::new(QName::new(None, "child"));
    child.self_closing = true;
    let other = Element::new(QName::new(None, "other"));
    assert_eq!(
        root.children,
        [
            text("t&x"),
            Node::CData("<raw>".into()),
            Node::Comment("c".into()),
            Node::ProcessingInstruction(ProcessingInstruction {
                target: "pi".into(),
                data: "data here".into(),
            }),
            Node::ProcessingInstruction(ProcessingInstruction {
                target: "bare".into(),
                data: String::new(),
            }),
            Node::Element(child),
            Node::Element(other),
        ]
    );
}

#[test]
fn byte_order_mark_is_recorded_and_not_counted_as_a_column() {
    let doc = ok("\u{FEFF}<a/>");
    assert!(doc.byte_order_mark);
    assert_eq!(doc.declaration, None);
    let error = err("\u{FEFF}<a>&bad;</a>");
    assert_eq!((error.line, error.column, error.offset), (1, 4, 6));
    let bytes = [&[0xEF, 0xBB, 0xBF][..], b"<a>\xFF</a>"].concat();
    let error = parse(&bytes, &limits()).unwrap_err();
    assert_eq!(error.kind, ErrorKind::InvalidUtf8);
    assert_eq!((error.line, error.column, error.offset), (1, 4, 6));
}

#[test]
fn line_ends_and_attribute_whitespace_are_normalized() {
    let doc =
        ok("<a v=\"x\r\ny\tz\n&#10;\">1\r\n2\r3<!--c\r\n--><![CDATA[d\re]]><?p q\r\nr?></a>\r\n");
    assert_eq!(doc.root.attribute("v"), Some("x y z \n"));
    assert_eq!(
        doc.root.children,
        [
            text("1\n2\n3"),
            Node::Comment("c\n".into()),
            Node::CData("d\ne".into()),
            Node::ProcessingInstruction(ProcessingInstruction {
                target: "p".into(),
                data: "q\nr".into(),
            }),
        ]
    );
    assert_eq!(doc.epilog, [text("\n")]);
}

#[test]
fn spans_locate_tags_and_attributes_in_the_input() {
    let src = "<r>\n  <a x=\"1\"  y='2'>t</a>\n  <b />\n</r>";
    let doc = ok(src);
    let a = doc.root.first_child_named(None, "a").unwrap();
    let span = a.span.unwrap();
    assert_eq!(span.start_tag.slice(src), Some("<a x=\"1\"  y='2'>"));
    assert_eq!(span.end_tag.unwrap().slice(src), Some("</a>"));
    assert_eq!(span.content().unwrap().slice(src), Some("t"));
    assert_eq!(span.outer().slice(src), Some("<a x=\"1\"  y='2'>t</a>"));
    let y = a.attributes[1].span.unwrap();
    assert_eq!(y.whole.slice(src), Some("y='2'"));
    assert_eq!(y.value.slice(src), Some("2"));
    let b = doc.root.first_child_named(None, "b").unwrap();
    assert!(b.self_closing);
    assert_eq!(b.span.unwrap().outer().slice(src), Some("<b />"));
    assert_eq!(b.span.unwrap().end_tag, None);
    assert_eq!(doc.root.span.unwrap().outer().slice(src), Some(src));
}

#[test]
fn namespaces_resolve_through_nested_scopes() {
    let doc = ok(concat!(
        "<p:r xmlns:p=\"urn:p\" xmlns=\"urn:d\" p:at=\"1\" plain=\"2\" xml:lang=\"en\">",
        "<c><p:c xmlns:p=\"urn:p2\"/><u xmlns=\"\"/></c></p:r>",
    ));
    let root = &doc.root;
    assert_eq!(root.namespace.as_deref(), Some("urn:p"));
    let namespaces: Vec<_> = root
        .attributes
        .iter()
        .map(|a| a.namespace.as_deref())
        .collect();
    assert_eq!(
        namespaces,
        [
            Some(XMLNS_NAMESPACE),
            Some(XMLNS_NAMESPACE),
            Some("urn:p"),
            None,
            Some(XML_NAMESPACE),
        ]
    );
    assert!(root.attributes[0].is_namespace_declaration());
    assert!(root.attributes[1].is_namespace_declaration());
    let c = root.first_child_named(Some("urn:d"), "c").unwrap();
    assert!(c.first_child_named(Some("urn:p2"), "c").is_some());
    let u = c.first_child_named(None, "u").unwrap();
    assert_eq!(u.namespace, None);
}

#[test]
fn legacy_encoding_labels_are_accepted_only_for_ascii_input() {
    let doc = ok("<?xml version='1.0' encoding='ISO-8859-1'?><a/>");
    assert_eq!(
        doc.declaration.unwrap().encoding.as_deref(),
        Some("ISO-8859-1")
    );
    ok("<?xml version='1.0' encoding='us-ascii' standalone='no'?><a/>");
    let error = err("<?xml version='1.0' encoding='ISO-8859-1'?><a>\u{e9}</a>");
    assert_eq!(
        error.kind,
        ErrorKind::UnsupportedEncoding("ISO-8859-1".into())
    );
    assert_eq!((error.line, error.column), (1, 31));
    assert_eq!(
        kind("<?xml version='1.0' encoding='UTF-16'?><a/>"),
        ErrorKind::UnsupportedEncoding("UTF-16".into())
    );
}

#[test]
fn malformed_declarations_are_refused() {
    assert_eq!(
        kind("<?xml version='1.1'?><a/>"),
        ErrorKind::UnsupportedVersion("1.1".into())
    );
    assert!(matches!(
        kind("<?xml encoding='UTF-8'?><a/>"),
        ErrorKind::InvalidXmlDeclaration(_)
    ));
    assert!(matches!(
        kind("<?xml version='1.0' standalone='maybe'?><a/>"),
        ErrorKind::InvalidXmlDeclaration(_)
    ));
    assert_eq!(
        kind("<?xml version='1.0' junk='1'?><a/>"),
        unexpected('j', "'?>'")
    );
    assert_eq!(kind("<?xml version '1.0'?><a/>"), unexpected('\'', "'='"));
    assert_eq!(
        kind("<?xml version=1.0?><a/>"),
        unexpected('1', "a quoted value")
    );
    assert_eq!(kind("<?xml version='1.0"), eof("the closing quote"));
    // A declaration anywhere but the very start is a reserved PI target.
    assert_eq!(
        kind(" <?xml version='1.0'?><a/>"),
        ErrorKind::ReservedPiTarget("xml".into())
    );
    assert_eq!(
        kind("<a><?XmL x?></a>"),
        ErrorKind::ReservedPiTarget("XmL".into())
    );
    assert_eq!(
        kind("<?xml?><a/>"),
        ErrorKind::ReservedPiTarget("xml".into())
    );
}

#[test]
fn every_doctype_is_refused_so_no_entity_can_be_declared() {
    let laughs = concat!(
        "<?xml version=\"1.0\"?>\n",
        "<!DOCTYPE lolz [\n",
        "  <!ENTITY lol \"lol\">\n",
        "  <!ENTITY lol2 \"&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;\">\n",
        "]>\n",
        "<lolz>&lol2;</lolz>",
    );
    let error = err(laughs);
    assert_eq!(error.kind, ErrorKind::DoctypeForbidden);
    assert_eq!((error.line, error.column), (2, 1));
    let xxe = "<!DOCTYPE r [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><r>&x;</r>";
    assert_eq!(kind(xxe), ErrorKind::DoctypeForbidden);
    assert_eq!(
        kind("<!DOCTYPE r SYSTEM \"http://x/r.dtd\"><r/>"),
        ErrorKind::DoctypeForbidden
    );
    assert_eq!(kind("<r><!DOCTYPE r></r>"), ErrorKind::DoctypeForbidden);
    assert_eq!(kind("<r/><!DOCTYPE r>"), ErrorKind::DoctypeForbidden);
    assert_eq!(kind("<!ENTITY x 'y'><r/>"), unexpected('E', "a comment"));
    assert_eq!(
        kind("<r><!ELEMENT r ANY></r>"),
        unexpected('E', "a comment or CDATA section")
    );
    assert_eq!(kind("<!"), eof("a comment"));
}

#[test]
fn references_other_than_the_predefined_five_are_refused() {
    assert_eq!(
        kind("<a>&nbsp;</a>"),
        ErrorKind::UndefinedEntity("nbsp".into())
    );
    assert_eq!(kind("<a v='&x;'/>"), ErrorKind::UndefinedEntity("x".into()));
    assert_eq!(kind("<a>a & b</a>"), ErrorKind::InvalidReference);
    assert_eq!(
        kind("<a>&#0;</a>"),
        ErrorKind::InvalidCharReference("#0".into())
    );
    let error = err("<a\n  v='x&#1;'/>");
    assert_eq!(error.kind, ErrorKind::InvalidCharReference("#1".into()));
    assert_eq!((error.line, error.column), (2, 7));
}

#[test]
fn invalid_characters_and_bytes_are_refused_with_positions() {
    let error = err("<a>\n x\u{1}</a>");
    assert_eq!(error.kind, ErrorKind::InvalidChar('\u{1}'));
    assert_eq!((error.line, error.column, error.offset), (2, 3, 6));
    assert_eq!(
        kind("<a b='\u{FFFE}'/>"),
        ErrorKind::InvalidChar('\u{FFFE}')
    );
    let error = parse(b"<a>\r\n\xC3</a>", &limits()).unwrap_err();
    assert_eq!(error.kind, ErrorKind::InvalidUtf8);
    assert_eq!((error.line, error.column, error.offset), (2, 1, 5));
}

#[test]
fn input_size_is_checked_before_anything_else() {
    let error = parse(b"\xFF\xFF", &Limits::new(1)).unwrap_err();
    assert_eq!(
        error.kind,
        ErrorKind::InputTooLarge {
            limit: 1,
            actual: 2
        }
    );
    assert_eq!((error.line, error.column, error.offset), (1, 1, 0));
    ok("<a/>");
    assert!(parse(b"<a/>", &Limits::new(4)).is_ok());
}

#[test]
fn depth_is_limited_without_recursion() {
    let mut limits = limits();
    limits.max_depth = 3;
    assert!(parse_str("<a><b><c/></b></a>", &limits).is_ok());
    let error = err_with("<a><b><c><d/></c></b></a>", &limits);
    assert_eq!(error.kind, ErrorKind::DepthLimitExceeded { limit: 3 });
    assert_eq!(error.column, 10);
    // The default limit, far below anything that could exhaust the stack.
    let deep = format!("{}{}", "<a>".repeat(257), "</a>".repeat(257));
    assert_eq!(kind(&deep), ErrorKind::DepthLimitExceeded { limit: 256 });
    let fine = format!("{}{}", "<a>".repeat(256), "</a>".repeat(256));
    ok(&fine);
}

#[test]
fn attributes_per_element_are_limited() {
    let mut limits = limits();
    limits.max_attributes = 2;
    assert!(parse_str("<a x='1' y='2'/>", &limits).is_ok());
    let error = err_with("<a x='1' y='2' z='3'/>", &limits);
    assert_eq!(error.kind, ErrorKind::AttributeLimitExceeded { limit: 2 });
    assert_eq!(error.column, 16);
}

#[test]
fn total_nodes_are_limited_wherever_they_occur() {
    let mut limits = limits();
    limits.max_nodes = 3;
    assert!(parse_str("<a><b/>t</a>", &limits).is_ok());
    for text in [
        "<a><b/>t<c/></a>",
        "<a><b/>t<!--c--></a>",
        "<a><b/>t<![CDATA[c]]></a>",
        "<a><b/>t<?p?></a>",
        "<a><b/><c/>t</a>",
        " <!--c--> <a/>",
    ] {
        assert_eq!(
            err_with(text, &limits).kind,
            ErrorKind::NodeLimitExceeded { limit: 3 },
            "{text}"
        );
    }
}

#[test]
fn namespace_bindings_in_scope_are_limited() {
    let mut limits = limits();
    limits.max_namespaces_in_scope = 2;
    assert!(parse_str(
        "<a xmlns='urn:0' xmlns:p='urn:1'><b xmlns:p='urn:2'/></a>",
        &limits
    )
    .is_ok());
    let error = err_with(
        "<a xmlns:p='urn:1'><b xmlns:q='urn:2'><c xmlns:r='urn:3'/></b></a>",
        &limits,
    );
    assert_eq!(error.kind, ErrorKind::NamespaceLimitExceeded { limit: 2 });
    assert_eq!(error.column, 39);
}

#[test]
fn truncated_documents_report_what_was_expected() {
    assert_eq!(kind("<a>"), eof("an end tag"));
    assert_eq!(kind("<a>text"), eof("an end tag"));
    assert_eq!(kind("<a"), eof("whitespace, '>' or '/>'"));
    assert_eq!(kind("<a "), eof("an attribute name, '>' or '/>'"));
    assert_eq!(kind("<a x"), eof("'='"));
    assert_eq!(kind("<a x="), eof("a quoted value"));
    assert_eq!(kind("<a x='1"), eof("the closing quote"));
    assert_eq!(kind("<a><!-- c"), eof("'-->'"));
    assert_eq!(kind("<a><![CDATA[ c"), eof("']]>'"));
    assert_eq!(kind("<a><?p d"), eof("'?>'"));
    assert_eq!(kind("<a><?"), eof("a processing instruction target"));
    assert_eq!(kind("<a></a"), eof("'>'"));
    assert_eq!(kind("<a></"), eof("the element name"));
    assert_eq!(kind("<?xml version='1.0'"), eof("'?>'"));
    assert_eq!(kind("<"), eof("an element name"));
}

#[test]
fn syntax_errors_name_the_unexpected_character() {
    assert_eq!(
        kind("<a x='1'y='2'/>"),
        unexpected('y', "whitespace, '>' or '/>'")
    );
    assert_eq!(kind("<a x y='1'/>"), unexpected('y', "'='"));
    assert_eq!(kind("<a x=1/>"), unexpected('1', "a quoted value"));
    assert_eq!(
        kind("<a x='<'/>"),
        unexpected('<', "an attribute value character")
    );
    assert_eq!(kind("<a><?p#?></a>"), unexpected('#', "whitespace or '?>'"));
    assert_eq!(kind("<a></a x>"), unexpected('x', "'>'"));
    assert_eq!(kind("<1a/>"), unexpected('1', "an element name"));
    assert_eq!(kind("</a>"), unexpected('/', "an element name"));
}

#[test]
fn names_must_be_qualified_names() {
    assert_eq!(kind("<a:b:c/>"), ErrorKind::InvalidName("a:b:c".into()));
    assert_eq!(kind("<:a/>"), ErrorKind::InvalidName(":a".into()));
    assert_eq!(kind("<a b:='1'/>"), ErrorKind::InvalidName("b:".into()));
    assert_eq!(kind("<a><?p:q?></a>"), ErrorKind::InvalidName("p:q".into()));
}

#[test]
fn end_tags_must_match() {
    let error = err("<a>\n<b></a></b>");
    assert_eq!(
        error.kind,
        ErrorKind::MismatchedEndTag {
            expected: "b".into(),
            found: "a".into(),
        }
    );
    assert_eq!((error.line, error.column), (2, 6));
    assert!(matches!(
        kind("<p:a xmlns:p='urn:p'></a>"),
        ErrorKind::MismatchedEndTag { .. }
    ));
}

#[test]
fn duplicate_attributes_are_refused_by_qualified_and_expanded_name() {
    assert_eq!(
        kind("<a x='1' x='2'/>"),
        ErrorKind::DuplicateAttribute("x".into())
    );
    let text = "<a xmlns:p='urn:x' xmlns:q='urn:x' p:y='1' q:y='2'/>";
    let error = err(text);
    assert_eq!(error.kind, ErrorKind::DuplicateAttribute("q:y".into()));
    assert_eq!(error.column, 44);
    ok("<a xmlns:p='urn:x' xmlns:q='urn:y' p:y='1' q:y='2' y='3'/>");
}

#[test]
fn prefixes_must_be_bound() {
    assert_eq!(kind("<p:a/>"), ErrorKind::UnboundPrefix("p".into()));
    assert_eq!(kind("<a p:x='1'/>"), ErrorKind::UnboundPrefix("p".into()));
    assert_eq!(kind("<xmlns:a/>"), ErrorKind::UnboundPrefix("xmlns".into()));
    assert_eq!(
        kind("<a xmlns:p='urn:p'><b/></a><!-- --><p:c/>"),
        ErrorKind::ContentOutsideRoot
    );
    assert_eq!(
        kind("<a xmlns:p='urn:p'/><p:c/>"),
        ErrorKind::ContentOutsideRoot
    );
    assert_eq!(
        kind("<a><b xmlns:p='urn:p'/><p:c/></a>"),
        ErrorKind::UnboundPrefix("p".into())
    );
}

#[test]
fn reserved_namespace_declarations_are_refused() {
    for text in [
        "<a xmlns:p=''/>",
        "<a xmlns:xmlns='urn:x'/>",
        "<a xmlns:xml='urn:x'/>",
        "<a xmlns='http://www.w3.org/XML/1998/namespace'/>",
        "<a xmlns:p='http://www.w3.org/2000/xmlns/'/>",
    ] {
        assert!(
            matches!(kind(text), ErrorKind::InvalidNamespaceDeclaration(_)),
            "{text}"
        );
    }
    ok("<a xmlns:xml='http://www.w3.org/XML/1998/namespace'/>");
}

#[test]
fn documents_need_exactly_one_root_and_nothing_else_outside_it() {
    assert_eq!(kind(""), ErrorKind::MissingRoot);
    assert_eq!(kind("  <!-- only -->  "), ErrorKind::MissingRoot);
    assert_eq!(kind("<?xml version='1.0'?>"), ErrorKind::MissingRoot);
    assert_eq!(kind("text<a/>"), ErrorKind::ContentOutsideRoot);
    assert_eq!(kind("<a/>text"), ErrorKind::ContentOutsideRoot);
    assert_eq!(kind("<a/><b/>"), ErrorKind::ContentOutsideRoot);
    assert_eq!(kind("<a/>&amp;"), ErrorKind::ContentOutsideRoot);
}

#[test]
fn delimiters_are_refused_where_they_are_not_allowed() {
    let error = err("<a>x]]>y</a>");
    assert_eq!(error.kind, ErrorKind::CdataEndInText);
    assert_eq!(error.column, 5);
    ok("<a>x]]y]>z</a>");
    assert_eq!(
        kind("<a><!-- x -- y --></a>"),
        ErrorKind::DoubleHyphenInComment
    );
    assert_eq!(kind("<!-- x ---><a/>"), ErrorKind::DoubleHyphenInComment);
    ok("<a><!----><!-- - --></a>");
}
