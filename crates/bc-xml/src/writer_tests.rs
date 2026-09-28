//! Writer tests: exact output, every refusal, and property-style round
//! trips for escaping and for whole trees.

use proptest::prelude::*;

use crate::*;

fn limits() -> Limits {
    Limits::new(1 << 20)
}

fn element(local: &str) -> Element {
    Element::new(QName::new(None, local))
}

fn document(root: Element) -> Document {
    Document {
        byte_order_mark: false,
        declaration: None,
        prolog: Vec::new(),
        root,
        epilog: Vec::new(),
    }
}

fn round_trip(text: &str) -> String {
    let parsed = parse_str(text, &limits()).unwrap();
    let written = write_document(&parsed).unwrap();
    assert_eq!(parse_str(&written, &limits()).unwrap(), parsed, "{written}");
    written
}

#[test]
fn output_keeps_prefixes_order_and_self_closing_form() {
    let text = concat!(
        "\u{FEFF}<?xml version='1.0' encoding='UTF-8' standalone='no'?>\n",
        "<!--c--><?p d?>\n",
        "<s:r xmlns:s='urn:s' b='2' a=\"1\" s:q='&quot;&apos;&#9;'>\n",
        "  <s:e/><f></f><g >&lt;&amp;&gt;&#13;</g><![CDATA[x<y]]><?t?>\n",
        "</s:r>\n",
        "<!--end-->",
    );
    assert_eq!(
        round_trip(text),
        concat!(
            "\u{FEFF}<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n",
            "<!--c--><?p d?>\n",
            "<s:r xmlns:s=\"urn:s\" b=\"2\" a=\"1\" s:q=\"&quot;'&#9;\">\n",
            "  <s:e/><f></f><g>&lt;&amp;&gt;&#13;</g><![CDATA[x<y]]><?t?>\n",
            "</s:r>\n",
            "<!--end-->",
        )
    );
    assert_eq!(
        round_trip("<?xml version='1.0' standalone='yes'?><a/>"),
        "<?xml version=\"1.0\" standalone=\"yes\"?><a/>"
    );
}

#[test]
fn elements_built_in_code_are_written_and_can_be_fragments() {
    let mut root = element("r");
    root.attributes
        .push(Attribute::new(QName::new(None, "k"), "v\n"));
    let mut empty = element("e");
    empty.self_closing = true;
    let mut opened = element("o");
    opened.self_closing = true;
    opened.children.push(Node::Text("t".into()));
    root.children.push(Node::Element(empty));
    root.children.push(Node::Element(opened));
    root.children.push(Node::Element(element("n")));
    assert_eq!(
        write_element(&root).unwrap(),
        "<r k=\"v&#10;\"><e/><o>t</o><n></n></r>"
    );
}

#[test]
fn a_legacy_encoding_label_requires_ascii_output() {
    let doc = parse_str("<?xml version='1.0' encoding='ISO-8859-1'?><a/>", &limits()).unwrap();
    assert!(write_document(&doc).is_ok());
    let mut changed = doc.clone();
    changed.root.children.push(Node::Text("\u{e9}".into()));
    assert!(matches!(
        write_document(&changed),
        Err(WriteError::InvalidDeclaration(_))
    ));
    let mut utf8 = changed.clone();
    utf8.declaration.as_mut().unwrap().encoding = Some("utf-8".into());
    assert!(write_document(&utf8).is_ok());
    let mut unknown = doc.clone();
    unknown.declaration.as_mut().unwrap().encoding = Some("EBCDIC\"".into());
    assert!(matches!(
        write_document(&unknown),
        Err(WriteError::InvalidDeclaration(_))
    ));
    let mut version = doc;
    version.declaration.as_mut().unwrap().version = "1.1".into();
    assert!(matches!(
        write_document(&version),
        Err(WriteError::InvalidDeclaration(_))
    ));
}

#[test]
fn trees_that_would_not_parse_are_refused() {
    let with_child = |node: Node| {
        let mut root = element("r");
        root.children.push(node);
        write_element(&root)
    };
    let pi = |target: &str, data: &str| {
        Node::ProcessingInstruction(ProcessingInstruction {
            target: target.into(),
            data: data.into(),
        })
    };
    assert_eq!(
        write_element(&element("1a")),
        Err(WriteError::InvalidName("1a".into()))
    );
    let mut bad_attribute = element("r");
    bad_attribute
        .attributes
        .push(Attribute::new(QName::new(Some("p"), "a:b"), ""));
    assert_eq!(
        write_element(&bad_attribute),
        Err(WriteError::InvalidName("p:a:b".into()))
    );
    let mut bad_value = element("r");
    bad_value
        .attributes
        .push(Attribute::new(QName::new(None, "a"), "\u{0}"));
    assert_eq!(
        write_element(&bad_value),
        Err(WriteError::InvalidChar('\u{0}'))
    );
    assert_eq!(
        with_child(Node::Text("\u{B}".into())),
        Err(WriteError::InvalidChar('\u{B}'))
    );
    assert_eq!(
        with_child(Node::CData("\u{FFFF}".into())),
        Err(WriteError::InvalidChar('\u{FFFF}'))
    );
    assert_eq!(
        with_child(Node::CData("a]]>b".into())),
        Err(WriteError::InvalidCData("a]]>b".into()))
    );
    assert_eq!(
        with_child(Node::Comment("\u{1}".into())),
        Err(WriteError::InvalidChar('\u{1}'))
    );
    for comment in ["a--b", "a-"] {
        assert_eq!(
            with_child(Node::Comment(comment.into())),
            Err(WriteError::InvalidComment(comment.into()))
        );
    }
    assert_eq!(
        with_child(pi("t", "\u{2}")),
        Err(WriteError::InvalidChar('\u{2}'))
    );
    for (target, data) in [("xml", ""), ("a:b", ""), ("", ""), ("t", "a?>b")] {
        assert_eq!(
            with_child(pi(target, data)),
            Err(WriteError::InvalidProcessingInstruction(target.into()))
        );
    }
}

#[test]
fn only_misc_nodes_may_sit_outside_the_root() {
    for node in [
        Node::Text(" x ".into()),
        Node::CData(String::new()),
        Node::Element(element("second")),
    ] {
        let mut doc = document(element("r"));
        doc.prolog.push(node.clone());
        assert_eq!(write_document(&doc), Err(WriteError::InvalidMisc));
        let mut doc = document(element("r"));
        doc.epilog.push(node);
        assert_eq!(write_document(&doc), Err(WriteError::InvalidMisc));
    }
    let mut doc = document(element("r"));
    doc.prolog.push(Node::Comment("-".into()));
    assert!(matches!(
        write_document(&doc),
        Err(WriteError::InvalidComment(_))
    ));
    let mut doc = document(element("1"));
    doc.epilog.push(Node::Text("\n".into()));
    assert!(matches!(
        write_document(&doc),
        Err(WriteError::InvalidName(_))
    ));
}

/// Characters XML 1.0 allows, weighted toward the ones escaping and
/// normalization have to get right.
fn xml_char() -> impl Strategy<Value = char> {
    prop_oneof![
        3 => prop::sample::select(vec!['&', '<', '>', '"', '\'', '\r', '\n', '\t', ']', ' ', ';', '#']),
        2 => prop::char::range('a', 'z'),
        1 => any::<char>(),
    ]
    .prop_filter("XML 1.0 characters only", |&c| crate::chars::is_xml_char(c))
}

fn xml_string() -> impl Strategy<Value = String> {
    prop::collection::vec(xml_char(), 0..40).prop_map(|chars| chars.into_iter().collect())
}

fn name() -> impl Strategy<Value = String> {
    prop::sample::select(vec!["a", "b", "c", "item", "x-y", "z.1"]).prop_map(str::to_string)
}

/// Trees that only use valid names and the `p` prefix the root declares,
/// with arbitrary text, so write-then-parse must succeed.
fn tree() -> impl Strategy<Value = Element> {
    let leaf = prop_oneof![
        xml_string().prop_map(Node::Text),
        xml_string()
            .prop_filter("no CDATA end", |s| !s.contains("]]>"))
            .prop_map(Node::CData),
        xml_string()
            .prop_filter("valid comment", |s| !s.contains("--") && !s.ends_with('-'))
            .prop_map(Node::Comment),
    ];
    let node = leaf.prop_recursive(4, 32, 6, |inner| {
        (
            name(),
            any::<bool>(),
            any::<bool>(),
            prop::collection::vec((name(), xml_string()), 0..4),
            prop::collection::vec(inner, 0..6),
        )
            .prop_map(|(local, prefixed, self_closing, attributes, children)| {
                let prefix = prefixed.then_some("p");
                let mut element = Element::new(QName::new(prefix, &local));
                for (key, value) in attributes {
                    if !element.attributes.iter().any(|a| a.name.local == key) {
                        element
                            .attributes
                            .push(Attribute::new(QName::new(None, &key), value));
                    }
                }
                element.self_closing = self_closing;
                element.children = children;
                Node::Element(element)
            })
    });
    prop::collection::vec(node, 0..6).prop_map(|children| {
        let mut root = Element::new(QName::new(None, "root"));
        root.attributes
            .push(Attribute::new(QName::new(Some("xmlns"), "p"), "urn:p"));
        root.children = children;
        root
    })
}

proptest! {
    #[test]
    fn escaped_text_decodes_to_the_original(value in xml_string()) {
        let doc = parse_str(&format!("<a>{}</a>", escape_text(&value)), &limits()).unwrap();
        prop_assert_eq!(doc.root.text(), value);
    }

    #[test]
    fn escaped_attribute_values_decode_to_the_original(value in xml_string()) {
        let text = format!("<a v=\"{}\"/>", escape_attribute(&value));
        let doc = parse_str(&text, &limits()).unwrap();
        prop_assert_eq!(doc.root.attribute("v"), Some(value.as_str()));
    }

    #[test]
    fn written_trees_parse_back_to_a_fixed_point(root in tree()) {
        let first = write_document(&document(root)).unwrap();
        let parsed = parse_str(&first, &limits()).unwrap();
        let second = write_document(&parsed).unwrap();
        let reparsed = parse_str(&second, &limits()).unwrap();
        prop_assert_eq!(&reparsed, &parsed);
        prop_assert_eq!(write_document(&reparsed).unwrap(), second);
    }
}
