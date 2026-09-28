//! Round trips and queries over a small corpus of realistic documents.
//! Every file under `tests/fixtures` is hand-written test data, labeled as
//! such in its first comment; none of it describes a real service.

use bc_xml::{
    apply_span_edits, parse_str, write_document, Document, Limits, Node, QName, SpanEdit,
};

const WSDL: &str = "http://schemas.xmlsoap.org/wsdl/";
const WSDL2: &str = "http://www.w3.org/ns/wsdl";
const XSD: &str = "http://www.w3.org/2001/XMLSchema";
const EDMX: &str = "http://docs.oasis-open.org/odata/ns/edmx";
const EDM: &str = "http://docs.oasis-open.org/odata/ns/edm";

const WSDL11_TEXT: &str = include_str!("fixtures/stock-quote.wsdl");
const WSDL20_TEXT: &str = include_str!("fixtures/reservation.wsdl2.xml");
const XSD_TEXT: &str = include_str!("fixtures/purchase-order.xsd");
const EDMX_TEXT: &str = include_str!("fixtures/trippin.edmx.xml");
const SOAP_TEXT: &str = include_str!("fixtures/get-quote.soap11.xml");

const CORPUS: [&str; 5] = [WSDL11_TEXT, WSDL20_TEXT, XSD_TEXT, EDMX_TEXT, SOAP_TEXT];

fn parse(text: &str) -> Document {
    parse_str(text, &Limits::new(1 << 20)).unwrap()
}

#[test]
fn every_fixture_round_trips_through_the_writer() {
    for text in CORPUS {
        let parsed = parse(text);
        let written = write_document(&parsed).unwrap();
        assert_eq!(parse(&written), parsed);
        // The writer is deterministic: a second pass is byte-identical.
        assert_eq!(write_document(&parse(&written)).unwrap(), written);
        // Every fixture opens with its TEST FIXTURE ONLY label.
        let label = parsed.prolog.iter().find_map(|node| match node {
            Node::Comment(text) => Some(text.as_str()),
            _ => None,
        });
        assert!(label.unwrap().contains("TEST FIXTURE ONLY"));
    }
}

#[test]
fn wsdl_1_1_operations_resolve_their_messages_across_prefixes() {
    let doc = parse(WSDL11_TEXT);
    let root = &doc.root;
    assert!(root.is_named(Some(WSDL), "definitions"));
    let schema = root
        .first_child_named(Some(WSDL), "types")
        .and_then(|types| types.first_child_named(Some(XSD), "schema"))
        .unwrap();
    let elements: Vec<_> = schema
        .children_named(Some(XSD), "element")
        .filter_map(|e| e.attribute("name"))
        .collect();
    assert_eq!(elements, ["TradePriceRequest", "TradePrice"]);
    let input = root
        .descendants_named(Some(WSDL), "input")
        .find_map(|input| input.attribute("message").map(|m| (input, m)))
        .unwrap();
    let message = input.0.resolve_qname_value(input.1).unwrap();
    assert_eq!(message.namespace, root.attribute("targetNamespace"));
    assert_eq!(message.local, "GetLastTradePriceInput");
    let address = root
        .descendants()
        .find(|e| e.name.local == "address")
        .unwrap();
    assert_eq!(
        address.attribute("location"),
        Some("https://example.com/stockquote?a=1&b=2")
    );
}

#[test]
fn wsdl_2_0_uses_the_default_namespace() {
    let doc = parse(WSDL20_TEXT);
    let interface = doc
        .root
        .first_child_named(Some(WSDL2), "interface")
        .unwrap();
    let operation = interface
        .first_child_named(Some(WSDL2), "operation")
        .unwrap();
    assert_eq!(
        operation.attribute_ns(Some("http://www.w3.org/ns/wsdl-extensions"), "safe"),
        Some("true")
    );
    let schema = doc
        .root
        .descendants_named(Some(XSD), "schema")
        .next()
        .unwrap();
    let element = schema.first_child_named(Some(XSD), "element").unwrap();
    let type_name = element
        .resolve_qname_value(element.attribute("type").unwrap())
        .unwrap();
    assert_eq!(
        type_name.namespace,
        Some("http://example.com/reservation/schema")
    );
    let documentation = doc
        .root
        .first_child_named(Some(WSDL2), "documentation")
        .unwrap();
    assert!(documentation
        .text()
        .contains("<quoted> per night & exclude"));
}

#[test]
fn xsd_and_csdl_are_walkable_by_expanded_name() {
    let doc = parse(XSD_TEXT);
    let types: Vec<_> = doc
        .root
        .children_named(Some(XSD), "complexType")
        .filter_map(|e| e.attribute("name"))
        .collect();
    assert_eq!(types, ["PurchaseOrderType", "USAddress", "Items"]);

    let doc = parse(EDMX_TEXT);
    assert!(doc.root.is_named(Some(EDMX), "Edmx"));
    let entity_types: Vec<_> = doc
        .root
        .descendants_named(Some(EDM), "EntityType")
        .filter_map(|e| e.attribute("Name"))
        .collect();
    assert_eq!(entity_types, ["Person", "Trip"]);
}

#[test]
fn a_repair_is_a_minimal_diff_of_the_original_text() {
    let doc = parse(WSDL11_TEXT);
    let service = doc.root.first_child_named(Some(WSDL), "service").unwrap();
    let port = service.first_child_named(Some(WSDL), "port").unwrap();
    let documentation = "\n      <wsdl:documentation>Primary endpoint</wsdl:documentation>";
    let edits = [
        SpanEdit::prepend_child(port, documentation).unwrap(),
        SpanEdit::set_attribute(port, &QName::new(None, "name"), "PrimaryPort").unwrap(),
    ];
    let repaired = apply_span_edits(WSDL11_TEXT, &edits).unwrap();
    let expected = WSDL11_TEXT.replace(
        "<wsdl:port name=\"StockQuotePort\" binding=\"tns:StockQuoteSoapBinding\">",
        &format!(
            "<wsdl:port name=\"PrimaryPort\" binding=\"tns:StockQuoteSoapBinding\">{documentation}"
        ),
    );
    assert_eq!(repaired, expected);
    let reparsed = parse(&repaired);
    let port = reparsed
        .root
        .descendants_named(Some(WSDL), "port")
        .next()
        .unwrap();
    assert_eq!(port.attribute("name"), Some("PrimaryPort"));
    assert_eq!(
        port.first_child_named(Some(WSDL), "documentation")
            .unwrap()
            .text(),
        "Primary endpoint"
    );
}
