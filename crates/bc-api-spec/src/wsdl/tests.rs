//! The WSDL standard: detection, validation, completeness, preservation
//! and new documents.

use serde_json::json;

use super::*;
use crate::diagnostic::{Code, Severity};
use crate::libraries::ApiLibrary;

/// A complete WSDL 1.1 document/literal wrapped description.
pub(crate) const QUOTE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!-- Stock quotes -->
<wsdl:definitions xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/"
    xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
    xmlns:xsd="http://www.w3.org/2001/XMLSchema"
    xmlns:tns="urn:example:quote" targetNamespace="urn:example:quote">
  <wsdl:types>
    <xsd:schema targetNamespace="urn:example:quote" elementFormDefault="qualified">
      <xsd:element name="GetQuote"><xsd:complexType><xsd:sequence>
        <xsd:element name="symbol" type="xsd:string"/>
      </xsd:sequence></xsd:complexType></xsd:element>
      <xsd:element name="GetQuoteResponse"><xsd:complexType><xsd:sequence>
        <xsd:element name="price" type="xsd:decimal"/>
      </xsd:sequence></xsd:complexType></xsd:element>
    </xsd:schema>
  </wsdl:types>
  <wsdl:message name="GetQuoteRequest"><wsdl:part name="parameters" element="tns:GetQuote"/></wsdl:message>
  <wsdl:message name="GetQuoteResponse"><wsdl:part name="parameters" element="tns:GetQuoteResponse"/></wsdl:message>
  <wsdl:portType name="QuotePortType">
    <wsdl:operation name="GetQuote">
      <wsdl:input message="tns:GetQuoteRequest"/>
      <wsdl:output message="tns:GetQuoteResponse"/>
    </wsdl:operation>
  </wsdl:portType>
  <wsdl:binding name="QuoteBinding" type="tns:QuotePortType">
    <soap:binding style="document" transport="http://schemas.xmlsoap.org/soap/http"/>
    <wsdl:operation name="GetQuote">
      <soap:operation soapAction="urn:example:quote:GetQuote"/>
      <wsdl:input><soap:body use="literal"/></wsdl:input>
      <wsdl:output><soap:body use="literal"/></wsdl:output>
    </wsdl:operation>
  </wsdl:binding>
  <wsdl:service name="QuoteService">
    <wsdl:port name="QuotePort" binding="tns:QuoteBinding">
      <soap:address location="http://example.com/ws/quote"/>
    </wsdl:port>
  </wsdl:service>
</wsdl:definitions>
"#;

fn parse(text: &str) -> Value {
    WSDL.parse(text, Syntax::Xml).unwrap()
}

fn diagnostics(text: &str, peers: &[Peer<'_>]) -> Vec<(Severity, Code, String, String)> {
    WSDL.validate(&parse(text), peers)
        .into_iter()
        .map(|d| (d.severity, d.code, d.pointer, d.message))
        .collect()
}

fn pointers(text: &str) -> Vec<String> {
    diagnostics(text, &[]).into_iter().map(|d| d.2).collect()
}

fn op(path: &str) -> Operation {
    Operation::new("operation", path)
}

#[test]
fn names_nominate_wsdl_schema_and_soap_files() {
    for (path, strength) in [
        (
            "src/main/resources/wsdl/Quote.WSDL",
            Some(NameStrength::Strong),
        ),
        ("xsd/common.xsd", Some(NameStrength::Weak)),
        ("Quote.wsdl.xml", Some(NameStrength::Weak)),
        ("soap-service.xml", Some(NameStrength::Weak)),
        ("pom.xml", None),
        ("wsdl", None),
        ("quote.json", None),
    ] {
        assert_eq!(WSDL.candidate_strength(path), strength, "{path}");
    }
}

#[test]
fn content_decides_what_a_candidate_is() {
    let classify = |path: &str, text: &str| WSDL.classify(path, text.as_bytes(), 1 << 20);
    assert!(matches!(
        classify("quote.wsdl", QUOTE),
        Candidate::Spec {
            syntax: Syntax::Xml,
            version: Some(SpecVersion::Wsdl11),
            ..
        }
    ));
    let schema = classify(
        "common.xsd",
        r#"<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"/>"#,
    );
    let parts = schema.into_parts().unwrap().unwrap();
    assert_eq!(parts.version, None);
    assert!(WSDL.supporting(&parts.document.unwrap()));
    assert!(!WSDL.supporting(&parse(QUOTE)));
    // A DOCTYPE is refused: no entity is ever declared or fetched.
    let doctype = "<!DOCTYPE d [<!ENTITY x SYSTEM \"http://example.com/\">]><d/>";
    let refused = classify("quote.wsdl", doctype);
    assert!(matches!(&refused, Candidate::Unverifiable { reason } if reason.contains("DOCTYPE")));
    assert_eq!(classify("common.xsd", doctype), Candidate::NotASpec);
    let mentions = format!("<d xmlns='{}'>", model::WSDL11);
    assert!(matches!(
        classify("soap-quote.xml", &mentions),
        Candidate::Unverifiable { .. }
    ));
    assert!(matches!(
        classify("quote.wsdl", "<project/>"),
        Candidate::Unverifiable { reason } if reason.contains("not a WSDL 1.1 definitions")
    ));
    assert_eq!(
        classify("soap-config.xml", "<project/>"),
        Candidate::NotASpec
    );
    assert_eq!(classify("pom.xml", QUOTE), Candidate::NotASpec);
    assert!(matches!(
        WSDL.classify("quote.wsdl", QUOTE.as_bytes(), 16),
        Candidate::Unverifiable { reason } if reason.contains("16-byte")
    ));
    assert_eq!(
        WSDL.classify("types.xsd", QUOTE.as_bytes(), 16),
        Candidate::NotASpec
    );
    assert!(matches!(
        WSDL.classify("quote.wsdl", &[0xff], 16),
        Candidate::Unverifiable { .. }
    ));
    assert_eq!(WSDL.classify("types.xsd", &[0xff], 16), Candidate::NotASpec);
}

#[test]
fn parsing_refuses_what_it_cannot_read_and_what_is_not_wsdl() {
    assert!(matches!(
        WSDL.parse("<!DOCTYPE d><d/>", Syntax::Xml),
        Err(ParseFailure::Unverifiable(_))
    ));
    assert!(matches!(
        WSDL.parse("<project/>", Syntax::Xml),
        Err(ParseFailure::Malformed(_))
    ));
    assert_eq!(WSDL.version(&parse(QUOTE)), Some(SpecVersion::Wsdl11));
    assert_eq!(WSDL.version(&json!({})), None);
}

#[test]
fn a_complete_description_has_no_diagnostics() {
    assert_eq!(diagnostics(QUOTE, &[]), []);
    assert_eq!(WSDL.name(), "WSDL");
    assert_eq!(WSDL.id(), FormatId::Wsdl);
    assert_eq!(WSDL.capabilities(), Capabilities::FULL);
    assert!(!WSDL.scans_source() && WSDL.scan_source("a.java", "@WebService").is_empty());
}

/// A WSDL 1.1 description breaking most rules once.
const BROKEN_11: &str = r#"<definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
    xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
    xmlns:http="http://schemas.xmlsoap.org/wsdl/http/"
    xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:tns="urn:b" targetNamespace="urn:b">
  <import namespace="urn:remote" location="https://example.com/remote.wsdl"/>
  <import namespace="urn:gone" location="../gone.wsdl"/>
  <import namespace="urn:nowhere"/>
  <types>
    <xsd:schema targetNamespace="urn:b">
      <xsd:import namespace="urn:unknown"/>
      <xsd:import namespace="http://schemas.xmlsoap.org/soap/encoding/"/>
      <xsd:element name="A"/>
    </xsd:schema>
  </types>
  <message name="M">
    <part name="p1" element="tns:Missing"/>
    <part name="p2" type="xsd:notAType"/>
    <part name="p3"/>
    <part name="p4" element="tns:A" type="xsd:string"/>
    <part name="p5" element="zz:A"/>
    <part name="p5" element="xsd:string"/>
    <part name="p6" type="tns:Remote"/>
    <part name="p7" element="rem:X" xmlns:rem="urn:remote"/>
  </message>
  <message name="M"/>
  <message/>
  <portType name="P">
    <operation name="Get"><input message="tns:Nope"/><fault name="f"/></operation>
    <operation name="Get"><output message="tns:M"/><fault name="g" message="tns:M"/></operation>
    <operation name="Empty"/>
  </portType>
  <binding name="NoProtocol" type="tns:P"><operation name="Get"/></binding>
  <binding name="Soap" type="tns:P">
    <soap:binding style="fancy"/>
    <operation name="Get"><soap:operation/><input><soap:body use="encoded"/></input></operation>
    <operation name="Other"/>
    <operation/>
  </binding>
  <binding name="Http" type="tns:P"><http:binding/></binding>
  <binding name="Unbound"/>
  <binding name="Lost" type="tns:Q"/>
  <service name="S">
    <port name="A" binding="tns:Soap"><soap:address location="https://user:pw@example.com/ws"/></port>
    <port name="A" binding="tns:Missing"/>
    <port name="B"/>
  </service>
</definitions>"#;

#[test]
fn a_broken_wsdl_11_description_reports_each_problem() {
    let found = diagnostics(BROKEN_11, &[]);
    let expected: &[(Severity, Code, &str)] = &[
        (
            Severity::Warning,
            Code::ExternalRef,
            "/imports/https:~1~1example.com~1remote.wsdl",
        ),
        (
            Severity::Error,
            Code::UnresolvedRef,
            "/imports/..~1gone.wsdl",
        ),
        (Severity::Error, Code::MissingField, "/imports/urn:nowhere"),
        (
            Severity::Warning,
            Code::UnresolvedRef,
            "/schemas/0/imports/urn:unknown",
        ),
        (Severity::Error, Code::DuplicateDefinition, "/messages/M"),
        (Severity::Error, Code::MissingField, "/messages/"),
        (
            Severity::Error,
            Code::DuplicateDefinition,
            "/messages/M/parts/p5",
        ),
        (Severity::Error, Code::UnknownType, "/messages/M/parts/p1"),
        (Severity::Error, Code::UnknownType, "/messages/M/parts/p2"),
        (Severity::Error, Code::MissingField, "/messages/M/parts/p3"),
        (Severity::Error, Code::InvalidType, "/messages/M/parts/p4"),
        (Severity::Error, Code::UnresolvedRef, "/messages/M/parts/p5"),
        (Severity::Error, Code::UnknownType, "/messages/M/parts/p5"),
        (Severity::Error, Code::UnknownType, "/messages/M/parts/p6"),
        (
            Severity::Warning,
            Code::DuplicateDefinition,
            "/portTypes/P/operations/Get",
        ),
        (
            Severity::Error,
            Code::UnresolvedRef,
            "/portTypes/P/operations/Get",
        ),
        (
            Severity::Error,
            Code::MissingField,
            "/portTypes/P/operations/Get",
        ),
        (
            Severity::Error,
            Code::MissingField,
            "/portTypes/P/operations/Empty",
        ),
        (
            Severity::Error,
            Code::InvalidBinding,
            "/bindings/NoProtocol",
        ),
        (
            Severity::Warning,
            Code::MissingField,
            "/bindings/NoProtocol",
        ),
        (Severity::Error, Code::InvalidBinding, "/bindings/Soap"),
        (Severity::Error, Code::InvalidBinding, "/bindings/Soap"),
        (Severity::Warning, Code::InvalidBinding, "/bindings/Soap"),
        (
            Severity::Error,
            Code::MissingField,
            "/bindings/Soap/operations/",
        ),
        (
            Severity::Error,
            Code::UnresolvedRef,
            "/bindings/Soap/operations/Other",
        ),
        (Severity::Warning, Code::MissingField, "/bindings/Soap"),
        (Severity::Error, Code::InvalidBinding, "/bindings/Http"),
        (Severity::Warning, Code::MissingField, "/bindings/Http"),
        (Severity::Warning, Code::MissingField, "/bindings/Http"),
        (Severity::Error, Code::MissingField, "/bindings/Unbound"),
        (Severity::Error, Code::InvalidBinding, "/bindings/Unbound"),
        (Severity::Error, Code::UnresolvedRef, "/bindings/Lost"),
        (Severity::Error, Code::InvalidBinding, "/bindings/Lost"),
        (
            Severity::Error,
            Code::DuplicateDefinition,
            "/services/S/ports/A",
        ),
        (Severity::Error, Code::InvalidServer, "/services/S/ports/A"),
        (Severity::Error, Code::UnresolvedRef, "/services/S/ports/A"),
        (Severity::Error, Code::MissingField, "/services/S/ports/A"),
        (Severity::Error, Code::MissingField, "/services/S/ports/B"),
        (Severity::Error, Code::MissingField, "/services/S/ports/B"),
    ];
    let found_keys: Vec<(Severity, Code, &str)> = found
        .iter()
        .map(|(severity, code, pointer, _)| (*severity, *code, pointer.as_str()))
        .collect();
    assert_eq!(found_keys, expected, "{found:#?}");
    let messages: Vec<&str> = found.iter().map(|d| d.3.as_str()).collect();
    for fragment in [
        "was not fetched",
        "not found among the repository's readable WSDL and XML Schema files",
        "a WSDL import needs a location",
        "without a schemaLocation",
        "element `{urn:b}Missing` is not declared",
        "type `{http://www.w3.org/2001/XMLSchema}notAType`",
        "`zz:A` is not a qualified name",
        "WS-I Basic Profile forbids overloading",
        "a required qualified-name reference is missing",
        "has neither an input nor an output",
        "declares no SOAP 1.1, SOAP 1.2 or HTTP binding",
        "needs a transport",
        "style `fancy` is neither document nor rpc",
        "uses encoded bodies",
        "`Other` is not an operation of portType `P`",
        "operation `Empty` of portType `P` is not bound",
        "HTTP binding `Http` needs a verb",
        "needs a `type` attribute",
        "embeds credentials",
        "port `A` needs an address location",
        "port `B` needs a binding",
    ] {
        assert!(
            messages.iter().any(|message| message.contains(fragment)),
            "{fragment}"
        );
    }
}

#[test]
fn a_description_without_port_types_describes_nothing() {
    let empty =
        r#"<definitions xmlns="http://schemas.xmlsoap.org/wsdl/" targetNamespace="urn:e"/>"#;
    assert_eq!(pointers(empty), ["/portTypes"]);
    // Without a target namespace WSDL 1.1 warns and WSDL 2.0 fails.
    let untargeted = diagnostics(
        r#"<definitions xmlns="http://schemas.xmlsoap.org/wsdl/"/>"#,
        &[],
    );
    assert_eq!(untargeted[0].0, Severity::Warning);
    assert_eq!(untargeted[0].2, "/targetNamespace");
    let untargeted = diagnostics(r#"<description xmlns="http://www.w3.org/ns/wsdl"/>"#, &[]);
    assert_eq!(untargeted[0].0, Severity::Error);
    assert!(untargeted[0]
        .3
        .contains("a WSDL 2.0 description needs a targetNamespace"));
    assert_eq!(untargeted[1].2, "/interfaces");
    let rpc = QUOTE.replace("style=\"document\"", "style=\"rpc\"");
    assert_eq!(pointers(&rpc), Vec::<String>::new());
    let unstyled = QUOTE.replace(" style=\"document\"", "");
    assert_eq!(pointers(&unstyled), ["/bindings/QuoteBinding"]);
    let per_operation = unstyled.replace(
        "<soap:operation soapAction",
        "<soap:operation style=\"document\" soapAction",
    );
    assert_eq!(pointers(&per_operation), Vec::<String>::new());
}

/// A WSDL 2.0 description with an XML Schema imported from the
/// repository.
const QUOTE_20: &str = r##"<description xmlns="http://www.w3.org/ns/wsdl"
    xmlns:tns="urn:example:quote" xmlns:q="urn:example:types"
    xmlns:wsoap="http://www.w3.org/ns/wsdl/soap" targetNamespace="urn:example:quote">
  <types>
    <xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema" targetNamespace="urn:example:quote">
      <xs:import namespace="urn:example:types" schemaLocation="../xsd/types.xsd"/>
      <xs:element name="Fault"/>
    </xs:schema>
  </types>
  <interface name="Base"><fault name="Busy" element="#any"/></interface>
  <interface name="Quote" extends="tns:Base">
    <fault name="Bad" element="tns:Fault"/>
    <operation name="Get" pattern="http://www.w3.org/ns/wsdl/in-out">
      <input element="q:GetQuote"/>
      <output element="q:GetQuoteResponse"/>
      <outfault ref="tns:Bad"/>
      <outfault ref="tns:Busy"/>
    </operation>
  </interface>
  <binding name="QuoteSoap" interface="tns:Quote" type="http://www.w3.org/ns/wsdl/soap"
      wsoap:protocol="http://www.w3.org/2003/05/soap/bindings/HTTP/">
    <operation ref="tns:Get"/>
  </binding>
  <service name="QuoteService" interface="tns:Quote">
    <endpoint name="QuoteEndpoint" binding="tns:QuoteSoap" address="http://example.com/quote"/>
  </service>
</description>"##;

const TYPES_XSD: &str = r#"<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema" targetNamespace="urn:example:types">
  <xs:element name="GetQuote"/><xs:element name="GetQuoteResponse"/>
</xs:schema>"#;

#[test]
fn a_wsdl_20_description_with_an_imported_schema_validates() {
    let types = parse(TYPES_XSD);
    let peers = [Peer {
        path: "svc/src/main/resources/xsd/types.xsd",
        document: &types,
    }];
    assert_eq!(diagnostics(QUOTE_20, &peers), []);
    assert_eq!(WSDL.version(&parse(QUOTE_20)), Some(SpecVersion::Wsdl20));
    // Without the schema file the import and what it declares fail.
    let alone: Vec<(Code, String)> = diagnostics(QUOTE_20, &[])
        .into_iter()
        .map(|d| (d.1, d.2))
        .collect();
    assert_eq!(
        alone,
        [(
            Code::UnresolvedRef,
            "/schemas/0/imports/..~1xsd~1types.xsd".to_string()
        )]
    );
    // The XML Schema itself is checked only for its own imports.
    assert_eq!(WSDL.validate(&types, &[]), []);
}

#[test]
fn a_remote_import_is_recorded_as_unverifiable_and_never_followed() {
    let remote = QUOTE_20.replace("../xsd/types.xsd", "https://example.com/types.xsd");
    let found = diagnostics(&remote, &[]);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].0, Severity::Warning);
    assert_eq!(found[0].1, Code::ExternalRef);
    assert!(found[0]
        .3
        .contains("was not fetched; what it declares is unverified"));
}

const BROKEN_20: &str = r##"<description xmlns="http://www.w3.org/ns/wsdl"
    xmlns:tns="urn:q" xmlns:wsoap="http://www.w3.org/ns/wsdl/soap" targetNamespace="urn:q">
  <interface name="Loop" extends="tns:Loop2"/>
  <interface name="Loop2" extends="tns:Loop tns:Missing"/>
  <interface name="Q">
    <fault name="F" element="tns:Undeclared"/>
    <operation name="Get"><input element="#any"/><outfault ref="tns:Nope"/><infault ref="zz:X"/></operation>
    <operation name="Get"><input element="#none"/></operation>
  </interface>
  <binding name="NoType" interface="tns:Q"><operation ref="tns:Get"/><operation ref="tns:Get"/><operation ref="tns:Put"/><operation ref="zz:X"/></binding>
  <binding name="NoProtocol" interface="tns:Q" type="http://www.w3.org/ns/wsdl/soap"><operation ref="tns:Get"/></binding>
  <binding name="Http" interface="tns:Loop" type="http://www.w3.org/ns/wsdl/http"/>
  <service name="S"><endpoint name="E" binding="tns:Http"/></service>
  <service name="T" interface="tns:Q"><endpoint name="E" binding="tns:NoType"/></service>
</description>"##;

#[test]
fn a_broken_wsdl_20_description_reports_each_problem() {
    let found = diagnostics(BROKEN_20, &[]);
    let keys: Vec<(Severity, Code, &str)> = found
        .iter()
        .map(|(severity, code, pointer, _)| (*severity, *code, pointer.as_str()))
        .collect();
    assert_eq!(
        keys,
        [
            (Severity::Error, Code::UnresolvedRef, "/interfaces/Loop2"),
            (Severity::Error, Code::UnknownType, "/interfaces/Q/faults/F"),
            (
                Severity::Error,
                Code::DuplicateDefinition,
                "/interfaces/Q/operations/Get"
            ),
            (
                Severity::Error,
                Code::UnresolvedRef,
                "/interfaces/Q/operations/Get"
            ),
            (
                Severity::Error,
                Code::UnresolvedRef,
                "/interfaces/Q/operations/Get"
            ),
            (Severity::Error, Code::MissingField, "/bindings/NoType"),
            (
                Severity::Error,
                Code::DuplicateDefinition,
                "/bindings/NoType/operations/Get"
            ),
            (
                Severity::Error,
                Code::UnresolvedRef,
                "/bindings/NoType/operations/Put"
            ),
            (
                Severity::Error,
                Code::UnresolvedRef,
                "/bindings/NoType/operations/zz:X"
            ),
            (
                Severity::Error,
                Code::InvalidBinding,
                "/bindings/NoProtocol"
            ),
            (Severity::Error, Code::MissingField, "/services/S"),
            (
                Severity::Error,
                Code::InvalidBinding,
                "/services/S/endpoints/E"
            ),
        ],
        "{found:#?}"
    );
    let messages: Vec<&str> = found.iter().map(|d| d.3.as_str()).collect();
    for fragment in [
        "names no interface",
        "fault reference `Nope` names no fault of interface `Q`",
        "needs a `type`",
        "needs a wsoap:protocol",
        "service `S` needs an `interface`",
        "uses a binding of another interface",
    ] {
        assert!(
            messages.iter().any(|message| message.contains(fragment)),
            "{fragment}"
        );
    }
}

#[test]
fn operations_are_port_type_operations_compared_by_name() {
    let document = parse(QUOTE);
    assert_eq!(WSDL.operations(&document), [op("QuotePortType/GetQuote")]);
    let other = parse(&QUOTE.replace("QuotePortType", "AdminPortType").replace(
        "name=\"GetQuote\">\n      <wsdl:input",
        "name=\"Ping\">\n      <wsdl:input",
    ));
    let peers = [Peer {
        path: "admin.wsdl",
        document: &other,
    }];
    let inventory = [
        op("GetQuote"),
        op("AdminPortType/Ping"),
        op("QuotePortType/Missing"),
    ];
    let result = WSDL.compare(&document, &peers, &inventory);
    assert_eq!(result.missing, [op("QuotePortType/Missing")]);
    assert!(result.unverified.is_empty());
    let stale = WSDL.compare(&document, &[], &[op("Other/GetQuote")]);
    assert_eq!(stale.unverified, [op("QuotePortType/GetQuote")]);
    assert!(WSDL
        .operations(&json!({"interfaces": [{"name": "", "operations": [{"name": "x"}]}]}))
        .is_empty());
}

#[test]
fn inventory_entries_are_operations() {
    assert_eq!(
        WSDL.inventory_operation(" Operation ", " QuotePortType/GetQuote ")
            .unwrap(),
        op("QuotePortType/GetQuote")
    );
    assert_eq!(
        WSDL.inventory_operation("operation", "GetQuote").unwrap(),
        op("GetQuote")
    );
    assert!(WSDL
        .inventory_operation("post", "GetQuote")
        .unwrap_err()
        .contains("is not operation"));
    for path in ["", "a/b/c", "1a", "/GetQuote", "a b"] {
        assert!(WSDL
            .inventory_operation("operation", path)
            .unwrap_err()
            .contains("is not `PortType/operation`"));
    }
}

#[test]
fn a_repair_keeps_the_version_prefixes_and_definitions() {
    let original = parse(QUOTE);
    let added = QUOTE.replace(
        "  </wsdl:portType>",
        "    <wsdl:operation name=\"Ping\"><wsdl:input message=\"tns:GetQuoteRequest\"/></wsdl:operation>\n  </wsdl:portType>",
    );
    assert!(WSDL.preservation(&original, &parse(&added), &[]).is_empty());
    let check = |text: &str| WSDL.preservation(&original, &parse(text), &[]);
    assert_eq!(
        check(
            &QUOTE
                .replace(
                    "xmlns:tns=\"urn:example:quote\" ",
                    "xmlns:q=\"urn:example:quote\" "
                )
                .replace("tns:", "q:")
        ),
        ["removed or rebound the namespace prefix `tns`; repairs keep the author's prefixes"]
    );
    assert_eq!(
        check(&QUOTE.replace(
            "targetNamespace=\"urn:example:quote\">\n  <wsdl:types>",
            "targetNamespace=\"urn:other\">\n  <wsdl:types>"
        )),
        ["changed the targetNamespace, which had no diagnostics"]
    );
    let dropped = check(&QUOTE.replace(
        "<xsd:element name=\"GetQuoteResponse\">",
        "<xsd:element name=\"Renamed\">",
    ));
    assert_eq!(
        dropped,
        ["removed schema element `{urn:example:quote}GetQuoteResponse`"]
    );
    let renamed = check(&QUOTE.replace("wsdl:port name=\"QuotePort\"", "wsdl:port name=\"Port\""));
    assert_eq!(
        renamed,
        ["removed documented port `QuoteService.QuotePort`"]
    );
    let converted = WSDL.preservation(&original, &parse(QUOTE_20), &[]);
    assert_eq!(converted.len(), 1);
    assert!(converted[0].contains("1.1 stays 1.1"));
    // WSDL 2.0 sections, and imports.
    let original = parse(QUOTE_20);
    let changed = parse(
        &QUOTE_20
            .replace(
                "schemaLocation=\"../xsd/types.xsd\"",
                "schemaLocation=\"types.xsd\"",
            )
            .replace("name=\"QuoteEndpoint\"", "name=\"Endpoint\""),
    );
    assert_eq!(
        WSDL.preservation(&original, &changed, &[]),
        ["removed documented endpoint `QuoteService.QuoteEndpoint`"]
    );
    let imports = json!({"version": "2.0", "imports": [{"location": "a.wsdl"}]});
    assert_eq!(
        WSDL.preservation(&imports, &json!({"version": "2.0"}), &[]),
        ["removed the import of `a.wsdl`"]
    );
    let before = [Diagnostic::error(
        Code::MissingField,
        "/targetNamespace",
        "",
    )];
    let untargeted = parse(&QUOTE.replace(
        " targetNamespace=\"urn:example:quote\">\n  <wsdl:types>",
        ">\n  <wsdl:types>",
    ));
    assert!(WSDL
        .preservation(&untargeted, &parse(QUOTE), &before)
        .is_empty());
}

#[test]
fn a_new_document_is_wsdl_11_document_literal_wrapped() {
    assert!(WSDL.new_document_problems(&parse(QUOTE)).is_empty());
    assert_eq!(
        WSDL.new_document_problems(&parse(QUOTE_20)),
        ["a new WSDL document must be WSDL 1.1 (http://schemas.xmlsoap.org/wsdl/)"]
    );
    let rpc = QUOTE
        .replace("style=\"document\"", "style=\"rpc\"")
        .replace(
            " targetNamespace=\"urn:example:quote\">\n  <wsdl:types>",
            ">\n  <wsdl:types>",
        )
        .replace(
            "<wsdl:part name=\"parameters\" element=\"tns:GetQuote\"/>",
            "<wsdl:part name=\"symbol\" type=\"xsd:string\"/>",
        );
    assert_eq!(
        WSDL.new_document_problems(&parse(&rpc)),
        [
            "a new WSDL document needs a targetNamespace",
            "binding `QuoteBinding` must be document/literal: style document and use literal throughout",
            "message `GetQuoteRequest` must have exactly one part that references an element (document/literal wrapped)",
        ]
    );
    let abstract_only = r#"<definitions xmlns="http://schemas.xmlsoap.org/wsdl/" targetNamespace="urn:a"><binding name="H"><http:binding xmlns:http="http://schemas.xmlsoap.org/wsdl/http/" verb="GET"/></binding></definitions>"#;
    assert_eq!(
        WSDL.new_document_problems(&parse(abstract_only)),
        [
            "a new WSDL document needs a binding and a service with a port",
            "binding `H` must be a SOAP binding",
        ]
    );
    let encoded = QUOTE.replace("use=\"literal\"", "use=\"encoded\"");
    assert_eq!(WSDL.new_document_problems(&parse(&encoded)).len(), 1);
}

#[test]
fn new_documents_are_emitted_as_the_generators_text() {
    assert_eq!(
        WSDL.emit(&json!(format!("{QUOTE}\n\n")), Syntax::Xml)
            .unwrap(),
        QUOTE
    );
    assert!(WSDL
        .emit(&json!({"definitions": {}}), Syntax::Xml)
        .unwrap_err()
        .contains("WSDL text"));
}

#[test]
fn owners_are_services_with_a_soap_server() {
    let surfaces = [
        ApiSurface {
            root: "svc".into(),
            manifests: vec!["svc/pom.xml".into()],
            libraries: [ApiLibrary::JaxWs, ApiLibrary::Kafka].into_iter().collect(),
        },
        ApiSurface {
            root: "events".into(),
            manifests: vec![],
            libraries: [ApiLibrary::Kafka].into_iter().collect(),
        },
    ];
    let owners = WSDL.owners(&[], &surfaces);
    assert_eq!(owners.len(), 1);
    assert_eq!(owners[0].stack, ["jax_ws"]);
    assert_eq!(
        owners[0].convention.path,
        "src/main/resources/wsdl/service.wsdl"
    );
    assert!(owners[0].convention.code_first);
    assert_eq!(WSDL.fallback().path, "wsdl/service.wsdl");
    assert_eq!(
        WSDL.document_capabilities(Some(SpecVersion::Wsdl20)),
        Capabilities::FULL
    );
}
