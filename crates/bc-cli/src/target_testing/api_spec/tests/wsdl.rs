//! The WSDL standard end to end: the same outcomes as OpenAPI, minus
//! relocation (no SOAP library reads a WSDL from a fixed place).

use bc_api_spec::diagnostic::Code;

use super::*;

const SERVICE: &str = "src/main/java/com/example/QuoteService.java";
const WSDL_PATH: &str = "src/main/resources/wsdl/service.wsdl";

/// A JAX-WS service (no HTTP framework, so OpenAPI stays out) with one
/// operation and no WSDL.
fn soap_repo() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    write(
        root.path(),
        "pom.xml",
        "<project><dependency><artifactId>jakarta.xml.ws-api</artifactId></dependency></project>\n",
    );
    write(
        root.path(),
        SERVICE,
        "package com.example;\n\nimport jakarta.jws.WebMethod;\nimport jakarta.jws.WebService;\n\n@WebService(name = \"QuotePortType\", serviceName = \"QuoteService\")\npublic class QuoteService {\n    @WebMethod(operationName = \"GetQuote\")\n    public java.math.BigDecimal getQuote(String symbol) { return null; }\n}\n",
    );
    root
}

fn soap_inventory() -> serde_json::Value {
    json!([{"method": "operation", "path": "QuotePortType/GetQuote", "file": SERVICE, "line": 8,
            "snippet": "@WebMethod(operationName = \"GetQuote\")"}])
}

/// A complete WSDL 1.1 document/literal wrapped description of it.
const QUOTE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!-- Stock quotes: document/literal wrapped -->
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

const TRANSPORT: &str = " transport=\"http://schemas.xmlsoap.org/soap/http\"";

/// The same description with the SOAP binding's transport missing.
fn broken() -> String {
    QUOTE.replace(TRANSPORT, "")
}

fn transport_repair() -> serde_json::Value {
    json!([{"old": "<soap:binding style=\"document\"/>",
            "new": "<soap:binding style=\"document\" transport=\"http://schemas.xmlsoap.org/soap/http\"/>"}])
}

fn soap_reply(decision: &str, edits: serde_json::Value) -> String {
    json!({"decision": decision, "edits": edits, "inventory": soap_inventory()}).to_string()
}

fn only_wsdl(assurance: &Assurance) -> &SpecOutcome {
    let outcome = only(assurance);
    assert_eq!(outcome.spec_format, FormatId::Wsdl);
    outcome
}

#[tokio::test]
async fn a_missing_wsdl_is_created_as_a_document_literal_snapshot() {
    let root = soap_repo();
    let reply = json!({"decision": "create", "document": QUOTE, "inventory": soap_inventory(),
                       "changes": ["documented GetQuote"]})
    .to_string();
    let client = Client::texts(&[reply, review(true)]);
    let assurance = run_step(root.path(), &config(), &client).await;
    let outcome = only_wsdl(&assurance);
    assert_eq!(outcome.action, SpecAction::Created);
    assert_eq!(outcome.path, WSDL_PATH);
    assert_eq!(outcome.syntax, Some(Syntax::Xml));
    assert_eq!(outcome.frameworks, ["jax_ws"]);
    assert_eq!(read(root.path(), WSDL_PATH), QUOTE);
    assert!(client.prompt(0).contains("\"state\":\"missing\""));
    assert!(client.prompt(0).contains("\"code_first\""));
    assert!(client
        .prompt(1)
        .contains(&format!("Create {WSDL_PATH} (Xml)")));
    assert!(assurance.approved_bytes.contains_key(WSDL_PATH));
    let gap = outcome.gaps.last().unwrap();
    assert!(
        gap.contains("jax_ws build this WSDL document from code"),
        "{gap}"
    );
}

#[tokio::test]
async fn a_new_wsdl_must_be_document_literal_wrapped() {
    let root = soap_repo();
    let rpc = QUOTE.replace("style=\"document\"", "style=\"rpc\"");
    let reply =
        json!({"decision": "create", "document": rpc, "inventory": soap_inventory()}).to_string();
    let client = Client::texts(&[reply.clone(), reply.clone(), reply]);
    let assurance = run_step(root.path(), &config(), &client).await;
    let outcome = only_wsdl(&assurance);
    assert_eq!(outcome.action, SpecAction::Rejected);
    assert!(outcome
        .gaps
        .last()
        .unwrap()
        .contains("must be document/literal"));
    assert!(!root.path().join(WSDL_PATH).exists());
}

#[tokio::test]
async fn a_service_that_serves_no_soap_gets_no_wsdl() {
    let root = soap_repo();
    let reply = json!({"decision": "not_applicable", "inventory": []}).to_string();
    let client = Client::texts(&[reply]);
    let assurance = run_step(root.path(), &config(), &client).await;
    let outcome = only_wsdl(&assurance);
    assert_eq!(outcome.action, SpecAction::Skipped);
    assert!(outcome.gaps[0].contains("no WSDL operations"));
    assert!(!root.path().join(WSDL_PATH).exists());
}

#[tokio::test]
async fn a_valid_complete_wsdl_is_left_unchanged() {
    let root = soap_repo();
    write(root.path(), WSDL_PATH, QUOTE);
    let client = Client::texts(&[soap_reply("no_change", json!([])), review(true)]);
    let assurance = run_step(root.path(), &config(), &client).await;
    let outcome = only_wsdl(&assurance);
    assert_eq!(outcome.action, SpecAction::Complete);
    assert_eq!(outcome.version, Some(SpecVersion::Wsdl11));
    assert!(outcome.diagnostics_before.is_empty());
    assert_eq!(read(root.path(), WSDL_PATH), QUOTE);
}

#[tokio::test]
async fn a_broken_wsdl_is_repaired_with_a_minimal_edit() {
    let root = soap_repo();
    write(root.path(), WSDL_PATH, &broken());
    let client = Client::texts(&[soap_reply("repair", transport_repair()), review(true)]);
    let assurance = run_step(root.path(), &config(), &client).await;
    let outcome = only_wsdl(&assurance);
    assert_eq!(outcome.action, SpecAction::Repaired);
    assert!(outcome
        .diagnostics_before
        .iter()
        .any(|diagnostic| diagnostic.pointer == "/bindings/QuoteBinding"
            && diagnostic.code == Code::InvalidBinding));
    assert!(outcome.diagnostics_after.is_empty());
    // Only the attribute changed: the comment, prefixes and layout stay.
    assert_eq!(read(root.path(), WSDL_PATH), QUOTE);
    assert!(client
        .prompt(0)
        .contains("Stock quotes: document/literal wrapped"));
}

#[tokio::test]
async fn a_repair_that_rebinds_a_prefix_is_refused() {
    let root = soap_repo();
    write(root.path(), WSDL_PATH, &broken());
    let edits = json!([
        {"old": "<soap:binding style=\"document\"/>",
         "new": "<soap:binding style=\"document\" transport=\"http://schemas.xmlsoap.org/soap/http\"/>"},
        {"old": "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\"\n",
         "new": "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:s=\"http://www.w3.org/2001/XMLSchema\"\n"},
        {"old": "xmlns:tns=\"urn:example:quote\" ", "new": "xmlns:tns=\"urn:other\" xmlns:q=\"urn:example:quote\" "},
    ]);
    let reply = soap_reply("repair", edits);
    let client = Client::texts(&[reply.clone(), reply.clone(), reply]);
    let assurance = run_step(root.path(), &config(), &client).await;
    let outcome = only_wsdl(&assurance);
    assert_eq!(outcome.action, SpecAction::Rejected);
    assert!(outcome
        .gaps
        .last()
        .unwrap()
        .contains("namespace prefix `tns`"));
    assert_eq!(read(root.path(), WSDL_PATH), broken());
}

#[tokio::test]
async fn a_remote_import_is_unverifiable_and_never_fetched() {
    let server = wiremock::MockServer::start().await;
    let root = soap_repo();
    let remote = format!("{}/types.xsd", server.uri());
    let importing = QUOTE.replace(
        "elementFormDefault=\"qualified\">",
        &format!(
            "elementFormDefault=\"qualified\">\n      <xsd:import namespace=\"urn:remote\" schemaLocation=\"{remote}\"/>"
        ),
    );
    write(root.path(), WSDL_PATH, &importing);
    let client = Client::texts(&[soap_reply("no_change", json!([])), review(true)]);
    let assurance = run_step(root.path(), &config(), &client).await;
    let outcome = only_wsdl(&assurance);
    // A warning, which does not block: the document is still complete.
    assert_eq!(outcome.action, SpecAction::Complete);
    assert_eq!(outcome.diagnostics_before.len(), 1);
    let warning = &outcome.diagnostics_before[0];
    assert_eq!(warning.code, Code::ExternalRef);
    assert!(warning.message.contains("was not fetched"));
    assert_eq!(server.received_requests().await.unwrap().len(), 0);
}

#[tokio::test]
async fn an_imported_schema_in_the_repository_is_read_but_not_assessed() {
    let root = soap_repo();
    let schema = "<xsd:schema xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" targetNamespace=\"urn:example:types\">\n  <xsd:element name=\"Price\"/>\n</xsd:schema>\n";
    write(root.path(), "src/main/resources/xsd/types.xsd", schema);
    let importing = QUOTE
        .replace(
            "elementFormDefault=\"qualified\">",
            "elementFormDefault=\"qualified\">\n      <xsd:import namespace=\"urn:example:types\" schemaLocation=\"../xsd/types.xsd\"/>",
        )
        .replace(
            "xmlns:tns=\"urn:example:quote\" ",
            "xmlns:tns=\"urn:example:quote\" xmlns:t=\"urn:example:types\" ",
        )
        .replace(
            "<xsd:element name=\"price\" type=\"xsd:decimal\"/>",
            "<xsd:element ref=\"t:Price\"/>",
        );
    write(root.path(), WSDL_PATH, &importing);
    let client = Client::texts(&[soap_reply("no_change", json!([])), review(true)]);
    let assurance = run_step(root.path(), &config(), &client).await;
    let outcome = only_wsdl(&assurance);
    assert_eq!(outcome.path, WSDL_PATH);
    assert_eq!(outcome.action, SpecAction::Complete);
    assert!(outcome.diagnostics_before.is_empty(), "{outcome:?}");
    assert_eq!(
        read(root.path(), "src/main/resources/xsd/types.xsd"),
        schema
    );
}

#[tokio::test]
async fn a_doctype_leaves_the_wsdl_untouched() {
    let root = soap_repo();
    let doctype = QUOTE.replace(
        "<!-- Stock quotes",
        "<!DOCTYPE d [<!ENTITY x SYSTEM \"file:///etc/passwd\">]>\n<!-- Stock quotes",
    );
    write(root.path(), WSDL_PATH, &doctype);
    let client = Client::new(Vec::new());
    let assurance = run_step(root.path(), &config(), &client).await;
    let outcome = only_wsdl(&assurance);
    assert_eq!(outcome.action, SpecAction::Unverifiable);
    assert!(outcome.gaps[0].contains("DOCTYPE declarations are not accepted"));
    assert_eq!(client.calls(), 0);
    assert_eq!(read(root.path(), WSDL_PATH), doctype);
}

#[tokio::test]
async fn a_rejected_review_leaves_the_wsdl_unchanged() {
    let root = soap_repo();
    write(root.path(), WSDL_PATH, &broken());
    let client = Client::texts(&[soap_reply("repair", transport_repair()), review(false)]);
    let assurance = run_step(root.path(), &config(), &client).await;
    assert_eq!(only_wsdl(&assurance).action, SpecAction::Rejected);
    assert_eq!(read(root.path(), WSDL_PATH), broken());
}

#[tokio::test]
async fn a_credential_in_a_new_wsdl_is_never_written() {
    let root = soap_repo();
    let leaky = QUOTE.replace(
        "<!-- Stock quotes: document/literal wrapped -->",
        "<!-- token: ghp_0123456789abcdefghijklmnopqrstuvwxyzAB -->",
    );
    let reply =
        json!({"decision": "create", "document": leaky, "inventory": soap_inventory()}).to_string();
    let client = Client::texts(&[reply.clone(), reply.clone(), reply]);
    let assurance = run_step(root.path(), &config(), &client).await;
    let outcome = only_wsdl(&assurance);
    assert_eq!(outcome.action, SpecAction::Rejected);
    assert!(outcome
        .gaps
        .last()
        .unwrap()
        .contains("look like credentials"));
    assert!(!root.path().join(WSDL_PATH).exists());
}

#[tokio::test]
async fn a_misplaced_wsdl_is_assessed_where_it_is() {
    let root = soap_repo();
    write(root.path(), "quote.wsdl", QUOTE);
    write(root.path(), "README.md", "The contract is quote.wsdl.\n");
    let client = Client::texts(&[soap_reply("no_change", json!([])), review(true)]);
    let assurance = run_step(root.path(), &config(), &client).await;
    let outcome = only_wsdl(&assurance);
    // No SOAP library reads a WSDL from a fixed place, so nothing moves.
    assert_eq!(outcome.action, SpecAction::Complete);
    assert_eq!(outcome.path, "quote.wsdl");
    assert_eq!(outcome.previous_path, None);
    assert!(!root.path().join(WSDL_PATH).exists());
    assert_eq!(
        read(root.path(), "README.md"),
        "The contract is quote.wsdl.\n"
    );
}
