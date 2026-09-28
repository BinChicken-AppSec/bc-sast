//! A WSDL 1.1 or 2.0 description, or an XML Schema, read into the stable
//! JSON model the rest of the standard works on.
//!
//! The model keeps what the checks need, by name: the target namespace,
//! the root's namespace declarations, imports, the inline schemas'
//! top-level element and type names, and the messages, port types (WSDL
//! 2.0: interfaces), bindings and services with their members. Every
//! qualified-name reference is resolved against the namespaces in scope
//! where it is written (see [`crate::xml::reference`]), so later checks
//! compare namespace URIs and never prefixes. Both versions share one
//! shape: a WSDL 1.1 port type is an entry of `interfaces`, a port an
//! entry of `endpoints`, and WSDL 2.0 has no `messages`.

use bc_xml::{Document, Element};
use serde_json::{json, Value};

use crate::xml::{attribute, declarations, reference, reference_attribute};

pub const WSDL11: &str = "http://schemas.xmlsoap.org/wsdl/";
pub const WSDL20: &str = "http://www.w3.org/ns/wsdl";
pub const XSD: &str = "http://www.w3.org/2001/XMLSchema";
/// The namespaces of XML Schema's drafts, still found in old WSDL files.
pub const XSD_DRAFTS: [&str; 2] = [
    "http://www.w3.org/1999/XMLSchema",
    "http://www.w3.org/2000/10/XMLSchema",
];
pub const SOAP11: &str = "http://schemas.xmlsoap.org/wsdl/soap/";
pub const SOAP12: &str = "http://schemas.xmlsoap.org/wsdl/soap12/";
pub const HTTP11: &str = "http://schemas.xmlsoap.org/wsdl/http/";
/// The WSDL 2.0 SOAP binding: the namespace of `wsoap:protocol` and the
/// value of a SOAP binding's `type`.
pub const WSOAP: &str = "http://www.w3.org/ns/wsdl/soap";
pub const SOAP_ENCODING: &str = "http://schemas.xmlsoap.org/soap/encoding/";

/// Whether `namespace` is XML Schema's, current or draft.
pub fn is_xsd(namespace: Option<&str>) -> bool {
    namespace.is_some_and(|namespace| namespace == XSD || XSD_DRAFTS.contains(&namespace))
}

/// The model of `document`, or `None` when its root is neither a WSDL
/// description nor an XML Schema.
pub fn model(document: &Document) -> Option<Value> {
    let root = &document.root;
    if root.is_named(Some(WSDL11), "definitions") {
        Some(wsdl11(root))
    } else if root.is_named(Some(WSDL20), "description") {
        Some(wsdl20(root))
    } else if root.name.local == "schema" && is_xsd(root.namespace.as_deref()) {
        Some(json!({
            "kind": "xsd",
            "targetNamespace": attribute(root, "targetNamespace"),
            "schemas": [schema(root)],
        }))
    } else {
        None
    }
}

fn xsd_children<'a>(
    element: &'a Element,
    locals: &'a [&'a str],
) -> impl Iterator<Item = &'a Element> + 'a {
    element.child_elements().filter(move |child| {
        is_xsd(child.namespace.as_deref()) && locals.contains(&child.name.local.as_str())
    })
}

/// One schema: its target namespace, the names of its top-level elements
/// and types, and what it imports or includes.
fn schema(element: &Element) -> Value {
    let names = |locals: &[&str]| -> Vec<Value> {
        xsd_children(element, locals)
            .filter_map(|child| child.attribute("name"))
            .map(|name| json!(name))
            .collect()
    };
    let imports: Vec<Value> = xsd_children(element, &["import", "include", "redefine", "override"])
        .map(|child| {
            json!({
                "namespace": attribute(child, "namespace"),
                "location": attribute(child, "schemaLocation"),
            })
        })
        .collect();
    json!({
        "targetNamespace": attribute(element, "targetNamespace"),
        "elements": names(&["element"]),
        "types": names(&["complexType", "simpleType"]),
        "imports": imports,
    })
}

/// The schemas under the root's `types` elements.
fn schemas(root: &Element, namespace: &str) -> Vec<Value> {
    root.children_named(Some(namespace), "types")
        .flat_map(|types| xsd_children(types, &["schema"]))
        .map(schema)
        .collect()
}

fn imports(root: &Element, namespace: &str) -> Vec<Value> {
    root.child_elements()
        .filter(|child| {
            child.namespace.as_deref() == Some(namespace)
                && matches!(child.name.local.as_str(), "import" | "include")
        })
        .map(|child| {
            json!({
                "namespace": attribute(child, "namespace"),
                "location": attribute(child, "location"),
            })
        })
        .collect()
}

/// The first child in one of `namespaces` named `local`.
fn extension<'a>(element: &'a Element, namespaces: &[&str], local: &str) -> Option<&'a Element> {
    element.child_elements().find(|child| {
        child.name.local == local
            && child
                .namespace
                .as_deref()
                .is_some_and(|namespace| namespaces.contains(&namespace))
    })
}

fn header(root: &Element, version: &str) -> serde_json::Map<String, Value> {
    let mut map = serde_json::Map::new();
    map.insert("kind".into(), json!("wsdl"));
    map.insert("version".into(), json!(version));
    map.insert("targetNamespace".into(), attribute(root, "targetNamespace"));
    map.insert("namespaces".into(), declarations(root));
    map
}

fn wsdl11(root: &Element) -> Value {
    let children = |local| root.children_named(Some(WSDL11), local);
    let mut map = header(root, "1.1");
    map.insert("imports".into(), json!(imports(root, WSDL11)));
    map.insert("schemas".into(), json!(schemas(root, WSDL11)));
    map.insert(
        "messages".into(),
        children("message").map(message).collect(),
    );
    map.insert(
        "interfaces".into(),
        children("portType").map(port_type).collect(),
    );
    map.insert(
        "bindings".into(),
        children("binding").map(binding11).collect(),
    );
    map.insert(
        "services".into(),
        children("service").map(service11).collect(),
    );
    Value::Object(map)
}

fn message(element: &Element) -> Value {
    let parts: Vec<Value> = element
        .children_named(Some(WSDL11), "part")
        .map(|part| {
            json!({
                "name": attribute(part, "name"),
                "element": reference_attribute(part, "element"),
                "type": reference_attribute(part, "type"),
            })
        })
        .collect();
    json!({"name": attribute(element, "name"), "parts": parts})
}

fn port_type(element: &Element) -> Value {
    let operations: Vec<Value> = element
        .children_named(Some(WSDL11), "operation")
        .map(|operation| {
            let io = |local| {
                operation.first_child_named(Some(WSDL11), local).map_or(
                    Value::Null,
                    |io| json!({"message": reference_attribute(io, "message")}),
                )
            };
            let faults: Vec<Value> = operation
                .children_named(Some(WSDL11), "fault")
                .map(|fault| {
                    json!({
                        "name": attribute(fault, "name"),
                        "message": reference_attribute(fault, "message"),
                    })
                })
                .collect();
            json!({
                "name": attribute(operation, "name"),
                "input": io("input"),
                "output": io("output"),
                "faults": faults,
            })
        })
        .collect();
    json!({"name": attribute(element, "name"), "operations": operations})
}

fn binding11(element: &Element) -> Value {
    let protocols = [SOAP11, SOAP12, HTTP11];
    let extension_element = extension(element, &protocols, "binding");
    let protocol = extension_element.map(|found| match found.namespace.as_deref() {
        Some(SOAP11) => "soap11",
        Some(SOAP12) => "soap12",
        _ => "http",
    });
    let operations: Vec<Value> = element
        .children_named(Some(WSDL11), "operation")
        .map(|operation| {
            let soap = extension(operation, &protocols, "operation");
            let uses: Vec<Value> = operation
                .descendants()
                .filter(|body| {
                    matches!(body.name.local.as_str(), "body" | "fault" | "header")
                        && matches!(body.namespace.as_deref(), Some(SOAP11 | SOAP12))
                })
                .filter_map(|body| body.attribute("use"))
                .map(|used| json!(used))
                .collect();
            json!({
                "name": attribute(operation, "name"),
                "style": soap.map_or(Value::Null, |soap| attribute(soap, "style")),
                "action": soap.map_or(Value::Null, |soap| attribute(soap, "soapAction")),
                "uses": uses,
            })
        })
        .collect();
    let binding_attribute =
        |name| extension_element.map_or(Value::Null, |found| attribute(found, name));
    json!({
        "name": attribute(element, "name"),
        "interface": reference_attribute(element, "type"),
        "protocol": protocol,
        "transport": binding_attribute("transport"),
        "style": binding_attribute("style"),
        "verb": binding_attribute("verb"),
        "operations": operations,
    })
}

fn service11(element: &Element) -> Value {
    let endpoints: Vec<Value> = element
        .children_named(Some(WSDL11), "port")
        .map(|port| {
            let address = extension(port, &[SOAP11, SOAP12, HTTP11], "address")
                .map_or(Value::Null, |address| attribute(address, "location"));
            json!({
                "name": attribute(port, "name"),
                "binding": reference_attribute(port, "binding"),
                "address": address,
            })
        })
        .collect();
    json!({"name": attribute(element, "name"), "endpoints": endpoints})
}

fn wsdl20(root: &Element) -> Value {
    let children = |local| root.children_named(Some(WSDL20), local);
    let mut map = header(root, "2.0");
    map.insert("imports".into(), json!(imports(root, WSDL20)));
    map.insert("schemas".into(), json!(schemas(root, WSDL20)));
    map.insert("messages".into(), json!([]));
    map.insert(
        "interfaces".into(),
        children("interface").map(interface).collect(),
    );
    map.insert(
        "bindings".into(),
        children("binding").map(binding20).collect(),
    );
    map.insert(
        "services".into(),
        children("service").map(service20).collect(),
    );
    Value::Object(map)
}

/// A WSDL 2.0 message reference: an element, or one of the `#any`,
/// `#none` and `#other` tokens (`#other` when no element is named).
fn element_reference(element: &Element) -> Value {
    match element.attribute("element") {
        Some(token) if token.trim().starts_with('#') => json!({"token": token.trim()}),
        Some(value) => json!({"element": reference(element, value)}),
        None => json!({"token": "#other"}),
    }
}

fn interface(element: &Element) -> Value {
    let extends: Vec<Value> = element
        .attribute("extends")
        .unwrap_or_default()
        .split_ascii_whitespace()
        .map(|name| reference(element, name))
        .collect();
    let faults: Vec<Value> = element
        .children_named(Some(WSDL20), "fault")
        .map(|fault| json!({"name": attribute(fault, "name"), "message": element_reference(fault)}))
        .collect();
    let operations: Vec<Value> = element
        .children_named(Some(WSDL20), "operation")
        .map(|operation| {
            let io = |local| {
                operation
                    .first_child_named(Some(WSDL20), local)
                    .map_or(Value::Null, element_reference)
            };
            let faults: Vec<Value> = operation
                .child_elements()
                .filter(|fault| {
                    fault.namespace.as_deref() == Some(WSDL20)
                        && matches!(fault.name.local.as_str(), "infault" | "outfault")
                })
                .map(|fault| json!({"ref": reference_attribute(fault, "ref")}))
                .collect();
            json!({
                "name": attribute(operation, "name"),
                "pattern": attribute(operation, "pattern"),
                "input": io("input"),
                "output": io("output"),
                "faults": faults,
            })
        })
        .collect();
    json!({
        "name": attribute(element, "name"),
        "extends": extends,
        "faults": faults,
        "operations": operations,
    })
}

fn binding20(element: &Element) -> Value {
    let operations: Vec<Value> = element
        .children_named(Some(WSDL20), "operation")
        .map(|operation| {
            let target = reference_attribute(operation, "ref");
            // Named by the operation it binds, for preservation.
            let name = target
                .get("local")
                .or_else(|| target.get("unresolved"))
                .cloned()
                .unwrap_or(Value::Null);
            json!({"name": name, "ref": target})
        })
        .collect();
    json!({
        "name": attribute(element, "name"),
        "interface": reference_attribute(element, "interface"),
        "type": attribute(element, "type"),
        "protocol": element
            .attribute_ns(Some(WSOAP), "protocol")
            .map_or(Value::Null, |protocol| json!(protocol)),
        "operations": operations,
    })
}

fn service20(element: &Element) -> Value {
    let endpoints: Vec<Value> = element
        .children_named(Some(WSDL20), "endpoint")
        .map(|endpoint| {
            json!({
                "name": attribute(endpoint, "name"),
                "binding": reference_attribute(endpoint, "binding"),
                "address": attribute(endpoint, "address"),
            })
        })
        .collect();
    json!({
        "name": attribute(element, "name"),
        "interface": reference_attribute(element, "interface"),
        "endpoints": endpoints,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xml::read;

    fn of(text: &str) -> Option<Value> {
        model(&read(text).unwrap())
    }

    #[test]
    fn a_wsdl_11_description_becomes_its_model() {
        let text = r#"<?xml version="1.0"?>
<definitions xmlns="http://schemas.xmlsoap.org/wsdl/" xmlns:tns="urn:q"
    xmlns:xsd="http://www.w3.org/2001/XMLSchema"
    xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
    xmlns:http="http://schemas.xmlsoap.org/wsdl/http/" targetNamespace="urn:q">
  <import namespace="urn:c" location="common.wsdl"/>
  <types>
    <xsd:schema targetNamespace="urn:q">
      <xsd:import namespace="urn:x" schemaLocation="x.xsd"/>
      <xsd:include schemaLocation="more.xsd"/>
      <xsd:element name="Get"/>
      <xsd:complexType name="T"/>
      <xsd:simpleType name="S"/>
      <xsd:attribute name="ignored"/>
    </xsd:schema>
  </types>
  <message name="GetIn"><part name="p" element="tns:Get"/><part name="q" type="xsd:string"/></message>
  <portType name="Quote">
    <operation name="Get">
      <input message="tns:GetIn"/>
      <fault name="f" message="tns:GetIn"/>
    </operation>
  </portType>
  <binding name="QuoteSoap" type="tns:Quote">
    <soap:binding style="document" transport="http://schemas.xmlsoap.org/soap/http"/>
    <operation name="Get">
      <soap:operation soapAction="urn:get"/>
      <input><soap:body use="literal"/></input>
      <fault name="f"><soap:fault name="f" use="literal"/></fault>
    </operation>
  </binding>
  <binding name="QuoteHttp" type="tns:Quote"><http:binding verb="GET"/><operation name="Get"/></binding>
  <binding name="Bare" type="tns:Quote"/>
  <service name="S">
    <port name="P" binding="tns:QuoteSoap"><soap:address location="http://example.com/q"/></port>
    <port name="H" binding="tns:QuoteHttp"/>
  </service>
</definitions>"#;
        let model = of(text).unwrap();
        assert_eq!(model["kind"], "wsdl");
        assert_eq!(model["version"], "1.1");
        assert_eq!(model["targetNamespace"], "urn:q");
        assert_eq!(model["namespaces"]["tns"], "urn:q");
        assert_eq!(model["namespaces"][""], WSDL11);
        assert_eq!(
            model["imports"],
            json!([{"namespace": "urn:c", "location": "common.wsdl"}])
        );
        assert_eq!(
            model["schemas"],
            json!([{
                "targetNamespace": "urn:q", "elements": ["Get"], "types": ["T", "S"],
                "imports": [
                    {"namespace": "urn:x", "location": "x.xsd"},
                    {"namespace": null, "location": "more.xsd"},
                ],
            }])
        );
        assert_eq!(
            model["messages"][0]["parts"],
            json!([
                {"name": "p", "element": {"ns": "urn:q", "local": "Get"}, "type": null},
                {"name": "q", "element": null, "type": {"ns": XSD, "local": "string"}},
            ])
        );
        let operation = &model["interfaces"][0]["operations"][0];
        assert_eq!(operation["input"]["message"]["local"], "GetIn");
        assert_eq!(operation["output"], Value::Null);
        assert_eq!(operation["faults"][0]["name"], "f");
        let soap = &model["bindings"][0];
        assert_eq!(soap["protocol"], "soap11");
        assert_eq!(soap["style"], "document");
        assert_eq!(soap["interface"]["local"], "Quote");
        assert_eq!(
            soap["operations"],
            json!([{"name": "Get", "style": null, "action": "urn:get", "uses": ["literal", "literal"]}])
        );
        assert_eq!(model["bindings"][1]["protocol"], "http");
        assert_eq!(model["bindings"][1]["verb"], "GET");
        assert_eq!(model["bindings"][1]["operations"][0]["action"], Value::Null);
        assert_eq!(model["bindings"][2]["protocol"], Value::Null);
        assert_eq!(model["bindings"][2]["transport"], Value::Null);
        let ports = &model["services"][0]["endpoints"];
        assert_eq!(ports[0]["address"], "http://example.com/q");
        assert_eq!(ports[1]["address"], Value::Null);
    }

    #[test]
    fn soap_12_bindings_are_recognized() {
        let text = r#"<definitions xmlns="http://schemas.xmlsoap.org/wsdl/" xmlns:s="http://schemas.xmlsoap.org/wsdl/soap12/">
  <binding name="B" type="Q"><s:binding transport="t"/><operation name="Get"><s:operation style="rpc"/></operation></binding>
</definitions>"#;
        let model = of(text).unwrap();
        assert_eq!(model["bindings"][0]["protocol"], "soap12");
        assert_eq!(model["bindings"][0]["operations"][0]["style"], "rpc");
        assert_eq!(
            model["bindings"][0]["interface"],
            json!({"ns": WSDL11, "local": "Q"})
        );
        assert_eq!(model["targetNamespace"], Value::Null);
    }

    #[test]
    fn a_wsdl_20_description_shares_the_shape() {
        let text = r##"<description xmlns="http://www.w3.org/ns/wsdl" xmlns:tns="urn:q"
    xmlns:wsoap="http://www.w3.org/ns/wsdl/soap" targetNamespace="urn:q">
  <import namespace="urn:c" location="c.wsdl"/>
  <include location="more.wsdl"/>
  <types><xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema" targetNamespace="urn:q"><xs:element name="Get"/></xs:schema></types>
  <interface name="Quote" extends="tns:Base tns:Other">
    <fault name="Bad" element="tns:Get"/>
    <operation name="Get" pattern="http://www.w3.org/ns/wsdl/in-out">
      <input element="tns:Get"/>
      <output element="#any"/>
      <outfault ref="tns:Bad"/>
    </operation>
    <operation name="Ping"><input/></operation>
  </interface>
  <binding name="B" interface="tns:Quote" type="http://www.w3.org/ns/wsdl/soap" wsoap:protocol="http://www.w3.org/2003/05/soap/bindings/HTTP/">
    <operation ref="tns:Get"/>
    <operation ref="x:Nope"/>
  </binding>
  <service name="S" interface="tns:Quote"><endpoint name="E" binding="tns:B" address="http://example.com/q"/></service>
</description>"##;
        let model = of(text).unwrap();
        assert_eq!(model["version"], "2.0");
        assert_eq!(model["messages"], json!([]));
        assert_eq!(
            model["imports"][1],
            json!({"namespace": null, "location": "more.wsdl"})
        );
        assert_eq!(model["schemas"][0]["elements"], json!(["Get"]));
        let interface = &model["interfaces"][0];
        assert_eq!(interface["extends"][1]["local"], "Other");
        assert_eq!(
            interface["faults"][0]["message"],
            json!({"element": {"ns": "urn:q", "local": "Get"}})
        );
        let get = &interface["operations"][0];
        assert_eq!(get["input"]["element"]["local"], "Get");
        assert_eq!(get["output"], json!({"token": "#any"}));
        assert_eq!(get["faults"][0]["ref"]["local"], "Bad");
        assert_eq!(
            interface["operations"][1]["input"],
            json!({"token": "#other"})
        );
        assert_eq!(interface["operations"][1]["output"], Value::Null);
        let binding = &model["bindings"][0];
        assert_eq!(binding["type"], WSOAP);
        assert!(binding["protocol"].as_str().unwrap().contains("HTTP"));
        assert_eq!(binding["operations"][0]["name"], "Get");
        assert_eq!(binding["operations"][1]["name"], "x:Nope");
        let service = &model["services"][0];
        assert_eq!(service["interface"]["local"], "Quote");
        assert_eq!(service["endpoints"][0]["binding"]["local"], "B");
        assert_eq!(
            of(r#"<description xmlns="http://www.w3.org/ns/wsdl"><binding name="B"/></description>"#)
                .unwrap()["bindings"][0]["protocol"],
            Value::Null
        );
    }

    #[test]
    fn schemas_are_models_and_other_roots_are_not() {
        let xsd = of(r#"<schema xmlns="http://www.w3.org/1999/XMLSchema" targetNamespace="urn:t"><element name="A"/></schema>"#)
            .unwrap();
        assert_eq!(xsd["kind"], "xsd");
        assert_eq!(xsd["targetNamespace"], "urn:t");
        assert_eq!(xsd["schemas"][0]["elements"], json!(["A"]));
        assert!(is_xsd(Some(XSD)) && !is_xsd(None) && !is_xsd(Some(WSDL11)));
        assert_eq!(of("<project/>"), None);
        assert_eq!(of(r#"<schema xmlns="urn:other"/>"#), None);
        assert_eq!(of(r#"<definitions/>"#), None);
    }
}
