use super::*;
use crate::diagnostic::{Code, Severity};
use crate::libraries::ApiLibrary;
use serde_json::json;

fn v2() -> Value {
    json!({
        "asyncapi": "2.6.0",
        "info": {"title": "Users", "version": "1.0.0"},
        "servers": {
            "production": {"url": "broker.example.invalid:9092", "protocol": "kafka"},
        },
        "channels": {
            "user/{userId}/signedup": {
                "parameters": {"userId": {"schema": {"type": "string"}}},
                "subscribe": {"operationId": "userSignedUp", "message": {"$ref": "#/components/messages/UserSignedUp"}},
            },
            "user/deleted": {
                "publish": {"operationId": "userDeleted", "security": [{"sasl": []}]},
                "x-internal": true,
            },
        },
        "components": {
            "messages": {"UserSignedUp": {"payload": {"type": "object", "example": {"$ref": "not a ref"}}}},
            "securitySchemes": {"sasl": {"type": "scramSha256"}, "shared": {"$ref": "#/components/securitySchemes/sasl"}},
        },
    })
}

fn v3() -> Value {
    json!({
        "asyncapi": "3.0.0",
        "info": {"title": "Users", "version": "1.0.0"},
        "servers": {"production": {"host": "broker.example.invalid", "protocol": "amqp"}},
        "channels": {
            "userSignedUp": {
                "address": "user/{userId}/signedup",
                "parameters": {"userId": {}},
                "messages": {"UserSignedUp": {"payload": {"type": "object"}}},
            },
            "dynamic": {"address": null, "messages": {"Event": {}}},
        },
        "operations": {
            "sendUserSignedUp": {
                "action": "send",
                "channel": {"$ref": "#/channels/userSignedUp"},
                "messages": [{"$ref": "#/channels/userSignedUp/messages/UserSignedUp"}],
            },
            "onEvent": {"action": "receive", "channel": {"$ref": "#/channels/dynamic"}},
        },
    })
}

fn codes(document: &Value) -> Vec<(Severity, Code, String)> {
    validate::validate(document)
        .into_iter()
        .map(|d| (d.severity, d.code, d.pointer))
        .collect()
}

#[test]
fn valid_documents_of_both_versions_have_no_diagnostics() {
    assert_eq!(codes(&v2()), []);
    assert_eq!(codes(&v3()), []);
    assert_eq!(declared_version(&v2()), Some(SpecVersion::AsyncApi2));
    assert_eq!(declared_version(&v3()), Some(SpecVersion::AsyncApi3));
    assert_eq!(declared_version(&json!({"asyncapi": "1.2.0"})), None);
    assert_eq!(declared_version(&json!({"asyncapi": "2"})), None);
    assert_eq!(declared_version(&json!({})), None);
}

#[test]
fn version_2_rules_are_checked() {
    let mut document = v2();
    document["asyncapi"] = json!(2.6);
    document["servers"] = json!({
        "a": {"url": "kafka://user:secret@broker.invalid", "protocol": "carrier-pigeon"},
        "b": {"url": ""},
        "c": {"$ref": "#/components/servers/c"},
    });
    document["channels"]["user/deleted"]["subscribe"] = json!({"operationId": "userDeleted"});
    document["channels"]["user/deleted"]["publish"]["security"] = json!([{"missing": []}, "odd"]);
    document["channels"]["user/deleted"]["parameters"] = json!({"ghost": {}});
    document["channels"]["user/deleted"]["bogus"] = json!(1);
    document["channels"]["odd"] = json!([]);
    document["channels"]["user/{userId}/signedup"]["publish"] = json!("text");
    document["components"]["securitySchemes"]["bad"] = json!({"type": "magic"});
    // An operation without an operationId is legal.
    document["channels"]["audit"] = json!({"publish": {}});
    let found = codes(&document);
    let expected = [
        (Severity::Error, Code::InvalidVersion, "/asyncapi"),
        (Severity::Error, Code::InvalidServer, "/servers/a/url"),
        (
            Severity::Warning,
            Code::InvalidServer,
            "/servers/a/protocol",
        ),
        (Severity::Error, Code::InvalidServer, "/servers/b"),
        (Severity::Error, Code::InvalidServer, "/servers/b"),
        (
            Severity::Error,
            Code::InvalidSecurityScheme,
            "/components/securitySchemes/bad",
        ),
        (Severity::Error, Code::InvalidType, "/channels/odd"),
        (
            Severity::Error,
            Code::UnknownPathParameter,
            "/channels/user~1deleted/parameters/ghost",
        ),
        (
            Severity::Error,
            Code::UnknownField,
            "/channels/user~1deleted/bogus",
        ),
        (
            Severity::Error,
            Code::UndefinedSecurityScheme,
            "/channels/user~1deleted/publish/security/0/missing",
        ),
        (
            Severity::Error,
            Code::DuplicateOperationId,
            "/channels/user~1deleted/subscribe/operationId",
        ),
        (
            Severity::Error,
            Code::InvalidType,
            "/channels/user~1{userId}~1signedup/publish",
        ),
        (Severity::Error, Code::UnresolvedRef, "/servers/c/$ref"),
    ];
    let expected: Vec<_> = expected
        .into_iter()
        .map(|(s, c, p)| (s, c, p.to_string()))
        .collect();
    assert_eq!(found, expected);
    // Invalid version declarations fall back to the 2.x rules.
    assert_eq!(
        codes(&json!({"asyncapi": "3.0.0", "info": {"title": "t", "version": "1"}})),
        []
    );
    let root = codes(&json!({"info": {"title": "t", "version": "1"}, "channels": []}));
    assert_eq!(
        root,
        [
            (Severity::Error, Code::MissingVersion, String::new()),
            (Severity::Error, Code::InvalidType, "/channels".into()),
        ]
    );
    assert_eq!(
        codes(&json!({"asyncapi": "2.0.0", "info": {"title": "t", "version": "1"}})),
        [(Severity::Error, Code::MissingField, "/channels".to_string())]
    );
    assert_eq!(
        codes(&json!([])),
        [(Severity::Error, Code::NotAnObject, String::new())]
    );
}

#[test]
fn version_3_rules_are_checked() {
    let mut document = v3();
    document["servers"]["production"] = json!({"host": "user@broker.invalid"});
    document["channels"]["userSignedUp"]["address"] = json!("user/{id}/signedup");
    document["channels"]["bad"] = json!({"address": 7});
    document["operations"]["sendUserSignedUp"]["action"] = json!("publish");
    document["operations"]["sendUserSignedUp"]["messages"] = json!([
        {"$ref": "#/channels/dynamic/messages/Event"},
        {"$ref": "#/channels/nowhere/messages/X"},
    ]);
    document["operations"]["noChannel"] =
        json!({"action": "send", "channel": {"$ref": "#/components/x"}});
    let found = codes(&document);
    let expected = [
        (
            Severity::Error,
            Code::InvalidServer,
            "/servers/production/host",
        ),
        (Severity::Error, Code::InvalidServer, "/servers/production"),
        (Severity::Error, Code::InvalidType, "/channels/bad/address"),
        (
            Severity::Error,
            Code::UnknownPathParameter,
            "/channels/userSignedUp/parameters/userId",
        ),
        (
            Severity::Warning,
            Code::UndeclaredPathParameter,
            "/channels/userSignedUp",
        ),
        (
            Severity::Error,
            Code::MissingField,
            "/operations/noChannel/channel",
        ),
        (
            Severity::Error,
            Code::InvalidMethod,
            "/operations/sendUserSignedUp/action",
        ),
        (
            Severity::Error,
            Code::UnresolvedRef,
            "/operations/sendUserSignedUp/messages/0",
        ),
        (
            Severity::Error,
            Code::UnresolvedRef,
            "/operations/noChannel/channel/$ref",
        ),
        (
            Severity::Error,
            Code::UnresolvedRef,
            "/operations/sendUserSignedUp/messages/1/$ref",
        ),
    ];
    let expected: Vec<_> = expected
        .into_iter()
        .map(|(s, c, p)| (s, c, p.to_string()))
        .collect();
    assert_eq!(found, expected);
    let mut odd = v3();
    odd["operations"] = json!([]);
    odd["channels"] = json!(null);
    assert_eq!(
        codes(&odd),
        [
            (Severity::Error, Code::InvalidType, "/channels".to_string()),
            (
                Severity::Error,
                Code::InvalidType,
                "/operations".to_string()
            ),
        ]
    );
}

#[test]
fn operations_read_the_application_side_of_each_channel() {
    assert_eq!(
        ASYNCAPI.operations(&v2()),
        [
            Operation::new("receive", "user/deleted"),
            Operation::new("send", "user/{userId}/signedup"),
        ]
    );
    assert_eq!(
        ASYNCAPI.operations(&v3()),
        [
            Operation::new("receive", "dynamic"),
            Operation::new("send", "user/{userId}/signedup"),
        ]
    );
    let mut broken = v3();
    broken["operations"]["x"] = json!({"action": "send", "channel": {"$ref": "#/nowhere"}});
    broken["operations"]["y"] =
        json!({"action": "sideways", "channel": {"$ref": "#/channels/dynamic"}});
    assert_eq!(ASYNCAPI.operations(&broken).len(), 2);
}

#[test]
fn completeness_matches_addresses_by_shape() {
    let inventory = [
        Operation::new("send", "/user/{id}/signedup"),
        Operation::new("send", "orders"),
    ];
    let result = ASYNCAPI.compare(&v2(), &[], &inventory);
    assert_eq!(result.missing, [Operation::new("send", "orders")]);
    assert_eq!(
        result.unverified,
        [Operation::new("receive", "user/deleted")]
    );
}

#[test]
fn repairs_keep_channels_operations_and_components() {
    let original = v3();
    let mut repaired = original.clone();
    repaired["operations"]["onOrder"] =
        json!({"action": "receive", "channel": {"$ref": "#/channels/dynamic"}});
    assert!(ASYNCAPI.preservation(&original, &repaired, &[]).is_empty());
    repaired["operations"]
        .as_object_mut()
        .unwrap()
        .remove("onEvent");
    repaired["asyncapi"] = json!("2.6.0");
    assert_eq!(
        ASYNCAPI.preservation(&original, &repaired, &[]),
        [
            "the repair changed the specification version; repairs keep the author's version",
            "removed documented operation `onEvent`",
        ]
    );
}

#[test]
fn candidates_inventory_and_emission() {
    assert_eq!(
        ASYNCAPI.candidate_strength("docs/asyncapi.yaml"),
        Some(NameStrength::Strong)
    );
    let text = b"asyncapi: 3.0.0\ninfo:\n  title: t\n  version: \"1\"\n";
    assert!(matches!(
        ASYNCAPI.classify("asyncapi.yaml", text, 1024),
        Candidate::Spec {
            version: Some(SpecVersion::AsyncApi3),
            ..
        }
    ));
    assert!(matches!(
        ASYNCAPI.classify("asyncapi.yaml", b"info:\n  title: t\n", 1024),
        Candidate::Broken { .. }
    ));
    let parsed = ASYNCAPI.parse("asyncapi: 3.0.0\n", Syntax::Yaml).unwrap();
    assert_eq!(ASYNCAPI.version(&parsed), Some(SpecVersion::AsyncApi3));
    assert!(ASYNCAPI.validate(&v3(), &[]).is_empty());
    assert_eq!(
        ASYNCAPI.inventory_operation(" SEND ", "orders").unwrap(),
        Operation::new("send", "orders")
    );
    assert!(ASYNCAPI
        .inventory_operation("publish", "a")
        .unwrap_err()
        .contains("send or receive"));
    assert!(ASYNCAPI
        .inventory_operation("send", " ")
        .unwrap_err()
        .contains("channel address"));
    let yaml = ASYNCAPI.emit(&v3(), Syntax::Yaml).unwrap();
    assert!(
        yaml.starts_with("\"asyncapi\": \"3.0.0\"\n\"info\":"),
        "{yaml}"
    );
    assert_eq!(bc_yaml::parse_strict(&yaml).unwrap(), v3());
    let json = ASYNCAPI.emit(&v3(), Syntax::Json).unwrap();
    assert!(json.starts_with("{\n  \"asyncapi\": \"3.0.0\""));
    assert!(ASYNCAPI
        .emit(&json!([]), Syntax::Yaml)
        .unwrap_err()
        .contains("as a mapping"));
    assert!(ASYNCAPI.new_document_problems(&v3()).is_empty());
    assert_eq!(
        ASYNCAPI.new_document_problems(&v2()),
        ["a new document must declare asyncapi: \"3.0.0\""]
    );
}

#[test]
fn owners_are_services_with_messaging_libraries() {
    let surfaces = [
        ApiSurface {
            root: "events".into(),
            manifests: vec![],
            libraries: [ApiLibrary::Kafka, ApiLibrary::Amqp, ApiLibrary::Grpc]
                .into_iter()
                .collect(),
        },
        ApiSurface {
            root: "rpc".into(),
            manifests: vec![],
            libraries: [ApiLibrary::Grpc].into_iter().collect(),
        },
    ];
    let owners = ASYNCAPI.owners(&[], &surfaces);
    assert_eq!(owners.len(), 1);
    assert_eq!(owners[0].stack, ["kafka", "amqp"]);
    assert!(!owners[0].convention.confident);
    assert_eq!(ASYNCAPI.fallback().path, "asyncapi.yaml");
    assert_eq!(ASYNCAPI.name(), "AsyncAPI");
    assert_eq!(ASYNCAPI.capabilities(), Capabilities::FULL);
}
