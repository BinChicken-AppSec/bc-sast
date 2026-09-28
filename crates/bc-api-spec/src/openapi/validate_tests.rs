use super::*;
use serde_json::json;

fn openapi() -> Value {
    json!({
        "openapi": "3.0.3",
        "info": {"title": "Pets", "version": "1.0.0"},
        "servers": [{"url": "https://api.example.invalid/v1"}],
        "security": [{"bearer": []}],
        "paths": {
            "/pets/{id}": {
                "parameters": [{"$ref": "#/components/parameters/Id"}],
                "get": {
                    "operationId": "getPet",
                    "responses": {"200": {"$ref": "#/components/responses/Pet"}, "4XX": {"description": "error"}},
                },
                "delete": {
                    "operationId": "deletePet",
                    "security": [{"bearer": []}],
                    "responses": {"default": {"description": "done"}, "x-note": "ignored"},
                },
                "summary": "one pet",
                "x-internal": true,
            },
            "x-extension": {},
        },
        "components": {
            "parameters": {"Id": {"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}},
            "responses": {"Pet": {"description": "a pet", "content": {"application/json": {"example": {"$ref": "not a ref"}}}}},
            "securitySchemes": {
                "bearer": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"},
                "key": {"type": "apiKey", "name": "X-API-Key", "in": "header"},
                "oauth": {"type": "oauth2", "flows": {}},
                "oidc": {"type": "openIdConnect", "openIdConnectUrl": "https://id.example.invalid"},
                "shared": {"$ref": "#/components/securitySchemes/key"},
            },
        },
    })
}

fn swagger() -> Value {
    json!({
        "swagger": "2.0",
        "info": {"title": "Pets", "version": "1"},
        "host": "api.example.invalid:8443",
        "basePath": "/v1",
        "schemes": ["https"],
        "securityDefinitions": {
            "basic": {"type": "basic"},
            "key": {"type": "apiKey", "name": "key", "in": "query"},
            "oauth": {"type": "oauth2", "flow": "accessCode"},
        },
        "paths": {
            "/pets/{id}": {
                "get": {
                    "parameters": [
                        {"name": "id", "in": "path", "required": true, "type": "string"},
                        {"name": "body", "in": "body", "schema": {"$ref": "#/definitions/Pet"}},
                    ],
                    "responses": {"200": {"description": "ok"}},
                    "security": [{"oauth": []}],
                }
            }
        },
        "definitions": {"Pet": {"type": "object"}},
    })
}

fn codes(document: &Value) -> Vec<(Code, String)> {
    validate(document)
        .into_iter()
        .map(|diagnostic| (diagnostic.code, diagnostic.pointer))
        .collect()
}

fn set(document: &mut Value, pointer: &str, value: Value) {
    let (parent, key) = pointer.rsplit_once('/').unwrap();
    document
        .pointer_mut(parent)
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert(key.replace("~1", "/").replace("~0", "~"), value);
}

fn remove(document: &mut Value, pointer: &str) {
    let (parent, key) = pointer.rsplit_once('/').unwrap();
    document
        .pointer_mut(parent)
        .unwrap()
        .as_object_mut()
        .unwrap()
        .remove(&key.replace("~1", "/").replace("~0", "~"));
}

#[test]
fn well_formed_documents_have_no_diagnostics() {
    assert_eq!(codes(&openapi()), []);
    assert_eq!(codes(&swagger()), []);
    let mut minimal = swagger();
    for key in ["/host", "/basePath", "/schemes"] {
        remove(&mut minimal, key);
    }
    assert_eq!(codes(&minimal), []);
    let mut v31 = openapi();
    set(&mut v31, "/openapi", json!("3.1.0"));
    set(
        &mut v31,
        "/components/securitySchemes/tls",
        json!({"type": "mutualTLS"}),
    );
    assert_eq!(codes(&v31), []);
}

#[test]
fn the_root_must_be_a_mapping() {
    assert_eq!(codes(&json!([])), [(Code::NotAnObject, String::new())]);
}

#[test]
fn version_fields_are_checked() {
    let mut document = openapi();
    set(&mut document, "/openapi", json!("3.1"));
    assert_eq!(
        codes(&document),
        [(Code::InvalidVersion, "/openapi".into())]
    );
    set(&mut document, "/openapi", json!(3.1));
    assert_eq!(
        codes(&document),
        [(Code::InvalidVersion, "/openapi".into())]
    );
    set(&mut document, "/openapi", json!("3.0.x"));
    assert_eq!(
        codes(&document),
        [(Code::InvalidVersion, "/openapi".into())]
    );
    set(&mut document, "/openapi", json!("3.0."));
    assert_eq!(
        codes(&document),
        [(Code::InvalidVersion, "/openapi".into())]
    );
    document
        .as_object_mut()
        .unwrap()
        .insert("swagger".into(), json!("2.0"));
    set(&mut document, "/openapi", json!("3.0.3"));
    assert!(codes(&document).contains(&(Code::InvalidVersion, String::new())));
    let mut document = swagger();
    set(&mut document, "/swagger", json!(2.0));
    assert_eq!(
        codes(&document),
        [(Code::InvalidVersion, "/swagger".into())]
    );
    let mut document = openapi();
    remove(&mut document, "/openapi");
    assert_eq!(codes(&document), [(Code::MissingVersion, String::new())]);
}

#[test]
fn info_title_and_version_are_required_strings() {
    let mut document = openapi();
    remove(&mut document, "/info/title");
    remove(&mut document, "/info/version");
    assert_eq!(
        codes(&document),
        [
            (Code::MissingField, "/info/title".into()),
            (Code::MissingField, "/info/version".into())
        ]
    );
    set(
        &mut document,
        "/info",
        json!({"title": " ", "version": 1.0}),
    );
    assert_eq!(
        codes(&document),
        [
            (Code::InvalidType, "/info/title".into()),
            (Code::InvalidType, "/info/version".into())
        ]
    );
    set(&mut document, "/info", json!("text"));
    assert_eq!(codes(&document), [(Code::InvalidType, "/info".into())]);
    remove(&mut document, "/info");
    assert_eq!(codes(&document), [(Code::MissingField, "/info".into())]);
}

#[test]
fn paths_are_required_unless_openapi_31_has_components_or_webhooks() {
    let mut document = openapi();
    set(&mut document, "/security", json!([]));
    remove(&mut document, "/paths");
    assert_eq!(codes(&document), [(Code::MissingField, "/paths".into())]);
    set(&mut document, "/openapi", json!("3.1.0"));
    assert_eq!(codes(&document), []);
    remove(&mut document, "/components");
    assert_eq!(codes(&document), [(Code::MissingField, "/paths".into())]);
    document
        .as_object_mut()
        .unwrap()
        .insert("paths".into(), json!([]));
    assert_eq!(codes(&document), [(Code::InvalidType, "/paths".into())]);
}

#[test]
fn path_keys_items_and_method_keys_are_checked() {
    let document = json!({
        "openapi": "3.0.3",
        "info": {"title": "t", "version": "1"},
        "paths": {
            "pets": {},
            "/a": [],
            "/b": {"GET": {}, "fetch": {}, "get": [], "servers": []},
        }
    });
    assert_eq!(
        codes(&document),
        [
            (Code::InvalidType, "/paths/~1a".into()),
            (Code::InvalidMethod, "/paths/~1b/GET".into()),
            (Code::InvalidMethod, "/paths/~1b/fetch".into()),
            (Code::InvalidType, "/paths/~1b/get".into()),
            (Code::InvalidPathKey, "/paths/pets".into()),
        ]
    );
    let mut document = swagger();
    set(
        &mut document,
        "/paths/~1pets~1{id}/trace",
        json!({"responses": {"200": {"description": "x"}}}),
    );
    assert_eq!(
        codes(&document),
        [(Code::InvalidMethod, "/paths/~1pets~1{id}/trace".into())]
    );
}

#[test]
fn responses_are_required_before_openapi_31_and_warned_after() {
    let mut document = openapi();
    remove(&mut document, "/paths/~1pets~1{id}/delete/responses");
    assert_eq!(
        codes(&document),
        [(Code::MissingResponses, "/paths/~1pets~1{id}/delete".into())]
    );
    set(&mut document, "/openapi", json!("3.1.0"));
    let diagnostics = validate(&document);
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(diagnostics[0].severity, Severity::Warning);
    set(
        &mut document,
        "/paths/~1pets~1{id}/delete/responses",
        json!({}),
    );
    assert_eq!(
        codes(&document),
        [(
            Code::MissingResponses,
            "/paths/~1pets~1{id}/delete/responses".into()
        )]
    );
    set(
        &mut document,
        "/paths/~1pets~1{id}/delete/responses",
        json!([]),
    );
    assert_eq!(
        codes(&document),
        [(
            Code::InvalidType,
            "/paths/~1pets~1{id}/delete/responses".into()
        )]
    );
}

#[test]
fn status_keys_and_response_objects_are_checked() {
    let mut document = openapi();
    set(
        &mut document,
        "/paths/~1pets~1{id}/delete/responses",
        json!({"20": {"description": "x"}, "600": {"description": "x"}, "2xx": {"description": "x"}, "204": "text", "201": {}}),
    );
    let pointer = "/paths/~1pets~1{id}/delete/responses";
    assert_eq!(
        codes(&document),
        [
            (Code::InvalidStatusKey, format!("{pointer}/20")),
            (Code::MissingField, format!("{pointer}/201/description")),
            (Code::InvalidType, format!("{pointer}/204")),
            (Code::InvalidStatusKey, format!("{pointer}/2xx")),
            (Code::InvalidStatusKey, format!("{pointer}/600")),
        ]
    );
    // OpenAPI 3.2 makes the description optional.
    set(&mut document, "/openapi", json!("3.2.0"));
    set(&mut document, pointer, json!({"201": {}}));
    assert_eq!(codes(&document), []);
    // Swagger 2.0 has no range keys.
    let mut document = swagger();
    set(
        &mut document,
        "/paths/~1pets~1{id}/get/responses",
        json!({"2XX": {"description": "x"}}),
    );
    assert_eq!(
        codes(&document),
        [(
            Code::InvalidStatusKey,
            "/paths/~1pets~1{id}/get/responses/2XX".into()
        )]
    );
}

#[test]
fn path_parameters_must_be_declared_required_and_in_the_template() {
    let mut document = openapi();
    remove(&mut document, "/paths/~1pets~1{id}/parameters");
    let get = "/paths/~1pets~1{id}/get";
    let delete = "/paths/~1pets~1{id}/delete";
    assert_eq!(
        codes(&document),
        [
            (Code::UndeclaredPathParameter, delete.into()),
            (Code::UndeclaredPathParameter, get.into())
        ]
    );
    set(
        &mut document,
        &format!("{get}/parameters"),
        json!([
            {"name": "id", "in": "path", "schema": {"type": "string"}},
            {"name": "other", "in": "path", "required": true, "schema": {}},
        ]),
    );
    let codes = codes(&document);
    assert!(codes.contains(&(
        Code::PathParameterNotRequired,
        format!("{get}/parameters/0")
    )));
    assert!(codes.contains(&(Code::UnknownPathParameter, format!("{get}/parameters/1"))));
    assert!(!codes.contains(&(Code::UndeclaredPathParameter, get.into())));
}

#[test]
fn parameters_are_well_formed_and_unique() {
    let mut document = openapi();
    let pointer = "/paths/~1pets~1{id}/get/parameters";
    set(
        &mut document,
        "/paths/~1pets~1{id}/get",
        json!({"responses": {"200": {"description": "x"}}, "parameters": [
            {"name": "q", "in": "query", "schema": {}},
            {"name": "q", "in": "query", "content": {}},
            {"name": "q", "in": "header", "schema": {}},
            {"name": "", "in": "query"},
            {"name": "c", "in": "formData"},
            {"name": "t", "in": "query"},
            "text",
            {"$ref": "#/components/parameters/Missing"},
        ]}),
    );
    assert_eq!(
        codes(&document),
        [
            (Code::DuplicateParameter, format!("{pointer}/1")),
            (Code::InvalidParameter, format!("{pointer}/3")),
            (Code::InvalidParameter, format!("{pointer}/4")),
            (Code::InvalidParameter, format!("{pointer}/5")),
            (Code::InvalidType, format!("{pointer}/6")),
            (Code::UnresolvedRef, format!("{pointer}/7/$ref")),
        ]
    );
    set(&mut document, pointer, json!({}));
    assert_eq!(codes(&document), [(Code::InvalidType, pointer.into())]);
    // Swagger 2.0 types parameters with `type`, bodies with `schema`.
    let mut document = swagger();
    let pointer = "/paths/~1pets~1{id}/get/parameters";
    set(
        &mut document,
        pointer,
        json!([
            {"name": "id", "in": "path", "required": true, "schema": {}},
            {"name": "body", "in": "body", "type": "object"},
            {"name": "c", "in": "cookie", "type": "string"},
        ]),
    );
    assert_eq!(
        codes(&document),
        [
            (Code::InvalidParameter, format!("{pointer}/0")),
            (Code::InvalidParameter, format!("{pointer}/1")),
            (Code::InvalidParameter, format!("{pointer}/2")),
        ]
    );
}

#[test]
fn operation_ids_are_unique_strings() {
    let mut document = openapi();
    set(
        &mut document,
        "/paths/~1pets~1{id}/delete/operationId",
        json!("getPet"),
    );
    // Keys iterate alphabetically, so `delete` registers the id first.
    assert_eq!(
        codes(&document),
        [(
            Code::DuplicateOperationId,
            "/paths/~1pets~1{id}/get/operationId".into()
        )]
    );
    set(
        &mut document,
        "/paths/~1pets~1{id}/delete/operationId",
        json!(7),
    );
    assert_eq!(
        codes(&document),
        [(
            Code::InvalidType,
            "/paths/~1pets~1{id}/delete/operationId".into()
        )]
    );
}

#[test]
fn references_must_resolve_locally() {
    let mut document = openapi();
    set(
        &mut document,
        "/components/schemas",
        json!({
            "A": {"$ref": "#/components/schemas/B"},
            "Encoded": {"$ref": "#/paths/~1pets~1%7Bid%7D"},
            "Bad": {"$ref": "#/components/schemas/%zz"},
            "External": {"$ref": "common.yaml#/Pet"},
            "Typed": {"$ref": 3},
            "Skipped": {"default": {"$ref": "#/nowhere"}, "x-meta": {"$ref": "#/nowhere"}},
            "List": {"allOf": [{"$ref": "#/nowhere"}]},
        }),
    );
    let diagnostics = validate(&document);
    let found: Vec<_> = diagnostics
        .iter()
        .map(|d| (d.severity, d.code, d.pointer.as_str()))
        .collect();
    assert_eq!(
        found,
        [
            (
                Severity::Error,
                Code::UnresolvedRef,
                "/components/schemas/A/$ref"
            ),
            (
                Severity::Error,
                Code::UnresolvedRef,
                "/components/schemas/Bad/$ref"
            ),
            (
                Severity::Warning,
                Code::ExternalRef,
                "/components/schemas/External/$ref"
            ),
            (
                Severity::Error,
                Code::UnresolvedRef,
                "/components/schemas/List/allOf/0/$ref"
            ),
            (
                Severity::Error,
                Code::InvalidType,
                "/components/schemas/Typed/$ref"
            ),
        ]
    );
}

#[test]
fn reference_resolution_follows_chains_and_stops_at_cycles() {
    let document = json!({
        "a": {"$ref": "#/b"}, "b": {"$ref": "#/c"}, "c": 1,
        "loop": {"$ref": "#/loop"},
    });
    assert_eq!(resolve(&document, &document["a"]), Some(&json!(1)));
    assert_eq!(resolve(&document, &document["loop"]), None);
    assert_eq!(resolve(&document, &json!({"$ref": "#/missing"})), None);
    assert_eq!(
        resolve(&document, &json!({"$ref": "x.yaml"})),
        Some(&json!({"$ref": "x.yaml"}))
    );
    assert_eq!(lookup(&document, "b"), None);
    assert_eq!(percent_decode("%7B%"), "{%");
    assert_eq!(percent_decode("%4"), "%4");
}

#[test]
fn the_reference_walk_is_depth_bounded() {
    let mut deep = json!({"$ref": "#/missing"});
    for _ in 0..(MAX_WALK_DEPTH + 10) {
        deep = json!([deep]);
    }
    let mut document = openapi();
    set(&mut document, "/components/schemas", json!({"Deep": deep}));
    assert_eq!(codes(&document), []);
}

#[test]
fn servers_must_have_urls_without_credentials() {
    let mut document = openapi();
    set(
        &mut document,
        "/servers",
        json!([
            {"url": "/relative"},
            {"url": "https://user:secret@api.example.invalid/v1"},
            {"url": "https://api.example.invalid/path@segment"},
            {"url": ""},
            {"description": "no url"},
        ]),
    );
    assert_eq!(
        codes(&document),
        [
            (Code::InvalidServer, "/servers/1/url".into()),
            (Code::InvalidServer, "/servers/3".into()),
            (Code::InvalidServer, "/servers/4".into()),
        ]
    );
    set(&mut document, "/servers", json!({}));
    assert_eq!(codes(&document), [(Code::InvalidType, "/servers".into())]);
}

#[test]
fn swagger_hosts_base_paths_and_schemes_are_sane() {
    for (pointer, value) in [
        ("/host", json!("https://api.example.invalid")),
        ("/host", json!("api.example.invalid/v1")),
        ("/host", json!("")),
        ("/host", json!("user:pass@api.example.invalid")),
        ("/basePath", json!("v1")),
        ("/schemes", json!(["ftp"])),
        ("/schemes", json!("https")),
    ] {
        let mut document = swagger();
        set(&mut document, pointer, value);
        assert_eq!(codes(&document), [(Code::InvalidServer, pointer.into())]);
    }
}

#[test]
fn security_schemes_are_well_formed_and_requirements_defined() {
    let mut document = openapi();
    set(
        &mut document,
        "/components/securitySchemes",
        json!({
            "bearer": {"type": "http", "scheme": "bearer"},
            "a": {"type": "apiKey", "name": "k", "in": "body"},
            "b": {"type": "http"},
            "c": {"type": "oauth2"},
            "d": {"type": "openIdConnect"},
            "e": {"type": "basic"},
            "f": "text",
            "g": {"$ref": "#/missing"},
        }),
    );
    set(
        &mut document,
        "/paths/~1pets~1{id}/delete/security",
        json!([{"nope": []}, "x"]),
    );
    let schemes = "/components/securitySchemes";
    assert_eq!(
        codes(&document),
        [
            (Code::InvalidSecurityScheme, format!("{schemes}/a")),
            (Code::InvalidSecurityScheme, format!("{schemes}/b")),
            (Code::InvalidSecurityScheme, format!("{schemes}/c")),
            (Code::InvalidSecurityScheme, format!("{schemes}/d")),
            (Code::InvalidSecurityScheme, format!("{schemes}/e")),
            (Code::InvalidSecurityScheme, format!("{schemes}/f")),
            (
                Code::UndefinedSecurityScheme,
                "/paths/~1pets~1{id}/delete/security/0/nope".into()
            ),
            (
                Code::InvalidType,
                "/paths/~1pets~1{id}/delete/security/1".into()
            ),
            (Code::UnresolvedRef, format!("{schemes}/g/$ref")),
        ]
    );
    set(&mut document, "/security", json!({}));
    assert!(codes(&document).contains(&(Code::InvalidType, "/security".into())));
    // mutualTLS arrived with 3.1.
    let mut document = openapi();
    set(
        &mut document,
        "/components/securitySchemes/tls",
        json!({"type": "mutualTLS"}),
    );
    assert_eq!(
        codes(&document),
        [(Code::InvalidSecurityScheme, format!("{schemes}/tls"))]
    );
    // Swagger 2.0 has its own scheme kinds.
    let mut document = swagger();
    set(
        &mut document,
        "/securityDefinitions",
        json!({"http": {"type": "http", "scheme": "bearer"}, "o": {"type": "oauth2", "flow": "code"}, "k": {"type": "apiKey", "name": "k", "in": "cookie"}}),
    );
    assert_eq!(
        codes(&document),
        [
            (
                Code::InvalidSecurityScheme,
                "/securityDefinitions/http".into()
            ),
            (Code::InvalidSecurityScheme, "/securityDefinitions/k".into()),
            (Code::InvalidSecurityScheme, "/securityDefinitions/o".into()),
            (
                Code::UndefinedSecurityScheme,
                "/paths/~1pets~1{id}/get/security/0/oauth".into()
            ),
        ]
    );
}

#[test]
fn helpers_behave_at_their_edges() {
    assert_eq!(escape("/a~b"), "~1a~0b");
    assert_eq!(
        template_parameters("/a/{x}/b/{y}/{unclosed"),
        ["x".to_string(), "y".to_string()].into()
    );
    assert!(valid_status("default", SpecVersion::Swagger20));
    assert!(!valid_status("abc", SpecVersion::OpenApi30));
    assert!(!embeds_credentials("/relative@path"));
}
