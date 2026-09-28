//! Standards the step checks and reports but never writes: Protocol
//! Buffers, RAML and API Blueprint. No model is involved.

use super::*;

const ORDERS_PROTO: &str = "api/proto/shop/v1/orders.proto";
const ORDERS: &str = "\
syntax = \"proto3\";
package shop.v1;
import \"shop/v1/common.proto\";
message GetRequest { string id = 1; }
service Orders { rpc Get (GetRequest) returns (Money); }
service Admin { rpc Ping (GetRequest) returns (GetRequest); }
";
const COMMON: &str = "syntax = \"proto3\";\npackage shop.v1;\nmessage Money { int64 cents = 1; }\n";

/// A gRPC service whose code registers one defined service and one that
/// no definition declares.
fn grpc_repo() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    write(
        root.path(),
        "go.mod",
        "module shop\nrequire google.golang.org/grpc v1.60.0\n",
    );
    write(root.path(), ORDERS_PROTO, ORDERS);
    write(root.path(), "api/proto/shop/v1/common.proto", COMMON);
    write(
        root.path(),
        "cmd/server/main.go",
        "func main() {\n\ts := grpc.NewServer()\n\tpb.RegisterOrdersServer(s, &orders{})\n\tpb.RegisterShippingServer(s, &shipping{})\n}\n",
    );
    // A test's in-process server is not the service's registration.
    write(
        root.path(),
        "cmd/server/main_test.go",
        "pb.RegisterAdminServer(s, &fake{})\n",
    );
    root
}

fn outcome<'a>(assurance: &'a Assurance, path: &str) -> &'a SpecOutcome {
    assurance
        .api_spec
        .documents
        .iter()
        .find(|outcome| outcome.path == path)
        .unwrap()
}

#[tokio::test]
async fn proto_files_are_checked_against_server_registrations() {
    let root = grpc_repo();
    let client = Client::new(Vec::new());
    let assurance = run_step(root.path(), &config(), &client).await;
    assert_eq!(client.calls(), 0);
    assert_eq!(assurance.api_spec.documents.len(), 2);
    let orders = outcome(&assurance, ORDERS_PROTO);
    assert_eq!(orders.spec_format, FormatId::Protobuf);
    assert_eq!(orders.action, SpecAction::Reported);
    assert_eq!(orders.version, Some(SpecVersion::Proto3));
    assert_eq!(orders.syntax, Some(Syntax::Protobuf));
    assert_eq!(orders.frameworks, ["grpc"]);
    assert!(orders.diagnostics_before.is_empty(), "{orders:?}");
    assert_eq!(
        orders.unverified_operations,
        [Operation::new("service", "shop.v1.Admin")]
    );
    assert_eq!(orders.inventory.len(), 1);
    assert_eq!(orders.inventory[0].file, "cmd/server/main.go");
    assert_eq!(orders.inventory[0].line, 3);
    assert!(orders.gaps[0].contains("source of truth"));
    assert!(orders.gaps[1].contains("shop.v1.Admin"));
    let note = assurance.api_spec.notes.last().unwrap();
    assert!(
        note.starts_with("Protocol Buffers: the code registers services")
            && note.contains("cmd/server/main.go:4 (Shipping)"),
        "{note}"
    );
    // Nothing was written.
    assert_eq!(read(root.path(), ORDERS_PROTO), ORDERS);
    assert!(!assurance.approved_bytes.contains_key(ORDERS_PROTO));
}

#[tokio::test]
async fn proto_problems_are_reported_and_unreadable_files_left_alone() {
    let root = grpc_repo();
    let broken = ORDERS.replace("string id = 1;", "string id = 1; string key = 1;");
    write(root.path(), ORDERS_PROTO, &broken);
    write(root.path(), "api/proto/legacy.proto", "message {\n");
    let client = Client::new(Vec::new());
    let assurance = run_step(root.path(), &config(), &client).await;
    let orders = outcome(&assurance, ORDERS_PROTO);
    assert_eq!(orders.action, SpecAction::Reported);
    assert!(orders
        .diagnostics_before
        .iter()
        .any(|d| d.pointer == "/messages/GetRequest/fields/key"));
    assert_eq!(read(root.path(), ORDERS_PROTO), broken);
    let legacy = outcome(&assurance, "api/proto/legacy.proto");
    assert_eq!(legacy.action, SpecAction::Unverifiable);
    assert!(legacy.gaps[0].contains("built-in Protocol Buffers parser"));
    // With every registration defined, no run-level note is added.
    write(
        root.path(),
        "cmd/server/main.go",
        "pb.RegisterOrdersServer(s, &orders{})\n",
    );
    let assurance = run_step(root.path(), &config(), &client).await;
    assert!(!assurance
        .api_spec
        .notes
        .iter()
        .any(|note| note.contains("registers services")));
}

#[tokio::test]
async fn a_registration_scan_beyond_its_bounds_is_named_not_guessed() {
    let root = grpc_repo();
    write(root.path(), &format!("{}deep.txt", "d/".repeat(34)), "x");
    let client = Client::new(Vec::new());
    let assurance = run_step(root.path(), &config(), &client).await;
    let orders = outcome(&assurance, ORDERS_PROTO);
    assert!(orders.unverified_operations.is_empty() && orders.inventory.is_empty());
    let note = assurance.api_spec.notes.last().unwrap();
    assert!(
        note.contains("were not checked") && note.contains("depth limit"),
        "{note}"
    );
}

#[tokio::test]
async fn many_unmatched_registrations_are_summarized() {
    let root = grpc_repo();
    let many: String = (0..25)
        .map(|index| format!("pb.RegisterExtra{index}Server(s, x)\n"))
        .collect();
    write(root.path(), "cmd/extra/main.go", &many);
    let client = Client::new(Vec::new());
    let assurance = run_step(root.path(), &config(), &client).await;
    let note = assurance.api_spec.notes.last().unwrap();
    assert!(note.ends_with("and 6 more"), "{note}");
}

#[tokio::test]
async fn raml_and_api_blueprint_are_reported_with_a_conversion_note() {
    let root = tempfile::tempdir().unwrap();
    write(
        root.path(),
        "api/pets.raml",
        "#%RAML 1.0\ntitle: Pets\n/pets:\n  get:\n    responses:\n      200: {}\n",
    );
    write(
        root.path(),
        "api/included.raml",
        "#%RAML 1.0\ntitle: x\n/a: !include a.raml\n",
    );
    write(
        root.path(),
        "docs/pets.apib",
        "FORMAT: 1A\n\n# Pets\n\n## Pets [/pets]\n### List [GET]\n",
    );
    let client = Client::new(Vec::new());
    let assurance = run_step(root.path(), &config(), &client).await;
    assert_eq!(client.calls(), 0);
    let raml = outcome(&assurance, "api/pets.raml");
    assert_eq!(raml.spec_format, FormatId::Raml);
    assert_eq!(raml.action, SpecAction::Reported);
    assert_eq!(raml.version, Some(SpecVersion::Raml10));
    assert!(raml.diagnostics_before.is_empty());
    assert!(raml.gaps[0].starts_with("RAML is checked but never rewritten"));
    assert!(raml.gaps[0].contains("converted to OpenAPI by hand"));
    let included = outcome(&assurance, "api/included.raml");
    assert_eq!(included.action, SpecAction::Unverifiable);
    let blueprint = outcome(&assurance, "docs/pets.apib");
    assert_eq!(blueprint.spec_format, FormatId::ApiBlueprint);
    assert_eq!(blueprint.action, SpecAction::Reported);
    assert!(blueprint.gaps[0].starts_with("API Blueprint is checked"));
    // The action has no response: reported, not repaired.
    assert!(blueprint
        .diagnostics_before
        .iter()
        .any(|d| d.message.contains("no `+ Response`")));
    let artifact = serde_json::to_value(&assurance.api_spec).unwrap();
    assert!(artifact["documents"]
        .as_array()
        .unwrap()
        .iter()
        .any(|document| document["action"] == "reported" && document["spec_format"] == "raml"));
}
