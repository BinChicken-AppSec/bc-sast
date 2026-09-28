//! The OpenRPC standard end to end: the same outcomes as OpenAPI.

use super::*;

const HANDLERS: &str = "src/rpc.py";

/// A JSON-RPC service (no HTTP framework) with two methods and no
/// OpenRPC document.
fn rpc_repo() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    write(root.path(), "requirements.txt", "jsonrpcserver==5.0\n");
    write(
        root.path(),
        HANDLERS,
        "from jsonrpcserver import method, Success\n\n@method\ndef pet_get(id):\n    return Success({\"id\": id})\n\n@method\ndef pet_put(pet):\n    return Success(pet)\n",
    );
    root
}

fn rpc_inventory() -> serde_json::Value {
    json!([
        {"method": "call", "path": "pet_get", "file": HANDLERS, "line": 4, "snippet": "def pet_get(id):"},
        {"method": "call", "path": "pet_put", "file": HANDLERS, "line": 8, "snippet": "def pet_put(pet):"},
    ])
}

fn method(name: &str, param: &str) -> serde_json::Value {
    json!({"name": name, "params": [{"name": param, "schema": {"type": "object"}}],
           "result": {"name": "pet", "schema": {"type": "object"}}})
}

fn new_rpc() -> serde_json::Value {
    json!({
        "openrpc": "1.3.2",
        "info": {"title": "Pets", "version": "1.0.0"},
        "methods": [method("pet_get", "id"), method("pet_put", "pet")],
    })
}

fn rpc_reply(decision: &str, edits: serde_json::Value) -> String {
    json!({"decision": decision, "edits": edits, "inventory": rpc_inventory()}).to_string()
}

fn only_openrpc(assurance: &Assurance) -> &SpecOutcome {
    let outcome = only(assurance);
    assert_eq!(outcome.spec_format, FormatId::OpenRpc);
    outcome
}

#[tokio::test]
async fn a_missing_openrpc_document_is_created_as_json() {
    let root = rpc_repo();
    let reply = json!({"decision": "create", "document": new_rpc(), "inventory": rpc_inventory()})
        .to_string();
    let client = Client::texts(&[reply, review(true)]);
    let assurance = run_step(root.path(), &config(), &client).await;
    let outcome = only_openrpc(&assurance);
    assert_eq!(outcome.action, SpecAction::Created, "{outcome:?}");
    assert_eq!(outcome.path, "openrpc.json");
    let written = read(root.path(), "openrpc.json");
    assert!(written.starts_with("{\n  \"openrpc\": \"1.3.2\""));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&written).unwrap(),
        new_rpc()
    );
}

#[tokio::test]
async fn complete_and_incomplete_documents() {
    // Complete: unchanged.
    let root = rpc_repo();
    let complete = bc_api_spec::emit::to_json(&new_rpc());
    write(root.path(), "openrpc.json", &complete);
    let client = Client::texts(&[rpc_reply("no_change", json!([])), review(true)]);
    let assurance = run_step(root.path(), &config(), &client).await;
    assert_eq!(only_openrpc(&assurance).action, SpecAction::Complete);
    assert_eq!(read(root.path(), "openrpc.json"), complete);

    // Missing a method: a minimal edit adds it.
    let root = rpc_repo();
    let partial = "{\n  \"openrpc\": \"1.3.2\",\n  \"info\": {\"title\": \"Pets\", \"version\": \"1.0.0\"},\n  \"methods\": [\n    {\"name\": \"pet_get\", \"params\": [], \"result\": {\"name\": \"pet\", \"schema\": {}}}\n  ]\n}\n";
    write(root.path(), "openrpc.json", partial);
    let edits = json!([{"old": "\"schema\": {}}}\n", "new": "\"schema\": {}}},\n    {\"name\": \"pet_put\", \"params\": [], \"result\": {\"name\": \"pet\", \"schema\": {}}}\n"}]);
    let client = Client::texts(&[rpc_reply("repair", edits), review(true)]);
    let assurance = run_step(root.path(), &config(), &client).await;
    let outcome = only_openrpc(&assurance);
    assert_eq!(outcome.action, SpecAction::Repaired, "{outcome:?}");
    assert!(read(root.path(), "openrpc.json").contains("\"name\": \"pet_put\""));

    // A review rejection leaves it as it was.
    let root = rpc_repo();
    write(root.path(), "openrpc.json", partial);
    let edits = json!([{"old": "\"schema\": {}}}\n", "new": "\"schema\": {}}},\n    {\"name\": \"pet_put\", \"params\": [], \"result\": {\"name\": \"pet\", \"schema\": {}}}\n"}]);
    let client = Client::texts(&[rpc_reply("repair", edits), review(false)]);
    let assurance = run_step(root.path(), &config(), &client).await;
    assert_eq!(only_openrpc(&assurance).action, SpecAction::Rejected);
    assert_eq!(read(root.path(), "openrpc.json"), partial);
}

#[tokio::test]
async fn an_unsupported_version_is_untouched_and_a_secret_is_refused() {
    let root = rpc_repo();
    write(
        root.path(),
        "openrpc.json",
        "{\"openrpc\": \"2.0.0\", \"methods\": []}",
    );
    let client = Client::new(Vec::new());
    let assurance = run_step(root.path(), &config(), &client).await;
    let outcome = only_openrpc(&assurance);
    assert_eq!(outcome.action, SpecAction::Unverifiable);
    assert!(outcome.gaps[0].contains("version this step does not support"));

    let root = rpc_repo();
    let mut leaky = new_rpc();
    leaky["methods"][0]["params"][0]["schema"]["example"] =
        json!("ghp_0123456789abcdefghijklmnopqrstuvwxyzAB");
    let reply =
        json!({"decision": "create", "document": leaky, "inventory": rpc_inventory()}).to_string();
    let client = Client::texts(&[reply.clone(), reply.clone(), reply]);
    let assurance = run_step(root.path(), &config(), &client).await;
    assert_eq!(only_openrpc(&assurance).action, SpecAction::Rejected);
    assert!(!root.path().join("openrpc.json").exists());
}

#[tokio::test]
async fn an_openrpc_document_anywhere_is_assessed_in_place() {
    let root = rpc_repo();
    let complete = bc_api_spec::emit::to_json(&new_rpc());
    write(root.path(), "docs/rpc/openrpc.json", &complete);
    let client = Client::texts(&[rpc_reply("no_change", json!([])), review(true)]);
    let assurance = run_step(root.path(), &config(), &client).await;
    let outcome = only_openrpc(&assurance);
    assert_eq!(outcome.action, SpecAction::Complete);
    assert_eq!(outcome.path, "docs/rpc/openrpc.json");
}
