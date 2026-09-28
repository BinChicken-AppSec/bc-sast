//! The AsyncAPI standard end to end: the same outcomes as OpenAPI.

use super::*;

const PRODUCER: &str = "src/events.js";

/// A Kafka service (no HTTP framework) that sends one event and receives
/// another, and has no AsyncAPI document.
fn events_repo() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    write(
        root.path(),
        "package.json",
        r#"{"dependencies":{"kafkajs":"2"}}"#,
    );
    write(
        root.path(),
        PRODUCER,
        "const producer = kafka.producer();\nconst consumer = kafka.consumer({ groupId: 'users' });\nawait producer.send({ topic: 'user.signedup', messages });\nawait consumer.subscribe({ topic: 'order.created' });\n",
    );
    root
}

fn events_inventory() -> serde_json::Value {
    json!([
        {"method": "send", "path": "user.signedup", "file": PRODUCER, "line": 3, "snippet": "topic: 'user.signedup'"},
        {"method": "RECEIVE", "path": "order.created", "file": PRODUCER, "line": 4, "snippet": "topic: 'order.created'"},
    ])
}

fn new_events() -> serde_json::Value {
    json!({
        "asyncapi": "3.0.0",
        "info": {"title": "Users", "version": "1.0.0"},
        "servers": {"production": {"host": "<broker-host>:9092", "protocol": "kafka"}},
        "channels": {
            "userSignedUp": {"address": "user.signedup", "messages": {"UserSignedUp": {"payload": {"type": "object"}}}},
            "orderCreated": {"address": "order.created", "messages": {"OrderCreated": {"payload": {"type": "object"}}}},
        },
        "operations": {
            "sendUserSignedUp": {"action": "send", "channel": {"$ref": "#/channels/userSignedUp"},
                                  "messages": [{"$ref": "#/channels/userSignedUp/messages/UserSignedUp"}]},
            "onOrderCreated": {"action": "receive", "channel": {"$ref": "#/channels/orderCreated"}},
        },
    })
}

const COMPLETE_EVENTS: &str = "\
# Events of the users service
asyncapi: 2.6.0
info:
  title: Users
  version: \"1.0.0\"
channels:
  user.signedup:
    subscribe:
      operationId: userSignedUp
  order.created:
    publish:
      operationId: orderCreated
";

const BROKEN_EVENTS: &str = "\
# Events of the users service
asyncapi: 2.6.0
info:
  title: Users
  version: 1.0
channels:
  user.signedup:
    subscribe:
      operationId: userSignedUp
";

fn events_repair() -> serde_json::Value {
    json!([
        {"old": "  version: 1.0\n", "new": "  version: \"1.0.0\"\n"},
        {"old": "      operationId: userSignedUp\n", "new": "      operationId: userSignedUp\n  order.created:\n    publish:\n      operationId: orderCreated\n"},
    ])
}

fn events_reply(decision: &str, edits: serde_json::Value) -> String {
    json!({"decision": decision, "edits": edits, "inventory": events_inventory()}).to_string()
}

fn only_asyncapi(assurance: &Assurance) -> &SpecOutcome {
    let outcome = only(assurance);
    assert_eq!(outcome.spec_format, FormatId::AsyncApi);
    outcome
}

#[tokio::test]
async fn a_missing_asyncapi_document_is_created_from_cited_producers_and_consumers() {
    let root = events_repo();
    let reply =
        json!({"decision": "create", "document": new_events(), "inventory": events_inventory()})
            .to_string();
    let client = Client::texts(&[reply, review(true)]);
    let assurance = run_step(root.path(), &config(), &client).await;
    let outcome = only_asyncapi(&assurance);
    assert_eq!(outcome.action, SpecAction::Created, "{outcome:?}");
    assert_eq!(outcome.path, "asyncapi.yaml");
    assert_eq!(outcome.frameworks, ["kafka"]);
    let written = read(root.path(), "asyncapi.yaml");
    assert!(written.starts_with("\"asyncapi\": \"3.0.0\"\n"));
    assert_eq!(
        bc_api_spec::parse::parse(&written, Syntax::Yaml).unwrap(),
        new_events()
    );
}

#[tokio::test]
async fn a_valid_complete_2x_document_is_left_unchanged() {
    let root = events_repo();
    write(root.path(), "asyncapi.yaml", COMPLETE_EVENTS);
    let client = Client::texts(&[events_reply("no_change", json!([])), review(true)]);
    let assurance = run_step(root.path(), &config(), &client).await;
    let outcome = only_asyncapi(&assurance);
    assert_eq!(outcome.action, SpecAction::Complete);
    assert_eq!(outcome.version, Some(SpecVersion::AsyncApi2));
    assert_eq!(read(root.path(), "asyncapi.yaml"), COMPLETE_EVENTS);
}

#[tokio::test]
async fn a_broken_document_is_repaired_in_its_own_version() {
    let root = events_repo();
    write(root.path(), "asyncapi.yaml", BROKEN_EVENTS);
    let client = Client::texts(&[events_reply("repair", events_repair()), review(true)]);
    let assurance = run_step(root.path(), &config(), &client).await;
    let outcome = only_asyncapi(&assurance);
    assert_eq!(outcome.action, SpecAction::Repaired);
    assert!(outcome.missing_operations.is_empty());
    assert!(outcome
        .diagnostics_before
        .iter()
        .any(|diagnostic| diagnostic.pointer == "/info/version"));
    assert_eq!(read(root.path(), "asyncapi.yaml"), COMPLETE_EVENTS);
}

#[tokio::test]
async fn a_repair_that_converts_the_version_is_refused() {
    let root = events_repo();
    write(root.path(), "asyncapi.yaml", COMPLETE_EVENTS);
    let converting = json!([{"old": "asyncapi: 2.6.0\n", "new": "asyncapi: 3.0.0\n"}]);
    let reply = events_reply("repair", converting);
    let client = Client::texts(&[reply.clone(), reply.clone(), reply]);
    let assurance = run_step(root.path(), &config(), &client).await;
    let outcome = only_asyncapi(&assurance);
    assert_eq!(outcome.action, SpecAction::Rejected);
    assert!(outcome
        .gaps
        .last()
        .unwrap()
        .contains("changed the specification version"));
    assert_eq!(read(root.path(), "asyncapi.yaml"), COMPLETE_EVENTS);
}

#[tokio::test]
async fn yaml_outside_the_parser_subset_is_untouched() {
    let root = events_repo();
    let anchored = "asyncapi: 2.6.0\ninfo: &info\n  title: Users\n  version: \"1\"\nchannels: {}\n";
    write(root.path(), "asyncapi.yaml", anchored);
    let client = Client::new(Vec::new());
    let assurance = run_step(root.path(), &config(), &client).await;
    assert_eq!(only_asyncapi(&assurance).action, SpecAction::Unverifiable);
    assert_eq!(read(root.path(), "asyncapi.yaml"), anchored);
    assert_eq!(client.calls(), 0);
}

#[tokio::test]
async fn a_rejected_review_or_a_secret_writes_nothing() {
    let root = events_repo();
    write(root.path(), "asyncapi.yaml", BROKEN_EVENTS);
    let client = Client::texts(&[events_reply("repair", events_repair()), review(false)]);
    let assurance = run_step(root.path(), &config(), &client).await;
    assert_eq!(only_asyncapi(&assurance).action, SpecAction::Rejected);
    assert_eq!(read(root.path(), "asyncapi.yaml"), BROKEN_EVENTS);

    let root = events_repo();
    let mut leaky = new_events();
    leaky["servers"]["production"]["host"] = json!("app:hunter2hunter2@broker.invalid:9092");
    leaky["channels"]["userSignedUp"]["messages"]["UserSignedUp"]["payload"]["example"] =
        json!({"token": format!("sk_live_{}", "a".repeat(24))});
    let reply = json!({"decision": "create", "document": leaky, "inventory": events_inventory()})
        .to_string();
    let client = Client::texts(&[reply.clone(), reply.clone(), reply]);
    let assurance = run_step(root.path(), &config(), &client).await;
    let outcome = only_asyncapi(&assurance);
    assert_eq!(outcome.action, SpecAction::Rejected);
    let last = outcome.gaps.last().unwrap();
    assert!(
        last.contains("look like credentials") && last.contains("must not embed credentials"),
        "{last}"
    );
    assert!(!root.path().join("asyncapi.yaml").exists());
}

#[tokio::test]
async fn an_asyncapi_document_anywhere_is_assessed_in_place() {
    // No messaging library reads a fixed location, so nothing is moved.
    let root = events_repo();
    write(root.path(), "docs/events/asyncapi.yaml", COMPLETE_EVENTS);
    let client = Client::texts(&[events_reply("no_change", json!([])), review(true)]);
    let assurance = run_step(root.path(), &config(), &client).await;
    let outcome = only_asyncapi(&assurance);
    assert_eq!(outcome.action, SpecAction::Complete);
    assert_eq!(outcome.path, "docs/events/asyncapi.yaml");
    assert!(!client.prompt(1).contains("Relocation:"));
}
