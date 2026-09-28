//! The GraphQL SDL standard end to end: the same outcomes as OpenAPI.

use super::*;

const RESOLVER: &str = "src/main/java/com/example/UserController.java";
const SCHEMA_PATH: &str = "src/main/resources/graphql/schema.graphqls";

/// A Spring for GraphQL service (no HTTP framework, so OpenAPI stays out)
/// with a query and a mutation and no schema.
fn graphql_repo() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    write(
        root.path(),
        "pom.xml",
        "<project><dependency><artifactId>spring-boot-starter-graphql</artifactId></dependency></project>\n",
    );
    write(
        root.path(),
        RESOLVER,
        "package com.example;\n\n@Controller\npublic class UserController {\n    @QueryMapping\n    public User user(@Argument String id) { return null; }\n    @MutationMapping\n    public User createUser(@Argument String name) { return null; }\n}\n",
    );
    root
}

fn graphql_inventory() -> serde_json::Value {
    json!([
        {"method": "query", "path": "user", "file": RESOLVER, "line": 6, "snippet": "public User user(@Argument String id)"},
        {"method": "MUTATION", "path": "createUser", "file": RESOLVER, "line": 8, "snippet": "public User createUser("},
    ])
}

const COMPLETE_SDL: &str = "\
# Users API
\"A user of the service\"
type User {
  id: ID!
  name: String
}

type Query {
  user(id: ID!): User
}

type Mutation {
  createUser(name: String!): User
}
";

/// The same schema without the mutation root and with an unknown type.
const BROKEN_SDL: &str = "\
# Users API
\"A user of the service\"
type User {
  id: ID!
  name: String
}

type Query {
  user(id: ID!): Person
}
";

fn repair() -> serde_json::Value {
    json!([
        {"old": "  user(id: ID!): Person\n}\n", "new": "  user(id: ID!): User\n}\n\ntype Mutation {\n  createUser(name: String!): User\n}\n"},
    ])
}

fn graphql_create(document: &str) -> String {
    json!({"decision": "create", "document": document, "inventory": graphql_inventory(),
           "changes": ["documented both root fields"]})
    .to_string()
}

fn graphql_reply(decision: &str, edits: serde_json::Value) -> String {
    json!({"decision": decision, "edits": edits, "inventory": graphql_inventory()}).to_string()
}

fn only_graphql(assurance: &Assurance) -> &SpecOutcome {
    let outcome = only(assurance);
    assert_eq!(outcome.spec_format, FormatId::Graphql);
    outcome
}

#[tokio::test]
async fn a_missing_schema_is_created_at_the_library_convention() {
    let root = graphql_repo();
    let client = Client::texts(&[graphql_create(COMPLETE_SDL), review(true)]);
    let assurance = run_step(root.path(), &config(), &client).await;
    let outcome = only_graphql(&assurance);
    assert_eq!(outcome.action, SpecAction::Created);
    assert_eq!(outcome.path, SCHEMA_PATH);
    assert_eq!(outcome.syntax, Some(Syntax::Graphql));
    assert_eq!(outcome.frameworks, ["spring_graphql"]);
    assert_eq!(read(root.path(), SCHEMA_PATH), COMPLETE_SDL);
    assert!(client.prompt(0).contains("\"state\":\"missing\""));
    assert!(client
        .prompt(1)
        .contains(&format!("Create {SCHEMA_PATH} (Graphql)")));
    assert!(assurance.approved_bytes.contains_key(SCHEMA_PATH));
    assert!(!outcome.gaps.iter().any(|gap| gap.contains("snapshot")));
}

#[tokio::test]
async fn a_code_first_schema_is_created_as_a_snapshot_and_says_so() {
    let root = tempfile::tempdir().unwrap();
    write(
        root.path(),
        "requirements.txt",
        "strawberry-graphql==0.220\n",
    );
    write(
        root.path(),
        "app/schema.py",
        "@strawberry.type\nclass Query:\n    @strawberry.field\n    def user(self, id: str) -> User: ...\n",
    );
    let inventory = json!([{"method": "query", "path": "user", "file": "app/schema.py", "line": 4, "snippet": "def user(self, id: str)"}]);
    let sdl = "type User { id: ID! }\ntype Query { user(id: ID!): User }\n";
    let reply = json!({"decision": "create", "document": sdl, "inventory": inventory}).to_string();
    let client = Client::texts(&[reply, review(true)]);
    let assurance = run_step(root.path(), &config(), &client).await;
    let outcome = only_graphql(&assurance);
    assert_eq!(outcome.action, SpecAction::Created);
    assert_eq!(outcome.path, "schema.graphql");
    assert!(client.prompt(0).contains("\"code_first\""));
    let gap = outcome.gaps.last().unwrap();
    assert!(
        gap.contains("strawberry build this GraphQL document from code")
            && gap.contains("reviewed static snapshot"),
        "{gap}"
    );
}

#[tokio::test]
async fn a_service_that_serves_no_graphql_gets_no_schema() {
    let root = graphql_repo();
    let reply = json!({"decision": "not_applicable", "inventory": []}).to_string();
    let client = Client::texts(&[reply]);
    let assurance = run_step(root.path(), &config(), &client).await;
    let outcome = only_graphql(&assurance);
    assert_eq!(outcome.action, SpecAction::Skipped);
    assert!(outcome.gaps[0].contains("no GraphQL operations"));
    assert!(!root.path().join(SCHEMA_PATH).exists());
    assert_eq!(client.calls(), 1);
    // Claiming there is nothing while citing operations is refused.
    let cited = json!({"decision": "not_applicable", "inventory": graphql_inventory()}).to_string();
    let client = Client::texts(&[cited.clone(), cited.clone(), cited]);
    let assurance = run_step(root.path(), &config(), &client).await;
    assert!(only_graphql(&assurance)
        .gaps
        .last()
        .unwrap()
        .contains("the inventory must be empty"));
}

#[tokio::test]
async fn a_valid_complete_schema_is_left_unchanged() {
    let root = graphql_repo();
    write(root.path(), SCHEMA_PATH, COMPLETE_SDL);
    let client = Client::texts(&[graphql_reply("no_change", json!([])), review(true)]);
    let assurance = run_step(root.path(), &config(), &client).await;
    let outcome = only_graphql(&assurance);
    assert_eq!(outcome.action, SpecAction::Complete);
    assert!(outcome.diagnostics_before.is_empty());
    assert_eq!(read(root.path(), SCHEMA_PATH), COMPLETE_SDL);
}

#[tokio::test]
async fn a_broken_schema_is_repaired_with_minimal_edits() {
    let root = graphql_repo();
    write(root.path(), SCHEMA_PATH, BROKEN_SDL);
    let client = Client::texts(&[graphql_reply("repair", repair()), review(true)]);
    let assurance = run_step(root.path(), &config(), &client).await;
    let outcome = only_graphql(&assurance);
    assert_eq!(outcome.action, SpecAction::Repaired);
    assert!(outcome
        .diagnostics_before
        .iter()
        .any(|diagnostic| diagnostic.pointer == "/types/Query/fields/user"));
    assert!(outcome.diagnostics_after.is_empty());
    assert_eq!(read(root.path(), SCHEMA_PATH), COMPLETE_SDL);
    assert!(client.prompt(0).contains("# Users API"));
}

#[tokio::test]
async fn a_repair_that_drops_a_documented_type_is_refused() {
    let root = graphql_repo();
    write(root.path(), SCHEMA_PATH, BROKEN_SDL);
    let dropping = json!([{"old": "\"A user of the service\"\ntype User {\n  id: ID!\n  name: String\n}\n", "new": ""}]);
    let reply = graphql_reply("repair", dropping);
    let client = Client::texts(&[reply.clone(), reply.clone(), reply]);
    let assurance = run_step(root.path(), &config(), &client).await;
    let outcome = only_graphql(&assurance);
    assert_eq!(outcome.action, SpecAction::Rejected);
    assert!(outcome
        .gaps
        .last()
        .unwrap()
        .contains("removed documented type `User`"));
    assert_eq!(read(root.path(), SCHEMA_PATH), BROKEN_SDL);
}

#[tokio::test]
async fn sdl_the_built_in_parser_cannot_read_is_untouched() {
    let root = graphql_repo();
    write(root.path(), SCHEMA_PATH, "type Query {\n  user: [User\n}\n");
    let client = Client::new(Vec::new());
    let assurance = run_step(root.path(), &config(), &client).await;
    let outcome = only_graphql(&assurance);
    assert_eq!(outcome.action, SpecAction::Unverifiable);
    assert!(outcome.gaps[0].contains("built-in GraphQL parser"));
    assert_eq!(client.calls(), 0);
}

#[tokio::test]
async fn a_rejected_review_writes_nothing() {
    let root = graphql_repo();
    write(root.path(), SCHEMA_PATH, BROKEN_SDL);
    let client = Client::texts(&[graphql_reply("repair", repair()), review(false)]);
    let assurance = run_step(root.path(), &config(), &client).await;
    assert_eq!(only_graphql(&assurance).action, SpecAction::Rejected);
    assert_eq!(read(root.path(), SCHEMA_PATH), BROKEN_SDL);
}

#[tokio::test]
async fn a_secret_in_a_description_is_never_written() {
    let root = graphql_repo();
    let leaky = COMPLETE_SDL.replace(
        "\"A user of the service\"",
        "\"Use ghp_0123456789abcdefghijklmnopqrstuvwxyzAB\"",
    );
    let reply = graphql_create(&leaky);
    let client = Client::texts(&[reply.clone(), reply.clone(), reply]);
    let assurance = run_step(root.path(), &config(), &client).await;
    let outcome = only_graphql(&assurance);
    assert_eq!(outcome.action, SpecAction::Rejected);
    assert!(outcome
        .gaps
        .last()
        .unwrap()
        .contains("look like credentials"));
    assert!(!root.path().join(SCHEMA_PATH).exists());
}

#[tokio::test]
async fn schema_files_split_across_a_directory_are_read_together() {
    let root = graphql_repo();
    write(
        root.path(),
        "src/main/resources/graphql/types.graphqls",
        "\"A user of the service\"\ntype User {\n  id: ID!\n  name: String\n}\n\ntype Query {\n  user(id: ID!): User\n}\n",
    );
    write(
        root.path(),
        "src/main/resources/graphql/mutations.graphqls",
        "type Mutation {\n  createUser(name: String!): User\n}\n",
    );
    // A client query document is not a schema and is ignored.
    write(
        root.path(),
        "client/me.graphql",
        "query Me { user(id: \"1\") { id } }\n",
    );
    let client = Client::texts(&[
        graphql_reply("no_change", json!([])),
        review(true),
        graphql_reply("no_change", json!([])),
        review(true),
    ]);
    let assurance = run_step(root.path(), &config(), &client).await;
    let outcomes = &assurance.api_spec.documents;
    assert_eq!(outcomes.len(), 2);
    for outcome in outcomes {
        assert_eq!(outcome.action, SpecAction::Complete, "{outcome:?}");
        assert!(outcome.diagnostics_before.is_empty(), "{outcome:?}");
        assert!(outcome.missing_operations.is_empty(), "{outcome:?}");
    }
}

// Relocation.

fn misplaced_graphql() -> tempfile::TempDir {
    let root = graphql_repo();
    write(root.path(), "schema.graphqls", COMPLETE_SDL);
    write(
        root.path(),
        "README.md",
        "The schema is in schema.graphqls.\n",
    );
    root
}

#[tokio::test]
async fn a_misplaced_schema_moves_where_spring_reads_it() {
    let root = misplaced_graphql();
    let client = Client::texts(&[graphql_reply("no_change", json!([])), review(true)]);
    let assurance = run_step(root.path(), &config(), &client).await;
    let outcome = only_graphql(&assurance);
    assert_eq!(outcome.action, SpecAction::Relocated);
    assert_eq!(outcome.previous_path.as_deref(), Some("schema.graphqls"));
    assert_eq!(outcome.path, SCHEMA_PATH);
    assert_eq!(read(root.path(), SCHEMA_PATH), COMPLETE_SDL);
    assert!(!root.path().join("schema.graphqls").exists());
    assert_eq!(
        read(root.path(), "README.md"),
        format!("The schema is in {SCHEMA_PATH}.\n")
    );
}

#[tokio::test]
async fn a_reference_in_code_keeps_the_schema_in_place() {
    let root = misplaced_graphql();
    write(
        root.path(),
        "src/main/java/com/example/Config.java",
        "class Config { String schema = \"schema.graphqls\"; }\n",
    );
    let client = Client::texts(&[graphql_reply("no_change", json!([])), review(true)]);
    let assurance = run_step(root.path(), &config(), &client).await;
    let outcome = only_graphql(&assurance);
    assert_eq!(outcome.action, SpecAction::Complete);
    assert_eq!(outcome.path, "schema.graphqls");
    assert!(outcome.gaps[0].contains("src/main/java/com/example/Config.java:1"));
    assert!(!root.path().join(SCHEMA_PATH).exists());
}

#[test]
fn a_create_decision_without_a_document_is_refused() {
    let root = graphql_repo();
    let reply = json!({"decision": "create", "inventory": []}).to_string();
    let subject = Subject::Create {
        syntax: Syntax::Graphql,
    };
    let refusal = proposal::evaluate(
        root.path(),
        &bc_api_spec::graphql::GRAPHQL,
        &subject,
        &[],
        &reply,
        1 << 20,
    )
    .unwrap_err();
    assert!(refusal.issues[0].contains("needs `document`"));
}

#[tokio::test]
async fn a_standard_left_off_the_operator_list_is_not_assessed() {
    let root = graphql_repo();
    write(root.path(), SCHEMA_PATH, COMPLETE_SDL);
    let mut narrowed = config();
    narrowed.api_spec_formats = vec![FormatId::OpenApi];
    let client = Client::new(Vec::new());
    let assurance = run_step(root.path(), &narrowed, &client).await;
    assert_eq!(assurance.api_spec.state, "skipped");
    assert!(assurance.api_spec.documents.is_empty());
    assert_eq!(client.calls(), 0);
}
