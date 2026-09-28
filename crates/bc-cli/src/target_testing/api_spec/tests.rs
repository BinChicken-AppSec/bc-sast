//! End-to-end tests of the API specification step with a scripted model,
//! plus the policy, proposal and file-level rules they rely on.

use std::collections::VecDeque;
use std::path::Path;
use std::process::Command;
use std::sync::Mutex;

use async_trait::async_trait;
use bc_llm_client::{
    ChatRequest, ChatResponse, ContentBlock, LlmClient, LlmError, StopReason, Usage,
};
use serde_json::json;

use super::super::{builtin_profiles, prepare, TargetTestingConfig};
use super::*;
use bc_api_spec::openapi::OPENAPI;

/// One scripted model turn.
enum Step {
    Text(String),
    /// A harmless tool call, used to exhaust a session's turn budget.
    Tool,
    Fail,
}

struct Client {
    steps: Mutex<VecDeque<Step>>,
    prompts: Mutex<Vec<String>>,
}

impl Client {
    fn new(steps: Vec<Step>) -> Self {
        Self {
            steps: Mutex::new(steps.into()),
            prompts: Mutex::new(Vec::new()),
        }
    }

    fn texts(replies: &[String]) -> Self {
        Self::new(replies.iter().cloned().map(Step::Text).collect())
    }

    fn calls(&self) -> usize {
        self.prompts.lock().unwrap().len()
    }

    fn prompt(&self, index: usize) -> String {
        self.prompts.lock().unwrap()[index].clone()
    }
}

#[async_trait]
impl LlmClient for Client {
    async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, LlmError> {
        assert!(request.tools.iter().all(|tool| tool.name != "Write"));
        let first = match request.messages[0].content.first() {
            Some(ContentBlock::Text(text)) => text.clone(),
            _ => String::new(),
        };
        self.prompts.lock().unwrap().push(first);
        let step = self
            .steps
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected extra model call");
        let content = match step {
            Step::Text(text) => vec![ContentBlock::Text(text)],
            Step::Tool => vec![ContentBlock::ToolUse {
                id: "t".into(),
                name: "Glob".into(),
                input: json!({"pattern": "*.md"}),
            }],
            Step::Fail => {
                return Err(LlmError::InvalidRequest {
                    message: "scripted failure".into(),
                })
            }
        };
        let stop_reason = if matches!(content[0], ContentBlock::ToolUse { .. }) {
            StopReason::ToolUse
        } else {
            StopReason::EndTurn
        };
        Ok(ChatResponse {
            content,
            stop_reason,
            usage: Usage::default(),
        })
    }
}

const CONTROLLER: &str = "src/main/java/com/example/PetController.java";
const SPRING_PATH: &str = "src/main/resources/static/openapi.yaml";

fn write(root: &Path, path: &str, contents: &str) {
    let full = root.join(path);
    std::fs::create_dir_all(full.parent().unwrap()).unwrap();
    std::fs::write(full, contents).unwrap();
}

fn read(root: &Path, path: &str) -> String {
    std::fs::read_to_string(root.join(path)).unwrap()
}

/// A Spring Boot service with two routes and no specification.
fn spring_repo() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    write(
        root.path(),
        "pom.xml",
        "<project><dependency><artifactId>spring-boot-starter-web</artifactId></dependency></project>\n",
    );
    write(
        root.path(),
        CONTROLLER,
        "package com.example;\n\n@RestController\npublic class PetController {\n    @GetMapping(\"/pets/{id}\")\n    public Pet get(@PathVariable String id) { return null; }\n    @PostMapping(\"/pets\")\n    public Pet create(@RequestBody Pet pet) { return pet; }\n}\n",
    );
    root
}

fn inventory() -> serde_json::Value {
    json!([
        {"method": "get", "path": "/pets/{id}", "file": CONTROLLER, "line": 5, "snippet": "@GetMapping(\"/pets/{id}\")"},
        {"method": "POST", "path": "/pets", "file": CONTROLLER, "line": 7, "snippet": "@PostMapping(\"/pets\")"},
    ])
}

fn new_document() -> serde_json::Value {
    json!({
        "openapi": "3.1.0",
        "info": {"title": "Pets", "version": "1.0.0"},
        "paths": {
            "/pets/{id}": {"get": {
                "operationId": "getPet", "tags": ["pets"],
                "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}],
                "responses": {"200": {"description": "A pet", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Pet"}}}}},
            }},
            "/pets": {"post": {
                "operationId": "createPet", "tags": ["pets"],
                "requestBody": {"required": true, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Pet"}}}},
                "responses": {"201": {"description": "Created"}},
                "security": [{"bearer": []}],
            }},
        },
        "components": {
            "schemas": {"Pet": {"type": "object", "properties": {"id": {"type": "string"}, "name": {"type": "string"}}}},
            "securitySchemes": {"bearer": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}},
        },
    })
}

fn create_reply(document: serde_json::Value) -> String {
    json!({"decision": "create", "document": document, "inventory": inventory(),
           "changes": ["documented both routes"], "remaining_gaps": ["error bodies unconfirmed"]})
    .to_string()
}

fn edit_reply(edits: serde_json::Value) -> String {
    json!({"decision": "repair", "edits": edits, "inventory": inventory(), "changes": ["fixed"]})
        .to_string()
}

fn no_change() -> String {
    json!({"decision": "no_change", "inventory": inventory()}).to_string()
}

fn review(accepted: bool) -> String {
    json!({"accepted": accepted, "inventory_supported": true, "matches_code": true,
           "preserves_author_content": true, "location_appropriate": true,
           "reasons": if accepted { vec![] } else { vec!["the relocation is not wanted"] }})
    .to_string()
}

/// A complete, valid, hand-written specification for the Spring routes.
const COMPLETE_YAML: &str = "\
# Pets API
openapi: 3.0.3
info:
  title: Pets
  version: \"1.0.0\"
paths:
  /pets/{id}:
    get:
      operationId: getPet
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: string
      responses:
        \"200\":
          description: A pet
  /pets:
    post:
      operationId: createPet
      responses:
        \"201\":
          description: Created
";

/// The same document with an unquoted version and no POST operation.
const BROKEN_YAML: &str = "\
# Pets API
openapi: 3.0.3
info:
  title: Pets
  version: 1.0
paths:
  /pets/{id}:
    get:
      operationId: getPet
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: string
      responses:
        \"200\":
          description: A pet
";

fn repair_edits() -> serde_json::Value {
    json!([
        {"old": "  version: 1.0\n", "new": "  version: \"1.0.0\"\n"},
        {"old": "          description: A pet\n", "new": "          description: A pet\n  /pets:\n    post:\n      operationId: createPet\n      responses:\n        \"201\":\n          description: Created\n"},
    ])
}

fn config() -> TargetTestingConfig {
    let mut config = builtin_profiles::load("comprehensive").unwrap();
    config.generate = false;
    config
}

/// Discovery and static preparation only, then the step itself.
async fn run_step(root: &Path, config: &TargetTestingConfig, client: &Client) -> Assurance {
    let static_config = TargetTestingConfig::default();
    let mut assurance = prepare(root, &static_config, "fake", client, "")
        .await
        .unwrap();
    run(root, config, client, &mut assurance).await.unwrap();
    assurance
}

fn only(assurance: &Assurance) -> &SpecOutcome {
    assert_eq!(
        assurance.api_spec.documents.len(),
        1,
        "{:?}",
        assurance.api_spec
    );
    &assurance.api_spec.documents[0]
}

#[tokio::test]
async fn a_missing_specification_is_created_at_the_framework_convention() {
    let root = spring_repo();
    let client = Client::texts(&[create_reply(new_document()), review(true)]);
    let assurance = run_step(root.path(), &config(), &client).await;
    let outcome = only(&assurance);
    assert_eq!(outcome.action, SpecAction::Created);
    assert_eq!(outcome.path, SPRING_PATH);
    assert_eq!(outcome.syntax, Some(Syntax::Yaml));
    assert!(outcome.missing_operations.is_empty() && outcome.unverified_operations.is_empty());
    assert_eq!(outcome.inventory.len(), 2);
    assert!(outcome
        .gaps
        .contains(&"error bodies unconfirmed".to_string()));
    let written = read(root.path(), SPRING_PATH);
    assert_eq!(
        bc_api_spec::parse::parse(&written, Syntax::Yaml).unwrap(),
        new_document()
    );
    assert_eq!(assurance.approved_bytes[SPRING_PATH], written.as_bytes());
    assert_eq!(assurance.api_spec.state, "assessed");
    // The generator saw the facts; the reviewer saw the document itself.
    assert!(client.prompt(0).contains("\"state\":\"missing\""));
    assert!(client
        .prompt(1)
        .contains(&format!("Create {SPRING_PATH} (Yaml)")));
    assert!(client.prompt(1).contains("\"operationId\": \"getPet\""));
    let roles: Vec<_> = assurance
        .model_usage
        .iter()
        .map(|usage| usage.role.as_str())
        .collect();
    assert_eq!(roles, ["api_spec_generator", "api_spec_reviewer"]);
    assert!(remediation_context(&assurance.api_spec).contains(SPRING_PATH));
}

#[tokio::test]
async fn a_json_convention_is_written_as_ordered_json() {
    let root = tempfile::tempdir().unwrap();
    write(
        root.path(),
        "Api.csproj",
        "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
    );
    write(
        root.path(),
        CONTROLLER,
        &read(spring_repo().path(), CONTROLLER),
    );
    let client = Client::texts(&[create_reply(new_document()), review(true)]);
    let assurance = run_step(root.path(), &config(), &client).await;
    assert_eq!(only(&assurance).path, "wwwroot/swagger/v1/swagger.json");
    let written = read(root.path(), "wwwroot/swagger/v1/swagger.json");
    assert!(written.starts_with("{\n  \"openapi\": \"3.1.0\""));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&written).unwrap(),
        new_document()
    );
}

#[tokio::test]
async fn a_valid_complete_specification_is_left_unchanged() {
    let root = spring_repo();
    write(root.path(), SPRING_PATH, COMPLETE_YAML);
    let client = Client::texts(&[no_change(), review(true)]);
    let assurance = run_step(root.path(), &config(), &client).await;
    let outcome = only(&assurance);
    assert_eq!(outcome.action, SpecAction::Complete);
    assert_eq!(outcome.version, Some(SpecVersion::OpenApi30));
    assert!(outcome.diagnostics_before.is_empty());
    assert_eq!(read(root.path(), SPRING_PATH), COMPLETE_YAML);
    assert!(!assurance.approved_bytes.contains_key(SPRING_PATH));
    assert!(client
        .prompt(1)
        .contains(&format!("No change to the text of {SPRING_PATH}.")));
    assert!(remediation_context(&assurance.api_spec).is_empty());
}

#[tokio::test]
async fn a_broken_specification_is_repaired_with_minimal_edits() {
    let root = spring_repo();
    write(root.path(), SPRING_PATH, BROKEN_YAML);
    let client = Client::texts(&[edit_reply(repair_edits()), review(true)]);
    let assurance = run_step(root.path(), &config(), &client).await;
    let outcome = only(&assurance);
    assert_eq!(outcome.action, SpecAction::Repaired);
    assert!(outcome
        .diagnostics_before
        .iter()
        .any(|diagnostic| diagnostic.pointer == "/info/version"));
    assert!(outcome.diagnostics_after.is_empty());
    // The author's comment and layout survive; only the edits changed.
    assert_eq!(read(root.path(), SPRING_PATH), COMPLETE_YAML);
    assert!(client.prompt(0).contains("# Pets API"));
    assert!(client.prompt(1).contains("each `old` occurs exactly once"));
}

#[tokio::test]
async fn yaml_the_built_in_parser_cannot_verify_is_recorded_and_untouched() {
    let root = spring_repo();
    let anchored = "openapi: 3.0.3\ninfo: &info\n  title: Pets\n  version: \"1\"\npaths: {}\n";
    write(root.path(), SPRING_PATH, anchored);
    let client = Client::new(Vec::new());
    let assurance = run_step(root.path(), &config(), &client).await;
    let outcome = only(&assurance);
    assert_eq!(outcome.action, SpecAction::Unverifiable);
    assert!(outcome.gaps[0].contains("could not be verified by the built-in YAML parser"));
    assert_eq!(read(root.path(), SPRING_PATH), anchored);
    assert_eq!(client.calls(), 0);
}

#[tokio::test]
async fn an_invalid_proposal_is_rejected_after_its_repair_rounds() {
    let root = spring_repo();
    let mut invalid = new_document();
    invalid["paths"]["/pets"]["POST"] = invalid["paths"]["/pets"]["post"].take();
    invalid["paths"]["/pets"]
        .as_object_mut()
        .unwrap()
        .remove("post");
    let reply = create_reply(invalid);
    let client = Client::texts(&[reply.clone(), reply.clone(), reply]);
    let assurance = run_step(root.path(), &config(), &client).await;
    let outcome = only(&assurance);
    assert_eq!(outcome.action, SpecAction::Rejected);
    assert_eq!(client.calls(), 3);
    assert!(client.prompt(1).contains("Your previous proposal failed"));
    assert!(outcome
        .diagnostics_after
        .iter()
        .any(|d| d.pointer == "/paths/~1pets/POST"));
    assert!(outcome
        .missing_operations
        .iter()
        .any(|op| op.method == "post" && op.path == "/pets"));
    assert!(outcome.gaps.last().unwrap().contains("after 3 attempt(s)"));
    assert!(!root.path().join(SPRING_PATH).exists());
}

#[tokio::test]
async fn a_feedback_round_can_fix_a_refused_proposal() {
    let root = spring_repo();
    let mut leaky = new_document();
    leaky["components"]["securitySchemes"]["bearer"]["x-example"] =
        json!("ghp_0123456789abcdefghijklmnopqrstuvwxyzAB");
    let client = Client::texts(&[
        "not json".into(),
        create_reply(leaky),
        create_reply(new_document()),
        review(true),
    ]);
    let assurance = run_step(root.path(), &config(), &client).await;
    assert_eq!(only(&assurance).action, SpecAction::Created);
    assert!(client.prompt(1).contains("not the required JSON object"));
    assert!(client.prompt(2).contains("look like credentials"));
}

#[tokio::test]
async fn a_secret_in_an_example_is_never_written() {
    let root = spring_repo();
    let mut leaky = new_document();
    leaky["paths"]["/pets"]["post"]["requestBody"]["content"]["application/json"]["example"] =
        json!({"token": format!("sk_live_{}", "a".repeat(24))});
    let reply = create_reply(leaky);
    let client = Client::texts(&[reply.clone(), reply.clone(), reply]);
    let assurance = run_step(root.path(), &config(), &client).await;
    let outcome = only(&assurance);
    assert_eq!(outcome.action, SpecAction::Rejected);
    assert!(outcome
        .gaps
        .last()
        .unwrap()
        .contains("look like credentials"));
    assert!(!root.path().join(SPRING_PATH).exists());
}

#[tokio::test]
async fn a_rejected_review_writes_nothing() {
    let root = spring_repo();
    write(root.path(), SPRING_PATH, BROKEN_YAML);
    let client = Client::texts(&[edit_reply(repair_edits()), review(false)]);
    let assurance = run_step(root.path(), &config(), &client).await;
    let outcome = only(&assurance);
    assert_eq!(outcome.action, SpecAction::Rejected);
    assert!(!outcome.review.as_ref().unwrap().accepted);
    assert!(outcome
        .gaps
        .iter()
        .any(|gap| gap.contains("the relocation is not wanted")));
    assert_eq!(read(root.path(), SPRING_PATH), BROKEN_YAML);
}

#[tokio::test]
async fn model_failures_and_exhausted_budgets_reject_without_writing() {
    // The generator errors outright.
    let root = spring_repo();
    let client = Client::new(vec![Step::Fail]);
    let assurance = run_step(root.path(), &config(), &client).await;
    assert!(only(&assurance).gaps[0].contains("generation failed"));
    // The generator runs out of turns every round.
    let mut steps = Vec::new();
    for _ in 0..3 {
        steps.extend((0..24).map(|_| Step::Tool));
        steps.push(Step::Text("{}".into()));
    }
    let client = Client::new(steps);
    let assurance = run_step(root.path(), &config(), &client).await;
    assert!(only(&assurance).gaps[0].contains("exhausted its turn budget"));
    // The reviewer errors, runs out of turns, or replies with prose.
    for review_steps in [
        vec![Step::Fail],
        (0..24)
            .map(|_| Step::Tool)
            .chain([Step::Text("{}".into())])
            .collect(),
        vec![Step::Text("looks fine".into())],
    ] {
        let mut steps = vec![Step::Text(create_reply(new_document()))];
        steps.extend(review_steps);
        let client = Client::new(steps);
        let assurance = run_step(root.path(), &config(), &client).await;
        let outcome = only(&assurance);
        assert_eq!(outcome.action, SpecAction::Rejected);
        assert!(outcome
            .gaps
            .last()
            .unwrap()
            .contains("independent review did not complete"));
        assert!(!root.path().join(SPRING_PATH).exists());
    }
}

#[tokio::test]
async fn an_unparseable_json_specification_may_be_replaced() {
    let root = spring_repo();
    write(
        root.path(),
        "src/main/resources/static/openapi.json",
        "{\"openapi\": \"3.1.0\",",
    );
    let replacement = bc_api_spec::emit::to_json(&new_document());
    let reply = json!({"decision": "repair", "replacement": replacement, "inventory": inventory()});
    let client = Client::texts(&[reply.to_string(), review(true)]);
    let assurance = run_step(root.path(), &config(), &client).await;
    let outcome = only(&assurance);
    assert_eq!(outcome.action, SpecAction::Repaired);
    assert!(outcome
        .parse_error
        .as_ref()
        .unwrap()
        .contains("invalid JSON"));
    assert!(client.prompt(0).contains("does_not_parse"));
    assert!(client.prompt(1).contains("Replace the unparseable"));
    assert_eq!(
        read(root.path(), "src/main/resources/static/openapi.json"),
        replacement
    );
}

#[tokio::test]
async fn a_specification_without_a_version_is_completed() {
    let root = spring_repo();
    let versionless = COMPLETE_YAML.replace("openapi: 3.0.3\n", "");
    write(root.path(), SPRING_PATH, &versionless);
    let edits = json!([{"old": "# Pets API\n", "new": "# Pets API\nopenapi: 3.0.3\n"}]);
    let client = Client::texts(&[edit_reply(edits), review(true)]);
    let assurance = run_step(root.path(), &config(), &client).await;
    assert_eq!(only(&assurance).action, SpecAction::Repaired);
    assert!(client.prompt(0).contains("missing_version"));
    assert_eq!(read(root.path(), SPRING_PATH), COMPLETE_YAML);
}

#[tokio::test]
async fn files_the_step_may_not_write_are_skipped_with_a_reason() {
    // A specification that already carries credential-looking values.
    let root = spring_repo();
    let leaky = COMPLETE_YAML.replace(
        "A pet\n",
        "A pet\n          x-note: \"password: hunter2hunter2\"\n",
    );
    write(root.path(), SPRING_PATH, &leaky);
    let client = Client::new(Vec::new());
    let assurance = run_step(root.path(), &config(), &client).await;
    assert_eq!(only(&assurance).action, SpecAction::Skipped);
    assert!(only(&assurance).gaps[0].contains("redactor"));
    // A specification inside a test layout.
    let root = tempfile::tempdir().unwrap();
    write(root.path(), "tests/fixtures/openapi.yaml", COMPLETE_YAML);
    let assurance = run_step(root.path(), &config(), &client).await;
    assert_eq!(only(&assurance).action, SpecAction::Skipped);
    assert!(only(&assurance).gaps[0].contains("not a path this step may write"));
    // The conventional location is already taken by something else.
    let root = spring_repo();
    write(root.path(), SPRING_PATH, "greeting: hello\n");
    let assurance = run_step(root.path(), &config(), &client).await;
    assert_eq!(only(&assurance).action, SpecAction::Skipped);
    assert_eq!(read(root.path(), SPRING_PATH), "greeting: hello\n");
    assert_eq!(client.calls(), 0);
}

#[tokio::test]
async fn the_step_is_skipped_visibly_when_off_unconfigured_or_without_http_surface() {
    let root = spring_repo();
    let client = Client::new(Vec::new());
    let mut disabled = config();
    disabled.api_spec_disabled = true;
    let assurance = run_step(root.path(), &disabled, &client).await;
    assert_eq!(assurance.api_spec.state, "skipped");
    assert_eq!(
        assurance.api_spec.reason.as_deref(),
        Some("disabled by --api-spec off")
    );
    let assurance = run_step(
        root.path(),
        &builtin_profiles::load("unit").unwrap(),
        &client,
    )
    .await;
    assert!(assurance
        .api_spec
        .reason
        .as_deref()
        .unwrap()
        .contains("does not include"));
    let empty = tempfile::tempdir().unwrap();
    let assurance = run_step(empty.path(), &config(), &client).await;
    assert!(assurance
        .api_spec
        .reason
        .as_deref()
        .unwrap()
        .contains("no HTTP framework"));
    // A profile that does not generate records the skip without reaching the step.
    let discover = builtin_profiles::load("discover").unwrap();
    let assurance = prepare(root.path(), &discover, "fake", &client, "")
        .await
        .unwrap();
    assert!(assurance
        .api_spec
        .reason
        .as_deref()
        .unwrap()
        .contains("does not generate"));
    assert_eq!(client.calls(), 0);
    let artifact = serde_json::to_value(&assurance).unwrap();
    assert_eq!(artifact["api_spec"]["state"], "skipped");
}

#[test]
fn the_operator_flag_can_only_switch_the_step_off() {
    let mut cli = crate::args::test_support::minimal_cli(Path::new("."));
    cli.remediate = true;
    cli.target_tests = Some("comprehensive".into());
    let config = super::super::load_config(&cli).unwrap().unwrap();
    assert!(config.api_spec.is_some() && !config.api_spec_disabled);
    cli.api_spec = ApiSpecMode::Off;
    assert!(
        super::super::load_config(&cli)
            .unwrap()
            .unwrap()
            .api_spec_disabled
    );
    cli.target_tests = Some("unit".into());
    cli.api_spec = ApiSpecMode::Auto;
    assert!(super::super::load_config(&cli)
        .unwrap()
        .unwrap()
        .api_spec
        .is_none());
}

#[tokio::test]
async fn preparation_runs_the_step_after_test_generation() {
    let root = spring_repo();
    let mut config = builtin_profiles::load("comprehensive").unwrap();
    config.generator_model = Some("generator-role".into());
    let client = Client::texts(&[
        json!({"files": [], "remaining_gaps": []}).to_string(),
        create_reply(new_document()),
        review(true),
    ]);
    let assurance = prepare(root.path(), &config, "fake", &client, "[]")
        .await
        .unwrap();
    assert_eq!(assurance.generation_state, "blocked");
    assert_eq!(only(&assurance).action, SpecAction::Created);
    assert!(super::super::remediation_context(&assurance)
        .contains("independently reviewed API specification"));
    let artifact = serde_json::to_value(&assurance).unwrap();
    assert_eq!(artifact["api_spec"]["documents"][0]["action"], "created");
}

// Relocation.

/// A Spring service whose complete specification sits at the repository
/// root, referenced from documentation and framework configuration.
fn misplaced_repo() -> tempfile::TempDir {
    let root = spring_repo();
    write(root.path(), "openapi.yaml", COMPLETE_YAML);
    write(root.path(), "README.md", "See [the API](openapi.yaml).\n");
    write(
        root.path(),
        "docs/guide.md",
        "Read ../openapi.yaml first.\n",
    );
    write(
        root.path(),
        "src/main/resources/application.yml",
        "contract: ./openapi.yaml\n",
    );
    root
}

async fn relocate(root: &Path) -> Assurance {
    let client = Client::texts(&[no_change(), review(true)]);
    let assurance = run_step(root, &config(), &client).await;
    assert!(client.prompt(0).contains("references_the_harness_rewrites"));
    assert!(client.prompt(1).contains(&format!(
        "Relocation: write the document to {SPRING_PATH} and delete openapi.yaml"
    )));
    assurance
}

#[tokio::test]
async fn a_misplaced_specification_moves_with_its_references() {
    let root = misplaced_repo();
    let assurance = relocate(root.path()).await;
    let outcome = only(&assurance);
    assert_eq!(outcome.action, SpecAction::Relocated);
    assert_eq!(outcome.previous_path.as_deref(), Some("openapi.yaml"));
    assert_eq!(outcome.path, SPRING_PATH);
    assert_eq!(outcome.updated_references.len(), 3);
    assert!(!root.path().join("openapi.yaml").exists());
    assert_eq!(read(root.path(), SPRING_PATH), COMPLETE_YAML);
    assert_eq!(
        read(root.path(), "README.md"),
        format!("See [the API]({SPRING_PATH}).\n")
    );
    assert_eq!(
        read(root.path(), "docs/guide.md"),
        format!("Read ../{SPRING_PATH} first.\n")
    );
    assert_eq!(
        read(root.path(), "src/main/resources/application.yml"),
        format!("contract: ./{SPRING_PATH}\n")
    );
    for bound in [SPRING_PATH, "README.md", "docs/guide.md"] {
        assert!(assurance.approved_bytes.contains_key(bound), "{bound}");
    }
}

#[tokio::test]
async fn a_reference_in_source_code_keeps_the_specification_in_place() {
    let root = misplaced_repo();
    write(root.path(), "openapi.yaml", BROKEN_YAML);
    write(
        root.path(),
        "src/main/java/com/example/SpecLoader.java",
        "class SpecLoader { String path = \"openapi.yaml\"; }\n",
    );
    let client = Client::texts(&[edit_reply(repair_edits()), review(true)]);
    let assurance = run_step(root.path(), &config(), &client).await;
    let outcome = only(&assurance);
    assert_eq!(outcome.action, SpecAction::Repaired);
    assert_eq!(outcome.path, "openapi.yaml");
    assert!(outcome.gaps[0].contains("src/main/java/com/example/SpecLoader.java:1"));
    assert_eq!(read(root.path(), "openapi.yaml"), COMPLETE_YAML);
    assert_eq!(
        read(root.path(), "README.md"),
        "See [the API](openapi.yaml).\n"
    );
    assert!(!root.path().join(SPRING_PATH).exists());
}

#[tokio::test]
async fn an_unknown_framework_or_accepted_location_is_never_moved() {
    let root = tempfile::tempdir().unwrap();
    write(
        root.path(),
        "package.json",
        r#"{"dependencies":{"express":"4"}}"#,
    );
    write(
        root.path(),
        CONTROLLER,
        &read(spring_repo().path(), CONTROLLER),
    );
    write(root.path(), "openapi.yaml", COMPLETE_YAML);
    let client = Client::texts(&[no_change(), review(true)]);
    let assurance = run_step(root.path(), &config(), &client).await;
    assert_eq!(only(&assurance).action, SpecAction::Complete);
    assert_eq!(read(root.path(), "openapi.yaml"), COMPLETE_YAML);
    assert!(!client.prompt(1).contains("Relocation:"));
}

#[cfg(unix)]
#[tokio::test]
async fn a_symlink_on_the_new_path_refuses_the_move() {
    let root = misplaced_repo();
    let elsewhere = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("src/main/resources")).unwrap();
    std::os::unix::fs::symlink(
        elsewhere.path(),
        root.path().join("src/main/resources/static"),
    )
    .unwrap();
    let client = Client::texts(&[no_change(), review(true)]);
    let assurance = run_step(root.path(), &config(), &client).await;
    let outcome = only(&assurance);
    assert_eq!(outcome.action, SpecAction::Complete);
    assert!(outcome.gaps[0].contains("symlink"));
    assert!(root.path().join("openapi.yaml").exists());
    assert_eq!(std::fs::read_dir(elsewhere.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn a_rejected_move_leaves_everything_unchanged() {
    let root = misplaced_repo();
    let client = Client::texts(&[no_change(), review(false)]);
    let assurance = run_step(root.path(), &config(), &client).await;
    assert_eq!(only(&assurance).action, SpecAction::Rejected);
    assert_eq!(read(root.path(), "openapi.yaml"), COMPLETE_YAML);
    assert_eq!(
        read(root.path(), "README.md"),
        "See [the API](openapi.yaml).\n"
    );
    assert!(!root.path().join(SPRING_PATH).exists());
}

fn git(root: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .current_dir(root)
        .args([
            "-c",
            "user.email=test@example.invalid",
            "-c",
            "user.name=BC SAST test",
        ])
        .args(args)
        .output()
        .unwrap();
    assert!(output.status.success(), "git {args:?}: {output:?}");
    String::from_utf8(output.stdout).unwrap()
}

/// A committed misplaced repository, then relocated in its working tree.
async fn relocated_git_repo() -> tempfile::TempDir {
    let root = misplaced_repo();
    git(root.path(), &["init", "-q"]);
    // Repository-local, not only `git -c`: `delivery_branch::publish`
    // commits with its own git invocations, and a CI runner has no
    // global identity to fall back on.
    git(
        root.path(),
        &["config", "user.email", "test@example.invalid"],
    );
    git(root.path(), &["config", "user.name", "BC SAST test"]);
    git(root.path(), &["add", "-A"]);
    git(root.path(), &["commit", "-qm", "baseline"]);
    assert_eq!(
        only(&relocate(root.path()).await).action,
        SpecAction::Relocated
    );
    root
}

#[tokio::test]
async fn patch_delivery_carries_the_move_as_a_rename() {
    let root = relocated_git_repo().await;
    let changed = bc_diffcapture::changed_files_whole_tree(root.path());
    let patch = bc_diffcapture::export_patch(root.path(), &changed);
    assert!(patch.contains("rename from openapi.yaml"), "{patch}");
    assert!(patch.contains(&format!("rename to {SPRING_PATH}")));
    assert!(patch.contains(&format!("+See [the API]({SPRING_PATH}).")));
    // The patch applies to the original commit and reproduces the move.
    let holder = tempfile::tempdir().unwrap();
    let copy = holder.path().join("copy");
    git(
        holder.path(),
        &["clone", "-q", root.path().to_str().unwrap(), "copy"],
    );
    std::fs::write(holder.path().join("move.patch"), &patch).unwrap();
    git(&copy, &["apply", "../move.patch"]);
    assert!(!copy.join("openapi.yaml").exists());
    assert_eq!(read(&copy, SPRING_PATH), COMPLETE_YAML);
    assert_eq!(
        read(&copy, "docs/guide.md"),
        format!("Read ../{SPRING_PATH} first.\n")
    );
}

#[tokio::test]
async fn branch_delivery_publishes_the_move() {
    let root = relocated_git_repo().await;
    let remote = tempfile::tempdir().unwrap();
    git(remote.path(), &["init", "--bare", "-q"]);
    git(root.path(), &["checkout", "--detach", "-q"]);
    git(
        root.path(),
        &["remote", "add", "origin", remote.path().to_str().unwrap()],
    );
    let receipt = crate::delivery_branch::publish(root.path(), "origin", "bc-sast/api-spec")
        .await
        .unwrap();
    assert!(receipt.published);
    let listed = git(
        remote.path(),
        &["ls-tree", "-r", "--name-only", "bc-sast/api-spec"],
    );
    assert!(listed.lines().any(|line| line == SPRING_PATH), "{listed}");
    assert!(
        !listed.lines().any(|line| line == "openapi.yaml"),
        "{listed}"
    );
    assert_eq!(
        git(remote.path(), &["show", "bc-sast/api-spec:README.md"]),
        format!("See [the API]({SPRING_PATH}).\n")
    );
}

#[tokio::test]
async fn zip_delivery_packages_the_moved_tree() {
    let root = relocated_git_repo().await;
    let out = tempfile::tempdir().unwrap();
    let artifact = out.path().join("source.zip");
    crate::delivery_archive::export_zip(root.path(), &artifact).unwrap();
    let data = std::fs::read(&artifact).unwrap();
    // Walk the central directory's file names.
    let end = data.len() - 22;
    let count = u16::from_le_bytes(data[end + 10..end + 12].try_into().unwrap()) as usize;
    let mut offset = u32::from_le_bytes(data[end + 16..end + 20].try_into().unwrap()) as usize;
    let mut names = Vec::new();
    for _ in 0..count {
        let length =
            u16::from_le_bytes(data[offset + 28..offset + 30].try_into().unwrap()) as usize;
        let extra = u16::from_le_bytes(data[offset + 30..offset + 32].try_into().unwrap()) as usize;
        let comment =
            u16::from_le_bytes(data[offset + 32..offset + 34].try_into().unwrap()) as usize;
        names.push(String::from_utf8(data[offset + 46..offset + 46 + length].to_vec()).unwrap());
        offset += 46 + length + extra + comment;
    }
    assert!(names.contains(&SPRING_PATH.to_string()), "{names:?}");
    assert!(!names.contains(&"openapi.yaml".to_string()), "{names:?}");
    assert!(names.contains(&"README.md".to_string()));
}

// Policy, proposal and file rules.

#[test]
fn policies_are_bounded_and_reference_patterns_never_reach_code() {
    let policy = config().api_spec.unwrap();
    policy.validate().unwrap();
    for (field, value) in [
        ("max_spec_bytes", json!(10)),
        ("max_spec_bytes", json!(5 * 1024 * 1024)),
        ("max_repair_rounds", json!(5)),
        ("max_documents", json!(0)),
        ("reference_files", json!(["*"])),
        ("reference_files", json!(["*.java"])),
        ("reference_files", json!(["docs/*.md"])),
        ("reference_files", json!(["*a*.md"])),
    ] {
        let mut raw = serde_json::to_value(&policy).unwrap();
        raw[field] = value;
        let bad: ApiSpecPolicy = serde_json::from_value(raw).unwrap();
        assert!(bad.validate().is_err(), "{field}");
    }
    assert!(policy.allows_reference("docs/guide.md"));
    assert!(policy.allows_reference("src/main/resources/application-prod.yml"));
    assert!(policy.allows_reference("appsettings.Development.json"));
    assert!(!policy.allows_reference("package.json"));
    assert!(!policy.allows_reference("src/App.java"));
    assert!(!policy.allows_reference("appsettings.json.bak"));
}

#[test]
fn proposals_are_checked_before_review() {
    let root = spring_repo();
    let evaluate = |subject: &Subject<'_>, reply: &str| {
        proposal::evaluate(root.path(), &OPENAPI, subject, &[], reply, 1024 * 1024)
            .err()
            .map(|refusal| refusal.issues.join(" | "))
            .unwrap_or_default()
    };
    let create = Subject::Create {
        syntax: Syntax::Yaml,
    };
    let mut entry = inventory()[0].clone();
    for (field, value, expected) in [
        ("method", json!("ANY"), "not an HTTP method"),
        ("path", json!("pets"), "must start with /"),
        ("line", json!(6), "unsupported expectation citation"),
    ] {
        entry[field] = value;
        let reply = json!({"decision": "create", "document": new_document(), "inventory": [entry]});
        assert!(
            evaluate(&create, &reply.to_string()).contains(expected),
            "{field}"
        );
        entry = inventory()[0].clone();
    }
    let many: Vec<_> = (0..2_001).map(|_| inventory()[0].clone()).collect();
    let reply = json!({"decision": "create", "document": new_document(), "inventory": many});
    assert!(evaluate(&create, &reply.to_string()).contains("2000-operation limit"));
    for (reply, expected) in [
        (
            json!({"decision": "create", "document": [], "inventory": []}),
            "`document` as a mapping",
        ),
        (
            json!({"decision": "repair", "inventory": []}),
            "must be create",
        ),
        (
            json!({"decision": "create", "document": {"x": u64::MAX}, "inventory": []}),
            "outside the range",
        ),
    ] {
        assert!(
            evaluate(&create, &reply.to_string()).contains(expected),
            "{expected}"
        );
    }
    let mut old = new_document();
    old["openapi"] = json!("3.0.3");
    assert!(evaluate(&create, &create_reply(old)).contains("must declare openapi: \"3.1.0\""));
    let small = proposal::evaluate(
        root.path(),
        &OPENAPI,
        &create,
        &[],
        &create_reply(new_document()),
        100,
    );
    assert!(small.unwrap_err().issues[0].contains("specification cap"));

    let parsed = bc_api_spec::parse::parse(BROKEN_YAML, Syntax::Yaml).unwrap();
    let before = bc_api_spec::openapi::validate::validate(&parsed);
    let existing = Subject::Existing {
        text: BROKEN_YAML,
        syntax: Syntax::Yaml,
        document: Some(&parsed),
        before: &before,
    };
    for (reply, expected) in [
        (
            json!({"decision": "create", "document": {}, "inventory": []}),
            "already exists",
        ),
        (
            json!({"decision": "repair", "inventory": []}),
            "at least one edit",
        ),
        (
            json!({"decision": "repair", "replacement": "x", "inventory": []}),
            "never replaced",
        ),
        (
            json!({"decision": "repair", "edits": [{"old": "absent", "new": "x"}], "inventory": []}),
            "not found",
        ),
        (
            json!({"decision": "repair", "edits": [{"old": "paths:\n", "new": "paths: [\n"}], "inventory": []}),
            "does not parse",
        ),
        (
            json!({"decision": "no_change", "inventory": inventory()}),
            "no_change is only acceptable",
        ),
        (
            json!({"decision": "repair", "edits": [{"old": "  title: Pets\n", "new": "  title: Pets\n  x-key: \"token: abcdef123456\"\n"}], "inventory": []}),
            "look like credentials",
        ),
    ] {
        assert!(
            evaluate(&existing, &reply.to_string()).contains(expected),
            "{expected}"
        );
    }
    // Edits that are clean on their own but not in their surroundings.
    let clean = "openapi: 3.0.3\ninfo:\n  title: t\n  version: \"1\"\npaths: {}\nx-password:\n  type: string\n";
    let document = bc_api_spec::parse::parse(clean, Syntax::Yaml).unwrap();
    let subject = Subject::Existing {
        text: clean,
        syntax: Syntax::Yaml,
        document: Some(&document),
        before: &[],
    };
    let reply = json!({"decision": "repair", "edits": [{"old": "  type: string\n", "new": "  description: The account secret\n  type: string\n"}], "inventory": []});
    assert!(evaluate(&subject, &reply.to_string()).contains("edited document contains"));
    // An unparseable file cannot be declared complete.
    let malformed = Subject::Existing {
        text: "{",
        syntax: Syntax::Json,
        document: None,
        before: &[],
    };
    let reply = json!({"decision": "no_change", "inventory": []});
    assert!(evaluate(&malformed, &reply.to_string()).contains("does not parse"));
}

#[test]
fn reads_are_bounded_jailed_and_never_follow_links() {
    let root = tempfile::tempdir().unwrap();
    write(root.path(), "openapi.yaml", "0123456789");
    assert_eq!(
        files::read_bounded(root.path(), "openapi.yaml", 4)
            .unwrap()
            .len(),
        5
    );
    assert!(files::read_bounded(root.path(), "missing.yaml", 4)
        .unwrap_err()
        .contains("cannot be read"));
    assert!(files::read_bounded(root.path(), "../x.yaml", 4)
        .unwrap_err()
        .contains("escapes"));
    std::fs::create_dir(root.path().join("dir.yaml")).unwrap();
    assert!(files::read_bounded(root.path(), "dir.yaml", 4)
        .unwrap_err()
        .contains("regular file"));
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(
            root.path().join("openapi.yaml"),
            root.path().join("link.yaml"),
        )
        .unwrap();
        assert!(files::read_bounded(root.path(), "link.yaml", 4)
            .unwrap_err()
            .contains("symlink"));
        assert!(files::has_symlink(root.path(), "link.yaml"));
    }
    assert!(files::occupied(root.path(), "dir.yaml"));
    assert!(!files::occupied(root.path(), "none.yaml"));
}

#[test]
fn relocation_scans_refuse_what_they_cannot_rewrite_or_bound() {
    let editable = |_: &str| true;
    let root = tempfile::tempdir().unwrap();
    write(root.path(), "openapi.yaml", COMPLETE_YAML);
    write(root.path(), "new/openapi.yaml", "taken");
    let refused =
        files::prepare_relocation(root.path(), "openapi.yaml", "new/openapi.yaml", &editable);
    assert!(refused.unwrap_err()[0].contains("already exists"));
    // A binary file naming the specification, and a crowd of blockers.
    std::fs::write(root.path().join("blob.bin"), b"\xff\xfeopenapi.yaml").unwrap();
    for index in 0..25 {
        write(root.path(), &format!("n{index:02}.txt"), "/openapi.yaml");
    }
    // Skipped directories are not scanned.
    write(
        root.path(),
        "node_modules/x/openapi.yaml.txt",
        "/openapi.yaml",
    );
    let refused =
        files::prepare_relocation(root.path(), "openapi.yaml", "moved/openapi.yaml", &editable)
            .unwrap_err();
    assert!(refused[0].contains("blob.bin: a non-UTF-8 file"));
    assert_eq!(refused.len(), 21);
    assert_eq!(refused[20], "and 6 more");
    // Oversized files and deep trees fail closed.
    let big = tempfile::tempdir().unwrap();
    std::fs::write(big.path().join("huge.txt"), vec![b'a'; 4 * 1024 * 1024 + 1]).unwrap();
    let refused =
        files::prepare_relocation(big.path(), "openapi.yaml", "moved/openapi.yaml", &editable);
    assert!(refused.unwrap_err()[0].contains("byte limits"));
    let deep = tempfile::tempdir().unwrap();
    write(deep.path(), &format!("{}a.txt", "d/".repeat(34)), "x");
    let refused =
        files::prepare_relocation(deep.path(), "openapi.yaml", "moved/openapi.yaml", &editable);
    assert!(refused.unwrap_err()[0].contains("depth limit"));
    let missing = tempfile::tempdir().unwrap();
    let gone = missing.path().join("gone");
    let refused = files::prepare_relocation(&gone, "openapi.yaml", "moved/openapi.yaml", &editable);
    assert!(refused.unwrap_err()[0].contains("cannot be read"));
}

#[test]
fn applying_changes_is_all_or_nothing() {
    use std::collections::BTreeMap;
    let root = tempfile::tempdir().unwrap();
    write(root.path(), "keep.yaml", "original");
    write(root.path(), "blocker", "a file, not a directory");
    let change = |path: &str, contents: Option<&str>| files::Change {
        path: path.into(),
        contents: contents.map(str::to_string),
    };
    let expected = BTreeMap::from([
        ("keep.yaml".to_string(), Some(b"original".to_vec())),
        ("new.yaml".to_string(), None),
    ]);
    // A later failure restores every earlier change.
    let result = files::apply(
        root.path(),
        &[
            change("new.yaml", Some("n")),
            change("keep.yaml", None),
            change("blocker/x.yaml", Some("x")),
        ],
        &expected,
    );
    assert!(
        matches!(result, Err(files::ApplyError::NotApplied(ref m)) if m.contains("blocker/x.yaml"))
    );
    assert_eq!(read(root.path(), "keep.yaml"), "original");
    assert!(!root.path().join("new.yaml").exists());
    // A removal that fails is a failure too.
    let result = files::apply(
        root.path(),
        &[change("absent.yaml", None)],
        &BTreeMap::new(),
    );
    assert!(matches!(result, Err(files::ApplyError::NotApplied(_))));
    // Content that moved since review is never overwritten.
    write(root.path(), "keep.yaml", "edited meanwhile");
    let result = files::apply(root.path(), &[change("keep.yaml", Some("x"))], &expected);
    assert!(
        matches!(result, Err(files::ApplyError::NotApplied(ref m)) if m.contains("changed after"))
    );
    let directory = BTreeMap::from([("blocker".to_string(), None)]);
    std::fs::remove_file(root.path().join("blocker")).unwrap();
    std::fs::create_dir(root.path().join("blocker")).unwrap();
    let result = files::apply(root.path(), &[], &directory);
    assert!(matches!(result, Err(files::ApplyError::NotApplied(ref m)) if m.contains("re-read")));
    // A rollback that cannot restore is reported distinctly.
    let expected = BTreeMap::from([("d/new.yaml".to_string(), None)]);
    let result = files::apply(
        root.path(),
        &[
            change("d/new.yaml", Some("n")),
            change("d/new.yaml", None),
            change("keep.yaml/x", Some("x")),
        ],
        &expected,
    );
    assert!(
        matches!(result, Err(files::ApplyError::RollbackFailed(ref m)) if m.contains("rolled back"))
    );
}

#[test]
fn a_rollback_failure_stops_the_step() {
    use std::collections::BTreeMap;
    let root = tempfile::tempdir().unwrap();
    write(root.path(), "keep.yaml", "k");
    let client = Client::new(Vec::new());
    let policy = config().api_spec.unwrap();
    let context = Context {
        root: root.path(),
        policy: &policy,
        llm: &client,
        tools: SandboxTools::new(root.path().to_path_buf()),
        discovery: String::new(),
        format: &OPENAPI,
        documents: Vec::new(),
    };
    let unit = bc_api_spec::plan::plan(
        &[],
        &OPENAPI.fallback(),
        &[FoundSpec {
            path: "keep.yaml".into(),
            usable: true,
        }],
        1,
        bc_api_spec::Capabilities::FULL,
    )
    .units
    .remove(0);
    let mut outcome = outcome_for(&OPENAPI, &unit, "keep.yaml");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let mut assurance = runtime
        .block_on(prepare(
            root.path(),
            &TargetTestingConfig::default(),
            "fake",
            &client,
            "",
        ))
        .unwrap();
    let changes = [
        files::Change {
            path: "d/new.yaml".into(),
            contents: Some("n".into()),
        },
        files::Change {
            path: "d/new.yaml".into(),
            contents: None,
        },
        files::Change {
            path: "keep.yaml/x".into(),
            contents: Some("x".into()),
        },
    ];
    let expected = BTreeMap::from([("d/new.yaml".to_string(), None)]);
    let error = apply(&context, &changes, &expected, &mut outcome, &mut assurance).unwrap_err();
    assert!(error.contains("could not be rolled back"));
    let skipped = apply(
        &context,
        &changes[2..],
        &BTreeMap::new(),
        &mut outcome,
        &mut assurance,
    );
    assert!(!skipped.unwrap());
    assert_eq!(outcome.action, SpecAction::Rejected);
}

#[test]
fn text_bounds_respect_character_boundaries() {
    assert_eq!(bounded("héllo", 2), ("h", true));
    assert_eq!(bounded("hi", 10), ("hi", false));
}

#[tokio::test]
async fn a_candidate_that_vanished_after_discovery_is_unverifiable() {
    let root = spring_repo();
    write(root.path(), SPRING_PATH, COMPLETE_YAML);
    let client = Client::new(Vec::new());
    let mut assurance = prepare(
        root.path(),
        &TargetTestingConfig::default(),
        "fake",
        &client,
        "",
    )
    .await
    .unwrap();
    std::fs::remove_file(root.path().join(SPRING_PATH)).unwrap();
    run(root.path(), &config(), &client, &mut assurance)
        .await
        .unwrap();
    let outcome = only(&assurance);
    assert_eq!(outcome.action, SpecAction::Unverifiable);
    assert!(outcome.gaps[0].contains("cannot be read"));
}

#[tokio::test]
async fn large_documents_are_quoted_in_bounded_excerpts() {
    // A new document longer than the reviewer's excerpt is flagged.
    let root = spring_repo();
    let mut long = new_document();
    long["info"]["description"] = json!("a".repeat(REVIEW_TEXT_BYTES));
    let client = Client::texts(&[create_reply(long), review(true)]);
    let assurance = run_step(root.path(), &config(), &client).await;
    let outcome = only(&assurance);
    assert_eq!(outcome.action, SpecAction::Created);
    assert!(outcome
        .gaps
        .iter()
        .any(|gap| gap.contains("truncated copy")));
    // An existing document longer than the generator's excerpt is read
    // with tools; documented operations the inventory lacks are kept.
    let root = spring_repo();
    let padded = format!(
        "{COMPLETE_YAML}x-notes: \"{}\"\n",
        "b".repeat(PROMPT_TEXT_BYTES)
    );
    write(root.path(), SPRING_PATH, &padded);
    let only_get = json!({"decision": "no_change", "inventory": [inventory()[0]]}).to_string();
    let client = Client::texts(&[only_get, review(true)]);
    let assurance = run_step(root.path(), &config(), &client).await;
    let outcome = only(&assurance);
    assert_eq!(outcome.action, SpecAction::Complete);
    assert!(client
        .prompt(0)
        .contains("read the rest with the Read tool"));
    assert_eq!(outcome.unverified_operations.len(), 1);
    assert!(outcome
        .gaps
        .iter()
        .any(|gap| gap.contains("need a human decision")));
}

#[tokio::test]
async fn a_generator_failure_on_an_existing_document_changes_nothing() {
    let root = spring_repo();
    write(root.path(), SPRING_PATH, BROKEN_YAML);
    let client = Client::new(vec![Step::Fail]);
    let assurance = run_step(root.path(), &config(), &client).await;
    assert_eq!(only(&assurance).action, SpecAction::Rejected);
    assert_eq!(read(root.path(), SPRING_PATH), BROKEN_YAML);
}

#[test]
fn a_reference_scan_over_too_many_entries_is_refused() {
    let root = tempfile::tempdir().unwrap();
    for index in 0..=20_000 {
        std::fs::File::create(root.path().join(format!("f{index:05}"))).unwrap();
    }
    let refused =
        files::prepare_relocation(root.path(), "openapi.yaml", "moved/openapi.yaml", &|_| true);
    assert!(refused.unwrap_err()[0].contains("entry limit"));
}

// The multi-format framework.

#[test]
fn the_formats_flag_parses_names_and_narrows_the_profile() {
    use clap::Parser;
    let base = [
        "bc-sast",
        "--repo",
        "/repo",
        "--gateway-base-url",
        "http://127.0.0.1:1",
        "--remediate",
        "--target-tests",
        "comprehensive",
    ];
    let cli = crate::args::Cli::try_parse_from(
        base.into_iter()
            .chain(["--api-spec-formats", "openapi,OpenAPI"]),
    )
    .unwrap();
    assert_eq!(cli.api_spec_formats, [FormatId::OpenApi, FormatId::OpenApi]);
    let config = super::super::load_config(&cli).unwrap().unwrap();
    assert_eq!(
        config.api_spec_formats,
        [FormatId::OpenApi, FormatId::OpenApi]
    );
    let error =
        crate::args::Cli::try_parse_from(base.into_iter().chain(["--api-spec-formats", "soap"]))
            .unwrap_err()
            .to_string();
    assert!(
        error.contains("unknown API description standard \"soap\""),
        "{error}"
    );
    assert!(crate::args::Cli::try_parse_from(base)
        .unwrap()
        .api_spec_formats
        .is_empty());
}

#[tokio::test]
async fn a_standard_outside_the_profile_or_the_operator_list_is_not_assessed() {
    let root = spring_repo();
    let client = Client::new(Vec::new());
    let mut narrowed = config();
    narrowed.api_spec.as_mut().unwrap().formats.clear();
    let assurance = run_step(root.path(), &narrowed, &client).await;
    assert!(assurance
        .api_spec
        .reason
        .as_deref()
        .unwrap()
        .contains("no HTTP framework"));
    // Listing the standard keeps it.
    let client = Client::new(vec![Step::Fail]);
    let mut listed = config();
    listed.api_spec_formats = vec![FormatId::OpenApi];
    let assurance = run_step(root.path(), &listed, &client).await;
    assert_eq!(only(&assurance).spec_format, FormatId::OpenApi);
}

#[tokio::test]
async fn documents_beyond_the_session_cap_are_named_in_a_note() {
    let root = spring_repo();
    std::fs::create_dir_all(root.path().join("second")).unwrap();
    std::fs::copy(
        root.path().join("pom.xml"),
        root.path().join("second/pom.xml"),
    )
    .unwrap();
    let mut capped = config();
    capped.api_spec.as_mut().unwrap().max_documents = 1;
    let client = Client::new(vec![Step::Fail]);
    let assurance = run_step(root.path(), &capped, &client).await;
    assert_eq!(only(&assurance).action, SpecAction::Rejected);
    let note = assurance.api_spec.notes.last().unwrap();
    assert!(
        note.contains("cap of 1 generator sessions") && note.contains("second/"),
        "{note}"
    );
}

#[test]
fn per_standard_caps_are_bounded() {
    let policy = config().api_spec.unwrap();
    let mut empty = policy.clone();
    empty.formats.clear();
    assert!(empty
        .validate()
        .unwrap_err()
        .contains("at least one standard"));
    let mut large = policy.clone();
    large
        .formats
        .get_mut(&FormatId::OpenApi)
        .unwrap()
        .max_documents = 65;
    assert!(large
        .validate()
        .unwrap_err()
        .contains("formats.openapi.max_documents"));
}

mod asyncapi;
mod checked;
mod graphql;
mod odata;
mod openrpc;
mod wsdl;
