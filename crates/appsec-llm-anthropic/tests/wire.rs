use appsec_llm_client::{
    CachePolicy, CacheTtl, ChatRequest, LlmClient, Message, ReasoningEffort, ToolExecutor,
    ToolSpec, Usage,
};
use serde_json::{json, Value};
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn client(server: &MockServer) -> appsec_llm_anthropic::AnthropicClient {
    appsec_llm_anthropic::AnthropicClient::new(
        reqwest::Client::new(),
        server.uri(),
        Some("k".into()),
    )
}

struct OneFile;

impl ToolExecutor for OneFile {
    fn available_tools(&self) -> Vec<ToolSpec> {
        vec![ToolSpec {
            name: "Read".into(),
            description: "read a file".into(),
            parameters: json!({"type": "object"}),
        }]
    }

    fn execute(&self, _name: &str, _args: &Value) -> String {
        "fn main() {}".into()
    }
}

#[tokio::test]
async fn a_two_turn_agentic_run_replays_thinking_with_its_signature() {
    let thinking = json!({"type": "thinking", "thinking": "look at main", "signature": "sig=="});
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "content": [
                thinking,
                {"type": "tool_use", "id": "t1", "name": "Read", "input": {"path": "main.rs"}},
            ],
            "stop_reason": "tool_use",
        })))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "content": [{"type": "text", "text": "no bug"}],
            "stop_reason": "end_turn",
        })))
        .mount(&server)
        .await;

    let mut config = appsec_llm_agentic::AgenticConfig::new("claude-opus-4-7");
    config.allowed_tools = vec!["Read".into()];
    config.reasoning_effort = Some(ReasoningEffort::High);
    let outcome = appsec_llm_agentic::run_agentic(&client(&server), &OneFile, "find it", &config)
        .await
        .unwrap();
    assert_eq!(outcome.final_text, "no bug");

    let requests = server.received_requests().await.unwrap();
    let second: Value = requests[1].body_json().unwrap();
    assert_eq!(second["thinking"], json!({"type": "adaptive"}));
    assert_eq!(second["output_config"], json!({"effort": "high"}));
    assert_eq!(
        second["messages"][1]["content"],
        json!([
            thinking,
            {"type": "tool_use", "id": "t1", "name": "Read", "input": {"path": "main.rs"}},
        ])
    );
}

#[tokio::test]
async fn a_learned_effort_rejection_is_not_paid_twice() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .and(body_partial_json(
            json!({"output_config": {"effort": "high"}}),
        ))
        .respond_with(
            ResponseTemplate::new(400)
                .set_body_string("output_config: Extra inputs are not permitted"),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "content": [{"type": "text", "text": "ok"}],
            "stop_reason": "end_turn",
        })))
        .expect(2)
        .mount(&server)
        .await;
    let client = client(&server);
    let mut req = ChatRequest::new(
        "wire-test-legacy-alias",
        vec![Message::user_text("hi")],
        100,
    );
    req.reasoning_effort = Some(ReasoningEffort::High);
    for _ in 0..2 {
        assert_eq!(client.chat(&req).await.unwrap().text(), "ok");
    }
}

#[tokio::test]
async fn cache_markers_reach_the_wire_with_the_policy_ttl() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .and(body_partial_json(json!({
            "system": [{"type": "text", "text": "be helpful",
                        "cache_control": {"type": "ephemeral", "ttl": "1h"}}],
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "content": [{"type": "text", "text": "ok"}],
            "stop_reason": "end_turn",
        })))
        .expect(1)
        .mount(&server)
        .await;
    let mut req = ChatRequest::new("claude-opus-4-6", vec![Message::user_text("hi")], 100);
    req.system = Some("be helpful".into());
    req.cache = CachePolicy {
        markers: true,
        min_block_tokens: Some(1),
        ttl: CacheTtl::OneHour,
    };
    client(&server).chat(&req).await.unwrap();
}

#[test]
fn cached_and_uncached_calls_are_priced_at_their_own_rates() {
    let parse = |usage: Value| -> Usage {
        let body = json!({
            "content": [{"type": "text", "text": "x"}],
            "stop_reason": "end_turn",
            "usage": usage,
        });
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(200).set_body_json(body))
                .mount(&server)
                .await;
            let req = ChatRequest::new("claude-sonnet-4-5", vec![Message::user_text("q")], 10);
            client(&server).chat(&req).await.unwrap().usage
        })
    };
    let pricer = appsec_pricing::Pricer::vendored();
    let usd = |u: Usage, one_hour: bool| {
        let mut call = appsec_pricing::Call::from_usage(
            u.input_tokens,
            u.output_tokens,
            u.cache_read_input_tokens,
            u.cache_creation_input_tokens,
        );
        if one_hour {
            call = call.long_ttl_cache_writes(u.cache_creation_input_tokens);
        }
        let cost = pricer
            .price_call("anthropic", "claude-sonnet-4-5", &call)
            .unwrap();
        assert!(cost.is_fully_rated());
        cost.total().to_usd_string(4)
    };

    let uncached = parse(json!({"input_tokens": 100_000, "output_tokens": 1_000}));
    assert_eq!(usd(uncached, false), "0.3150");

    let write = parse(json!({
        "input_tokens": 10_000, "output_tokens": 1_000,
        "cache_creation_input_tokens": 90_000, "cache_read_input_tokens": 0,
    }));
    assert_eq!(usd(write, false), "0.3825");
    assert_eq!(usd(write, true), "0.5850");

    let read = parse(json!({
        "input_tokens": 10_000, "output_tokens": 1_000,
        "cache_creation_input_tokens": 0, "cache_read_input_tokens": 90_000,
    }));
    assert_eq!(usd(read, false), "0.0720");
}
