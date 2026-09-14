//! `ChatRequest` -> Anthropic Messages API JSON request body, ported from
//! the request-shape half of `backends/sdk.py`'s `agentic()`.

use bc_llm_client::{ChatRequest, ContentBlock, Message, Role, ToolSpec};
use serde_json::{json, Value};

pub fn build_request_body(request: &ChatRequest) -> Value {
    let mut messages = to_anthropic_messages(&request.messages);
    // Only a multi-turn request gets the per-turn cache marker — see
    // `mark_latest_turn_for_caching`.
    if request.messages.len() > 1 {
        mark_latest_turn_for_caching(&mut messages);
    }
    let mut body = json!({
        "model": request.model,
        "max_tokens": request.max_tokens,
        "messages": messages,
    });

    if let Some(system) = &request.system {
        // Prompt-cache the system block: S4 fires the same large system
        // prompt N×runs×chunks, and S6/S3/S8 similarly repeat theirs across
        // many chunks — cache reads run ~10% of input cost. Ported from
        // `backends/sdk.py`'s own `kw["system"] = [{"type": "text",
        // "text": system_prompt, "cache_control": {"type": "ephemeral"}}]`.
        body["system"] = json!([{
            "type": "text",
            "text": system,
            "cache_control": {"type": "ephemeral"},
        }]);
    }
    if !request.tools.is_empty() {
        body["tools"] = Value::Array(request.tools.iter().map(to_anthropic_tool).collect());
    }
    // The Messages API rejects `temperature` and `top_p` in the same
    // request ("`temperature` and `top_p` cannot both be specified"), so
    // one has to win. `temperature` does: it's the knob the Python
    // original exposes per model role (`backends/llm.py::resolve` reads
    // only `models.<role>.temperature`), so a config that sets both is
    // near-certainly carrying `top_p` for an OpenAI-dialect role and
    // meant `temperature` here. Logged rather than silently dropped so
    // the divergence is visible in a debug-level run.
    match (request.temperature, request.top_p) {
        (Some(temperature), Some(top_p)) => {
            tracing::debug!(
                "[anthropic] both temperature ({temperature}) and top_p ({top_p}) were set; \
                 the Messages API accepts only one — sending temperature and dropping top_p."
            );
            body["temperature"] = json!(temperature);
        }
        (Some(temperature), None) => body["temperature"] = json!(temperature),
        (None, Some(top_p)) => body["top_p"] = json!(top_p),
        (None, None) => {}
    }
    // `request.seed` is deliberately not emitted: the Messages API has no
    // seed parameter, and sending an unknown top-level key is a 400.
    if let Some(budget) = request.thinking_budget {
        body["thinking"] = json!({"type": "enabled", "budget_tokens": budget});
    }
    if request.stream {
        // No `stream_options` counterpart here: the Messages API always
        // reports usage over a stream (input side on `message_start`,
        // output side on `message_delta`), so unlike the
        // chat-completions dialect nothing extra has to be asked for.
        body["stream"] = json!(true);
    }
    body
}

#[cfg(test)]
mod stream_key_tests {
    use super::*;

    #[test]
    fn a_non_streaming_request_carries_no_stream_key() {
        let body = build_request_body(&ChatRequest::new("claude", vec![], 512));
        assert!(body.get("stream").is_none());
    }

    #[test]
    fn a_streaming_request_sets_stream_and_nothing_else() {
        let mut req = ChatRequest::new("claude", vec![Message::user_text("hi")], 512);
        req.stream = true;
        let body = build_request_body(&req);
        assert_eq!(body["stream"], true);
        // No `stream_options` counterpart — sending an unknown key to
        // the Messages API is a 400.
        assert!(body.get("stream_options").is_none());
        assert_eq!(body["max_tokens"], 512);
    }
}

/// Anthropic's Messages API requires strict user/assistant role
/// alternation, so consecutive [`Role::Tool`] messages (one per tool call
/// `bc-llm-agentic` executed from a single assistant turn — see
/// [`Message::tool_result`]) must be folded into a single `user`-role
/// message with multiple `tool_result` blocks, matching
/// `backends/sdk.py`'s `messages.append({"role": "user", "content":
/// results})` after a turn's tool calls all run.
fn to_anthropic_messages(messages: &[Message]) -> Vec<Value> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < messages.len() {
        if messages[i].role == Role::Tool {
            let mut blocks = Vec::new();
            while i < messages.len() && messages[i].role == Role::Tool {
                blocks.extend(messages[i].content.iter().map(to_anthropic_block));
                i += 1;
            }
            out.push(json!({"role": "user", "content": blocks}));
        } else {
            let role = if messages[i].role == Role::User {
                "user"
            } else {
                "assistant"
            };
            let blocks: Vec<Value> = messages[i].content.iter().map(to_anthropic_block).collect();
            out.push(json!({"role": role, "content": blocks}));
            i += 1;
        }
    }
    out
}

/// Put ONE `cache_control: {"type": "ephemeral"}` marker on the last
/// content block of the most recent user/tool-result message, extending
/// the cached prefix past the system prompt to cover the whole
/// conversation so far. Ported from `backends/sdk.py::_with_cache_marker`,
/// which `agentic()` applies to `messages` on every turn (sdk.py:410-432,
/// 495, 568) — dropped in the initial port, which marked only the system
/// block, leaving every tool result in an agentic session (S1/S6/S10/S11 —
/// by far this pipeline's largest repeated input) re-billed at full input
/// price each turn.
///
/// Returns whether a marker was actually placed. At most ONE marker is
/// ever added here, so together with the system block a request carries at
/// most 2 of Anthropic's 4 allowed cache breakpoints — the same bound
/// `_with_cache_marker`'s own docstring reasons about ("system=1 + this=1
/// = 2 ... regardless of turn count").
///
/// **Divergence from Python, deliberate**: `_with_cache_marker` is applied
/// by `agentic()` only, never by `prompt()`; the caller here gates on
/// `messages.len() > 1` instead of on the presence of tools, because this
/// port's forced-final agentic turn sends an EMPTY tool list (see
/// `bc_llm_agentic::session::run_agentic`) while carrying the longest
/// history of the whole session — exactly the call that most needs the
/// marker. A single-shot stage call (S0/S1-autoexclude/S2/S3/S4/S7/S8)
/// always has exactly one message and is left unmarked: its user prompt is
/// unique per call, so a cache write nobody ever reads back would be a
/// flat ~25% surcharge on it.
fn mark_latest_turn_for_caching(messages: &mut [Value]) -> bool {
    let Some(last_user) = messages.iter_mut().rfind(|m| m["role"] == "user") else {
        return false;
    };
    let Some(last_block) = last_user["content"]
        .as_array_mut()
        .and_then(|c| c.last_mut())
    else {
        return false;
    };
    last_block["cache_control"] = json!({"type": "ephemeral"});
    true
}

fn to_anthropic_block(block: &ContentBlock) -> Value {
    match block {
        ContentBlock::Text(text) => json!({"type": "text", "text": text}),
        ContentBlock::ToolUse { id, name, input } => {
            json!({"type": "tool_use", "id": id, "name": name, "input": input})
        }
        ContentBlock::ToolResult {
            tool_use_id,
            content,
            is_error,
        } => {
            let mut value = json!({
                "type": "tool_result",
                "tool_use_id": tool_use_id,
                "content": content,
            });
            if *is_error {
                value["is_error"] = json!(true);
            }
            value
        }
    }
}

fn to_anthropic_tool(spec: &ToolSpec) -> Value {
    json!({
        "name": spec.name,
        "description": spec.description,
        "input_schema": spec.parameters,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_request_has_model_max_tokens_and_messages_only() {
        let req = ChatRequest::new("claude-opus-4-6", vec![Message::user_text("hi")], 512);
        let body = build_request_body(&req);
        assert_eq!(body["model"], "claude-opus-4-6");
        assert_eq!(body["max_tokens"], 512);
        assert_eq!(
            body["messages"],
            json!([{"role": "user", "content": [{"type": "text", "text": "hi"}]}])
        );
        assert!(body.get("system").is_none());
        assert!(body.get("tools").is_none());
        assert!(body.get("temperature").is_none());
        assert!(body.get("top_p").is_none());
        assert!(body.get("thinking").is_none());
    }

    #[test]
    fn a_seed_is_never_sent_because_the_messages_api_has_no_such_parameter() {
        let mut req = ChatRequest::new("claude-opus-4-6", vec![Message::user_text("hi")], 512);
        req.seed = Some(42);
        let body = build_request_body(&req);
        assert!(body.get("seed").is_none());
    }

    #[test]
    fn top_p_is_sent_when_temperature_is_unset() {
        let mut req = ChatRequest::new("claude-opus-4-6", vec![Message::user_text("hi")], 512);
        req.top_p = Some(0.1);
        let body = build_request_body(&req);
        assert_eq!(body["top_p"], 0.1);
        assert!(body.get("temperature").is_none());
    }

    #[test]
    fn temperature_wins_and_top_p_is_dropped_when_both_are_set() {
        // The Messages API rejects the pair outright — see
        // `build_request_body`'s own comment on which one wins and why.
        let mut req = ChatRequest::new("claude-opus-4-6", vec![Message::user_text("hi")], 512);
        req.temperature = Some(0.0);
        req.top_p = Some(0.1);
        let body = build_request_body(&req);
        assert_eq!(body["temperature"], 0.0);
        assert!(body.get("top_p").is_none());
    }

    #[test]
    fn a_single_shot_request_carries_no_per_turn_cache_marker() {
        let mut req = ChatRequest::new("claude-opus-4-6", vec![Message::user_text("hi")], 512);
        req.system = Some("be helpful".to_string());
        let body = build_request_body(&req);
        assert!(body["messages"][0]["content"][0]
            .get("cache_control")
            .is_none());
        // The system block is still marked.
        assert_eq!(
            body["system"][0]["cache_control"],
            json!({"type": "ephemeral"})
        );
    }

    #[test]
    fn a_multi_turn_request_marks_the_latest_tool_result_block_for_caching() {
        let mut req = ChatRequest::new(
            "claude-opus-4-6",
            vec![
                Message::user_text("find the bug"),
                Message::assistant(vec![ContentBlock::ToolUse {
                    id: "1".to_string(),
                    name: "Read".to_string(),
                    input: json!({}),
                }]),
                Message::tool_result("1", "first result", false),
                Message::tool_result("2", "second result", false),
            ],
            512,
        );
        req.system = Some("be helpful".to_string());
        let body = build_request_body(&req);
        let messages = body["messages"].as_array().unwrap();
        // [0] user, [1] assistant, [2] the folded tool-result user message.
        assert_eq!(messages.len(), 3);
        assert!(messages[0]["content"][0].get("cache_control").is_none());
        assert!(messages[2]["content"][0].get("cache_control").is_none());
        assert_eq!(
            messages[2]["content"][1]["cache_control"],
            json!({"type": "ephemeral"})
        );
    }

    #[test]
    fn at_most_two_cache_breakpoints_are_ever_sent() {
        // Anthropic caps a request at 4; system + one turn marker = 2, no
        // matter how long the conversation gets.
        let mut messages = vec![Message::user_text("start")];
        for i in 0..10 {
            messages.push(Message::assistant(vec![ContentBlock::ToolUse {
                id: i.to_string(),
                name: "Read".to_string(),
                input: json!({}),
            }]));
            messages.push(Message::tool_result(i.to_string(), "result", false));
        }
        let mut req = ChatRequest::new("claude-opus-4-6", messages, 512);
        req.system = Some("be helpful".to_string());
        let body = build_request_body(&req);
        let markers = body.to_string().matches("cache_control").count();
        assert_eq!(markers, 2);
    }

    #[test]
    fn the_marker_lands_on_the_last_user_turn_even_when_an_assistant_turn_follows() {
        // An assistant prefill as the final message: the marker still goes
        // on the most recent USER message, matching `_with_cache_marker`'s
        // "last content block of the conversation the model must re-read".
        let req = ChatRequest::new(
            "claude-opus-4-6",
            vec![
                Message::user_text("question"),
                Message::assistant(vec![ContentBlock::text("partial answer")]),
            ],
            512,
        );
        let body = build_request_body(&req);
        assert_eq!(
            body["messages"][0]["content"][0]["cache_control"],
            json!({"type": "ephemeral"})
        );
        assert!(body["messages"][1]["content"][0]
            .get("cache_control")
            .is_none());
    }

    #[test]
    fn marking_a_message_list_with_no_user_turn_is_a_no_op() {
        // Unreachable through `run_agentic` (every request starts with the
        // user prompt), so exercised directly against the helper.
        let mut messages =
            vec![json!({"role": "assistant", "content": [{"type": "text", "text": "x"}]})];
        assert!(!mark_latest_turn_for_caching(&mut messages));
        assert!(messages[0]["content"][0].get("cache_control").is_none());
    }

    #[test]
    fn marking_a_user_turn_with_no_content_blocks_is_a_no_op() {
        // `Message`'s fields are public, so a content-less user message is
        // constructible even though nothing in this workspace builds one.
        let mut messages = vec![json!({"role": "user", "content": []})];
        assert!(!mark_latest_turn_for_caching(&mut messages));
        assert_eq!(messages[0]["content"], json!([]));
    }

    #[test]
    fn system_prompt_is_a_top_level_field_not_a_message() {
        let mut req = ChatRequest::new("claude-opus-4-6", vec![Message::user_text("hi")], 512);
        req.system = Some("be helpful".to_string());
        let body = build_request_body(&req);
        assert_eq!(body["system"][0]["text"], "be helpful");
        assert_eq!(body["messages"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn system_prompt_is_marked_for_ephemeral_prompt_caching() {
        let mut req = ChatRequest::new("claude-opus-4-6", vec![Message::user_text("hi")], 512);
        req.system = Some("be helpful".to_string());
        let body = build_request_body(&req);
        assert_eq!(
            body["system"],
            json!([{
                "type": "text",
                "text": "be helpful",
                "cache_control": {"type": "ephemeral"},
            }])
        );
    }

    #[test]
    fn tools_use_the_input_schema_envelope() {
        let mut req = ChatRequest::new("claude-opus-4-6", vec![Message::user_text("hi")], 512);
        req.tools.push(ToolSpec {
            name: "Read".to_string(),
            description: "read a file".to_string(),
            parameters: json!({"type": "object"}),
        });
        let body = build_request_body(&req);
        assert_eq!(
            body["tools"],
            json!([{"name": "Read", "description": "read a file", "input_schema": {"type": "object"}}])
        );
    }

    #[test]
    fn temperature_and_thinking_budget_are_included_when_set() {
        let mut req = ChatRequest::new("claude-opus-4-6", vec![Message::user_text("hi")], 512);
        req.temperature = Some(0.2);
        req.thinking_budget = Some(4000);
        let body = build_request_body(&req);
        assert_eq!(body["temperature"], 0.2);
        assert_eq!(
            body["thinking"],
            json!({"type": "enabled", "budget_tokens": 4000})
        );
    }

    #[test]
    fn assistant_message_with_text_and_tool_use() {
        let messages = vec![Message::assistant(vec![
            ContentBlock::text("looking it up"),
            ContentBlock::ToolUse {
                id: "1".to_string(),
                name: "Glob".to_string(),
                input: json!({}),
            },
        ])];
        let out = to_anthropic_messages(&messages);
        assert_eq!(
            Value::Array(out),
            json!([{
                "role": "assistant",
                "content": [
                    {"type": "text", "text": "looking it up"},
                    {"type": "tool_use", "id": "1", "name": "Glob", "input": {}},
                ],
            }])
        );
    }

    #[test]
    fn a_single_tool_result_message_becomes_a_user_message_with_one_block() {
        let messages = vec![Message::tool_result("call_1", "contents", false)];
        let out = to_anthropic_messages(&messages);
        assert_eq!(
            Value::Array(out),
            json!([{
                "role": "user",
                "content": [{"type": "tool_result", "tool_use_id": "call_1", "content": "contents"}],
            }])
        );
    }

    #[test]
    fn an_error_tool_result_sets_is_error() {
        let messages = vec![Message::tool_result("call_1", "boom", true)];
        let out = to_anthropic_messages(&messages);
        assert_eq!(out[0]["content"][0]["is_error"], true);
    }

    #[test]
    fn consecutive_tool_messages_are_folded_into_one_user_message() {
        let messages = vec![
            Message::assistant(vec![ContentBlock::text("using two tools")]),
            Message::tool_result("call_1", "result one", false),
            Message::tool_result("call_2", "result two", false),
            Message::user_text("thanks"),
        ];
        let out = to_anthropic_messages(&messages);
        assert_eq!(out.len(), 3);
        assert_eq!(out[0]["role"], "assistant");
        assert_eq!(out[1]["role"], "user");
        assert_eq!(out[1]["content"].as_array().unwrap().len(), 2);
        assert_eq!(out[1]["content"][0]["tool_use_id"], "call_1");
        assert_eq!(out[1]["content"][1]["tool_use_id"], "call_2");
        assert_eq!(out[2]["role"], "user");
        assert_eq!(out[2]["content"][0]["text"], "thanks");
    }
}
