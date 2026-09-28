//! `ChatRequest` -> OpenAI chat-completions JSON request body, ported from
//! the request-shape half of `backends/oai.py`'s `agentic()`/`prompt()`.
//!
//! Parameters the capability table says the model rejects are left out
//! before sending (see [`crate::params`]); the client's quirk memory
//! catches whatever the table gets wrong.

use bc_llm_client::capabilities::TokenParam;
use bc_llm_client::{ChatRequest, ContentBlock, Message, Role, ToolSpec};
use serde_json::{json, Value};

use crate::cache_key::{prompt_cache_key, with_prefix};
use crate::params::resolve;

pub fn build_request_body(request: &ChatRequest) -> Value {
    let resolved = resolve(request);
    let mut messages = Vec::new();
    if let Some(system) = &request.system {
        messages.push(json!({"role": "system", "content": system}));
    }
    let first_user = request.messages.iter().position(|m| m.role == Role::User);
    messages.extend(
        request
            .messages
            .iter()
            .enumerate()
            .map(|(i, m)| to_openai_message(request, m, Some(i) == first_user)),
    );

    // Newer reasoning-class models (o-series, gpt-5+) reject the legacy
    // `max_tokens` name outright; `max_completion_tokens` is the current,
    // forward-compatible name OpenAI accepts across both old and new
    // models, and the capability table's default. The client's quirk
    // memory corrects (and remembers) this guess for the case where a
    // model only understands the legacy name (some OpenAI-compatible
    // gateways). Matches `backends/oai.py::prompt`'s own default ("assume
    // the new name, fall back to the old one on rejection").
    let token_key = match resolved.caps.token_param {
        TokenParam::MaxCompletionTokens => "max_completion_tokens",
        TokenParam::MaxTokens => "max_tokens",
    };
    let mut body = json!({
        "model": request.model,
        "messages": messages,
    });
    body[token_key] = json!(resolved.max_tokens);

    if !request.tools.is_empty() {
        body["tools"] = Value::Array(request.tools.iter().map(to_openai_tool).collect());
    }
    if let Some(effort) = resolved.effort {
        body["reasoning_effort"] = json!(effort.as_str());
    }
    if let Some(temperature) = resolved.temperature {
        body["temperature"] = json!(temperature);
    }
    // Sent alongside `temperature` when both are set and the model takes
    // sampling at all: unlike the Anthropic Messages API, the
    // chat-completions dialect documents both knobs as independently
    // settable (it only *recommends* altering one at a time).
    if let Some(top_p) = resolved.top_p {
        body["top_p"] = json!(top_p);
    }
    if let Some(seed) = resolved.seed {
        body["seed"] = json!(seed);
    }
    if request.json_mode {
        body["response_format"] = json!({"type": "json_object"});
    }
    if let Some(key) = prompt_cache_key(request) {
        body["prompt_cache_key"] = json!(key);
    }
    if request.stream {
        body["stream"] = json!(true);
        // Without this the chat-completions stream carries no `usage`
        // object at all — every streamed call would report zero tokens
        // spent, silently defeating the spend cap and every metric built
        // on it. The key is additive and ignored by servers that predate
        // it, so it costs nothing to always send alongside `stream`.
        body["stream_options"] = json!({"include_usage": true});
    }
    body
}

/// Opaque blocks (Responses API reasoning items, Anthropic thinking) have
/// no place in this shape and are dropped: Chat Completions keeps no
/// reasoning state across turns at all.
fn to_openai_message(request: &ChatRequest, m: &Message, first_user_turn: bool) -> Value {
    match m.role {
        Role::User => json!({
            "role": "user",
            "content": with_prefix(request, first_user_turn, content_to_text(&m.content)),
        }),
        Role::Assistant => assistant_message(&m.content),
        Role::Tool => tool_message(&m.content),
    }
}

fn assistant_message(content: &[ContentBlock]) -> Value {
    let text = content_to_text(content);
    let tool_calls: Vec<Value> = content
        .iter()
        .filter_map(|b| match b {
            ContentBlock::ToolUse { id, name, input } => Some(json!({
                "id": id,
                "type": "function",
                "function": {"name": name, "arguments": input.to_string()},
            })),
            _ => None,
        })
        .collect();
    let mut msg = json!({
        "role": "assistant",
        "content": if text.is_empty() { Value::Null } else { Value::String(text) },
    });
    if !tool_calls.is_empty() {
        msg["tool_calls"] = Value::Array(tool_calls);
    }
    msg
}

/// A `Role::Tool` message is expected to wrap exactly one
/// [`ContentBlock::ToolResult`] (the shape [`Message::tool_result`]
/// produces) — OpenAI represents it as its own `"tool"`-role message keyed
/// by `tool_call_id`. `Message`'s fields are public, so a directly
/// constructed `Role::Tool` message without that block is reachable
/// through this crate's public API even though the convenience constructor
/// never produces it; the fallback keeps that case a well-formed (if
/// content-less) request instead of panicking.
fn tool_message(content: &[ContentBlock]) -> Value {
    match content.first() {
        Some(ContentBlock::ToolResult {
            tool_use_id,
            content,
            ..
        }) => json!({
            "role": "tool",
            "tool_call_id": tool_use_id,
            "content": content,
        }),
        _ => json!({"role": "tool", "tool_call_id": "", "content": ""}),
    }
}

fn content_to_text(content: &[ContentBlock]) -> String {
    content
        .iter()
        .filter_map(|b| match b {
            ContentBlock::Text(t) => Some(t.as_str()),
            _ => None,
        })
        .collect()
}

fn to_openai_tool(spec: &ToolSpec) -> Value {
    json!({
        "type": "function",
        "function": {
            "name": spec.name,
            "description": spec.description,
            "parameters": spec.parameters,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_request_has_model_messages_and_max_completion_tokens_only() {
        let req = ChatRequest::new("gpt-4o", vec![Message::user_text("hi")], 512);
        let body = build_request_body(&req);
        assert_eq!(body["model"], "gpt-4o");
        assert_eq!(body["max_completion_tokens"], 512);
        assert!(body.get("max_tokens").is_none());
        assert_eq!(body["messages"], json!([{"role": "user", "content": "hi"}]));
        assert!(body.get("tools").is_none());
        assert!(body.get("temperature").is_none());
        assert!(body.get("top_p").is_none());
        assert!(body.get("seed").is_none());
        assert!(body.get("response_format").is_none());
    }

    #[test]
    fn a_non_streaming_request_carries_neither_stream_key() {
        let body = build_request_body(&ChatRequest::new("gpt-4o", vec![], 512));
        assert!(body.get("stream").is_none());
        assert!(body.get("stream_options").is_none());
    }

    #[test]
    fn a_streaming_request_always_asks_for_usage_too() {
        let mut req = ChatRequest::new("gpt-4o", vec![Message::user_text("hi")], 512);
        req.stream = true;
        let body = build_request_body(&req);
        assert_eq!(body["stream"], true);
        assert_eq!(body["stream_options"], json!({"include_usage": true}));
        // Everything else is unchanged — streaming is a transport
        // choice, not a different request.
        assert_eq!(body["max_completion_tokens"], 512);
        assert_eq!(body["messages"], json!([{"role": "user", "content": "hi"}]));
    }

    #[test]
    fn top_p_and_seed_are_included_when_set() {
        let mut req = ChatRequest::new("gpt-4o", vec![Message::user_text("hi")], 512);
        req.top_p = Some(0.1);
        req.seed = Some(42);
        let body = build_request_body(&req);
        assert_eq!(body["top_p"], 0.1);
        assert_eq!(body["seed"], 42);
    }

    #[test]
    fn temperature_and_top_p_are_both_sent_when_both_are_set() {
        // Unlike the Anthropic dialect (which rejects the pair), the
        // chat-completions API accepts both — see `build_request_body`.
        let mut req = ChatRequest::new("gpt-4o", vec![Message::user_text("hi")], 512);
        req.temperature = Some(0.0);
        req.top_p = Some(0.1);
        let body = build_request_body(&req);
        assert_eq!(body["temperature"], 0.0);
        assert_eq!(body["top_p"], 0.1);
    }

    #[test]
    fn system_prompt_becomes_the_first_message() {
        let mut req = ChatRequest::new("gpt-4o", vec![Message::user_text("hi")], 512);
        req.system = Some("be helpful".to_string());
        let body = build_request_body(&req);
        assert_eq!(
            body["messages"][0],
            json!({"role": "system", "content": "be helpful"})
        );
        assert_eq!(body["messages"][1]["role"], "user");
    }

    #[test]
    fn tools_are_wrapped_in_the_function_envelope() {
        let mut req = ChatRequest::new("gpt-4o", vec![Message::user_text("hi")], 512);
        req.tools.push(ToolSpec {
            name: "Read".to_string(),
            description: "read a file".to_string(),
            parameters: json!({"type": "object"}),
        });
        let body = build_request_body(&req);
        assert_eq!(
            body["tools"],
            json!([{
                "type": "function",
                "function": {
                    "name": "Read",
                    "description": "read a file",
                    "parameters": {"type": "object"},
                },
            }])
        );
    }

    #[test]
    fn temperature_and_json_mode_are_included_when_set() {
        let mut req = ChatRequest::new("gpt-4o", vec![Message::user_text("hi")], 512);
        req.temperature = Some(0.2);
        req.json_mode = true;
        let body = build_request_body(&req);
        assert_eq!(body["temperature"], 0.2);
        assert_eq!(body["response_format"], json!({"type": "json_object"}));
    }

    #[test]
    fn assistant_message_with_only_text() {
        let msg = Message::assistant(vec![ContentBlock::text("hello")]);
        let value = to_openai_message(&ChatRequest::default(), &msg, false);
        assert_eq!(value, json!({"role": "assistant", "content": "hello"}));
    }

    #[test]
    fn assistant_message_with_no_text_has_null_content() {
        let msg = Message::assistant(vec![ContentBlock::ToolUse {
            id: "1".to_string(),
            name: "Read".to_string(),
            input: json!({"path": "a"}),
        }]);
        let value = to_openai_message(&ChatRequest::default(), &msg, false);
        assert_eq!(value["content"], Value::Null);
        assert_eq!(value["tool_calls"][0]["id"], "1");
        assert_eq!(value["tool_calls"][0]["function"]["name"], "Read");
        assert_eq!(
            value["tool_calls"][0]["function"]["arguments"],
            "{\"path\":\"a\"}"
        );
    }

    #[test]
    fn assistant_message_with_text_and_tool_use() {
        let msg = Message::assistant(vec![
            ContentBlock::text("looking it up"),
            ContentBlock::ToolUse {
                id: "1".to_string(),
                name: "Glob".to_string(),
                input: json!({}),
            },
        ]);
        let value = to_openai_message(&ChatRequest::default(), &msg, false);
        assert_eq!(value["content"], "looking it up");
        assert_eq!(value["tool_calls"][0]["function"]["name"], "Glob");
    }

    #[test]
    fn tool_message_from_the_convenience_constructor() {
        let msg = Message::tool_result("call_1", "file contents", false);
        let value = to_openai_message(&ChatRequest::default(), &msg, false);
        assert_eq!(
            value,
            json!({"role": "tool", "tool_call_id": "call_1", "content": "file contents"})
        );
    }

    #[test]
    fn tool_message_with_non_tool_result_content_falls_back_to_empty() {
        // Only reachable via direct struct construction (Message's fields
        // are public) since Message::tool_result never produces this shape.
        let msg = Message {
            role: Role::Tool,
            content: vec![ContentBlock::text("oops")],
        };
        let value = to_openai_message(&ChatRequest::default(), &msg, false);
        assert_eq!(
            value,
            json!({"role": "tool", "tool_call_id": "", "content": ""})
        );
    }

    #[test]
    fn tool_message_with_empty_content_falls_back_to_empty() {
        let msg = Message {
            role: Role::Tool,
            content: vec![],
        };
        let value = to_openai_message(&ChatRequest::default(), &msg, false);
        assert_eq!(
            value,
            json!({"role": "tool", "tool_call_id": "", "content": ""})
        );
    }

    #[test]
    fn a_reasoning_request_carries_its_clamped_effort() {
        let mut req = ChatRequest::new("gpt-5.5", vec![Message::user_text("hi")], 512);
        req.reasoning_effort = Some(bc_llm_client::ReasoningEffort::Max);
        let body = build_request_body(&req);
        assert_eq!(body["reasoning_effort"], "xhigh");
    }

    #[test]
    fn gpt_5_6_luna_with_temperature_zero_and_no_effort_sends_no_sampling() {
        let mut req = ChatRequest::new("gpt-5.6-luna", vec![Message::user_text("hi")], 512);
        req.temperature = Some(0.0);
        let body = build_request_body(&req);
        assert!(body.get("temperature").is_none());
        assert!(body.get("reasoning_effort").is_none());
        req.reasoning_effort = Some(bc_llm_client::ReasoningEffort::None);
        let body = build_request_body(&req);
        assert_eq!(body["temperature"], 0.0);
        assert_eq!(body["reasoning_effort"], "none");
    }

    #[test]
    fn a_claude_model_behind_an_openai_gateway_gets_max_tokens() {
        let req = ChatRequest::new("claude-opus-4-7", vec![Message::user_text("hi")], 512);
        let body = build_request_body(&req);
        assert_eq!(body["max_tokens"], 512);
        assert!(body.get("max_completion_tokens").is_none());
    }

    #[test]
    fn the_output_budget_is_capped_at_the_model_ceiling() {
        let req = ChatRequest::new("gpt-5.6-luna", vec![Message::user_text("hi")], 900_000);
        assert_eq!(build_request_body(&req)["max_completion_tokens"], 128_000);
    }

    #[test]
    fn the_cache_prefix_leads_the_first_user_turn_only() {
        let mut req = ChatRequest::new(
            "gpt-4o",
            vec![
                Message::user_text("first"),
                Message::assistant(vec![ContentBlock::text("ok")]),
                Message::user_text("second"),
            ],
            512,
        );
        req.cache_prefix = Some("SHARED ".to_string());
        let body = build_request_body(&req);
        assert_eq!(body["messages"][0]["content"], "SHARED first");
        assert_eq!(body["messages"][2]["content"], "second");
    }

    #[test]
    fn a_large_keyed_prompt_carries_a_hashed_prompt_cache_key() {
        let mut req = ChatRequest::new("gpt-4o", vec![Message::user_text("x".repeat(5_000))], 512);
        req.cache_key = Some("s4:repo".to_string());
        let body = build_request_body(&req);
        let key = body["prompt_cache_key"].as_str().unwrap();
        assert_eq!(key.len(), 32);
        // Small prompts carry none.
        req.messages = vec![Message::user_text("x")];
        assert!(build_request_body(&req).get("prompt_cache_key").is_none());
    }

    #[test]
    fn opaque_blocks_are_never_sent_on_chat_completions() {
        let msg = Message::assistant(vec![
            ContentBlock::Opaque {
                dialect: bc_llm_client::OpaqueDialect::OpenAiResponses,
                payload: json!({"type": "reasoning", "encrypted_content": "zz"}),
            },
            ContentBlock::text("answer"),
        ]);
        let value = to_openai_message(&ChatRequest::default(), &msg, false);
        assert_eq!(value, json!({"role": "assistant", "content": "answer"}));
    }
}
