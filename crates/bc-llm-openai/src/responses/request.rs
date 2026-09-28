//! `ChatRequest` -> OpenAI Responses API (`POST {base}/responses`) JSON
//! request body. Mirrors what the Python original's DeepAgents route sends
//! through `ChatOpenAI(use_responses_api=True, store=False,
//! include=["reasoning.encrypted_content"])`
//! (`deepagents/options/model_building.py::_transport_kwargs`).
//!
//! **Stateless by design.** `store: false` asks OpenAI to retain nothing
//! server-side, so no prompt (and no scanned source code) outlives the
//! call there. The price is that the server cannot look up the model's
//! earlier reasoning by id, so the request asks for
//! `reasoning.encrypted_content` and every reasoning item is replayed
//! with it on the next turn (see [`to_input`]).

use bc_llm_client::capabilities::warn_param_once;
use bc_llm_client::{ChatRequest, ContentBlock, Message, OpaqueDialect, Role, ToolSpec};
use serde_json::{json, Value};

use crate::cache_key::{prompt_cache_key, with_prefix};
use crate::params::resolve;

/// The smallest `max_output_tokens` the Responses API accepts.
const MIN_OUTPUT_TOKENS: u32 = 16;

pub fn build_request_body(request: &ChatRequest) -> Value {
    let resolved = resolve(request);
    let mut body = json!({
        "model": request.model,
        "input": to_input(request),
        "max_output_tokens": resolved.max_tokens.max(MIN_OUTPUT_TOKENS),
        "store": false,
        "include": ["reasoning.encrypted_content"],
    });
    if let Some(system) = &request.system {
        body["instructions"] = json!(system);
    }
    if !request.tools.is_empty() {
        body["tools"] = Value::Array(request.tools.iter().map(to_responses_tool).collect());
    }
    if let Some(effort) = resolved.effort {
        body["reasoning"] = json!({"effort": effort.as_str()});
    }
    if let Some(temperature) = resolved.temperature {
        body["temperature"] = json!(temperature);
    }
    if let Some(top_p) = resolved.top_p {
        body["top_p"] = json!(top_p);
    }
    // The Responses API has no `seed` parameter at all.
    if resolved.seed.is_some() {
        warn_param_once(
            &request.model,
            "seed",
            "the Responses API has no seed parameter; not sent",
        );
    }
    if request.json_mode {
        body["text"] = json!({"format": {"type": "json_object"}});
    }
    if let Some(key) = prompt_cache_key(request) {
        body["prompt_cache_key"] = json!(key);
    }
    if request.stream {
        // No `stream_options` here: the Responses stream always ends with
        // the complete response object, usage included.
        body["stream"] = json!(true);
    }
    body
}

/// The conversation as Responses API input items, in order.
///
/// A user turn is a plain `{"role": "user"}` message; an assistant turn
/// becomes one item per block, in the block order the model produced
/// them (a reasoning item, then the function call it led to); a tool
/// result is a `function_call_output` addressed by `call_id`.
fn to_input(request: &ChatRequest) -> Vec<Value> {
    let first_user = request.messages.iter().position(|m| m.role == Role::User);
    let mut items = Vec::new();
    for (i, message) in request.messages.iter().enumerate() {
        match message.role {
            Role::User => items.push(json!({
                "role": "user",
                "content": with_prefix(request, Some(i) == first_user, text_of(message)),
            })),
            Role::Assistant => items.extend(message.content.iter().filter_map(assistant_item)),
            Role::Tool => items.extend(message.content.iter().filter_map(tool_output_item)),
        }
    }
    items
}

fn text_of(message: &Message) -> String {
    message
        .content
        .iter()
        .filter_map(|b| match b {
            ContentBlock::Text(t) => Some(t.as_str()),
            _ => None,
        })
        .collect()
}

fn assistant_item(block: &ContentBlock) -> Option<Value> {
    match block {
        ContentBlock::Text(text) if !text.is_empty() => Some(json!({
            "type": "message",
            "role": "assistant",
            "content": [{"type": "output_text", "text": text}],
        })),
        ContentBlock::ToolUse { id, name, input } => Some(json!({
            "type": "function_call",
            "call_id": id,
            "name": name,
            "arguments": input.to_string(),
        })),
        other => other
            .opaque_for(OpaqueDialect::OpenAiResponses)
            .and_then(replayable_reasoning),
    }
}

/// A reasoning item worth sending back: replayed VERBATIM, `id`
/// included, as OpenAI's stateless (`store: false`) guidance does
/// (`context += response.output`). With `encrypted_content` present the
/// server decrypts the reasoning from the item itself and never needs to
/// resolve the id.
///
/// An item WITHOUT `encrypted_content` is dropped instead: with
/// `store: false` its id points at nothing, and the API answers "Item
/// with id 'rs_...' not found" rather than ignoring it. It can only arise
/// from a gateway that stripped the field; losing that one turn's
/// reasoning is the right trade for not failing the call.
fn replayable_reasoning(item: &Value) -> Option<Value> {
    let has_ciphertext = item["encrypted_content"]
        .as_str()
        .is_some_and(|c| !c.is_empty());
    (item["type"] == "reasoning" && has_ciphertext).then(|| item.clone())
}

/// A `Role::Tool` message is expected to wrap exactly one
/// [`ContentBlock::ToolResult`]; anything else in it has no Responses API
/// counterpart and is skipped.
fn tool_output_item(block: &ContentBlock) -> Option<Value> {
    match block {
        ContentBlock::ToolResult {
            tool_use_id,
            content,
            ..
        } => Some(json!({
            "type": "function_call_output",
            "call_id": tool_use_id,
            "output": content,
        })),
        _ => None,
    }
}

/// The Responses API's flat function-tool envelope (no nested
/// `function` object). `strict: false` keeps the tool schemas this
/// project already has valid as they are: strict mode would demand every
/// property be listed as required and `additionalProperties: false`.
fn to_responses_tool(spec: &ToolSpec) -> Value {
    json!({
        "type": "function",
        "name": spec.name,
        "description": spec.description,
        "parameters": spec.parameters,
        "strict": false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_llm_client::{CachePolicy, ReasoningEffort};

    fn reasoning_item() -> Value {
        json!({
            "type": "reasoning",
            "id": "rs_1",
            "summary": [],
            "encrypted_content": "gAAAA-opaque",
        })
    }

    #[test]
    fn a_minimal_request_is_stateless_and_asks_for_encrypted_reasoning() {
        let req = ChatRequest::new("gpt-5.1", vec![Message::user_text("hi")], 512);
        let body = build_request_body(&req);
        assert_eq!(
            body,
            json!({
                "model": "gpt-5.1",
                "input": [{"role": "user", "content": "hi"}],
                "max_output_tokens": 512,
                "store": false,
                "include": ["reasoning.encrypted_content"],
            })
        );
    }

    #[test]
    fn every_optional_field_lands_where_the_responses_api_wants_it() {
        let mut req = ChatRequest::new("gpt-4o", vec![Message::user_text("x".repeat(5_000))], 8);
        req.system = Some("be careful".into());
        req.tools.push(ToolSpec {
            name: "Read".into(),
            description: "read a file".into(),
            parameters: json!({"type": "object"}),
        });
        req.temperature = Some(0.2);
        req.top_p = Some(0.9);
        req.seed = Some(42);
        req.json_mode = true;
        req.stream = true;
        req.cache_key = Some("stage".into());
        let body = build_request_body(&req);
        assert_eq!(body["instructions"], "be careful");
        assert_eq!(
            body["tools"],
            json!([{
                "type": "function",
                "name": "Read",
                "description": "read a file",
                "parameters": {"type": "object"},
                "strict": false,
            }])
        );
        assert_eq!(body["temperature"], 0.2);
        assert_eq!(body["top_p"], 0.9);
        assert_eq!(body["text"], json!({"format": {"type": "json_object"}}));
        assert_eq!(body["stream"], true);
        assert_eq!(body["prompt_cache_key"].as_str().unwrap().len(), 32);
        // The floor, and never the chat-only keys.
        assert_eq!(body["max_output_tokens"], 16);
        for key in [
            "seed",
            "stream_options",
            "messages",
            "max_completion_tokens",
        ] {
            assert!(body.get(key).is_none(), "{key} must not be sent");
        }
    }

    #[test]
    fn effort_goes_in_the_reasoning_object_and_blocks_sampling_on_gpt_5_6() {
        let mut req = ChatRequest::new("gpt-5.6-luna", vec![Message::user_text("hi")], 512);
        req.reasoning_effort = Some(ReasoningEffort::High);
        req.temperature = Some(0.0);
        let body = build_request_body(&req);
        assert_eq!(body["reasoning"], json!({"effort": "high"}));
        assert!(body.get("temperature").is_none());
    }

    #[test]
    fn a_tool_loop_is_replayed_as_reasoning_then_call_then_output() {
        let mut req = ChatRequest::new(
            "gpt-5.1",
            vec![
                Message::user_text("find the bug"),
                Message::assistant(vec![
                    ContentBlock::Opaque {
                        dialect: OpaqueDialect::OpenAiResponses,
                        payload: reasoning_item(),
                    },
                    ContentBlock::text("reading"),
                    ContentBlock::ToolUse {
                        id: "call_1".into(),
                        name: "Read".into(),
                        input: json!({"path": "a.rs"}),
                    },
                ]),
                Message::tool_result("call_1", "fn main() {}", false),
            ],
            512,
        );
        req.cache_prefix = Some("PREFIX ".into());
        req.cache = CachePolicy::default();
        let body = build_request_body(&req);
        assert_eq!(
            body["input"],
            json!([
                {"role": "user", "content": "PREFIX find the bug"},
                reasoning_item(),
                {"type": "message", "role": "assistant",
                 "content": [{"type": "output_text", "text": "reading"}]},
                {"type": "function_call", "call_id": "call_1", "name": "Read",
                 "arguments": "{\"path\":\"a.rs\"}"},
                {"type": "function_call_output", "call_id": "call_1", "output": "fn main() {}"},
            ])
        );
    }

    #[test]
    fn foreign_or_unreplayable_opaque_blocks_are_dropped() {
        let mut no_ciphertext = reasoning_item();
        no_ciphertext["encrypted_content"] = json!("");
        let req = ChatRequest::new(
            "gpt-5.1",
            vec![
                Message::user_text("q"),
                Message::assistant(vec![
                    ContentBlock::Opaque {
                        dialect: OpaqueDialect::Anthropic,
                        payload: json!({"type": "thinking", "signature": "s"}),
                    },
                    ContentBlock::Opaque {
                        dialect: OpaqueDialect::OpenAiResponses,
                        payload: no_ciphertext,
                    },
                    ContentBlock::Opaque {
                        dialect: OpaqueDialect::OpenAiResponses,
                        payload: json!({"type": "web_search_call", "encrypted_content": "x"}),
                    },
                    ContentBlock::text(""),
                ]),
                // Only a user turn's text is sent.
                Message {
                    role: Role::User,
                    content: vec![
                        ContentBlock::text("more"),
                        ContentBlock::ToolResult {
                            tool_use_id: "x".into(),
                            content: "stray".into(),
                            is_error: false,
                        },
                    ],
                },
                // A malformed tool message contributes nothing.
                Message {
                    role: Role::Tool,
                    content: vec![ContentBlock::text("stray")],
                },
            ],
            512,
        );
        let body = build_request_body(&req);
        assert_eq!(
            body["input"],
            json!([
                {"role": "user", "content": "q"},
                {"role": "user", "content": "more"},
            ])
        );
    }
}
