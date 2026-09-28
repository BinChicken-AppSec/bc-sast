//! OpenAI Responses API JSON response -> [`ChatResponse`].
//!
//! The response is a list of typed `output` items rather than one
//! message: `message` items carry `output_text` (and `refusal`) parts,
//! `function_call` items carry tool calls addressed by `call_id`, and
//! `reasoning` items carry the model's encrypted chain of thought, which
//! is kept as a [`ContentBlock::Opaque`] so the next turn can replay it.

use bc_llm_client::{ChatResponse, ContentBlock, LlmError, OpaqueDialect, StopReason};
use serde_json::{Map, Value};

use crate::chat::response::refusal_error;
use crate::errors::classify_stream_error;
use crate::usage::normalize_usage;

/// Whether `body` looks like a Responses API document at all. A 2xx
/// without an `output` array is what a gateway that does not route
/// `/responses` properly sends back, and is evidence for the transport
/// fallback, unless the body is a `failed` response (which reports its
/// own error instead).
pub fn has_output(body: &Value) -> bool {
    body["output"].is_array() || body["status"] == "failed"
}

pub fn parse_response_body(body: &Value) -> Result<ChatResponse, LlmError> {
    if body["status"] == "failed" {
        // The error object carries a `code`/`message` pair in the same
        // vocabulary as a mid-stream chat error, so it is classified the
        // same way (a missing one defaults to a transient 500).
        return Err(classify_stream_error(&body["error"]));
    }
    let items = body["output"].as_array().ok_or_else(|| LlmError::Other {
        message: "response has no output".to_string(),
    })?;

    let mut content = Vec::new();
    let mut refusals = Vec::new();
    for item in items {
        match item["type"].as_str() {
            Some("message") => {
                for part in item["content"].as_array().into_iter().flatten() {
                    match part["type"].as_str() {
                        Some("output_text") => {
                            if let Some(text) = part["text"].as_str().filter(|t| !t.is_empty()) {
                                content.push(ContentBlock::text(text));
                            }
                        }
                        Some("refusal") => {
                            refusals.extend(part["refusal"].as_str().map(str::to_string));
                        }
                        _ => {}
                    }
                }
            }
            Some("function_call") => content.push(ContentBlock::ToolUse {
                id: item["call_id"].as_str().unwrap_or_default().to_string(),
                name: item["name"].as_str().unwrap_or_default().to_string(),
                input: item["arguments"]
                    .as_str()
                    .and_then(|s| serde_json::from_str(s).ok())
                    .unwrap_or_else(|| Value::Object(Map::new())),
            }),
            Some("reasoning") => content.push(ContentBlock::Opaque {
                dialect: OpaqueDialect::OpenAiResponses,
                payload: item.clone(),
            }),
            // Built-in tool calls and anything newer: nothing this seam
            // models, skipped rather than failing the parts it does.
            _ => {}
        }
    }

    let answered = content
        .iter()
        .any(|b| matches!(b, ContentBlock::Text(_) | ContentBlock::ToolUse { .. }));
    if !answered {
        if let Some(refusal) = refusals.iter().find(|r| !r.is_empty()) {
            return Err(refusal_error(refusal));
        }
    }

    let called_a_tool = content
        .iter()
        .any(|b| matches!(b, ContentBlock::ToolUse { .. }));
    let stop_reason = if body["status"] == "incomplete" {
        match body["incomplete_details"]["reason"].as_str() {
            Some("max_output_tokens") => StopReason::MaxTokens,
            Some(other) => StopReason::Other(other.to_string()),
            None => StopReason::Other("incomplete".to_string()),
        }
    } else if called_a_tool {
        StopReason::ToolUse
    } else {
        StopReason::EndTurn
    };

    Ok(ChatResponse {
        content,
        stop_reason,
        usage: normalize_usage(
            &body["usage"],
            "input_tokens",
            "input_tokens_details",
            "output_tokens",
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_llm_client::Usage;
    use serde_json::json;

    #[test]
    fn a_text_answer_with_cached_usage() {
        let resp = parse_response_body(&json!({
            "status": "completed",
            "output": [{
                "type": "message", "role": "assistant",
                "content": [
                    {"type": "output_text", "text": "hello "},
                    {"type": "output_text", "text": ""},
                    {"type": "output_text", "text": "there"},
                    {"type": "annotation_like_future_part"},
                ],
            }],
            "usage": {
                "input_tokens": 9_000,
                "output_tokens": 12,
                "input_tokens_details": {"cached_tokens": 8_192},
            },
        }))
        .unwrap();
        assert_eq!(resp.text(), "hello there");
        assert_eq!(resp.stop_reason, StopReason::EndTurn);
        assert_eq!(
            resp.usage,
            Usage {
                input_tokens: 808,
                output_tokens: 12,
                cache_creation_input_tokens: 0,
                cache_read_input_tokens: 8_192,
            }
        );
    }

    #[test]
    fn reasoning_and_function_calls_in_order() {
        let reasoning = json!({"type": "reasoning", "id": "rs_1", "encrypted_content": "e"});
        let resp = parse_response_body(&json!({
            "status": "completed",
            "output": [
                reasoning,
                {"type": "function_call", "id": "fc_1", "call_id": "call_1",
                 "name": "Read", "arguments": "{\"path\":\"a.rs\"}"},
                {"type": "function_call", "call_id": "call_2", "name": "Glob",
                 "arguments": "not json"},
                {"type": "web_search_call"},
            ],
        }))
        .unwrap();
        assert_eq!(resp.stop_reason, StopReason::ToolUse);
        assert_eq!(
            resp.content,
            vec![
                ContentBlock::Opaque {
                    dialect: OpaqueDialect::OpenAiResponses,
                    payload: reasoning,
                },
                ContentBlock::ToolUse {
                    id: "call_1".into(),
                    name: "Read".into(),
                    input: json!({"path": "a.rs"}),
                },
                ContentBlock::ToolUse {
                    id: "call_2".into(),
                    name: "Glob".into(),
                    input: json!({}),
                },
            ]
        );
        assert_eq!(resp.usage, Usage::default());
    }

    #[test]
    fn incomplete_maps_to_max_tokens_or_other() {
        let of = |details: Value| {
            parse_response_body(&json!({
                "status": "incomplete", "incomplete_details": details, "output": [],
            }))
            .unwrap()
            .stop_reason
        };
        assert_eq!(
            of(json!({"reason": "max_output_tokens"})),
            StopReason::MaxTokens
        );
        assert_eq!(
            of(json!({"reason": "content_filter"})),
            StopReason::Other("content_filter".into())
        );
        assert_eq!(of(Value::Null), StopReason::Other("incomplete".into()));
    }

    #[test]
    fn a_failed_response_is_classified_like_any_other_error() {
        let err = parse_response_body(&json!({
            "status": "failed",
            "error": {"code": "rate_limit_exceeded", "message": "slow down"},
            "output": [],
        }))
        .unwrap_err();
        assert_eq!(
            err,
            LlmError::RateLimited {
                retry_after_secs: None
            }
        );
        let err = parse_response_body(&json!({"status": "failed"})).unwrap_err();
        assert!(
            matches!(err, LlmError::ServerError { status: 500, .. }),
            "{err:?}"
        );
    }

    #[test]
    fn a_refusal_with_nothing_else_is_a_guardrail_block() {
        let err = parse_response_body(&json!({
            "status": "completed",
            "output": [{"type": "message", "content": [
                {"type": "refusal", "refusal": ""},
                {"type": "refusal", "refusal": "I can't help with that."},
            ]}],
        }))
        .unwrap_err();
        assert!(matches!(err, LlmError::GuardrailBlocked { .. }), "{err:?}");
        // A refusal beside a real answer keeps the answer.
        let ok = parse_response_body(&json!({
            "output": [{"type": "message", "content": [
                {"type": "output_text", "text": "partial"},
                {"type": "refusal", "refusal": "no more"},
            ]}],
        }))
        .unwrap();
        assert_eq!(ok.text(), "partial");
        // Only empty refusals: an empty answer, not an error.
        let empty = parse_response_body(&json!({
            "output": [{"type": "message", "content": [{"type": "refusal", "refusal": ""}]}],
        }))
        .unwrap();
        assert!(empty.content.is_empty());
    }

    #[test]
    fn a_body_without_output_is_an_error_and_flagged_for_fallback() {
        let body = json!({"choices": []});
        assert!(!has_output(&body));
        assert!(matches!(
            parse_response_body(&body),
            Err(LlmError::Other { .. })
        ));
        assert!(has_output(&json!({"output": []})));
        assert!(has_output(&json!({"status": "failed"})));
    }
}
