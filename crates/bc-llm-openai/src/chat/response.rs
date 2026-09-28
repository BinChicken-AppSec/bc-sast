//! OpenAI chat-completions JSON response -> [`ChatResponse`], ported from
//! `backends/oai.py`'s response/usage handling. Error-status
//! classification is shared with the Responses API shape and lives in
//! [`crate::errors`].

use bc_llm_client::{sanitize_error_body, ChatResponse, ContentBlock, LlmError, StopReason};
use serde_json::Value;

use crate::usage::normalize_usage;

pub fn parse_response_body(body: &Value) -> Result<ChatResponse, LlmError> {
    let choice = body["choices"]
        .as_array()
        .and_then(|arr| arr.first())
        .ok_or_else(|| LlmError::Other {
            message: "response has no choices".to_string(),
        })?;
    let message = &choice["message"];

    let mut content = Vec::new();
    if let Some(text) = message["content"].as_str() {
        if !text.is_empty() {
            content.push(ContentBlock::text(text));
        }
    }
    if let Some(tool_calls) = message["tool_calls"].as_array() {
        for tc in tool_calls {
            content.push(ContentBlock::ToolUse {
                id: tc["id"].as_str().unwrap_or_default().to_string(),
                name: tc["function"]["name"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                input: tc["function"]["arguments"]
                    .as_str()
                    .and_then(|s| serde_json::from_str(s).ok())
                    .unwrap_or_else(|| Value::Object(serde_json::Map::new())),
            });
        }
    }

    // A refusal is the model declining on safety grounds (`message.refusal`,
    // with no content): surfaced as the same guardrail error the
    // Anthropic dialect raises for its canned refusal, so S6's
    // cumulative-refusal gate counts it, rather than as an empty answer a
    // stage would try to parse. A refusal alongside real content keeps
    // the content.
    if content.is_empty() {
        if let Some(refusal) = message["refusal"].as_str().filter(|r| !r.is_empty()) {
            return Err(refusal_error(refusal));
        }
    }

    let stop_reason = match choice["finish_reason"].as_str() {
        Some("tool_calls") => StopReason::ToolUse,
        Some("length") => StopReason::MaxTokens,
        Some("stop") => StopReason::EndTurn,
        Some(other) => StopReason::Other(other.to_string()),
        None => StopReason::Other("missing".to_string()),
    };

    Ok(ChatResponse {
        content,
        stop_reason,
        usage: normalize_usage(
            &body["usage"],
            "prompt_tokens",
            "prompt_tokens_details",
            "completion_tokens",
        ),
    })
}

/// The guardrail error for a model refusal, shared by both shapes.
pub fn refusal_error(refusal: &str) -> LlmError {
    LlmError::GuardrailBlocked {
        message: format!("the model refused: {}", sanitize_error_body(refusal)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_llm_client::Usage;
    use serde_json::json;

    #[test]
    fn parses_text_only_response() {
        let body = json!({
            "choices": [{"message": {"role": "assistant", "content": "hi there"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5},
        });
        let resp = parse_response_body(&body).unwrap();
        assert_eq!(resp.text(), "hi there");
        assert_eq!(resp.stop_reason, StopReason::EndTurn);
        assert_eq!(resp.usage.input_tokens, 10);
        assert_eq!(resp.usage.output_tokens, 5);
        assert_eq!(resp.usage.cache_read_input_tokens, 0);
    }

    #[test]
    fn parses_tool_call_response() {
        let body = json!({
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": {"name": "Read", "arguments": "{\"path\":\"a.rs\"}"},
                    }],
                },
                "finish_reason": "tool_calls",
            }],
            "usage": {"prompt_tokens": 20, "completion_tokens": 8,
                      "prompt_tokens_details": {"cached_tokens": 4}},
        });
        let resp = parse_response_body(&body).unwrap();
        assert_eq!(resp.stop_reason, StopReason::ToolUse);
        let calls = resp.tool_uses();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0], ("call_1", "Read", &json!({"path": "a.rs"})));
        assert_eq!(resp.usage.input_tokens, 16);
        assert_eq!(resp.usage.cache_read_input_tokens, 4);
    }

    #[test]
    fn tool_call_with_unparseable_arguments_falls_back_to_empty_object() {
        let body = json!({
            "choices": [{
                "message": {
                    "content": null,
                    "tool_calls": [{"id": "1", "function": {"name": "Read", "arguments": "not json"}}],
                },
                "finish_reason": "tool_calls",
            }],
        });
        let resp = parse_response_body(&body).unwrap();
        assert_eq!(resp.tool_uses()[0].2, &json!({}));
    }

    #[test]
    fn finish_reason_length_maps_to_max_tokens() {
        let body = json!({
            "choices": [{"message": {"content": "cut off"}, "finish_reason": "length"}],
        });
        let resp = parse_response_body(&body).unwrap();
        assert_eq!(resp.stop_reason, StopReason::MaxTokens);
    }

    #[test]
    fn unrecognized_finish_reason_is_preserved_as_other() {
        let body = json!({
            "choices": [{"message": {"content": "x"}, "finish_reason": "content_filter"}],
        });
        let resp = parse_response_body(&body).unwrap();
        assert_eq!(
            resp.stop_reason,
            StopReason::Other("content_filter".to_string())
        );
    }

    #[test]
    fn missing_finish_reason_is_other_missing() {
        let body = json!({"choices": [{"message": {"content": "x"}}]});
        let resp = parse_response_body(&body).unwrap();
        assert_eq!(resp.stop_reason, StopReason::Other("missing".to_string()));
    }

    #[test]
    fn empty_choices_array_is_an_error() {
        let body = json!({"choices": []});
        let err = parse_response_body(&body).unwrap_err();
        assert!(matches!(err, LlmError::Other { .. }));
    }

    #[test]
    fn missing_choices_field_is_an_error() {
        let body = json!({});
        let err = parse_response_body(&body).unwrap_err();
        assert!(matches!(err, LlmError::Other { .. }));
    }

    #[test]
    fn missing_usage_defaults_to_zero() {
        let body = json!({"choices": [{"message": {"content": "x"}, "finish_reason": "stop"}]});
        let resp = parse_response_body(&body).unwrap();
        assert_eq!(resp.usage, Usage::default());
    }

    #[test]
    fn empty_text_content_produces_no_text_block() {
        let body = json!({"choices": [{"message": {"content": ""}, "finish_reason": "stop"}]});
        let resp = parse_response_body(&body).unwrap();
        assert_eq!(resp.text(), "");
    }

    #[test]
    fn a_refusal_with_no_content_is_a_guardrail_block() {
        let err = parse_response_body(&json!({
            "choices": [{"message": {"content": null, "refusal": "I can't help with that."},
                         "finish_reason": "stop"}],
        }))
        .unwrap_err();
        assert!(
            matches!(&err, LlmError::GuardrailBlocked { message } if message.contains("can't help")),
            "{err:?}"
        );
    }

    #[test]
    fn a_refusal_alongside_content_keeps_the_content() {
        let resp = parse_response_body(&json!({
            "choices": [{"message": {"content": "partial", "refusal": "no"},
                         "finish_reason": "stop"}],
        }))
        .unwrap();
        assert_eq!(resp.text(), "partial");
        // An empty refusal string is no refusal.
        let empty = parse_response_body(&json!({
            "choices": [{"message": {"content": null, "refusal": ""}, "finish_reason": "stop"}],
        }))
        .unwrap();
        assert!(empty.content.is_empty());
    }

    #[test]
    fn usage_carves_cache_reads_and_writes_out_of_the_prompt() {
        let resp = parse_response_body(&json!({
            "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
            "usage": {
                "prompt_tokens": 12_000,
                "completion_tokens": 40,
                "prompt_tokens_details": {"cached_tokens": 8_000, "cache_write_tokens": 3_000},
            },
        }))
        .unwrap();
        assert_eq!(
            resp.usage,
            Usage {
                input_tokens: 1_000,
                output_tokens: 40,
                cache_creation_input_tokens: 3_000,
                cache_read_input_tokens: 8_000,
            }
        );
    }
}
