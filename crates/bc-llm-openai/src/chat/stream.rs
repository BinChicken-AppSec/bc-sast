//! Reassembles a streamed chat-completions response into the exact JSON
//! body a non-streamed one would have had.
//!
//! **That indirection is the point.** The obvious implementation builds
//! a [`ChatResponse`] directly from the deltas — and then has two
//! parsers for one dialect, which drift the first time either is
//! touched. Instead this accumulates the fragments back into a
//! `{"choices":[{"message":…,"finish_reason":…}],"usage":…}` document
//! and hands it to [`crate::chat::response::parse_response_body`], the same
//! function the non-streaming path calls. Text, tool calls, usage
//! normalization and stop-reason mapping are then identical by
//! construction, not by inspection — which is what makes it safe for a
//! caller to be unable to tell the two modes apart.
//!
//! Ported from no Python at all: `backends/oai.py` never streams (only
//! `backends/sdk.py` does, via the Anthropic SDK's own stream helper,
//! which hides exactly this reassembly).

use std::collections::BTreeMap;

use bc_llm_client::LlmError;
use serde_json::{json, Value};

/// One tool call being accumulated. The wire format splits a single call
/// across many chunks: the first carries `id` and `function.name`, every
/// later one appends a slice of `function.arguments`, and they are
/// correlated by `index` rather than by `id` (which only the first chunk
/// has).
#[derive(Debug, Default)]
struct ToolCall {
    id: String,
    name: String,
    arguments: String,
}

/// Accumulates `data:` payloads from a chat-completions stream.
#[derive(Debug, Default)]
pub struct StreamAssembler {
    content: String,
    /// Keyed by the wire `index` — a `BTreeMap` so the assembled
    /// `tool_calls` array comes out in the model's own order regardless
    /// of the order fragments arrived in.
    tool_calls: BTreeMap<i64, ToolCall>,
    finish_reason: Option<String>,
    usage: Option<Value>,
}

impl StreamAssembler {
    /// Consume one SSE payload.
    ///
    /// Returns `Err` only for an error object the provider itself sent
    /// mid-stream; a payload that isn't valid JSON, or that carries
    /// nothing this dialect understands, is skipped. A stream is a
    /// forward-only medium — refusing the whole response over one
    /// unrecognized keep-alive-shaped chunk would throw away everything
    /// already received, and the provider is free to add chunk types
    /// this port has never seen.
    pub fn push(&mut self, payload: &str) -> Result<(), LlmError> {
        let payload = payload.trim();
        // The chat-completions terminator. It is not JSON, so it must be
        // recognized before parsing rather than after.
        if payload.is_empty() || payload == "[DONE]" {
            return Ok(());
        }
        let Ok(event) = serde_json::from_str::<Value>(payload) else {
            return Ok(());
        };
        if !event["error"].is_null() {
            return Err(crate::errors::classify_stream_error(&event["error"]));
        }
        // Present only on the final chunk, and only because the request
        // asked for `stream_options.include_usage` — without that the
        // stream carries no token accounting at all.
        if !event["usage"].is_null() {
            self.usage = Some(event["usage"].clone());
        }
        for choice in event["choices"].as_array().into_iter().flatten() {
            if let Some(text) = choice["delta"]["content"].as_str() {
                self.content.push_str(text);
            }
            for fragment in choice["delta"]["tool_calls"]
                .as_array()
                .into_iter()
                .flatten()
            {
                self.push_tool_call_fragment(fragment);
            }
            if let Some(reason) = choice["finish_reason"].as_str() {
                self.finish_reason = Some(reason.to_string());
            }
        }
        Ok(())
    }

    /// `index` defaults to 0 for a provider that omits it on a
    /// single-call response — the alternative, dropping the fragment,
    /// would silently lose the tool call entirely.
    fn push_tool_call_fragment(&mut self, fragment: &Value) {
        let index = fragment["index"].as_i64().unwrap_or(0);
        let call = self.tool_calls.entry(index).or_default();
        if let Some(id) = fragment["id"].as_str() {
            call.id.push_str(id);
        }
        if let Some(name) = fragment["function"]["name"].as_str() {
            call.name.push_str(name);
        }
        if let Some(args) = fragment["function"]["arguments"].as_str() {
            call.arguments.push_str(args);
        }
    }

    /// The non-streaming response body this stream amounted to.
    ///
    /// `content` is `null` rather than `""` when the model produced no
    /// text, matching what the API itself sends for a pure tool-call
    /// response — `parse_response_body` skips an empty string anyway, so
    /// this is about the document being a faithful reconstruction rather
    /// than about the parse.
    pub fn finish(self) -> Value {
        let mut message = json!({
            "role": "assistant",
            "content": if self.content.is_empty() { Value::Null } else { Value::String(self.content) },
        });
        if !self.tool_calls.is_empty() {
            message["tool_calls"] = Value::Array(
                self.tool_calls
                    .into_values()
                    .map(|c| {
                        json!({
                            "id": c.id,
                            "type": "function",
                            "function": {"name": c.name, "arguments": c.arguments},
                        })
                    })
                    .collect(),
            );
        }
        json!({
            "choices": [{
                "message": message,
                "finish_reason": self.finish_reason,
            }],
            "usage": self.usage,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chat::response::parse_response_body;
    use bc_llm_client::StopReason;

    fn assemble(payloads: &[&str]) -> Result<Value, LlmError> {
        let mut a = StreamAssembler::default();
        for p in payloads {
            a.push(p)?;
        }
        Ok(a.finish())
    }

    #[test]
    fn text_deltas_concatenate_in_arrival_order() {
        let body = assemble(&[
            r#"{"choices":[{"delta":{"content":"Hello, "},"index":0}]}"#,
            r#"{"choices":[{"delta":{"content":"world"},"index":0}]}"#,
            r#"{"choices":[{"delta":{},"finish_reason":"stop","index":0}]}"#,
            r#"{"choices":[],"usage":{"prompt_tokens":10,"completion_tokens":5}}"#,
            "[DONE]",
        ])
        .unwrap();
        let resp = parse_response_body(&body).unwrap();
        assert_eq!(resp.text(), "Hello, world");
        assert_eq!(resp.stop_reason, StopReason::EndTurn);
        assert_eq!(resp.usage.input_tokens, 10);
        assert_eq!(resp.usage.output_tokens, 5);
    }

    /// The assembled document must parse to exactly what the equivalent
    /// single-response body parses to — the guarantee the whole
    /// reassemble-then-reparse design exists to provide.
    #[test]
    fn the_assembled_response_equals_the_non_streamed_one() {
        let streamed = parse_response_body(
            &assemble(&[
                r#"{"choices":[{"delta":{"role":"assistant","content":""},"index":0}]}"#,
                r#"{"choices":[{"delta":{"content":"hi there"},"index":0}]}"#,
                r#"{"choices":[{"delta":{},"finish_reason":"stop","index":0}]}"#,
                r#"{"choices":[],"usage":{"prompt_tokens":10,"completion_tokens":5,"prompt_tokens_details":{"cached_tokens":4}}}"#,
            ])
            .unwrap(),
        )
        .unwrap();
        let whole = parse_response_body(&json!({
            "choices": [{"message": {"role": "assistant", "content": "hi there"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5,
                      "prompt_tokens_details": {"cached_tokens": 4}},
        }))
        .unwrap();
        assert_eq!(streamed, whole);
    }

    #[test]
    fn tool_call_argument_fragments_accumulate_by_index() {
        let body = assemble(&[
            r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"Read","arguments":""}}]},"index":0}]}"#,
            r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"path\""}}]},"index":0}]}"#,
            r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":":\"a.rs\"}"}}]},"index":0}]}"#,
            r#"{"choices":[{"delta":{},"finish_reason":"tool_calls","index":0}]}"#,
        ])
        .unwrap();
        let resp = parse_response_body(&body).unwrap();
        assert_eq!(resp.stop_reason, StopReason::ToolUse);
        let calls = resp.tool_uses();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "call_1");
        assert_eq!(calls[0].1, "Read");
        assert_eq!(calls[0].2, &json!({"path": "a.rs"}));
    }

    #[test]
    fn two_parallel_tool_calls_come_back_in_index_order() {
        // Deliberately interleaved, and with index 1's fragments
        // arriving before index 0 is finished.
        let body = assemble(&[
            r#"{"choices":[{"delta":{"tool_calls":[{"index":1,"id":"b","function":{"name":"Glob","arguments":"{}"}}]}}]}"#,
            r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"a","function":{"name":"Read","arguments":"{}"}}]}}]}"#,
            r#"{"choices":[{"delta":{},"finish_reason":"tool_calls"}]}"#,
        ])
        .unwrap();
        let resp = parse_response_body(&body).unwrap();
        let calls = resp.tool_uses();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].1, "Read", "index 0 first, not arrival order");
        assert_eq!(calls[1].1, "Glob");
    }

    #[test]
    fn a_tool_call_fragment_without_an_index_defaults_to_zero() {
        let body = assemble(&[
            r#"{"choices":[{"delta":{"tool_calls":[{"id":"a","function":{"name":"Read","arguments":"{}"}}]}}]}"#,
            r#"{"choices":[{"delta":{},"finish_reason":"tool_calls"}]}"#,
        ])
        .unwrap();
        assert_eq!(parse_response_body(&body).unwrap().tool_uses().len(), 1);
    }

    #[test]
    fn text_and_a_tool_call_in_one_response() {
        let body = assemble(&[
            r#"{"choices":[{"delta":{"content":"looking it up"}}]}"#,
            r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"a","function":{"name":"Read","arguments":"{}"}}]}}]}"#,
            r#"{"choices":[{"delta":{},"finish_reason":"tool_calls"}]}"#,
        ])
        .unwrap();
        let resp = parse_response_body(&body).unwrap();
        assert_eq!(resp.text(), "looking it up");
        assert_eq!(resp.tool_uses().len(), 1);
    }

    #[test]
    fn a_mid_stream_error_event_aborts_with_a_classified_error() {
        let mut a = StreamAssembler::default();
        a.push(r#"{"choices":[{"delta":{"content":"partial"}}]}"#)
            .unwrap();
        let err = a
            .push(r#"{"error":{"type":"server_error","message":"upstream exploded"}}"#)
            .unwrap_err();
        assert!(
            matches!(err, LlmError::ServerError { status: 500, .. }),
            "{err:?}"
        );
    }

    #[test]
    fn a_mid_stream_rate_limit_error_is_retryable_as_such() {
        let mut a = StreamAssembler::default();
        let err = a
            .push(r#"{"error":{"code":"rate_limit_exceeded","message":"slow down"}}"#)
            .unwrap_err();
        assert_eq!(
            err,
            LlmError::RateLimited {
                retry_after_secs: None
            }
        );
    }

    #[test]
    fn a_mid_stream_context_overflow_error_keeps_its_specific_variant() {
        let mut a = StreamAssembler::default();
        let err = a
            .push(r#"{"error":{"message":"This model's maximum context length is 8192 tokens"}}"#)
            .unwrap_err();
        assert!(matches!(err, LlmError::ContextOverflow { .. }), "{err:?}");
    }

    #[test]
    fn an_unparseable_or_unrecognized_payload_is_skipped_not_fatal() {
        let body = assemble(&[
            "not json at all",
            r#"{"choices":[{"delta":{"content":"still here"}}]}"#,
            r#"{"some_new_chunk_type":true}"#,
            r#"{"choices":[{"delta":{},"finish_reason":"stop"}]}"#,
            "",
        ])
        .unwrap();
        assert_eq!(parse_response_body(&body).unwrap().text(), "still here");
    }

    #[test]
    fn a_stream_with_no_usage_chunk_reports_zero_usage() {
        let body = assemble(&[r#"{"choices":[{"delta":{"content":"x"},"finish_reason":"stop"}]}"#])
            .unwrap();
        let resp = parse_response_body(&body).unwrap();
        assert_eq!(resp.usage, bc_llm_client::Usage::default());
    }

    #[test]
    fn a_stream_that_never_reports_a_finish_reason_matches_the_non_streaming_fallback() {
        let body = assemble(&[r#"{"choices":[{"delta":{"content":"x"}}]}"#]).unwrap();
        assert_eq!(
            parse_response_body(&body).unwrap().stop_reason,
            StopReason::Other("missing".to_string())
        );
    }
}
