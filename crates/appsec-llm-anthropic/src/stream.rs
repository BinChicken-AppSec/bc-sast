use std::collections::BTreeMap;

use appsec_llm_client::LlmError;
use serde_json::{json, Value};

#[derive(Debug, Default)]
struct Block {
    kind: String,
    id: String,
    name: String,
    text: String,
    thinking: String,
    signature: String,
    data: String,
    partial_json: String,
    input: Option<Value>,
}

#[derive(Debug, Default)]
pub struct StreamAssembler {
    blocks: BTreeMap<i64, Block>,
    stop_reason: Option<String>,
    input_tokens: u64,
    output_tokens: u64,
    cache_creation_input_tokens: u64,
    cache_read_input_tokens: u64,
}

impl StreamAssembler {
    pub fn push(&mut self, payload: &str) -> Result<(), LlmError> {
        let payload = payload.trim();
        if payload.is_empty() {
            return Ok(());
        }
        let Ok(event) = serde_json::from_str::<Value>(payload) else {
            return Ok(());
        };
        let index = event["index"].as_i64().unwrap_or(0);
        match event["type"].as_str().unwrap_or_default() {
            "error" => return Err(crate::response::classify_stream_error(&event["error"])),
            "message_start" => self.read_usage(&event["message"]["usage"], false),
            "content_block_start" => {
                let block = self.blocks.entry(index).or_default();
                let start = &event["content_block"];
                block.kind = start["type"].as_str().unwrap_or_default().to_string();
                block.id = start["id"].as_str().unwrap_or_default().to_string();
                block.name = start["name"].as_str().unwrap_or_default().to_string();
                block
                    .text
                    .push_str(start["text"].as_str().unwrap_or_default());
                block
                    .thinking
                    .push_str(start["thinking"].as_str().unwrap_or_default());
                block
                    .signature
                    .push_str(start["signature"].as_str().unwrap_or_default());
                block
                    .data
                    .push_str(start["data"].as_str().unwrap_or_default());
            }
            "content_block_delta" => {
                let block = self.blocks.entry(index).or_default();
                let delta = &event["delta"];
                match delta["type"].as_str().unwrap_or_default() {
                    "text_delta" => block
                        .text
                        .push_str(delta["text"].as_str().unwrap_or_default()),
                    "input_json_delta" => block
                        .partial_json
                        .push_str(delta["partial_json"].as_str().unwrap_or_default()),
                    "thinking_delta" => block
                        .thinking
                        .push_str(delta["thinking"].as_str().unwrap_or_default()),
                    "signature_delta" => block
                        .signature
                        .push_str(delta["signature"].as_str().unwrap_or_default()),
                    _ => {}
                }
            }
            "content_block_stop" => self.close_block(index),
            "message_delta" => {
                if let Some(reason) = event["delta"]["stop_reason"].as_str() {
                    self.stop_reason = Some(reason.to_string());
                }
                self.read_usage(&event["usage"], true);
            }
            _ => {}
        }
        Ok(())
    }

    fn read_usage(&mut self, usage: &Value, output_only: bool) {
        if let Some(n) = usage["output_tokens"].as_u64() {
            self.output_tokens = n;
        }
        if output_only {
            return;
        }
        self.input_tokens = usage["input_tokens"].as_u64().unwrap_or(0);
        self.cache_creation_input_tokens =
            usage["cache_creation_input_tokens"].as_u64().unwrap_or(0);
        self.cache_read_input_tokens = usage["cache_read_input_tokens"].as_u64().unwrap_or(0);
    }

    fn close_block(&mut self, index: i64) {
        let Some(block) = self.blocks.get_mut(&index) else {
            return;
        };
        if block.kind != "tool_use" || block.input.is_some() {
            return;
        }
        block.input = Some(if block.partial_json.trim().is_empty() {
            json!({})
        } else {
            serde_json::from_str(&block.partial_json).unwrap_or_else(|_| json!({}))
        });
    }

    pub fn finish(mut self) -> Value {
        let indices: Vec<i64> = self.blocks.keys().copied().collect();
        for index in indices {
            self.close_block(index);
        }
        let content: Vec<Value> = self
            .blocks
            .into_values()
            .map(|b| match b.kind.as_str() {
                "tool_use" => json!({
                    "type": "tool_use",
                    "id": b.id,
                    "name": b.name,
                    "input": b.input.expect("every tool_use block was closed above"),
                }),
                "thinking" => json!({
                    "type": "thinking",
                    "thinking": b.thinking,
                    "signature": b.signature,
                }),
                "redacted_thinking" => json!({"type": "redacted_thinking", "data": b.data}),
                kind => json!({"type": kind, "text": b.text}),
            })
            .collect();
        json!({
            "content": content,
            "stop_reason": self.stop_reason,
            "usage": {
                "input_tokens": self.input_tokens,
                "output_tokens": self.output_tokens,
                "cache_creation_input_tokens": self.cache_creation_input_tokens,
                "cache_read_input_tokens": self.cache_read_input_tokens,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::response::parse_response_body;
    use appsec_llm_client::StopReason;

    fn assemble(payloads: &[&str]) -> Result<Value, LlmError> {
        let mut a = StreamAssembler::default();
        for p in payloads {
            a.push(p)?;
        }
        Ok(a.finish())
    }

    fn text_stream(chunks: &[&str]) -> Vec<String> {
        let mut events = vec![
            r#"{"type":"message_start","message":{"usage":{"input_tokens":10,"output_tokens":1,"cache_read_input_tokens":4}}}"#.to_string(),
            r#"{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}"#.to_string(),
        ];
        events.extend(chunks.iter().map(|c| {
            format!(
                r#"{{"type":"content_block_delta","index":0,"delta":{{"type":"text_delta","text":"{c}"}}}}"#
            )
        }));
        events.push(r#"{"type":"content_block_stop","index":0}"#.to_string());
        events.push(
            r#"{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":7}}"#
                .to_string(),
        );
        events.push(r#"{"type":"message_stop"}"#.to_string());
        events
    }

    fn assemble_all(events: &[String]) -> Value {
        let refs: Vec<&str> = events.iter().map(String::as_str).collect();
        assemble(&refs).unwrap()
    }

    #[test]
    fn text_deltas_concatenate_and_usage_comes_from_both_ends() {
        let body = assemble_all(&text_stream(&["Hello, ", "world"]));
        let resp = parse_response_body(&body).unwrap();
        assert_eq!(resp.text(), "Hello, world");
        assert_eq!(resp.stop_reason, StopReason::EndTurn);
        assert_eq!(resp.usage.input_tokens, 10);
        assert_eq!(resp.usage.cache_read_input_tokens, 4);
        assert_eq!(resp.usage.output_tokens, 7);
    }

    #[test]
    fn the_assembled_response_equals_the_non_streamed_one() {
        let streamed = parse_response_body(&assemble_all(&text_stream(&["hi ", "there"]))).unwrap();
        let whole = parse_response_body(&json!({
            "content": [{"type": "text", "text": "hi there"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 10, "output_tokens": 7,
                      "cache_creation_input_tokens": 0, "cache_read_input_tokens": 4},
        }))
        .unwrap();
        assert_eq!(streamed, whole);
    }

    #[test]
    fn a_tool_call_parses_its_partial_json_at_content_block_stop() {
        let body = assemble(&[
            r#"{"type":"message_start","message":{"usage":{"input_tokens":3}}}"#,
            r#"{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_1","name":"Read","input":{}}}"#,
            r#"{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"path\""}}"#,
            r#"{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":":\"a.rs\"}"}}"#,
            r#"{"type":"content_block_stop","index":0}"#,
            r#"{"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":12}}"#,
            r#"{"type":"message_stop"}"#,
        ])
        .unwrap();
        let resp = parse_response_body(&body).unwrap();
        assert_eq!(resp.stop_reason, StopReason::ToolUse);
        let calls = resp.tool_uses();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "toolu_1");
        assert_eq!(calls[0].1, "Read");
        assert_eq!(calls[0].2, &json!({"path": "a.rs"}));
    }

    #[test]
    fn text_and_a_tool_call_come_back_in_block_index_order() {
        let body = assemble(&[
            r#"{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}"#,
            r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"looking it up"}}"#,
            r#"{"type":"content_block_stop","index":0}"#,
            r#"{"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"t","name":"Glob"}}"#,
            r#"{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{}"}}"#,
            r#"{"type":"content_block_stop","index":1}"#,
            r#"{"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":2}}"#,
        ])
        .unwrap();
        let resp = parse_response_body(&body).unwrap();
        assert_eq!(resp.text(), "looking it up");
        assert_eq!(resp.tool_uses()[0].1, "Glob");
    }

    #[test]
    fn a_tool_call_with_no_arguments_gets_an_empty_object() {
        let body = assemble(&[
            r#"{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"t","name":"Ls"}}"#,
            r#"{"type":"content_block_stop","index":0}"#,
            r#"{"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":1}}"#,
        ])
        .unwrap();
        assert_eq!(
            parse_response_body(&body).unwrap().tool_uses()[0].2,
            &json!({})
        );
    }

    #[test]
    fn a_tool_block_never_closed_by_the_stream_is_closed_at_finish() {
        let body = assemble(&[
            r#"{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"t","name":"Read"}}"#,
            r#"{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"path\":\"a.rs\"}"}}"#,
        ])
        .unwrap();
        assert_eq!(
            parse_response_body(&body).unwrap().tool_uses()[0].2,
            &json!({"path": "a.rs"})
        );
    }

    #[test]
    fn tool_arguments_that_never_completed_become_an_empty_object() {
        let body = assemble(&[
            r#"{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"t","name":"Read"}}"#,
            r#"{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"path\":"}}"#,
            r#"{"type":"content_block_stop","index":0}"#,
        ])
        .unwrap();
        assert_eq!(
            parse_response_body(&body).unwrap().tool_uses()[0].2,
            &json!({})
        );
    }

    #[test]
    fn thinking_and_its_signature_are_reassembled_for_replay() {
        let body = assemble(&[
            r#"{"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":"","signature":""}}"#,
            r#"{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"hm"}}"#,
            r#"{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"m"}}"#,
            r#"{"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"sig=="}}"#,
            r#"{"type":"content_block_delta","index":0,"delta":{"type":"citations_delta_from_the_future"}}"#,
            r#"{"type":"content_block_stop","index":0}"#,
            r#"{"type":"content_block_start","index":1,"content_block":{"type":"redacted_thinking","data":"cipher"}}"#,
            r#"{"type":"content_block_stop","index":1}"#,
            r#"{"type":"content_block_start","index":2,"content_block":{"type":"mystery"}}"#,
            r#"{"type":"content_block_start","index":3,"content_block":{"type":"text","text":"answer"}}"#,
            r#"{"type":"content_block_stop","index":3}"#,
            r#"{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":1}}"#,
        ])
        .unwrap();
        assert_eq!(
            body["content"][0],
            json!({"type": "thinking", "thinking": "hmm", "signature": "sig=="})
        );
        assert_eq!(
            body["content"][1],
            json!({"type": "redacted_thinking", "data": "cipher"})
        );
        let resp = parse_response_body(&body).unwrap();
        assert_eq!(resp.text(), "answer");
        assert_eq!(resp.content.len(), 3, "two opaque blocks and the answer");
    }

    #[test]
    fn a_mid_stream_error_event_aborts_with_a_classified_error() {
        let mut a = StreamAssembler::default();
        a.push(r#"{"type":"content_block_start","index":0,"content_block":{"type":"text","text":"part"}}"#)
            .unwrap();
        let err = a
            .push(r#"{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}"#)
            .unwrap_err();
        assert!(
            matches!(err, LlmError::ServerError { status: 529, .. }),
            "{err:?}"
        );
    }

    #[test]
    fn a_mid_stream_rate_limit_error_is_retryable_as_such() {
        let mut a = StreamAssembler::default();
        let err = a
            .push(r#"{"type":"error","error":{"type":"rate_limit_error","message":"slow down"}}"#)
            .unwrap_err();
        assert_eq!(
            err,
            LlmError::RateLimited {
                retry_after_secs: None
            }
        );
    }

    #[test]
    fn ping_and_unparseable_events_are_skipped() {
        let body = assemble(&[
            r#"{"type":"ping"}"#,
            "not json at all",
            r#"{"type":"some_future_event"}"#,
            r#"{"type":"content_block_start","index":0,"content_block":{"type":"text","text":"still here"}}"#,
            r#"{"type":"content_block_stop","index":0}"#,
            r#"{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":1}}"#,
            "",
        ])
        .unwrap();
        assert_eq!(parse_response_body(&body).unwrap().text(), "still here");
    }

    #[test]
    fn a_delta_for_a_block_that_was_never_opened_still_accumulates() {
        let body = assemble(&[
            r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"orphan"}}"#,
        ])
        .unwrap();
        assert_eq!(body["content"][0]["text"], "orphan");
        assert_eq!(body["content"][0]["type"], "");
    }

    #[test]
    fn a_close_for_a_block_that_does_not_exist_is_ignored() {
        let mut a = StreamAssembler::default();
        a.push(r#"{"type":"content_block_stop","index":9}"#)
            .unwrap();
        assert_eq!(a.finish()["content"], json!([]));
    }

    #[test]
    fn a_stream_with_no_message_delta_reports_a_missing_stop_reason() {
        let body = assemble(&[
            r#"{"type":"content_block_start","index":0,"content_block":{"type":"text","text":"x"}}"#,
        ])
        .unwrap();
        assert_eq!(
            parse_response_body(&body).unwrap().stop_reason,
            StopReason::Other("missing".to_string())
        );
    }

    #[test]
    fn a_streamed_guardrail_refusal_is_still_detected() {
        let body = assemble(&[
            r#"{"type":"content_block_start","index":0,"content_block":{"type":"text","text":"Your request was not allowed"}}"#,
            r#"{"type":"content_block_stop","index":0}"#,
            r#"{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":5}}"#,
        ])
        .unwrap();
        assert!(matches!(
            parse_response_body(&body).unwrap_err(),
            LlmError::GuardrailBlocked { .. }
        ));
    }
}
