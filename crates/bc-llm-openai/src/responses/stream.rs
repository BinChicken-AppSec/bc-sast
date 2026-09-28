//! Reassembles a streamed Responses API call into the non-streamed
//! response document, for the same reason `crate::chat::stream` does:
//! one parser per shape, so the two modes cannot drift.
//!
//! This shape makes it simpler than Chat Completions. The terminal
//! `response.completed` (or `response.incomplete`) event carries the
//! whole response object, usage included, so nothing needs stitching
//! from deltas; the deltas (`response.output_text.delta` and friends) are
//! ignored. As a fallback for a gateway that forwards the terminal event
//! without its `output`, every finished item (`response.output_item.done`)
//! is collected and used in its place.

use std::collections::BTreeMap;

use bc_llm_client::LlmError;
use serde_json::{json, Value};

use crate::errors::classify_stream_error;

/// Accumulates `data:` payloads from a Responses API stream.
#[derive(Debug, Default)]
pub struct StreamAssembler {
    /// The terminal event's `response` object, once seen.
    terminal: Option<Value>,
    /// Finished output items keyed by `output_index`, in model order.
    items: BTreeMap<u64, Value>,
}

impl StreamAssembler {
    /// Consume one SSE payload. `Err` only for a failure the provider
    /// reported (`response.failed`, or an `error` event); anything
    /// unparseable or unrecognized is skipped.
    pub fn push(&mut self, payload: &str) -> Result<(), LlmError> {
        let Ok(event) = serde_json::from_str::<Value>(payload.trim()) else {
            return Ok(());
        };
        match event["type"].as_str().unwrap_or_default() {
            "response.completed" | "response.incomplete" => {
                self.terminal = Some(event["response"].clone());
            }
            "response.failed" => {
                return Err(classify_stream_error(&event["response"]["error"]));
            }
            // The error event carries `code`/`message` at the top level.
            "error" => return Err(classify_stream_error(&event)),
            "response.output_item.done" => {
                let index = event["output_index"]
                    .as_u64()
                    .unwrap_or(self.items.len() as u64);
                self.items.insert(index, event["item"].clone());
            }
            _ => {}
        }
        Ok(())
    }

    /// The response document this stream amounted to.
    ///
    /// A stream that ended with no terminal event but with finished
    /// items is reported `incomplete` (reason `stream_ended`), so a
    /// truncated answer is never mistaken for a whole one. A stream with
    /// neither is an empty object with no `output`, which is what an
    /// endpoint that does not speak this protocol produces, and which the
    /// client treats as a shape rejection.
    pub fn finish(self) -> Value {
        let collected = || Value::Array(self.items.values().cloned().collect());
        match self.terminal {
            Some(mut body) => {
                let lacks_output = body["output"].as_array().is_none_or(Vec::is_empty);
                if lacks_output && !self.items.is_empty() {
                    body["output"] = collected();
                }
                body
            }
            None if !self.items.is_empty() => json!({
                "status": "incomplete",
                "incomplete_details": {"reason": "stream_ended"},
                "output": collected(),
            }),
            None => json!({}),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::responses::response::{has_output, parse_response_body};
    use bc_llm_client::StopReason;

    fn assemble(payloads: &[&str]) -> Result<Value, LlmError> {
        let mut a = StreamAssembler::default();
        for p in payloads {
            a.push(p)?;
        }
        Ok(a.finish())
    }

    #[test]
    fn the_completed_event_is_the_whole_response() {
        let body = assemble(&[
            r#"{"type":"response.created","response":{"status":"in_progress"}}"#,
            r#"{"type":"response.output_text.delta","delta":"hel"}"#,
            "not json",
            r#"{"type":"response.completed","response":{"status":"completed","output":[{"type":"message","content":[{"type":"output_text","text":"hello"}]}],"usage":{"input_tokens":5,"output_tokens":1}}}"#,
        ])
        .unwrap();
        let resp = parse_response_body(&body).unwrap();
        assert_eq!(resp.text(), "hello");
        assert_eq!(resp.usage.input_tokens, 5);
    }

    #[test]
    fn a_terminal_event_without_output_is_filled_from_finished_items() {
        let body = assemble(&[
            r#"{"type":"response.output_item.done","output_index":1,"item":{"type":"function_call","call_id":"c","name":"Read","arguments":"{}"}}"#,
            r#"{"type":"response.output_item.done","output_index":0,"item":{"type":"reasoning","encrypted_content":"e"}}"#,
            r#"{"type":"response.incomplete","response":{"status":"incomplete","incomplete_details":{"reason":"max_output_tokens"}}}"#,
        ])
        .unwrap();
        assert_eq!(body["output"][0]["type"], "reasoning");
        assert_eq!(body["output"][1]["type"], "function_call");
        let resp = parse_response_body(&body).unwrap();
        assert_eq!(resp.stop_reason, StopReason::MaxTokens);
    }

    #[test]
    fn a_terminal_event_with_output_wins_over_collected_items() {
        let body = assemble(&[
            r#"{"type":"response.output_item.done","item":{"type":"message","content":[]}}"#,
            r#"{"type":"response.completed","response":{"output":[{"type":"message","content":[{"type":"output_text","text":"final"}]}]}}"#,
        ])
        .unwrap();
        assert_eq!(parse_response_body(&body).unwrap().text(), "final");
    }

    #[test]
    fn a_stream_cut_off_before_its_terminal_event_is_incomplete() {
        let body = assemble(&[
            r#"{"type":"response.output_item.done","item":{"type":"message","content":[{"type":"output_text","text":"half"}]}}"#,
        ])
        .unwrap();
        let resp = parse_response_body(&body).unwrap();
        assert_eq!(resp.stop_reason, StopReason::Other("stream_ended".into()));
        assert_eq!(resp.text(), "half");
    }

    #[test]
    fn an_empty_stream_has_no_output_at_all() {
        let body = assemble(&[]).unwrap();
        assert!(!has_output(&body));
    }

    #[test]
    fn failures_are_classified() {
        let failed = assemble(&[
            r#"{"type":"response.failed","response":{"status":"failed","error":{"code":"server_error","message":"boom"}}}"#,
        ])
        .unwrap_err();
        assert!(
            matches!(failed, LlmError::ServerError { status: 500, .. }),
            "{failed:?}"
        );
        let error =
            assemble(&[r#"{"type":"error","code":"rate_limit_exceeded","message":"slow"}"#])
                .unwrap_err();
        assert_eq!(
            error,
            LlmError::RateLimited {
                retry_after_secs: None
            }
        );
    }
}
