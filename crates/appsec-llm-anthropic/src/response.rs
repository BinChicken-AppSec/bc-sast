use std::sync::LazyLock;

use appsec_llm_client::{
    sanitize_error_body, ChatResponse, ContentBlock, LlmError, OpaqueDialect, StopReason, Usage,
};
use regex::Regex;
use serde_json::Value;

static CTX_OVERFLOW_RX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)context.?length|context length|exceed.*(?:token|limit)|too long").unwrap()
});

static QUOTA_RX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)credit balance|insufficient credit|billing").unwrap());

const GUARDRAIL_REFUSAL: &str = "Your request was not allowed";

pub fn parse_response_body(body: &Value) -> Result<ChatResponse, LlmError> {
    let blocks = body["content"].as_array().ok_or_else(|| LlmError::Other {
        message: "response has no content".to_string(),
    })?;

    let mut content = Vec::new();
    for block in blocks {
        match block["type"].as_str() {
            Some("text") => {
                if let Some(text) = block["text"].as_str() {
                    if !text.is_empty() {
                        content.push(ContentBlock::text(text));
                    }
                }
            }
            Some("tool_use") => content.push(ContentBlock::ToolUse {
                id: block["id"].as_str().unwrap_or_default().to_string(),
                name: block["name"].as_str().unwrap_or_default().to_string(),
                input: block["input"].clone(),
            }),
            Some("thinking") | Some("redacted_thinking") => content.push(ContentBlock::Opaque {
                dialect: OpaqueDialect::Anthropic,
                payload: block.clone(),
            }),
            _ => {}
        }
    }

    if body["stop_reason"] == "refusal" {
        return Err(LlmError::GuardrailBlocked {
            message: "the model declined to answer (stop_reason=refusal)".to_string(),
        });
    }

    let stop_reason = match body["stop_reason"].as_str() {
        Some("tool_use") => StopReason::ToolUse,
        Some("max_tokens") => StopReason::MaxTokens,
        Some("end_turn") | Some("stop_sequence") => StopReason::EndTurn,
        Some(other) => StopReason::Other(other.to_string()),
        None => StopReason::Other("missing".to_string()),
    };

    if stop_reason == StopReason::EndTurn {
        let text: String = content
            .iter()
            .filter_map(|b| match b {
                ContentBlock::Text(t) => Some(t.as_str()),
                _ => None,
            })
            .collect();
        if text.trim() == GUARDRAIL_REFUSAL {
            return Err(LlmError::GuardrailBlocked {
                message: format!(
                    "org content-guardrail blocked this prompt (result={GUARDRAIL_REFUSAL:?}). \
                     The classifier on api.anthropic.com is rejecting the prompt content — \
                     this is NOT a pipeline bug."
                ),
            });
        }
    }

    Ok(ChatResponse {
        content,
        stop_reason,
        usage: parse_usage(&body["usage"]),
    })
}

fn parse_usage(usage: &Value) -> Usage {
    if usage.is_null() {
        return Usage::default();
    }
    Usage {
        input_tokens: usage["input_tokens"].as_u64().unwrap_or(0),
        output_tokens: usage["output_tokens"].as_u64().unwrap_or(0),
        cache_creation_input_tokens: cache_creation_tokens(usage),
        cache_read_input_tokens: usage["cache_read_input_tokens"].as_u64().unwrap_or(0),
        reasoning_output_tokens: 0,
    }
}

pub fn cache_creation_tokens(usage: &Value) -> u64 {
    usage["cache_creation_input_tokens"]
        .as_u64()
        .unwrap_or_else(|| {
            let split = &usage["cache_creation"];
            split["ephemeral_5m_input_tokens"].as_u64().unwrap_or(0)
                + split["ephemeral_1h_input_tokens"].as_u64().unwrap_or(0)
        })
}

pub fn classify_http_error(status: u16, body: &str, retry_after_secs: Option<u64>) -> LlmError {
    if let Some(halting) = appsec_llm_client::classify_auth_or_proxy_status(status, body) {
        return halting;
    }
    if status == 429 {
        return LlmError::RateLimited { retry_after_secs };
    }
    if status == 400 && QUOTA_RX.is_match(body) {
        return LlmError::QuotaExhausted {
            message: sanitize_error_body(body),
        };
    }
    if CTX_OVERFLOW_RX.is_match(body) {
        return LlmError::ContextOverflow {
            message: sanitize_error_body(body),
        };
    }
    match status {
        500..=599 => LlmError::ServerError {
            status,
            message: sanitize_error_body(body),
        },
        400..=499 => LlmError::InvalidRequest {
            message: sanitize_error_body(body),
        },
        _ => LlmError::Other {
            message: format!("unexpected status {status}: {}", sanitize_error_body(body)),
        },
    }
}

pub fn classify_stream_error(error: &Value) -> LlmError {
    let status = match error["type"].as_str().unwrap_or_default() {
        "overloaded_error" => 529,
        "rate_limit_error" => 429,
        "invalid_request_error" => 400,
        "authentication_error" => 401,
        "permission_error" => 403,
        "not_found_error" => 404,
        "request_too_large" => 413,
        _ => 500,
    };
    classify_http_error(status, &error.to_string(), None)
}

pub fn parse_retry_after(headers: &reqwest::header::HeaderMap) -> Option<u64> {
    headers
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn classify_stream_error_maps_every_error_type_to_its_http_equivalent() {
        let of = |kind: &str| classify_stream_error(&json!({"type": kind, "message": "boom"}));
        assert!(matches!(
            of("overloaded_error"),
            LlmError::ServerError { status: 529, .. }
        ));
        assert!(matches!(
            of("api_error"),
            LlmError::ServerError { status: 500, .. }
        ));
        assert_eq!(
            of("rate_limit_error"),
            LlmError::RateLimited {
                retry_after_secs: None
            }
        );
        assert!(matches!(
            of("authentication_error"),
            LlmError::Authentication {
                status: Some(401),
                ..
            }
        ));
        for kind in [
            "invalid_request_error",
            "permission_error",
            "not_found_error",
            "request_too_large",
        ] {
            assert!(
                matches!(of(kind), LlmError::InvalidRequest { .. }),
                "{kind} must be a 4xx-shaped, non-retryable error"
            );
        }
        assert!(matches!(
            of("some_future_error"),
            LlmError::ServerError { status: 500, .. }
        ));
        assert!(matches!(
            classify_stream_error(&json!({"message": "no type at all"})),
            LlmError::ServerError { status: 500, .. }
        ));
    }

    #[test]
    fn classify_stream_error_still_detects_a_context_overflow() {
        let err = classify_stream_error(&json!({
            "type": "invalid_request_error",
            "message": "prompt is too long: 300000 tokens > context length",
        }));
        assert!(matches!(err, LlmError::ContextOverflow { .. }), "{err:?}");
    }

    #[test]
    fn parses_text_only_response() {
        let body = json!({
            "content": [{"type": "text", "text": "hi there"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 10, "output_tokens": 5},
        });
        let resp = parse_response_body(&body).unwrap();
        assert_eq!(resp.text(), "hi there");
        assert_eq!(resp.stop_reason, StopReason::EndTurn);
        assert_eq!(resp.usage.input_tokens, 10);
        assert_eq!(resp.usage.output_tokens, 5);
    }

    #[test]
    fn parses_tool_use_response() {
        let body = json!({
            "content": [
                {"type": "text", "text": "checking"},
                {"type": "tool_use", "id": "call_1", "name": "Read", "input": {"path": "a.rs"}},
            ],
            "stop_reason": "tool_use",
            "usage": {
                "input_tokens": 20, "output_tokens": 8,
                "cache_creation_input_tokens": 3, "cache_read_input_tokens": 4,
            },
        });
        let resp = parse_response_body(&body).unwrap();
        assert_eq!(resp.text(), "checking");
        assert_eq!(resp.stop_reason, StopReason::ToolUse);
        let calls = resp.tool_uses();
        assert_eq!(calls, vec![("call_1", "Read", &json!({"path": "a.rs"}))]);
        assert_eq!(resp.usage.cache_creation_input_tokens, 3);
        assert_eq!(resp.usage.cache_read_input_tokens, 4);
    }

    #[test]
    fn thinking_blocks_are_kept_verbatim_and_unknown_blocks_skipped() {
        let thinking = json!({"type": "thinking", "thinking": "reasoning...", "signature": "s=="});
        let redacted = json!({"type": "redacted_thinking", "data": "cipher"});
        let body = json!({
            "content": [
                thinking,
                redacted,
                {"type": "server_tool_use_from_the_future"},
                {"type": "text", "text": "answer"},
            ],
            "stop_reason": "end_turn",
        });
        let resp = parse_response_body(&body).unwrap();
        assert_eq!(resp.text(), "answer");
        assert_eq!(
            resp.content,
            vec![
                ContentBlock::Opaque {
                    dialect: OpaqueDialect::Anthropic,
                    payload: thinking,
                },
                ContentBlock::Opaque {
                    dialect: OpaqueDialect::Anthropic,
                    payload: redacted,
                },
                ContentBlock::text("answer"),
            ]
        );
    }

    #[test]
    fn a_refusal_stop_reason_is_a_guardrail_block() {
        let body = json!({
            "content": [{"type": "text", "text": "I started to"}],
            "stop_reason": "refusal",
        });
        assert!(matches!(
            parse_response_body(&body).unwrap_err(),
            LlmError::GuardrailBlocked { .. }
        ));
    }

    #[test]
    fn cache_writes_fall_back_to_the_per_lifetime_split() {
        assert_eq!(
            cache_creation_tokens(&json!({
                "cache_creation_input_tokens": 10,
                "cache_creation": {"ephemeral_5m_input_tokens": 99},
            })),
            10
        );
        assert_eq!(
            cache_creation_tokens(&json!({
                "cache_creation": {"ephemeral_5m_input_tokens": 3, "ephemeral_1h_input_tokens": 4},
            })),
            7
        );
        assert_eq!(cache_creation_tokens(&json!({})), 0);
    }

    #[test]
    fn stop_sequence_maps_to_end_turn() {
        let body =
            json!({"content": [{"type": "text", "text": "x"}], "stop_reason": "stop_sequence"});
        let resp = parse_response_body(&body).unwrap();
        assert_eq!(resp.stop_reason, StopReason::EndTurn);
    }

    #[test]
    fn max_tokens_stop_reason_is_preserved() {
        let body = json!({"content": [{"type": "text", "text": "x"}], "stop_reason": "max_tokens"});
        let resp = parse_response_body(&body).unwrap();
        assert_eq!(resp.stop_reason, StopReason::MaxTokens);
    }

    #[test]
    fn unrecognized_stop_reason_is_preserved_as_other() {
        let body = json!({"content": [{"type": "text", "text": "x"}], "stop_reason": "pause_turn"});
        let resp = parse_response_body(&body).unwrap();
        assert_eq!(
            resp.stop_reason,
            StopReason::Other("pause_turn".to_string())
        );
    }

    #[test]
    fn missing_stop_reason_is_other_missing() {
        let body = json!({"content": [{"type": "text", "text": "x"}]});
        let resp = parse_response_body(&body).unwrap();
        assert_eq!(resp.stop_reason, StopReason::Other("missing".to_string()));
    }

    #[test]
    fn a_canned_guardrail_refusal_on_end_turn_is_a_guardrail_blocked_error() {
        let body = json!({
            "content": [{"type": "text", "text": "Your request was not allowed"}],
            "stop_reason": "end_turn",
        });
        let err = parse_response_body(&body).unwrap_err();
        assert!(matches!(err, LlmError::GuardrailBlocked { .. }));
    }

    #[test]
    fn the_guardrail_refusal_string_with_surrounding_whitespace_still_matches() {
        let body = json!({
            "content": [{"type": "text", "text": "  Your request was not allowed\n"}],
            "stop_reason": "end_turn",
        });
        let err = parse_response_body(&body).unwrap_err();
        assert!(matches!(err, LlmError::GuardrailBlocked { .. }));
    }

    #[test]
    fn a_short_legitimate_reply_is_not_mistaken_for_a_guardrail_refusal() {
        let body = json!({
            "content": [{"type": "text", "text": "Your request was not allowed here"}],
            "stop_reason": "end_turn",
        });
        let resp = parse_response_body(&body).unwrap();
        assert_eq!(resp.text(), "Your request was not allowed here");
    }

    #[test]
    fn the_refusal_string_is_not_flagged_when_truncated_by_tool_use() {
        let body = json!({
            "content": [
                {"type": "text", "text": "Your request was not allowed"},
                {"type": "tool_use", "id": "call_1", "name": "Read", "input": {}},
            ],
            "stop_reason": "tool_use",
        });
        let resp = parse_response_body(&body).unwrap();
        assert_eq!(resp.stop_reason, StopReason::ToolUse);
    }

    #[test]
    fn a_tool_use_block_alongside_end_turn_is_ignored_by_the_refusal_check() {
        let body = json!({
            "content": [
                {"type": "text", "text": "ok"},
                {"type": "tool_use", "id": "call_1", "name": "Read", "input": {}},
            ],
            "stop_reason": "end_turn",
        });
        let resp = parse_response_body(&body).unwrap();
        assert_eq!(resp.text(), "ok");
    }

    #[test]
    fn the_refusal_string_is_not_flagged_when_truncated_by_max_tokens() {
        let body = json!({
            "content": [{"type": "text", "text": "Your request was not allowed"}],
            "stop_reason": "max_tokens",
        });
        let resp = parse_response_body(&body).unwrap();
        assert_eq!(resp.stop_reason, StopReason::MaxTokens);
    }

    #[test]
    fn missing_content_field_is_an_error() {
        let err = parse_response_body(&json!({})).unwrap_err();
        assert!(matches!(err, LlmError::Other { .. }));
    }

    #[test]
    fn missing_usage_defaults_to_zero() {
        let body = json!({"content": [{"type": "text", "text": "x"}], "stop_reason": "end_turn"});
        let resp = parse_response_body(&body).unwrap();
        assert_eq!(resp.usage, Usage::default());
    }

    #[test]
    fn empty_text_block_produces_no_text_content() {
        let body = json!({"content": [{"type": "text", "text": ""}], "stop_reason": "end_turn"});
        let resp = parse_response_body(&body).unwrap();
        assert_eq!(resp.text(), "");
    }

    #[test]
    fn a_text_block_missing_its_text_field_produces_no_text_content() {
        let body = json!({"content": [{"type": "text"}], "stop_reason": "end_turn"});
        let resp = parse_response_body(&body).unwrap();
        assert_eq!(resp.text(), "");
    }

    #[test]
    fn classify_http_error_429_is_rate_limited() {
        assert_eq!(
            classify_http_error(429, "slow down", None),
            LlmError::RateLimited {
                retry_after_secs: None
            }
        );
    }

    #[test]
    fn classify_http_error_429_carries_the_retry_after_value_through() {
        assert_eq!(
            classify_http_error(429, "slow down", Some(30)),
            LlmError::RateLimited {
                retry_after_secs: Some(30)
            }
        );
    }

    #[test]
    fn classify_http_error_400_naming_the_credit_balance_is_quota_exhausted() {
        for message in [
            "Your credit balance is too low to access the Claude API. \
             Please go to Plans & Billing to upgrade or purchase credits.",
            "insufficient credit for this request",
            "a billing problem prevents this request",
        ] {
            let body = json!({"type": "error", "error":
                {"type": "invalid_request_error", "message": message}})
            .to_string();
            let err = classify_http_error(400, &body, None);
            assert_eq!(
                err,
                LlmError::QuotaExhausted {
                    message: appsec_llm_client::sanitize_error_body(&body),
                },
                "{message}"
            );
            assert!(!err.is_retryable(), "{message}");
        }
    }

    #[test]
    fn a_429_stays_rate_limited_even_when_the_body_mentions_billing() {
        let err = classify_http_error(429, "rate limited; see billing for tiers", Some(5));
        assert_eq!(
            err,
            LlmError::RateLimited {
                retry_after_secs: Some(5)
            }
        );
        assert!(err.is_retryable());
    }

    #[test]
    fn a_throttle_body_that_reads_like_an_overflow_is_still_a_rate_limit() {
        let body = r#"{"type":"rate_limit_error","message":"Number of request tokens has
                     exceeded your per-minute rate limit"}"#;
        assert!(CTX_OVERFLOW_RX.is_match(body), "premise of this test");
        let err = classify_http_error(429, body, None);
        assert_eq!(
            err,
            LlmError::RateLimited {
                retry_after_secs: None
            }
        );
        assert!(err.is_retryable());
    }

    #[test]
    fn a_400_without_billing_wording_is_still_an_invalid_request() {
        assert!(matches!(
            classify_http_error(400, r#"{"error":{"message":"unexpected role"}}"#, None),
            LlmError::InvalidRequest { .. }
        ));
    }

    #[test]
    fn classify_stream_error_maps_a_billing_message_to_quota_exhausted() {
        let err = classify_stream_error(&json!({
            "type": "invalid_request_error",
            "message": "Your credit balance is too low to access the Claude API",
        }));
        assert!(matches!(err, LlmError::QuotaExhausted { .. }), "{err:?}");
    }

    #[test]
    fn classify_http_error_529_overloaded_is_server_error() {
        assert_eq!(
            classify_http_error(529, "overloaded", None),
            LlmError::ServerError {
                status: 529,
                message: "overloaded".to_string()
            }
        );
    }

    #[test]
    fn classify_http_error_other_4xx_is_invalid_request() {
        assert_eq!(
            classify_http_error(400, "bad field", None),
            LlmError::InvalidRequest {
                message: "bad field".to_string()
            }
        );
    }

    #[test]
    fn classify_http_error_detects_context_overflow_regardless_of_status() {
        assert_eq!(
            classify_http_error(400, "prompt is too long for this model", None),
            LlmError::ContextOverflow {
                message: "prompt is too long for this model".to_string()
            }
        );
    }

    #[test]
    fn classify_http_error_unexpected_status_is_other() {
        assert_eq!(
            classify_http_error(200, "weird", None),
            LlmError::Other {
                message: "unexpected status 200: weird".to_string()
            }
        );
    }

    #[test]
    fn classify_http_error_scrubs_a_reflected_credential_out_of_the_body() {
        let raw =
            r#"{"error":{"message":"bad key: Authorization: Bearer sk-live-abcd1234efgh5678"}}"#;
        let err = classify_http_error(400, raw, None);
        assert_eq!(
            err,
            LlmError::InvalidRequest {
                message: appsec_llm_client::sanitize_error_body(raw),
            }
        );
        assert!(
            !err.to_string().contains("sk-live-abcd1234efgh5678"),
            "token survived: {err}"
        );
    }

    #[test]
    fn classify_http_error_401_is_authentication_and_407_is_proxy() {
        let raw = r#"{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}"#;
        let err = classify_http_error(401, raw, None);
        assert_eq!(
            err,
            LlmError::Authentication {
                status: Some(401),
                message: raw.to_string(),
            }
        );
        assert!(err.halts_scan());
        assert_eq!(
            classify_http_error(407, "Proxy Authentication Required", None),
            LlmError::ProxyOrTls {
                status: Some(407),
                message: "Proxy Authentication Required".to_string(),
            }
        );
    }

    #[test]
    fn classify_http_error_caps_an_oversized_body() {
        let body = "z".repeat(appsec_llm_client::MAX_ERROR_BODY_CHARS + 100);
        let err = classify_http_error(529, &body, None);
        assert_eq!(
            err,
            LlmError::ServerError {
                status: 529,
                message: appsec_llm_client::sanitize_error_body(&body),
            }
        );
        assert!(err.to_string().ends_with("… [truncated]"));
    }

    #[test]
    fn parse_retry_after_reads_an_integer_seconds_header() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::RETRY_AFTER,
            reqwest::header::HeaderValue::from_static("30"),
        );
        assert_eq!(parse_retry_after(&headers), Some(30));
    }

    #[test]
    fn parse_retry_after_is_none_when_the_header_is_absent() {
        assert_eq!(parse_retry_after(&reqwest::header::HeaderMap::new()), None);
    }

    #[test]
    fn parse_retry_after_is_none_for_a_non_integer_value() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::RETRY_AFTER,
            reqwest::header::HeaderValue::from_static("Wed, 21 Oct 2026 07:28:00 GMT"),
        );
        assert_eq!(parse_retry_after(&headers), None);
    }
}
