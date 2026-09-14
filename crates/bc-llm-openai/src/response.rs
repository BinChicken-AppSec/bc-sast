//! OpenAI chat-completions JSON response -> [`ChatResponse`], and HTTP
//! error-status -> [`LlmError`] classification, ported from
//! `backends/oai.py`'s response/usage handling and its
//! `_is_transient_status`/`_CTX_OVERFLOW_RX` error classification.

use std::sync::LazyLock;

use bc_llm_client::{sanitize_error_body, ChatResponse, ContentBlock, LlmError, StopReason, Usage};
use regex::Regex;
use serde_json::Value;

static CTX_OVERFLOW_RX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)context.?length|context length|exceed.*(?:token|limit)|too long").unwrap()
});

/// The 429 bodies that mean "the account is out of money", not "slow
/// down" — OpenAI's documented non-transient 429 error codes
/// (`developers.openai.com/api/docs/guides/error-codes`), plus the prose
/// each of them ships with, since a gateway in front of the API can
/// forward the message while rewriting or dropping the `code` field.
///
/// `spend_limit_exceeded`/`usage_limit_exceeded` are matched as suffixes
/// so the `organization_`/`project_`-scoped spellings of each are covered
/// by one alternative apiece.
static QUOTA_RX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?i)insufficient_quota|credit_balance_exhausted",
        r"|spend_limit_exceeded|usage_limit_exceeded",
        r"|exceeded your current quota",
        // Prose forms, for a gateway that forwards the message but not
        // the code.
        r"|spend limit|usage limit|billing hard limit",
    ))
    .unwrap()
});

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
        usage: parse_usage(&body["usage"]),
    })
}

fn parse_usage(usage: &Value) -> Usage {
    if usage.is_null() {
        return Usage::default();
    }
    let prompt = usage["prompt_tokens"].as_u64().unwrap_or(0);
    let cached = usage["prompt_tokens_details"]["cached_tokens"]
        .as_u64()
        .unwrap_or(0);
    Usage {
        input_tokens: prompt.saturating_sub(cached),
        output_tokens: usage["completion_tokens"].as_u64().unwrap_or(0),
        cache_creation_input_tokens: 0,
        cache_read_input_tokens: cached,
    }
}

/// Classify a non-2xx HTTP response into an [`LlmError`], mirroring
/// `_is_transient_status`'s status-code set and `_CTX_OVERFLOW_RX`'s
/// body-text detection (checked first: a 400 that names a context-window
/// overflow gets the more specific variant so `bc-llm-agentic` can react
/// by evicting history, rather than treating it as an ordinary bad
/// request). `retry_after_secs` — parsed by the caller from the response's
/// own `Retry-After` header, since only it has access to headers before
/// the body is consumed — is threaded straight into
/// [`LlmError::RateLimited`] on a 429, ignored otherwise.
///
/// The body is *matched* raw but *retained* through
/// [`bc_llm_client::sanitize_error_body`] — a gateway can reflect
/// credentials or prompt source into an error body that then travels into
/// a `StageError` and onto disk. See that helper's own docs.
///
/// **A 429 is decided entirely before the context-overflow check**, and
/// splits two ways: [`QUOTA_RX`] means the account is out of money
/// ([`LlmError::QuotaExhausted`], never retryable — OpenAI overloads this
/// one status for both "slow down" and "you have no credits"), and
/// everything else is an ordinary [`LlmError::RateLimited`].
///
/// Ordering matters because `CTX_OVERFLOW_RX` is a text heuristic that
/// both kinds of 429 body trip by accident: its `exceed.*limit` branch
/// matches `organization_spend_limit_exceeded` … "exceeded your
/// organization spend limit", and equally `rate_limit_exceeded` …
/// "Limit 30000, Used 29000". Reached in the old order, either one came
/// back as a `ContextOverflow` — which made a plain throttle
/// non-retryable and sent `bc-llm-agentic` off evicting history to fit a
/// context window that was never the problem. Neither provider signals a
/// context overflow with a 429 (it is a 400 in both dialects), so nothing
/// is lost by settling that status first.
pub fn classify_http_error(status: u16, body: &str, retry_after_secs: Option<u64>) -> LlmError {
    if status == 429 {
        return if QUOTA_RX.is_match(body) {
            LlmError::QuotaExhausted {
                message: sanitize_error_body(body),
            }
        } else {
            LlmError::RateLimited { retry_after_secs }
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

/// Classifies an `error` object that arrived INSIDE a 200 streaming
/// response — the provider having already committed to a success status
/// before discovering it couldn't finish.
///
/// Routed through [`classify_http_error`] rather than given its own
/// mapping, so a mid-stream failure produces the same `LlmError` (and
/// therefore the same retry/context-shrink reaction in
/// `bc-llm-agentic`) as the identical failure delivered as an HTTP
/// status would. The synthetic status comes from the error's own
/// `type`/`code`, defaulting to 500 — transient, which is the right
/// default for a stream that died after the provider had already
/// accepted the request.
pub fn classify_stream_error(error: &Value) -> LlmError {
    let tag = error["code"]
        .as_str()
        .or_else(|| error["type"].as_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    // A billing tag routes to 429 — the status OpenAI uses for it over
    // HTTP — so `classify_http_error`'s own quota check (which needs both
    // a 429 AND a matching body) sees the pair it expects. The body it is
    // handed is the whole error object, so the tag that got us here is
    // itself what `QUOTA_RX` then matches on.
    let status = if tag.contains("rate_limit")
        || tag.contains("quota")
        || tag.contains("spend_limit")
        || tag.contains("usage_limit")
        || tag.contains("credit_balance")
    {
        429
    } else if tag.contains("invalid_request") || tag.contains("context_length") {
        400
    } else {
        500
    };
    // The whole object, not just `message`: `classify_http_error`
    // matches its context-overflow regex against the body text, and a
    // provider can name the overflow in `code` rather than in prose.
    classify_http_error(status, &error.to_string(), None)
}

/// Parses the HTTP `Retry-After` header's integer-seconds form (what
/// every gateway/provider this project talks to actually sends for a
/// 429) — `None` for a missing header, a non-integer value (e.g. the
/// less common HTTP-date form), or anything that doesn't parse as a
/// plain non-negative integer.
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

    /// A mid-stream error is classified by the same rules an HTTP one
    /// is, so everything downstream reacts to it identically.
    #[test]
    fn classify_stream_error_maps_the_error_tag_to_its_http_equivalent() {
        let of = |body| classify_stream_error(&body);
        assert_eq!(
            of(json!({"code": "rate_limit_exceeded", "message": "slow down"})),
            LlmError::RateLimited {
                retry_after_secs: None
            }
        );
        // `type` is consulted when `code` is absent.
        assert_eq!(
            of(json!({"type": "rate_limit_error", "message": "slow down"})),
            LlmError::RateLimited {
                retry_after_secs: None
            }
        );
        assert!(matches!(
            of(json!({"type": "invalid_request_error", "message": "bad tool schema"})),
            LlmError::InvalidRequest { .. }
        ));
        // Unknown, and untagged: transient, since the provider had
        // already accepted the request before failing.
        assert!(matches!(
            of(json!({"type": "server_error", "message": "boom"})),
            LlmError::ServerError { status: 500, .. }
        ));
        assert!(matches!(
            of(json!({"message": "no tag at all"})),
            LlmError::ServerError { status: 500, .. }
        ));
    }

    #[test]
    fn classify_stream_error_still_detects_a_context_overflow() {
        let err = classify_stream_error(&json!({
            "code": "context_length_exceeded",
            "message": "This model's maximum context length is 8192 tokens",
        }));
        assert!(matches!(err, LlmError::ContextOverflow { .. }), "{err:?}");
    }

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
    fn classify_http_error_429_prose_spend_or_usage_limit_is_quota_exhausted() {
        for body in [
            r#"{"error":{"message":"You have exceeded your organization spend limit."}}"#,
            r#"{"error":{"message":"Usage limit reached for this project."}}"#,
            r#"{"error":{"message":"billing hard limit reached"}}"#,
        ] {
            let verdict = classify_http_error(429, body, Some(5));
            assert!(matches!(verdict, LlmError::QuotaExhausted { .. }));
        }
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

    /// Every documented non-transient 429 code, in the body shape OpenAI
    /// actually sends — the 2026-09 CI failure was an account with no
    /// credits answering `insufficient_quota` to all ~250 S6 sessions,
    /// each of which then retried six times over a 10 s linear backoff
    /// because a 429 was a 429 was a rate limit.
    #[test]
    fn classify_http_error_429_with_a_billing_code_is_quota_exhausted() {
        for (code, message) in [
            (
                "insufficient_quota",
                "You exceeded your current quota, please check your plan and billing details.",
            ),
            (
                "credit_balance_exhausted",
                "Your credit balance is exhausted.",
            ),
            (
                "organization_spend_limit_exceeded",
                "You have exceeded your organization spend limit.",
            ),
            (
                "project_spend_limit_exceeded",
                "You have exceeded your project spend limit.",
            ),
            (
                "organization_usage_limit_exceeded",
                "You have exceeded your organization usage limit.",
            ),
        ] {
            let body =
                json!({"error": {"type": code, "code": code, "message": message}}).to_string();
            let err = classify_http_error(429, &body, Some(30));
            assert_eq!(
                err,
                LlmError::QuotaExhausted {
                    message: bc_llm_client::sanitize_error_body(&body),
                },
                "{code} must not be mistaken for a rate limit"
            );
            // The property the whole fix rests on.
            assert!(!err.is_retryable(), "{code}");
        }
    }

    /// The prose alone is enough: a gateway that forwards the message but
    /// rewrites or drops the `code` field still gets classified right.
    #[test]
    fn classify_http_error_429_recognizes_the_quota_message_without_the_code() {
        let body = r#"{"error":{"message":"You exceeded your current quota."}}"#;
        assert_eq!(
            classify_http_error(429, body, None),
            LlmError::QuotaExhausted {
                message: body.to_string(),
            }
        );
    }

    /// A billing 429's body contains the very words the context-overflow
    /// regex hunts for ("exceeded your organization spend limit" matches
    /// `exceed.*limit`), so the quota check has to run first or the
    /// account-is-empty signal is misfiled as a prompt-too-long one.
    #[test]
    fn a_billing_429_is_not_mistaken_for_a_context_overflow() {
        let body = r#"{"error":{"code":"organization_spend_limit_exceeded",
                     "message":"You have exceeded your organization spend limit"}}"#;
        assert!(CTX_OVERFLOW_RX.is_match(body), "premise of this test");
        assert!(matches!(
            classify_http_error(429, body, None),
            LlmError::QuotaExhausted { .. }
        ));
    }

    /// The other half of the split: an ordinary 429 is still a retryable
    /// rate limit, which is what makes a transient throttle survivable.
    #[test]
    fn classify_http_error_429_without_a_billing_code_stays_rate_limited() {
        let body =
            r#"{"error":{"code":"rate_limit_exceeded","message":"Rate limit reached for gpt-4o"}}"#;
        let err = classify_http_error(429, body, Some(2));
        assert_eq!(
            err,
            LlmError::RateLimited {
                retry_after_secs: Some(2)
            }
        );
        assert!(err.is_retryable());
    }

    /// A real OpenAI throttle body names a token-per-minute limit and its
    /// numbers, which is exactly what the context-overflow heuristic hunts
    /// for (`exceed.*limit`). Settling 429 first is what keeps a throttle
    /// retryable instead of turning it into a history-eviction the request
    /// never needed.
    #[test]
    fn a_throttle_body_that_reads_like_an_overflow_is_still_a_rate_limit() {
        let body = r#"{"error":{"code":"rate_limit_exceeded","message":"Rate limit reached for
                     gpt-4o on tokens per min (TPM): Limit 30000, Used 29000."}}"#;
        assert!(CTX_OVERFLOW_RX.is_match(body), "premise of this test");
        let err = classify_http_error(429, body, Some(2));
        assert_eq!(
            err,
            LlmError::RateLimited {
                retry_after_secs: Some(2)
            }
        );
        assert!(err.is_retryable());
    }

    /// The quota check is scoped to 429: the same words in a 400 body are
    /// not a billing failure in the OpenAI dialect.
    #[test]
    fn a_non_429_status_is_not_checked_for_quota_wording() {
        assert!(matches!(
            classify_http_error(403, r#"{"code":"insufficient_quota"}"#, None),
            LlmError::InvalidRequest { .. }
        ));
    }

    /// A billing failure delivered mid-stream (the provider had already
    /// sent a 200 before discovering the account was empty) must land on
    /// the same non-retryable variant the HTTP form does.
    #[test]
    fn classify_stream_error_routes_a_billing_tag_to_quota_exhausted() {
        for code in [
            "insufficient_quota",
            "credit_balance_exhausted",
            "organization_spend_limit_exceeded",
            "project_usage_limit_exceeded",
        ] {
            let err = classify_stream_error(&json!({"code": code, "message": "out of credits"}));
            assert!(matches!(err, LlmError::QuotaExhausted { .. }), "{err:?}");
            assert!(!err.is_retryable(), "{code}");
        }
        // `type` is consulted when `code` is absent, same as for every
        // other tag.
        assert!(matches!(
            classify_stream_error(&json!({"type": "insufficient_quota"})),
            LlmError::QuotaExhausted { .. }
        ));
    }

    #[test]
    fn classify_http_error_5xx_is_server_error() {
        assert_eq!(
            classify_http_error(503, "down", None),
            LlmError::ServerError {
                status: 503,
                message: "down".to_string()
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
            classify_http_error(
                400,
                "This model's maximum context length is 128000 tokens",
                None
            ),
            LlmError::ContextOverflow {
                message: "This model's maximum context length is 128000 tokens".to_string()
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
        let raw = "upstream said: Authorization: Bearer sk-live-abcd1234efgh5678";
        let err = classify_http_error(500, raw, None);
        assert_eq!(
            err,
            LlmError::ServerError {
                status: 500,
                message: bc_llm_client::sanitize_error_body(raw),
            }
        );
        assert!(
            !err.to_string().contains("sk-live-abcd1234efgh5678"),
            "token survived: {err}"
        );
    }

    #[test]
    fn classify_http_error_caps_an_oversized_body() {
        let body = "z".repeat(bc_llm_client::MAX_ERROR_BODY_CHARS + 100);
        let err = classify_http_error(400, &body, None);
        assert_eq!(
            err,
            LlmError::InvalidRequest {
                message: bc_llm_client::sanitize_error_body(&body),
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
        // The less common HTTP-date form — not handled, degrades to `None`.
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::RETRY_AFTER,
            reqwest::header::HeaderValue::from_static("Wed, 21 Oct 2026 07:28:00 GMT"),
        );
        assert_eq!(parse_retry_after(&headers), None);
    }
}
