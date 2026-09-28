//! Anthropic Messages API JSON response -> [`ChatResponse`], and HTTP
//! error-status -> [`LlmError`] classification, ported from
//! `backends/sdk.py`'s response/usage handling and its
//! `_is_transient_sdk` error classification.

use std::sync::LazyLock;

use bc_llm_client::{
    sanitize_error_body, ChatResponse, ContentBlock, LlmError, OpaqueDialect, StopReason, Usage,
};
use regex::Regex;
use serde_json::Value;

static CTX_OVERFLOW_RX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)context.?length|context length|exceed.*(?:token|limit)|too long").unwrap()
});

/// The 400 bodies that mean "the account is out of money". Anthropic does
/// NOT overload 429 for this the way OpenAI does — a billing problem
/// arrives as an ordinary HTTP 400 `invalid_request_error` whose message
/// reads "Your credit balance is too low to access the Claude API…" — so
/// the dialects need different triggers for the same
/// [`LlmError::QuotaExhausted`] outcome even though everything downstream
/// of them is shared.
static QUOTA_RX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)credit balance|insufficient credit|billing").unwrap());

/// The exact canned-refusal string Anthropic's org-level content
/// classifier substitutes for the model's real response when it silently
/// blocks a prompt server-side (a normal 200 response, `stop_reason:
/// end_turn`) — ported from `backends/claude_cli.py`'s
/// `_GUARDRAIL_REFUSALS`/`_check_guardrail`. That check reads the CLI
/// subprocess's own JSON envelope; this checks the parsed Messages API
/// response directly, since the same classifier sits in front of
/// `api.anthropic.com` regardless of which client reaches it — the CLI
/// subprocess backend was never the thing doing the blocking, just the
/// first client this project happened to observe it through. Exact
/// match only, matching Python's own discipline: a legitimately short
/// model reply must never be mistaken for a block.
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
            // Kept verbatim, signature included, so the next turn of a
            // tool loop can replay them: with extended thinking on, the
            // API rejects an assistant tool-use turn whose thinking was
            // dropped or altered.
            Some("thinking") | Some("redacted_thinking") => content.push(ContentBlock::Opaque {
                dialect: OpaqueDialect::Anthropic,
                payload: block.clone(),
            }),
            // Any other block type carries no signal this seam exposes;
            // skipped rather than erroring so a new Anthropic block type
            // doesn't break parsing of the parts we do understand.
            _ => {}
        }
    }

    // A model-level safety refusal arrives as an ordinary 200 with
    // `stop_reason: "refusal"` (Claude 4 and later), possibly with some
    // partial text before it. Surfaced as the same guardrail error the
    // org classifier's canned refusal below is, so S6's cumulative-refusal
    // gate counts both, rather than handing a stage a truncated answer.
    if body["stop_reason"] == "refusal" {
        return Err(LlmError::GuardrailBlocked {
            message: "the model declined to answer (stop_reason=refusal)".to_string(),
        });
    }

    let stop_reason = match body["stop_reason"].as_str() {
        Some("tool_use") => StopReason::ToolUse,
        Some("max_tokens") => StopReason::MaxTokens,
        // A natural stop (either the model finished on its own, or hit a
        // caller-supplied stop sequence) is the same "done" signal as
        // OpenAI's "stop" — not distinguished from `end_turn` here.
        Some("end_turn") | Some("stop_sequence") => StopReason::EndTurn,
        Some(other) => StopReason::Other(other.to_string()),
        None => StopReason::Other("missing".to_string()),
    };

    // Only a natural end-of-turn can carry the canned refusal — one
    // truncated by `tool_use`/`max_tokens` is real model output that
    // happens to be short, never the classifier's substitution.
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
    }
}

/// Tokens written to cache, both lifetimes together. The API reports the
/// total as `cache_creation_input_tokens` and the per-lifetime split as
/// `cache_creation: {ephemeral_5m_input_tokens, ephemeral_1h_input_tokens}`;
/// the total wins, and the split is summed only when a gateway forwarded
/// the breakdown without it (otherwise a working cache would read as zero
/// writes and be under-billed). Which lifetime applied is the request's
/// own `CachePolicy::ttl`: every marker in one request carries the same
/// one, so the split adds nothing a caller does not already know.
pub fn cache_creation_tokens(usage: &Value) -> u64 {
    usage["cache_creation_input_tokens"]
        .as_u64()
        .unwrap_or_else(|| {
            let split = &usage["cache_creation"];
            split["ephemeral_5m_input_tokens"].as_u64().unwrap_or(0)
                + split["ephemeral_1h_input_tokens"].as_u64().unwrap_or(0)
        })
}

/// Classify a non-2xx HTTP response into an [`LlmError`]. Anthropic's own
/// status vocabulary adds 529 ("overloaded_error") alongside the ordinary
/// 5xx range and 429 for rate limiting — both already fall through to the
/// same `ServerError`/`RateLimited` mapping used for the OpenAI dialect, so
/// this mirrors `bc-llm-openai::response::classify_http_error` rather than
/// diverging from it. `retry_after_secs` — parsed by the caller from the
/// response's own `Retry-After` header, since only it has access to
/// headers before the body is consumed — is threaded straight into
/// [`LlmError::RateLimited`] on a 429, ignored otherwise.
///
/// The body is *matched* raw but *retained* through
/// [`bc_llm_client::sanitize_error_body`], porting `backends/sdk.py`'s own
/// `redact(body)` around the provider response before it lands in the
/// raised exception's text (sdk.py:320-346) — a gateway can reflect an
/// `Authorization` header, an API key, or a slice of the prompt's source
/// snippet back in an error body that then travels into a `StageError`
/// and onto disk.
///
/// A 400 is checked against [`QUOTA_RX`] before the generic
/// `InvalidRequest` arm: "your credit balance is too low" is *shaped*
/// like a bad request but means the account cannot fund any further
/// request, which the scan has to react to rather than merely report —
/// see [`LlmError::QuotaExhausted`]. Unlike OpenAI, Anthropic does not
/// overload 429 for billing, so a 429 here is always a plain rate limit
/// — settled before the context-overflow check for the same reason
/// `bc_llm_openai::response::classify_http_error` settles it there: that
/// check is a text heuristic whose `exceed.*limit` branch a throttle
/// body ("rate_limit_exceeded", "Limit 30000, Used 29000") trips by
/// accident, and a context overflow is a 400 in this dialect, never a
/// 429. The two dialects keep the same shape here on purpose.
///
/// Authentication (401, or auth prose on a status no retry can help) and
/// a proxy's 407 are settled first, by the classifier both dialects
/// share: they halt the scan rather than failing one unit of work.
pub fn classify_http_error(status: u16, body: &str, retry_after_secs: Option<u64>) -> LlmError {
    if let Some(halting) = bc_llm_client::classify_auth_or_proxy_status(status, body) {
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

/// Classifies an `error` event that arrived INSIDE a 200 streaming
/// response — the provider having already committed to a success status
/// before discovering it couldn't finish.
///
/// Routed through [`classify_http_error`] rather than given its own
/// mapping, so a mid-stream failure produces the same `LlmError` (and
/// therefore the same retry reaction in `bc-llm-agentic`) as the
/// identical failure delivered as an HTTP status would. The synthetic
/// status comes from the Messages API's own documented error-type
/// vocabulary, which maps one-to-one onto the statuses those errors
/// carry when they are returned as an HTTP response instead —
/// `overloaded_error` being the 529 this dialect's own status
/// classification already calls out.
pub fn classify_stream_error(error: &Value) -> LlmError {
    let status = match error["type"].as_str().unwrap_or_default() {
        "overloaded_error" => 529,
        "rate_limit_error" => 429,
        "invalid_request_error" => 400,
        // 401, as the API sends it over HTTP, so a credential the
        // gateway rejects mid-stream halts the scan exactly as it would
        // have before the stream started.
        "authentication_error" => 401,
        "permission_error" => 403,
        "not_found_error" => 404,
        "request_too_large" => 413,
        // `api_error`, and anything the API adds later: transient, which
        // is the right default for a stream that died after the request
        // had already been accepted.
        _ => 500,
    };
    // The whole object, not just `message`: `classify_http_error`
    // matches its context-overflow regex against the body text, and the
    // naming can sit in either field.
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

    /// Every documented Messages API error type maps onto the status
    /// that same error carries when it arrives as an HTTP response —
    /// which is what makes a mid-stream failure indistinguishable from
    /// the equivalent HTTP one to everything downstream.
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
        // An error type this port has never seen is transient — the
        // stream died after the request had already been accepted.
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
        // Exact-match discipline: a short reply that merely CONTAINS the
        // refusal text, or resembles it, must not be flagged.
        let body = json!({
            "content": [{"type": "text", "text": "Your request was not allowed here"}],
            "stop_reason": "end_turn",
        });
        let resp = parse_response_body(&body).unwrap();
        assert_eq!(resp.text(), "Your request was not allowed here");
    }

    #[test]
    fn the_refusal_string_is_not_flagged_when_truncated_by_tool_use() {
        // Only a natural end-of-turn can carry the classifier's
        // substitution; a response that also emits a tool call couldn't
        // have been the canned block.
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
        // An unusual but syntactically valid shape (a tool_use block
        // present even though stop_reason is end_turn, not tool_use) —
        // the refusal check's own content filter must skip the
        // non-text block rather than choking on it.
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

    /// Anthropic's real shape for an account that has run dry: an HTTP
    /// 400 `invalid_request_error`, not the 429 OpenAI uses. Classified
    /// as a quota failure so a scan reacts to it (stop starting work)
    /// rather than reporting ~250 identical "invalid request" verify
    /// errors.
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
                    message: bc_llm_client::sanitize_error_body(&body),
                },
                "{message}"
            );
            assert!(!err.is_retryable(), "{message}");
        }
    }

    /// The check is scoped to 400 — a 429 stays the retryable rate limit
    /// it has always been in this dialect, since Anthropic never uses
    /// that status to mean "out of credits".
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

    /// A throttle body naming the limit it enforces reads like a context
    /// overflow to `CTX_OVERFLOW_RX` (`exceed.*limit`); settling 429
    /// first keeps it retryable, matching the OpenAI dialect exactly.
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

    /// An ordinary malformed request is untouched by the new arm.
    #[test]
    fn a_400_without_billing_wording_is_still_an_invalid_request() {
        assert!(matches!(
            classify_http_error(400, r#"{"error":{"message":"unexpected role"}}"#, None),
            LlmError::InvalidRequest { .. }
        ));
    }

    /// A billing message arriving mid-stream (the request was accepted
    /// with a 200 before the balance was checked) reaches the same
    /// non-retryable variant, because `invalid_request_error` already
    /// routes to 400.
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
        // Ported from `backends/sdk.py`'s `redact(body)` on the provider
        // response body — a gateway reflecting the auth header back must
        // not put the key into an `LlmError` that lands in a report.
        let raw =
            r#"{"error":{"message":"bad key: Authorization: Bearer sk-live-abcd1234efgh5678"}}"#;
        let err = classify_http_error(400, raw, None);
        assert_eq!(
            err,
            LlmError::InvalidRequest {
                message: bc_llm_client::sanitize_error_body(raw),
            }
        );
        assert!(
            !err.to_string().contains("sk-live-abcd1234efgh5678"),
            "token survived: {err}"
        );
    }

    /// A 401 used to be an `InvalidRequest`, so a wrong key failed every
    /// chunk of a scan one at a time. It now halts the scan (VVAH-E001),
    /// and a 407 from a proxy is VVAH-E002, both ahead of the 429 and
    /// quota arms.
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
        let body = "z".repeat(bc_llm_client::MAX_ERROR_BODY_CHARS + 100);
        let err = classify_http_error(529, &body, None);
        assert_eq!(
            err,
            LlmError::ServerError {
                status: 529,
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
