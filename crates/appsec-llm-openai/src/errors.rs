use std::sync::LazyLock;

use appsec_llm_client::{sanitize_error_body, LlmError};
use regex::Regex;
use serde_json::Value;

static CTX_OVERFLOW_RX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)context.?length|context length|exceed.*(?:token|limit)|too long").unwrap()
});

static QUOTA_RX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?i)insufficient_quota|credit_balance_exhausted",
        r"|spend_limit_exceeded|usage_limit_exceeded",
        r"|exceeded your current quota",
        r"|spend limit|usage limit|billing hard limit",
    ))
    .unwrap()
});

pub fn classify_http_error(status: u16, body: &str, retry_after_secs: Option<u64>) -> LlmError {
    if let Some(halting) = appsec_llm_client::classify_auth_or_proxy_status(status, body) {
        return halting;
    }
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

pub fn classify_stream_error(error: &Value) -> LlmError {
    let tag = error["code"]
        .as_str()
        .or_else(|| error["type"].as_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
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
    fn classify_stream_error_maps_the_error_tag_to_its_http_equivalent() {
        let of = |body| classify_stream_error(&body);
        assert_eq!(
            of(json!({"code": "rate_limit_exceeded", "message": "slow down"})),
            LlmError::RateLimited {
                retry_after_secs: None
            }
        );
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
                    message: appsec_llm_client::sanitize_error_body(&body),
                },
                "{code} must not be mistaken for a rate limit"
            );
            assert!(!err.is_retryable(), "{code}");
        }
    }

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

    #[test]
    fn a_non_429_status_is_not_checked_for_quota_wording() {
        assert!(matches!(
            classify_http_error(403, r#"{"code":"insufficient_quota"}"#, None),
            LlmError::InvalidRequest { .. }
        ));
    }

    #[test]
    fn a_401_is_authentication_and_a_407_is_a_proxy_error() {
        let body = r#"{"error":{"code":"invalid_api_key","message":"Incorrect API key provided"}}"#;
        assert_eq!(
            classify_http_error(401, body, None),
            LlmError::Authentication {
                status: Some(401),
                message: body.to_string(),
            }
        );
        assert!(matches!(
            classify_http_error(407, "Proxy Authentication Required", None),
            LlmError::ProxyOrTls {
                status: Some(407),
                ..
            }
        ));
    }

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
                message: appsec_llm_client::sanitize_error_body(raw),
            }
        );
        assert!(
            !err.to_string().contains("sk-live-abcd1234efgh5678"),
            "token survived: {err}"
        );
    }

    #[test]
    fn classify_http_error_caps_an_oversized_body() {
        let body = "z".repeat(appsec_llm_client::MAX_ERROR_BODY_CHARS + 100);
        let err = classify_http_error(400, &body, None);
        assert_eq!(
            err,
            LlmError::InvalidRequest {
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
