use std::fmt;

use crate::chat::ChatResponse;

pub mod codes {
    pub const AUTHENTICATION: &str = "VVAH-E001";
    pub const PROXY_OR_TLS: &str = "VVAH-E002";
    pub const TRUNCATED: &str = "VVAH-E005";
}

#[derive(Debug, Clone, PartialEq)]
pub enum LlmError {
    RateLimited {
        retry_after_secs: Option<u64>,
    },
    QuotaExhausted {
        message: String,
    },
    ServerError {
        status: u16,
        message: String,
    },
    InvalidRequest {
        message: String,
    },
    ContextOverflow {
        message: String,
    },
    ConnectionError {
        message: String,
    },
    GuardrailBlocked {
        message: String,
    },
    Authentication {
        status: Option<u16>,
        message: String,
    },
    ProxyOrTls {
        status: Option<u16>,
        message: String,
    },
    Truncated {
        requested: u32,
        retried_at: Option<u32>,
        partial: Box<ChatResponse>,
    },
    Other {
        message: String,
    },
}

impl LlmError {
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            LlmError::RateLimited { .. }
                | LlmError::ServerError { .. }
                | LlmError::ConnectionError { .. }
        )
    }

    pub fn code(&self) -> Option<&'static str> {
        match self {
            LlmError::Authentication { .. } => Some(codes::AUTHENTICATION),
            LlmError::ProxyOrTls { .. } => Some(codes::PROXY_OR_TLS),
            LlmError::Truncated { .. } => Some(codes::TRUNCATED),
            _ => None,
        }
    }

    pub fn halts_scan(&self) -> bool {
        matches!(
            self,
            LlmError::QuotaExhausted { .. }
                | LlmError::Authentication { .. }
                | LlmError::ProxyOrTls { .. }
        )
    }
}

fn status_suffix(status: Option<u16>) -> String {
    status.map(|s| format!(" (HTTP {s})")).unwrap_or_default()
}

impl fmt::Display for LlmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LlmError::RateLimited {
                retry_after_secs: Some(secs),
            } => {
                write!(f, "rate limited (retry after {secs}s)")
            }
            LlmError::RateLimited {
                retry_after_secs: None,
            } => write!(f, "rate limited"),
            LlmError::QuotaExhausted { message } => {
                write!(f, "provider quota exhausted: {message}")
            }
            LlmError::ServerError { status, message } => {
                write!(f, "server error {status}: {message}")
            }
            LlmError::InvalidRequest { message } => write!(f, "invalid request: {message}"),
            LlmError::ContextOverflow { message } => write!(f, "context overflow: {message}"),
            LlmError::ConnectionError { message } => write!(f, "connection error: {message}"),
            LlmError::GuardrailBlocked { message } => write!(f, "guardrail blocked: {message}"),
            LlmError::Authentication { status, message } => write!(
                f,
                "[{}] authentication failed{}: {message}",
                codes::AUTHENTICATION,
                status_suffix(*status)
            ),
            LlmError::ProxyOrTls { status, message } => write!(
                f,
                "[{}] proxy/TLS error{}: {message}",
                codes::PROXY_OR_TLS,
                status_suffix(*status)
            ),
            LlmError::Truncated {
                requested,
                retried_at: Some(at),
                ..
            } => write!(
                f,
                "[{}] truncated LLM response: hit max_tokens={requested}, and again after \
                 one retry at {at}",
                codes::TRUNCATED
            ),
            LlmError::Truncated {
                requested,
                retried_at: None,
                ..
            } => write!(
                f,
                "[{}] truncated LLM response: hit max_tokens={requested} with no larger \
                 budget left to retry at",
                codes::TRUNCATED
            ),
            LlmError::Other { message } => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for LlmError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limited_is_retryable_with_or_without_retry_after() {
        assert!(LlmError::RateLimited {
            retry_after_secs: Some(30)
        }
        .is_retryable());
        assert!(LlmError::RateLimited {
            retry_after_secs: None
        }
        .is_retryable());
    }

    #[test]
    fn server_and_connection_errors_are_retryable() {
        assert!(LlmError::ServerError {
            status: 503,
            message: "down".to_string()
        }
        .is_retryable());
        assert!(LlmError::ConnectionError {
            message: "reset".to_string()
        }
        .is_retryable());
    }

    #[test]
    fn invalid_request_context_overflow_and_other_are_not_retryable() {
        assert!(!LlmError::InvalidRequest {
            message: "bad".to_string()
        }
        .is_retryable());
        assert!(!LlmError::ContextOverflow {
            message: "too long".to_string()
        }
        .is_retryable());
        assert!(!LlmError::Other {
            message: "?".to_string()
        }
        .is_retryable());
        assert!(!LlmError::GuardrailBlocked {
            message: "refused".to_string()
        }
        .is_retryable());
    }

    #[test]
    fn quota_exhausted_is_not_retryable_even_though_it_arrives_on_a_429() {
        let quota = LlmError::QuotaExhausted {
            message: "You exceeded your current quota".to_string(),
        };
        assert!(!quota.is_retryable());
        assert!(LlmError::RateLimited {
            retry_after_secs: None
        }
        .is_retryable());
    }

    #[test]
    fn display_messages() {
        assert_eq!(
            LlmError::RateLimited {
                retry_after_secs: Some(5)
            }
            .to_string(),
            "rate limited (retry after 5s)"
        );
        assert_eq!(
            LlmError::RateLimited {
                retry_after_secs: None
            }
            .to_string(),
            "rate limited"
        );
        assert_eq!(
            LlmError::QuotaExhausted {
                message: "You exceeded your current quota".to_string()
            }
            .to_string(),
            "provider quota exhausted: You exceeded your current quota"
        );
        assert_eq!(
            LlmError::ServerError {
                status: 502,
                message: "bad gateway".to_string()
            }
            .to_string(),
            "server error 502: bad gateway"
        );
        assert_eq!(
            LlmError::InvalidRequest {
                message: "missing field".to_string()
            }
            .to_string(),
            "invalid request: missing field"
        );
        assert_eq!(
            LlmError::ContextOverflow {
                message: "128000 tokens".to_string()
            }
            .to_string(),
            "context overflow: 128000 tokens"
        );
        assert_eq!(
            LlmError::ConnectionError {
                message: "timed out".to_string()
            }
            .to_string(),
            "connection error: timed out"
        );
        assert_eq!(
            LlmError::GuardrailBlocked {
                message: "refused".to_string()
            }
            .to_string(),
            "guardrail blocked: refused"
        );
        assert_eq!(
            LlmError::Other {
                message: "weird".to_string()
            }
            .to_string(),
            "weird"
        );
    }

    fn truncated(retried_at: Option<u32>) -> LlmError {
        LlmError::Truncated {
            requested: 4096,
            retried_at,
            partial: Box::new(ChatResponse {
                content: vec![crate::message::ContentBlock::text("{\"findings\": [")],
                stop_reason: crate::chat::StopReason::MaxTokens,
                usage: crate::chat::Usage::default(),
            }),
        }
    }

    fn auth() -> LlmError {
        LlmError::Authentication {
            status: Some(401),
            message: "invalid x-api-key".to_string(),
        }
    }

    fn proxy() -> LlmError {
        LlmError::ProxyOrTls {
            status: None,
            message: "invalid peer certificate: UnknownIssuer".to_string(),
        }
    }

    #[test]
    fn the_coded_variants_carry_their_python_codes_and_nothing_else_does() {
        assert_eq!(auth().code(), Some("VVAH-E001"));
        assert_eq!(proxy().code(), Some("VVAH-E002"));
        assert_eq!(truncated(None).code(), Some("VVAH-E005"));
        for other in [
            LlmError::RateLimited {
                retry_after_secs: None,
            },
            LlmError::InvalidRequest {
                message: "x".to_string(),
            },
            LlmError::QuotaExhausted {
                message: "x".to_string(),
            },
        ] {
            assert_eq!(other.code(), None, "{other:?}");
        }
    }

    #[test]
    fn auth_proxy_and_truncation_are_never_retried_by_the_transient_ladder() {
        assert!(!auth().is_retryable());
        assert!(!proxy().is_retryable());
        assert!(!truncated(Some(8192)).is_retryable());
    }

    #[test]
    fn halts_scan_covers_auth_proxy_and_quota_but_not_truncation() {
        assert!(auth().halts_scan());
        assert!(proxy().halts_scan());
        assert!(LlmError::QuotaExhausted {
            message: "x".to_string()
        }
        .halts_scan());
        assert!(!truncated(Some(8192)).halts_scan());
        assert!(!LlmError::ConnectionError {
            message: "reset".to_string()
        }
        .halts_scan());
    }

    #[test]
    fn coded_variants_display_their_code_first() {
        assert_eq!(
            auth().to_string(),
            "[VVAH-E001] authentication failed (HTTP 401): invalid x-api-key"
        );
        assert_eq!(
            proxy().to_string(),
            "[VVAH-E002] proxy/TLS error: invalid peer certificate: UnknownIssuer"
        );
        assert_eq!(
            LlmError::ProxyOrTls {
                status: Some(407),
                message: "tunnel error".to_string()
            }
            .to_string(),
            "[VVAH-E002] proxy/TLS error (HTTP 407): tunnel error"
        );
        assert_eq!(
            truncated(Some(8192)).to_string(),
            "[VVAH-E005] truncated LLM response: hit max_tokens=4096, and again after one \
             retry at 8192"
        );
        assert_eq!(
            truncated(None).to_string(),
            "[VVAH-E005] truncated LLM response: hit max_tokens=4096 with no larger budget \
             left to retry at"
        );
    }

    #[test]
    fn implements_std_error() {
        let e = LlmError::Other {
            message: "x".to_string(),
        };
        let _: &dyn std::error::Error = &e;
    }
}
