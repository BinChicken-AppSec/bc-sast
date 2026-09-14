//! `LlmError`, the normalized failure shape both dialect implementations
//! (`bc-llm-openai`, `bc-llm-anthropic`) map their provider-specific
//! exceptions onto — ported from the retry/error classification logic
//! duplicated across `backends/oai.py` (`_is_transient_status`,
//! `_RETRYABLE_STATUS`, `_CTX_OVERFLOW_RX`) and `backends/sdk.py`
//! (`_is_transient_sdk`). Centralizing it here means `bc-llm-agentic`'s
//! retry/backoff/context-eviction loop is written once, against this type,
//! instead of once per dialect.

use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum LlmError {
    /// HTTP 429. `retry_after_secs` carries a `Retry-After` header value
    /// when the gateway sent one.
    RateLimited { retry_after_secs: Option<u64> },
    /// The provider says the account has no money/allowance left to fund
    /// this request — an exhausted prepaid credit balance, a spend cap, or
    /// a hard usage limit. **Not** "slow down": no amount of waiting makes
    /// the next attempt succeed, only a human topping up the account or
    /// raising a limit does.
    ///
    /// Split out of [`LlmError::RateLimited`] because OpenAI signals it as
    /// an HTTP **429** (`insufficient_quota` and friends), which the
    /// initial port classified as an ordinary rate limit and therefore
    /// retried. A 2026-09 CI run against an OpenAI account with no credits
    /// spent 80 minutes doing exactly that — ~250 S6 verification sessions
    /// × 6 retries × a 10 s linear backoff — and produced nothing but a
    /// `--max-scan-seconds` timeout. Anthropic reports the same condition
    /// as an HTTP 400 `invalid_request_error` whose message contains
    /// "credit balance is too low"; both dialects map onto this variant.
    ///
    /// Non-retryable on purpose, and additionally a signal a stage should
    /// act on rather than merely report: one session learning the account
    /// is empty means every *other* session in the scan is about to learn
    /// it too, so S4/S6 trip the scan's `bc_pipeline_core::BudgetGate` on
    /// it and stop starting new work.
    QuotaExhausted { message: String },
    /// A transient 5xx from the gateway or upstream provider.
    ServerError { status: u16, message: String },
    /// A non-retryable 4xx (other than 429) — a malformed request, an
    /// unsupported parameter the dialect didn't already know to drop, etc.
    InvalidRequest { message: String },
    /// The accumulated request (system + messages + tool results) no longer
    /// fits the model's context window. Distinguished from a generic
    /// [`LlmError::InvalidRequest`] so `bc-llm-agentic` can react by
    /// evicting history and retrying, rather than failing the turn outright.
    ContextOverflow { message: String },
    /// A network-level failure (DNS, TLS, connection reset) reaching the
    /// gateway at all.
    ConnectionError { message: String },
    /// The provider/gateway refused the request on safety/policy grounds
    /// rather than a normal 4xx (malformed request) or 5xx (transient)
    /// failure — the gateway-mediated equivalent of the Python original's
    /// `backends/claude_cli.GuardrailBlocked` (raised there when the Claude
    /// Code CLI subprocess backend's own safety system refused a tool
    /// request). Kept distinct from [`LlmError::InvalidRequest`] so a
    /// caller like `bc-stage-s6` can react to repeated refusals
    /// specifically (its cumulative-guardrail abort gate), the same way
    /// the Python original does — not retryable, since resending the same
    /// request would just be refused again.
    GuardrailBlocked { message: String },
    /// Anything else — an unrecognized response shape, a provider error
    /// code not covered above.
    Other { message: String },
}

impl LlmError {
    /// Whether a caller should retry this exact request after a backoff,
    /// mirroring `_is_transient_status`/`_is_transient_sdk`: rate limits,
    /// server errors, and connection errors are transient; a bad request or
    /// context overflow needs the request itself changed first, so retrying
    /// unmodified would just fail identically. [`LlmError::QuotaExhausted`]
    /// is deliberately NOT retryable even though it arrives on a 429 —
    /// see that variant's own docs.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            LlmError::RateLimited { .. }
                | LlmError::ServerError { .. }
                | LlmError::ConnectionError { .. }
        )
    }
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

    /// The whole point of the variant: it arrives on the same HTTP 429 a
    /// rate limit does, and must NOT be retried anyway — waiting cannot
    /// put money back in the account.
    #[test]
    fn quota_exhausted_is_not_retryable_even_though_it_arrives_on_a_429() {
        let quota = LlmError::QuotaExhausted {
            message: "You exceeded your current quota".to_string(),
        };
        assert!(!quota.is_retryable());
        // …unlike the rate limit it shares a status code with.
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

    #[test]
    fn implements_std_error() {
        let e = LlmError::Other {
            message: "x".to_string(),
        };
        let _: &dyn std::error::Error = &e;
    }
}
