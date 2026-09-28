//! `LlmError`, the normalized failure shape both dialect implementations
//! (`bc-llm-openai`, `bc-llm-anthropic`) map their provider-specific
//! exceptions onto — ported from the retry/error classification logic
//! duplicated across `backends/oai.py` (`_is_transient_status`,
//! `_RETRYABLE_STATUS`, `_CTX_OVERFLOW_RX`) and `backends/sdk.py`
//! (`_is_transient_sdk`). Centralizing it here means `bc-llm-agentic`'s
//! retry/backoff/context-eviction loop is written once, against this type,
//! instead of once per dialect.

use std::fmt;

use crate::chat::ChatResponse;

/// Stable operator-facing error codes, shared with the Python original's
/// `backends/harness/models.py` exception hierarchy so an operator who
/// searches either project's docs for a code finds the same meaning.
pub mod codes {
    /// Authentication with the provider or gateway failed.
    pub const AUTHENTICATION: &str = "VVAH-E001";
    /// Proxy, tunnel or TLS configuration stopped the request reaching
    /// the gateway at all.
    pub const PROXY_OR_TLS: &str = "VVAH-E002";
    /// The reply hit its output-token budget, even after one doubled
    /// retry.
    pub const TRUNCATED: &str = "VVAH-E005";
}

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
    /// The provider or gateway rejected the credential (VVAH-E001): an
    /// HTTP 401, or a non-retryable status whose body reads as an
    /// authentication failure (see
    /// [`crate::classify_auth_or_proxy_status`]).
    ///
    /// Before this variant existed a 401 was an ordinary
    /// [`LlmError::InvalidRequest`], so a wrong key failed every chunk of
    /// a scan individually and the report blamed the chunks. It is not
    /// retryable by [`LlmError::is_retryable`] (the transient ladder is
    /// the wrong tool), but `bc-llm-agentic` gives it a short ladder of
    /// its own (2 s, 4 s, 8 s) the way the Python original does, and it
    /// halts the scan (see [`LlmError::halts_scan`]).
    Authentication {
        status: Option<u16>,
        message: String,
    },
    /// A proxy, CONNECT tunnel or TLS verification failure (VVAH-E002):
    /// an HTTP 407, a refused tunnel, or a certificate the TLS stack
    /// would not accept. A misconfiguration, not an outage, so retrying
    /// only delays the report of it; halts the scan like
    /// [`LlmError::Authentication`].
    ProxyOrTls {
        status: Option<u16>,
        message: String,
    },
    /// The reply stopped because it hit its output-token budget
    /// (VVAH-E005), and one retry at double the budget (capped by the
    /// caller's ceiling, if any) did not fix it, or the provider refused
    /// the doubled budget as over its own cap.
    ///
    /// `requested` is the budget the caller asked for, `retried_at` the
    /// doubled budget actually tried (`None` when no retry was possible),
    /// and `partial` the last truncated reply, kept whole so a caller
    /// that can salvage a partial answer may do so. Not retryable and
    /// not halting: one oversized answer says nothing about the next
    /// unit of work.
    Truncated {
        requested: u32,
        retried_at: Option<u32>,
        partial: Box<ChatResponse>,
    },
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

    /// The stable operator-facing code for this failure, when it has one
    /// (see [`codes`]).
    ///
    /// Only the codes whose Python meaning this port can honor exactly
    /// are assigned. VVAH-E003 (a degenerate 200 reply) belongs to a
    /// per-stage quality floor this port does not run at the transport
    /// seam, and VVAH-E004 is the Python deepagents route's pre-dispatch
    /// prompt-size refusal, a route this port does not have; neither is
    /// ever returned here.
    pub fn code(&self) -> Option<&'static str> {
        match self {
            LlmError::Authentication { .. } => Some(codes::AUTHENTICATION),
            LlmError::ProxyOrTls { .. } => Some(codes::PROXY_OR_TLS),
            LlmError::Truncated { .. } => Some(codes::TRUNCATED),
            _ => None,
        }
    }

    /// Whether this failure means every other call in the scan is about
    /// to fail the same way, so the scan should stop starting new work.
    ///
    /// Mirrors Python's `is_halt_error` (VVAH-E001 and VVAH-E002) and
    /// adds [`LlmError::QuotaExhausted`], which this port already treats
    /// that way. A stage that sees `true` should trip its scan-wide
    /// `bc_pipeline_core::BudgetGate` with the error's own text, the same
    /// way S4 and S6 already do for a quota failure.
    pub fn halts_scan(&self) -> bool {
        matches!(
            self,
            LlmError::QuotaExhausted { .. }
                | LlmError::Authentication { .. }
                | LlmError::ProxyOrTls { .. }
        )
    }
}

/// ` (HTTP 401)`, or nothing when no status is known, for the Display of
/// the two coded transport variants.
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

    /// Auth and proxy/TLS halt like Python's `is_halt_error`; quota
    /// already did here. A truncation is one oversized answer, not a
    /// broken scan, so it must not stop anything.
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
