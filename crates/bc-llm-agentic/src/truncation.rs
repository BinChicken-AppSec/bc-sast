//! What to do with a reply that stopped because it hit its output-token
//! budget (VVAH-E005), ported from the Python original's
//! `backends/llm/openai.py` / `backends/llm/sdk.py` `prompt()` loops and
//! `backends/llm/models.py::truncation_retry_max`.
//!
//! One retry at double the budget (capped by an optional ceiling), then
//! [`LlmError::Truncated`] carrying the partial reply. Before this, both
//! dialects mapped the stop onto `StopReason::MaxTokens` and nothing read
//! it: a truncated JSON document went straight to the parsers and the
//! repair heuristics, and an agentic session treated it as a finished
//! answer.
//!
//! Pure state, no I/O: the two call loops ([`crate::chat_with_retry`]
//! and the agentic per-turn loop) own the sending, and ask this what the
//! answer they got means.

use bc_llm_client::{ChatResponse, LlmError, StopReason};

/// The retry budget's growth factor, Python's
/// `TRUNCATION_RETRY_MULTIPLIER`.
const TRUNCATION_RETRY_MULTIPLIER: u32 = 2;

/// The one retry's output budget, or `None` when retrying cannot help
/// because `requested` is already at (or past) the ceiling. Python's
/// `truncation_retry_max`. No ceiling means the provider's own cap
/// decides: a request over it comes back as a 400, which
/// [`TruncationGuard::cap_rejection`] reads as "that was the cap".
fn retry_budget(requested: u32, ceiling: Option<u32>) -> Option<u32> {
    let doubled = requested.saturating_mul(TRUNCATION_RETRY_MULTIPLIER);
    let budget = ceiling.map_or(doubled, |cap| doubled.min(cap));
    (budget > requested).then_some(budget)
}

/// Whether `err`, returned for the doubled-budget retry, is the provider
/// refusing that budget as over its cap. Python keys this on the 400's
/// text naming the budget parameter (`max_tokens` /
/// `max_completion_tokens`); `max_output_tokens` is the Responses-API
/// spelling. A context-window overflow naming the budget counts too:
/// "input + max_tokens > context window" is the same cap reached from
/// the other side, and the original request already fitted.
fn is_output_cap_rejection(err: &LlmError) -> bool {
    let (LlmError::InvalidRequest { message } | LlmError::ContextOverflow { message }) = err else {
        return false;
    };
    let lower = message.to_ascii_lowercase();
    ["max_tokens", "max_completion_tokens", "max_output_tokens"]
        .iter()
        .any(|name| lower.contains(name))
}

/// What a reply means for the call that received it.
#[derive(Debug, PartialEq)]
pub(crate) enum Verdict {
    /// Not truncated: hand it back.
    Done(ChatResponse),
    /// Truncated for the first time: send the same request again at
    /// [`TruncationGuard::max_tokens`].
    Retry,
    /// Truncated with no retry left: give up with this
    /// [`LlmError::Truncated`].
    GiveUp(LlmError),
}

/// One call's truncation state.
pub(crate) struct TruncationGuard {
    requested: u32,
    ceiling: Option<u32>,
    retried_at: Option<u32>,
    /// The first truncated reply, kept for the case where the retry is
    /// refused outright and so produces no reply of its own.
    first_partial: Option<ChatResponse>,
}

impl TruncationGuard {
    pub(crate) fn new(requested: u32, ceiling: Option<u32>) -> Self {
        TruncationGuard {
            requested,
            ceiling,
            retried_at: None,
            first_partial: None,
        }
    }

    /// The output budget the next send should carry.
    pub(crate) fn max_tokens(&self) -> u32 {
        self.retried_at.unwrap_or(self.requested)
    }

    /// Judge a successful reply.
    pub(crate) fn on_response(&mut self, response: ChatResponse) -> Verdict {
        if response.stop_reason != StopReason::MaxTokens {
            return Verdict::Done(response);
        }
        if self.retried_at.is_none() {
            if let Some(budget) = retry_budget(self.requested, self.ceiling) {
                tracing::warn!(
                    code = bc_llm_client::codes::TRUNCATED,
                    max_tokens = self.requested,
                    retry_at = budget,
                    "LLM reply truncated at its output budget; retrying once at a larger one"
                );
                self.retried_at = Some(budget);
                self.first_partial = Some(response);
                return Verdict::Retry;
            }
        }
        Verdict::GiveUp(self.truncated(response))
    }

    /// The [`LlmError::Truncated`] to give up with when `err`, returned
    /// for the doubled-budget retry, is the provider refusing that budget
    /// (see [`is_output_cap_rejection`]); `None` for any other error, or
    /// before a retry was sent. Returns the FIRST reply as the partial,
    /// not the error: the original request succeeded, and the caller is
    /// owed its reply, not a 400 about a request it never made.
    pub(crate) fn cap_rejection(&mut self, err: &LlmError) -> Option<LlmError> {
        if !is_output_cap_rejection(err) {
            return None;
        }
        let partial = self.first_partial.take()?;
        Some(self.truncated(partial))
    }

    fn truncated(&self, partial: ChatResponse) -> LlmError {
        LlmError::Truncated {
            requested: self.requested,
            retried_at: self.retried_at,
            partial: Box::new(partial),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_llm_client::{ContentBlock, Usage};

    fn reply(text: &str, stop: StopReason) -> ChatResponse {
        ChatResponse {
            content: vec![ContentBlock::text(text)],
            stop_reason: stop,
            usage: Usage::default(),
        }
    }

    fn cap_400() -> LlmError {
        LlmError::InvalidRequest {
            message: "max_tokens: 64000 > 32000, which is the maximum allowed".to_string(),
        }
    }

    #[test]
    fn retry_budget_doubles_and_respects_a_ceiling() {
        assert_eq!(retry_budget(4096, None), Some(8192));
        assert_eq!(retry_budget(4096, Some(6000)), Some(6000));
        assert_eq!(retry_budget(4096, Some(4096)), None, "already at the cap");
        assert_eq!(retry_budget(8000, Some(4096)), None, "already past the cap");
        assert_eq!(
            retry_budget(0, None),
            None,
            "doubling nothing gains nothing"
        );
        assert_eq!(retry_budget(u32::MAX, None), None, "saturates, never wraps");
    }

    #[test]
    fn output_cap_rejections_are_recognized_by_the_budget_parameter_they_name() {
        assert!(is_output_cap_rejection(&cap_400()));
        assert!(is_output_cap_rejection(&LlmError::InvalidRequest {
            message: "Invalid 'max_completion_tokens': too large".to_string()
        }));
        assert!(is_output_cap_rejection(&LlmError::ContextOverflow {
            message: "input length and `max_tokens` exceed context limit".to_string()
        }));
        assert!(!is_output_cap_rejection(&LlmError::InvalidRequest {
            message: "unknown model".to_string()
        }));
        assert!(!is_output_cap_rejection(&LlmError::ServerError {
            status: 500,
            message: "max_tokens".to_string()
        }));
    }

    #[test]
    fn a_reply_that_was_not_truncated_is_done() {
        let mut guard = TruncationGuard::new(100, None);
        let r = reply("ok", StopReason::EndTurn);
        assert_eq!(guard.on_response(r.clone()), Verdict::Done(r));
        assert_eq!(guard.max_tokens(), 100);
    }

    #[test]
    fn the_first_truncation_retries_at_double_and_the_second_gives_up() {
        let mut guard = TruncationGuard::new(100, None);
        assert_eq!(
            guard.on_response(reply("{\"a\":", StopReason::MaxTokens)),
            Verdict::Retry
        );
        assert_eq!(guard.max_tokens(), 200);
        let second = reply("{\"a\": [1,", StopReason::MaxTokens);
        assert_eq!(
            guard.on_response(second.clone()),
            Verdict::GiveUp(LlmError::Truncated {
                requested: 100,
                retried_at: Some(200),
                partial: Box::new(second),
            })
        );
    }

    #[test]
    fn a_retry_that_fixes_the_truncation_is_done() {
        let mut guard = TruncationGuard::new(100, None);
        guard.on_response(reply("{", StopReason::MaxTokens));
        let whole = reply("{}", StopReason::EndTurn);
        assert_eq!(guard.on_response(whole.clone()), Verdict::Done(whole));
    }

    #[test]
    fn a_request_already_at_the_ceiling_gives_up_without_retrying() {
        let mut guard = TruncationGuard::new(100, Some(100));
        let cut = reply("{", StopReason::MaxTokens);
        assert_eq!(
            guard.on_response(cut.clone()),
            Verdict::GiveUp(LlmError::Truncated {
                requested: 100,
                retried_at: None,
                partial: Box::new(cut),
            })
        );
    }

    #[test]
    fn a_refused_retry_returns_the_first_reply_not_the_400() {
        let mut guard = TruncationGuard::new(100, None);
        let first = reply("{\"a\":", StopReason::MaxTokens);
        guard.on_response(first.clone());
        assert_eq!(
            guard.cap_rejection(&cap_400()),
            Some(LlmError::Truncated {
                requested: 100,
                retried_at: Some(200),
                partial: Box::new(first),
            })
        );
    }

    /// Before any retry was sent, a `max_tokens` 400 is the caller's own
    /// misconfiguration and must reach them unchanged.
    #[test]
    fn a_budget_400_before_any_retry_is_not_a_truncation() {
        let mut guard = TruncationGuard::new(100, None);
        assert_eq!(guard.cap_rejection(&cap_400()), None);
    }

    #[test]
    fn an_unrelated_error_on_the_retry_is_not_a_truncation() {
        let mut guard = TruncationGuard::new(100, None);
        guard.on_response(reply("{", StopReason::MaxTokens));
        assert_eq!(
            guard.cap_rejection(&LlmError::InvalidRequest {
                message: "unknown model".to_string()
            }),
            None
        );
    }
}

/// Turns a still-truncated reply (VVAH-E005) back into its partial
/// response, for single-shot callers whose parsers already tolerate a cut
/// off document (JSON repair, a findings re-ask). Every other result
/// passes through untouched.
///
/// Losing the whole reply to an error would discard whatever the model
/// did finish, such as the first ninety findings of a hundred, which is
/// strictly worse than parsing what arrived: the truncation is still
/// counted (the client already saw it) and is logged here with its code.
pub fn salvage_truncated(
    result: Result<ChatResponse, LlmError>,
    stage: &str,
) -> Result<ChatResponse, LlmError> {
    match result {
        Err(LlmError::Truncated {
            requested,
            retried_at,
            partial,
        }) => {
            // Bound outside the macro: tracing skips evaluating its
            // arguments when no subscriber listens.
            let (code, reached) = (
                bc_llm_client::codes::TRUNCATED,
                retried_at.unwrap_or(requested),
            );
            tracing::warn!(
                "[{stage}] [{code}] reply still truncated at {reached} output tokens \
                 (asked {requested}); parsing the partial reply"
            );
            Ok(*partial)
        }
        other => other,
    }
}

#[cfg(test)]
mod salvage_tests {
    use super::*;

    fn partial(text: &str) -> ChatResponse {
        ChatResponse {
            content: vec![bc_llm_client::ContentBlock::Text(text.to_string())],
            stop_reason: StopReason::MaxTokens,
            usage: bc_llm_client::Usage::default(),
        }
    }

    #[test]
    fn a_truncated_error_yields_its_partial_reply() {
        let out = salvage_truncated(
            Err(LlmError::Truncated {
                requested: 100,
                retried_at: Some(200),
                partial: Box::new(partial("[{\"a\":1}, {\"b\"")),
            }),
            "s4",
        )
        .unwrap();
        assert_eq!(out.text(), "[{\"a\":1}, {\"b\"");
    }

    #[test]
    fn a_truncation_without_a_retry_reports_the_requested_budget() {
        let out = salvage_truncated(
            Err(LlmError::Truncated {
                requested: 100,
                retried_at: None,
                partial: Box::new(partial("x")),
            }),
            "s2",
        );
        assert_eq!(out.unwrap().text(), "x");
    }

    #[test]
    fn success_and_other_errors_pass_through() {
        assert_eq!(
            salvage_truncated(Ok(partial("ok")), "s3").unwrap().text(),
            "ok"
        );
        let err = salvage_truncated(
            Err(LlmError::Other {
                message: "boom".to_string(),
            }),
            "s3",
        )
        .unwrap_err();
        assert_eq!(
            err,
            LlmError::Other {
                message: "boom".to_string()
            }
        );
    }
}
