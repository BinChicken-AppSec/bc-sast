use appsec_llm_client::{ChatResponse, LlmError, StopReason};

const TRUNCATION_RETRY_MULTIPLIER: u32 = 2;

fn retry_budget(requested: u32, ceiling: Option<u32>) -> Option<u32> {
    let doubled = requested.saturating_mul(TRUNCATION_RETRY_MULTIPLIER);
    let budget = ceiling.map_or(doubled, |cap| doubled.min(cap));
    (budget > requested).then_some(budget)
}

fn is_output_cap_rejection(err: &LlmError) -> bool {
    let (LlmError::InvalidRequest { message } | LlmError::ContextOverflow { message }) = err else {
        return false;
    };
    let lower = message.to_ascii_lowercase();
    ["max_tokens", "max_completion_tokens", "max_output_tokens"]
        .iter()
        .any(|name| lower.contains(name))
}

#[derive(Debug, PartialEq)]
pub(crate) enum Verdict {
    Done(ChatResponse),
    Retry,
    GiveUp(LlmError),
}

pub(crate) struct TruncationGuard {
    requested: u32,
    ceiling: Option<u32>,
    retried_at: Option<u32>,
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

    pub(crate) fn max_tokens(&self) -> u32 {
        self.retried_at.unwrap_or(self.requested)
    }

    pub(crate) fn on_response(&mut self, response: ChatResponse) -> Verdict {
        if response.stop_reason != StopReason::MaxTokens {
            return Verdict::Done(response);
        }
        if self.retried_at.is_none() {
            if let Some(budget) = retry_budget(self.requested, self.ceiling) {
                tracing::warn!(
                    code = appsec_llm_client::codes::TRUNCATED,
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
    use appsec_llm_client::{ContentBlock, Usage};

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
            let (code, reached) = (
                appsec_llm_client::codes::TRUNCATED,
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
            content: vec![appsec_llm_client::ContentBlock::Text(text.to_string())],
            stop_reason: StopReason::MaxTokens,
            usage: appsec_llm_client::Usage::default(),
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
