use std::time::Duration;

use appsec_llm_client::LlmError;

const AUTH_BACKOFF: [Duration; 3] = [
    Duration::from_secs(2),
    Duration::from_secs(4),
    Duration::from_secs(8),
];

pub(crate) struct RetryLadder {
    max_transient: u32,
    base: Duration,
    transient: u32,
    auth: u32,
}

impl RetryLadder {
    pub(crate) fn new(max_transient: u32, base: Duration) -> Self {
        RetryLadder {
            max_transient,
            base,
            transient: 0,
            auth: 0,
        }
    }

    pub(crate) fn delay_for(&mut self, err: &LlmError, what: &'static str) -> Option<Duration> {
        let (attempt, max, delay) = match err {
            LlmError::Authentication { .. } if (self.auth as usize) < AUTH_BACKOFF.len() => {
                self.auth += 1;
                let delay = auth_backoff(self.auth, self.base);
                (self.auth, AUTH_BACKOFF.len() as u32, delay)
            }
            e if e.is_retryable() && self.transient < self.max_transient => {
                self.transient += 1;
                let delay = backoff_duration(e, self.transient, self.base);
                (self.transient, self.max_transient, delay)
            }
            _ => return None,
        };
        let delay_secs = delay.as_secs_f64();
        tracing::warn!(
            error = %err,
            attempt,
            max,
            delay_secs,
            what,
            "LLM call failed; retrying after backoff"
        );
        Some(delay)
    }
}

fn auth_backoff(attempt: u32, base: Duration) -> Duration {
    if base.is_zero() {
        return Duration::ZERO;
    }
    let index = (attempt as usize)
        .saturating_sub(1)
        .min(AUTH_BACKOFF.len() - 1);
    AUTH_BACKOFF[index]
}

pub(crate) fn backoff_duration(err: &LlmError, attempt: u32, base: Duration) -> Duration {
    if base.is_zero() {
        return Duration::ZERO;
    }
    let scheduled = base.saturating_mul(attempt).mul_f64(jitter_factor());
    if let LlmError::RateLimited {
        retry_after_secs: Some(secs),
    } = err
    {
        return Duration::from_secs(*secs).max(scheduled);
    }
    scheduled
}

fn jitter_factor() -> f64 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    0.75 + (nanos % 1000) as f64 / 1000.0 * 0.5
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth() -> LlmError {
        LlmError::Authentication {
            status: Some(401),
            message: "bad key".to_string(),
        }
    }

    fn down() -> LlmError {
        LlmError::ServerError {
            status: 503,
            message: "down".to_string(),
        }
    }

    #[test]
    fn authentication_gets_exactly_three_retries_at_two_four_and_eight_seconds() {
        let mut ladder = RetryLadder::new(0, Duration::from_secs(10));
        assert_eq!(ladder.delay_for(&auth(), "t"), Some(Duration::from_secs(2)));
        assert_eq!(ladder.delay_for(&auth(), "t"), Some(Duration::from_secs(4)));
        assert_eq!(ladder.delay_for(&auth(), "t"), Some(Duration::from_secs(8)));
        assert_eq!(ladder.delay_for(&auth(), "t"), None);
    }

    #[test]
    fn the_auth_and_transient_ladders_are_independent() {
        let mut ladder = RetryLadder::new(1, Duration::ZERO);
        assert_eq!(ladder.delay_for(&auth(), "t"), Some(Duration::ZERO));
        assert_eq!(ladder.delay_for(&down(), "t"), Some(Duration::ZERO));
        assert_eq!(ladder.delay_for(&down(), "t"), None);
        assert_eq!(ladder.delay_for(&auth(), "t"), Some(Duration::ZERO));
    }

    #[test]
    fn a_non_retryable_error_is_never_retried() {
        let mut ladder = RetryLadder::new(4, Duration::ZERO);
        let proxy = LlmError::ProxyOrTls {
            status: Some(407),
            message: "proxy".to_string(),
        };
        assert_eq!(ladder.delay_for(&proxy, "t"), None);
    }

    #[test]
    fn auth_backoff_is_zero_under_the_zero_base_switch_and_clamps_past_the_table() {
        assert_eq!(auth_backoff(1, Duration::ZERO), Duration::ZERO);
        assert_eq!(
            auth_backoff(9, Duration::from_secs(1)),
            Duration::from_secs(8)
        );
    }

    #[test]
    fn backoff_duration_is_zero_when_the_base_is_zero_even_for_a_real_retry_after() {
        let err = LlmError::RateLimited {
            retry_after_secs: Some(30),
        };
        assert_eq!(backoff_duration(&err, 1, Duration::ZERO), Duration::ZERO);
    }

    #[test]
    fn backoff_duration_honors_a_real_retry_after_value_unjittered() {
        let err = LlmError::RateLimited {
            retry_after_secs: Some(30),
        };
        assert_eq!(
            backoff_duration(&err, 2, Duration::from_secs(10)),
            Duration::from_secs(30)
        );
    }

    #[test]
    fn backoff_duration_waits_the_schedule_out_when_it_exceeds_retry_after() {
        let err = LlmError::RateLimited {
            retry_after_secs: Some(1),
        };
        let got = backoff_duration(&err, 3, Duration::from_secs(10));
        assert!(got >= Duration::from_millis(22_500) && got < Duration::from_millis(37_500));
    }

    #[test]
    fn backoff_duration_falls_back_to_jittered_linear_backoff_without_a_retry_after_value() {
        let err = LlmError::RateLimited {
            retry_after_secs: None,
        };
        let base = Duration::from_secs(10);
        let got = backoff_duration(&err, 2, base);
        assert!(got >= Duration::from_secs(15) && got < Duration::from_secs(25));
    }

    #[test]
    fn backoff_duration_jitters_a_non_rate_limited_retryable_error_too() {
        let base = Duration::from_secs(10);
        let got = backoff_duration(&down(), 1, base);
        assert!(got >= Duration::from_millis(7500) && got < Duration::from_millis(12500));
    }

    #[test]
    fn jitter_factor_is_always_within_the_documented_range() {
        for _ in 0..20 {
            let f = jitter_factor();
            assert!((0.75..1.25).contains(&f), "{f} out of range");
        }
    }

    #[test]
    fn a_small_retry_after_hint_does_not_shortcut_the_growing_schedule() {
        let err = LlmError::RateLimited {
            retry_after_secs: Some(1),
        };
        let d = backoff_duration(&err, 3, Duration::from_secs(10));
        assert!(d >= Duration::from_secs(22), "{d:?}");
    }

    #[test]
    fn a_large_retry_after_hint_is_honored_as_the_floor() {
        let err = LlmError::RateLimited {
            retry_after_secs: Some(120),
        };
        let d = backoff_duration(&err, 1, Duration::from_secs(10));
        assert_eq!(d, Duration::from_secs(120));
    }
}
