//! When a failed call is worth sending again, and how long to wait
//! first: the retry decisions [`crate::chat_with_retry`] and
//! [`crate::run_agentic`]'s per-turn loop share, kept in one place so the
//! two cannot drift apart.

use std::time::Duration;

use bc_llm_client::LlmError;

/// The fixed, short waits before each authentication retry, from the
/// Python original's `_AUTH_BACKOFF_SDK`/`_AUTH_BACKOFF_OAI` (2, 4, 8 s).
/// An authentication failure is synchronous, so the long transient
/// schedule is the wrong tool; three quick retries ride out a credential
/// that is mid-rotation, and anything longer lasting halts the scan.
const AUTH_BACKOFF: [Duration; 3] = [
    Duration::from_secs(2),
    Duration::from_secs(4),
    Duration::from_secs(8),
];

/// Per-call retry bookkeeping: the transient ladder (capped at
/// `max_transient`) and the separate authentication ladder
/// ([`AUTH_BACKOFF`]), counted independently as Python counts them.
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

    /// How long to wait before sending the same request again after `err`,
    /// or `None` when it should propagate now. Logs the retry at `WARN`:
    /// a stalled scan's retries are otherwise invisible (a 2026-09 CI run
    /// spent 80 minutes retrying a provider error and emitted nothing),
    /// and `WARN` is the level both of `bc_cli::logging`'s destinations
    /// show by default. `what` names the caller in that line.
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
        // Bound outside the macro, not inline as a field value: `tracing`
        // only evaluates field expressions when a subscriber is listening,
        // so an inline call would be dead code in every test (and this
        // crate's coverage gate is 100 %).
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

/// The wait before authentication retry `attempt` (1-indexed). A zero
/// `base` is this codebase's "never really sleep" switch (see
/// [`backoff_duration`]) and wins here too.
fn auth_backoff(attempt: u32, base: Duration) -> Duration {
    if base.is_zero() {
        return Duration::ZERO;
    }
    let index = (attempt as usize)
        .saturating_sub(1)
        .min(AUTH_BACKOFF.len() - 1);
    AUTH_BACKOFF[index]
}

/// The delay before retry attempt `attempt` (1-indexed) after `err`.
/// `base == Duration::ZERO` is this codebase's established "disable all
/// real sleeping" switch (used pervasively in tests) and always wins,
/// short-circuiting before either the header check or the syscall
/// jitter needs — real callers always pass a non-zero base. Otherwise, a
/// [`LlmError::RateLimited`] carrying a real `Retry-After` value wins
/// outright (the provider's own stated wait time, un-jittered — jittering
/// it down risks re-triggering the same rate limit). Absent that, falls
/// back to `base * attempt` (linear backoff) with up to ±25% jitter, so
/// concurrent callers hitting the same transient failure at once (e.g.
/// S6's per-finding fan-out) don't all wake and retry in lockstep — the
/// thundering-herd risk a fixed schedule invites under real concurrency.
pub(crate) fn backoff_duration(err: &LlmError, attempt: u32, base: Duration) -> Duration {
    if base.is_zero() {
        return Duration::ZERO;
    }
    let scheduled = base.saturating_mul(attempt).mul_f64(jitter_factor());
    if let LlmError::RateLimited {
        retry_after_secs: Some(secs),
    } = err
    {
        // The server's hint is a MINIMUM, not a schedule. Honoring a 1 s
        // `Retry-After` verbatim on every attempt burns the whole retry
        // budget in a few seconds under sustained saturation: a live
        // 2026-09-06 scan lost 24 of 235 verifications to "rate limited
        // (retry after 1s)" that way, with five verifiers in flight.
        // Waiting at least as long as the growing schedule is always
        // allowed and is what actually lets the window recover.
        return Duration::from_secs(*secs).max(scheduled);
    }
    scheduled
}

/// A multiplier in `[0.75, 1.25)`, seeded from the low bits of the
/// current time — no RNG dependency needed for this purpose (avoiding
/// synchronized retries, not cryptographic unpredictability): concurrent
/// callers each read the clock at very slightly different instants, so
/// their jitter naturally decorrelates.
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

    // ── RetryLadder ─────────────────────────────────────────────────────

    #[test]
    fn authentication_gets_exactly_three_retries_at_two_four_and_eight_seconds() {
        let mut ladder = RetryLadder::new(0, Duration::from_secs(10));
        assert_eq!(ladder.delay_for(&auth(), "t"), Some(Duration::from_secs(2)));
        assert_eq!(ladder.delay_for(&auth(), "t"), Some(Duration::from_secs(4)));
        assert_eq!(ladder.delay_for(&auth(), "t"), Some(Duration::from_secs(8)));
        assert_eq!(ladder.delay_for(&auth(), "t"), None);
    }

    /// The two ladders are counted apart: a transient budget of zero does
    /// not starve the auth ladder, and auth retries do not spend the
    /// transient budget.
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

    // ── backoff_duration / jitter_factor ────────────────────────────────

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
        // attempt 2 -> linear = 20s, jittered to within [15s, 25s), so the
        // 30s server hint dominates for every jitter value. Picking an
        // attempt whose jittered schedule could exceed the hint would make
        // this assertion pass only about half the time.
        assert_eq!(
            backoff_duration(&err, 2, Duration::from_secs(10)),
            Duration::from_secs(30)
        );
    }

    #[test]
    fn backoff_duration_waits_the_schedule_out_when_it_exceeds_retry_after() {
        // The 1s hint is the live case the schedule exists to defend
        // against: honoring it verbatim burns the retry budget in seconds.
        let err = LlmError::RateLimited {
            retry_after_secs: Some(1),
        };
        let got = backoff_duration(&err, 3, Duration::from_secs(10));
        // attempt 3 -> linear = 30s, jittered to within [22.5s, 37.5s),
        // every value of which outlasts the hint.
        assert!(got >= Duration::from_millis(22_500) && got < Duration::from_millis(37_500));
    }

    #[test]
    fn backoff_duration_falls_back_to_jittered_linear_backoff_without_a_retry_after_value() {
        let err = LlmError::RateLimited {
            retry_after_secs: None,
        };
        let base = Duration::from_secs(10);
        let got = backoff_duration(&err, 2, base);
        // attempt 2 -> linear = 20s, jittered to within [15s, 25s).
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
        // attempt 3 at a 10 s base is ~30 s ± 25 % jitter — far more than the
        // 1 s hint, which is a floor and must not win.
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
