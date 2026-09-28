//! A scan-wide, operator-driven stop: the cooperative half of Ctrl-C.
//!
//! The Python original aborts a run on `KeyboardInterrupt`: it kills its
//! verifier subprocesses and unwinds, and no report is written. This port
//! stops the same way a budget does instead. Tripping the token makes every
//! stage's [`crate::BudgetGate`] answer "stop starting new work", in-flight
//! calls are left to finish, the orchestrator skips the stages that have
//! not started yet, and the partial report and run manifest are still
//! written, marked as canceled.
//!
//! Deliberately separate from a gate's own external trip
//! ([`crate::BudgetGate::trip`], which a stage uses for a quota it just
//! discovered): a quota stop is a fact about one stage's provider, while a
//! cancellation is a fact about the whole run, including the stages and
//! the remediation that have not started yet, and the report has to say
//! which of the two happened.
//!
//! No async runtime here (this crate is Tier-0), so a caller that needs to
//! wait for a cancellation polls [`CancelToken::is_canceled`]; the check
//! is one uncontended lock.

use std::sync::{Arc, Mutex};

/// The reason recorded for an operator's Ctrl-C, worded for the report's
/// `## Scan Health` section and the run manifest.
pub const USER_CANCEL_REASON: &str = "canceled by user (Ctrl-C)";

/// A latching, first-reason-wins stop signal shared by everything one run
/// does. See the module docs for how it differs from a budget gate's trip.
#[derive(Debug, Default)]
pub struct CancelToken {
    reason: Mutex<Option<String>>,
}

/// How a token is shared: the signal listener holds one clone, the scan
/// and every stage gate hold the others.
pub type CancelTokenRef = Arc<CancelToken>;

impl CancelToken {
    /// A fresh, untripped token, already behind the `Arc` every holder
    /// needs.
    pub fn new_ref() -> CancelTokenRef {
        Arc::new(CancelToken::default())
    }

    /// Trips the token. Returns `true` only for the call that actually
    /// tripped it: a second cancellation does not rewrite the first
    /// reason, which is the one that explains where the run stopped.
    pub fn cancel(&self, reason: impl Into<String>) -> bool {
        // `unwrap`: the guarded code is an `is_none` check and an
        // assignment, neither of which can panic, so the lock is never
        // poisoned.
        let mut slot = self.reason.lock().unwrap();
        if slot.is_some() {
            return false;
        }
        *slot = Some(reason.into());
        true
    }

    /// Why the run was canceled, or `None` while it has not been.
    pub fn reason(&self) -> Option<String> {
        self.reason.lock().unwrap().clone()
    }

    pub fn is_canceled(&self) -> bool {
        self.reason.lock().unwrap().is_some()
    }
}

/// The cancellation reason behind an optional token: `None` when there is
/// no token at all (every caller that never wired one) or it has not been
/// tripped. The one-liner stage boundaries ask.
pub fn canceled(token: Option<&CancelTokenRef>) -> Option<String> {
    token.and_then(|t| t.reason())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_token_is_not_canceled() {
        let token = CancelToken::new_ref();
        assert!(!token.is_canceled());
        assert_eq!(token.reason(), None);
        assert_eq!(canceled(Some(&token)), None);
        assert_eq!(canceled(None), None);
    }

    #[test]
    fn the_first_reason_wins_and_later_cancels_report_false() {
        let token = CancelToken::new_ref();
        assert!(token.cancel(USER_CANCEL_REASON));
        assert!(!token.cancel("something else"));
        assert!(token.is_canceled());
        assert_eq!(token.reason().as_deref(), Some(USER_CANCEL_REASON));
        assert_eq!(canceled(Some(&token)).as_deref(), Some(USER_CANCEL_REASON));
    }

    #[test]
    fn a_clone_of_the_ref_sees_the_cancellation() {
        let token = CancelToken::new_ref();
        let held = token.clone();
        token.cancel("stop");
        assert!(held.is_canceled());
    }
}
