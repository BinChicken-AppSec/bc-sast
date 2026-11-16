use std::sync::{Arc, Mutex};

pub const USER_CANCEL_REASON: &str = "canceled by user (Ctrl-C)";

#[derive(Debug, Default)]
pub struct CancelToken {
    reason: Mutex<Option<String>>,
}

pub type CancelTokenRef = Arc<CancelToken>;

impl CancelToken {
    pub fn new_ref() -> CancelTokenRef {
        Arc::new(CancelToken::default())
    }

    pub fn cancel(&self, reason: impl Into<String>) -> bool {
        let mut slot = self.reason.lock().unwrap();
        if slot.is_some() {
            return false;
        }
        *slot = Some(reason.into());
        true
    }

    pub fn reason(&self) -> Option<String> {
        self.reason.lock().unwrap().clone()
    }

    pub fn is_canceled(&self) -> bool {
        self.reason.lock().unwrap().is_some()
    }
}

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
