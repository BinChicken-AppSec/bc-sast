use std::fmt;

/// A checkpoint-store failure. Ported from the *shape* of
/// `orchestrator/checkpoints.py::save_ckpt`'s failure modes (oversized
/// payload, underlying store I/O error) — unlike the Python original,
/// which logs and silently continues, this is a typed `Err` so a caller
/// can decide how to react; [`crate::NullCheckpointStore`] never produces
/// one, since it never persists anything to fail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointError {
    pub message: String,
}

impl CheckpointError {
    pub fn new(message: impl Into<String>) -> Self {
        CheckpointError {
            message: message.into(),
        }
    }
}

impl fmt::Display for CheckpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for CheckpointError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_shows_the_message() {
        assert_eq!(CheckpointError::new("disk full").to_string(), "disk full");
    }

    #[test]
    fn implements_std_error() {
        let e = CheckpointError::new("x");
        let _: &dyn std::error::Error = &e;
    }

    #[test]
    fn is_cloneable_and_comparable() {
        let a = CheckpointError::new("x");
        let b = a.clone();
        assert_eq!(a, b);
    }
}
