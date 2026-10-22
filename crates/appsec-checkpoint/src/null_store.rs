use crate::error::CheckpointError;
use crate::store::CheckpointStore;

/// The only [`CheckpointStore`] Phase 1 ships: saves nothing, and every
/// load is a miss. `--stop-after` still works with this in place (it's
/// independent, plain control flow in the orchestrator's stage loop) —
/// what's absent is `--resume` actually skipping already-done work, which
/// is a pure Phase 2 addition.
#[derive(Debug, Clone, Copy)]
pub struct NullCheckpointStore;

impl CheckpointStore for NullCheckpointStore {
    fn save(&self, _run_id: &str, _step: &str, _payload: &[u8]) -> Result<(), CheckpointError> {
        Ok(())
    }

    fn load(&self, _run_id: &str, _step: &str) -> Option<Vec<u8>> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_always_succeeds() {
        assert_eq!(NullCheckpointStore.save("run1", "s1", b"payload"), Ok(()));
    }

    #[test]
    fn load_is_always_a_miss() {
        assert_eq!(NullCheckpointStore.load("run1", "s1"), None);
    }

    #[test]
    fn a_save_followed_by_a_load_of_the_same_key_still_misses() {
        let store = NullCheckpointStore;
        store.save("run1", "s1", b"payload").unwrap();
        assert_eq!(store.load("run1", "s1"), None);
    }

    #[test]
    fn is_usable_as_a_trait_object() {
        let store: Box<dyn CheckpointStore> = Box::new(NullCheckpointStore);
        assert_eq!(store.load("run1", "s1"), None);
    }

    #[test]
    fn is_copyable_and_debug() {
        let a = NullCheckpointStore;
        let b = a; // Copy
        assert_eq!(format!("{a:?}"), format!("{b:?}"));
    }

    #[test]
    fn register_run_default_is_a_no_op() {
        // Nothing to assert beyond "doesn't panic" — this store has no
        // run-metadata concept to observe.
        NullCheckpointStore.register_run("run1", "/repo", Some("demo"), Some("app-1"));
    }

    #[test]
    fn reset_run_default_clears_nothing() {
        assert_eq!(NullCheckpointStore.reset_run("run1"), 0);
    }

    #[test]
    fn prune_stale_default_removes_nothing() {
        assert!(NullCheckpointStore
            .prune_stale("run1", "remediate_", &[])
            .is_empty());
    }
}
