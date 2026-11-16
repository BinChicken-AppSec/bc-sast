use crate::error::CheckpointError;

pub trait CheckpointStore: Send + Sync {
    fn save(&self, run_id: &str, step: &str, payload: &[u8]) -> Result<(), CheckpointError>;

    fn load(&self, run_id: &str, step: &str) -> Option<Vec<u8>>;

    fn register_run(
        &self,
        _run_id: &str,
        _repo_root: &str,
        _repo_name: Option<&str>,
        _app_id: Option<&str>,
    ) {
    }

    fn reset_run(&self, _run_id: &str) -> usize {
        0
    }

    fn prune_stale(&self, _run_id: &str, _prefix: &str, _live_keys: &[String]) -> Vec<String> {
        Vec::new()
    }
}
