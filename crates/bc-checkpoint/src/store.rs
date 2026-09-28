use crate::error::CheckpointError;

/// Resume-state persistence, ported from the *contract* of
/// `orchestrator/checkpoints.py`'s `save_ckpt`/`load_ckpt`: keyed by
/// `(run_id, step)` — `run_id` derived per scanned-repo-path, `step` a
/// fixed stage name (`"s1"`..`"s9"`) or a dynamic per-finding key
/// (`"remediate_<digest>"`, `"validate_<digest>"`, see
/// [`crate::step_key_for`]) — carrying already-serialized
/// JSON bytes rather than a generic type, so the trait stays `dyn`-safe
/// (a real implementation is selected at runtime from config, the same
/// reason `LlmClient` in `bc-llm-client` is `dyn`-dispatched rather than
/// generic).
///
/// [`crate::SqliteCheckpointStore`] is the real, persistent
/// implementation `bc-cli` opens by default (`open_checkpoint_store`);
/// [`crate::NullCheckpointStore`] remains available as an explicit
/// no-checkpointing choice (tests, or any embedder that doesn't want
/// `--resume` support at all). Landing the SQLite-backed store required
/// zero call-site changes in the orchestrator or stage crates — this
/// trait existed from day one precisely so that swap-in was a pure
/// addition, mirroring how `CheckpointStore` in the Python original is a
/// stable interface `scan_repo()` calls uniformly regardless of backend.
pub trait CheckpointStore: Send + Sync {
    /// Persist `payload` under `(run_id, step)`. A failure here is
    /// non-fatal to the overall scan — callers should log it and proceed
    /// as though this step's checkpoint is simply unavailable on a later
    /// resume, matching `save_ckpt`'s own "log and skip" treatment of an
    /// oversized or failed write.
    fn save(&self, run_id: &str, step: &str, payload: &[u8]) -> Result<(), CheckpointError>;

    /// Load the payload for `(run_id, step)`. Every failure mode —
    /// absent, corrupted, or otherwise unusable — collapses to `None`
    /// rather than an `Err`, matching `load_ckpt`'s "never raises, always
    /// degrades to re-run this step" contract exactly: a caller can
    /// always treat `None` as "just run the step" with no separate error
    /// path to handle.
    fn load(&self, run_id: &str, step: &str) -> Option<Vec<u8>>;

    /// Upsert this run's metadata row (`repo_root`/`repo_name`/`app_id`,
    /// bumping `updated_at`) — ported from `store.py::register_run`.
    /// Called once per invocation that uses checkpoints at all, so a
    /// later `gc` pass (age/count pruning) can rank runs by recency. A
    /// no-op default for a store with no run-metadata concept of its own
    /// (e.g. [`crate::NullCheckpointStore`]) — matching `save`/`load`'s
    /// own "a failure here is never fatal" spirit, since this is
    /// bookkeeping for `gc`, not something a scan's correctness depends
    /// on.
    fn register_run(
        &self,
        _run_id: &str,
        _repo_root: &str,
        _repo_name: Option<&str>,
        _app_id: Option<&str>,
    ) {
    }

    /// Clear every checkpoint row for `run_id` — both the fixed step keys
    /// and the dynamic per-finding (`remediate_<digest>`) ones — ported from
    /// `store.py::reset_run`. Called by a FRESH (non-`--resume`) run so
    /// stale rows from an earlier run of the same repo (same `run_id`,
    /// since it's derived purely from the resolved repo path) can never
    /// be loaded by a LATER `--resume`. The run's own metadata row (see
    /// [`Self::register_run`]) is deliberately left alone — only its
    /// checkpoints are cleared. Returns how many rows were cleared; a
    /// no-op (`0`) default.
    fn reset_run(&self, _run_id: &str) -> usize {
        0
    }

    /// Delete every checkpoint row of `run_id` whose step starts with
    /// `prefix` but is not one of `live_keys`, returning the removed step
    /// keys. Ported from `checkpoints.py::prune_stale_steps`.
    ///
    /// Engine-keyed steps ([`crate::step_key_for`]) are never overwritten
    /// by a run under a different model or engine version; they just stop
    /// being found. Without a prune they would accumulate for as long as
    /// the run id lives, and a `--resume` that switched back to the old
    /// model would find a result nobody expects it to. Callers pass the
    /// keys the CURRENT run will use, so only rows no live finding claims
    /// go. Best effort, like every other store write: a failure removes
    /// nothing and is never fatal. A no-op (nothing removed) default.
    fn prune_stale(&self, _run_id: &str, _prefix: &str, _live_keys: &[String]) -> Vec<String> {
        Vec::new()
    }
}
