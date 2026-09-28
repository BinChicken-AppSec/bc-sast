//! The `CheckpointStore` trait boundary, ported from
//! `vvaharness/orchestrator/checkpoints.py`'s save/load contract.
//!
//! [`NullCheckpointStore`] remains the right choice for anything that
//! doesn't need `--resume` support. [`SqliteCheckpointStore`] (Phase 2)
//! is a pure addition alongside it: the trait existed from day one
//! precisely so this landed with zero call-site changes in the
//! orchestrator or stage crates.

mod engine_key;
mod error;
mod null_store;
mod sqlite_store;
mod store;

pub use engine_key::{step_key_for, EngineKey};
pub use error::CheckpointError;
pub use null_store::NullCheckpointStore;
pub use sqlite_store::{default_db_path, run_id_for, SqliteCheckpointStore};
pub use store::CheckpointStore;
