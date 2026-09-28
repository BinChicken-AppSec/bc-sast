//! SQLite-backed [`CheckpointStore`], ported from `orchestrator/store.py`
//! and `orchestrator/checkpoints.py`'s `save_ckpt`/`load_ckpt` contract —
//! Phase 2's persistent implementation, enabling `--resume` for S10
//! remediation runs. `NullCheckpointStore` remains the right choice for
//! anything that doesn't need resume support; this is a pure addition,
//! not a replacement.
//!
//! **Deliberate divergence from the Python original**: `run_id_for` uses
//! SHA-1 (via the already-vetted `sha1` crate this workspace already
//! depends on for `bc-repo-analysis`'s config-dedup clustering key)
//! instead of Python's SHA-256. The run id only needs to be a stable,
//! non-reversible, effectively-unpredictable identifier derived from a
//! repo path — not a security control requiring collision resistance —
//! so reusing an already-present dependency was preferred over adding a
//! new one (`sha2`) for this narrow need. The two ports' checkpoint
//! databases are entirely separate on-disk artifacts; nothing requires
//! their run ids to match byte-for-byte.

use std::path::{Path, PathBuf};

use rusqlite::{params, Connection};
use sha1::{Digest, Sha1};

use crate::error::CheckpointError;
use crate::store::CheckpointStore;

/// No legitimate checkpoint this port produces approaches this size; an
/// oversized payload is either corruption or a resource-exhaustion
/// attempt. Enforced at save time AND by a `CHECK` constraint on
/// `checkpoints.size`, so a hostile direct `INSERT` is also rejected.
const MAX_PAYLOAD_BYTES: usize = 100 * 1024 * 1024;

// `checkpoints` deliberately has NO `REFERENCES runs(run_id)` — SQLite
// can't add a foreign key to an already-existing table without a full
// rebuild, and this table predates `runs` in this port's own schema
// history (unlike the Python original, where `runs` shipped in schema
// v1 from the start). Cascading a `runs` row's delete onto its
// checkpoints is instead done explicitly, in application code
// ([`SqliteCheckpointStore::delete_run`]) — see that method's own doc
// comment. This sidesteps the whole migration question: both tables are
// `CREATE TABLE IF NOT EXISTS`, additive-only, safe to run against an
// existing `checkpoints`-only database from before this field shipped.
const DDL: &str = "
CREATE TABLE IF NOT EXISTS checkpoints (
  run_id     TEXT    NOT NULL,
  step       TEXT    NOT NULL,
  payload    BLOB    NOT NULL,
  size       INTEGER NOT NULL CHECK (size <= 104857600),
  created_at TEXT    NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (run_id, step)
);

CREATE TABLE IF NOT EXISTS runs (
  run_id     TEXT PRIMARY KEY,
  repo_root  TEXT NOT NULL,
  repo_name  TEXT,
  app_id     TEXT,
  started_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS ix_runs_updated ON runs(updated_at);
";

const PRAGMAS: &str = "PRAGMA journal_mode = WAL; \
     PRAGMA foreign_keys = ON; \
     PRAGMA busy_timeout = 30000; \
     PRAGMA synchronous = NORMAL;";

impl From<rusqlite::Error> for CheckpointError {
    fn from(e: rusqlite::Error) -> Self {
        CheckpointError::new(e.to_string())
    }
}

/// Resolves the state DB path: `$BC_STATE_DIR/bc-sast.db`, or
/// `$HOME/.bc-sast/state/bc-sast.db` if unset — matching Python's
/// `store.db_path`. Creates the parent directory if it doesn't exist yet.
pub fn default_db_path() -> Result<PathBuf, CheckpointError> {
    let root = match std::env::var("BC_STATE_DIR") {
        Ok(v) if !v.is_empty() => PathBuf::from(v),
        _ => {
            let home = std::env::var("HOME")
                .map_err(|_| CheckpointError::new("cannot resolve state dir: HOME is not set"))?;
            PathBuf::from(home).join(".bc-sast").join("state")
        }
    };
    std::fs::create_dir_all(&root).map_err(|e| {
        CheckpointError::new(format!("cannot create state dir {}: {e}", root.display()))
    })?;
    Ok(root.join("bc-sast.db"))
}

/// Stable, non-reversible run id derived from a repo path (SHA-1 hex of
/// the resolved absolute path, truncated to 32 hex chars — matching the
/// Python original's own 32-char truncation, see the module doc comment
/// for why SHA-1 rather than SHA-256). Falls back to hashing the raw
/// (unresolved) path string if the path doesn't exist / can't be
/// canonicalized, rather than failing — a checkpoint run id must always
/// be derivable, even for a not-yet-created target.
pub fn run_id_for(repo: &Path) -> String {
    let canonical = std::fs::canonicalize(repo).unwrap_or_else(|_| repo.to_path_buf());
    let mut hasher = Sha1::new();
    hasher.update(canonical.to_string_lossy().as_bytes());
    let digest: String = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    digest[..32].to_string()
}

/// A persistent, SQLite-backed [`CheckpointStore`] — a single-file
/// database holding per-run checkpoint blobs. Opens a fresh connection
/// per operation rather than holding one open: `rusqlite::Connection` is
/// not `Sync`-shareable across threads by default, and per-call
/// connections are cheap enough here (sub-millisecond local file I/O)
/// that this avoids needing a connection pool for what's fundamentally a
/// low-throughput, single-process resume-state store. The schema is
/// bootstrapped once, eagerly, at construction ([`Self::new`]) rather
/// than on every connection — `save`/`load` only need a lighter,
/// already-bootstrapped-schema connection (see [`Self::connect`]).
#[derive(Debug)]
pub struct SqliteCheckpointStore {
    db_path: PathBuf,
}

impl SqliteCheckpointStore {
    /// Opens (creating if absent) the state DB at `db_path`, bootstrapping
    /// the schema eagerly so construction fails fast on a genuinely
    /// unusable path rather than deferring the error to the first `save`.
    pub fn new(db_path: impl Into<PathBuf>) -> Result<Self, CheckpointError> {
        let store = SqliteCheckpointStore {
            db_path: db_path.into(),
        };
        let con = store.open()?;
        con.execute_batch(DDL)?;
        Ok(store)
    }

    /// Opens the store at the default state-dir location (see
    /// [`default_db_path`]).
    pub fn open_default() -> Result<Self, CheckpointError> {
        Self::new(default_db_path()?)
    }

    /// Opens a connection and applies the standard PRAGMAs, without
    /// touching the schema — [`Self::new`] is solely responsible for
    /// schema bootstrap, so `save`/`load` never re-run `DDL` on every
    /// call.
    fn connect(&self) -> Result<Connection, CheckpointError> {
        let con = self.open()?;
        con.execute_batch(PRAGMAS)?;
        Ok(con)
    }

    fn open(&self) -> Result<Connection, CheckpointError> {
        Connection::open(&self.db_path).map_err(|e| {
            CheckpointError::new(format!(
                "cannot open state db {}: {e}",
                self.db_path.display()
            ))
        })
    }
}

impl CheckpointStore for SqliteCheckpointStore {
    fn save(&self, run_id: &str, step: &str, payload: &[u8]) -> Result<(), CheckpointError> {
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(CheckpointError::new(format!(
                "{step} payload {} bytes exceeds {MAX_PAYLOAD_BYTES}; not persisted",
                payload.len()
            )));
        }
        let con = self.connect()?;
        con.execute(
            "INSERT OR REPLACE INTO checkpoints(run_id, step, payload, size) \
             VALUES (?1, ?2, ?3, ?4)",
            params![run_id, step, payload, payload.len() as i64],
        )?;
        Ok(())
    }

    fn load(&self, run_id: &str, step: &str) -> Option<Vec<u8>> {
        let con = self.connect().ok()?;
        con.query_row(
            "SELECT payload FROM checkpoints WHERE run_id = ?1 AND step = ?2",
            params![run_id, step],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .ok()
    }

    fn register_run(
        &self,
        run_id: &str,
        repo_root: &str,
        repo_name: Option<&str>,
        app_id: Option<&str>,
    ) {
        // Best-effort, matching `save`'s own "never fatal" contract —
        // this is `gc`-ranking bookkeeping, not something a scan's own
        // correctness depends on.
        let Ok(con) = self.connect() else {
            return;
        };
        let _ = con.execute(
            "INSERT INTO runs(run_id, repo_root, repo_name, app_id) \
             VALUES (?1, ?2, ?3, ?4) \
             ON CONFLICT(run_id) DO UPDATE SET \
               repo_root = excluded.repo_root, \
               repo_name = excluded.repo_name, \
               app_id    = excluded.app_id, \
               updated_at = datetime('now')",
            params![run_id, repo_root, repo_name, app_id],
        );
    }

    fn reset_run(&self, run_id: &str) -> usize {
        let Ok(con) = self.connect() else {
            return 0;
        };
        con.execute("DELETE FROM checkpoints WHERE run_id = ?1", params![run_id])
            .unwrap_or(0)
    }

    fn prune_stale(&self, run_id: &str, prefix: &str, live_keys: &[String]) -> Vec<String> {
        self.try_prune_stale(run_id, prefix, live_keys)
            .unwrap_or_default()
    }
}

impl SqliteCheckpointStore {
    /// [`CheckpointStore::prune_stale`] with its errors visible, so the
    /// trait method can stay best effort while every failure path is still
    /// a plain `?`. The prefix is compared with `substr`, not `LIKE`, so
    /// the `_` in `remediate_` is a literal rather than a wildcard.
    fn try_prune_stale(
        &self,
        run_id: &str,
        prefix: &str,
        live_keys: &[String],
    ) -> Result<Vec<String>, CheckpointError> {
        let mut con = self.connect()?;
        let tx = con.transaction()?;
        let stale: Vec<String> = {
            let mut stmt = tx.prepare(
                "SELECT step FROM checkpoints \
                 WHERE run_id = ?1 AND substr(step, 1, length(?2)) = ?2 ORDER BY step",
            )?;
            let steps = stmt
                .query_map(params![run_id, prefix], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<String>, _>>()?;
            steps
                .into_iter()
                .filter(|step| !live_keys.contains(step))
                .collect()
        };
        for step in &stale {
            tx.execute(
                "DELETE FROM checkpoints WHERE run_id = ?1 AND step = ?2",
                params![run_id, step],
            )?;
        }
        tx.commit()?;
        Ok(stale)
    }
}

/// What one `prune` call (age/count-based `gc`) did or would do —
/// ported from `checkpoints.py::prune_checkpoints`'s return dict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PruneReport {
    pub db_path: PathBuf,
    /// Runs NOT selected for deletion (`kept = total - deleted.len()`).
    pub kept: usize,
    /// Run ids deleted (or, under `dry_run`, that WOULD be deleted),
    /// oldest-`updated_at`-first.
    pub deleted: Vec<String>,
}

impl SqliteCheckpointStore {
    /// The `gc`-only surface: fully evict one run (its `runs` row plus
    /// every checkpoint row for it) — ported from `store.py::delete_run`.
    /// Unlike [`CheckpointStore::reset_run`] (a per-scan hot-path
    /// operation that keeps the `runs` row and skips reclaiming space),
    /// this is an on-demand `gc` action: it also runs
    /// `incremental_vacuum` and `wal_checkpoint(TRUNCATE)` afterward to
    /// actually reclaim the freed pages. Returns whether a `runs` row
    /// was found and deleted.
    pub fn delete_run(&self, run_id: &str) -> Result<bool, CheckpointError> {
        let mut con = self.connect()?;
        let deleted = {
            let tx = con.transaction()?;
            tx.execute("DELETE FROM checkpoints WHERE run_id = ?1", params![run_id])?;
            let deleted = tx.execute("DELETE FROM runs WHERE run_id = ?1", params![run_id])?;
            tx.commit()?;
            deleted
        };
        if deleted > 0 {
            con.execute_batch("PRAGMA incremental_vacuum; PRAGMA wal_checkpoint(TRUNCATE);")?;
        }
        Ok(deleted > 0)
    }

    /// Age/count-based `gc`: deletes every `runs` row (and, via
    /// [`Self::delete_run`]'s same two-statement cascade, its
    /// checkpoints) either older than `max_age_days` OR beyond the
    /// `keep_runs` most-recent by `updated_at` — ported from
    /// `checkpoints.py::prune_checkpoints`. `dry_run` reports the same
    /// victim set without touching the database. Only this state store
    /// is touched — `<repo>/security-scan/` output is never affected.
    pub fn prune(
        &self,
        keep_runs: usize,
        max_age_days: i64,
        dry_run: bool,
    ) -> Result<PruneReport, CheckpointError> {
        let mut con = self.connect()?;
        let total: i64 = con.query_row("SELECT COUNT(*) FROM runs", [], |row| row.get(0))?;
        let age_expr = format!("-{max_age_days} days");
        let victims: Vec<String> = {
            let mut stmt = con.prepare(
                "SELECT run_id FROM runs \
                 WHERE updated_at < datetime('now', ?1) \
                    OR run_id NOT IN ( \
                         SELECT run_id FROM runs \
                         ORDER BY updated_at DESC LIMIT ?2) \
                 ORDER BY updated_at",
            )?;
            let rows = stmt
                .query_map(params![age_expr, keep_runs as i64], |row| {
                    row.get::<_, String>(0)
                })?
                .collect::<Result<Vec<String>, _>>()?;
            rows
        };
        if !dry_run && !victims.is_empty() {
            {
                let tx = con.transaction()?;
                for run_id in &victims {
                    // `checkpoints` has no FK cascade onto `runs` (see the
                    // module doc comment on `DDL`) — both statements are
                    // needed per victim, same as `delete_run`.
                    tx.execute("DELETE FROM checkpoints WHERE run_id = ?1", params![run_id])?;
                    tx.execute("DELETE FROM runs WHERE run_id = ?1", params![run_id])?;
                }
                tx.commit()?;
            }
            con.execute_batch("PRAGMA incremental_vacuum; PRAGMA wal_checkpoint(TRUNCATE);")?;
        }
        Ok(PruneReport {
            db_path: self.db_path.clone(),
            kept: (total as usize).saturating_sub(victims.len()),
            deleted: victims,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // `cargo test` runs a binary's tests on a thread pool by default, so
    // any test that mutates a process-global env var must serialize
    // against every other such test, not just restore its own prior
    // value — otherwise two of these running concurrently can interleave
    // their set/read/restore sequences. Both `BC_STATE_DIR` and
    // `HOME` tests share this one lock.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    // Factored out so each restore call site is a single line covered by
    // whichever of the tests below happens to run it — both of THIS
    // function's own branches only need covering once, by any test
    // (see `restore_env_*` below), rather than duplicating the Some/None
    // match (and the burden of exercising both arms of it, which ambient
    // state like an always-set `$HOME` would make impossible in practice)
    // at every call site.
    fn restore_env(name: &str, prior: Option<String>) {
        match prior {
            Some(v) => unsafe { std::env::set_var(name, v) },
            None => unsafe { std::env::remove_var(name) },
        }
    }

    fn restore_state_dir_env(prior: Option<String>) {
        restore_env("BC_STATE_DIR", prior)
    }

    #[test]
    fn restore_env_restores_a_prior_value() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("BC_CHECKPOINT_TEST_ENV_VAR", "temp");
        }
        restore_env("BC_CHECKPOINT_TEST_ENV_VAR", Some("prior".to_string()));
        assert_eq!(
            std::env::var("BC_CHECKPOINT_TEST_ENV_VAR").unwrap(),
            "prior"
        );
        unsafe {
            std::env::remove_var("BC_CHECKPOINT_TEST_ENV_VAR");
        }
    }

    #[test]
    fn restore_env_removes_the_var_when_there_was_no_prior_value() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("BC_CHECKPOINT_TEST_ENV_VAR", "temp");
        }
        restore_env("BC_CHECKPOINT_TEST_ENV_VAR", None);
        assert!(std::env::var("BC_CHECKPOINT_TEST_ENV_VAR").is_err());
    }

    fn store() -> (tempfile::TempDir, SqliteCheckpointStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteCheckpointStore::new(dir.path().join("state.db")).unwrap();
        (dir, store)
    }

    /// Backdates a run's `updated_at` directly (bypassing `register_run`,
    /// which always stamps "now") — the only way to deterministically
    /// exercise `prune`'s age-based branch without a real sleep.
    fn backdate(db_path: &Path, run_id: &str, days_ago: i64) {
        let con = Connection::open(db_path).unwrap();
        con.execute(
            "UPDATE runs SET updated_at = datetime('now', ?1) WHERE run_id = ?2",
            params![format!("-{days_ago} days"), run_id],
        )
        .unwrap();
    }

    #[test]
    fn register_run_creates_a_row_prune_can_see() {
        let (_dir, store) = store();
        store.register_run("run1", "/repo", Some("demo"), Some("app-1"));
        let report = store.prune(100, 5, true).unwrap();
        assert_eq!(report.kept, 1);
        assert!(report.deleted.is_empty());
    }

    #[test]
    fn register_run_upserts_rather_than_duplicating() {
        let (_dir, store) = store();
        store.register_run("run1", "/repo/old", Some("old-name"), None);
        store.register_run("run1", "/repo/new", Some("new-name"), Some("app-1"));
        // Still exactly one run — an upsert, not a second row.
        let report = store.prune(100, 5, true).unwrap();
        assert_eq!(report.kept, 1);
    }

    #[test]
    fn register_run_degrades_silently_when_the_state_dir_is_gone() {
        let (dir, store) = store();
        std::fs::remove_dir_all(dir.path()).unwrap();
        // Must not panic.
        store.register_run("run1", "/repo", None, None);
    }

    #[test]
    fn reset_run_clears_checkpoints_but_keeps_the_run_row() {
        let (_dir, store) = store();
        store.register_run("run1", "/repo", None, None);
        store.save("run1", "s1", b"x").unwrap();
        store.save("run1", "s2", b"y").unwrap();
        let cleared = store.reset_run("run1");
        assert_eq!(cleared, 2);
        assert_eq!(store.load("run1", "s1"), None);
        assert_eq!(store.load("run1", "s2"), None);
        // The runs row itself survives — prune still finds it.
        let report = store.prune(100, 5, true).unwrap();
        assert_eq!(report.kept, 1);
    }

    #[test]
    fn reset_run_of_a_run_with_no_checkpoints_clears_zero() {
        let (_dir, store) = store();
        assert_eq!(store.reset_run("nonexistent"), 0);
    }

    #[test]
    fn reset_run_degrades_to_zero_when_the_state_dir_is_gone() {
        let (dir, store) = store();
        std::fs::remove_dir_all(dir.path()).unwrap();
        assert_eq!(store.reset_run("run1"), 0);
    }

    #[test]
    fn delete_run_evicts_the_run_row_and_its_checkpoints() {
        let (_dir, store) = store();
        store.register_run("run1", "/repo", None, None);
        store.save("run1", "s1", b"x").unwrap();
        assert!(store.delete_run("run1").unwrap());
        assert_eq!(store.load("run1", "s1"), None);
        let report = store.prune(100, 5, true).unwrap();
        assert!(report.deleted.is_empty());
        assert_eq!(report.kept, 0);
    }

    #[test]
    fn delete_run_of_a_nonexistent_run_returns_false() {
        let (_dir, store) = store();
        assert!(!store.delete_run("nonexistent").unwrap());
    }

    #[test]
    fn delete_run_leaves_other_runs_checkpoints_untouched() {
        let (_dir, store) = store();
        store.save("run1", "s1", b"a").unwrap();
        store.save("run2", "s1", b"b").unwrap();
        store.delete_run("run1").unwrap();
        assert_eq!(store.load("run2", "s1"), Some(b"b".to_vec()));
    }

    #[test]
    fn delete_run_propagates_an_error_when_the_state_dir_is_gone() {
        let (dir, store) = store();
        std::fs::remove_dir_all(dir.path()).unwrap();
        let err = store.delete_run("run1").unwrap_err();
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn prune_keeps_only_the_n_most_recent_runs() {
        let (dir, store) = store();
        let db_path = dir.path().join("state.db");
        for i in 0..5 {
            store.register_run(&format!("run{i}"), "/repo", None, None);
            // Space out `updated_at` deterministically instead of relying
            // on real wall-clock time between fast, sub-second calls.
            backdate(&db_path, &format!("run{i}"), i);
        }
        // run0 is "now" (0 days ago, most recent); run4 is oldest.
        let report = store.prune(2, 999, false).unwrap();
        assert_eq!(report.kept, 2);
        assert_eq!(report.deleted.len(), 3);
        assert!(report.deleted.contains(&"run4".to_string()));
        assert!(report.deleted.contains(&"run3".to_string()));
        assert!(report.deleted.contains(&"run2".to_string()));
        assert!(!report.deleted.contains(&"run0".to_string()));
        assert!(!report.deleted.contains(&"run1".to_string()));
        // Actually deleted, not just reported (this call wasn't dry-run).
        assert_eq!(store.reset_run("run4"), 0);
    }

    #[test]
    fn prune_deletes_runs_older_than_max_age_days_regardless_of_keep_runs() {
        let (dir, store) = store();
        let db_path = dir.path().join("state.db");
        store.register_run("fresh", "/repo", None, None);
        store.register_run("stale", "/repo", None, None);
        backdate(&db_path, "stale", 10);
        let report = store.prune(100, 5, false).unwrap();
        assert_eq!(report.deleted, vec!["stale".to_string()]);
        assert_eq!(report.kept, 1);
    }

    #[test]
    fn prune_dry_run_reports_without_deleting_anything() {
        let (dir, store) = store();
        let db_path = dir.path().join("state.db");
        store.register_run("run1", "/repo", None, None);
        store.save("run1", "s1", b"x").unwrap();
        backdate(&db_path, "run1", 10);
        let report = store.prune(0, 5, true).unwrap();
        assert_eq!(report.deleted, vec!["run1".to_string()]);
        // Nothing was actually touched.
        assert_eq!(store.load("run1", "s1"), Some(b"x".to_vec()));
        let second_report = store.prune(0, 5, true).unwrap();
        assert_eq!(second_report.deleted, vec!["run1".to_string()]);
    }

    #[test]
    fn prune_of_an_empty_store_deletes_nothing() {
        let (_dir, store) = store();
        let report = store.prune(100, 5, false).unwrap();
        assert_eq!(report.kept, 0);
        assert!(report.deleted.is_empty());
    }

    #[test]
    fn prune_report_carries_the_db_path() {
        let (dir, store) = store();
        let report = store.prune(100, 5, true).unwrap();
        assert_eq!(report.db_path, dir.path().join("state.db"));
    }

    #[test]
    fn prune_propagates_an_error_when_the_state_dir_is_gone() {
        let (dir, store) = store();
        std::fs::remove_dir_all(dir.path()).unwrap();
        let err = store.prune(100, 5, false).unwrap_err();
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn prune_propagates_an_error_when_preparing_the_victim_query_fails() {
        // Distinct from the "state dir is gone" case above: the
        // connection succeeds AND the leading `SELECT COUNT(*) FROM
        // runs` succeeds (it names no columns) — only the second
        // query's own `PREPARE` fails, since the schema swap below
        // drops the `run_id`/`updated_at` columns it selects on.
        let (dir, store) = store();
        let db_path = dir.path().join("state.db");
        Connection::open(&db_path)
            .unwrap()
            .execute_batch("DROP TABLE runs; CREATE TABLE runs (only_a_dummy_column TEXT);")
            .unwrap();
        let err = store.prune(100, 5, false).unwrap_err();
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn new_creates_the_db_file() {
        let (dir, _store) = store();
        assert!(dir.path().join("state.db").is_file());
    }

    #[test]
    fn new_is_idempotent_against_an_already_bootstrapped_db() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.db");
        SqliteCheckpointStore::new(&path).unwrap();
        let store = SqliteCheckpointStore::new(&path).unwrap();
        store.save("run1", "s1", b"x").unwrap();
        assert_eq!(store.load("run1", "s1"), Some(b"x".to_vec()));
    }

    #[test]
    fn new_of_an_unwritable_path_is_an_error() {
        let err = SqliteCheckpointStore::new(Path::new("/does/not/exist/state.db")).unwrap_err();
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn new_of_a_file_that_is_not_a_sqlite_database_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("not-a-database.db");
        std::fs::write(&path, b"this is not a valid sqlite database file").unwrap();
        let err = SqliteCheckpointStore::new(&path).unwrap_err();
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn save_then_load_round_trips_the_exact_bytes() {
        let (_dir, store) = store();
        store.save("run1", "s1", b"payload bytes").unwrap();
        assert_eq!(store.load("run1", "s1"), Some(b"payload bytes".to_vec()));
    }

    #[test]
    fn load_of_a_missing_key_is_none() {
        let (_dir, store) = store();
        assert_eq!(store.load("run1", "s1"), None);
    }

    #[test]
    fn save_of_a_second_step_does_not_clobber_the_first() {
        let (_dir, store) = store();
        store.save("run1", "s1", b"one").unwrap();
        store.save("run1", "s2", b"two").unwrap();
        assert_eq!(store.load("run1", "s1"), Some(b"one".to_vec()));
        assert_eq!(store.load("run1", "s2"), Some(b"two".to_vec()));
    }

    #[test]
    fn save_of_the_same_key_twice_overwrites() {
        let (_dir, store) = store();
        store.save("run1", "s1", b"old").unwrap();
        store.save("run1", "s1", b"new").unwrap();
        assert_eq!(store.load("run1", "s1"), Some(b"new".to_vec()));
    }

    #[test]
    fn different_runs_do_not_share_checkpoints() {
        let (_dir, store) = store();
        store.save("run1", "s1", b"a").unwrap();
        store.save("run2", "s1", b"b").unwrap();
        assert_eq!(store.load("run1", "s1"), Some(b"a".to_vec()));
        assert_eq!(store.load("run2", "s1"), Some(b"b".to_vec()));
    }

    #[test]
    fn save_of_an_oversized_payload_is_refused() {
        let (_dir, store) = store();
        let huge = vec![0u8; MAX_PAYLOAD_BYTES + 1];
        let err = store.save("run1", "s1", &huge).unwrap_err();
        assert!(err.to_string().contains("exceeds"));
        assert_eq!(store.load("run1", "s1"), None);
    }

    #[test]
    fn save_after_the_state_dir_is_removed_is_an_error() {
        let (dir, store) = store();
        std::fs::remove_dir_all(dir.path()).unwrap();
        let err = store.save("run1", "s1", b"x").unwrap_err();
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn load_after_the_state_dir_is_removed_is_a_miss() {
        let (dir, store) = store();
        std::fs::remove_dir_all(dir.path()).unwrap();
        assert_eq!(store.load("run1", "s1"), None);
    }

    #[test]
    fn save_after_the_db_file_is_corrupted_in_place_is_an_error() {
        let (dir, store) = store();
        std::fs::write(
            dir.path().join("state.db"),
            b"no longer a valid sqlite file",
        )
        .unwrap();
        let err = store.save("run1", "s1", b"x").unwrap_err();
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn save_after_the_db_file_is_deleted_but_the_dir_remains_is_an_error() {
        let (dir, store) = store();
        std::fs::remove_file(dir.path().join("state.db")).unwrap();
        let err = store.save("run1", "s1", b"x").unwrap_err();
        assert!(err.to_string().contains("checkpoints"));
    }

    #[test]
    fn load_after_the_db_file_is_deleted_but_the_dir_remains_is_a_miss() {
        let (dir, store) = store();
        std::fs::remove_file(dir.path().join("state.db")).unwrap();
        assert_eq!(store.load("run1", "s1"), None);
    }

    #[test]
    fn prune_stale_removes_only_unclaimed_rows_under_the_prefix() {
        let (_dir, store) = store();
        for step in [
            "remediate_aaa",
            "remediate_bbb",
            "remediateXccc",
            "validate_ddd",
            "s1",
        ] {
            store.save("run1", step, b"x").unwrap();
        }
        store.save("run2", "remediate_zzz", b"x").unwrap();
        let removed = store.prune_stale("run1", "remediate_", &["remediate_bbb".to_string()]);
        assert_eq!(removed, vec!["remediate_aaa".to_string()]);
        assert_eq!(store.load("run1", "remediate_aaa"), None);
        // `_` is literal: `remediateXccc` does not share the prefix.
        for kept in ["remediate_bbb", "remediateXccc", "validate_ddd", "s1"] {
            assert!(store.load("run1", kept).is_some(), "{kept}");
        }
        assert!(store.load("run2", "remediate_zzz").is_some());
    }

    #[test]
    fn prune_stale_degrades_to_nothing_when_the_state_dir_is_gone() {
        let (dir, store) = store();
        std::fs::remove_dir_all(dir.path()).unwrap();
        assert!(store.prune_stale("run1", "remediate_", &[]).is_empty());
    }

    #[test]
    fn prune_stale_degrades_to_nothing_when_the_table_is_unusable() {
        let (dir, store) = store();
        Connection::open(dir.path().join("state.db"))
            .unwrap()
            .execute_batch("DROP TABLE checkpoints;")
            .unwrap();
        assert!(store.prune_stale("run1", "remediate_", &[]).is_empty());
    }

    #[test]
    fn is_usable_as_a_trait_object() {
        let (_dir, store) = store();
        let boxed: Box<dyn CheckpointStore> = Box::new(store);
        boxed.save("run1", "s1", b"x").unwrap();
        assert_eq!(boxed.load("run1", "s1"), Some(b"x".to_vec()));
    }

    #[test]
    fn run_id_for_is_stable_for_the_same_path() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(run_id_for(dir.path()), run_id_for(dir.path()));
    }

    #[test]
    fn run_id_for_differs_across_distinct_paths() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        assert_ne!(run_id_for(a.path()), run_id_for(b.path()));
    }

    #[test]
    fn run_id_for_is_32_hex_characters() {
        let dir = tempfile::tempdir().unwrap();
        let id = run_id_for(dir.path());
        assert_eq!(id.len(), 32);
        assert!(id.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn run_id_for_a_nonexistent_path_still_produces_an_id() {
        let id = run_id_for(Path::new("/does/not/exist/at/all"));
        assert_eq!(id.len(), 32);
    }

    // SAFETY (test-only): guarded by `ENV_LOCK` above against concurrent
    // mutation from other tests in this process; each test restores the
    // env var to its prior state via `restore_state_dir_env`/`restore_env`
    // before returning, regardless of test execution order.

    #[test]
    fn default_db_path_honors_the_state_dir_env_var() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let prior = std::env::var("BC_STATE_DIR").ok();
        unsafe {
            std::env::set_var("BC_STATE_DIR", dir.path());
        }
        let path = default_db_path().unwrap();
        restore_state_dir_env(prior);
        assert_eq!(path, dir.path().join("bc-sast.db"));
    }

    #[test]
    fn default_db_path_falls_back_to_home_when_the_env_var_is_unset_or_empty() {
        let _guard = ENV_LOCK.lock().unwrap();
        let prior = std::env::var("BC_STATE_DIR").ok();
        unsafe {
            std::env::set_var("BC_STATE_DIR", "");
        }
        let path = default_db_path().unwrap();
        restore_state_dir_env(prior);
        assert!(path.ends_with(".bc-sast/state/bc-sast.db"));
    }

    #[test]
    fn default_db_path_is_an_error_when_home_is_also_unset() {
        let _guard = ENV_LOCK.lock().unwrap();
        let prior_state_dir = std::env::var("BC_STATE_DIR").ok();
        let prior_home = std::env::var("HOME").ok();
        unsafe {
            std::env::remove_var("BC_STATE_DIR");
            std::env::remove_var("HOME");
        }
        let result = default_db_path();
        restore_state_dir_env(prior_state_dir);
        restore_env("HOME", prior_home);
        let err = result.unwrap_err();
        assert!(err.to_string().contains("HOME is not set"));
    }

    #[test]
    fn default_db_path_is_an_error_when_the_state_dir_cannot_be_created() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("blocker");
        std::fs::write(&blocker, b"not a directory").unwrap();
        let prior = std::env::var("BC_STATE_DIR").ok();
        unsafe {
            std::env::set_var("BC_STATE_DIR", &blocker);
        }
        let result = default_db_path();
        restore_state_dir_env(prior);
        let err = result.unwrap_err();
        assert!(err.to_string().contains("cannot create state dir"));
    }

    #[test]
    fn open_default_is_an_error_when_the_default_db_path_cannot_be_resolved() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("blocker");
        std::fs::write(&blocker, b"not a directory").unwrap();
        let prior = std::env::var("BC_STATE_DIR").ok();
        unsafe {
            std::env::set_var("BC_STATE_DIR", &blocker);
        }
        let result = SqliteCheckpointStore::open_default();
        restore_state_dir_env(prior);
        let err = result.unwrap_err();
        assert!(err.to_string().contains("cannot create state dir"));
    }

    #[test]
    fn open_default_opens_the_store_at_the_state_dir_env_var_location() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let prior = std::env::var("BC_STATE_DIR").ok();
        unsafe {
            std::env::set_var("BC_STATE_DIR", dir.path());
        }
        let store = SqliteCheckpointStore::open_default().unwrap();
        restore_state_dir_env(prior);
        store.save("run1", "s1", b"x").unwrap();
        assert_eq!(store.load("run1", "s1"), Some(b"x".to_vec()));
        assert!(dir.path().join("bc-sast.db").is_file());
    }
}
