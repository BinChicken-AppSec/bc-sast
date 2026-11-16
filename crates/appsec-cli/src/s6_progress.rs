use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use appsec_pipeline_core::{stage_id, ScanEvent};
use serde::Serialize;

const FILE_NAME: &str = "s6_progress.json";
const DIR_NAME: &str = "s6_progress";

fn safe_run_id(run_id: &str) -> String {
    let safe: String = run_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    match safe.as_str() {
        "" => "current".to_string(),
        "." | ".." => "_".to_string(),
        _ => safe,
    }
}

pub(crate) fn path_under(state_root: &Path, run_id: &str) -> PathBuf {
    state_root
        .join(DIR_NAME)
        .join(safe_run_id(run_id))
        .join(FILE_NAME)
}

pub(crate) fn resolve(repo_root: &Path) -> Option<PathBuf> {
    let db = appsec_checkpoint::default_db_path().ok()?;
    let state_root = db.parent()?;
    Some(path_under(
        state_root,
        &appsec_checkpoint::run_id_for(repo_root),
    ))
}

fn ensure_confined_dir(state_root: &Path, dir: &Path) -> std::io::Result<()> {
    let relative = dir.strip_prefix(state_root).map_err(|_| {
        std::io::Error::other(format!(
            "{} is not under the state directory",
            dir.display()
        ))
    })?;
    let mut current = state_root.to_path_buf();
    for component in relative.components() {
        current.push(component);
        match std::fs::symlink_metadata(&current) {
            Ok(meta) if meta.file_type().is_dir() => {}
            Ok(_) => {
                return Err(std::io::Error::other(format!(
                    "{} is a symlink or not a directory; refusing to write through it",
                    current.display()
                )))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(&current)?;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[derive(Debug, Serialize)]
struct Record<'a> {
    status: &'a str,
    total: usize,
    completed: usize,
    remaining: usize,
    outcomes: &'a BTreeMap<&'static str, u64>,
    updated_at: String,
}

pub(crate) struct S6ProgressFile {
    state_root: PathBuf,
    path: PathBuf,
    total: Option<usize>,
    completed: usize,
    outcomes: BTreeMap<&'static str, u64>,
    warned: bool,
}

impl S6ProgressFile {
    pub(crate) fn new(state_root: PathBuf, path: PathBuf) -> Self {
        S6ProgressFile {
            state_root,
            path,
            total: None,
            completed: 0,
            outcomes: BTreeMap::new(),
            warned: false,
        }
    }

    pub(crate) fn for_path(path: PathBuf) -> Self {
        let state_root = path
            .ancestors()
            .nth(3)
            .map_or_else(PathBuf::new, Path::to_path_buf);
        S6ProgressFile::new(state_root, path)
    }

    pub(crate) fn on_event(&mut self, event: &ScanEvent) {
        match event {
            ScanEvent::VerifyProgress {
                completed,
                total,
                outcome,
                ..
            } => {
                self.total = Some(*total);
                self.completed = *completed;
                if let Some(outcome) = outcome {
                    *self.outcomes.entry(outcome).or_default() += 1;
                }
                let status = if completed == total {
                    "completed"
                } else {
                    "running"
                };
                self.write(status);
            }
            ScanEvent::StageFinished { stage, .. } if stage_id(stage) == "s6" => {
                if let Some(total) = self.total {
                    let status = if self.completed == total {
                        "completed"
                    } else {
                        "stopped"
                    };
                    self.write(status);
                }
            }
            _ => {}
        }
    }

    fn write(&mut self, status: &str) {
        let total = self.total.unwrap_or(0);
        let record = Record {
            status,
            total,
            completed: self.completed,
            remaining: total.saturating_sub(self.completed),
            outcomes: &self.outcomes,
            updated_at: appsec_metrics::now_iso(),
        };
        if let Err(e) = self.write_atomically(&record) {
            if !self.warned {
                self.warned = true;
                eprintln!(
                    "  [s6-progress] WARNING: could not write {}: {e}",
                    self.path.display()
                );
            }
        }
    }

    fn write_atomically(&self, record: &Record<'_>) -> std::io::Result<()> {
        let dir = self
            .path
            .parent()
            .ok_or_else(|| std::io::Error::other("progress file has no parent directory"))?;
        ensure_confined_dir(&self.state_root, dir)?;
        let mut tmp = tempfile::Builder::new()
            .prefix(".s6_progress.")
            .suffix(".tmp")
            .tempfile_in(dir)?;
        let json = serde_json::to_string(record).expect("Record always serializes");
        tmp.write_all(json.as_bytes())?;
        tmp.write_all(b"\n")?;
        tmp.as_file().sync_all()?;
        tmp.persist(&self.path).map_err(|e| e.error)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use appsec_pipeline_core::StageStatus;

    fn progress(completed: usize, total: usize, outcome: Option<&'static str>) -> ScanEvent {
        ScanEvent::VerifyProgress {
            stage: "s6-verify",
            completed,
            total,
            outcome,
        }
    }

    fn s6_finished() -> ScanEvent {
        ScanEvent::StageFinished {
            stage: "s6-verify",
            status: StageStatus::Completed,
            duration: None,
            counts: Vec::new(),
            detail: None,
        }
    }

    fn read(path: &Path) -> serde_json::Value {
        let text = std::fs::read_to_string(path).unwrap();
        assert!(text.ends_with('\n'));
        serde_json::from_str(&text).unwrap()
    }

    #[test]
    fn run_ids_are_sanitized_as_python_does_and_can_never_climb_out() {
        assert_eq!(safe_run_id("abc123"), "abc123");
        assert_eq!(safe_run_id("a/b\\c d"), "a_b_c_d");
        assert_eq!(safe_run_id(""), "current");
        assert_eq!(safe_run_id("."), "_");
        assert_eq!(safe_run_id(".."), "_");
        assert_eq!(safe_run_id("../x"), ".._x");
        let root = Path::new("/state");
        assert_eq!(
            path_under(root, "../../etc"),
            Path::new("/state/s6_progress/.._.._etc/s6_progress.json")
        );
    }

    #[test]
    fn resolve_uses_the_checkpoint_state_dir_and_run_id() {
        let _guard = crate::tests::ENV_LOCK.blocking_lock();
        let state = tempfile::tempdir().unwrap();
        let prior = std::env::var("BC_STATE_DIR").ok();
        unsafe {
            std::env::set_var("BC_STATE_DIR", state.path());
        }
        let path = resolve(Path::new("/some/repo"));
        crate::tests::restore_env("BC_STATE_DIR", prior);
        let expected = path_under(
            state.path(),
            &appsec_checkpoint::run_id_for(Path::new("/some/repo")),
        );
        assert_eq!(path, Some(expected));
    }

    #[test]
    fn every_finding_rewrites_the_record_and_the_stage_end_settles_it() {
        let state = tempfile::tempdir().unwrap();
        let path = path_under(state.path(), "run1");
        let mut file = S6ProgressFile::for_path(path.clone());
        file.on_event(&s6_finished());
        file.on_event(&ScanEvent::StageStarted { stage: "s6-verify" });
        assert!(!path.exists());

        file.on_event(&progress(0, 3, None));
        let v = read(&path);
        assert_eq!(v["status"], "running");
        assert_eq!(v["total"], 3);
        assert_eq!(v["remaining"], 3);
        assert_eq!(v["outcomes"], serde_json::json!({}));
        assert!(v["updated_at"].as_str().is_some_and(|s| !s.is_empty()));

        file.on_event(&progress(1, 3, Some("TRUE_POSITIVE")));
        file.on_event(&progress(2, 3, Some("FALSE_POSITIVE")));
        file.on_event(&progress(3, 3, Some("TRUE_POSITIVE")));
        let v = read(&path);
        assert_eq!(v["status"], "completed");
        assert_eq!(v["completed"], 3);
        assert_eq!(v["remaining"], 0);
        assert_eq!(
            v["outcomes"],
            serde_json::json!({"FALSE_POSITIVE": 1, "TRUE_POSITIVE": 2})
        );
        file.on_event(&s6_finished());
        assert_eq!(read(&path)["status"], "completed");
        let leftovers: Vec<_> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(leftovers, vec![std::ffi::OsString::from(FILE_NAME)]);
    }

    #[test]
    fn a_pass_that_ends_with_findings_unverified_finishes_as_stopped() {
        let state = tempfile::tempdir().unwrap();
        let path = path_under(state.path(), "run1");
        let mut file = S6ProgressFile::for_path(path.clone());
        file.on_event(&progress(0, 2, None));
        file.on_event(&progress(1, 2, Some("TRUE_POSITIVE")));
        file.on_event(&ScanEvent::StageFinished {
            stage: "s5-prefilter",
            status: StageStatus::Completed,
            duration: None,
            counts: Vec::new(),
            detail: None,
        });
        assert_eq!(read(&path)["status"], "running");
        file.on_event(&s6_finished());
        let v = read(&path);
        assert_eq!(v["status"], "stopped");
        assert_eq!(v["remaining"], 1);
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_directory_under_the_state_root_is_refused_not_followed() {
        let state = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(elsewhere.path(), state.path().join(DIR_NAME)).unwrap();
        let path = path_under(state.path(), "run1");
        let mut file = S6ProgressFile::for_path(path.clone());
        file.on_event(&progress(0, 1, None));
        file.on_event(&progress(1, 1, Some("TRUE_POSITIVE")));
        assert!(file.warned);
        assert_eq!(std::fs::read_dir(elsewhere.path()).unwrap().count(), 0);
    }

    #[test]
    fn a_file_where_a_directory_belongs_is_refused() {
        let state = tempfile::tempdir().unwrap();
        std::fs::write(state.path().join(DIR_NAME), "not a dir").unwrap();
        let path = path_under(state.path(), "run1");
        let mut file = S6ProgressFile::for_path(path);
        file.on_event(&progress(0, 1, None));
        assert!(file.warned);
    }

    #[test]
    fn a_path_outside_the_state_root_or_with_no_parent_is_refused() {
        let state = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let mut outside =
            S6ProgressFile::new(state.path().to_path_buf(), other.path().join("x.json"));
        outside.on_event(&progress(0, 1, None));
        assert!(outside.warned);
        assert!(!other.path().join("x.json").exists());
        let mut rootless = S6ProgressFile::new(PathBuf::new(), PathBuf::from("/"));
        rootless.on_event(&progress(0, 1, None));
        assert!(rootless.warned);
    }

    #[test]
    fn an_unreadable_component_is_reported_rather_than_created() {
        let state = tempfile::tempdir().unwrap();
        let path = state.path().join("bad\0dir").join("run").join(FILE_NAME);
        let mut file = S6ProgressFile::new(state.path().to_path_buf(), path);
        file.on_event(&progress(0, 1, None));
        assert!(file.warned);
    }
}
