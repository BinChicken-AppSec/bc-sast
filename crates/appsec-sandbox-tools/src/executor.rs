use std::path::{Path, PathBuf};

use appsec_llm_client::{ToolExecutor, ToolSpec};
use serde_json::Value;

use crate::edit::edit_file;
use crate::glob::glob;
use crate::grep::grep;
use crate::journal::WriteJournal;
use crate::read::read;
use crate::schema::{tool_specs, write_tool_specs};
use crate::write::write_file;

pub struct SandboxTools {
    root: PathBuf,
    allow_write: bool,
    redact_reads: bool,
    journal: WriteJournal,
}

impl SandboxTools {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        let resolved = root.canonicalize().unwrap_or(root);
        SandboxTools {
            root: resolved,
            allow_write: false,
            redact_reads: true,
            journal: WriteJournal::new(),
        }
    }

    pub fn new_with_write(root: impl Into<PathBuf>) -> Self {
        let mut tools = Self::new(root);
        tools.allow_write = true;
        tools.redact_reads = false;
        tools
    }

    pub fn redact_reads(mut self, redact: bool) -> Self {
        self.redact_reads = redact;
        self
    }

    pub fn journal(&self) -> WriteJournal {
        self.journal.clone()
    }
}

impl ToolExecutor for SandboxTools {
    fn available_tools(&self) -> Vec<ToolSpec> {
        let mut specs = tool_specs();
        if self.allow_write {
            specs.extend(write_tool_specs());
        }
        specs
    }

    fn execute(&self, name: &str, args: &Value) -> String {
        let result = match name {
            "Read" => read(
                &self.root,
                str_arg(args, "path"),
                int_arg(args, "offset", 0),
                int_arg(args, "limit", 2000),
            ),
            "Glob" => glob(&self.root, str_arg(args, "pattern")),
            "Grep" => grep(
                &self.root,
                str_arg(args, "pattern"),
                opt_str_arg(args, "path"),
                opt_str_arg(args, "glob"),
                bool_arg(args, "ignore_case", false),
                int_arg(args, "context", 0),
            ),
            "Write" if self.allow_write => {
                match self
                    .journal
                    .prepare_write(&self.root, str_arg(args, "path"))
                {
                    Ok(path) => write_file(&self.root, &path, str_arg(args, "content")),
                    Err(error) => error,
                }
            }
            "Edit" if self.allow_write => {
                match self
                    .journal
                    .prepare_write(&self.root, str_arg(args, "path"))
                {
                    Ok(path) => edit_file(
                        &self.root,
                        &path,
                        str_arg(args, "old_string"),
                        str_arg(args, "new_string"),
                    ),
                    Err(error) => error,
                }
            }
            _ => return format!("ERROR: tool '{name}' is not available on this backend"),
        };
        if self.redact_reads && matches!(name, "Read" | "Grep") && !result.starts_with("ERROR:") {
            appsec_redact::redact(&result)
        } else {
            result
        }
    }
}

fn str_arg<'a>(args: &'a Value, key: &str) -> &'a str {
    args.get(key).and_then(Value::as_str).unwrap_or("")
}

fn opt_str_arg<'a>(args: &'a Value, key: &str) -> Option<&'a str> {
    args.get(key).and_then(Value::as_str)
}

fn int_arg(args: &Value, key: &str, default: i64) -> i64 {
    args.get(key).and_then(Value::as_i64).unwrap_or(default)
}

fn bool_arg(args: &Value, key: &str, default: bool) -> bool {
    args.get(key).and_then(Value::as_bool).unwrap_or(default)
}

impl SandboxTools {
    pub fn root(&self) -> &Path {
        &self.root
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn read_dispatches_with_defaults() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "hello\n").unwrap();
        let tools = SandboxTools::new(dir.path());
        assert_eq!(tools.execute("Read", &json!({"path": "a.txt"})), "1\thello");
    }

    #[test]
    fn read_dispatches_with_explicit_offset_and_limit() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "one\ntwo\nthree\n").unwrap();
        let tools = SandboxTools::new(dir.path());
        assert_eq!(
            tools.execute("Read", &json!({"path": "a.txt", "offset": 1, "limit": 1})),
            "2\ttwo"
        );
    }

    #[test]
    fn glob_dispatches() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.rs"), "").unwrap();
        let tools = SandboxTools::new(dir.path());
        assert_eq!(tools.execute("Glob", &json!({"pattern": "*.rs"})), "a.rs");
    }

    #[test]
    fn grep_dispatches_with_all_optional_args() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "NEEDLE\n").unwrap();
        let tools = SandboxTools::new(dir.path());
        let args = json!({
            "pattern": "needle",
            "path": "a.txt",
            "ignore_case": true,
            "context": 0,
        });
        assert_eq!(tools.execute("Grep", &args), "a.txt:1:NEEDLE");
    }

    #[test]
    fn grep_dispatches_with_glob_restriction() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.rs"), "needle\n").unwrap();
        std::fs::write(dir.path().join("a.txt"), "needle\n").unwrap();
        let tools = SandboxTools::new(dir.path());
        let args = json!({"pattern": "needle", "glob": "*.rs"});
        assert_eq!(tools.execute("Grep", &args), "a.rs:1:needle");
    }

    #[test]
    fn unknown_tool_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let tools = SandboxTools::new(dir.path());
        assert_eq!(
            tools.execute("Bash", &json!({})),
            "ERROR: tool 'Bash' is not available on this backend"
        );
    }

    #[test]
    fn read_result_is_redacted() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "AKIAAAAAAAAAAAAAAAAA\n").unwrap();
        let tools = SandboxTools::new(dir.path());
        let out = tools.execute("Read", &json!({"path": "a.txt"}));
        assert!(!out.contains("AKIAAAAAAAAAAAAAAAAA"), "not redacted: {out}");
    }

    #[test]
    fn glob_results_are_never_redacted() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("AKIAAAAAAAAAAAAAAAAA.rs"), "").unwrap();
        let tools = SandboxTools::new(dir.path());
        let out = tools.execute("Glob", &json!({"pattern": "*.rs"}));
        assert_eq!(out, "AKIAAAAAAAAAAAAAAAAA.rs");
    }

    #[test]
    fn an_error_result_is_not_redacted() {
        let dir = tempfile::tempdir().unwrap();
        let tools = SandboxTools::new(dir.path());
        let out = tools.execute("Read", &json!({"path": "missing.txt"}));
        assert_eq!(out, "ERROR: file not found: missing.txt");
    }

    #[test]
    fn available_tools_exposes_read_glob_and_grep() {
        let dir = tempfile::tempdir().unwrap();
        let tools = SandboxTools::new(dir.path());
        let names: Vec<String> = tools
            .available_tools()
            .into_iter()
            .map(|t| t.name)
            .collect();
        assert_eq!(names, vec!["Read", "Glob", "Grep"]);
    }

    #[test]
    fn root_returns_the_jailed_root() {
        let dir = tempfile::tempdir().unwrap();
        let tools = SandboxTools::new(dir.path());
        assert_eq!(tools.root(), dir.path().canonicalize().unwrap());
    }

    #[test]
    fn missing_arguments_fall_back_to_documented_defaults() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "one\ntwo\n").unwrap();
        let tools = SandboxTools::new(dir.path());
        assert_eq!(
            tools.execute("Read", &json!({"path": "a.txt"})),
            "1\tone\n2\ttwo"
        );
        assert_eq!(
            tools.execute("Grep", &json!({"pattern": "one"})),
            "a.txt:1:one"
        );
    }

    #[test]
    fn a_read_only_executor_refuses_write_and_edit_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let tools = SandboxTools::new(dir.path());
        assert_eq!(
            tools.execute("Write", &json!({"path": "a.txt", "content": "x"})),
            "ERROR: tool 'Write' is not available on this backend"
        );
        assert_eq!(
            tools.execute(
                "Edit",
                &json!({"path": "a.txt", "old_string": "a", "new_string": "b"})
            ),
            "ERROR: tool 'Edit' is not available on this backend"
        );
        assert!(!dir.path().join("a.txt").exists());
    }

    #[test]
    fn a_read_only_executor_does_not_advertise_write_or_edit() {
        let dir = tempfile::tempdir().unwrap();
        let tools = SandboxTools::new(dir.path());
        let names: Vec<String> = tools
            .available_tools()
            .into_iter()
            .map(|t| t.name)
            .collect();
        assert_eq!(names, vec!["Read", "Glob", "Grep"]);
    }

    #[test]
    fn a_write_enabled_executor_advertises_all_five_tools() {
        let dir = tempfile::tempdir().unwrap();
        let tools = SandboxTools::new_with_write(dir.path());
        let names: Vec<String> = tools
            .available_tools()
            .into_iter()
            .map(|t| t.name)
            .collect();
        assert_eq!(names, vec!["Read", "Glob", "Grep", "Write", "Edit"]);
    }

    #[test]
    fn a_write_enabled_executor_dispatches_write() {
        let dir = tempfile::tempdir().unwrap();
        let tools = SandboxTools::new_with_write(dir.path());
        let out = tools.execute("Write", &json!({"path": "a.txt", "content": "hello"}));
        assert_eq!(out, "Wrote 5 bytes to a.txt");
        assert_eq!(
            std::fs::read_to_string(dir.path().join("a.txt")).unwrap(),
            "hello"
        );
    }

    #[test]
    fn a_write_enabled_executor_dispatches_edit() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "old").unwrap();
        let tools = SandboxTools::new_with_write(dir.path());
        let out = tools.execute(
            "Edit",
            &json!({"path": "a.txt", "old_string": "old", "new_string": "new"}),
        );
        assert_eq!(out, "Edited a.txt");
        assert_eq!(
            std::fs::read_to_string(dir.path().join("a.txt")).unwrap(),
            "new"
        );
    }

    #[test]
    fn write_and_edit_results_are_never_redacted() {
        let dir = tempfile::tempdir().unwrap();
        let tools = SandboxTools::new_with_write(dir.path());
        let out = tools.execute(
            "Write",
            &json!({"path": "a.txt", "content": "AKIAAAAAAAAAAAAAAAAA"}),
        );
        assert_eq!(out, "Wrote 20 bytes to a.txt");
    }

    #[test]
    fn a_write_enabled_executor_still_refuses_bash() {
        let dir = tempfile::tempdir().unwrap();
        let tools = SandboxTools::new_with_write(dir.path());
        assert_eq!(
            tools.execute("Bash", &json!({"command": "ls"})),
            "ERROR: tool 'Bash' is not available on this backend"
        );
    }

    #[test]
    fn a_write_enabled_executor_does_not_redact_reads_by_default() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "AKIAAAAAAAAAAAAAAAAA\n").unwrap();
        let tools = SandboxTools::new_with_write(dir.path());
        let out = tools.execute("Read", &json!({"path": "a.txt"}));
        assert!(
            out.contains("AKIAAAAAAAAAAAAAAAAA"),
            "unexpectedly redacted"
        );
    }

    #[test]
    fn read_redaction_can_be_forced_back_on_for_a_write_enabled_executor() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "AKIAAAAAAAAAAAAAAAAA\n").unwrap();
        let tools = SandboxTools::new_with_write(dir.path()).redact_reads(true);
        let out = tools.execute("Read", &json!({"path": "a.txt"}));
        assert!(!out.contains("AKIAAAAAAAAAAAAAAAAA"), "not redacted: {out}");
    }

    #[test]
    fn read_redaction_can_be_turned_off_for_a_read_only_executor() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "AKIAAAAAAAAAAAAAAAAA\n").unwrap();
        let tools = SandboxTools::new(dir.path()).redact_reads(false);
        let out = tools.execute("Grep", &json!({"pattern": "AKIA"}));
        assert!(
            out.contains("AKIAAAAAAAAAAAAAAAAA"),
            "unexpectedly redacted"
        );
    }

    #[test]
    fn a_read_only_executors_journal_stays_empty() {
        let dir = tempfile::tempdir().unwrap();
        let tools = SandboxTools::new(dir.path());
        tools.execute("Write", &json!({"path": "a.txt", "content": "x"}));
        assert!(tools.journal().is_empty());
    }

    #[test]
    fn write_journals_the_files_original_bytes_before_overwriting_them() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "before\n").unwrap();
        let tools = SandboxTools::new_with_write(dir.path());
        tools.execute("Write", &json!({"path": "a.txt", "content": "after\n"}));
        assert_eq!(tools.journal().touched(), vec!["a.txt".to_string()]);
        assert_eq!(
            tools.journal().originals().get("a.txt"),
            Some(&Some(b"before\n".to_vec()))
        );
    }

    #[test]
    fn edit_journals_the_files_original_bytes_before_replacing_them() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "x = 1\n").unwrap();
        let tools = SandboxTools::new_with_write(dir.path());
        tools.execute(
            "Edit",
            &json!({"path": "a.py", "old_string": "x = 1", "new_string": "x = 2"}),
        );
        assert_eq!(
            tools.journal().originals().get("a.py"),
            Some(&Some(b"x = 1\n".to_vec()))
        );
    }

    #[test]
    fn a_brand_new_file_is_journalled_as_not_having_existed() {
        let dir = tempfile::tempdir().unwrap();
        let tools = SandboxTools::new_with_write(dir.path());
        tools.execute("Write", &json!({"path": "new.txt", "content": "x"}));
        assert_eq!(tools.journal().originals().get("new.txt"), Some(&None));
    }

    #[test]
    fn a_failed_write_is_still_journalled() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "x = 1\n").unwrap();
        let tools = SandboxTools::new_with_write(dir.path());
        let out = tools.execute(
            "Edit",
            &json!({"path": "a.py", "old_string": "nope", "new_string": "y"}),
        );
        assert_eq!(out, "ERROR: old_string not found in a.py");
        assert_eq!(tools.journal().touched(), vec!["a.py".to_string()]);
    }

    #[test]
    fn the_journal_handle_is_shared_not_a_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let tools = SandboxTools::new_with_write(dir.path());
        let journal = tools.journal();
        tools.execute("Write", &json!({"path": "a.txt", "content": "x"}));
        assert_eq!(journal.touched(), vec!["a.txt".to_string()]);
    }

    #[test]
    fn write_returns_the_journals_own_refusal_for_an_outside_root_path() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        std::fs::create_dir(&root).unwrap();
        let outside = dir.path().join("escaped.txt");
        let tools = SandboxTools::new_with_write(&root);

        let out = tools.execute("Write", &json!({"path": "../escaped.txt", "content": "x"}));

        assert_eq!(out, "ERROR: invalid or outside-root write path");
        assert!(!outside.exists());
        assert!(tools.journal().is_empty());
    }

    #[test]
    fn edit_returns_the_journals_own_refusal_for_a_git_control_path() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".git")).unwrap();
        std::fs::write(dir.path().join(".git/config"), "[core]\n").unwrap();
        let tools = SandboxTools::new_with_write(dir.path());

        let out = tools.execute(
            "Edit",
            &json!({"path": "./.git/config", "old_string": "[core]", "new_string": "[remote]"}),
        );

        assert_eq!(out, "ERROR: writes to Git control paths are not permitted");
        assert_eq!(
            std::fs::read_to_string(dir.path().join(".git/config")).unwrap(),
            "[core]\n"
        );
        assert!(tools.journal().is_empty());
    }
}
