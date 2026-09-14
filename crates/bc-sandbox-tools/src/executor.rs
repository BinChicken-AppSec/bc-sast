//! [`SandboxTools`]: the jailed, local `ToolExecutor`, ported from
//! `backends/localtools.py`'s module-level `execute()`/`schemas_for`.
//!
//! Read-only by default: `new()` never offers `Edit`/`Write` in
//! `available_tools()`, and `execute()` refuses them even if a caller
//! somehow asked for them by name (the `"Write" if self.allow_write`/`"Edit"
//! if self.allow_write` match guards fall through to the same "not
//! available" error `Bash` gets). Only `new_with_write()` (Phase 2's S10
//! remediation stage) enables them. Bash is never offered either
//! construction; a host shell would defeat the `root` jail on
//! prompt-injected/untrusted targets.
//!
//! The write-capable construction also flips two defaults that only make
//! sense once edits are in play: every `Write`/`Edit` is recorded in a
//! copy-on-first-write [`WriteJournal`] (so S10's safety gates can undo
//! exactly what the agent did, on a non-git target too), and `Read`/`Grep`
//! redaction is off (so an `Edit.old_string` can actually match a
//! hardcoded secret) — see [`SandboxTools::redact_reads`].

use std::path::{Path, PathBuf};

use bc_llm_client::{ToolExecutor, ToolSpec};
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
    /// Canonicalizes `root` up front (matching `backends/localtools.py`'s
    /// `execute()`, which resolves `cwd` once via `Path(cwd).resolve()`)
    /// so every subsequent tool call compares paths against one
    /// consistent, fully-resolved root rather than re-deriving it per
    /// call — falls back to the path as given if it doesn't exist yet.
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

    /// Like [`Self::new`], but also offers `Edit`/`Write` — for stages
    /// that generate code fixes (Phase 2's S10 remediation stage). Every
    /// write is jailed via `bc_pathjail::confine`, the same as every
    /// other tool call; `Bash` is still never offered regardless of this
    /// flag, matching the Python original's own SDK-backend design (the
    /// safer of its two write-capable routes — see the crate's own doc
    /// comment for why that one, not the shipped-default CLI route).
    ///
    /// Two behaviors differ from [`Self::new`] beyond the tool list:
    /// every `Write`/`Edit` is journalled (see [`Self::journal`]), and
    /// `Read`/`Grep` output is NOT redacted (see [`Self::redact_reads`]
    /// for the trade-off).
    pub fn new_with_write(root: impl Into<PathBuf>) -> Self {
        let mut tools = Self::new(root);
        tools.allow_write = true;
        tools.redact_reads = false;
        tools
    }

    /// Overrides the read-redaction default this executor was built with.
    ///
    /// **The trade-off, and why write-capable defaults to OFF.**
    /// `bc_redact::redact` masks credential/PII material in `Read`/`Grep`
    /// output before it reaches the model. That is unambiguously right for
    /// a read-only executor. For the write-capable one it is actively
    /// harmful: the agent's `Edit` tool requires `old_string` to match the
    /// file byte-for-byte, so for the single finding class where the
    /// secret IS the vulnerability — a hardcoded credential — the model
    /// can only ever see `AKIA****` and every `Edit` it composes is
    /// guaranteed to fail with "old_string not found". The Python original
    /// resolved this the same way, disabling read-redaction whenever
    /// writes were allowed (`harness/deepagents/options.py:421-425`).
    ///
    /// Nothing about this widens what leaves the process: everything S10
    /// emits (diffs, summaries, verdicts) is still redacted downstream by
    /// `bc_orchestrator::redact_remediate_outcome` before it is written to
    /// disk or posted anywhere. The exposure this trades away is to the
    /// model provider only — pass `true` here to keep redaction on and
    /// accept that hardcoded-secret findings become unfixable.
    pub fn redact_reads(mut self, redact: bool) -> Self {
        self.redact_reads = redact;
        self
    }

    /// A handle on this executor's copy-on-first-write ledger — the same
    /// shared ledger, not a snapshot, so a caller can hold it before the
    /// agent runs and read it afterwards. Always present; it simply stays
    /// empty for a read-only executor, which never writes anything.
    ///
    /// This is how `bc_stage_s10` learns which files the agent ACTUALLY
    /// touched (not merely the ones it claimed in its JSON verdict, and
    /// not merely the finding's own file) and what they contained before —
    /// see [`crate::WriteJournal`]'s module doc comment.
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
            // The journal capture happens BEFORE the handler runs, so the
            // bytes it records are genuinely the ones about to be
            // overwritten — and it happens even when the write then fails,
            // since restoring a file to content it already has is a no-op
            // while missing a baseline for one that DID change is not.
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
        // Mask PII/credential material in file CONTENT before it is handed
        // back to the model (Read and Grep return source text; Glob
        // returns only paths and Write/Edit return a plain status
        // message, so neither is ever redacted). Gated on `redact_reads`,
        // which defaults OFF for a write-capable executor — see
        // [`Self::redact_reads`] for that trade-off.
        if self.redact_reads && matches!(name, "Read" | "Grep") && !result.starts_with("ERROR:") {
            bc_redact::redact(&result)
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

/// The jailed root this executor confines every tool call to — exposed so
/// callers can build fixtures relative to it; not part of [`ToolExecutor`]
/// itself since that trait is dialect/backend-neutral.
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
        // Paths are never secret material; Glob's output is filenames only.
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
        // `new()` canonicalizes the root (e.g. macOS's `/tmp` ->
        // `/private/tmp`), so compare against the same canonicalization
        // rather than the raw `dir.path()`.
        assert_eq!(tools.root(), dir.path().canonicalize().unwrap());
    }

    #[test]
    fn missing_arguments_fall_back_to_documented_defaults() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "one\ntwo\n").unwrap();
        let tools = SandboxTools::new(dir.path());
        // No "offset"/"limit"/"ignore_case"/"context" keys at all.
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
        // The status message itself never contains file content, so
        // redaction (which only ever applies to Read/Grep output) simply
        // never has anything to mask here — this asserts the message is
        // returned as-is, not that redaction was skipped for a hidden
        // reason.
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
        // The hardcoded-secret case: with redaction on, the model only
        // ever sees `AKIA****`, so every `Edit.old_string` it composes is
        // guaranteed never to match the on-disk line.
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
        // Restoring a file to content it already has is a harmless no-op;
        // MISSING a baseline for one that did change is not, so the
        // capture deliberately does not depend on the write succeeding.
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
        // Taken BEFORE any write, exactly as `bc_stage_s10` takes it.
        let journal = tools.journal();
        tools.execute("Write", &json!({"path": "a.txt", "content": "x"}));
        assert_eq!(journal.touched(), vec!["a.txt".to_string()]);
    }

    #[test]
    fn write_returns_the_journals_own_refusal_for_an_outside_root_path() {
        // The baseline capture is also the gate: a path it will not
        // journal is a path the handler must never be handed. The exact
        // wording proves the refusal came from `prepare_write`, before
        // `write_file` ran at all.
        let dir = tempfile::tempdir().unwrap();
        // The jail root is a subdirectory, so "outside it" is still inside
        // this test's own temporary directory and cannot collide with
        // anything another process left in the system temp directory.
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
