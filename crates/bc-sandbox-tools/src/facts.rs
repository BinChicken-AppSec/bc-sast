//! The five deterministic, read-only **fact tools** the Python original
//! grants its validation personas alongside `Read`/`Glob`/`Grep`:
//! `DiffTouched`, `ChangedLines`, `DiffImpactMap`, `PatternScan` and
//! `TestInventory` — ported from `validation/tools/deep_tools.py:43-95`
//! with their helpers in `validation/tools/{_scope,diff_facts,
//! pattern_scanner,test_inventory}.py` and their constants in
//! `validation/constants/{diff,pattern_sets,test_inventory}.py`.
//!
//! **Why they exist.** A persona asked "is `Foo.java` part of this fix?"
//! can answer by grepping the diff and eyeballing hunk headers, or it can
//! call `DiffTouched` and get the answer computed by code. The first way
//! is a coin flip that costs turns; the second is a fact. Python's
//! orchestrator prompt (`validation/prompts/system.md:79-81`) instructs
//! every persona to gather evidence with these tools by name for exactly
//! that reason, and this port's personas had no such tools at all until
//! now.
//!
//! **The one interface change from Python.** Python's tools read
//! `diff.patch` out of the staged per-finding workspace
//! (`validation/constants/diff.py:21`), because its validator runs as a
//! separate command over an on-disk snapshot. This port validates
//! in-process immediately after S10 applies a fix and has no such staging
//! directory — the unified diff lives in `RemediationRecord::diff`, in
//! memory. So the diff is passed in as text ([`FactTools::new`]) rather
//! than read from a file; every *other* input (the repo tree) is read
//! through the same [`bc_pathjail::confine`]-guarded walk every other tool
//! in this crate uses. Nothing here executes anything, and nothing here
//! writes.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use bc_llm_client::{ToolExecutor, ToolSpec};
use fancy_regex::Regex as FancyRegex;
use regex::Regex;
use serde_json::{json, Value};

use crate::pattern_scan::pattern_scan;
use crate::schema::fact_tool_specs;
use crate::scope::iter_in_scope_files;

/// The five tool names, in `validation/constants/tools.py:22-31`'s order
/// (after its three readers). Exported so `bc_stage_s11` can append them
/// to its default `allowed_tools` and strip them again when the
/// `step_validate.fact_tools` toggle is off, without restating string
/// literals that would silently drift from the dispatch below.
pub const FACT_TOOL_NAMES: [&str; 5] = [
    "DiffTouched",
    "ChangedLines",
    "DiffImpactMap",
    "PatternScan",
    "TestInventory",
];

// ── validation/constants/diff.py ────────────────────────────────────────

const GIT_HEADER_PREFIX: &str = "diff --git ";
/// A well-formed `diff --git a/<old> b/<new>` header splits into at least
/// 4 tokens; fewer means it is truncated and carries no usable new-side
/// path (`validation/constants/diff.py:38`).
const GIT_HEADER_MIN_TOKENS: usize = 4;
const OLD_FILE_MARKER: &str = "--- ";
const NEW_FILE_MARKER: &str = "+++ ";
/// Byte offset past `+++ ` / `--- ` where the file path begins.
const MARKER_PATH_START: usize = 4;
const DEV_NULL_PATH: &str = "/dev/null";
const GIT_PATH_PREFIXES: [&str; 2] = ["a/", "b/"];

static TRUST_BOUNDARY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(auth|session|login|logout|password|crypto|cipher|tls|ssl|token|secret|credential|permission|role|config|settings)\b",
    )
    .expect("TRUST_BOUNDARY_RE is a compile-time-constant valid regex")
});

static HUNK_HEADER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
        .expect("HUNK_HEADER_RE is a compile-time-constant valid regex")
});

// ── validation/constants/test_inventory.py ──────────────────────────────

const PY_TEST_EXACT_NAMES: [&str; 3] = ["conftest.py", "tests.py", "test.py"];
const PY_TEST_NAME_PREFIX: &str = "test_";
const PY_TEST_NAME_SUFFIX: &str = "_test.py";
const JS_TEST_SUFFIXES: [&str; 8] = [
    ".test.js",
    ".test.jsx",
    ".test.ts",
    ".test.tsx",
    ".spec.js",
    ".spec.jsx",
    ".spec.ts",
    ".spec.tsx",
];

/// Matched case-insensitively on word boundaries, so short tokens like
/// `mock` do not match inside `MagicMock`
/// (`validation/constants/test_inventory.py:27-33`).
const NEGATIVE_TEST_MARKERS: [&str; 14] = [
    "pytest.raises",
    "assertRaises",
    "with raises",
    "expect_exception",
    "toThrow",
    "rejects",
    "should fail",
    "assert.throws",
    "malformed",
    "invalid",
    "fake",
    "mock",
    "exploit",
    "payload",
];

static MARKER_PATTERNS: LazyLock<Vec<(&'static str, FancyRegex)>> = LazyLock::new(|| {
    NEGATIVE_TEST_MARKERS
        .iter()
        .map(|marker| {
            let pattern = format!(r"(?i)(?<!\w){}(?!\w)", fancy_regex::escape(marker));
            let rx = FancyRegex::new(&pattern)
                .expect("every NEGATIVE_TEST_MARKERS entry escapes to a valid regex");
            (*marker, rx)
        })
        .collect()
});

// ── validation/tools/diff_facts.py ──────────────────────────────────────

/// One file's added line ranges, as parsed out of a unified diff
/// (`validation/tools/diff_facts.py:48-53`).
///
/// Each entry of `added_ranges` is `(first added line, how many lines)` on
/// the NEW side — Python calls them "ranges" but builds them as
/// `(added_run_start, added_run_length)` pairs
/// (`diff_facts.py:68-71`). The shape is part of the LLM-facing tool
/// contract, so it is preserved exactly; the tool schema below says
/// `[start_line, line_count]` in so many words, since a model handed a
/// bare pair labeled "range" will otherwise read the second element as an
/// end line and cite the wrong code.
#[derive(Debug, Clone, PartialEq)]
pub struct FileChange {
    pub path: String,
    pub added_ranges: Vec<(i64, i64)>,
}

fn without_git_prefix(path: &str) -> &str {
    if GIT_PATH_PREFIXES.iter().any(|p| path.starts_with(p)) {
        &path[2..]
    } else {
        path
    }
}

fn marker_path(marker_line: &str) -> &str {
    let rest = &marker_line[MARKER_PATH_START..];
    rest.split('\t').next().unwrap_or(rest)
}

/// Feed unified-diff lines in order, then call `finish()` for the per-file
/// changes — a line-for-line port of `_DiffParser`
/// (`validation/tools/diff_facts.py:56-118`).
#[derive(Default)]
struct DiffParser {
    changes: Vec<FileChange>,
    current_path: Option<String>,
    old_path: Option<String>,
    added_ranges: Vec<(i64, i64)>,
    new_line_number: i64,
    added_run_start: Option<i64>,
    added_run_length: i64,
}

impl DiffParser {
    fn close_added_run(&mut self) {
        if let Some(start) = self.added_run_start {
            if self.added_run_length != 0 {
                self.added_ranges.push((start, self.added_run_length));
            }
        }
        self.added_run_start = None;
        self.added_run_length = 0;
    }

    fn close_file(&mut self) {
        self.close_added_run();
        if let Some(path) = self.current_path.take() {
            self.changes.push(FileChange {
                path,
                added_ranges: std::mem::take(&mut self.added_ranges),
            });
        }
        self.old_path = None;
        self.added_ranges.clear();
    }

    fn consume_hunk_line(&mut self, line: &str) {
        match line.chars().next() {
            Some('+') => {
                if self.added_run_start.is_none() {
                    self.added_run_start = Some(self.new_line_number);
                }
                self.added_run_length += 1;
                self.new_line_number += 1;
            }
            Some('-') => self.close_added_run(),
            // "\ No newline at end of file" is a note, not a line of code.
            Some('\\') => (),
            _ => {
                self.close_added_run();
                self.new_line_number += 1;
            }
        }
    }

    fn feed(&mut self, line: &str) {
        if let Some(rest) = line.strip_prefix(GIT_HEADER_PREFIX) {
            self.close_file();
            // Keep the new-side path as a rename/binary fallback.
            let tokens: Vec<&str> = rest.split(' ').collect();
            // `rest` dropped the 2-token "diff --git " prefix, so the
            // 4-token minimum becomes 2 here.
            if tokens.len() + 2 >= GIT_HEADER_MIN_TOKENS {
                if let Some(last) = tokens.last() {
                    self.current_path = Some(without_git_prefix(last).to_string());
                }
            }
        } else if line.starts_with(OLD_FILE_MARKER) {
            self.close_added_run();
            self.old_path = Some(without_git_prefix(marker_path(line)).to_string());
        } else if line.starts_with(NEW_FILE_MARKER) {
            self.close_added_run();
            let new_path = without_git_prefix(marker_path(line)).to_string();
            // "+++ /dev/null" is a deletion; keep the real old path so the
            // file stays tracked.
            self.current_path = if new_path == DEV_NULL_PATH {
                self.old_path.clone()
            } else {
                Some(new_path)
            };
            self.new_line_number = 0;
        } else if let Some(hunk) = HUNK_HEADER_RE.captures(line) {
            self.close_added_run();
            self.new_line_number = hunk
                .get(1)
                .and_then(|m| m.as_str().parse::<i64>().ok())
                .unwrap_or(0);
        } else if self.new_line_number != 0 {
            self.consume_hunk_line(line);
        }
    }

    fn finish(mut self) -> Vec<FileChange> {
        self.close_file();
        self.changes
    }
}

/// Parse a unified diff into per-file changes, ported from
/// `parse_diff_patch` (`validation/tools/diff_facts.py:121-129`) — reading
/// the diff from a string rather than `workspace/diff.patch`, see this
/// module's own doc comment.
pub fn parse_diff_patch(diff: &str) -> Vec<FileChange> {
    let mut parser = DiffParser::default();
    for line in diff.lines() {
        parser.feed(line);
    }
    parser.finish()
}

fn ranges_json(ranges: &[(i64, i64)]) -> Value {
    Value::Array(ranges.iter().map(|&(a, b)| json!([a, b])).collect())
}

/// `{"touched": bool, "added_ranges": [[start, count], ...]}` — ported
/// from `diff_touched` (`validation/tools/diff_facts.py:132-137`).
pub fn diff_touched(diff: &str, file_path: &str) -> Value {
    for change in parse_diff_patch(diff) {
        if change.path == file_path {
            return json!({"touched": true, "added_ranges": ranges_json(&change.added_ranges)});
        }
    }
    json!({"touched": false, "added_ranges": []})
}

/// Just the `added_ranges` half of [`diff_touched`], ported from
/// `changed_lines` (`validation/tools/diff_facts.py:140-142`).
pub fn changed_lines(diff: &str, file_path: &str) -> Value {
    diff_touched(diff, file_path)["added_ranges"].clone()
}

/// `{"files_changed": [...], "trust_boundary_touched": bool}` — ported
/// from `build_diff_impact_map` (`validation/tools/diff_facts.py:153-159`)
/// plus the `DiffImpactMap` tool's own dict projection
/// (`deep_tools.py:68-72`).
pub fn diff_impact_map(diff: &str) -> Value {
    let files: Vec<String> = parse_diff_patch(diff).into_iter().map(|c| c.path).collect();
    let unique: BTreeSet<&String> = files.iter().collect();
    json!({
        "files_changed": unique.into_iter().collect::<Vec<_>>(),
        "trust_boundary_touched": files.iter().any(|p| TRUST_BOUNDARY_RE.is_match(p)),
    })
}

// ── validation/tools/pattern_scanner.py ─────────────────────────────────
//
// Lives in `crate::pattern_scan`: since v1.4 it is a bounded scanner with
// its own limits and summary record, big enough to stand alone.

// ── validation/tools/test_inventory.py ──────────────────────────────────

fn is_test_file(name: &str) -> bool {
    if PY_TEST_EXACT_NAMES.contains(&name) {
        return true;
    }
    if name.ends_with(".py")
        && (name.starts_with(PY_TEST_NAME_PREFIX) || name.ends_with(PY_TEST_NAME_SUFFIX))
    {
        return true;
    }
    JS_TEST_SUFFIXES.iter().any(|suffix| name.ends_with(suffix))
}

fn negative_markers(text: &str) -> Vec<&'static str> {
    MARKER_PATTERNS
        .iter()
        .filter(|(_, rx)| rx.is_match(text).unwrap_or(false))
        .map(|(marker, _)| *marker)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Inventory test files and flag negative/adversarial test markers,
/// ported from `test_inventory`
/// (`validation/tools/test_inventory.py:51-75`).
pub fn test_inventory(root: &Path) -> Value {
    let mut test_files: Vec<(String, Value)> = Vec::new();
    for (rel, path) in iter_in_scope_files(root, true) {
        let name = rel.rsplit('/').next().unwrap_or(&rel);
        if !is_test_file(name) {
            continue;
        }
        let Ok(raw_bytes) = std::fs::read(&path) else {
            continue;
        };
        let text = String::from_utf8_lossy(&raw_bytes);
        let markers = negative_markers(&text);
        test_files.push((
            rel.clone(),
            json!({
                "file": rel,
                "lines": text.lines().count(),
                "negative_test_markers": markers,
                "has_negative_tests": !markers.is_empty(),
            }),
        ));
    }
    test_files.sort_by(|a, b| a.0.cmp(&b.0));
    let with_negative = test_files
        .iter()
        .filter(|(_, v)| v["has_negative_tests"] == Value::Bool(true))
        .count();
    json!({
        "test_files": test_files.iter().map(|(_, v)| v.clone()).collect::<Vec<_>>(),
        "total_test_files": test_files.len(),
        "files_with_negative_tests": with_negative,
    })
}

// ── the executor wrapper ────────────────────────────────────────────────

/// A read-only [`ToolExecutor`] decorator that adds the five fact tools on
/// top of whatever `inner` already offers — the port's equivalent of
/// Python's `build_validation_tools`
/// (`validation/tools/deep_tools.py:98-106`), which likewise appends the
/// fact tools to the generic reader set rather than replacing it.
///
/// It is a **wrapper, not a constructor flag on [`crate::SandboxTools`]**,
/// for one structural reason: `bc_stage_s11::validate_finding` receives a
/// `&dyn ToolExecutor` built by the orchestrator, not a concrete
/// `SandboxTools`, so the only place that knows the diff (S11) is not the
/// place that builds the executor. Wrapping lets S11 add the tools for its
/// own personas without every other stage's executor growing a field it
/// never uses — an S1/S6/S10 session still sees exactly `Read`/`Glob`/
/// `Grep` (plus S10's `Write`/`Edit`), because nothing outside S11
/// constructs this type.
///
/// Every unknown tool name falls through to `inner`, so the wrapper never
/// widens what the wrapped executor allows: if `inner` refuses `Bash` or
/// `Write`, so does this.
pub struct FactTools<'a> {
    inner: &'a dyn ToolExecutor,
    root: PathBuf,
    diff: String,
}

impl<'a> FactTools<'a> {
    /// `root` is the jailed repo root the file-reading tools
    /// (`PatternScan`, `TestInventory`) walk; `diff` is the unified diff
    /// text the diff tools answer from — S10's `RemediationRecord::diff`,
    /// standing in for Python's `workspace/diff.patch`.
    ///
    /// `root` is canonicalized here for the same reason
    /// [`crate::SandboxTools::new`] does it: every later confinement check
    /// then compares against one consistent, fully-resolved root.
    pub fn new(
        inner: &'a dyn ToolExecutor,
        root: impl Into<PathBuf>,
        diff: impl Into<String>,
    ) -> Self {
        let root = root.into();
        let resolved = root.canonicalize().unwrap_or(root);
        FactTools {
            inner,
            root: resolved,
            diff: diff.into(),
        }
    }
}

impl ToolExecutor for FactTools<'_> {
    fn available_tools(&self) -> Vec<ToolSpec> {
        let mut specs = self.inner.available_tools();
        specs.extend(fact_tool_specs());
        specs
    }

    fn execute(&self, name: &str, args: &Value) -> String {
        let file_path = args.get("file_path").and_then(Value::as_str).unwrap_or("");
        let result: Value = match name {
            "DiffTouched" => diff_touched(&self.diff, file_path),
            "ChangedLines" => changed_lines(&self.diff, file_path),
            "DiffImpactMap" => diff_impact_map(&self.diff),
            "PatternScan" => {
                let set_name = args
                    .get("pattern_set")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                match pattern_scan(&self.root, set_name) {
                    Ok(v) => v,
                    // Same `ERROR: ` convention every other tool in this
                    // crate uses, so the agentic loop surfaces it to the
                    // model as a recoverable tool error rather than a fact.
                    Err(message) => return format!("ERROR: {message}"),
                }
            }
            "TestInventory" => test_inventory(&self.root),
            _ => return self.inner.execute(name, args),
        };
        // `Value`'s own `Display` is compact JSON and is infallible —
        // pretty-printing would only spend prompt tokens on indentation
        // for output a model reads once.
        result.to_string()
    }
}

#[cfg(test)]
mod tests;
