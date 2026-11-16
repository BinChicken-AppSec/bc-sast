use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use appsec_llm_client::{ToolExecutor, ToolSpec};
use fancy_regex::Regex as FancyRegex;
use regex::Regex;
use serde_json::{json, Value};

use crate::pattern_scan::pattern_scan;
use crate::schema::fact_tool_specs;
use crate::scope::iter_in_scope_files;

pub const FACT_TOOL_NAMES: [&str; 5] = [
    "DiffTouched",
    "ChangedLines",
    "DiffImpactMap",
    "PatternScan",
    "TestInventory",
];

const GIT_HEADER_PREFIX: &str = "diff --git ";
const GIT_HEADER_MIN_TOKENS: usize = 4;
const OLD_FILE_MARKER: &str = "--- ";
const NEW_FILE_MARKER: &str = "+++ ";
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
            let tokens: Vec<&str> = rest.split(' ').collect();
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

pub fn diff_touched(diff: &str, file_path: &str) -> Value {
    for change in parse_diff_patch(diff) {
        if change.path == file_path {
            return json!({"touched": true, "added_ranges": ranges_json(&change.added_ranges)});
        }
    }
    json!({"touched": false, "added_ranges": []})
}

pub fn changed_lines(diff: &str, file_path: &str) -> Value {
    diff_touched(diff, file_path)["added_ranges"].clone()
}

pub fn diff_impact_map(diff: &str) -> Value {
    let files: Vec<String> = parse_diff_patch(diff).into_iter().map(|c| c.path).collect();
    let unique: BTreeSet<&String> = files.iter().collect();
    json!({
        "files_changed": unique.into_iter().collect::<Vec<_>>(),
        "trust_boundary_touched": files.iter().any(|p| TRUST_BOUNDARY_RE.is_match(p)),
    })
}

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

pub struct FactTools<'a> {
    inner: &'a dyn ToolExecutor,
    root: PathBuf,
    diff: String,
}

impl<'a> FactTools<'a> {
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
                    Err(message) => return format!("ERROR: {message}"),
                }
            }
            "TestInventory" => test_inventory(&self.root),
            _ => return self.inner.execute(name, args),
        };
        result.to_string()
    }
}

#[cfg(test)]
mod tests;
