//! Tests for the five deterministic fact tools. Fixtures are built on
//! disk (a real tempdir tree) rather than mocked, because the whole point
//! of these tools is that they answer from the filesystem and the diff
//! text instead of from the model's imagination.

use super::*;
use serde_json::json;

use crate::SandboxTools;

fn write(dir: &Path, rel: &str, contents: &str) {
    let path = dir.join(rel);
    std::fs::create_dir_all(path.parent().expect("fixture paths always have a parent"))
        .expect("fixture dir is writable");
    std::fs::write(path, contents).expect("fixture file is writable");
}

/// A two-file unified diff: one modified file, one deleted file.
const DIFF: &str = "\
diff --git a/src/auth.py b/src/auth.py
index 1111111..2222222 100644
--- a/src/auth.py
+++ b/src/auth.py
@@ -10,6 +10,8 @@ def login(user):
     check(user)
-    query(\"SELECT \" + user)
+    query(\"SELECT ?\", user)
+    audit(user)
     return ok
diff --git a/docs/old.md b/docs/old.md
deleted file mode 100644
--- a/docs/old.md
+++ /dev/null
@@ -1,2 +0,0 @@
-gone
-also gone
";

// ── the diff parser ─────────────────────────────────────────────────────

#[test]
fn parse_diff_patch_collects_added_runs_per_file() {
    let changes = parse_diff_patch(DIFF);
    assert_eq!(
        changes,
        vec![
            FileChange {
                path: "src/auth.py".to_string(),
                // Line 10 is context, 11 was removed, so the two added
                // lines start at the new-side line 11 and run for 2.
                added_ranges: vec![(11, 2)],
            },
            FileChange {
                // "+++ /dev/null" is a deletion: the OLD path is kept so
                // the file still shows up as touched.
                path: "docs/old.md".to_string(),
                added_ranges: Vec::new(),
            },
        ]
    );
}

#[test]
fn parse_diff_patch_on_empty_input_finds_nothing() {
    assert!(parse_diff_patch("").is_empty());
}

#[test]
fn a_truncated_git_header_contributes_no_path() {
    // Fewer than GIT_HEADER_MIN_TOKENS: no usable new-side path, and no
    // "+++ " marker follows either, so nothing is recorded.
    assert!(parse_diff_patch("diff --git a/x\n").is_empty());
    assert!(parse_diff_patch("diff --git \n").is_empty());
}

#[test]
fn a_git_header_alone_still_tracks_the_new_side_path() {
    // The rename/binary fallback: no ---/+++ markers at all.
    let changes = parse_diff_patch("diff --git a/old.bin b/new.bin\nBinary files differ\n");
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].path, "new.bin");
}

#[test]
fn a_marker_path_stops_at_a_tab_and_keeps_a_path_without_a_git_prefix() {
    // `git diff` appends a timestamp after a tab in some formats, and a
    // plain `diff -u` has no a/ b/ prefixes at all.
    let changes = parse_diff_patch(
        "--- one.py\t2026-01-01\n+++ one.py\t2026-01-02\n@@ -1 +1,2 @@\n one\n+two\n",
    );
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].path, "one.py");
    assert_eq!(changes[0].added_ranges, vec![(2, 1)]);
}

#[test]
fn a_no_newline_note_does_not_advance_the_line_counter() {
    // "\ No newline at end of file" is a note about the previous line,
    // not a line of its own — counting it would shift every later range.
    let changes = parse_diff_patch(
        "+++ a.py\n@@ -1 +1,3 @@\n one\n\\ No newline at end of file\n+two\n+three\n",
    );
    assert_eq!(changes[0].added_ranges, vec![(2, 2)]);
}

#[test]
fn a_removed_line_between_two_added_runs_splits_them() {
    let changes = parse_diff_patch("+++ a.py\n@@ -1,4 +1,4 @@\n+one\n-old\n+two\n ctx\n");
    assert_eq!(changes[0].added_ranges, vec![(1, 1), (2, 1)]);
}

#[test]
fn lines_before_any_hunk_header_are_ignored() {
    // `new_line_number` is 0 until a hunk header lands, so extended-header
    // lines ("index ...", "new file mode ...") never become code lines.
    let changes =
        parse_diff_patch("diff --git a/a.py b/a.py\nindex 000..111\nnew file mode 100644\n");
    assert_eq!(changes[0].added_ranges, Vec::new());
}

#[test]
fn a_hunk_header_whose_start_line_overflows_falls_back_to_zero() {
    // `\d+` matches it, `i64` cannot hold it — the parse failure must not
    // panic, it just leaves the parser outside any hunk.
    let changes = parse_diff_patch("+++ a.py\n@@ -1 +99999999999999999999999 @@\n+added\n");
    assert_eq!(changes[0].added_ranges, Vec::new());
}

#[test]
fn file_change_is_debug_clone_and_comparable() {
    let change = FileChange {
        path: "a.py".to_string(),
        added_ranges: vec![(1, 2)],
    };
    assert_eq!(change.clone(), change);
    assert!(format!("{change:?}").contains("a.py"));
}

// ── DiffTouched / ChangedLines / DiffImpactMap ──────────────────────────

#[test]
fn diff_touched_reports_a_changed_file_and_its_added_runs() {
    assert_eq!(
        diff_touched(DIFF, "src/auth.py"),
        json!({"touched": true, "added_ranges": [[11, 2]]})
    );
}

#[test]
fn diff_touched_reports_an_untouched_file_with_no_ranges() {
    assert_eq!(
        diff_touched(DIFF, "src/other.py"),
        json!({"touched": false, "added_ranges": []})
    );
}

#[test]
fn changed_lines_is_the_added_ranges_half_of_diff_touched() {
    assert_eq!(changed_lines(DIFF, "src/auth.py"), json!([[11, 2]]));
    assert_eq!(changed_lines(DIFF, "nope.py"), json!([]));
}

#[test]
fn diff_impact_map_lists_unique_sorted_files_and_flags_a_trust_boundary() {
    assert_eq!(
        diff_impact_map(DIFF),
        json!({
            "files_changed": ["docs/old.md", "src/auth.py"],
            // "auth" matches TRUST_BOUNDARY_RE.
            "trust_boundary_touched": true,
        })
    );
}

#[test]
fn diff_impact_map_without_a_trust_boundary_path_says_so() {
    let diff = "+++ src/render.py\n@@ -1 +1,2 @@\n one\n+two\n";
    assert_eq!(
        diff_impact_map(diff),
        json!({"files_changed": ["src/render.py"], "trust_boundary_touched": false})
    );
}

// ── PatternScan ─────────────────────────────────────────────────────────

#[test]
fn pattern_scan_finds_a_hardcoded_secret_with_its_file_and_line() {
    let dir = tempfile::tempdir().expect("tempdir");
    write(
        dir.path(),
        "app/config.yaml",
        "name: svc\npassword: hunter2hunter2\n",
    );
    let hits = pattern_scan(dir.path(), "secret_exposure").expect("known set");
    let hits = hits.as_array().expect("an array of matches");
    assert_eq!(hits.len(), 1, "{hits:?}");
    assert_eq!(hits[0]["file"], "app/config.yaml");
    assert_eq!(hits[0]["line"], 2);
    assert_eq!(hits[0]["rule"], "__builtin__");
    assert_eq!(hits[0]["pattern_set"], "secret_exposure");
    assert_eq!(hits[0]["description"], "hardcoded secret or credential");
}

#[test]
fn pattern_scan_redacts_the_credential_out_of_the_snippet() {
    // The one deliberate divergence from Python: the persona is told
    // WHERE the secret is, never what it is.
    let dir = tempfile::tempdir().expect("tempdir");
    write(dir.path(), "keys.env", "AWS_KEY = AKIAAAAAAAAAAAAAAAAA\n");
    let hits = pattern_scan(dir.path(), "secret_exposure").expect("known set");
    let rendered = hits.to_string();
    assert!(!rendered.contains("AKIAAAAAAAAAAAAAAAAA"), "{rendered}");
    assert!(rendered.contains("keys.env"), "{rendered}");
}

#[test]
fn pattern_scan_finds_insecure_values_and_orders_hits_by_file_then_line() {
    let dir = tempfile::tempdir().expect("tempdir");
    write(dir.path(), "z.yaml", "debug: true\n");
    write(
        dir.path(),
        "a.yaml",
        "x: 1\nssl_verify: false\ndebug: true\n",
    );
    let hits = pattern_scan(dir.path(), "insecure_value").expect("known set");
    let hits = hits.as_array().expect("an array of matches");
    let located: Vec<(&str, u64)> = hits
        .iter()
        .map(|h| {
            (
                h["file"].as_str().expect("file"),
                h["line"].as_u64().expect("line"),
            )
        })
        .collect();
    assert_eq!(located, vec![("a.yaml", 2), ("a.yaml", 3), ("z.yaml", 1)]);
    assert_eq!(hits[0]["description"], "insecure configuration value");
}

#[test]
fn pattern_scan_rejects_an_unknown_set_rather_than_returning_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let err = pattern_scan(dir.path(), "made_up").expect_err("unknown set");
    assert_eq!(
        err,
        "unknown pattern_set 'made_up'; available: insecure_value, secret_exposure"
    );
}

#[test]
fn pattern_scan_skips_binary_media_vendor_and_test_files() {
    let dir = tempfile::tempdir().expect("tempdir");
    let secret = "password: hunter2hunter2\n";
    write(dir.path(), "node_modules/dep/conf.yaml", secret); // infra dir
    write(dir.path(), "tests/fixture.yaml", secret); // test dir
    write(dir.path(), "logo.SVG", secret); // excluded ext, case-insensitively
    write(dir.path(), "diff.patch", secret); // host artifact
    std::fs::write(dir.path().join("blob.dat"), b"password: hunter2hunter2\x00")
        .expect("binary fixture"); // NUL byte -> binary
    write(dir.path(), "keep.yaml", secret);

    let hits = pattern_scan(dir.path(), "secret_exposure").expect("known set");
    let files: Vec<&str> = hits
        .as_array()
        .expect("array")
        .iter()
        .map(|h| h["file"].as_str().expect("file"))
        .collect();
    assert_eq!(files, vec!["keep.yaml"], "{hits}");
}

#[test]
fn pattern_scan_reads_invalid_utf8_lossily_instead_of_skipping_the_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("mixed.yaml"),
        [b"password: hunter2hunter2\n".as_slice(), &[0xff, 0xfe]].concat(),
    )
    .expect("fixture");
    let hits = pattern_scan(dir.path(), "secret_exposure").expect("known set");
    assert_eq!(hits.as_array().expect("array").len(), 1, "{hits}");
}

#[cfg(unix)]
#[test]
fn pattern_scan_skips_an_unreadable_file_instead_of_failing_the_scan() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().expect("tempdir");
    write(dir.path(), "ok.yaml", "password: hunter2hunter2\n");
    let locked = dir.path().join("locked.yaml");
    std::fs::write(&locked, "password: hunter2hunter2\n").expect("fixture");
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).expect("chmod");
    let hits = pattern_scan(dir.path(), "secret_exposure").expect("known set");
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o644)).expect("chmod");
    let files: Vec<&str> = hits
        .as_array()
        .expect("array")
        .iter()
        .map(|h| h["file"].as_str().expect("file"))
        .collect();
    assert_eq!(files, vec!["ok.yaml"]);
}

#[cfg(unix)]
#[test]
fn pattern_scan_never_follows_a_symlink_out_of_the_repo() {
    // The host-file-disclosure guard `_scope.py::_escapes_workspace`
    // exists for: a symlinked "config" pointing at a host secrets file.
    let base = tempfile::tempdir().expect("tempdir");
    let root = base.path().join("repo");
    std::fs::create_dir(&root).expect("repo dir");
    let outside = base.path().join("host-secrets.yaml");
    std::fs::write(&outside, "password: hunter2hunter2\n").expect("fixture");
    std::os::unix::fs::symlink(&outside, root.join("config.yaml")).expect("symlink");

    let hits = pattern_scan(&root, "secret_exposure").expect("known set");
    assert_eq!(hits, json!([]), "escaped the repo root: {hits}");
}

// ── TestInventory ───────────────────────────────────────────────────────

#[test]
fn test_inventory_finds_python_and_js_test_files_and_flags_negative_markers() {
    let dir = tempfile::tempdir().expect("tempdir");
    write(
        dir.path(),
        "tests/test_login.py",
        "def t():\n    pytest.raises(X)\n",
    );
    write(dir.path(), "src/conftest.py", "import pytest\n");
    write(
        dir.path(),
        "web/login.spec.ts",
        "it('rejects bad input', () => {})\n",
    );
    write(dir.path(), "src/app.py", "pytest.raises(X)\n"); // not a test file

    let out = test_inventory(dir.path());
    assert_eq!(out["total_test_files"], 3);
    assert_eq!(out["files_with_negative_tests"], 2);
    let files: Vec<&str> = out["test_files"]
        .as_array()
        .expect("array")
        .iter()
        .map(|f| f["file"].as_str().expect("file"))
        .collect();
    // Sorted by path, and the non-test `src/app.py` is absent.
    assert_eq!(
        files,
        vec![
            "src/conftest.py",
            "tests/test_login.py",
            "web/login.spec.ts"
        ]
    );
    assert_eq!(
        out["test_files"][1]["negative_test_markers"],
        json!(["pytest.raises"])
    );
    assert_eq!(out["test_files"][1]["has_negative_tests"], true);
    assert_eq!(out["test_files"][1]["lines"], 2);
    assert_eq!(out["test_files"][0]["has_negative_tests"], false);
    // "rejects" is one marker; "invalid" is NOT, because "input" ends the
    // word before it — word-boundary matching, per Python.
    assert_eq!(
        out["test_files"][2]["negative_test_markers"],
        json!(["rejects"])
    );
}

#[test]
fn a_negative_marker_does_not_match_inside_a_longer_word() {
    // The reason Python compiles `(?<!\w)marker(?!\w)` rather than a plain
    // substring search: "mock" must not fire on "MagicMock".
    let dir = tempfile::tempdir().expect("tempdir");
    write(
        dir.path(),
        "test_a.py",
        "from unittest.mock import MagicMock\n",
    );
    write(dir.path(), "b_test.py", "x = MagicMocked\n");
    let out = test_inventory(dir.path());
    // `unittest.mock` DOES contain a bare `mock` at a word boundary...
    assert_eq!(
        out["test_files"][1]["negative_test_markers"],
        json!(["mock"])
    );
    // ...but `MagicMocked` alone does not.
    assert_eq!(out["test_files"][0]["negative_test_markers"], json!([]));
    assert_eq!(out["test_files"][0]["has_negative_tests"], false);
}

#[test]
fn test_inventory_keeps_test_directories_that_the_secret_scan_drops() {
    // The whole reason `_scope.py` partitions the production exclude set:
    // `tests/` is out of scope for a secret scan and in scope here.
    let dir = tempfile::tempdir().expect("tempdir");
    write(dir.path(), "tests/test_a.py", "x\n");
    write(dir.path(), "node_modules/test_vendor.py", "x\n");
    let out = test_inventory(dir.path());
    assert_eq!(out["total_test_files"], 1);
    assert_eq!(out["test_files"][0]["file"], "tests/test_a.py");
}

#[test]
fn every_test_file_naming_convention_python_recognizes_is_recognized_here() {
    for name in [
        "conftest.py",
        "tests.py",
        "test.py",
        "test_x.py",
        "x_test.py",
        "a.test.js",
        "a.test.jsx",
        "a.test.ts",
        "a.test.tsx",
        "a.spec.js",
        "a.spec.jsx",
        "a.spec.ts",
        "a.spec.tsx",
    ] {
        assert!(is_test_file(name), "{name} should be a test file");
    }
    for name in ["app.py", "test_x.rb", "spec.js", "readme.md"] {
        assert!(!is_test_file(name), "{name} should not be a test file");
    }
}

#[cfg(unix)]
#[test]
fn test_inventory_skips_an_unreadable_test_file() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().expect("tempdir");
    let locked = dir.path().join("test_locked.py");
    std::fs::write(&locked, "x\n").expect("fixture");
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).expect("chmod");
    let out = test_inventory(dir.path());
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o644)).expect("chmod");
    assert_eq!(out["total_test_files"], 0);
}

// ── the scope partition ─────────────────────────────────────────────────

#[test]
fn the_test_dir_partition_is_still_a_subset_of_the_production_exclude_set() {
    // Python enforces this at import time with a `raise`
    // (`validation/tools/_scope.py:48-52`): if the production walk adds a
    // new test directory and this list is not updated, `TestInventory`
    // silently stops seeing that directory's tests. Rust has no import
    // hook, so the guard lives here, where CI runs it.
    let production: BTreeSet<&str> = bc_repo_analysis::DEFAULT_EXCLUDE_DIRS
        .iter()
        .copied()
        .collect();
    let missing: Vec<&str> = TEST_DIRS
        .iter()
        .copied()
        .filter(|d| !production.contains(d))
        .collect();
    assert!(
        missing.is_empty(),
        "TEST_DIRS drifted from bc_repo_analysis::DEFAULT_EXCLUDE_DIRS: {missing:?}"
    );
    // ...and the infra half is exactly the rest of it.
    assert_eq!(INFRA_DIRS.len(), production.len() - TEST_DIRS.len());
}

#[test]
fn regexes_match_the_s1_preprocess_originals() {
    // Spot-checks pinning the two ported patterns to the behaviours the
    // Python source documents, so a future edit to either string is
    // caught by a failing assertion rather than by a silent scan gap.
    assert!(SECRET_RX
        .is_match("api_key = 'abcdefghijkl'")
        .expect("no backtrack limit"));
    // Templated / vault refs are deliberately NOT secrets.
    assert!(!SECRET_RX.is_match("password: ${DB_PASSWORD}").expect("ok"));
    assert!(!SECRET_RX.is_match("password: vault:secret/db").expect("ok"));
    // A nested key whose "value" is really another key.
    assert!(!SECRET_RX
        .is_match("auth-token:\n  timeout: 30")
        .expect("ok"));
    assert!(INSECURE_RX
        .is_match("InsecureSkipVerify = true")
        .expect("ok"));
    assert!(INSECURE_RX.is_match("allow_anonymous: yes").expect("ok"));
    assert!(!INSECURE_RX.is_match("tls_verify: true").expect("ok"));
}

#[test]
fn pattern_set_resolves_both_builtin_names_and_nothing_else() {
    assert!(pattern_set("secret_exposure").is_some());
    assert!(pattern_set("insecure_value").is_some());
    assert!(pattern_set("SECRET_EXPOSURE").is_none());
}

// ── the executor wrapper ────────────────────────────────────────────────

fn fixture_repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    write(dir.path(), "src/auth.py", "def login(u):\n    return u\n");
    write(dir.path(), "conf.yaml", "debug: true\n");
    write(
        dir.path(),
        "test_auth.py",
        "def t():\n    pytest.raises(X)\n",
    );
    dir
}

#[test]
fn fact_tools_advertises_the_wrapped_readers_plus_the_five_fact_tools() {
    let dir = fixture_repo();
    let inner = SandboxTools::new(dir.path());
    let tools = FactTools::new(&inner, dir.path(), DIFF);
    let names: Vec<String> = tools
        .available_tools()
        .into_iter()
        .map(|t| t.name)
        .collect();
    assert_eq!(
        names,
        vec![
            "Read",
            "Glob",
            "Grep",
            "DiffTouched",
            "ChangedLines",
            "DiffImpactMap",
            "PatternScan",
            "TestInventory"
        ]
    );
}

#[test]
fn fact_tools_dispatches_every_one_of_the_five() {
    let dir = fixture_repo();
    let inner = SandboxTools::new(dir.path());
    let tools = FactTools::new(&inner, dir.path(), DIFF);

    assert_eq!(
        tools.execute("DiffTouched", &json!({"file_path": "src/auth.py"})),
        r#"{"added_ranges":[[11,2]],"touched":true}"#
    );
    assert_eq!(
        tools.execute("ChangedLines", &json!({"file_path": "src/auth.py"})),
        "[[11,2]]"
    );
    assert_eq!(
        tools.execute("DiffImpactMap", &json!({})),
        r#"{"files_changed":["docs/old.md","src/auth.py"],"trust_boundary_touched":true}"#
    );
    let scan = tools.execute("PatternScan", &json!({"pattern_set": "insecure_value"}));
    assert!(scan.contains(r#""file":"conf.yaml""#), "{scan}");
    let inventory = tools.execute("TestInventory", &json!({}));
    assert!(inventory.contains(r#""total_test_files":1"#), "{inventory}");
    assert!(inventory.contains("pytest.raises"), "{inventory}");
}

#[test]
fn a_missing_argument_degrades_to_the_empty_string_not_a_panic() {
    let dir = fixture_repo();
    let inner = SandboxTools::new(dir.path());
    let tools = FactTools::new(&inner, dir.path(), DIFF);
    assert_eq!(
        tools.execute("DiffTouched", &json!({})),
        r#"{"added_ranges":[],"touched":false}"#
    );
    assert_eq!(tools.execute("ChangedLines", &json!({})), "[]");
    assert_eq!(
        tools.execute("PatternScan", &json!({})),
        "ERROR: unknown pattern_set ''; available: insecure_value, secret_exposure"
    );
}

#[test]
fn an_unknown_pattern_set_is_a_recoverable_tool_error() {
    let dir = fixture_repo();
    let inner = SandboxTools::new(dir.path());
    let tools = FactTools::new(&inner, dir.path(), DIFF);
    assert_eq!(
        tools.execute("PatternScan", &json!({"pattern_set": "nope"})),
        "ERROR: unknown pattern_set 'nope'; available: insecure_value, secret_exposure"
    );
}

#[test]
fn fact_tools_delegates_every_other_name_to_the_wrapped_executor() {
    let dir = fixture_repo();
    let inner = SandboxTools::new(dir.path());
    let tools = FactTools::new(&inner, dir.path(), DIFF);
    assert_eq!(
        tools.execute("Read", &json!({"path": "conf.yaml"})),
        "1\tdebug: true"
    );
    // ...including refusing what the wrapped executor refuses. The
    // wrapper never widens the inner tool policy.
    assert_eq!(
        tools.execute("Bash", &json!({"command": "ls"})),
        "ERROR: tool 'Bash' is not available on this backend"
    );
    assert_eq!(
        tools.execute("Write", &json!({"path": "x", "content": "y"})),
        "ERROR: tool 'Write' is not available on this backend"
    );
}

#[test]
fn a_root_that_does_not_exist_yet_is_kept_as_given() {
    // `canonicalize` fails on a path with no inode; the tools then simply
    // find nothing, rather than the constructor failing.
    let dir = tempfile::tempdir().expect("tempdir");
    let inner = SandboxTools::new(dir.path());
    let tools = FactTools::new(&inner, dir.path().join("not-yet"), DIFF);
    assert_eq!(
        tools.execute("TestInventory", &json!({})),
        r#"{"files_with_negative_tests":0,"test_files":[],"total_test_files":0}"#
    );
}
