use super::*;
use serde_json::json;

use crate::SandboxTools;

fn write(dir: &Path, rel: &str, contents: &str) {
    let path = dir.join(rel);
    std::fs::create_dir_all(path.parent().expect("fixture paths always have a parent"))
        .expect("fixture dir is writable");
    std::fs::write(path, contents).expect("fixture file is writable");
}

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

#[test]
fn parse_diff_patch_collects_added_runs_per_file() {
    let changes = parse_diff_patch(DIFF);
    assert_eq!(
        changes,
        vec![
            FileChange {
                path: "src/auth.py".to_string(),
                added_ranges: vec![(11, 2)],
            },
            FileChange {
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
    assert!(parse_diff_patch("diff --git a/x\n").is_empty());
    assert!(parse_diff_patch("diff --git \n").is_empty());
}

#[test]
fn a_git_header_alone_still_tracks_the_new_side_path() {
    let changes = parse_diff_patch("diff --git a/old.bin b/new.bin\nBinary files differ\n");
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].path, "new.bin");
}

#[test]
fn a_marker_path_stops_at_a_tab_and_keeps_a_path_without_a_git_prefix() {
    let changes = parse_diff_patch(
        "--- one.py\t2026-01-01\n+++ one.py\t2026-01-02\n@@ -1 +1,2 @@\n one\n+two\n",
    );
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].path, "one.py");
    assert_eq!(changes[0].added_ranges, vec![(2, 1)]);
}

#[test]
fn a_no_newline_note_does_not_advance_the_line_counter() {
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
    let changes =
        parse_diff_patch("diff --git a/a.py b/a.py\nindex 000..111\nnew file mode 100644\n");
    assert_eq!(changes[0].added_ranges, Vec::new());
}

#[test]
fn a_hunk_header_whose_start_line_overflows_falls_back_to_zero() {
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
    write(dir.path(), "src/app.py", "pytest.raises(X)\n");

    let out = test_inventory(dir.path());
    assert_eq!(out["total_test_files"], 3);
    assert_eq!(out["files_with_negative_tests"], 2);
    let files: Vec<&str> = out["test_files"]
        .as_array()
        .expect("array")
        .iter()
        .map(|f| f["file"].as_str().expect("file"))
        .collect();
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
    assert_eq!(
        out["test_files"][2]["negative_test_markers"],
        json!(["rejects"])
    );
}

#[test]
fn a_negative_marker_does_not_match_inside_a_longer_word() {
    let dir = tempfile::tempdir().expect("tempdir");
    write(
        dir.path(),
        "test_a.py",
        "from unittest.mock import MagicMock\n",
    );
    write(dir.path(), "b_test.py", "x = MagicMocked\n");
    let out = test_inventory(dir.path());
    assert_eq!(
        out["test_files"][1]["negative_test_markers"],
        json!(["mock"])
    );
    assert_eq!(out["test_files"][0]["negative_test_markers"], json!([]));
    assert_eq!(out["test_files"][0]["has_negative_tests"], false);
}

#[test]
fn test_inventory_keeps_test_directories_that_the_secret_scan_drops() {
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

#[cfg(target_os = "linux")]
fn bury_near_path_max(staged: &Path) -> PathBuf {
    const TARGET: usize = 4096 - 100;
    let mut deep = staged
        .parent()
        .expect("staged directory has a parent")
        .canonicalize()
        .expect("staging parent resolves");
    while TARGET.saturating_sub(deep.as_os_str().len() + 1) > 255 {
        deep.push("d".repeat(200));
    }
    std::fs::create_dir_all(&deep).expect("deep fixture directory");
    let buried = deep.join("r".repeat(TARGET - deep.as_os_str().len() - 1));
    std::fs::rename(staged, &buried).expect("move the staged tree into place");
    buried
}

#[cfg(target_os = "linux")]
#[test]
fn test_inventory_skips_an_unreadable_test_file() {
    let base = tempfile::tempdir().expect("tempdir");
    let staged = base.path().join("staged");
    write(&staged, "test_ok.py", "x\n");
    write(&staged, &format!("test_{}.py", "x".repeat(200)), "x\n");
    let root = bury_near_path_max(&staged);
    let out = test_inventory(&root);
    assert_eq!(out["total_test_files"], 1);
    assert_eq!(out["test_files"][0]["file"], "test_ok.py");
}

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
    let dir = tempfile::tempdir().expect("tempdir");
    let inner = SandboxTools::new(dir.path());
    let tools = FactTools::new(&inner, dir.path().join("not-yet"), DIFF);
    assert_eq!(
        tools.execute("TestInventory", &json!({})),
        r#"{"files_with_negative_tests":0,"test_files":[],"total_test_files":0}"#
    );
}
