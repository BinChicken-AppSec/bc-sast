//! Tests for the bounded `PatternScan`. Fixtures are real tempdir trees,
//! because the tool's whole job is to answer from the filesystem.

use super::*;

fn write(dir: &Path, rel: &str, contents: &[u8]) {
    let path = dir.join(rel);
    std::fs::create_dir_all(path.parent().expect("fixture paths have a parent"))
        .expect("fixture dir is writable");
    std::fs::write(path, contents).expect("fixture file is writable");
}

/// The match records (everything but the trailing summary).
fn matches(result: &Value) -> Vec<Value> {
    let all = result.as_array().expect("an array");
    all[..all.len() - 1].to_vec()
}

/// The trailing summary record.
fn summary(result: &Value) -> Value {
    result
        .as_array()
        .expect("an array")
        .last()
        .expect("a summary is always present")
        .clone()
}

fn files(result: &Value) -> Vec<String> {
    matches(result)
        .iter()
        .map(|m| m["file"].as_str().expect("file").to_string())
        .collect()
}

const SECRET: &[u8] = b"password: hunter2hunter2\n";

#[test]
fn a_hardcoded_secret_is_located_without_any_candidate_text() {
    let dir = tempfile::tempdir().expect("tempdir");
    write(
        dir.path(),
        "app/config.yaml",
        b"name: svc\npassword: hunter2hunter2\nkey: AKIAAAAAAAAAAAAAAAAA\n",
    );
    let result = pattern_scan(dir.path(), "secret_exposure").expect("known set");
    let hits = matches(&result);
    assert_eq!(hits.len(), 2, "{result}");
    assert_eq!(
        hits[0],
        json!({
            "kind": "match",
            "file": "app/config.yaml",
            "line": 2,
            "pattern_set": "secret_exposure",
            "rule": "__builtin__",
            "description": "hardcoded secret or credential",
        })
    );
    let rendered = result.to_string();
    assert!(!rendered.contains("hunter2"), "{rendered}");
    assert!(!rendered.contains("AKIA"), "{rendered}");
    assert!(!rendered.contains("snippet"), "{rendered}");
}

#[test]
fn the_summary_reports_counts_limits_and_no_truncation_for_a_clean_scan() {
    let dir = tempfile::tempdir().expect("tempdir");
    write(dir.path(), "a.yaml", SECRET);
    write(dir.path(), "b.yaml", b"nothing here\n");
    let result = pattern_scan(dir.path(), "secret_exposure").expect("known set");
    assert_eq!(
        summary(&result),
        json!({
            "kind": "summary",
            "pattern_set": "secret_exposure",
            "matches_seen": 1,
            "matches_returned": 1,
            "files_considered": 2,
            "files_scanned": 2,
            "files_too_large": 0,
            "files_unreadable": 0,
            "binary_files": 0,
            "bytes_scanned": SECRET.len() + 13,
            "truncated": false,
            "truncation_reasons": [],
            "limits": {
                "max_file_bytes": 524_288,
                "max_total_bytes": 33_554_432,
                "max_files": 10_000,
                "max_matches_per_file": 50,
                "max_matches": 200,
            },
        })
    );
}

#[test]
fn insecure_values_are_ordered_by_file_then_line() {
    let dir = tempfile::tempdir().expect("tempdir");
    write(dir.path(), "z.yaml", b"debug: true\n");
    write(
        dir.path(),
        "a.yaml",
        b"x: 1\nssl_verify: false\ndebug: true\n",
    );
    let result = pattern_scan(dir.path(), "insecure_value").expect("known set");
    let located: Vec<(String, u64)> = matches(&result)
        .iter()
        .map(|h| {
            (
                h["file"].as_str().expect("file").to_string(),
                h["line"].as_u64().expect("line"),
            )
        })
        .collect();
    assert_eq!(
        located,
        vec![
            ("a.yaml".to_string(), 2),
            ("a.yaml".to_string(), 3),
            ("z.yaml".to_string(), 1)
        ]
    );
    assert_eq!(
        matches(&result)[0]["description"],
        "insecure configuration value"
    );
}

#[test]
fn an_unknown_set_is_an_error_rather_than_an_empty_result() {
    let dir = tempfile::tempdir().expect("tempdir");
    assert_eq!(
        pattern_scan(dir.path(), "made_up").expect_err("unknown set"),
        "unknown pattern_set 'made_up'; available: insecure_value, secret_exposure"
    );
}

#[test]
fn binary_media_vendor_test_and_host_artifact_files_are_skipped() {
    let dir = tempfile::tempdir().expect("tempdir");
    write(dir.path(), "node_modules/dep/conf.yaml", SECRET);
    write(dir.path(), "tests/fixture.yaml", SECRET);
    write(dir.path(), "test_settings.py", SECRET); // S1 test-file glob
    write(dir.path(), "logo.SVG", SECRET);
    write(dir.path(), "diff.patch", SECRET);
    write(dir.path(), "blob.dat", b"password: hunter2hunter2\x00");
    write(dir.path(), "keep.yaml", SECRET);
    let result = pattern_scan(dir.path(), "secret_exposure").expect("known set");
    assert_eq!(files(&result), vec!["keep.yaml"], "{result}");
    let summary = summary(&result);
    assert_eq!(summary["binary_files"], 1);
    assert_eq!(summary["truncation_reasons"], json!(["binary_files"]));
    assert_eq!(summary["truncated"], true);
}

#[test]
fn invalid_utf8_is_read_lossily_instead_of_skipping_the_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    write(dir.path(), "mixed.yaml", &[SECRET, &[0xff, 0xfe]].concat());
    let result = pattern_scan(dir.path(), "secret_exposure").expect("known set");
    assert_eq!(matches(&result).len(), 1, "{result}");
}

#[test]
fn a_file_over_the_per_file_size_limit_is_skipped_and_reported() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut big = SECRET.to_vec();
    big.resize(MAX_FILE_BYTES as usize + 1, b'#');
    write(dir.path(), "big.yaml", &big);
    write(dir.path(), "small.yaml", SECRET);
    let result = pattern_scan(dir.path(), "secret_exposure").expect("known set");
    assert_eq!(files(&result), vec!["small.yaml"]);
    let summary = summary(&result);
    assert_eq!(summary["files_too_large"], 1);
    assert_eq!(summary["files_considered"], 2);
    assert_eq!(summary["files_scanned"], 1);
    assert_eq!(summary["truncation_reasons"], json!(["file_size_limit"]));
}

#[test]
fn per_file_and_overall_match_caps_truncate_but_still_count_every_match() {
    let dir = tempfile::tempdir().expect("tempdir");
    let crowded = SECRET.repeat(MAX_MATCHES_PER_FILE + 5);
    for i in 0..5 {
        write(dir.path(), &format!("f{i}.yaml"), &crowded);
    }
    let result = pattern_scan(dir.path(), "secret_exposure").expect("known set");
    assert_eq!(matches(&result).len(), MAX_MATCHES);
    let summary = summary(&result);
    assert_eq!(summary["matches_seen"], 5 * (MAX_MATCHES_PER_FILE + 5));
    assert_eq!(summary["matches_returned"], MAX_MATCHES);
    assert_eq!(
        summary["truncation_reasons"],
        json!(["per_file_match_limit", "overall_match_limit"])
    );
}

#[test]
fn the_file_count_limit_stops_the_scan() {
    let dir = tempfile::tempdir().expect("tempdir");
    for i in 0..=MAX_FILES {
        write(dir.path(), &format!("d{}/f{i}.txt", i % 50), b"x\n");
    }
    let result = pattern_scan(dir.path(), "secret_exposure").expect("known set");
    let summary = summary(&result);
    assert_eq!(summary["files_considered"], MAX_FILES);
    assert_eq!(summary["truncation_reasons"], json!(["overall_file_limit"]));
}

#[test]
fn the_total_byte_budget_stops_the_scan() {
    let dir = tempfile::tempdir().expect("tempdir");
    // Binary (a leading NUL) so no regex runs over 32 MiB in a debug
    // build: the budget counts bytes READ, scanned or not, exactly as
    // Python's `bytes_scanned` does.
    let mut chunk = vec![b'#'; MAX_FILE_BYTES as usize];
    chunk[0] = 0;
    let needed = (MAX_TOTAL_BYTES / MAX_FILE_BYTES) as usize + 1;
    for i in 0..needed {
        write(dir.path(), &format!("f{i:03}.txt"), &chunk);
    }
    let result = pattern_scan(dir.path(), "secret_exposure").expect("known set");
    let summary = summary(&result);
    assert_eq!(summary["bytes_scanned"], MAX_TOTAL_BYTES);
    assert_eq!(
        summary["truncation_reasons"],
        json!(["binary_files", "overall_byte_limit"])
    );
    assert_eq!(summary["files_considered"], needed);
    assert_eq!(summary["files_scanned"], 0);
}

#[test]
fn read_bounded_reports_a_read_error_as_unreadable() {
    // Opening a directory succeeds on Unix and the read then fails, the
    // cheapest way to reach the mid-read error arm without root games.
    let dir = tempfile::tempdir().expect("tempdir");
    let result = read_bounded(dir.path(), 10);
    if cfg!(unix) {
        assert!(result.unreadable, "{result:?}");
    }
    let missing = read_bounded(&dir.path().join("missing"), 10);
    assert!(missing.unreadable);
}

#[cfg(unix)]
#[test]
fn an_unreadable_file_is_counted_instead_of_failing_the_scan() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().expect("tempdir");
    write(dir.path(), "ok.yaml", SECRET);
    let locked = dir.path().join("locked.yaml");
    std::fs::write(&locked, SECRET).expect("fixture");
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).expect("chmod");
    if std::fs::File::open(&locked).is_ok() {
        // Running as root: permissions cannot make the file unreadable.
        // The companion test below covers the same path for root.
        eprintln!(
            "SKIPPED (permissions not enforced for this user): \
             an_unreadable_file_is_counted_instead_of_failing_the_scan"
        );
        return;
    }
    let result = pattern_scan(dir.path(), "secret_exposure").expect("known set");
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o644)).expect("chmod");
    assert_eq!(files(&result), vec!["ok.yaml"]);
    assert_eq!(summary(&result)["files_unreadable"], 1);
}

/// The same "count it, keep scanning" path for any user, root included:
/// `/proc/sys/vm/drop_caches` is a regular file the kernel refuses to read
/// even with CAP_DAC_OVERRIDE, so it is unreadable where chmod is not.
#[cfg(target_os = "linux")]
#[test]
fn a_file_no_user_can_read_is_counted_instead_of_failing_the_scan() {
    let result =
        pattern_scan(std::path::Path::new("/proc/sys/vm"), "secret_exposure").expect("known set");
    assert!(
        summary(&result)["files_unreadable"].as_u64().unwrap() >= 1,
        "{result}"
    );
    assert!(matches(&result).is_empty(), "{result}");
}

#[cfg(unix)]
#[test]
fn a_symlink_out_of_the_repo_is_never_followed() {
    let base = tempfile::tempdir().expect("tempdir");
    let root = base.path().join("repo");
    std::fs::create_dir(&root).expect("repo dir");
    let outside = base.path().join("host-secrets.yaml");
    std::fs::write(&outside, SECRET).expect("fixture");
    std::os::unix::fs::symlink(&outside, root.join("config.yaml")).expect("symlink");
    let result = pattern_scan(&root, "secret_exposure").expect("known set");
    assert!(
        matches(&result).is_empty(),
        "escaped the repo root: {result}"
    );
    assert_eq!(summary(&result)["files_considered"], 0);
}

#[test]
fn regexes_match_the_s1_preprocess_originals() {
    // Spot-checks pinning the two ported patterns to the behaviors the
    // Python source documents.
    assert!(SECRET_RX
        .is_match("api_key = 'abcdefghijkl'")
        .expect("no backtrack limit"));
    assert!(!SECRET_RX.is_match("password: ${DB_PASSWORD}").expect("ok"));
    assert!(!SECRET_RX.is_match("password: vault:secret/db").expect("ok"));
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
