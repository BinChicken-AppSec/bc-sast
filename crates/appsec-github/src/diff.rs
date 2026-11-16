use std::collections::{BTreeMap, BTreeSet};

pub fn parse_diff(diff: &str) -> BTreeMap<String, BTreeSet<i64>> {
    let mut result: BTreeMap<String, BTreeSet<i64>> = BTreeMap::new();
    let mut current_file: Option<String> = None;
    let mut new_line: i64 = 0;
    let mut in_hunk = false;

    for line in diff.lines() {
        if let Some(path) = line.strip_prefix("+++ ") {
            in_hunk = false;
            current_file = normalize_diff_path(path);
        } else if let Some(start) = line.strip_prefix("@@").and_then(parse_hunk_header) {
            new_line = start;
            in_hunk = true;
        } else if in_hunk {
            in_hunk = record_hunk_line(line, &current_file, &mut new_line, &mut result);
        }
    }

    result
}

fn record_hunk_line(
    line: &str,
    current_file: &Option<String>,
    new_line: &mut i64,
    result: &mut BTreeMap<String, BTreeSet<i64>>,
) -> bool {
    match line.chars().next() {
        Some('+') | Some(' ') => {
            if let Some(file) = current_file {
                result.entry(file.clone()).or_default().insert(*new_line);
            }
            *new_line += 1;
            true
        }
        Some('-') => true,
        Some('\\') => true,
        _ => false,
    }
}

fn normalize_diff_path(path: &str) -> Option<String> {
    let trimmed = path.trim();
    if trimmed == "/dev/null" {
        return None;
    }
    Some(trimmed.strip_prefix("b/").unwrap_or(trimmed).to_string())
}

fn parse_hunk_header(rest: &str) -> Option<i64> {
    let plus_idx = rest.find('+')?;
    let after_plus = &rest[plus_idx + 1..];
    let end = after_plus.find([',', ' '])?;
    after_plus[..end].parse::<i64>().ok()
}

fn parse_old_range(rest: &str) -> Option<(i64, i64)> {
    let minus_idx = rest.find('-')?;
    let after_minus = &rest[minus_idx + 1..];
    let end = after_minus.find([',', ' '])?;
    let start: i64 = after_minus[..end].parse().ok()?;
    if after_minus.as_bytes().get(end) == Some(&b',') {
        let after_comma = &after_minus[end + 1..];
        let count_end = after_comma.find(' ')?;
        let count: i64 = after_comma[..count_end].parse().ok()?;
        Some((start, count))
    } else {
        Some((start, 1))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SingleHunkFix {
    pub file: String,
    pub old_start: i64,
    pub old_end: i64,
    pub new_lines: Vec<String>,
}

pub fn parse_single_hunk_fix(diff: &str) -> Option<SingleHunkFix> {
    let mut hunks = parse_multi_hunk_fix(diff)?;
    if hunks.len() != 1 {
        return None;
    }
    Some(hunks.remove(0))
}

pub fn parse_multi_hunk_fix(diff: &str) -> Option<Vec<SingleHunkFix>> {
    let mut file: Option<String> = None;
    let mut hunks: Vec<SingleHunkFix> = Vec::new();
    let mut old_start = 0i64;
    let mut old_end = 0i64;
    let mut new_lines: Vec<String> = Vec::new();
    let mut file_count = 0u32;
    let mut in_hunk = false;
    let mut have_open_hunk = false;

    for line in diff.lines() {
        if let Some(path) = line.strip_prefix("+++ ") {
            in_hunk = false;
            file = Some(normalize_diff_path(path)?);
            file_count += 1;
            if file_count > 1 {
                return None;
            }
        } else if let Some(rest) = line.strip_prefix("@@") {
            if have_open_hunk {
                hunks.push(SingleHunkFix {
                    file: file.clone()?,
                    old_start,
                    old_end,
                    new_lines: std::mem::take(&mut new_lines),
                });
            }
            let (start, count) = parse_old_range(rest)?;
            if count < 1 {
                return None;
            }
            old_start = start;
            old_end = start + count - 1;
            in_hunk = true;
            have_open_hunk = true;
        } else if in_hunk {
            match line.chars().next() {
                Some('+') | Some(' ') => new_lines.push(line[1..].to_string()),
                Some('-') | Some('\\') => {}
                _ => in_hunk = false,
            }
        }
    }
    if have_open_hunk {
        hunks.push(SingleHunkFix {
            file: file?,
            old_start,
            old_end,
            new_lines,
        });
    }

    if file_count != 1 || hunks.is_empty() {
        return None;
    }
    Some(hunks)
}

pub fn fully_diff_touched(
    fix: &SingleHunkFix,
    diff_lines: &BTreeMap<String, BTreeSet<i64>>,
) -> bool {
    let Some(touched) = diff_lines.get(&fix.file) else {
        return false;
    };
    (fix.old_start..=fix.old_end).all(|line| touched.contains(&line))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_hunk_modified_file_tracks_context_and_added_lines() {
        let diff = [
            "diff --git a/app.py b/app.py",
            "index 111..222 100644",
            "--- a/app.py",
            "+++ b/app.py",
            "@@ -8,4 +8,5 @@ def handler():",
            " line8",
            " line9",
            "+new_line",
            " line10",
            " line11",
        ]
        .join("\n");
        let touched = parse_diff(&diff);
        assert_eq!(
            touched.get("app.py").cloned().unwrap_or_default(),
            [8, 9, 10, 11, 12].into_iter().collect()
        );
    }

    #[test]
    fn removed_lines_do_not_advance_the_new_line_counter() {
        let diff = [
            "diff --git a/app.py b/app.py",
            "--- a/app.py",
            "+++ b/app.py",
            "@@ -1,3 +1,2 @@",
            " keep1",
            "-removed",
            " keep2",
        ]
        .join("\n");
        let touched = parse_diff(&diff);
        assert_eq!(
            touched.get("app.py").cloned().unwrap_or_default(),
            [1, 2].into_iter().collect()
        );
    }

    #[test]
    fn newly_added_file_tracks_every_added_line_from_one() {
        let diff = [
            "diff --git a/new.py b/new.py",
            "new file mode 100644",
            "--- /dev/null",
            "+++ b/new.py",
            "@@ -0,0 +1,2 @@",
            "+first",
            "+second",
        ]
        .join("\n");
        let touched = parse_diff(&diff);
        assert_eq!(
            touched.get("new.py").cloned().unwrap_or_default(),
            [1, 2].into_iter().collect()
        );
    }

    #[test]
    fn deleted_file_contributes_no_touched_lines() {
        let diff = [
            "diff --git a/gone.py b/gone.py",
            "deleted file mode 100644",
            "--- a/gone.py",
            "+++ /dev/null",
            "@@ -1,2 +0,0 @@",
            "-old1",
            "-old2",
        ]
        .join("\n");
        let touched = parse_diff(&diff);
        assert!(touched.is_empty());
    }

    #[test]
    fn binary_file_between_two_text_diffs_is_skipped_without_corrupting_the_next_file() {
        let diff = [
            "diff --git a/one.py b/one.py",
            "--- a/one.py",
            "+++ b/one.py",
            "@@ -1,1 +1,2 @@",
            " line1",
            "+added",
            "diff --git a/logo.png b/logo.png",
            "index abc..def 100644",
            "Binary files a/logo.png and b/logo.png differ",
            "diff --git a/two.py b/two.py",
            "--- a/two.py",
            "+++ b/two.py",
            "@@ -1,1 +1,1 @@",
            " only_line",
        ]
        .join("\n");
        let touched = parse_diff(&diff);
        assert_eq!(
            touched.get("one.py").cloned().unwrap_or_default(),
            [1, 2].into_iter().collect()
        );
        assert!(!touched.contains_key("logo.png"));
        assert_eq!(
            touched.get("two.py").cloned().unwrap_or_default(),
            [1].into_iter().collect()
        );
    }

    #[test]
    fn no_newline_at_end_of_file_marker_is_ignored() {
        let diff = [
            "diff --git a/a.py b/a.py",
            "--- a/a.py",
            "+++ b/a.py",
            "@@ -1,1 +1,1 @@",
            "+last",
            "\\ No newline at end of file",
        ]
        .join("\n");
        let touched = parse_diff(&diff);
        assert_eq!(
            touched.get("a.py").cloned().unwrap_or_default(),
            [1].into_iter().collect()
        );
    }

    #[test]
    fn renamed_file_uses_the_post_image_path() {
        let diff = [
            "diff --git a/old_name.py b/new_name.py",
            "similarity index 100%",
            "rename from old_name.py",
            "rename to new_name.py",
        ]
        .join("\n");
        let touched = parse_diff(&diff);
        assert!(touched.is_empty());
    }

    #[test]
    fn hunk_header_length_omitted_defaults_to_a_single_line() {
        let diff = [
            "diff --git a/a.py b/a.py",
            "--- a/a.py",
            "+++ b/a.py",
            "@@ -1 +1 @@",
            "+only",
        ]
        .join("\n");
        let touched = parse_diff(&diff);
        assert_eq!(
            touched.get("a.py").cloned().unwrap_or_default(),
            [1].into_iter().collect()
        );
    }

    #[test]
    fn empty_diff_yields_no_touched_files() {
        assert!(parse_diff("").is_empty());
    }

    #[test]
    fn malformed_hunk_header_is_ignored_rather_than_panicking() {
        let diff = [
            "diff --git a/a.py b/a.py",
            "--- a/a.py",
            "+++ b/a.py",
            "@@ garbage @@",
            "+would_be_ignored",
        ]
        .join("\n");
        let touched = parse_diff(&diff);
        assert!(touched.is_empty());
    }

    #[test]
    fn multiple_hunks_in_one_file_both_contribute() {
        let diff = [
            "diff --git a/a.py b/a.py",
            "--- a/a.py",
            "+++ b/a.py",
            "@@ -1,1 +1,1 @@",
            " line1",
            "@@ -50,1 +50,2 @@",
            " line50",
            "+line51",
        ]
        .join("\n");
        let touched = parse_diff(&diff);
        assert_eq!(
            touched.get("a.py").cloned().unwrap_or_default(),
            [1, 50, 51].into_iter().collect()
        );
    }

    #[test]
    fn parse_single_hunk_fix_reads_an_old_side_header_with_the_count_omitted() {
        let diff = [
            "diff --git a/a.py b/a.py",
            "--- a/a.py",
            "+++ b/a.py",
            "@@ -1 +1 @@",
            "+only",
        ]
        .join("\n");
        let fix = parse_single_hunk_fix(&diff).unwrap();
        assert_eq!(fix.old_start, 1);
        assert_eq!(fix.old_end, 1);
    }

    #[test]
    fn parse_single_hunk_fix_reads_a_single_hunk_single_file_modify() {
        let diff = [
            "diff --git a/app.py b/app.py",
            "--- a/app.py",
            "+++ b/app.py",
            "@@ -8,3 +8,4 @@",
            " line8",
            "+new_line",
            " line9",
            " line10",
        ]
        .join("\n");
        let fix = parse_single_hunk_fix(&diff).unwrap();
        assert_eq!(fix.file, "app.py");
        assert_eq!(fix.old_start, 8);
        assert_eq!(fix.old_end, 10);
        assert_eq!(
            fix.new_lines,
            vec![
                "line8".to_string(),
                "new_line".to_string(),
                "line9".to_string(),
                "line10".to_string(),
            ]
        );
    }

    #[test]
    fn parse_single_hunk_fix_excludes_removed_lines_from_new_lines_but_they_still_consume_an_old_line(
    ) {
        let diff = [
            "diff --git a/app.py b/app.py",
            "--- a/app.py",
            "+++ b/app.py",
            "@@ -1,3 +1,2 @@",
            " keep1",
            "-removed",
            " keep2",
        ]
        .join("\n");
        let fix = parse_single_hunk_fix(&diff).unwrap();
        assert_eq!(fix.old_start, 1);
        assert_eq!(fix.old_end, 3);
        assert_eq!(
            fix.new_lines,
            vec!["keep1".to_string(), "keep2".to_string()]
        );
    }

    #[test]
    fn parse_single_hunk_fix_returns_none_for_more_than_one_file() {
        let diff = [
            "diff --git a/one.py b/one.py",
            "--- a/one.py",
            "+++ b/one.py",
            "@@ -1,1 +1,1 @@",
            "+a",
            "diff --git a/two.py b/two.py",
            "--- a/two.py",
            "+++ b/two.py",
            "@@ -1,1 +1,1 @@",
            "+b",
        ]
        .join("\n");
        assert!(parse_single_hunk_fix(&diff).is_none());
    }

    #[test]
    fn parse_single_hunk_fix_returns_none_for_more_than_one_hunk_in_the_same_file() {
        let diff = [
            "diff --git a/app.py b/app.py",
            "--- a/app.py",
            "+++ b/app.py",
            "@@ -1,1 +1,1 @@",
            "+a",
            "@@ -10,1 +10,1 @@",
            "+b",
        ]
        .join("\n");
        assert!(parse_single_hunk_fix(&diff).is_none());
    }

    #[test]
    fn parse_single_hunk_fix_returns_none_for_a_brand_new_file() {
        let diff = [
            "diff --git a/new.py b/new.py",
            "new file mode 100644",
            "--- /dev/null",
            "+++ b/new.py",
            "@@ -0,0 +1,2 @@",
            "+first",
            "+second",
        ]
        .join("\n");
        assert!(parse_single_hunk_fix(&diff).is_none());
    }

    #[test]
    fn parse_single_hunk_fix_returns_none_for_a_deleted_file() {
        let diff = [
            "diff --git a/gone.py b/gone.py",
            "deleted file mode 100644",
            "--- a/gone.py",
            "+++ /dev/null",
            "@@ -1,2 +0,0 @@",
            "-old1",
            "-old2",
        ]
        .join("\n");
        assert!(parse_single_hunk_fix(&diff).is_none());
    }

    #[test]
    fn parse_single_hunk_fix_returns_none_for_an_empty_diff() {
        assert!(parse_single_hunk_fix("").is_none());
    }

    #[test]
    fn parse_single_hunk_fix_returns_none_for_a_malformed_hunk_header() {
        let diff = [
            "diff --git a/a.py b/a.py",
            "--- a/a.py",
            "+++ b/a.py",
            "@@ garbage @@",
            "+would_be_ignored",
        ]
        .join("\n");
        assert!(parse_single_hunk_fix(&diff).is_none());
    }

    #[test]
    fn parse_multi_hunk_fix_collects_each_hunk_in_order() {
        let diff = [
            "diff --git a/app.py b/app.py",
            "--- a/app.py",
            "+++ b/app.py",
            "@@ -1,1 +1,1 @@",
            "+first",
            "@@ -10,2 +10,1 @@",
            " keep",
            "-removed",
        ]
        .join("\n");
        let hunks = parse_multi_hunk_fix(&diff).unwrap();
        assert_eq!(hunks.len(), 2);
        assert_eq!(hunks[0].file, "app.py");
        assert_eq!(hunks[0].old_start, 1);
        assert_eq!(hunks[0].old_end, 1);
        assert_eq!(hunks[0].new_lines, vec!["first".to_string()]);
        assert_eq!(hunks[1].old_start, 10);
        assert_eq!(hunks[1].old_end, 11);
        assert_eq!(hunks[1].new_lines, vec!["keep".to_string()]);
    }

    #[test]
    fn parse_multi_hunk_fix_on_a_single_hunk_diff_returns_one_element() {
        let diff = [
            "diff --git a/app.py b/app.py",
            "--- a/app.py",
            "+++ b/app.py",
            "@@ -8,1 +8,1 @@",
            "+only",
        ]
        .join("\n");
        let hunks = parse_multi_hunk_fix(&diff).unwrap();
        assert_eq!(hunks.len(), 1);
        assert_eq!(hunks[0].old_start, 8);
    }

    #[test]
    fn parse_multi_hunk_fix_returns_none_for_more_than_one_file() {
        let diff = [
            "diff --git a/one.py b/one.py",
            "--- a/one.py",
            "+++ b/one.py",
            "@@ -1,1 +1,1 @@",
            "+a",
            "diff --git a/two.py b/two.py",
            "--- a/two.py",
            "+++ b/two.py",
            "@@ -1,1 +1,1 @@",
            "+b",
        ]
        .join("\n");
        assert!(parse_multi_hunk_fix(&diff).is_none());
    }

    #[test]
    fn parse_multi_hunk_fix_returns_none_for_a_brand_new_file() {
        let diff = [
            "diff --git a/new.py b/new.py",
            "new file mode 100644",
            "--- /dev/null",
            "+++ b/new.py",
            "@@ -0,0 +1,2 @@",
            "+first",
            "+second",
        ]
        .join("\n");
        assert!(parse_multi_hunk_fix(&diff).is_none());
    }

    #[test]
    fn parse_multi_hunk_fix_returns_none_for_a_deleted_file() {
        let diff = [
            "diff --git a/gone.py b/gone.py",
            "deleted file mode 100644",
            "--- a/gone.py",
            "+++ /dev/null",
            "@@ -1,2 +0,0 @@",
            "-old1",
            "-old2",
        ]
        .join("\n");
        assert!(parse_multi_hunk_fix(&diff).is_none());
    }

    #[test]
    fn parse_multi_hunk_fix_returns_none_for_an_empty_diff() {
        assert!(parse_multi_hunk_fix("").is_none());
    }

    #[test]
    fn parse_multi_hunk_fix_returns_none_for_a_malformed_hunk_header() {
        let diff = [
            "diff --git a/a.py b/a.py",
            "--- a/a.py",
            "+++ b/a.py",
            "@@ garbage @@",
            "+would_be_ignored",
        ]
        .join("\n");
        assert!(parse_multi_hunk_fix(&diff).is_none());
    }

    #[test]
    fn fully_diff_touched_is_true_when_every_line_in_range_is_touched() {
        let fix = SingleHunkFix {
            file: "app.py".to_string(),
            old_start: 8,
            old_end: 10,
            new_lines: vec![],
        };
        let mut diff_lines = BTreeMap::new();
        diff_lines.insert("app.py".to_string(), BTreeSet::from([8, 9, 10, 11]));
        assert!(fully_diff_touched(&fix, &diff_lines));
    }

    #[test]
    fn fully_diff_touched_is_false_when_the_file_is_not_in_diff_lines_at_all() {
        let fix = SingleHunkFix {
            file: "app.py".to_string(),
            old_start: 8,
            old_end: 10,
            new_lines: vec![],
        };
        assert!(!fully_diff_touched(&fix, &BTreeMap::new()));
    }

    #[test]
    fn fully_diff_touched_is_false_when_one_line_in_the_range_is_missing() {
        let fix = SingleHunkFix {
            file: "app.py".to_string(),
            old_start: 8,
            old_end: 10,
            new_lines: vec![],
        };
        let mut diff_lines = BTreeMap::new();
        diff_lines.insert("app.py".to_string(), BTreeSet::from([8, 10]));
        assert!(!fully_diff_touched(&fix, &diff_lines));
    }
}
