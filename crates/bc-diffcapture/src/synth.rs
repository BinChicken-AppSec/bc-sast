//! Synthesized unified diff for non-git targets, ported from
//! `artifacts/diff/synth.py`. [`crate::capture_git_diff`] covers the
//! common case (the scan target is a git repository); this module is the
//! fallback used when that returns `None` — a line-level diff built from
//! the pre-edit [`crate::Snapshot`] against the current on-disk content,
//! via a hand-rolled LCS diff (no new dependency — this project's
//! established supply-chain-minimization stance for a single, narrowly-
//! scoped algorithm, matching the CSV/unified-diff parsers already
//! hand-rolled elsewhere in this workspace).

use std::path::Path;

use crate::{norm_path, Snapshot};

/// Marker placed at the top of a synthesized (non-git) patch so
/// reviewers can tell it is not a true VCS diff.
pub const SYNTH_HEADER: &str = "# (synthesized diff — target is not a git repository)\n";

/// Synthesizes a git-style unified diff for a **non-git** target.
///
/// Compares `before` (the pre-edit snapshot: path -> contents, `None` =
/// the file did not exist) against the current on-disk contents, scoped
/// to the union of the snapshot's own paths and `extra_files` (e.g.
/// files the agent reported editing that weren't snapshotted up front —
/// these have no baseline and render as newly-added). Returns the
/// concatenated unified diff (prefixed with [`SYNTH_HEADER`]), or `None`
/// when nothing changed or nothing in scope resolves inside `root`.
/// Best-effort: an unreadable (e.g. binary) file is skipped, never an
/// error.
pub fn synth_unified_diff(
    root: &Path,
    before: &Snapshot,
    extra_files: &[String],
) -> Option<String> {
    let mut paths: Vec<String> = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for raw in before
        .keys()
        .cloned()
        .chain(extra_files.iter().map(|f| norm_path(f)))
    {
        if !raw.is_empty() && seen.insert(raw.clone()) {
            paths.push(raw);
        }
    }
    if paths.is_empty() {
        return None;
    }

    let mut chunks = Vec::new();
    for rel in &paths {
        let Some(resolved) = bc_pathjail::confine(root, rel) else {
            continue;
        };
        // The snapshot stores raw bytes so a revert can restore a binary
        // file verbatim; a *diff* still needs text, so a baseline that
        // isn't valid UTF-8 is skipped here — exactly what this loop
        // already did for a current-content read that came back binary.
        let old_text = match before.get(rel).cloned().flatten() {
            Some(bytes) => match String::from_utf8(bytes) {
                Ok(text) => text,
                Err(_) => continue,
            },
            None => String::new(),
        };
        let new_text = if resolved.is_file() {
            match std::fs::read_to_string(&resolved) {
                Ok(text) => text,
                Err(_) => continue, // binary/unreadable — skip this file
            }
        } else {
            String::new()
        };
        if old_text == new_text {
            continue;
        }
        // `old_text != new_text` guarantees at least one add/delete diff
        // op below, so `unified_diff_body` always has something to render.
        let existed_before = before.get(rel).map(Option::is_some).unwrap_or(false);
        let body = unified_diff_body(&old_text, &new_text, existed_before, rel);
        chunks.push(format!("diff --git a/{rel} b/{rel}\n{body}"));
    }

    if chunks.is_empty() {
        None
    } else {
        Some(format!("{SYNTH_HEADER}{}", chunks.concat()))
    }
}

/// One line-level diff segment: an unchanged run kept as context, or a
/// run of lines removed from the old text / added in the new text. An
/// `Equal` run carries both sides' start index directly (rather than
/// only the old-side one) since it always advances old/new in lockstep,
/// but the two are not simply offsets of each other once a hunk boundary
/// trims a run's length independently on each end.
enum Op {
    Equal(usize, usize, usize), // (old_start, new_start, len)
    Delete(usize, usize),       // (old_start, len)
    Insert(usize, usize),       // (new_start, len)
}

/// Splits `text` into lines, each keeping its own trailing `\n` (the
/// last line has none if the text itself doesn't end in one) —
/// matching Python's `str.splitlines(keepends=True)`.
fn split_keepends(text: &str) -> Vec<&str> {
    if text.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut start = 0;
    for (i, b) in text.bytes().enumerate() {
        if b == b'\n' {
            out.push(&text[start..=i]);
            start = i + 1;
        }
    }
    if start < text.len() {
        out.push(&text[start..]);
    }
    out
}

/// The full list of equal/delete/insert runs covering `old`/`new`
/// entirely, via a dynamic-programming LCS backtrack.
fn diff_ops(old: &[&str], new: &[&str]) -> Vec<Op> {
    let (n, m) = (old.len(), new.len());
    let mut lcs = vec![vec![0u32; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            lcs[i][j] = if old[i] == new[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }

    #[derive(PartialEq, Clone, Copy)]
    enum Tag {
        Equal,
        Delete,
        Insert,
    }
    let mut tags = Vec::with_capacity(n + m);
    let (mut i, mut j) = (0, 0);
    while i < n && j < m {
        if old[i] == new[j] {
            tags.push((Tag::Equal, i, j));
            i += 1;
            j += 1;
        } else if lcs[i + 1][j] >= lcs[i][j + 1] {
            tags.push((Tag::Delete, i, j));
            i += 1;
        } else {
            tags.push((Tag::Insert, i, j));
            j += 1;
        }
    }
    while i < n {
        tags.push((Tag::Delete, i, j));
        i += 1;
    }
    while j < m {
        tags.push((Tag::Insert, i, j));
        j += 1;
    }

    let mut ops = Vec::new();
    for (tag, oi, ni) in tags {
        match (ops.last_mut(), tag) {
            (Some(Op::Equal(o, n, len)), Tag::Equal) if *o + *len == oi && *n + *len == ni => {
                *len += 1
            }
            (Some(Op::Delete(start, len)), Tag::Delete) if *start + *len == oi => *len += 1,
            (Some(Op::Insert(start, len)), Tag::Insert) if *start + *len == ni => *len += 1,
            _ => ops.push(match tag {
                Tag::Equal => Op::Equal(oi, ni, 1),
                Tag::Delete => Op::Delete(oi, 1),
                Tag::Insert => Op::Insert(ni, 1),
            }),
        }
    }
    ops
}

/// A group of ops rendered as one `@@ ... @@` hunk.
struct Hunk {
    ops: Vec<Op>,
}

/// Groups `ops` into hunks with up to `context` lines of surrounding
/// unchanged context each, merging changes separated by `<= 2*context`
/// unchanged lines into a single hunk — ported from difflib's
/// `SequenceMatcher.get_grouped_opcodes`.
fn group_hunks(mut ops: Vec<Op>, context: usize) -> Vec<Hunk> {
    if ops.is_empty() {
        return Vec::new();
    }
    if let Some(Op::Equal(o, n, len)) = ops.first() {
        let (o, n, len) = (*o, *n, *len);
        let trimmed = len.saturating_sub(context);
        ops[0] = Op::Equal(o + trimmed, n + trimmed, len - trimmed);
    }
    let last = ops.len() - 1;
    if let Some(Op::Equal(o, n, len)) = ops.last() {
        let (o, n, len) = (*o, *n, *len);
        ops[last] = Op::Equal(o, n, len.min(context));
    }

    let mut hunks = Vec::new();
    let mut group: Vec<Op> = Vec::new();
    let threshold = context * 2;
    for op in ops {
        if let Op::Equal(o, n, len) = op {
            if len > threshold {
                group.push(Op::Equal(o, n, context.min(len)));
                hunks.push(Hunk {
                    ops: std::mem::take(&mut group),
                });
                let consumed = len - context.min(len);
                group.push(Op::Equal(o + consumed, n + consumed, len - consumed));
                continue;
            }
        }
        group.push(op);
    }
    if !(group.len() == 1 && matches!(group.first(), Some(Op::Equal(..)))) && !group.is_empty() {
        hunks.push(Hunk { ops: group });
    }
    hunks
}

/// Renders one hunk's `@@ -old_start,old_len +new_start,new_len @@`
/// header plus its `-`/`+`/` `-prefixed body lines.
fn render_hunk(hunk: &Hunk, old: &[&str], new: &[&str]) -> String {
    // `None` until the first op that actually touches that side — a
    // hunk for a brand-new file is entirely `Insert` ops (zero old-side
    // lines at all), so `old_start` must default to 0 rather than ever
    // being compared via `.min()` against an initial sentinel: seeding
    // that sentinel at `usize::MAX` (as this used to) left it completely
    // untouched for such a hunk, rendering literally as `usize::MAX` in
    // the header — confirmed live, a real
    // "@@ -18446744073709551615,0 +1,2 @@" hunk header that no diff
    // tool could apply. Symmetric for `new_start` on a pure-deletion hunk.
    let (mut old_start, mut old_len, mut new_start, mut new_len): (
        Option<usize>,
        usize,
        Option<usize>,
        usize,
    ) = (None, 0, None, 0);
    for op in &hunk.ops {
        match *op {
            Op::Equal(o, n, l) => {
                old_start = Some(old_start.map_or(o, |v: usize| v.min(o)));
                new_start = Some(new_start.map_or(n, |v: usize| v.min(n)));
                old_len += l;
                new_len += l;
            }
            Op::Delete(s, l) => {
                old_start = Some(old_start.map_or(s, |v: usize| v.min(s)));
                old_len += l;
            }
            Op::Insert(s, l) => {
                new_start = Some(new_start.map_or(s, |v: usize| v.min(s)));
                new_len += l;
            }
        }
    }
    let old_start = old_start.unwrap_or(0);
    let new_start = new_start.unwrap_or(0);
    let mut out = format!(
        "@@ -{},{} +{},{} @@\n",
        header_start(old_start, old_len),
        old_len,
        header_start(new_start, new_len),
        new_len
    );
    for op in &hunk.ops {
        match *op {
            Op::Equal(o, _n, l) => {
                for line in &old[o..o + l] {
                    out.push(' ');
                    out.push_str(line);
                }
            }
            Op::Delete(s, l) => {
                for line in &old[s..s + l] {
                    out.push('-');
                    out.push_str(line);
                }
            }
            Op::Insert(s, l) => {
                for line in &new[s..s + l] {
                    out.push('+');
                    out.push_str(line);
                }
            }
        }
    }
    out
}

/// Unified-diff hunk headers use 1-based line numbers, except a
/// zero-length side is conventionally reported as the 0-based position
/// immediately before it (matching `git`/`difflib`).
fn header_start(start: usize, len: usize) -> usize {
    if len == 0 {
        start
    } else {
        start + 1
    }
}

/// Renders the `--- `/`+++ ` file header plus every hunk for a file
/// known to have actually changed (`old_text != new_text` — the only
/// caller, [`synth_unified_diff`], already guarantees this, so `hunks`
/// is never empty here: a real difference always produces at least one
/// add/delete diff op).
fn unified_diff_body(old_text: &str, new_text: &str, existed_before: bool, rel: &str) -> String {
    let old_lines = split_keepends(old_text);
    let new_lines = split_keepends(new_text);
    let ops = diff_ops(&old_lines, &new_lines);
    let hunks = group_hunks(ops, 3);
    let from_label = if existed_before {
        format!("a/{rel}")
    } else {
        "/dev/null".to_string()
    };
    let to_label = if !new_text.is_empty() {
        format!("b/{rel}")
    } else {
        "/dev/null".to_string()
    };
    let mut out = format!("--- {from_label}\n+++ {to_label}\n");
    for hunk in &hunks {
        out.push_str(&render_hunk(hunk, &old_lines, &new_lines));
    }
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_keepends_matches_python_splitlines_keepends() {
        assert_eq!(split_keepends(""), Vec::<&str>::new());
        assert_eq!(split_keepends("a\n"), vec!["a\n"]);
        assert_eq!(split_keepends("a\nb"), vec!["a\n", "b"]);
        assert_eq!(split_keepends("a\nb\n"), vec!["a\n", "b\n"]);
    }

    #[test]
    fn synth_unified_diff_of_no_paths_at_all_is_none() {
        let dir = tempfile::tempdir().unwrap();
        let snap = Snapshot::default();
        assert!(synth_unified_diff(dir.path(), &snap, &[]).is_none());
    }

    #[test]
    fn synth_unified_diff_of_an_unchanged_file_is_none() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "same\n").unwrap();
        let snap = crate::snapshot_files(dir.path(), &["a.py".to_string()]);
        assert!(synth_unified_diff(dir.path(), &snap, &[]).is_none());
    }

    #[test]
    fn synth_unified_diff_shows_a_modified_files_change() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "before\n").unwrap();
        let snap = crate::snapshot_files(dir.path(), &["a.py".to_string()]);
        std::fs::write(dir.path().join("a.py"), "after\n").unwrap();
        let diff = synth_unified_diff(dir.path(), &snap, &[]).unwrap();
        assert!(diff.starts_with(SYNTH_HEADER));
        assert!(diff.contains("diff --git a/a.py b/a.py"));
        assert!(diff.contains("--- a/a.py"));
        assert!(diff.contains("+++ b/a.py"));
        assert!(diff.contains("-before"));
        assert!(diff.contains("+after"));
    }

    #[test]
    fn synth_unified_diff_shows_a_brand_new_file_as_added_against_dev_null() {
        let dir = tempfile::tempdir().unwrap();
        let snap = crate::snapshot_files(dir.path(), &["new.py".to_string()]);
        std::fs::write(dir.path().join("new.py"), "print(1)\n").unwrap();
        let diff = synth_unified_diff(dir.path(), &snap, &[]).unwrap();
        assert!(diff.contains("--- /dev/null"));
        assert!(diff.contains("+++ b/new.py"));
        assert!(diff.contains("+print(1)"));
        // The actual regression: a brand-new file's hunk is entirely
        // `Insert` ops (zero old-side lines), which once left old_start
        // at its `usize::MAX` initial sentinel forever untouched,
        // rendering as a literal "18446744073709551615" here instead of
        // the conventional git-style "0". Asserting marker presence
        // alone (the three lines above) doesn't catch this — this test
        // previously had 100% line coverage of the buggy code and still
        // missed it.
        assert!(diff.contains("@@ -0,0 +1,1 @@"), "hunk header was: {diff}");
    }

    #[test]
    fn synth_unified_diff_shows_a_deleted_files_hunk_header_with_a_zero_new_side() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("gone.py"), "bye\n").unwrap();
        let snap = crate::snapshot_files(dir.path(), &["gone.py".to_string()]);
        std::fs::remove_file(dir.path().join("gone.py")).unwrap();
        let diff = synth_unified_diff(dir.path(), &snap, &[]).unwrap();
        // Symmetric case: a pure-deletion hunk has zero new-side lines,
        // so new_start must default sanely too, not just old_start.
        assert!(diff.contains("@@ -1,1 +0,0 @@"), "hunk header was: {diff}");
    }

    #[test]
    fn synth_unified_diff_shows_a_deleted_file_as_removed_against_dev_null() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("gone.py"), "bye\n").unwrap();
        let snap = crate::snapshot_files(dir.path(), &["gone.py".to_string()]);
        std::fs::remove_file(dir.path().join("gone.py")).unwrap();
        let diff = synth_unified_diff(dir.path(), &snap, &[]).unwrap();
        assert!(diff.contains("--- a/gone.py"));
        assert!(diff.contains("+++ /dev/null"));
        assert!(diff.contains("-bye"));
    }

    #[test]
    fn synth_unified_diff_includes_an_extra_file_not_in_the_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let snap = Snapshot::default();
        std::fs::write(dir.path().join("side.py"), "new content\n").unwrap();
        let diff = synth_unified_diff(dir.path(), &snap, &["side.py".to_string()]).unwrap();
        assert!(diff.contains("diff --git a/side.py b/side.py"));
        assert!(diff.contains("+new content"));
    }

    #[test]
    fn synth_unified_diff_strips_a_line_suffix_from_an_extra_file_reference() {
        let dir = tempfile::tempdir().unwrap();
        let snap = Snapshot::default();
        std::fs::write(dir.path().join("side.py"), "x\n").unwrap();
        let diff = synth_unified_diff(dir.path(), &snap, &["side.py:12".to_string()]).unwrap();
        assert!(diff.contains("diff --git a/side.py b/side.py"));
    }

    #[test]
    fn synth_unified_diff_skips_a_path_escaping_the_root() {
        let dir = tempfile::tempdir().unwrap();
        let snap = Snapshot::default();
        assert!(synth_unified_diff(dir.path(), &snap, &["../outside.py".to_string()]).is_none());
    }

    #[test]
    fn synth_unified_diff_deduplicates_a_path_in_both_snapshot_and_extra_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "before\n").unwrap();
        let snap = crate::snapshot_files(dir.path(), &["a.py".to_string()]);
        std::fs::write(dir.path().join("a.py"), "after\n").unwrap();
        let diff = synth_unified_diff(dir.path(), &snap, &["a.py".to_string()]).unwrap();
        assert_eq!(diff.matches("diff --git").count(), 1);
    }

    #[test]
    fn synth_unified_diff_skips_a_file_whose_current_content_is_binary() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.bin"), "before\n").unwrap();
        let snap = crate::snapshot_files(dir.path(), &["a.bin".to_string()]);
        std::fs::write(dir.path().join("a.bin"), [0xFF, 0xFE, 0x00, 0xC0]).unwrap();
        assert!(synth_unified_diff(dir.path(), &snap, &[]).is_none());
    }

    #[test]
    fn synth_unified_diff_skips_a_file_whose_baseline_is_binary() {
        // The snapshot now stores raw bytes (so a revert can restore a
        // binary file exactly), which means a baseline that isn't valid
        // UTF-8 reaches this diff for the first time. It has to be
        // skipped, not lossily converted — and skipping it must not
        // suppress the diff of every OTHER file in scope.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.bin"), [0xFF, 0xFE, 0x00, 0xC0]).unwrap();
        std::fs::write(dir.path().join("b.py"), "before\n").unwrap();
        let snap = crate::snapshot_files(dir.path(), &["a.bin".to_string(), "b.py".to_string()]);
        std::fs::write(dir.path().join("a.bin"), "now it is text\n").unwrap();
        std::fs::write(dir.path().join("b.py"), "after\n").unwrap();

        let diff = synth_unified_diff(dir.path(), &snap, &[]).unwrap();

        assert!(!diff.contains("a.bin"), "binary baseline leaked in: {diff}");
        assert!(diff.contains("+after"));
    }

    #[test]
    fn synth_unified_diff_adds_context_lines_around_a_small_change() {
        let dir = tempfile::tempdir().unwrap();
        let before_text = "1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n";
        std::fs::write(dir.path().join("f.py"), before_text).unwrap();
        let snap = crate::snapshot_files(dir.path(), &["f.py".to_string()]);
        let after_text = "1\n2\n3\n4\nCHANGED\n6\n7\n8\n9\n10\n";
        std::fs::write(dir.path().join("f.py"), after_text).unwrap();
        let diff = synth_unified_diff(dir.path(), &snap, &[]).unwrap();
        assert!(diff.contains("-5"));
        assert!(diff.contains("+CHANGED"));
        // 3 lines of context on each side of the single-line change.
        assert!(diff.contains(" 2\n"));
        assert!(diff.contains(" 4\n"));
        assert!(diff.contains(" 6\n"));
        assert!(diff.contains(" 8\n"));
        assert!(!diff.contains(" 1\n"));
        assert!(!diff.contains(" 9\n"));
    }

    #[test]
    fn synth_unified_diff_merges_two_close_changes_into_one_hunk() {
        let dir = tempfile::tempdir().unwrap();
        let before_text = (1..=20)
            .map(|n| format!("{n}\n"))
            .collect::<Vec<_>>()
            .concat();
        std::fs::write(dir.path().join("f.py"), &before_text).unwrap();
        let snap = crate::snapshot_files(dir.path(), &["f.py".to_string()]);
        let mut lines: Vec<String> = (1..=20).map(|n| n.to_string()).collect();
        lines[2] = "CHANGED_A".to_string(); // line 3
        lines[7] = "CHANGED_B".to_string(); // line 8, 4 lines away — merges
        let after_text: String = lines.iter().map(|l| format!("{l}\n")).collect();
        std::fs::write(dir.path().join("f.py"), &after_text).unwrap();
        let diff = synth_unified_diff(dir.path(), &snap, &[]).unwrap();
        assert_eq!(diff.matches("@@").count(), 2); // one hunk == 2 "@@" markers
    }

    #[test]
    fn synth_unified_diff_splits_two_far_apart_changes_into_separate_hunks() {
        let dir = tempfile::tempdir().unwrap();
        let before_text = (1..=40)
            .map(|n| format!("{n}\n"))
            .collect::<Vec<_>>()
            .concat();
        std::fs::write(dir.path().join("f.py"), &before_text).unwrap();
        let snap = crate::snapshot_files(dir.path(), &["f.py".to_string()]);
        let mut lines: Vec<String> = (1..=40).map(|n| n.to_string()).collect();
        lines[2] = "CHANGED_A".to_string(); // line 3
        lines[35] = "CHANGED_B".to_string(); // line 36 — far away, separate hunk
        let after_text: String = lines.iter().map(|l| format!("{l}\n")).collect();
        std::fs::write(dir.path().join("f.py"), &after_text).unwrap();
        let diff = synth_unified_diff(dir.path(), &snap, &[]).unwrap();
        assert_eq!(diff.matches("@@ -").count(), 2);
    }

    #[test]
    fn synth_unified_diff_handles_a_file_missing_a_trailing_newline() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("f.py"), "one\ntwo").unwrap();
        let snap = crate::snapshot_files(dir.path(), &["f.py".to_string()]);
        std::fs::write(dir.path().join("f.py"), "one\nTWO").unwrap();
        let diff = synth_unified_diff(dir.path(), &snap, &[]).unwrap();
        assert!(diff.contains("-two"));
        assert!(diff.contains("+TWO"));
    }

    #[test]
    fn synth_unified_diff_shows_a_consecutive_multi_line_replacement() {
        // Two adjacent changed lines exercise the "extend the current
        // Delete/Insert run" path in `diff_ops`, not just single-line
        // isolated Delete+Insert pairs.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("f.py"), "a\nb\nc\nd\ne\n").unwrap();
        let snap = crate::snapshot_files(dir.path(), &["f.py".to_string()]);
        std::fs::write(dir.path().join("f.py"), "a\nB2\nC2\nd\ne\n").unwrap();
        let diff = synth_unified_diff(dir.path(), &snap, &[]).unwrap();
        assert!(diff.contains("-b\n-c\n"));
        assert!(diff.contains("+B2\n+C2\n"));
    }

    #[test]
    fn group_hunks_of_no_ops_at_all_is_empty() {
        assert!(group_hunks(Vec::new(), 3).is_empty());
    }
}
