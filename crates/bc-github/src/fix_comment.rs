//! A second, independent comment kind — "here's a suggested fix" — for a
//! finding that's already been remediated by S10. Deliberately reuses
//! [`crate::comment::marker`]/[`crate::comment::extract_marker`] and
//! [`crate::reconcile::reconcile`] completely unchanged: a fix-suggestion
//! comment for finding `<id>` is keyed by the marker id `<id>:fix`, not
//! `<id>` — the suffix is enough to keep it from colliding with that same
//! finding's own description comment (keyed by plain `<id>`) in
//! `reconcile`'s exact-match lookup, without teaching that matching logic
//! (or the marker grammar itself) about a second comment kind at all.
//!
//! A fix whose every hunk lands entirely on lines the PR's own diff
//! already touches (see [`crate::diff::parse_multi_hunk_fix`]/
//! [`crate::diff::fully_diff_touched`]) gets one native, anchored
//! `\`\`\`suggestion` review comment PER HUNK — GitHub renders a
//! one-click "Commit suggestion" button on each. A single-hunk fix is
//! just the `hunk_count == 1` case of this, keyed by the same plain
//! `<id>:fix` marker it always has been; a genuinely multi-hunk fix gets
//! `<id>:fix:0`, `<id>:fix:1`, ... so `reconcile` can track/update each
//! hunk's comment independently across re-scans. Everything else
//! (multi-file, a brand-new/deleted file, or ANY hunk landing even
//! partly off the PR's diff) falls back to a single unanchored
//! conversation comment for the WHOLE fix, showing the diff as a
//! `\`\`\`diff` block instead — deliberately all-or-nothing at the fix
//! level, not a partial mix of suggestion + fallback comments for the
//! same fix, to keep the reconcile/marker story simple. The
//! `/apply-fix <finding-id>` instruction is carried by the FALLBACK
//! comment only: it is the only way to apply a fix that has no native
//! button, whereas repeating it under a `\`\`\`suggestion` block would
//! ask the reader to retype a forty-character hex id to do what the
//! button immediately above it already does in one click. Either
//! comment kind still carries the hidden marker, which is the identity
//! `apply-fix.yml` and re-scan reconciliation both key off, so
//! `/apply-fix <id>` keeps working on a suggestion comment for anyone
//! who types it.

use crate::comment::{marker, Anchor, PlannedComment};
use crate::diff::{self, SingleHunkFix};
use std::collections::{BTreeMap, BTreeSet};

/// One finding's already-generated fix, as handed to this crate by the
/// caller (`bc-cli`, reading a `RemediationExport` written by
/// `--out-remediation-json`) — deliberately its own small type rather
/// than a dependency on `bc-stage-s10`'s own `RemediationRecord`,
/// mirroring how [`crate::plan_comments`] takes `&[bc_model::Finding]`
/// from a shared, lower-tier crate rather than a higher-tier one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixSuggestion {
    pub finding_id: String,
    pub diff: String,
}

/// Renders the FALLBACK fix-suggestion comment body: the (redacted) diff
/// as a `\`\`\`diff` block, the `/apply-fix` instruction, and the hidden
/// marker `apply-fix.yml` and re-scans both key off.
///
/// This is the body that carries the instruction, and the only one that
/// does. An unanchored conversation comment gets no "Commit suggestion"
/// button from GitHub, so `/apply-fix <id>` is the sole way to apply
/// what it shows.
pub fn render_fix_comment_body(finding_id: &str, diff: &str) -> String {
    let diff = bc_redact::redact(diff);
    format!(
        "**Suggested fix available** for this finding.\n\n\
         ```diff\n{}\n```\n\n\
         To apply this fix to the PR branch, comment `/apply-fix {finding_id}` \
         (requires write access to this repository).\n\n\
         {}\n",
        diff.trim_end(),
        marker(&fix_marker_id(finding_id)),
    )
}

/// Renders a NATIVE, anchored fix-suggestion comment body: the (redacted)
/// replacement content as a `\`\`\`suggestion` block, plus the same
/// hidden marker [`render_fix_comment_body`] uses. GitHub renders a
/// one-click "Commit suggestion" button on a review comment shaped like
/// this.
///
/// Deliberately WITHOUT the `/apply-fix` instruction that body carries.
/// The button GitHub puts directly above this line already applies the
/// fix, so the sentence is pure noise here, and the alternative it
/// offers is worse: retyping a forty-character hex id. The marker is
/// unchanged, so `apply-fix.yml` still recognizes the comment and
/// `/apply-fix <id>` still works for anyone who types it.
pub fn render_suggestion_comment_body(finding_id: &str, hunk: &SingleHunkFix) -> String {
    let content = bc_redact::redact(&hunk.new_lines.join("\n"));
    format!(
        "**Suggested fix available** for this finding.\n\n\
         ```suggestion\n{}\n```\n\n\
         {}\n",
        content,
        marker(&fix_marker_id(finding_id)),
    )
}

/// The marker id a fix-suggestion comment for `finding_id` is keyed by —
/// distinct from that same finding's own description-comment marker id
/// (plain `finding_id`), so the two never collide in `reconcile`'s
/// exact-match lookup.
pub fn fix_marker_id(finding_id: &str) -> String {
    format!("{finding_id}:fix")
}

/// Marker id for hunk `index` (0-based) of an `hunk_count`-hunk fix —
/// plain [`fix_marker_id`] when `hunk_count == 1`, preserving the
/// existing single-hunk marker shape exactly so a fix that stays
/// single-hunk across re-scans keeps updating the same comment rather
/// than orphaning it; an indexed `<id>:fix:<index>` suffix when
/// `hunk_count > 1`.
fn hunk_marker_id(finding_id: &str, hunk_count: usize, index: usize) -> String {
    let base = fix_marker_id(finding_id);
    if hunk_count == 1 {
        base
    } else {
        format!("{base}:{index}")
    }
}

/// Plans comments for one fix: one native, anchored `\`\`\`suggestion`
/// review comment per hunk when every hunk is covered by `diff_lines`
/// (the PR's own diff-touched lines — see [`crate::sync_fixes`]);
/// otherwise a single unanchored conversation comment for the whole fix,
/// showing the diff as a `\`\`\`diff` block.
fn plan_one_fix(
    f: &FixSuggestion,
    diff_lines: &BTreeMap<String, BTreeSet<i64>>,
) -> Vec<PlannedComment> {
    let hunks = diff::parse_multi_hunk_fix(&f.diff).filter(|hunks| {
        hunks
            .iter()
            .all(|h| diff::fully_diff_touched(h, diff_lines))
    });

    match hunks {
        Some(hunks) => {
            let hunk_count = hunks.len();
            hunks
                .into_iter()
                .enumerate()
                .map(|(index, hunk)| PlannedComment {
                    finding_id: hunk_marker_id(&f.finding_id, hunk_count, index),
                    legacy_ids: Vec::new(),
                    locator: None,
                    body: render_suggestion_comment_body(&f.finding_id, &hunk),
                    anchor: Some(Anchor {
                        file: hunk.file,
                        start_line: hunk.old_start,
                        end_line: hunk.old_end,
                    }),
                })
                .collect()
        }
        None => vec![PlannedComment {
            finding_id: fix_marker_id(&f.finding_id),
            legacy_ids: Vec::new(),
            locator: None,
            body: render_fix_comment_body(&f.finding_id, &f.diff),
            anchor: None,
        }],
    }
}

/// Plans comments for every fix — see [`plan_one_fix`] for the per-fix
/// suggestion-vs-fallback decision. A single fix can now produce more
/// than one comment (one per hunk), so this is a `flat_map`, not a
/// 1:1 `map`.
pub fn plan_fix_comments(
    fixes: &[FixSuggestion],
    diff_lines: &BTreeMap<String, BTreeSet<i64>>,
) -> Vec<PlannedComment> {
    fixes
        .iter()
        .flat_map(|f| plan_one_fix(f, diff_lines))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::comment::extract_marker;

    #[test]
    fn fix_marker_id_suffixes_the_finding_id() {
        assert_eq!(fix_marker_id("abc123"), "abc123:fix");
    }

    #[test]
    fn render_fix_comment_body_includes_the_diff_instruction_and_marker() {
        let body = render_fix_comment_body("abc123", "diff --git a/x b/x\n+fixed");
        assert!(body.contains("```diff\ndiff --git a/x b/x\n+fixed\n```"));
        assert!(body.contains("/apply-fix abc123"));
        assert_eq!(extract_marker(&body), Some("abc123:fix".to_string()));
    }

    #[test]
    fn render_fix_comment_body_redacts_secrets_in_the_diff() {
        let body = render_fix_comment_body(
            "abc123",
            "diff --git a/x b/x\n+key = \"AKIAAAAAAAAAAAAAAAAA\"",
        );
        assert!(!body.contains("AKIAAAAAAAAAAAAAAAAA"));
    }

    #[test]
    fn render_suggestion_comment_body_includes_the_suggestion_block_and_marker() {
        let hunk = SingleHunkFix {
            file: "app.py".to_string(),
            old_start: 8,
            old_end: 9,
            new_lines: vec!["fixed_line".to_string()],
        };
        let body = render_suggestion_comment_body("abc123", &hunk);
        assert!(body.contains("```suggestion\nfixed_line\n```"));
        assert_eq!(extract_marker(&body), Some("abc123:fix".to_string()));
    }

    /// The one difference between the two bodies: GitHub's own "Commit
    /// suggestion" button sits directly above the suggestion body, so
    /// repeating the command there is noise; the fallback body has no
    /// button, so the command is the only way to apply what it shows.
    /// Both keep the marker regardless: it is the reconcile/`apply-fix.
    /// yml` identity, not a human-visible instruction.
    #[test]
    fn only_the_fallback_body_carries_the_apply_fix_instruction() {
        let hunk = SingleHunkFix {
            file: "app.py".to_string(),
            old_start: 8,
            old_end: 9,
            new_lines: vec!["fixed_line".to_string()],
        };
        let suggestion = render_suggestion_comment_body("abc123", &hunk);
        let fallback = render_fix_comment_body("abc123", "diff --git a/x b/x\n+fixed");

        assert!(!suggestion.contains("/apply-fix"), "{suggestion}");
        assert!(fallback.contains("/apply-fix abc123"), "{fallback}");
        assert_eq!(extract_marker(&suggestion), Some("abc123:fix".to_string()));
        assert_eq!(extract_marker(&fallback), Some("abc123:fix".to_string()));
    }

    #[test]
    fn render_suggestion_comment_body_redacts_secrets_in_the_replacement_content() {
        let hunk = SingleHunkFix {
            file: "app.py".to_string(),
            old_start: 1,
            old_end: 1,
            new_lines: vec!["key = \"AKIAAAAAAAAAAAAAAAAA\"".to_string()],
        };
        let body = render_suggestion_comment_body("abc123", &hunk);
        assert!(!body.contains("AKIAAAAAAAAAAAAAAAAA"));
    }

    fn single_hunk_diff(file: &str, old_start: i64, old_count: i64, new_line: &str) -> String {
        format!(
            "diff --git a/{file} b/{file}\n--- a/{file}\n+++ b/{file}\n@@ -{old_start},{old_count} +{old_start},{old_count} @@\n+{new_line}\n"
        )
    }

    #[test]
    fn plan_fix_comments_falls_back_to_an_unanchored_comment_when_the_diff_is_not_a_single_hunk() {
        let fixes = vec![FixSuggestion {
            finding_id: "f1".to_string(),
            diff: "diff --git a/a b/a\n".to_string(),
        }];
        let planned = plan_fix_comments(&fixes, &BTreeMap::new());
        assert_eq!(planned.len(), 1);
        assert_eq!(planned[0].finding_id, "f1:fix");
        assert!(planned[0].anchor.is_none());
        assert!(planned[0].body.contains("diff --git a/a b/a"));
    }

    #[test]
    fn plan_fix_comments_falls_back_when_a_single_hunk_fix_lands_off_the_prs_own_diff() {
        let fixes = vec![FixSuggestion {
            finding_id: "f1".to_string(),
            diff: single_hunk_diff("app.py", 8, 1, "fixed"),
        }];
        // Empty `diff_lines` — the PR's own diff never touched app.py at
        // all, so even a well-formed single hunk can't be anchored.
        let planned = plan_fix_comments(&fixes, &BTreeMap::new());
        assert!(planned[0].anchor.is_none());
        assert!(planned[0].body.contains("```diff"));
    }

    #[test]
    fn plan_fix_comments_anchors_a_single_hunk_fix_fully_covered_by_the_prs_own_diff() {
        let fixes = vec![FixSuggestion {
            finding_id: "f1".to_string(),
            diff: single_hunk_diff("app.py", 8, 1, "fixed"),
        }];
        let mut diff_lines = BTreeMap::new();
        diff_lines.insert("app.py".to_string(), BTreeSet::from([8]));
        let planned = plan_fix_comments(&fixes, &diff_lines);
        assert_eq!(
            planned[0].anchor,
            Some(Anchor {
                file: "app.py".to_string(),
                start_line: 8,
                end_line: 8,
            })
        );
        assert!(planned[0].body.contains("```suggestion\nfixed\n```"));
        assert_eq!(extract_marker(&planned[0].body), Some("f1:fix".to_string()));
    }

    #[test]
    fn plan_fix_comments_of_an_empty_list_is_empty() {
        assert!(plan_fix_comments(&[], &BTreeMap::new()).is_empty());
    }

    fn multi_hunk_diff(file: &str) -> String {
        format!(
            "diff --git a/{file} b/{file}\n--- a/{file}\n+++ b/{file}\n\
             @@ -8,1 +8,1 @@\n+first_fix\n\
             @@ -20,1 +20,1 @@\n+second_fix\n"
        )
    }

    #[test]
    fn plan_fix_comments_emits_one_suggestion_per_hunk_when_every_hunk_is_diff_touched() {
        let fixes = vec![FixSuggestion {
            finding_id: "f1".to_string(),
            diff: multi_hunk_diff("app.py"),
        }];
        let mut diff_lines = BTreeMap::new();
        diff_lines.insert("app.py".to_string(), BTreeSet::from([8, 20]));

        let planned = plan_fix_comments(&fixes, &diff_lines);

        assert_eq!(planned.len(), 2);
        assert_eq!(planned[0].finding_id, "f1:fix:0");
        assert_eq!(
            planned[0].anchor,
            Some(Anchor {
                file: "app.py".to_string(),
                start_line: 8,
                end_line: 8,
            })
        );
        assert!(planned[0].body.contains("```suggestion\nfirst_fix\n```"));
        assert_eq!(planned[1].finding_id, "f1:fix:1");
        assert_eq!(
            planned[1].anchor,
            Some(Anchor {
                file: "app.py".to_string(),
                start_line: 20,
                end_line: 20,
            })
        );
        assert!(planned[1].body.contains("```suggestion\nsecond_fix\n```"));
    }

    #[test]
    fn plan_fix_comments_falls_back_to_one_whole_fix_comment_when_only_one_hunk_is_off_diff() {
        let fixes = vec![FixSuggestion {
            finding_id: "f1".to_string(),
            diff: multi_hunk_diff("app.py"),
        }];
        // Only line 8 is in the PR's diff — line 20's hunk isn't, so the
        // whole fix falls back rather than posting a partial mix of one
        // suggestion comment and one fallback comment.
        let mut diff_lines = BTreeMap::new();
        diff_lines.insert("app.py".to_string(), BTreeSet::from([8]));

        let planned = plan_fix_comments(&fixes, &diff_lines);

        assert_eq!(planned.len(), 1);
        assert_eq!(planned[0].finding_id, "f1:fix");
        assert!(planned[0].anchor.is_none());
        assert!(planned[0].body.contains("```diff"));
    }

    #[test]
    fn hunk_marker_id_uses_the_plain_marker_for_a_single_hunk() {
        assert_eq!(hunk_marker_id("f1", 1, 0), "f1:fix");
    }

    #[test]
    fn hunk_marker_id_suffixes_the_index_for_multiple_hunks() {
        assert_eq!(hunk_marker_id("f1", 3, 0), "f1:fix:0");
        assert_eq!(hunk_marker_id("f1", 3, 2), "f1:fix:2");
    }
}
