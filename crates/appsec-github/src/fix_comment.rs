use crate::comment::{marker, Anchor, PlannedComment};
use crate::diff::{self, SingleHunkFix};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixSuggestion {
    pub finding_id: String,
    pub diff: String,
}

pub fn render_fix_comment_body(finding_id: &str, diff: &str) -> String {
    let diff = appsec_redact::redact(diff);
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

pub fn render_suggestion_comment_body(finding_id: &str, hunk: &SingleHunkFix) -> String {
    let content = appsec_redact::redact(&hunk.new_lines.join("\n"));
    format!(
        "**Suggested fix available** for this finding.\n\n\
         ```suggestion\n{}\n```\n\n\
         {}\n",
        content,
        marker(&fix_marker_id(finding_id)),
    )
}

pub fn fix_marker_id(finding_id: &str) -> String {
    format!("{finding_id}:fix")
}

fn hunk_marker_id(finding_id: &str, hunk_count: usize, index: usize) -> String {
    let base = fix_marker_id(finding_id);
    if hunk_count == 1 {
        base
    } else {
        format!("{base}:{index}")
    }
}

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
