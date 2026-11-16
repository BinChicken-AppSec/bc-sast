use crate::comment::{Locator, PlannedComment, LOC_LINE_TOLERANCE};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExistingKind {
    Review,
    Issue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExistingComment {
    pub id: u64,
    pub finding_id: String,
    pub kind: ExistingKind,
    pub locator: Option<Locator>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconcileAction {
    CreateReview {
        file: String,
        start_line: i64,
        end_line: i64,
        body: String,
    },
    UpdateReview {
        comment_id: u64,
        body: String,
    },
    CreateIssue {
        body: String,
    },
    UpdateIssue {
        comment_id: u64,
        body: String,
    },
}

pub fn reconcile(planned: &[PlannedComment], existing: &[ExistingComment]) -> Vec<ReconcileAction> {
    planned
        .iter()
        .map(|p| {
            match existing
                .iter()
                .find(|e| e.finding_id == p.finding_id)
                .or_else(|| {
                    existing
                        .iter()
                        .find(|e| p.legacy_ids.contains(&e.finding_id))
                })
                .or_else(|| {
                    let want = p.locator.as_ref()?;
                    existing.iter().find(|e| {
                        e.locator
                            .as_ref()
                            .is_some_and(|have| want.plausibly_same(have, LOC_LINE_TOLERANCE))
                    })
                }) {
                Some(e) => match e.kind {
                    ExistingKind::Review => ReconcileAction::UpdateReview {
                        comment_id: e.id,
                        body: p.body.clone(),
                    },
                    ExistingKind::Issue => ReconcileAction::UpdateIssue {
                        comment_id: e.id,
                        body: p.body.clone(),
                    },
                },
                None => match &p.anchor {
                    Some(anchor) => ReconcileAction::CreateReview {
                        file: anchor.file.clone(),
                        start_line: anchor.start_line,
                        end_line: anchor.end_line,
                        body: p.body.clone(),
                    },
                    None => ReconcileAction::CreateIssue {
                        body: p.body.clone(),
                    },
                },
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn planned(finding_id: &str, anchor: Option<(&str, i64, i64)>) -> PlannedComment {
        planned_with_legacy(finding_id, Vec::new(), anchor)
    }

    pub(super) fn planned_with_legacy(
        finding_id: &str,
        legacy_ids: Vec<String>,
        anchor: Option<(&str, i64, i64)>,
    ) -> PlannedComment {
        PlannedComment {
            finding_id: finding_id.to_string(),
            legacy_ids,
            locator: None,
            body: format!("body for {finding_id}"),
            anchor: anchor.map(|(file, start_line, end_line)| crate::comment::Anchor {
                file: file.to_string(),
                start_line,
                end_line,
            }),
        }
    }

    #[test]
    fn no_existing_match_and_anchored_creates_a_review_comment() {
        let planned = vec![planned("f1", Some(("a.py", 10, 10)))];
        let actions = reconcile(&planned, &[]);
        assert_eq!(
            actions[0],
            ReconcileAction::CreateReview {
                file: "a.py".to_string(),
                start_line: 10,
                end_line: 10,
                body: "body for f1".to_string(),
            }
        );
    }

    #[test]
    fn no_existing_match_and_multi_line_anchored_creates_a_review_comment_with_both_bounds() {
        let planned = vec![planned("f1", Some(("a.py", 8, 10)))];
        let actions = reconcile(&planned, &[]);
        assert_eq!(
            actions[0],
            ReconcileAction::CreateReview {
                file: "a.py".to_string(),
                start_line: 8,
                end_line: 10,
                body: "body for f1".to_string(),
            }
        );
    }

    #[test]
    fn no_existing_match_and_unanchored_creates_an_issue_comment() {
        let planned = vec![planned("f1", None)];
        let actions = reconcile(&planned, &[]);
        assert_eq!(
            actions[0],
            ReconcileAction::CreateIssue {
                body: "body for f1".to_string(),
            }
        );
    }

    #[test]
    fn existing_review_comment_is_updated_in_place() {
        let planned = vec![planned("f1", None)];
        let existing = vec![ExistingComment {
            id: 99,
            finding_id: "f1".to_string(),
            kind: ExistingKind::Review,
            locator: None,
        }];
        let actions = reconcile(&planned, &existing);
        assert_eq!(
            actions[0],
            ReconcileAction::UpdateReview {
                comment_id: 99,
                body: "body for f1".to_string(),
            }
        );
    }

    #[test]
    fn existing_issue_comment_is_updated_in_place() {
        let planned = vec![planned("f1", Some(("a.py", 10, 10)))];
        let existing = vec![ExistingComment {
            id: 7,
            finding_id: "f1".to_string(),
            kind: ExistingKind::Issue,
            locator: None,
        }];
        let actions = reconcile(&planned, &existing);
        assert_eq!(
            actions[0],
            ReconcileAction::UpdateIssue {
                comment_id: 7,
                body: "body for f1".to_string(),
            }
        );
    }

    #[test]
    fn unrelated_existing_comments_do_not_affect_a_different_finding() {
        let planned = vec![planned("f2", None)];
        let existing = vec![ExistingComment {
            id: 1,
            finding_id: "f1".to_string(),
            kind: ExistingKind::Review,
            locator: None,
        }];
        let actions = reconcile(&planned, &existing);
        assert_eq!(
            actions[0],
            ReconcileAction::CreateIssue {
                body: "body for f2".to_string(),
            }
        );
    }
}

#[cfg(test)]
mod legacy_id_tests {
    use super::*;

    #[test]
    fn a_comment_posted_under_a_superseded_id_is_updated_not_duplicated() {
        let p = tests::planned_with_legacy("v2-id", vec!["v1-id".to_string()], None);
        let existing = vec![ExistingComment {
            id: 99,
            finding_id: "v1-id".to_string(),
            kind: ExistingKind::Issue,
            locator: None,
        }];
        assert_eq!(
            reconcile(&[p], &existing),
            vec![ReconcileAction::UpdateIssue {
                comment_id: 99,
                body: "body for v2-id".to_string(),
            }],
            "must update in place, carrying the current body/marker"
        );
    }

    #[test]
    fn the_current_id_is_preferred_over_a_legacy_one() {
        let p = tests::planned_with_legacy("v2-id", vec!["v1-id".to_string()], None);
        let existing = vec![
            ExistingComment {
                id: 1,
                finding_id: "v1-id".to_string(),
                kind: ExistingKind::Issue,
                locator: None,
            },
            ExistingComment {
                id: 2,
                finding_id: "v2-id".to_string(),
                kind: ExistingKind::Issue,
                locator: None,
            },
        ];
        assert_eq!(
            reconcile(&[p], &existing),
            vec![ReconcileAction::UpdateIssue {
                comment_id: 2,
                body: "body for v2-id".to_string(),
            }]
        );
    }

    #[test]
    fn an_unrelated_existing_comment_is_never_matched() {
        let p = tests::planned_with_legacy("v2-id", vec!["v1-id".to_string()], None);
        let existing = vec![ExistingComment {
            id: 5,
            finding_id: "someone-elses-id".to_string(),
            kind: ExistingKind::Issue,
            locator: None,
        }];
        assert_eq!(
            reconcile(&[p], &existing),
            vec![ReconcileAction::CreateIssue {
                body: "body for v2-id".to_string(),
            }]
        );
    }
}

#[cfg(test)]
mod locator_tests {
    use super::*;

    fn loc(file: &str, start: i64, end: i64, class: &str) -> Locator {
        Locator {
            file: file.to_string(),
            line_start: start,
            line_end: end,
            vuln_class: class.to_string(),
        }
    }

    fn planned_at(finding_id: &str, l: Locator) -> PlannedComment {
        PlannedComment {
            finding_id: finding_id.to_string(),
            legacy_ids: Vec::new(),
            locator: Some(l),
            body: format!("body for {finding_id}"),
            anchor: None,
        }
    }

    fn existing_at(id: u64, finding_id: &str, l: Option<Locator>) -> ExistingComment {
        ExistingComment {
            id,
            finding_id: finding_id.to_string(),
            kind: ExistingKind::Issue,
            locator: l,
        }
    }

    #[test]
    fn a_redrawn_line_range_matches_the_existing_comment() {
        let p = planned_at("id-run4", loc("app.py", 25, 29, "other"));
        let existing = vec![existing_at(
            11,
            "id-run3",
            Some(loc("app.py", 28, 29, "other")),
        )];
        assert_eq!(
            reconcile(&[p], &existing),
            vec![ReconcileAction::UpdateIssue {
                comment_id: 11,
                body: "body for id-run4".to_string(),
            }]
        );
    }

    #[test]
    fn a_different_class_on_the_same_lines_is_a_separate_finding() {
        let p = planned_at("id-a", loc("wf.yml", 77, 77, "injection"));
        let existing = vec![existing_at(1, "id-b", Some(loc("wf.yml", 77, 77, "other")))];
        assert!(matches!(
            reconcile(&[p], &existing).as_slice(),
            [ReconcileAction::CreateIssue { .. }]
        ));
    }

    #[test]
    fn a_different_file_never_matches_on_position() {
        let p = planned_at("id-a", loc("a.py", 10, 12, "injection"));
        let existing = vec![existing_at(
            1,
            "id-b",
            Some(loc("b.py", 10, 12, "injection")),
        )];
        assert!(matches!(
            reconcile(&[p], &existing).as_slice(),
            [ReconcileAction::CreateIssue { .. }]
        ));
    }

    #[test]
    fn a_distant_non_overlapping_range_is_not_merged() {
        let p = planned_at("id-a", loc("a.py", 100, 101, "injection"));
        let existing = vec![existing_at(
            1,
            "id-b",
            Some(loc("a.py", 10, 12, "injection")),
        )];
        assert!(matches!(
            reconcile(&[p], &existing).as_slice(),
            [ReconcileAction::CreateIssue { .. }]
        ));
    }

    #[test]
    fn an_exact_id_match_wins_over_a_position_match() {
        let p = planned_at("id-exact", loc("a.py", 10, 12, "injection"));
        let existing = vec![
            existing_at(1, "someone-else", Some(loc("a.py", 10, 12, "injection"))),
            existing_at(2, "id-exact", None),
        ];
        assert_eq!(
            reconcile(&[p], &existing),
            vec![ReconcileAction::UpdateIssue {
                comment_id: 2,
                body: "body for id-exact".to_string(),
            }]
        );
    }

    #[test]
    fn a_comment_without_a_locator_is_simply_unmatchable_by_position() {
        let p = planned_at("id-a", loc("a.py", 10, 12, "injection"));
        let existing = vec![existing_at(1, "id-b", None)];
        assert!(matches!(
            reconcile(&[p], &existing).as_slice(),
            [ReconcileAction::CreateIssue { .. }]
        ));
    }

    #[test]
    fn a_planned_comment_without_a_locator_falls_through_to_create() {
        let mut p = planned_at("id-a", loc("a.py", 10, 12, "injection"));
        p.locator = None;
        let existing = vec![existing_at(
            1,
            "id-b",
            Some(loc("a.py", 10, 12, "injection")),
        )];
        assert!(matches!(
            reconcile(&[p], &existing).as_slice(),
            [ReconcileAction::CreateIssue { .. }]
        ));
    }

    #[test]
    fn tolerance_covers_a_small_shift_without_overlap() {
        let p = planned_at("id-a", loc("a.py", 13, 13, "injection"));
        let existing = vec![existing_at(
            1,
            "id-b",
            Some(loc("a.py", 10, 10, "injection")),
        )];
        assert!(matches!(
            reconcile(&[p], &existing).as_slice(),
            [ReconcileAction::UpdateIssue { .. }]
        ));
    }
}
