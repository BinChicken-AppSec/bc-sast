//! Renders a `Finding` into a PR comment body and decides whether it lands
//! as an inline review comment (diff-touched line) or falls back to a
//! plain conversation comment — pure logic, no network I/O.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use bc_model::Finding;

pub const MARKER_PREFIX: &str = "<!-- bc:finding-id=";
pub const MARKER_SUFFIX: &str = " -->";

/// A second, independent hidden marker recording WHERE a comment's
/// finding was, so a later run can recognise the same vulnerability by
/// position when its content hash has moved. See [`Locator`].
pub const LOC_MARKER_PREFIX: &str = "<!-- bc:loc=";

pub fn marker(finding_id: &str) -> String {
    format!("{MARKER_PREFIX}{finding_id}{MARKER_SUFFIX}")
}

/// Where a finding was, as recorded in a posted comment: enough to
/// recognise the same vulnerability across runs that report it at
/// slightly different bounds.
///
/// Content-derived identity ([`bc_sarif::finding_id_v2`]) removed the
/// variance that came from the model quoting different amounts of code,
/// but not the variance in the RANGE it reports. Runs on 2026-09-05
/// described one path traversal as `app.py:28-29` and then `app.py:25-29`
/// — the same lines of the same unchanged file, hashing differently
/// because the second run drew a wider box around them, so the reviewer
/// got a second comment for it. Position is what survives that.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Locator {
    pub file: String,
    pub line_start: i64,
    pub line_end: i64,
    /// The finding's `vuln_class` wire string. Two different weaknesses
    /// on one line are two findings, so the class has to agree before
    /// overlapping ranges mean "the same one".
    pub vuln_class: String,
}

impl Locator {
    /// Whether `self` and `other` plausibly describe the same finding:
    /// same file, same class, and line ranges that overlap or start
    /// within `tolerance` lines of each other.
    ///
    /// The geometric half of `bc_dedup_core::collapse_trivial`'s rule,
    /// reimplemented locally rather than taking a dependency for one
    /// predicate — the same call this project's own S4 vote clustering
    /// makes, for the same reason.
    pub fn plausibly_same(&self, other: &Locator, tolerance: i64) -> bool {
        self.file == other.file
            && self.vuln_class == other.vuln_class
            && ((self.line_start - other.line_start).abs() <= tolerance
                || (self.line_start <= other.line_end && other.line_start <= self.line_end))
    }
}

/// How far apart two runs' reported `line_start`s can be and still be
/// taken for the same finding. Deliberately small: this only has to
/// absorb a model redrawing the boundary of one finding, not merge two
/// genuinely separate ones a few lines apart.
pub const LOC_LINE_TOLERANCE: i64 = 3;

pub fn loc_marker(loc: &Locator) -> String {
    // `file` can contain anything a path can, so the fields it could
    // collide with go FIRST and it takes the rest of the marker.
    format!(
        "{LOC_MARKER_PREFIX}{}:{}:{}:{}{MARKER_SUFFIX}",
        loc.line_start, loc.line_end, loc.vuln_class, loc.file
    )
}

/// Reads back a [`loc_marker`]. `None` for a comment posted before this
/// marker existed, which simply leaves that comment unmatchable by
/// position — it can still match on either finding id.
pub fn extract_loc_marker(body: &str) -> Option<Locator> {
    let start = body.rfind(LOC_MARKER_PREFIX)?;
    let after = &body[start + LOC_MARKER_PREFIX.len()..];
    let end = after.find(MARKER_SUFFIX)?;
    let payload = &after[..end];
    let mut parts = payload.splitn(4, ':');
    let line_start = parts.next()?.parse().ok()?;
    let line_end = parts.next()?.parse().ok()?;
    let vuln_class = parts.next()?.to_string();
    let file = parts.next()?.to_string();
    if file.is_empty() {
        return None;
    }
    Some(Locator {
        file,
        line_start,
        line_end,
        vuln_class,
    })
}

/// Extracts the finding id from a comment body previously produced by
/// [`render_comment_body`]. Deliberately takes the LAST occurrence: this
/// function's own output always appends its real marker as the final
/// line, so matching on the last occurrence is immune to a finding's own
/// (redacted) free text happening to contain a marker-shaped substring
/// earlier in the body.
pub fn extract_marker(body: &str) -> Option<String> {
    let start = body.rfind(MARKER_PREFIX)?;
    let after_prefix = &body[start + MARKER_PREFIX.len()..];
    let end = after_prefix.find(MARKER_SUFFIX)?;
    Some(after_prefix[..end].to_string())
}

/// Renders a Markdown comment body for `finding`. Every field sourced from
/// repo content or an LLM's output passes through [`bc_redact::redact`]
/// first — the same "redact before it leaves the process" invariant
/// applied at every other write/log boundary in this project.
pub fn render_comment_body(finding: &Finding, finding_id: &str) -> String {
    let title = bc_redact::redact(&finding.title);
    let description = bc_redact::redact(&finding.description);
    let snippet = bc_redact::redact(&finding.code_snippet);
    let recommendation = bc_redact::redact(&finding.recommendation);

    let mut body = format!(
        "### {title}\n\n**Location:** `{}:{}-{}`\n",
        finding.file, finding.line_start, finding.line_end
    );
    if let Some(rating) = &finding.cvss_rating {
        body.push_str(&format!("**Severity:** {rating}\n"));
    }
    body.push('\n');
    body.push_str(description.trim());
    body.push('\n');
    if !snippet.trim().is_empty() {
        body.push_str(&format!("\n```\n{}\n```\n", snippet.trim()));
    }
    if !recommendation.trim().is_empty() {
        body.push_str(&format!(
            "\n**Recommendation:** {}\n",
            recommendation.trim()
        ));
    }
    body.push_str(&format!("\n{}\n", marker(finding_id)));
    body.push_str(&format!(
        "{}\n",
        loc_marker(&Locator {
            file: finding.file.clone(),
            line_start: finding.line_start,
            line_end: finding.line_end,
            vuln_class: finding.vuln_class.as_str().to_string(),
        })
    ));
    body
}

/// Where an inline review comment anchors — a single line when
/// `start_line == end_line` (every [`plan_comments`] anchor today), or a
/// contiguous multi-line range (used by [`crate::fix_comment::
/// plan_fix_comments`]'s native `suggestion`-fenced comments, which must
/// cover the fix's ENTIRE replaced range for GitHub's "Commit suggestion"
/// button to apply cleanly).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anchor {
    pub file: String,
    pub start_line: i64,
    pub end_line: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedComment {
    pub finding_id: String,
    pub body: String,
    /// Identities the same finding may already be posted under from an
    /// earlier run, tried by [`crate::reconcile::reconcile`] after
    /// `finding_id` itself. Lets a comment marked with a superseded id be
    /// UPDATED in place — and re-marked with the current one — instead of
    /// posting a second comment for a finding the reviewer already has.
    pub legacy_ids: Vec<String>,
    /// Where this finding is, for position-based matching against an
    /// already-posted comment whose content hash has since moved. `None`
    /// for planned comments that aren't a finding (fix suggestions).
    pub locator: Option<Locator>,
    /// `Some(_)` when the finding's `line_start` is part of the PR diff on
    /// the given file (an inline review comment can anchor there); `None`
    /// when it isn't (falls back to a conversation comment).
    pub anchor: Option<Anchor>,
}

/// Plan one comment per finding.
///
/// `repo_root` is what lets a comment be keyed on
/// [`bc_sarif::finding_id_v2`] — a hash of the code actually on disk at
/// the finding's line range — instead of [`bc_sarif::finding_id`], which
/// hashes the snippet the MODEL quoted. That snippet is not stable: a
/// 2026-09-03 scan and its 2026-09-04 re-run described the same SQL
/// injection with different quoted text and a two-line-different range,
/// so the v1 id changed, reconciliation found no match, and the reviewer
/// got a third near-identical comment for one vulnerability. Pass `None`
/// only when the repository is not available to read (the ids then stay
/// v1, exactly as before).
pub fn plan_comments(
    findings: &[Finding],
    diff_lines: &BTreeMap<String, BTreeSet<i64>>,
    repo_root: Option<&Path>,
) -> Vec<PlannedComment> {
    findings
        .iter()
        .map(|f| {
            let v1 = bc_sarif::finding_id(f);
            // v2 needs to read the file; fall back to v1 when the range
            // can't be read (file gone, line numbers past EOF).
            let v2 = repo_root.and_then(|root| bc_sarif::finding_id_v2(root, f));
            let (finding_id, legacy_ids) = match v2 {
                Some(id) => (id, vec![v1]),
                None => (v1, Vec::new()),
            };
            let body = render_comment_body(f, &finding_id);
            let anchor = diff_lines
                .get(&f.file)
                .filter(|lines| lines.contains(&f.line_start))
                .map(|_| Anchor {
                    file: f.file.clone(),
                    start_line: f.line_start,
                    end_line: f.line_start,
                });
            PlannedComment {
                finding_id,
                legacy_ids,
                locator: Some(Locator {
                    file: f.file.clone(),
                    line_start: f.line_start,
                    line_end: f.line_end,
                    vuln_class: f.vuln_class.as_str().to_string(),
                }),
                body,
                anchor,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_model::VulnClass;

    pub(super) fn finding(overrides: impl FnOnce(&mut Finding)) -> Finding {
        let mut f = Finding {
            provider_origins: Vec::new(),
            chunk_id: "c1".to_string(),
            file: "app/login.py".to_string(),
            line_start: 10,
            line_end: 12,
            vuln_class: VulnClass::Injection,
            cwe: None,
            title: "SQL injection".to_string(),
            impact: String::new(),
            description: "user input reaches a query unescaped".to_string(),
            exploit_scenario: String::new(),
            preconditions: Vec::new(),
            recommendation: String::new(),
            code_snippet: "query(x)".to_string(),
            source_ref: None,
            sink_ref: None,
            backfilled_refs: Vec::new(),
            reanchored: Vec::new(),
            compliance_requirements: Vec::new(),
            confidence: 0.9,
            votes: 1,
            duplicates: Vec::new(),
            verdict: None,
            verdict_confidence: None,
            verdict_reason: String::new(),
            cvss_vector: None,
            cvss_score: None,
            cvss_rating: None,
            verifier_reasoning: String::new(),
            vsvs_vector: None,
            vsvs_score: None,
            vsvs_rating: None,
            offensive_priority: None,
            offensive_reason: String::new(),
            related_cwes: Vec::new(),
        };
        overrides(&mut f);
        f
    }

    #[test]
    fn marker_round_trips_through_extract_marker() {
        let m = marker("abc123");
        assert_eq!(extract_marker(&m), Some("abc123".to_string()));
    }

    #[test]
    fn extract_marker_returns_none_when_absent() {
        assert_eq!(extract_marker("just a normal comment"), None);
    }

    #[test]
    fn extract_marker_returns_none_on_an_unterminated_marker() {
        assert_eq!(extract_marker("<!-- bc:finding-id=abc no closing"), None);
    }

    #[test]
    fn extract_marker_takes_the_last_occurrence_not_the_first() {
        // A finding's own (attacker-influenced) description could contain
        // a marker-shaped substring; the real marker rendered by
        // `render_comment_body` is always last, so a lookalike earlier in
        // the body must not be picked up instead.
        let body = format!(
            "spoofed lookalike: {}\n\nreal body\n{}",
            marker("spoofed-id"),
            marker("real-id")
        );
        assert_eq!(extract_marker(&body), Some("real-id".to_string()));
    }

    #[test]
    fn render_comment_body_includes_marker_location_and_description() {
        let f = finding(|_| {});
        let id = "deadbeef";
        let body = render_comment_body(&f, id);
        assert!(body.contains("### SQL injection"));
        assert!(body.contains("`app/login.py:10-12`"));
        assert!(body.contains("user input reaches a query unescaped"));
        assert!(body.contains(&marker(id)));
    }

    #[test]
    fn render_comment_body_omits_severity_when_unrated() {
        let f = finding(|_| {});
        let body = render_comment_body(&f, "id");
        assert!(!body.contains("**Severity:**"));
    }

    #[test]
    fn render_comment_body_includes_severity_when_rated() {
        let f = finding(|f| f.cvss_rating = Some("Critical".to_string()));
        let body = render_comment_body(&f, "id");
        assert!(body.contains("**Severity:** Critical"));
    }

    #[test]
    fn render_comment_body_omits_empty_snippet_and_recommendation_blocks() {
        let f = finding(|f| {
            f.code_snippet = "   ".to_string();
            f.recommendation = String::new();
        });
        let body = render_comment_body(&f, "id");
        assert!(!body.contains("```"));
        assert!(!body.contains("**Recommendation:**"));
    }

    #[test]
    fn render_comment_body_includes_populated_snippet_and_recommendation() {
        let f = finding(|f| f.recommendation = "use parameterized queries".to_string());
        let body = render_comment_body(&f, "id");
        assert!(body.contains("```\nquery(x)\n```"));
        assert!(body.contains("**Recommendation:** use parameterized queries"));
    }

    #[test]
    fn render_comment_body_redacts_secrets_in_free_text_fields() {
        let f = finding(|f| {
            f.description = "leaked key AKIAAAAAAAAAAAAAAAAA found here".to_string();
        });
        let body = render_comment_body(&f, "id");
        assert!(!body.contains("AKIAAAAAAAAAAAAAAAAA"));
    }

    #[test]
    fn plan_comments_anchors_a_finding_on_a_diff_touched_line() {
        let f = finding(|_| {});
        let mut diff_lines = BTreeMap::new();
        diff_lines.insert("app/login.py".to_string(), BTreeSet::from([9, 10, 11]));
        let planned = plan_comments(std::slice::from_ref(&f), &diff_lines, None);
        assert_eq!(
            planned[0].anchor,
            Some(Anchor {
                file: "app/login.py".to_string(),
                start_line: 10,
                end_line: 10,
            })
        );
        assert_eq!(planned[0].finding_id, bc_sarif::finding_id(&f));
    }

    #[test]
    fn plan_comments_falls_back_when_the_file_is_not_in_the_diff_at_all() {
        let f = finding(|_| {});
        let diff_lines = BTreeMap::new();
        let planned = plan_comments(std::slice::from_ref(&f), &diff_lines, None);
        assert_eq!(planned[0].anchor, None);
    }

    #[test]
    fn plan_comments_falls_back_when_the_file_is_touched_but_not_this_line() {
        let f = finding(|_| {});
        let mut diff_lines = BTreeMap::new();
        diff_lines.insert("app/login.py".to_string(), BTreeSet::from([500]));
        let planned = plan_comments(std::slice::from_ref(&f), &diff_lines, None);
        assert_eq!(planned[0].anchor, None);
    }
}

#[cfg(test)]
mod v2_identity_tests {
    use super::*;
    use bc_model::VulnClass;

    fn f(line_start: i64, line_end: i64, snippet: &str) -> Finding {
        let mut f = Finding {
            provider_origins: Vec::new(),
            chunk_id: "c1".to_string(),
            file: "app.py".to_string(),
            line_start,
            line_end,
            vuln_class: VulnClass::Injection,
            cwe: Some("CWE-89".to_string()),
            title: "SQL injection".to_string(),
            impact: String::new(),
            description: "d".to_string(),
            exploit_scenario: String::new(),
            preconditions: Vec::new(),
            recommendation: String::new(),
            code_snippet: snippet.to_string(),
            source_ref: None,
            sink_ref: None,
            backfilled_refs: Vec::new(),
            reanchored: Vec::new(),
            compliance_requirements: Vec::new(),
            confidence: 0.9,
            votes: 1,
            duplicates: Vec::new(),
            verdict: None,
            verdict_confidence: None,
            verdict_reason: String::new(),
            cvss_vector: None,
            cvss_score: None,
            cvss_rating: None,
            verifier_reasoning: String::new(),
            vsvs_vector: None,
            vsvs_score: None,
            vsvs_rating: None,
            offensive_priority: None,
            offensive_reason: String::new(),
            related_cwes: Vec::new(),
        };
        f.title = "SQL injection".to_string();
        f
    }

    /// The field case: two runs describe the same vulnerability, quoting
    /// different amounts of the same code. Keyed on the model's snippet
    /// those are two findings; keyed on what is on disk they are one.
    #[test]
    fn the_same_code_gets_one_id_across_differently_quoted_runs() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("app.py"),
            "import x\nquery = 'SELECT ' + name\ncursor.execute(query)\nreturn 1\n",
        )
        .unwrap();
        let diff_lines = BTreeMap::new();

        let run1 = plan_comments(
            &[f(2, 3, "query = 'SELECT ' + name")],
            &diff_lines,
            Some(dir.path()),
        );
        let run2 = plan_comments(
            &[f(2, 3, "query = 'SELECT ' + name\ncursor.execute(query)")],
            &diff_lines,
            Some(dir.path()),
        );
        assert_eq!(
            run1[0].finding_id, run2[0].finding_id,
            "same code range must yield one identity regardless of what the model quoted"
        );
        // And the v1 id they would previously have been keyed on differs,
        // which is exactly why the duplicate comments appeared.
        assert_ne!(run1[0].legacy_ids, run2[0].legacy_ids);
    }

    #[test]
    fn without_a_repo_root_the_ids_stay_v1_and_carry_no_legacy() {
        let diff_lines = BTreeMap::new();
        let planned = plan_comments(&[f(2, 3, "q")], &diff_lines, None);
        assert_eq!(planned[0].finding_id, bc_sarif::finding_id(&f(2, 3, "q")));
        assert!(planned[0].legacy_ids.is_empty());
    }

    #[test]
    fn an_unreadable_range_falls_back_to_v1() {
        let dir = tempfile::tempdir().unwrap();
        // No app.py on disk at all.
        let diff_lines = BTreeMap::new();
        let planned = plan_comments(&[f(2, 3, "q")], &diff_lines, Some(dir.path()));
        assert_eq!(planned[0].finding_id, bc_sarif::finding_id(&f(2, 3, "q")));
        assert!(planned[0].legacy_ids.is_empty());
    }
}

#[cfg(test)]
mod loc_marker_tests {
    use super::*;

    fn loc(file: &str) -> Locator {
        Locator {
            file: file.to_string(),
            line_start: 25,
            line_end: 29,
            vuln_class: "injection".to_string(),
        }
    }

    #[test]
    fn a_loc_marker_round_trips() {
        let l = loc("app.py");
        assert_eq!(extract_loc_marker(&loc_marker(&l)), Some(l));
    }

    #[test]
    fn a_path_containing_colons_survives_because_the_file_comes_last() {
        // The whole reason `file` is the final field.
        let l = loc("weird:dir/a:b.py");
        assert_eq!(extract_loc_marker(&loc_marker(&l)), Some(l));
    }

    #[test]
    fn a_body_without_the_marker_yields_none() {
        assert_eq!(extract_loc_marker("### A finding\n\nno markers"), None);
    }

    #[test]
    fn a_malformed_marker_yields_none_rather_than_a_wrong_locator() {
        for body in [
            "<!-- bc:loc=notanumber:29:injection:app.py -->",
            "<!-- bc:loc=25:notanumber:injection:app.py -->",
            "<!-- bc:loc=25:29:injection -->",  // no file
            "<!-- bc:loc=25:29:injection: -->", // empty file
            "<!-- bc:loc=25 -->",
            "<!-- bc:loc=25:29:injection:app.py", // unterminated
        ] {
            assert_eq!(extract_loc_marker(body), None, "for {body}");
        }
    }

    #[test]
    fn the_rendered_body_carries_both_markers_and_they_read_back() {
        use bc_model::VulnClass;
        let mut f = super::tests::finding(|_| {});
        f.file = "app.py".to_string();
        f.line_start = 25;
        f.line_end = 29;
        f.vuln_class = VulnClass::Injection;
        let body = render_comment_body(&f, "the-id");
        assert_eq!(extract_marker(&body).as_deref(), Some("the-id"));
        assert_eq!(
            extract_loc_marker(&body),
            Some(Locator {
                file: "app.py".to_string(),
                line_start: 25,
                line_end: 29,
                vuln_class: "injection".to_string(),
            })
        );
    }

    #[test]
    fn a_finding_id_marker_in_the_free_text_does_not_confuse_the_locator() {
        let mut f = super::tests::finding(|f| {
            f.description = "<!-- bc:loc=1:2:other:evil.py --> not the real one".to_string();
        });
        f.file = "app.py".to_string();
        f.line_start = 25;
        f.line_end = 29;
        let body = render_comment_body(&f, "the-id");
        // `rfind` takes the LAST marker, which is always the real one.
        assert_eq!(extract_loc_marker(&body).unwrap().file, "app.py");
    }
}
