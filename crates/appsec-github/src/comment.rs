use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use appsec_model::Finding;

pub const MARKER_PREFIX: &str = "<!-- bc:finding-id=";
pub const MARKER_SUFFIX: &str = " -->";

pub const LOC_MARKER_PREFIX: &str = "<!-- bc:loc=";

pub fn marker(finding_id: &str) -> String {
    format!("{MARKER_PREFIX}{finding_id}{MARKER_SUFFIX}")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Locator {
    pub file: String,
    pub line_start: i64,
    pub line_end: i64,
    pub vuln_class: String,
}

impl Locator {
    pub fn plausibly_same(&self, other: &Locator, tolerance: i64) -> bool {
        self.file == other.file
            && self.vuln_class == other.vuln_class
            && ((self.line_start - other.line_start).abs() <= tolerance
                || (self.line_start <= other.line_end && other.line_start <= self.line_end))
    }
}

pub const LOC_LINE_TOLERANCE: i64 = 3;

pub fn loc_marker(loc: &Locator) -> String {
    format!(
        "{LOC_MARKER_PREFIX}{}:{}:{}:{}{MARKER_SUFFIX}",
        loc.line_start, loc.line_end, loc.vuln_class, loc.file
    )
}

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

pub fn extract_marker(body: &str) -> Option<String> {
    let start = body.rfind(MARKER_PREFIX)?;
    let after_prefix = &body[start + MARKER_PREFIX.len()..];
    let end = after_prefix.find(MARKER_SUFFIX)?;
    Some(after_prefix[..end].to_string())
}

pub fn render_comment_body(finding: &Finding, finding_id: &str) -> String {
    let title = appsec_redact::redact(&finding.title);
    let description = appsec_redact::redact(&finding.description);
    let snippet = appsec_redact::redact(&finding.code_snippet);
    let recommendation = appsec_redact::redact(&finding.recommendation);

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
    pub legacy_ids: Vec<String>,
    pub locator: Option<Locator>,
    pub anchor: Option<Anchor>,
}

pub fn plan_comments(
    findings: &[Finding],
    diff_lines: &BTreeMap<String, BTreeSet<i64>>,
    repo_root: Option<&Path>,
) -> Vec<PlannedComment> {
    findings
        .iter()
        .map(|f| {
            let v1 = appsec_sarif::finding_id(f);
            let v2 = repo_root.and_then(|root| appsec_sarif::finding_id_v2(root, f));
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
    use appsec_model::VulnClass;

    pub(super) fn finding(overrides: impl FnOnce(&mut Finding)) -> Finding {
        let mut f = Finding {
            provider_origins: Vec::new(),
            component: None,
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
        assert_eq!(planned[0].finding_id, appsec_sarif::finding_id(&f));
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
    use appsec_model::VulnClass;

    fn f(line_start: i64, line_end: i64, snippet: &str) -> Finding {
        let mut f = Finding {
            provider_origins: Vec::new(),
            component: None,
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
        assert_ne!(run1[0].legacy_ids, run2[0].legacy_ids);
    }

    #[test]
    fn without_a_repo_root_the_ids_stay_v1_and_carry_no_legacy() {
        let diff_lines = BTreeMap::new();
        let planned = plan_comments(&[f(2, 3, "q")], &diff_lines, None);
        assert_eq!(
            planned[0].finding_id,
            appsec_sarif::finding_id(&f(2, 3, "q"))
        );
        assert!(planned[0].legacy_ids.is_empty());
    }

    #[test]
    fn an_unreadable_range_falls_back_to_v1() {
        let dir = tempfile::tempdir().unwrap();
        let diff_lines = BTreeMap::new();
        let planned = plan_comments(&[f(2, 3, "q")], &diff_lines, Some(dir.path()));
        assert_eq!(
            planned[0].finding_id,
            appsec_sarif::finding_id(&f(2, 3, "q"))
        );
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
            "<!-- bc:loc=25:29:injection -->",
            "<!-- bc:loc=25:29:injection: -->",
            "<!-- bc:loc=25 -->",
            "<!-- bc:loc=25:29:injection:app.py",
        ] {
            assert_eq!(extract_loc_marker(body), None, "for {body}");
        }
    }

    #[test]
    fn the_rendered_body_carries_both_markers_and_they_read_back() {
        use appsec_model::VulnClass;
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
        assert_eq!(extract_loc_marker(&body).unwrap().file, "app.py");
    }
}
