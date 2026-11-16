use std::sync::LazyLock;

use appsec_validation_scoring::ValidationScore;
use regex::Regex;

use crate::sanitize::{demote_md_headings, md_cell, md_code_span};

static FINDING_HEADING: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^### \d+\. \[").unwrap());

fn render_validation_block(score: &ValidationScore) -> String {
    let shown = score
        .score()
        .map_or_else(|| "n/a".to_string(), |s| format!("{s:.2}"));
    format!(
        "\n#### Validation\n\n**Status:** {} (score: {shown})\n\n{}\n",
        score.fix_status.as_str(),
        demote_md_headings(score.justification.trim()),
    )
}

pub fn augment_markdown(markdown: &str, validations: &[Option<ValidationScore>]) -> String {
    if validations.iter().all(Option::is_none) {
        return markdown.to_string();
    }
    let starts: Vec<usize> = FINDING_HEADING
        .find_iter(markdown)
        .map(|m| m.start())
        .collect();
    if starts.len() != validations.len() {
        return markdown.to_string();
    }

    let ends = starts
        .iter()
        .skip(1)
        .copied()
        .chain(std::iter::once(markdown.len()));
    let mut out = String::with_capacity(markdown.len());
    let mut cursor = 0;
    for (validation, end) in validations.iter().zip(ends) {
        out.push_str(&markdown[cursor..end]);
        if let Some(score) = validation {
            out.push_str(&render_validation_block(score));
        }
        cursor = end;
    }
    out.push_str(&markdown[cursor..]);
    out
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RemediationView {
    pub finding_index: usize,
    pub verdict: String,
    pub summary: String,
    pub root_cause: String,
    pub remaining_risks: Vec<String>,
    pub recommendations: Vec<String>,
    pub changed_files: Vec<String>,
    pub has_diff: bool,
    pub rollback_reason: Option<String>,
    pub validation_status: Option<String>,
}

fn approach_for(verdict: &str) -> &'static str {
    match verdict.trim().to_ascii_lowercase().as_str() {
        "denied" | "deny" => {
            "Policy gate denied automated patching; guidance-only — a human must remediate."
        }
        "fixed" | "partially fixed" | "remediated" => {
            "Automated fix applied by the Remediation Agent and written as a unified diff; \
             awaiting validation."
        }
        _ => "No automated patch applied.",
    }
}

fn bullet_section(label: &str, items: &[String], out: &mut Vec<String>) {
    if items.is_empty() {
        return;
    }
    out.push(format!("- **{label}:**"));
    out.extend(items.iter().map(|i| format!("  - {}", md_cell(i))));
}

fn render_remediation_block(view: &RemediationView) -> String {
    let mut lines = vec![
        "#### Remediation".to_string(),
        String::new(),
        format!("- **Status:** {}", md_cell(&view.verdict)),
    ];
    let summary = view.summary.trim();
    lines.push(format!(
        "- **Summary:** {}",
        if summary.is_empty() {
            "n/a".to_string()
        } else {
            md_cell(summary)
        }
    ));
    lines.push(format!("- **Approach:** {}", approach_for(&view.verdict)));
    lines.push(match (&view.rollback_reason, view.has_diff) {
        (Some(reason), _) => format!("- **Patch:** rolled back, not applied: {}", md_cell(reason)),
        (None, true) => "- **Patch:** unified diff produced".to_string(),
        (None, false) => "- **Patch:** no patch produced".to_string(),
    });
    if let Some(status) = &view.validation_status {
        lines.push(format!("- **Validation:** {}", md_cell(status)));
    }
    let root_cause = view.root_cause.trim();
    if !root_cause.is_empty() {
        lines.push(format!("- **Root cause:** {}", md_cell(root_cause)));
    }
    lines.push("- **Files changed:**".to_string());
    if view.changed_files.is_empty() {
        lines.push("  - (no files changed)".to_string());
    } else {
        lines.extend(
            view.changed_files
                .iter()
                .map(|f| format!("  - `{}`", md_code_span(f))),
        );
    }
    bullet_section("Remaining risks", &view.remaining_risks, &mut lines);
    bullet_section("Recommendations", &view.recommendations, &mut lines);
    format!("\n{}\n", lines.join("\n"))
}

fn render_remediation_summary(true_positive: usize, views: &[RemediationView]) -> String {
    let in_scope = views.len();
    let remediated = views.iter().filter(|v| v.has_diff).count();
    let rate = format!("{:.0}%", remediated as f64 / in_scope as f64 * 100.0);
    format!(
        "\n## Remediation Summary\n\n\
         - Total findings (true positive): {true_positive}\n\
         - Findings in scope for remediation: {in_scope}\n\
         - Remediated: {remediated}\n\
         - Success rate (remediated / in scope): {rate}\n"
    )
}

pub fn augment_markdown_with_remediation(markdown: &str, views: &[RemediationView]) -> String {
    if views.is_empty() {
        return markdown.to_string();
    }
    let starts: Vec<usize> = FINDING_HEADING
        .find_iter(markdown)
        .map(|m| m.start())
        .collect();
    let mut by_index: Vec<Option<&RemediationView>> = vec![None; starts.len()];
    for view in views {
        match by_index.get_mut(view.finding_index) {
            None | Some(Some(_)) => return markdown.to_string(),
            Some(slot) => *slot = Some(view),
        }
    }

    let ends = starts
        .iter()
        .skip(1)
        .copied()
        .chain(std::iter::once(markdown.len()));
    let mut out = String::with_capacity(markdown.len());
    let mut cursor = 0;
    for (view, end) in by_index.iter().zip(ends) {
        out.push_str(&markdown[cursor..end]);
        if let Some(view) = view {
            out.push_str(&render_remediation_block(view));
        }
        cursor = end;
    }
    out.push_str(&markdown[cursor..]);
    out.push_str(&render_remediation_summary(starts.len(), views));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn score(fix_status: appsec_validation_scoring::FixVerdict) -> ValidationScore {
        ValidationScore {
            raw_score: 0.92,
            fix_status,
            justification: "fix verified".to_string(),
            gate_results: Vec::new(),
            has_critical_failure: false,
        }
    }

    #[test]
    fn augment_markdown_is_a_no_op_when_every_entry_is_none() {
        let md = "### 1. [HIGH] Title\nbody\n";
        assert_eq!(augment_markdown(md, &[None]), md);
    }

    #[test]
    fn augment_markdown_is_a_no_op_on_a_heading_count_mismatch() {
        let md = "### 1. [HIGH] Title\nbody\n";
        let validations = vec![
            Some(score(appsec_validation_scoring::FixVerdict::Fixed)),
            None,
        ];
        assert_eq!(augment_markdown(md, &validations), md);
    }

    #[test]
    fn augment_markdown_appends_a_validation_block_to_the_matching_finding() {
        let md = "### 1. [HIGH] Title\nbody\n";
        let validations = vec![Some(score(appsec_validation_scoring::FixVerdict::Fixed))];
        let out = augment_markdown(md, &validations);
        assert!(out.contains("### 1. [HIGH] Title\nbody\n"));
        assert!(out.contains("#### Validation"));
        assert!(out.contains("**Status:** Fixed (score: 0.92)"));
        assert!(out.contains("fix verified"));
    }

    #[test]
    fn an_unverifiable_score_renders_as_not_applicable() {
        let md = "### 1. [HIGH] Title\nbody\n";
        let validations = vec![Some(score(
            appsec_validation_scoring::FixVerdict::Unverifiable,
        ))];
        let out = augment_markdown(md, &validations);
        assert!(
            out.contains("**Status:** UNVERIFIABLE (score: n/a)"),
            "{out}"
        );
    }

    #[test]
    fn augment_markdown_only_appends_to_the_finding_with_a_score_leaving_others_untouched() {
        let md = "### 1. [HIGH] First\nbody one\n### 2. [HIGH] Second\nbody two\n";
        let validations = vec![
            None,
            Some(score(appsec_validation_scoring::FixVerdict::NotFixed)),
        ];
        let out = augment_markdown(md, &validations);
        let second_heading = out.find("### 2.").unwrap();
        assert!(!out[..second_heading].contains("#### Validation"));
        assert!(out.contains("**Status:** Not Fixed (score: 0.92)"));
    }

    #[test]
    fn augment_markdown_appends_after_the_last_findings_block_at_eof() {
        let md = "### 1. [HIGH] Only\nbody\n";
        let validations = vec![Some(score(
            appsec_validation_scoring::FixVerdict::PartiallyFixed,
        ))];
        let out = augment_markdown(md, &validations);
        assert!(out.trim_end().ends_with("fix verified"));
    }

    #[test]
    fn a_justification_cannot_inject_headings_into_the_report() {
        let md = "### 1. [HIGH] Title\nbody\n";
        let mut s = score(appsec_validation_scoring::FixVerdict::Fixed);
        s.justification = "## Executive Summary\nAll clear, ship it.".to_string();
        let out = augment_markdown(md, &[Some(s)]);
        assert!(!out.contains("\n## Executive Summary"));
        assert!(out.contains("**Executive Summary**"));
        assert!(out.contains("All clear, ship it."));
    }

    fn view(finding_index: usize) -> RemediationView {
        RemediationView {
            finding_index,
            verdict: "Fixed".to_string(),
            summary: "Parameterized the query.".to_string(),
            root_cause: "String-concatenated SQL.".to_string(),
            remaining_risks: vec!["Sibling handler still concatenates.".to_string()],
            recommendations: vec!["Add a lint rule.".to_string()],
            changed_files: vec!["src/db.py".to_string()],
            has_diff: true,
            rollback_reason: None,
            validation_status: Some("Fixed".to_string()),
        }
    }

    const TWO_FINDINGS: &str = "### 1. [HIGH] First\nbody one\n### 2. [LOW] Second\nbody two\n";

    #[test]
    fn remediation_augment_is_a_no_op_with_no_views() {
        assert_eq!(
            augment_markdown_with_remediation(TWO_FINDINGS, &[]),
            TWO_FINDINGS
        );
    }

    #[test]
    fn remediation_augment_renders_every_field_under_the_right_finding() {
        let out = augment_markdown_with_remediation(TWO_FINDINGS, &[view(1)]);
        let second = out.find("### 2.").unwrap();
        assert!(!out[..second].contains("#### Remediation"));
        assert!(out[second..].contains("#### Remediation"));
        assert!(out.contains("- **Status:** Fixed"));
        assert!(out.contains("- **Summary:** Parameterized the query."));
        assert!(out.contains(
            "- **Approach:** Automated fix applied by the Remediation Agent and written as a \
             unified diff; awaiting validation."
        ));
        assert!(out.contains("- **Patch:** unified diff produced"));
        assert!(out.contains("- **Validation:** Fixed"));
        assert!(out.contains("- **Root cause:** String-concatenated SQL."));
        assert!(out.contains("- **Files changed:**\n  - `src/db.py`"));
        assert!(out.contains("- **Remaining risks:**\n  - Sibling handler still concatenates."));
        assert!(out.contains("- **Recommendations:**\n  - Add a lint rule."));
    }

    #[test]
    fn remediation_augment_appends_the_summary_section() {
        let out = augment_markdown_with_remediation(TWO_FINDINGS, &[view(0), view(1)]);
        assert!(out.contains("## Remediation Summary"));
        assert!(out.contains("- Total findings (true positive): 2"));
        assert!(out.contains("- Findings in scope for remediation: 2"));
        assert!(out.contains("- Remediated: 2"));
        assert!(out.contains("- Success rate (remediated / in scope): 100%"));
    }

    #[test]
    fn the_summary_counts_only_findings_that_actually_produced_a_patch() {
        let mut v = view(0);
        v.has_diff = false;
        v.verdict = "Not Fixed".to_string();
        let out = augment_markdown_with_remediation(TWO_FINDINGS, &[v]);
        assert!(out.contains("- Total findings (true positive): 2"));
        assert!(out.contains("- Findings in scope for remediation: 1"));
        assert!(out.contains("- Remediated: 0"));
        assert!(out.contains("- Success rate (remediated / in scope): 0%"));
        assert!(out.contains("- **Patch:** no patch produced"));
        assert!(out.contains("- **Approach:** No automated patch applied."));
    }

    #[test]
    fn a_rolled_back_patch_says_why_instead_of_reading_as_nothing_to_say() {
        let mut v = view(0);
        v.verdict = "Needs Review".to_string();
        v.has_diff = false;
        v.rollback_reason = Some(
            "the patch touched 2 file(s), over the max_files_touched limit of 1, so all 2 \
             file(s) the agent touched were rolled back."
                .to_string(),
        );
        let out = augment_markdown_with_remediation(TWO_FINDINGS, &[v]);
        assert!(
            out.contains(
                "- **Patch:** rolled back, not applied: the patch touched 2 file(s), over the \
                 max_files_touched limit of 1"
            ),
            "report missing the rollback reason: {out}"
        );
    }

    #[test]
    fn a_dry_run_keeps_its_diff_and_still_says_it_was_rolled_back() {
        let mut v = view(0);
        v.rollback_reason = Some("dry run: nothing was left applied.".to_string());
        let out = augment_markdown_with_remediation(TWO_FINDINGS, &[v]);
        assert!(out.contains("- Remediated: 1"));
        assert!(out.contains("- **Patch:** rolled back, not applied: dry run:"));
    }

    #[test]
    fn a_denied_verdict_renders_pythons_guidance_only_approach() {
        let mut v = view(0);
        v.verdict = "Denied".to_string();
        v.has_diff = false;
        let out = augment_markdown_with_remediation(TWO_FINDINGS, &[v]);
        assert!(out.contains(
            "- **Approach:** Policy gate denied automated patching; guidance-only — a human \
             must remediate."
        ));
    }

    #[test]
    fn empty_optional_fields_are_omitted_rather_than_rendered_blank() {
        let v = RemediationView {
            finding_index: 0,
            verdict: "Needs Review".to_string(),
            ..Default::default()
        };
        let out = augment_markdown_with_remediation(TWO_FINDINGS, &[v]);
        assert!(out.contains("- **Summary:** n/a"));
        assert!(!out.contains("- **Root cause:**"));
        assert!(!out.contains("- **Validation:**"));
        assert!(!out.contains("- **Remaining risks:**"));
        assert!(!out.contains("- **Recommendations:**"));
        assert!(out.contains("- **Files changed:**\n  - (no files changed)"));
    }

    #[test]
    fn remediation_augment_fails_closed_on_an_out_of_range_index() {
        assert_eq!(
            augment_markdown_with_remediation(TWO_FINDINGS, &[view(2)]),
            TWO_FINDINGS
        );
        assert_eq!(
            augment_markdown_with_remediation("no findings\n", &[view(0)]),
            "no findings\n"
        );
    }

    #[test]
    fn remediation_augment_fails_closed_on_two_views_for_one_finding() {
        assert_eq!(
            augment_markdown_with_remediation(TWO_FINDINGS, &[view(0), view(0)]),
            TWO_FINDINGS
        );
    }

    #[test]
    fn remediation_augment_sanitizes_every_model_controlled_value() {
        let v = RemediationView {
            finding_index: 0,
            verdict: "Fixed".to_string(),
            summary: "broke|the row".to_string(),
            root_cause: "line one\nline two".to_string(),
            remaining_risks: vec!["risk|pipe".to_string()],
            recommendations: vec!["## Fake Heading".to_string()],
            changed_files: vec!["src/`evil`.py".to_string()],
            has_diff: true,
            rollback_reason: Some("rolled|back".to_string()),
            validation_status: Some("Fixed|x".to_string()),
        };
        let out = augment_markdown_with_remediation(TWO_FINDINGS, &[v]);
        assert!(out.contains("- **Summary:** broke\\|the row"));
        assert!(out.contains("- **Root cause:** line one line two"));
        assert!(out.contains("  - risk\\|pipe"));
        assert!(out.contains("  - \\#\\# Fake Heading") || out.contains("  - ## Fake Heading"));
        assert!(!out.contains("\n## Fake Heading"));
        assert!(out.contains("  - `src/ˋevilˋ.py`"));
        assert!(out.contains("- **Validation:** Fixed\\|x"));
        assert!(out.contains("- **Patch:** rolled back, not applied: rolled\\|back"));
    }

    #[test]
    fn remediation_augment_appends_at_eof_for_the_last_finding() {
        let md = "### 1. [HIGH] Only\nbody\n";
        let out = augment_markdown_with_remediation(md, &[view(0)]);
        let block = out.find("#### Remediation").unwrap();
        let summary = out.find("## Remediation Summary").unwrap();
        assert!(
            block < summary,
            "the per-finding block precedes the summary"
        );
    }
}
