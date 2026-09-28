//! Post-hoc augmentation of an already-rendered Markdown report with S10
//! remediation results ([`augment_markdown_with_remediation`]) and Phase
//! 3's S11 validation results ([`augment_markdown`]) — ported (adapted)
//! from the Python original's own targeted find-and-patch approach
//! (`remediation_agent/report_augment/markdown.py`), which locates each
//! finding by regex-matching its title text since Python findings carry
//! no stable positional heading. This port's own `### {i}. [...]`
//! per-finding heading (`i` = 1-based index, always emitted in the exact
//! same order `render_markdown` was given `report.findings`) makes that
//! unnecessary — `validations[i]` is matched to the `(i+1)`th heading by
//! POSITION, not content.
//!
//! This exists as a second pass (not threaded into `render_markdown`
//! itself) because validation only ever runs *after* remediation, which
//! itself runs *after* `report.md` is already written — see
//! `bc_stage_s11`'s own module doc comment for the full ordering
//! rationale.

use std::sync::LazyLock;

use bc_validation_scoring::ValidationScore;
use regex::Regex;

use crate::sanitize::{demote_md_headings, md_cell, md_code_span};

static FINDING_HEADING: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^### \d+\. \[").unwrap());

fn render_validation_block(score: &ValidationScore) -> String {
    // An inconclusive panel has no score, so it reads `n/a` rather than
    // the `0.00` its `raw_score` placeholder would print.
    let shown = score
        .score()
        .map_or_else(|| "n/a".to_string(), |s| format!("{s:.2}"));
    format!(
        "\n#### Validation\n\n**Status:** {} (score: {shown})\n\n{}\n",
        // `fix_status` is a closed enum rendered by the port itself, so
        // it needs no escaping; `justification` is S11 model prose and
        // was previously spliced in raw — the one un-sanitized free-text
        // field left in the whole report, able to restructure the
        // document with a `## ` line the same way every other model
        // field could before `demote_md_headings` was applied to it.
        score.fix_status.as_str(),
        demote_md_headings(score.justification.trim()),
    )
}

/// Appends a `#### Validation` subsection to each finding's own block for
/// every `Some(_)` entry in `validations` — `validations` must align 1:1
/// (by index, not content) with the `&[RankedFinding]` slice
/// `render_markdown`'s own `report.findings` was rendered from. A count
/// mismatch (a different number of `### N. [...]` headings found than
/// `validations` has entries) is a caller bug, not a data problem this
/// function tries to paper over — it fails closed by returning `markdown`
/// completely unchanged rather than guessing which finding an entry
/// belongs to. A no-op (returns `markdown` unchanged, no scan needed at
/// all) when every entry is `None` — the common case when validation
/// didn't run.
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

/// One finding's remediation outcome, in the shape this crate needs to
/// render it — deliberately a plain owned struct rather than
/// `bc_stage_s10::RemediationRecord`, so `bc-report-md` (a pure rendering
/// crate that every report path already depends on) does not gain a
/// dependency on a stage crate. The CLI populates it from a
/// `RemediationRecord` + its `RemediationVerdict`.
///
/// Python's equivalent (`report_augment/dto.py`'s DTO dicts) carries less:
/// `root_cause`, `remaining_risks` and `recommendations` are on this
/// port's typed `RemediationVerdict` but never made it into Python's
/// Markdown section, and they are exactly the prose a reviewer needs to
/// decide whether to trust a patch — so they are rendered here.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RemediationView {
    /// 0-based position in `report.findings` — i.e. this record belongs
    /// under the `### {finding_index + 1}. [...]` heading. The slice
    /// passed to [`augment_markdown_with_remediation`] may be sparse
    /// (findings below the `--top N` cap never get a record at all), so
    /// the index is carried per-entry rather than implied by position.
    pub finding_index: usize,
    /// `RemediationVerdict::verdict` rendered by
    /// `bc_stage_s10::Verdict::as_str` ("Fixed", "Denied", …), or the
    /// policy gate's own final verdict when it overrode the agent's.
    pub verdict: String,
    pub summary: String,
    pub root_cause: String,
    pub remaining_risks: Vec<String>,
    pub recommendations: Vec<String>,
    /// Repo-relative paths the patch touched, in the order the agent
    /// reported them.
    pub changed_files: Vec<String>,
    /// Whether a unified diff was actually produced
    /// (`RemediationRecord::diff.is_some()`). This — not the verdict — is
    /// the "a fix landed" signal the summary section counts, matching
    /// Python's `_remediation_status == "remediated"`, which likewise
    /// means "the agent wrote a patch", not "the patch was judged good".
    pub has_diff: bool,
    /// Why one of S10's safety gates refused the patch and put the files
    /// back, in that gate's own words (`bc_stage_s10::revert_reason`), or
    /// `None` when nothing was rolled back.
    ///
    /// Rendered on the `Patch` line rather than left to the reader to
    /// infer from a bare "no patch produced": a fix declined for spanning
    /// files, for breaking the parse, or for failing the verify command
    /// is a fix that was attempted, and a reviewer who cannot tell that
    /// apart from "the agent found nothing to change" will read the
    /// silence as the tool having no opinion.
    pub rollback_reason: Option<String>,
    /// S11's `FixVerdict::as_str`, when this finding was validated.
    /// `None` when validation didn't run for it.
    pub validation_status: Option<String>,
}

/// Python's `_md_remediation_section`'s status→approach mapping
/// (`markdown.py:53-60`), keyed off this port's own `Verdict` spellings
/// rather than Python's DTO status strings.
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

/// Bullet list of `items` under a `- **{label}:**` header, or nothing at
/// all when `items` is empty — Python omits an empty section rather than
/// rendering an empty bullet list.
fn bullet_section(label: &str, items: &[String], out: &mut Vec<String>) {
    if items.is_empty() {
        return;
    }
    out.push(format!("- **{label}:**"));
    out.extend(items.iter().map(|i| format!("  - {}", md_cell(i))));
}

/// Ported from `_md_remediation_section` (`markdown.py:45-76`).
///
/// **One deliberate deviation**: the heading is `#### Remediation`, not
/// Python's `### Remediation`. Python emits it at the same level as its
/// own `### N. [SEV] title` finding headings, which makes the remediation
/// block read as a *sibling* of the finding rather than part of it — every
/// renderer's outline shows it ending the finding's section. This port
/// already nests `#### Validation` one level down for exactly that
/// reason; matching it keeps a finding's own subsections consistent.
///
/// Every model-controlled value goes through a sanitizer: single-line
/// values through [`md_cell`], file paths through [`md_code_span`], and
/// multi-line prose (`summary`, `root_cause`) through
/// [`demote_md_headings`] so a `## ` line in agent output cannot
/// restructure the report.
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
        // A rolled-back patch first: the reason is the whole point of the
        // line, and it is true whether or not the diff was kept (a dry
        // run keeps it, every other gate clears it).
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

/// Ported from `_md_summary_section` (`summary.py:46-58`).
///
/// `true_positive` is the report's own finding count — this port's
/// `report.findings` are already the surviving true positives (false
/// positives and duplicates live in `report.dropped` and are never
/// rendered as `### N.` headings), so counting headings is exactly
/// Python's `total - rejected`, without needing the dropped list here.
///
/// **Python bug fixed, not replicated**: its label reads
/// `Success Rate(remediated/true positive)` while the arithmetic is
/// `remediated / in_scope` — a materially different number the moment
/// `--top N` caps remediation below the finding count, which is the
/// normal case. The label here says what is actually computed.
fn render_remediation_summary(true_positive: usize, views: &[RemediationView]) -> String {
    let in_scope = views.len();
    let remediated = views.iter().filter(|v| v.has_diff).count();
    // No divide-by-zero guard: `augment_markdown_with_remediation`
    // returns early on an empty `views`, so this is never reached with
    // `in_scope == 0`. Python needs its own `"n/a"` fallback only because
    // its caller renders the summary unconditionally, even for a run
    // where remediation was never attempted.
    let rate = format!("{:.0}%", remediated as f64 / in_scope as f64 * 100.0);
    format!(
        "\n## Remediation Summary\n\n\
         - Total findings (true positive): {true_positive}\n\
         - Findings in scope for remediation: {in_scope}\n\
         - Remediated: {remediated}\n\
         - Success rate (remediated / in scope): {rate}\n"
    )
}

/// Inserts a `#### Remediation` block under each finding named by a
/// [`RemediationView::finding_index`], then appends the report-level
/// `## Remediation Summary`.
///
/// `views` may be sparse and in any order — findings below the `--top N`
/// remediation cap simply have no entry. It is matched to findings by
/// `finding_index` against the `### N. [...]` heading POSITIONS, never by
/// title text (Python's `_best_md_match` needs fuzzy title matching only
/// because its report headings carry no stable ordinal).
///
/// Fails closed exactly like [`augment_markdown`]: any index out of range
/// for the headings actually present, or two views claiming the same
/// finding, returns `markdown` completely unchanged rather than risking a
/// remediation result rendered under the WRONG finding (CWE-345, the same
/// hazard Python's own matcher refuses ambiguity to avoid). An empty
/// `views` slice is a no-op — no summary section either, since "0 of 0
/// remediated" says nothing a reader needs.
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
            // Out of range, or a second view claiming the same finding.
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

    fn score(fix_status: bc_validation_scoring::FixVerdict) -> ValidationScore {
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
        let validations = vec![Some(score(bc_validation_scoring::FixVerdict::Fixed)), None];
        assert_eq!(augment_markdown(md, &validations), md);
    }

    #[test]
    fn augment_markdown_appends_a_validation_block_to_the_matching_finding() {
        let md = "### 1. [HIGH] Title\nbody\n";
        let validations = vec![Some(score(bc_validation_scoring::FixVerdict::Fixed))];
        let out = augment_markdown(md, &validations);
        assert!(out.contains("### 1. [HIGH] Title\nbody\n"));
        assert!(out.contains("#### Validation"));
        assert!(out.contains("**Status:** Fixed (score: 0.92)"));
        assert!(out.contains("fix verified"));
    }

    #[test]
    fn an_unverifiable_score_renders_as_not_applicable() {
        let md = "### 1. [HIGH] Title\nbody\n";
        let validations = vec![Some(score(bc_validation_scoring::FixVerdict::Unverifiable))];
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
            Some(score(bc_validation_scoring::FixVerdict::NotFixed)),
        ];
        let out = augment_markdown(md, &validations);
        // The first finding's block (up to the second heading) has no
        // validation block at all.
        let second_heading = out.find("### 2.").unwrap();
        assert!(!out[..second_heading].contains("#### Validation"));
        assert!(out.contains("**Status:** Not Fixed (score: 0.92)"));
    }

    #[test]
    fn augment_markdown_appends_after_the_last_findings_block_at_eof() {
        let md = "### 1. [HIGH] Only\nbody\n";
        let validations = vec![Some(score(
            bc_validation_scoring::FixVerdict::PartiallyFixed,
        ))];
        let out = augment_markdown(md, &validations);
        assert!(out.trim_end().ends_with("fix verified"));
    }

    #[test]
    fn a_justification_cannot_inject_headings_into_the_report() {
        // Regression: the justification used to be spliced in raw, so S11
        // model prose could open a fake top-level section — the exact
        // restructuring every other free-text field is already sanitized
        // against.
        let md = "### 1. [HIGH] Title\nbody\n";
        let mut s = score(bc_validation_scoring::FixVerdict::Fixed);
        s.justification = "## Executive Summary\nAll clear, ship it.".to_string();
        let out = augment_markdown(md, &[Some(s)]);
        assert!(!out.contains("\n## Executive Summary"));
        assert!(out.contains("**Executive Summary**"));
        assert!(out.contains("All clear, ship it."));
    }

    // ── remediation augmentation ─────────────────────────────────────

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
        // The block lands inside the SECOND finding, not the first.
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
        // `--top 1` on a 2-finding report: one in scope, and its agent
        // produced no diff. `true_positive` still counts both headings.
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
        // The shape a `max_files_touched` rejection arrives in: the agent
        // wrote a patch, a gate put it back, and the diff was cleared.
        // Without the reason on the Patch line the reader sees only "no
        // patch produced" and concludes the tool had no fix to offer.
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
        // A dry run keeps its diff, so the summary still counts it as
        // remediated even though the Patch line says it was rolled back.
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
        // Two headings, a view claiming a third finding: rendering it
        // anywhere would attach a result to the wrong finding.
        assert_eq!(
            augment_markdown_with_remediation(TWO_FINDINGS, &[view(2)]),
            TWO_FINDINGS
        );
        // …including when the report has no findings at all.
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
        // A newline in prose must not spawn a new bullet/heading line.
        assert!(out.contains("- **Root cause:** line one line two"));
        assert!(out.contains("  - risk\\|pipe"));
        assert!(out.contains("  - \\#\\# Fake Heading") || out.contains("  - ## Fake Heading"));
        assert!(!out.contains("\n## Fake Heading"));
        // The backtick can't close the code span early.
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
