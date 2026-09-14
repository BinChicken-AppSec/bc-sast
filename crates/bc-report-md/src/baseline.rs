//! The `## Baseline Comparison` section — what changed since a prior
//! scan, appended to `report.md` when `--baseline` was given.
//!
//! Not a port: the Python original has no baseline mode at all. The
//! shape follows SARIF 2.1.0's own `baselineState` vocabulary
//! (`new`/`unchanged`/`absent`) so the Markdown and the SARIF tell the
//! same story, with `absent` rendered as "resolved" — which is what it
//! means to a human reading a security report, and what `report.sarif`
//! cannot say because SARIF's own word for it is fixed.
//!
//! Counts come first and the two interesting lists follow: a reviewer's
//! question is almost always "what did this change introduce" (the `new`
//! list) and only then "what did it fix" (`resolved`). `unchanged` is a
//! count only — listing dozens of pre-existing findings a second time,
//! immediately below the section that already lists them in full, is
//! noise.

use crate::sanitize::{md_cell, md_code_span};

/// One finding on either side of the comparison, reduced to what the
/// section renders. Deliberately a plain owned struct rather than a
/// `RankedFinding`/`SarifResult`, so this crate stays a pure renderer:
/// the baseline half of a comparison may come from a prior `report.sarif`
/// that has no `bc_model` type behind it at all.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BaselineEntry {
    pub file: String,
    pub line: i64,
    pub title: String,
}

/// A whole comparison, ready to render.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BaselineView {
    /// The `--baseline` path, echoed so the report says what it was
    /// compared against — a report with a bare "3 new findings" and no
    /// statement of the baseline is not reproducible by the reader.
    pub baseline: String,
    /// Findings in this scan with no counterpart in the baseline.
    pub new: Vec<BaselineEntry>,
    /// How many findings matched a baseline entry.
    pub unchanged: usize,
    /// Baseline findings with no counterpart in this scan — SARIF's
    /// `absent`.
    pub resolved: Vec<BaselineEntry>,
}

fn entry_line(e: &BaselineEntry) -> String {
    format!(
        "- `{}:{}` — {}",
        md_code_span(&e.file),
        e.line,
        md_cell(&e.title)
    )
}

/// Renders the section, including its leading blank line, so a caller can
/// append it straight onto an existing report.
///
/// Always renders, even when nothing changed: "0 new, 0 resolved" against
/// a named baseline is a *result* — it is the sentence a PR gate wants —
/// whereas an omitted section is indistinguishable from a run where
/// `--baseline` was forgotten.
pub fn render_baseline_section(view: &BaselineView) -> String {
    let mut out = vec![
        String::new(),
        "## Baseline Comparison".to_string(),
        String::new(),
        format!("- Baseline: `{}`", md_code_span(&view.baseline)),
        format!("- New: {}", view.new.len()),
        format!("- Unchanged: {}", view.unchanged),
        format!(
            "- Resolved (absent from this scan): {}",
            view.resolved.len()
        ),
    ];
    if !view.new.is_empty() {
        out.push(String::new());
        out.push("### New findings".to_string());
        out.push(String::new());
        out.extend(view.new.iter().map(entry_line));
    }
    if !view.resolved.is_empty() {
        out.push(String::new());
        out.push("### Resolved findings".to_string());
        out.push(String::new());
        out.extend(view.resolved.iter().map(entry_line));
    }
    out.push(String::new());
    out.join("\n")
}

/// [`render_baseline_section`] appended to an existing report.
pub fn append_baseline_section(markdown: &str, view: &BaselineView) -> String {
    format!("{markdown}{}", render_baseline_section(view))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(file: &str, line: i64, title: &str) -> BaselineEntry {
        BaselineEntry {
            file: file.to_string(),
            line,
            title: title.to_string(),
        }
    }

    #[test]
    fn a_clean_comparison_still_renders_its_counts() {
        let view = BaselineView {
            baseline: "prior.sarif".to_string(),
            new: Vec::new(),
            unchanged: 4,
            resolved: Vec::new(),
        };
        let out = render_baseline_section(&view);
        assert!(out.contains("## Baseline Comparison"));
        assert!(out.contains("- Baseline: `prior.sarif`"));
        assert!(out.contains("- New: 0"));
        assert!(out.contains("- Unchanged: 4"));
        assert!(out.contains("- Resolved (absent from this scan): 0"));
        assert!(!out.contains("### New findings"));
        assert!(!out.contains("### Resolved findings"));
    }

    #[test]
    fn new_and_resolved_findings_are_listed_by_file_line_and_title() {
        let view = BaselineView {
            baseline: "b.json".to_string(),
            new: vec![entry("app/db.py", 12, "SQL injection")],
            unchanged: 1,
            resolved: vec![entry("app/old.py", 3, "Path traversal")],
        };
        let out = render_baseline_section(&view);
        assert!(out.contains("### New findings"));
        assert!(out.contains("- `app/db.py:12` — SQL injection"), "{out}");
        assert!(out.contains("### Resolved findings"));
        assert!(out.contains("- `app/old.py:3` — Path traversal"), "{out}");
    }

    /// Titles and paths are model-authored, so both go through the same
    /// sanitizers every other rendered field does — a title carrying a
    /// newline plus `## ` would otherwise restructure the report.
    #[test]
    fn model_authored_text_is_sanitized() {
        let view = BaselineView {
            baseline: "b.json".to_string(),
            new: vec![entry("a`b.py", 1, "one\n## Injected Heading")],
            unchanged: 0,
            resolved: Vec::new(),
        };
        let out = render_baseline_section(&view);
        assert!(!out.contains("\n## Injected Heading"), "{out}");
        assert!(!out.contains("a`b.py"), "{out}");
    }

    #[test]
    fn append_puts_the_section_at_the_end_of_the_report() {
        let view = BaselineView {
            baseline: "b.json".to_string(),
            unchanged: 2,
            ..BaselineView::default()
        };
        let out = append_baseline_section("# Report\n\nbody\n", &view);
        assert!(out.starts_with("# Report\n\nbody\n"));
        assert!(out
            .trim_end()
            .ends_with("- Resolved (absent from this scan): 0"));
    }
}
