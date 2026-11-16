use crate::sanitize::{md_cell, md_code_span};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BaselineEntry {
    pub file: String,
    pub line: i64,
    pub title: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BaselineView {
    pub baseline: String,
    pub new: Vec<BaselineEntry>,
    pub unchanged: usize,
    pub unchanged_fuzzy: usize,
    pub unchanged_renamed: usize,
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
    if view.unchanged_renamed > 0 {
        out.push(format!(
            "  - {} matched across a renamed path",
            view.unchanged_renamed
        ));
    }
    if view.unchanged_fuzzy > 0 {
        out.push(format!(
            "  - {} matched only on the fuzzy rule (same file and class, nearby lines), \
             which is a weaker claim than an identical-code match",
            view.unchanged_fuzzy
        ));
    }
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
    fn the_fuzzy_share_of_unchanged_is_called_out_as_a_weaker_claim() {
        let view = BaselineView {
            baseline: "prior.json".to_string(),
            new: Vec::new(),
            unchanged: 5,
            unchanged_fuzzy: 2,
            unchanged_renamed: 0,
            resolved: Vec::new(),
        };
        let out = render_baseline_section(&view);
        assert!(out.contains("- Unchanged: 5"), "{out}");
        assert!(out.contains("2 matched only on the fuzzy rule"), "{out}");
        assert!(out.contains("weaker claim"), "{out}");
        assert!(!out.contains("renamed path"), "{out}");
    }

    #[test]
    fn matches_across_a_rename_are_reported_separately() {
        let view = BaselineView {
            baseline: "prior.json".to_string(),
            new: Vec::new(),
            unchanged: 3,
            unchanged_fuzzy: 0,
            unchanged_renamed: 3,
            resolved: Vec::new(),
        };
        let out = render_baseline_section(&view);
        assert!(out.contains("3 matched across a renamed path"), "{out}");
        assert!(!out.contains("fuzzy rule"), "{out}");
    }

    #[test]
    fn a_clean_comparison_still_renders_its_counts() {
        let view = BaselineView {
            unchanged_fuzzy: 0,
            unchanged_renamed: 0,
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
            unchanged_fuzzy: 0,
            unchanged_renamed: 0,
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

    #[test]
    fn model_authored_text_is_sanitized() {
        let view = BaselineView {
            unchanged_fuzzy: 0,
            unchanged_renamed: 0,
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
            unchanged_fuzzy: 0,
            unchanged_renamed: 0,
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
