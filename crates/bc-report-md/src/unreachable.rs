//! The "Files Not Sent for Catch-All Review" appendix, ported from
//! `models.py::FinalReport._render_unreachable_appendix`. Lists files
//! `step3.catchall_mode: reachable_only` dropped from the catch-all sweep
//! (call-graph unreachable from any entry point/sink), so coverage stays
//! auditable rather than silently truncated. Renders only when
//! `report.unreachable_files` is non-empty — always empty under
//! `default.yaml`, since that mode is `taint.yaml`-only.

use crate::sanitize::md_code_span;

const CAP: usize = 200;

pub fn render_unreachable_appendix(unreachable_files: &[String]) -> Vec<String> {
    let n = unreachable_files.len();
    let mut out = vec![
        String::new(),
        "## Appendix — Files Not Sent for Catch-All Review (call-graph unreachable)".to_string(),
        String::new(),
        format!(
            "`step3.catchall_mode: reachable_only` dropped **{n}** file(s) that were neither \
             forward-reachable from any entry point nor backward-reachable from any sink on \
             the call graph. They were **not** sent for catch-all review, but remain covered \
             by the specialist passes (logic-bug always; access-control/crypto when enabled). \
             To send them for catch-all review too, re-scan with `--config profiles/default.yaml` \
             (catchall_mode: all)."
        ),
        String::new(),
    ];
    for f in unreachable_files.iter().take(CAP) {
        // Repo-controlled file paths: neutralize Markdown injection the
        // same way every other path-rendering call site in this crate
        // does — collapse newlines and replace a literal backtick so a
        // hostile filename can't close this code span early.
        out.push(format!("- `{}`", md_code_span(f)));
    }
    if n > CAP {
        out.push(format!(
            "- _… and {} more (full list in the s3 checkpoint manifest)_",
            n - CAP
        ));
    }
    out.push(String::new());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heading_and_count_render() {
        let md = render_unreachable_appendix(&["a.py".to_string(), "b.py".to_string()]).join("\n");
        assert!(md.contains(
            "## Appendix — Files Not Sent for Catch-All Review (call-graph unreachable)"
        ));
        assert!(md.contains("dropped **2** file(s)"));
    }

    #[test]
    fn lists_every_file_as_a_code_span_bullet() {
        let md = render_unreachable_appendix(&["a.py".to_string(), "b.py".to_string()]).join("\n");
        assert!(md.contains("- `a.py`"));
        assert!(md.contains("- `b.py`"));
    }

    #[test]
    fn caps_the_inline_list_at_200_and_notes_the_remainder() {
        let files: Vec<String> = (0..205).map(|i| format!("f{i}.py")).collect();
        let out = render_unreachable_appendix(&files);
        let bullet_lines = out.iter().filter(|l| l.starts_with("- `")).count();
        assert_eq!(bullet_lines, 200);
        assert!(out
            .iter()
            .any(|l| l.contains("… and 5 more (full list in the s3 checkpoint manifest)")));
    }

    #[test]
    fn exactly_at_cap_has_no_remainder_note() {
        let files: Vec<String> = (0..200).map(|i| format!("f{i}.py")).collect();
        let out = render_unreachable_appendix(&files);
        assert!(!out.iter().any(|l| l.contains("more (full list")));
    }

    #[test]
    fn a_hostile_filename_cannot_break_out_of_its_code_span() {
        let path = "foo`) [pwned](javascript:alert(1)) (`bar".to_string();
        let out = render_unreachable_appendix(&[path]);
        let line = out.iter().find(|l| l.starts_with("- `")).unwrap();
        assert_eq!(line.matches('`').count(), 2);
    }

    #[test]
    fn empty_list_still_renders_the_heading_and_zero_count() {
        let md = render_unreachable_appendix(&[]).join("\n");
        assert!(md.contains("dropped **0** file(s)"));
    }
}
