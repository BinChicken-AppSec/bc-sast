//! The `## Dropped Findings` section, ported from `models.py::to_markdown`
//! (lines 912-933). The heading always renders; the body is either one
//! bullet per dropped finding or the literal `_None._`.

use bc_model::DroppedFinding;

use crate::sanitize::{md_cell, md_code_span};
use crate::wire::drop_tag;

pub fn render_dropped(dropped: &[DroppedFinding]) -> Vec<String> {
    let mut out = vec![
        String::new(),
        "## Dropped Findings".to_string(),
        String::new(),
    ];
    if dropped.is_empty() {
        out.push("_None._".to_string());
    } else {
        for d in dropped {
            let tag = drop_tag(d.reason, d.canonical_idx);
            out.push(format!(
                "- **[{tag}]** `{}:{}` {} ({}) — {}",
                md_code_span(&d.file),
                d.line,
                d.vuln_class.as_str(),
                md_cell(&d.chunk_id),
                md_cell(&d.detail)
            ));
        }
    }
    out.push(String::new());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_model::{DropReason, VulnClass};

    fn dropped(reason: DropReason, canonical_idx: Option<i64>) -> DroppedFinding {
        DroppedFinding {
            file: "a.py".to_string(),
            line: 10,
            vuln_class: VulnClass::Injection,
            title: "t".to_string(),
            chunk_id: "c1".to_string(),
            reason,
            detail: "why".to_string(),
            canonical_idx,
            provider_origins: Vec::new(),
            verification: None,
        }
    }

    #[test]
    fn empty_dropped_renders_none_italic() {
        let md = render_dropped(&[]).join("\n");
        assert!(md.contains("_None._"));
    }

    #[test]
    fn heading_always_renders_even_when_empty() {
        let md = render_dropped(&[]).join("\n");
        assert!(md.contains("## Dropped Findings"));
    }

    #[test]
    fn one_bullet_per_dropped_finding_with_tag_and_detail() {
        let d = dropped(DropReason::FalsePositive, None);
        let md = render_dropped(&[d]).join("\n");
        assert!(md.contains("- **[FP]** `a.py:10` injection (c1) — why"));
    }

    #[test]
    fn duplicate_with_canonical_idx_shows_dup_of_n() {
        let d = dropped(DropReason::Duplicate, Some(4));
        let md = render_dropped(&[d]).join("\n");
        assert!(md.contains("**[DUP of #5]**"));
    }

    #[test]
    fn duplicate_without_canonical_idx_shows_pre_verify() {
        let d = dropped(DropReason::Duplicate, None);
        let md = render_dropped(&[d]).join("\n");
        assert!(md.contains("**[DUP (pre-verify)]**"));
    }

    #[test]
    fn chunk_id_and_detail_are_md_cell_escaped() {
        let mut d = dropped(DropReason::Excluded, None);
        d.chunk_id = "c|1".to_string();
        d.detail = "line1\nline2".to_string();
        let md = render_dropped(&[d]).join("\n");
        assert!(md.contains("(c\\|1) — line1 line2"));
    }

    #[test]
    fn file_path_is_md_code_span_escaped_against_backtick_breakout() {
        let mut d = dropped(DropReason::Excluded, None);
        d.file = "foo`) [pwned](javascript:x) (`bar".to_string();
        let md = render_dropped(&[d]).join("\n");
        // Exactly the two delimiter backticks this format! call itself
        // wraps the path in — the attacker's own backticks must both be
        // neutralized, never left free to close the span early.
        let line = md.lines().find(|l| l.starts_with("- **[")).unwrap();
        assert_eq!(line.matches('`').count(), 2);
    }

    #[test]
    fn multiple_dropped_findings_in_list_order() {
        let a = dropped(DropReason::VerifyError, None);
        let b = dropped(DropReason::GuardrailBlocked, None);
        let md = render_dropped(&[a, b]).join("\n");
        let verr_pos = md.find("VERIFY-ERR").unwrap();
        let guard_pos = md.find("GUARDRAIL").unwrap();
        assert!(verr_pos < guard_pos);
    }
}
