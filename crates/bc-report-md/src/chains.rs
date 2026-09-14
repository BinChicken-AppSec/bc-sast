//! The `## Exploit Chains` section, ported from `models.py::to_markdown`
//! (lines 885-911).

use bc_model::{Chain, RankedFinding};

use crate::sanitize::{demote_md_headings, md_cell};
use crate::wire::severity_upper;

/// `chains` empty + `degraded` renders nothing at all (neither the chain
/// list nor the "no chains" message) — a deliberate `elif`, not an `else`,
/// in the Python source.
pub fn render_chains(chains: &[Chain], findings: &[RankedFinding], degraded: bool) -> Vec<String> {
    let mut out = Vec::new();
    if !chains.is_empty() {
        out.push("## Exploit Chains".to_string());
        out.push(String::new());
        for c in chains {
            // `c.steps` indices are produced by the same pipeline run
            // (S8's chain-analysis stage) that produced `findings` — an
            // out-of-range index is an internal contract violation, so
            // this indexes directly rather than degrading silently,
            // matching the Python source's own `self.findings[idx]`
            // (which likewise raises `IndexError` rather than coping).
            let steps_str: Vec<String> = c
                .steps
                .iter()
                .map(|&idx| {
                    format!(
                        "#{} {}",
                        idx + 1,
                        md_cell(&findings[idx as usize].finding.title)
                    )
                })
                .collect();
            let blocked = if c.blocked_by_controls.is_empty() {
                String::new()
            } else {
                let joined: Vec<String> =
                    c.blocked_by_controls.iter().map(|x| md_cell(x)).collect();
                format!("  \n**Blocked by:** {}", joined.join(", "))
            };
            out.push(format!("### [{}] {}", severity_upper(c.severity), c.title));
            out.push(format!("**Path:** {}{blocked}", steps_str.join(" → ")));
            out.push(String::new());
            out.push(demote_md_headings(&c.narrative));
            out.push(String::new());
        }
    } else if !degraded {
        out.push("## Exploit Chains".to_string());
        out.push(String::new());
        out.push(
            "No exploit chains were identified — the findings above are independent and do not \
             combine into a multi-step path."
                .to_string(),
        );
        out.push(String::new());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_model::{Finding, Severity, VulnClass};

    fn finding(title: &str) -> RankedFinding {
        RankedFinding {
            finding: Finding {
                provider_origins: Vec::new(),
                chunk_id: "c1".to_string(),
                file: "a.py".to_string(),
                line_start: 1,
                line_end: 1,
                vuln_class: VulnClass::Other,
                cwe: None,
                title: title.to_string(),
                impact: String::new(),
                description: "d".to_string(),
                exploit_scenario: String::new(),
                preconditions: Vec::new(),
                recommendation: String::new(),
                code_snippet: "x".to_string(),
                source_ref: None,
                sink_ref: None,
                backfilled_refs: Vec::new(),
                reanchored: Vec::new(),
                compliance_requirements: Vec::new(),
                confidence: 0.5,
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
            },
            severity: Severity::High,
            exploitability_notes: String::new(),
        }
    }

    #[test]
    fn renders_a_chain_path_and_narrative() {
        let findings = vec![finding("UAF"), finding("Arb write")];
        let chains = vec![Chain {
            title: "UAF -> arb write -> code exec".to_string(),
            steps: vec![0, 1],
            severity: Severity::Critical,
            blocked_by_controls: Vec::new(),
            narrative: "step by step".to_string(),
        }];
        let md = render_chains(&chains, &findings, false).join("\n");
        assert!(md.contains("### [CRITICAL] UAF -> arb write -> code exec"));
        assert!(md.contains("**Path:** #1 UAF → #2 Arb write"));
        assert!(md.contains("step by step"));
    }

    #[test]
    fn blocked_by_controls_appended_with_hard_linebreak() {
        let findings = vec![finding("UAF")];
        let chains = vec![Chain {
            title: "t".to_string(),
            steps: vec![0],
            severity: Severity::High,
            blocked_by_controls: vec!["WAF".to_string(), "CSP".to_string()],
            narrative: "n".to_string(),
        }];
        let md = render_chains(&chains, &findings, false).join("\n");
        assert!(md.contains("**Path:** #1 UAF  \n**Blocked by:** WAF, CSP"));
    }

    #[test]
    fn no_blocked_by_controls_omits_the_suffix() {
        let findings = vec![finding("UAF")];
        let chains = vec![Chain {
            title: "t".to_string(),
            steps: vec![0],
            severity: Severity::High,
            blocked_by_controls: Vec::new(),
            narrative: "n".to_string(),
        }];
        let md = render_chains(&chains, &findings, false).join("\n");
        assert!(!md.contains("Blocked by"));
    }

    #[test]
    fn empty_chains_not_degraded_emits_no_chains_message() {
        let md = render_chains(&[], &[], false).join("\n");
        assert!(md.contains("## Exploit Chains"));
        assert!(md.contains("No exploit chains were identified"));
    }

    #[test]
    fn empty_chains_and_degraded_emits_nothing_at_all() {
        let out = render_chains(&[], &[], true);
        assert!(out.is_empty());
    }

    #[test]
    fn chain_title_is_not_escaped() {
        let findings = vec![finding("f")];
        let chains = vec![Chain {
            title: "raw | title".to_string(),
            steps: vec![0],
            severity: Severity::Low,
            blocked_by_controls: Vec::new(),
            narrative: "n".to_string(),
        }];
        let md = render_chains(&chains, &findings, false).join("\n");
        assert!(md.contains("### [LOW] raw | title"));
    }
}
