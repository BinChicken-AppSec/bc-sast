//! The `## Findings (N)` section: one block per `RankedFinding`, ported
//! from `models.py::to_markdown`'s finding loop (lines 801-884).

use bc_model::{offensive_label, Finding, RankedFinding};

use crate::sanitize::{demote_md_headings, md_cell, md_code_span};
use crate::wire;

/// `**9.8** (Critical) — \`CVSS:3.1/...\`` when a score is known; just the
/// backticked vector if only the vector parsed but scoring failed; else
/// the literal `_not computed_`. All three representations (score,
/// rating, vector) are shown together whenever the score is available —
/// none of the three is dropped in favor of another.
fn cvss_display(f: &Finding) -> String {
    if let Some(score) = f.cvss_score {
        format!(
            "**{:.1}** ({}) — `{}`",
            score,
            f.cvss_rating.as_deref().unwrap_or(""),
            f.cvss_vector.as_deref().unwrap_or("")
        )
    } else if let Some(vector) = f.cvss_vector.as_deref().filter(|v| !v.is_empty()) {
        format!("`{vector}`")
    } else {
        "_not computed_".to_string()
    }
}

/// `(label, mitre_number)` — `label` is `"CWE-416: Use After Free"` (or
/// just `"CWE-416"` if the name is unknown), `None` if no CWE resolves at
/// all (explicit token absent AND the vuln class has no fallback, i.e.
/// `VulnClass::Other`). Note the `": "` separator here is deliberately
/// different from `bc_cwe::cwe_label`'s `" - "` — the Python source uses
/// two different separators for this vs. the adjacent `**CWE:**` line,
/// and this port preserves that exact (if inconsistent) formatting.
fn cwe_label_and_number(f: &Finding) -> Option<(String, String)> {
    let cwe = bc_cwe::cwe_for(f.cwe.as_deref(), Some(f.vuln_class.as_str()))?;
    let name = bc_cwe::cwe_name(Some(&cwe));
    let label = if name.is_empty() {
        cwe.clone()
    } else {
        format!("{cwe}: {name}")
    };
    let number = cwe.strip_prefix("CWE-").unwrap_or(&cwe).to_string();
    Some((label, number))
}

fn render_one(out: &mut Vec<String>, i: usize, rf: &RankedFinding) {
    let f = &rf.finding;
    let cwe = cwe_label_and_number(f);
    let class_line = match &cwe {
        Some((label, _)) => label.clone(),
        None => f.vuln_class.as_str().to_string(),
    };

    out.push(format!(
        "### {i}. [{}] {}",
        wire::severity_upper(rf.severity),
        md_cell(&f.title)
    ));
    out.push(format!("**Class:** {class_line}"));
    if let Some((label, number)) = &cwe {
        out.push(format!(
            "**CWE:** {label} - https://cwe.mitre.org/data/definitions/{number}.html"
        ));
    }
    if !f.related_cwes.is_empty() {
        // The other CWE lenses S7 merged into this one (see
        // `bc_dedup_core::collapse_same_range_cwes`). Rendered right under
        // the primary CWE so a reader sees at a glance that one entry
        // stands for several classifications of the same code range,
        // rather than concluding the scanner missed them.
        let labels: Vec<String> = f
            .related_cwes
            .iter()
            .map(|cwe| {
                let name = bc_cwe::cwe_name(Some(cwe));
                if name.is_empty() {
                    md_cell(cwe)
                } else {
                    format!("{} ({})", md_cell(cwe), md_cell(name))
                }
            })
            .collect();
        out.push(format!("**Also flagged as:** {}", labels.join(", ")));
    }
    if !f.compliance_requirements.is_empty() {
        out.push(format!(
            "**Compliance:** {}",
            f.compliance_requirements.join(", ")
        ));
    }
    let file = md_code_span(&f.file);
    out.push(format!(
        "**File:** `{file}:{}-{}`",
        f.line_start, f.line_end
    ));
    out.push(format!("**CVSS 3.1:** {}", cvss_display(f)));
    if let Some(score) = f.vsvs_score {
        out.push(format!(
            "**VulContextSeverity:** `{}` - **{:.1} ({})**",
            f.vsvs_vector.as_deref().unwrap_or(""),
            score,
            f.vsvs_rating.as_deref().unwrap_or("")
        ));
    }
    if let Some(tier) = f.offensive_priority.as_deref().filter(|t| !t.is_empty()) {
        out.push(format!(
            "**OffensivePriority:** **{tier}** - {} | *{}*",
            offensive_label(tier).unwrap_or(""),
            f.offensive_reason
        ));
    }
    let vote_word = if f.votes == 1 { "run" } else { "runs" };
    out.push(format!(
        "**Confidence:** {:.2} ({} {vote_word} agreed)",
        f.confidence, f.votes
    ));
    if !f.duplicates.is_empty() {
        let refs: Vec<String> = f
            .duplicates
            .iter()
            .map(|d| {
                let file = md_code_span(&d.file);
                if d.line_end != 0 && d.line_end != d.line_start {
                    format!("`{file}:{}-{}`", d.line_start, d.line_end)
                } else {
                    format!("`{file}:{}`", d.line_start)
                }
            })
            .collect();
        out.push(format!("**Also at:** {}", refs.join(", ")));
    }
    out.push(String::new());
    if !f.duplicates.is_empty() {
        out.push(format!(
            "*{} additional call site(s) collapsed during dedup — same root cause; \
             each location needs the same fix applied.*",
            f.duplicates.len()
        ));
        out.push(String::new());
    }
    out.push("#### Description".to_string());
    out.push(demote_md_headings(&f.description));
    out.push(String::new());
    if !f.impact.is_empty() {
        out.push("#### Impact".to_string());
        out.push(demote_md_headings(&f.impact));
        out.push(String::new());
    }
    if !f.exploit_scenario.is_empty() {
        out.push("#### Exploit scenario".to_string());
        out.push(demote_md_headings(&f.exploit_scenario));
        out.push(String::new());
    }
    if !f.preconditions.is_empty() {
        out.push("#### Preconditions".to_string());
        out.extend(f.preconditions.iter().map(|p| format!("- {}", md_cell(p))));
        out.push(String::new());
    }
    out.push("```".to_string());
    out.push(f.code_snippet.clone());
    out.push("```".to_string());
    out.push(String::new());
    if !f.recommendation.is_empty() {
        out.push("#### How to fix".to_string());
        out.push(demote_md_headings(&f.recommendation));
        out.push(String::new());
    }
    out.push(format!(
        "**Exploitability:** {}",
        demote_md_headings(&rf.exploitability_notes)
    ));
    out.push(String::new());
    if let Some(verdict) = f.verdict {
        out.push("#### Adversarial verification".to_string());
        out.push(format!(
            "**Verdict:** {} (confidence: {}/10) — {}",
            wire::verdict_str(verdict),
            f.verdict_confidence
                .map(|c| c.to_string())
                .unwrap_or_default(),
            demote_md_headings(&f.verdict_reason)
        ));
        out.push(String::new());
        out.push(demote_md_headings(&f.verifier_reasoning));
        out.push(String::new());
    }
}

pub fn render_findings(findings: &[RankedFinding]) -> Vec<String> {
    let mut out = Vec::new();
    for (i, rf) in findings.iter().enumerate() {
        render_one(&mut out, i + 1, rf);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_model::{DupLocation, Severity, Verdict, VulnClass};

    fn finding(overrides: impl FnOnce(&mut Finding)) -> Finding {
        let mut f = Finding {
            provider_origins: Vec::new(),
            chunk_id: "c1".to_string(),
            file: "app/login.py".to_string(),
            line_start: 42,
            line_end: 48,
            vuln_class: VulnClass::HeapOverflow,
            cwe: None,
            title: "Heap overflow".to_string(),
            impact: String::new(),
            description: "desc".to_string(),
            exploit_scenario: String::new(),
            preconditions: Vec::new(),
            recommendation: String::new(),
            code_snippet: "buf[i] = x".to_string(),
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

    fn ranked(f: Finding) -> RankedFinding {
        RankedFinding {
            finding: f,
            severity: Severity::High,
            exploitability_notes: "n".to_string(),
        }
    }

    #[test]
    fn cvss_score_known_shows_all_three_representations() {
        let f = finding(|f| {
            f.cvss_score = Some(9.8);
            f.cvss_rating = Some("Critical".to_string());
            f.cvss_vector = Some("CVSS:3.1/AV:N".to_string());
        });
        assert_eq!(cvss_display(&f), "**9.8** (Critical) — `CVSS:3.1/AV:N`");
    }

    #[test]
    fn cvss_vector_only_no_score() {
        let f = finding(|f| f.cvss_vector = Some("CVSS:3.1/AV:N".to_string()));
        assert_eq!(cvss_display(&f), "`CVSS:3.1/AV:N`");
    }

    #[test]
    fn cvss_neither_score_nor_vector() {
        let f = finding(|_| {});
        assert_eq!(cvss_display(&f), "_not computed_");
    }

    #[test]
    fn cvss_empty_vector_string_treated_as_absent() {
        let f = finding(|f| f.cvss_vector = Some(String::new()));
        assert_eq!(cvss_display(&f), "_not computed_");
    }

    #[test]
    fn explicit_cwe_token_unknown_to_the_name_table_renders_bare_id() {
        let f = finding(|f| f.cwe = Some("CWE-999999".to_string()));
        let md = render_findings(&[ranked(f)]).join("\n");
        assert!(md.contains("**Class:** CWE-999999"));
        assert!(
            md.contains("**CWE:** CWE-999999 - https://cwe.mitre.org/data/definitions/999999.html")
        );
    }

    #[test]
    fn explicit_cwe_token_wins_over_vuln_class_fallback() {
        let f = finding(|f| {
            f.vuln_class = VulnClass::UseAfterFree;
            f.cwe = Some("CWE-787".to_string());
        });
        let md = render_findings(&[ranked(f)]).join("\n");
        assert!(md.contains("**CWE:** CWE-787"));
        assert!(!md.contains("CWE-416"));
    }

    #[test]
    fn cwe_backfilled_from_vuln_class_when_token_absent() {
        let f = finding(|f| f.vuln_class = VulnClass::UseAfterFree);
        let md = render_findings(&[ranked(f)]).join("\n");
        assert!(md.contains("**CWE:** CWE-416"));
        assert!(md.contains("data/definitions/416.html"));
    }

    #[test]
    fn other_vuln_class_with_no_cwe_renders_no_cwe_line() {
        let f = finding(|f| f.vuln_class = VulnClass::Other);
        let md = render_findings(&[ranked(f)]).join("\n");
        assert!(!md.contains("**CWE:**"));
        assert!(md.contains("**Class:** other"));
    }

    #[test]
    fn compliance_requirements_render_as_a_joined_tag_line() {
        let f = finding(|f| {
            f.compliance_requirements = vec!["6.2.4".to_string(), "ASVS-5.1.3".to_string()]
        });
        let md = render_findings(&[ranked(f)]).join("\n");
        assert!(md.contains("**Compliance:** 6.2.4, ASVS-5.1.3"));
    }

    #[test]
    fn no_compliance_requirements_renders_no_compliance_line() {
        let f = finding(|_| {});
        let md = render_findings(&[ranked(f)]).join("\n");
        assert!(!md.contains("**Compliance:**"));
    }

    #[test]
    fn injected_verifier_heading_is_demoted_not_left_as_a_real_heading() {
        let f = finding(|f| {
            f.verdict = Some(Verdict::TruePositive);
            f.verdict_confidence = Some(8);
            f.verifier_reasoning =
                "## Fake Section\nthe model tried to inject a heading".to_string();
        });
        let md = render_findings(&[ranked(f)]).join("\n");
        assert!(md.contains("**Fake Section**"));
        assert!(!md.contains("## Fake Section"));
        assert!(md.contains("#### Adversarial verification"));
    }

    #[test]
    fn injected_precondition_bullet_is_flattened_to_one_line() {
        let f = finding(|f| f.preconditions = vec!["ok\n## Injected Heading".to_string()]);
        let md = render_findings(&[ranked(f)]).join("\n");
        assert!(!md.lines().any(|l| l.starts_with("## Injected")));
        assert!(md.contains("- ok ## Injected Heading"));
    }

    #[test]
    fn votes_pluralization() {
        let one = finding(|f| f.votes = 1);
        let many = finding(|f| f.votes = 3);
        assert!(render_findings(&[ranked(one)])
            .join("\n")
            .contains("(1 run agreed)"));
        assert!(render_findings(&[ranked(many)])
            .join("\n")
            .contains("(3 runs agreed)"));
    }

    #[test]
    fn duplicates_render_also_at_refs_and_collapsed_note() {
        let f = finding(|f| {
            f.duplicates = vec![
                DupLocation {
                    file: "b.py".to_string(),
                    line_start: 5,
                    line_end: 5,
                    vuln_class: VulnClass::HeapOverflow,
                    title: String::new(),
                    chunk_id: String::new(),
                    source_ref: None,
                    sink_ref: None,
                    reasoning: String::new(),
                },
                DupLocation {
                    file: "c.py".to_string(),
                    line_start: 10,
                    line_end: 20,
                    vuln_class: VulnClass::HeapOverflow,
                    title: String::new(),
                    chunk_id: String::new(),
                    source_ref: None,
                    sink_ref: None,
                    reasoning: String::new(),
                },
            ];
        });
        let md = render_findings(&[ranked(f)]).join("\n");
        assert!(md.contains("**Also at:** `b.py:5`, `c.py:10-20`"));
        assert!(md.contains("*2 additional call site(s) collapsed during dedup"));
    }

    /// The 2026-09-06 Juice Shop field case: one code range in
    /// `routes/continueCode.ts` reported under four CWEs. S7 now merges
    /// them, so the report has to say so or a reader will think the
    /// scanner missed the other three.
    #[test]
    fn merged_cwe_lenses_render_as_an_also_flagged_as_line() {
        let f = finding(|f| {
            f.cwe = Some("CWE-200".to_string());
            f.related_cwes = vec![
                "CWE-345".to_string(),
                "CWE-284".to_string(),
                "CWE-798".to_string(),
            ];
        });
        let md = render_findings(&[ranked(f)]).join("\n");
        assert!(md.contains("**Also flagged as:** CWE-345 ("), "{md}");
        assert!(md.contains("CWE-284 ("), "{md}");
        assert!(md.contains("CWE-798 ("), "{md}");
    }

    #[test]
    fn a_merged_cwe_with_no_known_name_renders_as_the_bare_token() {
        let f = finding(|f| {
            f.cwe = Some("CWE-200".to_string());
            f.related_cwes = vec!["CWE-999999".to_string()];
        });
        let md = render_findings(&[ranked(f)]).join("\n");
        assert!(md.contains("**Also flagged as:** CWE-999999\n"), "{md}");
    }

    #[test]
    fn no_related_cwes_omits_the_also_flagged_as_line() {
        let f = finding(|_| {});
        let md = render_findings(&[ranked(f)]).join("\n");
        assert!(!md.contains("**Also flagged as:**"));
    }

    #[test]
    fn no_duplicates_omits_also_at_and_collapsed_note() {
        let f = finding(|_| {});
        let md = render_findings(&[ranked(f)]).join("\n");
        assert!(!md.contains("**Also at:**"));
        assert!(!md.contains("collapsed during dedup"));
    }

    #[test]
    fn optional_impact_exploit_scenario_preconditions_and_recommendation() {
        let f = finding(|f| {
            f.impact = "big impact".to_string();
            f.exploit_scenario = "do the exploit".to_string();
            f.preconditions = vec!["needs X".to_string()];
            f.recommendation = "fix it".to_string();
        });
        let md = render_findings(&[ranked(f)]).join("\n");
        assert!(md.contains("#### Impact\nbig impact"));
        assert!(md.contains("#### Exploit scenario\ndo the exploit"));
        assert!(md.contains("#### Preconditions\n- needs X"));
        assert!(md.contains("#### How to fix\nfix it"));
    }

    #[test]
    fn absent_optional_sections_are_omitted() {
        let f = finding(|_| {});
        let md = render_findings(&[ranked(f)]).join("\n");
        assert!(!md.contains("#### Impact"));
        assert!(!md.contains("#### Exploit scenario"));
        assert!(!md.contains("#### Preconditions"));
        assert!(!md.contains("#### How to fix"));
        assert!(!md.contains("#### Adversarial verification"));
    }

    #[test]
    fn vsvs_and_offensive_priority_lines_when_present() {
        let f = finding(|f| {
            f.vsvs_score = Some(7.5);
            f.vsvs_vector = Some("CR:H/IR:H".to_string());
            f.vsvs_rating = Some("High".to_string());
            f.offensive_priority = Some("P1".to_string());
            f.offensive_reason = "internet-facing, no auth".to_string();
        });
        let md = render_findings(&[ranked(f)]).join("\n");
        assert!(md.contains("**VulContextSeverity:** `CR:H/IR:H` - **7.5 (High)**"));
        assert!(md.contains(
            "**OffensivePriority:** **P1** - Externally Exploitable, No Auth | *internet-facing, no auth*"
        ));
    }

    #[test]
    fn vsvs_and_offensive_priority_absent_by_default() {
        let f = finding(|_| {});
        let md = render_findings(&[ranked(f)]).join("\n");
        assert!(!md.contains("VulContextSeverity"));
        assert!(!md.contains("OffensivePriority"));
    }

    #[test]
    fn title_is_md_cell_escaped_in_the_heading_line() {
        let f = finding(|f| f.title = "SQLi | in query".to_string());
        let md = render_findings(&[ranked(f)]).join("\n");
        assert!(md.contains("### 1. [HIGH] SQLi \\| in query"));
    }

    #[test]
    fn empty_findings_list_renders_nothing() {
        assert!(render_findings(&[]).is_empty());
    }

    #[test]
    fn multiple_findings_are_numbered_sequentially_in_list_order() {
        let a = finding(|f| f.title = "First".to_string());
        let b = finding(|f| f.title = "Second".to_string());
        let md = render_findings(&[ranked(a), ranked(b)]).join("\n");
        assert!(md.contains("### 1. [HIGH] First"));
        assert!(md.contains("### 2. [HIGH] Second"));
    }
}
