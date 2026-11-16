use appsec_model::{AppProfile, ContextPackage, Control, Finding, ThreatModel};
use appsec_repo_analysis::GraphView;

use crate::wire::{
    actor_str, control_kind_str, impact_str, likelihood_str, sensitivity_str, verdict_str,
};

pub const SYSTEM: &str = "You are an exploit development strategist reviewing verified findings
that have ALREADY PASSED adversarial verification by a security expert. Each finding
carries a TRUE_POSITIVE verdict, confidence level, and CVSS vector — use this as
authoritative ground truth. Your job is NOT to re-verify bugs or judge exploitability
directly — it's to assess what an attacker can actually DO with these bugs TOGETHER,
and to rank them by chaining opportunity.

For each finding, reassess only the CHAIN potential given:
- Is it pre-auth or post-auth? (check design controls)
- Can a prior finding (or external source) supply input to this sink?
- Does a prior finding's output become this finding's input?
- What primitive does it give? (read, write, control flow, leak, DoS only)

Then look for CHAINS — combinations more dangerous than any single bug:
- Info leak + ASLR bypass + memory corruption = full chain
- UAF + type confusion = arbitrary write
- Logic flaw bypassing auth + post-auth bug = pre-auth exploit
- New finding + known unpatched CVE = combined attack
- Reachability: Finding #A flows to Finding #B via call-graph if they share
  function neighborhoods or data flow (check the \"reachability\" block per finding).

If a design control genuinely blocks a chain, say so and downrank it.

Rank each finding primarily by its CVSS base score (verifier already validated it):
- CRITICAL (9.0-10.0): likely a standalone problem needing immediate patching
- HIGH (7.0-8.9): serious but may be blocked by pre-auth, sandboxing, or require a chain
- MEDIUM (4.0-6.9): chaining or multi-stage is common; look for it
- LOW (0.1-3.9): useful only in chain or as a stepping stone
- INFO: no standalone or chained exploit path visible

Respond with ONLY a JSON object:
{
  \"summary\": \"Executive summary, 2-4 sentences.\",
  \"ranked_findings\": [
    {
      \"index\": 0,
      \"severity\": \"critical|high|medium|low|info\",
      \"exploitability_notes\": \"Why this severity, what controls apply.\"
    }
  ],
  \"chains\": [
    {
      \"title\": \"UAF -> arb write -> RCE\",
      \"steps\": [2, 0, 5],
      \"severity\": \"high\",
      \"blocked_by_controls\": [\"seccomp-sandbox\"],
      \"narrative\": \"Step-by-step explanation.\"
    }
  ]
}
The 'index' and 'steps' values are 0-based indices into the findings list.";

pub fn topology_prompt_block(ap: &AppProfile) -> String {
    if ap.reaches.is_empty() && ap.reached_by.is_empty() && ap.exposure.is_empty() {
        return String::new();
    }
    let render = |edges: &[appsec_model::Reach]| -> String {
        edges
            .iter()
            .map(|r| {
                let auth = match r.authenticated {
                    Some(true) => ", authenticated",
                    Some(false) => ", UNAUTHENTICATED",
                    None => ", authentication not stated",
                };
                format!(
                    "\u{20}\u{20}\u{20}\u{20}- {} ({}{})\n",
                    r.name, r.kind, auth
                )
            })
            .collect()
    };
    let mut out = String::from("DEPLOYMENT TOPOLOGY:\n");
    if !ap.exposure.is_empty() {
        out.push_str(&format!("\u{20}\u{20}- Reachability: {}\n", ap.exposure));
    }
    if !ap.reached_by.is_empty() {
        out.push_str("\u{20}\u{20}- Reached by:\n");
        out.push_str(&render(&ap.reached_by));
    }
    if !ap.reaches.is_empty() {
        out.push_str("\u{20}\u{20}- Can reach:\n");
        out.push_str(&render(&ap.reaches));
    }
    out.push_str(
        "\u{20}\u{20}- Treat this as operator-stated deployment fact, not as\n\
         \u{20}\u{20}\u{20}\u{20}verified code behavior. It tells you what a chain could\n\
         \u{20}\u{20}\u{20}\u{20}reach if exploited; it does not establish that any control\n\
         \u{20}\u{20}\u{20}\u{20}named here is present or effective.\n",
    );
    out
}

pub fn app_profile_prompt_block(ap: &AppProfile) -> String {
    let mut sens = Vec::new();
    if ap.pci_scoped {
        sens.push("PCI-scoped");
    }
    if ap.processes_pan {
        sens.push("processes PAN");
    }
    if ap.pii {
        sens.push("handles PII");
    }
    format!(
        "CMDB APPLICATION PROFILE:\n\
         \u{20}\u{20}- Application ID: {}\n\
         \u{20}\u{20}- Name: {}\n\
         \u{20}\u{20}- Externally facing: {}\n\
         \u{20}\u{20}- Data sensitivity: {}\n\
         \u{20}\u{20}- Source: {}\n",
        ap.application_id,
        if ap.name.is_empty() {
            "(unnamed)"
        } else {
            &ap.name
        },
        if ap.externally_facing { "YES" } else { "NO" },
        if sens.is_empty() {
            "standard".to_string()
        } else {
            sens.join(", ")
        },
        ap.source
    )
}

pub fn threat_model_prompt_block(tm: &ThreatModel) -> String {
    let mut lines = vec![
        "THREAT MODEL:".to_string(),
        String::new(),
        "System context:".to_string(),
        tm.system_context.clone(),
        String::new(),
    ];

    if !tm.assets.is_empty() {
        lines.push(format!("Assets ({}):", tm.assets.len()));
        for a in &tm.assets {
            lines.push(format!(
                "  - [{}] {} — {}",
                sensitivity_str(a.sensitivity),
                a.name,
                a.description
            ));
        }
        lines.push(String::new());
    }

    if !tm.trust_boundaries.is_empty() {
        lines.push(format!("Trust boundaries ({}):", tm.trust_boundaries.len()));
        for b in &tm.trust_boundaries {
            let ra = if b.reachable_assets.is_empty() {
                "-".to_string()
            } else {
                b.reachable_assets.join(", ")
            };
            lines.push(format!(
                "  - {}: {} → assets: {ra}",
                b.entry_point, b.crossing
            ));
        }
        lines.push(String::new());
    }

    if !tm.threats.is_empty() {
        lines.push(format!("Ranked threats ({}):", tm.threats.len()));
        for t in &tm.threats {
            let controls_suffix = if !t.controls.is_empty() && t.controls != "none" {
                format!(", controls: {}", t.controls)
            } else {
                String::new()
            };
            lines.push(format!(
                "  - {} [{}/{}] {} (actor={}, surface={}, asset={}{controls_suffix})",
                t.id,
                impact_str(t.impact),
                likelihood_str(t.likelihood),
                t.threat,
                actor_str(t.actor),
                t.surface,
                t.asset,
            ));
        }
        lines.push(String::new());
    }

    lines.join("\n")
}

fn ref_part(label: &str, r: Option<&str>, backfilled_refs: &[String], key: &str) -> Option<String> {
    let r = r.filter(|s| !s.is_empty())?;
    let marker = if backfilled_refs.iter().any(|x| x == key) {
        " (inferred from AST, unverified)"
    } else {
        ""
    };
    Some(format!("{label}={r}{marker}"))
}

fn reachability_for_finding(f: &Finding, ctx: &ContextPackage, view: &GraphView) -> String {
    let source_part = ref_part(
        "source",
        f.source_ref.as_deref(),
        &f.backfilled_refs,
        "source_ref",
    );
    let sink_part = ref_part(
        "sink",
        f.sink_ref.as_deref(),
        &f.backfilled_refs,
        "sink_ref",
    );

    if ctx.call_graph.is_empty() {
        let parts: Vec<String> = [source_part, sink_part].into_iter().flatten().collect();
        return if parts.is_empty() {
            "(no graph context)".to_string()
        } else {
            parts.join(" ")
        };
    }

    let cands = appsec_repo_analysis::qnodes_at(
        view,
        &f.file,
        f.line_start.max(1),
        f.line_end.max(f.line_start).max(1),
        6,
        false,
    );

    let mut parts: Vec<String> = [source_part, sink_part].into_iter().flatten().collect();

    if let Some(qn) = cands.first() {
        let callers: Vec<&str> = view
            .rev
            .get(qn)
            .map(|v| v.iter().take(2).map(String::as_str).collect())
            .unwrap_or_default();
        let callees: Vec<&str> = view
            .forward
            .get(qn)
            .map(|v| v.iter().take(2).map(String::as_str).collect())
            .unwrap_or_default();
        let mut reachable = Vec::new();
        if !callers.is_empty() {
            reachable.push(format!("called-by: {}", callers.join(", ")));
        }
        if !callees.is_empty() {
            reachable.push(format!("calls: {}", callees.join(", ")));
        }
        if !reachable.is_empty() {
            parts.push(format!("neighbors={}", reachable.join("; ")));
        }
    }

    if parts.is_empty() {
        "(no reachability data)".to_string()
    } else {
        parts.join(" ")
    }
}

fn component_line(f: &Finding) -> String {
    let Some(c) = f.component.as_ref().filter(|c| !c.is_empty()) else {
        return String::new();
    };
    let mut parts = Vec::new();
    let coordinate = c.coordinate();
    if !coordinate.is_empty() {
        parts.push(coordinate);
    }
    if !c.cves.is_empty() {
        parts.push(c.cves.join(", "));
    }
    match c.direct {
        Some(true) => parts.push("direct".to_string()),
        Some(false) => parts.push("transitive".to_string()),
        None => {}
    }
    if !c.dependency_path.is_empty() {
        parts.push(format!("via {}", c.dependency_path.join(" -> ")));
    }
    if parts.is_empty() {
        return String::new();
    }
    format!("    Dependency: {}\n", parts.join("  |  "))
}

fn findings_block(findings: &[Finding], ctx: &ContextPackage, view: &GraphView) -> String {
    findings
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let cvss = if f.cvss_vector.is_none() { "n/a".to_string() } else { f.cvss_vector.clone().unwrap() };
            let verified = match (f.verdict, f.verdict_confidence) {
                (Some(v), Some(conf)) => format!("{} {conf}/10", verdict_str(v)),
                _ => "unverified".to_string(),
            };
            let reachability = reachability_for_finding(f, ctx, view);
            let component = component_line(f);
            format!(
                "[{i}] {} @ {}:{}-{}\n    Title: {}\n    CVSS: {cvss}  |  Verified: {verified}\n    Confidence: {:.2} ({} runs agreed)\n    {}\n{component}    Reachability: {reachability}\n",
                f.vuln_class.as_str(),
                f.file,
                f.line_start,
                f.line_end,
                f.title,
                f.confidence,
                f.votes,
                f.description,
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn controls_block(controls: &[Control]) -> String {
    if controls.is_empty() {
        return "  (none)".to_string();
    }
    controls
        .iter()
        .map(|c| {
            let protects = if c.protects.is_empty() {
                "global".to_string()
            } else {
                c.protects.join(", ")
            };
            format!(
                "  - [{}] {} -> protects: {protects}",
                control_kind_str(c.kind),
                c.name
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn build_prompt(findings: &[Finding], ctx: &ContextPackage) -> String {
    let mut tm_block = String::new();
    if let Some(ap) = &ctx.app_profile {
        tm_block.push_str(&app_profile_prompt_block(ap));
        tm_block.push_str(&topology_prompt_block(ap));
        tm_block.push('\n');
    }
    if let Some(tm) = &ctx.threat_model {
        tm_block.push_str(&threat_model_prompt_block(tm));
        tm_block.push('\n');
    }

    let mut compliance_block = String::new();
    if !ctx.compliance_guidance.is_empty() {
        compliance_block.push_str("COMPLIANCE GUIDANCE:\n");
        compliance_block.push_str(&ctx.compliance_guidance);
        compliance_block.push_str("\n\n");
    }

    let corroboration_block = appsec_context::corroborate::render(ctx);

    let view = GraphView::new(ctx);

    format!(
        "REPO: {}\n\
\n\
{tm_block}{compliance_block}{corroboration_block}DESIGN CONTROLS:\n\
{}\n\
\n\
FINDINGS (indices are 0-based):\n\
{}\n\
\n\
Analyze and respond with ONLY the JSON object.",
        ctx.repo_root,
        controls_block(&ctx.design_controls),
        findings_block(findings, ctx, &view),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use appsec_model::{ControlKind, VulnClass};

    #[test]
    fn system_prompt_preserves_json_indentation() {
        assert!(SYSTEM.contains("{\n  \"summary\""));
        assert!(SYSTEM.contains("\"ranked_findings\": [\n    {\n      \"index\": 0,"));
        assert!(SYSTEM.contains("\"chains\": [\n    {\n      \"title\":"));
    }

    pub(super) fn minimal_finding() -> Finding {
        Finding {
            provider_origins: Vec::new(),
            component: None,
            chunk_id: "c".to_string(),
            file: "src/mod.c".to_string(),
            line_start: 10,
            line_end: 11,
            vuln_class: VulnClass::Other,
            cwe: None,
            title: "f".to_string(),
            impact: String::new(),
            description: "desc".to_string(),
            exploit_scenario: String::new(),
            preconditions: Vec::new(),
            recommendation: String::new(),
            code_snippet: "x = 1;".to_string(),
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
        }
    }

    pub(super) fn minimal_ctx() -> ContextPackage {
        ContextPackage {
            seed_taint_paths: Default::default(),
            seed_taint_evidence: Default::default(),
            def_spans: Default::default(),
            repo_root: "/repo".to_string(),
            language: "c".to_string(),
            call_graph: Default::default(),
            call_graph_files: Default::default(),
            entry_points: Vec::new(),
            unsafe_sinks: Vec::new(),
            modules: Vec::new(),
            all_files: Vec::new(),
            excluded: Default::default(),
            design_controls: Vec::new(),
            changed_files: Default::default(),
            diff_scope_active: false,
            app_profile: None,
            threat_model: None,
            provider_digest: None,
            notes: String::new(),
            compliance_guidance: String::new(),
        }
    }

    #[test]
    fn system_prompt_carries_the_cvss_band_rubric_and_schema() {
        assert!(SYSTEM.contains("CRITICAL (9.0-10.0)"));
        assert!(SYSTEM.contains("\"ranked_findings\""));
        assert!(SYSTEM.contains("\"chains\""));
    }

    #[test]
    fn system_prompt_reassesses_chain_potential_not_open_rescoring() {
        assert!(SYSTEM.contains("reassess only the CHAIN potential"));
        assert!(SYSTEM.contains("TRUE_POSITIVE verdict"));
    }

    #[test]
    fn app_profile_prompt_block_lists_all_sensitivity_flags() {
        let ap = AppProfile {
            exposure: String::new(),
            reaches: Vec::new(),
            reached_by: Vec::new(),
            application_id: "APP1".to_string(),
            name: "My App".to_string(),
            externally_facing: true,
            pci_scoped: true,
            processes_pan: true,
            pii: true,
            source: "cmdb".to_string(),
        };
        let block = app_profile_prompt_block(&ap);
        assert!(block.contains("Application ID: APP1"));
        assert!(block.contains("PCI-scoped, processes PAN, handles PII"));
    }

    #[test]
    fn app_profile_prompt_block_defaults_when_no_flags_or_name() {
        let ap = AppProfile {
            exposure: String::new(),
            reaches: Vec::new(),
            reached_by: Vec::new(),
            application_id: "APP1".to_string(),
            name: String::new(),
            externally_facing: false,
            pci_scoped: false,
            processes_pan: false,
            pii: false,
            source: "cmdb".to_string(),
        };
        let block = app_profile_prompt_block(&ap);
        assert!(block.contains("Name: (unnamed)"));
        assert!(block.contains("Externally facing: NO"));
        assert!(block.contains("Data sensitivity: standard"));
    }

    #[test]
    fn threat_model_prompt_block_renders_empty_sections_as_nothing() {
        let tm = ThreatModel {
            system_context: "ctx".to_string(),
            ..Default::default()
        };
        let block = threat_model_prompt_block(&tm);
        assert!(block.contains("THREAT MODEL:"));
        assert!(block.contains("System context:\nctx"));
        assert!(!block.contains("Assets ("));
        assert!(!block.contains("Trust boundaries ("));
        assert!(!block.contains("Ranked threats ("));
    }

    #[test]
    fn threat_model_prompt_block_renders_assets_boundaries_and_threats() {
        use appsec_model::{Actor, Asset, Impact, Likelihood, Sensitivity, Threat, TrustBoundary};
        let tm = ThreatModel {
            system_context: "ctx".to_string(),
            assets: vec![Asset {
                name: "DB".to_string(),
                description: "customer data".to_string(),
                sensitivity: Sensitivity::High,
            }],
            trust_boundaries: vec![TrustBoundary {
                entry_point: "api".to_string(),
                crossing: "unauth -> app".to_string(),
                reachable_assets: vec!["DB".to_string()],
            }],
            threats: vec![Threat {
                id: "T1".to_string(),
                threat: "SQLi".to_string(),
                actor: Actor::RemoteUnauth,
                surface: "api".to_string(),
                asset: "DB".to_string(),
                impact: Impact::High,
                likelihood: Likelihood::Likely,
                controls: "none".to_string(),
                evidence: String::new(),
            }],
            ..Default::default()
        };
        let block = threat_model_prompt_block(&tm);
        assert!(block.contains("Assets (1):"));
        assert!(block.contains("  - [high] DB — customer data"));
        assert!(block.contains("Trust boundaries (1):"));
        assert!(block.contains("  - api: unauth -> app → assets: DB"));
        assert!(block.contains("Ranked threats (1):"));
        assert!(block
            .contains("  - T1 [high/likely] SQLi (actor=remote_unauth, surface=api, asset=DB)"));
        assert!(!block.contains("controls:"));
    }

    #[test]
    fn threat_model_prompt_block_shows_controls_when_not_none() {
        use appsec_model::{Actor, Impact, Likelihood, Threat};
        let tm = ThreatModel {
            system_context: "ctx".to_string(),
            threats: vec![Threat {
                id: "T1".to_string(),
                threat: "SQLi".to_string(),
                actor: Actor::RemoteUnauth,
                surface: "api".to_string(),
                asset: "DB".to_string(),
                impact: Impact::High,
                likelihood: Likelihood::Likely,
                controls: "waf".to_string(),
                evidence: String::new(),
            }],
            ..Default::default()
        };
        let block = threat_model_prompt_block(&tm);
        assert!(block.contains(", controls: waf)"));
    }

    #[test]
    fn trust_boundary_with_no_reachable_assets_renders_a_dash() {
        use appsec_model::TrustBoundary;
        let tm = ThreatModel {
            system_context: "ctx".to_string(),
            trust_boundaries: vec![TrustBoundary {
                entry_point: "api".to_string(),
                crossing: "x".to_string(),
                reachable_assets: Vec::new(),
            }],
            ..Default::default()
        };
        let block = threat_model_prompt_block(&tm);
        assert!(block.contains("→ assets: -"));
    }

    #[test]
    fn build_prompt_defaults_when_context_is_empty() {
        let prompt = build_prompt(&[minimal_finding()], &minimal_ctx());
        assert!(prompt.contains("REPO: /repo"));
        assert!(prompt.contains("DESIGN CONTROLS:\n  (none)"));
        assert!(
            !prompt.contains("KNOWN CVEs"),
            "the legacy injected-CVE block is gone: {prompt}"
        );
        assert!(prompt.contains("[0] other @ src/mod.c:10-11"));
        assert!(prompt.contains("Verified: unverified"));
        assert!(prompt.contains("Reachability: (no graph context)"));
    }

    #[test]
    fn system_prompt_includes_the_reachability_bullet() {
        assert!(SYSTEM.contains("check the \"reachability\" block per finding"));
    }

    #[test]
    fn ref_part_none_for_an_absent_ref() {
        assert_eq!(ref_part("source", None, &[], "source_ref"), None);
    }

    #[test]
    fn ref_part_none_for_a_blank_ref() {
        assert_eq!(ref_part("source", Some(""), &[], "source_ref"), None);
    }

    #[test]
    fn ref_part_unmarked_when_not_backfilled() {
        assert_eq!(
            ref_part("source", Some("a.py:1"), &[], "source_ref"),
            Some("source=a.py:1".to_string())
        );
    }

    #[test]
    fn ref_part_marks_a_backfilled_ref() {
        let backfilled = vec!["source_ref".to_string()];
        assert_eq!(
            ref_part("source", Some("a.py:1"), &backfilled, "source_ref"),
            Some("source=a.py:1 (inferred from AST, unverified)".to_string())
        );
    }

    #[test]
    fn reachability_for_finding_no_graph_and_no_refs_is_no_graph_context() {
        let ctx = minimal_ctx();
        let view = GraphView::new(&ctx);
        assert_eq!(
            reachability_for_finding(&minimal_finding(), &ctx, &view),
            "(no graph context)"
        );
    }

    #[test]
    fn reachability_for_finding_no_graph_reports_source_and_sink_refs() {
        let ctx = minimal_ctx();
        let view = GraphView::new(&ctx);
        let mut f = minimal_finding();
        f.source_ref = Some("src/mod.c:1".to_string());
        f.sink_ref = Some("src/mod.c:10".to_string());
        f.backfilled_refs = vec!["sink_ref".to_string()];
        let out = reachability_for_finding(&f, &ctx, &view);
        assert_eq!(
            out,
            "source=src/mod.c:1 sink=src/mod.c:10 (inferred from AST, unverified)"
        );
    }

    #[test]
    fn reachability_for_finding_with_graph_and_no_candidates_or_refs_is_no_reachability_data() {
        let mut ctx = minimal_ctx();
        ctx.call_graph
            .insert("other.c::a".to_string(), vec!["other.c::b".to_string()]);
        let view = GraphView::new(&ctx);
        assert_eq!(
            reachability_for_finding(&minimal_finding(), &ctx, &view),
            "(no reachability data)"
        );
    }

    #[test]
    fn reachability_for_finding_with_graph_reports_neighbors_of_the_best_candidate() {
        let mut ctx = minimal_ctx();
        ctx.call_graph.insert(
            "caller.c::caller_fn".to_string(),
            vec!["src/mod.c::handler".to_string()],
        );
        ctx.call_graph.insert(
            "src/mod.c::handler".to_string(),
            vec!["callee.c::callee_fn".to_string()],
        );
        let view = GraphView::new(&ctx);
        let out = reachability_for_finding(&minimal_finding(), &ctx, &view);
        assert_eq!(
            out,
            "neighbors=called-by: caller.c::caller_fn; calls: callee.c::callee_fn"
        );
    }

    #[test]
    fn reachability_for_finding_with_graph_candidate_with_no_edges_omits_the_neighbors_part() {
        let mut ctx = minimal_ctx();
        ctx.call_graph
            .insert("src/mod.c::handler".to_string(), Vec::new());
        ctx.call_graph
            .insert("other.c::a".to_string(), vec!["other.c::b".to_string()]);
        let view = GraphView::new(&ctx);
        assert_eq!(
            reachability_for_finding(&minimal_finding(), &ctx, &view),
            "(no reachability data)"
        );
    }

    #[test]
    fn findings_block_includes_the_reachability_line() {
        let mut ctx = minimal_ctx();
        ctx.call_graph.insert(
            "src/mod.c::handler".to_string(),
            vec!["callee.c::callee_fn".to_string()],
        );
        let view = GraphView::new(&ctx);
        let out = findings_block(&[minimal_finding()], &ctx, &view);
        assert!(out.contains("Reachability: neighbors=calls: callee.c::callee_fn"));
    }

    #[test]
    fn build_prompt_shows_verified_verdict_and_confidence() {
        use appsec_model::Verdict;
        let mut f = minimal_finding();
        f.verdict = Some(Verdict::TruePositive);
        f.verdict_confidence = Some(9);
        f.cvss_vector = Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string());
        let prompt = build_prompt(&[f], &minimal_ctx());
        assert!(prompt.contains("CVSS: CVSS:3.1/AV:N"));
        assert!(prompt.contains("Verified: TRUE_POSITIVE 9/10"));
    }

    #[test]
    fn build_prompt_shows_design_controls() {
        let mut ctx = minimal_ctx();
        ctx.design_controls = vec![Control {
            name: "WAF".to_string(),
            kind: ControlKind::Auth,
            protects: vec!["app.py".to_string()],
            notes: String::new(),
        }];
        let prompt = build_prompt(&[minimal_finding()], &ctx);
        assert!(prompt.contains("[auth] WAF -> protects: app.py"));
        assert!(
            !prompt.contains("KNOWN CVEs"),
            "the legacy injected-CVE block is gone: {prompt}"
        );
    }

    #[test]
    fn build_prompt_control_with_no_protects_is_global() {
        let mut ctx = minimal_ctx();
        ctx.design_controls = vec![Control {
            name: "Global".to_string(),
            kind: ControlKind::Other,
            protects: Vec::new(),
            notes: String::new(),
        }];
        let prompt = build_prompt(&[minimal_finding()], &ctx);
        assert!(prompt.contains("-> protects: global"));
    }

    #[test]
    fn build_prompt_includes_app_profile_and_threat_model_blocks() {
        let mut ctx = minimal_ctx();
        ctx.app_profile = Some(AppProfile {
            exposure: String::new(),
            reaches: Vec::new(),
            reached_by: Vec::new(),
            application_id: "APP1".to_string(),
            name: "App".to_string(),
            externally_facing: true,
            pci_scoped: false,
            processes_pan: false,
            pii: false,
            source: "cmdb".to_string(),
        });
        ctx.threat_model = Some(ThreatModel {
            system_context: "ctx here".to_string(),
            ..Default::default()
        });
        let prompt = build_prompt(&[minimal_finding()], &ctx);
        assert!(prompt.contains("CMDB APPLICATION PROFILE:"));
        assert!(prompt.contains("THREAT MODEL:"));
    }

    #[test]
    fn build_prompt_includes_compliance_guidance_when_present() {
        let mut ctx = minimal_ctx();
        ctx.compliance_guidance = "Prioritize PCI-DSS Req 6 findings.".to_string();
        let prompt = build_prompt(&[minimal_finding()], &ctx);
        assert!(prompt.contains("COMPLIANCE GUIDANCE:\nPrioritize PCI-DSS Req 6 findings."));
    }

    fn topo_profile(
        exposure: &str,
        reached_by: Vec<appsec_model::Reach>,
        reaches: Vec<appsec_model::Reach>,
    ) -> AppProfile {
        AppProfile {
            application_id: "a".into(),
            name: String::new(),
            externally_facing: false,
            pci_scoped: false,
            processes_pan: false,
            pii: false,
            source: String::new(),
            exposure: exposure.into(),
            reaches,
            reached_by,
        }
    }

    #[test]
    fn topology_block_is_empty_without_topology() {
        let ap = topo_profile("", Vec::new(), Vec::new());
        assert!(topology_prompt_block(&ap).is_empty());
    }

    #[test]
    fn topology_block_states_reachability_and_both_directions() {
        let ap = topo_profile(
            "internet",
            vec![appsec_model::Reach {
                name: "edge-gateway".into(),
                kind: "service".into(),
                authenticated: Some(true),
            }],
            vec![
                appsec_model::Reach {
                    name: "instance-metadata".into(),
                    kind: "metadata".into(),
                    authenticated: Some(false),
                },
                appsec_model::Reach {
                    name: "payments-db".into(),
                    kind: "database".into(),
                    authenticated: None,
                },
            ],
        );
        let b = topology_prompt_block(&ap);
        assert!(b.contains("Reachability: internet"));
        assert!(b.contains("edge-gateway (service, authenticated)"));
        assert!(b.contains("instance-metadata (metadata, UNAUTHENTICATED)"));
        assert!(b.contains("payments-db (database, authentication not stated)"));
        assert!(b.contains("not as\n    verified code behavior"));
    }

    #[test]
    fn topology_block_renders_exposure_alone() {
        let ap = topo_profile("isolated", Vec::new(), Vec::new());
        let b = topology_prompt_block(&ap);
        assert!(b.contains("Reachability: isolated"));
        assert!(!b.contains("Can reach"));
    }

    #[test]
    fn build_prompt_omits_compliance_guidance_when_absent() {
        let prompt = build_prompt(&[minimal_finding()], &minimal_ctx());
        assert!(!prompt.contains("COMPLIANCE GUIDANCE"));
    }

    #[test]
    fn the_prompt_carries_gathered_claims_checked_against_the_code() {
        let mut ctx = minimal_ctx();
        ctx.app_profile = Some(AppProfile {
            application_id: "APP-1".into(),
            name: "payments".into(),
            externally_facing: true,
            pci_scoped: false,
            processes_pan: false,
            pii: false,
            source: "gathered-context".into(),
            exposure: "internet".into(),
            reaches: Vec::new(),
            reached_by: Vec::new(),
        });
        ctx.design_controls.push(appsec_model::Control {
            name: "Edge WAF".into(),
            kind: appsec_model::ControlKind::Auth,
            protects: Vec::new(),
            notes: String::new(),
        });
        ctx.call_graph
            .insert("middleware::require_session".into(), Vec::new());

        let prompt = build_prompt(&[minimal_finding()], &ctx);
        assert!(prompt.contains("CHECKED AGAINST THIS CODE"), "{prompt}");
        assert!(prompt.contains("\"Edge WAF\""), "{prompt}");
        assert!(prompt.contains("require_session"), "{prompt}");
        assert!(
            prompt.contains("NOT evidence the control is absent"),
            "{prompt}"
        );
        let at = prompt.find("CHECKED AGAINST THIS CODE").expect("present");
        let controls = prompt.find("DESIGN CONTROLS:").expect("present");
        assert!(at < controls);
    }

    #[test]
    fn the_prompt_gains_nothing_for_a_profile_that_was_not_gathered() {
        let mut ctx = minimal_ctx();
        ctx.app_profile = Some(AppProfile {
            application_id: "APP-1".into(),
            name: "payments".into(),
            externally_facing: true,
            pci_scoped: false,
            processes_pan: false,
            pii: false,
            source: "cmdb".into(),
            exposure: "internet".into(),
            reaches: Vec::new(),
            reached_by: Vec::new(),
        });
        ctx.design_controls.push(appsec_model::Control {
            name: "Edge WAF".into(),
            kind: appsec_model::ControlKind::Auth,
            protects: Vec::new(),
            notes: String::new(),
        });
        let prompt = build_prompt(&[minimal_finding()], &ctx);
        assert!(!prompt.contains("CHECKED AGAINST THIS CODE"), "{prompt}");
    }
}

#[cfg(test)]
mod component_line_tests {
    use super::*;

    fn dependency_finding() -> Finding {
        let mut f = super::tests::minimal_finding();
        f.component = Some(appsec_model::ComponentRef {
            name: "lodash".to_string(),
            version: "4.17.15".to_string(),
            purl: None,
            cves: vec!["CVE-2020-8203".to_string()],
            fixed_in: vec!["4.17.19".to_string()],
            dependency_path: vec!["app@1.0.0".to_string(), "lodash@4.17.15".to_string()],
            direct: Some(false),
        });
        f
    }

    #[test]
    fn a_code_finding_adds_no_dependency_line() {
        let prompt = build_prompt(
            &[super::tests::minimal_finding()],
            &super::tests::minimal_ctx(),
        );
        assert!(!prompt.contains("Dependency:"), "{prompt}");
    }

    #[test]
    fn a_dependency_finding_reaches_chaining_with_its_path() {
        let prompt = build_prompt(&[dependency_finding()], &super::tests::minimal_ctx());
        assert!(prompt.contains("Dependency: lodash@4.17.15"), "{prompt}");
        assert!(prompt.contains("CVE-2020-8203"), "{prompt}");
        assert!(
            prompt.contains("via app@1.0.0 -> lodash@4.17.15"),
            "the path is what makes a dependency chainable: {prompt}"
        );
        assert!(prompt.contains("transitive"), "{prompt}");
    }

    #[test]
    fn an_empty_component_adds_no_line() {
        let mut f = super::tests::minimal_finding();
        f.component = Some(appsec_model::ComponentRef::default());
        let prompt = build_prompt(&[f], &super::tests::minimal_ctx());
        assert!(!prompt.contains("Dependency:"), "{prompt}");
    }
}

#[cfg(test)]
mod component_line_branch_tests {
    use super::*;

    fn line_for(component: appsec_model::ComponentRef) -> String {
        let mut f = super::tests::minimal_finding();
        f.component = Some(component);
        component_line(&f)
    }

    #[test]
    fn a_bare_cve_with_no_package_still_reaches_chaining() {
        let line = line_for(appsec_model::ComponentRef {
            cves: vec!["CVE-2020-8203".to_string()],
            ..appsec_model::ComponentRef::default()
        });
        assert!(line.contains("CVE-2020-8203"), "{line}");
    }

    #[test]
    fn a_direct_dependency_is_labelled_direct() {
        let line = line_for(appsec_model::ComponentRef {
            name: "lodash".to_string(),
            direct: Some(true),
            ..appsec_model::ComponentRef::default()
        });
        assert!(line.contains("direct"), "{line}");
        assert!(!line.contains("transitive"), "{line}");
    }

    #[test]
    fn an_unknown_depth_is_left_unstated() {
        let line = line_for(appsec_model::ComponentRef {
            name: "lodash".to_string(),
            ..appsec_model::ComponentRef::default()
        });
        assert!(line.contains("lodash"), "{line}");
        assert!(!line.contains("direct"), "{line}");
        assert!(!line.contains("via "), "{line}");
    }

    #[test]
    fn a_component_with_nothing_worth_saying_renders_no_line() {
        let line = line_for(appsec_model::ComponentRef {
            purl: Some("pkg:npm/x@1".to_string()),
            ..appsec_model::ComponentRef::default()
        });
        assert_eq!(
            line, "",
            "a purl alone adds no chaining signal, so it adds no line"
        );
    }
}
