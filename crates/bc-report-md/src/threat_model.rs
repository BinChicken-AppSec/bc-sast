//! The `## Threat Model` section (Application profile / System context /
//! Assets / Trust boundaries / Ranked threats / Open questions), ported
//! from `models.py::_render_threat_model` (lines 938-992). Each
//! subsection independently no-ops when its own data is empty; the
//! caller only invokes this at all when `FinalReport.threat_model` is
//! present.

use bc_model::{AppProfile, ThreatModel};

use crate::sanitize::{demote_md_headings, md_cell, md_code_span};
use crate::wire::{actor_str, impact_str, likelihood_str, sensitivity_str};

fn render_app_profile(out: &mut Vec<String>, ap: &AppProfile) {
    let mut sens_parts = Vec::new();
    if ap.pci_scoped {
        sens_parts.push("PCI-scoped");
    }
    if ap.processes_pan {
        sens_parts.push("processes PAN");
    }
    if ap.pii {
        sens_parts.push("PII");
    }
    let sens = if sens_parts.is_empty() {
        "standard".to_string()
    } else {
        sens_parts.join(", ")
    };
    let name = md_cell(&ap.name);
    out.push("### Application profile (CMDB)".to_string());
    out.push(format!(
        "- ID: `{}`  ({})",
        md_code_span(&ap.application_id),
        if name.is_empty() { "-" } else { &name }
    ));
    out.push(format!(
        "- Externally facing: **{}**",
        if ap.externally_facing { "YES" } else { "NO" }
    ));
    out.push(format!("- Data sensitivity: {sens}"));
    out.push(format!("- Source: {}", md_cell(&ap.source)));
    out.push(String::new());
}

pub fn render_threat_model(tm: &ThreatModel, app_profile: Option<&AppProfile>) -> Vec<String> {
    let mut out = vec!["## Threat Model".to_string(), String::new()];

    if let Some(ap) = app_profile {
        render_app_profile(&mut out, ap);
    }

    if !tm.system_context.is_empty() {
        out.push("### System context".to_string());
        out.push(String::new());
        out.push(demote_md_headings(&tm.system_context));
        out.push(String::new());
    }

    if !tm.assets.is_empty() {
        out.push("### Assets".to_string());
        out.push(String::new());
        out.push("| Asset | Sensitivity | Description |".to_string());
        out.push("|---|---|---|".to_string());
        for a in &tm.assets {
            out.push(format!(
                "| {} | {} | {} |",
                md_cell(&a.name),
                md_cell(sensitivity_str(a.sensitivity)),
                md_cell(&a.description)
            ));
        }
        out.push(String::new());
    }

    if !tm.trust_boundaries.is_empty() {
        out.push("### Trust boundaries".to_string());
        out.push(String::new());
        for b in &tm.trust_boundaries {
            let reachable: Vec<String> = b.reachable_assets.iter().map(|x| md_cell(x)).collect();
            let ra = if reachable.is_empty() {
                "-".to_string()
            } else {
                reachable.join(", ")
            };
            out.push(format!(
                "- **{}** — {} → {ra}",
                md_cell(&b.entry_point),
                md_cell(&b.crossing)
            ));
        }
        out.push(String::new());
    }

    if !tm.threats.is_empty() {
        out.push("### Ranked threats".to_string());
        out.push(String::new());
        out.push(
            "| ID | Threat | Actor | Surface | Asset | Impact | Likelihood | Controls |"
                .to_string(),
        );
        out.push("|---|---|---|---|---|---|---|---|".to_string());
        for t in &tm.threats {
            let controls = md_cell(&t.controls);
            out.push(format!(
                "| {} | {} | {} | {} | {} | {} | {} | {} |",
                md_cell(&t.id),
                md_cell(&t.threat),
                md_cell(actor_str(t.actor)),
                md_cell(&t.surface),
                md_cell(&t.asset),
                md_cell(impact_str(t.impact)),
                md_cell(likelihood_str(t.likelihood)),
                if controls.is_empty() {
                    "-".to_string()
                } else {
                    controls
                }
            ));
        }
        out.push(String::new());
    }

    if !tm.open_questions.is_empty() {
        out.push("### Open questions".to_string());
        out.push(String::new());
        out.extend(
            tm.open_questions
                .iter()
                .map(|q| format!("- {}", md_cell(q))),
        );
        out.push(String::new());
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_model::{Actor, Asset, Impact, Likelihood, Sensitivity, Threat, TrustBoundary};

    fn app_profile() -> AppProfile {
        AppProfile {
            application_id: "APP1".to_string(),
            name: "My App".to_string(),
            externally_facing: true,
            pci_scoped: true,
            processes_pan: false,
            pii: true,
            source: "cmdb".to_string(),
        }
    }

    #[test]
    fn empty_threat_model_renders_only_the_heading() {
        let tm = ThreatModel::default();
        let md = render_threat_model(&tm, None).join("\n");
        assert_eq!(md, "## Threat Model\n");
    }

    #[test]
    fn app_profile_renders_id_name_and_sensitivity_flags() {
        let tm = ThreatModel::default();
        let md = render_threat_model(&tm, Some(&app_profile())).join("\n");
        assert!(md.contains("### Application profile (CMDB)"));
        assert!(md.contains("- ID: `APP1`  (My App)"));
        assert!(md.contains("- Externally facing: **YES**"));
        assert!(md.contains("- Data sensitivity: PCI-scoped, PII"));
        assert!(md.contains("- Source: cmdb"));
    }

    #[test]
    fn app_profile_no_sensitivity_flags_is_standard() {
        let mut ap = app_profile();
        ap.pci_scoped = false;
        ap.pii = false;
        let tm = ThreatModel::default();
        let md = render_threat_model(&tm, Some(&ap)).join("\n");
        assert!(md.contains("- Data sensitivity: standard"));
    }

    #[test]
    fn app_profile_processes_pan_flag_is_included() {
        let mut ap = app_profile();
        ap.pci_scoped = false;
        ap.pii = false;
        ap.processes_pan = true;
        let tm = ThreatModel::default();
        let md = render_threat_model(&tm, Some(&ap)).join("\n");
        assert!(md.contains("- Data sensitivity: processes PAN"));
    }

    #[test]
    fn app_profile_empty_name_renders_dash() {
        let mut ap = app_profile();
        ap.name = String::new();
        let tm = ThreatModel::default();
        let md = render_threat_model(&tm, Some(&ap)).join("\n");
        assert!(md.contains("- ID: `APP1`  (-)"));
    }

    #[test]
    fn app_profile_not_externally_facing() {
        let mut ap = app_profile();
        ap.externally_facing = false;
        let tm = ThreatModel::default();
        let md = render_threat_model(&tm, Some(&ap)).join("\n");
        assert!(md.contains("Externally facing: **NO**"));
    }

    #[test]
    fn injected_cmdb_fields_are_neutralized_but_content_preserved() {
        let mut ap = app_profile();
        ap.application_id = "APP1\n## Pwned ID".to_string();
        ap.name = "evil\n## Pwned Name\n[click](http://evil)".to_string();
        ap.source = "src\n## Pwned Source".to_string();
        let tm = ThreatModel::default();
        let md = render_threat_model(&tm, Some(&ap)).join("\n");
        assert!(md.contains("### Application profile (CMDB)"));
        assert!(!md.lines().any(|l| l.trim_start().starts_with("## Pwned")));
        assert!(!md.lines().any(|l| l.trim() == "[click](http://evil)"));
        assert!(md.contains("Pwned Name"));
    }

    #[test]
    fn application_id_backtick_cannot_break_out_of_its_code_span() {
        let mut ap = app_profile();
        ap.application_id = "APP1`) [pwned](javascript:x) (`END".to_string();
        let tm = ThreatModel::default();
        let md = render_threat_model(&tm, Some(&ap)).join("\n");
        let line = md.lines().find(|l| l.starts_with("- ID:")).unwrap();
        assert_eq!(line.matches('`').count(), 2);
    }

    #[test]
    fn system_context_is_demoted() {
        let tm = ThreatModel {
            system_context: "## Fake\nreal context".to_string(),
            ..Default::default()
        };
        let md = render_threat_model(&tm, None).join("\n");
        assert!(md.contains("### System context"));
        assert!(md.contains("**Fake**\nreal context"));
    }

    #[test]
    fn assets_table_renders_one_row_per_asset() {
        let tm = ThreatModel {
            assets: vec![
                Asset {
                    name: "DB".to_string(),
                    description: "primary store".to_string(),
                    sensitivity: Sensitivity::Critical,
                },
                Asset {
                    name: "Cache".to_string(),
                    description: "".to_string(),
                    sensitivity: Sensitivity::Low,
                },
            ],
            ..Default::default()
        };
        let md = render_threat_model(&tm, None).join("\n");
        assert!(md.contains("| Asset | Sensitivity | Description |"));
        assert!(md.contains("| DB | critical | primary store |"));
        assert!(md.contains("| Cache | low |  |"));
    }

    #[test]
    fn trust_boundaries_render_reachable_assets_or_dash() {
        let tm = ThreatModel {
            trust_boundaries: vec![
                TrustBoundary {
                    entry_point: "API".to_string(),
                    crossing: "internet->dmz".to_string(),
                    reachable_assets: vec!["DB".to_string(), "Cache".to_string()],
                },
                TrustBoundary {
                    entry_point: "Internal".to_string(),
                    crossing: "x".to_string(),
                    reachable_assets: Vec::new(),
                },
            ],
            ..Default::default()
        };
        let md = render_threat_model(&tm, None).join("\n");
        assert!(md.contains("- **API** — internet->dmz → DB, Cache"));
        assert!(md.contains("- **Internal** — x → -"));
    }

    #[test]
    fn ranked_threats_table_renders_wire_strings_for_enums() {
        let tm = ThreatModel {
            threats: vec![Threat {
                id: "T1".to_string(),
                threat: "SSRF".to_string(),
                actor: Actor::RemoteUnauth,
                surface: "webhook".to_string(),
                asset: "internal API".to_string(),
                impact: Impact::High,
                likelihood: Likelihood::Likely,
                controls: String::new(),
                evidence: String::new(),
            }],
            ..Default::default()
        };
        let md = render_threat_model(&tm, None).join("\n");
        assert!(md.contains(
            "| T1 | SSRF | remote_unauth | webhook | internal API | high | likely | - |"
        ));
    }

    #[test]
    fn ranked_threats_controls_present_is_not_dash() {
        let tm = ThreatModel {
            threats: vec![Threat {
                id: "T1".to_string(),
                threat: "t".to_string(),
                actor: Actor::Insider,
                surface: "s".to_string(),
                asset: "a".to_string(),
                impact: Impact::Low,
                likelihood: Likelihood::Rare,
                controls: "MFA".to_string(),
                evidence: String::new(),
            }],
            ..Default::default()
        };
        let md = render_threat_model(&tm, None).join("\n");
        assert!(md.ends_with("| MFA |\n"));
    }

    #[test]
    fn open_questions_render_as_bullets() {
        let tm = ThreatModel {
            open_questions: vec!["is X in scope?".to_string()],
            ..Default::default()
        };
        let md = render_threat_model(&tm, None).join("\n");
        assert!(md.contains("### Open questions"));
        assert!(md.contains("- is X in scope?"));
    }
}
