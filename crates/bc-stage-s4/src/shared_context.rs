// Portions of this file are transcribed from vvaharness, Visa's agentic
// SAST harness: Copyright 2026 Visa, Inc., licensed under the Apache
// License, Version 2.0. Reimplemented in Rust and modified; see the module
// documentation below, and NOTICE for the full attribution.
//! The scan-scoped context block every deep-dive call shares, ported from
//! upstream v1.4.0 `s4_deepdive.py::_build_shared_context_block` and
//! `ThreatModel.to_compact_prompt_block`.
//!
//! It is a pure function of the [`ContextPackage`], which is the same for
//! every chunk of a scan, so it renders byte-identical for all of them.
//! That is the whole point: it rides at the front of each call as
//! [`bc_llm_client::ChatRequest::cache_prefix`], so after the first call a
//! provider prompt cache can read it back instead of billing it again. Any
//! per-chunk byte here (a chunk id, a timestamp, a `HashMap` iteration
//! order) would silently turn every call into a cache miss, so every list
//! is rendered in a fixed order and capped.
//!
//! The block supersedes [`crate::prompts::trust_context_block`] in the
//! open-ended deep-dive prompt: it carries every fact that block rendered
//! (exposure, data sensitivity, the system context, the untrusted entry
//! points and the trust rule) plus the ranked threats and the entry-point
//! inventory.

use bc_model::{AppProfile, ContextPackage, EntryPoint, ThreatModel};

use crate::wire::{actor_str, ep_kind_str, impact_str, likelihood_str, sensitivity_str};

/// Character cap on the threat model's system context (upstream
/// `_SHARED_CTX_MAX_SYSTEM_CHARS`).
pub const MAX_SYSTEM_CONTEXT_CHARS: usize = 4000;
/// Ranked threats rendered (upstream `_SHARED_CTX_MAX_THREATS`).
pub const MAX_THREATS: usize = 25;
/// Trust boundaries rendered (upstream `_SHARED_CTX_MAX_BOUNDARIES`).
pub const MAX_BOUNDARIES: usize = 15;
/// Assets rendered (upstream `_SHARED_CTX_MAX_ASSETS`).
pub const MAX_ASSETS: usize = 10;
/// Entry points listed in the inventory (upstream `_SHARED_CTX_MAX_EPS`).
pub const MAX_ENTRY_POINTS: usize = 60;

/// Verbatim from upstream; always present, so the block is never empty.
const TRUST_RULE: &str = "TRUST RULE: Operator argv/env on the operator's OWN host is TRUSTED.\n\
CI job parameters, scheduler args, shared config/CSV/test-data files editable by other \
principals, and framework-overridable variables ARE attack surface even on an internal app \
— report those (typically LOW). See OUT-OF-SCOPE rule A.";

/// The scan-constant context block: CMDB application profile, compact
/// threat model, entry-point inventory and the trust rule, joined by
/// blank lines. Identical for every chunk of a scan.
pub fn shared_context_block(ctx: &ContextPackage) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(ap) = &ctx.app_profile {
        parts.push(app_profile_prompt_block(ap));
    }
    if let Some(tm) = &ctx.threat_model {
        parts.push(threat_model_compact_block(tm));
    }
    if !ctx.entry_points.is_empty() {
        parts.push(entry_point_inventory(&ctx.entry_points));
    }
    parts.push(TRUST_RULE.to_string());
    parts.join("\n\n")
}

/// Ported from `AppProfile.to_prompt_block()`. A byte-identical copy of
/// the renderer `bc-stage-s2`, `bc-stage-s3` and `bc-stage-s8` each keep
/// in their own `prompts.rs` (see `bc_stage_s2::prompts::
/// app_profile_prompt_block` for why it is duplicated rather than
/// shared); keep every copy identical if one changes.
fn app_profile_prompt_block(ap: &AppProfile) -> String {
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

/// Ported from `ThreatModel.to_compact_prompt_block` at the shared-block
/// caps above. Every section shows `shown/total` and a `…(truncated)`
/// marker when clipped, so the model knows the list is partial.
fn threat_model_compact_block(tm: &ThreatModel) -> String {
    let context: String = tm
        .system_context
        .chars()
        .take(MAX_SYSTEM_CONTEXT_CHARS)
        .collect();
    let mut lines = vec![
        "THREAT MODEL:".to_string(),
        String::new(),
        "System context:".to_string(),
        context,
        String::new(),
    ];

    if !tm.assets.is_empty() {
        let assets: Vec<_> = tm.assets.iter().take(MAX_ASSETS).collect();
        lines.push(format!("Assets ({}/{}):", assets.len(), tm.assets.len()));
        for a in &assets {
            lines.push(format!(
                "  - [{}] {} — {}",
                sensitivity_str(a.sensitivity),
                a.name,
                a.description
            ));
        }
        push_truncated_marker(&mut lines, tm.assets.len(), assets.len());
    }

    if !tm.trust_boundaries.is_empty() {
        let bounds: Vec<_> = tm.trust_boundaries.iter().take(MAX_BOUNDARIES).collect();
        lines.push(format!(
            "Trust boundaries ({}/{}):",
            bounds.len(),
            tm.trust_boundaries.len()
        ));
        for b in &bounds {
            let reachable = if b.reachable_assets.is_empty() {
                "-".to_string()
            } else {
                b.reachable_assets.join(", ")
            };
            lines.push(format!(
                "  - {}: {} → assets: {reachable}",
                b.entry_point, b.crossing
            ));
        }
        push_truncated_marker(&mut lines, tm.trust_boundaries.len(), bounds.len());
    }

    if !tm.threats.is_empty() {
        let threats: Vec<_> = tm.threats.iter().take(MAX_THREATS).collect();
        lines.push(format!(
            "Ranked threats ({}/{}):",
            threats.len(),
            tm.threats.len()
        ));
        for t in &threats {
            let controls = if !t.controls.is_empty() && t.controls != "none" {
                format!(", controls: {}", t.controls)
            } else {
                String::new()
            };
            lines.push(format!(
                "  - {} [{}/{}] {} (actor={}, surface={}, asset={}{controls})",
                t.id,
                impact_str(t.impact),
                likelihood_str(t.likelihood),
                t.threat,
                actor_str(t.actor),
                t.surface,
                t.asset,
            ));
        }
        push_truncated_marker(&mut lines, tm.threats.len(), threats.len());
    }

    lines.join("\n")
}

/// The `…(truncated)` line (when `shown < total`) and the blank line that
/// closes every threat-model section.
fn push_truncated_marker(lines: &mut Vec<String>, total: usize, shown: usize) {
    if total > shown {
        lines.push("  …(truncated)".to_string());
    }
    lines.push(String::new());
}

/// Sorted by `(file, function)` so the inventory is byte-identical on
/// every call, whatever order S1 discovered the entry points in. The sort
/// is stable, so two entries sharing both keys keep their `ctx` order,
/// which is itself fixed for the whole scan.
fn entry_point_inventory(entry_points: &[EntryPoint]) -> String {
    let mut sorted: Vec<&EntryPoint> = entry_points.iter().collect();
    sorted.sort_by(|a, b| (&a.file, &a.function).cmp(&(&b.file, &b.function)));
    sorted.truncate(MAX_ENTRY_POINTS);
    let mut lines = vec![format!(
        "ENTRY POINT INVENTORY ({}/{} total):",
        sorted.len(),
        entry_points.len()
    )];
    for ep in &sorted {
        let auth = if ep.reachable_from_unauth {
            "[unauth]"
        } else {
            "[auth]"
        };
        lines.push(format!(
            "  {auth} [{}] {}::{}",
            ep_kind_str(ep.kind),
            ep.file,
            ep.function
        ));
    }
    if entry_points.len() > MAX_ENTRY_POINTS {
        lines.push(format!(
            "  …({} more omitted)",
            entry_points.len() - MAX_ENTRY_POINTS
        ));
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_model::{
        Actor, Asset, EntryPointKind, Impact, Likelihood, Sensitivity, Threat, TrustBoundary,
    };

    fn ep(file: &str, function: &str, unauth: bool) -> EntryPoint {
        EntryPoint {
            file: file.to_string(),
            function: function.to_string(),
            kind: EntryPointKind::Network,
            reachable_from_unauth: unauth,
        }
    }

    fn threat(id: &str, controls: &str) -> Threat {
        Threat {
            id: id.to_string(),
            threat: format!("threat {id}"),
            actor: Actor::RemoteUnauth,
            surface: "api".to_string(),
            asset: "db".to_string(),
            impact: Impact::High,
            likelihood: Likelihood::Likely,
            controls: controls.to_string(),
            evidence: String::new(),
        }
    }

    fn asset(name: &str) -> Asset {
        Asset {
            name: name.to_string(),
            description: format!("{name} desc"),
            sensitivity: Sensitivity::Critical,
        }
    }

    fn boundary(entry: &str, reachable: &[&str]) -> TrustBoundary {
        TrustBoundary {
            entry_point: entry.to_string(),
            crossing: "internet → app".to_string(),
            reachable_assets: reachable.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn profile() -> AppProfile {
        AppProfile {
            application_id: "APP-1".to_string(),
            name: String::new(),
            externally_facing: true,
            pci_scoped: true,
            processes_pan: true,
            pii: true,
            source: "application".to_string(),
        }
    }

    fn full_ctx() -> ContextPackage {
        ContextPackage {
            app_profile: Some(profile()),
            threat_model: Some(ThreatModel {
                system_context: "A payments API.".to_string(),
                assets: vec![asset("cards")],
                trust_boundaries: vec![boundary("POST /pay", &["cards"]), boundary("GET /", &[])],
                threats: vec![threat("T1", "waf"), threat("T2", "none"), threat("T3", "")],
                open_questions: Vec::new(),
            }),
            entry_points: vec![ep("b.py", "handler", true), ep("a.py", "zeta", false)],
            ..Default::default()
        }
    }

    #[test]
    fn an_empty_context_renders_the_trust_rule_alone() {
        assert_eq!(shared_context_block(&ContextPackage::default()), TRUST_RULE);
    }

    #[test]
    fn a_full_context_renders_every_section_in_upstream_order() {
        let block = shared_context_block(&full_ctx());
        let expected = [
            "CMDB APPLICATION PROFILE:",
            "  - Application ID: APP-1",
            "  - Name: (unnamed)",
            "  - Externally facing: YES",
            "  - Data sensitivity: PCI-scoped, processes PAN, handles PII",
            "  - Source: application",
            "",
            "",
            "THREAT MODEL:",
            "",
            "System context:",
            "A payments API.",
            "",
            "Assets (1/1):",
            "  - [critical] cards — cards desc",
            "",
            "Trust boundaries (2/2):",
            "  - POST /pay: internet → app → assets: cards",
            "  - GET /: internet → app → assets: -",
            "",
            "Ranked threats (3/3):",
            "  - T1 [high/likely] threat T1 (actor=remote_unauth, surface=api, asset=db, controls: waf)",
            "  - T2 [high/likely] threat T2 (actor=remote_unauth, surface=api, asset=db)",
            "  - T3 [high/likely] threat T3 (actor=remote_unauth, surface=api, asset=db)",
            "",
            "",
            "ENTRY POINT INVENTORY (2/2 total):",
            "  [auth] [network] a.py::zeta",
            "  [unauth] [network] b.py::handler",
            "",
            TRUST_RULE,
        ]
        .join("\n");
        assert_eq!(block, expected);
    }

    #[test]
    fn an_internal_profile_with_no_sensitive_data_reads_standard() {
        let ap = AppProfile {
            name: "Ledger".to_string(),
            externally_facing: false,
            pci_scoped: false,
            processes_pan: false,
            pii: false,
            ..profile()
        };
        let block = app_profile_prompt_block(&ap);
        assert!(block.contains("  - Name: Ledger\n"));
        assert!(block.contains("  - Externally facing: NO\n"));
        assert!(block.contains("  - Data sensitivity: standard\n"));
    }

    #[test]
    fn the_block_is_byte_identical_whatever_order_entry_points_arrive_in() {
        let mut a = full_ctx();
        let mut b = full_ctx();
        b.entry_points.reverse();
        assert_eq!(shared_context_block(&a), shared_context_block(&b));
        // And repeatable: two renders of one context never differ.
        a.entry_points.push(ep("c.py", "x", false));
        assert_eq!(shared_context_block(&a), shared_context_block(&a));
    }

    #[test]
    fn the_inventory_sorts_by_file_then_function_and_caps_with_an_omitted_line() {
        let eps: Vec<EntryPoint> = (0..MAX_ENTRY_POINTS + 5)
            .rev()
            .map(|i| ep(&format!("f{i:03}.py"), "h", false))
            .collect();
        let inv = entry_point_inventory(&eps);
        let lines: Vec<&str> = inv.lines().collect();
        assert_eq!(lines[0], "ENTRY POINT INVENTORY (60/65 total):");
        assert_eq!(lines[1], "  [auth] [network] f000.py::h");
        assert_eq!(lines[60], "  [auth] [network] f059.py::h");
        assert_eq!(lines[61], "  …(5 more omitted)");
        assert_eq!(lines.len(), 62);
        // Same file: ordered by function name.
        let inv = entry_point_inventory(&[ep("a.py", "b", false), ep("a.py", "a", false)]);
        assert!(inv.find("a.py::a").unwrap() < inv.find("a.py::b").unwrap());
    }

    #[test]
    fn every_threat_model_section_is_capped_and_marked_truncated() {
        let tm = ThreatModel {
            system_context: "x".repeat(MAX_SYSTEM_CONTEXT_CHARS + 50),
            assets: (0..MAX_ASSETS + 1)
                .map(|i| asset(&format!("a{i}")))
                .collect(),
            trust_boundaries: (0..MAX_BOUNDARIES + 2)
                .map(|i| boundary(&format!("b{i}"), &[]))
                .collect(),
            threats: (0..MAX_THREATS + 3)
                .map(|i| threat(&format!("T{i}"), ""))
                .collect(),
            open_questions: Vec::new(),
        };
        let block = threat_model_compact_block(&tm);
        assert!(block.contains(&format!("\n{}\n", "x".repeat(MAX_SYSTEM_CONTEXT_CHARS))));
        assert!(!block.contains(&"x".repeat(MAX_SYSTEM_CONTEXT_CHARS + 1)));
        assert!(block.contains("Assets (10/11):"));
        assert!(block.contains("Trust boundaries (15/17):"));
        assert!(block.contains("Ranked threats (25/28):"));
        assert_eq!(block.matches("  …(truncated)").count(), 3);
        assert!(block.contains("] a9 — "));
        assert!(!block.contains("] a10 — "));
        assert!(block.contains("  - T24 "));
        assert!(!block.contains("  - T25 "));
    }

    #[test]
    fn the_system_context_cap_counts_characters_not_bytes() {
        let tm = ThreatModel {
            system_context: "é".repeat(MAX_SYSTEM_CONTEXT_CHARS + 1),
            ..Default::default()
        };
        let block = threat_model_compact_block(&tm);
        assert_eq!(block.matches('é').count(), MAX_SYSTEM_CONTEXT_CHARS);
    }

    #[test]
    fn an_empty_threat_model_renders_only_the_header_and_context() {
        let block = threat_model_compact_block(&ThreatModel::default());
        assert_eq!(block, "THREAT MODEL:\n\nSystem context:\n\n");
    }
}
