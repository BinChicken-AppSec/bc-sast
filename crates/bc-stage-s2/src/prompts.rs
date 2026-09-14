// Portions of this file are transcribed from vvaharness, Visa's agentic
// SAST harness: Copyright 2026 Visa, Inc., licensed under the Apache
// License, Version 2.0. Reimplemented in Rust and modified; see the module
// documentation below, and NOTICE for the full attribution.
//! S2's system/user prompts, ported verbatim from
//! `s2_threatmodel.py`'s `SYSTEM` constant and `_build_user_prompt`.

use bc_model::{AppProfile, Control, Cve};

use crate::evidence::{stride_for_kind, Evidence};

pub const SYSTEM: &str = "\
You are an application-security threat modeler. You receive a STRUCTURAL
snapshot of a codebase — docs, manifests, the component list, the
agentically-mapped MODULES (purpose-tagged) and ENTRY POINTS (kind +
auth-reachability), representative CONFIG files, and API-contract artefacts —
NOT the source code bodies. From this you produce a threat model: what the
system IS, what it PROTECTS, where untrusted input ENTERS, and what an
attacker would TRY.

A threat survives a patch. \"Heap overflow in parser.c:412\" is a vulnerability;
\"RCE via untrusted media parsing\" is a threat. You produce threats.

Work through these stages:

1. SYSTEM CONTEXT — from docs/manifests/tree: what is this application, what
   does it do, who runs it, where (service / CLI / library / batch job)?

2. ASSETS — what does it protect or produce? Data (PII, payment data, secrets,
   credentials), process integrity, service availability, downstream consumers.
   Assign sensitivity: low|medium|high|critical.

3. TRUST BOUNDARIES — every place untrusted input enters or privilege changes.
   Derive from manifests, framework hints in the tree, and docs. Include
   supply-chain and infra/IAM surfaces. Name the crossing
   (\"unauth network → application logic\", \"tenant A → shared DB\").

4. THREATS — for EACH trust boundary, walk STRIDE (Spoofing, Tampering,
   Repudiation, Info-disclosure, DoS, Elevation) and emit the plausible ones.
   Use prior CVEs as EVIDENCE that raises likelihood; design controls LOWER it.
   Score impact (low|medium|high|critical|existential) and likelihood
   (very_rare|rare|possible|likely|almost_certain). Sort by (impact,likelihood)
   descending and assign ids T1, T2, …

5. OPEN QUESTIONS — things the snapshot can't tell you (deployment exposure,
   upstream WAF, who supplies inputs, risk appetite).

Respond with ONLY a JSON object — no prose, no markdown fences:
{
  \"system_context\": \"1-3 paragraphs\",
  \"assets\": [{\"name\":\"str\",\"description\":\"str\",\"sensitivity\":\"low|medium|high|critical\"}],
  \"trust_boundaries\": [{\"entry_point\":\"str\",\"crossing\":\"str\",\"reachable_assets\":[\"asset name\"]}],
  \"threats\": [{\"id\":\"T1\",\"threat\":\"one sentence, names the outcome\",
               \"actor\":\"remote_unauth|remote_auth|adjacent_network|local_user|local_admin|supply_chain|insider\",
               \"surface\":\"entry_point name from trust_boundaries\",
               \"asset\":\"asset name\",
               \"impact\":\"low|medium|high|critical|existential\",
               \"likelihood\":\"very_rare|rare|possible|likely|almost_certain\",
               \"controls\":\"current mitigations or 'none'\",
               \"evidence\":\"CVE ids / commit hashes or ''\"}],
  \"open_questions\": [\"str\"]
}

Coverage rule: every trust_boundary MUST appear as the surface of ≥1 threat.";

/// Ported from `AppProfile.to_prompt_block()` — kept as a free function
/// here (not on `bc_model::AppProfile`) matching this project's
/// convention of keeping prompt/render formatting out of the DTO crate.
///
/// Deliberately duplicated byte-for-byte in `bc-stage-s3`/`bc-stage-s8`'s
/// own `prompts.rs` rather than factored into a shared crate: it's a
/// short, stable, data-driven renderer with no natural existing home —
/// `bc-prompts` is deliberately scoped to `&'static str` constants ported
/// from Python's `util/prompts.py` (see that crate's doc comment) for
/// prompt-cache stability, not per-call dynamic rendering, and `bc-model`
/// excludes rendering by the same DTO-crate convention cited above. Keep
/// all three copies byte-identical if either changes.
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

#[allow(clippy::too_many_arguments)]
pub fn build_user_prompt(
    repo_root: &str,
    repo_name: &str,
    ev: &Evidence,
    cves: &[Cve],
    controls: &[Control],
    app_profile: Option<&AppProfile>,
    baseline_block: &str,
) -> String {
    let lang_block = if ev.languages.is_empty() {
        "  (none detected)".to_string()
    } else {
        ev.languages
            .iter()
            .map(|(lang, n)| format!("  - {lang}: {n} files"))
            .collect::<Vec<_>>()
            .join("\n")
    };

    let comp_block = if ev.top_dirs.is_empty() {
        "  (flat repo)".to_string()
    } else {
        ev.top_dirs
            .iter()
            .map(|d| format!("  - {d}/"))
            .collect::<Vec<_>>()
            .join("\n")
    };

    let mut mod_block = if ev.modules.is_empty() {
        "  (s1 emitted no modules)".to_string()
    } else {
        ev.modules
            .iter()
            .map(|(name, purpose, loc)| format!("  - {name}  ({loc} LOC) — {purpose}"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    if ev.modules_truncated {
        mod_block.push_str("\n  …(truncated)");
    }

    let mut ep_block = if ev.entry_points.is_empty() {
        "  (s1 emitted no entry points)".to_string()
    } else {
        ev.entry_points
            .iter()
            .map(|(kind, unauth, file, func)| {
                format!(
                    "  - [{kind:<14}] {}  STRIDE:{}  {file}::{func}",
                    if *unauth { "UNAUTH" } else { "auth  " },
                    stride_for_kind(kind)
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    if ev.entry_points_truncated {
        ep_block.push_str("\n  …(truncated)");
    }

    let site_block = if ev.function_sites.is_empty() {
        "  (none)".to_string()
    } else {
        ev.function_sites
            .iter()
            .map(|(fn_name, sites, span_txt)| {
                format!("  - {fn_name} @ {}{span_txt}", sites.join(", "))
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    let edge_block = if ev.call_edges.is_empty() {
        "  (none)".to_string()
    } else {
        ev.call_edges
            .iter()
            .map(|(caller, callee)| format!("  - {caller} -> {callee}"))
            .collect::<Vec<_>>()
            .join("\n")
    };

    let cfg_block = if ev.config_reps.is_empty() {
        "  (none)".to_string()
    } else {
        ev.config_reps
            .iter()
            .map(|p| format!("  - {p}"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let api_block = if ev.api_artefacts.is_empty() {
        "  (none)".to_string()
    } else {
        ev.api_artefacts
            .iter()
            .map(|p| format!("  - {p}"))
            .collect::<Vec<_>>()
            .join("\n")
    };

    let docs_block = if ev.docs.is_empty() {
        "(no README / SECURITY / ARCHITECTURE docs found)".to_string()
    } else {
        ev.docs
            .iter()
            .map(|(name, body)| format!("=== {name} ===\n{body}"))
            .collect::<Vec<_>>()
            .join("\n\n")
    };
    let manifest_block = if ev.manifests.is_empty() {
        "(no build/dependency manifests found)".to_string()
    } else {
        ev.manifests
            .iter()
            .map(|(name, body)| format!("=== {name} ===\n{body}"))
            .collect::<Vec<_>>()
            .join("\n\n")
    };
    let cve_block = if cves.is_empty() {
        "  (none on file)".to_string()
    } else {
        cves.iter()
            .map(|c| {
                format!(
                    "  - {} (CVSS {}, {}): {}",
                    c.id,
                    c.cvss
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "None".to_string()),
                    if c.patched { "patched" } else { "UNPATCHED" },
                    c.summary
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    let ctl_block = if controls.is_empty() {
        "  (none on file)".to_string()
    } else {
        controls
            .iter()
            .map(|c| {
                let prot = if c.protects.is_empty() {
                    "global".to_string()
                } else {
                    c.protects.join(", ")
                };
                let notes = if c.notes.is_empty() {
                    String::new()
                } else {
                    format!(" — {}", c.notes)
                };
                format!(
                    "  - [{}] {} → protects: {prot}{notes}",
                    crate::wire::control_kind_str(c.kind),
                    c.name
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    let cmdb_block = match app_profile {
        Some(ap) => format!(
            "{}\n  → Use externally_facing to set default actor (remote_unauth only if YES; \
             otherwise adjacent_network/remote_auth). Use PCI/PAN/PII flags to set asset \
             sensitivity = critical.\n\n",
            app_profile_prompt_block(ap)
        ),
        None => String::new(),
    };

    let notes_block = if ev.s1_notes.is_empty() {
        String::new()
    } else {
        format!("\nMAPPER OBSERVATIONS (s1 free-form):\n{}\n", ev.s1_notes)
    };

    format!(
        "TARGET: {repo_name}  ({repo_root})\n\
         PRIMARY LANGUAGE: {}\n\
         FILES IN AST FRONTIER: {} (from {} total in-scope files)\n\
         \n\
         {cmdb_block}LANGUAGE BREAKDOWN:\n\
         {lang_block}\n\
         \n\
         COMPONENTS (top-level directories):\n\
         {comp_block}\n\
         \n\
         MODULES (s1-mapped — treat as asset candidates):\n\
         {mod_block}\n\
         \n\
         ENTRY POINTS (s1-mapped — these ARE the trust boundaries; STRIDE hint per kind):\n\
         {ep_block}\n\
         \n\
         AST FUNCTION SITES (method-level anchors chosen from entry-point/sink/callgraph frontier):\n\
         {site_block}\n\
         \n\
         AST CALL EDGES (bounded frontier, one edge per line):\n\
         {edge_block}\n\
         \n\
         REPRESENTATIVE CONFIGURATION (one per component, post-dedup — reveals data\n\
         stores, message buses, key/secret managers, TLS posture, external endpoints):\n\
         {cfg_block}\n\
         \n\
         API CONTRACT ARTEFACTS (OpenAPI/Swagger/Protobuf/GraphQL/WSDL/META-INF — the\n\
         explicit external interface):\n\
         {api_block}\n\
         {notes_block}\n\
         DOCUMENTATION:\n\
         {docs_block}\n\
         \n\
         BUILD / DEPENDENCY MANIFESTS:\n\
         {manifest_block}\n\
         \n\
         KNOWN PRIOR CVEs (use as evidence; raises likelihood):\n\
         {cve_block}\n\
         \n\
         DESIGN CONTROLS (lower likelihood where they apply):\n\
         {ctl_block}\n\
         {baseline_block}\n\
         Produce the threat model JSON now. Anchor each trust_boundary.entry_point to\n\
         one of the ENTRY POINTS above where possible; use the STRIDE hint to seed\n\
         threats per boundary.",
        if ev.primary_language.is_empty() {
            "unknown"
        } else {
            &ev.primary_language
        },
        ev.file_count,
        ev.original_file_count,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_evidence() -> Evidence {
        Evidence::default()
    }

    #[test]
    fn system_prompt_mentions_expected_schema_keys() {
        for key in [
            "system_context",
            "assets",
            "trust_boundaries",
            "threats",
            "open_questions",
        ] {
            assert!(SYSTEM.contains(key), "missing schema key: {key}");
        }
    }

    #[test]
    fn app_profile_prompt_block_lists_all_sensitivity_flags() {
        let ap = AppProfile {
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
        assert!(block.contains("Name: My App"));
        assert!(block.contains("Externally facing: YES"));
        assert!(block.contains("Data sensitivity: PCI-scoped, processes PAN, handles PII"));
        assert!(block.contains("Source: cmdb"));
    }

    #[test]
    fn app_profile_prompt_block_defaults_when_no_flags_or_name() {
        let ap = AppProfile {
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
    fn build_user_prompt_uses_defaults_for_empty_evidence() {
        let ev = empty_evidence();
        let prompt = build_user_prompt("/repo", "myrepo", &ev, &[], &[], None, "");
        assert!(prompt.contains("TARGET: myrepo  (/repo)"));
        assert!(prompt.contains("PRIMARY LANGUAGE: unknown"));
        assert!(prompt.contains("FILES IN AST FRONTIER: 0 (from 0 total in-scope files)"));
        assert!(prompt.contains("(none detected)"));
        assert!(prompt.contains("(flat repo)"));
        assert!(prompt.contains("(s1 emitted no modules)"));
        assert!(prompt.contains("(s1 emitted no entry points)"));
        assert!(prompt.contains("AST FUNCTION SITES"));
        assert!(prompt.contains("AST CALL EDGES"));
        assert!(prompt.contains("(none on file)"));
        assert!(prompt.contains("(no README / SECURITY / ARCHITECTURE docs found)"));
        assert!(prompt.contains("(no build/dependency manifests found)"));
    }

    #[test]
    fn build_user_prompt_shows_files_in_frontier_vs_total_in_scope() {
        let mut ev = empty_evidence();
        ev.file_count = 40;
        ev.original_file_count = 900;
        let prompt = build_user_prompt("/repo", "myrepo", &ev, &[], &[], None, "");
        assert!(prompt.contains("FILES IN AST FRONTIER: 40 (from 900 total in-scope files)"));
    }

    #[test]
    fn build_user_prompt_renders_function_sites_and_call_edges() {
        let mut ev = empty_evidence();
        ev.function_sites = vec![(
            "app.py::handler".to_string(),
            vec!["a.py:1".to_string(), "b.py:2".to_string()],
            " lines 10-20".to_string(),
        )];
        ev.call_edges = vec![("caller".to_string(), "callee".to_string())];
        let prompt = build_user_prompt("/repo", "myrepo", &ev, &[], &[], None, "");
        assert!(prompt.contains("  - app.py::handler @ a.py:1, b.py:2 lines 10-20"));
        assert!(prompt.contains("  - caller -> callee"));
    }

    #[test]
    fn build_user_prompt_includes_cmdb_block_when_app_profile_present() {
        let ev = empty_evidence();
        let ap = AppProfile {
            application_id: "APP1".to_string(),
            name: "App".to_string(),
            externally_facing: true,
            pci_scoped: false,
            processes_pan: false,
            pii: false,
            source: "cmdb".to_string(),
        };
        let prompt = build_user_prompt("/repo", "myrepo", &ev, &[], &[], Some(&ap), "");
        assert!(prompt.contains("CMDB APPLICATION PROFILE"));
        assert!(prompt.contains("Use externally_facing to set default actor"));
    }

    #[test]
    fn build_user_prompt_shows_truncation_markers() {
        let mut ev = empty_evidence();
        ev.modules = vec![("m".to_string(), "p".to_string(), 1)];
        ev.modules_truncated = true;
        ev.entry_points = vec![
            (
                "network".to_string(),
                true,
                "a.py".to_string(),
                "f".to_string(),
            ),
            (
                "network".to_string(),
                false,
                "b.py".to_string(),
                "g".to_string(),
            ),
        ];
        ev.entry_points_truncated = true;
        let prompt = build_user_prompt("/repo", "myrepo", &ev, &[], &[], None, "");
        assert!(prompt.contains("…(truncated)"));
        assert!(prompt.contains("UNAUTH"));
        assert!(prompt.contains("auth  "));
    }

    #[test]
    fn build_user_prompt_renders_non_empty_top_dirs_api_docs_and_manifests() {
        let mut ev = empty_evidence();
        ev.top_dirs = vec!["src".to_string(), "tests".to_string()];
        ev.config_reps = vec!["src/config.yaml".to_string()];
        ev.api_artefacts = vec!["openapi.yaml".to_string()];
        ev.docs = vec![("README.md".to_string(), "hello world".to_string())];
        ev.manifests = vec![("Cargo.toml".to_string(), "[package]".to_string())];
        let prompt = build_user_prompt("/repo", "myrepo", &ev, &[], &[], None, "");
        assert!(prompt.contains("  - src/"));
        assert!(prompt.contains("  - tests/"));
        assert!(prompt.contains("  - src/config.yaml"));
        assert!(prompt.contains("  - openapi.yaml"));
        assert!(prompt.contains("=== README.md ===\nhello world"));
        assert!(prompt.contains("=== Cargo.toml ===\n[package]"));
    }

    #[test]
    fn build_user_prompt_includes_cve_and_control_blocks() {
        let ev = empty_evidence();
        let cves = vec![Cve {
            id: "CVE-1".to_string(),
            summary: "a bug".to_string(),
            affected_files: vec![],
            cvss: Some(7.5),
            patched: false,
        }];
        let controls = vec![Control {
            name: "WAF".to_string(),
            kind: bc_model::ControlKind::Auth,
            protects: vec!["app.py".to_string()],
            notes: "blocks XSS".to_string(),
        }];
        let prompt = build_user_prompt("/repo", "myrepo", &ev, &cves, &controls, None, "");
        assert!(prompt.contains("CVE-1 (CVSS 7.5, UNPATCHED): a bug"));
        assert!(prompt.contains("[auth] WAF → protects: app.py — blocks XSS"));
    }

    #[test]
    fn build_user_prompt_cve_with_no_cvss_score_renders_none_literally() {
        let ev = empty_evidence();
        let cves = vec![Cve {
            id: "CVE-2".to_string(),
            summary: "unscored".to_string(),
            affected_files: vec![],
            cvss: None,
            patched: true,
        }];
        let prompt = build_user_prompt("/repo", "myrepo", &ev, &cves, &[], None, "");
        assert!(prompt.contains("CVE-2 (CVSS None, patched): unscored"));
    }

    #[test]
    fn build_user_prompt_control_with_no_protects_is_global() {
        let ev = empty_evidence();
        let controls = vec![Control {
            name: "Global WAF".to_string(),
            kind: bc_model::ControlKind::Auth,
            protects: vec![],
            notes: String::new(),
        }];
        let prompt = build_user_prompt("/repo", "myrepo", &ev, &[], &controls, None, "");
        assert!(prompt.contains("Global WAF → protects: global"));
    }

    #[test]
    fn build_user_prompt_includes_notes_and_baseline_block() {
        let mut ev = empty_evidence();
        ev.s1_notes = "some free-form notes".to_string();
        let prompt = build_user_prompt("/repo", "myrepo", &ev, &[], &[], None, "\nBASELINE TEXT\n");
        assert!(prompt.contains("MAPPER OBSERVATIONS (s1 free-form):\nsome free-form notes"));
        assert!(prompt.contains("BASELINE TEXT"));
    }
}
