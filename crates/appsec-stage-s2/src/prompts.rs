use appsec_model::{AppProfile, Control};

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
   (very_rare|rare|possible|likely|almost_certain). Assign ids T1, T2, … in the
   order you emit them; ordering does not matter — the caller ranks
   deterministically. Do NOT drop a threat because you are unsure: a plausible
   threat with likelihood \"rare\" is useful, a missing threat is not. Downstream
   stages re-check every threat against the real source code and discard the ones
   that do not hold up.

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

Every element of \"assets\", \"trust_boundaries\" and \"threats\" MUST be an object
carrying the keys shown above — never a bare string. A bare string where an
object is required fails schema validation and discards the ENTIRE response;
it is the one malformation observed to do so in production runs.

Coverage rules:
  - Every trust_boundary MUST appear as the surface of ≥1 threat.
  - Every MINIMUM BASELINE item, if any are supplied, MUST be either the basis of
    a threat (with \"evidence\" starting \"baseline: <ID>\") or named in
    open_questions with a one-clause reason. Never drop a baseline item without a
    written trace.";

pub const AGENTIC_SYSTEM_LINE: &str =
    "\n\nYou have read-only tools (Read, Glob, Grep): you may open the \
     configuration files listed by path in the evidence — and any other repository file — to \
     confirm details before emitting the JSON.";

pub fn repair_json_prompt(raw: &str, err: &str) -> String {
    format!(
        "REPAIR TASK:
The previous threat-model response failed to parse against the required
schema. Return ONLY a corrected JSON object that (a) is syntactically valid
JSON and (b) matches the schema in the system prompt exactly — in particular,
every element of \"assets\", \"trust_boundaries\" and \"threats\" must be an object
with the keys shown there, never a bare string. Preserve the original content
faithfully: do not add, remove, or reword any asset, boundary, or threat
beyond what restructuring requires.

PARSE/VALIDATION ERROR:
{err}

BROKEN RESPONSE:
{raw}
"
    )
}

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

fn control_prompt_block(controls: &[Control]) -> String {
    if controls.is_empty() {
        return "  (none on file)".to_string();
    }
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
}

pub fn provider_digest_prompt_block(digest: &appsec_model::ProviderDigest) -> String {
    if digest.is_empty() {
        return "  (no third-party scanner results supplied)".to_string();
    }
    let mut out = Vec::new();
    out.push(format!("  TOTAL: {} finding(s)", digest.total));
    if !digest.by_vendor.is_empty() {
        out.push(format!("  BY TOOL: {}", joined_counts(&digest.by_vendor)));
    }
    if !digest.by_product.is_empty() {
        out.push(format!("  BY KIND: {}", joined_counts(&digest.by_product)));
    }
    if !digest.by_severity.is_empty() {
        out.push(format!(
            "  BY VENDOR SEVERITY: {}",
            joined_counts(&digest.by_severity)
        ));
    }
    if !digest.by_class.is_empty() {
        out.push(format!("  BY CLASS: {}", joined_counts(&digest.by_class)));
    }
    if !digest.hotspots.is_empty() {
        let spots = digest
            .hotspots
            .iter()
            .map(|h| format!("{} ({})", h.path, h.count))
            .collect::<Vec<_>>()
            .join(", ");
        out.push(format!("  CONCENTRATED IN: {spots}"));
    }
    if !digest.dependencies.is_empty() {
        out.push("  FLAGGED DEPENDENCIES:".to_string());
        for dep in &digest.dependencies {
            let mut line = format!(
                "    - [{}] {} — {} ({})",
                dep.severity, dep.component, dep.title, dep.vendor
            );
            if !dep.cves.is_empty() {
                line.push_str(&format!(" {}", dep.cves.join(", ")));
            }
            match dep.direct {
                Some(true) => line.push_str(" [direct]"),
                Some(false) => line.push_str(" [transitive]"),
                None => {}
            }
            if !dep.fixed_in.is_empty() {
                line.push_str(&format!(" fixed in {}", dep.fixed_in.join(", ")));
            }
            out.push(line);
        }
        if digest.dependencies_truncated {
            out.push("    …(truncated)".to_string());
        }
    }
    out.join("\n")
}

fn joined_counts(counts: &std::collections::BTreeMap<String, usize>) -> String {
    counts
        .iter()
        .map(|(k, n)| format!("{k}={n}"))
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn build_user_prompt(
    repo_name: &str,
    ev: &Evidence,
    controls: &[Control],
    app_profile: Option<&AppProfile>,
    baseline_block: &str,
    provider_digest: &appsec_model::ProviderDigest,
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
            .map(|(p, body)| {
                if body.is_empty() {
                    format!("  - {p}")
                } else {
                    format!("  === {p} ===\n{body}")
                }
            })
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
    let provider_block = provider_digest_prompt_block(provider_digest);
    let ctl_block = control_prompt_block(controls);

    let cmdb_block = match app_profile {
        Some(ap) => format!(
            "{}{}\n  → Use externally_facing to set default actor (remote_unauth only if YES; \
             otherwise adjacent_network/remote_auth). Use PCI/PAN/PII flags to set asset \
             sensitivity = critical.\n\n",
            app_profile_prompt_block(ap),
            topology_prompt_block(ap)
        ),
        None => String::new(),
    };

    let notes_block = if ev.s1_notes.is_empty() {
        String::new()
    } else {
        format!("\nMAPPER OBSERVATIONS (s1 free-form):\n{}\n", ev.s1_notes)
    };

    format!(
        "{baseline_block}{cmdb_block}LANGUAGE BREAKDOWN:\n\
         {lang_block}\n\
         \n\
         COMPONENTS (top-level directories):\n\
         {comp_block}\n\
         \n\
         REPRESENTATIVE CONFIGURATION (one per component, post-dedup — entries under a\n\
         \"=== path ===\" header carry redacted, length-capped file contents revealing\n\
         data stores, message buses, key/secret managers, TLS posture, external\n\
         endpoints; entries listed as \"- path\" are present by name only):\n\
         {cfg_block}\n\
         \n\
         API CONTRACT ARTEFACTS (OpenAPI/Swagger/Protobuf/GraphQL/WSDL/META-INF — the\n\
         explicit external interface):\n\
         {api_block}\n\
         \n\
         DOCUMENTATION:\n\
         {docs_block}\n\
         \n\
         BUILD / DEPENDENCY MANIFESTS:\n\
         {manifest_block}\n\
         \n\
         PRIOR SCANNER FINDINGS (SAST/SCA/secret tools already run against this repo —\n\
         unverified, but they are evidence of where defects cluster; raise likelihood for\n\
         components and classes they already flagged):\n\
         {provider_block}\n\
         \n\
         DESIGN CONTROLS (lower likelihood where they apply):\n\
         {ctl_block}\n\
         \n\
         TARGET: {repo_name}\n\
         PRIMARY LANGUAGE: {}\n\
         FILES IN AST FRONTIER: {} (from {} total in-scope files)\n\
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
         {notes_block}\n\
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
        assert!(block.contains("Name: My App"));
        assert!(block.contains("Externally facing: YES"));
        assert!(block.contains("Data sensitivity: PCI-scoped, processes PAN, handles PII"));
        assert!(block.contains("Source: cmdb"));
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
    fn build_user_prompt_uses_defaults_for_empty_evidence() {
        let ev = empty_evidence();
        let prompt = build_user_prompt(
            "myrepo",
            &ev,
            &[],
            None,
            "",
            &appsec_model::ProviderDigest::default(),
        );
        assert!(prompt.contains("TARGET: myrepo\n"));
        assert!(
            !prompt.contains("/repo"),
            "the absolute root is never rendered"
        );
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
        let prompt = build_user_prompt(
            "myrepo",
            &ev,
            &[],
            None,
            "",
            &appsec_model::ProviderDigest::default(),
        );
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
        let prompt = build_user_prompt(
            "myrepo",
            &ev,
            &[],
            None,
            "",
            &appsec_model::ProviderDigest::default(),
        );
        assert!(prompt.contains("  - app.py::handler @ a.py:1, b.py:2 lines 10-20"));
        assert!(prompt.contains("  - caller -> callee"));
    }

    #[test]
    fn build_user_prompt_includes_cmdb_block_when_app_profile_present() {
        let ev = empty_evidence();
        let ap = AppProfile {
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
        };
        let prompt = build_user_prompt(
            "myrepo",
            &ev,
            &[],
            Some(&ap),
            "",
            &appsec_model::ProviderDigest::default(),
        );
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
        let prompt = build_user_prompt(
            "myrepo",
            &ev,
            &[],
            None,
            "",
            &appsec_model::ProviderDigest::default(),
        );
        assert!(prompt.contains("…(truncated)"));
        assert!(prompt.contains("UNAUTH"));
        assert!(prompt.contains("auth  "));
    }

    #[test]
    fn build_user_prompt_renders_non_empty_top_dirs_api_docs_and_manifests() {
        let mut ev = empty_evidence();
        ev.top_dirs = vec!["src".to_string(), "tests".to_string()];
        ev.config_reps = vec![
            ("src/config.yaml".to_string(), String::new()),
            ("WEB-INF/web.xml".to_string(), "<web-app/>".to_string()),
        ];
        ev.api_artefacts = vec!["openapi.yaml".to_string()];
        ev.docs = vec![("README.md".to_string(), "hello world".to_string())];
        ev.manifests = vec![("Cargo.toml".to_string(), "[package]".to_string())];
        let prompt = build_user_prompt(
            "myrepo",
            &ev,
            &[],
            None,
            "",
            &appsec_model::ProviderDigest::default(),
        );
        assert!(prompt.contains("  - src/"));
        assert!(prompt.contains("  - tests/"));
        assert!(prompt.contains("  - src/config.yaml"));
        assert!(prompt.contains("  === WEB-INF/web.xml ===\n<web-app/>"));
        assert!(prompt.contains("carry redacted, length-capped file contents"));
        assert!(prompt.contains("  - openapi.yaml"));
        assert!(prompt.contains("=== README.md ===\nhello world"));
        assert!(prompt.contains("=== Cargo.toml ===\n[package]"));
    }

    #[test]
    fn build_user_prompt_includes_the_control_block_and_no_cve_block() {
        let ev = empty_evidence();
        let controls = vec![Control {
            name: "WAF".to_string(),
            kind: appsec_model::ControlKind::Auth,
            protects: vec!["app.py".to_string()],
            notes: "blocks XSS".to_string(),
        }];
        let prompt = build_user_prompt(
            "myrepo",
            &ev,
            &controls,
            None,
            "",
            &appsec_model::ProviderDigest::default(),
        );
        assert!(prompt.contains("[auth] WAF → protects: app.py — blocks XSS"));
        assert!(
            !prompt.contains("KNOWN PRIOR CVEs"),
            "the legacy injected-CVE block is gone: {prompt}"
        );
    }

    #[test]
    fn build_user_prompt_control_with_no_protects_is_global() {
        let ev = empty_evidence();
        let controls = vec![Control {
            name: "Global WAF".to_string(),
            kind: appsec_model::ControlKind::Auth,
            protects: vec![],
            notes: String::new(),
        }];
        let prompt = build_user_prompt(
            "myrepo",
            &ev,
            &controls,
            None,
            "",
            &appsec_model::ProviderDigest::default(),
        );
        assert!(prompt.contains("Global WAF → protects: global"));
    }

    #[test]
    fn build_user_prompt_includes_notes_and_baseline_block() {
        let mut ev = empty_evidence();
        ev.s1_notes = "some free-form notes".to_string();
        let prompt = build_user_prompt(
            "myrepo",
            &ev,
            &[],
            None,
            "\nBASELINE TEXT\n",
            &appsec_model::ProviderDigest::default(),
        );
        assert!(prompt.contains("MAPPER OBSERVATIONS (s1 free-form):\nsome free-form notes"));
        assert!(prompt.starts_with("\nBASELINE TEXT\nLANGUAGE BREAKDOWN:"));
    }

    #[test]
    fn system_prompt_requires_object_elements_and_baseline_dispositions() {
        assert!(SYSTEM.contains("never a bare string"));
        assert!(SYSTEM.contains("\"evidence\" starting \"baseline: <ID>\""));
        assert!(SYSTEM.contains("the caller ranks\n   deterministically"));
        assert!(!SYSTEM.contains("Sort by (impact,likelihood)"));
        assert!(AGENTIC_SYSTEM_LINE.starts_with("\n\nYou have read-only tools (Read, Glob, Grep)"));
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
    fn repair_prompt_names_the_error_and_carries_the_broken_response() {
        let p = repair_json_prompt("{\"assets\": [\"db\"]}", "assets[0]: expected an object");
        assert!(p.starts_with("REPAIR TASK:\n"));
        assert!(p.contains("PARSE/VALIDATION ERROR:\nassets[0]: expected an object\n"));
        assert!(p.ends_with("BROKEN RESPONSE:\n{\"assets\": [\"db\"]}\n"));
    }
}

#[cfg(test)]
mod provider_digest_block_tests {
    use super::*;
    use appsec_model::{ProviderDependencyAlert, ProviderDigest, ProviderHotspot};

    fn populated() -> ProviderDigest {
        ProviderDigest {
            total: 4,
            by_vendor: [("snyk".to_string(), 3), ("semgrep".to_string(), 1)].into(),
            by_product: [("dependency".to_string(), 3), ("sast".to_string(), 1)].into(),
            by_severity: [("critical".to_string(), 1), ("high".to_string(), 3)].into(),
            by_class: [("injection".to_string(), 1)].into(),
            hotspots: vec![ProviderHotspot {
                path: "src".to_string(),
                count: 1,
            }],
            dependencies: vec![ProviderDependencyAlert {
                component: "lodash@4.17.15".to_string(),
                title: "Prototype Pollution".to_string(),
                severity: "critical".to_string(),
                vendor: "snyk".to_string(),
                ..ProviderDependencyAlert::default()
            }],
            dependencies_truncated: false,
        }
    }

    #[test]
    fn an_empty_digest_says_no_results_were_supplied() {
        let block = provider_digest_prompt_block(&ProviderDigest::default());
        assert!(
            block.contains("no third-party scanner results supplied"),
            "{block}"
        );
    }

    #[test]
    fn a_populated_digest_renders_counts_hotspots_and_components() {
        let block = provider_digest_prompt_block(&populated());
        assert!(block.contains("TOTAL: 4 finding(s)"), "{block}");
        assert!(block.contains("snyk=3"), "{block}");
        assert!(block.contains("dependency=3"), "{block}");
        assert!(block.contains("critical=1"), "{block}");
        assert!(block.contains("src (1)"), "{block}");
        assert!(
            block.contains("[critical] lodash@4.17.15 — Prototype Pollution (snyk)"),
            "{block}"
        );
        assert!(!block.contains("truncated"), "{block}");
    }

    #[test]
    fn a_capped_component_list_says_it_was_capped() {
        let mut digest = populated();
        digest.dependencies_truncated = true;
        let block = provider_digest_prompt_block(&digest);
        assert!(block.contains("…(truncated)"), "{block}");
    }

    #[test]
    fn the_prompt_carries_the_digest_under_its_own_heading() {
        let ev = Evidence::default();
        let prompt = build_user_prompt("myrepo", &ev, &[], None, "", &populated());
        assert!(prompt.contains("PRIOR SCANNER FINDINGS"), "{prompt}");
        assert!(prompt.contains("lodash@4.17.15"), "{prompt}");
        let scanner_at = prompt
            .find("PRIOR SCANNER FINDINGS")
            .expect("section present");
        let controls_at = prompt
            .find("DESIGN CONTROLS")
            .expect("controls section present");
        assert!(
            scanner_at < controls_at,
            "the scanner digest sits with the other prior-evidence blocks"
        );
        assert!(
            !prompt.contains("KNOWN PRIOR CVEs"),
            "the legacy injected-CVE block is gone: {prompt}"
        );
    }

    #[test]
    fn a_dependency_line_carries_the_cve_the_fix_and_whether_it_is_direct() {
        let mut digest = populated();
        digest.dependencies[0].cves = vec!["CVE-2020-8203".to_string()];
        digest.dependencies[0].fixed_in = vec!["4.17.19".to_string()];
        digest.dependencies[0].direct = Some(false);
        let block = provider_digest_prompt_block(&digest);
        assert!(block.contains("CVE-2020-8203"), "{block}");
        assert!(block.contains("[transitive]"), "{block}");
        assert!(block.contains("fixed in 4.17.19"), "{block}");
    }

    #[test]
    fn a_direct_dependency_says_so() {
        let mut digest = populated();
        digest.dependencies[0].direct = Some(true);
        let block = provider_digest_prompt_block(&digest);
        assert!(block.contains("[direct]"), "{block}");
    }

    #[test]
    fn an_unknown_dependency_depth_claims_neither() {
        let block = provider_digest_prompt_block(&populated());
        assert!(!block.contains("[direct]"), "{block}");
        assert!(!block.contains("[transitive]"), "{block}");
    }

    #[test]
    fn a_prompt_without_provider_results_still_names_the_section() {
        let ev = Evidence::default();
        let prompt = build_user_prompt("myrepo", &ev, &[], None, "", &ProviderDigest::default());
        assert!(prompt.contains("PRIOR SCANNER FINDINGS"), "{prompt}");
        assert!(
            prompt.contains("no third-party scanner results supplied"),
            "{prompt}"
        );
    }
}
