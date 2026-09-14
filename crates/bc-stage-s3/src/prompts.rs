// Portions of this file are transcribed from vvaharness, Visa's agentic
// SAST harness: Copyright 2026 Visa, Inc., licensed under the Apache
// License, Version 2.0. Reimplemented in Rust and modified; see the module
// documentation below, and NOTICE for the full attribution.
//! S3's system/user prompts, ported from `s3_decompose.py`'s `SYSTEM`
//! constant and `models.py`'s `ContextPackage.to_decompose_prompt_block`/
//! `_function_sites_block`/`_call_graph_block_full`/`_signatures_block`,
//! `ThreatModel.to_compact_prompt_block`, and `AppProfile.to_prompt_block`
//! — kept as free functions here (not on `bc_model`'s types), matching
//! this project's established convention (`bc-stage-s2`/`-s8` also keep
//! prompt/render formatting out of the DTO crate).
//!
//! [`to_decompose_prompt_block`] is the function `s3_decompose.py`'s real
//! `run()` calls — NOT `ContextPackage.to_prompt_block` (a different,
//! still-real Python method used by S2/S6's own prompt rendering, and
//! confirmed dead within THIS crate specifically: `bc-stage-s3` was
//! previously wired to a faithful port of it, `to_prompt_block`, which
//! has since been removed as genuinely unused dead code now that the
//! correct function is wired in). `to_decompose_prompt_block` deliberately
//! omits the repo-wide `ALL FILES`/per-module file listings
//! `to_prompt_block` had: the strategist only needs structural anchors
//! for risk ranking, since the deterministic taint/catch-all passes that
//! run after S3 preserve full-file coverage regardless of what the LLM
//! says.

use std::path::Path;

use bc_model::{AppProfile, ContextPackage, ThreatModel};

use crate::wire::{
    actor_str, control_kind_str, ep_kind_str, impact_str, likelihood_str, sensitivity_str,
};

// A plain (non-`\`-continued) multi-line literal below — every physical
// source newline is a real character in the compiled string, so each
// line's own leading whitespace survives verbatim (this matters a lot
// here: the embedded JSON example's nesting was previously flattened to
// zero indentation by `\`-continuation eating it — confirmed by compiling
// and diffing against Python). `bc_prompts::EXCLUSION_RULES` already uses
// this exact style for the same reason.
pub const SYSTEM: &str = "You are a vulnerability research strategist. You receive a structured
map of a codebase — NOT the source code itself — and produce a prioritized
hunting plan.

Your job:
1. Rank attack surfaces by risk. Unauth-reachable entry points + unsafe sinks
   in the same data flow path = highest priority.
2. Hunt for VARIANTS of known CVEs. If CVE-X is a heap overflow in parser.c,
   look for sibling parsers with the same pattern.
3. Account for design controls. A bug behind strong auth ranks lower than the
   same bug pre-auth.
4. Tie every chunk to a THREAT. The THREAT MODEL section lists ranked threats
   T1..Tn. Each chunk MUST cite the threat_id it tests. Every threat should be
   covered by at least one chunk; if a threat has no plausible code surface,
   omit it — do NOT invent a chunk.
5. Chunk the work. Each chunk = a coherent set of files to deep-dive together.
   Use the CALL GRAPH section: when caller -> callee crosses files, put BOTH
   files in the same chunk so the entry-point and its sink are reviewed
   together. Tag size: small (<2k loc), medium (<8k), large (more).
6. For LARGE chunks, name the entry-point functions to anchor a sliding window.

Respond with ONLY a JSON object, no prose:
{
  \"rationale\": \"one paragraph explaining your ranking\",
  \"chunks\": [
    {
      \"id\": \"chunk-01\",
      \"size\": \"small|medium|large\",
      \"risk_rank\": 1,
      \"files\": [\"src/parser.c\", \"src/parser.h\"],
      \"focus_entry_points\": [\"parse_request\"],
      \"hypothesis\": \"Specific reasoning about what to hunt and why\",
      \"threat_id\": \"T3\",
      \"related_cves\": [\"CVE-2024-1234\"]
    }
  ]
}";

/// Ported from `AppProfile.to_prompt_block()`. Deliberately duplicated
/// byte-for-byte in `bc-stage-s2`/`bc-stage-s8`'s own `prompts.rs` rather
/// than factored into a shared crate — see `bc-stage-s2::prompts::
/// app_profile_prompt_block`'s doc comment for why. Keep all three copies
/// byte-identical if either changes.
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

/// The unqualified name half of a `file::name` qualified identifier
/// (falling back to the whole string when there's no `::`).
fn bare(qn: &str) -> &str {
    qn.rsplit_once("::").map(|(_, n)| n).unwrap_or(qn)
}

/// `(ep_fqns, sink_fqns, ep_bare, sink_bare)` — the four membership sets
/// `_hot`'s per-edge classification checks against. Built once per prompt
/// render rather than per edge.
struct HotSets {
    ep_fqns: std::collections::HashSet<String>,
    sink_fqns: std::collections::HashSet<String>,
    ep_bare: std::collections::HashSet<String>,
    sink_bare: std::collections::HashSet<String>,
}

fn hot_sets(ctx: &ContextPackage) -> HotSets {
    HotSets {
        ep_fqns: ctx
            .entry_points
            .iter()
            .map(|e| format!("{}::{}", e.file, e.function))
            .collect(),
        sink_fqns: ctx
            .unsafe_sinks
            .iter()
            .map(|s| format!("{}::{}", s.file, s.function))
            .collect(),
        ep_bare: ctx
            .entry_points
            .iter()
            .map(|e| e.function.clone())
            .collect(),
        sink_bare: ctx
            .unsafe_sinks
            .iter()
            .map(|s| s.function.clone())
            .collect(),
    }
}

/// Ported from `ContextPackage._call_graph_block`/`_call_graph_block_full`'s
/// shared `_hot` closure: a QUALIFIED name (contains `::`) is hot only via
/// an EXACT full-qnode match against `ep_fqns`/`sink_fqns`; an UNQUALIFIED
/// name (no `::`) falls back to a bare-name match instead. Fixes a real
/// divergence from a prior port: the previous version always stripped to
/// the bare name regardless of qualification, so a qualified name sharing
/// an entry/sink's bare function name in a DIFFERENT file was incorrectly
/// classified hot — this restores Python's stricter, qualification-aware
/// check.
fn is_hot(name: &str, sets: &HotSets) -> bool {
    if sets.ep_fqns.contains(name) || sets.sink_fqns.contains(name) {
        return true;
    }
    if !name.contains("::") {
        let b = bare(name);
        return sets.ep_bare.contains(b) || sets.sink_bare.contains(b);
    }
    false
}

/// Ordered `caller -> callee1, callee2` edge lines, entry-point/sink-touching
/// edges first (stable partition, not a full sort — Rust's `BTreeMap`
/// iteration is sorted-by-key rather than the Python `dict`'s
/// insertion-order, an accepted pre-existing divergence in `ContextPackage`'s
/// own type choice, not introduced here). `max_edges` truncates with a
/// trailing "…(N more)" marker when `Some`; `None` renders every edge
/// (`_call_graph_block_full`'s own behavior — no clipping at all). Ported
/// from `ContextPackage._call_graph_block`/`_call_graph_block_full`, which
/// are otherwise byte-for-byte identical apart from the cap.
fn call_graph_block(ctx: &ContextPackage, max_edges: Option<usize>) -> Vec<String> {
    let sets = hot_sets(ctx);

    let mut hot = Vec::new();
    let mut cold = Vec::new();
    for (caller, callees) in &ctx.call_graph {
        let mut seen = std::collections::HashSet::new();
        let uniq: Vec<&str> = callees
            .iter()
            .filter(|c| !c.is_empty())
            .map(|c| c.as_str())
            .filter(|c| seen.insert(*c))
            .collect();
        if uniq.is_empty() {
            continue;
        }
        let line = format!("  - {caller} -> {}", uniq.join(", "));
        let hot_hit = is_hot(caller, &sets) || uniq.iter().any(|callee| is_hot(callee, &sets));
        if hot_hit {
            hot.push(line);
        } else {
            cold.push(line);
        }
    }

    let mut ordered = hot;
    ordered.extend(cold);
    let n_total = ordered.len();
    let mut out = vec![format!(
        "CALL GRAPH ({n_total} edges — group caller+callee files in the SAME chunk):"
    )];
    match max_edges {
        Some(max_edges) => {
            out.extend(ordered.into_iter().take(max_edges));
            if n_total > max_edges {
                out.push(format!(
                    "  … ({} more edges truncated)",
                    n_total - max_edges
                ));
            }
        }
        None => out.extend(ordered),
    }
    out
}

/// Real source excerpts for every entry point and sink, so the strategist
/// can see parameter shapes without receiving raw source elsewhere. Does
/// real file I/O — this is why the Rust port deliberately excludes it from
/// `bc-model` (kept here instead). Ported from
/// `ContextPackage._signatures_block`.
fn signatures_block(
    ctx: &ContextPackage,
    repo_root: &Path,
    body_lines: usize,
    cap: usize,
) -> Vec<String> {
    let mut out = vec!["SIGNATURES (entry points + sinks — use param types to group related files into one chunk):".to_string()];
    let mut seen: std::collections::HashSet<(String, usize)> = std::collections::HashSet::new();

    let mut emit = |tag: &str, file: &str, function: &str, hint_line: i64| {
        if seen.len() >= cap {
            return;
        }
        // `file` comes from `ctx.entry_points`/`ctx.unsafe_sinks`, which
        // can be LLM-annotated (S1's `detect_specs` pass) — confine
        // before reading rather than trusting it stayed in-repo (CWE-22).
        let Some(resolved) = bc_pathjail::confine(repo_root, file) else {
            return;
        };
        let Ok(contents) = std::fs::read_to_string(resolved) else {
            return;
        };
        let src: Vec<&str> = contents.lines().collect();
        let mut anchor = if hint_line > 0 && (hint_line as usize) <= src.len() {
            Some(hint_line as usize - 1)
        } else {
            None
        };
        if anchor.is_none() {
            anchor = src
                .iter()
                .position(|ln| !function.is_empty() && ln.contains(function) && ln.contains('('));
        }
        let Some(anchor) = anchor else {
            return;
        };
        if !seen.insert((file.to_string(), anchor)) {
            return;
        }
        let hi = src.len().min(anchor + 1 + body_lines);
        out.push(format!("  [{tag}] {file}:{} {function}()", anchor + 1));
        for ln in &src[anchor..hi] {
            let trimmed = ln.trim_end();
            let capped: String = trimmed.chars().take(160).collect();
            out.push(format!("      {capped}"));
        }
    };

    for e in &ctx.entry_points {
        emit("ENTRY", &e.file, &e.function, 0);
    }
    for s in &ctx.unsafe_sinks {
        emit("SINK", &s.file, &s.function, s.line);
    }
    if seen.len() >= cap {
        out.push(format!("  … (capped at {cap})"));
    }

    if out.len() > 1 {
        out
    } else {
        Vec::new()
    }
}

/// Method/file anchors for chunk grouping — up to 3 de-duplicated
/// (by function+file) call sites per function, each optionally annotated
/// with its `def_spans` line range. Ported from `ContextPackage.
/// _function_sites_block`. Iterates `call_graph_files` in `BTreeMap`
/// (sorted-by-key) order rather than Python's dict insertion order — the
/// same accepted divergence as `call_graph_block`.
///
/// NOTE: the Python original's `span = self.def_spans.get(fn)` looks up
/// `def_spans` (keyed by qualified `"file::name"` qnodes) using `fn`, the
/// BARE function-name key from `call_graph_files` — these two maps use
/// different key formats, so in practice this lookup essentially never
/// finds a match. Ported faithfully (not "fixed") since correcting it
/// would diverge from what the real Python product actually renders.
fn function_sites_block(ctx: &ContextPackage, cap: usize) -> Vec<String> {
    let mut out = vec!["FUNCTION SITES (use these method/file anchors when grouping related files into one chunk):".to_string()];
    let mut count = 0usize;
    let mut seen: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();
    for (fname, sites) in &ctx.call_graph_files {
        let mut uniq_sites: Vec<&str> = Vec::new();
        for site in sites {
            let file_part = site.split(':').next().unwrap_or(site.as_str());
            if !seen.insert((fname.clone(), file_part.to_string())) {
                continue;
            }
            uniq_sites.push(site.as_str());
        }
        if uniq_sites.is_empty() {
            continue;
        }
        let span_txt = ctx
            .def_spans
            .get(fname)
            .map(|(sl, el)| format!(" lines {sl}-{el}"))
            .unwrap_or_default();
        out.push(format!(
            "  - {fname} @ {}{span_txt}",
            uniq_sites
                .into_iter()
                .take(3)
                .collect::<Vec<_>>()
                .join(", ")
        ));
        count += 1;
        if count >= cap {
            let remaining = ctx.call_graph_files.len().saturating_sub(count);
            if remaining > 0 {
                out.push(format!("  … ({remaining} more function sites truncated)"));
            }
            break;
        }
    }
    if count == 0 {
        Vec::new()
    } else {
        out
    }
}

/// Ported from `ThreatModel.to_compact_prompt_block` — the same sections
/// as `bc_stage_s8::prompts::threat_model_prompt_block` (not an intra-doc
/// link: `bc-stage-s3` doesn't depend on `bc-stage-s8`), each capped with
/// an explicit "N/total" count and a "…(truncated)" marker when clipped,
/// plus a character-capped system context. Used by S3's decompose prompt
/// (which is ALSO fed through `ContextPackage.ast_context_view`'s own
/// upstream trim in the real product — see task #36) instead of S8's
/// uncapped version.
fn threat_model_compact_prompt_block(
    tm: &ThreatModel,
    max_assets: usize,
    max_boundaries: usize,
    max_threats: usize,
    max_context_chars: usize,
) -> String {
    let context: String = tm.system_context.chars().take(max_context_chars).collect();
    let mut lines = vec![
        "THREAT MODEL:".to_string(),
        String::new(),
        "System context:".to_string(),
        context,
        String::new(),
    ];

    if !tm.assets.is_empty() {
        let assets: Vec<_> = tm.assets.iter().take(max_assets).collect();
        lines.push(format!("Assets ({}/{}):", assets.len(), tm.assets.len()));
        for a in &assets {
            lines.push(format!(
                "  - [{}] {} — {}",
                sensitivity_str(a.sensitivity),
                a.name,
                a.description
            ));
        }
        if tm.assets.len() > assets.len() {
            lines.push("  …(truncated)".to_string());
        }
        lines.push(String::new());
    }

    if !tm.trust_boundaries.is_empty() {
        let bounds: Vec<_> = tm.trust_boundaries.iter().take(max_boundaries).collect();
        lines.push(format!(
            "Trust boundaries ({}/{}):",
            bounds.len(),
            tm.trust_boundaries.len()
        ));
        for b in &bounds {
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
        if tm.trust_boundaries.len() > bounds.len() {
            lines.push("  …(truncated)".to_string());
        }
        lines.push(String::new());
    }

    if !tm.threats.is_empty() {
        let threats: Vec<_> = tm.threats.iter().take(max_threats).collect();
        lines.push(format!(
            "Ranked threats ({}/{}):",
            threats.len(),
            tm.threats.len()
        ));
        for t in &threats {
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
        if tm.threats.len() > threats.len() {
            lines.push("  …(truncated)".to_string());
        }
        lines.push(String::new());
    }

    lines.join("\n")
}

/// Method-centric text representation for S3's strategist prompt, ported
/// from `ContextPackage.to_decompose_prompt_block` — this is the function
/// `s3_decompose.py`'s real `run()` actually calls, NOT `to_prompt_block`
/// (a different, still-real Python method used by S2/S6's own generic
/// prompt rendering, and the function this Rust port's S3 stage was
/// incorrectly wired to before this fix). Deliberately omits the
/// repo-wide `ALL FILES`/per-module file listings `to_prompt_block` has:
/// the strategist only needs structural anchors for risk ranking, since
/// the deterministic taint/catch-all passes that run after S3 preserve
/// full-file coverage regardless of what the LLM says.
pub fn to_decompose_prompt_block(ctx: &ContextPackage, repo_root: &Path) -> String {
    let mut lines = vec![
        format!("REPO: {}  LANG: {}", ctx.repo_root, ctx.language),
        String::new(),
        format!("MODULES ({}):", ctx.modules.len()),
    ];
    for m in &ctx.modules {
        lines.push(format!("  - {} ({} loc): {}", m.name, m.loc, m.purpose));
    }
    lines.push(String::new());

    // `diff_scope_active`, not `!changed_files.is_empty()`: a rename-only
    // PR is a diff-scoped scan whose changed set is legitimately empty,
    // and the strategist needs to be told that explicitly rather than
    // handed a prompt indistinguishable from a full-repo scan.
    if ctx.diff_scope_active {
        lines.push(format!(
            "PRIORITIZE THESE FILES ({}) — this is a diff-scoped scan; these are the \
             files the PR actually changed, and chunks covering them are what will be \
             analyzed. Other files above are available only as call-graph/import \
             context for reasoning about these changes:",
            ctx.changed_files.len()
        ));
        for fp in ctx.changed_files.keys() {
            lines.push(format!("  - {fp}"));
        }
        lines.push(String::new());
    }

    lines.push(format!("ENTRY POINTS ({}):", ctx.entry_points.len()));
    for e in &ctx.entry_points {
        let unauth = if e.reachable_from_unauth {
            " [UNAUTH-REACHABLE]"
        } else {
            ""
        };
        lines.push(format!(
            "  - {}: {} @ {}{unauth}",
            ep_kind_str(e.kind),
            e.function,
            e.file
        ));
    }
    lines.push(String::new());

    lines.push(format!("UNSAFE SINKS ({}):", ctx.unsafe_sinks.len()));
    for s in &ctx.unsafe_sinks {
        lines.push(format!("  - {} @ {}:{}", s.function, s.file, s.line));
    }
    lines.push(String::new());

    let sites = function_sites_block(ctx, 120);
    if !sites.is_empty() {
        lines.extend(sites);
        lines.push(String::new());
    }
    let sigs = signatures_block(ctx, repo_root, 1, 40);
    if !sigs.is_empty() {
        lines.extend(sigs);
        lines.push(String::new());
    }
    if !ctx.call_graph.is_empty() {
        lines.extend(call_graph_block(ctx, None));
        lines.push(String::new());
    }
    if !ctx.known_cves.is_empty() {
        lines.push(format!(
            "KNOWN CVEs ({}) — DO NOT REDISCOVER:",
            ctx.known_cves.len()
        ));
        for c in &ctx.known_cves {
            lines.push(format!("  - {}: {}", c.id, c.summary));
        }
        lines.push(String::new());
    }
    if !ctx.design_controls.is_empty() {
        lines.push(format!("DESIGN CONTROLS ({}):", ctx.design_controls.len()));
        for c in ctx.design_controls.iter().take(40) {
            let prot = if c.protects.is_empty() {
                "global".to_string()
            } else {
                c.protects.join(", ")
            };
            lines.push(format!(
                "  - [{}] {} → protects: {prot}",
                control_kind_str(c.kind),
                c.name
            ));
        }
        lines.push(String::new());
    }
    if let Some(ap) = &ctx.app_profile {
        lines.push(app_profile_prompt_block(ap));
        lines.push(String::new());
    }
    if let Some(tm) = &ctx.threat_model {
        lines.push(threat_model_compact_prompt_block(tm, 8, 12, 12, 2500));
    }
    if !ctx.notes.is_empty() {
        let notes: String = ctx.notes.chars().take(3000).collect();
        lines.push(format!("OPUS NOTES:\n{notes}"));
    }
    if !ctx.compliance_guidance.is_empty() {
        lines.push(format!("COMPLIANCE GUIDANCE:\n{}", ctx.compliance_guidance));
    }

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_model::{
        Actor, Asset, Control, ControlKind, Cve, EntryPoint, EntryPointKind, Impact, Likelihood,
        ModuleInfo, Sensitivity, Sink, Threat, TrustBoundary,
    };

    /// The `\`-continuation indentation-stripping bug (see
    /// `bc_prompts::EXCLUSION_RULES`'s own doc comment) — the numbered
    /// list's hanging indent and the embedded JSON example's nesting must
    /// both keep their real leading whitespace in the compiled string.
    #[test]
    fn system_prompt_preserves_list_and_json_indentation() {
        assert!(SYSTEM.contains("\n   in the same data flow path = highest priority."));
        assert!(SYSTEM.contains("{\n  \"rationale\""));
        assert!(SYSTEM.contains("\"chunks\": [\n    {\n      \"id\": \"chunk-01\","));
    }

    fn minimal_ctx() -> ContextPackage {
        ContextPackage {
            seed_taint_paths: Default::default(),
            seed_taint_evidence: Default::default(),
            def_spans: Default::default(),
            repo_root: "/repo".to_string(),
            language: "python".to_string(),
            call_graph: Default::default(),
            call_graph_files: Default::default(),
            entry_points: Vec::new(),
            unsafe_sinks: Vec::new(),
            modules: Vec::new(),
            all_files: Vec::new(),
            excluded: Default::default(),
            known_cves: Vec::new(),
            design_controls: Vec::new(),
            changed_files: Default::default(),
            diff_scope_active: false,
            app_profile: None,
            threat_model: None,
            notes: String::new(),
            compliance_guidance: String::new(),
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
        assert!(block.contains("PCI-scoped, processes PAN, handles PII"));
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
        assert!(block.contains("Data sensitivity: standard"));
    }

    #[test]
    fn call_graph_block_puts_entry_and_sink_touching_edges_first() {
        let mut ctx = minimal_ctx();
        ctx.entry_points = vec![EntryPoint {
            file: "a.py".to_string(),
            function: "handler".to_string(),
            kind: EntryPointKind::Network,
            reachable_from_unauth: true,
        }];
        ctx.unsafe_sinks = vec![Sink {
            file: "c.py".to_string(),
            line: 1,
            function: "sink".to_string(),
            snippet: String::new(),
            cwe: Vec::new(),
        }];
        ctx.call_graph.insert(
            "z.py::cold_caller".to_string(),
            vec!["z.py::cold_callee".to_string()],
        );
        ctx.call_graph.insert(
            "a.py::handler".to_string(),
            vec!["b.py::helper".to_string()],
        );
        let out = call_graph_block(&ctx, Some(400));
        assert!(out[0].starts_with("CALL GRAPH (2 edges"));
        // The entry-point-touching edge sorts before the unrelated one.
        let handler_pos = out.iter().position(|l| l.contains("handler")).unwrap();
        let cold_pos = out.iter().position(|l| l.contains("cold_caller")).unwrap();
        assert!(handler_pos < cold_pos);
    }

    #[test]
    fn is_hot_does_not_bare_match_a_qualified_name_against_a_different_files_entry_point() {
        // "b.py::handler" shares a bare function name ("handler") with the
        // entry point "a.py::handler", but lives in a DIFFERENT file —
        // Python's `_hot` only bare-matches UNQUALIFIED names; a qualified
        // name must match the full `file::function` qnode exactly. A
        // prior Rust port stripped every name to bare unconditionally,
        // which would have incorrectly classified this as hot.
        let mut ctx = minimal_ctx();
        ctx.entry_points = vec![EntryPoint {
            file: "a.py".to_string(),
            function: "handler".to_string(),
            kind: EntryPointKind::Network,
            reachable_from_unauth: true,
        }];
        let sets = hot_sets(&ctx);
        assert!(is_hot("a.py::handler", &sets));
        assert!(!is_hot("b.py::handler", &sets));
        assert!(is_hot("handler", &sets));
    }

    #[test]
    fn call_graph_block_bare_unqualified_name_still_matches_by_bare_name() {
        // An unqualified (no "::") caller/callee still hot-matches via the
        // bare-name fallback — this is the one case where bare matching is
        // correct per Python's own `"::" not in caller and bare(caller) in
        // ep_bare` branch.
        let mut ctx = minimal_ctx();
        ctx.entry_points = vec![EntryPoint {
            file: "a.py".to_string(),
            function: "handler".to_string(),
            kind: EntryPointKind::Network,
            reachable_from_unauth: true,
        }];
        ctx.call_graph.insert(
            "z.py::cold_caller".to_string(),
            vec!["z.py::cold_callee".to_string()],
        );
        ctx.call_graph
            .insert("handler".to_string(), vec!["b.py::helper".to_string()]);
        let out = call_graph_block(&ctx, Some(400));
        let handler_pos = out
            .iter()
            .position(|l| l.starts_with("  - handler"))
            .unwrap();
        let cold_pos = out.iter().position(|l| l.contains("cold_caller")).unwrap();
        assert!(handler_pos < cold_pos);
    }

    #[test]
    fn call_graph_block_skips_empty_callee_lists_and_dedupes() {
        let mut ctx = minimal_ctx();
        ctx.call_graph.insert("a.py::f".to_string(), vec![]);
        ctx.call_graph.insert(
            "b.py::g".to_string(),
            vec!["c.py::h".to_string(), "c.py::h".to_string(), String::new()],
        );
        let out = call_graph_block(&ctx, Some(400));
        assert!(out[0].starts_with("CALL GRAPH (1 edges"));
        assert!(out[1].contains("c.py::h") && !out[1].matches("c.py::h").count().eq(&2));
    }

    #[test]
    fn call_graph_block_truncates_past_max_edges() {
        let mut ctx = minimal_ctx();
        for i in 0..5 {
            ctx.call_graph
                .insert(format!("caller{i}.py::f"), vec![format!("callee{i}.py::g")]);
        }
        let out = call_graph_block(&ctx, Some(2));
        assert!(out.iter().any(
            |l| l.contains("(+3 more edges truncated)") || l.contains("3 more edges truncated")
        ));
    }

    #[test]
    fn call_graph_block_full_renders_every_edge_with_no_truncation_marker() {
        let mut ctx = minimal_ctx();
        for i in 0..5 {
            ctx.call_graph
                .insert(format!("caller{i}.py::f"), vec![format!("callee{i}.py::g")]);
        }
        let out = call_graph_block(&ctx, None);
        assert!(out[0].starts_with("CALL GRAPH (5 edges"));
        assert!(!out.iter().any(|l| l.contains("truncated")));
        assert_eq!(out.len(), 6);
    }

    #[test]
    fn signatures_block_emits_entry_and_sink_with_source_excerpts() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("a.py"),
            "line0\ndef handler():\n    pass\n\n\n",
        )
        .unwrap();
        let mut ctx = minimal_ctx();
        ctx.entry_points = vec![EntryPoint {
            file: "a.py".to_string(),
            function: "handler".to_string(),
            kind: EntryPointKind::Network,
            reachable_from_unauth: false,
        }];
        let out = signatures_block(&ctx, dir.path(), 3, 60);
        assert!(!out.is_empty());
        assert!(out[1].contains("[ENTRY] a.py:2 handler()"));
    }

    #[test]
    fn signatures_block_uses_the_sink_hint_line_directly_when_in_range() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "l0\nl1\nl2\nl3\n").unwrap();
        let mut ctx = minimal_ctx();
        ctx.unsafe_sinks = vec![Sink {
            file: "a.py".to_string(),
            line: 3,
            function: "sink".to_string(),
            snippet: String::new(),
            cwe: Vec::new(),
        }];
        let out = signatures_block(&ctx, dir.path(), 1, 60);
        assert!(out[1].contains("[SINK] a.py:3 sink()"));
    }

    #[test]
    fn signatures_block_falls_back_to_text_search_when_hint_line_out_of_range() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "l0\ndef sink():\n    pass\n").unwrap();
        let mut ctx = minimal_ctx();
        ctx.unsafe_sinks = vec![Sink {
            file: "a.py".to_string(),
            line: 999,
            function: "sink".to_string(),
            snippet: String::new(),
            cwe: Vec::new(),
        }];
        let out = signatures_block(&ctx, dir.path(), 1, 60);
        assert!(out[1].contains("[SINK] a.py:2 sink()"));
    }

    #[test]
    fn signatures_block_dedupes_the_same_anchor_across_entries_and_sinks() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "def shared():\n    pass\n").unwrap();
        let mut ctx = minimal_ctx();
        ctx.entry_points = vec![EntryPoint {
            file: "a.py".to_string(),
            function: "shared".to_string(),
            kind: EntryPointKind::Network,
            reachable_from_unauth: false,
        }];
        ctx.unsafe_sinks = vec![Sink {
            file: "a.py".to_string(),
            line: 1,
            function: "shared".to_string(),
            snippet: String::new(),
            cwe: Vec::new(),
        }];
        let out = signatures_block(&ctx, dir.path(), 1, 60);
        // Both reference the same (file, anchor=0) — only one excerpt
        // header total (a body line can separately contain "shared()"
        // text, so count tagged header lines specifically, not any line
        // mentioning the function).
        assert_eq!(
            out.iter()
                .filter(|l| l.contains("[ENTRY]") || l.contains("[SINK]"))
                .count(),
            1
        );
    }

    #[test]
    fn signatures_block_returns_empty_when_nothing_can_be_emitted() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = minimal_ctx();
        assert!(signatures_block(&ctx, dir.path(), 1, 60).is_empty());
    }

    #[test]
    fn signatures_block_unreadable_file_is_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let mut ctx = minimal_ctx();
        ctx.entry_points = vec![EntryPoint {
            file: "missing.py".to_string(),
            function: "f".to_string(),
            kind: EntryPointKind::Network,
            reachable_from_unauth: false,
        }];
        assert!(signatures_block(&ctx, dir.path(), 1, 60).is_empty());
    }

    #[test]
    fn signatures_block_an_llm_annotated_path_that_escapes_the_repo_root_is_skipped_not_read() {
        let dir = tempfile::tempdir().unwrap();
        let mut ctx = minimal_ctx();
        ctx.entry_points = vec![EntryPoint {
            file: "../outside.py".to_string(),
            function: "f".to_string(),
            kind: EntryPointKind::Network,
            reachable_from_unauth: false,
        }];
        assert!(signatures_block(&ctx, dir.path(), 1, 60).is_empty());
    }

    #[test]
    fn signatures_block_skips_an_entry_whose_function_appears_nowhere_in_the_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "print('nothing relevant here')\n").unwrap();
        let mut ctx = minimal_ctx();
        ctx.entry_points = vec![EntryPoint {
            file: "a.py".to_string(),
            function: "totally_absent".to_string(),
            kind: EntryPointKind::Network,
            reachable_from_unauth: false,
        }];
        assert!(signatures_block(&ctx, dir.path(), 1, 60).is_empty());
    }

    #[test]
    fn signatures_block_stops_at_the_cap_and_appends_a_marker() {
        let dir = tempfile::tempdir().unwrap();
        let mut ctx = minimal_ctx();
        for i in 0..3 {
            let name = format!("f{i}.py");
            std::fs::write(dir.path().join(&name), format!("def fn{i}():\n    pass\n")).unwrap();
            ctx.entry_points.push(EntryPoint {
                file: name,
                function: format!("fn{i}"),
                kind: EntryPointKind::Network,
                reachable_from_unauth: false,
            });
        }
        let out = signatures_block(&ctx, dir.path(), 1, 2);
        assert!(out.iter().any(|l| l.contains("capped at 2")));
    }

    #[test]
    fn signatures_block_truncates_long_lines_to_160_chars() {
        let dir = tempfile::tempdir().unwrap();
        let long_line = "x".repeat(300);
        std::fs::write(
            dir.path().join("a.py"),
            format!("def f():\n    {long_line}\n"),
        )
        .unwrap();
        let mut ctx = minimal_ctx();
        ctx.entry_points = vec![EntryPoint {
            file: "a.py".to_string(),
            function: "f".to_string(),
            kind: EntryPointKind::Network,
            reachable_from_unauth: false,
        }];
        let out = signatures_block(&ctx, dir.path(), 1, 60);
        let body_line = &out[2];
        assert!(body_line.trim().len() <= 160);
    }

    #[test]
    fn function_sites_block_renders_up_to_three_deduped_sites_with_a_span() {
        let mut ctx = minimal_ctx();
        ctx.call_graph_files.insert(
            "handler".to_string(),
            vec![
                "a.py:1".to_string(),
                "a.py:2".to_string(), // same file as the first — deduped away
                "b.py:5".to_string(),
                "c.py:9".to_string(),
                "d.py:1".to_string(), // 4th distinct file — dropped by the take(3)
            ],
        );
        let out = function_sites_block(&ctx, 120);
        assert!(out[0].starts_with("FUNCTION SITES"));
        assert!(out[1].starts_with("  - handler @ a.py:1, b.py:5, c.py:9"));
        assert!(!out[1].contains("d.py"));
    }

    #[test]
    fn function_sites_block_looks_up_def_spans_by_the_bare_key_matching_python() {
        // Faithful port of a real Python quirk: `call_graph_files` is
        // keyed by bare function name, `def_spans` by qualified
        // `"file::name"` — so a `def_spans` entry keyed by the SAME bare
        // string (never a real qnode in practice) is what actually
        // renders a span suffix here, exactly mirroring what the real
        // Python product does (or rather, doesn't) render.
        let mut ctx = minimal_ctx();
        ctx.call_graph_files
            .insert("handler".to_string(), vec!["a.py:1".to_string()]);
        ctx.def_spans.insert("handler".to_string(), (1, 4));
        ctx.def_spans.insert("a.py::handler".to_string(), (99, 100));
        let out = function_sites_block(&ctx, 120);
        assert!(out[1].contains("lines 1-4"));
        assert!(!out[1].contains("99-100"));
    }

    #[test]
    fn function_sites_block_skips_a_function_with_no_sites() {
        let mut ctx = minimal_ctx();
        ctx.call_graph_files.insert("orphan".to_string(), vec![]);
        assert!(function_sites_block(&ctx, 120).is_empty());
    }

    #[test]
    fn function_sites_block_stops_at_the_cap_and_appends_a_marker() {
        let mut ctx = minimal_ctx();
        for i in 0..5 {
            ctx.call_graph_files
                .insert(format!("f{i}"), vec![format!("file{i}.py:1")]);
        }
        let out = function_sites_block(&ctx, 2);
        assert!(out
            .iter()
            .any(|l| l.contains("3 more function sites truncated")));
    }

    #[test]
    fn threat_model_compact_prompt_block_caps_every_section_and_marks_truncation() {
        let tm = ThreatModel {
            system_context: "x".repeat(10),
            assets: vec![
                Asset {
                    name: "A".to_string(),
                    description: "d".to_string(),
                    sensitivity: Sensitivity::High,
                };
                3
            ],
            trust_boundaries: vec![
                TrustBoundary {
                    entry_point: "api".to_string(),
                    crossing: "x".to_string(),
                    reachable_assets: vec!["DB".to_string()],
                },
                TrustBoundary {
                    entry_point: "cli".to_string(),
                    crossing: "y".to_string(),
                    reachable_assets: Vec::new(),
                },
                TrustBoundary {
                    entry_point: "batch".to_string(),
                    crossing: "z".to_string(),
                    reachable_assets: Vec::new(),
                },
            ],
            threats: vec![
                Threat {
                    id: "T1".to_string(),
                    threat: "SQLi".to_string(),
                    actor: Actor::RemoteUnauth,
                    surface: "api".to_string(),
                    asset: "DB".to_string(),
                    impact: Impact::High,
                    likelihood: Likelihood::Likely,
                    controls: "waf".to_string(),
                    evidence: String::new(),
                },
                Threat {
                    id: "T2".to_string(),
                    threat: "XSS".to_string(),
                    actor: Actor::RemoteUnauth,
                    surface: "api".to_string(),
                    asset: "DB".to_string(),
                    impact: Impact::Low,
                    likelihood: Likelihood::Rare,
                    controls: "none".to_string(),
                    evidence: String::new(),
                },
            ],
            open_questions: Vec::new(),
        };
        let block = threat_model_compact_prompt_block(&tm, 2, 2, 1, 5);
        assert!(block.contains("System context:\nxxxxx"));
        assert!(!block.contains("xxxxxxxxxx"));
        assert!(block.contains("Assets (2/3):"));
        assert!(block.contains("  …(truncated)"));
        assert!(block.contains("Trust boundaries (2/3):"));
        assert!(block.contains("→ assets: DB"));
        assert!(block.contains("→ assets: -"));
        assert!(block.contains("Ranked threats (1/2):"));
        assert!(block.contains(", controls: waf)"));
        // All three truncation markers fire (assets, trust boundaries,
        // threats).
        assert_eq!(block.matches("…(truncated)").count(), 3);
    }

    #[test]
    fn threat_model_compact_prompt_block_omits_untruncated_marker_when_under_cap() {
        let tm = ThreatModel {
            system_context: "ctx".to_string(),
            assets: vec![Asset {
                name: "DB".to_string(),
                description: "data".to_string(),
                sensitivity: Sensitivity::High,
            }],
            ..Default::default()
        };
        let block = threat_model_compact_prompt_block(&tm, 8, 12, 12, 2500);
        assert!(block.contains("Assets (1/1):"));
        assert!(!block.contains("…(truncated)"));
    }

    #[test]
    fn to_decompose_prompt_block_omits_all_files_and_module_file_listings() {
        let dir = tempfile::tempdir().unwrap();
        let mut ctx = minimal_ctx();
        ctx.modules = vec![ModuleInfo {
            name: "auth".to_string(),
            files: vec!["a.py".to_string()],
            loc: 10,
            purpose: "handles auth".to_string(),
        }];
        ctx.all_files = vec!["a.py".to_string(), "b.py".to_string()];
        let block = to_decompose_prompt_block(&ctx, dir.path());
        assert!(block.contains("MODULES (1):"));
        assert!(block.contains("  - auth (10 loc): handles auth"));
        // Neither the repo-wide file inventory nor per-module file
        // bullets (both present in `to_prompt_block`) appear here.
        assert!(!block.contains("ALL FILES"));
        assert!(!block.contains("• a.py"));
    }

    #[test]
    fn to_decompose_prompt_block_includes_function_sites_and_full_call_graph() {
        let dir = tempfile::tempdir().unwrap();
        let mut ctx = minimal_ctx();
        ctx.call_graph_files
            .insert("handler".to_string(), vec!["a.py:1".to_string()]);
        for i in 0..5 {
            ctx.call_graph
                .insert(format!("caller{i}.py::f"), vec![format!("callee{i}.py::g")]);
        }
        let block = to_decompose_prompt_block(&ctx, dir.path());
        assert!(block.contains("FUNCTION SITES"));
        assert!(block.contains("CALL GRAPH (5 edges"));
        assert!(!block.contains("truncated"));
    }

    #[test]
    fn to_decompose_prompt_block_caps_design_controls_at_40() {
        let dir = tempfile::tempdir().unwrap();
        let mut ctx = minimal_ctx();
        ctx.design_controls = (0..45)
            .map(|i| Control {
                name: format!("C{i}"),
                kind: ControlKind::Other,
                protects: Vec::new(),
                notes: String::new(),
            })
            .collect();
        let block = to_decompose_prompt_block(&ctx, dir.path());
        assert!(block.contains("DESIGN CONTROLS (45):"));
        assert!(block.contains("C39"));
        assert!(!block.contains("C40"));
    }

    #[test]
    fn to_decompose_prompt_block_includes_cves_protected_controls_app_profile_and_a_non_unauth_entry_point(
    ) {
        let dir = tempfile::tempdir().unwrap();
        let mut ctx = minimal_ctx();
        ctx.entry_points = vec![EntryPoint {
            file: "a.py".to_string(),
            function: "internal_handler".to_string(),
            kind: EntryPointKind::Network,
            reachable_from_unauth: false,
        }];
        ctx.known_cves = vec![Cve {
            id: "CVE-1".to_string(),
            summary: "a bug".to_string(),
            affected_files: Vec::new(),
            cvss: None,
            patched: false,
        }];
        ctx.design_controls = vec![Control {
            name: "WAF".to_string(),
            kind: ControlKind::Auth,
            protects: vec!["a.py".to_string()],
            notes: String::new(),
        }];
        ctx.app_profile = Some(AppProfile {
            application_id: "APP1".to_string(),
            name: "App".to_string(),
            externally_facing: true,
            pci_scoped: false,
            processes_pan: false,
            pii: false,
            source: "cmdb".to_string(),
        });
        let block = to_decompose_prompt_block(&ctx, dir.path());
        assert!(block.contains("  - network: internal_handler @ a.py"));
        assert!(!block.contains("internal_handler @ a.py [UNAUTH-REACHABLE]"));
        assert!(block.contains("KNOWN CVEs (1)"));
        assert!(block.contains("CVE-1: a bug"));
        assert!(block.contains("DESIGN CONTROLS (1):"));
        assert!(block.contains("[auth] WAF → protects: a.py"));
        assert!(block.contains("CMDB APPLICATION PROFILE:"));
    }

    #[test]
    fn to_decompose_prompt_block_truncates_notes_at_3000_chars() {
        let dir = tempfile::tempdir().unwrap();
        let mut ctx = minimal_ctx();
        ctx.notes = "n".repeat(3100);
        let block = to_decompose_prompt_block(&ctx, dir.path());
        let notes_section = block.split("OPUS NOTES:\n").nth(1).unwrap();
        assert_eq!(notes_section.len(), 3000);
    }

    #[test]
    fn to_decompose_prompt_block_includes_compliance_guidance_when_present() {
        let dir = tempfile::tempdir().unwrap();
        let mut ctx = minimal_ctx();
        ctx.compliance_guidance = "Prioritize PCI-DSS Req 6 findings.".to_string();
        let block = to_decompose_prompt_block(&ctx, dir.path());
        assert!(block.contains("COMPLIANCE GUIDANCE:\nPrioritize PCI-DSS Req 6 findings."));
    }

    #[test]
    fn to_decompose_prompt_block_uses_the_compact_threat_model_renderer() {
        let dir = tempfile::tempdir().unwrap();
        let mut ctx = minimal_ctx();
        ctx.threat_model = Some(ThreatModel {
            system_context: "ctx here".to_string(),
            assets: vec![
                Asset {
                    name: "A".to_string(),
                    description: "d".to_string(),
                    sensitivity: Sensitivity::High,
                };
                10
            ],
            ..Default::default()
        });
        let block = to_decompose_prompt_block(&ctx, dir.path());
        assert!(block.contains("THREAT MODEL:"));
        // The compact renderer's "kept/total" counter is the observable
        // signature that distinguishes it from the uncapped renderer.
        assert!(block.contains("Assets (8/10):"));
    }

    #[test]
    fn to_decompose_prompt_block_lists_changed_files_when_diff_scope_is_active() {
        let dir = tempfile::tempdir().unwrap();
        let mut ctx = minimal_ctx();
        ctx.all_files = vec!["a.py".to_string(), "b.py".to_string()];
        ctx.diff_scope_active = true;
        ctx.changed_files = std::collections::BTreeMap::from([(
            "a.py".to_string(),
            std::collections::BTreeSet::from([1i64]),
        )]);
        let block = to_decompose_prompt_block(&ctx, dir.path());
        assert!(block.contains("PRIORITIZE THESE FILES (1)"));
        assert!(block.contains("  - a.py"));
    }

    #[test]
    fn to_decompose_prompt_block_still_says_diff_scoped_with_an_empty_changed_set() {
        // A rename-only PR. The hint used to disappear here, leaving the
        // strategist a prompt identical to a full-repo scan's.
        let dir = tempfile::tempdir().unwrap();
        let mut ctx = minimal_ctx();
        ctx.all_files = vec!["a.py".to_string(), "b.py".to_string()];
        ctx.diff_scope_active = true;
        let block = to_decompose_prompt_block(&ctx, dir.path());
        assert!(block.contains("PRIORITIZE THESE FILES (0)"));
    }

    #[test]
    fn to_decompose_prompt_block_omits_optional_sections_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = minimal_ctx();
        let block = to_decompose_prompt_block(&ctx, dir.path());
        assert!(!block.contains("FUNCTION SITES"));
        assert!(!block.contains("SIGNATURES"));
        assert!(!block.contains("CALL GRAPH"));
        assert!(!block.contains("KNOWN CVEs"));
        assert!(!block.contains("DESIGN CONTROLS"));
        assert!(!block.contains("CMDB APPLICATION PROFILE"));
        assert!(!block.contains("THREAT MODEL"));
        assert!(!block.contains("OPUS NOTES"));
        assert!(!block.contains("PRIORITIZE THESE FILES"));
        assert!(!block.contains("COMPLIANCE GUIDANCE"));
    }
}
