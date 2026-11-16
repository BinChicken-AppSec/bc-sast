use std::collections::{BTreeMap, HashSet};
use std::sync::LazyLock;

use appsec_model::{Chunk, ContextPackage, TaintEvidencePath, TaintTransferEdge};

use crate::code_loading::truncate_chars;
use crate::hints::{hint_key_for_path, hints_for};
use crate::wire::chunk_size_str;

const QUALITY_BAR: &str = r"QUALITY BAR:
- Trace data flow: WHERE untrusted input enters → HOW it reaches the dangerous
  operation. No confirmed data flow = no finding.
- Verify reachability from external input (not dead code, not test-only).
- Check for upstream protections (validation, sanitization, framework
  safeguards) BEFORE reporting.
- Missing authorization/authentication: FLAG it, do not adjudicate it. You
  have no file access — only this slice and the neighbor excerpts — so the
  file that REGISTERS a route is usually not in front of you. If the
  registration IS in the code you were given and the route sits behind
  framework middleware, a filter or an annotation (Laravel
  `->middleware('auth')`, Ktor `authenticate { }`, Rails `before_action`,
  axum `.route_layer(...)`, Spring `@PreAuthorize`, ASP.NET `[Authorize]`),
  the check already runs on every request and the handler's own silence is
  not a finding — report it only if you can show the guard is bypassable or
  not registered on this route. If the registration site is NOT in the code
  you were given, still report it: say so in `preconditions` (for example
  `route registration not visible in this slice; guard status unverified`)
  and set `confidence` to 0.6 — below a finding you fully verified, but NOT
  under 0.6, which is where the pre-verify gate drops a finding before any
  verifier sees it. A verifier with repository access opens the registration
  file and drops the finding if a guard is there. An unverifiable guard
  lowers confidence; it is never a reason to stay silent.
  A guard limits WHO can exploit a flaw, not whether it exists: report
  injection, path traversal, SSRF, deserialization, command execution and
  every other class regardless of the route's guard.
- Write a concrete exploit: specific input, specific impact. If you can't,
  drop the finding.

For each file, trace the logic — don't just scan for patterns:
- What does the code assume about its inputs?
- What happens at boundary conditions?
- Are there check-then-act patterns where state could change between check
  and action?
- Do error paths leak state or skip validation?

CROSS-CUTTING (applies to docs/config/non-code files in your scope too):
- Insecure-transport directives committed to the repo (CWE-295): grep your
  scope for sslVerify=false, SSL_VERIFY_NONE, verify=False, verify_ssl: false,
  rejectUnauthorized: false, InsecureSkipVerify, NODE_TLS_REJECT_UNAUTHORIZED=0,
  curl -k / --insecure, TrustAllCerts, ALLOW_ALL_HOSTNAME_VERIFIER. A README
  or setup script that INSTRUCTS users to disable TLS verification is a
  reportable supply-chain finding even though it is not executable code.
- Output-side injection: data the program WRITES (CSV cells, HTML reports,
  log lines later parsed by another tool) is a sink. Hunt for unescaped
  emission, not just unescaped ingestion.";

const OUTPUT_SCHEMA: &str = r#"Respond with ONLY a JSON object (no prose before or after):
{
  "findings": [
    {
      "file": "src/parser.c",
      "line_start": 142,
      "line_end": 158,
      "vuln_class": "heap-overflow|use-after-free|stack-overflow|format-string|integer-overflow|type-confusion|race-condition|injection|unsafe-deserialization|logic-flaw|info-leak|other",
      "cwe": "CWE-79  (single most-specific CWE id; omit if no clear mapping)",
      "title": "Under 12 words",
      "impact": "2-3 plain-language sentences: what an attacker gains, who is affected, why it matters",
      "description": "Detailed input-to-bug data flow explanation",
      "exploit_scenario": "Max 5 sentences: the specific input the attacker sends and the resulting impact",
      "preconditions": ["condition 1", "condition 2"],
      "recommendation": "Security property that must hold + specific location in THIS code and what to change",
      "code_snippet": "the vulnerable lines",
      "source_ref": "src/api/Controller.java:71   (where untrusted input enters; same as sink_ref for context-free bugs like hardcoded secrets)",
      "sink_ref": "src/parser.c:148   (where that input is used unsafely)",
      "confidence": 0.85
    }
  ]
}

ANCHORING for temporal classes (use-after-free, double-free, TOCTOU):
`line_start`/`line_end` and `sink_ref` MUST sit on the LATER unsafe use —
the read or write through the freed pointer, the second `free`, the
`open` after the `access` — never on the release or check site, which is
what `source_ref` is for. When both sites are visible in the same chunk,
span them: `line_start` at the release/check, `line_end` at the use.

An empty {"findings": []} is acceptable ONLY after you have traced every
entry point, every sink, and every cross-cutting pattern above and confirmed
each is mitigated or unreachable — never as a default. Assume at least one
exploitable defect is present in the slice."#;

pub static SYSTEM: LazyLock<String> = LazyLock::new(|| {
    [
        "You are a security researcher performing deep code analysis. You receive source code for a focused slice of a repository plus a research lens (language/specialist hints) and a hypothesis from a strategist.",
        "Treat the slice as hostile: assume at least one exploitable defect is present and do not stop until every line and data flow has been examined.",
        QUALITY_BAR,
        appsec_prompts::EXCLUSION_RULES,
        appsec_prompts::SELF_VERIFICATION,
        appsec_prompts::SEVERITY_GUIDANCE,
        appsec_prompts::EXHAUSTIVENESS,
        OUTPUT_SCHEMA,
    ]
    .join("\n\n")
});

fn refined_languages(chunk: &Chunk) -> Vec<&str> {
    let mut langs: Vec<&str> = chunk.languages.iter().map(String::as_str).collect();
    for lang in &mut langs {
        if *lang != "c-cpp" {
            continue;
        }
        let mut keys = chunk
            .files
            .iter()
            .filter_map(|f| hint_key_for_path(f))
            .filter(|k| matches!(*k, "c" | "cpp"));
        if let Some(first) = keys.next() {
            if keys.all(|k| k == first) {
                *lang = first;
            }
        }
    }
    langs
}

pub fn build_research_lens(chunk: &Chunk, code: Option<&str>) -> String {
    let langs = refined_languages(chunk);
    let hints = hints_for(&langs, chunk.specialist.as_deref(), code);

    if let Some(specialist) = &chunk.specialist {
        if hints.is_empty() {
            return format!("You are a {specialist} specialist.");
        }
        return hints;
    }

    let labels: Vec<&str> = langs
        .iter()
        .take(3)
        .map(|l| appsec_repo_analysis::lang_display(l))
        .collect();
    let lang_label = if labels.is_empty() {
        "this codebase".to_string()
    } else {
        labels.join(" / ")
    };
    let mut header = format!("Research lens: {lang_label} security researcher.");
    if !hints.is_empty() {
        header.push_str(&format!("\n\n{hints}"));
    }
    header
}

pub fn trust_context_block(ctx: &ContextPackage) -> String {
    let ap = ctx.app_profile.as_ref();
    let tm = ctx.threat_model.as_ref();
    if ap.is_none() && tm.is_none() {
        return String::new();
    }

    let mut lines =
        vec!["TRUST CONTEXT (use this to decide if input is attacker-controlled):".to_string()];

    if let Some(ap) = ap {
        let facing = if ap.externally_facing {
            "YES"
        } else {
            "NO — internal only"
        };
        lines.push(format!("  - Externally facing: {facing}"));
        let mut sens = Vec::new();
        if ap.pci_scoped {
            sens.push("PCI");
        }
        if ap.processes_pan {
            sens.push("PAN");
        }
        if ap.pii {
            sens.push("PII");
        }
        if !sens.is_empty() {
            lines.push(format!("  - Data sensitivity: {}", sens.join(", ")));
        }
    }

    if let Some(tm) = tm {
        if !tm.system_context.is_empty() {
            let first_para = tm.system_context.split("\n\n").next().unwrap_or("");
            lines.push(format!("  - System: {}", truncate_chars(first_para, 400)));
        }
        if !tm.trust_boundaries.is_empty() {
            lines.push(
                "  - UNTRUSTED entry points (only these cross a trust boundary):".to_string(),
            );
            for b in tm.trust_boundaries.iter().take(8) {
                lines.push(format!("      • {}", b.entry_point));
            }
        }
    }

    lines.push(
        "  - Operator argv/env on the operator's OWN host is TRUSTED. But CI job parameters, \
scheduler args, shared config/CSV/test-data files editable by other principals, and \
framework-overridable variables ARE attack surface even on an internal app — report those \
(typically LOW). See OUT-OF-SCOPE rule A."
            .to_string(),
    );
    lines.join("\n") + "\n"
}

pub fn cve_block(chunk: &Chunk) -> String {
    if chunk.related_cves.is_empty() {
        return String::new();
    }
    let body: Vec<String> = chunk
        .related_cves
        .iter()
        .map(|id| format!("  - {id}"))
        .collect();
    format!(
        "\nRELATED CVEs (hunt for variants/siblings):\n{}\n",
        body.join("\n")
    )
}

fn compliance_guidance_block(ctx: &ContextPackage) -> String {
    if ctx.compliance_guidance.is_empty() {
        return String::new();
    }
    format!("\nCOMPLIANCE GUIDANCE:\n{}\n", ctx.compliance_guidance)
}

pub fn build_prompt(chunk: &Chunk, ctx: &ContextPackage, code: &str) -> String {
    format!(
        "{}\nSOURCE CODE:\n{code}\n\nAnalyze this code and respond with ONLY the JSON findings object.",
        prompt_head(chunk, ctx, code),
    )
}

pub fn build_shard_prompt(chunk: &Chunk, ctx: &ContextPackage, code: &str) -> String {
    format!(
        "{}\nAnalyze this code and respond with ONLY the JSON findings object.",
        prompt_head(chunk, ctx, code),
    )
}

pub fn shard_source_block(code: &str) -> String {
    format!("SOURCE CODE:\n{code}\n\n")
}

fn prompt_head(chunk: &Chunk, ctx: &ContextPackage, code: &str) -> String {
    let focus = if chunk.focus_entry_points.is_empty() {
        "(none)".to_string()
    } else {
        chunk.focus_entry_points.join(", ")
    };
    format!(
        "RESEARCH LENS:\n{}\n\nCHUNK: {}  SIZE: {}\nHYPOTHESIS: {}\nFOCUS ENTRY POINTS: {}\n{}{}",
        build_research_lens(chunk, Some(code)),
        chunk.id,
        chunk_size_str(chunk.size),
        chunk.hypothesis,
        focus,
        cve_block(chunk),
        compliance_guidance_block(ctx),
    )
}

fn norm_rel_path(path: &str) -> String {
    let mut norm = path.trim().replace('\\', "/");
    while let Some(rest) = norm.strip_prefix("./") {
        norm = rest.to_string();
    }
    norm
}

fn parse_ref_file_line(reference: &str) -> (String, Option<i64>) {
    let raw = reference.trim();
    if raw.is_empty() {
        return (String::new(), None);
    }
    if let Some((f, _tail)) = raw.split_once("::") {
        return (norm_rel_path(f), None);
    }
    if let Some((f, ln)) = raw.rsplit_once(':') {
        if !f.is_empty() && !ln.is_empty() && ln.chars().all(|c| c.is_ascii_digit()) {
            let line: i64 = ln.parse().unwrap_or(1).max(1);
            return (norm_rel_path(f), Some(line));
        }
    }
    (norm_rel_path(raw), None)
}

fn short_symbol(symbol: &str) -> String {
    let s = symbol.trim();
    if s.is_empty() {
        return "(unknown)".to_string();
    }
    if s.chars().count() <= 64 {
        return s.to_string();
    }
    let truncated: String = s.chars().take(63).collect();
    format!("{truncated}…")
}

const RESPONSE_SINK_PATTERNS: &[&str] = &[
    "JsonResponse",
    "ResponseEntity",
    "Ok",
    "Created",
    "BadRequest",
    "Conflict",
    "Response",
    "HttpResponse",
    "JsonResult",
    "ViewResult",
    "ContentResult",
    "DirectResult",
    "StatusCodeResult",
    "ObjectResult",
    "ApiResponse",
    "render",
    "json",
    "jsonify",
    "dumps",
    "to_json",
    "HttpServletResponse",
    "ServletResponse",
    "PrintWriter",
    "OutputStream",
];

fn response_type_for(sink_sym: &str) -> &'static str {
    let lower = sink_sym.to_lowercase();
    if ["html", "render", "template"]
        .iter()
        .any(|p| lower.contains(p))
    {
        "html"
    } else if ["json", "jsonify", "to_json"]
        .iter()
        .any(|p| lower.contains(p))
    {
        "json"
    } else if lower.contains("xml") {
        "xml"
    } else {
        "text"
    }
}

const KEY_TRANSFER_KINDS: &[&str] = &[
    "assign",
    "arg_to_param",
    "return_to_local",
    "local_to_sink",
    "return_to_sink",
];

fn best_matching_evidence<'a>(
    chunk: &Chunk,
    evidence_paths: &'a [TaintEvidencePath],
) -> Option<&'a TaintEvidencePath> {
    let (src_file, _) = parse_ref_file_line(&chunk.source_ref);
    let (sink_file, sink_line) = parse_ref_file_line(&chunk.sink_ref);
    let chunk_path: HashSet<&str> = chunk.path_funcs.iter().map(String::as_str).collect();

    let mut best: Option<&TaintEvidencePath> = None;
    let mut best_score = 0i64;
    for ev in evidence_paths {
        if ev.edges.is_empty() {
            continue;
        }
        let (ev_src_file, _) = parse_ref_file_line(&ev.source_ref);
        let (ev_sink_file, ev_sink_line) = parse_ref_file_line(&ev.sink_ref);
        let mut score = 0i64;
        if !src_file.is_empty() && src_file == ev_src_file {
            score += 3;
        }
        if !sink_file.is_empty() && sink_file == ev_sink_file {
            score += 3;
        }
        if sink_line.is_some() && sink_line == ev_sink_line {
            score += 2;
        }
        if !chunk_path.is_empty() && !ev.path_funcs.is_empty() {
            let overlap = ev
                .path_funcs
                .iter()
                .filter(|f| chunk_path.contains(f.as_str()))
                .count();
            score += (overlap as i64).min(3);
        }
        if score > best_score {
            best = Some(ev);
            best_score = score;
        }
    }
    best
}

pub fn compact_taint_evidence_block(chunk: &Chunk, ctx: &ContextPackage) -> String {
    if ctx.seed_taint_evidence.is_empty() {
        return String::new();
    }
    let Some(best) = best_matching_evidence(chunk, &ctx.seed_taint_evidence) else {
        return String::new();
    };
    let edges = &best.edges;
    let (first_edge, last_edge) = (&edges[0], edges.last().expect("edges is non-empty"));

    let mut transfer_counts: BTreeMap<&str, usize> = BTreeMap::new();
    for edge in edges {
        if KEY_TRANSFER_KINDS.contains(&edge.transfer_kind.as_str()) {
            *transfer_counts
                .entry(edge.transfer_kind.as_str())
                .or_insert(0) += 1;
        }
    }
    if transfer_counts.is_empty() {
        return String::new();
    }

    let source_edge = edges
        .iter()
        .find(|e| e.transfer_kind == "source")
        .unwrap_or(first_edge);
    let sink_edge = edges
        .iter()
        .rev()
        .find(|e| matches!(e.transfer_kind.as_str(), "local_to_sink" | "return_to_sink"))
        .unwrap_or(last_edge);

    let transfer_summary = KEY_TRANSFER_KINDS
        .iter()
        .filter_map(|k| transfer_counts.get(k).map(|c| format!("{k}:{c}")))
        .collect::<Vec<_>>()
        .join(", ");

    let mut sink_sym = short_symbol(&sink_edge.dst.symbol);
    if sink_sym == "(unknown)" {
        sink_sym = short_symbol(&sink_edge.src.symbol);
    }

    let mut extra_lines: Vec<String> = Vec::new();

    let sanitize_edges: Vec<&TaintTransferEdge> = edges
        .iter()
        .filter(|e| e.transfer_kind == "sanitize")
        .collect();
    if let Some(san_e) = sanitize_edges.first() {
        let fn_name = appsec_repo_analysis::q_name(&san_e.function_qnode);
        let san_sym = if !fn_name.is_empty() {
            fn_name
        } else {
            short_symbol(&san_e.dst.symbol)
        };
        extra_lines.push(format!("  SANITIZED via              : {san_sym}"));
    }

    let field_edges: Vec<&TaintTransferEdge> = edges
        .iter()
        .filter(|e| matches!(e.transfer_kind.as_str(), "field_write" | "field_read"))
        .collect();
    if !field_edges.is_empty() {
        let fw = field_edges
            .iter()
            .filter(|e| e.transfer_kind == "field_write")
            .count();
        let fr = field_edges
            .iter()
            .filter(|e| e.transfer_kind == "field_read")
            .count();
        let mut parts = Vec::new();
        if fw > 0 {
            parts.push(format!("field_write:{fw}"));
        }
        if fr > 0 {
            parts.push(format!("field_read:{fr}"));
        }
        extra_lines.push(format!(
            "  FIELD FLOW                 : {}",
            parts.join(", ")
        ));
    }

    let container_edges: Vec<&TaintTransferEdge> = edges
        .iter()
        .filter(|e| matches!(e.transfer_kind.as_str(), "container_put" | "container_get"))
        .collect();
    if !container_edges.is_empty() {
        let cp = container_edges
            .iter()
            .filter(|e| e.transfer_kind == "container_put")
            .count();
        let cg = container_edges
            .iter()
            .filter(|e| e.transfer_kind == "container_get")
            .count();
        let mut parts = Vec::new();
        if cp > 0 {
            parts.push(format!("container_put:{cp}"));
        }
        if cg > 0 {
            parts.push(format!("container_get:{cg}"));
        }
        extra_lines.push(format!(
            "  CONTAINER FLOW             : {}",
            parts.join(", ")
        ));
    }

    let condition_edges: Vec<&TaintTransferEdge> = edges
        .iter()
        .filter(|e| e.transfer_kind == "condition")
        .collect();
    if let Some(cond_e) = condition_edges.first() {
        let cond_text = cond_e
            .condition_text
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or("(unknown)");
        let cond_conf = cond_e.confidence.as_deref().unwrap_or("high");
        extra_lines.push(format!(
            "  CONDITION GATE             : [{cond_text}] (confidence: {cond_conf})"
        ));
    }

    let reflect_edges: Vec<&TaintTransferEdge> = edges
        .iter()
        .filter(|e| e.transfer_kind == "reflect")
        .collect();
    if let Some(ref_e) = reflect_edges.first() {
        let call_type = ref_e.call_type.as_deref().unwrap_or("reflect");
        let ref_conf = ref_e.confidence.as_deref().unwrap_or("medium");
        let targets = ref_e.reflected_targets.as_deref().unwrap_or(&[]);
        if let Some(first) = targets.first() {
            let first_s = short_symbol(first);
            let targets_str = if let Some(second) = targets.get(1) {
                let second_s = short_symbol(second);
                let remaining = targets.len() - 2;
                if remaining > 0 {
                    format!("{first_s}, {second_s} +{remaining} more")
                } else {
                    format!("{first_s}, {second_s}")
                }
            } else {
                first_s
            };
            extra_lines.push(format!(
                "  REFLECT EDGE               : [{call_type}] → {targets_str} (confidence: {ref_conf}, speculative)"
            ));
        } else {
            extra_lines.push(format!(
                "  REFLECT EDGE               : [{call_type}] (confidence: {ref_conf}, speculative)"
            ));
        }
    }

    let framework_edges: Vec<&TaintTransferEdge> = edges
        .iter()
        .filter(|e| e.transfer_kind == "framework")
        .collect();
    if let Some(fw_e) = framework_edges.first() {
        let framework = fw_e.framework.as_deref().unwrap_or("framework");
        let marker_name = fw_e.marker_type.as_deref().unwrap_or("marker");
        let fw_conf = fw_e.confidence.as_deref().unwrap_or("high");
        extra_lines.push(format!(
            "  FRAMEWORK SOURCE           : [{framework}] {marker_name} (confidence: {fw_conf})"
        ));
    }

    let sink_sym_for_response = short_symbol(&sink_edge.dst.symbol);
    if RESPONSE_SINK_PATTERNS.contains(&sink_sym_for_response.as_str()) {
        let response_type = response_type_for(&sink_sym_for_response);
        extra_lines.push(format!(
            "  RESPONSE OUTPUT            : {sink_sym_for_response} (type: {response_type})"
        ));
    }

    extra_lines.truncate(6);
    let extra_block: String = extra_lines.iter().map(|l| format!("{l}\n")).collect();

    let mut annotation_lines: Vec<String> = Vec::new();
    if let Some(cond_e) = condition_edges.first() {
        let cond_text = cond_e
            .condition_text
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or("(unknown)");
        annotation_lines.push(format!(
            "  NOTE: Path is gated by condition: {cond_text}. If condition is false, taint is neutralized."
        ));
    }
    if let Some(ref_e) = reflect_edges.first() {
        let targets = ref_e.reflected_targets.as_deref().unwrap_or(&[]);
        let target_str = targets
            .first()
            .map(|t| short_symbol(t))
            .unwrap_or_else(|| "(unresolved)".to_string());
        annotation_lines.push(format!(
            "  NOTE: Path involves reflection to {target_str}. This is a speculative path based on static analysis."
        ));
    }
    if let Some(fw_e) = framework_edges.first() {
        let fw_framework = fw_e.framework.as_deref().unwrap_or("framework");
        annotation_lines.push(format!(
            "  NOTE: Source is framework-injected ({fw_framework}). Parameters are automatically tainted via framework binding."
        ));
    }
    if RESPONSE_SINK_PATTERNS.contains(&sink_edge.dst.symbol.as_str())
        || RESPONSE_SINK_PATTERNS.contains(&short_symbol(&sink_edge.dst.symbol).as_str())
    {
        annotation_lines.push(
            "  NOTE: Output flows to response object. Risk: XSS if data not escaped, or injection if response type is HTML/XML/JSON.".to_string(),
        );
    }
    let annotation_block: String = annotation_lines.iter().map(|l| format!("{l}\n")).collect();

    format!(
        "\nSTRUCTURED TAINT EVIDENCE (compact)\n  origin tainted symbol : {}\n  transfer edges kinds  : {transfer_summary}\n  sink-consuming symbol : {sink_sym}\n{extra_block}{annotation_block}",
        short_symbol(&source_edge.src.symbol),
    )
}

pub fn build_confirm_refute_prompt(
    chunk: &Chunk,
    ctx: &ContextPackage,
    code: &str,
    sliced: bool,
) -> String {
    let (src_file, src_fn) = match chunk.source_ref.rsplit_once("::") {
        Some((f, n)) => (f.to_string(), n.to_string()),
        None => (String::new(), chunk.source_ref.clone()),
    };
    let cwe = if chunk.sink_cwe.is_empty() {
        "(infer from sink)".to_string()
    } else {
        chunk.sink_cwe.join(", ")
    };
    let hop_names: Vec<String> = chunk
        .path_funcs
        .iter()
        .map(|n| appsec_repo_analysis::q_name(n))
        .collect();
    let hops = if hop_names.is_empty() {
        "(direct)".to_string()
    } else {
        hop_names.join(" -> ")
    };
    let evidence_block = compact_taint_evidence_block(chunk, ctx);
    let kb_block =
        crate::cwe_kb::prompt_block(&chunk.sink_cwe, chunk.languages.first().map(String::as_str));
    let src_display = if src_fn.is_empty() {
        &chunk.source_ref
    } else {
        &src_fn
    };
    let src_file_display = if src_file.is_empty() {
        &chunk.source_ref
    } else {
        &src_file
    };
    let slice_note = if sliced {
        "The SOURCE CODE below contains ONLY the functions on this path (plus a few\n\
         context lines and out-of-chunk neighbor excerpts). Line numbers are real file\n\
         positions — cite them exactly.\n"
    } else {
        "The SOURCE CODE below covers every function on this path, but is NOT limited\n\
         to them — it also carries surrounding code from the same files and\n\
         out-of-chunk neighbor excerpts. Trace the hops listed above; treat anything\n\
         else you see as context, not as a second thing to report. Line numbers are\n\
         real file positions — cite them exactly.\n"
    };

    format!(
        "TASK: confirm or refute ONE candidate taint path. Do NOT hunt for\n\
unrelated issues — that is covered by other chunks.\n\
\n\
CANDIDATE PATH\n\
\u{20}\u{20}source : {src_display}()  [{src_file_display}]\n\
\u{20}\u{20}sink   : {}\n\
\u{20}\u{20}hops   : {hops}\n\
\u{20}\u{20}\u{20}\u{20}class  : {cwe}{evidence_block}\n\
{kb_block}\n\
{slice_note}\
{}\
DECISION RULES\n\
\u{20}\u{20}• CONFIRMED  — attacker-controlled data from the source reaches the sink\n\
\u{20}\u{20}\u{20}\u{20}without an effective sanitiser/validator/allow-list on the path. Emit\n\
\u{20}\u{20}\u{20}\u{20}EXACTLY ONE finding. `source_ref` MUST cite the source line, `sink_ref`\n\
\u{20}\u{20}\u{20}\u{20}MUST cite the sink line, and `description` MUST name the first hop where\n\
\u{20}\u{20}\u{20}\u{20}sanitisation was missing.\n\
\u{20}\u{20}• Framework sources (with FRAMEWORK SOURCE marker): Source is framework-injected\n\
\u{20}\u{20}\u{20}\u{20}(Spring @RequestParam, Django request.GET, ASP.NET model binding, etc.).\n\
\u{20}\u{20}\u{20}\u{20}Parameters are automatically tainted and must be validated downstream\n\
\u{20}\u{20}\u{20}\u{20}before reaching a sink.\n\
\u{20}\u{20}• Response flows (with RESPONSE OUTPUT marker): Output flows to a response\n\
\u{20}\u{20}\u{20}\u{20}object (JSON, HTML, XML, plain text). Risk: XSS if data not escaped,\n\
\u{20}\u{20}\u{20}\u{20}or response-format injection if type not properly handled.\n\
\u{20}\u{20}• REFUTED    — a sanitiser/validator/type-coercion neutralises the input\n\
\u{20}\u{20}\u{20}\u{20}before it reaches the sink, OR the path is not actually connected in the\n\
\u{20}\u{20}\u{20}\u{20}code shown. Emit ZERO findings. In the JSON, set\n\
\u{20}\u{20}\u{20}\u{20}`findings: []` and add `refuted_reason: \"<file:line> — <one-line why>\"`.\n\
\u{20}\u{20}\u{20}\u{20}• If you cannot decide from the code shown, emit `findings: []` with\n\
\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}`refuted_reason: \"insufficient evidence in provided slice\"`.\n\
\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}Do NOT claim a sanitizer/control unless you can cite it in the shown code.\n\
\n\
SOURCE CODE:\n\
{code}\n\
\n\
Respond with ONLY the JSON object (`findings` array, optional\n\
`refuted_reason`).",
        chunk.sink_ref,
        trust_context_block(ctx),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use appsec_model::{AppProfile, ChunkSize, TaintSymbolRef, ThreatModel, TrustBoundary};

    fn chunk() -> Chunk {
        Chunk {
            id: "c1".to_string(),
            size: ChunkSize::Medium,
            risk_rank: 1,
            files: vec!["a.py".to_string()],
            focus_entry_points: Vec::new(),
            hypothesis: "test hypothesis".to_string(),
            related_cves: Vec::new(),
            threat_id: None,
            languages: Vec::new(),
            specialist: None,
            path_funcs: Vec::new(),
            source_ref: String::new(),
            sink_ref: String::new(),
            sink_cwe: Vec::new(),
            shard_id: String::new(),
        }
    }

    fn chunk_with_taint(source_ref: &str, sink_ref: &str, path_funcs: &[&str]) -> Chunk {
        let mut c = chunk();
        c.source_ref = source_ref.to_string();
        c.sink_ref = sink_ref.to_string();
        c.path_funcs = path_funcs.iter().map(|s| s.to_string()).collect();
        c
    }

    fn taint_symbol(symbol: &str) -> TaintSymbolRef {
        TaintSymbolRef {
            qnode: "a.py::f".to_string(),
            symbol: symbol.to_string(),
            kind: "local".to_string(),
        }
    }

    fn taint_edge(kind: &str) -> TaintTransferEdge {
        TaintTransferEdge {
            file: "a.py".to_string(),
            line: 10,
            function_qnode: "a.py::f".to_string(),
            src: taint_symbol("src_sym"),
            dst: taint_symbol("dst_sym"),
            transfer_kind: kind.to_string(),
            condition_text: None,
            is_tainted_condition: None,
            confidence: None,
            call_type: None,
            reflected_targets: None,
            is_speculative: None,
            framework: None,
            marker_type: None,
        }
    }

    fn evidence_path(
        source_ref: &str,
        sink_ref: &str,
        path_funcs: &[&str],
        edges: Vec<TaintTransferEdge>,
    ) -> TaintEvidencePath {
        TaintEvidencePath {
            source_ref: source_ref.to_string(),
            sink_ref: sink_ref.to_string(),
            path_funcs: path_funcs.iter().map(|s| s.to_string()).collect(),
            edges,
            sink_cwe: Vec::new(),
            sanitized: false,
        }
    }

    fn ctx_with_evidence(evs: Vec<TaintEvidencePath>) -> ContextPackage {
        ContextPackage {
            seed_taint_evidence: evs,
            ..Default::default()
        }
    }

    #[test]
    fn system_prompt_splices_every_shared_constant() {
        assert!(SYSTEM.contains(appsec_prompts::EXCLUSION_RULES));
        assert!(SYSTEM.contains(appsec_prompts::SELF_VERIFICATION));
        assert!(SYSTEM.contains(appsec_prompts::SEVERITY_GUIDANCE));
        assert!(SYSTEM.contains(appsec_prompts::EXHAUSTIVENESS));
        assert!(SYSTEM.contains("QUALITY BAR:"));
        assert!(SYSTEM.contains("\"findings\""));
    }

    #[test]
    fn the_quality_bar_tells_the_deep_dive_to_flag_missing_auth_rather_than_adjudicate_it() {
        let p = &*SYSTEM;
        assert!(
            p.contains("Missing authorization/authentication: FLAG it, do not adjudicate it."),
            "{p}"
        );
        assert!(
            p.contains("A guard limits WHO can exploit a flaw, not whether it exists"),
            "{p}"
        );
        assert!(
            p.contains("You\n  have no file access — only this slice and the neighbor excerpts"),
            "{p}"
        );
        assert!(
            p.contains(
                "If the registration site is NOT in the code\n  you were given, still report it"
            ),
            "{p}"
        );
        assert!(
            p.contains("`route registration not visible in this slice; guard status unverified`"),
            "{p}"
        );
        assert!(p.contains("and set `confidence` to 0.6 —"), "{p}");
        assert!(p.contains("it is never a reason to stay silent."), "{p}");
        assert!(
            !p.contains("open the file that REGISTERS its route first"),
            "{p}"
        );
        for guard in [
            "`->middleware('auth')`",
            "Ktor `authenticate { }`",
            "`.route_layer(...)`",
            "Spring `@PreAuthorize`",
            "`[Authorize]`",
        ] {
            assert!(p.contains(guard), "missing guard spelling {guard}");
        }
        let hint = crate::hints::specialist_hint("access-control");
        assert!(
            hint.contains("FLAG it rather than adjudicating it"),
            "{hint}"
        );
        assert!(hint.contains("set `confidence` to 0.6 —"), "{hint}");
        assert!(
            !hint.contains("open the file that REGISTERS its route"),
            "{hint}"
        );
        assert!(hint.contains("concrete bypass"), "{hint}");
        assert!(
            hint.contains("Do in depth analysis to confirm first.\n\nWhen a handler appears"),
            "{hint}"
        );
    }

    #[test]
    fn the_missing_auth_confidence_floor_clears_the_s5_pre_verify_gate() {
        let gate = appsec_stage_s5::Step5Config::new("m").min_pre_confidence;
        assert_eq!(gate, 0.6, "s5's pre-verify gate moved; move the prompt too");
        for text in [&*SYSTEM, crate::hints::specialist_hint("access-control")] {
            assert!(text.contains("set `confidence` to 0.6 —"), "{text}");
            assert!(!text.contains("0.5 or lower"), "{text}");
        }
        assert!(0.6_f64 >= gate);
    }

    #[test]
    fn the_output_schema_anchors_temporal_findings_at_the_later_use() {
        let p = &*SYSTEM;
        assert!(
            p.contains("ANCHORING for temporal classes (use-after-free, double-free, TOCTOU)"),
            "{p}"
        );
        assert!(
            p.contains("`line_start`/`line_end` and `sink_ref` MUST sit on the LATER unsafe use"),
            "{p}"
        );
        assert!(
            p.contains("never on the release or check site, which is\nwhat `source_ref` is for"),
            "{p}"
        );
        assert!(
            p.contains("span them: `line_start` at the release/check, `line_end` at the use"),
            "{p}"
        );
        let schema = p.split_once("Respond with ONLY a JSON object").unwrap().1;
        let anchoring = schema.find("ANCHORING for temporal classes").unwrap();
        assert!(anchoring > schema.find("\"sink_ref\"").unwrap());
        assert!(anchoring < schema.find("An empty {\"findings\": []}").unwrap());
    }

    #[test]
    fn research_lens_specialist_with_a_known_hint_returns_the_hint_alone() {
        let mut c = chunk();
        c.specialist = Some("crypto".to_string());
        let out = build_research_lens(&c, None);
        assert!(out.contains("cryptography, key-handling"));
        assert!(!out.contains("Research lens:"));
    }

    #[test]
    fn research_lens_unknown_specialist_falls_back_to_a_generic_header() {
        let mut c = chunk();
        c.specialist = Some("totally-unknown".to_string());
        let out = build_research_lens(&c, None);
        assert_eq!(out, "You are a totally-unknown specialist.");
    }

    #[test]
    fn research_lens_no_specialist_no_languages_falls_back_to_this_codebase() {
        let out = build_research_lens(&chunk(), None);
        assert_eq!(out, "Research lens: this codebase security researcher.");
    }

    #[test]
    fn research_lens_no_specialist_with_languages_appends_lang_hints() {
        let mut c = chunk();
        c.languages = vec!["python".to_string(), "rust".to_string()];
        let out = build_research_lens(&c, None);
        assert!(out.starts_with("Research lens: Python / Rust security researcher."));
        assert!(out.contains("── Python ──"));
        assert!(out.contains("── Rust ──"));
    }

    #[test]
    fn research_lens_sharpens_a_pure_cpp_chunk_to_the_cpp_hint() {
        let mut c = chunk();
        c.languages = vec!["c-cpp".to_string()];
        c.files = vec![
            "src/parser.cpp".to_string(),
            "include/parser.hpp".to_string(),
        ];
        let out = build_research_lens(&c, None);
        assert!(out.starts_with("Research lens: C++ security researcher."));
        assert!(out.contains("── C++ ──"));
        assert!(out.contains("Iterator / reference / pointer invalidation"));
    }

    #[test]
    fn research_lens_sharpens_a_pure_c_chunk_to_the_c_hint() {
        let mut c = chunk();
        c.languages = vec!["c-cpp".to_string()];
        c.files = vec!["src/parser.c".to_string(), "include/parser.h".to_string()];
        let out = build_research_lens(&c, None);
        assert!(out.starts_with("Research lens: C security researcher."));
        assert!(out.contains("── C ──"));
        assert!(!out.contains("Iterator / reference / pointer invalidation"));
    }

    #[test]
    fn research_lens_keeps_c_cpp_for_a_mixed_chunk() {
        let mut c = chunk();
        c.languages = vec!["c-cpp".to_string()];
        c.files = vec!["src/parser.c".to_string(), "src/wrapper.cpp".to_string()];
        let out = build_research_lens(&c, None);
        assert!(out.starts_with("Research lens: C/C++ security researcher."));
        assert!(out.contains("Iterator / reference / pointer invalidation"));
    }

    #[test]
    fn research_lens_keeps_c_cpp_when_no_c_family_file_is_listed() {
        let mut c = chunk();
        c.languages = vec!["c-cpp".to_string()];
        c.files = vec!["docs/README.md".to_string()];
        let out = build_research_lens(&c, None);
        assert!(out.starts_with("Research lens: C/C++ security researcher."));
    }

    #[test]
    fn research_lens_leaves_other_languages_alone() {
        let mut c = chunk();
        c.languages = vec!["python".to_string()];
        c.files = vec!["src/parser.cpp".to_string()];
        let out = build_research_lens(&c, None);
        assert!(out.starts_with("Research lens: Python security researcher."));
    }

    #[test]
    fn trust_context_block_is_empty_with_no_app_profile_or_threat_model() {
        let ctx = ContextPackage::default();
        assert_eq!(trust_context_block(&ctx), "");
    }

    #[test]
    fn trust_context_block_reports_externally_facing_and_sensitivity() {
        let ctx = ContextPackage {
            app_profile: Some(AppProfile {
                exposure: String::new(),
                reaches: Vec::new(),
                reached_by: Vec::new(),
                application_id: "app1".to_string(),
                name: String::new(),
                externally_facing: true,
                pci_scoped: true,
                processes_pan: true,
                pii: true,
                source: String::new(),
            }),
            ..Default::default()
        };
        let out = trust_context_block(&ctx);
        assert!(out.contains("Externally facing: YES"));
        assert!(out.contains("Data sensitivity: PCI, PAN, PII"));
    }

    #[test]
    fn trust_context_block_internal_app_with_no_sensitive_data_omits_sensitivity_line() {
        let ctx = ContextPackage {
            app_profile: Some(AppProfile {
                exposure: String::new(),
                reaches: Vec::new(),
                reached_by: Vec::new(),
                application_id: "app1".to_string(),
                name: String::new(),
                externally_facing: false,
                pci_scoped: false,
                processes_pan: false,
                pii: false,
                source: String::new(),
            }),
            ..Default::default()
        };
        let out = trust_context_block(&ctx);
        assert!(out.contains("Externally facing: NO — internal only"));
        assert!(!out.contains("Data sensitivity"));
    }

    #[test]
    fn trust_context_block_truncates_system_context_to_first_paragraph_and_400_chars() {
        let long = "x".repeat(500);
        let ctx = ContextPackage {
            threat_model: Some(ThreatModel {
                system_context: format!("{long}\n\nsecond paragraph"),
                assets: Vec::new(),
                trust_boundaries: Vec::new(),
                threats: Vec::new(),
                open_questions: Vec::new(),
            }),
            ..Default::default()
        };
        let out = trust_context_block(&ctx);
        assert!(!out.contains("second paragraph"));
        assert!(out.contains(&"x".repeat(400)));
        assert!(!out.contains(&"x".repeat(401)));
    }

    #[test]
    fn trust_context_block_lists_up_to_eight_trust_boundaries() {
        let boundaries: Vec<TrustBoundary> = (0..10)
            .map(|i| TrustBoundary {
                entry_point: format!("ep{i}"),
                crossing: String::new(),
                reachable_assets: Vec::new(),
            })
            .collect();
        let ctx = ContextPackage {
            threat_model: Some(ThreatModel {
                system_context: String::new(),
                assets: Vec::new(),
                trust_boundaries: boundaries,
                threats: Vec::new(),
                open_questions: Vec::new(),
            }),
            ..Default::default()
        };
        let out = trust_context_block(&ctx);
        assert!(out.contains("ep7"));
        assert!(!out.contains("ep8"));
    }

    #[test]
    fn trust_context_block_empty_system_context_and_no_boundaries_skips_both_sections() {
        let ctx = ContextPackage {
            threat_model: Some(ThreatModel {
                system_context: String::new(),
                assets: Vec::new(),
                trust_boundaries: Vec::new(),
                threats: Vec::new(),
                open_questions: Vec::new(),
            }),
            ..Default::default()
        };
        let out = trust_context_block(&ctx);
        assert!(!out.contains("System:"));
        assert!(!out.contains("UNTRUSTED entry points"));
        assert!(out.contains("Operator argv/env"));
    }

    #[test]
    fn cve_block_is_empty_when_the_chunk_names_no_cves() {
        assert_eq!(cve_block(&chunk()), "");
    }

    #[test]
    fn cve_block_lists_the_ids_the_chunk_names_in_order() {
        let mut c = chunk();
        c.related_cves = vec!["CVE-2024-0002".to_string(), "CVE-2024-0001".to_string()];
        let out = cve_block(&c);
        assert!(out.contains("RELATED CVEs"));
        let second = out.find("CVE-2024-0002").expect("first listed");
        let first = out.find("CVE-2024-0001").expect("second listed");
        assert!(
            second < first,
            "the chunk's own order is kept, not re-sorted: {out}"
        );
    }

    #[test]
    fn build_prompt_with_no_focus_entry_points_shows_none_placeholder() {
        let out = build_prompt(&chunk(), &ContextPackage::default(), "print(1)");
        assert!(out.contains("FOCUS ENTRY POINTS: (none)"));
        assert!(out.contains("CHUNK: c1  SIZE: medium"));
        assert!(out.contains("HYPOTHESIS: test hypothesis"));
        assert!(out.contains("print(1)"));
        assert!(out.ends_with("Analyze this code and respond with ONLY the JSON findings object."));
    }

    #[test]
    fn build_prompt_joins_multiple_focus_entry_points() {
        let mut c = chunk();
        c.focus_entry_points = vec!["main".to_string(), "handler".to_string()];
        let out = build_prompt(&c, &ContextPackage::default(), "code");
        assert!(out.contains("FOCUS ENTRY POINTS: main, handler"));
    }

    #[test]
    fn build_prompt_includes_compliance_guidance_when_present() {
        let ctx = ContextPackage {
            compliance_guidance: "Prioritize PCI-DSS Req 6 findings.".to_string(),
            ..ContextPackage::default()
        };
        let out = build_prompt(&chunk(), &ctx, "code");
        assert!(out.contains("COMPLIANCE GUIDANCE:\nPrioritize PCI-DSS Req 6 findings."));
    }

    #[test]
    fn build_prompt_omits_compliance_guidance_when_absent() {
        let out = build_prompt(&chunk(), &ContextPackage::default(), "code");
        assert!(!out.contains("COMPLIANCE GUIDANCE"));
    }

    #[test]
    fn build_prompt_no_longer_embeds_the_trust_context() {
        let ctx = ContextPackage {
            app_profile: Some(AppProfile {
                exposure: String::new(),
                reaches: Vec::new(),
                reached_by: Vec::new(),
                application_id: "A".to_string(),
                name: String::new(),
                externally_facing: true,
                pci_scoped: false,
                processes_pan: false,
                pii: false,
                source: String::new(),
            }),
            ..ContextPackage::default()
        };
        let out = build_prompt(&chunk(), &ctx, "code");
        assert!(!out.contains("TRUST CONTEXT"));
        assert!(!out.contains("TRUST RULE"));
    }

    #[test]
    fn build_shard_prompt_is_build_prompt_minus_the_source_code_section() {
        let ctx = ContextPackage {
            compliance_guidance: "PCI first.".to_string(),
            ..ContextPackage::default()
        };
        let normal = build_prompt(&chunk(), &ctx, "SECRET_CODE_BODY");
        let shard = build_shard_prompt(&chunk(), &ctx, "SECRET_CODE_BODY");
        assert!(!shard.contains("SOURCE CODE:"));
        assert!(!shard.contains("SECRET_CODE_BODY"));
        assert!(shard.starts_with("RESEARCH LENS:\n"));
        assert!(shard.contains("COMPLIANCE GUIDANCE:\nPCI first."));
        assert_eq!(
            normal.replace("SOURCE CODE:\nSECRET_CODE_BODY\n\n", ""),
            shard
        );
    }

    #[test]
    fn shard_source_block_ends_with_a_blank_line_so_the_user_text_can_follow() {
        assert_eq!(shard_source_block("x = 1"), "SOURCE CODE:\nx = 1\n\n");
    }

    #[test]
    fn norm_rel_path_trims_replaces_backslashes_and_strips_leading_dot_slashes() {
        assert_eq!(norm_rel_path("  ./././src\\a.py  "), "src/a.py");
        assert_eq!(norm_rel_path("src/a.py"), "src/a.py");
    }

    #[test]
    fn parse_ref_file_line_empty_string_is_empty_file_no_line() {
        assert_eq!(parse_ref_file_line(""), (String::new(), None));
        assert_eq!(parse_ref_file_line("   "), (String::new(), None));
    }

    #[test]
    fn parse_ref_file_line_qnode_form_has_no_line() {
        assert_eq!(parse_ref_file_line("a.py::foo"), ("a.py".to_string(), None));
    }

    #[test]
    fn parse_ref_file_line_file_colon_line_form_parses_line() {
        assert_eq!(
            parse_ref_file_line("a.py:42"),
            ("a.py".to_string(), Some(42))
        );
    }

    #[test]
    fn parse_ref_file_line_zero_line_clamps_up_to_one() {
        assert_eq!(parse_ref_file_line("a.py:0"), ("a.py".to_string(), Some(1)));
    }

    #[test]
    fn parse_ref_file_line_non_digit_suffix_falls_back_to_whole_string_as_file() {
        assert_eq!(
            parse_ref_file_line("a.py:notaline"),
            ("a.py:notaline".to_string(), None)
        );
    }

    #[test]
    fn parse_ref_file_line_no_separator_is_treated_as_a_bare_file() {
        assert_eq!(
            parse_ref_file_line("just_a_ref"),
            ("just_a_ref".to_string(), None)
        );
    }

    #[test]
    fn parse_ref_file_line_trailing_colon_with_empty_tail_falls_back_to_whole_string() {
        assert_eq!(parse_ref_file_line("a.py:"), ("a.py:".to_string(), None));
    }

    #[test]
    fn parse_ref_file_line_leading_colon_with_empty_file_falls_back_to_whole_string() {
        assert_eq!(parse_ref_file_line(":42"), (":42".to_string(), None));
    }

    #[test]
    fn short_symbol_empty_or_whitespace_only_is_unknown() {
        assert_eq!(short_symbol(""), "(unknown)");
        assert_eq!(short_symbol("   "), "(unknown)");
    }

    #[test]
    fn short_symbol_under_limit_is_unchanged_after_trim() {
        assert_eq!(short_symbol("  foo  "), "foo");
    }

    #[test]
    fn short_symbol_over_64_chars_is_truncated_with_ellipsis() {
        let long = "a".repeat(100);
        let out = short_symbol(&long);
        assert_eq!(out.chars().count(), 64);
        assert!(out.ends_with('…'));
        assert!(out.starts_with(&"a".repeat(63)));
    }

    #[test]
    fn short_symbol_exactly_64_chars_is_unchanged() {
        let s = "a".repeat(64);
        assert_eq!(short_symbol(&s), s);
    }

    #[test]
    fn response_type_for_classifies_common_sink_symbols() {
        assert_eq!(response_type_for("render"), "html");
        assert_eq!(response_type_for("HtmlTemplate"), "html");
        assert_eq!(response_type_for("jsonify"), "json");
        assert_eq!(response_type_for("to_json"), "json");
        assert_eq!(response_type_for("XmlWriter"), "xml");
        assert_eq!(response_type_for("PrintWriter"), "text");
    }

    #[test]
    fn best_matching_evidence_skips_entries_with_no_edges() {
        let c = chunk_with_taint("a.py::f", "a.py:10", &[]);
        let empty_edges_ev = evidence_path("a.py::f", "a.py:10", &[], Vec::new());
        assert!(best_matching_evidence(&c, &[empty_edges_ev]).is_none());
    }

    #[test]
    fn best_matching_evidence_requires_a_positive_score() {
        let c = chunk_with_taint("a.py::f", "a.py:10", &[]);
        let unrelated = evidence_path("b.py::g", "b.py:99", &[], vec![taint_edge("assign")]);
        assert!(best_matching_evidence(&c, &[unrelated]).is_none());
    }

    #[test]
    fn best_matching_evidence_skips_overlap_scoring_when_chunk_has_no_path_funcs() {
        let c = chunk_with_taint("a.py::f", "a.py:10", &[]);
        let ev = evidence_path(
            "a.py::f",
            "a.py:10",
            &["h1", "h2"],
            vec![taint_edge("assign")],
        );
        let evs = [ev];
        let best = best_matching_evidence(&c, &evs).unwrap();
        assert_eq!(best.source_ref, "a.py::f");
    }

    #[test]
    fn best_matching_evidence_caps_path_func_overlap_score_at_three() {
        let c = chunk_with_taint("x.py::z", "x.py:1", &["h1", "h2", "h3", "h4", "h5"]);
        let ev = evidence_path(
            "x.py::z",
            "x.py:1",
            &["h1", "h2", "h3", "h4", "h5"],
            vec![taint_edge("assign")],
        );
        let evs = [ev];
        let best = best_matching_evidence(&c, &evs).unwrap();
        assert_eq!(best.path_funcs.len(), 5);
    }

    #[test]
    fn best_matching_evidence_picks_the_highest_scoring_entry_regardless_of_order() {
        let c = chunk_with_taint("a.py::f", "a.py:10", &["h1", "h2", "h3", "h4"]);
        let weak = evidence_path("a.py::f", "b.py:1", &[], vec![taint_edge("assign")]);
        let strong = evidence_path(
            "a.py::f",
            "a.py:10",
            &["h1", "h2", "h3", "h4"],
            vec![taint_edge("assign")],
        );
        let forward = [weak.clone(), strong.clone()];
        let best = best_matching_evidence(&c, &forward).unwrap();
        assert_eq!(best.sink_ref, "a.py:10");
        let backward = [strong, weak];
        let best2 = best_matching_evidence(&c, &backward).unwrap();
        assert_eq!(best2.sink_ref, "a.py:10");
    }

    #[test]
    fn best_matching_evidence_keeps_the_first_entry_on_a_tied_score() {
        let c = chunk_with_taint("a.py::f", "a.py:10", &[]);
        let first = evidence_path("a.py::f", "a.py:10", &[], vec![taint_edge("assign")]);
        let second = evidence_path("a.py::f", "a.py:10", &[], vec![taint_edge("condition")]);
        let evs = [first, second];
        let best = best_matching_evidence(&c, &evs).unwrap();
        assert_eq!(best.edges[0].transfer_kind, "assign");
    }

    #[test]
    fn compact_taint_evidence_block_no_evidence_at_all_is_empty() {
        let c = chunk_with_taint("a.py::f", "a.py:10", &["h1"]);
        assert_eq!(
            compact_taint_evidence_block(&c, &ContextPackage::default()),
            ""
        );
    }

    #[test]
    fn compact_taint_evidence_block_no_matching_evidence_is_empty() {
        let c = chunk_with_taint("a.py::f", "a.py:10", &[]);
        let ev = evidence_path(
            "unrelated.py::g",
            "unrelated.py:1",
            &[],
            vec![taint_edge("assign")],
        );
        let ctx = ctx_with_evidence(vec![ev]);
        assert_eq!(compact_taint_evidence_block(&c, &ctx), "");
    }

    #[test]
    fn compact_taint_evidence_block_matched_but_no_key_transfer_kinds_is_empty() {
        let c = chunk_with_taint("a.py::f", "a.py:10", &[]);
        let ev = evidence_path("a.py::f", "a.py:10", &[], vec![taint_edge("sanitize")]);
        let ctx = ctx_with_evidence(vec![ev]);
        assert_eq!(compact_taint_evidence_block(&c, &ctx), "");
    }

    #[test]
    fn compact_taint_evidence_block_no_source_kind_edge_falls_back_to_first_edge() {
        let c = chunk_with_taint("a.py::f", "a.py:10", &[]);
        let mut first = taint_edge("assign");
        first.src = taint_symbol("first_src");
        let ev = evidence_path("a.py::f", "a.py:10", &[], vec![first]);
        let ctx = ctx_with_evidence(vec![ev]);
        let out = compact_taint_evidence_block(&c, &ctx);
        assert!(out.contains("origin tainted symbol : first_src"));
    }

    #[test]
    fn compact_taint_evidence_block_no_terminal_sink_edge_falls_back_to_last_edge() {
        let c = chunk_with_taint("a.py::f", "a.py:10", &[]);
        let e1 = taint_edge("assign");
        let mut e2 = taint_edge("arg_to_param");
        e2.dst = taint_symbol("last_dst");
        let ev = evidence_path("a.py::f", "a.py:10", &[], vec![e1, e2]);
        let ctx = ctx_with_evidence(vec![ev]);
        let out = compact_taint_evidence_block(&c, &ctx);
        assert!(out.contains("sink-consuming symbol : last_dst"));
        assert!(out.contains("transfer edges kinds  : assign:1, arg_to_param:1"));
    }

    #[test]
    fn compact_taint_evidence_block_sink_symbol_falls_back_to_src_symbol_when_dst_is_unknown() {
        let c = chunk_with_taint("a.py::f", "a.py:10", &[]);
        let assign_edge = taint_edge("assign");
        let mut sink_edge = taint_edge("local_to_sink");
        sink_edge.dst = taint_symbol("");
        sink_edge.src = taint_symbol("fallback_src");
        let ev = evidence_path("a.py::f", "a.py:10", &[], vec![assign_edge, sink_edge]);
        let ctx = ctx_with_evidence(vec![ev]);
        let out = compact_taint_evidence_block(&c, &ctx);
        assert!(out.contains("sink-consuming symbol : fallback_src"));
    }

    #[test]
    fn compact_taint_evidence_block_sanitize_with_no_function_qnode_falls_back_to_dst_symbol() {
        let c = chunk_with_taint("a.py::f", "a.py:10", &[]);
        let assign_edge = taint_edge("assign");
        let mut sanitize_edge = taint_edge("sanitize");
        sanitize_edge.function_qnode = String::new();
        sanitize_edge.dst = taint_symbol("escape_html");
        let ev = evidence_path("a.py::f", "a.py:10", &[], vec![assign_edge, sanitize_edge]);
        let ctx = ctx_with_evidence(vec![ev]);
        let out = compact_taint_evidence_block(&c, &ctx);
        assert!(out.contains("SANITIZED via              : escape_html"));
    }

    #[test]
    fn compact_taint_evidence_block_field_flow_with_writes_only() {
        let c = chunk_with_taint("a.py::f", "a.py:10", &[]);
        let ev = evidence_path(
            "a.py::f",
            "a.py:10",
            &[],
            vec![taint_edge("assign"), taint_edge("field_write")],
        );
        let ctx = ctx_with_evidence(vec![ev]);
        let out = compact_taint_evidence_block(&c, &ctx);
        assert!(out.contains("FIELD FLOW                 : field_write:1"));
        assert!(!out.contains("field_read"));
    }

    #[test]
    fn compact_taint_evidence_block_container_flow_with_gets_only() {
        let c = chunk_with_taint("a.py::f", "a.py:10", &[]);
        let ev = evidence_path(
            "a.py::f",
            "a.py:10",
            &[],
            vec![taint_edge("assign"), taint_edge("container_get")],
        );
        let ctx = ctx_with_evidence(vec![ev]);
        let out = compact_taint_evidence_block(&c, &ctx);
        assert!(out.contains("CONTAINER FLOW             : container_get:1"));
        assert!(!out.contains("container_put"));
    }

    #[test]
    fn compact_taint_evidence_block_condition_defaults_when_text_and_confidence_absent() {
        let c = chunk_with_taint("a.py::f", "a.py:10", &[]);
        let ev = evidence_path(
            "a.py::f",
            "a.py:10",
            &[],
            vec![taint_edge("assign"), taint_edge("condition")],
        );
        let ctx = ctx_with_evidence(vec![ev]);
        let out = compact_taint_evidence_block(&c, &ctx);
        assert!(out.contains("CONDITION GATE             : [(unknown)] (confidence: high)"));
        assert!(out.contains("NOTE: Path is gated by condition: (unknown)"));
    }

    #[test]
    fn compact_taint_evidence_block_condition_text_of_empty_string_also_falls_back_to_unknown() {
        let c = chunk_with_taint("a.py::f", "a.py:10", &[]);
        let mut condition_edge = taint_edge("condition");
        condition_edge.condition_text = Some(String::new());
        let ev = evidence_path(
            "a.py::f",
            "a.py:10",
            &[],
            vec![taint_edge("assign"), condition_edge],
        );
        let ctx = ctx_with_evidence(vec![ev]);
        let out = compact_taint_evidence_block(&c, &ctx);
        assert!(out.contains("CONDITION GATE             : [(unknown)]"));
    }

    #[test]
    fn compact_taint_evidence_block_reflect_with_no_targets_renders_the_no_target_form() {
        let c = chunk_with_taint("a.py::f", "a.py:10", &[]);
        let reflect_edge = taint_edge("reflect");
        let ev = evidence_path(
            "a.py::f",
            "a.py:10",
            &[],
            vec![taint_edge("assign"), reflect_edge],
        );
        let ctx = ctx_with_evidence(vec![ev]);
        let out = compact_taint_evidence_block(&c, &ctx);
        assert!(out
            .contains("REFLECT EDGE               : [reflect] (confidence: medium, speculative)"));
        assert!(out.contains("NOTE: Path involves reflection to (unresolved)"));
    }

    #[test]
    fn compact_taint_evidence_block_reflect_with_one_target_omits_the_more_suffix() {
        let c = chunk_with_taint("a.py::f", "a.py:10", &[]);
        let mut reflect_edge = taint_edge("reflect");
        reflect_edge.call_type = Some("invoke".to_string());
        reflect_edge.confidence = Some("low".to_string());
        reflect_edge.reflected_targets = Some(vec!["OnlyTarget".to_string()]);
        let ev = evidence_path(
            "a.py::f",
            "a.py:10",
            &[],
            vec![taint_edge("assign"), reflect_edge],
        );
        let ctx = ctx_with_evidence(vec![ev]);
        let out = compact_taint_evidence_block(&c, &ctx);
        assert!(out.contains(
            "REFLECT EDGE               : [invoke] → OnlyTarget (confidence: low, speculative)"
        ));
        assert!(out.contains("NOTE: Path involves reflection to OnlyTarget"));
    }

    #[test]
    fn compact_taint_evidence_block_reflect_with_two_targets_omits_the_more_suffix() {
        let c = chunk_with_taint("a.py::f", "a.py:10", &[]);
        let mut reflect_edge = taint_edge("reflect");
        reflect_edge.reflected_targets = Some(vec!["T1".to_string(), "T2".to_string()]);
        let ev = evidence_path(
            "a.py::f",
            "a.py:10",
            &[],
            vec![taint_edge("assign"), reflect_edge],
        );
        let ctx = ctx_with_evidence(vec![ev]);
        let out = compact_taint_evidence_block(&c, &ctx);
        assert!(out.contains("→ T1, T2 (confidence"));
        assert!(!out.contains("more"));
    }

    #[test]
    fn compact_taint_evidence_block_framework_defaults_when_fields_absent() {
        let c = chunk_with_taint("a.py::f", "a.py:10", &[]);
        let ev = evidence_path(
            "a.py::f",
            "a.py:10",
            &[],
            vec![taint_edge("assign"), taint_edge("framework")],
        );
        let ctx = ctx_with_evidence(vec![ev]);
        let out = compact_taint_evidence_block(&c, &ctx);
        assert!(out.contains("FRAMEWORK SOURCE           : [framework] marker (confidence: high)"));
        assert!(out.contains("NOTE: Source is framework-injected (framework)"));
    }

    #[test]
    fn compact_taint_evidence_block_response_note_matches_via_trimmed_symbol_fallback() {
        let c = chunk_with_taint("a.py::f", "a.py:10", &[]);
        let assign_edge = taint_edge("assign");
        let mut sink_edge = taint_edge("local_to_sink");
        sink_edge.dst = taint_symbol("  render  ");
        let ev = evidence_path("a.py::f", "a.py:10", &[], vec![assign_edge, sink_edge]);
        let ctx = ctx_with_evidence(vec![ev]);
        let out = compact_taint_evidence_block(&c, &ctx);
        assert!(out.contains("RESPONSE OUTPUT            : render (type: html)"));
        assert!(out.contains("NOTE: Output flows to response object"));
    }

    #[test]
    fn compact_taint_evidence_block_renders_every_extra_line_kind_capped_at_six() {
        let c = chunk_with_taint("a.py::f", "a.py:10", &["h1"]);

        let mut source_edge = taint_edge("source");
        source_edge.src = taint_symbol("tainted_input");

        let assign_edge = taint_edge("assign");

        let mut sanitize_edge = taint_edge("sanitize");
        sanitize_edge.function_qnode = "a.py::sanitize_fn".to_string();

        let field_write = taint_edge("field_write");
        let field_read = taint_edge("field_read");
        let container_put = taint_edge("container_put");
        let container_get = taint_edge("container_get");

        let mut condition_edge = taint_edge("condition");
        condition_edge.condition_text = Some("x > 0".to_string());
        condition_edge.confidence = Some("high".to_string());

        let mut reflect_edge = taint_edge("reflect");
        reflect_edge.call_type = Some("invoke".to_string());
        reflect_edge.confidence = Some("low".to_string());
        reflect_edge.reflected_targets = Some(vec![
            "Target1".to_string(),
            "Target2".to_string(),
            "Target3".to_string(),
        ]);

        let mut framework_edge = taint_edge("framework");
        framework_edge.framework = Some("spring".to_string());
        framework_edge.marker_type = Some("RequestParam".to_string());
        framework_edge.confidence = Some("high".to_string());

        let mut sink_edge = taint_edge("local_to_sink");
        sink_edge.dst = taint_symbol("render");

        let ev = evidence_path(
            "a.py::f",
            "a.py:10",
            &["h1"],
            vec![
                source_edge,
                assign_edge,
                sanitize_edge,
                field_write,
                field_read,
                container_put,
                container_get,
                condition_edge,
                reflect_edge,
                framework_edge,
                sink_edge,
            ],
        );
        let ctx = ctx_with_evidence(vec![ev]);
        let out = compact_taint_evidence_block(&c, &ctx);

        assert!(out.contains("STRUCTURED TAINT EVIDENCE (compact)"));
        assert!(out.contains("origin tainted symbol : tainted_input"));
        assert!(out.contains("transfer edges kinds  : assign:1, local_to_sink:1"));
        assert!(out.contains("sink-consuming symbol : render"));
        assert!(out.contains("SANITIZED via              : sanitize_fn"));
        assert!(out.contains("FIELD FLOW                 : field_write:1, field_read:1"));
        assert!(out.contains("CONTAINER FLOW             : container_put:1, container_get:1"));
        assert!(out.contains("CONDITION GATE             : [x > 0] (confidence: high)"));
        assert!(out.contains(
            "REFLECT EDGE               : [invoke] → Target1, Target2 +1 more (confidence: low, speculative)"
        ));
        assert!(
            out.contains("FRAMEWORK SOURCE           : [spring] RequestParam (confidence: high)")
        );
        assert!(!out.contains("RESPONSE OUTPUT"));
        assert!(out.contains("NOTE: Output flows to response object"));
        assert!(out.contains("NOTE: Path is gated by condition"));
        assert!(out.contains("NOTE: Path involves reflection to Target1"));
        assert!(out.contains("NOTE: Source is framework-injected (spring)"));
    }

    #[test]
    fn build_confirm_refute_prompt_renders_the_full_candidate_path() {
        let mut c = chunk_with_taint("a.py::source_fn", "a.py:42", &["a.py::hop1", "b.py::hop2"]);
        c.sink_cwe = vec!["CWE-89".to_string()];
        let out = build_confirm_refute_prompt(&c, &ContextPackage::default(), "print(1)", false);
        assert!(out.starts_with("TASK: confirm or refute ONE candidate taint path."));
        assert!(out.contains("source : source_fn()  [a.py]"));
        assert!(out.contains("sink   : a.py:42"));
        assert!(out.contains("hops   : hop1 -> hop2"));
        assert!(out.contains("class  : CWE-89"));
        assert!(out.contains("SOURCE CODE:\nprint(1)"));
        assert!(out.ends_with(
            "Respond with ONLY the JSON object (`findings` array, optional\n`refuted_reason`)."
        ));
    }

    #[test]
    fn build_confirm_refute_prompt_claims_a_path_only_slice_only_when_one_was_built() {
        let c = chunk_with_taint("a.py::f", "a.py:1", &[]);
        let sliced = build_confirm_refute_prompt(&c, &ContextPackage::default(), "code", true);
        assert!(
            sliced.contains("contains ONLY the functions on this path"),
            "{sliced}"
        );
        assert!(!sliced.contains("is NOT limited"), "{sliced}");

        let whole = build_confirm_refute_prompt(&c, &ContextPackage::default(), "code", false);
        assert!(
            !whole.contains("ONLY the functions on this path"),
            "{whole}"
        );
        assert!(
            whole.contains("covers every function on this path, but is NOT limited"),
            "{whole}"
        );
        for marker in ["CANDIDATE PATH", "DECISION RULES", "SOURCE CODE:"] {
            assert!(sliced.contains(marker) && whole.contains(marker));
        }
    }

    #[test]
    fn build_confirm_refute_prompt_defaults_cwe_and_hops_when_absent() {
        let c = chunk_with_taint("a.py::f", "a.py:1", &[]);
        let out = build_confirm_refute_prompt(&c, &ContextPackage::default(), "code", false);
        assert!(out.contains("hops   : (direct)"));
        assert!(out.contains("class  : (infer from sink)"));
    }

    #[test]
    fn build_confirm_refute_prompt_splices_the_kb_block_right_after_the_class_line() {
        let mut c = chunk_with_taint("a.py::source_fn", "a.py:42", &[]);
        c.sink_cwe = vec!["CWE-89".to_string()];
        let out = build_confirm_refute_prompt(&c, &ContextPackage::default(), "code", false);
        assert!(out.contains(
            "class  : CWE-89\nTAINT KB — SQL Injection  (origin: generic)\n\
             \u{20}\u{20}SANITIZERS"
        ));
        assert!(out.contains("Parameterized queries / prepared statements"));
        assert!(out.contains("\n\nThe SOURCE CODE below"));
    }

    #[test]
    fn build_confirm_refute_prompt_kb_block_is_language_filtered_from_chunk_languages() {
        let mut c = chunk_with_taint("a.py::source_fn", "a.py:42", &[]);
        c.sink_cwe = vec!["CWE-89".to_string()];
        c.languages = vec!["python".to_string()];
        let out = build_confirm_refute_prompt(&c, &ContextPackage::default(), "code", false);
        assert!(out.contains("cursor.execute"));
        assert!(!out.contains("PreparedStatement"));
    }

    #[test]
    fn build_confirm_refute_prompt_kb_block_is_empty_for_an_unmapped_cwe() {
        let c = chunk_with_taint("a.py::f", "a.py:1", &[]);
        let out = build_confirm_refute_prompt(&c, &ContextPackage::default(), "code", false);
        assert!(out.contains("class  : (infer from sink)\n\nThe SOURCE CODE below"));
    }

    #[test]
    fn build_confirm_refute_prompt_source_ref_with_no_qnode_separator_uses_the_whole_ref_for_both_fields(
    ) {
        let c = chunk_with_taint("just_a_name", "a.py:1", &[]);
        let out = build_confirm_refute_prompt(&c, &ContextPackage::default(), "code", false);
        assert!(out.contains("source : just_a_name()  [just_a_name]"));
    }

    #[test]
    fn build_confirm_refute_prompt_source_ref_with_empty_function_name_falls_back_to_the_full_ref()
    {
        let c = chunk_with_taint("a.py::", "a.py:1", &[]);
        let out = build_confirm_refute_prompt(&c, &ContextPackage::default(), "code", false);
        assert!(out.contains("source : a.py::()  [a.py]"));
    }

    #[test]
    fn build_confirm_refute_prompt_source_ref_with_empty_file_falls_back_to_the_full_ref() {
        let c = chunk_with_taint("::fn_only", "a.py:1", &[]);
        let out = build_confirm_refute_prompt(&c, &ContextPackage::default(), "code", false);
        assert!(out.contains("source : fn_only()  [::fn_only]"));
    }

    #[test]
    fn build_confirm_refute_prompt_includes_structured_taint_evidence_when_matched() {
        let c = chunk_with_taint("a.py::f", "a.py:10", &["h1"]);
        let ev = evidence_path("a.py::f", "a.py:10", &["h1"], vec![taint_edge("assign")]);
        let ctx = ctx_with_evidence(vec![ev]);
        let out = build_confirm_refute_prompt(&c, &ctx, "code", false);
        assert!(out.contains("STRUCTURED TAINT EVIDENCE (compact)"));
    }
}
