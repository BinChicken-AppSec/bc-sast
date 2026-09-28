//! The `### Pipeline Diagnostics` subsection of `## Scan Metrics`, ported
//! in spirit from `models/_scan.py::_render_pipeline_diagnostics`
//! (vvaharness v1.3/v1.4).
//!
//! Python emits one bullet per non-zero counter and renders the heading
//! whenever any bullet exists, which in practice is every run that built a
//! threat model (its "threats identified" and "repository kind" lines are
//! always non-zero). This port renders the section only when
//! [`PipelineDiagnostics::is_noteworthy`] says something happened (a
//! repair, a cap that cut real output, a guard that fired, a coverage gap,
//! a specialist lens breakdown) or a reply was lost to truncation; the
//! context lines (repository kinds, agentic S2) then ride along so the
//! noteworthy ones can be read in context. A clean run carries no section.
//!
//! Every string that did not originate in this crate (lens names, baseline
//! ids, repository kinds, and above all the model-authored auto-exclude
//! entries) goes through the same neutralization the rest of the report
//! uses: [`md_code_span`] inside a code span, [`md_cell`] elsewhere.

use bc_model::{PipelineDiagnostics, ScanMetrics};

use crate::sanitize::{md_cell, md_code_span};

/// `a, b, c` with every item neutralized for bullet text.
fn list(items: &[String]) -> String {
    items
        .iter()
        .map(|s| md_cell(s))
        .collect::<Vec<_>>()
        .join(", ")
}

/// `` `a`, `b` `` with every item neutralized for its code span.
fn code_list(items: &[String]) -> String {
    items
        .iter()
        .map(|s| format!("`{}`", md_code_span(s)))
        .collect::<Vec<_>>()
        .join(", ")
}

fn autoexclude_lines(d: &PipelineDiagnostics, out: &mut Vec<String>) {
    let ae = &d.autoexclude;
    if !ae.vetoed.is_empty() {
        out.push(format!(
            "- Auto-exclude entries vetoed because each would have removed a whole \
             language from scope: {}",
            code_list(&ae.vetoed)
        ));
    }
    if ae.discarded_empty_scope {
        out.push(format!(
            "- **Auto-exclude overlay discarded**: it would have emptied the scope \
             ({} files -> 0), so the scan ran with the global step1 exclusions only.",
            ae.files_before
        ));
    }
    if ae.aggressive {
        out.push(format!(
            "- **Aggressive auto-exclude overlay applied**: it kept {} of {} files \
             (under 10%); check the exclusions in the Scan Scope appendix.",
            ae.files_after, ae.files_before
        ));
    }
}

fn threat_model_lines(d: &PipelineDiagnostics, out: &mut Vec<String>) {
    let tm = &d.threat_model;
    if tm.degraded {
        out.push(
            "- Threat model: **degraded**. The model call failed or returned no usable \
             threat model; ranking and baseline coverage for this scan fell back to the \
             deterministic passes only."
                .to_string(),
        );
    }
    if tm.agentic {
        out.push("- Threat model built by an agentic, tool-using session".to_string());
    }
    if tm.parse_repair_attempted {
        let result = if tm.parse_repair_recovered {
            "recovered it"
        } else {
            "did not recover it"
        };
        out.push(format!(
            "- Threat model reply did not parse; the one repair re-ask {result}"
        ));
    }
    if tm.threats_truncated > 0 {
        out.push(format!(
            "- Threats truncated by the prompt cap: {} of {}",
            tm.threats_truncated, tm.threats_raw
        ));
    }
    if tm.threats_promoted > 0 {
        out.push(format!(
            "- Threats re-promoted after truncation to keep a trust boundary covered: {}",
            tm.threats_promoted
        ));
    }
    if !tm.baseline_undisposed.is_empty() {
        out.push(format!(
            "- Baseline checklist items with no threat or open question disposing of \
             them: {}",
            list(&tm.baseline_undisposed)
        ));
    }
    if !tm.repo_kinds.is_empty() {
        out.push(format!(
            "- Repository kind(s) detected: {}",
            list(&tm.repo_kinds)
        ));
    }
}

fn decompose_lines(d: &PipelineDiagnostics, out: &mut Vec<String>) {
    let dc = &d.decompose;
    if dc.no_threats_prompt {
        out.push("- Strategist ran without a threat model (no-threats prompt)".to_string());
    }
    if dc.threats_covered < dc.threats_counted {
        out.push(format!(
            "- Threats with at least one chunk reviewing them: {} of {}",
            dc.threats_covered, dc.threats_counted
        ));
    }
    if !dc.lens_chunks.is_empty() {
        let lenses: Vec<String> = dc
            .lens_chunks
            .iter()
            .map(|(lens, n)| format!("{}={n}", md_cell(lens)))
            .collect();
        out.push(format!(
            "- Specialist chunks by lens: {}",
            lenses.join(", ")
        ));
    }
    if !dc.gated_off_lenses.is_empty() {
        out.push(format!(
            "- Specialist lenses with no matching surface (not run): {}",
            list(&dc.gated_off_lenses)
        ));
    }
    if dc.unknown_file_ids > 0 {
        out.push(format!(
            "- Chunk file references that matched no known file id: {}",
            dc.unknown_file_ids
        ));
    }
    if dc.dropped_paths > 0 {
        out.push(format!(
            "- File references dropped (no matching file found): {}",
            dc.dropped_paths
        ));
    }
    if dc.relocated_paths > 0 {
        out.push(format!(
            "- **File references repaired by a suffix match: {}**. The strategist named a \
             file that did not exist as given; verify these did not resolve onto the \
             wrong file of the same name.",
            dc.relocated_paths
        ));
    }
    if dc.invalid_chunks_dropped > 0 {
        out.push(format!(
            "- Strategist chunks dropped as invalid (the rest of the reply was kept): {}",
            dc.invalid_chunks_dropped
        ));
    }
    if dc.empty_chunks_dropped > 0 {
        out.push(format!(
            "- Empty chunks dropped: {}",
            dc.empty_chunks_dropped
        ));
    }
    if dc.forced_coverage_files > 0 {
        // Python's own comment on this label: the backstop carries a skip
        // list and `reachable_only` prunes further, so files can still
        // reach zero reviewers. The label must not claim full coverage.
        out.push(format!(
            "- **Files added back by the coverage backstop: {}**. Files no review pass \
             would otherwise have reached.",
            dc.forced_coverage_files
        ));
    }
    if dc.unreachable_files > 0 {
        out.push(format!(
            "- Files left out of the catch-all sweep as unreachable: {}",
            dc.unreachable_files
        ));
    }
    if dc.fallback_chunks > 0 {
        out.push(format!(
            "- Threat-fallback chunks built for threats the strategist left \
             uncovered: {}",
            dc.fallback_chunks
        ));
    }
    if dc.fallback_chunks_capped > 0 {
        out.push(format!(
            "- Threat-fallback chunks suppressed by the fallback cap: {}",
            dc.fallback_chunks_capped
        ));
    }
    if dc.fallback_files_trimmed > 0 {
        out.push(format!(
            "- Files trimmed from threat-fallback chunks to stay within the chunk size: {}",
            dc.fallback_files_trimmed
        ));
    }
}

fn later_stage_lines(d: &PipelineDiagnostics, out: &mut Vec<String>) {
    let dd = &d.deepdive;
    if dd.json_repairs_attempted > 0 {
        out.push(format!(
            "- Deep-dive replies that needed a JSON repair re-ask: {} ({} recovered)",
            dd.json_repairs_attempted, dd.json_repairs_succeeded
        ));
    }
    if dd.findings_truncated > 0 {
        out.push(format!(
            "- **Deep-dive findings discarded by the per-call cap: {}**. One or more calls \
             produced more findings than step4.max_findings_per_run allows; only the \
             highest-confidence findings from each call were kept.",
            dd.findings_truncated
        ));
    }
    if dd.vote_threshold_clamped > 0 {
        out.push(format!(
            "- Chunks whose vote threshold was lowered to the runs that succeeded: {}",
            dd.vote_threshold_clamped
        ));
    }
    if dd.empty_chunks_skipped > 0 {
        out.push(format!(
            "- Deep-dive chunks skipped because they carried no files: {}",
            dd.empty_chunks_skipped
        ));
    }
    if dd.leader_start_cap_expired > 0 {
        out.push(format!(
            "- Shard siblings that stopped waiting for their leader to start and ran \
             ungated (the shared prompt prefix may have been cached twice): {}",
            dd.leader_start_cap_expired
        ));
    }
    if dd.gate_cap_expired > 0 {
        out.push(format!(
            "- Shard siblings whose leader was still running when the wait cap \
             expired: {}",
            dd.gate_cap_expired
        ));
    }
    if dd.sibling_parked_ms > 0 {
        out.push(format!(
            "- Time shard siblings spent parked behind their leader: {:.1}s",
            dd.sibling_parked_ms as f64 / 1000.0
        ));
    }
    if d.prefilter.evidence_exempted > 0 {
        out.push(format!(
            "- Findings kept without a source/sink pair because they are \
             point-of-occurrence (credential, missing control, information leak): {}",
            d.prefilter.evidence_exempted
        ));
    }
    let v = &d.verify;
    if v.verdict_repairs_attempted > 0 {
        out.push(format!(
            "- Verifier replies that needed a verdict-format repair re-ask: {} ({} adopted)",
            v.verdict_repairs_attempted, v.verdict_repairs_adopted
        ));
    }
}

/// The section's lines, or nothing at all for a run with nothing to say.
pub fn render_pipeline_diagnostics(m: &ScanMetrics) -> Vec<String> {
    let d = &m.pipeline_diagnostics;
    if !d.is_noteworthy() && m.llm_truncated_replies == 0 {
        return Vec::new();
    }
    let mut lines = vec!["### Pipeline Diagnostics".to_string(), String::new()];
    autoexclude_lines(d, &mut lines);
    threat_model_lines(d, &mut lines);
    decompose_lines(d, &mut lines);
    later_stage_lines(d, &mut lines);
    if m.llm_truncated_replies > 0 {
        lines.push(format!(
            "- **LLM replies cut off by the output-token budget: {}** (VVAH-E005). The \
             reply and its one doubled-budget retry both hit the completion cap, so the \
             owning unit failed loudly instead of a truncated reply passing as success; \
             its results are absent from this report.",
            m.llm_truncated_replies
        ));
    }
    lines.push(String::new());
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metrics(d: PipelineDiagnostics) -> ScanMetrics {
        ScanMetrics {
            pipeline_diagnostics: d,
            ..ScanMetrics::default()
        }
    }

    #[test]
    fn a_clean_run_renders_no_section() {
        assert!(render_pipeline_diagnostics(&ScanMetrics::default()).is_empty());
        // Context alone is not a reason to render.
        let mut d = PipelineDiagnostics::default();
        d.threat_model.repo_kinds = vec!["web".to_string()];
        d.threat_model.agentic = true;
        d.threat_model.threats_raw = 9;
        assert!(render_pipeline_diagnostics(&metrics(d)).is_empty());
    }

    #[test]
    fn a_truncated_reply_alone_renders_the_section() {
        let m = ScanMetrics {
            llm_truncated_replies: 2,
            ..ScanMetrics::default()
        };
        let md = render_pipeline_diagnostics(&m).join("\n");
        assert!(md.starts_with("### Pipeline Diagnostics\n"), "{md}");
        assert!(
            md.contains("LLM replies cut off by the output-token budget: 2**"),
            "{md}"
        );
        assert!(md.ends_with('\n'));
    }

    #[test]
    fn every_counter_renders_its_own_line() {
        let mut d = PipelineDiagnostics::default();
        d.autoexclude.vetoed = vec!["*.py".to_string()];
        d.autoexclude.discarded_empty_scope = true;
        d.autoexclude.aggressive = true;
        d.autoexclude.files_before = 100;
        d.autoexclude.files_after = 5;
        d.threat_model.degraded = true;
        d.threat_model.agentic = true;
        d.threat_model.parse_repair_attempted = true;
        d.threat_model.threats_raw = 30;
        d.threat_model.threats_truncated = 5;
        d.threat_model.threats_promoted = 2;
        d.threat_model.baseline_undisposed = vec!["WEB-01".to_string()];
        d.threat_model.repo_kinds = vec!["web".to_string(), "cli".to_string()];
        d.decompose.no_threats_prompt = true;
        d.decompose.threats_covered = 3;
        d.decompose.threats_counted = 4;
        d.decompose.lens_chunks.insert("authz".to_string(), 2);
        d.decompose.lens_chunks.insert("crypto".to_string(), 1);
        d.decompose.gated_off_lenses = vec!["ssrf".to_string()];
        d.decompose.unknown_file_ids = 1;
        d.decompose.dropped_paths = 2;
        d.decompose.relocated_paths = 3;
        d.decompose.invalid_chunks_dropped = 4;
        d.decompose.empty_chunks_dropped = 5;
        d.decompose.forced_coverage_files = 6;
        d.decompose.unreachable_files = 7;
        d.decompose.fallback_chunks = 8;
        d.decompose.fallback_chunks_capped = 9;
        d.decompose.fallback_files_trimmed = 10;
        d.deepdive.json_repairs_attempted = 3;
        d.deepdive.json_repairs_succeeded = 2;
        d.deepdive.findings_truncated = 11;
        d.deepdive.vote_threshold_clamped = 12;
        d.deepdive.empty_chunks_skipped = 13;
        d.deepdive.leader_start_cap_expired = 15;
        d.deepdive.gate_cap_expired = 16;
        d.deepdive.sibling_parked_ms = 2500;
        d.prefilter.evidence_exempted = 14;
        d.verify.verdict_repairs_attempted = 4;
        d.verify.verdict_repairs_adopted = 1;
        let md = render_pipeline_diagnostics(&metrics(d)).join("\n");
        for expected in [
            "language from scope: `*.py`",
            "Auto-exclude overlay discarded**: it would have emptied the scope (100 files -> 0)",
            "Aggressive auto-exclude overlay applied**: it kept 5 of 100 files",
            "Threat model: **degraded**",
            "agentic, tool-using session",
            "the one repair re-ask did not recover it",
            "Threats truncated by the prompt cap: 5 of 30",
            "keep a trust boundary covered: 2",
            "disposing of them: WEB-01",
            "Repository kind(s) detected: web, cli",
            "without a threat model (no-threats prompt)",
            "Threats with at least one chunk reviewing them: 3 of 4",
            "Specialist chunks by lens: authz=2, crypto=1",
            "no matching surface (not run): ssrf",
            "matched no known file id: 1",
            "no matching file found): 2",
            "repaired by a suffix match: 3**",
            "dropped as invalid (the rest of the reply was kept): 4",
            "Empty chunks dropped: 5",
            "coverage backstop: 6**",
            "catch-all sweep as unreachable: 7",
            "strategist left uncovered: 8",
            "suppressed by the fallback cap: 9",
            "within the chunk size: 10",
            "JSON repair re-ask: 3 (2 recovered)",
            "per-call cap: 11**",
            "runs that succeeded: 12",
            "carried no files: 13",
            "cached twice): 15",
            "wait cap expired: 16",
            "parked behind their leader: 2.5s",
            "information leak): 14",
            "verdict-format repair re-ask: 4 (1 adopted)",
        ] {
            assert!(md.contains(expected), "missing {expected:?} in:\n{md}");
        }
        assert!(!md.contains("LLM replies cut off"), "{md}");
    }

    #[test]
    fn a_recovered_parse_repair_says_so() {
        let mut d = PipelineDiagnostics::default();
        d.threat_model.parse_repair_attempted = true;
        d.threat_model.parse_repair_recovered = true;
        let md = render_pipeline_diagnostics(&metrics(d)).join("\n");
        assert!(md.contains("the one repair re-ask recovered it"), "{md}");
    }

    #[test]
    fn model_authored_and_config_text_cannot_restructure_the_report() {
        let mut d = PipelineDiagnostics::default();
        d.autoexclude.vetoed = vec!["x`\n## Injected".to_string()];
        d.threat_model.baseline_undisposed = vec!["a\n# Heading".to_string()];
        d.decompose.lens_chunks.insert("l|x\n- item".to_string(), 1);
        let md = render_pipeline_diagnostics(&metrics(d)).join("\n");
        assert!(!md.contains("\n## Injected"), "{md}");
        assert!(!md.contains("\n# Heading"), "{md}");
        assert!(!md.contains("\n- item"), "{md}");
        assert!(md.contains("`x\u{2CB}"), "{md}");
    }
}
