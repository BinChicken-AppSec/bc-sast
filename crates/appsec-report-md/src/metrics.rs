use serde_json::Value;
use std::path::Path;

use appsec_model::{FileDisposition, RepoIdentity, ScanMetrics};

use crate::sanitize::md_code_span;

pub(crate) fn with_commas(n: i64) -> String {
    let (sign, digits) = if n < 0 {
        ("-", n.unsigned_abs().to_string())
    } else {
        ("", n.to_string())
    };
    let mut grouped = String::new();
    for (i, c) in digits.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            grouped.push(',');
        }
        grouped.push(c);
    }
    format!("{sign}{}", grouped.chars().rev().collect::<String>())
}

fn get_i64(v: &Value, key: &str) -> i64 {
    v.get(key).and_then(Value::as_i64).unwrap_or(0)
}

fn get_f64(v: &Value, key: &str) -> Option<f64> {
    v.get(key).and_then(Value::as_f64)
}

pub(crate) fn usd(dollars: f64) -> String {
    format!("{dollars:.6}")
}

pub(crate) const UNPRICED: &str = "unpriced";

fn count_map(v: &Value, key: &str) -> Vec<(String, i64)> {
    v.get(key)
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .filter_map(|(k, n)| n.as_i64().map(|n| (k.clone(), n)))
                .collect()
        })
        .unwrap_or_default()
}

fn pair_list(v: &Value, key: &str) -> Vec<(String, i64)> {
    v.get(key)
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|item| {
                    let a = item.as_array()?;
                    let path = a.first()?.as_str()?.to_string();
                    let n = a.get(1)?.as_i64()?;
                    Some((path, n))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn str_pair_list(v: &Value, key: &str) -> Vec<(String, String)> {
    v.get(key)
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|item| {
                    let a = item.as_array()?;
                    let path = a.first()?.as_str()?.to_string();
                    let why = a.get(1)?.as_str()?.to_string();
                    Some((path, why))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn sorted_desc(mut pairs: Vec<(String, i64)>) -> Vec<(String, i64)> {
    pairs.sort_by_key(|(_, n)| -*n);
    pairs
}

struct Phase<'a> {
    name: &'a str,
    calls: i64,
    prompt: i64,
    completion: i64,
    reasoning: i64,
    cache_read: i64,
    cost_usd: Option<f64>,
    unpriced_tokens: i64,
}

impl Phase<'_> {
    fn tokens(&self) -> i64 {
        self.prompt + self.completion
    }

    fn cost_cell(&self) -> String {
        match self.cost_usd {
            Some(dollars) => usd(dollars),
            None if self.unpriced_tokens > 0 => UNPRICED.to_string(),
            None => "-".to_string(),
        }
    }
}

fn render_cost(m: &ScanMetrics) -> Vec<String> {
    if m.cost_usd.is_none() && m.unpriced_tokens.is_none() {
        return Vec::new();
    }
    let mut lines = vec![format!(
        "- Cost (USD): {}",
        m.cost_usd.map(usd).unwrap_or_else(|| UNPRICED.to_string())
    )];
    let unpriced_tokens = m.unpriced_tokens.unwrap_or(0);
    if unpriced_tokens > 0 {
        let calls = m.unpriced_calls.unwrap_or(0);
        let models = if m.unpriced_models.is_empty() {
            String::new()
        } else {
            format!(" ({})", m.unpriced_models.join(", "))
        };
        lines.push(format!(
            "- Unpriced tokens: {unpriced_tokens} across {calls} call(s) with no published \
             rate{models}; the cost above is a lower bound"
        ));
    }
    lines
}

pub fn render_repo_identity(identity: Option<&RepoIdentity>) -> Vec<String> {
    let Some(id) = identity else {
        return Vec::new();
    };
    let mut lines = Vec::new();
    match &id.key {
        Some(key) => lines.push(format!(
            "- Repository key: `{}` (from {})",
            md_code_span(&key.value),
            key.source.as_str()
        )),
        None => lines.push(
            "- Repository key: none resolved, so this scan cannot be compared with              earlier scans of the same repository. Pass `--repo-key` or set a git              remote that is not a filesystem path."
                .to_string(),
        ),
    }
    if let Some(origin) = &id.origin_display {
        lines.push(format!("- Origin: `{}`", md_code_span(origin)));
    }
    if !id.subtree.is_empty() {
        lines.push(format!("- Subtree: `{}`", md_code_span(&id.subtree)));
    }
    if let Some(branch) = &id.branch {
        lines.push(format!("- Branch: `{}`", md_code_span(branch)));
    }
    if let Some(base) = &id.merge_base {
        lines.push(format!("- Merge base: `{}`", md_code_span(base)));
    }
    if id.worktree_dirty {
        lines.push(
            "- Worktree: dirty at scan time, so these findings cannot be attributed              to the recorded commit"
                .to_string(),
        );
    }
    if id.root_commit.is_some() && !id.root_commit_verified {
        lines.push(
            "- Repository identity: unverified (shallow clone), so a later scan              cannot use it to confirm this is the same repository"
                .to_string(),
        );
    }
    let mut out = vec!["## Repository".to_string(), String::new()];
    out.extend(lines);
    out.push(String::new());
    out
}

fn not_reviewed_lines(m: &ScanMetrics) -> Vec<String> {
    let mut by_reason: Vec<(&'static str, i64)> = Vec::new();
    let mut total = 0;
    for (key, count) in &m.files_by_disposition {
        let Some(d) = FileDisposition::from_key(key) else {
            continue;
        };
        if d.reviewed() || *count == 0 {
            continue;
        }
        total += count;
        by_reason.push((d.reason(), *count));
    }
    if total == 0 {
        return Vec::new();
    }
    by_reason.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    let mut lines = vec![format!("- Not reviewed: {total}")];
    lines.extend(
        by_reason
            .into_iter()
            .map(|(reason, count)| format!("  - {reason}: {count}")),
    );
    lines
}

pub fn render_metrics(m: &ScanMetrics) -> Vec<String> {
    let mut lines = vec![
        "## Scan Metrics".to_string(),
        String::new(),
        format!("- Scan ID: {}", m.scan_id),
        format!("- Module: {}", m.module_name),
        format!("- Start: {}", m.start_ts),
        format!("- End: {}", m.end_ts),
        format!("- Duration (sec): {:.0}", m.duration_sec),
        format!("- Files in scope: {}", m.total_files_in_scope),
        format!("- Files analyzed (unique): {}", m.analyzed_files_unique),
        format!("- Coverage: {:.1}%", m.coverage_pct()),
    ];
    lines.extend(not_reviewed_lines(m));
    if !m.scan_uuid.is_empty() {
        lines.insert(3, format!("- Scan UUID: {}", m.scan_uuid));
    }
    if m.diff_scope_active {
        lines.push(format!(
            "- Scope: PR diff ({} of {} files)",
            m.changed_files_count, m.total_files_in_scope
        ));
    }
    lines.extend([
        format!(
            "- Chunks: {} (risk={}, catch-all={}, specialist={})",
            m.chunks_total, m.chunks_risk, m.chunks_catchall, m.chunks_specialist
        ),
        format!(
            "- Tokens (prompt): {}",
            m.prompt_tokens
                .map(|t| t.to_string())
                .unwrap_or_else(|| "unavailable".to_string())
        ),
        format!(
            "- Tokens (completion): {}",
            m.completion_tokens
                .map(|t| t.to_string())
                .unwrap_or_else(|| "unavailable".to_string())
        ),
        format!(
            "- Tokens (total): {}",
            m.total_tokens
                .map(|t| t.to_string())
                .unwrap_or_else(|| "unavailable".to_string())
        ),
    ]);
    lines.extend(render_cost(m));
    lines.push(String::new());

    if !m.folders_scanned.is_empty() {
        lines.push(format!("- Folders scanned: {}", m.folders_scanned.len()));
    }
    lines.extend(crate::diagnostics::render_pipeline_diagnostics(m));

    if let Some(phases) = m.tokens_by_phase.as_ref().filter(|p| !p.is_empty()) {
        lines.push("### Tokens by Phase".to_string());
        lines.push(String::new());
        lines.push(
            "_Prompt = fresh + cache-write (billable). Cache-read shown separately, NOT included \
             in totals. Cost is summed one call at a time, each at its own context tier, and \
             cache-reads DO cost money and are included in it._"
                .to_string(),
        );
        lines.push(String::new());
        lines.push(
            "| Phase | Calls | Prompt | Completion | of which reasoning | Total | % | Cache-read (excl.) | Cost (USD) |"
                .to_string(),
        );
        lines.push("|---|---:|---:|---:|---:|---:|---:|---:|---:|".to_string());

        let totals: Vec<Phase<'_>> = phases
            .iter()
            .map(|(ph, b)| Phase {
                name: ph,
                calls: get_i64(b, "calls"),
                prompt: get_i64(b, "prompt"),
                completion: get_i64(b, "completion"),
                cache_read: get_i64(b, "cache_read"),
                reasoning: get_i64(b, "reasoning"),
                cost_usd: get_f64(b, "cost_usd"),
                unpriced_tokens: get_i64(b, "unpriced_tokens"),
            })
            .collect();
        let grand: i64 = totals.iter().map(Phase::tokens).sum::<i64>().max(1);
        let mut sorted = totals;
        sorted.sort_by_key(|p| -p.tokens());
        for phase in sorted {
            let tot = phase.tokens();
            let pct = tot as f64 / grand as f64 * 100.0;
            lines.push(format!(
                "| {} | {} | {} | {} | {} | {} | {pct:.1} | {} | {} |",
                phase.name,
                phase.calls,
                with_commas(phase.prompt),
                with_commas(phase.completion),
                with_commas(phase.reasoning),
                with_commas(tot),
                with_commas(phase.cache_read),
                phase.cost_cell(),
            ));
        }
        lines.push(String::new());
    }

    if !m.loc_in_scope_by_language.is_empty() {
        lines.push("### Language LOC Coverage".to_string());
        lines.push(String::new());
        lines.push("| Language | LOC in scope | LOC scanned | Coverage % |".to_string());
        lines.push("|---|---:|---:|---:|".to_string());
        for (lang, loc_in) in &m.loc_in_scope_by_language {
            let loc_sc = m.loc_scanned_by_language.get(lang).copied().unwrap_or(0);
            let pct = if *loc_in != 0 {
                loc_sc as f64 / *loc_in as f64 * 100.0
            } else {
                0.0
            };
            lines.push(format!("| {lang} | {loc_in} | {loc_sc} | {pct:.1} |"));
        }
        lines.push(String::new());
    }

    lines
}

pub fn render_scan_health(
    degraded: bool,
    degraded_reason: &str,
    metrics: Option<&ScanMetrics>,
) -> Vec<String> {
    let failed = metrics.map(|m| m.chunks_failed).unwrap_or(0);
    let errs: Vec<(String, i64)> = metrics
        .map(|m| {
            m.errors_by_stage
                .iter()
                .map(|(k, v)| (k.clone(), *v))
                .collect()
        })
        .unwrap_or_default();
    let budget_stop = metrics
        .map(|m| m.budget_stop.as_str())
        .filter(|b| !b.is_empty());
    let canceled = metrics.is_some_and(|m| m.canceled);
    let unchunked = metrics
        .and_then(|m| m.files_by_disposition.get("unchunked").copied())
        .unwrap_or(0);
    if !degraded
        && failed == 0
        && errs.is_empty()
        && budget_stop.is_none()
        && !canceled
        && unchunked == 0
    {
        return Vec::new();
    }
    let mut lines = vec!["## Scan Health".to_string(), String::new()];
    if unchunked > 0 {
        lines.push(format!(
            "- **SCANNER DEFECT**: {unchunked} in-scope file(s) were eligible for review              and reached no chunk, so nothing looked at them. Every eligible file is              supposed to be swept into a chunk; please report this with the file list              from `findings.json`."
        ));
    }
    if canceled {
        let at = budget_stop.map(|b| format!(" ({b})")).unwrap_or_default();
        lines.push(format!(
            "- \u{26a0}\u{fe0f} **CANCELED** by the operator (Ctrl-C){at}. This is a \
             PARTIAL report: the scan stopped starting new work at that point, the stages \
             after it were skipped, and any finding listed as not verified was never sent \
             to the verifier."
        ));
    } else if let Some(budget_stop) = budget_stop {
        lines.push(format!(
            "- \u{26a0}\u{fe0f} **BUDGET REACHED** — {budget_stop}. The scan stopped starting new \
             work at that point; findings from the work not done are absent, and any finding \
             listed as not verified was never sent to the verifier."
        ));
    }
    if degraded {
        let reason = if degraded_reason.is_empty() {
            "the exploit-chain pass could not be computed; findings are unranked"
        } else {
            degraded_reason
        };
        lines.push(format!("- \u{26a0}\u{fe0f} **DEGRADED** — {reason}"));
    }
    if failed != 0 {
        let attempted = metrics
            .map(|m| {
                if m.chunks_attempted != 0 {
                    m.chunks_attempted
                } else {
                    m.chunks_total
                }
            })
            .unwrap_or(0);
        lines.push(format!(
            "- \u{26a0}\u{fe0f} Degraded coverage: {failed}/{attempted} deep-dive chunk(s) failed or \
             timed out — their findings are absent from this report."
        ));
    }
    if !errs.is_empty() {
        let brk: Vec<String> = errs.iter().map(|(s, n)| format!("{s}={n}")).collect();
        lines.push(format!(
            "- Recoverable errors logged by stage: {}",
            brk.join(", ")
        ));
    }
    if let Some(log_path) = metrics
        .map(|m| m.errors_log_path.as_str())
        .filter(|p| !p.is_empty())
    {
        let basename = Path::new(log_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(log_path);
        lines.push(format!("- Full error log: `{basename}`"));
    }
    lines.push(String::new());
    lines
}

pub fn render_scope_appendix(m: &ScanMetrics) -> Vec<String> {
    let mut out = vec![
        String::new(),
        "---".to_string(),
        String::new(),
        "## Appendix: Scan Scope".to_string(),
        String::new(),
    ];

    if !m.folders_scanned.is_empty() {
        out.push(format!("### Folders scanned ({})", m.folders_scanned.len()));
        out.push(String::new());
        out.extend(m.folders_scanned.iter().map(|d| format!("- `{d}/`")));
        out.push(String::new());
    }

    let ex = Value::Object(
        m.excluded
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
    );
    let config_dedup = ex.get("config_dedup").cloned().unwrap_or(Value::Null);
    let dd_dropped = get_i64(&config_dedup, "dropped");
    let dirs = sorted_desc(count_map(&ex, "dirs"));
    let exts = sorted_desc(count_map(&ex, "exts"));
    let globs = sorted_desc(count_map(&ex, "globs"));
    let oversize = get_i64(&ex, "oversize");
    let symlinks = sorted_desc(count_map(&ex, "symlinks"));

    if dd_dropped != 0
        || !dirs.is_empty()
        || !exts.is_empty()
        || !globs.is_empty()
        || oversize != 0
        || !symlinks.is_empty()
    {
        let n_total: i64 = dirs.iter().map(|(_, n)| n).sum::<i64>()
            + exts.iter().map(|(_, n)| n).sum::<i64>()
            + globs.iter().map(|(_, n)| n).sum::<i64>()
            + oversize
            + symlinks.iter().map(|(_, n)| n).sum::<i64>()
            + dd_dropped;
        out.push(format!("### Excluded from scan ({n_total} files)"));
        out.push(String::new());

        if !dirs.is_empty() {
            out.push("**Folders** (matched `exclude_dirs`):".to_string());
            out.push(String::new());
            out.extend(dirs.iter().map(|(d, n)| format!("- `{d}/` — {n} files")));
            out.push(String::new());
        }
        if !exts.is_empty() {
            out.push("**File types** (matched `exclude_exts`):".to_string());
            out.push(String::new());
            out.extend(exts.iter().map(|(e, n)| format!("- `*{e}` — {n} files")));
            out.push(String::new());
        }
        if !globs.is_empty() {
            out.push("**Patterns** (matched `exclude_globs`):".to_string());
            out.push(String::new());
            out.extend(globs.iter().map(|(g, n)| format!("- `{g}` — {n} files")));
            out.push(String::new());
        }
        if oversize != 0 {
            out.push(format!("**Oversize** (> `max_file_kb`): {oversize} files"));
            out.push(String::new());
            let oversize_files = pair_list(&ex, "oversize_files");
            out.extend(
                oversize_files.iter().map(|(p, sz)| {
                    format!("- `{}` — {:.0} KB", md_code_span(p), *sz as f64 / 1024.0)
                }),
            );
            if !oversize_files.is_empty() {
                out.push(String::new());
            }
        }
        if !symlinks.is_empty() {
            out.push("**Symlinks** (target resolves outside the repo — not followed):".to_string());
            out.push(String::new());
            out.extend(symlinks.iter().map(|(p, n)| {
                let suffix = if *n != 1 {
                    format!(" — {n} files")
                } else {
                    String::new()
                };
                format!("- `{}`{suffix}", md_code_span(p))
            }));
            out.push(String::new());
        }
        if dd_dropped != 0 {
            let candidates = get_i64(&config_dedup, "candidates");
            let clusters = get_i64(&config_dedup, "clusters");
            let kept_reps = get_i64(&config_dedup, "kept_reps");
            let promoted = get_i64(&config_dedup, "promoted");
            out.push(format!(
                "**Config dedup**: {candidates} config files -> {clusters} shape-clusters; kept \
                 {kept_reps} representatives + {promoted} promoted (suspicious value), dropped \
                 {dd_dropped} near-duplicates."
            ));
            out.push(String::new());
            if let Some(top_clusters) = config_dedup.get("top_clusters").and_then(Value::as_array) {
                for c in top_clusters {
                    let sample = c.get("sample").and_then(Value::as_str).unwrap_or("");
                    let size = get_i64(c, "size");
                    let reps_len = c
                        .get("reps")
                        .and_then(Value::as_array)
                        .map(Vec::len)
                        .unwrap_or(0);
                    let dropped = get_i64(c, "dropped");
                    out.push(format!(
                        "- `{}` x{size} (kept {reps_len}, dropped {dropped})",
                        md_code_span(sample)
                    ));
                }
            }
            let promoted_files = str_pair_list(&config_dedup, "promoted_files");
            if !promoted_files.is_empty() {
                out.push(String::new());
                out.push(
                    "Promoted (suspicious value not present in cluster representative):"
                        .to_string(),
                );
                out.push(String::new());
                out.extend(
                    promoted_files.iter().map(|(p, why)| {
                        format!("- `{}` — `{}`", md_code_span(p), md_code_span(why))
                    }),
                );
            }
            out.push(String::new());
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use serde_json::json;
    use std::collections::BTreeMap;

    #[rstest]
    #[case(0, "0")]
    #[case(999, "999")]
    #[case(1000, "1,000")]
    #[case(1234567, "1,234,567")]
    #[case(-1234, "-1,234")]
    fn with_commas_cases(#[case] n: i64, #[case] expected: &str) {
        assert_eq!(with_commas(n), expected);
    }

    fn base_metrics() -> ScanMetrics {
        ScanMetrics {
            scan_id: "s1".to_string(),
            module_name: "core".to_string(),
            start_ts: "2026-01-01T00:00:00Z".to_string(),
            end_ts: "2026-01-01T00:10:00Z".to_string(),
            duration_sec: 600.0,
            total_files_in_scope: 100,
            analyzed_files_unique: 50,
            chunks_total: 10,
            chunks_risk: 6,
            chunks_catchall: 3,
            chunks_specialist: 1,
            ..Default::default()
        }
    }

    #[test]
    fn render_metrics_basic_fields() {
        let md = render_metrics(&base_metrics()).join("\n");
        assert!(md.contains("## Scan Metrics"));
        assert!(md.contains("- Scan ID: s1"));
        assert!(md.contains("- Module: core"));
        assert!(md.contains("- Start: 2026-01-01T00:00:00Z"));
        assert!(md.contains("- End: 2026-01-01T00:10:00Z"));
        assert!(md.contains("- Duration (sec): 600"));
        assert!(md.contains("- Files in scope: 100"));
        assert!(md.contains("- Files analyzed (unique): 50"));
        assert!(md.contains("- Coverage: 50.0%"));
        assert!(md.contains("- Chunks: 10 (risk=6, catch-all=3, specialist=1)"));
    }

    #[test]
    fn scope_line_omitted_when_diff_scope_is_not_active() {
        let md = render_metrics(&base_metrics()).join("\n");
        assert!(!md.contains("- Scope:"));
    }

    #[test]
    fn scope_line_shows_changed_vs_total_files_when_diff_scope_is_active() {
        let m = ScanMetrics {
            diff_scope_active: true,
            changed_files_count: 3,
            ..base_metrics()
        };
        let md = render_metrics(&m).join("\n");
        assert!(md.contains("- Scope: PR diff (3 of 100 files)"));
    }

    #[test]
    fn scope_line_still_renders_with_a_zero_count_when_diff_scope_is_active() {
        let m = ScanMetrics {
            diff_scope_active: true,
            changed_files_count: 0,
            ..base_metrics()
        };
        let md = render_metrics(&m).join("\n");
        assert!(md.contains("- Scope: PR diff (0 of 100 files)"));
    }

    #[test]
    fn scope_line_stays_omitted_for_a_full_repo_scan_with_a_stale_nonzero_count() {
        let m = ScanMetrics {
            diff_scope_active: false,
            changed_files_count: 3,
            ..base_metrics()
        };
        let md = render_metrics(&m).join("\n");
        assert!(!md.contains("- Scope:"));
    }

    #[test]
    fn tokens_absent_render_unavailable() {
        let md = render_metrics(&base_metrics()).join("\n");
        assert!(md.contains("- Tokens (prompt): unavailable"));
        assert!(md.contains("- Tokens (completion): unavailable"));
        assert!(md.contains("- Tokens (total): unavailable"));
    }

    #[test]
    fn tokens_present_render_numerically() {
        let m = ScanMetrics {
            prompt_tokens: Some(100),
            completion_tokens: Some(50),
            total_tokens: Some(150),
            ..base_metrics()
        };
        let md = render_metrics(&m).join("\n");
        assert!(md.contains("- Tokens (prompt): 100"));
        assert!(md.contains("- Tokens (completion): 50"));
        assert!(md.contains("- Tokens (total): 150"));
    }

    #[test]
    fn folders_scanned_absent_omits_the_bullet() {
        let md = render_metrics(&base_metrics()).join("\n");
        assert!(!md.contains("Folders scanned"));
    }

    #[test]
    fn folders_scanned_present_shows_count() {
        let m = ScanMetrics {
            folders_scanned: vec!["a".to_string(), "b".to_string()],
            ..base_metrics()
        };
        let md = render_metrics(&m).join("\n");
        assert!(md.contains("- Folders scanned: 2"));
    }

    #[test]
    fn tokens_by_phase_absent_omits_the_table() {
        let md = render_metrics(&base_metrics()).join("\n");
        assert!(!md.contains("Tokens by Phase"));
    }

    #[test]
    fn tokens_by_phase_empty_map_omits_the_table() {
        let m = ScanMetrics {
            tokens_by_phase: Some(BTreeMap::new()),
            ..base_metrics()
        };
        let md = render_metrics(&m).join("\n");
        assert!(!md.contains("Tokens by Phase"));
    }

    #[test]
    fn tokens_by_phase_sorted_descending_with_commas_and_percentages() {
        let mut phases = BTreeMap::new();
        phases.insert(
            "s1_preprocess".to_string(),
            json!({"calls": 2, "prompt": 1000, "completion": 500, "cache_read": 200,
                   "cost_usd": 0.0125, "unpriced_tokens": 0}),
        );
        phases.insert(
            "s4_deepdive".to_string(),
            json!({"calls": 5, "prompt": 5000, "completion": 3500, "cache_read": 1000,
                   "cost_usd": 0.0715, "unpriced_tokens": 0}),
        );
        let m = ScanMetrics {
            tokens_by_phase: Some(phases),
            ..base_metrics()
        };
        let md = render_metrics(&m).join("\n");
        assert!(md.contains("### Tokens by Phase"));
        assert!(md.contains(
            "| Phase | Calls | Prompt | Completion | of which reasoning | Total | % | Cache-read (excl.) | Cost (USD) |"
        ));
        assert!(md.contains("|---|---:|---:|---:|---:|---:|---:|---:|---:|"));
        let deepdive_pos = md.find("s4_deepdive").unwrap();
        let preprocess_pos = md.find("s1_preprocess").unwrap();
        assert!(
            deepdive_pos < preprocess_pos,
            "larger total must sort first"
        );
        assert!(
            md.contains(
                "| s4_deepdive | 5 | 5,000 | 3,500 | 0 | 8,500 | 85.0 | 1,000 | 0.071500 |"
            ),
            "{md}"
        );
        assert!(
            md.contains("| s1_preprocess | 2 | 1,000 | 500 | 0 | 1,500 | 15.0 | 200 | 0.012500 |"),
            "{md}"
        );
    }

    #[test]
    fn tokens_by_phase_missing_sub_fields_default_to_zero() {
        let mut phases = BTreeMap::new();
        phases.insert("ph".to_string(), json!({}));
        let m = ScanMetrics {
            tokens_by_phase: Some(phases),
            ..base_metrics()
        };
        let md = render_metrics(&m).join("\n");
        assert!(
            md.contains("| ph | 0 | 0 | 0 | 0 | 0 | 0.0 | 0 | - |"),
            "{md}"
        );
    }

    #[test]
    fn a_phase_that_spent_tokens_it_could_not_price_says_unpriced_in_its_own_row() {
        let mut phases = BTreeMap::new();
        phases.insert(
            "s4_deepdive".to_string(),
            json!({"calls": 3, "prompt": 900, "completion": 100, "cache_read": 0,
                   "cost_usd": null, "unpriced_tokens": 1000}),
        );
        let m = ScanMetrics {
            tokens_by_phase: Some(phases),
            ..base_metrics()
        };
        let md = render_metrics(&m).join("\n");
        assert!(
            md.contains("| s4_deepdive | 3 | 900 | 100 | 0 | 1,000 | 100.0 | 0 | unpriced |"),
            "{md}"
        );
        assert!(!md.contains("| 0.000000 |"), "never a zero here: {md}");
    }

    #[test]
    fn the_table_caption_states_how_cost_is_summed() {
        let mut phases = BTreeMap::new();
        phases.insert("ph".to_string(), json!({}));
        let m = ScanMetrics {
            tokens_by_phase: Some(phases),
            ..base_metrics()
        };
        let md = render_metrics(&m).join("\n");
        assert!(md.contains("Cost is summed one call at a time"), "{md}");
    }

    #[test]
    fn cost_lines_are_absent_when_the_run_recorded_no_money_at_all() {
        let md = render_metrics(&base_metrics()).join("\n");
        assert!(!md.contains("Cost (USD)"), "{md}");
        assert!(!md.contains("Unpriced tokens"), "{md}");
    }

    #[test]
    fn a_fully_priced_run_reports_one_cost_line_and_no_unpriced_line() {
        let m = ScanMetrics {
            cost_usd: Some(12.345678),
            unpriced_tokens: Some(0),
            unpriced_calls: Some(0),
            ..base_metrics()
        };
        let md = render_metrics(&m).join("\n");
        assert!(md.contains("- Cost (USD): 12.345678"), "{md}");
        assert!(!md.contains("Unpriced tokens"), "{md}");
    }

    #[test]
    fn an_unpriced_run_says_unpriced_rather_than_zero_and_names_the_models() {
        let m = ScanMetrics {
            cost_usd: None,
            unpriced_tokens: Some(1_700),
            unpriced_calls: Some(2),
            unpriced_models: vec![
                "openai/house-blend-9".to_string(),
                "openai/mystery-2".to_string(),
            ],
            ..base_metrics()
        };
        let md = render_metrics(&m).join("\n");
        assert!(md.contains("- Cost (USD): unpriced"), "{md}");
        assert!(!md.contains("- Cost (USD): 0"), "{md}");
        assert!(
            md.contains(
                "- Unpriced tokens: 1700 across 2 call(s) with no published rate \
                 (openai/house-blend-9, openai/mystery-2); the cost above is a lower bound"
            ),
            "{md}"
        );
    }

    #[test]
    fn a_mixed_run_reports_a_figure_and_the_gap_beside_it() {
        let m = ScanMetrics {
            cost_usd: Some(4.5),
            unpriced_tokens: Some(300),
            unpriced_calls: Some(1),
            unpriced_models: vec!["openai/mystery-2".to_string()],
            ..base_metrics()
        };
        let md = render_metrics(&m).join("\n");
        assert!(md.contains("- Cost (USD): 4.500000"), "{md}");
        assert!(
            md.contains(
                "- Unpriced tokens: 300 across 1 call(s) with no published rate \
                 (openai/mystery-2); the cost above is a lower bound"
            ),
            "{md}"
        );
    }

    #[test]
    fn unpriced_tokens_with_no_named_model_omit_the_parenthetical() {
        let m = ScanMetrics {
            cost_usd: Some(1.0),
            unpriced_tokens: Some(4_000),
            unpriced_calls: Some(0),
            ..base_metrics()
        };
        let md = render_metrics(&m).join("\n");
        assert!(
            md.contains(
                "- Unpriced tokens: 4000 across 0 call(s) with no published rate; the cost \
                 above is a lower bound"
            ),
            "{md}"
        );
    }

    #[test]
    fn a_cost_with_no_unpriced_count_at_all_still_renders_its_figure() {
        let m = ScanMetrics {
            cost_usd: Some(0.5),
            unpriced_tokens: None,
            ..base_metrics()
        };
        let md = render_metrics(&m).join("\n");
        assert!(md.contains("- Cost (USD): 0.500000"), "{md}");
        assert!(!md.contains("Unpriced tokens"), "{md}");
    }

    #[test]
    fn an_unpriced_count_of_zero_with_no_cost_still_says_unpriced() {
        let m = ScanMetrics {
            cost_usd: None,
            unpriced_tokens: Some(0),
            ..base_metrics()
        };
        let md = render_metrics(&m).join("\n");
        assert!(md.contains("- Cost (USD): unpriced"), "{md}");
        assert!(!md.contains("Unpriced tokens"), "{md}");
    }

    #[test]
    fn loc_by_language_absent_omits_the_table() {
        let md = render_metrics(&base_metrics()).join("\n");
        assert!(!md.contains("Language LOC Coverage"));
    }

    #[test]
    fn loc_by_language_sorted_alphabetically_with_coverage_pct() {
        let mut in_scope = BTreeMap::new();
        in_scope.insert("rust".to_string(), 1000);
        in_scope.insert("python".to_string(), 2000);
        let mut scanned = BTreeMap::new();
        scanned.insert("rust".to_string(), 500);
        let m = ScanMetrics {
            loc_in_scope_by_language: in_scope,
            loc_scanned_by_language: scanned,
            ..base_metrics()
        };
        let md = render_metrics(&m).join("\n");
        let python_pos = md.find("| python |").unwrap();
        let rust_pos = md.find("| rust |").unwrap();
        assert!(
            python_pos < rust_pos,
            "must sort alphabetically, not by value"
        );
        assert!(md.contains("| python | 2000 | 0 | 0.0 |"));
        assert!(md.contains("| rust | 1000 | 500 | 50.0 |"));
    }

    #[test]
    fn loc_by_language_zero_loc_in_scope_is_zero_pct_not_a_divide_by_zero_panic() {
        let mut in_scope = BTreeMap::new();
        in_scope.insert("cobol".to_string(), 0);
        let m = ScanMetrics {
            loc_in_scope_by_language: in_scope,
            ..base_metrics()
        };
        let md = render_metrics(&m).join("\n");
        assert!(md.contains("| cobol | 0 | 0 | 0.0 |"));
    }

    #[test]
    fn render_scan_health_healthy_scan_is_empty() {
        assert!(render_scan_health(false, "", None).is_empty());
        assert!(render_scan_health(false, "", Some(&base_metrics())).is_empty());
    }

    #[test]
    fn render_scan_health_reports_a_budget_stop_on_its_own() {
        let m = ScanMetrics {
            budget_stop: "S6: token budget of 3000000 reached (3012044 spent) — 412 of 1881 \
                          finding(s) verified, 1469 left unverified"
                .to_string(),
            ..Default::default()
        };
        let md = render_scan_health(false, "", Some(&m)).join("\n");
        assert!(md.contains("## Scan Health"), "{md}");
        assert!(md.contains("**BUDGET REACHED**"), "{md}");
        assert!(md.contains("412 of 1881 finding(s) verified"), "{md}");
        assert!(md.contains("never sent to the verifier"), "{md}");
        assert!(!md.contains("DEGRADED"), "{md}");
        assert!(!md.contains("deep-dive chunk"), "{md}");
    }

    #[test]
    fn render_scan_health_budget_stop_leads_the_other_warnings() {
        let mut errs = BTreeMap::new();
        errs.insert("s7".to_string(), 1);
        let m = ScanMetrics {
            budget_stop: "S4: time budget of 60s reached (61s elapsed)".to_string(),
            chunks_failed: 2,
            chunks_attempted: 8,
            errors_by_stage: errs,
            ..Default::default()
        };
        let md = render_scan_health(true, "chain pass failed", Some(&m)).join("\n");
        let budget_at = md.find("BUDGET REACHED").unwrap();
        assert!(budget_at < md.find("DEGRADED").unwrap(), "{md}");
        assert!(budget_at < md.find("deep-dive chunk").unwrap(), "{md}");
        assert!(
            md.contains("- Recoverable errors logged by stage: s7=1"),
            "{md}"
        );
    }

    #[test]
    fn a_canceled_run_says_canceled_not_budget_and_names_where_it_stopped() {
        let m = ScanMetrics {
            canceled: true,
            budget_stop: "S6: canceled by user (Ctrl-C)".to_string(),
            ..ScanMetrics::default()
        };
        let md = render_scan_health(false, "", Some(&m)).join("\n");
        assert!(md.contains("## Scan Health"), "{md}");
        assert!(
            md.contains("**CANCELED** by the operator (Ctrl-C) (S6: canceled"),
            "{md}"
        );
        assert!(md.contains("PARTIAL report"), "{md}");
        assert!(!md.contains("BUDGET REACHED"), "{md}");
    }

    #[test]
    fn a_canceled_run_with_no_stop_point_still_renders_the_banner() {
        let m = ScanMetrics {
            canceled: true,
            ..ScanMetrics::default()
        };
        let md = render_scan_health(false, "", Some(&m)).join("\n");
        assert!(
            md.contains("**CANCELED** by the operator (Ctrl-C). This"),
            "{md}"
        );
    }

    #[test]
    fn render_metrics_places_pipeline_diagnostics_before_the_token_table() {
        let mut m = base_metrics();
        m.llm_truncated_replies = 1;
        m.tokens_by_phase = Some(BTreeMap::from([(
            "s4".to_string(),
            serde_json::json!({"calls": 1, "prompt": 1, "completion": 1}),
        )]));
        let md = render_metrics(&m).join("\n");
        let diag = md.find("### Pipeline Diagnostics").expect(&md);
        let tokens = md.find("### Tokens by Phase").expect(&md);
        assert!(diag < tokens, "{md}");
    }

    #[test]
    fn render_scan_health_degraded_with_custom_reason() {
        let md = render_scan_health(true, "custom reason", None).join("\n");
        assert!(md.contains("## Scan Health"));
        assert!(md.contains("DEGRADED"));
        assert!(md.contains("custom reason"));
    }

    #[test]
    fn render_scan_health_degraded_with_empty_reason_uses_default() {
        let md = render_scan_health(true, "", None).join("\n");
        assert!(md.contains("the exploit-chain pass could not be computed"));
    }

    #[test]
    fn render_scan_health_failed_chunks_uses_chunks_attempted() {
        let m = ScanMetrics {
            chunks_failed: 2,
            chunks_attempted: 8,
            chunks_total: 10,
            ..Default::default()
        };
        let md = render_scan_health(false, "", Some(&m)).join("\n");
        assert!(md.contains("2/8 deep-dive chunk(s) failed"));
    }

    #[test]
    fn render_scan_health_failed_chunks_falls_back_to_chunks_total_when_attempted_is_zero() {
        let m = ScanMetrics {
            chunks_failed: 2,
            chunks_attempted: 0,
            chunks_total: 10,
            ..Default::default()
        };
        let md = render_scan_health(false, "", Some(&m)).join("\n");
        assert!(md.contains("2/10 deep-dive chunk(s) failed"));
    }

    #[test]
    fn render_scan_health_errors_by_stage_sorted_by_stage_name() {
        let mut errs = BTreeMap::new();
        errs.insert("s4".to_string(), 3);
        errs.insert("s1".to_string(), 1);
        let m = ScanMetrics {
            errors_by_stage: errs,
            ..Default::default()
        };
        let md = render_scan_health(false, "", Some(&m)).join("\n");
        assert!(md.contains("- Recoverable errors logged by stage: s1=1, s4=3"));
    }

    #[test]
    fn render_scan_health_errors_log_path_uses_basename() {
        let m = ScanMetrics {
            chunks_failed: 1,
            errors_log_path: "/var/log/run123/errors.jsonl".to_string(),
            ..Default::default()
        };
        let md = render_scan_health(false, "", Some(&m)).join("\n");
        assert!(md.contains("- Full error log: `errors.jsonl`"));
    }

    #[test]
    fn render_scan_health_degraded_with_no_metrics_at_all() {
        let md = render_scan_health(true, "", None).join("\n");
        assert!(md.contains("## Scan Health"));
        assert!(!md.contains("Full error log"));
        assert!(!md.contains("deep-dive chunk"));
    }

    #[test]
    fn scope_appendix_empty_metrics_renders_just_the_appendix_heading() {
        let md = render_scope_appendix(&ScanMetrics::default()).join("\n");
        assert!(md.contains("## Appendix: Scan Scope"));
        assert!(!md.contains("Folders scanned"));
        assert!(!md.contains("Excluded from scan"));
    }

    #[test]
    fn scope_appendix_folders_scanned_lists_each_folder() {
        let m = ScanMetrics {
            folders_scanned: vec!["src".to_string(), "lib".to_string()],
            ..Default::default()
        };
        let md = render_scope_appendix(&m).join("\n");
        assert!(md.contains("### Folders scanned (2)"));
        assert!(md.contains("- `src/`"));
        assert!(md.contains("- `lib/`"));
    }

    fn metrics_with_excluded(excluded: serde_json::Value) -> ScanMetrics {
        let map: BTreeMap<String, serde_json::Value> = excluded
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        ScanMetrics {
            excluded: map,
            ..Default::default()
        }
    }

    #[test]
    fn scope_appendix_dirs_exts_globs_sorted_descending_by_count() {
        let m = metrics_with_excluded(json!({
            "dirs": {"node_modules": 40, "target": 100},
            "exts": {".png": 5, ".lock": 20},
            "globs": {"*.min.js": 3, "*.map": 30},
        }));
        let md = render_scope_appendix(&m).join("\n");
        assert!(md.contains("### Excluded from scan (198 files)"));
        let target_pos = md.find("`target/`").unwrap();
        let nm_pos = md.find("`node_modules/`").unwrap();
        assert!(target_pos < nm_pos);
        assert!(md.contains("- `target/` — 100 files"));
        assert!(md.contains("- `*.lock` — 20 files"));
        assert!(md.contains("- `*.map` — 30 files"));
    }

    #[test]
    fn scope_appendix_oversize_files_converted_to_kb() {
        let m = metrics_with_excluded(json!({
            "oversize": 2,
            "oversize_files": [["big.bin", 2048], ["huge.bin", 1048576]],
        }));
        let md = render_scope_appendix(&m).join("\n");
        assert!(md.contains("**Oversize** (> `max_file_kb`): 2 files"));
        assert!(md.contains("- `big.bin` — 2 KB"));
        assert!(md.contains("- `huge.bin` — 1024 KB"));
    }

    #[test]
    fn scope_appendix_oversize_count_disagrees_with_an_empty_files_list_omits_the_trailing_blank_line(
    ) {
        let m = metrics_with_excluded(json!({
            "oversize": 3,
            "oversize_files": [],
        }));
        let md = render_scope_appendix(&m).join("\n");
        assert!(md.contains("**Oversize** (> `max_file_kb`): 3 files"));
        let lines: Vec<&str> = md.lines().collect();
        let heading = lines
            .iter()
            .position(|l| l.contains("**Oversize**"))
            .unwrap();
        assert_ne!(lines.get(heading + 1), Some(&""));
    }

    #[rstest]
    #[case(json!([["only-one-element"]]))]
    #[case(json!([[]]))]
    #[case(json!(["not-an-array"]))]
    #[case(json!([[123, 456]]))]
    #[case(json!([["path", "not-an-integer"]]))]
    fn pair_list_skips_a_malformed_entry_instead_of_panicking(#[case] oversize_files: Value) {
        let m = metrics_with_excluded(json!({
            "oversize": 1,
            "oversize_files": oversize_files,
        }));
        let md = render_scope_appendix(&m).join("\n");
        assert!(!md.contains(" KB"));
    }

    #[rstest]
    #[case(json!([["only-one-element"]]))]
    #[case(json!([[]]))]
    #[case(json!(["not-an-array"]))]
    #[case(json!([[123, "reason"]]))]
    #[case(json!([["path", 456]]))]
    fn str_pair_list_skips_a_malformed_entry_instead_of_panicking(#[case] promoted_files: Value) {
        let m = metrics_with_excluded(json!({
            "config_dedup": {
                "dropped": 1,
                "candidates": 1,
                "clusters": 1,
                "kept_reps": 1,
                "promoted": 0,
                "top_clusters": [],
                "promoted_files": promoted_files,
            },
        }));
        let md = render_scope_appendix(&m).join("\n");
        assert!(!md.contains("Promoted (suspicious"));
    }

    #[test]
    fn scope_appendix_symlinks_pluralizes_correctly() {
        let m = metrics_with_excluded(json!({
            "symlinks": {"a.py": 1, "b.py": 3},
        }));
        let md = render_scope_appendix(&m).join("\n");
        assert!(
            md.lines().any(|l| l == "- `a.py`"),
            "singular count must omit the suffix entirely"
        );
        assert!(md.contains("- `b.py` — 3 files"));
    }

    #[test]
    fn scope_appendix_symlink_path_pipe_renders_literally_inside_the_code_span() {
        let m = metrics_with_excluded(json!({
            "symlinks": {"weird|path.py": 2},
        }));
        let md = render_scope_appendix(&m).join("\n");
        assert!(md.contains("`weird|path.py` — 2 files"));
    }

    #[test]
    fn scope_appendix_symlink_path_backtick_cannot_break_out_of_its_code_span() {
        let m = metrics_with_excluded(json!({
            "symlinks": {"foo`) [pwned](javascript:x) (`bar": 2},
        }));
        let md = render_scope_appendix(&m).join("\n");
        let line = md.lines().find(|l| l.contains("— 2 files")).unwrap();
        assert_eq!(line.matches('`').count(), 2);
    }

    #[test]
    fn scope_appendix_config_dedup_summary_and_clusters() {
        let m = metrics_with_excluded(json!({
            "config_dedup": {
                "dropped": 12,
                "candidates": 20,
                "clusters": 3,
                "kept_reps": 5,
                "promoted": 2,
                "top_clusters": [
                    {"sample": "config/a.yaml", "size": 8, "reps": ["r1", "r2"], "dropped": 6},
                ],
                "promoted_files": [["config/b.yaml", "contains secret-looking value"]],
            },
        }));
        let md = render_scope_appendix(&m).join("\n");
        assert!(md.contains(
            "**Config dedup**: 20 config files -> 3 shape-clusters; kept 5 representatives + 2 promoted (suspicious value), dropped 12 near-duplicates."
        ));
        assert!(md.contains("- `config/a.yaml` x8 (kept 2, dropped 6)"));
        assert!(md.contains("Promoted (suspicious value not present in cluster representative):"));
        assert!(md.contains("- `config/b.yaml` — `contains secret-looking value`"));
    }

    #[test]
    fn scope_appendix_config_dedup_with_no_promoted_files_omits_that_subsection() {
        let m = metrics_with_excluded(json!({
            "config_dedup": {"dropped": 3, "candidates": 5, "clusters": 1, "kept_reps": 2, "promoted": 0, "top_clusters": [], "promoted_files": []},
        }));
        let md = render_scope_appendix(&m).join("\n");
        assert!(md.contains("Config dedup"));
        assert!(!md.contains("Promoted (suspicious"));
    }

    #[test]
    fn scope_appendix_config_dedup_with_no_top_clusters_key_at_all() {
        let m = metrics_with_excluded(json!({
            "config_dedup": {"dropped": 3, "candidates": 5, "clusters": 1, "kept_reps": 2, "promoted": 0},
        }));
        let md = render_scope_appendix(&m).join("\n");
        assert!(md.contains("Config dedup"));
        assert!(!md.contains("x0 (kept"));
    }

    #[test]
    fn scope_appendix_dropped_zero_config_dedup_does_not_trigger_excluded_section_alone() {
        let m = metrics_with_excluded(json!({
            "config_dedup": {"dropped": 0},
        }));
        let md = render_scope_appendix(&m).join("\n");
        assert!(!md.contains("Excluded from scan"));
    }

    #[test]
    fn scope_appendix_no_excluded_data_at_all() {
        let m = metrics_with_excluded(json!({}));
        let md = render_scope_appendix(&m).join("\n");
        assert!(!md.contains("Excluded from scan"));
    }
}

#[cfg(test)]
mod repo_identity_tests {
    use super::render_repo_identity;
    use appsec_model::{RepoIdentity, RepoKey, RepoKeySource};

    fn identity() -> RepoIdentity {
        RepoIdentity {
            key: Some(RepoKey {
                value: "github.com/org/repo".to_string(),
                source: RepoKeySource::Derived,
            }),
            origin_display: Some("https://github.com/org/repo".to_string()),
            subtree: String::new(),
            root_commit: Some("abc123".to_string()),
            root_commit_verified: true,
            branch: Some("main".to_string()),
            merge_base: None,
            worktree_dirty: false,
        }
    }

    #[test]
    fn a_resolved_identity_reports_its_key_and_provenance() {
        let md = render_repo_identity(Some(&identity())).join("\n");
        assert!(md.contains("## Repository"), "{md}");
        assert!(
            md.contains("- Repository key: `github.com/org/repo` (from derived)"),
            "{md}"
        );
        assert!(
            md.contains("- Origin: `https://github.com/org/repo`"),
            "{md}"
        );
        assert!(md.contains("- Branch: `main`"), "{md}");
        assert!(!md.contains("unverified"), "{md}");
        assert!(!md.contains("dirty"), "{md}");
        assert!(!md.contains("Subtree"), "{md}");
    }

    #[test]
    fn an_unresolved_key_says_what_it_costs_and_how_to_fix_it() {
        let mut id = identity();
        id.key = None;
        id.origin_display = None;
        let md = render_repo_identity(Some(&id)).join("\n");
        assert!(md.contains("none resolved"), "{md}");
        assert!(md.contains("cannot be compared"), "{md}");
        assert!(md.contains("--repo-key"), "{md}");
    }

    #[test]
    fn a_key_from_the_environment_names_the_environment_as_its_source() {
        let mut id = identity();
        id.key = Some(RepoKey {
            value: "env/key".to_string(),
            source: RepoKeySource::Environment,
        });
        let md = render_repo_identity(Some(&id)).join("\n");
        assert!(
            md.contains("- Repository key: `env/key` (from environment)"),
            "{md}"
        );
    }

    #[test]
    fn a_subtree_scan_and_a_dirty_worktree_are_both_reported() {
        let mut id = identity();
        id.subtree = "services/a".to_string();
        id.worktree_dirty = true;
        let md = render_repo_identity(Some(&id)).join("\n");
        assert!(md.contains("- Subtree: `services/a`"), "{md}");
        assert!(md.contains("dirty at scan time"), "{md}");
    }

    #[test]
    fn a_shallow_clones_root_commit_is_reported_as_unverified() {
        let mut id = identity();
        id.root_commit_verified = false;
        let md = render_repo_identity(Some(&id)).join("\n");
        assert!(md.contains("unverified (shallow clone)"), "{md}");
    }

    #[test]
    fn a_merge_base_is_reported_when_a_base_ref_was_given() {
        let mut id = identity();
        id.merge_base = Some("def456".to_string());
        let md = render_repo_identity(Some(&id)).join("\n");
        assert!(md.contains("- Merge base: `def456`"), "{md}");
    }

    #[test]
    fn a_backtick_in_a_repository_controlled_value_cannot_break_its_code_span() {
        let mut id = identity();
        id.key = Some(RepoKey {
            value: "github.com/org/re`po".to_string(),
            source: RepoKeySource::Explicit,
        });
        id.branch = Some("feat/`injected`".to_string());
        let md = render_repo_identity(Some(&id)).join("\n");
        assert!(!md.contains("re`po`"), "{md}");
        for line in md.lines().filter(|l| l.starts_with("- ")) {
            assert_eq!(
                line.matches('`').count() % 2,
                0,
                "unbalanced code span: {line}"
            );
        }
    }

    #[test]
    fn no_identity_renders_no_section_at_all() {
        assert!(render_repo_identity(None).is_empty());
    }
}

#[cfg(test)]
mod coverage_tests {
    use super::{render_metrics, render_scan_health};
    use appsec_model::ScanMetrics;
    use std::collections::BTreeMap;

    fn metrics(pairs: &[(&str, i64)]) -> ScanMetrics {
        let mut m = ScanMetrics {
            total_files_in_scope: pairs.iter().map(|(_, c)| c).sum(),
            ..Default::default()
        };
        m.analyzed_files_unique = pairs
            .iter()
            .find(|(k, _)| *k == "reviewed")
            .map(|(_, c)| *c)
            .unwrap_or(0);
        m.files_by_disposition = pairs
            .iter()
            .map(|(k, c)| (k.to_string(), *c))
            .collect::<BTreeMap<_, _>>();
        m
    }

    #[test]
    fn the_gap_between_in_scope_and_reviewed_is_itemized_largest_first() {
        let md = render_metrics(&metrics(&[
            ("reviewed", 295),
            ("not_eligible_extension", 12),
            ("not_eligible_directory", 5),
            ("budget_skipped", 3),
            ("unreachable", 2),
        ]))
        .join("\n");
        assert!(md.contains("- Files in scope: 317"), "{md}");
        assert!(md.contains("- Files analyzed (unique): 295"), "{md}");
        assert!(md.contains("- Not reviewed: 22"), "{md}");
        let needles = [
            "non-code extension",
            "under an excluded directory",
            "budget ran out",
            "not on a call path",
        ];
        for needle in needles {
            assert!(md.contains(needle), "{needle} missing from {md}");
        }
        let order: Vec<usize> = needles.iter().map(|n| md.find(n).unwrap()).collect();
        let mut sorted = order.clone();
        sorted.sort_unstable();
        assert_eq!(order, sorted, "reasons must be listed largest first: {md}");
    }

    #[test]
    fn the_scan_uuid_is_rendered_after_the_label_when_present() {
        let mut m = metrics(&[("reviewed", 1)]);
        m.scan_id = "2026-01-01T00:00:00Z__demo".to_string();
        m.scan_uuid = "01932f1a-7c3d-7000-8000-0123456789ab".to_string();
        let lines = render_metrics(&m);
        let find = |needle: &str| lines.iter().position(|l| l.contains(needle));
        let label = find("- Scan ID:").unwrap();
        let uuid = find("- Scan UUID: 01932f1a-7c3d-7000-8000-0123456789ab");
        assert_eq!(uuid, Some(label + 1), "{lines:?}");
    }

    #[test]
    fn a_report_without_a_scan_uuid_renders_no_uuid_line() {
        let md = render_metrics(&metrics(&[("reviewed", 1)])).join("\n");
        assert!(!md.contains("Scan UUID"), "{md}");
    }

    #[test]
    fn a_fully_reviewed_scan_says_nothing_about_files_not_reviewed() {
        let md = render_metrics(&metrics(&[("reviewed", 10)])).join("\n");
        assert!(!md.contains("Not reviewed"), "{md}");
    }

    #[test]
    fn a_report_without_dispositions_renders_no_breakdown() {
        let md = render_metrics(&ScanMetrics::default()).join("\n");
        assert!(!md.contains("Not reviewed"), "{md}");
    }

    #[test]
    fn an_unrecognized_disposition_is_ignored_rather_than_miscounted() {
        let md = render_metrics(&metrics(&[
            ("reviewed", 5),
            ("something_from_the_future", 7),
            ("budget_skipped", 1),
        ]))
        .join("\n");
        assert!(md.contains("- Not reviewed: 1"), "{md}");
    }

    #[test]
    fn an_unchunked_file_raises_a_scanner_defect_in_scan_health() {
        let md = render_scan_health(
            false,
            "",
            Some(&metrics(&[("reviewed", 4), ("unchunked", 2)])),
        )
        .join("\n");
        assert!(md.contains("## Scan Health"), "{md}");
        assert!(md.contains("SCANNER DEFECT"), "{md}");
        assert!(md.contains("2 in-scope file(s)"), "{md}");
    }

    #[test]
    fn a_healthy_scan_with_no_unchunked_files_has_no_scan_health_section() {
        assert!(render_scan_health(false, "", Some(&metrics(&[("reviewed", 4)]))).is_empty());
    }
}
