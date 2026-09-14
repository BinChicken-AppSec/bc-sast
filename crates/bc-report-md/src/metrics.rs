//! The `## Scan Metrics`, `## Scan Health`, and `## Appendix: Scan Scope`
//! sections, ported from `models.py::_render_metrics`/`_render_scan_health`/
//! `_render_scope_appendix` (lines 994-1163).
//!
//! `ScanMetrics.excluded`/`.tokens_by_phase` are untyped JSON on the model
//! (matching the Python source's own untyped `dict` fields) — the shapes
//! this module expects are documented on each accessor below; a future S1
//! stage crate producing a `ScanMetrics` must serialize into these same
//! shapes for the appendix to render.

use serde_json::Value;
use std::path::Path;

use bc_model::ScanMetrics;

use crate::sanitize::md_code_span;

/// `1234567` -> `"1,234,567"`. Rust's `format!` has no built-in
/// thousands-separator flag (unlike Python's `:,` format spec used for
/// the Tokens-by-Phase table), so this reimplements it directly.
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

/// A per-phase dollar amount, or `None` when the phase priced nothing.
/// Absent and explicitly null read the same: neither is a zero cost.
fn get_f64(v: &Value, key: &str) -> Option<f64> {
    v.get(key).and_then(Value::as_f64)
}

/// A dollar amount at the six decimal places `bc_pricing::Money`'s own
/// `Display` uses, which is enough to show a single cheap call without
/// collapsing it to zero and few enough to stay readable.
pub(crate) fn usd(dollars: f64) -> String {
    format!("{dollars:.6}")
}

/// What one table cell or one bullet says about money that has no figure
/// behind it. Never `0`: a scan whose model this build has no rate for
/// did not cost nothing, it cost an amount the report cannot state.
pub(crate) const UNPRICED: &str = "unpriced";

/// `{key: {name: count, ...}}` sub-object, dropping any entry whose value
/// isn't an integer (defensive against a malformed/partial producer,
/// mirroring Python's tolerant `dict.get`-based access).
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

/// `[[path, size], ...]` list, matching how a Python
/// `list[tuple[str, int]]` naturally serializes to JSON.
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

/// `[[path, reason], ...]` list — the string-valued counterpart of
/// [`pair_list`], used for `config_dedup.promoted_files` (each entry
/// pairs a file with the human-readable reason it was promoted).
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

/// Sorted descending by count, ties broken by insertion order (a stable
/// sort on the negated count), matching Python's
/// `sorted(d.items(), key=lambda kv: -kv[1])`.
fn sorted_desc(mut pairs: Vec<(String, i64)>) -> Vec<(String, i64)> {
    pairs.sort_by_key(|(_, n)| -*n);
    pairs
}

/// One row of the Tokens-by-Phase table, read out of the untyped
/// per-phase bucket `bc_orchestrator::build_metrics` writes.
struct Phase<'a> {
    name: &'a str,
    calls: i64,
    prompt: i64,
    completion: i64,
    cache_read: i64,
    /// `None` for a phase that priced nothing, which is not the same as
    /// a phase that cost nothing.
    cost_usd: Option<f64>,
    unpriced_tokens: i64,
}

impl Phase<'_> {
    /// Billable tokens, which is what the table's `%` column apportions.
    /// Cache reads are excluded here exactly as they are from the report's
    /// headline totals.
    fn tokens(&self) -> i64 {
        self.prompt + self.completion
    }

    /// The Cost column: a figure when the phase priced something, an
    /// explicit `unpriced` when it spent tokens it could not price, and a
    /// dash when it never billed anything at all.
    fn cost_cell(&self) -> String {
        match self.cost_usd {
            Some(dollars) => usd(dollars),
            None if self.unpriced_tokens > 0 => UNPRICED.to_string(),
            None => "-".to_string(),
        }
    }
}

/// The run's money, as bullets beside the token counts: one cost line
/// always, and a second naming what went unpriced whenever anything did.
///
/// Nothing at all when the run recorded neither a cost nor an unpriced
/// count: a scan whose backend never reported usage, or a report written
/// before this section existed. A zero is never printed in place of a
/// missing rate: an operator reconciling this against an invoice has to be
/// able to tell "free" from "nobody here knows".
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
    // Keyed on `diff_scope_active`, not on a non-zero count: a
    // diff-scoped scan that matched no files (a rename-only PR) is
    // exactly the run whose report most needs this line, and testing the
    // count alone made it vanish precisely then.
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
            "| Phase | Calls | Prompt | Completion | Total | % | Cache-read (excl.) | Cost (USD) |"
                .to_string(),
        );
        lines.push("|---|---:|---:|---:|---:|---:|---:|---:|".to_string());

        let totals: Vec<Phase<'_>> = phases
            .iter()
            .map(|(ph, b)| Phase {
                name: ph,
                calls: get_i64(b, "calls"),
                prompt: get_i64(b, "prompt"),
                completion: get_i64(b, "completion"),
                cache_read: get_i64(b, "cache_read"),
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
                "| {} | {} | {} | {} | {} | {pct:.1} | {} | {} |",
                phase.name,
                phase.calls,
                with_commas(phase.prompt),
                with_commas(phase.completion),
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
    if !degraded && failed == 0 && errs.is_empty() && budget_stop.is_none() {
        return Vec::new();
    }
    let mut lines = vec!["## Scan Health".to_string(), String::new()];
    // First, and on its own line: a budget stop means the scan analysed
    // less than it was asked to, and every other number in this report
    // has to be read in that light. Before this, tripping `--max-tokens`
    // left no trace in the report at all.
    if let Some(budget_stop) = budget_stop {
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
        // Already in sorted-by-stage-name order: `errs` was collected from
        // a `BTreeMap`, matching Python's explicit `sorted(errs.items())`.
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
        // A rename-only PR: diff scope was genuinely requested and matched
        // nothing. Keying the line on `changed_files_count > 0` made it
        // vanish exactly here, leaving the report with no trace that the
        // run had been scoped at all.
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
        // Regression guard on the inactive path: the flag, not the count,
        // is what decides. A full-repo scan renders no scope line.
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
            "| Phase | Calls | Prompt | Completion | Total | % | Cache-read (excl.) | Cost (USD) |"
        ));
        assert!(md.contains("|---|---:|---:|---:|---:|---:|---:|---:|"));
        let deepdive_pos = md.find("s4_deepdive").unwrap();
        let preprocess_pos = md.find("s1_preprocess").unwrap();
        assert!(
            deepdive_pos < preprocess_pos,
            "larger total must sort first"
        );
        assert!(
            md.contains("| s4_deepdive | 5 | 5,000 | 3,500 | 8,500 | 85.0 | 1,000 | 0.071500 |"),
            "{md}"
        );
        assert!(
            md.contains("| s1_preprocess | 2 | 1,000 | 500 | 1,500 | 15.0 | 200 | 0.012500 |"),
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
        // A phase that billed nothing gets a dash, not a zero cost: there
        // is no evidence here either way, and `0.000000` would claim
        // there is.
        assert!(md.contains("| ph | 0 | 0 | 0 | 0 | 0.0 | 0 | - |"), "{md}");
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
            md.contains("| s4_deepdive | 3 | 900 | 100 | 1,000 | 100.0 | 0 | unpriced |"),
            "{md}"
        );
        assert!(!md.contains("| 0.000000 |"), "never a zero here: {md}");
    }

    #[test]
    fn the_table_caption_states_how_cost_is_summed() {
        // The one constraint a reader cannot infer from the numbers: a
        // tiered model's rate depends on each call's own context, so
        // these figures are per-call sums, not the phase totals priced.
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
        // The partially-rated case: the call itself priced, so no
        // `provider/model` pair failed, but some of its tokens had no
        // published rate of their own.
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
        // A hand-built or older `ScanMetrics` that carries a cost and
        // nothing else: report the money, claim nothing about gaps.
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
        // "python" deliberately absent from scanned -> defaults to 0.
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

    /// Before this, a scan that hit `--max-tokens` said nothing at all
    /// in the report — the section did not even render, and a reader had
    /// no way to know a third of the analysis had never happened.
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
        // Nothing else fired, so nothing else is claimed.
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
        // `oversize` (a count) and `oversize_files` (the detail list) come
        // from an untyped, independently-producer-populated JSON blob — a
        // malformed/partial producer can set one without the other. This
        // exercises `pair_list`'s empty-result path feeding
        // `render_scope_appendix`'s `!oversize_files.is_empty()` branch.
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
        // `|` isn't special inside a backtick code span (only in a table
        // row, which this bullet list isn't) — it renders through as-is.
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
