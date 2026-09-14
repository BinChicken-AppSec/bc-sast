//! JSON hydration of the chain-analysis response into a `FinalReport`, and
//! the degraded "unranked" fallback used when the pass could not be
//! computed at all. Ported from `s8_chain.py`'s `_coerce_list_payload` /
//! `_hydrate_report` / `_unranked_report`.

use std::collections::HashMap;

use bc_model::{
    Chain, ContextPackage, DropReason, DroppedFinding, FinalReport, Finding, RankedFinding,
    ScanMetrics, Severity,
};
use serde_json::Value;

use crate::severity::{coerce_sev, final_severity, severity_sort_order};

/// Map a top-level JSON array onto the chain-object schema when its
/// elements are recognizably chains or ranked findings; `Err` otherwise. A
/// bare array is off-schema, but the model occasionally emits `[{chain},
/// …]`/`[{ranked}, …]` directly. Element-shape gating is mandatory:
/// blindly wrapping an arbitrary array would feed junk into hydration and
/// yield a silently-empty report — worse than the visible unranked
/// degrade.
pub fn coerce_list_payload(items: &[Value]) -> Result<Value, String> {
    let dicts: Vec<Value> = items.iter().filter(|x| x.is_object()).cloned().collect();
    if !dicts.is_empty()
        && dicts
            .iter()
            .all(|x| x.get("steps").is_some() || x.get("title").is_some())
    {
        let mut map = serde_json::Map::new();
        map.insert("chains".to_string(), Value::Array(dicts));
        return Ok(Value::Object(map));
    }
    if !dicts.is_empty() && dicts.iter().all(|x| x.get("index").is_some()) {
        let mut map = serde_json::Map::new();
        map.insert("ranked_findings".to_string(), Value::Array(dicts));
        return Ok(Value::Object(map));
    }
    Err("top-level array is not chain- or ranked-finding-shaped".to_string())
}

/// Degraded fallback used ONLY when the exploit-chain pass could not be
/// COMPUTED (LLM call / parse / hydration failure). Findings keep their
/// CVSS-anchored severity band; they drop to INFO only when a finding has
/// no vector at all. What is lost is the chain-pass exploitability
/// ranking — not the severity.
pub fn unranked_report(
    ctx: &ContextPackage,
    findings: &[Finding],
    dropped: &[DroppedFinding],
    raw_findings_count: i64,
    metrics: Option<ScanMetrics>,
    summary: String,
) -> FinalReport {
    let mut ranked: Vec<RankedFinding> = findings
        .iter()
        .map(|f| RankedFinding {
            finding: f.clone(),
            severity: final_severity(f, Severity::Info),
            exploitability_notes: "(chain analysis unavailable — severity from CVSS only)"
                .to_string(),
        })
        .collect();

    let order = severity_sort_order(&ranked);
    ranked = order.iter().map(|&k| ranked[k].clone()).collect();
    let orig_to_sorted: HashMap<usize, usize> = order
        .iter()
        .enumerate()
        .map(|(new_i, &orig)| (orig, new_i))
        .collect();
    let dropped_out = remap_duplicate_canonical_idx(dropped, &orig_to_sorted);

    FinalReport {
        provider_ledger: Default::default(),
        repo_root: ctx.repo_root.clone(),
        repo_name: None,
        git_sha: None,
        findings: ranked,
        chains: Vec::new(),
        dropped: dropped_out,
        raw_findings_count,
        metrics,
        threat_model: None,
        app_profile: None,
        summary: summary.clone(),
        degraded: true,
        degraded_reason: summary,
        unreachable_files: Vec::new(),
    }
}

fn remap_duplicate_canonical_idx(
    dropped: &[DroppedFinding],
    orig_to_sorted: &HashMap<usize, usize>,
) -> Vec<DroppedFinding> {
    dropped
        .iter()
        .map(|d| {
            let mut d = d.clone();
            if d.reason != DropReason::Duplicate {
                return d;
            }
            let Some(orig) = d.canonical_idx else {
                return d;
            };
            let Some(&new_idx) = orig_to_sorted.get(&(orig as usize)) else {
                return d;
            };
            d.canonical_idx = Some(new_idx as i64);
            d
        })
        .collect()
}

fn as_string_vec(v: Option<&Value>) -> Result<Vec<String>, String> {
    let arr = match v {
        Some(Value::Array(a)) => a,
        _ => return Ok(Vec::new()),
    };
    arr.iter()
        .map(|item| match item {
            Value::String(s) => Ok(s.clone()),
            other => Err(format!("blocked_by_controls item is not a string: {other}")),
        })
        .collect()
}

fn valid_index(item: &Value) -> Option<usize> {
    let idx = item.get("index")?;
    if idx.is_boolean() {
        return None;
    }
    idx.as_i64().filter(|&i| i >= 0).map(|i| i as usize)
}

/// Hydrate the parsed chain-analysis JSON into a `FinalReport`. `Err` on
/// any off-schema value pydantic would have rejected in the Python
/// original (currently: a non-string `blocked_by_controls` entry) — the
/// caller degrades to [`unranked_report`] in that case, exactly mirroring
/// the Python original's broad `except Exception` around this hydration.
pub fn hydrate_report(
    data: &Value,
    ctx: &ContextPackage,
    findings: &[Finding],
    dropped: &[DroppedFinding],
    raw_findings_count: i64,
    metrics: Option<ScanMetrics>,
) -> Result<FinalReport, String> {
    let mut ranked: Vec<RankedFinding> = Vec::new();
    let mut ranked_orig_idx: Vec<usize> = Vec::new();
    let mut covered: std::collections::HashSet<usize> = std::collections::HashSet::new();

    for item in data
        .get("ranked_findings")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
    {
        if !item.is_object() {
            continue;
        }
        let Some(idx) = valid_index(item) else {
            continue;
        };
        if idx >= findings.len() || covered.contains(&idx) {
            continue;
        }
        covered.insert(idx);
        let notes = item
            .get("exploitability_notes")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        ranked.push(RankedFinding {
            finding: findings[idx].clone(),
            severity: final_severity(&findings[idx], coerce_sev(item.get("severity"))),
            exploitability_notes: notes,
        });
        ranked_orig_idx.push(idx);
    }

    for (i, f) in findings.iter().enumerate() {
        if !covered.contains(&i) {
            ranked.push(RankedFinding {
                finding: f.clone(),
                severity: final_severity(f, Severity::Info),
                exploitability_notes: "(not ranked by chaining pass)".to_string(),
            });
            ranked_orig_idx.push(i);
        }
    }

    let order = severity_sort_order(&ranked);
    ranked = order.iter().map(|&k| ranked[k].clone()).collect();
    ranked_orig_idx = order.iter().map(|&k| ranked_orig_idx[k]).collect();
    let orig_to_sorted: HashMap<usize, usize> = ranked_orig_idx
        .iter()
        .enumerate()
        .map(|(new_i, &orig)| (orig, new_i))
        .collect();

    let mut chains: Vec<Chain> = Vec::new();
    for item in data
        .get("chains")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
    {
        if !item.is_object() {
            continue;
        }
        let raw_steps: Vec<Value> = item
            .get("steps")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let is_int_step = |s: &Value| s.as_i64().is_some() && !s.is_boolean();
        let remapped: Vec<i64> = raw_steps
            .iter()
            .filter(|s| is_int_step(s))
            .filter_map(|s| {
                orig_to_sorted
                    .get(&(s.as_i64().unwrap() as usize))
                    .map(|&v| v as i64)
            })
            .collect();
        if remapped.len() < 2 {
            continue;
        }

        let mut narrative = item
            .get("narrative")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let dropped_steps: Vec<i64> = raw_steps
            .iter()
            .filter(|s| is_int_step(s))
            .map(|s| s.as_i64().unwrap())
            .filter(|s| !orig_to_sorted.contains_key(&(*s as usize)))
            .collect();
        if !dropped_steps.is_empty() {
            let shown: Vec<i64> = dropped_steps.iter().take(20).copied().collect();
            let extra = if dropped_steps.len() <= 20 {
                String::new()
            } else {
                format!(" (+{} more)", dropped_steps.len() - 20)
            };
            let shown_str = format!(
                "[{}]",
                shown
                    .iter()
                    .map(i64::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            narrative = format!(
                "{narrative}\n\n_Note: this chain referenced finding indices {shown_str}{extra} that were not in the verified set; they have been omitted from the path above._"
            )
            .trim()
            .to_string();
        }

        let blocked = as_string_vec(item.get("blocked_by_controls"))?;
        let title = item
            .get("title")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or("Unnamed chain")
            .to_string();
        chains.push(Chain {
            title,
            steps: remapped,
            severity: coerce_sev(item.get("severity")),
            blocked_by_controls: blocked,
            narrative,
        });
    }

    let dropped_out = remap_duplicate_canonical_idx(dropped, &orig_to_sorted);
    let summary = data
        .get("summary")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    Ok(FinalReport {
        provider_ledger: Default::default(),
        repo_root: ctx.repo_root.clone(),
        repo_name: None,
        git_sha: None,
        findings: ranked,
        chains,
        dropped: dropped_out,
        raw_findings_count,
        metrics,
        threat_model: None,
        app_profile: None,
        summary,
        degraded: false,
        degraded_reason: String::new(),
        unreachable_files: Vec::new(),
    })
}
