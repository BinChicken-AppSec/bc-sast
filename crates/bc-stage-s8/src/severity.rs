//! Deterministic severity reconciliation and sort order, ported from
//! `s8_chain.py`'s `_coerce_sev` / `_sev_from_band` / `_final_severity` /
//! `_offensive_rank` / `_severity_sort_order`.

use bc_model::{Finding, RankedFinding, Severity};
use serde_json::Value;

/// Map a CVSS qualitative band string ("Critical"/"High"/...) to a
/// `Severity`, or `None` for a missing/unrecognized band so the caller can
/// fall through to the next, less-contextual source. Deliberately has no
/// `"info"` mapping, matching the Python original's `_CVSS_BAND_TO_SEV`
/// dict (which only covers critical/high/medium/low).
pub fn sev_from_band(rating: Option<&str>) -> Option<Severity> {
    match rating?.trim().to_lowercase().as_str() {
        "critical" => Some(Severity::Critical),
        "high" => Some(Severity::High),
        "medium" => Some(Severity::Medium),
        "low" => Some(Severity::Low),
        _ => None,
    }
}

/// Reconcile a finding's reported severity to the CVSS framework, most-
/// contextual band first: environmental (`vsvs_rating`) is authoritative
/// when present; else the base CVSS band; else the chaining LLM's
/// qualitative label (only when no vector exists at all). `OffensivePriority`
/// is a separate exploitability axis (see [`offensive_rank`]) and is
/// deliberately not folded into the severity band.
pub fn final_severity(f: &Finding, llm_label: Severity) -> Severity {
    sev_from_band(f.vsvs_rating.as_deref())
        .or_else(|| sev_from_band(f.cvss_rating.as_deref()))
        .unwrap_or(llm_label)
}

/// `OffensivePriority` as a secondary sort key (P1 first, unset/malformed
/// last at 9). Kept orthogonal to severity — it ranks reachability, not
/// impact.
pub fn offensive_rank(f: &Finding) -> i32 {
    let op = f
        .offensive_priority
        .as_deref()
        .unwrap_or("")
        .trim()
        .to_uppercase();
    let chars: Vec<char> = op.chars().collect();
    if chars.len() == 2 && chars[0] == 'P' && chars[1].is_ascii_digit() {
        chars[1].to_digit(10).expect("checked is_ascii_digit above") as i32
    } else {
        9
    }
}

fn sev_order(s: Severity) -> u8 {
    match s {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
        Severity::Info => 4,
    }
}

/// Index permutation ordering `ranked` by severity band, then
/// `OffensivePriority` (P1 first), then `(file, line_start)` — stable,
/// matching Python's `sorted()`, so entries equal on all three keep their
/// original relative order. Shared by the hydrated report and the degraded
/// fallback so CRITICAL/HIGH always surface at the top.
///
/// The `(file, line_start)` tertiary key is net-new versus
/// `s8_chain.py::_severity_sort_order`, which stops at the offensive rank.
/// Two findings tied on both of those are extremely common (same band, no
/// offensive priority set), and the incoming order they then inherit
/// traces back through S7 → S6 to LLM-call completion timing — so
/// `report.md` and `report.sarif` reshuffled between two runs of the same
/// scan, producing a large, meaningless diff. Ordering ties by source
/// position makes the reports diffable without changing which findings
/// rank above which.
pub fn severity_sort_order(ranked: &[RankedFinding]) -> Vec<usize> {
    let mut order: Vec<usize> = (0..ranked.len()).collect();
    order.sort_by(|&a, &b| {
        let fa = &ranked[a].finding;
        let fb = &ranked[b].finding;
        (sev_order(ranked[a].severity), offensive_rank(fa))
            .cmp(&(sev_order(ranked[b].severity), offensive_rank(fb)))
            .then_with(|| fa.file.cmp(&fb.file))
            .then_with(|| fa.line_start.cmp(&fb.line_start))
    });
    order
}

/// Coerce an arbitrary (attacker/model-controlled) JSON value to a
/// `Severity`, defaulting to `Info` for anything that isn't exactly one of
/// the five recognized strings (case/whitespace-insensitively) — mirroring
/// the Python original's `_coerce_sev`, which stringifies non-string
/// truthy values before the enum lookup fails; skipped here since no
/// non-string JSON value's `Display` form can coincidentally equal a valid
/// severity word, so the observable result is identical either way.
pub fn coerce_sev(v: Option<&Value>) -> Severity {
    let Some(Value::String(s)) = v else {
        return Severity::Info;
    };
    match s.trim().to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_model::VulnClass;
    use serde_json::json;

    fn finding_with(
        vsvs_rating: Option<&str>,
        cvss_rating: Option<&str>,
        offensive_priority: Option<&str>,
    ) -> Finding {
        Finding {
            provider_origins: Vec::new(),
            chunk_id: "c".to_string(),
            file: "a.rs".to_string(),
            line_start: 1,
            line_end: 1,
            vuln_class: VulnClass::Other,
            cwe: None,
            title: "t".to_string(),
            impact: String::new(),
            description: "d".to_string(),
            exploit_scenario: String::new(),
            preconditions: Vec::new(),
            recommendation: String::new(),
            code_snippet: "x".to_string(),
            source_ref: None,
            sink_ref: None,
            backfilled_refs: Vec::new(),
            reanchored: Vec::new(),
            compliance_requirements: Vec::new(),
            confidence: 0.9,
            votes: 1,
            duplicates: Vec::new(),
            verdict: None,
            verdict_confidence: None,
            verdict_reason: String::new(),
            cvss_vector: None,
            cvss_score: None,
            cvss_rating: cvss_rating.map(String::from),
            verifier_reasoning: String::new(),
            vsvs_vector: None,
            vsvs_score: None,
            vsvs_rating: vsvs_rating.map(String::from),
            offensive_priority: offensive_priority.map(String::from),
            offensive_reason: String::new(),
            related_cwes: Vec::new(),
        }
    }

    #[test]
    fn sev_from_band_maps_bands() {
        assert_eq!(sev_from_band(Some("Critical")), Some(Severity::Critical));
        assert_eq!(sev_from_band(Some("High")), Some(Severity::High));
        assert_eq!(sev_from_band(Some("Medium")), Some(Severity::Medium));
        assert_eq!(sev_from_band(Some("low")), Some(Severity::Low));
        assert_eq!(sev_from_band(None), None);
        assert_eq!(sev_from_band(Some("Unknown")), None);
        assert_eq!(sev_from_band(Some("None")), None);
    }

    #[test]
    fn final_severity_prefers_vsvs_then_base_then_llm() {
        let f = finding_with(Some("Critical"), Some("Medium"), None);
        assert_eq!(final_severity(&f, Severity::Low), Severity::Critical);

        let f = finding_with(None, Some("High"), None);
        assert_eq!(final_severity(&f, Severity::Low), Severity::High);

        let f = finding_with(None, None, None);
        assert_eq!(final_severity(&f, Severity::High), Severity::High);

        let f = finding_with(None, Some("Medium"), None);
        assert_eq!(final_severity(&f, Severity::High), Severity::Medium);
    }

    #[test]
    fn offensive_rank_orders_p1_first() {
        assert_eq!(offensive_rank(&finding_with(None, None, Some("P1"))), 1);
        assert_eq!(offensive_rank(&finding_with(None, None, Some("P4"))), 4);
        assert_eq!(offensive_rank(&finding_with(None, None, None)), 9);
        assert_eq!(offensive_rank(&finding_with(None, None, Some("bogus"))), 9);
    }

    #[test]
    fn offensive_rank_is_case_insensitive_and_trims_whitespace() {
        assert_eq!(offensive_rank(&finding_with(None, None, Some(" p2 "))), 2);
    }

    #[test]
    fn coerce_sev_allows_critical() {
        assert_eq!(coerce_sev(Some(&json!("critical"))), Severity::Critical);
        assert_eq!(coerce_sev(Some(&json!("CRITICAL"))), Severity::Critical);
        assert_eq!(coerce_sev(Some(&json!("  Critical  "))), Severity::Critical);
    }

    #[test]
    fn coerce_sev_passthrough_valid_levels() {
        assert_eq!(coerce_sev(Some(&json!("high"))), Severity::High);
        assert_eq!(coerce_sev(Some(&json!("medium"))), Severity::Medium);
        assert_eq!(coerce_sev(Some(&json!("low"))), Severity::Low);
        assert_eq!(coerce_sev(Some(&json!("info"))), Severity::Info);
    }

    #[test]
    fn coerce_sev_falsy_and_unknown_default_to_info() {
        assert_eq!(coerce_sev(None), Severity::Info);
        assert_eq!(coerce_sev(Some(&json!(""))), Severity::Info);
        assert_eq!(coerce_sev(Some(&json!(0))), Severity::Info);
        assert_eq!(coerce_sev(Some(&json!("bogus"))), Severity::Info);
    }

    #[test]
    fn coerce_sev_non_string_truthy_coerced_to_info() {
        assert_eq!(coerce_sev(Some(&json!(7))), Severity::Info);
        assert_eq!(coerce_sev(Some(&json!(["high"]))), Severity::Info);
        assert_eq!(coerce_sev(Some(&json!(true))), Severity::Info);
        assert_eq!(coerce_sev(Some(&json!(null))), Severity::Info);
    }

    #[test]
    fn severity_sort_order_orders_by_band_then_offensive_priority() {
        let ranked = vec![
            RankedFinding {
                finding: finding_with(None, None, Some("P3")),
                severity: Severity::High,
                exploitability_notes: String::new(),
            },
            RankedFinding {
                finding: finding_with(None, None, Some("P1")),
                severity: Severity::High,
                exploitability_notes: String::new(),
            },
            RankedFinding {
                finding: finding_with(None, None, None),
                severity: Severity::Critical,
                exploitability_notes: String::new(),
            },
        ];
        let order = severity_sort_order(&ranked);
        assert_eq!(order, vec![2, 1, 0]);
    }

    #[test]
    fn severity_sort_order_is_stable_for_equal_keys() {
        let ranked = vec![
            RankedFinding {
                finding: finding_with(None, None, None),
                severity: Severity::Low,
                exploitability_notes: "a".to_string(),
            },
            RankedFinding {
                finding: finding_with(None, None, None),
                severity: Severity::Low,
                exploitability_notes: "b".to_string(),
            },
        ];
        assert_eq!(severity_sort_order(&ranked), vec![0, 1]);
    }

    #[test]
    fn severity_sort_order_breaks_band_and_priority_ties_by_file_then_line() {
        let at = |file: &str, line: i64| {
            let mut f = finding_with(None, None, None);
            f.file = file.to_string();
            f.line_start = line;
            RankedFinding {
                finding: f,
                severity: Severity::High,
                exploitability_notes: String::new(),
            }
        };
        let ranked = vec![at("b.rs", 10), at("a.rs", 50), at("a.rs", 5)];
        assert_eq!(severity_sort_order(&ranked), vec![2, 1, 0]);
    }

    #[test]
    fn severity_sort_order_is_independent_of_input_order() {
        // The determinism property this key exists for: two permutations
        // of the same finding set must render in the same report order,
        // regardless of the S6-completion-timing order they arrived in.
        let at = |file: &str, line: i64, sev: Severity| {
            let mut f = finding_with(None, None, None);
            f.file = file.to_string();
            f.line_start = line;
            RankedFinding {
                finding: f,
                severity: sev,
                exploitability_notes: String::new(),
            }
        };
        let a = at("a.rs", 5, Severity::High);
        let b = at("a.rs", 50, Severity::High);
        let c = at("z.rs", 1, Severity::Critical);

        let forward = vec![a.clone(), b.clone(), c.clone()];
        let shuffled = vec![c, b, a];
        let key = |ranked: &[RankedFinding], order: Vec<usize>| -> Vec<(String, i64)> {
            order
                .into_iter()
                .map(|i| (ranked[i].finding.file.clone(), ranked[i].finding.line_start))
                .collect()
        };
        assert_eq!(
            key(&forward, severity_sort_order(&forward)),
            key(&shuffled, severity_sort_order(&shuffled))
        );
    }

    #[test]
    fn severity_sort_order_of_an_empty_slice_is_empty() {
        assert!(severity_sort_order(&[]).is_empty());
    }
}
