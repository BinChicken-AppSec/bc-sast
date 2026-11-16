use std::collections::HashSet;
use std::path::Path;
use std::sync::LazyLock;

use appsec_model::{DropReason, DroppedFinding, Finding, VulnClass};
use regex::Regex;

use crate::lang_gates;
use crate::route_gates::{self, RouteIndex};

static EXCLUDE_PATH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(^|/)(tests?|__tests__|mocks?|examples?|fixtures?|samples?|testdata)(/|$)|_test\.|\.test\.|\.spec\.|Test\.java$|Tests\.cs$",
    )
    .unwrap()
});

static SECRET_TEXT_RX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(?:hard[\s-]?coded|password|passwd|api[_-]?key|access[_-]?key|secret[_-]?key|auth[_-]?token|bearer\s+token|jwt|private[_-]?key|client[_-]?secret|credential)\b|-----BEGIN\s+[A-Z ]*PRIVATE\s+KEY-----|\bAKIA[0-9A-Z]{16}\b|\bgh[pousr]_[0-9A-Za-z]{36,}\b|\bxox[baprs]-[0-9A-Za-z-]{10,}\b",
    )
    .unwrap()
});

const HARDCODED_CWES: &[&str] = &["CWE-798", "CWE-259", "CWE-321", "CWE-256"];

const CONTROL_ABSENCE_CWES: &[&str] = &[
    "CWE-352", "CWE-1004", "CWE-614", "CWE-307", "CWE-778", "CWE-311", "CWE-312", "CWE-532",
    "CWE-209",
];

fn canonical_cwe(f: &Finding) -> Option<String> {
    let raw = f.cwe.as_deref()?.trim();
    let digits = raw
        .strip_prefix("CWE-")
        .or_else(|| raw.strip_prefix("cwe-"))
        .or_else(|| raw.strip_prefix("Cwe-"))
        .unwrap_or(raw)
        .trim();
    (!digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
        .then(|| format!("CWE-{digits}"))
}

pub(crate) fn is_point_of_occurrence(f: &Finding) -> bool {
    if f.vuln_class == VulnClass::InfoLeak {
        return true;
    }
    if canonical_cwe(f).is_some_and(|cwe| {
        HARDCODED_CWES.contains(&cwe.as_str()) || CONTROL_ABSENCE_CWES.contains(&cwe.as_str())
    }) {
        return true;
    }
    let haystack = format!("{} {} {}", f.title, f.description, f.code_snippet);
    SECRET_TEXT_RX.is_match(&haystack)
}

fn has_text(s: Option<&str>) -> bool {
    s.is_some_and(|s| !s.trim().is_empty())
}

fn drop_finding(f: &Finding, reason: DropReason, detail: impl Into<String>) -> DroppedFinding {
    DroppedFinding {
        file: f.file.clone(),
        line: f.line_start,
        vuln_class: f.vuln_class,
        title: f.title.clone(),
        chunk_id: f.chunk_id.clone(),
        reason,
        detail: detail.into(),
        canonical_idx: None,
        provider_origins: f.provider_origins.clone(),
        verification: None,
    }
}

pub fn repair_path(reported: &str, valid: &HashSet<&str>) -> Option<String> {
    if valid.contains(reported) {
        return None;
    }
    let trimmed = reported.trim_start_matches("./").trim_start_matches('/');
    if valid.contains(trimmed) {
        return Some(trimmed.to_string());
    }
    let ends_at_boundary = |long: &str, short: &str| {
        long.len() > short.len()
            && long.ends_with(short)
            && long.as_bytes()[long.len() - short.len() - 1] == b'/'
    };
    let mut hits = valid
        .iter()
        .filter(|v| ends_at_boundary(trimmed, v) || ends_at_boundary(v, trimmed));
    let first = *hits.next()?;
    hits.next().is_none().then(|| first.to_string())
}

pub struct GateResult {
    pub keep: Vec<Finding>,
    pub dropped: Vec<DroppedFinding>,
    pub evidence_exempted: usize,
}

pub fn apply_gates(
    findings: &[Finding],
    valid_files: Option<&HashSet<&str>>,
    min_confidence: f64,
    require_evidence: bool,
    repo_root: Option<&Path>,
    routes: &RouteIndex,
) -> GateResult {
    let mut keep = Vec::new();
    let mut dropped = Vec::new();
    let mut evidence_exempted = 0;

    for f in findings {
        let repaired = valid_files
            .and_then(|v| repair_path(&f.file, v))
            .map(|file| Finding { file, ..f.clone() });
        let f = repaired.as_ref().unwrap_or(f);
        let in_test_path = EXCLUDE_PATH_RE.is_match(&f.file);
        let point_of_occurrence = is_point_of_occurrence(f);
        let secret_class = in_test_path && point_of_occurrence;
        let has_flow = has_text(f.source_ref.as_deref()) && has_text(f.sink_ref.as_deref());

        if in_test_path && !secret_class {
            dropped.push(drop_finding(
                f,
                DropReason::Excluded,
                "test/mock/example path",
            ));
        } else if valid_files.is_some_and(|v| !v.contains(f.file.as_str())) {
            dropped.push(drop_finding(
                f,
                DropReason::Excluded,
                "file not in repo inventory",
            ));
        } else if f.confidence < min_confidence {
            dropped.push(drop_finding(
                f,
                DropReason::Unconfirmed,
                format!(
                    "s4 confidence {:.2} < gate {min_confidence:.2}",
                    f.confidence
                ),
            ));
        } else if require_evidence && !point_of_occurrence && !has_flow {
            dropped.push(drop_finding(
                f,
                DropReason::Unconfirmed,
                "missing source_ref/sink_ref — data flow unproven",
            ));
        } else if let Some(reason) = language_verdict(f, repo_root) {
            dropped.push(drop_finding(f, DropReason::Excluded, reason));
        } else if let Some(reason) = route_gates::guarded_route(f, routes, repo_root) {
            dropped.push(drop_finding(f, DropReason::Excluded, reason));
        } else {
            if require_evidence && !has_flow {
                evidence_exempted += 1;
            }
            keep.push(f.clone());
        }
    }

    GateResult {
        keep,
        dropped,
        evidence_exempted,
    }
}

fn language_verdict(f: &Finding, repo_root: Option<&Path>) -> Option<String> {
    if !lang_gates::could_apply(f) {
        return None;
    }
    let window = lang_gates::SourceWindow::read(f, repo_root);
    lang_gates::synchronous_js_race(f, &window)
        .map(str::to_string)
        .or_else(|| lang_gates::template_autoescaped(f, &window))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_routes() -> RouteIndex<'static> {
        RouteIndex::new(&[])
    }

    fn f(file: &str, confidence: f64, source_ref: Option<&str>, sink_ref: Option<&str>) -> Finding {
        Finding {
            provider_origins: Vec::new(),
            component: None,
            chunk_id: "c".to_string(),
            file: file.to_string(),
            line_start: 1,
            line_end: 1,
            vuln_class: VulnClass::Injection,
            cwe: None,
            title: "t".to_string(),
            impact: String::new(),
            description: "d".to_string(),
            exploit_scenario: String::new(),
            preconditions: Vec::new(),
            recommendation: String::new(),
            code_snippet: "x".to_string(),
            source_ref: source_ref.map(String::from),
            sink_ref: sink_ref.map(String::from),
            backfilled_refs: Vec::new(),
            reanchored: Vec::new(),
            compliance_requirements: Vec::new(),
            confidence,
            votes: 1,
            duplicates: Vec::new(),
            verdict: None,
            verdict_confidence: None,
            verdict_reason: String::new(),
            cvss_vector: None,
            cvss_score: None,
            cvss_rating: None,
            verifier_reasoning: String::new(),
            vsvs_vector: None,
            vsvs_score: None,
            vsvs_rating: None,
            offensive_priority: None,
            offensive_reason: String::new(),
            related_cwes: Vec::new(),
        }
    }

    #[test]
    fn clean_finding_with_evidence_survives_every_gate() {
        let findings = vec![f("app.py", 0.9, Some("src"), Some("sink"))];
        let r = apply_gates(&findings, None, 0.6, true, None, &no_routes());
        assert_eq!(r.keep.len(), 1);
        assert!(r.dropped.is_empty());
    }

    #[test]
    fn test_path_finding_is_excluded() {
        let findings = vec![f("tests/foo.py", 0.9, Some("s"), Some("k"))];
        let r = apply_gates(&findings, None, 0.6, true, None, &no_routes());
        assert!(r.keep.is_empty());
        assert_eq!(r.dropped[0].reason, DropReason::Excluded);
        assert_eq!(r.dropped[0].detail, "test/mock/example path");
    }

    #[test]
    fn secret_class_finding_in_a_test_path_survives_the_path_gate() {
        let mut secret = f("tests/fixtures/creds.py", 0.9, Some("s"), Some("k"));
        secret.description = "hardcoded password found".to_string();
        let r = apply_gates(&[secret], None, 0.6, true, None, &no_routes());
        assert_eq!(r.keep.len(), 1);
    }

    #[test]
    fn info_leak_vuln_class_is_always_secret_class_regardless_of_text() {
        let mut leak = f("tests/foo.py", 0.9, Some("s"), Some("k"));
        leak.vuln_class = VulnClass::InfoLeak;
        leak.description = "nothing suspicious here".to_string();
        let r = apply_gates(&[leak], None, 0.6, true, None, &no_routes());
        assert_eq!(r.keep.len(), 1);
    }

    #[test]
    fn file_not_in_repo_inventory_is_excluded() {
        let valid: HashSet<&str> = ["other.py"].into_iter().collect();
        let findings = vec![f("app.py", 0.9, Some("s"), Some("k"))];
        let r = apply_gates(&findings, Some(&valid), 0.6, true, None, &no_routes());
        assert!(r.keep.is_empty());
        assert_eq!(r.dropped[0].reason, DropReason::Excluded);
        assert_eq!(r.dropped[0].detail, "file not in repo inventory");
    }

    #[test]
    fn a_wrong_directory_on_a_real_file_is_repaired_to_the_unique_inventory_path() {
        let valid: HashSet<&str> = ["server.ts", "routes/login.ts"].into_iter().collect();
        let findings = vec![
            f("src/server.ts", 0.9, Some("s"), Some("k")),
            f("./routes/login.ts", 0.9, Some("s"), Some("k")),
            f("login.ts", 0.9, Some("s"), Some("k")),
            f("/server.ts", 0.9, Some("s"), Some("k")),
        ];
        let r = apply_gates(&findings, Some(&valid), 0.6, true, None, &no_routes());
        assert!(r.dropped.is_empty(), "{:?}", r.dropped);
        let files: Vec<&str> = r.keep.iter().map(|k| k.file.as_str()).collect();
        assert_eq!(
            files,
            [
                "server.ts",
                "routes/login.ts",
                "routes/login.ts",
                "server.ts"
            ]
        );
    }

    #[test]
    fn an_ambiguous_or_unmatched_path_is_still_excluded() {
        let valid: HashSet<&str> = ["a/index.ts", "b/index.ts", "server.ts"]
            .into_iter()
            .collect();
        for reported in ["index.ts", "src/index.ts", "src/nothing.ts", "myserver.ts"] {
            let r = apply_gates(
                &[f(reported, 0.9, Some("s"), Some("k"))],
                Some(&valid),
                0.6,
                true,
                None,
                &no_routes(),
            );
            assert!(r.keep.is_empty(), "{reported} should not be kept");
            assert_eq!(r.dropped[0].detail, "file not in repo inventory");
        }
        assert_eq!(repair_path("server.ts", &valid), None);
    }

    #[test]
    fn the_later_gates_judge_the_repaired_path() {
        let valid: HashSet<&str> = ["tests/helper.py"].into_iter().collect();
        let r = apply_gates(
            &[f("src/tests/helper.py", 0.9, Some("s"), Some("k"))],
            Some(&valid),
            0.6,
            true,
            None,
            &no_routes(),
        );
        assert_eq!(r.dropped[0].detail, "test/mock/example path");
        assert_eq!(r.dropped[0].file, "tests/helper.py");
    }

    #[test]
    fn file_in_repo_inventory_passes_that_gate() {
        let valid: HashSet<&str> = ["app.py"].into_iter().collect();
        let findings = vec![f("app.py", 0.9, Some("s"), Some("k"))];
        let r = apply_gates(&findings, Some(&valid), 0.6, true, None, &no_routes());
        assert_eq!(r.keep.len(), 1);
    }

    #[test]
    fn no_valid_files_set_skips_the_inventory_gate_entirely() {
        let findings = vec![f("anything.py", 0.9, Some("s"), Some("k"))];
        let r = apply_gates(&findings, None, 0.6, true, None, &no_routes());
        assert_eq!(r.keep.len(), 1);
    }

    #[test]
    fn confidence_below_gate_is_unconfirmed() {
        let findings = vec![f("app.py", 0.4, Some("s"), Some("k"))];
        let r = apply_gates(&findings, None, 0.6, true, None, &no_routes());
        assert!(r.keep.is_empty());
        assert_eq!(r.dropped[0].reason, DropReason::Unconfirmed);
        assert_eq!(r.dropped[0].detail, "s4 confidence 0.40 < gate 0.60");
    }

    #[test]
    fn confidence_equal_to_gate_is_not_dropped() {
        let findings = vec![f("app.py", 0.6, Some("s"), Some("k"))];
        let r = apply_gates(&findings, None, 0.6, true, None, &no_routes());
        assert_eq!(r.keep.len(), 1);
    }

    #[test]
    fn missing_source_ref_is_unconfirmed_when_evidence_required() {
        let findings = vec![f("app.py", 0.9, None, Some("k"))];
        let r = apply_gates(&findings, None, 0.6, true, None, &no_routes());
        assert!(r.keep.is_empty());
        assert_eq!(
            r.dropped[0].detail,
            "missing source_ref/sink_ref — data flow unproven"
        );
    }

    #[test]
    fn missing_sink_ref_is_unconfirmed_when_evidence_required() {
        let findings = vec![f("app.py", 0.9, Some("s"), None)];
        let r = apply_gates(&findings, None, 0.6, true, None, &no_routes());
        assert!(r.keep.is_empty());
    }

    #[test]
    fn blank_source_ref_counts_as_missing() {
        let findings = vec![f("app.py", 0.9, Some("   "), Some("k"))];
        let r = apply_gates(&findings, None, 0.6, true, None, &no_routes());
        assert!(r.keep.is_empty());
    }

    #[test]
    fn missing_evidence_is_allowed_when_require_evidence_is_off() {
        let findings = vec![f("app.py", 0.9, None, None)];
        let r = apply_gates(&findings, None, 0.6, false, None, &no_routes());
        assert_eq!(r.keep.len(), 1);
        assert_eq!(r.evidence_exempted, 0);
    }

    fn with_cwe(cwe: &str) -> Finding {
        Finding {
            cwe: Some(cwe.to_string()),
            ..f("app.py", 0.9, None, None)
        }
    }

    #[test]
    fn point_of_occurrence_cwes_pass_require_evidence_without_a_flow() {
        for cwe in [
            "CWE-798", "CWE-259", "CWE-321", "CWE-256", "CWE-352", "CWE-1004", "CWE-614",
            "CWE-307", "CWE-778", "CWE-311", "CWE-312", "CWE-532", "CWE-209",
        ] {
            let r = apply_gates(&[with_cwe(cwe)], None, 0.6, true, None, &no_routes());
            assert_eq!(r.keep.len(), 1, "{cwe}");
            assert_eq!(r.evidence_exempted, 1, "{cwe}");
        }
    }

    #[test]
    fn the_cwe_match_tolerates_model_spellings_but_not_other_cwes() {
        for cwe in ["cwe-352", " CWE-352 ", "352", "Cwe-798"] {
            let r = apply_gates(&[with_cwe(cwe)], None, 0.6, true, None, &no_routes());
            assert_eq!(r.keep.len(), 1, "{cwe:?}");
        }
        for cwe in ["CWE-89", "CWE-", "CWE-35x", ""] {
            let r = apply_gates(&[with_cwe(cwe)], None, 0.6, true, None, &no_routes());
            assert!(r.keep.is_empty(), "{cwe:?}");
            assert_eq!(
                r.dropped[0].detail,
                "missing source_ref/sink_ref — data flow unproven"
            );
        }
    }

    #[test]
    fn a_point_of_occurrence_finding_still_faces_every_other_gate() {
        let low = Finding {
            confidence: 0.1,
            ..with_cwe("CWE-352")
        };
        let r = apply_gates(&[low], None, 0.6, true, None, &no_routes());
        assert!(r.keep.is_empty());
        assert!(r.dropped[0].detail.starts_with("s4 confidence"));
        let valid: HashSet<&str> = ["other.py"].into_iter().collect();
        let r = apply_gates(
            &[with_cwe("CWE-798")],
            Some(&valid),
            0.6,
            true,
            None,
            &no_routes(),
        );
        assert_eq!(r.dropped[0].detail, "file not in repo inventory");
    }

    #[test]
    fn a_control_absence_cwe_in_a_test_path_is_kept_as_upstream_does() {
        let csrf = Finding {
            file: "tests/views.py".to_string(),
            ..with_cwe("CWE-352")
        };
        let r = apply_gates(&[csrf], None, 0.6, true, None, &no_routes());
        assert_eq!(r.keep.len(), 1);
    }

    #[test]
    fn a_finding_with_a_flow_is_not_counted_as_exempted() {
        let r = apply_gates(
            &[Finding {
                source_ref: Some("a:1".into()),
                sink_ref: Some("a:2".into()),
                ..with_cwe("CWE-352")
            }],
            None,
            0.6,
            true,
            None,
            &no_routes(),
        );
        assert_eq!((r.keep.len(), r.evidence_exempted), (1, 0));
    }

    #[test]
    fn the_language_gates_run_after_every_cheap_gate() {
        let mut low = f("routes/captcha.ts", 0.1, Some("s"), Some("k"));
        low.vuln_class = VulnClass::RaceCondition;
        low.code_snippet = "counter += 1".to_string();
        let r = apply_gates(&[low], None, 0.6, true, None, &no_routes());
        assert_eq!(r.dropped[0].detail, "s4 confidence 0.10 < gate 0.60");
    }

    #[test]
    fn a_synchronous_javascript_race_is_excluded_by_the_language_gate() {
        let mut race = f("routes/captcha.ts", 0.9, Some("s"), Some("k"));
        race.vuln_class = VulnClass::RaceCondition;
        race.cwe = Some("CWE-362".to_string());
        race.code_snippet = "const captchaId = req.app.locals.captchaId++".to_string();
        let r = apply_gates(&[race], None, 0.6, true, None, &no_routes());
        assert!(r.keep.is_empty());
        assert_eq!(r.dropped[0].reason, DropReason::Excluded);
        assert_eq!(r.dropped[0].detail, lang_gates::SYNC_JS_REASON);
    }

    #[test]
    fn an_autoescaped_template_xss_is_excluded_by_the_language_gate() {
        let mut xss = f("views/dataErasureForm.hbs", 0.9, Some("s"), Some("k"));
        xss.cwe = Some("CWE-79".to_string());
        xss.code_snippet = "<input type=text name=email value={{userEmail}}>".to_string();
        let r = apply_gates(&[xss], None, 0.6, true, None, &no_routes());
        assert!(r.keep.is_empty());
        assert_eq!(r.dropped[0].reason, DropReason::Excluded);
        assert!(r.dropped[0]
            .detail
            .starts_with(lang_gates::TEMPLATE_ESCAPED_REASON));
    }

    #[test]
    fn a_finding_neither_language_gate_can_settle_survives_untouched() {
        let mut real = f("routes/order.ts", 0.9, Some("s"), Some("k"));
        real.vuln_class = VulnClass::RaceCondition;
        real.cwe = Some("CWE-362".to_string());
        real.code_snippet = "const b = await find(id)
if (b.total > 0) { b.total = 0 }"
            .to_string();
        assert_eq!(
            apply_gates(&[real], None, 0.6, true, None, &no_routes())
                .keep
                .len(),
            1
        );
    }

    #[test]
    fn the_route_gate_is_the_last_link_in_the_chain() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        std::fs::create_dir_all(dir.path().join("src")).expect("mkdir");
        std::fs::write(
            dir.path().join("src/handlers.rs"),
            "pub async fn search_reports(q: String) -> String { q }\n\
             pub async fn export_report(slug: String) -> String { slug }\n",
        )
        .expect("write");
        std::fs::write(
            dir.path().join("src/main.rs"),
            ".route_layer(middleware::from_fn(require_operator_token));\n",
        )
        .expect("write");
        let eps = [
            appsec_model::EntryPoint {
                file: "src/main.rs".to_string(),
                function: "export_report".to_string(),
                kind: appsec_model::EntryPointKind::Framework,
                reachable_from_unauth: false,
            },
            appsec_model::EntryPoint {
                file: "src/main.rs".to_string(),
                function: "search_reports".to_string(),
                kind: appsec_model::EntryPointKind::Framework,
                reachable_from_unauth: true,
            },
        ];
        let routes = RouteIndex::new(&eps);

        let mut guarded = f("src/handlers.rs", 0.9, Some("s"), Some("k"));
        guarded.cwe = Some("CWE-862".to_string());
        guarded.line_start = 2;
        guarded.line_end = 2;
        let mut open = guarded.clone();
        open.line_start = 1;
        open.line_end = 1;

        let r = apply_gates(&[guarded, open], None, 0.6, true, Some(dir.path()), &routes);
        assert_eq!(r.keep.len(), 1);
        assert_eq!(r.dropped.len(), 1);
        assert_eq!(r.dropped[0].reason, DropReason::Excluded);
        assert!(r.dropped[0]
            .detail
            .starts_with("route is guarded by the framework"));
        assert!(r.dropped[0]
            .detail
            .contains("middleware::from_fn(require_operator_token)"));
    }

    #[test]
    fn gates_apply_in_order_first_match_wins() {
        let findings = vec![f("tests/foo.py", 0.1, None, None)];
        let r = apply_gates(&findings, None, 0.6, true, None, &no_routes());
        assert_eq!(r.dropped[0].detail, "test/mock/example path");
    }
}
