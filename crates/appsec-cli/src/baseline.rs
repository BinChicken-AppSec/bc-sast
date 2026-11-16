use std::path::Path;

use appsec_model::{Finding, RankedFinding};
use appsec_sarif::SarifResult;
use serde::Deserialize;

#[derive(Debug, Clone)]
pub struct BaselineFinding {
    pub id_v3: Option<String>,
    pub id_v2: Option<String>,
    pub id_v1: String,
    pub file: String,
    pub vuln_class: String,
    pub line_start: i64,
    pub line_end: i64,
    pub title: String,
    pub sarif: Option<Box<SarifResult>>,
    pub finding: Option<Box<Finding>>,
}

#[derive(Debug, Clone, Default)]
pub struct Baseline {
    pub findings: Vec<BaselineFinding>,
    pub commit_sha: Option<String>,
    pub from_sarif: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaselineState {
    New,
    Unchanged(MatchTier),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MatchTier {
    ContentExact,
    ContentCollapsed,
    Legacy,
    Renamed,
    Fuzzy,
}

impl BaselineState {
    pub fn as_str(self) -> &'static str {
        match self {
            BaselineState::New => "new",
            BaselineState::Unchanged(_) => "unchanged",
        }
    }

    pub fn tier(self) -> Option<MatchTier> {
        match self {
            BaselineState::New => None,
            BaselineState::Unchanged(tier) => Some(tier),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Comparison {
    pub states: Vec<BaselineState>,
    pub absent: Vec<BaselineFinding>,
}

impl Comparison {
    pub fn new_count(&self) -> usize {
        self.states
            .iter()
            .filter(|s| **s == BaselineState::New)
            .count()
    }

    pub fn unchanged_count(&self) -> usize {
        self.states.len() - self.new_count()
    }

    pub fn resolved_count(&self) -> usize {
        self.absent.len()
    }
}

#[derive(Debug, Deserialize)]
struct FindingsBaseline {
    findings: Vec<Finding>,
    #[serde(default)]
    commit_sha: String,
}

pub fn load(path: &Path, repo_root: &Path) -> Result<Baseline, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read baseline {}: {e}", path.display()))?;
    let value: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| format!("baseline {} is not valid JSON: {e}", path.display()))?;
    if value.get("runs").is_some() {
        return from_sarif(&value, path);
    }
    if value.get("findings").is_some() {
        let parsed: FindingsBaseline = serde_json::from_value(value)
            .map_err(|e| format!("baseline {} is not a findings export: {e}", path.display()))?;
        return Ok(Baseline {
            findings: parsed
                .findings
                .iter()
                .map(|f| BaselineFinding {
                    finding: Some(Box::new(f.clone())),
                    ..from_finding(f, repo_root)
                })
                .collect(),
            commit_sha: Some(parsed.commit_sha).filter(|s| !s.trim().is_empty()),
            from_sarif: false,
        });
    }
    Err(format!(
        "baseline {} is neither a SARIF document (no `runs`) nor a \
         findings export (no `findings`)",
        path.display()
    ))
}

fn from_finding(f: &Finding, repo_root: &Path) -> BaselineFinding {
    BaselineFinding {
        id_v3: appsec_sarif::finding_id_v3(repo_root, f),
        id_v2: appsec_sarif::finding_id_v2(repo_root, f),
        id_v1: appsec_sarif::finding_id(f),
        file: f.file.clone(),
        vuln_class: f.vuln_class.as_str().to_string(),
        line_start: f.line_start,
        line_end: f.line_end,
        title: f.title.clone(),
        sarif: None,
        finding: None,
    }
}

fn from_sarif(value: &serde_json::Value, path: &Path) -> Result<Baseline, String> {
    let doc: appsec_sarif::SarifDocument = serde_json::from_value(value.clone()).map_err(|e| {
        format!(
            "baseline {} is not a SARIF 2.1.0 document: {e}",
            path.display()
        )
    })?;
    let findings = doc
        .runs
        .into_iter()
        .flat_map(|run| run.results)
        .enumerate()
        .map(|(i, result)| {
            let id_v3 = result
                .partial_fingerprints
                .get(appsec_sarif::FINGERPRINT_KEY_V3)
                .cloned();
            let id_v2 = result
                .partial_fingerprints
                .get(appsec_sarif::FINGERPRINT_KEY_V2)
                .cloned();
            let id_v1 = result
                .partial_fingerprints
                .get(appsec_sarif::FINGERPRINT_KEY)
                .cloned()
                .unwrap_or_else(|| format!("baseline-without-fingerprint-{i}"));
            let location = result.locations.first();
            let file = location
                .map(|l| l.physical_location.artifact_location.uri.clone())
                .unwrap_or_default();
            let region = location.map(|l| &l.physical_location.region);
            let line_start = region.map(|r| r.start_line).unwrap_or(0);
            let line_end = region.and_then(|r| r.end_line).unwrap_or(line_start);
            BaselineFinding {
                id_v3,
                id_v2,
                id_v1,
                file,
                vuln_class: result.rule_id.clone(),
                line_start,
                line_end,
                title: result.message.text.clone(),
                sarif: Some(Box::new(result)),
                finding: None,
            }
        })
        .collect();
    Ok(Baseline {
        findings,
        commit_sha: revision_id(value),
        from_sarif: true,
    })
}

fn revision_id(value: &serde_json::Value) -> Option<String> {
    let revision = value
        .get("runs")?
        .as_array()?
        .iter()
        .filter_map(|run| run.get("versionControlProvenance")?.as_array()?.first())
        .filter_map(|prov| prov.get("revisionId")?.as_str())
        .find(|rev| !rev.trim().is_empty())?;
    Some(revision.to_string())
}

fn fuzzy_match(a: &BaselineFinding, b: &BaselineFinding, line_tolerance: i64) -> bool {
    if a.file != b.file || a.vuln_class != b.vuln_class {
        return false;
    }
    let close = (a.line_start - b.line_start).abs() <= line_tolerance;
    let overlap = a.line_start <= b.line_end && b.line_start <= a.line_end;
    close || overlap
}

type ExactMatch = fn(&BaselineFinding, &BaselineFinding) -> bool;

const EXACT_PASSES: [(MatchTier, ExactMatch); 3] = [
    (MatchTier::ContentExact, |a, b| {
        a.id_v3.is_some() && a.id_v3 == b.id_v3
    }),
    (MatchTier::ContentCollapsed, |a, b| {
        a.id_v2.is_some() && a.id_v2 == b.id_v2
    }),
    (MatchTier::Legacy, |a, b| a.id_v1 == b.id_v1),
];

fn run_pass(
    projected: &[BaselineFinding],
    candidates: &[BaselineFinding],
    tier: MatchTier,
    states: &mut [BaselineState],
    claimed: &mut [bool],
    matches: impl Fn(&BaselineFinding, &BaselineFinding) -> bool,
) {
    for (i, cur) in projected.iter().enumerate() {
        if matches!(states[i], BaselineState::Unchanged(_)) {
            continue;
        }
        let hit = candidates
            .iter()
            .enumerate()
            .find(|(j, prior)| !claimed[*j] && matches(cur, prior));
        if let Some((j, _)) = hit {
            claimed[j] = true;
            states[i] = BaselineState::Unchanged(tier);
        }
    }
}

fn remap_renamed(
    baseline: &[BaselineFinding],
    renames: &std::collections::BTreeMap<String, String>,
    repo_root: &Path,
) -> Vec<BaselineFinding> {
    baseline
        .iter()
        .map(|f| {
            let Some(new_path) = renames.get(&f.file) else {
                return f.clone();
            };
            let mut out = f.clone();
            out.file = new_path.clone();
            match appsec_sarif::line_range_text(repo_root, new_path, f.line_start, f.line_end) {
                Some(text) => {
                    out.id_v3 = Some(appsec_sarif::finding_fingerprint_v3(new_path, &text));
                    out.id_v2 = Some(appsec_sarif::finding_fingerprint_v2(new_path, &text));
                }
                None => {
                    out.id_v3 = None;
                    out.id_v2 = None;
                }
            }
            if let Some(prior) = &f.finding {
                let mut moved = (**prior).clone();
                moved.file = new_path.clone();
                out.id_v1 = appsec_sarif::finding_id(&moved);
            }
            out
        })
        .collect()
}

pub fn compare(
    current: &[RankedFinding],
    baseline: &Baseline,
    repo_root: &Path,
    line_tolerance: i64,
    renames: &std::collections::BTreeMap<String, String>,
) -> Comparison {
    let projected: Vec<BaselineFinding> = current
        .iter()
        .map(|rf| from_finding(&rf.finding, repo_root))
        .collect();
    let mut states = vec![BaselineState::New; projected.len()];
    let mut claimed = vec![false; baseline.findings.len()];

    for (tier, matches) in EXACT_PASSES {
        run_pass(
            &projected,
            &baseline.findings,
            tier,
            &mut states,
            &mut claimed,
            matches,
        );
    }

    if !renames.is_empty() {
        let remapped = remap_renamed(&baseline.findings, renames, repo_root);
        for (_, matches) in EXACT_PASSES {
            run_pass(
                &projected,
                &remapped,
                MatchTier::Renamed,
                &mut states,
                &mut claimed,
                matches,
            );
        }
    }

    run_pass(
        &projected,
        &baseline.findings,
        MatchTier::Fuzzy,
        &mut states,
        &mut claimed,
        |a, b| fuzzy_match(a, b, line_tolerance),
    );

    let absent = baseline
        .findings
        .iter()
        .zip(&claimed)
        .filter(|(_, taken)| !**taken)
        .map(|(f, _)| f.clone())
        .collect();
    Comparison { states, absent }
}

pub fn view(
    comparison: &Comparison,
    current: &[RankedFinding],
    baseline_path: &Path,
) -> appsec_report_md::BaselineView {
    let new = comparison
        .states
        .iter()
        .zip(current)
        .filter(|(state, _)| **state == BaselineState::New)
        .map(|(_, rf)| appsec_report_md::BaselineEntry {
            file: rf.finding.file.clone(),
            line: rf.finding.line_start,
            title: rf.finding.title.clone(),
        })
        .collect();
    let resolved = comparison
        .absent
        .iter()
        .map(|f| appsec_report_md::BaselineEntry {
            file: f.file.clone(),
            line: f.line_start,
            title: f.title.clone(),
        })
        .collect();
    let tier_count = |want: MatchTier| {
        comparison
            .states
            .iter()
            .filter(|s| s.tier() == Some(want))
            .count()
    };
    appsec_report_md::BaselineView {
        baseline: baseline_path.display().to_string(),
        new,
        unchanged: comparison.unchanged_count(),
        unchanged_fuzzy: tier_count(MatchTier::Fuzzy),
        unchanged_renamed: tier_count(MatchTier::Renamed),
        resolved,
    }
}

fn absent_result(f: &BaselineFinding) -> Option<appsec_sarif::SarifResult> {
    if let Some(prior) = &f.sarif {
        return Some((**prior).clone().with_baseline_state("absent"));
    }
    let finding = f.finding.as_ref()?;
    let ranked = RankedFinding {
        severity: appsec_stage_s8::final_severity(finding, appsec_model::Severity::Info),
        finding: (**finding).clone(),
        exploitability_notes: String::new(),
    };
    Some(appsec_sarif::build_absent_result(
        &ranked,
        appsec_sarif::Fingerprints {
            v2: f.id_v2.clone(),
            v3: f.id_v3.clone(),
        },
    ))
}

pub fn annotate_sarif(sarif: &str, comparison: &Comparison) -> String {
    let Ok(mut doc) = serde_json::from_str::<appsec_sarif::SarifDocument>(sarif) else {
        return sarif.to_string();
    };
    let mut states = comparison.states.iter();
    for run in &mut doc.runs {
        for result in &mut run.results {
            match states.next() {
                Some(state) => result.baseline_state = Some(state.as_str().to_string()),
                None => return sarif.to_string(),
            }
        }
    }
    if states.next().is_some() {
        return sarif.to_string();
    }
    if let Some(run) = doc.runs.first_mut() {
        run.results
            .extend(comparison.absent.iter().filter_map(absent_result));
    }
    serde_json::to_string_pretty(&doc).expect("SarifDocument always serializes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use appsec_model::{Severity, VulnClass};

    fn no_renames() -> std::collections::BTreeMap<String, String> {
        std::collections::BTreeMap::new()
    }

    fn states_of(cmp: &Comparison) -> Vec<&'static str> {
        cmp.states.iter().map(|s| s.as_str()).collect()
    }

    fn tiers_of(cmp: &Comparison) -> Vec<Option<MatchTier>> {
        cmp.states.iter().map(|s| s.tier()).collect()
    }

    fn finding(file: &str, line: i64, title: &str, class: VulnClass) -> Finding {
        Finding {
            provider_origins: Vec::new(),
            component: None,
            chunk_id: "c1".to_string(),
            file: file.to_string(),
            line_start: line,
            line_end: line,
            vuln_class: class,
            cwe: None,
            title: title.to_string(),
            impact: String::new(),
            description: "d".to_string(),
            exploit_scenario: String::new(),
            preconditions: Vec::new(),
            recommendation: String::new(),
            code_snippet: format!("snippet for {title}"),
            source_ref: None,
            sink_ref: None,
            backfilled_refs: Vec::new(),
            reanchored: Vec::new(),
            compliance_requirements: Vec::new(),
            confidence: 0.5,
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

    fn ranked(f: Finding) -> RankedFinding {
        RankedFinding {
            finding: f,
            severity: Severity::High,
            exploitability_notes: String::new(),
        }
    }

    fn report_of(findings: Vec<Finding>) -> appsec_model::FinalReport {
        appsec_model::FinalReport {
            repo_identity: None,
            provider_ledger: Default::default(),
            repo_root: "/r".to_string(),
            repo_name: None,
            git_sha: None,
            findings: findings.into_iter().map(ranked).collect(),
            chains: Vec::new(),
            dropped: Vec::new(),
            raw_findings_count: 0,
            metrics: None,
            threat_model: None,
            app_profile: None,
            summary: String::new(),
            degraded: false,
            degraded_reason: String::new(),
            unreachable_files: Vec::new(),
        }
    }

    fn write_findings_baseline(dir: &Path, findings: &[Finding]) -> std::path::PathBuf {
        let path = dir.join("baseline.json");
        let body = serde_json::json!({"commit_sha": "abc", "findings": findings});
        std::fs::write(&path, serde_json::to_string(&body).unwrap()).unwrap();
        path
    }

    #[test]
    fn a_directory_rename_is_recognized_instead_of_resolved_and_re_reported() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("src/old")).unwrap();
        let names = ["a.py", "b.py", "c.py"];
        for n in names {
            std::fs::write(
                dir.path().join("src/old").join(n),
                "def handler(request):\n    q = request.GET['q']\n    cur.execute(q)\n",
            )
            .unwrap();
        }
        let before: Vec<Finding> = names
            .iter()
            .map(|n| finding(&format!("src/old/{n}"), 2, "SQLi", VulnClass::Injection))
            .collect();
        let path = write_findings_baseline(dir.path(), &before);
        let baseline = load(&path, dir.path()).unwrap();

        std::fs::create_dir_all(dir.path().join("src/new")).unwrap();
        for n in names {
            std::fs::rename(
                dir.path().join("src/old").join(n),
                dir.path().join("src/new").join(n),
            )
            .unwrap();
        }
        let after: Vec<Finding> = names
            .iter()
            .map(|n| finding(&format!("src/new/{n}"), 2, "SQLi", VulnClass::Injection))
            .collect();
        let report = report_of(after);

        let blind = compare(&report.findings, &baseline, dir.path(), 3, &no_renames());
        assert_eq!(blind.new_count(), 3);
        assert_eq!(blind.resolved_count(), 3);

        let renames: std::collections::BTreeMap<String, String> = names
            .iter()
            .map(|n| (format!("src/old/{n}"), format!("src/new/{n}")))
            .collect();
        let cmp = compare(&report.findings, &baseline, dir.path(), 3, &renames);
        assert_eq!(cmp.new_count(), 0, "{:?}", states_of(&cmp));
        assert_eq!(cmp.resolved_count(), 0);
        assert_eq!(cmp.unchanged_count(), 3);
        assert_eq!(tiers_of(&cmp), vec![Some(MatchTier::Renamed); 3]);
    }

    #[test]
    fn a_renamed_file_whose_code_changed_still_matches_on_the_legacy_key() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("old.py"), "q = request.GET['q']\n").unwrap();
        let before = finding("old.py", 1, "SQLi", VulnClass::Injection);
        let path = write_findings_baseline(dir.path(), std::slice::from_ref(&before));
        let baseline = load(&path, dir.path()).unwrap();

        std::fs::rename(dir.path().join("old.py"), dir.path().join("new.py")).unwrap();
        std::fs::write(dir.path().join("new.py"), "q = request.GET['query']\n").unwrap();
        let mut after = before.clone();
        after.file = "new.py".to_string();
        let report = report_of(vec![after]);

        let renames =
            std::collections::BTreeMap::from([("old.py".to_string(), "new.py".to_string())]);
        let cmp = compare(&report.findings, &baseline, dir.path(), 3, &renames);
        assert_eq!(tiers_of(&cmp), vec![Some(MatchTier::Renamed)]);
        assert_eq!(cmp.resolved_count(), 0);
    }

    #[test]
    fn a_rename_to_an_unreadable_path_does_not_match_on_the_stored_keys() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("old.py"), "q = request.GET['q']\n").unwrap();
        let before = finding("old.py", 1, "SQLi", VulnClass::Injection);
        let path = write_findings_baseline(dir.path(), std::slice::from_ref(&before));
        let baseline = load(&path, dir.path()).unwrap();
        std::fs::remove_file(dir.path().join("old.py")).unwrap();

        let mut after = before.clone();
        after.file = "gone.py".to_string();
        after.title = "something else entirely".to_string();
        after.vuln_class = VulnClass::LogicFlaw;
        after.code_snippet = "unrelated".to_string();
        let report = report_of(vec![after]);

        let renames =
            std::collections::BTreeMap::from([("old.py".to_string(), "gone.py".to_string())]);
        let cmp = compare(&report.findings, &baseline, dir.path(), 3, &renames);
        assert_eq!(states_of(&cmp), vec!["new"]);
        assert_eq!(cmp.resolved_count(), 1);
    }

    #[test]
    fn a_spacing_only_reformat_still_matches_at_the_strongest_tier() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("app.py"), "cur.execute( q )\n").unwrap();
        let f = finding("app.py", 1, "SQLi", VulnClass::Injection);
        let path = write_findings_baseline(dir.path(), std::slice::from_ref(&f));
        let baseline = load(&path, dir.path()).unwrap();

        std::fs::write(dir.path().join("app.py"), "cur.execute(q)\n").unwrap();
        let cmp = compare(
            &report_of(vec![f]).findings,
            &baseline,
            dir.path(),
            3,
            &no_renames(),
        );
        assert_eq!(tiers_of(&cmp), vec![Some(MatchTier::ContentExact)]);
    }

    #[test]
    fn every_tier_reports_unchanged_and_orders_strongest_first() {
        assert_eq!(BaselineState::New.tier(), None);
        assert_eq!(BaselineState::New.as_str(), "new");
        let tiers = [
            MatchTier::ContentExact,
            MatchTier::ContentCollapsed,
            MatchTier::Legacy,
            MatchTier::Renamed,
            MatchTier::Fuzzy,
        ];
        for t in tiers {
            assert_eq!(BaselineState::Unchanged(t).as_str(), "unchanged");
            assert_eq!(BaselineState::Unchanged(t).tier(), Some(t));
        }
        let mut sorted = tiers;
        sorted.sort_unstable();
        assert_eq!(sorted, tiers, "declaration order must be strength order");
        assert!(MatchTier::ContentExact < MatchTier::Fuzzy);
    }

    #[test]
    fn a_findings_export_baselines_commit_sha_is_read() {
        let dir = tempfile::tempdir().unwrap();
        let f = finding("app.py", 1, "SQLi", VulnClass::Injection);
        let path = write_findings_baseline(dir.path(), std::slice::from_ref(&f));
        assert_eq!(
            load(&path, dir.path()).unwrap().commit_sha.as_deref(),
            Some("abc")
        );
    }

    #[test]
    fn an_export_without_a_commit_sha_simply_has_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("b.json");
        std::fs::write(&path, r#"{"findings": []}"#).unwrap();
        assert_eq!(load(&path, dir.path()).unwrap().commit_sha, None);

        let blank = dir.path().join("blank.json");
        std::fs::write(&blank, r#"{"commit_sha": "  ", "findings": []}"#).unwrap();
        assert_eq!(load(&blank, dir.path()).unwrap().commit_sha, None);
    }

    #[test]
    fn a_sarif_baselines_revision_is_read_from_provenance_when_present() {
        let dir = tempfile::tempdir().unwrap();
        let report = report_of(vec![finding("app.py", 10, "SQLi", VulnClass::Injection)]);
        let doc = appsec_sarif::build_sarif(&report, "test");
        let mut value: serde_json::Value = serde_json::to_value(&doc).unwrap();

        let without = dir.path().join("without.sarif");
        std::fs::write(&without, serde_json::to_string(&value).unwrap()).unwrap();
        assert_eq!(load(&without, dir.path()).unwrap().commit_sha, None);

        value["runs"][0]["versionControlProvenance"] = serde_json::json!([{
            "repositoryUri": "https://github.com/org/repo",
            "revisionId": "deadbeef",
        }]);
        let with = dir.path().join("with.sarif");
        std::fs::write(&with, serde_json::to_string(&value).unwrap()).unwrap();
        assert_eq!(
            load(&with, dir.path()).unwrap().commit_sha.as_deref(),
            Some("deadbeef")
        );

        value["runs"][0]["versionControlProvenance"] = serde_json::json!([{
            "repositoryUri": "https://github.com/org/repo",
            "revisionId": "   ",
        }]);
        let blank = dir.path().join("blank.sarif");
        std::fs::write(&blank, serde_json::to_string(&value).unwrap()).unwrap();
        assert_eq!(load(&blank, dir.path()).unwrap().commit_sha, None);
    }

    #[test]
    fn an_identical_finding_is_unchanged_and_nothing_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        let f = finding("app.py", 10, "SQLi", VulnClass::Injection);
        let path = write_findings_baseline(dir.path(), std::slice::from_ref(&f));
        let baseline = load(&path, dir.path()).unwrap();
        let report = report_of(vec![f]);

        let cmp = compare(&report.findings, &baseline, dir.path(), 3, &no_renames());
        assert_eq!(states_of(&cmp), vec!["unchanged"]);
        assert_eq!(cmp.new_count(), 0);
        assert_eq!(cmp.unchanged_count(), 1);
        assert_eq!(cmp.resolved_count(), 0);
    }

    #[test]
    fn a_finding_absent_from_the_baseline_is_new() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_findings_baseline(dir.path(), &[]);
        let baseline = load(&path, dir.path()).unwrap();
        let report = report_of(vec![finding("app.py", 10, "SQLi", VulnClass::Injection)]);

        let cmp = compare(&report.findings, &baseline, dir.path(), 3, &no_renames());
        assert_eq!(states_of(&cmp), vec!["new"]);
        assert_eq!(cmp.new_count(), 1);
    }

    #[test]
    fn a_baseline_finding_absent_from_this_scan_is_resolved() {
        let dir = tempfile::tempdir().unwrap();
        let f = finding("gone.py", 4, "Path traversal", VulnClass::Other);
        let path = write_findings_baseline(dir.path(), std::slice::from_ref(&f));
        let baseline = load(&path, dir.path()).unwrap();
        let report = report_of(Vec::new());

        let cmp = compare(&report.findings, &baseline, dir.path(), 3, &no_renames());
        assert_eq!(cmp.resolved_count(), 1);
        assert_eq!(cmp.absent[0].title, "Path traversal");
    }

    #[test]
    fn a_moved_finding_with_the_same_snippet_matches_on_the_v1_key() {
        let dir = tempfile::tempdir().unwrap();
        let before = finding("app.py", 10, "SQLi", VulnClass::Injection);
        let path = write_findings_baseline(dir.path(), std::slice::from_ref(&before));
        let baseline = load(&path, dir.path()).unwrap();
        let mut after = before.clone();
        after.line_start = 900;
        after.line_end = 900;
        let report = report_of(vec![after]);

        let cmp = compare(&report.findings, &baseline, dir.path(), 3, &no_renames());
        assert_eq!(states_of(&cmp), vec!["unchanged"]);
    }

    #[test]
    fn the_fuzzy_pass_matches_a_reworded_finding_a_few_lines_away() {
        let dir = tempfile::tempdir().unwrap();
        let before = finding("app.py", 10, "SQLi", VulnClass::Injection);
        let path = write_findings_baseline(dir.path(), std::slice::from_ref(&before));
        let baseline = load(&path, dir.path()).unwrap();
        let after = finding("app.py", 12, "Unsanitized SQL", VulnClass::Injection);
        assert_ne!(
            appsec_sarif::finding_id(&after),
            appsec_sarif::finding_id(&before)
        );

        let cmp = compare(
            &report_of(vec![after.clone()]).findings,
            &baseline,
            dir.path(),
            3,
            &no_renames(),
        );
        assert_eq!(states_of(&cmp), vec!["unchanged"]);

        let far = finding("app.py", 40, "Unsanitized SQL", VulnClass::Injection);
        let cmp = compare(
            &report_of(vec![far]).findings,
            &baseline,
            dir.path(),
            3,
            &no_renames(),
        );
        assert_eq!(states_of(&cmp), vec!["new"]);

        let other_class = finding("app.py", 10, "Unsanitized SQL", VulnClass::LogicFlaw);
        let cmp = compare(
            &report_of(vec![other_class]).findings,
            &baseline,
            dir.path(),
            3,
            &no_renames(),
        );
        assert_eq!(states_of(&cmp), vec!["new"]);
    }

    #[test]
    fn an_exact_key_match_wins_over_a_fuzzy_one() {
        let dir = tempfile::tempdir().unwrap();
        let prior = finding("app.py", 10, "SQLi", VulnClass::Injection);
        let path = write_findings_baseline(dir.path(), std::slice::from_ref(&prior));
        let baseline = load(&path, dir.path()).unwrap();
        let fuzzy = finding("app.py", 11, "Something else", VulnClass::Injection);
        let report = report_of(vec![fuzzy, prior]);

        let cmp = compare(&report.findings, &baseline, dir.path(), 3, &no_renames());
        assert_eq!(states_of(&cmp), vec!["new", "unchanged"]);
    }

    #[test]
    fn the_v2_key_matches_when_the_on_disk_code_is_readable_and_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("app.py"), "one\ntwo\nthree\n").unwrap();
        let mut f = finding("app.py", 2, "SQLi", VulnClass::Injection);
        f.line_end = 2;
        let path = write_findings_baseline(dir.path(), std::slice::from_ref(&f));
        let baseline = load(&path, dir.path()).unwrap();
        assert!(
            baseline.findings[0].id_v2.is_some(),
            "a readable file yields a v2 key"
        );
        let cmp = compare(
            &report_of(vec![f]).findings,
            &baseline,
            dir.path(),
            3,
            &no_renames(),
        );
        assert_eq!(states_of(&cmp), vec!["unchanged"]);
    }

    #[test]
    fn a_sarif_baseline_is_recognized_and_carries_its_prior_results() {
        let dir = tempfile::tempdir().unwrap();
        let report = report_of(vec![finding("app.py", 10, "SQLi", VulnClass::Injection)]);
        let doc = appsec_sarif::build_sarif(&report, "test");
        let path = dir.path().join("prior.sarif");
        std::fs::write(&path, serde_json::to_string_pretty(&doc).unwrap()).unwrap();

        let baseline = load(&path, dir.path()).unwrap();
        assert!(baseline.from_sarif);
        assert_eq!(baseline.findings.len(), 1);
        assert!(baseline.findings[0].sarif.is_some());
        assert_eq!(baseline.findings[0].file, "app.py");
        assert_eq!(baseline.findings[0].vuln_class, "injection");

        let cmp = compare(&report.findings, &baseline, dir.path(), 3, &no_renames());
        assert_eq!(states_of(&cmp), vec!["unchanged"]);
    }

    #[test]
    fn a_sarif_result_without_a_fingerprint_still_loads_and_can_match_fuzzily() {
        let dir = tempfile::tempdir().unwrap();
        let prior = report_of(vec![finding("app.py", 10, "SQLi", VulnClass::Injection)]);
        let mut doc = serde_json::to_value(appsec_sarif::build_sarif(&prior, "test")).unwrap();
        doc["runs"][0]["results"][0]["partialFingerprints"] = serde_json::json!({});
        let path = dir.path().join("no-fingerprints.sarif");
        std::fs::write(&path, serde_json::to_string_pretty(&doc).unwrap()).unwrap();

        let baseline = load(&path, dir.path()).unwrap();
        assert_eq!(baseline.findings.len(), 1);
        assert!(baseline.findings[0].id_v1.starts_with("baseline-without-"));
        assert!(baseline.findings[0].id_v2.is_none());
        let report = report_of(vec![finding(
            "app.py",
            11,
            "Reworded",
            VulnClass::Injection,
        )]);
        let cmp = compare(&report.findings, &baseline, dir.path(), 3, &no_renames());
        assert_eq!(states_of(&cmp), vec!["unchanged"]);
    }

    #[test]
    fn a_foreign_sarif_document_is_refused_with_a_clear_message() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("foreign.sarif");
        std::fs::write(
            &path,
            r#"{"$schema":"s","version":"2.1.0","runs":[{"tool":{"driver":{"name":"other"}},"results":[]}]}"#,
        )
        .unwrap();
        let err = load(&path, dir.path()).unwrap_err();
        assert!(err.contains("not a SARIF 2.1.0 document"), "{err}");
    }

    #[test]
    fn a_missing_unparseable_or_unrecognized_baseline_is_a_hard_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load(&dir.path().join("nope.json"), dir.path()).is_err());
        let broken = dir.path().join("broken.json");
        std::fs::write(&broken, "{ nope").unwrap();
        assert!(load(&broken, dir.path()).is_err());
        let foreign = dir.path().join("foreign.json");
        std::fs::write(&foreign, r#"{"something": []}"#).unwrap();
        let err = load(&foreign, dir.path()).unwrap_err();
        assert!(err.contains("neither a SARIF document"), "{err}");
    }

    #[test]
    fn a_malformed_findings_export_and_a_malformed_sarif_both_error() {
        let dir = tempfile::tempdir().unwrap();
        let bad_findings = dir.path().join("f.json");
        std::fs::write(&bad_findings, r#"{"findings": [7]}"#).unwrap();
        assert!(load(&bad_findings, dir.path())
            .unwrap_err()
            .contains("not a findings export"));
        let bad_sarif = dir.path().join("s.sarif");
        std::fs::write(&bad_sarif, r#"{"runs": [7]}"#).unwrap();
        assert!(load(&bad_sarif, dir.path())
            .unwrap_err()
            .contains("not a SARIF 2.1.0 document"));
    }

    #[test]
    fn the_view_lists_new_and_resolved_findings_and_counts_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let kept = finding("kept.py", 1, "Kept", VulnClass::Injection);
        let gone = finding("gone.py", 2, "Gone", VulnClass::Other);
        let path = write_findings_baseline(dir.path(), &[kept.clone(), gone]);
        let baseline = load(&path, dir.path()).unwrap();
        let fresh = finding("fresh.py", 3, "Fresh", VulnClass::LogicFlaw);
        let report = report_of(vec![kept, fresh]);

        let cmp = compare(&report.findings, &baseline, dir.path(), 3, &no_renames());
        let v = view(&cmp, &report.findings, Path::new("b.json"));
        assert_eq!(v.baseline, "b.json");
        assert_eq!(v.unchanged, 1);
        assert_eq!(v.new.len(), 1);
        assert_eq!(v.new[0].title, "Fresh");
        assert_eq!(v.resolved.len(), 1);
        assert_eq!(v.resolved[0].title, "Gone");
    }

    #[test]
    fn annotate_sarif_stamps_every_result_and_appends_absent_ones() {
        let dir = tempfile::tempdir().unwrap();
        let prior = report_of(vec![
            finding("kept.py", 1, "Kept", VulnClass::Injection),
            finding("gone.py", 2, "Gone", VulnClass::Other),
        ]);
        let prior_path = dir.path().join("prior.sarif");
        std::fs::write(
            &prior_path,
            serde_json::to_string_pretty(&appsec_sarif::build_sarif(&prior, "test")).unwrap(),
        )
        .unwrap();
        let baseline = load(&prior_path, dir.path()).unwrap();

        let current = report_of(vec![
            finding("kept.py", 1, "Kept", VulnClass::Injection),
            finding("fresh.py", 3, "Fresh", VulnClass::LogicFlaw),
        ]);
        let sarif =
            serde_json::to_string_pretty(&appsec_sarif::build_sarif(&current, "test")).unwrap();
        let cmp = compare(&current.findings, &baseline, dir.path(), 3, &no_renames());

        let annotated = annotate_sarif(&sarif, &cmp);
        let doc: serde_json::Value = serde_json::from_str(&annotated).unwrap();
        let results = doc["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 3, "two current + one absent");
        assert_eq!(results[0]["baselineState"], "unchanged");
        assert_eq!(results[1]["baselineState"], "new");
        assert_eq!(results[2]["baselineState"], "absent");
        assert_eq!(results[2]["message"]["text"], "Gone");
    }

    #[test]
    fn annotate_sarif_appends_absent_results_for_a_findings_json_baseline() {
        let dir = tempfile::tempdir().unwrap();
        let mut gone = finding("gone.py", 2, "Gone", VulnClass::Other);
        gone.cvss_score = Some(9.8);
        gone.cvss_rating = Some("Critical".to_string());
        let path = write_findings_baseline(dir.path(), std::slice::from_ref(&gone));
        let baseline = load(&path, dir.path()).unwrap();
        let current = report_of(vec![finding("fresh.py", 3, "Fresh", VulnClass::LogicFlaw)]);
        let sarif =
            serde_json::to_string_pretty(&appsec_sarif::build_sarif(&current, "test")).unwrap();
        let cmp = compare(&current.findings, &baseline, dir.path(), 3, &no_renames());

        let doc: serde_json::Value = serde_json::from_str(&annotate_sarif(&sarif, &cmp)).unwrap();
        let results = doc["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 2, "one current + one absent");
        assert_eq!(results[0]["baselineState"], "new");
        assert_eq!(results[1]["baselineState"], "absent");
        assert_eq!(results[1]["message"]["text"], "Gone");
        assert_eq!(results[1]["level"], "error");
        assert_eq!(results[1]["rank"], 98.0);
        assert_eq!(results[1]["properties"]["severity"], "critical");
        assert_eq!(results[1]["properties"]["cvssRating"], "Critical");
        assert_eq!(results[1]["ruleId"], "other");
        assert_eq!(
            results[1]["partialFingerprints"][appsec_sarif::FINGERPRINT_KEY],
            appsec_sarif::finding_id(&gone)
        );
    }

    #[test]
    fn an_absent_result_from_an_export_without_cvss_falls_back_to_info() {
        let dir = tempfile::tempdir().unwrap();
        let gone = finding("gone.py", 2, "Gone", VulnClass::Other);
        let path = write_findings_baseline(dir.path(), std::slice::from_ref(&gone));
        let baseline = load(&path, dir.path()).unwrap();
        let result = absent_result(&baseline.findings[0]).unwrap();
        assert_eq!(result.level, "note");
        assert_eq!(result.rank, None);
        assert_eq!(result.properties.severity, "info");
        assert_eq!(result.baseline_state.as_deref(), Some("absent"));
    }

    #[test]
    fn an_entry_with_neither_source_shape_yields_no_absent_result() {
        let dir = tempfile::tempdir().unwrap();
        let projected = from_finding(&finding("a.py", 1, "A", VulnClass::Other), dir.path());
        assert!(projected.sarif.is_none() && projected.finding.is_none());
        assert!(absent_result(&projected).is_none());
    }

    #[test]
    fn annotate_sarif_returns_the_input_unchanged_on_any_misalignment() {
        let dir = tempfile::tempdir().unwrap();
        let current = report_of(vec![finding("a.py", 1, "A", VulnClass::Other)]);
        let sarif =
            serde_json::to_string_pretty(&appsec_sarif::build_sarif(&current, "test")).unwrap();

        assert_eq!(
            annotate_sarif("not json", &Comparison::default()),
            "not json"
        );
        assert_eq!(annotate_sarif(&sarif, &Comparison::default()), sarif);
        let too_many = Comparison {
            states: vec![BaselineState::New; 2],
            absent: Vec::new(),
        };
        assert_eq!(annotate_sarif(&sarif, &too_many), sarif);
        let _ = dir;
    }
}
