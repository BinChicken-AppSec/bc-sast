//! `--baseline`: classify this scan's findings against a prior run's.
//!
//! **Why this needs three matchers rather than one.** A finding's
//! identity across two scans is not a solved problem here. `bc/findingId/v1`
//! hashes the rule id, the path and the LLM-QUOTED snippet, so a model
//! that quotes one line this run and three the next, or reclassifies
//! `injection` as `logic_flaw`, mints a brand-new id for the same defect.
//! `bc/findingId/v2` fixes that by hashing the path plus the ON-DISK text
//! of the finding's line range and dropping the class — but it is only
//! computable when the file is readable, and it deliberately changes when
//! that code changes, which is exactly right for "is this still the same
//! finding" and useless for "the fix moved it three lines down".
//!
//! So: v2 first (the strongest signal), then v1 (which survives a code
//! edit as long as the model quoted the same snippet), then a fuzzy
//! same-file/same-class/nearby-line fallback reusing the rule
//! `bc_dedup_core::collapse_trivial` already applies within a run. Each
//! runs as a full pass over everything still unmatched, so a fuzzy
//! candidate can never steal a pairing an exact key would have made.
//!
//! Matching is one-to-one: a baseline entry is consumed by the first
//! current finding that claims it. Anything unclaimed on the current side
//! is `new`; anything unclaimed on the baseline side is `absent`
//! (rendered as "resolved").
//!
//! **Two accepted baseline formats**, sniffed by content rather than by
//! extension: a prior `--out-findings-json` export (`{commit_sha,
//! findings}`) or a prior `report.sarif`. The SARIF form is the better
//! one — it carries the fingerprints the prior run actually computed,
//! including a v2 taken against the code AS IT WAS. A findings JSON
//! carries no fingerprints, so both keys are recomputed here against the
//! CURRENT tree; v1 is unaffected by that (it is derived from the report
//! content), but a recomputed v2 only matches when the code at those
//! lines is unchanged, which is the same thing it means anyway.
//!
//! **Both formats emit `absent` results** into this run's own SARIF, by
//! different routes (see [`absent_result`]): a SARIF baseline re-emits
//! the earlier run's result verbatim, a findings export rebuilds one
//! from the typed `Finding` it carries, through the same
//! `bc_sarif::build_result` a live finding's result comes from. Nothing
//! about a resolved finding's severity is fabricated either way — which
//! is what makes it safe to publish, and what lets a Code Scanning
//! consumer actually close the alert.

use std::path::Path;

use bc_model::{Finding, RankedFinding};
use bc_sarif::SarifResult;
use serde::Deserialize;

/// One prior finding, reduced to the keys a comparison needs.
#[derive(Debug, Clone)]
pub struct BaselineFinding {
    /// `bc/findingId/v2`, when the baseline carried one (SARIF) or one
    /// could be recomputed (findings JSON, against the current tree).
    pub id_v2: Option<String>,
    /// `bc/findingId/v1`. Always present — it is derivable from report
    /// content alone.
    pub id_v1: String,
    pub file: String,
    pub vuln_class: String,
    pub line_start: i64,
    pub line_end: i64,
    pub title: String,
    /// The prior SARIF result verbatim, when the baseline was a SARIF
    /// document. Kept so an `absent` result can be re-emitted exactly as
    /// the earlier run described it — including the fingerprints and the
    /// severity IT computed — rather than recomputed here.
    pub sarif: Option<Box<SarifResult>>,
    /// The prior `Finding` verbatim, when the baseline was a
    /// `--out-findings-json` export. That export carries the whole typed
    /// record (severity band, CVSS score and vector, CWE, confidence,
    /// votes), which is everything `bc_sarif::build_result` needs — so a
    /// resolved finding from a JSON baseline gets a real `absent` result
    /// built by the same builder a live finding's result comes from, not
    /// a fabricated one. Exactly one of this and [`Self::sarif`] is
    /// `Some(_)`, decided by which format the baseline was.
    pub finding: Option<Box<Finding>>,
}

/// A loaded baseline.
#[derive(Debug, Clone, Default)]
pub struct Baseline {
    pub findings: Vec<BaselineFinding>,
    /// Whether the source document was SARIF. Both formats now yield
    /// `absent` results (see [`absent_result`]); this records which of
    /// the two routes an entry took, for the loader's own tests and for
    /// anything that needs to know how faithful a resolved result is
    /// (a SARIF baseline's is the earlier run's own bytes; a findings
    /// export's is rebuilt from the record it carries).
    pub from_sarif: bool,
}

/// Where one current finding stands relative to the baseline. SARIF's own
/// vocabulary, minus `updated`: this port has no notion of "the same
/// finding, changed" — a finding whose code changed enough to break v2
/// but not v1 or the fuzzy rule is still the same finding, and one that
/// breaks all three is a different one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaselineState {
    New,
    Unchanged,
}

impl BaselineState {
    /// The SARIF 2.1.0 `baselineState` spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            BaselineState::New => "new",
            BaselineState::Unchanged => "unchanged",
        }
    }
}

/// The result of comparing a scan against a baseline.
#[derive(Debug, Clone, Default)]
pub struct Comparison {
    /// One entry per current finding, in `report.findings` order.
    pub states: Vec<BaselineState>,
    /// Baseline findings no current finding claimed.
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

/// `--out-findings-json`'s own shape, re-declared here rather than shared
/// with `lib.rs`'s private `FindingsExport`: this is a READER of a
/// possibly-older file, and coupling it to the writer's struct would mean
/// a future field addition on the writer silently becoming a hard
/// requirement on every existing baseline on disk.
#[derive(Debug, Deserialize)]
struct FindingsBaseline {
    findings: Vec<Finding>,
}

/// Load a baseline from a prior `--out-findings-json` export or a prior
/// `report.sarif`, sniffed by content: a top-level `runs` array is SARIF,
/// a top-level `findings` array is the findings export.
///
/// Fails hard on a missing/unparseable/unrecognized file, unlike the
/// `inject.*` feeds: a baseline decides which findings a PR gate calls
/// NEW, so silently comparing against nothing would report every
/// pre-existing finding as newly introduced — the opposite of what the
/// flag was asked to do.
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
                    // Kept alongside the derived match keys so a
                    // resolved finding can be re-emitted as a real
                    // `absent` SARIF result — see `absent_result`.
                    finding: Some(Box::new(f.clone())),
                    ..from_finding(f, repo_root)
                })
                .collect(),
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
        id_v2: bc_sarif::finding_id_v2(repo_root, f),
        id_v1: bc_sarif::finding_id(f),
        file: f.file.clone(),
        vuln_class: f.vuln_class.as_str().to_string(),
        line_start: f.line_start,
        line_end: f.line_end,
        title: f.title.clone(),
        sarif: None,
        // Attached only by `load` (see there): `compare` also runs this
        // over every CURRENT finding purely to derive match keys, and
        // cloning each record for that would be pointless work.
        finding: None,
    }
}

/// Projects every result in every run of a SARIF document.
///
/// Only THIS tool's own SARIF parses — `bc_sarif`'s types are strict, so
/// a document from another scanner is refused with a clear message rather
/// than half-read. That is the right trade for a baseline: silently
/// dropping half a foreign document's results would report the findings
/// it could not read as newly introduced.
///
/// A result with no `bc/findingId/v1` fingerprint (an older document, or
/// one whose fingerprints were stripped) still participates: `id_v1`
/// falls back to a value no current finding can ever hash to, leaving the
/// fuzzy pass as its only route to a match.
fn from_sarif(value: &serde_json::Value, path: &Path) -> Result<Baseline, String> {
    let doc: bc_sarif::SarifDocument = serde_json::from_value(value.clone()).map_err(|e| {
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
            let id_v2 = result
                .partial_fingerprints
                .get(bc_sarif::FINGERPRINT_KEY_V2)
                .cloned();
            let id_v1 = result
                .partial_fingerprints
                .get(bc_sarif::FINGERPRINT_KEY)
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
        from_sarif: true,
    })
}

/// True when `a` and `b` are close enough to be the same finding under
/// the fuzzy fallback: same file, same vulnerability class, and either
/// their line ranges overlap or their start lines are within
/// `line_tolerance`.
///
/// The same rule `bc_dedup_core::collapse_trivial` applies WITHIN a run
/// (and therefore the same rule S4's vote clustering and S5/S7's dedup
/// use), deliberately: two findings this pipeline would have collapsed
/// into one had they appeared together are the same finding across two
/// runs too. The CWE guard from that rule is not reused — a baseline
/// entry loaded from SARIF carries a rule id but no CWE, so requiring
/// agreement would make the fuzzy pass never fire for the SARIF format.
fn fuzzy_match(a: &BaselineFinding, b: &BaselineFinding, line_tolerance: i64) -> bool {
    if a.file != b.file || a.vuln_class != b.vuln_class {
        return false;
    }
    let close = (a.line_start - b.line_start).abs() <= line_tolerance;
    let overlap = a.line_start <= b.line_end && b.line_start <= a.line_end;
    close || overlap
}

/// Classify `current` against `baseline`.
///
/// Three passes in decreasing strength (v2 key, v1 key, fuzzy), each over
/// everything still unmatched, so an exact pairing is never lost to a
/// fuzzy one that happened to be considered first.
pub fn compare(
    current: &[RankedFinding],
    baseline: &Baseline,
    repo_root: &Path,
    line_tolerance: i64,
) -> Comparison {
    let projected: Vec<BaselineFinding> = current
        .iter()
        .map(|rf| from_finding(&rf.finding, repo_root))
        .collect();
    let mut states = vec![BaselineState::New; projected.len()];
    let mut claimed = vec![false; baseline.findings.len()];

    let passes: [fn(&BaselineFinding, &BaselineFinding, i64) -> bool; 3] = [
        |a, b, _| a.id_v2.is_some() && a.id_v2 == b.id_v2,
        |a, b, _| a.id_v1 == b.id_v1,
        fuzzy_match,
    ];
    for matches in passes {
        for (i, cur) in projected.iter().enumerate() {
            if states[i] == BaselineState::Unchanged {
                continue;
            }
            let hit = baseline
                .findings
                .iter()
                .enumerate()
                .find(|(j, prior)| !claimed[*j] && matches(cur, prior, line_tolerance));
            if let Some((j, _)) = hit {
                claimed[j] = true;
                states[i] = BaselineState::Unchanged;
            }
        }
    }

    let absent = baseline
        .findings
        .iter()
        .zip(&claimed)
        .filter(|(_, taken)| !**taken)
        .map(|(f, _)| f.clone())
        .collect();
    Comparison { states, absent }
}

/// The `bc_report_md` view for `## Baseline Comparison`.
pub fn view(
    comparison: &Comparison,
    current: &[RankedFinding],
    baseline_path: &Path,
) -> bc_report_md::BaselineView {
    let new = comparison
        .states
        .iter()
        .zip(current)
        .filter(|(state, _)| **state == BaselineState::New)
        .map(|(_, rf)| bc_report_md::BaselineEntry {
            file: rf.finding.file.clone(),
            line: rf.finding.line_start,
            title: rf.finding.title.clone(),
        })
        .collect();
    let resolved = comparison
        .absent
        .iter()
        .map(|f| bc_report_md::BaselineEntry {
            file: f.file.clone(),
            line: f.line_start,
            title: f.title.clone(),
        })
        .collect();
    bc_report_md::BaselineView {
        baseline: baseline_path.display().to_string(),
        new,
        unchanged: comparison.unchanged_count(),
        resolved,
    }
}

/// The SARIF `absent` result for ONE resolved baseline finding, or
/// `None` for an entry that carries neither of the two source shapes
/// (unreachable through [`load`], which always fills exactly one).
///
/// Two routes, one per baseline format:
///
/// - **SARIF baseline**: the earlier run's own result, cloned and
///   re-tagged. Nothing is recomputed, because the earlier document
///   already holds the fingerprints and the severity that run actually
///   assigned — including a v2 fingerprint taken against the code AS IT
///   WAS, which cannot be recovered now that the finding is gone.
/// - **Findings-JSON baseline**: rebuilt from the exported `Finding`
///   through [`bc_sarif::build_absent_result`], the same builder a live
///   finding's result comes from. The export is a full typed record —
///   CVSS score and vector, CWE, confidence, votes — so `level`, `rank`
///   and `security-severity` are genuinely derived, not fabricated. The
///   one input the export does not carry is the `RankedFinding` severity
///   band S8 assigned, which is reconstructed with
///   `bc_stage_s8::final_severity` from the CVSS bands the record does
///   carry — the same function S8 itself used, and the same
///   reconstruction `--remediate-from` already relies on. Its
///   `Severity::Info` last-resort argument only applies to a finding
///   with no CVSS band at all.
///
/// The v2 fingerprint passed on the second route is the one the loader
/// computed against the CURRENT tree (see [`load`]) — the same value the
/// comparison itself matched on, and `None` when the file is no longer
/// readable, which simply omits the key.
fn absent_result(f: &BaselineFinding) -> Option<bc_sarif::SarifResult> {
    if let Some(prior) = &f.sarif {
        return Some((**prior).clone().with_baseline_state("absent"));
    }
    let finding = f.finding.as_ref()?;
    let ranked = RankedFinding {
        severity: bc_stage_s8::final_severity(finding, bc_model::Severity::Info),
        finding: (**finding).clone(),
        exploitability_notes: String::new(),
    };
    Some(bc_sarif::build_absent_result(&ranked, f.id_v2.clone()))
}

/// Stamps `baselineState` onto an already-built SARIF document and
/// appends the baseline's own `absent` results.
///
/// The document is re-parsed from the string the scan already produced
/// rather than rebuilt, so this cannot drift from `build_sarif`'s output.
/// A document that fails to parse is returned unchanged — the scan's real
/// SARIF is worth more than the annotation.
///
/// `absent` results are appended for BOTH baseline formats — see
/// [`absent_result`] for how each one is built. Emitting them is what
/// lets a Code Scanning consumer close a resolved alert instead of
/// leaving it open indefinitely; the same findings also appear in
/// `report.md`'s `## Baseline Comparison` and in the run summary's
/// counts.
///
/// The `Baseline` itself is no longer a parameter: which route a
/// resolved entry takes is decided per-entry (each carries either the
/// prior SARIF result or the prior `Finding`), not per-document.
pub fn annotate_sarif(sarif: &str, comparison: &Comparison) -> String {
    let Ok(mut doc) = serde_json::from_str::<bc_sarif::SarifDocument>(sarif) else {
        return sarif.to_string();
    };
    let mut states = comparison.states.iter();
    for run in &mut doc.runs {
        for result in &mut run.results {
            match states.next() {
                Some(state) => result.baseline_state = Some(state.as_str().to_string()),
                // More results than findings: the alignment this relies
                // on (one result per `report.findings` entry, in order)
                // has broken, so stop rather than mislabel.
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
    // `expect`, not a fallback: `doc` was just deserialized from
    // `sarif`, so it is serializable by construction — the same
    // reasoning (and the same message) as every other `SarifDocument`
    // serialization in this crate.
    serde_json::to_string_pretty(&doc).expect("SarifDocument always serializes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_model::{Severity, VulnClass};

    fn finding(file: &str, line: i64, title: &str, class: VulnClass) -> Finding {
        Finding {
            provider_origins: Vec::new(),
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

    fn report_of(findings: Vec<Finding>) -> bc_model::FinalReport {
        bc_model::FinalReport {
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
    fn an_identical_finding_is_unchanged_and_nothing_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        let f = finding("app.py", 10, "SQLi", VulnClass::Injection);
        let path = write_findings_baseline(dir.path(), std::slice::from_ref(&f));
        let baseline = load(&path, dir.path()).unwrap();
        let report = report_of(vec![f]);

        let cmp = compare(&report.findings, &baseline, dir.path(), 3);
        assert_eq!(cmp.states, vec![BaselineState::Unchanged]);
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

        let cmp = compare(&report.findings, &baseline, dir.path(), 3);
        assert_eq!(cmp.states, vec![BaselineState::New]);
        assert_eq!(cmp.new_count(), 1);
    }

    #[test]
    fn a_baseline_finding_absent_from_this_scan_is_resolved() {
        let dir = tempfile::tempdir().unwrap();
        let f = finding("gone.py", 4, "Path traversal", VulnClass::Other);
        let path = write_findings_baseline(dir.path(), std::slice::from_ref(&f));
        let baseline = load(&path, dir.path()).unwrap();
        let report = report_of(Vec::new());

        let cmp = compare(&report.findings, &baseline, dir.path(), 3);
        assert_eq!(cmp.resolved_count(), 1);
        assert_eq!(cmp.absent[0].title, "Path traversal");
    }

    /// The v1 key hashes the rule id, path and the model's own snippet —
    /// so a finding whose LINE moved but whose text the model quoted
    /// identically still matches exactly, without needing the fuzzy pass.
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

        let cmp = compare(&report.findings, &baseline, dir.path(), 3);
        assert_eq!(cmp.states, vec![BaselineState::Unchanged]);
    }

    /// Different snippet AND a different title, so neither key matches —
    /// only the same-file/same-class/nearby-line rule can pair them.
    #[test]
    fn the_fuzzy_pass_matches_a_reworded_finding_a_few_lines_away() {
        let dir = tempfile::tempdir().unwrap();
        let before = finding("app.py", 10, "SQLi", VulnClass::Injection);
        let path = write_findings_baseline(dir.path(), std::slice::from_ref(&before));
        let baseline = load(&path, dir.path()).unwrap();
        let after = finding("app.py", 12, "Unsanitized SQL", VulnClass::Injection);
        assert_ne!(bc_sarif::finding_id(&after), bc_sarif::finding_id(&before));

        let cmp = compare(
            &report_of(vec![after.clone()]).findings,
            &baseline,
            dir.path(),
            3,
        );
        assert_eq!(cmp.states, vec![BaselineState::Unchanged]);

        // Outside the tolerance and not overlapping: a different finding.
        let far = finding("app.py", 40, "Unsanitized SQL", VulnClass::Injection);
        let cmp = compare(&report_of(vec![far]).findings, &baseline, dir.path(), 3);
        assert_eq!(cmp.states, vec![BaselineState::New]);

        // Same line, different class: also a different finding.
        let other_class = finding("app.py", 10, "Unsanitized SQL", VulnClass::LogicFlaw);
        let cmp = compare(
            &report_of(vec![other_class]).findings,
            &baseline,
            dir.path(),
            3,
        );
        assert_eq!(cmp.states, vec![BaselineState::New]);
    }

    /// A fuzzy candidate considered first must not consume the baseline
    /// entry an exact key would have paired with.
    #[test]
    fn an_exact_key_match_wins_over_a_fuzzy_one() {
        let dir = tempfile::tempdir().unwrap();
        let prior = finding("app.py", 10, "SQLi", VulnClass::Injection);
        let path = write_findings_baseline(dir.path(), std::slice::from_ref(&prior));
        let baseline = load(&path, dir.path()).unwrap();
        // The FIRST current finding is a fuzzy candidate; the second is
        // the exact one. Only one baseline entry exists, so exactly one
        // of them may claim it — and it must be the exact match.
        let fuzzy = finding("app.py", 11, "Something else", VulnClass::Injection);
        let report = report_of(vec![fuzzy, prior]);

        let cmp = compare(&report.findings, &baseline, dir.path(), 3);
        assert_eq!(
            cmp.states,
            vec![BaselineState::New, BaselineState::Unchanged]
        );
    }

    /// v2 hashes the on-disk text of the line range, so an identical
    /// report against a tree whose code has changed at those lines loses
    /// the v2 match — and falls through to v1, which still holds.
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
        let cmp = compare(&report_of(vec![f]).findings, &baseline, dir.path(), 3);
        assert_eq!(cmp.states, vec![BaselineState::Unchanged]);
    }

    #[test]
    fn a_sarif_baseline_is_recognized_and_carries_its_prior_results() {
        let dir = tempfile::tempdir().unwrap();
        let report = report_of(vec![finding("app.py", 10, "SQLi", VulnClass::Injection)]);
        let doc = bc_sarif::build_sarif(&report, "test");
        let path = dir.path().join("prior.sarif");
        std::fs::write(&path, serde_json::to_string_pretty(&doc).unwrap()).unwrap();

        let baseline = load(&path, dir.path()).unwrap();
        assert!(baseline.from_sarif);
        assert_eq!(baseline.findings.len(), 1);
        assert!(baseline.findings[0].sarif.is_some());
        assert_eq!(baseline.findings[0].file, "app.py");
        assert_eq!(baseline.findings[0].vuln_class, "injection");

        let cmp = compare(&report.findings, &baseline, dir.path(), 3);
        assert_eq!(cmp.states, vec![BaselineState::Unchanged]);
    }

    #[test]
    fn a_sarif_result_without_a_fingerprint_still_loads_and_can_match_fuzzily() {
        let dir = tempfile::tempdir().unwrap();
        let prior = report_of(vec![finding("app.py", 10, "SQLi", VulnClass::Injection)]);
        let mut doc = serde_json::to_value(bc_sarif::build_sarif(&prior, "test")).unwrap();
        // An older document, or one whose fingerprints were stripped: no
        // key of ours to match on, so only the fuzzy pass is left.
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
        let cmp = compare(&report.findings, &baseline, dir.path(), 3);
        assert_eq!(cmp.states, vec![BaselineState::Unchanged]);
    }

    /// A SARIF document from a different scanner does not parse into
    /// `bc_sarif`'s strict types — refused outright rather than
    /// half-read, since dropping the results it could not decode would
    /// report them as newly introduced.
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

        let cmp = compare(&report.findings, &baseline, dir.path(), 3);
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
            serde_json::to_string_pretty(&bc_sarif::build_sarif(&prior, "test")).unwrap(),
        )
        .unwrap();
        let baseline = load(&prior_path, dir.path()).unwrap();

        let current = report_of(vec![
            finding("kept.py", 1, "Kept", VulnClass::Injection),
            finding("fresh.py", 3, "Fresh", VulnClass::LogicFlaw),
        ]);
        let sarif = serde_json::to_string_pretty(&bc_sarif::build_sarif(&current, "test")).unwrap();
        let cmp = compare(&current.findings, &baseline, dir.path(), 3);

        let annotated = annotate_sarif(&sarif, &cmp);
        let doc: serde_json::Value = serde_json::from_str(&annotated).unwrap();
        let results = doc["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 3, "two current + one absent");
        assert_eq!(results[0]["baselineState"], "unchanged");
        assert_eq!(results[1]["baselineState"], "new");
        assert_eq!(results[2]["baselineState"], "absent");
        assert_eq!(results[2]["message"]["text"], "Gone");
    }

    /// A findings-JSON baseline now yields real `absent` results too —
    /// with a `level` and `rank` genuinely derived from the exported
    /// record, so Code Scanning can close the resolved alert.
    #[test]
    fn annotate_sarif_appends_absent_results_for_a_findings_json_baseline() {
        let dir = tempfile::tempdir().unwrap();
        let mut gone = finding("gone.py", 2, "Gone", VulnClass::Other);
        gone.cvss_score = Some(9.8);
        gone.cvss_rating = Some("Critical".to_string());
        let path = write_findings_baseline(dir.path(), std::slice::from_ref(&gone));
        let baseline = load(&path, dir.path()).unwrap();
        let current = report_of(vec![finding("fresh.py", 3, "Fresh", VulnClass::LogicFlaw)]);
        let sarif = serde_json::to_string_pretty(&bc_sarif::build_sarif(&current, "test")).unwrap();
        let cmp = compare(&current.findings, &baseline, dir.path(), 3);

        let doc: serde_json::Value = serde_json::from_str(&annotate_sarif(&sarif, &cmp)).unwrap();
        let results = doc["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 2, "one current + one absent");
        assert_eq!(results[0]["baselineState"], "new");
        assert_eq!(results[1]["baselineState"], "absent");
        assert_eq!(results[1]["message"]["text"], "Gone");
        // Derived from the export's own CVSS data, not fabricated: a
        // 9.8 is `error`/rank 98, and the `Critical` band is the
        // severity S8 assigned.
        assert_eq!(results[1]["level"], "error");
        assert_eq!(results[1]["rank"], 98.0);
        assert_eq!(results[1]["properties"]["severity"], "critical");
        assert_eq!(results[1]["properties"]["cvssRating"], "Critical");
        assert_eq!(results[1]["ruleId"], "other");
        // The v1 fingerprint is what a consumer matches an already-open
        // alert on, so a resolved one must carry the same key it was
        // first posted under.
        assert_eq!(
            results[1]["partialFingerprints"][bc_sarif::FINGERPRINT_KEY],
            bc_sarif::finding_id(&gone)
        );
    }

    /// Without any CVSS data the export still reconstructs a coherent
    /// result — `Severity::Info`'s fallback band, no `rank` at all —
    /// rather than claiming a severity it doesn't know.
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

    /// An entry carrying neither source shape is unreachable through
    /// `load`, but the projection `compare` builds internally has both
    /// `None` — proving it yields nothing rather than a half-built
    /// result keeps that invariant honest.
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
        let sarif = serde_json::to_string_pretty(&bc_sarif::build_sarif(&current, "test")).unwrap();

        // Unparseable input.
        assert_eq!(
            annotate_sarif("not json", &Comparison::default()),
            "not json"
        );
        // Fewer states than results.
        assert_eq!(annotate_sarif(&sarif, &Comparison::default()), sarif);
        // More states than results.
        let too_many = Comparison {
            states: vec![BaselineState::New; 2],
            absent: Vec::new(),
        };
        assert_eq!(annotate_sarif(&sarif, &too_many), sarif);
        let _ = dir;
    }
}
