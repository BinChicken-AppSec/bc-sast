use std::collections::{BTreeMap, BTreeSet};

use appsec_model::{ContextPackage, FileDisposition, TaskManifest};
use appsec_stage_s3::CatchallSkip;
use appsec_stage_s4::ChunkOutcome;

pub(crate) fn file_dispositions(
    ctx: &ContextPackage,
    manifest: &TaskManifest,
    chunk_outcomes: &BTreeMap<String, ChunkOutcome>,
) -> BTreeMap<String, FileDisposition> {
    let mut best: BTreeMap<&str, FileDisposition> = BTreeMap::new();
    for chunk in &manifest.chunks {
        let from_chunk = match chunk_outcomes.get(&chunk.id) {
            Some(ChunkOutcome::Completed) => FileDisposition::Reviewed,
            Some(ChunkOutcome::Skipped) => FileDisposition::BudgetSkipped,
            Some(ChunkOutcome::Guardrail) => FileDisposition::ChunkGuardrailed,
            Some(ChunkOutcome::Error) => FileDisposition::ChunkFailed,
            None => FileDisposition::ChunkFailed,
        };
        for file in &chunk.files {
            let slot = best.entry(file.as_str()).or_insert(from_chunk);
            if chunk_rank(from_chunk) < chunk_rank(*slot) {
                *slot = from_chunk;
            }
        }
    }

    let unreachable: BTreeSet<&str> = manifest
        .unreachable_files
        .iter()
        .map(String::as_str)
        .collect();

    ctx.all_files
        .iter()
        .map(|file| {
            let disposition = best.get(file.as_str()).copied().unwrap_or_else(|| {
                if unreachable.contains(file.as_str()) {
                    FileDisposition::Unreachable
                } else if ctx.diff_scope_active && !ctx.changed_files.contains_key(file) {
                    FileDisposition::OutOfDiffScope
                } else {
                    match appsec_stage_s3::catchall_skip_reason(file) {
                        Some(CatchallSkip::Name) => FileDisposition::NotEligibleName,
                        Some(CatchallSkip::Extension) => FileDisposition::NotEligibleExtension,
                        Some(CatchallSkip::Directory) => FileDisposition::NotEligibleDirectory,
                        None => FileDisposition::Unchunked,
                    }
                }
            });
            (file.clone(), disposition)
        })
        .collect()
}

fn chunk_rank(d: FileDisposition) -> u8 {
    match d {
        FileDisposition::Reviewed => 0,
        FileDisposition::BudgetSkipped => 1,
        FileDisposition::ChunkGuardrailed => 2,
        _ => 3,
    }
}

pub(crate) fn counts(dispositions: &BTreeMap<String, FileDisposition>) -> BTreeMap<String, i64> {
    let mut out: BTreeMap<String, i64> = BTreeMap::new();
    for d in dispositions.values() {
        *out.entry(d.as_str().to_string()).or_insert(0) += 1;
    }
    out
}

pub(crate) fn not_reviewed(
    dispositions: &BTreeMap<String, FileDisposition>,
) -> BTreeMap<String, FileDisposition> {
    dispositions
        .iter()
        .filter(|(_, d)| !d.reviewed() && **d != FileDisposition::OutOfDiffScope)
        .map(|(f, d)| (f.clone(), *d))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use appsec_model::{Chunk, ChunkSize};

    fn chunk(id: &str, files: &[&str]) -> Chunk {
        Chunk {
            id: id.to_string(),
            size: ChunkSize::Small,
            risk_rank: 1,
            files: files.iter().map(|f| f.to_string()).collect(),
            focus_entry_points: Vec::new(),
            hypothesis: String::new(),
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

    fn ctx(files: &[&str]) -> ContextPackage {
        ContextPackage {
            all_files: files.iter().map(|f| f.to_string()).collect(),
            ..Default::default()
        }
    }

    fn manifest(chunks: Vec<Chunk>, unreachable: &[&str]) -> TaskManifest {
        TaskManifest {
            chunks,
            rationale: String::new(),
            unreachable_files: unreachable.iter().map(|f| f.to_string()).collect(),
        }
    }

    fn outcomes(pairs: &[(&str, ChunkOutcome)]) -> BTreeMap<String, ChunkOutcome> {
        pairs.iter().map(|(id, o)| (id.to_string(), *o)).collect()
    }

    #[test]
    fn reviewed_wins_over_every_failure_that_claimed_the_same_file() {
        let d = file_dispositions(
            &ctx(&["app.py"]),
            &manifest(
                vec![
                    chunk("risk-001", &["app.py"]),
                    chunk("specialist-002", &["app.py"]),
                    chunk("catchall-003", &["app.py"]),
                ],
                &[],
            ),
            &outcomes(&[
                ("risk-001", ChunkOutcome::Error),
                ("specialist-002", ChunkOutcome::Completed),
                ("catchall-003", ChunkOutcome::Skipped),
            ]),
        );
        assert_eq!(d["app.py"], FileDisposition::Reviewed);
    }

    #[test]
    fn among_failures_the_most_actionable_explanation_wins() {
        let d = file_dispositions(
            &ctx(&["a.py", "b.py"]),
            &manifest(
                vec![
                    chunk("risk-001", &["a.py", "b.py"]),
                    chunk("risk-002", &["a.py"]),
                    chunk("risk-003", &["b.py"]),
                ],
                &[],
            ),
            &outcomes(&[
                ("risk-001", ChunkOutcome::Error),
                ("risk-002", ChunkOutcome::Skipped),
                ("risk-003", ChunkOutcome::Guardrail),
            ]),
        );
        assert_eq!(d["a.py"], FileDisposition::BudgetSkipped);
        assert_eq!(d["b.py"], FileDisposition::ChunkGuardrailed);
    }

    #[test]
    fn a_chunk_with_no_recorded_outcome_did_not_review_its_files() {
        let d = file_dispositions(
            &ctx(&["app.py"]),
            &manifest(vec![chunk("risk-001", &["app.py"])], &[]),
            &BTreeMap::new(),
        );
        assert_eq!(d["app.py"], FileDisposition::ChunkFailed);
    }

    #[test]
    fn the_catchall_ineligibility_rule_is_named_rather_than_lumped() {
        let d = file_dispositions(
            &ctx(&["README", "guide.md", "app/samples/handler.py"]),
            &manifest(Vec::new(), &[]),
            &BTreeMap::new(),
        );
        assert_eq!(d["README"], FileDisposition::NotEligibleName);
        assert_eq!(d["guide.md"], FileDisposition::NotEligibleExtension);
        assert_eq!(
            d["app/samples/handler.py"],
            FileDisposition::NotEligibleDirectory
        );
    }

    #[test]
    fn the_reachable_only_gate_is_reported_as_unreachable() {
        let d = file_dispositions(
            &ctx(&["lib.py"]),
            &manifest(Vec::new(), &["lib.py"]),
            &BTreeMap::new(),
        );
        assert_eq!(d["lib.py"], FileDisposition::Unreachable);
    }

    #[test]
    fn out_of_diff_scope_outranks_a_permanent_ineligibility() {
        let mut c = ctx(&["changed.py", "untouched.py", "guide.md"]);
        c.diff_scope_active = true;
        c.changed_files
            .insert("changed.py".to_string(), Default::default());
        let d = file_dispositions(
            &c,
            &manifest(vec![chunk("risk-001", &["changed.py"])], &[]),
            &outcomes(&[("risk-001", ChunkOutcome::Completed)]),
        );
        assert_eq!(d["changed.py"], FileDisposition::Reviewed);
        assert_eq!(d["untouched.py"], FileDisposition::OutOfDiffScope);
        assert_eq!(d["guide.md"], FileDisposition::OutOfDiffScope);
    }

    #[test]
    fn an_eligible_file_in_no_chunk_is_flagged_as_a_scanner_defect() {
        let d = file_dispositions(
            &ctx(&["orphan.py"]),
            &manifest(Vec::new(), &[]),
            &BTreeMap::new(),
        );
        assert_eq!(d["orphan.py"], FileDisposition::Unchunked);
        assert_eq!(counts(&d)["unchunked"], 1);
    }

    #[test]
    fn the_scope_is_partitioned_exactly_and_the_counts_sum_to_it() {
        let files = [
            "app.py",
            "lib.py",
            "README",
            "guide.md",
            "docs/x.py",
            "orphan.py",
            "failed.py",
        ];
        let d = file_dispositions(
            &ctx(&files),
            &manifest(
                vec![
                    chunk("risk-001", &["app.py"]),
                    chunk("risk-002", &["failed.py"]),
                ],
                &["lib.py"],
            ),
            &outcomes(&[
                ("risk-001", ChunkOutcome::Completed),
                ("risk-002", ChunkOutcome::Error),
            ]),
        );
        assert_eq!(d.len(), files.len());
        for f in files {
            assert!(d.contains_key(f), "{f} has no disposition");
        }
        assert_eq!(
            counts(&d).values().sum::<i64>(),
            files.len() as i64,
            "counts must sum to the scope"
        );
    }

    #[test]
    fn not_reviewed_omits_reviewed_files_and_the_diff_scope_bulk() {
        let mut c = ctx(&["changed.py", "untouched.py", "README"]);
        c.diff_scope_active = true;
        c.changed_files
            .insert("changed.py".to_string(), Default::default());
        c.changed_files
            .insert("README".to_string(), Default::default());
        let d = file_dispositions(
            &c,
            &manifest(vec![chunk("risk-001", &["changed.py"])], &[]),
            &outcomes(&[("risk-001", ChunkOutcome::Completed)]),
        );
        let listed = not_reviewed(&d);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed["README"], FileDisposition::NotEligibleName);
        assert_eq!(counts(&d)["out_of_diff_scope"], 1);
    }
}
