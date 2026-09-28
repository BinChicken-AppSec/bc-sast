//! `--repo-file` batch-scan mode: a deliberately SCOPED, MINIMAL stub of
//! Python's `orchestrator/batch.py` (~688 lines) — not a full port. Loops
//! the exact same single-repo scan path this crate already uses
//! ([`crate::run`]/[`crate::build_scan_config`]/[`crate::build_scan_input`])
//! once per manifest entry, in sequence, matching Python's own ungrouped
//! batch loop (`run_batch`, `batch.py:461-527`): each entry is a fully
//! independent, isolated scan (no shared findings/call-graph context
//! across repos), and one entry's failure is recorded and skipped rather
//! than aborting the whole batch.
//!
//! **Deliberately NOT ported** (see the tracked follow-up task for the
//! full-parity version):
//! - `--group-by-app` — Python's version is a genuine scan-SCOPE change
//!   (every repo sharing an app id is staged under one directory and
//!   scanned as a single combined tree, so cross-repo call-graph edges
//!   are visible), not just a reporting grouping. Approximating that by
//!   merely grouping separate per-repo reports afterward would silently
//!   misrepresent what Python's flag actually does, so it's left
//!   unimplemented rather than faked.
//! - Deriving a clone URL from a blank `Path`/`url` cell via
//!   `batch.git_base_url` — both manifest shapes still require that
//!   column outright (see `crate::clone`'s own module doc comment).
//!
//! `--remediate` (task #151) IS forwarded per entry — `run_one_entry`
//! builds a [`RemediateRun`] from `entry_cli` exactly like `main_impl`'s
//! single-repo path does, so `--remediate`/`--top`/`--interactive`/
//! `--force`/`--resume`/`--enforce-remediation-policy`/
//! `--remediation-policy`/`--remediation-playbook` all apply to every
//! entry, matching Python's own behavior (`batch.py` passes the same
//! parsed `args` into `scan_repo` that a single-repo run uses, so
//! `--remediate` was never actually excluded there either).
//!
//! `--baseline` is PER ENTRY, not per batch: the manifest carries an
//! optional baseline field (a 4th `.txt` comma field, a `baseline` column
//! in a `.csv`), and the top-level `--baseline` flag is refused outright
//! alongside `--repo-file` — see [`run_batch`]'s own refusal for why one
//! file cannot classify several repositories' scans. Net-new versus
//! Python, which has no baseline mode at all.
//!
//! Remote git-URL cloning (task #150) IS supported: a manifest `path`/
//! `Path` cell that looks like a git URL (see `crate::clone::is_remote`)
//! is cloned into `--workspace` rather than resolved as a local
//! directory — see `crate::clone`'s own module doc comment for the full
//! `--workspace`/`--keep-clones`/`--git-token` story.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bc_llm_client::{LlmClient, ToolExecutor};
use bc_sandbox_tools::SandboxTools;

use crate::{
    build_github_client, build_llm_client, build_scan_config, build_scan_input,
    load_compliance_policies, open_checkpoint_store, parse_stop_after, resolve_output_paths,
    run_with_publication, stringify, Cli, ScanSummary, StopAfter,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestEntry {
    pub app_id: String,
    pub repo_name: String,
    pub path: PathBuf,
    /// This entry's own `--baseline` (task: batch baseline support),
    /// already resolved to a path that exists — see
    /// [`resolve_entry_baseline`]. `None` when the manifest gave none,
    /// which is every pre-existing manifest: the column/field is
    /// optional precisely so an older manifest keeps parsing unchanged.
    ///
    /// Per-entry rather than one top-level `--baseline` because a
    /// baseline IS one repository's prior findings — see
    /// [`run_batch`]'s own refusal of the top-level flag.
    pub baseline: Option<PathBuf>,
}

/// Resolves and validates one manifest entry's optional baseline cell.
///
/// A RELATIVE path resolves against the MANIFEST's own directory, not the
/// process's working directory: a manifest is a checked-in artifact that
/// names files sitting beside it, and resolving against the cwd would
/// make the same manifest mean different things depending on where the
/// batch happened to be launched from. An absolute path is taken as-is.
///
/// Existence is checked HERE, at parse time, for the same reason every
/// other cell is: an unusable baseline is a hard error in single-repo
/// mode (see `crate::baseline::load`), and discovering that only after
/// the manifest's earlier repos have already been scanned would waste
/// every one of those scans. Only existence is checked, not
/// parseability — `baseline::load` also needs the repo root (for v2
/// fingerprints), and a remote entry has no local repo root until it is
/// cloned, so the full load stays in [`run_one_entry`].
fn resolve_entry_baseline(
    cell: &str,
    manifest_path: &Path,
    lineno: usize,
) -> Result<Option<PathBuf>, String> {
    let cell = cell.trim();
    if cell.is_empty() {
        return Ok(None);
    }
    let raw = Path::new(cell);
    let resolved = match manifest_path.parent() {
        Some(dir) if !raw.is_absolute() && !dir.as_os_str().is_empty() => dir.join(raw),
        _ => raw.to_path_buf(),
    };
    if !resolved.is_file() {
        return Err(format!(
            "{}:{lineno}: baseline {cell:?} is not an existing file (resolved to {})",
            manifest_path.display(),
            resolved.display()
        ));
    }
    Ok(Some(resolved))
}

/// Parses the `.txt` manifest shape (`application_id,repository_name,
/// path[,baseline]` — one per line, blank lines and `#`-prefixed comments
/// skipped). `path` is either a git URL (see [`crate::clone::is_remote`],
/// resolved later by [`run_one_entry`]) or an EXISTING LOCAL DIRECTORY,
/// checked here so a bad line fails the whole batch before any scan
/// starts — matching `_parse_repo_file`.
///
/// The 4th `baseline` field is OPTIONAL and net-new versus Python (which
/// has no baseline mode at all): a 3-field line is exactly as valid as it
/// has always been, so existing manifests are unaffected.
pub fn parse_manifest_file(path: &Path) -> Result<Vec<ManifestEntry>, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read batch manifest {}: {e}", path.display()))?;

    let mut entries = Vec::new();
    let mut seen_paths: HashSet<PathBuf> = HashSet::new();
    for (idx, raw_line) in text.lines().enumerate() {
        let lineno = idx + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split(',').map(str::trim).collect();
        let (app_id, repo_name, entry_path, baseline_cell) = match fields.as_slice() {
            [app_id, repo_name, entry_path] => (*app_id, *repo_name, *entry_path, ""),
            [app_id, repo_name, entry_path, baseline] => {
                (*app_id, *repo_name, *entry_path, *baseline)
            }
            _ => {
                return Err(format!(
                    "{}:{lineno}: expected 'application_id,repository_name,path[,baseline]', \
                     got {line:?}",
                    path.display()
                ))
            }
        };
        if app_id.is_empty() || repo_name.is_empty() || entry_path.is_empty() {
            return Err(format!(
                "{}:{lineno}: application_id/repository_name/path must all be non-empty",
                path.display()
            ));
        }
        if !crate::clone::is_remote(entry_path) && !Path::new(entry_path).is_dir() {
            return Err(format!(
                "{}:{lineno}: {entry_path:?} is not an existing local directory",
                path.display()
            ));
        }
        let baseline = resolve_entry_baseline(baseline_cell, path, lineno)?;
        let entry_path = PathBuf::from(entry_path);
        if !seen_paths.insert(entry_path.clone()) {
            return Err(format!(
                "{}:{lineno}: duplicate path {entry_path:?} in manifest",
                path.display()
            ));
        }
        entries.push(ManifestEntry {
            app_id: app_id.to_string(),
            repo_name: repo_name.to_string(),
            path: entry_path,
            baseline,
        });
    }
    if entries.is_empty() {
        return Err(format!("batch manifest {} has no entries", path.display()));
    }
    Ok(entries)
}

/// Dispatches on the manifest file's extension (case-insensitive
/// `.csv` vs anything else), matching Python's own
/// `list_file.suffix.lower() == ".csv"` check in `run_batch`.
fn parse_manifest(path: &Path) -> Result<Vec<ManifestEntry>, String> {
    let is_csv = path
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("csv"));
    if is_csv {
        parse_manifest_csv(path)
    } else {
        parse_manifest_file(path)
    }
}

fn csv_col(hdr: &std::collections::HashMap<String, usize>, names: &[&str]) -> Option<usize> {
    names.iter().find_map(|n| hdr.get(*n).copied())
}

/// Parses the `.csv` manifest shape (task #148): a required header row,
/// case-insensitively aliased (`AppID`/`application_id`/`app_id`/
/// `applicationid`; `RepoName`/`repository_name`/`repo_name`/`repo`;
/// `Path`/`url`/`repo_url`/`ref`; the OPTIONAL `baseline`/`baseline_path`/
/// `baseline_file`), then one data row per repo. Ported
/// from `_parse_repo_csv`'s header-aliasing and row validation, but —
/// like [`parse_manifest_file`] — the `Path`/`url` column is always
/// required: Python can leave it blank and derive a clone URL from
/// `batch.git_base_url`, but this port has no `git_base_url` config to
/// resolve a blank cell against (see `crate::clone`'s own module doc
/// comment), so accepting one here would only defer an error to clone
/// time that's already knowable at parse time. A non-blank cell is
/// either a git URL (resolved later by [`run_one_entry`]) or an
/// EXISTING LOCAL DIRECTORY, checked here.
fn parse_manifest_csv(path: &Path) -> Result<Vec<ManifestEntry>, String> {
    let bytes = std::fs::read(path)
        .map_err(|e| format!("failed to read batch manifest {}: {e}", path.display()))?;
    let text = String::from_utf8_lossy(&bytes);
    let text = text.strip_prefix('\u{FEFF}').unwrap_or(&text);
    let mut rows = crate::csv_parse::parse_csv(text).into_iter();

    let Some(header) = rows.next() else {
        return Err(format!("batch manifest {} is empty", path.display()));
    };
    let hdr: std::collections::HashMap<String, usize> = header
        .iter()
        .enumerate()
        .filter(|(_, h)| !h.trim().is_empty())
        .map(|(i, h)| (h.trim().to_lowercase(), i))
        .collect();
    let i_app = csv_col(
        &hdr,
        &["appid", "application_id", "app_id", "applicationid"],
    );
    let i_repo = csv_col(&hdr, &["reponame", "repository_name", "repo_name", "repo"]);
    let i_path = csv_col(&hdr, &["path", "url", "repo_url", "ref"]);
    // Optional: a manifest with no baseline column is exactly as valid as
    // it was before this column existed, so `None` here is not an error.
    let i_baseline = csv_col(&hdr, &["baseline", "baseline_path", "baseline_file"]);
    let (Some(i_app), Some(i_repo)) = (i_app, i_repo) else {
        return Err(format!(
            "batch manifest {}: header must contain AppID and RepoName columns (found: {:?})",
            path.display(),
            {
                let mut names: Vec<&str> = hdr.keys().map(String::as_str).collect();
                names.sort_unstable();
                names
            }
        ));
    };
    let Some(i_path) = i_path else {
        return Err(format!(
            "batch manifest {}: header must contain a Path or url column — this batch-mode \
             stub cannot derive a clone URL from a bare AppID/RepoName row",
            path.display()
        ));
    };

    let at = |row: &[String], i: usize| row.get(i).map(|s| s.trim().to_string());

    let mut entries = Vec::new();
    let mut seen_paths: HashSet<PathBuf> = HashSet::new();
    for (idx, row) in rows.enumerate() {
        let lineno = idx + 2; // 1-indexed, plus the header row.
        let app_id = at(&row, i_app).unwrap_or_default();
        let repo_name = at(&row, i_repo).unwrap_or_default();
        let entry_path = at(&row, i_path).unwrap_or_default();
        let baseline_cell = i_baseline.and_then(|i| at(&row, i)).unwrap_or_default();
        if app_id.is_empty() && repo_name.is_empty() && entry_path.is_empty() {
            continue;
        }
        if app_id.is_empty() || repo_name.is_empty() {
            return Err(format!(
                "{}:{lineno}: AppID and RepoName are both required",
                path.display()
            ));
        }
        if entry_path.is_empty() {
            return Err(format!(
                "{}:{lineno}: Path is blank — this batch-mode stub cannot derive a clone URL",
                path.display()
            ));
        }
        if !crate::clone::is_remote(&entry_path) && !Path::new(&entry_path).is_dir() {
            return Err(format!(
                "{}:{lineno}: {entry_path:?} is not an existing local directory",
                path.display()
            ));
        }
        let baseline = resolve_entry_baseline(&baseline_cell, path, lineno)?;
        let entry_path = PathBuf::from(&entry_path);
        if !seen_paths.insert(entry_path.clone()) {
            return Err(format!(
                "{}:{lineno}: duplicate path {entry_path:?} in manifest",
                path.display()
            ));
        }
        entries.push(ManifestEntry {
            app_id,
            repo_name,
            path: entry_path,
            baseline,
        });
    }
    if entries.is_empty() {
        return Err(format!("batch manifest {} has no entries", path.display()));
    }
    Ok(entries)
}

#[derive(Debug, Clone, PartialEq)]
enum EntryStatus {
    Completed {
        findings: usize,
        /// This entry's `--baseline` counts, when the manifest gave it a
        /// baseline and the scan reached a `FinalReport`.
        baseline: Option<crate::BaselineTally>,
    },
    Failed {
        error: String,
    },
}

#[derive(Debug, Clone, PartialEq)]
struct EntryResult {
    entry: ManifestEntry,
    status: EntryStatus,
    report_path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchSummary {
    pub total: usize,
    pub completed: usize,
    pub failed: usize,
    pub summary_path: PathBuf,
}

/// Runs one independent scan per manifest entry, in sequence, then writes
/// `--out-batch-summary` (default `./batch_summary.md`).
pub async fn run_batch(cli: &Cli, manifest_path: &Path) -> Result<BatchSummary, String> {
    // A baseline is ONE repository's prior findings. Applied to a second
    // repository it would classify every one of that repo's findings as
    // `new` and every one of the baseline's as `resolved` — a confidently
    // wrong answer, which is worse than no answer, and exactly what a PR
    // gate reading these counts would act on. There is no sensible
    // whole-batch semantic to fall back on, so this is refused outright
    // and the per-entry column is pointed at instead.
    if cli.baseline.is_some() {
        return Err(
            "--baseline cannot be combined with --repo-file: a baseline is a single \
             repository's prior findings, so one file cannot classify several repositories' \
             scans. Give each manifest entry its own baseline instead — a 4th comma field in \
             a `.txt` manifest, or a `baseline` column in a `.csv` one."
                .to_string(),
        );
    }
    let entries = parse_manifest(manifest_path)?;
    // The gateway/GitHub config doesn't vary per repo, only `--repo`/
    // `--repo-name`/`--app-id` (and the resulting sandbox root) do; `llm`
    // is cheap to clone (an `Arc`), but `bc_github::GithubClient` isn't
    // `Clone`, so it's rebuilt fresh from the same unchanged `cli` each
    // iteration instead — equally cheap (just config), no shared state.
    let llm = build_llm_client(cli)?;

    let mut results = Vec::with_capacity(entries.len());
    for entry in entries {
        let reference = entry.path.to_string_lossy().into_owned();
        let is_remote = crate::clone::is_remote(&reference);
        let resolved = crate::clone::acquire_repo(
            &reference,
            &cli.workspace,
            &entry.repo_name,
            cli.git_token.as_deref(),
        )
        .await;
        let resolved_path = match resolved {
            Ok(p) => p,
            Err(error) => {
                results.push(EntryResult {
                    entry,
                    status: EntryStatus::Failed { error },
                    report_path: None,
                });
                continue;
            }
        };

        let mut entry_cli = cli.clone();
        entry_cli.repo = Some(resolved_path.clone());
        entry_cli.repo_file = None;
        entry_cli.repo_name = Some(entry.repo_name.clone());
        entry_cli.app_id = entry.app_id.clone();
        // Always from the manifest, never from the (refused above)
        // top-level flag — so an entry with no baseline column runs with
        // no baseline at all rather than inheriting a neighbor's.
        entry_cli.baseline = entry.baseline.clone();
        // Never reuse a single shared `--out-dir`/`--out-*` override
        // across entries. Every entry falling back to its own
        // `<path>/security-scan/` default is what keeps entries from
        // clobbering each other's output, matching Python's own per-repo
        // report location. It is also what `clone::purge_clone` spares
        // when it deletes a remote entry's source afterwards, so an
        // entry whose reports were redirected elsewhere would have them
        // deleted along with the clone.
        entry_cli.out_dir = None;
        entry_cli.out_md = None;
        entry_cli.out_sarif = None;
        entry_cli.out_csv = None;
        entry_cli.out_findings_json = None;
        entry_cli.out_remediation_json = None;

        // Gated through the same `--pr-comments` opt-in the single-repo
        // path uses, so a batch cannot post what a single scan would not.
        let github = crate::pr_comment_target(&entry_cli, build_github_client(&entry_cli)?);
        let outcome = run_one_entry(&entry_cli, &resolved_path, llm.clone(), github).await;
        // A cloned repo's source is deleted after the scan (the
        // `security-scan/` output survives) unless `--keep-clones` was
        // passed — a local (non-remote) manifest entry is never touched.
        if is_remote && !cli.keep_clones {
            crate::clone::purge_clone(&resolved_path, crate::clone::CLONE_KEEP_DEFAULT);
        }
        let (status, report_path) = match outcome {
            Ok(summary) => (
                EntryStatus::Completed {
                    findings: summary.findings,
                    baseline: summary.baseline,
                },
                summary.markdown_path,
            ),
            Err(error) => (EntryStatus::Failed { error }, None),
        };
        results.push(EntryResult {
            entry,
            status,
            report_path,
        });
    }

    let summary_path = cli
        .out_batch_summary
        .clone()
        .unwrap_or_else(|| PathBuf::from("batch_summary.md"));
    write_batch_summary(&summary_path, &results)?;

    let completed = results
        .iter()
        .filter(|r| matches!(r.status, EntryStatus::Completed { .. }))
        .count();
    Ok(BatchSummary {
        total: results.len(),
        completed,
        failed: results.len() - completed,
        summary_path,
    })
}

/// One entry's scan — the same [`crate::run`] path a single `--repo`
/// invocation takes, given a `Cli` whose `repo`/`repo_name`/`app_id` have
/// already been overridden for this entry, and `resolved_path` (the
/// entry's manifest `path` after [`crate::clone::acquire_repo`] — a
/// no-op for an already-local entry, an actual clone destination for a
/// remote one). A failure here is caught by the caller and recorded, not
/// propagated — one bad repo must never abort the rest of the batch.
/// `--remediate` (and everything it implies — `--top`, `--interactive`,
/// `--force`, `--resume`, `--enforce-remediation-policy`,
/// `--remediation-policy`/`-playbook`) is forwarded per entry exactly as
/// `main_impl`'s own single-repo path builds it — `entry_cli` already
/// carries these unchanged from the top-level `Cli` (Python's own
/// `batch.py` does the same: `args` is the one parsed namespace shared
/// by both the single-repo and batch code paths, so `--remediate
/// --interactive` prompts once per repo there too, not just here).
async fn run_one_entry(
    entry_cli: &Cli,
    resolved_path: &Path,
    llm: Arc<dyn LlmClient>,
    github: Option<bc_github::GithubClient>,
) -> Result<ScanSummary, String> {
    crate::check_automatic_publication_mode(entry_cli)?;
    let publication = crate::provider_publish::automatic::configure(entry_cli)?;
    let tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new(resolved_path.to_path_buf()));
    let mut config = build_scan_config(entry_cli)?;
    crate::autoexclude::maybe_apply(entry_cli, &llm, resolved_path, &mut config).await;
    config.checkpoint = open_checkpoint_store();
    let mut input = build_scan_input(entry_cli);
    input.compliance = load_compliance_policies(entry_cli)?;
    let stop_after = parse_stop_after(&entry_cli.stop_after)?.map(StopAfter::from);
    // Every report, including this entry's own `findings.json`. The
    // single-repo path writes all four unconditionally, and a batch
    // entry is the same scan with a different repo, so it writes the
    // same set into its own `<path>/security-scan/`.
    let paths = resolve_output_paths(entry_cli);
    // Identical to `main_impl`'s own single-repo construction, including
    // the write journal and (for a git entry) the isolated worktree —
    // shared through `build_remediate_run` rather than duplicated, since
    // the journal must come from the same executor instance the agent
    // writes through or every S10 rollback gate silently degrades.
    let remediate = (entry_cli.remediate && stop_after.is_none())
        .then(|| crate::build_remediate_run(entry_cli, resolved_path))
        .transpose()?;

    // This entry's OWN baseline, from the manifest's optional
    // baseline field/column (`entry_cli.baseline` was set from it by
    // `run_batch`). Loaded before the scan, exactly as the single-repo
    // path does: an unusable baseline is a hard error, and finding that
    // out afterwards would waste the scan it was meant to classify —
    // here it fails this entry only, leaving the rest of the batch to
    // run, which is the batch loop's standing contract for a bad entry.
    let baseline = entry_cli
        .baseline
        .as_ref()
        .map(|path| -> Result<crate::BaselineRun, String> {
            Ok(crate::BaselineRun {
                path: path.clone(),
                baseline: crate::baseline::load(path, resolved_path)?,
            })
        })
        .transpose()?;

    run_with_publication(
        input,
        config,
        stop_after,
        &paths,
        llm,
        tools,
        github,
        remediate,
        baseline,
        publication,
    )
    .await
}

/// A `|`/newline-safe cell for the summary's Markdown table — manifest
/// content (app id, repo name) and scan error text both flow into this
/// table, so neither may be trusted to stay on one line or free of the
/// table's own column delimiter.
fn table_cell(text: &str) -> String {
    text.replace(['\r', '\n'], " ").replace('|', "\\|")
}

/// The three baseline columns for one row. A dash — not a zero — when
/// this entry had no baseline: "0 new" and "no comparison was made" are
/// materially different claims, and a zero would read as the first.
fn baseline_cells(status: &EntryStatus) -> [String; 3] {
    let tally = match status {
        EntryStatus::Completed {
            baseline: Some(t), ..
        } => t,
        _ => return ["-".to_string(), "-".to_string(), "-".to_string()],
    };
    [
        tally.new.to_string(),
        tally.unchanged.to_string(),
        tally.resolved.to_string(),
    ]
}

fn write_batch_summary(path: &Path, results: &[EntryResult]) -> Result<(), String> {
    let mut out = vec![
        "# Batch Scan Summary".to_string(),
        String::new(),
        "| # | App ID | Repo | Status | Findings | New | Unchanged | Resolved | Report |"
            .to_string(),
        "| - | ------ | ---- | ------ | -------- | --- | --------- | -------- | ------ |"
            .to_string(),
    ];
    for (i, r) in results.iter().enumerate() {
        let (status, findings) = match &r.status {
            EntryStatus::Completed { findings, .. } => ("OK".to_string(), findings.to_string()),
            EntryStatus::Failed { error } => {
                (format!("FAILED: {}", table_cell(error)), "-".to_string())
            }
        };
        let [new, unchanged, resolved] = baseline_cells(&r.status);
        let report = r
            .report_path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "-".to_string());
        out.push(format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} |",
            i + 1,
            table_cell(&r.entry.app_id),
            table_cell(&r.entry.repo_name),
            status,
            findings,
            new,
            unchanged,
            resolved,
            table_cell(&report),
        ));
    }
    out.push(String::new());

    let failures: Vec<&EntryResult> = results
        .iter()
        .filter(|r| matches!(r.status, EntryStatus::Failed { .. }))
        .collect();
    if !failures.is_empty() {
        out.push("## Failures".to_string());
        out.push(String::new());
        for r in &failures {
            if let EntryStatus::Failed { error } = &r.status {
                out.push(format!(
                    "- **{}** ({}): {}",
                    table_cell(&r.entry.repo_name),
                    table_cell(&r.entry.app_id),
                    error
                ));
            }
        }
        out.push(String::new());
    }

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(stringify)?;
        }
    }
    std::fs::write(path, out.join("\n")).map_err(stringify)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, rel: &str, contents: &str) {
        std::fs::write(dir.join(rel), contents).unwrap();
    }

    // ── parse_manifest_file ──────────────────────────────────────────────

    #[test]
    fn parses_valid_entries_skipping_blank_lines_and_comments() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("repo-a")).unwrap();
        std::fs::create_dir(dir.path().join("repo-b")).unwrap();
        let manifest = dir.path().join("manifest.txt");
        std::fs::write(
            &manifest,
            format!(
                "# a comment\n\napp1,repo-a,{}\napp2,repo-b,{}\n",
                dir.path().join("repo-a").display(),
                dir.path().join("repo-b").display(),
            ),
        )
        .unwrap();
        let entries = parse_manifest_file(&manifest).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].app_id, "app1");
        assert_eq!(entries[0].repo_name, "repo-a");
        assert_eq!(entries[1].app_id, "app2");
    }

    #[test]
    fn missing_manifest_file_is_an_error() {
        let err = parse_manifest_file(Path::new("/nonexistent/manifest.txt")).unwrap_err();
        assert!(err.contains("failed to read batch manifest"));
    }

    #[test]
    fn empty_manifest_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("manifest.txt");
        write(dir.path(), "manifest.txt", "# only comments\n\n");
        let err = parse_manifest_file(&manifest).unwrap_err();
        assert!(err.contains("no entries"));
    }

    #[test]
    fn wrong_field_count_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("manifest.txt");
        write(dir.path(), "manifest.txt", "app1,repo-a\n");
        let err = parse_manifest_file(&manifest).unwrap_err();
        assert!(err.contains("expected 'application_id,repository_name,path[,baseline]'"));
    }

    #[test]
    fn an_empty_field_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("repo-a")).unwrap();
        let manifest = dir.path().join("manifest.txt");
        write(
            dir.path(),
            "manifest.txt",
            &format!(",repo-a,{}\n", dir.path().join("repo-a").display()),
        );
        let err = parse_manifest_file(&manifest).unwrap_err();
        assert!(err.contains("must all be non-empty"));
    }

    #[test]
    fn a_missing_local_path_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("manifest.txt");
        write(
            dir.path(),
            "manifest.txt",
            "app1,repo-a,/nonexistent/local/path\n",
        );
        let err = parse_manifest_file(&manifest).unwrap_err();
        assert!(err.contains("not an existing local directory"));
    }

    #[test]
    fn a_git_url_is_accepted_at_parse_time_and_resolved_later() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("manifest.txt");
        write(
            dir.path(),
            "manifest.txt",
            "app1,repo-a,https://example.com/repo-a.git\n",
        );
        let entries = parse_manifest_file(&manifest).unwrap();
        assert_eq!(entries[0].path, Path::new("https://example.com/repo-a.git"));
    }

    #[test]
    fn a_duplicate_path_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("repo-a")).unwrap();
        let manifest = dir.path().join("manifest.txt");
        let p = dir.path().join("repo-a").display().to_string();
        write(
            dir.path(),
            "manifest.txt",
            &format!("app1,repo-a,{p}\napp2,repo-a-again,{p}\n"),
        );
        let err = parse_manifest_file(&manifest).unwrap_err();
        assert!(err.contains("duplicate path"));
    }

    #[test]
    fn whitespace_around_fields_is_trimmed() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("repo-a")).unwrap();
        let manifest = dir.path().join("manifest.txt");
        write(
            dir.path(),
            "manifest.txt",
            &format!(
                " app1 , repo-a , {} \n",
                dir.path().join("repo-a").display()
            ),
        );
        let entries = parse_manifest_file(&manifest).unwrap();
        assert_eq!(entries[0].app_id, "app1");
        assert_eq!(entries[0].repo_name, "repo-a");
    }

    // ── the optional per-entry baseline (txt) ────────────────────────────

    /// Writes a minimal findings-export baseline next to the manifest.
    fn write_baseline(dir: &Path, rel: &str) -> PathBuf {
        let path = dir.join(rel);
        std::fs::write(&path, r#"{"commit_sha": "abc", "findings": []}"#).unwrap();
        path
    }

    #[test]
    fn a_three_field_line_still_parses_with_no_baseline() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("repo-a")).unwrap();
        let manifest = dir.path().join("manifest.txt");
        write(
            dir.path(),
            "manifest.txt",
            &format!("app1,repo-a,{}\n", dir.path().join("repo-a").display()),
        );
        let entries = parse_manifest_file(&manifest).unwrap();
        assert_eq!(entries[0].baseline, None);
    }

    #[test]
    fn a_fourth_field_is_taken_as_this_entrys_baseline() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("repo-a")).unwrap();
        let baseline = write_baseline(dir.path(), "base.json");
        let manifest = dir.path().join("manifest.txt");
        write(
            dir.path(),
            "manifest.txt",
            &format!(
                "app1,repo-a,{},{}\n",
                dir.path().join("repo-a").display(),
                baseline.display()
            ),
        );
        let entries = parse_manifest_file(&manifest).unwrap();
        assert_eq!(entries[0].baseline.as_deref(), Some(baseline.as_path()));
    }

    #[test]
    fn a_relative_baseline_resolves_against_the_manifests_own_directory() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("repo-a")).unwrap();
        write_baseline(dir.path(), "base.json");
        let manifest = dir.path().join("manifest.txt");
        write(
            dir.path(),
            "manifest.txt",
            &format!(
                "app1,repo-a,{},base.json\n",
                dir.path().join("repo-a").display()
            ),
        );
        let entries = parse_manifest_file(&manifest).unwrap();
        assert_eq!(
            entries[0].baseline,
            Some(dir.path().join("base.json")),
            "a relative cell must not resolve against the process cwd"
        );
    }

    #[test]
    fn a_blank_fourth_field_is_the_same_as_omitting_it() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("repo-a")).unwrap();
        let manifest = dir.path().join("manifest.txt");
        write(
            dir.path(),
            "manifest.txt",
            &format!("app1,repo-a,{}, \n", dir.path().join("repo-a").display()),
        );
        let entries = parse_manifest_file(&manifest).unwrap();
        assert_eq!(entries[0].baseline, None);
    }

    #[test]
    fn a_missing_baseline_file_is_rejected_at_parse_time() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("repo-a")).unwrap();
        let manifest = dir.path().join("manifest.txt");
        write(
            dir.path(),
            "manifest.txt",
            &format!(
                "app1,repo-a,{},nope.json\n",
                dir.path().join("repo-a").display()
            ),
        );
        let err = parse_manifest_file(&manifest).unwrap_err();
        assert!(err.contains("is not an existing file"), "{err}");
    }

    #[test]
    fn a_baseline_that_is_a_directory_not_a_file_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("repo-a")).unwrap();
        let manifest = dir.path().join("manifest.txt");
        write(
            dir.path(),
            "manifest.txt",
            &format!(
                "app1,repo-a,{},repo-a\n",
                dir.path().join("repo-a").display()
            ),
        );
        let err = parse_manifest_file(&manifest).unwrap_err();
        assert!(err.contains("is not an existing file"), "{err}");
    }

    #[test]
    fn five_fields_are_still_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("manifest.txt");
        write(dir.path(), "manifest.txt", "a,b,c,d,e\n");
        let err = parse_manifest_file(&manifest).unwrap_err();
        assert!(err.contains("expected 'application_id,repository_name,path[,baseline]'"));
    }

    /// A manifest read through a bare relative filename has no parent
    /// directory component to resolve against — the cell is then used
    /// verbatim rather than being joined onto an empty path.
    #[test]
    fn a_manifest_with_no_directory_component_resolves_the_cell_verbatim() {
        let dir = tempfile::tempdir().unwrap();
        let baseline = write_baseline(dir.path(), "base.json");
        assert_eq!(
            resolve_entry_baseline(
                &baseline.display().to_string(),
                Path::new("manifest.txt"),
                1
            )
            .unwrap(),
            Some(baseline)
        );
    }

    // ── parse_manifest_csv ───────────────────────────────────────────────

    #[test]
    fn csv_parses_valid_rows_with_canonical_headers() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("repo-a")).unwrap();
        std::fs::create_dir(dir.path().join("repo-b")).unwrap();
        let manifest = dir.path().join("manifest.csv");
        std::fs::write(
            &manifest,
            format!(
                "AppID,RepoName,Path\napp1,repo-a,{}\napp2,repo-b,{}\n",
                dir.path().join("repo-a").display(),
                dir.path().join("repo-b").display(),
            ),
        )
        .unwrap();
        let entries = parse_manifest_csv(&manifest).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].app_id, "app1");
        assert_eq!(entries[1].repo_name, "repo-b");
    }

    #[test]
    fn csv_header_aliases_are_case_insensitive() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("repo-a")).unwrap();
        let manifest = dir.path().join("manifest.csv");
        std::fs::write(
            &manifest,
            format!(
                "application_id,repository_name,url\napp1,repo-a,{}\n",
                dir.path().join("repo-a").display(),
            ),
        )
        .unwrap();
        let entries = parse_manifest_csv(&manifest).unwrap();
        assert_eq!(entries[0].app_id, "app1");
    }

    #[test]
    fn csv_a_leading_utf8_bom_is_stripped_before_parsing_the_header() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("repo-a")).unwrap();
        let manifest = dir.path().join("manifest.csv");
        std::fs::write(
            &manifest,
            format!(
                "\u{FEFF}AppID,RepoName,Path\napp1,repo-a,{}\n",
                dir.path().join("repo-a").display(),
            ),
        )
        .unwrap();
        let entries = parse_manifest_csv(&manifest).unwrap();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn csv_blank_rows_between_data_rows_are_skipped() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("repo-a")).unwrap();
        let manifest = dir.path().join("manifest.csv");
        std::fs::write(
            &manifest,
            format!(
                "AppID,RepoName,Path\napp1,repo-a,{}\n\n",
                dir.path().join("repo-a").display(),
            ),
        )
        .unwrap();
        let entries = parse_manifest_csv(&manifest).unwrap();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn csv_missing_appid_or_reponame_column_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("manifest.csv");
        std::fs::write(&manifest, "AppID,Path\napp1,/repo-a\n").unwrap();
        let err = parse_manifest_csv(&manifest).unwrap_err();
        assert!(err.contains("must contain AppID and RepoName columns"));
    }

    #[test]
    fn csv_missing_path_column_is_rejected_since_cloning_is_unsupported() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("manifest.csv");
        std::fs::write(&manifest, "AppID,RepoName\napp1,repo-a\n").unwrap();
        let err = parse_manifest_csv(&manifest).unwrap_err();
        assert!(err.contains("cannot derive a clone URL"));
    }

    #[test]
    fn csv_a_row_missing_reponame_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("manifest.csv");
        std::fs::write(&manifest, "AppID,RepoName,Path\napp1,,/repo-a\n").unwrap();
        let err = parse_manifest_csv(&manifest).unwrap_err();
        assert!(err.contains("AppID and RepoName are both required"));
    }

    #[test]
    fn csv_a_blank_path_cell_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("manifest.csv");
        std::fs::write(&manifest, "AppID,RepoName,Path\napp1,repo-a,\n").unwrap();
        let err = parse_manifest_csv(&manifest).unwrap_err();
        assert!(err.contains("Path is blank"));
    }

    #[test]
    fn csv_a_missing_local_path_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("manifest.csv");
        std::fs::write(
            &manifest,
            "AppID,RepoName,Path\napp1,repo-a,/nonexistent/local/path\n",
        )
        .unwrap();
        let err = parse_manifest_csv(&manifest).unwrap_err();
        assert!(err.contains("not an existing local directory"));
    }

    #[test]
    fn csv_a_git_url_is_accepted_at_parse_time_and_resolved_later() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("manifest.csv");
        std::fs::write(
            &manifest,
            "AppID,RepoName,Path\napp1,repo-a,https://example.com/repo-a.git\n",
        )
        .unwrap();
        let entries = parse_manifest_csv(&manifest).unwrap();
        assert_eq!(entries[0].path, Path::new("https://example.com/repo-a.git"));
    }

    #[test]
    fn csv_a_duplicate_path_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("repo-a")).unwrap();
        let manifest = dir.path().join("manifest.csv");
        let p = dir.path().join("repo-a").display().to_string();
        std::fs::write(
            &manifest,
            format!("AppID,RepoName,Path\napp1,repo-a,{p}\napp2,repo-a-again,{p}\n"),
        )
        .unwrap();
        let err = parse_manifest_csv(&manifest).unwrap_err();
        assert!(err.contains("duplicate path"));
    }

    #[test]
    fn csv_with_only_a_header_row_has_no_entries() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("manifest.csv");
        std::fs::write(&manifest, "AppID,RepoName,Path\n").unwrap();
        let err = parse_manifest_csv(&manifest).unwrap_err();
        assert!(err.contains("has no entries"));
    }

    #[test]
    fn csv_an_empty_file_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("manifest.csv");
        std::fs::write(&manifest, "").unwrap();
        let err = parse_manifest_csv(&manifest).unwrap_err();
        assert!(err.contains("is empty"));
    }

    #[test]
    fn csv_missing_manifest_file_is_an_error() {
        let err = parse_manifest_csv(Path::new("/nonexistent/manifest.csv")).unwrap_err();
        assert!(err.contains("failed to read batch manifest"));
    }

    // ── the optional per-entry baseline (csv) ────────────────────────────

    #[test]
    fn csv_without_a_baseline_column_parses_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("repo-a")).unwrap();
        let manifest = dir.path().join("manifest.csv");
        std::fs::write(
            &manifest,
            format!(
                "AppID,RepoName,Path\napp1,repo-a,{}\n",
                dir.path().join("repo-a").display(),
            ),
        )
        .unwrap();
        assert_eq!(parse_manifest_csv(&manifest).unwrap()[0].baseline, None);
    }

    #[rstest::rstest]
    #[case("baseline")]
    #[case("Baseline_Path")]
    #[case("BASELINE_FILE")]
    fn csv_baseline_column_aliases_are_case_insensitive(#[case] header: &str) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("repo-a")).unwrap();
        write_baseline(dir.path(), "base.json");
        let manifest = dir.path().join("manifest.csv");
        std::fs::write(
            &manifest,
            format!(
                "AppID,RepoName,Path,{header}\napp1,repo-a,{},base.json\n",
                dir.path().join("repo-a").display(),
            ),
        )
        .unwrap();
        let entries = parse_manifest_csv(&manifest).unwrap();
        assert_eq!(entries[0].baseline, Some(dir.path().join("base.json")));
    }

    #[test]
    fn csv_a_blank_baseline_cell_is_the_same_as_omitting_the_column() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("repo-a")).unwrap();
        std::fs::create_dir(dir.path().join("repo-b")).unwrap();
        write_baseline(dir.path(), "base.json");
        let manifest = dir.path().join("manifest.csv");
        std::fs::write(
            &manifest,
            format!(
                "AppID,RepoName,Path,baseline\napp1,repo-a,{},\napp2,repo-b,{},base.json\n",
                dir.path().join("repo-a").display(),
                dir.path().join("repo-b").display(),
            ),
        )
        .unwrap();
        let entries = parse_manifest_csv(&manifest).unwrap();
        assert_eq!(entries[0].baseline, None);
        assert_eq!(entries[1].baseline, Some(dir.path().join("base.json")));
    }

    #[test]
    fn csv_a_missing_baseline_file_is_rejected_at_parse_time() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("repo-a")).unwrap();
        let manifest = dir.path().join("manifest.csv");
        std::fs::write(
            &manifest,
            format!(
                "AppID,RepoName,Path,baseline\napp1,repo-a,{},nope.json\n",
                dir.path().join("repo-a").display(),
            ),
        )
        .unwrap();
        let err = parse_manifest_csv(&manifest).unwrap_err();
        assert!(err.contains("is not an existing file"), "{err}");
    }

    // ── parse_manifest (extension dispatch) ─────────────────────────────

    #[test]
    fn parse_manifest_dispatches_csv_extension_case_insensitively_to_the_csv_parser() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("repo-a")).unwrap();
        let manifest = dir.path().join("manifest.CSV");
        std::fs::write(
            &manifest,
            format!(
                "AppID,RepoName,Path\napp1,repo-a,{}\n",
                dir.path().join("repo-a").display(),
            ),
        )
        .unwrap();
        let entries = parse_manifest(&manifest).unwrap();
        assert_eq!(entries[0].app_id, "app1");
    }

    #[test]
    fn parse_manifest_dispatches_any_other_extension_to_the_txt_parser() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("repo-a")).unwrap();
        let manifest = dir.path().join("manifest.txt");
        std::fs::write(
            &manifest,
            format!("app1,repo-a,{}\n", dir.path().join("repo-a").display()),
        )
        .unwrap();
        let entries = parse_manifest(&manifest).unwrap();
        assert_eq!(entries[0].app_id, "app1");
    }

    // ── table_cell ───────────────────────────────────────────────────────

    #[test]
    fn table_cell_escapes_pipe_and_collapses_newlines() {
        assert_eq!(table_cell("a|b"), "a\\|b");
        assert_eq!(table_cell("line1\nline2"), "line1 line2");
    }

    // ── write_batch_summary ──────────────────────────────────────────────

    #[test]
    fn summary_renders_a_row_per_entry_and_a_failures_section() {
        let dir = tempfile::tempdir().unwrap();
        let out_path = dir.path().join("summary.md");
        let results = vec![
            EntryResult {
                entry: ManifestEntry {
                    app_id: "app1".to_string(),
                    repo_name: "repo-a".to_string(),
                    path: PathBuf::from("/repo-a"),
                    baseline: None,
                },
                status: EntryStatus::Completed {
                    findings: 3,
                    baseline: Some(crate::BaselineTally {
                        new: 1,
                        unchanged: 2,
                        resolved: 4,
                    }),
                },
                report_path: Some(PathBuf::from("/repo-a/security-scan/report.md")),
            },
            EntryResult {
                entry: ManifestEntry {
                    app_id: "app2".to_string(),
                    repo_name: "repo-b".to_string(),
                    path: PathBuf::from("/repo-b"),
                    baseline: None,
                },
                status: EntryStatus::Failed {
                    error: "boom".to_string(),
                },
                report_path: None,
            },
        ];
        write_batch_summary(&out_path, &results).unwrap();
        let text = std::fs::read_to_string(&out_path).unwrap();
        assert!(text.contains("# Batch Scan Summary"));
        assert!(text.contains("| 1 | app1 | repo-a | OK | 3 | 1 | 2 | 4 |"));
        // The failed entry has no counts at all — dashes, not zeroes.
        assert!(text.contains("| - | - | - |"));
        assert!(text.contains("FAILED: boom"));
        assert!(text.contains("## Failures"));
        assert!(text.contains("- **repo-b** (app2): boom"));
    }

    #[test]
    fn summary_omits_the_failures_section_when_everything_succeeded() {
        let dir = tempfile::tempdir().unwrap();
        let out_path = dir.path().join("summary.md");
        let results = vec![EntryResult {
            entry: ManifestEntry {
                app_id: "app1".to_string(),
                repo_name: "repo-a".to_string(),
                path: PathBuf::from("/repo-a"),
                baseline: None,
            },
            status: EntryStatus::Completed {
                findings: 0,
                baseline: None,
            },
            report_path: None,
        }];
        write_batch_summary(&out_path, &results).unwrap();
        let text = std::fs::read_to_string(&out_path).unwrap();
        assert!(!text.contains("## Failures"));
    }

    #[test]
    fn summary_write_creates_missing_parent_directories() {
        let dir = tempfile::tempdir().unwrap();
        let out_path = dir.path().join("nested").join("dir").join("summary.md");
        write_batch_summary(&out_path, &[]).unwrap();
        assert!(out_path.is_file());
    }

    // ── run_batch: manifest-level failure surfaces before any scan ──────

    #[tokio::test]
    async fn run_batch_propagates_a_manifest_parse_error() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("missing.txt");
        let cli = crate::test_support::minimal_cli(dir.path());
        let err = run_batch(&cli, &manifest).await.unwrap_err();
        assert!(err.contains("failed to read batch manifest"));
    }

    /// Refused BEFORE the manifest is even read — the flag is wrong for
    /// this mode regardless of what the manifest turns out to contain.
    #[tokio::test]
    async fn run_batch_refuses_a_top_level_baseline() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("missing.txt");
        let mut cli = crate::test_support::minimal_cli(dir.path());
        cli.baseline = Some(dir.path().join("base.json"));
        let err = run_batch(&cli, &manifest).await.unwrap_err();
        assert!(
            err.contains("--baseline cannot be combined with --repo-file"),
            "{err}"
        );
        assert!(err.contains("baseline` column"), "{err}");
    }
}
