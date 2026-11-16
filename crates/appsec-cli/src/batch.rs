use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use appsec_llm_client::{LlmClient, ToolExecutor};
use appsec_sandbox_tools::SandboxTools;

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
    pub baseline: Option<PathBuf>,
}

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
        let lineno = idx + 2;
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

pub async fn run_batch(cli: &Cli, manifest_path: &Path) -> Result<BatchSummary, String> {
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
        entry_cli.baseline = entry.baseline.clone();
        entry_cli.out_dir = None;
        entry_cli.out_md = None;
        entry_cli.out_sarif = None;
        entry_cli.out_csv = None;
        entry_cli.out_findings_json = None;
        entry_cli.out_remediation_json = None;

        let github = crate::pr_comment_target(&entry_cli, build_github_client(&entry_cli)?);
        let outcome = run_one_entry(&entry_cli, &resolved_path, llm.clone(), github).await;
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

async fn run_one_entry(
    entry_cli: &Cli,
    resolved_path: &Path,
    llm: Arc<dyn LlmClient>,
    github: Option<appsec_github::GithubClient>,
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
    let paths = resolve_output_paths(entry_cli);
    let remediate = (entry_cli.remediate && stop_after.is_none())
        .then(|| crate::build_remediate_run(entry_cli, resolved_path))
        .transpose()?;

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

fn table_cell(text: &str) -> String {
    text.replace(['\r', '\n'], " ").replace('|', "\\|")
}

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

    #[test]
    fn table_cell_escapes_pipe_and_collapses_newlines() {
        assert_eq!(table_cell("a|b"), "a\\|b");
        assert_eq!(table_cell("line1\nline2"), "line1 line2");
    }

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

    #[tokio::test]
    async fn run_batch_propagates_a_manifest_parse_error() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("missing.txt");
        let cli = crate::test_support::minimal_cli(dir.path());
        let err = run_batch(&cli, &manifest).await.unwrap_err();
        assert!(err.contains("failed to read batch manifest"));
    }

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
