use super::*;
pub(super) const DEFAULT_OUT_DIR: &str = "security-scan";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputPaths {
    pub provider_writeback_plan: Option<PathBuf>,
    pub markdown: PathBuf,
    pub sarif: PathBuf,
    pub csv: PathBuf,
    pub findings_json: PathBuf,
}

impl OutputPaths {
    pub(super) fn ensure_dirs(&self) -> Result<(), String> {
        let mut created: Vec<&Path> = Vec::new();
        for path in [&self.markdown, &self.sarif, &self.csv, &self.findings_json]
            .into_iter()
            .chain(self.provider_writeback_plan.iter())
        {
            let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) else {
                continue;
            };
            if created.contains(&dir) {
                continue;
            }
            std::fs::create_dir_all(dir)
                .map_err(|e| format!("cannot create output directory {}: {e}", dir.display()))?;
            reject_unsafe_output_dir(dir)?;
            created.push(dir);
        }
        Ok(())
    }
}

pub(super) fn reject_unsafe_output_dir(dir: &Path) -> Result<(), String> {
    let meta = std::fs::symlink_metadata(dir)
        .map_err(|e| format!("cannot inspect output directory {}: {e}", dir.display()))?;
    if meta.file_type().is_symlink() {
        return Err(format!(
            "refusing to write artifacts to {}: it is a symbolic link, so every report \
             this run writes would land somewhere other than the directory named",
            dir.display()
        ));
    }
    let resolved = dir
        .canonicalize()
        .map_err(|e| format!("cannot resolve output directory {}: {e}", dir.display()))?;
    let leaf = dir.file_name();
    if leaf.is_some() && resolved.file_name() != leaf {
        return Err(format!(
            "refusing to write artifacts to {}: it resolves to {}, so a component of the \
             path is a symbolic link",
            dir.display(),
            resolved.display()
        ));
    }
    Ok(())
}

pub fn resolve_output_paths(cli: &Cli) -> OutputPaths {
    let dir = cli
        .out_dir
        .clone()
        .unwrap_or_else(|| repo_path(cli).join(DEFAULT_OUT_DIR));
    OutputPaths {
        provider_writeback_plan: (cli.provider_writeback != "off")
            .then(|| dir.join("provider-writeback-plan.json")),
        markdown: cli.out_md.clone().unwrap_or_else(|| dir.join("report.md")),
        sarif: cli
            .out_sarif
            .clone()
            .unwrap_or_else(|| dir.join("report.sarif")),
        csv: cli
            .out_csv
            .clone()
            .unwrap_or_else(|| dir.join("report.csv")),
        findings_json: cli
            .out_findings_json
            .clone()
            .unwrap_or_else(|| dir.join("findings.json")),
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(super) struct FindingsExport {
    pub(super) commit_sha: String,
    pub(super) findings: Vec<appsec_model::Finding>,
}

pub(super) fn extract_findings(report: &appsec_model::FinalReport) -> Vec<appsec_model::Finding> {
    report
        .findings
        .iter()
        .map(|rf| rf.finding.clone())
        .collect()
}

pub(super) fn write_findings_json(
    path: &Path,
    report: Option<&appsec_model::FinalReport>,
) -> std::io::Result<bool> {
    let Some(report) = report else {
        return Ok(false);
    };
    let Some(commit_sha) = &report.git_sha else {
        return Ok(false);
    };
    let export = FindingsExport {
        commit_sha: commit_sha.clone(),
        findings: extract_findings(report),
    };
    let json = serde_json::to_string_pretty(&export)
        .expect("FindingsExport contains no non-serializable types");
    create_parent_dir(path)?;
    std::fs::write(path, json)?;
    Ok(true)
}

pub(super) fn create_parent_dir(path: &Path) -> std::io::Result<()> {
    match path.parent() {
        Some(parent) => std::fs::create_dir_all(parent),
        None => Ok(()),
    }
}

pub fn write_outputs(
    outcome: &ScanOutcome,
    md_path: &Path,
    sarif_path: &Path,
    csv_path: &Path,
) -> std::io::Result<()> {
    if outcome.stopped_after == Some(StopAfter::S8) {
        return Ok(());
    }
    if let Some(md) = &outcome.markdown {
        create_parent_dir(md_path)?;
        std::fs::write(md_path, md)?;
    }
    if let Some(sarif) = &outcome.sarif {
        create_parent_dir(sarif_path)?;
        std::fs::write(sarif_path, sarif)?;
    }
    if let Some(report) = &outcome.report {
        create_parent_dir(csv_path)?;
        std::fs::write(csv_path, appsec_csv::build_csv(report))?;
    }
    Ok(())
}
