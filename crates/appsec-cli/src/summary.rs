use super::*;
pub fn process_exit_code(
    result: &Result<ScanSummary, String>,
    remediation_exit_code: bool,
    canceled: bool,
) -> u8 {
    if canceled {
        return cancel::CANCELED_EXIT_CODE;
    }
    let Ok(summary) = result else {
        return 1;
    };
    let unhealthy = summary.doctor.as_ref().is_some_and(|d| !d.healthy())
        || summary.setup.as_ref().is_some_and(|s| !s.healthy());
    if unhealthy {
        return 1;
    }
    summary
        .remediation
        .as_ref()
        .filter(|_| remediation_exit_code)
        .map_or(0, RemediationSummary::exit_code)
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct ScanSummary {
    pub provider_publication: Option<String>,
    pub findings: usize,
    pub markdown_path: Option<PathBuf>,
    pub sarif_path: Option<PathBuf>,
    pub csv_path: Option<PathBuf>,
    pub findings_json_path: Option<PathBuf>,
    pub stopped_after: Option<StopAfter>,
    pub github_sync: Option<Result<appsec_github::SyncSummary, String>>,
    pub remediation: Option<RemediationSummary>,
    pub baseline: Option<BaselineTally>,
    pub remediation_patch: Option<PathBuf>,
    pub gc: Option<GcSummary>,
    pub batch: Option<batch::BatchSummary>,
    pub estimate: Option<estimate::EstimateSummary>,
    pub doctor: Option<DoctorSummary>,
    pub setup: Option<SetupSummary>,
    pub cost: Option<CostSummary>,
    pub augmented: Option<AugmentedReports>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AugmentOutcome {
    Written,
    NotFound,
    Unchanged,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AugmentedReports {
    pub markdown_path: PathBuf,
    pub markdown: AugmentOutcome,
    pub sarif_path: PathBuf,
    pub sarif: AugmentOutcome,
}

impl std::fmt::Display for AugmentedReports {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let describe = |outcome: AugmentOutcome, path: &Path| match outcome {
            AugmentOutcome::Written => format!("augmented {}", path.display()),
            AugmentOutcome::NotFound => {
                format!("no prior report at {} to augment", path.display())
            }
            AugmentOutcome::Unchanged => format!(
                "left {} unchanged (it already carries a remediation section, or its findings \
                 don't line up with this export)",
                path.display()
            ),
        };
        write!(
            f,
            " Reports: {}; {}.",
            describe(self.markdown, &self.markdown_path),
            describe(self.sarif, &self.sarif_path)
        )
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DoctorSummary {
    pub checks_rendered: String,
    pub blocking: usize,
    pub models_rendered: String,
    pub probe: Option<environment::Check>,
    pub cache_probe: Option<cache_probe::CacheProbeOutcome>,
}

impl DoctorSummary {
    pub fn healthy(&self) -> bool {
        self.blocking == 0
            && self
                .probe
                .as_ref()
                .is_some_and(|p| p.status == environment::CheckStatus::Ok)
            && self
                .cache_probe
                .as_ref()
                .is_none_or(cache_probe::CacheProbeOutcome::completed)
    }
}

impl std::fmt::Display for DoctorSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{}", self.checks_rendered)?;
        if !self.models_rendered.is_empty() {
            writeln!(f, "{}", self.models_rendered)?;
        }
        let probe_line = if self.blocking > 0 {
            "  [probe] skipped — fix the blocking item(s) above first".to_string()
        } else {
            let probe = self
                .probe
                .as_ref()
                .expect("blocking == 0 always means run_doctor ran the probe");
            let icon = if probe.status == environment::CheckStatus::Ok {
                '\u{2713}'
            } else {
                '\u{2717}'
            };
            format!("  [probe] {icon} {}", probe.detail)
        };
        match &self.cache_probe {
            Some(outcome) => write!(f, "{probe_line}\n{outcome}"),
            None => f.write_str(&probe_line),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SetupSummary {
    pub checks_rendered: String,
    pub blocking: usize,
}

impl SetupSummary {
    pub fn healthy(&self) -> bool {
        self.blocking == 0
    }
}

impl std::fmt::Display for SetupSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.checks_rendered)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GcSummary {
    Evicted {
        path: PathBuf,
        run_id: String,
        found: bool,
        dry_run: bool,
    },
    Pruned {
        db_path: PathBuf,
        kept: usize,
        deleted: Vec<String>,
        dry_run: bool,
    },
}

impl std::fmt::Display for GcSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GcSummary::Evicted {
                path,
                run_id,
                dry_run: true,
                ..
            } => write!(
                f,
                "gc: [dry-run] would evict run {run_id} for {}",
                path.display()
            ),
            GcSummary::Evicted {
                path,
                run_id,
                found: true,
                dry_run: false,
            } => write!(f, "gc: evicted run {run_id} for {}", path.display()),
            GcSummary::Evicted {
                path,
                run_id,
                found: false,
                dry_run: false,
            } => write!(
                f,
                "gc: no run found for {} (run_id {run_id})",
                path.display()
            ),
            GcSummary::Pruned {
                db_path,
                kept,
                deleted,
                dry_run,
            } => {
                let tag = if *dry_run { "[dry-run] " } else { "" };
                let verb = if *dry_run { "would delete" } else { "deleted" };
                write!(
                    f,
                    "gc: {} — {tag}kept {kept} run(s), {verb} {}",
                    db_path.display(),
                    deleted.len()
                )?;
                for run_id in deleted {
                    write!(f, "\n    - {run_id}")?;
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CostSummary {
    pub usd: Option<f64>,
    pub unpriced_tokens: i64,
}

impl CostSummary {
    pub(super) fn from_metrics(metrics: &appsec_model::ScanMetrics) -> Option<Self> {
        (metrics.cost_usd.is_some() || metrics.unpriced_tokens.is_some()).then(|| CostSummary {
            usd: metrics.cost_usd,
            unpriced_tokens: metrics.unpriced_tokens.unwrap_or(0),
        })
    }
}

impl std::fmt::Display for CostSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.usd {
            Some(usd) => write!(f, " Cost (USD): {usd:.6}")?,
            None => write!(f, " Cost (USD): unpriced")?,
        }
        match self.unpriced_tokens {
            0 => write!(f, "."),
            n => write!(f, " ({n} token(s) had no published rate)."),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BaselineTally {
    pub new: usize,
    pub unchanged: usize,
    pub resolved: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ValidationTally {
    pub fixed: usize,
    pub partially_fixed: usize,
    pub not_fixed: usize,
    pub unverifiable: usize,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct RemediationSummary {
    pub refused: Option<String>,
    pub processed: usize,
    pub failed: usize,
    pub fixed: usize,
    pub not_fixed: usize,
    pub rollup: appsec_validation_scoring::Rollup,
    pub validated: Option<ValidationTally>,
    pub validation_failures: usize,
}

pub const EXIT_NOT_REMEDIATED: u8 = 3;

impl RemediationSummary {
    pub fn exit_code(&self) -> u8 {
        if self.failed > 0 || self.validation_failures > 0 {
            return 1;
        }
        let not_remediated = self
            .validated
            .is_some_and(|v| v.fixed == 0 && v.partially_fixed + v.not_fixed > 0);
        if not_remediated {
            EXIT_NOT_REMEDIATED
        } else {
            0
        }
    }
}

pub(super) fn remediation_rollup(
    outcome: &appsec_orchestrator::RemediateOutcome,
) -> appsec_validation_scoring::Rollup {
    use appsec_validation_scoring::{verdict_state, CaseState};
    let cases = outcome.outcomes.iter().enumerate().filter_map(|(i, o)| {
        let appsec_stage_s10::RemediationOutcome::Processed(record) = o else {
            return None;
        };
        let decision = outcome
            .validations
            .get(i)
            .and_then(Option::as_ref)
            .map(|s| s.decision());
        let state = match decision {
            Some(d) => verdict_state(d),
            None if record.diff.as_deref().is_some_and(|d| !d.trim().is_empty())
                && !appsec_stage_s10::was_reverted(record) =>
            {
                CaseState::Remediated
            }
            None => CaseState::Declined,
        };
        Some((state, decision))
    });
    appsec_validation_scoring::Rollup::tally(cases)
}

impl From<&appsec_orchestrator::RemediateOutcome> for RemediationSummary {
    fn from(outcome: &appsec_orchestrator::RemediateOutcome) -> Self {
        let counts = appsec_stage_s10::RemediationCounts::from_outcomes(&outcome.outcomes);
        let processed = counts.fixed + counts.not_fixed;
        let validated = (!outcome.validations.is_empty()).then(|| {
            let mut tally = ValidationTally::default();
            for score in outcome.validations.iter().flatten() {
                match score.fix_status {
                    appsec_validation_scoring::FixVerdict::Fixed => tally.fixed += 1,
                    appsec_validation_scoring::FixVerdict::PartiallyFixed => {
                        tally.partially_fixed += 1
                    }
                    appsec_validation_scoring::FixVerdict::NotFixed => tally.not_fixed += 1,
                    appsec_validation_scoring::FixVerdict::Unverifiable => tally.unverifiable += 1,
                }
            }
            tally
        });
        RemediationSummary {
            refused: outcome.refused.clone(),
            processed,
            failed: counts.failed,
            fixed: counts.fixed,
            not_fixed: counts.not_fixed,
            rollup: remediation_rollup(outcome),
            validated,
            validation_failures: outcome.validation_failures,
        }
    }
}

impl std::fmt::Display for ScanSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(result) = &self.provider_publication {
            if self.markdown_path.is_none() && self.findings_json_path.is_none() {
                return writeln!(f, "{result}");
            }
            write!(f, "{result} ")?;
        }
        if let Some(gc) = &self.gc {
            return write!(f, "{gc}");
        }
        if let Some(estimate) = &self.estimate {
            return write!(f, "{estimate}");
        }
        if let Some(doctor) = &self.doctor {
            return write!(f, "{doctor}");
        }
        if let Some(setup) = &self.setup {
            return write!(f, "{setup}");
        }
        if let Some(b) = &self.batch {
            return write!(
                f,
                "Batch scan complete: {}/{} succeeded, {} failed. Summary: {}",
                b.completed,
                b.total,
                b.failed,
                b.summary_path.display()
            );
        }
        match self.stopped_after {
            Some(stop) => write!(f, "Scan stopped after {stop:?}.")?,
            None => write!(f, "Scan complete: {} finding(s).", self.findings)?,
        }
        if let Some(cost) = &self.cost {
            write!(f, "{cost}")?;
        }
        if let Some(p) = &self.markdown_path {
            write!(f, " Markdown: {}", p.display())?;
        }
        if let Some(p) = &self.sarif_path {
            write!(f, " SARIF: {}", p.display())?;
        }
        if let Some(p) = &self.csv_path {
            write!(f, " CSV: {}", p.display())?;
        }
        if let Some(p) = &self.findings_json_path {
            write!(f, " Findings JSON: {}", p.display())?;
        }
        match &self.github_sync {
            Some(Ok(s)) => write!(f, " GitHub: {} created, {} updated.", s.created, s.updated)?,
            Some(Err(e)) => write!(f, " GitHub sync failed: {e}")?,
            None => {}
        }
        match &self.remediation {
            Some(r) if r.refused.is_some() => {
                write!(f, " Remediation refused: {}", r.refused.as_deref().unwrap())?
            }
            Some(r) => {
                let msg = format!(
                    " Remediation: {} processed, {} failed. Outcome: {} fixed, {} not fixed.",
                    r.processed, r.failed, r.fixed, r.not_fixed
                );
                write!(f, "{msg}")?;
                r.validated.iter().try_for_each(|v| {
                    write!(
                        f,
                        " Validation: {} fixed, {} partially fixed, {} not fixed, {} unverifiable.",
                        v.fixed, v.partially_fixed, v.not_fixed, v.unverifiable
                    )
                })?;
                if r.validation_failures > 0 {
                    write!(f, " ({} validation error(s).)", r.validation_failures)?;
                }
                if r.exit_code() == EXIT_NOT_REMEDIATED {
                    let code = EXIT_NOT_REMEDIATED;
                    write!(f, " Nothing validated as fixed (exit code {code}).")?;
                }
            }
            None => {}
        }
        if let Some(a) = &self.augmented {
            write!(f, "{a}")?;
        }
        if let Some(b) = &self.baseline {
            write!(
                f,
                " Baseline: {} new, {} unchanged, {} resolved.",
                b.new, b.unchanged, b.resolved
            )?;
        }
        if let Some(p) = &self.remediation_patch {
            write!(
                f,
                " Patch (worktree-isolated, apply with `git apply {}`): {}",
                p.display(),
                p.display()
            )?;
        }
        Ok(())
    }
}
