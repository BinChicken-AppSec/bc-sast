use super::*;
pub(super) fn validations_by_finding_id(
    outcome: &appsec_orchestrator::RemediateOutcome,
) -> std::collections::BTreeMap<String, appsec_validation_scoring::ValidationScore> {
    outcome
        .outcomes
        .iter()
        .zip(&outcome.validations)
        .filter_map(|(o, validation)| {
            let appsec_stage_s10::RemediationOutcome::Processed(record) = o else {
                return None;
            };
            Some((record.finding_id.clone(), validation.clone()?))
        })
        .collect()
}

pub(super) fn augment_report_outputs(
    md_path: &Path,
    sarif_path: &Path,
    report: &appsec_model::FinalReport,
    tool_version: &str,
    markdown: Option<&str>,
    sarif_was_written: bool,
    outcome: &appsec_orchestrator::RemediateOutcome,
) -> std::io::Result<()> {
    let by_id = validations_by_finding_id(outcome);
    let views = remediation_views(report, outcome);
    if by_id.is_empty() && views.is_empty() {
        return Ok(());
    }
    markdown.into_iter().try_for_each(|md| {
        let aligned: Vec<Option<appsec_validation_scoring::ValidationScore>> = report
            .findings
            .iter()
            .map(|rf| by_id.get(&appsec_sarif::finding_id(&rf.finding)).cloned())
            .collect();
        let with_remediation = appsec_report_md::augment_markdown_with_remediation(md, &views);
        let augmented = appsec_redact::redact(&appsec_report_md::augment_markdown(
            &with_remediation,
            &aligned,
        ));
        create_parent_dir(md_path)?;
        std::fs::write(md_path, augmented)
    })?;
    sarif_was_written
        .then_some(())
        .into_iter()
        .try_for_each(|()| {
            let mut doc = appsec_sarif::build_sarif_with_validations(report, tool_version, &by_id);
            apply_remediation_status(&mut doc, report, outcome);
            let json = serde_json::to_string_pretty(&doc).expect("SarifDocument always serializes");
            create_parent_dir(sarif_path)?;
            std::fs::write(sarif_path, json)
        })
}

pub(super) const REMEDIATION_SUMMARY_HEADING: &str = "\n## Remediation Summary\n";

pub(super) fn augment_prior_reports(
    md_path: &Path,
    sarif_path: &Path,
    report: &appsec_model::FinalReport,
    outcome: &appsec_orchestrator::RemediateOutcome,
) -> std::io::Result<AugmentedReports> {
    Ok(AugmentedReports {
        markdown: augment_in_place(md_path, |text| {
            augment_prior_markdown(text, report, outcome)
        })?,
        markdown_path: md_path.to_path_buf(),
        sarif: augment_in_place(sarif_path, |text| augment_prior_sarif(text, outcome))?,
        sarif_path: sarif_path.to_path_buf(),
    })
}

pub(super) fn augment_in_place(
    path: &Path,
    augment: impl FnOnce(&str) -> Option<String>,
) -> std::io::Result<AugmentOutcome> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Ok(AugmentOutcome::NotFound);
    };
    match augment(&text) {
        Some(augmented) => {
            std::fs::write(path, augmented)?;
            Ok(AugmentOutcome::Written)
        }
        None => Ok(AugmentOutcome::Unchanged),
    }
}

pub(super) fn augment_prior_markdown(
    markdown: &str,
    report: &appsec_model::FinalReport,
    outcome: &appsec_orchestrator::RemediateOutcome,
) -> Option<String> {
    if markdown.contains(REMEDIATION_SUMMARY_HEADING) {
        return None;
    }
    let by_id = validations_by_finding_id(outcome);
    let views = remediation_views(report, outcome);
    if by_id.is_empty() && views.is_empty() {
        return None;
    }
    let aligned: Vec<Option<appsec_validation_scoring::ValidationScore>> = report
        .findings
        .iter()
        .map(|rf| by_id.get(&appsec_sarif::finding_id(&rf.finding)).cloned())
        .collect();
    let with_remediation = appsec_report_md::augment_markdown_with_remediation(markdown, &views);
    let augmented = appsec_redact::redact(&appsec_report_md::augment_markdown(
        &with_remediation,
        &aligned,
    ));
    (augmented != markdown).then_some(augmented)
}

pub(super) fn augment_prior_sarif(
    sarif: &str,
    outcome: &appsec_orchestrator::RemediateOutcome,
) -> Option<String> {
    let validations = validations_by_finding_id(outcome);
    let statuses = remediation_statuses(outcome);
    if validations.is_empty() && statuses.is_empty() {
        return None;
    }
    let mut doc: appsec_sarif::SarifDocument = serde_json::from_str(sarif).ok()?;
    let mut touched = false;
    for run in &mut doc.runs {
        for result in &mut run.results {
            let Some(id) = result
                .partial_fingerprints
                .get(appsec_sarif::FINGERPRINT_KEY)
                .cloned()
            else {
                continue;
            };
            if let Some(validation) = validations.get(&id) {
                appsec_sarif::apply_validation(result, validation);
                touched = true;
            }
            if let Some(status) = statuses.get(&id) {
                result.properties.remediation_status = Some(status.clone());
                touched = true;
            }
        }
    }
    touched.then(|| serde_json::to_string_pretty(&doc).expect("SarifDocument always serializes"))
}
