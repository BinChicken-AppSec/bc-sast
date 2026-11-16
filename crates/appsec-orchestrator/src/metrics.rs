use super::*;
pub(super) fn outcome_str(outcome: appsec_stage_s4::ChunkOutcome) -> &'static str {
    match outcome {
        appsec_stage_s4::ChunkOutcome::Completed => "completed",
        appsec_stage_s4::ChunkOutcome::Error => "error",
        appsec_stage_s4::ChunkOutcome::Guardrail => "guardrail",
        appsec_stage_s4::ChunkOutcome::Skipped => SKIPPED_CHUNK,
    }
}

pub(super) const SKIPPED_CHUNK: &str = "skipped";

pub(super) const BUDGET_SKIP: &str = "semantic dedup skipped:";

pub(super) fn budget_skip_reason(stage: &str, outcome_reason: Option<&str>) -> Option<String> {
    let reason = outcome_reason?;
    reason
        .contains(BUDGET_SKIP)
        .then(|| format!("{stage}: {reason}"))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn build_metrics(
    ctx: &ContextPackage,
    manifest: &TaskManifest,
    repo_root: &Path,
    repo_name: &str,
    scan_uuid: &str,
    start_ts: &str,
    end_ts: &str,
    raw_findings_count: i64,
    true_positive_count: i64,
    false_positive_count: i64,
    duplicate_count: i64,
    chunk_outcomes: &BTreeMap<String, appsec_stage_s4::ChunkOutcome>,
    tokens_by_phase: &BTreeMap<String, PhaseUsage>,
    unpriced_models: Vec<String>,
    mut errors_by_stage: BTreeMap<String, i64>,
    budget_stop: Option<String>,
) -> ScanMetrics {
    let dispositions = coverage::file_dispositions(ctx, manifest, chunk_outcomes);
    let analyzed: BTreeSet<&str> = dispositions
        .iter()
        .filter(|(_, d)| d.reviewed())
        .map(|(f, _)| f.as_str())
        .collect();
    let (mut chunks_risk, mut chunks_catchall, mut chunks_specialist) = (0i64, 0i64, 0i64);
    let mut scope = Vec::with_capacity(manifest.chunks.len());
    for chunk in &manifest.chunks {
        let kind = appsec_metrics::chunk_kind(&chunk.id, chunk.specialist.is_some());
        match kind {
            appsec_metrics::ChunkKind::Risk => chunks_risk += 1,
            appsec_metrics::ChunkKind::Catchall => chunks_catchall += 1,
            appsec_metrics::ChunkKind::Specialist => chunks_specialist += 1,
        }
        let mut files = chunk.files.clone();
        files.sort();
        scope.push(ScopeEntry {
            name: chunk.id.clone(),
            kind: match kind {
                appsec_metrics::ChunkKind::Risk => ScopeKind::Risk,
                appsec_metrics::ChunkKind::Catchall => ScopeKind::Catchall,
                appsec_metrics::ChunkKind::Specialist => ScopeKind::Specialist,
            },
            files,
        });
    }

    let folders_scanned = appsec_metrics::folders_scanned(analyzed.iter().copied());

    let mut loc_in_scope_by_language: BTreeMap<String, i64> = BTreeMap::new();
    let mut loc_scanned_by_language: BTreeMap<String, i64> = BTreeMap::new();
    for file in &ctx.all_files {
        let ext = Path::new(file)
            .extension()
            .map(|e| format!(".{}", e.to_string_lossy().to_lowercase()))
            .unwrap_or_default();
        let lang = appsec_repo_analysis::ext_to_lang(&ext)
            .unwrap_or("other")
            .to_string();
        let loc = appsec_pathjail::confine(repo_root, file)
            .and_then(|p| std::fs::read_to_string(p).ok())
            .map(|content| appsec_metrics::count_nonblank_lines(&content) as i64)
            .unwrap_or(0);
        *loc_in_scope_by_language.entry(lang.clone()).or_insert(0) += loc;
        if analyzed.contains(file.as_str()) {
            *loc_scanned_by_language.entry(lang).or_insert(0) += loc;
        }
    }

    let outcome_strs: Vec<&str> = chunk_outcomes.values().copied().map(outcome_str).collect();
    let chunks_skipped = outcome_strs.iter().filter(|&&v| v == SKIPPED_CHUNK).count() as i64;
    let chunks_failed = appsec_metrics::count_failed_chunks(
        outcome_strs.iter().copied().filter(|&v| v != SKIPPED_CHUNK),
    ) as i64;
    if chunks_failed > 0 {
        errors_by_stage.insert("s4".to_string(), chunks_failed);
    }

    let mut prompt_total = 0i64;
    let mut completion_total = 0i64;
    let mut cache_read_total = 0i64;
    let mut cache_write_total = 0i64;
    let mut truncated_total = 0u64;
    let mut usage_recorded = false;
    let mut run_cost = pricing::PhaseCost::default();
    let tokens_by_phase_json: BTreeMap<String, serde_json::Value> = tokens_by_phase
        .iter()
        .map(|(phase, phase_usage)| {
            let usage = phase_usage.usage;
            let prompt = prompt_tokens(usage);
            let completion = usage.output_tokens as i64;
            prompt_total += prompt;
            completion_total += completion;
            cache_read_total += usage.cache_read_input_tokens as i64;
            cache_write_total += usage.cache_creation_input_tokens as i64;
            truncated_total += phase_usage.truncated_replies;
            usage_recorded |= phase_usage.calls_with_usage > 0;
            run_cost.merge(phase_usage.cost);
            let cost = phase_usage.cost;
            (
                phase.clone(),
                serde_json::json!({
                    "calls": phase_usage.calls,
                    "prompt": prompt,
                    "completion": completion,
                    "cache_read": usage.cache_read_input_tokens as i64,
                    "cache_write": usage.cache_creation_input_tokens as i64,
                    "reasoning": usage.reasoning_output_tokens as i64,
                    "cost_usd": (cost.priced_calls() > 0).then(|| cost.total().dollars_f64()),
                    "unpriced_tokens": cost.unpriced_tokens() as i64,
                }),
            )
        })
        .collect();

    ScanMetrics {
        scan_id: format!("{start_ts}__{repo_name}"),
        scan_uuid: scan_uuid.to_string(),
        module_name: repo_name.to_string(),
        start_ts: start_ts.to_string(),
        end_ts: end_ts.to_string(),
        duration_sec: appsec_metrics::duration_seconds(start_ts, end_ts),
        total_files_in_scope: ctx.all_files.len() as i64,
        analyzed_files_unique: analyzed.len() as i64,
        chunks_total: manifest.chunks.len() as i64,
        chunks_risk,
        chunks_catchall,
        chunks_specialist,
        chunks_attempted: manifest.chunks.len() as i64 - chunks_skipped,
        chunks_failed,
        errors_by_stage,
        errors_log_path: String::new(),
        budget_stop: budget_stop.unwrap_or_default(),
        canceled: false,
        pipeline_diagnostics: appsec_model::PipelineDiagnostics::default(),
        files_by_disposition: coverage::counts(&dispositions),
        files_not_reviewed: coverage::not_reviewed(&dispositions),
        loc_in_scope_by_language,
        loc_scanned_by_language,
        raw_findings_count,
        true_positive_count,
        false_positive_count,
        duplicate_count,
        prompt_tokens: usage_recorded.then_some(prompt_total),
        completion_tokens: usage_recorded.then_some(completion_total),
        total_tokens: usage_recorded.then_some(prompt_total + completion_total),
        cache_read_tokens: usage_recorded.then_some(cache_read_total),
        cache_write_tokens: usage_recorded.then_some(cache_write_total),
        tokens_by_phase: usage_recorded.then_some(tokens_by_phase_json),
        llm_truncated_replies: truncated_total as i64,
        stage_timings: BTreeMap::new(),
        cost_usd: (usage_recorded && run_cost.priced_calls() > 0)
            .then(|| run_cost.total().dollars_f64()),
        unpriced_tokens: usage_recorded.then_some(run_cost.unpriced_tokens() as i64),
        unpriced_calls: usage_recorded.then_some(run_cost.unpriced_calls() as i64),
        unpriced_models,
        folders_scanned,
        scope,
        excluded: ctx.excluded.clone(),
        changed_files_count: ctx.changed_files.len() as i64,
        diff_scope_active: ctx.diff_scope_active,
    }
}

pub(super) fn threat_model_has_content(tm: &appsec_model::ThreatModel) -> bool {
    !(tm.threats.is_empty() && tm.assets.is_empty() && tm.trust_boundaries.is_empty())
}

pub(super) fn threat_model_counts(
    tm: Option<&appsec_model::ThreatModel>,
) -> Vec<(&'static str, u64)> {
    tm.map(|tm| {
        vec![
            ("assets", telemetry::count(tm.assets.len())),
            ("boundaries", telemetry::count(tm.trust_boundaries.len())),
            ("threats", telemetry::count(tm.threats.len())),
        ]
    })
    .unwrap_or_default()
}

pub(super) fn s4_counts(
    findings: usize,
    outcomes: &BTreeMap<String, appsec_stage_s4::ChunkOutcome>,
) -> Vec<(&'static str, u64)> {
    let failed = outcomes
        .values()
        .filter(|o| {
            !matches!(
                o,
                appsec_stage_s4::ChunkOutcome::Completed | appsec_stage_s4::ChunkOutcome::Skipped
            )
        })
        .count();
    let skipped = outcomes
        .values()
        .filter(|o| **o == appsec_stage_s4::ChunkOutcome::Skipped)
        .count();
    vec![
        ("findings", telemetry::count(findings)),
        ("chunks", telemetry::count(outcomes.len())),
        ("chunks_failed", telemetry::count(failed)),
        ("chunks_skipped", telemetry::count(skipped)),
    ]
}

pub(super) fn kept_dropped_counts(
    kept_name: &'static str,
    kept: &[Finding],
    dropped: &[DroppedFinding],
) -> Vec<(&'static str, u64)> {
    vec![
        (kept_name, telemetry::count(kept.len())),
        ("dropped", telemetry::count(dropped.len())),
    ]
}
