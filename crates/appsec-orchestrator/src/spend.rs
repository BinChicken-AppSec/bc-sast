use super::*;
#[derive(Debug, Clone, Copy, Default)]
pub struct SpendCap {
    pub max_total_tokens: Option<u64>,
    pub max_wall_clock: Option<std::time::Duration>,
}

pub(super) fn cap_tripped_by(
    cap: &SpendCap,
    spent: u64,
    elapsed: std::time::Duration,
) -> Option<String> {
    if let Some(max_tokens) = cap.max_total_tokens {
        if spent >= max_tokens {
            return Some(format!(
                "token budget of {max_tokens} reached ({spent} spent)"
            ));
        }
    }
    if let Some(max_wall_clock) = cap.max_wall_clock {
        if elapsed >= max_wall_clock {
            return Some(format!(
                "time budget of {}s reached ({}s elapsed)",
                max_wall_clock.as_secs(),
                elapsed.as_secs()
            ));
        }
    }
    None
}

pub(super) fn boundary_stop(
    cancel: Option<&appsec_pipeline_core::CancelTokenRef>,
    cap: Option<&SpendCap>,
    tokens_by_phase: &BTreeMap<String, PhaseUsage>,
    scan_start: std::time::Instant,
) -> Option<String> {
    appsec_pipeline_core::canceled(cancel)
        .or_else(|| spend_cap_exceeded(cap, tokens_by_phase, scan_start))
}

pub(super) fn spend_cap_exceeded(
    cap: Option<&SpendCap>,
    tokens_by_phase: &BTreeMap<String, PhaseUsage>,
    scan_start: std::time::Instant,
) -> Option<String> {
    cap_tripped_by(cap?, recorded_tokens(tokens_by_phase), scan_start.elapsed())
}

pub(super) struct SpendGate {
    pub(super) cap: Option<SpendCap>,
    pub(super) tracker: Arc<UsageTrackingClient>,
    pub(super) baseline_tokens: u64,
    pub(super) scan_start: std::time::Instant,
    pub(super) external: std::sync::Mutex<Option<String>>,
    pub(super) cancel: Option<appsec_pipeline_core::CancelTokenRef>,
}

impl SpendGate {
    pub(super) fn tripped(&self) -> Option<String> {
        if let Some(reason) = appsec_pipeline_core::canceled(self.cancel.as_ref()) {
            return Some(reason);
        }
        if let Some(reason) = self.external.lock().unwrap().clone() {
            return Some(reason);
        }
        cap_tripped_by(
            self.cap.as_ref()?,
            self.baseline_tokens + phase_tokens(self.tracker.peek()),
            self.scan_start.elapsed(),
        )
    }
}

impl std::fmt::Debug for SpendGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpendGate")
            .field("cap", &self.cap)
            .field("baseline_tokens", &self.baseline_tokens)
            .field("external", &self.external)
            .field("cancel", &self.cancel)
            .finish_non_exhaustive()
    }
}

impl appsec_pipeline_core::BudgetGate for SpendGate {
    fn should_stop(&self) -> bool {
        self.tripped().is_some()
    }

    fn stop_reason(&self) -> String {
        self.tripped()
            .unwrap_or_else(|| "spend cap reached".to_string())
    }

    fn trip(&self, reason: String) {
        self.external.lock().unwrap().get_or_insert(reason);
    }
}

pub(super) fn budget_gate(
    cap: Option<&SpendCap>,
    tracker: &Arc<UsageTrackingClient>,
    tokens_by_phase: &BTreeMap<String, PhaseUsage>,
    scan_start: std::time::Instant,
    cancel: Option<&appsec_pipeline_core::CancelTokenRef>,
) -> Option<appsec_pipeline_core::BudgetGateRef> {
    Some(Arc::new(SpendGate {
        cap: cap.copied(),
        tracker: tracker.clone(),
        baseline_tokens: recorded_tokens(tokens_by_phase),
        scan_start,
        external: std::sync::Mutex::new(None),
        cancel: cancel.cloned(),
    }))
}
