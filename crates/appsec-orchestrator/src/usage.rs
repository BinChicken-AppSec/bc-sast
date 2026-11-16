use super::*;
pub(super) struct UsageTrackingClient {
    pub(super) inner: Arc<dyn LlmClient>,
    pub(super) total: Mutex<PhaseUsage>,
    pub(super) pricer: appsec_pricing::Pricer<'static>,
    pub(super) provider: Option<String>,
    pub(super) cache_ttl: appsec_llm_client::CacheTtl,
    pub(super) unpriced_models: pricing::UnpricedModels,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct PhaseUsage {
    pub(super) usage: Usage,
    pub(super) calls: i64,
    pub(super) calls_with_usage: i64,
    pub(super) cost: pricing::PhaseCost,
    pub(super) truncated_replies: u64,
}

impl UsageTrackingClient {
    pub(super) fn new(inner: Arc<dyn LlmClient>, pricing: &pricing::PricingConfig) -> Self {
        UsageTrackingClient {
            inner,
            total: Mutex::new(PhaseUsage::default()),
            pricer: pricing.pricer(),
            provider: pricing.provider.clone(),
            cache_ttl: pricing.cache_ttl,
            unpriced_models: pricing::UnpricedModels::default(),
        }
    }

    pub(super) fn take(&self) -> PhaseUsage {
        std::mem::take(&mut self.total.lock().unwrap())
    }

    pub(super) fn peek(&self) -> PhaseUsage {
        *self.total.lock().unwrap()
    }
}

#[async_trait::async_trait]
impl LlmClient for UsageTrackingClient {
    async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, LlmError> {
        let response = self.inner.chat(request).await?;
        let mut total = self.total.lock().unwrap();
        total.calls += 1;
        let mut unpriced = None;
        if response.usage != Usage::default() {
            total.calls_with_usage += 1;
            unpriced = total.cost.record_call(
                &self.pricer,
                self.provider.as_deref(),
                &request.model,
                response.usage,
                self.cache_ttl,
            );
        }
        total.usage.input_tokens += response.usage.input_tokens;
        total.usage.output_tokens += response.usage.output_tokens;
        total.usage.cache_creation_input_tokens += response.usage.cache_creation_input_tokens;
        total.usage.cache_read_input_tokens += response.usage.cache_read_input_tokens;
        drop(total);
        if let Some(label) = unpriced {
            self.unpriced_models.add(label);
        }
        Ok(response)
    }

    fn note_truncated_reply(&self) {
        self.total.lock().unwrap().truncated_replies += 1;
        self.inner.note_truncated_reply();
    }
}

pub(super) fn stage_usage(phase: PhaseUsage) -> appsec_pipeline_core::StageUsage {
    appsec_pipeline_core::StageUsage {
        prompt_tokens: prompt_tokens(phase.usage),
        completion_tokens: phase.usage.output_tokens as i64,
        cache_read_tokens: phase.usage.cache_read_input_tokens as i64,
        cache_write_tokens: phase.usage.cache_creation_input_tokens as i64,
        calls: phase.calls,
        cost_usd: (phase.cost.priced_calls() > 0).then(|| phase.cost.total().dollars_f64()),
        unpriced_tokens: phase.cost.unpriced_tokens() as i64,
        truncated_replies: phase.truncated_replies,
    }
}

pub(super) fn prompt_tokens(usage: Usage) -> i64 {
    (usage.input_tokens + usage.cache_creation_input_tokens) as i64
}

pub(super) fn recorded_tokens(tokens_by_phase: &BTreeMap<String, PhaseUsage>) -> u64 {
    tokens_by_phase.values().copied().map(phase_tokens).sum()
}

pub(super) fn phase_tokens(phase: PhaseUsage) -> u64 {
    prompt_tokens(phase.usage) as u64 + phase.usage.output_tokens
}
