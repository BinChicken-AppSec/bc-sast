use std::time::Duration;

/// Everything one agentic session needs beyond the initial user prompt —
/// combines the model-role config (`model`/`temperature`/`thinking_budget`/
/// `betas`, resolved from `bc-config` by the caller) with the loop's own
/// tunables (`max_turns`, retry/backoff caps), mirroring the parameters
/// `backends/oai.py`'s/`backends/sdk.py`'s `agentic()` accept today.
#[derive(Debug, Clone)]
pub struct AgenticConfig {
    pub model: String,
    pub system_prompt: Option<String>,
    pub allowed_tools: Vec<String>,
    pub max_tokens: u32,
    pub max_turns: u32,
    pub temperature: Option<f64>,
    /// Nucleus-sampling cutoff, forwarded to
    /// [`bc_llm_client::ChatRequest::top_p`]. `None` (the default) sends
    /// none — net-new versus Python, which exposes only `temperature`.
    /// The Anthropic dialect drops it when `temperature` is also set, as
    /// the Messages API rejects the pair.
    pub top_p: Option<f64>,
    /// Deterministic-sampling seed, forwarded to
    /// [`bc_llm_client::ChatRequest::seed`] (OpenAI dialect only — see
    /// that field). `None` (the default) sends no seed. Net-new versus
    /// Python, which exposes only `models.<role>.temperature`.
    pub seed: Option<u64>,
    pub thinking_budget: Option<u32>,
    pub betas: Vec<String>,
    pub json_mode: bool,
    /// How many times a single turn retries after a retryable
    /// [`bc_llm_client::LlmError`] (429/5xx/connection failure) before
    /// giving up and propagating it.
    pub max_transient_retries: u32,
    /// How many times a single turn retries after a
    /// [`bc_llm_client::LlmError::ContextOverflow`] by evicting the oldest
    /// oversized tool result (see [`crate::pure::shrink_history`]) before
    /// giving up and propagating it.
    pub max_context_shrinks: u32,
    /// Base delay before a transient-retry attempt; the actual delay is
    /// `retry_backoff_base * attempt_number` (linear backoff). Set to
    /// [`Duration::ZERO`] to make retries instant, e.g. in tests.
    pub retry_backoff_base: Duration,
    /// Per-turn wall-clock deadline in seconds, forwarded to
    /// [`bc_llm_client::ChatRequest::timeout`] and overriding the shared
    /// gateway client's own 300 s default. Seconds (not a [`Duration`])
    /// to match the `stepN.timeout` config keys this is wired from.
    ///
    /// `None` (the default) keeps the client default. No direct Python
    /// equivalent: `backends/sdk.py`/`backends/oai.py` accept a `timeout`
    /// on `prompt()` (the single-shot path) but not on `agentic()`, which
    /// relies on the SDK's own default — an agentic *turn* is bounded by
    /// `max_tokens` per turn, not by the whole session, so the client
    /// default is usually adequate here and this exists for the operator
    /// who needs to raise it.
    pub timeout_secs: Option<u64>,
    /// Upper bound on the one truncation retry's doubled output budget
    /// (VVAH-E005, see [`crate::chat_with_retry`]). `None` (the default)
    /// leaves the doubling uncapped and lets the provider's own 400 on an
    /// over-cap budget stand in for the ceiling, as Python's OpenAI
    /// route does; Python's Anthropic route passes the model's output
    /// cap here instead. A turn already at the ceiling is not retried.
    pub max_tokens_ceiling: Option<u32>,
    /// Reasoning-effort tier for every turn (the Python original's
    /// `models.<role>.effort`), forwarded to
    /// [`bc_llm_client::ChatRequest::reasoning_effort`]. `None` sends none.
    pub reasoning_effort: Option<bc_llm_client::ReasoningEffort>,
    /// Per-role OpenAI transport pin (Python's
    /// `models.<role>.use_responses_api`), forwarded to
    /// [`bc_llm_client::ChatRequest::openai_api`]. `None` keeps the
    /// client's configured transport.
    pub openai_api: Option<bc_llm_client::OpenAiApi>,
    /// Stable leading prefix of the first user turn, forwarded to
    /// [`bc_llm_client::ChatRequest::cache_prefix`] on every turn.
    pub cache_prefix: Option<String>,
    /// OpenAI `prompt_cache_key` material, forwarded to
    /// [`bc_llm_client::ChatRequest::cache_key`] on every turn.
    pub cache_key: Option<String>,
}

impl AgenticConfig {
    /// Sensible defaults matching the Python originals' `_MAX_TURNS`/retry
    /// caps: no system prompt, no tools, 16000 max tokens, 25-turn cap, 4
    /// transient retries, 16 context-shrink attempts, no dialect extras.
    pub fn new(model: impl Into<String>) -> Self {
        AgenticConfig {
            model: model.into(),
            system_prompt: None,
            allowed_tools: Vec::new(),
            max_tokens: 16_000,
            max_turns: 25,
            temperature: None,
            top_p: None,
            seed: None,
            thinking_budget: None,
            betas: Vec::new(),
            json_mode: false,
            max_transient_retries: 4,
            max_context_shrinks: 16,
            retry_backoff_base: Duration::from_secs(10),
            timeout_secs: None,
            max_tokens_ceiling: None,
            reasoning_effort: None,
            openai_api: None,
            cache_prefix: None,
            cache_key: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_has_documented_defaults() {
        let cfg = AgenticConfig::new("gpt-4o");
        assert_eq!(cfg.model, "gpt-4o");
        assert!(cfg.system_prompt.is_none());
        assert!(cfg.allowed_tools.is_empty());
        assert_eq!(cfg.max_tokens, 16_000);
        assert_eq!(cfg.max_turns, 25);
        assert!(cfg.temperature.is_none());
        assert!(cfg.top_p.is_none());
        assert!(cfg.seed.is_none());
        assert!(cfg.thinking_budget.is_none());
        assert!(cfg.betas.is_empty());
        assert!(!cfg.json_mode);
        assert_eq!(cfg.max_transient_retries, 4);
        assert_eq!(cfg.max_context_shrinks, 16);
        assert_eq!(cfg.retry_backoff_base, Duration::from_secs(10));
        assert!(cfg.timeout_secs.is_none());
        assert!(cfg.max_tokens_ceiling.is_none());
        assert!(cfg.reasoning_effort.is_none());
        assert!(cfg.openai_api.is_none());
        assert!(cfg.cache_prefix.is_none());
        assert!(cfg.cache_key.is_none());
    }

    #[test]
    fn is_cloneable() {
        let cfg = AgenticConfig::new("gpt-4o");
        let cloned = cfg.clone();
        assert_eq!(cloned.model, cfg.model);
    }
}
