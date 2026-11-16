use std::time::Duration;

#[derive(Debug, Clone)]
pub struct AgenticConfig {
    pub model: String,
    pub system_prompt: Option<String>,
    pub allowed_tools: Vec<String>,
    pub max_tokens: u32,
    pub max_turns: u32,
    pub temperature: Option<f64>,
    pub top_p: Option<f64>,
    pub seed: Option<u64>,
    pub thinking_budget: Option<u32>,
    pub betas: Vec<String>,
    pub json_mode: bool,
    pub max_transient_retries: u32,
    pub max_context_shrinks: u32,
    pub retry_backoff_base: Duration,
    pub timeout_secs: Option<u64>,
    pub max_tokens_ceiling: Option<u32>,
    pub reasoning_effort: Option<appsec_llm_client::ReasoningEffort>,
    pub openai_api: Option<appsec_llm_client::OpenAiApi>,
    pub cache_prefix: Option<String>,
    pub cache_key: Option<String>,
}

impl AgenticConfig {
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
