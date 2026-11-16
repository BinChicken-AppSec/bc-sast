use std::collections::BTreeSet;

use appsec_llm_client::{CacheTtl, Usage};
use appsec_pricing::{Call, CostTotal, Money, PriceTable, Pricer};

pub const UNKNOWN_PROVIDER: &str = "unidentified-provider";

#[derive(Debug, Clone, Default)]
pub struct PricingConfig {
    pub provider: Option<String>,
    pub overrides: PriceTable,
    pub cache_ttl: CacheTtl,
}

impl PricingConfig {
    pub fn for_provider(provider: Option<impl Into<String>>) -> Self {
        PricingConfig {
            provider: provider.map(Into::into),
            overrides: PriceTable::default(),
            cache_ttl: CacheTtl::default(),
        }
    }

    pub(crate) fn pricer(&self) -> Pricer<'static> {
        Pricer::vendored().with_overrides(self.overrides.clone())
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct PhaseCost {
    priced: CostTotal,
    unpriced_calls: u64,
    unpriced_call_tokens: u64,
}

impl PhaseCost {
    pub(crate) fn total(self) -> Money {
        self.priced.total()
    }

    pub(crate) fn priced_calls(self) -> u64 {
        self.priced.calls
    }

    pub(crate) fn unpriced_calls(self) -> u64 {
        self.unpriced_calls
    }

    pub(crate) fn unpriced_tokens(self) -> u64 {
        self.unpriced_call_tokens + self.priced.unrated_tokens
    }

    pub(crate) fn merge(&mut self, other: Self) {
        self.priced.input += other.priced.input;
        self.priced.output += other.priced.output;
        self.priced.cache_read += other.priced.cache_read;
        self.priced.cache_write += other.priced.cache_write;
        self.priced.calls += other.priced.calls;
        self.priced.unrated_tokens += other.priced.unrated_tokens;
        self.unpriced_calls += other.unpriced_calls;
        self.unpriced_call_tokens += other.unpriced_call_tokens;
    }

    pub(crate) fn record_call(
        &mut self,
        pricer: &Pricer<'_>,
        provider: Option<&str>,
        model: &str,
        usage: Usage,
        cache_ttl: CacheTtl,
    ) -> Option<String> {
        let call = call_of(usage, cache_ttl);
        if let Some(provider) = provider {
            if let Ok(cost) = pricer.price_call(provider, model, &call) {
                self.priced.add_call(cost);
                return None;
            }
        }
        self.unpriced_calls += 1;
        self.unpriced_call_tokens += billable_tokens(usage);
        Some(format!("{}/{model}", provider.unwrap_or(UNKNOWN_PROVIDER)))
    }
}

fn call_of(usage: Usage, cache_ttl: CacheTtl) -> Call {
    let call = Call::from_usage(
        usage.input_tokens,
        usage.output_tokens,
        usage.cache_read_input_tokens,
        usage.cache_creation_input_tokens,
    );
    match cache_ttl {
        CacheTtl::FiveMinutes => call,
        CacheTtl::OneHour => call.long_ttl_cache_writes(usage.cache_creation_input_tokens),
    }
}

fn billable_tokens(usage: Usage) -> u64 {
    usage.input_tokens
        + usage.output_tokens
        + usage.cache_creation_input_tokens
        + usage.cache_read_input_tokens
}

const PROVIDER_HOSTS: &[(&str, &str)] = &[
    ("aihubmix.com", "aihubmix"),
    ("ai-gateway.vercel.sh", "vercel"),
    ("anthropic.com", "anthropic"),
    ("baseten.co", "baseten"),
    ("bigmodel.cn", "zhipuai"),
    ("cerebras.ai", "cerebras"),
    ("cognitiveservices.azure.com", "azure"),
    ("dashscope.aliyuncs.com", "alibaba"),
    ("dashscope-intl.aliyuncs.com", "alibaba"),
    ("deepinfra.com", "deepinfra"),
    ("deepseek.com", "deepseek"),
    ("fireworks.ai", "fireworks-ai"),
    ("generativelanguage.googleapis.com", "google"),
    ("groq.com", "groq"),
    ("huggingface.co", "huggingface"),
    ("inceptionlabs.ai", "inception"),
    ("llama.com", "llama"),
    ("llmgateway.io", "llmgateway"),
    ("minimax.io", "minimax"),
    ("minimaxi.com", "minimax"),
    ("mistral.ai", "mistral"),
    ("moonshot.ai", "moonshotai"),
    ("moonshot.cn", "moonshotai"),
    ("morphllm.com", "morph"),
    ("openai.azure.com", "azure"),
    ("openai.com", "openai"),
    ("openrouter.ai", "openrouter"),
    ("perplexity.ai", "perplexity"),
    ("requesty.ai", "requesty"),
    ("services.ai.azure.com", "azure"),
    ("studio.nebius.ai", "nebius"),
    ("studio.nebius.com", "nebius"),
    ("together.ai", "togetherai"),
    ("together.xyz", "togetherai"),
    ("upstage.ai", "upstage"),
    ("venice.ai", "venice"),
    ("x.ai", "xai"),
    ("z.ai", "zhipuai"),
];

pub fn infer_provider(base_url: &str) -> Option<&'static str> {
    let host = host_of(base_url)?;
    PROVIDER_HOSTS
        .iter()
        .find(|(domain, _)| is_host_or_subdomain_of(&host, domain))
        .map(|(_, provider)| *provider)
}

fn host_of(base_url: &str) -> Option<String> {
    let after_scheme = base_url.split_once("://").map_or(base_url, |(_, r)| r);
    let authority = after_scheme.split(['/', '?', '#']).next()?;
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = match authority.rsplit_once(':') {
        Some((head, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => head,
        _ => authority,
    };
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

fn is_host_or_subdomain_of(host: &str, domain: &str) -> bool {
    let host = host.strip_suffix('.').unwrap_or(host);
    match host.len().checked_sub(domain.len()) {
        Some(0) => host == domain,
        Some(cut) => host.as_bytes()[cut - 1] == b'.' && &host[cut..] == domain,
        None => false,
    }
}

#[derive(Debug, Default)]
pub(crate) struct UnpricedModels(std::sync::Mutex<BTreeSet<String>>);

impl UnpricedModels {
    pub(crate) fn add(&self, label: String) {
        self.0.lock().unwrap().insert(label);
    }

    pub(crate) fn snapshot(&self) -> Vec<String> {
        self.0.lock().unwrap().iter().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use appsec_pricing::ModelPrice;

    fn million_of_everything() -> Usage {
        Usage {
            input_tokens: 1_000_000,
            output_tokens: 1_000_000,
            cache_creation_input_tokens: 0,
            cache_read_input_tokens: 0,
            reasoning_output_tokens: 0,
        }
    }

    #[test]
    fn a_known_provider_and_model_is_priced_from_the_vendored_table() {
        let config = PricingConfig::for_provider(Some("anthropic"));
        let pricer = config.pricer();
        let mut cost = PhaseCost::default();
        assert_eq!(
            cost.record_call(
                &pricer,
                config.provider.as_deref(),
                "claude-sonnet-4-5",
                million_of_everything(),
                CacheTtl::FiveMinutes
            ),
            None
        );
        assert_eq!(cost.total().to_usd_string(2), "18.00");
        assert_eq!(cost.priced_calls(), 1);
        assert_eq!(cost.unpriced_calls(), 0);
        assert_eq!(cost.unpriced_tokens(), 0);
    }

    #[test]
    fn a_model_the_table_does_not_know_is_unpriced_not_free() {
        let pricer = PricingConfig::default().pricer();
        let mut cost = PhaseCost::default();
        let label = cost.record_call(
            &pricer,
            Some("openai"),
            "house-blend-9",
            million_of_everything(),
            CacheTtl::FiveMinutes,
        );
        assert_eq!(label.as_deref(), Some("openai/house-blend-9"));
        assert_eq!(cost.total(), Money::ZERO);
        assert_eq!(cost.priced_calls(), 0);
        assert_eq!(cost.unpriced_calls(), 1);
        assert_eq!(cost.unpriced_tokens(), 2_000_000);
    }

    #[test]
    fn no_provider_at_all_prices_nothing_and_says_which_model() {
        let pricer = PricingConfig::default().pricer();
        let mut cost = PhaseCost::default();
        let label = cost.record_call(
            &pricer,
            None,
            "claude-sonnet-4-5",
            million_of_everything(),
            CacheTtl::FiveMinutes,
        );
        assert_eq!(
            label.as_deref(),
            Some("unidentified-provider/claude-sonnet-4-5")
        );
        assert_eq!(cost.total(), Money::ZERO);
        assert_eq!(cost.unpriced_tokens(), 2_000_000);
    }

    #[test]
    fn an_override_replaces_the_published_rate_for_a_negotiated_one() {
        let mut overrides = PriceTable::default();
        overrides.insert(
            "acme-gateway",
            "claude-sonnet-4-5",
            ModelPrice::flat(1_500_000, 7_500_000),
        );
        let config = PricingConfig {
            provider: Some("acme-gateway".to_string()),
            overrides,
            cache_ttl: CacheTtl::FiveMinutes,
        };
        let pricer = config.pricer();
        let mut cost = PhaseCost::default();
        assert_eq!(
            cost.record_call(
                &pricer,
                config.provider.as_deref(),
                "claude-sonnet-4-5",
                million_of_everything(),
                CacheTtl::FiveMinutes
            ),
            None
        );
        assert_eq!(cost.total().to_usd_string(2), "9.00");
    }

    #[test]
    fn a_call_with_no_published_cache_rate_counts_those_tokens_unpriced() {
        let mut overrides = PriceTable::default();
        overrides.insert("gw", "flat-model", ModelPrice::flat(1_000_000, 1_000_000));
        let config = PricingConfig {
            provider: Some("gw".to_string()),
            overrides,
            cache_ttl: CacheTtl::FiveMinutes,
        };
        let mut cost = PhaseCost::default();
        cost.record_call(
            &config.pricer(),
            Some("gw"),
            "flat-model",
            Usage {
                input_tokens: 1_000_000,
                output_tokens: 0,
                cache_creation_input_tokens: 0,
                cache_read_input_tokens: 4_000,
                reasoning_output_tokens: 0,
            },
            CacheTtl::FiveMinutes,
        );
        assert_eq!(cost.priced_calls(), 1);
        assert_eq!(cost.unpriced_calls(), 0);
        assert_eq!(cost.unpriced_tokens(), 4_000);
        assert_eq!(cost.total().to_usd_string(2), "1.00");
    }

    #[test]
    fn a_phase_straddling_a_tier_costs_more_than_its_aggregate_would_suggest() {
        let config = PricingConfig::for_provider(Some("aihubmix"));
        let pricer = config.pricer();
        let under = Usage {
            input_tokens: 200_000,
            ..Usage::default()
        };
        let over = Usage {
            input_tokens: 200_001,
            ..Usage::default()
        };
        let mut per_call = PhaseCost::default();
        per_call.record_call(
            &pricer,
            Some("aihubmix"),
            "claude-opus-4-6",
            under,
            CacheTtl::FiveMinutes,
        );
        per_call.record_call(
            &pricer,
            Some("aihubmix"),
            "claude-opus-4-6",
            over,
            CacheTtl::FiveMinutes,
        );
        assert_eq!(per_call.priced_calls(), 2);

        let mut as_aggregate = PhaseCost::default();
        as_aggregate.record_call(
            &pricer,
            Some("aihubmix"),
            "claude-opus-4-6",
            Usage {
                input_tokens: 400_001,
                ..Usage::default()
            },
            CacheTtl::FiveMinutes,
        );

        assert_eq!(per_call.total().to_usd_string(6), "3.000010");
        assert_eq!(as_aggregate.total().to_usd_string(6), "4.000010");
        assert!(as_aggregate.total() > per_call.total());
    }

    #[test]
    fn merging_two_phases_adds_their_money_and_their_gaps() {
        let config = PricingConfig::for_provider(Some("anthropic"));
        let pricer = config.pricer();
        let mut a = PhaseCost::default();
        a.record_call(
            &pricer,
            Some("anthropic"),
            "claude-sonnet-4-5",
            million_of_everything(),
            CacheTtl::FiveMinutes,
        );
        let mut b = PhaseCost::default();
        b.record_call(
            &pricer,
            Some("anthropic"),
            "not-a-model",
            million_of_everything(),
            CacheTtl::FiveMinutes,
        );
        b.record_call(
            &pricer,
            Some("anthropic"),
            "claude-sonnet-4-5",
            million_of_everything(),
            CacheTtl::FiveMinutes,
        );

        let mut run = PhaseCost::default();
        run.merge(a);
        run.merge(b);
        assert_eq!(run.total().to_usd_string(2), "36.00");
        assert_eq!(run.priced_calls(), 2);
        assert_eq!(run.unpriced_calls(), 1);
        assert_eq!(run.unpriced_tokens(), 2_000_000);
        assert_eq!(run, {
            let mut same = PhaseCost::default();
            same.merge(b);
            same.merge(a);
            same
        });
        assert_ne!(run, a);
        assert!(format!("{run:?}").contains("unpriced_calls"));
        assert_eq!(Clone::clone(&run), run);
    }

    #[test]
    fn a_cache_heavy_call_prices_every_class_at_its_own_rate() {
        let config = PricingConfig::for_provider(Some("anthropic"));
        let mut cost = PhaseCost::default();
        cost.record_call(
            &config.pricer(),
            Some("anthropic"),
            "claude-sonnet-4-5",
            Usage {
                input_tokens: 0,
                output_tokens: 0,
                cache_creation_input_tokens: 1_000_000,
                cache_read_input_tokens: 1_000_000,
                reasoning_output_tokens: 0,
            },
            CacheTtl::FiveMinutes,
        );
        assert_eq!(cost.total().to_usd_string(2), "4.05");
    }

    #[test]
    fn a_one_hour_cache_write_bills_at_twice_the_input_rate() {
        let config = PricingConfig::for_provider(Some("anthropic"));
        let writes = Usage {
            input_tokens: 0,
            output_tokens: 0,
            cache_creation_input_tokens: 1_000_000,
            cache_read_input_tokens: 0,
            reasoning_output_tokens: 0,
        };
        let mut five = PhaseCost::default();
        five.record_call(
            &config.pricer(),
            Some("anthropic"),
            "claude-sonnet-4-5",
            writes,
            CacheTtl::FiveMinutes,
        );
        let mut hour = PhaseCost::default();
        hour.record_call(
            &config.pricer(),
            Some("anthropic"),
            "claude-sonnet-4-5",
            writes,
            CacheTtl::OneHour,
        );
        assert_eq!(five.total().to_usd_string(2), "3.75");
        assert_eq!(hour.total().to_usd_string(2), "6.00");
        assert_eq!(config.cache_ttl, CacheTtl::FiveMinutes);
    }

    #[tokio::test]
    async fn the_usage_tracking_client_prices_one_hour_writes_from_the_config() {
        use appsec_llm_client::{ChatRequest, ChatResponse, ContentBlock, LlmClient, LlmError};

        struct Cached;
        #[async_trait::async_trait]
        impl LlmClient for Cached {
            async fn chat(&self, _request: &ChatRequest) -> Result<ChatResponse, LlmError> {
                Ok(ChatResponse {
                    content: vec![ContentBlock::text("ok")],
                    stop_reason: appsec_llm_client::StopReason::EndTurn,
                    usage: Usage {
                        input_tokens: 1_000_000,
                        output_tokens: 0,
                        cache_creation_input_tokens: 1_000_000,
                        cache_read_input_tokens: 1_000_000,
                        reasoning_output_tokens: 0,
                    },
                })
            }
        }

        let cost_with = |ttl| async move {
            let config = PricingConfig {
                cache_ttl: ttl,
                ..PricingConfig::for_provider(Some("anthropic"))
            };
            let tracker = crate::UsageTrackingClient::new(std::sync::Arc::new(Cached), &config);
            let request = ChatRequest::new("claude-sonnet-4-5", Vec::new(), 16);
            tracker.chat(&request).await.unwrap();
            tracker.take().cost.total().to_usd_string(2)
        };
        assert_eq!(cost_with(CacheTtl::FiveMinutes).await, "7.05");
        assert_eq!(cost_with(CacheTtl::OneHour).await, "9.30");
    }

    #[test]
    fn a_first_party_host_resolves_to_its_vendored_provider_id() {
        let cases = [
            ("https://api.openai.com/v1", "openai"),
            ("https://api.anthropic.com", "anthropic"),
            ("http://api.deepseek.com:8080/v1/", "deepseek"),
            ("https://user:pass@openrouter.ai/api/v1", "openrouter"),
            ("https://API.X.AI/v1", "xai"),
            ("api.mistral.ai/v1", "mistral"),
            ("https://my-resource.openai.azure.com/openai", "azure"),
            (
                "https://generativelanguage.googleapis.com/v1beta/openai",
                "google",
            ),
            ("https://api.openai.com./v1", "openai"),
            ("https://api.openai.com/v1?x=1#f", "openai"),
        ];
        for (base_url, expected) in cases {
            assert_eq!(infer_provider(base_url), Some(expected), "{base_url}");
        }
    }

    #[test]
    fn a_host_that_does_not_settle_the_question_infers_nothing() {
        let cases = [
            "https://oai.helicone.ai/v1",
            "https://gateway.ai.cloudflare.com/v1/acct/gw/openai",
            "https://llm.corp.internal/v1",
            "http://127.0.0.1:4000/v1",
            "http://[::1]:4000/v1",
            "https://notopenai.com/v1",
            "https://openai.com.evil.test/v1",
            "",
            "https:///v1",
            "/v1/chat",
        ];
        for base_url in cases {
            assert_eq!(infer_provider(base_url), None, "{base_url}");
        }
    }

    #[test]
    fn every_inferred_provider_id_exists_in_the_vendored_table() {
        let vendored = appsec_pricing::vendored_table();
        for (domain, provider) in PROVIDER_HOSTS {
            assert!(
                vendored.has_provider(provider),
                "{domain} maps to {provider}, which the vendored table does not publish"
            );
        }
    }

    #[test]
    fn no_mapped_domain_shadows_another() {
        for (a, _) in PROVIDER_HOSTS {
            for (b, provider_b) in PROVIDER_HOSTS {
                assert!(
                    a == b || !is_host_or_subdomain_of(a, b),
                    "{a} would also match {b} ({provider_b})"
                );
            }
        }
    }

    #[test]
    fn the_default_config_prices_nothing_and_carries_no_overrides() {
        let config = PricingConfig::default();
        assert_eq!(config.provider, None);
        assert!(config.overrides.is_empty());
        assert!(format!("{config:?}").contains("PricingConfig"));
        assert_eq!(config.clone().provider, None);
        assert_eq!(PricingConfig::for_provider(None::<String>).provider, None);
        assert_eq!(
            PricingConfig::for_provider(Some("openai"))
                .provider
                .as_deref(),
            Some("openai")
        );
    }

    #[test]
    fn unpriced_models_are_reported_once_each_in_sorted_order() {
        let seen = UnpricedModels::default();
        assert!(seen.snapshot().is_empty());
        seen.add("openai/z-model".to_string());
        seen.add("openai/a-model".to_string());
        seen.add("openai/z-model".to_string());
        assert_eq!(seen.snapshot(), ["openai/a-model", "openai/z-model"]);
        assert!(format!("{seen:?}").contains("UnpricedModels"));
    }
}
