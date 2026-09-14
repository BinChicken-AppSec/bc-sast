//! What a scan cost: which provider the gateway URL implies, the
//! operator's own rate corrections, and one phase's money.
//!
//! `bc-pricing` turns `(provider, model, one call's token counts)` into
//! dollars and nothing else. This module supplies the two things it
//! cannot know on its own, and both are load bearing.
//!
//! # The provider is not optional, and this scanner does not know it
//!
//! The same model id costs different amounts under different providers:
//! 775 ids in the captured price table are published by more than one, and
//! `claude-sonnet-4-5` alone is 3.00 dollars per million input tokens
//! direct from Anthropic and 3.75 through a reseller. A lookup by model
//! id alone would quietly pick one of them.
//!
//! What this scanner actually has is a base URL and a wire dialect
//! (`--gateway-base-url` and `--dialect`), neither of which is a provider
//! name. [`infer_provider`] recovers one from the URL's host where the
//! host is a first-party API endpoint whose operator is not in doubt, and
//! returns `None` for everything else, including every host that is a
//! pass-through proxy in front of somebody else's models. `None` prices
//! nothing: the tokens are reported as unpriced. That is deliberate. A
//! guess here does not produce an approximate invoice, it produces a
//! confident wrong one, and an operator reconciling a report against a
//! real bill has no way to tell which figure was guessed.
//!
//! [`PricingConfig::provider`] overrides the inference outright, which is
//! how a private or self-hosted endpoint gets priced at all, and
//! [`PricingConfig::overrides`] replaces the published rates, which is how
//! a gateway on negotiated terms gets priced correctly.
//!
//! # Money is accumulated per call, never per phase
//!
//! Long context pricing switches rate on the size of *one call's* prompt.
//! A stage that made forty calls, thirty under a provider's 200,000 token
//! threshold and ten over it, has no single correct rate, so a phase's
//! summed token counts cannot be priced at all: the answer would be wrong
//! by the whole tier difference, a factor of two on the Anthropic long
//! context tier. [`PhaseCost`] therefore holds money, not tokens. Each
//! call is priced as it returns, while its own context size is still
//! known, and only the resulting dollars are added up.
//!
//! That choice also settles the memory question. Costing at the point of
//! the call keeps one fixed-size accumulator per phase no matter how many
//! calls a scan makes; carrying per-call records to price later would
//! grow linearly with a scan that routinely makes thousands of them, and
//! would buy nothing, because nothing downstream reports a single call.

use std::collections::BTreeSet;

use bc_llm_client::Usage;
use bc_pricing::{Call, CostTotal, Money, PriceTable, Pricer};

/// How an unpriced call names a provider that could not be identified at
/// all, as opposed to one that was identified and simply has no published
/// rate for the model.
pub const UNKNOWN_PROVIDER: &str = "unidentified-provider";

/// Everything a scan needs to turn its token usage into dollars.
///
/// The default prices nothing: no provider, no overrides. That is the
/// right default for a caller that has not been told which endpoint it is
/// talking to, and it reports every token as unpriced rather than as
/// free.
#[derive(Debug, Clone, Default)]
pub struct PricingConfig {
    /// The provider id every call is priced under. `None` leaves the run
    /// unpriced. Set from `--pricing-provider`, else `pricing.provider`
    /// in `--config`, else [`infer_provider`] on the gateway base URL.
    pub provider: Option<String>,
    /// Operator supplied rates layered over the vendored table, for a
    /// gateway on terms the public table does not know. Empty by
    /// default.
    pub overrides: PriceTable,
}

impl PricingConfig {
    /// Price under `provider` with no rate corrections.
    pub fn for_provider(provider: Option<impl Into<String>>) -> Self {
        PricingConfig {
            provider: provider.map(Into::into),
            overrides: PriceTable::default(),
        }
    }

    /// A [`Pricer`] over the vendored table with these overrides layered
    /// on. Built once per scan; the vendored table itself is parsed once
    /// per process.
    pub(crate) fn pricer(&self) -> Pricer<'static> {
        Pricer::vendored().with_overrides(self.overrides.clone())
    }
}

/// One phase's money, plus what it could not price.
///
/// Built only by folding in already-priced calls, so there is no context
/// size here for a tier to be applied to and no way to price an aggregate
/// by accident. See this module's own doc comment for why that matters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct PhaseCost {
    /// Calls that resolved to a published rate, summed in dollars.
    priced: CostTotal,
    /// Calls whose provider and model resolved to no rate at all.
    unpriced_calls: u64,
    /// Billable tokens on those calls.
    unpriced_call_tokens: u64,
}

impl PhaseCost {
    /// The cost of every priced call so far. A lower bound whenever
    /// [`Self::unpriced_tokens`] is non-zero.
    pub(crate) fn total(self) -> Money {
        self.priced.total()
    }

    /// How many calls carried a published rate.
    pub(crate) fn priced_calls(self) -> u64 {
        self.priced.calls
    }

    /// How many calls carried none.
    pub(crate) fn unpriced_calls(self) -> u64 {
        self.unpriced_calls
    }

    /// Every token that contributed nothing to [`Self::total`]: the
    /// billable tokens of a wholly unpriced call, plus the individually
    /// unrated tokens of a priced one, which is what a model with no
    /// published cache rate leaves behind.
    pub(crate) fn unpriced_tokens(self) -> u64 {
        self.unpriced_call_tokens + self.priced.unrated_tokens
    }

    /// Fold another phase's money into this one, for a run total.
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

    /// Price one call and fold it in, returning the `provider/model`
    /// label when nothing about it could be priced, so the caller can
    /// name it in the report. A call the table knows returns `None`.
    pub(crate) fn record_call(
        &mut self,
        pricer: &Pricer<'_>,
        provider: Option<&str>,
        model: &str,
        usage: Usage,
    ) -> Option<String> {
        let call = call_of(usage);
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

/// One call's usage in the shape `bc-pricing` prices, taking the prompt
/// to be everything that was in it: fresh input, cache reads and cache
/// writes. Both dialect crates already report `input_tokens` net of
/// cached tokens (`bc-llm-openai` subtracts `cached_tokens` from
/// `prompt_tokens` explicitly), so this sum is the real prompt size and
/// therefore the real tier selector.
fn call_of(usage: Usage) -> Call {
    Call::from_usage(
        usage.input_tokens,
        usage.output_tokens,
        usage.cache_read_input_tokens,
        usage.cache_creation_input_tokens,
    )
}

/// Every token a call would have been billed for, at whatever rate. Used
/// only to say how much of a run went unpriced, so it counts cache reads
/// too: they cost money, and leaving them out would understate the size
/// of the hole rather than the cost of it.
fn billable_tokens(usage: Usage) -> u64 {
    usage.input_tokens
        + usage.output_tokens
        + usage.cache_creation_input_tokens
        + usage.cache_read_input_tokens
}

/// Hosts whose provider is not in doubt, mapped to the vendored table's
/// own provider id.
///
/// Matching is label-wise: `api.openai.com` matches `openai.com`, and
/// `notopenai.com` does not. Every id here exists in the vendored table,
/// so a match always resolves to real rates.
///
/// The list is deliberately short, and what is missing from it is the
/// point. A pass-through proxy such as Helicone or a Cloudflare AI
/// Gateway carries the upstream provider in its path or its headers, not
/// its host, so its host says nothing about who is billing; Vertex and
/// Bedrock encode a region in the host and authenticate in ways this
/// scanner's two dialects do not speak. None of those are guessed at.
/// Anything absent here needs `pricing.provider` or
/// `--pricing-provider`, and gets reported as unpriced until it has one.
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

/// The vendored table provider id a gateway base URL implies, or `None`
/// when
/// the host does not settle the question.
///
/// See [`PROVIDER_HOSTS`] for what is matched and this module's own doc
/// comment for why `None` reports unpriced tokens instead of guessing.
pub fn infer_provider(base_url: &str) -> Option<&'static str> {
    let host = host_of(base_url)?;
    PROVIDER_HOSTS
        .iter()
        .find(|(domain, _)| is_host_or_subdomain_of(&host, domain))
        .map(|(_, provider)| *provider)
}

/// The lowercased host of a URL, without scheme, userinfo, port or path.
/// `None` for anything with no host at all.
///
/// Hand rolled rather than pulled from a URL parser: this needs a host to
/// compare against a fixed list of domains, not a validated URL, and the
/// dependency would be new.
fn host_of(base_url: &str) -> Option<String> {
    let after_scheme = base_url.split_once("://").map_or(base_url, |(_, r)| r);
    let authority = after_scheme.split(['/', '?', '#']).next()?;
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    // Only a genuinely numeric tail is a port, so an IPv6 literal's own
    // colons are left alone. It matches nothing in the table either way.
    let host = match authority.rsplit_once(':') {
        Some((head, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => head,
        _ => authority,
    };
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// Whether `host` is `domain` or a subdomain of it, compared label by
/// label so `notopenai.com` is not a match for `openai.com`.
fn is_host_or_subdomain_of(host: &str, domain: &str) -> bool {
    let host = host.strip_suffix('.').unwrap_or(host);
    match host.len().checked_sub(domain.len()) {
        Some(0) => host == domain,
        Some(cut) => host.as_bytes()[cut - 1] == b'.' && &host[cut..] == domain,
        None => false,
    }
}

/// Every `provider/model` pair a run could not price, in sorted order.
/// This is the one thing an operator needs to fix the gap, since it is
/// exactly the key a `pricing.rates` override is written under.
#[derive(Debug, Default)]
pub(crate) struct UnpricedModels(std::sync::Mutex<BTreeSet<String>>);

impl UnpricedModels {
    pub(crate) fn add(&self, label: String) {
        // `unwrap`, matching every other lock in this crate: the guarded
        // code is a single `insert` and cannot panic, so the lock cannot
        // become poisoned.
        self.0.lock().unwrap().insert(label);
    }

    pub(crate) fn snapshot(&self) -> Vec<String> {
        self.0.lock().unwrap().iter().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_pricing::ModelPrice;

    /// A million tokens of each class, so a rate in dollars per million
    /// reads straight off the asserted total.
    fn million_of_everything() -> Usage {
        Usage {
            input_tokens: 1_000_000,
            output_tokens: 1_000_000,
            cache_creation_input_tokens: 0,
            cache_read_input_tokens: 0,
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
                million_of_everything()
            ),
            None
        );
        // 3.00 in, 15.00 out, per million.
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
        let label = cost.record_call(&pricer, None, "claude-sonnet-4-5", million_of_everything());
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
        };
        let pricer = config.pricer();
        let mut cost = PhaseCost::default();
        assert_eq!(
            cost.record_call(
                &pricer,
                config.provider.as_deref(),
                "claude-sonnet-4-5",
                million_of_everything()
            ),
            None
        );
        // Half of Anthropic's own 18.00 for the same call.
        assert_eq!(cost.total().to_usd_string(2), "9.00");
    }

    #[test]
    fn a_call_with_no_published_cache_rate_counts_those_tokens_unpriced() {
        // The partially rated case: the call itself prices, but the
        // cache-read tokens have no rate, so the total is a lower bound
        // and has to say so without the whole call reading as unpriced.
        let mut overrides = PriceTable::default();
        overrides.insert("gw", "flat-model", ModelPrice::flat(1_000_000, 1_000_000));
        let config = PricingConfig {
            provider: Some("gw".to_string()),
            overrides,
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
            },
        );
        assert_eq!(cost.priced_calls(), 1);
        assert_eq!(cost.unpriced_calls(), 0);
        assert_eq!(cost.unpriced_tokens(), 4_000);
        assert_eq!(cost.total().to_usd_string(2), "1.00");
    }

    #[test]
    fn a_phase_straddling_a_tier_costs_more_than_its_aggregate_would_suggest() {
        // The whole reason this module accumulates dollars rather than
        // tokens. Two calls to a tiered model, one either side of the
        // threshold: pricing their summed tokens as one call applies the
        // cheap tier to all of it and is wrong by the tier difference.
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
        per_call.record_call(&pricer, Some("aihubmix"), "claude-opus-4-6", under);
        per_call.record_call(&pricer, Some("aihubmix"), "claude-opus-4-6", over);
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
        );

        // 5.00 per million below the 200,000 threshold, 10.00 above it.
        // The aggregate charges the tier rate on the 200,000 tokens that
        // were under it, and is a whole dollar out on 400,001 tokens.
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
        );
        let mut b = PhaseCost::default();
        b.record_call(
            &pricer,
            Some("anthropic"),
            "not-a-model",
            million_of_everything(),
        );
        b.record_call(
            &pricer,
            Some("anthropic"),
            "claude-sonnet-4-5",
            million_of_everything(),
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
            },
        );
        // 3.75 per million written, 0.30 per million read.
        assert_eq!(cost.total().to_usd_string(2), "4.05");
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
            // Pass-through proxies: the host says nothing about who bills.
            "https://oai.helicone.ai/v1",
            "https://gateway.ai.cloudflare.com/v1/acct/gw/openai",
            // A private deployment, which is the common real-world case.
            "https://llm.corp.internal/v1",
            "http://127.0.0.1:4000/v1",
            "http://[::1]:4000/v1",
            // Lookalikes that must not match the real thing.
            "https://notopenai.com/v1",
            "https://openai.com.evil.test/v1",
            // No host at all.
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
        // A typo in the table above would otherwise be invisible: the
        // inference would succeed and every call would then report as
        // unpriced under a provider that does not exist.
        let vendored = bc_pricing::vendored_table();
        for (domain, provider) in PROVIDER_HOSTS {
            assert!(
                vendored.has_provider(provider),
                "{domain} maps to {provider}, which the vendored table does not publish"
            );
        }
    }

    #[test]
    fn no_mapped_domain_shadows_another() {
        // Order in the table is not significant only because no domain is
        // a subdomain match for another one; this is what keeps that true.
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
