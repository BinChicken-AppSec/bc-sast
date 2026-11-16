use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::call::{Call, CallCost};
use crate::money::Money;

pub type Rate = u64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unpriced {
    UnknownProvider,
    UnknownModel,
}

impl fmt::Display for Unpriced {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnknownProvider => "no price table entry for this provider",
            Self::UnknownModel => "no price table entry for this model under this provider",
        })
    }
}

impl std::error::Error for Unpriced {}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TableMeta {
    pub source: String,
    pub source_license: String,
    pub source_license_url: String,
    pub captured: String,
    pub generator: String,
    pub rate_unit: String,
    pub providers: usize,
    pub models: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tier {
    pub above: u64,
    pub input: Rate,
    pub output: Rate,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_read: Option<Rate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_write: Option<Rate>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelPrice {
    pub input: Rate,
    pub output: Rate,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_read: Option<Rate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_write: Option<Rate>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tiers: Vec<Tier>,
}

impl ModelPrice {
    pub const fn flat(input: Rate, output: Rate) -> Self {
        Self {
            input,
            output,
            cache_read: None,
            cache_write: None,
            tiers: Vec::new(),
        }
    }

    pub fn tier_for(&self, context_tokens: u64) -> Option<&Tier> {
        let mut chosen: Option<&Tier> = None;
        for tier in &self.tiers {
            if context_tokens > tier.above && chosen.is_none_or(|best| tier.above > best.above) {
                chosen = Some(tier);
            }
        }
        chosen
    }

    pub fn cost_of(&self, call: &Call) -> CallCost {
        let tier = self.tier_for(call.context_tokens());
        let (input, output, cache_read, cache_write) = match tier {
            Some(tier) => (tier.input, tier.output, tier.cache_read, tier.cache_write),
            None => (self.input, self.output, self.cache_read, self.cache_write),
        };
        let long_writes = call.long_ttl_cache_write_tokens();
        let short_writes = call.cache_write_tokens() - long_writes;
        let long_rate = cache_write.map(|_| input * LONG_TTL_WRITE_MULTIPLIER);
        let (read_cost, read_unrated) = charge(cache_read, call.cache_read_tokens());
        let (short_cost, short_unrated) = charge(cache_write, short_writes);
        let (long_cost, long_unrated) = charge(long_rate, long_writes);

        CallCost {
            input: extend(input, call.input_tokens()),
            output: extend(output, call.output_tokens()),
            cache_read: read_cost,
            cache_write: short_cost + long_cost,
            tier_applied: tier.map(|tier| tier.above),
            unrated_tokens: read_unrated + short_unrated + long_unrated,
        }
    }
}

pub const LONG_TTL_WRITE_MULTIPLIER: Rate = 2;

fn extend(rate: Rate, tokens: u64) -> Money {
    Money::from_picodollars(u128::from(rate) * u128::from(tokens))
}

fn charge(rate: Option<Rate>, tokens: u64) -> (Money, u64) {
    match rate {
        Some(rate) => (extend(rate, tokens), 0),
        None => (Money::ZERO, tokens),
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PriceTable {
    #[serde(default)]
    pub meta: TableMeta,
    #[serde(default)]
    providers: BTreeMap<String, BTreeMap<String, ModelPrice>>,
}

impl PriceTable {
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    pub fn insert(
        &mut self,
        provider: impl Into<String>,
        model: impl Into<String>,
        price: ModelPrice,
    ) -> Option<ModelPrice> {
        self.providers
            .entry(provider.into())
            .or_default()
            .insert(model.into(), price)
    }

    pub fn lookup(&self, provider: &str, model: &str) -> Result<&ModelPrice, Unpriced> {
        let models = find(&self.providers, provider).ok_or(Unpriced::UnknownProvider)?;
        find(models, model).ok_or(Unpriced::UnknownModel)
    }

    pub fn has_provider(&self, provider: &str) -> bool {
        find(&self.providers, provider).is_some()
    }

    pub fn provider_ids(&self) -> impl Iterator<Item = &str> {
        self.providers.keys().map(String::as_str)
    }

    pub fn model_ids<'a>(&'a self, provider: &str) -> impl Iterator<Item = &'a str> + 'a {
        find(&self.providers, provider)
            .into_iter()
            .flat_map(|models| models.keys().map(String::as_str))
    }

    pub fn provider_count(&self) -> usize {
        self.providers.len()
    }

    pub fn model_count(&self) -> usize {
        self.providers.values().map(BTreeMap::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.providers.is_empty()
    }
}

fn find<'a, V>(map: &'a BTreeMap<String, V>, key: &str) -> Option<&'a V> {
    if let Some(value) = map.get(key) {
        return Some(value);
    }
    map.iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(key))
        .map(|(_, value)| value)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONE_DOLLAR_PER_MILLION: Rate = 1_000_000;
    const TEN_DOLLARS_PER_MILLION: Rate = 10_000_000;

    fn tiered() -> ModelPrice {
        ModelPrice {
            input: 3_000_000,
            output: 15_000_000,
            cache_read: Some(300_000),
            cache_write: Some(3_750_000),
            tiers: vec![Tier {
                above: 200_000,
                input: 6_000_000,
                output: 22_500_000,
                cache_read: Some(600_000),
                cache_write: Some(7_500_000),
            }],
        }
    }

    #[test]
    fn one_hour_cache_writes_bill_at_twice_the_input_rate() {
        let call = Call::from_usage(0, 0, 0, 100_000).long_ttl_cache_writes(40_000);
        let cost = tiered().cost_of(&call);
        assert_eq!(cost.cache_write.to_usd_string(4), "0.4650");
        assert_eq!(cost.unrated_tokens, 0);
    }

    #[test]
    fn one_hour_writes_follow_the_tier_input_rate() {
        let call = Call::from_usage(250_000, 0, 0, 100_000).long_ttl_cache_writes(100_000);
        let cost = tiered().cost_of(&call);
        assert_eq!(cost.tier_applied, Some(200_000));
        assert_eq!(cost.cache_write.to_usd_string(4), "1.2000");
    }

    #[test]
    fn one_hour_writes_on_a_model_without_a_cache_are_unrated() {
        let price = ModelPrice::flat(ONE_DOLLAR_PER_MILLION, TEN_DOLLARS_PER_MILLION);
        let cost = price.cost_of(&Call::from_usage(0, 0, 0, 300).long_ttl_cache_writes(100));
        assert_eq!(cost.cache_write, Money::ZERO);
        assert_eq!(cost.unrated_tokens, 300);
    }

    #[test]
    fn a_flat_model_charges_input_and_output_only() {
        let price = ModelPrice::flat(ONE_DOLLAR_PER_MILLION, TEN_DOLLARS_PER_MILLION);
        let cost = price.cost_of(&Call::from_usage(1_000_000, 1_000_000, 0, 0));
        assert_eq!(cost.input, Money::from_picodollars(1_000_000_000_000));
        assert_eq!(cost.output, Money::from_picodollars(10_000_000_000_000));
        assert_eq!(cost.total().to_usd_string(2), "11.00");
        assert_eq!(cost.tier_applied, None);
        assert!(cost.is_fully_rated());
    }

    #[test]
    fn cache_reads_are_charged_at_the_cache_read_rate() {
        let price = ModelPrice {
            cache_write: None,
            tiers: Vec::new(),
            ..tiered()
        };
        let cost = price.cost_of(&Call::from_usage(0, 0, 1_000_000, 0));
        assert_eq!(cost.cache_read.to_usd_string(2), "0.30");
        assert_eq!(cost.input, Money::ZERO);
        assert_eq!(cost.total().to_usd_string(2), "0.30");
        assert!(cost.is_fully_rated());
    }

    #[test]
    fn cache_writes_are_charged_at_the_cache_write_rate() {
        let price = ModelPrice {
            tiers: Vec::new(),
            ..tiered()
        };
        let cost = price.cost_of(&Call::from_usage(0, 0, 0, 1_000_000));
        assert_eq!(cost.cache_write.to_usd_string(2), "3.75");
        assert_eq!(cost.total().to_usd_string(2), "3.75");
        assert_eq!(cost.tier_applied, None);

        let tiered_cost = tiered().cost_of(&Call::from_usage(0, 0, 0, 1_000_000));
        assert_eq!(tiered_cost.tier_applied, Some(200_000));
        assert_eq!(tiered_cost.cache_write.to_usd_string(2), "7.50");
    }

    #[test]
    fn tokens_with_no_published_rate_are_counted_not_guessed() {
        let price = ModelPrice::flat(ONE_DOLLAR_PER_MILLION, TEN_DOLLARS_PER_MILLION);
        let cost = price.cost_of(&Call::from_usage(1_000_000, 0, 4_000, 500));
        assert_eq!(cost.cache_read, Money::ZERO);
        assert_eq!(cost.cache_write, Money::ZERO);
        assert_eq!(cost.unrated_tokens, 4_500);
        assert!(!cost.is_fully_rated());
        assert_eq!(cost.total().to_usd_string(2), "1.00");
    }

    #[test]
    fn a_call_below_the_threshold_uses_base_rates() {
        let cost = tiered().cost_of(&Call::with_context(199_999).input(1_000_000));
        assert_eq!(cost.tier_applied, None);
        assert_eq!(cost.total().to_usd_string(2), "3.00");
    }

    #[test]
    fn a_call_exactly_on_the_threshold_uses_base_rates() {
        let cost = tiered().cost_of(&Call::with_context(200_000).input(1_000_000));
        assert_eq!(cost.tier_applied, None);
        assert_eq!(cost.total().to_usd_string(2), "3.00");
        assert!(tiered().tier_for(200_000).is_none());
    }

    #[test]
    fn a_call_above_the_threshold_uses_tier_rates() {
        let call = Call::with_context(200_001)
            .input(1_000_000)
            .output(1_000_000)
            .cache_read(1_000_000)
            .cache_write(1_000_000);
        let cost = tiered().cost_of(&call);
        assert_eq!(cost.tier_applied, Some(200_000));
        assert_eq!(cost.input.to_usd_string(2), "6.00");
        assert_eq!(cost.output.to_usd_string(2), "22.50");
        assert_eq!(cost.cache_read.to_usd_string(2), "0.60");
        assert_eq!(cost.cache_write.to_usd_string(2), "7.50");
        assert_eq!(cost.total().to_usd_string(2), "36.60");
    }

    #[test]
    fn a_tier_rate_can_itself_be_unpublished() {
        let price = ModelPrice {
            tiers: vec![Tier {
                above: 100,
                input: 1,
                output: 1,
                cache_read: None,
                cache_write: None,
            }],
            ..tiered()
        };
        let cost = price.cost_of(&Call::with_context(1_000).cache_read(9));
        assert_eq!(cost.tier_applied, Some(100));
        assert_eq!(cost.unrated_tokens, 9);
    }

    #[test]
    fn the_highest_cleared_tier_wins_whatever_order_it_is_listed_in() {
        let ascending = ModelPrice {
            input: 100,
            output: 100,
            cache_read: None,
            cache_write: None,
            tiers: vec![
                Tier {
                    above: 32_000,
                    input: 200,
                    output: 200,
                    cache_read: None,
                    cache_write: None,
                },
                Tier {
                    above: 128_000,
                    input: 400,
                    output: 400,
                    cache_read: None,
                    cache_write: None,
                },
            ],
        };
        let mut descending = ascending.clone();
        descending.tiers.reverse();

        for price in [&ascending, &descending] {
            assert_eq!(price.tier_for(1_000), None);
            assert_eq!(price.tier_for(32_001).map(|t| t.above), Some(32_000));
            assert_eq!(price.tier_for(128_000).map(|t| t.above), Some(32_000));
            assert_eq!(price.tier_for(128_001).map(|t| t.above), Some(128_000));
        }
    }

    #[test]
    fn lookup_distinguishes_an_unknown_provider_from_an_unknown_model() {
        let mut table = PriceTable::default();
        assert!(table.is_empty());
        assert_eq!(
            table.insert("anthropic", "claude-sonnet-4-5", tiered()),
            None
        );
        assert_eq!(
            table.insert("anthropic", "claude-sonnet-4-5", tiered()),
            Some(tiered())
        );
        assert!(!table.is_empty());

        assert!(table.lookup("anthropic", "claude-sonnet-4-5").is_ok());
        assert_eq!(
            table.lookup("anthropic", "gpt-5"),
            Err(Unpriced::UnknownModel)
        );
        assert_eq!(
            table.lookup("nope", "claude-sonnet-4-5"),
            Err(Unpriced::UnknownProvider)
        );
        assert!(table.has_provider("anthropic"));
        assert!(!table.has_provider("nope"));
    }

    #[test]
    fn lookup_falls_back_to_a_case_insensitive_match() {
        let mut table = PriceTable::default();
        table.insert("anthropic", "Claude-Sonnet-4-5", tiered());
        assert!(table.lookup("Anthropic", "claude-SONNET-4-5").is_ok());
        assert!(table.lookup("anthropic", "Claude-Sonnet-4-5").is_ok());
    }

    #[test]
    fn table_inventory_is_reportable() {
        let mut table = PriceTable::default();
        table.insert("anthropic", "claude-sonnet-4-5", tiered());
        table.insert("anthropic", "claude-opus-4-5", tiered());
        table.insert("openai", "gpt-5", ModelPrice::flat(1, 2));
        assert_eq!(table.provider_count(), 2);
        assert_eq!(table.model_count(), 3);
        assert_eq!(
            table.provider_ids().collect::<Vec<_>>(),
            ["anthropic", "openai"]
        );
        assert_eq!(
            table.model_ids("anthropic").collect::<Vec<_>>(),
            ["claude-opus-4-5", "claude-sonnet-4-5"]
        );
        assert_eq!(table.model_ids("nope").count(), 0);
    }

    #[test]
    fn json_round_trips_through_every_shape() {
        let json = r#"{
            "meta": {"source": "https://models.dev/api.json", "captured": "2026-09-09"},
            "providers": {
                "anthropic": {
                    "claude-sonnet-4-5": {"input":3000000,"output":15000000,"cache_read":300000,"cache_write":3750000,
                        "tiers":[{"above":200000,"input":6000000,"output":22500000,"cache_read":600000,"cache_write":7500000}]},
                    "flat": {"input":1,"output":2}
                }
            }
        }"#;
        let table = PriceTable::from_json(json).expect("valid table");
        assert_eq!(table.meta.captured, "2026-09-09");
        assert_eq!(table.meta.source, "https://models.dev/api.json");
        assert_eq!(table.meta.providers, 0);
        assert_eq!(
            table.lookup("anthropic", "flat").expect("present").output,
            2
        );

        let reserialized = serde_json::to_string(&table).expect("serializable");
        let again = PriceTable::from_json(&reserialized).expect("round trip");
        assert_eq!(again, table);
        assert!(!reserialized.contains("null"));
        assert!(reserialized.contains("\"tiers\""));
        assert!(format!("{table:?}").contains("anthropic"));

        let meta_only = TableMeta::default();
        assert_eq!(serde_json::to_string(&meta_only).expect("meta"), "{\"source\":\"\",\"source_license\":\"\",\"source_license_url\":\"\",\"captured\":\"\",\"generator\":\"\",\"rate_unit\":\"\",\"providers\":0,\"models\":0}");
        assert_ne!(meta_only, table.meta);
    }

    #[test]
    fn a_typo_in_an_override_file_fails_loudly() {
        let json = r#"{"providers":{"gw":{"m":{"input":1,"output":2,"cache-read":3}}}}"#;
        let error = PriceTable::from_json(json).expect_err("unknown field");
        assert!(error.to_string().contains("cache-read"), "{error}");

        let missing = r#"{"providers":{"gw":{"m":{"input":1}}}}"#;
        assert!(PriceTable::from_json(missing).is_err());
    }

    #[test]
    fn unpriced_reads_as_an_error() {
        assert_eq!(
            Unpriced::UnknownProvider.to_string(),
            "no price table entry for this provider"
        );
        assert_eq!(
            Unpriced::UnknownModel.to_string(),
            "no price table entry for this model under this provider"
        );
        let boxed: Box<dyn std::error::Error> = Box::new(Unpriced::UnknownModel);
        assert!(boxed.to_string().contains("model"));
        assert_eq!(Unpriced::UnknownModel, Unpriced::UnknownModel);
        assert_ne!(Unpriced::UnknownModel, Unpriced::UnknownProvider);
        assert!(format!("{:?}", Unpriced::UnknownModel).contains("UnknownModel"));
        let copied = Unpriced::UnknownModel;
        assert_eq!(Clone::clone(&copied), Unpriced::UnknownModel);
    }

    #[test]
    fn tier_and_model_price_carry_the_usual_derives() {
        let tier = tiered().tiers[0].clone();
        assert_eq!(tier, tiered().tiers[0]);
        assert_ne!(tier.above, 0);
        assert!(format!("{tier:?}").contains("above"));
        assert_eq!(tiered(), tiered().clone());
        assert_ne!(tiered(), ModelPrice::flat(1, 2));
        assert!(format!("{:?}", ModelPrice::flat(1, 2)).contains("input"));
    }
}
