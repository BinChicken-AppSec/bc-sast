pub mod call;
pub mod money;
pub mod table;

use std::sync::LazyLock;

pub use call::{Call, CallCost, CostTotal};
pub use money::Money;
pub use table::{
    ModelPrice, PriceTable, Rate, TableMeta, Tier, Unpriced, LONG_TTL_WRITE_MULTIPLIER,
};

pub const VENDORED_JSON: &str = include_str!("../data/models-dev-prices.json");

pub const ANY_PROVIDER: &str = "*";

static VENDORED: LazyLock<PriceTable> = LazyLock::new(|| {
    PriceTable::from_json(VENDORED_JSON)
        .expect("the vendored price table is committed with this crate and is tested on every run")
});

pub fn vendored_table() -> &'static PriceTable {
    &VENDORED
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PriceSource {
    Base,
    Override,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PriceRef<'a> {
    pub source: PriceSource,
    pub price: &'a ModelPrice,
}

#[derive(Clone, Debug)]
pub struct Pricer<'t> {
    base: &'t PriceTable,
    overrides: PriceTable,
}

impl Pricer<'static> {
    pub fn vendored() -> Self {
        Self::new(vendored_table())
    }
}

impl<'t> Pricer<'t> {
    pub fn new(base: &'t PriceTable) -> Self {
        Self {
            base,
            overrides: PriceTable::default(),
        }
    }

    pub fn with_overrides(mut self, overrides: PriceTable) -> Self {
        self.overrides = overrides;
        self
    }

    pub fn overrides(&self) -> &PriceTable {
        &self.overrides
    }

    pub fn base(&self) -> &PriceTable {
        self.base
    }

    pub fn resolve(&self, provider: &str, model: &str) -> Result<PriceRef<'_>, Unpriced> {
        for key in [provider, ANY_PROVIDER] {
            if let Ok(price) = self.overrides.lookup(key, model) {
                return Ok(PriceRef {
                    source: PriceSource::Override,
                    price,
                });
            }
        }
        match self.base.lookup(provider, model) {
            Ok(price) => Ok(PriceRef {
                source: PriceSource::Base,
                price,
            }),
            Err(_) => Err(self.unpriced_reason(provider)),
        }
    }

    pub fn price_call(
        &self,
        provider: &str,
        model: &str,
        call: &Call,
    ) -> Result<CallCost, Unpriced> {
        Ok(self.resolve(provider, model)?.price.cost_of(call))
    }

    fn unpriced_reason(&self, provider: &str) -> Unpriced {
        if self.base.has_provider(provider) || self.overrides.has_provider(provider) {
            Unpriced::UnknownModel
        } else {
            Unpriced::UnknownProvider
        }
    }
}

#[cfg(test)]
#[allow(clippy::clone_on_copy)]
mod tests {
    use super::*;

    #[test]
    fn the_worked_example_prices_a_call_to_the_cent() {
        let pricer = Pricer::vendored();
        let call = Call::from_usage(12_000, 800, 40_000, 0);
        let cost = pricer
            .price_call("anthropic", "claude-sonnet-4-5", &call)
            .expect("a model the vendored table knows");
        assert_eq!(cost.total().to_usd_string(4), "0.0600");
    }

    fn gateway_override() -> PriceTable {
        let mut table = PriceTable::default();
        table.insert(
            "acme-gateway",
            "claude-sonnet-4-5",
            ModelPrice {
                input: 1_500_000,
                output: 7_500_000,
                cache_read: Some(150_000),
                cache_write: Some(1_875_000),
                tiers: Vec::new(),
            },
        );
        table
    }

    #[test]
    fn the_vendored_file_deserializes_every_entry() {
        let table = PriceTable::from_json(VENDORED_JSON).expect("vendored table parses");
        assert_eq!(table.provider_count(), table.meta.providers);
        assert_eq!(table.model_count(), table.meta.models);
        assert!(table.provider_count() > 100, "{}", table.provider_count());
        assert!(table.model_count() > 5_000, "{}", table.model_count());

        let mut tiered = 0;
        let mut cached = 0;
        for provider in table.provider_ids() {
            for model in table.model_ids(provider) {
                let price = table
                    .lookup(provider, model)
                    .expect("listed model resolves");
                for tier in &price.tiers {
                    assert!(tier.above > 0, "{provider}/{model} has a zero threshold");
                    tiered += 1;
                }
                if price.cache_read.is_some() || price.cache_write.is_some() {
                    cached += 1;
                }
            }
        }
        assert!(tiered > 100, "{tiered}");
        assert!(cached > 1_000, "{cached}");
    }

    #[test]
    fn the_vendored_file_records_its_provenance() {
        let meta = &vendored_table().meta;
        assert_eq!(meta.source, "https://models.dev/api.json");
        assert_eq!(meta.source_license, "MIT");
        assert!(meta.source_license_url.starts_with("https://"));
        let captured: Vec<&str> = meta.captured.split('-').collect();
        assert_eq!(captured.len(), 3, "{}", meta.captured);
        assert!(
            captured[0].len() == 4
                && captured[1].len() == 2
                && captured[2].len() == 2
                && meta
                    .captured
                    .chars()
                    .all(|c| c.is_ascii_digit() || c == '-'),
            "{} is not YYYY-MM-DD",
            meta.captured
        );
        assert!(meta.generator.ends_with("refresh_prices.py"));
        assert!(meta.rate_unit.contains("picodollars"));
    }

    #[test]
    fn the_vendored_table_is_parsed_once() {
        assert!(std::ptr::eq(vendored_table(), vendored_table()));
    }

    #[test]
    fn claude_opus_5_5_is_priced_with_its_cache_rates() {
        let pricer = Pricer::vendored();
        let call = Call::from_usage(1_000_000, 1_000_000, 1_000_000, 1_000_000);
        let cost = pricer
            .price_call("anthropic", "claude-opus-5-5", &call)
            .expect("supplemented model");
        assert_eq!(cost.total().to_usd_string(2), "29.20");
    }

    #[test]
    fn the_same_model_id_costs_different_amounts_under_different_providers() {
        let pricer = Pricer::vendored();
        let call = Call::from_usage(1_000_000, 0, 0, 0);
        let direct = pricer
            .price_call("anthropic", "claude-sonnet-4-5", &call)
            .expect("anthropic");
        let reseller = pricer
            .price_call("venice", "claude-sonnet-4-5", &call)
            .expect("venice");
        assert_eq!(direct.total().to_usd_string(2), "3.00");
        assert_eq!(reseller.total().to_usd_string(2), "3.75");
        assert_ne!(direct, reseller);
    }

    #[test]
    fn an_unknown_model_is_unpriced_not_free() {
        let pricer = Pricer::vendored();
        let call = Call::from_usage(1_000_000, 1_000_000, 0, 0);
        assert_eq!(
            pricer.price_call("anthropic", "claude-does-not-exist", &call),
            Err(Unpriced::UnknownModel)
        );
        assert_eq!(
            pricer.resolve("anthropic", "claude-does-not-exist"),
            Err(Unpriced::UnknownModel)
        );
    }

    #[test]
    fn an_unknown_provider_is_unpriced_not_free() {
        let pricer = Pricer::vendored();
        let call = Call::from_usage(1_000_000, 1_000_000, 0, 0);
        assert_eq!(
            pricer.price_call("acme-gateway", "claude-sonnet-4-5", &call),
            Err(Unpriced::UnknownProvider)
        );
    }

    #[test]
    fn an_override_wins_over_the_vendored_rate() {
        let base = vendored_table();
        let pricer = Pricer::new(base).with_overrides(gateway_override());
        let call = Call::from_usage(1_000_000, 0, 0, 0);

        let resolved = pricer
            .resolve("acme-gateway", "claude-sonnet-4-5")
            .expect("override resolves");
        assert_eq!(resolved.source, PriceSource::Override);
        assert_eq!(
            pricer
                .price_call("acme-gateway", "claude-sonnet-4-5", &call)
                .expect("override prices")
                .total()
                .to_usd_string(2),
            "1.50"
        );

        let direct = pricer
            .resolve("anthropic", "claude-sonnet-4-5")
            .expect("base resolves");
        assert_eq!(direct.source, PriceSource::Base);
        assert_eq!(
            pricer
                .price_call("anthropic", "claude-sonnet-4-5", &call)
                .expect("base prices")
                .total()
                .to_usd_string(2),
            "3.00"
        );

        assert_eq!(
            pricer.resolve("acme-gateway", "not-a-model"),
            Err(Unpriced::UnknownModel)
        );
        assert_eq!(pricer.overrides().provider_count(), 1);
        assert_eq!(pricer.base().provider_count(), base.provider_count());
    }

    #[test]
    fn an_override_can_correct_a_provider_the_vendored_table_already_has() {
        let mut overrides = PriceTable::default();
        overrides.insert("anthropic", "claude-sonnet-4-5", ModelPrice::flat(1, 1));
        let pricer = Pricer::vendored().with_overrides(overrides);
        let cost = pricer
            .price_call(
                "anthropic",
                "claude-sonnet-4-5",
                &Call::from_usage(1_000_000, 0, 0, 0),
            )
            .expect("override prices");
        assert_eq!(cost.total().to_usd_string(6), "0.000001");
    }

    #[test]
    fn a_wildcard_override_applies_to_any_provider() {
        let mut overrides = PriceTable::default();
        overrides.insert(ANY_PROVIDER, "house-model", ModelPrice::flat(2_000_000, 0));
        let pricer = Pricer::vendored().with_overrides(overrides);
        let call = Call::from_usage(1_000_000, 0, 0, 0);
        for provider in ["anthropic", "some-private-gateway"] {
            let cost = pricer
                .price_call(provider, "house-model", &call)
                .expect("wildcard prices");
            assert_eq!(cost.total().to_usd_string(2), "2.00");
        }
        assert_eq!(
            pricer.resolve("some-private-gateway", "other-model"),
            Err(Unpriced::UnknownProvider)
        );
    }

    #[test]
    fn overrides_parse_from_the_same_json_shape_as_the_vendored_file() {
        let json = r#"{"providers":{"acme-gateway":{"gpt-5":{"input":500000,"output":4000000}}}}"#;
        let pricer =
            Pricer::vendored().with_overrides(PriceTable::from_json(json).expect("parses"));
        let cost = pricer
            .price_call(
                "acme-gateway",
                "gpt-5",
                &Call::from_usage(2_000_000, 0, 0, 0),
            )
            .expect("prices");
        assert_eq!(cost.total().to_usd_string(2), "1.00");
    }

    #[test]
    fn a_straddling_stage_is_summed_in_dollars_not_tokens() {
        let pricer = Pricer::vendored();
        let (provider, model) = ("aihubmix", "claude-opus-4-6");
        let under = Call::with_context(200_000).input(1_000_000);
        let over = Call::with_context(200_001).input(1_000_000);

        let mut total = CostTotal::default();
        for call in [under, over] {
            total.add_call(
                pricer
                    .price_call(provider, model, &call)
                    .expect("a tiered model"),
            );
        }
        assert_eq!(total.calls, 2);

        let under_cost = pricer.price_call(provider, model, &under).expect("under");
        let over_cost = pricer.price_call(provider, model, &over).expect("over");
        assert_eq!(under_cost.tier_applied, None);
        assert_eq!(over_cost.tier_applied, Some(200_000));
        assert_eq!(under_cost.total().to_usd_string(2), "5.00");
        assert_eq!(over_cost.total().to_usd_string(2), "10.00");
        assert_eq!(total.total(), under_cost.total() + over_cost.total());
        assert_eq!(total.total().to_usd_string(2), "15.00");

        let as_one_aggregate = Call::with_context(400_001).input(2_000_000);
        let wrong = pricer
            .price_call(provider, model, &as_one_aggregate)
            .expect("a tiered model");
        assert_eq!(wrong.total().to_usd_string(2), "20.00");
        assert_ne!(wrong.total(), total.total());
    }

    #[test]
    fn price_source_and_ref_carry_the_usual_derives() {
        let pricer = Pricer::vendored();
        let resolved = pricer
            .resolve("anthropic", "claude-sonnet-4-5")
            .expect("ok");
        assert_eq!(resolved, resolved);
        assert_ne!(PriceSource::Base, PriceSource::Override);
        assert!(format!("{resolved:?}").contains("Base"));
        assert!(format!("{:?}", PriceSource::Override).contains("Override"));
        assert!(format!("{pricer:?}").contains("Pricer"));
        assert_eq!(
            Clone::clone(&pricer).base().provider_count(),
            pricer.base().provider_count()
        );
        assert_eq!(Clone::clone(&resolved).source, PriceSource::Base);
        assert_eq!(Clone::clone(&PriceSource::Base), PriceSource::Base);
    }
}
