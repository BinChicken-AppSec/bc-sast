//! Token pricing: what a scan actually cost, per call, per model, in
//! exact dollars.
//!
//! The pipeline can route a different model to each of its stages, so a
//! run's token counts on their own do not add up to a number. This crate
//! turns `(provider, model, one call's token counts)` into money, and
//! nothing else. It does no I/O, opens no network connection, and reads
//! no file at run time.
//!
//! ```
//! use bc_pricing::{Call, Pricer};
//!
//! let pricer = Pricer::vendored();
//! let call = Call::from_usage(12_000, 800, 40_000, 0);
//! let cost = pricer
//!     .price_call("anthropic", "claude-sonnet-4-5", &call)
//!     .expect("a model the vendored table knows");
//! assert_eq!(cost.total().to_usd_string(4), "0.0600");
//! ```
//!
//! # The vendored table
//!
//! `data/models-dev-prices.json` is a trimmed capture of
//! <https://models.dev/api.json>, which is MIT licensed open data, pulled
//! into the binary with `include_str!`. It is committed rather than
//! fetched so that a price change arrives as a reviewable diff on a pull
//! request instead of as a silent change in what yesterday's scan would
//! have cost. `scripts/refresh_prices.py` regenerates it; that script's
//! docstring covers how to run it.
//!
//! The capture is trimmed to the four rate classes the scanner meters,
//! plus long context tiers, which takes the upstream 4.3 MB down to about
//! 615 KB.
//!
//! ## Why every provider is kept
//!
//! The obvious saving would be to keep only the handful of providers this
//! scanner is expected to talk to. That is the wrong call here, and the
//! shape of the upstream data is what makes it wrong.
//!
//! The scanner speaks to an OpenAI dialect or an Anthropic dialect
//! endpoint at a configurable base URL. In practice that endpoint is
//! frequently a gateway, and the upstream catalog's long tail is
//! overwhelmingly gateways: OpenRouter, Vercel AI Gateway, LLM Gateway,
//! Kilo, Requesty, Helicone, Cloudflare AI Gateway, and dozens more, each
//! republishing hundreds of models at its own prices. Curating those out
//! would delete precisely the entries a real deployment is most likely to
//! be pointed at, and the failure would be quiet: the operator gets
//! "unpriced" for the model they actually ran, which is the exact hole
//! this crate exists to close.
//!
//! Those resellers are also not redundant with the first party entries.
//! In the captured snapshot, 775 model ids are published by more than one
//! provider with different cost objects, across 4,244 provider and model
//! entries. `claude-sonnet-4-5` is 3.00 dollars per million input tokens
//! direct from Anthropic and 3.75 through one of the resellers, a 25
//! percent gap on the single most likely model in this pipeline. So the
//! provider dimension is preserved in the keying, and a lookup never
//! falls back to searching other providers for a matching model id.
//!
//! Against that, 615 KB of static data is a small price in a binary that
//! already links a dozen tree sitter grammars, and it needs no
//! maintenance decision on every refresh about who is still worth
//! keeping.
//!
//! # Overrides
//!
//! A public table is exactly wrong for the case it matters most in: a
//! gateway on negotiated rates. [`Pricer::with_overrides`] takes a second
//! [`PriceTable`] that wins over the vendored one, and it uses the same
//! JSON shape, so an operator can copy the entry they want to correct
//! straight out of the vendored file and edit the numbers. A provider id
//! of `*` in an override table matches any provider, for the deployment
//! that fronts everything through one endpoint and prices it uniformly.
//!
//! # Precision and tiers
//!
//! See [`money`] for why costs are exact integers rather than floats, and
//! [`call`] for why pricing takes one call at a time and aggregation
//! happens in dollars rather than in tokens.

pub mod call;
pub mod money;
pub mod table;

use std::sync::LazyLock;

pub use call::{Call, CallCost, CostTotal};
pub use money::Money;
pub use table::{
    ModelPrice, PriceTable, Rate, TableMeta, Tier, Unpriced, LONG_TTL_WRITE_MULTIPLIER,
};

/// The trimmed models.dev capture, exactly as committed.
pub const VENDORED_JSON: &str = include_str!("../data/models-dev-prices.json");

/// A provider id in an override table that matches any provider.
pub const ANY_PROVIDER: &str = "*";

static VENDORED: LazyLock<PriceTable> = LazyLock::new(|| {
    PriceTable::from_json(VENDORED_JSON)
        .expect("the vendored price table is committed with this crate and is tested on every run")
});

/// The parsed vendored price table, parsed once per process.
pub fn vendored_table() -> &'static PriceTable {
    &VENDORED
}

/// Which table an answer came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PriceSource {
    /// The table the [`Pricer`] was built on, normally the vendored one.
    Base,
    /// An operator supplied override.
    Override,
}

/// A resolved price and where it came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PriceRef<'a> {
    /// Which table won.
    pub source: PriceSource,
    /// The rates themselves.
    pub price: &'a ModelPrice,
}

/// Resolves a provider and model to rates, with operator overrides layered
/// over a base table, and prices one call at a time.
#[derive(Clone, Debug)]
pub struct Pricer<'t> {
    base: &'t PriceTable,
    overrides: PriceTable,
}

impl Pricer<'static> {
    /// A pricer over the vendored table, with no overrides.
    pub fn vendored() -> Self {
        Self::new(vendored_table())
    }
}

impl<'t> Pricer<'t> {
    /// A pricer over some other base table, with no overrides.
    pub fn new(base: &'t PriceTable) -> Self {
        Self {
            base,
            overrides: PriceTable::default(),
        }
    }

    /// Layer operator supplied rates over the base table.
    pub fn with_overrides(mut self, overrides: PriceTable) -> Self {
        self.overrides = overrides;
        self
    }

    /// The override table in force, for a caller that wants to report it.
    pub fn overrides(&self) -> &PriceTable {
        &self.overrides
    }

    /// The base table this pricer resolves against.
    pub fn base(&self) -> &PriceTable {
        self.base
    }

    /// Resolve rates for a provider and model.
    ///
    /// An exact provider override wins, then an [`ANY_PROVIDER`]
    /// override, then the base table. An id neither table knows is
    /// reported as [`Unpriced`] rather than priced at zero.
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
            // Recomputed across both tables, so an override supplying a
            // provider the base table has never heard of still reports
            // the more specific reason.
            Err(_) => Err(self.unpriced_reason(provider)),
        }
    }

    /// Price one call, resolving its rates first.
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
mod tests {
    use super::*;

    fn gateway_override() -> PriceTable {
        let mut table = PriceTable::default();
        // A negotiated rate: half of Anthropic's list price.
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
        // A refresh that introduces a cost shape this crate cannot parse
        // has to fail here rather than at scan time.
        let table = PriceTable::from_json(VENDORED_JSON).expect("vendored table parses");
        assert_eq!(table.provider_count(), table.meta.providers);
        assert_eq!(table.model_count(), table.meta.models);
        assert!(table.provider_count() > 100, "{}", table.provider_count());
        assert!(table.model_count() > 5_000, "{}", table.model_count());

        // Every entry, not just the ones a lookup happens to touch.
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
        // Shape, not a pinned day: refreshing the table legitimately moves
        // this date, and an equality assert only added a second file to edit
        // on every refresh. A malformed or missing date still fails here.
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

    /// `claude-opus-5-5` comes from the refresh script's SUPPLEMENT (it
    /// was not in the models.dev capture yet): 1M fresh input, 1M output,
    /// 1M cache reads and 1M 5-minute cache writes at $4 / $20 / $0.20 /
    /// $5 per million.
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
        // The trap this table's shape exists to avoid. Both entries are
        // real, and deduping by model id would silently pick one.
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

        // The vendored rate is untouched for the provider that publishes it.
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

        // A provider only the override table knows still reports the more
        // specific reason for a model neither table has.
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
        // The wildcard does not make every model priced.
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
        // Two calls to a tiered model, one on each side of the threshold.
        // Pricing their summed tokens as a single call would apply one
        // tier to both and be wrong by the whole tier difference.
        let pricer = Pricer::vendored();
        // A real vendored entry with a 200,000 token tier: 5.00 dollars
        // per million input tokens below it, 10.00 above.
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

        // Pricing the two calls' summed tokens as one 400,001 token call
        // would have charged the tier rate on all of it.
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
