//! The unit of pricing: one model call, and the cost of one model call.
//!
//! Everything in this module exists to make a single mistake impossible.
//! Long context pricing switches rate as a function of *one call's*
//! prompt size, so a stage that made forty calls, thirty of them under a
//! provider's 200,000 token threshold and ten of them over it, has no
//! single correct rate. Handing that stage's summed token counts to a
//! cost function would produce a number that is not wrong by rounding, it
//! is wrong by the entire tier difference, which on the Anthropic long
//! context tier is a factor of two.
//!
//! The type system is arranged so that cannot be typed by accident:
//!
//! * [`Call`] cannot be constructed without stating a context size. There
//!   is no `Default`, and no constructor that leaves it out.
//! * Pricing consumes a `Call` and produces a [`CallCost`], which carries
//!   the tier that was applied, so a caller can see which side of a
//!   threshold a call landed on.
//! * Aggregation is a separate type, [`CostTotal`], which accumulates
//!   already priced [`CallCost`] values. It has no rates and no tier, so
//!   there is nothing to apply a tier to. Summing happens in dollars,
//!   after pricing, never in tokens, before it.
//!
//! There is deliberately no function anywhere in this crate that takes a
//! total token count without a context size beside it.

use crate::money::Money;

/// The token counts for exactly one model call.
///
/// `context_tokens` is the size of the prompt that call sent, which is
/// what a provider's long context tier is keyed on. When usage is
/// reported with cached tokens broken out, the prompt is the sum of the
/// fresh input, the cache reads and the cache writes, which is what
/// [`Call::from_usage`] computes. Use [`Call::with_context`] when the
/// real prompt size is known separately and differs, for example when a
/// gateway reports a context window the token counts do not add up to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Call {
    context_tokens: u64,
    input_tokens: u64,
    output_tokens: u64,
    cache_read_tokens: u64,
    cache_write_tokens: u64,
    /// How many of `cache_write_tokens` were written with Anthropic's
    /// one-hour lifetime, which bills at a different rate. Always at
    /// most `cache_write_tokens`.
    long_ttl_cache_write_tokens: u64,
}

impl Call {
    /// A call whose prompt was `context_tokens` long and which, so far,
    /// billed nothing. Add the token counts with the builder methods.
    pub const fn with_context(context_tokens: u64) -> Self {
        Self {
            context_tokens,
            input_tokens: 0,
            output_tokens: 0,
            cache_read_tokens: 0,
            cache_write_tokens: 0,
            long_ttl_cache_write_tokens: 0,
        }
    }

    /// A call built from a provider's usage report, taking the context
    /// size to be everything that was in the prompt: fresh input tokens,
    /// tokens served from cache, and tokens written to cache.
    pub const fn from_usage(
        input_tokens: u64,
        output_tokens: u64,
        cache_read_tokens: u64,
        cache_write_tokens: u64,
    ) -> Self {
        Self {
            context_tokens: input_tokens + cache_read_tokens + cache_write_tokens,
            input_tokens,
            output_tokens,
            cache_read_tokens,
            cache_write_tokens,
            long_ttl_cache_write_tokens: 0,
        }
    }

    /// Set the fresh input tokens.
    pub const fn input(mut self, tokens: u64) -> Self {
        self.input_tokens = tokens;
        self
    }

    /// Set the generated output tokens. Providers that bill reasoning
    /// tokens as output should include them here.
    pub const fn output(mut self, tokens: u64) -> Self {
        self.output_tokens = tokens;
        self
    }

    /// Set the tokens served from a prompt cache.
    pub const fn cache_read(mut self, tokens: u64) -> Self {
        self.cache_read_tokens = tokens;
        self
    }

    /// Set the tokens written into a prompt cache.
    pub const fn cache_write(mut self, tokens: u64) -> Self {
        self.cache_write_tokens = tokens;
        if self.long_ttl_cache_write_tokens > tokens {
            self.long_ttl_cache_write_tokens = tokens;
        }
        self
    }

    /// Mark `tokens` of this call's cache writes as written with
    /// Anthropic's one-hour lifetime (`cache_control.ttl: "1h"`), which
    /// bills at twice the base input rate instead of the five-minute
    /// write rate (1.25x). Clamped to the call's cache writes, so it can
    /// only re-rate tokens already counted, never add any. Set it after
    /// [`Self::cache_write`] when using the builder.
    ///
    /// Which lifetime a call used is known to the caller: every marker in
    /// one request carries the same `ttl`, so a request sent with the
    /// one-hour lifetime wrote ALL its cache tokens at it.
    pub const fn long_ttl_cache_writes(mut self, tokens: u64) -> Self {
        self.long_ttl_cache_write_tokens = if tokens < self.cache_write_tokens {
            tokens
        } else {
            self.cache_write_tokens
        };
        self
    }

    /// The prompt size that selects the rate tier.
    pub const fn context_tokens(self) -> u64 {
        self.context_tokens
    }

    /// Fresh input tokens.
    pub const fn input_tokens(self) -> u64 {
        self.input_tokens
    }

    /// Generated output tokens.
    pub const fn output_tokens(self) -> u64 {
        self.output_tokens
    }

    /// Tokens served from a prompt cache.
    pub const fn cache_read_tokens(self) -> u64 {
        self.cache_read_tokens
    }

    /// Tokens written into a prompt cache, both lifetimes together.
    pub const fn cache_write_tokens(self) -> u64 {
        self.cache_write_tokens
    }

    /// Of [`Self::cache_write_tokens`], those written with the one-hour
    /// lifetime.
    pub const fn long_ttl_cache_write_tokens(self) -> u64 {
        self.long_ttl_cache_write_tokens
    }
}

/// What one call cost, broken out by token class.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CallCost {
    /// Cost of the fresh input tokens.
    pub input: Money,
    /// Cost of the generated output tokens.
    pub output: Money,
    /// Cost of the tokens served from cache, at the cache read rate.
    pub cache_read: Money,
    /// Cost of the tokens written to cache, at the cache write rate.
    pub cache_write: Money,
    /// The tier threshold whose rates were used, or `None` when the call
    /// was priced at the model's base rates.
    pub tier_applied: Option<u64>,
    /// Tokens this call used for which the price table publishes no rate,
    /// and which therefore contributed nothing to the cost above. Any
    /// value other than zero means the cost is a lower bound, and it is
    /// the only way a rate can be missing without the whole call reading
    /// as unpriced.
    pub unrated_tokens: u64,
}

impl CallCost {
    /// The call's total cost.
    pub fn total(self) -> Money {
        self.input + self.output + self.cache_read + self.cache_write
    }

    /// Whether every token in the call had a published rate.
    pub const fn is_fully_rated(self) -> bool {
        self.unrated_tokens == 0
    }
}

/// A running total over calls that have already been priced.
///
/// Built only by accumulating [`CallCost`] values, because a total has no
/// context size and so cannot be tiered. This is the aggregation path.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CostTotal {
    /// Summed cost of fresh input tokens.
    pub input: Money,
    /// Summed cost of generated output tokens.
    pub output: Money,
    /// Summed cost of tokens served from cache.
    pub cache_read: Money,
    /// Summed cost of tokens written to cache.
    pub cache_write: Money,
    /// How many calls were accumulated.
    pub calls: u64,
    /// Summed tokens that had no published rate. See
    /// [`CallCost::unrated_tokens`].
    pub unrated_tokens: u64,
}

impl CostTotal {
    /// Fold one priced call into the total.
    pub fn add_call(&mut self, cost: CallCost) {
        self.input += cost.input;
        self.output += cost.output;
        self.cache_read += cost.cache_read;
        self.cache_write += cost.cache_write;
        self.calls += 1;
        self.unrated_tokens += cost.unrated_tokens;
    }

    /// The total cost of every call accumulated so far.
    pub fn total(self) -> Money {
        self.input + self.output + self.cache_read + self.cache_write
    }

    /// Whether every token in every accumulated call had a published rate.
    pub const fn is_fully_rated(self) -> bool {
        self.unrated_tokens == 0
    }
}

impl Extend<CallCost> for CostTotal {
    fn extend<I: IntoIterator<Item = CallCost>>(&mut self, iter: I) {
        for cost in iter {
            self.add_call(cost);
        }
    }
}

impl FromIterator<CallCost> for CostTotal {
    fn from_iter<I: IntoIterator<Item = CallCost>>(iter: I) -> Self {
        let mut total = Self::default();
        total.extend(iter);
        total
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_usage_treats_the_whole_prompt_as_the_context() {
        let call = Call::from_usage(1_000, 500, 4_000, 200);
        assert_eq!(call.context_tokens(), 5_200);
        assert_eq!(call.input_tokens(), 1_000);
        assert_eq!(call.output_tokens(), 500);
        assert_eq!(call.cache_read_tokens(), 4_000);
        assert_eq!(call.cache_write_tokens(), 200);
    }

    #[test]
    fn long_ttl_writes_are_a_clamped_subset_of_the_writes() {
        let call = Call::from_usage(10, 1, 0, 500).long_ttl_cache_writes(200);
        assert_eq!(call.long_ttl_cache_write_tokens(), 200);
        assert_eq!(call.cache_write_tokens(), 500);
        assert_eq!(call.context_tokens(), 510, "re-rating adds no tokens");
        let clamped = Call::from_usage(10, 1, 0, 500).long_ttl_cache_writes(9_999);
        assert_eq!(clamped.long_ttl_cache_write_tokens(), 500);
        // Lowering the writes afterwards keeps the subset inside them.
        let lowered = clamped.cache_write(100);
        assert_eq!(lowered.long_ttl_cache_write_tokens(), 100);
        let raised = Call::from_usage(10, 1, 0, 50)
            .long_ttl_cache_writes(50)
            .cache_write(80);
        assert_eq!(raised.long_ttl_cache_write_tokens(), 50);
    }

    #[test]
    fn the_builder_keeps_the_context_the_caller_stated() {
        // A gateway can report a context window that the broken out
        // counts do not add up to, so an explicit context wins.
        let call = Call::with_context(300_000)
            .input(1_000)
            .output(2_000)
            .cache_read(3_000)
            .cache_write(4_000);
        assert_eq!(call.context_tokens(), 300_000);
        assert_eq!(call.input_tokens(), 1_000);
        assert_eq!(call.output_tokens(), 2_000);
        assert_eq!(call.cache_read_tokens(), 3_000);
        assert_eq!(call.cache_write_tokens(), 4_000);
        assert_eq!(call, call);
        assert_ne!(call, Call::with_context(1));
        assert!(format!("{call:?}").contains("300000"));
        // UFCS, because clippy rejects `.clone()` on a `Copy` type but the
        // derived impl still needs exercising for the coverage gate.
        assert_eq!(Clone::clone(&call).context_tokens(), 300_000);
    }

    fn sample(dollars_of_input: u128) -> CallCost {
        CallCost {
            input: Money::from_picodollars(dollars_of_input),
            output: Money::from_picodollars(2),
            cache_read: Money::from_picodollars(3),
            cache_write: Money::from_picodollars(4),
            tier_applied: Some(200_000),
            unrated_tokens: 7,
        }
    }

    #[test]
    fn call_cost_totals_every_token_class() {
        let cost = sample(1);
        assert_eq!(cost.total(), Money::from_picodollars(10));
        assert!(!cost.is_fully_rated());
        assert!(CallCost::default().is_fully_rated());
        assert_eq!(CallCost::default().total(), Money::ZERO);
        assert_eq!(cost, sample(1));
        assert_ne!(cost, sample(2));
        assert!(format!("{cost:?}").contains("tier_applied"));
        assert_eq!(Clone::clone(&cost).total(), Money::from_picodollars(10));
    }

    #[test]
    fn cost_total_accumulates_priced_calls_only() {
        let mut total = CostTotal::default();
        total.add_call(sample(1));
        total.add_call(sample(1));
        assert_eq!(total.calls, 2);
        assert_eq!(total.total(), Money::from_picodollars(20));
        assert_eq!(total.unrated_tokens, 14);
        assert!(!total.is_fully_rated());

        // The same two calls collected through the iterator path.
        let collected: CostTotal = [sample(1), sample(1)].into_iter().collect();
        assert_eq!(collected, total);
        assert!(format!("{collected:?}").contains("calls"));
        assert_eq!(Clone::clone(&collected).calls, 2);

        let mut extended = CostTotal::default();
        extended.extend([sample(1)]);
        assert_eq!(extended.calls, 1);
        assert!(CostTotal::default().is_fully_rated());
        assert_ne!(extended, total);
    }
}
