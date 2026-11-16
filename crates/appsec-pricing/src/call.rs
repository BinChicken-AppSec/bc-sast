use crate::money::Money;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Call {
    context_tokens: u64,
    input_tokens: u64,
    output_tokens: u64,
    cache_read_tokens: u64,
    cache_write_tokens: u64,
    long_ttl_cache_write_tokens: u64,
}

impl Call {
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

    pub const fn input(mut self, tokens: u64) -> Self {
        self.input_tokens = tokens;
        self
    }

    pub const fn output(mut self, tokens: u64) -> Self {
        self.output_tokens = tokens;
        self
    }

    pub const fn cache_read(mut self, tokens: u64) -> Self {
        self.cache_read_tokens = tokens;
        self
    }

    pub const fn cache_write(mut self, tokens: u64) -> Self {
        self.cache_write_tokens = tokens;
        if self.long_ttl_cache_write_tokens > tokens {
            self.long_ttl_cache_write_tokens = tokens;
        }
        self
    }

    pub const fn long_ttl_cache_writes(mut self, tokens: u64) -> Self {
        self.long_ttl_cache_write_tokens = if tokens < self.cache_write_tokens {
            tokens
        } else {
            self.cache_write_tokens
        };
        self
    }

    pub const fn context_tokens(self) -> u64 {
        self.context_tokens
    }

    pub const fn input_tokens(self) -> u64 {
        self.input_tokens
    }

    pub const fn output_tokens(self) -> u64 {
        self.output_tokens
    }

    pub const fn cache_read_tokens(self) -> u64 {
        self.cache_read_tokens
    }

    pub const fn cache_write_tokens(self) -> u64 {
        self.cache_write_tokens
    }

    pub const fn long_ttl_cache_write_tokens(self) -> u64 {
        self.long_ttl_cache_write_tokens
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CallCost {
    pub input: Money,
    pub output: Money,
    pub cache_read: Money,
    pub cache_write: Money,
    pub tier_applied: Option<u64>,
    pub unrated_tokens: u64,
}

impl CallCost {
    pub fn total(self) -> Money {
        self.input + self.output + self.cache_read + self.cache_write
    }

    pub const fn is_fully_rated(self) -> bool {
        self.unrated_tokens == 0
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CostTotal {
    pub input: Money,
    pub output: Money,
    pub cache_read: Money,
    pub cache_write: Money,
    pub calls: u64,
    pub unrated_tokens: u64,
}

impl CostTotal {
    pub fn add_call(&mut self, cost: CallCost) {
        self.input += cost.input;
        self.output += cost.output;
        self.cache_read += cost.cache_read;
        self.cache_write += cost.cache_write;
        self.calls += 1;
        self.unrated_tokens += cost.unrated_tokens;
    }

    pub fn total(self) -> Money {
        self.input + self.output + self.cache_read + self.cache_write
    }

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
#[allow(clippy::clone_on_copy)]
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
        let lowered = clamped.cache_write(100);
        assert_eq!(lowered.long_ttl_cache_write_tokens(), 100);
        let raised = Call::from_usage(10, 1, 0, 50)
            .long_ttl_cache_writes(50)
            .cache_write(80);
        assert_eq!(raised.long_ttl_cache_write_tokens(), 50);
    }

    #[test]
    fn the_builder_keeps_the_context_the_caller_stated() {
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
