use appsec_llm_client::{estimate_tokens, CachePolicy};
use serde_json::Value;

pub const MAX_BREAKPOINTS: u8 = 4;

#[derive(Debug)]
pub struct Breakpoints<'a> {
    policy: &'a CachePolicy,
    model: &'a str,
    cumulative: u64,
    placed: u8,
}

impl<'a> Breakpoints<'a> {
    pub fn new(policy: &'a CachePolicy, model: &'a str) -> Self {
        Breakpoints {
            policy,
            model,
            cumulative: 0,
            placed: 0,
        }
    }

    pub fn add(&mut self, text: &str) {
        self.cumulative += estimate_tokens(text);
    }

    pub fn place(&mut self, block: &mut Value) -> bool {
        if self.placed >= MAX_BREAKPOINTS
            || !self
                .policy
                .anthropic_marker_worth_placing(self.model, self.cumulative)
        {
            return false;
        }
        block["cache_control"] = self.policy.ttl.cache_control();
        self.placed += 1;
        true
    }

    #[cfg(test)]
    pub fn placed(&self) -> u8 {
        self.placed
    }
}

pub fn markable(block: &Value) -> bool {
    !matches!(
        block["type"].as_str(),
        Some("thinking") | Some("redacted_thinking")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use appsec_llm_client::CacheTtl;
    use serde_json::json;

    #[test]
    fn a_marker_needs_the_minimum_and_a_free_slot() {
        let policy = CachePolicy {
            min_block_tokens: Some(10),
            ..CachePolicy::default()
        };
        let mut bp = Breakpoints::new(&policy, "claude-sonnet-4-5");
        let mut block = json!({"type": "text", "text": "x"});
        bp.add("abcd");
        assert!(!bp.place(&mut block), "1 token is below 10");
        bp.add(&"y".repeat(40));
        for _ in 0..MAX_BREAKPOINTS {
            assert!(bp.place(&mut block));
        }
        assert!(!bp.place(&mut json!({})), "only four per request");
        assert_eq!(bp.placed(), 4);
        assert_eq!(block["cache_control"], json!({"type": "ephemeral"}));
    }

    #[test]
    fn the_marker_carries_the_policy_ttl() {
        let policy = CachePolicy {
            min_block_tokens: Some(1),
            ttl: CacheTtl::OneHour,
            ..CachePolicy::default()
        };
        let mut bp = Breakpoints::new(&policy, "m");
        bp.add("abcd");
        let mut block = json!({});
        assert!(bp.place(&mut block));
        assert_eq!(
            block["cache_control"],
            json!({"type": "ephemeral", "ttl": "1h"})
        );
    }

    #[test]
    fn thinking_blocks_are_never_markable() {
        assert!(!markable(&json!({"type": "thinking"})));
        assert!(!markable(&json!({"type": "redacted_thinking"})));
        assert!(markable(&json!({"type": "text"})));
    }
}
