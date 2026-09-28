//! Where this dialect puts Anthropic `cache_control` breakpoints, and
//! whether each is worth placing. Ported from `backends/llm/sdk.py:243-465`
//! (the gated system-block marker, the `cache_prefix` leading block, and
//! `_with_cache_marker`'s per-turn tail marker) and the DeepAgents route's
//! tool-definition marker (`deepagents/client.py::_oneshot_content`: "4th
//! of 4 breakpoints (middleware spends 3: system, tools, tail)").
//!
//! Anthropic renders a request as tools, then system, then messages, and
//! caches every prefix ending at a breakpoint. At most four breakpoints
//! are allowed per request; this module places at most one of each kind,
//! in rendering order:
//!
//! 1. the last tool definition (tools are identical on every turn of an
//!    agentic session, so they are the most reusable prefix of all);
//! 2. the system prompt;
//! 3. the cache prefix, a leading block of the first user turn (S4's
//!    shared context plus one shard's source);
//! 4. the last content block of the latest user turn, on a multi-turn
//!    request only (extending the cached prefix over the conversation so
//!    far, turn after turn).
//!
//! Each is gated on [`bc_llm_client::CachePolicy`]: the kill switch, and
//! the model's minimum cacheable prefix measured CUMULATIVELY from the
//! start of the request (a breakpoint below the minimum silently caches
//! nothing while spending a slot).

use bc_llm_client::{estimate_tokens, CachePolicy};
use serde_json::Value;

/// Anthropic's per-request breakpoint limit.
pub const MAX_BREAKPOINTS: u8 = 4;

/// Tracks the cumulative estimated prefix and the breakpoints spent.
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

    /// Account for `text` being rendered before the next breakpoint.
    pub fn add(&mut self, text: &str) {
        self.cumulative += estimate_tokens(text);
    }

    /// Mark `block` as a breakpoint if the policy allows, the prefix so
    /// far clears the model's minimum, and a slot remains. Returns
    /// whether it did.
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

/// Whether a block may carry a marker: never a thinking block, which
/// the API rejects `cache_control` on.
pub fn markable(block: &Value) -> bool {
    !matches!(
        block["type"].as_str(),
        Some("thinking") | Some("redacted_thinking")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_llm_client::CacheTtl;
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
