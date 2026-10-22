//! OpenAI usage -> [`Usage`], shared by both API shapes, ported from
//! `backends/llm/openai.py::_normalise_usage` (`:750-784`).
//!
//! Both shapes report the WHOLE prompt as one number (`prompt_tokens` on
//! Chat Completions, `input_tokens` on the Responses API) with the cache
//! slices broken out underneath it (`*_tokens_details.cached_tokens`, and
//! `cache_write_tokens` on the models and gateways that bill a cache
//! write). [`Usage`]'s contract is that its three input fields are
//! disjoint, so both slices are carved OUT of the total here: fresh +
//! read + write adds back up to the reported prompt, and `appsec-pricing`
//! rates each slice at its own rate.

use appsec_llm_client::Usage;
use serde_json::Value;

/// Normalize one usage object. `total_key`/`details_key`/`output_key` are
/// the shape's own field names; a missing or `null` object is all zeros.
pub fn normalize_usage(
    usage: &Value,
    total_key: &str,
    details_key: &str,
    output_key: &str,
    output_details_key: &str,
) -> Usage {
    if usage.is_null() {
        return Usage::default();
    }
    let details = &usage[details_key];
    let total = usage[total_key].as_u64().unwrap_or(0);
    let cached = details["cached_tokens"].as_u64().unwrap_or(0);
    let written = details["cache_write_tokens"].as_u64().unwrap_or(0);
    // The reasoning share of the output, where the shape breaks it out:
    // `completion_tokens_details` on Chat Completions,
    // `output_tokens_details` on Responses. Absent or null reads as 0,
    // which is indistinguishable from a model that did no reasoning. That
    // ambiguity is why this never feeds pricing: `output_key` already
    // includes reasoning, and billing is computed from that.
    let reasoning = usage[output_details_key]["reasoning_tokens"]
        .as_u64()
        .unwrap_or(0);
    Usage {
        // Saturating: a gateway reporting slices larger than the total
        // is wrong, but must not wrap into a four-billion-token bill.
        input_tokens: total.saturating_sub(cached).saturating_sub(written),
        output_tokens: usage[output_key].as_u64().unwrap_or(0),
        cache_creation_input_tokens: written,
        cache_read_input_tokens: cached,
        // Clamped to the output it is a share of. A provider reporting more
        // reasoning than output is wrong, and an unclamped value would make
        // the visible-text figure (output minus reasoning) underflow.
        reasoning_output_tokens: reasoning.min(usage[output_key].as_u64().unwrap_or(0)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn chat(u: Value) -> Usage {
        normalize_usage(
            &u,
            "prompt_tokens",
            "prompt_tokens_details",
            "completion_tokens",
            "completion_tokens_details",
        )
    }

    #[test]
    fn null_usage_is_all_zeros() {
        assert_eq!(chat(Value::Null), Usage::default());
    }

    #[test]
    fn cached_and_written_slices_are_carved_out_of_the_total() {
        let u = chat(json!({
            "prompt_tokens": 10_000,
            "completion_tokens": 50,
            "prompt_tokens_details": {"cached_tokens": 6_000, "cache_write_tokens": 3_000},
        }));
        assert_eq!(
            u,
            Usage {
                input_tokens: 1_000,
                output_tokens: 50,
                cache_creation_input_tokens: 3_000,
                cache_read_input_tokens: 6_000,
                reasoning_output_tokens: 0,
            }
        );
        // The disjoint slices add back up to the reported prompt.
        assert_eq!(
            u.input_tokens + u.cache_read_input_tokens + u.cache_creation_input_tokens,
            10_000
        );
    }

    #[test]
    fn slices_larger_than_the_total_saturate_rather_than_wrap() {
        let u = chat(json!({
            "prompt_tokens": 10,
            "prompt_tokens_details": {"cached_tokens": 50},
        }));
        assert_eq!(u.input_tokens, 0);
        assert_eq!(u.cache_read_input_tokens, 50);
    }

    #[test]
    fn the_responses_shape_uses_its_own_field_names() {
        let u = normalize_usage(
            &json!({
                "input_tokens": 2_000,
                "output_tokens": 30,
                "input_tokens_details": {"cached_tokens": 1_500},
            }),
            "input_tokens",
            "input_tokens_details",
            "output_tokens",
            "output_tokens_details",
        );
        assert_eq!(u.input_tokens, 500);
        assert_eq!(u.cache_read_input_tokens, 1_500);
        assert_eq!(u.output_tokens, 30);
        assert_eq!(u.cache_creation_input_tokens, 0);
    }
}

#[cfg(test)]
mod reasoning_share_tests {
    use super::normalize_usage;
    use serde_json::json;

    #[test]
    fn chat_completions_reports_its_reasoning_share() {
        // The shape OpenAI returns for a reasoning model on Chat
        // Completions: the slice lives under `completion_tokens_details`.
        let u = normalize_usage(
            &json!({
                "prompt_tokens": 1000,
                "prompt_tokens_details": {"cached_tokens": 200},
                "completion_tokens": 900,
                "completion_tokens_details": {"reasoning_tokens": 700},
            }),
            "prompt_tokens",
            "prompt_tokens_details",
            "completion_tokens",
            "completion_tokens_details",
        );
        assert_eq!(u.output_tokens, 900, "output still counts everything");
        assert_eq!(u.reasoning_output_tokens, 700);
        // The point of the field: 200 tokens of the output were visible.
        assert_eq!(u.output_tokens - u.reasoning_output_tokens, 200);
    }

    #[test]
    fn responses_api_uses_its_own_details_key() {
        let u = normalize_usage(
            &json!({
                "input_tokens": 50,
                "input_tokens_details": {"cached_tokens": 0},
                "output_tokens": 400,
                "output_tokens_details": {"reasoning_tokens": 350},
            }),
            "input_tokens",
            "input_tokens_details",
            "output_tokens",
            "output_tokens_details",
        );
        assert_eq!(u.reasoning_output_tokens, 350);
    }

    #[test]
    fn a_shape_that_reports_no_reasoning_reads_zero() {
        // Indistinguishable from a model that did none, which is why this
        // field never feeds pricing.
        let u = normalize_usage(
            &json!({"prompt_tokens": 10, "completion_tokens": 20}),
            "prompt_tokens",
            "prompt_tokens_details",
            "completion_tokens",
            "completion_tokens_details",
        );
        assert_eq!(u.reasoning_output_tokens, 0);
        assert_eq!(u.output_tokens, 20);
    }

    #[test]
    fn reasoning_larger_than_the_output_is_clamped() {
        // A provider reporting more reasoning than output is wrong, and an
        // unclamped value would make `output - reasoning` underflow.
        let u = normalize_usage(
            &json!({
                "prompt_tokens": 10,
                "completion_tokens": 100,
                "completion_tokens_details": {"reasoning_tokens": 5000},
            }),
            "prompt_tokens",
            "prompt_tokens_details",
            "completion_tokens",
            "completion_tokens_details",
        );
        assert_eq!(u.reasoning_output_tokens, 100);
        assert_eq!(u.output_tokens - u.reasoning_output_tokens, 0);
    }
}
