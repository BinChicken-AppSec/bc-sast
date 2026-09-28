//! OpenAI usage -> [`Usage`], shared by both API shapes, ported from
//! `backends/llm/openai.py::_normalise_usage` (`:750-784`).
//!
//! Both shapes report the WHOLE prompt as one number (`prompt_tokens` on
//! Chat Completions, `input_tokens` on the Responses API) with the cache
//! slices broken out underneath it (`*_tokens_details.cached_tokens`, and
//! `cache_write_tokens` on the models and gateways that bill a cache
//! write). [`Usage`]'s contract is that its three input fields are
//! disjoint, so both slices are carved OUT of the total here: fresh +
//! read + write adds back up to the reported prompt, and `bc-pricing`
//! rates each slice at its own rate.

use bc_llm_client::Usage;
use serde_json::Value;

/// Normalize one usage object. `total_key`/`details_key`/`output_key` are
/// the shape's own field names; a missing or `null` object is all zeros.
pub fn normalize_usage(
    usage: &Value,
    total_key: &str,
    details_key: &str,
    output_key: &str,
) -> Usage {
    if usage.is_null() {
        return Usage::default();
    }
    let details = &usage[details_key];
    let total = usage[total_key].as_u64().unwrap_or(0);
    let cached = details["cached_tokens"].as_u64().unwrap_or(0);
    let written = details["cache_write_tokens"].as_u64().unwrap_or(0);
    Usage {
        // Saturating: a gateway reporting slices larger than the total
        // is wrong, but must not wrap into a four-billion-token bill.
        input_tokens: total.saturating_sub(cached).saturating_sub(written),
        output_tokens: usage[output_key].as_u64().unwrap_or(0),
        cache_creation_input_tokens: written,
        cache_read_input_tokens: cached,
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
        );
        assert_eq!(u.input_tokens, 500);
        assert_eq!(u.cache_read_input_tokens, 1_500);
        assert_eq!(u.output_tokens, 30);
        assert_eq!(u.cache_creation_input_tokens, 0);
    }
}
