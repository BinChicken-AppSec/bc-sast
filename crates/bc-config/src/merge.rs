//! The three merge strategies ported from `vvaharness/config/__init__.py`:
//! `_deep_merge`, `_replace_merge`, and `_append_merge`. All three treat
//! two JSON objects the same way at the top ("recurse into nested
//! objects present on both sides") and differ only in how they handle
//! everything else (scalars, arrays, an object meeting a non-object).

use serde_json::Value;

/// `over` wins at every key; two nested objects merge recursively,
/// anything else (including arrays) is replaced outright. Used to layer
/// a loaded config UNDER the built-in step defaults, and to layer
/// `config.local.yaml` OVER the resolved config.
pub fn deep_merge(base: &Value, over: &Value) -> Value {
    match (base, over) {
        (Value::Object(base_map), Value::Object(over_map)) => {
            let mut out = base_map.clone();
            for (k, v) in over_map {
                let merged = match out.get(k) {
                    Some(existing) => deep_merge(existing, v),
                    None => v.clone(),
                };
                out.insert(k.clone(), merged);
            }
            Value::Object(out)
        }
        _ => over.clone(),
    }
}

/// Identical recursion rule to [`deep_merge`] — kept as a distinctly named
/// alias (rather than reusing `deep_merge` directly) because the Python
/// original defines it as a separate function that `append_merge` calls
/// for its nested-object case, and future divergence between the two is
/// easy to imagine (e.g. a stricter type-mismatch policy) — mirroring the
/// module boundary makes that future edit a one-function change instead
/// of an audit of every `deep_merge` call site to see which meant
/// "replace" semantics.
pub fn replace_merge(base: &Value, over: &Value) -> Value {
    deep_merge(base, over)
}

/// The step1-overlay merge: top-level **arrays append** (skipping values
/// already present, so re-applying the same overlay is idempotent),
/// nested objects use [`replace_merge`], everything else is replaced.
pub fn append_merge(base: &Value, over: &Value) -> Value {
    let (Value::Object(base_map), Value::Object(over_map)) = (base, over) else {
        return over.clone();
    };
    let mut out = base_map.clone();
    for (k, v) in over_map {
        let merged = match (out.get(k), v) {
            (Some(Value::Object(cur)), Value::Object(new)) => {
                replace_merge(&Value::Object(cur.clone()), &Value::Object(new.clone()))
            }
            (Some(Value::Array(cur)), Value::Array(new)) => {
                let mut combined = cur.clone();
                for item in new {
                    if !combined.contains(item) {
                        combined.push(item.clone());
                    }
                }
                Value::Array(combined)
            }
            _ => v.clone(),
        };
        out.insert(k.clone(), merged);
    }
    Value::Object(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn deep_merge_over_wins_on_scalar_conflict() {
        assert_eq!(
            deep_merge(&json!({"a": 1}), &json!({"a": 2})),
            json!({"a": 2})
        );
    }

    #[test]
    fn deep_merge_recurses_into_nested_objects_present_on_both_sides() {
        assert_eq!(
            deep_merge(
                &json!({"a": {"x": 1, "y": 2}}),
                &json!({"a": {"y": 3, "z": 4}})
            ),
            json!({"a": {"x": 1, "y": 3, "z": 4}})
        );
    }

    #[test]
    fn deep_merge_replaces_arrays_outright_rather_than_concatenating() {
        assert_eq!(
            deep_merge(&json!({"a": [1, 2]}), &json!({"a": [3]})),
            json!({"a": [3]})
        );
    }

    #[test]
    fn deep_merge_over_object_replaces_a_base_scalar() {
        assert_eq!(
            deep_merge(&json!({"a": 1}), &json!({"a": {"x": 1}})),
            json!({"a": {"x": 1}})
        );
    }

    #[test]
    fn deep_merge_base_object_is_replaced_by_an_over_scalar() {
        assert_eq!(
            deep_merge(&json!({"a": {"x": 1}}), &json!({"a": 5})),
            json!({"a": 5})
        );
    }

    #[test]
    fn deep_merge_keeps_base_only_keys() {
        assert_eq!(
            deep_merge(&json!({"a": 1, "b": 2}), &json!({"a": 3})),
            json!({"a": 3, "b": 2})
        );
    }

    #[test]
    fn deep_merge_non_object_base_is_fully_replaced() {
        assert_eq!(
            deep_merge(&json!([1, 2]), &json!({"a": 1})),
            json!({"a": 1})
        );
        assert_eq!(deep_merge(&json!(null), &json!({"a": 1})), json!({"a": 1}));
    }

    #[test]
    fn replace_merge_matches_deep_merge_semantics() {
        let base = json!({"a": {"x": 1}, "b": [1, 2]});
        let over = json!({"a": {"y": 2}, "b": [3]});
        assert_eq!(replace_merge(&base, &over), deep_merge(&base, &over));
    }

    #[test]
    fn append_merge_appends_new_array_items_and_skips_duplicates() {
        let base = json!({"exclude_dirs": ["a", "b"]});
        let over = json!({"exclude_dirs": ["b", "c"]});
        assert_eq!(
            append_merge(&base, &over),
            json!({"exclude_dirs": ["a", "b", "c"]})
        );
    }

    #[test]
    fn append_merge_nested_object_uses_replace_semantics_not_append() {
        let base = json!({"config_dedup": {"exts": ["a"], "enabled": true}});
        let over = json!({"config_dedup": {"exts": ["b"]}});
        // Nested dict -> replace_merge, so "exts" is REPLACED (["b"]), not
        // appended to (["a", "b"]) — only top-level lists append.
        assert_eq!(
            append_merge(&base, &over),
            json!({"config_dedup": {"exts": ["b"], "enabled": true}})
        );
    }

    #[test]
    fn append_merge_scalar_over_replaces() {
        assert_eq!(
            append_merge(&json!({"a": 1}), &json!({"a": 2})),
            json!({"a": 2})
        );
    }

    #[test]
    fn append_merge_array_meeting_a_non_array_replaces() {
        assert_eq!(
            append_merge(&json!({"a": [1, 2]}), &json!({"a": "x"})),
            json!({"a": "x"})
        );
        assert_eq!(
            append_merge(&json!({"a": "x"}), &json!({"a": [1, 2]})),
            json!({"a": [1, 2]})
        );
    }

    #[test]
    fn append_merge_non_object_inputs_are_fully_replaced() {
        assert_eq!(
            append_merge(&json!([1, 2]), &json!({"a": 1})),
            json!({"a": 1})
        );
        assert_eq!(append_merge(&json!({"a": 1}), &json!([9])), json!([9]));
    }

    #[test]
    fn append_merge_new_key_not_present_in_base_is_added() {
        assert_eq!(
            append_merge(&json!({"a": 1}), &json!({"b": 2})),
            json!({"a": 1, "b": 2})
        );
    }
}
