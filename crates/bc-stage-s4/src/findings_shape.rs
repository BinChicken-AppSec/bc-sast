//! Shape check on a parsed deep-dive reply, ported from `s4_deepdive.py::
//! _findings_list` (v1.4.0).
//!
//! `extract_json` only guarantees "some valid JSON". Feeding that straight
//! into "take `findings` if it is a list, else nothing" turned
//! `{"findings": null}`, a misspelled key such as `{"findigns": []}`, or
//! any other conforming-looking but wrong object into ZERO findings,
//! silently, indistinguishable from a clean chunk. This check refuses
//! those shapes so they take the same one-repair path a JSON syntax error
//! does, and fail the run (recording the coverage loss) if the repair
//! does not fix them.

use serde_json::Value;

/// How many top-level keys the refusal message names, and how long each
/// may be. The keys are model-controlled (a reply can echo a secret it
/// read from the repo AS a key) and the message reaches logs, so each is
/// redacted and capped.
const MAX_KEYS_SHOWN: usize = 8;
const MAX_KEY_CHARS: usize = 60;

/// The findings list `data` carries, or `Err(message)` describing why the
/// reply is off-schema.
///
/// Accepted: an object whose `findings` is an array (including the empty
/// array, the legitimate "found nothing" answer), or a NON-EMPTY bare
/// top-level array (the documented tolerance: `extract_json` can return
/// one). Refused: `{}`, `[]`, `{"findings": null}`, a non-array
/// `findings`, a misspelled key, and any scalar. An empty bare array is
/// refused by the same standard that refuses `{}`: the schema demands an
/// object, and accepting `[]` would reproduce the silent zero-finding
/// chunk this exists to prevent.
pub(crate) fn findings_list(data: &Value) -> Result<Vec<Value>, String> {
    match data {
        Value::Array(items) if !items.is_empty() => return Ok(items.clone()),
        Value::Object(map) => {
            if let Some(Value::Array(items)) = map.get("findings") {
                return Ok(items.clone());
            }
        }
        _ => {}
    }
    let keys = match data {
        Value::Object(map) if !map.is_empty() => map
            .keys()
            .take(MAX_KEYS_SHOWN)
            .map(|k| {
                let safe: String = bc_redact::redact(k).chars().take(MAX_KEY_CHARS).collect();
                format!("{safe:?}")
            })
            .collect::<Vec<_>>()
            .join(", "),
        _ => "(none)".to_string(),
    };
    Err(format!(
        "reply parsed as JSON but carries no well-formed 'findings' list \
         (top-level keys: {keys}): refusing to treat it as zero findings"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_findings_array_is_accepted_even_when_empty() {
        assert_eq!(
            findings_list(&json!({"findings": []})).unwrap(),
            Vec::<Value>::new()
        );
        assert_eq!(
            findings_list(&json!({"findings": [1, 2]})).unwrap(),
            vec![json!(1), json!(2)]
        );
    }

    #[test]
    fn a_non_empty_bare_array_is_the_findings_list_itself() {
        assert_eq!(
            findings_list(&json!([{"a": 1}])).unwrap(),
            vec![json!({"a": 1})]
        );
    }

    #[test]
    fn off_schema_shapes_are_refused() {
        for data in [
            json!({}),
            json!([]),
            json!({"findings": null}),
            json!({"findings": {"a": 1}}),
            json!({"findigns": []}),
            json!("findings"),
            json!(3),
        ] {
            assert!(findings_list(&data).is_err(), "{data} must be refused");
        }
    }

    #[test]
    fn the_refusal_names_capped_redacted_keys() {
        let err = findings_list(&json!({"findigns": [], "x": 1})).unwrap_err();
        assert!(err.contains("\"findigns\", \"x\""), "{err}");
        assert!(findings_list(&json!({})).unwrap_err().contains("(none)"));
        assert!(findings_list(&json!(null)).unwrap_err().contains("(none)"));

        // The secret key is first in both insertion and sorted order, so it
        // is among the keys shown whichever map ordering serde_json uses.
        let mut many = serde_json::Map::new();
        let secret = format!("AKIA{}", "ABCDEFGHIJKLMNOP");
        many.insert(format!("a {secret}"), json!(1));
        for i in 0..12 {
            many.insert(format!("k{i:02}{}", "z".repeat(80)), json!(1));
        }
        let err = findings_list(&Value::Object(many)).unwrap_err();
        assert!(!err.contains(&secret), "{err}");
        assert!(!err.contains("k08"), "only eight keys are named: {err}");
        assert!(!err.contains(&"z".repeat(60)), "each key is capped: {err}");
    }
}
