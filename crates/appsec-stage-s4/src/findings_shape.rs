use serde_json::Value;

const MAX_KEYS_SHOWN: usize = 8;
const MAX_KEY_CHARS: usize = 60;

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
                let safe: String = appsec_redact::redact(k)
                    .chars()
                    .take(MAX_KEY_CHARS)
                    .collect();
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
