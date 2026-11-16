use appsec_model::ThreatModel;
use serde_json::Value;

const THREAT_MODEL_FIELDS: &[&str] = &[
    "system_context",
    "assets",
    "trust_boundaries",
    "threats",
    "open_questions",
];

pub(crate) fn parse_threat_model(raw: &str) -> Result<ThreatModel, String> {
    let data = appsec_json_repair::extract_json(raw).map_err(|e| e.to_string())?;
    let Value::Object(map) = &data else {
        return Err("expected a JSON object, got a top-level array".to_string());
    };
    if !map.is_empty()
        && !map
            .keys()
            .any(|k| THREAT_MODEL_FIELDS.contains(&k.as_str()))
    {
        let keys: Vec<&String> = map.keys().take(8).collect();
        return Err(format!(
            "extracted JSON object has none of the threat-model fields (got keys: {keys:?}): \
             likely a sub-object of a truncated or malformed response"
        ));
    }
    serde_json::from_value(data).map_err(|e| format!("ThreatModel validation failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_well_formed_reply_and_an_empty_object_parse() {
        let tm = parse_threat_model(r#"{"system_context": "ctx", "threats": []}"#).unwrap();
        assert_eq!(tm.system_context, "ctx");
        assert_eq!(parse_threat_model("{}").unwrap(), ThreatModel::default());
    }

    #[test]
    fn no_json_is_an_extraction_error() {
        assert!(parse_threat_model("not json")
            .unwrap_err()
            .contains("no JSON"));
    }

    #[test]
    fn a_top_level_array_is_refused() {
        let err = parse_threat_model(r#"["a", "b", "c", "d", "e"]"#).unwrap_err();
        assert!(err.contains("top-level array"), "{err}");
    }

    #[test]
    fn a_stray_sub_object_is_refused_rather_than_read_as_an_empty_model() {
        let raw = r#"{"system_context": "x", "assets": [{"name": "db", "sensitivity": "high"}"#;
        let err = parse_threat_model(raw).unwrap_err();
        assert!(err.contains("none of the threat-model fields"), "{err}");
    }

    #[test]
    fn a_bare_string_where_an_object_is_required_fails_validation() {
        let err = parse_threat_model(r#"{"assets": ["customer data"]}"#).unwrap_err();
        assert!(err.starts_with("ThreatModel validation failed"), "{err}");
    }
}
