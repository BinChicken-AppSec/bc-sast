use serde_json::Value;

pub fn norm(v: &Value) -> String {
    let raw = match v {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        Value::Bool(b) => {
            if *b {
                "True".to_string()
            } else {
                "False".to_string()
            }
        }
        Value::Number(n) => n.to_string(),
        other => other.to_string(),
    };
    raw.trim().to_lowercase().replace(['-', ' '], "_")
}

fn raw_str(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        Value::Bool(b) => {
            if *b {
                "True".to_string()
            } else {
                "False".to_string()
            }
        }
        Value::Number(n) => n.to_string(),
        other => other.to_string(),
    }
    .trim()
    .to_string()
}

pub fn coerce_enum_str(v: &Value, valid: &[&str], alias: &[(&str, &str)], default: &str) -> String {
    let raw = raw_str(v);
    if valid.contains(&raw.as_str()) {
        return raw;
    }
    let k = norm(v);
    if valid.contains(&k.as_str()) {
        return k;
    }
    alias
        .iter()
        .find(|(from, _)| *from == k.as_str())
        .map(|(_, to)| (*to).to_string())
        .unwrap_or_else(|| default.to_string())
}

pub fn coerce_int(v: &Value, default: i64) -> i64 {
    match v {
        Value::Bool(_) => default,
        Value::Number(n) => n
            .as_i64()
            .unwrap_or_else(|| n.as_f64().expect("Number is always finite") as i64),
        Value::String(s) => s.trim().parse::<i64>().unwrap_or(default),
        _ => default,
    }
}

pub fn coerce_confidence(v: &Value, default: f64) -> f64 {
    let f = match v {
        Value::Bool(_) => return default,
        Value::Number(n) => n.as_f64().expect("Number is always finite"),
        Value::String(s) => {
            let s = s.trim().trim_end_matches('%').trim();
            match s.parse::<f64>() {
                Ok(f) => f,
                Err(_) => return default,
            }
        }
        Value::Null => return default,
        _ => return default,
    };
    let f = if (2.0..=10.0).contains(&f) && f.fract() == 0.0 {
        f / 10.0
    } else if (2.0..=100.0).contains(&f) {
        f / 100.0
    } else {
        f
    };
    f.clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use serde_json::json;

    #[rstest]
    #[case(json!(null), "")]
    #[case(json!(""), "")]
    #[case(json!("Input-Validation"), "input_validation")]
    #[case(json!("  RPC  "), "rpc")]
    #[case(json!(true), "true")]
    #[case(json!(false), "false")]
    #[case(json!(42), "42")]
    #[case(json!([1, 2]), "[1,2]")]
    fn norm_cases(#[case] v: Value, #[case] expected: &str) {
        assert_eq!(norm(&v), expected);
    }

    const CONTROL_KIND_VALID: &[&str] = &[
        "auth",
        "sandbox",
        "input-validation",
        "aslr",
        "cfi",
        "other",
    ];
    const CONTROL_KIND_ALIAS: &[(&str, &str)] = &[
        ("authn", "auth"),
        ("authentication", "auth"),
        ("input_validation", "input-validation"),
        ("waf", "input-validation"),
        ("seccomp", "sandbox"),
    ];

    #[test]
    fn coerce_enum_str_exact_hit_preserves_hyphen() {
        assert_eq!(
            coerce_enum_str(
                &json!("input-validation"),
                CONTROL_KIND_VALID,
                CONTROL_KIND_ALIAS,
                "other"
            ),
            "input-validation"
        );
    }

    #[test]
    fn coerce_enum_str_normalized_hit_for_single_word_value() {
        assert_eq!(
            coerce_enum_str(
                &json!("Auth"),
                CONTROL_KIND_VALID,
                CONTROL_KIND_ALIAS,
                "other"
            ),
            "auth"
        );
    }

    #[test]
    fn coerce_enum_str_alias_recovers_hyphenated_value_from_normalized_form() {
        assert_eq!(
            coerce_enum_str(
                &json!("Input-Validation"),
                CONTROL_KIND_VALID,
                CONTROL_KIND_ALIAS,
                "other"
            ),
            "input-validation"
        );
        assert_eq!(
            coerce_enum_str(
                &json!("WAF"),
                CONTROL_KIND_VALID,
                CONTROL_KIND_ALIAS,
                "other"
            ),
            "input-validation"
        );
    }

    #[test]
    fn coerce_enum_str_handles_non_string_scalars() {
        assert_eq!(
            coerce_enum_str(
                &json!(true),
                CONTROL_KIND_VALID,
                CONTROL_KIND_ALIAS,
                "other"
            ),
            "other"
        );
        assert_eq!(
            coerce_enum_str(
                &json!(false),
                CONTROL_KIND_VALID,
                CONTROL_KIND_ALIAS,
                "other"
            ),
            "other"
        );
        assert_eq!(
            coerce_enum_str(&json!(42), CONTROL_KIND_VALID, CONTROL_KIND_ALIAS, "other"),
            "other"
        );
        assert_eq!(
            coerce_enum_str(
                &json!([1, 2]),
                CONTROL_KIND_VALID,
                CONTROL_KIND_ALIAS,
                "other"
            ),
            "other"
        );
    }

    #[test]
    fn coerce_enum_str_unknown_falls_back_to_default() {
        assert_eq!(
            coerce_enum_str(
                &json!("totally-unrecognized"),
                CONTROL_KIND_VALID,
                CONTROL_KIND_ALIAS,
                "other"
            ),
            "other"
        );
        assert_eq!(
            coerce_enum_str(
                &json!(null),
                CONTROL_KIND_VALID,
                CONTROL_KIND_ALIAS,
                "other"
            ),
            "other"
        );
    }

    #[rstest]
    #[case(json!(42), 0, 42)]
    #[case(json!(-7), 0, -7)]
    #[case(json!(true), 5, 5)]
    #[case(json!(false), 5, 5)]
    #[case(json!(3.7), 0, 3)]
    #[case(json!("42"), 0, 42)]
    #[case(json!("  -3 "), 0, -3)]
    #[case(json!("not a number"), 11, 11)]
    #[case(json!(null), 11, 11)]
    #[case(json!([1,2]), 11, 11)]
    fn coerce_int_cases(#[case] v: Value, #[case] default: i64, #[case] expected: i64) {
        assert_eq!(coerce_int(&v, default), expected);
    }

    #[rstest]
    #[case(json!(0.85), 0.85)]
    #[case(json!(true), 0.5)]
    #[case(json!(false), 0.5)]
    #[case(json!(null), 0.5)]
    #[case(json!(8), 0.8)]
    #[case(json!(95), 0.95)]
    #[case(json!("95%"), 0.95)]
    #[case(json!(" 0.42 "), 0.42)]
    #[case(json!(1.5), 1.0)]
    #[case(json!(-1.0), 0.0)]
    #[case(json!("not a number"), 0.5)]
    #[case(json!([1]), 0.5)]
    fn coerce_confidence_cases(#[case] v: Value, #[case] expected: f64) {
        assert_eq!(coerce_confidence(&v, 0.5), expected);
    }

    #[test]
    fn coerce_confidence_integral_ten_is_ambiguous_with_percent_and_prefers_scale_ten() {
        assert_eq!(coerce_confidence(&json!(10.0), 0.5), 1.0);
    }
}
