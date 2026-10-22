//! LLM-output coercion helpers, ported from `vvaharness/models.py`'s
//! `_norm` / `_coerce_enum` / `_coerce_int` / `_coerce_confidence`.
//!
//! Several fields on the structs in this crate are populated straight from
//! a `serde_json::from_value` of LLM-emitted JSON. A single off-schema
//! value (e.g. `kind="rpc"`, `size="tiny"`, `confidence="high"`) must not
//! kill the whole run — every such field is deserialized through one of
//! these coercers instead of plain strict deserialization, mapping common
//! synonyms to a valid value and falling back to a safe default. None of
//! these functions can fail (they don't return `Result`), matching the
//! Python original's "always produces something usable" contract.

use serde_json::Value;

/// `str(v or "").strip().lower().replace("-","_").replace(" ","_")` —
/// Python's `or` treats `None`/empty-string as falsy (mapped to `""`
/// before stringifying); anything else is stringified as Python's `str()`
/// would render it. Booleans render as `"True"`/`"False"` and numbers
/// render via their natural decimal form, matching Python's `str(int)`/
/// `str(float)` closely enough for this normalization's purpose (these are
/// unrealistic inputs for an enum-shaped field in the first place — this
/// only needs to never panic and produce *some* deterministic string).
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

/// `str(v or "").strip()` without lowercasing — the exact-hit half of
/// `_coerce_enum`, kept separate from [`norm`] because it preserves case
/// *and* hyphens (needed for valid values like `"input-validation"` that
/// contain a literal hyphen the normalized form would convert away).
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

/// Coerce an arbitrary JSON value to one of `valid`'s canonical strings:
/// 1. exact (case- and hyphen-preserving) hit against `valid`,
/// 2. normalized (lowercase, `-`/` ` -> `_`) hit against `valid`,
/// 3. `alias` lookup of the normalized form,
/// 4. `default`.
///
/// `alias`'s values must themselves always be members of `valid` — every
/// call site in this crate upholds that invariant, mirroring the Python
/// source's own alias tables.
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

/// Crash-proof int coercion. `bool` is rejected (Python: `bool ⊂ int`, but
/// a JSON boolean is not a meaningful integer here).
///
/// Python's original also guards against NaN/±Infinity (`int()` raises on
/// those). There is no equivalent guard here: `serde_json::Number` can
/// structurally never hold a non-finite float — the JSON grammar has no
/// token for one, `Number::from_f64` rejects them at construction, and the
/// `json!` macro silently maps `f64::NAN`/`INFINITY` to `Value::Null`
/// instead (verified empirically) — so `Number::as_f64()` is guaranteed
/// `Some(finite)` for every `Number` this crate's `serde_json` (no
/// `arbitrary_precision` feature) can ever construct. Encoding a dead
/// "what if it's infinite" branch just to mirror Python here would trade a
/// real invariant for untestable dead code.
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

/// Crash-proof float coercion for a `[0.0, 1.0]`-bounded confidence field.
/// Maps a 1-10 or 1-100 scale down to `[0,1]`, strips a trailing `%`,
/// clamps, and never fails — an uninterpretable value degrades to
/// `default` instead of the finding vanishing entirely.
///
/// See [`coerce_int`]'s doc comment for why there is no NaN/Infinity guard
/// on the `Number` branch: it's structurally unreachable through this
/// crate's `serde_json`.
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
        // "auth" has no hyphen, so the normalized form matches `valid` directly
        // (no alias table entry needed for this exact case).
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
        // "Input-Validation" normalizes to "input_validation" (underscore),
        // which is NOT itself in `valid` (which has the hyphenated form) —
        // the alias table is what maps it back.
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
        // An enum-shaped field is realistically always a string, but the
        // coercer must not panic on a bool/number/array — every non-string
        // JSON scalar just falls through to `default` since none of them
        // can ever equal a `valid` member.
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
    #[case(json!(true), 5, 5)] // bool rejected -> default
    #[case(json!(false), 5, 5)]
    #[case(json!(3.7), 0, 3)] // truncates toward zero
    #[case(json!("42"), 0, 42)]
    #[case(json!("  -3 "), 0, -3)]
    #[case(json!("not a number"), 11, 11)]
    #[case(json!(null), 11, 11)]
    #[case(json!([1,2]), 11, 11)]
    fn coerce_int_cases(#[case] v: Value, #[case] default: i64, #[case] expected: i64) {
        assert_eq!(coerce_int(&v, default), expected);
    }

    // Note: `json!(f64::NAN)`/`json!(f64::INFINITY)` do NOT produce a
    // `Value::Number` — the `json!` macro (like `Number::from_f64`) maps
    // non-finite floats to `Value::Null` instead (verified empirically),
    // which is already covered by the `json!(null)` cases above. There is
    // no separate "rejects infinite float" case to test because
    // `serde_json::Number` can't structurally hold one in the first place
    // — see `coerce_int`'s doc comment.

    #[rstest]
    #[case(json!(0.85), 0.85)]
    #[case(json!(true), 0.5)] // bool rejected
    #[case(json!(false), 0.5)]
    #[case(json!(null), 0.5)]
    #[case(json!(8), 0.8)] // 2..=10 integral -> /10
    #[case(json!(95), 0.95)] // 2..=100 -> /100
    #[case(json!("95%"), 0.95)]
    #[case(json!(" 0.42 "), 0.42)]
    #[case(json!(1.5), 1.0)] // clamped
    #[case(json!(-1.0), 0.0)] // clamped
    #[case(json!("not a number"), 0.5)]
    #[case(json!([1]), 0.5)]
    fn coerce_confidence_cases(#[case] v: Value, #[case] expected: f64) {
        assert_eq!(coerce_confidence(&v, 0.5), expected);
    }

    #[test]
    fn coerce_confidence_integral_ten_is_ambiguous_with_percent_and_prefers_scale_ten() {
        // 10.0 satisfies BOTH the 2..=10 (integral) and 2..=100 branches;
        // Python's elif ordering picks the /10 branch first — 10 -> 1.0.
        assert_eq!(coerce_confidence(&json!(10.0), 0.5), 1.0);
    }
}
