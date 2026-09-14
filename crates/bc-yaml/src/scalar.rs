//! Scalar resolution: PyYAML-compatible implicit typing for plain
//! (unquoted) scalars, and escape handling for single-/double-quoted
//! scalars.
//!
//! Scoped to what this tool's own config files actually use: decimal
//! integers/floats, the YAML 1.1 boolean set (`true/false`, `yes/no`,
//! `on/off`, any casing) since PyYAML's `safe_load` resolves those too,
//! and `null`/`~`/empty. `.inf`/`.nan` are recognized as YAML sentinels
//! but resolve as plain strings, not numbers — JSON (and so
//! `serde_json::Number`) has no representation for a non-finite float.
//! Hex (`0x1A`), octal (`0o17`), and sexagesimal (`1:30`) integer forms
//! are deliberately NOT resolved as numbers either — none of the real
//! config/input files use them, and an unresolved one safely falls
//! through to a string rather than silently misparsing.

use serde_json::Value;

/// Resolve a plain (unquoted) scalar to its implicit type.
pub fn resolve_plain(s: &str) -> Value {
    if s.is_empty() {
        return Value::Null;
    }
    match s {
        "~" | "null" | "Null" | "NULL" => return Value::Null,
        "true" | "True" | "TRUE" | "yes" | "Yes" | "YES" | "on" | "On" | "ON" => {
            return Value::Bool(true)
        }
        "false" | "False" | "FALSE" | "no" | "No" | "NO" | "off" | "Off" | "OFF" => {
            return Value::Bool(false)
        }
        // `.inf`/`-.inf`/`.nan` are YAML 1.1 float sentinels, but
        // `serde_json::Number` can't structurally hold a non-finite float
        // (see `bc-model::coerce`'s doc comment for the same invariant) —
        // `Number::from_f64` always returns `None` for them. Falling
        // through to a plain string is the only sensible outcome: no real
        // config uses these, and a string is never silently wrong the way
        // e.g. treating `.inf` as `0` would be.
        ".inf" | ".Inf" | ".INF" | "+.inf" | "+.Inf" | "+.INF" | "-.inf" | "-.Inf" | "-.INF" => {
            return Value::String(s.to_string())
        }
        _ => {}
    }
    if let Ok(i) = s.parse::<i64>() {
        return Value::Number(i.into());
    }
    if looks_like_float(s) {
        if let Ok(f) = s.parse::<f64>() {
            if let Some(n) = serde_json::Number::from_f64(f) {
                return Value::Number(n);
            }
        }
    }
    Value::String(s.to_string())
}

/// True if `s` (already known not to be a bare integer) has the shape of a
/// decimal float literal: optional sign, digits, and a `.` and/or
/// exponent. Deliberately stricter than `f64::from_str`, which also
/// accepts `"inf"`/`"nan"` (unqualified, no leading dot) as valid input —
/// YAML's float sentinel forms are the dotted `.inf`/`.nan` spellings
/// only, already handled above, so a bare "infinity" or "NaN" typed by a
/// config author must resolve as a string, not silently become a float.
fn looks_like_float(s: &str) -> bool {
    let s = s.strip_prefix(['+', '-']).unwrap_or(s);
    if s.is_empty() {
        return false;
    }
    let mut chars = s.chars().peekable();
    let mut seen_digit = false;
    let mut seen_dot = false;
    let mut seen_e = false;
    while let Some(c) = chars.next() {
        match c {
            '0'..='9' => seen_digit = true,
            '.' if !seen_dot && !seen_e => seen_dot = true,
            'e' | 'E' if !seen_e && seen_digit => {
                seen_e = true;
                if matches!(chars.peek(), Some('+') | Some('-')) {
                    chars.next();
                }
            }
            _ => return false,
        }
    }
    seen_digit && (seen_dot || seen_e)
}

/// Unescape a single-quoted YAML scalar body (quotes already stripped).
/// The *only* escape in single-quoted style is `''` -> a literal `'`;
/// backslashes have no special meaning at all.
pub fn unescape_single_quoted(body: &str) -> String {
    body.replace("''", "'")
}

/// Unescape a double-quoted YAML scalar body (quotes already stripped).
/// Supports the common C-like escapes; an unrecognized `\x` sequence
/// passes the character through literally rather than erroring, since a
/// config file with a stray backslash is far more likely than a
/// deliberate obscure escape this parser doesn't know about.
pub fn unescape_double_quoted(body: &str) -> String {
    let chars: Vec<char> = body.chars().collect();
    let mut out = String::with_capacity(body.len());
    let mut i = 0;
    while i < chars.len() {
        if chars[i] != '\\' || i + 1 >= chars.len() {
            out.push(chars[i]);
            i += 1;
            continue;
        }
        let esc = chars[i + 1];
        match esc {
            '\\' => out.push('\\'),
            '"' => out.push('"'),
            'n' => out.push('\n'),
            't' => out.push('\t'),
            'r' => out.push('\r'),
            '0' => out.push('\0'),
            'a' => out.push('\u{7}'),
            'b' => out.push('\u{8}'),
            'f' => out.push('\u{c}'),
            'v' => out.push('\u{b}'),
            'e' => out.push('\u{1b}'),
            ' ' => out.push(' '),
            'x' => {
                if let Some(v) = parse_hex_escape(&chars, i + 2, 2) {
                    out.push(v);
                    i += 2 + 2;
                    continue;
                }
                out.push('x');
            }
            'u' => {
                if let Some(v) = parse_hex_escape(&chars, i + 2, 4) {
                    out.push(v);
                    i += 2 + 4;
                    continue;
                }
                out.push('u');
            }
            'U' => {
                if let Some(v) = parse_hex_escape(&chars, i + 2, 8) {
                    out.push(v);
                    i += 2 + 8;
                    continue;
                }
                out.push('U');
            }
            other => out.push(other), // unknown escape: pass through literally
        }
        i += 2;
    }
    out
}

fn parse_hex_escape(chars: &[char], start: usize, len: usize) -> Option<char> {
    if start + len > chars.len() {
        return None;
    }
    let hex: String = chars[start..start + len].iter().collect();
    u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("", Value::Null)]
    #[case("~", Value::Null)]
    #[case("null", Value::Null)]
    #[case("Null", Value::Null)]
    #[case("NULL", Value::Null)]
    #[case("true", Value::Bool(true))]
    #[case("True", Value::Bool(true))]
    #[case("TRUE", Value::Bool(true))]
    #[case("yes", Value::Bool(true))]
    #[case("On", Value::Bool(true))]
    #[case("false", Value::Bool(false))]
    #[case("no", Value::Bool(false))]
    #[case("Off", Value::Bool(false))]
    #[case("25", Value::Number(serde_json::Number::from(25)))]
    #[case("-7", Value::Number(serde_json::Number::from(-7)))]
    #[case("+5", Value::Number(serde_json::Number::from(5)))]
    fn resolve_plain_cases(#[case] input: &str, #[case] expected: Value) {
        assert_eq!(resolve_plain(input), expected);
    }

    #[test]
    fn resolve_plain_float() {
        let v = resolve_plain("25.0");
        assert_eq!(v.as_f64(), Some(25.0));
    }

    #[test]
    fn resolve_plain_negative_float_with_exponent() {
        let v = resolve_plain("-1.5e3");
        assert_eq!(v.as_f64(), Some(-1500.0));
    }

    #[test]
    fn resolve_plain_float_with_explicit_exponent_sign() {
        let v = resolve_plain("1.5e+3");
        assert_eq!(v.as_f64(), Some(1500.0));
    }

    #[test]
    fn resolve_plain_float_shaped_but_unparseable_exponent_falls_back_to_string() {
        // "1e" passes the shape check (digit, then 'e') but has no digits
        // after the 'e', so f64::from_str actually rejects it -- exercises
        // the "shape looked right but parse failed" fallthrough.
        assert_eq!(resolve_plain("1e"), Value::String("1e".to_string()));
    }

    #[test]
    fn resolve_plain_float_that_parses_to_infinity_via_overflow_falls_back_to_string() {
        // "1e400" is shape-valid AND parses successfully as f64 (per
        // IEEE-754 overflow-to-infinity rules) -- but the resulting value
        // is non-finite, so serde_json::Number::from_f64 rejects it and
        // this must fall back to a string rather than silently becoming 0
        // or panicking.
        assert_eq!(resolve_plain("1e400"), Value::String("1e400".to_string()));
    }

    #[test]
    fn resolve_plain_lone_sign_is_not_float_shaped() {
        assert_eq!(resolve_plain("+"), Value::String("+".to_string()));
        assert_eq!(resolve_plain("-"), Value::String("-".to_string()));
    }

    #[test]
    fn resolve_plain_infinity_sentinels_fall_back_to_string() {
        // JSON (and so serde_json::Number) has no way to represent an
        // infinite value, so these YAML 1.1 float sentinels resolve as
        // plain strings rather than silently becoming some other number.
        assert_eq!(resolve_plain(".inf"), Value::String(".inf".to_string()));
        assert_eq!(resolve_plain("-.inf"), Value::String("-.inf".to_string()));
        assert_eq!(resolve_plain("+.INF"), Value::String("+.INF".to_string()));
    }

    #[test]
    fn resolve_plain_bare_infinity_word_is_a_string_not_a_float() {
        // Rust's f64::from_str would happily parse "infinity"/"nan" — YAML's
        // sentinel forms are the dotted spellings only, already handled
        // above, so a bare word must resolve as a plain string.
        assert_eq!(
            resolve_plain("infinity"),
            Value::String("infinity".to_string())
        );
        assert_eq!(resolve_plain("NaN"), Value::String("NaN".to_string()));
        assert_eq!(resolve_plain("inf"), Value::String("inf".to_string()));
    }

    #[test]
    fn resolve_plain_hex_and_octal_are_not_resolved_as_numbers() {
        // Deliberate scope limitation — see module doc comment.
        assert_eq!(resolve_plain("0x1A"), Value::String("0x1A".to_string()));
        assert_eq!(resolve_plain("0o17"), Value::String("0o17".to_string()));
    }

    #[test]
    fn resolve_plain_ordinary_string() {
        assert_eq!(
            resolve_plain("claude-sonnet-4-6"),
            Value::String("claude-sonnet-4-6".to_string())
        );
    }

    #[test]
    fn resolve_plain_string_that_looks_like_a_bad_float_falls_through() {
        // "1.2.3" has two dots -> not a valid float shape -> string.
        assert_eq!(resolve_plain("1.2.3"), Value::String("1.2.3".to_string()));
    }

    #[test]
    fn unescape_single_quoted_doubled_quote() {
        assert_eq!(unescape_single_quoted("it''s"), "it's");
        assert_eq!(
            unescape_single_quoted(r"no\backslash\handling"),
            r"no\backslash\handling"
        );
    }

    #[test]
    fn unescape_double_quoted_common_escapes() {
        assert_eq!(unescape_double_quoted(r"line1\nline2"), "line1\nline2");
        assert_eq!(unescape_double_quoted(r"tab\there"), "tab\there");
        assert_eq!(unescape_double_quoted(r#"quote\"here"#), "quote\"here");
        assert_eq!(unescape_double_quoted(r"back\\slash"), "back\\slash");
    }

    #[test]
    fn unescape_double_quoted_regex_pattern_from_real_fixture() {
        // "try:\\s*\\n\\s*.*\\n\\s*except.*:\\s*pass" from
        // inputs/remediation_playbook.yaml's forbid_patterns.
        let raw = r"try:\\s*\\n\\s*.*\\n\\s*except.*:\\s*pass";
        assert_eq!(
            unescape_double_quoted(raw),
            r"try:\s*\n\s*.*\n\s*except.*:\s*pass"
        );
    }

    #[test]
    fn unescape_double_quoted_hex_unicode_escapes() {
        assert_eq!(unescape_double_quoted(r"\x41"), "A");
        assert_eq!(unescape_double_quoted("\\u0041"), "A");
        assert_eq!(unescape_double_quoted(r"\U00000041"), "A");
    }

    #[test]
    fn unescape_double_quoted_truncated_hex_escape_passes_through_literally() {
        assert_eq!(unescape_double_quoted(r"\x4"), "x4");
        assert_eq!(unescape_double_quoted(r"\u12"), "u12");
        assert_eq!(unescape_double_quoted(r"\U1234"), "U1234");
    }

    #[test]
    fn unescape_double_quoted_unknown_escape_passes_through() {
        assert_eq!(unescape_double_quoted(r"\q"), "q");
    }

    #[test]
    fn unescape_double_quoted_trailing_lone_backslash() {
        assert_eq!(unescape_double_quoted("abc\\"), "abc\\");
    }

    #[test]
    fn unescape_double_quoted_all_named_escapes() {
        assert_eq!(unescape_double_quoted(r"\0"), "\0");
        assert_eq!(unescape_double_quoted(r"\a"), "\u{7}");
        assert_eq!(unescape_double_quoted(r"\b"), "\u{8}");
        assert_eq!(unescape_double_quoted(r"\f"), "\u{c}");
        assert_eq!(unescape_double_quoted(r"\v"), "\u{b}");
        assert_eq!(unescape_double_quoted(r"\e"), "\u{1b}");
        assert_eq!(unescape_double_quoted(r"\r"), "\r");
        assert_eq!(unescape_double_quoted("\\ "), " ");
    }
}
