use serde_json::Value;

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

pub fn unescape_single_quoted(body: &str) -> String {
    body.replace("''", "'")
}

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
            other => out.push(other),
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
        assert_eq!(resolve_plain("1e"), Value::String("1e".to_string()));
    }

    #[test]
    fn resolve_plain_float_that_parses_to_infinity_via_overflow_falls_back_to_string() {
        assert_eq!(resolve_plain("1e400"), Value::String("1e400".to_string()));
    }

    #[test]
    fn resolve_plain_lone_sign_is_not_float_shaped() {
        assert_eq!(resolve_plain("+"), Value::String("+".to_string()));
        assert_eq!(resolve_plain("-"), Value::String("-".to_string()));
    }

    #[test]
    fn resolve_plain_infinity_sentinels_fall_back_to_string() {
        assert_eq!(resolve_plain(".inf"), Value::String(".inf".to_string()));
        assert_eq!(resolve_plain("-.inf"), Value::String("-.inf".to_string()));
        assert_eq!(resolve_plain("+.INF"), Value::String("+.INF".to_string()));
    }

    #[test]
    fn resolve_plain_bare_infinity_word_is_a_string_not_a_float() {
        assert_eq!(
            resolve_plain("infinity"),
            Value::String("infinity".to_string())
        );
        assert_eq!(resolve_plain("NaN"), Value::String("NaN".to_string()));
        assert_eq!(resolve_plain("inf"), Value::String("inf".to_string()));
    }

    #[test]
    fn resolve_plain_hex_and_octal_are_not_resolved_as_numbers() {
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
