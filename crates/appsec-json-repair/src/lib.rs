mod truncated;

use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;

pub const MAX_JSON_INPUT: usize = 5_000_000;

pub use truncated::{close_truncated, extract_truncated_json};

const VALID_ESCAPE: &str = "\"\\/nrtu";

#[derive(Debug, thiserror::Error)]
pub enum ExtractError {
    #[error("no JSON object found in response")]
    NotFound,
    #[error("invalid JSON: {0}")]
    Invalid(#[from] serde_json::Error),
}

static FENCE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?s)```(?:json)?\s*(.*?)\s*```").unwrap());
static FENCE_FULL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?s)^```(?:json)?\s*(.*?)\s*```$").unwrap());
static FENCE_OPEN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^```\w*\s*").unwrap());

pub fn extract_json(text: &str) -> Result<Value, ExtractError> {
    extract_json_capped(text, MAX_JSON_INPUT)
}

fn extract_json_capped(text: &str, cap: usize) -> Result<Value, ExtractError> {
    let scan_text: String = if text.chars().count() > cap {
        text.chars().take(cap).collect()
    } else {
        text.to_string()
    };
    let stripped = scan_text.trim();

    let mut candidates: Vec<String> = Vec::new();
    if let Some(caps) = FENCE_FULL.captures(stripped) {
        candidates.push(caps.get(1).unwrap().as_str().to_string());
    }
    for caps in FENCE.captures_iter(&scan_text) {
        candidates.push(caps.get(1).unwrap().as_str().to_string());
    }
    candidates.push(scan_text.clone());

    let peek = FENCE_OPEN.replace(stripped, "");
    let want_dict = peek.starts_with('{');

    let mut held_list: Option<Value> = None;
    let mut last_err: Option<serde_json::Error> = None;

    for cand in &candidates {
        let chars: Vec<char> = cand.chars().collect();
        let mut i = 0usize;
        while i < chars.len() {
            if chars[i] != '{' && chars[i] != '[' {
                i += 1;
                continue;
            }
            let Some((start, end)) = balanced_span(&chars, i) else {
                i += 1;
                continue;
            };
            let span: String = chars[start..end].iter().collect();
            let val = match serde_json::from_str::<Value>(&span) {
                Ok(v) => Some(v),
                Err(e) => {
                    last_err = Some(e);
                    repair_and_parse(&span)
                }
            };
            let Some(val) = val else {
                i = end;
                continue;
            };
            if want_dict && matches!(val, Value::Array(_)) {
                if held_list.is_none() {
                    held_list = Some(val);
                }
                i = end;
                continue;
            }
            return Ok(val);
        }
    }

    if let Some(v) = held_list {
        return Ok(v);
    }
    match last_err {
        Some(e) => Err(ExtractError::Invalid(e)),
        None => Err(ExtractError::NotFound),
    }
}

fn repair_and_parse(span: &str) -> Option<Value> {
    let escaped = repair_invalid_escapes(span);
    if escaped != span {
        if let Ok(v) = serde_json::from_str::<Value>(&escaped) {
            return Some(v);
        }
    }
    let loose = repair_loose_json(span)?;
    if let Ok(v) = serde_json::from_str::<Value>(&loose) {
        return Some(v);
    }
    let both = repair_invalid_escapes(&loose);
    if both != loose {
        if let Ok(v) = serde_json::from_str::<Value>(&both) {
            return Some(v);
        }
    }
    None
}

fn repair_loose_json(span: &str) -> Option<String> {
    let chars: Vec<char> = span.chars().collect();
    let mut out = String::with_capacity(span.len());
    let mut changed = false;
    let mut i = 0usize;

    while i < chars.len() {
        let c = chars[i];
        match c {
            '"' => {
                out.push('"');
                i += 1;
                while i < chars.len() {
                    let d = chars[i];
                    out.push(d);
                    i += 1;
                    if d == '\\' {
                        if let Some(&esc) = chars.get(i) {
                            out.push(esc);
                            i += 1;
                        }
                    } else if d == '"' {
                        break;
                    }
                }
            }
            '\'' | '\u{2018}' | '\u{201C}' => {
                let close = match c {
                    '\u{2018}' => '\u{2019}',
                    '\u{201C}' => '\u{201D}',
                    _ => '\'',
                };
                changed = true;
                out.push('"');
                i += 1;
                while i < chars.len() && chars[i] != close {
                    match chars[i] {
                        '\\' if chars.get(i + 1) == Some(&'\'') => {
                            out.push('\'');
                            i += 2;
                        }
                        '\\' => {
                            out.push('\\');
                            i += 1;
                            if let Some(&esc) = chars.get(i) {
                                out.push(esc);
                                i += 1;
                            }
                        }
                        '"' => {
                            out.push_str("\\\"");
                            i += 1;
                        }
                        d => {
                            out.push(d);
                            i += 1;
                        }
                    }
                }
                i += 1;
                out.push('"');
            }
            ',' => {
                let mut j = i + 1;
                while j < chars.len() && chars[j].is_whitespace() {
                    j += 1;
                }
                if matches!(chars.get(j), Some('}') | Some(']')) {
                    changed = true;
                } else {
                    out.push(',');
                }
                i += 1;
            }
            c if c.is_alphabetic() || c == '_' => {
                let start = i;
                while i < chars.len()
                    && (chars[i].is_alphanumeric() || chars[i] == '_' || chars[i] == '$')
                {
                    i += 1;
                }
                let word: String = chars[start..i].iter().collect();
                let mut j = i;
                while j < chars.len() && chars[j].is_whitespace() {
                    j += 1;
                }
                if chars.get(j) == Some(&':') {
                    changed = true;
                    out.push('"');
                    out.push_str(&word);
                    out.push('"');
                } else {
                    match word.as_str() {
                        "True" => {
                            changed = true;
                            out.push_str("true");
                        }
                        "False" => {
                            changed = true;
                            out.push_str("false");
                        }
                        "None" => {
                            changed = true;
                            out.push_str("null");
                        }
                        _ => out.push_str(&word),
                    }
                }
            }
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }

    changed.then_some(out)
}

fn repair_invalid_escapes(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0usize;
    while i < chars.len() {
        let ch = chars[i];
        if ch == '\\' {
            let valid_next = chars.get(i + 1).is_some_and(|n| VALID_ESCAPE.contains(*n));
            if valid_next {
                out.push(ch);
                out.push(chars[i + 1]);
                i += 2;
                continue;
            }
            out.push('\\');
            out.push('\\');
            i += 1;
            continue;
        }
        out.push(ch);
        i += 1;
    }
    out
}

fn balanced_span(chars: &[char], start: usize) -> Option<(usize, usize)> {
    let open_ch = chars[start];
    let close_ch = if open_ch == '{' { '}' } else { ']' };
    let mut depth = 0i32;
    let mut in_str = false;
    let mut esc = false;
    for (i, &ch) in chars.iter().enumerate().skip(start) {
        if in_str {
            if esc {
                esc = false;
            } else if ch == '\\' {
                esc = true;
            } else if ch == '"' {
                in_str = false;
            }
            continue;
        }
        if ch == '"' {
            in_str = true;
        } else if ch == open_ch {
            depth += 1;
        } else if ch == close_ch {
            depth -= 1;
            if depth == 0 {
                return Some((start, i + 1));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[test]
    fn plain_object_no_fence() {
        let v = extract_json(r#"{"a": 1}"#).unwrap();
        assert_eq!(v, serde_json::json!({"a": 1}));
    }

    #[test]
    fn plain_array_no_fence() {
        let v = extract_json("[1, 2, 3]").unwrap();
        assert_eq!(v, serde_json::json!([1, 2, 3]));
    }

    #[rstest]
    #[case("```json\n{\"a\": 1}\n```")]
    #[case("```\n{\"a\": 1}\n```")]
    #[case("Here is the result:\n```json\n{\"a\": 1}\n```\nDone.")]
    fn fenced_object_extracted(#[case] text: &str) {
        let v = extract_json(text).unwrap();
        assert_eq!(v, serde_json::json!({"a": 1}));
    }

    #[test]
    fn prose_prefix_and_suffix_around_bare_object() {
        let v = extract_json("Sure, here you go: {\"a\": 1} — hope that helps!").unwrap();
        assert_eq!(v, serde_json::json!({"a": 1}));
    }

    #[test]
    fn invalid_regex_escape_is_repaired() {
        let v = extract_json(r#"{"pattern": "\d+"}"#).unwrap();
        assert_eq!(v["pattern"], "\\d+");
    }

    #[test]
    fn windows_path_escape_is_repaired() {
        let v = extract_json(r#"{"path": "C:\Users\me"}"#).unwrap();
        assert_eq!(v["path"], "C:\\Users\\me");
    }

    #[test]
    fn valid_escapes_are_left_untouched() {
        let v = extract_json(r#"{"s": "line1\nline2\t\"quoted\"\\end"}"#).unwrap();
        assert_eq!(v["s"], "line1\nline2\t\"quoted\"\\end");
    }

    #[test]
    fn repair_pass_preserves_valid_escapes_alongside_invalid_ones() {
        let v = extract_json(r#"{"mixed": "line1\nhas\dboth"}"#).unwrap();
        assert_eq!(v["mixed"], "line1\nhas\\dboth");
    }

    #[test]
    fn whole_response_fenced_block_with_inner_backticks_hb009() {
        let text = "```json\n{\"note\": \"see ```python\\nprint(1)\\n``` for details\"}\n```";
        let v = extract_json(text).unwrap();
        assert_eq!(v["note"], "see ```python\nprint(1)\n``` for details");
    }

    #[test]
    fn bracket_lookalikes_inside_a_string_value_do_not_confuse_the_scanner() {
        let text = r#"{"narrative": "counts were [10] and [20]", "result": {"ok": true}}"#;
        let v = extract_json(text).unwrap();
        assert_eq!(
            v,
            serde_json::json!({"narrative": "counts were [10] and [20]", "result": {"ok": true}})
        );
    }

    #[test]
    fn list_returned_directly_when_response_does_not_signal_dict_intent() {
        let text = "prose [1, 2, 3] more prose, no object here";
        let v = extract_json(text).unwrap();
        assert_eq!(v, serde_json::json!([1, 2, 3]));
    }

    #[test]
    fn held_list_is_returned_as_fallback_when_no_dict_ever_found() {
        let text = r#"{ x } [1,2] prose, no dict anywhere"#;
        let v = extract_json(text).unwrap();
        assert_eq!(v, serde_json::json!([1, 2]));
    }

    #[test]
    fn two_decoy_lists_are_held_without_overwrite_then_dict_wins() {
        let text = r#"{ x } [1,2] prose [3,4] prose {"real": true}"#;
        let v = extract_json(text).unwrap();
        assert_eq!(v, serde_json::json!({"real": true}));
    }

    #[test]
    fn no_json_found_returns_not_found() {
        let err = extract_json("just a plain sentence, no braces at all").unwrap_err();
        assert!(matches!(err, ExtractError::NotFound));
    }

    #[test]
    fn unrepairable_garbage_returns_invalid_error() {
        let err = extract_json("{not json at all, just braces}").unwrap_err();
        assert!(matches!(err, ExtractError::Invalid(_)));
    }

    #[test]
    fn unclosed_brace_is_skipped_not_treated_as_a_span() {
        let v = extract_json("prose { unbalanced then {\"a\": 1} for real").unwrap();
        assert_eq!(v, serde_json::json!({"a": 1}));
    }

    #[test]
    fn error_display_messages() {
        assert_eq!(
            ExtractError::NotFound.to_string(),
            "no JSON object found in response"
        );
        let serde_err = serde_json::from_str::<Value>("not json").unwrap_err();
        assert!(ExtractError::Invalid(serde_err)
            .to_string()
            .starts_with("invalid JSON:"));
    }

    #[test]
    fn content_within_cap_is_found() {
        let text = format!(r#"{{"a": 1}}{}"#, "x".repeat(100));
        let v = extract_json_capped(&text, 20).unwrap();
        assert_eq!(v, serde_json::json!({"a": 1}));
    }

    #[test]
    fn content_beyond_cap_is_truncated_away() {
        let text = format!(r#"{}{{"a": 1}}"#, "x".repeat(100));
        let err = extract_json_capped(&text, 20).unwrap_err();
        assert!(matches!(err, ExtractError::NotFound));
    }

    #[test]
    fn extract_json_uses_the_real_max_constant() {
        let v = extract_json(r#"{"a": 1}"#).unwrap();
        assert_eq!(v, serde_json::json!({"a": 1}));
        assert_eq!(MAX_JSON_INPUT, 5_000_000);
    }

    #[test]
    fn unquoted_object_keys_are_quoted() {
        assert_eq!(
            extract_json(r#"{verdict: "Fixed", changes: 2}"#).unwrap(),
            serde_json::json!({"verdict": "Fixed", "changes": 2})
        );
    }

    #[test]
    fn single_quoted_keys_and_values_are_converted() {
        assert_eq!(
            extract_json("{'verdict': 'Fixed', 'files': ['app.py']}").unwrap(),
            serde_json::json!({"verdict": "Fixed", "files": ["app.py"]})
        );
    }

    #[test]
    fn a_realistic_single_quoted_s10_envelope_parses() {
        let text = "Here is my result:\n\
            {'verdict': 'Fixed', 'summary': 'Used send_from_directory', \
             'changes': [{'file': 'app.py', 'summary': \"escaped the user's path\"}], \
             'root_cause': 'unsanitized filename', 'remaining_risks': [], \
             'confident': True, 'score': None,}";
        let v = extract_json(text).unwrap();
        assert_eq!(v["verdict"], "Fixed");
        assert_eq!(v["changes"][0]["summary"], "escaped the user's path");
        assert_eq!(v["confident"], serde_json::Value::Bool(true));
        assert_eq!(v["score"], serde_json::Value::Null);
    }

    #[test]
    fn trailing_commas_and_python_literals_are_normalized() {
        assert_eq!(
            extract_json(r#"{"a": True, "b": False, "c": None, "d": [1, 2,],}"#).unwrap(),
            serde_json::json!({"a": true, "b": false, "c": null, "d": [1, 2]})
        );
    }

    #[test]
    fn typographic_quotes_used_as_delimiters_are_converted() {
        assert_eq!(
            extract_json("{\u{201C}verdict\u{201D}: \u{2018}Fixed\u{2019}}").unwrap(),
            serde_json::json!({"verdict": "Fixed"})
        );
    }

    #[test]
    fn a_double_quote_inside_a_single_quoted_value_is_escaped() {
        assert_eq!(
            extract_json(r#"{'msg': 'he said "hi"'}"#).unwrap(),
            serde_json::json!({"msg": "he said \"hi\""})
        );
    }

    #[test]
    fn an_escaped_single_quote_inside_a_single_quoted_value_is_unescaped() {
        assert_eq!(
            extract_json(r"{'msg': 'it\'s here'}").unwrap(),
            serde_json::json!({"msg": "it's here"})
        );
    }

    #[test]
    fn valid_json_is_returned_untouched_and_never_reaches_the_repair() {
        let text = r#"{"a": "the user's name", "b": "uses shell=True", "c": "None", "d": "x, }", "e": "say \"hi\"", "f": "a: b"}"#;
        let v = extract_json(text).unwrap();
        assert_eq!(v["a"], "the user's name");
        assert_eq!(v["b"], "uses shell=True");
        assert_eq!(v["c"], "None");
        assert_eq!(v["d"], "x, }");
        assert_eq!(v["e"], "say \"hi\"");
        assert_eq!(v["f"], "a: b");
        assert!(repair_loose_json(text).is_none(), "nothing to change");
    }

    #[test]
    fn a_broken_span_keeps_apostrophes_inside_valid_strings_intact() {
        let v = extract_json(r#"{note: "it's True, isn't it", ok: True}"#).unwrap();
        assert_eq!(v["note"], "it's True, isn't it");
        assert_eq!(v["ok"], serde_json::Value::Bool(true));
    }

    #[test]
    fn repair_loose_json_reports_no_change_for_already_valid_input() {
        assert!(repair_loose_json(r#"{"a": [1, true, null], "b": "c"}"#).is_none());
    }

    #[test]
    fn an_unterminated_single_quoted_string_is_closed_rather_than_running_off_the_end() {
        let repaired = repair_loose_json("{'a': 'b").unwrap();
        assert_eq!(repaired, r#"{"a": "b""#);
    }

    #[test]
    fn a_trailing_backslash_at_the_end_of_a_string_is_survivable() {
        let repaired = repair_loose_json(r"{'a': 'b\").unwrap();
        assert!(repaired.starts_with(r#"{"a": "b"#), "{repaired}");
        assert!(repair_loose_json(r#"{"a": "b\"#).is_none());
    }

    #[test]
    fn genuinely_unrepairable_input_still_reports_the_original_error() {
        let err = extract_json("{@@@}").unwrap_err();
        assert!(matches!(err, ExtractError::Invalid(_)), "{err}");
    }

    #[test]
    fn a_later_valid_object_is_still_found_after_an_unrepairable_one() {
        let v = extract_json(r#"{@@@} then {"good": 1}"#).unwrap();
        assert_eq!(v, serde_json::json!({"good": 1}));
    }

    #[test]
    fn a_span_needing_both_quoting_and_escape_repair_is_fixed_by_the_chain() {
        let v = extract_json(r#"{pattern: "\d+ digits"}"#).unwrap();
        assert_eq!(v["pattern"], r"\d+ digits");
    }

    #[test]
    fn a_span_that_resists_the_escape_pass_too_gives_up() {
        assert!(repair_and_parse(r"{'a': '\d' @@}").is_none());
    }

    #[test]
    fn a_repaired_span_that_still_will_not_parse_gives_up() {
        assert!(repair_and_parse("{'a': 1,, }").is_none());
    }

    #[test]
    fn an_escape_inside_a_single_quoted_string_is_carried_over() {
        let v = extract_json(r"{'a': 'line\nbreak'}").unwrap();
        assert_eq!(v["a"], "line\nbreak");
    }

    #[test]
    fn dollar_and_underscore_key_characters_survive_quoting() {
        assert_eq!(
            extract_json("{_private$key: 1}").unwrap(),
            serde_json::json!({"_private$key": 1})
        );
    }
}
