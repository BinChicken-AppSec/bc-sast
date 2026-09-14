//! Pull a JSON object/array out of a model response that may have prose
//! (and possibly fenced code blocks) around it.
//!
//! Ported from the Python reference's `util/json_extract.py`, minus its
//! stderr `WARN` print on truncation — logging an oversized-input event is
//! an orchestration-layer concern, not something a pure-logic utility
//! crate should do as a side effect.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;

/// Defensive ceiling (in Unicode scalar values, matching Python's
/// codepoint-counting `len()`) on the text scanned. The balanced-span scan
/// is O(openers x length); this cap only ever trims a runaway response —
/// normal LLM envelopes are a few KB.
pub const MAX_JSON_INPUT: usize = 5_000_000;

const VALID_ESCAPE: &str = "\"\\/nrtu";

#[derive(Debug, thiserror::Error)]
pub enum ExtractError {
    #[error("no JSON object found in response")]
    NotFound,
    #[error("invalid JSON: {0}")]
    Invalid(#[from] serde_json::Error),
}

// Strip ```json ... ``` fences if present, then find the first balanced
// brace/bracket block. `FENCE_FULL` additionally anchors both ends so a
// response that IS, in its entirety, one fenced block is recovered whole
// even when the JSON value contains a literal ``` inside a string (e.g. a
// narrative quoting a code block) — a plain non-anchored find would stop
// at that inner ``` and return a truncated, unbalanced body.
static FENCE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?s)```(?:json)?\s*(.*?)\s*```").unwrap());
static FENCE_FULL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?s)^```(?:json)?\s*(.*?)\s*```$").unwrap());
static FENCE_OPEN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^```\w*\s*").unwrap());

/// Extract the first JSON object or array found in `text`.
pub fn extract_json(text: &str) -> Result<Value, ExtractError> {
    extract_json_capped(text, MAX_JSON_INPUT)
}

/// [`extract_json`] with an explicit input-length cap, so the truncation
/// boundary is testable without constructing multi-megabyte strings.
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

    // If the (post-fence-opener) response visibly starts with '{', a
    // top-level *list* result is almost certainly a sub-span like "[10]"
    // that happened to balance inside a string literal. Hold the first
    // such list and keep scanning for a dict; only return the held list if
    // no dict is found in any candidate.
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

/// Every repair this module knows, cheapest and least invasive first,
/// re-parsing after each. Only ever reached once a strict parse of the
/// span has already failed, so a response that is valid JSON is returned
/// exactly as the model wrote it and none of this runs.
///
/// Net-new versus `util/json_extract.py`, which stops at the escape
/// repair. A live scan on 2026-09-03 lost a real path-traversal fix
/// because the S10 agent's final answer came back with unquoted keys:
/// `bc_stage_s10` could not parse it, the finding fell through to
/// `Needs Review`, and no fix suggestion was ever posted.
fn repair_and_parse(span: &str) -> Option<Value> {
    let escaped = repair_invalid_escapes(span);
    if escaped != span {
        if let Ok(v) = serde_json::from_str::<Value>(&escaped) {
            return Some(v);
        }
    }
    // The loose repair works off the ORIGINAL span (the escape pass may
    // have made things worse for a span whose real problem was quoting),
    // then gets the escape pass applied on top if it still won't parse.
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

/// Rewrite the JSON dialects models actually emit into real JSON:
/// single-quoted or typographically-quoted strings, unquoted object
/// keys, trailing commas before a closer, and Python's `True`/`False`/
/// `None` literals. Returns `None` when there was nothing to change, so
/// the caller doesn't re-parse identical text.
///
/// **Everything here is driven by one left-to-right scan that tracks
/// string state**, because the whole risk of this pass is corrupting
/// content that was already fine: an apostrophe in `"the user's name"`,
/// the word `True` inside `"uses shell=True"`, or a brace inside prose
/// must all survive untouched. A correctly-quoted string literal is
/// copied through verbatim, escapes included, and never inspected.
fn repair_loose_json(span: &str) -> Option<String> {
    let chars: Vec<char> = span.chars().collect();
    let mut out = String::with_capacity(span.len());
    let mut changed = false;
    let mut i = 0usize;

    while i < chars.len() {
        let c = chars[i];
        match c {
            // A proper JSON string: copy it out verbatim, honouring
            // escapes, so nothing inside it is ever rewritten.
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
            // A string the model delimited the wrong way.
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
                        // `\'` is meaningless in JSON — unescape it.
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
                        // A double quote that was legal inside single
                        // quotes has to be escaped once it becomes the
                        // delimiter.
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
                i += 1; // consume the closing delimiter, if any
                out.push('"');
            }
            ',' => {
                let mut j = i + 1;
                while j < chars.len() && chars[j].is_whitespace() {
                    j += 1;
                }
                if matches!(chars.get(j), Some('}') | Some(']')) {
                    changed = true; // trailing comma: drop it
                } else {
                    out.push(',');
                }
                i += 1;
            }
            // A bare word: either an unquoted key or a Python literal.
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
                        // Anything else (`true`, a number, genuine
                        // garbage) is left for serde to judge.
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

/// Best-effort repair: double any backslash that does NOT introduce a
/// valid JSON escape, so a value like `"\d+"` (regex) or `"C:\Users"`
/// (Windows path) parses. Backslashes only legally appear inside JSON
/// string literals, so scanning the whole span is safe; genuinely valid
/// escapes (`\\`, `\"`, `\n`, `\uXXXX`, ...) are left untouched.
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

/// Scan `chars` from `start` (which must be `{` or `[`) for the matching
/// balanced close, skipping over brace/bracket characters that appear
/// inside a (possibly escaped-quote-containing) JSON string literal.
/// Returns the `[start, end)` char-index range of the balanced span, or
/// `None` if the input runs out before depth returns to zero.
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
        // `\d` is not a valid JSON escape; the repair pass doubles the
        // backslash so it parses as the literal two-character sequence
        // \d rather than failing outright.
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
        // The span above is already-valid JSON, so `repair_invalid_escapes`
        // is never actually invoked by it (the first parse attempt
        // succeeds). Force the repair path to run by mixing one invalid
        // escape (`\d`) into a span that also has a genuinely valid one
        // (`\n`), and confirm the valid escape survives the repair pass
        // unchanged while only the invalid one gets doubled.
        let v = extract_json(r#"{"mixed": "line1\nhas\dboth"}"#).unwrap();
        assert_eq!(v["mixed"], "line1\nhas\\dboth");
    }

    #[test]
    fn whole_response_fenced_block_with_inner_backticks_hb009() {
        // The whole (trimmed) response is one fenced block, but the JSON
        // string value itself contains a nested ``` sequence — a naive
        // non-anchored fence match would stop at that inner ``` and
        // return a truncated, unbalanced body.
        let text = "```json\n{\"note\": \"see ```python\\nprint(1)\\n``` for details\"}\n```";
        let v = extract_json(text).unwrap();
        assert_eq!(v["note"], "see ```python\nprint(1)\n``` for details");
    }

    #[test]
    fn bracket_lookalikes_inside_a_string_value_do_not_confuse_the_scanner() {
        // "[10]"/"[20]" here are inside a quoted string, so balanced_span's
        // in-string tracking skips over them entirely — the whole object
        // balances as a single span on the first attempt, without ever
        // engaging the want-dict/held-list logic at all.
        let text = r#"{"narrative": "counts were [10] and [20]", "result": {"ok": true}}"#;
        let v = extract_json(text).unwrap();
        assert_eq!(
            v,
            serde_json::json!({"narrative": "counts were [10] and [20]", "result": {"ok": true}})
        );
    }

    #[test]
    fn list_returned_directly_when_response_does_not_signal_dict_intent() {
        // The response doesn't start with '{', so want_dict is false and a
        // top-level list is returned immediately — no hold-and-keep-
        // scanning behaviour applies here at all.
        let text = "prose [1, 2, 3] more prose, no object here";
        let v = extract_json(text).unwrap();
        assert_eq!(v, serde_json::json!([1, 2, 3]));
    }

    #[test]
    fn held_list_is_returned_as_fallback_when_no_dict_ever_found() {
        // want_dict is true and a list gets held, but scanning finishes
        // without ever finding a balanceable dict — the held list is the
        // final fallback result rather than an error.
        let text = r#"{ x } [1,2] prose, no dict anywhere"#;
        let v = extract_json(text).unwrap();
        assert_eq!(v, serde_json::json!([1, 2]));
    }

    #[test]
    fn two_decoy_lists_are_held_without_overwrite_then_dict_wins() {
        // want_dict is true (response starts with '{'), but that leading
        // brace is a stray, never-closing-into-valid-JSON token ("{ x }"
        // fails to parse and is skipped as a failed span) — so scanning
        // continues and finds two separate top-level lists before finally
        // reaching the real dict. The second list must NOT overwrite the
        // first one already held; the dict must still win over both.
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
        // A brace/bracket-balanced span whose content is not JSON even
        // after the escape-repair pass.
        let err = extract_json("{not json at all, just braces}").unwrap_err();
        assert!(matches!(err, ExtractError::Invalid(_)));
    }

    #[test]
    fn unclosed_brace_is_skipped_not_treated_as_a_span() {
        // A stray unbalanced '{' in prose must not abort the scan of the
        // rest of the candidate — the real object after it is still found.
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

    // ── truncation boundary (via the capped internal entry point, so this
    //    doesn't need to allocate a multi-megabyte string) ───────────────

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
        // Cheap smoke test that the public entry point is wired to
        // MAX_JSON_INPUT rather than some other cap, without allocating
        // a 5M-char string: content well inside the real cap is found.
        let v = extract_json(r#"{"a": 1}"#).unwrap();
        assert_eq!(v, serde_json::json!({"a": 1}));
        assert_eq!(MAX_JSON_INPUT, 5_000_000);
    }

    // ---- loose-JSON repair -------------------------------------------

    // The two shapes serde reports as "key must be a string at line 1
    // column 2" — the exact failure that lost a real remediation on
    // 2026-09-03.
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

    // ---- the repair must never damage content that was already fine ---

    #[test]
    fn valid_json_is_returned_untouched_and_never_reaches_the_repair() {
        // Every construct the repair looks for, but inside correctly
        // quoted strings where it must not fire.
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
        // The object needs repairing (unquoted key) AND contains a
        // double-quoted value with an apostrophe and a Python-looking
        // word — neither may be rewritten.
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
        // Defensive: the scan must terminate even when the closing
        // delimiter never arrives.
        let repaired = repair_loose_json("{'a': 'b").unwrap();
        assert_eq!(repaired, r#"{"a": "b""#);
    }

    #[test]
    fn a_trailing_backslash_at_the_end_of_a_string_is_survivable() {
        // Both string modes must handle an escape introducer as the very
        // last character without indexing past the end.
        let repaired = repair_loose_json(r"{'a': 'b\").unwrap();
        assert!(repaired.starts_with(r#"{"a": "b"#), "{repaired}");
        // Double-quoted mode has nothing to change, so it reports none —
        // the point is that it returns at all.
        assert!(repair_loose_json(r#"{"a": "b\"#).is_none());
    }

    #[test]
    fn genuinely_unrepairable_input_still_reports_the_original_error() {
        // `@` is not fixable by any repair here, so the error must be
        // serde's own complaint about the untouched span.
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
        // Unquoted key AND an invalid `\d` escape: neither pass alone is
        // enough, so this only parses if the escape repair runs on top of
        // the loose repair's output.
        let v = extract_json(r#"{pattern: "\d+ digits"}"#).unwrap();
        assert_eq!(v["pattern"], r"\d+ digits");
    }

    #[test]
    fn a_span_that_resists_the_escape_pass_too_gives_up() {
        // The loose pass fires (single quotes), the escape pass then also
        // fires (`\d`), and the result STILL will not parse because of
        // the stray `@@` — the give-up path after both repairs.
        assert!(repair_and_parse(r"{'a': '\d' @@}").is_none());
    }

    #[test]
    fn a_repaired_span_that_still_will_not_parse_gives_up() {
        // The loose pass fires (the trailing comma goes) but the result
        // is still broken, so `repair_and_parse` must return None rather
        // than loop or panic.
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
