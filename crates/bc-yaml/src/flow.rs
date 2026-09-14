//! Flow-style collection parsing: `{key: value, ...}` and `[a, b, ...]`.
//!
//! Operates on a single logical line of text — the caller (`block.rs`) is
//! responsible for joining any continuation physical lines (a flow
//! collection may span multiple lines in real YAML) into one string,
//! folding embedded newlines to spaces first, matching YAML's flow-context
//! line-folding rule closely enough for config files that never rely on
//! the fine print of that fold.

use serde_json::{Map, Value};

use crate::error::YamlError;
use crate::scalar;

/// Caps flow-collection nesting (`[[[...]]]`, `{a: {b: {c: ...}}}`), the
/// same stack-overflow-DoS guard as `block::MAX_DEPTH` — `parse_value`
/// recurses once per nesting level, so this bounds the real stack-frame
/// depth for a flow collection the same way that one bounds block-level
/// nesting.
const MAX_DEPTH: usize = 200;

struct FlowParser<'a> {
    chars: Vec<char>,
    pos: usize,
    line: usize,
    src: &'a str,
    depth: usize,
}

/// Parse a flow collection starting at the beginning of `s` (which must
/// start with `{` or `[`, after any leading whitespace). Returns the value
/// and the count of UTF-8 bytes of `s` consumed, so the caller can inspect
/// anything left over (e.g. a trailing comment).
pub fn parse_flow(s: &str, line: usize) -> Result<(Value, usize), YamlError> {
    let mut p = FlowParser {
        chars: s.chars().collect(),
        pos: 0,
        line,
        src: s,
        depth: 0,
    };
    p.skip_ws();
    let v = p.parse_value()?;
    let byte_pos = p.chars[..p.pos].iter().collect::<String>().len();
    Ok((v, byte_pos))
}

impl<'a> FlowParser<'a> {
    fn err(&self, msg: impl Into<String>) -> YamlError {
        YamlError::new(self.line, format!("{} (in {:?})", msg.into(), self.src))
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(' ') | Some('\t')) {
            self.pos += 1;
        }
    }

    /// [`Self::parse_value_at`], guarded by [`MAX_DEPTH`] — every
    /// recursive "parse one level deeper" call in this module goes
    /// through here, so this single wrapper bounds the whole
    /// flow-collection recursion.
    fn parse_value(&mut self) -> Result<Value, YamlError> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            self.depth -= 1;
            return Err(self.err(format!("exceeded maximum nesting depth of {MAX_DEPTH}")));
        }
        let result = self.parse_value_at();
        self.depth -= 1;
        result
    }

    fn parse_value_at(&mut self) -> Result<Value, YamlError> {
        self.skip_ws();
        match self.peek() {
            Some('{') => self.parse_mapping(),
            Some('[') => self.parse_sequence(),
            Some('"') => Ok(Value::String(self.parse_double_quoted()?)),
            Some('\'') => Ok(Value::String(self.parse_single_quoted()?)),
            Some(_) => Ok(scalar::resolve_plain(
                self.consume_plain(&[',', '}', ']', ':']).trim(),
            )),
            None => Err(self.err("unexpected end of input while parsing a flow value")),
        }
    }

    fn parse_mapping(&mut self) -> Result<Value, YamlError> {
        self.pos += 1; // consume '{'
        let mut map = Map::new();
        self.skip_ws();
        if self.peek() == Some('}') {
            self.pos += 1;
            return Ok(Value::Object(map));
        }
        loop {
            self.skip_ws();
            let key = match self.peek() {
                Some('"') => self.parse_double_quoted()?,
                Some('\'') => self.parse_single_quoted()?,
                Some(_) => self.consume_plain(&[':', ',', '}']).trim().to_string(),
                None => return Err(self.err("unexpected end of input reading a flow-mapping key")),
            };
            self.skip_ws();
            let value = if self.peek() == Some(':') {
                self.pos += 1;
                self.parse_value()?
            } else {
                Value::Null // `{key}` shorthand: value defaults to null
            };
            map.insert(key, value);
            self.skip_ws();
            match self.peek() {
                Some(',') => {
                    self.pos += 1;
                    continue;
                }
                Some('}') => {
                    self.pos += 1;
                    break;
                }
                _ => return Err(self.err("expected ',' or '}' in flow mapping")),
            }
        }
        Ok(Value::Object(map))
    }

    fn parse_sequence(&mut self) -> Result<Value, YamlError> {
        self.pos += 1; // consume '['
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(']') {
            self.pos += 1;
            return Ok(Value::Array(items));
        }
        loop {
            items.push(self.parse_value()?);
            self.skip_ws();
            match self.peek() {
                Some(',') => {
                    self.pos += 1;
                    continue;
                }
                Some(']') => {
                    self.pos += 1;
                    break;
                }
                _ => return Err(self.err("expected ',' or ']' in flow sequence")),
            }
        }
        Ok(Value::Array(items))
    }

    fn consume_plain(&mut self, stops: &[char]) -> String {
        let start = self.pos;
        while let Some(c) = self.peek() {
            if stops.contains(&c) {
                break;
            }
            self.pos += 1;
        }
        self.chars[start..self.pos].iter().collect()
    }

    fn parse_single_quoted(&mut self) -> Result<String, YamlError> {
        self.pos += 1; // opening quote
        let start = self.pos;
        loop {
            match self.peek() {
                None => return Err(self.err("unterminated single-quoted scalar")),
                Some('\'') => {
                    if self.chars.get(self.pos + 1) == Some(&'\'') {
                        self.pos += 2;
                        continue;
                    }
                    let body: String = self.chars[start..self.pos].iter().collect();
                    self.pos += 1; // closing quote
                    return Ok(scalar::unescape_single_quoted(&body));
                }
                Some(_) => self.pos += 1,
            }
        }
    }

    fn parse_double_quoted(&mut self) -> Result<String, YamlError> {
        self.pos += 1; // opening quote
        let start = self.pos;
        loop {
            match self.peek() {
                None => return Err(self.err("unterminated double-quoted scalar")),
                Some('\\') => self.pos += 2, // skip escaped char (may overshoot at EOF; next loop catches it)
                Some('"') => {
                    let body: String = self.chars[start..self.pos].iter().collect();
                    self.pos += 1; // closing quote
                    return Ok(scalar::unescape_double_quoted(&body));
                }
                Some(_) => self.pos += 1,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn parse(s: &str) -> Value {
        parse_flow(s, 1).unwrap().0
    }

    #[test]
    fn empty_flow_mapping() {
        assert_eq!(parse("{}"), json!({}));
    }

    #[test]
    fn empty_flow_sequence() {
        assert_eq!(parse("[]"), json!([]));
    }

    #[test]
    fn simple_flow_mapping() {
        assert_eq!(
            parse("{id: claude-sonnet-4-6, via: cli}"),
            json!({"id": "claude-sonnet-4-6", "via": "cli"})
        );
    }

    #[test]
    fn simple_flow_sequence() {
        assert_eq!(
            parse("[security-scan, security-remediation]"),
            json!(["security-scan", "security-remediation"])
        );
    }

    #[test]
    fn flow_sequence_of_quoted_strings() {
        assert_eq!(
            parse(r#"["*automation*", "*-e2e*"]"#),
            json!(["*automation*", "*-e2e*"])
        );
    }

    #[test]
    fn nested_flow_collections() {
        assert_eq!(
            parse("{a: [1, 2, {b: true}], c: null}"),
            json!({"a": [1, 2, {"b": true}], "c": null})
        );
    }

    #[test]
    fn flow_mapping_key_shorthand_defaults_to_null() {
        assert_eq!(parse("{a, b: 1}"), json!({"a": null, "b": 1}));
    }

    #[test]
    fn flow_scalar_types_resolved() {
        assert_eq!(
            parse("[1, 2.5, true, false, null, ~]"),
            json!([1, 2.5, true, false, null, null])
        );
    }

    #[test]
    fn single_quoted_key_and_value() {
        assert_eq!(parse("{'a key': 'a value'}"), json!({"a key": "a value"}));
    }

    #[test]
    fn double_quoted_with_escapes() {
        assert_eq!(
            parse(r#"{"k": "line\nbreak"}"#),
            json!({"k": "line\nbreak"})
        );
    }

    #[test]
    fn parse_flow_reports_consumed_byte_length() {
        let (v, len) = parse_flow("[1, 2] # trailing", 1).unwrap();
        assert_eq!(v, json!([1, 2]));
        assert_eq!(&"[1, 2] # trailing"[..len], "[1, 2]");
    }

    #[test]
    fn unterminated_single_quote_errors() {
        assert!(parse_flow("['unterminated", 1).is_err());
    }

    #[test]
    fn unterminated_double_quote_errors() {
        assert!(parse_flow("[\"unterminated", 1).is_err());
    }

    #[test]
    fn unterminated_mapping_errors() {
        assert!(parse_flow("{a: 1", 1).is_err());
    }

    #[test]
    fn mapping_key_at_absolute_eof_errors() {
        assert!(parse_flow("{", 1).is_err());
    }

    #[test]
    fn single_quoted_string_with_doubled_quote_escape() {
        assert_eq!(parse("['it''s here']"), json!(["it's here"]));
    }

    #[test]
    fn unterminated_sequence_errors() {
        assert!(parse_flow("[1, 2", 1).is_err());
    }

    #[test]
    fn empty_input_errors() {
        assert!(parse_flow("", 1).is_err());
    }

    #[test]
    fn malformed_mapping_separator_errors() {
        assert!(parse_flow("{a: 1; b: 2}", 1).is_err());
    }
}
