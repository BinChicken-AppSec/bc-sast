use serde_json::{Map, Value};

use crate::error::YamlError;
use crate::flow;
use crate::scalar;

const MAX_DEPTH: usize = 200;

pub struct Parser<'a> {
    lines: Vec<&'a str>,
    pos: usize,
    depth: usize,
    strict: bool,
}

impl<'a> Parser<'a> {
    pub fn new(input: &'a str) -> Self {
        let normalized_owned;
        let normalized: &str = if input.contains('\r') {
            normalized_owned = input.replace("\r\n", "\n").replace('\r', "\n");
            return Self::from_owned(normalized_owned);
        } else {
            input
        };
        Self {
            lines: normalized.lines().collect(),
            pos: 0,
            depth: 0,
            strict: false,
        }
    }

    pub fn new_strict(input: &'a str) -> Self {
        let mut parser = Self::new(input);
        parser.strict = true;
        parser
    }

    fn from_owned(s: String) -> Self {
        let leaked: &'static str = Box::leak(s.into_boxed_str());
        Self {
            lines: leaked.lines().collect(),
            pos: 0,
            depth: 0,
            strict: false,
        }
    }

    fn line_no(&self) -> usize {
        self.pos + 1
    }

    fn err(&self, msg: impl Into<String>) -> YamlError {
        YamlError::new(self.line_no(), msg)
    }

    fn skip_blank_and_comments(&mut self) {
        while self.pos < self.lines.len() {
            let trimmed = self.lines[self.pos].trim_start();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn peek(&mut self) -> Option<(usize, &'a str)> {
        self.skip_blank_and_comments();
        let line = *self.lines.get(self.pos)?;
        let indent = line.len() - line.trim_start_matches(' ').len();
        Some((indent, line[indent..].trim_end()))
    }

    pub fn parse_document(&mut self) -> Result<Value, YamlError> {
        if self.strict {
            self.check_strict_lines()?;
        }
        let value = match self.peek() {
            None => Value::Null,
            Some((indent, _)) => self.parse_node(indent)?,
        };
        if self.strict && self.peek().is_some() {
            return Err(self.err(
                "content the supported YAML subset cannot place (inconsistent indentation, a \
                 multi-line plain scalar, or a second document)",
            ));
        }
        Ok(value)
    }

    fn check_strict_lines(&self) -> Result<(), YamlError> {
        for (index, line) in self.lines.iter().enumerate() {
            let content = line.trim_start_matches([' ', '\t']);
            let leading = &line[..line.len() - content.len()];
            if leading.contains('\t') && !content.is_empty() {
                return Err(YamlError::new(index + 1, "tab character in indentation"));
            }
            if *line == "---" || line.starts_with("--- ") || *line == "..." {
                return Err(YamlError::new(
                    index + 1,
                    "document markers and multi-document streams are outside the supported subset",
                ));
            }
        }
        Ok(())
    }

    fn parse_node(&mut self, min_indent: usize) -> Result<Value, YamlError> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            self.depth -= 1;
            return Err(self.err(format!("exceeded maximum nesting depth of {MAX_DEPTH}")));
        }
        let result = self.parse_node_at(min_indent);
        self.depth -= 1;
        result
    }

    fn parse_node_at(&mut self, min_indent: usize) -> Result<Value, YamlError> {
        let Some((indent, content)) = self.peek() else {
            return Ok(Value::Null);
        };
        if indent < min_indent {
            return Ok(Value::Null);
        }
        if content == "-" || content.starts_with("- ") {
            self.parse_sequence(indent)
        } else if let Some((literal, chomp)) = block_scalar_indicator(content) {
            self.pos += 1;
            self.parse_block_scalar(indent, literal, chomp)
        } else if find_mapping_colon(content).is_some() {
            self.parse_mapping(indent)
        } else {
            self.pos += 1;
            self.parse_inline_value(content)
        }
    }

    fn parse_sequence(&mut self, indent: usize) -> Result<Value, YamlError> {
        let mut items = Vec::new();
        while let Some((cur_indent, content)) = self.peek() {
            if cur_indent != indent || !(content == "-" || content.starts_with("- ")) {
                break;
            }
            self.pos += 1;
            let after_dash = if content == "-" {
                ""
            } else {
                content[1..].trim_start()
            };
            if is_effectively_empty(after_dash) {
                items.push(self.parse_node(indent + 1)?);
                continue;
            }
            let value_col = indent + (content.len() - after_dash.len());
            if let Some((literal, chomp)) = block_scalar_indicator(after_dash) {
                items.push(self.parse_block_scalar(value_col, literal, chomp)?);
            } else if after_dash.starts_with('{') || after_dash.starts_with('[') {
                items.push(self.parse_inline_value(after_dash)?);
            } else if find_mapping_colon(after_dash).is_some() {
                items.push(self.parse_inline_mapping_start(value_col, after_dash)?);
            } else {
                items.push(self.parse_inline_value(after_dash)?);
            }
        }
        Ok(Value::Array(items))
    }

    fn parse_mapping(&mut self, indent: usize) -> Result<Value, YamlError> {
        let mut map = Map::new();
        while let Some((cur_indent, content)) = self.peek() {
            if cur_indent != indent || find_mapping_colon(content).is_none() {
                break;
            }
            self.pos += 1;
            self.parse_one_entry(content, indent, &mut map)?;
        }
        Ok(Value::Object(map))
    }

    fn parse_inline_mapping_start(
        &mut self,
        key_col: usize,
        first_line: &str,
    ) -> Result<Value, YamlError> {
        let mut map = Map::new();
        self.parse_one_entry(first_line, key_col, &mut map)?;
        while let Some((cur_indent, content)) = self.peek() {
            if cur_indent != key_col || find_mapping_colon(content).is_none() {
                break;
            }
            self.pos += 1;
            self.parse_one_entry(content, key_col, &mut map)?;
        }
        Ok(Value::Object(map))
    }

    fn parse_one_entry(
        &mut self,
        content: &str,
        indent: usize,
        map: &mut Map<String, Value>,
    ) -> Result<(), YamlError> {
        let colon = find_mapping_colon(content).ok_or_else(|| self.err("expected 'key: value'"))?;
        let key_part = content[..colon].trim();
        if self.strict && !key_part.starts_with(['"', '\'']) {
            if let Some(problem) = plain_problem(key_part) {
                return Err(YamlError::new(self.pos, format!("mapping key: {problem}")));
            }
        }
        let key = dequote_scalar(key_part);
        let key_line = self.pos;
        let rest = content[colon + 1..].trim_start();
        let value = if is_effectively_empty(rest) {
            match self.peek() {
                Some((next, item)) if next == indent && (item == "-" || item.starts_with("- ")) => {
                    self.parse_node(indent)?
                }
                _ => self.parse_node(indent + 1)?,
            }
        } else if let Some((literal, chomp)) = block_scalar_indicator(rest) {
            self.parse_block_scalar(indent, literal, chomp)?
        } else {
            self.parse_inline_value(rest)?
        };
        if map.insert(key, value).is_some() && self.strict {
            return Err(YamlError::new(key_line, "duplicate mapping key"));
        }
        Ok(())
    }

    fn parse_inline_value(&mut self, content: &str) -> Result<Value, YamlError> {
        if content.starts_with('{') || content.starts_with('[') {
            let joined = self.collect_flow_text(content);
            let line = self.line_no();
            let (v, consumed) = flow::parse_flow_with(&joined, line, self.strict)?;
            if self.strict && !strip_trailing_comment(joined[consumed..].trim()).is_empty() {
                return Err(YamlError::new(self.pos, "text after a flow collection"));
            }
            return Ok(v);
        }
        if self.strict {
            if let Some(problem) = strict_inline_problem(content) {
                return Err(YamlError::new(self.pos, problem));
            }
        }
        Ok(scalar_from_line(content))
    }

    fn collect_flow_text(&mut self, first: &str) -> String {
        let mut buf = first.to_string();
        while !flow_is_balanced(&buf) {
            let Some((_, more)) = self.peek() else { break };
            self.pos += 1;
            buf.push(' ');
            buf.push_str(more);
        }
        buf
    }

    fn parse_block_scalar(
        &mut self,
        indent: usize,
        literal: bool,
        chomp: Chomp,
    ) -> Result<Value, YamlError> {
        let mut collected: Vec<&str> = Vec::new();
        let mut min_content_indent: Option<usize> = None;
        while self.pos < self.lines.len() {
            let raw = self.lines[self.pos];
            if raw.trim().is_empty() {
                collected.push("");
                self.pos += 1;
                continue;
            }
            let this_indent = raw.len() - raw.trim_start_matches(' ').len();
            if this_indent <= indent {
                break;
            }
            min_content_indent = Some(match min_content_indent {
                Some(m) => m.min(this_indent),
                None => this_indent,
            });
            collected.push(raw);
            self.pos += 1;
        }
        let body_indent = min_content_indent.unwrap_or(indent + 1);
        let dedented: Vec<&str> = collected
            .iter()
            .map(|l| {
                if l.len() >= body_indent {
                    &l[body_indent..]
                } else {
                    ""
                }
            })
            .collect();

        let text = if literal {
            let mut s = String::new();
            for l in &dedented {
                s.push_str(l);
                s.push('\n');
            }
            s
        } else {
            fold_lines(&dedented)
        };
        Ok(Value::String(apply_chomp(text, chomp)))
    }
}

fn scalar_from_line(content: &str) -> Value {
    if let Some(rest) = content.strip_prefix('"') {
        if let Some(end) = find_quote_end(rest, b'"') {
            return Value::String(scalar::unescape_double_quoted(&rest[..end - 1]));
        }
    }
    if let Some(rest) = content.strip_prefix('\'') {
        if let Some(end) = find_quote_end(rest, b'\'') {
            return Value::String(scalar::unescape_single_quoted(&rest[..end - 1]));
        }
    }
    let stripped = strip_trailing_comment(content);
    scalar::resolve_plain(stripped.trim())
}

fn strict_inline_problem(content: &str) -> Option<&'static str> {
    if content.starts_with(['"', '\'']) {
        let rest = &content[1..];
        let Some(end) = find_quote_end(rest, content.as_bytes()[0]) else {
            return Some("unterminated or multi-line quoted scalar");
        };
        if !strip_trailing_comment(rest[end..].trim()).is_empty() {
            return Some("text after a quoted scalar");
        }
        return None;
    }
    plain_problem(strip_trailing_comment(content).trim())
}

pub(crate) fn plain_problem(s: &str) -> Option<&'static str> {
    let first = s.chars().next()?;
    let indicator = matches!(
        first,
        '&' | '*' | '!' | '%' | '@' | '`' | '|' | '>' | '{' | '[' | '"' | '\''
    ) || (matches!(first, '?' | '-') && (s.len() == 1 || s[1..].starts_with(' ')))
        || s == "<<";
    if indicator {
        return Some(
            "a YAML feature outside the supported subset (anchor, alias, tag, directive, \
             reserved indicator, block-scalar indentation indicator, complex or merge key, \
             or an unterminated quote)",
        );
    }
    if s.contains(": ") || s.ends_with(':') {
        return Some("an unquoted ': ' inside a plain scalar");
    }
    None
}

fn dequote_scalar(s: &str) -> String {
    if let Some(rest) = s.strip_prefix('"') {
        if let Some(end) = find_quote_end(rest, b'"') {
            return scalar::unescape_double_quoted(&rest[..end - 1]);
        }
    }
    if let Some(rest) = s.strip_prefix('\'') {
        if let Some(end) = find_quote_end(rest, b'\'') {
            return scalar::unescape_single_quoted(&rest[..end - 1]);
        }
    }
    s.to_string()
}

fn is_effectively_empty(rest: &str) -> bool {
    if rest.starts_with('\'') || rest.starts_with('"') {
        return false;
    }
    strip_trailing_comment(rest).trim().is_empty()
}

fn find_quote_end(rest: &str, quote: u8) -> Option<usize> {
    let bytes = rest.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == quote {
            if quote == b'\'' {
                if bytes.get(i + 1) == Some(&b'\'') {
                    i += 2;
                    continue;
                }
                return Some(i + 1);
            } else {
                let mut bs = 0;
                let mut j = i;
                while j > 0 && bytes[j - 1] == b'\\' {
                    bs += 1;
                    j -= 1;
                }
                if bs % 2 == 1 {
                    i += 1;
                    continue;
                }
                return Some(i + 1);
            }
        }
        i += 1;
    }
    None
}

fn strip_trailing_comment(s: &str) -> &str {
    if let Some(rest) = s.strip_prefix('#') {
        let _ = rest;
        return "";
    }
    let bytes = s.as_bytes();
    for i in 1..bytes.len() {
        if bytes[i] == b'#' && (bytes[i - 1] == b' ' || bytes[i - 1] == b'\t') {
            return s[..i].trim_end();
        }
    }
    s
}

fn find_mapping_colon(s: &str) -> Option<usize> {
    if s.is_empty() {
        return None;
    }
    let bytes = s.as_bytes();
    if bytes[0] == b'\'' || bytes[0] == b'"' {
        let quote = bytes[0];
        let end = find_quote_end(&s[1..], quote)? + 1;
        let after = &s[end..];
        let trimmed = after.trim_start();
        if let Some(rest) = trimmed.strip_prefix(':') {
            let next = rest.chars().next();
            if next.is_none() || next == Some(' ') || next == Some('\t') {
                return Some(end + (after.len() - trimmed.len()));
            }
        }
        return None;
    }
    for (idx, ch) in s.char_indices() {
        if ch == ':' {
            let next = s[idx + 1..].chars().next();
            if next.is_none() || next == Some(' ') || next == Some('\t') {
                return Some(idx);
            }
        }
    }
    None
}

fn block_scalar_indicator(content: &str) -> Option<(bool, Chomp)> {
    let mut chars = content.chars();
    let literal = match chars.next()? {
        '|' => true,
        '>' => false,
        _ => return None,
    };
    let rest = chars.as_str();
    let (chomp, rest) = match rest.chars().next() {
        Some('-') => (Chomp::Strip, &rest[1..]),
        Some('+') => (Chomp::Keep, &rest[1..]),
        _ => (Chomp::Clip, rest),
    };
    let trailing = strip_trailing_comment(rest.trim());
    if !trailing.is_empty() {
        return None;
    }
    Some((literal, chomp))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Chomp {
    Strip,
    Clip,
    Keep,
}

fn apply_chomp(text: String, chomp: Chomp) -> String {
    match chomp {
        Chomp::Keep => text,
        Chomp::Strip => text.trim_end_matches('\n').to_string(),
        Chomp::Clip => {
            let trimmed = text.trim_end_matches('\n');
            if trimmed.is_empty() {
                trimmed.to_string()
            } else {
                format!("{trimmed}\n")
            }
        }
    }
}

fn fold_lines(lines: &[&str]) -> String {
    let mut out = String::new();
    let mut i = 0;
    while i < lines.len() {
        if lines[i].is_empty() {
            out.push('\n');
            i += 1;
            continue;
        }
        out.push_str(lines[i]);
        out.push('\n');
        if i + 1 < lines.len() && !lines[i + 1].is_empty() {
            out.pop();
            out.push(' ');
        }
        i += 1;
    }
    out
}

fn flow_is_balanced(s: &str) -> bool {
    let mut depth = 0i32;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                while let Some(&n) = chars.peek() {
                    chars.next();
                    if n == '\\' {
                        chars.next();
                    } else if n == '"' {
                        break;
                    }
                }
            }
            '\'' => {
                while let Some(&n) = chars.peek() {
                    chars.next();
                    if n == '\'' {
                        break;
                    }
                }
            }
            '{' | '[' => depth += 1,
            '}' | ']' => depth -= 1,
            _ => {}
        }
    }
    depth <= 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_one_entry_error_path_is_reachable_directly() {
        let mut p = Parser::new("");
        let mut map = Map::new();
        let err = p.parse_one_entry("no colon here", 0, &mut map).unwrap_err();
        assert!(err.to_string().contains("expected 'key: value'"));
    }

    #[test]
    fn dequote_scalar_unterminated_quotes_are_reachable_only_directly() {
        assert_eq!(dequote_scalar("\"unterminated"), "\"unterminated");
        assert_eq!(dequote_scalar("'unterminated"), "'unterminated");
    }

    #[test]
    fn find_mapping_colon_empty_string_is_reachable_only_directly() {
        assert_eq!(find_mapping_colon(""), None);
    }

    #[test]
    fn find_mapping_colon_skips_a_colon_not_followed_by_whitespace() {
        assert_eq!(find_mapping_colon("http://x"), None);
        assert_eq!(find_mapping_colon("aaa:bbb: value"), Some("aaa:bbb".len()));
    }

    #[test]
    fn find_mapping_colon_quoted_key_immediately_followed_by_non_whitespace_is_rejected() {
        assert_eq!(find_mapping_colon("\"key\":value"), None);
    }
}
