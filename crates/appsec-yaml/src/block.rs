//! Indentation-driven block structure: mappings, sequences, and block
//! scalars (`|`/`>`), plus the glue that hands off to the flow parser for
//! `{...}`/`[...]` values.

use serde_json::{Map, Value};

use crate::error::YamlError;
use crate::flow;
use crate::scalar;

/// Caps block-level nesting (sequences-of-sequences, mappings-of-
/// mappings, any mix thereof) so a maliciously or accidentally
/// deep-nested document returns a clean [`YamlError`] instead of
/// overflowing the call stack — `parse_node` recurses once per nesting
/// level, so this is also the real stack-frame bound. 200 comfortably
/// covers every real config/profile/input file this project ships while
/// staying far short of a stack overflow on any platform's default
/// thread stack size.
const MAX_DEPTH: usize = 200;

pub struct Parser<'a> {
    lines: Vec<&'a str>,
    pos: usize,
    depth: usize,
    /// Refuse, rather than approximate, anything outside the supported
    /// subset. See [`crate::parse_strict`].
    strict: bool,
}

impl<'a> Parser<'a> {
    pub fn new(input: &'a str) -> Self {
        let normalized_owned;
        let normalized: &str = if input.contains('\r') {
            normalized_owned = input.replace("\r\n", "\n").replace('\r', "\n");
            // SAFETY-free workaround: leak nothing; instead just re-split below.
            // We can't return a borrow of a local, so handle this by boxing.
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

    /// A parser that errors on every construct the lenient parser would
    /// silently approximate or drop. See [`crate::parse_strict`].
    pub fn new_strict(input: &'a str) -> Self {
        let mut parser = Self::new(input);
        parser.strict = true;
        parser
    }

    fn from_owned(s: String) -> Self {
        // Leaking is acceptable here: this is a short-lived, one-shot parse
        // of a small config file, and avoids threading a lifetime-owning
        // Cow through every function in this module for the rare
        // CRLF-normalization case.
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

    /// `(indent, content)` of the next significant line, without consuming
    /// it. `content` has trailing whitespace stripped but an inline
    /// trailing comment is NOT stripped here (callers that need that call
    /// [`strip_trailing_comment`] themselves, since a quoted scalar's `#`
    /// must not be touched).
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
        // The lenient parser stops at the first line it cannot place and
        // returns what it has, which silently drops the rest of the file.
        if self.strict && self.peek().is_some() {
            return Err(self.err(
                "content the supported YAML subset cannot place (inconsistent indentation, a \
                 multi-line plain scalar, or a second document)",
            ));
        }
        Ok(value)
    }

    /// Line-level refusals for strict mode: tab indentation (YAML forbids
    /// it and this parser counts only spaces) and document markers (this
    /// parser reads one document and would otherwise treat `---` as text).
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

    /// [`Self::parse_node_at`], guarded by [`MAX_DEPTH`] — every recursive
    /// "parse one level deeper" call in this module goes through here, so
    /// this single wrapper bounds the whole block-level recursion.
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

    /// Parse whatever value starts at (or continues from) the current
    /// position, provided it's indented at least `min_indent`. Returns
    /// `Value::Null` if the next line is dedented past `min_indent` (i.e.
    /// there is no value here — the key this was called for has an empty/
    /// null value) or if input is exhausted.
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
                // A flow collection (`- { id: CWE-89 }`, `- [1, 2]`) always
                // contains a colon of its own once it's a mapping — checked
                // ahead of `find_mapping_colon` below, or that colon would
                // be mistaken for a block-mapping `key: value` split on
                // this line (e.g. splitting "{ id: CWE-89 }" into a key of
                // `"{ id"` and a value of `"CWE-89 }"`).
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

    /// Like [`Self::parse_mapping`], but the first entry's key:value was
    /// already on the same physical line as a sequence dash (`- key:
    /// value`), which this crate already consumed — subsequent sibling
    /// keys are expected at `key_col` (where the first key started, not
    /// where the dash was).
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
            // A sequence may sit at its key's own indentation (`key:` then
            // `- item` directly below), which YAML reads as the key's value.
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

    /// Parse a value that starts inline (same line as its key, a sequence
    /// dash, or the whole document): a flow collection, or a plain/quoted
    /// scalar with any trailing comment stripped.
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

    /// If `content` doesn't already contain a balanced flow collection,
    /// keep consuming subsequent physical lines (folding the break to a
    /// space, mirroring YAML's flow-context line fold) until brackets
    /// balance. Real config files never actually split a flow collection
    /// across lines, so the common case returns after zero extra lines.
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

/// Why strict mode refuses an inline block-context value, if it does. A
/// quoted scalar must close and be followed by nothing but a comment; a
/// plain scalar must pass [`plain_problem`].
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

/// Why strict mode refuses a plain (unquoted) scalar, if it does. A plain
/// scalar may not start with a YAML indicator this subset does not
/// implement (anchors, aliases, tags, directives, reserved characters,
/// block-scalar indentation indicators, complex keys, merge keys), and may
/// not contain `: `, which YAML rejects and the lenient parser would split
/// or keep as text.
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

/// True if `rest` (whatever follows a mapping colon or sequence dash on
/// the same line) has no real value on it — either genuinely empty, or
/// *entirely* a trailing comment (`# a comment spanning this whole
/// line`), in which case the value lives on subsequent, more-indented
/// lines instead. A quoted value is never considered empty here even if
/// it happens to be `""` or `''`, since `#` inside quotes is literal
/// content, not a comment to strip.
fn is_effectively_empty(rest: &str) -> bool {
    if rest.starts_with('\'') || rest.starts_with('"') {
        return false;
    }
    strip_trailing_comment(rest).trim().is_empty()
}

/// Byte index right after the closing quote in `rest` (which is the
/// content *after* the opening quote character), or `None` if unterminated.
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

/// Strip an inline `# comment` (must be preceded by whitespace or be at
/// the start of the line to count as a comment — a bare `#` glued to other
/// text is literal content) from an already-known-plain (unquoted) scalar
/// line.
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

/// Find the byte index of the `:` that separates a mapping key from its
/// value on this line, if any. A colon only counts when followed by
/// whitespace or end-of-line (`http://x` is not a mapping entry); a
/// quoted key is skipped over first so a colon inside it is never
/// mistaken for the separator.
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

/// `Some((is_literal, chomping))` if `content` starts with a block-scalar
/// indicator (`|`/`>`, optionally followed by a chomping indicator `-`/`+`
/// and/or — not supported here, since unused in every real fixture — an
/// explicit indentation-indicator digit).
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
    // Anything else on the line must be blank or a comment.
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

/// `text` is expected to already carry its "natural" line breaks — one
/// trailing `\n` per collected line, including the last (see
/// `parse_block_scalar`/`fold_lines`) — so chomping only ever needs to
/// trim or re-normalize trailing newlines, never invent a first one.
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

/// YAML folded-scalar (`>`) line-joining: a run of non-blank lines joins
/// with single spaces; a blank line becomes a literal `\n` instead — each
/// one contributing its own newline (so `chomp: keep` can tell three
/// trailing blank lines from one), matching literal mode's "every
/// collected line ends in `\n`" convention that `apply_chomp` relies on.
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

/// True if flow-bracket nesting in `s` is balanced (accounting for
/// quoted-string content, where brackets are just literal characters).
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
        // Unreachable through `parse()`: both real call sites
        // (`parse_mapping`, `parse_inline_mapping_start`) only invoke
        // `parse_one_entry` after already confirming `find_mapping_colon`
        // succeeded on the identical string, so the `ok_or_else` fallback
        // can never fire via any YAML text. Exercise it directly instead
        // of leaving it an untested "just in case" branch.
        let mut p = Parser::new("");
        let mut map = Map::new();
        let err = p.parse_one_entry("no colon here", 0, &mut map).unwrap_err();
        assert!(err.to_string().contains("expected 'key: value'"));
    }

    #[test]
    fn dequote_scalar_unterminated_quotes_are_reachable_only_directly() {
        // Same reasoning as above: by the time `parse_one_entry` calls
        // `dequote_scalar(key_part)`, `find_mapping_colon` has *already*
        // proven the key's quoting is well-formed (it uses the same
        // `find_quote_end`), so an unterminated quote here can only be
        // observed by calling the pure function directly.
        assert_eq!(dequote_scalar("\"unterminated"), "\"unterminated");
        assert_eq!(dequote_scalar("'unterminated"), "'unterminated");
    }

    #[test]
    fn find_mapping_colon_empty_string_is_reachable_only_directly() {
        // Every real call site (`parse_node`, `parse_sequence`) already
        // filters out empty/comment-only content via `peek()` or
        // `is_effectively_empty` before calling this, so an empty `s` can
        // only be observed by calling the pure function directly.
        assert_eq!(find_mapping_colon(""), None);
    }

    #[test]
    fn find_mapping_colon_skips_a_colon_not_followed_by_whitespace() {
        // Per this function's own doc comment, `http://x` is not a mapping
        // entry: the colon after "http" is followed by '/', not
        // whitespace/EOL, so the scan must keep going rather than stop
        // there. A bare URL used as a plain scalar (e.g. a `- http://host`
        // sequence item) hits exactly this path in real YAML.
        assert_eq!(find_mapping_colon("http://x"), None);
        // And once a genuine separator follows later in the string, the
        // scan must find *that* one instead of the earlier false match.
        assert_eq!(find_mapping_colon("aaa:bbb: value"), Some("aaa:bbb".len()));
    }

    #[test]
    fn find_mapping_colon_quoted_key_immediately_followed_by_non_whitespace_is_rejected() {
        // A quoted key with no space after its colon (`"key":value`, as
        // opposed to `"key": value`) is not a valid separator either,
        // matching the unquoted-colon rule above.
        assert_eq!(find_mapping_colon("\"key\":value"), None);
    }
}
