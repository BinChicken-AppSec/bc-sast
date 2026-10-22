//! Tokens of the GraphQL language (October 2021 specification, section
//! 2.1), for the type system subset this crate parses.
//!
//! Commas, white space, line terminators, comments and a leading byte
//! order mark are insignificant and skipped. Every token carries the
//! 1-based line it starts on, for error messages.

/// One lexical token.
#[derive(Clone, Debug, PartialEq)]
pub enum Token {
    /// `! $ & ( ) : = @ [ ] { | }`.
    Punct(char),
    /// `...`
    Spread,
    Name(String),
    Int(String),
    Float(String),
    /// A string value with escapes decoded; `block` for `"""` strings.
    Str {
        value: String,
        block: bool,
    },
}

/// A token and the line it starts on.
#[derive(Clone, Debug, PartialEq)]
pub struct Spanned {
    pub token: Token,
    pub line: usize,
}

/// Why text is not GraphQL: a message and its line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LexError {
    pub line: usize,
    pub message: String,
}

/// Split `text` into tokens.
pub fn tokenize(text: &str) -> Result<Vec<Spanned>, LexError> {
    let chars: Vec<char> = text
        .strip_prefix('\u{feff}')
        .unwrap_or(text)
        .chars()
        .collect();
    let mut lexer = Lexer {
        chars: &chars,
        index: 0,
        line: 1,
    };
    let mut tokens = Vec::new();
    while let Some(token) = lexer.next()? {
        tokens.push(token);
    }
    Ok(tokens)
}

struct Lexer<'a> {
    chars: &'a [char],
    index: usize,
    line: usize,
}

impl Lexer<'_> {
    fn peek(&self, offset: usize) -> Option<char> {
        self.chars.get(self.index + offset).copied()
    }

    fn error(&self, message: impl Into<String>) -> LexError {
        LexError {
            line: self.line,
            message: message.into(),
        }
    }

    /// Advance past one character, counting `\n`, `\r\n` and `\r` as one
    /// line terminator each.
    fn bump(&mut self) -> Option<char> {
        let character = self.peek(0)?;
        self.index += 1;
        if character == '\n' || (character == '\r' && self.peek(0) != Some('\n')) {
            self.line += 1;
        }
        Some(character)
    }

    fn next(&mut self) -> Result<Option<Spanned>, LexError> {
        self.skip_ignored();
        let line = self.line;
        let Some(character) = self.peek(0) else {
            return Ok(None);
        };
        let token = match character {
            '!' | '$' | '&' | '(' | ')' | ':' | '=' | '@' | '[' | ']' | '{' | '|' | '}' => {
                self.bump();
                Token::Punct(character)
            }
            '.' => {
                if self.peek(1) == Some('.') && self.peek(2) == Some('.') {
                    self.index += 3;
                    Token::Spread
                } else {
                    return Err(self.error("unexpected `.`"));
                }
            }
            '"' => self.string()?,
            '-' | '0'..='9' => self.number()?,
            c if c == '_' || c.is_ascii_alphabetic() => {
                let start = self.index;
                while self
                    .peek(0)
                    .is_some_and(|c| c == '_' || c.is_ascii_alphanumeric())
                {
                    self.index += 1;
                }
                Token::Name(self.chars[start..self.index].iter().collect())
            }
            other => return Err(self.error(format!("unexpected character {other:?}"))),
        };
        Ok(Some(Spanned { token, line }))
    }

    fn skip_ignored(&mut self) {
        while let Some(character) = self.peek(0) {
            match character {
                ' ' | '\t' | ',' | '\n' | '\r' | '\u{feff}' => {
                    self.bump();
                }
                '#' => {
                    while self.peek(0).is_some_and(|c| c != '\n' && c != '\r') {
                        self.index += 1;
                    }
                }
                _ => return,
            }
        }
    }

    fn number(&mut self) -> Result<Token, LexError> {
        let start = self.index;
        if self.peek(0) == Some('-') {
            self.index += 1;
        }
        let digits = |lexer: &mut Self| {
            let from = lexer.index;
            while lexer.peek(0).is_some_and(|c| c.is_ascii_digit()) {
                lexer.index += 1;
            }
            lexer.index - from
        };
        let integer = self.index;
        if digits(self) == 0 {
            return Err(self.error("a number needs digits"));
        }
        if self.chars[integer] == '0' && self.index - integer > 1 {
            return Err(self.error("a number must not have a leading zero"));
        }
        let mut float = false;
        if self.peek(0) == Some('.') {
            self.index += 1;
            float = true;
            if digits(self) == 0 {
                return Err(self.error("a fraction needs digits"));
            }
        }
        if matches!(self.peek(0), Some('e' | 'E')) {
            self.index += 1;
            float = true;
            if matches!(self.peek(0), Some('+' | '-')) {
                self.index += 1;
            }
            if digits(self) == 0 {
                return Err(self.error("an exponent needs digits"));
            }
        }
        if self
            .peek(0)
            .is_some_and(|c| c == '_' || c == '.' || c.is_ascii_alphabetic())
        {
            return Err(self.error("a number must not be followed by a name"));
        }
        let text: String = self.chars[start..self.index].iter().collect();
        Ok(if float {
            Token::Float(text)
        } else {
            Token::Int(text)
        })
    }

    fn string(&mut self) -> Result<Token, LexError> {
        if self.peek(1) == Some('"') && self.peek(2) == Some('"') {
            self.index += 3;
            return self.block_string();
        }
        self.index += 1;
        let mut value = String::new();
        loop {
            match self.peek(0) {
                None | Some('\n' | '\r') => return Err(self.error("unterminated string")),
                Some('"') => {
                    self.index += 1;
                    break;
                }
                Some('\\') => {
                    self.index += 1;
                    value.push(self.escape()?);
                }
                Some(other) => {
                    self.index += 1;
                    value.push(other);
                }
            }
        }
        Ok(Token::Str {
            value,
            block: false,
        })
    }

    fn escape(&mut self) -> Result<char, LexError> {
        let escaped = match self.peek(0) {
            Some('"') => '"',
            Some('\\') => '\\',
            Some('/') => '/',
            Some('b') => '\u{8}',
            Some('f') => '\u{c}',
            Some('n') => '\n',
            Some('r') => '\r',
            Some('t') => '\t',
            Some('u') => {
                self.index += 1;
                let digits: String = if self.peek(0) == Some('{') {
                    self.index += 1;
                    let start = self.index;
                    while self.peek(0).is_some_and(|c| c != '}') {
                        self.index += 1;
                    }
                    let digits = self.chars[start..self.index].iter().collect();
                    self.index += 1;
                    digits
                } else {
                    let end = (self.index + 4).min(self.chars.len());
                    let digits = self.chars[self.index..end].iter().collect();
                    self.index = end;
                    digits
                };
                return u32::from_str_radix(&digits, 16)
                    .ok()
                    .and_then(char::from_u32)
                    .ok_or_else(|| self.error(format!("invalid unicode escape \\u{digits}")));
            }
            other => return Err(self.error(format!("invalid escape {other:?}"))),
        };
        self.index += 1;
        Ok(escaped)
    }

    fn block_string(&mut self) -> Result<Token, LexError> {
        let mut raw = String::new();
        loop {
            match self.peek(0) {
                None => return Err(self.error("unterminated block string")),
                Some('"') if self.peek(1) == Some('"') && self.peek(2) == Some('"') => {
                    self.index += 3;
                    break;
                }
                Some('\\')
                    if self.peek(1) == Some('"')
                        && self.peek(2) == Some('"')
                        && self.peek(3) == Some('"') =>
                {
                    self.index += 4;
                    raw.push_str("\"\"\"");
                }
                Some(_) => {
                    // `bump` counts the line terminators a block spans.
                    raw.extend(self.bump());
                }
            }
        }
        Ok(Token::Str {
            value: block_string_value(&raw),
            block: true,
        })
    }
}

/// The value of a block string: common indentation removed from every
/// line but the first, and leading and trailing blank lines dropped
/// (section 2.9.4, BlockStringValue).
pub fn block_string_value(raw: &str) -> String {
    let normalized = raw.replace("\r\n", "\n").replace('\r', "\n");
    let lines: Vec<&str> = normalized.split('\n').collect();
    let indent = lines
        .iter()
        .skip(1)
        .filter(|line| !line.trim_matches([' ', '\t']).is_empty())
        .map(|line| line.len() - line.trim_start_matches([' ', '\t']).len())
        .min()
        .unwrap_or(0);
    let mut out: Vec<&str> = lines
        .iter()
        .enumerate()
        .map(|(index, line)| {
            if index == 0 {
                line
            } else {
                line.get(indent..).unwrap_or("")
            }
        })
        .collect();
    while out
        .first()
        .is_some_and(|line| line.trim_matches([' ', '\t']).is_empty())
    {
        out.remove(0);
    }
    while out
        .last()
        .is_some_and(|line| line.trim_matches([' ', '\t']).is_empty())
    {
        out.pop();
    }
    out.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tokens(text: &str) -> Vec<Token> {
        tokenize(text)
            .unwrap()
            .into_iter()
            .map(|spanned| spanned.token)
            .collect()
    }

    fn error(text: &str) -> String {
        tokenize(text).unwrap_err().message
    }

    #[test]
    fn punctuators_names_and_numbers_are_recognized() {
        assert_eq!(
            tokens(
                "\u{feff}type Query { a(x: Int = -1, y: [Float!] = 1.5e3): ID! } ... @d | & $ ="
            ),
            [
                Token::Name("type".into()),
                Token::Name("Query".into()),
                Token::Punct('{'),
                Token::Name("a".into()),
                Token::Punct('('),
                Token::Name("x".into()),
                Token::Punct(':'),
                Token::Name("Int".into()),
                Token::Punct('='),
                Token::Int("-1".into()),
                Token::Name("y".into()),
                Token::Punct(':'),
                Token::Punct('['),
                Token::Name("Float".into()),
                Token::Punct('!'),
                Token::Punct(']'),
                Token::Punct('='),
                Token::Float("1.5e3".into()),
                Token::Punct(')'),
                Token::Punct(':'),
                Token::Name("ID".into()),
                Token::Punct('!'),
                Token::Punct('}'),
                Token::Spread,
                Token::Punct('@'),
                Token::Name("d".into()),
                Token::Punct('|'),
                Token::Punct('&'),
                Token::Punct('$'),
                Token::Punct('='),
            ]
        );
        assert_eq!(
            tokens("0 2E-3 7e+1"),
            [
                Token::Int("0".into()),
                Token::Float("2E-3".into()),
                Token::Float("7e+1".into())
            ]
        );
    }

    #[test]
    fn comments_commas_and_lines_are_tracked() {
        let spanned = tokenize("# c\r\na,\rb\n\n  c # trailing").unwrap();
        let lines: Vec<usize> = spanned.iter().map(|s| s.line).collect();
        assert_eq!(lines, [2, 3, 5]);
    }

    #[test]
    fn strings_decode_escapes() {
        assert_eq!(
            tokens(r#""a\"\\\/\b\f\n\r\t\u0041\u{1F600}""#),
            [Token::Str {
                value: "a\"\\/\u{8}\u{c}\n\r\tA\u{1F600}".into(),
                block: false
            }]
        );
    }

    #[test]
    fn block_strings_are_dedented_and_escape_triple_quotes() {
        let text = "\"\"\"\n    Hello,\n      World!\n\n    Yours, \\\"\"\" GraphQL.\n  \"\"\" x";
        let spanned = tokenize(text).unwrap();
        assert_eq!(
            spanned[0].token,
            Token::Str {
                value: "Hello,\n  World!\n\nYours, \"\"\" GraphQL.".into(),
                block: true
            }
        );
        assert_eq!(spanned[1].line, 6);
        assert_eq!(
            block_string_value("  first\r\n  \r   second"),
            "  first\n\nsecond"
        );
        assert_eq!(block_string_value(""), "");
    }

    #[test]
    fn malformed_tokens_are_errors_with_lines() {
        assert_eq!(error("."), "unexpected `.`");
        assert_eq!(error("\n%").trim(), "unexpected character '%'");
        assert_eq!(tokenize("\n%").unwrap_err().line, 2);
        assert_eq!(error("-"), "a number needs digits");
        assert_eq!(error("01"), "a number must not have a leading zero");
        assert_eq!(error("1."), "a fraction needs digits");
        assert_eq!(error("1e"), "an exponent needs digits");
        assert_eq!(error("1x"), "a number must not be followed by a name");
        assert_eq!(error("\"open"), "unterminated string");
        assert_eq!(error("\"a\nb\""), "unterminated string");
        assert_eq!(error("\"\\q\""), "invalid escape Some('q')");
        assert_eq!(error("\"\\"), "invalid escape None");
        assert!(error("\"\\uZZZZ\"").contains("invalid unicode escape"));
        assert!(error("\"\\u{D800}\"").contains("invalid unicode escape"));
        assert_eq!(error("\"\"\"open"), "unterminated block string");
    }
}
