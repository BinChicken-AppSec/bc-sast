use std::collections::BTreeMap;

pub const MAX_DEPTH: usize = 64;

pub const MAX_STRING: usize = 1 << 20;

#[derive(Debug, Clone, PartialEq)]
pub enum Object {
    Null,
    Bool(bool),
    Number(f64),
    String(Vec<u8>),
    Name(String),
    Array(Vec<Object>),
    Dict(Dict),
    Stream { dict: Dict, data: Vec<u8> },
    Reference(u32, u16),
}

pub type Dict = BTreeMap<String, Object>;

impl Object {
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Number(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_name(&self) -> Option<&str> {
        match self {
            Self::Name(n) => Some(n),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Object]> {
        match self {
            Self::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_dict(&self) -> Option<&Dict> {
        match self {
            Self::Dict(d) => Some(d),
            Self::Stream { dict, .. } => Some(dict),
            _ => None,
        }
    }

    pub fn as_reference(&self) -> Option<(u32, u16)> {
        match self {
            Self::Reference(n, g) => Some((*n, *g)),
            _ => None,
        }
    }
}

pub fn is_white(b: u8) -> bool {
    matches!(b, b'\0' | b'\t' | b'\n' | b'\x0c' | b'\r' | b' ')
}

pub fn is_delimiter(b: u8) -> bool {
    matches!(
        b,
        b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
    )
}

fn is_regular(b: u8) -> bool {
    !is_white(b) && !is_delimiter(b)
}

pub struct Lexer<'a> {
    pub data: &'a [u8],
    pub at: usize,
}

impl<'a> Lexer<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, at: 0 }
    }

    pub fn at(data: &'a [u8], at: usize) -> Self {
        Self { data, at }
    }

    fn peek(&self) -> Option<u8> {
        self.data.get(self.at).copied()
    }

    pub fn skip_space(&mut self) {
        loop {
            match self.peek() {
                Some(b) if is_white(b) => self.at += 1,
                Some(b'%') => {
                    while let Some(b) = self.peek() {
                        self.at += 1;
                        if b == b'\n' || b == b'\r' {
                            break;
                        }
                    }
                }
                _ => return,
            }
        }
    }

    pub fn keyword(&mut self) -> Option<&'a [u8]> {
        self.skip_space();
        let start = self.at;
        while matches!(self.peek(), Some(b) if is_regular(b)) {
            self.at += 1;
        }
        (self.at > start).then(|| &self.data[start..self.at])
    }

    pub fn object(&mut self, depth: usize) -> Option<Object> {
        if depth > MAX_DEPTH {
            return None;
        }
        self.skip_space();
        match self.peek()? {
            b'/' => self.name().map(Object::Name),
            b'(' => self.literal_string().map(Object::String),
            b'[' => self.array(depth).map(Object::Array),
            b'<' => {
                if self.data.get(self.at + 1) == Some(&b'<') {
                    self.dictionary(depth).map(Object::Dict)
                } else {
                    self.hex_string().map(Object::String)
                }
            }
            b']' | b'>' | b')' | b'}' => None,
            _ => self.number_keyword_or_reference(),
        }
    }

    fn name(&mut self) -> Option<String> {
        if self.peek()? != b'/' {
            return None;
        }
        self.at += 1;
        let mut out = Vec::new();
        while let Some(b) = self.peek() {
            if !is_regular(b) {
                break;
            }
            self.at += 1;
            if b == b'#' {
                let hi = self.data.get(self.at).copied().and_then(hex_value);
                let lo = self.data.get(self.at + 1).copied().and_then(hex_value);
                if let (Some(hi), Some(lo)) = (hi, lo) {
                    out.push(hi * 16 + lo);
                    self.at += 2;
                    continue;
                }
            }
            out.push(b);
            if out.len() > MAX_STRING {
                return None;
            }
        }
        Some(String::from_utf8_lossy(&out).into_owned())
    }

    fn literal_string(&mut self) -> Option<Vec<u8>> {
        if self.peek()? != b'(' {
            return None;
        }
        self.at += 1;
        let mut out = Vec::new();
        let mut nesting = 1usize;
        while let Some(b) = self.peek() {
            self.at += 1;
            match b {
                b'(' => {
                    nesting += 1;
                    out.push(b);
                }
                b')' => {
                    nesting -= 1;
                    if nesting == 0 {
                        return Some(out);
                    }
                    out.push(b);
                }
                b'\\' => {
                    let Some(next) = self.peek() else { break };
                    self.at += 1;
                    match next {
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'b' => out.push(8),
                        b'f' => out.push(12),
                        b'(' | b')' | b'\\' => out.push(next),
                        b'\n' => {}
                        b'\r' => {
                            if self.peek() == Some(b'\n') {
                                self.at += 1;
                            }
                        }
                        b'0'..=b'7' => {
                            let mut value = u32::from(next - b'0');
                            for _ in 0..2 {
                                match self.peek() {
                                    Some(d @ b'0'..=b'7') => {
                                        value = value * 8 + u32::from(d - b'0');
                                        self.at += 1;
                                    }
                                    _ => break,
                                }
                            }
                            out.push((value & 0xFF) as u8);
                        }
                        other => out.push(other),
                    }
                }
                _ => out.push(b),
            }
            if out.len() > MAX_STRING {
                return None;
            }
        }
        Some(out)
    }

    fn hex_string(&mut self) -> Option<Vec<u8>> {
        if self.peek()? != b'<' {
            return None;
        }
        self.at += 1;
        let mut out = Vec::new();
        let mut half: Option<u8> = None;
        while let Some(b) = self.peek() {
            self.at += 1;
            if b == b'>' {
                break;
            }
            let Some(v) = hex_value(b) else { continue };
            match half.take() {
                Some(hi) => out.push(hi * 16 + v),
                None => half = Some(v),
            }
            if out.len() > MAX_STRING {
                return None;
            }
        }
        if let Some(hi) = half {
            out.push(hi * 16);
        }
        Some(out)
    }

    fn array(&mut self, depth: usize) -> Option<Vec<Object>> {
        if self.peek()? != b'[' {
            return None;
        }
        self.at += 1;
        let mut out = Vec::new();
        loop {
            self.skip_space();
            match self.peek() {
                None => break,
                Some(b']') => {
                    self.at += 1;
                    break;
                }
                _ => {}
            }
            let before = self.at;
            match self.object(depth + 1) {
                Some(o) => out.push(o),
                None => {
                    self.at = before + 1;
                }
            }
        }
        Some(out)
    }

    pub fn dictionary(&mut self, depth: usize) -> Option<Dict> {
        if self.peek()? != b'<' || self.data.get(self.at + 1) != Some(&b'<') {
            return None;
        }
        self.at += 2;
        let mut out = Dict::new();
        loop {
            self.skip_space();
            match self.peek() {
                None => break,
                Some(b'>') => {
                    self.at += 1;
                    if self.peek() == Some(b'>') {
                        self.at += 1;
                    }
                    break;
                }
                Some(b'/') => {}
                _ => {
                    self.at += 1;
                    continue;
                }
            }
            let Some(key) = self.name() else { continue };
            let Some(value) = self.object(depth + 1) else {
                continue;
            };
            out.insert(key, value);
            if out.len() > 4096 {
                return Some(out);
            }
        }
        Some(out)
    }

    fn number_keyword_or_reference(&mut self) -> Option<Object> {
        let start = self.at;
        let token = self.keyword()?;
        match token {
            b"true" => return Some(Object::Bool(true)),
            b"false" => return Some(Object::Bool(false)),
            b"null" => return Some(Object::Null),
            _ => {}
        }
        let text = std::str::from_utf8(token).ok()?;
        let Ok(number) = parse_number(text) else {
            return Some(Object::Name(text.to_string()));
        };

        if number >= 0.0 && number.fract() == 0.0 && number <= f64::from(u32::MAX) {
            let save = self.at;
            if let Some(second) = self.keyword() {
                if let Ok(generation) = parse_number(std::str::from_utf8(second).ok()?) {
                    if generation >= 0.0 && generation.fract() == 0.0 && generation <= 65535.0 {
                        let third = self.at;
                        if self.keyword() == Some(b"R") {
                            return Some(Object::Reference(number as u32, generation as u16));
                        }
                        self.at = third;
                    }
                }
            }
            self.at = save;
        }
        let _ = start;
        Some(Object::Number(number))
    }
}

fn parse_number(text: &str) -> Result<f64, ()> {
    let text = text.trim();
    if text.is_empty() {
        return Err(());
    }
    let mut cleaned = String::with_capacity(text.len());
    let mut seen_any = false;
    let mut seen_digit = false;
    for (i, c) in text.chars().enumerate() {
        match c {
            '+' if i == 0 => {}
            '-' if !seen_any => {
                if !cleaned.starts_with('-') {
                    cleaned.push('-');
                }
            }
            '0'..='9' => {
                seen_any = true;
                seen_digit = true;
                cleaned.push(c);
            }
            '.' => {
                seen_any = true;
                cleaned.push(c);
            }
            _ => return Err(()),
        }
    }
    if !seen_digit {
        return Err(());
    }
    let cleaned = match (cleaned.starts_with('.'), cleaned.ends_with('.')) {
        (true, _) => format!("0{cleaned}"),
        (_, true) => format!("{cleaned}0"),
        _ => cleaned,
    };
    cleaned
        .parse::<f64>()
        .map_err(|_| ())
        .and_then(|n| if n.is_finite() { Ok(n) } else { Err(()) })
}

pub fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Option<Object> {
        Lexer::new(text.as_bytes()).object(0)
    }

    #[test]
    fn the_simple_types_parse() {
        assert_eq!(parse("true"), Some(Object::Bool(true)));
        assert_eq!(parse("false"), Some(Object::Bool(false)));
        assert_eq!(parse("null"), Some(Object::Null));
        assert_eq!(parse("/Name"), Some(Object::Name("Name".into())));
        assert_eq!(parse("42"), Some(Object::Number(42.0)));
    }

    #[test]
    fn the_number_forms_real_writers_emit_all_parse() {
        for (text, expected) in [
            ("0", 0.0),
            ("42", 42.0),
            ("-7", -7.0),
            ("+5", 5.0),
            ("4.", 4.0),
            (".5", 0.5),
            ("-.002", -0.002),
            ("--7", -7.0),
            ("34.5", 34.5),
        ] {
            assert_eq!(parse(text), Some(Object::Number(expected)), "{text}");
        }
        assert_eq!(parse("Tj"), Some(Object::Name("Tj".into())));
        assert_eq!(parse("."), Some(Object::Name(".".into())));
    }

    #[test]
    fn a_literal_string_handles_nesting_and_escapes() {
        assert_eq!(parse("(plain)"), Some(Object::String(b"plain".to_vec())));
        assert_eq!(
            parse("(a (nested) b)"),
            Some(Object::String(b"a (nested) b".to_vec()))
        );
        assert_eq!(
            parse(r"(\(escaped\))"),
            Some(Object::String(b"(escaped)".to_vec()))
        );
        assert_eq!(
            parse(r"(tab\there\nnew)"),
            Some(Object::String(b"tab\there\nnew".to_vec()))
        );
        assert_eq!(parse(r"(\351)"), Some(Object::String(vec![0xE9])));
        assert_eq!(parse(r"(\7)"), Some(Object::String(vec![7])));
        assert_eq!(
            parse("(one\\\ntwo)"),
            Some(Object::String(b"onetwo".to_vec()))
        );
        assert_eq!(parse(r"(\q)"), Some(Object::String(b"q".to_vec())));
        assert_eq!(parse("(no end"), Some(Object::String(b"no end".to_vec())));
    }

    #[test]
    fn every_backslash_escape_is_handled() {
        assert_eq!(parse(r"(\r)"), Some(Object::String(b"\r".to_vec())));
        assert_eq!(parse(r"(\b)"), Some(Object::String(vec![8])));
        assert_eq!(parse(r"(\f)"), Some(Object::String(vec![12])));
        assert_eq!(parse(r"(\\)"), Some(Object::String(b"\\".to_vec())));
        assert_eq!(
            parse("(one\\\r\ntwo)"),
            Some(Object::String(b"onetwo".to_vec()))
        );
        assert_eq!(
            parse("(one\\\rtwo)"),
            Some(Object::String(b"onetwo".to_vec()))
        );
        assert_eq!(
            parse("(trailing\\"),
            Some(Object::String(b"trailing".to_vec()))
        );
    }

    #[test]
    fn a_hex_string_pads_an_odd_digit_and_ignores_whitespace() {
        assert_eq!(parse("<48656C>"), Some(Object::String(b"Hel".to_vec())));
        assert_eq!(parse("<48 65 6C>"), Some(Object::String(b"Hel".to_vec())));
        assert_eq!(parse("<4>"), Some(Object::String(vec![0x40])));
        assert_eq!(parse("<>"), Some(Object::String(Vec::new())));
        assert_eq!(parse("<4865"), Some(Object::String(b"He".to_vec())));
    }

    #[test]
    fn a_name_decodes_its_hash_escapes() {
        assert_eq!(parse("/A#20B"), Some(Object::Name("A B".into())));
        assert_eq!(parse("/Length1"), Some(Object::Name("Length1".into())));
        assert_eq!(parse("/A#ZZ"), Some(Object::Name("A#ZZ".into())));
        assert_eq!(parse("/"), Some(Object::Name(String::new())));
    }

    #[test]
    fn an_array_parses_and_survives_rubbish_inside_it() {
        assert_eq!(
            parse("[1 2 3]"),
            Some(Object::Array(vec![
                Object::Number(1.0),
                Object::Number(2.0),
                Object::Number(3.0)
            ]))
        );
        assert_eq!(parse("[]"), Some(Object::Array(Vec::new())));
        let got = parse("[1 } 2]").expect("an array");
        assert!(matches!(got, Object::Array(_)), "{got:?}");
        assert!(matches!(parse("[1 2"), Some(Object::Array(_))));
    }

    #[test]
    fn a_dictionary_parses_and_skips_a_key_that_is_not_a_name() {
        let got = parse("<< /Type /Page /Count 3 >>").expect("a dictionary");
        let dict = got.as_dict().expect("a dict");
        assert_eq!(dict.get("Type").and_then(Object::as_name), Some("Page"));
        assert_eq!(dict.get("Count").and_then(Object::as_f64), Some(3.0));
        let got = parse("<< 5 /Type /Page >>").expect("a dictionary");
        assert_eq!(
            got.as_dict()
                .and_then(|d| d.get("Type"))
                .and_then(Object::as_name),
            Some("Page")
        );
        assert!(parse("<< /A 1")
            .and_then(|o| o.as_dict().cloned())
            .is_some());
    }

    #[test]
    fn a_reference_is_told_apart_from_two_numbers() {
        assert_eq!(parse("12 0 R"), Some(Object::Reference(12, 0)));
        assert_eq!(parse("3 65535 R"), Some(Object::Reference(3, 65535)));
        let mut lexer = Lexer::new(b"12 0 Tj");
        assert_eq!(lexer.object(0), Some(Object::Number(12.0)));
        assert_eq!(lexer.object(0), Some(Object::Number(0.0)));
        assert_eq!(lexer.object(0), Some(Object::Name("Tj".into())));
        assert_eq!(parse("-1 0 R"), Some(Object::Number(-1.0)));
    }

    #[test]
    fn nesting_past_the_depth_cap_is_refused_rather_than_overflowing() {
        let deep = "[".repeat(MAX_DEPTH + 10);
        let _ = parse(&deep);
        let deep_dicts = "<< /A ".repeat(MAX_DEPTH + 10);
        let _ = parse(&deep_dicts);
        assert_eq!(Lexer::new(b"[1]").object(MAX_DEPTH + 1), None);
        assert_eq!(Lexer::new(b"<< /A 1 >>").object(MAX_DEPTH + 1), None);
        assert_eq!(Lexer::new(b"(x)").object(MAX_DEPTH + 1), None);
        let nested = "[".repeat(3) + &"]".repeat(3);
        let _ = Lexer::new(nested.as_bytes()).object(MAX_DEPTH - 1);
    }

    #[test]
    fn comments_and_whitespace_are_skipped_wherever_they_appear() {
        assert_eq!(parse("% a comment\n42"), Some(Object::Number(42.0)));
        assert_eq!(parse("\0\t\r\n 42"), Some(Object::Number(42.0)));
        let got = parse("<< % comment\n /A 1 >>").expect("a dictionary");
        assert_eq!(
            got.as_dict()
                .and_then(|d| d.get("A"))
                .and_then(Object::as_f64),
            Some(1.0)
        );
        assert_eq!(parse("% never ends"), None);
    }

    #[test]
    fn a_closing_delimiter_on_its_own_is_not_an_object() {
        for text in ["]", ">", ")", "}"] {
            assert_eq!(parse(text), None, "{text}");
        }
        assert_eq!(parse(""), None);
    }

    #[test]
    fn the_accessors_answer_only_for_their_own_type() {
        let dict = parse("<< /A 1 >>").expect("a dict");
        assert!(dict.as_dict().is_some());
        assert!(dict.as_array().is_none());
        assert!(dict.as_name().is_none());
        assert!(dict.as_f64().is_none());
        assert!(dict.as_reference().is_none());

        let stream = Object::Stream {
            dict: Dict::new(),
            data: Vec::new(),
        };
        assert!(stream.as_dict().is_some());

        assert_eq!(Object::Number(2.0).as_f64(), Some(2.0));
        assert_eq!(Object::Name("x".into()).as_name(), Some("x"));
        assert_eq!(Object::Array(Vec::new()).as_array(), Some(&[][..]));
        assert_eq!(Object::Reference(1, 2).as_reference(), Some((1, 2)));
        assert!(Object::Null.as_dict().is_none());
    }

    #[test]
    fn an_over_long_string_or_name_is_refused() {
        let long = format!("({})", "x".repeat(MAX_STRING + 10));
        assert_eq!(parse(&long), None);
        let long_hex = format!("<{}>", "41".repeat(MAX_STRING + 10));
        assert_eq!(parse(&long_hex), None);
        let long_name = format!("/{}", "x".repeat(MAX_STRING + 10));
        assert_eq!(parse(&long_name), None);
    }

    #[test]
    fn the_character_classes_match_the_specification() {
        for b in *b"\0\t\n\x0c\r " {
            assert!(is_white(b), "{b:?}");
            assert!(!is_delimiter(b), "{b:?}");
        }
        for b in *b"()<>[]{}/%" {
            assert!(is_delimiter(b), "{b:?}");
            assert!(!is_white(b), "{b:?}");
        }
        assert!(!is_white(b'A') && !is_delimiter(b'A'));
    }

    #[test]
    fn hex_digits_decode_in_both_cases() {
        assert_eq!(hex_value(b'0'), Some(0));
        assert_eq!(hex_value(b'9'), Some(9));
        assert_eq!(hex_value(b'a'), Some(10));
        assert_eq!(hex_value(b'F'), Some(15));
        assert_eq!(hex_value(b'g'), None);
    }

    #[test]
    fn a_dictionary_with_absurdly_many_keys_stops() {
        let body: String = (0..5000).map(|i| format!("/K{i} {i} ")).collect();
        let got = parse(&format!("<< {body} >>")).expect("a dictionary");
        assert!(got.as_dict().expect("dict").len() <= 4097);
    }
}
