#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextRules {
    pub text_elements: &'static [&'static str],
    pub break_elements: &'static [&'static str],
    pub tab_elements: &'static [&'static str],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    pub max_chars: usize,
    pub max_depth: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_chars: 1024 * 1024,
            max_depth: 256,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XmlError {
    DoctypeRefused,
    TooDeep { limit: usize },
    NotUtf8,
}

impl std::fmt::Display for XmlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DoctypeRefused => write!(
                f,
                "this part declares a DOCTYPE, which is refused: a document \
                 that declares entities is not one we will expand"
            ),
            Self::TooDeep { limit } => write!(f, "element nesting passed {limit} levels"),
            Self::NotUtf8 => write!(f, "the part was not valid UTF-8"),
        }
    }
}

impl std::error::Error for XmlError {}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Text {
    pub text: String,
    pub truncated: bool,
}

struct Sink {
    out: String,
    chars: usize,
    limit: usize,
    truncated: bool,
}

impl Sink {
    fn new(limit: usize) -> Self {
        Self {
            out: String::new(),
            chars: 0,
            limit,
            truncated: false,
        }
    }

    fn push(&mut self, c: char) {
        if self.chars >= self.limit {
            self.truncated = true;
            return;
        }
        self.out.push(c);
        self.chars += 1;
    }

    fn push_str(&mut self, s: &str) {
        for c in s.chars() {
            if self.chars >= self.limit {
                self.truncated = true;
                return;
            }
            self.out.push(c);
            self.chars += 1;
        }
    }

    fn full(&self) -> bool {
        self.chars >= self.limit
    }

    fn newline(&mut self) {
        if self.out.is_empty() || self.out.ends_with('\n') {
            return;
        }
        self.push('\n');
    }
}

fn local_name(tag: &str) -> &str {
    let name = tag
        .split([' ', '\t', '\n', '\r', '/'])
        .next()
        .unwrap_or_default();
    match name.rsplit_once(':') {
        Some((_, local)) => local,
        None => name,
    }
}

pub fn extract(part: &[u8], rules: &TextRules, limits: &Limits) -> Result<Text, XmlError> {
    let text = std::str::from_utf8(part).map_err(|_| XmlError::NotUtf8)?;
    let bytes = text.as_bytes();
    let mut sink = Sink::new(limits.max_chars);
    let mut open: Vec<&str> = Vec::new();
    let mut in_text = 0usize;
    let mut at = 0usize;

    while at < bytes.len() {
        if sink.full() {
            sink.truncated = true;
            break;
        }
        if bytes[at] != b'<' {
            let end = memchr(bytes, b'<', at).unwrap_or(bytes.len());
            if in_text > 0 {
                push_decoded(&mut sink, &text[at..end]);
            }
            at = end;
            continue;
        }
        let rest = &text[at..];
        if rest.starts_with("<!--") {
            at = find(text, "-->", at + 4).map_or(bytes.len(), |i| i + 3);
            continue;
        }
        if rest.starts_with("<![CDATA[") {
            let start = at + 9;
            let end = find(text, "]]>", start).unwrap_or(bytes.len());
            if in_text > 0 {
                sink.push_str(&text[start..end.min(bytes.len())]);
            }
            at = end.saturating_add(3).min(bytes.len());
            continue;
        }
        if rest.starts_with("<!") {
            return Err(XmlError::DoctypeRefused);
        }
        if rest.starts_with("<?") {
            at = find(text, "?>", at + 2).map_or(bytes.len(), |i| i + 2);
            continue;
        }

        let Some(close) = memchr(bytes, b'>', at) else {
            break;
        };
        let inner = &text[at + 1..close];
        at = close + 1;

        if let Some(name) = inner.strip_prefix('/') {
            let name = local_name(name);
            if let Some(position) = open.iter().rposition(|o| *o == name) {
                for closed in open.drain(position..) {
                    if rules.text_elements.contains(&closed) {
                        in_text = in_text.saturating_sub(1);
                    }
                }
            }
            if rules.break_elements.contains(&name) {
                sink.newline();
            }
            continue;
        }

        let self_closing = inner.ends_with('/');
        let name = local_name(inner);
        if name.is_empty() {
            continue;
        }
        if rules.tab_elements.contains(&name) {
            sink.push('\t');
        }
        if self_closing {
            if rules.break_elements.contains(&name) {
                sink.newline();
            }
            continue;
        }
        if open.len() >= limits.max_depth {
            return Err(XmlError::TooDeep {
                limit: limits.max_depth,
            });
        }
        if rules.text_elements.contains(&name) {
            in_text += 1;
        }
        open.push(name);
    }
    Ok(Text {
        text: sink.out,
        truncated: sink.truncated,
    })
}

fn memchr(bytes: &[u8], needle: u8, from: usize) -> Option<usize> {
    bytes[from..]
        .iter()
        .position(|b| *b == needle)
        .map(|i| i + from)
}

fn find(text: &str, needle: &str, from: usize) -> Option<usize> {
    text.get(from..)
        .and_then(|t| t.find(needle))
        .map(|i| i + from)
}

fn push_decoded(sink: &mut Sink, s: &str) {
    let mut rest = s;
    while let Some(amp) = rest.find('&') {
        sink.push_str(&rest[..amp]);
        rest = &rest[amp..];
        let Some(semi) = rest.get(..64).unwrap_or(rest).find(';') else {
            sink.push('&');
            rest = &rest[1..];
            continue;
        };
        let body = &rest[1..semi];
        let decoded = match body {
            "lt" => Some('<'),
            "gt" => Some('>'),
            "amp" => Some('&'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ => numeric_reference(body),
        };
        match decoded {
            Some(c) => sink.push(c),
            None => sink.push_str(&rest[..=semi]),
        }
        rest = &rest[semi + 1..];
    }
    sink.push_str(rest);
}

fn numeric_reference(body: &str) -> Option<char> {
    let digits = body.strip_prefix('#')?;
    let value = match digits.strip_prefix(['x', 'X']) {
        Some(hex) => u32::from_str_radix(hex, 16).ok()?,
        None => digits.parse::<u32>().ok()?,
    };
    char::from_u32(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULES: TextRules = TextRules {
        text_elements: &["t"],
        break_elements: &["p", "br"],
        tab_elements: &["tab"],
    };

    fn text_of(xml: &str) -> String {
        extract(xml.as_bytes(), &RULES, &Limits::default())
            .expect("readable")
            .text
    }

    #[test]
    fn only_the_named_elements_contribute_text() {
        assert_eq!(
            text_of("<a><t>kept</t><u>dropped</u><t>also kept</t></a>"),
            "keptalso kept"
        );
    }

    #[test]
    fn a_prefix_is_ignored_and_only_the_local_name_matters() {
        assert_eq!(text_of("<w:t>a</w:t><a:t>b</a:t><t>c</t>"), "abc");
    }

    #[test]
    fn the_five_predefined_entities_and_both_numeric_forms_decode() {
        assert_eq!(
            text_of("<t>&lt;&gt;&amp;&quot;&apos;&#65;&#x42;&#x4d2;</t>"),
            "<>&\"'AB\u{4d2}"
        );
    }

    #[test]
    fn an_undefined_entity_is_passed_through_as_text() {
        assert_eq!(text_of("<t>&nbsp;&lol;</t>"), "&nbsp;&lol;");
    }

    #[test]
    fn a_bare_ampersand_is_text() {
        assert_eq!(text_of("<t>Tom & Jerry</t>"), "Tom & Jerry");
        let long = format!("<t>&{}</t>", "x".repeat(100));
        assert!(text_of(&long).starts_with('&'));
    }

    #[test]
    fn a_malformed_numeric_reference_is_text() {
        assert_eq!(
            text_of("<t>&#;&#xZZ;&#99999999999;</t>"),
            "&#;&#xZZ;&#99999999999;"
        );
    }

    #[test]
    fn comments_and_processing_instructions_are_not_text() {
        assert_eq!(
            text_of("<?xml version=\"1.0\"?><t>kept<!-- dropped --></t>"),
            "kept"
        );
        assert_eq!(text_of("<t>kept</t><!-- never closed"), "kept");
        assert_eq!(text_of("<t>kept</t><?never closed"), "kept");
    }

    #[test]
    fn a_single_character_push_stops_at_the_bound() {
        let limits = Limits {
            max_chars: 2,
            ..Limits::default()
        };
        let got = extract(b"<t>ab</t><tab/><t>c</t>", &RULES, &limits).expect("bounded");
        assert_eq!(got.text, "ab");
        assert!(got.truncated);
        let got = extract(b"<t>ab&amp;</t>", &RULES, &limits).expect("bounded");
        assert_eq!(got.text, "ab");
        assert!(got.truncated);
    }

    #[test]
    fn cdata_outside_a_text_element_contributes_nothing() {
        assert_eq!(text_of("<a><![CDATA[ignored]]></a><t>kept</t>"), "kept");
    }

    #[test]
    fn cdata_is_taken_verbatim_including_markup() {
        assert_eq!(text_of("<t><![CDATA[<b>&amp;</b>]]></t>"), "<b>&amp;</b>");
        assert!(text_of("<t><![CDATA[tail").contains("tail"));
    }

    #[test]
    fn a_doctype_is_refused_whatever_follows_it() {
        for xml in [
            "<!DOCTYPE t><t>x</t>",
            "<!DOCTYPE t [<!ENTITY e \"x\">]><t>&e;</t>",
            "<!ANYTHING><t>x</t>",
        ] {
            assert_eq!(
                extract(xml.as_bytes(), &RULES, &Limits::default()),
                Err(XmlError::DoctypeRefused),
                "{xml}"
            );
        }
    }

    #[test]
    fn breaks_become_newlines_and_never_double_up() {
        assert_eq!(text_of("<p><t>one</t></p><p><t>two</t></p>"), "one\ntwo\n");
        assert_eq!(text_of("<p><t>one</t><br/><t>two</t></p>"), "one\ntwo\n");
        assert_eq!(text_of("<p><p><p><t>x</t></p></p></p>"), "x\n");
        assert_eq!(text_of("<br/><t>x</t>"), "x");
    }

    #[test]
    fn a_tab_element_inserts_a_tab() {
        assert_eq!(text_of("<t>a</t><tab/><t>b</t>"), "a\tb");
    }

    #[test]
    fn an_unterminated_tag_ends_the_document_with_what_was_read() {
        assert_eq!(text_of("<t>kept</t><unclosed"), "kept");
    }

    #[test]
    fn an_empty_tag_name_is_skipped() {
        assert_eq!(text_of("<><t>kept</t>"), "kept");
    }

    #[test]
    fn mismatched_close_tags_do_not_corrupt_the_state() {
        assert_eq!(text_of("</t><t>kept</t>"), "kept");
        assert_eq!(text_of("<a><t>kept</a><t>also</t>"), "keptalso");
    }

    #[test]
    fn text_outside_any_named_element_is_ignored() {
        assert_eq!(text_of("loose text<t>kept</t>more loose"), "kept");
    }

    #[test]
    fn the_character_bound_stops_extraction_and_is_reported() {
        let limits = Limits {
            max_chars: 4,
            ..Limits::default()
        };
        let got = extract(b"<t>abcdefgh</t>", &RULES, &limits).expect("bounded");
        assert_eq!(got.text, "abcd");
        assert!(got.truncated);
        let got = extract(
            "<t>\u{4e00}\u{4e8c}\u{4e09}\u{56db}\u{4e94}</t>".as_bytes(),
            &RULES,
            &limits,
        )
        .expect("bounded");
        assert_eq!(got.text.chars().count(), 4);
        assert!(got.truncated);
    }

    #[test]
    fn a_bound_of_zero_yields_nothing_rather_than_looping() {
        let limits = Limits {
            max_chars: 0,
            ..Limits::default()
        };
        let got = extract(b"<t>abc</t>", &RULES, &limits).expect("bounded");
        assert!(got.text.is_empty());
    }

    #[test]
    fn nesting_past_the_depth_bound_is_refused() {
        let limits = Limits {
            max_depth: 3,
            ..Limits::default()
        };
        let deep = "<a><b><c><d><t>x</t></d></c></b></a>";
        assert_eq!(
            extract(deep.as_bytes(), &RULES, &limits),
            Err(XmlError::TooDeep { limit: 3 })
        );
    }

    #[test]
    fn self_closing_elements_do_not_count_towards_depth() {
        let limits = Limits {
            max_depth: 2,
            ..Limits::default()
        };
        let many = "<br/>".repeat(100);
        assert!(extract(many.as_bytes(), &RULES, &limits).is_ok());
    }

    #[test]
    fn a_part_that_is_not_utf8_is_refused() {
        assert_eq!(
            extract(&[0xFF, 0xFE, 0x00], &RULES, &Limits::default()),
            Err(XmlError::NotUtf8)
        );
    }

    #[test]
    fn every_error_renders_and_is_a_std_error() {
        for e in [
            XmlError::DoctypeRefused,
            XmlError::TooDeep { limit: 1 },
            XmlError::NotUtf8,
        ] {
            assert!(!e.to_string().is_empty(), "{e:?} rendered empty");
            let _: &dyn std::error::Error = &e;
        }
    }

    #[test]
    fn the_default_bounds_are_stated_rather_than_implied() {
        let d = Limits::default();
        assert_eq!(d.max_chars, 1024 * 1024);
        assert_eq!(d.max_depth, 256);
    }
}
