//! A minimal, purpose-scoped XML parser — no external crate, matching
//! this project's dependency-minimization policy (see `bc-enrich::
//! csv_parse`'s own doc comment for the precedent this follows). Scoped
//! exactly to what `checkmarx.rs` needs to walk a `CxXMLResults`
//! document: nested elements carrying their data in attributes **and**,
//! inside `<PathNode>`, in element text.
//!
//! Element text used to be discarded on the premise that "Checkmarx's
//! classic XML report carries everything this pipeline needs in
//! attributes" — which is false for the one part of that report that
//! carries the actual evidence. A `<Result>`'s dataflow lives in
//! `<Path><PathNode><FileName>src/app.py</FileName><Line>42</Line>
//! <Name>execute</Name></PathNode>…`, i.e. entirely in element text, so
//! discarding it made source/sink information unreachable to the parser
//! that needed it.
//!
//! Still deliberately NOT a general-purpose XML parser — no namespaces,
//! no DTD/entity declarations, no CDATA sections, and text is flattened
//! per element (every text run directly inside an element is
//! concatenated and trimmed) rather than interleaved with children.

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct XmlNode {
    pub tag: String,
    pub attrs: Vec<(String, String)>,
    /// All text directly inside this element, entity-decoded,
    /// concatenated across runs and trimmed. Empty when the element has
    /// no text of its own.
    pub text: String,
    pub children: Vec<XmlNode>,
}

impl XmlNode {
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    pub fn child_elements<'a>(&'a self, tag: &'a str) -> impl Iterator<Item = &'a XmlNode> {
        self.children.iter().filter(move |c| c.tag == tag)
    }

    /// Text of the first `<tag>` child, or `None` when there is no such
    /// child or its text is empty.
    pub fn child_text(&self, tag: &str) -> Option<&str> {
        // Iterates `children` directly rather than via `child_elements`,
        // whose signature ties `tag`'s lifetime to `self`'s.
        self.children
            .iter()
            .find(|c| c.tag == tag)
            .map(|c| c.text.as_str())
            .filter(|t| !t.is_empty())
    }
}

/// Parses `text` into its single root element, discarding the XML
/// declaration and comments. A best-effort parser, not a validating one —
/// it accepts anything it can walk without ambiguity, but doesn't enforce
/// every XML well-formedness rule (e.g. attribute-name uniqueness).
pub(crate) fn parse(text: &str) -> Result<XmlNode, String> {
    let chars: Vec<char> = text.chars().collect();
    let mut pos = 0usize;
    skip_prolog_and_trivia(&chars, &mut pos);
    let root = parse_element(&chars, &mut pos)?;
    Ok(root)
}

fn skip_prolog_and_trivia(chars: &[char], pos: &mut usize) {
    loop {
        skip_ws(chars, pos);
        if starts_with(chars, *pos, "<?") {
            while *pos < chars.len() && !starts_with(chars, *pos, "?>") {
                *pos += 1;
            }
            *pos = (*pos + 2).min(chars.len());
        } else if starts_with(chars, *pos, "<!--") {
            skip_comment(chars, pos);
        } else {
            break;
        }
    }
}

fn skip_comment(chars: &[char], pos: &mut usize) {
    *pos += 4; // consume "<!--"
    while *pos < chars.len() && !starts_with(chars, *pos, "-->") {
        *pos += 1;
    }
    *pos = (*pos + 3).min(chars.len());
}

fn starts_with(chars: &[char], pos: usize, needle: &str) -> bool {
    let needle: Vec<char> = needle.chars().collect();
    chars[pos..].starts_with(needle.as_slice())
}

fn skip_ws(chars: &[char], pos: &mut usize) {
    while *pos < chars.len() && chars[*pos].is_whitespace() {
        *pos += 1;
    }
}

fn is_name_start(c: char) -> bool {
    c.is_alphabetic() || c == '_' || c == ':'
}

fn is_name_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_' || c == ':' || c == '-' || c == '.'
}

fn read_name(chars: &[char], pos: &mut usize) -> Result<String, String> {
    let start = *pos;
    if !chars.get(*pos).is_some_and(|c| is_name_start(*c)) {
        return Err(format!("expected a name at position {pos}"));
    }
    while *pos < chars.len() && is_name_char(chars[*pos]) {
        *pos += 1;
    }
    Ok(chars[start..*pos].iter().collect())
}

fn read_attr(chars: &[char], pos: &mut usize) -> Result<(String, String), String> {
    let name = read_name(chars, pos)?;
    skip_ws(chars, pos);
    if chars.get(*pos) != Some(&'=') {
        return Err(format!("expected '=' after attribute name {name}"));
    }
    *pos += 1;
    skip_ws(chars, pos);
    let quote = match chars.get(*pos) {
        Some(q @ ('"' | '\'')) => *q,
        _ => return Err(format!("expected a quoted value for attribute {name}")),
    };
    *pos += 1;
    let start = *pos;
    while *pos < chars.len() && chars[*pos] != quote {
        *pos += 1;
    }
    if *pos >= chars.len() {
        return Err(format!("unterminated attribute value for {name}"));
    }
    let raw: String = chars[start..*pos].iter().collect();
    *pos += 1; // consume closing quote
    Ok((name, decode_entities(&raw)))
}

fn decode_entities(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '&' {
            out.push(c);
            continue;
        }
        let mut entity = String::new();
        let mut closed = false;
        for _ in 0..16 {
            match chars.peek() {
                Some(';') => {
                    chars.next();
                    closed = true;
                    break;
                }
                Some(&ec) if ec != '&' => {
                    entity.push(ec);
                    chars.next();
                }
                _ => break,
            }
        }
        if !closed {
            out.push('&');
            out.push_str(&entity);
            continue;
        }
        if let Some(decoded) = decode_one_entity(&entity) {
            out.push(decoded);
        } else {
            out.push('&');
            out.push_str(&entity);
            out.push(';');
        }
    }
    out
}

fn decode_one_entity(entity: &str) -> Option<char> {
    match entity {
        "amp" => return Some('&'),
        "lt" => return Some('<'),
        "gt" => return Some('>'),
        "quot" => return Some('"'),
        "apos" => return Some('\''),
        _ => {}
    }
    let digits = entity
        .strip_prefix("#x")
        .or_else(|| entity.strip_prefix("#X"));
    if let Some(hex) = digits {
        return u32::from_str_radix(hex, 16).ok().and_then(char::from_u32);
    }
    entity
        .strip_prefix('#')
        .and_then(|dec| dec.parse::<u32>().ok())
        .and_then(char::from_u32)
}

fn parse_element(chars: &[char], pos: &mut usize) -> Result<XmlNode, String> {
    skip_ws(chars, pos);
    if chars.get(*pos) != Some(&'<') {
        return Err(format!("expected '<' at position {pos}"));
    }
    *pos += 1;
    let tag = read_name(chars, pos)?;
    let mut attrs = Vec::new();
    loop {
        skip_ws(chars, pos);
        match chars.get(*pos) {
            Some('/') => {
                *pos += 1;
                if chars.get(*pos) != Some(&'>') {
                    return Err(format!("malformed self-closing tag <{tag}>"));
                }
                *pos += 1;
                return Ok(XmlNode {
                    tag,
                    attrs,
                    text: String::new(),
                    children: Vec::new(),
                });
            }
            Some('>') => {
                *pos += 1;
                break;
            }
            Some(c) if is_name_start(*c) => {
                attrs.push(read_attr(chars, pos)?);
            }
            _ => return Err(format!("unexpected character in <{tag}> tag attributes")),
        }
    }

    let mut children = Vec::new();
    let mut text = String::new();
    loop {
        if starts_with(chars, *pos, "<!--") {
            skip_comment(chars, pos);
            continue;
        }
        if chars.get(*pos) == Some(&'<') {
            if chars.get(*pos + 1) == Some(&'/') {
                *pos += 2;
                let close_tag = read_name(chars, pos)?;
                skip_ws(chars, pos);
                if chars.get(*pos) != Some(&'>') {
                    return Err(format!("malformed closing tag </{close_tag}>"));
                }
                *pos += 1;
                if close_tag != tag {
                    return Err(format!(
                        "mismatched close tag: expected </{tag}>, got </{close_tag}>"
                    ));
                }
                return Ok(XmlNode {
                    tag,
                    attrs,
                    text: text.trim().to_string(),
                    children,
                });
            }
            children.push(parse_element(chars, pos)?);
            continue;
        }
        // Plain text content: accumulated onto this element (see module
        // doc — Checkmarx's `<PathNode>` dataflow lives here).
        let start = *pos;
        while *pos < chars.len() && chars[*pos] != '<' {
            *pos += 1;
        }
        if *pos == start {
            return Err(format!("unclosed element <{tag}>"));
        }
        if *pos >= chars.len() {
            return Err(format!("unclosed element <{tag}>"));
        }
        let raw: String = chars[start..*pos].iter().collect();
        text.push_str(&decode_entities(&raw));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_self_closing_root_element_with_attributes() {
        let root = parse(r#"<Root a="1" b="two"/>"#).unwrap();
        assert_eq!(root.tag, "Root");
        assert_eq!(root.attr("a"), Some("1"));
        assert_eq!(root.attr("b"), Some("two"));
        assert!(root.children.is_empty());
    }

    #[test]
    fn parses_nested_elements() {
        let root = parse(r#"<A><B x="1"/><B x="2"/></A>"#).unwrap();
        assert_eq!(root.tag, "A");
        let bs: Vec<&str> = root
            .child_elements("B")
            .map(|b| b.attr("x").unwrap())
            .collect();
        assert_eq!(bs, vec!["1", "2"]);
    }

    #[test]
    fn skips_the_xml_declaration_and_comments() {
        let root =
            parse("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!-- a comment --><Root/>").unwrap();
        assert_eq!(root.tag, "Root");
    }

    #[test]
    fn captures_text_content_alongside_child_elements() {
        let root = parse("<Root>   some text   <Child/></Root>").unwrap();
        assert_eq!(root.children.len(), 1);
        assert_eq!(root.children[0].tag, "Child");
        assert_eq!(root.text, "some text");
    }

    #[test]
    fn captures_the_text_of_a_leaf_element() {
        let root = parse("<Path><FileName>src/app.py</FileName><Line>42</Line></Path>").unwrap();
        assert_eq!(root.child_text("FileName"), Some("src/app.py"));
        assert_eq!(root.child_text("Line"), Some("42"));
    }

    #[test]
    fn text_runs_split_by_a_child_element_are_concatenated() {
        let root = parse("<R>a<C/>b</R>").unwrap();
        assert_eq!(root.text, "ab");
    }

    #[test]
    fn entities_in_element_text_are_decoded() {
        let root = parse("<R><N>a &amp; b &lt;c&gt;</N></R>").unwrap();
        assert_eq!(root.child_text("N"), Some("a & b <c>"));
    }

    #[test]
    fn an_element_with_no_text_of_its_own_has_empty_text() {
        let root = parse("<R><C/></R>").unwrap();
        assert_eq!(root.text, "");
        assert_eq!(root.children[0].text, "");
    }

    #[test]
    fn child_text_of_a_whitespace_only_element_is_none() {
        let root = parse("<R><N>   </N></R>").unwrap();
        assert_eq!(root.child_text("N"), None);
    }

    #[test]
    fn child_text_of_a_missing_child_is_none() {
        let root = parse("<R><N>x</N></R>").unwrap();
        assert_eq!(root.child_text("Missing"), None);
    }

    #[test]
    fn a_self_closing_element_has_empty_text() {
        assert_eq!(parse("<R/>").unwrap().text, "");
    }

    #[test]
    fn skips_a_comment_between_child_elements() {
        let root = parse("<Root><!-- a comment --><Child/></Root>").unwrap();
        assert_eq!(root.children.len(), 1);
        assert_eq!(root.children[0].tag, "Child");
    }

    #[test]
    fn an_element_tag_name_that_cannot_start_a_name_is_an_error() {
        let err = parse("<1abc/>").unwrap_err();
        assert!(err.contains("expected a name"));
    }

    #[test]
    fn trailing_text_content_with_no_further_tag_and_no_closing_tag_is_an_error() {
        let err = parse("<A>some text with no more tags").unwrap_err();
        assert!(err.contains("unclosed element"));
    }

    #[test]
    fn decodes_standard_entities_in_attribute_values() {
        let root = parse(r#"<R v="a &amp; b &lt;c&gt; &quot;d&quot; &apos;e&apos;"/>"#).unwrap();
        assert_eq!(root.attr("v"), Some("a & b <c> \"d\" 'e'"));
    }

    #[test]
    fn decodes_numeric_character_references() {
        let root = parse(r#"<R v="&#65;&#x42;"/>"#).unwrap();
        assert_eq!(root.attr("v"), Some("AB"));
    }

    #[test]
    fn an_unrecognized_entity_is_passed_through_literally() {
        let root = parse(r#"<R v="a &nope; b"/>"#).unwrap();
        assert_eq!(root.attr("v"), Some("a &nope; b"));
    }

    #[test]
    fn an_unterminated_entity_is_passed_through_literally() {
        let root = parse(r#"<R v="a &amp b"/>"#).unwrap();
        // No terminating ';' within range -> left as-is, including the '&'.
        assert_eq!(root.attr("v"), Some("a &amp b"));
    }

    #[test]
    fn single_quoted_attribute_values_are_supported() {
        let root = parse("<R v='hello'/>").unwrap();
        assert_eq!(root.attr("v"), Some("hello"));
    }

    #[test]
    fn attr_returns_none_for_a_missing_attribute() {
        let root = parse(r#"<R a="1"/>"#).unwrap();
        assert_eq!(root.attr("missing"), None);
    }

    #[test]
    fn mismatched_close_tag_is_an_error() {
        let err = parse("<A><B></C></A>").unwrap_err();
        assert!(err.contains("mismatched close tag"));
    }

    #[test]
    fn missing_leading_angle_bracket_is_an_error() {
        let err = parse("not xml at all").unwrap_err();
        assert!(err.contains("expected '<'"));
    }

    #[test]
    fn malformed_self_closing_tag_is_an_error() {
        let err = parse("<A/x>").unwrap_err();
        assert!(err.contains("malformed self-closing tag"));
    }

    #[test]
    fn unterminated_element_is_an_error() {
        let err = parse("<A>").unwrap_err();
        assert!(err.contains("unclosed element"));
    }

    #[test]
    fn missing_equals_after_attribute_name_is_an_error() {
        let err = parse(r#"<A b "x"/>"#).unwrap_err();
        assert!(err.contains("expected '='"));
    }

    #[test]
    fn unquoted_attribute_value_is_an_error() {
        let err = parse("<A b=1/>").unwrap_err();
        assert!(err.contains("expected a quoted value"));
    }

    #[test]
    fn unterminated_attribute_value_is_an_error() {
        let err = parse(r#"<A b="unterminated"#).unwrap_err();
        assert!(err.contains("unterminated attribute value"));
    }

    #[test]
    fn unexpected_character_in_attribute_position_is_an_error() {
        let err = parse("<A =b/>").unwrap_err();
        assert!(err.contains("unexpected character"));
    }

    #[test]
    fn malformed_closing_tag_is_an_error() {
        let err = parse("<A></A ").unwrap_err();
        assert!(err.contains("malformed closing tag"));
    }
}
