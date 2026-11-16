use std::collections::BTreeMap;

use super::document::Document;
use super::encoding::{Encoding, UNDEFINED};
use super::object::{Dict, Lexer, Object};

const WORD_GAP: f64 = 200.0;

const SAME_LINE: f64 = 1.5;

pub struct Font {
    to_unicode: BTreeMap<u32, String>,
    encoding: Encoding,
    two_byte: bool,
}

impl Font {
    fn simple() -> Self {
        Self {
            to_unicode: BTreeMap::new(),
            encoding: Encoding::default(),
            two_byte: false,
        }
    }

    fn decode(&self, bytes: &[u8], undecoded: &mut usize) -> String {
        let mut out = String::new();
        if self.two_byte {
            for pair in bytes.chunks(2) {
                let [hi, lo] = pair else {
                    *undecoded += 1;
                    continue;
                };
                let code = (u32::from(*hi) << 8) | u32::from(*lo);
                match self.to_unicode.get(&code) {
                    Some(text) => out.push_str(text),
                    None => *undecoded += 1,
                }
            }
            return out;
        }
        for &byte in bytes {
            if let Some(text) = self.to_unicode.get(&u32::from(byte)) {
                out.push_str(text);
                continue;
            }
            let c = self.encoding.decode(byte);
            if c == UNDEFINED {
                *undecoded += 1;
            } else {
                out.push(c);
            }
        }
        out
    }
}

fn page_fonts(doc: &Document, resources: Option<&Dict>) -> BTreeMap<String, Font> {
    let mut out = BTreeMap::new();
    let Some(resources) = resources else {
        return out;
    };
    let Some(fonts) = doc.entry(resources, "Font").and_then(Object::as_dict) else {
        return out;
    };
    for (name, reference) in fonts {
        let Some(dict) = doc.resolve(reference).as_dict() else {
            continue;
        };
        out.insert(name.clone(), build_font(doc, dict));
    }
    out
}

fn build_font(doc: &Document, dict: &Dict) -> Font {
    let subtype = doc
        .entry(dict, "Subtype")
        .and_then(Object::as_name)
        .unwrap_or_default()
        .to_string();
    let two_byte = subtype == "Type0";

    let mut to_unicode = BTreeMap::new();
    if let Some(stream) = doc.entry(dict, "ToUnicode") {
        if let Some(data) = doc.stream_data(stream) {
            to_unicode = parse_cmap(&data);
        }
    }

    let mut encoding = Encoding::base(
        doc.entry(dict, "Encoding")
            .and_then(Object::as_name)
            .or_else(|| {
                doc.entry(dict, "Encoding")
                    .and_then(Object::as_dict)
                    .and_then(|d| doc.entry(d, "BaseEncoding"))
                    .and_then(Object::as_name)
            }),
    );
    if let Some(differences) = doc
        .entry(dict, "Encoding")
        .and_then(Object::as_dict)
        .and_then(|d| doc.entry(d, "Differences"))
        .and_then(Object::as_array)
    {
        encoding.apply_differences(differences);
    }

    Font {
        to_unicode,
        encoding,
        two_byte,
    }
}

pub fn parse_cmap(data: &[u8]) -> BTreeMap<u32, String> {
    let mut out = BTreeMap::new();
    let mut lexer = Lexer::new(data);
    let mut stack: Vec<Object> = Vec::new();
    loop {
        lexer.skip_space();
        if lexer.at >= data.len() {
            break;
        }
        let before = lexer.at;
        let Some(object) = lexer.object(0) else {
            lexer.at = before + 1;
            continue;
        };
        if lexer.at == before {
            lexer.at += 1;
            continue;
        }
        match &object {
            Object::Name(word) if word == "beginbfchar" => {
                read_bfchar(&mut lexer, &mut out);
                stack.clear();
            }
            Object::Name(word) if word == "beginbfrange" => {
                read_bfrange(&mut lexer, &mut out);
                stack.clear();
            }
            _ => {
                stack.push(object);
                if stack.len() > 64 {
                    stack.clear();
                }
            }
        }
        if out.len() > 65_536 {
            break;
        }
    }
    out
}

fn read_bfchar(lexer: &mut Lexer<'_>, out: &mut BTreeMap<u32, String>) {
    loop {
        let before = lexer.at;
        let Some(src) = lexer.object(0) else { break };
        if lexer.at == before {
            break;
        }
        if matches!(&src, Object::Name(w) if w == "endbfchar") {
            break;
        }
        let Some(dst) = lexer.object(0) else { break };
        let (Object::String(src), Object::String(dst)) = (&src, &dst) else {
            continue;
        };
        if let Some(code) = be_code(src) {
            out.insert(code, utf16be(dst));
        }
        if out.len() > 65_536 {
            break;
        }
    }
}

fn read_bfrange(lexer: &mut Lexer<'_>, out: &mut BTreeMap<u32, String>) {
    loop {
        let before = lexer.at;
        let Some(lo) = lexer.object(0) else { break };
        if lexer.at == before {
            break;
        }
        if matches!(&lo, Object::Name(w) if w == "endbfrange") {
            break;
        }
        let (Some(hi), Some(dst)) = (lexer.object(0), lexer.object(0)) else {
            break;
        };
        let (Object::String(lo), Object::String(hi)) = (&lo, &hi) else {
            continue;
        };
        let (Some(lo), Some(hi)) = (be_code(lo), be_code(hi)) else {
            continue;
        };
        if hi < lo || hi - lo > 65_535 {
            continue;
        }
        match dst {
            Object::String(start) => {
                let base = utf16be(&start);
                let chars: Vec<char> = base.chars().collect();
                let Some(last) = chars.last().copied() else {
                    continue;
                };
                let prefix: String = chars[..chars.len() - 1].iter().collect();
                for code in lo..=hi {
                    let advanced = char::from_u32(u32::from(last) + (code - lo)).unwrap_or(last);
                    let mut text = prefix.clone();
                    text.push(advanced);
                    out.insert(code, text);
                }
            }
            Object::Array(items) => {
                for (offset, item) in items.iter().enumerate() {
                    if let Object::String(bytes) = item {
                        out.insert(lo + offset as u32, utf16be(bytes));
                    }
                }
            }
            _ => {}
        }
        if out.len() > 65_536 {
            break;
        }
    }
}

fn be_code(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() || bytes.len() > 4 {
        return None;
    }
    Some(bytes.iter().fold(0u32, |acc, b| (acc << 8) | u32::from(*b)))
}

fn utf16be(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks(2)
        .map(|c| match c {
            [hi, lo] => (u16::from(*hi) << 8) | u16::from(*lo),
            [only] => u16::from(*only),
            _ => 0,
        })
        .collect();
    String::from_utf16_lossy(&units)
        .chars()
        .filter(|c| *c != '\u{FFFD}' && *c != '\0')
        .collect()
}

#[derive(Debug, Default)]
pub struct PageText {
    pub text: String,
    pub truncated: bool,
    pub undecoded: usize,
}

pub fn page_text(doc: &Document, page: &Dict, max_chars: usize) -> PageText {
    let fonts = page_fonts(
        doc,
        doc.inherited(page, "Resources").and_then(Object::as_dict),
    );
    let mut data = Vec::new();
    match doc.entry(page, "Contents") {
        Some(Object::Array(parts)) => {
            for part in parts {
                if let Some(bytes) = doc.stream_data(doc.resolve(part)) {
                    data.extend_from_slice(&bytes);
                    data.push(b'\n');
                }
            }
        }
        Some(single) => {
            if let Some(bytes) = doc.stream_data(single) {
                data = bytes;
            }
        }
        None => {}
    }
    interpret(&data, &fonts, max_chars)
}

fn interpret(data: &[u8], fonts: &BTreeMap<String, Font>, max_chars: usize) -> PageText {
    let mut out = PageText::default();
    let fallback = Font::simple();
    let mut font: &Font = &fallback;
    let mut stack: Vec<Object> = Vec::new();
    let mut lexer = Lexer::new(data);

    let mut y: Option<f64> = None;
    let mut leading = 0.0f64;
    let mut pending_break = false;

    loop {
        lexer.skip_space();
        if lexer.at >= data.len() {
            break;
        }
        if out.text.chars().count() >= max_chars {
            out.truncated = true;
            break;
        }
        let before = lexer.at;
        let Some(object) = lexer.object(0) else {
            lexer.at = before + 1;
            continue;
        };
        if lexer.at == before {
            lexer.at += 1;
            continue;
        }

        let Object::Name(word) = &object else {
            stack.push(object);
            if stack.len() > 64 {
                stack.remove(0);
            }
            continue;
        };
        if data.get(before) == Some(&b'/') {
            stack.push(object.clone());
            if stack.len() > 64 {
                stack.remove(0);
            }
            continue;
        }

        let numbers: Vec<f64> = stack.iter().filter_map(Object::as_f64).collect();
        match word.as_str() {
            "BT" => {
                y = None;
                pending_break = !out.text.is_empty();
            }
            "Tf" => {
                if let Some(Object::Name(name)) = stack.first() {
                    font = fonts.get(name).unwrap_or(&fallback);
                }
            }
            "TL" => leading = numbers.last().copied().unwrap_or(leading),
            "Td" | "TD" => {
                if let Some(ty) = numbers.get(numbers.len().wrapping_sub(1)) {
                    if word == "TD" {
                        leading = -ty;
                    }
                    let next = y.unwrap_or(0.0) + ty;
                    pending_break |= moved_line(y, next);
                    y = Some(next);
                }
            }
            "Tm" => {
                if numbers.len() >= 6 {
                    let next = numbers[5];
                    pending_break |= moved_line(y, next);
                    y = Some(next);
                }
            }
            "T*" => {
                let next = y.unwrap_or(0.0) - leading;
                pending_break |= moved_line(y, next);
                y = Some(next);
            }
            "Tj" | "'" | "\"" => {
                if word != "Tj" {
                    let next = y.unwrap_or(0.0) - leading;
                    pending_break |= moved_line(y, next);
                    y = Some(next);
                }
                if let Some(Object::String(bytes)) = stack.last() {
                    let decoded = font.decode(bytes, &mut out.undecoded);
                    push(&mut out.text, &decoded, &mut pending_break, max_chars);
                }
            }
            "TJ" => {
                if let Some(Object::Array(items)) = stack.last() {
                    let mut piece = String::new();
                    for item in items {
                        match item {
                            Object::String(bytes) => {
                                piece.push_str(&font.decode(bytes, &mut out.undecoded));
                            }
                            Object::Number(n) if *n <= -WORD_GAP && !piece.ends_with(' ') => {
                                piece.push(' ');
                            }
                            _ => {}
                        }
                    }
                    push(&mut out.text, &piece, &mut pending_break, max_chars);
                }
            }
            _ => {}
        }
        stack.clear();
    }
    out
}

fn moved_line(from: Option<f64>, to: f64) -> bool {
    match from {
        Some(previous) => (previous - to).abs() > SAME_LINE,
        None => false,
    }
}

fn push(text: &mut String, piece: &str, pending_break: &mut bool, max_chars: usize) {
    if piece.is_empty() {
        return;
    }
    if *pending_break {
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        *pending_break = false;
    }
    for c in piece.chars() {
        if text.chars().count() >= max_chars {
            return;
        }
        text.push(c);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(content: &str) -> PageText {
        interpret(content.as_bytes(), &BTreeMap::new(), 10_000)
    }

    #[test]
    fn a_show_operator_yields_its_string() {
        assert_eq!(run("BT (hello) Tj ET").text, "hello");
    }

    #[test]
    fn an_array_show_joins_its_pieces() {
        assert_eq!(run("BT [(a) (b) (c)] TJ ET").text, "abc");
    }

    #[test]
    fn only_a_large_gap_in_an_array_becomes_a_space() {
        assert_eq!(run("BT [(one) -400 (two)] TJ ET").text, "one two");
        assert_eq!(run("BT [(on) -30 (e)] TJ ET").text, "one");
        let at = format!("BT [(a) {} (b)] TJ ET", -WORD_GAP);
        assert_eq!(run(&at).text, "a b");
        assert_eq!(run("BT [(a) 400 (b)] TJ ET").text, "ab");
        assert_eq!(run("BT [(a) -400 -400 (b)] TJ ET").text, "a b");
    }

    #[test]
    fn vertical_movement_between_shows_becomes_a_line_break() {
        assert_eq!(
            run("BT 0 700 Td (one) Tj 0 680 Td (two) Tj ET").text,
            "one\ntwo"
        );
        assert_eq!(
            run("BT 1 0 0 1 0 700 Tm (one) Tj 1 0 0 1 0 680 Tm (two) Tj ET").text,
            "one\ntwo"
        );
    }

    #[test]
    fn movement_smaller_than_a_line_does_not_break() {
        assert_eq!(run("BT 0 700 Td (a) Tj 0 0.5 Td (b) Tj ET").text, "ab");
        assert_eq!(run("BT 0 700 Td (a) Tj 0 -12 Td (b) Tj ET").text, "a\nb");
    }

    #[test]
    fn the_next_line_operators_move_by_the_leading() {
        assert_eq!(run("BT 14 TL 0 700 Td (a) Tj T* (b) Tj ET").text, "a\nb");
        assert_eq!(run("BT 0 700 Td (a) Tj 0 -14 TD (b) Tj ET").text, "a\nb");
        assert_eq!(run("BT 14 TL 0 700 Td (a) Tj (b) ' ET").text, "a\nb");
        assert_eq!(run("BT 14 TL 0 700 Td (a) Tj 1 2 (b) \" ET").text, "a\nb");
    }

    #[test]
    fn a_new_text_object_breaks_the_line() {
        assert_eq!(run("BT (a) Tj ET BT (b) Tj ET").text, "a\nb");
    }

    #[test]
    fn operators_that_are_not_about_text_are_stepped_over() {
        let text = run("q 1 0 0 1 0 0 cm /Cs1 cs 0 sc BT (kept) Tj ET Q 0 0 m 1 1 l S").text;
        assert_eq!(text, "kept");
    }

    #[test]
    fn an_empty_or_rubbish_stream_yields_nothing_rather_than_looping() {
        assert_eq!(run("").text, "");
        assert_eq!(run("]]]>>>)))").text, "");
        assert_eq!(run("BT ET").text, "");
    }

    #[test]
    fn the_character_bound_stops_the_interpreter_and_is_reported() {
        let got = interpret(b"BT (abcdefghij) Tj (more) Tj ET", &BTreeMap::new(), 4);
        assert_eq!(got.text, "abcd");
        assert!(got.truncated);
    }

    #[test]
    fn a_long_operand_run_does_not_grow_without_bound() {
        let many: String = (0..500).map(|n| format!("{n} ")).collect();
        let got = run(&format!("BT {many} (kept) Tj ET"));
        assert_eq!(got.text, "kept");
    }

    #[test]
    fn a_slash_name_operand_is_not_mistaken_for_an_operator() {
        assert_eq!(run("BT /Tj /ET (kept) Tj ET").text, "kept");
    }

    use super::super::document::{Document, Limits};

    fn doc_of(body: &str) -> Document {
        let data = format!("%PDF-1.7\n{body}\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n");
        Document::parse(data.as_bytes(), &Limits::default()).expect("a readable PDF")
    }

    fn first_page_text(d: &Document) -> PageText {
        let (pages, _) = d.pages().expect("pages");
        page_text(d, pages[0], 10_000)
    }

    #[test]
    fn a_page_resolves_its_fonts_and_shows_its_text() {
        let d = doc_of(
            "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n\
             2 0 obj\n<< /Type /Pages /Kids [3 0 R] >>\nendobj\n\
             3 0 obj\n<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 5 0 R >> >> \
             /Contents 4 0 R >>\nendobj\n\
             4 0 obj\n<< >>\nstream\nBT /F1 12 Tf (hello) Tj ET\nendstream\nendobj\n\
             5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n",
        );
        assert_eq!(first_page_text(&d).text, "hello");
    }

    #[test]
    fn a_contents_array_concatenates_its_streams() {
        let d = doc_of(
            "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n\
             2 0 obj\n<< /Type /Pages /Kids [3 0 R] >>\nendobj\n\
             3 0 obj\n<< /Type /Page /Parent 2 0 R /Contents [4 0 R 5 0 R] >>\nendobj\n\
             4 0 obj\n<< >>\nstream\nBT (one) Tj ET\nendstream\nendobj\n\
             5 0 obj\n<< >>\nstream\nBT (two) Tj ET\nendstream\nendobj\n",
        );
        let got = first_page_text(&d);
        assert!(got.text.contains("one"), "{:?}", got.text);
        assert!(got.text.contains("two"), "{:?}", got.text);
    }

    #[test]
    fn a_page_with_no_contents_yields_nothing_rather_than_failing() {
        let d = doc_of(
            "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n\
             2 0 obj\n<< /Type /Pages /Kids [3 0 R] >>\nendobj\n\
             3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n",
        );
        assert_eq!(first_page_text(&d).text, "");
    }

    #[test]
    fn a_page_with_no_resources_still_shows_its_text() {
        let d = doc_of(
            "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n\
             2 0 obj\n<< /Type /Pages /Kids [3 0 R] >>\nendobj\n\
             3 0 obj\n<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>\nendobj\n\
             4 0 obj\n<< >>\nstream\nBT (no font named) Tj ET\nendstream\nendobj\n",
        );
        assert_eq!(first_page_text(&d).text, "no font named");
    }

    #[test]
    fn a_font_reads_its_base_encoding_and_differences_from_a_dictionary() {
        let d = doc_of(
            "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n\
             2 0 obj\n<< /Type /Pages /Kids [3 0 R] >>\nendobj\n\
             3 0 obj\n<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 5 0 R >> >> \
             /Contents 4 0 R >>\nendobj\n\
             4 0 obj\n<< >>\nstream\nBT /F1 12 Tf (AB) Tj ET\nendstream\nendobj\n\
             5 0 obj\n<< /Type /Font /Subtype /Type1 /Encoding << /BaseEncoding \
             /WinAnsiEncoding /Differences [65 /emdash /bullet] >> >>\nendobj\n",
        );
        assert_eq!(first_page_text(&d).text, "—•");
    }

    #[test]
    fn a_font_reads_its_tounicode_stream() {
        let d = doc_of(
            "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n\
             2 0 obj\n<< /Type /Pages /Kids [3 0 R] >>\nendobj\n\
             3 0 obj\n<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 5 0 R >> >> \
             /Contents 4 0 R >>\nendobj\n\
             4 0 obj\n<< >>\nstream\nBT /F1 12 Tf <00010002> Tj ET\nendstream\nendobj\n\
             5 0 obj\n<< /Type /Font /Subtype /Type0 /ToUnicode 6 0 R >>\nendobj\n\
             6 0 obj\n<< >>\nstream\n2 beginbfchar <0001> <0048> <0002> <0069> \
             endbfchar\nendstream\nendobj\n",
        );
        assert_eq!(first_page_text(&d).text, "Hi");
    }

    #[test]
    fn naming_an_unknown_font_falls_back_to_a_simple_one() {
        let d = doc_of(
            "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n\
             2 0 obj\n<< /Type /Pages /Kids [3 0 R] >>\nendobj\n\
             3 0 obj\n<< /Type /Page /Parent 2 0 R /Resources << /Font << >> >> \
             /Contents 4 0 R >>\nendobj\n\
             4 0 obj\n<< >>\nstream\nBT /Missing 12 Tf (kept) Tj ET\nendstream\nendobj\n",
        );
        assert_eq!(first_page_text(&d).text, "kept");
    }

    #[test]
    fn a_font_entry_that_is_not_a_dictionary_is_skipped() {
        let d = doc_of(
            "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n\
             2 0 obj\n<< /Type /Pages /Kids [3 0 R] >>\nendobj\n\
             3 0 obj\n<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 42 >> >> \
             /Contents 4 0 R >>\nendobj\n\
             4 0 obj\n<< >>\nstream\nBT /F1 12 Tf (kept) Tj ET\nendstream\nendobj\n",
        );
        assert_eq!(first_page_text(&d).text, "kept");
    }

    #[test]
    fn a_font_with_no_cmap_decodes_through_its_encoding() {
        let font = Font::simple();
        let mut undecoded = 0;
        assert_eq!(font.decode(b"Hello", &mut undecoded), "Hello");
        assert_eq!(undecoded, 0);
    }

    #[test]
    fn a_bfchar_cmap_maps_single_codes() {
        let cmap =
            parse_cmap(b"begincmap 2 beginbfchar <0001> <0041> <0002> <0042> endbfchar endcmap");
        assert_eq!(cmap.get(&1).map(String::as_str), Some("A"));
        assert_eq!(cmap.get(&2).map(String::as_str), Some("B"));
        assert_eq!(cmap.get(&3), None);
    }

    #[test]
    fn a_bfrange_cmap_maps_a_run_and_an_explicit_list() {
        let cmap = parse_cmap(
            b"1 beginbfrange <0010> <0012> <0041> endbfrange \
              1 beginbfrange <0020> <0021> [<0061> <0062>] endbfrange",
        );
        assert_eq!(cmap.get(&0x10).map(String::as_str), Some("A"));
        assert_eq!(cmap.get(&0x11).map(String::as_str), Some("B"));
        assert_eq!(cmap.get(&0x12).map(String::as_str), Some("C"));
        assert_eq!(cmap.get(&0x20).map(String::as_str), Some("a"));
        assert_eq!(cmap.get(&0x21).map(String::as_str), Some("b"));
    }

    #[test]
    fn an_absurdly_wide_bfrange_is_skipped() {
        let cmap = parse_cmap(b"1 beginbfrange <00000000> <FFFFFFFF> <0041> endbfrange");
        assert!(cmap.len() < 70_000, "{} entries", cmap.len());
        let backwards = parse_cmap(b"1 beginbfrange <0050> <0010> <0041> endbfrange");
        assert!(backwards.is_empty());
    }

    #[test]
    fn a_cmap_destination_may_be_several_code_units() {
        let cmap = parse_cmap(b"1 beginbfchar <0001> <00660069> endbfchar");
        assert_eq!(cmap.get(&1).map(String::as_str), Some("fi"));
    }

    #[test]
    fn a_malformed_cmap_yields_what_it_can_rather_than_nothing() {
        for text in [
            &b"beginbfchar"[..],
            b"1 beginbfchar <0001> endbfchar",
            b"1 beginbfrange <0001>",
            b"garbage ) ] >",
            b"",
        ] {
            let _ = parse_cmap(text);
        }
        let cmap = parse_cmap(b"2 beginbfchar <0001> <0041> <0002> endbfchar");
        assert_eq!(cmap.get(&1).map(String::as_str), Some("A"));
    }

    #[test]
    fn a_two_byte_font_with_no_cmap_counts_its_codes_as_undecoded() {
        let font = Font {
            to_unicode: BTreeMap::new(),
            encoding: Encoding::default(),
            two_byte: true,
        };
        let mut undecoded = 0;
        assert_eq!(font.decode(&[0x00, 0x01, 0x00, 0x02], &mut undecoded), "");
        assert_eq!(undecoded, 2);
    }

    #[test]
    fn a_two_byte_font_with_a_cmap_decodes_pairs() {
        let mut to_unicode = BTreeMap::new();
        to_unicode.insert(1u32, "H".to_string());
        to_unicode.insert(2u32, "i".to_string());
        let font = Font {
            to_unicode,
            encoding: Encoding::default(),
            two_byte: true,
        };
        let mut undecoded = 0;
        assert_eq!(font.decode(&[0, 1, 0, 2], &mut undecoded), "Hi");
        assert_eq!(undecoded, 0);
        let mut odd = 0;
        assert_eq!(font.decode(&[0, 1, 1], &mut odd), "H");
        assert_eq!(odd, 1);
    }

    #[test]
    fn a_code_the_encoding_does_not_define_is_counted_not_emitted() {
        let mut encoding = Encoding::base(None);
        encoding.apply_differences(&[
            super::super::object::Object::Number(65.0),
            super::super::object::Object::Name("notaglyph".into()),
        ]);
        let font = Font {
            to_unicode: BTreeMap::new(),
            encoding,
            two_byte: false,
        };
        let mut undecoded = 0;
        assert_eq!(font.decode(b"ABC", &mut undecoded), "BC");
        assert_eq!(undecoded, 1);
    }

    #[test]
    fn a_cmap_entry_beats_the_encoding_for_the_same_code() {
        let mut to_unicode = BTreeMap::new();
        to_unicode.insert(u32::from(b'A'), "\u{2713}".to_string());
        let font = Font {
            to_unicode,
            encoding: Encoding::default(),
            two_byte: false,
        };
        let mut undecoded = 0;
        assert_eq!(font.decode(b"AB", &mut undecoded), "\u{2713}B");
    }

    #[test]
    fn malformed_cmaps_take_every_skip_path() {
        for text in [
            &b"1 beginbfchar <0001> <0041>"[..],
            b"1 beginbfrange <0001> <0002>",
            b"1 beginbfchar /Name /Other endbfchar",
            b"1 beginbfchar 1 2 endbfchar",
            b"1 beginbfrange /A /B /C endbfrange",
            b"1 beginbfrange 1 2 3 endbfrange",
            b"1 beginbfrange <0001> <0002> 7 endbfrange",
            b"1 beginbfchar <0102030405> <0041> endbfchar",
            b"1 beginbfrange <0102030405> <0002> <0041> endbfrange",
            b"1 beginbfrange <0001> <0003> <> endbfrange",
            b"1 beginbfchar endbfchar",
            b"1 beginbfrange endbfrange",
            b") ] >> 1 beginbfchar <0001> <0041> endbfchar ) ] >>",
            b"0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 \
              26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 \
              49 50 51 52 53 54 55 56 57 58 59 60 61 62 63 64 65 66 67 68 69 70",
        ] {
            let _ = parse_cmap(text);
        }
        let cmap = parse_cmap(b") ] 1 beginbfchar <0001> <0041> endbfchar >> )");
        assert_eq!(cmap.get(&1).map(String::as_str), Some("A"));
    }

    #[test]
    fn malformed_content_streams_take_every_skip_path() {
        for text in [
            ") ] >> } (kept) Tj",
            "BT (a) Tj",
            "BT [",
            "BT [(a)",
            "<< /A 1 >> (kept) Tj",
            "Tj TJ T* ' \" BT ET Tf TL Td TD Tm",
            "BT Tf Td TD Tm TJ Tj ET",
            &(0..200).map(|n| format!("{n} ")).collect::<String>(),
        ] {
            let _ = interpret(text.as_bytes(), &BTreeMap::new(), 1000);
        }
        assert_eq!(
            interpret(b"BT 5 Tf (kept) Tj ET", &BTreeMap::new(), 100).text,
            "kept"
        );
        assert_eq!(interpret(b"BT (x) TJ ET", &BTreeMap::new(), 100).text, "");
        assert_eq!(
            interpret(b"BT 1 2 Tm (a) Tj 1 2 Tm (b) Tj ET", &BTreeMap::new(), 100).text,
            "ab"
        );
    }

    #[test]
    fn arbitrary_bytes_never_panic_either_parser() {
        let mut state: u64 = 0xC0FFEE123;
        let mut next = move || {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            state = state.wrapping_mul(0x2545F4914F6CDD1D);
            state
        };
        let pieces = [
            "BT",
            "ET",
            "Tj",
            "TJ",
            "Tf",
            "Td",
            "TD",
            "Tm",
            "T*",
            "TL",
            "'",
            "\"",
            "(abc)",
            "<0041>",
            "[",
            "]",
            "<<",
            ">>",
            "/F1",
            "-400",
            "12",
            "0",
            "beginbfchar",
            "endbfchar",
            "beginbfrange",
            "endbfrange",
            ")",
            "%",
        ];
        for _ in 0..600 {
            let count = 1 + (next() % 24) as usize;
            let text: String = (0..count)
                .map(|_| pieces[(next() as usize) % pieces.len()])
                .collect::<Vec<_>>()
                .join(" ");
            let _ = interpret(text.as_bytes(), &BTreeMap::new(), 500);
            let _ = parse_cmap(text.as_bytes());
        }
    }

    #[test]
    fn a_code_is_read_big_endian_at_every_width() {
        assert_eq!(be_code(&[0x41]), Some(0x41));
        assert_eq!(be_code(&[0x00, 0x41]), Some(0x41));
        assert_eq!(be_code(&[0x01, 0x02, 0x03, 0x04]), Some(0x0102_0304));
        assert_eq!(be_code(&[]), None);
        assert_eq!(be_code(&[0; 5]), None);
    }

    #[test]
    fn a_destination_is_utf16_big_endian_with_the_rubbish_dropped() {
        assert_eq!(utf16be(&[0x00, 0x41]), "A");
        assert_eq!(utf16be(&[0x20, 0xAC]), "€");
        assert_eq!(utf16be(&[0xD8, 0x3D, 0xDE, 0x00]), "\u{1F600}");
        assert_eq!(utf16be(&[0xD8, 0x00]), "");
        assert_eq!(utf16be(&[0x00, 0x00]), "");
        assert_eq!(utf16be(&[]), "");
    }
}
