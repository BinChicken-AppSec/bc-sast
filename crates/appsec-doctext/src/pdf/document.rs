use std::collections::{BTreeMap, BTreeSet};

use super::encoding;
use super::object::{Dict, Lexer, Object};
use crate::inflate::inflate;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    pub max_objects: usize,
    pub max_pages: usize,
    pub max_stream_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_objects: 50_000,
            max_pages: 2_000,
            max_stream_bytes: 32 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PdfError {
    NotAPdf,
    Encrypted,
    NoPages,
    TooMany { what: &'static str, limit: usize },
    NoTextFound { pages: usize },
}

impl std::fmt::Display for PdfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAPdf => write!(f, "this does not begin with a %PDF- header"),
            Self::Encrypted => write!(
                f,
                "the PDF is encrypted; decryption is not supported, so export \
                 an unprotected copy instead"
            ),
            Self::NoPages => write!(f, "no page objects were found"),
            Self::TooMany { what, limit } => {
                write!(f, "the PDF declares more than {limit} {what}")
            }
            Self::NoTextFound { pages } => write!(
                f,
                "{pages} page(s) were read but none contained extractable text; \
                 a scanned document is an image of text and holds none"
            ),
        }
    }
}

impl std::error::Error for PdfError {}

pub struct Document {
    objects: BTreeMap<u32, Object>,
    limits: Limits,
}

impl Document {
    pub fn parse(data: &[u8], limits: &Limits) -> Result<Self, PdfError> {
        let window = &data[..data.len().min(1024)];
        if !window.windows(5).any(|w| w == b"%PDF-") {
            return Err(PdfError::NotAPdf);
        }
        if is_encrypted(data) {
            return Err(PdfError::Encrypted);
        }

        let mut doc = Self {
            objects: BTreeMap::new(),
            limits: limits.clone(),
        };
        doc.scan(data)?;
        if doc.declares_encryption() {
            return Err(PdfError::Encrypted);
        }
        doc.expand_object_streams()?;
        Ok(doc)
    }

    fn scan(&mut self, data: &[u8]) -> Result<(), PdfError> {
        let mut at = 0usize;
        while let Some(found) = find(data, b"obj", at) {
            at = found + 3;
            let Some((number, _generation)) = object_header(data, found) else {
                continue;
            };
            if self.objects.len() >= self.limits.max_objects {
                return Err(PdfError::TooMany {
                    what: "objects",
                    limit: self.limits.max_objects,
                });
            }
            let mut lexer = Lexer::at(data, found + 3);
            let Some(object) = lexer.object(0) else {
                continue;
            };
            let object = match object {
                Object::Dict(dict) => match self.read_stream(data, &mut lexer, dict) {
                    (dict, Some(raw)) => Object::Stream { dict, data: raw },
                    (dict, None) => Object::Dict(dict),
                },
                other => other,
            };
            self.objects.insert(number, object);
            at = lexer.at.max(at);
        }
        Ok(())
    }

    fn read_stream(
        &self,
        data: &[u8],
        lexer: &mut Lexer<'_>,
        dict: Dict,
    ) -> (Dict, Option<Vec<u8>>) {
        let save = lexer.at;
        lexer.skip_space();
        if !data[lexer.at..].starts_with(b"stream") {
            lexer.at = save;
            return (dict, None);
        }
        lexer.at += 6;
        if data.get(lexer.at) == Some(&b'\r') {
            lexer.at += 1;
        }
        if data.get(lexer.at) == Some(&b'\n') {
            lexer.at += 1;
        }
        let start = lexer.at;

        let declared = dict.get("Length").and_then(Object::as_f64);
        let end = declared
            .filter(|n| *n >= 0.0 && n.is_finite())
            .map(|n| start + n as usize)
            .filter(|e| *e <= data.len() && looks_like_endstream(data, *e))
            .or_else(|| find(data, b"endstream", start))
            .unwrap_or(data.len());

        let mut end = end.min(data.len());
        if end > start && data.get(end - 1) == Some(&b'\n') {
            end -= 1;
        }
        if end > start && data.get(end - 1) == Some(&b'\r') {
            end -= 1;
        }
        lexer.at = find(data, b"endstream", end).map_or(data.len(), |e| e + 9);
        (dict, Some(data[start..end].to_vec()))
    }

    fn expand_object_streams(&mut self) -> Result<(), PdfError> {
        let streams: Vec<u32> = self
            .objects
            .iter()
            .filter(|(_, o)| {
                o.as_dict()
                    .and_then(|d| d.get("Type"))
                    .and_then(Object::as_name)
                    == Some("ObjStm")
            })
            .map(|(n, _)| *n)
            .collect();

        let mut recovered: Vec<(u32, Object)> = Vec::new();
        for number in streams {
            let Some(object) = self.objects.get(&number) else {
                continue;
            };
            let Some(dict) = object.as_dict().cloned() else {
                continue;
            };
            let Some(data) = self.stream_data(object) else {
                continue;
            };
            let count = dict.get("N").and_then(Object::as_f64).unwrap_or(0.0);
            let first = dict.get("First").and_then(Object::as_f64).unwrap_or(0.0);
            if !(0.0..=100_000.0).contains(&count) || first < 0.0 {
                continue;
            }
            let first = first as usize;
            if first > data.len() {
                continue;
            }
            let mut head = Lexer::new(&data[..first]);
            for _ in 0..count as usize {
                let (Some(num), Some(offset)) = (head.keyword(), head.keyword()) else {
                    break;
                };
                let Ok(num) = std::str::from_utf8(num).unwrap_or("x").parse::<u32>() else {
                    continue;
                };
                let Ok(offset) = std::str::from_utf8(offset).unwrap_or("x").parse::<usize>() else {
                    continue;
                };
                let Some(at) = first.checked_add(offset).filter(|a| *a < data.len()) else {
                    continue;
                };
                let mut body = Lexer::at(&data, at);
                if let Some(parsed) = body.object(0) {
                    recovered.push((num, parsed));
                }
            }
        }
        for (number, object) in recovered {
            self.objects.entry(number).or_insert(object);
            if self.objects.len() > self.limits.max_objects {
                return Err(PdfError::TooMany {
                    what: "objects",
                    limit: self.limits.max_objects,
                });
            }
        }
        Ok(())
    }

    fn declares_encryption(&self) -> bool {
        self.objects.values().filter_map(Object::as_dict).any(|d| {
            d.get("Type").and_then(Object::as_name) == Some("XRef") && d.contains_key("Encrypt")
        })
    }

    pub fn get(&self, number: u32) -> Option<&Object> {
        self.objects.get(&number)
    }

    pub fn len(&self) -> usize {
        self.objects.len()
    }

    pub fn is_empty(&self) -> bool {
        self.objects.is_empty()
    }

    pub fn resolve<'a>(&'a self, object: &'a Object) -> &'a Object {
        match object.as_reference() {
            Some((number, _)) => self.get(number).unwrap_or(&Object::Null),
            None => object,
        }
    }

    pub fn entry<'a>(&'a self, dict: &'a Dict, key: &str) -> Option<&'a Object> {
        dict.get(key).map(|o| self.resolve(o))
    }

    pub fn stream_data(&self, object: &Object) -> Option<Vec<u8>> {
        let Object::Stream { dict, data } = object else {
            return None;
        };
        let mut bytes = data.clone();
        for filter in self.filters(dict) {
            bytes = match filter.as_str() {
                "FlateDecode" | "Fl" => inflate(&bytes, self.limits.max_stream_bytes)
                    .ok()
                    .or_else(|| {
                        bytes
                            .len()
                            .gt(&2)
                            .then(|| inflate(&bytes[2..], self.limits.max_stream_bytes).ok())
                            .flatten()
                    })?,
                "ASCIIHexDecode" | "AHx" => ascii_hex_decode(&bytes),
                "ASCII85Decode" | "A85" => ascii85_decode(&bytes),
                _ => return None,
            };
            if bytes.len() > self.limits.max_stream_bytes {
                return None;
            }
        }
        Some(apply_predictor(bytes, self.predictor(dict)))
    }

    fn filters(&self, dict: &Dict) -> Vec<String> {
        match dict.get("Filter").map(|f| self.resolve(f)) {
            Some(Object::Name(n)) => vec![n.clone()],
            Some(Object::Array(a)) => a
                .iter()
                .filter_map(|o| self.resolve(o).as_name().map(str::to_owned))
                .collect(),
            _ => Vec::new(),
        }
    }

    fn predictor(&self, dict: &Dict) -> Option<(usize, usize)> {
        let parms = match dict.get("DecodeParms").map(|p| self.resolve(p)) {
            Some(Object::Dict(d)) => d.clone(),
            Some(Object::Array(a)) => a
                .iter()
                .filter_map(|o| self.resolve(o).as_dict().cloned())
                .next_back()?,
            _ => return None,
        };
        let predictor = self.entry(&parms, "Predictor")?.as_f64()? as usize;
        if predictor < 10 {
            return None;
        }
        let columns = self
            .entry(&parms, "Columns")
            .and_then(Object::as_f64)
            .unwrap_or(1.0) as usize;
        let colors = self
            .entry(&parms, "Colors")
            .and_then(Object::as_f64)
            .unwrap_or(1.0) as usize;
        Some((columns.max(1), colors.max(1)))
    }

    pub fn pages(&self) -> Result<(Vec<&Dict>, bool), PdfError> {
        let mut out = Vec::new();
        if let Some(root) = self.catalog() {
            let mut seen = BTreeSet::new();
            if let Some(pages) = self.entry(root, "Pages") {
                self.walk_pages(pages, &mut seen, &mut out, 0);
            }
        }
        if out.is_empty() {
            out = self
                .objects
                .values()
                .filter(|o| {
                    o.as_dict()
                        .and_then(|d| d.get("Type"))
                        .and_then(Object::as_name)
                        == Some("Page")
                })
                .filter_map(Object::as_dict)
                .collect();
        }
        if out.is_empty() {
            return Err(PdfError::NoPages);
        }
        let truncated = out.len() > self.limits.max_pages;
        out.truncate(self.limits.max_pages);
        Ok((out, truncated))
    }

    fn catalog(&self) -> Option<&Dict> {
        self.objects
            .values()
            .filter_map(Object::as_dict)
            .find(|d| d.get("Type").and_then(Object::as_name) == Some("Catalog"))
    }

    fn walk_pages<'a>(
        &'a self,
        node: &'a Object,
        seen: &mut BTreeSet<u32>,
        out: &mut Vec<&'a Dict>,
        depth: usize,
    ) {
        if depth > 64 || out.len() > self.limits.max_pages {
            return;
        }
        let Some(dict) = node.as_dict() else { return };
        match dict.get("Type").and_then(Object::as_name) {
            Some("Page") => out.push(dict),
            _ => {
                let Some(Object::Array(kids)) = self.entry(dict, "Kids") else {
                    if dict.contains_key("Contents") {
                        out.push(dict);
                    }
                    return;
                };
                for kid in kids {
                    if let Some((number, _)) = kid.as_reference() {
                        if !seen.insert(number) {
                            continue;
                        }
                    }
                    self.walk_pages(self.resolve(kid), seen, out, depth + 1);
                }
            }
        }
    }

    pub fn inherited<'a>(&'a self, page: &'a Dict, key: &str) -> Option<&'a Object> {
        let mut node = page;
        for _ in 0..64 {
            if let Some(found) = self.entry(node, key) {
                if !matches!(found, Object::Null) {
                    return Some(found);
                }
            }
            node = self.entry(node, "Parent")?.as_dict()?;
        }
        None
    }
}

fn is_encrypted(data: &[u8]) -> bool {
    let mut at = 0usize;
    while let Some(found) = find(data, b"trailer", at) {
        at = found + 7;
        let mut lexer = Lexer::at(data, at);
        lexer.skip_space();
        if let Some(dict) = lexer.dictionary(0) {
            if dict.contains_key("Encrypt") {
                return true;
            }
        }
    }
    false
}

fn object_header(data: &[u8], obj_at: usize) -> Option<(u32, u16)> {
    let mut at = obj_at;
    let back = |at: &mut usize| -> Option<u64> {
        while *at > 0 && super::object::is_white(data[*at - 1]) {
            *at -= 1;
        }
        let end = *at;
        while *at > 0 && data[*at - 1].is_ascii_digit() {
            *at -= 1;
        }
        if *at == end {
            return None;
        }
        std::str::from_utf8(&data[*at..end])
            .ok()?
            .parse::<u64>()
            .ok()
    };
    let generation = back(&mut at)?;
    let number = back(&mut at)?;
    if at > 0
        && !super::object::is_white(data[at - 1])
        && !super::object::is_delimiter(data[at - 1])
    {
        return None;
    }
    Some((u32::try_from(number).ok()?, u16::try_from(generation).ok()?))
}

fn looks_like_endstream(data: &[u8], at: usize) -> bool {
    let window = &data[at..data.len().min(at + 20)];
    window
        .iter()
        .position(|b| !super::object::is_white(*b))
        .is_some_and(|skip| window[skip..].starts_with(b"endstream"))
}

pub fn find(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if from >= haystack.len() || needle.is_empty() {
        return None;
    }
    haystack[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|i| i + from)
}

fn ascii_hex_decode(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut half: Option<u8> = None;
    for &b in data {
        if b == b'>' {
            break;
        }
        let Some(v) = encoding_hex(b) else { continue };
        match half.take() {
            Some(hi) => out.push(hi * 16 + v),
            None => half = Some(v),
        }
    }
    if let Some(hi) = half {
        out.push(hi * 16);
    }
    out
}

fn encoding_hex(b: u8) -> Option<u8> {
    super::object::hex_value(b)
}

fn ascii85_decode(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut group = [0u8; 5];
    let mut count = 0usize;
    let mut at = 0usize;
    if data.starts_with(b"<~") {
        at = 2;
    }
    while at < data.len() {
        let b = data[at];
        at += 1;
        if b == b'~' {
            break;
        }
        if super::object::is_white(b) {
            continue;
        }
        if b == b'z' && count == 0 {
            out.extend_from_slice(&[0, 0, 0, 0]);
            continue;
        }
        if !(b'!'..=b'u').contains(&b) {
            continue;
        }
        group[count] = b - b'!';
        count += 1;
        if count == 5 {
            let mut value = 0u32;
            for g in group {
                value = value.wrapping_mul(85).wrapping_add(u32::from(g));
            }
            out.extend_from_slice(&value.to_be_bytes());
            count = 0;
        }
    }
    if count > 1 {
        for slot in group.iter_mut().skip(count) {
            *slot = 84;
        }
        let mut value = 0u32;
        for g in group {
            value = value.wrapping_mul(85).wrapping_add(u32::from(g));
        }
        out.extend_from_slice(&value.to_be_bytes()[..count - 1]);
    }
    out
}

fn apply_predictor(data: Vec<u8>, settings: Option<(usize, usize)>) -> Vec<u8> {
    let Some((columns, colors)) = settings else {
        return data;
    };
    let row_len = columns.saturating_mul(colors);
    if row_len == 0 {
        return data;
    }
    let stride = row_len + 1;
    let mut out: Vec<u8> = Vec::with_capacity(data.len());
    let mut previous = vec![0u8; row_len];
    for chunk in data.chunks(stride) {
        if chunk.len() < 2 {
            break;
        }
        let tag = chunk[0];
        let mut row = chunk[1..].to_vec();
        row.resize(row_len, 0);
        for i in 0..row_len {
            let left = if i >= colors { row[i - colors] } else { 0 };
            let up = previous[i];
            let up_left = if i >= colors { previous[i - colors] } else { 0 };
            row[i] = match tag {
                1 => row[i].wrapping_add(left),
                2 => row[i].wrapping_add(up),
                3 => row[i].wrapping_add(((u16::from(left) + u16::from(up)) / 2) as u8),
                4 => row[i].wrapping_add(paeth(left, up, up_left)),
                _ => row[i],
            };
        }
        out.extend_from_slice(&row);
        previous = row;
    }
    out
}

fn paeth(a: u8, b: u8, c: u8) -> u8 {
    let p = i16::from(a) + i16::from(b) - i16::from(c);
    let (pa, pb, pc) = (
        (p - i16::from(a)).abs(),
        (p - i16::from(b)).abs(),
        (p - i16::from(c)).abs(),
    );
    if pa <= pb && pa <= pc {
        a
    } else if pb <= pc {
        b
    } else {
        c
    }
}

pub use encoding::Encoding;

#[cfg(test)]
mod tests {
    use super::*;

    fn pdf(body: &str) -> Vec<u8> {
        format!("%PDF-1.7\n{body}\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n").into_bytes()
    }

    fn doc(body: &str) -> Document {
        Document::parse(&pdf(body), &Limits::default()).expect("a readable PDF")
    }

    const ONE_PAGE: &str = "\
1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n\
2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n\
3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n";

    #[test]
    fn objects_are_found_by_scanning_rather_than_through_an_index() {
        let d = doc(ONE_PAGE);
        assert_eq!(d.len(), 3);
        assert!(!d.is_empty());
        assert!(d.get(1).is_some());
        assert!(d.get(99).is_none());
    }

    #[test]
    fn a_later_definition_of_the_same_object_wins() {
        let d = doc("1 0 obj\n<< /Version 1 >>\nendobj\n\
             1 0 obj\n<< /Version 2 >>\nendobj\n");
        assert_eq!(
            d.get(1)
                .and_then(Object::as_dict)
                .and_then(|x| x.get("Version"))
                .and_then(Object::as_f64),
            Some(2.0)
        );
    }

    #[test]
    fn the_word_obj_inside_something_else_is_not_an_object_header() {
        let d = doc("1 0 obj\n<< /Note (endobj and objstm) >>\nendobj\n");
        assert_eq!(d.len(), 1);
        let d = Document::parse(&pdf("obj\n<< /A 1 >>\nendobj\n"), &Limits::default());
        assert_eq!(d.expect("parses").len(), 0);
        let d = doc("x12 0 obj\n<< /A 1 >>\nendobj\n");
        assert_eq!(d.len(), 0);
    }

    #[test]
    fn a_header_may_be_preceded_by_junk_but_must_exist() {
        let mut data = b"leading rubbish\n".to_vec();
        data.extend_from_slice(&pdf(ONE_PAGE));
        assert!(Document::parse(&data, &Limits::default()).is_ok());
        assert_eq!(
            Document::parse(b"no header here", &Limits::default()).map(|_| ()),
            Err(PdfError::NotAPdf)
        );
        let mut late = vec![b' '; 2000];
        late.extend_from_slice(&pdf(ONE_PAGE));
        assert_eq!(
            Document::parse(&late, &Limits::default()).map(|_| ()),
            Err(PdfError::NotAPdf)
        );
    }

    #[test]
    fn the_object_cap_is_enforced() {
        let body: String = (1..=50)
            .map(|n| format!("{n} 0 obj\n<< >>\nendobj\n"))
            .collect();
        let limits = Limits {
            max_objects: 10,
            ..Limits::default()
        };
        assert_eq!(
            Document::parse(&pdf(&body), &limits).map(|_| ()),
            Err(PdfError::TooMany {
                what: "objects",
                limit: 10
            })
        );
    }

    #[test]
    fn an_uncompressed_stream_reads_back() {
        let d = doc("1 0 obj\n<< /Length 5 >>\nstream\nhello\nendstream\nendobj\n");
        let got = d.stream_data(d.get(1).expect("the object"));
        assert_eq!(got, Some(b"hello".to_vec()));
    }

    #[test]
    fn a_wrong_length_falls_back_to_finding_endstream() {
        for length in ["0", "99999", "-4"] {
            let d = doc(&format!(
                "1 0 obj\n<< /Length {length} >>\nstream\nhello\nendstream\nendobj\n"
            ));
            assert_eq!(
                d.stream_data(d.get(1).expect("the object")),
                Some(b"hello".to_vec()),
                "length {length}"
            );
        }
    }

    #[test]
    fn an_ascii_hex_filter_decodes() {
        let d = doc("1 0 obj\n<< /Filter /ASCIIHexDecode >>\nstream\n48656c>\nendstream\nendobj\n");
        assert_eq!(
            d.stream_data(d.get(1).expect("the object")),
            Some(b"Hel".to_vec())
        );
    }

    #[test]
    fn an_ascii85_filter_decodes_including_its_short_forms() {
        for (encoded, expected) in [
            ("87cURD_*#4DfTZ)+T", "Hello, World!"),
            ("5l", "A"),
            ("5sb", "AB"),
            ("5sdp", "ABC"),
        ] {
            let d = doc(&format!(
                "1 0 obj\n<< /Filter /ASCII85Decode >>\nstream\n{encoded}~>\nendstream\nendobj\n"
            ));
            assert_eq!(
                d.stream_data(d.get(1).expect("the object")),
                Some(expected.as_bytes().to_vec()),
                "{encoded}"
            );
        }
        let d = doc("1 0 obj\n<< /Filter /ASCII85Decode >>\nstream\n<~z~>\nendstream\nendobj\n");
        assert_eq!(
            d.stream_data(d.get(1).expect("the object")),
            Some(vec![0, 0, 0, 0])
        );
    }

    #[test]
    fn an_unsupported_filter_yields_nothing_rather_than_rubbish() {
        for filter in ["DCTDecode", "LZWDecode", "CCITTFaxDecode", "JPXDecode"] {
            let d = doc(&format!(
                "1 0 obj\n<< /Filter /{filter} >>\nstream\nxx\nendstream\nendobj\n"
            ));
            assert_eq!(
                d.stream_data(d.get(1).expect("the object")),
                None,
                "{filter}"
            );
        }
    }

    #[test]
    fn a_filter_array_chains_in_order() {
        let d =
            doc("1 0 obj\n<< /Filter [/ASCIIHexDecode] >>\nstream\n48656c>\nendstream\nendobj\n");
        assert_eq!(
            d.stream_data(d.get(1).expect("the object")),
            Some(b"Hel".to_vec())
        );
    }

    #[test]
    fn a_non_stream_object_has_no_stream_data() {
        let d = doc("1 0 obj\n<< /A 1 >>\nendobj\n");
        assert_eq!(d.stream_data(d.get(1).expect("the object")), None);
        assert_eq!(d.stream_data(&Object::Null), None);
    }

    #[test]
    fn a_stream_past_the_byte_bound_is_refused() {
        let limits = Limits {
            max_stream_bytes: 2,
            ..Limits::default()
        };
        let data =
            pdf("1 0 obj\n<< /Filter /ASCIIHexDecode >>\nstream\n48656c>\nendstream\nendobj\n");
        let d = Document::parse(&data, &limits).expect("parses");
        assert_eq!(d.stream_data(d.get(1).expect("the object")), None);
    }

    #[test]
    fn a_png_predictor_is_undone() {
        let raw: Vec<u8> = vec![2, 1, 2, 3, 2, 1, 2, 3];
        let decoded = apply_predictor(raw, Some((3, 1)));
        assert_eq!(decoded, vec![1, 2, 3, 2, 4, 6]);
        assert_eq!(apply_predictor(vec![9, 9], None), vec![9, 9]);
        assert_eq!(apply_predictor(vec![1, 2], Some((0, 0))), vec![1, 2]);
    }

    #[test]
    fn every_png_filter_tag_is_handled() {
        for tag in 0u8..=4 {
            let raw = vec![tag, 10, 20, 30];
            let got = apply_predictor(raw, Some((3, 1)));
            assert_eq!(got.len(), 3, "tag {tag}");
        }
        assert_eq!(paeth(1, 2, 3), 1);
        assert_eq!(paeth(10, 2, 3), 10);
        assert_eq!(paeth(2, 10, 3), 10);
    }

    fn with_objstm(entries: &[(u32, &str)]) -> Vec<u8> {
        let mut head = String::new();
        let mut bodies = String::new();
        for (num, body) in entries {
            head.push_str(&format!("{num} {} ", bodies.len()));
            bodies.push_str(body);
            bodies.push(' ');
        }
        let payload = format!("{head}{bodies}");
        pdf(&format!(
            "9 0 obj\n<< /Type /ObjStm /N {} /First {} /Length {} >>\nstream\n{payload}\nendstream\nendobj\n",
            entries.len(),
            head.len(),
            payload.len(),
        ))
    }

    #[test]
    fn objects_inside_an_object_stream_are_recovered() {
        let data = with_objstm(&[
            (1, "<< /Type /Catalog /Pages 2 0 R >>"),
            (2, "<< /Type /Pages /Kids [3 0 R] >>"),
            (3, "<< /Type /Page >>"),
        ]);
        let d = Document::parse(&data, &Limits::default()).expect("parses");
        assert!(d.get(1).is_some());
        assert_eq!(d.pages().expect("pages").0.len(), 1);
    }

    #[test]
    fn a_top_level_object_beats_one_inside_a_stream() {
        let mut data = with_objstm(&[(1, "<< /From (stream) >>")]);
        let extra = b"1 0 obj\n<< /From (top) >>\nendobj\n";
        let at = data
            .windows(7)
            .position(|w| w == b"trailer")
            .expect("a trailer");
        data.splice(at..at, extra.iter().copied());
        let d = Document::parse(&data, &Limits::default()).expect("parses");
        let from = d
            .get(1)
            .and_then(Object::as_dict)
            .and_then(|x| x.get("From"))
            .cloned();
        assert_eq!(from, Some(Object::String(b"top".to_vec())));
    }

    #[test]
    fn a_malformed_object_stream_is_skipped_rather_than_fatal() {
        for header in [
            "/Type /ObjStm /N -1 /First 0",
            "/Type /ObjStm /N 999999999 /First 0",
            "/Type /ObjStm /N 2 /First 99999",
            "/Type /ObjStm /N 2",
            "/Type /ObjStm",
        ] {
            let data = pdf(&format!(
                "9 0 obj\n<< {header} >>\nstream\n1 0 << /A 1 >>\nendstream\nendobj\n\
                 1 0 obj\n<< /Type /Page >>\nendobj\n"
            ));
            let d = Document::parse(&data, &Limits::default()).expect("parses");
            assert_eq!(d.pages().expect("pages").0.len(), 1, "{header}");
        }
    }

    #[test]
    fn an_object_stream_with_rubbish_in_its_head_is_skipped() {
        let payload = "x y z  << /A 1 >>";
        let data = pdf(&format!(
            "9 0 obj\n<< /Type /ObjStm /N 2 /First 7 /Length {} >>\nstream\n{payload}\nendstream\nendobj\n\
             1 0 obj\n<< /Type /Page >>\nendobj\n",
            payload.len()
        ));
        let d = Document::parse(&data, &Limits::default()).expect("parses");
        assert_eq!(d.pages().expect("pages").0.len(), 1);
    }

    #[test]
    fn an_objstm_that_is_not_readable_is_skipped() {
        let data = pdf("9 0 obj\n<< /Type /ObjStm /N 1 /First 4 >>\nendobj\n\
             1 0 obj\n<< /Type /Page >>\nendobj\n");
        let d = Document::parse(&data, &Limits::default()).expect("parses");
        assert_eq!(d.pages().expect("pages").0.len(), 1);

        let data = pdf(
            "9 0 obj\n<< /Type /ObjStm /N 1 /First 4 /Filter /FlateDecode >>\n\
             stream\nnot deflate\nendstream\nendobj\n\
             1 0 obj\n<< /Type /Page >>\nendobj\n",
        );
        let d = Document::parse(&data, &Limits::default()).expect("parses");
        assert_eq!(d.pages().expect("pages").0.len(), 1);
    }

    #[test]
    fn decode_parms_may_be_an_array_of_dictionaries() {
        let d = doc(
            "1 0 obj\n<< /Filter [/ASCIIHexDecode] /DecodeParms [null << /Predictor 12 \
             /Columns 3 >>] >>\nstream\n02010203>\nendstream\nendobj\n",
        );
        let got = d
            .stream_data(d.get(1).expect("the object"))
            .expect("decodes");
        assert_eq!(got, vec![1, 2, 3]);
    }

    #[test]
    fn a_predictor_below_ten_is_not_a_png_predictor() {
        let d = doc(
            "1 0 obj\n<< /Filter /ASCIIHexDecode /DecodeParms << /Predictor 2 >> >>\n\
             stream\n48656c>\nendstream\nendobj\n",
        );
        assert_eq!(
            d.stream_data(d.get(1).expect("the object")),
            Some(b"Hel".to_vec())
        );
    }

    #[test]
    fn pages_come_from_the_tree_when_there_is_one() {
        let d = doc(ONE_PAGE);
        let (pages, truncated) = d.pages().expect("pages");
        assert_eq!(pages.len(), 1);
        assert!(!truncated);
    }

    #[test]
    fn pages_fall_back_to_scanning_when_there_is_no_catalog() {
        let d = doc("7 0 obj\n<< /Type /Page >>\nendobj\n\
             4 0 obj\n<< /Type /Page >>\nendobj\n");
        let (pages, _) = d.pages().expect("pages");
        assert_eq!(pages.len(), 2);
    }

    #[test]
    fn a_document_with_no_pages_says_so() {
        let d = doc("1 0 obj\n<< /Type /Catalog >>\nendobj\n");
        assert_eq!(d.pages().map(|_| ()), Err(PdfError::NoPages));
    }

    #[test]
    fn the_page_cap_truncates_and_reports() {
        let kids = "4 0 R 5 0 R 6 0 R";
        let d = doc(&format!(
            "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n\
             2 0 obj\n<< /Type /Pages /Kids [{kids}] >>\nendobj\n\
             4 0 obj\n<< /Type /Page >>\nendobj\n\
             5 0 obj\n<< /Type /Page >>\nendobj\n\
             6 0 obj\n<< /Type /Page >>\nendobj\n"
        ));
        let (pages, truncated) = d.pages().expect("pages");
        assert_eq!(pages.len(), 3);
        assert!(!truncated);

        let limited = Document::parse(
            &pdf(&format!(
                "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n\
                 2 0 obj\n<< /Type /Pages /Kids [{kids}] >>\nendobj\n\
                 4 0 obj\n<< /Type /Page >>\nendobj\n\
                 5 0 obj\n<< /Type /Page >>\nendobj\n\
                 6 0 obj\n<< /Type /Page >>\nendobj\n"
            )),
            &Limits {
                max_pages: 2,
                ..Limits::default()
            },
        )
        .expect("parses");
        let (pages, truncated) = limited.pages().expect("pages");
        assert_eq!(pages.len(), 2);
        assert!(truncated, "the cap was not reported");
    }

    #[test]
    fn a_kid_with_contents_and_no_type_counts_as_a_page() {
        let d = doc("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n\
             2 0 obj\n<< /Type /Pages /Kids [3 0 R] >>\nendobj\n\
             3 0 obj\n<< /Contents 4 0 R >>\nendobj\n");
        assert_eq!(d.pages().expect("pages").0.len(), 1);
    }

    #[test]
    fn a_reference_resolves_and_a_dangling_one_is_null() {
        let d = doc("1 0 obj\n<< /A 2 0 R >>\nendobj\n2 0 obj\n42\nendobj\n");
        let dict = d.get(1).and_then(Object::as_dict).expect("a dict");
        assert_eq!(d.entry(dict, "A").and_then(Object::as_f64), Some(42.0));
        assert_eq!(d.resolve(&Object::Reference(99, 0)), &Object::Null);
        assert_eq!(d.resolve(&Object::Number(1.0)), &Object::Number(1.0));
        assert!(d.entry(dict, "Missing").is_none());
    }

    #[test]
    fn an_inherited_attribute_is_found_on_a_parent() {
        let d = doc(
            "1 0 obj\n<< /Type /Pages /Resources << /Font << >> >> >>\nendobj\n\
             2 0 obj\n<< /Type /Page /Parent 1 0 R >>\nendobj\n",
        );
        let page = d.get(2).and_then(Object::as_dict).expect("a page");
        assert!(d.inherited(page, "Resources").is_some());
        assert!(d.inherited(page, "Nothing").is_none());
        let d = doc("2 0 obj\n<< /Type /Page /Resources << /A 1 >> >>\nendobj\n");
        let page = d.get(2).and_then(Object::as_dict).expect("a page");
        assert!(d.inherited(page, "Resources").is_some());
    }

    #[test]
    fn an_inheritance_loop_terminates() {
        let d = doc("1 0 obj\n<< /Type /Pages /Parent 2 0 R >>\nendobj\n\
             2 0 obj\n<< /Type /Pages /Parent 1 0 R >>\nendobj\n");
        let node = d.get(1).and_then(Object::as_dict).expect("a node");
        assert!(d.inherited(node, "Nothing").is_none());
    }

    #[test]
    fn an_encrypted_trailer_is_refused() {
        let data = b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n\
                     trailer\n<< /Root 1 0 R /Encrypt 9 0 R >>\n%%EOF\n";
        assert_eq!(
            Document::parse(data, &Limits::default()).map(|_| ()),
            Err(PdfError::Encrypted)
        );
    }

    #[test]
    fn an_encrypted_xref_stream_is_refused() {
        let data = b"%PDF-1.7\n1 0 obj\n<< /Type /XRef /Root 2 0 R /Encrypt 9 0 R >>\n\
                     stream\nxx\nendstream\nendobj\n%%EOF\n";
        assert_eq!(
            Document::parse(data, &Limits::default()).map(|_| ()),
            Err(PdfError::Encrypted)
        );
    }

    #[test]
    fn the_word_encrypt_in_content_does_not_refuse_the_document() {
        let d = Document::parse(
            &pdf("1 0 obj\n<< /Type /Page /Note (/Encrypt is discussed here) >>\nendobj\n"),
            &Limits::default(),
        );
        assert!(d.is_ok(), "a mention was taken for a declaration");
    }

    #[test]
    fn malformed_files_take_every_skip_path() {
        for body in [
            "1 0 obj\n)))\nendobj\n",
            "1 x obj\n<< >>\nendobj\n",
            "99999999999999 0 obj\n<< >>\nendobj\n",
            "1 99999999 obj\n<< >>\nendobj\n",
            "1 0 obj\n<< /Length 4 >>\nstream\nabcd",
            "1 0 obj\n<< /Length 4 >>\nnotastream\nendobj\n",
            "1 0 obj\n<< >>\nstream\nabc\r\nendstream\nendobj\n",
            "1 0 obj\n<< >>\nstream\r\nabc\nendstream\nendobj\n",
            "",
        ] {
            let _ = Document::parse(&pdf(body), &Limits::default());
        }
        let d = doc("1 0 obj\n<< /Length 3 >>\nstream\nabc\nendstream\nendobj\n");
        assert_eq!(
            d.stream_data(d.get(1).expect("the object")),
            Some(b"abc".to_vec())
        );
    }

    #[test]
    fn the_object_cap_applies_while_expanding_a_stream() {
        let entries: Vec<(u32, String)> = (1..=40).map(|n| (n, format!("<< /N {n} >>"))).collect();
        let mut head = String::new();
        let mut bodies = String::new();
        for (num, body) in &entries {
            head.push_str(&format!("{num} {} ", bodies.len()));
            bodies.push_str(body);
            bodies.push(' ');
        }
        let payload = format!("{head}{bodies}");
        let data = pdf(&format!(
            "9 0 obj\n<< /Type /ObjStm /N {} /First {} /Length {} >>\n\
             stream\n{payload}\nendstream\nendobj\n",
            entries.len(),
            head.len(),
            payload.len()
        ));
        let limits = Limits {
            max_objects: 5,
            ..Limits::default()
        };
        assert_eq!(
            Document::parse(&data, &limits).map(|_| ()),
            Err(PdfError::TooMany {
                what: "objects",
                limit: 5
            })
        );
    }

    #[test]
    fn ascii_hex_and_ascii85_handle_their_edges() {
        assert_eq!(ascii_hex_decode(b"4"), vec![0x40]);
        assert_eq!(ascii_hex_decode(b"41>ignored"), vec![0x41]);
        assert_eq!(ascii_hex_decode(b"zz"), Vec::<u8>::new());
        assert_eq!(ascii_hex_decode(b""), Vec::<u8>::new());
        assert_eq!(ascii85_decode(b"~>"), Vec::<u8>::new());
        assert_eq!(ascii85_decode(b""), Vec::<u8>::new());
        assert_eq!(ascii85_decode(b"\x01\x02~>"), Vec::<u8>::new());
        assert_eq!(ascii85_decode(b"5~>").len(), 0);
    }

    #[test]
    fn decode_parms_that_name_no_dictionary_are_ignored() {
        for parms in ["[null null]", "7", "/Name", "<< /Columns 3 >>"] {
            let d = doc(&format!(
                "1 0 obj\n<< /Filter /ASCIIHexDecode /DecodeParms {parms} >>\n\
                 stream\n48656c>\nendstream\nendobj\n"
            ));
            assert_eq!(
                d.stream_data(d.get(1).expect("the object")),
                Some(b"Hel".to_vec()),
                "{parms}"
            );
        }
    }

    #[test]
    fn a_filter_that_is_neither_a_name_nor_an_array_is_no_filter() {
        let d = doc("1 0 obj\n<< /Filter 7 >>\nstream\nraw\nendstream\nendobj\n");
        assert_eq!(
            d.stream_data(d.get(1).expect("the object")),
            Some(b"raw".to_vec())
        );
    }

    #[test]
    fn every_error_renders_and_is_a_std_error() {
        for e in [
            PdfError::NotAPdf,
            PdfError::Encrypted,
            PdfError::NoPages,
            PdfError::TooMany {
                what: "objects",
                limit: 1,
            },
            PdfError::NoTextFound { pages: 2 },
        ] {
            assert!(!e.to_string().is_empty(), "{e:?}");
            let _: &dyn std::error::Error = &e;
        }
    }

    #[test]
    fn the_default_bounds_are_stated_rather_than_implied() {
        let d = Limits::default();
        assert_eq!(d.max_objects, 50_000);
        assert_eq!(d.max_pages, 2_000);
        assert_eq!(d.max_stream_bytes, 32 * 1024 * 1024);
    }

    #[test]
    fn find_behaves_at_its_edges() {
        assert_eq!(find(b"abcabc", b"abc", 0), Some(0));
        assert_eq!(find(b"abcabc", b"abc", 1), Some(3));
        assert_eq!(find(b"abcabc", b"abc", 4), None);
        assert_eq!(find(b"abc", b"", 0), None);
        assert_eq!(find(b"", b"a", 0), None);
        assert_eq!(find(b"abc", b"abc", 99), None);
    }
}
