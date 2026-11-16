pub mod document;
pub mod encoding;
pub mod object;
pub mod tables;
pub mod text;

pub use document::{Limits, PdfError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extracted {
    pub text: String,
    pub pages: usize,
    pub pages_with_text: Vec<usize>,
    pub truncated: bool,
}

pub fn extract(data: &[u8], limits: &Limits, max_chars: usize) -> Result<Extracted, PdfError> {
    let doc = document::Document::parse(data, limits)?;
    let (pages, mut truncated) = doc.pages()?;
    let page_count = pages.len();

    let mut out = String::new();
    let mut undecoded = 0usize;
    let mut pages_with_text = Vec::new();

    for (index, page) in pages.into_iter().enumerate() {
        let separator = usize::from(!out.is_empty());
        let spent = out.chars().count() + separator;
        if spent >= max_chars {
            truncated = true;
            break;
        }
        let got = text::page_text(&doc, page, max_chars - spent);
        undecoded += got.undecoded;
        truncated |= got.truncated;
        let trimmed = tidy(&got.text);
        if trimmed.is_empty() {
            continue;
        }
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(&trimmed);
        pages_with_text.push(index + 1);
    }

    let decoded = out.chars().filter(|c| !c.is_whitespace()).count();
    if decoded == 0 || undecoded > decoded {
        return Err(PdfError::NoTextFound { pages: page_count });
    }

    Ok(Extracted {
        text: out,
        pages: page_count,
        pages_with_text,
        truncated,
    })
}

fn tidy(text: &str) -> String {
    let lines: Vec<&str> = text.lines().map(str::trim_end).collect();
    let first = lines.iter().position(|l| !l.is_empty()).unwrap_or(0);
    let last = lines
        .iter()
        .rposition(|l| !l.is_empty())
        .map_or(0, |i| i + 1);
    lines.get(first..last).unwrap_or_default().join("\n")
}
