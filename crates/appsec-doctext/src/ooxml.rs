use crate::xmltext::{self, TextRules};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Docx,
    Xlsx,
    Pptx,
    Pdf,
}

const WORD_RULES: TextRules = TextRules {
    text_elements: &["t"],
    break_elements: &["p", "br", "cr"],
    tab_elements: &["tab"],
};

const SHEET_RULES: TextRules = TextRules {
    text_elements: &["t"],
    break_elements: &["si", "row"],
    tab_elements: &["c"],
};

const SLIDE_RULES: TextRules = TextRules {
    text_elements: &["t"],
    break_elements: &["p", "br"],
    tab_elements: &[],
};

impl Format {
    pub fn of_name(file_name: &str) -> Option<Self> {
        let extension = file_name.rsplit_once('.')?.1.to_ascii_lowercase();
        match extension.as_str() {
            "docx" | "docm" => Some(Self::Docx),
            "xlsx" | "xlsm" => Some(Self::Xlsx),
            "pptx" | "pptm" => Some(Self::Pptx),
            "pdf" => Some(Self::Pdf),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Docx => "docx",
            Self::Xlsx => "xlsx",
            Self::Pptx => "pptx",
            Self::Pdf => "pdf",
        }
    }

    fn rules(self) -> &'static TextRules {
        match self {
            Self::Docx => &WORD_RULES,
            Self::Xlsx => &SHEET_RULES,
            Self::Pptx => &SLIDE_RULES,
            Self::Pdf => &WORD_RULES,
        }
    }

    fn parts(self, available: &[String], max_parts: usize) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let mut take_fixed = |name: &str| {
            if available.iter().any(|a| a == name) {
                out.push(name.to_string());
            }
        };
        match self {
            Self::Docx => {
                take_fixed("word/document.xml");
                take_fixed("word/footnotes.xml");
                take_fixed("word/endnotes.xml");
            }
            Self::Xlsx => {
                take_fixed("xl/sharedStrings.xml");
                out.extend(numbered(available, "xl/worksheets/sheet", ".xml"));
            }
            Self::Pptx => {
                out.extend(numbered(available, "ppt/slides/slide", ".xml"));
                out.extend(numbered(available, "ppt/notesSlides/notesSlide", ".xml"));
            }
            Self::Pdf => {}
        }
        out.truncate(max_parts);
        out
    }
}

fn numbered(available: &[String], prefix: &str, suffix: &str) -> Vec<String> {
    let mut found: Vec<(u32, &String)> = available
        .iter()
        .filter_map(|name| {
            let middle = name.strip_prefix(prefix)?.strip_suffix(suffix)?;
            if middle.is_empty() || !middle.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            middle.parse::<u32>().ok().map(|n| (n, name))
        })
        .collect();
    found.sort_by_key(|(n, _)| *n);
    found.into_iter().map(|(_, name)| name.clone()).collect()
}

pub(crate) fn extract_part(
    format: Format,
    part: &[u8],
    limits: &xmltext::Limits,
) -> Result<xmltext::Text, xmltext::XmlError> {
    xmltext::extract(part, format.rules(), limits)
}

pub(crate) fn parts_of(format: Format, available: &[String], max_parts: usize) -> Vec<String> {
    format.parts(available, max_parts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_format_names_itself() {
        assert_eq!(Format::Docx.as_str(), "docx");
        assert_eq!(Format::Xlsx.as_str(), "xlsx");
        assert_eq!(Format::Pptx.as_str(), "pptx");
    }

    #[test]
    fn only_the_parts_the_archive_actually_has_are_read() {
        let available = vec![
            "word/document.xml".to_string(),
            "word/styles.xml".to_string(),
        ];
        assert_eq!(
            parts_of(Format::Docx, &available, 256),
            ["word/document.xml"],
            "a missing footnotes part is ordinary, not an error"
        );
    }

    #[test]
    fn the_part_cap_is_applied() {
        let available: Vec<String> = (1..=10)
            .map(|n| format!("ppt/slides/slide{n}.xml"))
            .collect();
        assert_eq!(parts_of(Format::Pptx, &available, 3).len(), 3);
    }

    #[test]
    fn a_numbered_part_must_be_numbered() {
        let available = vec![
            "xl/worksheets/sheet1.xml".to_string(),
            "xl/worksheets/sheetA.xml".to_string(),
            "xl/worksheets/sheet.xml".to_string(),
            "xl/worksheets/sheet1x.xml".to_string(),
            "xl/worksheets/sheet-1.xml".to_string(),
            "xl/worksheets/sheet1/../../evil.xml".to_string(),
        ];
        assert_eq!(
            parts_of(Format::Xlsx, &available, 256),
            ["xl/worksheets/sheet1.xml"]
        );
    }

    #[test]
    fn numbered_parts_sort_numerically() {
        let available: Vec<String> = [2u32, 10, 1, 21, 3]
            .iter()
            .map(|n| format!("ppt/slides/slide{n}.xml"))
            .collect();
        assert_eq!(
            parts_of(Format::Pptx, &available, 256),
            [
                "ppt/slides/slide1.xml",
                "ppt/slides/slide2.xml",
                "ppt/slides/slide3.xml",
                "ppt/slides/slide10.xml",
                "ppt/slides/slide21.xml",
            ]
        );
    }

    #[test]
    fn notes_follow_slides_rather_than_interleaving() {
        let available = vec![
            "ppt/notesSlides/notesSlide1.xml".to_string(),
            "ppt/slides/slide1.xml".to_string(),
        ];
        assert_eq!(
            parts_of(Format::Pptx, &available, 256),
            ["ppt/slides/slide1.xml", "ppt/notesSlides/notesSlide1.xml"]
        );
    }

    #[test]
    fn the_pdf_arms_are_inert_rather_than_a_panic() {
        assert!(parts_of(Format::Pdf, &["word/document.xml".into()], 256).is_empty());
        assert_eq!(Format::Pdf.rules(), &WORD_RULES);
    }

    #[test]
    fn an_archive_with_no_matching_parts_yields_none() {
        assert!(parts_of(Format::Docx, &["other.xml".to_string()], 256).is_empty());
    }
}
