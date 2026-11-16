#![forbid(unsafe_code)]

pub mod inflate;
pub mod ooxml;
pub mod pdf;
pub mod xmltext;
pub mod zipentry;

use std::fmt;

pub use ooxml::Format;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    pub max_archive_bytes: usize,
    pub max_entries: usize,
    pub max_part_bytes: usize,
    pub max_parts: usize,
    pub max_chars: usize,
    pub max_depth: usize,
    pub max_pdf_objects: usize,
    pub max_pdf_pages: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_archive_bytes: 16 * 1024 * 1024,
            max_entries: 4096,
            max_part_bytes: 8 * 1024 * 1024,
            max_parts: 256,
            max_chars: 512 * 1024,
            max_depth: 256,
            max_pdf_objects: 50_000,
            max_pdf_pages: 2_000,
        }
    }
}

impl Limits {
    fn zip(&self) -> zipentry::Limits {
        zipentry::Limits {
            max_entries: self.max_entries,
            max_entry_bytes: self.max_part_bytes,
            max_name_len: 512,
        }
    }

    fn pdf(&self) -> pdf::Limits {
        pdf::Limits {
            max_objects: self.max_pdf_objects,
            max_pages: self.max_pdf_pages,
            max_stream_bytes: self.max_part_bytes,
        }
    }

    fn xml(&self, already: usize) -> xmltext::Limits {
        xmltext::Limits {
            max_chars: self.max_chars.saturating_sub(already),
            max_depth: self.max_depth,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extracted {
    pub format: Format,
    pub text: String,
    pub parts_read: Vec<String>,
    pub truncated: bool,
}

impl Extracted {
    pub fn pages_read(&self) -> usize {
        self.parts_read.len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DocError {
    UnsupportedFormat {
        extension: Option<String>,
    },
    TooLarge {
        bytes: usize,
        limit: usize,
    },
    Archive(zipentry::ZipError),
    NoReadableParts {
        format: Format,
    },
    Xml {
        part: String,
        cause: xmltext::XmlError,
    },
    Pdf(pdf::PdfError),
}

impl fmt::Display for DocError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedFormat { extension } => match extension {
                Some(e) => write!(
                    f,
                    ".{e} is not a format this reads; supported: \
                     docx, docm, xlsx, xlsm, pptx, pptm, pdf"
                ),
                None => write!(f, "a file with no extension cannot be identified"),
            },
            Self::TooLarge { bytes, limit } => {
                write!(
                    f,
                    "the document is {bytes} bytes, past the {limit} byte limit"
                )
            }
            Self::Archive(e) => write!(f, "{e}"),
            Self::NoReadableParts { format } => write!(
                f,
                "this is a valid archive but holds no {} part with text in it",
                format.as_str()
            ),
            Self::Xml { part, cause } => write!(f, "{part}: {cause}"),
            Self::Pdf(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for DocError {}

pub fn extract(file_name: &str, bytes: &[u8], limits: &Limits) -> Result<Extracted, DocError> {
    let format = Format::of_name(file_name).ok_or_else(|| DocError::UnsupportedFormat {
        extension: file_name
            .rsplit_once('.')
            .map(|(_, e)| e.to_ascii_lowercase()),
    })?;
    if bytes.len() > limits.max_archive_bytes {
        return Err(DocError::TooLarge {
            bytes: bytes.len(),
            limit: limits.max_archive_bytes,
        });
    }

    if format == Format::Pdf {
        let got = pdf::extract(bytes, &limits.pdf(), limits.max_chars).map_err(DocError::Pdf)?;
        return Ok(Extracted {
            format,
            text: got.text,
            parts_read: got
                .pages_with_text
                .iter()
                .map(|n| format!("page {n}"))
                .collect(),
            truncated: got.truncated,
        });
    }

    let zip_limits = limits.zip();
    let available = zipentry::entry_names(bytes, &zip_limits).map_err(DocError::Archive)?;
    let parts = ooxml::parts_of(format, &available, limits.max_parts);
    if parts.is_empty() {
        return Err(DocError::NoReadableParts { format });
    }

    let mut text = String::new();
    let mut parts_read = Vec::new();
    let mut truncated = false;
    let mut chars_so_far = 0usize;
    let mut first_failure: Option<DocError> = None;

    for part in parts {
        let raw = match zipentry::read_entry(bytes, &part, &zip_limits) {
            Ok(raw) => raw,
            Err(e) => {
                truncated = true;
                first_failure.get_or_insert(DocError::Archive(e));
                continue;
            }
        };
        match ooxml::extract_part(format, &raw, &limits.xml(chars_so_far)) {
            Ok(part_text) => {
                let trimmed = part_text.text.trim_end();
                if !trimmed.is_empty() {
                    if !text.is_empty() && !text.ends_with('\n') {
                        text.push('\n');
                    }
                    text.push_str(trimmed);
                    chars_so_far = text.chars().count();
                }
                parts_read.push(part);
                if part_text.truncated {
                    truncated = true;
                    break;
                }
            }
            Err(cause @ xmltext::XmlError::TooDeep { .. }) => {
                truncated = true;
                first_failure.get_or_insert(DocError::Xml {
                    part: part.clone(),
                    cause,
                });
                continue;
            }
            Err(cause) => return Err(DocError::Xml { part, cause }),
        }
    }

    if parts_read.is_empty() {
        return Err(first_failure.unwrap_or(DocError::NoReadableParts { format }));
    }
    Ok(Extracted {
        format,
        text,
        parts_read,
        truncated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_error_renders_and_is_a_std_error() {
        let all = [
            DocError::UnsupportedFormat {
                extension: Some("pdf".into()),
            },
            DocError::UnsupportedFormat { extension: None },
            DocError::TooLarge {
                bytes: 10,
                limit: 5,
            },
            DocError::Archive(zipentry::ZipError::NotAnArchive),
            DocError::NoReadableParts {
                format: Format::Xlsx,
            },
            DocError::Xml {
                part: "word/document.xml".into(),
                cause: xmltext::XmlError::DoctypeRefused,
            },
        ];
        for e in all {
            assert!(!e.to_string().is_empty(), "{e:?} rendered empty");
            let _: &dyn std::error::Error = &e;
        }
        let too_large = DocError::TooLarge {
            bytes: 900,
            limit: 100,
        };
        let rendered = too_large.to_string();
        assert!(rendered.contains("900"), "{rendered}");
        assert!(rendered.contains("100"), "{rendered}");
    }

    #[test]
    fn the_default_bounds_are_stated_rather_than_implied() {
        let d = Limits::default();
        assert_eq!(d.max_archive_bytes, 16 * 1024 * 1024);
        assert_eq!(d.max_entries, 4096);
        assert_eq!(d.max_part_bytes, 8 * 1024 * 1024);
        assert_eq!(d.max_parts, 256);
        assert_eq!(d.max_chars, 512 * 1024);
        assert_eq!(d.max_depth, 256);
    }

    #[test]
    fn the_character_budget_is_shared_across_parts() {
        let limits = Limits {
            max_chars: 100,
            ..Limits::default()
        };
        assert_eq!(limits.xml(0).max_chars, 100);
        assert_eq!(limits.xml(60).max_chars, 40);
        assert_eq!(limits.xml(1000).max_chars, 0);
    }

    #[test]
    fn the_zip_bounds_are_derived_from_the_document_bounds() {
        let limits = Limits {
            max_entries: 7,
            max_part_bytes: 11,
            ..Limits::default()
        };
        let zip = limits.zip();
        assert_eq!(zip.max_entries, 7);
        assert_eq!(zip.max_entry_bytes, 11);
    }
}
