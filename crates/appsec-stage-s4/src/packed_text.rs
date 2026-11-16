use std::sync::LazyLock;

use regex::Regex;

const BINARY_SNIFF_CHARS: usize = 8192;

static DATA_URI_RX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"data:([\w.+-]+/[\w.+-]+);base64,([A-Za-z0-9+/=]*)").unwrap());

fn is_binary_text(text: &str) -> bool {
    let mut len = 0usize;
    let mut replacements = 0usize;
    for c in text.chars().take(BINARY_SNIFF_CHARS) {
        if c == '\0' {
            return true;
        }
        len += 1;
        replacements += usize::from(c == '\u{FFFD}');
    }
    len > 0 && replacements * 10 > len
}

fn elide_data_uris(text: &str) -> String {
    DATA_URI_RX
        .replace_all(text, |caps: &regex::Captures<'_>| {
            let media = &caps[1];
            match caps[2].len() {
                0 => format!("[data-uri {media} elided]"),
                n => format!("[data-uri {media} elided: {n} chars]"),
            }
        })
        .into_owned()
}

pub(crate) fn sanitize_packed_text(text: &str, rel: &str) -> String {
    if is_binary_text(text) {
        let name = if rel.is_empty() { "file" } else { rel };
        return format!("[binary content elided: {name} is not text]");
    }
    elide_data_uris(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_nul_byte_in_the_head_marks_the_file_binary() {
        assert_eq!(
            sanitize_packed_text("ELF\0\0junk\nmore", "bin/tool"),
            "[binary content elided: bin/tool is not text]"
        );
        assert_eq!(
            sanitize_packed_text("\0", ""),
            "[binary content elided: file is not text]"
        );
    }

    #[test]
    fn a_nul_past_the_sniff_window_is_not_seen() {
        let text = format!("{}\0", "a".repeat(BINARY_SNIFF_CHARS));
        assert_eq!(sanitize_packed_text(&text, "x"), text);
    }

    #[test]
    fn replacement_character_density_above_ten_percent_is_binary() {
        assert!(is_binary_text("\u{FFFD}\u{FFFD}abcdefgh"));
        assert!(!is_binary_text("\u{FFFD}abcdefghi"));
        assert!(!is_binary_text(""));
    }

    #[test]
    fn data_uris_are_elided_in_place_without_moving_lines() {
        let text =
            "a\n<img src=\"data:image/png;base64,iVBORw0KGgo=\">\nb data:text/plain;base64, c";
        let out = sanitize_packed_text(text, "t.html");
        assert_eq!(
            out,
            "a\n<img src=\"[data-uri image/png elided: 12 chars]\">\nb [data-uri text/plain elided] c"
        );
        assert_eq!(out.lines().count(), text.lines().count());
    }

    #[test]
    fn ordinary_text_is_unchanged() {
        assert_eq!(
            sanitize_packed_text("fn main() {}\n", "m.rs"),
            "fn main() {}\n"
        );
    }
}
