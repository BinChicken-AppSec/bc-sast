use std::sync::LazyLock;

use regex::Regex;

static ATX_HEADING_RX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(\s{0,3})#{1,6}[ \t]+(.*)$").unwrap());
static FENCE_RX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\s{0,3}(`{3,}|~{3,})").unwrap());
static SETEXT_RX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\s{0,3}(=+|-+)\s*$").unwrap());

pub fn demote_md_headings(text: &str) -> String {
    if text.is_empty() {
        return String::new();
    }
    let mut out: Vec<String> = Vec::new();
    let mut fence: Option<String> = None;
    for line in text.lines() {
        if let Some(caps) = FENCE_RX.captures(line) {
            let marker = caps[1].to_string();
            match &fence {
                None => fence = Some(marker),
                Some(open) => {
                    let same_kind = open.chars().next() == marker.chars().next();
                    if same_kind && marker.len() >= open.len() {
                        fence = None;
                    }
                }
            }
            out.push(line.to_string());
            continue;
        }
        if fence.is_none() {
            if let Some(caps) = ATX_HEADING_RX.captures(line) {
                let leading = &caps[1];
                let heading_text = caps[2].trim_end();
                out.push(format!("{leading}**{heading_text}**"));
                continue;
            }
            if SETEXT_RX.is_match(line) {
                if let Some(prev) = out.last_mut() {
                    let body = prev.trim();
                    if !body.is_empty() && !body.starts_with("**") {
                        let indent = &prev[..prev.len() - prev.trim_start().len()];
                        *prev = format!("{indent}**{body}**");
                        continue;
                    }
                    if body.starts_with("**") {
                        continue;
                    }
                }
            }
        }
        out.push(line.to_string());
    }
    out.join("\n")
}

fn is_md_linebreak(c: char) -> bool {
    matches!(
        c,
        '\r' | '\n'
            | '\u{0B}'
            | '\u{0C}'
            | '\u{1C}'
            | '\u{1D}'
            | '\u{1E}'
            | '\u{85}'
            | '\u{2028}'
            | '\u{2029}'
    )
}

fn is_md_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{00}'..='\u{08}'
            | '\u{0E}'..='\u{1F}'
            | '\u{7F}'
            | '\u{AD}'
            | '\u{061C}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{2069}'
            | '\u{FEFF}'
    )
}

fn neutralize_invisible(text: &str) -> String {
    text.chars()
        .filter_map(|c| {
            if is_md_linebreak(c) {
                Some(' ')
            } else if is_md_invisible(c) {
                None
            } else {
                Some(c)
            }
        })
        .collect()
}

pub fn md_cell(text: &str) -> String {
    neutralize_invisible(text)
        .replace('\\', "\\\\")
        .replace('|', "\\|")
        .trim()
        .to_string()
}

pub fn md_code_span(text: &str) -> String {
    neutralize_invisible(text)
        .replace('`', "\u{2CB}")
        .trim()
        .to_string()
}

pub fn sanitize_title(title: &str) -> String {
    title
        .chars()
        .filter(|c| !matches!(c, '<' | '>' | '`' | '|' | '[' | ']'))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demotes_leading_atx_headings_of_every_level() {
        assert_eq!(
            demote_md_headings("## Analysis\nbody"),
            "**Analysis**\nbody"
        );
        assert_eq!(demote_md_headings("# H1"), "**H1**");
        assert_eq!(demote_md_headings("###### H6"), "**H6**");
    }

    #[test]
    fn preserves_inline_hashes_and_indented_or_fenced_lines() {
        assert_eq!(
            demote_md_headings("use C# or #1 or #define"),
            "use C# or #1 or #define"
        );
        let fenced = "```python\n# a comment\nx = 1\n```";
        assert_eq!(demote_md_headings(fenced), fenced);
        assert_eq!(demote_md_headings("    # indented"), "    # indented");
    }

    #[test]
    fn empty_input_is_unchanged() {
        assert_eq!(demote_md_headings(""), "");
    }

    #[test]
    fn md_cell_escapes_pipe_and_collapses_newlines() {
        assert_eq!(md_cell("a|b"), "a\\|b");
        assert_eq!(md_cell("line1\nline2"), "line1 line2");
        assert_eq!(md_cell("line1\r\nline2"), "line1  line2");
        assert_eq!(md_cell(""), "");
        assert_eq!(md_cell("  padded  "), "padded");
    }

    #[test]
    fn md_cell_escapes_a_literal_backslash() {
        assert_eq!(md_cell("a\\b"), "a\\\\b");
    }

    #[test]
    fn md_cell_does_not_let_a_trailing_backslash_consume_the_pipe_escape() {
        let escaped = md_cell("a\\|b");
        assert_eq!(escaped, "a\\\\\\|b");
        assert!(
            !contains_unescaped_pipe(&escaped),
            "an attacker-supplied backslash must never expose a bare, \
             table-breaking `|` in the rendered cell: {escaped:?}"
        );
    }

    #[test]
    fn contains_unescaped_pipe_detects_a_genuinely_bare_pipe() {
        assert!(contains_unescaped_pipe("a|b"));
        assert!(contains_unescaped_pipe("a\\\\|b"));
        assert!(!contains_unescaped_pipe("a\\|b"));
    }

    fn contains_unescaped_pipe(s: &str) -> bool {
        let bytes = s.as_bytes();
        let mut backslash_run = 0usize;
        for &b in bytes {
            if b == b'\\' {
                backslash_run += 1;
                continue;
            }
            if b == b'|' && backslash_run.is_multiple_of(2) {
                return true;
            }
            backslash_run = 0;
        }
        false
    }

    #[test]
    fn sanitize_title_strips_markdown_metacharacters() {
        assert_eq!(sanitize_title("my-repo"), "my-repo");
        assert_eq!(sanitize_title("evil<script>`|[x]"), "evilscriptx");
    }

    #[test]
    fn md_code_span_neutralizes_a_backtick() {
        assert_eq!(md_code_span("a`b"), "aˋb");
    }

    #[test]
    fn md_code_span_breakout_is_closed() {
        let path = "foo`) [pwned](javascript:alert(1)) (`bar";
        let rendered = format!("`{}`", md_code_span(path));
        assert_eq!(rendered.matches('`').count(), 2);
        assert!(rendered.starts_with('`') && rendered.ends_with('`'));
    }

    #[test]
    fn md_code_span_collapses_newlines() {
        assert_eq!(md_code_span("line1\nline2"), "line1 line2");
        assert_eq!(md_code_span("line1\r\nline2"), "line1  line2");
    }

    #[test]
    fn md_cell_folds_every_unicode_line_separator_to_a_space() {
        for sep in [
            '\u{0B}', '\u{0C}', '\u{1C}', '\u{1D}', '\u{1E}', '\u{85}', '\u{2028}', '\u{2029}',
        ] {
            let input = format!("a{sep}## forged");
            assert_eq!(md_cell(&input), "a ## forged", "separator {sep:?}");
            assert_eq!(md_code_span(&input), "a ## forged", "separator {sep:?}");
        }
    }

    #[test]
    fn md_cell_strips_remaining_c0_controls_and_del_but_keeps_tab() {
        assert_eq!(md_cell("a\u{00}b\u{07}c\u{1B}d\u{1F}e\u{7F}f"), "abcdef");
        assert_eq!(md_cell("a\tb"), "a\tb");
        assert_eq!(md_code_span("a\u{08}b\u{0E}c"), "abc");
    }

    #[test]
    fn md_cell_strips_zero_width_characters() {
        let input = "FA\u{200B}IL\u{200C}E\u{200D}D\u{2060}\u{FEFF}\u{AD}\u{2064}";
        assert_eq!(md_cell(input), "FAILED");
        assert_eq!(md_code_span(input), "FAILED");
    }

    #[test]
    fn md_cell_strips_bidi_overrides_embeddings_isolates_and_marks() {
        let input = "\u{202E}DELIAF\u{202C} \u{2066}x\u{2069} \u{200E}y\u{200F} \u{061C}z\u{202A}\u{202B}\u{202D}\u{2067}\u{2068}";
        assert_eq!(md_cell(input), "DELIAF x y z");
        assert_eq!(md_code_span(input), "DELIAF x y z");
    }

    #[test]
    fn md_cell_leaves_ordinary_non_ascii_text_alone() {
        assert_eq!(md_cell("café ü 漢字 \u{2065}"), "café ü 漢字 \u{2065}");
    }
}

#[cfg(test)]
mod heading_forgery_tests {
    use super::demote_md_headings;

    #[test]
    fn a_setext_underline_cannot_forge_a_heading() {
        assert_eq!(
            demote_md_headings("Critical Finding\n===\nbody"),
            "**Critical Finding**\nbody"
        );
        assert_eq!(
            demote_md_headings("Looks Official\n---\nbody"),
            "**Looks Official**\nbody"
        );
    }

    #[test]
    fn a_thematic_break_is_left_alone() {
        assert_eq!(
            demote_md_headings("paragraph\n\n---\n\nnext"),
            "paragraph\n\n---\n\nnext"
        );
    }

    #[test]
    fn a_mismatched_fence_marker_does_not_close_the_block() {
        assert_eq!(
            demote_md_headings("~~~\n```\n# inside\n~~~\n# outside"),
            "~~~\n```\n# inside\n~~~\n**outside**"
        );
    }

    #[test]
    fn a_longer_run_closes_a_shorter_one_of_the_same_kind() {
        assert_eq!(
            demote_md_headings("```\n# inside\n````\n# outside"),
            "```\n# inside\n````\n**outside**"
        );
    }

    #[test]
    fn a_leading_underline_has_nothing_to_promote() {
        assert_eq!(demote_md_headings("===\nbody"), "===\nbody");
        assert_eq!(demote_md_headings("---"), "---");
    }

    #[test]
    fn an_underline_after_an_already_demoted_heading_is_dropped() {
        assert_eq!(
            demote_md_headings("# Heading\n===\nbody"),
            "**Heading**\nbody"
        );
    }

    #[test]
    fn headings_inside_a_fence_are_still_untouched() {
        assert_eq!(
            demote_md_headings("```\n# literal\n```\n# real"),
            "```\n# literal\n```\n**real**"
        );
    }
}
