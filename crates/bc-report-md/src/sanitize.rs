//! Anti-injection sanitizers applied to every LLM/CMDB-sourced free-text
//! field before it's embedded in the report, ported from
//! `models.py::_demote_md_headings`/`_md_cell`. LLM output and CMDB data
//! are both untrusted relative to the report's own Markdown structure —
//! without these, an attacker-influenced description containing `## Fake
//! Section` or a `|` could restructure the document or break a table row.

use std::sync::LazyLock;

use regex::Regex;

static ATX_HEADING_RX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(\s{0,3})#{1,6}[ \t]+(.*)$").unwrap());
static FENCE_RX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\s{0,3}(```|~~~)").unwrap());

/// Turn any ATX heading (`#` to `######`) into **bold text** instead,
/// preserving its content but never letting injected text restructure the
/// document. Lines inside a fenced code block (naive toggle on any line
/// starting with 0-3 spaces then ``` or ~~~ — fence *type*/length aren't
/// tracked beyond that) are left untouched.
///
/// The Python original also accepts `None` (returning `None` unchanged),
/// but every real call site passes an always-`str` model field, so that
/// case doesn't arise for this port's `&str`-typed callers.
pub fn demote_md_headings(text: &str) -> String {
    if text.is_empty() {
        return String::new();
    }
    let mut out: Vec<String> = Vec::new();
    let mut in_fence = false;
    for line in text.lines() {
        if FENCE_RX.is_match(line) {
            in_fence = !in_fence;
            out.push(line.to_string());
            continue;
        }
        if !in_fence {
            if let Some(caps) = ATX_HEADING_RX.captures(line) {
                let leading = &caps[1];
                let heading_text = caps[2].trim_end();
                out.push(format!("{leading}**{heading_text}**"));
                continue;
            }
        }
        out.push(line.to_string());
    }
    out.join("\n")
}

/// Line and paragraph separators beyond `\r`/`\n`: VT, FF, FS/GS/RS,
/// NEL, LS and PS. Many renderers and post-processors treat every one of
/// these as a line break, so an untrusted value carrying e.g. U+2028 could
/// still forge a table row or heading after `\r`/`\n` were neutralized.
/// Folded to a space, exactly like `\r`/`\n`. Mirrors the upstream
/// `_MD_LINEBREAK_RX`.
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

/// Remaining C0 controls and DEL (tab excepted), plus zero-width and
/// bidirectional formatting characters. Stripped so an untrusted value
/// cannot hide, disguise or visually reorder rendered report text (a
/// Trojan Source style spoof, e.g. making a FAILED status read as
/// something else). Mirrors the upstream `_MD_INVISIBLE_RX`; call only
/// after [`is_md_linebreak`] characters have been folded.
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

/// Fold every line-breaking character to a space and strip invisible or
/// bidi-reordering characters. The shared first step of [`md_cell`] and
/// [`md_code_span`].
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

/// Escape a value for embedding in a Markdown table cell or single-line
/// bullet: fold every line-breaking character (`\r`, `\n`, VT, FF,
/// FS/GS/RS, NEL, U+2028, U+2029) to a space (so an injected newline can't
/// break out of a table row or spawn a new bullet/heading line), strip the
/// remaining C0 controls, zero-width and bidi override/isolate characters,
/// escape `\` itself, THEN escape `|` (the table-cell delimiter), then trim.
///
/// The backslash escape must come first: escaping `|` before `\` lets an
/// attacker-supplied `\` immediately preceding a `|` consume the `\` this
/// function inserts, so the pair renders as one literal backslash
/// followed by a bare, unescaped `|`, re-exposing the table-cell
/// delimiter this function exists to neutralize. Confirmed exploitable
/// against the pre-fix ordering; matches the upstream Python fix.
pub fn md_cell(text: &str) -> String {
    neutralize_invisible(text)
        .replace('\\', "\\\\")
        .replace('|', "\\|")
        .trim()
        .to_string()
}

/// Escape a value for embedding inside a single backtick-delimited inline
/// code span (`` `{value}` ``): fold line breaks and strip invisible or
/// bidi characters exactly as [`md_cell`] does (same row/line-breakout and
/// visual-spoofing rationale), and replace a literal backtick with the
/// visually-similar U+02CB MODIFIER LETTER GRAVE ACCENT (ˋ) so it can
/// never close the span early and let the rest of the value render as
/// raw, unintended Markdown.
///
/// A repo-controlled file path (or CMDB-supplied value, both untrusted
/// per this module's own doc comment) containing a literal backtick was
/// confirmed to break out of every inline code span this port renders one
/// into unescaped. `md_cell` alone doesn't help here, since backtick
/// isn't one of the characters it escapes; that function targets *table*
/// breakout, this one targets *code-span* breakout, and a value can need
/// either, both, or neither depending on where it's embedded.
pub fn md_code_span(text: &str) -> String {
    neutralize_invisible(text)
        .replace('`', "\u{2CB}")
        .trim()
        .to_string()
}

/// Strip (not escape) `< > \` | [ ]` from the report title — it becomes
/// literal H1 text (`# Agentic SAST — {title}`), so these characters are
/// removed outright rather than escaped.
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
        // A naive `.replace('|', "\\|")` alone turns `a\|b` into `a\\|b` —
        // which a Markdown renderer reads as a literal `\` (from `\\`)
        // followed by a BARE, unescaped `|`, breaking back out of the
        // table cell. Escaping `\` first closes this: the attacker's own
        // `\` is itself escaped before the `|`-escape ever runs, so the
        // rendered output can only ever be interpreted as an escaped
        // backslash immediately followed by an escaped pipe — never a
        // bare `|`.
        let escaped = md_cell("a\\|b");
        assert_eq!(escaped, "a\\\\\\|b");
        // Assert directly on rendering intent, not just the literal
        // bytes: split on every UNESCAPED `|` (one not preceded by an odd
        // run of backslashes) the way a table parser would — there must
        // be none inside the cell's own content.
        assert!(
            !contains_unescaped_pipe(&escaped),
            "an attacker-supplied backslash must never expose a bare, \
             table-breaking `|` in the rendered cell: {escaped:?}"
        );
    }

    #[test]
    fn contains_unescaped_pipe_detects_a_genuinely_bare_pipe() {
        // Proves the detector itself actually works, independent of
        // whether `md_cell` ever produces this shape — a self-check on
        // the test helper, not on production code.
        assert!(contains_unescaped_pipe("a|b"));
        assert!(contains_unescaped_pipe("a\\\\|b")); // even number of `\` before `|`: still bare
        assert!(!contains_unescaped_pipe("a\\|b")); // odd (one) `\`: escaped
    }

    /// Test-only stand-in for "how would a Markdown table parser read
    /// this": a `|` is escaped iff it's preceded by an odd number of
    /// consecutive backslashes.
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
        // A repo-controlled path like `foo`) [pwned](javascript:...` — if
        // embedded unescaped in `` `{path}` ``, the FIRST backtick in the
        // path closes the code span early and everything after it (here,
        // a fake Markdown link) renders as live, unintended Markdown
        // instead of literal code-span text. Confirmed exploitable
        // against every un-sanitized call site this fix touches.
        let path = "foo`) [pwned](javascript:alert(1)) (`bar";
        let rendered = format!("`{}`", md_code_span(path));
        // The rendered span must contain no backtick at all other than
        // the two delimiters this format! call itself added.
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
        // Trojan Source style: U+202E would render "DELIAF" reversed so a
        // FAILED status could visually read as something else.
        let input = "\u{202E}DELIAF\u{202C} \u{2066}x\u{2069} \u{200E}y\u{200F} \u{061C}z\u{202A}\u{202B}\u{202D}\u{2067}\u{2068}";
        assert_eq!(md_cell(input), "DELIAF x y z");
        assert_eq!(md_code_span(input), "DELIAF x y z");
    }

    #[test]
    fn md_cell_leaves_ordinary_non_ascii_text_alone() {
        assert_eq!(md_cell("café ü 漢字 \u{2065}"), "café ü 漢字 \u{2065}");
    }
}
