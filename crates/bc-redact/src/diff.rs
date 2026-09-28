//! Structure-preserving redaction of a unified diff, ported from
//! `remediation_agent/artifacts/writer.py::_redact_diff` (vvaharness
//! v1.4.0).
//!
//! **Why plain [`crate::redact`] is not enough for a diff.** Redaction
//! replaces matched text, and two of its patterns can match across line
//! boundaries: the PEM private-key block spans every line between its
//! `BEGIN` and `END` markers, and a card number may straddle a newline.
//! Collapsing several diff lines into one `[REDACTED-...]` token leaves a
//! hunk whose `@@ -a,b +c,d @@` counts no longer match its body, so
//! `git apply` refuses the patch and every diff-reading tool downstream
//! (S11's `DiffTouched`/`ChangedLines`, a PR suggestion) misreads it.
//!
//! [`redact_diff`] therefore redacts one line at a time, never touching:
//! - the file headers (`diff --git`, `index`, `---`, `+++`, mode and
//!   rename lines, binary markers),
//! - the `@@ ... @@` range header itself (trailing function context after
//!   it is still redacted),
//! - the one-character ` `/`+`/`-` prefix of every hunk line, or its line
//!   ending.
//!
//! PEM bodies are masked line by line, tracked separately for the old and
//! the new side of a hunk so a key being removed and one being added are
//! both caught, and a credential read from a safe source
//! (`password = os.environ["DB_PASSWORD"]`) is left readable, because a
//! reviewer needs to see that the fix moved the secret into configuration.
//!
//! **One deliberate divergence.** Python splits the diff with
//! `str.splitlines`, which also breaks on `\r`, `\v`, `\f` and the Unicode
//! line separators; git does not, so a source line containing any of them
//! desynchronized Python's hunk counting. This port splits on `\n` only
//! (keeping a `\r\n` ending intact), which is exactly git's own framing.

use std::sync::LazyLock;

use fancy_regex::Regex;

use crate::{re, redact};

static HUNK_HEADER_RE: LazyLock<Regex> =
    LazyLock::new(|| re(r"^@@ -\d+(?:,(?P<old>\d+))? \+\d+(?:,(?P<new>\d+))? @@"));

/// Lines outside (or ending) a hunk that are diff framing, not content.
const DIFF_STRUCTURE_PREFIXES: [&str; 19] = [
    "diff --git ",
    "index ",
    "--- ",
    "+++ ",
    "old mode ",
    "new mode ",
    "new file mode ",
    "deleted file mode ",
    "similarity index ",
    "dissimilarity index ",
    "rename from ",
    "rename to ",
    "copy from ",
    "copy to ",
    "Binary files ",
    "GIT binary patch",
    "literal ",
    "delta ",
    "# (synthesized diff ",
];

static SAFE_CONFIG_READ_RE: LazyLock<Regex> = LazyLock::new(|| {
    re(concat!(
        r#"(?:\bos\.environ\[\s*['"][A-Z_][A-Z0-9_]*['"]\s*\]"#,
        r#"|\bos\.(?:environ\.get|getenv)\(\s*['"][A-Z_][A-Z0-9_]*['"]\s*\)"#,
        r#"|\b(?:config|settings|secrets)\[\s*['"][A-Z_][A-Z0-9_.-]*['"]\s*\]"#,
        r#"|\b(?:config|settings)\.[A-Z_][A-Z0-9_]*\b"#,
        r#"|\bprocess\.env(?:\.[A-Z_][A-Z0-9_]*"#,
        r#"|\[\s*['"][A-Z_][A-Z0-9_]*['"]\s*\]))"#,
    ))
});

static SECRET_ASSIGNMENT_PREFIX_RE: LazyLock<Regex> = LazyLock::new(|| {
    re(concat!(
        r"(?i)(?:\b|(?<=[a-z])|(?<=_))(?:pass(?:word|wd)?|pwd|secret|",
        r"api[_-]?key|access[_-]?key|client[_-]?secret|auth[_-]?token|token|",
        r#"credential)s?\b['"`]?\s*[:=]\s*$"#,
    ))
});

static SAFE_CONFIG_SUFFIX_RE: LazyLock<Regex> =
    LazyLock::new(|| re(r"^\s*[)\]}]*[,;]?\s*(?:(?:#|//).*)?$"));

static PEM_BOUNDARY_RE: LazyLock<Regex> =
    LazyLock::new(|| re(r"-{5}(?:BEGIN|END) [A-Z0-9 ]*PRIVATE KEY-{5}"));

static PEM_HEADER_RE: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)^(?:Proc-Type|DEK-Info):"));

static PEM_FRAGMENT_RE: LazyLock<Regex> =
    LazyLock::new(|| re(r#"^\s*["'`]?(?P<body>[A-Za-z0-9+/]{2,}={0,2})["'`]?[;,]?\s*$"#));

static PEM_WRAPPED_FRAGMENT_RE: LazyLock<Regex> = LazyLock::new(|| {
    re(r#"(?:["'`]|>\s*)(?P<body>[A-Za-z0-9+/]{2,}={0,2})(?=(?:\\[rn])?(?:["'`]|<))"#)
});

static PEM_SHORT_CONTEXT_RE: LazyLock<Regex> = LazyLock::new(|| {
    re(concat!(
        r"(?i)(?:<(?:[A-Za-z0-9_.-]+:)?(?:private[-_]?key|pem(?:[-_]?key)?|",
        r"key(?:data|value|material)?)(?:\s[^>]*)?>\s*",
        r"[A-Za-z0-9+/]{4,}={0,2}<",
        r#"|(?:private[-_]?key|pem(?:[-_]?key)?)\s*["'`]?\s*[:=]\s*"#,
        r#"["'`][A-Za-z0-9+/]{4,}={0,2}(?:\\[rn])?["'`])"#,
    ))
});

const PRIVATE_KEY_MASK: &str = "[REDACTED-PRIVATE-KEY]";

/// `is_match` that fails closed to "matched": every caller below uses a
/// match to decide to MASK, so a backtrack-limit error must never be read
/// as "nothing sensitive here".
fn hit(regex: &Regex, text: &str) -> bool {
    regex.is_match(text).unwrap_or(true)
}

/// Splits one physical line into content and its exact line ending.
fn line_parts(line: &str) -> (&str, &str) {
    if let Some(content) = line.strip_suffix("\r\n") {
        (content, "\r\n")
    } else if let Some(content) = line.strip_suffix('\n') {
        (content, "\n")
    } else {
        (line, "")
    }
}

/// `(start, end, payload)` of every base64-looking PEM payload in `body`:
/// a bare fragment filling the line, and any quoted or tag-wrapped one.
fn private_key_payloads(body: &str) -> Vec<(usize, usize, String)> {
    let mut out: Vec<(usize, usize, String)> = Vec::new();
    let bare = PEM_FRAGMENT_RE.captures(body).ok().flatten();
    let wrapped = PEM_WRAPPED_FRAGMENT_RE
        .captures_iter(body)
        .map_while(Result::ok);
    for caps in bare.into_iter().chain(wrapped) {
        let m = caps
            .name("body")
            .expect("both patterns define the body group");
        let entry = (m.start(), m.end(), m.as_str().to_string());
        if !out.contains(&entry) {
            out.push(entry);
        }
    }
    out
}

fn short_private_key_fragment(body: &str) -> bool {
    private_key_payloads(body)
        .iter()
        .any(|(_, _, p)| p.len() >= 4 && p.len() % 4 == 0)
}

/// Conservative recognition of a PEM payload fragment with no delimiter
/// on its own line (`_private_key_fragment`).
fn private_key_fragment(body: &str, continuation: bool) -> bool {
    if hit(&PEM_HEADER_RE, body.trim()) {
        return true;
    }
    let explicit_context = hit(&PEM_SHORT_CONTEXT_RE, body);
    private_key_payloads(body).iter().any(|(_, _, p)| {
        p.starts_with("MII")
            || p.starts_with("MHc")
            || p.starts_with("MIG")
            || p.len() >= 24
            || ((continuation || explicit_context) && p.len() % 4 == 0)
    })
}

/// Replaces every PEM boundary and payload span in `body` with the mask,
/// or the whole body when there is nothing more specific to replace.
/// Overlapping spans are merged first, so the result is well formed
/// whatever order the patterns matched in.
fn mask_private_key_body(body: &str) -> String {
    let mut spans: Vec<(usize, usize)> = PEM_BOUNDARY_RE
        .find_iter(body)
        .map_while(Result::ok)
        .map(|m| (m.start(), m.end()))
        .chain(
            private_key_payloads(body)
                .into_iter()
                .map(|(s, e, _)| (s, e)),
        )
        .collect();
    if spans.is_empty() {
        return PRIVATE_KEY_MASK.to_string();
    }
    spans.sort_unstable();
    let mut out = String::with_capacity(body.len());
    let mut cursor = 0usize;
    // A span that starts inside the previous mask extends it; one wholly
    // inside the previous mask adds nothing.
    for (start, end) in spans {
        if start >= cursor {
            out.push_str(&body[cursor..start]);
            out.push_str(PRIVATE_KEY_MASK);
        }
        cursor = cursor.max(end);
    }
    out.push_str(&body[cursor..]);
    out
}

/// Masks an already-emitted hunk line's body as a private key, keeping
/// its prefix character and ending (`_mask_diff_line`).
fn mask_diff_line(line: &str) -> String {
    let (content, ending) = line_parts(line);
    let split = content.chars().next().map_or(0, char::len_utf8);
    format!(
        "{}{}{ending}",
        &content[..split],
        mask_private_key_body(&content[split..])
    )
}

/// [`redact`], except a credential assignment whose value is a read from
/// a safe configuration source survives intact (`_redact_diff_text`).
fn redact_diff_text(text: &str) -> String {
    let safe: Vec<(usize, usize)> = SAFE_CONFIG_READ_RE
        .find_iter(text)
        .map_while(Result::ok)
        .filter(|m| {
            SECRET_ASSIGNMENT_PREFIX_RE
                .is_match(&text[..m.start()])
                .unwrap_or(false)
                && SAFE_CONFIG_SUFFIX_RE
                    .is_match(&text[m.end()..])
                    .unwrap_or(false)
        })
        .map(|m| (m.start(), m.end()))
        .collect();
    if safe.is_empty() {
        return redact(text);
    }
    // Swap each safe read for a `${NAME}` marker, which `redact` treats as
    // a template placeholder and leaves alone, then swap them back.
    let mut protected = text.to_string();
    let mut replacements: Vec<(String, &str)> = Vec::new();
    for (index, &(start, end)) in safe.iter().enumerate().rev() {
        let mut marker = format!("${{BCSAST_SAFE_CONFIG_READ_{index}}}");
        while text.contains(&marker) {
            marker.insert(marker.len() - 1, '_');
        }
        protected.replace_range(start..end, &marker);
        replacements.push((marker, &text[start..end]));
    }
    let mut masked = redact(&protected);
    for (marker, source) in replacements {
        masked = masked.replace(&marker, source);
    }
    masked
}

fn redact_unstructured(text: &str, continuation: bool) -> String {
    if hit(&PEM_BOUNDARY_RE, text) || private_key_fragment(text, continuation) {
        redact_diff_text(&mask_private_key_body(text))
    } else {
        redact_diff_text(text)
    }
}

/// Per-side PEM tracking inside one hunk.
#[derive(Default, Clone, Copy)]
struct Side {
    remaining: usize,
    in_private_key: bool,
    fragment: bool,
    /// Index in the output of a short fragment line that turns out to be a
    /// key body only once its `END` marker arrives.
    pending: Option<usize>,
}

impl Side {
    fn reset_tracking(&mut self) {
        self.in_private_key = false;
        self.fragment = false;
        self.pending = None;
    }
}

fn is_structure(line: &str) -> bool {
    DIFF_STRUCTURE_PREFIXES.iter().any(|p| line.starts_with(p))
}

/// Redacts a unified diff's hunk payloads while keeping its framing and
/// line endings byte-for-byte, so the result still parses (and still
/// applies, when nothing on a line needed masking) as the same patch. See
/// the module doc comment.
pub fn redact_diff(diff: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut old = Side::default();
    let mut new = Side::default();

    for physical in diff.split_inclusive('\n') {
        let (line, ending) = line_parts(physical);
        if let Some(caps) = HUNK_HEADER_RE.captures(line).ok().flatten() {
            let count = |name: &str| {
                caps.name(name)
                    .map_or(1, |m| m.as_str().parse().unwrap_or(usize::MAX))
            };
            old = Side {
                remaining: count("old"),
                ..Side::default()
            };
            new = Side {
                remaining: count("new"),
                ..Side::default()
            };
            let end = caps.get(0).expect("group 0 always matches").end();
            out.push(format!(
                "{}{}{ending}",
                &line[..end],
                redact_unstructured(&line[end..], false)
            ));
            continue;
        }

        let in_hunk = old.remaining > 0 || new.remaining > 0;
        if let Some(note) = line.strip_prefix('\\') {
            out.push(format!("\\{}{ending}", redact_diff_text(note)));
            continue;
        }

        if !in_hunk {
            old.reset_tracking();
            new.reset_tracking();
            if is_structure(line) {
                out.push(physical.to_string());
            } else {
                out.push(format!("{}{ending}", redact_unstructured(line, false)));
            }
            continue;
        }

        let prefix = line.chars().next();
        let (old_line, new_line) = match prefix {
            Some(' ') => (true, true),
            Some('-') => (true, false),
            Some('+') => (false, true),
            _ => {
                if is_structure(line) {
                    old = Side::default();
                    new = Side::default();
                    out.push(physical.to_string());
                } else {
                    // Unknown in-hunk input is content, not proof the hunk
                    // ended: stay in the safe (masking) state.
                    let continuation = old.in_private_key || new.in_private_key;
                    out.push(format!(
                        "{}{ending}",
                        redact_unstructured(line, continuation)
                    ));
                }
                continue;
            }
        };

        let body = &line[1..];
        let boundary = hit(&PEM_BOUNDARY_RE, body);
        let begins = body.contains("-----BEGIN ") && body.contains("PRIVATE KEY-----");
        let ends = body.contains("-----END ") && body.contains("PRIVATE KEY-----");
        if ends {
            let mut pending: Vec<usize> = Vec::new();
            pending.extend(old.pending.filter(|_| old_line));
            pending.extend(new.pending.filter(|_| new_line));
            pending.dedup();
            for index in pending {
                out[index] = mask_diff_line(&out[index]);
            }
        }

        let continuation = (old_line && old.fragment) || (new_line && new.fragment);
        let fragment = private_key_fragment(body, continuation);
        let mask = boundary
            || fragment
            || (old_line && old.in_private_key)
            || (new_line && new.in_private_key);
        let safe_body = if mask {
            mask_private_key_body(body)
        } else {
            redact_diff_text(body)
        };
        out.push(format!("{}{safe_body}{ending}", &line[..1]));
        let index = out.len() - 1;
        let short = short_private_key_fragment(body);

        for (is_side, side) in [(old_line, &mut old), (new_line, &mut new)] {
            if !is_side {
                continue;
            }
            side.in_private_key = (side.in_private_key || begins) && !ends;
            side.fragment = fragment && !ends;
            side.pending = (short && !ends).then_some(index);
            side.remaining = side.remaining.saturating_sub(1);
        }
        if old.remaining == 0 && new.remaining == 0 {
            old.reset_tracking();
            new.reset_tracking();
        }
    }
    out.concat()
}

#[cfg(test)]
mod tests;
