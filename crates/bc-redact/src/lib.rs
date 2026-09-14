//! Sensitive-data redaction for emitted reports (Markdown + SARIF) and any
//! tool output that re-enters LLM context.
//!
//! Applied at every write/log/tool-output boundary so card data, PII and
//! credential material that the model quoted from source never lands in an
//! on-disk report or gets echoed back into a prompt.
//!
//! Design goals (ported from the Python reference implementation):
//! - High precision (low false-positive rate): card numbers are Luhn +
//!   IIN-gated, SSNs are area/group/serial-gated, generic secrets are
//!   keyword-gated.
//! - String-in / string-out: callers pass the fully rendered text, so every
//!   field is covered without enumerating them.
//! - No shared mutable state: unlike the Python original's non-thread-safe
//!   `redact.last_counts` side channel, [`redact_counts`] always returns
//!   counts directly, so it's safe to call from concurrent stages.
//!
//! Digit classes (PAN/SSN/CVV) are deliberately restricted to ASCII `0-9`
//! rather than Python's Unicode-decimal-digit-aware `\d` — real payment
//! card and SSN data in source code or LLM narrative is always ASCII, and
//! keeping the whole PAN/SSN pipeline internally ASCII-only avoids relying
//! on Unicode digit-category semantics that would need per-engine
//! verification. Structural separators (`\s`, `\w`) remain Unicode-aware,
//! matching Python's default behaviour.

use std::collections::HashMap;
use std::sync::LazyLock;

use fancy_regex::{Captures, Regex};

/// Per-label hit counts from a redaction pass.
pub type Counts = HashMap<String, u32>;

/// Redact `text` and discard the hit counts. Use [`redact_counts`] when the
/// counts are needed (e.g. for logging how much was masked).
pub fn redact(text: &str) -> String {
    redact_counts(text).0
}

/// Redact `text`, returning the masked text and per-label hit counts.
/// Pure and stateless — safe to call from concurrent stages (e.g. parallel
/// deep-dive chunks, an agentic tool loop scrubbing outbound tool output).
pub fn redact_counts(text: &str) -> (String, Counts) {
    if text.is_empty() {
        return (String::new(), Counts::new());
    }
    // NUL is reserved as the in-band placeholder sentinel below. Strip any
    // NUL already present so a literal sentinel-shaped sequence in the
    // input can't collide with the reinsertion pass.
    let cleaned: String = if text.contains('\u{0}') {
        text.chars().filter(|&c| c != '\u{0}').collect()
    } else {
        text.to_string()
    };

    let mut r = Redactor::default();
    let mut out = cleaned;
    out = step_pan(&out, &mut r);
    out = step_cvv(&out, &mut r);
    out = step_track(&out, &mut r);
    out = step_ssn(&out, &mut r);
    out = step_ssn_ctx(&out, &mut r);
    out = step_aws_key(&out, &mut r);
    out = step_github_token(&out, &mut r);
    out = step_slack_token(&out, &mut r);
    out = step_stripe_key(&out, &mut r);
    out = step_google_api_key(&out, &mut r);
    out = step_azure_sas(&out, &mut r);
    out = step_twilio_key(&out, &mut r);
    out = step_jwt(&out, &mut r);
    out = step_bearer(&out, &mut r);
    out = step_url_cred(&out, &mut r);
    out = step_private_key(&out, &mut r);
    out = step_secret(&out, &mut r);

    if !r.placeholders.is_empty() {
        out = reinsert_placeholders(&out, &r.placeholders);
    }
    (out, r.counts)
}

/// Recursively redact every string leaf in a JSON-serializable structure.
/// Call this *before* serializing so redaction never sees (or corrupts)
/// escape sequences that a serializer would otherwise introduce.
pub fn redact_tree(value: &serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), redact_tree(v)))
                .collect(),
        ),
        Value::Array(arr) => Value::Array(arr.iter().map(redact_tree).collect()),
        Value::String(s) => Value::String(redact(s)),
        other => other.clone(),
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Redactor: accumulates placeholders + counts across all pattern passes.
// ─────────────────────────────────────────────────────────────────────────

#[derive(Default)]
struct Redactor {
    placeholders: Vec<String>,
    counts: Counts,
}

impl Redactor {
    /// Record a hit for `label` and return the NUL-wrapped sentinel to
    /// splice into the running text; the real `[REDACTED-LABEL]` text is
    /// reinserted once, after all patterns have run.
    fn mask(&mut self, label: &str) -> String {
        *self.counts.entry(label.to_string()).or_insert(0) += 1;
        self.placeholders.push(format!("[REDACTED-{label}]"));
        format!("\u{0}{}\u{0}", self.placeholders.len() - 1)
    }
}

fn reinsert_placeholders(text: &str, placeholders: &[String]) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0usize;
    while i < chars.len() {
        if chars[i] != '\u{0}' {
            out.push(chars[i]);
            i += 1;
            continue;
        }
        let Some(rel_end) = chars[i + 1..].iter().position(|&c| c == '\u{0}') else {
            // No closing NUL: leave the rest untouched (defensive — should
            // not occur, since every sentinel we emit is well-formed).
            out.push(chars[i]);
            i += 1;
            continue;
        };
        let end = i + 1 + rel_end;
        let digits: String = chars[i + 1..end].iter().collect();
        let idx = (!digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit()))
            .then(|| digits.parse::<usize>().ok())
            .flatten();
        match idx.filter(|&i| i < placeholders.len()) {
            Some(idx) => {
                out.push_str(&placeholders[idx]);
                i = end + 1;
            }
            // Out-of-range/malformed index: can only come from a sentinel
            // collision, which is precluded by the NUL-strip above — kept
            // as a defensive fallback, matching the Python original.
            None => {
                out.push(chars[i]);
                i += 1;
            }
        }
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────
// Shared scan-and-splice helper.
// ─────────────────────────────────────────────────────────────────────────

/// Apply `re` to `text`, replacing each match with whatever `f` returns.
/// `f` receives the matched substring, its captures, and the shared
/// [`Redactor`] state. Fails open per-pattern (keeps the remaining text
/// unchanged) if the backtracking engine ever errors on a match attempt —
/// none of the patterns below have the nested-quantifier shape that would
/// make that likely, but redaction must never panic at a write boundary.
fn replace_matches(
    text: &str,
    re: &Regex,
    mut f: impl FnMut(&str, &Captures, &mut Redactor) -> String,
    r: &mut Redactor,
) -> String {
    let mut out = String::with_capacity(text.len());
    let mut last = 0usize;
    for caps in re.captures_iter(text) {
        let Ok(caps) = caps else { break };
        let m = caps.get(0).expect("group 0 always matches");
        out.push_str(&text[last..m.start()]);
        out.push_str(&f(m.as_str(), &caps, r));
        last = m.end();
    }
    out.push_str(&text[last..]);
    out
}

fn step_generic(
    text: &str,
    re: &Regex,
    label: &str,
    validate: impl Fn(&str, &Captures) -> bool,
    r: &mut Redactor,
) -> String {
    replace_matches(
        text,
        re,
        |full, caps, r| {
            if validate(full, caps) {
                r.mask(label)
            } else {
                full.to_string()
            }
        },
        r,
    )
}

fn re(pattern: &str) -> Regex {
    Regex::new(pattern)
        .unwrap_or_else(|e| panic!("invalid static redaction pattern: {e}\n{pattern}"))
}

// ─────────────────────────────────────────────────────────────────────────
// Validators
// ─────────────────────────────────────────────────────────────────────────

/// Luhn check-digit validator. Public so a stage-specific partial-PAN
/// mask (e.g. S4's own layer-1 "keep the BIN prefix" masker, distinct from
/// this crate's full-blot redaction) can reuse the same check-digit math
/// rather than re-implementing/re-validating it.
pub fn luhn(digits: &str) -> bool {
    let mut total = 0u32;
    let mut odd = true;
    for ch in digits.chars().rev() {
        let mut n = ch.to_digit(10).unwrap_or(0);
        if !odd {
            n *= 2;
            if n > 9 {
                n -= 9;
            }
        }
        total += n;
        odd = !odd;
    }
    total.is_multiple_of(10)
}

/// IIN/BIN gate so a random Luhn-passing digit string isn't masked.
fn cc_network(digits: &str) -> bool {
    let n = digits.len();
    if !(12..=19).contains(&n) {
        return false;
    }
    let p1 = digits.as_bytes()[0];
    let p2: i64 = digits[0..2].parse().unwrap_or(-1);
    let p3: i64 = digits[0..3].parse().unwrap_or(-1);
    let p4: i64 = digits[0..4].parse().unwrap_or(-1);
    (n == 15 && (p2 == 34 || p2 == 37)) // Amex
        || (p1 == b'4' && (13..=19).contains(&n)) // Visa
        || (n == 16 && ((51..=55).contains(&p2) || (2221..=2720).contains(&p4))) // Mastercard
        || ((16..=19).contains(&n) && (p4 == 6011 || p2 == 65 || (644..=649).contains(&p3))) // Discover
        || ((16..=19).contains(&n) && (3528..=3589).contains(&p4)) // JCB
        || ((16..=19).contains(&n) && p2 == 62) // UnionPay
        || ((14..=19).contains(&n) && p2 == 36) // Diners
        || ((12..=19).contains(&n)
            && [5018, 5020, 5038, 5893, 6304, 6759, 6761, 6762, 6763].contains(&p4)) // Maestro
        || (n == 16 && (p3 == 508 || p2 == 81 || p2 == 82)) // RuPay
}

/// Reject only structurally-impossible SSN groupings (area 000/666, group
/// 00, serial 0000). Area 900-999 (the ITIN range) is deliberately
/// ALLOWED through this gate and masked — sensitive taxpayer-id PII.
fn ssn_valid(d: &str) -> bool {
    let a: u32 = d[0..3].parse().unwrap_or(0);
    let g: u32 = d[3..5].parse().unwrap_or(0);
    let s: u32 = d[5..9].parse().unwrap_or(0);
    !(a == 0 || a == 666 || g == 0 || s == 0)
}

/// True only when the post-scheme value looks like a real bearer/basic
/// token rather than prose (e.g. "HTTP Basic Authentication" would
/// otherwise false-positive on the all-alphabetic word "Authentication").
fn bearer_credential(bv: &str) -> bool {
    bv.chars().any(|c| !c.is_alphabetic())
}

static SECRET_CODE_SHAPE_RE: LazyLock<Regex> =
    LazyLock::new(|| re(r"^\(|^[A-Za-z_]\w*\(|^[A-Za-z_]\w*\.\w"));

// ─────────────────────────────────────────────────────────────────────────
// Pattern steps, applied in this exact order (later patterns must not
// re-capture an earlier pattern's sentinel, hence \x00 exclusion in SECRET).
// ─────────────────────────────────────────────────────────────────────────

static PAN_RE: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?<![0-9A-Za-z./_-])(?:[0-9][\s\-]?){12,18}[0-9](?![0-9A-Za-z./_-])"));

fn step_pan(text: &str, r: &mut Redactor) -> String {
    step_generic(
        text,
        &PAN_RE,
        "PAN",
        |full, _| {
            let digits: String = full.chars().filter(char::is_ascii_digit).collect();
            cc_network(&digits) && luhn(&digits)
        },
        r,
    )
}

static CVV_RE: LazyLock<Regex> =
    LazyLock::new(|| re(r#"(?i)\b(cvv2?|cvc2?|cid|csc)\b\s*[:=]?\s*"?([0-9]{3,4})"?"#));

fn step_cvv(text: &str, r: &mut Redactor) -> String {
    replace_matches(
        text,
        &CVV_RE,
        |full, caps, r| {
            let m0 = caps.get(0).unwrap();
            let g2 = caps.get(2).unwrap();
            let head = &full[..g2.start() - m0.start()];
            format!("{head}{}", r.mask("CVV"))
        },
        r,
    )
}

static TRACK_RE: LazyLock<Regex> = LazyLock::new(|| re(r"%B[0-9]{12,19}\^[^?]{2,90}\?"));

fn step_track(text: &str, r: &mut Redactor) -> String {
    step_generic(text, &TRACK_RE, "TRACK", |_, _| true, r)
}

static SSN_RE: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?<![0-9])([0-9]{3})[-.\t \u{00a0}\u{2009}\u{202f}\u{2007}]([0-9]{2})[-.\t \u{00a0}\u{2009}\u{202f}\u{2007}]([0-9]{4})(?![0-9])",
    )
});

fn step_ssn(text: &str, r: &mut Redactor) -> String {
    step_generic(
        text,
        &SSN_RE,
        "SSN",
        |_, caps| {
            let d1 = caps.get(1).unwrap().as_str();
            let d2 = caps.get(2).unwrap().as_str();
            let d3 = caps.get(3).unwrap().as_str();
            ssn_valid(&format!("{d1}{d2}{d3}"))
        },
        r,
    )
}

static SSN_CTX_RE: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r#"(?i)\b(ssn|social[\s_-]*sec(?:urity)?(?:[\s_-]*(?:no|num|number))?|itin|tin|taxpayer[\s_-]*id)\b['"]?\s*[:=#-]?\s*['"]?(?<![0-9])([0-9]{9})(?![0-9])"#,
    )
});

fn step_ssn_ctx(text: &str, r: &mut Redactor) -> String {
    replace_matches(
        text,
        &SSN_CTX_RE,
        |full, caps, r| {
            let m0 = caps.get(0).unwrap();
            let g2 = caps.get(2).unwrap();
            if !ssn_valid(g2.as_str()) {
                return full.to_string();
            }
            let head = &full[..g2.start() - m0.start()];
            format!("{head}{}", r.mask("SSN"))
        },
        r,
    )
}

static AWS_KEY_RE: LazyLock<Regex> =
    LazyLock::new(|| re(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\b"));
fn step_aws_key(text: &str, r: &mut Redactor) -> String {
    step_generic(text, &AWS_KEY_RE, "AWS-KEY", |_, _| true, r)
}

static GITHUB_TOKEN_RE: LazyLock<Regex> = LazyLock::new(|| {
    re(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22}_[A-Za-z0-9]{59})\b")
});
fn step_github_token(text: &str, r: &mut Redactor) -> String {
    step_generic(text, &GITHUB_TOKEN_RE, "GITHUB-TOKEN", |_, _| true, r)
}

static SLACK_TOKEN_RE: LazyLock<Regex> =
    LazyLock::new(|| re(r"\bxox[baprs]-[A-Za-z0-9-]{10,72}\b"));
fn step_slack_token(text: &str, r: &mut Redactor) -> String {
    step_generic(text, &SLACK_TOKEN_RE, "SLACK-TOKEN", |_, _| true, r)
}

static STRIPE_KEY_RE: LazyLock<Regex> =
    LazyLock::new(|| re(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24,99}\b"));
fn step_stripe_key(text: &str, r: &mut Redactor) -> String {
    step_generic(text, &STRIPE_KEY_RE, "STRIPE-KEY", |_, _| true, r)
}

static GOOGLE_API_KEY_RE: LazyLock<Regex> = LazyLock::new(|| re(r"\bAIza[0-9A-Za-z_-]{35}\b"));
fn step_google_api_key(text: &str, r: &mut Redactor) -> String {
    step_generic(text, &GOOGLE_API_KEY_RE, "GOOGLE-API-KEY", |_, _| true, r)
}

static AZURE_SAS_RE: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)\bsig=[0-9A-Za-z%+/=]{20,}\b"));
fn step_azure_sas(text: &str, r: &mut Redactor) -> String {
    step_generic(text, &AZURE_SAS_RE, "AZURE-SAS", |_, _| true, r)
}

static TWILIO_KEY_RE: LazyLock<Regex> = LazyLock::new(|| re(r"\bSK[0-9a-fA-F]{32}\b"));
fn step_twilio_key(text: &str, r: &mut Redactor) -> String {
    step_generic(text, &TWILIO_KEY_RE, "TWILIO-KEY", |_, _| true, r)
}

static JWT_RE: LazyLock<Regex> =
    LazyLock::new(|| re(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"));
fn step_jwt(text: &str, r: &mut Redactor) -> String {
    step_generic(text, &JWT_RE, "JWT", |_, _| true, r)
}

static BEARER_RE: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?i)\b(?:Bearer|Basic)\s+(?P<bv>[A-Za-z0-9+/=._-]{8,})\b"));
fn step_bearer(text: &str, r: &mut Redactor) -> String {
    step_generic(
        text,
        &BEARER_RE,
        "BEARER",
        |_, caps| bearer_credential(caps.name("bv").unwrap().as_str()),
        r,
    )
}

static URL_CRED_RE: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?i)\b([a-z][a-z0-9+.\-]*://[^\s:/@]+:)([^\s/@]{1,256})@"));
fn step_url_cred(text: &str, r: &mut Redactor) -> String {
    replace_matches(
        text,
        &URL_CRED_RE,
        |_, caps, r| {
            let g1 = caps.get(1).unwrap().as_str();
            format!("{g1}{}@", r.mask("URL-CRED"))
        },
        r,
    )
}

static PRIVATE_KEY_RE: LazyLock<Regex> =
    LazyLock::new(|| re(r"-{5}BEGIN [A-Z ]*PRIVATE KEY-{5}[\s\S]*?-{5}END [A-Z ]*PRIVATE KEY-{5}"));
fn step_private_key(text: &str, r: &mut Redactor) -> String {
    step_generic(text, &PRIVATE_KEY_RE, "PRIVATE-KEY", |_, _| true, r)
}

const STRONG_SECRET_KEYWORDS: [&str; 7] = [
    "password",
    "passwd",
    "pwd",
    "apikey",
    "accesskey",
    "clientsecret",
    "authtoken",
];

static SECRET_RE: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r#"(?i)(?:\b|(?<=[a-z]))(pass(?:word|wd)?|pwd|secret|api[_-]?key|access[_-]?key|client[_-]?secret|auth[_-]?token|token|credential)s?\b['"`]?\s*[:=]\s*(?P<q>['"`]?)(?P<v>[^\s'"`,;\x00]{6,256})\k<q>"#,
    )
});

/// Values that look like a template placeholder / env-var reference / boolean
/// / obviously-fake sentinel rather than a real secret — the SECRET pattern
/// must not mask these (checked, full-match, before any of the plain-word or
/// code-shape carve-outs below).
static SECRET_PLACEHOLDER_RE: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)^(?:\$\{?[A-Z0-9_.]+\}?|%[A-Z0-9_]+%|<[^>]+>|\*{3,}|x{3,}|\[?redacted\]?|\[redacted-[a-z0-9-]+\]|null|none|true|false|changeme|your[_-]?\w+|placeholder|example)$",
    )
});

fn step_secret(text: &str, r: &mut Redactor) -> String {
    replace_matches(
        text,
        &SECRET_RE,
        |full, caps, r| {
            let m0 = caps.get(0).unwrap();
            let v_match = caps.name("v").unwrap();
            let q_match = caps.name("q").unwrap();
            let v = v_match.as_str();
            let quoted = !q_match.as_str().is_empty();

            // Fail-closed here too: if the placeholder check itself errors,
            // don't grant the "leave unmasked" carve-out.
            if SECRET_PLACEHOLDER_RE.is_match(v).unwrap_or(false) {
                return full.to_string();
            }

            let stripped = v.trim_end_matches(|c| ").}]!?>".contains(c));
            let mut v_core = if quoted || stripped.is_empty() {
                v
            } else {
                stripped
            };
            if v_core.chars().count() < 6 {
                v_core = v;
            }

            let keyword: String = caps
                .get(1)
                .unwrap()
                .as_str()
                .to_lowercase()
                .chars()
                .filter(char::is_ascii_lowercase)
                .collect();
            let generic_unquoted = !STRONG_SECRET_KEYWORDS.contains(&keyword.as_str()) && !quoted;
            let plain_word = generic_unquoted
                && !v_core.is_empty()
                && v_core.chars().all(char::is_alphabetic)
                && v_core.chars().all(|c| !c.is_uppercase())
                && v_core.chars().count() < 20;
            // Fail-closed: if the code-shape check itself errors, don't
            // grant the "leave unmasked" carve-out — mask by default.
            let code_shape =
                generic_unquoted && SECRET_CODE_SHAPE_RE.is_match(v_core).unwrap_or(false);

            if plain_word || code_shape {
                return full.to_string();
            }

            let head = &full[..v_match.start() - m0.start()];
            let tail_from_v = &v[v_core.len()..];
            let tail_rest = &full[v_match.end() - m0.start()..];
            format!("{head}{}{tail_from_v}{tail_rest}", r.mask("SECRET"))
        },
        r,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    // ── validators ──────────────────────────────────────────────────────

    #[test]
    fn luhn_accepts_valid_check_digit() {
        assert!(luhn("4111111111111111"));
        assert!(luhn("378282246310005"));
    }

    #[test]
    fn luhn_rejects_bad_check_digit() {
        assert!(!luhn("4111111111111112"));
        assert!(!luhn("1234567890123456"));
    }

    #[rstest]
    #[case("4111111111111111", true)] // Visa 16
    #[case("5555555555554444", true)] // Mastercard
    #[case("2223003122003222", true)] // Mastercard 2221-2720
    #[case("378282246310005", true)] // Amex
    #[case("9000000000000001", false)] // no assigned IIN
    fn cc_network_gates_by_iin(#[case] digits: &str, #[case] expected: bool) {
        assert_eq!(cc_network(digits), expected);
    }

    #[test]
    fn cc_network_length_bounds() {
        assert!(!cc_network("41111"));
        assert!(!cc_network(&("4".to_string() + &"1".repeat(19))));
    }

    #[rstest]
    #[case("078051120", true)]
    #[case("000051120", false)]
    #[case("666051120", false)]
    #[case("078001120", false)]
    #[case("078050000", false)]
    #[case("900051120", true)] // ITIN range allowed through
    #[case("936184524", true)]
    #[case("961080047", true)]
    fn ssn_valid_gate(#[case] d: &str, #[case] expected: bool) {
        assert_eq!(ssn_valid(d), expected);
    }

    #[test]
    fn bearer_credential_requires_non_alpha() {
        assert!(!bearer_credential("Authentication"));
        assert!(bearer_credential("abc123DEF"));
    }

    #[test]
    fn re_helper_panics_on_invalid_pattern() {
        let result = std::panic::catch_unwind(|| re("(unclosed"));
        assert!(result.is_err());
    }

    // ── TRACK (magnetic-stripe) ─────────────────────────────────────────

    #[test]
    fn track_data_masked() {
        let out = redact("swipe: %B4111111111111111^DOE/JOHN^25121010000000000000?");
        assert!(!out.contains("4111111111111111"));
        assert!(out.contains("[REDACTED-TRACK]"));
    }

    // ── CVV ─────────────────────────────────────────────────────────────

    #[rstest]
    #[case("cvv: 123", "123")]
    #[case("CVC2 1234", "1234")]
    #[case("csc=999", "999")]
    fn cvv_value_masked_keyword_preserved(#[case] text: &str, #[case] value: &str) {
        let out = redact(text);
        assert!(!out.contains(value));
        assert!(out.contains("[REDACTED-CVV]"));
    }

    // ── PAN ─────────────────────────────────────────────────────────────

    #[rstest]
    #[case("4111111111111111")]
    #[case("4111 1111 1111 1111")]
    #[case("5555555555554444")]
    #[case("378282246310005")]
    fn valid_pan_is_masked(#[case] pan: &str) {
        let out = redact(&format!("the card is {pan} on file"));
        assert!(!out.replace(' ', "").contains(&pan.replace(' ', "")));
        assert!(out.contains("[REDACTED-PAN]"));
    }

    #[test]
    fn random_16_digits_not_masked() {
        let text = "trace id 9000000000000001 here";
        assert_eq!(redact(text), text);
    }

    #[test]
    fn non_luhn_pan_not_masked() {
        let text = "card 4111111111111112 invalid";
        assert_eq!(redact(text), text);
    }

    // ── SSN ─────────────────────────────────────────────────────────────

    #[test]
    fn itin_9xx_is_masked() {
        let out = redact("itin 936-18-4524 and 961-08-0047 on file");
        assert!(!out.contains("936-18-4524"));
        assert!(!out.contains("961-08-0047"));
        let (_, counts) = redact_counts("itin 936-18-4524 and 961-08-0047 on file");
        assert_eq!(counts.get("SSN"), Some(&2));
    }

    #[rstest]
    #[case("078-05-1120")]
    #[case("078 05 1120")]
    #[case("078.05.1120")]
    #[case("078\t05\t1120")]
    fn ssn_separator_variants_masked(#[case] sep_value: &str) {
        let out = redact(&format!("value {sep_value} here"));
        assert!(!out.contains(sep_value));
        assert!(out.contains("[REDACTED-SSN]"));
    }

    #[rstest]
    #[case("ssn=078051120")]
    #[case("SSN: 078051120")]
    #[case("social_security_number = 078051120")]
    #[case("taxpayer-id 078051120")]
    #[case("itin: 936184524")]
    fn keyworded_bare_ssn_masked(#[case] text: &str) {
        let out = redact(text);
        assert!(!out.contains("078051120") && !out.contains("936184524"));
        assert!(out.contains("[REDACTED-SSN]"));
    }

    #[test]
    fn bare_9_digits_without_keyword_not_masked() {
        for text in [
            "trace id 123456789 logged",
            "order 078051120 shipped",
            "count = 936184524",
        ] {
            assert_eq!(redact(text), text);
        }
    }

    #[test]
    fn invalid_ssn_area_not_masked() {
        let text = "ref 666-05-1120 ok";
        assert_eq!(redact(text), text);
    }

    #[test]
    fn keyworded_bare_ssn_with_invalid_area_not_masked() {
        // Keyword present (so the SSN-CTX pattern structurally matches) but
        // the digit value fails the ssn_valid gate (area 000).
        let text = "ssn=000051120";
        assert_eq!(redact(text), text);
    }

    #[test]
    fn ssn_unicode_space_separators_masked() {
        assert!(redact("id 078\u{00a0}05\u{00a0}1120 x").contains("[REDACTED-SSN]"));
        assert!(redact("id 078\u{202f}05\u{202f}1120 x").contains("[REDACTED-SSN]"));
        assert!(!redact("078\n05\n1120").contains("[REDACTED-SSN]"));
    }

    // ── cloud credentials ───────────────────────────────────────────────

    #[rstest]
    #[case("AWS-KEY", "AKIAIOSFODNN7EXAMPLE".to_string())]
    #[case("AWS-KEY", format!("ASIA{}", "A".repeat(16)))]
    #[case("GITHUB-TOKEN", format!("ghp_{}", "a".repeat(36)))]
    #[case("SLACK-TOKEN", format!("xoxb-{}", "1".repeat(20)))]
    #[case("STRIPE-KEY", format!("sk_live_{}", "a".repeat(24)))]
    #[case("STRIPE-KEY", format!("rk_test_{}", "B".repeat(30)))]
    #[case("GOOGLE-API-KEY", format!("AIza{}", "a".repeat(35)))]
    #[case("TWILIO-KEY", format!("SK{}", "0".repeat(32)))]
    fn cloud_credential_masked(#[case] label: &str, #[case] secret: String) {
        let out = redact(&format!("key = {secret} end"));
        assert!(!out.contains(&secret));
        assert!(out.contains(&format!("[REDACTED-{label}]")));
    }

    #[test]
    fn azure_sas_signature_masked() {
        let out = redact("blob?sig=ABCDabcd1234efgh5678XYZ%2Fpq end");
        assert!(out.contains("[REDACTED-AZURE-SAS]"));
    }

    #[test]
    fn short_aws_lookalike_not_masked() {
        let text = "AKIASHORT end";
        assert_eq!(redact(text), text);
    }

    // ── JWT / Bearer / private key ──────────────────────────────────────

    #[test]
    fn jwt_masked() {
        let jwt = "eyJabcdefghij.klmnopqrst.uvwxyz0123";
        let out = redact(&format!("Authorization: {jwt}"));
        assert!(!out.contains(jwt));
        assert!(out.contains("[REDACTED-JWT]"));
    }

    #[test]
    fn private_key_block_masked() {
        let pk = "-----BEGIN RSA PRIVATE KEY-----\nABCDEFGHIJKLMNOP\nQRSTUVWXYZ012345\n-----END RSA PRIVATE KEY-----";
        let out = redact(&format!("embedded:\n{pk}\ntail"));
        assert!(!out.contains("ABCDEFGHIJKLMNOP"));
        assert!(out.contains("[REDACTED-PRIVATE-KEY]"));
    }

    #[test]
    fn large_private_key_block_masked() {
        let big = format!(
            "-----BEGIN RSA PRIVATE KEY-----\n{}\n-----END RSA PRIVATE KEY-----",
            "A".repeat(20000)
        );
        let out = redact(&format!("key: {big}"));
        assert!(out.contains("[REDACTED-PRIVATE-KEY]"));
        assert!(!out.contains(&"A".repeat(100)));
    }

    // ── SECRET value-shape gate ─────────────────────────────────────────

    #[rstest]
    #[case("password: \"supersecret\"")]
    #[case("password: hunter2")]
    #[case("secret: abcDEFghi")]
    #[case("api_key: aaa-bbb!cc")]
    #[case(&format!("token: {}", "a".repeat(30)))]
    fn secret_credential_shape_redacted(#[case] text: &str) {
        assert!(redact(text).contains("[REDACTED-SECRET]"));
    }

    #[rstest]
    #[case("secret: rotate")]
    #[case("token: refresh")]
    #[case("credential: review")]
    fn secret_weak_keyword_plain_word_not_redacted(#[case] text: &str) {
        assert_eq!(redact(text), text);
    }

    #[rstest]
    #[case("password: correcthorse")]
    #[case("pwd: hunterpw")]
    #[case("api_key: supersecret")]
    #[case("access_key: accesskeyval")]
    #[case("client_secret: clientsecretval")]
    #[case("auth_token: authtokenval")]
    fn secret_strong_keyword_lowercase_value_redacted(#[case] text: &str) {
        assert!(redact(text).contains("[REDACTED-SECRET]"));
    }

    #[rstest]
    #[case("password: changeme")]
    #[case("password: ${DB_PASS}")]
    #[case("secret: <your-secret>")]
    #[case("api_key: example")]
    fn secret_placeholder_allowlist_not_redacted(#[case] text: &str) {
        assert_eq!(redact(text), text);
    }

    #[test]
    fn secret_keeps_keyword_and_quotes_around_mask() {
        let out = redact("password: \"supersecret\"");
        assert!(out.starts_with("password: "));
        assert_eq!(out.matches('"').count(), 2);
        assert!(out.contains("[REDACTED-SECRET]"));
    }

    #[test]
    fn secret_backtick_placeholder_not_redacted() {
        let text = "use `token: ${DB_PASS}` in env";
        assert_eq!(redact(text), text);
    }

    #[test]
    fn secret_backtick_value_masked_keeps_span_balanced() {
        let out = redact("password: `hunter2pw`");
        assert!(out.contains("[REDACTED-SECRET]"));
        assert!(!out.contains("hunter2pw"));
        assert_eq!(out.matches('`').count(), 2);
    }

    #[rstest]
    #[case("superSecret: hunter2pw")]
    #[case("myApiKey: abc123def456")]
    #[case("dbPassword: s3cr3tvalue")]
    fn secret_camelcase_strong_keyword_redacted(#[case] text: &str) {
        assert!(redact(text).contains("[REDACTED-SECRET]"));
    }

    #[rstest]
    #[case("secret = (sasl_secret_t *)realloc(p, n);")]
    #[case("token = parse(input)")]
    #[case("this.secret = obj.field")]
    fn secret_code_expression_not_redacted(#[case] text: &str) {
        assert_eq!(redact(text), text);
    }

    #[rstest]
    #[case("HTTP Basic Authentication is supported")]
    #[case("uses Bearer authentication for the API")]
    #[case("Basic Authorization header")]
    fn bearer_prose_not_redacted(#[case] text: &str) {
        assert_eq!(redact(text), text);
    }

    #[test]
    fn secret_does_not_swallow_trailing_period() {
        assert_eq!(redact("token=mysecretvalue9."), "token=[REDACTED-SECRET].");
    }

    #[test]
    fn secret_does_not_swallow_trailing_paren_or_sentence() {
        assert_eq!(
            redact("api_key=abcdef123456) in the call."),
            "api_key=[REDACTED-SECRET]) in the call."
        );
    }

    #[test]
    fn secret_does_not_swallow_trailing_bracket() {
        assert_eq!(
            redact("auth_token=abcdefghij]"),
            "auth_token=[REDACTED-SECRET]]"
        );
    }

    #[test]
    fn secret_in_json_object_is_redacted() {
        let out = redact(r#"config {"token": "abc123def456"}"#);
        assert!(!out.contains("abc123def456"));
        assert!(out.ends_with('}'));
        assert!(out.contains("[REDACTED-SECRET]"));
    }

    #[test]
    fn secret_value_that_becomes_too_short_after_trailing_strip_falls_back_to_full_value() {
        // "abcde." strips its trailing '.' down to "abcde" (5 chars, below
        // the 6-char floor), so v_core must fall back to the untrimmed "abcde."
        // rather than treating the too-short stripped core as canonical.
        let out = redact("token=abcde.");
        assert_eq!(out, "token=[REDACTED-SECRET]");
    }

    #[test]
    fn quoted_secret_with_interior_paren_preserved() {
        let out = redact("password = 'p)ss)word12'");
        assert!(!out.contains("p)ss)word12"));
    }

    #[test]
    fn prose_carveout_after_weak_keyword_survives() {
        assert_eq!(
            redact("the secret: management approach"),
            "the secret: management approach"
        );
    }

    // ── NUL, counts, empty ──────────────────────────────────────────────

    #[test]
    fn nul_bytes_stripped_no_panic() {
        let out = redact("\u{0}0\u{0} hello \u{0}42\u{0} world");
        assert!(!out.contains('\u{0}'));
        assert_eq!(out, "0 hello 42 world");
    }

    #[test]
    fn empty_passthrough() {
        assert_eq!(redact(""), "");
    }

    #[test]
    fn last_counts_aggregates_multiple_hits() {
        let (out, counts) = redact_counts("4111111111111111 and 5555555555554444 here");
        assert_eq!(out.matches("[REDACTED-PAN]").count(), 2);
        assert_eq!(counts.get("PAN"), Some(&2));
    }

    #[test]
    fn clean_text_unchanged() {
        let text = "This is an ordinary sentence with no secrets.";
        let (out, counts) = redact_counts(text);
        assert_eq!(out, text);
        assert!(counts.is_empty());
    }

    // ── redact_tree ─────────────────────────────────────────────────────

    #[test]
    fn redact_tree_recurses_strings_only() {
        let tree = serde_json::json!({
            "card": "PAN 4111111111111111 here",
            "nested": {"list": ["clean", format!("ghp_{}", "a".repeat(36))]},
            "number": 42,
            "flag": true,
            "none": null,
        });
        let out = redact_tree(&tree);
        let card = out["card"].as_str().unwrap();
        assert!(!card.contains("4111111111111111"));
        assert!(card.contains("[REDACTED-PAN]"));
        assert_eq!(out["nested"]["list"][0], "clean");
        assert!(out["nested"]["list"][1]
            .as_str()
            .unwrap()
            .contains("[REDACTED-GITHUB-TOKEN]"));
        assert_eq!(out["number"], 42);
        assert_eq!(out["flag"], true);
        assert!(out["none"].is_null());
    }

    #[test]
    fn redact_tree_preserves_structure() {
        let tree = serde_json::json!(["a", ["b", {"c": "d"}], 1]);
        assert_eq!(redact_tree(&tree), tree);
    }

    // ── over-match boundary / idempotence / thread-safety shape ─────────

    #[test]
    fn redact_is_idempotent_no_double_bracket() {
        let once = redact("token=supersecretvalue123");
        assert_eq!(once, "token=[REDACTED-SECRET]");
        let twice = redact(&once);
        assert_eq!(twice, once);
        assert!(!twice.contains("]]"));
    }

    #[test]
    fn url_userinfo_password_masked_user_preserved() {
        let out = redact("clone https://x-access-token:ghp_SECRETVALUE123@example.com/o/r.git");
        assert!(!out.contains("ghp_SECRETVALUE123"));
        assert!(out.contains("x-access-token"));
        assert!(out.contains("[REDACTED-URL-CRED]"));
        let clean = "see https://api.example.com:443/v1";
        assert_eq!(redact(clean), clean);
    }

    #[test]
    fn redact_counts_matches_redact_output() {
        let s = format!("x 078-05-1120 y ghp_{} z", "a".repeat(36));
        assert_eq!(redact_counts(&s).0, redact(&s));
    }

    #[test]
    fn redact_counts_empty() {
        assert_eq!(redact_counts(""), (String::new(), Counts::new()));
    }

    // ── reinsertion defensive fallback (internal, not reachable via the
    //    public API since NUL is always stripped up front) ──────────────

    #[test]
    fn reinsert_placeholders_leaves_out_of_range_sentinel_untouched() {
        let placeholders = vec!["[REDACTED-X]".to_string()];
        let malformed = "before \u{0}7\u{0} after"; // index 7 doesn't exist
        assert_eq!(reinsert_placeholders(malformed, &placeholders), malformed);
    }

    #[test]
    fn reinsert_placeholders_leaves_unclosed_sentinel_untouched() {
        let placeholders = vec!["[REDACTED-X]".to_string()];
        let malformed = "before \u{0}0 after"; // no closing NUL
        assert_eq!(reinsert_placeholders(malformed, &placeholders), malformed);
    }

    proptest::proptest! {
        #[test]
        fn redact_is_always_idempotent(s in ".{0,200}") {
            let once = redact(&s);
            let twice = redact(&once);
            proptest::prop_assert_eq!(&once, &twice);
        }

        #[test]
        fn redact_never_panics_on_arbitrary_input(s in ".{0,500}") {
            let _ = redact_counts(&s);
        }
    }
}
