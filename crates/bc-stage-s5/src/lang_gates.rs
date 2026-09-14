//! Language-aware pre-verify gates: two classes of false positive that a
//! model reliably produces, that a human reviewer rejects in seconds, and
//! that no amount of prompt wording fully stops — so they are settled
//! mechanically, before a verification session is spent on them.
//!
//! Both are net-new versus `s5_prefilter.py`, which has no language
//! awareness at all. Both are deliberately **one-directional**: they only
//! ever DROP a finding whose language rules make it impossible, and every
//! ambiguity — an unreadable file, an unknown extension, a construct that
//! might be in a script or URL context — resolves to *keep*, leaving the
//! call to S6's verifier, which now carries the same knowledge in its
//! prompt (see `bc_stage_s4::hints` and `bc_stage_s6::prompts`).
//!
//! **1. A race condition in synchronous JavaScript/TypeScript.** A live
//! 2026-09-06 scan of OWASP Juice Shop reported 16 CWE-362 findings, all
//! verified TRUE_POSITIVE at 8/10. Five were on purely synchronous code:
//! `req.app.locals.captchaId++` (`routes/captcha.ts:11`), check-then-act
//! with no `await` between the halves (`routes/2fa.ts:19-20` and
//! `:115-116`), `lib/challengeUtils.ts:71-76`, and
//! `lib/startup/registerWebsocketEvents.ts:22-50`. Node runs one
//! JavaScript thread with a run-to-completion event loop: synchronous code
//! cannot be interrupted, so a `++` or an `if (x) { x = ... }` with no
//! suspension point between the read and the write is not a race, whatever
//! else is true about it. The other 11 findings had an `await` or `.then`
//! between check and act and are plausible TOCTOUs; they still flow.
//!
//! **2. An XSS finding on a template construct the engine already
//! escapes.** The same scan reported 5 XSS/injection findings in
//! `views/*.hbs` and `views/*.pug`; 3 were on default-escaped syntax and
//! verified TRUE_POSITIVE at 8-9/10: Handlebars `{{userEmail}}`
//! (`views/dataErasureForm.hbs:38` — `{{ }}` HTML-escapes `=` too, so even
//! an unquoted attribute is safe), Pug `img(src=profileImage)`
//! (`views/userProfile.pug:42`) and a `placeholder='...' + imageUrl`
//! attribute interpolation (`:60`) — Pug escapes attribute values and
//! `#{}`. Escaping is not universal, though: it protects HTML text and
//! attribute contexts, and does nothing inside a `<script>` block, a
//! `javascript:` URL, an inline event handler or a CSS context. Every one
//! of those vetoes the drop.

use std::path::Path;
use std::sync::LazyLock;

use bc_model::{Finding, VulnClass};
use regex::Regex;

/// Lines of context read either side of the finding's own range. Enough
/// to catch an `await` on the line above a check-then-act pair, small
/// enough not to drag in the whole enclosing function (whose handler
/// registration would veto every drop — see [`CALLBACK_CALL_RE`]).
const CONTEXT_LINES: i64 = 2;

/// The reason string a race-condition drop carries.
pub const SYNC_JS_REASON: &str = "synchronous JS/TS code cannot race";
/// The reason prefix a template-escaping drop carries; the engine name is
/// appended in parentheses.
pub const TEMPLATE_ESCAPED_REASON: &str = "template engine escapes this construct by default";

/// The code a gate reasons over, plus what the surrounding file says about
/// its context.
pub struct SourceWindow {
    /// The finding's own lines plus [`CONTEXT_LINES`] either side, read
    /// from the repo — or the model's own `code_snippet` when the file
    /// could not be read (a deleted file, a path outside the repo root, a
    /// finding the model located in a file that does not exist).
    text: String,
    /// True when the finding's line sits inside an open `<script>` or
    /// `<style>` element. Only computable when the real file was read;
    /// `false` from a snippet, where the line-level checks still apply.
    in_script_or_style: bool,
}

impl SourceWindow {
    /// Reads the window for `f`. `repo_root` is `None` when the caller has
    /// no repo on disk (every S5 unit test that isn't about these gates),
    /// which simply falls back to the snippet.
    pub fn read(f: &Finding, repo_root: Option<&Path>) -> Self {
        let lines = repo_root
            .and_then(|root| bc_pathjail::confine(root, &f.file))
            .and_then(|path| std::fs::read_to_string(path).ok());
        let Some(contents) = lines else {
            return SourceWindow {
                text: f.code_snippet.clone(),
                in_script_or_style: false,
            };
        };
        let lines: Vec<&str> = contents.lines().collect();
        // `line_start`/`line_end` are 1-based and model-supplied, so both
        // "0" (never located) and "past the end of the file" are ordinary
        // inputs, not bugs to assert about.
        let lo = (f.line_start - CONTEXT_LINES).max(1) as usize;
        let hi = (f.line_end.max(f.line_start) + CONTEXT_LINES).max(1) as usize;
        let slice: Vec<&str> = lines
            .iter()
            .skip(lo.saturating_sub(1))
            .take(hi.saturating_sub(lo) + 1)
            .copied()
            .collect();
        if slice.is_empty() {
            return SourceWindow {
                text: f.code_snippet.clone(),
                in_script_or_style: false,
            };
        }
        let before = lines
            .iter()
            .take(lo.saturating_sub(1))
            .copied()
            .collect::<Vec<_>>()
            .join("\n");
        SourceWindow {
            text: slice.join("\n"),
            in_script_or_style: inside_open_element(&before, engine_for(&f.file)),
        }
    }

    /// A window over literal text — how the gates below are exercised
    /// against a code shape without staging a whole repo on disk for it.
    #[cfg(test)]
    pub fn from_text(text: impl Into<String>) -> Self {
        SourceWindow {
            text: text.into(),
            in_script_or_style: false,
        }
    }
}

/// True when `before` (everything preceding the finding) leaves a
/// `<script>` or `<style>` element open. Counting opens against closes is
/// enough for real templates and errs toward "inside" — an unbalanced
/// document keeps the finding rather than dropping it.
fn inside_open_element(before: &str, engine: Option<Engine>) -> bool {
    if matches!(engine, Some(Engine::Pug)) {
        return inside_open_pug_block(before);
    }
    let lower = before.to_lowercase();
    ["script", "style"].iter().any(|tag| {
        lower.matches(&format!("<{tag}")).count() > lower.matches(&format!("</{tag}")).count()
    })
}

/// Pug has no closing tags: a `script`/`style` block is everything
/// indented deeper than the tag's own line, and ends at the first later
/// non-blank line at that indentation or shallower. Counting `<script`
/// against `</script>` (the HTML rule) sees an open block that never
/// closes, so every finding below the template's stylesheet looked like
/// it sat inside `<style>` and the escaping gate vetoed itself — a live
/// 2026-09-06 scan let `views/userProfile.pug:60` through for exactly that
/// reason (its `style.` block is at line 15).
fn inside_open_pug_block(before: &str) -> bool {
    let mut open_indent: Option<usize> = None;
    for line in before.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        if let Some(depth) = open_indent {
            if indent <= depth {
                open_indent = None;
            } else {
                continue;
            }
        }
        let head = line.trim_start();
        let is_block_tag = ["script", "style"].iter().any(|tag| {
            head.starts_with(tag)
                && head[tag.len()..]
                    .chars()
                    .next()
                    .is_none_or(|c| matches!(c, '.' | '(' | ' ' | '#' | ':' | '\t'))
        });
        if is_block_tag {
            open_indent = Some(indent);
        }
    }
    open_indent.is_some()
}

// ── 1. Synchronous JS/TS cannot race ────────────────────────────────

fn is_js_or_ts(file: &str) -> bool {
    let lower = file.to_lowercase();
    [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"]
        .iter()
        .any(|ext| lower.ends_with(ext))
}

/// Whether this finding claims a race/TOCTOU, by either of the two labels
/// the model uses for one.
fn claims_a_race(f: &Finding) -> bool {
    if f.vuln_class == VulnClass::RaceCondition {
        return true;
    }
    // CWE-362 (race condition), CWE-366 (race within a thread) and
    // CWE-367 (TOCTOU) are the three the model reaches for here.
    matches!(cwe_number(f.cwe.as_deref()), Some(362 | 366 | 367))
}

/// A suspension point: somewhere the JavaScript engine can hand the thread
/// to another task between two statements. `async` on its own is
/// deliberately absent — an `async function` with no `await` in it runs to
/// completion exactly like a synchronous one, so treating the keyword as a
/// boundary would gut the gate for no safety gain.
static SUSPENSION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?x)
        \bawait\b
        | \byield\b
        | \.\s*then\s*\(
        | \.\s*catch\s*\(
        | \.\s*finally\s*\(
        | \bPromise\b
        | \bsetTimeout\s*\(
        | \bsetInterval\s*\(
        | \bsetImmediate\s*\(
        | \bnextTick\s*\(
        | \bqueueMicrotask\s*\(
        | \bAtomics\s*\.
        | \bSharedArrayBuffer\b
        | \bworker_threads\b
        | \bnew\s+Worker\s*\(
        | \bcluster\b
        ",
    )
    .expect("literal regex")
});

/// An opening parenthesis preceded by a callee: a named one (captured), or
/// a `)`/`]` closing a chained or computed one (`make()(…)`,
/// `handlers[0](…)`, not captured). [`has_asynchronous_callback`] looks the
/// named callee up in [`ASYNC_CALLBACK_CALLEES`] and then requires `=>` or
/// `function` AFTER the parenthesis on the same line — a callback being
/// handed over, not a handler being declared.
///
/// Capturing only a real identifier is what keeps `return (req, res) =>
/// { … }` — a parenthesised arrow being returned, which is how an Express
/// middleware factory is written — and `async (req, res) => { … }` from
/// reading as calls taking a callback: `return` and `async` are not in the
/// allowlist, and a computed callee has no name to look up. A declaration
/// (`function handler(req, res) {`) and an assignment (`const cb = (a) =>
/// a;`) put the marker outside any argument list already.
static CALL_OPEN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:([A-Za-z_$][\w$]*)|[\)\]])\s*\(").expect("literal regex"));

/// Callees whose callback argument is a genuine event-loop boundary: the
/// callback runs LATER, on another turn, so a check before the call and
/// an act inside or after it can interleave with another request. A
/// callback passed to anything else — `Array.prototype.some`, a helper
/// like `challengeUtils.solveIf(ch, () => true)`, a user-defined
/// synchronous function — runs to completion before the call returns and
/// is no boundary at all. The earlier rule ("any callback keeps the
/// finding") was inverted: a live 2026-09-06 Juice Shop scan kept
/// `lib/challengeUtils.ts:71-76` on a `.some(...)` and
/// `routes/nftMint.ts:38-52` on a `solveIf(..., () => true)`, both fully
/// synchronous. An unknown callee with no `await`/`.then` in the window is
/// now assumed synchronous, which is what JavaScript code is unless
/// something in it suspends.
const ASYNC_CALLBACK_CALLEES: &[&str] = &[
    // timers / scheduling
    "setTimeout",
    "setInterval",
    "setImmediate",
    "nextTick",
    "queueMicrotask",
    "requestAnimationFrame",
    // promises
    "then",
    "catch",
    "finally",
    "Promise",
    // events
    "on",
    "once",
    "addListener",
    "addEventListener",
    "subscribe",
    "emit",
    // node fs / child_process / net (callback style)
    "readFile",
    "writeFile",
    "readdir",
    "stat",
    "access",
    "unlink",
    "mkdir",
    "exec",
    "execFile",
    "spawn",
    "listen",
    "connect",
    // db / http clients (callback style). `find` and `each` are deliberately
    // absent: `Array.prototype.find(cb)` and jQuery `.each(cb)` are
    // synchronous and far more common than the callback-style database
    // spellings; a promise-based `find` shows up as `.then`/`await` anyway.
    "query",
    "get",
    "post",
    "put",
    "delete",
    "request",
    "fetch",
    "findOne",
    "save",
    "update",
    "insert",
    "run",
    "all",
];

fn has_asynchronous_callback(text: &str) -> bool {
    text.lines().any(|line| {
        CALL_OPEN_RE.captures_iter(line).any(|c| {
            let Some(id) = c.get(1) else {
                return false;
            };
            if !ASYNC_CALLBACK_CALLEES.contains(&id.as_str()) {
                return false;
            }
            let rest = &line[c.get(0).expect("whole match").end()..];
            rest.contains("=>") || rest.contains("function")
        })
    })
}

/// Whether either gate could possibly fire for this finding — a cheap
/// filename/CWE test the caller asks BEFORE paying for a
/// [`SourceWindow::read`], since the overwhelming majority of findings
/// are neither a JS/TS race claim nor an XSS in a template.
pub fn could_apply(f: &Finding) -> bool {
    (is_js_or_ts(&f.file) && claims_a_race(f))
        || (matches!(cwe_number(f.cwe.as_deref()), Some(79 | 80)) && engine_for(&f.file).is_some())
}

/// `Some(reason)` when this finding claims a race in JS/TS code that
/// contains no asynchronous boundary at all, and therefore cannot have
/// one.
pub fn synchronous_js_race(f: &Finding, window: &SourceWindow) -> Option<&'static str> {
    if !is_js_or_ts(&f.file) || !claims_a_race(f) {
        return None;
    }
    // No text to reason about is not evidence of anything.
    if window.text.trim().is_empty() {
        return None;
    }
    if SUSPENSION_RE.is_match(&window.text) || has_asynchronous_callback(&window.text) {
        return None;
    }
    Some(SYNC_JS_REASON)
}

// ── 2. Template engines that escape by default ──────────────────────

/// The template engines whose escaping rules are unambiguous enough to
/// act on without a model. JSX/TSX and Angular templates are deliberately
/// absent: `{expr}` is indistinguishable from a `${}` template literal or
/// an ordinary block by regex, and `.html` names no engine at all. Those
/// get the knowledge in the S4/S6 prompts and nothing more.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Engine {
    Handlebars,
    Pug,
    Ejs,
    Jinja,
    Erb,
    Razor,
    Blade,
    Vue,
}

impl Engine {
    fn name(self) -> &'static str {
        match self {
            Engine::Handlebars => "handlebars",
            Engine::Pug => "pug",
            Engine::Ejs => "ejs",
            Engine::Jinja => "jinja/twig",
            Engine::Erb => "erb",
            Engine::Razor => "razor",
            Engine::Blade => "blade",
            Engine::Vue => "vue",
        }
    }
}

fn engine_for(file: &str) -> Option<Engine> {
    let lower = file.to_lowercase();
    // Longest/most specific suffixes first: `.blade.php` before `.php`
    // would matter if `.php` were listed, and `.html.erb` ends with
    // `.erb` either way.
    for (suffix, engine) in [
        (".blade.php", Engine::Blade),
        (".hbs", Engine::Handlebars),
        (".handlebars", Engine::Handlebars),
        (".mustache", Engine::Handlebars),
        (".pug", Engine::Pug),
        (".jade", Engine::Pug),
        (".ejs", Engine::Ejs),
        (".jinja", Engine::Jinja),
        (".jinja2", Engine::Jinja),
        (".j2", Engine::Jinja),
        (".twig", Engine::Jinja),
        (".erb", Engine::Erb),
        (".cshtml", Engine::Razor),
        (".razor", Engine::Razor),
        (".vue", Engine::Vue),
    ] {
        if lower.ends_with(suffix) {
            return Some(engine);
        }
    }
    None
}

macro_rules! re {
    ($name:ident, $pattern:literal) => {
        static $name: LazyLock<Regex> = LazyLock::new(|| Regex::new($pattern).expect("literal"));
    };
}

// Raw (unescaped) output, per engine. Checked BEFORE the escaped forms,
// since several raw spellings contain an escaped one as a prefix
// (`<%==` starts with `<%=`, `!=` ends with `=`).
re!(HBS_RAW_RE, r"\{\{\{|\{\{\s*&");
re!(HBS_ESCAPED_RE, r"\{\{(?:[^\{&!#/>]|$)");
re!(PUG_RAW_RE, r"!\{|!=|\bunescaped\b");
re!(PUG_ESCAPED_RE, r"#\{|[\w-]+\s*=");
re!(EJS_RAW_RE, r"<%-");
re!(EJS_ESCAPED_RE, r"<%=");
re!(
    JINJA_RAW_RE,
    r"\|\s*safe\b|\|\s*raw\b|autoescape\s+false|\bMarkup\s*\("
);
re!(JINJA_ESCAPED_RE, r"\{\{");
re!(ERB_RAW_RE, r"<%==|\.html_safe\b|\braw[\s(]");
re!(ERB_ESCAPED_RE, r"<%=");
re!(RAZOR_RAW_RE, r"@Html\.Raw\b|\bHtmlString\b|\bRaw\s*\(");
re!(RAZOR_ESCAPED_RE, r"@[A-Za-z_(]");
re!(BLADE_RAW_RE, r"\{!!");
re!(BLADE_ESCAPED_RE, r"\{\{");
re!(VUE_RAW_RE, r"v-html|innerHTML");
re!(VUE_ESCAPED_RE, r"\{\{|:[\w-]+\s*=");

fn raw_construct(engine: Engine, text: &str) -> bool {
    match engine {
        Engine::Handlebars => HBS_RAW_RE.is_match(text),
        Engine::Pug => PUG_RAW_RE.is_match(text),
        Engine::Ejs => EJS_RAW_RE.is_match(text),
        Engine::Jinja => JINJA_RAW_RE.is_match(text),
        Engine::Erb => ERB_RAW_RE.is_match(text),
        Engine::Razor => RAZOR_RAW_RE.is_match(text),
        Engine::Blade => BLADE_RAW_RE.is_match(text),
        Engine::Vue => VUE_RAW_RE.is_match(text),
    }
}

fn escaped_re(engine: Engine) -> &'static Regex {
    match engine {
        Engine::Handlebars => &HBS_ESCAPED_RE,
        Engine::Pug => &PUG_ESCAPED_RE,
        Engine::Ejs => &EJS_ESCAPED_RE,
        Engine::Jinja => &JINJA_ESCAPED_RE,
        Engine::Erb => &ERB_ESCAPED_RE,
        Engine::Razor => &RAZOR_ESCAPED_RE,
        Engine::Blade => &BLADE_ESCAPED_RE,
        Engine::Vue => &VUE_ESCAPED_RE,
    }
}

fn escaped_construct(engine: Engine, text: &str) -> bool {
    escaped_re(engine).is_match(text)
}

// Attributes where HTML-entity escaping does not make a value safe: a
// URL that may be `javascript:`, an inline handler, CSS, or literal HTML.
re!(
    DANGEROUS_ATTR_RE,
    r"(?i)^(?:href|xlink:href|action|formaction|style|srcdoc|on[a-z]+)$"
);
// The attribute the construct at `pos` sits in, if any: the last
// `name=` opened on that line before `pos` whose value has not yet been
// closed by a quote. Works for `name="..."`, `name='...'` and Pug's bare
// `name=expr`.
re!(
    OPEN_ATTR_RE,
    r#"([A-Za-z_:][\w:.-]*)\s*=\s*(?:"[^"]*|'[^']*|[^"'\s(),]*)$"#
);
// The element a line's attributes belong to: `<tag` for HTML-shaped
// engines, the leading `tag.class#id(` for Pug.
re!(OPEN_TAG_RE, r"<\s*([A-Za-z][\w-]*)[^<>]*$");
re!(PUG_TAG_RE, r"^\s*([A-Za-z][\w-]*)[\w.#-]*\(");

/// Whether any default-escaped construct on these lines sits inside an
/// attribute where escaping is not enough. Checked per construct rather
/// than per window: a live 2026-09-06 Juice Shop scan kept
/// `img.img-rounded(src=profileImage, ..., style='margin-right: 5%')` as
/// XSS because a whole-window rule saw the literal `style=` and vetoed the
/// drop, although the user value is in `src`, which an `img` renders
/// harmlessly. `src` is dangerous only on an element that executes it.
fn construct_in_dangerous_attribute(engine: Engine, text: &str) -> bool {
    let re = escaped_re(engine);
    text.lines().any(|line| {
        re.find_iter(line).any(|m| {
            let before = &line[..m.start()];
            // Pug's escaped form IS `name=`, so the attribute is the match
            // itself; for the others it is whatever `=` was opened before.
            if engine == Engine::Pug {
                // `style='margin: 0'` is a literal, not a place a value
                // flows into; only `name=expr` / `name=#{...}` carries data.
                let after = line[m.end()..].trim_start();
                if after.starts_with('\'') || after.starts_with('"') {
                    return false;
                }
            }
            let attr = match (engine, m.as_str().split_once('=')) {
                // Pug's escaped attribute form IS `name=`: the match names
                // the attribute directly.
                (Engine::Pug, Some((name, _))) => Some(name.trim().to_string()),
                // A Pug `#{…}` interpolation, or any other engine's
                // construct: whatever attribute was opened before it.
                _ => OPEN_ATTR_RE.captures(before).map(|c| c[1].to_string()),
            };
            let Some(attr) = attr else {
                return false;
            };
            if DANGEROUS_ATTR_RE.is_match(&attr) {
                return true;
            }
            if attr.eq_ignore_ascii_case("src") {
                let tag = if engine == Engine::Pug {
                    PUG_TAG_RE.captures(line).map(|c| c[1].to_lowercase())
                } else {
                    OPEN_TAG_RE.captures(before).map(|c| c[1].to_lowercase())
                };
                return matches!(
                    tag.as_deref(),
                    Some("script" | "iframe" | "frame" | "object" | "embed")
                );
            }
            false
        })
    })
}

// A context where HTML escaping does not save you regardless of which
// attribute a value is in: inside a script or style element, or next to a
// literal `javascript:`/`data:` scheme. Any of these anywhere on the
// finding's own lines vetoes the drop. Attribute-level contexts (`href`,
// `style=`, `on*=`) are judged per construct by
// `construct_in_dangerous_attribute`, not per window.
re!(
    BLOCK_CONTEXT_RE,
    r"(?im)<\s*script|<\s*/\s*script|<\s*style|<\s*/\s*style|javascript\s*:|\bsrcdoc\b|\bdata\s*:|^\s*(?:script|style)\b"
);

/// `Some(reason)` when this XSS finding sits on a template construct the
/// engine escapes by default, in an HTML text or attribute context, with
/// no raw construct anywhere in the window.
pub fn template_autoescaped(f: &Finding, window: &SourceWindow) -> Option<String> {
    if !matches!(cwe_number(f.cwe.as_deref()), Some(79 | 80)) {
        return None;
    }
    let engine = engine_for(&f.file)?;
    let text = &window.text;
    if text.trim().is_empty() {
        return None;
    }
    if window.in_script_or_style || BLOCK_CONTEXT_RE.is_match(text) {
        return None;
    }
    if raw_construct(engine, text) || !escaped_construct(engine, text) {
        return None;
    }
    if construct_in_dangerous_attribute(engine, text) {
        return None;
    }
    Some(format!("{TEMPLATE_ESCAPED_REASON} ({})", engine.name()))
}

/// The CWE's numeric identity. A local copy of the same normalization
/// `bc_dedup_core::cwe_number` documents — this crate does not depend on
/// that one, and one bounded integer parse is not worth a dependency
/// edge.
fn cwe_number(raw: Option<&str>) -> Option<u32> {
    let token = raw?.trim();
    let digits = match token.get(..4) {
        Some(prefix) if prefix.eq_ignore_ascii_case("cwe-") => &token[4..],
        _ => token,
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

#[cfg(test)]
mod tests;
