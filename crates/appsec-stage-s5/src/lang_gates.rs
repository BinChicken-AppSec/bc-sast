use std::path::Path;
use std::sync::LazyLock;

use appsec_model::{Finding, VulnClass};
use regex::Regex;

const CONTEXT_LINES: i64 = 2;

pub const SYNC_JS_REASON: &str = "synchronous JS/TS code cannot race";
pub const TEMPLATE_ESCAPED_REASON: &str = "template engine escapes this construct by default";

pub struct SourceWindow {
    text: String,
    in_script_or_style: bool,
}

impl SourceWindow {
    pub fn read(f: &Finding, repo_root: Option<&Path>) -> Self {
        let lines = repo_root
            .and_then(|root| appsec_pathjail::confine(root, &f.file))
            .and_then(|path| std::fs::read_to_string(path).ok());
        let Some(contents) = lines else {
            return SourceWindow {
                text: f.code_snippet.clone(),
                in_script_or_style: false,
            };
        };
        let lines: Vec<&str> = contents.lines().collect();
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

    #[cfg(test)]
    pub fn from_text(text: impl Into<String>) -> Self {
        SourceWindow {
            text: text.into(),
            in_script_or_style: false,
        }
    }
}

fn inside_open_element(before: &str, engine: Option<Engine>) -> bool {
    if matches!(engine, Some(Engine::Pug)) {
        return inside_open_pug_block(before);
    }
    let lower = before.to_lowercase();
    ["script", "style"].iter().any(|tag| {
        lower.matches(&format!("<{tag}")).count() > lower.matches(&format!("</{tag}")).count()
    })
}

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

fn is_js_or_ts(file: &str) -> bool {
    let lower = file.to_lowercase();
    [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"]
        .iter()
        .any(|ext| lower.ends_with(ext))
}

fn claims_a_race(f: &Finding) -> bool {
    if f.vuln_class == VulnClass::RaceCondition {
        return true;
    }
    matches!(cwe_number(f.cwe.as_deref()), Some(362 | 366 | 367))
}

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

static CALL_OPEN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:([A-Za-z_$][\w$]*)|[\)\]])\s*\(").expect("literal regex"));

const ASYNC_CALLBACK_CALLEES: &[&str] = &[
    "setTimeout",
    "setInterval",
    "setImmediate",
    "nextTick",
    "queueMicrotask",
    "requestAnimationFrame",
    "then",
    "catch",
    "finally",
    "Promise",
    "on",
    "once",
    "addListener",
    "addEventListener",
    "subscribe",
    "emit",
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

pub fn could_apply(f: &Finding) -> bool {
    (is_js_or_ts(&f.file) && claims_a_race(f))
        || (matches!(cwe_number(f.cwe.as_deref()), Some(79 | 80)) && engine_for(&f.file).is_some())
}

pub fn synchronous_js_race(f: &Finding, window: &SourceWindow) -> Option<&'static str> {
    if !is_js_or_ts(&f.file) || !claims_a_race(f) {
        return None;
    }
    if window.text.trim().is_empty() {
        return None;
    }
    if SUSPENSION_RE.is_match(&window.text) || has_asynchronous_callback(&window.text) {
        return None;
    }
    Some(SYNC_JS_REASON)
}

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

re!(
    DANGEROUS_ATTR_RE,
    r"(?i)^(?:href|xlink:href|action|formaction|style|srcdoc|on[a-z]+)$"
);
re!(
    OPEN_ATTR_RE,
    r#"([A-Za-z_:][\w:.-]*)\s*=\s*(?:"[^"]*|'[^']*|[^"'\s(),]*)$"#
);
re!(OPEN_TAG_RE, r"<\s*([A-Za-z][\w-]*)[^<>]*$");
re!(PUG_TAG_RE, r"^\s*([A-Za-z][\w-]*)[\w.#-]*\(");

fn construct_in_dangerous_attribute(engine: Engine, text: &str) -> bool {
    let re = escaped_re(engine);
    text.lines().any(|line| {
        re.find_iter(line).any(|m| {
            let before = &line[..m.start()];
            if engine == Engine::Pug {
                let after = line[m.end()..].trim_start();
                if after.starts_with('\'') || after.starts_with('"') {
                    return false;
                }
            }
            let attr = match (engine, m.as_str().split_once('=')) {
                (Engine::Pug, Some((name, _))) => Some(name.trim().to_string()),
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

re!(
    BLOCK_CONTEXT_RE,
    r"(?im)<\s*script|<\s*/\s*script|<\s*style|<\s*/\s*style|javascript\s*:|\bsrcdoc\b|\bdata\s*:|^\s*(?:script|style)\b"
);

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
