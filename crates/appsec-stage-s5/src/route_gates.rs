use std::collections::BTreeMap;
use std::path::Path;
use std::sync::LazyLock;

use appsec_model::{EntryPoint, EntryPointKind, Finding};
use regex::Regex;

const ENCLOSING_SCAN_LINES: usize = 400;

pub const GUARDED_ROUTE_REASON: &str =
    "route is guarded by the framework ({}) — authorization findings on it need a bypass, none claimed";

fn guarded_route_reason(guard: &str) -> String {
    GUARDED_ROUTE_REASON.replacen("{}", guard, 1)
}

static MISSING_AUTHZ_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(?:unauthenticated|unauthori[sz]ed)\s+(?:access|endpoint|route|request|caller|invocation|use)\b|\b(?:missing|no|lacks?|lack of|without|absent|anonymous)\b.{0,40}\b(?:auth|authori[sz]ation|authori[sz]ed|authentication|authenticated|access control|access check|login|session|permission)\b",
    )
    .expect("literal regex")
});

static BYPASS_CLAIM_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(bypass\w*|circumvent\w*|misconfigur\w*|weak\w*|hard-?coded|forge\w*|spoof\w*|predictable|replay\w*)\b|\bmissing\b.{0,20}\b(middleware|filter|guard|annotation)\b.{0,20}\bregistration\b|\b(middleware|guard|filter)\b.{0,20}\bnot\s+(registered|applied|wired)\b",
    )
    .expect("literal regex")
});

static FN_DEF_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?x)
        ^\s*
        (?:
            (?:(?:pub(?:\([^)]*\))?|private|protected|public|internal|static|final|open|override|suspend|async|export|default|abstract|inline|operator)\s+)*
            (?:fn|def|function|func|fun|sub)\s+([A-Za-z_][A-Za-z0-9_]*)
          |
            (?:public|private|protected|internal)\s+
            (?:(?:static|final|abstract|override|virtual|async|suspend)\s+)*
            [A-Za-z_][\w<>\[\],.?\ ]*\s+
            ([A-Za-z_]\w*)\s*\(
        )
        ",
    )
    .expect("literal regex")
});

static GUARD_NAME_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?x)
          \bmiddleware\s*\(\s*\[?\s*['"]([^'"]+)['"]
        | ['"]middleware['"]\s*=>\s*\[?\s*['"]([^'"]+)['"]
        | \bauthenticate\s*\(\s*"([^"]*)"
        | \bbefore_action\s+:([A-Za-z_]\w*[!?]?)
        | \bfrom_fn\w*\s*\(\s*([A-Za-z_][\w:]*)
        | (@PreAuthorize|@RolesAllowed|@Secured|@Authenticated|@login_required|@requires_auth|\[Authorize\]|@UseGuards)
        "#,
    )
    .expect("literal regex")
});

const GENERIC_GUARD: &str = "framework auth guard";

pub struct RouteIndex<'a> {
    by_file: BTreeMap<&'a str, Vec<&'a EntryPoint>>,
}

impl<'a> RouteIndex<'a> {
    pub fn new(entry_points: &'a [EntryPoint]) -> Self {
        let mut by_file: BTreeMap<&str, Vec<&EntryPoint>> = BTreeMap::new();
        for ep in entry_points {
            if matches!(ep.kind, EntryPointKind::Framework) && !ep.file.is_empty() {
                by_file.entry(ep.file.as_str()).or_default().push(ep);
            }
        }
        RouteIndex { by_file }
    }

    fn is_empty(&self) -> bool {
        self.by_file.is_empty()
    }

    pub fn counts(&self) -> (usize, usize) {
        let all: Vec<&EntryPoint> = self.all().collect();
        let guarded = all.iter().filter(|ep| !ep.reachable_from_unauth).count();
        (all.len(), guarded)
    }

    fn all(&self) -> impl Iterator<Item = &'a EntryPoint> + '_ {
        self.by_file.values().flatten().copied()
    }
}

fn split_handler(function: &str) -> (Option<&str>, &str) {
    for sep in ['@', '#'] {
        if let Some((q, leaf)) = function.split_once(sep) {
            if !q.is_empty() && !leaf.is_empty() {
                return (Some(q), leaf);
            }
        }
    }
    (None, function)
}

fn normalize_ident(s: &str) -> String {
    let last = s.rsplit('/').next().unwrap_or(s);
    last.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

fn file_stem(file: &str) -> &str {
    let name = file.rsplit('/').next().unwrap_or(file);
    name.split_once('.').map_or(name, |(stem, _)| stem)
}

fn qualifier_matches_file(qualifier: &str, file: &str) -> bool {
    let stem = normalize_ident(file_stem(file));
    let qual = normalize_ident(qualifier);
    !qual.is_empty() && (stem == qual || stem == format!("{qual}controller"))
}

fn mentions_ident(text: &str, ident: &str) -> bool {
    if ident.is_empty() {
        return false;
    }
    let is_word = |c: char| c.is_alphanumeric() || c == '_';
    let mut from = 0;
    while let Some(offset) = text[from..].find(ident) {
        let start = from + offset;
        let end = start + ident.len();
        let before_ok = !text[..start].chars().next_back().is_some_and(is_word);
        let after_ok = !text[end..].chars().next().is_some_and(is_word);
        if before_ok && after_ok {
            return true;
        }
        from = end;
    }
    false
}

fn read_file(repo_root: Option<&Path>, file: &str) -> Option<String> {
    let root = repo_root?;
    let path = appsec_pathjail::confine(root, file)?;
    std::fs::read_to_string(path).ok()
}

fn enclosing_function(source: &str, line: i64) -> Option<String> {
    let lines: Vec<&str> = source.lines().collect();
    let start = (line.max(1) as usize).min(lines.len());
    let floor = start.saturating_sub(ENCLOSING_SCAN_LINES);
    for idx in (floor..start).rev() {
        if let Some(caps) = FN_DEF_RE.captures(lines[idx]) {
            let name = caps.get(1).or_else(|| caps.get(2))?;
            return Some(name.as_str().to_string());
        }
    }
    None
}

fn own_lines(source: &str, f: &Finding) -> String {
    let lines: Vec<&str> = source.lines().collect();
    let lo = f.line_start.max(1) as usize;
    let hi = (f.line_end.max(f.line_start).max(1) as usize).min(lines.len());
    if lo > hi {
        return String::new();
    }
    lines[lo - 1..hi].join("\n")
}

fn guard_label(finding_src: Option<&str>, route_src: Option<&str>) -> String {
    for src in [finding_src, route_src].into_iter().flatten() {
        if let Some(caps) = GUARD_NAME_RE.captures(src) {
            let group = (1..=6).find(|i| caps.get(*i).is_some()).unwrap_or(6);
            let text = caps.get(group).map_or(GENERIC_GUARD, |m| m.as_str());
            return match group {
                1 | 2 => format!("middleware('{text}')"),
                3 => format!("authenticate(\"{text}\")"),
                4 => format!("before_action :{text}"),
                5 => format!("middleware::from_fn({text})"),
                _ => text.to_string(),
            };
        }
    }
    GENERIC_GUARD.to_string()
}

pub fn could_apply(f: &Finding, routes: &RouteIndex) -> bool {
    !routes.is_empty() && claims_missing_authz(f) && !claims_a_bypass(f)
}

fn claims_missing_authz(f: &Finding) -> bool {
    if matches!(
        cwe_number(f.cwe.as_deref()),
        Some(284 | 285 | 287 | 306 | 862 | 863)
    ) {
        return true;
    }
    MISSING_AUTHZ_RE.is_match(&format!("{} {}", f.title, f.description))
}

fn claims_a_bypass(f: &Finding) -> bool {
    BYPASS_CLAIM_RE.is_match(&format!(
        "{} {} {} {}",
        f.title, f.description, f.exploit_scenario, f.recommendation
    ))
}

pub fn guarded_route(f: &Finding, routes: &RouteIndex, repo_root: Option<&Path>) -> Option<String> {
    if !could_apply(f, routes) {
        return None;
    }
    let finding_src = read_file(repo_root, &f.file);
    let enclosing = finding_src.as_deref().and_then(|src| {
        let mid = (f.line_start + f.line_end.max(f.line_start)) / 2;
        enclosing_function(src, mid)
            .or_else(|| enclosing_function(src, f.line_start))
            .or_else(|| enclosing_function(src, f.line_end))
    });
    let lines = finding_src
        .as_deref()
        .map(|src| own_lines(src, f))
        .unwrap_or_default();

    let mut matched: Vec<&EntryPoint> = Vec::new();
    for ep in routes.all() {
        let (qualifier, leaf) = split_handler(&ep.function);
        let by_name = enclosing.as_deref() == Some(leaf)
            && qualifier.is_none_or(|q| qualifier_matches_file(q, &f.file));
        let by_line = ep.file == f.file
            && !lines.is_empty()
            && mentions_ident(&lines, leaf)
            && qualifier.is_none_or(|q| mentions_ident(&lines, q.rsplit('/').next().unwrap_or(q)));
        if by_name || by_line {
            matched.push(ep);
        }
    }
    if matched.is_empty() {
        matched = routes
            .by_file
            .get(f.file.as_str())
            .map(|eps| eps.to_vec())
            .unwrap_or_default();
    }
    let read_ok = finding_src.is_some();
    let enclosing_fn = enclosing.as_deref().unwrap_or("-").to_string();
    let matched_n = matched.len();
    let any_open = matched.iter().any(|ep| ep.reachable_from_unauth);
    let file = f.file.as_str();
    let line = f.line_start;
    tracing::info!(
        file,
        line,
        read_ok,
        enclosing_fn,
        matched_n,
        any_open,
        "[s5] route gate decision for an authorization-class finding"
    );
    if matched.is_empty() || any_open {
        return None;
    }

    let route_file = &matched[0].file;
    let route_src = (route_file != &f.file)
        .then(|| read_file(repo_root, route_file))
        .flatten();
    Some(guarded_route_reason(&guard_label(
        finding_src.as_deref(),
        route_src.as_deref(),
    )))
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
