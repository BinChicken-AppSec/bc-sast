//! Route-aware pre-verify gate: a "this handler has no authorization
//! check" finding on a route the framework already guards.
//!
//! Net-new versus `s5_prefilter.py`, and the same shape as
//! [`crate::lang_gates`] — one-directional (it only ever DROPS a finding
//! whose framework wiring makes it impossible), every ambiguity resolves
//! to *keep*, and the decision is anchored on a fact an earlier stage
//! established mechanically rather than on a model's opinion.
//!
//! **What went wrong.** A 2026-09-07 run over the polyglot test bed
//! reported "Missing Authorization Check" / "Unauthenticated Access" on
//! four handlers whose routes are guarded by their framework:
//! `OpsConsoleController::runMaintenance` behind Laravel's
//! `Route::middleware(['auth'])->group(…)`, Ktor's `restoreConsoleSnapshot`
//! and `listOwnedReports` inside `authenticate("auth-session")`,
//! `ReportsController#index`/`#download` behind Rails'
//! `before_action :authenticate_user!`, and axum's
//! `export_report`/`rebuild_index`/`read_frame` behind
//! `.route_layer(middleware::from_fn(require_operator_token))`. S4 raised
//! them and S6 *confirmed* them — both were wrong in the same direction,
//! because neither was told that a guard on the ROUTE satisfies the check
//! the finding demands.
//!
//! **What S0 already knew.** `bc_stage_s0::run_seed` emits a framework
//! entry point per route with `reachable_from_unauth` set from the guard
//! facts `bc_callgraph::framework` extracted, and S1 merges those into
//! `ContextPackage::entry_points`. Every one of the handlers above is
//! already `reachable_from_unauth: false` there (verified by probing the
//! four apps through `bc_callgraph::scan_file` +
//! `emit_framework_entry_points`). This gate is that fact, applied.
//!
//! Ktor's two handlers reach rule 1 like the rest: `bc_callgraph`'s
//! Kotlin section reads the delegate out of a route lambda that does
//! nothing but call one function, so the entry point is
//! `restoreConsoleSnapshot` rather than a path-derived
//! `post_ops_snapshot_restore`. A lambda with a body of its own, and any
//! delegate two routes in a file share, still fall back to the synthetic
//! name and so still need rule 3.
//!
//! **Why only `EntryPointKind::Framework` counts.** `reachable_from_unauth`
//! is `#[serde(default)]`, so an S1 agent that never mentions the field
//! leaves it `false` — which reads as "guarded" while actually meaning
//! "unknown". Only S0's framework plane sets it from evidence, so only
//! `Framework`-kind entry points are allowed to gate a drop; every other
//! kind is ignored entirely.
//!
//! **The guard name is not in the model.** `bc_callgraph`'s `AuthGuardFact`
//! carries the marker (`auth`, `authenticate`, `authenticate_user!`,
//! `require_operator_token`), but `EntryPoint` keeps only the boolean, so
//! the name is gone by the time a `ContextPackage` exists. The drop
//! *reason* re-reads it out of the source for legibility — it never
//! decides anything, and falls back to a generic label when no spelling
//! matches.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::LazyLock;

use bc_model::{EntryPoint, EntryPointKind, Finding};
use regex::Regex;

/// How far above a finding's first line the enclosing-function scan
/// walks. Comfortably past any real handler's signature-to-body distance
/// (the four field cases are 1-6 lines), bounded so a finding reported at
/// line 40000 of a generated file cannot turn into a full-file scan.
const ENCLOSING_SCAN_LINES: usize = 400;

/// The reason a route-guard drop carries. `{}` is the guard as read back
/// out of the source (see the module doc), or a generic label.
pub const GUARDED_ROUTE_REASON: &str =
    "route is guarded by the framework ({}) — authorization findings on it need a bypass, none claimed";

fn guarded_route_reason(guard: &str) -> String {
    GUARDED_ROUTE_REASON.replacen("{}", guard, 1)
}

/// The finding claims the handler performs no authorization/authentication
/// at all. The CWE list is the authoritative half; this catches the same
/// claim filed under a neighbouring CWE (639 IDOR, 200 exposure) or under
/// none. Two shapes, because the titles S4 actually writes come in two:
/// the standalone "Unauthenticated Access to …", and the
/// "Missing/No … authorization" form.
static MISSING_AUTHZ_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(?:unauthenticated|unauthori[sz]ed)\s+(?:access|endpoint|route|request|caller|invocation|use)\b|\b(?:missing|no|lacks?|lack of|without|absent|anonymous)\b.{0,40}\b(?:auth|authori[sz]ation|authori[sz]ed|authentication|authenticated|access control|access check|login|session|permission)\b",
    )
    .expect("literal regex")
});

/// The finding attacks the guard itself rather than its absence. Such a
/// finding is exactly what this gate tells the verifier to look for, so
/// it must never be the thing the gate drops.
static BYPASS_CLAIM_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(bypass\w*|circumvent\w*|misconfigur\w*|weak\w*|hard-?coded|forge\w*|spoof\w*|predictable|replay\w*)\b|\bmissing\b.{0,20}\b(middleware|filter|guard|annotation)\b.{0,20}\bregistration\b|\b(middleware|guard|filter)\b.{0,20}\bnot\s+(registered|applied|wired)\b",
    )
    .expect("literal regex")
});

/// A function definition line, in the spellings the languages that carry
/// framework routes use. Two alternatives: a keyword form (`fn`, `def`,
/// `function`, `func`, `fun`, `sub` — Rust, Python, Ruby, Kotlin, PHP,
/// Go, JS) and a modifier-led form for the brace languages that have no keyword
/// (`public JsonResponse runMaintenance(…)` — Java, C#). The second
/// deliberately requires an access modifier so a bare `if (x) {` cannot
/// pose as a definition.
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

/// The framework guard spellings worth naming in a drop reason, in the
/// four ecosystems the field cases cover plus the annotation-style ones.
/// Purely cosmetic — see the module doc.
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

/// The label used when no spelling in [`GUARD_NAME_RE`] matches — the
/// entry point still says the route is not reachable without auth, which
/// is the part that decided the drop.
const GENERIC_GUARD: &str = "framework auth guard";

/// Framework entry points grouped by the file that declares them, built
/// once per S5 run. Non-`Framework` kinds are dropped on the way in (see
/// the module doc), so an empty index means this gate can never fire and
/// no finding pays for a file read.
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

    /// `(framework entry points indexed, of which guarded)` — for the
    /// stage's diagnostics line.
    pub fn counts(&self) -> (usize, usize) {
        let all: Vec<&EntryPoint> = self.all().collect();
        let guarded = all.iter().filter(|ep| !ep.reachable_from_unauth).count();
        (all.len(), guarded)
    }

    fn all(&self) -> impl Iterator<Item = &'a EntryPoint> + '_ {
        self.by_file.values().flatten().copied()
    }
}

/// `(qualifier, leaf)` for an entry point's function id: Laravel's
/// `OpsConsoleController@runMaintenance`, Rails' `reports#index`, or a
/// bare `export_report`. The qualifier names the class/controller the
/// handler lives in, which is what ties a route-table entry point to the
/// handler file it points at.
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

/// A comparison key that survives the naming conventions between a route
/// table and a source file: lowercase, punctuation removed, and only the
/// last path segment of a namespaced controller (`admin/users` ->
/// `users`).
fn normalize_ident(s: &str) -> String {
    let last = s.rsplit('/').next().unwrap_or(s);
    last.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// The file's own name without directories or extension —
/// `app/controllers/reports_controller.rb` -> `reports_controller`.
fn file_stem(file: &str) -> &str {
    let name = file.rsplit('/').next().unwrap_or(file);
    name.split_once('.').map_or(name, |(stem, _)| stem)
}

/// Whether `file` is the source file of a handler qualified as `qualifier`
/// in a route table: `OpsConsoleController` for
/// `.../OpsConsoleController.php`, and Rails' `reports` for
/// `.../reports_controller.rb`, whose file name adds the suffix the route
/// table leaves off.
fn qualifier_matches_file(qualifier: &str, file: &str) -> bool {
    let stem = normalize_ident(file_stem(file));
    let qual = normalize_ident(qualifier);
    !qual.is_empty() && (stem == qual || stem == format!("{qual}controller"))
}

/// Whether `text` names `ident` as a whole word — the route-table test.
/// Word-bounded so Rails' `reports#index` cannot match the line declaring
/// `ops#reindex`. Hand-rolled rather than a `\b`-anchored `Regex`, which
/// would have to be compiled per entry point per finding.
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

/// The source of `file` under `repo_root`, when both are known and the
/// path stays inside the jail. `None` for every fixture with no repo on
/// disk, which simply leaves the text-dependent matches unavailable.
fn read_file(repo_root: Option<&Path>, file: &str) -> Option<String> {
    let root = repo_root?;
    let path = bc_pathjail::confine(root, file)?;
    std::fs::read_to_string(path).ok()
}

/// The name of the function whose body contains `line` (1-based), found
/// by walking up from that line to the nearest definition — the same
/// "read what is really there" approach `lang_gates` takes to its
/// windows, and the only way to tie a finding to a handler when the
/// entry point lives in a different file.
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

/// The finding's own lines, used for the route-table match. A finding
/// anchored on `routes/web.php:24` is a finding about the route that line
/// declares, and the entry point for that route knows its guard.
fn own_lines(source: &str, f: &Finding) -> String {
    let lines: Vec<&str> = source.lines().collect();
    // `line_start`/`line_end` are 1-based and model-supplied, so "0",
    // inverted, and past-the-end are ordinary inputs. A start past the
    // end names nothing — it must NOT clamp back onto the last line.
    let lo = f.line_start.max(1) as usize;
    let hi = (f.line_end.max(f.line_start).max(1) as usize).min(lines.len());
    if lo > hi {
        return String::new();
    }
    lines[lo - 1..hi].join("\n")
}

/// A guard spelling read out of the handler's file, else the route
/// table's. Cosmetic only — see the module doc.
fn guard_label(finding_src: Option<&str>, route_src: Option<&str>) -> String {
    for src in [finding_src, route_src].into_iter().flatten() {
        if let Some(caps) = GUARD_NAME_RE.captures(src) {
            // [`GUARD_NAME_RE`] is a flat alternation of six capturing
            // alternatives, so a match always sets exactly one group.
            // `unwrap_or` names the last as the default rather than
            // leaving a branch no input can reach.
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

/// Whether this gate could possibly fire — a cheap CWE/wording test the
/// caller asks BEFORE paying for any file read, since the overwhelming
/// majority of findings claim something other than missing authorization.
pub fn could_apply(f: &Finding, routes: &RouteIndex) -> bool {
    !routes.is_empty() && claims_missing_authz(f) && !claims_a_bypass(f)
}

/// CWE-284/285/287/306/862/863, or the same claim in words under any
/// other CWE.
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

/// `Some(reason)` when every framework route that can reach this finding
/// is guarded, and the finding claims nothing about the guard itself.
///
/// Entry points are matched to the finding three ways, strongest first:
///
/// 1. **By handler name.** The finding's enclosing function equals the
///    entry point's function id — directly (axum's `export_report`, whose
///    route lives in `main.rs` and whose body lives in `handlers.rs`) or
///    after splitting a qualified id whose class/controller half also
///    names the finding's file (Laravel's
///    `OpsConsoleController@runMaintenance`, Rails' `reports#index`).
/// 2. **By route-table line.** The finding sits in a file that declares
///    routes, and its own lines name the entry point — `routes/web.php:24`,
///    `config/routes.rb:4`, `main.rs:47`. Such a finding is about the
///    route that line declares.
/// 3. **Whole file, as a fallback.** No entry point matched by name or
///    line, but the finding is inside a file that declares routes and
///    EVERY route it declares is guarded. This is what covers a finding
///    raised on the route table itself, and the Ktor routes whose entry
///    point ids are still synthesised from the path
///    (`post_ops_snapshot_restore`) because the lambda has a body of its
///    own or shares its delegate with another route. Deliberately the
///    weakest rule: it needs unanimity, so one open route anywhere in
///    the file disables it, and a finding it cannot reach is left to
///    S6's LANGUAGE FACTS.
///
/// Whatever the rule, a single matched entry point that IS reachable
/// without auth vetoes the drop.
pub fn guarded_route(f: &Finding, routes: &RouteIndex, repo_root: Option<&Path>) -> Option<String> {
    if !could_apply(f, routes) {
        return None;
    }
    let finding_src = read_file(repo_root, &f.file);
    // Midpoint first: a model routinely starts a range a line or two
    // early (a blank line, the previous action's `end`), and scanning back
    // from that line finds the handler ABOVE the one the finding is about —
    // a live Rails run matched "Missing Authorization Check in Reports
    // Index" (lines 17-26) to the open `search` action ending at line 17.
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

    // The route table is a second place to look for the guard's spelling
    // — Laravel and axum declare it there, away from the handler.
    let route_file = &matched[0].file;
    let route_src = (route_file != &f.file)
        .then(|| read_file(repo_root, route_file))
        .flatten();
    Some(guarded_route_reason(&guard_label(
        finding_src.as_deref(),
        route_src.as_deref(),
    )))
}

/// The CWE's numeric identity — the same normalization
/// [`crate::lang_gates`] keeps its own copy of, and for the same reason
/// (one bounded integer parse is not worth a dependency edge).
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
