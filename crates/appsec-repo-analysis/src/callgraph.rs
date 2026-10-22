//! Deterministic call-graph validation/supplementation, ported from
//! `s1_preprocess.py`'s `_supplement_call_graph` and helpers. The LLM's
//! emitted `call_graph` is sparse, unvalidated, and uses bare function
//! names; this pass (a) drops hallucinated names (no def-site or call-site
//! evidence anywhere in the source), (b) fills missing edges by
//! regex-scanning source for calls to known functions, and (c) records
//! def-site `file:line` locations for every function it sees.
//!
//! Nodes are file-qualified (`rel/path::function`) so polymorphic names
//! like `save`/`process` don't collapse the whole repo into one connected
//! component or shadow real entry→sink paths in the taint-chunking pass.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::sync::LazyLock;

use fancy_regex::Regex as FancyRegex;
use regex::Regex;

/// One scanned source file: (repo-relative path, its lines, its def-sites
/// as `(1-based line, function name)`).
type SourceFile = (String, Vec<String>, Vec<(usize, String)>);

pub const QSEP: &str = "::";
pub const MODULE_SCOPE: &str = "<module>";

pub fn q_join(file: &str, name: &str) -> String {
    format!("{file}{QSEP}{name}")
}

/// `(file, name)` — `file` is empty if `qname` carried no `::` separator.
pub fn q_split(qname: &str) -> (String, String) {
    match qname.rfind(QSEP) {
        Some(idx) => (
            qname[..idx].to_string(),
            qname[idx + QSEP.len()..].to_string(),
        ),
        None => (String::new(), qname.to_string()),
    }
}

pub fn q_file(qname: &str) -> String {
    q_split(qname).0
}

pub fn q_name(qname: &str) -> String {
    q_split(qname).1
}

/// File extensions this pass scans for def-sites/call-tokens, ported from
/// `vvaharness/lang/hints.py::EXT_TO_LANG`'s key set (the language each
/// maps to is irrelevant here — only "is this a source file at all"
/// matters for this pass).
pub const SOURCE_EXTENSIONS: &[&str] = &[
    ".aba",
    ".abap",
    ".ascx",
    ".asm",
    ".aspx",
    ".bas",
    ".bash",
    ".bat",
    ".bicep",
    ".c",
    ".cbl",
    ".cc",
    ".cjs",
    ".clj",
    ".cljc",
    ".cljs",
    ".cls",
    ".cmd",
    ".cob",
    ".cpp",
    ".cpy",
    ".cr",
    ".cs",
    ".cshtml",
    ".cts",
    ".cxx",
    ".dart",
    ".ddl",
    ".dml",
    ".edn",
    ".ejs",
    ".erb",
    ".erl",
    ".ex",
    ".exs",
    ".fnc",
    ".frm",
    ".fs",
    ".fsi",
    ".fsx",
    ".ftl",
    ".ftlh",
    ".go",
    ".groovy",
    ".gsh",
    ".gvy",
    ".gy",
    ".h",
    ".haml",
    ".handlebars",
    ".hbs",
    ".hcl",
    ".hpp",
    ".hrl",
    ".hs",
    ".htm",
    ".html",
    ".j2",
    ".jade",
    ".java",
    ".jcl",
    ".jinja",
    ".jinja2",
    ".jl",
    ".js",
    ".jsp",
    ".jspf",
    ".jspx",
    ".jsx",
    ".kt",
    ".kts",
    ".lhs",
    ".liquid",
    ".lua",
    ".m",
    ".mako",
    ".master",
    ".mjs",
    ".ml",
    ".mli",
    ".mm",
    ".mts",
    ".mustache",
    ".nim",
    ".nims",
    ".njk",
    ".php",
    ".phtml",
    ".pkb",
    ".pks",
    ".pl",
    ".plb",
    ".pls",
    ".plsql",
    ".pm",
    ".prc",
    ".ps1",
    ".psd1",
    ".psm1",
    ".pug",
    ".py",
    ".r",
    ".rb",
    ".rhtml",
    ".rs",
    ".s",
    ".sc",
    ".scala",
    ".sh",
    ".slim",
    ".sol",
    ".sql",
    ".svelte",
    ".swift",
    ".tag",
    ".tagx",
    ".tf",
    ".tfvars",
    ".trg",
    ".ts",
    ".tsql",
    ".tsx",
    ".twig",
    ".vb",
    ".vbhtml",
    ".vbs",
    ".vm",
    ".vtl",
    ".vue",
    ".vw",
    ".zig",
    ".zsh",
];

/// Language-agnostic function-definition patterns, checked in order per
/// line (`^`-anchored, matching Python's `re.match`). A pattern matching a
/// name in [`NOT_A_DEF`] does *not* stop the scan — the next pattern is
/// still tried against the same line, exactly mirroring the Python
/// original's `if m and m.group(1) not in _NOT_A_DEF` gate around both the
/// record and the `break`.
static DEF_RXS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        r"^\s*(?:async\s+)?def\s+(\w+)\s*\(",
        r"^\s*(?:export\s+)?(?:async\s+)?function\*?\s+(\w+)\s*\(",
        r"^\s*func\s+(?:\([^)]*\)\s*)?(\w+)\s*[(<]",
        r"^\s*fn\s+(\w+)",
        r"^\s*sub\s+(\w+)",
        r"^\s*(?:@\w+\s*)?(?:(?:public|private|protected|internal|static|final|override|virtual|abstract|async|synchronized|native|inline|extern)\s+)+[\w<>\[\],.?*&\s]+?\b(\w+)\s*\(",
        r"^\s*(?:[\w*&:]+\s+){1,2}(\w+)\s*\([^;()]*\)\s*\{",
        r"^\s{2,}(?:async\s+|static\s+|get\s+|set\s+)?(\w+)\s*\([^;()]*\)\s*\{",
    ]
    .iter()
    .map(|p| Regex::new(p).unwrap())
    .collect()
});

/// Also reused directly by [`crate::ts_graph`] — the Query-based backend
/// filters `@name`/`@callee` captures against the same not-a-def token set
/// (`ts_graph.py` imports `_NOT_A_DEF` from `s1_preprocess` for the same
/// reason).
pub static NOT_A_DEF: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    [
        "if",
        "for",
        "while",
        "switch",
        "catch",
        "return",
        "throw",
        "new",
        "else",
        "do",
        "try",
        "with",
        "using",
        "lock",
        "super",
        "this",
        "typeof",
        "delete",
        "sizeof",
        "instanceof",
        "synchronized",
        "yield",
        "await",
        "assert",
        "print",
    ]
    .into_iter()
    .collect()
});

/// Also reused directly by [`crate::ts_graph`]'s per-file regex fallback
/// for languages/files no tree-sitter query covers.
pub static CALL_TOKEN_RX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b([A-Za-z_]\w{2,})\s*\(").unwrap());

/// `(1-based line, function name)` for every recognized definition in
/// `lines`, in ascending line order.
pub fn scan_defs(lines: &[&str]) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        for rx in DEF_RXS.iter() {
            if let Some(caps) = rx.captures(line) {
                let name = &caps[1];
                if !NOT_A_DEF.contains(name) {
                    out.push((i + 1, name.to_string()));
                    break;
                }
            }
        }
    }
    out
}

/// Pick up to `max_targets` def-site files for bare `name`, called from
/// `caller_file`: same-file wins outright; a unique def-site wins; else
/// rank by longest common leading-path-segment count with `caller_file`
/// (deterministic tiebreak on the file path itself for equal scores —
/// the Python original ties break on a `set`'s arbitrary iteration order,
/// which isn't reproducible to begin with).
pub fn resolve_callee_files(
    name: &str,
    caller_file: &str,
    def_files: &HashMap<String, HashSet<String>>,
    max_targets: usize,
) -> Vec<String> {
    let Some(cands) = def_files.get(name) else {
        return Vec::new();
    };
    if cands.contains(caller_file) {
        return vec![caller_file.to_string()];
    }
    if cands.len() == 1 {
        return cands.iter().cloned().collect();
    }
    let caller_parts: Vec<&str> = caller_file.split('/').collect();
    let mut scored: Vec<(usize, String)> = cands
        .iter()
        .map(|f| {
            let score = caller_parts
                .iter()
                .zip(f.split('/'))
                .take_while(|(a, b)| **a == *b)
                .count();
            (score, f.clone())
        })
        .collect();
    scored.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    scored
        .into_iter()
        .take(max_targets)
        .map(|(_, f)| f)
        .collect()
}

#[derive(Debug, Clone, PartialEq)]
pub struct CallGraphConfig {
    pub validate: bool,
    pub supplement: bool,
    pub rounds: u32,
    pub max_targets: usize,
}

impl CallGraphConfig {
    pub fn new() -> Self {
        CallGraphConfig {
            validate: true,
            supplement: true,
            rounds: 4,
            max_targets: 3,
        }
    }
}

impl Default for CallGraphConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CallGraphReport {
    pub agent_edges: usize,
    pub dropped: usize,
    pub added: usize,
    pub source_files_scanned: usize,
    pub located_functions: usize,
    /// How many repo-defined function names seeded the supplement because
    /// the agent supplied no seeds at all (`0` on an agent-seeded run).
    /// A non-zero value means the call graph came from the deterministic
    /// backstop alone.
    pub backstop_seeds: usize,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct CallGraphResult {
    /// Qualified caller -> qualified callees, sorted.
    pub call_graph: BTreeMap<String, Vec<String>>,
    /// Bare function name -> sorted `"file:line"` def-sites, restricted to
    /// names appearing in `call_graph`.
    pub call_graph_files: BTreeMap<String, Vec<String>>,
    pub report: CallGraphReport,
}

/// Validate and supplement `raw_call_graph` (bare function names, as
/// emitted by the LLM) against a deterministic static scan of every source
/// file under `repo_root`. `entry_point_functions`/`sink_functions` seed
/// the supplement phase's regex-based expansion.
pub fn supplement_call_graph(
    raw_call_graph: &BTreeMap<String, Vec<String>>,
    entry_point_functions: &[String],
    sink_functions: &[String],
    all_files: &[String],
    repo_root: &Path,
    config: &CallGraphConfig,
) -> CallGraphResult {
    let raw_cg: HashMap<String, HashSet<String>> = raw_call_graph
        .iter()
        .filter(|(k, _)| !k.is_empty())
        .map(|(k, vs)| {
            (
                k.clone(),
                vs.iter().filter(|v| !v.is_empty()).cloned().collect(),
            )
        })
        .collect();
    let agent_edges = raw_cg.values().map(HashSet::len).sum();

    if !config.supplement && !config.validate {
        return CallGraphResult::default();
    }

    let mut seeds: HashSet<String> = HashSet::new();
    seeds.extend(
        entry_point_functions
            .iter()
            .filter(|f| !f.is_empty())
            .cloned(),
    );
    seeds.extend(sink_functions.iter().filter(|f| !f.is_empty()).cloned());
    seeds.extend(raw_cg.keys().cloned());
    for vs in raw_cg.values() {
        seeds.extend(vs.iter().cloned());
    }
    seeds.retain(|s| s.len() >= 3 && !NOT_A_DEF.contains(s.as_str()));

    // Static scan pass: every source file, once.
    let mut src_files: Vec<SourceFile> = Vec::new();
    let mut seen_call_tokens: HashSet<String> = HashSet::new();
    let mut fn_locs: HashMap<String, HashSet<String>> = HashMap::new();
    let mut def_files: HashMap<String, HashSet<String>> = HashMap::new();
    for rel in all_files {
        let ext = Path::new(rel)
            .extension()
            .map(|e| format!(".{}", e.to_string_lossy().to_lowercase()));
        if !ext.is_some_and(|e| SOURCE_EXTENSIONS.contains(&e.as_str())) {
            continue;
        }
        let Ok(bytes) = std::fs::read(repo_root.join(rel)) else {
            continue;
        };
        let text = String::from_utf8_lossy(&bytes).into_owned();
        let lines: Vec<String> = text.lines().map(str::to_string).collect();
        let line_refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        let defs = scan_defs(&line_refs);
        for (lineno, name) in &defs {
            fn_locs
                .entry(name.clone())
                .or_default()
                .insert(format!("{rel}:{lineno}"));
            def_files
                .entry(name.clone())
                .or_default()
                .insert(rel.clone());
        }
        for caps in CALL_TOKEN_RX.captures_iter(&text) {
            seen_call_tokens.insert(caps[1].to_string());
        }
        src_files.push((rel.clone(), lines, defs));
    }

    let seen_any: HashSet<String> = seen_call_tokens
        .union(&fn_locs.keys().cloned().collect())
        .cloned()
        .collect();

    let mut cg = qualify_and_validate(
        &raw_cg,
        &def_files,
        &seen_any,
        config.validate,
        config.max_targets,
    );
    let dropped = count_dropped(
        &raw_cg,
        &def_files,
        &seen_any,
        config.validate,
        config.max_targets,
    );

    // Deterministic backstop: when the agent produced nothing to seed from
    // (a refusal parsed down to an empty map, or a gap-fill run with no
    // entry points or sinks yet), seed the expansion from the definition
    // index this function just built from the files on disk. `fn_locs` is
    // agent-independent, so an empty agent map still yields a call graph.
    // Gating the supplement on `!seeds.is_empty()` (as v1.2 did) made the
    // backstop a no-op exactly when it was needed most. Agent-seeded runs
    // are unaffected: this only fires when `seeds` is empty. Ported from
    // upstream v1.3 `s1_preprocess.py`.
    let mut backstop_seeds = 0;
    if config.supplement && seeds.is_empty() {
        seeds = fn_locs
            .keys()
            .filter(|n| n.len() >= 3 && !NOT_A_DEF.contains(n.as_str()))
            .cloned()
            .collect();
        backstop_seeds = seeds.len();
        if backstop_seeds > 0 {
            tracing::info!(
                backstop_seeds,
                "[s1] call-graph supplement: no agent seeds; seeding from repo-defined \
                 function names (deterministic backstop)"
            );
        }
    }
    let added = if config.supplement && !seeds.is_empty() {
        run_supplement_rounds(&mut cg, &seeds, &seen_any, &src_files, &def_files, config)
    } else {
        0
    };

    let call_graph: BTreeMap<String, Vec<String>> = cg
        .into_iter()
        .filter(|(_, v)| !v.is_empty())
        .map(|(k, v)| {
            let mut v: Vec<String> = v.into_iter().collect();
            v.sort();
            (k, v)
        })
        .collect();

    let mut relevant: HashSet<String> = HashSet::new();
    for (k, vs) in &call_graph {
        relevant.insert(q_name(k));
        relevant.extend(vs.iter().map(|v| q_name(v)));
    }
    let call_graph_files: BTreeMap<String, Vec<String>> = fn_locs
        .into_iter()
        .filter(|(k, _)| relevant.contains(k))
        .map(|(k, v)| {
            let mut v: Vec<String> = v.into_iter().collect();
            v.sort();
            (k, v)
        })
        .collect();

    CallGraphResult {
        report: CallGraphReport {
            agent_edges,
            dropped,
            added,
            source_files_scanned: src_files.len(),
            located_functions: call_graph_files.len(),
            backstop_seeds,
        },
        call_graph,
        call_graph_files,
    }
}

fn resolve_targets_for(
    callee: &str,
    caller_file: &str,
    def_files: &HashMap<String, HashSet<String>>,
    max_targets: usize,
) -> Vec<String> {
    if !caller_file.is_empty() {
        return resolve_callee_files(callee, caller_file, def_files, max_targets);
    }
    let mut v: Vec<String> = def_files
        .get(callee)
        .map(|s| s.iter().cloned().collect())
        .unwrap_or_default();
    v.sort();
    v.truncate(max_targets);
    v
}

fn caller_sites_for(
    caller: &str,
    def_files: &HashMap<String, HashSet<String>>,
    max_targets: usize,
) -> Vec<String> {
    let mut sites: Vec<String> = def_files
        .get(caller)
        .map(|s| s.iter().cloned().collect())
        .unwrap_or_default();
    sites.sort();
    sites.truncate(max_targets);
    if sites.is_empty() {
        sites.push(String::new());
    }
    sites
}

fn qualify_and_validate(
    raw_cg: &HashMap<String, HashSet<String>>,
    def_files: &HashMap<String, HashSet<String>>,
    seen_any: &HashSet<String>,
    do_validate: bool,
    max_targets: usize,
) -> HashMap<String, HashSet<String>> {
    let mut cg: HashMap<String, HashSet<String>> = HashMap::new();
    let gate_active = do_validate && !seen_any.is_empty();
    for (caller, callees) in raw_cg {
        if gate_active && !seen_any.contains(caller) {
            continue;
        }
        for cf in caller_sites_for(caller, def_files, max_targets) {
            let key = if cf.is_empty() {
                caller.clone()
            } else {
                q_join(&cf, caller)
            };
            for callee in callees {
                if gate_active && !seen_any.contains(callee) {
                    continue;
                }
                let tgts = resolve_targets_for(callee, &cf, def_files, max_targets);
                if tgts.is_empty() {
                    if !do_validate {
                        cg.entry(key.clone()).or_default().insert(callee.clone());
                    }
                    continue;
                }
                for tf in &tgts {
                    cg.entry(key.clone())
                        .or_default()
                        .insert(q_join(tf, callee));
                }
            }
        }
    }
    cg
}

/// Recomputes how many agent-emitted edges [`qualify_and_validate`]
/// discarded — kept as a separate pass (rather than a mutable counter
/// threaded through the pure builder above) so the edge-building logic
/// stays a plain, easily-tested pure function.
fn count_dropped(
    raw_cg: &HashMap<String, HashSet<String>>,
    def_files: &HashMap<String, HashSet<String>>,
    seen_any: &HashSet<String>,
    do_validate: bool,
    max_targets: usize,
) -> usize {
    let mut dropped = 0usize;
    let gate_active = do_validate && !seen_any.is_empty();
    for (caller, callees) in raw_cg {
        if gate_active && !seen_any.contains(caller) {
            dropped += callees.len();
            continue;
        }
        let caller_sites = caller_sites_for(caller, def_files, max_targets);
        for callee in callees {
            if gate_active && !seen_any.contains(callee) {
                dropped += 1;
                continue;
            }
            if do_validate {
                let any_resolved = caller_sites
                    .iter()
                    .any(|cf| !resolve_targets_for(callee, cf, def_files, max_targets).is_empty());
                if !any_resolved {
                    dropped += caller_sites.len();
                }
            }
        }
    }
    dropped
}

#[allow(clippy::too_many_arguments)]
fn run_supplement_rounds(
    cg: &mut HashMap<String, HashSet<String>>,
    seeds: &HashSet<String>,
    seen_any: &HashSet<String>,
    src_files: &[SourceFile],
    def_files: &HashMap<String, HashSet<String>>,
    config: &CallGraphConfig,
) -> usize {
    let mut added = 0usize;
    let mut targets: HashSet<String> = if seen_any.is_empty() {
        seeds.clone()
    } else {
        seeds.intersection(seen_any).cloned().collect()
    };
    let mut known: HashSet<String> = targets.clone();

    for _ in 0..config.rounds.max(1) {
        if targets.is_empty() {
            break;
        }
        // Infallible here: `build_target_regex` only returns `None` for an
        // empty `targets`, and the loop already broke above when that was
        // true — see `build_target_regex`'s own doc comment.
        let rx = build_target_regex(&targets).expect("targets is non-empty here");
        let mut new_targets: HashSet<String> = HashSet::new();

        for (rel, lines, defs) in src_files {
            let mut cur: Option<&str> = None;
            let mut di = 0usize;
            for (idx, line) in lines.iter().enumerate() {
                let lineno = idx + 1;
                while di < defs.len() && defs[di].0 <= lineno {
                    cur = Some(defs[di].1.as_str());
                    di += 1;
                }
                for caps in rx.captures_iter(line) {
                    let Ok(caps) = caps else { break };
                    let callee = caps.get(1).expect("group 1 always matches").as_str();
                    let enclosing = cur.unwrap_or(MODULE_SCOPE);
                    if enclosing == callee {
                        continue;
                    }
                    let qcur = q_join(rel, enclosing);
                    for tf in resolve_callee_files(callee, rel, def_files, config.max_targets) {
                        let qcal = q_join(&tf, callee);
                        if cg.entry(qcur.clone()).or_default().insert(qcal) {
                            added += 1;
                        }
                    }
                    if let Some(c) = cur {
                        if !known.contains(c) {
                            new_targets.insert(c.to_string());
                        }
                    }
                }
            }
        }

        known.extend(new_targets.iter().cloned());
        targets = new_targets;
    }
    added
}

/// One alternation regex matching any of (up to 600, longest-first) target
/// names not preceded by a word character, followed by `(`. `None` if
/// `targets` is empty (never actually reached given the caller's own
/// `targets.is_empty()` guard, but kept honest rather than assuming).
fn build_target_regex(targets: &HashSet<String>) -> Option<FancyRegex> {
    let mut names: Vec<&String> = targets.iter().collect();
    names.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
    names.truncate(600);
    if names.is_empty() {
        return None;
    }
    let escaped: Vec<String> = names
        .iter()
        .map(|n| fancy_regex::escape(n).into_owned())
        .collect();
    let pattern = format!(r"(?<!\w)({})\s*\(", escaped.join("|"));
    FancyRegex::new(&pattern).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, rel: &str, contents: &str) {
        let path = dir.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }

    fn strs(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    // ── q_join / q_split / q_file / q_name ──────────────────────────────

    #[test]
    fn q_join_and_split_round_trip() {
        let q = q_join("src/a.py", "handler");
        assert_eq!(q, "src/a.py::handler");
        assert_eq!(q_split(&q), ("src/a.py".to_string(), "handler".to_string()));
        assert_eq!(q_file(&q), "src/a.py");
        assert_eq!(q_name(&q), "handler");
    }

    #[test]
    fn q_split_with_no_separator_has_an_empty_file() {
        assert_eq!(
            q_split("bare_name"),
            (String::new(), "bare_name".to_string())
        );
        assert_eq!(q_file("bare_name"), "");
        assert_eq!(q_name("bare_name"), "bare_name");
    }

    #[test]
    fn q_split_uses_the_rightmost_separator() {
        // A file path itself never contains "::", but the split is
        // rightmost-anchored regardless, matching Python's `rpartition`.
        assert_eq!(q_split("a::b::c"), ("a::b".to_string(), "c".to_string()));
    }

    // ── scan_defs ────────────────────────────────────────────────────────

    #[test]
    fn scan_defs_finds_a_python_def() {
        assert_eq!(
            scan_defs(&["def handler(request):"]),
            vec![(1, "handler".to_string())]
        );
    }

    #[test]
    fn scan_defs_finds_an_async_python_def() {
        assert_eq!(
            scan_defs(&["async def handler(request):"]),
            vec![(1, "handler".to_string())]
        );
    }

    #[test]
    fn scan_defs_finds_a_javascript_function() {
        assert_eq!(
            scan_defs(&["function process(x) {"]),
            vec![(1, "process".to_string())]
        );
        assert_eq!(
            scan_defs(&["export async function process(x) {"]),
            vec![(1, "process".to_string())]
        );
    }

    #[test]
    fn scan_defs_finds_a_go_func() {
        assert_eq!(
            scan_defs(&["func Handle(w http.ResponseWriter) {"]),
            vec![(1, "Handle".to_string())]
        );
        assert_eq!(
            scan_defs(&["func (s *Server) Handle(w http.ResponseWriter) {"]),
            vec![(1, "Handle".to_string())]
        );
    }

    #[test]
    fn scan_defs_finds_a_rust_fn() {
        assert_eq!(
            scan_defs(&["fn process(x: i32) -> i32 {"]),
            vec![(1, "process".to_string())]
        );
    }

    #[test]
    fn scan_defs_finds_a_perl_sub() {
        assert_eq!(
            scan_defs(&["sub handle_request {"]),
            vec![(1, "handle_request".to_string())]
        );
    }

    #[test]
    fn scan_defs_finds_a_java_style_method() {
        assert_eq!(
            scan_defs(&["    public static void processRequest(String input) {"]),
            vec![(1, "processRequest".to_string())]
        );
    }

    #[test]
    fn scan_defs_finds_a_c_style_function() {
        assert_eq!(
            scan_defs(&["int process_input(char *buf) {"]),
            vec![(1, "process_input".to_string())]
        );
    }

    #[test]
    fn scan_defs_finds_an_indented_method_body() {
        assert_eq!(
            scan_defs(&["  handleRequest(req, res) {"]),
            vec![(1, "handleRequest".to_string())]
        );
    }

    #[test]
    fn scan_defs_records_line_numbers_in_order() {
        let lines = ["def a():", "    pass", "def b():", "    pass"];
        assert_eq!(
            scan_defs(&lines),
            vec![(1, "a".to_string()), (3, "b".to_string())]
        );
    }

    #[test]
    fn scan_defs_skips_a_keyword_and_keeps_trying_other_patterns() {
        // "def return(x):" matches the Python-def pattern's shape with
        // "return" as the captured name, but "return" is a keyword, not a
        // def -- the scan must NOT stop there; it keeps trying the
        // remaining patterns against the same line (none of which match
        // this shape either, so the line yields nothing at all) rather
        // than recording a false def.
        assert_eq!(scan_defs(&["def return(x):"]), vec![]);
    }

    #[test]
    fn scan_defs_ignores_lines_matching_nothing() {
        assert_eq!(scan_defs(&["just some prose", "x = 1 + 2"]), vec![]);
    }

    // ── resolve_callee_files ─────────────────────────────────────────────

    fn def_files(pairs: &[(&str, &[&str])]) -> HashMap<String, HashSet<String>> {
        pairs
            .iter()
            .map(|(name, files)| {
                (
                    name.to_string(),
                    files.iter().map(|f| f.to_string()).collect(),
                )
            })
            .collect()
    }

    #[test]
    fn resolve_callee_files_same_file_wins_outright() {
        let df = def_files(&[("helper", &["a/b.py", "c/d.py"])]);
        assert_eq!(
            resolve_callee_files("helper", "a/b.py", &df, 3),
            vec!["a/b.py".to_string()]
        );
    }

    #[test]
    fn resolve_callee_files_unique_def_site_wins() {
        let df = def_files(&[("helper", &["only/here.py"])]);
        assert_eq!(
            resolve_callee_files("helper", "elsewhere.py", &df, 3),
            vec!["only/here.py".to_string()]
        );
    }

    #[test]
    fn resolve_callee_files_unknown_name_is_empty() {
        let df = def_files(&[]);
        assert!(resolve_callee_files("nope", "a.py", &df, 3).is_empty());
    }

    #[test]
    fn resolve_callee_files_ranks_by_common_path_prefix() {
        let df = def_files(&[("helper", &["a/b/near.py", "z/far.py"])]);
        // caller is under "a/b/..." -- "a/b/near.py" shares 2 leading
        // segments with "a/b/caller.py" while "z/far.py" shares 0, so it
        // ranks first; capping at 1 target confirms it's the one kept.
        assert_eq!(
            resolve_callee_files("helper", "a/b/caller.py", &df, 1),
            vec!["a/b/near.py".to_string()]
        );
    }

    #[test]
    fn resolve_callee_files_caps_at_max_targets() {
        let df = def_files(&[("helper", &["a.py", "b.py", "c.py", "d.py"])]);
        assert_eq!(
            resolve_callee_files("helper", "unrelated.py", &df, 2).len(),
            2
        );
    }

    // ── supplement_call_graph: end to end ───────────────────────────────

    #[test]
    fn config_default_matches_new() {
        assert_eq!(CallGraphConfig::default(), CallGraphConfig::new());
    }

    #[test]
    fn disabled_validate_and_supplement_returns_empty_result() {
        let dir = tempfile::tempdir().unwrap();
        let raw = BTreeMap::from([("a".to_string(), vec!["b".to_string()])]);
        let mut config = CallGraphConfig::new();
        config.validate = false;
        config.supplement = false;
        let result =
            supplement_call_graph(&raw, &[], &[], &["a.py".to_string()], dir.path(), &config);
        assert!(result.call_graph.is_empty());
        assert_eq!(result.report, CallGraphReport::default());
    }

    #[test]
    fn validation_drops_a_hallucinated_edge() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.py", "def real_caller():\n    pass\n");
        let raw = BTreeMap::from([(
            "real_caller".to_string(),
            vec!["totally_made_up_fn".to_string()],
        )]);
        let config = CallGraphConfig::new();
        let result =
            supplement_call_graph(&raw, &[], &[], &["a.py".to_string()], dir.path(), &config);
        // "totally_made_up_fn" was never seen anywhere in source, so the
        // edge is dropped entirely -- no entry is ever recorded for the
        // caller at all (an edge is only inserted once it has at least
        // one resolved callee).
        assert!(result.call_graph.is_empty());
        assert!(result.report.dropped > 0);
    }

    #[test]
    fn a_real_edge_between_two_known_functions_is_qualified_and_kept() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.py", "def caller():\n    pass\n");
        write(dir.path(), "b.py", "def callee():\n    pass\n");
        let raw = BTreeMap::from([("caller".to_string(), vec!["callee".to_string()])]);
        let config = CallGraphConfig::new();
        let result = supplement_call_graph(
            &raw,
            &[],
            &[],
            &["a.py".to_string(), "b.py".to_string()],
            dir.path(),
            &config,
        );
        assert_eq!(
            result.call_graph.get("a.py::caller"),
            Some(&vec!["b.py::callee".to_string()])
        );
    }

    #[test]
    fn supplement_discovers_a_regex_visible_call_edge_from_seeds() {
        let dir = tempfile::tempdir().unwrap();
        // No agent-emitted call_graph at all -- everything here must come
        // from the supplement phase's regex scan. The seed must be the
        // CALLEE ("validate_input"), not the caller: the scan searches
        // for *occurrences of a known name being called* and records
        // whatever enclosing function it finds them in -- an entry point
        // that's never itself called by anything in-repo can't be
        // discovered by searching for calls TO it.
        write(
            dir.path(),
            "app.py",
            "def handle_request():\n    validate_input()\n",
        );
        write(
            dir.path(),
            "validators.py",
            "def validate_input():\n    pass\n",
        );
        let raw = BTreeMap::new();
        let config = CallGraphConfig::new();
        let result = supplement_call_graph(
            &raw,
            &strs(&["validate_input"]),
            &[],
            &["app.py".to_string(), "validators.py".to_string()],
            dir.path(),
            &config,
        );
        assert_eq!(
            result.call_graph.get("app.py::handle_request"),
            Some(&vec!["validators.py::validate_input".to_string()])
        );
        assert!(result.report.added > 0);
    }

    #[test]
    fn supplement_expands_across_rounds_transitively() {
        let dir = tempfile::tempdir().unwrap();
        // entry -> mid -> sink, none of it agent-emitted. The scan works
        // backward from a known CALLEE: round 1 searches for "sink(" and
        // finds it inside "mid" (recording mid->sink, and discovering
        // "mid" as a newly-known name); round 2 searches for "mid(" and
        // finds it inside "entry" (recording entry->mid).
        write(dir.path(), "a.py", "def entry():\n    mid()\n");
        write(dir.path(), "b.py", "def mid():\n    sink()\n");
        write(dir.path(), "c.py", "def sink():\n    pass\n");
        let raw = BTreeMap::new();
        let config = CallGraphConfig::new();
        let result = supplement_call_graph(
            &raw,
            &strs(&["sink"]),
            &[],
            &["a.py".to_string(), "b.py".to_string(), "c.py".to_string()],
            dir.path(),
            &config,
        );
        assert_eq!(
            result.call_graph.get("a.py::entry"),
            Some(&vec!["b.py::mid".to_string()])
        );
        assert_eq!(
            result.call_graph.get("b.py::mid"),
            Some(&vec!["c.py::sink".to_string()])
        );
    }

    #[test]
    fn a_module_level_call_uses_the_module_scope_placeholder() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "app.py", "validate_input()\n");
        write(
            dir.path(),
            "validators.py",
            "def validate_input():\n    pass\n",
        );
        let raw = BTreeMap::new();
        let config = CallGraphConfig::new();
        let result = supplement_call_graph(
            &raw,
            &strs(&["validate_input"]),
            &[],
            &["app.py".to_string(), "validators.py".to_string()],
            dir.path(),
            &config,
        );
        let key = format!("app.py{QSEP}{MODULE_SCOPE}");
        assert_eq!(
            result.call_graph.get(&key),
            Some(&vec!["validators.py::validate_input".to_string()])
        );
    }

    #[test]
    fn a_self_recursive_call_is_not_recorded_as_an_edge() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.py", "def factorial():\n    factorial()\n");
        let raw = BTreeMap::new();
        let config = CallGraphConfig::new();
        let result = supplement_call_graph(
            &raw,
            &strs(&["factorial"]),
            &[],
            &["a.py".to_string()],
            dir.path(),
            &config,
        );
        assert!(!result.call_graph.contains_key("a.py::factorial"));
    }

    #[test]
    fn sink_functions_also_seed_the_supplement_scan() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "app.py", "def handler():\n    run_query()\n");
        write(dir.path(), "db.py", "def run_query():\n    pass\n");
        let raw = BTreeMap::new();
        let config = CallGraphConfig::new();
        let result = supplement_call_graph(
            &raw,
            &[],
            &strs(&["run_query"]),
            &["app.py".to_string(), "db.py".to_string()],
            dir.path(),
            &config,
        );
        assert_eq!(
            result.call_graph.get("app.py::handler"),
            Some(&vec!["db.py::run_query".to_string()])
        );
    }

    #[test]
    fn non_source_files_and_unreadable_files_are_skipped() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "notes.txt", "def fake_def():\n");
        write(dir.path(), "a.py", "def real():\n    pass\n");
        let raw = BTreeMap::new();
        let config = CallGraphConfig::new();
        let result = supplement_call_graph(
            &raw,
            &strs(&["real"]),
            &[],
            &[
                "notes.txt".to_string(),
                "missing.py".to_string(),
                "a.py".to_string(),
            ],
            dir.path(),
            &config,
        );
        assert_eq!(result.report.source_files_scanned, 1);
    }

    #[test]
    fn call_graph_files_is_restricted_to_names_relevant_to_the_final_graph() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "a.py",
            "def caller():\n    callee()\ndef unrelated():\n    pass\n",
        );
        write(dir.path(), "b.py", "def callee():\n    pass\n");
        let raw = BTreeMap::new();
        let config = CallGraphConfig::new();
        let result = supplement_call_graph(
            &raw,
            &strs(&["callee"]),
            &[],
            &["a.py".to_string(), "b.py".to_string()],
            dir.path(),
            &config,
        );
        assert!(result.call_graph_files.contains_key("caller"));
        assert!(result.call_graph_files.contains_key("callee"));
        assert!(!result.call_graph_files.contains_key("unrelated"));
    }

    #[test]
    fn empty_seeds_and_no_agent_graph_yields_an_empty_result() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.py", "def solo():\n    pass\n");
        let raw = BTreeMap::new();
        let config = CallGraphConfig::new();
        let result =
            supplement_call_graph(&raw, &[], &[], &["a.py".to_string()], dir.path(), &config);
        assert!(result.call_graph.is_empty());
        assert_eq!(result.report.added, 0);
        // The backstop still seeded from the one repo-defined name; it
        // just found no call to it.
        assert_eq!(result.report.backstop_seeds, 1);
    }

    #[test]
    fn no_agent_seeds_backstops_the_supplement_from_repo_definitions() {
        // Regression for the v1.2 gate: an agent that produced nothing
        // (no call graph, no entry points, no sinks) used to leave the
        // regex supplement a no-op, so the scan ran with no call graph.
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "a.py",
            "def handler():\n    helper()\n\ndef helper():\n    pass\n",
        );
        let raw = BTreeMap::new();
        let config = CallGraphConfig::new();
        let result =
            supplement_call_graph(&raw, &[], &[], &["a.py".to_string()], dir.path(), &config);
        assert_eq!(
            result.call_graph.get("a.py::handler"),
            Some(&vec!["a.py::helper".to_string()])
        );
        assert_eq!(result.report.backstop_seeds, 2);
        assert!(result.report.added > 0);
    }

    #[test]
    fn a_backstop_over_a_repo_with_no_definitions_seeds_nothing() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.py", "x = 1\n");
        let config = CallGraphConfig::new();
        let result = supplement_call_graph(
            &BTreeMap::new(),
            &[],
            &[],
            &["a.py".to_string()],
            dir.path(),
            &config,
        );
        assert_eq!(result.report.backstop_seeds, 0);
        assert!(result.call_graph.is_empty());
    }

    #[test]
    fn agent_seeds_never_trigger_the_backstop() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.py", "def handler():\n    helper()\n");
        let config = CallGraphConfig::new();
        let result = supplement_call_graph(
            &BTreeMap::new(),
            &strs(&["handler"]),
            &[],
            &["a.py".to_string()],
            dir.path(),
            &config,
        );
        assert_eq!(result.report.backstop_seeds, 0);
    }

    #[test]
    fn a_disabled_supplement_never_backstops() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.py", "def handler():\n    helper()\n");
        let mut config = CallGraphConfig::new();
        config.supplement = false;
        let result = supplement_call_graph(
            &BTreeMap::new(),
            &[],
            &[],
            &["a.py".to_string()],
            dir.path(),
            &config,
        );
        assert_eq!(result.report.backstop_seeds, 0);
        assert!(result.call_graph.is_empty());
    }

    #[test]
    fn validation_disabled_keeps_an_unresolvable_edge_unqualified() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.py", "def caller():\n    pass\n");
        let raw = BTreeMap::from([("caller".to_string(), vec!["nowhere_defined".to_string()])]);
        let mut config = CallGraphConfig::new();
        config.validate = false;
        let result =
            supplement_call_graph(&raw, &[], &[], &["a.py".to_string()], dir.path(), &config);
        // With validation off, an edge whose callee has no resolvable
        // def-site file is kept as a bare (unqualified) name rather than
        // dropped. (Supplement is still enabled but finds nothing new
        // here -- the only occurrence of "caller(" is its own def line,
        // a self-match the scan skips.)
        assert_eq!(
            result.call_graph.get("a.py::caller"),
            Some(&vec!["nowhere_defined".to_string()])
        );
    }

    #[test]
    fn a_caller_with_no_known_def_site_produces_an_unqualified_key_but_still_resolves_the_callee() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "b.py", "def real_callee():\n    pass\n");
        // "mystery_caller" never appears anywhere in source at all (not
        // even as a call token) -- with validation off, it's still
        // processed; `caller_sites_for` finds no def-site for it, so the
        // edge is recorded under the bare (unqualified) caller name.
        let raw = BTreeMap::from([(
            "mystery_caller".to_string(),
            vec!["real_callee".to_string()],
        )]);
        let mut config = CallGraphConfig::new();
        config.validate = false;
        let result =
            supplement_call_graph(&raw, &[], &[], &["b.py".to_string()], dir.path(), &config);
        assert_eq!(
            result.call_graph.get("mystery_caller"),
            Some(&vec!["b.py::real_callee".to_string()])
        );
    }

    #[test]
    fn validation_drops_an_entire_caller_never_seen_anywhere_in_source() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.py", "def real():\n    pass\n");
        // "ghost_caller" never appears anywhere in source -- unlike the
        // hallucinated-callee case above, here the CALLER itself fails
        // validation, so its whole edge set is dropped before ever
        // reaching per-callee resolution.
        let raw = BTreeMap::from([("ghost_caller".to_string(), vec!["real".to_string()])]);
        let config = CallGraphConfig::new();
        let result =
            supplement_call_graph(&raw, &[], &[], &["a.py".to_string()], dir.path(), &config);
        // "ghost_caller" is dropped before ever reaching per-callee
        // resolution, so no entry is recorded for it at all.
        assert!(result.call_graph.is_empty());
        assert!(result.report.dropped > 0);
    }

    #[test]
    fn validation_drops_a_seen_but_never_defined_callee() {
        let dir = tempfile::tempdir().unwrap();
        // "external_lib_call(" appears as a bare call (never a
        // recognized `def`), so it's a genuine member of `seen_any` --
        // unlike a pure hallucination, this exercises the "no resolvable
        // target file" drop path specifically, not the "never seen at
        // all" one.
        write(
            dir.path(),
            "a.py",
            "def caller():\n    pass\nexternal_lib_call()\n",
        );
        let raw = BTreeMap::from([("caller".to_string(), vec!["external_lib_call".to_string()])]);
        let config = CallGraphConfig::new();
        let result =
            supplement_call_graph(&raw, &[], &[], &["a.py".to_string()], dir.path(), &config);
        // The callee has no resolvable def-site anywhere, so no entry is
        // ever recorded for the caller either.
        assert!(!result.call_graph.contains_key("a.py::caller"));
        assert!(result.report.dropped > 0);
    }

    #[test]
    fn build_target_regex_is_none_for_an_empty_target_set() {
        // Provably unreachable through `run_supplement_rounds`'s own call
        // site (it already breaks out of the loop when `targets` is
        // empty, before ever calling this), so exercised directly.
        assert!(build_target_regex(&HashSet::new()).is_none());
    }

    #[test]
    fn seen_any_empty_uses_seeds_directly_without_intersecting() {
        // No source files at all, so `seen_any` ends up empty -- the
        // supplement phase's starting `targets` must still be seeded
        // directly from `seeds` rather than intersected with an empty
        // set, which would silently disable it even with real seeds.
        let dir = tempfile::tempdir().unwrap();
        let raw = BTreeMap::new();
        let config = CallGraphConfig::new();
        let result =
            supplement_call_graph(&raw, &strs(&["some_seed"]), &[], &[], dir.path(), &config);
        assert!(result.call_graph.is_empty());
        assert_eq!(result.report.added, 0);
    }
}
