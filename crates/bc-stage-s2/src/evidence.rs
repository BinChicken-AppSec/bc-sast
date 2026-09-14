//! Deterministic, LLM-free evidence gathering for the threat-model prompt,
//! ported from `s2_threatmodel.py::_gather_evidence` and its constants.
//! Everything here reasons over `ctx.all_files`/`ctx.modules`/
//! `ctx.entry_points` (S1's already-mapped surface) plus a handful of
//! disk reads (READMEs, manifests) keyed off fixed candidate lists.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use bc_model::{ContextPackage, EntryPointKind};
use regex::Regex;

use crate::Step2Config;

const DOC_CANDIDATES: &[&str] = &[
    "README.md",
    "README.rst",
    "README.txt",
    "README",
    "SECURITY.md",
    "THREAT_MODEL.md",
    "ARCHITECTURE.md",
    "CHANGELOG.md",
    "CHANGELOG",
];
const DOC_EXTRA_MAX: usize = 8;

static DOC_NAME_RX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(analysis|architecture|design|migration|specification|spec|threat|security|dataflow|data[_-]?flow|interface)",
    )
    .unwrap()
});

const MANIFEST_CANDIDATES: &[&str] = &[
    "package.json",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "setup.py",
    "pyproject.toml",
    "requirements.txt",
    "go.mod",
    "Cargo.toml",
    "Gemfile",
    "composer.json",
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    ".csproj",
];

const API_SURFACE_GLOBS: &[&str] = &[
    "*openapi*.y*ml",
    "*openapi*.json",
    "*swagger*.y*ml",
    "*swagger*.json",
    "*.proto",
    "*.graphql",
    "*.graphqls",
    "*.avsc",
    "*.wsdl",
    "*.thrift",
    "*META-INF/*",
    "*AndroidManifest.xml",
];

const CONFIG_EXTS: &[&str] = &[
    ".yml",
    ".yaml",
    ".json",
    ".toml",
    ".ini",
    ".properties",
    ".conf",
    ".cfg",
    ".env",
];

/// Entry-point kind -> STRIDE categories an attacker at that boundary can
/// typically pursue. Used as a prompt hint, not a constraint.
pub fn stride_for_kind(kind: &str) -> &'static str {
    match kind {
        "network" => "S T R I D E",
        "ipc" => "T I E",
        "file" => "T I D",
        "cli" => "T E",
        "deserialization" => "T E",
        _ => "T I",
    }
}

pub fn ep_kind_str(kind: EntryPointKind) -> &'static str {
    match kind {
        EntryPointKind::Network => "network",
        EntryPointKind::Ipc => "ipc",
        EntryPointKind::File => "file",
        EntryPointKind::Cli => "cli",
        EntryPointKind::Deserialization => "deserialization",
        EntryPointKind::Framework => "framework",
        EntryPointKind::Other => "other",
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Evidence {
    pub file_count: usize,
    /// The repo's TOTAL in-scope file count, before AST-frontier
    /// narrowing — set by the caller (`Stage2::run`) from the
    /// pre-narrowing `ContextPackage`, since by the time `gather_evidence`
    /// runs it only ever sees the already-narrowed frontier and has no
    /// way to recover the original count itself. `0` (the `Default`) for
    /// any caller that doesn't set it, e.g. direct unit tests of this
    /// struct that don't care about the frontier-vs-total distinction.
    pub original_file_count: usize,
    pub primary_language: String,
    /// Display language name -> file count, sorted descending by count
    /// (ties broken by first-encountered order, matching Python's
    /// `Counter.most_common()`).
    pub languages: Vec<(String, i64)>,
    pub top_dirs: Vec<String>,
    /// `(name, purpose, loc)`.
    pub modules: Vec<(String, String, i64)>,
    pub modules_truncated: bool,
    /// `(kind, reachable_from_unauth, file, function)`.
    pub entry_points: Vec<(String, bool, String, String)>,
    pub entry_points_truncated: bool,
    /// `(function, up-to-2 call sites, " lines N-M" or "")` — method-level
    /// anchors from the AST-frontier's `call_graph_files`/`def_spans`.
    /// Ported from `_gather_evidence`'s `function_sites` (`s2_threatmodel.py:311-316`).
    /// `call_graph_files` is a `BTreeMap` (sorted-by-name iteration),
    /// unlike the Python original's insertion-ordered `dict` — the same
    /// accepted, pre-existing divergence from `bc-model`'s own type
    /// choice already documented elsewhere (e.g. `bc-stage-s6::prompts`);
    /// only which entries survive the `max_function_sites` truncation can
    /// differ, never correctness.
    pub function_sites: Vec<(String, Vec<String>, String)>,
    /// `(caller, callee)`, one row per de-duplicated edge — ported from
    /// `_gather_evidence`'s `call_edges` (`s2_threatmodel.py:318-322`).
    /// Already bounded by the frontier's own `max_edges` cap (applied to
    /// `ctx.call_graph` before this function ever sees it), matching
    /// Python's `call_edges` having no separate cap of its own.
    pub call_edges: Vec<(String, String)>,
    pub config_reps: Vec<String>,
    pub api_artefacts: Vec<String>,
    /// `(name, body)`.
    pub docs: Vec<(String, String)>,
    /// `(relpath, body)`.
    pub manifests: Vec<(String, String)>,
    pub s1_notes: String,
}

fn file_stem(rel: &str) -> String {
    Path::new(rel)
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Read `path` as UTF-8 (lossy), truncating to `cap_chars` Unicode scalar
/// values (matching Python's codepoint-based `txt[:cap_chars]` slicing) —
/// `""` on any read failure, matching Python's bare `except Exception`.
fn read_capped(path: &Path, cap_chars: usize) -> String {
    let Ok(bytes) = std::fs::read(path) else {
        return String::new();
    };
    let txt = String::from_utf8_lossy(&bytes).into_owned();
    let char_count = txt.chars().count();
    if char_count > cap_chars {
        let truncated: String = txt.chars().take(cap_chars).collect();
        format!("{truncated}\n…(truncated, {char_count} chars total)")
    } else {
        txt
    }
}

/// `Path(root).rglob(f"*{suffix}")[:limit]`, sorted (Python's own order is
/// OS-directory-entry order — unspecified — so this sorts for determinism,
/// a strict improvement since only membership, never order, is meaningful
/// here). Symlinks are never traversed or matched (see below), avoiding a
/// symlink-cycle hang Python's own `rglob` doesn't guard against.
fn rglob_suffix(root: &Path, suffix: &str, limit: usize) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            // `symlink_metadata` (never follows symlinks, unlike
            // `DirEntry::file_type()`'s platform-dependent dirent-cache-or-
            // stat fallback) so a symlink — to a directory or a file — is
            // reliably never traversed into or matched, avoiding a
            // symlink-cycle hang Python's own `rglob` doesn't guard against.
            let is_symlink = std::fs::symlink_metadata(&path)
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false);
            if is_symlink {
                continue;
            }
            if path.is_dir() {
                stack.push(path);
            } else if path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(suffix))
            {
                if let Ok(rel) = path.strip_prefix(root) {
                    found.push(rel.to_string_lossy().replace('\\', "/"));
                }
            }
        }
    }
    found.sort();
    found.truncate(limit);
    found
}

/// Majority language breakdown, matching Python's
/// `collections.Counter(...).most_common()`: sorted descending by count,
/// ties broken by first-encountered order (a stable sort over an
/// insertion-ordered accumulator reproduces this exactly).
fn count_languages(all_files: &[String]) -> Vec<(String, i64)> {
    let mut order: Vec<&'static str> = Vec::new();
    let mut counts: std::collections::HashMap<&'static str, i64> = std::collections::HashMap::new();
    for f in all_files {
        let ext = bc_repo_analysis::suffix_lower(f);
        let Some(key) = bc_repo_analysis::ext_to_lang(&ext) else {
            continue;
        };
        let display = bc_repo_analysis::lang_display(key);
        // `lang_display` always returns a value from a fixed table for any
        // key `ext_to_lang` can produce, so this is effectively `&'static
        // str` in practice; leak-free since it's always a table literal.
        let display: &'static str = Box::leak(display.to_string().into_boxed_str());
        if !counts.contains_key(display) {
            order.push(display);
        }
        *counts.entry(display).or_insert(0) += 1;
    }
    let mut result: Vec<(String, i64)> = order
        .into_iter()
        .map(|d| (d.to_string(), counts[d]))
        .collect();
    result.sort_by_key(|(_, c)| std::cmp::Reverse(*c));
    result
}

pub fn gather_evidence(repo_root: &Path, config: &Step2Config, ctx: &ContextPackage) -> Evidence {
    let all_files = &ctx.all_files;
    let languages = count_languages(all_files);

    // ── Docs ──────────────────────────────────────────────────────────
    let mut docs: Vec<(String, String)> = Vec::new();
    let mut budget: i64 = config.max_doc_chars as i64;
    let half_cap = (config.max_doc_chars / 2) as i64;
    for name in DOC_CANDIDATES {
        let p = repo_root.join(name);
        if p.is_file() && budget > 0 {
            let cap = budget.min(half_cap).max(0) as usize;
            let body = read_capped(&p, cap);
            if !body.is_empty() {
                budget -= body.chars().count() as i64;
                docs.push((name.to_string(), body));
            }
        }
    }
    let seen_doc_names: HashSet<&str> = docs.iter().map(|(n, _)| n.as_str()).collect();
    let mut extras: Vec<&String> = all_files
        .iter()
        .filter(|rel| {
            let ext = bc_repo_analysis::suffix_lower(rel);
            (ext == ".md" || ext == ".rst")
                && !seen_doc_names.contains(rel.as_str())
                && DOC_NAME_RX.is_match(&file_stem(rel))
        })
        .collect();
    extras.sort();
    extras.truncate(DOC_EXTRA_MAX);
    if !extras.is_empty() {
        let per_cap: i64 = if budget > 0 {
            (budget / extras.len() as i64).max(1000)
        } else {
            0
        };
        for rel in &extras {
            if budget <= 0 {
                break;
            }
            // `rel` came off `ctx.all_files`, so confine it before reading
            // rather than trusting it stayed inside `repo_root` — a
            // `ContextPackage` loaded from an untrusted `--resume`
            // checkpoint is exactly the kind of indirection `bc_pathjail`
            // exists to guard against, even though today's live-walk path
            // is already safe by construction (CWE-22).
            let Some(path) = bc_pathjail::confine(repo_root, rel.as_str()) else {
                continue;
            };
            let cap = budget.min(per_cap).max(0) as usize;
            let body = read_capped(&path, cap);
            if !body.is_empty() {
                docs.push(((*rel).clone(), body.clone()));
                budget -= body.chars().count() as i64;
            }
        }
    }

    // ── Manifests ─────────────────────────────────────────────────────
    let mut manifests: Vec<(String, String)> = Vec::new();
    for name in MANIFEST_CANDIDATES {
        let hits: Vec<PathBuf> = if let Some(suffix) = name.strip_prefix('.') {
            rglob_suffix(repo_root, &format!(".{suffix}"), 3)
                .into_iter()
                .map(|r| repo_root.join(r))
                .collect()
        } else {
            let p = repo_root.join(name);
            if p.is_file() {
                vec![p]
            } else {
                Vec::new()
            }
        };
        // `hits` are already guaranteed files here (the non-dotted branch
        // only ever pushes a path after its own `is_file()` check;
        // `rglob_suffix` itself only ever matches non-directory entries),
        // unlike the Python original's `rglob(f"*{name}")`, which can also
        // match a directory literally named e.g. `foo.csproj` and so needs
        // its own re-check — not reproducing that redundant check here.
        for p in hits {
            let rel = p
                .strip_prefix(repo_root)
                .map(|r| r.to_string_lossy().replace('\\', "/"))
                .unwrap_or_default();
            manifests.push((rel, read_capped(&p, config.max_manifest_chars)));
        }
    }

    // ── Top-level components ─────────────────────────────────────────
    let mut top_dirs: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for rel in all_files {
        if let Some(idx) = rel.find('/') {
            top_dirs.insert(rel[..idx].to_string());
        }
    }
    let top_dirs: Vec<String> = top_dirs.into_iter().collect();

    // ── Modules / entry points ───────────────────────────────────────
    let modules_all: Vec<(String, String, i64)> = ctx
        .modules
        .iter()
        .map(|m| (m.name.clone(), m.purpose.clone(), m.loc))
        .collect();
    let modules_truncated = modules_all.len() > config.max_modules;
    let modules: Vec<(String, String, i64)> =
        modules_all.into_iter().take(config.max_modules).collect();

    let mut eps: Vec<(String, bool, String, String)> = ctx
        .entry_points
        .iter()
        .map(|e| {
            (
                ep_kind_str(e.kind).to_string(),
                e.reachable_from_unauth,
                e.file.clone(),
                e.function.clone(),
            )
        })
        .collect();
    eps.sort_by_key(|(kind, unauth, file, _)| {
        (kind != "network", !unauth, kind.clone(), file.clone())
    });
    let entry_points_truncated = eps.len() > config.max_entry_points;
    let entry_points: Vec<(String, bool, String, String)> =
        eps.into_iter().take(config.max_entry_points).collect();

    // ── AST function sites / call edges ───────────────────────────────
    let function_sites: Vec<(String, Vec<String>, String)> = ctx
        .call_graph_files
        .iter()
        .take(config.max_function_sites)
        .map(|(fn_name, sites)| {
            let span_txt = ctx
                .def_spans
                .get(fn_name)
                .map(|(start, end)| format!(" lines {start}-{end}"))
                .unwrap_or_default();
            (
                fn_name.clone(),
                sites.iter().take(2).cloned().collect(),
                span_txt,
            )
        })
        .collect();

    let mut call_edges: Vec<(String, String)> = Vec::new();
    for (caller, callees) in &ctx.call_graph {
        let mut seen: HashSet<&str> = HashSet::new();
        for callee in callees {
            if seen.insert(callee.as_str()) {
                call_edges.push((caller.clone(), callee.clone()));
            }
        }
    }

    // ── Representative config files (one per top-level dir) ──────────
    let mut cfg_reps: Vec<String> = Vec::new();
    let mut seen_dirs: HashSet<String> = HashSet::new();
    for rel in all_files {
        let ext = bc_repo_analysis::suffix_lower(rel);
        let name = Path::new(rel)
            .file_name()
            .map(|n| n.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        if CONFIG_EXTS.contains(&ext.as_str()) || CONFIG_EXTS.contains(&name.as_str()) {
            let top = rel.split('/').next().unwrap_or(rel).to_string();
            if seen_dirs.insert(top) {
                cfg_reps.push(rel.clone());
            }
        }
    }
    cfg_reps.truncate(config.max_config_reps);

    // ── API-contract artefacts ────────────────────────────────────────
    let mut api_artefacts: Vec<String> = Vec::new();
    for rel in all_files {
        let lower = rel.to_lowercase();
        if API_SURFACE_GLOBS
            .iter()
            .any(|g| bc_repo_analysis::fnmatch(rel, g) || bc_repo_analysis::fnmatch(&lower, g))
        {
            api_artefacts.push(rel.clone());
        }
    }
    api_artefacts.truncate(config.max_api_artefacts);

    Evidence {
        file_count: all_files.len(),
        // Set by the caller from the pre-narrowing `ContextPackage` — see
        // this field's own doc comment on `Evidence`.
        original_file_count: 0,
        primary_language: ctx.language.clone(),
        languages,
        top_dirs,
        modules,
        modules_truncated,
        entry_points,
        entry_points_truncated,
        function_sites,
        call_edges,
        config_reps: cfg_reps,
        api_artefacts,
        docs,
        manifests,
        s1_notes: ctx.notes.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_model::{EntryPoint, ModuleInfo};
    use rstest::rstest;

    fn write(dir: &Path, rel: &str, contents: &str) {
        let path = dir.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }

    fn minimal_ctx(all_files: Vec<String>) -> ContextPackage {
        ContextPackage {
            seed_taint_paths: Default::default(),
            seed_taint_evidence: Default::default(),
            def_spans: Default::default(),
            repo_root: "/repo".to_string(),
            language: "python".to_string(),
            call_graph: Default::default(),
            call_graph_files: Default::default(),
            entry_points: Vec::new(),
            unsafe_sinks: Vec::new(),
            modules: Vec::new(),
            all_files,
            excluded: Default::default(),
            known_cves: Vec::new(),
            design_controls: Vec::new(),
            changed_files: Default::default(),
            diff_scope_active: false,
            app_profile: None,
            threat_model: None,
            notes: String::new(),
            compliance_guidance: String::new(),
        }
    }

    // ── stride_for_kind / ep_kind_str ─────────────────────────────────

    #[rstest]
    #[case("network", "S T R I D E")]
    #[case("ipc", "T I E")]
    #[case("file", "T I D")]
    #[case("cli", "T E")]
    #[case("deserialization", "T E")]
    #[case("other", "T I")]
    #[case("unknown-kind", "T I")]
    fn stride_for_kind_mapping(#[case] kind: &str, #[case] expected: &str) {
        assert_eq!(stride_for_kind(kind), expected);
    }

    #[rstest]
    #[case(EntryPointKind::Network, "network")]
    #[case(EntryPointKind::Ipc, "ipc")]
    #[case(EntryPointKind::File, "file")]
    #[case(EntryPointKind::Cli, "cli")]
    #[case(EntryPointKind::Deserialization, "deserialization")]
    #[case(EntryPointKind::Framework, "framework")]
    #[case(EntryPointKind::Other, "other")]
    fn ep_kind_str_mapping(#[case] kind: EntryPointKind, #[case] expected: &str) {
        assert_eq!(ep_kind_str(kind), expected);
    }

    // ── gather_evidence: languages ─────────────────────────────────────

    #[test]
    fn gather_evidence_language_breakdown_sorted_by_count_ties_first_seen() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = minimal_ctx(vec![
            "a.rs".to_string(),
            "b.py".to_string(),
            "c.py".to_string(),
            "d.rs".to_string(),
            "e.txt".to_string(),
        ]);
        let config = Step2Config::new("m");
        let ev = gather_evidence(dir.path(), &config, &ctx);
        // python: 2, rust: 2 -> tie, first-encountered (rust from a.rs) wins first place
        assert_eq!(
            ev.languages,
            vec![("Rust".to_string(), 2), ("Python".to_string(), 2)]
        );
        assert_eq!(ev.file_count, 5);
        assert_eq!(ev.primary_language, "python");
    }

    #[test]
    fn gather_evidence_unrecognized_extensions_are_excluded_from_languages() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = minimal_ctx(vec!["README".to_string(), "Makefile".to_string()]);
        let ev = gather_evidence(dir.path(), &Step2Config::new("m"), &ctx);
        assert!(ev.languages.is_empty());
    }

    // ── gather_evidence: docs ──────────────────────────────────────────

    #[test]
    fn gather_evidence_finds_top_level_readme() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "README.md", "hello world");
        let ctx = minimal_ctx(vec!["README.md".to_string()]);
        let ev = gather_evidence(dir.path(), &Step2Config::new("m"), &ctx);
        assert_eq!(
            ev.docs,
            vec![("README.md".to_string(), "hello world".to_string())]
        );
    }

    #[test]
    fn gather_evidence_doc_candidates_checked_in_fixed_order() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "README.md", "one");
        write(dir.path(), "SECURITY.md", "two");
        let ctx = minimal_ctx(vec![]);
        let ev = gather_evidence(dir.path(), &Step2Config::new("m"), &ctx);
        assert_eq!(ev.docs[0].0, "README.md");
        assert_eq!(ev.docs[1].0, "SECURITY.md");
    }

    #[test]
    fn gather_evidence_doc_truncated_past_half_the_total_budget() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = Step2Config::new("m");
        cfg.max_doc_chars = 10; // half_cap = 5
        write(dir.path(), "README.md", "0123456789ABCDEF");
        let ctx = minimal_ctx(vec![]);
        let ev = gather_evidence(dir.path(), &cfg, &ctx);
        assert_eq!(ev.docs.len(), 1);
        assert!(ev.docs[0]
            .1
            .starts_with("01234\n…(truncated, 16 chars total)"));
    }

    #[test]
    fn gather_evidence_no_docs_found_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = minimal_ctx(vec![]);
        let ev = gather_evidence(dir.path(), &Step2Config::new("m"), &ctx);
        assert!(ev.docs.is_empty());
    }

    #[test]
    fn gather_evidence_extra_docs_matched_by_name_regex_sorted_and_capped() {
        let dir = tempfile::tempdir().unwrap();
        let mut all_files = Vec::new();
        for i in 0..10 {
            let rel = format!("docs/architecture-{i}.md");
            write(dir.path(), &rel, "extra doc body");
            all_files.push(rel);
        }
        // A .md file that does NOT match the name regex must be excluded.
        write(dir.path(), "docs/random.md", "unrelated");
        all_files.push("docs/random.md".to_string());
        let ctx = minimal_ctx(all_files);
        let ev = gather_evidence(dir.path(), &Step2Config::new("m"), &ctx);
        assert_eq!(ev.docs.len(), DOC_EXTRA_MAX);
        assert!(ev
            .docs
            .iter()
            .all(|(name, _)| name.starts_with("docs/architecture-")));
        // sorted alphabetically -> architecture-0 before architecture-1
        assert_eq!(ev.docs[0].0, "docs/architecture-0.md");
    }

    #[test]
    fn gather_evidence_an_extra_doc_path_that_escapes_the_repo_root_is_skipped_not_read() {
        let dir = tempfile::tempdir().unwrap();
        // Never actually created inside `dir` — if the escape guard were
        // missing, this would resolve to a real file one level up and get
        // read into the prompt.
        let ctx = minimal_ctx(vec!["../architecture.md".to_string()]);
        let ev = gather_evidence(dir.path(), &Step2Config::new("m"), &ctx);
        assert!(ev.docs.is_empty());
    }

    #[test]
    fn gather_evidence_extra_doc_already_picked_as_top_level_candidate_is_not_duplicated() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "README.md", "root readme");
        let ctx = minimal_ctx(vec!["README.md".to_string()]);
        let ev = gather_evidence(dir.path(), &Step2Config::new("m"), &ctx);
        assert_eq!(ev.docs.len(), 1);
    }

    #[test]
    fn gather_evidence_extra_docs_stop_once_budget_is_exhausted() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = Step2Config::new("m");
        cfg.max_doc_chars = 10;
        // The top-level README alone consumes (and overruns, once the
        // truncation suffix is added) the entire budget, so the extras
        // loop must never read `docs/architecture.md` at all.
        write(dir.path(), "README.md", "0123456789ABCDEF");
        write(
            dir.path(),
            "docs/architecture.md",
            "some architecture notes",
        );
        let ctx = minimal_ctx(vec![
            "README.md".to_string(),
            "docs/architecture.md".to_string(),
        ]);
        let ev = gather_evidence(dir.path(), &cfg, &ctx);
        assert_eq!(ev.docs.len(), 1);
        assert_eq!(ev.docs[0].0, "README.md");
    }

    // ── gather_evidence: manifests ──────────────────────────────────────

    #[test]
    fn gather_evidence_finds_top_level_manifest() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "package.json", "{}");
        let ctx = minimal_ctx(vec!["package.json".to_string()]);
        let ev = gather_evidence(dir.path(), &Step2Config::new("m"), &ctx);
        assert_eq!(
            ev.manifests,
            vec![("package.json".to_string(), "{}".to_string())]
        );
    }

    #[test]
    fn gather_evidence_finds_dotted_manifest_recursively() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "src/MyProj/MyProj.csproj",
            "<Project></Project>",
        );
        let ctx = minimal_ctx(vec!["src/MyProj/MyProj.csproj".to_string()]);
        let ev = gather_evidence(dir.path(), &Step2Config::new("m"), &ctx);
        assert_eq!(ev.manifests.len(), 1);
        assert_eq!(ev.manifests[0].0, "src/MyProj/MyProj.csproj");
    }

    #[test]
    fn gather_evidence_dotted_manifest_search_is_capped_at_three_and_sorted() {
        let dir = tempfile::tempdir().unwrap();
        let mut all_files = Vec::new();
        for i in 0..5 {
            let rel = format!("proj{i}/p.csproj");
            write(dir.path(), &rel, "<Project/>");
            all_files.push(rel);
        }
        let ctx = minimal_ctx(all_files);
        let ev = gather_evidence(dir.path(), &Step2Config::new("m"), &ctx);
        assert_eq!(ev.manifests.len(), 3);
        assert_eq!(ev.manifests[0].0, "proj0/p.csproj");
        assert_eq!(ev.manifests[1].0, "proj1/p.csproj");
        assert_eq!(ev.manifests[2].0, "proj2/p.csproj");
    }

    #[test]
    fn gather_evidence_no_manifests_found_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = minimal_ctx(vec![]);
        let ev = gather_evidence(dir.path(), &Step2Config::new("m"), &ctx);
        assert!(ev.manifests.is_empty());
    }

    #[test]
    fn gather_evidence_symlinked_directory_is_not_followed_during_manifest_rglob() {
        let dir = tempfile::tempdir().unwrap();
        // A genuinely separate tempdir, so the ONLY path to `evil.csproj`
        // from `dir` is through the "linked" symlink below — not, as a
        // symlink-inside-`dir`-pointing-to-a-real-subdir-of-`dir` would be,
        // also directly reachable by the real (non-symlink) traversal.
        let outside = tempfile::tempdir().unwrap();
        write(outside.path(), "evil.csproj", "<Project/>");
        #[cfg(unix)]
        std::os::unix::fs::symlink(outside.path(), dir.path().join("linked")).unwrap();
        let ctx = minimal_ctx(vec![]);
        let ev = gather_evidence(dir.path(), &Step2Config::new("m"), &ctx);
        assert!(ev.manifests.is_empty());
    }

    // ── gather_evidence: top_dirs ────────────────────────────────────────

    #[test]
    fn gather_evidence_top_dirs_sorted_and_deduped() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = minimal_ctx(vec![
            "b/x.py".to_string(),
            "a/y.py".to_string(),
            "a/z.py".to_string(),
            "root.py".to_string(),
        ]);
        let ev = gather_evidence(dir.path(), &Step2Config::new("m"), &ctx);
        assert_eq!(ev.top_dirs, vec!["a".to_string(), "b".to_string()]);
    }

    // ── gather_evidence: modules / entry points ──────────────────────────

    #[test]
    fn gather_evidence_modules_truncated_flag() {
        let dir = tempfile::tempdir().unwrap();
        let mut ctx = minimal_ctx(vec![]);
        ctx.modules = (0..5)
            .map(|i| ModuleInfo {
                name: format!("m{i}"),
                files: vec![],
                loc: 10,
                purpose: "p".to_string(),
            })
            .collect();
        let mut cfg = Step2Config::new("m");
        cfg.max_modules = 2;
        let ev = gather_evidence(dir.path(), &cfg, &ctx);
        assert_eq!(ev.modules.len(), 2);
        assert!(ev.modules_truncated);
    }

    #[test]
    fn gather_evidence_modules_not_truncated_when_under_cap() {
        let dir = tempfile::tempdir().unwrap();
        let mut ctx = minimal_ctx(vec![]);
        ctx.modules = vec![ModuleInfo {
            name: "m".to_string(),
            files: vec![],
            loc: 1,
            purpose: "p".to_string(),
        }];
        let ev = gather_evidence(dir.path(), &Step2Config::new("m"), &ctx);
        assert!(!ev.modules_truncated);
    }

    #[test]
    fn gather_evidence_entry_points_sorted_network_and_unauth_first() {
        let dir = tempfile::tempdir().unwrap();
        let mut ctx = minimal_ctx(vec![]);
        ctx.entry_points = vec![
            EntryPoint {
                file: "b.py".to_string(),
                function: "g".to_string(),
                kind: EntryPointKind::Cli,
                reachable_from_unauth: false,
            },
            EntryPoint {
                file: "a.py".to_string(),
                function: "f".to_string(),
                kind: EntryPointKind::Network,
                reachable_from_unauth: true,
            },
            EntryPoint {
                file: "c.py".to_string(),
                function: "h".to_string(),
                kind: EntryPointKind::Network,
                reachable_from_unauth: false,
            },
        ];
        let ev = gather_evidence(dir.path(), &Step2Config::new("m"), &ctx);
        assert_eq!(ev.entry_points[0].0, "network");
        assert!(ev.entry_points[0].1); // unauth network entry sorts first
        assert_eq!(ev.entry_points[1].2, "c.py"); // network, non-unauth, second
        assert_eq!(ev.entry_points[2].2, "b.py"); // cli last
    }

    #[test]
    fn gather_evidence_entry_points_truncated_flag() {
        let dir = tempfile::tempdir().unwrap();
        let mut ctx = minimal_ctx(vec![]);
        ctx.entry_points = (0..3)
            .map(|i| EntryPoint {
                file: format!("f{i}.py"),
                function: "f".to_string(),
                kind: EntryPointKind::Other,
                reachable_from_unauth: false,
            })
            .collect();
        let mut cfg = Step2Config::new("m");
        cfg.max_entry_points = 1;
        let ev = gather_evidence(dir.path(), &cfg, &ctx);
        assert_eq!(ev.entry_points.len(), 1);
        assert!(ev.entry_points_truncated);
    }

    // ── gather_evidence: config reps / api artefacts ─────────────────────

    #[test]
    fn gather_evidence_config_reps_keep_one_per_top_level_dir() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = minimal_ctx(vec![
            "svc1/config.yaml".to_string(),
            "svc1/other.yaml".to_string(),
            "svc2/config.yaml".to_string(),
            ".env".to_string(),
        ]);
        let ev = gather_evidence(dir.path(), &Step2Config::new("m"), &ctx);
        assert_eq!(
            ev.config_reps,
            vec![
                "svc1/config.yaml".to_string(),
                "svc2/config.yaml".to_string(),
                ".env".to_string()
            ]
        );
    }

    #[test]
    fn gather_evidence_config_reps_truncated_at_cap() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = minimal_ctx(vec![
            "a/x.yaml".to_string(),
            "b/x.yaml".to_string(),
            "c/x.yaml".to_string(),
        ]);
        let mut cfg = Step2Config::new("m");
        cfg.max_config_reps = 2;
        let ev = gather_evidence(dir.path(), &cfg, &ctx);
        assert_eq!(ev.config_reps.len(), 2);
    }

    #[test]
    fn gather_evidence_api_artefacts_matched_and_capped() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = minimal_ctx(vec![
            "api/openapi.yaml".to_string(),
            "proto/service.proto".to_string(),
            "app.py".to_string(),
        ]);
        let ev = gather_evidence(dir.path(), &Step2Config::new("m"), &ctx);
        assert_eq!(
            ev.api_artefacts,
            vec![
                "api/openapi.yaml".to_string(),
                "proto/service.proto".to_string()
            ]
        );
    }

    #[test]
    fn gather_evidence_api_artefacts_case_insensitive_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = minimal_ctx(vec!["API/OPENAPI.YAML".to_string()]);
        let ev = gather_evidence(dir.path(), &Step2Config::new("m"), &ctx);
        assert_eq!(ev.api_artefacts, vec!["API/OPENAPI.YAML".to_string()]);
    }

    #[test]
    fn gather_evidence_s1_notes_passthrough() {
        let dir = tempfile::tempdir().unwrap();
        let mut ctx = minimal_ctx(vec![]);
        ctx.notes = "free form notes".to_string();
        let ev = gather_evidence(dir.path(), &Step2Config::new("m"), &ctx);
        assert_eq!(ev.s1_notes, "free form notes");
    }

    // ── gather_evidence: function_sites / call_edges ───────────────────

    #[test]
    fn gather_evidence_function_sites_include_up_to_two_call_sites_and_a_span() {
        let dir = tempfile::tempdir().unwrap();
        let mut ctx = minimal_ctx(vec![]);
        ctx.call_graph_files.insert(
            "app.py::handler".to_string(),
            vec![
                "a.py:1".to_string(),
                "b.py:2".to_string(),
                "c.py:3".to_string(),
            ],
        );
        ctx.def_spans
            .insert("app.py::handler".to_string(), (10, 20));
        let ev = gather_evidence(dir.path(), &Step2Config::new("m"), &ctx);
        assert_eq!(
            ev.function_sites,
            vec![(
                "app.py::handler".to_string(),
                vec!["a.py:1".to_string(), "b.py:2".to_string()],
                " lines 10-20".to_string(),
            )]
        );
    }

    #[test]
    fn gather_evidence_function_sites_with_no_span_has_an_empty_suffix() {
        let dir = tempfile::tempdir().unwrap();
        let mut ctx = minimal_ctx(vec![]);
        ctx.call_graph_files
            .insert("app.py::handler".to_string(), vec!["a.py:1".to_string()]);
        let ev = gather_evidence(dir.path(), &Step2Config::new("m"), &ctx);
        assert_eq!(ev.function_sites[0].2, "");
    }

    #[test]
    fn gather_evidence_function_sites_are_truncated_at_max_function_sites() {
        let dir = tempfile::tempdir().unwrap();
        let mut ctx = minimal_ctx(vec![]);
        for i in 0..5 {
            ctx.call_graph_files
                .insert(format!("fn_{i:02}"), vec!["a.py:1".to_string()]);
        }
        let mut config = Step2Config::new("m");
        config.max_function_sites = 2;
        let ev = gather_evidence(dir.path(), &config, &ctx);
        assert_eq!(ev.function_sites.len(), 2);
    }

    #[test]
    fn gather_evidence_call_edges_dedup_repeated_callees_per_caller() {
        let dir = tempfile::tempdir().unwrap();
        let mut ctx = minimal_ctx(vec![]);
        ctx.call_graph.insert(
            "caller".to_string(),
            vec![
                "callee_a".to_string(),
                "callee_b".to_string(),
                "callee_a".to_string(),
            ],
        );
        let ev = gather_evidence(dir.path(), &Step2Config::new("m"), &ctx);
        assert_eq!(
            ev.call_edges,
            vec![
                ("caller".to_string(), "callee_a".to_string()),
                ("caller".to_string(), "callee_b".to_string()),
            ]
        );
    }

    #[test]
    fn gather_evidence_original_file_count_defaults_to_zero_until_the_caller_sets_it() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = minimal_ctx(vec!["a.py".to_string()]);
        let ev = gather_evidence(dir.path(), &Step2Config::new("m"), &ctx);
        assert_eq!(ev.original_file_count, 0);
    }

    #[test]
    fn read_capped_missing_file_is_empty() {
        assert_eq!(
            read_capped(Path::new("/nonexistent/does-not-exist.txt"), 100),
            ""
        );
    }
}
