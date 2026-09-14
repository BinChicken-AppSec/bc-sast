//! Catch-all coverage sweep for files no chunk claimed, ported from
//! `s3_decompose.py`'s `_catchall_eligible`/`_add_catchall_chunks`/
//! `_mk_catchall`.

use std::collections::HashSet;
use std::path::Path;

use bc_model::{Chunk, ChunkSize, ContextPackage};

use crate::grouping::cohesive_groups;
use crate::pack::{char_budget, pack};
use crate::Step3Config;

const CATCHALL_SKIP_EXTS: &[&str] = &[
    ".md", ".mdx", ".txt", ".rst", ".adoc", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".webp", ".woff", ".woff2", ".ttf", ".eot", ".css", ".scss", ".sass", ".less", ".lock", ".log",
    ".map", ".min.js", ".min.css", ".snap", ".d.ts", ".csv", ".tsv", ".xls", ".xlsx", ".po",
    ".pot", ".mo",
];

const CATCHALL_SKIP_NAMES: &[&str] = &[
    "license",
    "changelog",
    "changes",
    "authors",
    "contributors",
    "notice",
    "readme",
    "codeowners",
    ".gitignore",
    ".gitattributes",
    ".editorconfig",
    ".prettierrc",
    ".prettierignore",
    ".eslintignore",
    ".dockerignore",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "pipfile.lock",
    "go.sum",
    "cargo.lock",
    "composer.lock",
];

const CATCHALL_SKIP_DIR_PARTS: &[&str] = &[
    "__snapshots__",
    "__fixtures__",
    "fixtures",
    "__mocks__",
    "mocks",
    "docs",
    "doc",
    "examples",
    "example",
    "samples",
];

/// Files that can't realistically carry an exploitable vuln (docs, locks,
/// snapshots, images, …) are dropped from catch-all coverage so dozens of
/// chunks of noise don't get scanned. Credential-prone dotfiles (`.env`,
/// `.npmrc`, keys/certs) are deliberately KEPT.
pub fn catchall_eligible(rel: &str) -> bool {
    let path = Path::new(rel);
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(rel)
        .to_lowercase();
    if CATCHALL_SKIP_NAMES.contains(&name.as_str()) {
        return false;
    }
    let suffix = path
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy().to_lowercase()))
        .unwrap_or_default();
    if CATCHALL_SKIP_EXTS.contains(&suffix.as_str()) {
        return false;
    }
    // Also test every trailing dotted tail (not just the single final
    // suffix) to catch multi-dot names like `foo.bundle.min.js`, whose
    // only final suffix (`.js`) isn't itself a skip key but the tail
    // `.min.js` is.
    if CATCHALL_SKIP_EXTS.iter().any(|ext| name.ends_with(ext)) {
        return false;
    }
    let dir_parts: Vec<&str> = rel.split('/').collect();
    let dir_parts = &dir_parts[..dir_parts.len().saturating_sub(1)];
    if dir_parts
        .iter()
        .any(|part| CATCHALL_SKIP_DIR_PARTS.contains(&part.to_lowercase().as_str()))
    {
        return false;
    }
    true
}

fn size_for(loc: i64) -> ChunkSize {
    bc_repo_analysis::size_for(loc.max(0) as usize)
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct CatchallResult {
    pub chunks: Vec<Chunk>,
    /// Files `step3.catchall_mode=reachable_only` dropped from this sweep
    /// (call-graph unreachable from any entry point/sink). Always empty
    /// under `mode: all` (the default) or when the reachable-only gate
    /// itself fell back to `all` (no entry points/sinks, or too sparse).
    pub unreachable_files: Vec<String>,
}

fn mk_catchall(idx: usize, dir_name: &str, files: Vec<String>, loc: i64, rank: i64) -> Chunk {
    Chunk {
        id: format!("catchall-{idx:02}"),
        size: size_for(loc),
        risk_rank: rank,
        files,
        focus_entry_points: Vec::new(),
        hypothesis: format!("Coverage sweep of '{dir_name}' — files not assigned to any risk-ranked chunk. Hunt for any vulnerability class."),
        related_cves: Vec::new(),
        threat_id: None,
        languages: Vec::new(),
        specialist: None,
        path_funcs: Vec::new(),
        source_ref: String::new(),
        sink_ref: String::new(),
        sink_cwe: Vec::new(),
    }
}

/// Under `step3.catchall_mode: reachable_only`, drop any catch-all
/// candidate that is NOT forward-reachable from an entry point NOR
/// backward-reachable from a sink on the file-level call graph. Falls back
/// to `eligible` unchanged (no gating) when there are no entry
/// points/sinks at all (gating would otherwise drop the whole repo) or
/// when the reachable set is too sparse to trust
/// ([`bc_repo_analysis::reachable_only_too_sparse`]). Returns
/// `(kept_eligible, dropped)`. Ported from `_add_catchall_chunks`'s own
/// reachable-only gate block.
fn apply_reachable_only_gate(
    eligible: Vec<String>,
    ctx: &ContextPackage,
    config: &Step3Config,
) -> (Vec<String>, Vec<String>) {
    if !config.catchall_mode.eq_ignore_ascii_case("reachable_only") || eligible.is_empty() {
        return (eligible, Vec::new());
    }
    if ctx.entry_points.is_empty() && ctx.unsafe_sinks.is_empty() {
        return (eligible, Vec::new());
    }

    let all_file_set: HashSet<&str> = ctx.all_files.iter().map(String::as_str).collect();
    let reach: HashSet<String> = bc_repo_analysis::reachable_files(ctx)
        .into_iter()
        .filter(|f| all_file_set.contains(f.as_str()))
        .collect();
    let before = eligible.len();
    let mut dropped: Vec<String> = eligible
        .iter()
        .filter(|f| !reach.contains(f.as_str()))
        .cloned()
        .collect();
    dropped.sort();
    let kept: Vec<String> = eligible
        .iter()
        .filter(|f| reach.contains(f.as_str()))
        .cloned()
        .collect();

    let (too_sparse, _reason) = bc_repo_analysis::reachable_only_too_sparse(
        kept.len(),
        before,
        config.catchall_reachable_min_ratio,
        config.catchall_reachable_min_files,
    );
    if too_sparse {
        (eligible, Vec::new())
    } else {
        (kept, dropped)
    }
}

/// Create low-rank chunks for every file not already assigned to a chunk.
/// Returns the new chunks (appended to the manifest by the caller) plus
/// any files `catchall_mode: reachable_only` dropped — kept as a pure
/// function returning new state, matching this crate's other
/// manifest-mutating passes' shape.
pub fn add_catchall_chunks(
    existing_chunks: &[Chunk],
    ctx: &ContextPackage,
    config: &Step3Config,
) -> CatchallResult {
    let covered: HashSet<&str> = existing_chunks
        .iter()
        .flat_map(|c| c.files.iter().map(String::as_str))
        .collect();
    // Diff-scope active: narrow the sweep to changed files only — anything
    // else would just get trimmed back out by S3's final trim pass anyway,
    // so this only skips real disk I/O in `pack()` for files that would be
    // discarded regardless. Branches on `diff_scope_active`, NOT on
    // `changed_files.is_empty()`: a rename-only PR is a diff-scoped scan
    // of zero files, and treating its empty map as "no diff scope" would
    // sweep the entire repository at full LLM spend.
    let candidates: Vec<&String> = if ctx.diff_scope_active {
        ctx.changed_files.keys().collect()
    } else {
        ctx.all_files.iter().collect()
    };
    let uncovered: Vec<String> = candidates
        .into_iter()
        .filter(|f| !covered.contains(f.as_str()))
        .cloned()
        .collect();

    if !config.catchall_enabled {
        return CatchallResult::default();
    }
    let eligible: Vec<String> = uncovered
        .into_iter()
        .filter(|f| catchall_eligible(f))
        .collect();

    let (eligible, unreachable_files) = apply_reachable_only_gate(eligible, ctx, config);

    if eligible.is_empty() {
        return CatchallResult {
            chunks: Vec::new(),
            unreachable_files,
        };
    }

    let repo_root = Path::new(&ctx.repo_root);
    let max_loc = config.catchall_chunk_loc;
    let max_files = config.catchall_max_files;
    let base_rank = existing_chunks
        .iter()
        .map(|c| c.risk_rank)
        .max()
        .unwrap_or(0);

    let groups = cohesive_groups(&eligible, ctx);
    let buckets = pack(
        &groups,
        repo_root,
        max_loc,
        max_files,
        char_budget(config),
        config.pack_merge_underfilled,
    );

    let chunks = buckets
        .into_iter()
        .enumerate()
        .map(|(i, (label, files, loc))| {
            mk_catchall(i + 1, &label, files, loc, base_rank + (i as i64) + 1)
        })
        .collect();

    CatchallResult {
        chunks,
        unreachable_files,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    #[test]
    fn catchall_eligible_rejects_known_skip_names() {
        assert!(!catchall_eligible("README"));
        assert!(!catchall_eligible("LICENSE"));
        assert!(!catchall_eligible("yarn.lock"));
    }

    #[test]
    fn catchall_eligible_rejects_known_skip_extensions() {
        assert!(!catchall_eligible("docs/guide.md"));
        assert!(!catchall_eligible("assets/logo.png"));
    }

    #[test]
    fn catchall_eligible_rejects_multi_dot_tail_even_when_final_suffix_is_not_skipped() {
        assert!(!catchall_eligible("dist/foo.bundle.min.js"));
    }

    #[test]
    fn catchall_eligible_rejects_skip_directory_segments() {
        assert!(!catchall_eligible("__snapshots__/foo.snap.js"));
        assert!(!catchall_eligible("test/fixtures/data.json"));
    }

    #[test]
    fn catchall_eligible_keeps_credential_prone_dotfiles() {
        assert!(catchall_eligible(".env"));
        assert!(catchall_eligible(".npmrc"));
    }

    #[test]
    fn catchall_eligible_keeps_ordinary_source() {
        assert!(catchall_eligible("src/app.py"));
    }

    fn ctx_with_root(root: &Path, all_files: Vec<&str>) -> ContextPackage {
        ContextPackage {
            seed_taint_paths: Default::default(),
            seed_taint_evidence: Default::default(),
            def_spans: Default::default(),
            repo_root: root.to_string_lossy().to_string(),
            language: "python".to_string(),
            call_graph: Default::default(),
            call_graph_files: Default::default(),
            entry_points: Vec::new(),
            unsafe_sinks: Vec::new(),
            modules: Vec::new(),
            all_files: all_files.into_iter().map(String::from).collect(),
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

    #[test]
    fn add_catchall_chunks_disabled_returns_nothing() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "x\n").unwrap();
        let ctx = ctx_with_root(dir.path(), vec!["a.py"]);
        let mut cfg = Step3Config::new("m");
        cfg.catchall_enabled = false;
        assert!(add_catchall_chunks(&[], &ctx, &cfg).chunks.is_empty());
    }

    #[test]
    fn add_catchall_chunks_all_ineligible_returns_nothing() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("README"), "x\n").unwrap();
        let ctx = ctx_with_root(dir.path(), vec!["README"]);
        let cfg = Step3Config::new("m");
        assert!(add_catchall_chunks(&[], &ctx, &cfg).chunks.is_empty());
    }

    #[test]
    fn add_catchall_chunks_covers_uncovered_files_ranked_above_existing() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "x\n").unwrap();
        std::fs::write(dir.path().join("b.py"), "x\n").unwrap();
        let ctx = ctx_with_root(dir.path(), vec!["a.py", "b.py"]);
        let existing = vec![Chunk {
            id: "c1".to_string(),
            size: ChunkSize::Small,
            risk_rank: 5,
            files: vec!["a.py".to_string()],
            focus_entry_points: Vec::new(),
            hypothesis: String::new(),
            related_cves: Vec::new(),
            threat_id: None,
            languages: Vec::new(),
            specialist: None,
            path_funcs: Vec::new(),
            source_ref: String::new(),
            sink_ref: String::new(),
            sink_cwe: Vec::new(),
        }];
        let cfg = Step3Config::new("m");
        let out = add_catchall_chunks(&existing, &ctx, &cfg).chunks;
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, "catchall-01");
        assert_eq!(out[0].files, vec!["b.py".to_string()]);
        assert_eq!(out[0].risk_rank, 6);
    }

    #[test]
    fn add_catchall_chunks_uses_zero_base_rank_when_manifest_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "x\n").unwrap();
        let ctx = ctx_with_root(dir.path(), vec!["a.py"]);
        let cfg = Step3Config::new("m");
        let out = add_catchall_chunks(&[], &ctx, &cfg).chunks;
        assert_eq!(out[0].risk_rank, 1);
    }

    #[test]
    fn add_catchall_chunks_with_diff_scope_only_sweeps_changed_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "x\n").unwrap();
        std::fs::write(dir.path().join("b.py"), "x\n").unwrap();
        let mut ctx = ctx_with_root(dir.path(), vec!["a.py", "b.py"]);
        ctx.diff_scope_active = true;
        ctx.changed_files = BTreeMap::from([("a.py".to_string(), BTreeSet::from([1]))]);
        let cfg = Step3Config::new("m");
        // Neither file is claimed by an existing chunk — without
        // diff-scope both would be swept; with it, only the changed file
        // (`a.py`) is a candidate, so `b.py` is left uncovered.
        let out = add_catchall_chunks(&[], &ctx, &cfg).chunks;
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].files, vec!["a.py".to_string()]);
    }

    #[test]
    fn add_catchall_chunks_with_diff_scope_active_and_no_changed_files_sweeps_nothing() {
        // The fail-open regression: a rename-only PR parses to an empty
        // changed set, and the pre-fix `changed_files.is_empty()` test
        // read that as "no diff scope" and swept EVERY file in the repo
        // at full LLM spend. Active + empty must scope to nothing.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "x\n").unwrap();
        std::fs::write(dir.path().join("b.py"), "x\n").unwrap();
        let mut ctx = ctx_with_root(dir.path(), vec!["a.py", "b.py"]);
        ctx.diff_scope_active = true;
        assert!(ctx.changed_files.is_empty());
        let cfg = Step3Config::new("m");
        assert!(add_catchall_chunks(&[], &ctx, &cfg).chunks.is_empty());
    }

    #[test]
    fn add_catchall_chunks_without_diff_scope_still_sweeps_every_file() {
        // The other half of the same branch: diff-scope inactive is
        // byte-for-byte what it always was — an empty `changed_files`
        // there means "full repo", and both files get swept.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "x\n").unwrap();
        std::fs::write(dir.path().join("b.py"), "x\n").unwrap();
        let ctx = ctx_with_root(dir.path(), vec!["a.py", "b.py"]);
        assert!(!ctx.diff_scope_active);
        let cfg = Step3Config::new("m");
        let swept: Vec<String> = add_catchall_chunks(&[], &ctx, &cfg)
            .chunks
            .into_iter()
            .flat_map(|c| c.files)
            .collect();
        assert_eq!(swept, vec!["a.py".to_string(), "b.py".to_string()]);
    }

    // ── catchall_mode: reachable_only ────────────────────────────────────

    fn ctx_with_reach(
        root: &Path,
        all_files: Vec<&str>,
        entry_points: Vec<bc_model::EntryPoint>,
        call_graph: BTreeMap<String, Vec<String>>,
    ) -> ContextPackage {
        let mut ctx = ctx_with_root(root, all_files);
        ctx.entry_points = entry_points;
        ctx.call_graph = call_graph;
        ctx
    }

    fn ep(file: &str) -> bc_model::EntryPoint {
        bc_model::EntryPoint {
            file: file.to_string(),
            function: "handle".to_string(),
            kind: bc_model::EntryPointKind::Network,
            reachable_from_unauth: true,
        }
    }

    #[test]
    fn mode_all_never_gates_regardless_of_reachability() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("reached.py"), "x\n").unwrap();
        std::fs::write(dir.path().join("unreached.py"), "x\n").unwrap();
        let ctx = ctx_with_reach(
            dir.path(),
            vec!["reached.py", "unreached.py"],
            vec![ep("reached.py")],
            BTreeMap::new(),
        );
        let cfg = Step3Config::new("m");
        let result = add_catchall_chunks(&[], &ctx, &cfg);
        assert!(result.unreachable_files.is_empty());
        let covered: HashSet<&str> = result
            .chunks
            .iter()
            .flat_map(|c| c.files.iter().map(String::as_str))
            .collect();
        assert!(covered.contains("unreached.py"));
    }

    #[test]
    fn reachable_only_drops_unreachable_files_and_records_them() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("reached.py"), "x\n").unwrap();
        std::fs::write(dir.path().join("unreached.py"), "x\n").unwrap();
        let ctx = ctx_with_reach(
            dir.path(),
            vec!["reached.py", "unreached.py"],
            vec![ep("reached.py")],
            BTreeMap::new(),
        );
        let mut cfg = Step3Config::new("m");
        cfg.catchall_mode = "reachable_only".to_string();
        let result = add_catchall_chunks(&[], &ctx, &cfg);
        assert_eq!(result.unreachable_files, vec!["unreached.py".to_string()]);
        let covered: HashSet<&str> = result
            .chunks
            .iter()
            .flat_map(|c| c.files.iter().map(String::as_str))
            .collect();
        assert!(covered.contains("reached.py"));
        assert!(!covered.contains("unreached.py"));
    }

    #[test]
    fn reachable_only_is_case_insensitive() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("reached.py"), "x\n").unwrap();
        std::fs::write(dir.path().join("unreached.py"), "x\n").unwrap();
        let ctx = ctx_with_reach(
            dir.path(),
            vec!["reached.py", "unreached.py"],
            vec![ep("reached.py")],
            BTreeMap::new(),
        );
        let mut cfg = Step3Config::new("m");
        cfg.catchall_mode = "Reachable_Only".to_string();
        let result = add_catchall_chunks(&[], &ctx, &cfg);
        assert_eq!(result.unreachable_files, vec!["unreached.py".to_string()]);
    }

    #[test]
    fn reachable_only_falls_back_to_all_with_no_entry_points_or_sinks() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "x\n").unwrap();
        let ctx = ctx_with_root(dir.path(), vec!["a.py"]);
        let mut cfg = Step3Config::new("m");
        cfg.catchall_mode = "reachable_only".to_string();
        let result = add_catchall_chunks(&[], &ctx, &cfg);
        assert!(result.unreachable_files.is_empty());
        assert_eq!(result.chunks[0].files, vec!["a.py".to_string()]);
    }

    #[test]
    fn reachable_only_falls_back_to_all_when_too_sparse() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("reached.py"), "x\n").unwrap();
        std::fs::write(dir.path().join("unreached.py"), "x\n").unwrap();
        let ctx = ctx_with_reach(
            dir.path(),
            vec!["reached.py", "unreached.py"],
            vec![ep("reached.py")],
            BTreeMap::new(),
        );
        let mut cfg = Step3Config::new("m");
        cfg.catchall_mode = "reachable_only".to_string();
        // Only 1/2 eligible files would survive -- below a 90% floor.
        cfg.catchall_reachable_min_ratio = 0.9;
        let result = add_catchall_chunks(&[], &ctx, &cfg);
        assert!(result.unreachable_files.is_empty());
        let covered: HashSet<&str> = result
            .chunks
            .iter()
            .flat_map(|c| c.files.iter().map(String::as_str))
            .collect();
        assert!(covered.contains("unreached.py"));
    }

    #[test]
    fn reachable_only_is_a_noop_when_nothing_is_eligible() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("README"), "x\n").unwrap();
        let ctx = ctx_with_reach(
            dir.path(),
            vec!["README"],
            vec![ep("a.py")],
            BTreeMap::new(),
        );
        let mut cfg = Step3Config::new("m");
        cfg.catchall_mode = "reachable_only".to_string();
        let result = add_catchall_chunks(&[], &ctx, &cfg);
        assert!(result.chunks.is_empty());
        assert!(result.unreachable_files.is_empty());
    }
}
