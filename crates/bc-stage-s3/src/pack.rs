//! Char/LOC budget accounting and greedy bin-packing, ported from
//! `s3_decompose.py`'s `_char_budget`/`_split_oversize_risk_chunks`/
//! `_pack`/`_count_chars`/`_count_loc`.
//!
//! **Deliberately not cached**: Python's `_count_chars` memoizes `stat()`
//! results in a module-global dict purely as a performance optimization
//! (repeated `stat()` calls against an unchanging filesystem mid-scan
//! always return the same size) — it has no observable effect on behavior,
//! so this port skips the cache rather than introducing global mutable
//! state for a speedup correctness doesn't need.

use std::path::Path;

use bc_model::{Chunk, ContextPackage};

use crate::grouping::cohesive_groups;
use crate::Step3Config;

pub fn count_loc(p: &Path) -> i64 {
    match std::fs::read(p) {
        Ok(bytes) => String::from_utf8_lossy(&bytes).lines().count() as i64,
        Err(_) => 0,
    }
}

pub fn count_chars(p: &Path) -> i64 {
    std::fs::metadata(p).map(|m| m.len() as i64).unwrap_or(0)
}

/// [`count_loc`], but confines `rel` to `repo_root` first — `rel` comes
/// from an LLM-authored chunk/group's file list, so a `../../etc/passwd`
/// entry must size to `0` (the same value a genuinely missing file gets),
/// never actually stat outside the repo (CWE-22).
fn confined_loc(repo_root: &Path, rel: &str) -> i64 {
    bc_pathjail::confine(repo_root, rel)
        .map(|p| count_loc(&p))
        .unwrap_or(0)
}

/// [`count_chars`]'s confined-read counterpart to [`confined_loc`].
fn confined_chars(repo_root: &Path, rel: &str) -> i64 {
    bc_pathjail::confine(repo_root, rel)
        .map(|p| count_chars(&p))
        .unwrap_or(0)
}

/// Shard-boundary char cap when `pack_by == "tokens"`, else `None`. chars ≈
/// tokens × 4; budget = (context window − fixed overhead) × 4, floored at
/// 10,000.
pub fn char_budget(config: &Step3Config) -> Option<i64> {
    if config.pack_by.to_lowercase() != "tokens" {
        return None;
    }
    Some(((config.chunk_token_budget - config.chunk_overhead_tokens) * 4).max(10_000))
}

fn size_for(loc: i64) -> bc_model::ChunkSize {
    bc_repo_analysis::size_for(loc.max(0) as usize)
}

/// Split each group into `(label, files, loc)` buckets. Shard boundary is
/// decided by `max_chars` (when given) or `max_loc` otherwise, so
/// `pack_by` switches the metric without touching callers. `loc` is
/// always the real line count (not chars) so size tagging stays
/// meaningful in both modes. Groups that shard into N>1 buckets get a
/// `"[shard k/N]"` label suffix.
///
/// The per-group loop below emits at least one bucket PER GROUP and never
/// back-fills, so on its own the bucket count tracks GROUP count rather
/// than code volume: a repo whose cohesion groups are mostly small
/// directories yields dozens of buckets with a median fill far under the
/// cap, and each bucket costs one S4 model call per lens.
/// `merge_underfilled` (kill switch
/// [`Step3Config::pack_merge_underfilled`], default on) folds ADJACENT
/// under-filled buckets back together afterwards, see
/// [`coalesce_underfilled`].
pub fn pack(
    groups: &[(String, Vec<String>)],
    repo_root: &Path,
    max_loc: i64,
    max_files: usize,
    max_chars: Option<i64>,
    merge_underfilled: bool,
) -> Vec<(String, Vec<String>, i64)> {
    let mut out = Vec::new();
    for (label, files) in groups {
        let mut shards: Vec<(Vec<String>, i64)> = Vec::new();
        let mut b_files: Vec<String> = Vec::new();
        let mut b_loc = 0i64;
        let mut b_chars = 0i64;
        for f in files {
            let loc = confined_loc(repo_root, f);
            let chars = if max_chars.is_some() {
                confined_chars(repo_root, f)
            } else {
                0
            };
            let over = match max_chars {
                Some(cap) => b_chars + chars > cap,
                None => b_loc + loc > max_loc,
            };
            if !b_files.is_empty() && (over || b_files.len() >= max_files) {
                shards.push((std::mem::take(&mut b_files), b_loc));
                b_loc = 0;
                b_chars = 0;
            }
            b_files.push(f.clone());
            b_loc += loc;
            b_chars += chars;
        }
        if !b_files.is_empty() {
            shards.push((b_files, b_loc));
        }
        let n = shards.len();
        for (k, (bf, bl)) in shards.into_iter().enumerate() {
            let lbl = if n == 1 {
                label.clone()
            } else {
                format!("{label} [shard {}/{n}]", k + 1)
            };
            out.push((lbl, bf, bl));
        }
    }
    if merge_underfilled && out.len() > 1 {
        out = coalesce_underfilled(out, repo_root, max_loc, max_files, max_chars);
    }
    out
}

/// One in-progress merge target: the first folded bucket's label, how many
/// further buckets folded into it, and the running file list / LOC / char
/// totals the cap checks read.
struct Acc {
    label: String,
    folded: usize,
    files: Vec<String>,
    loc: i64,
    chars: i64,
}

/// Fold consecutive under-filled buckets together while the union still
/// respects every cap.
///
/// Merging is ADJACENT-only, deliberately: the group order coming out of
/// [`cohesive_groups`] keeps call-graph components and directory siblings
/// next to each other, so a greedy fold over neighbours preserves that
/// locality. Grouping keeps deciding WHICH files sit together, and the
/// caps alone decide HOW MANY buckets that takes. Reordering buckets to
/// bin-pack tighter would trade that locality for a marginal count win.
///
/// The cap checks mirror [`pack`]'s own: `max_chars` decides the boundary
/// when given (`pack_by: tokens`), else `max_loc`, and `max_files` binds
/// in both modes. A single file that alone exceeds the cap arrived here as
/// a one-file bucket whose running total already breaches the cap, so
/// nothing ever merges into it and it never merges forward: it stays
/// isolated. Files are concatenated in bucket order, so the flattened file
/// sequence is bit-identical to the unmerged output, nothing is dropped,
/// duplicated, or reordered.
///
/// Chars are re-derived per file rather than threaded through from
/// [`pack`], whose shards only carry `(files, loc)`. Python memoizes
/// `_count_chars`' `stat()` so the re-derivation costs it no extra I/O;
/// this port has no such cache (see the module doc comment) and pays a
/// second `stat()` per file in char mode only, which is not measurable
/// next to the S4 call it saves.
fn coalesce_underfilled(
    buckets: Vec<(String, Vec<String>, i64)>,
    repo_root: &Path,
    max_loc: i64,
    max_files: usize,
    max_chars: Option<i64>,
) -> Vec<(String, Vec<String>, i64)> {
    let mut merged: Vec<Acc> = Vec::new();
    for (label, files, loc) in buckets {
        let chars: i64 = match max_chars {
            Some(_) => files.iter().map(|f| confined_chars(repo_root, f)).sum(),
            None => 0,
        };
        if let Some(acc) = merged.last_mut() {
            let over = match max_chars {
                Some(cap) => acc.chars + chars > cap,
                None => acc.loc + loc > max_loc,
            };
            if !over && acc.files.len() + files.len() <= max_files {
                acc.folded += 1;
                acc.files.extend(files);
                acc.loc += loc;
                acc.chars += chars;
                continue;
            }
        }
        merged.push(Acc {
            label,
            folded: 0,
            files,
            loc,
            chars,
        });
    }
    merged
        .into_iter()
        .map(|acc| {
            // Keep the first label and record how many more groups folded
            // in, so the hypothesis text / shard label still says where a
            // bucket came from instead of silently presenting a merged
            // bucket as one group.
            let label = if acc.folded == 0 {
                acc.label
            } else {
                format!("{} (+{} more groups)", acc.label, acc.folded)
            };
            (label, acc.files, acc.loc)
        })
        .collect()
}

/// Re-pack any chunk (LLM-risk or taint) whose LOC/chars/file-count
/// exceeds the configured caps into `chunk-NN-a`, `chunk-NN-b`, … —
/// everything else on the chunk (risk_rank, hypothesis, related_cves,
/// threat_id, focus_entry_points) is preserved on every sub-chunk.
pub fn split_oversize_risk_chunks(
    manifest_chunks: Vec<Chunk>,
    ctx: &ContextPackage,
    config: &Step3Config,
) -> Vec<Chunk> {
    let max_loc = config.risk_chunk_loc;
    let max_files = config.max_files_per_chunk;
    let char_cap = char_budget(config);
    if max_loc <= 0 && char_cap.is_none() {
        return manifest_chunks;
    }
    let repo_root = Path::new(&ctx.repo_root);

    let mut out = Vec::new();
    for mut c in manifest_chunks {
        let loc: i64 = c.files.iter().map(|f| confined_loc(repo_root, f)).sum();
        let fits = match char_cap {
            Some(cap) => {
                let chars: i64 = c.files.iter().map(|f| confined_chars(repo_root, f)).sum();
                chars <= cap && c.files.len() <= max_files
            }
            None => loc <= max_loc && c.files.len() <= max_files,
        };
        if fits {
            c.size = size_for(loc);
            out.push(c);
            continue;
        }
        let groups = cohesive_groups(&c.files, ctx);
        let buckets = pack(
            &groups,
            repo_root,
            max_loc,
            max_files,
            char_cap,
            config.pack_merge_underfilled,
        );
        for (i, (_, files, bloc)) in buckets.into_iter().enumerate() {
            let suffix = if i < 26 {
                ((b'a' + i as u8) as char).to_string()
            } else {
                (i + 1).to_string()
            };
            out.push(Chunk {
                id: format!("{}-{suffix}", c.id),
                size: size_for(bloc),
                files,
                risk_rank: c.risk_rank,
                focus_entry_points: c.focus_entry_points.clone(),
                hypothesis: c.hypothesis.clone(),
                related_cves: c.related_cves.clone(),
                threat_id: c.threat_id.clone(),
                languages: c.languages.clone(),
                specialist: c.specialist.clone(),
                // Ported from `c.model_copy(update={...})`: every field
                // NOT explicitly overridden is copied from the original
                // chunk verbatim — a taint chunk's structured metadata
                // survives an oversize split onto each of its pieces.
                path_funcs: c.path_funcs.clone(),
                source_ref: c.source_ref.clone(),
                sink_ref: c.sink_ref.clone(),
                sink_cwe: c.sink_cwe.clone(),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, rel: &str, lines: usize) {
        let path = dir.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "x\n".repeat(lines)).unwrap();
    }

    #[test]
    fn char_budget_is_none_for_loc_mode() {
        let mut cfg = Step3Config::new("m");
        cfg.pack_by = "loc".to_string();
        assert_eq!(char_budget(&cfg), None);
    }

    #[test]
    fn char_budget_computes_tokens_times_4_floored_at_10000() {
        let mut cfg = Step3Config::new("m");
        cfg.pack_by = "TOKENS".to_string();
        cfg.chunk_token_budget = 180_000;
        cfg.chunk_overhead_tokens = 80_000;
        assert_eq!(char_budget(&cfg), Some(400_000));
    }

    #[test]
    fn char_budget_is_floored_at_10000_chars() {
        let mut cfg = Step3Config::new("m");
        cfg.pack_by = "tokens".to_string();
        cfg.chunk_token_budget = 1_000;
        cfg.chunk_overhead_tokens = 900;
        assert_eq!(char_budget(&cfg), Some(10_000));
    }

    #[test]
    fn pack_splits_a_group_exceeding_max_loc_into_multiple_shards() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.py", 5);
        write(dir.path(), "b.py", 5);
        let groups = vec![(
            "g".to_string(),
            vec!["a.py".to_string(), "b.py".to_string()],
        )];
        let buckets = pack(&groups, dir.path(), 8, 25, None, true);
        assert_eq!(buckets.len(), 2);
        assert_eq!(buckets[0].0, "g [shard 1/2]");
        assert_eq!(buckets[1].0, "g [shard 2/2]");
    }

    #[test]
    fn pack_keeps_a_single_shard_label_bare_when_it_fits() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.py", 5);
        let groups = vec![("g".to_string(), vec!["a.py".to_string()])];
        let buckets = pack(&groups, dir.path(), 8000, 25, None, true);
        assert_eq!(buckets[0].0, "g");
    }

    #[test]
    fn pack_shards_by_max_files_even_under_the_loc_cap() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.py", 1);
        write(dir.path(), "b.py", 1);
        write(dir.path(), "c.py", 1);
        let groups = vec![(
            "g".to_string(),
            vec!["a.py".to_string(), "b.py".to_string(), "c.py".to_string()],
        )];
        let buckets = pack(&groups, dir.path(), 8000, 2, None, true);
        assert_eq!(buckets.len(), 2);
        assert_eq!(buckets[0].1.len(), 2);
        assert_eq!(buckets[1].1.len(), 1);
    }

    #[test]
    fn pack_uses_char_cap_when_given() {
        let dir = tempfile::tempdir().unwrap();
        // Each file is 4 bytes ("x\n" * 2 = "x\nx\n").
        write(dir.path(), "a.py", 2);
        write(dir.path(), "b.py", 2);
        let groups = vec![(
            "g".to_string(),
            vec!["a.py".to_string(), "b.py".to_string()],
        )];
        let buckets = pack(&groups, dir.path(), 100_000, 25, Some(4), true);
        assert_eq!(buckets.len(), 2);
    }

    #[test]
    fn pack_a_single_oversize_file_still_gets_its_own_bucket() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "huge.py", 100);
        let groups = vec![("g".to_string(), vec!["huge.py".to_string()])];
        let buckets = pack(&groups, dir.path(), 1, 25, None, true);
        assert_eq!(buckets.len(), 1);
        assert_eq!(buckets[0].1, vec!["huge.py".to_string()]);
    }

    // ── `pack` coalesces ADJACENT under-filled buckets ──────────────────
    // Without it the per-group loop above emits at least one bucket per
    // cohesion group and never back-fills, so bucket count tracks GROUP
    // count instead of code volume — and every bucket costs one S4 model
    // call per lens. The properties pinned below, in order: the collapse
    // itself plus provenance in the label; both caps still binding in LOC
    // mode and in char mode; the flattened file sequence staying
    // bit-identical to the unmerged output (the security-critical one — a
    // lost file is a lost lens sweep); the kill switch reproducing the
    // one-bucket-per-group output exactly; and a single oversize file
    // staying isolated, which also proves only ADJACENT buckets merge.

    /// `n` one-file cohesion groups of `loc` lines each: the worst case for
    /// the one-bucket-per-group behavior. Returns `(groups, files)` in
    /// emission order.
    fn singleton_groups(
        dir: &Path,
        n: usize,
        loc: usize,
    ) -> (Vec<(String, Vec<String>)>, Vec<String>) {
        let files: Vec<String> = (0..n).map(|i| format!("pkg{i:02}/mod.py")).collect();
        for f in &files {
            write(dir, f, loc);
        }
        let groups = files
            .iter()
            .enumerate()
            .map(|(i, f)| (format!("pkg{i:02}"), vec![f.clone()]))
            .collect();
        (groups, files)
    }

    fn flatten(buckets: &[(String, Vec<String>, i64)]) -> Vec<String> {
        buckets.iter().flat_map(|(_, f, _)| f.clone()).collect()
    }

    #[test]
    fn coalesce_folds_underfilled_singleton_groups_into_one_bucket() {
        let dir = tempfile::tempdir().unwrap();
        let (groups, files) = singleton_groups(dir.path(), 10, 10);

        let buckets = pack(&groups, dir.path(), 10_000, 40, None, true);

        assert_eq!(buckets.len(), 1);
        assert_eq!(buckets[0].1, files);
        assert_eq!(buckets[0].2, 100);
        // The label keeps provenance: first group's name plus a fold count.
        assert_eq!(buckets[0].0, "pkg00 (+9 more groups)");
    }

    #[test]
    fn coalesce_stops_at_the_loc_cap() {
        let dir = tempfile::tempdir().unwrap();
        // 12 × 25 LOC against a 100-LOC cap packs 4 files per bucket
        // exactly: ceil(12·25 / 100) = 3 buckets, none breaching a cap.
        let (groups, _) = singleton_groups(dir.path(), 12, 25);

        let buckets = pack(&groups, dir.path(), 100, 100, None, true);

        assert_eq!(buckets.len(), 3);
        for (_, bf, loc) in &buckets {
            assert!(*loc <= 100);
            assert!(bf.len() <= 100);
        }
    }

    #[test]
    fn coalesce_stops_at_the_file_cap_in_loc_mode() {
        let dir = tempfile::tempdir().unwrap();
        // 10 one-line files against a 4-file cap: ceil(10 / 4) = 3 buckets.
        let (groups, _) = singleton_groups(dir.path(), 10, 1);

        let buckets = pack(&groups, dir.path(), 10_000, 4, None, true);

        let sizes: Vec<usize> = buckets.iter().map(|(_, bf, _)| bf.len()).collect();
        assert_eq!(sizes, vec![4, 4, 2]);
    }

    #[test]
    fn coalesce_stops_at_the_file_cap_in_char_mode_too() {
        let dir = tempfile::tempdir().unwrap();
        // Char mode with a cap far larger than the whole corpus: only
        // `max_files` can bind, so it must, exactly as it does in LOC mode.
        let (groups, _) = singleton_groups(dir.path(), 10, 1);

        let buckets = pack(&groups, dir.path(), 10_000, 3, Some(1_000_000), true);

        let sizes: Vec<usize> = buckets.iter().map(|(_, bf, _)| bf.len()).collect();
        assert_eq!(sizes, vec![3, 3, 3, 1]);
    }

    #[test]
    fn coalesce_preserves_the_file_sequence_exactly() {
        // Mixed shape — a two-file group, an oversize single file, then
        // three singletons — exercises the skip-merge, isolate, and fold
        // branches in one pass. The flattened file sequence must be
        // bit-identical either way: a dropped or duplicated file here means
        // a lost or double lens sweep.
        let dir = tempfile::tempdir().unwrap();
        for (name, loc) in [
            ("a.py", 10),
            ("b.py", 10),
            ("big.py", 300),
            ("c.py", 10),
            ("d.py", 10),
            ("e.py", 10),
        ] {
            write(dir.path(), name, loc);
        }
        let groups = vec![
            (
                "g1".to_string(),
                vec!["a.py".to_string(), "b.py".to_string()],
            ),
            ("g2".to_string(), vec!["big.py".to_string()]),
            ("g3".to_string(), vec!["c.py".to_string()]),
            ("g4".to_string(), vec!["d.py".to_string()]),
            ("g5".to_string(), vec!["e.py".to_string()]),
        ];

        let plain = pack(&groups, dir.path(), 100, 3, None, false);
        let merged = pack(&groups, dir.path(), 100, 3, None, true);

        assert_eq!(flatten(&merged), flatten(&plain));
        let unique: std::collections::BTreeSet<String> = flatten(&merged).into_iter().collect();
        assert_eq!(unique.len(), flatten(&merged).len());
        // And the merge actually happened where the caps allowed it.
        let file_sets: Vec<Vec<String>> = merged.iter().map(|(_, bf, _)| bf.clone()).collect();
        assert_eq!(
            file_sets,
            vec![
                vec!["a.py".to_string(), "b.py".to_string()],
                vec!["big.py".to_string()],
                vec!["c.py".to_string(), "d.py".to_string(), "e.py".to_string()],
            ]
        );
    }

    #[test]
    fn coalesce_kill_switch_reproduces_the_unmerged_packing() {
        // `pack_merge_underfilled: false` is the escape hatch if a target
        // regresses — it must restore the one-bucket-per-group output
        // exactly, labels and LOC included, not merely the same coverage.
        let dir = tempfile::tempdir().unwrap();
        let (groups, files) = singleton_groups(dir.path(), 10, 10);

        let buckets = pack(&groups, dir.path(), 10_000, 40, None, false);

        let expected: Vec<(String, Vec<String>, i64)> = (0..10)
            .map(|i| (format!("pkg{i:02}"), vec![files[i].clone()], 10))
            .collect();
        assert_eq!(buckets, expected);
    }

    #[test]
    fn coalesce_leaves_a_single_oversize_file_isolated_on_both_sides() {
        let dir = tempfile::tempdir().unwrap();
        for (name, loc) in [("a.py", 10), ("big.py", 300), ("b.py", 10)] {
            write(dir.path(), name, loc);
        }
        let groups = vec![
            ("g1".to_string(), vec!["a.py".to_string()]),
            ("g2".to_string(), vec!["big.py".to_string()]),
            ("g3".to_string(), vec!["b.py".to_string()]),
        ];

        let buckets = pack(&groups, dir.path(), 100, 100, None, true);

        // The oversize file neither absorbs a neighbour nor merges forward
        // — and because merging is ADJACENT-only, a.py and b.py (separated
        // by it) stay apart too, even though their union would fit the cap.
        let file_sets: Vec<Vec<String>> = buckets.iter().map(|(_, bf, _)| bf.clone()).collect();
        assert_eq!(
            file_sets,
            vec![
                vec!["a.py".to_string()],
                vec!["big.py".to_string()],
                vec!["b.py".to_string()],
            ]
        );
        // Labels are untouched when nothing folded.
        assert_eq!(buckets[0].0, "g1");
    }

    #[test]
    fn coalesce_in_char_mode_respects_the_char_cap_and_ignores_max_loc() {
        // 10 × 100-byte files against a 400-char cap: 4 per bucket, so 3
        // buckets. `max_loc = 1` on purpose — in char mode the LOC cap must
        // play no part in the coalescing decision, exactly as it plays none
        // in `pack`'s own split.
        let dir = tempfile::tempdir().unwrap();
        let files: Vec<String> = (0..10).map(|i| format!("f{i}.py")).collect();
        for f in &files {
            // 50 lines of "x\n" == 100 bytes.
            write(dir.path(), f, 50);
        }
        let groups: Vec<(String, Vec<String>)> = files
            .iter()
            .enumerate()
            .map(|(i, f)| (format!("g{i}"), vec![f.clone()]))
            .collect();

        let buckets = pack(&groups, dir.path(), 1, 100, Some(400), true);

        assert_eq!(buckets.len(), 3);
        for (_, bf, _) in &buckets {
            let chars: i64 = bf.iter().map(|f| confined_chars(dir.path(), f)).sum();
            assert!(chars <= 400);
        }
        assert_eq!(flatten(&buckets), files);
    }

    fn ctx_with_root(root: &Path) -> ContextPackage {
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
            all_files: Vec::new(),
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

    fn chunk(id: &str, files: Vec<&str>, risk_rank: i64) -> Chunk {
        Chunk {
            id: id.to_string(),
            size: bc_model::ChunkSize::Medium,
            risk_rank,
            files: files.into_iter().map(String::from).collect(),
            focus_entry_points: vec!["main".to_string()],
            hypothesis: "h".to_string(),
            related_cves: vec!["CVE-1".to_string()],
            threat_id: Some("T1".to_string()),
            languages: Vec::new(),
            specialist: None,
            path_funcs: Vec::new(),
            source_ref: String::new(),
            sink_ref: String::new(),
            sink_cwe: Vec::new(),
        }
    }

    #[test]
    fn split_oversize_risk_chunks_is_a_noop_when_no_caps_are_set() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_with_root(dir.path());
        let mut cfg = Step3Config::new("m");
        cfg.risk_chunk_loc = 0;
        let chunks = vec![chunk("c1", vec!["a.py"], 1)];
        let out = split_oversize_risk_chunks(chunks.clone(), &ctx, &cfg);
        assert_eq!(out, chunks);
    }

    #[test]
    fn split_oversize_risk_chunks_keeps_a_chunk_that_fits() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.py", 5);
        let ctx = ctx_with_root(dir.path());
        let mut cfg = Step3Config::new("m");
        cfg.risk_chunk_loc = 8000;
        cfg.max_files_per_chunk = 25;
        let out = split_oversize_risk_chunks(vec![chunk("c1", vec!["a.py"], 1)], &ctx, &cfg);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, "c1");
        assert_eq!(out[0].size, bc_model::ChunkSize::Small);
    }

    #[test]
    fn split_oversize_risk_chunks_splits_and_preserves_other_fields() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.py", 10);
        write(dir.path(), "b.py", 10);
        let ctx = ctx_with_root(dir.path());
        let mut cfg = Step3Config::new("m");
        cfg.risk_chunk_loc = 8;
        cfg.max_files_per_chunk = 25;
        let out =
            split_oversize_risk_chunks(vec![chunk("c1", vec!["a.py", "b.py"], 3)], &ctx, &cfg);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].id, "c1-a");
        assert_eq!(out[1].id, "c1-b");
        for c in &out {
            assert_eq!(c.risk_rank, 3);
            assert_eq!(c.hypothesis, "h");
            assert_eq!(c.related_cves, vec!["CVE-1".to_string()]);
            assert_eq!(c.threat_id, Some("T1".to_string()));
            assert_eq!(c.focus_entry_points, vec!["main".to_string()]);
        }
    }

    #[test]
    fn split_oversize_risk_chunks_preserves_taint_metadata_on_every_piece() {
        // Ported from `c.model_copy(update={...})`'s full-field-copy
        // semantics: a taint chunk's `path_funcs`/`source_ref`/
        // `sink_ref`/`sink_cwe` must survive an oversize split onto
        // EVERY resulting sub-chunk, not just the first.
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.py", 10);
        write(dir.path(), "b.py", 10);
        let ctx = ctx_with_root(dir.path());
        let mut cfg = Step3Config::new("m");
        cfg.risk_chunk_loc = 8;
        cfg.max_files_per_chunk = 25;
        let mut taint_chunk = chunk("taint-01", vec!["a.py", "b.py"], 1);
        taint_chunk.path_funcs = vec!["a.py::f".to_string(), "b.py::g".to_string()];
        taint_chunk.source_ref = "a.py::f".to_string();
        taint_chunk.sink_ref = "b.py:5".to_string();
        taint_chunk.sink_cwe = vec!["CWE-89".to_string()];
        let out = split_oversize_risk_chunks(vec![taint_chunk], &ctx, &cfg);
        assert_eq!(out.len(), 2);
        for c in &out {
            assert_eq!(
                c.path_funcs,
                vec!["a.py::f".to_string(), "b.py::g".to_string()]
            );
            assert_eq!(c.source_ref, "a.py::f");
            assert_eq!(c.sink_ref, "b.py:5");
            assert_eq!(c.sink_cwe, vec!["CWE-89".to_string()]);
        }
    }

    #[test]
    fn split_oversize_risk_chunks_uses_numeric_suffix_past_26_buckets() {
        let dir = tempfile::tempdir().unwrap();
        let mut files = Vec::new();
        for i in 0..30 {
            let name = format!("f{i}.py");
            write(dir.path(), &name, 5);
            files.push(name);
        }
        let ctx = ctx_with_root(dir.path());
        let mut cfg = Step3Config::new("m");
        cfg.risk_chunk_loc = 8000;
        cfg.max_files_per_chunk = 1;
        let file_refs: Vec<&str> = files.iter().map(String::as_str).collect();
        let out = split_oversize_risk_chunks(vec![chunk("c1", file_refs, 1)], &ctx, &cfg);
        assert_eq!(out.len(), 30);
        assert_eq!(out[25].id, "c1-z");
        assert_eq!(out[26].id, "c1-27");
    }

    #[test]
    fn split_oversize_risk_chunks_over_file_count_cap_still_splits() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.py", 1);
        write(dir.path(), "b.py", 1);
        write(dir.path(), "c.py", 1);
        let ctx = ctx_with_root(dir.path());
        let mut cfg = Step3Config::new("m");
        cfg.risk_chunk_loc = 8000;
        cfg.max_files_per_chunk = 2;
        let out = split_oversize_risk_chunks(
            vec![chunk("c1", vec!["a.py", "b.py", "c.py"], 1)],
            &ctx,
            &cfg,
        );
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn split_oversize_risk_chunks_uses_char_cap_when_pack_by_tokens() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.py", 500);
        let ctx = ctx_with_root(dir.path());
        let mut cfg = Step3Config::new("m");
        cfg.pack_by = "tokens".to_string();
        cfg.chunk_token_budget = 2_600;
        cfg.chunk_overhead_tokens = 100;
        // char_budget = (2600-100)*4 = 10000, floored at 10000 anyway.
        // a.py is 1000 bytes ("x\n" * 500), well under 10000 -> fits.
        let out = split_oversize_risk_chunks(vec![chunk("c1", vec!["a.py"], 1)], &ctx, &cfg);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, "c1");
    }

    #[test]
    fn count_loc_and_count_chars_return_zero_for_a_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(count_loc(&dir.path().join("missing.py")), 0);
        assert_eq!(count_chars(&dir.path().join("missing.py")), 0);
    }

    #[test]
    fn confined_loc_and_confined_chars_return_zero_for_a_path_that_escapes_the_repo_root() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(confined_loc(dir.path(), "../outside.py"), 0);
        assert_eq!(confined_chars(dir.path(), "../outside.py"), 0);
    }

    #[test]
    fn pack_an_llm_chosen_path_that_escapes_the_repo_root_sizes_to_zero_not_a_real_read() {
        let dir = tempfile::tempdir().unwrap();
        let groups = vec![("g".to_string(), vec!["../outside.py".to_string()])];
        let buckets = pack(&groups, dir.path(), 8000, 25, Some(4), true);
        assert_eq!(buckets.len(), 1);
        assert_eq!(buckets[0].2, 0);
    }

    #[test]
    fn split_oversize_risk_chunks_an_llm_chosen_escaping_path_sizes_to_zero_and_fits() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_with_root(dir.path());
        let mut cfg = Step3Config::new("m");
        cfg.pack_by = "tokens".to_string();
        cfg.chunk_token_budget = 2_600;
        cfg.chunk_overhead_tokens = 100;
        let chunks = vec![chunk("c1", vec!["../outside.py"], 1)];
        let out = split_oversize_risk_chunks(chunks, &ctx, &cfg);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].size, bc_model::ChunkSize::Small);
    }
}
