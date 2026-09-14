//! Repo-wide specialist sweep passes (crypto, logic-bug, access-control,
//! batch-etl, iac), ported from `s3_decompose.py`'s `_gate_specialists`/
//! `_has_batch_surface`/`_scan_any`/`_has_authz_surface`/`_mk_specialist`/
//! `_add_specialist_chunks`.

use std::collections::{BTreeSet, HashSet};
use std::path::Path;
use std::sync::LazyLock;

use bc_model::{Actor, Chunk, ChunkSize, ContextPackage, ControlKind, EntryPointKind};
use regex::Regex;

use crate::grouping::cohesive_groups;
use crate::pack::{char_budget, pack};
use crate::source::is_source;
use crate::Step3Config;

static CRYPTO_RX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(AES|RSA|HMAC|SHA-?(1|2|256|384|512)|MD5|PBKDF2|bcrypt|scrypt|argon2|Cipher|KeyPair|SecretKey|X509|PKCS|TLS|SSLContext|jwt|jose|nacl|sodium|hashlib|hmac\.|cryptography\.|javax\.crypto|BouncyCastle|OpenSSL|Crypt::|Digest::|Mcrypt|RandomNumberGenerator|SecureRandom)\b",
    )
    .unwrap()
});

static DESER_RX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\b(ObjectInputStream|readObject|XMLDecoder|XStream|SnakeYAML|yaml\.load|pickle\.|marshal\.load|unserialize|BinaryFormatter|Kryo|Hessian|JdkSerializationRedisSerializer|Marshal\.load)\b",
    )
    .unwrap()
});

static BATCH_ETL_RX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(struct\.(?:un)?pack|codecs\.(?:encode|decode)\([^)]*ebcdic|cp037|cp1047|COMP-3|packed[_-]?decimal|RECFM|LRECL|glob\.glob|os\.listdir|shutil\.(?:move|copy)|csv\.(?:writer|reader)|EXEC\s+PGM=|//\w+\s+DD\b|DISP=\()\b",
    )
    .unwrap()
});

fn scan_any(repo_root: &Path, files: &[String], rx: &Regex) -> bool {
    for rel in files {
        let Ok(bytes) = std::fs::read(repo_root.join(rel)) else {
            continue;
        };
        if rx.is_match(&String::from_utf8_lossy(&bytes)) {
            return true;
        }
    }
    false
}

fn has_batch_surface(ctx: &ContextPackage, repo_root: &Path, source: &[String]) -> bool {
    if ctx
        .entry_points
        .iter()
        .any(|ep| matches!(ep.kind, EntryPointKind::File | EntryPointKind::Cli))
    {
        return true;
    }
    let langs: HashSet<&str> = bc_repo_analysis::detect_languages(&ctx.all_files, Some(repo_root))
        .into_iter()
        .collect();
    if langs.contains("cobol") || langs.contains("jcl") {
        return true;
    }
    scan_any(repo_root, source, &BATCH_ETL_RX)
}

fn has_authz_surface(ctx: &ContextPackage) -> bool {
    if ctx
        .app_profile
        .as_ref()
        .is_some_and(|ap| ap.externally_facing)
    {
        return true;
    }
    if ctx.entry_points.iter().any(|ep| {
        matches!(ep.kind, EntryPointKind::Network | EntryPointKind::Ipc) || ep.reachable_from_unauth
    }) {
        return true;
    }
    if ctx
        .design_controls
        .iter()
        .any(|c| c.kind == ControlKind::Auth)
    {
        return true;
    }
    if let Some(tm) = &ctx.threat_model {
        if tm
            .threats
            .iter()
            .any(|t| matches!(t.actor, Actor::RemoteUnauth | Actor::RemoteAuth))
        {
            return true;
        }
    }
    false
}

/// Drop specialist passes whose target surface doesn't exist in this repo,
/// so S4/S5/S6 don't burn budget verifying guaranteed-false-positive
/// findings. A specialist name with no gate in the table (e.g.
/// `"logic-bug"`) is always kept.
fn gate_specialists(enabled: &[String], ctx: &ContextPackage, source: &[String]) -> Vec<String> {
    let repo_root = Path::new(&ctx.repo_root);
    enabled
        .iter()
        .filter(|spec| match spec.as_str() {
            "access-control" => has_authz_surface(ctx),
            "crypto" => scan_any(repo_root, source, &CRYPTO_RX),
            "deserialization" => scan_any(repo_root, source, &DESER_RX),
            "batch-etl" => has_batch_surface(ctx, repo_root, source),
            "iac" => ctx
                .all_files
                .iter()
                .any(|f| bc_repo_analysis::is_iac_file(f)),
            _ => true,
        })
        .cloned()
        .collect()
}

fn size_for(loc: i64) -> ChunkSize {
    bc_repo_analysis::size_for(loc.max(0) as usize)
}

/// Best-effort method anchors for one specialist shard, ported from
/// `s3_decompose.py::_specialist_focus_entry_points` (`:1448-1464`).
///
/// Picks bare function names from `call_graph_files` that have a
/// def-site in this shard's own file set, capped at [`FOCUS_CAP`]. S4
/// uses them to prioritize which spans to load — without them a
/// specialist shard reaches `load_sliding_window` with nothing to anchor
/// on and falls all the way through to blind whole-file tiling, which is
/// exactly the case sharding exists to avoid.
///
/// One deterministic divergence: `ctx.call_graph_files` is a `BTreeMap`
/// here, so the cap takes the first `FOCUS_CAP` names in sorted order
/// rather than Python's dict-insertion order. Both are arbitrary
/// truncations of the same candidate set; sorted order is at least
/// reproducible across runs.
fn specialist_focus_entry_points(files: &[String], ctx: &ContextPackage) -> Vec<String> {
    if files.is_empty() {
        return Vec::new();
    }
    let file_set: BTreeSet<&str> = files.iter().map(String::as_str).collect();
    ctx.call_graph_files
        .iter()
        .filter(|(_, locs)| {
            locs.iter()
                .any(|loc| file_set.contains(loc.rsplit_once(':').map_or(loc.as_str(), |(f, _)| f)))
        })
        .map(|(fname, _)| fname.clone())
        .take(FOCUS_CAP)
        .collect()
}

/// `cap` in `_specialist_focus_entry_points`.
const FOCUS_CAP: usize = 24;

/// Eight parameters, one over clippy's default: this mirrors Python's own
/// `_mk_specialist(spec, shard, label, files, loc, rank, langs, focus)`
/// signature exactly, and every argument is a distinct value the caller
/// computes separately. Bundling them into a struct purely to satisfy the
/// lint would obscure that correspondence for no reader's benefit.
#[allow(clippy::too_many_arguments)]
fn mk_specialist(
    spec: &str,
    shard: usize,
    label: &str,
    files: Vec<String>,
    loc: i64,
    rank: i64,
    langs: Vec<&'static str>,
    focus_entry_points: Vec<String>,
) -> Chunk {
    Chunk {
        id: format!("spec-{spec}-{shard:02}"),
        size: size_for(loc),
        risk_rank: rank,
        files,
        focus_entry_points,
        hypothesis: format!("{spec} specialist sweep over module '{label}'."),
        related_cves: Vec::new(),
        threat_id: None,
        languages: langs.into_iter().map(String::from).collect(),
        specialist: Some(spec.to_string()),
        path_funcs: Vec::new(),
        source_ref: String::new(),
        sink_ref: String::new(),
        sink_cwe: Vec::new(),
    }
}

/// Append repo-wide specialist passes. These see ALL source files
/// regardless of risk-ranking — they hunt for cross-cutting bug classes
/// that per-chunk language researchers miss. Sharding is module-aware
/// (via [`cohesive_groups`]) and restricted to actual source files.
/// Returns the new chunks (appended to the manifest by the caller).
pub fn add_specialist_chunks(
    existing_chunks: &[Chunk],
    ctx: &ContextPackage,
    config: &Step3Config,
) -> Vec<Chunk> {
    let source: Vec<String> = ctx
        .all_files
        .iter()
        .filter(|f| is_source(f))
        .cloned()
        .collect();
    let enabled = gate_specialists(&config.specialists, ctx, &source);
    if enabled.is_empty() || source.is_empty() {
        return Vec::new();
    }

    let repo_root = Path::new(&ctx.repo_root);
    let max_loc = config.specialist_chunk_loc;
    let max_files = config.max_files_per_chunk;
    let char_cap = char_budget(config);
    let base_rank = existing_chunks
        .iter()
        .map(|c| c.risk_rank)
        .max()
        .unwrap_or(0);

    let default_buckets = pack(
        &cohesive_groups(&source, ctx),
        repo_root,
        max_loc,
        max_files,
        char_cap,
        config.pack_merge_underfilled,
    );

    let mut out = Vec::new();
    let mut n_added: i64 = 0;
    for spec in &enabled {
        let spec_buckets = if spec == "iac" {
            // Never empty when we get here: `source` already only contains
            // `is_source`-eligible files, and `is_source` returns true for
            // every `is_iac_file` match (it's the last check in that
            // cascade) — so "iac" surviving `gate_specialists`'s "any IaC
            // file in `ctx.all_files`" check guarantees at least one of
            // those same files is also in `source`. The Python original
            // has this same check as an acknowledged redundant guard
            // against `_gate_specialists` (see that function's own
            // comment); dropped here rather than kept as untestable dead
            // code.
            let iac_source: Vec<String> = source
                .iter()
                .filter(|f| bc_repo_analysis::is_iac_file(f))
                .cloned()
                .collect();
            pack(
                &cohesive_groups(&iac_source, ctx),
                repo_root,
                max_loc,
                max_files,
                char_cap,
                config.pack_merge_underfilled,
            )
        } else {
            default_buckets.clone()
        };
        for (shard, (label, files, loc)) in spec_buckets.into_iter().enumerate() {
            let langs = bc_repo_analysis::detect_languages(&files, Some(repo_root));
            // Computed before `files` is moved into the chunk, matching
            // Python's own `focus = _specialist_focus_entry_points(files, ctx)`
            // ordering at `s3_decompose.py:1338`.
            let focus = specialist_focus_entry_points(&files, ctx);
            out.push(mk_specialist(
                spec,
                shard + 1,
                &label,
                files,
                loc,
                base_rank + n_added + 1,
                langs,
                focus,
            ));
            n_added += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_model::{AppProfile, Control, EntryPoint, Impact, Likelihood, Threat, ThreatModel};

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

    fn write(dir: &Path, rel: &str, contents: &str) {
        std::fs::write(dir.join(rel), contents).unwrap();
    }

    #[test]
    fn specialist_focus_entry_points_picks_names_with_a_def_site_in_the_shard() {
        let mut ctx = ctx_with_root(Path::new("/repo"));
        ctx.call_graph_files
            .insert("encrypt".to_string(), vec!["src/crypto.py:12".to_string()]);
        ctx.call_graph_files
            .insert("unrelated".to_string(), vec!["src/other.py:3".to_string()]);
        // A def-site with no `:line` suffix still matches on the whole
        // string, matching Python's `ref.rpartition(":")[0]` fallback.
        ctx.call_graph_files
            .insert("bare".to_string(), vec!["src/crypto.py".to_string()]);

        let files = vec!["src/crypto.py".to_string()];
        let focus = specialist_focus_entry_points(&files, &ctx);
        assert_eq!(focus, vec!["bare".to_string(), "encrypt".to_string()]);
    }

    #[test]
    fn specialist_focus_entry_points_is_empty_for_an_empty_shard() {
        let ctx = ctx_with_root(Path::new("/repo"));
        assert!(specialist_focus_entry_points(&[], &ctx).is_empty());
    }

    #[test]
    fn specialist_focus_entry_points_is_capped() {
        let mut ctx = ctx_with_root(Path::new("/repo"));
        for i in 0..(FOCUS_CAP + 10) {
            ctx.call_graph_files
                .insert(format!("fn{i:03}"), vec!["src/a.py:1".to_string()]);
        }
        let files = vec!["src/a.py".to_string()];
        assert_eq!(specialist_focus_entry_points(&files, &ctx).len(), FOCUS_CAP);
    }

    #[test]
    fn has_authz_surface_true_from_externally_facing_app_profile() {
        let mut ctx = ctx_with_root(Path::new("/repo"));
        ctx.app_profile = Some(AppProfile {
            application_id: "A".to_string(),
            name: String::new(),
            externally_facing: true,
            pci_scoped: false,
            processes_pan: false,
            pii: false,
            source: "cmdb".to_string(),
        });
        assert!(has_authz_surface(&ctx));
    }

    #[test]
    fn has_authz_surface_true_from_network_entry_point() {
        let mut ctx = ctx_with_root(Path::new("/repo"));
        ctx.entry_points = vec![EntryPoint {
            file: "a.py".to_string(),
            function: "f".to_string(),
            kind: EntryPointKind::Network,
            reachable_from_unauth: false,
        }];
        assert!(has_authz_surface(&ctx));
    }

    #[test]
    fn has_authz_surface_true_from_auth_control() {
        let mut ctx = ctx_with_root(Path::new("/repo"));
        ctx.design_controls = vec![Control {
            name: "WAF".to_string(),
            kind: ControlKind::Auth,
            protects: Vec::new(),
            notes: String::new(),
        }];
        assert!(has_authz_surface(&ctx));
    }

    #[test]
    fn has_authz_surface_false_with_no_signals() {
        let ctx = ctx_with_root(Path::new("/repo"));
        assert!(!has_authz_surface(&ctx));
    }

    #[test]
    fn has_authz_surface_true_from_a_remote_actor_threat() {
        let mut ctx = ctx_with_root(Path::new("/repo"));
        ctx.threat_model = Some(ThreatModel {
            threats: vec![Threat {
                id: "T1".to_string(),
                threat: "t".to_string(),
                actor: Actor::RemoteAuth,
                surface: "s".to_string(),
                asset: "a".to_string(),
                impact: Impact::High,
                likelihood: Likelihood::Likely,
                controls: String::new(),
                evidence: String::new(),
            }],
            ..Default::default()
        });
        assert!(has_authz_surface(&ctx));
    }

    #[test]
    fn has_authz_surface_false_when_threat_model_has_only_non_remote_actors() {
        let mut ctx = ctx_with_root(Path::new("/repo"));
        ctx.threat_model = Some(ThreatModel {
            threats: vec![Threat {
                id: "T1".to_string(),
                threat: "t".to_string(),
                actor: Actor::LocalUser,
                surface: "s".to_string(),
                asset: "a".to_string(),
                impact: Impact::High,
                likelihood: Likelihood::Likely,
                controls: String::new(),
                evidence: String::new(),
            }],
            ..Default::default()
        });
        assert!(!has_authz_surface(&ctx));
    }

    #[test]
    fn scan_any_skips_an_unreadable_file_and_keeps_scanning() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "b.py", "cipher = AES.new(key)\n");
        let files = vec!["missing.py".to_string(), "b.py".to_string()];
        assert!(scan_any(dir.path(), &files, &CRYPTO_RX));
    }

    #[test]
    fn gate_specialists_keeps_logic_bug_unconditionally() {
        let ctx = ctx_with_root(Path::new("/repo"));
        let enabled = vec!["logic-bug".to_string()];
        assert_eq!(gate_specialists(&enabled, &ctx, &[]), enabled);
    }

    #[test]
    fn gate_specialists_drops_crypto_with_no_matching_content() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.py", "print('hello')\n");
        let ctx = ctx_with_root(dir.path());
        let enabled = vec!["crypto".to_string()];
        assert!(gate_specialists(&enabled, &ctx, &["a.py".to_string()]).is_empty());
    }

    #[test]
    fn gate_specialists_keeps_crypto_with_matching_content() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.py", "cipher = AES.new(key)\n");
        let ctx = ctx_with_root(dir.path());
        let enabled = vec!["crypto".to_string()];
        assert_eq!(
            gate_specialists(&enabled, &ctx, &["a.py".to_string()]),
            enabled
        );
    }

    #[test]
    fn gate_specialists_deserialization_is_case_sensitive() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.py", "pickle.loads(data)\n");
        write(dir.path(), "b.py", "readObject()\n");
        let ctx = ctx_with_root(dir.path());
        // "pickle." (lowercase, matches the literal case-sensitive pattern)
        let enabled = vec!["deserialization".to_string()];
        assert_eq!(
            gate_specialists(&enabled, &ctx, &["a.py".to_string()]),
            enabled
        );
        assert_eq!(
            gate_specialists(&enabled, &ctx, &["b.py".to_string()]),
            enabled
        );
    }

    #[test]
    fn gate_specialists_keeps_batch_etl_from_file_entry_point() {
        let mut ctx = ctx_with_root(Path::new("/repo"));
        ctx.entry_points = vec![EntryPoint {
            file: "a.py".to_string(),
            function: "f".to_string(),
            kind: EntryPointKind::File,
            reachable_from_unauth: false,
        }];
        let enabled = vec!["batch-etl".to_string()];
        assert_eq!(gate_specialists(&enabled, &ctx, &[]), enabled);
    }

    #[test]
    fn gate_specialists_keeps_batch_etl_from_cobol_language() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.cbl", "IDENTIFICATION DIVISION.\n");
        let mut ctx = ctx_with_root(dir.path());
        ctx.all_files = vec!["a.cbl".to_string()];
        let enabled = vec!["batch-etl".to_string()];
        assert_eq!(
            gate_specialists(&enabled, &ctx, &["a.cbl".to_string()]),
            enabled
        );
    }

    #[test]
    fn gate_specialists_keeps_batch_etl_from_content_scan() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.py", "import struct\nstruct.pack('i', 5)\n");
        let ctx = ctx_with_root(dir.path());
        let enabled = vec!["batch-etl".to_string()];
        assert_eq!(
            gate_specialists(&enabled, &ctx, &["a.py".to_string()]),
            enabled
        );
    }

    #[test]
    fn gate_specialists_iac_gated_by_repo_wide_all_files_not_just_source() {
        let mut ctx = ctx_with_root(Path::new("/repo"));
        ctx.all_files = vec!["Dockerfile".to_string()];
        let enabled = vec!["iac".to_string()];
        assert_eq!(gate_specialists(&enabled, &ctx, &[]), enabled);
    }

    #[test]
    fn gate_specialists_drops_iac_with_no_iac_files_anywhere() {
        let mut ctx = ctx_with_root(Path::new("/repo"));
        ctx.all_files = vec!["a.py".to_string()];
        let enabled = vec!["iac".to_string()];
        assert!(gate_specialists(&enabled, &ctx, &[]).is_empty());
    }

    #[test]
    fn add_specialist_chunks_empty_when_nothing_enabled() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.py", "print(1)\n");
        let mut ctx = ctx_with_root(dir.path());
        ctx.all_files = vec!["a.py".to_string()];
        let mut cfg = Step3Config::new("m");
        cfg.specialists = vec!["crypto".to_string()];
        assert!(add_specialist_chunks(&[], &ctx, &cfg).is_empty());
    }

    #[test]
    fn add_specialist_chunks_builds_chunks_ranked_above_existing() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.py", "print(1)\n");
        let mut ctx = ctx_with_root(dir.path());
        ctx.all_files = vec!["a.py".to_string()];
        let mut cfg = Step3Config::new("m");
        cfg.specialists = vec!["logic-bug".to_string()];
        let out = add_specialist_chunks(&[], &ctx, &cfg);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, "spec-logic-bug-01");
        assert_eq!(out[0].specialist, Some("logic-bug".to_string()));
        assert_eq!(out[0].risk_rank, 1);
    }

    #[test]
    fn add_specialist_chunks_iac_scoped_narrower_than_default() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.py", "print(1)\n");
        write(dir.path(), "Dockerfile", "FROM scratch\n");
        let mut ctx = ctx_with_root(dir.path());
        ctx.all_files = vec!["a.py".to_string(), "Dockerfile".to_string()];
        let mut cfg = Step3Config::new("m");
        cfg.specialists = vec!["iac".to_string()];
        let out = add_specialist_chunks(&[], &ctx, &cfg);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].files, vec!["Dockerfile".to_string()]);
    }

    #[test]
    fn add_specialist_chunks_running_rank_counter_spans_specialists() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.py", "cipher = AES.new(key)\n");
        let mut ctx = ctx_with_root(dir.path());
        ctx.all_files = vec!["a.py".to_string()];
        let mut cfg = Step3Config::new("m");
        cfg.specialists = vec!["crypto".to_string(), "logic-bug".to_string()];
        let out = add_specialist_chunks(&[], &ctx, &cfg);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].risk_rank, 1);
        assert_eq!(out[1].risk_rank, 2);
    }

    /// 30 one-file directories, each far under one `specialist_chunk_loc`.
    /// This is the shape the coalescing pass exists for.
    fn thirty_singleton_dirs(dir: &Path) -> Vec<String> {
        let mut all_files = Vec::new();
        for i in 0..30 {
            let rel = format!("d{i:02}/m.py");
            std::fs::create_dir_all(dir.join(format!("d{i:02}"))).unwrap();
            // One AES mention keeps the crypto lens gated ON.
            let body = if i == 0 {
                "cipher = AES.new(key)\n".to_string()
            } else {
                format!("def fn{i}():\n    return {i}\n")
            };
            write(dir, &rel, &body);
            all_files.push(rel);
        }
        all_files
    }

    #[test]
    fn add_specialist_chunks_coalesces_across_singleton_directories() {
        // Cost measurement, not a shape assertion: 30 singleton directories
        // used to emit 30 chunks PER LENS (one S4 model call each). With
        // coalescing that is one chunk per lens, with identical coverage.
        let dir = tempfile::tempdir().unwrap();
        let all_files = thirty_singleton_dirs(dir.path());
        let mut ctx = ctx_with_root(dir.path());
        ctx.all_files = all_files.clone();
        let mut cfg = Step3Config::new("m");
        cfg.specialists = vec!["crypto".to_string(), "logic-bug".to_string()];

        cfg.pack_merge_underfilled = false;
        let before = add_specialist_chunks(&[], &ctx, &cfg);
        cfg.pack_merge_underfilled = true;
        let after = add_specialist_chunks(&[], &ctx, &cfg);

        assert_eq!(before.len(), 60); // 30 buckets × 2 lenses
        assert_eq!(after.len(), 2); //  1 bucket  × 2 lenses
        for lens in ["crypto", "logic-bug"] {
            let chunks: Vec<&Chunk> = after
                .iter()
                .filter(|c| c.specialist.as_deref() == Some(lens))
                .collect();
            assert_eq!(chunks.len(), 1);
            assert_eq!(chunks[0].files, all_files);
        }
        // Same file set either way, no file lost to the merge.
        let flat_before: Vec<&String> = before
            .iter()
            .filter(|c| c.specialist.as_deref() == Some("crypto"))
            .flat_map(|c| c.files.iter())
            .collect();
        let flat_after: Vec<&String> = after
            .iter()
            .filter(|c| c.specialist.as_deref() == Some("crypto"))
            .flat_map(|c| c.files.iter())
            .collect();
        assert_eq!(flat_before, flat_after);
    }
}
