//! Deterministic threat-surface fallback chunks: guarantees every threat in
//! the threat model ends up covered by at least one chunk carrying its
//! `threat_id`, even when the risk/taint/catch-all/specialist passes
//! already review the same files but never stamp a `threat_id` onto them
//! (so `report::drop_unknown_threat_ids`'s coverage signal would otherwise
//! underreport a threat that's actually being looked at). Ported from
//! `s3_decompose.py::_add_threat_surface_fallback_chunks` and its
//! `_candidate_files_for_threat`/`_matches_threat_surface`/`_threat_text`/
//! `_is_config_file`/`_tok` helpers. Active in Python's `default.yaml`.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::LazyLock;

use bc_model::{Actor, Chunk, ContextPackage, EntryPoint, Threat};
use regex::Regex;

use crate::pack::confined_loc;
use crate::wire::actor_str;
use crate::Step3Config;
use bc_repo_analysis::is_source;

static TOKEN_RX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[a-z0-9]+").unwrap());

static THREAT_IAC_RX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(supply\s*chain|dependency|dependencies|package|sbom|build|release|ci/?cd|pipeline|workflow|actions?|github\s*actions|jenkins|docker|kubernetes|k8s|terraform|helm|image)\b",
    )
    .unwrap()
});
static THREAT_LLM_RX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(llm|prompt|jailbreak|rag|tool\s*call|agent|assistant|model\s*output|prompt\s*inject|indirect\s*inject)\b",
    )
    .unwrap()
});
static THREAT_AUTHZ_RX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(authz|authorization|access\s*control|idor|rbac|acl|privilege|session|csrf|oauth|jwt|tenant\s*isolation)\b",
    )
    .unwrap()
});
static THREAT_CRYPTO_RX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(crypto|cipher|encryption|decrypt|signature|hmac|hash|md5|sha|tls|ssl|x509|certificate|secret\s*key|key\s*management)\b",
    )
    .unwrap()
});
static THREAT_DESER_RX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(deserial|pickle|marshal|yaml\.load|objectinputstream|readobject|binaryformatter|xstream|snakeyaml|hessian|kryo)\b",
    )
    .unwrap()
});
static THREAT_BATCH_RX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(batch|etl|file\s*ingest|bulk\s*import|job\s*scheduler|mainframe|jcl|cobol|record\s*format)\b",
    )
    .unwrap()
});
static THREAT_CONFIG_RX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(config|configuration|policy|feature\s*flag|runtime\s*toggle|environment\s*variable|env\b|deployment\s*setting)\b",
    )
    .unwrap()
});
static IAC_PATH_RX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(\.github/workflows/|dockerfile|jenkinsfile|\.gitlab-ci|azure-pipelines|\.tf$|helm/|k8s/|kubernetes/|chart\.ya?ml$|values\.ya?ml$|pom\.xml$|package\.json$|requirements(\.txt)?$|pyproject\.toml$|poetry\.lock$|setup\.py$)",
    )
    .unwrap()
});
static LLM_PATH_RX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(llm|prompt|agent|assistant|openai|anthropic|rag|chat|completion|tool)")
        .unwrap()
});
static AUTHZ_PATH_RX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(auth|oauth|jwt|rbac|acl|permission|policy|session|tenant)").unwrap()
});

const CONFIG_EXTS: &[&str] = &[
    ".yml",
    ".yaml",
    ".json",
    ".toml",
    ".ini",
    ".conf",
    ".properties",
    ".xml",
    ".env",
];

fn tok(s: &str) -> HashSet<String> {
    TOKEN_RX
        .find_iter(&s.to_lowercase())
        .map(|m| m.as_str().to_string())
        .collect()
}

fn is_config_file(rel: &str) -> bool {
    let name = Path::new(rel)
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if name.starts_with(".env") {
        return true;
    }
    let ext = Path::new(rel)
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy().to_lowercase()))
        .unwrap_or_default();
    if CONFIG_EXTS.contains(&ext.as_str()) {
        return true;
    }
    name.contains("config") || name.contains("policy") || name.contains("settings")
}

/// The text the routing regexes read. `controls` is deliberately excluded
/// (upstream v1.3): it describes MITIGATIONS, the opposite of where to
/// hunt, so a threat whose controls mention "JWT signature validation"
/// pulled in every file containing "jwt". `evidence` is excluded because it
/// carries the `baseline: BL-*` provenance prefix.
fn threat_text(t: &Threat) -> String {
    [
        t.threat.as_str(),
        t.surface.as_str(),
        t.asset.as_str(),
        actor_str(t.actor),
    ]
    .into_iter()
    .filter(|s| !s.is_empty())
    .collect::<Vec<_>>()
    .join(" ")
}

fn matches_threat_surface(ep: &EntryPoint, t: &Threat) -> bool {
    let surface_tokens = tok(&t.surface);
    if surface_tokens.is_empty() {
        return false;
    }
    let fn_lower = ep.function.to_lowercase();
    if !fn_lower.is_empty() && t.surface.to_lowercase() == fn_lower {
        return true;
    }
    !surface_tokens.is_disjoint(&tok(&ep.function))
}

/// Must match the pattern S2 writes these evidence strings with. A threat
/// S2 emitted to satisfy a mandatory baseline disposition carries
/// `"baseline: BL-<AREA>-<ID>"` evidence.
static BASELINE_EVIDENCE_RX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^baseline:\s*(BL-[A-Z]+-\w+)").unwrap());

/// A path-shaped token inside a threat's `surface` (`routes/b2bOrder.ts`,
/// `lib/insecurity.ts::decode(token)`). Requires a file extension, so prose
/// surfaces ("npm dependencies", "terraform/ IaC") yield nothing.
static SURFACE_PATH_RX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[\w./\\-]+\.[A-Za-z0-9]{1,6}").unwrap());

fn surface_names_a_real_file(t: &Threat, all_files: &HashSet<&str>) -> bool {
    SURFACE_PATH_RX.find_iter(&t.surface).any(|m| {
        let mut cand = m.as_str().replace('\\', "/");
        while let Some(rest) = cand.strip_prefix("./") {
            cand = rest.to_string();
        }
        let suffix = format!("/{cand}");
        all_files.contains(cand.as_str()) || all_files.iter().any(|f| f.ends_with(&suffix))
    })
}

/// A baseline disposition that pins itself to no code surface in this repo
/// (upstream v1.3 `_is_unmatched_baseline_threat`). These, and only these,
/// are exempt from a dedicated fallback chunk and from the threat-coverage
/// denominator: a chunk for one would select noise through the routing
/// regexes for no recall benefit, and it would otherwise count as
/// permanently uncovered. The baseline marker alone is NOT the test: S2
/// asks for it on every disposed checklist item, so a threat naming a
/// concrete file carries it too, and exempting on the marker stripped the
/// coverage guarantee from most real threats.
pub fn is_unmatched_baseline_threat(t: &Threat, all_files: &HashSet<&str>) -> bool {
    BASELINE_EVIDENCE_RX.is_match(&t.evidence) && !surface_names_a_real_file(t, all_files)
}

/// Appends to `chosen` in order, skipping duplicates and anything outside
/// the inventory, and stops at `max_files`.
fn add_candidates(
    seq: impl IntoIterator<Item = String>,
    all_file_set: &HashSet<&str>,
    chosen: &mut Vec<String>,
    seen: &mut HashSet<String>,
    max_files: usize,
) {
    for f in seq {
        if chosen.len() >= max_files {
            return;
        }
        if all_file_set.contains(f.as_str()) && seen.insert(f.clone()) {
            chosen.push(f);
        }
    }
}

fn candidate_files_for_threat(
    t: &Threat,
    ctx: &ContextPackage,
    specialist_files: &HashMap<String, Vec<String>>,
    max_files: usize,
) -> Vec<String> {
    let txt = threat_text(t);
    let all_file_set: HashSet<&str> = ctx.all_files.iter().map(String::as_str).collect();
    let source_or_config: Vec<String> = ctx
        .all_files
        .iter()
        .filter(|f| is_source(f) || is_config_file(f))
        .cloned()
        .collect();
    let empty: Vec<String> = Vec::new();

    let mut chosen: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    // Order matters under truncation (upstream v1.3): entry-point hits are
    // the strongest signal (the threat's surface names a function that IS
    // this entry point), so they go first and survive truncation; their
    // call-graph neighbors (the files those entry points call into or are
    // called from) come next. The regex and specialist heuristics, with no
    // direct evidence tying them to this threat, come last and are the
    // first to be cut at `max_files`.
    let ep_hits: Vec<String> = ctx
        .entry_points
        .iter()
        .filter(|ep| matches_threat_surface(ep, t))
        .map(|ep| ep.file.clone())
        .collect();
    let adj = crate::grouping::file_call_graph(ctx);
    let neighbors: Vec<String> = ep_hits
        .iter()
        .flat_map(|f| adj.get(f).into_iter().flatten().cloned())
        .collect();
    add_candidates(ep_hits, &all_file_set, &mut chosen, &mut seen, max_files);
    add_candidates(neighbors, &all_file_set, &mut chosen, &mut seen, max_files);

    if t.actor == Actor::SupplyChain || THREAT_IAC_RX.is_match(&txt) {
        add_candidates(
            specialist_files
                .get("iac")
                .unwrap_or(&empty)
                .iter()
                .cloned(),
            &all_file_set,
            &mut chosen,
            &mut seen,
            max_files,
        );
        add_candidates(
            source_or_config
                .iter()
                .filter(|f| bc_repo_analysis::is_iac_file(f) || IAC_PATH_RX.is_match(f))
                .cloned(),
            &all_file_set,
            &mut chosen,
            &mut seen,
            max_files,
        );
    }
    if THREAT_LLM_RX.is_match(&txt) {
        add_candidates(
            source_or_config
                .iter()
                .filter(|f| LLM_PATH_RX.is_match(f))
                .cloned(),
            &all_file_set,
            &mut chosen,
            &mut seen,
            max_files,
        );
    }
    if matches!(t.actor, Actor::RemoteUnauth | Actor::RemoteAuth) || THREAT_AUTHZ_RX.is_match(&txt)
    {
        add_candidates(
            specialist_files
                .get("access-control")
                .unwrap_or(&empty)
                .iter()
                .cloned(),
            &all_file_set,
            &mut chosen,
            &mut seen,
            max_files,
        );
        add_candidates(
            source_or_config
                .iter()
                .filter(|f| AUTHZ_PATH_RX.is_match(f))
                .cloned(),
            &all_file_set,
            &mut chosen,
            &mut seen,
            max_files,
        );
    }
    if THREAT_CRYPTO_RX.is_match(&txt) {
        add_candidates(
            specialist_files
                .get("crypto")
                .unwrap_or(&empty)
                .iter()
                .cloned(),
            &all_file_set,
            &mut chosen,
            &mut seen,
            max_files,
        );
    }
    if THREAT_DESER_RX.is_match(&txt) {
        add_candidates(
            specialist_files
                .get("deserialization")
                .unwrap_or(&empty)
                .iter()
                .cloned(),
            &all_file_set,
            &mut chosen,
            &mut seen,
            max_files,
        );
    }
    if THREAT_BATCH_RX.is_match(&txt) {
        add_candidates(
            specialist_files
                .get("batch-etl")
                .unwrap_or(&empty)
                .iter()
                .cloned(),
            &all_file_set,
            &mut chosen,
            &mut seen,
            max_files,
        );
    }
    if THREAT_CONFIG_RX.is_match(&txt) {
        add_candidates(
            source_or_config
                .iter()
                .filter(|f| is_config_file(f))
                .cloned(),
            &all_file_set,
            &mut chosen,
            &mut seen,
            max_files,
        );
    }

    chosen
}

/// What the fallback pass produced and what its ceilings cut.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct FallbackResult {
    pub chunks: Vec<Chunk>,
    /// Threats with a candidate chunk that `max_threat_fallback_chunks`
    /// suppressed.
    pub capped: usize,
    /// Candidate files dropped to keep a chunk within `risk_chunk_loc`.
    pub files_trimmed: usize,
}

/// Append one chunk per uncovered threat whose surface signals resolve to
/// at least one concrete file — silently skipping any threat with no
/// plausible code surface, matching the SYSTEM prompt's own "omit it"
/// instruction for the LLM-authored pass this backstops. Returns the new
/// chunks (appended to the manifest by the caller), each carrying a
/// non-null `threat_id`, plus what the ceilings suppressed.
///
/// Upstream v1.3 bounds the pass three ways: at most
/// `max_threat_fallback_chunks` chunks (a suppressed candidate is counted,
/// not silently skipped), each chunk trimmed at build time to
/// `risk_chunk_loc` (keeping at least one file; trimmed rather than split
/// afterwards, so the chunk ceiling stays a real ceiling on S4 calls), and
/// no chunk for a baseline disposition that names no code surface
/// ([`is_unmatched_baseline_threat`]).
pub fn add_threat_surface_fallback_chunks(
    existing_chunks: &[Chunk],
    ctx: &ContextPackage,
    config: &Step3Config,
) -> FallbackResult {
    if !config.threat_surface_fallbacks {
        return FallbackResult::default();
    }
    let Some(tm) = &ctx.threat_model else {
        return FallbackResult::default();
    };
    let all_files: HashSet<&str> = ctx.all_files.iter().map(String::as_str).collect();
    let covered: HashSet<&str> = existing_chunks
        .iter()
        .filter_map(|c| c.threat_id.as_deref())
        .collect();
    let missing: Vec<&Threat> = tm
        .threats
        .iter()
        .filter(|t| !t.id.is_empty() && !covered.contains(t.id.as_str()))
        .filter(|t| !is_unmatched_baseline_threat(t, &all_files))
        .collect();
    if missing.is_empty() {
        return FallbackResult::default();
    }
    let max_chunks = crate::cap_or_default(
        config.max_threat_fallback_chunks,
        crate::DEFAULT_MAX_THREAT_FALLBACK_CHUNKS,
    );
    // Read the way the splitter reads it, NOT through `cap_or_default`:
    // `risk_chunk_loc: 0` documents "off", and mapping it onto a default
    // budget would override the operator's off switch.
    let loc_budget = config.risk_chunk_loc.max(0);

    // Matches Python's `int(getattr(step3, "threat_fallback_max_files", 12)
    // or 12)`: an explicit `0` is falsy in Python and falls back to 12,
    // same as an unset value — preserved here rather than "fixed" since
    // this port's discipline is faithful parity, not silent behavior drift.
    let max_files = if config.threat_fallback_max_files == 0 {
        12
    } else {
        config.threat_fallback_max_files
    };
    let base_rank = existing_chunks
        .iter()
        .map(|c| c.risk_rank)
        .max()
        .unwrap_or(0);
    let repo_root = Path::new(&ctx.repo_root);

    let mut specialist_files: HashMap<String, Vec<String>> = HashMap::new();
    for c in existing_chunks {
        if let Some(spec) = &c.specialist {
            specialist_files
                .entry(spec.clone())
                .or_default()
                .extend(c.files.iter().cloned());
        }
    }
    for files in specialist_files.values_mut() {
        let mut seen = HashSet::new();
        files.retain(|f| seen.insert(f.clone()));
    }

    let mut used_ids: HashSet<String> = existing_chunks.iter().map(|c| c.id.clone()).collect();
    let mut result = FallbackResult::default();
    let mut added: i64 = 0;

    for t in missing {
        let candidates = candidate_files_for_threat(t, ctx, &specialist_files, max_files);
        if candidates.is_empty() {
            continue;
        }
        if result.chunks.len() >= max_chunks {
            result.capped += 1;
            continue;
        }
        // Fewest-files-dropped order is kept (the candidate list is already
        // ranked), and the first file always survives so a single oversize
        // file is still reviewed.
        let mut files: Vec<String> = Vec::new();
        let mut loc: i64 = 0;
        for f in candidates {
            let f_loc = confined_loc(repo_root, &f);
            if !files.is_empty() && loc_budget > 0 && loc + f_loc > loc_budget {
                result.files_trimmed += 1;
                continue;
            }
            files.push(f);
            loc += f_loc;
        }

        let mut cid = format!("threat-{}-fallback", t.id.to_lowercase());
        if used_ids.contains(&cid) {
            let mut n = 2;
            loop {
                let candidate = format!("{cid}-{n}");
                if !used_ids.contains(&candidate) {
                    cid = candidate;
                    break;
                }
                n += 1;
            }
        }
        used_ids.insert(cid.clone());

        let focus: Vec<String> = ctx
            .entry_points
            .iter()
            .filter(|ep| matches_threat_surface(ep, t))
            .map(|ep| ep.function.clone())
            .take(8)
            .collect();

        added += 1;
        result.chunks.push(Chunk {
            id: cid,
            size: bc_repo_analysis::size_for(loc.max(0) as usize),
            risk_rank: base_rank + added,
            files,
            focus_entry_points: focus,
            hypothesis: format!(
                "Deterministic threat-surface fallback for {}: {}. Review likely files derived from actor/surface signals and repository specialist coverage.",
                t.id, t.threat
            ),
            related_cves: Vec::new(),
            threat_id: Some(t.id.clone()),
            languages: Vec::new(),
            specialist: None,
            path_funcs: Vec::new(),
            source_ref: String::new(),
            sink_ref: String::new(),
            sink_cwe: Vec::new(),
            shard_id: String::new(),
        });
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_model::{ChunkSize, EntryPointKind, Impact, Likelihood, ThreatModel};

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
        let path = dir.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, contents).unwrap();
    }

    fn threat(id: &str, threat: &str, actor: Actor, surface: &str) -> Threat {
        Threat {
            id: id.to_string(),
            threat: threat.to_string(),
            actor,
            surface: surface.to_string(),
            asset: String::new(),
            impact: Impact::High,
            likelihood: Likelihood::Likely,
            controls: String::new(),
            evidence: String::new(),
        }
    }

    fn chunk(id: &str, risk_rank: i64, threat_id: Option<&str>) -> Chunk {
        Chunk {
            id: id.to_string(),
            size: ChunkSize::Small,
            risk_rank,
            files: Vec::new(),
            focus_entry_points: Vec::new(),
            hypothesis: String::new(),
            related_cves: Vec::new(),
            threat_id: threat_id.map(String::from),
            languages: Vec::new(),
            specialist: None,
            path_funcs: Vec::new(),
            source_ref: String::new(),
            sink_ref: String::new(),
            sink_cwe: Vec::new(),
            shard_id: String::new(),
        }
    }

    // ── is_config_file ──────────────────────────────────────────────────

    #[test]
    fn is_config_file_matches_dotenv_prefix() {
        assert!(is_config_file(".env.production"));
    }

    #[test]
    fn is_config_file_matches_known_extension() {
        assert!(is_config_file("app/settings.yaml"));
        assert!(is_config_file("app/values.json"));
    }

    #[test]
    fn is_config_file_matches_name_keyword() {
        assert!(is_config_file("src/config.py"));
        assert!(is_config_file("src/policy_engine.py"));
    }

    #[test]
    fn is_config_file_false_for_plain_source() {
        assert!(!is_config_file("src/handler.py"));
    }

    // ── matches_threat_surface ──────────────────────────────────────────

    #[test]
    fn matches_threat_surface_exact_case_insensitive() {
        let ep = EntryPoint {
            file: "a.py".to_string(),
            function: "Handle_Login".to_string(),
            kind: EntryPointKind::Network,
            reachable_from_unauth: false,
        };
        let t = threat("T1", "t", Actor::RemoteAuth, "handle_login");
        assert!(matches_threat_surface(&ep, &t));
    }

    #[test]
    fn matches_threat_surface_shared_token() {
        let ep = EntryPoint {
            file: "a.py".to_string(),
            function: "handle_login_v2".to_string(),
            kind: EntryPointKind::Network,
            reachable_from_unauth: false,
        };
        let t = threat("T1", "t", Actor::RemoteAuth, "login flow");
        assert!(matches_threat_surface(&ep, &t));
    }

    #[test]
    fn matches_threat_surface_empty_surface_never_matches() {
        let ep = EntryPoint {
            file: "a.py".to_string(),
            function: "login".to_string(),
            kind: EntryPointKind::Network,
            reachable_from_unauth: false,
        };
        let t = threat("T1", "t", Actor::RemoteAuth, "");
        assert!(!matches_threat_surface(&ep, &t));
    }

    #[test]
    fn matches_threat_surface_no_token_overlap_is_false() {
        let ep = EntryPoint {
            file: "a.py".to_string(),
            function: "process_payment".to_string(),
            kind: EntryPointKind::Network,
            reachable_from_unauth: false,
        };
        let t = threat("T1", "t", Actor::RemoteAuth, "login");
        assert!(!matches_threat_surface(&ep, &t));
    }

    // ── add_threat_surface_fallback_chunks: gates ───────────────────────

    #[test]
    fn disabled_config_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let mut ctx = ctx_with_root(dir.path());
        ctx.threat_model = Some(ThreatModel {
            threats: vec![threat(
                "T1",
                "IaC pipeline compromise",
                Actor::SupplyChain,
                "",
            )],
            ..Default::default()
        });
        let mut cfg = Step3Config::new("m");
        cfg.threat_surface_fallbacks = false;
        assert!(add_threat_surface_fallback_chunks(&[], &ctx, &cfg)
            .chunks
            .is_empty());
    }

    #[test]
    fn no_threat_model_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_with_root(dir.path());
        let cfg = Step3Config::new("m");
        assert!(add_threat_surface_fallback_chunks(&[], &ctx, &cfg)
            .chunks
            .is_empty());
    }

    #[test]
    fn empty_threat_list_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let mut ctx = ctx_with_root(dir.path());
        ctx.threat_model = Some(ThreatModel::default());
        let cfg = Step3Config::new("m");
        assert!(add_threat_surface_fallback_chunks(&[], &ctx, &cfg)
            .chunks
            .is_empty());
    }

    #[test]
    fn threat_with_empty_id_is_never_a_candidate() {
        let dir = tempfile::tempdir().unwrap();
        let mut ctx = ctx_with_root(dir.path());
        ctx.threat_model = Some(ThreatModel {
            threats: vec![threat("", "supply chain risk", Actor::SupplyChain, "")],
            ..Default::default()
        });
        let cfg = Step3Config::new("m");
        assert!(add_threat_surface_fallback_chunks(&[], &ctx, &cfg)
            .chunks
            .is_empty());
    }

    #[test]
    fn already_covered_threat_produces_no_new_chunk() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), ".github/workflows/ci.yml", "name: ci\n");
        let mut ctx = ctx_with_root(dir.path());
        ctx.all_files = vec![".github/workflows/ci.yml".to_string()];
        ctx.threat_model = Some(ThreatModel {
            threats: vec![threat("T1", "supply chain risk", Actor::SupplyChain, "")],
            ..Default::default()
        });
        let cfg = Step3Config::new("m");
        let existing = vec![chunk("chunk-01", 1, Some("T1"))];
        assert!(add_threat_surface_fallback_chunks(&existing, &ctx, &cfg)
            .chunks
            .is_empty());
    }

    #[test]
    fn threat_with_no_candidate_files_is_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let mut ctx = ctx_with_root(dir.path());
        ctx.threat_model = Some(ThreatModel {
            threats: vec![threat(
                "T1",
                "a totally unrelated threat",
                Actor::LocalUser,
                "",
            )],
            ..Default::default()
        });
        let cfg = Step3Config::new("m");
        assert!(add_threat_surface_fallback_chunks(&[], &ctx, &cfg)
            .chunks
            .is_empty());
    }

    // ── add_threat_surface_fallback_chunks: real chunk emission ─────────

    #[test]
    fn supply_chain_actor_matches_iac_files_by_actor_alone() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), ".github/workflows/ci.yml", "name: ci\n");
        let mut ctx = ctx_with_root(dir.path());
        ctx.all_files = vec![".github/workflows/ci.yml".to_string()];
        // Threat text itself has no IaC keyword — only the actor triggers it.
        ctx.threat_model = Some(ThreatModel {
            threats: vec![threat("T1", "unrelated wording", Actor::SupplyChain, "")],
            ..Default::default()
        });
        let cfg = Step3Config::new("m");
        let out = add_threat_surface_fallback_chunks(&[], &ctx, &cfg).chunks;
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, "threat-t1-fallback");
        assert_eq!(out[0].threat_id, Some("T1".to_string()));
        assert_eq!(out[0].files, vec![".github/workflows/ci.yml".to_string()]);
        assert!(out[0]
            .hypothesis
            .contains("Deterministic threat-surface fallback for T1"));
        assert!(out[0].languages.is_empty());
        assert!(out[0].specialist.is_none());
    }

    #[test]
    fn threat_text_keyword_match_finds_config_files() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "settings.yaml", "flag: true\n");
        let mut ctx = ctx_with_root(dir.path());
        ctx.all_files = vec!["settings.yaml".to_string()];
        ctx.threat_model = Some(ThreatModel {
            threats: vec![threat(
                "T2",
                "a malicious feature flag toggle",
                Actor::LocalUser,
                "",
            )],
            ..Default::default()
        });
        let cfg = Step3Config::new("m");
        let out = add_threat_surface_fallback_chunks(&[], &ctx, &cfg).chunks;
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].files, vec!["settings.yaml".to_string()]);
    }

    #[test]
    fn entry_point_surface_match_populates_focus_and_files() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "auth.py", "def handle_login(): pass\n");
        let mut ctx = ctx_with_root(dir.path());
        ctx.all_files = vec!["auth.py".to_string()];
        ctx.entry_points = vec![EntryPoint {
            file: "auth.py".to_string(),
            function: "handle_login".to_string(),
            kind: EntryPointKind::Network,
            reachable_from_unauth: true,
        }];
        ctx.threat_model = Some(ThreatModel {
            threats: vec![threat(
                "T3",
                "account takeover",
                Actor::RemoteAuth,
                "handle_login",
            )],
            ..Default::default()
        });
        let cfg = Step3Config::new("m");
        let out = add_threat_surface_fallback_chunks(&[], &ctx, &cfg).chunks;
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].files, vec!["auth.py".to_string()]);
        assert_eq!(out[0].focus_entry_points, vec!["handle_login".to_string()]);
    }

    #[test]
    fn remote_actor_reuses_access_control_specialist_files() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "authz.py", "def check(): pass\n");
        let mut ctx = ctx_with_root(dir.path());
        ctx.all_files = vec!["authz.py".to_string()];
        // No authz keyword in the threat text — only the remote actor
        // triggers reuse of the access-control specialist's file list.
        ctx.threat_model = Some(ThreatModel {
            threats: vec![threat("T4", "unrelated wording", Actor::RemoteUnauth, "")],
            ..Default::default()
        });
        let cfg = Step3Config::new("m");
        let mut spec_chunk = chunk("spec-access-control-01", 1, None);
        spec_chunk.specialist = Some("access-control".to_string());
        spec_chunk.files = vec!["authz.py".to_string()];
        let out = add_threat_surface_fallback_chunks(&[spec_chunk], &ctx, &cfg).chunks;
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].files, vec!["authz.py".to_string()]);
    }

    #[test]
    fn base_rank_continues_above_existing_chunks() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), ".github/workflows/ci.yml", "name: ci\n");
        let mut ctx = ctx_with_root(dir.path());
        ctx.all_files = vec![".github/workflows/ci.yml".to_string()];
        ctx.threat_model = Some(ThreatModel {
            threats: vec![threat("T1", "supply chain risk", Actor::SupplyChain, "")],
            ..Default::default()
        });
        let cfg = Step3Config::new("m");
        let existing = vec![chunk("chunk-01", 5, None)];
        let out = add_threat_surface_fallback_chunks(&existing, &ctx, &cfg).chunks;
        assert_eq!(out[0].risk_rank, 6);
    }

    #[test]
    fn multiple_missing_threats_get_increasing_risk_rank() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), ".github/workflows/ci.yml", "name: ci\n");
        write(dir.path(), "settings.yaml", "flag: true\n");
        let mut ctx = ctx_with_root(dir.path());
        ctx.all_files = vec![
            ".github/workflows/ci.yml".to_string(),
            "settings.yaml".to_string(),
        ];
        ctx.threat_model = Some(ThreatModel {
            threats: vec![
                threat("T1", "supply chain risk", Actor::SupplyChain, ""),
                threat("T2", "a feature flag toggle", Actor::LocalUser, ""),
            ],
            ..Default::default()
        });
        let cfg = Step3Config::new("m");
        let out = add_threat_surface_fallback_chunks(&[], &ctx, &cfg).chunks;
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].risk_rank, 1);
        assert_eq!(out[1].risk_rank, 2);
    }

    #[test]
    fn llm_keyword_match_finds_llm_path_files() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "app/prompt_builder.py", "def build(): pass\n");
        let mut ctx = ctx_with_root(dir.path());
        ctx.all_files = vec!["app/prompt_builder.py".to_string()];
        ctx.threat_model = Some(ThreatModel {
            threats: vec![threat(
                "T5",
                "a prompt injection risk",
                Actor::RemoteAuth,
                "",
            )],
            ..Default::default()
        });
        let cfg = Step3Config::new("m");
        let out = add_threat_surface_fallback_chunks(&[], &ctx, &cfg).chunks;
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].files, vec!["app/prompt_builder.py".to_string()]);
    }

    #[test]
    fn crypto_keyword_match_reuses_crypto_specialist_files() {
        let dir = tempfile::tempdir().unwrap();
        let mut ctx = ctx_with_root(dir.path());
        ctx.all_files = vec!["crypto_utils.py".to_string()];
        ctx.threat_model = Some(ThreatModel {
            threats: vec![threat(
                "T6",
                "weak encryption key management",
                Actor::LocalUser,
                "",
            )],
            ..Default::default()
        });
        let cfg = Step3Config::new("m");
        let mut spec_chunk = chunk("spec-crypto-01", 1, None);
        spec_chunk.specialist = Some("crypto".to_string());
        spec_chunk.files = vec!["crypto_utils.py".to_string()];
        let out = add_threat_surface_fallback_chunks(&[spec_chunk], &ctx, &cfg).chunks;
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].files, vec!["crypto_utils.py".to_string()]);
    }

    #[test]
    fn deserialization_keyword_match_reuses_deserialization_specialist_files() {
        let dir = tempfile::tempdir().unwrap();
        let mut ctx = ctx_with_root(dir.path());
        ctx.all_files = vec!["loader.py".to_string()];
        ctx.threat_model = Some(ThreatModel {
            threats: vec![threat(
                "T7",
                "insecure pickle usage in the loader",
                Actor::LocalUser,
                "",
            )],
            ..Default::default()
        });
        let cfg = Step3Config::new("m");
        let mut spec_chunk = chunk("spec-deserialization-01", 1, None);
        spec_chunk.specialist = Some("deserialization".to_string());
        spec_chunk.files = vec!["loader.py".to_string()];
        let out = add_threat_surface_fallback_chunks(&[spec_chunk], &ctx, &cfg).chunks;
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].files, vec!["loader.py".to_string()]);
    }

    #[test]
    fn batch_keyword_match_reuses_batch_etl_specialist_files() {
        let dir = tempfile::tempdir().unwrap();
        let mut ctx = ctx_with_root(dir.path());
        ctx.all_files = vec!["ingest.py".to_string()];
        ctx.threat_model = Some(ThreatModel {
            threats: vec![threat(
                "T8",
                "a compromised batch job scheduler",
                Actor::LocalUser,
                "",
            )],
            ..Default::default()
        });
        let cfg = Step3Config::new("m");
        let mut spec_chunk = chunk("spec-batch-etl-01", 1, None);
        spec_chunk.specialist = Some("batch-etl".to_string());
        spec_chunk.files = vec!["ingest.py".to_string()];
        let out = add_threat_surface_fallback_chunks(&[spec_chunk], &ctx, &cfg).chunks;
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].files, vec!["ingest.py".to_string()]);
    }

    #[test]
    fn cid_collision_loop_advances_past_the_first_disambiguating_suffix() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), ".github/workflows/ci.yml", "name: ci\n");
        let mut ctx = ctx_with_root(dir.path());
        ctx.all_files = vec![".github/workflows/ci.yml".to_string()];
        ctx.threat_model = Some(ThreatModel {
            threats: vec![threat("T1", "supply chain risk", Actor::SupplyChain, "")],
            ..Default::default()
        });
        let cfg = Step3Config::new("m");
        let existing = vec![
            chunk("threat-t1-fallback", 1, None),
            chunk("threat-t1-fallback-2", 2, None),
        ];
        let out = add_threat_surface_fallback_chunks(&existing, &ctx, &cfg).chunks;
        assert_eq!(out[0].id, "threat-t1-fallback-3");
    }

    #[test]
    fn cid_collision_appends_a_disambiguating_suffix() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), ".github/workflows/ci.yml", "name: ci\n");
        let mut ctx = ctx_with_root(dir.path());
        ctx.all_files = vec![".github/workflows/ci.yml".to_string()];
        ctx.threat_model = Some(ThreatModel {
            threats: vec![threat("T1", "supply chain risk", Actor::SupplyChain, "")],
            ..Default::default()
        });
        let cfg = Step3Config::new("m");
        // Pre-existing chunk already claims the id this fallback would use.
        let existing = vec![chunk("threat-t1-fallback", 1, None)];
        let out = add_threat_surface_fallback_chunks(&existing, &ctx, &cfg).chunks;
        assert_eq!(out[0].id, "threat-t1-fallback-2");
    }

    #[test]
    fn max_files_truncates_candidate_list() {
        let dir = tempfile::tempdir().unwrap();
        let mut all_files = Vec::new();
        for i in 0..5 {
            let name = format!("cfg{i}.yaml");
            write(dir.path(), &name, "flag: true\n");
            all_files.push(name);
        }
        let mut ctx = ctx_with_root(dir.path());
        ctx.all_files = all_files;
        ctx.threat_model = Some(ThreatModel {
            threats: vec![threat("T1", "a feature flag toggle", Actor::LocalUser, "")],
            ..Default::default()
        });
        let mut cfg = Step3Config::new("m");
        cfg.threat_fallback_max_files = 2;
        let out = add_threat_surface_fallback_chunks(&[], &ctx, &cfg).chunks;
        assert_eq!(out[0].files.len(), 2);
    }

    #[test]
    fn zero_max_files_falls_back_to_twelve_matching_pythons_truthiness_quirk() {
        let dir = tempfile::tempdir().unwrap();
        let mut all_files = Vec::new();
        for i in 0..15 {
            let name = format!("cfg{i}.yaml");
            write(dir.path(), &name, "flag: true\n");
            all_files.push(name);
        }
        let mut ctx = ctx_with_root(dir.path());
        ctx.all_files = all_files;
        ctx.threat_model = Some(ThreatModel {
            threats: vec![threat("T1", "a feature flag toggle", Actor::LocalUser, "")],
            ..Default::default()
        });
        let mut cfg = Step3Config::new("m");
        cfg.threat_fallback_max_files = 0;
        let out = add_threat_surface_fallback_chunks(&[], &ctx, &cfg).chunks;
        assert_eq!(out[0].files.len(), 12);
    }

    #[test]
    fn step3_config_threat_fallback_defaults() {
        let cfg = Step3Config::new("m");
        assert!(cfg.threat_surface_fallbacks);
        assert_eq!(cfg.threat_fallback_max_files, 12);
    }

    // ── upstream v1.3 bounds and exemptions ──────────────────────────────

    fn baseline(id: &str, surface: &str) -> Threat {
        Threat {
            evidence: "baseline: BL-AUTH-01 disposition".to_string(),
            ..threat(
                id,
                "session fixation config weakness",
                Actor::LocalUser,
                surface,
            )
        }
    }

    #[test]
    fn a_baseline_threat_naming_no_real_file_is_exempt() {
        let all: HashSet<&str> = ["routes/b2b.ts", "server.ts"].into_iter().collect();
        assert!(is_unmatched_baseline_threat(
            &baseline("T1", "npm dependencies"),
            &all
        ));
        assert!(is_unmatched_baseline_threat(
            &baseline("T1", "lib/missing.ts"),
            &all
        ));
        // A surface naming a real file (exactly, by suffix, or with ./ or
        // backslashes) keeps the coverage guarantee despite the marker.
        for surface in [
            "routes/b2b.ts::b2bOrder",
            "b2b.ts",
            "./server.ts",
            r"routes\b2b.ts",
        ] {
            assert!(
                !is_unmatched_baseline_threat(&baseline("T1", surface), &all),
                "{surface}"
            );
        }
        // No marker at all: never exempt, whatever the surface says.
        let plain = threat("T2", "t", Actor::LocalUser, "npm dependencies");
        assert!(!is_unmatched_baseline_threat(&plain, &all));
        // The marker must lead the evidence and carry a well-formed id.
        let mut late = baseline("T3", "npm dependencies");
        late.evidence = "see baseline: BL-AUTH-01".to_string();
        assert!(!is_unmatched_baseline_threat(&late, &all));
        late.evidence = "baseline: none".to_string();
        assert!(!is_unmatched_baseline_threat(&late, &all));
    }

    #[test]
    fn unmatched_baseline_threats_get_no_fallback_chunk() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "settings.yaml", "x: 1\n");
        let mut ctx = ctx_with_root(dir.path());
        ctx.all_files = vec!["settings.yaml".to_string()];
        ctx.threat_model = Some(ThreatModel {
            threats: vec![baseline("T1", "global configuration policy")],
            ..Default::default()
        });
        let cfg = Step3Config::new("m");
        assert!(add_threat_surface_fallback_chunks(&[], &ctx, &cfg)
            .chunks
            .is_empty());
    }

    fn config_threats(n: usize) -> Vec<Threat> {
        (0..n)
            .map(|i| threat(&format!("T{i}"), "feature flag abuse", Actor::LocalUser, ""))
            .collect()
    }

    #[test]
    fn the_chunk_ceiling_counts_what_it_suppresses() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "settings.yaml", "x: 1\n");
        let mut ctx = ctx_with_root(dir.path());
        ctx.all_files = vec!["settings.yaml".to_string()];
        ctx.threat_model = Some(ThreatModel {
            threats: config_threats(4),
            ..Default::default()
        });
        let mut cfg = Step3Config::new("m");
        cfg.max_threat_fallback_chunks = 3;
        let result = add_threat_surface_fallback_chunks(&[], &ctx, &cfg);
        assert_eq!(result.chunks.len(), 3);
        assert_eq!(result.capped, 1);
        // `0` means the default ceiling (50), not "none".
        cfg.max_threat_fallback_chunks = 0;
        let result = add_threat_surface_fallback_chunks(&[], &ctx, &cfg);
        assert_eq!((result.chunks.len(), result.capped), (4, 0));
    }

    #[test]
    fn a_fallback_chunk_is_trimmed_to_risk_chunk_loc_but_keeps_one_file() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a_config.yaml", &"x: 1\n".repeat(8));
        write(dir.path(), "b_config.yaml", &"x: 1\n".repeat(8));
        write(dir.path(), "c_config.yaml", "x: 1\n");
        let mut ctx = ctx_with_root(dir.path());
        ctx.all_files = vec![
            "a_config.yaml".to_string(),
            "b_config.yaml".to_string(),
            "c_config.yaml".to_string(),
        ];
        ctx.threat_model = Some(ThreatModel {
            threats: config_threats(1),
            ..Default::default()
        });
        let mut cfg = Step3Config::new("m");
        cfg.risk_chunk_loc = 10;
        let result = add_threat_surface_fallback_chunks(&[], &ctx, &cfg);
        // 8 LOC fits, the next 8 would reach 16 > 10 and is skipped, the
        // 1-LOC file still fits.
        assert_eq!(
            result.chunks[0].files,
            vec!["a_config.yaml".to_string(), "c_config.yaml".to_string()]
        );
        assert_eq!(result.files_trimmed, 1);
        // A first file over the budget alone is still kept.
        cfg.risk_chunk_loc = 2;
        let result = add_threat_surface_fallback_chunks(&[], &ctx, &cfg);
        assert_eq!(result.chunks[0].files, vec!["a_config.yaml".to_string()]);
        // `risk_chunk_loc: 0` is the documented off switch: no trim.
        cfg.risk_chunk_loc = 0;
        let result = add_threat_surface_fallback_chunks(&[], &ctx, &cfg);
        assert_eq!(result.chunks[0].files.len(), 3);
        assert_eq!(result.files_trimmed, 0);
    }

    #[test]
    fn entry_point_hits_and_their_call_graph_neighbors_rank_first() {
        let dir = tempfile::tempdir().unwrap();
        let mut ctx = ctx_with_root(dir.path());
        ctx.all_files = vec![
            "auth/policy.py".to_string(),
            "handlers.py".to_string(),
            "db.py".to_string(),
        ];
        ctx.entry_points = vec![EntryPoint {
            file: "handlers.py".to_string(),
            function: "reset_password".to_string(),
            kind: EntryPointKind::Network,
            reachable_from_unauth: true,
        }];
        ctx.call_graph.insert(
            "handlers.py::reset_password".to_string(),
            vec!["db.py::update_user".to_string()],
        );
        ctx.threat_model = Some(ThreatModel {
            threats: vec![threat(
                "T1",
                "account takeover",
                Actor::RemoteUnauth,
                "reset_password",
            )],
            ..Default::default()
        });
        let mut cfg = Step3Config::new("m");
        cfg.threat_fallback_max_files = 2;
        let result = add_threat_surface_fallback_chunks(&[], &ctx, &cfg);
        // The authz path regex would pick `auth/policy.py`, but the entry
        // point and its callee come first and fill the two-file cap.
        assert_eq!(
            result.chunks[0].files,
            vec!["handlers.py".to_string(), "db.py".to_string()]
        );
    }

    #[test]
    fn controls_text_no_longer_routes_files() {
        let dir = tempfile::tempdir().unwrap();
        let mut ctx = ctx_with_root(dir.path());
        ctx.all_files = vec!["lib/crypto_util.py".to_string()];
        let mut t = threat("T1", "data tampering", Actor::LocalUser, "");
        t.controls = "HMAC signature validation".to_string();
        let crypto_chunk = Chunk {
            specialist: Some("crypto".to_string()),
            files: vec!["lib/crypto_util.py".to_string()],
            ..chunk("spec-crypto-01", 1, None)
        };
        ctx.threat_model = Some(ThreatModel {
            threats: vec![t],
            ..Default::default()
        });
        let cfg = Step3Config::new("m");
        assert!(
            add_threat_surface_fallback_chunks(&[crypto_chunk], &ctx, &cfg)
                .chunks
                .is_empty()
        );
    }
}
