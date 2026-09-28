//! Repo-wide specialist sweep passes (crypto, logic-bug, access-control,
//! batch-etl, iac, deserialization, csrf, sensitive-data, hardcoded-creds,
//! log-injection, injection), ported from `s3_decompose.py`'s
//! `_gate_specialists`/`_has_batch_surface`/`_scan_any`/
//! `_has_authz_surface`/`_mk_specialist`/`_add_specialist_chunks`.
//!
//! Chunks are emitted shard-major (upstream v1.3): every unscoped lens's
//! chunk for shard 1, then every lens for shard 2, and so on, each stamped
//! with the shard it reviews in `Chunk.shard_id`. All unscoped lenses see
//! the identical default buckets either way; only the emission ORDER
//! changes, so consecutive S4 calls for one shard share its source prefix
//! and can land inside one provider prompt-cache window instead of
//! re-sending the same shard once per lens.

use std::collections::{BTreeSet, HashSet};
use std::io::Read;
use std::path::Path;
use std::sync::LazyLock;

use bc_model::{Actor, Chunk, ChunkSize, ContextPackage, ControlKind, EntryPointKind};
use regex::Regex;

use crate::grouping::cohesive_groups;
use crate::pack::{char_budget, pack};
use crate::Step3Config;
use bc_repo_analysis::is_source;

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

/// Literal credential/key values in source and config: an assignment or
/// YAML colon to a security-sensitive key with a non-placeholder quoted
/// value (not a `${...}` reference), an equality comparison against a
/// password/username literal, or a quoted dict/JSON key. Upstream's
/// `(?!\s*\$\{)` lookahead has no `regex`-crate equivalent, so the value is
/// captured and the placeholder check applied in code
/// ([`has_hardcoded_credential`]); every other alternative is verbatim.
static HARDCODED_CREDS_RX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(?:(?:SECRET_KEY|password|passwd|api[_-]?key|access[_-]?key|secret[_-]?key|auth[_-]?token|jwt[_-]?secret|signing[_-]?key|private[_-]?key|encryption[_-]?key|database[_-]?url|connection[_-]?string)\s*[=:]\s*['"](?P<v1>[^'"]{4,})|(?:password|passwd|username)\s*==\s*['"][^'"]{3,}['"]|['"](?:password|passwd|secret[_-]?key)['"]\s*:\s*['"](?P<v2>[^'"]{4,}))"#,
    )
    .unwrap()
});

static PLACEHOLDER_VALUE_RX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\s*\$\{").unwrap());

/// CSRF-relevant framework patterns (token middleware, exemptions, and
/// state-changing route annotations).
static CSRF_RX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)\b(csrf_exempt|CsrfViewMiddleware|CSRFProtect|csrf\.exempt|csurf|csrf_token|protect_from_forgery|verify_authenticity_token|@csrf|HttpPost|@PostMapping|@PutMapping|@DeleteMapping|request\.method\s*==\s*['"]POST['"]|csrf\.disable\(\))"#,
    )
    .unwrap()
});

/// Presence-only gate for the `injection` lens, one alternative per sink
/// family: S4 still has to prove attacker flow and missing defences.
/// Transcribed from upstream's `_INJECTION_FAMILY_PATTERNS` and joined the
/// same way (`|` of `(?:...)` groups, case-insensitive).
const INJECTION_FAMILY_PATTERNS: &[&str] = &[
    // sql-nosql
    r"\.(?:execute|executemany|executeQuery|executeUpdate|prepareStatement|createQuery|createNativeQuery)\s*\(|\b(?:JdbcTemplate|NamedParameterJdbcTemplate)\s*\.\s*(?:query|update|execute|queryForObject|queryForList)\s*\(|\b(?:session|db|Sequelize|knex)\s*\.\s*(?:query|raw)\s*\(|\$(?:queryRaw|queryRawUnsafe|executeRaw|executeRawUnsafe|where|function)\b|\.(?:aggregate|extra)\s*\(|\b(?:mysqli_query|pg_query|mysql_query|find_by_sql)\s*\(|\b(?:GraphDatabaseService\.execute|Neo4j\w*\.run)\s*\(",
    // command-code
    r"\bsubprocess\.(?:run|Popen|call|check_call|check_output)\s*\(|\bos\.(?:system|popen|exec\w*)\s*\(|\bRuntime\.getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(|\b(?:ProcessBuilder|Process\.Start|exec\.Command(?:Context)?)\s*\(|\bchild_process\.(?:exec|execSync|spawn)\s*\(|\b(?:shell_exec|passthru|proc_open|popen)\s*\(|\bOpen3\.(?:capture\w*|popen\w*)\s*\(|\b(?:eval|setTimeout|setInterval)\s*\(|\bnew\s+Function\s*\(|\b(?:GroovyShell|ScriptEngine)\w*\.\w*eval\w*\s*\(|\bshell\s*=\s*True\b",
    // ldap-xpath-xml
    r"\b(?:InitialDirContext|LdapContext|DirContext)\w*\.search\s*\(|\b(?:ldap\.(?:search|search_s)|Connection\.search)\s*\(|\b(?:XPathFactory|XPathExpression|XPath)\b|\.(?:xpath|selectSingleNode|selectNodes)\s*\(|\b(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory|SchemaFactory|XMLReader|DOMParser|XmlReader|XmlDocument|Nokogiri::XML|lxml\.etree)\b|\betree\.(?:parse|fromstring|XMLParser|XPath)\s*\(|\bresolve_entities\b",
    // ssrf
    r"\b(?:requests|httpx)\.(?:get|post|put|delete|request)\s*\(|\b(?:urllib\.request|urllib3|http\.client|aiohttp\.ClientSession)\b|\b(?:RestTemplate|WebClient|HttpClient|HttpURLConnection|OkHttpClient|GuzzleHttp|Net::HTTP|reqwest|ureq)\b|\b(?:fetch|urlopen|file_get_contents|curl_exec)\s*\(|\bCURLOPT_URL\b|\bhttp\.(?:Get|Post|NewRequest)\s*\(|\bClient\.Do\s*\(|\baxios\.\w+\s*\(|\.openConnection\s*\(",
    // path-archive
    r"\b(?:java\.io\.File|Paths\.get|Path\.of|pathlib\.Path)\s*\(|\bFiles\.(?:newInputStream|newOutputStream|readAllBytes|readString|write)\s*\(|\bos\.path\.(?:join|abspath|realpath)\s*\(|\bfs\.(?:readFile|readFileSync|writeFile|createReadStream|createWriteStream)\s*\(|\b(?:sendFile|send_from_directory|fopen|unpack_archive)\s*\(|\b(?:ZipFile|TarFile)\.(?:extract|extractall)\s*\(|\b(?:ZipInputStream|TarArchiveInputStream)\b|\bextractall\s*\(",
    // template-xss
    r"\b(?:render_template_string|mark_safe|bypassSecurityTrustHtml)\s*\(|\bEnvironment\.from_string\s*\(|\b(?:Mako\w*\.)?Template\s*\(|\b(?:Velocity\.(?:evaluate|eval)|SpelExpressionParser|parseExpression|Ognl\.(?:getValue|setValue)|JexlEngine|createExpression|ELProcessor\.eval|ERB\.new|Handlebars\.compile|Mustache\.compile)\b|\b(?:innerHTML|outerHTML|dangerouslySetInnerHTML|html_safe)\b|\b(?:insertAdjacentHTML|document\.(?:write|writeln))\s*\(|\b(?:res\.(?:send|write|end)|Response\.Write)\s*\(",
    // redirect-header
    r"\b(?:sendRedirect|redirect_to|Response\.Redirect)\s*\(|\b(?:res\.)?redirect\s*\(|\bRedirectView\s*\(|\b(?:setHeader|addHeader|headers\.set|Headers\.Add|set_cookie)\s*\(",
    // regex
    r"\b(?:re|Pattern|Regex|regexp)\.(?:compile|Compile|MustCompile|new)\s*\(|\bnew\s+(?:RegExp|Regex)\s*\(",
];

static INJECTION_RX: LazyLock<Regex> = LazyLock::new(|| {
    let joined: Vec<String> = INJECTION_FAMILY_PATTERNS
        .iter()
        .map(|p| format!("(?:{p})"))
        .collect();
    Regex::new(&format!("(?i){}", joined.join("|"))).unwrap()
});

/// Whether `text` holds a hardcoded credential by [`HARDCODED_CREDS_RX`],
/// skipping an assignment whose value is a `${...}` placeholder (the
/// upstream lookahead, applied per match).
fn has_hardcoded_credential(text: &str) -> bool {
    HARDCODED_CREDS_RX.captures_iter(text).any(|caps| {
        match caps.name("v1").or_else(|| caps.name("v2")) {
            Some(value) => !PLACEHOLDER_VALUE_RX.is_match(value.as_str()),
            None => true,
        }
    })
}

/// Largest prefix of one file a content gate reads. The walk already caps
/// files at `step1.max_file_kb` (1 MiB by default); this bound keeps the
/// gate itself bounded even for a context built some other way.
const GATE_READ_LIMIT: u64 = 4 * 1024 * 1024;

/// One file's text for the content gates: confined to `repo_root` (the
/// file list is repo-derived, but a `../` entry must never be read) and
/// capped at [`GATE_READ_LIMIT`]. `None` for anything unreadable, which
/// the gates skip, matching upstream's `except OSError: continue`.
fn read_for_gate(repo_root: &Path, rel: &str) -> Option<String> {
    let path = bc_pathjail::confine(repo_root, rel)?;
    let file = std::fs::File::open(path).ok()?;
    let mut bytes = Vec::new();
    file.take(GATE_READ_LIMIT).read_to_end(&mut bytes).ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// A content test one lens gate needs answered over the source files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Probe {
    Crypto,
    Deser,
    BatchEtl,
    HardcodedCreds,
    Csrf,
    Injection,
}

impl Probe {
    fn matches(self, text: &str) -> bool {
        match self {
            Probe::Crypto => CRYPTO_RX.is_match(text),
            Probe::Deser => DESER_RX.is_match(text),
            Probe::BatchEtl => BATCH_ETL_RX.is_match(text),
            Probe::HardcodedCreds => has_hardcoded_credential(text),
            Probe::Csrf => CSRF_RX.is_match(text),
            Probe::Injection => INJECTION_RX.is_match(text),
        }
    }
}

/// Answers every requested probe in ONE pass over `files`: each file is
/// read once and tested against the probes still unanswered, stopping as
/// soon as all are answered. Upstream re-reads the whole source tree once
/// per content-gated lens (six passes with the default lens list); the
/// verdicts are identical, the I/O is not.
fn scan_probes(repo_root: &Path, files: &[String], probes: &HashSet<Probe>) -> HashSet<Probe> {
    let mut found: HashSet<Probe> = HashSet::new();
    if probes.is_empty() {
        return found;
    }
    for rel in files {
        let Some(text) = read_for_gate(repo_root, rel) else {
            continue;
        };
        for probe in probes {
            if !found.contains(probe) && probe.matches(&text) {
                found.insert(*probe);
            }
        }
        if found.len() == probes.len() {
            break;
        }
    }
    found
}

fn has_batch_surface_without_content(ctx: &ContextPackage, repo_root: &Path) -> bool {
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
    langs.contains("cobol") || langs.contains("jcl")
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

/// How one lens decides whether its surface exists: a structural answer
/// that needs no file content, or a content probe (optionally preceded by
/// a structural shortcut that makes the probe unnecessary).
enum Gate {
    Always,
    Structural(bool),
    Content { shortcut: bool, probe: Probe },
}

fn gate_for(spec: &str, ctx: &ContextPackage, repo_root: &Path) -> Gate {
    match spec {
        "access-control" => Gate::Structural(has_authz_surface(ctx)),
        "iac" => Gate::Structural(
            ctx.all_files
                .iter()
                .any(|f| bc_repo_analysis::is_iac_file(f)),
        ),
        // Always on for any app with entry points; cost is proportional
        // to LOC, so no surface-specific gate is needed.
        "sensitive-data" | "log-injection" => Gate::Structural(!ctx.entry_points.is_empty()),
        "crypto" => Gate::Content {
            shortcut: false,
            probe: Probe::Crypto,
        },
        "deserialization" => Gate::Content {
            shortcut: false,
            probe: Probe::Deser,
        },
        "batch-etl" => Gate::Content {
            shortcut: has_batch_surface_without_content(ctx, repo_root),
            probe: Probe::BatchEtl,
        },
        // Only when literal credential values are actually present, so a
        // pure-IaC or generated-code repo does not pay for the pass.
        "hardcoded-creds" => Gate::Content {
            shortcut: false,
            probe: Probe::HardcodedCreds,
        },
        // Web-framework routing or explicit CSRF markers, so a non-web
        // repo does not get this pass.
        "csrf" => Gate::Content {
            shortcut: has_authz_surface(ctx),
            probe: Probe::Csrf,
        },
        // At least one injection-family sink. Broad by design: most web
        // and CLI apps carry one.
        "injection" => Gate::Content {
            shortcut: false,
            probe: Probe::Injection,
        },
        _ => Gate::Always,
    }
}

/// Drop specialist passes whose target surface doesn't exist in this repo,
/// so S4/S5/S6 don't burn budget verifying guaranteed-false-positive
/// findings. A specialist name with no gate in the table (e.g.
/// `"logic-bug"`) is always kept. Returns `(kept, gated_off)`, both in
/// `enabled` order.
fn gate_specialists(
    enabled: &[String],
    ctx: &ContextPackage,
    source: &[String],
) -> (Vec<String>, Vec<String>) {
    let repo_root = Path::new(&ctx.repo_root);
    let gates: Vec<(&String, Gate)> = enabled
        .iter()
        .map(|spec| (spec, gate_for(spec, ctx, repo_root)))
        .collect();
    let probes: HashSet<Probe> = gates
        .iter()
        .filter_map(|(_, g)| match g {
            Gate::Content {
                shortcut: false,
                probe,
            } => Some(*probe),
            _ => None,
        })
        .collect();
    let found = scan_probes(repo_root, source, &probes);
    let mut kept = Vec::new();
    let mut gated_off = Vec::new();
    for (spec, gate) in gates {
        let on = match gate {
            Gate::Always => true,
            Gate::Structural(on) => on,
            Gate::Content { shortcut, probe } => shortcut || found.contains(&probe),
        };
        if on {
            kept.push(spec.clone());
        } else {
            gated_off.push(spec.clone());
        }
    }
    (kept, gated_off)
}

fn size_for(loc: i64) -> ChunkSize {
    bc_repo_analysis::size_for(loc.max(0) as usize)
}

/// Best-effort method anchors for one specialist shard, ported from
/// `s3_decompose.py::_specialist_focus_entry_points`.
///
/// Picks bare function names from `call_graph_files` that have a
/// def-site in this shard's own file set, capped at [`FOCUS_CAP`]. S4
/// uses them to prioritize which spans to load — without them a
/// specialist shard reaches `load_sliding_window` with nothing to anchor
/// on and falls all the way through to blind whole-file tiling, which is
/// exactly the case sharding exists to avoid. Computed once per shard
/// (shared by every lens), not once per lens per shard.
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

/// One shared bucket every lens in a pass reviews: its label, files, LOC,
/// the languages and focus anchors derived from it once, and its
/// `shard_id`.
struct Shard {
    index: usize,
    shard_id: String,
    label: String,
    files: Vec<String>,
    loc: i64,
    languages: Vec<String>,
    focus: Vec<String>,
}

fn shards_for(
    files: &[String],
    id_prefix: &str,
    ctx: &ContextPackage,
    config: &Step3Config,
) -> Vec<Shard> {
    let repo_root = Path::new(&ctx.repo_root);
    pack(
        &cohesive_groups(files, ctx, config.max_cohesion_groups()),
        repo_root,
        config.specialist_chunk_loc,
        config.max_files_per_chunk,
        char_budget(config),
        config.pack_merge_underfilled,
    )
    .into_iter()
    .enumerate()
    .map(|(i, (label, files, loc))| Shard {
        index: i + 1,
        shard_id: format!("{id_prefix}-{:02}", i + 1),
        languages: bc_repo_analysis::detect_languages(&files, Some(repo_root))
            .into_iter()
            .map(String::from)
            .collect(),
        focus: specialist_focus_entry_points(&files, ctx),
        label,
        files,
        loc,
    })
    .collect()
}

fn mk_specialist(spec: &str, shard: &Shard, rank: i64) -> Chunk {
    Chunk {
        id: format!("spec-{spec}-{:02}", shard.index),
        size: size_for(shard.loc),
        risk_rank: rank,
        files: shard.files.clone(),
        focus_entry_points: shard.focus.clone(),
        hypothesis: format!("{spec} specialist sweep over module '{}'.", shard.label),
        related_cves: Vec::new(),
        threat_id: None,
        languages: shard.languages.clone(),
        specialist: Some(spec.to_string()),
        path_funcs: Vec::new(),
        source_ref: String::new(),
        sink_ref: String::new(),
        sink_cwe: Vec::new(),
        shard_id: shard.shard_id.clone(),
    }
}

/// What the specialist pass produced, plus the lenses its surface gates
/// switched off (for the run's diagnostics).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SpecialistResult {
    pub chunks: Vec<Chunk>,
    pub gated_off: Vec<String>,
}

/// Append repo-wide specialist passes. These see ALL source files
/// regardless of risk-ranking — they hunt for cross-cutting bug classes
/// that per-chunk language researchers miss. Sharding is module-aware
/// (via [`cohesive_groups`]) and restricted to actual source files; `iac`
/// narrows to its own IaC-only buckets. Returns the new chunks (appended to
/// the manifest by the caller) in shard-major order.
pub fn add_specialist_chunks(
    existing_chunks: &[Chunk],
    ctx: &ContextPackage,
    config: &Step3Config,
) -> SpecialistResult {
    let source: Vec<String> = ctx
        .all_files
        .iter()
        .filter(|f| is_source(f))
        .cloned()
        .collect();
    let (enabled, gated_off) = gate_specialists(&config.specialists, ctx, &source);
    if enabled.is_empty() || source.is_empty() {
        return SpecialistResult {
            chunks: Vec::new(),
            gated_off,
        };
    }

    let base_rank = existing_chunks
        .iter()
        .map(|c| c.risk_rank)
        .max()
        .unwrap_or(0);
    let mut out: Vec<Chunk> = Vec::new();

    let unscoped: Vec<&String> = enabled.iter().filter(|s| s.as_str() != "iac").collect();
    if !unscoped.is_empty() {
        for shard in shards_for(&source, "shard", ctx, config) {
            for spec in &unscoped {
                let rank = base_rank + out.len() as i64 + 1;
                out.push(mk_specialist(spec, &shard, rank));
            }
        }
    }

    if enabled.iter().any(|s| s == "iac") {
        // Never empty when we get here: `is_source` returns true for every
        // `is_iac_file` match (it is the last check in that cascade), so
        // "iac" surviving the "any IaC file in `ctx.all_files`" gate
        // guarantees at least one of those files is also in `source`.
        let iac_source: Vec<String> = source
            .iter()
            .filter(|f| bc_repo_analysis::is_iac_file(f))
            .cloned()
            .collect();
        for shard in shards_for(&iac_source, "iac-shard", ctx, config) {
            let rank = base_rank + out.len() as i64 + 1;
            out.push(mk_specialist("iac", &shard, rank));
        }
    }

    SpecialistResult {
        chunks: out,
        gated_off,
    }
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
    fn scan_probes_skips_an_unreadable_file_and_keeps_scanning() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "b.py", "cipher = AES.new(key)\n");
        let files = vec![
            "missing.py".to_string(),
            "../escape.py".to_string(),
            "b.py".to_string(),
        ];
        let probes = HashSet::from([Probe::Crypto]);
        assert_eq!(scan_probes(dir.path(), &files, &probes), probes);
    }

    #[test]
    fn scan_probes_stops_once_every_probe_is_answered() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "a.py",
            "cipher = AES.new(key)\npickle.loads(x)\n",
        );
        write(dir.path(), "b.py", "os.system(cmd)\n");
        let files = vec!["a.py".to_string(), "b.py".to_string()];
        let probes = HashSet::from([Probe::Crypto, Probe::Deser]);
        assert_eq!(scan_probes(dir.path(), &files, &probes), probes);
        // A probe nothing matches leaves the scan running to the end.
        let probes = HashSet::from([Probe::Crypto, Probe::Csrf]);
        assert_eq!(
            scan_probes(dir.path(), &files, &probes),
            HashSet::from([Probe::Crypto])
        );
        assert!(scan_probes(dir.path(), &files, &HashSet::new()).is_empty());
    }

    #[test]
    fn gate_specialists_keeps_logic_bug_unconditionally() {
        let ctx = ctx_with_root(Path::new("/repo"));
        let enabled = vec!["logic-bug".to_string()];
        assert_eq!(gate_specialists(&enabled, &ctx, &[]).0, enabled);
    }

    #[test]
    fn gate_specialists_drops_crypto_with_no_matching_content() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.py", "print('hello')\n");
        let ctx = ctx_with_root(dir.path());
        let enabled = vec!["crypto".to_string()];
        assert!(gate_specialists(&enabled, &ctx, &["a.py".to_string()])
            .0
            .is_empty());
    }

    #[test]
    fn gate_specialists_keeps_crypto_with_matching_content() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.py", "cipher = AES.new(key)\n");
        let ctx = ctx_with_root(dir.path());
        let enabled = vec!["crypto".to_string()];
        assert_eq!(
            gate_specialists(&enabled, &ctx, &["a.py".to_string()]).0,
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
            gate_specialists(&enabled, &ctx, &["a.py".to_string()]).0,
            enabled
        );
        assert_eq!(
            gate_specialists(&enabled, &ctx, &["b.py".to_string()]).0,
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
        assert_eq!(gate_specialists(&enabled, &ctx, &[]).0, enabled);
    }

    #[test]
    fn gate_specialists_keeps_batch_etl_from_cobol_language() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.cbl", "IDENTIFICATION DIVISION.\n");
        let mut ctx = ctx_with_root(dir.path());
        ctx.all_files = vec!["a.cbl".to_string()];
        let enabled = vec!["batch-etl".to_string()];
        assert_eq!(
            gate_specialists(&enabled, &ctx, &["a.cbl".to_string()]).0,
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
            gate_specialists(&enabled, &ctx, &["a.py".to_string()]).0,
            enabled
        );
    }

    #[test]
    fn gate_specialists_iac_gated_by_repo_wide_all_files_not_just_source() {
        let mut ctx = ctx_with_root(Path::new("/repo"));
        ctx.all_files = vec!["Dockerfile".to_string()];
        let enabled = vec!["iac".to_string()];
        assert_eq!(gate_specialists(&enabled, &ctx, &[]).0, enabled);
    }

    #[test]
    fn gate_specialists_drops_iac_with_no_iac_files_anywhere() {
        let mut ctx = ctx_with_root(Path::new("/repo"));
        ctx.all_files = vec!["a.py".to_string()];
        let enabled = vec!["iac".to_string()];
        assert!(gate_specialists(&enabled, &ctx, &[]).0.is_empty());
    }

    #[test]
    fn add_specialist_chunks_empty_when_nothing_enabled() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.py", "print(1)\n");
        let mut ctx = ctx_with_root(dir.path());
        ctx.all_files = vec!["a.py".to_string()];
        let mut cfg = Step3Config::new("m");
        cfg.specialists = vec!["crypto".to_string()];
        assert!(add_specialist_chunks(&[], &ctx, &cfg).chunks.is_empty());
    }

    #[test]
    fn add_specialist_chunks_builds_chunks_ranked_above_existing() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.py", "print(1)\n");
        let mut ctx = ctx_with_root(dir.path());
        ctx.all_files = vec!["a.py".to_string()];
        let mut cfg = Step3Config::new("m");
        cfg.specialists = vec!["logic-bug".to_string()];
        let out = add_specialist_chunks(&[], &ctx, &cfg).chunks;
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
        let out = add_specialist_chunks(&[], &ctx, &cfg).chunks;
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
        let out = add_specialist_chunks(&[], &ctx, &cfg).chunks;
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
        let before = add_specialist_chunks(&[], &ctx, &cfg).chunks;
        cfg.pack_merge_underfilled = true;
        let after = add_specialist_chunks(&[], &ctx, &cfg).chunks;

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

    // ── shard-major emission (upstream v1.3) ─────────────────────────────

    /// Three directories, each its own cohesion group, with specialist
    /// packing forced to one file per shard.
    fn three_shard_ctx(dir: &Path) -> (ContextPackage, Step3Config) {
        for d in ["a", "b", "c"] {
            std::fs::create_dir_all(dir.join(d)).unwrap();
            write(dir, &format!("{d}/m.py"), "cipher = AES.new(key)\n");
        }
        write(dir, "Dockerfile", "FROM scratch\n");
        let mut ctx = ctx_with_root(dir);
        ctx.all_files = vec![
            "a/m.py".to_string(),
            "b/m.py".to_string(),
            "c/m.py".to_string(),
            "Dockerfile".to_string(),
        ];
        let mut cfg = Step3Config::new("m");
        cfg.max_files_per_chunk = 1;
        cfg.specialists = vec![
            "crypto".to_string(),
            "logic-bug".to_string(),
            "iac".to_string(),
        ];
        (ctx, cfg)
    }

    #[test]
    fn unscoped_lenses_are_emitted_shard_major_with_a_shard_id() {
        let dir = tempfile::tempdir().unwrap();
        let (ctx, cfg) = three_shard_ctx(dir.path());
        let out = add_specialist_chunks(&[], &ctx, &cfg).chunks;
        let seq: Vec<(&str, &str)> = out
            .iter()
            .map(|c| (c.id.as_str(), c.shard_id.as_str()))
            .collect();
        assert_eq!(
            seq,
            vec![
                ("spec-crypto-01", "shard-01"),
                ("spec-logic-bug-01", "shard-01"),
                ("spec-crypto-02", "shard-02"),
                ("spec-logic-bug-02", "shard-02"),
                ("spec-crypto-03", "shard-03"),
                ("spec-logic-bug-03", "shard-03"),
                ("spec-crypto-04", "shard-04"),
                ("spec-logic-bug-04", "shard-04"),
                ("spec-iac-01", "iac-shard-01"),
            ]
        );
        // Ranks keep counting across the whole pass.
        let ranks: Vec<i64> = out.iter().map(|c| c.risk_rank).collect();
        assert_eq!(ranks, (1..=9).collect::<Vec<i64>>());
        // Every lens on one shard reviews byte-for-byte the same files.
        for pair in out[..8].chunks(2) {
            assert_eq!(pair[0].files, pair[1].files);
            assert_eq!(pair[0].languages, pair[1].languages);
        }
    }

    #[test]
    fn shard_major_order_does_not_change_any_lens_file_set() {
        let dir = tempfile::tempdir().unwrap();
        let (ctx, cfg) = three_shard_ctx(dir.path());
        let out = add_specialist_chunks(&[], &ctx, &cfg).chunks;
        let files_of = |lens: &str| -> Vec<String> {
            out.iter()
                .filter(|c| c.specialist.as_deref() == Some(lens))
                .flat_map(|c| c.files.clone())
                .collect()
        };
        let mut source: Vec<String> = ctx.all_files.clone();
        source.sort();
        assert_eq!(files_of("crypto"), source);
        assert_eq!(files_of("logic-bug"), source);
        assert_eq!(files_of("iac"), vec!["Dockerfile".to_string()]);
    }

    #[test]
    fn an_iac_only_lens_list_emits_no_default_shards() {
        let dir = tempfile::tempdir().unwrap();
        let (ctx, mut cfg) = three_shard_ctx(dir.path());
        cfg.specialists = vec!["iac".to_string()];
        let out = add_specialist_chunks(&[], &ctx, &cfg).chunks;
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].shard_id, "iac-shard-01");
    }

    #[test]
    fn gated_off_lenses_are_reported_in_configured_order() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.py", "print(1)\n");
        let mut ctx = ctx_with_root(dir.path());
        ctx.all_files = vec!["a.py".to_string()];
        let mut cfg = Step3Config::new("m");
        cfg.specialists = vec![
            "csrf".to_string(),
            "logic-bug".to_string(),
            "crypto".to_string(),
        ];
        let result = add_specialist_chunks(&[], &ctx, &cfg);
        assert_eq!(
            result.gated_off,
            vec!["csrf".to_string(), "crypto".to_string()]
        );
        assert_eq!(result.chunks.len(), 1);
        // Nothing enabled at all still reports what was gated.
        cfg.specialists = vec!["crypto".to_string()];
        let result = add_specialist_chunks(&[], &ctx, &cfg);
        assert!(result.chunks.is_empty());
        assert_eq!(result.gated_off, vec!["crypto".to_string()]);
    }

    // ── the five v1.3 lens gates ──────────────────────────────────────────

    fn gate_one(lens: &str, body: &str, entry_points: bool) -> bool {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.py", body);
        let mut ctx = ctx_with_root(dir.path());
        if entry_points {
            ctx.entry_points = vec![EntryPoint {
                file: "a.py".to_string(),
                function: "main".to_string(),
                kind: EntryPointKind::Cli,
                reachable_from_unauth: false,
            }];
        }
        let enabled = vec![lens.to_string()];
        !gate_specialists(&enabled, &ctx, &["a.py".to_string()])
            .0
            .is_empty()
    }

    #[test]
    fn hardcoded_creds_gate_needs_a_literal_not_a_placeholder() {
        assert!(gate_one(
            "hardcoded-creds",
            "SECRET_KEY = 'abcd1234'\n",
            false
        ));
        assert!(gate_one(
            "hardcoded-creds",
            "db_password: \"hunter22\"\n",
            false
        ));
        assert!(gate_one(
            "hardcoded-creds",
            "if password == 'admin':\n",
            false
        ));
        assert!(gate_one(
            "hardcoded-creds",
            "{'password': 'admin123'}\n",
            false
        ));
        assert!(!gate_one(
            "hardcoded-creds",
            "password = '${DB_PASSWORD}'\n",
            false
        ));
        assert!(!gate_one(
            "hardcoded-creds",
            "'secret_key': \" ${KEY}\"\n",
            false
        ));
        assert!(!gate_one(
            "hardcoded-creds",
            "password = os.environ['PW']\n",
            false
        ));
        // A placeholder first does not hide a real literal later on.
        assert!(gate_one(
            "hardcoded-creds",
            "password = '${PW}'\napi_key = 'sk-live-123'\n",
            false
        ));
    }

    #[test]
    fn csrf_gate_opens_on_a_web_surface_or_on_csrf_markers() {
        assert!(gate_one("csrf", "@csrf_exempt\ndef view(r): pass\n", false));
        assert!(gate_one("csrf", "if request.method == 'POST':\n", false));
        assert!(!gate_one("csrf", "print(1)\n", false));
        // A network entry point is an authz surface, which opens it alone.
        let mut ctx = ctx_with_root(Path::new("/nonexistent"));
        ctx.entry_points = vec![EntryPoint {
            file: "a.py".to_string(),
            function: "h".to_string(),
            kind: EntryPointKind::Network,
            reachable_from_unauth: false,
        }];
        let enabled = vec!["csrf".to_string()];
        assert_eq!(gate_specialists(&enabled, &ctx, &[]).0, enabled);
    }

    #[test]
    fn injection_gate_opens_on_any_injection_family_sink() {
        for body in [
            "cursor.execute(q)\n",
            "subprocess.run(cmd, shell=True)\n",
            "etree.fromstring(x)\n",
            "requests.get(url)\n",
            "open(os.path.join(a, b))\n",
            "render_template_string(t)\n",
            "return redirect(url)\n",
            "re.compile(pattern)\n",
            "EVAL(x)\n",
        ] {
            assert!(gate_one("injection", body, false), "{body}");
        }
        assert!(!gate_one("injection", "x = 1 + 2\n", false));
    }

    #[test]
    fn sensitive_data_and_log_injection_gate_on_entry_points() {
        for lens in ["sensitive-data", "log-injection"] {
            assert!(gate_one(lens, "x = 1\n", true), "{lens}");
            assert!(!gate_one(lens, "x = 1\n", false), "{lens}");
        }
    }

    #[test]
    fn batch_etl_content_probe_is_skipped_when_a_structural_signal_exists() {
        // The shortcut decides; the probe set stays empty.
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.py", "print(1)\n");
        let mut ctx = ctx_with_root(dir.path());
        ctx.entry_points = vec![EntryPoint {
            file: "a.py".to_string(),
            function: "main".to_string(),
            kind: EntryPointKind::Cli,
            reachable_from_unauth: false,
        }];
        let enabled = vec!["batch-etl".to_string()];
        assert_eq!(
            gate_specialists(&enabled, &ctx, &["a.py".to_string()]).0,
            enabled
        );
    }

    #[test]
    fn the_default_lens_list_gates_every_lens_in_one_pass() {
        // Smoke test over the full default list on a small web app: every
        // content-gated lens that has a matching surface stays on.
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "app.py",
            "pickle.loads(b)\nos.listdir(d)\n@csrf_exempt\ndef h(r):\n    cursor.execute(r.q)\n    \
             SECRET_KEY = 'abcdefgh'\n    return AES.new(k)\n",
        );
        let mut ctx = ctx_with_root(dir.path());
        ctx.all_files = vec!["app.py".to_string()];
        ctx.entry_points = vec![EntryPoint {
            file: "app.py".to_string(),
            function: "h".to_string(),
            kind: EntryPointKind::Network,
            reachable_from_unauth: true,
        }];
        let cfg = Step3Config::new("m");
        let result = add_specialist_chunks(&[], &ctx, &cfg);
        assert_eq!(result.gated_off, vec!["iac".to_string()]);
        let lenses: Vec<&str> = result
            .chunks
            .iter()
            .filter_map(|c| c.specialist.as_deref())
            .collect();
        assert_eq!(
            lenses,
            vec![
                "crypto",
                "logic-bug",
                "access-control",
                "batch-etl",
                "deserialization",
                "csrf",
                "sensitive-data",
                "hardcoded-creds",
                "log-injection",
                "injection",
            ]
        );
    }

    #[test]
    fn gate_reads_are_confined_and_bounded() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_for_gate(dir.path(), "../../etc/passwd").is_none());
        let big = "x".repeat((GATE_READ_LIMIT + 10) as usize);
        write(dir.path(), "big.py", &big);
        assert_eq!(
            read_for_gate(dir.path(), "big.py").unwrap().len() as u64,
            GATE_READ_LIMIT
        );
    }
}
