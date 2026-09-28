// Portions of this file are transcribed from vvaharness, Visa's agentic
// SAST harness: Copyright 2026 Visa, Inc., licensed under the Apache
// License, Version 2.0. Reimplemented in Rust and modified; see the module
// documentation below, and NOTICE for the full attribution.
//! Optional LLM-derived step1 exclusion overlay, ported from
//! `s1_autoexclude.py`: survey the repo (directory tree, extension
//! histogram, largest files, README/build-file excerpts) and ask the
//! model for ADDITIONAL non-production exclusions beyond what's already
//! configured — written as an overlay a caller layers onto `step1`
//! before S1 actually runs.
//!
//! The survey here is built from [`bc_repo_analysis::walk_repo`]'s own
//! already-exclusion-respecting output rather than a second, independent
//! walk the way Python's `_survey()` re-derives its own exclusion
//! predicate — one walk, guaranteed consistent with what S1 itself will
//! see, instead of two that could theoretically disagree.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use bc_llm_client::{ChatRequest, LlmClient, LlmError, Message};
use bc_repo_analysis::{suffix_lower, walk_repo, WalkConfig};
use serde_json::Value;

/// Upstream v1.3's expanded triage prompt: explicit EXCLUDE and NEVER
/// EXCLUDE category lists instead of one example sentence each.
const SYSTEM: &str = r#"You are a build/scan triage agent. You will be shown a deterministic survey of
a source tree (directory layout, file counts, extension histogram, and excerpts
from build/README files). Decide which parts are NOT production code so a
security scanner can skip them.

EXCLUDE these categories:
- Generated/auto-generated code: protobuf stubs, OpenAPI clients, code-gen
  output, compiled assets, *.pb.go, *.generated.*, *_pb2.py
- Vendored/third-party copies: vendor/, third_party/, node_modules/ (if checked
  in), bower_components/, external/
- Test-only trees: test fixtures, sample data, mock servers, e2e test suites,
  cypress/fixtures, __snapshots__
- IDE/editor metadata: .idea/, .vscode/ (except shared settings), .vs/,
  *.swp, *~
- Build/CI output: dist/, build/, out/, target/, bin/ (compiled output),
  .cache/, coverage/
- Documentation-only trees: docs/, documentation/, wiki/, man/, guides/
- Demo/example apps: examples/, samples/, demo/, playground/, tutorial/
- Data dumps: fixtures with large data files, seed data, migration SQL dumps,
  database backups
- Localisation bundles: locale/, i18n/, l10n/, translations/ (unless they
  contain code)
- Lock files and manifests that are not source: package-lock.json, yarn.lock,
  Gemfile.lock, poetry.lock, go.sum, Cargo.lock

NEVER EXCLUDE — these are in scope even if they look non-functional:
- Application source code in ANY language
- Configuration files that affect runtime behavior (nginx.conf, app.yaml,
  settings.py, application.properties, .env.example)
- Infrastructure-as-code that provisions production (Terraform, CloudFormation,
  Helm charts, Kubernetes manifests, Ansible playbooks, Dockerfiles)
- Database migration scripts (they modify production schema)
- API schema definitions (OpenAPI/Swagger YAML, GraphQL SDL, protobuf .proto
  source files — NOT generated stubs)
- Security-related files (auth middleware, RBAC config, certificate handling)
- Shared libraries or internal packages (even if they look like vendor code,
  if they are maintained in this repo they are production)

When unsure whether something is production code, do NOT exclude it. A false
negative (scanning non-production code) wastes time; a false positive
(excluding production code) misses vulnerabilities.

You MUST reply with a single fenced ```yaml block and nothing else."#;

/// Below this fraction of the pre-overlay scope surviving, the overlay is
/// reported as aggressive. A reporting threshold only, never a rejection
/// bar: only a fully emptied scope is unambiguously wrong.
const AGGRESSIVE_KEEP_RATIO: f64 = 0.10;

const EXCERPT_NAMES: &[&str] = &[
    "readme",
    "package.json",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "setup.py",
    "setup.cfg",
    "pyproject.toml",
    "cargo.toml",
    "go.mod",
    "makefile",
    "dockerfile",
    "composer.json",
    "gemfile",
    "angular.json",
    "lerna.json",
    "nx.json",
    "turbo.json",
];
const EXCERPT_CHARS: usize = 1500;
const EXCERPT_MAX: usize = 12;
const TREE_DEPTH: usize = 2;
const TREE_MAX_CHILDREN: usize = 60;
const EXT_TOP_N: usize = 40;
const LARGEST_N: usize = 15;

/// A repo-specific exclusion addition the model proposed, already
/// filtered against what's already excluded — apply by appending onto
/// the caller's own `step1` config (lists append; `max_file_kb`/
/// `config_dedup` replace only when the model actually proposed a
/// change).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct AutoExcludeOverlay {
    pub exclude_dirs: Vec<String>,
    pub exclude_exts: Vec<String>,
    pub exclude_globs: Vec<String>,
    pub max_file_kb: Option<u64>,
    pub config_dedup: BTreeMap<String, Value>,
}

impl AutoExcludeOverlay {
    /// Rendered exactly as `s1_autoexclude.py::run`'s own `out.write_text`
    /// — a header comment plus the YAML body — so the file is the same
    /// inspectable, `--resume`-detectable artifact Python produces.
    ///
    /// `bc-yaml` is parse-only (no writer — see that crate's own doc
    /// comment on why this project doesn't depend on `serde_yaml`), so
    /// this hand-writes the small, fixed shape this ONE overlay format
    /// needs, matching PyYAML's `safe_dump(..., default_flow_style=False)`
    /// output for it: block-style lists (one `- item` per line, `[]` for
    /// an empty one — a block sequence has no way to represent "empty"
    /// without falling back to flow style), scalars/nested maps inline.
    pub fn to_yaml(&self) -> String {
        let mut out =
            String::from("# Auto-generated by bc-sast auto-step1 — appended to global step1.\n");
        write_yaml_list(&mut out, "exclude_dirs", &self.exclude_dirs);
        write_yaml_list(&mut out, "exclude_exts", &self.exclude_exts);
        write_yaml_list(&mut out, "exclude_globs", &self.exclude_globs);
        if let Some(kb) = self.max_file_kb {
            out.push_str(&format!("max_file_kb: {kb}\n"));
        }
        if !self.config_dedup.is_empty() {
            out.push_str("config_dedup:\n");
            for (k, v) in &self.config_dedup {
                out.push_str(&format!("  {k}: {}\n", yaml_scalar_or_flow(v)));
            }
        }
        out
    }

    /// Inverse of [`Self::to_yaml`] — for `--resume` reusing a
    /// previously-written overlay file without re-surveying/re-calling
    /// the model. Malformed content degrades to an all-empty overlay
    /// (the same fail-safe `parse_response` uses), never an error, since
    /// a corrupted resume artifact should just mean "no proposed
    /// exclusions" rather than aborting the scan.
    pub fn from_yaml(text: &str) -> Self {
        let data = bc_yaml::parse(text).unwrap_or(Value::Null);
        Self {
            exclude_dirs: string_list(&data, "exclude_dirs"),
            exclude_exts: string_list(&data, "exclude_exts"),
            exclude_globs: string_list(&data, "exclude_globs"),
            max_file_kb: data.get("max_file_kb").and_then(Value::as_u64),
            config_dedup: data
                .get("config_dedup")
                .and_then(Value::as_object)
                .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
                .unwrap_or_default(),
        }
    }
}

fn write_yaml_list(out: &mut String, key: &str, items: &[String]) {
    if items.is_empty() {
        out.push_str(&format!("{key}: []\n"));
        return;
    }
    out.push_str(&format!("{key}:\n"));
    for item in items {
        out.push_str(&format!("  - {}\n", yaml_scalar(item)));
    }
}

/// Quotes a string scalar only when it needs it (starts with a
/// YAML-significant character, or would otherwise be misread as a
/// non-string type) — plain style otherwise, matching PyYAML's own
/// "quote only when necessary" default.
fn yaml_scalar(s: &str) -> String {
    let needs_quoting = s.is_empty()
        || s.starts_with([
            '"', '\'', '#', '&', '*', '!', '|', '>', '%', '@', '`', '-', '?', '[', ']', '{', '}',
            ',', ':',
        ])
        || s.contains(": ")
        || s.ends_with(':')
        || matches!(
            s,
            "true" | "false" | "null" | "~" | "Null" | "True" | "False"
        );
    if needs_quoting {
        format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
    } else {
        s.to_string()
    }
}

fn yaml_scalar_or_flow(v: &Value) -> String {
    match v {
        Value::String(s) => yaml_scalar(s),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::Array(items) => {
            let rendered: Vec<String> = items.iter().map(yaml_scalar_or_flow).collect();
            format!("[{}]", rendered.join(", "))
        }
        Value::Null => "null".to_string(),
        Value::Object(_) => String::new(), // not needed by this overlay's own schema
    }
}

fn string_list(data: &Value, key: &str) -> Vec<String> {
    data.get(key)
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// The one-shot call's own config — deliberately separate from
/// [`crate::Step1Config`] (S1's own agentic-session config): this is a
/// single non-agentic prompt that runs BEFORE S1 even starts, not part
/// of S1's own tool-use loop.
#[derive(Debug, Clone, PartialEq)]
pub struct AutoExcludeConfig {
    pub model: String,
    pub max_tokens: u32,
    pub max_transient_retries: u32,
    pub retry_backoff_base: Duration,
    /// Sampling temperature for the survey call. `None` sends no
    /// `temperature` at all, leaving the provider's own default — which
    /// for both dialects is `1.0`, i.e. maximally divergent between two
    /// scans of the same repo. Ported from the Python original's per-role
    /// `models.<role>.temperature` (`backends/llm.py::resolve`), which
    /// this port had dropped.
    pub temperature: Option<f64>,
    /// Nucleus-sampling cutoff, forwarded to
    /// [`bc_llm_client::ChatRequest::top_p`]. `None` (the default) sends
    /// none — net-new versus Python, which exposes only `temperature`.
    /// The Anthropic dialect drops it when `temperature` is also set, as
    /// the Messages API rejects the pair.
    pub top_p: Option<f64>,
    /// Deterministic-sampling seed, forwarded to
    /// [`bc_llm_client::ChatRequest::seed`] (OpenAI dialect only).
    /// `None` sends no seed.
    pub seed: Option<u64>,
    /// Reasoning-effort tier for this stage's calls (the Python
    /// original's `models.<role>.effort`, else `--reasoning-effort`),
    /// forwarded to [`bc_llm_client::ChatRequest::reasoning_effort`].
    /// `None` (the default) sends none, leaving the provider's default.
    pub reasoning_effort: Option<bc_llm_client::ReasoningEffort>,
    /// Per-role OpenAI transport pin (Python's
    /// `models.<role>.use_responses_api`), forwarded to
    /// [`bc_llm_client::ChatRequest::openai_api`]. `None` (the default)
    /// keeps the client-wide `--openai-api` choice.
    pub openai_api: Option<bc_llm_client::OpenAiApi>,
    /// Per-call wall-clock deadline in seconds, overriding the shared
    /// gateway client's own 300 s default. `None` keeps that default —
    /// Python has no `step1.auto_exclude_timeout` key.
    pub timeout_secs: Option<u64>,
}

/// Survey `repo_root` and ask `client` for additional step1 exclusions.
/// `walk_config` is the CURRENT effective step1 exclusion set (built-ins
/// plus whatever `--config`/CLI already exclude) — used both to build the
/// survey (already-excluded content is hidden, mirroring `_survey`'s own
/// `globbed`/base-set filtering) and to filter the model's own proposals
/// down to genuinely NEW additions.
pub async fn run_autoexclude(
    client: &dyn LlmClient,
    repo_root: &Path,
    walk_config: &WalkConfig,
    dedup_exts: &[String],
    dedup_min_cluster_size: usize,
    config: &AutoExcludeConfig,
) -> Result<AutoExcludeOverlay, LlmError> {
    run_autoexclude_with_diagnostics(
        client,
        repo_root,
        walk_config,
        dedup_exts,
        dedup_min_cluster_size,
        config,
    )
    .await
    .map(|(overlay, _)| overlay)
}

/// [`run_autoexclude`], also returning what the overlay guards decided
/// (language vetoes, the scope before and after, and whether the overlay
/// was discarded or flagged as aggressive).
pub async fn run_autoexclude_with_diagnostics(
    client: &dyn LlmClient,
    repo_root: &Path,
    walk_config: &WalkConfig,
    dedup_exts: &[String],
    dedup_min_cluster_size: usize,
    config: &AutoExcludeConfig,
) -> Result<(AutoExcludeOverlay, AutoExcludeDiagnostics), LlmError> {
    let (survey_text, n_files) = survey(repo_root, walk_config);
    let user_prompt = build_prompt(
        walk_config,
        dedup_exts,
        dedup_min_cluster_size,
        n_files,
        &survey_text,
    );

    let request = ChatRequest {
        model: config.model.clone(),
        system: Some(SYSTEM.to_string()),
        messages: vec![Message::user_text(&user_prompt)],
        tools: Vec::new(),
        max_tokens: config.max_tokens,
        temperature: config.temperature,
        top_p: config.top_p,
        seed: config.seed,
        reasoning_effort: config.reasoning_effort,
        openai_api: config.openai_api,
        thinking_budget: None,
        betas: Vec::new(),
        json_mode: false,
        timeout: config.timeout_secs.map(Duration::from_secs),
        stream: false,
        ..ChatRequest::default()
    };
    let response = bc_llm_agentic::chat_with_retry(
        client,
        &request,
        config.max_transient_retries,
        config.retry_backoff_base,
    )
    .await?;

    let (overlay, vetoed) = parse_response(&response.text(), walk_config);
    let mut diag = AutoExcludeDiagnostics {
        vetoed,
        ..AutoExcludeDiagnostics::default()
    };
    // `n_files` is the in-scope count by the very walk S1 runs, so it is
    // the "before" side of the guard with no second walk.
    let overlay = guard_scope(overlay, repo_root, walk_config, n_files, &mut diag);
    Ok((overlay, diag))
}

/// Builds the three survey blocks (tree/histogram/excerpts) from
/// `walk_repo`'s already-filtered file list. Returns the rendered survey
/// text plus the kept-file count (for the operator-facing log line).
///
/// The largest-files block is the one place `walk_repo`'s filtered list
/// is NOT enough. Python surveys with a raw `os.walk` that applies the
/// dir/ext/glob exclusions but never the size limit, so a file bigger
/// than `max_file_kb` still shows up in its largest-files list — which is
/// exactly what the prompt's `max_file_kb` instruction tells the model to
/// read ("Only emit if the largest-files list shows genuine source bigger
/// than the current limit (raise it)"). `walk_repo` drops those files, so
/// this port's list could only ever contain files already *under* the
/// limit and the raise-the-limit branch was unreachable: a repo whose
/// real source sat above `max_file_kb` would be silently under-scanned
/// forever, with no signal the model could act on. `walk_repo` already
/// records exactly what was hidden in `ExclusionReport::oversize_files`,
/// so they are folded back in here and marked as currently skipped.
fn survey(repo_root: &Path, walk_config: &WalkConfig) -> (String, usize) {
    let (files, report) = walk_repo(repo_root, walk_config);
    let n_files = files.len();

    // rel dir ("" = root) -> (immediate child dir names at TREE_DEPTH, file count)
    let mut tree: BTreeMap<String, (std::collections::BTreeSet<String>, usize)> = BTreeMap::new();
    tree.entry(String::new()).or_default();
    let mut ext_hist: BTreeMap<String, usize> = BTreeMap::new();
    // (size, rel, currently skipped for being over max_file_kb)
    let mut largest: Vec<(u64, String, bool)> = Vec::new();
    let mut excerpts: Vec<(String, String)> = Vec::new();

    for rel in &files {
        let parts: Vec<&str> = rel.split('/').collect();
        let (dir_parts, file_name) = parts.split_at(parts.len() - 1);
        let file_name = file_name[0];
        let depth = dir_parts.len();

        // Bump this file's own file count onto every ancestor dir node
        // (mirrors Python's `while True: ... anc = anc.rpartition("/")[0]`
        // walk up to the root), creating intermediate nodes as needed.
        for d in 0..=dir_parts.len() {
            let anc = dir_parts[..d].join("/");
            tree.entry(anc).or_default().1 += 1;
        }
        // Register each ancestor-to-child link along this file's path, up
        // to and including depth TREE_DEPTH (Python only tracks subdirs
        // for a node at depth <= TREE_DEPTH — `d <= TREE_DEPTH`, not `<`,
        // since this registers dir_parts[d] as a child of the node AT
        // depth `d`, and a depth-TREE_DEPTH node's own children are what
        // `render_survey`'s `depth == TREE_DEPTH` branch actually shows).
        for d in 0..dir_parts.len() {
            if d <= TREE_DEPTH {
                let parent = dir_parts[..d].join("/");
                let child = dir_parts[d].to_string();
                tree.entry(parent).or_default().0.insert(child);
            }
        }

        let ext = suffix_lower(rel);
        let ext = if ext.is_empty() {
            "(none)".to_string()
        } else {
            ext
        };
        *ext_hist.entry(ext).or_insert(0) += 1;

        let abs = repo_root.join(rel);
        let size = std::fs::metadata(&abs).map(|m| m.len()).unwrap_or(0);
        largest.push((size, rel.clone(), false));

        if depth <= TREE_DEPTH
            && excerpts.len() < EXCERPT_MAX
            && size <= 5_000_000
            && is_excerpt_name(file_name)
        {
            if let Ok(txt) = std::fs::read_to_string(&abs) {
                let capped: String = txt.chars().take(EXCERPT_CHARS).collect();
                excerpts.push((rel.clone(), capped.trim_end().to_string()));
            }
        }
    }

    largest.extend(
        report
            .oversize_files
            .iter()
            .map(|(rel, size)| (*size, rel.clone(), true)),
    );
    largest.sort_by_key(|b| std::cmp::Reverse(b.0));
    largest.truncate(LARGEST_N);

    let mut ext_sorted: Vec<(String, usize)> = ext_hist.into_iter().collect();
    ext_sorted.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let ext_total = ext_sorted.len();
    ext_sorted.truncate(EXT_TOP_N);

    (
        render_survey(&tree, &ext_sorted, ext_total, &largest, &excerpts),
        n_files,
    )
}

fn is_excerpt_name(file_name: &str) -> bool {
    let lower = file_name.to_lowercase();
    EXCERPT_NAMES.iter().any(|n| {
        if *n == "readme" {
            lower == "readme" || lower.starts_with("readme.")
        } else {
            lower == *n
        }
    }) || lower.ends_with(".csproj")
        || lower.ends_with(".sln")
}

fn render_survey(
    tree: &BTreeMap<String, (std::collections::BTreeSet<String>, usize)>,
    ext_sorted: &[(String, usize)],
    ext_total: usize,
    largest: &[(u64, String, bool)],
    excerpts: &[(String, String)],
) -> String {
    let root_count = tree.get("").map(|(_, c)| *c).unwrap_or(0);
    let mut tree_lines = vec![format!("./    ({root_count} files)")];
    for (rel, (subs, cnt)) in tree {
        if rel.is_empty() {
            continue;
        }
        let depth = rel.split('/').count();
        let indent = "  ".repeat(depth);
        let name = rel.rsplit('/').next().unwrap_or(rel);
        tree_lines.push(format!("{indent}{name}/    ({cnt} files)"));
        if depth == TREE_DEPTH && !subs.is_empty() {
            let kids: Vec<&String> = subs.iter().collect();
            let shown = &kids[..kids.len().min(TREE_MAX_CHILDREN)];
            for k in shown {
                tree_lines.push(format!("{indent}  {k}/"));
            }
            if kids.len() > TREE_MAX_CHILDREN {
                tree_lines.push(format!(
                    "{indent}  … (+{} more)",
                    kids.len() - TREE_MAX_CHILDREN
                ));
            }
        }
    }

    let mut ext_block = if ext_sorted.is_empty() {
        "  (none)".to_string()
    } else {
        ext_sorted
            .iter()
            .map(|(ext, n)| format!("  {ext:<16} {n:>7}"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    if ext_total > EXT_TOP_N {
        ext_block.push_str(&format!(
            "\n  … (+{} more extensions)",
            ext_total - EXT_TOP_N
        ));
    }

    let exc_block = if excerpts.is_empty() {
        "(no README/build files found at depth ≤2)".to_string()
    } else {
        excerpts
            .iter()
            .map(|(rel, txt)| format!("### {rel}\n```\n{txt}\n```"))
            .collect::<Vec<_>>()
            .join("\n\n")
    };

    let large_block = if largest.is_empty() {
        "  (none)".to_string()
    } else {
        largest
            .iter()
            .map(|(sz, rel, oversize)| {
                let marker = if *oversize {
                    "  [SKIPPED: over max_file_kb]"
                } else {
                    ""
                };
                format!("  {:8.1} KB  {rel}{marker}", *sz as f64 / 1024.0)
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    format!(
        "## Directory tree (depth ≤{}, already-excluded dirs hidden, \
         counts = files that survive current exclusions)\n\
         ```\n{}\n```\n\n\
         ## Extension histogram (top {EXT_TOP_N})\n\
         ```\n{ext_block}\n```\n\n\
         ## Largest {LARGEST_N} files (after current dir/ext/glob exclusions;\n\
         entries marked [SKIPPED: over max_file_kb] are NOT currently scanned)\n\
         ```\n{large_block}\n```\n\n\
         ## Build / README excerpts\n{exc_block}",
        TREE_DEPTH + 1,
        tree_lines.join("\n"),
    )
}

fn build_prompt(
    walk_config: &WalkConfig,
    dedup_exts: &[String],
    dedup_min_cluster_size: usize,
    n_files: usize,
    survey: &str,
) -> String {
    let mut dirs = builtin_and_configured_dirs(walk_config);
    dirs.sort();
    let mut exts = builtin_and_configured_exts(walk_config);
    exts.sort();
    let globs = walk_config.exclude_globs.join(", ");

    let _ = n_files; // only used for the operator-facing log line, not the prompt
    format!(
        "Below is a deterministic survey of a repository. Propose\n\
         ADDITIONAL scan exclusions so the security scanner only sees production code.\n\
         \n\
         Already excluded (do NOT repeat these — propose only repo-specific extras):\n\
         \u{20}\u{20}dirs : {}\n\
         \u{20}\u{20}exts : {}\n\
         \u{20}\u{20}globs: {globs}\n\
         \n\
         Current max_file_kb = {}\n\
         Current config_dedup = {{exts: {dedup_exts:?}, min_cluster_size: {dedup_min_cluster_size}}}\n\
         \n\
         {survey}\n\
         \n\
         Return ONLY a fenced YAML block with these keys (omit any key you have no\n\
         change for — do NOT emit empty/null placeholders):\n\
         \n\
         ```yaml\n\
         exclude_dirs:   # directory NAMES (any depth), e.g. \"generated\", \"samples\"\n\
         \u{20}\u{20}- ...\n\
         exclude_exts:   # file extensions WITH leading dot, e.g. \".pb.go\", \".min.js\"\n\
         \u{20}\u{20}- ...\n\
         exclude_globs:  # repo-relative posix fnmatch, e.g. \"**/*.g.dart\", \"tools/codegen/**\"\n\
         \u{20}\u{20}- ...\n\
         max_file_kb: 1024   # OPTIONAL int. Only emit if the largest-files list shows\n\
         \u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}# genuine source bigger than the current limit (raise it)\n\
         \u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}# or only data dumps above a lower threshold (lower it).\n\
         config_dedup:       # OPTIONAL. Only emit keys you want to change.\n\
         \u{20}\u{20}exts: [...]       # FULL list (REPLACES current). Include defaults you want\n\
         \u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}# to keep plus repo-specific formats e.g. \".tfvars\", \".cue\".\n\
         \u{20}\u{20}min_cluster_size: 3\n\
         ```\n\
         \n\
         Whole sub-repos that are clearly test-automation, demo, or tooling-only may\n\
         be excluded via exclude_globs (e.g. \"that-repo/**\"). Be conservative.",
        dirs.join(", "),
        exts.join(", "),
        walk_config.max_file_kb,
    )
}

/// The bare extension if `entry` would drop an entire scanner-known
/// language from scope (`.pug`, `*.hbs`, `**/*.hbs`, where the extension is
/// in the language table), else `None`. Compound suffixes (`.pb.go`,
/// `.min.js`, `.spec.ts`) are not table keys and pass, as do path-scoped
/// globs (`rsn/**`, `frontend/dist/**`), which narrow a directory rather
/// than a language. A directory glob can still hide a language whose files
/// all live under one directory; that is legitimate scoping and
/// unknowable in general, and the scope guard below is the backstop.
/// Ported from upstream v1.3 `_erases_language`.
fn erases_language(entry: &str) -> Option<String> {
    let rest = entry.strip_prefix("**/").unwrap_or(entry);
    let ext = rest.strip_prefix('*').unwrap_or(rest);
    let bare = ext.len() > 1
        && ext.starts_with('.')
        && ext[1..]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_');
    // A plain `.ext` entry must be exactly that; a glob form must have had
    // its `*`. `**/.pug` (no star) is neither.
    let well_formed = if rest.len() == entry.len() {
        true
    } else {
        rest.starts_with('*')
    };
    if !(bare && well_formed) {
        return None;
    }
    let ext = ext.to_lowercase();
    bc_repo_analysis::ext_to_lang(&ext).map(|_| ext)
}

/// What the overlay guards decided, for the run's diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AutoExcludeDiagnostics {
    /// Model-proposed extension or glob entries vetoed because each would
    /// erase a whole scanner-known language from scope.
    pub vetoed: Vec<String>,
    /// In-scope files before and after the overlay, by the same walk S1
    /// runs.
    pub files_before: usize,
    pub files_after: usize,
    /// The overlay would have emptied the scope and was discarded.
    pub discarded_empty_scope: bool,
    /// The overlay keeps under 10% of the scope. Applied, but reported.
    pub aggressive: bool,
}

/// The walk configuration S1 would run with `overlay` applied (lists
/// appended, `max_file_kb` replaced), matching how the CLI applies it.
fn with_overlay(walk_config: &WalkConfig, overlay: &AutoExcludeOverlay) -> WalkConfig {
    let mut wc = walk_config.clone();
    wc.exclude_dirs.extend(overlay.exclude_dirs.iter().cloned());
    wc.exclude_exts.extend(overlay.exclude_exts.iter().cloned());
    wc.exclude_globs
        .extend(overlay.exclude_globs.iter().cloned());
    if let Some(kb) = overlay.max_file_kb {
        wc.max_file_kb = kb;
    }
    wc
}

/// Gate an LLM-authored overlay on its measured effect, through the
/// authoritative walk (the language veto misses catch-all globs and never
/// sees `exclude_dirs` or `max_file_kb`). The overlay is written by a
/// model reading repository content, so it must not be able to silently
/// remove the whole repository from a security scan: an overlay that would
/// empty a non-empty scope is discarded (the scan runs as with
/// `--no-auto-step1`), keeping only its `config_dedup` tuning. One that
/// keeps under 10% is applied but flagged. Ported from upstream v1.3.
fn guard_scope(
    mut overlay: AutoExcludeOverlay,
    repo_root: &Path,
    walk_config: &WalkConfig,
    files_before: usize,
    diag: &mut AutoExcludeDiagnostics,
) -> AutoExcludeOverlay {
    diag.files_before = files_before;
    let (after, _) = walk_repo(repo_root, &with_overlay(walk_config, &overlay));
    diag.files_after = after.len();
    if files_before == 0 {
        return overlay;
    }
    if diag.files_after == 0 {
        tracing::warn!(
            files_before,
            "[auto-step1] overlay would empty the scope ({files_before} files -> 0); \
             DISCARDING it. Scanning with global step1 only."
        );
        diag.discarded_empty_scope = true;
        overlay.exclude_dirs.clear();
        overlay.exclude_exts.clear();
        overlay.exclude_globs.clear();
        overlay.max_file_kb = None;
        diag.files_after = files_before;
    } else if (diag.files_after as f64) / (files_before as f64) < AGGRESSIVE_KEEP_RATIO {
        let files_after = diag.files_after;
        tracing::warn!(
            files_before,
            files_after,
            "[auto-step1] overlay is aggressive ({files_before} files -> {files_after}); \
             applying it. Re-run with --no-auto-step1 if coverage looks wrong."
        );
        diag.aggressive = true;
    }
    overlay
}

fn builtin_and_configured_dirs(walk_config: &WalkConfig) -> Vec<String> {
    bc_repo_analysis::DEFAULT_EXCLUDE_DIRS
        .iter()
        .map(|s| s.to_string())
        .chain(walk_config.exclude_dirs.iter().cloned())
        .collect()
}

fn builtin_and_configured_exts(walk_config: &WalkConfig) -> Vec<String> {
    bc_repo_analysis::DEFAULT_EXCLUDE_EXTS
        .iter()
        .map(|s| s.to_string())
        .chain(walk_config.exclude_exts.iter().cloned())
        .collect()
}

/// Extracts the model's fenced ```yaml block (falling back to the whole
/// response text if no fence is found, matching Python's own `_extract_
/// yaml`), parses it, unwraps an optional top-level `step1:` wrapper, and
/// filters every proposal down to genuinely NEW additions the caller's
/// `walk_config` doesn't already cover. Malformed/unparseable YAML
/// degrades to an all-empty overlay rather than an error — matching
/// Python's own non-fatal "WARN + write empty overlay" behavior, since a
/// bad model response should never abort the scan.
///
/// Enforces the system prompt's own "never exclude application source"
/// rule deterministically: any model-proposed extension or glob that would
/// erase a whole scanner-known language ([`erases_language`]) is vetoed
/// and returned in the second slot. Only the model overlay is policed;
/// built-in defaults and operator configuration never pass through here,
/// so an operator can still exclude `.pug` deliberately.
fn parse_response(raw: &str, walk_config: &WalkConfig) -> (AutoExcludeOverlay, Vec<String>) {
    let blob = extract_yaml_fence(raw);
    let data = match bc_yaml::parse(&blob) {
        Ok(v) => v,
        Err(_) => return (AutoExcludeOverlay::default(), Vec::new()),
    };
    let data = match &data {
        Value::Object(map) if map.len() == 1 && map.get("step1").is_some_and(Value::is_object) => {
            map["step1"].clone()
        }
        other => other.clone(),
    };
    if !data.is_object() {
        return (AutoExcludeOverlay::default(), Vec::new());
    }

    let base_dirs_l: std::collections::HashSet<String> = builtin_and_configured_dirs(walk_config)
        .into_iter()
        .map(|d| d.to_lowercase())
        .collect();
    let base_exts_l: std::collections::HashSet<String> = builtin_and_configured_exts(walk_config)
        .into_iter()
        .map(|e| e.to_lowercase())
        .collect();
    let base_globs: std::collections::HashSet<&String> = walk_config.exclude_globs.iter().collect();

    let dirs: Vec<String> = norm_list(&data, "exclude_dirs", false)
        .into_iter()
        .filter(|d| !base_dirs_l.contains(&d.to_lowercase()))
        .collect();
    let exts: Vec<String> = norm_list(&data, "exclude_exts", true)
        .into_iter()
        .map(|e| {
            if e.starts_with('.') {
                e
            } else {
                format!(".{e}")
            }
        })
        .filter(|e| !base_exts_l.contains(e))
        .collect();
    let globs: Vec<String> = norm_list(&data, "exclude_globs", false)
        .into_iter()
        .filter(|g| !base_globs.contains(g))
        .collect();
    let vetoed: Vec<String> = exts
        .iter()
        .chain(globs.iter())
        .filter(|x| erases_language(x).is_some())
        .cloned()
        .collect();
    let exts: Vec<String> = exts
        .into_iter()
        .filter(|e| erases_language(e).is_none())
        .collect();
    let globs: Vec<String> = globs
        .into_iter()
        .filter(|g| erases_language(g).is_none())
        .collect();
    if !vetoed.is_empty() {
        let list = vetoed.join(", ");
        tracing::warn!(
            "[auto-step1] vetoed language-wide exclusions proposed by the model \
             (would erase scannable source): {list}"
        );
    }

    let max_file_kb = data
        .get("max_file_kb")
        .and_then(Value::as_u64)
        .filter(|&kb| kb > 0 && kb != walk_config.max_file_kb);

    let mut config_dedup = BTreeMap::new();
    if let Some(dd) = data.get("config_dedup").and_then(Value::as_object) {
        for key in [
            "enabled",
            "exts",
            "min_cluster_size",
            "keep_per_top_dir",
            "promote_on_secret_hit",
            "promote_on_insecure_value",
            "max_file_kb",
        ] {
            let Some(v) = dd.get(key) else { continue };
            match key {
                "exts" => {
                    let xs: Vec<Value> = norm_list_value(v, true)
                        .into_iter()
                        .map(|e| {
                            let e = if e.starts_with('.') {
                                e
                            } else {
                                format!(".{e}")
                            };
                            Value::String(e)
                        })
                        .collect();
                    if !xs.is_empty() {
                        config_dedup.insert(key.to_string(), Value::Array(xs));
                    }
                }
                "enabled"
                | "keep_per_top_dir"
                | "promote_on_secret_hit"
                | "promote_on_insecure_value" => {
                    if let Some(b) = v.as_bool() {
                        config_dedup.insert(key.to_string(), Value::Bool(b));
                    }
                }
                "min_cluster_size" | "max_file_kb" => {
                    if let Some(n) = v.as_u64() {
                        config_dedup.insert(key.to_string(), Value::from(n));
                    }
                }
                _ => {}
            }
        }
    }

    (
        AutoExcludeOverlay {
            exclude_dirs: dirs,
            exclude_exts: exts,
            exclude_globs: globs,
            max_file_kb,
            config_dedup,
        },
        vetoed,
    )
}

fn extract_yaml_fence(text: &str) -> String {
    if let Some(start) = text.find("```") {
        let after = &text[start + 3..];
        let after = after
            .strip_prefix("yaml")
            .or_else(|| after.strip_prefix("yml"))
            .unwrap_or(after);
        let after = after.strip_prefix('\n').unwrap_or(after);
        if let Some(end) = after.find("```") {
            return after[..end].to_string();
        }
    }
    text.to_string()
}

fn norm_list(data: &Value, key: &str, lower: bool) -> Vec<String> {
    data.get(key)
        .map(|v| norm_list_value(v, lower))
        .unwrap_or_default()
}

fn norm_list_value(v: &Value, lower: bool) -> Vec<String> {
    let items: Vec<&Value> = match v {
        Value::Array(a) => a.iter().collect(),
        Value::String(_) => vec![v],
        _ => return Vec::new(),
    };
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for item in items {
        let Some(s) = item.as_str() else { continue };
        let s = s.trim().trim_matches(|c| c == '/' || c == '\\');
        if s.is_empty() {
            continue;
        }
        let s = if lower {
            s.to_lowercase()
        } else {
            s.to_string()
        };
        if seen.insert(s.clone()) {
            out.push(s);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wc() -> WalkConfig {
        WalkConfig::new()
    }

    #[test]
    fn parse_response_extracts_a_fenced_yaml_block() {
        let raw = "here you go\n```yaml\nexclude_dirs:\n  - generated\n```\nthanks";
        let overlay = parse_response(raw, &wc()).0;
        assert_eq!(overlay.exclude_dirs, vec!["generated".to_string()]);
    }

    #[test]
    fn parse_response_falls_back_to_raw_text_when_unfenced() {
        let raw = "exclude_dirs:\n  - generated\n";
        let overlay = parse_response(raw, &wc()).0;
        assert_eq!(overlay.exclude_dirs, vec!["generated".to_string()]);
    }

    #[test]
    fn parse_response_degrades_to_empty_on_malformed_yaml() {
        let raw = "```yaml\nexclude_dirs: [unterminated\n```";
        let overlay = parse_response(raw, &wc()).0;
        assert_eq!(overlay, AutoExcludeOverlay::default());
    }

    #[test]
    fn parse_response_unwraps_a_top_level_step1_key() {
        let raw = "```yaml\nstep1:\n  exclude_dirs:\n    - generated\n```";
        let overlay = parse_response(raw, &wc()).0;
        assert_eq!(overlay.exclude_dirs, vec!["generated".to_string()]);
    }

    #[test]
    fn parse_response_drops_dirs_already_excluded_by_default() {
        // ".git" is one of bc_repo_analysis::DEFAULT_EXCLUDE_DIRS.
        let raw = "```yaml\nexclude_dirs:\n  - .git\n  - generated\n```";
        let overlay = parse_response(raw, &wc()).0;
        assert_eq!(overlay.exclude_dirs, vec!["generated".to_string()]);
    }

    #[test]
    fn parse_response_drops_dirs_already_in_the_configured_walk_config() {
        let mut config = wc();
        config.exclude_dirs.push("already-excluded".to_string());
        let raw = "```yaml\nexclude_dirs:\n  - already-excluded\n  - new-one\n```";
        let overlay = parse_response(raw, &config).0;
        assert_eq!(overlay.exclude_dirs, vec!["new-one".to_string()]);
    }

    #[test]
    fn parse_response_normalizes_extensions_to_have_a_leading_dot() {
        let raw = "```yaml\nexclude_exts:\n  - pb.go\n  - .g.dart\n```";
        let overlay = parse_response(raw, &wc()).0;
        assert_eq!(
            overlay.exclude_exts,
            vec![".pb.go".to_string(), ".g.dart".to_string()]
        );
    }

    #[test]
    fn parse_response_drops_an_already_excluded_extension() {
        // ".png" is one of bc_repo_analysis::DEFAULT_EXCLUDE_EXTS.
        let raw = "```yaml\nexclude_exts:\n  - .png\n  - .foo\n```";
        let overlay = parse_response(raw, &wc()).0;
        assert_eq!(overlay.exclude_exts, vec![".foo".to_string()]);
    }

    #[test]
    fn parse_response_globs_filter_out_already_configured_ones() {
        let mut config = wc();
        config.exclude_globs.push("already/**".to_string());
        let raw = "```yaml\nexclude_globs:\n  - already/**\n  - tools/codegen/**\n```";
        let overlay = parse_response(raw, &config).0;
        assert_eq!(overlay.exclude_globs, vec!["tools/codegen/**".to_string()]);
    }

    #[test]
    fn parse_response_max_file_kb_only_kept_when_positive_and_different() {
        let mut config = wc();
        config.max_file_kb = 1024;
        let same = parse_response("```yaml\nmax_file_kb: 1024\n```", &config).0;
        assert_eq!(same.max_file_kb, None);
        let zero = parse_response("```yaml\nmax_file_kb: 0\n```", &config).0;
        assert_eq!(zero.max_file_kb, None);
        let changed = parse_response("```yaml\nmax_file_kb: 2048\n```", &config).0;
        assert_eq!(changed.max_file_kb, Some(2048));
    }

    #[test]
    fn parse_response_config_dedup_only_keeps_recognized_typed_keys() {
        let raw = "```yaml\nconfig_dedup:\n  exts: [.tfvars, cue]\n  min_cluster_size: 5\n  enabled: true\n  unknown_key: 7\n```";
        let overlay = parse_response(raw, &wc()).0;
        assert_eq!(
            overlay.config_dedup.get("exts"),
            Some(&Value::Array(vec![
                Value::String(".tfvars".to_string()),
                Value::String(".cue".to_string()),
            ]))
        );
        assert_eq!(
            overlay.config_dedup.get("min_cluster_size"),
            Some(&Value::from(5u64))
        );
        assert_eq!(
            overlay.config_dedup.get("enabled"),
            Some(&Value::Bool(true))
        );
        assert!(!overlay.config_dedup.contains_key("unknown_key"));
    }

    #[test]
    fn parse_response_config_dedup_absent_when_no_keys_recognized() {
        let raw = "```yaml\nconfig_dedup:\n  bogus: 1\n```";
        let overlay = parse_response(raw, &wc()).0;
        assert!(overlay.config_dedup.is_empty());
    }

    #[test]
    fn to_yaml_renders_empty_lists_in_flow_style() {
        let text = AutoExcludeOverlay::default().to_yaml();
        assert!(text.contains("exclude_dirs: []"));
        assert!(text.contains("exclude_exts: []"));
        assert!(text.contains("exclude_globs: []"));
        assert!(!text.contains("max_file_kb"));
        assert!(!text.contains("config_dedup"));
    }

    #[test]
    fn yaml_scalar_quotes_a_value_that_would_otherwise_be_misread() {
        assert_eq!(yaml_scalar("true"), "\"true\"");
        assert_eq!(yaml_scalar("-leading-dash"), "\"-leading-dash\"");
        assert_eq!(yaml_scalar("a: b"), "\"a: b\"");
        assert_eq!(yaml_scalar("trailing:"), "\"trailing:\"");
        assert_eq!(yaml_scalar("plain"), "plain");
        // Embedded quotes/backslashes only get escaped once the value
        // ALSO needs quoting for some other reason (a leading `"` here) —
        // a plain scalar can contain a mid-string `"` unescaped in YAML.
        assert_eq!(
            yaml_scalar(r#""already has quotes""#),
            "\"\\\"already has quotes\\\"\""
        );
        assert_eq!(
            yaml_scalar("has \"quotes\" mid-string"),
            "has \"quotes\" mid-string"
        );
    }

    #[test]
    fn yaml_scalar_or_flow_renders_an_array_in_flow_style() {
        let v = Value::Array(vec![
            Value::String("a".to_string()),
            Value::Bool(true),
            Value::Null,
        ]);
        assert_eq!(yaml_scalar_or_flow(&v), "[a, true, null]");
    }

    #[test]
    fn parse_response_config_dedup_exts_is_normalized_and_deduplicated() {
        let raw = "```yaml\nconfig_dedup:\n  exts: [tfvars, .cue, tfvars]\n```";
        let overlay = parse_response(raw, &wc()).0;
        assert_eq!(
            overlay.config_dedup.get("exts"),
            Some(&Value::Array(vec![
                Value::String(".tfvars".to_string()),
                Value::String(".cue".to_string()),
            ]))
        );
    }

    #[test]
    fn parse_response_returns_default_when_the_top_level_value_is_not_an_object() {
        let overlay = parse_response("```yaml\n- just\n- a\n- list\n```", &wc()).0;
        assert_eq!(overlay, AutoExcludeOverlay::default());
    }

    #[test]
    fn extract_yaml_fence_falls_back_to_the_raw_text_when_the_fence_is_unterminated() {
        let raw = "```yaml\nexclude_dirs:\n  - generated\n(no closing fence)";
        // No closing fence, so the whole raw string (fence markers
        // included) is returned unparsed as-is — `bc_yaml::parse` then
        // fails on the stray "```yaml" line, degrading to an empty
        // overlay, exactly like any other malformed-YAML response.
        let overlay = parse_response(raw, &wc()).0;
        assert_eq!(overlay, AutoExcludeOverlay::default());
    }

    #[test]
    fn norm_list_value_accepts_a_bare_string_not_just_an_array() {
        let overlay = parse_response("```yaml\nexclude_dirs: generated\n```", &wc()).0;
        assert_eq!(overlay.exclude_dirs, vec!["generated".to_string()]);
    }

    #[test]
    fn norm_list_value_skips_an_item_that_trims_to_empty() {
        let raw = "```yaml\nexclude_dirs:\n  - \"/\"\n  - generated\n```";
        let overlay = parse_response(raw, &wc()).0;
        assert_eq!(overlay.exclude_dirs, vec!["generated".to_string()]);
    }

    #[test]
    fn survey_labels_an_extensionless_file_as_none() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Makefile2"), "").unwrap();
        let (text, _) = survey(dir.path(), &wc());
        assert!(text.contains("(none)"));
    }

    #[test]
    fn a_file_over_max_file_kb_still_appears_in_the_largest_files_block() {
        // Regression: the survey used to be built purely from
        // `walk_repo`'s kept list, which drops oversize files — so the
        // prompt's own "raise max_file_kb if the largest-files list shows
        // genuine source bigger than the current limit" branch could
        // never fire, no matter how much real source the limit was hiding.
        let dir = tempfile::tempdir().unwrap();
        let mut config = wc();
        config.max_file_kb = 1;
        std::fs::write(dir.path().join("small.rs"), "fn main() {}").unwrap();
        std::fs::write(dir.path().join("huge.rs"), "x".repeat(4096)).unwrap();

        let (text, n_files) = survey(dir.path(), &config);
        // The oversize file is still excluded from the *scan* — only the
        // survey learns about it.
        assert_eq!(n_files, 1);
        assert!(text.contains("small.rs"), "{text}");
        assert!(
            text.contains("huge.rs  [SKIPPED: over max_file_kb]"),
            "the oversize file must be visible AND marked:\n{text}"
        );
        // Sorted with the other files by size, largest first.
        let huge_at = text.find("huge.rs").unwrap();
        let small_at = text.rfind("small.rs").unwrap();
        assert!(huge_at < small_at, "{text}");
    }

    #[test]
    fn render_survey_truncates_a_deep_directory_with_over_60_children() {
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("a").join("b");
        std::fs::create_dir_all(&parent).unwrap();
        for i in 0..65 {
            let child = parent.join(format!("child{i:02}"));
            std::fs::create_dir(&child).unwrap();
            std::fs::write(child.join("f.rs"), "").unwrap();
        }
        let (text, n_files) = survey(dir.path(), &wc());
        assert_eq!(n_files, 65);
        assert!(text.contains("… (+5 more)"));
    }

    #[test]
    fn render_survey_notes_extensions_beyond_the_top_40() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..45 {
            std::fs::write(dir.path().join(format!("f{i:02}.ext{i:02}")), "").unwrap();
        }
        let (text, n_files) = survey(dir.path(), &wc());
        assert_eq!(n_files, 45);
        assert!(text.contains("more extensions"));
    }

    #[test]
    fn to_yaml_round_trips_through_from_yaml() {
        let overlay = AutoExcludeOverlay {
            exclude_dirs: vec!["generated".to_string()],
            exclude_exts: vec![".pb.go".to_string()],
            exclude_globs: vec!["tools/**".to_string()],
            max_file_kb: Some(2048),
            config_dedup: BTreeMap::from([("min_cluster_size".to_string(), Value::from(5u64))]),
        };
        let text = overlay.to_yaml();
        assert!(text.starts_with("# Auto-generated by bc-sast auto-step1"));
        let round_tripped = AutoExcludeOverlay::from_yaml(&text);
        assert_eq!(round_tripped, overlay);
    }

    #[test]
    fn from_yaml_degrades_to_default_on_malformed_content() {
        let overlay = AutoExcludeOverlay::from_yaml("not: [valid");
        assert_eq!(overlay, AutoExcludeOverlay::default());
    }

    #[test]
    fn is_excerpt_name_matches_readme_variants_and_manifest_files() {
        assert!(is_excerpt_name("README"));
        assert!(is_excerpt_name("readme.md"));
        assert!(is_excerpt_name("package.json"));
        assert!(is_excerpt_name("Dockerfile"));
        assert!(is_excerpt_name("my-app.csproj"));
        assert!(!is_excerpt_name("main.rs"));
    }

    #[test]
    fn survey_builds_a_tree_ext_histogram_and_excerpt_from_a_real_dir() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("README.md"), "# hi\nsome text").unwrap();
        std::fs::create_dir(dir.path().join("src")).unwrap();
        std::fs::write(dir.path().join("src/main.rs"), "fn main() {}").unwrap();
        let (text, n_files) = survey(dir.path(), &wc());
        assert_eq!(n_files, 2);
        assert!(text.contains("Directory tree"));
        assert!(text.contains("src/"));
        assert!(text.contains(".rs"));
        assert!(text.contains("README.md"));
    }

    #[test]
    fn build_prompt_includes_current_exclusion_sets_and_the_survey() {
        let config = wc();
        let prompt = build_prompt(&config, &[".yml".to_string()], 3, 5, "SURVEY_TEXT_HERE");
        assert!(prompt.contains("SURVEY_TEXT_HERE"));
        assert!(prompt.contains("dirs :"));
        assert!(prompt.contains(".yml"));
        assert!(prompt.contains("min_cluster_size: 3"));
    }

    #[tokio::test]
    async fn run_autoexclude_propagates_a_non_retryable_llm_error() {
        struct FailingClient;
        #[async_trait::async_trait]
        impl LlmClient for FailingClient {
            async fn chat(
                &self,
                _request: &ChatRequest,
            ) -> Result<bc_llm_client::ChatResponse, LlmError> {
                Err(LlmError::InvalidRequest {
                    message: "nope".to_string(),
                })
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let config = AutoExcludeConfig {
            model: "test-model".to_string(),
            max_tokens: 8000,
            max_transient_retries: 0,
            retry_backoff_base: Duration::ZERO,
            temperature: None,
            top_p: None,
            seed: None,
            reasoning_effort: None,
            openai_api: None,
            timeout_secs: None,
        };
        let result = run_autoexclude(&FailingClient, dir.path(), &wc(), &[], 3, &config).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn run_autoexclude_returns_a_parsed_overlay_on_success() {
        struct FakeClient;
        #[async_trait::async_trait]
        impl LlmClient for FakeClient {
            async fn chat(
                &self,
                _request: &ChatRequest,
            ) -> Result<bc_llm_client::ChatResponse, LlmError> {
                Ok(bc_llm_client::ChatResponse {
                    content: vec![bc_llm_client::ContentBlock::text(
                        "```yaml\nexclude_dirs:\n  - generated\n```",
                    )],
                    stop_reason: bc_llm_client::StopReason::EndTurn,
                    usage: bc_llm_client::Usage::default(),
                })
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let config = AutoExcludeConfig {
            model: "test-model".to_string(),
            max_tokens: 8000,
            max_transient_retries: 0,
            retry_backoff_base: Duration::ZERO,
            temperature: None,
            top_p: None,
            seed: None,
            reasoning_effort: None,
            openai_api: None,
            timeout_secs: None,
        };
        let overlay = run_autoexclude(&FakeClient, dir.path(), &wc(), &[], 3, &config)
            .await
            .unwrap();
        assert_eq!(overlay.exclude_dirs, vec!["generated".to_string()]);
    }

    // ── upstream v1.3 overlay guards ─────────────────────────────────────

    #[test]
    fn erases_language_flags_only_whole_language_exclusions() {
        for entry in [".pug", ".PY", "*.hbs", "**/*.hbs", "**/*.ts"] {
            assert!(erases_language(entry).is_some(), "{entry}");
        }
        assert_eq!(erases_language("**/*.PY").as_deref(), Some(".py"));
        for entry in [
            ".pb.go",
            ".min.js",
            "*.spec.ts",
            "rsn/**",
            "frontend/dist/**",
            "**/.pug",
            "*pug",
            ".",
            "**/*.",
            ".nosuchlang",
            "src/*.py",
        ] {
            assert_eq!(erases_language(entry), None, "{entry}");
        }
    }

    #[test]
    fn parse_response_vetoes_language_wide_exts_and_globs() {
        let raw = "```yaml\nexclude_exts:\n  - .pug\n  - .pb.go\nexclude_globs:\n  - \"**/*.hbs\"\n  - gen/**\n```";
        let (overlay, vetoed) = parse_response(raw, &wc());
        assert_eq!(overlay.exclude_exts, vec![".pb.go".to_string()]);
        assert_eq!(overlay.exclude_globs, vec!["gen/**".to_string()]);
        assert_eq!(vetoed, vec![".pug".to_string(), "**/*.hbs".to_string()]);
    }

    fn repo_with(files: &[&str]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for f in files {
            let path = dir.path().join(f);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, "x\n").unwrap();
        }
        dir
    }

    fn overlay_of(globs: &[&str]) -> AutoExcludeOverlay {
        AutoExcludeOverlay {
            exclude_globs: globs.iter().map(|g| g.to_string()).collect(),
            config_dedup: BTreeMap::from([("enabled".to_string(), Value::Bool(true))]),
            ..AutoExcludeOverlay::default()
        }
    }

    #[test]
    fn an_overlay_that_would_empty_the_scope_is_discarded_but_keeps_dedup_tuning() {
        let dir = repo_with(&["src/a.py", "lib/b.py"]);
        let mut diag = AutoExcludeDiagnostics::default();
        let mut overlay = overlay_of(&["**"]);
        overlay.exclude_dirs = vec!["src".to_string()];
        overlay.max_file_kb = Some(1);
        let kept = guard_scope(overlay, dir.path(), &wc(), 2, &mut diag);
        assert!(diag.discarded_empty_scope);
        assert!(kept.exclude_globs.is_empty());
        assert!(kept.exclude_dirs.is_empty());
        assert_eq!(kept.max_file_kb, None);
        assert_eq!(kept.config_dedup.len(), 1);
        assert_eq!((diag.files_before, diag.files_after), (2, 2));
    }

    #[test]
    fn an_aggressive_overlay_is_applied_and_flagged() {
        let files: Vec<String> = (0..20).map(|i| format!("gen/f{i}.py")).collect();
        let mut refs: Vec<&str> = files.iter().map(String::as_str).collect();
        refs.push("src/app.py");
        let dir = repo_with(&refs);
        let mut diag = AutoExcludeDiagnostics::default();
        let kept = guard_scope(overlay_of(&["gen/**"]), dir.path(), &wc(), 21, &mut diag);
        assert!(diag.aggressive);
        assert!(!diag.discarded_empty_scope);
        assert_eq!(diag.files_after, 1);
        assert_eq!(kept.exclude_globs, vec!["gen/**".to_string()]);
    }

    #[test]
    fn a_moderate_overlay_passes_the_guard_untouched() {
        let dir = repo_with(&["gen/a.py", "src/b.py"]);
        let mut diag = AutoExcludeDiagnostics::default();
        let overlay = overlay_of(&["gen/**"]);
        let kept = guard_scope(overlay.clone(), dir.path(), &wc(), 2, &mut diag);
        assert_eq!(kept, overlay);
        assert!(!diag.aggressive && !diag.discarded_empty_scope);
        assert_eq!(diag.files_after, 1);
    }

    #[test]
    fn an_empty_repo_is_never_reported_as_emptied() {
        let dir = tempfile::tempdir().unwrap();
        let mut diag = AutoExcludeDiagnostics::default();
        let overlay = overlay_of(&["**"]);
        let kept = guard_scope(overlay.clone(), dir.path(), &wc(), 0, &mut diag);
        assert_eq!(kept, overlay);
        assert!(!diag.discarded_empty_scope);
    }

    #[test]
    fn with_overlay_appends_lists_and_replaces_the_size_limit() {
        let overlay = AutoExcludeOverlay {
            exclude_dirs: vec!["gen".to_string()],
            exclude_exts: vec![".foo".to_string()],
            exclude_globs: vec!["x/**".to_string()],
            max_file_kb: Some(7),
            config_dedup: BTreeMap::new(),
        };
        let wc2 = with_overlay(&wc(), &overlay);
        assert!(wc2.exclude_dirs.contains(&"gen".to_string()));
        assert!(wc2.exclude_exts.contains(&".foo".to_string()));
        assert!(wc2.exclude_globs.contains(&"x/**".to_string()));
        assert_eq!(wc2.max_file_kb, 7);
        let wc3 = with_overlay(&wc(), &AutoExcludeOverlay::default());
        assert_eq!(wc3.max_file_kb, wc().max_file_kb);
    }

    #[tokio::test]
    async fn a_model_cannot_exclude_the_whole_repository() {
        // Security regression: the overlay is model-authored from repo
        // content. A catch-all glob must not silently remove every file
        // from the scan, and a bare language extension must be vetoed.
        struct Hostile;
        #[async_trait::async_trait]
        impl LlmClient for Hostile {
            async fn chat(
                &self,
                _request: &ChatRequest,
            ) -> Result<bc_llm_client::ChatResponse, LlmError> {
                Ok(bc_llm_client::ChatResponse {
                    content: vec![bc_llm_client::ContentBlock::text(
                        "```yaml\nexclude_globs:\n  - \"*\"\n  - \"**/*.py\"\nexclude_exts: [.py]\n```",
                    )],
                    stop_reason: bc_llm_client::StopReason::EndTurn,
                    usage: bc_llm_client::Usage::default(),
                })
            }
        }
        let dir = repo_with(&["app.py", "pkg/util.py"]);
        let config = AutoExcludeConfig {
            model: "test-model".to_string(),
            max_tokens: 8000,
            max_transient_retries: 0,
            retry_backoff_base: Duration::ZERO,
            temperature: None,
            top_p: None,
            seed: None,
            reasoning_effort: None,
            openai_api: None,
            timeout_secs: None,
        };
        let (overlay, diag) =
            run_autoexclude_with_diagnostics(&Hostile, dir.path(), &wc(), &[], 3, &config)
                .await
                .unwrap();
        assert_eq!(diag.vetoed, vec![".py".to_string(), "**/*.py".to_string()]);
        assert!(diag.discarded_empty_scope);
        assert_eq!(overlay, AutoExcludeOverlay::default());
    }
}
