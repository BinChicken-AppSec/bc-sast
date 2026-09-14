//! Config-file structural dedup, ported from
//! `s1_preprocess.py::_dedup_configs` and its helpers. Collapses
//! near-duplicate per-environment config files (e.g. thousands of
//! `service/<svc>/<env>/config.yml` copies in a monorepo) to one
//! representative per shape-cluster, so downstream LLM steps don't burn
//! tokens on structurally-identical variants. A file is only ever dropped
//! if (a) at least `min_cluster_size` siblings share its exact key
//! structure (values ignored) AND (b) it carries no secret/insecure-value
//! signal not already present in the kept representative.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::LazyLock;

use fancy_regex::Regex as FancyRegex;
use regex::Regex;
use serde_json::Value;
use sha1::{Digest, Sha1};

/// `step1.config_dedup.*` — see `_DEDUP_DEFAULTS`.
#[derive(Debug, Clone, PartialEq)]
pub struct DedupConfig {
    pub enabled: bool,
    pub exts: Vec<String>,
    pub min_cluster_size: usize,
    pub keep_per_top_dir: bool,
    pub promote_on_secret_hit: bool,
    pub promote_on_insecure_value: bool,
    pub max_file_kb: u64,
}

impl DedupConfig {
    pub fn new() -> Self {
        DedupConfig {
            enabled: true,
            exts: [
                ".yml",
                ".yaml",
                ".json",
                ".toml",
                ".ini",
                ".properties",
                ".conf",
                ".cfg",
                ".env",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            min_cluster_size: 3,
            keep_per_top_dir: true,
            promote_on_secret_hit: true,
            promote_on_insecure_value: true,
            max_file_kb: 512,
        }
    }
}

impl Default for DedupConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClusterSummary {
    /// First 12 hex chars of the shape hash.
    pub shape: String,
    pub size: usize,
    pub reps: Vec<String>,
    pub dropped: usize,
    pub sample: String,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct DedupReport {
    pub enabled: bool,
    pub candidates: usize,
    pub unparseable_kept: usize,
    pub clusters: usize,
    pub kept_reps: usize,
    /// `(file, matched_signal)` for every file kept despite matching its
    /// cluster's shape, because it carried a suspicious value the
    /// representative didn't already have.
    pub promoted: Vec<(String, String)>,
    pub dropped: Vec<String>,
    /// Largest clusters first.
    pub top_clusters: Vec<ClusterSummary>,
}

/// Drop near-duplicate config files from `files` (repo-relative POSIX
/// paths), reading bodies from under `repo_root`. Returns (sorted kept
/// files, report). A no-op (returns `files` unchanged) if disabled or if
/// fewer than `min_cluster_size` candidates exist at all.
pub fn dedup_configs(
    files: &[String],
    repo_root: &Path,
    config: &DedupConfig,
) -> (Vec<String>, DedupReport) {
    if !config.enabled {
        return (
            files.to_vec(),
            DedupReport {
                enabled: false,
                ..Default::default()
            },
        );
    }

    let exts: HashSet<String> = config.exts.iter().map(|e| e.to_lowercase()).collect();
    let max_bytes = config.max_file_kb * 1024;

    let mut candidates = Vec::new();
    let mut passthrough = Vec::new();
    for rel in files {
        let ext = Path::new(rel)
            .extension()
            .map(|e| format!(".{}", e.to_string_lossy().to_lowercase()));
        if ext.is_some_and(|e| exts.contains(&e)) {
            candidates.push(rel.clone());
        } else {
            passthrough.push(rel.clone());
        }
    }

    if candidates.len() < config.min_cluster_size {
        return (
            files.to_vec(),
            DedupReport {
                enabled: true,
                candidates: candidates.len(),
                ..Default::default()
            },
        );
    }

    // Pass 1: shape-hash every candidate, discarding its body immediately
    // afterward (memory-bounded regardless of candidate count).
    let mut clusters: HashMap<String, Vec<(String, u64)>> = HashMap::new();
    let mut unclustered = Vec::new();
    for rel in &candidates {
        let path = repo_root.join(rel);
        let ext = Path::new(rel)
            .extension()
            .map(|e| format!(".{}", e.to_string_lossy().to_lowercase()));
        let ext = ext.unwrap_or_default();
        match read_bounded_text(&path, max_bytes) {
            Some(text) => match shape_hash(&text, &ext) {
                Some(hash) => {
                    let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                    clusters.entry(hash).or_default().push((rel.clone(), size));
                }
                None => unclustered.push(rel.clone()),
            },
            None => unclustered.push(rel.clone()),
        }
    }

    let mut keep: Vec<String> = passthrough;
    keep.extend(unclustered.iter().cloned());
    let mut promoted = Vec::new();
    let mut dropped = Vec::new();
    let mut cluster_summaries = Vec::new();

    for (hash, mut members) in clusters {
        if members.len() < config.min_cluster_size {
            keep.extend(members.into_iter().map(|(rel, _)| rel));
            continue;
        }
        members.sort_by_key(|a| rep_score(&a.0, a.1));

        let mut reps: Vec<String> = Vec::new();
        if config.keep_per_top_dir {
            let mut seen_top_dirs = HashSet::new();
            for (rel, _) in &members {
                let top_dir = rel.split('/').next().unwrap_or(rel).to_string();
                if seen_top_dirs.insert(top_dir) {
                    reps.push(rel.clone());
                }
            }
        } else {
            reps.push(members[0].0.clone());
        }
        let rep_set: HashSet<String> = reps.iter().cloned().collect();

        let mut rep_suspicious = HashSet::new();
        for rep in &reps {
            if let Some(text) = read_bounded_text(&repo_root.join(rep), max_bytes) {
                rep_suspicious.extend(suspicious_set(
                    &text,
                    config.promote_on_secret_hit,
                    config.promote_on_insecure_value,
                ));
            }
        }
        keep.extend(reps.iter().cloned());

        let mut cluster_dropped = Vec::new();
        for (rel, _) in &members {
            if rep_set.contains(rel) {
                continue;
            }
            let text = read_bounded_text(&repo_root.join(rel), max_bytes);
            match decide_member(
                text.as_deref(),
                &rep_suspicious,
                config.promote_on_secret_hit,
                config.promote_on_insecure_value,
            ) {
                MemberDecision::Drop => cluster_dropped.push(rel.clone()),
                MemberDecision::Keep { signal, sus } => {
                    keep.push(rel.clone());
                    // `signal` is `Some(..)` only when this was a genuine
                    // promotion (a new suspicious value); the TOCTOU
                    // "unreadable on re-read" case keeps the file too but
                    // records no signal. `.extend(signal.map(...))` folds
                    // that Some/None distinction into `Option`'s own
                    // combinator rather than a second branch here.
                    promoted.extend(signal.map(|s| (rel.clone(), s)));
                    rep_suspicious.extend(sus);
                }
            }
        }
        dropped.extend(cluster_dropped.iter().cloned());
        cluster_summaries.push(ClusterSummary {
            shape: hash.chars().take(12).collect(),
            size: members.len(),
            reps: {
                let mut r: Vec<String> = rep_set.into_iter().collect();
                r.sort();
                r
            },
            dropped: cluster_dropped.len(),
            sample: members[0].0.clone(),
        });
    }

    cluster_summaries.sort_by_key(|b| std::cmp::Reverse(b.size));
    keep.sort();

    let report = DedupReport {
        enabled: true,
        candidates: candidates.len(),
        unparseable_kept: unclustered.len(),
        clusters: cluster_summaries.len(),
        kept_reps: cluster_summaries.iter().map(|c| c.reps.len()).sum(),
        promoted,
        dropped,
        top_clusters: cluster_summaries,
    };
    (keep, report)
}

fn read_bounded_text(path: &Path, max_bytes: u64) -> Option<String> {
    let metadata = std::fs::metadata(path).ok()?;
    if metadata.len() > max_bytes {
        return None;
    }
    let bytes = std::fs::read(path).ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

enum MemberDecision {
    Drop,
    /// Kept either way; `signal` is `Some` only for a genuine promotion (a
    /// new suspicious value not already covered by the representative),
    /// `None` for the TOCTOU "unreadable on re-read" case.
    Keep {
        signal: Option<String>,
        sus: HashSet<String>,
    },
}

/// What to do with one non-representative cluster member, given its body
/// (or `None` if it could no longer be read on re-read — a TOCTOU race:
/// changed or removed since Pass 1's shape-hash scan). Split out from
/// `dedup_configs`'s loop so the `None` case is directly testable without
/// needing to race a real filesystem change mid-function-call.
fn decide_member(
    text: Option<&str>,
    rep_suspicious: &HashSet<String>,
    want_secret: bool,
    want_insecure: bool,
) -> MemberDecision {
    let Some(text) = text else {
        return MemberDecision::Keep {
            signal: None,
            sus: HashSet::new(),
        };
    };
    let sus = suspicious_set(text, want_secret, want_insecure);
    let mut extra: Vec<&String> = sus.difference(rep_suspicious).collect();
    if extra.is_empty() {
        return MemberDecision::Drop;
    }
    extra.sort();
    let signal = extra[0].clone();
    MemberDecision::Keep {
        signal: Some(signal),
        sus,
    }
}

/// Pick the most production-relevant variant as the cluster representative:
/// prod-like paths first, then larger files, then lexical path order (a
/// stable, deterministic tiebreak).
fn rep_score(rel: &str, size: u64) -> (u8, std::cmp::Reverse<u64>, String) {
    let low = rel.to_lowercase();
    let env_tier = if low.contains("/prod") {
        0
    } else if ["/cert", "/stag", "/stg"].iter().any(|e| low.contains(e)) {
        1
    } else if ["/perf", "/qa"].iter().any(|e| low.contains(e)) {
        2
    } else {
        3
    };
    (env_tier, std::cmp::Reverse(size), rel.to_string())
}

static YAML_KEY_RX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^( *)(?:- +)?([\w.\-]+)\s*:").unwrap());
static KV_LINE_RX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*([A-Za-z0-9_.\-]+)\s*[:=]").unwrap());

fn yaml_shape_keys(text: &str) -> Vec<String> {
    let mut stack: Vec<(usize, String)> = Vec::new();
    let mut keys = Vec::new();
    for line in text.lines() {
        if line.is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let Some(caps) = YAML_KEY_RX.captures(line) else {
            continue;
        };
        let indent = caps[1].len();
        let name = caps[2].to_string();
        while stack.last().is_some_and(|(i, _)| *i >= indent) {
            stack.pop();
        }
        stack.push((indent, name));
        keys.push(
            stack
                .iter()
                .map(|(_, n)| n.as_str())
                .collect::<Vec<_>>()
                .join("."),
        );
    }
    keys
}

fn generic_kv_keys(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| KV_LINE_RX.captures(line).map(|c| c[1].to_string()))
        .collect()
}

/// A scoped port of `configparser.ConfigParser(strict=False,
/// allow_no_value=True)`'s section/option scan — just enough to produce
/// `section.option` key paths for shape-hashing, not full INI semantics
/// (no continuation lines, no `%()s` interpolation). Returns `None` for
/// content appearing before any `[section]` header, mirroring
/// `MissingSectionHeaderError`.
fn ini_keys(text: &str) -> Option<Vec<String>> {
    let mut keys = Vec::new();
    let mut section = String::new();
    let mut has_section = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix('[') {
            let name = rest.strip_suffix(']')?;
            section = name.to_string();
            has_section = true;
            continue;
        }
        if !has_section {
            return None;
        }
        let key = match trimmed.find(['=', ':']) {
            Some(idx) => trimmed[..idx].trim(),
            None => trimmed,
        };
        if !key.is_empty() {
            keys.push(format!("{section}.{key}"));
        }
    }
    Some(keys)
}

fn flatten_json_keys(value: &Value, prefix: &str) -> Vec<String> {
    match value {
        Value::Object(map) => {
            let mut out = Vec::new();
            for (k, v) in map {
                let next = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                out.extend(flatten_json_keys(v, &next));
            }
            if out.is_empty() {
                vec![prefix.to_string()]
            } else {
                out
            }
        }
        Value::Array(items) => {
            let mut out = Vec::new();
            for item in items {
                out.extend(flatten_json_keys(item, &format!("{prefix}[]")));
            }
            if out.is_empty() {
                vec![prefix.to_string()]
            } else {
                out
            }
        }
        _ => vec![prefix.to_string()],
    }
}

/// Hash of the sorted, deduplicated key-path set (values stripped) — same
/// shape ⇒ same hash regardless of values. `None` means "keep the file
/// unconditionally" (unparseable or structurally empty).
fn shape_hash(text: &str, ext: &str) -> Option<String> {
    let keys: Vec<String> = match ext {
        ".yml" | ".yaml" => yaml_shape_keys(text),
        ".json" => {
            let value: Value = serde_json::from_str(text).ok()?;
            flatten_json_keys(&value, "")
        }
        ".ini" | ".cfg" | ".conf" => ini_keys(text)?,
        _ => generic_kv_keys(text),
    };
    if keys.is_empty() {
        return None;
    }
    let unique: std::collections::BTreeSet<&String> = keys.iter().collect();
    let joined = unique
        .into_iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join("\n");
    let mut hasher = Sha1::new();
    hasher.update(joined.as_bytes());
    Some(
        hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
    )
}

// Layer-2 safety net: literal credential material that must never be
// silently dropped by the shape-only comparison above. Negative lookahead
// skips templated/encrypted refs (`{{var}}`, `${VAR}`, `CRYPT:...`,
// `ENC(...)`, `<%= ... %>`, `vault:...`) and nested-key false positives
// (`auth-token:\n  timeout:` — the "value" looks like another key).
static SECRET_RX: LazyLock<FancyRegex> = LazyLock::new(|| {
    FancyRegex::new(
        r#"(?i)(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|auth[_-]?token|private[_-]?key|client[_-]?secret|credential)s?[ \t]*[:=][ \t]*['"]?(?!CRYPT:|ENC\(|\{\{|\$\{|<%=|<%|vault:|secret:|file:|/)(?![\w.-]+[ \t]*:)[^\s'",}{]{8,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|\bAKIA[0-9A-Z]{16}\b|\bxox[baprs]-[0-9A-Za-z-]{10,}\b|\bgh[pousr]_[0-9A-Za-z]{36,}\b|\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"#,
    )
    .unwrap()
});

// Insecure *values* (not secrets) whose presence makes a config variant
// worth scanning even if its shape matches a safe sibling.
static INSECURE_RX: LazyLock<FancyRegex> = LazyLock::new(|| {
    FancyRegex::new(
        r#"(?i)\b(?:verify|verif(?:y|ication)[_-]?ssl|ssl[_-]?verify|validate[_-]?cert\w*|tls[_-]?verify|check[_-]?hostname|reject[_-]?unauthori[sz]ed)\b\s*[:=]\s*['"]?(?:false|0|no|none|off)\b|\binsecure\w*\s*[:=]\s*['"]?(?:true|1|yes)\b|\bInsecureSkipVerify\s*[:=]\s*true\b|\b(?:auth|authentication|authn|security)\s*[:=]\s*['"]?(?:none|disabled|off|false)\b|\bdebug\s*[:=]\s*['"]?(?:true|1|yes)\b|\ballow[_-]?anonymous\s*[:=]\s*['"]?(?:true|1|yes)\b"#,
    )
    .unwrap()
});

fn normalize_match(m: &str) -> String {
    let collapsed: String = m.split_whitespace().collect::<Vec<_>>().join(" ");
    collapsed.chars().take(80).collect()
}

/// Normalized set of suspicious-pattern hits — used to diff a candidate
/// against its cluster representative so only *new* signals trigger a
/// promotion (keep), not ones the representative already carries.
fn suspicious_set(text: &str, want_secret: bool, want_insecure: bool) -> HashSet<String> {
    let mut out = HashSet::new();
    if want_secret {
        for m in SECRET_RX.find_iter(text) {
            let Ok(m) = m else { break };
            out.insert(format!("secret:{}", normalize_match(m.as_str())));
        }
    }
    if want_insecure {
        for m in INSECURE_RX.find_iter(text) {
            let Ok(m) = m else { break };
            out.insert(format!("insecure:{}", normalize_match(m.as_str())));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, rel: &str, contents: &str) {
        let path = dir.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }

    // ── shape_hash: YAML ────────────────────────────────────────────────

    #[test]
    fn yaml_same_shape_different_values_hashes_equal() {
        let a = shape_hash("a: 1\nb: 2\n", ".yaml");
        let b = shape_hash("a: 99\nb: hello\n", ".yaml");
        assert!(a.is_some());
        assert_eq!(a, b);
    }

    #[test]
    fn yaml_different_keys_hash_differently() {
        let a = shape_hash("a: 1\n", ".yaml");
        let b = shape_hash("b: 1\n", ".yaml");
        assert_ne!(a, b);
    }

    #[test]
    fn yaml_nested_keys_use_dotted_paths() {
        let keys = yaml_shape_keys("a:\n  b: 1\n  c: 2\n");
        assert_eq!(keys, vec!["a", "a.b", "a.c"]);
    }

    #[test]
    fn yaml_sibling_at_same_indent_pops_the_previous_child() {
        let keys = yaml_shape_keys("a:\n  b: 1\nc: 2\n");
        assert_eq!(keys, vec!["a", "a.b", "c"]);
    }

    #[test]
    fn yaml_comments_and_blank_lines_are_ignored() {
        let keys = yaml_shape_keys("# comment\n\na: 1\n");
        assert_eq!(keys, vec!["a"]);
    }

    #[test]
    fn yaml_list_item_dash_prefix_does_not_count_as_indent() {
        let keys = yaml_shape_keys("items:\n  - name: x\n");
        assert_eq!(keys, vec!["items", "items.name"]);
    }

    #[test]
    fn yaml_with_no_matching_keys_is_none() {
        assert_eq!(shape_hash("just some prose\nno keys here\n", ".yaml"), None);
    }

    // ── shape_hash: JSON ─────────────────────────────────────────────────

    #[test]
    fn json_same_shape_different_values_hashes_equal() {
        let a = shape_hash(r#"{"a": 1, "b": "x"}"#, ".json");
        let b = shape_hash(r#"{"a": 999, "b": "y"}"#, ".json");
        assert!(a.is_some());
        assert_eq!(a, b);
    }

    #[test]
    fn json_different_keys_hash_differently() {
        let a = shape_hash(r#"{"a": 1}"#, ".json");
        let b = shape_hash(r#"{"b": 1}"#, ".json");
        assert_ne!(a, b);
    }

    #[test]
    fn json_nested_objects_and_arrays_flatten() {
        let value: Value = serde_json::from_str(r#"{"a": {"b": 1}, "c": [1, 2]}"#).unwrap();
        let mut keys = flatten_json_keys(&value, "");
        keys.sort();
        // Each array element independently produces its own "c[]" leaf —
        // duplicates are only collapsed later, by `shape_hash`'s
        // `sorted(set(...))` step, matching the Python original exactly.
        assert_eq!(keys, vec!["a.b", "c[]", "c[]"]);
    }

    #[test]
    fn json_empty_object_is_its_own_leaf() {
        let value: Value = serde_json::from_str(r#"{"a": {}}"#).unwrap();
        assert_eq!(flatten_json_keys(&value, ""), vec!["a"]);
    }

    #[test]
    fn json_empty_array_is_its_own_leaf() {
        let value: Value = serde_json::from_str(r#"{"a": []}"#).unwrap();
        assert_eq!(flatten_json_keys(&value, ""), vec!["a"]);
    }

    #[test]
    fn invalid_json_is_none() {
        assert_eq!(shape_hash("{not json", ".json"), None);
    }

    // ── shape_hash: INI ──────────────────────────────────────────────────

    #[test]
    fn ini_sections_and_options_hash_by_shape() {
        let a = shape_hash("[db]\nhost=1\nport=2\n", ".ini");
        let b = shape_hash("[db]\nhost=other\nport=99\n", ".ini");
        assert!(a.is_some());
        assert_eq!(a, b);
    }

    #[test]
    fn ini_content_before_any_section_is_none() {
        assert_eq!(shape_hash("host=1\n[db]\nport=2\n", ".ini"), None);
    }

    #[test]
    fn ini_bare_key_with_no_value_is_kept() {
        let keys = ini_keys("[flags]\nenabled\n").unwrap();
        assert_eq!(keys, vec!["flags.enabled"]);
    }

    #[test]
    fn ini_comments_and_blank_lines_are_ignored() {
        let keys = ini_keys("[db]\n; a comment\n# another\n\nhost=1\n").unwrap();
        assert_eq!(keys, vec!["db.host"]);
    }

    #[test]
    fn ini_unterminated_section_header_is_none() {
        assert_eq!(ini_keys("[db\nhost=1\n"), None);
    }

    // ── shape_hash: generic key/value (.properties, .env) ───────────────

    #[test]
    fn generic_kv_lines_hash_by_key_shape() {
        let a = shape_hash("FOO=1\nBAR=2\n", ".env");
        let b = shape_hash("FOO=one\nBAR=two\n", ".env");
        assert!(a.is_some());
        assert_eq!(a, b);
    }

    #[test]
    fn generic_kv_with_no_matching_lines_is_none() {
        assert_eq!(shape_hash("just some text\n", ".properties"), None);
    }

    // ── suspicious_set ───────────────────────────────────────────────────

    #[test]
    fn detects_a_literal_password() {
        let sus = suspicious_set("password: hunter2!!!\n", true, false);
        assert!(sus.iter().any(|s| s.starts_with("secret:")));
    }

    #[test]
    fn skips_a_templated_secret_reference() {
        let sus = suspicious_set("password: ${DB_PASSWORD}\n", true, false);
        assert!(sus.is_empty());
    }

    #[test]
    fn skips_a_nested_key_that_looks_like_a_value() {
        let sus = suspicious_set("auth_token:\n  timeout: 30\n", true, false);
        assert!(sus.is_empty());
    }

    #[test]
    fn detects_an_aws_access_key() {
        let sus = suspicious_set("AKIAAAAAAAAAAAAAAAAA", true, false);
        assert!(sus.iter().any(|s| s.starts_with("secret:")));
    }

    #[test]
    fn detects_an_insecure_tls_verify_false() {
        let sus = suspicious_set("ssl_verify: false\n", false, true);
        assert!(sus.iter().any(|s| s.starts_with("insecure:")));
    }

    #[test]
    fn respects_want_secret_and_want_insecure_flags() {
        let text = "password: realsecretvalue\nssl_verify: false\n";
        assert!(suspicious_set(text, false, false).is_empty());
        assert!(suspicious_set(text, true, false)
            .iter()
            .all(|s| s.starts_with("secret:")));
        assert!(suspicious_set(text, false, true)
            .iter()
            .all(|s| s.starts_with("insecure:")));
    }

    // ── rep_score ────────────────────────────────────────────────────────

    #[test]
    fn prod_beats_staging_beats_other() {
        assert!(rep_score("a/prod/x.yaml", 100) < rep_score("a/staging/x.yaml", 100));
        assert!(rep_score("a/staging/x.yaml", 100) < rep_score("a/dev/x.yaml", 100));
    }

    #[test]
    fn larger_file_preferred_within_same_env_tier() {
        assert!(rep_score("a/dev/big.yaml", 1000) < rep_score("a/dev/small.yaml", 10));
    }

    #[test]
    fn path_is_the_final_tiebreak() {
        assert!(rep_score("a/dev/a.yaml", 100) < rep_score("a/dev/b.yaml", 100));
    }

    // ── dedup_configs: end to end ────────────────────────────────────────

    #[test]
    fn disabled_config_is_a_no_op() {
        let dir = tempfile::tempdir().unwrap();
        let files = vec!["a.yaml".to_string()];
        let mut config = DedupConfig::new();
        config.enabled = false;
        let (kept, report) = dedup_configs(&files, dir.path(), &config);
        assert_eq!(kept, files);
        assert!(!report.enabled);
    }

    #[test]
    fn fewer_candidates_than_min_cluster_size_is_a_no_op() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.yaml", "x: 1\n");
        write(dir.path(), "b.yaml", "x: 2\n");
        let files = vec!["a.yaml".to_string(), "b.yaml".to_string()];
        let (kept, report) = dedup_configs(&files, dir.path(), &DedupConfig::new());
        assert_eq!(kept, files);
        assert_eq!(report.candidates, 2);
        assert_eq!(report.clusters, 0);
    }

    #[test]
    fn non_candidate_extensions_pass_through_untouched() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..3 {
            write(dir.path(), &format!("svc{i}/config.yaml"), "x: 1\n");
        }
        write(dir.path(), "main.rs", "fn main() {}\n");
        let files: Vec<String> = (0..3)
            .map(|i| format!("svc{i}/config.yaml"))
            .chain(["main.rs".to_string()])
            .collect();
        let (kept, _) = dedup_configs(&files, dir.path(), &DedupConfig::new());
        assert!(kept.contains(&"main.rs".to_string()));
    }

    #[test]
    fn a_singleton_shape_is_kept_unconditionally_alongside_a_real_cluster() {
        let dir = tempfile::tempdir().unwrap();
        // Cluster A: shape {host, port} x3.
        for i in 0..3 {
            write(
                dir.path(),
                &format!("a{i}/config.yaml"),
                &format!("host: h{i}\nport: {i}\n"),
            );
        }
        // Cluster B: a different shape {name, value} x3, so there are TWO
        // large clusters (exercising the cluster-summary sort with 2+
        // elements, not just a single trivially-already-sorted one).
        for i in 0..3 {
            write(
                dir.path(),
                &format!("b{i}/config.yaml"),
                &format!("name: n{i}\nvalue: {i}\n"),
            );
        }
        // A singleton, unique shape -- its own cluster of size 1, below
        // `min_cluster_size`, so it must be kept unconditionally rather
        // than going through representative-selection at all.
        write(dir.path(), "solo/config.yaml", "totally_unique_key: 1\n");

        let files: Vec<String> = (0..3)
            .map(|i| format!("a{i}/config.yaml"))
            .chain((0..3).map(|i| format!("b{i}/config.yaml")))
            .chain(["solo/config.yaml".to_string()])
            .collect();
        let (kept, report) = dedup_configs(&files, dir.path(), &DedupConfig::new());
        assert!(kept.contains(&"solo/config.yaml".to_string()));
        assert_eq!(report.clusters, 2);
        assert_eq!(report.top_clusters.len(), 2);
    }

    #[test]
    fn a_cluster_of_identical_shape_files_is_deduped_to_one_rep_per_top_dir() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..3 {
            write(
                dir.path(),
                &format!("svc{i}/dev/config.yaml"),
                &format!("host: h{i}\nport: {i}\n"),
            );
        }
        let files: Vec<String> = (0..3).map(|i| format!("svc{i}/dev/config.yaml")).collect();
        let (kept, report) = dedup_configs(&files, dir.path(), &DedupConfig::new());
        // keep_per_top_dir=true and each file has a DIFFERENT top dir
        // (svc0/svc1/svc2), so every one of them is its own top-dir rep —
        // nothing is actually dropped in this shape.
        assert_eq!(kept.len(), 3);
        assert_eq!(report.clusters, 1);
        assert_eq!(report.dropped.len(), 0);
    }

    #[test]
    fn a_cluster_sharing_one_top_dir_drops_all_but_one_representative() {
        let dir = tempfile::tempdir().unwrap();
        for env in ["dev", "qa", "staging"] {
            write(
                dir.path(),
                &format!("svc/{env}/config.yaml"),
                &format!("host: h-{env}\nport: 1\n"),
            );
        }
        let files: Vec<String> = ["dev", "qa", "staging"]
            .iter()
            .map(|e| format!("svc/{e}/config.yaml"))
            .collect();
        let (kept, report) = dedup_configs(&files, dir.path(), &DedupConfig::new());
        // All three share the SAME top dir ("svc"), so keep_per_top_dir
        // collapses them to exactly one representative -- staging (env
        // tier 1) beats dev/qa (tier 2/3... wait qa is tier 2, dev is
        // tier 3) so staging wins.
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0], "svc/staging/config.yaml");
        assert_eq!(report.dropped.len(), 2);
    }

    #[test]
    fn a_promoted_file_carrying_a_new_secret_is_kept_not_dropped() {
        let dir = tempfile::tempdir().unwrap();
        // All three share the SAME key shape (host/port/password) so they
        // cluster together; only qa's *value* for `password` is a real
        // leaked secret rather than a templated reference the negative
        // lookahead skips.
        write(
            dir.path(),
            "svc/dev/config.yaml",
            "host: h1\nport: 1\npassword: ${DB_PASSWORD}\n",
        );
        write(
            dir.path(),
            "svc/qa/config.yaml",
            "host: h2\nport: 1\npassword: realsecretvalue123\n",
        );
        write(
            dir.path(),
            "svc/staging/config.yaml",
            "host: h3\nport: 1\npassword: ${DB_PASSWORD}\n",
        );
        let files: Vec<String> = ["dev", "qa", "staging"]
            .iter()
            .map(|e| format!("svc/{e}/config.yaml"))
            .collect();
        let (kept, report) = dedup_configs(&files, dir.path(), &DedupConfig::new());
        // staging (tier 1) is the sole top-dir rep; dev (templated,
        // matches staging's own signal set) gets dropped, qa (a genuine
        // new secret) gets promoted.
        assert!(kept.contains(&"svc/staging/config.yaml".to_string()));
        assert!(kept.contains(&"svc/qa/config.yaml".to_string()));
        assert!(!kept.contains(&"svc/dev/config.yaml".to_string()));
        assert_eq!(report.promoted.len(), 1);
        assert_eq!(report.promoted[0].0, "svc/qa/config.yaml");
        assert_eq!(report.dropped, vec!["svc/dev/config.yaml".to_string()]);
    }

    #[test]
    fn keep_per_top_dir_false_collapses_to_one_global_representative() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..3 {
            write(
                dir.path(),
                &format!("svc{i}/dev/config.yaml"),
                &format!("host: h{i}\nport: 1\n"),
            );
        }
        let files: Vec<String> = (0..3).map(|i| format!("svc{i}/dev/config.yaml")).collect();
        let mut config = DedupConfig::new();
        config.keep_per_top_dir = false;
        let (kept, _) = dedup_configs(&files, dir.path(), &config);
        assert_eq!(kept.len(), 1);
    }

    #[test]
    fn unparseable_candidates_are_kept_unconditionally() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..3 {
            write(
                dir.path(),
                &format!("svc{i}/dev/config.json"),
                "not valid json",
            );
        }
        let files: Vec<String> = (0..3).map(|i| format!("svc{i}/dev/config.json")).collect();
        let (kept, report) = dedup_configs(&files, dir.path(), &DedupConfig::new());
        assert_eq!(kept.len(), 3);
        assert_eq!(report.unparseable_kept, 3);
    }

    #[test]
    fn oversize_candidates_are_treated_as_unparseable_and_kept() {
        let dir = tempfile::tempdir().unwrap();
        let big = "x: 1\n".to_string() + &"# padding\n".repeat(1000);
        for i in 0..3 {
            write(dir.path(), &format!("svc{i}/dev/config.yaml"), &big);
        }
        let files: Vec<String> = (0..3).map(|i| format!("svc{i}/dev/config.yaml")).collect();
        let mut config = DedupConfig::new();
        config.max_file_kb = 0; // every file exceeds this
        let (kept, report) = dedup_configs(&files, dir.path(), &config);
        assert_eq!(kept.len(), 3);
        assert_eq!(report.unparseable_kept, 3);
    }

    #[test]
    fn dedup_config_default_matches_new() {
        assert_eq!(DedupConfig::default(), DedupConfig::new());
    }

    #[test]
    fn decide_member_keeps_without_a_signal_when_unreadable_on_re_read() {
        // The TOCTOU case (changed/removed between Pass 1 and Pass 2) --
        // not reproducible deterministically via real file I/O within one
        // synchronous call, so exercised directly with `text: None`.
        let decision = decide_member(None, &HashSet::new(), true, true);
        assert!(matches!(
            decision,
            MemberDecision::Keep { signal: None, .. }
        ));
    }

    #[test]
    fn decide_member_drops_a_member_with_no_new_suspicious_signal() {
        let rep_sus = HashSet::new();
        let decision = decide_member(Some("host: h1\nport: 1\n"), &rep_sus, true, true);
        assert!(matches!(decision, MemberDecision::Drop));
    }

    #[test]
    fn decide_member_promotes_a_member_with_a_new_suspicious_signal() {
        let rep_sus = HashSet::new();
        let decision = decide_member(Some("password: realsecretvalue123\n"), &rep_sus, true, true);
        assert!(
            matches!(&decision, MemberDecision::Keep { signal: Some(s), sus } if s.starts_with("secret:") && !sus.is_empty()),
            "unexpected decision"
        );
    }
}
