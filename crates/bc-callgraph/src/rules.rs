//! Convert `sources.generated.yaml` / `sinks.generated.yaml` (semgrep-format
//! rule files, but with rich `metadata.*` fields read directly) into
//! structured [`MatchSpec`] records the tree-sitter scanner can use.
//! Ported from `vvaharness/pipeline/stages/callgraph_engine/_rules.py`.
//!
//! Four match categories per rule:
//!   * `qualified` — package + class + method-set (CodeQL / FSB origins)
//!   * `module_attr` — best-effort parse of a semgrep call-shape pattern
//!     like `pickle.loads(...)` or `os.system(...)` (semgrep origin)
//!   * `bare_call` — a receiver-less call shape, `open(...)` / `eval(...)`
//!   * `receiver_method` — semgrep's receiver-metavariable shape,
//!     `$CUR.execute(...)`: any receiver, named method
//!
//! **The last two are divergences from `_rules.py`, and both fix rules
//! that silently never matched.** Python's `_try_module_attr` (and this
//! port's first cut of it) only accepts `MODULE_ATTR_RX`, whose captured
//! group requires at least one `.`, so a `pattern: open(...)` leaf parses
//! to nothing and its rule yields *zero* `MatchSpec`s — the bundled
//! corpus's `py.open-file`, `py.eval-exec` (two leaves) and `js.eval`
//! were dead on arrival. Receiver-method shapes were not expressible at
//! all, which is why the corpus carried a `sqlite3.connect(...)` proxy in
//! place of the real `cursor.execute(...)` SQL sink; that proxy takes no
//! query argument, so no Python SQL path could ever ground in evidence.
//!
//! Rules whose patterns are too complex for this translator (regex-only
//! bodies, nested pattern-either trees, etc.) are omitted from the
//! callgraph engine's view; simplify or pre-compile those patterns before
//! using them as S0 inputs.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;

use crate::families;

/// A rule/YAML load failure — a malformed file, not merely an absent one
/// (a missing or unset path is a legitimate "no rules configured" case,
/// see [`load_rulepacks`]'s own doc comment). Ported from the *shape* of
/// `_rules.py::_load`'s behavior: a present-but-unparseable file raises in
/// the Python original (propagating to the S0 wrapper's own try/except,
/// which degrades to an empty seed); this is a typed `Err` instead so
/// that decision stays with the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RulesError {
    pub message: String,
}

impl RulesError {
    pub fn new(message: impl Into<String>) -> Self {
        RulesError {
            message: message.into(),
        }
    }
}

impl fmt::Display for RulesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for RulesError {}

/// The YAML `languages:` field uses semgrep's language keys, which are
/// 1:1 with our language keys for the [`families::VVAH_LANGUAGES`] this
/// engine supports today, plus a few more that rule packs may reference
/// even though no extractor is wired for them yet. Mirrors
/// `_SEMGREP_TO_VVAH` — kept as its own table (distinct from
/// `families::canonical_lang`'s alias table) so any future divergence
/// between "how a rule pack spells a language" and "how an operator's
/// `step0.languages` config spells one" lives in exactly one place each.
fn semgrep_to_vvah(key: &str) -> Option<&'static str> {
    Some(match key {
        "python" => "python",
        "java" => "java",
        "javascript" => "javascript",
        "typescript" => "typescript",
        "go" => "go",
        "csharp" => "csharp",
        "kotlin" => "kotlin",
        "scala" => "scala",
        "ruby" => "ruby",
        "php" => "php",
        "rust" => "rust",
        "c" | "cpp" => "c-cpp",
        _ => return None,
    })
}

/// A single API pattern the scanner can look for.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MatchSpec {
    pub rule_id: String,
    /// `"source"` | `"sink"`.
    pub role: String,
    /// `"semgrep"` | `"codeql"` | `"fsb"` | `"llm"`.
    pub origin: String,
    pub cwe: String,
    /// `ep_kind` (sources) / `sink_kind` (sinks).
    pub kind: String,
    pub languages: BTreeSet<String>,
    /// Iteration B semantic sink/source class.
    pub semantic_family: String,
    pub owasp_top10_2025: BTreeSet<String>,

    // STRUCTURED match (codeql / fsb): match a call whose receiver's
    // static type is `class_name` (imported from `package`) AND whose
    // method is in `methods`. Optional constructor form
    // (`is_constructor: true`) matches `new <leaf_class>(...)`.
    pub package: String,
    /// Source-form (may contain '.').
    pub class_name: String,
    /// Top segment, for import matching.
    pub top_class: String,
    pub methods: BTreeSet<String>,
    pub is_constructor: bool,

    // SEMGREP-LIFTED module-attribute match: a call of the form
    // `<module>.<attr>(...)` where `<module>` is this name (bare first
    // segment). Attrs are the method-name set.
    pub module_attr_module: String,
    pub module_attr_names: BTreeSet<String>,

    /// SEMGREP-LIFTED bare-call match: a call of the form `<name>(...)`
    /// with no receiver at all — `open(...)`, `eval(...)`, or a
    /// `from flask import send_file` handler's `send_file(...)`.
    pub bare_call_names: BTreeSet<String>,
    /// SEMGREP-LIFTED receiver-method match: a call of the form
    /// `<anything>.<name>(...)`, written in semgrep's own receiver
    /// -metavariable syntax (`$CUR.execute(...)`). This is the only way
    /// to express an instance-method sink — `cursor.execute`,
    /// `Statement.executeQuery`, `SqlCommand.ExecuteReader` — whose
    /// receiver is a local variable rather than an imported module.
    pub receiver_method_names: BTreeSet<String>,
    /// `metadata.requires_dynamic_arg: true` — only match a call whose
    /// first positional argument is *not* a static string literal.
    /// `cur.execute("SELECT … WHERE email LIKE ?", (email,))` binds its
    /// parameters and is not an injection sink; `cur.execute("…" + p)`
    /// and `cur.execute(query)` both are.
    pub requires_dynamic_arg: bool,
    /// `metadata.requires_any_arg: true` — only match a call that
    /// passes at least one argument. A JDBC `statement.executeQuery()`
    /// with no argument is the *prepared* form: the SQL text was fixed
    /// when the statement was prepared, so there is nothing at this
    /// call site to inject into. It is per-rule rather than folded into
    /// [`MatchSpec::requires_dynamic_arg`] because ADO.NET's
    /// `cmd.ExecuteReader()` is the opposite case — its query lives in
    /// `cmd.CommandText`, so the zero-argument form is exactly the one
    /// worth flagging.
    pub requires_any_arg: bool,
    /// Which argument `requires_dynamic_arg` judges, `0` by default.
    /// The C `printf` family puts its format string second
    /// (`fprintf(stream, fmt)`) or third (`snprintf(dst, n, fmt)`), and
    /// a format string that is not a literal is CWE-134 — so the flag
    /// has to be able to look somewhere other than argument 0.
    pub dynamic_arg_index: usize,
    /// `metadata.requires_arithmetic_arg: true` — only match a call
    /// whose argument at [`MatchSpec::arithmetic_arg_index`] is an
    /// ARITHMETIC expression (a `*` or `+` of two or more operands)
    /// rather than a bare name, a literal or a `sizeof`. The same kind
    /// of predicate-over-an-argument as
    /// [`MatchSpec::requires_dynamic_arg`], asking a different question
    /// about the argument's syntax: `malloc(count * size)` computes its
    /// allocation size at the call site and can wrap (CWE-190), while
    /// `malloc(len)` cannot and must not be flagged.
    ///
    /// **Polarity, and why it differs from `requires_dynamic_arg`.** An
    /// extractor that computes no argument shapes reports an empty
    /// vector. For `requires_dynamic_arg` that reads as "not a literal"
    /// and the rule keeps matching; for this flag it reads as "not
    /// arithmetic" and the rule goes DARK. That is unavoidable — this
    /// is a positive requirement, not a veto — so a rule carrying it
    /// must name only languages whose extractor computes the answer.
    /// Today that is C/C++ alone (see `scan::lite::C_CPP`).
    pub requires_arithmetic_arg: bool,
    /// Which argument `requires_arithmetic_arg` judges, `0` by default.
    /// `malloc(n)`/`alloca(n)` size first, `realloc(p, n)` second — the
    /// same reason [`MatchSpec::dynamic_arg_index`] exists.
    pub arithmetic_arg_index: usize,
    /// `metadata.requires_unit_arg: true` — only match a call whose
    /// argument at [`MatchSpec::unit_arg_index`] is the integer literal
    /// `1`. The third argument predicate, built like the other two and
    /// carrying `requires_arithmetic_arg`'s polarity: an extractor that
    /// computes no answer leaves a rule asking for it DARK.
    ///
    /// **Why a second flag rather than a wider one.** Each predicate
    /// states a condition at ONE argument, and
    /// [`crate::scan::match_call`] requires every predicate a spec
    /// carries — so a spec naming two of them is already a conjunction
    /// across two arguments, and the corpus can spell one without any
    /// new matching machinery. That is what
    /// `c.calloc-hand-multiplied-size` does: arithmetic at 0 AND a unit
    /// size at 1, which is `calloc(n * size, 1)` and nothing else.
    /// `calloc(n, size)` is the safe idiom and stays unflagged because
    /// argument 0 is not arithmetic; `calloc(len + 1, sizeof(char))`
    /// stays unflagged because `sizeof(char)` is not the literal `1`
    /// even though it equals it. Folding the pair into one hard-coded
    /// "calloc shape" test in Rust would have put the rule in the
    /// engine instead of the corpus, where every other sink lives.
    pub requires_unit_arg: bool,
    /// Which argument `requires_unit_arg` judges, `0` by default. The
    /// one rule that asks reads `calloc`'s element size, at `1`.
    pub unit_arg_index: usize,

    // Translation metadata for auditability: when Semgrep patterns are
    // flattened into module-attribute call shapes, preserve what was
    // parsed vs dropped so downstream stages and tests can reason about
    // fidelity.
    pub total_pattern_leaves: usize,
    pub parsed_pattern_leaves: BTreeSet<String>,
    pub dropped_pattern_leaves: BTreeSet<String>,
    pub translation_flags: BTreeSet<String>,
}

impl MatchSpec {
    pub fn has_qualified(&self) -> bool {
        !self.methods.is_empty() && !self.class_name.is_empty() && !self.package.is_empty()
    }

    pub fn has_module_attr(&self) -> bool {
        !self.module_attr_module.is_empty() && !self.module_attr_names.is_empty()
    }

    pub fn has_bare_call(&self) -> bool {
        !self.bare_call_names.is_empty()
    }

    pub fn has_receiver_method(&self) -> bool {
        !self.receiver_method_names.is_empty()
    }
}

// ── extractors ──────────────────────────────────────────────────────────

/// Semgrep pattern grep: `<name>.<name>[.<name>]*(...)` at the top level.
static MODULE_ATTR_RX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+)\s*\(").unwrap()
});
/// Regex alternation body inside `metavariable-regex`: `^(a|b|c)$` ->
/// `["a","b","c"]`.
static ALT_BODY_RX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*\^?\s*\(([^)]+)\)\s*\$?\s*$").unwrap());
static IDENT_RX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*$").unwrap());
/// Semgrep receiver-metavariable call shape: `$CUR.execute(...)` ->
/// `"execute"`. Tried before [`BARE_CALL_RX`], which its leading `$`
/// already excludes.
static RECEIVER_METHOD_RX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*\$[A-Za-z_][A-Za-z0-9_]*\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(").unwrap()
});
/// Receiver-less call shape: `open(...)` -> `"open"`. Tried last, so a
/// dotted `os.system(...)` leaf always lands in [`MODULE_ATTR_RX`].
static BARE_CALL_RX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(").unwrap());

fn is_truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Number(n)) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
    }
}

/// `str(meta.get(key) or "")` — a missing, null, or non-string value
/// collapses to `""` rather than propagating; every real rule-pack value
/// here is already a plain YAML string.
fn meta_string(meta: Option<&serde_json::Map<String, Value>>, key: &str) -> String {
    meta.and_then(|m| m.get(key))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

fn value_as_lower_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.to_lowercase(),
        other => other.to_string().to_lowercase(),
    }
}

fn norm_langs(raw_langs: Option<&Value>) -> BTreeSet<String> {
    let Some(arr) = raw_langs.and_then(Value::as_array) else {
        return BTreeSet::new();
    };
    arr.iter()
        .filter_map(|l| semgrep_to_vvah(&value_as_lower_string(l)))
        .map(String::from)
        .collect()
}

fn extract_methods_from_regex(pattern: &str) -> BTreeSet<String> {
    let Some(caps) = ALT_BODY_RX.captures(pattern) else {
        return BTreeSet::new();
    };
    caps[1]
        .split('|')
        .map(str::trim)
        .filter(|p| !p.is_empty() && IDENT_RX.is_match(p))
        .map(String::from)
        .collect()
}

/// Walk a rule's `patterns:` list looking for `{metavariable-regex: {
/// metavariable: $NAME, regex: ...}}` and return the alternation set.
fn metavar_methods(rule: &Value, metavar_name: &str) -> BTreeSet<String> {
    let Some(patterns) = rule.get("patterns").and_then(Value::as_array) else {
        return BTreeSet::new();
    };
    for pat in patterns {
        let Some(mvr) = pat.get("metavariable-regex") else {
            continue;
        };
        if mvr.get("metavariable").and_then(Value::as_str) != Some(metavar_name) {
            continue;
        }
        let regex_str = mvr.get("regex").and_then(Value::as_str).unwrap_or("");
        return extract_methods_from_regex(regex_str);
    }
    BTreeSet::new()
}

/// Recursively collect every leaf `pattern: <str>` inside an arbitrarily
/// nested semgrep patterns tree (`patterns` -> `pattern-either` ->
/// `patterns` -> ...). Duplicates are preserved (not deduplicated) —
/// callers that need a distinct set collect into a `BTreeSet` themselves.
fn walk_pattern_leaves(node: &Value, out: &mut Vec<String>) {
    match node {
        Value::Object(map) => {
            for (k, v) in map {
                if k == "pattern" {
                    if let Some(s) = v.as_str() {
                        out.push(s.to_string());
                        continue;
                    }
                }
                if v.is_object() || v.is_array() {
                    walk_pattern_leaves(v, out);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                walk_pattern_leaves(item, out);
            }
        }
        _ => {}
    }
}

/// Collect every dict key in a nested semgrep rule tree.
fn walk_rule_keys(node: &Value, out: &mut BTreeSet<String>) {
    match node {
        Value::Object(map) => {
            for (k, v) in map {
                out.insert(k.clone());
                if v.is_object() || v.is_array() {
                    walk_rule_keys(v, out);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                walk_rule_keys(item, out);
            }
        }
        _ => {}
    }
}

/// Infer a stable semantic family from sink/source metadata.
///
/// Intentionally coarse and repo-agnostic so grouping can work across
/// framework-specific APIs and wrapper layers. The result is only ever
/// used as a fallback into [`families::resolve_semantic_family`], which
/// clamps it to the canonical vocabulary — it need not itself be a
/// canonical family name.
fn normalize_family(kind: &str, cwe: &str, rule_id: &str, rule: &Value) -> String {
    let k = kind.trim().to_lowercase();
    let rid = rule_id.to_lowercase();
    let c = cwe.to_uppercase();
    let mut leaves = Vec::new();
    walk_pattern_leaves(rule, &mut leaves);
    let leaf_patterns = leaves.join("\n").to_lowercase();

    if c.contains("79")
        || matches!(k.as_str(), "xss" | "template")
        || rid.contains("raw-html-format")
        || leaf_patterns.contains("response(")
        || leaf_patterns.contains("render_template")
        || leaf_patterns.contains("htmlresponse")
    {
        return "html-response".to_string();
    }
    if c.contains("78") || matches!(k.as_str(), "cmd" | "dyn-eval") || rid.contains("subprocess") {
        return "command-exec".to_string();
    }
    if c.contains("89") || c.contains("90") || k == "sql" {
        return "sql-exec".to_string();
    }
    if c.contains("918") || k == "ssrf" {
        return "url-fetch".to_string();
    }
    if c.contains("22") || k == "path" {
        return "file-io".to_string();
    }
    if c.contains("502") || k == "deserialize" {
        return "deserialization".to_string();
    }
    if matches!(k.as_str(), "credentials" | "secret") {
        return "credentials".to_string();
    }
    if k.is_empty() {
        "other".to_string()
    } else {
        k
    }
}

fn translation_flags(rule: &Value, parsed_count: usize, total_count: usize) -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    walk_rule_keys(rule, &mut keys);
    let mut flags = BTreeSet::new();
    if keys.contains("patterns") || keys.contains("pattern-either") {
        flags.insert("nested-patterns".to_string());
    }
    if keys.contains("pattern-not") || keys.contains("pattern-not-inside") {
        flags.insert("negative-patterns".to_string());
    }
    if keys.contains("pattern-regex") || keys.contains("pattern-not-regex") {
        flags.insert("regex-patterns".to_string());
    }
    if keys.contains("metavariable-regex") {
        flags.insert("metavariable-constraints".to_string());
    }
    if total_count > 0 && parsed_count == 0 {
        flags.insert("no-parseable-module-attr".to_string());
    } else if total_count > 0 && parsed_count < total_count {
        flags.insert("partial-pattern-coverage".to_string());
    }
    flags
}

/// Parse every call-shape leaf in a semgrep-lifted rule. Emits ONE
/// [`MatchSpec`] per unique module-root (with all seen method names
/// merged into `module_attr_names`), plus at most one bare-call spec and
/// one receiver-method spec for the leaves that use those shapes.
/// Returns `[]` if no shapes are parseable.
fn try_module_attr(
    rule_id: &str,
    role: &str,
    origin: &str,
    cwe: &str,
    kind: &str,
    langs: &BTreeSet<String>,
    rule: &Value,
) -> Vec<MatchSpec> {
    let mut all_leaves = Vec::new();
    walk_pattern_leaves(rule, &mut all_leaves);

    let mut by_module: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut bare_names: BTreeSet<String> = BTreeSet::new();
    let mut receiver_names: BTreeSet<String> = BTreeSet::new();
    let mut parsed_leaves: BTreeSet<String> = BTreeSet::new();
    for leaf in &all_leaves {
        if let Some(caps) = MODULE_ATTR_RX.captures(leaf) {
            parsed_leaves.insert(leaf.clone());
            // `MODULE_ATTR_RX`'s captured group requires the first
            // identifier plus a `+` (one-or-more) repetition of
            // `.identifier`, so a successful match always yields >=2
            // dot-separated parts — no length check needed (Python's own
            // `_try_module_attr` carries the same guarantee, unchecked).
            let dotted = &caps[1];
            let parts: Vec<&str> = dotted.split('.').collect();
            by_module
                .entry(parts[0].to_string())
                .or_default()
                .insert((*parts.last().unwrap()).to_string());
            continue;
        }
        if let Some(caps) = RECEIVER_METHOD_RX.captures(leaf) {
            parsed_leaves.insert(leaf.clone());
            receiver_names.insert(caps[1].to_string());
            continue;
        }
        if let Some(caps) = BARE_CALL_RX.captures(leaf) {
            parsed_leaves.insert(leaf.clone());
            bare_names.insert(caps[1].to_string());
        }
    }

    let meta = rule.get("metadata");
    let fallback = normalize_family(kind, cwe, rule_id, rule);
    let semantic_family = families::resolve_semantic_family(meta, &fallback).to_string();
    let owasp_tags: BTreeSet<String> = families::owasp_labels(&semantic_family)
        .iter()
        .map(|s| s.to_string())
        .collect();
    let all_leaves_set: BTreeSet<String> = all_leaves.iter().cloned().collect();
    let dropped_leaves: BTreeSet<String> =
        all_leaves_set.difference(&parsed_leaves).cloned().collect();
    let total_count = all_leaves.len();
    let parsed_count = parsed_leaves.len();
    let flags = translation_flags(rule, parsed_count, total_count);

    let requires_dynamic_arg = is_truthy(meta.and_then(|m| m.get("requires_dynamic_arg")));
    let requires_any_arg = is_truthy(meta.and_then(|m| m.get("requires_any_arg")));
    let dynamic_arg_index = meta
        .and_then(|m| m.get("dynamic_arg_index"))
        .and_then(Value::as_u64)
        .unwrap_or(0) as usize;
    let requires_arithmetic_arg = is_truthy(meta.and_then(|m| m.get("requires_arithmetic_arg")));
    let arithmetic_arg_index = meta
        .and_then(|m| m.get("arithmetic_arg_index"))
        .and_then(Value::as_u64)
        .unwrap_or(0) as usize;
    let requires_unit_arg = is_truthy(meta.and_then(|m| m.get("requires_unit_arg")));
    let unit_arg_index = meta
        .and_then(|m| m.get("unit_arg_index"))
        .and_then(Value::as_u64)
        .unwrap_or(0) as usize;
    let base = MatchSpec {
        rule_id: rule_id.to_string(),
        role: role.to_string(),
        origin: origin.to_string(),
        cwe: cwe.to_string(),
        kind: kind.to_string(),
        languages: langs.clone(),
        semantic_family,
        owasp_top10_2025: owasp_tags,
        requires_dynamic_arg,
        requires_any_arg,
        dynamic_arg_index,
        requires_arithmetic_arg,
        arithmetic_arg_index,
        requires_unit_arg,
        unit_arg_index,
        total_pattern_leaves: total_count,
        parsed_pattern_leaves: parsed_leaves,
        dropped_pattern_leaves: dropped_leaves,
        translation_flags: flags,
        ..Default::default()
    };

    let mut out: Vec<MatchSpec> = by_module
        .into_iter()
        .map(|(module_root, names)| MatchSpec {
            module_attr_module: module_root,
            module_attr_names: names,
            ..base.clone()
        })
        .collect();
    if !receiver_names.is_empty() {
        out.push(MatchSpec {
            receiver_method_names: receiver_names,
            ..base.clone()
        });
    }
    if !bare_names.is_empty() {
        out.push(MatchSpec {
            bare_call_names: bare_names,
            ..base
        });
    }
    out
}

/// Convert one semgrep rule dict into zero or more [`MatchSpec`] records.
fn spec_from_rule(rule: &Value, role: &str) -> Vec<MatchSpec> {
    let rule_id = rule
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    if rule_id.is_empty() {
        return Vec::new();
    }
    let langs = norm_langs(rule.get("languages"));
    if langs.is_empty() {
        return Vec::new();
    }
    let meta_obj = rule.get("metadata").and_then(Value::as_object);
    let cwe = {
        let raw = meta_obj
            .and_then(|m| m.get("cwe"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim();
        if raw.is_empty() {
            "CWE-20".to_string()
        } else {
            raw.to_string()
        }
    };
    let kind = {
        let raw = meta_obj
            .and_then(|m| m.get("sink_kind").or_else(|| m.get("ep_kind")))
            .and_then(Value::as_str)
            .unwrap_or("other");
        if raw.is_empty() {
            "other".to_string()
        } else {
            raw.to_string()
        }
    };
    let fallback = normalize_family(&kind, &cwe, &rule_id, rule);
    let semantic_family =
        families::resolve_semantic_family(rule.get("metadata"), &fallback).to_string();
    let owasp_tags: BTreeSet<String> = families::owasp_labels(&semantic_family)
        .iter()
        .map(|s| s.to_string())
        .collect();

    let codeql_pkg = meta_obj.and_then(|m| m.get("codeql_pkg"));
    let fsb_pkg = meta_obj.and_then(|m| m.get("fsb_pkg"));

    let (origin, package, class_name, methods, is_ctor) = if is_truthy(codeql_pkg) {
        (
            "codeql",
            meta_string(meta_obj, "codeql_pkg"),
            meta_string(meta_obj, "codeql_class"),
            metavar_methods(rule, "$METHOD"),
            false,
        )
    } else if is_truthy(fsb_pkg) {
        let is_ctor = rule_id.ends_with("-ctor");
        (
            "fsb",
            meta_string(meta_obj, "fsb_pkg"),
            meta_string(meta_obj, "fsb_class"),
            metavar_methods(rule, "$METHOD"),
            is_ctor,
        )
    } else {
        // Semgrep-lifted rule — try module-attribute parse only.
        // Everything more complex is omitted from this callgraph input.
        return try_module_attr(&rule_id, role, "semgrep", &cwe, &kind, &langs, rule);
    };

    if package.is_empty() {
        return Vec::new();
    }
    let top_class = class_name.split('.').next().unwrap_or("").to_string();
    if is_ctor && !top_class.is_empty() {
        // Constructor rules apply to the class itself, not method-named
        // calls.
        return vec![MatchSpec {
            rule_id,
            role: role.to_string(),
            origin: origin.to_string(),
            cwe,
            kind,
            semantic_family,
            owasp_top10_2025: owasp_tags,
            languages: langs,
            package,
            class_name,
            top_class: top_class.clone(),
            methods: BTreeSet::from([top_class]),
            is_constructor: true,
            ..Default::default()
        }];
    }
    if methods.is_empty() {
        return Vec::new();
    }
    vec![MatchSpec {
        rule_id,
        role: role.to_string(),
        origin: origin.to_string(),
        cwe,
        kind,
        semantic_family,
        owasp_top10_2025: owasp_tags,
        languages: langs,
        package,
        class_name,
        top_class,
        methods,
        is_constructor: false,
        ..Default::default()
    }]
}

// ── public loader ───────────────────────────────────────────────────────

/// Parse the `rules:` list out of already-read YAML text. `label` is used
/// only in error messages — a file path for [`load_yaml_rules`]'s own
/// callers, or a fixed description like "embedded default corpus" for
/// non-file-backed text (see [`parse_rulepacks_text`]).
fn parse_yaml_rules_text(text: &str, label: &str) -> Result<Vec<Value>, RulesError> {
    let doc =
        bc_yaml::parse(text).map_err(|e| RulesError::new(format!("cannot parse {label}: {e}")))?;
    if doc.is_null() {
        return Ok(Vec::new());
    }
    let Some(map) = doc.as_object() else {
        return Err(RulesError::new(format!(
            "{label}: expected a YAML mapping with a top-level `rules:` list, got a {}",
            value_kind_name(&doc),
        )));
    };
    Ok(map
        .get("rules")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default())
}

/// A missing or unset path is "no rules configured" (`Ok(vec![])`), not
/// an error — matching `_load`'s own `if not path or not path.is_file()`
/// short-circuit. A present-but-unreadable-or-malformed file is a real
/// [`RulesError`] instead, matching the Python original's raise (which
/// its own caller, the S0 wrapper, degrades to an empty seed).
fn load_yaml_rules(path: Option<&Path>) -> Result<Vec<Value>, RulesError> {
    let Some(path) = path else {
        return Ok(Vec::new());
    };
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let text = std::fs::read_to_string(path)
        .map_err(|e| RulesError::new(format!("cannot read {}: {e}", path.display())))?;
    parse_yaml_rules_text(&text, &path.display().to_string())
}

/// `Value`'s variant name, for a human-readable "expected X, got Y"
/// message. Exhaustive over every variant (not just the ones reachable
/// from [`load_yaml_rules`]'s own narrowed call site) so it stays
/// independently correct and testable.
fn value_kind_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "list",
        Value::Object(_) => "mapping",
    }
}

/// `(source_specs, sink_specs, rule_cwe)` — [`load_rulepacks`]'s success
/// shape, factored out to keep clippy's `type_complexity` lint happy.
pub type RulePacks = (
    Vec<MatchSpec>,
    Vec<MatchSpec>,
    BTreeMap<String, Vec<String>>,
);

/// Shared tail end of both [`load_rulepacks`] (file-backed) and
/// [`parse_rulepacks_text`] (embedded/in-memory) — converts each role's
/// raw rule list into filtered `MatchSpec`s once both have already been
/// read/parsed by the caller.
fn build_rulepacks(raw: [(&str, Vec<Value>); 2], active_langs: &[String]) -> RulePacks {
    let lang_filter: BTreeSet<String> = active_langs.iter().cloned().collect();
    let mut source_specs = Vec::new();
    let mut sink_specs = Vec::new();
    let mut rule_cwe: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for (role, raw_rules) in raw {
        for r in &raw_rules {
            for spec in spec_from_rule(r, role) {
                if spec.languages.is_disjoint(&lang_filter) {
                    continue;
                }
                rule_cwe.insert(spec.rule_id.clone(), vec![spec.cwe.clone()]);
                if role == "source" {
                    source_specs.push(spec);
                } else {
                    sink_specs.push(spec);
                }
            }
        }
    }
    (source_specs, sink_specs, rule_cwe)
}

/// Load both YAMLs, filter to `active_langs`, return `(source_specs,
/// sink_specs, rule_cwe)`.
pub fn load_rulepacks(
    sources_yaml: Option<&Path>,
    sinks_yaml: Option<&Path>,
    active_langs: &[String],
) -> Result<RulePacks, RulesError> {
    let raw = [
        ("source", load_yaml_rules(sources_yaml)?),
        ("sink", load_yaml_rules(sinks_yaml)?),
    ];
    Ok(build_rulepacks(raw, active_langs))
}

/// Same as [`load_rulepacks`], but for embedded/in-memory YAML text
/// rather than on-disk files — used by S0's bundled default corpus
/// (`crates/bc-stage-s0/corpus/*.yaml`, embedded via `include_str!`),
/// which ships inside the binary so `step0.enabled: true` produces real
/// rule content even when an operator hasn't supplied their own
/// `sources_yaml`/`sinks_yaml` files. `None` for either argument behaves
/// exactly like an absent path in [`load_rulepacks`] — "no rules of that
/// role," not an error.
pub fn parse_rulepacks_text(
    sources_text: Option<&str>,
    sinks_text: Option<&str>,
    active_langs: &[String],
) -> Result<RulePacks, RulesError> {
    let sources = match sources_text {
        Some(t) => parse_yaml_rules_text(t, "embedded sources corpus")?,
        None => Vec::new(),
    };
    let sinks = match sinks_text {
        Some(t) => parse_yaml_rules_text(t, "embedded sinks corpus")?,
        None => Vec::new(),
    };
    Ok(build_rulepacks(
        [("source", sources), ("sink", sinks)],
        active_langs,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn langs(vals: &[&str]) -> Vec<String> {
        vals.iter().map(|s| s.to_string()).collect()
    }

    fn write_yaml(dir: &Path, name: &str, contents: &str) -> std::path::PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, contents).unwrap();
        path
    }

    // ── MatchSpec ────────────────────────────────────────────────────

    #[test]
    fn has_qualified_requires_all_three_fields() {
        let mut spec = MatchSpec::default();
        assert!(!spec.has_qualified());
        spec.package = "os".to_string();
        spec.class_name = "Runtime".to_string();
        assert!(!spec.has_qualified());
        spec.methods.insert("exec".to_string());
        assert!(spec.has_qualified());
    }

    #[test]
    fn has_module_attr_requires_both_fields() {
        let mut spec = MatchSpec::default();
        assert!(!spec.has_module_attr());
        spec.module_attr_module = "os".to_string();
        assert!(!spec.has_module_attr());
        spec.module_attr_names.insert("system".to_string());
        assert!(spec.has_module_attr());
    }

    // ── RulesError ───────────────────────────────────────────────────

    #[test]
    fn rules_error_display_and_traits() {
        let e = RulesError::new("bad yaml");
        assert_eq!(e.to_string(), "bad yaml");
        let _: &dyn std::error::Error = &e;
        assert_eq!(e.clone(), e);
    }

    // ── value_kind_name ──────────────────────────────────────────────
    //
    // Exercised directly (not only through `load_yaml_rules`'s narrower
    // call site, which by construction never reaches the `Null`/`Object`
    // arms) so every variant of this exhaustive match is independently
    // covered.

    #[test]
    fn value_kind_name_covers_every_variant() {
        assert_eq!(value_kind_name(&Value::Null), "null");
        assert_eq!(value_kind_name(&json!(true)), "boolean");
        assert_eq!(value_kind_name(&json!(1)), "number");
        assert_eq!(value_kind_name(&json!("x")), "string");
        assert_eq!(value_kind_name(&json!([1])), "list");
        assert_eq!(value_kind_name(&json!({"a": 1})), "mapping");
    }

    // ── norm_langs ───────────────────────────────────────────────────

    #[test]
    fn norm_langs_empty_when_languages_key_is_absent() {
        assert!(norm_langs(None).is_empty());
    }

    #[test]
    fn norm_langs_empty_when_languages_is_not_a_list() {
        assert!(norm_langs(Some(&json!("python"))).is_empty());
    }

    // ── extract_methods_from_regex ──────────────────────────────────

    #[test]
    fn extract_methods_from_regex_parses_a_simple_alternation() {
        let got = extract_methods_from_regex("^(loads|load)$");
        assert_eq!(
            got,
            BTreeSet::from(["load".to_string(), "loads".to_string()])
        );
    }

    #[test]
    fn extract_methods_from_regex_drops_non_identifier_alternatives() {
        let got = extract_methods_from_regex(r"^(loads|[a-z]+)$");
        assert_eq!(got, BTreeSet::from(["loads".to_string()]));
    }

    #[test]
    fn extract_methods_from_regex_empty_for_non_matching_shape() {
        assert!(extract_methods_from_regex("loads").is_empty());
        assert!(extract_methods_from_regex("").is_empty());
    }

    // ── metavar_methods ──────────────────────────────────────────────

    #[test]
    fn metavar_methods_finds_the_named_metavariable_regex() {
        let rule = json!({
            "patterns": [
                {"metavariable-regex": {"metavariable": "$OTHER", "regex": "^(x)$"}},
                {"metavariable-regex": {"metavariable": "$METHOD", "regex": "^(loads|load)$"}},
            ]
        });
        let got = metavar_methods(&rule, "$METHOD");
        assert_eq!(
            got,
            BTreeSet::from(["load".to_string(), "loads".to_string()])
        );
    }

    #[test]
    fn metavar_methods_empty_when_no_patterns_list() {
        assert!(metavar_methods(&json!({}), "$METHOD").is_empty());
    }

    #[test]
    fn metavar_methods_empty_when_metavariable_never_matches() {
        let rule =
            json!({"patterns": [{"metavariable-regex": {"metavariable": "$X", "regex": "^(a)$"}}]});
        assert!(metavar_methods(&rule, "$METHOD").is_empty());
    }

    #[test]
    fn metavar_methods_skips_pattern_entries_without_a_metavariable_regex_key() {
        let rule = json!({"patterns": [
            {"pattern-not": "x"},
            {"metavariable-regex": {"metavariable": "$METHOD", "regex": "^(exec)$"}},
        ]});
        assert_eq!(
            metavar_methods(&rule, "$METHOD"),
            BTreeSet::from(["exec".to_string()])
        );
    }

    // ── walk_pattern_leaves / walk_rule_keys ─────────────────────────

    #[test]
    fn walk_pattern_leaves_collects_nested_leaves_with_duplicates() {
        let rule = json!({
            "patterns": [
                {"pattern": "os.system(...)"},
                {"pattern-either": [
                    {"pattern": "subprocess.call(...)"},
                    {"pattern": "os.system(...)"},
                ]},
            ]
        });
        let mut out = Vec::new();
        walk_pattern_leaves(&rule, &mut out);
        out.sort();
        assert_eq!(
            out,
            vec![
                "os.system(...)".to_string(),
                "os.system(...)".to_string(),
                "subprocess.call(...)".to_string(),
            ]
        );
    }

    #[test]
    fn walk_pattern_leaves_recurses_when_pattern_key_holds_a_non_string() {
        let rule = json!({"pattern": {"pattern": "os.system(...)"}});
        let mut out = Vec::new();
        walk_pattern_leaves(&rule, &mut out);
        assert_eq!(out, vec!["os.system(...)".to_string()]);
    }

    #[test]
    fn walk_rule_keys_collects_keys_at_every_depth() {
        let rule = json!({"patterns": [{"pattern-not": "x", "metavariable-regex": {}}]});
        let mut out = BTreeSet::new();
        walk_rule_keys(&rule, &mut out);
        assert!(out.contains("patterns"));
        assert!(out.contains("pattern-not"));
        assert!(out.contains("metavariable-regex"));
    }

    // ── normalize_family ──────────────────────────────────────────────

    #[test]
    fn normalize_family_detects_html_response_via_cwe() {
        assert_eq!(
            normalize_family("other", "CWE-79", "r1", &json!({})),
            "html-response"
        );
    }

    #[test]
    fn normalize_family_detects_command_exec_via_rule_id() {
        assert_eq!(
            normalize_family(
                "other",
                "CWE-0",
                "python.lang.security.subprocess-shell",
                &json!({})
            ),
            "command-exec"
        );
    }

    #[test]
    fn normalize_family_detects_sql_exec_via_kind() {
        assert_eq!(
            normalize_family("sql", "CWE-0", "r1", &json!({})),
            "sql-exec"
        );
    }

    #[test]
    fn normalize_family_detects_via_leaf_pattern_text() {
        let rule = json!({"pattern": "response(html, ...)"});
        assert_eq!(
            normalize_family("other", "CWE-0", "r1", &rule),
            "html-response"
        );
    }

    #[test]
    fn normalize_family_falls_back_to_kind_then_other() {
        assert_eq!(
            normalize_family("weird-kind", "CWE-0", "r1", &json!({})),
            "weird-kind"
        );
        assert_eq!(normalize_family("", "CWE-0", "r1", &json!({})), "other");
    }

    #[test]
    fn normalize_family_detects_url_fetch_via_cwe_and_kind() {
        assert_eq!(
            normalize_family("other", "CWE-918", "r1", &json!({})),
            "url-fetch"
        );
        assert_eq!(
            normalize_family("ssrf", "CWE-0", "r1", &json!({})),
            "url-fetch"
        );
    }

    #[test]
    fn normalize_family_detects_file_io_via_cwe_and_kind() {
        assert_eq!(
            normalize_family("other", "CWE-22", "r1", &json!({})),
            "file-io"
        );
        assert_eq!(
            normalize_family("path", "CWE-0", "r1", &json!({})),
            "file-io"
        );
    }

    #[test]
    fn normalize_family_detects_deserialization_via_cwe_and_kind() {
        assert_eq!(
            normalize_family("other", "CWE-502", "r1", &json!({})),
            "deserialization"
        );
        assert_eq!(
            normalize_family("deserialize", "CWE-0", "r1", &json!({})),
            "deserialization"
        );
    }

    #[test]
    fn normalize_family_detects_credentials_via_kind() {
        assert_eq!(
            normalize_family("credentials", "CWE-0", "r1", &json!({})),
            "credentials"
        );
        assert_eq!(
            normalize_family("secret", "CWE-0", "r1", &json!({})),
            "credentials"
        );
    }

    // ── translation_flags ────────────────────────────────────────────

    #[test]
    fn translation_flags_detects_nested_and_negative_and_regex_and_metavar() {
        let rule = json!({
            "patterns": [],
            "pattern-not-inside": "x",
            "pattern-regex": "y",
            "metavariable-regex": {},
        });
        let flags = translation_flags(&rule, 1, 1);
        assert!(flags.contains("nested-patterns"));
        assert!(flags.contains("negative-patterns"));
        assert!(flags.contains("regex-patterns"));
        assert!(flags.contains("metavariable-constraints"));
    }

    #[test]
    fn translation_flags_no_parseable_when_zero_parsed_of_some() {
        let flags = translation_flags(&json!({}), 0, 3);
        assert_eq!(
            flags,
            BTreeSet::from(["no-parseable-module-attr".to_string()])
        );
    }

    #[test]
    fn translation_flags_partial_coverage_when_some_but_not_all_parsed() {
        let flags = translation_flags(&json!({}), 1, 3);
        assert_eq!(
            flags,
            BTreeSet::from(["partial-pattern-coverage".to_string()])
        );
    }

    #[test]
    fn translation_flags_empty_when_nothing_to_flag() {
        assert!(translation_flags(&json!({}), 0, 0).is_empty());
    }

    // ── spec_from_rule / try_module_attr (via load_rulepacks) ────────

    #[test]
    fn load_rulepacks_parses_a_semgrep_module_attr_rule() {
        let dir = tempfile::tempdir().unwrap();
        let sources = write_yaml(
            dir.path(),
            "sources.yaml",
            r#"
rules:
  - id: py.flask.request-source
    languages: [python]
    pattern: request.args.get(...)
    metadata:
      cwe: CWE-20
"#,
        );
        let (source_specs, sink_specs, rule_cwe) =
            load_rulepacks(Some(&sources), None, &langs(&["python"])).unwrap();
        assert!(sink_specs.is_empty());
        assert_eq!(source_specs.len(), 1);
        let spec = &source_specs[0];
        assert_eq!(spec.rule_id, "py.flask.request-source");
        assert_eq!(spec.origin, "semgrep");
        assert_eq!(spec.module_attr_module, "request");
        assert_eq!(spec.module_attr_names, BTreeSet::from(["get".to_string()]));
        assert_eq!(
            rule_cwe["py.flask.request-source"],
            vec!["CWE-20".to_string()]
        );
    }

    #[test]
    fn load_rulepacks_parses_a_bare_call_rule() {
        // Before the `bare_call` category this rule produced *zero*
        // specs: `MODULE_ATTR_RX` requires a `.`, so `open(...)` fell
        // through every branch and the corpus's `py.open-file`,
        // `py.eval-exec` and `js.eval` never matched anything.
        let dir = tempfile::tempdir().unwrap();
        let sinks = write_yaml(
            dir.path(),
            "sinks.yaml",
            r#"
rules:
  - id: py.open-file
    languages: [python]
    pattern-either:
      - pattern: open(...)
      - pattern: eval(...)
    metadata:
      cwe: CWE-22
      sink_kind: path
"#,
        );
        let (_src, sink_specs, _cwe) =
            load_rulepacks(None, Some(&sinks), &langs(&["python"])).unwrap();
        assert_eq!(sink_specs.len(), 1);
        let spec = &sink_specs[0];
        assert!(spec.has_bare_call());
        assert!(!spec.has_module_attr());
        assert_eq!(
            spec.bare_call_names,
            BTreeSet::from(["open".to_string(), "eval".to_string()])
        );
        assert!(spec.dropped_pattern_leaves.is_empty());
        assert!(!spec.translation_flags.contains("no-parseable-module-attr"));
    }

    #[test]
    fn load_rulepacks_parses_a_receiver_method_rule_with_requires_dynamic_arg() {
        let dir = tempfile::tempdir().unwrap();
        let sinks = write_yaml(
            dir.path(),
            "sinks.yaml",
            r#"
rules:
  - id: py.dbapi-cursor-execute
    languages: [python]
    pattern-either:
      - pattern: $CUR.execute(...)
      - pattern: $CUR.executemany(...)
    metadata:
      cwe: CWE-89
      sink_kind: sql
      requires_dynamic_arg: true
"#,
        );
        let (_src, sink_specs, _cwe) =
            load_rulepacks(None, Some(&sinks), &langs(&["python"])).unwrap();
        assert_eq!(sink_specs.len(), 1);
        let spec = &sink_specs[0];
        assert!(spec.has_receiver_method());
        assert!(spec.requires_dynamic_arg);
        assert_eq!(
            spec.receiver_method_names,
            BTreeSet::from(["execute".to_string(), "executemany".to_string()])
        );
    }

    #[test]
    fn load_rulepacks_parses_requires_arithmetic_arg_and_its_index() {
        let dir = tempfile::tempdir().unwrap();
        let sinks = write_yaml(
            dir.path(),
            "sinks.yaml",
            r#"
rules:
  - id: c.alloc-size-overflow
    languages: [c, cpp]
    pattern-either:
      - pattern: malloc(...)
      - pattern: alloca(...)
    metadata:
      cwe: CWE-190
      sink_kind: memory
      requires_arithmetic_arg: true
  - id: c.alloc-size-overflow-second-arg
    languages: [c, cpp]
    pattern-either:
      - pattern: realloc(...)
    metadata:
      cwe: CWE-190
      sink_kind: memory
      requires_arithmetic_arg: true
      arithmetic_arg_index: 1
"#,
        );
        let (_src, sink_specs, _cwe) =
            load_rulepacks(None, Some(&sinks), &langs(&["c-cpp"])).unwrap();
        assert_eq!(sink_specs.len(), 2);
        assert!(sink_specs.iter().all(|s| s.requires_arithmetic_arg));
        // Which argument carries the size is per-rule: `malloc(n * m)`
        // first, `realloc(p, n * m)` second.
        assert_eq!(
            sink_specs
                .iter()
                .map(|s| (s.rule_id.as_str(), s.arithmetic_arg_index))
                .collect::<Vec<_>>(),
            vec![
                ("c.alloc-size-overflow", 0),
                ("c.alloc-size-overflow-second-arg", 1),
            ]
        );
        assert_eq!(
            sink_specs[0].bare_call_names,
            BTreeSet::from(["malloc".to_string(), "alloca".to_string()])
        );
    }

    #[test]
    fn load_rulepacks_leaves_requires_arithmetic_arg_off_by_default() {
        let dir = tempfile::tempdir().unwrap();
        let sinks = write_yaml(
            dir.path(),
            "sinks.yaml",
            r#"
rules:
  - id: c.command-exec
    languages: [c, cpp]
    pattern-either:
      - pattern: system(...)
    metadata:
      cwe: CWE-78
      sink_kind: cmd
"#,
        );
        let (_src, sink_specs, _cwe) =
            load_rulepacks(None, Some(&sinks), &langs(&["c-cpp"])).unwrap();
        assert_eq!(sink_specs.len(), 1);
        assert!(!sink_specs[0].requires_arithmetic_arg);
        assert_eq!(sink_specs[0].arithmetic_arg_index, 0);
        assert!(!sink_specs[0].requires_unit_arg);
        assert_eq!(sink_specs[0].unit_arg_index, 0);
    }

    #[test]
    fn load_rulepacks_parses_two_argument_predicates_on_one_rule() {
        // The corpus states `calloc(n * size, 1)` as a CONJUNCTION —
        // arithmetic at 0 and the literal `1` at 1 — and both
        // predicates have to survive onto the one spec, since the
        // matcher requires every predicate a spec carries.
        let dir = tempfile::tempdir().unwrap();
        let sinks = write_yaml(
            dir.path(),
            "sinks.yaml",
            r#"
rules:
  - id: c.calloc-hand-multiplied-size
    languages: [c, cpp]
    pattern-either:
      - pattern: calloc(...)
    metadata:
      cwe: CWE-190
      sink_kind: memory
      requires_arithmetic_arg: true
      arithmetic_arg_index: 0
      requires_unit_arg: true
      unit_arg_index: 1
"#,
        );
        let (_src, sink_specs, _cwe) =
            load_rulepacks(None, Some(&sinks), &langs(&["c-cpp"])).unwrap();
        assert_eq!(sink_specs.len(), 1);
        let spec = &sink_specs[0];
        assert!(spec.requires_arithmetic_arg);
        assert_eq!(spec.arithmetic_arg_index, 0);
        assert!(spec.requires_unit_arg);
        assert_eq!(spec.unit_arg_index, 1);
        assert_eq!(spec.bare_call_names, BTreeSet::from(["calloc".to_string()]));
    }

    #[test]
    fn load_rulepacks_splits_a_rule_that_mixes_all_three_semgrep_shapes() {
        let dir = tempfile::tempdir().unwrap();
        let sinks = write_yaml(
            dir.path(),
            "sinks.yaml",
            r#"
rules:
  - id: py.mixed
    languages: [python]
    pattern-either:
      - pattern: flask.send_file(...)
      - pattern: send_file(...)
      - pattern: $CUR.execute(...)
    metadata:
      cwe: CWE-22
      sink_kind: path
"#,
        );
        let (_src, sink_specs, _cwe) =
            load_rulepacks(None, Some(&sinks), &langs(&["python"])).unwrap();
        assert_eq!(sink_specs.len(), 3);
        assert_eq!(
            sink_specs
                .iter()
                .filter(|s| s.has_module_attr())
                .map(|s| s.module_attr_module.as_str())
                .collect::<Vec<_>>(),
            vec!["flask"]
        );
        assert!(sink_specs.iter().any(|s| s.has_bare_call()));
        assert!(sink_specs.iter().any(|s| s.has_receiver_method()));
        // Every leaf parsed, under one shape or another.
        assert!(sink_specs
            .iter()
            .all(|s| s.dropped_pattern_leaves.is_empty()));
        assert!(!sink_specs[0].requires_dynamic_arg);
    }

    #[test]
    fn load_rulepacks_parses_a_codeql_qualified_sink_rule() {
        let dir = tempfile::tempdir().unwrap();
        let sinks = write_yaml(
            dir.path(),
            "sinks.yaml",
            r#"
rules:
  - id: java.codeql.runtime-exec
    languages: [java]
    metadata:
      cwe: CWE-78
      sink_kind: cmd
      codeql_pkg: java.lang
      codeql_class: Runtime
    patterns:
      - metavariable-regex:
          metavariable: $METHOD
          regex: "^(exec)$"
"#,
        );
        let (source_specs, sink_specs, _) =
            load_rulepacks(None, Some(&sinks), &langs(&["java"])).unwrap();
        assert!(source_specs.is_empty());
        assert_eq!(sink_specs.len(), 1);
        let spec = &sink_specs[0];
        assert_eq!(spec.origin, "codeql");
        assert_eq!(spec.package, "java.lang");
        assert_eq!(spec.class_name, "Runtime");
        assert_eq!(spec.methods, BTreeSet::from(["exec".to_string()]));
        assert!(spec.has_qualified());
        assert!(!spec.is_constructor);
    }

    #[test]
    fn load_rulepacks_parses_an_fsb_constructor_rule() {
        let dir = tempfile::tempdir().unwrap();
        let sinks = write_yaml(
            dir.path(),
            "sinks.yaml",
            r#"
rules:
  - id: java.fsb.xxe-ctor
    languages: [java]
    metadata:
      cwe: CWE-611
      sink_kind: xxe
      fsb_pkg: javax.xml.parsers
      fsb_class: DocumentBuilderFactory
"#,
        );
        let (_, sink_specs, _) = load_rulepacks(None, Some(&sinks), &langs(&["java"])).unwrap();
        assert_eq!(sink_specs.len(), 1);
        let spec = &sink_specs[0];
        assert_eq!(spec.origin, "fsb");
        assert!(spec.is_constructor);
        assert_eq!(
            spec.methods,
            BTreeSet::from(["DocumentBuilderFactory".to_string()])
        );
    }

    #[test]
    fn load_rulepacks_treats_a_zero_valued_codeql_pkg_as_falsy() {
        // `codeql_pkg: 0` is a JSON number, not a string — exercises
        // `is_truthy`'s `Value::Number` arm specifically (falsy, since
        // 0.0 == 0.0), falling through to the semgrep module-attr path
        // rather than the codeql qualified-match path.
        let dir = tempfile::tempdir().unwrap();
        let sinks = write_yaml(
            dir.path(),
            "sinks.yaml",
            "rules:\n  - id: r1\n    languages: [python]\n    metadata:\n      codeql_pkg: 0\n    pattern: os.system(...)\n",
        );
        let (_, sink_specs, _) = load_rulepacks(None, Some(&sinks), &langs(&["python"])).unwrap();
        assert_eq!(sink_specs.len(), 1);
        assert_eq!(sink_specs[0].origin, "semgrep");
    }

    #[test]
    fn load_rulepacks_treats_an_empty_string_codeql_pkg_as_falsy_and_falls_back_to_semgrep() {
        // `codeql_pkg: ""` is falsy (matching Python's `if meta.get(...)`
        // truthiness), so this never reaches the codeql branch at all —
        // it falls through to the semgrep module-attr path, which itself
        // finds nothing parseable here.
        let dir = tempfile::tempdir().unwrap();
        let sinks = write_yaml(
            dir.path(),
            "sinks.yaml",
            r#"
rules:
  - id: bad.codeql
    languages: [java]
    metadata:
      codeql_pkg: ""
      cwe: CWE-78
"#,
        );
        let (_, sink_specs, _) = load_rulepacks(None, Some(&sinks), &langs(&["java"])).unwrap();
        assert!(sink_specs.is_empty());
    }

    #[test]
    fn load_rulepacks_drops_a_codeql_rule_whose_package_is_truthy_but_not_a_string() {
        // `codeql_pkg: true` is truthy (exercising `is_truthy`'s `Bool`
        // arm) but not extractable via `meta_string`'s `.as_str()`, so
        // `package` ends up empty anyway — a genuinely different path
        // from the falsy-empty-string case above.
        let dir = tempfile::tempdir().unwrap();
        let sinks = write_yaml(
            dir.path(),
            "sinks.yaml",
            r#"
rules:
  - id: bad.codeql
    languages: [java]
    metadata:
      codeql_pkg: true
      cwe: CWE-78
"#,
        );
        let (_, sink_specs, _) = load_rulepacks(None, Some(&sinks), &langs(&["java"])).unwrap();
        assert!(sink_specs.is_empty());
    }

    #[test]
    fn load_rulepacks_drops_a_qualified_rule_with_no_methods() {
        let dir = tempfile::tempdir().unwrap();
        let sinks = write_yaml(
            dir.path(),
            "sinks.yaml",
            r#"
rules:
  - id: no.methods
    languages: [java]
    metadata:
      codeql_pkg: java.lang
      codeql_class: Runtime
      cwe: CWE-78
"#,
        );
        let (_, sink_specs, _) = load_rulepacks(None, Some(&sinks), &langs(&["java"])).unwrap();
        assert!(sink_specs.is_empty());
    }

    #[test]
    fn load_rulepacks_treats_an_empty_array_fsb_pkg_as_falsy() {
        let dir = tempfile::tempdir().unwrap();
        let sinks = write_yaml(
            dir.path(),
            "sinks.yaml",
            "rules:\n  - id: r1\n    languages: [java]\n    metadata:\n      fsb_pkg: []\n    pattern: x.y(...)\n",
        );
        let (_, sink_specs, _) = load_rulepacks(None, Some(&sinks), &langs(&["java"])).unwrap();
        assert_eq!(sink_specs.len(), 1);
        assert_eq!(sink_specs[0].origin, "semgrep");
    }

    #[test]
    fn load_rulepacks_drops_an_fsb_rule_whose_package_is_truthy_but_not_a_string() {
        let dir = tempfile::tempdir().unwrap();
        let sinks = write_yaml(
            dir.path(),
            "sinks.yaml",
            "rules:\n  - id: r1\n    languages: [java]\n    metadata:\n      fsb_pkg: {x: 1}\n",
        );
        let (_, sink_specs, _) = load_rulepacks(None, Some(&sinks), &langs(&["java"])).unwrap();
        assert!(sink_specs.is_empty());
    }

    #[test]
    fn load_rulepacks_drops_a_rule_with_no_id() {
        let dir = tempfile::tempdir().unwrap();
        let sinks = write_yaml(
            dir.path(),
            "sinks.yaml",
            "rules:\n  - languages: [python]\n",
        );
        let (_, sink_specs, _) = load_rulepacks(None, Some(&sinks), &langs(&["python"])).unwrap();
        assert!(sink_specs.is_empty());
    }

    #[test]
    fn load_rulepacks_drops_a_rule_with_no_recognized_language() {
        let dir = tempfile::tempdir().unwrap();
        let sinks = write_yaml(
            dir.path(),
            "sinks.yaml",
            "rules:\n  - id: r1\n    languages: [cobol]\n    pattern: x.y(...)\n",
        );
        let (_, sink_specs, _) = load_rulepacks(None, Some(&sinks), &langs(&["python"])).unwrap();
        assert!(sink_specs.is_empty());
    }

    #[test]
    fn load_rulepacks_ignores_a_non_string_language_entry_alongside_a_valid_one() {
        let dir = tempfile::tempdir().unwrap();
        let sinks = write_yaml(
            dir.path(),
            "sinks.yaml",
            "rules:\n  - id: r1\n    languages: [python, 123]\n    pattern: x.y(...)\n",
        );
        let (_, sink_specs, _) = load_rulepacks(None, Some(&sinks), &langs(&["python"])).unwrap();
        assert_eq!(sink_specs.len(), 1);
    }

    #[test]
    fn load_rulepacks_filters_out_rules_not_applicable_to_active_langs() {
        let dir = tempfile::tempdir().unwrap();
        let sinks = write_yaml(
            dir.path(),
            "sinks.yaml",
            "rules:\n  - id: r1\n    languages: [java]\n    pattern: x.y(...)\n",
        );
        let (_, sink_specs, _) = load_rulepacks(None, Some(&sinks), &langs(&["python"])).unwrap();
        assert!(sink_specs.is_empty());
    }

    #[test]
    fn load_rulepacks_merges_method_names_across_leaves_sharing_a_module() {
        let dir = tempfile::tempdir().unwrap();
        let sinks = write_yaml(
            dir.path(),
            "sinks.yaml",
            r#"
rules:
  - id: r1
    languages: [python]
    pattern-either:
      - pattern: os.system(...)
      - pattern: os.popen(...)
"#,
        );
        let (_, sink_specs, _) = load_rulepacks(None, Some(&sinks), &langs(&["python"])).unwrap();
        assert_eq!(sink_specs.len(), 1);
        assert_eq!(
            sink_specs[0].module_attr_names,
            BTreeSet::from(["system".to_string(), "popen".to_string()])
        );
    }

    #[test]
    fn load_rulepacks_skips_a_leaf_that_does_not_match_the_module_attr_shape() {
        let dir = tempfile::tempdir().unwrap();
        let sinks = write_yaml(
            dir.path(),
            "sinks.yaml",
            r#"
rules:
  - id: r1
    languages: [python]
    pattern-either:
      - pattern: "just some free text, no call shape"
      - pattern: os.system(...)
"#,
        );
        let (_, sink_specs, _) = load_rulepacks(None, Some(&sinks), &langs(&["python"])).unwrap();
        assert_eq!(sink_specs.len(), 1);
        assert_eq!(sink_specs[0].module_attr_module, "os");
    }

    #[test]
    fn load_rulepacks_emits_one_spec_per_distinct_module_root() {
        let dir = tempfile::tempdir().unwrap();
        let sinks = write_yaml(
            dir.path(),
            "sinks.yaml",
            r#"
rules:
  - id: r1
    languages: [python]
    pattern-either:
      - pattern: os.system(...)
      - pattern: pickle.loads(...)
"#,
        );
        let (_, sink_specs, _) = load_rulepacks(None, Some(&sinks), &langs(&["python"])).unwrap();
        assert_eq!(sink_specs.len(), 2);
        let modules: BTreeSet<_> = sink_specs
            .iter()
            .map(|s| s.module_attr_module.clone())
            .collect();
        assert_eq!(
            modules,
            BTreeSet::from(["os".to_string(), "pickle".to_string()])
        );
    }

    #[test]
    fn load_rulepacks_drops_a_semgrep_rule_with_no_parseable_shape() {
        let dir = tempfile::tempdir().unwrap();
        let sinks = write_yaml(
            dir.path(),
            "sinks.yaml",
            "rules:\n  - id: r1\n    languages: [python]\n    pattern-regex: \"os\\\\.system\"\n",
        );
        let (_, sink_specs, _) = load_rulepacks(None, Some(&sinks), &langs(&["python"])).unwrap();
        assert!(sink_specs.is_empty());
    }

    #[test]
    fn load_rulepacks_defaults_cwe_and_kind_when_metadata_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        let sources = write_yaml(
            dir.path(),
            "sources.yaml",
            "rules:\n  - id: r1\n    languages: [python]\n    pattern: os.getenv(...)\n",
        );
        let (source_specs, _, rule_cwe) =
            load_rulepacks(Some(&sources), None, &langs(&["python"])).unwrap();
        assert_eq!(source_specs[0].cwe, "CWE-20");
        assert_eq!(source_specs[0].kind, "other");
        assert_eq!(rule_cwe["r1"], vec!["CWE-20".to_string()]);
    }

    #[test]
    fn load_rulepacks_defaults_kind_to_other_when_sink_kind_is_present_but_blank() {
        let dir = tempfile::tempdir().unwrap();
        let sources = write_yaml(
            dir.path(),
            "sources.yaml",
            "rules:\n  - id: r1\n    languages: [python]\n    metadata:\n      sink_kind: \"\"\n    pattern: os.getenv(...)\n",
        );
        let (source_specs, _, _) =
            load_rulepacks(Some(&sources), None, &langs(&["python"])).unwrap();
        assert_eq!(source_specs[0].kind, "other");
    }

    // ── load_rulepacks / load_yaml_rules edge cases ──────────────────

    #[test]
    fn load_rulepacks_with_no_paths_returns_everything_empty() {
        let (source_specs, sink_specs, rule_cwe) =
            load_rulepacks(None, None, &langs(&["python"])).unwrap();
        assert!(source_specs.is_empty());
        assert!(sink_specs.is_empty());
        assert!(rule_cwe.is_empty());
    }

    #[test]
    fn load_rulepacks_with_a_nonexistent_path_is_empty_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist.yaml");
        let (source_specs, _, _) =
            load_rulepacks(Some(&missing), None, &langs(&["python"])).unwrap();
        assert!(source_specs.is_empty());
    }

    #[test]
    fn load_rulepacks_with_an_empty_file_is_empty_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let empty = write_yaml(dir.path(), "empty.yaml", "");
        let (source_specs, _, _) = load_rulepacks(Some(&empty), None, &langs(&["python"])).unwrap();
        assert!(source_specs.is_empty());
    }

    #[test]
    fn load_rulepacks_with_a_mapping_missing_the_rules_key_is_empty_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_yaml(dir.path(), "no_rules_key.yaml", "other_key: 1\n");
        let (source_specs, _, _) = load_rulepacks(Some(&path), None, &langs(&["python"])).unwrap();
        assert!(source_specs.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn load_rulepacks_propagates_an_io_error_when_the_file_is_unreadable() {
        // A regular file nobody can open for reading. The kernel checks a
        // sysctl's mode bits itself, without the CAP_DAC_OVERRIDE bypass a
        // chmod 000 file gets, so the read fails for root as well.
        let path = Path::new("/proc/sys/vm/drop_caches");
        assert!(
            path.is_file(),
            "the fixture must pass the is_file pre-check"
        );
        let err = load_rulepacks(Some(path), None, &langs(&["python"]));
        assert!(err.unwrap_err().to_string().contains("cannot read"));
    }

    #[test]
    fn load_rulepacks_propagates_a_malformed_yaml_error() {
        let dir = tempfile::tempdir().unwrap();
        let bad = write_yaml(dir.path(), "bad.yaml", "rules: [\n  - unterminated");
        let err = load_rulepacks(Some(&bad), None, &langs(&["python"])).unwrap_err();
        assert!(err.to_string().contains("bad.yaml"));
    }

    #[test]
    fn load_rulepacks_errors_when_the_top_level_document_is_not_a_mapping() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_yaml(dir.path(), "list.yaml", "- id: r1\n");
        let err = load_rulepacks(Some(&path), None, &langs(&["python"])).unwrap_err();
        assert!(err.to_string().contains("expected a YAML mapping"));
    }

    #[test]
    fn load_rulepacks_errors_when_the_top_level_document_is_a_bare_string() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_yaml(dir.path(), "scalar.yaml", "just a string\n");
        let err = load_rulepacks(Some(&path), None, &langs(&["python"])).unwrap_err();
        assert!(err.to_string().contains("got a string"));
    }

    #[test]
    fn load_rulepacks_errors_when_the_top_level_document_is_a_bare_number() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_yaml(dir.path(), "scalar.yaml", "42\n");
        let err = load_rulepacks(Some(&path), None, &langs(&["python"])).unwrap_err();
        assert!(err.to_string().contains("got a number"));
    }

    #[test]
    fn load_rulepacks_errors_when_the_top_level_document_is_a_bare_bool() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_yaml(dir.path(), "scalar.yaml", "true\n");
        let err = load_rulepacks(Some(&path), None, &langs(&["python"])).unwrap_err();
        assert!(err.to_string().contains("got a boolean"));
    }

    #[test]
    fn load_rulepacks_treats_a_non_list_rules_value_as_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_yaml(dir.path(), "scalar_rules.yaml", "rules: not-a-list\n");
        let (source_specs, _, _) = load_rulepacks(Some(&path), None, &langs(&["python"])).unwrap();
        assert!(source_specs.is_empty());
    }

    // ── parse_rulepacks_text ──────────────────────────────────────────

    #[test]
    fn parse_rulepacks_text_with_no_text_returns_everything_empty() {
        let (source_specs, sink_specs, rule_cwe) =
            parse_rulepacks_text(None, None, &langs(&["python"])).unwrap();
        assert!(source_specs.is_empty());
        assert!(sink_specs.is_empty());
        assert!(rule_cwe.is_empty());
    }

    #[test]
    fn parse_rulepacks_text_parses_a_module_attr_source_rule() {
        let sources = "rules:\n  - id: py.flask.request-source\n    languages: [python]\n    pattern: request.args.get(...)\n    metadata:\n      cwe: CWE-20\n";
        let (source_specs, sink_specs, rule_cwe) =
            parse_rulepacks_text(Some(sources), None, &langs(&["python"])).unwrap();
        assert!(sink_specs.is_empty());
        assert_eq!(source_specs.len(), 1);
        assert_eq!(source_specs[0].rule_id, "py.flask.request-source");
        assert_eq!(
            rule_cwe["py.flask.request-source"],
            vec!["CWE-20".to_string()]
        );
    }

    #[test]
    fn parse_rulepacks_text_parses_both_sources_and_sinks() {
        let sources =
            "rules:\n  - id: src1\n    languages: [python]\n    pattern: os.getenv(...)\n";
        let sinks = "rules:\n  - id: sink1\n    languages: [python]\n    pattern: os.system(...)\n";
        let (source_specs, sink_specs, _) =
            parse_rulepacks_text(Some(sources), Some(sinks), &langs(&["python"])).unwrap();
        assert_eq!(source_specs.len(), 1);
        assert_eq!(sink_specs.len(), 1);
    }

    #[test]
    fn parse_rulepacks_text_filters_by_active_langs() {
        let sinks = "rules:\n  - id: r1\n    languages: [java]\n    pattern: x.y(...)\n";
        let (_, sink_specs, _) =
            parse_rulepacks_text(None, Some(sinks), &langs(&["python"])).unwrap();
        assert!(sink_specs.is_empty());
    }

    #[test]
    fn parse_rulepacks_text_propagates_a_malformed_yaml_error_naming_the_embedded_source() {
        let err = parse_rulepacks_text(
            Some("rules: [\n  - unterminated"),
            None,
            &langs(&["python"]),
        )
        .unwrap_err();
        assert!(err.to_string().contains("embedded sources corpus"));
    }

    #[test]
    fn parse_rulepacks_text_propagates_a_malformed_sinks_yaml_error_naming_the_embedded_source() {
        let err = parse_rulepacks_text(
            None,
            Some("rules: [\n  - unterminated"),
            &langs(&["python"]),
        )
        .unwrap_err();
        assert!(err.to_string().contains("embedded sinks corpus"));
    }

    #[test]
    fn parse_rulepacks_text_errors_when_the_top_level_document_is_not_a_mapping() {
        let err = parse_rulepacks_text(Some("- id: r1\n"), None, &langs(&["python"])).unwrap_err();
        assert!(err.to_string().contains("expected a YAML mapping"));
    }
}
