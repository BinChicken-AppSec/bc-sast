//! Injected context, threat model (S2 output), and context package (S1
//! output) — ported from the corresponding sections of `models.py`.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

use crate::coerce;

// ─────────────────────────────────────────────────────────────────────────
// Injected context
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Cve {
    pub id: String,
    pub summary: String,
    #[serde(default)]
    pub affected_files: Vec<String>,
    #[serde(default)]
    pub cvss: Option<f64>,
    #[serde(default)]
    pub patched: bool,
}

const CONTROL_KIND_VALID: &[&str] = &[
    "auth",
    "sandbox",
    "input-validation",
    "aslr",
    "cfi",
    "other",
];
const CONTROL_KIND_ALIAS: &[(&str, &str)] = &[
    ("authn", "auth"),
    ("authentication", "auth"),
    ("authz", "auth"),
    ("authorization", "auth"),
    ("rbac", "auth"),
    ("iam", "auth"),
    ("sso", "auth"),
    ("waf", "input-validation"),
    ("validation", "input-validation"),
    ("input_validation", "input-validation"),
    ("sanitization", "input-validation"),
    ("sanitisation", "input-validation"),
    ("encoding", "input-validation"),
    ("seccomp", "sandbox"),
    ("container", "sandbox"),
    ("isolation", "sandbox"),
    ("chroot", "sandbox"),
    ("jail", "sandbox"),
];

/// Design-level mitigation. The strategist/chain stages use these to
/// downrank exploitability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ControlKind {
    Auth,
    Sandbox,
    InputValidation,
    Aslr,
    Cfi,
    Other,
}

impl ControlKind {
    fn from_canonical(s: &str) -> Self {
        match s {
            "auth" => Self::Auth,
            "sandbox" => Self::Sandbox,
            "input-validation" => Self::InputValidation,
            "aslr" => Self::Aslr,
            "cfi" => Self::Cfi,
            _ => Self::Other,
        }
    }
}

fn deserialize_control_kind<'de, D>(d: D) -> Result<ControlKind, D::Error>
where
    D: Deserializer<'de>,
{
    let v = Value::deserialize(d)?;
    let s = coerce::coerce_enum_str(&v, CONTROL_KIND_VALID, CONTROL_KIND_ALIAS, "other");
    Ok(ControlKind::from_canonical(&s))
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Control {
    pub name: String,
    #[serde(deserialize_with = "deserialize_control_kind")]
    pub kind: ControlKind,
    #[serde(default)]
    pub protects: Vec<String>,
    #[serde(default)]
    pub notes: String,
}

/// CMDB-derived deployment context for the application under scan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AppProfile {
    pub application_id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub externally_facing: bool,
    #[serde(default)]
    pub pci_scoped: bool,
    #[serde(default)]
    pub processes_pan: bool,
    #[serde(default)]
    pub pii: bool,
    #[serde(default)]
    pub source: String,
}

// ─────────────────────────────────────────────────────────────────────────
// Step 2 output: ThreatModel
// ─────────────────────────────────────────────────────────────────────────

const SENSITIVITY_VALID: &[&str] = &["low", "medium", "high", "critical"];
const SENSITIVITY_ALIAS: &[(&str, &str)] = &[
    ("none", "low"),
    ("info", "low"),
    ("informational", "low"),
    ("minor", "low"),
    ("moderate", "medium"),
    ("med", "medium"),
    ("normal", "medium"),
    ("major", "high"),
    ("severe", "high"),
    ("important", "high"),
    ("crit", "critical"),
    ("blocker", "critical"),
    ("extreme", "critical"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Sensitivity {
    Low,
    Medium,
    High,
    Critical,
}

impl Sensitivity {
    fn from_canonical(s: &str) -> Self {
        match s {
            "low" => Self::Low,
            "high" => Self::High,
            "critical" => Self::Critical,
            _ => Self::Medium,
        }
    }
}

fn deserialize_sensitivity<'de, D>(d: D) -> Result<Sensitivity, D::Error>
where
    D: Deserializer<'de>,
{
    let v = Value::deserialize(d)?;
    let s = coerce::coerce_enum_str(&v, SENSITIVITY_VALID, SENSITIVITY_ALIAS, "medium");
    Ok(Sensitivity::from_canonical(&s))
}

fn default_sensitivity() -> Sensitivity {
    Sensitivity::Medium
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Asset {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(
        default = "default_sensitivity",
        deserialize_with = "deserialize_sensitivity"
    )]
    pub sensitivity: Sensitivity,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrustBoundary {
    pub entry_point: String,
    pub crossing: String,
    #[serde(default)]
    pub reachable_assets: Vec<String>,
}

const ACTOR_VALID: &[&str] = &[
    "remote_unauth",
    "remote_auth",
    "adjacent_network",
    "local_user",
    "local_admin",
    "supply_chain",
    "insider",
];
const ACTOR_ALIAS: &[(&str, &str)] = &[
    ("external", "remote_unauth"),
    ("anonymous", "remote_unauth"),
    ("unauthenticated", "remote_unauth"),
    ("internet", "remote_unauth"),
    ("public", "remote_unauth"),
    ("attacker", "remote_unauth"),
    ("authenticated", "remote_auth"),
    ("user", "remote_auth"),
    ("tenant", "remote_auth"),
    ("customer", "remote_auth"),
    ("internal", "adjacent_network"),
    ("network", "adjacent_network"),
    ("lan", "adjacent_network"),
    ("adjacent", "adjacent_network"),
    ("local", "local_user"),
    ("physical", "local_user"),
    ("admin", "local_admin"),
    ("root", "local_admin"),
    ("operator", "local_admin"),
    ("privileged", "local_admin"),
    ("supply", "supply_chain"),
    ("dependency", "supply_chain"),
    ("third_party", "supply_chain"),
    ("vendor", "supply_chain"),
    ("employee", "insider"),
    ("developer", "insider"),
    ("malicious_insider", "insider"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Actor {
    RemoteUnauth,
    RemoteAuth,
    AdjacentNetwork,
    LocalUser,
    LocalAdmin,
    SupplyChain,
    Insider,
}

impl Actor {
    fn from_canonical(s: &str) -> Self {
        match s {
            "remote_unauth" => Self::RemoteUnauth,
            "adjacent_network" => Self::AdjacentNetwork,
            "local_user" => Self::LocalUser,
            "local_admin" => Self::LocalAdmin,
            "supply_chain" => Self::SupplyChain,
            "insider" => Self::Insider,
            _ => Self::RemoteAuth,
        }
    }
}

fn deserialize_actor<'de, D>(d: D) -> Result<Actor, D::Error>
where
    D: Deserializer<'de>,
{
    let v = Value::deserialize(d)?;
    let s = coerce::coerce_enum_str(&v, ACTOR_VALID, ACTOR_ALIAS, "remote_auth");
    Ok(Actor::from_canonical(&s))
}

const IMPACT_VALID: &[&str] = &["low", "medium", "high", "critical", "existential"];
// _IMPACT_ALIAS = {**_SENSITIVITY_ALIAS, "catastrophic": "existential", "fatal": "existential"}
const IMPACT_ALIAS: &[(&str, &str)] = &[
    ("none", "low"),
    ("info", "low"),
    ("informational", "low"),
    ("minor", "low"),
    ("moderate", "medium"),
    ("med", "medium"),
    ("normal", "medium"),
    ("major", "high"),
    ("severe", "high"),
    ("important", "high"),
    ("crit", "critical"),
    ("blocker", "critical"),
    ("extreme", "critical"),
    ("catastrophic", "existential"),
    ("fatal", "existential"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Impact {
    Low,
    Medium,
    High,
    Critical,
    Existential,
}

impl Impact {
    fn from_canonical(s: &str) -> Self {
        match s {
            "low" => Self::Low,
            "high" => Self::High,
            "critical" => Self::Critical,
            "existential" => Self::Existential,
            _ => Self::Medium,
        }
    }
}

fn deserialize_impact<'de, D>(d: D) -> Result<Impact, D::Error>
where
    D: Deserializer<'de>,
{
    let v = Value::deserialize(d)?;
    let s = coerce::coerce_enum_str(&v, IMPACT_VALID, IMPACT_ALIAS, "medium");
    Ok(Impact::from_canonical(&s))
}

const LIKELIHOOD_VALID: &[&str] = &["very_rare", "rare", "possible", "likely", "almost_certain"];
const LIKELIHOOD_ALIAS: &[(&str, &str)] = &[
    ("very_unlikely", "very_rare"),
    ("negligible", "very_rare"),
    ("remote", "very_rare"),
    ("improbable", "very_rare"),
    ("unlikely", "rare"),
    ("low", "rare"),
    ("moderate", "possible"),
    ("medium", "possible"),
    ("occasional", "possible"),
    ("probable", "likely"),
    ("high", "likely"),
    ("frequent", "likely"),
    ("very_likely", "almost_certain"),
    ("certain", "almost_certain"),
    ("definite", "almost_certain"),
    ("inevitable", "almost_certain"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Likelihood {
    VeryRare,
    Rare,
    Possible,
    Likely,
    AlmostCertain,
}

impl Likelihood {
    fn from_canonical(s: &str) -> Self {
        match s {
            "very_rare" => Self::VeryRare,
            "rare" => Self::Rare,
            "likely" => Self::Likely,
            "almost_certain" => Self::AlmostCertain,
            _ => Self::Possible,
        }
    }
}

fn deserialize_likelihood<'de, D>(d: D) -> Result<Likelihood, D::Error>
where
    D: Deserializer<'de>,
{
    let v = Value::deserialize(d)?;
    let s = coerce::coerce_enum_str(&v, LIKELIHOOD_VALID, LIKELIHOOD_ALIAS, "possible");
    Ok(Likelihood::from_canonical(&s))
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Threat {
    pub id: String,
    pub threat: String,
    #[serde(deserialize_with = "deserialize_actor")]
    pub actor: Actor,
    pub surface: String,
    pub asset: String,
    #[serde(deserialize_with = "deserialize_impact")]
    pub impact: Impact,
    #[serde(deserialize_with = "deserialize_likelihood")]
    pub likelihood: Likelihood,
    #[serde(default)]
    pub controls: String,
    #[serde(default)]
    pub evidence: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ThreatModel {
    #[serde(default)]
    pub system_context: String,
    #[serde(default)]
    pub assets: Vec<Asset>,
    #[serde(default)]
    pub trust_boundaries: Vec<TrustBoundary>,
    #[serde(default)]
    pub threats: Vec<Threat>,
    #[serde(default)]
    pub open_questions: Vec<String>,
}

// ─────────────────────────────────────────────────────────────────────────
// Step 1 output: ContextPackage
// ─────────────────────────────────────────────────────────────────────────

// `"framework"` is in Python's own `_EP_KINDS` (`models.py:364`) — the
// kind `_graph.py::_emit_framework_entry_points` stamps on every route/
// annotation-derived entry point.
//
// `EP_KIND_VALID` and `EP_KIND_ALIAS` are the one place a kind label is
// resolved: the serde path (`deserialize_ep_kind`) and the in-code path
// ([`EntryPointKind::parse`], which S0 uses on a rule's `ep_kind`) both
// go through them, so a spelling either resolves everywhere or nowhere.
const EP_KIND_VALID: &[&str] = &[
    "network",
    "ipc",
    "file",
    "cli",
    "deserialization",
    "framework",
    "other",
];
const EP_KIND_ALIAS: &[(&str, &str)] = &[
    ("rpc", "network"),
    ("grpc", "network"),
    ("http", "network"),
    ("https", "network"),
    ("rest", "network"),
    ("api", "network"),
    ("graphql", "network"),
    ("websocket", "network"),
    ("ws", "network"),
    ("soap", "network"),
    ("tcp", "network"),
    ("udp", "network"),
    ("socket", "network"),
    ("webhook", "network"),
    ("endpoint", "network"),
    ("queue", "ipc"),
    ("message", "ipc"),
    ("mq", "ipc"),
    ("kafka", "ipc"),
    ("amqp", "ipc"),
    ("jms", "ipc"),
    ("pubsub", "ipc"),
    ("event", "ipc"),
    ("signal", "ipc"),
    ("pipe", "ipc"),
    ("bus", "ipc"),
    ("stdin", "cli"),
    ("argv", "cli"),
    ("command", "cli"),
    ("arg", "cli"),
    ("config", "file"),
    ("env", "file"),
    ("filesystem", "file"),
    ("fs", "file"),
    ("deserialize", "deserialization"),
    ("serde", "deserialization"),
    ("unmarshal", "deserialization"),
    ("parse", "deserialization"),
    ("pickle", "deserialization"),
    ("json", "deserialization"),
    ("spring", "framework"),
    ("django", "framework"),
    ("aspnet", "framework"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryPointKind {
    Network,
    Ipc,
    File,
    Cli,
    Deserialization,
    /// A web-framework route/binding entry point, emitted by S0's
    /// framework marker detection (`bc_callgraph::framework`).
    Framework,
    Other,
}

impl EntryPointKind {
    fn from_canonical(s: &str) -> Self {
        match s {
            "network" => Self::Network,
            "ipc" => Self::Ipc,
            "file" => Self::File,
            "cli" => Self::Cli,
            "deserialization" => Self::Deserialization,
            "framework" => Self::Framework,
            _ => Self::Other,
        }
    }

    /// Alias-aware parse of a free-form kind label. The canonical
    /// spellings (`network`, `ipc`, `file`, `cli`, `deserialization`,
    /// `framework`) map to themselves; every alias in `EP_KIND_ALIAS`
    /// (`http` and `rpc` to `Network`, `stdin` and `argv` to `Cli`,
    /// `env` and `config` to `File`, ...) maps to its canonical kind;
    /// anything else is `Other`. Case- and whitespace-insensitive, as
    /// the serde path is.
    ///
    /// This is the same table `EntryPoint`'s deserializer applies,
    /// exposed so a producer that builds an `EntryPoint` in code
    /// resolves a label exactly as a JSON reader would. S0's bundled
    /// corpus tagged 20 of its 21 source rules `http`, `stdin` or `env`
    /// and, matching canonical spellings only, the seed stage collapsed
    /// every one of them to `Other`.
    pub fn parse(label: &str) -> Self {
        Self::coerce(&Value::String(label.to_string()))
    }

    fn coerce(v: &Value) -> Self {
        let s = coerce::coerce_enum_str(v, EP_KIND_VALID, EP_KIND_ALIAS, "other");
        Self::from_canonical(&s)
    }
}

fn deserialize_ep_kind<'de, D>(d: D) -> Result<EntryPointKind, D::Error>
where
    D: Deserializer<'de>,
{
    let v = Value::deserialize(d)?;
    Ok(EntryPointKind::coerce(&v))
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EntryPoint {
    pub file: String,
    pub function: String,
    #[serde(deserialize_with = "deserialize_ep_kind")]
    pub kind: EntryPointKind,
    #[serde(default)]
    pub reachable_from_unauth: bool,
}

fn deserialize_line<'de, D>(d: D) -> Result<i64, D::Error>
where
    D: Deserializer<'de>,
{
    let v = Value::deserialize(d)?;
    Ok(coerce::coerce_int(&v, 0))
}

fn default_zero_i64() -> i64 {
    0
}

/// Unsafe function call site flagged by static grep.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Sink {
    pub file: String,
    #[serde(default = "default_zero_i64", deserialize_with = "deserialize_line")]
    pub line: i64,
    pub function: String,
    #[serde(default)]
    pub snippet: String,
    /// CWE ids from S0's static-seed rule metadata (e.g. `["CWE-89"]`).
    /// Propagated to `Chunk.sink_cwe` in S3 so S4's confirm/refute prompt
    /// can splice per-CWE sanitizer guidance. Empty for agent-discovered
    /// sinks — the KB block simply omits itself.
    #[serde(default)]
    pub cwe: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModuleInfo {
    pub name: String,
    #[serde(default)]
    pub files: Vec<String>,
    #[serde(default = "default_zero_i64", deserialize_with = "deserialize_line")]
    pub loc: i64,
    #[serde(default)]
    pub purpose: String,
}

const TAINT_SYMBOL_KIND_VALID: &[&str] = &[
    "param",
    "local",
    "return",
    "arg",
    "field",
    "container",
    "property",
];

fn deserialize_taint_symbol_kind<'de, D>(d: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let v = Value::deserialize(d)?;
    // Python's `TaintSymbolRef.kind` has no `field_validator` at all — an
    // off-schema value hard-fails `ContextPackage.model_validate()` there.
    // A deliberate, documented divergence: this whole port otherwise
    // leans on lenient coercion everywhere a field could come from
    // LLM/seed JSON (see e.g. `bc-stage-s1`'s "off-schema enum/int values
    // are coerced... model_validate() therefore never raises" comment),
    // so introducing the one hard-failing enum here would be an
    // inconsistent trap for a field this port doesn't even construct yet
    // (the taint-evidence BUILDER itself — `_build_taint_evidence_for_
    // path` — is still unported, tracked by tasks #34/#37/#38). Falls
    // back to `"local"`, the most generic/common case, matching this
    // crate's `coerce_enum_str` convention used everywhere else.
    Ok(coerce::coerce_enum_str(
        &v,
        TAINT_SYMBOL_KIND_VALID,
        &[],
        "local",
    ))
}

/// One symbol a taint transfer edge reads from or writes to. Ported from
/// `models.py::TaintSymbolRef`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TaintSymbolRef {
    pub qnode: String,
    pub symbol: String,
    #[serde(deserialize_with = "deserialize_taint_symbol_kind")]
    pub kind: String,
}

// Python's own `TaintTransferEdge._coerce_unknown_kind` only recognizes
// the base class's 11 kinds — its "condition"/"reflect"/"framework"
// SUBCLASSES (`ConditionTaintEdge`/`ReflectionTaintEdge`/
// `FrameworkTaintEdge`) each override `transfer_kind` to a fixed literal
// default that bypasses runtime coercion entirely (a subclass instance
// is constructed directly, never round-tripped through the base
// validator). This port flattens that class hierarchy into one struct
// (see `TaintTransferEdge` below) with no subclassing, so the single
// shared coercion set here deliberately ADDS those three kinds — the
// three-way class split has no direct Rust equivalent, and dropping them
// from the valid set would silently mangle every condition/reflect/
// framework edge into "assign" the moment it round-trips through this
// port's deserializer.
const TRANSFER_KIND_VALID: &[&str] = &[
    "source",
    "assign",
    "arg_to_param",
    "return_to_local",
    "return_to_sink",
    "local_to_sink",
    "field_write",
    "field_read",
    "container_put",
    "container_get",
    "sanitize",
    "condition",
    "reflect",
    "framework",
];

fn deserialize_transfer_kind<'de, D>(d: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let v = Value::deserialize(d)?;
    // Ported from `TaintTransferEdge._coerce_unknown_kind`: any value
    // outside the known set coerces to `"assign"` — no alias table, this
    // is a straight unknown-value fallback (unlike e.g. `ControlKind`'s
    // real alias list).
    Ok(coerce::coerce_enum_str(
        &v,
        TRANSFER_KIND_VALID,
        &[],
        "assign",
    ))
}

/// A single taint transfer step within a [`TaintEvidencePath`]. Ported
/// from `models.py::TaintTransferEdge`. `transfer_kind` is a plain
/// `String` (not a Rust `enum`) rather than following this crate's usual
/// enum-plus-`deserialize_with` pattern (see `Impact`/`Likelihood`
/// above), since — unlike those — this port doesn't yet construct or
/// match on specific `transfer_kind` values anywhere (the S0 taint-
/// evidence builder that would is deferred to tasks #34/#37/#38); a
/// `String` avoids introducing an enum with no real consumer yet while
/// still validating/coercing on the way in.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TaintTransferEdge {
    pub file: String,
    #[serde(default = "default_zero_i64", deserialize_with = "deserialize_line")]
    pub line: i64,
    pub function_qnode: String,
    pub src: TaintSymbolRef,
    pub dst: TaintSymbolRef,
    #[serde(deserialize_with = "deserialize_transfer_kind")]
    pub transfer_kind: String,
    // Fields below are ONLY ever populated when `transfer_kind` is
    // `"condition"`/`"reflect"`/`"framework"` — Python models each as its
    // own `TaintTransferEdge` SUBCLASS (`ConditionTaintEdge`/
    // `ReflectionTaintEdge`/`FrameworkTaintEdge`) with its own extra
    // fields; this port flattens all three into optional fields on the
    // one struct instead, matching how `s4_deepdive.py::
    // _compact_taint_evidence_block` itself already treats them —
    // defensive `getattr(edge, "field", default)` access throughout,
    // never a direct/required attribute read, since the DECLARED type of
    // `TaintEvidencePath.edges` is the plain base class regardless of
    // which subclass actually produced a given edge at runtime.
    /// `ConditionTaintEdge` only: the (possibly tainted) guard text.
    #[serde(default)]
    pub condition_text: Option<String>,
    /// `ConditionTaintEdge` only.
    #[serde(default)]
    pub is_tainted_condition: Option<bool>,
    /// `ConditionTaintEdge`/`ReflectionTaintEdge`/`FrameworkTaintEdge`
    /// share this field name but NOT its default ("high"/"medium"/"high"
    /// respectively) — callers apply the right per-context default via
    /// `.unwrap_or(...)`, matching Python's own per-call-site
    /// `getattr(e, "confidence", "<kind-specific default>")`.
    #[serde(default)]
    pub confidence: Option<String>,
    /// `ReflectionTaintEdge` only: e.g. `"getattr"`/`"invoke"`.
    #[serde(default)]
    pub call_type: Option<String>,
    /// `ReflectionTaintEdge` only.
    #[serde(default)]
    pub reflected_targets: Option<Vec<String>>,
    /// `ReflectionTaintEdge` only.
    #[serde(default)]
    pub is_speculative: Option<bool>,
    /// `FrameworkTaintEdge` only: e.g. `"spring"`/`"django"`.
    #[serde(default)]
    pub framework: Option<String>,
    /// `FrameworkTaintEdge` only: e.g. `"@RequestParam"`.
    #[serde(default)]
    pub marker_type: Option<String>,
}

/// One source-to-sink taint chain, structured evidence for S4's confirm/
/// refute prompt (task #37) and S3/S5/S6/S7/S8's shared reachability
/// grounding (tasks #34/#38/#36). Ported from `models.py::TaintEvidencePath`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TaintEvidencePath {
    pub source_ref: String,
    pub sink_ref: String,
    #[serde(default)]
    pub path_funcs: Vec<String>,
    #[serde(default)]
    pub edges: Vec<TaintTransferEdge>,
    #[serde(default)]
    pub sink_cwe: Vec<String>,
    #[serde(default)]
    pub sanitized: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ContextPackage {
    pub repo_root: String,
    pub language: String,
    #[serde(default)]
    pub call_graph: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub call_graph_files: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub entry_points: Vec<EntryPoint>,
    #[serde(default)]
    pub unsafe_sinks: Vec<Sink>,
    #[serde(default)]
    pub modules: Vec<ModuleInfo>,
    #[serde(default)]
    pub all_files: Vec<String>,
    #[serde(default)]
    pub excluded: BTreeMap<String, Value>,
    #[serde(default)]
    pub known_cves: Vec<Cve>,
    #[serde(default)]
    pub design_controls: Vec<Control>,
    /// `--diff-scope`'s changed-file map (repo-relative path -> changed
    /// line numbers), sourced from `ScanInput`/`Step1Input` the same way
    /// `known_cves`/`design_controls` are — never touched by S1's own
    /// agentic call, just stamped into its JSON output before typed
    /// deserialization (see `bc-stage-s1`).
    ///
    /// Empty is NOT the same as "diff-scope is off": a PR whose diff is
    /// only renames, deletions, mode changes or binary files parses to an
    /// empty map (`bc_github::parse_diff` returns no line-level hits for
    /// any of those), and that is a legitimate diff-scoped scan of zero
    /// files. Read [`ContextPackage::diff_scope_active`], never
    /// `changed_files.is_empty()`, to decide whether scoping is in
    /// effect.
    #[serde(default)]
    pub changed_files: BTreeMap<String, BTreeSet<i64>>,
    /// Whether `--diff-scope` was actually requested for this run, as
    /// opposed to `changed_files` merely happening to be empty.
    ///
    /// These two are deliberately separate because "empty" is overloaded:
    /// it means both "the flag was never passed" and "the flag was passed
    /// and the diff matched no source lines." Collapsing them fails open
    /// — a rename-only PR would sweep the whole repository at full LLM
    /// spend while the report claimed no scoping was ever requested. Every
    /// diff-scope-aware pass branches on THIS flag, so `true` with an
    /// empty `changed_files` correctly scopes the scan to nothing.
    ///
    /// `false` (the default, and what old checkpoints deserialize to)
    /// means a full-repo scan, byte-for-byte as before this field existed.
    #[serde(default)]
    pub diff_scope_active: bool,
    /// Qualified def name (`"rel/path::name"`) -> `(start_line, end_line)`,
    /// populated by S0's tree-sitter seed engine and/or S1's `ts_graph`
    /// call-graph backend (`step1.call_graph: tree_sitter`) for
    /// downstream function slicing. Empty when neither ran (e.g.
    /// `step1.call_graph: regex`), which every consumer treats as "no
    /// AST span available for this def."
    #[serde(default)]
    pub def_spans: BTreeMap<String, (i64, i64)>,
    /// S0-seeded (semgrep codeFlow) taint paths: each inner `Vec` is an
    /// ordered list of `"file:line"` hops from source to sink. Ported
    /// from `ContextPackage.seed_taint_paths`. Consumed by tasks
    /// #34/#36/#38's `callgraph_consumer`-equivalent reachability
    /// helpers, not yet by any Rust stage.
    #[serde(default)]
    pub seed_taint_paths: Vec<Vec<String>>,
    /// S0-seeded structured taint evidence — richer than
    /// `seed_taint_paths`: per-edge symbol/transfer-kind detail for S4's
    /// confirm/refute prompt (task #37) and the same reachability
    /// helpers `seed_taint_paths` feeds. Ported from
    /// `ContextPackage.seed_taint_evidence`.
    #[serde(default)]
    pub seed_taint_evidence: Vec<TaintEvidencePath>,
    #[serde(default)]
    pub app_profile: Option<AppProfile>,
    #[serde(default)]
    pub threat_model: Option<ThreatModel>,
    #[serde(default)]
    pub notes: String,
    /// Free-text guidance from the active `bc-compliance` policy (if
    /// any), stamped in by S1 the same way `known_cves`/`design_controls`
    /// are — S3/S4/S6/S8 splice this into their own prompts, each under
    /// its own stage-appropriate header, to steer prioritization. Empty
    /// when no compliance policy is active. Not a port — this tool's own
    /// feature, with no Python-original counterpart.
    #[serde(default)]
    pub compliance_guidance: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("input-validation", ControlKind::InputValidation)]
    #[case("Input-Validation", ControlKind::InputValidation)] // via alias
    #[case("WAF", ControlKind::InputValidation)] // via alias
    #[case("AUTH", ControlKind::Auth)]
    #[case("seccomp", ControlKind::Sandbox)]
    #[case("nonsense", ControlKind::Other)]
    fn control_kind_coercion(#[case] input: &str, #[case] expected: ControlKind) {
        let json = serde_json::json!({"name": "x", "kind": input});
        let c: Control = serde_json::from_value(json).unwrap();
        assert_eq!(c.kind, expected);
    }

    #[rstest]
    #[case("param", "param")]
    #[case("local", "local")]
    #[case("return", "return")]
    #[case("arg", "arg")]
    #[case("field", "field")]
    #[case("container", "container")]
    #[case("property", "property")]
    #[case("nonsense", "local")]
    fn taint_symbol_ref_kind_coercion(#[case] input: &str, #[case] expected: &str) {
        let json = serde_json::json!({"qnode": "a.py::f", "symbol": "x", "kind": input});
        let r: TaintSymbolRef = serde_json::from_value(json).unwrap();
        assert_eq!(r.kind, expected);
    }

    #[rstest]
    #[case("source", "source")]
    #[case("assign", "assign")]
    #[case("arg_to_param", "arg_to_param")]
    #[case("return_to_local", "return_to_local")]
    #[case("return_to_sink", "return_to_sink")]
    #[case("local_to_sink", "local_to_sink")]
    #[case("field_write", "field_write")]
    #[case("field_read", "field_read")]
    #[case("container_put", "container_put")]
    #[case("container_get", "container_get")]
    #[case("sanitize", "sanitize")]
    #[case("nonsense", "assign")]
    fn taint_transfer_edge_kind_coercion(#[case] input: &str, #[case] expected: &str) {
        let json = serde_json::json!({
            "file": "a.py",
            "line": 3,
            "function_qnode": "a.py::f",
            "src": {"qnode": "a.py::f", "symbol": "x", "kind": "local"},
            "dst": {"qnode": "a.py::f", "symbol": "y", "kind": "local"},
            "transfer_kind": input,
        });
        let e: TaintTransferEdge = serde_json::from_value(json).unwrap();
        assert_eq!(e.transfer_kind, expected);
    }

    #[test]
    fn taint_evidence_path_defaults_optional_fields() {
        let json = serde_json::json!({"source_ref": "a.py:1", "sink_ref": "a.py:5"});
        let p: TaintEvidencePath = serde_json::from_value(json).unwrap();
        assert!(p.path_funcs.is_empty());
        assert!(p.edges.is_empty());
        assert!(p.sink_cwe.is_empty());
        assert!(!p.sanitized);
    }

    #[test]
    fn context_package_seed_taint_fields_default_to_empty() {
        let json = serde_json::json!({"repo_root": "/r", "language": "python"});
        let pkg: ContextPackage = serde_json::from_value(json).unwrap();
        assert!(pkg.seed_taint_paths.is_empty());
        assert!(pkg.seed_taint_evidence.is_empty());
    }

    #[test]
    fn context_package_round_trips_populated_seed_taint_fields() {
        let json = serde_json::json!({
            "repo_root": "/r",
            "language": "python",
            "seed_taint_paths": [["a.py:1", "a.py:5"]],
            "seed_taint_evidence": [{
                "source_ref": "a.py:1",
                "sink_ref": "a.py:5",
                "path_funcs": ["f"],
                "edges": [{
                    "file": "a.py",
                    "line": 3,
                    "function_qnode": "a.py::f",
                    "src": {"qnode": "a.py::f", "symbol": "x", "kind": "param"},
                    "dst": {"qnode": "a.py::f", "symbol": "y", "kind": "local"},
                    "transfer_kind": "assign",
                }],
                "sink_cwe": ["CWE-89"],
                "sanitized": true,
            }],
        });
        let pkg: ContextPackage = serde_json::from_value(json).unwrap();
        assert_eq!(
            pkg.seed_taint_paths,
            vec![vec!["a.py:1".to_string(), "a.py:5".to_string()]]
        );
        assert_eq!(pkg.seed_taint_evidence.len(), 1);
        let path = &pkg.seed_taint_evidence[0];
        assert_eq!(path.source_ref, "a.py:1");
        assert!(path.sanitized);
        assert_eq!(path.edges[0].transfer_kind, "assign");
        assert_eq!(path.edges[0].src.kind, "param");
    }

    #[test]
    fn asset_sensitivity_defaults_to_medium_when_absent() {
        let a: Asset = serde_json::from_value(serde_json::json!({"name": "db"})).unwrap();
        assert_eq!(a.sensitivity, Sensitivity::Medium);
    }

    #[rstest]
    #[case("crit", Sensitivity::Critical)]
    #[case("info", Sensitivity::Low)]
    #[case("severe", Sensitivity::High)]
    #[case("bogus", Sensitivity::Medium)]
    fn asset_sensitivity_coercion(#[case] input: &str, #[case] expected: Sensitivity) {
        let a: Asset =
            serde_json::from_value(serde_json::json!({"name": "x", "sensitivity": input})).unwrap();
        assert_eq!(a.sensitivity, expected);
    }

    #[rstest]
    #[case("external", Actor::RemoteUnauth)]
    #[case("tenant", Actor::RemoteAuth)]
    #[case("lan", Actor::AdjacentNetwork)]
    #[case("physical", Actor::LocalUser)]
    #[case("root", Actor::LocalAdmin)]
    #[case("vendor", Actor::SupplyChain)]
    #[case("developer", Actor::Insider)]
    #[case("unknown-thing", Actor::RemoteAuth)]
    fn threat_actor_coercion(#[case] input: &str, #[case] expected: Actor) {
        let t: Threat = serde_json::from_value(serde_json::json!({
            "id": "T1", "threat": "x", "actor": input, "surface": "s",
            "asset": "a", "impact": "low", "likelihood": "rare"
        }))
        .unwrap();
        assert_eq!(t.actor, expected);
    }

    #[rstest]
    #[case("catastrophic", Impact::Existential)]
    #[case("fatal", Impact::Existential)]
    #[case("severe", Impact::High)]
    #[case("info", Impact::Low)]
    #[case("???", Impact::Medium)]
    fn threat_impact_coercion(#[case] input: &str, #[case] expected: Impact) {
        let t: Threat = serde_json::from_value(serde_json::json!({
            "id": "T1", "threat": "x", "actor": "insider", "surface": "s",
            "asset": "a", "impact": input, "likelihood": "rare"
        }))
        .unwrap();
        assert_eq!(t.impact, expected);
    }

    #[rstest]
    #[case("negligible", Likelihood::VeryRare)]
    #[case("unlikely", Likelihood::Rare)]
    #[case("occasional", Likelihood::Possible)]
    #[case("probable", Likelihood::Likely)]
    #[case("certain", Likelihood::AlmostCertain)]
    #[case("???", Likelihood::Possible)]
    fn threat_likelihood_coercion(#[case] input: &str, #[case] expected: Likelihood) {
        let t: Threat = serde_json::from_value(serde_json::json!({
            "id": "T1", "threat": "x", "actor": "insider", "surface": "s",
            "asset": "a", "impact": "low", "likelihood": input
        }))
        .unwrap();
        assert_eq!(t.likelihood, expected);
    }

    #[test]
    fn threat_model_default_is_all_empty() {
        let tm = ThreatModel::default();
        assert!(tm.assets.is_empty());
        assert!(tm.threats.is_empty());
        assert_eq!(tm.system_context, "");
    }

    #[rstest]
    #[case("rpc", EntryPointKind::Network)]
    #[case("graphql", EntryPointKind::Network)]
    #[case("kafka", EntryPointKind::Ipc)]
    #[case("argv", EntryPointKind::Cli)]
    #[case("env", EntryPointKind::File)]
    #[case("pickle", EntryPointKind::Deserialization)]
    #[case("framework", EntryPointKind::Framework)]
    #[case("spring", EntryPointKind::Framework)]
    #[case("django", EntryPointKind::Framework)]
    #[case("aspnet", EntryPointKind::Framework)]
    #[case("???", EntryPointKind::Other)]
    fn entry_point_kind_coercion(#[case] input: &str, #[case] expected: EntryPointKind) {
        let e: EntryPoint = serde_json::from_value(serde_json::json!({
            "file": "a.py", "function": "f", "kind": input
        }))
        .unwrap();
        assert_eq!(e.kind, expected);
    }

    #[rstest]
    #[case("network", EntryPointKind::Network)]
    #[case("http", EntryPointKind::Network)]
    #[case("stdin", EntryPointKind::Cli)]
    #[case("env", EntryPointKind::File)]
    #[case(" HTTP ", EntryPointKind::Network)]
    #[case("framework", EntryPointKind::Framework)]
    #[case("", EntryPointKind::Other)]
    #[case("bogus", EntryPointKind::Other)]
    fn entry_point_kind_parse_resolves_aliases(
        #[case] input: &str,
        #[case] expected: EntryPointKind,
    ) {
        assert_eq!(EntryPointKind::parse(input), expected);
    }

    #[test]
    fn entry_point_kind_parse_agrees_with_the_serde_path_for_every_alias() {
        // One table, two readers: a label that resolves through JSON
        // must resolve identically in code, and no alias may land on
        // `Other`, or a corpus spelling it would be silently discarded.
        for (alias, _) in EP_KIND_ALIAS {
            let e: EntryPoint = serde_json::from_value(serde_json::json!({
                "file": "a.py", "function": "f", "kind": alias
            }))
            .unwrap();
            assert_eq!(EntryPointKind::parse(alias), e.kind, "{alias}");
            assert_ne!(
                EntryPointKind::parse(alias),
                EntryPointKind::Other,
                "{alias}"
            );
        }
    }

    #[test]
    fn sink_line_defaults_and_coerces() {
        let s: Sink =
            serde_json::from_value(serde_json::json!({"file": "a.c", "function": "strcpy"}))
                .unwrap();
        assert_eq!(s.line, 0);
        let s2: Sink = serde_json::from_value(
            serde_json::json!({"file": "a.c", "function": "strcpy", "line": "42"}),
        )
        .unwrap();
        assert_eq!(s2.line, 42);
    }

    #[test]
    fn module_info_loc_coerces_malformed_to_zero() {
        let m: ModuleInfo =
            serde_json::from_value(serde_json::json!({"name": "core", "loc": "not-a-number"}))
                .unwrap();
        assert_eq!(m.loc, 0);
    }

    #[test]
    fn context_package_defaults_are_empty() {
        let ctx: ContextPackage =
            serde_json::from_value(serde_json::json!({"repo_root": "/r", "language": "python"}))
                .unwrap();
        assert!(ctx.entry_points.is_empty());
        assert!(ctx.unsafe_sinks.is_empty());
        assert!(ctx.call_graph.is_empty());
        assert!(ctx.app_profile.is_none());
        assert!(ctx.threat_model.is_none());
    }

    #[test]
    fn context_package_round_trips_through_json() {
        let ctx = ContextPackage {
            repo_root: "/r".to_string(),
            language: "rust".to_string(),
            all_files: vec!["src/main.rs".to_string()],
            ..Default::default()
        };
        let v = serde_json::to_value(&ctx).unwrap();
        let back: ContextPackage = serde_json::from_value(v).unwrap();
        assert_eq!(ctx, back);
    }

    #[test]
    fn cve_defaults() {
        let c: Cve =
            serde_json::from_value(serde_json::json!({"id": "CVE-2024-1", "summary": "x"}))
                .unwrap();
        assert!(c.affected_files.is_empty());
        assert_eq!(c.cvss, None);
        assert!(!c.patched);
    }
}
