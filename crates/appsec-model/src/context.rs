use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

use crate::coerce;

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

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reach {
    pub name: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub authenticated: Option<bool>,
}

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
    #[serde(default)]
    pub exposure: String,
    #[serde(default)]
    pub reaches: Vec<Reach>,
    #[serde(default)]
    pub reached_by: Vec<Reach>,
}

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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Sink {
    pub file: String,
    #[serde(default = "default_zero_i64", deserialize_with = "deserialize_line")]
    pub line: i64,
    pub function: String,
    #[serde(default)]
    pub snippet: String,
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
    Ok(coerce::coerce_enum_str(
        &v,
        TAINT_SYMBOL_KIND_VALID,
        &[],
        "local",
    ))
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TaintSymbolRef {
    pub qnode: String,
    pub symbol: String,
    #[serde(deserialize_with = "deserialize_taint_symbol_kind")]
    pub kind: String,
}

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
    Ok(coerce::coerce_enum_str(
        &v,
        TRANSFER_KIND_VALID,
        &[],
        "assign",
    ))
}

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
    #[serde(default)]
    pub condition_text: Option<String>,
    #[serde(default)]
    pub is_tainted_condition: Option<bool>,
    #[serde(default)]
    pub confidence: Option<String>,
    #[serde(default)]
    pub call_type: Option<String>,
    #[serde(default)]
    pub reflected_targets: Option<Vec<String>>,
    #[serde(default)]
    pub is_speculative: Option<bool>,
    #[serde(default)]
    pub framework: Option<String>,
    #[serde(default)]
    pub marker_type: Option<String>,
}

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
    pub design_controls: Vec<Control>,
    #[serde(default)]
    pub changed_files: BTreeMap<String, BTreeSet<i64>>,
    #[serde(default)]
    pub diff_scope_active: bool,
    #[serde(default)]
    pub def_spans: BTreeMap<String, (i64, i64)>,
    #[serde(default)]
    pub seed_taint_paths: Vec<Vec<String>>,
    #[serde(default)]
    pub seed_taint_evidence: Vec<TaintEvidencePath>,
    #[serde(default)]
    pub app_profile: Option<AppProfile>,
    #[serde(default)]
    pub threat_model: Option<ThreatModel>,
    #[serde(default)]
    pub provider_digest: Option<crate::ProviderDigest>,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub compliance_guidance: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("input-validation", ControlKind::InputValidation)]
    #[case("Input-Validation", ControlKind::InputValidation)]
    #[case("WAF", ControlKind::InputValidation)]
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
}
