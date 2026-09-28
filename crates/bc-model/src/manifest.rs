//! Step 3 output: `TaskManifest`, the strategist's risk-ranked hunt list.

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

use crate::coerce;

const CHUNK_SIZE_VALID: &[&str] = &["small", "medium", "large"];
const CHUNK_SIZE_ALIAS: &[(&str, &str)] = &[
    ("xs", "small"),
    ("tiny", "small"),
    ("s", "small"),
    ("m", "medium"),
    ("med", "medium"),
    ("moderate", "medium"),
    ("normal", "medium"),
    ("default", "medium"),
    ("l", "large"),
    ("xl", "large"),
    ("xxl", "large"),
    ("big", "large"),
    ("huge", "large"),
    ("x_large", "large"),
];

/// `small` fits in one context (exhaustive); `medium` fits but tight;
/// `large` needs a sliding window anchored to entry points.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChunkSize {
    Small,
    Medium,
    Large,
}

impl ChunkSize {
    fn from_canonical(s: &str) -> Self {
        match s {
            "small" => Self::Small,
            "large" => Self::Large,
            _ => Self::Medium,
        }
    }
}

fn deserialize_chunk_size<'de, D>(d: D) -> Result<ChunkSize, D::Error>
where
    D: Deserializer<'de>,
{
    let v = Value::deserialize(d)?;
    let s = coerce::coerce_enum_str(&v, CHUNK_SIZE_VALID, CHUNK_SIZE_ALIAS, "medium");
    Ok(ChunkSize::from_canonical(&s))
}

fn deserialize_rationale<'de, D>(d: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(match Value::deserialize(d)? {
        Value::String(s) => s,
        _ => String::new(),
    })
}

fn default_chunk_size() -> ChunkSize {
    ChunkSize::Medium
}

fn default_risk_rank() -> i64 {
    999
}

fn deserialize_risk_rank<'de, D>(d: D) -> Result<i64, D::Error>
where
    D: Deserializer<'de>,
{
    let v = Value::deserialize(d)?;
    Ok(coerce::coerce_int(&v, 999))
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Chunk {
    pub id: String,
    #[serde(
        default = "default_chunk_size",
        deserialize_with = "deserialize_chunk_size"
    )]
    pub size: ChunkSize,
    /// 1 = highest risk, descending.
    #[serde(
        default = "default_risk_rank",
        deserialize_with = "deserialize_risk_rank"
    )]
    pub risk_rank: i64,
    #[serde(default)]
    pub files: Vec<String>,
    #[serde(default)]
    pub focus_entry_points: Vec<String>,
    #[serde(default)]
    pub hypothesis: String,
    #[serde(default)]
    pub related_cves: Vec<String>,
    #[serde(default)]
    pub threat_id: Option<String>,
    #[serde(default)]
    pub languages: Vec<String>,
    #[serde(default)]
    pub specialist: Option<String>,
    /// Taint-chunk metadata (populated by S3 for entry→…→sink chunks;
    /// empty on risk/specialist/catch-all chunks). Drives S4's function-
    /// slice loading and confirm/refute prompt under the `taint.yaml`
    /// profile. Ported from `models.py::Chunk`'s own taint-chunk fields.
    /// Qnodes on the BFS path, entry -> ... -> sink.
    #[serde(default)]
    pub path_funcs: Vec<String>,
    /// `"file::function"` — the `EntryPoint`.
    #[serde(default)]
    pub source_ref: String,
    /// `"file:line"` — the `Sink` location.
    #[serde(default)]
    pub sink_ref: String,
    /// CWE tags from S0 rule metadata (confirm/refute focus).
    #[serde(default)]
    pub sink_cwe: Vec<String>,
    /// Which shared file bucket a specialist chunk reviews: `"shard-NN"`
    /// for the default source buckets every unscoped lens shares, and
    /// `"iac-shard-NN"` for the IaC-only buckets. Empty on every other
    /// chunk kind. S3 emits specialist chunks shard-major (every lens for
    /// shard 1, then shard 2, ...), so consecutive S4 calls with the same
    /// `shard_id` send an identical source prefix and can reuse a provider
    /// prompt cache. Ported from upstream v1.3 `Chunk.shard_id`.
    #[serde(default)]
    pub shard_id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TaskManifest {
    /// Deliberately required: a missing or null `chunks` key is what marks
    /// a genuinely malformed strategist reply, which S3 must still degrade.
    pub chunks: Vec<Chunk>,
    /// Defaulted (and a JSON `null` or non-string read as empty), as
    /// upstream v1.3 does: a reply missing only its rationale used to fail
    /// the whole manifest even though every chunk was well formed.
    #[serde(default, deserialize_with = "deserialize_rationale")]
    pub rationale: String,
    /// Files `step3.catchall_mode=reachable_only` dropped from catch-all
    /// review (call-graph unreachable from any entry point/sink) — listed
    /// here so coverage is auditable, never silently truncated. Always
    /// empty under `default.yaml` (that mode is opt-in). Populated
    /// deterministically after the LLM strategist call, so `#[serde(default)]`
    /// keeps a strategist response that never mentions this field parsing
    /// cleanly. Ported from `models.py::TaskManifest.unreachable_files`.
    #[serde(default)]
    pub unreachable_files: Vec<String>,
}

impl TaskManifest {
    /// Chunks ordered by ascending `risk_rank` (1 = highest risk first).
    /// Stable with respect to input order for ties, matching Python's
    /// `sorted()` (Timsort, stable).
    pub fn sorted_chunks(&self) -> Vec<&Chunk> {
        let mut v: Vec<&Chunk> = self.chunks.iter().collect();
        v.sort_by_key(|c| c.risk_rank);
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("small", ChunkSize::Small)]
    #[case("xs", ChunkSize::Small)]
    #[case("tiny", ChunkSize::Small)]
    #[case("XL", ChunkSize::Large)]
    #[case("huge", ChunkSize::Large)]
    #[case("m", ChunkSize::Medium)]
    #[case("???", ChunkSize::Medium)]
    fn chunk_size_coercion(#[case] input: &str, #[case] expected: ChunkSize) {
        let c: Chunk =
            serde_json::from_value(serde_json::json!({"id": "c1", "size": input})).unwrap();
        assert_eq!(c.size, expected);
    }

    #[test]
    fn chunk_defaults() {
        let c: Chunk = serde_json::from_value(serde_json::json!({"id": "c1"})).unwrap();
        assert_eq!(c.size, ChunkSize::Medium);
        assert_eq!(c.risk_rank, 999);
        assert!(c.files.is_empty());
        assert_eq!(c.threat_id, None);
        assert_eq!(c.specialist, None);
    }

    #[test]
    fn chunk_risk_rank_coerces_malformed_to_default() {
        let c: Chunk =
            serde_json::from_value(serde_json::json!({"id": "c1", "risk_rank": "high"})).unwrap();
        assert_eq!(c.risk_rank, 999);
        let c2: Chunk =
            serde_json::from_value(serde_json::json!({"id": "c1", "risk_rank": 3})).unwrap();
        assert_eq!(c2.risk_rank, 3);
    }

    #[test]
    fn task_manifest_rationale_is_optional_and_null_tolerant_but_chunks_is_not() {
        let m: TaskManifest = serde_json::from_value(serde_json::json!({"chunks": []})).unwrap();
        assert_eq!(m.rationale, "");
        let m: TaskManifest =
            serde_json::from_value(serde_json::json!({"chunks": [], "rationale": null})).unwrap();
        assert_eq!(m.rationale, "");
        let m: TaskManifest =
            serde_json::from_value(serde_json::json!({"chunks": [], "rationale": "r"})).unwrap();
        assert_eq!(m.rationale, "r");
        assert!(
            serde_json::from_value::<TaskManifest>(serde_json::json!({"rationale": "r"})).is_err()
        );
    }

    #[test]
    fn chunk_shard_id_defaults_to_empty_and_round_trips() {
        // A checkpoint written before the field existed must still load.
        let c: Chunk = serde_json::from_value(serde_json::json!({"id": "c1"})).unwrap();
        assert_eq!(c.shard_id, "");
        let c: Chunk =
            serde_json::from_value(serde_json::json!({"id": "c1", "shard_id": "shard-02"}))
                .unwrap();
        assert_eq!(serde_json::to_value(&c).unwrap()["shard_id"], "shard-02");
    }

    #[test]
    fn sorted_chunks_orders_by_ascending_risk_rank_stably() {
        let manifest = TaskManifest {
            chunks: vec![
                Chunk {
                    id: "c-b".into(),
                    size: ChunkSize::Medium,
                    risk_rank: 5,
                    files: vec![],
                    focus_entry_points: vec![],
                    hypothesis: String::new(),
                    related_cves: vec![],
                    threat_id: None,
                    languages: vec![],
                    specialist: None,
                    path_funcs: vec![],
                    source_ref: String::new(),
                    sink_ref: String::new(),
                    sink_cwe: vec![],
                    shard_id: String::new(),
                },
                Chunk {
                    id: "c-a".into(),
                    size: ChunkSize::Medium,
                    risk_rank: 1,
                    files: vec![],
                    focus_entry_points: vec![],
                    hypothesis: String::new(),
                    related_cves: vec![],
                    threat_id: None,
                    languages: vec![],
                    specialist: None,
                    path_funcs: vec![],
                    source_ref: String::new(),
                    sink_ref: String::new(),
                    sink_cwe: vec![],
                    shard_id: String::new(),
                },
                Chunk {
                    id: "c-c".into(),
                    size: ChunkSize::Medium,
                    risk_rank: 5,
                    files: vec![],
                    focus_entry_points: vec![],
                    hypothesis: String::new(),
                    related_cves: vec![],
                    threat_id: None,
                    languages: vec![],
                    specialist: None,
                    path_funcs: vec![],
                    source_ref: String::new(),
                    sink_ref: String::new(),
                    sink_cwe: vec![],
                    shard_id: String::new(),
                },
            ],
            rationale: "r".into(),
            unreachable_files: Vec::new(),
        };
        let ids: Vec<&str> = manifest
            .sorted_chunks()
            .iter()
            .map(|c| c.id.as_str())
            .collect();
        assert_eq!(ids, vec!["c-a", "c-b", "c-c"]);
    }

    #[test]
    fn sorted_chunks_empty_manifest() {
        let manifest = TaskManifest {
            chunks: vec![],
            rationale: "r".into(),
            unreachable_files: Vec::new(),
        };
        assert!(manifest.sorted_chunks().is_empty());
    }
}
