//! Engine-keyed dynamic checkpoint steps, ported from
//! `orchestrator/checkpoints.py::step_key_for` (vvaharness v1.3.0).
//!
//! **Why.** A per-finding checkpoint used to be keyed by the finding
//! alone (`remediate_<index>`), so `--resume` under a different model or
//! backend happily republished the previous model's remediation as this
//! run's result. The key now hashes everything that produced the result:
//! which engine, which version of it, which model, through which API
//! dialect and host. Change any of them and the old row is simply not
//! found (and [`crate::CheckpointStore::prune_stale`] clears it away).
//!
//! **SHA-1, not Python's SHA-256**, for the same reason as
//! [`crate::run_id_for`]: this is staleness detection over values the
//! operator controls, not a security boundary, and the workspace already
//! carries a vetted `sha1` while `sha2` would be a new dependency.

use sha1::{Digest, Sha1};

/// Hex characters of the digest kept in a step key. 16 hex characters is
/// 64 bits: far beyond any number of steps one run holds.
const STEP_DIGEST_CHARS: usize = 16;

/// Everything about the producer of a checkpointed result that must
/// match for the result to be reused.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EngineKey {
    /// Which engine produced it, e.g. `bc-sast.s10`.
    pub engine_id: String,
    /// That engine's version: a result from an older release may have been
    /// produced under rules this release no longer applies.
    pub engine_version: String,
    /// The model (or, for a panel, every persona model) that answered.
    pub model: String,
    /// The API dialect it was reached through (`openai`, `anthropic`).
    pub dialect: String,
    /// The gateway host it was reached through. A model name is only
    /// meaningful relative to the endpoint that served it.
    pub base_host: String,
}

impl EngineKey {
    /// The newline-joined material hashed into a step key. Newline is safe
    /// as a separator because none of these values can contain one that
    /// would let two different tuples produce the same material: they come
    /// from operator configuration, and a field containing a newline would
    /// at worst make a key differ, never collide by design.
    fn material(&self, case_id: &str) -> String {
        [
            self.engine_id.as_str(),
            self.engine_version.as_str(),
            case_id,
            self.model.as_str(),
            self.dialect.as_str(),
            self.base_host.as_str(),
        ]
        .join("\n")
    }
}

/// The dynamic checkpoint step for `case_id` under `engine`:
/// `prefix` followed by a truncated hex digest, so the key reveals nothing
/// about the finding or the model while staying stable across runs.
pub fn step_key_for(prefix: &str, engine: &EngineKey, case_id: &str) -> String {
    let digest: String = Sha1::digest(engine.material(case_id).as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("{prefix}{}", &digest[..STEP_DIGEST_CHARS])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> EngineKey {
        EngineKey {
            engine_id: "bc-sast.s10".to_string(),
            engine_version: "1.0.0".to_string(),
            model: "model-a".to_string(),
            dialect: "openai".to_string(),
            base_host: "gateway.example".to_string(),
        }
    }

    #[test]
    fn a_step_key_is_the_prefix_plus_a_stable_digest() {
        let key = step_key_for("remediate_", &engine(), "case-1");
        assert!(key.starts_with("remediate_"));
        assert_eq!(key.len(), "remediate_".len() + STEP_DIGEST_CHARS);
        assert_eq!(key, step_key_for("remediate_", &engine(), "case-1"));
        assert!(!key.contains("model-a"));
    }

    #[test]
    fn every_field_changes_the_key() {
        let base = step_key_for("p_", &engine(), "case-1");
        let variants = [
            EngineKey {
                engine_id: "other".to_string(),
                ..engine()
            },
            EngineKey {
                engine_version: "2.0.0".to_string(),
                ..engine()
            },
            EngineKey {
                model: "model-b".to_string(),
                ..engine()
            },
            EngineKey {
                dialect: "anthropic".to_string(),
                ..engine()
            },
            EngineKey {
                base_host: "other.example".to_string(),
                ..engine()
            },
        ];
        for variant in variants {
            assert_ne!(step_key_for("p_", &variant, "case-1"), base, "{variant:?}");
        }
        assert_ne!(step_key_for("p_", &engine(), "case-2"), base);
    }
}
