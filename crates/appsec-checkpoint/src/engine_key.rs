use sha1::{Digest, Sha1};

const STEP_DIGEST_CHARS: usize = 16;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EngineKey {
    pub engine_id: String,
    pub engine_version: String,
    pub model: String,
    pub dialect: String,
    pub base_host: String,
}

impl EngineKey {
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
