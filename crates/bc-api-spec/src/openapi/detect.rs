//! Recognizing OpenAPI and Swagger files, first by name and then by
//! content (see [`crate::tree`] for the rules shared with the other JSON
//! and YAML standards). A file becomes a specification when its parsed top
//! level declares `openapi: 3.x` or `swagger: "2.0"`.

use serde_json::Value;

use crate::format::Syntax;
pub use crate::format::{Candidate, NameStrength, SpecVersion};
use crate::tree::TreeRules;

/// The declared version, read leniently: a YAML author who wrote
/// `swagger: 2.0` or `openapi: 3.1` gets a number where the specification
/// wants a string. The document is still recognized as what it is, and the
/// validator reports the type separately, so a repair can quote it.
pub fn declared_version(document: &Value) -> Option<SpecVersion> {
    if let Some(openapi) = document.get("openapi").and_then(scalar_text) {
        let mut parts = openapi.split('.');
        return match (parts.next(), parts.next()) {
            (Some("3"), Some("0")) => Some(SpecVersion::OpenApi30),
            (Some("3"), Some("1")) => Some(SpecVersion::OpenApi31),
            (Some("3"), Some("2")) => Some(SpecVersion::OpenApi32),
            _ => None,
        };
    }
    match document.get("swagger").and_then(scalar_text).as_deref() {
        Some("2.0") => Some(SpecVersion::Swagger20),
        _ => None,
    }
}

/// A version written as a string or, leniently, as a YAML number.
pub(crate) fn scalar_text(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        _ => None,
    }
}

/// Whether `path` (repository relative, `/` separated) is a specification
/// candidate by name, and how strongly. Strong names are `openapi.*`,
/// `swagger.*`, `*.openapi.*`, `*.swagger.*` and Ktor's
/// `openapi/documentation.yaml`; weak ones are `api-docs.*` (l5-swagger),
/// `api.*`, and names containing `openapi` or `swagger`.
pub fn candidate_strength(path: &str) -> Option<NameStrength> {
    Syntax::from_path(path)?;
    let lower = path.to_ascii_lowercase();
    let name = lower.rsplit('/').next().unwrap_or_default();
    // The extension check above guarantees a dot.
    let stem = name.rsplit_once('.').map_or(name, |(stem, _)| stem);
    if matches!(stem, "openapi" | "swagger")
        || stem.ends_with(".openapi")
        || stem.ends_with(".swagger")
        || lower == "openapi/documentation.yaml"
        || lower.ends_with("/openapi/documentation.yaml")
    {
        return Some(NameStrength::Strong);
    }
    if stem == "api-docs" || stem == "api" || stem.contains("openapi") || stem.contains("swagger") {
        return Some(NameStrength::Weak);
    }
    None
}

const RULES: TreeRules = TreeRules {
    markers: &["openapi", "swagger"],
    shape: &["info", "paths"],
    // A strongly named file that declares another standard is that
    // standard's document, never an incomplete OpenAPI one.
    foreign: &["asyncapi", "openrpc"],
    version: declared_version,
};

/// Classify one candidate's bytes. `max_bytes` bounds what is parsed.
pub fn classify(path: &str, bytes: &[u8], max_bytes: usize) -> Candidate {
    crate::tree::classify(path, bytes, max_bytes, candidate_strength(path), &RULES)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn names_nominate_candidates_with_a_strength() {
        for strong in [
            "openapi.yaml",
            "docs/api/openapi.json",
            "swagger/v1/swagger.yaml",
            "wwwroot/swagger/v1/swagger.json",
            "src/main/resources/static/openapi.yml",
            "api/petstore.openapi.yaml",
            "gen/service.swagger.json",
            "openapi/documentation.yaml",
            "src/main/resources/openapi/documentation.yaml",
        ] {
            assert_eq!(
                candidate_strength(strong),
                Some(NameStrength::Strong),
                "{strong}"
            );
        }
        for weak in [
            "storage/api-docs/api-docs.json",
            "api.yaml",
            "docs/petstore-openapi-v1.json",
            "legacy_swagger_spec.yml",
        ] {
            assert_eq!(candidate_strength(weak), Some(NameStrength::Weak), "{weak}");
        }
        for not in [
            "openapi.md",
            "package.json",
            "docs/documentation.yaml",
            "README",
        ] {
            assert_eq!(candidate_strength(not), None, "{not}");
        }
    }

    #[test]
    fn versions_are_read_leniently_from_strings_and_numbers() {
        assert_eq!(
            declared_version(&json!({"openapi": "3.0.3"})),
            Some(SpecVersion::OpenApi30)
        );
        assert_eq!(
            declared_version(&json!({"openapi": "3.1.0"})),
            Some(SpecVersion::OpenApi31)
        );
        assert_eq!(
            declared_version(&json!({"openapi": 3.1})),
            Some(SpecVersion::OpenApi31)
        );
        assert_eq!(
            declared_version(&json!({"openapi": "3.2.0"})),
            Some(SpecVersion::OpenApi32)
        );
        assert_eq!(declared_version(&json!({"openapi": "4.0.0"})), None);
        assert_eq!(declared_version(&json!({"openapi": true})), None);
        assert_eq!(
            declared_version(&json!({"swagger": "2.0"})),
            Some(SpecVersion::Swagger20)
        );
        assert_eq!(
            declared_version(&json!({"swagger": 2.0})),
            Some(SpecVersion::Swagger20)
        );
        assert_eq!(declared_version(&json!({"swagger": "1.2"})), None);
        assert_eq!(declared_version(&json!({})), None);
        assert!(SpecVersion::Swagger20.is_swagger());
        assert!(!SpecVersion::OpenApi30.is_swagger());
        assert!(SpecVersion::OpenApi31.responses_optional());
        assert!(SpecVersion::OpenApi32.responses_optional());
        assert!(!SpecVersion::OpenApi30.responses_optional());
    }

    #[test]
    fn content_confirms_or_rejects_a_candidate() {
        let spec = classify("openapi.yaml", b"openapi: 3.1.0\ninfo:\n  title: x\n", 1024);
        assert!(matches!(
            spec,
            Candidate::Spec {
                version: Some(SpecVersion::OpenApi31),
                syntax: Syntax::Yaml,
                ..
            }
        ));
        let weak = classify("api.json", br#"{"swagger":"2.0","info":{}}"#, 1024);
        assert!(matches!(
            weak,
            Candidate::Spec {
                version: Some(SpecVersion::Swagger20),
                ..
            }
        ));
        assert_eq!(
            classify("README.md", b"openapi: 3.1.0", 1024),
            Candidate::NotASpec
        );
        assert_eq!(
            classify("api.json", br#"{"name":"x"}"#, 1024),
            Candidate::NotASpec
        );
        assert_eq!(
            classify("openapi.json", br#"{"name":"x"}"#, 1024),
            Candidate::NotASpec
        );
        assert_eq!(classify("openapi.json", b"[1]", 1024), Candidate::NotASpec);
    }

    #[test]
    fn another_standards_document_is_never_an_incomplete_specification() {
        let asyncapi = classify("openapi.yaml", b"asyncapi: 9.0.0\ninfo: {}\n", 1024);
        assert_eq!(asyncapi, Candidate::NotASpec);
    }

    #[test]
    fn a_strong_name_without_a_version_is_a_broken_specification() {
        let broken = classify("openapi.json", br#"{"info":{"title":"x"}}"#, 1024);
        assert!(matches!(
            broken,
            Candidate::Broken {
                syntax: Syntax::Json,
                ..
            }
        ));
        let paths_only = classify("swagger.yaml", b"paths: {}\n", 1024);
        assert!(matches!(paths_only, Candidate::Broken { .. }));
        // A weak name with the same content is not claimed.
        assert_eq!(
            classify("api.json", br#"{"info":{}}"#, 1024),
            Candidate::NotASpec
        );
    }

    #[test]
    fn unsupported_versions_are_never_touched() {
        for (path, bytes) in [
            ("openapi.json", br#"{"openapi":"4.0.0"}"#.as_slice()),
            ("api.json", br#"{"swagger":"1.2"}"#.as_slice()),
        ] {
            assert!(matches!(
                classify(path, bytes, 1024),
                Candidate::Unverifiable { .. }
            ));
        }
    }

    #[test]
    fn unparseable_json_under_a_strong_name_is_malformed_and_replaceable() {
        assert!(matches!(
            classify("openapi.json", b"{\"openapi\": ", 1024),
            Candidate::Malformed {
                syntax: Syntax::Json,
                ..
            }
        ));
        // A weak name that claims to be a spec is left alone instead.
        assert!(matches!(
            classify("api.json", b"{\"openapi\": ", 1024),
            Candidate::Unverifiable { .. }
        ));
        assert_eq!(
            classify("api.json", b"{\"name\": ", 1024),
            Candidate::NotASpec
        );
    }

    #[test]
    fn yaml_the_built_in_parser_cannot_verify_is_never_treated_as_malformed() {
        let anchors = b"openapi: 3.0.3\ninfo: &info\n  title: x\n";
        assert!(matches!(
            classify("openapi.yaml", anchors, 1024),
            Candidate::Unverifiable { .. }
        ));
        assert!(matches!(
            classify("api.yaml", anchors, 1024),
            Candidate::Unverifiable { .. }
        ));
        assert_eq!(
            classify("api.yaml", b"name: &a x\n", 1024),
            Candidate::NotASpec
        );
    }

    #[test]
    fn oversized_and_non_utf8_files_are_bounded() {
        let big = b"openapi: 3.1.0\n".repeat(10);
        assert!(matches!(
            classify("openapi.yaml", &big, 20),
            Candidate::Unverifiable { .. }
        ));
        assert!(matches!(
            classify("api.yaml", &big, 20),
            Candidate::Unverifiable { .. }
        ));
        assert_eq!(
            classify("api.yaml", &b"name: x\n".repeat(10), 20),
            Candidate::NotASpec
        );
        assert!(matches!(
            classify("openapi.yaml", &[0xff, 0xfe], 20),
            Candidate::Unverifiable { .. }
        ));
        assert_eq!(classify("api.yaml", &[0xff, 0xfe], 20), Candidate::NotASpec);
    }
}
