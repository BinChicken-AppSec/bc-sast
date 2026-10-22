//! OpenAPI 3.0, 3.1 and 3.2 and Swagger 2.0: the first standard on the
//! framework, with HTTP operations (lower-case method, path template) as
//! its inventory and web frameworks as its owners.

pub mod detect;
pub mod location;
pub mod preserve;
pub mod routes;
pub mod validate;

use serde_json::Value;

use crate::diagnostic::Diagnostic;
use crate::format::{
    framework_names, Candidate, Capabilities, FormatId, NameStrength, Owner, Peer, SpecFormat,
    SpecVersion, Syntax,
};
use crate::inventory::{CitedOperation, Completeness, Operation};
use crate::libraries::ApiSurface;
use crate::location::Convention;
use crate::parse::ParseFailure;
use crate::plan::HttpService;

/// OpenAPI and Swagger.
pub struct OpenApi;

/// The registered instance.
pub static OPENAPI: OpenApi = OpenApi;

impl SpecFormat for OpenApi {
    fn id(&self) -> FormatId {
        FormatId::OpenApi
    }

    fn name(&self) -> &'static str {
        "OpenAPI"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::FULL
    }

    fn candidate_strength(&self, path: &str) -> Option<NameStrength> {
        detect::candidate_strength(path)
    }

    fn classify(&self, path: &str, bytes: &[u8], max_bytes: usize) -> Candidate {
        detect::classify(path, bytes, max_bytes)
    }

    fn parse(&self, text: &str, syntax: Syntax) -> Result<Value, ParseFailure> {
        crate::parse::parse(text, syntax)
    }

    fn version(&self, document: &Value) -> Option<SpecVersion> {
        detect::declared_version(document)
    }

    fn validate(&self, document: &Value, _: &[Peer<'_>]) -> Vec<Diagnostic> {
        // External references are reported as unverified warnings rather
        // than resolved against other files.
        validate::validate(document)
    }

    fn operations(&self, document: &Value) -> Vec<Operation> {
        routes::spec_operations(document)
    }

    fn compare(&self, document: &Value, _: &[Peer<'_>], inventory: &[Operation]) -> Completeness {
        routes::compare(document, inventory)
    }

    fn preservation(
        &self,
        original: &Value,
        repaired: &Value,
        before: &[Diagnostic],
    ) -> Vec<String> {
        preserve::violations(original, repaired, before)
    }

    fn inventory_operation(&self, method: &str, path: &str) -> Result<Operation, String> {
        let method = routes::normalize_method(method)
            .ok_or_else(|| format!("inventory method {method:?} is not an HTTP method"))?;
        if !path.starts_with('/') {
            return Err(format!("inventory path {path:?} must start with /"));
        }
        Ok(Operation::new(method, path))
    }

    fn emit(&self, document: &Value, syntax: Syntax) -> Result<String, String> {
        if !document.is_object() {
            return Err("a create decision needs `document` as a mapping".into());
        }
        match syntax {
            Syntax::Yaml => crate::emit::to_yaml(document),
            Syntax::Json => Ok(crate::emit::to_json(document)),
            other => Err(format!("OpenAPI is written as JSON or YAML, not {other:?}")),
        }
    }

    fn new_document_problems(&self, document: &Value) -> Vec<String> {
        if detect::declared_version(document) == Some(SpecVersion::OpenApi31) {
            Vec::new()
        } else {
            vec!["a new document must declare openapi: \"3.1.0\"".into()]
        }
    }

    fn owners(&self, services: &[HttpService], _: &[ApiSurface]) -> Vec<Owner> {
        services
            .iter()
            .map(|service| Owner {
                root: service.root.clone(),
                stack: framework_names(&service.frameworks),
                convention: location::convention(&service.frameworks),
            })
            .collect()
    }

    fn fallback(&self) -> Convention {
        location::FALLBACK
    }

    fn scans_source(&self) -> bool {
        false
    }

    fn scan_source(&self, _: &str, _: &str) -> Vec<CitedOperation> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frameworks::WebFramework;
    use serde_json::json;

    #[test]
    fn the_trait_exposes_the_openapi_rules() {
        let format: &dyn SpecFormat = &OPENAPI;
        assert_eq!(format.name(), "OpenAPI");
        assert_eq!(format.capabilities(), Capabilities::FULL);
        assert_eq!(
            format.candidate_strength("openapi.yaml"),
            Some(NameStrength::Strong)
        );
        let text = "openapi: 3.1.0\ninfo:\n  title: t\n  version: \"1\"\npaths: {}\n";
        assert!(matches!(
            format.classify("openapi.yaml", text.as_bytes(), 1024),
            Candidate::Spec { .. }
        ));
        let document = format.parse(text, Syntax::Yaml).unwrap();
        assert_eq!(format.version(&document), Some(SpecVersion::OpenApi31));
        assert!(format.validate(&document, &[]).is_empty());
        assert!(format.operations(&document).is_empty());
        assert!(format.compare(&document, &[], &[]).is_complete());
        assert!(format.preservation(&document, &document, &[]).is_empty());
        assert!(format.new_document_problems(&document).is_empty());
        assert_eq!(
            format.new_document_problems(&json!({"openapi": "3.0.3"})),
            ["a new document must declare openapi: \"3.1.0\""]
        );
        assert_eq!(
            format.emit(&json!({"a": 1}), Syntax::Json).unwrap(),
            "{\n  \"a\": 1\n}\n"
        );
        assert_eq!(
            format.emit(&json!({"a": 1}), Syntax::Yaml).unwrap(),
            "\"a\": 1\n"
        );
        assert!(format
            .emit(&json!({}), Syntax::Graphql)
            .unwrap_err()
            .contains("not Graphql"));
        assert!(format
            .emit(&json!([]), Syntax::Json)
            .unwrap_err()
            .contains("as a mapping"));
        assert_eq!(format.fallback().path, "docs/api/openapi.yaml");
    }

    #[test]
    fn inventory_entries_are_http_operations() {
        assert_eq!(
            OPENAPI.inventory_operation("GET", "/a").unwrap(),
            Operation::new("get", "/a")
        );
        assert!(OPENAPI
            .inventory_operation("ANY", "/a")
            .unwrap_err()
            .contains("not an HTTP method"));
        assert!(OPENAPI
            .inventory_operation("get", "a")
            .unwrap_err()
            .contains("must start with /"));
    }

    #[test]
    fn owners_are_the_http_services_with_their_conventions() {
        let services = [HttpService {
            root: "svc".into(),
            manifests: vec!["svc/pom.xml".into()],
            frameworks: [WebFramework::SpringBoot].into_iter().collect(),
        }];
        let owners = OPENAPI.owners(&services, &[]);
        assert_eq!(owners[0].root, "svc");
        assert_eq!(owners[0].stack, ["spring_boot"]);
        assert!(owners[0].convention.confident);
    }
}
