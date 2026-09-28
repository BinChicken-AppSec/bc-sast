//! RAML 0.8 and 1.0: detected and sanity-checked, never rewritten.
//!
//! A RAML document is YAML whose first line is a `#%RAML <version>`
//! header (`#%RAML 1.0 Library` and other fragment types name the
//! fragment after the version). RAML leans on `!include` tags, which the
//! strict YAML parser refuses, so such a document is reported as
//! unverifiable rather than guessed at. A readable root API document is
//! checked for a `title`, a credential-free `baseUri`, resources that are
//! mappings, known methods and numeric response codes.
//!
//! This step does not maintain RAML: it reports it, and notes that it
//! could be converted to OpenAPI by hand, after which the OpenAPI step
//! maintains that document.

use serde_json::{json, Map, Value};

use crate::diagnostic::{escape, Code, Diagnostic};
use crate::format::{
    Candidate, Capabilities, FormatId, NameStrength, Owner, Peer, SpecFormat, SpecVersion, Syntax,
};
use crate::inventory::{compare_by_key, CitedOperation, Completeness, Operation};
use crate::libraries::ApiSurface;
use crate::location::Convention;
use crate::openapi::routes::{normalize_method, normalize_path};
use crate::parse::ParseFailure;
use crate::plan::HttpService;
use crate::tree_checks::embeds_credentials;

/// RAML.
pub struct Raml;

/// The registered instance.
pub static RAML: Raml = Raml;

pub(crate) const CHECK_ONLY_NOTE: &str = "RAML is checked but never rewritten automatically; \
     it could be converted to OpenAPI by hand, after which this step maintains the OpenAPI \
     document";

const METHODS_10: [&str; 7] = ["get", "patch", "put", "post", "delete", "options", "head"];
const METHODS_08: [&str; 9] = [
    "get", "patch", "put", "post", "delete", "options", "head", "trace", "connect",
];
const RESOURCE_FIELDS: [&str; 7] = [
    "displayName",
    "description",
    "type",
    "is",
    "securedBy",
    "uriParameters",
    "baseUriParameters",
];

const CONVENTION: Convention = Convention {
    path: "api.raml",
    syntax: Syntax::Yaml,
    confident: false,
    accepted_directories: &[],
    basis: "RAML is reported where it is; this step never creates or moves a RAML document",
    code_first: false,
};

/// The version and fragment type the header line declares, if any.
fn header(text: &str) -> Option<(String, Option<String>)> {
    let first = text
        .strip_prefix('\u{feff}')
        .unwrap_or(text)
        .lines()
        .next()?;
    let mut words = first.strip_prefix("#%RAML")?.split_whitespace();
    let version = words.next()?.to_string();
    let fragment = words.next().map(str::to_string);
    Some((version, fragment))
}

fn version_of(version: &str) -> Option<SpecVersion> {
    match version {
        "0.8" => Some(SpecVersion::Raml08),
        "1.0" => Some(SpecVersion::Raml10),
        _ => None,
    }
}

/// `(method, full path, pointer)` for every method of every resource.
fn methods(document: &Value) -> Vec<(String, String, String)> {
    fn walk(
        map: &Map<String, Value>,
        path: &str,
        pointer: &str,
        methods: &[&str],
        out: &mut Vec<(String, String, String)>,
    ) {
        for (key, value) in map {
            let child = format!("{pointer}/{}", escape(key));
            if key.starts_with('/') {
                if let Some(resource) = value.as_object() {
                    walk(resource, &format!("{path}{key}"), &child, methods, out);
                }
            } else if methods.contains(&key.as_str()) && !path.is_empty() {
                out.push((key.clone(), path.to_string(), child));
            }
        }
    }
    let mut out = Vec::new();
    let known: &[&str] = if document["raml"] == "0.8" {
        &METHODS_08
    } else {
        &METHODS_10
    };
    if let Some(api) = document["api"].as_object() {
        walk(api, "", "", known, &mut out);
    }
    out
}

impl SpecFormat for Raml {
    fn id(&self) -> FormatId {
        FormatId::Raml
    }

    fn name(&self) -> &'static str {
        "RAML"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::CHECK_ONLY
    }

    fn candidate_strength(&self, path: &str) -> Option<NameStrength> {
        path.to_ascii_lowercase()
            .ends_with(".raml")
            .then_some(NameStrength::Strong)
    }

    fn classify(&self, path: &str, bytes: &[u8], max_bytes: usize) -> Candidate {
        if self.candidate_strength(path).is_none() {
            return Candidate::NotASpec;
        }
        if bytes.len() > max_bytes {
            return Candidate::Unverifiable {
                reason: format!("larger than the {max_bytes}-byte specification cap"),
            };
        }
        let Ok(text) = std::str::from_utf8(bytes) else {
            return Candidate::Unverifiable {
                reason: "not UTF-8 text".into(),
            };
        };
        // A `.raml` file without the header is a plain included fragment.
        let Some((version, _)) = header(text) else {
            return Candidate::NotASpec;
        };
        if version_of(&version).is_none() {
            return Candidate::Unverifiable {
                reason: format!("declares RAML {version}, which this step does not read"),
            };
        }
        match self.parse(text, Syntax::Yaml) {
            Ok(document) => Candidate::Spec {
                syntax: Syntax::Yaml,
                version: self.version(&document),
                document,
            },
            Err(ParseFailure::Unverifiable(reason) | ParseFailure::Malformed(reason)) => {
                Candidate::Unverifiable { reason }
            }
        }
    }

    fn parse(&self, text: &str, _: Syntax) -> Result<Value, ParseFailure> {
        let (version, fragment) = header(text).ok_or_else(|| {
            ParseFailure::Malformed("a RAML document starts with a #%RAML header".into())
        })?;
        // The header is a YAML comment, so the text parses as it is.
        let api = crate::parse::parse(text, Syntax::Yaml).map_err(|failure| {
            let (ParseFailure::Unverifiable(reason) | ParseFailure::Malformed(reason)) = failure;
            ParseFailure::Unverifiable(format!(
                "{reason}; RAML `!include` and other tags are not read"
            ))
        })?;
        Ok(json!({"raml": version, "fragment": fragment, "api": api}))
    }

    fn version(&self, document: &Value) -> Option<SpecVersion> {
        version_of(document["raml"].as_str()?)
    }

    fn validate(&self, document: &Value, _: &[Peer<'_>]) -> Vec<Diagnostic> {
        let mut out = Vec::new();
        // Typed fragments (libraries, data types, traits) have no title
        // or resources of their own.
        if !document["fragment"].is_null() {
            return out;
        }
        let Some(api) = document["api"].as_object() else {
            out.push(Diagnostic::error(
                Code::NotAnObject,
                "",
                "a RAML API definition must be a mapping",
            ));
            return out;
        };
        if !api
            .get("title")
            .is_some_and(|title| title.as_str().is_some_and(|t| !t.is_empty()))
        {
            out.push(Diagnostic::error(
                Code::MissingField,
                "/title",
                "a RAML API definition needs a non-empty `title`",
            ));
        }
        if api
            .get("baseUri")
            .and_then(Value::as_str)
            .is_some_and(embeds_credentials)
        {
            out.push(Diagnostic::error(
                Code::InvalidServer,
                "/baseUri",
                "`baseUri` must not embed credentials",
            ));
        }
        resources(api, "", document["raml"] == "0.8", &mut out);
        out
    }

    fn operations(&self, document: &Value) -> Vec<Operation> {
        methods(document)
            .into_iter()
            .map(|(method, path, _)| Operation::new(method, path))
            .collect()
    }

    fn compare(&self, document: &Value, _: &[Peer<'_>], inventory: &[Operation]) -> Completeness {
        let key = |operation: &Operation| {
            (
                normalize_method(&operation.method).unwrap_or_default(),
                normalize_path(&operation.path),
            )
        };
        let documented = self
            .operations(document)
            .into_iter()
            .map(|operation| {
                let keys = vec![key(&operation)];
                (operation, keys)
            })
            .collect();
        compare_by_key(documented, inventory, key)
    }

    fn preservation(&self, _: &Value, _: &Value, _: &[Diagnostic]) -> Vec<String> {
        vec![CHECK_ONLY_NOTE.into()]
    }

    fn inventory_operation(&self, method: &str, path: &str) -> Result<Operation, String> {
        crate::openapi::OPENAPI.inventory_operation(method, path)
    }

    fn emit(&self, _: &Value, _: Syntax) -> Result<String, String> {
        Err(CHECK_ONLY_NOTE.into())
    }

    fn new_document_problems(&self, _: &Value) -> Vec<String> {
        vec![CHECK_ONLY_NOTE.into()]
    }

    fn owners(&self, services: &[HttpService], _: &[ApiSurface]) -> Vec<Owner> {
        http_owners(services, CONVENTION)
    }

    fn fallback(&self) -> Convention {
        CONVENTION
    }

    fn scans_source(&self) -> bool {
        false
    }

    fn scan_source(&self, _: &str, _: &str) -> Vec<CitedOperation> {
        Vec::new()
    }
}

/// HTTP services as owners of a document that is only reported.
pub(crate) fn http_owners(services: &[HttpService], convention: Convention) -> Vec<Owner> {
    services
        .iter()
        .map(|service| Owner {
            root: service.root.clone(),
            stack: crate::format::framework_names(&service.frameworks),
            convention,
        })
        .collect()
}

fn resources(map: &Map<String, Value>, pointer: &str, v08: bool, out: &mut Vec<Diagnostic>) {
    let methods: &[&str] = if v08 { &METHODS_08 } else { &METHODS_10 };
    for (key, value) in map {
        let child = format!("{pointer}/{}", escape(key));
        if key.starts_with('/') {
            match value {
                Value::Object(resource) => resources(resource, &child, v08, out),
                Value::Null => {}
                _ => out.push(Diagnostic::error(
                    Code::InvalidType,
                    &child,
                    "a resource must be a mapping",
                )),
            }
        } else if pointer.is_empty() {
            // Root-level properties are the API's own, not a resource's.
        } else if methods.contains(&key.as_str()) {
            let responses = value.get("responses").and_then(Value::as_object);
            for status in responses.into_iter().flat_map(Map::keys) {
                if status.len() != 3 || !status.chars().all(|c| c.is_ascii_digit()) {
                    out.push(Diagnostic::error(
                        Code::InvalidStatusKey,
                        format!("{child}/responses/{}", escape(status)),
                        format!("`{status}` is not an HTTP status code"),
                    ));
                }
            }
        } else if !RESOURCE_FIELDS.contains(&key.as_str()) && !key.starts_with('(') {
            out.push(Diagnostic::warning(
                Code::UnknownField,
                &child,
                format!("`{key}` is not a method or resource property of this RAML version"),
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frameworks::WebFramework;

    const API: &str = "#%RAML 1.0\ntitle: Pets\nbaseUri: https://api.example.invalid/{version}\n/pets:\n  displayName: Pets\n  get:\n    responses:\n      200:\n        body: {}\n  /{id}:\n    (audit): true\n    delete: {}\n    uriParameters: {}\n";

    fn document(text: &str) -> Value {
        RAML.parse(text, Syntax::Yaml).unwrap()
    }

    #[test]
    fn a_headed_document_is_recognized_and_checked() {
        assert!(matches!(
            RAML.classify("api/pets.raml", API.as_bytes(), 1 << 20),
            Candidate::Spec {
                version: Some(SpecVersion::Raml10),
                ..
            }
        ));
        assert!(RAML.validate(&document(API), &[]).is_empty());
        assert_eq!(
            RAML.operations(&document(API)),
            // Keys read in order, and `/` sorts before letters.
            [
                Operation::new("delete", "/pets/{id}"),
                Operation::new("get", "/pets")
            ]
        );
        let fragment = document("#%RAML 1.0 Library\ntypes: {}\n");
        assert_eq!(fragment["fragment"], "Library");
        assert!(RAML.validate(&fragment, &[]).is_empty());
    }

    #[test]
    fn what_cannot_be_read_is_unverifiable_or_not_raml() {
        assert_eq!(
            RAML.classify("types/user.raml", b"type: object\n", 64),
            Candidate::NotASpec
        );
        assert_eq!(
            RAML.classify("api.yaml", b"#%RAML 1.0\n", 64),
            Candidate::NotASpec
        );
        for (bytes, cap, reason) in [
            (&b"#%RAML 2.0\ntitle: x\n"[..], 64, "RAML 2.0"),
            (
                &b"#%RAML 1.0\ntitle: x\n/a: !include a.raml\n"[..],
                64,
                "`!include`",
            ),
            (&[0xff][..], 64, "UTF-8"),
            (&b"#%RAML 1.0\ntitle: a long title\n"[..], 24, "cap"),
        ] {
            let classified = RAML.classify("api.raml", bytes, cap);
            assert!(
                matches!(&classified, Candidate::Unverifiable { reason: r } if r.contains(reason)),
                "{classified:?}"
            );
        }
        assert!(matches!(
            RAML.parse("title: x", Syntax::Yaml),
            Err(ParseFailure::Malformed(_))
        ));
        assert_eq!(header("#%RAML"), None);
    }

    #[test]
    fn titles_uris_resources_methods_and_status_codes_are_checked() {
        let text = "#%RAML 0.8\nbaseUri: https://u:p@api.example.invalid\n/a: text\n/b:\n  trace:\n    responses:\n      2xx: {}\n  fetch: {}\n/c:\n";
        let found: Vec<(Code, String)> = RAML
            .validate(&document(text), &[])
            .into_iter()
            .map(|d| (d.code, d.pointer))
            .collect();
        assert_eq!(
            found,
            [
                (Code::MissingField, "/title".into()),
                (Code::InvalidServer, "/baseUri".into()),
                (Code::InvalidType, "/~1a".into()),
                (Code::UnknownField, "/~1b/fetch".into()),
                (Code::InvalidStatusKey, "/~1b/trace/responses/2xx".into()),
            ]
        );
        assert_eq!(
            RAML.operations(&document(text)),
            [Operation::new("trace", "/b")]
        );
        assert_eq!(
            RAML.validate(&document("#%RAML 1.0\n- a\n"), &[])[0].code,
            Code::NotAnObject
        );
    }

    #[test]
    fn raml_is_reported_never_written() {
        let parsed = document(API);
        assert_eq!(RAML.capabilities(), Capabilities::CHECK_ONLY);
        assert!(RAML
            .emit(&parsed, Syntax::Yaml)
            .unwrap_err()
            .contains("converted to OpenAPI"));
        assert_eq!(RAML.new_document_problems(&parsed), [CHECK_ONLY_NOTE]);
        assert_eq!(RAML.preservation(&parsed, &parsed, &[]), [CHECK_ONLY_NOTE]);
        let result = RAML.compare(
            &parsed,
            &[],
            &[
                Operation::new("GET", "/pets/"),
                Operation::new("post", "/x"),
            ],
        );
        assert_eq!(result.missing, [Operation::new("post", "/x")]);
        assert_eq!(result.unverified, [Operation::new("delete", "/pets/{id}")]);
        assert!(RAML.inventory_operation("get", "/a").is_ok());
        let services = [HttpService {
            root: ".".into(),
            manifests: vec![],
            frameworks: [WebFramework::Express].into_iter().collect(),
        }];
        assert_eq!(RAML.owners(&services, &[])[0].stack, ["express"]);
        assert!(!RAML.fallback().confident);
        assert_eq!(RAML.name(), "RAML");
        assert_eq!(RAML.version(&serde_json::json!({})), None);
    }
}
