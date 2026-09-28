//! API Blueprint (`.apib`): detected and sanity-checked, never rewritten.
//!
//! API Blueprint is Markdown with conventions: a metadata block at the top
//! (`FORMAT: 1A`, `HOST: ...`), `# <API name>`, `# Group <name>`
//! sections, resources as headings ending in a URI template
//! (`## Pets [/pets]`) and actions as headings ending in a method
//! (`### List [GET]`) or a method and URI (`## Create [POST /pets]`, or a
//! bare `# GET /pets`), each with `+ Response <code>` items. This module
//! reads that outline only (not payloads or MSON data structures) and
//! checks the format version, the API name, a credential-free host,
//! valid methods and URIs, and that every action has a response.
//!
//! Like RAML, it is reported and could be converted to OpenAPI by hand,
//! after which the OpenAPI step maintains that document.

use serde_json::{json, Value};

use crate::diagnostic::{Code, Diagnostic};
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

/// API Blueprint.
pub struct ApiBlueprint;

/// The registered instance.
pub static API_BLUEPRINT: ApiBlueprint = ApiBlueprint;

const CHECK_ONLY_NOTE: &str = "API Blueprint is checked but never rewritten automatically; it \
     could be converted to OpenAPI by hand, after which this step maintains the OpenAPI document";

const METHODS: [&str; 9] = [
    "GET", "PUT", "POST", "DELETE", "OPTIONS", "HEAD", "PATCH", "TRACE", "CONNECT",
];

const CONVENTION: Convention = Convention {
    path: "apiary.apib",
    syntax: Syntax::Markdown,
    confident: false,
    accepted_directories: &[],
    basis: "API Blueprint is reported where it is; this step never creates or moves one",
    code_first: false,
};

/// What one heading declares.
enum Heading<'a> {
    Resource(&'a str),
    /// A method and, when the heading names one, its own URI.
    Action(&'a str, Option<&'a str>),
    /// A bracketed token that is neither a URI nor a method.
    Invalid(&'a str),
    Other,
}

fn heading(text: &str) -> Heading<'_> {
    let text = text.trim();
    let (method_or_uri, rest) = match (text.rfind('['), text.strip_suffix(']')) {
        (Some(open), Some(inner)) => {
            let inner = inner[open + 1..].trim();
            match inner.split_once(char::is_whitespace) {
                Some((method, uri)) => (method, Some(uri.trim())),
                None => (inner, None),
            }
        }
        // `# GET /pets` or `# /pets` without brackets.
        _ => match text.split_once(char::is_whitespace) {
            Some((method, uri)) if METHODS.contains(&method) && uri.starts_with('/') => {
                (method, Some(uri))
            }
            _ if text.starts_with('/') => (text, None),
            _ => return Heading::Other,
        },
    };
    if method_or_uri.starts_with('/') || method_or_uri.starts_with('{') {
        Heading::Resource(method_or_uri)
    } else if method_or_uri.chars().all(|c| c.is_ascii_uppercase()) && !method_or_uri.is_empty() {
        Heading::Action(method_or_uri, rest)
    } else if text.ends_with(']') && rest.is_none() {
        Heading::Invalid(method_or_uri)
    } else {
        Heading::Other
    }
}

/// Read the outline of `text` into a JSON tree.
fn outline(text: &str) -> Value {
    let mut metadata = true;
    let mut format = Value::Null;
    let mut host = Value::Null;
    let mut name = Value::Null;
    let mut resources = Vec::new();
    let mut actions: Vec<Value> = Vec::new();
    let mut invalid = Vec::new();
    let mut resource: Option<String> = None;
    for (index, raw) in text
        .strip_prefix('\u{feff}')
        .unwrap_or(text)
        .lines()
        .enumerate()
    {
        let line = index + 1;
        if metadata {
            match raw.split_once(':') {
                Some((key, value)) if !raw.starts_with('#') && !key.contains(' ') => {
                    match key.trim() {
                        "FORMAT" => format = json!(value.trim()),
                        "HOST" => host = json!(value.trim()),
                        _ => {}
                    }
                    continue;
                }
                _ if raw.trim().is_empty() => continue,
                _ => metadata = false,
            }
        }
        let trimmed = raw.trim_start();
        if raw.starts_with('#') {
            let title = raw.trim_start_matches('#');
            match heading(title) {
                Heading::Resource(uri) => {
                    resource = Some(uri.to_string());
                    resources.push(json!({"uri": uri, "line": line}));
                }
                Heading::Action(method, uri) => {
                    let uri = uri.map(str::to_string).or_else(|| resource.clone());
                    actions
                        .push(json!({"method": method, "uri": uri, "responses": 0, "line": line}));
                }
                Heading::Invalid(token) => invalid.push(json!({"token": token, "line": line})),
                Heading::Other => {
                    if name.is_null()
                        && raw.starts_with("# ")
                        && !title.trim().starts_with("Group ")
                    {
                        name = json!(title.trim());
                    }
                }
            }
        } else if ["+ Response", "- Response", "* Response"]
            .iter()
            .any(|marker| trimmed.starts_with(marker))
        {
            if let Some(action) = actions.last_mut() {
                action["responses"] = json!(action["responses"].as_u64().unwrap_or_default() + 1);
            }
        }
    }
    json!({
        "format": format,
        "host": host,
        "name": name,
        "resources": resources,
        "actions": actions,
        "invalid": invalid,
    })
}

fn items<'a>(document: &'a Value, key: &str) -> &'a [Value] {
    document[key].as_array().map_or(&[], Vec::as_slice)
}

/// A URI template without its query expression (`{?page}`).
fn without_query(uri: &str) -> &str {
    uri.split_once("{?").map_or(uri, |(path, _)| path)
}

impl SpecFormat for ApiBlueprint {
    fn id(&self) -> FormatId {
        FormatId::ApiBlueprint
    }

    fn name(&self) -> &'static str {
        "API Blueprint"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::CHECK_ONLY
    }

    fn candidate_strength(&self, path: &str) -> Option<NameStrength> {
        path.to_ascii_lowercase()
            .ends_with(".apib")
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
        let document = outline(text);
        Candidate::Spec {
            syntax: Syntax::Markdown,
            version: self.version(&document),
            document,
        }
    }

    fn parse(&self, text: &str, _: Syntax) -> Result<Value, ParseFailure> {
        Ok(outline(text))
    }

    fn version(&self, document: &Value) -> Option<SpecVersion> {
        (document["format"] == "1A").then_some(SpecVersion::Blueprint1A)
    }

    fn validate(&self, document: &Value, _: &[Peer<'_>]) -> Vec<Diagnostic> {
        let mut out = Vec::new();
        match document["format"].as_str() {
            None => out.push(Diagnostic::warning(
                Code::MissingVersion,
                "/format",
                "no `FORMAT: 1A` metadata line; API Blueprint tools assume 1A",
            )),
            Some("1A") => {}
            Some(other) => out.push(Diagnostic::error(
                Code::InvalidVersion,
                "/format",
                format!("FORMAT `{other}` is not 1A"),
            )),
        }
        if document["name"].is_null() {
            out.push(Diagnostic::warning(
                Code::MissingField,
                "/name",
                "no `# <API name>` heading",
            ));
        }
        if document["host"].as_str().is_some_and(embeds_credentials) {
            out.push(Diagnostic::error(
                Code::InvalidServer,
                "/host",
                "HOST must not embed credentials",
            ));
        }
        if items(document, "resources").is_empty() && items(document, "actions").is_empty() {
            out.push(Diagnostic::warning(
                Code::EmptyType,
                "/resources",
                "the blueprint declares no resources or actions",
            ));
        }
        for (index, action) in items(document, "actions").iter().enumerate() {
            let pointer = format!("/actions/{index}");
            let line = &action["line"];
            let method = action["method"].as_str().unwrap_or_default();
            if !METHODS.contains(&method) {
                out.push(Diagnostic::error(
                    Code::InvalidMethod,
                    &pointer,
                    format!("line {line}: `{method}` is not an HTTP method"),
                ));
            }
            match action["uri"].as_str() {
                Some(uri) if uri.starts_with('/') || uri.starts_with('{') => {}
                Some(uri) => out.push(Diagnostic::error(
                    Code::InvalidPathKey,
                    &pointer,
                    format!("line {line}: `{uri}` is not a URI template"),
                )),
                None => out.push(Diagnostic::error(
                    Code::InvalidPathKey,
                    &pointer,
                    format!("line {line}: the action belongs to no resource URI"),
                )),
            }
            if action["responses"] == 0 {
                out.push(Diagnostic::error(
                    Code::MissingResponses,
                    &pointer,
                    format!("line {line}: the action declares no `+ Response`"),
                ));
            }
        }
        for token in items(document, "invalid") {
            out.push(Diagnostic::error(
                Code::InvalidMethod,
                "/invalid",
                format!(
                    "line {}: `[{}]` is neither an HTTP method nor a URI template",
                    token["line"],
                    token["token"].as_str().unwrap_or_default()
                ),
            ));
        }
        out
    }

    fn operations(&self, document: &Value) -> Vec<Operation> {
        items(document, "actions")
            .iter()
            .filter_map(|action| {
                let method = action["method"].as_str()?.to_ascii_lowercase();
                let uri = without_query(action["uri"].as_str()?);
                Some(Operation::new(method, uri))
            })
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
        crate::raml::http_owners(services, CONVENTION)
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

#[cfg(test)]
mod tests {
    use super::*;

    const BLUEPRINT: &str = "\u{feff}FORMAT: 1A\nHOST: https://api.example.invalid\nVERSION: 2\n\n# Pets API\nA sample.\n\n# Group Pets\n\n## Pets [/pets{?page}]\n\n### List [GET]\n+ Response 200 (application/json)\n\n### Create [POST]\n+ Request (application/json)\n+ Response 201\n\n## Pet [/pets/{id}]\n### Remove [DELETE]\n- Response 204\n\n## Search [GET /search]\n* Response 200\n\n# GET /health\n+ Response 200\n";

    fn document(text: &str) -> Value {
        API_BLUEPRINT.parse(text, Syntax::Markdown).unwrap()
    }

    #[test]
    fn the_outline_is_read() {
        let parsed = document(BLUEPRINT);
        assert_eq!(parsed["format"], "1A");
        assert_eq!(parsed["name"], "Pets API");
        assert_eq!(parsed["resources"].as_array().unwrap().len(), 2);
        assert_eq!(
            API_BLUEPRINT.operations(&parsed),
            [
                Operation::new("get", "/pets"),
                Operation::new("post", "/pets"),
                Operation::new("delete", "/pets/{id}"),
                Operation::new("get", "/search"),
                Operation::new("get", "/health"),
            ]
        );
        assert!(API_BLUEPRINT.validate(&parsed, &[]).is_empty());
        assert!(matches!(
            API_BLUEPRINT.classify("docs/apiary.apib", BLUEPRINT.as_bytes(), 1 << 20),
            Candidate::Spec {
                version: Some(SpecVersion::Blueprint1A),
                syntax: Syntax::Markdown,
                ..
            }
        ));
    }

    #[test]
    fn problems_are_reported_with_lines() {
        let text = "FORMAT: 2B\nHOST: https://u:p@api.invalid\n\n## [FETCH /a]\n### Bad [get]\n### Loose [GET]\n## Thing [nope]\n### Odd [GET other]\n";
        let found: Vec<(Code, String)> = API_BLUEPRINT
            .validate(&document(text), &[])
            .into_iter()
            .map(|d| (d.code, d.message))
            .collect();
        assert_eq!(
            found,
            [
                (Code::InvalidVersion, "FORMAT `2B` is not 1A".into()),
                (Code::MissingField, "no `# <API name>` heading".into()),
                (
                    Code::InvalidServer,
                    "HOST must not embed credentials".into()
                ),
                (
                    Code::InvalidMethod,
                    "line 4: `FETCH` is not an HTTP method".into()
                ),
                (
                    Code::MissingResponses,
                    "line 4: the action declares no `+ Response`".into()
                ),
                (
                    Code::InvalidPathKey,
                    "line 6: the action belongs to no resource URI".into()
                ),
                (
                    Code::MissingResponses,
                    "line 6: the action declares no `+ Response`".into()
                ),
                (
                    Code::InvalidPathKey,
                    "line 8: `other` is not a URI template".into()
                ),
                (
                    Code::MissingResponses,
                    "line 8: the action declares no `+ Response`".into()
                ),
                (
                    Code::InvalidMethod,
                    "line 5: `[get]` is neither an HTTP method nor a URI template".into()
                ),
                (
                    Code::InvalidMethod,
                    "line 7: `[nope]` is neither an HTTP method nor a URI template".into()
                ),
            ]
        );
        let empty: Vec<Code> = API_BLUEPRINT
            .validate(&document("Just prose.\n+ Response 200\n"), &[])
            .into_iter()
            .map(|d| d.code)
            .collect();
        assert_eq!(
            empty,
            [Code::MissingVersion, Code::MissingField, Code::EmptyType]
        );
    }

    #[test]
    fn candidates_and_what_is_never_written() {
        assert_eq!(API_BLUEPRINT.classify("a.md", b"", 1), Candidate::NotASpec);
        assert!(matches!(
            API_BLUEPRINT.classify("a.apib", b"FORMAT: 1A", 2),
            Candidate::Unverifiable { .. }
        ));
        assert!(matches!(
            API_BLUEPRINT.classify("a.apib", &[0xff], 2),
            Candidate::Unverifiable { .. }
        ));
        let parsed = document(BLUEPRINT);
        assert_eq!(API_BLUEPRINT.capabilities(), Capabilities::CHECK_ONLY);
        assert!(API_BLUEPRINT.emit(&parsed, Syntax::Markdown).is_err());
        assert_eq!(
            API_BLUEPRINT.new_document_problems(&parsed),
            [CHECK_ONLY_NOTE]
        );
        assert_eq!(
            API_BLUEPRINT.preservation(&parsed, &parsed, &[]),
            [CHECK_ONLY_NOTE]
        );
        assert!(API_BLUEPRINT.inventory_operation("get", "/a").is_ok());
        let result = API_BLUEPRINT.compare(&parsed, &[], &[Operation::new("get", "/pets")]);
        assert_eq!(result.unverified.len(), 4);
        assert!(API_BLUEPRINT.owners(&[], &[]).is_empty());
        assert!(!API_BLUEPRINT.fallback().confident);
        assert_eq!(API_BLUEPRINT.name(), "API Blueprint");
        assert_eq!(API_BLUEPRINT.version(&serde_json::json!({})), None);
        assert!(matches!(heading("Plain words"), Heading::Other));
        assert!(matches!(heading("Pets [Pet Model]"), Heading::Other));
        assert!(matches!(heading("/pets"), Heading::Resource("/pets")));
    }
}
