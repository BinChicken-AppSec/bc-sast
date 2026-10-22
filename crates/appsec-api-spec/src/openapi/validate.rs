//! Structural validation of OpenAPI 3.0, 3.1 and 3.2 and Swagger 2.0
//! documents, implemented directly from the specifications' own rules.
//!
//! This is not a JSON Schema validation of every object. It checks the
//! rules that decide whether a document can be read at all and whether it
//! describes its operations coherently: required top-level fields, valid
//! method and status keys, declared and required path parameters, unique
//! operation identifiers and parameters, resolvable local references,
//! server and host sanity, and defined security schemes. Each problem is a
//! typed [`Diagnostic`] located by a JSON pointer.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

use super::detect::declared_version;
pub use crate::diagnostic::{escape, Code, Diagnostic, Severity};
use crate::format::SpecVersion;
pub use crate::refs::{lookup, resolve};
#[cfg(test)]
use crate::refs::{percent_decode, MAX_WALK_DEPTH};

/// HTTP methods an OpenAPI 3.x path item may carry.
pub const METHODS: [&str; 8] = [
    "get", "put", "post", "delete", "options", "head", "patch", "trace",
];

/// Path-item keys that are not operations.
const PATH_ITEM_FIELDS: [&str; 5] = ["$ref", "summary", "description", "servers", "parameters"];

/// Validate `document`. An empty result means the rules above hold.
pub fn validate(document: &Value) -> Vec<Diagnostic> {
    let mut validator = Validator {
        document,
        version: SpecVersion::OpenApi31,
        out: Vec::new(),
        requirements: Vec::new(),
    };
    let Some(root) = document.as_object() else {
        validator.error(Code::NotAnObject, "", "the document root must be a mapping");
        return validator.out;
    };
    validator.version(root);
    validator.info(root);
    validator.paths(root);
    validator.servers(root);
    validator.security(root);
    // Example and default values are data, not document structure, and
    // may legitimately contain a `$ref` key.
    validator.out.extend(crate::refs::check(
        document,
        &["example", "default", "enum", "const"],
    ));
    validator.out
}

struct Validator<'a> {
    document: &'a Value,
    version: SpecVersion,
    out: Vec<Diagnostic>,
    /// Security requirement lists found while walking, checked once every
    /// scheme is known.
    requirements: Vec<(String, &'a Value)>,
}

impl<'a> Validator<'a> {
    fn push(&mut self, severity: Severity, code: Code, pointer: &str, message: impl Into<String>) {
        self.out.push(Diagnostic {
            severity,
            code,
            pointer: pointer.into(),
            message: message.into(),
        });
    }

    fn error(&mut self, code: Code, pointer: &str, message: impl Into<String>) {
        self.push(Severity::Error, code, pointer, message);
    }

    fn version(&mut self, root: &Map<String, Value>) {
        // Unknown or missing versions are validated by the most recent
        // rules; the version diagnostic already says what is wrong.
        self.version = declared_version(self.document).unwrap_or(SpecVersion::OpenApi31);
        match (root.get("openapi"), root.get("swagger")) {
            (Some(_), Some(_)) => self.error(
                Code::InvalidVersion,
                "",
                "declares both `openapi` and `swagger`; keep the one the document follows",
            ),
            (Some(openapi), None) => {
                let valid = openapi.as_str().is_some_and(|text| {
                    let parts: Vec<&str> = text.split('.').collect();
                    parts.len() == 3
                        && parts[0] == "3"
                        && matches!(parts[1], "0" | "1" | "2")
                        && !parts[2].is_empty()
                        && parts[2].chars().all(|c| c.is_ascii_digit())
                });
                if !valid {
                    self.error(
                        Code::InvalidVersion,
                        "/openapi",
                        "`openapi` must be a quoted version string such as \"3.0.3\" or \"3.1.0\"",
                    );
                }
            }
            (None, Some(swagger)) => {
                if swagger.as_str() != Some("2.0") {
                    self.error(
                        Code::InvalidVersion,
                        "/swagger",
                        "`swagger` must be the string \"2.0\"",
                    );
                }
            }
            (None, None) => self.error(
                Code::MissingVersion,
                "",
                "missing the `openapi` (or `swagger: \"2.0\"`) version field",
            ),
        }
    }

    fn info(&mut self, root: &Map<String, Value>) {
        let Some(info) = root.get("info") else {
            self.error(
                Code::MissingField,
                "/info",
                "missing the required `info` object",
            );
            return;
        };
        let Some(info) = info.as_object() else {
            self.error(Code::InvalidType, "/info", "`info` must be a mapping");
            return;
        };
        match info.get("title") {
            None => self.error(Code::MissingField, "/info/title", "missing `info.title`"),
            Some(Value::String(title)) if !title.trim().is_empty() => {}
            Some(_) => self.error(
                Code::InvalidType,
                "/info/title",
                "`info.title` must be a non-empty string",
            ),
        }
        match info.get("version") {
            None => self.error(
                Code::MissingField,
                "/info/version",
                "missing `info.version`",
            ),
            Some(Value::String(_)) => {}
            Some(_) => self.error(
                Code::InvalidType,
                "/info/version",
                "`info.version` must be a string; quote it",
            ),
        }
    }

    fn paths(&mut self, root: &'a Map<String, Value>) {
        let Some(paths) = root.get("paths") else {
            let alternatives = root.contains_key("components") || root.contains_key("webhooks");
            if !(self.version.responses_optional() && alternatives) {
                self.error(
                    Code::MissingField,
                    "/paths",
                    "missing the required `paths` object",
                );
            }
            return;
        };
        let Some(paths) = paths.as_object() else {
            self.error(Code::InvalidType, "/paths", "`paths` must be a mapping");
            return;
        };
        let mut operation_ids: BTreeMap<&str, String> = BTreeMap::new();
        for (path, item) in paths {
            let pointer = format!("/paths/{}", escape(path));
            if path.starts_with("x-") {
                continue;
            }
            if !path.starts_with('/') {
                self.error(
                    Code::InvalidPathKey,
                    &pointer,
                    format!("path `{path}` must start with `/`"),
                );
            }
            let Some(item) = item.as_object() else {
                self.error(Code::InvalidType, &pointer, "a path item must be a mapping");
                continue;
            };
            let template = template_parameters(path);
            let shared = match item.get("parameters") {
                Some(list) => self.parameters(list, &format!("{pointer}/parameters")),
                None => Vec::new(),
            };
            for (key, operation) in item {
                let operation_pointer = format!("{pointer}/{}", escape(key));
                let is_method = METHODS.contains(&key.as_str())
                    && !(self.version.is_swagger() && key == "trace");
                if is_method {
                    self.operation(
                        operation,
                        &operation_pointer,
                        &template,
                        &shared,
                        &mut operation_ids,
                    );
                } else if !PATH_ITEM_FIELDS.contains(&key.as_str()) && !key.starts_with("x-") {
                    self.error(
                        Code::InvalidMethod,
                        &operation_pointer,
                        format!(
                            "`{key}` is not a lower-case HTTP method or path-item field of this \
                             specification version"
                        ),
                    );
                }
            }
        }
    }

    fn operation(
        &mut self,
        operation: &'a Value,
        pointer: &str,
        template: &BTreeSet<String>,
        shared: &[Parameter],
        operation_ids: &mut BTreeMap<&'a str, String>,
    ) {
        let Some(operation) = operation.as_object() else {
            self.error(Code::InvalidType, pointer, "an operation must be a mapping");
            return;
        };
        self.responses(operation.get("responses"), pointer);
        let own = match operation.get("parameters") {
            Some(list) => self.parameters(list, &format!("{pointer}/parameters")),
            None => Vec::new(),
        };
        // An operation parameter overrides a path-level one with the same
        // name and location, so both lists together declare the path.
        let declared: BTreeSet<&str> = shared
            .iter()
            .chain(&own)
            .filter(|parameter| parameter.location == "path")
            .map(|parameter| parameter.name.as_str())
            .collect();
        for name in template {
            if !declared.contains(name.as_str()) {
                self.error(
                    Code::UndeclaredPathParameter,
                    pointer,
                    format!("path parameter `{name}` is not declared with `in: path`"),
                );
            }
        }
        for parameter in shared.iter().chain(&own) {
            if parameter.location == "path" && !template.contains(&parameter.name) {
                self.error(
                    Code::UnknownPathParameter,
                    &parameter.pointer,
                    format!(
                        "path parameter `{}` does not appear in the path template",
                        parameter.name
                    ),
                );
            }
        }
        match operation.get("operationId") {
            None => {}
            Some(Value::String(id)) => {
                if let Some(first) = operation_ids.get(id.as_str()) {
                    let message = format!("operationId `{id}` is already used at {first}");
                    self.error(
                        Code::DuplicateOperationId,
                        &format!("{pointer}/operationId"),
                        message,
                    );
                } else {
                    operation_ids.insert(id, pointer.into());
                }
            }
            Some(_) => self.error(
                Code::InvalidType,
                &format!("{pointer}/operationId"),
                "`operationId` must be a string",
            ),
        }
        if let Some(requirements) = operation.get("security") {
            self.requirements
                .push((format!("{pointer}/security"), requirements));
        }
    }

    fn responses(&mut self, responses: Option<&Value>, operation_pointer: &str) {
        let pointer = format!("{operation_pointer}/responses");
        let Some(responses) = responses else {
            if self.version.responses_optional() {
                self.push(
                    Severity::Warning,
                    Code::MissingResponses,
                    operation_pointer,
                    "operation declares no responses",
                );
            } else {
                self.error(
                    Code::MissingResponses,
                    operation_pointer,
                    "operation is missing the required `responses` object",
                );
            }
            return;
        };
        let Some(responses) = responses.as_object() else {
            self.error(Code::InvalidType, &pointer, "`responses` must be a mapping");
            return;
        };
        let mut declared = 0;
        for (status, response) in responses {
            if status.starts_with("x-") {
                continue;
            }
            declared += 1;
            let status_pointer = format!("{pointer}/{}", escape(status));
            if !valid_status(status, self.version) {
                self.error(
                    Code::InvalidStatusKey,
                    &status_pointer,
                    format!("`{status}` is not `default` or an HTTP status code"),
                );
            }
            let Some(response) = response.as_object() else {
                self.error(
                    Code::InvalidType,
                    &status_pointer,
                    "a response must be a mapping",
                );
                continue;
            };
            let described = response.contains_key("description") || response.contains_key("$ref");
            if !described && self.version != SpecVersion::OpenApi32 {
                self.error(
                    Code::MissingField,
                    &format!("{status_pointer}/description"),
                    "a response requires a `description`",
                );
            }
        }
        if declared == 0 {
            self.error(
                Code::MissingResponses,
                &pointer,
                "`responses` must declare at least one response",
            );
        }
    }

    fn parameters(&mut self, list: &'a Value, pointer: &str) -> Vec<Parameter> {
        let Some(list) = list.as_array() else {
            self.error(
                Code::InvalidType,
                pointer,
                "`parameters` must be a sequence",
            );
            return Vec::new();
        };
        let locations: &[&str] = if self.version.is_swagger() {
            &["query", "header", "path", "formData", "body"]
        } else {
            &["query", "header", "path", "cookie"]
        };
        let mut found: Vec<Parameter> = Vec::new();
        for (index, item) in list.iter().enumerate() {
            let item_pointer = format!("{pointer}/{index}");
            // An unresolvable reference is reported by the reference walk.
            let Some(item) = resolve(self.document, item) else {
                continue;
            };
            let Some(parameter) = item.as_object() else {
                self.error(
                    Code::InvalidType,
                    &item_pointer,
                    "a parameter must be a mapping",
                );
                continue;
            };
            let name = parameter
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let location = parameter
                .get("in")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if name.is_empty() || !locations.contains(&location) {
                self.error(
                    Code::InvalidParameter,
                    &item_pointer,
                    format!(
                        "a parameter needs a non-empty `name` and `in` set to one of {locations:?}"
                    ),
                );
                continue;
            }
            let typed = if self.version.is_swagger() {
                if location == "body" {
                    parameter.contains_key("schema")
                } else {
                    parameter.contains_key("type")
                }
            } else {
                parameter.contains_key("schema") || parameter.contains_key("content")
            };
            if !typed {
                let needs = match (self.version.is_swagger(), location) {
                    (true, "body") => "`schema`",
                    (true, _) => "`type`",
                    (false, _) => "`schema` or `content`",
                };
                self.error(
                    Code::InvalidParameter,
                    &item_pointer,
                    format!("parameter `{name}` must declare {needs}"),
                );
            }
            if location == "path" && parameter.get("required") != Some(&Value::Bool(true)) {
                self.error(
                    Code::PathParameterNotRequired,
                    &item_pointer,
                    format!("path parameter `{name}` must set `required: true`"),
                );
            }
            if found
                .iter()
                .any(|seen| seen.name == name && seen.location == location)
            {
                self.error(
                    Code::DuplicateParameter,
                    &item_pointer,
                    format!("parameter `{name}` in `{location}` is declared twice"),
                );
                continue;
            }
            found.push(Parameter {
                name: name.into(),
                location: location.into(),
                pointer: item_pointer,
            });
        }
        found
    }

    fn servers(&mut self, root: &Map<String, Value>) {
        if self.version.is_swagger() {
            if let Some(host) = root.get("host") {
                let valid = host.as_str().is_some_and(|host| {
                    !host.is_empty() && !host.contains("://") && !host.contains('/')
                });
                if !valid {
                    self.error(
                        Code::InvalidServer,
                        "/host",
                        "`host` must be a host name (and optional port) without a scheme or path",
                    );
                } else if host.as_str().is_some_and(|host| host.contains('@')) {
                    self.error(
                        Code::InvalidServer,
                        "/host",
                        "`host` must not embed credentials",
                    );
                }
            }
            if let Some(base) = root.get("basePath") {
                if !base.as_str().is_some_and(|base| base.starts_with('/')) {
                    self.error(
                        Code::InvalidServer,
                        "/basePath",
                        "`basePath` must start with `/`",
                    );
                }
            }
            if let Some(schemes) = root.get("schemes") {
                let valid = schemes.as_array().is_some_and(|schemes| {
                    schemes.iter().all(|scheme| {
                        matches!(scheme.as_str(), Some("http" | "https" | "ws" | "wss"))
                    })
                });
                if !valid {
                    self.error(
                        Code::InvalidServer,
                        "/schemes",
                        "`schemes` must be a sequence of http, https, ws or wss",
                    );
                }
            }
            return;
        }
        let Some(servers) = root.get("servers") else {
            return;
        };
        let Some(servers) = servers.as_array() else {
            self.error(
                Code::InvalidType,
                "/servers",
                "`servers` must be a sequence",
            );
            return;
        };
        for (index, server) in servers.iter().enumerate() {
            let pointer = format!("/servers/{index}");
            match server.get("url").and_then(Value::as_str) {
                Some(url) if !url.trim().is_empty() => {
                    if embeds_credentials(url) {
                        self.error(
                            Code::InvalidServer,
                            &format!("{pointer}/url"),
                            "a server URL must not embed credentials",
                        );
                    }
                }
                _ => self.error(
                    Code::InvalidServer,
                    &pointer,
                    "a server needs a non-empty `url` string",
                ),
            }
        }
    }

    fn security(&mut self, root: &'a Map<String, Value>) {
        let (container, pointer) = if self.version.is_swagger() {
            (
                root.get("securityDefinitions"),
                "/securityDefinitions".to_string(),
            )
        } else {
            (
                root.get("components")
                    .and_then(|components| components.get("securitySchemes")),
                "/components/securitySchemes".to_string(),
            )
        };
        let mut defined = BTreeSet::new();
        if let Some(schemes) = container.and_then(Value::as_object) {
            for (name, scheme) in schemes {
                defined.insert(name.as_str());
                let scheme_pointer = format!("{pointer}/{}", escape(name));
                if let Some(problem) = scheme_problem(resolve(self.document, scheme), self.version)
                {
                    self.error(Code::InvalidSecurityScheme, &scheme_pointer, problem);
                }
            }
        }
        if let Some(requirements) = root.get("security") {
            self.requirements.push(("/security".into(), requirements));
        }
        for (pointer, requirements) in std::mem::take(&mut self.requirements) {
            let Some(requirements) = requirements.as_array() else {
                self.error(Code::InvalidType, &pointer, "`security` must be a sequence");
                continue;
            };
            for (index, requirement) in requirements.iter().enumerate() {
                let Some(requirement) = requirement.as_object() else {
                    self.error(
                        Code::InvalidType,
                        &format!("{pointer}/{index}"),
                        "a security requirement must be a mapping",
                    );
                    continue;
                };
                for name in requirement.keys() {
                    if !defined.contains(name.as_str()) {
                        self.error(
                            Code::UndefinedSecurityScheme,
                            &format!("{pointer}/{index}/{}", escape(name)),
                            format!("security scheme `{name}` is not defined"),
                        );
                    }
                }
            }
        }
    }
}

struct Parameter {
    name: String,
    location: String,
    pointer: String,
}

/// `{name}` segments of a path template.
fn template_parameters(path: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let mut rest = path;
    while let Some(start) = rest.find('{') {
        let after = &rest[start + 1..];
        let Some(end) = after.find('}') else {
            break;
        };
        names.insert(after[..end].to_string());
        rest = &after[end + 1..];
    }
    names
}

fn valid_status(status: &str, version: SpecVersion) -> bool {
    if status == "default" {
        return true;
    }
    let bytes = status.as_bytes();
    if bytes.len() != 3 || !(b'1'..=b'5').contains(&bytes[0]) {
        return false;
    }
    let digits = bytes[1..].iter().all(u8::is_ascii_digit);
    // Range keys such as `4XX` arrived with OpenAPI 3.0.
    let range = !version.is_swagger() && &bytes[1..] == b"XX";
    digits || range
}

fn embeds_credentials(url: &str) -> bool {
    let Some((_, rest)) = url.split_once("://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    authority.contains('@')
}

fn scheme_problem(scheme: Option<&Value>, version: SpecVersion) -> Option<String> {
    // An unresolvable reference is reported by the reference walk.
    let scheme = scheme?;
    let Some(scheme) = scheme.as_object() else {
        return Some("a security scheme must be a mapping".into());
    };
    let text = |key: &str| scheme.get(key).and_then(Value::as_str).unwrap_or_default();
    let kind = text("type");
    match (version.is_swagger(), kind) {
        (_, "apiKey") => {
            let locations: &[&str] = if version.is_swagger() {
                &["query", "header"]
            } else {
                &["query", "header", "cookie"]
            };
            (text("name").is_empty() || !locations.contains(&text("in"))).then(|| {
                format!("an apiKey scheme needs `name` and `in` set to one of {locations:?}")
            })
        }
        (true, "basic") => None,
        (true, "oauth2") => (!matches!(
            text("flow"),
            "implicit" | "password" | "application" | "accessCode"
        ))
        .then(|| "a Swagger 2.0 oauth2 scheme needs a valid `flow`".to_string()),
        (false, "http") => text("scheme")
            .is_empty()
            .then(|| "an http scheme needs `scheme` (for example bearer or basic)".to_string()),
        (false, "oauth2") => (!scheme.get("flows").is_some_and(Value::is_object))
            .then(|| "an oauth2 scheme needs a `flows` mapping".to_string()),
        (false, "openIdConnect") => text("openIdConnectUrl")
            .is_empty()
            .then(|| "an openIdConnect scheme needs `openIdConnectUrl`".to_string()),
        (false, "mutualTLS") if version != SpecVersion::OpenApi30 => None,
        _ => Some(format!(
            "security scheme type `{kind}` is not valid for this specification version"
        )),
    }
}

#[cfg(test)]
#[path = "validate_tests.rs"]
mod tests;
