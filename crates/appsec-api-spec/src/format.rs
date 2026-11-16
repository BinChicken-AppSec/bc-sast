use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::diagnostic::Diagnostic;
use crate::frameworks::WebFramework;
use crate::inventory::{CitedOperation, Completeness, Operation};
use crate::libraries::ApiSurface;
use crate::location::Convention;
use crate::parse::ParseFailure;
use crate::plan::HttpService;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum FormatId {
    #[serde(rename = "openapi")]
    OpenApi,
    #[serde(rename = "graphql")]
    Graphql,
    #[serde(rename = "asyncapi")]
    AsyncApi,
    #[serde(rename = "openrpc")]
    OpenRpc,
    #[serde(rename = "protobuf")]
    Protobuf,
    #[serde(rename = "raml")]
    Raml,
    #[serde(rename = "api_blueprint")]
    ApiBlueprint,
    #[serde(rename = "wsdl")]
    Wsdl,
    #[serde(rename = "odata")]
    OData,
}

impl FormatId {
    pub const ALL: [FormatId; 9] = [
        FormatId::OpenApi,
        FormatId::Graphql,
        FormatId::AsyncApi,
        FormatId::OpenRpc,
        FormatId::Protobuf,
        FormatId::Raml,
        FormatId::ApiBlueprint,
        FormatId::Wsdl,
        FormatId::OData,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::OpenApi => "openapi",
            Self::Graphql => "graphql",
            Self::AsyncApi => "asyncapi",
            Self::OpenRpc => "openrpc",
            Self::Protobuf => "protobuf",
            Self::Raml => "raml",
            Self::ApiBlueprint => "api_blueprint",
            Self::Wsdl => "wsdl",
            Self::OData => "odata",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|id| id.as_str() == name.trim().to_ascii_lowercase())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Syntax {
    Json,
    Yaml,
    Graphql,
    Protobuf,
    Markdown,
    Xml,
}

impl Syntax {
    pub fn from_path(path: &str) -> Option<Self> {
        let lower = path.to_ascii_lowercase();
        if lower.ends_with(".json") {
            Some(Self::Json)
        } else if lower.ends_with(".yaml") || lower.ends_with(".yml") {
            Some(Self::Yaml)
        } else {
            None
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpecVersion {
    Swagger20,
    OpenApi30,
    OpenApi31,
    OpenApi32,
    AsyncApi2,
    AsyncApi3,
    OpenRpc1,
    Proto2,
    Proto3,
    ProtoEditions,
    Raml08,
    Raml10,
    Blueprint1A,
    Wsdl11,
    Wsdl20,
    Odata2,
    Odata3,
    Odata4,
}

impl SpecVersion {
    pub fn is_swagger(self) -> bool {
        self == Self::Swagger20
    }

    pub fn responses_optional(self) -> bool {
        matches!(self, Self::OpenApi31 | Self::OpenApi32)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NameStrength {
    Strong,
    Weak,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Candidate {
    Spec {
        syntax: Syntax,
        version: Option<SpecVersion>,
        document: Value,
    },
    Broken {
        syntax: Syntax,
        document: Value,
    },
    Malformed {
        syntax: Syntax,
        reason: String,
    },
    Unverifiable {
        reason: String,
    },
    NotASpec,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Parts {
    pub syntax: Syntax,
    pub version: Option<SpecVersion>,
    pub document: Option<Value>,
    pub parse_error: Option<String>,
}

impl Candidate {
    pub fn into_parts(self) -> Option<Result<Parts, String>> {
        let parts = |syntax, version, document, parse_error| {
            Some(Ok(Parts {
                syntax,
                version,
                document,
                parse_error,
            }))
        };
        match self {
            Self::Spec {
                syntax,
                version,
                document,
            } => parts(syntax, version, Some(document), None),
            Self::Broken { syntax, document } => parts(syntax, None, Some(document), None),
            Self::Malformed { syntax, reason } => parts(syntax, None, None, Some(reason)),
            Self::Unverifiable { reason } => Some(Err(reason)),
            Self::NotASpec => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Capabilities {
    pub create: bool,
    pub repair: bool,
    pub relocate: bool,
}

impl Capabilities {
    pub const FULL: Capabilities = Capabilities {
        create: true,
        repair: true,
        relocate: true,
    };
    pub const CHECK_ONLY: Capabilities = Capabilities {
        create: false,
        repair: false,
        relocate: false,
    };

    pub fn writes(self) -> bool {
        self.create || self.repair || self.relocate
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Owner {
    pub root: String,
    pub stack: Vec<String>,
    pub convention: Convention,
}

#[derive(Clone, Copy, Debug)]
pub struct Peer<'a> {
    pub path: &'a str,
    pub document: &'a Value,
}

pub trait SpecFormat: Sync {
    fn id(&self) -> FormatId;
    fn name(&self) -> &'static str;
    fn capabilities(&self) -> Capabilities;
    fn candidate_strength(&self, path: &str) -> Option<NameStrength>;
    fn classify(&self, path: &str, bytes: &[u8], max_bytes: usize) -> Candidate;
    fn parse(&self, text: &str, syntax: Syntax) -> Result<Value, ParseFailure>;
    fn version(&self, document: &Value) -> Option<SpecVersion>;
    fn validate(&self, document: &Value, peers: &[Peer<'_>]) -> Vec<Diagnostic>;
    fn document_capabilities(&self, version: Option<SpecVersion>) -> Capabilities {
        let _ = version;
        self.capabilities()
    }
    fn supporting(&self, document: &Value) -> bool {
        let _ = document;
        false
    }
    fn operations(&self, document: &Value) -> Vec<Operation>;
    fn compare(
        &self,
        document: &Value,
        peers: &[Peer<'_>],
        inventory: &[Operation],
    ) -> Completeness;
    fn preservation(
        &self,
        original: &Value,
        repaired: &Value,
        before: &[Diagnostic],
    ) -> Vec<String>;
    fn inventory_operation(&self, method: &str, path: &str) -> Result<Operation, String>;
    fn emit(&self, document: &Value, syntax: Syntax) -> Result<String, String>;
    fn new_document_problems(&self, document: &Value) -> Vec<String>;
    fn owners(&self, services: &[HttpService], surfaces: &[ApiSurface]) -> Vec<Owner>;
    fn fallback(&self) -> Convention;
    fn scans_source(&self) -> bool;
    fn scan_source(&self, path: &str, text: &str) -> Vec<CitedOperation>;
}

use crate::asyncapi::ASYNCAPI;
use crate::blueprint::API_BLUEPRINT;
use crate::graphql::GRAPHQL;
use crate::odata::ODATA;
use crate::openapi::OPENAPI;
use crate::openrpc::OPENRPC;
use crate::protobuf::PROTOBUF;
use crate::raml::RAML;
use crate::wsdl::WSDL;

pub fn registry() -> [&'static dyn SpecFormat; 9] {
    [
        &OPENAPI,
        &GRAPHQL,
        &ASYNCAPI,
        &OPENRPC,
        &PROTOBUF,
        &RAML,
        &API_BLUEPRINT,
        &WSDL,
        &ODATA,
    ]
}

pub fn format(id: FormatId) -> &'static dyn SpecFormat {
    match id {
        FormatId::OpenApi => &OPENAPI,
        FormatId::Graphql => &GRAPHQL,
        FormatId::AsyncApi => &ASYNCAPI,
        FormatId::OpenRpc => &OPENRPC,
        FormatId::Protobuf => &PROTOBUF,
        FormatId::Raml => &RAML,
        FormatId::ApiBlueprint => &API_BLUEPRINT,
        FormatId::Wsdl => &WSDL,
        FormatId::OData => &ODATA,
    }
}

pub fn candidate_strength(path: &str) -> Option<NameStrength> {
    let strengths: Vec<NameStrength> = registry()
        .iter()
        .filter_map(|format| format.candidate_strength(path))
        .collect();
    if strengths.contains(&NameStrength::Strong) {
        Some(NameStrength::Strong)
    } else {
        strengths.first().copied()
    }
}

pub fn framework_names(frameworks: &BTreeSet<WebFramework>) -> Vec<String> {
    frameworks.iter().map(name_of).collect()
}

pub(crate) fn name_of<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standards_have_stable_names_and_implementations() {
        for (index, id) in FormatId::ALL.into_iter().enumerate() {
            assert_eq!(FormatId::parse(id.as_str()), Some(id));
            assert_eq!(format(id).id(), id);
            assert_eq!(registry()[index].id(), id);
            assert_eq!(name_of(&id), id.as_str());
        }
        assert_eq!(FormatId::parse(" OpenAPI "), Some(FormatId::OpenApi));
        assert_eq!(FormatId::parse("soap"), None);
    }

    #[test]
    fn by_default_every_document_has_the_standards_capabilities() {
        let document = serde_json::json!({});
        for format in registry() {
            if format.id() != FormatId::OData {
                assert_eq!(format.document_capabilities(None), format.capabilities());
            }
            if format.id() != FormatId::Wsdl {
                assert!(!format.supporting(&document));
            }
        }
    }

    #[test]
    fn only_protocol_buffers_scan_source_code() {
        for format in registry() {
            let scans = format.id() == FormatId::Protobuf;
            assert_eq!(format.scans_source(), scans);
            let found = format.scan_source("main.go", "pb.RegisterGreeterServer(s, x)");
            assert_eq!(found.len(), usize::from(scans), "{:?}", format.id());
        }
    }

    #[test]
    fn candidates_split_into_parts() {
        let document = serde_json::json!({});
        let spec = Candidate::Spec {
            syntax: Syntax::Json,
            version: None,
            document: document.clone(),
        };
        assert_eq!(
            spec.into_parts(),
            Some(Ok(Parts {
                syntax: Syntax::Json,
                version: None,
                document: Some(document.clone()),
                parse_error: None
            }))
        );
        let broken = Candidate::Broken {
            syntax: Syntax::Yaml,
            document,
        };
        assert!(matches!(
            broken.into_parts(),
            Some(Ok(Parts { version: None, .. }))
        ));
        let malformed = Candidate::Malformed {
            syntax: Syntax::Json,
            reason: "r".into(),
        };
        assert!(matches!(
            malformed.into_parts(),
            Some(Ok(Parts { document: None, .. }))
        ));
        let unverifiable = Candidate::Unverifiable { reason: "u".into() };
        assert_eq!(unverifiable.into_parts(), Some(Err("u".into())));
        assert_eq!(Candidate::NotASpec.into_parts(), None);
    }

    #[test]
    fn the_strongest_nomination_wins() {
        assert_eq!(
            candidate_strength("openapi.yaml"),
            Some(NameStrength::Strong)
        );
        assert_eq!(candidate_strength("api.json"), Some(NameStrength::Weak));
        assert_eq!(candidate_strength("README.md"), None);
    }

    #[test]
    fn syntax_follows_the_extension() {
        assert_eq!(Syntax::from_path("a/OPENAPI.JSON"), Some(Syntax::Json));
        assert_eq!(Syntax::from_path("a/openapi.yml"), Some(Syntax::Yaml));
        assert_eq!(Syntax::from_path("a/openapi.yaml"), Some(Syntax::Yaml));
        assert_eq!(Syntax::from_path("a/openapi.toml"), None);
    }

    #[test]
    fn capabilities_say_whether_anything_is_written() {
        assert!(Capabilities::FULL.writes());
        assert!(!Capabilities::CHECK_ONLY.writes());
        let names = framework_names(&[WebFramework::SpringBoot].into_iter().collect());
        assert_eq!(names, ["spring_boot"]);
        assert_eq!(name_of(&1), "");
    }
}
