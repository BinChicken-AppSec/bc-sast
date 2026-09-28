//! The multi-format framework: what every API description standard this
//! crate supports provides, and the registry the caller iterates.
//!
//! A standard is one implementation of [`SpecFormat`]. It recognizes its
//! documents by name and content, parses them into a `serde_json::Value`
//! (a JSON or YAML tree as is, or a text format's own syntax tree in a
//! stable JSON shape), validates them into typed [`Diagnostic`]s, lists
//! the operations they document, compares those with a cited inventory,
//! checks that a repair kept the author's content, serializes a new
//! document, and names where its documents conventionally live for the
//! services discovery found.
//!
//! Everything the caller does with a document goes through this trait, so
//! a new standard plugs in without touching the caller. The XML standards
//! (WSDL, OData CSDL) show the shape: each parses its text with `bc_xml`
//! into a `Value` model of its own, validates that model, and declares
//! through [`Capabilities`] whether this step may create, repair or
//! relocate its documents. Repairs are exact text edits
//! ([`crate::edits`]), which work on any text format.

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

/// An API description standard.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum FormatId {
    /// OpenAPI 3.x and Swagger 2.0.
    #[serde(rename = "openapi")]
    OpenApi,
    /// GraphQL schema definition language.
    #[serde(rename = "graphql")]
    Graphql,
    /// AsyncAPI 2.x and 3.x.
    #[serde(rename = "asyncapi")]
    AsyncApi,
    /// OpenRPC 1.x.
    #[serde(rename = "openrpc")]
    OpenRpc,
    /// Protocol Buffers service definitions for gRPC (checked only).
    #[serde(rename = "protobuf")]
    Protobuf,
    /// RAML 0.8 and 1.0 (checked only).
    #[serde(rename = "raml")]
    Raml,
    /// API Blueprint (checked only).
    #[serde(rename = "api_blueprint")]
    ApiBlueprint,
    /// SOAP services described by WSDL 1.1 or 2.0, with XML Schema.
    #[serde(rename = "wsdl")]
    Wsdl,
    /// OData CSDL: XML (EDMX) or JSON; version 4 is repaired, versions 2
    /// and 3 are checked only.
    #[serde(rename = "odata")]
    OData,
}

impl FormatId {
    /// Every standard, in the order the step assesses them.
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

    /// The name used in policies, flags and reports.
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

    /// The standard `name` (as [`FormatId::as_str`] spells it) names.
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|id| id.as_str() == name.trim().to_ascii_lowercase())
    }
}

/// How a document's text is written.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Syntax {
    Json,
    Yaml,
    /// GraphQL SDL.
    Graphql,
    /// A Protocol Buffers `.proto` file.
    Protobuf,
    /// Markdown (API Blueprint).
    Markdown,
    /// XML (WSDL, XML Schema, OData CSDL in EDMX).
    Xml,
}

impl Syntax {
    /// The JSON or YAML syntax a path's extension implies. Text formats
    /// recognize their own extensions.
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

/// Specification version declared by a document.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpecVersion {
    Swagger20,
    OpenApi30,
    OpenApi31,
    OpenApi32,
    /// AsyncAPI 2.0 to 2.6.
    AsyncApi2,
    /// AsyncAPI 3.x.
    AsyncApi3,
    /// OpenRPC 1.x.
    OpenRpc1,
    Proto2,
    Proto3,
    /// Protocol Buffers editions (`edition = "2023"`).
    ProtoEditions,
    Raml08,
    Raml10,
    /// API Blueprint `FORMAT: 1A`.
    Blueprint1A,
    /// WSDL 1.1 (`http://schemas.xmlsoap.org/wsdl/`).
    Wsdl11,
    /// WSDL 2.0 (`http://www.w3.org/ns/wsdl`).
    Wsdl20,
    /// OData version 1 or 2 metadata (Microsoft EDMX namespaces; legacy).
    Odata2,
    /// OData version 3 metadata (Microsoft EDMX namespaces; legacy).
    Odata3,
    /// OData version 4.0 or 4.01 CSDL (OASIS namespaces or CSDL JSON).
    Odata4,
}

impl SpecVersion {
    pub fn is_swagger(self) -> bool {
        self == Self::Swagger20
    }

    /// `responses` stopped being required on an operation in OpenAPI 3.1.
    pub fn responses_optional(self) -> bool {
        matches!(self, Self::OpenApi31 | Self::OpenApi32)
    }
}

/// How strongly a file name nominates a specification candidate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NameStrength {
    /// A name tooling uses for exactly this purpose, such as
    /// `openapi.yaml`.
    Strong,
    /// A name that often, but not only, holds a specification. It counts
    /// only when the content confirms it.
    Weak,
}

/// What a candidate file turned out to be.
#[derive(Clone, Debug, PartialEq)]
pub enum Candidate {
    /// A document this crate can validate and, if the format allows it,
    /// repair.
    Spec {
        syntax: Syntax,
        version: Option<SpecVersion>,
        document: Value,
    },
    /// A strongly named, parseable, specification-shaped document with no
    /// version: an incomplete specification, repairable in place.
    Broken {
        syntax: Syntax,
        document: Value,
    },
    /// A strongly named file that does not parse at all. It may be
    /// replaced wholesale by a reviewed proposal, which is the only case
    /// where a repair does not have to preserve existing text.
    Malformed {
        syntax: Syntax,
        reason: String,
    },
    /// A file that is, or may be, a specification this crate cannot read
    /// safely. It is never modified.
    Unverifiable {
        reason: String,
    },
    NotASpec,
}

/// A readable candidate's parts: its syntax, its declared version, its
/// parsed tree (`None` when the text does not parse) and why not.
#[derive(Clone, Debug, PartialEq)]
pub struct Parts {
    pub syntax: Syntax,
    pub version: Option<SpecVersion>,
    pub document: Option<Value>,
    pub parse_error: Option<String>,
}

impl Candidate {
    /// `None` for a file that is not a specification, the reason for one
    /// that is unverifiable, and the parts of any other.
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

/// What this step may do with a standard's documents.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Capabilities {
    /// Create a missing document from a cited inventory.
    pub create: bool,
    /// Repair or complete an existing document with minimal edits.
    pub repair: bool,
    /// Move a misplaced document to its conventional location.
    pub relocate: bool,
}

impl Capabilities {
    /// Create, repair and relocate.
    pub const FULL: Capabilities = Capabilities {
        create: true,
        repair: true,
        relocate: true,
    };
    /// Validate and report only: the document is never written.
    pub const CHECK_ONLY: Capabilities = Capabilities {
        create: false,
        repair: false,
        relocate: false,
    };

    /// Whether the step ever writes this standard's documents.
    pub fn writes(self) -> bool {
        self.create || self.repair || self.relocate
    }
}

/// A service a standard's documents may belong to, with the convention
/// that decides where they go.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Owner {
    /// Repository-relative directory, `.` for the root.
    pub root: String,
    /// The frameworks and libraries that made it an owner, as reported.
    pub stack: Vec<String>,
    pub convention: Convention,
}

/// Another document of the same standard in the repository, for checks
/// that span files (imports, cross-file types).
#[derive(Clone, Copy, Debug)]
pub struct Peer<'a> {
    pub path: &'a str,
    pub document: &'a Value,
}

/// One API description standard. See the module comment.
pub trait SpecFormat: Sync {
    fn id(&self) -> FormatId;
    /// A human-readable name for reports and notes.
    fn name(&self) -> &'static str;
    fn capabilities(&self) -> Capabilities;
    /// Whether `path` names a candidate document of this standard.
    fn candidate_strength(&self, path: &str) -> Option<NameStrength>;
    /// Classify one candidate's bytes; `max_bytes` bounds what is parsed.
    fn classify(&self, path: &str, bytes: &[u8], max_bytes: usize) -> Candidate;
    /// Parse text written in `syntax` into this standard's tree.
    fn parse(&self, text: &str, syntax: Syntax) -> Result<Value, ParseFailure>;
    /// The version a parsed document declares, when it declares one.
    fn version(&self, document: &Value) -> Option<SpecVersion>;
    /// The standard's rules, with the standard's other documents in the
    /// repository (`peers`) as context for what spans files: types and
    /// imports defined elsewhere.
    fn validate(&self, document: &Value, peers: &[Peer<'_>]) -> Vec<Diagnostic>;
    /// What this step may do with an existing document of `version`. A
    /// standard that reads legacy versions it never rewrites narrows its
    /// [`SpecFormat::capabilities`] here.
    fn document_capabilities(&self, version: Option<SpecVersion>) -> Capabilities {
        let _ = version;
        self.capabilities()
    }
    /// Whether a parsed document only supports the standard's other
    /// documents (an XML Schema a WSDL imports): it is read as a peer for
    /// the checks that span files, and never assessed or written itself.
    fn supporting(&self, document: &Value) -> bool {
        let _ = document;
        false
    }
    /// Every operation the document declares.
    fn operations(&self, document: &Value) -> Vec<Operation>;
    /// How the document's operations compare with a cited inventory. An
    /// operation a peer documents is not missing from this document.
    fn compare(
        &self,
        document: &Value,
        peers: &[Peer<'_>],
        inventory: &[Operation],
    ) -> Completeness;
    /// Ways `repaired` fails to keep what `original` documented, given the
    /// diagnostics `original` had before the repair.
    fn preservation(
        &self,
        original: &Value,
        repaired: &Value,
        before: &[Diagnostic],
    ) -> Vec<String>;
    /// An inventory entry as an operation of this standard, or why it is
    /// not one.
    fn inventory_operation(&self, method: &str, path: &str) -> Result<Operation, String>;
    /// Serialize a generated document in `syntax`.
    fn emit(&self, document: &Value, syntax: Syntax) -> Result<String, String>;
    /// Why a parsed new document is not acceptable as a new document.
    fn new_document_problems(&self, document: &Value) -> Vec<String>;
    /// The services discovery found that this standard documents.
    fn owners(&self, services: &[HttpService], surfaces: &[ApiSurface]) -> Vec<Owner>;
    /// The convention for a document outside every owner.
    fn fallback(&self) -> Convention;
    /// Whether [`SpecFormat::scan_source`] finds operations in code, so
    /// the caller should scan the repository's source files for them.
    fn scans_source(&self) -> bool;
    /// Operations one source file registers, found deterministically,
    /// each with its citation. Empty for a standard whose inventory the
    /// generator builds instead.
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

/// Every supported standard, in [`FormatId::ALL`] order.
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

/// The implementation of `id`.
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

/// The strongest nomination any standard gives `path`: discovery lists a
/// file as a candidate when some standard's naming covers it.
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

/// Names of web frameworks, for an owner's reported stack.
pub fn framework_names(frameworks: &BTreeSet<WebFramework>) -> Vec<String> {
    frameworks.iter().map(name_of).collect()
}

/// The snake_case wire name of a serializable unit enum value.
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
