//! Typed diagnostics every standard reports.
//!
//! A diagnostic's `pointer` locates the problem. For JSON and YAML
//! standards it is an RFC 6901 JSON pointer into the document; for text
//! standards it is the same shape over the standard's syntax tree, a `/`
//! separated path of definition and member names (for example
//! `/types/User/fields/id`, or for WSDL `/portTypes/Quote/operations/Get`
//! and for OData CSDL `/types/Shop.Product/properties/ID`), so a repair
//! can be matched to what it fixes.

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// The document breaks a rule of its specification version.
    Error,
    /// Legal, but worth a reader's attention.
    Warning,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Code {
    NotAnObject,
    MissingVersion,
    InvalidVersion,
    MissingField,
    InvalidType,
    InvalidPathKey,
    InvalidMethod,
    MissingResponses,
    InvalidStatusKey,
    InvalidParameter,
    PathParameterNotRequired,
    UndeclaredPathParameter,
    UnknownPathParameter,
    DuplicateParameter,
    DuplicateOperationId,
    UnresolvedRef,
    ExternalRef,
    InvalidServer,
    InvalidSecurityScheme,
    UndefinedSecurityScheme,
    // Shared by the schema languages (GraphQL SDL, Protocol Buffers).
    DuplicateDefinition,
    DuplicateField,
    DuplicateArgument,
    UnknownType,
    ReservedName,
    EmptyType,
    // GraphQL SDL.
    InvalidExtension,
    InvalidInterface,
    MissingInterfaceField,
    InvalidUnionMember,
    InvalidOutputType,
    InvalidInputType,
    UnknownDirective,
    InvalidLocation,
    InvalidRootType,
    MissingQueryRoot,
    // AsyncAPI and OpenRPC.
    UnknownField,
    // Protocol Buffers.
    DuplicateFieldNumber,
    InvalidFieldNumber,
    ReservedConflict,
    InvalidLabel,
    InvalidEnumValue,
    // WSDL.
    InvalidBinding,
    // OData CSDL.
    MissingKey,
    InvalidKey,
    /// A legacy version this step reads but never rewrites.
    LegacyVersion,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    pub severity: Severity,
    pub code: Code,
    /// Where the problem is (see the module comment); empty for the root.
    pub pointer: String,
    pub message: String,
}

impl Diagnostic {
    pub fn error(code: Code, pointer: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Error,
            code,
            pointer: pointer.into(),
            message: message.into(),
        }
    }

    pub fn warning(code: Code, pointer: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warning,
            ..Self::error(code, pointer, message)
        }
    }
}

/// RFC 6901 escaping of one pointer segment.
pub fn escape(segment: &str) -> String {
    segment.replace('~', "~0").replace('/', "~1")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructors_set_the_severity_and_segments_are_escaped() {
        let error = Diagnostic::error(Code::MissingField, "/a", "m");
        assert_eq!(error.severity, Severity::Error);
        let warning = Diagnostic::warning(Code::ExternalRef, "/b", "n");
        assert_eq!(warning.severity, Severity::Warning);
        assert_eq!(warning.pointer, "/b");
        assert_eq!(escape("a/b~c"), "a~1b~0c");
    }
}
