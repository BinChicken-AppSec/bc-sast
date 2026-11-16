use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Error,
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
    DuplicateDefinition,
    DuplicateField,
    DuplicateArgument,
    UnknownType,
    ReservedName,
    EmptyType,
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
    UnknownField,
    DuplicateFieldNumber,
    InvalidFieldNumber,
    ReservedConflict,
    InvalidLabel,
    InvalidEnumValue,
    InvalidBinding,
    MissingKey,
    InvalidKey,
    LegacyVersion,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    pub severity: Severity,
    pub code: Code,
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
