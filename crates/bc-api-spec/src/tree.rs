//! Classification shared by the standards whose documents are JSON or
//! YAML trees (OpenAPI, AsyncAPI, OpenRPC).
//!
//! A name only nominates a candidate. A file becomes a document of the
//! standard when its parsed top level declares a supported version. How
//! strongly the name nominates it decides what happens when the content
//! cannot be confirmed: a file literally called `openapi.yaml` that fails
//! to parse is somebody's broken specification and is never ignored, while
//! an `api.json` that fails to parse is most likely something else.

use serde_json::Value;

use crate::format::{Candidate, NameStrength, SpecVersion, Syntax};
use crate::parse::{parse, ParseFailure};

/// What identifies one standard's tree documents.
pub struct TreeRules {
    /// Top-level keys that declare the standard and its version, such as
    /// `openapi` and `swagger`.
    pub markers: &'static [&'static str],
    /// Top-level keys that make a strongly named, versionless mapping an
    /// incomplete document of the standard.
    pub shape: &'static [&'static str],
    /// Top-level keys that mark another standard's document.
    pub foreign: &'static [&'static str],
    /// The supported version a document declares.
    pub version: fn(&Value) -> Option<SpecVersion>,
}

/// Classify one candidate's bytes, named with `strength`, under `rules`.
/// `max_bytes` bounds what is parsed.
pub fn classify(
    path: &str,
    bytes: &[u8],
    max_bytes: usize,
    strength: Option<NameStrength>,
    rules: &TreeRules,
) -> Candidate {
    let (Some(strength), Some(syntax)) = (strength, Syntax::from_path(path)) else {
        return Candidate::NotASpec;
    };
    let strong = strength == NameStrength::Strong;
    // Weak names only count when the text itself claims to be a document.
    let claims = |text: &str| {
        strong
            || text.lines().any(|line| {
                rules.markers.iter().any(|marker| {
                    line.starts_with(&format!("{marker}:"))
                        || line.contains(&format!("\"{marker}\""))
                })
            })
    };
    if bytes.len() > max_bytes {
        let lossy = String::from_utf8_lossy(&bytes[..max_bytes.min(bytes.len())]);
        return if claims(&lossy) {
            Candidate::Unverifiable {
                reason: format!("larger than the {max_bytes}-byte specification cap"),
            }
        } else {
            Candidate::NotASpec
        };
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return if strong {
            Candidate::Unverifiable {
                reason: "not UTF-8 text".into(),
            }
        } else {
            Candidate::NotASpec
        };
    };
    match parse(text, syntax) {
        Ok(document) => {
            if let Some(version) = (rules.version)(&document) {
                return Candidate::Spec {
                    syntax,
                    version: Some(version),
                    document,
                };
            }
            let object = document.as_object();
            let has =
                |keys: &[&str]| object.is_some_and(|map| keys.iter().any(|k| map.contains_key(*k)));
            if has(rules.markers) {
                return Candidate::Unverifiable {
                    reason: "declares a specification version this step does not support".into(),
                };
            }
            if strong && has(rules.shape) && !has(rules.foreign) {
                return Candidate::Broken { syntax, document };
            }
            Candidate::NotASpec
        }
        Err(ParseFailure::Malformed(reason)) if strong => Candidate::Malformed { syntax, reason },
        Err(ParseFailure::Unverifiable(reason)) | Err(ParseFailure::Malformed(reason))
            if claims(text) =>
        {
            Candidate::Unverifiable { reason }
        }
        Err(_) => Candidate::NotASpec,
    }
}
