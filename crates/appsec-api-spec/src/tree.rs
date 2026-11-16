use serde_json::Value;

use crate::format::{Candidate, NameStrength, SpecVersion, Syntax};
use crate::parse::{parse, ParseFailure};

pub struct TreeRules {
    pub markers: &'static [&'static str],
    pub shape: &'static [&'static str],
    pub foreign: &'static [&'static str],
    pub version: fn(&Value) -> Option<SpecVersion>,
}

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
