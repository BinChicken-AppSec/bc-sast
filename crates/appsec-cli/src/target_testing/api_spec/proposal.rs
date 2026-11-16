use std::path::Path;

use appsec_api_spec::edits::{apply_edits, TextEdit};
use appsec_api_spec::{Assessment, Diagnostic, Operation, Peer, SpecFormat, Syntax};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::super::{check_citation, ContractEvidence};

const MAX_INVENTORY: usize = 2_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Decision {
    Create,
    Repair,
    NoChange,
    NotApplicable,
}

pub use appsec_api_spec::CitedOperation;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct GeneratorReply {
    pub decision: Decision,
    #[serde(default)]
    pub document: Option<Value>,
    #[serde(default)]
    pub edits: Vec<TextEdit>,
    #[serde(default)]
    pub replacement: Option<String>,
    pub inventory: Vec<CitedOperation>,
    #[serde(default)]
    pub changes: Vec<String>,
    #[serde(default)]
    pub remaining_gaps: Vec<String>,
}

pub(super) enum Subject<'a> {
    Create {
        syntax: Syntax,
    },
    Existing {
        text: &'a str,
        syntax: Syntax,
        document: Option<&'a Value>,
        before: &'a [Diagnostic],
    },
}

impl Subject<'_> {
    fn syntax(&self) -> Syntax {
        match self {
            Self::Create { syntax } | Self::Existing { syntax, .. } => *syntax,
        }
    }
}

#[derive(Debug)]
pub(super) struct Candidate {
    pub reply: GeneratorReply,
    pub text: String,
    pub assessment: Assessment,
}

#[derive(Debug, Default)]
pub(super) struct Refusal {
    pub issues: Vec<String>,
    pub assessment: Option<Box<Assessment>>,
}

impl Refusal {
    fn of(issue: impl Into<String>) -> Self {
        Self {
            issues: vec![issue.into()],
            assessment: None,
        }
    }
}

pub(super) fn evaluate(
    root: &Path,
    format: &dyn SpecFormat,
    subject: &Subject<'_>,
    peers: &[Peer<'_>],
    reply_text: &str,
    max_bytes: usize,
) -> Result<Candidate, Refusal> {
    let reply: GeneratorReply = serde_json::from_str(reply_text)
        .map_err(|e| Refusal::of(format!("the reply is not the required JSON object: {e}")))?;
    let inventory = checked_inventory(root, format, &reply.inventory).map_err(Refusal::of)?;
    if matches!(subject, Subject::Create { .. }) && reply.decision == Decision::NotApplicable {
        if !inventory.is_empty() {
            return Err(Refusal::of(
                "not_applicable means the code serves no such operations; the inventory must be \
                 empty",
            ));
        }
        return Ok(Candidate {
            reply,
            text: String::new(),
            assessment: Assessment::default(),
        });
    }
    let syntax = subject.syntax();
    let text = proposed_text(format, subject, &reply)?;
    if text.len() > max_bytes {
        return Err(Refusal::of(format!(
            "the proposed document is {} bytes, over the {max_bytes}-byte specification cap",
            text.len()
        )));
    }
    let document = format.parse(&text, syntax).map_err(|failure| {
        Refusal::of(format!(
            "the proposed document does not parse as {syntax:?} with the built-in parser: \
             {failure:?}"
        ))
    })?;
    let mut issues = Vec::new();
    let edited = matches!(subject, Subject::Existing { .. })
        && reply.decision == Decision::Repair
        && reply.replacement.is_none();
    if edited {
        for edit in &reply.edits {
            issues.extend(appsec_api_spec::hygiene::problems(&edit.new));
        }
        if appsec_redact::redact(&text) != text {
            issues.push(
                "the edited document contains a value the redactor treats as a credential"
                    .to_string(),
            );
        }
    } else {
        issues.extend(appsec_api_spec::hygiene::problems(&text));
    }
    let original = match subject {
        Subject::Existing {
            document: Some(document),
            before,
            ..
        } => Some((*document, *before)),
        _ => None,
    };
    if matches!(subject, Subject::Create { .. }) {
        issues.extend(format.new_document_problems(&document));
    }
    let assessment = appsec_api_spec::assess(format, &document, peers, &inventory, original);
    issues.extend(assessment.blocking());
    if reply.decision == Decision::NoChange && !issues.is_empty() {
        issues.insert(
            0,
            "no_change is only acceptable for a valid document that covers every cited operation"
                .into(),
        );
    }
    if issues.is_empty() {
        Ok(Candidate {
            reply,
            text,
            assessment,
        })
    } else {
        Err(Refusal {
            issues,
            assessment: Some(Box::new(assessment)),
        })
    }
}

fn checked_inventory(
    root: &Path,
    format: &dyn SpecFormat,
    inventory: &[CitedOperation],
) -> Result<Vec<Operation>, String> {
    if inventory.len() > MAX_INVENTORY {
        return Err(format!(
            "the inventory lists {} operations, over the {MAX_INVENTORY}-operation limit",
            inventory.len()
        ));
    }
    let mut operations = Vec::new();
    for entry in inventory {
        let operation = format.inventory_operation(&entry.method, &entry.path)?;
        check_citation(
            root,
            &ContractEvidence {
                file: entry.file.clone(),
                line: entry.line,
                snippet: entry.snippet.clone(),
            },
        )
        .map_err(|e| {
            format!(
                "inventory entry {} {}: {e}",
                operation.method.to_uppercase(),
                operation.path
            )
        })?;
        operations.push(operation);
    }
    Ok(operations)
}

fn proposed_text(
    format: &dyn SpecFormat,
    subject: &Subject<'_>,
    reply: &GeneratorReply,
) -> Result<String, Refusal> {
    match (subject, reply.decision) {
        (Subject::Create { syntax }, Decision::Create) => {
            let Some(document) = &reply.document else {
                return Err(Refusal::of("a create decision needs `document`"));
            };
            format.emit(document, *syntax).map_err(Refusal::of)
        }
        (Subject::Create { .. }, _) => Err(Refusal::of(
            "no specification exists for this service; the decision must be create",
        )),
        (Subject::Existing { .. }, Decision::Create | Decision::NotApplicable) => Err(Refusal::of(
            "a specification already exists; repair it or report no_change",
        )),
        (Subject::Existing { text, document, .. }, Decision::Repair) => {
            match (&reply.replacement, document) {
                (Some(replacement), None) => Ok(replacement.clone()),
                (Some(_), Some(_)) => Err(Refusal::of(
                    "a parseable specification is repaired with minimal edits, never replaced",
                )),
                (None, _) if reply.edits.is_empty() => {
                    Err(Refusal::of("a repair decision needs at least one edit"))
                }
                (None, _) => apply_edits(text, &reply.edits).map_err(Refusal::of),
            }
        }
        (Subject::Existing { text, .. }, Decision::NoChange) => Ok((*text).to_string()),
    }
}
