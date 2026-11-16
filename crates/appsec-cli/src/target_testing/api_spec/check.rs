use appsec_api_spec::plan::{Target, Unit};
use appsec_api_spec::{CitedOperation, Operation, SpecFormat};

use super::super::test_path;
use super::{files, outcome_for, prompts, Context, Readable, SpecAction, SpecOutcome};

const MAX_NAMED: usize = 20;

pub(super) struct Checked {
    scan: Option<Result<Vec<CitedOperation>, String>>,
}

fn operation(cited: &CitedOperation) -> Operation {
    Operation::new(&cited.method, &cited.path)
}

impl Checked {
    pub(super) fn new(root: &std::path::Path, format: &dyn SpecFormat, units: &[Unit]) -> Self {
        let wanted = format.scans_source()
            && units
                .iter()
                .any(|unit| matches!(unit.target, Target::Existing { .. }));
        let scan = wanted.then(|| {
            files::texts(root, &|path| !test_path(path)).map(|texts| {
                texts
                    .iter()
                    .flat_map(|(path, text)| format.scan_source(path, text))
                    .collect()
            })
        });
        Self { scan }
    }

    pub(super) fn notes(&self, context: &Context<'_>) -> Vec<String> {
        let name = context.format.name();
        let cited = match &self.scan {
            None => return Vec::new(),
            Some(Err(reason)) => {
                return vec![format!(
                    "{name}: server registrations in the code were not checked: {reason}"
                )]
            }
            Some(Ok(cited)) => cited,
        };
        let inventory: Vec<Operation> = cited.iter().map(operation).collect();
        let missing = context
            .documents
            .first()
            .map(|(path, document)| {
                context
                    .format
                    .compare(document, &context.peers(path), &inventory)
                    .missing
            })
            .unwrap_or_default();
        let mut unmatched: Vec<String> = cited
            .iter()
            .filter(|entry| missing.contains(&operation(entry)))
            .map(|entry| format!("{}:{} ({})", entry.file, entry.line, entry.path))
            .collect();
        if unmatched.is_empty() {
            return Vec::new();
        }
        let extra = unmatched.len().saturating_sub(MAX_NAMED);
        unmatched.truncate(MAX_NAMED);
        if extra > 0 {
            unmatched.push(format!("and {extra} more"));
        }
        vec![format!(
            "{name}: the code registers services that no definition in the repository \
             defines: {}",
            unmatched.join(", ")
        )]
    }
}

pub(super) fn check(
    context: &Context<'_>,
    unit: &Unit,
    path: &str,
    found: &Readable,
    checked: &Checked,
) -> SpecOutcome {
    let format = context.format;
    let mut outcome = outcome_for(format, unit, path);
    outcome.action = SpecAction::Reported;
    outcome.syntax = Some(found.syntax);
    outcome.version = found.version;
    outcome.gaps.push(prompts::check_only_note(format.id()));
    for document in found.document.iter() {
        outcome.diagnostics_before = format.validate(document, &context.peers(path));
        if let Some(Ok(cited)) = &checked.scan {
            let inventory: Vec<Operation> = cited.iter().map(operation).collect();
            let own = format.compare(document, &[], &inventory);
            outcome.inventory = cited
                .iter()
                .filter(|entry| !own.missing.contains(&operation(entry)))
                .cloned()
                .collect();
            if !own.unverified.is_empty() {
                let names: Vec<&str> = own.unverified.iter().map(|op| op.path.as_str()).collect();
                outcome.gaps.push(format!(
                    "no server registration the scan recognizes was found for {names:?}; they \
                     may be client-only or registered another way"
                ));
            }
            outcome.unverified_operations = own.unverified;
        }
    }
    outcome
}
