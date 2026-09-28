// Portions of this file are transcribed from vvaharness, Visa's agentic
// SAST harness: Copyright 2026 Visa, Inc., licensed under the Apache
// License, Version 2.0. Reimplemented in Rust and modified; see the module
// documentation below, and NOTICE for the full attribution.
//! The remediation method as model-agnostic prompt text, ported verbatim
//! from `remediation_agent/prompts.py` (3-gate triage, minimal-diff
//! fix-scoring, code-level-signals-only, secrets-handling). This module
//! owns ONLY the prompt text — the structured-output contract lives in
//! [`crate::verdict`].
//!
//! **Schema note**: the Python original embeds its Pydantic model's own
//! generated JSON schema in the SYSTEM prompt. This port hand-writes an
//! equivalent JSON Schema string for [`crate::verdict::RemediationVerdict`]
//! instead of pulling in a schema-generation dependency (`schemars`) for
//! one fixed struct — a byte-identical schema isn't needed, only clear
//! shape guidance for the model.

use bc_policy_gate::Strategy;

const VERDICT_SCHEMA: &str = r#"{"type":"object","required":["finding_index","verdict","gates","root_cause","changes","remaining_risks","recommendations","summary"],"properties":{"finding_index":{"type":"integer"},"verdict":{"type":"string","enum":["Fixed","Partially Fixed","Not Fixed","False Positive","Needs Review","Denied"]},"gates":{"type":"object","required":["source","sink","missing_control"],"properties":{"source":{"type":"string","enum":["pass","partial","fail"],"description":"Gate A - attacker-controlled source identified"},"sink":{"type":"string","enum":["pass","partial","fail"],"description":"Gate B - security-relevant sink reachable from source"},"missing_control":{"type":"string","enum":["pass","partial","fail"],"description":"Gate C - missing/insufficient validation"}}},"root_cause":{"type":"string","description":"one paragraph, cites file:line"},"changes":{"type":"array","items":{"type":"object","properties":{"file":{"type":"string"},"summary":{"type":"string"}}}},"remaining_risks":{"type":"array","items":{"type":"string"}},"recommendations":{"type":"array","items":{"type":"string"}},"summary":{"type":"string","description":"2-4 sentence human-readable summary"}}}"#;

/// SYSTEM prompt with the structured-output JSON schema embedded, so
/// every backend (including a backend with no native schema flag) is
/// told the exact output shape.
pub fn build_system() -> String {
    format!(
        r#"You are an application-security REMEDIATION agent operating on a single SAST
finding inside a checked-out repository. You have read/search tools (and, in
fix mode, edit tools) scoped to the repo. Your job: confirm the finding via
evidence, then apply the MINIMAL safe code change that removes the root cause.

EVIDENCE GATES (assess all three before fixing):
  - Gate A — Source: identify the attacker/user-controlled input with file:line.
  - Gate B — Sink: identify the security-relevant sink reachable from the source
    with file:line.
  - Gate C — Missing control: explain why existing validation/sanitization does
    not constrain the source (or that none exists).

REMEDIATION RULES (authoritative):
  - LEAST-CHANGE: minimal diff at the vulnerable site(s). No refactors, no
    renames, no unrelated cleanup. Preserve behaviour for legitimate inputs.
  - ROOT CAUSE: fix the actual flaw (e.g. parameterized query, output encoding,
    constant-time compare, TLS verification on, auth dependency, input
    allow-list), not a symptom.
  - PLAYBOOK STRATEGY: when the user prompt includes a "Required fix strategy"
    section, follow it exactly — do NOT invent an alternative approach.
  - POLICY: when the user prompt includes a "Remediation policy" section, never
    edit files matching its do-not-edit globs.
  - INSTANCE COVERAGE: fix every instance of the same root cause the finding
    references; note any sibling instances you spot.
  - NO NEW VULNERABILITIES: do not introduce new issues; use the framework's
    standard secure idiom.
  - CODE-LEVEL SIGNALS ONLY: do not rely on or recommend operational controls
    (WAF, SIEM, manual review, ADR docs, pre-commit hooks) as the fix.
  - SECRETS: never echo plaintext secrets/tokens/keys. Refer by file:line or
    redact as XX***YY (≤4 contiguous original chars). For hardcoded-secret
    findings, move the value to a config/env/secret-manager read and note that
    rotation is required.
  - SNIPPETS: quote at most ~20 lines of code in your output.
  - WORKFLOW PINS: never invent a commit SHA or write a placeholder SHA. Pin a
    remote reusable workflow only to an exact commit already evidenced in the
    repository. If no such SHA is available, make no edit and report Not Fixed.
  - VERIFY BEFORE CLAIMING SUCCESS: after editing a file, use your read tool
    to re-read it back and confirm the change is actually present on disk
    before setting `verdict` to "Fixed" or "Partially Fixed". If the edit
    did not take (tool error, wrong path, no-op), reflect that honestly —
    "Not Fixed" or "Needs Review", not a false "Fixed".

STRUCTURED OUTPUT (REQUIRED):
Respond with ONLY a single JSON object — no prose, no markdown fences — that
validates against this JSON Schema:
{VERDICT_SCHEMA}

Every field is REQUIRED — populate them all. In particular, `summary` MUST be a
non-empty 2-4 sentence human-readable description of the verdict and what you
changed (or, for non-fix verdicts, why). Never leave `summary` blank or omit it.

In fix mode you MUST actually apply the edits to the files before responding;
`changes` lists the diffs you made. In report-only mode, do NOT edit files —
populate `changes` with the edits you WOULD make and set the verdict accordingly."#
    )
}

/// Renders the policy guidance injected on the ALLOW path: the
/// do-NOT-edit path lists. Edits to those paths are programmatically
/// reverted post-run, so surfacing them up front reduces wasted work.
fn policy_block(deny_paths: &[String], forbid_paths: &[String]) -> String {
    if deny_paths.is_empty() && forbid_paths.is_empty() {
        return String::new();
    }
    // `paths` is always non-empty here: the guard above already
    // established at least one of `deny_paths`/`forbid_paths` is
    // non-empty, and concatenation (unlike dedup) never removes a
    // list's only elements.
    let mut paths: Vec<&str> = deny_paths
        .iter()
        .chain(forbid_paths.iter())
        .map(String::as_str)
        .collect();
    paths.sort_unstable();
    paths.dedup();
    let shown = if paths.len() > 24 {
        format!("{} …", paths[..24].join(", "))
    } else {
        paths.join(", ")
    };
    let lines = [
        String::new(),
        "## Remediation policy (authoritative)".to_string(),
        format!(
            "- Do NOT edit files matching these globs (sensitive subsystems / \
             build & CI infrastructure). Any such edit is automatically \
             reverted on disk after you finish: {shown}"
        ),
    ];
    format!("{}\n", lines.join("\n"))
}

/// The per-finding facts + policy context [`build_user`] renders into a
/// prompt — bundled into one struct rather than a long parameter list.
/// Every field is a reference or a small `Copy` scalar, so the struct
/// itself is cheaply `Copy`.
#[derive(Clone, Copy)]
pub struct FindingPrompt<'a> {
    pub finding_index: i64,
    pub file: &'a str,
    pub body: &'a str,
    pub repo: &'a str,
    pub fix_mode: bool,
    /// The resolved playbook strategy on the ALLOW path; `None` when
    /// policy enforcement is off or the CWE has no playbook entry.
    pub strategy: Option<&'a Strategy>,
    pub deny_paths: &'a [String],
    pub forbid_paths: &'a [String],
}

/// Per-finding user prompt: the full finding block + repo root + mode.
/// When the policy gate allows a patch, the caller passes the resolved
/// playbook `strategy` (the authoritative fix approach) plus the
/// do-not-edit path globs, which are injected as additional prompt
/// sections. With `strategy: None` and both path lists empty, this
/// renders exactly as the plain (no-policy) prompt.
pub fn build_user(p: &FindingPrompt) -> String {
    let FindingPrompt {
        finding_index,
        file,
        body,
        repo,
        fix_mode,
        strategy,
        deny_paths,
        forbid_paths,
    } = *p;
    let mode = if fix_mode { "fix" } else { "report-only" };
    let action = if fix_mode {
        "apply the minimal safe fix"
    } else {
        "describe the minimal safe fix (do NOT edit files)"
    };
    let strat = strategy
        .map(|s| format!("\n{}\n", s.as_prompt_block().trim()))
        .unwrap_or_default();
    let policy = policy_block(deny_paths, forbid_paths);
    let file_display = if file.is_empty() { "unknown" } else { file };
    format!(
        "REPOSITORY ROOT: {repo}\n\
         MODE: {mode}   (fix = apply minimal diffs; report-only = describe only, no edits)\n\
         FINDING INDEX: {finding_index}\n\
         PRIMARY FILE: {file_display}\n\
         \n\
         === SAST FINDING (from security-scan report) ===\n\
         {body}\n\
         === END FINDING ===\n\
         {strat}{policy}\n\
         Locate the code referenced above, assess Evidence Gates A/B/C, and {action}.\n\
         Set `finding_index` to {finding_index}. Respond with ONLY the JSON verdict\n\
         object that validates against the schema in your instructions."
    )
}

/// The retry prompt for the "described a fix but never wrote it" case:
/// the ORIGINAL per-finding prompt, the agent's own prior answer, and an
/// unambiguous statement of what the tool ledger says actually happened.
///
/// Net-new versus the Python original, which has no such retry (and no
/// gate that could detect the condition). Three deliberate choices:
///
/// 1. **The original prompt is replayed in full.** The retry is a fresh
///    agentic session, not a continuation — the previous session's tool
///    results are gone — so the finding, the repo root, the playbook
///    strategy and the policy path lists all have to be present again or
///    the model is being asked to fix something it can no longer see.
/// 2. **Its own prior answer is quoted back.** The model already did the
///    analysis; the failure was in the doing, not the thinking. Handing
///    the analysis back makes the second session about applying an edit
///    rather than re-deriving a fix, which is both cheaper and far more
///    likely to reproduce the same intended change.
/// 3. **The claim is contradicted with a fact, not a scolding.** "No
///    Edit/Write tool call was recorded for <files>" is checkable ground
///    truth from the write journal / computed diff, which is exactly the
///    kind of statement a model can act on.
pub fn build_retry(original_user: &str, prior_answer: &str, claimed: &[String]) -> String {
    let files = claimed.join(", ");
    format!(
        "{original_user}\n\
         \n\
         === RETRY — YOUR PREVIOUS ANSWER WAS NOT APPLIED ===\n\
         You already answered this finding once. Your previous answer was:\n\
         \n\
         {prior_answer}\n\
         \n\
         That answer claimed changes to: {files}\n\
         No Edit or Write tool call was recorded for any of those files, and the \
         repository content is unchanged — so the fix you described was never \
         applied. Do not simply repeat the answer.\n\
         \n\
         Apply the change now using the Edit tool (or Write, for a new file), \
         re-read the file to confirm the change is on disk, and then answer again \
         with the JSON verdict object. If, on looking again, the change should NOT \
         be made, say so honestly with a 'Not Fixed' or 'Needs Review' verdict \
         instead of claiming a fix that does not exist.\n\
         === END RETRY ==="
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base<'a>() -> FindingPrompt<'a> {
        FindingPrompt {
            finding_index: 1,
            file: "a.py",
            body: "body",
            repo: "/repo",
            fix_mode: true,
            strategy: None,
            deny_paths: &[],
            forbid_paths: &[],
        }
    }

    #[test]
    fn build_system_embeds_the_verdict_schema() {
        let sys = build_system();
        assert!(sys.contains("REMEDIATION agent"));
        assert!(sys.contains("EVIDENCE GATES"));
        assert!(sys.contains(r#""enum":["Fixed","Partially Fixed""#));
    }

    #[test]
    fn build_system_instructs_the_agent_to_verify_its_own_edit_before_claiming_fixed() {
        // Found live: gpt-4o claimed "Fixed" with a described change for
        // findings whose file was never actually modified on disk. This
        // instruction alone can't guarantee compliance (see
        // reconcile_verdict_with_diff in lib.rs for the deterministic
        // backstop that doesn't depend on the model behaving), but it's
        // a real behavioral ask, not just documentation.
        let sys = build_system();
        assert!(sys.contains("VERIFY BEFORE CLAIMING SUCCESS"));
    }

    #[test]
    fn build_system_forbids_inventing_a_workflow_pin() {
        // The prompt half of the workflow-pin gate (`crate::workflow_gate`
        // is the enforcing half): say up front that an invented SHA is
        // refused, so the model declines instead of spending a session on
        // an edit that will be rolled back.
        let sys = build_system();
        assert!(sys.contains("WORKFLOW PINS: never invent a commit SHA"));
        assert!(sys.contains("make no edit and report Not Fixed"));
    }

    #[test]
    fn build_user_plain_has_no_strategy_or_policy_sections() {
        let prompt = build_user(&FindingPrompt {
            finding_index: 3,
            file: "app.py",
            body: "finding body",
            ..base()
        });
        assert!(prompt.contains("REPOSITORY ROOT: /repo"));
        assert!(prompt.contains("MODE: fix"));
        assert!(prompt.contains("FINDING INDEX: 3"));
        assert!(prompt.contains("PRIMARY FILE: app.py"));
        assert!(prompt.contains("finding body"));
        assert!(prompt.contains("apply the minimal safe fix"));
        assert!(!prompt.contains("Required fix strategy"));
        assert!(!prompt.contains("Remediation policy"));
    }

    #[test]
    fn build_user_report_only_mode_asks_for_a_description_not_edits() {
        let prompt = build_user(&FindingPrompt {
            fix_mode: false,
            ..base()
        });
        assert!(prompt.contains("MODE: report-only"));
        assert!(prompt.contains("describe the minimal safe fix (do NOT edit files)"));
    }

    #[test]
    fn build_user_with_no_file_shows_unknown() {
        let prompt = build_user(&FindingPrompt { file: "", ..base() });
        assert!(prompt.contains("PRIMARY FILE: unknown"));
    }

    #[test]
    fn build_user_injects_the_resolved_strategy_block() {
        let yaml = "cwe:\n  CWE-89:\n    title: SQLi\n    strategies:\n      default:\n        name: parameterize\n        instruction: use bound params\n";
        let pb = bc_policy_gate::parse_playbook(yaml).unwrap();
        let strategy = pb.resolve("CWE-89", "python", &[]).unwrap();
        let prompt = build_user(&FindingPrompt {
            strategy: Some(&strategy),
            ..base()
        });
        assert!(prompt.contains("Required fix strategy: parameterize"));
    }

    #[test]
    fn build_user_injects_the_policy_do_not_edit_block() {
        let deny = ["**/auth/**".to_string()];
        let forbid = ["**/ci/**".to_string()];
        let prompt = build_user(&FindingPrompt {
            deny_paths: &deny,
            forbid_paths: &forbid,
            ..base()
        });
        assert!(prompt.contains("## Remediation policy (authoritative)"));
        assert!(prompt.contains("**/auth/**"));
        assert!(prompt.contains("**/ci/**"));
    }

    #[test]
    fn build_user_policy_block_dedupes_and_sorts_overlapping_paths() {
        let deny = ["**/auth/**".to_string(), "**/ci/**".to_string()];
        let forbid = ["**/ci/**".to_string()];
        let prompt = build_user(&FindingPrompt {
            deny_paths: &deny,
            forbid_paths: &forbid,
            ..base()
        });
        let count = prompt.matches("**/ci/**").count();
        assert_eq!(count, 1);
    }

    #[test]
    fn build_retry_replays_the_original_prompt_and_names_the_unwritten_files() {
        let original = build_user(&base());
        let retry = build_retry(&original, r#"{"verdict":"Fixed"}"#, &["db.py".to_string()]);
        // The retry is a FRESH session, so the finding itself has to be
        // present again — a model asked to "apply it now" with no finding
        // in front of it has nothing to apply.
        assert!(retry.contains("REPOSITORY ROOT: /repo"));
        assert!(retry.contains(r#"{"verdict":"Fixed"}"#));
        assert!(retry.contains("claimed changes to: db.py"));
        assert!(retry.contains("No Edit or Write tool call was recorded"));
        assert!(retry.contains("Apply the change now using the Edit tool"));
    }

    #[test]
    fn build_retry_still_allows_an_honest_negative_answer() {
        // The nudge must not read as "produce a Fixed verdict" — that
        // would trade one false claim for another.
        let retry = build_retry("orig", "prior", &["a.py".to_string(), "b.py".to_string()]);
        assert!(retry.contains("claimed changes to: a.py, b.py"));
        assert!(retry.contains("'Not Fixed' or 'Needs Review'"));
    }

    #[test]
    fn build_user_policy_block_truncates_beyond_24_paths() {
        let many: Vec<String> = (0..30).map(|i| format!("path{i}/**")).collect();
        let prompt = build_user(&FindingPrompt {
            deny_paths: &many,
            ..base()
        });
        assert!(prompt.contains(" …"));
    }
}
