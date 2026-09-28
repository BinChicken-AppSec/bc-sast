//! One bounded verdict-format repair re-ask, ported from the v1.4.0
//! `s6_verify.py::_verify_one` repair block.
//!
//! A verifier reply that reached a conclusion but mis-shaped the two-line
//! `VERDICT:`/`CVSS:` footer (ran long past it, or dropped the literal
//! `VERDICT:` prefix) used to go straight to `VERIFY_ERROR`, discarding
//! paid-for verification of committed true positives. Now it gets exactly
//! one chance to restate its conclusion in the required shape.
//!
//! Two gates keep that from fabricating a verdict:
//! - **Only when the primary reply mentions a verdict token.** The repair
//!   prompt asserts "your previous reply reached a conclusion"; if the
//!   reply carries neither `TRUE_POSITIVE` nor `FALSE_POSITIVE` there is
//!   nothing to restate and the model would invent one. So no re-ask.
//! - **Adoption must agree with the primary commitment** (see [`adopt`]).

use bc_llm_agentic::{run_agentic, AgenticConfig};
use bc_llm_client::{LlmClient, LlmError, ToolExecutor};
use bc_model::Verdict;

use crate::parse::{self, ParsedVerdict};

/// The reason `parse_verdict` gives a reply with no `VERDICT:` line.
pub(crate) const UNPARSEABLE: &str = "verifier output unparseable";

/// What the repair step did for one finding, rolled up into
/// [`crate::VerifyDiagnostics`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct RepairTrace {
    pub attempted: bool,
    pub adopted: bool,
}

/// Which verdict tokens the primary reply mentions, case-insensitively
/// (`(tp, fp)`). Mirrors upstream's `"TRUE_POSITIVE" in raw.upper()`.
pub(crate) fn verdict_tokens(raw: &str) -> (bool, bool) {
    let up = raw.to_uppercase();
    (up.contains("TRUE_POSITIVE"), up.contains("FALSE_POSITIVE"))
}

/// The adoption rule. The repaired verdict is adopted only when it parsed
/// AND agrees with what the primary reply committed to:
/// - primary named exactly one token: the repair must match it, which
///   recovers a committed verdict missing its `VERDICT:` prefix but
///   forbids a repair flipping a clear commitment to its opposite;
/// - primary named both tokens (prose weighing TP against FP without
///   ending in the contract's shape): the repair is the legitimate
///   disambiguation, so whichever it commits to is adopted.
pub(crate) fn adopt(primary: (bool, bool), repaired: &ParsedVerdict) -> bool {
    if repaired.reason == UNPARSEABLE {
        return false;
    }
    let (tp, fp) = primary;
    (tp && fp)
        || (tp && repaired.verdict == Verdict::TruePositive)
        || (fp && repaired.verdict == Verdict::FalsePositive)
}

/// Parse the primary reply and, when it is unparseable but names a verdict
/// token, spend exactly one repair call. Returns the verdict to classify
/// (the repaired one when adopted, else the primary's unparseable
/// sentinel, which [`crate::classify`] turns into `VERIFY_ERROR`).
///
/// `may_spend` is asked right before the repair call so a tripped budget
/// gate is honored for this billed call too (upstream checks its Ctrl-C
/// abort flag at the same point for the same reason). A repair that
/// errors, including a guardrail block, is swallowed: the finding keeps
/// the `VERIFY_ERROR` it would have had with no repair, and the failure
/// never counts toward the stage's guardrail-abort gate.
///
/// **Divergence from Python**: upstream re-dispatches the repair with the
/// primary's full agentic kwargs, tools included. Here the repair session
/// is given no tools. The prompt forbids re-analysis and carries the
/// previous reply verbatim, so a tool call could only reopen the analysis
/// the prompt says not to reopen, and costs turns for nothing.
pub(crate) async fn parse_with_repair(
    client: &dyn LlmClient,
    tools: &dyn ToolExecutor,
    primary_raw: &str,
    agentic_cfg: &AgenticConfig,
    may_spend: impl FnOnce() -> bool,
    index: usize,
) -> (ParsedVerdict, RepairTrace) {
    let parsed = parse::parse_verdict(primary_raw);
    if parsed.reason != UNPARSEABLE {
        return (parsed, RepairTrace::default());
    }
    let tokens = verdict_tokens(primary_raw);
    let mut trace = RepairTrace::default();
    let mut logged = primary_raw.to_string();
    if (tokens.0 || tokens.1) && may_spend() {
        trace.attempted = true;
        let mut cfg = agentic_cfg.clone();
        cfg.allowed_tools = Vec::new();
        let prompt = crate::prompts::repair_verdict_prompt(primary_raw);
        match run_agentic(client, tools, &prompt, &cfg).await {
            Ok(outcome) => {
                let repaired = parse::parse_verdict(&outcome.final_text);
                if adopt(tokens, &repaired) {
                    trace.adopted = true;
                    return (repaired, trace);
                }
                logged = outcome.final_text;
            }
            Err(e) => log_repair_failure(index, &e),
        }
    }
    log_unparseable(index, &logged);
    (parsed, trace)
}

fn log_repair_failure(index: usize, err: &LlmError) {
    let detail: String = bc_redact::redact(&err.to_string())
        .chars()
        .take(120)
        .collect();
    tracing::warn!("s6-verify: #{index} verdict-repair failed, keeping VERIFY_ERROR: {detail}");
}

/// Log the last text actually seen (the repair reply when one parsed but
/// was rejected, else the primary). The FULL reply is redacted BEFORE it
/// is cut: slicing first could bisect a credential the verifier quoted
/// from the repo so the surviving prefix matches no redaction pattern.
fn log_unparseable(index: usize, raw: &str) {
    let head: String = bc_redact::redact(raw).chars().take(200).collect();
    tracing::warn!("s6-verify: #{index} UNPARSEABLE raw[:200]={head:?}");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(raw: &str) -> ParsedVerdict {
        parse::parse_verdict(raw)
    }

    #[test]
    fn verdict_tokens_are_case_insensitive() {
        assert_eq!(verdict_tokens("a true_positive b"), (true, false));
        assert_eq!(verdict_tokens("FALSE_POSITIVE"), (false, true));
        assert_eq!(
            verdict_tokens("TRUE_POSITIVE or FALSE_POSITIVE"),
            (true, true)
        );
        assert_eq!(verdict_tokens("no idea"), (false, false));
    }

    #[test]
    fn adopt_requires_a_parseable_repair() {
        assert!(!adopt((true, true), &parsed("still no footer")));
    }

    #[test]
    fn adopt_requires_agreement_with_a_single_commitment() {
        let tp = parsed("VERDICT: TRUE_POSITIVE (confidence: 8/10) - x");
        let fp = parsed("VERDICT: FALSE_POSITIVE (confidence: 8/10) - x");
        assert!(adopt((true, false), &tp));
        assert!(!adopt((true, false), &fp));
        assert!(adopt((false, true), &fp));
        assert!(!adopt((false, true), &tp));
        // Both tokens: the repair disambiguates either way.
        assert!(adopt((true, true), &tp));
        assert!(adopt((true, true), &fp));
        // Neither token never reaches adoption in practice, but is refused.
        assert!(!adopt((false, false), &tp));
    }

    #[test]
    fn log_helpers_redact_before_truncating() {
        // Exercised for coverage; tracing output is not captured here.
        log_unparseable(
            0,
            &format!("{} AKIA{}", "x".repeat(190), "ABCDEFGHIJKLMNOP"),
        );
        log_repair_failure(
            0,
            &LlmError::Other {
                message: "boom".into(),
            },
        );
    }
}
