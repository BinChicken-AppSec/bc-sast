use appsec_llm_agentic::{run_agentic, AgenticConfig};
use appsec_llm_client::{LlmClient, LlmError, ToolExecutor};
use appsec_model::Verdict;

use crate::parse::{self, ParsedVerdict};

pub(crate) const UNPARSEABLE: &str = "verifier output unparseable";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct RepairTrace {
    pub attempted: bool,
    pub adopted: bool,
}

pub(crate) fn verdict_tokens(raw: &str) -> (bool, bool) {
    let up = raw.to_uppercase();
    (up.contains("TRUE_POSITIVE"), up.contains("FALSE_POSITIVE"))
}

pub(crate) fn adopt(primary: (bool, bool), repaired: &ParsedVerdict) -> bool {
    if repaired.reason == UNPARSEABLE {
        return false;
    }
    let (tp, fp) = primary;
    (tp && fp)
        || (tp && repaired.verdict == Verdict::TruePositive)
        || (fp && repaired.verdict == Verdict::FalsePositive)
}

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
    let detail: String = appsec_redact::redact(&err.to_string())
        .chars()
        .take(120)
        .collect();
    tracing::warn!("s6-verify: #{index} verdict-repair failed, keeping VERIFY_ERROR: {detail}");
}

fn log_unparseable(index: usize, raw: &str) {
    let head: String = appsec_redact::redact(raw).chars().take(200).collect();
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
        assert!(adopt((true, true), &tp));
        assert!(adopt((true, true), &fp));
        assert!(!adopt((false, false), &tp));
    }

    #[test]
    fn log_helpers_redact_before_truncating() {
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
