use std::collections::HashSet;
use std::sync::{LazyLock, Mutex};

use regex::Regex;

use crate::effort::ReasoningEffort;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lifecycle {
    Current,
    Legacy,
    Deprecated { retires: Option<&'static str> },
    Retired,
}

impl Lifecycle {
    pub fn as_of(self, today: &str) -> Lifecycle {
        match self {
            Lifecycle::Deprecated {
                retires: Some(date),
            } if date <= today => Lifecycle::Retired,
            other => other,
        }
    }

    pub fn label(self) -> String {
        match self {
            Lifecycle::Current => "current".to_string(),
            Lifecycle::Legacy => "legacy".to_string(),
            Lifecycle::Deprecated {
                retires: Some(date),
            } => format!("deprecated (retires {date})"),
            Lifecycle::Deprecated { retires: None } => "deprecated".to_string(),
            Lifecycle::Retired => "retired".to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sampling {
    Allowed,
    OneOfTemperatureOrTopP,
    OnlyWhenEffortNone,
    Rejected,
}

impl Sampling {
    fn label(self) -> &'static str {
        match self {
            Sampling::Allowed => "allowed",
            Sampling::OneOfTemperatureOrTopP => "temperature-or-top_p",
            Sampling::OnlyWhenEffortNone => "only-when-effort-none",
            Sampling::Rejected => "rejected",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Thinking {
    None,
    BudgetTokens,
    AdaptivePreferred,
    Adaptive,
    AdaptiveDefaultOn,
    AdaptiveAlwaysOn,
    Unknown,
}

impl Thinking {
    pub fn is_adaptive(self) -> bool {
        matches!(
            self,
            Thinking::AdaptivePreferred
                | Thinking::Adaptive
                | Thinking::AdaptiveDefaultOn
                | Thinking::AdaptiveAlwaysOn
        )
    }

    fn label(self) -> &'static str {
        match self {
            Thinking::None => "none",
            Thinking::BudgetTokens => "budget-tokens",
            Thinking::AdaptivePreferred => "adaptive (budget deprecated)",
            Thinking::Adaptive => "adaptive",
            Thinking::AdaptiveDefaultOn => "adaptive (on by default)",
            Thinking::AdaptiveAlwaysOn => "adaptive (always on)",
            Thinking::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenParam {
    MaxTokens,
    MaxCompletionTokens,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    Anthropic,
    OpenAi,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModelCapabilities {
    pub family: &'static str,
    pub provider: Provider,
    pub lifecycle: Lifecycle,
    pub sampling: Sampling,
    pub seed: Sampling,
    pub effort_levels: Option<&'static [ReasoningEffort]>,
    pub default_effort: Option<ReasoningEffort>,
    pub thinking: Thinking,
    pub max_output_tokens: Option<u32>,
    pub cache_min_tokens: Option<u32>,
    pub forced_tool_choice: bool,
    pub assistant_prefill: bool,
    pub token_param: TokenParam,
}

impl ModelCapabilities {
    pub const fn permissive() -> Self {
        ModelCapabilities {
            family: "",
            provider: Provider::Unknown,
            lifecycle: Lifecycle::Current,
            sampling: Sampling::Allowed,
            seed: Sampling::Allowed,
            effort_levels: None,
            default_effort: None,
            thinking: Thinking::Unknown,
            max_output_tokens: None,
            cache_min_tokens: None,
            forced_tool_choice: true,
            assistant_prefill: true,
            token_param: TokenParam::MaxCompletionTokens,
        }
    }

    pub fn is_known(&self) -> bool {
        !self.family.is_empty()
    }

    pub fn is_reasoning(&self) -> bool {
        self.effort_levels.is_some_and(|levels| !levels.is_empty())
    }

    pub fn clamp_effort(&self, requested: ReasoningEffort) -> Option<ReasoningEffort> {
        match self.effort_levels {
            None => Some(requested),
            Some(levels) => requested.clamp_to(levels),
        }
    }

    pub fn sampling_allowed(&self, sent_effort: Option<ReasoningEffort>) -> bool {
        self.rule_allows(self.sampling, sent_effort)
    }

    pub fn seed_allowed(&self, sent_effort: Option<ReasoningEffort>) -> bool {
        self.rule_allows(self.seed, sent_effort)
    }

    fn rule_allows(&self, rule: Sampling, sent_effort: Option<ReasoningEffort>) -> bool {
        match rule {
            Sampling::Allowed | Sampling::OneOfTemperatureOrTopP => true,
            Sampling::Rejected => false,
            Sampling::OnlyWhenEffortNone => sent_effort
                .or(self.default_effort)
                .is_none_or(|e| e == ReasoningEffort::None),
        }
    }

    pub fn clamp_max_tokens(&self, max_tokens: u32) -> u32 {
        self.max_output_tokens
            .map_or(max_tokens, |cap| max_tokens.min(cap))
    }

    pub fn render(&self, model: &str, today: &str) -> String {
        let family = if self.is_known() {
            self.family
        } else {
            "(unknown: sent as requested, rejections learned)"
        };
        let effort = match self.effort_levels {
            None => "any".to_string(),
            Some([]) => "none".to_string(),
            Some(levels) => levels
                .iter()
                .map(|e| e.as_str())
                .collect::<Vec<_>>()
                .join(","),
        };
        let default_effort = self
            .default_effort
            .map_or(String::new(), |e| format!(" (default {e})"));
        let opt = |v: Option<u32>| v.map_or("-".to_string(), |n| n.to_string());
        format!(
            "{model}: family={family} lifecycle={} sampling={} effort={effort}{default_effort} \
             thinking={} max_output={} cache_min={}",
            self.lifecycle.as_of(today).label(),
            self.sampling.label(),
            self.thinking.label(),
            opt(self.max_output_tokens),
            opt(self.cache_min_tokens),
        )
    }
}

use ReasoningEffort as E;

const CLAUDE_ALL: &[E] = &[E::Low, E::Medium, E::High, E::XHigh, E::Max];
const CLAUDE_NO_XHIGH: &[E] = &[E::Low, E::Medium, E::High, E::Max];
const CLAUDE_LMH: &[E] = &[E::Low, E::Medium, E::High];
const NO_EFFORT: &[E] = &[];
const GPT_56: &[E] = &[E::None, E::Low, E::Medium, E::High, E::XHigh, E::Max];
const GPT_52_55: &[E] = &[E::None, E::Low, E::Medium, E::High, E::XHigh];
const GPT_51: &[E] = &[E::None, E::Low, E::Medium, E::High];
const GPT_5: &[E] = &[E::Minimal, E::Low, E::Medium, E::High];
const O_SERIES: &[E] = &[E::Low, E::Medium, E::High];

#[allow(clippy::too_many_arguments)]
fn claude(
    family: &'static str,
    lifecycle: Lifecycle,
    sampling: Sampling,
    thinking: Thinking,
    effort: &'static [E],
    default_effort: Option<E>,
    max_out: u32,
    cache_min: u32,
    forced_tool_choice: bool,
) -> ModelCapabilities {
    let prefill = !matches!(
        thinking,
        Thinking::AdaptivePreferred
            | Thinking::Adaptive
            | Thinking::AdaptiveDefaultOn
            | Thinking::AdaptiveAlwaysOn
    );
    ModelCapabilities {
        family,
        provider: Provider::Anthropic,
        lifecycle,
        sampling,
        seed: Sampling::Rejected,
        effort_levels: Some(effort),
        default_effort,
        thinking,
        max_output_tokens: Some(max_out),
        cache_min_tokens: Some(cache_min),
        forced_tool_choice,
        assistant_prefill: prefill,
        token_param: TokenParam::MaxTokens,
    }
}

fn gpt(
    family: &'static str,
    lifecycle: Lifecycle,
    sampling: Sampling,
    effort: &'static [E],
    default_effort: Option<E>,
) -> ModelCapabilities {
    ModelCapabilities {
        family,
        provider: Provider::OpenAi,
        lifecycle,
        sampling,
        seed: sampling,
        effort_levels: Some(effort),
        default_effort,
        thinking: Thinking::None,
        max_output_tokens: None,
        cache_min_tokens: None,
        forced_tool_choice: true,
        assistant_prefill: true,
        token_param: TokenParam::MaxCompletionTokens,
    }
}

fn retired(family: &'static str, provider: Provider) -> ModelCapabilities {
    let mut row = ModelCapabilities::permissive();
    row.family = family;
    row.provider = provider;
    row.lifecycle = Lifecycle::Retired;
    row
}

fn dep(retires: &'static str) -> Lifecycle {
    Lifecycle::Deprecated {
        retires: Some(retires),
    }
}

const DEPRECATED: Lifecycle = Lifecycle::Deprecated { retires: None };

use Lifecycle::{Current, Legacy};
use Sampling::{Allowed, OneOfTemperatureOrTopP as OneOf, OnlyWhenEffortNone, Rejected};

#[rustfmt::skip]
static TABLE: LazyLock<Vec<ModelCapabilities>> = LazyLock::new(|| vec![
    claude("claude-fable-5-1",   Current,             Rejected, Thinking::AdaptiveAlwaysOn,  CLAUDE_ALL,      Some(E::High),   128_000, 512,  false),
    claude("claude-mythos-5-1",  Current,             Rejected, Thinking::AdaptiveAlwaysOn,  CLAUDE_ALL,      Some(E::High),   128_000, 512,  false),
    claude("claude-fable-5",     Current,             Rejected, Thinking::AdaptiveAlwaysOn,  CLAUDE_ALL,      Some(E::High),   128_000, 512,  true),
    claude("claude-mythos-5",    Current,             Rejected, Thinking::AdaptiveAlwaysOn,  CLAUDE_ALL,      Some(E::High),   128_000, 512,  true),
    claude("claude-opus-5-5",    Current,             Rejected, Thinking::AdaptiveAlwaysOn,  CLAUDE_ALL,      Some(E::Medium), 128_000, 512,  false),
    claude("claude-opus-5",      Current,             Rejected, Thinking::AdaptiveDefaultOn, CLAUDE_ALL,      Some(E::High),   128_000, 512,  true),
    claude("claude-opus-4-8",    Current,             Rejected, Thinking::Adaptive,          CLAUDE_ALL,      Some(E::High),   128_000, 1024, true),
    claude("claude-opus-4-7",    Current,             Rejected, Thinking::Adaptive,          CLAUDE_ALL,      Some(E::High),   128_000, 2048, true),
    claude("claude-sonnet-5",    Current,             Rejected, Thinking::AdaptiveDefaultOn, CLAUDE_ALL,      Some(E::High),   128_000, 1024, true),
    claude("claude-opus-4-6",    Current,             OneOf,    Thinking::AdaptivePreferred, CLAUDE_NO_XHIGH, Some(E::High),   128_000, 4096, true),
    claude("claude-sonnet-4-6",  Current,             OneOf,    Thinking::AdaptivePreferred, CLAUDE_NO_XHIGH, Some(E::High),   128_000, 1024, true),
    claude("claude-opus-4-5",    Legacy,              OneOf,    Thinking::BudgetTokens,      CLAUDE_LMH,      Some(E::High),   64_000,  4096, true),
    claude("claude-sonnet-4-5",  Legacy,              OneOf,    Thinking::BudgetTokens,      NO_EFFORT,       None,            64_000,  1024, true),
    claude("claude-haiku-4-5",   Current,             OneOf,    Thinking::BudgetTokens,      NO_EFFORT,       None,            64_000,  4096, true),
    claude("claude-opus-4-1",    dep("2026-08-05"),   OneOf,    Thinking::BudgetTokens,      NO_EFFORT,       None,            32_000,  1024, true),
    claude("claude-opus-4-0",    DEPRECATED,          OneOf,    Thinking::BudgetTokens,      NO_EFFORT,       None,            32_000,  1024, true),
    claude("claude-opus-4",      DEPRECATED,          OneOf,    Thinking::BudgetTokens,      NO_EFFORT,       None,            32_000,  1024, true),
    claude("claude-sonnet-4-0",  DEPRECATED,          OneOf,    Thinking::BudgetTokens,      NO_EFFORT,       None,            64_000,  1024, true),
    claude("claude-sonnet-4",    DEPRECATED,          OneOf,    Thinking::BudgetTokens,      NO_EFFORT,       None,            64_000,  1024, true),
    {
        let mut row = retired("claude-3-haiku", Provider::Anthropic);
        row.lifecycle = dep("2026-04-19");
        row
    },
    retired("claude-3-5", Provider::Anthropic),
    retired("claude-3-7", Provider::Anthropic),
    retired("claude-3", Provider::Anthropic),
    retired("claude-2", Provider::Anthropic),
    retired("claude-2.0", Provider::Anthropic),
    retired("claude-2.1", Provider::Anthropic),
    retired("claude-instant", Provider::Anthropic),
    gpt("gpt-6",       Current,           Allowed,            GPT_56,    Some(E::Medium)),
    {
        let mut row = gpt("gpt-6-luna", Current, Allowed, GPT_56, Some(E::Medium));
        row.max_output_tokens = Some(128_000);
        row
    },
    gpt("gpt-5.6",     Current,           OnlyWhenEffortNone, GPT_56,    Some(E::Medium)),
    {
        let mut row = gpt("gpt-5.6-luna", Current, OnlyWhenEffortNone, GPT_56, Some(E::Medium));
        row.max_output_tokens = Some(128_000);
        row
    },
    gpt("gpt-5.5",     Current,           OnlyWhenEffortNone, GPT_52_55, Some(E::Medium)),
    gpt("gpt-5.4",     Current,           OnlyWhenEffortNone, GPT_52_55, Some(E::None)),
    gpt("gpt-5.3",     Current,           OnlyWhenEffortNone, GPT_52_55, Some(E::None)),
    gpt("gpt-5.2",     Current,           OnlyWhenEffortNone, GPT_52_55, Some(E::None)),
    gpt("gpt-5.1",     Current,           OnlyWhenEffortNone, GPT_51,    Some(E::None)),
    gpt("gpt-5",       dep("2026-12-11"), Rejected,           GPT_5,     Some(E::Medium)),
    gpt("o1",          dep("2026-10-23"), Rejected,           O_SERIES,  Some(E::Medium)),
    gpt("o3",          dep("2026-12-11"), Rejected,           O_SERIES,  Some(E::Medium)),
    gpt("o3-mini",     dep("2026-10-23"), Rejected,           O_SERIES,  Some(E::Medium)),
    gpt("o3-pro",      DEPRECATED,        Rejected,           O_SERIES,  Some(E::Medium)),
    gpt("o4-mini",     dep("2026-10-23"), Rejected,           O_SERIES,  Some(E::Medium)),
    retired("o1-preview", Provider::OpenAi),
    retired("o1-mini", Provider::OpenAi),
    gpt("gpt-4.1",     Legacy,            Allowed,            NO_EFFORT, None),
    gpt("gpt-4o",      Legacy,            Allowed,            NO_EFFORT, None),
    gpt("chatgpt-4o",  Legacy,            Allowed,            NO_EFFORT, None),
    retired("gpt-4.5", Provider::OpenAi),
    gpt("gpt-4",       dep("2026-10-23"), Allowed,            NO_EFFORT, None),
    gpt("gpt-3.5",     dep("2026-10-23"), Allowed,            NO_EFFORT, None),
]);

fn chat_latest() -> ModelCapabilities {
    gpt("*-chat-latest", Current, Allowed, NO_EFFORT, None)
}

static PROVIDER_PREFIX_RX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:(?:us|eu|apac|ap|au|jp|ca|us-gov|global)\.)?(?:anthropic|openai)\.")
        .expect("static pattern")
});
static BEDROCK_VERSION_RX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:-v\d+)?(?::\d+)?$").expect("static pattern"));
static DATE_SUFFIX_RX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"-(?:\d{8}|\d{4}-\d{2}-\d{2})$").expect("static pattern"));

pub fn normalize_model_id(model: &str) -> String {
    let lower = model.trim().to_ascii_lowercase();
    let tail = lower.rsplit('/').next().unwrap_or_default();
    let no_vertex = tail.split('@').next().unwrap_or_default();
    let no_vendor = PROVIDER_PREFIX_RX.replace(no_vertex, "");
    let no_version = BEDROCK_VERSION_RX.replace(&no_vendor, "");
    DATE_SUFFIX_RX.replace(&no_version, "").into_owned()
}

fn family_matches(id: &str, family: &str) -> bool {
    let Some(rest) = id.strip_prefix(family) else {
        return false;
    };
    let mut chars = rest.chars();
    match chars.next() {
        None => true,
        Some('.') => !chars.next().is_some_and(|c| c.is_ascii_digit()),
        Some('-') => {
            let digits = chars.clone().take_while(char::is_ascii_digit).count();
            !(digits == 1 || digits == 2)
        }
        Some(_) => false,
    }
}

pub fn capabilities(model: &str) -> ModelCapabilities {
    let id = normalize_model_id(model);
    if id.ends_with("-chat-latest") {
        return chat_latest();
    }
    TABLE
        .iter()
        .filter(|row| family_matches(&id, row.family))
        .max_by_key(|row| row.family.len())
        .copied()
        .unwrap_or_else(ModelCapabilities::permissive)
}

pub fn lifecycle_on(model: &str, today: &str) -> Lifecycle {
    capabilities(model).lifecycle.as_of(today)
}

pub fn lifecycle(model: &str) -> Lifecycle {
    lifecycle_on(model, &today_utc())
}

pub fn today_utc() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    civil_from_days(secs / 86_400)
}

fn civil_from_days(days: u64) -> String {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

static WARNED: LazyLock<Mutex<HashSet<(String, String)>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

pub fn warn_param_once(model: &str, param: &str, reason: &str) -> bool {
    let first = WARNED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert((model.to_string(), param.to_string()));
    if first {
        tracing::warn!(
            model,
            param,
            "[llm] adjusted `{param}` for {model}: {reason}"
        );
    }
    first
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalization_strips_gateway_bedrock_vertex_and_date_decorations() {
        let cases = [
            ("Claude-Opus-4-7", "claude-opus-4-7"),
            ("anthropic/claude-sonnet-4-5", "claude-sonnet-4-5"),
            ("openrouter/openai/gpt-5.1", "gpt-5.1"),
            (
                "us.anthropic.claude-opus-4-1-20250805-v1:0",
                "claude-opus-4-1",
            ),
            (
                "global.anthropic.claude-sonnet-4-5-20250929-v1:0",
                "claude-sonnet-4-5",
            ),
            ("anthropic.claude-3-haiku-20240307-v1:0", "claude-3-haiku"),
            ("claude-sonnet-4-5@20250929", "claude-sonnet-4-5"),
            ("claude-opus-4-5-20251101", "claude-opus-4-5"),
            ("gpt-5-2025-08-07", "gpt-5"),
            ("gpt-4o-2024-08-06", "gpt-4o"),
            ("  gpt-4.1  ", "gpt-4.1"),
        ];
        for (raw, want) in cases {
            assert_eq!(normalize_model_id(raw), want, "{raw}");
        }
    }

    #[test]
    fn the_family_boundary_rejects_newer_minor_versions_but_accepts_snapshots() {
        assert!(family_matches("gpt-5", "gpt-5"));
        assert!(family_matches("gpt-5-mini", "gpt-5"));
        assert!(!family_matches("gpt-5.1", "gpt-5"));
        assert!(family_matches("gpt-5.x", "gpt-5"));
        assert!(!family_matches("claude-opus-4-9", "claude-opus-4"));
        assert!(!family_matches("claude-opus-4-10", "claude-opus-4"));
        assert!(family_matches("gpt-4-0613", "gpt-4"));
        assert!(family_matches("gpt-3.5-turbo-0125", "gpt-3.5"));
        assert!(!family_matches("gpt-40", "gpt-4"));
        assert!(!family_matches("gpt", "gpt-4"));
    }

    fn family(model: &str) -> &'static str {
        capabilities(model).family
    }

    #[test]
    fn lookup_takes_the_longest_matching_family() {
        let cases = [
            ("claude-fable-5-1", "claude-fable-5-1"),
            ("claude-fable-5", "claude-fable-5"),
            ("claude-opus-5-5", "claude-opus-5-5"),
            ("claude-opus-5", "claude-opus-5"),
            ("us.anthropic.claude-opus-4-7-v1:0", "claude-opus-4-7"),
            ("claude-opus-4-20250514", "claude-opus-4"),
            ("claude-3-5-sonnet-latest", "claude-3-5"),
            ("claude-3-haiku-20240307", "claude-3-haiku"),
            ("claude-3-opus-20240229", "claude-3"),
            ("claude-2.1", "claude-2.1"),
            ("gpt-5.1-codex", "gpt-5.1"),
            ("gpt-5-mini", "gpt-5"),
            ("gpt-4o-mini", "gpt-4o"),
            ("gpt-4-1106-preview", "gpt-4"),
            ("gpt-3.5-turbo", "gpt-3.5"),
            ("o3-mini", "o3-mini"),
            ("o1-preview", "o1-preview"),
            ("gpt-6-mini", "gpt-6"),
            ("gpt-5.6-luna", "gpt-5.6-luna"),
            ("gpt-5.6-mini", "gpt-5.6"),
            ("gpt-5-chat-latest", "*-chat-latest"),
        ];
        for (model, want) in cases {
            assert_eq!(family(model), want, "{model}");
        }
    }

    #[test]
    fn gpt_6_luna_takes_sampling_at_any_effort() {
        let caps = capabilities("gpt-6-luna");
        assert_eq!(caps.family, "gpt-6-luna", "has its own row");
        assert_eq!(caps.max_output_tokens, Some(128_000), "card ceiling");
        assert_eq!(
            caps.cache_min_tokens, None,
            "implicit OpenAI caching is not an Anthropic breakpoint floor"
        );
        assert!(capabilities("gpt-6-mini").sampling_allowed(Some(E::High)));
        for effort in [None, Some(E::None), Some(E::Medium), Some(E::High)] {
            assert!(caps.sampling_allowed(effort), "temperature at {effort:?}");
            assert!(caps.seed_allowed(effort), "seed at {effort:?}");
        }
    }

    #[test]
    fn an_unknown_model_is_permissive_and_never_refused() {
        for model in ["my-private-alias", "claude-opus-4-9", "gpt-5.9", "llama-4"] {
            let caps = capabilities(model);
            assert!(!caps.is_known(), "{model}");
            assert_eq!(caps, ModelCapabilities::permissive());
            assert_eq!(caps.lifecycle, Lifecycle::Current);
            assert_eq!(caps.clamp_effort(E::Max), Some(E::Max));
            assert!(caps.sampling_allowed(Some(E::High)));
            assert_eq!(caps.clamp_max_tokens(1_000_000), 1_000_000);
        }
    }

    #[test]
    fn lifecycle_is_date_adjusted() {
        assert_eq!(
            lifecycle_on("claude-opus-4-1", "2026-08-04"),
            dep("2026-08-05")
        );
        assert_eq!(
            lifecycle_on("claude-opus-4-1", "2026-08-05"),
            Lifecycle::Retired
        );
        assert_eq!(
            lifecycle_on("claude-3-haiku-20240307", "2026-09-25"),
            Lifecycle::Retired
        );
        assert_eq!(lifecycle_on("gpt-4-0613", "2026-09-25"), dep("2026-10-23"));
        assert_eq!(lifecycle_on("claude-sonnet-4", "2030-01-01"), DEPRECATED);
        assert_eq!(
            lifecycle_on("claude-3-5-sonnet", "2026-09-25"),
            Lifecycle::Retired
        );
        assert_eq!(lifecycle_on("gpt-4o", "2026-09-25"), Lifecycle::Legacy);
        assert_eq!(
            lifecycle_on("claude-opus-4-7", "2026-09-25"),
            Lifecycle::Current
        );
        assert_eq!(lifecycle("claude-3-5-sonnet"), Lifecycle::Retired);
    }

    #[test]
    fn lifecycle_labels() {
        assert_eq!(Lifecycle::Current.label(), "current");
        assert_eq!(Lifecycle::Legacy.label(), "legacy");
        assert_eq!(dep("2026-10-23").label(), "deprecated (retires 2026-10-23)");
        assert_eq!(DEPRECATED.label(), "deprecated");
        assert_eq!(Lifecycle::Retired.label(), "retired");
    }

    #[test]
    fn effort_is_clamped_per_model() {
        assert_eq!(
            capabilities("claude-opus-4-6").clamp_effort(E::XHigh),
            Some(E::High)
        );
        assert_eq!(
            capabilities("claude-sonnet-4-5").clamp_effort(E::High),
            None
        );
        assert_eq!(
            capabilities("gpt-5").clamp_effort(E::None),
            Some(E::Minimal)
        );
        assert_eq!(capabilities("gpt-5.5").clamp_effort(E::Max), Some(E::XHigh));
        assert_eq!(capabilities("o4-mini").clamp_effort(E::Max), Some(E::High));
        assert_eq!(capabilities("gpt-4o").clamp_effort(E::High), None);
    }

    #[test]
    fn sampling_follows_the_effective_effort() {
        let gpt54 = capabilities("gpt-5.4");
        assert!(gpt54.sampling_allowed(None));
        assert!(gpt54.sampling_allowed(Some(E::None)));
        assert!(!gpt54.sampling_allowed(Some(E::High)));
        assert!(!gpt54.seed_allowed(Some(E::High)));
        let gpt55 = capabilities("gpt-5.5");
        assert!(!gpt55.sampling_allowed(None));
        assert!(gpt55.sampling_allowed(Some(E::None)));
        assert!(!capabilities("o3").sampling_allowed(None));
        assert!(capabilities("gpt-4o").seed_allowed(None));
        assert!(capabilities("claude-opus-4-6").sampling_allowed(None));
        assert!(!capabilities("claude-opus-4-7").sampling_allowed(None));
        assert!(!capabilities("claude-opus-4-6").seed_allowed(None));
    }

    #[test]
    fn reasoning_families_are_recognized() {
        assert!(capabilities("gpt-5.6-luna").is_reasoning());
        assert!(capabilities("o3").is_reasoning());
        assert!(capabilities("claude-opus-4-7").is_reasoning());
        assert!(!capabilities("gpt-4o").is_reasoning());
        assert!(!capabilities("gpt-5-chat-latest").is_reasoning());
        assert!(!capabilities("unknown-alias").is_reasoning());
        assert_eq!(
            capabilities("gpt-5.6-luna").clamp_max_tokens(200_000),
            128_000
        );
    }

    #[test]
    fn max_tokens_are_clamped_to_the_published_ceiling() {
        assert_eq!(
            capabilities("claude-sonnet-4-5").clamp_max_tokens(200_000),
            64_000
        );
        assert_eq!(
            capabilities("claude-sonnet-4-5").clamp_max_tokens(1_000),
            1_000
        );
        assert_eq!(capabilities("gpt-5.1").clamp_max_tokens(200_000), 200_000);
    }

    #[test]
    fn thinking_modes_and_prefill() {
        assert_eq!(capabilities("claude-opus-4-7").thinking, Thinking::Adaptive);
        assert!(Thinking::Adaptive.is_adaptive());
        assert!(!Thinking::BudgetTokens.is_adaptive());
        assert!(!Thinking::Unknown.is_adaptive());
        assert!(!capabilities("claude-opus-4-6").assistant_prefill);
        assert!(capabilities("claude-opus-4-5").assistant_prefill);
        assert!(!capabilities("claude-fable-5-1").forced_tool_choice);
        assert_eq!(
            capabilities("claude-opus-5-5").default_effort,
            Some(E::Medium)
        );
        assert_eq!(capabilities("claude-opus-4-7").cache_min_tokens, Some(2048));
        assert_eq!(
            capabilities("gpt-5.1").token_param,
            TokenParam::MaxCompletionTokens
        );
        assert_eq!(
            capabilities("claude-opus-4-7").token_param,
            TokenParam::MaxTokens
        );
    }

    #[test]
    fn the_default_model_renders_as_the_user_guide_documents() {
        assert_eq!(
            capabilities("gpt-6-luna").render("gpt-6-luna", "2026-10-22"),
            "gpt-6-luna: family=gpt-6-luna lifecycle=current sampling=allowed \
             effort=none,low,medium,high,xhigh,max (default medium) \
             thinking=none max_output=128000 cache_min=-"
        );
    }

    #[test]
    fn rendering_names_every_field() {
        let row = capabilities("claude-opus-4-6").render("claude-opus-4-6", "2026-09-25");
        assert_eq!(
            row,
            "claude-opus-4-6: family=claude-opus-4-6 lifecycle=current \
             sampling=temperature-or-top_p effort=low,medium,high,max (default high) \
             thinking=adaptive (budget deprecated) max_output=128000 cache_min=4096"
        );
        let unknown = capabilities("alias").render("alias", "2026-09-25");
        assert!(unknown.contains("family=(unknown"), "{unknown}");
        assert!(unknown.contains("effort=any"));
        assert!(unknown.contains("max_output=-"));
        let none = capabilities("gpt-4o").render("gpt-4o", "2026-09-25");
        assert!(none.contains("effort=none thinking=none"), "{none}");
        let retired = capabilities("claude-opus-4-1").render("m", "2026-09-25");
        assert!(retired.contains("lifecycle=retired"), "{retired}");
        for t in [
            Thinking::None,
            Thinking::BudgetTokens,
            Thinking::AdaptivePreferred,
            Thinking::Adaptive,
            Thinking::AdaptiveDefaultOn,
            Thinking::AdaptiveAlwaysOn,
            Thinking::Unknown,
        ] {
            assert!(!t.label().is_empty());
        }
        for s in [
            Sampling::Allowed,
            Sampling::OnlyWhenEffortNone,
            Sampling::Rejected,
        ] {
            assert!(!s.label().is_empty());
        }
    }

    #[test]
    fn civil_dates_are_correct_across_leap_years_and_month_ends() {
        assert_eq!(civil_from_days(0), "1970-01-01");
        assert_eq!(civil_from_days(59), "1970-03-01");
        assert_eq!(civil_from_days(11_016), "2000-02-29");
        assert_eq!(civil_from_days(20_721), "2026-09-25");
        assert_eq!(civil_from_days(20_819), "2027-01-01");
        let today = today_utc();
        assert_eq!(today.len(), 10);
        assert_eq!(&today[4..5], "-");
    }

    #[test]
    fn warnings_fire_once_per_model_and_parameter() {
        assert!(warn_param_once(
            "caps-test-model",
            "temperature",
            "rejected"
        ));
        assert!(!warn_param_once(
            "caps-test-model",
            "temperature",
            "rejected"
        ));
        assert!(warn_param_once("caps-test-model", "top_p", "rejected"));
    }
}
