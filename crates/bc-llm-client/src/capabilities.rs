//! What each model family accepts, so both dialects send only the
//! parameters a model actually supports instead of learning each
//! rejection from a 400.
//!
//! Net-new versus the Python original, which learns every rejection
//! reactively (`_NO_TEMP_MODELS`, `_NO_REASONING_EFFORT` and friends) and
//! guesses a few up front from model-name regexes. A table is used here
//! because several rejections are not cheaply learnable: Claude Opus 4.7
//! and later reject `thinking.type: "enabled"` with a message that names
//! no single parameter to drop, and GPT-5.x rejects `temperature` only
//! when reasoning is on. The reactive quirk memories in each dialect crate
//! stay in place as the backstop for anything this table gets wrong.
//!
//! **Data sources and confidence.** Researched 2026-09-25 from the
//! Anthropic model catalog, thinking/effort reference and migration
//! guide; the `openai-python` SDK's generated types; and OpenAI's
//! deprecation notices. OpenAI's own documentation was not reachable when
//! this was written, so the OpenAI per-model effort tiers and sampling
//! rules marked "inferred" below are best guesses: a wrong entry costs one
//! 400 and a learned correction, never a failed scan.
//!
//! **Unknown models are never refused.** Gateways routinely alias models
//! to custom names, so an id this table does not recognize gets
//! [`ModelCapabilities::permissive`]: every parameter the caller asked
//! for is sent, and the dialect's reactive learning handles the rest.

use std::collections::HashSet;
use std::sync::{LazyLock, Mutex};

use regex::Regex;

use crate::effort::ReasoningEffort;

/// Where a model is in its provider's support lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lifecycle {
    /// Actively supported.
    Current,
    /// Superseded, with no shutdown announced. Worth a warning.
    Legacy,
    /// A shutdown is announced (`retires`, an ISO `YYYY-MM-DD` date, when
    /// the provider published one). Worth a warning until the date, and
    /// [`Lifecycle::Retired`] after it (see [`lifecycle_on`]).
    Deprecated { retires: Option<&'static str> },
    /// No longer served. A scan against it cannot succeed.
    Retired,
}

impl Lifecycle {
    /// This lifecycle as of `today` (ISO `YYYY-MM-DD`): a deprecation
    /// whose retirement date has arrived is [`Lifecycle::Retired`]. ISO
    /// dates compare correctly as strings, so no date type is needed.
    pub fn as_of(self, today: &str) -> Lifecycle {
        match self {
            Lifecycle::Deprecated {
                retires: Some(date),
            } if date <= today => Lifecycle::Retired,
            other => other,
        }
    }

    /// A short human label, for `--doctor` and warnings.
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

/// Which sampling parameters (`temperature`, `top_p`; and, on OpenAI,
/// `seed`) a model accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sampling {
    Allowed,
    /// Either may be sent, never both (Claude 4.x: "`temperature` and
    /// `top_p` cannot both be specified").
    OneOfTemperatureOrTopP,
    /// Accepted only when the request's effective reasoning effort is
    /// `none` (GPT-5.1 and later: "Unsupported parameter: 'temperature'"
    /// otherwise). "Effective" means the requested tier, or the model's
    /// default tier when none was requested.
    OnlyWhenEffortNone,
    /// Rejected outright.
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

/// How an Anthropic model's extended thinking is requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Thinking {
    /// No extended thinking (every OpenAI model: reasoning there is
    /// controlled by effort alone).
    None,
    /// `thinking: {"type": "enabled", "budget_tokens": N}` only.
    BudgetTokens,
    /// `{"type": "adaptive"}` recommended; the budget form is deprecated
    /// but still accepted (Opus 4.6, Sonnet 4.6).
    AdaptivePreferred,
    /// `{"type": "adaptive"}` only; the budget form is a 400, and
    /// omitting `thinking` means no thinking (Opus 4.7, 4.8).
    Adaptive,
    /// `{"type": "adaptive"}` only, and ON by default when omitted
    /// (Opus 5, Sonnet 5).
    AdaptiveDefaultOn,
    /// Always on: `thinking` may be omitted or adaptive, and disabling it
    /// or sending a budget is a 400 (Fable 5.x, Mythos 5.x, Opus 5.5).
    AdaptiveAlwaysOn,
    /// Not in the table: the caller's request is sent as asked.
    Unknown,
}

impl Thinking {
    /// Whether this model takes the adaptive form at all.
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

/// Which Chat Completions output-budget parameter a model takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenParam {
    MaxTokens,
    MaxCompletionTokens,
}

/// Which provider publishes a family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    Anthropic,
    OpenAi,
    Unknown,
}

/// One model family's capability row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModelCapabilities {
    /// The table prefix that matched, or `""` for an unknown model.
    pub family: &'static str,
    pub provider: Provider,
    /// As published; see [`lifecycle_on`] for the date-adjusted value.
    pub lifecycle: Lifecycle,
    pub sampling: Sampling,
    /// OpenAI `seed`, which follows the same rules as sampling on
    /// reasoning models. Irrelevant on Anthropic (never sent).
    pub seed: Sampling,
    /// Supported effort tiers. `None` means unknown (send whatever was
    /// asked); `Some(&[])` means the model takes no effort parameter.
    pub effort_levels: Option<&'static [ReasoningEffort]>,
    /// The tier the provider applies when none is sent.
    pub default_effort: Option<ReasoningEffort>,
    pub thinking: Thinking,
    /// The model's output-token ceiling, when published.
    pub max_output_tokens: Option<u32>,
    /// Anthropic minimum cacheable prefix, in real tokens.
    pub cache_min_tokens: Option<u32>,
    /// Whether `tool_choice` may force a specific tool.
    pub forced_tool_choice: bool,
    /// Whether a trailing assistant message (prefill) is accepted.
    pub assistant_prefill: bool,
    pub token_param: TokenParam,
}

impl ModelCapabilities {
    /// The row for a model this table does not know: send everything the
    /// caller asked for, and let reactive learning handle rejections.
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

    /// Whether the table recognized the model.
    pub fn is_known(&self) -> bool {
        !self.family.is_empty()
    }

    /// Whether this is a known reasoning model (it takes an effort
    /// parameter). `false` for an unknown model.
    pub fn is_reasoning(&self) -> bool {
        self.effort_levels.is_some_and(|levels| !levels.is_empty())
    }

    /// `requested` clamped onto this model's tiers (see
    /// [`ReasoningEffort::clamp_to`]); passed through unchanged for an
    /// unknown model, and `None` when the model takes no effort at all.
    pub fn clamp_effort(&self, requested: ReasoningEffort) -> Option<ReasoningEffort> {
        match self.effort_levels {
            None => Some(requested),
            Some(levels) => requested.clamp_to(levels),
        }
    }

    /// Whether `temperature`/`top_p` may be sent alongside the (already
    /// clamped) effort this request will carry.
    pub fn sampling_allowed(&self, sent_effort: Option<ReasoningEffort>) -> bool {
        self.rule_allows(self.sampling, sent_effort)
    }

    /// Whether `seed` may be sent alongside `sent_effort`.
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

    /// `max_tokens` capped at the model's published output ceiling.
    pub fn clamp_max_tokens(&self, max_tokens: u32) -> u32 {
        self.max_output_tokens
            .map_or(max_tokens, |cap| max_tokens.min(cap))
    }

    /// One line describing this row, for `--doctor`.
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
// OpenAI tiers. Inferred where OpenAI's docs were unreachable (see the
// module doc); every one is backed by the dialect's reactive learning.
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
    // Assistant prefill is rejected from the 4.6 generation on, which is
    // exactly the adaptive-thinking generation.
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

/// The family table. Lookup is by longest matching prefix of the
/// normalized id (see [`family_matches`] for the boundary rule). Kept one
/// row per line, as a table, so a reviewer can scan a column.
///
/// Built at first use rather than as a `const` array so the row
/// constructors run (and are measured) like any other code.
#[rustfmt::skip]
static TABLE: LazyLock<Vec<ModelCapabilities>> = LazyLock::new(|| vec![
    // ---- Anthropic -----------------------------------------------------
    //     family                lifecycle            sampling  thinking                     effort           default         max_out  cache  forced tool_choice
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
    // ---- OpenAI --------------------------------------------------------
    // Per-model effort tiers and sampling rules below are partly INFERRED
    // (OpenAI's docs were unreachable when researched; see the module
    // doc) and backed by `bc_llm_openai::quirks`' reactive learning.
    // gpt-6 / gpt-5.6: the `max` tier is assumed supported.
    //  family         lifecycle          sampling            effort     default
    gpt("gpt-6",       Current,           OnlyWhenEffortNone, GPT_56,    Some(E::Medium)),
    gpt("gpt-5.6",     Current,           OnlyWhenEffortNone, GPT_56,    Some(E::Medium)),
    // The CLI default. Output ceiling confirmed by the operator (128K
    // output, 1.1M context).
    {
        let mut row = gpt("gpt-5.6-luna", Current, OnlyWhenEffortNone, GPT_56, Some(E::Medium));
        row.max_output_tokens = Some(128_000);
        row
    },
    gpt("gpt-5.5",     Current,           OnlyWhenEffortNone, GPT_52_55, Some(E::Medium)),
    gpt("gpt-5.4",     Current,           OnlyWhenEffortNone, GPT_52_55, Some(E::None)),
    // gpt-5.3 / gpt-5.2: `xhigh` inferred.
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
    // Original GPT-4 (every snapshot, turbo and previews included) and
    // GPT-3.5: shutdown announced for 2026-10-23.
    gpt("gpt-4",       dep("2026-10-23"), Allowed,            NO_EFFORT, None),
    gpt("gpt-3.5",     dep("2026-10-23"), Allowed,            NO_EFFORT, None),
]);

/// Any `*-chat-latest` alias: a non-reasoning chat snapshot that accepts
/// sampling, whatever generation it fronts.
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

/// Reduce a configured model id to the bare family-plus-version form the
/// table is keyed on: lower-cased; any gateway path prefix
/// (`openrouter/anthropic/...`) dropped; a Bedrock region and vendor prefix
/// (`us.anthropic.`), Bedrock version suffix (`-v1:0`), Vertex snapshot
/// (`@20250929`) and trailing date (`-20250929`, `-2025-08-07`) removed.
pub fn normalize_model_id(model: &str) -> String {
    let lower = model.trim().to_ascii_lowercase();
    let tail = lower.rsplit('/').next().unwrap_or_default();
    let no_vertex = tail.split('@').next().unwrap_or_default();
    let no_vendor = PROVIDER_PREFIX_RX.replace(no_vertex, "");
    let no_version = BEDROCK_VERSION_RX.replace(&no_vendor, "");
    DATE_SUFFIX_RX.replace(&no_version, "").into_owned()
}

/// Whether `family` is a prefix of `id` at a family boundary. A prefix
/// followed by what reads as a NEWER minor version is not a match:
/// `gpt-5` must not claim `gpt-5.1`, nor `claude-opus-4` claim
/// `claude-opus-4-9`. A `.` plus digit, or a `-` plus one or two digits
/// ending the segment, is such a version; a longer digit run
/// (`gpt-4-0613`, `gpt-3.5-turbo-0125`) is a snapshot of the same family.
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

/// The capability row for `model`, by longest matching family prefix of
/// its normalized id, else [`ModelCapabilities::permissive`].
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

/// `model`'s lifecycle as of `today` (ISO `YYYY-MM-DD`).
pub fn lifecycle_on(model: &str, today: &str) -> Lifecycle {
    capabilities(model).lifecycle.as_of(today)
}

/// `model`'s lifecycle as of today's UTC date, for the startup model gate
/// (refuse [`Lifecycle::Retired`], warn on the rest).
pub fn lifecycle(model: &str) -> Lifecycle {
    lifecycle_on(model, &today_utc())
}

/// Today's UTC date as ISO `YYYY-MM-DD`, from the system clock.
pub fn today_utc() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    civil_from_days(secs / 86_400)
}

/// Days since 1970-01-01 to an ISO date: Howard Hinnant's
/// `civil_from_days`, specialized to non-negative day counts.
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

/// Log, once per process per `(model, param)`, that a request builder
/// changed or dropped `param` for `model` and why. Returns whether this
/// call was the first (and so actually logged).
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
        // The clock-driven form agrees with some date on or after the
        // table was written.
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
        // Opus 4.6 has no xhigh.
        assert_eq!(
            capabilities("claude-opus-4-6").clamp_effort(E::XHigh),
            Some(E::High)
        );
        // Sonnet 4.5 takes no effort parameter.
        assert_eq!(
            capabilities("claude-sonnet-4-5").clamp_effort(E::High),
            None
        );
        // GPT-5 has minimal, not none.
        assert_eq!(
            capabilities("gpt-5").clamp_effort(E::None),
            Some(E::Minimal)
        );
        // GPT-5.5 tops out at xhigh.
        assert_eq!(capabilities("gpt-5.5").clamp_effort(E::Max), Some(E::XHigh));
        // o-series: low..high.
        assert_eq!(capabilities("o4-mini").clamp_effort(E::Max), Some(E::High));
        assert_eq!(capabilities("gpt-4o").clamp_effort(E::High), None);
    }

    #[test]
    fn sampling_follows_the_effective_effort() {
        let gpt54 = capabilities("gpt-5.4");
        // Default effort none: sampling allowed when effort is omitted.
        assert!(gpt54.sampling_allowed(None));
        assert!(gpt54.sampling_allowed(Some(E::None)));
        assert!(!gpt54.sampling_allowed(Some(E::High)));
        assert!(!gpt54.seed_allowed(Some(E::High)));
        let gpt55 = capabilities("gpt-5.5");
        // Default effort medium: omitted effort still means reasoning on.
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
