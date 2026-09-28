//! The pure half of a live prompt-cache diagnostic (`--doctor
//! --cache-probe`), ported from the Python original's
//! `orchestrator/preflight.py:864-1000` (`cache_probe_filler`,
//! `classify_cache_verdict` and its verdict table).
//!
//! The probe sends two calls that share a large, deterministic system
//! prompt ([`cache_probe_filler`]) but carry different user turns
//! ([`CACHE_PROBE_USER_A`], [`CACHE_PROBE_USER_B`]), so a cache hit on
//! the second can only come from the shared prefix. [`classify_cache_probe`]
//! then turns the pair's cache accounting into one verdict. Building and
//! sending the calls is I/O and belongs to `bc-cli`; nothing here touches
//! the network.

use crate::chat::Usage;

/// The estimated-token floor the filler is built past. Clears every row
/// of the Anthropic minimum table (largest 4,096) and OpenAI's 1,024.
pub const CACHE_PROBE_FILLER_MIN_TOKENS: u32 = 8192;

/// Build the filler to this multiple of the requested floor (as a
/// percentage), leaving headroom for estimation error so a filler that
/// tokenizes smaller than estimated is not misdiagnosed as "marker not
/// honored" when it is really "filler too small".
const FILLER_MARGIN_PERCENT: u64 = 125;
const FILLER_CHARS_PER_TOKEN: u64 = 4;

/// Call A's user turn: fixed, and distinct from Call B's so a hit on B can
/// only come from the shared system prefix, never an identical request.
pub const CACHE_PROBE_USER_A: &str =
    "Reply with the single word PONG. cache-probe call A deterministic marker \
     sequence diagnostic token filler padding text alpha bravo charlie delta \
     echo foxtrot golf hotel india juliet kilo lima mike november oscar";

/// Call B's user turn.
pub const CACHE_PROBE_USER_B: &str =
    "Reply with the single word PONG. cache-probe call B deterministic marker \
     sequence diagnostic token filler padding text papa quebec romeo sierra \
     tango uniform victor whiskey xray yankee zulu alpha bravo charlie";

/// Deterministic filler of at least `min_tokens` estimated tokens (built
/// to 1.25x that), for the probe's synthetic system prompt. Identical on
/// every call, with no randomness or clock, so two probe runs a week apart
/// are comparable. Line format matches the Python original's exactly.
pub fn cache_probe_filler(min_tokens: u32) -> String {
    const WORDS: &str = "alpha bravo charlie delta echo foxtrot golf hotel india juliet \
                         kilo lima mike november oscar papa quebec romeo sierra tango \
                         uniform victor whiskey xray yankee zulu";
    let target_chars = u64::from(min_tokens) * FILLER_CHARS_PER_TOKEN * FILLER_MARGIN_PERCENT / 100;
    let mut out = String::new();
    let mut i = 0u64;
    while (out.len() as u64) < target_chars {
        out.push_str(&format!("CACHE-PROBE-FILLER-LINE-{i:06} {WORDS} {i}\n"));
        i += 1;
    }
    out
}

/// Which cache-accounting shape a dialect reports, needed because
/// [`Usage`] stores an absent field as zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheDialect {
    /// The Messages API always reports both cache fields.
    Anthropic,
    /// Chat Completions / Responses always report the read subset
    /// (`cached_tokens`) but report a write only on models that bill one.
    OpenAi,
}

/// What one call's usage says about cache fields, with PRESENCE kept
/// distinct from a zero value: a route that never reports a write field
/// is a different diagnosis from one that reports writing nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheObservation {
    pub write: Option<u64>,
    pub read: Option<u64>,
}

impl CacheObservation {
    /// Recover presence from a normalized [`Usage`] as well as it can be.
    ///
    /// Anthropic reports both fields on every response, so both are
    /// present. On OpenAI a non-zero write proves the field was present,
    /// while a zero write is read as absent, which is what every current
    /// OpenAI model sends (it bills no cache write). This is the one
    /// inference the Python original warns about (`preflight.py::
    /// usage_dict_for_classifier`): a gateway that reports
    /// `cache_write_tokens: 0` explicitly is classified in the implicit
    /// family rather than the explicit one. A caller that observed the
    /// raw usage can build a [`CacheObservation`] directly instead.
    pub fn from_usage(usage: &Usage, dialect: CacheDialect) -> Self {
        match dialect {
            CacheDialect::Anthropic => CacheObservation {
                write: Some(usage.cache_creation_input_tokens),
                read: Some(usage.cache_read_input_tokens),
            },
            CacheDialect::OpenAi => CacheObservation {
                write: (usage.cache_creation_input_tokens > 0)
                    .then_some(usage.cache_creation_input_tokens),
                read: Some(usage.cache_read_input_tokens),
            },
        }
    }
}

/// One cache-probe diagnosis. [`Self::code`] strings are the Python
/// original's machine-stable verdict codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheProbeVerdict {
    /// Call A wrote, Call B read: markers are honored.
    AnthropicWorks,
    /// Call A wrote but Call B read nothing: a routing or affinity gap.
    WriteOkReadFails,
    /// Nothing written, nothing read, though the write field exists.
    MarkerNotHonored,
    /// Nothing written because the prefix was already cached, and it was
    /// read back: a working cache seen inside its lifetime.
    AlreadyWarm,
    /// No write field, but Call B read: the implicit prefix cache works.
    OpenAiImplicitWorking,
    /// No write field and no read: below the minimum, or an unstable
    /// prefix.
    BelowMinimum,
    /// Neither field present at all: caching is unmeasurable here.
    NoCacheFields,
    /// Not produced by [`classify_cache_probe`]: the caller assigns it
    /// when this tool's own gate
    /// ([`crate::CachePolicy::anthropic_marker_worth_placing`]) says no
    /// marker was ever placed, so a zero/zero result implicates the gate,
    /// not the gateway.
    MarkerWithheld,
}

impl CacheProbeVerdict {
    /// The Python original's machine-stable verdict code.
    pub fn code(self) -> &'static str {
        match self {
            CacheProbeVerdict::AnthropicWorks => "anthropic_works",
            CacheProbeVerdict::WriteOkReadFails => "anthropic_write_ok_read_fails",
            CacheProbeVerdict::MarkerNotHonored => "anthropic_marker_not_honoured",
            CacheProbeVerdict::AlreadyWarm => "anthropic_works_prefix_already_cached",
            CacheProbeVerdict::OpenAiImplicitWorking => "openai_implicit_working",
            CacheProbeVerdict::BelowMinimum => "openai_below_minimum_or_unstable",
            CacheProbeVerdict::NoCacheFields => "no_cache_fields_treat_as_implicit",
            CacheProbeVerdict::MarkerWithheld => "anthropic_marker_withheld_by_gate",
        }
    }

    /// Operator-facing explanation, ported from `_VERDICT_TEXT`.
    pub fn explanation(self) -> &'static str {
        match self {
            CacheProbeVerdict::AnthropicWorks => {
                "cache markers are honored on this route; explicit breakpoints are an \
                 optimization here, not a fix."
            }
            CacheProbeVerdict::WriteOkReadFails => {
                "writes succeed but reads do not: investigate request routing or cache-key \
                 affinity, not marker placement."
            }
            CacheProbeVerdict::MarkerNotHonored => {
                "the marker is not taking effect at all: check whether the base URL points \
                 at a gateway that strips it, whether the block is below this model's \
                 minimum cacheable size, retest with thinking disabled, and retest against \
                 the vendor endpoint directly."
            }
            CacheProbeVerdict::AlreadyWarm => {
                "caching is working; nothing new was written because this prefix was \
                 already cached from an earlier call, and it was read back. Re-run after \
                 the cache lifetime has elapsed to observe a write."
            }
            CacheProbeVerdict::OpenAiImplicitWorking => {
                "the implicit prefix cache is working normally; no explicit marker is \
                 needed or available on this route."
            }
            CacheProbeVerdict::BelowMinimum => {
                "no cache read observed: the prompt may be below this route's minimum \
                 cacheable size, or its prefix is unstable across calls; re-probe with a \
                 larger filler to tell which."
            }
            CacheProbeVerdict::NoCacheFields => {
                "this route reports no cache accounting at all: treat caching as implicit \
                 and unmeasurable here, and rely on keeping the prompt prefix stable."
            }
            CacheProbeVerdict::MarkerWithheld => {
                "this tool's own gate never placed a cache_control marker on this call \
                 (markers switched off, or the prompt is below this model's estimated \
                 minimum cacheable size), so the gateway was never asked to cache \
                 anything. Re-probe with a larger prompt, or set a lower minimum block \
                 size to change the gate's decision."
            }
        }
    }
}

/// Classify a probe pair from normalized [`Usage`] (see
/// [`CacheObservation::from_usage`] for how presence is recovered).
pub fn classify_cache_probe(
    first: &Usage,
    second: &Usage,
    dialect: CacheDialect,
) -> CacheProbeVerdict {
    classify_cache_observations(
        CacheObservation::from_usage(first, dialect),
        CacheObservation::from_usage(second, dialect),
    )
}

/// The six-way classifier, row for row `classify_cache_verdict`: field
/// presence selects the family (Call A's write field, Call B's read
/// field), values select the row.
pub fn classify_cache_observations(
    first: CacheObservation,
    second: CacheObservation,
) -> CacheProbeVerdict {
    let read = second.read.unwrap_or(0);
    match (first.write, second.read) {
        (None, None) => CacheProbeVerdict::NoCacheFields,
        (Some(write), _) => match (write > 0, read > 0) {
            (true, true) => CacheProbeVerdict::AnthropicWorks,
            (true, false) => CacheProbeVerdict::WriteOkReadFails,
            (false, true) => CacheProbeVerdict::AlreadyWarm,
            (false, false) => CacheProbeVerdict::MarkerNotHonored,
        },
        (None, Some(_)) if read > 0 => CacheProbeVerdict::OpenAiImplicitWorking,
        (None, Some(_)) => CacheProbeVerdict::BelowMinimum,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::{estimate_tokens, CachePolicy};

    fn obs(write: Option<u64>, read: Option<u64>) -> CacheObservation {
        CacheObservation { write, read }
    }

    /// Row for row against `classify_cache_verdict`.
    #[test]
    fn the_classifier_table() {
        use CacheProbeVerdict::*;
        let rows = [
            (obs(None, None), obs(None, None), NoCacheFields),
            (obs(Some(5000), None), obs(None, Some(5000)), AnthropicWorks),
            (obs(Some(5000), None), obs(None, Some(0)), WriteOkReadFails),
            // A write field with no read field at all reads as zero reads.
            (obs(Some(5000), None), obs(None, None), WriteOkReadFails),
            (obs(Some(0), None), obs(None, Some(5000)), AlreadyWarm),
            (obs(Some(0), None), obs(None, Some(0)), MarkerNotHonored),
            (
                obs(None, None),
                obs(None, Some(5000)),
                OpenAiImplicitWorking,
            ),
            (obs(None, None), obs(None, Some(0)), BelowMinimum),
        ];
        for (a, b, want) in rows {
            assert_eq!(classify_cache_observations(a, b), want, "{a:?} {b:?}");
        }
    }

    fn usage(write: u64, read: u64) -> Usage {
        Usage {
            input_tokens: 10,
            output_tokens: 1,
            cache_creation_input_tokens: write,
            cache_read_input_tokens: read,
        }
    }

    #[test]
    fn anthropic_usage_always_carries_both_fields() {
        use CacheProbeVerdict::*;
        let a = CacheDialect::Anthropic;
        assert_eq!(
            classify_cache_probe(&usage(9000, 0), &usage(0, 9000), a),
            AnthropicWorks
        );
        assert_eq!(
            classify_cache_probe(&usage(0, 0), &usage(0, 0), a),
            MarkerNotHonored
        );
    }

    #[test]
    fn openai_usage_reads_a_zero_write_as_absent() {
        use CacheProbeVerdict::*;
        let o = CacheDialect::OpenAi;
        assert_eq!(
            classify_cache_probe(&usage(0, 0), &usage(0, 8960), o),
            OpenAiImplicitWorking
        );
        assert_eq!(
            classify_cache_probe(&usage(0, 0), &usage(0, 0), o),
            BelowMinimum
        );
        // A gateway that bills writes lands in the explicit family.
        assert_eq!(
            classify_cache_probe(&usage(9000, 0), &usage(0, 9000), o),
            AnthropicWorks
        );
    }

    #[test]
    fn every_verdict_has_a_stable_code_and_an_explanation() {
        use CacheProbeVerdict::*;
        let all = [
            AnthropicWorks,
            WriteOkReadFails,
            MarkerNotHonored,
            AlreadyWarm,
            OpenAiImplicitWorking,
            BelowMinimum,
            NoCacheFields,
            MarkerWithheld,
        ];
        let codes: std::collections::HashSet<_> = all.iter().map(|v| v.code()).collect();
        assert_eq!(codes.len(), all.len(), "codes are unique");
        for v in all {
            assert!(!v.explanation().is_empty());
            assert!(!v.explanation().contains('\u{2014}'), "no em-dashes");
        }
        assert_eq!(MarkerWithheld.code(), "anthropic_marker_withheld_by_gate");
    }

    #[test]
    fn the_filler_is_deterministic_and_clears_every_gate_it_audits() {
        let a = cache_probe_filler(CACHE_PROBE_FILLER_MIN_TOKENS);
        let b = cache_probe_filler(CACHE_PROBE_FILLER_MIN_TOKENS);
        assert_eq!(a, b);
        assert!(a.starts_with("CACHE-PROBE-FILLER-LINE-000000 alpha bravo"));
        let est = estimate_tokens(&a);
        assert!(est >= u64::from(CACHE_PROBE_FILLER_MIN_TOKENS) * 125 / 100);
        // Clears the largest Anthropic minimum and the OpenAI floor.
        let p = CachePolicy::default();
        assert!(p.anthropic_marker_worth_placing("unknown-model", est));
        assert!(p.openai_cache_key_worth_sending(est));
        assert_ne!(CACHE_PROBE_USER_A, CACHE_PROBE_USER_B);
    }

    #[test]
    fn a_zero_floor_filler_is_empty() {
        assert_eq!(cache_probe_filler(0), "");
    }
}
