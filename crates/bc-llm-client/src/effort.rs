//! [`ReasoningEffort`]: the dialect-neutral reasoning-effort tier a model
//! role can ask for, ported from the Python original's `EffortLevel`
//! (`backends/harness/models.py`) and its OpenAI mapping
//! (`backends/harness/deepagents/options/model_building.py::
//! _OPENAI_EFFORT_MAP`), which maps each tier one to one onto the
//! provider's own literal.
//!
//! Net-new versus Python: [`ReasoningEffort::None`] and
//! [`ReasoningEffort::Minimal`], which OpenAI's API accepts (GPT-5.1 and
//! later take `none`; the original GPT-5 takes `minimal`) but the Python
//! vocabulary predates. Neither exists on Anthropic, whose dialect maps
//! them to "no thinking" or clamps them up (see `crate::capabilities`).

use std::fmt;
use std::str::FromStr;

/// How hard a reasoning-class model should think before answering.
/// Declared in increasing order, so `Ord` is "more effort", which is what
/// clamping to the nearest supported tier relies on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ReasoningEffort {
    None,
    Minimal,
    Low,
    Medium,
    High,
    XHigh,
    Max,
}

impl ReasoningEffort {
    /// Every tier, lowest first.
    pub const ALL: [ReasoningEffort; 7] = [
        ReasoningEffort::None,
        ReasoningEffort::Minimal,
        ReasoningEffort::Low,
        ReasoningEffort::Medium,
        ReasoningEffort::High,
        ReasoningEffort::XHigh,
        ReasoningEffort::Max,
    ];

    /// The wire literal, identical to the config spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            ReasoningEffort::None => "none",
            ReasoningEffort::Minimal => "minimal",
            ReasoningEffort::Low => "low",
            ReasoningEffort::Medium => "medium",
            ReasoningEffort::High => "high",
            ReasoningEffort::XHigh => "xhigh",
            ReasoningEffort::Max => "max",
        }
    }

    /// Clamp `self` onto `supported` (any order): the highest supported
    /// tier at or below the request, else the lowest supported tier.
    /// `None` when `supported` is empty (the model takes no effort
    /// parameter at all).
    pub fn clamp_to(self, supported: &[ReasoningEffort]) -> Option<ReasoningEffort> {
        supported
            .iter()
            .copied()
            .filter(|s| *s <= self)
            .max()
            .or_else(|| supported.iter().copied().min())
    }
}

impl fmt::Display for ReasoningEffort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Parses the config spelling (`none`, `minimal`, `low`, `medium`,
/// `high`, `xhigh`, `max`), ignoring case and surrounding whitespace.
///
/// **Divergence from Python, deliberate**: `EffortLevel.parse` returns
/// `None` for an unknown value, which silently runs the role at the
/// provider's default effort. This returns an error instead so a config
/// typo (`effort: hihg`) fails the run at load time rather than quietly
/// costing a scan its reasoning.
impl FromStr for ReasoningEffort {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let wanted = s.trim().to_ascii_lowercase();
        ReasoningEffort::ALL
            .into_iter()
            .find(|e| e.as_str() == wanted)
            .ok_or_else(|| {
                format!(
                    "unknown reasoning effort {wanted:?} (expected none, minimal, low, medium, \
                     high, xhigh or max)"
                )
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ReasoningEffort::*;

    #[test]
    fn every_tier_round_trips_through_its_wire_literal() {
        for effort in ReasoningEffort::ALL {
            assert_eq!(effort.as_str().parse::<ReasoningEffort>(), Ok(effort));
            assert_eq!(effort.to_string(), effort.as_str());
        }
    }

    #[test]
    fn parsing_ignores_case_and_whitespace() {
        assert_eq!(" XHigh ".parse(), Ok(XHigh));
    }

    #[test]
    fn an_unknown_value_is_an_error_not_a_silent_default() {
        let err = "hihg".parse::<ReasoningEffort>().unwrap_err();
        assert!(err.contains("\"hihg\""), "{err}");
    }

    #[test]
    fn tiers_are_ordered_by_effort() {
        assert!(None < Minimal && Minimal < Low && Low < Medium);
        assert!(Medium < High && High < XHigh && XHigh < Max);
    }

    #[test]
    fn clamping_takes_the_nearest_supported_tier_at_or_below() {
        let no_xhigh = [Low, Medium, High, Max];
        assert_eq!(XHigh.clamp_to(&no_xhigh), Some(High));
        assert_eq!(Max.clamp_to(&no_xhigh), Some(Max));
        assert_eq!(Medium.clamp_to(&no_xhigh), Some(Medium));
        // Nothing at or below: the lowest supported tier.
        assert_eq!(None.clamp_to(&no_xhigh), Some(Low));
        assert_eq!(None.clamp_to(&[Minimal, Low]), Some(Minimal));
        // No effort parameter at all.
        assert_eq!(High.clamp_to(&[]), Option::None);
    }
}
