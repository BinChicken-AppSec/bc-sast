use std::fmt;
use std::str::FromStr;

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
    pub const ALL: [ReasoningEffort; 7] = [
        ReasoningEffort::None,
        ReasoningEffort::Minimal,
        ReasoningEffort::Low,
        ReasoningEffort::Medium,
        ReasoningEffort::High,
        ReasoningEffort::XHigh,
        ReasoningEffort::Max,
    ];

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
        assert_eq!(None.clamp_to(&no_xhigh), Some(Low));
        assert_eq!(None.clamp_to(&[Minimal, Low]), Some(Minimal));
        assert_eq!(High.clamp_to(&[]), Option::None);
    }
}
