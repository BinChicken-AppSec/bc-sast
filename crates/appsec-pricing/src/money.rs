//! Exact money amounts, held as integers rather than floats.
//!
//! A scan's cost is a few hundred rate multiplications, each one a
//! published rate with up to six decimal places times a token count in
//! the millions, and the answer is reported to the cent. `f64` gets that
//! wrong in two ways at once. Neither `0.1` nor a rate such as `0.15`
//! dollars per million tokens is representable in binary floating point,
//! so every individual product starts out slightly off, and summing a few
//! hundred of them accumulates the error in a way that depends on the
//! order the stages happened to finish in. A cost report that changes in
//! its last digit when two stages swap places is not a cost report anyone
//! can reconcile against an invoice.
//!
//! So this crate never multiplies floats. Rates are stored as integer
//! picodollars per token, token counts are integers, and their product is
//! an exact integer count of picodollars. There is no division anywhere on
//! the pricing path, so there is nothing to round until a human wants to
//! read the number, and [`Money::to_usd_string`] does that rounding once,
//! exactly, at the point of display.
//!
//! A picodollar is 1e-12 US dollars. That is not an arbitrary choice: the
//! upstream catalog quotes dollars per million tokens, so scaling a rate
//! by 10^6 to clear its decimals leaves a value that reads directly as
//! picodollars per token, and `rate * tokens` is then already in
//! picodollars with no scaling step to get wrong.
//!
//! `u128` holds the result. The most expensive rate in the captured
//! catalog is 600 dollars per million tokens, or 6e8 picodollars per
//! token, so a single call would need on the order of 1e29 tokens to
//! overflow. Costs are never negative, and there is no subtraction, so an
//! unsigned type also makes an impossible state unrepresentable.

use std::fmt;
use std::iter::Sum;
use std::ops::{Add, AddAssign};

/// Picodollars in one US dollar.
const PICODOLLARS_PER_DOLLAR: u128 = 1_000_000_000_000;

/// Decimal places a picodollar amount can express exactly.
const MAX_DECIMALS: u32 = 12;

/// An exact, non-negative US dollar amount, counted in picodollars.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Money(u128);

impl Money {
    /// Zero dollars.
    pub const ZERO: Self = Self(0);

    /// Wrap a raw picodollar count.
    pub const fn from_picodollars(picodollars: u128) -> Self {
        Self(picodollars)
    }

    /// The raw picodollar count. This is the exact value; every other
    /// accessor is a lossy rendering of it.
    pub const fn picodollars(self) -> u128 {
        self.0
    }

    /// The amount as a float, for callers that have to hand a number to a
    /// JSON field or a formatter. Lossy by definition, and never used to
    /// compute anything inside this crate.
    pub fn dollars_f64(self) -> f64 {
        self.0 as f64 / PICODOLLARS_PER_DOLLAR as f64
    }

    /// Render as a plain decimal dollar amount with `decimals` places,
    /// rounding half up, using integer arithmetic only.
    ///
    /// `decimals` above 12 is clamped to 12, the most a picodollar count
    /// can express, rather than inventing digits.
    pub fn to_usd_string(self, decimals: u32) -> String {
        let decimals = decimals.min(MAX_DECIMALS);
        let divisor = 10u128.pow(MAX_DECIMALS - decimals);
        let mut scaled = self.0 / divisor;
        if (self.0 % divisor) * 2 >= divisor {
            scaled += 1;
        }
        let unit = 10u128.pow(decimals);
        let whole = scaled / unit;
        if decimals == 0 {
            return whole.to_string();
        }
        let fraction = scaled % unit;
        let width = decimals as usize;
        format!("{whole}.{fraction:0width$}")
    }
}

/// Six decimal places, which is enough to show a single cheap call
/// without collapsing it to zero and few enough to stay readable.
impl fmt::Display for Money {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_usd_string(6))
    }
}

impl Add for Money {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self(self.0 + rhs.0)
    }
}

impl AddAssign for Money {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
    }
}

impl Sum for Money {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::ZERO, Add::add)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picodollars_round_trip_exactly() {
        let money = Money::from_picodollars(3_000_000_000_123);
        assert_eq!(money.picodollars(), 3_000_000_000_123);
        assert_eq!(Money::ZERO.picodollars(), 0);
        assert_eq!(Money::default(), Money::ZERO);
    }

    #[test]
    fn dollars_f64_is_the_lossy_escape_hatch() {
        let two_dollars_fifty = Money::from_picodollars(2_500_000_000_000);
        assert!((two_dollars_fifty.dollars_f64() - 2.5).abs() < 1e-12);
    }

    #[test]
    fn to_usd_string_rounds_half_up_at_every_width() {
        // 0.0000005 dollars, chosen to sit exactly on the half at six
        // decimal places so the half-up rule is what decides the digit.
        let half = Money::from_picodollars(500_000);
        assert_eq!(half.to_usd_string(6), "0.000001");
        assert_eq!(half.to_usd_string(7), "0.0000005");

        // Half a dollar, on the half at zero decimal places.
        let fifty_cents = Money::from_picodollars(500_000_000_000);
        assert_eq!(fifty_cents.to_usd_string(0), "1");
        assert_eq!(fifty_cents.to_usd_string(2), "0.50");

        // Just below the half stays down.
        let just_under = Money::from_picodollars(499_999_999_999);
        assert_eq!(just_under.to_usd_string(0), "0");

        // Full precision, and a request for more precision than a
        // picodollar count can carry, which clamps rather than padding.
        let awkward = Money::from_picodollars(1_234_567_890_123);
        assert_eq!(awkward.to_usd_string(12), "1.234567890123");
        assert_eq!(awkward.to_usd_string(30), "1.234567890123");
        assert_eq!(awkward.to_usd_string(4), "1.2346");
    }

    #[test]
    fn display_uses_six_decimal_places() {
        let money = Money::from_picodollars(12_345_600_000);
        assert_eq!(money.to_string(), "0.012346");
        assert_eq!(format!("{money}"), "0.012346");
    }

    #[test]
    fn addition_is_exact_and_order_independent() {
        // Three rates that are all unrepresentable in binary floating
        // point. Summed as f64 in the two orders below they disagree; as
        // picodollars they cannot.
        let a = Money::from_picodollars(100_000_000_000);
        let b = Money::from_picodollars(200_000_000_000);
        let c = Money::from_picodollars(300_000_000_000);

        let forward: Money = [a, b, c].into_iter().sum();
        let backward: Money = [c, b, a].into_iter().sum();
        assert_eq!(forward, backward);
        assert_eq!(forward, Money::from_picodollars(600_000_000_000));
        assert_eq!(a + b, Money::from_picodollars(300_000_000_000));

        let mut running = Money::ZERO;
        running += a;
        running += b;
        assert_eq!(running, Money::from_picodollars(300_000_000_000));
    }

    #[test]
    fn ordering_and_debug_are_available_for_reports() {
        let small = Money::from_picodollars(1);
        let large = Money::from_picodollars(2);
        assert!(small < large);
        assert_eq!(small.cmp(&large), std::cmp::Ordering::Less);
        assert_eq!(small.partial_cmp(&large), Some(std::cmp::Ordering::Less));
        assert_ne!(small, large);
        assert_eq!(small, Clone::clone(&small));
        assert!(format!("{small:?}").contains('1'));
    }
}
