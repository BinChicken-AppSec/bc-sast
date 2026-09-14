//! CVSS 3.1 base + environmental score calculator (FIRST.org spec §7).
//!
//! Given a vector string like `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`,
//! [`score`] returns the 0.0-10.0 base score and [`rating`] its qualitative
//! band. [`environmental`] layers a Modified Attack Vector override plus
//! environmental requirement weights (confidentiality/integrity/
//! availability requirement — how much a specific deployment cares about
//! each) on top of the same base vector, using this project's fixed SAST
//! temporal preset (Exploit-code-maturity: Proof-of-Concept, Remediation-
//! Level: Official-fix, Report-Confidence: Confirmed — every finding here
//! already passed adversarial verification, so these three are constants,
//! not caller-supplied).

use std::sync::LazyLock;

use regex::Regex;

static VECTOR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"CVSS:3\.[01]/AV:(?P<AV>[NALP])/AC:(?P<AC>[LH])/PR:(?P<PR>[NLH])/UI:(?P<UI>[NR])/S:(?P<S>[UC])/C:(?P<C>[NLH])/I:(?P<I>[NLH])/A:(?P<A>[NLH])",
    )
    .expect("static CVSS vector pattern is valid")
});

/// The eight base metric letters parsed out of a vector string. Shared by
/// [`score`] and [`environmental`] so both build on one parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Metrics {
    pub av: char,
    pub ac: char,
    pub pr: char,
    pub ui: char,
    pub s: char,
    pub c: char,
    pub i: char,
    pub a: char,
}

/// Parse a CVSS 3.0/3.1 vector's eight base metrics. `None` if the vector
/// doesn't match the expected shape (missing metrics, unknown letters, bad
/// ordering/separators).
pub fn parse(vector: &str) -> Option<Metrics> {
    let caps = VECTOR_RE.captures(vector)?;
    let ch = |name: &str| caps.name(name).unwrap().as_str().chars().next().unwrap();
    Some(Metrics {
        av: ch("AV"),
        ac: ch("AC"),
        pr: ch("PR"),
        ui: ch("UI"),
        s: ch("S"),
        c: ch("C"),
        i: ch("I"),
        a: ch("A"),
    })
}

/// Compute the CVSS 3.1 base score from a vector string. Returns `None` if
/// the vector is absent, empty, or doesn't match the expected shape.
pub fn score(vector: Option<&str>) -> Option<f64> {
    let v = vector.filter(|s| !s.is_empty())?;
    let m = parse(v)?;

    let scope_changed = m.s == 'C';
    let c = cia_value(m.c)?;
    let i = cia_value(m.i)?;
    let a = cia_value(m.a)?;

    let iss = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a);
    let impact = if scope_changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powf(15.0)
    } else {
        6.42 * iss
    };
    if impact <= 0.0 {
        return Some(0.0);
    }

    let pr = pr_value(m.pr, scope_changed)?;
    let exploitability = 8.22 * av_value(m.av)? * ac_value(m.ac)? * pr * ui_value(m.ui)?;

    let base = if scope_changed {
        (1.08 * (impact + exploitability)).min(10.0)
    } else {
        (impact + exploitability).min(10.0)
    };
    Some(roundup1(base))
}

/// This project's fixed SAST temporal multiplier: E:P (0.94) × RL:O (0.95)
/// × RC:C (1.0).
const SAST_TEMPORAL: f64 = 0.94 * 0.95 * 1.0;

fn req_value(c: char) -> f64 {
    match c {
        'H' => 1.5,
        'L' => 0.5,
        _ => 1.0,
    }
}

/// `(full environmental vector string, 0.0-10.0 environmental score)` for
/// `base_vector` with `mav` overriding its Attack Vector (e.g. downgrading
/// `N`→`A` for an application confirmed non-externally-facing) and
/// `cr`/`ir`/`ar` — the Confidentiality/Integrity/Availability Requirement
/// weights (`'H'`/`'M'`/`'L'`; any other character behaves like the CVSS
/// spec's own "Not Defined" default of `'M'`, matching the Python
/// original's dict-`.get(..., 1.0)` fallback) — layered on top. `None` if
/// `base_vector` is absent, empty, or malformed, or `mav` isn't a valid
/// Attack Vector letter.
pub fn environmental(
    base_vector: Option<&str>,
    mav: char,
    cr: char,
    ir: char,
    ar: char,
) -> Option<(String, f64)> {
    let v = base_vector.filter(|s| !s.is_empty())?;
    let m = parse(v)?;

    let scope_changed = m.s == 'C';
    let mav_v = av_value(mav)?;
    let ac_v = ac_value(m.ac)?;
    let pr_v = pr_value(m.pr, scope_changed)?;
    let ui_v = ui_value(m.ui)?;
    let c_v = cia_value(m.c)?;
    let i_v = cia_value(m.i)?;
    let a_v = cia_value(m.a)?;
    let cr_v = req_value(cr);
    let ir_v = req_value(ir);
    let ar_v = req_value(ar);

    let vector = environmental_vector(v, mav, cr, ir, ar);

    let miss = (1.0 - (1.0 - cr_v * c_v) * (1.0 - ir_v * i_v) * (1.0 - ar_v * a_v)).min(0.915);
    let m_impact = if scope_changed {
        7.52 * (miss - 0.029) - 3.25 * (miss * 0.9731 - 0.02).powf(13.0)
    } else {
        6.42 * miss
    };
    if m_impact <= 0.0 {
        return Some((vector, 0.0));
    }

    let m_exploit = 8.22 * mav_v * ac_v * pr_v * ui_v;
    let raw = if scope_changed {
        1.08 * (m_impact + m_exploit)
    } else {
        m_impact + m_exploit
    };
    let mod_base = roundup1(raw.min(10.0));
    Some((vector, roundup1(mod_base * SAST_TEMPORAL)))
}

fn environmental_vector(base_vector: &str, mav: char, cr: char, ir: char, ar: char) -> String {
    let prefix = if base_vector.starts_with("CVSS:") {
        base_vector.to_string()
    } else {
        format!("CVSS:3.1/{base_vector}")
    };
    format!("{prefix}/E:P/RL:O/RC:C/CR:{cr}/IR:{ir}/AR:{ar}/MAV:{mav}")
}

/// Qualitative rating for a base score, per the CVSS 3.1 spec's severity
/// ranges. `None` (unparseable vector) maps to `"Unknown"`.
pub fn rating(s: Option<f64>) -> &'static str {
    let Some(s) = s else {
        return "Unknown";
    };
    if s == 0.0 {
        "None"
    } else if s < 4.0 {
        "Low"
    } else if s < 7.0 {
        "Medium"
    } else if s < 9.0 {
        "High"
    } else {
        "Critical"
    }
}

fn roundup1(x: f64) -> f64 {
    let n = (x * 100_000.0) as i64;
    if n % 10_000 == 0 {
        n as f64 / 100_000.0
    } else {
        ((n / 10_000) + 1) as f64 / 10.0
    }
}

// Each metric's letter-to-weight mapping is only ever called with a
// character the VECTOR_RE regex has already constrained to a fixed small
// alphabet (e.g. `[NALP]` for AV) — the None arm can't be reached through
// `score()`. It's still a normal, directly-testable `Option`-returning
// function rather than a `match ... => unreachable!()`, so the "invalid
// character" case is real, covered behaviour instead of untestable dead
// code (see the tests below).

fn cia_value(c: char) -> Option<f64> {
    match c {
        'H' => Some(0.56),
        'L' => Some(0.22),
        'N' => Some(0.0),
        _ => None,
    }
}

fn av_value(c: char) -> Option<f64> {
    match c {
        'N' => Some(0.85),
        'A' => Some(0.62),
        'L' => Some(0.55),
        'P' => Some(0.2),
        _ => None,
    }
}

fn ac_value(c: char) -> Option<f64> {
    match c {
        'L' => Some(0.77),
        'H' => Some(0.44),
        _ => None,
    }
}

fn pr_value(c: char, scope_changed: bool) -> Option<f64> {
    if scope_changed {
        match c {
            'N' => Some(0.85),
            'L' => Some(0.68),
            'H' => Some(0.50),
            _ => None,
        }
    } else {
        match c {
            'N' => Some(0.85),
            'L' => Some(0.62),
            'H' => Some(0.27),
            _ => None,
        }
    }
}

fn ui_value(c: char) -> Option<f64> {
    match c {
        'N' => Some(0.85),
        'R' => Some(0.62),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    // Canonical vectors + expected base score, cross-checked against the
    // FIRST.org CVSS 3.1 calculator.
    #[rstest]
    #[case("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8)]
    #[case("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0)]
    #[case("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:L", 1.6)]
    #[case("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0)]
    #[case("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8)]
    fn score_matches_known_vectors(#[case] vector: &str, #[case] expected: f64) {
        assert_eq!(score(Some(vector)), Some(expected));
    }

    #[test]
    fn score_none_for_missing_or_empty_or_malformed() {
        assert_eq!(score(None), None);
        assert_eq!(score(Some("")), None);
        assert_eq!(score(Some("not a vector")), None);
        assert_eq!(
            score(Some("CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")),
            None
        );
    }

    #[rstest]
    #[case(None, "Unknown")]
    #[case(Some(0.0), "None")]
    #[case(Some(3.9), "Low")]
    #[case(Some(4.0), "Medium")]
    #[case(Some(6.9), "Medium")]
    #[case(Some(7.0), "High")]
    #[case(Some(8.9), "High")]
    #[case(Some(9.0), "Critical")]
    #[case(Some(10.0), "Critical")]
    fn rating_bands(#[case] s: Option<f64>, #[case] expected: &str) {
        assert_eq!(rating(s), expected);
    }

    // Direct tests of the per-metric decoders' None arm — see the comment
    // above them for why this is the honest way to cover a branch that's
    // unreachable through the public `score()` API (which only ever calls
    // these with a regex-validated character).
    #[test]
    fn metric_decoders_reject_invalid_characters() {
        assert_eq!(cia_value('X'), None);
        assert_eq!(av_value('X'), None);
        assert_eq!(ac_value('X'), None);
        assert_eq!(pr_value('X', true), None);
        assert_eq!(pr_value('X', false), None);
        assert_eq!(ui_value('X'), None);
    }

    // Every valid arm's constant, transcribed 1:1 from the Python source's
    // _AV/_AC/_PR_U/_PR_C/_UI/_CIA tables. The full-vector tests above
    // already prove the end-to-end formula against known-good reference
    // scores for a handful of vectors; asserting each constant directly
    // here is the safe way to cover every remaining letter (some
    // combinations, like AV:A or a scope-changed PR:L, would require
    // hand-deriving an exotic reference score to exercise via score()
    // alone, which is error-prone to verify by hand).
    #[test]
    fn metric_decoders_valid_arms_match_reference_constants() {
        assert_eq!(cia_value('H'), Some(0.56));
        assert_eq!(cia_value('L'), Some(0.22));
        assert_eq!(cia_value('N'), Some(0.0));

        assert_eq!(av_value('N'), Some(0.85));
        assert_eq!(av_value('A'), Some(0.62));
        assert_eq!(av_value('L'), Some(0.55));
        assert_eq!(av_value('P'), Some(0.2));

        assert_eq!(ac_value('L'), Some(0.77));
        assert_eq!(ac_value('H'), Some(0.44));

        assert_eq!(pr_value('N', false), Some(0.85));
        assert_eq!(pr_value('L', false), Some(0.62));
        assert_eq!(pr_value('H', false), Some(0.27));
        assert_eq!(pr_value('N', true), Some(0.85));
        assert_eq!(pr_value('L', true), Some(0.68));
        assert_eq!(pr_value('H', true), Some(0.50));

        assert_eq!(ui_value('N'), Some(0.85));
        assert_eq!(ui_value('R'), Some(0.62));
    }

    proptest::proptest! {
        #[test]
        fn score_is_always_in_range_or_none(v in "\\PC{0,80}") {
            if let Some(s) = score(Some(&v)) {
                proptest::prop_assert!((0.0..=10.0).contains(&s));
            }
        }
    }

    #[test]
    fn parse_extracts_every_metric_letter() {
        let m = parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").unwrap();
        assert_eq!(
            m,
            Metrics {
                av: 'N',
                ac: 'L',
                pr: 'N',
                ui: 'N',
                s: 'U',
                c: 'H',
                i: 'H',
                a: 'H'
            }
        );
    }

    #[test]
    fn parse_none_for_malformed_vector() {
        assert_eq!(parse("not a vector"), None);
    }

    // Cross-checked against the Python original's `vsvs_score` directly
    // (via a throwaway `AppInfo`-alike shim invoking the real
    // `report/enrich.py` module), not hand-derived.
    #[rstest]
    #[case(
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        'A',
        'H',
        'H',
        'M',
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O/RC:C/CR:H/IR:H/AR:M/MAV:A",
        7.9
    )]
    #[case(
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        'N',
        'M',
        'M',
        'M',
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O/RC:C/CR:M/IR:M/AR:M/MAV:N",
        8.8
    )]
    #[case(
        "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:C/C:L/I:N/A:N",
        'P',
        'M',
        'M',
        'M',
        "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:C/C:L/I:N/A:N/E:P/RL:O/RC:C/CR:M/IR:M/AR:M/MAV:P",
        1.7
    )]
    fn environmental_matches_the_python_reference(
        #[case] vector: &str,
        #[case] mav: char,
        #[case] cr: char,
        #[case] ir: char,
        #[case] ar: char,
        #[case] expected_vector: &str,
        #[case] expected_score: f64,
    ) {
        let (v, s) = environmental(Some(vector), mav, cr, ir, ar).unwrap();
        assert_eq!(v, expected_vector);
        assert_eq!(s, expected_score);
    }

    #[test]
    fn environmental_zero_impact_short_circuits_before_temporal_multiplication() {
        let (v, s) = environmental(
            Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
            'N',
            'H',
            'H',
            'M',
        )
        .unwrap();
        assert_eq!(s, 0.0);
        assert!(v.ends_with("/MAV:N"));
    }

    #[test]
    fn environmental_none_for_missing_empty_or_malformed_vector() {
        assert_eq!(environmental(None, 'N', 'M', 'M', 'M'), None);
        assert_eq!(environmental(Some(""), 'N', 'M', 'M', 'M'), None);
        assert_eq!(
            environmental(Some("not a vector"), 'N', 'M', 'M', 'M'),
            None
        );
    }

    #[test]
    fn environmental_none_for_an_invalid_mav_letter() {
        assert_eq!(
            environmental(
                Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
                'Z',
                'M',
                'M',
                'M'
            ),
            None
        );
    }

    // `environmental()`'s own `parse()` gate already requires the
    // `CVSS:3.[01]/` prefix to match at all, so the "prefix missing" branch
    // below is unreachable through that public entry point — whitebox-
    // tested directly against the private helper, which stays defensive
    // for any future caller that doesn't route through `parse()` first.
    #[test]
    fn environmental_vector_prefixes_a_bare_metric_string_with_the_cvss_header() {
        let v = environmental_vector("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 'N', 'M', 'M', 'M');
        assert!(v.starts_with("CVSS:3.1/AV:N"));
    }

    #[test]
    fn req_value_maps_h_and_l_and_defaults_everything_else_to_one() {
        assert_eq!(req_value('H'), 1.5);
        assert_eq!(req_value('L'), 0.5);
        assert_eq!(req_value('M'), 1.0);
        assert_eq!(req_value('?'), 1.0);
    }

    proptest::proptest! {
        #[test]
        fn environmental_is_always_in_range_or_none(v in "\\PC{0,80}", mav in "[NALP]") {
            let mav_char = mav.chars().next().unwrap();
            if let Some((_, s)) = environmental(Some(&v), mav_char, 'H', 'H', 'M') {
                proptest::prop_assert!((0.0..=10.0).contains(&s));
            }
        }
    }
}
