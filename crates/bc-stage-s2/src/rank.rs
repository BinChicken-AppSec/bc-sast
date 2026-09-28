//! Deterministic threat-model capping, ported from upstream v1.4.0
//! `s2_threatmodel.py::_rank_key`/`_cap_threats`/`_cap_assets`/
//! `_cap_boundaries`. Replaces the previous positional truncation, which
//! kept whatever the model happened to emit first.

use std::collections::{BTreeSet, HashSet};

use bc_model::{Actor, Impact, Likelihood, Sensitivity, Threat, ThreatModel, TrustBoundary};

/// What [`cap_threats`] did, for diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CapStats {
    /// Threats the model emitted.
    pub raw: usize,
    /// Threats past `max_threats` that did not survive.
    pub truncated: usize,
    /// Dropped threats promoted back because they were the only cover of
    /// a trust boundary.
    pub promoted: usize,
}

fn impact_rank(i: Impact) -> i64 {
    match i {
        Impact::Existential => 5,
        Impact::Critical => 4,
        Impact::High => 3,
        Impact::Medium => 2,
        Impact::Low => 1,
    }
}

fn likelihood_rank(l: Likelihood) -> i64 {
    match l {
        Likelihood::AlmostCertain => 5,
        Likelihood::Likely => 4,
        Likelihood::Possible => 3,
        Likelihood::Rare => 2,
        Likelihood::VeryRare => 1,
    }
}

fn sensitivity_rank(s: Sensitivity) -> i64 {
    match s {
        Sensitivity::Critical => 4,
        Sensitivity::High => 3,
        Sensitivity::Medium => 2,
        Sensitivity::Low => 1,
    }
}

fn actor_rank(a: Actor) -> i64 {
    match a {
        Actor::RemoteUnauth => 6,
        Actor::RemoteAuth => 5,
        Actor::AdjacentNetwork => 4,
        Actor::LocalAdmin => 3,
        Actor::LocalUser => 2,
        Actor::SupplyChain | Actor::Insider => 1,
    }
}

fn sensitivity_of(t: &Threat, tm: &ThreatModel) -> i64 {
    let key = t.asset.trim().to_lowercase();
    tm.assets
        .iter()
        .find(|a| a.name.trim().to_lowercase() == key)
        .map_or(0, |a| sensitivity_rank(a.sensitivity))
}

/// Numeric part of an id like `T7`, for a stable tiebreak; an id that is
/// not `<letter><number>` sorts after every one that is.
fn id_ordinal(id: &str) -> i64 {
    id.chars()
        .skip(1)
        .collect::<String>()
        .trim()
        .parse()
        .unwrap_or(1_000_000)
}

/// Total order, most severe first: impact, then the sensitivity of the
/// asset it threatens (the one part of PASTA worth adopting: business
/// impact at zero prompt cost), likelihood, actor reach, threats with no
/// stated control ahead of mitigated ones, then the id. Evidence is
/// deliberately not a term: baseline dispositions carry evidence too.
fn rank_key(t: &Threat, tm: &ThreatModel) -> (i64, i64, i64, i64, u8, i64, String) {
    let uncontrolled = t.controls.is_empty() || t.controls == "none";
    (
        -impact_rank(t.impact),
        -sensitivity_of(t, tm),
        -likelihood_rank(t.likelihood),
        -actor_rank(t.actor),
        u8::from(!uncontrolled),
        id_ordinal(&t.id),
        t.id.clone(),
    )
}

fn norm(s: &str) -> String {
    s.trim().to_lowercase()
}

/// Which boundaries (by raw `entry_point`) at least one threat in `pool`
/// covers. `pool` holds positions, never ids: a model can emit several
/// threats sharing one id, and keying on id would merge them.
fn covered(
    surfaces: &[String],
    pool: &BTreeSet<usize>,
    boundaries: &[TrustBoundary],
) -> HashSet<String> {
    let pool_surfaces: HashSet<&str> = pool.iter().map(|&i| surfaces[i].as_str()).collect();
    boundaries
        .iter()
        .filter(|b| pool_surfaces.contains(norm(&b.entry_point).as_str()))
        .map(|b| b.entry_point.clone())
        .collect()
}

/// Sort threats deterministically (permuting only: ids are never
/// rewritten), then keep `max_threats` while preserving every trust
/// boundary's sole cover: if truncation would drop the only threat
/// covering a boundary, the best-ranked dropped threat that covers it is
/// promoted back, evicting the lowest-ranked kept threat whose removal
/// uncovers nothing. No deduplication: measured upstream, it never merged
/// a real near-duplicate and did erase per-category coverage.
///
/// **Divergence from upstream**: uncovered boundaries are visited in
/// sorted order. Upstream iterates a Python `set`, whose order depends on
/// the per-process string hash seed, so which boundary claimed an eviction
/// slot first could differ between two runs on identical input.
pub fn cap_threats(tm: &mut ThreatModel, max_threats: usize) -> CapStats {
    let mut threats = std::mem::take(&mut tm.threats);
    threats.sort_by_cached_key(|t| rank_key(t, tm));
    let mut stats = CapStats {
        raw: threats.len(),
        ..CapStats::default()
    };
    if threats.len() <= max_threats {
        tm.threats = threats;
        return stats;
    }

    let surfaces: Vec<String> = threats.iter().map(|t| norm(&t.surface)).collect();
    let mut kept: BTreeSet<usize> = (0..max_threats).collect();
    let evicted: Vec<usize> = (max_threats..threats.len()).collect();
    stats.truncated = evicted.len();
    let mut kept_order: Vec<usize> = kept.iter().copied().collect();
    let all: BTreeSet<String> = tm
        .trust_boundaries
        .iter()
        .map(|b| b.entry_point.clone())
        .collect();
    let now = covered(&surfaces, &kept, &tm.trust_boundaries);
    let mut uncovered: BTreeSet<String> = all.into_iter().filter(|b| !now.contains(b)).collect();

    let mut progressed = true;
    while !uncovered.is_empty() && progressed {
        progressed = false;
        for boundary in uncovered.clone() {
            let bnorm = norm(&boundary);
            let Some(candidate) = evicted
                .iter()
                .copied()
                .find(|i| !kept.contains(i) && surfaces[*i] == bnorm)
            else {
                continue;
            };
            let current = covered(&surfaces, &kept, &tm.trust_boundaries).len();
            let evict_at = kept_order.iter().rev().copied().find(|&i| {
                let mut trial = kept.clone();
                trial.remove(&i);
                covered(&surfaces, &trial, &tm.trust_boundaries).len() >= current
            });
            // Every survivor is some boundary's sole cover: cannot evict.
            let Some(evict_at) = evict_at else {
                continue;
            };
            kept.remove(&evict_at);
            kept_order.retain(|&i| i != evict_at);
            kept.insert(candidate);
            kept_order.push(candidate);
            stats.promoted += 1;
            uncovered.remove(&boundary);
            progressed = true;
        }
    }

    tm.threats = threats
        .into_iter()
        .enumerate()
        .filter(|(i, _)| kept.contains(i))
        .map(|(_, t)| t)
        .collect();
    stats
}

/// Keep the `max_assets` most sensitive assets (name as the tiebreak).
pub fn cap_assets(tm: &mut ThreatModel, max_assets: usize) {
    if tm.assets.len() <= max_assets {
        return;
    }
    tm.assets
        .sort_by_cached_key(|a| (-sensitivity_rank(a.sensitivity), a.name.clone()));
    tm.assets.truncate(max_assets);
}

/// Keep the `max_boundaries` boundaries reaching the most assets
/// (entry point as the tiebreak).
pub fn cap_boundaries(tm: &mut ThreatModel, max_boundaries: usize) {
    if tm.trust_boundaries.len() <= max_boundaries {
        return;
    }
    tm.trust_boundaries.sort_by_cached_key(|b| {
        (
            std::cmp::Reverse(b.reachable_assets.len()),
            b.entry_point.clone(),
        )
    });
    tm.trust_boundaries.truncate(max_boundaries);
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_model::Asset;

    fn threat(id: &str, surface: &str, impact: Impact, likelihood: Likelihood) -> Threat {
        Threat {
            id: id.to_string(),
            threat: "t".to_string(),
            actor: Actor::RemoteUnauth,
            surface: surface.to_string(),
            asset: "db".to_string(),
            impact,
            likelihood,
            controls: "none".to_string(),
            evidence: String::new(),
        }
    }

    fn boundary(ep: &str, reach: usize) -> TrustBoundary {
        TrustBoundary {
            entry_point: ep.to_string(),
            crossing: "x".to_string(),
            reachable_assets: (0..reach).map(|i| format!("a{i}")).collect(),
        }
    }

    fn asset(name: &str, s: Sensitivity) -> Asset {
        Asset {
            name: name.to_string(),
            description: String::new(),
            sensitivity: s,
        }
    }

    fn ids(tm: &ThreatModel) -> Vec<&str> {
        tm.threats.iter().map(|t| t.id.as_str()).collect()
    }

    #[test]
    fn threats_are_ranked_by_impact_sensitivity_likelihood_actor_and_controls() {
        let mut low = threat("T1", "s", Impact::Low, Likelihood::AlmostCertain);
        low.asset = "logs".into();
        let high_rare = threat("T2", "s", Impact::High, Likelihood::Rare);
        let high_likely = threat("T3", "s", Impact::High, Likelihood::Likely);
        let mut high_likely_ctl = threat("T4", "s", Impact::High, Likelihood::Likely);
        high_likely_ctl.controls = "WAF".into();
        let mut high_likely_local = threat("T5", "s", Impact::High, Likelihood::Likely);
        high_likely_local.actor = Actor::LocalUser;
        let mut on_secret = threat("T6", "s", Impact::High, Likelihood::VeryRare);
        on_secret.asset = " Secrets ".into();
        let mut tm = ThreatModel {
            threats: vec![
                low,
                high_rare,
                high_likely_ctl,
                high_likely_local,
                on_secret,
                high_likely,
            ],
            assets: vec![
                asset("secrets", Sensitivity::Critical),
                asset("db", Sensitivity::Low),
            ],
            ..ThreatModel::default()
        };
        let stats = cap_threats(&mut tm, 10);
        assert_eq!(ids(&tm), vec!["T6", "T3", "T4", "T5", "T2", "T1"]);
        assert_eq!(
            stats,
            CapStats {
                raw: 6,
                truncated: 0,
                promoted: 0
            }
        );
    }

    #[test]
    fn equal_threats_tiebreak_on_the_numeric_id_then_the_raw_id() {
        let mk = |id: &str| threat(id, "s", Impact::Medium, Likelihood::Possible);
        let mut tm = ThreatModel {
            threats: vec![mk("T10"), mk("weird"), mk("T2"), mk(""), mk("T 3")],
            ..ThreatModel::default()
        };
        cap_threats(&mut tm, 10);
        assert_eq!(ids(&tm), vec!["T2", "T 3", "T10", "", "weird"]);
    }

    #[test]
    fn truncation_promotes_the_sole_cover_of_a_boundary() {
        let mut tm = ThreatModel {
            threats: vec![
                threat("T1", "api", Impact::Critical, Likelihood::Likely),
                threat("T2", "api", Impact::High, Likelihood::Likely),
                threat("T3", " Admin ", Impact::Low, Likelihood::Rare),
            ],
            trust_boundaries: vec![boundary("api", 1), boundary("admin", 1)],
            ..ThreatModel::default()
        };
        let stats = cap_threats(&mut tm, 2);
        // T3 is the only threat on "admin": it evicts T2 (whose removal
        // leaves "api" still covered by T1), and the result stays in rank
        // order.
        assert_eq!(ids(&tm), vec!["T1", "T3"]);
        assert_eq!(
            stats,
            CapStats {
                raw: 3,
                truncated: 1,
                promoted: 1
            }
        );
    }

    #[test]
    fn a_sole_cover_is_never_evicted_to_promote_another() {
        let mut tm = ThreatModel {
            threats: vec![
                threat("T1", "a", Impact::Critical, Likelihood::Likely),
                threat("T2", "b", Impact::High, Likelihood::Likely),
                threat("T3", "c", Impact::Low, Likelihood::Rare),
                threat("T4", "nowhere", Impact::Low, Likelihood::VeryRare),
            ],
            trust_boundaries: vec![
                boundary("a", 0),
                boundary("b", 0),
                boundary("c", 0),
                boundary("d", 0),
            ],
            ..ThreatModel::default()
        };
        let stats = cap_threats(&mut tm, 2);
        assert_eq!(ids(&tm), vec!["T1", "T2"]);
        assert_eq!(stats.promoted, 0);
        assert_eq!(stats.truncated, 2);
    }

    #[test]
    fn duplicate_ids_are_kept_apart_by_position() {
        let mut tm = ThreatModel {
            threats: (0..5)
                .map(|_| threat("T1", "s", Impact::Medium, Likelihood::Possible))
                .collect(),
            ..ThreatModel::default()
        };
        cap_threats(&mut tm, 3);
        assert_eq!(tm.threats.len(), 3);
    }

    #[test]
    fn a_zero_cap_keeps_no_threats() {
        let mut tm = ThreatModel {
            threats: vec![threat("T1", "a", Impact::Low, Likelihood::Rare)],
            trust_boundaries: vec![boundary("a", 0)],
            ..ThreatModel::default()
        };
        let stats = cap_threats(&mut tm, 0);
        assert!(tm.threats.is_empty());
        assert_eq!(stats.truncated, 1);
    }

    #[test]
    fn assets_are_capped_most_sensitive_first() {
        let mut tm = ThreatModel {
            assets: vec![
                asset("b", Sensitivity::Low),
                asset("z", Sensitivity::Critical),
                asset("a", Sensitivity::Low),
                asset("m", Sensitivity::High),
            ],
            ..ThreatModel::default()
        };
        cap_assets(&mut tm, 4);
        assert_eq!(tm.assets[0].name, "b", "under the cap nothing moves");
        cap_assets(&mut tm, 3);
        let names: Vec<&str> = tm.assets.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, vec!["z", "m", "a"]);
    }

    #[test]
    fn boundaries_are_capped_widest_reach_first() {
        let mut tm = ThreatModel {
            trust_boundaries: vec![boundary("b", 1), boundary("c", 3), boundary("a", 1)],
            ..ThreatModel::default()
        };
        cap_boundaries(&mut tm, 3);
        assert_eq!(tm.trust_boundaries[0].entry_point, "b");
        cap_boundaries(&mut tm, 2);
        let eps: Vec<&str> = tm
            .trust_boundaries
            .iter()
            .map(|b| b.entry_point.as_str())
            .collect();
        assert_eq!(eps, vec!["c", "a"]);
    }

    #[test]
    fn every_enum_value_has_a_rank() {
        for (i, r) in [
            (Impact::Existential, 5),
            (Impact::Critical, 4),
            (Impact::High, 3),
            (Impact::Medium, 2),
            (Impact::Low, 1),
        ] {
            assert_eq!(impact_rank(i), r);
        }
        assert_eq!(likelihood_rank(Likelihood::VeryRare), 1);
        assert_eq!(likelihood_rank(Likelihood::AlmostCertain), 5);
        assert_eq!(sensitivity_rank(Sensitivity::Medium), 2);
        for (a, r) in [
            (Actor::RemoteAuth, 5),
            (Actor::AdjacentNetwork, 4),
            (Actor::LocalAdmin, 3),
            (Actor::SupplyChain, 1),
            (Actor::Insider, 1),
        ] {
            assert_eq!(actor_rank(a), r);
        }
    }
}
