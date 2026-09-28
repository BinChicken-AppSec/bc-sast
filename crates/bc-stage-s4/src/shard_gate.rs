// Portions of this file are transcribed from vvaharness, Visa's agentic
// SAST harness: Copyright 2026 Visa, Inc., licensed under the Apache
// License, Version 2.0. Reimplemented in Rust and modified; see the module
// documentation below, and NOTICE for the full attribution.
//! Shard leader gating, ported from upstream v1.4.0 `s4_deepdive.py`'s
//! `_shard_gates` / `_gated_deepdive`.
//!
//! Every lens on one S3 shard sends a byte-identical cache prefix (the
//! shared context plus the shard's source, see [`crate::prompt_layout`]).
//! Dispatched back to back, they would all be in flight at once and each
//! would WRITE that prefix at the cache-write rate, because a cache entry
//! only becomes readable when the request that writes it completes.
//! Upstream measured duplicate writes at 59 to 74% of S4's cache-write
//! mass before gating. So the first chunk of each shard group (in
//! dispatch order) is the leader and runs at once; its siblings hold
//! their model call until the leader's call has returned, then read the
//! prefix at the cache-read rate.
//!
//! Both waits are bounded, so gating can never deadlock: a sibling waits
//! at most [`LEADER_START_CAP`] for the leader to start and then at most
//! [`LEADER_DONE_CAP`] for it to finish, and past either cap it proceeds
//! ungated (a duplicate write, counted in the diagnostics rather than
//! silent). A leader that fails, is budget-stopped or is aborted releases
//! its siblings at once, since [`Leader`]'s `Drop` marks it done.
//!
//! **Divergence from Python, deliberate.** Upstream parks a sibling on a
//! thread-pool worker, which occupies a slot of `step4.parallel` for the
//! whole leader call (its own comment records the head-of-line cost). This
//! port parks a sibling *without* its concurrency permit: the stage hands
//! the permit back before parking and takes a fresh one afterwards, so a
//! parked sibling never holds capacity other chunks could use, and
//! `parallel: 1` cannot wedge on a sibling waiting for a leader that needs
//! the only permit. Upstream also polls in one-second slices to notice an
//! abort; a tokio task is simply dropped at its await point when the stage
//! aborts, so no polling is needed.

use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

use bc_model::Chunk;
use tokio::sync::watch;
use tokio::time::{timeout, Instant};

/// Longest a sibling waits for its leader's call to even start (upstream
/// `_SHARD_LEADER_CAP`). The stage dispatches in order, so a leader has
/// always been dispatched before its siblings and this only guards
/// against pathological scheduling.
pub const LEADER_START_CAP: Duration = Duration::from_secs(15);

/// Longest a sibling waits for its leader's call to finish (upstream
/// `_SHARD_LEADER_DONE_CAP`), above the worst observed deep-dive call so
/// it does not fire in normal operation. It exists so a leader wedged in
/// a provider retry storm degrades to a duplicate write instead of
/// stalling its whole group.
pub const LEADER_DONE_CAP: Duration = Duration::from_secs(240);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Phase {
    Queued,
    Started,
    Done,
}

/// A shard group's leader. Call [`Leader::start`] just before its model
/// call; dropping it (success, failure, budget stop or abort alike) marks
/// the leader done and releases every sibling.
#[derive(Debug)]
pub struct Leader {
    tx: watch::Sender<Phase>,
}

impl Leader {
    pub fn start(&self) {
        self.tx.send_replace(Phase::Started);
    }
}

impl Drop for Leader {
    fn drop(&mut self) {
        self.tx.send_replace(Phase::Done);
    }
}

/// A shard group member that is not the leader.
#[derive(Debug)]
pub struct Sibling {
    leader: String,
    rx: watch::Receiver<Phase>,
}

/// What one sibling's wait cost, for [`crate::DeepdiveDiagnostics`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ParkReport {
    /// The leader never started within [`LEADER_START_CAP`].
    pub start_cap_expired: bool,
    /// The leader started but was still running at [`LEADER_DONE_CAP`].
    pub done_cap_expired: bool,
    /// Wall-clock time spent parked.
    pub parked: Duration,
}

impl Sibling {
    /// The leader chunk's id, for log lines.
    pub fn leader(&self) -> &str {
        &self.leader
    }

    /// Whether the leader's call has already returned, in which case the
    /// sibling can run at once and need not park.
    pub fn leader_finished(&self) -> bool {
        *self.rx.borrow() == Phase::Done
    }

    /// Wait for the leader to start and then finish, each bounded by its
    /// cap. Never errors: a closed channel means the leader is gone,
    /// which releases the sibling exactly like a finished leader.
    pub async fn park(&mut self) -> ParkReport {
        let began = Instant::now();
        let mut report = ParkReport::default();
        let started = timeout(LEADER_START_CAP, self.rx.wait_for(|p| *p >= Phase::Started));
        if started.await.is_err() {
            report.start_cap_expired = true;
        } else {
            let done = timeout(LEADER_DONE_CAP, self.rx.wait_for(|p| *p == Phase::Done));
            report.done_cap_expired = done.await.is_err();
        }
        report.parked = began.elapsed();
        report
    }
}

/// One chunk's role in its shard group.
#[derive(Debug)]
pub enum Gate {
    Leader(Leader),
    Sibling(Sibling),
}

/// Map each gated shard-group member's chunk id to its gate. `chunks`
/// must already be in dispatch order: the first member seen for a shard
/// is its leader. Only chunks `gated` accepts take part (the stage passes
/// the ones whose prefix carries shard source, see
/// [`crate::prompt_layout::shares_shard_prefix`]), and a shard with a
/// single gated member gets no gate at all, since there is nobody to
/// share its cache entry with.
pub fn build_gates(chunks: &[Chunk], gated: impl Fn(&Chunk) -> bool) -> HashMap<String, Gate> {
    let mut groups: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for chunk in chunks.iter().filter(|c| !c.shard_id.is_empty() && gated(c)) {
        groups
            .entry(chunk.shard_id.as_str())
            .or_default()
            .push(chunk.id.as_str());
    }
    let mut gates = HashMap::new();
    for ids in groups.values().filter(|ids| ids.len() > 1) {
        let (tx, rx) = watch::channel(Phase::Queued);
        let leader = ids[0].to_string();
        for id in &ids[1..] {
            let sibling = Sibling {
                leader: leader.clone(),
                rx: rx.clone(),
            };
            gates.insert(id.to_string(), Gate::Sibling(sibling));
        }
        gates.insert(leader, Gate::Leader(Leader { tx }));
    }
    gates
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_model::ChunkSize;

    fn chunk(id: &str, shard: &str) -> Chunk {
        Chunk {
            id: id.to_string(),
            size: ChunkSize::Small,
            risk_rank: 1,
            files: vec!["a.py".to_string()],
            focus_entry_points: Vec::new(),
            hypothesis: String::new(),
            related_cves: Vec::new(),
            threat_id: None,
            languages: Vec::new(),
            specialist: None,
            path_funcs: Vec::new(),
            source_ref: String::new(),
            sink_ref: String::new(),
            sink_cwe: Vec::new(),
            shard_id: shard.to_string(),
        }
    }

    /// A leader and sibling wired the way `build_gates` wires them (the
    /// stage-level tests in `shard_cache_tests` cover `build_gates`'
    /// own wiring end to end).
    fn pair() -> (Leader, Sibling) {
        let (tx, rx) = watch::channel(Phase::Queued);
        let sibling = Sibling {
            leader: "l".to_string(),
            rx,
        };
        (Leader { tx }, sibling)
    }

    /// The leader a gate follows, or `"(leads)"` for a leader.
    fn leader_of(gate: &Gate) -> &str {
        match gate {
            Gate::Sibling(s) => s.leader(),
            Gate::Leader(_) => "(leads)",
        }
    }

    #[test]
    fn the_first_member_of_each_multi_chunk_shard_leads_and_singletons_get_no_gate() {
        let chunks = [
            chunk("risk-01", ""),
            chunk("spec-a-01", "shard-01"),
            chunk("spec-b-01", "shard-01"),
            chunk("spec-c-01", "shard-01"),
            chunk("spec-a-02", "shard-02"),
            chunk("spec-iac-01", "iac-shard-01"),
            chunk("spec-iac-02", "iac-shard-01"),
        ];
        let gates = build_gates(&chunks, |_| true);
        assert_eq!(leader_of(&gates["spec-a-01"]), "(leads)");
        assert_eq!(leader_of(&gates["spec-b-01"]), "spec-a-01");
        assert_eq!(leader_of(&gates["spec-c-01"]), "spec-a-01");
        assert!(matches!(gates["spec-iac-01"], Gate::Leader(_)));
        assert!(matches!(gates["spec-iac-02"], Gate::Sibling(_)));
        assert!(!gates.contains_key("risk-01"));
        assert!(!gates.contains_key("spec-a-02"));
        assert_eq!(gates.len(), 5);
    }

    #[test]
    fn chunks_the_predicate_rejects_take_no_part() {
        let chunks = [
            chunk("a", "shard-01"),
            chunk("b", "shard-01"),
            chunk("c", "shard-01"),
        ];
        let gates = build_gates(&chunks, |c| c.id != "a");
        // "a" is skipped, so "b" leads.
        assert!(!gates.contains_key("a"));
        assert!(matches!(gates["b"], Gate::Leader(_)));
        assert!(matches!(gates["c"], Gate::Sibling(_)));
        assert!(build_gates(&chunks, |_| false).is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn a_sibling_parks_until_the_leader_finishes() {
        let (leader, mut sibling) = pair();
        assert!(!sibling.leader_finished());
        let waiter = tokio::spawn(async move { sibling.park().await });
        leader.start();
        tokio::time::sleep(Duration::from_secs(30)).await;
        drop(leader);
        let report = waiter.await.unwrap();
        assert!(!report.start_cap_expired);
        assert!(!report.done_cap_expired);
        assert_eq!(report.parked, Duration::from_secs(30));
    }

    #[tokio::test(start_paused = true)]
    async fn a_leader_that_never_starts_releases_its_sibling_at_the_start_cap() {
        let (leader, mut sibling) = pair();
        let report = sibling.park().await;
        assert!(report.start_cap_expired);
        assert!(!report.done_cap_expired);
        assert_eq!(report.parked, LEADER_START_CAP);
        drop(leader);
    }

    #[tokio::test(start_paused = true)]
    async fn a_leader_that_never_finishes_releases_its_sibling_at_the_done_cap() {
        let (leader, mut sibling) = pair();
        leader.start();
        let report = sibling.park().await;
        assert!(!report.start_cap_expired);
        assert!(report.done_cap_expired);
        assert_eq!(report.parked, LEADER_DONE_CAP);
        drop(leader);
    }

    #[tokio::test(start_paused = true)]
    async fn a_leader_dropped_before_starting_releases_its_sibling_at_once() {
        let (leader, mut sibling) = pair();
        drop(leader);
        assert!(sibling.leader_finished());
        let report = sibling.park().await;
        assert_eq!(report, ParkReport::default());
    }

    #[tokio::test(start_paused = true)]
    async fn a_closed_channel_releases_the_sibling_like_a_finished_leader() {
        // A sender dropped without ever reaching `Done` (impossible through
        // `Leader`, whose `Drop` always sends it) still never strands a
        // sibling: `wait_for` errors out and the wait ends.
        let (tx, rx) = watch::channel(Phase::Queued);
        let mut sibling = Sibling {
            leader: "l".to_string(),
            rx,
        };
        drop(tx);
        let report = sibling.park().await;
        assert!(!report.start_cap_expired);
        assert!(!report.done_cap_expired);
        assert_eq!(report.parked, Duration::ZERO);
    }
}
