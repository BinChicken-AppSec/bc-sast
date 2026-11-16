use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

use appsec_model::Chunk;
use tokio::sync::watch;
use tokio::time::{timeout, Instant};

pub const LEADER_START_CAP: Duration = Duration::from_secs(15);

pub const LEADER_DONE_CAP: Duration = Duration::from_secs(240);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Phase {
    Queued,
    Started,
    Done,
}

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

#[derive(Debug)]
pub struct Sibling {
    leader: String,
    rx: watch::Receiver<Phase>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ParkReport {
    pub start_cap_expired: bool,
    pub done_cap_expired: bool,
    pub parked: Duration,
}

impl Sibling {
    pub fn leader(&self) -> &str {
        &self.leader
    }

    pub fn leader_finished(&self) -> bool {
        *self.rx.borrow() == Phase::Done
    }

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

#[derive(Debug)]
pub enum Gate {
    Leader(Leader),
    Sibling(Sibling),
}

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
    use appsec_model::ChunkSize;

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

    fn pair() -> (Leader, Sibling) {
        let (tx, rx) = watch::channel(Phase::Queued);
        let sibling = Sibling {
            leader: "l".to_string(),
            rx,
        };
        (Leader { tx }, sibling)
    }

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
