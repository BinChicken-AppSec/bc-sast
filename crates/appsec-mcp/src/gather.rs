use std::io::{BufRead, Write};
use std::time::{Duration, Instant};

use crate::client::{Client, Fetched};
use crate::SearchQuery;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Budget {
    pub max_documents: usize,
    pub max_total_bytes: usize,
    pub max_duration: Option<Duration>,
}

impl Default for Budget {
    fn default() -> Self {
        Self {
            max_documents: 20,
            max_total_bytes: 256 * 1024,
            max_duration: Some(Duration::from_secs(120)),
        }
    }
}

#[derive(Debug, Default)]
pub struct Gathering {
    pub documents: Vec<Fetched>,
    pub problems: Vec<String>,
}

impl Gathering {
    pub fn is_empty(&self) -> bool {
        self.documents.is_empty()
    }

    pub fn total_bytes(&self) -> usize {
        self.documents.iter().map(|d| d.text.len()).sum()
    }
}

pub fn gather<R: BufRead, W: Write>(
    client: &mut Client<R, W>,
    spaces: &[String],
    query: &SearchQuery,
    budget: &Budget,
) -> Gathering {
    gather_with_clock(client, spaces, query, budget, Instant::now)
}

pub(crate) fn gather_with_clock<R: BufRead, W: Write>(
    client: &mut Client<R, W>,
    spaces: &[String],
    query: &SearchQuery,
    budget: &Budget,
    now: impl Fn() -> Instant,
) -> Gathering {
    let mut out = Gathering::default();
    let mut bytes = 0usize;
    let started = now();
    let out_of_time = |out: &mut Gathering, where_: &str| -> bool {
        match budget.max_duration {
            Some(limit) if now().duration_since(started) >= limit => {
                out.problems.push(format!(
                    "stopped {where_}: gathering passed its {limit:?} time limit"
                ));
                true
            }
            _ => false,
        }
    };

    for space in spaces {
        if out_of_time(&mut out, &format!("before space {space:?}")) {
            break;
        }
        if out.documents.len() >= budget.max_documents {
            out.problems.push(format!(
                "stopped before space {space:?}: already at the {} document limit",
                budget.max_documents
            ));
            continue;
        }
        let hits = match client.search(space, query) {
            Ok(h) => h,
            Err(e) => {
                out.problems
                    .push(format!("searching {space:?} failed: {e}"));
                continue;
            }
        };
        if hits.is_empty() {
            out.problems
                .push(format!("space {space:?} matched no documents"));
            continue;
        }
        for hit in hits {
            if out_of_time(&mut out, &format!("in space {space:?}")) {
                break;
            }
            if out.documents.len() >= budget.max_documents {
                out.problems.push(format!(
                    "stopped in space {space:?}: reached the {} document limit",
                    budget.max_documents
                ));
                break;
            }
            match client.fetch(&hit.id) {
                Ok(doc) => {
                    if bytes + doc.text.len() > budget.max_total_bytes {
                        out.problems.push(format!(
                            "stopped in space {space:?}: {:?} would pass the {} byte limit",
                            doc.doc.title, budget.max_total_bytes
                        ));
                        break;
                    }
                    bytes += doc.text.len();
                    out.documents.push(doc);
                }
                Err(e) => out
                    .problems
                    .push(format!("fetching {:?} failed: {e}", hit.id)),
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn transcript(payloads: &[serde_json::Value]) -> String {
        payloads
            .iter()
            .enumerate()
            .map(|(i, payload)| reply(i as u64 + 1, payload.clone()))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n"
    }

    fn reply(id: u64, payload: serde_json::Value) -> String {
        json!({"jsonrpc": "2.0", "id": id,
               "result": {"content": [{"type": "text", "text": payload.to_string()}]}})
        .to_string()
    }

    fn rpc_error(id: u64, message: &str) -> String {
        json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32602, "message": message}})
            .to_string()
    }

    fn hit(id: &str) -> serde_json::Value {
        json!({"id": id, "title": format!("doc {id}"), "space": "ENG"})
    }

    fn page(id: &str, text: &str) -> serde_json::Value {
        json!({"id": id, "title": format!("doc {id}"), "space": "ENG",
               "url": format!("https://x/wiki/pages/{id}"), "text": text})
    }

    fn client_over(script: String) -> Client<std::io::Cursor<Vec<u8>>, Vec<u8>> {
        Client::new(std::io::Cursor::new(script.into_bytes()), Vec::new())
    }

    fn stepping_clock(step: Duration) -> impl Fn() -> Instant {
        let base = Instant::now();
        let calls = std::cell::Cell::new(0u32);
        move || {
            let n = calls.get();
            calls.set(n + 1);
            base + step * n
        }
    }

    #[test]
    fn the_deadline_expiring_part_way_through_a_space_stops_the_fetching() {
        let script = transcript(&[
            json!({}),
            json!([hit("1"), hit("2"), hit("3")]),
            page("1", "first"),
            page("2", "second"),
            page("3", "third"),
        ]);
        let mut c = client_over(script);
        c.initialize().expect("handshake");

        let budget = Budget {
            max_duration: Some(Duration::from_secs(3)),
            ..Budget::default()
        };
        let got = gather_with_clock(
            &mut c,
            &spaces(&["ENG"]),
            &SearchQuery::default(),
            &budget,
            stepping_clock(Duration::from_secs(1)),
        );

        assert_eq!(got.documents.len(), 1, "{:?}", got.documents);
        assert_eq!(got.documents[0].doc.id, "1");
        assert!(
            got.problems
                .iter()
                .any(|p| p.contains("stopped in space \"ENG\"") && p.contains("time limit")),
            "{:?}",
            got.problems
        );
    }

    #[test]
    fn a_deadline_already_passed_stops_before_the_first_space_is_searched() {
        let mut c = client_over(transcript(&[json!({})]));
        c.initialize().expect("handshake");
        let budget = Budget {
            max_duration: Some(Duration::ZERO),
            ..Budget::default()
        };
        let got = gather_with_clock(
            &mut c,
            &spaces(&["ENG", "SEC"]),
            &SearchQuery::default(),
            &budget,
            stepping_clock(Duration::from_secs(1)),
        );
        assert!(got.documents.is_empty());
        assert_eq!(got.problems.len(), 1, "{:?}", got.problems);
        assert!(
            got.problems[0].contains("before space"),
            "{:?}",
            got.problems
        );
    }

    #[test]
    fn no_deadline_means_the_clock_is_never_consulted_against_a_limit() {
        let script = transcript(&[json!({}), json!([hit("1")]), page("1", "only")]);
        let mut c = client_over(script);
        c.initialize().expect("handshake");
        let budget = Budget {
            max_duration: None,
            ..Budget::default()
        };
        let got = gather_with_clock(
            &mut c,
            &spaces(&["ENG"]),
            &SearchQuery::default(),
            &budget,
            stepping_clock(Duration::from_secs(3600)),
        );
        assert_eq!(got.documents.len(), 1, "an hour per call must not matter");
    }

    fn spaces(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn every_hit_in_every_space_is_fetched() {
        let script = transcript(&[
            json!([hit("1"), hit("2")]),
            page("1", "alpha"),
            page("2", "beta"),
            json!([hit("3")]),
            page("3", "gamma"),
        ]);
        let mut c = client_over(script);
        let got = gather(
            &mut c,
            &spaces(&["ENG", "SEC"]),
            &SearchQuery::default(),
            &Budget::default(),
        );

        assert_eq!(got.problems, Vec::<String>::new());
        let texts: Vec<&str> = got.documents.iter().map(|d| d.text.as_str()).collect();
        assert_eq!(texts, ["alpha", "beta", "gamma"]);
        assert_eq!(got.total_bytes(), 14, "alpha + beta + gamma");
        assert!(!got.is_empty());
    }

    #[test]
    fn a_label_narrows_every_search_the_same_way() {
        let script = transcript(&[json!([]), json!([])]);
        let mut c = client_over(script);
        let _ = gather(
            &mut c,
            &spaces(&["ENG", "SEC"]),
            &SearchQuery {
                label: Some("architecture".into()),
                terms: Vec::new(),
            },
            &Budget::default(),
        );
        let sent = String::from_utf8(c.sent().clone()).expect("utf-8");
        assert_eq!(
            sent.matches(r#""label":"architecture""#).count(),
            2,
            "{sent}"
        );
    }

    #[test]
    fn a_failing_space_is_reported_and_the_rest_continue() {
        let script = [
            rpc_error(1, "space \"OPS\" is not permitted"),
            reply(2, json!([hit("9")])),
            reply(3, page("9", "still here")),
        ]
        .join("\n")
            + "\n";

        let mut c = client_over(script);
        let got = gather(
            &mut c,
            &spaces(&["OPS", "ENG"]),
            &SearchQuery::default(),
            &Budget::default(),
        );

        assert_eq!(got.documents.len(), 1, "{:?}", got.problems);
        assert_eq!(got.documents[0].text, "still here");
        assert_eq!(got.problems.len(), 1);
        assert!(
            got.problems[0].contains("searching \"OPS\" failed"),
            "{:?}",
            got.problems
        );
        assert!(
            got.problems[0].contains("not permitted"),
            "{:?}",
            got.problems
        );
    }

    #[test]
    fn a_space_with_no_matches_is_reported_rather_than_passed_over() {
        let script = transcript(&[json!([])]);
        let mut c = client_over(script);
        let got = gather(
            &mut c,
            &spaces(&["ENG"]),
            &SearchQuery::default(),
            &Budget::default(),
        );
        assert!(got.is_empty());
        assert_eq!(got.problems.len(), 1);
        assert!(
            got.problems[0].contains("matched no documents"),
            "{:?}",
            got.problems
        );
    }

    #[test]
    fn a_failing_fetch_is_reported_and_the_next_hit_is_still_fetched() {
        let mut script = String::new();
        script.push_str(&reply(1, json!([hit("1"), hit("2")])));
        script.push('\n');
        script.push_str(&rpc_error(2, "gone"));
        script.push('\n');
        script.push_str(&reply(3, page("2", "second")));
        script.push('\n');

        let mut c = client_over(script);
        let got = gather(
            &mut c,
            &spaces(&["ENG"]),
            &SearchQuery::default(),
            &Budget::default(),
        );
        assert_eq!(got.documents.len(), 1);
        assert_eq!(got.documents[0].text, "second");
        assert!(
            got.problems[0].contains("fetching \"1\" failed"),
            "{:?}",
            got.problems
        );
    }

    #[test]
    fn the_document_count_limit_stops_the_loop_and_says_so() {
        let script = transcript(&[
            json!([hit("1"), hit("2"), hit("3")]),
            page("1", "a"),
            page("2", "b"),
        ]);
        let mut c = client_over(script);
        let budget = Budget {
            max_documents: 2,
            max_total_bytes: 1 << 20,
            max_duration: None,
        };
        let got = gather(&mut c, &spaces(&["ENG"]), &SearchQuery::default(), &budget);
        assert_eq!(got.documents.len(), 2);
        assert!(
            got.problems[0].contains("reached the 2 document limit"),
            "{:?}",
            got.problems
        );
    }

    #[test]
    fn a_full_budget_skips_the_remaining_spaces_without_searching_them() {
        let script = transcript(&[json!([hit("1")]), page("1", "a")]);
        let mut c = client_over(script);
        let budget = Budget {
            max_documents: 1,
            max_total_bytes: 1 << 20,
            max_duration: None,
        };
        let got = gather(
            &mut c,
            &spaces(&["ENG", "SEC", "OPS"]),
            &SearchQuery::default(),
            &budget,
        );

        assert_eq!(got.documents.len(), 1);
        let sent = String::from_utf8(c.sent().clone()).expect("utf-8");
        assert_eq!(sent.lines().count(), 2, "{sent}");
        assert_eq!(got.problems.len(), 2);
        assert!(
            got.problems
                .iter()
                .all(|p| p.contains("already at the 1 document limit")),
            "{:?}",
            got.problems
        );
    }

    #[test]
    fn the_byte_limit_stops_before_adding_a_document_that_would_pass_it() {
        let script = transcript(&[
            json!([hit("1"), hit("2")]),
            page("1", "0123456789"),
            page("2", "much longer than the remaining budget"),
        ]);
        let mut c = client_over(script);
        let budget = Budget {
            max_documents: 10,
            max_total_bytes: 20,
            max_duration: None,
        };
        let got = gather(&mut c, &spaces(&["ENG"]), &SearchQuery::default(), &budget);

        assert_eq!(
            got.documents.len(),
            1,
            "the oversized second document is left out"
        );
        assert_eq!(got.total_bytes(), 10);
        assert!(
            got.problems[0].contains("would pass the 20 byte limit"),
            "{:?}",
            got.problems
        );
    }

    #[test]
    fn an_empty_space_list_gathers_nothing_and_asks_nothing() {
        let mut c = client_over(String::new());
        let got = gather(&mut c, &[], &SearchQuery::default(), &Budget::default());
        assert!(got.is_empty());
        assert!(got.problems.is_empty());
        assert!(c.sent().is_empty(), "it should not have sent anything");
    }

    #[test]
    fn a_gather_stops_once_it_passes_its_time_limit() {
        let script = transcript(&[json!([hit("1")]), page("1", "a")]);
        let mut c = client_over(script);
        let budget = Budget {
            max_documents: 10,
            max_total_bytes: 1 << 20,
            max_duration: Some(Duration::ZERO),
        };
        let got = gather(
            &mut c,
            &spaces(&["ENG", "SEC"]),
            &SearchQuery::default(),
            &budget,
        );

        assert!(got.is_empty(), "nothing should have been gathered");
        assert!(
            got.problems.iter().any(|p| p.contains("time limit")),
            "{:?}",
            got.problems
        );
        assert!(c.sent().is_empty(), "it made a request past its deadline");
    }

    #[test]
    fn no_time_limit_means_the_loop_is_not_cut_short() {
        let script = transcript(&[json!([hit("1")]), page("1", "a")]);
        let mut c = client_over(script);
        let budget = Budget {
            max_documents: 10,
            max_total_bytes: 1 << 20,
            max_duration: None,
        };
        let got = gather(&mut c, &spaces(&["ENG"]), &SearchQuery::default(), &budget);
        assert_eq!(got.documents.len(), 1, "{:?}", got.problems);
    }

    #[test]
    fn the_default_budget_bounds_time_as_well_as_size() {
        let b = Budget::default();
        assert_eq!(b.max_documents, 20);
        assert_eq!(b.max_total_bytes, 256 * 1024);
        assert_eq!(b.max_duration, Some(Duration::from_secs(120)));
    }
}
