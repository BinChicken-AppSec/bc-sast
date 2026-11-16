use std::cell::RefCell;
use std::rc::Rc;

use appsec_mcp::client::Client;
use appsec_mcp::gather::{gather, Budget};
use appsec_mcp::{handle, DocRef, Document, DocumentSource, Policy, SearchQuery};
use serde_json::{json, Value};

struct Stub;

impl DocumentSource for Stub {
    fn search(&self, space: &str, _query: &SearchQuery) -> Result<Vec<DocRef>, String> {
        Ok(vec![DocRef {
            id: "7".into(),
            title: "Architecture".into(),
            space: space.into(),
            modified: Some("2024-02-01".into()),
        }])
    }
    fn fetch(&self, id: &str) -> Result<Document, String> {
        Ok(Document {
            doc: DocRef {
                id: id.into(),
                title: "Architecture".into(),
                space: "ENG".into(),
                modified: Some("2024-02-01".into()),
            },
            url: format!("https://w/wiki/pages/{id}"),
            text: "the gateway terminates TLS".into(),
            truncated: false,
        })
    }
}

fn transcript_for(requests: &[Value]) -> String {
    let policy = Policy::new(["ENG".to_string()]);
    let mut out = String::new();
    for request in requests {
        let response = handle(request, &Stub, &policy).expect("a request gets a response");
        out.push_str(&response.to_string());
        out.push('\n');
    }
    out
}

fn client_for(methods: &[(&str, Value)]) -> Client<std::io::Cursor<Vec<u8>>, Vec<u8>> {
    let requests: Vec<Value> = methods
        .iter()
        .enumerate()
        .map(|(i, (name, args))| {
            let id = i + 1;
            if *name == "tools/list" || *name == "initialize" {
                json!({"jsonrpc": "2.0", "id": id, "method": name})
            } else {
                json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
                       "params": {"name": name, "arguments": args}})
            }
        })
        .collect();
    Client::new(
        std::io::Cursor::new(transcript_for(&requests).into_bytes()),
        Vec::new(),
    )
}

#[test]
fn the_client_parses_a_real_search_result() {
    let mut client = client_for(&[("context_search", json!({"space": "ENG"}))]);
    let hits = client
        .search("ENG", &SearchQuery::default())
        .expect("the client must parse what the server actually emits");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].id, "7");
    assert_eq!(hits[0].title, "Architecture");
    assert_eq!(hits[0].space, "ENG");
    assert_eq!(hits[0].modified.as_deref(), Some("2024-02-01"));
}

#[test]
fn the_client_parses_a_real_fetch_result() {
    let mut client = client_for(&[("context_fetch", json!({"id": "7"}))]);
    let doc = client
        .fetch("7")
        .expect("the client must parse a real fetch");
    assert_eq!(doc.doc.id, "7");
    assert_eq!(doc.doc.space, "ENG");
    assert_eq!(doc.url, "https://w/wiki/pages/7");
    assert_eq!(doc.text, "the gateway terminates TLS");
    assert!(!doc.truncated);
}

#[test]
fn gathering_over_the_real_server_returns_the_document() {
    let mut client = client_for(&[
        ("context_search", json!({"space": "ENG"})),
        ("context_fetch", json!({"id": "7"})),
    ]);
    let got = gather(
        &mut client,
        &["ENG".to_string()],
        &SearchQuery::default(),
        &Budget::default(),
    );
    assert_eq!(got.problems, Vec::<String>::new(), "no problems expected");
    assert_eq!(got.documents.len(), 1, "the feature must actually gather");
    assert_eq!(got.documents[0].text, "the gateway terminates TLS");
    assert_eq!(got.documents[0].doc.space, "ENG");
}

#[test]
fn the_client_parses_a_real_tools_list_and_initialize() {
    let mut client = client_for(&[("tools/list", Value::Null)]);
    assert_eq!(
        client.tools().expect("tools/list"),
        ["context_search", "context_fetch"]
    );

    let mut client = client_for(&[("initialize", Value::Null)]);
    assert_eq!(client.initialize().expect("initialize"), "appsec-mcp");
}

#[test]
fn a_real_policy_refusal_arrives_as_an_error() {
    let mut client = client_for(&[("context_search", json!({"space": "FINANCE"}))]);
    let err = client
        .search("FINANCE", &SearchQuery::default())
        .expect_err("an unpermitted space must be refused");
    assert!(err.contains("not permitted"), "{err}");
    assert!(
        err.contains("ENG"),
        "the refusal names what is configured: {err}"
    );
}

#[derive(Clone, Default)]
struct Shared(Rc<RefCell<Vec<u8>>>);

impl Shared {
    fn written(&self) -> String {
        String::from_utf8(self.0.borrow().clone()).expect("the client writes utf-8")
    }

    fn first_request(&self) -> Value {
        let text = self.written();
        serde_json::from_str(text.lines().next().expect("a request")).expect("json")
    }
}

impl std::io::Write for Shared {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn writing_client(out: Shared) -> Client<std::io::Cursor<Vec<u8>>, Shared> {
    Client::new(std::io::Cursor::new(Vec::new()), out)
}

struct Recording {
    seen: RefCell<Vec<SearchQuery>>,
}

impl DocumentSource for Recording {
    fn search(&self, space: &str, query: &SearchQuery) -> Result<Vec<DocRef>, String> {
        self.seen.borrow_mut().push(query.clone());
        Ok(vec![DocRef {
            id: "7".into(),
            title: "Architecture".into(),
            space: space.into(),
            modified: None,
        }])
    }
    fn fetch(&self, _id: &str) -> Result<Document, String> {
        Err("not used".into())
    }
}

#[test]
fn search_terms_reach_the_source_through_the_real_protocol() {
    let source = Recording {
        seen: RefCell::new(Vec::new()),
    };
    let policy = Policy::new(["ENG".to_string()]);
    let query = SearchQuery {
        label: Some("architecture".into()),
        terms: vec!["payments-api".into(), "Payments API".into()],
    };

    let out = Shared::default();
    let _ = writing_client(out.clone()).search("ENG", &query);
    let request = out.first_request();

    let response = handle(&request, &source, &policy).expect("a response");
    assert!(response.get("error").is_none(), "{response}");

    let seen = source.seen.borrow();
    assert_eq!(seen.len(), 1, "the server did not reach the source");
    assert_eq!(seen[0], query, "the query changed in transit");
}

#[test]
fn a_search_with_no_terms_sends_no_terms_key_at_all() {
    let out = Shared::default();
    let _ = writing_client(out.clone()).search("ENG", &SearchQuery::default());
    let request = out.first_request();
    let arguments = &request["params"]["arguments"];
    assert_eq!(arguments["space"], "ENG");
    assert!(arguments.get("terms").is_none(), "{arguments}");
    assert!(arguments.get("label").is_none(), "{arguments}");
}

#[test]
fn the_advertised_search_schema_accepts_the_arguments_the_client_sends() {
    let policy = Policy::new(["ENG".to_string()]);
    let listed = handle(
        &json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
        &Stub,
        &policy,
    )
    .expect("a response");
    let search = listed["result"]["tools"]
        .as_array()
        .expect("tools")
        .iter()
        .find(|t| t["name"] == "context_search")
        .expect("context_search is listed")
        .clone();
    let properties = &search["inputSchema"]["properties"];
    assert!(properties.get("terms").is_some(), "{search}");
    assert_eq!(properties["terms"]["type"], "array");
    assert_eq!(properties["terms"]["items"]["type"], "string");
    for forbidden in ["url", "host", "endpoint"] {
        assert!(
            properties.get(forbidden).is_none(),
            "the surface grew {forbidden}: {search}"
        );
    }
}
