pub mod client;
pub mod confluence;
pub mod gather;
pub mod http;
pub mod server;
pub mod sharepoint;

use std::collections::BTreeSet;

use serde_json::{json, Map, Value};

pub const TOOLS: [&str; 2] = ["context_search", "context_fetch"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub body: String,
    pub retry_after: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BytesResponse {
    pub status: u16,
    pub body: Vec<u8>,
    pub retry_after: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SearchQuery {
    pub label: Option<String>,
    pub terms: Vec<String>,
}

impl SearchQuery {
    pub fn with_terms(terms: impl IntoIterator<Item = String>) -> Self {
        Self {
            label: None,
            terms: terms.into_iter().filter(|t| !t.trim().is_empty()).collect(),
        }
    }

    fn from_args(args: &Map<String, Value>) -> Self {
        Self {
            label: args
                .get("label")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(str::to_owned),
            terms: args
                .get("terms")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(str::trim)
                        .filter(|t| !t.is_empty())
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocRef {
    pub id: String,
    pub title: String,
    pub space: String,
    pub modified: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document {
    pub doc: DocRef,
    pub url: String,
    pub text: String,
    pub truncated: bool,
}

pub trait DocumentSource {
    fn search(&self, space: &str, query: &SearchQuery) -> Result<Vec<DocRef>, String>;
    fn fetch(&self, id: &str) -> Result<Document, String>;
}

#[derive(Debug, Clone)]
pub struct Policy {
    spaces: BTreeSet<String>,
    pub max_documents: usize,
    pub max_bytes_per_document: usize,
}

impl Policy {
    pub fn new(spaces: impl IntoIterator<Item = String>) -> Self {
        Self {
            spaces: spaces.into_iter().collect(),
            max_documents: 50,
            max_bytes_per_document: 1_048_576,
        }
    }

    pub fn permits(&self, space: &str) -> bool {
        self.spaces.contains(space)
    }

    pub fn spaces(&self) -> impl Iterator<Item = &str> {
        self.spaces.iter().map(String::as_str)
    }
}

const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;

pub fn handle(req: &Value, source: &dyn DocumentSource, policy: &Policy) -> Option<Value> {
    let method = req
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let id = req.get("id").cloned()?;

    let result = match method {
        "initialize" => Ok(json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "appsec-mcp", "version": env!("CARGO_PKG_VERSION")},
        })),
        "tools/list" => Ok(json!({"tools": tool_specs()})),
        "tools/call" => call_tool(req.get("params"), source, policy),
        _ => {
            return Some(error(
                id,
                METHOD_NOT_FOUND,
                &format!("unknown method {method:?}"),
            ));
        }
    };
    Some(match result {
        Ok(v) => json!({"jsonrpc": "2.0", "id": id, "result": v}),
        Err(e) => error(id, INVALID_PARAMS, &e),
    })
}

fn error(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

fn tool_specs() -> Vec<Value> {
    vec![
        json!({
            "name": "context_search",
            "description": "List deployment-context documents in a permitted space.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "space": {"type": "string"},
                    "label": {"type": "string"},
                    "terms": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["space"],
            },
        }),
        json!({
            "name": "context_fetch",
            "description": "Fetch one document's text by id.",
            "inputSchema": {
                "type": "object",
                "properties": {"id": {"type": "string"}},
                "required": ["id"],
            },
        }),
    ]
}

fn call_tool(
    params: Option<&Value>,
    source: &dyn DocumentSource,
    policy: &Policy,
) -> Result<Value, String> {
    let params = params
        .and_then(Value::as_object)
        .ok_or("params must be an object")?;
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or("params.name is required")?;
    let args = params
        .get("arguments")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();

    if !TOOLS.contains(&name) {
        return Err(format!(
            "unknown tool {name:?}; this server offers only {}",
            TOOLS.join(", ")
        ));
    }
    let out = match name {
        "context_search" => search(&args, source, policy)?,
        _ => fetch(&args, source, policy)?,
    };
    Ok(json!({"content": [{"type": "text", "text": appsec_redact::redact_tree(&out).to_string()}]}))
}

fn string_arg(args: &Map<String, Value>, key: &str) -> Result<String, String> {
    args.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .map(str::to_owned)
        .ok_or_else(|| format!("{key} is required"))
}

fn search(
    args: &Map<String, Value>,
    source: &dyn DocumentSource,
    policy: &Policy,
) -> Result<Value, String> {
    let space = string_arg(args, "space")?;
    if !policy.permits(&space) {
        return Err(refusal(&space, policy));
    }
    let mut docs = source.search(&space, &SearchQuery::from_args(args))?;
    docs.truncate(policy.max_documents);
    Ok(Value::Array(
        docs.iter()
            .map(|d| {
                json!({"id": d.id, "title": d.title, "space": d.space,
                       "modified": d.modified})
            })
            .collect(),
    ))
}

fn fetch(
    args: &Map<String, Value>,
    source: &dyn DocumentSource,
    policy: &Policy,
) -> Result<Value, String> {
    let id = string_arg(args, "id")?;
    let doc = source.fetch(&id)?;
    if !policy.permits(&doc.doc.space) {
        return Err(refusal(&doc.doc.space, policy));
    }
    let mut text = doc.text;
    let truncated = doc.truncated || text.len() > policy.max_bytes_per_document;
    if truncated {
        let mut cut = policy.max_bytes_per_document;
        while cut > 0 && !text.is_char_boundary(cut) {
            cut -= 1;
        }
        text.truncate(cut);
    }
    Ok(json!({
        "id": doc.doc.id,
        "title": doc.doc.title,
        "space": doc.doc.space,
        "modified": doc.doc.modified,
        "url": doc.url,
        "text": text,
        "truncated": truncated,
    }))
}

fn refusal(space: &str, policy: &Policy) -> String {
    let permitted: Vec<&str> = policy.spaces().collect();
    if permitted.is_empty() {
        return format!("space {space:?} is not permitted; no spaces are configured");
    }
    format!(
        "space {space:?} is not permitted; configured spaces are {}",
        permitted.join(", ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fake {
        docs: Vec<Document>,
    }

    impl Fake {
        fn one(space: &str, text: &str) -> Self {
            Self {
                docs: vec![Document {
                    doc: DocRef {
                        id: "1".into(),
                        title: "Architecture".into(),
                        space: space.into(),
                        modified: Some("2024-02-01".into()),
                    },
                    url: "https://wiki/x".into(),
                    text: text.into(),
                    truncated: false,
                }],
            }
        }
        fn many(space: &str, n: usize) -> Self {
            Self {
                docs: (0..n)
                    .map(|i| Document {
                        doc: DocRef {
                            id: i.to_string(),
                            title: format!("doc {i}"),
                            space: space.into(),
                            modified: None,
                        },
                        url: String::new(),
                        text: String::new(),
                        truncated: false,
                    })
                    .collect(),
            }
        }
    }

    impl DocumentSource for Fake {
        fn search(&self, space: &str, _query: &SearchQuery) -> Result<Vec<DocRef>, String> {
            Ok(self
                .docs
                .iter()
                .filter(|d| d.doc.space == space)
                .map(|d| d.doc.clone())
                .collect())
        }
        fn fetch(&self, id: &str) -> Result<Document, String> {
            self.docs
                .iter()
                .find(|d| d.doc.id == id)
                .cloned()
                .ok_or_else(|| format!("no such document {id:?}"))
        }
    }

    fn call(name: &str, args: Value, source: &dyn DocumentSource, policy: &Policy) -> Value {
        let req = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                         "params": {"name": name, "arguments": args}});
        handle(&req, source, policy).expect("a response")
    }

    fn text_of(resp: &Value) -> String {
        resp["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    }

    fn err_of(resp: &Value) -> String {
        resp["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    }

    #[test]
    fn the_surface_is_exactly_two_read_only_tools() {
        let req = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});
        let resp = handle(
            &req,
            &Fake::one("ENG", ""),
            &Policy::new(["ENG".to_string()]),
        )
        .expect("a response");
        let tools = resp["result"]["tools"].as_array().expect("a list");
        assert_eq!(tools.len(), 2);
        let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert_eq!(names, TOOLS);
        let all = resp.to_string();
        for forbidden in ["url", "host", "request", "fetch_url", "http"] {
            assert!(
                !all.contains(&format!("\"{forbidden}\"")),
                "the surface must not accept {forbidden}: {all}"
            );
        }
    }

    #[test]
    fn an_unknown_tool_is_refused_and_names_what_exists() {
        let p = Policy::new(["ENG".to_string()]);
        let resp = call("http_request", json!({}), &Fake::one("ENG", ""), &p);
        let e = err_of(&resp);
        assert!(e.contains("unknown tool"), "{e}");
        assert!(e.contains("context_search"), "{e}");
    }

    #[test]
    fn a_space_nobody_permitted_is_refused_on_search() {
        let p = Policy::new(["ENG".to_string()]);
        let resp = call(
            "context_search",
            json!({"space": "FINANCE"}),
            &Fake::one("FINANCE", ""),
            &p,
        );
        let e = err_of(&resp);
        assert!(e.contains("not permitted"), "{e}");
        assert!(e.contains("ENG"), "it should name what is configured: {e}");
    }

    #[test]
    fn a_fetch_is_checked_against_the_space_the_document_turned_out_to_be_in() {
        let p = Policy::new(["ENG".to_string()]);
        let resp = call(
            "context_fetch",
            json!({"id": "1"}),
            &Fake::one("FINANCE", "secret plans"),
            &p,
        );
        let e = err_of(&resp);
        assert!(e.contains("not permitted"), "{e}");
        assert!(
            !resp.to_string().contains("secret plans"),
            "the body leaked"
        );
    }

    #[test]
    fn an_empty_policy_permits_nothing_rather_than_everything() {
        let p = Policy::new(Vec::new());
        let resp = call(
            "context_search",
            json!({"space": "ENG"}),
            &Fake::one("ENG", ""),
            &p,
        );
        let e = err_of(&resp);
        assert!(e.contains("no spaces are configured"), "{e}");
    }

    #[test]
    fn search_is_bounded_by_the_document_cap() {
        let mut p = Policy::new(["ENG".to_string()]);
        p.max_documents = 3;
        let resp = call(
            "context_search",
            json!({"space": "ENG"}),
            &Fake::many("ENG", 25),
            &p,
        );
        let parsed: Value = serde_json::from_str(&text_of(&resp)).expect("json");
        assert_eq!(parsed.as_array().expect("a list").len(), 3);
    }

    #[test]
    fn a_fetch_is_bounded_and_says_when_it_truncated() {
        let mut p = Policy::new(["ENG".to_string()]);
        p.max_bytes_per_document = 10;
        let resp = call(
            "context_fetch",
            json!({"id": "1"}),
            &Fake::one("ENG", "0123456789abcdef"),
            &p,
        );
        let parsed: Value = serde_json::from_str(&text_of(&resp)).expect("json");
        assert_eq!(parsed["text"], "0123456789");
        assert_eq!(parsed["truncated"], true);
    }

    #[test]
    fn truncation_lands_on_a_character_boundary() {
        let mut p = Policy::new(["ENG".to_string()]);
        p.max_bytes_per_document = 4;
        let resp = call(
            "context_fetch",
            json!({"id": "1"}),
            &Fake::one("ENG", "aa☃bb"),
            &p,
        );
        let parsed: Value = serde_json::from_str(&text_of(&resp)).expect("json");
        assert_eq!(parsed["text"], "aa", "cut back to the boundary");
        assert_eq!(parsed["truncated"], true);
    }

    #[test]
    fn a_document_that_is_not_truncated_says_so() {
        let p = Policy::new(["ENG".to_string()]);
        let resp = call(
            "context_fetch",
            json!({"id": "1"}),
            &Fake::one("ENG", "short"),
            &p,
        );
        let parsed: Value = serde_json::from_str(&text_of(&resp)).expect("json");
        assert_eq!(parsed["truncated"], false);
        assert_eq!(parsed["modified"], "2024-02-01", "the age must survive");
        assert_eq!(parsed["url"], "https://wiki/x");
    }

    #[test]
    fn a_credential_in_a_page_is_redacted_before_it_leaves() {
        let p = Policy::new(["ENG".to_string()]);
        let page = "db password is AKIAIOSFODNN7EXAMPLE and a key\n\
                    -----BEGIN RSA PRIVATE KEY-----\nMIIEowIB\n-----END RSA PRIVATE KEY-----";
        let resp = call(
            "context_fetch",
            json!({"id": "1"}),
            &Fake::one("ENG", page),
            &p,
        );
        let out = resp.to_string();
        assert!(
            !out.contains("AKIAIOSFODNN7EXAMPLE"),
            "an access key survived: {out}"
        );
        assert!(!out.contains("MIIEowIB"), "a private key body survived");
    }

    #[test]
    fn missing_arguments_are_refused_by_name() {
        let p = Policy::new(["ENG".to_string()]);
        let f = Fake::one("ENG", "");
        assert!(err_of(&call("context_search", json!({}), &f, &p)).contains("space is required"));
        assert!(err_of(&call("context_fetch", json!({}), &f, &p)).contains("id is required"));
        assert!(err_of(&call("context_fetch", json!({"id": "  "}), &f, &p)).contains("required"));
    }

    #[test]
    fn a_source_error_reaches_the_caller() {
        let p = Policy::new(["ENG".to_string()]);
        let resp = call(
            "context_fetch",
            json!({"id": "99"}),
            &Fake::one("ENG", ""),
            &p,
        );
        assert!(err_of(&resp).contains("no such document"));
    }

    #[test]
    fn initialize_reports_tools_and_this_server() {
        let req = json!({"jsonrpc": "2.0", "id": 7, "method": "initialize"});
        let resp =
            handle(&req, &Fake::one("ENG", ""), &Policy::new(Vec::new())).expect("a response");
        assert_eq!(resp["id"], 7);
        assert_eq!(resp["result"]["serverInfo"]["name"], "appsec-mcp");
        assert!(resp["result"]["capabilities"]["tools"].is_object());
    }

    #[test]
    fn an_unknown_method_is_a_jsonrpc_error() {
        let req = json!({"jsonrpc": "2.0", "id": 1, "method": "resources/read"});
        let resp =
            handle(&req, &Fake::one("ENG", ""), &Policy::new(Vec::new())).expect("a response");
        assert_eq!(resp["error"]["code"], -32601);
        assert!(err_of(&resp).contains("resources/read"));
    }

    #[test]
    fn a_notification_gets_no_reply() {
        let req = json!({"jsonrpc": "2.0", "method": "initialize"});
        assert!(handle(&req, &Fake::one("ENG", ""), &Policy::new(Vec::new())).is_none());
    }

    #[test]
    fn malformed_params_are_refused() {
        let p = Policy::new(["ENG".to_string()]);
        let f = Fake::one("ENG", "");
        for req in [
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call"}),
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": []}),
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {}}),
        ] {
            let resp = handle(&req, &f, &p).expect("a response");
            assert_eq!(resp["error"]["code"], -32602, "{resp}");
        }
    }

    #[test]
    fn the_default_bounds_are_stated_rather_than_implied() {
        let p = Policy::new(["ENG".to_string()]);
        assert_eq!(p.max_documents, 50);
        assert_eq!(p.max_bytes_per_document, 1_048_576);
        assert!(p.permits("ENG"));
        assert!(!p.permits("eng"), "space names are exact");
        assert_eq!(p.spaces().collect::<Vec<_>>(), vec!["ENG"]);
    }
}
