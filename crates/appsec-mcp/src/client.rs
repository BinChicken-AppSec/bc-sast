use std::io::{BufRead, Write};

use serde_json::{json, Value};

use crate::{DocRef, SearchQuery};

pub const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetched {
    pub doc: DocRef,
    pub url: String,
    pub text: String,
    pub truncated: bool,
}

pub struct Client<R: BufRead, W: Write> {
    reader: R,
    writer: W,
    next_id: u64,
    max_response_bytes: usize,
}

impl<R: BufRead, W: Write> Client<R, W> {
    pub fn new(reader: R, writer: W) -> Self {
        Self {
            reader,
            writer,
            next_id: 1,
            max_response_bytes: MAX_RESPONSE_BYTES,
        }
    }

    #[cfg(test)]
    pub(crate) fn sent(&self) -> &W {
        &self.writer
    }

    fn call(&mut self, method: &str, params: Option<Value>) -> Result<Value, String> {
        let id = self.next_id;
        self.next_id += 1;
        let mut request = json!({"jsonrpc": "2.0", "id": id, "method": method});
        if let Some(p) = params {
            request["params"] = p;
        }
        writeln!(self.writer, "{request}").map_err(|e| format!("sending {method} failed: {e}"))?;
        self.writer
            .flush()
            .map_err(|e| format!("sending {method} failed: {e}"))?;

        let line = read_line_capped(&mut self.reader, self.max_response_bytes)?
            .ok_or_else(|| format!("the server closed the stream before answering {method}"))?;
        let response: Value = serde_json::from_slice(&line)
            .map_err(|e| format!("the server's answer to {method} was not JSON: {e}"))?;

        if let Some(error) = response.get("error") {
            let code = error.get("code").and_then(Value::as_i64).unwrap_or(0);
            let message = error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("no message");
            return Err(format!("{method} failed ({code}): {message}"));
        }
        match response.get("id").and_then(Value::as_u64) {
            Some(got) if got == id => {}
            other => {
                return Err(format!(
                    "the server answered {method} with id {other:?}, expected {id}"
                ))
            }
        }
        response
            .get("result")
            .cloned()
            .ok_or_else(|| format!("the server's answer to {method} had no result"))
    }

    fn call_tool(&mut self, tool: &str, arguments: Value) -> Result<Value, String> {
        let result = self.call(
            "tools/call",
            Some(json!({"name": tool, "arguments": arguments})),
        )?;
        let content = result
            .get("content")
            .and_then(Value::as_array)
            .ok_or_else(|| format!("{tool} returned no content envelope"))?;
        let first = content
            .first()
            .ok_or_else(|| format!("{tool} returned an empty content envelope"))?;
        match first.get("type").and_then(Value::as_str) {
            Some("text") => {}
            other => {
                return Err(format!(
                    "{tool} returned content of type {other:?}, which this client cannot read"
                ))
            }
        }
        let text = first
            .get("text")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("{tool}'s content carried no text"))?;
        serde_json::from_str(text).map_err(|e| format!("{tool}'s payload was not JSON: {e}"))
    }

    pub fn initialize(&mut self) -> Result<String, String> {
        let result = self.call("initialize", None)?;
        Ok(result
            .get("serverInfo")
            .and_then(|i| i.get("name"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string())
    }

    pub fn tools(&mut self) -> Result<Vec<String>, String> {
        let result = self.call("tools/list", None)?;
        let tools = result
            .get("tools")
            .and_then(Value::as_array)
            .ok_or_else(|| "tools/list did not return a list".to_string())?;
        Ok(tools
            .iter()
            .filter_map(|t| t.get("name").and_then(Value::as_str))
            .map(str::to_owned)
            .collect())
    }

    pub fn search(&mut self, space: &str, query: &SearchQuery) -> Result<Vec<DocRef>, String> {
        let mut arguments = json!({"space": space});
        if let Some(l) = query.label.as_deref() {
            arguments["label"] = json!(l);
        }
        if !query.terms.is_empty() {
            arguments["terms"] = json!(query.terms);
        }
        let result = self.call_tool("context_search", arguments)?;
        let hits = result
            .as_array()
            .ok_or_else(|| "context_search did not return a list".to_string())?;
        Ok(hits.iter().map(doc_ref).collect())
    }

    pub fn fetch(&mut self, id: &str) -> Result<Fetched, String> {
        let result = self.call_tool("context_fetch", json!({"id": id}))?;
        if result
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .is_empty()
        {
            return Err(format!("context_fetch returned no id for {id:?}"));
        }
        Ok(Fetched {
            doc: doc_ref(&result),
            url: str_field(&result, "url"),
            text: str_field(&result, "text"),
            truncated: result
                .get("truncated")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        })
    }
}

fn str_field(v: &Value, key: &str) -> String {
    v.get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn doc_ref(v: &Value) -> DocRef {
    DocRef {
        id: str_field(v, "id"),
        title: str_field(v, "title"),
        space: str_field(v, "space"),
        modified: v.get("modified").and_then(Value::as_str).map(str::to_owned),
    }
}

fn read_line_capped<R: BufRead>(reader: &mut R, max: usize) -> Result<Option<Vec<u8>>, String> {
    let mut line = Vec::new();
    loop {
        let available = reader
            .fill_buf()
            .map_err(|e| format!("reading from the server failed: {e}"))?;
        if available.is_empty() {
            return Ok((!line.is_empty()).then_some(line));
        }
        match available.iter().position(|&b| b == b'\n') {
            Some(at) => {
                if line.len() + at > max {
                    return Err(format!("the server sent more than {max} bytes on one line"));
                }
                line.extend_from_slice(&available[..at]);
                reader.consume(at + 1);
                return Ok(Some(line));
            }
            None => {
                let taken = available.len();
                if line.len() + taken > max {
                    return Err(format!("the server sent more than {max} bytes on one line"));
                }
                line.extend_from_slice(available);
                reader.consume(taken);
            }
        }
    }
}

pub struct Session {
    child: std::process::Child,
    pub client: Client<std::io::BufReader<std::process::ChildStdout>, std::process::ChildStdin>,
}

impl Session {
    pub fn spawn(program: &std::path::Path, env: &[(String, String)]) -> Result<Self, String> {
        let mut command = std::process::Command::new(program);
        command.env_clear().envs(env.iter().cloned());
        Self::start(command, program)
    }

    fn start(
        mut command: std::process::Command,
        program: &std::path::Path,
    ) -> Result<Self, String> {
        let mut child = command
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .spawn()
            .map_err(|e| format!("could not start {}: {e}", program.display()))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| "the server has no stdin".to_string())?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "the server has no stdout".to_string())?;
        Ok(Self {
            child,
            client: Client::new(std::io::BufReader::new(stdout), stdin),
        })
    }

    pub fn spawn_with_inherited_env(program: &std::path::Path) -> Result<Self, String> {
        Self::start(std::process::Command::new(program), program)
    }

    pub fn shutdown(self) -> Result<std::process::ExitStatus, String> {
        let Self { mut child, client } = self;
        drop(client);
        child
            .wait()
            .map_err(|e| format!("waiting for the server failed: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool_response(id: u64, payload: Value) -> String {
        json!({"jsonrpc": "2.0", "id": id,
               "result": {"content": [{"type": "text", "text": payload.to_string()}]}})
        .to_string()
            + "\n"
    }

    fn client_over(responses: impl Into<String>) -> Client<std::io::Cursor<Vec<u8>>, Vec<u8>> {
        Client::new(
            std::io::Cursor::new(responses.into().into_bytes()),
            Vec::new(),
        )
    }

    #[test]
    fn initialize_returns_the_server_name_and_sends_a_jsonrpc_request() {
        let mut c = client_over(
            r#"{"jsonrpc":"2.0","id":1,"result":{"serverInfo":{"name":"appsec-mcp"}}}
"#,
        );
        assert_eq!(c.initialize().expect("ok"), "appsec-mcp");
        let sent: Value = serde_json::from_slice(&c.writer).expect("one request");
        assert_eq!(sent["jsonrpc"], "2.0");
        assert_eq!(sent["method"], "initialize");
        assert_eq!(sent["id"], 1);
    }

    #[test]
    fn tools_lists_the_names() {
        let mut c = client_over(
            r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"context_search"},{"name":"context_fetch"}]}}
"#,
        );
        assert_eq!(c.tools().expect("ok"), ["context_search", "context_fetch"]);
    }

    #[test]
    fn search_parses_hits_and_sends_the_space_and_label() {
        let mut c = client_over(tool_response(
            1,
            json!([{"id": "7", "title": "Arch", "space": "ENG", "modified": "2024-01-01"}]),
        ));
        let hits = c
            .search(
                "ENG",
                &SearchQuery {
                    label: Some("architecture".into()),
                    terms: Vec::new(),
                },
            )
            .expect("ok");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, "7");
        assert_eq!(hits[0].title, "Arch");
        assert_eq!(hits[0].modified.as_deref(), Some("2024-01-01"));

        let sent: Value = serde_json::from_slice(&c.writer).expect("one request");
        assert_eq!(sent["method"], "tools/call");
        assert_eq!(sent["params"]["name"], "context_search");
        assert_eq!(sent["params"]["arguments"]["space"], "ENG");
        assert_eq!(sent["params"]["arguments"]["label"], "architecture");
    }

    #[test]
    fn search_without_a_label_sends_no_label_key() {
        let mut c = client_over(tool_response(1, json!([])));
        assert!(c
            .search("ENG", &SearchQuery::default())
            .expect("ok")
            .is_empty());
        let sent: Value = serde_json::from_slice(&c.writer).expect("one request");
        assert!(sent["params"]["arguments"].get("label").is_none());
    }

    #[test]
    fn fetch_carries_the_text_url_and_truncation_flag() {
        let mut c = client_over(tool_response(
            1,
            json!({"id": "7", "title": "Arch", "space": "ENG",
                   "url": "https://x/wiki/pages/7",
                   "text": "the gateway terminates TLS", "truncated": true}),
        ));
        let got = c.fetch("7").expect("ok");
        assert_eq!(got.doc.id, "7");
        assert_eq!(got.url, "https://x/wiki/pages/7");
        assert_eq!(got.text, "the gateway terminates TLS");
        assert!(got.truncated, "a cut document must not look complete");
    }

    #[test]
    fn an_absent_truncated_flag_means_not_truncated() {
        let mut c = client_over(tool_response(1, json!({"id": "7", "text": "x"})));
        assert!(!c.fetch("7").expect("ok").truncated);
    }

    #[test]
    fn a_jsonrpc_error_becomes_an_error_with_its_code_and_message() {
        let mut c = client_over(
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"space \"FIN\" is not permitted"}}
"#,
        );
        let e = c
            .search("FIN", &SearchQuery::default())
            .expect_err("refused");
        assert!(e.contains("-32602"), "{e}");
        assert!(e.contains("not permitted"), "{e}");
    }

    #[test]
    fn an_error_without_a_message_still_reports() {
        let mut c = client_over("{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{}}\n");
        let e = c.tools().expect_err("refused");
        assert!(e.contains("no message"), "{e}");
    }

    #[test]
    fn a_mismatched_id_is_an_error_not_something_to_skip() {
        let mut c = client_over("{\"jsonrpc\":\"2.0\",\"id\":99,\"result\":{}}\n");
        let e = c.initialize().expect_err("refused");
        assert!(e.contains("id Some(99)"), "{e}");
        assert!(e.contains("expected 1"), "{e}");
    }

    #[test]
    fn ids_advance_so_a_stale_answer_cannot_satisfy_a_later_call() {
        let mut c = client_over(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[]}}\n{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[]}}\n",
        );
        assert!(c.tools().is_ok());
        let e = c.tools().expect_err("refused");
        assert!(e.contains("expected 2"), "{e}");
    }

    #[test]
    fn a_closed_stream_is_an_error_naming_the_method() {
        let mut c = client_over("");
        let e = c.initialize().expect_err("refused");
        assert!(e.contains("closed the stream"), "{e}");
        assert!(e.contains("initialize"), "{e}");
    }

    #[test]
    fn a_non_json_answer_is_an_error() {
        let mut c = client_over("not json at all\n");
        assert!(c.tools().expect_err("refused").contains("was not JSON"));
    }

    #[test]
    fn an_answer_with_neither_result_nor_error_is_an_error() {
        let mut c = client_over("{\"jsonrpc\":\"2.0\",\"id\":1}\n");
        assert!(c
            .initialize()
            .expect_err("refused")
            .contains("had no result"));
    }

    #[test]
    fn a_result_of_the_wrong_shape_is_an_error() {
        let mut c = client_over("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":7}}\n");
        assert!(c
            .tools()
            .expect_err("refused")
            .contains("did not return a list"));
        let mut c = client_over(tool_response(1, json!({})));
        assert!(c
            .search("ENG", &SearchQuery::default())
            .expect_err("refused")
            .contains("did not return a list"));
    }

    struct Failing {
        at_flush: bool,
    }

    impl Write for Failing {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if self.at_flush {
                Ok(buf.len())
            } else {
                Err(std::io::Error::other("pipe closed"))
            }
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::other("flush failed"))
        }
    }

    #[test]
    fn a_failing_write_is_reported_before_any_read() {
        let mut c = Client::new(&b""[..], Failing { at_flush: false });
        assert!(c
            .initialize()
            .expect_err("refused")
            .contains("sending initialize failed"));
    }

    #[test]
    fn a_failing_flush_is_reported_before_any_read() {
        let mut c = Client::new(&b""[..], Failing { at_flush: true });
        assert!(c
            .initialize()
            .expect_err("refused")
            .contains("sending initialize failed"));
    }

    #[test]
    fn the_inheriting_spawn_also_names_a_program_that_is_not_there() {
        let missing = std::path::Path::new("/nonexistent/appsec-mcp-not-installed");
        let Err(e) = Session::spawn_with_inherited_env(missing) else {
            panic!("spawning a program that is not installed must fail");
        };
        assert!(e.contains("could not start"), "{e}");
        assert!(e.contains("appsec-mcp-not-installed"), "{e}");
    }

    #[test]
    fn spawning_a_server_that_is_not_there_names_the_program() {
        let missing = std::path::Path::new("/nonexistent/appsec-mcp-not-installed");
        let Err(e) = Session::spawn(missing, &[]) else {
            panic!("spawning a program that is not installed must fail");
        };
        assert!(e.contains("could not start"), "{e}");
        assert!(e.contains("appsec-mcp-not-installed"), "{e}");
    }

    #[test]
    fn a_line_longer_than_the_cap_is_refused_rather_than_buffered() {
        let long = format!("{}\n", "x".repeat(100));
        let mut reader = long.as_bytes();
        let e = read_line_capped(&mut reader, 32).expect_err("refused");
        assert!(e.contains("more than 32 bytes"), "{e}");
    }

    #[test]
    fn the_cap_also_applies_when_no_newline_ever_arrives() {
        let endless = "y".repeat(500);
        let mut reader = endless.as_bytes();
        let e = read_line_capped(&mut reader, 64).expect_err("refused");
        assert!(e.contains("more than 64 bytes"), "{e}");
    }

    #[test]
    fn a_line_at_exactly_the_cap_is_accepted() {
        let exact = format!("{}\n", "z".repeat(16));
        let mut reader = exact.as_bytes();
        let line = read_line_capped(&mut reader, 16)
            .expect("ok")
            .expect("a line");
        assert_eq!(line.len(), 16);
    }

    #[test]
    fn an_empty_stream_reads_as_end_of_stream() {
        let mut reader = &b""[..];
        assert_eq!(read_line_capped(&mut reader, 16).expect("ok"), None);
    }

    #[test]
    fn a_final_line_without_a_newline_is_still_returned() {
        let mut reader = &b"last"[..];
        assert_eq!(
            read_line_capped(&mut reader, 16).expect("ok"),
            Some(b"last".to_vec())
        );
        assert_eq!(read_line_capped(&mut reader, 16).expect("ok"), None);
    }

    #[test]
    fn successive_lines_are_read_one_at_a_time() {
        let mut reader = &b"one\ntwo\n"[..];
        assert_eq!(
            read_line_capped(&mut reader, 16).expect("ok").unwrap(),
            b"one"
        );
        assert_eq!(
            read_line_capped(&mut reader, 16).expect("ok").unwrap(),
            b"two"
        );
        assert_eq!(read_line_capped(&mut reader, 16).expect("ok"), None);
    }

    #[test]
    fn a_failing_reader_is_reported() {
        struct Broken;
        impl std::io::Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("stream reset"))
            }
        }
        let mut reader = std::io::BufReader::new(Broken);
        let e = read_line_capped(&mut reader, 16).expect_err("refused");
        assert!(e.contains("reading from the server failed"), "{e}");
    }

    #[test]
    fn the_default_cap_is_the_documented_one() {
        assert_eq!(MAX_RESPONSE_BYTES, 4 * 1024 * 1024);
        let c = Client::new(&b""[..], Vec::new());
        assert_eq!(c.max_response_bytes, MAX_RESPONSE_BYTES);
    }

    #[test]
    fn a_tool_result_with_no_envelope_is_an_error() {
        let mut c = client_over("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":[]}\n");
        let e = c
            .search("ENG", &SearchQuery::default())
            .expect_err("refused");
        assert!(e.contains("no content envelope"), "{e}");
        assert!(e.contains("context_search"), "names the tool: {e}");
    }

    #[test]
    fn an_empty_content_array_is_an_error() {
        let mut c = client_over(
            json!({"jsonrpc": "2.0", "id": 1, "result": {"content": []}}).to_string() + "\n",
        );
        assert!(c
            .search("ENG", &SearchQuery::default())
            .expect_err("refused")
            .contains("empty content envelope"));
    }

    #[test]
    fn content_of_an_unreadable_type_is_an_error_naming_the_type() {
        let mut c = client_over(
            json!({"jsonrpc": "2.0", "id": 1,
                   "result": {"content": [{"type": "image", "data": "..."}]}})
            .to_string()
                + "\n",
        );
        let e = c.fetch("7").expect_err("refused");
        assert!(e.contains("image"), "{e}");
        assert!(e.contains("cannot read"), "{e}");
    }

    #[test]
    fn content_carrying_no_text_is_an_error() {
        let mut c = client_over(
            json!({"jsonrpc": "2.0", "id": 1,
                   "result": {"content": [{"type": "text"}]}})
            .to_string()
                + "\n",
        );
        assert!(c
            .fetch("7")
            .expect_err("refused")
            .contains("carried no text"));
    }

    #[test]
    fn a_payload_that_is_not_json_is_an_error() {
        let mut c = client_over(
            json!({"jsonrpc": "2.0", "id": 1,
                   "result": {"content": [{"type": "text", "text": "not json"}]}})
            .to_string()
                + "\n",
        );
        assert!(c
            .search("ENG", &SearchQuery::default())
            .expect_err("refused")
            .contains("was not JSON"));
    }

    #[test]
    fn a_fetched_document_with_no_id_is_an_error_not_a_blank_document() {
        let mut c = client_over(tool_response(1, json!({"title": "no id here"})));
        let e = c.fetch("7").expect_err("refused");
        assert!(e.contains("returned no id"), "{e}");
        assert!(e.contains("\"7\""), "names what was asked for: {e}");
    }
}
