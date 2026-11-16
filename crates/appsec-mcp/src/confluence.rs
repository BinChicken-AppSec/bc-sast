use std::collections::BTreeSet;
use std::time::Duration;

use serde_json::Value;

use crate::{DocRef, Document, DocumentSource, SearchQuery};

pub use crate::HttpResponse;

const MAX_RETRIES: u32 = 4;
const BASE_DELAY: Duration = Duration::from_secs(1);
const MAX_DELAY: Duration = Duration::from_secs(30);

pub const MAX_SEARCH_LIMIT: u32 = 25;

pub trait HttpTransport {
    fn get(&self, url: &str, auth: &str) -> Result<HttpResponse, String>;
}

#[derive(Clone)]
pub struct Credentials {
    base_url: String,
    email: String,
    token: String,
    pub expires_hint: Option<String>,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("base_url", &self.base_url)
            .field("email", &self.email)
            .field("token", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfluenceError {
    UnsupportedHost(String),
    NotHttps(String),
    MissingCredential(&'static str),
    Status { status: u16, body: String },
    RateLimited { attempts: u32 },
    Malformed(String),
}

impl std::fmt::Display for ConfluenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedHost(u) => write!(
                f,
                "{u} is not a Confluence Cloud base URL; expected \
                 https://<site>.atlassian.net/wiki or \
                 https://api.atlassian.com/ex/confluence/<cloudId>"
            ),
            Self::NotHttps(u) => write!(f, "refusing a non-HTTPS base URL: {u}"),
            Self::MissingCredential(w) => write!(f, "{w} is required"),
            Self::Status { status, body } => {
                write!(f, "Confluence answered {status}: {body}")
            }
            Self::RateLimited { attempts } => write!(
                f,
                "still rate limited after {attempts} attempts; not retrying further"
            ),
            Self::Malformed(w) => write!(f, "unexpected response shape: {w}"),
        }
    }
}

impl std::error::Error for ConfluenceError {}

impl Credentials {
    pub fn new(
        base_url: &str,
        email: &str,
        token: &str,
        expires_hint: Option<String>,
    ) -> Result<Self, ConfluenceError> {
        let trimmed = base_url.trim();
        let parsed = reqwest::Url::parse(trimmed)
            .map_err(|_| ConfluenceError::UnsupportedHost(trimmed.to_string()))?;
        if parsed.scheme() != "https" {
            return Err(ConfluenceError::NotHttps(trimmed.to_string()));
        }
        if !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(ConfluenceError::UnsupportedHost(trimmed.to_string()));
        }
        let host = parsed.host_str().unwrap_or_default().to_ascii_lowercase();
        let host = host.trim_end_matches('.').to_string();
        let site = host.ends_with(".atlassian.net");
        let scoped = host == "api.atlassian.com" && parsed.path().starts_with("/ex/confluence/");
        if !(site || scoped) {
            return Err(ConfluenceError::UnsupportedHost(trimmed.to_string()));
        }
        if email.trim().is_empty() {
            return Err(ConfluenceError::MissingCredential("email"));
        }
        if token.trim().is_empty() {
            return Err(ConfluenceError::MissingCredential("token"));
        }
        let path = parsed
            .path()
            .trim_end_matches('/')
            .trim_end_matches("/wiki");
        let mut base = format!("https://{host}");
        if let Some(port) = parsed.port() {
            base.push_str(&format!(":{port}"));
        }
        base.push_str(path.trim_end_matches('/'));

        Ok(Self {
            base_url: base,
            email: email.trim().to_string(),
            token: token.to_string(),
            expires_hint,
        })
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    fn header(&self) -> String {
        format!(
            "Basic {}",
            base64(format!("{}:{}", self.email, self.token).as_bytes())
        )
    }
}

fn base64(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(TABLE[(n >> (18 - 6 * i) & 0x3F) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

pub struct ConfluenceSource<T: HttpTransport> {
    transport: T,
    creds: Credentials,
    spaces: BTreeSet<String>,
    limit: u32,
    sleeper: Box<dyn Fn(Duration) + Send + Sync>,
}

impl<T: HttpTransport> ConfluenceSource<T> {
    pub fn new(transport: T, creds: Credentials, spaces: impl IntoIterator<Item = String>) -> Self {
        Self {
            transport,
            creds,
            spaces: spaces.into_iter().collect(),
            limit: MAX_SEARCH_LIMIT,
            sleeper: Box::new(std::thread::sleep),
        }
    }

    #[cfg(test)]
    fn with_sleeper(mut self, sleeper: Box<dyn Fn(Duration) + Send + Sync>) -> Self {
        self.sleeper = sleeper;
        self
    }

    fn search_url(&self, space: &str, query: &SearchQuery, cursor: Option<&str>) -> String {
        let mut cql = format!("type=page and space=\"{}\"", cql_escape(space));
        if let Some(l) = query.label.as_deref() {
            cql.push_str(&format!(" and label=\"{}\"", cql_escape(l)));
        }
        if !query.terms.is_empty() {
            let ors: Vec<String> = query
                .terms
                .iter()
                .map(|t| format!("text ~ \"{}\"", cql_escape(t)))
                .collect();
            cql.push_str(&format!(" and ({})", ors.join(" or ")));
        }
        let mut url = format!(
            "{}/wiki/rest/api/search?cql={}&limit={}",
            self.creds.base_url,
            percent_encode(&cql),
            self.limit
        );
        if let Some(c) = cursor {
            url.push_str(&format!("&cursor={}", percent_encode(c)));
        }
        url
    }

    fn get(&self, url: &str) -> Result<HttpResponse, ConfluenceError> {
        let auth = self.creds.header();
        let mut attempt = 0;
        loop {
            let resp = self
                .transport
                .get(url, &auth)
                .map_err(ConfluenceError::Malformed)?;
            if resp.status == 429 {
                attempt += 1;
                if attempt > MAX_RETRIES || resp.retry_after.is_none() {
                    return Err(ConfluenceError::RateLimited { attempts: attempt });
                }
                (self.sleeper)(with_jitter(
                    retry_delay(attempt - 1, resp.retry_after),
                    jitter_factor(),
                ));
                continue;
            }
            if !(200..300).contains(&resp.status) {
                return Err(ConfluenceError::Status {
                    status: resp.status,
                    body: resp.body,
                });
            }
            return Ok(resp);
        }
    }
}

pub fn retry_delay(attempt: u32, retry_after: Option<u64>) -> Duration {
    let backoff = BASE_DELAY.saturating_mul(1u32 << attempt.min(16));
    let server = retry_after.map(Duration::from_secs).unwrap_or(BASE_DELAY);
    backoff.max(server).min(MAX_DELAY)
}

pub const JITTER_LOW: f64 = 1.0;
pub const JITTER_HIGH: f64 = 1.3;

pub fn with_jitter(base: Duration, factor: f64) -> Duration {
    let factor = if factor.is_finite() {
        factor.clamp(JITTER_LOW, JITTER_HIGH)
    } else {
        JITTER_LOW
    };
    base.mul_f64(factor).min(MAX_DELAY)
}

pub fn jitter_factor() -> f64 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};

    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u64(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0),
    );
    let steps = (JITTER_HIGH - JITTER_LOW) * 1000.0;
    JITTER_LOW + f64::from((hasher.finish() % (steps as u64 + 1)) as u32) / 1000.0
}

pub fn next_cursor(body: &Value) -> Option<String> {
    let next = body.get("_links")?.get("next")?.as_str()?;
    let q = next.split('?').nth(1)?;
    q.split('&')
        .find_map(|kv| kv.strip_prefix("cursor="))
        .map(percent_decode)
}

fn str_at(v: &Value, path: &[&str]) -> String {
    let mut cur = v;
    for key in path {
        match cur.get(key) {
            Some(next) => cur = next,
            None => return String::new(),
        }
    }
    cur.as_str().unwrap_or_default().to_string()
}

fn opt_str_at(v: &Value, path: &[&str]) -> Option<String> {
    let mut cur = v;
    for key in path {
        cur = cur.get(key)?;
    }
    cur.as_str().map(str::to_owned)
}

fn id_at(v: &Value, key: &str) -> Option<String> {
    let found = v.get(key)?;
    if let Some(s) = found.as_str() {
        return Some(s.to_string());
    }
    found.as_i64().map(|n| n.to_string())
}

fn parse_hits(body: &Value) -> Result<Vec<DocRef>, ConfluenceError> {
    let results = body
        .get("results")
        .and_then(Value::as_array)
        .ok_or_else(|| ConfluenceError::Malformed("results is not an array".into()))?;
    let mut out = Vec::with_capacity(results.len());
    for r in results {
        let content = r.get("content").unwrap_or(&Value::Null);
        let Some(id) = content.get("id").and_then(Value::as_str) else {
            continue;
        };
        let title = match opt_str_at(content, &["title"]) {
            Some(t) => t,
            None => str_at(r, &["title"]),
        };
        out.push(DocRef {
            id: id.to_string(),
            title,
            space: str_at(content, &["space", "key"]),
            modified: opt_str_at(r, &["lastModified"]),
        });
    }
    Ok(out)
}

impl<T: HttpTransport> DocumentSource for ConfluenceSource<T> {
    fn search(&self, space: &str, query: &SearchQuery) -> Result<Vec<DocRef>, String> {
        if !self.spaces.contains(space) {
            return Err(format!("space {space:?} is not configured for this source"));
        }
        let url = self.search_url(space, query, None);
        let resp = self.get(&url).map_err(|e| e.to_string())?;
        let body: Value = serde_json::from_str(&resp.body).map_err(|e| format!("search: {e}"))?;
        parse_hits(&body).map_err(|e| e.to_string())
    }

    fn fetch(&self, id: &str) -> Result<Document, String> {
        let url = format!(
            "{}/wiki/rest/api/content/{}?expand=body.storage,space,version",
            self.creds.base_url,
            percent_encode(id)
        );
        let resp = self.get(&url).map_err(|e| e.to_string())?;
        let body: Value = serde_json::from_str(&resp.body).map_err(|e| format!("page: {e}"))?;
        Ok(Document {
            doc: DocRef {
                id: id_at(&body, "id").unwrap_or_else(|| id.to_string()),
                title: str_at(&body, &["title"]),
                space: opt_str_at(&body, &["space", "key"])
                    .or_else(|| id_at(&body, "spaceId"))
                    .unwrap_or_default(),
                modified: opt_str_at(&body, &["version", "when"])
                    .or_else(|| opt_str_at(&body, &["version", "createdAt"])),
            },
            url: format!("{}/wiki/pages/{id}", self.creds.base_url),
            text: str_at(&body, &["body", "storage", "value"]),
            truncated: false,
        })
    }
}

fn cql_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use serde_json::json;

    use super::*;

    struct Fake {
        replies: RefCell<Vec<HttpResponse>>,
        seen: RefCell<Vec<(String, String)>>,
    }

    impl Fake {
        fn new(replies: Vec<HttpResponse>) -> Self {
            Self {
                replies: RefCell::new(replies),
                seen: RefCell::new(Vec::new()),
            }
        }
        fn ok(body: Value) -> Self {
            Self::new(vec![HttpResponse {
                status: 200,
                body: body.to_string(),
                retry_after: None,
            }])
        }
        fn urls(&self) -> Vec<String> {
            self.seen.borrow().iter().map(|(u, _)| u.clone()).collect()
        }
        fn auth(&self) -> String {
            self.seen
                .borrow()
                .first()
                .map(|(_, a)| a.clone())
                .unwrap_or_default()
        }
    }

    impl HttpTransport for Fake {
        fn get(&self, url: &str, auth: &str) -> Result<HttpResponse, String> {
            self.seen
                .borrow_mut()
                .push((url.to_string(), auth.to_string()));
            let mut r = self.replies.borrow_mut();
            if r.is_empty() {
                return Err("the fake ran out of replies".into());
            }
            Ok(r.remove(0))
        }
    }

    fn creds() -> Credentials {
        Credentials::new(
            "https://example.atlassian.net/wiki",
            "svc@example.com",
            "tok",
            None,
        )
        .expect("valid")
    }

    fn source(f: Fake) -> ConfluenceSource<Fake> {
        ConfluenceSource::new(f, creds(), ["ENG".to_string()]).with_sleeper(Box::new(|_| {}))
    }

    fn recording_source(
        f: Fake,
    ) -> (
        ConfluenceSource<Fake>,
        std::sync::Arc<std::sync::Mutex<Vec<Duration>>>,
    ) {
        let waits = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = std::sync::Arc::clone(&waits);
        let source = ConfluenceSource::new(f, creds(), ["ENG".to_string()])
            .with_sleeper(Box::new(move |d| seen.lock().expect("lock").push(d)));
        (source, waits)
    }

    fn hit(id: &str, space: &str) -> Value {
        json!({
            "content": {"id": id, "title": "Architecture", "space": {"key": space}},
            "lastModified": "2024-02-01T00:00:00.000Z"
        })
    }

    #[test]
    fn both_documented_hosts_are_accepted_and_nothing_else() {
        for ok in [
            "https://example.atlassian.net/wiki",
            "https://api.atlassian.com/ex/confluence/abc-123",
        ] {
            assert!(Credentials::new(ok, "a@b.c", "t", None).is_ok(), "{ok}");
        }
        for bad in [
            "https://evil.example.com/wiki",
            "https://atlassian.net.evil.com/wiki",
            "https://api.atlassian.com/other/path",
        ] {
            let e = Credentials::new(bad, "a@b.c", "t", None).expect_err(bad);
            assert!(
                matches!(e, ConfluenceError::UnsupportedHost(_)),
                "{bad}: {e:?}"
            );
        }
    }

    #[test]
    fn a_host_that_only_looks_like_atlassian_is_refused() {
        for bad in [
            "https://evil.example.com?x=.atlassian.net",
            "https://evil.example.com#.atlassian.net",
            "https://evil.example.com\\x.atlassian.net/wiki",
        ] {
            let result = Credentials::new(bad, "a@b.c", "t", None);
            let e = result
                .err()
                .unwrap_or_else(|| panic!("accepted a known bypass: {bad:?}"));
            assert!(
                matches!(e, ConfluenceError::UnsupportedHost(_)),
                "{bad}: {e:?}"
            );
        }

        for bad in [
            "https://evil.example.com/?x=.atlassian.net",
            "https://evil.example.com/#.atlassian.net",
            "https://evil.example.com/wiki?next=https://x.atlassian.net",
            "https://x.atlassian.net@evil.example.com/wiki",
            "https://user:pass@x.atlassian.net/wiki",
            "https://",
            "not even a url",
        ] {
            let result = Credentials::new(bad, "a@b.c", "t", None);
            let e = result.err().unwrap_or_else(|| panic!("accepted {bad:?}"));
            assert!(
                matches!(
                    e,
                    ConfluenceError::UnsupportedHost(_) | ConfluenceError::NotHttps(_)
                ),
                "{bad}: {e:?}"
            );
        }
    }

    #[test]
    fn a_legitimate_base_still_works_and_is_rebuilt_from_parsed_parts() {
        for (input, want) in [
            (
                "https://example.atlassian.net",
                "https://example.atlassian.net",
            ),
            (
                "https://example.atlassian.net/",
                "https://example.atlassian.net",
            ),
            (
                "https://example.atlassian.net/wiki",
                "https://example.atlassian.net",
            ),
            (
                "https://EXAMPLE.atlassian.net/wiki/",
                "https://example.atlassian.net",
            ),
            (
                "https://example.atlassian.net./wiki",
                "https://example.atlassian.net",
            ),
            (
                "https://api.atlassian.com/ex/confluence/abc-123",
                "https://api.atlassian.com/ex/confluence/abc-123",
            ),
            (
                "https://example.atlassian.net:8443/wiki",
                "https://example.atlassian.net:8443",
            ),
        ] {
            let c = Credentials::new(input, "a@b.c", "t", None)
                .unwrap_or_else(|e| panic!("{input}: {e:?}"));
            assert_eq!(c.base_url(), want, "from {input}");
        }
    }

    #[test]
    fn plain_http_is_refused_rather_than_upgraded() {
        let e = Credentials::new("http://example.atlassian.net/wiki", "a@b.c", "t", None)
            .expect_err("refused");
        assert!(matches!(e, ConfluenceError::NotHttps(_)), "{e:?}");
        assert!(e.to_string().contains("non-HTTPS"));
    }

    #[test]
    fn an_empty_credential_part_is_refused() {
        for (email, token, want) in [
            ("", "t", "email"),
            (" ", "t", "email"),
            ("a@b.c", "", "token"),
        ] {
            let e = Credentials::new("https://x.atlassian.net/wiki", email, token, None)
                .expect_err("refused");
            assert_eq!(e.to_string(), format!("{want} is required"));
        }
    }

    #[test]
    fn debug_never_prints_the_token() {
        let c = Credentials::new(
            "https://x.atlassian.net/wiki",
            "a@b.c",
            "s3cr3t-token",
            None,
        )
        .expect("valid");
        let shown = format!("{c:?}");
        assert!(!shown.contains("s3cr3t-token"), "{shown}");
        assert!(shown.contains("<redacted>"), "{shown}");
        assert!(shown.contains("x.atlassian.net"));
    }

    #[test]
    fn basic_auth_encodes_email_and_token() {
        let s = source(Fake::ok(json!({"results": []})));
        let _ = s.search("ENG", &SearchQuery::default());
        assert_eq!(s.transport.auth(), "Basic c3ZjQGV4YW1wbGUuY29tOnRvaw==");
    }

    #[test]
    fn base64_matches_known_vectors_including_padding() {
        for (input, want) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64(input.as_bytes()), want, "{input:?}");
        }
    }

    #[test]
    fn a_space_outside_the_configured_set_is_never_requested() {
        let s = source(Fake::ok(json!({"results": []})));
        let e = s
            .search("FINANCE", &SearchQuery::default())
            .expect_err("refused");
        assert!(e.contains("not configured"), "{e}");
        assert!(
            s.transport.urls().is_empty(),
            "it reached the network anyway"
        );
    }

    #[test]
    fn the_search_url_is_built_from_configured_parts() {
        let s = source(Fake::ok(json!({"results": []})));
        s.search(
            "ENG",
            &SearchQuery {
                label: Some("architecture".into()),
                terms: Vec::new(),
            },
        )
        .expect("ok");
        let url = &s.transport.urls()[0];
        assert!(
            url.starts_with("https://example.atlassian.net/wiki/rest/api/search?cql="),
            "{url}"
        );
        assert!(url.contains(&format!("limit={MAX_SEARCH_LIMIT}")), "{url}");
        assert!(url.contains("space%3D%22ENG%22"), "{url}");
        assert!(url.contains("label%3D%22architecture%22"), "{url}");
    }

    #[test]
    fn subject_terms_become_a_cql_full_text_or_group() {
        let s = source(Fake::ok(json!({"results": []})));
        s.search(
            "ENG",
            &SearchQuery::with_terms(["payments-api".into(), "Payments API".into()]),
        )
        .expect("ok");
        let cql = percent_decode(&s.transport.urls()[0]);
        assert!(cql.contains("type=page and space=\"ENG\""), "{cql}");
        assert!(
            cql.contains("and (text ~ \"payments-api\" or text ~ \"Payments API\")"),
            "{cql}"
        );
    }

    #[test]
    fn no_terms_leaves_the_query_exactly_as_it_was() {
        let s = source(Fake::ok(json!({"results": []})));
        s.search("ENG", &SearchQuery::default()).expect("ok");
        let cql = percent_decode(&s.transport.urls()[0]);
        assert!(cql.contains("cql=type=page and space=\"ENG\"&"), "{cql}");
        assert!(!cql.contains("text ~"), "{cql}");
        assert!(!cql.contains("()"), "{cql}");
    }

    #[test]
    fn a_label_and_terms_both_narrow_the_same_query() {
        let s = source(Fake::ok(json!({"results": []})));
        s.search(
            "ENG",
            &SearchQuery {
                label: Some("architecture".into()),
                terms: vec!["payments-api".into()],
            },
        )
        .expect("ok");
        let cql = percent_decode(&s.transport.urls()[0]);
        assert!(cql.contains("space=\"ENG\""), "{cql}");
        assert!(cql.contains("label=\"architecture\""), "{cql}");
        assert!(cql.contains("text ~ \"payments-api\""), "{cql}");
    }

    #[test]
    fn a_crafted_term_cannot_escape_its_cql_clause() {
        let s = source(Fake::ok(json!({"results": []})));
        s.search(
            "ENG",
            &SearchQuery::with_terms(["a\" or space=\"FINANCE".into()]),
        )
        .expect("ok");
        let cql = percent_decode(&s.transport.urls()[0]);
        assert!(cql.contains(r#"text ~ "a\" or space=\"FINANCE""#), "{cql}");
        assert!(
            !cql.contains("and space=\"FINANCE\""),
            "a term added a clause: {cql}"
        );
    }

    #[test]
    fn a_crafted_space_name_cannot_escape_the_query_or_the_cql() {
        let empty = || HttpResponse {
            status: 200,
            body: json!({"results": []}).to_string(),
            retry_after: None,
        };
        let f = Fake::new(vec![empty(), empty()]);
        let s = ConfluenceSource::new(
            f,
            creds(),
            ["A\" or space=\"B".to_string(), "x&limit=9999".to_string()],
        );
        s.search("A\" or space=\"B", &SearchQuery::default())
            .expect("ok");
        s.search("x&limit=9999", &SearchQuery::default())
            .expect("ok");
        for url in s.transport.urls() {
            let cql = url.split("cql=").nth(1).unwrap().split('&').next().unwrap();
            assert!(!cql.contains('"'), "{url}");
            assert!(!cql.contains('='), "{url}");
            assert_eq!(url.matches("limit=").count(), 1, "{url}");
            assert!(url.contains(&format!("limit={MAX_SEARCH_LIMIT}")), "{url}");
        }
    }

    #[test]
    fn cql_escaping_handles_quotes_and_backslashes() {
        assert_eq!(cql_escape(r#"a"b"#), r#"a\"b"#);
        assert_eq!(cql_escape(r"a\b"), r"a\\b");
        assert_eq!(cql_escape("plain"), "plain");
    }

    #[test]
    fn only_the_cursor_is_taken_from_a_next_link() {
        let body =
            json!({"_links": {"next": "/rest/api/search?cql=type=page&limit=25&cursor=raNDoM"}});
        assert_eq!(next_cursor(&body).as_deref(), Some("raNDoM"));
    }

    #[test]
    fn a_next_link_pointing_at_another_host_yields_only_its_cursor() {
        let body = json!({"_links": {"next": "https://evil.example.com/steal?cursor=abc"}});
        assert_eq!(next_cursor(&body).as_deref(), Some("abc"));
    }

    #[test]
    fn a_missing_or_shapeless_next_link_yields_no_cursor() {
        for body in [
            json!({}),
            json!({"_links": {}}),
            json!({"_links": {"next": 7}}),
            json!({"_links": {"next": "/rest/api/search"}}),
            json!({"_links": {"next": "/rest/api/search?limit=25"}}),
        ] {
            assert_eq!(next_cursor(&body), None, "{body}");
        }
    }

    #[test]
    fn a_cursor_is_percent_decoded_then_re_encoded_into_our_own_url() {
        let body = json!({"_links": {"next": "/x?cursor=a%2Fb%20c"}});
        let cursor = next_cursor(&body).expect("a cursor");
        assert_eq!(cursor, "a/b c");
        let s = source(Fake::ok(json!({"results": []})));
        let url = s.search_url("ENG", &SearchQuery::default(), Some(&cursor));
        assert!(url.contains("cursor=a%2Fb%20c"), "{url}");
        assert!(url.starts_with("https://example.atlassian.net/"), "{url}");
    }

    #[test]
    fn percent_decoding_leaves_malformed_escapes_alone() {
        assert_eq!(percent_decode("a%2Fb"), "a/b");
        assert_eq!(percent_decode("a%zzb"), "a%zzb");
        assert_eq!(percent_decode("a%2"), "a%2");
        assert_eq!(percent_decode("plain"), "plain");
    }

    #[test]
    fn a_hit_carries_its_id_title_space_and_age() {
        let s = source(Fake::ok(json!({"results": [hit("123", "ENG")]})));
        let docs = s.search("ENG", &SearchQuery::default()).expect("ok");
        assert_eq!(docs.len(), 1);
        assert_eq!(docs[0].id, "123");
        assert_eq!(docs[0].title, "Architecture");
        assert_eq!(docs[0].space, "ENG");
        assert_eq!(
            docs[0].modified.as_deref(),
            Some("2024-02-01T00:00:00.000Z")
        );
    }

    #[test]
    fn a_hit_without_a_content_id_is_dropped_not_half_carried() {
        let s = source(Fake::ok(json!({"results": [
            json!({"title": "no content key"}),
            hit("9", "ENG"),
        ]})));
        let docs = s.search("ENG", &SearchQuery::default()).expect("ok");
        assert_eq!(docs.len(), 1);
        assert_eq!(docs[0].id, "9");
    }

    #[test]
    fn a_response_without_results_is_an_error_not_an_empty_list() {
        let s = source(Fake::ok(json!({"unexpected": true})));
        let e = s
            .search("ENG", &SearchQuery::default())
            .expect_err("refused");
        assert!(e.contains("results is not an array"), "{e}");
    }

    #[test]
    fn a_body_that_is_not_json_is_an_error() {
        let s = source(Fake::new(vec![HttpResponse {
            status: 200,
            body: "<html>nope".into(),
            retry_after: None,
        }]));
        assert!(s
            .search("ENG", &SearchQuery::default())
            .expect_err("refused")
            .contains("search:"));
    }

    #[test]
    fn a_fetch_reads_the_storage_body_the_space_key_and_the_version_date() {
        let s = source(Fake::ok(json!({
            "id": "123", "title": "Arch",
            "space": {"key": "ENG", "id": 42},
            "version": {"when": "2024-03-04T00:00:00Z"},
            "body": {"storage": {"value": "<p>text</p>"}}
        })));
        let d = s.fetch("123").expect("ok");
        assert_eq!(d.doc.id, "123");
        assert_eq!(d.doc.space, "ENG");
        assert_eq!(d.doc.modified.as_deref(), Some("2024-03-04T00:00:00Z"));
        assert_eq!(d.text, "<p>text</p>");
        assert!(d.url.ends_with("/wiki/pages/123"));
        let url = &s.transport.urls()[0];
        assert!(url.contains("/wiki/rest/api/content/123"), "{url}");
        assert!(url.contains("expand=body.storage,space,version"), "{url}");
    }

    #[test]
    fn a_numeric_space_id_is_carried_but_does_not_match_a_key_allowlist() {
        let s = source(Fake::ok(json!({
            "id": "123", "title": "Arch", "spaceId": 42,
            "body": {"storage": {"value": "x"}}
        })));
        let d = s.fetch("123").expect("ok");
        assert_eq!(d.doc.space, "42");
        assert_ne!(d.doc.space, "ENG", "it must not pass as the permitted key");
        assert!(!crate::Policy::new(["ENG".to_string()]).permits(&d.doc.space));
    }

    #[test]
    fn a_fetch_of_a_page_with_no_body_is_empty_rather_than_an_error() {
        let s = source(Fake::ok(json!({"id": "1", "title": "Empty"})));
        let d = s.fetch("1").expect("ok");
        assert_eq!(d.text, "");
        assert_eq!(d.doc.modified, None);
    }

    #[test]
    fn a_page_id_is_percent_encoded_into_the_path() {
        let s = source(Fake::ok(json!({"id": "x"})));
        let _ = s.fetch("../../admin");
        let url = &s.transport.urls()[0];
        assert!(!url.contains("../"), "a traversal reached the path: {url}");
        assert!(url.contains("..%2F..%2Fadmin"), "{url}");
    }

    #[test]
    fn a_non_success_status_is_reported_with_its_body() {
        let s = source(Fake::new(vec![HttpResponse {
            status: 403,
            body: "scope does not match".into(),
            retry_after: None,
        }]));
        let e = s
            .search("ENG", &SearchQuery::default())
            .expect_err("refused");
        assert!(e.contains("403"), "{e}");
        assert!(e.contains("scope does not match"), "{e}");
    }

    #[test]
    fn a_429_without_retry_after_is_not_retried() {
        let s = source(Fake::new(vec![HttpResponse {
            status: 429,
            body: String::new(),
            retry_after: None,
        }]));
        let e = s
            .search("ENG", &SearchQuery::default())
            .expect_err("refused");
        assert!(e.contains("still rate limited after 1 attempts"), "{e}");
        assert_eq!(s.transport.urls().len(), 1, "it retried anyway");
    }

    #[test]
    fn a_429_with_retry_after_is_retried_up_to_the_budget() {
        let limited = || HttpResponse {
            status: 429,
            body: String::new(),
            retry_after: Some(1),
        };
        let s = source(Fake::new(vec![
            limited(),
            limited(),
            limited(),
            limited(),
            limited(),
        ]));
        let e = s
            .search("ENG", &SearchQuery::default())
            .expect_err("refused");
        assert!(
            e.contains(&format!("after {} attempts", MAX_RETRIES + 1)),
            "{e}"
        );
        assert_eq!(s.transport.urls().len() as u32, MAX_RETRIES + 1);
    }

    #[test]
    fn a_429_that_then_succeeds_returns_the_success() {
        let s = source(Fake::new(vec![
            HttpResponse {
                status: 429,
                body: String::new(),
                retry_after: Some(1),
            },
            HttpResponse {
                status: 200,
                body: json!({"results": [hit("7", "ENG")]}).to_string(),
                retry_after: None,
            },
        ]));
        let docs = s.search("ENG", &SearchQuery::default()).expect("ok");
        assert_eq!(docs[0].id, "7");
        assert_eq!(s.transport.urls().len(), 2);
    }

    #[test]
    fn a_transport_failure_reaches_the_caller() {
        let s = source(Fake::new(Vec::new()));
        assert!(s
            .search("ENG", &SearchQuery::default())
            .expect_err("refused")
            .contains("ran out of replies"));
    }

    #[test]
    fn the_retry_delay_is_exponential_capped_and_respects_retry_after() {
        assert_eq!(retry_delay(0, None), Duration::from_secs(1));
        assert_eq!(retry_delay(1, None), Duration::from_secs(2));
        assert_eq!(retry_delay(2, None), Duration::from_secs(4));
        assert_eq!(retry_delay(20, None), MAX_DELAY);
        assert_eq!(retry_delay(0, Some(10)), Duration::from_secs(10));
        assert_eq!(retry_delay(3, Some(1)), Duration::from_secs(8));
        assert_eq!(retry_delay(0, Some(600)), MAX_DELAY);
    }

    #[test]
    fn jitter_only_ever_lengthens_a_wait_and_stays_within_the_cap() {
        let base = Duration::from_secs(4);
        assert_eq!(with_jitter(base, 1.0), base);
        assert_eq!(with_jitter(base, 1.3), Duration::from_millis(5200));
        assert_eq!(with_jitter(base, 0.5), base);
        assert_eq!(with_jitter(base, 99.0), Duration::from_millis(5200));
        assert_eq!(with_jitter(base, f64::NAN), base);
        assert_eq!(with_jitter(base, f64::INFINITY), base);
        assert_eq!(with_jitter(MAX_DELAY, JITTER_HIGH), MAX_DELAY);
        assert_eq!(with_jitter(Duration::ZERO, JITTER_HIGH), Duration::ZERO);
    }

    #[test]
    fn the_sampled_jitter_stays_in_range_and_actually_varies() {
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..500 {
            let f = jitter_factor();
            assert!(
                (JITTER_LOW..=JITTER_HIGH).contains(&f),
                "{f} is outside [{JITTER_LOW}, {JITTER_HIGH}]"
            );
            seen.insert((f * 1000.0) as u64);
        }
        assert!(
            seen.len() > 20,
            "only {} distinct factors in 500 draws; retries would stay in lockstep",
            seen.len()
        );
    }

    #[test]
    fn every_error_renders_and_is_a_std_error() {
        fn assert_error<E: std::error::Error>(_: &E) {}
        for (e, want) in [
            (
                ConfluenceError::UnsupportedHost("u".into()),
                "not a Confluence Cloud base URL",
            ),
            (ConfluenceError::NotHttps("u".into()), "non-HTTPS"),
            (
                ConfluenceError::MissingCredential("email"),
                "email is required",
            ),
            (
                ConfluenceError::Status {
                    status: 500,
                    body: "b".into(),
                },
                "answered 500",
            ),
            (
                ConfluenceError::RateLimited { attempts: 3 },
                "after 3 attempts",
            ),
            (
                ConfluenceError::Malformed("why".into()),
                "unexpected response shape",
            ),
        ] {
            assert!(e.to_string().contains(want), "{e:?}");
            assert_error(&e);
        }
    }

    #[test]
    fn a_hit_falls_back_to_the_result_level_title() {
        let s = source(Fake::ok(json!({"results": [
            {"content": {"id": "5", "space": {"key": "ENG"}}, "title": "outer title"}
        ]})));
        let docs = s.search("ENG", &SearchQuery::default()).expect("ok");
        assert_eq!(docs[0].title, "outer title");
    }

    #[test]
    fn a_fetch_reports_a_status_error_from_the_transport() {
        let s = source(Fake::new(vec![HttpResponse {
            status: 404,
            body: "no such page".into(),
            retry_after: None,
        }]));
        let e = s.fetch("1").expect_err("refused");
        assert!(e.contains("404"), "{e}");
        assert!(e.contains("no such page"), "{e}");
    }

    #[test]
    fn a_fetch_body_that_is_not_json_is_an_error_naming_the_stage() {
        let s = source(Fake::new(vec![HttpResponse {
            status: 200,
            body: "<html>".into(),
            retry_after: None,
        }]));
        assert!(s.fetch("1").expect_err("refused").contains("page:"));
    }

    #[test]
    fn a_numeric_page_id_becomes_a_string() {
        let s = source(Fake::ok(json!({"id": 123, "title": "N"})));
        assert_eq!(s.fetch("123").expect("ok").doc.id, "123");
    }

    #[test]
    fn a_response_with_no_id_falls_back_to_the_requested_one() {
        let s = source(Fake::ok(json!({"title": "No id"})));
        assert_eq!(s.fetch("req-42").expect("ok").doc.id, "req-42");
    }

    #[test]
    fn the_base_url_loses_a_trailing_slash_and_keeps_the_expiry_hint() {
        let c = Credentials::new(
            "https://x.atlassian.net/wiki/",
            "a@b.c",
            "t",
            Some("2027-01-01".into()),
        )
        .expect("valid");
        assert_eq!(c.base_url(), "https://x.atlassian.net");
        assert_eq!(c.expires_hint.as_deref(), Some("2027-01-01"));
    }

    #[test]
    fn a_rate_limited_request_waits_between_attempts() {
        let limited = || HttpResponse {
            status: 429,
            body: String::new(),
            retry_after: Some(1),
        };
        let (s, waits) = recording_source(Fake::new(vec![
            limited(),
            limited(),
            limited(),
            limited(),
            limited(),
        ]));
        let _ = s.search("ENG", &SearchQuery::default());

        let waited = waits.lock().expect("lock").clone();
        assert_eq!(waited.len(), MAX_RETRIES as usize, "{waited:?}");

        for (attempt, actual) in waited.iter().enumerate() {
            let base = retry_delay(attempt as u32, Some(1));
            assert!(
                *actual >= base && *actual <= base.mul_f64(JITTER_HIGH),
                "attempt {attempt}: {actual:?} is outside [{base:?}, {:?}]",
                base.mul_f64(JITTER_HIGH)
            );
        }
        for pair in waited.windows(2) {
            assert!(pair[1] > pair[0], "the backoff must grow: {waited:?}");
        }
    }

    #[test]
    fn a_successful_request_waits_for_nothing() {
        let (s, waits) = recording_source(Fake::ok(json!({"results": []})));
        s.search("ENG", &SearchQuery::default()).expect("ok");
        assert!(waits.lock().expect("lock").is_empty());
    }

    #[test]
    fn a_429_without_retry_after_waits_for_nothing() {
        let (s, waits) = recording_source(Fake::new(vec![HttpResponse {
            status: 429,
            body: String::new(),
            retry_after: None,
        }]));
        let _ = s.search("ENG", &SearchQuery::default());
        assert!(waits.lock().expect("lock").is_empty());
    }
}
