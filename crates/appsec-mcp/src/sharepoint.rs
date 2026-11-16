use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use serde_json::{json, Value};

use crate::confluence::{jitter_factor, retry_delay, with_jitter};
use crate::{BytesResponse, DocRef, Document, DocumentSource, HttpResponse, SearchQuery};

const GRAPH: &str = "https://graph.microsoft.com/v1.0";
const LOGIN: &str = "https://login.microsoftonline.com";
const SCOPE: &str = "https://graph.microsoft.com/.default";

const MAX_RETRIES: u32 = 4;

pub const MAX_SEARCH_SIZE: u32 = 200;

const MAX_QUERY_CHARS: usize = 2048;

const TEXT_EXTENSIONS: [&str; 20] = [
    "md", "markdown", "txt", "text", "csv", "tsv", "json", "yaml", "yml", "xml", "html", "htm",
    "log", "rst", "adoc", "asciidoc", "toml", "ini", "conf", "cfg",
];

pub trait GraphTransport {
    fn post_form(&self, url: &str, body: &str) -> Result<HttpResponse, String>;

    fn post_json(&self, url: &str, auth: &str, body: &str) -> Result<HttpResponse, String>;

    fn get_json(&self, url: &str, auth: &str) -> Result<HttpResponse, String>;

    fn get_unauthenticated(&self, url: &str) -> Result<BytesResponse, String>;
}

trait Throttled {
    fn status(&self) -> u16;
    fn retry_after(&self) -> Option<u64>;
}

impl Throttled for HttpResponse {
    fn status(&self) -> u16 {
        self.status
    }
    fn retry_after(&self) -> Option<u64> {
        self.retry_after
    }
}

impl Throttled for BytesResponse {
    fn status(&self) -> u16 {
        self.status
    }
    fn retry_after(&self) -> Option<u64> {
        self.retry_after
    }
}

#[derive(Clone)]
pub struct Credentials {
    tenant_id: String,
    client_id: String,
    client_secret: String,
    region: String,
    pub expires_hint: Option<String>,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("tenant_id", &self.tenant_id)
            .field("client_id", &self.client_id)
            .field("client_secret", &"<redacted>")
            .field("region", &self.region)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SharePointError {
    BadCredential(String),
    BadSite(String),
    BadId(String),
    Transport(String),
    Status { status: u16, body: String },
    RateLimited { attempts: u32 },
    Malformed(String),
    NoTerms,
    Unreadable { name: String, extension: String },
    Undecodable { name: String, cause: String },
}

impl std::fmt::Display for SharePointError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadCredential(w) => write!(f, "{w}"),
            Self::BadSite(s) => write!(
                f,
                "{s} is not a usable site; expected \
                 <tenant>.sharepoint.com:/sites/<name> \
                 (the sovereign clouds use other Graph hosts and are not supported)"
            ),
            Self::BadId(i) => write!(
                f,
                "{i:?} is not a document id from this source; \
                 expected <drive-id>|<item-id>"
            ),
            Self::Transport(e) => write!(f, "request failed: {e}"),
            Self::Status { status, body } => write!(f, "Microsoft Graph answered {status}: {body}"),
            Self::RateLimited { attempts } => write!(
                f,
                "still rate limited after {attempts} attempts; not retrying further"
            ),
            Self::Malformed(w) => write!(f, "unexpected response shape: {w}"),
            Self::NoTerms => write!(
                f,
                "a SharePoint search needs terms identifying the application; \
                 refusing to search the tenant for everything"
            ),
            Self::Unreadable { name, extension } => write!(
                f,
                "{name:?} is a .{extension} file, which cannot be read. \
                 Text formats: {}. Document formats: docx, docm, xlsx, xlsm, \
                 pptx, pptm, pdf. A scanned PDF holds an image of text rather \
                 than text, and yields nothing; export a text-bearing copy",
                TEXT_EXTENSIONS.join(", ")
            ),
            Self::Undecodable { name, cause } => {
                write!(f, "{name:?} could not be read: {cause}")
            }
        }
    }
}

impl std::error::Error for SharePointError {}

impl Credentials {
    pub fn new(
        tenant_id: &str,
        client_id: &str,
        client_secret: &str,
        region: &str,
        expires_hint: Option<String>,
    ) -> Result<Self, SharePointError> {
        let tenant_id = path_safe(tenant_id, "the tenant id")?;
        let client_id = path_safe(client_id, "the client id")?;
        let secret = client_secret.trim();
        if secret.is_empty() {
            return Err(SharePointError::BadCredential(
                "the client secret is required".into(),
            ));
        }
        let region = region.trim().to_ascii_uppercase();
        if region.is_empty() || !region.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err(SharePointError::BadCredential(format!(
                "the region {region:?} is not a data-location code like NAM or EUR; \
                 Graph requires one for an application-permission search"
            )));
        }
        Ok(Self {
            tenant_id,
            client_id,
            client_secret: secret.to_string(),
            region,
            expires_hint,
        })
    }

    pub fn region(&self) -> &str {
        &self.region
    }

    fn token_url(&self) -> String {
        format!("{LOGIN}/{}/oauth2/v2.0/token", self.tenant_id)
    }

    fn token_body(&self) -> String {
        format!(
            "client_id={}&client_secret={}&grant_type=client_credentials&scope={}",
            percent_encode(&self.client_id),
            percent_encode(&self.client_secret),
            percent_encode(SCOPE),
        )
    }
}

fn path_safe(value: &str, what: &str) -> Result<String, SharePointError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(SharePointError::BadCredential(format!(
            "{what} is required"
        )));
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
    {
        return Err(SharePointError::BadCredential(format!(
            "{what} may contain only letters, digits, dots and hyphens"
        )));
    }
    Ok(value.to_string())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiteRef {
    host: String,
    path: String,
}

impl SiteRef {
    pub fn parse(raw: &str) -> Result<Self, SharePointError> {
        let raw = raw.trim();
        let bad = || SharePointError::BadSite(raw.to_string());
        let (host, path) = raw.split_once(':').ok_or_else(bad)?;
        let host = host.trim().to_ascii_lowercase();
        if host.is_empty()
            || !host.ends_with(".sharepoint.com")
            || host.starts_with('.')
            || !host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
        {
            return Err(bad());
        }
        let path = path.trim();
        if !path.starts_with('/') || path.contains("..") {
            return Err(bad());
        }
        if path
            .chars()
            .any(|c| c.is_control() || matches!(c, '?' | '#' | '\\' | '%'))
        {
            return Err(bad());
        }
        Ok(Self {
            host,
            path: path.to_string(),
        })
    }

    fn url(&self) -> String {
        let encoded: Vec<String> = self
            .path
            .split('/')
            .filter(|s| !s.is_empty())
            .map(percent_encode)
            .collect();
        format!("{GRAPH}/sites/{}:/{}", self.host, encoded.join("/"))
    }
}

pub struct SharePointSource<T: GraphTransport> {
    transport: T,
    creds: Credentials,
    sites: BTreeSet<String>,
    token: RefCell<Option<String>>,
    resolved: RefCell<BTreeMap<String, String>>,
    resolved_all: std::cell::Cell<bool>,
    size: u32,
    sleeper: Box<dyn Fn(Duration) + Send + Sync>,
}

impl<T: GraphTransport> SharePointSource<T> {
    pub fn new(transport: T, creds: Credentials, sites: impl IntoIterator<Item = String>) -> Self {
        Self {
            transport,
            creds,
            sites: sites.into_iter().collect(),
            token: RefCell::new(None),
            resolved: RefCell::new(BTreeMap::new()),
            resolved_all: std::cell::Cell::new(false),
            size: MAX_SEARCH_SIZE,
            sleeper: Box::new(std::thread::sleep),
        }
    }

    #[cfg(test)]
    fn with_sleeper(mut self, sleeper: Box<dyn Fn(Duration) + Send + Sync>) -> Self {
        self.sleeper = sleeper;
        self
    }

    fn send<R: Throttled>(
        &self,
        mut call: impl FnMut() -> Result<R, String>,
    ) -> Result<R, SharePointError> {
        let mut attempt = 0;
        loop {
            let resp = call().map_err(SharePointError::Transport)?;
            if resp.status() != 429 {
                return Ok(resp);
            }
            attempt += 1;
            if attempt > MAX_RETRIES {
                return Err(SharePointError::RateLimited { attempts: attempt });
            }
            (self.sleeper)(with_jitter(
                retry_delay(attempt - 1, resp.retry_after()),
                jitter_factor(),
            ));
        }
    }

    fn token(&self) -> Result<String, SharePointError> {
        if let Some(cached) = self.token.borrow().clone() {
            return Ok(cached);
        }
        let url = self.creds.token_url();
        let body = self.creds.token_body();
        let resp = self.send(|| self.transport.post_form(&url, &body))?;
        if resp.status != 200 {
            return Err(SharePointError::Status {
                status: resp.status,
                body: resp.body,
            });
        }
        let parsed: Value = serde_json::from_str(&resp.body).map_err(|e| {
            SharePointError::Malformed(format!("the token reply was not JSON: {e}"))
        })?;
        let token = parsed
            .get("access_token")
            .and_then(Value::as_str)
            .filter(|t| !t.is_empty())
            .ok_or_else(|| {
                SharePointError::Malformed("the token reply carried no access_token".into())
            })?;
        let header = format!("Bearer {token}");
        *self.token.borrow_mut() = Some(header.clone());
        Ok(header)
    }

    fn forget_token(&self) {
        *self.token.borrow_mut() = None;
    }

    fn graph_get(&self, url: &str) -> Result<Value, SharePointError> {
        let mut refreshed = false;
        loop {
            let auth = self.token()?;
            let resp = self.send(|| self.transport.get_json(url, &auth))?;
            if resp.status == 401 && !refreshed {
                self.forget_token();
                refreshed = true;
                continue;
            }
            return decode(resp);
        }
    }

    fn site_id(&self, site: &str) -> Result<String, SharePointError> {
        let reference = SiteRef::parse(site)?;
        let body = self.graph_get(&reference.url())?;
        let id = body
            .get("id")
            .and_then(Value::as_str)
            .filter(|i| !i.is_empty())
            .ok_or_else(|| {
                SharePointError::Malformed(format!("the site {site:?} came back with no id"))
            })?;
        self.resolved
            .borrow_mut()
            .insert(id.to_string(), site.to_string());
        Ok(id.to_string())
    }

    fn configured_name(&self, site_id: &str) -> Option<String> {
        if let Some(found) = self.resolved.borrow().get(site_id) {
            return Some(found.clone());
        }
        if self.resolved_all.get() {
            return None;
        }
        for site in &self.sites {
            let _ = self.site_id(site);
            if let Some(found) = self.resolved.borrow().get(site_id) {
                return Some(found.clone());
            }
        }
        self.resolved_all.set(true);
        None
    }

    fn search_body(&self, query: &SearchQuery) -> Result<String, SharePointError> {
        let kql = kql_for(query)?;
        Ok(json!({
            "requests": [{
                "entityTypes": ["driveItem"],
                "query": {"queryString": kql},
                "region": self.creds.region,
                "from": 0,
                "size": self.size,
                "fields": [
                    "id", "name", "webUrl", "size",
                    "lastModifiedDateTime", "parentReference",
                ],
            }],
        })
        .to_string())
    }
}

fn decode(resp: HttpResponse) -> Result<Value, SharePointError> {
    if !(200..300).contains(&resp.status) {
        return Err(SharePointError::Status {
            status: resp.status,
            body: resp.body,
        });
    }
    serde_json::from_str(&resp.body)
        .map_err(|e| SharePointError::Malformed(format!("the reply was not JSON: {e}")))
}

fn kql_for(query: &SearchQuery) -> Result<String, SharePointError> {
    let mut phrases: Vec<String> = Vec::new();
    let mut used = 0usize;
    for term in &query.terms {
        let cleaned: String = term
            .chars()
            .filter(|c| !c.is_control() && *c != '"')
            .collect();
        let cleaned = cleaned.trim();
        if cleaned.is_empty() {
            continue;
        }
        let phrase = format!("\"{cleaned}\"");
        let cost = phrase.chars().count() + if phrases.is_empty() { 0 } else { 4 };
        if used + cost > MAX_QUERY_CHARS {
            break;
        }
        used += cost;
        if !phrases.contains(&phrase) {
            phrases.push(phrase);
        }
    }
    if phrases.is_empty() {
        return Err(SharePointError::NoTerms);
    }
    Ok(phrases.join(" OR "))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reading {
    AsText,
    AsDocument,
}

fn reading_for(name: &str) -> Result<Reading, SharePointError> {
    let extension = name
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();
    if TEXT_EXTENSIONS.contains(&extension.as_str()) {
        return Ok(Reading::AsText);
    }
    if appsec_doctext::Format::of_name(name).is_some() {
        return Ok(Reading::AsDocument);
    }
    Err(SharePointError::Unreadable {
        name: name.to_string(),
        extension: if extension.is_empty() {
            "(none)".into()
        } else {
            extension
        },
    })
}

fn join_id(drive: &str, item: &str) -> String {
    format!("{drive}|{item}")
}

fn split_id(id: &str) -> Result<(String, String), SharePointError> {
    let bad = || SharePointError::BadId(id.to_string());
    let (drive, item) = id.split_once('|').ok_or_else(bad)?;
    for half in [drive, item] {
        if half.is_empty()
            || !half
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '!' | '.' | '_' | '~' | '-'))
        {
            return Err(bad());
        }
    }
    Ok((drive.to_string(), item.to_string()))
}

fn str_at(v: &Value, path: &[&str]) -> String {
    opt_str_at(v, path).unwrap_or_default()
}

fn opt_str_at(v: &Value, path: &[&str]) -> Option<String> {
    let mut at = v;
    for key in path {
        at = at.get(key)?;
    }
    at.as_str()
        .map(str::to_owned)
        .filter(|s| !s.trim().is_empty())
}

fn hits_of(body: &Value) -> Result<Vec<&Value>, SharePointError> {
    let containers: Vec<&Value> = match body.get("value").and_then(Value::as_array) {
        Some(responses) => responses
            .iter()
            .filter_map(|r| r.get("hitsContainers").and_then(Value::as_array))
            .flatten()
            .collect(),
        None => body
            .get("hitsContainers")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                SharePointError::Malformed(
                    "the search reply carried neither value[] nor hitsContainers[]".into(),
                )
            })?
            .iter()
            .collect(),
    };
    Ok(containers
        .into_iter()
        .filter_map(|c| c.get("hits").and_then(Value::as_array))
        .flatten()
        .collect())
}

impl<T: GraphTransport> DocumentSource for SharePointSource<T> {
    fn search(&self, space: &str, query: &SearchQuery) -> Result<Vec<DocRef>, String> {
        if !self.sites.contains(space) {
            return Err(format!("site {space:?} is not configured for this source"));
        }
        self.search_site(space, query).map_err(|e| e.to_string())
    }

    fn fetch(&self, id: &str) -> Result<Document, String> {
        self.fetch_item(id).map_err(|e| e.to_string())
    }
}

impl<T: GraphTransport> SharePointSource<T> {
    fn search_site(
        &self,
        space: &str,
        query: &SearchQuery,
    ) -> Result<Vec<DocRef>, SharePointError> {
        let wanted = self.site_id(space)?;
        let body = self.search_body(query)?;
        let url = format!("{GRAPH}/search/query");

        let mut refreshed = false;
        let parsed = loop {
            let auth = self.token()?;
            let resp = self.send(|| self.transport.post_json(&url, &auth, &body))?;
            if resp.status == 401 && !refreshed {
                self.forget_token();
                refreshed = true;
                continue;
            }
            break decode(resp)?;
        };

        let hits = hits_of(&parsed)?;
        let total = hits.len();
        let mut out = Vec::new();
        let mut unaddressable = 0usize;
        for hit in hits {
            let resource = hit.get("resource").unwrap_or(&Value::Null);
            let drive = opt_str_at(resource, &["parentReference", "driveId"]);
            let site = opt_str_at(resource, &["parentReference", "siteId"]);
            let item = opt_str_at(resource, &["id"]).or_else(|| opt_str_at(hit, &["hitId"]));
            let (Some(drive), Some(site), Some(item)) = (drive, site, item) else {
                unaddressable += 1;
                continue;
            };
            if site != wanted {
                continue;
            }
            out.push(DocRef {
                id: join_id(&drive, &item),
                title: str_at(resource, &["name"]),
                space: space.to_string(),
                modified: opt_str_at(resource, &["lastModifiedDateTime"]),
            });
        }
        if total > 0 && unaddressable == total {
            return Err(SharePointError::Malformed(format!(
                "all {total} search hits lacked a drive id, a site id or an item id, \
                 so none could be addressed"
            )));
        }
        Ok(out)
    }

    fn fetch_item(&self, id: &str) -> Result<Document, SharePointError> {
        let (drive, item) = split_id(id)?;
        let url = format!(
            "{GRAPH}/drives/{}/items/{}\
             ?select=id,name,webUrl,size,lastModifiedDateTime,parentReference,\
             @microsoft.graph.downloadUrl",
            percent_encode(&drive),
            percent_encode(&item),
        );
        let body = self.graph_get(&url)?;

        let name = str_at(&body, &["name"]);
        let modified = opt_str_at(&body, &["lastModifiedDateTime"]);
        let site_id = opt_str_at(&body, &["parentReference", "siteId"]).unwrap_or_default();

        let Some(space) = self.configured_name(&site_id) else {
            return Ok(Document {
                doc: DocRef {
                    id: id.to_string(),
                    title: name,
                    space: format!("unconfigured-site:{site_id}"),
                    modified,
                },
                url: String::new(),
                text: String::new(),
                truncated: false,
            });
        };

        let reading = reading_for(&name)?;

        let download = opt_str_at(&body, &["@microsoft.graph.downloadUrl"]).ok_or_else(|| {
            SharePointError::Malformed(format!(
                "{name:?} came back with no @microsoft.graph.downloadUrl, so its \
                 content cannot be read without following a redirect"
            ))
        })?;
        if !download.starts_with("https://") {
            return Err(SharePointError::Malformed(format!(
                "the download URL for {name:?} was not HTTPS; refusing it"
            )));
        }
        let resp = self.send(|| self.transport.get_unauthenticated(&download))?;
        if !(200..300).contains(&resp.status) {
            return Err(SharePointError::Status {
                status: resp.status,
                body: String::from_utf8_lossy(&resp.body).into_owned(),
            });
        }

        let (text, truncated) = decode_document(&name, reading, resp.body)?;

        Ok(Document {
            doc: DocRef {
                id: id.to_string(),
                title: name,
                space,
                modified,
            },
            url: str_at(&body, &["webUrl"]),
            text,
            truncated,
        })
    }
}

fn decode_document(
    name: &str,
    reading: Reading,
    bytes: Vec<u8>,
) -> Result<(String, bool), SharePointError> {
    match reading {
        Reading::AsText => String::from_utf8(bytes)
            .map(|text| (text, false))
            .map_err(|_| SharePointError::Undecodable {
                name: name.to_string(),
                cause: "the file is not valid UTF-8 text".into(),
            }),
        Reading::AsDocument => {
            let limits = appsec_doctext::Limits::default();
            let got = appsec_doctext::extract(name, &bytes, &limits).map_err(|e| {
                SharePointError::Undecodable {
                    name: name.to_string(),
                    cause: e.to_string(),
                }
            })?;
            Ok((got.text, got.truncated))
        }
    }
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

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Call {
        kind: &'static str,
        url: String,
        auth: Option<String>,
        body: Option<String>,
    }

    struct Fake {
        replies: RefCell<Vec<HttpResponse>>,
        seen: RefCell<Vec<Call>>,
        binary: RefCell<Vec<Vec<u8>>>,
    }

    impl Fake {
        fn new(replies: Vec<HttpResponse>) -> Self {
            Self {
                replies: RefCell::new(replies),
                seen: RefCell::new(Vec::new()),
                binary: RefCell::new(Vec::new()),
            }
        }

        fn next(&self, call: Call) -> Result<HttpResponse, String> {
            self.seen.borrow_mut().push(call);
            let mut left = self.replies.borrow_mut();
            if left.is_empty() {
                return Err("the script ran out of replies".into());
            }
            Ok(left.remove(0))
        }

        fn push_binary(&self, bytes: Vec<u8>) {
            self.binary.borrow_mut().push(bytes);
        }

        fn calls(&self) -> Vec<Call> {
            self.seen.borrow().clone()
        }

        fn urls(&self) -> Vec<String> {
            self.calls().into_iter().map(|c| c.url).collect()
        }
    }

    impl GraphTransport for Fake {
        fn post_form(&self, url: &str, body: &str) -> Result<HttpResponse, String> {
            self.next(Call {
                kind: "post_form",
                url: url.into(),
                auth: None,
                body: Some(body.into()),
            })
        }
        fn post_json(&self, url: &str, auth: &str, body: &str) -> Result<HttpResponse, String> {
            self.next(Call {
                kind: "post_json",
                url: url.into(),
                auth: Some(auth.into()),
                body: Some(body.into()),
            })
        }
        fn get_json(&self, url: &str, auth: &str) -> Result<HttpResponse, String> {
            self.next(Call {
                kind: "get_json",
                url: url.into(),
                auth: Some(auth.into()),
                body: None,
            })
        }
        fn get_unauthenticated(&self, url: &str) -> Result<BytesResponse, String> {
            let queued = {
                let mut waiting = self.binary.borrow_mut();
                (!waiting.is_empty()).then(|| waiting.remove(0))
            };
            if let Some(bytes) = queued {
                self.seen.borrow_mut().push(Call {
                    kind: "get_unauth",
                    url: url.into(),
                    auth: None,
                    body: None,
                });
                return Ok(BytesResponse {
                    status: 200,
                    body: bytes,
                    retry_after: None,
                });
            }
            let text = self.next(Call {
                kind: "get_unauth",
                url: url.into(),
                auth: None,
                body: None,
            })?;
            Ok(BytesResponse {
                status: text.status,
                body: text.body.into_bytes(),
                retry_after: text.retry_after,
            })
        }
    }

    const SITE: &str = "contoso.sharepoint.com:/sites/Engineering";
    const SITE_ID: &str = "contoso.sharepoint.com,aaa-bbb,ccc-ddd";
    const SECRET: &str = "s3cr3t+with/reserved=chars";

    fn ok(body: Value) -> HttpResponse {
        HttpResponse {
            status: 200,
            body: body.to_string(),
            retry_after: None,
        }
    }

    fn ok_text(body: &str) -> HttpResponse {
        HttpResponse {
            status: 200,
            body: body.into(),
            retry_after: None,
        }
    }

    fn status(code: u16, body: &str) -> HttpResponse {
        HttpResponse {
            status: code,
            body: body.into(),
            retry_after: None,
        }
    }

    fn creds() -> Credentials {
        Credentials::new(
            "contoso.onmicrosoft.com",
            "11111111-2222-3333-4444-555555555555",
            SECRET,
            "nam",
            Some("2027-01-01".into()),
        )
        .expect("valid credentials")
    }

    fn token_reply() -> HttpResponse {
        ok(json!({"access_token": "TOKEN-ABC", "expires_in": 3599}))
    }

    fn site_reply() -> HttpResponse {
        ok(json!({"id": SITE_ID, "displayName": "Engineering"}))
    }

    fn search_reply(hits: Vec<Value>) -> HttpResponse {
        ok(json!({"value": [{"hitsContainers": [{"hits": hits, "total": hits.len()}]}]}))
    }

    fn hit(name: &str, item: &str, site: &str) -> Value {
        json!({
            "hitId": item,
            "summary": "a snippet",
            "resource": {
                "id": item,
                "name": name,
                "webUrl": format!("https://contoso.sharepoint.com/sites/Engineering/{name}"),
                "size": 1024,
                "lastModifiedDateTime": "2026-03-04T05:06:07Z",
                "parentReference": {"driveId": "b!DRIVE", "siteId": site},
            },
        })
    }

    fn source(f: Fake) -> SharePointSource<Fake> {
        SharePointSource::new(f, creds(), [SITE.to_string()])
    }

    #[test]
    fn a_missing_or_unusable_credential_part_is_refused() {
        let cases: [(&str, &str, &str, &str); 7] = [
            ("", "cid", "sec", "NAM"),
            ("tenant", "", "sec", "NAM"),
            ("tenant", "cid", "   ", "NAM"),
            ("tenant", "cid", "sec", ""),
            ("tenant/../other", "cid", "sec", "NAM"),
            ("tenant?x=1", "cid", "sec", "NAM"),
            ("tenant", "cid#frag", "sec", "NAM"),
        ];
        for (tenant, cid, secret, region) in cases {
            let got = Credentials::new(tenant, cid, secret, region, None);
            assert!(
                got.is_err(),
                "({tenant:?}, {cid:?}, {secret:?}, {region:?}) was accepted"
            );
        }
    }

    #[test]
    fn the_region_is_required_and_normalised() {
        assert_eq!(creds().region(), "NAM", "a lowercase code is upper-cased");
        for bad in ["", "   ", "na m", "NAM-1", "nam!"] {
            assert!(
                Credentials::new("t", "c", "s", bad, None).is_err(),
                "region {bad:?} was accepted"
            );
        }
        let e = Credentials::new("t", "c", "s", "", None).expect_err("refused");
        assert!(e.to_string().contains("data-location code"), "{e}");
    }

    #[test]
    fn debug_never_prints_the_secret() {
        let rendered = format!("{:?}", creds());
        assert!(!rendered.contains(SECRET), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(rendered.contains("contoso.onmicrosoft.com"), "{rendered}");
        assert!(rendered.contains("NAM"), "{rendered}");
    }

    #[test]
    fn the_token_body_percent_encodes_the_secret_and_the_scope() {
        let body = creds().token_body();
        assert!(!body.contains(SECRET), "the raw secret reached the body");
        assert!(
            body.contains("client_secret=s3cr3t%2Bwith%2Freserved%3Dchars"),
            "{body}"
        );
        assert!(body.contains("grant_type=client_credentials"), "{body}");
        assert!(
            body.contains("scope=https%3A%2F%2Fgraph.microsoft.com%2F.default"),
            "{body}"
        );
    }

    #[test]
    fn the_token_url_is_the_documented_endpoint_for_the_tenant() {
        assert_eq!(
            creds().token_url(),
            "https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/token"
        );
    }

    #[test]
    fn a_site_is_parsed_into_the_documented_path_address() {
        let r = SiteRef::parse(SITE).expect("valid");
        assert_eq!(
            r.url(),
            "https://graph.microsoft.com/v1.0/sites/contoso.sharepoint.com:/sites/Engineering"
        );
        let upper = SiteRef::parse("CONTOSO.SharePoint.com:/sites/Eng").expect("valid");
        assert!(
            upper.url().contains("contoso.sharepoint.com"),
            "{}",
            upper.url()
        );
        assert!(upper.url().ends_with("/sites/Eng"), "{}", upper.url());
    }

    #[test]
    fn a_site_host_outside_sharepoint_online_is_refused() {
        for bad in [
            "evil.example.com:/sites/Eng",
            "contoso.sharepoint.com.evil.example.com:/sites/Eng",
            "contoso.sharepoint.cn:/sites/Eng",
            ".sharepoint.com:/sites/Eng",
            "contoso.sharepoint.com",
            ":/sites/Eng",
            "contoso.sharepoint.com:sites/Eng",
            "contoso.sharepoint.com:/sites/../../other",
            "contoso.sharepoint.com:/sites/Eng?x=1",
            "contoso.sharepoint.com:/sites/Eng#f",
            "contoso.sharepoint.com:/sites/Eng%2f..",
            "contoso.sharepoint.com:/sites/E\\ng",
        ] {
            assert!(SiteRef::parse(bad).is_err(), "{bad:?} was accepted");
        }
    }

    #[test]
    fn a_site_path_segment_with_a_space_is_encoded_not_sent_raw() {
        let r = SiteRef::parse("contoso.sharepoint.com:/sites/Platform Eng").expect("valid");
        assert!(r.url().ends_with("/sites/Platform%20Eng"), "{}", r.url());
    }

    #[test]
    fn terms_become_quoted_phrases_ored_together() {
        let q = SearchQuery::with_terms(["Payments API".into(), "payments-api".into()]);
        assert_eq!(
            kql_for(&q).expect("a query"),
            "\"Payments API\" OR \"payments-api\""
        );
    }

    #[test]
    fn a_term_that_looks_like_an_operator_is_a_phrase() {
        let q = SearchQuery::with_terms(["AND".into(), "NOT".into()]);
        assert_eq!(kql_for(&q).expect("a query"), "\"AND\" OR \"NOT\"");
    }

    #[test]
    fn a_quote_in_a_term_cannot_end_the_phrase() {
        let q = SearchQuery::with_terms(["a\" OR filetype:docx OR \"b".into()]);
        let built = kql_for(&q).expect("a query");
        assert_eq!(built, "\"a OR filetype:docx OR b\"");
        assert_eq!(built.matches('"').count(), 2, "{built}");
    }

    #[test]
    fn control_characters_and_blanks_drop_out_of_terms() {
        let q = SearchQuery::with_terms(["  spaced  ".into(), "a\nb".into()]);
        assert_eq!(kql_for(&q).expect("a query"), "\"spaced\" OR \"ab\"");
        assert!(SearchQuery::with_terms(["   ".into()]).terms.is_empty());
    }

    #[test]
    fn a_repeated_term_appears_once() {
        let q = SearchQuery::with_terms(["api".into(), "api".into()]);
        assert_eq!(kql_for(&q).expect("a query"), "\"api\"");
    }

    #[test]
    fn a_search_with_no_terms_is_refused_rather_than_matching_everything() {
        assert_eq!(
            kql_for(&SearchQuery::default()),
            Err(SharePointError::NoTerms)
        );
        let e = kql_for(&SearchQuery::default()).expect_err("refused");
        assert!(
            e.to_string().contains("refusing to search the tenant"),
            "{e}"
        );
    }

    #[test]
    fn the_query_length_cap_drops_whole_terms() {
        let long = "x".repeat(MAX_QUERY_CHARS - 10);
        let q = SearchQuery::with_terms([long.clone(), "dropped".into()]);
        let built = kql_for(&q).expect("a query");
        assert!(built.contains(&long), "the first term survived");
        assert!(!built.contains("dropped"), "{}", &built[..60]);
        assert!(built.chars().count() <= MAX_QUERY_CHARS, "{}", built.len());
        assert_eq!(built.matches('"').count() % 2, 0);
    }

    #[test]
    fn a_text_format_reads_as_text_and_an_office_one_as_a_package() {
        for name in ["design.md", "NOTES.TXT", "a.b.yaml", "runbook.adoc"] {
            assert_eq!(reading_for(name), Ok(Reading::AsText), "{name}");
        }
        for name in [
            "architecture.docx",
            "DESIGN.DOCX",
            "data.xlsx",
            "deck.pptx",
            "macros.docm",
        ] {
            assert_eq!(reading_for(name), Ok(Reading::AsDocument), "{name}");
        }
    }

    #[test]
    fn an_unreadable_format_is_refused_by_name_and_says_what_to_do() {
        for name in ["diagram.png", "legacy.doc", "archive.zip", "README"] {
            let e = reading_for(name).expect_err("refused");
            assert!(e.to_string().contains(name), "{e}");
        }
        let legacy = reading_for("legacy.doc").expect_err("refused");
        let rendered = legacy.to_string();
        assert!(rendered.contains(".doc"), "{rendered}");
        assert!(rendered.contains("docx"), "{rendered}");
        assert!(rendered.contains("pdf"), "{rendered}");
        assert!(rendered.contains("export"), "{rendered}");
        let bare = reading_for("README").expect_err("refused");
        assert!(bare.to_string().contains("(none)"), "{bare}");
    }

    #[test]
    fn an_id_carries_both_halves_of_a_graph_address_and_round_trips() {
        let id = join_id("b!DRIVE-1_x", "01ITEMID");
        assert_eq!(
            split_id(&id).expect("valid"),
            ("b!DRIVE-1_x".into(), "01ITEMID".into())
        );
    }

    #[test]
    fn an_id_that_could_escape_the_item_route_is_refused() {
        for bad in [
            "no-separator",
            "|item",
            "drive|",
            "drive|../../users/me",
            "drive/other|item",
            "drive|item?select=x",
            "drive|item#f",
            "drive|it%2Fem",
            "",
            "|",
        ] {
            assert!(split_id(bad).is_err(), "{bad:?} was accepted");
        }
    }

    #[test]
    fn a_search_sends_the_documented_request_and_returns_addressable_hits() {
        let f = Fake::new(vec![
            token_reply(),
            site_reply(),
            search_reply(vec![hit("design.md", "01AAA", SITE_ID)]),
        ]);
        let s = source(f);
        let docs = s
            .search(SITE, &SearchQuery::with_terms(["payments-api".into()]))
            .expect("a result");

        assert_eq!(docs.len(), 1);
        assert_eq!(docs[0].title, "design.md");
        assert_eq!(docs[0].space, SITE, "the operator's own string survives");
        assert_eq!(docs[0].id, "b!DRIVE|01AAA");
        assert_eq!(docs[0].modified.as_deref(), Some("2026-03-04T05:06:07Z"));

        let calls = s.transport.calls();
        assert_eq!(
            calls.iter().map(|c| c.kind).collect::<Vec<_>>(),
            ["post_form", "get_json", "post_json"]
        );
        assert_eq!(
            calls[2].url,
            "https://graph.microsoft.com/v1.0/search/query"
        );
        assert_eq!(calls[2].auth.as_deref(), Some("Bearer TOKEN-ABC"));

        let body: Value =
            serde_json::from_str(calls[2].body.as_deref().expect("a body")).expect("json");
        let request = &body["requests"][0];
        assert_eq!(request["entityTypes"], json!(["driveItem"]));
        assert_eq!(request["query"]["queryString"], "\"payments-api\"");
        assert_eq!(request["region"], "NAM");
        assert_eq!(request["size"], json!(MAX_SEARCH_SIZE));
        assert_eq!(request["from"], json!(0));
        let fields = request["fields"].as_array().expect("fields");
        assert!(fields.contains(&json!("parentReference")), "{fields:?}");
    }

    #[test]
    fn a_hit_from_another_site_is_dropped_even_though_the_search_found_it() {
        let f = Fake::new(vec![
            token_reply(),
            site_reply(),
            search_reply(vec![
                hit("ours.md", "01AAA", SITE_ID),
                hit("theirs.md", "01BBB", "finance.sharepoint.com,xxx,yyy"),
            ]),
        ]);
        let s = source(f);
        let docs = s
            .search(SITE, &SearchQuery::with_terms(["api".into()]))
            .expect("a result");
        assert_eq!(docs.len(), 1, "{docs:?}");
        assert_eq!(docs[0].title, "ours.md");
    }

    #[test]
    fn a_site_outside_the_configured_set_is_never_searched() {
        let f = Fake::new(vec![]);
        let s = source(f);
        let e = s
            .search(
                "finance.sharepoint.com:/sites/Payroll",
                &SearchQuery::with_terms(["api".into()]),
            )
            .expect_err("refused");
        assert!(e.contains("not configured"), "{e}");
        assert!(s.transport.calls().is_empty(), "it reached the network");
    }

    #[test]
    fn a_search_reply_without_the_value_envelope_is_still_read() {
        let f = Fake::new(vec![
            token_reply(),
            site_reply(),
            ok(json!({"hitsContainers": [{"hits": [hit("x.md", "01AAA", SITE_ID)]}]})),
        ]);
        let s = source(f);
        let docs = s
            .search(SITE, &SearchQuery::with_terms(["api".into()]))
            .expect("a result");
        assert_eq!(docs.len(), 1);
    }

    #[test]
    fn a_search_reply_in_neither_shape_is_an_error_not_an_empty_result() {
        let f = Fake::new(vec![token_reply(), site_reply(), ok(json!({"odd": true}))]);
        let e = source(f)
            .search(SITE, &SearchQuery::with_terms(["api".into()]))
            .expect_err("refused");
        assert!(e.contains("neither value[] nor hitsContainers[]"), "{e}");
    }

    #[test]
    fn one_unaddressable_hit_is_skipped_but_all_of_them_is_an_error() {
        let addressable = hit("ok.md", "01AAA", SITE_ID);
        let bare = json!({"hitId": "01BBB", "resource": {"name": "odd.md"}});

        let f = Fake::new(vec![
            token_reply(),
            site_reply(),
            search_reply(vec![addressable, bare.clone()]),
        ]);
        let docs = source(f)
            .search(SITE, &SearchQuery::with_terms(["api".into()]))
            .expect("a result");
        assert_eq!(docs.len(), 1, "the good hit survived");

        let f = Fake::new(vec![token_reply(), site_reply(), search_reply(vec![bare])]);
        let e = source(f)
            .search(SITE, &SearchQuery::with_terms(["api".into()]))
            .expect_err("refused");
        assert!(e.contains("could be addressed"), "{e}");
    }

    #[test]
    fn no_hits_at_all_is_an_empty_list_rather_than_an_error() {
        let f = Fake::new(vec![token_reply(), site_reply(), search_reply(vec![])]);
        assert!(source(f)
            .search(SITE, &SearchQuery::with_terms(["api".into()]))
            .expect("a result")
            .is_empty());
    }

    fn searched_source(extra: Vec<HttpResponse>) -> SharePointSource<Fake> {
        let mut replies = vec![
            token_reply(),
            site_reply(),
            search_reply(vec![hit("design.md", "01AAA", SITE_ID)]),
        ];
        replies.extend(extra);
        let s = source(Fake::new(replies));
        s.search(SITE, &SearchQuery::with_terms(["api".into()]))
            .expect("a search");
        s
    }

    fn item_reply(name: &str) -> HttpResponse {
        ok(json!({
            "id": "01AAA",
            "name": name,
            "webUrl": "https://contoso.sharepoint.com/sites/Engineering/design.md",
            "size": 42,
            "lastModifiedDateTime": "2026-03-04T05:06:07Z",
            "parentReference": {"driveId": "b!DRIVE", "siteId": SITE_ID},
            "@microsoft.graph.downloadUrl":
                "https://b0mpua-by3301.files.1drv.com/y23vmaga?token=opaque",
        }))
    }

    #[test]
    fn the_token_is_never_sent_anywhere_but_graph_and_never_to_the_download_host() {
        let s = searched_source(vec![item_reply("design.md"), ok_text("# Design\n")]);
        let doc = s.fetch("b!DRIVE|01AAA").expect("a document");
        assert_eq!(doc.text, "# Design\n");

        let calls = s.transport.calls();
        let download = calls.last().expect("a last call");
        assert_eq!(download.kind, "get_unauth");
        assert!(download.url.contains("files.1drv.com"), "{}", download.url);
        assert_eq!(
            download.auth, None,
            "the download carried a credential to an undocumented host"
        );

        for call in &calls {
            if let Some(auth) = &call.auth {
                assert!(
                    call.url.starts_with("https://graph.microsoft.com/"),
                    "a credential went to {}: {auth}",
                    call.url
                );
            }
            if call.kind != "post_form" {
                let rendered = format!("{call:?}");
                assert!(
                    !rendered.contains(SECRET),
                    "the secret reached {}",
                    call.url
                );
            }
        }
        let token_call = calls
            .iter()
            .find(|c| c.kind == "post_form")
            .expect("a token call");
        assert!(token_call.url.starts_with(LOGIN), "{}", token_call.url);
        assert_eq!(token_call.auth, None);
    }

    #[test]
    fn a_fetch_asks_graph_for_the_download_url_rather_than_following_a_redirect() {
        let s = searched_source(vec![item_reply("design.md"), ok_text("body")]);
        s.fetch("b!DRIVE|01AAA").expect("a document");
        let item_url = &s.transport.urls()[3];
        assert!(
            item_url.starts_with("https://graph.microsoft.com/v1.0/drives/b%21DRIVE/items/01AAA?"),
            "{item_url}"
        );
        assert!(
            item_url.contains("@microsoft.graph.downloadUrl"),
            "{item_url}"
        );
        assert!(item_url.contains("parentReference"), "{item_url}");
    }

    #[test]
    fn a_fetched_document_carries_its_site_title_url_and_age() {
        let s = searched_source(vec![item_reply("design.md"), ok_text("text here")]);
        let doc = s.fetch("b!DRIVE|01AAA").expect("a document");
        assert_eq!(doc.doc.title, "design.md");
        assert_eq!(doc.doc.space, SITE);
        assert_eq!(doc.doc.id, "b!DRIVE|01AAA");
        assert_eq!(doc.doc.modified.as_deref(), Some("2026-03-04T05:06:07Z"));
        assert_eq!(
            doc.url,
            "https://contoso.sharepoint.com/sites/Engineering/design.md"
        );
    }

    #[test]
    fn an_item_from_an_unconfigured_site_gets_a_space_no_allowlist_can_permit() {
        let elsewhere = ok(json!({
            "id": "01ZZZ",
            "name": "secret.md",
            "webUrl": "https://finance.sharepoint.com/sites/Payroll/secret.md",
            "parentReference": {"driveId": "b!OTHER", "siteId": "finance.sharepoint.com,x,y"},
            "@microsoft.graph.downloadUrl": "https://files.example.com/x",
        }));
        let s = searched_source(vec![elsewhere, site_reply(), ok_text("payroll")]);
        let doc = s.fetch("b!OTHER|01ZZZ").expect("a document");
        assert_eq!(
            doc.doc.space,
            "unconfigured-site:finance.sharepoint.com,x,y"
        );
        assert!(
            !crate::Policy::new([SITE.to_string()]).permits(&doc.doc.space),
            "the allowlist permitted an unconfigured site"
        );
    }

    #[test]
    fn an_unpermitted_site_never_has_its_filenames_named_in_an_error() {
        let elsewhere = ok(json!({
            "id": "01ZZZ",
            "name": "payroll-restructure-2027.docx",
            "webUrl": "https://finance.sharepoint.com/sites/Payroll/x.docx",
            "parentReference": {"driveId": "b!OTHER", "siteId": "finance.sharepoint.com,x,y"},
            "@microsoft.graph.downloadUrl": "https://files.example.com/x",
        }));
        let s = searched_source(vec![elsewhere, site_reply()]);
        let doc = s.fetch("b!OTHER|01ZZZ").expect("a refusable document");
        assert_eq!(
            doc.doc.space,
            "unconfigured-site:finance.sharepoint.com,x,y"
        );
        assert!(
            !crate::Policy::new([SITE.to_string()]).permits(&doc.doc.space),
            "the allowlist permitted an unconfigured site"
        );
        assert!(
            !s.transport.calls().iter().any(|c| c.kind == "get_unauth"),
            "it downloaded from an unpermitted site"
        );
    }

    #[test]
    fn an_unresolvable_site_is_not_swept_for_twice() {
        let elsewhere = || {
            ok(json!({
                "id": "01ZZZ", "name": "x.md",
                "parentReference": {"driveId": "b!OTHER", "siteId": "other.sharepoint.com,x,y"},
                "@microsoft.graph.downloadUrl": "https://files.example.com/x",
            }))
        };
        let s = searched_source(vec![elsewhere(), site_reply(), elsewhere()]);
        for _ in 0..2 {
            let doc = s.fetch("b!OTHER|01ZZZ").expect("a refusable document");
            assert!(doc.doc.space.starts_with("unconfigured-site:"));
        }
        assert_eq!(s.transport.calls().len(), 6, "{:?}", s.transport.urls());
    }

    #[test]
    fn an_unreadable_format_is_refused_before_its_bytes_are_downloaded() {
        let s = searched_source(vec![item_reply("diagram.png")]);
        let e = s.fetch("b!DRIVE|01AAA").expect_err("refused");
        assert!(e.contains("diagram.png"), "{e}");
        assert!(e.contains("cannot be read"), "{e}");
        assert_eq!(s.transport.calls().len(), 4);
        assert!(
            !s.transport.calls().iter().any(|c| c.kind == "get_unauth"),
            "it downloaded the bytes anyway"
        );
    }

    #[test]
    fn an_office_document_is_downloaded_and_read_as_text() {
        const MINIMAL: &[u8] = include_bytes!("../tests/support/minimal.docx");
        let s = searched_source(vec![item_reply("design.docx")]);
        s.transport.push_binary(MINIMAL.to_vec());

        let doc = s.fetch("b!DRIVE|01AAA").expect("a readable document");
        assert!(
            doc.text.contains("The payments API is internet facing."),
            "{:?}",
            doc.text
        );
        assert!(
            doc.text.contains("It reaches the cards database."),
            "{:?}",
            doc.text
        );
        assert!(!doc.truncated, "nothing should have been cut");
        assert_eq!(doc.doc.title, "design.docx");
        assert!(s.transport.calls().iter().any(|c| c.kind == "get_unauth"));
    }

    #[test]
    fn a_pdf_is_downloaded_and_read_as_text() {
        const MINIMAL: &[u8] = include_bytes!("../tests/support/minimal.pdf");
        let s = searched_source(vec![item_reply("architecture.pdf")]);
        s.transport.push_binary(MINIMAL.to_vec());

        let doc = s.fetch("b!DRIVE|01AAA").expect("a readable document");
        assert!(
            doc.text.contains("The payments API is internet facing."),
            "{:?}",
            doc.text
        );
        assert!(
            doc.text.contains("It reaches the cards database."),
            "{:?}",
            doc.text
        );
        assert!(s.transport.calls().iter().any(|c| c.kind == "get_unauth"));
    }

    #[test]
    fn a_pdf_with_no_text_is_reported_as_such_rather_than_as_empty() {
        let s = searched_source(vec![item_reply("scan.pdf")]);
        s.transport.push_binary(
            b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n\
              2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n\
              3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n\
              trailer\n<< /Root 1 0 R >>\n%%EOF\n"
                .to_vec(),
        );
        let e = s.fetch("b!DRIVE|01AAA").expect_err("no text in it");
        assert!(e.contains("scan.pdf"), "{e}");
        assert!(e.contains("scanned"), "{e}");
    }

    #[test]
    fn an_office_document_that_is_not_an_archive_says_why() {
        let s = searched_source(vec![item_reply("design.docx")]);
        s.transport.push_binary(b"%PDF-1.7 mislabelled".to_vec());
        let e = s.fetch("b!DRIVE|01AAA").expect_err("refused");
        assert!(e.contains("design.docx"), "{e}");
        assert!(e.contains("not a ZIP archive"), "{e}");
    }

    #[test]
    fn a_text_file_that_is_not_utf8_is_refused_rather_than_mangled() {
        let s = searched_source(vec![item_reply("notes.md")]);
        s.transport.push_binary(vec![0xFF, 0xFE, 0x00, 0x41]);
        let e = s.fetch("b!DRIVE|01AAA").expect_err("refused");
        assert!(e.contains("notes.md"), "{e}");
        assert!(e.contains("not valid UTF-8"), "{e}");
    }

    #[test]
    fn an_item_with_no_download_url_is_an_error_naming_the_document() {
        let no_url = ok(json!({
            "id": "01AAA", "name": "design.md",
            "parentReference": {"driveId": "b!DRIVE", "siteId": SITE_ID},
        }));
        let s = searched_source(vec![no_url]);
        let e = s.fetch("b!DRIVE|01AAA").expect_err("refused");
        assert!(e.contains("design.md"), "{e}");
        assert!(e.contains("no @microsoft.graph.downloadUrl"), "{e}");
    }

    #[test]
    fn a_non_https_download_url_is_refused() {
        let plain = ok(json!({
            "id": "01AAA", "name": "design.md",
            "parentReference": {"driveId": "b!DRIVE", "siteId": SITE_ID},
            "@microsoft.graph.downloadUrl": "http://files.example.com/x",
        }));
        let s = searched_source(vec![plain]);
        let e = s.fetch("b!DRIVE|01AAA").expect_err("refused");
        assert!(e.contains("not HTTPS"), "{e}");
        assert!(!s.transport.calls().iter().any(|c| c.kind == "get_unauth"));
    }

    #[test]
    fn a_failed_download_is_reported_with_its_status() {
        let s = searched_source(vec![item_reply("design.md"), status(403, "expired")]);
        let e = s.fetch("b!DRIVE|01AAA").expect_err("refused");
        assert!(e.contains("403"), "{e}");
        assert!(e.contains("expired"), "{e}");
    }

    #[test]
    fn a_malformed_id_never_reaches_the_network() {
        let f = Fake::new(vec![]);
        let s = source(f);
        let e = s.fetch("not-an-id").expect_err("refused");
        assert!(e.contains("not a document id"), "{e}");
        assert!(s.transport.calls().is_empty());
    }

    #[test]
    fn the_token_is_acquired_once_and_reused() {
        let s = searched_source(vec![item_reply("design.md"), ok_text("x")]);
        s.fetch("b!DRIVE|01AAA").expect("a document");
        assert_eq!(
            s.transport
                .calls()
                .iter()
                .filter(|c| c.kind == "post_form")
                .count(),
            1,
            "the token was re-acquired without a 401"
        );
    }

    #[test]
    fn a_401_re_acquires_the_token_once_and_retries() {
        let f = Fake::new(vec![
            token_reply(),
            status(401, "expired"),
            ok(json!({"access_token": "TOKEN-TWO"})),
            site_reply(),
            search_reply(vec![hit("x.md", "01AAA", SITE_ID)]),
        ]);
        let s = source(f);
        let docs = s
            .search(SITE, &SearchQuery::with_terms(["api".into()]))
            .expect("a result");
        assert_eq!(docs.len(), 1);
        let calls = s.transport.calls();
        assert_eq!(
            calls.iter().filter(|c| c.kind == "post_form").count(),
            2,
            "the token was not re-acquired"
        );
        assert_eq!(calls[3].auth.as_deref(), Some("Bearer TOKEN-TWO"));
    }

    #[test]
    fn a_second_401_is_reported_rather_than_looping() {
        let f = Fake::new(vec![
            token_reply(),
            status(401, "nope"),
            ok(json!({"access_token": "TOKEN-TWO"})),
            status(401, "still nope"),
        ]);
        let e = source(f)
            .search(SITE, &SearchQuery::with_terms(["api".into()]))
            .expect_err("refused");
        assert!(e.contains("401"), "{e}");
        assert!(e.contains("still nope"), "{e}");
    }

    #[test]
    fn a_429_is_retried_after_the_delay_the_server_asked_for() {
        let slept: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&slept);
        let f = Fake::new(vec![
            HttpResponse {
                status: 429,
                body: "slow down".into(),
                retry_after: Some(7),
            },
            token_reply(),
            site_reply(),
            search_reply(vec![hit("x.md", "01AAA", SITE_ID)]),
        ]);
        let s = source(f).with_sleeper(Box::new(move |d| {
            seen.fetch_add(d.as_secs() as usize, Ordering::SeqCst);
        }));
        let docs = s
            .search(SITE, &SearchQuery::with_terms(["api".into()]))
            .expect("a result");
        assert_eq!(docs.len(), 1);
        let waited = slept.load(Ordering::SeqCst);
        assert!(
            (7..=9).contains(&waited),
            "{waited}s is outside the jittered range for a 7s Retry-After"
        );
    }

    #[test]
    fn a_throttled_download_is_retried_on_the_delay_the_server_asked_for() {
        let slept: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&slept);
        let s = searched_source(vec![
            item_reply("design.md"),
            HttpResponse {
                status: 429,
                body: "slow down".into(),
                retry_after: Some(5),
            },
            ok_text("# Design"),
        ])
        .with_sleeper(Box::new(move |d| {
            seen.fetch_add(d.as_secs() as usize, Ordering::SeqCst);
        }));

        let doc = s
            .fetch("b!DRIVE|01AAA")
            .expect("a document after the retry");
        assert_eq!(doc.text, "# Design");
        let slept = slept.load(Ordering::SeqCst);
        assert!(
            (5..=6).contains(&slept),
            "the download must wait at least the 5s the server asked for, \
             and at most the jittered 1.3x of it; slept {slept}s"
        );
    }

    #[test]
    fn a_429_that_never_stops_gives_up_rather_than_retrying_forever() {
        let replies = (0..MAX_RETRIES + 2)
            .map(|_| HttpResponse {
                status: 429,
                body: "no".into(),
                retry_after: Some(1),
            })
            .collect();
        let s = source(Fake::new(replies)).with_sleeper(Box::new(|_| {}));
        let e = s
            .search(SITE, &SearchQuery::with_terms(["api".into()]))
            .expect_err("refused");
        assert!(e.contains("still rate limited"), "{e}");
        assert!(e.contains(&format!("{}", MAX_RETRIES + 1)), "{e}");
    }

    #[test]
    fn a_token_endpoint_failure_reports_the_reason_azure_gave() {
        let f = Fake::new(vec![status(
            401,
            r#"{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret"}"#,
        )]);
        let e = source(f)
            .search(SITE, &SearchQuery::with_terms(["api".into()]))
            .expect_err("refused");
        assert!(e.contains("AADSTS7000215"), "{e}");
    }

    #[test]
    fn a_token_reply_without_an_access_token_is_an_error() {
        for body in [json!({"token_type": "Bearer"}), json!({"access_token": ""})] {
            let f = Fake::new(vec![ok(body.clone())]);
            let e = source(f)
                .search(SITE, &SearchQuery::with_terms(["api".into()]))
                .expect_err("refused");
            assert!(e.contains("no access_token"), "{body}: {e}");
        }
    }

    #[test]
    fn a_token_reply_that_is_not_json_is_an_error() {
        let f = Fake::new(vec![ok_text("<html>sign in</html>")]);
        let e = source(f)
            .search(SITE, &SearchQuery::with_terms(["api".into()]))
            .expect_err("refused");
        assert!(e.contains("token reply was not JSON"), "{e}");
    }

    #[test]
    fn a_transport_failure_is_reported_not_swallowed() {
        let f = Fake::new(vec![]);
        let e = source(f)
            .search(SITE, &SearchQuery::with_terms(["api".into()]))
            .expect_err("refused");
        assert!(e.contains("request failed"), "{e}");
    }

    #[test]
    fn a_site_that_comes_back_with_no_id_is_an_error() {
        let f = Fake::new(vec![token_reply(), ok(json!({"displayName": "Eng"}))]);
        let e = source(f)
            .search(SITE, &SearchQuery::with_terms(["api".into()]))
            .expect_err("refused");
        assert!(e.contains("came back with no id"), "{e}");
    }

    #[test]
    fn a_graph_error_status_is_reported_with_its_body() {
        let f = Fake::new(vec![token_reply(), status(403, "Access denied")]);
        let e = source(f)
            .search(SITE, &SearchQuery::with_terms(["api".into()]))
            .expect_err("refused");
        assert!(e.contains("403"), "{e}");
        assert!(e.contains("Access denied"), "{e}");
    }

    #[test]
    fn a_term_that_cleans_away_to_nothing_is_dropped_not_emptied() {
        let q = SearchQuery {
            label: None,
            terms: vec!["\"".into(), "\u{7}\u{1}".into(), "ok".into()],
        };
        assert_eq!(kql_for(&q).expect("a query"), "\"ok\"");
        let all_gone = SearchQuery {
            label: None,
            terms: vec!["\"\"".into()],
        };
        assert_eq!(kql_for(&all_gone), Err(SharePointError::NoTerms));
    }

    #[test]
    fn a_fetch_with_no_prior_search_resolves_the_site_on_demand() {
        let f = Fake::new(vec![
            token_reply(),
            item_reply("design.md"),
            site_reply(),
            ok_text("# Design"),
        ]);
        let s = source(f);
        let doc = s.fetch("b!DRIVE|01AAA").expect("a document");
        assert_eq!(
            doc.doc.space, SITE,
            "the site was not mapped back to the configured string"
        );
        assert!(
            crate::Policy::new([SITE.to_string()]).permits(&doc.doc.space),
            "a permitted site was refused"
        );
        assert_eq!(
            s.transport
                .calls()
                .iter()
                .map(|c| c.kind)
                .collect::<Vec<_>>(),
            ["post_form", "get_json", "get_json", "get_unauth"]
        );
    }

    #[test]
    fn a_401_on_the_search_itself_re_acquires_the_token_and_retries() {
        let f = Fake::new(vec![
            token_reply(),
            site_reply(),
            status(401, "expired mid-scan"),
            ok(json!({"access_token": "TOKEN-TWO"})),
            search_reply(vec![hit("x.md", "01AAA", SITE_ID)]),
        ]);
        let s = source(f);
        let docs = s
            .search(SITE, &SearchQuery::with_terms(["api".into()]))
            .expect("a result");
        assert_eq!(docs.len(), 1);
        let calls = s.transport.calls();
        assert_eq!(calls.iter().filter(|c| c.kind == "post_form").count(), 2);
        let last = calls.last().expect("a last call");
        assert_eq!(last.kind, "post_json");
        assert_eq!(last.auth.as_deref(), Some("Bearer TOKEN-TWO"));
    }

    #[test]
    fn a_second_401_on_the_search_is_reported_rather_than_looping() {
        let f = Fake::new(vec![
            token_reply(),
            site_reply(),
            status(401, "no"),
            ok(json!({"access_token": "TOKEN-TWO"})),
            status(401, "still no"),
        ]);
        let e = source(f)
            .search(SITE, &SearchQuery::with_terms(["api".into()]))
            .expect_err("refused");
        assert!(e.contains("still no"), "{e}");
    }

    #[test]
    fn a_success_status_with_a_non_json_body_is_an_error() {
        let f = Fake::new(vec![token_reply(), ok_text("<html>sign in</html>")]);
        let e = source(f)
            .search(SITE, &SearchQuery::with_terms(["api".into()]))
            .expect_err("refused");
        assert!(e.contains("the reply was not JSON"), "{e}");
    }

    #[test]
    fn the_documented_limits_are_stated_rather_than_implied() {
        assert_eq!(MAX_SEARCH_SIZE, 200);
        assert_eq!(MAX_QUERY_CHARS, 2048);
        assert_eq!(MAX_RETRIES, 4);
        assert_eq!(GRAPH, "https://graph.microsoft.com/v1.0");
        assert_eq!(LOGIN, "https://login.microsoftonline.com");
        assert_eq!(SCOPE, "https://graph.microsoft.com/.default");
    }
}
