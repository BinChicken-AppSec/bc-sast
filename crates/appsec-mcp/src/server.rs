use std::collections::BTreeSet;
use std::io::{BufRead, Write};

use serde_json::Value;

use crate::confluence::ConfluenceSource;
use crate::http::{ReqwestTransport, DEFAULT_MAX_BYTES, DEFAULT_TIMEOUT};
use crate::sharepoint::{SharePointSource, SiteRef};
use crate::{handle, DocumentSource, Policy};

pub const ENV_BASE_URL: &str = "BC_CONFLUENCE_BASE_URL";
pub const ENV_EMAIL: &str = "BC_CONFLUENCE_EMAIL";
pub const ENV_TOKEN: &str = "BC_CONFLUENCE_TOKEN";
pub const ENV_SPACES: &str = "BC_CONFLUENCE_SPACES";
pub const ENV_EXPIRES: &str = "BC_CONFLUENCE_TOKEN_EXPIRES";

pub const ENV_SP_TENANT: &str = "BC_SHAREPOINT_TENANT_ID";
pub const ENV_SP_CLIENT_ID: &str = "BC_SHAREPOINT_CLIENT_ID";
pub const ENV_SP_SECRET: &str = "BC_SHAREPOINT_CLIENT_SECRET";
pub const ENV_SP_REGION: &str = "BC_SHAREPOINT_REGION";
pub const ENV_SP_SITES: &str = "BC_SHAREPOINT_SITES";
pub const ENV_SP_EXPIRES: &str = "BC_SHAREPOINT_SECRET_EXPIRES";

pub const ENV_SOURCE: &str = "BC_CONTEXT_SOURCE";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    Confluence,
    SharePoint,
}

impl SourceKind {
    fn parse(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "" | "confluence" => Some(Self::Confluence),
            "sharepoint" | "onedrive" => Some(Self::SharePoint),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Confluence => "confluence",
            Self::SharePoint => "sharepoint",
        }
    }
}

#[derive(Debug)]
pub enum Backend {
    Confluence(crate::confluence::Credentials),
    SharePoint(crate::sharepoint::Credentials),
}

#[derive(Debug)]
pub struct Config {
    pub backend: Backend,
    pub spaces: BTreeSet<String>,
}

impl Config {
    pub fn kind(&self) -> SourceKind {
        match self.backend {
            Backend::Confluence(_) => SourceKind::Confluence,
            Backend::SharePoint(_) => SourceKind::SharePoint,
        }
    }
}

pub fn config_from_env(getenv: impl Fn(&str) -> Option<String>) -> Result<Config, String> {
    let required = |name: &str| -> Result<String, String> {
        match getenv(name) {
            Some(v) if !v.trim().is_empty() => Ok(v),
            _ => Err(format!("{name} is required and must not be empty")),
        }
    };

    let kind = match getenv(ENV_SOURCE) {
        Some(name) => SourceKind::parse(&name).ok_or_else(|| {
            format!("{ENV_SOURCE} is {name:?}; expected confluence or sharepoint")
        })?,
        None => SourceKind::Confluence,
    };
    let hint = |name: &str| getenv(name).filter(|v| !v.trim().is_empty());

    match kind {
        SourceKind::Confluence => {
            let base_url = required(ENV_BASE_URL)?;
            let email = required(ENV_EMAIL)?;
            let token = required(ENV_TOKEN)?;
            let spaces = allowlist(&required(ENV_SPACES)?, ENV_SPACES)?;
            let credentials =
                crate::confluence::Credentials::new(&base_url, &email, &token, hint(ENV_EXPIRES))
                    .map_err(|e| e.to_string())?;
            Ok(Config {
                backend: Backend::Confluence(credentials),
                spaces,
            })
        }
        SourceKind::SharePoint => {
            let tenant = required(ENV_SP_TENANT)?;
            let client_id = required(ENV_SP_CLIENT_ID)?;
            let secret = required(ENV_SP_SECRET)?;
            let region = required(ENV_SP_REGION)?;
            let sites = allowlist(&required(ENV_SP_SITES)?, ENV_SP_SITES)?;
            for site in &sites {
                SiteRef::parse(site).map_err(|e| format!("{ENV_SP_SITES}: {e}"))?;
            }
            let credentials = crate::sharepoint::Credentials::new(
                &tenant,
                &client_id,
                &secret,
                &region,
                hint(ENV_SP_EXPIRES),
            )
            .map_err(|e| e.to_string())?;
            Ok(Config {
                backend: Backend::SharePoint(credentials),
                spaces: sites,
            })
        }
    }
}

fn allowlist(raw: &str, name: &str) -> Result<BTreeSet<String>, String> {
    let set: BTreeSet<String> = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    if set.is_empty() {
        return Err(format!(
            "{name} listed nothing usable; an empty allowlist permits nothing"
        ));
    }
    Ok(set)
}

pub fn serve<R: BufRead, W: Write>(
    input: R,
    mut output: W,
    source: &dyn DocumentSource,
    policy: &Policy,
) -> Result<(), String> {
    for line in input.lines() {
        let line = line.map_err(|e| format!("reading the request stream failed: {e}"))?;
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<Value>(&line) {
            Ok(request) => handle(&request, source, policy),
            Err(e) => Some(crate::error(Value::Null, -32700, &e.to_string())),
        };
        if let Some(response) = response {
            writeln!(output, "{response}")
                .map_err(|e| format!("writing the response failed: {e}"))?;
            output
                .flush()
                .map_err(|e| format!("flushing failed: {e}"))?;
        }
    }
    Ok(())
}

pub fn run() -> Result<(), String> {
    let config = config_from_env(|k| std::env::var(k).ok())?;
    let transport = ReqwestTransport::new(DEFAULT_TIMEOUT, DEFAULT_MAX_BYTES)?;
    let policy = Policy::new(config.spaces.iter().cloned());
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let source: Box<dyn DocumentSource> = match config.backend {
        Backend::Confluence(creds) => Box::new(ConfluenceSource::new(
            transport,
            creds,
            config.spaces.clone(),
        )),
        Backend::SharePoint(creds) => Box::new(SharePointSource::new(
            transport,
            creds,
            config.spaces.clone(),
        )),
    };
    serve(stdin.lock(), stdout.lock(), source.as_ref(), &policy)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use serde_json::json;

    use super::*;
    use crate::{DocRef, Document, SearchQuery};

    fn env() -> HashMap<String, String> {
        [
            (ENV_BASE_URL, "https://example.atlassian.net"),
            (ENV_EMAIL, "svc@example.com"),
            (ENV_TOKEN, "a-scoped-service-account-token"),
            (ENV_SPACES, "ENG,SEC"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
    }

    fn from(map: &HashMap<String, String>) -> Result<Config, String> {
        config_from_env(|k| map.get(k).cloned())
    }

    struct Stub;

    impl DocumentSource for Stub {
        fn search(&self, space: &str, _query: &SearchQuery) -> Result<Vec<DocRef>, String> {
            Ok(vec![DocRef {
                id: "1".into(),
                title: "Architecture".into(),
                space: space.to_string(),
                modified: None,
            }])
        }
        fn fetch(&self, id: &str) -> Result<Document, String> {
            Ok(Document {
                doc: DocRef {
                    id: id.to_string(),
                    title: "Architecture".into(),
                    space: "ENG".into(),
                    modified: None,
                },
                url: "https://example.atlassian.net/wiki/pages/1".into(),
                text: "the gateway terminates TLS".into(),
                truncated: false,
            })
        }
    }

    fn serve_lines(input: &str) -> Vec<Value> {
        let mut out = Vec::new();
        serve(
            input.as_bytes(),
            &mut out,
            &Stub,
            &Policy::new(["ENG".to_string()]),
        )
        .expect("the loop should finish");
        String::from_utf8(out)
            .expect("utf-8")
            .lines()
            .map(|l| serde_json::from_str(l).expect("each response is one JSON object"))
            .collect()
    }

    fn confluence_of(config: &Config) -> &crate::confluence::Credentials {
        match &config.backend {
            Backend::Confluence(c) => c,
            Backend::SharePoint(_) => panic!("configured SharePoint, expected Confluence"),
        }
    }

    fn sharepoint_of(config: &Config) -> &crate::sharepoint::Credentials {
        match &config.backend {
            Backend::SharePoint(c) => c,
            Backend::Confluence(_) => panic!("configured Confluence, expected SharePoint"),
        }
    }

    fn sp_env() -> HashMap<String, String> {
        let mut e = HashMap::new();
        e.insert(ENV_SOURCE.to_string(), "sharepoint".into());
        e.insert(ENV_SP_TENANT.to_string(), "contoso.onmicrosoft.com".into());
        e.insert(ENV_SP_CLIENT_ID.to_string(), "1111-2222".into());
        e.insert(ENV_SP_SECRET.to_string(), "a-secret".into());
        e.insert(ENV_SP_REGION.to_string(), "NAM".into());
        e.insert(
            ENV_SP_SITES.to_string(),
            "contoso.sharepoint.com:/sites/Engineering,contoso.sharepoint.com:/sites/Platform"
                .into(),
        );
        e
    }

    #[test]
    fn a_complete_environment_configures_the_server() {
        let config = from(&env()).expect("valid");
        assert_eq!(
            confluence_of(&config).base_url(),
            "https://example.atlassian.net"
        );
        assert_eq!(
            config.spaces.iter().cloned().collect::<Vec<_>>(),
            ["ENG", "SEC"]
        );
    }

    #[test]
    fn each_required_variable_is_named_when_it_is_missing_or_blank() {
        for key in [ENV_BASE_URL, ENV_EMAIL, ENV_TOKEN, ENV_SPACES] {
            let mut missing = env();
            missing.remove(key);
            let e = from(&missing).expect_err("refused");
            assert_eq!(e, format!("{key} is required and must not be empty"));

            let mut blank = env();
            blank.insert(key.to_string(), "   ".into());
            let e = from(&blank).expect_err("refused");
            assert_eq!(e, format!("{key} is required and must not be empty"));
        }
    }

    #[test]
    fn no_error_message_echoes_the_token() {
        let secret = "s3cret-token-value";
        for key in [ENV_BASE_URL, ENV_EMAIL, ENV_SPACES] {
            let mut broken = env();
            broken.insert(ENV_TOKEN.to_string(), secret.into());
            broken.remove(key);
            let e = from(&broken).expect_err("refused");
            assert!(!e.contains(secret), "{key}: {e}");
        }
        let mut bad_host = env();
        bad_host.insert(ENV_TOKEN.to_string(), secret.into());
        bad_host.insert(ENV_BASE_URL.to_string(), "https://evil.example.com".into());
        let e = from(&bad_host).expect_err("refused");
        assert!(!e.contains(secret), "{e}");
        assert!(e.contains("not a Confluence Cloud base URL"), "{e}");
    }

    #[test]
    fn a_space_list_of_only_separators_permits_nothing_and_says_so() {
        let mut only_commas = env();
        only_commas.insert(ENV_SPACES.to_string(), " , , ".into());
        let e = from(&only_commas).expect_err("refused");
        assert!(e.contains("permits nothing"), "{e}");
    }

    #[test]
    fn spaces_are_trimmed_and_deduplicated() {
        let mut messy = env();
        messy.insert(ENV_SPACES.to_string(), " ENG , SEC,ENG, ".into());
        let config = from(&messy).expect("valid");
        assert_eq!(
            config.spaces.iter().cloned().collect::<Vec<_>>(),
            ["ENG", "SEC"]
        );
    }

    #[test]
    fn the_expiry_hint_is_optional_and_blank_counts_as_absent() {
        assert_eq!(
            confluence_of(&from(&env()).expect("valid")).expires_hint,
            None
        );

        let mut blank = env();
        blank.insert(ENV_EXPIRES.to_string(), "  ".into());
        assert_eq!(
            confluence_of(&from(&blank).expect("valid")).expires_hint,
            None
        );

        let mut set = env();
        set.insert(ENV_EXPIRES.to_string(), "2027-03-01".into());
        assert_eq!(
            confluence_of(&from(&set).expect("valid"))
                .expires_hint
                .as_deref(),
            Some("2027-03-01")
        );
    }

    #[test]
    fn a_bad_base_url_is_refused_at_startup_not_at_first_request() {
        let mut http = env();
        http.insert(
            ENV_BASE_URL.to_string(),
            "http://example.atlassian.net".into(),
        );
        assert!(from(&http).expect_err("refused").contains("non-HTTPS"));
    }

    #[test]
    fn config_debug_does_not_print_the_token() {
        let shown = format!("{:?}", from(&env()).expect("valid"));
        assert!(!shown.contains("a-scoped-service-account-token"), "{shown}");
        assert!(shown.contains("<redacted>"), "{shown}");
    }

    #[test]
    fn a_request_gets_exactly_one_response_line() {
        let responses =
            serve_lines(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).to_string());
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0]["id"], 1);
        assert!(responses[0]["result"]["tools"].is_array());
    }

    #[test]
    fn several_requests_are_answered_in_order() {
        let input = [
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).to_string(),
            json!({"jsonrpc": "2.0", "id": 2, "method": "initialize"}).to_string(),
        ]
        .join("\n");
        let responses = serve_lines(&input);
        assert_eq!(responses.len(), 2);
        assert_eq!(responses[0]["id"], 1);
        assert_eq!(responses[1]["id"], 2);
    }

    #[test]
    fn a_notification_produces_no_output() {
        let responses = serve_lines(&json!({"jsonrpc": "2.0", "method": "initialize"}).to_string());
        assert!(responses.is_empty(), "{responses:?}");
    }

    #[test]
    fn blank_lines_are_skipped_rather_than_answered() {
        let responses = serve_lines(&format!(
            "\n   \n{}\n\n",
            json!({"jsonrpc": "2.0", "id": 4, "method": "tools/list"})
        ));
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0]["id"], 4);
    }

    #[test]
    fn a_malformed_line_is_a_parse_error_and_the_loop_continues() {
        let responses = serve_lines(&format!(
            "{{not json\n{}\n",
            json!({"jsonrpc": "2.0", "id": 9, "method": "tools/list"})
        ));
        assert_eq!(responses.len(), 2);
        assert_eq!(responses[0]["error"]["code"], -32700);
        assert_eq!(responses[0]["id"], Value::Null);
        assert_eq!(responses[1]["id"], 9, "the next request is still served");
    }

    #[test]
    fn a_search_call_reaches_the_source_and_returns_its_hits() {
        let responses = serve_lines(
            &json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                    "params": {"name": "context_search", "arguments": {"space": "ENG"}}})
            .to_string(),
        );
        assert_eq!(responses.len(), 1);
        let text = responses[0]["result"].to_string();
        assert!(text.contains("Architecture"), "{text}");
        assert!(text.contains("ENG"), "{text}");
    }

    #[test]
    fn a_tool_call_reaches_the_source_and_returns_its_document() {
        let responses = serve_lines(
            &json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                    "params": {"name": "context_fetch", "arguments": {"id": "1"}}})
            .to_string(),
        );
        assert_eq!(responses.len(), 1);
        let text = responses[0]["result"].to_string();
        assert!(text.contains("the gateway terminates TLS"), "{text}");
    }

    #[test]
    fn an_empty_input_finishes_without_error() {
        assert!(serve(
            &b""[..],
            &mut Vec::new(),
            &Stub,
            &Policy::new(["ENG".to_string()])
        )
        .is_ok());
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
            if self.at_flush {
                Err(std::io::Error::other("flush failed"))
            } else {
                Ok(())
            }
        }
    }

    fn serve_to(writer: Failing) -> String {
        let request = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).to_string();
        serve(
            request.as_bytes(),
            writer,
            &Stub,
            &Policy::new(["ENG".to_string()]),
        )
        .expect_err("a failing writer is an error")
    }

    #[test]
    fn a_failing_write_is_reported() {
        let err = serve_to(Failing { at_flush: false });
        assert!(err.contains("writing the response failed"), "{err}");
    }

    #[test]
    fn a_failing_flush_is_reported() {
        let err = serve_to(Failing { at_flush: true });
        assert!(err.contains("flushing failed"), "{err}");
    }

    #[test]
    fn a_failing_reader_is_reported() {
        struct Broken;
        impl std::io::Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("stream reset"))
            }
        }
        let err = serve(
            std::io::BufReader::new(Broken),
            &mut Vec::new(),
            &Stub,
            &Policy::new(["ENG".to_string()]),
        )
        .expect_err("a reset stream is an error");
        assert!(err.contains("reading the request stream failed"), "{err}");
    }

    #[test]
    fn no_source_named_means_confluence_so_existing_deployments_keep_working() {
        assert_eq!(from(&env()).expect("valid").kind(), SourceKind::Confluence);
        let mut explicit = env();
        explicit.insert(ENV_SOURCE.to_string(), "Confluence".into());
        assert_eq!(
            from(&explicit).expect("valid").kind(),
            SourceKind::Confluence
        );
    }

    #[test]
    fn a_complete_sharepoint_environment_configures_that_backend() {
        for name in ["sharepoint", "SharePoint", "onedrive", " sharepoint "] {
            let mut asked = sp_env();
            asked.insert(ENV_SOURCE.to_string(), name.into());
            let config = from(&asked).expect("valid");
            assert_eq!(config.kind(), SourceKind::SharePoint, "{name}");
            assert_eq!(sharepoint_of(&config).region(), "NAM");
            assert_eq!(config.spaces.len(), 2);
        }
    }

    #[test]
    fn asking_for_sharepoint_without_its_variables_names_the_missing_one() {
        let mut asked = env();
        asked.insert(ENV_SOURCE.to_string(), "sharepoint".into());
        let e = from(&asked).expect_err("refused");
        assert!(e.contains(ENV_SP_TENANT), "{e}");
        assert!(e.contains("required"), "{e}");
    }

    #[test]
    fn every_sharepoint_variable_is_required() {
        for missing in [
            ENV_SP_TENANT,
            ENV_SP_CLIENT_ID,
            ENV_SP_SECRET,
            ENV_SP_REGION,
            ENV_SP_SITES,
        ] {
            let mut short = sp_env();
            short.remove(missing);
            let e = from(&short).expect_err("refused");
            assert!(e.contains(missing), "{missing} was not named: {e}");
        }
    }

    #[test]
    fn an_unaddressable_site_is_refused_at_startup() {
        let mut bad = sp_env();
        bad.insert(
            ENV_SP_SITES.to_string(),
            "evil.example.com:/sites/Engineering".into(),
        );
        let e = from(&bad).expect_err("refused");
        assert!(e.contains(ENV_SP_SITES), "{e}");
        assert!(e.contains("sharepoint.com"), "{e}");
    }

    #[test]
    fn a_sharepoint_failure_never_quotes_the_secret() {
        let mut bad = sp_env();
        bad.insert(ENV_SP_TENANT.to_string(), "tenant/../else".into());
        bad.insert(ENV_SP_SECRET.to_string(), "SUPER-SECRET-VALUE".into());
        let e = from(&bad).expect_err("refused");
        assert!(!e.contains("SUPER-SECRET-VALUE"), "{e}");
    }

    #[test]
    fn an_empty_site_list_permits_nothing_rather_than_everything() {
        let mut empty = sp_env();
        empty.insert(ENV_SP_SITES.to_string(), " , ,".into());
        let e = from(&empty).expect_err("refused");
        assert!(e.contains("permits nothing"), "{e}");
    }

    #[test]
    fn an_unknown_source_names_what_is_accepted() {
        let mut bad = env();
        bad.insert(ENV_SOURCE.to_string(), "notion".into());
        let e = from(&bad).expect_err("refused");
        assert!(e.contains("notion"), "{e}");
        assert!(e.contains("confluence or sharepoint"), "{e}");
    }

    #[test]
    fn each_kind_has_a_canonical_name() {
        assert_eq!(SourceKind::Confluence.as_str(), "confluence");
        assert_eq!(SourceKind::SharePoint.as_str(), "sharepoint");
    }
}
