//! Dialect-independent failure classification for the two halting
//! transport errors, [`LlmError::Authentication`] (VVAH-E001) and
//! [`LlmError::ProxyOrTls`] (VVAH-E002).
//!
//! Both dialect crates call into this rather than each keeping its own
//! copy, because the Python original's two copies (`backends/llm/sdk.py`
//! `_AUTH_STATUS_RX`/`_PROXY_CAUSE_RX` and `backends/llm/openai.py`'s
//! `_OAI` twins) had already drifted: only the OpenAI one knows
//! "incorrect api key". This keeps the union, once.
//!
//! Pure string logic apart from walking a `std::error::Error` source
//! chain, so it needs no HTTP client and is unit-tested on plain text.

use std::sync::LazyLock;

use regex::Regex;

use crate::error::LlmError;
use crate::scrub::sanitize_error_body;

/// Authentication prose, ported from `sdk.py`/`openai.py`
/// `_AUTH_STATUS_RX*`. The `{0,24}` gaps are bounded on purpose: Python
/// once used `.*` and a 400 reading "invalid_request_error ... prompt is
/// too long: 300000 tokens" matched, so an oversized chunk was reported
/// as a bad credential.
///
/// **Deliberate divergence**: `token` must be a whole word here. Python's
/// `invalid[^\n]{0,24}token` also matches "Invalid 'max_tokens': ...",
/// the 400 a provider sends for an output budget over its cap, which
/// would turn the truncation retry's expected refusal (and any
/// misconfigured `max_tokens`) into a scan-halting credential error.
static AUTH_RX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)unauthorized|invalid[_ ]api[_ ]key|invalid[^\n]{0,24}\btoken\b|\btoken\b[^\n]{0,24}(?:expired|invalid|revoked)|authentication[_ ]failed|incorrect[_ ]api[_ ]key",
    )
    .unwrap()
});

/// Proxy/TLS causes, ported from `_PROXY_CAUSE_RX*` and extended with the
/// wording the Rust stack actually produces: rustls reports every
/// verifier rejection as "invalid peer certificate: <reason>"
/// (`UnknownIssuer`, `Expired`, `NotValidForName`, ...), a server that
/// refuses this client's mTLS certificate answers with a fatal alert, and
/// hyper-util's CONNECT tunnel says "tunnel error: ...".
///
/// **Deliberate divergence**: Python matches `CONNECT.*failed`
/// case-insensitively. Here that would catch reqwest's ordinary
/// "client error (Connect): dns error: failed to lookup address", and
/// turn a DNS blip into a scan halt, so only an upper-case `CONNECT` (the
/// HTTP method, as proxies spell it) counts.
static PROXY_RX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i:\b407\b|proxy[_ ]auth|tunnel[_ ](?:failed|error)|SSL.*CERTIFICATE|CERTIFICATE.*VERIFY.*FAILED|CERT_VERIFY_FAILED|certificate[_ ]verify[_ ]failed|invalid peer certificate|UnknownIssuer|received fatal alert: (?:BadCertificate|CertificateRequired|CertificateUnknown|UnknownCA|UnsupportedCertificate|CertificateExpired|CertificateRevoked))|\bCONNECT\b[^\n]*failed",
    )
    .unwrap()
});

/// Python's `status_code=407 if re.search(r"\b407\b", detail)`: the one
/// proxy failure whose status can be recovered from the cause text.
/// hyper-util never prints the number for a CONNECT refused with 407, it
/// says "proxy authorization required", so that wording counts too.
static STATUS_407_RX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b407\b|proxy authori[sz]ation required|proxy authentication required")
        .unwrap()
});

/// Statuses a retry can help, from Python's `backends/llm/models.py`
/// `RETRYABLE_STATUS`. Authentication prose on one of these is read as
/// an outage that happens to mention a token, never as a bad credential:
/// the transient ladder is what rides an outage out.
const RETRYABLE_STATUS: [u16; 6] = [429, 500, 502, 503, 504, 529];

/// The halting classification of an HTTP error status, or `None` when the
/// status is not an authentication or proxy failure and the dialect's own
/// classifier should decide.
///
/// Mirrors `sdk.py`/`openai.py`: a 401 is always authentication; any
/// other status whose body reads as an authentication failure is too,
/// unless the status is one a retry can help. A 407 is the proxy asking
/// for credentials of its own (VVAH-E002). Each dialect's
/// `classify_http_error` asks this first.
pub fn classify_auth_or_proxy_status(status: u16, body: &str) -> Option<LlmError> {
    if status == 407 {
        return Some(LlmError::ProxyOrTls {
            status: Some(status),
            message: sanitize_error_body(body),
        });
    }
    if status == 401 || (AUTH_RX.is_match(body) && !RETRYABLE_STATUS.contains(&status)) {
        return Some(LlmError::Authentication {
            status: Some(status),
            message: sanitize_error_body(body),
        });
    }
    None
}

/// Classify a failure to get any HTTP response at all (DNS, TCP, TLS, a
/// proxy tunnel). `connect_or_timeout` is the HTTP client's own verdict
/// that this was a connection-phase failure or a timeout (for reqwest,
/// `e.is_connect() || e.is_timeout()`).
///
/// The whole `source()` chain is read, not just the top-level message:
/// reqwest's own Display is "error sending request for url (...)", and
/// the certificate or tunnel detail that tells an operator what to fix
/// lives two or three causes down.
pub fn classify_transport_error(
    err: &(dyn std::error::Error + 'static),
    connect_or_timeout: bool,
) -> LlmError {
    classify_transport_text(&error_chain_text(err), connect_or_timeout)
}

/// [`classify_transport_error`] on already-flattened text, split out so
/// the classification is testable without constructing a real transport
/// error.
///
/// A proxy/TLS cause wins over everything: it cannot heal on a retry, so
/// the transient ladder would only delay the report of it (Python:
/// "VVAH-E002: proxy/TLS misconfiguration cannot heal, so don't burn the
/// retry budget"). Otherwise a connection-phase failure or timeout is a
/// retryable [`LlmError::ConnectionError`], and anything else is
/// [`LlmError::Other`].
pub fn classify_transport_text(chain: &str, connect_or_timeout: bool) -> LlmError {
    let message = sanitize_error_body(chain);
    if PROXY_RX.is_match(chain) {
        let status = STATUS_407_RX.is_match(chain).then_some(407);
        LlmError::ProxyOrTls { status, message }
    } else if connect_or_timeout {
        LlmError::ConnectionError { message }
    } else {
        LlmError::Other { message }
    }
}

/// `outer: cause: root cause`, skipping a cause whose text the previous
/// link already ends with (hyper and reqwest often repeat it). Bounded by
/// a fixed depth, since a chain is library-built but not guaranteed
/// acyclic.
fn error_chain_text(err: &(dyn std::error::Error + 'static)) -> String {
    const MAX_DEPTH: usize = 16;
    let mut out = err.to_string();
    let mut next = err.source();
    for _ in 0..MAX_DEPTH {
        let Some(cause) = next else { break };
        let text = cause.to_string();
        if !out.ends_with(&text) {
            out.push_str(": ");
            out.push_str(&text);
        }
        next = cause.source();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_401_is_always_authentication_whatever_the_body_says() {
        let err = classify_auth_or_proxy_status(401, "nothing useful").unwrap();
        assert_eq!(
            err,
            LlmError::Authentication {
                status: Some(401),
                message: "nothing useful".to_string()
            }
        );
    }

    #[test]
    fn a_407_is_a_proxy_error_not_an_auth_error() {
        assert_eq!(
            classify_auth_or_proxy_status(407, "Proxy Authentication Required"),
            Some(LlmError::ProxyOrTls {
                status: Some(407),
                message: "Proxy Authentication Required".to_string(),
            })
        );
    }

    #[test]
    fn auth_prose_on_a_non_retryable_status_is_authentication() {
        for body in [
            r#"{"error":{"code":"invalid_api_key"}}"#,
            "Incorrect API key provided",
            "the access token has expired",
            "Invalid bearer token",
            "authentication_failed",
            "Unauthorized",
        ] {
            assert_eq!(
                classify_auth_or_proxy_status(403, body),
                Some(LlmError::Authentication {
                    status: Some(403),
                    message: body.to_string(),
                })
            );
        }
    }

    /// A 503 whose body mentions an expired token is an outage, and the
    /// transient ladder is what rides one out.
    #[test]
    fn auth_prose_on_a_retryable_status_is_left_to_the_dialect() {
        for status in RETRYABLE_STATUS {
            assert_eq!(
                classify_auth_or_proxy_status(status, "token expired upstream"),
                None,
                "{status}"
            );
        }
    }

    /// The Python regression that bounded the gaps: an oversized prompt
    /// must never read as a bad credential.
    #[test]
    fn a_prompt_too_long_400_is_not_mistaken_for_an_auth_failure() {
        let body = "invalid_request_error: prompt is too long: 300000 tokens > 200000 maximum";
        assert_eq!(classify_auth_or_proxy_status(400, body), None);
    }

    /// The divergence from Python: an output budget over the provider's
    /// cap is a 400 naming `max_tokens`, and must stay a plain request
    /// error (the truncation retry relies on reading it as the cap).
    #[test]
    fn a_max_tokens_refusal_is_not_mistaken_for_an_auth_failure() {
        for body in [
            "Invalid 'max_tokens': integer above maximum value",
            "Invalid value for max_completion_tokens: 200000",
            "max_tokens is invalid for this model",
        ] {
            assert_eq!(classify_auth_or_proxy_status(400, body), None, "{body}");
        }
    }

    #[test]
    fn an_ordinary_400_is_left_to_the_dialect() {
        assert_eq!(classify_auth_or_proxy_status(400, "missing field"), None);
    }

    #[test]
    fn a_reflected_key_in_an_auth_body_is_redacted() {
        let raw = "Unauthorized: Authorization: Bearer sk-live-abcd1234efgh5678";
        let err = classify_auth_or_proxy_status(401, raw).unwrap();
        assert!(
            !err.to_string().contains("sk-live-abcd1234efgh5678"),
            "{err}"
        );
    }

    #[test]
    fn certificate_and_tunnel_failures_are_proxy_or_tls() {
        for chain in [
            "error sending request: client error (Connect): invalid peer certificate: UnknownIssuer",
            "invalid peer certificate: certificate expired: verification time 1 (UNIX)",
            "received fatal alert: CertificateRequired",
            "received fatal alert: BadCertificate",
            "tunnel error: unsuccessful",
            "tunnel error: failed to create underlying connection",
            "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed",
            "CONNECT tunnel failed, response 403",
        ] {
            assert_eq!(
                classify_transport_text(chain, true),
                LlmError::ProxyOrTls {
                    status: None,
                    message: chain.to_string(),
                }
            );
        }
    }

    #[test]
    fn a_proxy_auth_refusal_carries_its_407() {
        for chain in [
            "tunnel error: proxy authorization required",
            "proxy returned HTTP 407",
        ] {
            assert_eq!(
                classify_transport_text(chain, true),
                LlmError::ProxyOrTls {
                    status: Some(407),
                    message: chain.to_string(),
                }
            );
        }
    }

    /// The divergence from Python's case-insensitive `CONNECT.*failed`:
    /// reqwest's own "(Connect)" wording ahead of a DNS failure must stay
    /// an ordinary retryable connection error.
    #[test]
    fn a_dns_failure_after_reqwests_connect_label_is_still_a_connection_error() {
        let chain = "error sending request for url (https://gw/v1): client error (Connect): \
                     dns error: failed to lookup address information";
        assert!(matches!(
            classify_transport_text(chain, true),
            LlmError::ConnectionError { .. }
        ));
    }

    #[test]
    fn a_non_connect_non_tls_failure_is_other() {
        assert!(matches!(
            classify_transport_text("error decoding response body", false),
            LlmError::Other { .. }
        ));
    }

    #[derive(Debug)]
    struct Link(&'static str, Option<Box<Link>>);

    impl std::fmt::Display for Link {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(self.0)
        }
    }

    impl std::error::Error for Link {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            self.1
                .as_deref()
                .map(|l| l as &(dyn std::error::Error + 'static))
        }
    }

    #[test]
    fn classify_transport_error_reads_the_whole_source_chain() {
        let err = Link(
            "error sending request for url (https://gw/v1/messages)",
            Some(Box::new(Link(
                "client error (Connect)",
                Some(Box::new(Link(
                    "invalid peer certificate: UnknownIssuer",
                    None,
                ))),
            ))),
        );
        let classified = classify_transport_error(&err, true);
        assert_eq!(
            classified,
            LlmError::ProxyOrTls {
                status: None,
                message: "error sending request for url (https://gw/v1/messages): client error \
                          (Connect): invalid peer certificate: UnknownIssuer"
                    .to_string()
            }
        );
    }

    #[test]
    fn a_cause_the_outer_message_already_ends_with_is_not_repeated() {
        let err = Link(
            "connect failed: connection refused",
            Some(Box::new(Link("connection refused", None))),
        );
        assert_eq!(
            classify_transport_error(&err, true),
            LlmError::ConnectionError {
                message: "connect failed: connection refused".to_string()
            }
        );
    }

    /// A chain deeper than the walk's bound is cut off rather than
    /// followed forever.
    #[test]
    fn the_chain_walk_is_bounded() {
        let mut link = Link("root", None);
        for i in 0..40 {
            let text: &'static str = Box::leak(format!("<{i}>").into_boxed_str());
            link = Link(text, Some(Box::new(link)));
        }
        let text = error_chain_text(&link);
        assert!(!text.contains("root"), "walked past the bound: {text}");
    }
}
