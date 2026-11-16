use std::sync::LazyLock;

use regex::Regex;

use crate::error::LlmError;
use crate::scrub::sanitize_error_body;

static AUTH_RX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)unauthorized|invalid[_ ]api[_ ]key|invalid[^\n]{0,24}\btoken\b|\btoken\b[^\n]{0,24}(?:expired|invalid|revoked)|authentication[_ ]failed|incorrect[_ ]api[_ ]key",
    )
    .unwrap()
});

static PROXY_RX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i:\b407\b|proxy[_ ]auth|tunnel[_ ](?:failed|error)|SSL.*CERTIFICATE|CERTIFICATE.*VERIFY.*FAILED|CERT_VERIFY_FAILED|certificate[_ ]verify[_ ]failed|invalid peer certificate|UnknownIssuer|received fatal alert: (?:BadCertificate|CertificateRequired|CertificateUnknown|UnknownCA|UnsupportedCertificate|CertificateExpired|CertificateRevoked))|\bCONNECT\b[^\n]*failed",
    )
    .unwrap()
});

static STATUS_407_RX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b407\b|proxy authori[sz]ation required|proxy authentication required")
        .unwrap()
});

const RETRYABLE_STATUS: [u16; 6] = [429, 500, 502, 503, 504, 529];

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

pub fn classify_transport_error(
    err: &(dyn std::error::Error + 'static),
    connect_or_timeout: bool,
) -> LlmError {
    classify_transport_text(&error_chain_text(err), connect_or_timeout)
}

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

    #[test]
    fn a_prompt_too_long_400_is_not_mistaken_for_an_auth_failure() {
        let body = "invalid_request_error: prompt is too long: 300000 tokens > 200000 maximum";
        assert_eq!(classify_auth_or_proxy_status(400, body), None);
    }

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
