//! Shared TLS-aware HTTP client construction for talking to an AI gateway,
//! ported from the client-setup half of `backends/oai.py`'s `_get_client`
//! (auth-header attachment and the OpenAI/Anthropic request/response shapes
//! stay in `bc-llm-openai`/`bc-llm-anthropic` — this crate only builds
//! the underlying [`reqwest::Client`]).

mod config;
mod error;

pub use config::GatewayConfig;
pub use error::GatewayError;

/// Build a [`reqwest::Client`] for `config`.
///
/// - No `ca_cert_path`, `verify_tls: true` (the default): use the
///   platform/container's native trust store.
/// - `ca_cert_path` set: trust *only* that CA bundle, matching
///   `backends/oai.py`'s `verify = ca_cert or verify_ssl` precedence — an
///   explicit CA always wins over `verify_tls`.
/// - No `ca_cert_path`, `verify_tls: false`: accept any certificate. Same
///   "dangerous" path as `backends/oai.py`'s `verify_ssl=false`; this crate
///   does not warn about it, callers should.
pub fn build_client(config: &GatewayConfig) -> Result<reqwest::Client, GatewayError> {
    let mut builder = reqwest::Client::builder().timeout(config.timeout);

    if let Some(path) = &config.ca_cert_path {
        // Checked before any filesystem touch: even a failed read would
        // trigger Windows' SMB handshake for a `\\host\share` path,
        // leaking the caller's NTLMv2 hash to a malicious host.
        if bc_pathjail::is_network_path(&path.to_string_lossy()) {
            return Err(GatewayError::Io {
                path: path.clone(),
                message: "network paths are not allowed".to_string(),
            });
        }
        let pem = std::fs::read(path).map_err(|e| GatewayError::Io {
            path: path.clone(),
            message: e.to_string(),
        })?;
        // On the rustls backend, `reqwest::Certificate::from_pem` stores the
        // raw bytes and only actually parses them at first real TLS
        // connection — too late for a fail-closed check on a config file.
        // Validate the PEM syntax ourselves first so a malformed
        // `ca_cert_path` is rejected immediately, at startup.
        validate_ca_cert_pem(&pem).map_err(|message| GatewayError::InvalidCaCert {
            path: path.clone(),
            message,
        })?;
        // Infallible here: with only the `rustls` feature enabled (no
        // `native-tls`), `Certificate::from_pem` unconditionally returns
        // `Ok` for any bytes — it just stores them, deferring real parsing
        // to first connection (see `validate_ca_cert_pem` above for the
        // actual eager check).
        let cert = reqwest::Certificate::from_pem(&pem)
            .expect("Certificate::from_pem cannot fail on the rustls-only backend");
        builder = builder.tls_certs_only([cert]);
    } else if !config.verify_tls {
        builder = builder.danger_accept_invalid_certs(true);
    }

    finish(builder)
}

/// Split out from [`build_client`] so its `map_err` is directly testable
/// with a builder state [`build_client`]'s own config surface (timeout,
/// TLS-trust knobs only) can never actually produce — none of those calls
/// can set reqwest's internal deferred-error slot, unlike e.g. an invalid
/// `user_agent()` value.
fn finish(builder: reqwest::ClientBuilder) -> Result<reqwest::Client, GatewayError> {
    builder.build().map_err(|e| GatewayError::Build {
        message: e.to_string(),
    })
}

fn validate_ca_cert_pem(pem: &[u8]) -> Result<(), String> {
    use rustls_pki_types::pem::{from_buf, SectionKind};

    let mut cursor = std::io::Cursor::new(pem);
    match from_buf(&mut cursor) {
        Ok(Some((SectionKind::Certificate, _))) => Ok(()),
        Ok(Some((other, _))) => Err(format!(
            "expected a CERTIFICATE PEM section, found {other:?}"
        )),
        Ok(None) => Err("no PEM section found".to_string()),
        Err(e) => Err(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    // A real, syntactically valid self-signed CA certificate (openssl req
    // -x509 ..., 2026-07-21) used only to exercise the PEM-parsing success
    // path — never presented over the network by anything in this test
    // suite, so its matching private key does not need to exist anywhere.
    const TEST_CA_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIDDTCCAfWgAwIBAgIUX6HKaTESp/lCYAnA7Yx2HXLHWi4wDQYJKoZIhvcNAQEL
BQAwFjEUMBIGA1UEAwwLdnZhLXRlc3QtY2EwHhcNMjYwNzIxMDgxMTIwWhcNMzYw
NzE4MDgxMTIwWjAWMRQwEgYDVQQDDAt2dmEtdGVzdC1jYTCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBAKK2Cl5r01DvCJmoKsNza1U5v+9zce52DZ0w4ics
HXK4cTPo3eKTEfrNyRDhaVrRR9DbuKfWlDayicTpTUAHIJSO5eijv/bEcTq7DyJ4
d3sL8/89uFf0wtGu/QjhsoM5MHbsxhXkaLYxTQ/9GCHkGIiehvctGMVPOBdlMZur
JSrMtz5Rm1GfYv1JP0F3wVCPBP2TQWE8KM1xfCu4Md2MQK+pHYNUXvAxHGSYnTKw
sYuQRBF5uOJ4nEhS+SnsnPFEIDClGW2RALo+kvuik/LiMN9gddwEzDYdZG/ney5E
VhUz13hfm3P9iqLB2IlXUaXAHN0Y2Iumj0MVFtuxftClUNMCAwEAAaNTMFEwHQYD
VR0OBBYEFIercHMSf/hLhIxpjGOi61C/9xjDMB8GA1UdIwQYMBaAFIercHMSf/hL
hIxpjGOi61C/9xjDMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEB
AAKu1F5PqRYo96g2hrg+E5rANwVB0ZZuezXy7Yvv7f59MHKEaCiypsZ4nDwf5giI
jZaj1OOBNpWJSWgvXgalXOUciUkeow4xCiP5KJOpUxgwTKs25pmRP6rttPFUzTUD
1FwHBXK19VVgTPavw22+UiReGA42gV4d22xcIqRlfQcxLO3X0+HB7scRqlXVoNkb
jq3134wRdiN4EcAG4bQ3q1dAb2vPzrA1ml2MVKQQRNgodiMt5fooNuLJcHX+9rsF
WHxXIXXWRXgdb3YO1yK7stnixX4u+E5AFGVnIfg24IINw/oqCL0xER9smglmaAK3
LeXltE6upN6JKdVB655LW4Q=
-----END CERTIFICATE-----
";

    #[test]
    fn build_client_with_default_config_succeeds() {
        let cfg = GatewayConfig::new("https://gateway.example.com");
        assert!(build_client(&cfg).is_ok());
    }

    #[test]
    fn build_client_with_verify_tls_false_succeeds() {
        let mut cfg = GatewayConfig::new("https://gateway.example.com");
        cfg.verify_tls = false;
        assert!(build_client(&cfg).is_ok());
    }

    #[test]
    fn build_client_with_a_valid_ca_cert_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ca.pem");
        std::fs::write(&path, TEST_CA_PEM).unwrap();
        let mut cfg = GatewayConfig::new("https://gateway.example.com");
        cfg.ca_cert_path = Some(path);
        assert!(build_client(&cfg).is_ok());
    }

    #[test]
    fn build_client_ca_cert_takes_priority_over_verify_tls() {
        // Mirrors `verify = ca_cert or verify_ssl`: even with verify_tls
        // explicitly false, a present ca_cert_path is what governs trust.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ca.pem");
        std::fs::write(&path, TEST_CA_PEM).unwrap();
        let mut cfg = GatewayConfig::new("https://gateway.example.com");
        cfg.ca_cert_path = Some(path);
        cfg.verify_tls = false;
        assert!(build_client(&cfg).is_ok());
    }

    #[test]
    fn build_client_missing_ca_cert_file_is_an_io_error() {
        let mut cfg = GatewayConfig::new("https://gateway.example.com");
        cfg.ca_cert_path = Some(std::path::PathBuf::from("/does/not/exist.pem"));
        let err = build_client(&cfg).unwrap_err();
        assert!(matches!(err, GatewayError::Io { .. }));
    }

    #[test]
    fn build_client_refuses_a_network_ca_cert_path_without_touching_the_filesystem() {
        let mut cfg = GatewayConfig::new("https://gateway.example.com");
        cfg.ca_cert_path = Some(std::path::PathBuf::from(r"\\attacker\share\ca.pem"));
        let err = build_client(&cfg).unwrap_err();
        assert!(matches!(err, GatewayError::Io { .. }));
        assert!(err.to_string().contains("network paths are not allowed"));
    }

    #[test]
    fn finish_wraps_a_builder_failure_as_gateway_error_build() {
        // `build_client`'s own config surface (timeout, TLS-trust knobs)
        // can never make `.build()` fail, so this exercises `finish`
        // directly with a builder state (an invalid `user_agent` header
        // value) that reaches its `map_err` the same way a future config
        // knob that *can* fail would.
        let builder = reqwest::Client::builder().user_agent("bad\nvalue");
        let err = finish(builder).unwrap_err();
        assert!(matches!(err, GatewayError::Build { .. }));
    }

    #[test]
    fn build_client_invalid_ca_cert_content_is_a_parse_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ca.pem");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(b"not a certificate").unwrap();
        let mut cfg = GatewayConfig::new("https://gateway.example.com");
        cfg.ca_cert_path = Some(path);
        let err = build_client(&cfg).unwrap_err();
        assert!(matches!(err, GatewayError::InvalidCaCert { .. }));
    }

    // A syntactically valid PEM file, but the wrong section kind (a private
    // key, not a certificate) — real openssl output, matching TEST_CA_PEM's
    // (never-used-for-TLS) key pair.
    const TEST_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCitgpea9NQ7wiZ
qCrDc2tVOb/vc3Hudg2dMOInLB1yuHEz6N3ikxH6zckQ4Wla0UfQ27in1pQ2sonE
6U1AByCUjuXoo7/2xHE6uw8ieHd7C/P/PbhX9MLRrv0I4bKDOTB27MYV5Gi2MU0P
/Rgh5BiInob3LRjFTzgXZTGbqyUqzLc+UZtRn2L9ST9Bd8FQjwT9k0FhPCjNcXwr
uDHdjECvqR2DVF7wMRxkmJ0ysLGLkEQRebjieJxIUvkp7JzxRCAwpRltkQC6PpL7
opPy4jDfYHXcBMw2HWRv53suRFYVM9d4X5tz/YqiwdiJV1GlwBzdGNiLpo9DFRbb
sX7QpVDTAgMBAAECggEAAZm80bT0fS/8wQDbJX+10el22TTPgsL9MKCnI4TW5/v8
e8A8qS/n1gm+1+r/uE76tTPpcG03RAUkPyBJtumFs9sRU+UtzDrzyi9w31aZW50r
J0WaJ0isaezzZupMG+esxwlejB8/uxsSYP03sY2m2CExvq4I4lf8e0PEOyhx0yab
A6AiEDmv1u45kRW6n8bS5ZPqukN4XjkN5Fx/qP5HA1dXDfvI3kv6UrP4A7eGjC2k
M2M/55mr1Nu0XHf1wj/YiQThZjdRT6d7+T9U4RH1ZrT7XYBmTON3nGgzYMDljF6y
EznkxTNdVAYkuol6cIJw47da2i39Js7KUPI2x1uA0QKBgQDZJuwjWfbzTmVdp0v7
IryP4moKTxjOmNoZ5hizpNXon9jopl0T/kb7CLMMzo3Dz0sJugF/kXsO0Sk6X31n
UXRKEpZ9GuNBO2xCd6ze0sRne+NEjvJxUePiUqd6oBu1rR2A0lZhjlptHiUFJolr
csXBDGyaieklhvEhU9q/GjiErwKBgQC/0dg5FSSSYhdOrtXZs3fqOYwa7+iYRo7d
3wPR0LIbDyTD0xoqFdjw6BdQcyTxB6UtOcXO0dIYxXHMfQD9JvwAIbsNdZqcKg4H
KF9Je6WsiGZlhuCpzQUoJ2KA1pZfTtcnjnynEDTGZdkmxbvGK77EUtN2UNOm1l9X
2jnel5qHHQKBgFZFjWlaE6+EROdZUOl8Wne7ly9zT0K9HWFOth+g7E8YOn/roG0S
B7cyNJhw84eIsqIxoOjCrqYrWPrU9yh2BwJqshkP9pty9UbO7wIzsE4AvUD+nbmB
tEy1U853D6s1FNSaPDFT8f8KC+Eo902V8pUIz5jyE4uSOfhorS5hR3UHAoGBAL2+
miB9JZwXo+6VS7z5ppjvLARJZM+cnB4lSOX3hvb1V+zNmYgf7GUBcG6IN/alFWNT
TrRzIVyXkyYwURYZxhVrSFjcCICJqS6zZO6PfSbaFlA/x2SwBXXe37WKj1zf5Dyg
2fV4Nnw6qz+LQV+aTi5tr/fNpE/Ypp+EotHpLVaRAoGAE96sVe2G4el5EjRXz8h7
5OznYnPtjx/KCL5HlN3gQlaql8Y2iYkIzMRqxtUFkkrvPSIvFnXbU2muyYJbNGtL
XxwNQ3sYTkmaH9k5bUmFHDFvvYd2OMTOJrHmQiMlJDkARJigXiucWrrxLJctqQSC
GpH/WXUUMrQWeeoxgIB6db4=
-----END PRIVATE KEY-----
";

    #[test]
    fn build_client_ca_cert_pem_with_the_wrong_section_kind_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key.pem");
        std::fs::write(&path, TEST_PRIVATE_KEY_PEM).unwrap();
        let mut cfg = GatewayConfig::new("https://gateway.example.com");
        cfg.ca_cert_path = Some(path);
        let err = build_client(&cfg).unwrap_err();
        assert!(
            matches!(&err, GatewayError::InvalidCaCert { message, .. } if message.contains("CERTIFICATE")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn build_client_malformed_pem_missing_end_marker_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ca.pem");
        std::fs::write(&path, "-----BEGIN CERTIFICATE-----\nMIIB\n").unwrap();
        let mut cfg = GatewayConfig::new("https://gateway.example.com");
        cfg.ca_cert_path = Some(path);
        let err = build_client(&cfg).unwrap_err();
        assert!(matches!(err, GatewayError::InvalidCaCert { .. }));
    }
}
