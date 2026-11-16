mod config;
mod error;
mod identity;
#[cfg(test)]
pub(crate) mod test_identity;

pub use config::GatewayConfig;
pub use error::GatewayError;

pub fn build_client(config: &GatewayConfig) -> Result<reqwest::Client, GatewayError> {
    let mut builder = reqwest::Client::builder().timeout(config.timeout);

    if let Some(path) = &config.ca_cert_path {
        if appsec_pathjail::is_network_path(&path.to_string_lossy()) {
            return Err(GatewayError::Io {
                path: path.clone(),
                message: "network paths are not allowed".to_string(),
            });
        }
        let pem = std::fs::read(path).map_err(|e| GatewayError::Io {
            path: path.clone(),
            message: e.to_string(),
        })?;
        validate_ca_cert_pem(&pem).map_err(|message| GatewayError::InvalidCaCert {
            path: path.clone(),
            message,
        })?;
        let cert = reqwest::Certificate::from_pem(&pem)
            .expect("Certificate::from_pem cannot fail on the rustls-only backend");
        builder = builder.tls_certs_only([cert]);
    } else if !config.verify_tls {
        builder = builder.danger_accept_invalid_certs(true);
    }

    match (&config.client_cert_path, &config.client_key_path) {
        (Some(cert), key) => {
            builder = builder.identity(identity::load(cert, key.as_deref())?);
        }
        (None, Some(key)) => return Err(identity::key_without_cert(key)),
        (None, None) => {}
    }

    finish(builder)
}

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
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ca.pem");
        std::fs::write(&path, TEST_CA_PEM).unwrap();
        let mut cfg = GatewayConfig::new("https://gateway.example.com");
        cfg.ca_cert_path = Some(path);
        cfg.verify_tls = false;
        assert!(build_client(&cfg).is_ok());
    }

    use crate::test_identity::generated;

    #[test]
    fn build_client_presents_a_valid_client_identity_alongside_a_private_ca() {
        let dir = tempfile::tempdir().unwrap();
        let ca = dir.path().join("ca.pem");
        std::fs::write(&ca, TEST_CA_PEM).unwrap();
        let mut cfg = GatewayConfig::new("https://gateway.example.com");
        cfg.ca_cert_path = Some(ca);
        cfg.client_cert_path = Some(generated().cert.clone());
        cfg.client_key_path = Some(generated().key.clone());
        assert!(build_client(&cfg).is_ok());
    }

    #[test]
    fn build_client_accepts_a_combined_certificate_and_key_file() {
        let mut cfg = GatewayConfig::new("https://gateway.example.com");
        cfg.client_cert_path = Some(generated().combined.clone());
        assert!(build_client(&cfg).is_ok());
    }

    #[test]
    fn build_client_refuses_a_client_certificate_it_cannot_load() {
        let mut cfg = GatewayConfig::new("https://gateway.example.com");
        cfg.client_cert_path = Some(generated().cert.clone());
        let err = build_client(&cfg).unwrap_err();
        assert!(matches!(err, GatewayError::InvalidClientIdentity { .. }));

        cfg.client_cert_path = Some(std::path::PathBuf::from("/does/not/exist.pem"));
        let err = build_client(&cfg).unwrap_err();
        assert!(matches!(err, GatewayError::InvalidClientIdentity { .. }));
    }

    #[test]
    fn build_client_refuses_a_client_key_without_a_certificate() {
        let mut cfg = GatewayConfig::new("https://gateway.example.com");
        cfg.client_key_path = Some(generated().key.clone());
        let err = build_client(&cfg).unwrap_err();
        assert!(matches!(err, GatewayError::InvalidClientIdentity { .. }));
        assert!(err.to_string().contains("without a client certificate"));
    }

    #[test]
    fn build_client_refuses_a_key_that_does_not_match_the_certificate() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("other-key.pem");
        std::fs::copy(&generated().unrelated_key, &key).unwrap();
        let mut cfg = GatewayConfig::new("https://gateway.example.com");
        cfg.client_cert_path = Some(generated().cert.clone());
        cfg.client_key_path = Some(key);
        assert!(build_client(&cfg).is_err());
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

    #[test]
    fn build_client_ca_cert_pem_with_the_wrong_section_kind_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key.pem");
        std::fs::copy(&generated().unrelated_key, &path).unwrap();
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
