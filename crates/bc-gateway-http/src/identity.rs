//! The mTLS client identity (`client_cert_path` / `client_key_path`),
//! loaded eagerly so a bad file fails at startup rather than at the first
//! TLS handshake.
//!
//! **Deliberate divergence from Python, which fails open.** The Python
//! original (`backends/llm/tls.py::resolve_client_chain` and
//! `load_client_chain`) warns and carries on with server-authenticated
//! TLS when a configured client certificate is missing or will not load.
//! Here the same conditions are an error. An operator who configured mTLS
//! did so because the gateway (or a policy in front of it) is meant to see
//! a client certificate; quietly connecting without one either fails later
//! with a less legible handshake error, or, worse, succeeds against an
//! endpoint that was supposed to demand the certificate and did not.
//! Neither is something a security tool should do on the operator's
//! behalf, and the same reasoning already makes a bad `ca_cert_path`
//! fatal.

use std::path::{Path, PathBuf};

use crate::GatewayError;

/// Read `cert` (and `key`, when the key lives in its own file) and parse
/// them into the identity `reqwest` presents during the handshake.
///
/// The two files are simply concatenated before parsing, which is what
/// lets one combined PEM (certificate chain plus key) and a split pair
/// share a code path, as they do in Python's `chain_paths`.
pub(crate) fn load(cert: &Path, key: Option<&Path>) -> Result<reqwest::Identity, GatewayError> {
    let mut pem = read_pem(cert)?;
    if let Some(key) = key {
        // A newline between the two, in case the certificate file does
        // not end with one: `-----END CERTIFICATE----------BEGIN` would
        // otherwise hide the key from the PEM parser.
        pem.push(b'\n');
        pem.extend(read_pem(key)?);
    }
    // On the rustls backend this parses every PEM section immediately
    // and refuses input with no certificate or no private key, unlike
    // `Certificate::from_pem` (see `validate_ca_cert_pem`). Only the
    // error's text is kept; it never quotes the key material.
    reqwest::Identity::from_pem(&pem).map_err(|e| GatewayError::InvalidClientIdentity {
        path: cert.to_path_buf(),
        message: format!("not a usable PEM certificate and private key ({e})"),
    })
}

/// The refusal for a key configured without a certificate to go with it.
pub(crate) fn key_without_cert(key: &Path) -> GatewayError {
    GatewayError::InvalidClientIdentity {
        path: key.to_path_buf(),
        message: "a client key was given without a client certificate".to_string(),
    }
}

/// Read one identity file, refusing a network path before any filesystem
/// access (the same NTLM-leak guard `build_client` applies to the CA
/// bundle).
fn read_pem(path: &Path) -> Result<Vec<u8>, GatewayError> {
    let invalid = |message: String| GatewayError::InvalidClientIdentity {
        path: PathBuf::from(path),
        message,
    };
    if bc_pathjail::is_network_path(&path.to_string_lossy()) {
        return Err(invalid("network paths are not allowed".to_string()));
    }
    std::fs::read(path).map_err(|e| invalid(format!("cannot read: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name)
    }

    /// `(path, message)` of an `InvalidClientIdentity`, read back from its
    /// Display so a wrong variant fails the `expect` rather than needing
    /// a panic arm of its own.
    fn message_of(err: GatewayError) -> (PathBuf, String) {
        let text = err.to_string();
        let rest = text
            .strip_prefix("invalid mTLS client certificate/key ")
            .expect("an InvalidClientIdentity error");
        let (path, message) = rest.split_once(": ").expect("path: message");
        (PathBuf::from(path), message.to_string())
    }

    #[test]
    fn a_split_certificate_and_key_pair_loads() {
        load(
            &fixture("client-cert.pem"),
            Some(&fixture("client-key.pem")),
        )
        .unwrap();
    }

    #[test]
    fn a_combined_pem_holding_both_loads_without_a_key_path() {
        load(&fixture("client-combined.pem"), None).unwrap();
    }

    #[test]
    fn a_certificate_without_its_key_is_refused() {
        let (path, message) = message_of(load(&fixture("client-cert.pem"), None).unwrap_err());
        assert_eq!(path, fixture("client-cert.pem"));
        assert!(message.contains("not a usable PEM"), "{message}");
    }

    #[test]
    fn garbage_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("cert.pem");
        std::fs::write(&cert, "not a certificate at all").unwrap();
        let (_, message) = message_of(load(&cert, None).unwrap_err());
        assert!(message.contains("not a usable PEM"), "{message}");
    }

    #[test]
    fn a_missing_certificate_or_key_file_is_refused_and_named() {
        let missing = Path::new("/does/not/exist/cert.pem");
        let (path, message) = message_of(load(missing, None).unwrap_err());
        assert_eq!(path, missing);
        assert!(message.starts_with("cannot read"), "{message}");

        let missing_key = Path::new("/does/not/exist/key.pem");
        let (path, _) =
            message_of(load(&fixture("client-cert.pem"), Some(missing_key)).unwrap_err());
        assert_eq!(path, missing_key, "the key file is the one named");
    }

    #[test]
    fn a_network_path_is_refused_without_touching_the_filesystem() {
        let (_, message) =
            message_of(load(Path::new(r"\\attacker\share\cert.pem"), None).unwrap_err());
        assert_eq!(message, "network paths are not allowed");
        let (_, message) = message_of(
            load(
                &fixture("client-cert.pem"),
                Some(Path::new(r"\\attacker\share\key.pem")),
            )
            .unwrap_err(),
        );
        assert_eq!(message, "network paths are not allowed");
    }

    #[test]
    fn key_without_cert_names_the_key() {
        let (path, message) = message_of(key_without_cert(Path::new("/k.pem")));
        assert_eq!(path, Path::new("/k.pem"));
        assert!(message.contains("without a client certificate"));
    }

    /// The test key never appears in an error, whatever went wrong.
    #[test]
    fn an_error_never_quotes_the_key_material() {
        let key = std::fs::read_to_string(fixture("client-key.pem")).unwrap();
        let body_line = key
            .lines()
            .find(|l| !l.starts_with("-----") && !l.starts_with("TEST") && l.len() > 40)
            .unwrap()
            .to_string();
        // Key alone, no certificate: refused.
        let err = load(&fixture("client-key.pem"), None).unwrap_err();
        assert!(!err.to_string().contains(&body_line), "{err}");
    }
}
