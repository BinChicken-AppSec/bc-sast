use std::path::{Path, PathBuf};

use crate::GatewayError;

pub(crate) fn load(cert: &Path, key: Option<&Path>) -> Result<reqwest::Identity, GatewayError> {
    let mut pem = read_pem(cert)?;
    if let Some(key) = key {
        pem.push(b'\n');
        pem.extend(read_pem(key)?);
    }
    reqwest::Identity::from_pem(&pem).map_err(|e| GatewayError::InvalidClientIdentity {
        path: cert.to_path_buf(),
        message: format!("not a usable PEM certificate and private key ({e})"),
    })
}

pub(crate) fn key_without_cert(key: &Path) -> GatewayError {
    GatewayError::InvalidClientIdentity {
        path: key.to_path_buf(),
        message: "a client key was given without a client certificate".to_string(),
    }
}

fn read_pem(path: &Path) -> Result<Vec<u8>, GatewayError> {
    let invalid = |message: String| GatewayError::InvalidClientIdentity {
        path: PathBuf::from(path),
        message,
    };
    if appsec_pathjail::is_network_path(&path.to_string_lossy()) {
        return Err(invalid("network paths are not allowed".to_string()));
    }
    std::fs::read(path).map_err(|e| invalid(format!("cannot read: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::test_identity::generated;

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
        load(&generated().cert, Some(&generated().key)).unwrap();
    }

    #[test]
    fn a_combined_pem_holding_both_loads_without_a_key_path() {
        load(&generated().combined, None).unwrap();
    }

    #[test]
    fn a_certificate_without_its_key_is_refused() {
        let (path, message) = message_of(load(&generated().cert, None).unwrap_err());
        assert_eq!(path, generated().cert);
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
        let (path, _) = message_of(load(&generated().cert, Some(missing_key)).unwrap_err());
        assert_eq!(path, missing_key, "the key file is the one named");
    }

    #[test]
    fn a_network_path_is_refused_without_touching_the_filesystem() {
        let (_, message) =
            message_of(load(Path::new(r"\\attacker\share\cert.pem"), None).unwrap_err());
        assert_eq!(message, "network paths are not allowed");
        let (_, message) = message_of(
            load(
                &generated().cert,
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

    #[test]
    fn an_error_never_quotes_the_key_material() {
        let key = std::fs::read_to_string(&generated().key).unwrap();
        let body_line = key
            .lines()
            .find(|l| !l.starts_with("-----") && !l.starts_with("TEST") && l.len() > 40)
            .unwrap()
            .to_string();
        let err = load(&generated().key, None).unwrap_err();
        assert!(!err.to_string().contains(&body_line), "{err}");
    }
}
