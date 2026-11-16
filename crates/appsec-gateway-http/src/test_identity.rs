use std::path::PathBuf;

pub(crate) struct Generated {
    _dir: tempfile::TempDir,
    pub(crate) cert: PathBuf,
    pub(crate) key: PathBuf,
    pub(crate) combined: PathBuf,
    pub(crate) unrelated_key: PathBuf,
}

pub(crate) fn generated() -> &'static Generated {
    static ONCE: std::sync::OnceLock<Generated> = std::sync::OnceLock::new();
    ONCE.get_or_init(|| {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let cert = dir.path().join("client-cert.pem");
        let key = dir.path().join("client-key.pem");
        let combined = dir.path().join("client-combined.pem");
        let unrelated_key = dir.path().join("unrelated-key.pem");
        let run = std::process::Command::new("openssl")
            .arg("req")
            .args(["-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1"])
            .args(["-subj", "/CN=bc-sast TEST ONLY client identity"])
            .arg("-keyout")
            .arg(&key)
            .arg("-out")
            .arg(&cert)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("openssl must be on PATH to run this crate's tests");
        assert!(run.success(), "openssl could not generate a test identity");
        let mut both = std::fs::read(&cert).expect("the generated certificate");
        both.push(b'\n');
        both.extend(std::fs::read(&key).expect("the generated key"));
        std::fs::write(&combined, both).expect("the combined pem");
        let second = std::process::Command::new("openssl")
            .args([
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
            ])
            .arg("-out")
            .arg(&unrelated_key)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("openssl must be on PATH to run this crate's tests");
        assert!(second.success(), "openssl could not generate a second key");
        Generated {
            _dir: dir,
            cert,
            key,
            combined,
            unrelated_key,
        }
    })
}
