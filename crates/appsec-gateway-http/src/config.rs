use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq)]
pub struct GatewayConfig {
    pub base_url: String,
    pub timeout: Duration,
    pub ca_cert_path: Option<PathBuf>,
    pub verify_tls: bool,
    pub client_cert_path: Option<PathBuf>,
    pub client_key_path: Option<PathBuf>,
}

impl GatewayConfig {
    pub fn new(base_url: impl Into<String>) -> Self {
        GatewayConfig {
            base_url: base_url.into(),
            timeout: Duration::from_secs(300),
            ca_cert_path: None,
            verify_tls: true,
            client_cert_path: None,
            client_key_path: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_has_safe_defaults() {
        let cfg = GatewayConfig::new("https://gateway.example.com");
        assert_eq!(cfg.base_url, "https://gateway.example.com");
        assert_eq!(cfg.timeout, Duration::from_secs(300));
        assert!(cfg.ca_cert_path.is_none());
        assert!(cfg.verify_tls);
        assert!(cfg.client_cert_path.is_none());
        assert!(cfg.client_key_path.is_none());
    }

    #[test]
    fn is_cloneable_and_comparable() {
        let a = GatewayConfig::new("https://x");
        let b = a.clone();
        assert_eq!(a, b);
    }
}
