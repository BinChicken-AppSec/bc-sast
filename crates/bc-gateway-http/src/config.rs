use std::path::PathBuf;
use std::time::Duration;

/// Connection settings for talking to an AI gateway (Bifrost, Portkey, or
/// any OpenAI-/Anthropic-compatible endpoint) — everything needed to build
/// a [`reqwest::Client`](crate::build_client), but no auth header or
/// request/response shape, since those are per-dialect
/// (`bc-llm-openai`/`bc-llm-anthropic`) concerns, not shared ones.
#[derive(Debug, Clone, PartialEq)]
pub struct GatewayConfig {
    pub base_url: String,
    /// Client-wide DEFAULT request timeout — the floor, not the whole
    /// story. Each dialect crate applies
    /// [`bc_llm_client::ChatRequest::timeout`] per request on top of this
    /// when the caller set one (mirroring both Python backends'
    /// `client.with_options(timeout=...)`), so a stage asking for 64k
    /// output tokens can carry its own `stepN.timeout` budget of
    /// 1800-3600 s without every other call inheriting it. Requests that
    /// set no per-request timeout still get this value.
    pub timeout: Duration,
    /// A private CA bundle to trust *instead of* the platform/container
    /// trust store — matches `backends/oai.py`'s `configure(ca_cert=...)`
    /// semantics (`verify = ca_cert or verify_ssl`: an explicit CA bundle
    /// always wins over `verify_tls`, it doesn't merely add to the default
    /// store).
    pub ca_cert_path: Option<PathBuf>,
    /// Disabling this without a `ca_cert_path` accepts any TLS certificate
    /// from the gateway — matches `backends/oai.py`'s `verify_ssl=false`
    /// "dangerous" path. Callers that flip this should emit their own loud
    /// warning the way that backend does; this crate has no logging of its
    /// own.
    pub verify_tls: bool,
}

impl GatewayConfig {
    /// A config with the default 300s timeout, no custom CA, and TLS
    /// verification on — the safe default for a fresh gateway target.
    /// See [`Self::timeout`] on why 300 s stays the default even though
    /// several stages need far longer: they carry their own per-request
    /// deadline instead of raising the floor for every call.
    pub fn new(base_url: impl Into<String>) -> Self {
        GatewayConfig {
            base_url: base_url.into(),
            timeout: Duration::from_secs(300),
            ca_cert_path: None,
            verify_tls: true,
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
    }

    #[test]
    fn is_cloneable_and_comparable() {
        let a = GatewayConfig::new("https://x");
        let b = a.clone();
        assert_eq!(a, b);
    }
}
