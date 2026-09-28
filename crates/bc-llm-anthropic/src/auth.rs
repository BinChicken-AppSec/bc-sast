//! Which credential header a Messages API request carries, ported from
//! the Python original's `backends/llm/tls.py::anthropic_auth_kwargs`.
//!
//! A static API key goes in `x-api-key`. An Anthropic OAuth workspace
//! token (documented prefix `sk-ant-oat`) is refused there: it has to be
//! sent as `Authorization: Bearer <token>` together with the
//! `anthropic-beta: oauth-2025-04-20` opt-in. Sending such a token as
//! `x-api-key`, which this port used to do unconditionally, fails every
//! call with a 401.

use bc_llm_client::LlmError;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, AUTHORIZATION};

/// The documented prefix of an Anthropic OAuth token.
const OAUTH_TOKEN_PREFIX: &str = "sk-ant-oat";
/// The beta flag an OAuth-authenticated request must carry.
const OAUTH_BETA: &str = "oauth-2025-04-20";

/// The credential and `anthropic-beta` headers for one request.
///
/// The key is trimmed first, as Python does: a key pasted with a trailing
/// newline is otherwise an illegal header value and fails in a way that
/// does not name the key as the cause. An OAuth token's beta flag is
/// MERGED into any betas the request already asked for (one
/// comma-separated `anthropic-beta` header, the documented format),
/// rather than replacing them. Python sets it as a client default header
/// that a per-request `extra_headers` beta would silently override;
/// merging keeps both.
///
/// Credential values are marked sensitive so `reqwest` never prints them
/// in a `Debug` rendering, and an invalid one is reported without its
/// value.
pub(crate) fn auth_headers(api_key: Option<&str>, betas: &[String]) -> Result<HeaderMap, LlmError> {
    let mut headers = HeaderMap::new();
    let key = api_key.map(str::trim).filter(|k| !k.is_empty());
    let mut betas: Vec<&str> = betas.iter().map(String::as_str).collect();
    if let Some(key) = key {
        let (name, value) = if key.starts_with(OAUTH_TOKEN_PREFIX) {
            if !betas.contains(&OAUTH_BETA) {
                betas.push(OAUTH_BETA);
            }
            (AUTHORIZATION, format!("Bearer {key}"))
        } else {
            (HeaderName::from_static("x-api-key"), key.to_string())
        };
        let mut value = HeaderValue::from_str(&value).map_err(|_| LlmError::InvalidRequest {
            message: "the gateway API key contains characters that are not allowed in an \
                      HTTP header"
                .to_string(),
        })?;
        value.set_sensitive(true);
        headers.insert(name, value);
    }
    if !betas.is_empty() {
        let joined = betas.join(",");
        let value = HeaderValue::from_str(&joined).map_err(|_| LlmError::InvalidRequest {
            message: format!("invalid anthropic-beta value: {joined:?}"),
        })?;
        headers.insert(HeaderName::from_static("anthropic-beta"), value);
    }
    Ok(headers)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
        headers.get(name).map(|v| v.to_str().unwrap())
    }

    #[test]
    fn a_static_key_goes_in_x_api_key_and_nowhere_else() {
        let h = auth_headers(Some("sk-ant-api03-abc"), &[]).unwrap();
        assert_eq!(value(&h, "x-api-key"), Some("sk-ant-api03-abc"));
        assert_eq!(value(&h, "authorization"), None);
        assert_eq!(value(&h, "anthropic-beta"), None);
        assert!(h.get("x-api-key").unwrap().is_sensitive());
    }

    #[test]
    fn an_oauth_token_is_a_bearer_credential_with_its_beta() {
        let h = auth_headers(Some("sk-ant-oat01-xyz"), &[]).unwrap();
        assert_eq!(value(&h, "authorization"), Some("Bearer sk-ant-oat01-xyz"));
        assert_eq!(value(&h, "x-api-key"), None);
        assert_eq!(value(&h, "anthropic-beta"), Some("oauth-2025-04-20"));
        assert!(h.get("authorization").unwrap().is_sensitive());
    }

    #[test]
    fn the_oauth_beta_is_merged_into_betas_the_request_already_asked_for() {
        let betas = vec!["beta-one".to_string(), "beta-two".to_string()];
        let h = auth_headers(Some("sk-ant-oat01-xyz"), &betas).unwrap();
        assert_eq!(
            value(&h, "anthropic-beta"),
            Some("beta-one,beta-two,oauth-2025-04-20")
        );
    }

    #[test]
    fn the_oauth_beta_is_not_repeated_when_the_request_already_names_it() {
        let betas = vec!["oauth-2025-04-20".to_string()];
        let h = auth_headers(Some("sk-ant-oat01-xyz"), &betas).unwrap();
        assert_eq!(value(&h, "anthropic-beta"), Some("oauth-2025-04-20"));
    }

    #[test]
    fn surrounding_whitespace_is_trimmed_before_the_prefix_is_checked() {
        let h = auth_headers(Some("  sk-ant-oat01-xyz\n"), &[]).unwrap();
        assert_eq!(value(&h, "authorization"), Some("Bearer sk-ant-oat01-xyz"));
    }

    #[test]
    fn no_key_or_a_blank_key_sends_no_credential() {
        for key in [None, Some(""), Some("   ")] {
            let h = auth_headers(key, &["b".to_string()]).unwrap();
            assert_eq!(value(&h, "x-api-key"), None);
            assert_eq!(value(&h, "authorization"), None);
            assert_eq!(value(&h, "anthropic-beta"), Some("b"));
        }
    }

    #[test]
    fn an_illegal_key_is_refused_without_echoing_it() {
        let err = auth_headers(Some("sk-bad\u{7f}secret"), &[]).unwrap_err();
        assert!(matches!(err, LlmError::InvalidRequest { .. }));
        assert!(!err.to_string().contains("secret"), "{err}");
    }

    #[test]
    fn an_illegal_beta_is_refused() {
        let err = auth_headers(None, &["bad\nbeta".to_string()]).unwrap_err();
        assert!(matches!(err, LlmError::InvalidRequest { .. }), "{err:?}");
    }
}
