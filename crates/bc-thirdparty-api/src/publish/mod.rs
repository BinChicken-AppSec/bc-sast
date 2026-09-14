//! Native provider publication transport. Callers own explicit approval and journals.
mod aikido;
mod checkmarx;
mod semgrep;
mod snyk;

use bc_model::{ProviderKind, ProviderOrigin};
use reqwest::{Method, Url};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;

#[derive(Clone)]
pub enum Auth {
    Bearer(String),
    Token(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovedAction {
    FalsePositive {
        reason: String,
    },
    Confirmed {
        reason: String,
        severity: Option<String>,
    },
    Note {
        reason: String,
    },
}
impl ApprovedAction {
    pub fn reason(&self) -> &str {
        match self {
            Self::FalsePositive { reason }
            | Self::Confirmed { reason, .. }
            | Self::Note { reason } => reason,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WriteStatus {
    Verified,
    AwaitingRetest,
    PendingApproval,
    AcceptedUnverified,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteResult {
    pub status: WriteStatus,
    pub response: Value,
}
#[derive(Debug, Clone, thiserror::Error)]
#[error("{message}")]
pub struct PublishError {
    pub message: String,
    pub uncertain: bool,
}
impl PublishError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            uncertain: false,
        }
    }
    fn transport(uncertain: bool) -> Self {
        Self {
            message: "Provider request failed; no automatic mutation retry".into(),
            uncertain,
        }
    }
}

/// The client never accepts an endpoint from report/model content. The public
/// constructor restricts credentials to documented provider origins over HTTPS.
pub struct PublishClient {
    http: reqwest::Client,
    base_url: Url,
    auth: Auth,
    provider: ProviderKind,
    next_request: tokio::sync::Mutex<tokio::time::Instant>,
    interval: Duration,
}
impl PublishClient {
    pub fn new(provider: ProviderKind, base_url: &str, auth: Auth) -> Result<Self, PublishError> {
        let url = trusted_url(provider, base_url)?;
        Self::build(
            provider,
            url,
            auth,
            if provider == ProviderKind::Aikido {
                Duration::from_secs(3)
            } else {
                Duration::ZERO
            },
        )
    }
    /// Credential-free regional origin bound into the publication journal.
    pub fn endpoint_origin(&self) -> String {
        self.base_url.origin().ascii_serialization()
    }

    fn build(
        provider: ProviderKind,
        base_url: Url,
        auth: Auth,
        interval: Duration,
    ) -> Result<Self, PublishError> {
        let http = http_client()?;
        Ok(Self {
            http,
            base_url,
            auth,
            provider,
            next_request: tokio::sync::Mutex::new(tokio::time::Instant::now()),
            interval,
        })
    }
    #[cfg(test)]
    pub(crate) fn test(base_url: impl AsRef<str>, auth: Auth) -> Self {
        Self::build(
            ProviderKind::Unknown,
            Url::parse(base_url.as_ref()).unwrap(),
            auth,
            Duration::ZERO,
        )
        .unwrap()
    }
    pub async fn get(&self, path: &str) -> Result<Value, PublishError> {
        self.request(Method::GET, path, None).await
    }
    pub async fn send_once(
        &self,
        method: Method,
        path: &str,
        body: &Value,
    ) -> Result<Value, PublishError> {
        self.request(method, path, Some(body)).await
    }
    async fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Value, PublishError> {
        if !path.starts_with('/')
            || path.starts_with("//")
            || path.contains('\\')
            || path.chars().any(char::is_control)
        {
            return Err(PublishError::new("Unsafe provider request path"));
        }
        let url = self
            .base_url
            .join(path)
            .map_err(|_| PublishError::new("Invalid provider request path"))?;
        if url.origin() != self.base_url.origin() {
            return Err(PublishError::new("Provider origin changed"));
        }
        let mut next = self.next_request.lock().await;
        tokio::time::sleep_until(*next).await;
        *next = tokio::time::Instant::now() + self.interval;
        drop(next);
        let mut request = self.http.request(method.clone(), url);
        request = match &self.auth {
            Auth::Bearer(token) => request.bearer_auth(token),
            Auth::Token(token) => request.header("Authorization", format!("token {token}")),
        };
        if self.provider == ProviderKind::Snyk || matches!(self.auth, Auth::Token(_)) {
            request = request
                .header("Accept", "application/vnd.api+json")
                .header("Content-Type", "application/vnd.api+json");
        }
        if self.provider == ProviderKind::Checkmarx {
            request = request.header("Accept", "application/json; version=1.0");
        }
        if let Some(body) = body {
            request = request.json(body);
        }
        let mut response = request
            .send()
            .await
            .map_err(|_| PublishError::transport(method != Method::GET))?;
        let status = response.status();
        if !status.is_success() {
            return Err(PublishError {
                message: format!(
                    "Provider returned HTTP {}; no automatic mutation retry",
                    status.as_u16()
                ),
                uncertain: method != Method::GET
                    && (status.is_server_error() || status.is_redirection()),
            });
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| PublishError::transport(method != Method::GET))?
        {
            if bytes.len() + chunk.len() > 8 * 1024 * 1024 {
                return Err(PublishError {
                    message: "Provider response exceeded 8 MiB".into(),
                    uncertain: method != Method::GET,
                });
            }
            bytes.extend_from_slice(&chunk);
        }
        if bytes.is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_slice(&bytes).map_err(|_| PublishError {
            message: "Provider returned malformed JSON".into(),
            uncertain: method != Method::GET,
        })
    }
}

/// Validate before OAuth as well as before data-plane access.
pub fn trusted_url(provider: ProviderKind, base_url: &str) -> Result<Url, PublishError> {
    let url = Url::parse(base_url).map_err(|_| PublishError::new("Invalid provider URL"))?;
    let host = url.host_str().unwrap_or("");
    let allowed = match provider {
        ProviderKind::Semgrep => matches!(host, "semgrep.dev" | "api.semgrep.dev"),
        ProviderKind::Snyk => matches!(
            host,
            "api.snyk.io" | "api.eu.snyk.io" | "api.au.snyk.io" | "api.us.snyk.io"
        ),
        ProviderKind::Aikido => matches!(
            host,
            "app.aikido.dev" | "app.us.aikido.dev" | "app.au.aikido.dev" | "app.me.aikido.dev"
        ),
        ProviderKind::Checkmarx => {
            matches!(host, "ast.checkmarx.net" | "iam.checkmarx.net")
                || host.ends_with(".ast.checkmarx.net")
                || host.ends_with(".iam.checkmarx.net")
        }
        _ => false,
    };
    if !allowed
        || url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some_and(|p| p != 443)
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(PublishError::new(
            "Publishing requires an approved HTTPS provider origin without credentials or query",
        ));
    }
    Ok(url)
}

pub async fn read(client: &PublishClient, origin: &ProviderOrigin) -> Result<Value, PublishError> {
    if client.provider != origin.provider && client.provider != ProviderKind::Unknown {
        return Err(PublishError::new("Provider client binding mismatch"));
    }
    match origin.provider {
        ProviderKind::Semgrep => semgrep::read(client, origin).await,
        ProviderKind::Snyk => snyk::read(client, origin).await,
        ProviderKind::Checkmarx => checkmarx::read(client, origin).await,
        ProviderKind::Aikido => aikido::read(client, origin).await,
        _ => Err(PublishError::new("Provider publication is unsupported")),
    }
}
pub async fn write(
    client: &PublishClient,
    origin: &ProviderOrigin,
    action: &ApprovedAction,
    expected: &Value,
) -> Result<WriteResult, PublishError> {
    if action.reason().trim().is_empty() || action.reason().len() > 1000 {
        return Err(PublishError::new(
            "Publication requires a reason of 1 to 1000 bytes",
        ));
    }
    if client.provider != origin.provider && client.provider != ProviderKind::Unknown {
        return Err(PublishError::new("Provider client binding mismatch"));
    }
    match origin.provider {
        ProviderKind::Semgrep => semgrep::write(client, origin, action, expected).await,
        ProviderKind::Snyk => snyk::write(client, origin, action, expected).await,
        ProviderKind::Checkmarx => checkmarx::write(client, origin, action, expected).await,
        ProviderKind::Aikido => aikido::write(client, origin, action, expected).await,
        _ => Err(PublishError::new("Provider publication is unsupported")),
    }
}

// OAuth and finding requests share the same redirect and timeout policy.
fn http_client() -> Result<reqwest::Client, PublishError> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|_| PublishError::new("Could not construct publishing client"))
}

fn authenticated_client<E>(
    provider: ProviderKind,
    base_url: &str,
    token: Result<String, E>,
) -> Result<PublishClient, PublishError> {
    match token {
        Ok(token) => PublishClient::new(provider, base_url, Auth::Bearer(token)),
        // Authentication errors may contain a response body or credentials.
        Err(_) => Err(PublishError::new(format!(
            "{provider:?} authentication failed"
        ))),
    }
}

pub async fn checkmarx_client(
    config: crate::checkmarx::CheckmarxConfig,
) -> Result<PublishClient, PublishError> {
    trusted_url(ProviderKind::Checkmarx, &config.base_url)?;
    trusted_url(ProviderKind::Checkmarx, &config.iam_url)?;
    let token = crate::checkmarx::CheckmarxClient::new(http_client()?, config.clone())
        .access_token()
        .await;
    authenticated_client(ProviderKind::Checkmarx, &config.base_url, token)
}
pub async fn aikido_client(
    config: crate::aikido::AikidoConfig,
) -> Result<PublishClient, PublishError> {
    trusted_url(ProviderKind::Aikido, &config.base_url)?;
    let token = crate::aikido::AikidoClient::new(http_client()?, config.clone())
        .access_token()
        .await;
    authenticated_client(ProviderKind::Aikido, &config.base_url, token)
}

#[cfg(test)]
mod transport_tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn trusted_origins_reject_credential_host_and_protocol_confusion() {
        for (provider, url) in [
            (ProviderKind::Semgrep, "https://semgrep.dev"),
            (ProviderKind::Snyk, "https://api.snyk.io"),
            (ProviderKind::Aikido, "https://app.aikido.dev"),
            (ProviderKind::Checkmarx, "https://eu.ast.checkmarx.net"),
        ] {
            assert!(trusted_url(provider, url).is_ok(), "{url}");
        }
        for (provider, url) in [
            (ProviderKind::Semgrep, "http://semgrep.dev"),
            (ProviderKind::Semgrep, "https://semgrep.dev.evil.invalid"),
            (ProviderKind::Semgrep, "https://semgrep.dev@evil.invalid"),
            (ProviderKind::Semgrep, "https://user:password@semgrep.dev"),
            (ProviderKind::Semgrep, "https://semgrep.dev:8443"),
            (ProviderKind::Semgrep, "https://semgrep.dev?endpoint=evil"),
            (ProviderKind::Semgrep, "https://semgrep.dev#evil"),
            (
                ProviderKind::Checkmarx,
                "https://eu.ast.checkmarx.net.evil.invalid",
            ),
            (ProviderKind::Snyk, "https://semgrep.dev"),
            (ProviderKind::Unknown, "https://semgrep.dev"),
        ] {
            assert!(trusted_url(provider, url).is_err(), "{url}");
        }
    }

    #[tokio::test]
    async fn untrusted_request_paths_never_receive_credentials_or_reach_transport() {
        let server = MockServer::start().await;
        let client = PublishClient::test(server.uri(), Auth::Bearer("synthetic-token".into()));
        for path in [
            "https://evil.invalid",
            "//evil.invalid/path",
            "/\\evil.invalid",
            "/bad\npath",
        ] {
            let error = client.get(path).await.unwrap_err();
            assert!(!error.uncertain);
        }
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn redirect_never_forwards_authorization_and_write_remains_uncertain() {
        let source = MockServer::start().await;
        let destination = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/mutate"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("Location", format!("{}/capture", destination.uri())),
            )
            .expect(1)
            .mount(&source)
            .await;
        let client = PublishClient::test(source.uri(), Auth::Bearer("synthetic-token".into()));
        let error = client
            .send_once(Method::POST, "/mutate", &json!({"action":"test"}))
            .await
            .unwrap_err();
        assert!(
            error.uncertain,
            "A redirect does not establish that the original mutation was rejected"
        );
        assert!(destination.received_requests().await.unwrap().is_empty());
        assert_eq!(source.received_requests().await.unwrap().len(), 1);
        assert!(!error.message.contains("synthetic-token"));
    }

    #[tokio::test]
    async fn write_http_errors_are_not_retried_and_response_bodies_are_not_exposed() {
        for status in [400, 401, 403, 404, 409, 422, 429, 500, 503] {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/mutate"))
                .respond_with(
                    ResponseTemplate::new(status).set_body_string("credential-response-canary"),
                )
                .expect(1)
                .mount(&server)
                .await;
            let client = PublishClient::test(server.uri(), Auth::Bearer("synthetic-token".into()));
            let error = client
                .send_once(Method::POST, "/mutate", &json!({}))
                .await
                .unwrap_err();
            assert_eq!(error.uncertain, status >= 500, "HTTP {status}");
            assert!(error.message.contains(&status.to_string()));
            assert!(!error.message.contains("credential-response-canary"));
            assert_eq!(server.received_requests().await.unwrap().len(), 1);
        }
    }

    #[tokio::test]
    async fn malformed_successful_write_response_is_uncertain_without_mutation_retry() {
        for verb in [Method::GET, Method::POST] {
            let server = MockServer::start().await;
            Mock::given(method(verb.as_str()))
                .and(path("/result"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_string("{malformed credential-response-canary"),
                )
                .expect(1)
                .mount(&server)
                .await;
            let client = PublishClient::test(server.uri(), Auth::Bearer("synthetic-token".into()));
            let error = if verb == Method::GET {
                client.get("/result").await.unwrap_err()
            } else {
                client
                    .send_once(verb.clone(), "/result", &json!({}))
                    .await
                    .unwrap_err()
            };
            assert_eq!(error.uncertain, verb != Method::GET);
            assert!(!error.message.contains("credential-response-canary"));
            assert_eq!(server.received_requests().await.unwrap().len(), 1);
        }
    }

    #[tokio::test]
    async fn oversized_write_response_is_bounded_and_cannot_be_called_verified() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/mutate"))
            .respond_with(
                ResponseTemplate::new(200).set_body_bytes(vec![b'x'; 8 * 1024 * 1024 + 1]),
            )
            .expect(1)
            .mount(&server)
            .await;
        let client = PublishClient::test(server.uri(), Auth::Bearer("synthetic-token".into()));
        let error = client
            .send_once(Method::POST, "/mutate", &json!({}))
            .await
            .unwrap_err();
        assert!(error.uncertain);
        assert!(error.message.contains("8 MiB"));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn token_auth_uses_native_json_api_headers_and_empty_ack_is_not_a_verified_result() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/mutate"))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;
        let client = PublishClient::test(server.uri(), Auth::Token("synthetic-token".into()));
        assert_eq!(
            client
                .send_once(Method::POST, "/mutate", &json!({"data":{}}))
                .await
                .unwrap(),
            Value::Null
        );
        let requests = server.received_requests().await.unwrap();
        assert_eq!(
            requests[0].headers.get("authorization").unwrap(),
            "token synthetic-token"
        );
        assert_eq!(
            requests[0].headers.get("accept").unwrap(),
            "application/vnd.api+json"
        );
        assert_eq!(
            requests[0].headers.get("content-type").unwrap(),
            "application/vnd.api+json"
        );
    }

    #[tokio::test]
    async fn public_constructors_preserve_binding_rate_limit_and_reject_before_oauth() {
        for (provider, url, seconds) in [
            (ProviderKind::Semgrep, "https://semgrep.dev", 0),
            (ProviderKind::Snyk, "https://api.snyk.io", 0),
            (ProviderKind::Aikido, "https://app.aikido.dev", 3),
            (ProviderKind::Checkmarx, "https://eu.ast.checkmarx.net", 0),
        ] {
            let client =
                PublishClient::new(provider, url, Auth::Bearer("synthetic".into())).unwrap();
            assert_eq!(client.provider, provider);
            assert_eq!(client.endpoint_origin(), url);
            assert_eq!(client.interval, Duration::from_secs(seconds));
        }
        assert!(PublishClient::new(
            ProviderKind::Unknown,
            "not a URL",
            Auth::Bearer("synthetic".into())
        )
        .is_err());
        let server = MockServer::start().await;
        for (base, iam) in [
            (server.uri(), server.uri()),
            ("https://eu.ast.checkmarx.net".into(), server.uri()),
        ] {
            let config =
                crate::checkmarx::CheckmarxConfig::new(base, iam, "tenant", "synthetic", "project");
            assert!(checkmarx_client(config).await.is_err());
        }
        let mut config = crate::aikido::AikidoConfig::new("synthetic", "synthetic", 1);
        config.base_url = server.uri();
        assert!(aikido_client(config).await.is_err());
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn public_dispatch_refuses_missing_native_identity_and_cross_provider_clients() {
        let server = MockServer::start().await;
        let mut client = PublishClient::test(server.uri(), Auth::Bearer("synthetic".into()));
        let action = ApprovedAction::Note {
            reason: "Reviewed evidence SEC-123".into(),
        };
        for provider in [
            ProviderKind::Semgrep,
            ProviderKind::Snyk,
            ProviderKind::Checkmarx,
            ProviderKind::Aikido,
            ProviderKind::Unknown,
        ] {
            let origin = ProviderOrigin {
                provider,
                ..Default::default()
            };
            assert!(read(&client, &origin).await.is_err());
            assert!(write(&client, &origin, &action, &Value::Null)
                .await
                .is_err());
        }
        client.provider = ProviderKind::Semgrep;
        let origin = ProviderOrigin {
            provider: ProviderKind::Snyk,
            ..Default::default()
        };
        assert!(read(&client, &origin)
            .await
            .unwrap_err()
            .message
            .contains("binding mismatch"));
        assert!(write(&client, &origin, &action, &Value::Null)
            .await
            .unwrap_err()
            .message
            .contains("binding mismatch"));
        for reason in [" ".into(), "x".repeat(1001)] {
            assert!(write(
                &client,
                &origin,
                &ApprovedAction::Note { reason },
                &Value::Null
            )
            .await
            .unwrap_err()
            .message
            .contains("reason"));
        }
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn invalid_authorization_cannot_send_and_does_not_leak_its_value() {
        let server = MockServer::start().await;
        let client = PublishClient::test(server.uri(), Auth::Bearer("synthetic\ninvalid".into()));
        for verb in [Method::GET, Method::POST] {
            let error = client
                .request(verb.clone(), "/test", None)
                .await
                .unwrap_err();
            assert_eq!(error.uncertain, verb != Method::GET);
            assert!(!error.message.contains("synthetic"));
        }
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn checkmarx_requests_use_the_reviewed_api_version_header() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/version"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .expect(1)
            .mount(&server)
            .await;
        let mut client = PublishClient::test(server.uri(), Auth::Bearer("synthetic".into()));
        client.provider = ProviderKind::Checkmarx;
        client.get("/version").await.unwrap();
        assert_eq!(
            server.received_requests().await.unwrap()[0]
                .headers
                .get("accept")
                .unwrap(),
            "application/json; version=1.0"
        );
    }

    #[tokio::test]
    async fn native_oauth_results_bind_tokens_and_suppress_sensitive_authentication_errors() {
        for success in [true, false] {
            let server = MockServer::start().await;
            for endpoint in [
                "/api/oauth/token",
                "/auth/realms/tenant/protocol/openid-connect/token",
            ] {
                Mock::given(method("POST")).and(path(endpoint))
                    .respond_with(if success {
                        ResponseTemplate::new(200).set_body_json(json!({"access_token":"synthetic-token", "expires_in":3600,"token_type":"bearer"}))
                    } else {
                        ResponseTemplate::new(401).set_body_string("sensitive-authentication-canary")
                    }).expect(1).mount(&server).await;
            }
            let mut a = crate::aikido::AikidoConfig::new("synthetic", "synthetic", 1);
            a.base_url = server.uri();
            let a = crate::aikido::AikidoClient::new(http_client().unwrap(), a)
                .access_token()
                .await;
            let c = crate::checkmarx::CheckmarxConfig::new(
                "https://eu.ast.checkmarx.net",
                server.uri(),
                "tenant",
                "synthetic",
                "project",
            );
            let c = crate::checkmarx::CheckmarxClient::new(http_client().unwrap(), c)
                .access_token()
                .await;
            for result in [
                authenticated_client(ProviderKind::Aikido, "https://app.aikido.dev", a),
                authenticated_client(ProviderKind::Checkmarx, "https://eu.ast.checkmarx.net", c),
            ] {
                if success {
                    let client = result.unwrap();
                    assert!(
                        matches!(&client.auth, Auth::Bearer(value) if value == "synthetic-token")
                    );
                    assert!(trusted_url(client.provider, &client.endpoint_origin()).is_ok());
                } else {
                    let error = result.err().unwrap();
                    assert!(error.message.ends_with("authentication failed"));
                    assert!(!error.message.contains("sensitive-authentication-canary"));
                    assert!(!error.uncertain);
                }
            }
        }
    }
}
