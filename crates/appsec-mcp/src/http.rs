use std::time::Duration;

use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, RETRY_AFTER};

use crate::confluence::HttpTransport;
use crate::sharepoint::GraphTransport;
use crate::{BytesResponse, HttpResponse};

pub const DEFAULT_MAX_BYTES: usize = 8 * 1024 * 1024;
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub struct ReqwestTransport {
    client: reqwest::Client,
    runtime: tokio::runtime::Runtime,
    timeout: Duration,
    max_bytes: usize,
}

impl ReqwestTransport {
    pub fn new(timeout: Duration, max_bytes: usize) -> Result<Self, String> {
        Self::build(timeout, max_bytes, true)
    }

    #[cfg(test)]
    fn plaintext_for_tests(timeout: Duration, max_bytes: usize) -> Result<Self, String> {
        Self::build(timeout, max_bytes, false)
    }

    fn build(timeout: Duration, max_bytes: usize, https_only: bool) -> Result<Self, String> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .https_only(https_only)
            .build()
            .map_err(|e| format!("could not build the HTTP client: {e}"))?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("could not start a runtime: {e}"))?;
        Ok(Self {
            client,
            runtime,
            timeout,
            max_bytes,
        })
    }
}

impl ReqwestTransport {
    fn send(&self, request: reqwest::RequestBuilder) -> Result<HttpResponse, String> {
        self.runtime.block_on(async {
            let response = request
                .timeout(self.timeout)
                .send()
                .await
                .map_err(|e| format!("request failed: {e}"))?;

            let status = response.status().as_u16();
            let retry_after = response
                .headers()
                .get(RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim().parse::<u64>().ok());

            let body = read_capped(response, self.max_bytes).await?;
            Ok(HttpResponse {
                status,
                body: String::from_utf8(body).map_err(|_| "response body was not UTF-8")?,
                retry_after,
            })
        })
    }

    fn send_bytes(&self, request: reqwest::RequestBuilder) -> Result<BytesResponse, String> {
        self.runtime.block_on(async {
            let response = request
                .timeout(self.timeout)
                .send()
                .await
                .map_err(|e| format!("request failed: {e}"))?;
            let status = response.status().as_u16();
            let retry_after = response
                .headers()
                .get(RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim().parse::<u64>().ok());
            let body = read_capped(response, self.max_bytes).await?;
            Ok(BytesResponse {
                status,
                body,
                retry_after,
            })
        })
    }
}

impl HttpTransport for ReqwestTransport {
    fn get(&self, url: &str, auth: &str) -> Result<HttpResponse, String> {
        self.send(
            self.client
                .get(url)
                .header(AUTHORIZATION, auth)
                .header(ACCEPT, "application/json"),
        )
    }
}

impl GraphTransport for ReqwestTransport {
    fn post_form(&self, url: &str, body: &str) -> Result<HttpResponse, String> {
        self.send(
            self.client
                .post(url)
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(ACCEPT, "application/json")
                .body(body.to_string()),
        )
    }

    fn post_json(&self, url: &str, auth: &str, body: &str) -> Result<HttpResponse, String> {
        self.send(
            self.client
                .post(url)
                .header(AUTHORIZATION, auth)
                .header(CONTENT_TYPE, "application/json")
                .header(ACCEPT, "application/json")
                .body(body.to_string()),
        )
    }

    fn get_json(&self, url: &str, auth: &str) -> Result<HttpResponse, String> {
        self.send(
            self.client
                .get(url)
                .header(AUTHORIZATION, auth)
                .header(ACCEPT, "application/json"),
        )
    }

    fn get_unauthenticated(&self, url: &str) -> Result<BytesResponse, String> {
        self.send_bytes(self.client.get(url))
    }
}

async fn read_capped(mut response: reqwest::Response, max_bytes: usize) -> Result<Vec<u8>, String> {
    let mut body: Vec<u8> = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| format!("reading the response body failed: {e}"))?
    {
        if body.len() + chunk.len() > max_bytes {
            return Err(format!(
                "response body exceeded the {max_bytes} byte cap; refusing it"
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    fn server_with(mock: Mock) -> (tokio::runtime::Runtime, MockServer) {
        let rt = tokio::runtime::Runtime::new().expect("a runtime");
        let server = rt.block_on(MockServer::start());
        rt.block_on(mock.mount(&server));
        (rt, server)
    }

    fn transport() -> ReqwestTransport {
        ReqwestTransport::plaintext_for_tests(Duration::from_secs(5), DEFAULT_MAX_BYTES)
            .expect("a transport")
    }

    #[test]
    fn a_get_carries_the_auth_header_and_returns_status_and_body() {
        let (_rt, server) = server_with(
            Mock::given(method("GET"))
                .and(path("/wiki/rest/api/search"))
                .and(header("authorization", "Basic dXNlcjp0b2tlbg=="))
                .and(header("accept", "application/json"))
                .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"results":[]}"#)),
        );
        let got = transport()
            .get(
                &format!("{}/wiki/rest/api/search", server.uri()),
                "Basic dXNlcjp0b2tlbg==",
            )
            .expect("a response");
        assert_eq!(got.status, 200);
        assert_eq!(got.body, r#"{"results":[]}"#);
        assert_eq!(got.retry_after, None);
    }

    #[test]
    fn a_429_surfaces_its_retry_after_in_seconds() {
        let (_rt, server) = server_with(
            Mock::given(method("GET")).respond_with(
                ResponseTemplate::new(429)
                    .insert_header("retry-after", "7")
                    .set_body_string("slow down"),
            ),
        );
        let got = transport()
            .get(&server.uri(), "Basic x")
            .expect("a response");
        assert_eq!(got.status, 429);
        assert_eq!(got.retry_after, Some(7));
    }

    #[test]
    fn a_non_numeric_retry_after_reads_as_absent() {
        let (_rt, server) = server_with(
            Mock::given(method("GET")).respond_with(
                ResponseTemplate::new(429)
                    .insert_header("retry-after", "Wed, 21 Oct 2026 07:28:00 GMT"),
            ),
        );
        assert_eq!(
            transport()
                .get(&server.uri(), "Basic x")
                .expect("ok")
                .retry_after,
            None
        );
    }

    #[test]
    fn a_redirect_is_not_followed() {
        let (_rt, server) = server_with(Mock::given(method("GET")).respond_with(
            ResponseTemplate::new(302).insert_header("location", "https://evil.example.com/"),
        ));
        let got = transport()
            .get(&server.uri(), "Basic x")
            .expect("a response");
        assert_eq!(got.status, 302);
        assert!(got.body.is_empty(), "{:?}", got.body);
    }

    #[test]
    fn a_body_over_the_cap_is_refused() {
        let (_rt, server) = server_with(
            Mock::given(method("GET"))
                .respond_with(ResponseTemplate::new(200).set_body_string("x".repeat(4096))),
        );
        let small = ReqwestTransport::plaintext_for_tests(Duration::from_secs(5), 1024)
            .expect("a transport");
        let err = small.get(&server.uri(), "Basic x").expect_err("refused");
        assert!(err.contains("exceeded the 1024 byte cap"), "{err}");
    }

    #[test]
    fn a_body_at_the_cap_is_accepted() {
        let (_rt, server) = server_with(
            Mock::given(method("GET"))
                .respond_with(ResponseTemplate::new(200).set_body_string("x".repeat(1024))),
        );
        let exact = ReqwestTransport::plaintext_for_tests(Duration::from_secs(5), 1024)
            .expect("a transport");
        assert_eq!(
            exact.get(&server.uri(), "Basic x").expect("ok").body.len(),
            1024
        );
    }

    #[test]
    fn a_non_utf8_body_is_an_error_not_a_lossy_string() {
        let (_rt, server) = server_with(
            Mock::given(method("GET"))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![0xff, 0xfe, 0x00])),
        );
        let err = transport()
            .get(&server.uri(), "Basic x")
            .expect_err("refused");
        assert!(err.contains("not UTF-8"), "{err}");
    }

    #[test]
    fn an_unreachable_host_is_a_transport_error() {
        let err = transport()
            .get("http://127.0.0.1:1/x", "Basic x")
            .expect_err("refused");
        assert!(err.contains("request failed"), "{err}");
    }

    #[test]
    fn the_real_constructor_refuses_plain_http_that_the_test_one_accepts() {
        let (_rt, server) = server_with(
            Mock::given(method("GET"))
                .respond_with(ResponseTemplate::new(200).set_body_string("reached")),
        );
        let url = server.uri();
        assert!(url.starts_with("http://"), "{url}");

        assert_eq!(
            transport().get(&url, "Basic x").expect("ok").body,
            "reached"
        );
        let real = ReqwestTransport::new(Duration::from_secs(5), DEFAULT_MAX_BYTES).expect("built");
        let err = real.get(&url, "Basic x").expect_err("refused");
        assert!(err.contains("request failed"), "{err}");
    }

    #[test]
    fn the_defaults_are_the_documented_ones() {
        assert_eq!(DEFAULT_MAX_BYTES, 8 * 1024 * 1024);
        assert_eq!(DEFAULT_TIMEOUT, Duration::from_secs(30));
        assert!(ReqwestTransport::new(DEFAULT_TIMEOUT, DEFAULT_MAX_BYTES).is_ok());
    }

    #[test]
    fn a_body_that_ends_early_is_an_error_not_a_short_string() {
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
        let port = listener.local_addr().expect("an address").port();
        std::thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let _ = sock.read(&mut [0u8; 1024]);
                let _ = sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort");
            }
        });

        let err = transport()
            .get(&format!("http://127.0.0.1:{port}/x"), "Basic x")
            .expect_err("an incomplete body must not read as a complete one");
        assert!(err.contains("reading the response body failed"), "{err}");
    }

    fn sent_headers(rt: &tokio::runtime::Runtime, server: &MockServer) -> Vec<(String, String)> {
        rt.block_on(server.received_requests())
            .expect("the mock server records requests")
            .first()
            .expect("one request")
            .headers
            .iter()
            .map(|(n, v)| {
                (
                    n.as_str().to_ascii_lowercase(),
                    v.to_str().unwrap_or_default().to_string(),
                )
            })
            .collect()
    }

    fn header_names(headers: &[(String, String)]) -> Vec<&str> {
        headers.iter().map(|(n, _)| n.as_str()).collect()
    }

    #[test]
    fn an_unauthenticated_get_sends_no_authorization_header_at_all() {
        let (rt, server) = server_with(
            Mock::given(method("GET"))
                .respond_with(ResponseTemplate::new(200).set_body_string("# doc")),
        );
        let got = transport()
            .get_unauthenticated(&format!("{}/y23vmaga?token=opaque", server.uri()))
            .expect("a response");
        assert_eq!(got.status, 200);
        assert_eq!(got.body, b"# doc");

        let headers = sent_headers(&rt, &server);
        let names = header_names(&headers);
        assert!(
            !names.contains(&"authorization"),
            "a credential went to the download host: {names:?}"
        );
        assert!(!names.contains(&"cookie"), "{names:?}");
    }

    #[test]
    fn the_authenticated_get_does_send_one_so_the_difference_is_the_method() {
        let (rt, server) = server_with(
            Mock::given(method("GET"))
                .respond_with(ResponseTemplate::new(200).set_body_string("{}")),
        );
        transport()
            .get_json(&server.uri(), "Bearer TOKEN-ABC")
            .expect("a response");
        let headers = sent_headers(&rt, &server);
        assert!(
            headers
                .iter()
                .any(|(n, v)| n == "authorization" && v == "Bearer TOKEN-ABC"),
            "{headers:?}"
        );
    }

    #[test]
    fn a_form_post_carries_the_body_and_no_authorization_header() {
        let (rt, server) = server_with(
            Mock::given(method("POST"))
                .and(header("content-type", "application/x-www-form-urlencoded"))
                .respond_with(
                    ResponseTemplate::new(200).set_body_string(r#"{"access_token":"x"}"#),
                ),
        );
        let got = transport()
            .post_form(&server.uri(), "client_id=a&client_secret=b%2Bc")
            .expect("a response");
        assert_eq!(got.status, 200);

        let requests = rt
            .block_on(server.received_requests())
            .expect("recorded")
            .clone();
        assert_eq!(
            String::from_utf8_lossy(&requests[0].body),
            "client_id=a&client_secret=b%2Bc"
        );
        assert!(
            !header_names(&sent_headers(&rt, &server)).contains(&"authorization"),
            "the token request carried a second copy of the credential"
        );
    }

    #[test]
    fn a_json_post_carries_the_token_the_body_and_the_content_type() {
        let (rt, server) = server_with(
            Mock::given(method("POST"))
                .and(header("content-type", "application/json"))
                .and(header("authorization", "Bearer T"))
                .respond_with(ResponseTemplate::new(200).set_body_string("{}")),
        );
        let got = transport()
            .post_json(&server.uri(), "Bearer T", r#"{"requests":[]}"#)
            .expect("a response");
        assert_eq!(got.status, 200);
        let requests = rt.block_on(server.received_requests()).expect("recorded");
        assert_eq!(
            String::from_utf8_lossy(&requests[0].body),
            r#"{"requests":[]}"#
        );
    }

    #[test]
    fn the_body_cap_applies_to_the_unauthenticated_path_too() {
        let (_rt, server) = server_with(
            Mock::given(method("GET"))
                .respond_with(ResponseTemplate::new(200).set_body_string("x".repeat(4096))),
        );
        let small = ReqwestTransport::plaintext_for_tests(Duration::from_secs(5), 1024)
            .expect("a transport");
        let err = small
            .get_unauthenticated(&server.uri())
            .expect_err("refused");
        assert!(err.contains("exceeded the 1024 byte cap"), "{err}");
    }

    #[test]
    fn a_redirect_is_not_followed_on_the_graph_methods_either() {
        let (_rt, server) = server_with(Mock::given(method("GET")).respond_with(
            ResponseTemplate::new(302).insert_header("location", "https://evil.example.com/"),
        ));
        let t = transport();
        let unauth = t.get_unauthenticated(&server.uri()).expect("a response");
        assert_eq!(unauth.status, 302);
        assert!(unauth.body.is_empty(), "{:?}", unauth.body);
        let authed = t.get_json(&server.uri(), "Bearer T").expect("a response");
        assert_eq!(authed.status, 302);
        assert!(authed.body.is_empty(), "{:?}", authed.body);
    }

    #[test]
    fn a_graph_429_surfaces_its_retry_after_through_the_shared_reader() {
        let (_rt, server) = server_with(
            Mock::given(method("POST")).respond_with(
                ResponseTemplate::new(429)
                    .insert_header("retry-after", "10")
                    .set_body_string("throttled"),
            ),
        );
        let got = transport()
            .post_json(&server.uri(), "Bearer T", "{}")
            .expect("a response");
        assert_eq!(got.status, 429);
        assert_eq!(got.retry_after, Some(10));
    }

    #[test]
    fn a_throttled_download_surfaces_its_retry_after() {
        let (_rt, server) = server_with(
            Mock::given(method("GET")).respond_with(
                ResponseTemplate::new(429)
                    .insert_header("retry-after", "13")
                    .set_body_string("slow down"),
            ),
        );
        let got = transport()
            .get_unauthenticated(&server.uri())
            .expect("a response");
        assert_eq!(got.status, 429);
        assert_eq!(got.retry_after, Some(13));
        assert_eq!(got.body, b"slow down");
    }

    #[test]
    fn a_non_numeric_retry_after_on_the_download_reads_as_absent() {
        let (_rt, server) = server_with(
            Mock::given(method("GET")).respond_with(
                ResponseTemplate::new(429)
                    .insert_header("retry-after", "Wed, 21 Oct 2026 07:28:00 GMT"),
            ),
        );
        assert_eq!(
            transport()
                .get_unauthenticated(&server.uri())
                .expect("ok")
                .retry_after,
            None
        );
    }

    #[test]
    fn the_real_constructor_refuses_a_plaintext_download_url() {
        let (_rt, server) = server_with(
            Mock::given(method("GET"))
                .respond_with(ResponseTemplate::new(200).set_body_string("reached")),
        );
        let url = server.uri();
        assert!(url.starts_with("http://"), "{url}");
        assert_eq!(
            transport().get_unauthenticated(&url).expect("ok").body,
            b"reached"
        );
        let real = ReqwestTransport::new(Duration::from_secs(5), DEFAULT_MAX_BYTES).expect("built");
        let err = real.get_unauthenticated(&url).expect_err("refused");
        assert!(err.contains("request failed"), "{err}");
    }
}
