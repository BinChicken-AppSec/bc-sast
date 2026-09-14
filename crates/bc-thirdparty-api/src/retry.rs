//! A tiny, crate-internal HTTP retry helper shared by all five live vendor
//! clients. Every one of these vendors publishes a rate limit and expects
//! clients to back off rather than fail: Aikido documents a 20-calls-per-
//! minute sliding window that answers `429` with a `Retry-After` header in
//! seconds (`apidocs.aikido.dev/reference/rate-limiting`), and Snyk
//! documents 1620 requests/minute with the explicit instruction that "all
//! clients are expected to handle the `429` responses correctly, and such
//! requests can be retried later safely"
//! (`snyk/user-docs` — `about-the-rest-api.md`). Semgrep/Sonatype/Checkmarx
//! publish no numbers but sit behind the same class of edge proxies that
//! emit transient `502`/`503`/`504`.
//!
//! Retrying matters more here than it looks: a live-fetch failure is a
//! warn-and-skip in `bc-orchestrator`, so a single transient `429` silently
//! costs the operator that vendor's entire finding set for the run, with
//! nothing but one WARN line to show for it.
//!
//! Deliberately narrow: retries only the four statuses above, never a
//! transport error (a connect/DNS failure is usually a misconfiguration
//! worth surfacing immediately, not a blip worth three round-trips) and
//! never a `4xx` other than `429` (an auth or request-shape problem does
//! not get better by repeating it).

use std::time::Duration;

/// Total attempts including the first — so at most two *re*-tries.
const MAX_ATTEMPTS: u32 = 3;
/// Cap on an honored `Retry-After`: a vendor is free to ask for a
/// ten-minute wait, but a scan pipeline blocking that long on one optional
/// enrichment source is worse than skipping the vendor.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(60);
/// Fallback backoff when the response carries no usable `Retry-After` —
/// doubled per attempt (1s, then 2s).
const BASE_BACKOFF: Duration = Duration::from_secs(1);

/// A fully-read HTTP response: every vendor client here needs both the
/// status and the body text (the body doubles as the error message on a
/// non-success status), so the helper reads the body eagerly rather than
/// handing back a streaming `reqwest::Response`.
pub(crate) struct HttpText {
    pub status: reqwest::StatusCode,
    pub body: String,
}

/// Parses a `Retry-After` header value as delta-seconds. The HTTP-date
/// form of `Retry-After` is deliberately not supported — none of these five
/// vendors documents emitting it, and falling through to the exponential
/// backoff below is a safe, bounded degrade.
fn retry_after_seconds(raw: Option<&str>) -> Option<Duration> {
    raw?.trim().parse::<u64>().ok().map(Duration::from_secs)
}

/// How long to wait before re-issuing a request that returned `status`, or
/// `None` if it should not be retried at all. `attempt` is 0-based and
/// always `< MAX_ATTEMPTS`, so the `2^attempt` factor cannot overflow.
fn retry_delay(status: u16, retry_after: Option<&str>, attempt: u32) -> Option<Duration> {
    if !matches!(status, 429 | 502 | 503 | 504) {
        return None;
    }
    match retry_after_seconds(retry_after) {
        Some(delay) => Some(delay.min(MAX_RETRY_AFTER)),
        None => Some(BASE_BACKOFF * 2u32.pow(attempt)),
    }
}

/// Sends the request `build` produces, retrying per [`retry_delay`] until
/// it succeeds, returns a non-retryable status, or exhausts
/// [`MAX_ATTEMPTS`]. `build` is a closure rather than a prepared
/// `RequestBuilder` because a `RequestBuilder` is consumed by `send()` and
/// so cannot be reused for a second attempt.
///
/// The final response is returned as-is even when it is still a `429`/`5xx`
/// — the caller turns that into its own vendor-specific `Http` error, so
/// the operator sees the real status and body rather than a generic
/// "retries exhausted".
pub(crate) async fn send_with_retry<F>(build: F) -> Result<HttpText, reqwest::Error>
where
    F: Fn() -> reqwest::RequestBuilder,
{
    let mut attempt = 0u32;
    loop {
        let response = build().send().await?;
        let status = response.status();
        let retry_after = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let delay = if attempt + 1 < MAX_ATTEMPTS {
            retry_delay(status.as_u16(), retry_after.as_deref(), attempt)
        } else {
            None
        };
        let Some(delay) = delay else {
            return Ok(HttpText {
                status,
                body: response.text().await?,
            });
        };
        drop(response);
        tokio::time::sleep(delay).await;
        attempt += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn retry_after_seconds_parses_plain_delta_seconds() {
        assert_eq!(
            retry_after_seconds(Some("12")),
            Some(Duration::from_secs(12))
        );
    }

    #[test]
    fn retry_after_seconds_tolerates_surrounding_whitespace() {
        assert_eq!(
            retry_after_seconds(Some(" 3 ")),
            Some(Duration::from_secs(3))
        );
    }

    #[test]
    fn retry_after_seconds_rejects_an_http_date() {
        assert_eq!(
            retry_after_seconds(Some("Wed, 21 Oct 2026 07:28:00 GMT")),
            None
        );
    }

    #[test]
    fn retry_after_seconds_of_an_absent_header_is_none() {
        assert_eq!(retry_after_seconds(None), None);
    }

    #[rstest::rstest]
    #[case(429)]
    #[case(502)]
    #[case(503)]
    #[case(504)]
    fn retryable_statuses_get_a_delay(#[case] status: u16) {
        assert!(retry_delay(status, None, 0).is_some());
    }

    #[rstest::rstest]
    #[case(200)]
    #[case(401)]
    #[case(403)]
    #[case(404)]
    #[case(500)]
    fn non_retryable_statuses_get_no_delay(#[case] status: u16) {
        assert_eq!(retry_delay(status, None, 0), None);
    }

    #[test]
    fn retry_delay_honors_a_retry_after_header() {
        assert_eq!(retry_delay(429, Some("7"), 0), Some(Duration::from_secs(7)));
    }

    #[test]
    fn retry_delay_caps_an_excessive_retry_after_at_sixty_seconds() {
        assert_eq!(retry_delay(429, Some("6000"), 0), Some(MAX_RETRY_AFTER));
    }

    #[test]
    fn retry_delay_backs_off_exponentially_without_a_retry_after() {
        assert_eq!(retry_delay(503, None, 0), Some(Duration::from_secs(1)));
        assert_eq!(retry_delay(503, None, 1), Some(Duration::from_secs(2)));
    }

    #[tokio::test]
    async fn a_successful_response_is_returned_without_retrying() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/ok"))
            .respond_with(ResponseTemplate::new(200).set_body_string("hello"))
            .expect(1)
            .mount(&server)
            .await;

        let http = reqwest::Client::new();
        let url = format!("{}/ok", server.uri());
        let result = send_with_retry(|| http.get(&url)).await.unwrap();

        assert_eq!(result.status.as_u16(), 200);
        assert_eq!(result.body, "hello");
    }

    #[tokio::test]
    async fn a_non_retryable_status_is_returned_after_a_single_attempt() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/nope"))
            .respond_with(ResponseTemplate::new(401).set_body_string("unauthorized"))
            .expect(1)
            .mount(&server)
            .await;

        let http = reqwest::Client::new();
        let url = format!("{}/nope", server.uri());
        let result = send_with_retry(|| http.get(&url)).await.unwrap();

        assert_eq!(result.status.as_u16(), 401);
        assert_eq!(result.body, "unauthorized");
    }

    #[tokio::test]
    async fn a_429_with_retry_after_zero_is_retried_then_succeeds() {
        let server = MockServer::start().await;
        // wiremock serves the first-mounted matching mock that still has
        // uses left, so the 200 registered second answers only once the
        // 429's `up_to_n_times(1)` is spent.
        Mock::given(method("GET"))
            .and(path("/limited"))
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("Retry-After", "0")
                    .set_body_string("slow down"),
            )
            .up_to_n_times(1)
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/limited"))
            .respond_with(ResponseTemplate::new(200).set_body_string("finally"))
            .expect(1)
            .mount(&server)
            .await;

        let http = reqwest::Client::new();
        let url = format!("{}/limited", server.uri());
        let result = send_with_retry(|| http.get(&url)).await.unwrap();

        assert_eq!(result.status.as_u16(), 200);
        assert_eq!(result.body, "finally");
    }

    #[tokio::test(start_paused = true)]
    async fn a_503_without_retry_after_is_retried_on_the_exponential_backoff() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/flaky"))
            .respond_with(ResponseTemplate::new(503).set_body_string("unavailable"))
            .up_to_n_times(1)
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/flaky"))
            .respond_with(ResponseTemplate::new(200).set_body_string("recovered"))
            .expect(1)
            .mount(&server)
            .await;

        let http = reqwest::Client::new();
        let url = format!("{}/flaky", server.uri());
        let result = send_with_retry(|| http.get(&url)).await.unwrap();

        assert_eq!(result.status.as_u16(), 200);
        assert_eq!(result.body, "recovered");
    }

    #[tokio::test]
    async fn a_persistently_rate_limited_endpoint_gives_up_after_three_attempts() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/always-limited"))
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("Retry-After", "0")
                    .set_body_string("still limited"),
            )
            .expect(MAX_ATTEMPTS as u64)
            .mount(&server)
            .await;

        let http = reqwest::Client::new();
        let url = format!("{}/always-limited", server.uri());
        let result = send_with_retry(|| http.get(&url)).await.unwrap();

        assert_eq!(result.status.as_u16(), 429);
        assert_eq!(result.body, "still limited");
    }

    #[tokio::test]
    async fn a_transport_failure_is_propagated_without_retrying() {
        let http = reqwest::Client::new();
        let url = "http://127.0.0.1:1/unreachable".to_string();
        assert!(send_with_retry(|| http.get(&url)).await.is_err());
    }
}
