use std::time::Duration;

const MAX_ATTEMPTS: u32 = 3;
const MAX_RETRY_AFTER: Duration = Duration::from_secs(60);
const BASE_BACKOFF: Duration = Duration::from_secs(1);

pub(crate) struct HttpText {
    pub status: reqwest::StatusCode,
    pub body: String,
}

fn retry_after_seconds(raw: Option<&str>) -> Option<Duration> {
    raw?.trim().parse::<u64>().ok().map(Duration::from_secs)
}

fn retry_delay(status: u16, retry_after: Option<&str>, attempt: u32) -> Option<Duration> {
    if !matches!(status, 429 | 502 | 503 | 504) {
        return None;
    }
    match retry_after_seconds(retry_after) {
        Some(delay) => Some(delay.min(MAX_RETRY_AFTER)),
        None => Some(BASE_BACKOFF * 2u32.pow(attempt)),
    }
}

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
