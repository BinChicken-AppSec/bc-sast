use std::future::Future;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

#[derive(Debug, Clone)]
pub(crate) struct CachedToken {
    pub access_token: String,
    expires_at: Instant,
}

impl CachedToken {
    pub(crate) fn new(access_token: String, expires_in: Duration) -> Self {
        let margin = Duration::from_secs(30).min(expires_in / 4);
        CachedToken {
            access_token,
            expires_at: Instant::now() + expires_in.saturating_sub(margin),
        }
    }

    fn is_valid(&self) -> bool {
        Instant::now() < self.expires_at
    }
}

pub(crate) struct TokenCache {
    cached: Mutex<Option<CachedToken>>,
}

impl TokenCache {
    pub(crate) fn new() -> Self {
        TokenCache {
            cached: Mutex::new(None),
        }
    }

    pub(crate) async fn get_or_refresh<F, Fut, E>(&self, fetch: F) -> Result<String, E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<CachedToken, E>>,
    {
        let mut guard = self.cached.lock().await;
        if let Some(tok) = guard.as_ref() {
            if tok.is_valid() {
                return Ok(tok.access_token.clone());
            }
        }
        let fresh = fetch().await?;
        let token = fresh.access_token.clone();
        *guard = Some(fresh);
        Ok(token)
    }

    pub(crate) async fn invalidate(&self) {
        *self.cached.lock().await = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cached_token_with_a_long_lifetime_is_valid_immediately() {
        let tok = CachedToken::new("abc".to_string(), Duration::from_secs(3600));
        assert!(tok.is_valid());
    }

    #[test]
    fn cached_token_with_zero_lifetime_is_immediately_invalid() {
        let tok = CachedToken::new("abc".to_string(), Duration::ZERO);
        assert!(!tok.is_valid());
    }

    #[tokio::test]
    async fn get_or_refresh_fetches_on_first_call() {
        let cache = TokenCache::new();
        let calls = std::sync::atomic::AtomicU32::new(0);
        let token: Result<String, String> = cache
            .get_or_refresh(|| async {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(CachedToken::new(
                    "fresh".to_string(),
                    Duration::from_secs(3600),
                ))
            })
            .await;
        assert_eq!(token, Ok("fresh".to_string()));
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn get_or_refresh_reuses_a_still_valid_cached_token() {
        let cache = TokenCache::new();
        let calls = std::sync::atomic::AtomicU32::new(0);
        for _ in 0..3 {
            let _: Result<String, String> = cache
                .get_or_refresh(|| async {
                    calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Ok(CachedToken::new(
                        "fresh".to_string(),
                        Duration::from_secs(3600),
                    ))
                })
                .await;
        }
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn get_or_refresh_refetches_once_the_cached_token_expires() {
        let cache = TokenCache::new();
        let calls = std::sync::atomic::AtomicU32::new(0);
        let first: Result<String, String> = cache
            .get_or_refresh(|| async {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(CachedToken::new("stale".to_string(), Duration::ZERO))
            })
            .await;
        assert_eq!(first, Ok("stale".to_string()));
        let second: Result<String, String> = cache
            .get_or_refresh(|| async {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(CachedToken::new(
                    "renewed".to_string(),
                    Duration::from_secs(3600),
                ))
            })
            .await;
        assert_eq!(second, Ok("renewed".to_string()));
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn invalidate_forces_a_refetch_of_a_still_valid_token() {
        let cache = TokenCache::new();
        let calls = std::sync::atomic::AtomicU32::new(0);
        let fetch = || async {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok::<_, String>(CachedToken::new(
                "fresh".to_string(),
                Duration::from_secs(3600),
            ))
        };

        let first = cache.get_or_refresh(fetch).await;
        cache.invalidate().await;
        let second = cache.get_or_refresh(fetch).await;

        assert_eq!(first, Ok("fresh".to_string()));
        assert_eq!(second, Ok("fresh".to_string()));
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn invalidate_on_an_empty_cache_is_a_no_op() {
        let cache = TokenCache::new();
        cache.invalidate().await;
        let token: Result<String, String> = cache
            .get_or_refresh(|| async {
                Ok(CachedToken::new("t".to_string(), Duration::from_secs(60)))
            })
            .await;
        assert_eq!(token, Ok("t".to_string()));
    }

    #[tokio::test]
    async fn get_or_refresh_propagates_a_fetch_error() {
        let cache = TokenCache::new();
        let result: Result<String, String> = cache
            .get_or_refresh(|| async { Err::<CachedToken, String>("boom".to_string()) })
            .await;
        assert_eq!(result, Err("boom".to_string()));
    }
}
