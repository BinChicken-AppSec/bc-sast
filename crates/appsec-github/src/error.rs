use thiserror::Error;

#[derive(Debug, Error)]
pub enum GithubError {
    #[error("GitHub API request failed: {message}")]
    Request { message: String },
    #[error("GitHub API returned HTTP {status}: {message}")]
    Http { status: u16, message: String },
    #[error("failed to parse GitHub API response: {message}")]
    Json { message: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_messages() {
        assert_eq!(
            GithubError::Request {
                message: "timed out".to_string()
            }
            .to_string(),
            "GitHub API request failed: timed out"
        );
        assert_eq!(
            GithubError::Http {
                status: 404,
                message: "not found".to_string()
            }
            .to_string(),
            "GitHub API returned HTTP 404: not found"
        );
        assert_eq!(
            GithubError::Json {
                message: "eof".to_string()
            }
            .to_string(),
            "failed to parse GitHub API response: eof"
        );
    }

    #[test]
    fn implements_std_error_and_debug() {
        let e = GithubError::Request {
            message: "x".to_string(),
        };
        let _: &dyn std::error::Error = &e;
        assert!(format!("{e:?}").contains("Request"));
    }
}
