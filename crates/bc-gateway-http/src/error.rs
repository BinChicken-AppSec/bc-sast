use std::fmt;
use std::path::PathBuf;

#[derive(Debug)]
pub enum GatewayError {
    Io { path: PathBuf, message: String },
    InvalidCaCert { path: PathBuf, message: String },
    Build { message: String },
}

impl fmt::Display for GatewayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GatewayError::Io { path, message } => {
                write!(f, "cannot read ca_cert {}: {message}", path.display())
            }
            GatewayError::InvalidCaCert { path, message } => {
                write!(f, "invalid ca_cert {}: {message}", path.display())
            }
            GatewayError::Build { message } => write!(f, "failed to build HTTP client: {message}"),
        }
    }
}

impl std::error::Error for GatewayError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_messages() {
        let io = GatewayError::Io {
            path: PathBuf::from("/a"),
            message: "not found".to_string(),
        };
        assert_eq!(io.to_string(), "cannot read ca_cert /a: not found");
        let invalid = GatewayError::InvalidCaCert {
            path: PathBuf::from("/a"),
            message: "bad pem".to_string(),
        };
        assert_eq!(invalid.to_string(), "invalid ca_cert /a: bad pem");
        let build = GatewayError::Build {
            message: "boom".to_string(),
        };
        assert_eq!(build.to_string(), "failed to build HTTP client: boom");
    }

    #[test]
    fn implements_std_error() {
        let e = GatewayError::Build {
            message: "x".to_string(),
        };
        let _: &dyn std::error::Error = &e;
    }
}
