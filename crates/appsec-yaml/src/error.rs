use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YamlError {
    pub line: usize,
    pub message: String,
}

impl YamlError {
    pub fn new(line: usize, message: impl Into<String>) -> Self {
        Self {
            line,
            message: message.into(),
        }
    }
}

impl fmt::Display for YamlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

impl std::error::Error for YamlError {}
