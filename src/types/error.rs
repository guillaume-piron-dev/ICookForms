//! Error types for `ICOokForms`

use thiserror::Error;

/// Main error type for `ICOokForms`
#[derive(Error, Debug)]
pub enum Error {
    /// HTTP request error
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    /// URL parsing error
    #[error("Invalid URL: {0}")]
    UrlParse(#[from] url::ParseError),

    /// Cookie parsing error
    #[error("Failed to parse cookie: {0}")]
    CookieParse(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Database error
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    /// Serialization error (JSON)
    #[error("JSON serialization error: {0}")]
    JsonSerialization(#[from] serde_json::Error),

    /// Serialization error (YAML)
    #[error("YAML serialization error: {0}")]
    YamlSerialization(#[from] serde_yaml::Error),

    /// PDF generation error
    #[error("PDF generation error: {0}")]
    Pdf(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// Analysis error
    #[error("Analysis failed: {0}")]
    Analysis(String),

    /// Scanner error
    #[error("Scanner error: {0}")]
    Scanner(String),

    /// Reporter error
    #[error("Report generation failed: {0}")]
    Reporter(String),

    /// Compliance check error
    #[error("Compliance check failed: {0}")]
    Compliance(String),

    /// Validation error
    #[error("Validation error: {0}")]
    Validation(String),

    /// Not found error
    #[error("Not found: {0}")]
    NotFound(String),

    /// Permission denied
    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    /// Timeout error
    #[error("Operation timed out: {0}")]
    Timeout(String),

    /// Generic error
    #[error("{0}")]
    Generic(String),

    /// Forensic analysis error
    #[error("Forensic analysis error: {0}")]
    ForensicError(String),

    /// Invalid state error
    #[error("Invalid state: {0}")]
    InvalidState(String),

    /// Invalid input error
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// ML/AI error
    #[error("ML/AI error: {0}")]
    MLError(String),
}

/// Result type alias for `ICOokForms` operations
pub type Result<T> = std::result::Result<T, Error>;

// Custom From implementations for libraries without std::error::Error
#[cfg(feature = "reporter")]
impl From<printpdf::Error> for Error {
    fn from(err: printpdf::Error) -> Self {
        Self::Pdf(format!("{err:?}"))
    }
}

impl Error {
    /// Create a new configuration error
    pub fn config<S: Into<String>>(msg: S) -> Self {
        Self::Config(msg.into())
    }

    /// Create a new analysis error
    pub fn analysis<S: Into<String>>(msg: S) -> Self {
        Self::Analysis(msg.into())
    }

    /// Create a new scanner error
    pub fn scanner<S: Into<String>>(msg: S) -> Self {
        Self::Scanner(msg.into())
    }

    /// Create a new reporter error
    pub fn reporter<S: Into<String>>(msg: S) -> Self {
        Self::Reporter(msg.into())
    }

    /// Create a new compliance error
    pub fn compliance<S: Into<String>>(msg: S) -> Self {
        Self::Compliance(msg.into())
    }

    /// Create a new validation error
    pub fn validation<S: Into<String>>(msg: S) -> Self {
        Self::Validation(msg.into())
    }

    /// Create a new not found error
    pub fn not_found<S: Into<String>>(msg: S) -> Self {
        Self::NotFound(msg.into())
    }

    /// Create a new timeout error
    pub fn timeout<S: Into<String>>(msg: S) -> Self {
        Self::Timeout(msg.into())
    }

    /// Create a new generic error
    pub fn generic<S: Into<String>>(msg: S) -> Self {
        Self::Generic(msg.into())
    }

    /// Create a new PDF error
    pub fn pdf<S: Into<String>>(msg: S) -> Self {
        Self::Pdf(msg.into())
    }

    /// Create a new forensic error
    pub fn forensic<S: Into<String>>(msg: S) -> Self {
        Self::ForensicError(msg.into())
    }

    /// Create a new invalid state error
    pub fn invalid_state<S: Into<String>>(msg: S) -> Self {
        Self::InvalidState(msg.into())
    }

    /// Create a new invalid input error
    pub fn invalid_input<S: Into<String>>(msg: S) -> Self {
        Self::InvalidInput(msg.into())
    }

    /// Create a new ML error
    pub fn ml<S: Into<String>>(msg: S) -> Self {
        Self::MLError(msg.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_creation() {
        let err = Error::config("test config error");
        assert!(matches!(err, Error::Config(_)));

        let err = Error::analysis("test analysis error");
        assert!(matches!(err, Error::Analysis(_)));
    }

    #[test]
    fn test_error_display() {
        let err = Error::config("test error");
        assert_eq!(err.to_string(), "Configuration error: test error");
    }
}
