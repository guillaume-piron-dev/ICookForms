//! RFC 6265 compliant cookie parser
//!
//! This module implements a complete parser for HTTP cookies according to RFC 6265.
//! It handles all cookie attributes and provides comprehensive validation.

pub mod attributes;
pub mod rfc6265;
pub mod validation;

use crate::types::{Cookie, Error, Result};

// Re-exports
pub use rfc6265::parse_set_cookie;
pub use validation::validate_cookie;

/// Main cookie parser
pub struct CookieParser {
    /// Strict RFC compliance mode
    strict: bool,
}

impl CookieParser {
    /// Create a new parser with default settings
    #[must_use]
    pub fn new() -> Self {
        Self { strict: false }
    }

    /// Create a new parser in strict mode
    #[must_use]
    pub fn strict() -> Self {
        Self { strict: true }
    }

    /// Parse a Set-Cookie header value
    pub fn parse_set_cookie(&self, header: &str) -> Result<Cookie> {
        rfc6265::parse_set_cookie(header, self.strict)
    }

    /// Parse a Cookie header value (client → server)
    pub fn parse_cookie(&self, header: &str) -> Result<Vec<(String, String)>> {
        rfc6265::parse_cookie_header(header)
    }

    /// Parse multiple Set-Cookie headers
    #[must_use]
    pub fn parse_multiple(&self, headers: &[String]) -> Vec<Result<Cookie>> {
        headers.iter().map(|h| self.parse_set_cookie(h)).collect()
    }
}

impl Default for CookieParser {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse error types
#[derive(Debug, Clone, thiserror::Error)]
pub enum ParseError {
    /// Empty input
    #[error("Empty cookie string")]
    EmptyInput,

    /// Missing equals sign in name=value
    #[error("Missing '=' in cookie")]
    MissingEquals,

    /// Invalid cookie name
    #[error("Invalid cookie name: {0}")]
    InvalidName(String),

    /// Invalid cookie value
    #[error("Invalid cookie value: {0}")]
    InvalidValue(String),

    /// Invalid attribute
    #[error("Invalid attribute: {0}")]
    InvalidAttribute(String),

    /// Invalid date format
    #[error("Invalid date format: {0}")]
    InvalidDate(String),

    /// Invalid domain
    #[error("Invalid domain: {0}")]
    InvalidDomain(String),

    /// Invalid path
    #[error("Invalid path: {0}")]
    InvalidPath(String),

    /// Invalid `SameSite` value
    #[error("Invalid SameSite value: {0}")]
    InvalidSameSite(String),

    /// Generic parse error
    #[error("Parse error: {0}")]
    Generic(String),
}

impl From<ParseError> for Error {
    fn from(err: ParseError) -> Self {
        Error::CookieParse(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parser_creation() {
        let parser = CookieParser::new();
        assert!(!parser.strict);

        let strict_parser = CookieParser::strict();
        assert!(strict_parser.strict);
    }

    #[test]
    fn test_parse_simple_cookie() {
        let parser = CookieParser::new();
        let result = parser.parse_set_cookie("session_id=abc123");

        assert!(result.is_ok());
        let cookie = result.unwrap();
        assert_eq!(cookie.name, "session_id");
        assert_eq!(cookie.value, "abc123");
    }

    #[test]
    fn test_parse_empty_string() {
        let parser = CookieParser::new();
        let result = parser.parse_set_cookie("");

        assert!(result.is_err());
    }

    #[test]
    fn test_parse_cookie_with_attributes() {
        let parser = CookieParser::new();
        let result = parser.parse_set_cookie("token=xyz; Path=/; Secure; HttpOnly");

        assert!(result.is_ok());
        let cookie = result.unwrap();
        assert_eq!(cookie.name, "token");
        assert_eq!(cookie.value, "xyz");
        assert_eq!(cookie.path, Some("/".to_string()));
        assert!(cookie.secure);
        assert!(cookie.http_only);
    }

    #[test]
    fn test_parse_multiple_cookies() {
        let parser = CookieParser::new();
        let headers = vec!["cookie1=value1".to_string(), "cookie2=value2".to_string()];

        let results = parser.parse_multiple(&headers);
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(std::result::Result::is_ok));
    }
}
