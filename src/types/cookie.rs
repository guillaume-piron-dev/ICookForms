//! Cookie type and related structures

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents a cookie with all its attributes and metadata
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Cookie {
    /// Cookie name
    pub name: String,

    /// Cookie value
    pub value: String,

    /// Domain attribute
    pub domain: Option<String>,

    /// Path attribute
    pub path: Option<String>,

    /// Expires attribute
    pub expires: Option<DateTime<Utc>>,

    /// Max-Age attribute (in seconds)
    pub max_age: Option<i64>,

    /// Secure flag
    pub secure: bool,

    /// `HttpOnly` flag
    pub http_only: bool,

    /// `SameSite` attribute
    pub same_site: Option<SameSite>,

    /// Cookie size in bytes
    pub size: usize,

    /// When the cookie was first seen/created
    pub created_at: DateTime<Utc>,

    /// Additional attributes not in RFC 6265
    pub extensions: HashMap<String, String>,

    /// Whether this is a first-party or third-party cookie
    pub is_third_party: bool,

    /// The URL where this cookie was found
    pub source_url: Option<String>,

    /// Cookie category for compliance
    pub category: Option<CookieCategory>,
}

/// `SameSite` attribute values
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SameSite {
    /// Strict - Cookie is only sent in first-party context
    Strict,

    /// Lax - Cookie is sent with top-level navigations
    Lax,

    /// None - Cookie is sent in all contexts (requires Secure)
    None,
}

/// Cookie category for GDPR/CCPA compliance
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum CookieCategory {
    /// Strictly necessary for site functionality
    StrictlyNecessary,

    /// Functional cookies for enhanced features
    Functional,

    /// Performance/Analytics cookies
    Performance,

    /// Targeting/Advertising cookies
    Targeting,

    /// Social media cookies
    SocialMedia,

    /// Unknown/Unclassified
    Unknown,
}

/// Cookie attribute representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookieAttribute {
    /// Attribute name
    pub name: String,

    /// Attribute value (if any)
    pub value: Option<String>,
}

impl Cookie {
    /// Create a new cookie with minimal information
    #[must_use]
    pub fn new(name: String, value: String) -> Self {
        Self {
            name,
            value,
            domain: None,
            path: None,
            expires: None,
            max_age: None,
            secure: false,
            http_only: false,
            same_site: None,
            size: 0,
            created_at: Utc::now(),
            extensions: HashMap::new(),
            is_third_party: false,
            source_url: None,
            category: None,
        }
    }

    /// Check if cookie is expired
    #[must_use]
    pub fn is_expired(&self) -> bool {
        if let Some(expires) = self.expires {
            return Utc::now() > expires;
        }
        false
    }

    /// Check if cookie is a session cookie (no Expires or Max-Age)
    #[must_use]
    pub fn is_session(&self) -> bool {
        self.expires.is_none() && self.max_age.is_none()
    }

    /// Check if cookie is a persistent cookie
    #[must_use]
    pub fn is_persistent(&self) -> bool {
        !self.is_session()
    }

    /// Calculate the lifetime of the cookie in seconds
    #[must_use]
    pub fn lifetime_seconds(&self) -> Option<i64> {
        if let Some(max_age) = self.max_age {
            return Some(max_age);
        }

        if let Some(expires) = self.expires {
            let duration = expires.signed_duration_since(self.created_at);
            return Some(duration.num_seconds());
        }

        None
    }

    /// Check if cookie has security flags set appropriately
    #[must_use]
    pub fn has_secure_flags(&self) -> bool {
        self.secure && self.http_only
    }

    /// Check if cookie looks like a session/authentication cookie
    #[must_use]
    pub fn is_likely_auth_cookie(&self) -> bool {
        let name_lower = self.name.to_lowercase();
        let auth_patterns = [
            "session",
            "sess",
            "auth",
            "token",
            "jwt",
            "login",
            "user",
            "id",
            "credentials",
        ];

        auth_patterns
            .iter()
            .any(|pattern| name_lower.contains(pattern))
    }

    /// Check if cookie is set for localhost or local development
    ///
    /// Returns true if the cookie's domain is localhost, 127.0.0.1, or a .local domain
    #[must_use]
    pub fn is_localhost(&self) -> bool {
        if let Some(ref domain) = self.domain {
            let domain_lower = domain.to_lowercase();
            return domain_lower == "localhost"
                || domain_lower == "127.0.0.1"
                || domain_lower == "::1"
                || std::path::Path::new(&domain_lower)
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("local"))
                || domain_lower.ends_with(".localhost");
        }

        // Check source URL if domain not set
        if let Some(ref url) = self.source_url {
            let url_lower = url.to_lowercase();
            return url_lower.contains("localhost")
                || url_lower.contains("127.0.0.1")
                || url_lower.contains("::1");
        }

        false
    }

    /// Get the effective domain for this cookie
    #[must_use]
    pub fn effective_domain(&self) -> Option<&str> {
        self.domain.as_deref()
    }

    /// Get the effective path for this cookie
    #[must_use]
    pub fn effective_path(&self) -> &str {
        self.path.as_deref().unwrap_or("/")
    }

    /// Check if cookie uses __Secure- prefix
    #[must_use]
    pub fn has_secure_prefix(&self) -> bool {
        self.name.starts_with("__Secure-")
    }

    /// Check if cookie uses __Host- prefix
    #[must_use]
    pub fn has_host_prefix(&self) -> bool {
        self.name.starts_with("__Host-")
    }

    /// Validate cookie against RFC 6265 prefix rules
    pub fn validate_prefix(&self) -> Result<(), String> {
        if self.has_secure_prefix() && !self.secure {
            return Err("__Secure- prefix requires Secure flag".to_string());
        }

        if self.has_host_prefix() {
            if !self.secure {
                return Err("__Host- prefix requires Secure flag".to_string());
            }
            if self.path != Some("/".to_string()) {
                return Err("__Host- prefix requires Path=/".to_string());
            }
            if self.domain.is_some() {
                return Err("__Host- prefix forbids Domain attribute".to_string());
            }
        }

        Ok(())
    }
}

impl std::fmt::Display for Cookie {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}={}", self.name, self.value)?;

        if let Some(domain) = &self.domain {
            write!(f, "; Domain={domain}")?;
        }

        if let Some(path) = &self.path {
            write!(f, "; Path={path}")?;
        }

        if self.secure {
            write!(f, "; Secure")?;
        }

        if self.http_only {
            write!(f, "; HttpOnly")?;
        }

        if let Some(same_site) = self.same_site {
            write!(f, "; SameSite={same_site:?}")?;
        }

        Ok(())
    }
}

impl Default for Cookie {
    fn default() -> Self {
        Self::new(String::new(), String::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cookie_creation() {
        let cookie = Cookie::new("test".to_string(), "value".to_string());
        assert_eq!(cookie.name, "test");
        assert_eq!(cookie.value, "value");
        assert!(!cookie.secure);
        assert!(!cookie.http_only);
    }

    #[test]
    fn test_is_session_cookie() {
        let cookie = Cookie::new("session".to_string(), "abc123".to_string());
        assert!(cookie.is_session());
        assert!(!cookie.is_persistent());
    }

    #[test]
    fn test_is_likely_auth_cookie() {
        let cookie = Cookie::new("session_id".to_string(), "abc123".to_string());
        assert!(cookie.is_likely_auth_cookie());

        let cookie2 = Cookie::new("preferences".to_string(), "dark_mode".to_string());
        assert!(!cookie2.is_likely_auth_cookie());
    }

    #[test]
    fn test_is_localhost() {
        let mut cookie = Cookie::new("test".to_string(), "value".to_string());

        // Test localhost domain
        cookie.domain = Some("localhost".to_string());
        assert!(cookie.is_localhost());

        // Test 127.0.0.1
        cookie.domain = Some("127.0.0.1".to_string());
        assert!(cookie.is_localhost());

        // Test .local domain
        cookie.domain = Some("myapp.local".to_string());
        assert!(cookie.is_localhost());

        // Test production domain
        cookie.domain = Some("example.com".to_string());
        assert!(!cookie.is_localhost());

        // Test source URL
        cookie.domain = None;
        cookie.source_url = Some("http://localhost:8080".to_string());
        assert!(cookie.is_localhost());
    }

    #[test]
    fn test_secure_prefix_validation() {
        let mut cookie = Cookie::new("__Secure-token".to_string(), "value".to_string());
        assert!(cookie.validate_prefix().is_err());

        cookie.secure = true;
        assert!(cookie.validate_prefix().is_ok());
    }

    #[test]
    fn test_host_prefix_validation() {
        let mut cookie = Cookie::new("__Host-token".to_string(), "value".to_string());
        cookie.secure = true;
        cookie.path = Some("/".to_string());
        assert!(cookie.validate_prefix().is_ok());

        cookie.domain = Some("example.com".to_string());
        assert!(cookie.validate_prefix().is_err());
    }
}
