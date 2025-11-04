//! URL utility functions

use crate::types::{Error, Result};
use url::Url;

/// Normalize URL (remove trailing slash, fragments, etc.)
pub fn normalize_url(url_str: &str) -> Result<String> {
    let mut url = Url::parse(url_str)?;

    // Remove fragment
    url.set_fragment(None);

    // Remove trailing slash from path - CORRECTED: Store path in variable to avoid borrow conflict
    let path = url.path().trim_end_matches('/').to_string();
    url.set_path(&path);

    Ok(url.to_string())
}

/// Check if URL is HTTPS
pub fn is_https(url_str: &str) -> Result<bool> {
    let url = Url::parse(url_str)?;
    Ok(url.scheme() == "https")
}

/// Get domain from URL
pub fn get_domain(url_str: &str) -> Result<String> {
    let url = Url::parse(url_str)?;
    url.host_str()
        .ok_or_else(|| Error::generic("No host in URL"))
        .map(std::string::ToString::to_string)
}

/// Get top-level domain
pub fn get_tld(url_str: &str) -> Result<String> {
    let domain = get_domain(url_str)?;
    let parts: Vec<&str> = domain.split('.').collect();

    if parts.len() >= 2 {
        Ok(parts[parts.len() - 1].to_string())
    } else {
        Ok(domain)
    }
}

/// Check if two URLs are same origin
pub fn is_same_origin(url1: &str, url2: &str) -> Result<bool> {
    let u1 = Url::parse(url1)?;
    let u2 = Url::parse(url2)?;

    Ok(u1.scheme() == u2.scheme() && u1.host() == u2.host() && u1.port() == u2.port())
}

/// Join URL path
pub fn join_url(base: &str, relative: &str) -> Result<String> {
    let base_url = Url::parse(base)?;
    let joined = base_url.join(relative)?;
    Ok(joined.to_string())
}

/// Extract domain from URL (alias for `get_domain` for backward compatibility)
pub fn extract_domain(url_str: &str) -> Result<String> {
    get_domain(url_str)
}

/// Check if URL is valid
#[must_use]
pub fn is_valid_url(url_str: &str) -> bool {
    Url::parse(url_str).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_url() {
        let normalized = normalize_url("https://example.com/path/#fragment").unwrap();
        assert_eq!(normalized, "https://example.com/path");

        let normalized2 = normalize_url("https://example.com/path/").unwrap();
        assert_eq!(normalized2, "https://example.com/path");
    }

    #[test]
    fn test_is_https() {
        assert!(is_https("https://example.com").unwrap());
        assert!(!is_https("http://example.com").unwrap());
    }

    #[test]
    fn test_get_domain() {
        let domain = get_domain("https://example.com/path").unwrap();
        assert_eq!(domain, "example.com");
    }

    #[test]
    fn test_get_tld() {
        let tld = get_tld("https://example.com").unwrap();
        assert_eq!(tld, "com");

        let tld2 = get_tld("https://example.co.uk").unwrap();
        assert_eq!(tld2, "uk");
    }

    #[test]
    fn test_is_same_origin() {
        assert!(is_same_origin("https://example.com/page1", "https://example.com/page2").unwrap());

        assert!(!is_same_origin("https://example.com", "https://other.com").unwrap());

        assert!(!is_same_origin("http://example.com", "https://example.com").unwrap());
    }

    #[test]
    fn test_join_url() {
        let joined = join_url("https://example.com/path/", "subpath").unwrap();
        assert_eq!(joined, "https://example.com/path/subpath");

        let joined2 = join_url("https://example.com/path", "../other").unwrap();
        assert_eq!(joined2, "https://example.com/other");
    }
}
