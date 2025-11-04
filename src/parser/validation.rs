//! Cookie validation according to RFC 6265 and security best practices

use super::ParseError;
use crate::types::{Cookie, Result, SameSite};

/// Validate a cookie for RFC 6265 compliance and security
pub fn validate_cookie(cookie: &Cookie) -> Result<()> {
    // Validate name
    validate_name(&cookie.name)?;

    // Validate value
    validate_value(&cookie.value)?;

    // Validate domain if present
    if let Some(ref domain) = cookie.domain {
        validate_domain(domain)?;
    }

    // Validate path if present
    if let Some(ref path) = cookie.path {
        validate_path(path)?;
    }

    // Validate prefix rules
    validate_prefix(cookie)?;

    // Validate SameSite=None requires Secure
    validate_samesite_secure(cookie)?;

    // Validate Max-Age
    if let Some(max_age) = cookie.max_age {
        validate_max_age(max_age)?;
    }

    Ok(())
}

/// Validate cookie name
fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(ParseError::InvalidName("Cookie name cannot be empty".to_string()).into());
    }

    // Check for invalid characters
    for ch in name.chars() {
        if ch.is_control()
            || matches!(
                ch,
                '(' | ')'
                    | '<'
                    | '>'
                    | '@'
                    | ','
                    | ';'
                    | ':'
                    | '\\'
                    | '"'
                    | '/'
                    | '['
                    | ']'
                    | '?'
                    | '='
                    | '{'
                    | '}'
                    | ' '
                    | '\t'
            )
        {
            return Err(ParseError::InvalidName(format!(
                "Cookie name contains invalid character: '{ch}'"
            ))
            .into());
        }
    }

    Ok(())
}

/// Validate cookie value
fn validate_value(value: &str) -> Result<()> {
    // Value can be empty (RFC allows it)
    if value.is_empty() {
        return Ok(());
    }

    // Handle quoted values
    if value.starts_with('"') && value.ends_with('"') {
        if value.len() < 2 {
            return Err(ParseError::InvalidValue("Invalid quoted value".to_string()).into());
        }
        let inner = &value[1..value.len() - 1];
        return validate_cookie_octets(inner);
    }

    validate_cookie_octets(value)
}

/// Validate cookie-octets
fn validate_cookie_octets(value: &str) -> Result<()> {
    for ch in value.chars() {
        let byte = ch as u8;
        if !matches!(byte,
            0x21 | 0x23..=0x2B | 0x2D..=0x3A | 0x3C..=0x5B | 0x5D..=0x7E
        ) {
            return Err(ParseError::InvalidValue(format!(
                "Cookie value contains invalid character: '{ch}'"
            ))
            .into());
        }
    }
    Ok(())
}

/// Validate domain
fn validate_domain(domain: &str) -> Result<()> {
    if domain.is_empty() {
        return Err(ParseError::InvalidDomain("Domain cannot be empty".to_string()).into());
    }

    // Domain cannot contain whitespace
    if domain.contains(char::is_whitespace) {
        return Err(ParseError::InvalidDomain("Domain contains whitespace".to_string()).into());
    }

    // Basic domain format check
    if domain.starts_with('.') {
        return Err(ParseError::InvalidDomain(
            "Domain cannot start with '.' (it's added automatically)".to_string(),
        )
        .into());
    }

    // Check for invalid characters
    for ch in domain.chars() {
        if !ch.is_alphanumeric() && ch != '.' && ch != '-' {
            return Err(ParseError::InvalidDomain(format!(
                "Domain contains invalid character: '{ch}'"
            ))
            .into());
        }
    }

    // Domain parts cannot start or end with hyphen
    for part in domain.split('.') {
        if part.starts_with('-') || part.ends_with('-') {
            return Err(ParseError::InvalidDomain(
                "Domain parts cannot start or end with hyphen".to_string(),
            )
            .into());
        }
    }

    Ok(())
}

/// Validate path
fn validate_path(path: &str) -> Result<()> {
    if path.is_empty() {
        return Err(ParseError::InvalidPath("Path cannot be empty".to_string()).into());
    }

    // Path must start with /
    if !path.starts_with('/') {
        return Err(ParseError::InvalidPath("Path must start with '/'".to_string()).into());
    }

    Ok(())
}

/// Validate cookie prefix rules (RFC 6265bis)
fn validate_prefix(cookie: &Cookie) -> Result<()> {
    // __Secure- prefix
    if cookie.name.starts_with("__Secure-") && !cookie.secure {
        return Err(ParseError::InvalidAttribute(
            "__Secure- prefix requires Secure flag".to_string(),
        )
        .into());
    }

    // __Host- prefix
    if cookie.name.starts_with("__Host-") {
        if !cookie.secure {
            return Err(ParseError::InvalidAttribute(
                "__Host- prefix requires Secure flag".to_string(),
            )
            .into());
        }

        if cookie.domain.is_some() {
            return Err(ParseError::InvalidAttribute(
                "__Host- prefix forbids Domain attribute".to_string(),
            )
            .into());
        }

        if cookie.path != Some("/".to_string()) {
            return Err(
                ParseError::InvalidAttribute("__Host- prefix requires Path=/".to_string()).into(),
            );
        }
    }

    Ok(())
}

/// Validate SameSite=None requires Secure
fn validate_samesite_secure(cookie: &Cookie) -> Result<()> {
    if cookie.same_site == Some(SameSite::None) && !cookie.secure {
        return Err(
            ParseError::InvalidAttribute("SameSite=None requires Secure flag".to_string()).into(),
        );
    }
    Ok(())
}

/// Validate Max-Age
fn validate_max_age(max_age: i64) -> Result<()> {
    if max_age < 0 {
        return Err(
            ParseError::InvalidAttribute(format!("Max-Age cannot be negative: {max_age}")).into(),
        );
    }
    Ok(())
}

/// Check if cookie is compliant with security best practices
#[must_use]
pub fn check_security_compliance(cookie: &Cookie) -> Vec<String> {
    let mut issues = Vec::new();

    // Check Secure flag
    if !cookie.secure {
        issues.push("Missing Secure flag - cookie can be transmitted over HTTP".to_string());
    }

    // Check HttpOnly for sensitive cookies
    if cookie.is_likely_auth_cookie() && !cookie.http_only {
        issues
            .push("Missing HttpOnly flag on authentication cookie - vulnerable to XSS".to_string());
    }

    // Check SameSite
    if cookie.same_site.is_none() {
        issues.push("Missing SameSite attribute - vulnerable to CSRF attacks".to_string());
    }

    // Check excessive lifetime
    if let Some(lifetime) = cookie.lifetime_seconds() {
        if lifetime > 31_536_000 {
            // > 1 year
            issues.push(format!(
                "Cookie lifetime too long: {} days (recommend max 13 months)",
                lifetime / 86400
            ));
        }
    }

    // Check for public suffix domain
    if let Some(ref domain) = cookie.domain {
        if is_public_suffix(domain) {
            issues.push(format!(
                "Domain '{domain}' appears to be a public suffix - security risk"
            ));
        }
    }

    issues
}

/// Check if domain is a public suffix (simplified check)
fn is_public_suffix(domain: &str) -> bool {
    // Common public suffixes
    let suffixes = [
        "com",
        "org",
        "net",
        "edu",
        "gov",
        "mil",
        "co.uk",
        "github.io",
        "herokuapp.com",
        "blogspot.com",
        "wordpress.com",
    ];

    suffixes.contains(&domain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_name() {
        assert!(validate_name("session_id").is_ok());
        assert!(validate_name("user-token").is_ok());
        assert!(validate_name("").is_err());
        assert!(validate_name("invalid;name").is_err());
        assert!(validate_name("invalid name").is_err());
    }

    #[test]
    fn test_validate_domain() {
        assert!(validate_domain("example.com").is_ok());
        assert!(validate_domain("sub.example.com").is_ok());
        assert!(validate_domain("").is_err());
        assert!(validate_domain(".example.com").is_err());
        assert!(validate_domain("invalid domain").is_err());
    }

    #[test]
    fn test_validate_path() {
        assert!(validate_path("/").is_ok());
        assert!(validate_path("/api").is_ok());
        assert!(validate_path("/api/v1").is_ok());
        assert!(validate_path("").is_err());
        assert!(validate_path("invalid").is_err());
    }

    #[test]
    fn test_validate_secure_prefix() {
        let mut cookie = Cookie::new("__Secure-token".to_string(), "value".to_string());
        assert!(validate_prefix(&cookie).is_err());

        cookie.secure = true;
        assert!(validate_prefix(&cookie).is_ok());
    }

    #[test]
    fn test_validate_host_prefix() {
        let mut cookie = Cookie::new("__Host-token".to_string(), "value".to_string());
        cookie.secure = true;
        cookie.path = Some("/".to_string());

        assert!(validate_prefix(&cookie).is_ok());

        cookie.domain = Some("example.com".to_string());
        assert!(validate_prefix(&cookie).is_err());
    }

    #[test]
    fn test_validate_samesite_none() {
        let mut cookie = Cookie::new("id".to_string(), "value".to_string());
        cookie.same_site = Some(SameSite::None);

        assert!(validate_samesite_secure(&cookie).is_err());

        cookie.secure = true;
        assert!(validate_samesite_secure(&cookie).is_ok());
    }

    #[test]
    fn test_check_security_compliance() {
        let cookie = Cookie::new("session_id".to_string(), "value".to_string());
        let issues = check_security_compliance(&cookie);

        assert!(!issues.is_empty());
        assert!(issues.iter().any(|i| i.contains("Secure")));
        assert!(issues.iter().any(|i| i.contains("HttpOnly")));
        assert!(issues.iter().any(|i| i.contains("SameSite")));
    }

    #[test]
    fn test_is_public_suffix() {
        assert!(is_public_suffix("com"));
        assert!(is_public_suffix("github.io"));
        assert!(!is_public_suffix("example.com"));
    }
}
