//! RFC 6265 cookie parsing implementation
//!
//! Complete implementation of RFC 6265 HTTP State Management Mechanism

use super::ParseError;
use crate::types::{Cookie, Result, SameSite};
use chrono::{DateTime, Utc};

/// Parse a Set-Cookie header (server → client)
///
/// According to RFC 6265 Section 4.1.1, the syntax is:
/// ```text
/// set-cookie-header = "Set-Cookie:" SP set-cookie-string
/// set-cookie-string = cookie-pair *( ";" SP cookie-av )
/// cookie-pair       = cookie-name "=" cookie-value
/// ```
pub fn parse_set_cookie(header: &str, strict: bool) -> Result<Cookie> {
    if header.trim().is_empty() {
        return Err(ParseError::EmptyInput.into());
    }

    // Split into cookie-pair and attributes
    let parts: Vec<&str> = header.split(';').map(str::trim).collect();

    if parts.is_empty() {
        return Err(ParseError::EmptyInput.into());
    }

    // Parse cookie-pair (name=value)
    let (name, value) = parse_cookie_pair(parts[0], strict)?;

    // Create base cookie
    let mut cookie = Cookie::new(name, value);

    // Parse attributes
    for attr in &parts[1..] {
        parse_attribute(&mut cookie, attr, strict)?;
    }

    // Set cookie size
    cookie.size = header.len();

    // Validate if strict mode
    if strict {
        super::validation::validate_cookie(&cookie)?;
    }

    Ok(cookie)
}

/// Parse cookie-pair (name=value)
fn parse_cookie_pair(pair: &str, strict: bool) -> Result<(String, String)> {
    let (name, value) = pair.split_once('=').ok_or(ParseError::MissingEquals)?;

    let name = name.trim();
    let value = value.trim();

    // Validate name (RFC 6265 Section 4.1.1)
    if name.is_empty() {
        return Err(ParseError::InvalidName("Cookie name cannot be empty".to_string()).into());
    }

    // In strict mode, validate cookie-name characters
    if strict && !is_valid_cookie_name(name) {
        return Err(ParseError::InvalidName(format!(
            "Cookie name contains invalid characters: {name}"
        ))
        .into());
    }

    // Value can be empty (RFC allows it)
    // In strict mode, validate cookie-value characters
    if strict && !value.is_empty() && !is_valid_cookie_value(value) {
        return Err(ParseError::InvalidValue(format!(
            "Cookie value contains invalid characters: {value}"
        ))
        .into());
    }

    Ok((name.to_string(), value.to_string()))
}

/// Check if cookie name is valid (RFC 6265 Section 4.1.1)
///
/// cookie-name = token
/// token = 1*<any CHAR except CTLs or separators>
fn is_valid_cookie_name(name: &str) -> bool {
    !name.is_empty()
        && name.chars().all(|c| {
            !c.is_control()
                && !matches!(
                    c,
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
        })
}

/// Check if cookie value is valid (RFC 6265 Section 4.1.1)
///
/// cookie-value = *cookie-octet / ( DQUOTE *cookie-octet DQUOTE )
/// cookie-octet = %x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E
fn is_valid_cookie_value(value: &str) -> bool {
    // Handle quoted values (must have at least 2 chars: opening and closing quotes)
    if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
        let inner = &value[1..value.len() - 1];
        return is_valid_cookie_octet_string(inner);
    }

    is_valid_cookie_octet_string(value)
}

/// Check if string contains only valid cookie-octets
fn is_valid_cookie_octet_string(s: &str) -> bool {
    s.chars().all(|c| {
        matches!(c as u8,
            0x21 | 0x23..=0x2B | 0x2D..=0x3A | 0x3C..=0x5B | 0x5D..=0x7E
        )
    })
}

/// Parse a cookie attribute
fn parse_attribute(cookie: &mut Cookie, attr: &str, _strict: bool) -> Result<()> {
    if attr.is_empty() {
        return Ok(());
    }

    // Split attribute name and value
    if let Some((name, value)) = attr.split_once('=') {
        let name = name.trim().to_lowercase();
        let value = value.trim();

        match name.as_str() {
            "domain" => parse_domain(cookie, value)?,
            "path" => parse_path(cookie, value)?,
            "expires" => parse_expires(cookie, value)?,
            "max-age" => parse_max_age(cookie, value)?,
            "samesite" => parse_samesite(cookie, value)?,
            _ => {
                // Unknown attribute - store in extensions
                cookie.extensions.insert(name, value.to_string());
            }
        }
    } else {
        // Boolean attribute (no value)
        let name = attr.trim().to_lowercase();
        match name.as_str() {
            "secure" => cookie.secure = true,
            "httponly" => cookie.http_only = true,
            _ => {
                cookie.extensions.insert(name, String::new());
            }
        }
    }

    Ok(())
}

/// Parse Domain attribute
fn parse_domain(cookie: &mut Cookie, value: &str) -> Result<()> {
    let domain = value.trim().trim_start_matches('.');

    if domain.is_empty() {
        return Err(ParseError::InvalidDomain("Domain cannot be empty".to_string()).into());
    }

    // Basic validation
    if domain.contains(char::is_whitespace) {
        return Err(ParseError::InvalidDomain("Domain contains whitespace".to_string()).into());
    }

    cookie.domain = Some(domain.to_string());
    Ok(())
}

/// Parse Path attribute
fn parse_path(cookie: &mut Cookie, value: &str) -> Result<()> {
    let path = value.trim();

    if path.is_empty() {
        return Err(ParseError::InvalidPath("Path cannot be empty".to_string()).into());
    }

    // Path must start with /
    if !path.starts_with('/') {
        return Err(ParseError::InvalidPath("Path must start with /".to_string()).into());
    }

    cookie.path = Some(path.to_string());
    Ok(())
}

/// Parse Expires attribute (RFC 6265 Section 5.1.1)
fn parse_expires(cookie: &mut Cookie, value: &str) -> Result<()> {
    // Try multiple date formats (RFC 822, RFC 850, asctime)
    let formats = [
        "%a, %d %b %Y %H:%M:%S GMT", // RFC 822
        "%A, %d-%b-%y %H:%M:%S GMT", // RFC 850
        "%a %b %e %H:%M:%S %Y",      // asctime
        "%a, %d-%b-%Y %H:%M:%S GMT", // Common variant
    ];

    for format in &formats {
        if let Ok(dt) = DateTime::parse_from_str(value.trim(), format) {
            cookie.expires = Some(dt.with_timezone(&Utc));
            return Ok(());
        }
    }

    Err(ParseError::InvalidDate(format!("Cannot parse date: {value}")).into())
}

/// Parse Max-Age attribute
fn parse_max_age(cookie: &mut Cookie, value: &str) -> Result<()> {
    let max_age: i64 = value
        .trim()
        .parse()
        .map_err(|_| ParseError::InvalidAttribute(format!("Invalid Max-Age: {value}")))?;

    cookie.max_age = Some(max_age);
    Ok(())
}

/// Parse `SameSite` attribute
fn parse_samesite(cookie: &mut Cookie, value: &str) -> Result<()> {
    let value_lower = value.trim().to_lowercase();

    cookie.same_site = match value_lower.as_str() {
        "strict" => Some(SameSite::Strict),
        "lax" => Some(SameSite::Lax),
        "none" => Some(SameSite::None),
        _ => return Err(ParseError::InvalidSameSite(value.to_string()).into()),
    };

    Ok(())
}

/// Parse Cookie header (client → server)
///
/// According to RFC 6265 Section 4.2.1:
/// ```text
/// cookie-header = "Cookie:" OWS cookie-string OWS
/// cookie-string = cookie-pair *( ";" SP cookie-pair )
/// ```
pub fn parse_cookie_header(header: &str) -> Result<Vec<(String, String)>> {
    if header.trim().is_empty() {
        return Ok(Vec::new());
    }

    let mut cookies = Vec::new();

    for pair in header.split(';') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }

        let (name, value) = parse_cookie_pair(pair, false)?;
        cookies.push((name, value));
    }

    Ok(cookies)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_cookie() {
        let result = parse_set_cookie("session_id=abc123", false);
        assert!(result.is_ok());

        let cookie = result.unwrap();
        assert_eq!(cookie.name, "session_id");
        assert_eq!(cookie.value, "abc123");
    }

    #[test]
    fn test_parse_with_domain() {
        let result = parse_set_cookie("id=value; Domain=example.com", false);
        assert!(result.is_ok());

        let cookie = result.unwrap();
        assert_eq!(cookie.domain, Some("example.com".to_string()));
    }

    #[test]
    fn test_parse_with_path() {
        let result = parse_set_cookie("id=value; Path=/api", false);
        assert!(result.is_ok());

        let cookie = result.unwrap();
        assert_eq!(cookie.path, Some("/api".to_string()));
    }

    #[test]
    fn test_parse_secure_flag() {
        let result = parse_set_cookie("id=value; Secure", false);
        assert!(result.is_ok());

        let cookie = result.unwrap();
        assert!(cookie.secure);
    }

    #[test]
    fn test_parse_httponly_flag() {
        let result = parse_set_cookie("id=value; HttpOnly", false);
        assert!(result.is_ok());

        let cookie = result.unwrap();
        assert!(cookie.http_only);
    }

    #[test]
    fn test_parse_samesite_strict() {
        let result = parse_set_cookie("id=value; SameSite=Strict", false);
        assert!(result.is_ok());

        let cookie = result.unwrap();
        assert_eq!(cookie.same_site, Some(SameSite::Strict));
    }

    #[test]
    fn test_parse_samesite_lax() {
        let result = parse_set_cookie("id=value; SameSite=Lax", false);
        assert!(result.is_ok());

        let cookie = result.unwrap();
        assert_eq!(cookie.same_site, Some(SameSite::Lax));
    }

    #[test]
    fn test_parse_samesite_none() {
        let result = parse_set_cookie("id=value; SameSite=None; Secure", false);
        assert!(result.is_ok());

        let cookie = result.unwrap();
        assert_eq!(cookie.same_site, Some(SameSite::None));
        assert!(cookie.secure);
    }

    #[test]
    fn test_parse_max_age() {
        let result = parse_set_cookie("id=value; Max-Age=3600", false);
        assert!(result.is_ok());

        let cookie = result.unwrap();
        assert_eq!(cookie.max_age, Some(3600));
    }

    #[test]
    fn test_parse_complete_cookie() {
        let result = parse_set_cookie(
            "session=xyz; Domain=example.com; Path=/; Max-Age=3600; Secure; HttpOnly; SameSite=Strict",
            false,
        );

        assert!(result.is_ok());

        let cookie = result.unwrap();
        assert_eq!(cookie.name, "session");
        assert_eq!(cookie.value, "xyz");
        assert_eq!(cookie.domain, Some("example.com".to_string()));
        assert_eq!(cookie.path, Some("/".to_string()));
        assert_eq!(cookie.max_age, Some(3600));
        assert!(cookie.secure);
        assert!(cookie.http_only);
        assert_eq!(cookie.same_site, Some(SameSite::Strict));
    }

    #[test]
    fn test_parse_cookie_header() {
        let result = parse_cookie_header("session=abc; user=john");
        assert!(result.is_ok());

        let cookies = result.unwrap();
        assert_eq!(cookies.len(), 2);
        assert_eq!(cookies[0], ("session".to_string(), "abc".to_string()));
        assert_eq!(cookies[1], ("user".to_string(), "john".to_string()));
    }

    #[test]
    fn test_empty_input() {
        let result = parse_set_cookie("", false);
        assert!(result.is_err());
    }

    #[test]
    fn test_missing_equals() {
        let result = parse_set_cookie("invalid_cookie", false);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_path() {
        let result = parse_set_cookie("id=value; Path=invalid", false);
        assert!(result.is_err());
    }

    #[test]
    fn test_quoted_value() {
        let result = parse_set_cookie(r#"id="quoted value""#, false);
        assert!(result.is_ok());

        let cookie = result.unwrap();
        assert_eq!(cookie.value, r#""quoted value""#);
    }

    #[test]
    fn test_is_valid_cookie_name() {
        assert!(is_valid_cookie_name("session_id"));
        assert!(is_valid_cookie_name("user-token"));
        assert!(!is_valid_cookie_name("invalid;name"));
        assert!(!is_valid_cookie_name("invalid name"));
        assert!(!is_valid_cookie_name(""));
    }
}
