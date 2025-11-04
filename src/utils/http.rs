//! HTTP utility functions

/// Normalize HTTP header value
#[must_use]
pub fn normalize_header_value(value: &str) -> String {
    value.trim().to_lowercase()
}

/// Check if HTTP status code is successful (2xx)
#[must_use]
pub fn is_success_status(code: u16) -> bool {
    (200..=299).contains(&code)
}

/// Check if HTTP status code is redirect (3xx)
#[must_use]
pub fn is_redirect_status(code: u16) -> bool {
    (300..=399).contains(&code)
}

/// Check if HTTP status code is client error (4xx)
#[must_use]
pub fn is_client_error(code: u16) -> bool {
    (400..=499).contains(&code)
}

/// Check if HTTP status code is server error (5xx)
#[must_use]
pub fn is_server_error(code: u16) -> bool {
    (500..=599).contains(&code)
}

/// Parse User-Agent string
#[must_use]
pub fn parse_user_agent(ua: &str) -> (Option<String>, Option<String>) {
    // Simple parser - can be enhanced
    let parts: Vec<&str> = ua.split('/').collect();
    if parts.len() >= 2 {
        (Some(parts[0].to_string()), Some(parts[1].to_string()))
    } else {
        (Some(ua.to_string()), None)
    }
}

/// Build HTTP request headers
#[must_use]
pub fn build_request(user_agent: Option<&str>) -> Vec<(String, String)> {
    let mut headers = vec![
        ("Accept".to_string(), "*/*".to_string()),
        ("Accept-Language".to_string(), "en-US,en;q=0.9".to_string()),
    ];

    if let Some(ua) = user_agent {
        headers.push(("User-Agent".to_string(), ua.to_string()));
    } else {
        headers.push(("User-Agent".to_string(), "ICookForms/1.0".to_string()));
    }

    headers
}

/// Extract cookies from HTTP headers
#[must_use]
pub fn extract_cookies_from_headers(headers: &[(String, String)]) -> Vec<String> {
    headers
        .iter()
        .filter(|(name, _)| name.to_lowercase() == "set-cookie")
        .map(|(_, value)| value.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_header() {
        assert_eq!(normalize_header_value("  Content-Type  "), "content-type");
    }

    #[test]
    fn test_status_checks() {
        assert!(is_success_status(200));
        assert!(is_redirect_status(301));
        assert!(is_client_error(404));
        assert!(is_server_error(500));
    }
}
