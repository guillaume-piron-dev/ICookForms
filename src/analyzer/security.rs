//! Security analysis for cookies

use std::collections::HashMap;

use crate::types::issue::{AttackVector, VulnerabilityType};
use crate::types::{Cookie, SameSite, SecurityIssue, Severity};

/// Analyze cookies for security vulnerabilities
#[must_use]
pub fn analyze_security(cookies: &[Cookie]) -> Vec<SecurityIssue> {
    let mut issues = Vec::new();

    for cookie in cookies {
        check_secure_flag(cookie, &mut issues);
        check_http_only_flag(cookie, &mut issues);
        check_same_site(cookie, &mut issues);
        check_session_fixation(cookie, &mut issues);
        check_predictable_value(cookie, &mut issues);
        check_sensitive_data(cookie, &mut issues);
    }

    issues
}

/// Check for missing Secure flag
fn check_secure_flag(cookie: &Cookie, issues: &mut Vec<SecurityIssue>) {
    if !cookie.secure && !cookie.is_localhost() {
        let mut issue = SecurityIssue::new(
            Severity::High,
            "Missing Secure Flag",
            format!(
                "Cookie '{}' transmitted without Secure flag, vulnerable to interception",
                cookie.name
            ),
            VulnerabilityType::InsecureTransmission,
        );
        issue.issue = issue
            .issue
            .add_cookie(&cookie.name)
            .add_recommendation("Add Secure flag to ensure HTTPS-only transmission")
            .with_cwe("CWE-614");
        issue.attack_vector = Some(AttackVector::Network);
        issue.exploitability = 7.0;
        issue.impact = 8.0;
        issue.calculate_cvss();
        issues.push(issue);
    }
}

/// Check for missing `HttpOnly` flag
fn check_http_only_flag(cookie: &Cookie, issues: &mut Vec<SecurityIssue>) {
    if !cookie.http_only && is_session_cookie(cookie) {
        let mut issue = SecurityIssue::new(
            Severity::High,
            "Missing HttpOnly Flag",
            format!(
                "Session cookie '{}' accessible via JavaScript, vulnerable to XSS",
                cookie.name
            ),
            VulnerabilityType::XSS,
        );
        issue.issue = issue
            .issue
            .add_cookie(&cookie.name)
            .add_recommendation("Add HttpOnly flag to prevent JavaScript access")
            .with_cwe("CWE-1004");
        issue.attack_vector = Some(AttackVector::Network);
        issue.exploitability = 8.0;
        issue.impact = 9.0;
        issue.calculate_cvss();
        issues.push(issue);
    }
}

/// Check for missing or weak `SameSite` attribute
fn check_same_site(cookie: &Cookie, issues: &mut Vec<SecurityIssue>) {
    if cookie.same_site.is_none() || cookie.same_site == Some(SameSite::None) {
        let mut issue = SecurityIssue::new(
            Severity::Medium,
            "Missing or Weak SameSite Attribute",
            format!(
                "Cookie '{}' lacks SameSite protection, vulnerable to CSRF",
                cookie.name
            ),
            VulnerabilityType::CSRF,
        );
        issue.issue = issue
            .issue
            .add_cookie(&cookie.name)
            .add_recommendation("Set SameSite=Strict or SameSite=Lax")
            .with_cwe("CWE-352");
        issue.attack_vector = Some(AttackVector::Network);
        issue.exploitability = 6.0;
        issue.impact = 7.0;
        issue.calculate_cvss();
        issues.push(issue);
    }
}

/// Check for session fixation vulnerability
fn check_session_fixation(cookie: &Cookie, issues: &mut Vec<SecurityIssue>) {
    if is_session_cookie(cookie) && !cookie.secure {
        let mut issue = SecurityIssue::new(
            Severity::High,
            "Session Fixation Risk",
            format!(
                "Session cookie '{}' may be vulnerable to session fixation",
                cookie.name
            ),
            VulnerabilityType::SessionFixation,
        );
        issue.issue = issue
            .issue
            .add_cookie(&cookie.name)
            .add_recommendation("Regenerate session ID after authentication")
            .with_cwe("CWE-384");
        issue.attack_vector = Some(AttackVector::Network);
        issue.exploitability = 5.0;
        issue.impact = 8.0;
        issue.calculate_cvss();
        issues.push(issue);
    }
}

/// Check for weak cookie values (potential for tampering)
fn check_predictable_value(cookie: &Cookie, issues: &mut Vec<SecurityIssue>) {
    if is_predictable_value(&cookie.value) {
        let mut issue = SecurityIssue::new(
            Severity::Medium,
            "Predictable Cookie Value",
            format!(
                "Cookie '{}' has a predictable value pattern, vulnerable to tampering",
                cookie.name
            ),
            VulnerabilityType::CookieTampering,
        );
        issue.issue = issue
            .issue
            .add_cookie(&cookie.name)
            .add_recommendation("Use cryptographically random values and HMAC signatures")
            .with_cwe("CWE-330");
        issue.exploitability = 6.0;
        issue.impact = 6.0;
        issue.calculate_cvss();
        issues.push(issue);
    }
}

/// Check for sensitive data in cookie name/value
fn check_sensitive_data(cookie: &Cookie, issues: &mut Vec<SecurityIssue>) {
    if contains_sensitive_data(cookie) {
        let mut issue = SecurityIssue::new(
            Severity::High,
            "Sensitive Data Exposure",
            format!(
                "Cookie '{}' may contain sensitive data in plain text",
                cookie.name
            ),
            VulnerabilityType::WeakCryptography,
        );
        issue.issue = issue
            .issue
            .add_cookie(&cookie.name)
            .add_recommendation("Encrypt sensitive cookie values or use session IDs")
            .with_cwe("CWE-311");
        issue.exploitability = 7.0;
        issue.impact = 9.0;
        issue.calculate_cvss();
        issues.push(issue);
    }
}

/// Check if a cookie is likely a session cookie
fn is_session_cookie(cookie: &Cookie) -> bool {
    let session_patterns = [
        "session",
        "sess",
        "sid",
        "jsessionid",
        "phpsessid",
        "asp.net_sessionid",
        "cfid",
        "cftoken",
    ];

    let name_lower = cookie.name.to_lowercase();
    session_patterns
        .iter()
        .any(|pattern| name_lower.contains(pattern))
}

/// Check if a cookie value appears to be predictable
fn is_predictable_value(value: &str) -> bool {
    // Check for simple sequential patterns
    if value.chars().all(char::is_numeric) {
        return true;
    }

    // Check for simple base64 of sequential data
    if value.len() < 16 {
        return true;
    }

    // Check for timestamps only
    if value.parse::<i64>().is_ok() {
        return true;
    }

    false
}

/// Check if a cookie might contain sensitive data
fn contains_sensitive_data(cookie: &Cookie) -> bool {
    let sensitive_patterns = [
        "email", "password", "ssn", "credit", "card", "account", "token", "key", "secret", "auth",
    ];

    let name_lower = cookie.name.to_lowercase();
    let value_lower = cookie.value.to_lowercase();

    sensitive_patterns
        .iter()
        .any(|pattern| name_lower.contains(pattern) || value_lower.contains(pattern))
}

/// Perform advanced security analysis
#[must_use]
pub fn advanced_security_analysis<S: std::hash::BuildHasher>(
    cookies: &[Cookie],
    _domain_map: &HashMap<String, Vec<Cookie>, S>,
) -> Vec<SecurityIssue> {
    let mut issues = Vec::new();

    // Check for cookie injection patterns
    for cookie in cookies {
        if cookie.value.contains(';') || cookie.value.contains('\n') {
            let mut issue = SecurityIssue::new(
                Severity::Critical,
                "Cookie Injection Risk",
                format!(
                    "Cookie '{}' contains suspicious characters that may indicate injection",
                    cookie.name
                ),
                VulnerabilityType::CookieInjection,
            );
            issue.issue = issue
                .issue
                .add_cookie(&cookie.name)
                .add_recommendation("Validate and sanitize cookie values")
                .with_cwe("CWE-93");
            issue.exploitability = 8.0;
            issue.impact = 9.0;
            issue.calculate_cvss();
            issues.push(issue);
        }
    }

    // Check for session hijacking risks
    let session_cookies: Vec<_> = cookies.iter().filter(|c| is_session_cookie(c)).collect();

    if !session_cookies.is_empty() {
        let insecure_sessions = session_cookies
            .iter()
            .filter(|c| !c.secure || !c.http_only)
            .count();

        if insecure_sessions > 0 {
            let mut issue = SecurityIssue::new(
                Severity::Critical,
                "Session Hijacking Vulnerability",
                format!("{insecure_sessions} session cookie(s) lack proper security attributes"),
                VulnerabilityType::SessionHijacking,
            );
            issue.issue = issue
                .issue
                .add_recommendation("Enable Secure and HttpOnly flags on all session cookies")
                .with_cwe("CWE-523");
            issue.exploitability = 8.0;
            issue.impact = 10.0;
            issue.calculate_cvss();
            issues.push(issue);
        }
    }

    issues
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_missing_secure() {
        let cookie = Cookie {
            name: "session".to_string(),
            value: "abc123".to_string(),
            secure: false,
            http_only: true,
            same_site: Some(SameSite::Lax),
            ..Default::default()
        };

        let issues = analyze_security(&[cookie]);
        assert!(issues
            .iter()
            .any(|i| i.vulnerability_type == VulnerabilityType::InsecureTransmission));
    }

    #[test]
    fn test_detect_missing_httponly() {
        let cookie = Cookie {
            name: "session_id".to_string(),
            value: "xyz789".to_string(),
            secure: true,
            http_only: false,
            ..Default::default()
        };

        let issues = analyze_security(&[cookie]);
        assert!(issues
            .iter()
            .any(|i| i.vulnerability_type == VulnerabilityType::XSS));
    }

    #[test]
    fn test_detect_missing_samesite() {
        let cookie = Cookie {
            name: "user_token".to_string(),
            value: "token123".to_string(),
            secure: true,
            http_only: true,
            same_site: None,
            ..Default::default()
        };

        let issues = analyze_security(&[cookie]);
        assert!(issues
            .iter()
            .any(|i| i.vulnerability_type == VulnerabilityType::CSRF));
    }

    #[test]
    fn test_session_cookie_detection() {
        assert!(is_session_cookie(&Cookie {
            name: "JSESSIONID".to_string(),
            value: "test".to_string(),
            ..Default::default()
        }));

        assert!(is_session_cookie(&Cookie {
            name: "session_token".to_string(),
            value: "test".to_string(),
            ..Default::default()
        }));

        assert!(!is_session_cookie(&Cookie {
            name: "user_preference".to_string(),
            value: "test".to_string(),
            ..Default::default()
        }));
    }

    #[test]
    fn test_predictable_value_detection() {
        assert!(is_predictable_value("12345"));
        assert!(is_predictable_value("1234567890"));
        assert!(!is_predictable_value("a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"));
    }

    #[test]
    fn test_sensitive_data_detection() {
        let cookie = Cookie {
            name: "user_email".to_string(),
            value: "test@example.com".to_string(),
            ..Default::default()
        };
        assert!(contains_sensitive_data(&cookie));

        let cookie = Cookie {
            name: "preferences".to_string(),
            value: "theme=dark".to_string(),
            ..Default::default()
        };
        assert!(!contains_sensitive_data(&cookie));
    }

    #[test]
    fn test_cookie_injection_detection() {
        let cookie = Cookie {
            name: "test".to_string(),
            value: "value;Path=/".to_string(),
            ..Default::default()
        };

        let issues = advanced_security_analysis(&[cookie], &HashMap::new());
        assert!(issues
            .iter()
            .any(|i| i.vulnerability_type == VulnerabilityType::CookieInjection));
    }

    #[test]
    fn test_secure_cookie_no_issues() {
        let cookie = Cookie {
            name: "secure_session".to_string(),
            value: "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6".to_string(),
            secure: true,
            http_only: true,
            same_site: Some(SameSite::Strict),
            ..Default::default()
        };

        let issues = analyze_security(&[cookie]);
        // Should have minimal issues for a well-configured cookie
        assert!(issues.is_empty() || issues.iter().all(|i| i.issue.severity <= Severity::Low));
    }
}
