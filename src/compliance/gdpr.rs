//! GDPR (General Data Protection Regulation) compliance checking
//!
//! This module implements comprehensive GDPR compliance checks for cookies.
//! Reference: Regulation (EU) 2016/679

use crate::types::issue::ComplianceIssue;
use crate::types::report::ComplianceResult;
use crate::types::{Cookie, Regulation, Severity};
use chrono::Utc;

/// Check GDPR compliance for a cookie
#[must_use]
pub fn check_gdpr_compliance(cookie: &Cookie) -> ComplianceResult {
    let mut result = ComplianceResult {
        id: uuid::Uuid::new_v4().to_string(),
        regulation: Regulation::GDPR,
        checked_at: Utc::now(),
        compliant: true,
        score: 100.0,
        issues: Vec::new(),
        compliant_cookies: 0,
        non_compliant_cookies: 0,
        warnings: Vec::new(),
        recommendations: Vec::new(),
        consent_analysis: None,
    };

    check_essential_vs_non_essential(cookie, &mut result);
    check_pii_security(cookie, &mut result);
    check_pii_httponly(cookie, &mut result);
    check_third_party_transfers(cookie, &mut result);
    check_data_minimization(cookie, &mut result);
    check_retention_period(cookie, &mut result);
    check_purpose_limitation(cookie, &mut result);
    finalize_gdpr_score(&mut result);

    result
}

/// Check 1: Essential cookies vs non-essential
fn check_essential_vs_non_essential(cookie: &Cookie, result: &mut ComplianceResult) {
    if is_non_essential_cookie(cookie) {
        result.warnings.push(
            "Non-essential cookie detected. Explicit user consent required before setting."
                .to_string(),
        );
        result
            .recommendations
            .push("Implement a cookie consent banner with opt-in mechanism.".to_string());
    }
}

/// Check 2: Security attributes for cookies containing personal data
fn check_pii_security(cookie: &Cookie, result: &mut ComplianceResult) {
    if potentially_contains_pii(cookie) && !cookie.secure {
        let mut issue = ComplianceIssue::new(
            Severity::High,
            Regulation::GDPR,
            "Insecure Transmission of PII",
            "Cookie potentially containing PII transmitted over non-secure connection",
            "Article 32 requires appropriate security measures including encryption in transit",
        )
        .with_article("Article 32: Security of Processing");

        issue.issue = issue.issue.add_cookie(&cookie.name);
        issue.issue = issue
            .issue
            .add_recommendation("Enable Secure flag to ensure transmission over HTTPS only");

        result.issues.push(issue);
        result.compliant = false;
    }
}

/// Check `HttpOnly` for PII cookies
fn check_pii_httponly(cookie: &Cookie, result: &mut ComplianceResult) {
    if potentially_contains_pii(cookie) && !cookie.http_only {
        let mut issue = ComplianceIssue::new(
            Severity::Medium,
            Regulation::GDPR,
            "JavaScript-Accessible PII",
            "Cookie accessible via JavaScript (XSS vulnerability)",
            "Article 32 requires protection against accidental or unlawful destruction",
        )
        .with_article("Article 32: Security of Processing");

        issue.issue = issue.issue.add_cookie(&cookie.name);
        issue.issue = issue
            .issue
            .add_recommendation("Enable HttpOnly flag to prevent JavaScript access");

        result.issues.push(issue);
        result.compliant = false;
    }
}

/// Check 3: Data retention period
fn check_retention_period(cookie: &Cookie, result: &mut ComplianceResult) {
    if let Some(max_age) = cookie.max_age {
        // GDPR principle: data should not be kept longer than necessary
        // Cookies > 13 months require justification (ePrivacy Directive)
        if max_age > 13 * 30 * 24 * 3600 {
            let mut issue = ComplianceIssue::new(
                Severity::Medium,
                Regulation::GDPR,
                "Excessive Cookie Lifespan",
                format!(
                    "Cookie lifespan exceeds 13 months ({} days)",
                    max_age / 86400
                ),
                "Article 5(1)(e) requires that personal data be kept for no longer than necessary",
            )
            .with_article("Article 5(1)(e): Storage Limitation");

            issue.issue = issue.issue.add_cookie(&cookie.name);
            issue.issue = issue.issue.add_recommendation(
                "Reduce cookie lifespan to maximum 13 months or provide justification",
            );

            result.issues.push(issue);
            result
                .warnings
                .push("Cookie lifespan exceeds recommended 13 month maximum".to_string());
        }
    }
}

/// Check 4: Third-party transfers and data sharing
fn check_third_party_transfers(cookie: &Cookie, result: &mut ComplianceResult) {
    if cookie.is_third_party {
        result.warnings.push(
            "Third-party cookie detected. Data sharing with third parties requires explicit consent and disclosure.".to_string()
        );
        result.recommendations.push(
            "Ensure privacy policy discloses all third-party data recipients (Article 13)."
                .to_string(),
        );

        let mut issue = ComplianceIssue::new(
            Severity::Medium,
            Regulation::GDPR,
            "Third-Party Data Sharing",
            "Third-party cookie requires disclosure and consent",
            "Articles 13 and 28 require disclosure and documentation of data processor relationships"
        )
        .with_article("Article 13: Information to be provided; Article 28: Processor");

        issue.issue = issue.issue.add_cookie(&cookie.name);
        issue.issue = issue
            .issue
            .add_recommendation("Document data controller/processor relationship with third party");

        result.issues.push(issue);
    }
}

/// Check 5: Data minimization - tracking cookies require consent
fn check_data_minimization(cookie: &Cookie, result: &mut ComplianceResult) {
    if is_tracking_cookie(cookie) {
        let mut issue = ComplianceIssue::new(
            Severity::High,
            Regulation::GDPR,
            "Tracking Without Consent",
            "Tracking cookie requires explicit user consent before setting",
            "Article 6(1)(a) requires explicit consent for processing personal data for tracking purposes"
        )
        .with_article("Article 6(1)(a): Consent; Recital 32");

        issue.issue = issue.issue.add_cookie(&cookie.name);
        issue.issue = issue.issue.add_recommendation(
            "Implement consent mechanism with clear opt-in before setting tracking cookies",
        );

        result.issues.push(issue);
        result.compliant = false;
    }
}

/// Check 6: Purpose limitation - `SameSite` attribute for CSRF protection
fn check_purpose_limitation(cookie: &Cookie, result: &mut ComplianceResult) {
    if cookie.same_site.is_none() || matches!(cookie.same_site, Some(crate::types::SameSite::None))
    {
        result
            .warnings
            .push("Cookie lacks adequate SameSite protection against CSRF attacks".to_string());
        result
            .recommendations
            .push("Set SameSite=Strict or SameSite=Lax for improved security".to_string());
    }
}

/// Finalize GDPR score and compliance status
fn finalize_gdpr_score(result: &mut ComplianceResult) {
    // Calculate compliance score
    let total_checks = 6.0;
    #[allow(clippy::cast_precision_loss)]
    let failed_checks = result.issues.len() as f32;
    result.score = ((total_checks - failed_checks) / total_checks * 100.0).max(0.0);

    // Update compliant status
    if result
        .issues
        .iter()
        .any(|i| matches!(i.issue.severity, Severity::Critical | Severity::High))
    {
        result.compliant = false;
    }
}

/// Determine if cookie is non-essential (requires consent)
fn is_non_essential_cookie(cookie: &Cookie) -> bool {
    // Essential cookies are typically:
    // - Session cookies
    // - Security cookies
    // - Load balancing cookies
    // - User interface customization cookies (for accessibility)

    let essential_patterns = [
        "sessionid",
        "session_id",
        "csrf",
        "xsrf",
        "auth",
        "authentication",
        "security",
        "remember",
        "login",
        "jsessionid",
        "aspsessionid",
        "phpsessid",
        "sess",
        "sid",
        "load_balancer",
        "server_id",
    ];

    let name_lower = cookie.name.to_lowercase();

    // If name matches essential patterns, it's likely essential
    if essential_patterns.iter().any(|p| name_lower.contains(p)) {
        return false; // Essential, no consent needed
    }

    // Analytics, advertising, tracking are non-essential
    let non_essential_patterns = [
        "_ga",
        "_gid",
        "_gat",
        "utm_",
        "analytics",
        "tracking",
        "fbp",
        "fbclid",
        "doubleclick",
        "adsense",
        "advertising",
        "marketing",
        "remarketing",
        "conversion",
        "_fbp",
        "_fbc",
    ];

    if non_essential_patterns
        .iter()
        .any(|p| name_lower.contains(p))
    {
        return true; // Non-essential, consent required
    }

    // Default: treat as non-essential (safer approach for GDPR)
    true
}

/// Check if cookie potentially contains PII
fn potentially_contains_pii(cookie: &Cookie) -> bool {
    let pii_patterns = [
        "user",
        "email",
        "name",
        "address",
        "phone",
        "id",
        "profile",
        "personal",
        "identity",
        "credential",
    ];

    let name_lower = cookie.name.to_lowercase();
    pii_patterns.iter().any(|p| name_lower.contains(p)) || cookie.name.len() > 32
    // Long cookies often contain session IDs or user tokens
}

/// Check if cookie is used for tracking
fn is_tracking_cookie(cookie: &Cookie) -> bool {
    let tracking_patterns = [
        "_ga",
        "_gid",
        "_gat",
        "utm_",
        "analytics",
        "tracking",
        "_fbp",
        "_fbc",
        "fbclid",
        "doubleclick",
        "adsense",
        "_hjid",
        "intercom",
        "mixpanel",
        "amplitude",
    ];

    let name_lower = cookie.name.to_lowercase();
    tracking_patterns.iter().any(|p| name_lower.contains(p))
}

/// Generate GDPR compliance report
#[must_use]
pub fn generate_gdpr_report(cookies: &[Cookie]) -> ComplianceResult {
    let mut aggregate_result = ComplianceResult {
        id: uuid::Uuid::new_v4().to_string(),
        regulation: Regulation::GDPR,
        checked_at: Utc::now(),
        compliant: true,
        score: 100.0,
        issues: Vec::new(),
        compliant_cookies: 0,
        non_compliant_cookies: 0,
        warnings: Vec::new(),
        recommendations: Vec::new(),
        consent_analysis: None,
    };

    for cookie in cookies {
        let cookie_result = check_gdpr_compliance(cookie);

        if cookie_result.compliant {
            aggregate_result.compliant_cookies += 1;
        } else {
            aggregate_result.non_compliant_cookies += 1;
            aggregate_result.compliant = false;
        }

        aggregate_result.issues.extend(cookie_result.issues);
        aggregate_result.warnings.extend(cookie_result.warnings);
        aggregate_result
            .recommendations
            .extend(cookie_result.recommendations);
    }

    // Calculate aggregate score
    if !cookies.is_empty() {
        #[allow(clippy::cast_precision_loss)]
        let score = (aggregate_result.compliant_cookies as f32 / cookies.len() as f32) * 100.0;
        aggregate_result.score = score;
    }

    // Deduplicate recommendations
    aggregate_result.recommendations.sort();
    aggregate_result.recommendations.dedup();

    aggregate_result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_essential_cookie() {
        let cookie = Cookie::new("sessionid".to_string(), "abc123".to_string());
        assert!(!is_non_essential_cookie(&cookie));
    }

    #[test]
    fn test_non_essential_cookie() {
        let cookie = Cookie::new("_ga".to_string(), "GA1.2.123456".to_string());
        assert!(is_non_essential_cookie(&cookie));
    }

    #[test]
    fn test_tracking_cookie() {
        let cookie = Cookie::new("_gid".to_string(), "GA1.2.123456".to_string());
        assert!(is_tracking_cookie(&cookie));
    }

    #[test]
    fn test_pii_cookie() {
        let cookie = Cookie::new("user_email".to_string(), "test@example.com".to_string());
        assert!(potentially_contains_pii(&cookie));
    }

    #[test]
    fn test_gdpr_compliance_secure_cookie() {
        let mut cookie = Cookie::new("sessionid".to_string(), "abc123".to_string());
        cookie.secure = true;
        cookie.http_only = true;
        cookie.same_site = Some(crate::types::SameSite::Strict);

        let result = check_gdpr_compliance(&cookie);
        assert!(result.score > 80.0);
    }

    #[test]
    fn test_gdpr_compliance_insecure_cookie() {
        let mut cookie = Cookie::new("_ga".to_string(), "GA1.2.123456".to_string());
        cookie.secure = false;
        cookie.http_only = false;
        cookie.is_third_party = true;

        let result = check_gdpr_compliance(&cookie);
        assert!(!result.compliant);
        assert!(!result.issues.is_empty());
    }
}
