//! CCPA (California Consumer Privacy Act) compliance checking
//!
//! This module implements comprehensive CCPA/CPRA compliance checks for cookies.
//! Reference: California Civil Code §1798.100 et seq.

use crate::types::issue::ComplianceIssue;
use crate::types::report::ComplianceResult;
use crate::types::{Cookie, Regulation, Severity};
use chrono::Utc;

/// Check CCPA compliance for a cookie
#[must_use]
pub fn check_ccpa_compliance(cookie: &Cookie) -> ComplianceResult {
    let mut result = ComplianceResult {
        id: uuid::Uuid::new_v4().to_string(),
        regulation: Regulation::CCPA,
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

    check_sale_of_personal_info(cookie, &mut result);
    check_third_party_sharing(cookie, &mut result);
    check_sensitive_personal_info(cookie, &mut result);
    check_security_measures(cookie, &mut result);
    check_tracking_and_advertising(cookie, &mut result);
    check_global_privacy_control(&mut result);
    check_data_retention(cookie, &mut result);

    result
}

/// Check 1: Sale of Personal Information
fn check_sale_of_personal_info(cookie: &Cookie, result: &mut ComplianceResult) {
    if is_selling_personal_info(cookie) {
        let mut issue = ComplianceIssue::new(
            Severity::High,
            Regulation::CCPA,
            "Sale of Personal Information Without Opt-Out",
            "Cookie used for selling/sharing personal information requires opt-out mechanism",
            "§1798.120 grants consumers the right to opt-out of the sale of their personal information"
        )
        .with_article("§1798.120: Right to Opt-Out of Sale");

        issue.issue = issue.issue.add_cookie(&cookie.name);
        issue.issue = issue
            .issue
            .add_recommendation("Provide clear 'Do Not Sell My Personal Information' link");

        result.issues.push(issue);
        result.recommendations.push(
            "Implement 'Do Not Sell My Personal Information' mechanism as required by CCPA"
                .to_string(),
        );
        result.compliant = false;
    }
}

/// Check 2: Third-party sharing/selling
fn check_third_party_sharing(cookie: &Cookie, result: &mut ComplianceResult) {
    if cookie.is_third_party {
        result
            .warnings
            .push("Third-party cookie detected. Verify disclosure in privacy policy.".to_string());
        result.recommendations.push(
            "Disclose all categories of personal information sold or shared with third parties (§1798.110)".to_string()
        );

        let mut issue = ComplianceIssue::new(
            Severity::Medium,
            Regulation::CCPA,
            "Third-Party Data Sharing Disclosure Required",
            "Third-party cookie requires privacy policy disclosure",
            "§1798.110 and §1798.115 require disclosure of categories of personal information",
        )
        .with_article("§1798.110: Right to Know; §1798.115: Right to Know (Categories)");

        issue.issue = issue.issue.add_cookie(&cookie.name);
        issue.issue = issue
            .issue
            .add_recommendation("Update privacy policy with third-party data sharing details");

        result.issues.push(issue);
    }
}

/// Check 3: Sensitive Personal Information
fn check_sensitive_personal_info(cookie: &Cookie, result: &mut ComplianceResult) {
    if contains_sensitive_info(cookie) {
        let mut issue = ComplianceIssue::new(
            Severity::High,
            Regulation::CCPA,
            "Sensitive Personal Information Without Opt-Out",
            "Cookie may contain sensitive personal information requiring additional protections",
            "§1798.121 grants right to limit use and disclosure of sensitive personal information",
        )
        .with_article("§1798.121: Right to Limit Use of Sensitive Personal Information");

        issue.issue = issue.issue.add_cookie(&cookie.name);
        issue.issue = issue.issue.add_recommendation(
            "Provide opt-out for use of sensitive personal information (CPRA requirement)",
        );

        result.issues.push(issue);
        result.compliant = false;
    }
}

/// Check 4: Security measures
fn check_security_measures(cookie: &Cookie, result: &mut ComplianceResult) {
    if !cookie.secure {
        let mut issue = ComplianceIssue::new(
            Severity::Medium,
            Regulation::CCPA,
            "Insecure Cookie Transmission",
            "Cookie transmitted without encryption (security vulnerability)",
            "§1798.150 imposes liability for security breaches involving unencrypted data",
        )
        .with_article("§1798.150: Security Breach Requirements");

        issue.issue = issue.issue.add_cookie(&cookie.name);
        issue.issue = issue
            .issue
            .add_recommendation("Enable Secure flag to ensure HTTPS-only transmission");

        result.issues.push(issue);
    }
}

/// Check 5: Tracking and advertising
fn check_tracking_and_advertising(cookie: &Cookie, result: &mut ComplianceResult) {
    if is_cross_context_tracking(cookie) {
        let mut issue = ComplianceIssue::new(
            Severity::High,
            Regulation::CCPA,
            "Cross-Context Behavioral Advertising",
            "Cookie used for cross-context behavioral advertising requires opt-out",
            "CPRA defines cross-context behavioral advertising as requiring opt-out",
        )
        .with_article("CPRA Amendment: Cross-Context Behavioral Advertising");

        issue.issue = issue.issue.add_cookie(&cookie.name);
        issue.issue = issue
            .issue
            .add_recommendation("Implement opt-out mechanism for targeted advertising");

        result.issues.push(issue);
        result.compliant = false;
    }
}

/// Check 6: Global Privacy Control (GPC)
fn check_global_privacy_control(result: &mut ComplianceResult) {
    result.recommendations.push(
        "Ensure your website respects Global Privacy Control (GPC) signals (CPRA requirement)"
            .to_string(),
    );
}

/// Check 7: Data retention
fn check_data_retention(cookie: &Cookie, result: &mut ComplianceResult) {
    if let Some(max_age) = cookie.max_age {
        // CCPA requires businesses to not retain data longer than necessary
        if max_age > 365 * 24 * 3600 {
            result.warnings.push(format!(
                "Cookie lifespan exceeds 1 year ({} days). Verify retention necessity.",
                max_age / 86400
            ));
            result.recommendations.push(
                "Review data retention policy to ensure compliance with §1798.105 (Right to Delete)".to_string()
            );
        }
    }

    // Calculate compliance score
    let total_checks = 7.0;
    #[allow(clippy::cast_precision_loss)]
    let failed_checks = result.issues.len() as f32;
    result.score = ((total_checks - failed_checks) / total_checks * 100.0).max(0.0);

    // Update compliant status based on severity
    if result
        .issues
        .iter()
        .any(|i| matches!(i.issue.severity, Severity::Critical | Severity::High))
    {
        result.compliant = false;
    }
}

/// Check if cookie is used for selling personal information
fn is_selling_personal_info(cookie: &Cookie) -> bool {
    // Under CCPA, "sale" includes disclosure for monetary or other valuable consideration
    // Common indicators: ad networks, data brokers, analytics sold to third parties

    let sale_patterns = [
        "doubleclick",
        "adsense",
        "adwords",
        "facebook",
        "fbp",
        "fbc",
        "twitter",
        "linkedin",
        "pinterest",
        "outbrain",
        "taboola",
        "criteo",
        "quantcast",
        "bluekai",
        "lotame",
        "neustar",
        "liveramp",
        "acxiom",
        "experian",
        "oracle",
        "salesforce",
    ];

    let name_lower = cookie.name.to_lowercase();
    let domain_lower = cookie
        .domain
        .as_ref()
        .map(|d| d.to_lowercase())
        .unwrap_or_default();

    sale_patterns
        .iter()
        .any(|p| name_lower.contains(p) || domain_lower.contains(p))
}

/// Check if cookie contains sensitive personal information
fn contains_sensitive_info(cookie: &Cookie) -> bool {
    // CPRA defines sensitive personal information as:
    // - SSN, driver's license, passport, financial account info
    // - Precise geolocation, racial/ethnic origin, religious beliefs
    // - Health information, sex life, sexual orientation
    // - Contents of mail, email, text messages (unless business is recipient)
    // - Genetic data, biometric data

    let sensitive_patterns = [
        "ssn",
        "social_security",
        "license",
        "passport",
        "account",
        "financial",
        "bank",
        "credit",
        "debit",
        "payment",
        "geolocation",
        "location",
        "gps",
        "lat",
        "lon",
        "coordinates",
        "race",
        "ethnic",
        "religion",
        "religious",
        "health",
        "medical",
        "diagnosis",
        "prescription",
        "sexual",
        "biometric",
        "fingerprint",
        "facial",
        "genetic",
    ];

    let name_lower = cookie.name.to_lowercase();
    let value_lower = cookie.value.to_lowercase();

    sensitive_patterns
        .iter()
        .any(|p| name_lower.contains(p) || value_lower.contains(p))
}

/// Check if cookie is used for cross-context behavioral advertising
fn is_cross_context_tracking(cookie: &Cookie) -> bool {
    // Cross-context behavioral advertising tracks consumers across:
    // - Different businesses
    // - Distinctly-branded websites
    // - Distinctly-branded applications

    if !cookie.is_third_party {
        return false; // First-party cookies don't qualify
    }

    let advertising_patterns = [
        "_ga",
        "_gid",
        "_gat", // Google Analytics (when used for advertising)
        "fbp",
        "fbc",
        "fbclid", // Facebook
        "ads",
        "advertising",
        "remarketing",
        "retargeting",
        "conversion",
        "campaign",
        "utm_",
        "doubleclick",
        "adsense",
        "adwords",
    ];

    let name_lower = cookie.name.to_lowercase();
    advertising_patterns.iter().any(|p| name_lower.contains(p))
}

/// Generate CCPA compliance report
#[must_use]
pub fn generate_ccpa_report(cookies: &[Cookie]) -> ComplianceResult {
    let mut aggregate_result = ComplianceResult {
        id: uuid::Uuid::new_v4().to_string(),
        regulation: Regulation::CCPA,
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
        let cookie_result = check_ccpa_compliance(cookie);

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

    // Add general CCPA recommendations
    aggregate_result.recommendations.push(
        "Provide a clear and conspicuous link titled 'Do Not Sell My Personal Information'"
            .to_string(),
    );
    aggregate_result
        .recommendations
        .push("Honor Global Privacy Control (GPC) signals automatically".to_string());
    aggregate_result
        .recommendations
        .push("Update privacy policy with CCPA-required disclosures within 12 months".to_string());

    // Deduplicate
    aggregate_result.recommendations.sort();
    aggregate_result.recommendations.dedup();

    aggregate_result
}

/// Check if "Do Not Sell" mechanism is present
#[must_use]
pub fn check_do_not_sell_mechanism(has_dns_link: bool, respects_gpc: bool) -> Vec<String> {
    let mut issues = Vec::new();

    if !has_dns_link {
        issues.push(
            "Missing 'Do Not Sell My Personal Information' link (CCPA §1798.135 violation)"
                .to_string(),
        );
    }

    if !respects_gpc {
        issues.push(
            "Website does not respect Global Privacy Control signals (CPRA requirement)"
                .to_string(),
        );
    }

    if issues.is_empty() {
        issues.push("CCPA opt-out mechanisms properly implemented".to_string());
    }

    issues
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_selling_personal_info() {
        let cookie = Cookie::new("doubleclick_id".to_string(), "abc123".to_string());
        assert!(is_selling_personal_info(&cookie));
    }

    #[test]
    fn test_sensitive_info() {
        let cookie = Cookie::new("health_data".to_string(), "diagnosis".to_string());
        assert!(contains_sensitive_info(&cookie));
    }

    #[test]
    fn test_cross_context_tracking() {
        let mut cookie = Cookie::new("_ga".to_string(), "GA1.2.123456".to_string());
        cookie.is_third_party = true;
        assert!(is_cross_context_tracking(&cookie));
    }

    #[test]
    fn test_ccpa_compliance_secure_cookie() {
        let mut cookie = Cookie::new("user_pref".to_string(), "dark_mode".to_string());
        cookie.secure = true;
        cookie.is_third_party = false;

        let result = check_ccpa_compliance(&cookie);
        assert!(result.score > 80.0);
    }

    #[test]
    fn test_ccpa_compliance_ad_cookie() {
        let mut cookie = Cookie::new("doubleclick_id".to_string(), "xyz789".to_string());
        cookie.secure = false;
        cookie.is_third_party = true;

        let result = check_ccpa_compliance(&cookie);
        assert!(!result.compliant);
        assert!(!result.issues.is_empty());
    }

    #[test]
    fn test_do_not_sell_mechanism() {
        let issues = check_do_not_sell_mechanism(true, true);
        assert!(issues[0].contains("properly implemented"));

        let issues = check_do_not_sell_mechanism(false, false);
        assert_eq!(issues.len(), 2);
    }
}
