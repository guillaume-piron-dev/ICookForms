//! International privacy regulations compliance checking
//!
//! This module implements compliance checks for various international privacy regulations
//! including LGPD (Brazil), POPIA (South Africa), PIPEDA (Canada), PDPA (Singapore),
//! and ePrivacy Directive (EU), plus US state privacy laws and other regulations.

use crate::types::issue::ComplianceIssue;
use crate::types::report::ComplianceResult;
use crate::types::{Cookie, Regulation, Severity};
use chrono::Utc;

/// Check UK GDPR compliance (similar to EU GDPR with UK specifics)
#[must_use]
pub fn check_ukgdpr_compliance(cookie: &Cookie) -> ComplianceResult {
    let mut result = create_compliance_result(Regulation::UKGDPR);

    // UK GDPR has similar requirements to EU GDPR
    if !is_strictly_necessary(cookie) {
        add_consent_issue(
            &mut result,
            cookie,
            "UK GDPR requires consent for non-essential cookies",
        );
    }

    if !cookie.secure && contains_personal_data(cookie) {
        add_security_issue(
            &mut result,
            cookie,
            "UK GDPR requires appropriate security measures",
        );
    }

    calculate_score(&mut result, 2);
    result
}

/// Check CPRA (California Privacy Rights Act) compliance
#[must_use]
pub fn check_cpra_compliance(cookie: &Cookie) -> ComplianceResult {
    let mut result = create_compliance_result(Regulation::CPRA);

    // CPRA expands CCPA with additional requirements
    if cookie.is_third_party {
        result.warnings.push(
            "Third-party cookie may constitute 'sharing' under CPRA - provide opt-out".to_string(),
        );
    }

    if !cookie.secure && contains_sensitive_personal_info(cookie) {
        add_security_issue(
            &mut result,
            cookie,
            "CPRA requires security for sensitive personal information",
        );
    }

    result.recommendations.push(
        "Provide clear notice and opt-out mechanism for cookie-based data sharing".to_string(),
    );

    calculate_score(&mut result, 2);
    result
}

/// Check Privacy Act (Australia) compliance
#[must_use]
pub fn check_privacy_act_compliance(cookie: &Cookie) -> ComplianceResult {
    let mut result = create_compliance_result(Regulation::PrivacyAct);

    // Australian Privacy Principles (APPs)
    if !cookie.secure && contains_personal_data(cookie) {
        add_security_issue(
            &mut result,
            cookie,
            "APP 11 requires security safeguards for personal information",
        );
    }

    if cookie.is_third_party {
        result.warnings.push(
            "Third-party cookie may involve disclosure - ensure APP 6 compliance".to_string(),
        );
    }

    calculate_score(&mut result, 2);
    result
}

/// Check APPI (Act on Protection of Personal Information - Japan) compliance
#[must_use]
pub fn check_appi_compliance(cookie: &Cookie) -> ComplianceResult {
    let mut result = create_compliance_result(Regulation::APPI);

    // APPI requirements for personal information
    if !cookie.secure && contains_personal_data(cookie) {
        add_security_issue(
            &mut result,
            cookie,
            "APPI Article 23 requires security control measures",
        );
    }

    if cookie.is_third_party {
        result.warnings.push(
            "Third-party cookie may involve provision to third party - verify APPI Article 27 compliance".to_string()
        );
    }

    calculate_score(&mut result, 2);
    result
}

/// Check COPPA (Children's Online Privacy Protection Act - USA) compliance
#[must_use]
pub fn check_coppa_compliance(cookie: &Cookie) -> ComplianceResult {
    let mut result = create_compliance_result(Regulation::COPPA);

    // COPPA applies to sites directed to children under 13
    result.warnings.push(
        "If site is directed to children under 13, COPPA requires verifiable parental consent"
            .to_string(),
    );

    if cookie.is_third_party {
        let mut issue = ComplianceIssue::new(
            Severity::High,
            Regulation::COPPA,
            "Third-Party Cookie on Children's Site",
            "Third-party cookies require parental consent for children under 13",
            "COPPA prohibits collection of personal information from children without parental consent"
        )
        .with_article("16 CFR § 312.5: Parental Consent");

        issue.issue = issue.issue.add_cookie(&cookie.name);
        issue.issue = issue
            .issue
            .add_recommendation("Obtain verifiable parental consent before setting cookies");

        result.issues.push(issue);
        result.compliant = false;
    }

    calculate_score(&mut result, 2);
    result
}

/// Check HIPAA (Health Insurance Portability and Accountability Act - USA) compliance
#[must_use]
pub fn check_hipaa_compliance(cookie: &Cookie) -> ComplianceResult {
    let mut result = create_compliance_result(Regulation::HIPAA);

    // HIPAA applies to Protected Health Information (PHI)
    if contains_health_information(cookie) {
        if !cookie.secure {
            let mut issue = ComplianceIssue::new(
                Severity::Critical,
                Regulation::HIPAA,
                "Unencrypted PHI in Cookie",
                "Protected Health Information transmitted without encryption",
                "HIPAA Security Rule requires encryption of PHI in transit",
            )
            .with_article("45 CFR § 164.312(e)(1): Transmission Security");

            issue.issue = issue.issue.add_cookie(&cookie.name);
            issue.issue = issue
                .issue
                .add_recommendation("Enable Secure flag and encrypt PHI");

            result.issues.push(issue);
            result.compliant = false;
        }

        if !cookie.http_only {
            result.warnings.push(
                "PHI in cookie should have HttpOnly flag to prevent JavaScript access".to_string(),
            );
        }
    }

    calculate_score(&mut result, 2);
    result
}

/// Check VCDPA (Virginia Consumer Data Protection Act) compliance
#[must_use]
pub fn check_vcdpa_compliance(cookie: &Cookie) -> ComplianceResult {
    let mut result = create_compliance_result(Regulation::VCDPA);

    // VCDPA is similar to CCPA with Virginia specifics
    if cookie.is_third_party {
        result.warnings.push(
            "Targeted advertising or sale requires opt-out mechanism under VCDPA".to_string(),
        );
    }

    if !cookie.secure && contains_sensitive_data_vcdpa(cookie) {
        add_security_issue(
            &mut result,
            cookie,
            "VCDPA requires security for sensitive data",
        );
    }

    result
        .recommendations
        .push("Provide clear privacy notice and opt-out for targeted advertising".to_string());

    calculate_score(&mut result, 2);
    result
}

/// Check CPA (Colorado Privacy Act) compliance
#[must_use]
pub fn check_cpa_compliance(cookie: &Cookie) -> ComplianceResult {
    let mut result = create_compliance_result(Regulation::CPA);

    // CPA requirements similar to other US state laws
    if cookie.is_third_party {
        result
            .warnings
            .push("Targeted advertising requires opt-out under CPA".to_string());
    }

    if !cookie.secure && contains_sensitive_data_cpa(cookie) {
        add_security_issue(
            &mut result,
            cookie,
            "CPA requires security for sensitive data",
        );
    }

    calculate_score(&mut result, 2);
    result
}

/// Check CTDPA (Connecticut Data Privacy Act) compliance
#[must_use]
pub fn check_ctdpa_compliance(cookie: &Cookie) -> ComplianceResult {
    let mut result = create_compliance_result(Regulation::CTDPA);

    // CTDPA follows similar pattern to other state laws
    if cookie.is_third_party {
        result.warnings.push(
            "Processing for targeted advertising requires consumer consent under CTDPA".to_string(),
        );
    }

    if !cookie.secure && contains_personal_data(cookie) {
        add_security_issue(
            &mut result,
            cookie,
            "CTDPA requires reasonable security practices",
        );
    }

    calculate_score(&mut result, 2);
    result
}

/// Check UCPA (Utah Consumer Privacy Act) compliance
#[must_use]
pub fn check_ucpa_compliance(cookie: &Cookie) -> ComplianceResult {
    let mut result = create_compliance_result(Regulation::UCPA);

    // UCPA has opt-out requirements
    if cookie.is_third_party {
        result.warnings.push(
            "Sale of personal data or targeted advertising requires opt-out under UCPA".to_string(),
        );
    }

    if !cookie.secure && contains_sensitive_data_ucpa(cookie) {
        add_security_issue(
            &mut result,
            cookie,
            "UCPA requires security for sensitive data",
        );
    }

    calculate_score(&mut result, 2);
    result
}

/// Check LGPD (Lei Geral de Proteção de Dados - Brazil) compliance
#[must_use]
pub fn check_lgpd_compliance(cookie: &Cookie) -> ComplianceResult {
    let mut result = create_compliance_result(Regulation::LGPD);

    // LGPD is similar to GDPR with Brazilian specifics

    // Check 1: Consent requirement (Article 7)
    if requires_consent_lgpd(cookie) {
        result
            .warnings
            .push("Cookie requires explicit consent under LGPD Article 7".to_string());
        result
            .recommendations
            .push("Implement consent mechanism with clear purpose disclosure".to_string());
    }

    // Check 2: Security measures (Article 46)
    if !cookie.secure && contains_personal_data(cookie) {
        let mut issue = ComplianceIssue::new(
            Severity::High,
            Regulation::LGPD,
            "Insecure Personal Data Transmission",
            "Personal data transmitted without encryption",
            "Article 46 requires security measures including encryption of personal data in transit"
        )
        .with_article("Article 46: Security Measures");

        issue.issue = issue.issue.add_cookie(&cookie.name);
        issue.issue = issue
            .issue
            .add_recommendation("Enable Secure flag for HTTPS-only transmission");

        result.issues.push(issue);
        result.compliant = false;
    }

    // Check 3: Data minimization (Article 6, III)
    if let Some(max_age) = cookie.max_age {
        if max_age > 365 * 24 * 3600 {
            result
                .warnings
                .push("Cookie lifespan exceeds 1 year - verify necessity principle".to_string());
        }
    }

    // Check 4: International data transfer (Article 33)
    if cookie.is_third_party {
        result.warnings.push(
            "Third-party cookie may involve international data transfer - verify adequacy"
                .to_string(),
        );
        result.recommendations.push(
            "Ensure adequate safeguards for international data transfers (Article 33)".to_string(),
        );
    }

    calculate_score(&mut result, 4);
    result
}

/// Check POPIA (Protection of Personal Information Act - South Africa) compliance
#[must_use]
pub fn check_popia_compliance(cookie: &Cookie) -> ComplianceResult {
    let mut result = create_compliance_result(Regulation::POPIA);

    // Check 1: Consent (Section 69)
    if requires_consent_popia(cookie) {
        result
            .warnings
            .push("Non-essential cookie requires consent under POPIA Section 69".to_string());
    }

    // Check 2: Security safeguards (Section 19)
    if !cookie.secure && contains_personal_data(cookie) {
        let mut issue = ComplianceIssue::new(
            Severity::High,
            Regulation::POPIA,
            "Inadequate Security Safeguards",
            "Inadequate security for personal information",
            "Section 19 requires security safeguards to protect personal information",
        )
        .with_article("Section 19: Security Safeguards");

        issue.issue = issue.issue.add_cookie(&cookie.name);
        issue.issue = issue
            .issue
            .add_recommendation("Implement appropriate security measures (Secure flag)");

        result.issues.push(issue);
        result.compliant = false;
    }

    // Check 3: Purpose specification (Section 13)
    result
        .recommendations
        .push("Ensure cookie usage aligns with specified, explicit and lawful purpose".to_string());

    calculate_score(&mut result, 3);
    result
}

/// Check PIPEDA (Personal Information Protection and Electronic Documents Act - Canada) compliance
#[must_use]
pub fn check_pipeda_compliance(cookie: &Cookie) -> ComplianceResult {
    let mut result = create_compliance_result(Regulation::PIPEDA);

    // PIPEDA Principle 3: Consent
    if requires_consent_pipeda(cookie) {
        result
            .warnings
            .push("Cookie requires meaningful consent under PIPEDA Principle 3".to_string());
        result
            .recommendations
            .push("Obtain meaningful consent - make it clear and understandable".to_string());
    }

    // PIPEDA Principle 7: Safeguards
    if !cookie.secure && contains_personal_data(cookie) {
        let mut issue = ComplianceIssue::new(
            Severity::Medium,
            Regulation::PIPEDA,
            "Insufficient Security Safeguards",
            "Insufficient safeguards for personal information",
            "Principle 7 requires safeguards appropriate to the sensitivity of the information",
        )
        .with_article("Principle 7: Safeguards");

        issue.issue = issue.issue.add_cookie(&cookie.name);
        issue.issue = issue
            .issue
            .add_recommendation("Implement security safeguards appropriate to sensitivity");

        result.issues.push(issue);
        result.compliant = false;
    }

    // PIPEDA Principle 5: Limiting Use, Disclosure, and Retention
    if let Some(max_age) = cookie.max_age {
        if max_age > 730 * 24 * 3600 {
            // 2 years
            result
                .warnings
                .push("Cookie retention period exceeds 2 years - verify necessity".to_string());
        }
    }

    calculate_score(&mut result, 3);
    result
}

/// Check PDPA (Personal Data Protection Act - Singapore) compliance
#[must_use]
pub fn check_pdpa_compliance(cookie: &Cookie) -> ComplianceResult {
    let mut result = create_compliance_result(Regulation::PDPA);

    // PDPA Section 13: Consent Obligation
    if requires_consent_pdpa(cookie) {
        result
            .warnings
            .push("Cookie requires consent under PDPA Section 13".to_string());
    }

    // PDPA Section 24: Protection Obligation
    if !cookie.secure && contains_personal_data(cookie) {
        let mut issue = ComplianceIssue::new(
            Severity::Medium,
            Regulation::PDPA,
            "Inadequate Data Protection",
            "Inadequate protection for personal data",
            "Section 24 requires reasonable security arrangements to protect personal data",
        )
        .with_article("Section 24: Protection Obligation");

        issue.issue = issue.issue.add_cookie(&cookie.name);
        issue.issue = issue
            .issue
            .add_recommendation("Make reasonable security arrangements (Section 24)");

        result.issues.push(issue);
        result.compliant = false;
    }

    // PDPA Section 25: Retention Limitation Obligation
    result.recommendations.push(
        "Retain personal data only as long as necessary for legal/business purposes".to_string(),
    );

    calculate_score(&mut result, 3);
    result
}

/// Check ePrivacy Directive (EU) compliance
#[must_use]
pub fn check_eprivacy_compliance(cookie: &Cookie) -> ComplianceResult {
    let mut result = create_compliance_result(Regulation::EPrivacy);

    // Article 5(3): Cookie consent requirement
    if !is_strictly_necessary(cookie) {
        let mut issue = ComplianceIssue::new(
            Severity::High,
            Regulation::EPrivacy,
            "Non-Essential Cookie Without Consent",
            "Non-essential cookie requires prior consent",
            "Article 5(3) requires informed consent before storing or accessing cookies",
        )
        .with_article("Article 5(3): Confidentiality of Communications");

        issue.issue = issue.issue.add_cookie(&cookie.name);
        issue.issue = issue
            .issue
            .add_recommendation("Obtain informed consent before storing or accessing cookie");

        result.issues.push(issue);
        result.compliant = false;
    }

    // Cookie duration recommendation (13 months max)
    if let Some(max_age) = cookie.max_age {
        if max_age > 13 * 30 * 24 * 3600 {
            let mut issue = ComplianceIssue::new(
                Severity::Medium,
                Regulation::EPrivacy,
                "Excessive Cookie Duration",
                "Cookie lifespan exceeds recommended 13 months",
                "EDPB Guidelines recommend maximum 13 month cookie duration",
            )
            .with_article("EDPB Guidelines: Cookie Duration");

            issue.issue = issue.issue.add_cookie(&cookie.name);
            issue.issue = issue
                .issue
                .add_recommendation("Reduce cookie lifespan to 13 months or less");

            result.issues.push(issue);
        }
    }

    // Clear and comprehensive information
    result
        .recommendations
        .push("Provide clear and comprehensive information about cookie purposes".to_string());

    calculate_score(&mut result, 3);
    result
}

// Helper functions

fn create_compliance_result(regulation: Regulation) -> ComplianceResult {
    ComplianceResult {
        id: uuid::Uuid::new_v4().to_string(),
        regulation,
        checked_at: Utc::now(),
        compliant: true,
        score: 100.0,
        issues: Vec::new(),
        compliant_cookies: 0,
        non_compliant_cookies: 0,
        warnings: Vec::new(),
        recommendations: Vec::new(),
        consent_analysis: None,
    }
}

fn add_consent_issue(result: &mut ComplianceResult, cookie: &Cookie, description: &str) {
    let mut issue = ComplianceIssue::new(
        Severity::High,
        result.regulation,
        "Consent Required",
        description,
        "Non-essential cookies require user consent",
    );

    issue.issue = issue.issue.add_cookie(&cookie.name);
    issue.issue = issue
        .issue
        .add_recommendation("Implement consent mechanism before setting cookie");

    result.issues.push(issue);
    result.compliant = false;
}

fn add_security_issue(result: &mut ComplianceResult, cookie: &Cookie, description: &str) {
    let mut issue = ComplianceIssue::new(
        Severity::High,
        result.regulation,
        "Security Requirement",
        description,
        "Personal data requires appropriate security measures",
    );

    issue.issue = issue.issue.add_cookie(&cookie.name);
    issue.issue = issue
        .issue
        .add_recommendation("Enable Secure flag for HTTPS transmission");

    result.issues.push(issue);
    result.compliant = false;
}

fn requires_consent_lgpd(cookie: &Cookie) -> bool {
    !is_strictly_necessary(cookie)
}

fn requires_consent_popia(cookie: &Cookie) -> bool {
    !is_strictly_necessary(cookie) && contains_personal_data(cookie)
}

fn requires_consent_pipeda(cookie: &Cookie) -> bool {
    contains_personal_data(cookie)
}

fn requires_consent_pdpa(cookie: &Cookie) -> bool {
    contains_personal_data(cookie)
}

fn is_strictly_necessary(cookie: &Cookie) -> bool {
    // Strictly necessary cookies are essential for website operation
    let necessary_patterns = [
        "session",
        "csrf",
        "xsrf",
        "auth",
        "login",
        "security",
        "load_balancer",
        "jsessionid",
        "phpsessid",
    ];

    let name_lower = cookie.name.to_lowercase();
    necessary_patterns.iter().any(|p| name_lower.contains(p))
}

fn contains_personal_data(cookie: &Cookie) -> bool {
    let personal_data_patterns = [
        "user",
        "email",
        "name",
        "id",
        "profile",
        "account",
        "personal",
        "identity",
        "credential",
    ];

    let name_lower = cookie.name.to_lowercase();
    personal_data_patterns
        .iter()
        .any(|p| name_lower.contains(p))
        || cookie.name.len() > 32 // Long cookies often contain user identifiers
}

fn contains_sensitive_personal_info(cookie: &Cookie) -> bool {
    let sensitive_patterns = [
        "ssn",
        "race",
        "religion",
        "health",
        "biometric",
        "genetic",
        "financial",
    ];
    let name_lower = cookie.name.to_lowercase();
    sensitive_patterns.iter().any(|p| name_lower.contains(p))
}

fn contains_health_information(cookie: &Cookie) -> bool {
    let health_patterns = [
        "health",
        "medical",
        "patient",
        "diagnosis",
        "treatment",
        "prescription",
        "phi",
    ];
    let name_lower = cookie.name.to_lowercase();
    health_patterns.iter().any(|p| name_lower.contains(p))
}

fn contains_sensitive_data_vcdpa(cookie: &Cookie) -> bool {
    contains_sensitive_personal_info(cookie)
}

fn contains_sensitive_data_cpa(cookie: &Cookie) -> bool {
    contains_sensitive_personal_info(cookie)
}

fn contains_sensitive_data_ucpa(cookie: &Cookie) -> bool {
    contains_sensitive_personal_info(cookie)
}

#[allow(clippy::cast_precision_loss)] // Small check counts, f32 precision acceptable
fn calculate_score(result: &mut ComplianceResult, total_checks: usize) {
    let failed_checks = result.issues.len() as f32;
    result.score = ((total_checks as f32 - failed_checks) / total_checks as f32 * 100.0).max(0.0);

    if result
        .issues
        .iter()
        .any(|i| matches!(i.issue.severity, Severity::Critical | Severity::High))
    {
        result.compliant = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strictly_necessary() {
        let cookie = Cookie::new("sessionid".to_string(), "abc123".to_string());
        assert!(is_strictly_necessary(&cookie));

        let cookie = Cookie::new("_ga".to_string(), "GA1.2.123456".to_string());
        assert!(!is_strictly_necessary(&cookie));
    }

    #[test]
    fn test_contains_personal_data() {
        let cookie = Cookie::new("user_email".to_string(), "test@example.com".to_string());
        assert!(contains_personal_data(&cookie));

        let cookie = Cookie::new("theme".to_string(), "dark".to_string());
        assert!(!contains_personal_data(&cookie));
    }

    #[test]
    fn test_lgpd_compliance() {
        let mut cookie = Cookie::new("user_id".to_string(), "12345".to_string());
        cookie.secure = true;
        let result = check_lgpd_compliance(&cookie);
        assert!(result.score > 50.0);
    }

    #[test]
    fn test_eprivacy_compliance_essential() {
        let cookie = Cookie::new("sessionid".to_string(), "abc".to_string());
        let result = check_eprivacy_compliance(&cookie);
        assert!(result.compliant);
    }

    #[test]
    fn test_eprivacy_compliance_non_essential() {
        let cookie = Cookie::new("_ga".to_string(), "GA1.2.123".to_string());
        let result = check_eprivacy_compliance(&cookie);
        assert!(!result.compliant);
    }

    #[test]
    fn test_coppa_compliance() {
        let mut cookie = Cookie::new("analytics".to_string(), "test".to_string());
        cookie.is_third_party = true;
        let result = check_coppa_compliance(&cookie);
        assert!(!result.compliant);
    }

    #[test]
    fn test_hipaa_compliance() {
        let mut cookie = Cookie::new("patient_health".to_string(), "data".to_string());
        cookie.secure = false;
        let result = check_hipaa_compliance(&cookie);
        assert!(!result.compliant);
    }
}
