//! Compliance checking module
//!
//! This module provides comprehensive compliance checking for various regulations
//! including GDPR, CCPA, LGPD, and more.

pub mod ccpa;
pub mod consent;
pub mod gdpr;
pub mod google_consent;
pub mod iab_tcf;
pub mod regulations;

use crate::types::{ComplianceIssue, ComplianceResult, Cookie, Regulation, Severity};
use chrono::Utc;

/// Compliance checker for cookies
pub struct ComplianceChecker {
    /// Regulations to check against
    regulations: Vec<Regulation>,
    /// Strict mode (fails on warnings)
    strict: bool,
}

impl ComplianceChecker {
    /// Create a new compliance checker with default regulations
    #[must_use]
    pub fn new() -> Self {
        Self {
            regulations: vec![Regulation::GDPR, Regulation::CCPA],
            strict: false,
        }
    }

    /// Create a compliance checker with specific regulations
    #[must_use]
    pub fn with_regulations(regulations: Vec<Regulation>) -> Self {
        Self {
            regulations,
            strict: false,
        }
    }

    /// Enable strict mode
    #[must_use]
    pub fn strict(mut self) -> Self {
        self.strict = true;
        self
    }

    /// Check compliance for a single cookie
    #[must_use]
    pub fn check(&self, cookie: &Cookie, regulation: Regulation) -> ComplianceResult {
        // Exhaustive match with all Regulation variants
        match regulation {
            Regulation::GDPR => gdpr::check_gdpr_compliance(cookie),
            Regulation::CCPA => ccpa::check_ccpa_compliance(cookie),
            Regulation::LGPD => regulations::check_lgpd_compliance(cookie),
            Regulation::POPIA => regulations::check_popia_compliance(cookie),
            Regulation::PIPEDA => regulations::check_pipeda_compliance(cookie),
            Regulation::PDPA => regulations::check_pdpa_compliance(cookie),
            Regulation::EPrivacy => regulations::check_eprivacy_compliance(cookie),
            Regulation::UKGDPR => regulations::check_ukgdpr_compliance(cookie),
            Regulation::CPRA => regulations::check_cpra_compliance(cookie),
            Regulation::PrivacyAct => regulations::check_privacy_act_compliance(cookie),
            Regulation::APPI => regulations::check_appi_compliance(cookie),
            Regulation::COPPA => regulations::check_coppa_compliance(cookie),
            Regulation::HIPAA => regulations::check_hipaa_compliance(cookie),
            Regulation::VCDPA => regulations::check_vcdpa_compliance(cookie),
            Regulation::CPA => regulations::check_cpa_compliance(cookie),
            Regulation::CTDPA => regulations::check_ctdpa_compliance(cookie),
            Regulation::UCPA => regulations::check_ucpa_compliance(cookie),
            // Regulations without specific implementations - use generic compliance check
            Regulation::PCIDSS
            | Regulation::PIPL
            | Regulation::PIPA
            | Regulation::THPDPA
            | Regulation::IDPDP
            | Regulation::PHDPA
            | Regulation::NZPA
            | Regulation::FADP => generic_compliance_check(cookie, regulation),
        }
    }

    /// Check compliance for multiple cookies
    #[must_use]
    pub fn check_batch(&self, cookies: &[Cookie]) -> Vec<ComplianceResult> {
        let mut results = Vec::new();

        for regulation in &self.regulations {
            let mut result = ComplianceResult {
                id: uuid::Uuid::new_v4().to_string(),
                regulation: *regulation,
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
                let cookie_result = self.check(cookie, *regulation);

                if cookie_result.compliant {
                    result.compliant_cookies += 1;
                } else {
                    result.non_compliant_cookies += 1;
                    result.compliant = false;
                }

                result.issues.extend(cookie_result.issues);
                result.warnings.extend(cookie_result.warnings);
                result.recommendations.extend(cookie_result.recommendations);
            }

            // Calculate score
            if !cookies.is_empty() {
                #[allow(clippy::cast_precision_loss)]
                let total = cookies.len() as f32;
                #[allow(clippy::cast_precision_loss)]
                let compliant_ratio = result.compliant_cookies as f32 / total;
                result.score = compliant_ratio * 100.0;
            }

            results.push(result);
        }

        results
    }

    /// Analyze consent mechanisms
    #[must_use]
    pub fn analyze_consent(&self, cookies: &[Cookie]) -> consent::ConsentAnalysis {
        consent::analyze_consent_mechanism(cookies)
    }

    /// Generate compliance recommendations
    #[must_use]
    pub fn generate_recommendations(&self, issues: &[ComplianceIssue]) -> Vec<String> {
        let mut recommendations = Vec::new();

        for issue in issues {
            match issue.issue.severity {
                Severity::Critical | Severity::High => {
                    recommendations.push(format!(
                        "URGENT: Fix {} violation: {}",
                        issue.regulation, issue.issue.description
                    ));
                }
                Severity::Medium => {
                    recommendations.push(format!(
                        "Recommended: Address {} issue: {}",
                        issue.regulation, issue.issue.description
                    ));
                }
                _ => {}
            }
        }

        recommendations
    }
}

/// Generic compliance check for regulations without specific implementations
fn generic_compliance_check(cookie: &Cookie, regulation: Regulation) -> ComplianceResult {
    let mut result = ComplianceResult {
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
    };

    // Basic security checks applicable to all regulations
    if !cookie.secure {
        result.warnings.push(format!(
            "Cookie lacks Secure flag - may not meet {regulation} security requirements"
        ));
    }

    if !cookie.http_only && is_session_like(cookie) {
        result.warnings.push(format!(
            "Session cookie lacks HttpOnly flag - may not meet {regulation} security requirements"
        ));
    }

    // Generic consent warning
    result.recommendations.push(format!(
        "Verify cookie compliance with {regulation} requirements"
    ));

    result
}

fn is_session_like(cookie: &Cookie) -> bool {
    let name_lower = cookie.name.to_lowercase();
    name_lower.contains("session") || name_lower.contains("auth") || name_lower.contains("token")
}

impl Default for ComplianceChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compliance_checker_creation() {
        let checker = ComplianceChecker::new();
        assert_eq!(checker.regulations.len(), 2);
        assert!(!checker.strict);
    }

    #[test]
    fn test_compliance_checker_with_regulations() {
        let regulations = vec![Regulation::GDPR, Regulation::CCPA, Regulation::LGPD];
        let checker = ComplianceChecker::with_regulations(regulations);
        assert_eq!(checker.regulations.len(), 3);
    }

    #[test]
    fn test_compliance_checker_strict() {
        let checker = ComplianceChecker::new().strict();
        assert!(checker.strict);
    }

    #[test]
    fn test_check_single_cookie() {
        let checker = ComplianceChecker::new();
        let cookie = Cookie::new("test".to_string(), "value".to_string());
        let result = checker.check(&cookie, Regulation::GDPR);

        assert!(!result.id.is_empty());
        assert_eq!(result.regulation, Regulation::GDPR);
    }

    #[test]
    fn test_check_batch() {
        let checker = ComplianceChecker::new();
        let cookies = vec![
            Cookie::new("test1".to_string(), "value1".to_string()),
            Cookie::new("test2".to_string(), "value2".to_string()),
        ];
        let results = checker.check_batch(&cookies);

        assert!(!results.is_empty());
        assert_eq!(results.len(), 2); // GDPR and CCPA
    }

    #[test]
    fn test_generic_compliance_check() {
        let cookie = Cookie::new("test".to_string(), "value".to_string());
        let result = generic_compliance_check(&cookie, Regulation::PIPL);

        assert!(result.compliant);
        assert!(!result.warnings.is_empty());
    }
}
