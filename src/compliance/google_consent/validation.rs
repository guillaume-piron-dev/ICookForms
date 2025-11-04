//! Google Consent Validation Module
//!
//! This module validates Google Consent Mode V2 and Additional Consent configurations
//! for compliance with GDPR, ePrivacy Directive, and Google's best practices.
//!
//! # Overview
//!
//! The validation module provides comprehensive compliance checking including:
//! - Consent presence validation
//! - Google cookies without consent detection
//! - AC String version validation
//! - ATP ID validation against official list
//! - Consent Mode V2 completeness checks
//!
//! # Validation Rules
//!
//! ## Critical Issues (Non-Compliant)
//! - Google cookies present without any consent mechanism
//! - Invalid AC String format
//! - Missing required consents for detected cookies
//! - Unknown ATP IDs (not in official Google list)
//!
//! ## Warnings (Should be addressed)
//! - Obsolete AC String v1 (should upgrade to v2)
//! - No disclosed vendors in AC String v2
//! - Partial consent (some parameters granted, others denied)
//! - Legacy gcs parameter (v1) usage
//!
//! # Examples
//!
//! ```
//! # use icookforms::compliance::google_consent::{GoogleConsentAnalysis, validate_google_consent};
//! let mut analysis = GoogleConsentAnalysis::new();
//! analysis.has_analytics_cookies = true;
//! // No consent cookie
//!
//! let report = validate_google_consent(&analysis);
//! assert!(!report.is_compliant);
//! assert!(!report.issues.is_empty());
//! ```

use std::fmt::Write;

use super::{ACString, ConsentModeV2, GoogleATPList, GoogleConsentAnalysis};
use std::collections::HashSet;

/// Consent compliance report
///
/// Contains the results of a comprehensive Google Consent validation,
/// including compliance status, issues, warnings, and recommendations.
#[derive(Debug, Clone)]
pub struct ConsentComplianceReport {
    /// Overall compliance status
    pub is_compliant: bool,

    /// Compliance score (0-100)
    pub score: f32,

    /// Critical issues that make the configuration non-compliant
    pub issues: Vec<ConsentIssue>,

    /// Warnings about potential problems or best practices
    pub warnings: Vec<ConsentWarning>,

    /// Recommendations for improving compliance
    pub recommendations: Vec<String>,

    /// Summary of detected Google products
    pub detected_products: Vec<String>,
}

/// Critical consent issues
///
/// These issues indicate non-compliance with GDPR or Google's requirements.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsentIssue {
    /// No cookie consent mechanism found
    NoCookieConsentFound,

    /// Google cookies are set without user consent
    GoogleCookiesWithoutConsent(Vec<String>),

    /// Invalid AC String format
    InvalidACString(String),

    /// Missing required consents for detected Google products
    MissingRequiredConsents(Vec<String>),

    /// Unknown ATP ID in AC String (not in official Google list)
    UnknownAtpId(u16),

    /// Consent Mode V2 parameters missing or incomplete
    IncompleteConsentModeV2,
}

/// Consent warnings
///
/// These indicate areas that should be improved but don't necessarily
/// violate compliance requirements.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsentWarning {
    /// AC String v1 is obsolete (should upgrade to v2)
    ObsoleteACStringVersion,

    /// No disclosed vendors in AC String v2
    NoDisclosedVendors,

    /// Google Analytics cookies detected
    AnalyticsCookiesFound,

    /// Google Ads cookies detected
    AdsCookiesFound,

    /// `DoubleClick` cookies detected
    DoubleClickCookiesFound,

    /// `YouTube` cookies detected
    YouTubeCookiesFound,

    /// Partial consent (mixed granted/denied)
    PartialConsent,

    /// Legacy gcs parameter (v1) in use
    LegacyGcsParameter,

    /// Multiple consent sources (potential conflict)
    MultipleConsentSources,

    /// Consent Mode V2 parameters missing or incomplete
    IncompleteConsentModeV2,
}

impl ConsentComplianceReport {
    /// Creates a new compliant report (starting point)
    #[must_use]
    pub fn new_compliant() -> Self {
        Self {
            is_compliant: true,
            score: 100.0,
            issues: Vec::new(),
            warnings: Vec::new(),
            recommendations: Vec::new(),
            detected_products: Vec::new(),
        }
    }

    /// Adds a critical issue to the report
    pub fn add_issue(&mut self, issue: ConsentIssue) {
        self.is_compliant = false;
        self.issues.push(issue);
        self.recalculate_score();
    }

    /// Adds a warning to the report
    pub fn add_warning(&mut self, warning: ConsentWarning) {
        self.warnings.push(warning);
        self.recalculate_score();
    }

    /// Adds a recommendation
    pub fn add_recommendation(&mut self, recommendation: String) {
        self.recommendations.push(recommendation);
    }

    /// Recalculates the compliance score
    ///
    /// Score calculation:
    /// - Start at 100
    /// - Each critical issue: -20 points
    /// - Each warning: -5 points
    /// - Minimum: 0
    fn recalculate_score(&mut self) {
        let mut score = 100.0;

        // Critical issues have high impact
        #[allow(clippy::cast_precision_loss)]
        let issue_impact = self.issues.len() as f32 * 20.0;
        score -= issue_impact;

        // Warnings have lower impact
        #[allow(clippy::cast_precision_loss)]
        let warning_impact = self.warnings.len() as f32 * 5.0;
        score -= warning_impact;

        // Clamp to [0, 100]
        self.score = score.clamp(0.0, 100.0);
    }

    /// Checks if the configuration is fully compliant (no issues)
    #[must_use]
    pub fn is_fully_compliant(&self) -> bool {
        self.is_compliant && self.warnings.is_empty()
    }

    /// Gets the severity level based on score
    #[must_use]
    pub fn severity_level(&self) -> SeverityLevel {
        if self.score >= 90.0 {
            SeverityLevel::Low
        } else if self.score >= 70.0 {
            SeverityLevel::Medium
        } else if self.score >= 50.0 {
            SeverityLevel::High
        } else {
            SeverityLevel::Critical
        }
    }
}

/// Severity level for compliance report
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeverityLevel {
    /// Minor issues only (score >= 90)
    Low,

    /// Some concerns (score 70-89)
    Medium,

    /// Significant problems (score 50-69)
    High,

    /// Critical compliance violations (score < 50)
    Critical,
}

/// Validates Google Consent configuration
///
/// Performs comprehensive validation of consent signals including:
/// - Consent presence check
/// - Google cookies vs consent alignment
/// - AC String validation
/// - Consent Mode V2 validation
///
/// # Arguments
/// * `analysis` - Google consent analysis results
///
/// # Returns
/// `ConsentComplianceReport` with validation results
///
/// # Examples
/// ```
/// # use icookforms::compliance::google_consent::{GoogleConsentAnalysis, validate_google_consent};
/// let mut analysis = GoogleConsentAnalysis::new();
/// analysis.has_analytics_cookies = true;
/// // No consent cookie
///
/// let report = validate_google_consent(&analysis);
/// assert!(!report.is_compliant);
/// ```
#[must_use]
pub fn validate_google_consent(analysis: &GoogleConsentAnalysis) -> ConsentComplianceReport {
    let mut report = ConsentComplianceReport::new_compliant();

    // Get detected products
    report.detected_products = analysis.detected_products();

    // Check 1: Google cookies without consent
    if analysis.has_google_cookies() && !analysis.has_consent_data() {
        report.add_issue(ConsentIssue::NoCookieConsentFound);
        report.add_recommendation(
            "Implement a consent management platform (CMP) to collect user consent before setting Google cookies.".to_string()
        );
    }

    // Check 2: Specific product cookies without matching consent
    if analysis.has_analytics_cookies {
        report.add_warning(ConsentWarning::AnalyticsCookiesFound);

        if let Some(ref consent) = analysis.consent_mode_v2 {
            if !consent.analytics_storage.is_granted() {
                report.add_issue(ConsentIssue::MissingRequiredConsents(vec![
                    "Google Analytics".to_string(),
                ]));
            }
        } else if analysis.consent_cookie.is_none() {
            report.add_issue(ConsentIssue::GoogleCookiesWithoutConsent(vec![
                "_ga".to_string(),
                "_gid".to_string(),
            ]));
        }
    }

    if analysis.has_ads_cookies {
        report.add_warning(ConsentWarning::AdsCookiesFound);

        if let Some(ref consent) = analysis.consent_mode_v2 {
            if !consent.ad_storage.is_granted() {
                report.add_issue(ConsentIssue::MissingRequiredConsents(vec![
                    "Google Ads".to_string()
                ]));
            }
        } else if analysis.consent_cookie.is_none() {
            report.add_issue(ConsentIssue::GoogleCookiesWithoutConsent(vec![
                "_gcl_au".to_string(),
                "_gcl_aw".to_string(),
            ]));
        }
    }

    if analysis.has_doubleclick_cookies {
        report.add_warning(ConsentWarning::DoubleClickCookiesFound);
    }

    if analysis.has_youtube_cookies {
        report.add_warning(ConsentWarning::YouTubeCookiesFound);
    }

    // Check 3: AC String validation
    if let Some(ref ac) = analysis.ac_string {
        // Obsolete version
        if ac.is_legacy() {
            report.add_warning(ConsentWarning::ObsoleteACStringVersion);
            report.add_recommendation(
                "Upgrade AC String to version 2 for full transparency compliance.".to_string(),
            );
        }

        // No disclosed vendors in v2
        if ac.version == 2 && ac.disclosed_atps.is_empty() && !ac.consented_atps.is_empty() {
            report.add_warning(ConsentWarning::NoDisclosedVendors);
            report.add_recommendation(
                "Include disclosed vendors in AC String v2 for full transparency.".to_string(),
            );
        }
    }

    // Check 4: Consent Mode V2 validation
    if let Some(ref consent) = analysis.consent_mode_v2 {
        // Check for partial consent
        if !consent.is_fully_granted() && consent.is_partially_granted() {
            report.add_warning(ConsentWarning::PartialConsent);
        }

        // Recommend full consent mode v2 implementation
        if analysis.has_google_cookies() {
            report.add_recommendation(
                "Ensure all 4 Consent Mode V2 parameters are properly configured: ad_storage, analytics_storage, ad_user_data, ad_personalization.".to_string()
            );
        }
    } else if analysis.has_google_cookies() {
        // Google cookies but no Consent Mode V2
        report.add_warning(ConsentWarning::IncompleteConsentModeV2);
        report.add_recommendation(
            "Implement Google Consent Mode V2 for better compliance and data quality.".to_string(),
        );
    }

    // Check 5: Legacy gcs parameter
    if analysis.gcs_value.is_some() {
        report.add_warning(ConsentWarning::LegacyGcsParameter);
        report.add_recommendation(
            "Migrate from legacy gcs parameter to gcd (Consent Mode V2).".to_string(),
        );
    }

    // Check 6: Multiple consent sources
    if let super::ConsentSource::Both = analysis.consent_source {
        report.add_warning(ConsentWarning::MultipleConsentSources);
    }

    report
}

/// Validates AC String against the official Google ATP List
///
/// Checks if all ATP IDs in the AC String are present in the official
/// Google Ad Tech Provider list.
///
/// # Arguments
/// * `ac` - AC String to validate
/// * `atp_list` - Official Google ATP List
///
/// # Returns
/// `ConsentComplianceReport` with ATP validation results
///
/// # Examples
/// ```
/// # use icookforms::compliance::google_consent::{ACString, GoogleATPList, validate_ac_string_with_atp_list};
/// let ac = ACString::with_atps(vec![1, 35, 41], vec![]);
/// let atp_list = GoogleATPList::new(); // Empty for example
///
/// let report = validate_ac_string_with_atp_list(&ac, &atp_list);
/// // Will have issues for unknown ATP IDs
/// ```
#[must_use]
pub fn validate_ac_string_with_atp_list(
    ac: &ACString,
    atp_list: &GoogleATPList,
) -> ConsentComplianceReport {
    let mut report = ConsentComplianceReport::new_compliant();

    let valid_ids: HashSet<u16> = atp_list.all_ids().into_iter().collect();

    // Check consented ATPs
    for &atp_id in &ac.consented_atps {
        if !valid_ids.contains(&atp_id) {
            report.add_issue(ConsentIssue::UnknownAtpId(atp_id));
        }
    }

    // Check disclosed ATPs
    for &atp_id in &ac.disclosed_atps {
        if !valid_ids.contains(&atp_id) {
            report.add_issue(ConsentIssue::UnknownAtpId(atp_id));
        }
    }

    if !report.is_compliant {
        report.add_recommendation(
            "Ensure all ATP IDs in the AC String are valid according to the official Google ATP List.".to_string()
        );
    }

    report
}

/// Validates Consent Mode V2 configuration
///
/// Checks for completeness and best practices in Consent Mode V2 setup.
///
/// # Arguments
/// * `consent` - Consent Mode V2 configuration
///
/// # Returns
/// `ConsentComplianceReport` with validation results
#[must_use]
pub fn validate_consent_mode_v2(consent: &ConsentModeV2) -> ConsentComplianceReport {
    let mut report = ConsentComplianceReport::new_compliant();

    // Check for partial consent
    if !consent.is_fully_granted() && consent.is_partially_granted() {
        report.add_warning(ConsentWarning::PartialConsent);
        report.add_recommendation(
            "Partial consent detected. Ensure your implementation respects user choices."
                .to_string(),
        );
    }

    // Check for user action vs default
    let has_user_action = consent.ad_storage.is_user_action()
        || consent.analytics_storage.is_user_action()
        || consent.ad_user_data.is_user_action()
        || consent.ad_personalization.is_user_action();

    if !has_user_action {
        report.add_warning(ConsentWarning::PartialConsent);
        report.add_recommendation(
            "All consent states are set to default. Wait for user interaction before setting defaults.".to_string()
        );
    }

    report
}

/// Generates a detailed compliance summary
///
/// # Arguments
/// * `report` - Compliance report to summarize
///
/// # Returns
/// Human-readable compliance summary
#[must_use]
pub fn generate_compliance_summary(report: &ConsentComplianceReport) -> String {
    let mut summary = String::new();

    writeln!(
        summary,
        "Compliance Status: {}",
        if report.is_compliant {
            "✓ COMPLIANT"
        } else {
            "✗ NON-COMPLIANT"
        }
    )
    .unwrap();

    writeln!(summary, "Compliance Score: {:.1}/100", report.score).unwrap();
    writeln!(summary, "Severity: {:?}\n", report.severity_level()).unwrap();

    if !report.detected_products.is_empty() {
        summary.push_str("Detected Google Products:\n");
        for product in &report.detected_products {
            writeln!(summary, "  - {product}").unwrap();
        }
        summary.push('\n');
    }

    if !report.issues.is_empty() {
        writeln!(summary, "Critical Issues ({}):", report.issues.len()).unwrap();
        for issue in &report.issues {
            writeln!(summary, "  ✗ {issue:?}").unwrap();
        }
        summary.push('\n');
    }

    if !report.warnings.is_empty() {
        writeln!(summary, "Warnings ({}):", report.warnings.len()).unwrap();
        for warning in &report.warnings {
            writeln!(summary, "  ⚠ {warning:?}").unwrap();
        }
        summary.push('\n');
    }

    if !report.recommendations.is_empty() {
        summary.push_str("Recommendations:\n");
        for (i, rec) in report.recommendations.iter().enumerate() {
            writeln!(summary, "  {}. {}", i + 1, rec).unwrap();
        }
    }

    summary
}

#[cfg(test)]
mod tests {
    use super::super::{ConsentState, GoogleConsentAnalysis};
    use super::*;

    // ========================================================================
    // ConsentComplianceReport Tests
    // ========================================================================

    #[test]
    fn test_new_compliant_report() {
        let report = ConsentComplianceReport::new_compliant();
        assert!(report.is_compliant);
        assert!((report.score - 100.0).abs() < f32::EPSILON);
        assert!(report.issues.is_empty());
        assert!(report.warnings.is_empty());
    }

    #[test]
    fn test_add_issue() {
        let mut report = ConsentComplianceReport::new_compliant();
        report.add_issue(ConsentIssue::NoCookieConsentFound);

        assert!(!report.is_compliant);
        assert_eq!(report.issues.len(), 1);
        assert!((report.score - 80.0).abs() < f32::EPSILON); // 100 - 20
    }

    #[test]
    fn test_add_warning() {
        let mut report = ConsentComplianceReport::new_compliant();
        report.add_warning(ConsentWarning::ObsoleteACStringVersion);

        assert!(report.is_compliant); // Still compliant
        assert_eq!(report.warnings.len(), 1);
        assert!((report.score - 95.0).abs() < f32::EPSILON); // 100 - 5
    }

    #[test]
    fn test_score_calculation() {
        let mut report = ConsentComplianceReport::new_compliant();

        // 2 issues + 3 warnings
        report.add_issue(ConsentIssue::NoCookieConsentFound);
        report.add_issue(ConsentIssue::InvalidACString("test".to_string()));
        report.add_warning(ConsentWarning::ObsoleteACStringVersion);
        report.add_warning(ConsentWarning::PartialConsent);
        report.add_warning(ConsentWarning::LegacyGcsParameter);

        // 100 - (2 * 20) - (3 * 5) = 45
        assert!((report.score - 45.0).abs() < f32::EPSILON);
    }

    #[test]
    fn test_severity_level() {
        let mut report = ConsentComplianceReport::new_compliant();
        assert_eq!(report.severity_level(), SeverityLevel::Low);

        report.add_warning(ConsentWarning::PartialConsent);
        report.add_warning(ConsentWarning::PartialConsent);
        assert_eq!(report.severity_level(), SeverityLevel::Low); // 90

        report.add_issue(ConsentIssue::NoCookieConsentFound);
        assert_eq!(report.severity_level(), SeverityLevel::Medium); // 70

        report.add_issue(ConsentIssue::InvalidACString("test".to_string()));
        assert_eq!(report.severity_level(), SeverityLevel::High); // 50

        report.add_issue(ConsentIssue::IncompleteConsentModeV2);
        assert_eq!(report.severity_level(), SeverityLevel::Critical); // 30
    }

    // ========================================================================
    // validate_google_consent Tests
    // ========================================================================

    #[test]
    fn test_validate_no_cookies() {
        let analysis = GoogleConsentAnalysis::new();
        let report = validate_google_consent(&analysis);

        assert!(report.is_compliant);
        assert!(report.issues.is_empty());
    }

    #[test]
    fn test_validate_cookies_without_consent() {
        let mut analysis = GoogleConsentAnalysis::new();
        analysis.has_analytics_cookies = true;

        let report = validate_google_consent(&analysis);

        assert!(!report.is_compliant);
        assert!(!report.issues.is_empty());
    }

    #[test]
    fn test_validate_cookies_with_consent() {
        let mut analysis = GoogleConsentAnalysis::new();
        analysis.has_analytics_cookies = true;
        analysis.consent_mode_v2 = Some(ConsentModeV2::new_granted());

        let report = validate_google_consent(&analysis);

        // Should have warnings but be compliant
        assert!(report.is_compliant);
    }

    #[test]
    fn test_validate_obsolete_ac_string() {
        let mut analysis = GoogleConsentAnalysis::new();
        let mut ac = ACString::new();
        ac.version = 1;
        analysis.ac_string = Some(ac);

        let report = validate_google_consent(&analysis);

        assert!(report
            .warnings
            .contains(&ConsentWarning::ObsoleteACStringVersion));
    }

    #[test]
    fn test_validate_legacy_gcs() {
        let mut analysis = GoogleConsentAnalysis::new();
        analysis.gcs_value = Some("G111".to_string());

        let report = validate_google_consent(&analysis);

        assert!(report
            .warnings
            .contains(&ConsentWarning::LegacyGcsParameter));
    }

    // ========================================================================
    // validate_ac_string_with_atp_list Tests
    // ========================================================================

    #[test]
    fn test_validate_ac_string_valid_atps() {
        let ac = ACString::with_atps(vec![1, 35], vec![41]);
        let atp_list = GoogleATPList::with_providers(vec![
            super::super::AdTechProvider::new(1, "Test1".to_string(), vec![]),
            super::super::AdTechProvider::new(35, "Test35".to_string(), vec![]),
            super::super::AdTechProvider::new(41, "Test41".to_string(), vec![]),
        ]);

        let report = validate_ac_string_with_atp_list(&ac, &atp_list);

        assert!(report.is_compliant);
        assert!(report.issues.is_empty());
    }

    #[test]
    fn test_validate_ac_string_unknown_atps() {
        let ac = ACString::with_atps(vec![1, 999], vec![]);
        let atp_list = GoogleATPList::with_providers(vec![super::super::AdTechProvider::new(
            1,
            "Test1".to_string(),
            vec![],
        )]);

        let report = validate_ac_string_with_atp_list(&ac, &atp_list);

        assert!(!report.is_compliant);
        assert!(report
            .issues
            .iter()
            .any(|i| matches!(i, ConsentIssue::UnknownAtpId(999))));
    }

    // ========================================================================
    // validate_consent_mode_v2 Tests
    // ========================================================================

    #[test]
    fn test_validate_consent_mode_fully_granted() {
        let consent = ConsentModeV2::new_granted();
        let report = validate_consent_mode_v2(&consent);

        assert!(report.is_compliant);
    }

    #[test]
    fn test_validate_consent_mode_partial() {
        let mut consent = ConsentModeV2::new_granted();
        consent.ad_storage = ConsentState::DeniedUpdate;

        let report = validate_consent_mode_v2(&consent);

        assert!(report.warnings.contains(&ConsentWarning::PartialConsent));
    }

    // ========================================================================
    // generate_compliance_summary Tests
    // ========================================================================

    #[test]
    fn test_generate_summary() {
        let mut report = ConsentComplianceReport::new_compliant();
        report.add_issue(ConsentIssue::NoCookieConsentFound);
        report.add_warning(ConsentWarning::PartialConsent);
        report.add_recommendation("Test recommendation".to_string());

        let summary = generate_compliance_summary(&report);

        assert!(summary.contains("NON-COMPLIANT"));
        assert!(summary.contains("Critical Issues"));
        assert!(summary.contains("Warnings"));
        assert!(summary.contains("Recommendations"));
    }
}
