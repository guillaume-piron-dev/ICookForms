//! Google Consent Mode V2 & Additional Consent Module
//!
//! This module provides comprehensive support for Google Consent Mode V2 and
//! Additional Consent (AC) String parsing, validation, and compliance checking.
//!
//! # Overview
//!
//! Google Consent Mode V2 is mandatory for EEA/UK as of March 2024. This module
//! implements:
//!
//! - **Consent Mode V2**: Parse and encode `gcd` parameters with 4 mandatory signals
//! - **Additional Consent**: Parse and validate AC Strings (v1 and v2)
//! - **ATP List Management**: Fetch and validate against official Google ATP List
//! - **Detection**: Identify consent signals in cookies, URLs, and HTTP requests
//! - **Validation**: Comprehensive compliance checking for GDPR and Google requirements
//!
//! # Features
//!
//! ## Consent Mode V2
//!
//! Handles the 4 mandatory consent parameters:
//! - `ad_storage`: Storage of advertising cookies
//! - `analytics_storage`: Storage of analytics cookies
//! - `ad_user_data`: Sending user data to Google for ads (NEW in v2)
//! - `ad_personalization`: Ad personalization (NEW in v2)
//!
//! ## Additional Consent (AC String)
//!
//! Manages Google Ad Tech Provider (ATP) consent:
//! - Parse AC String v1 (legacy) and v2 (current)
//! - Validate ATP IDs against official Google list
//! - Track consented and disclosed ATPs separately
//!
//! ## Detection
//!
//! Detects consent signals from:
//! - HTTP cookies (`addtl_consent`, CMP cookies, Google cookies)
//! - URL parameters (`gcd`, `gcs`, `addtl_consent`)
//! - Combined HTTP requests (cookies + URL)
//!
//! ## Validation
//!
//! Comprehensive compliance checking:
//! - Consent presence validation
//! - Google cookies vs consent alignment
//! - AC String version and ATP ID validation
//! - Compliance scoring and recommendations
//!
//! # Quick Start
//!
//! ```
//! use icookforms::compliance::google_consent::{
//!     parse_gcd_parameter,
//!     parse_ac_string,
//!     detect_google_consent_cookies,
//!     validate_google_consent,
//! };
//! use icookforms::types::Cookie;
//!
//! // Parse Consent Mode V2 from URL parameter
//! let consent = parse_gcd_parameter("11l1m1n1p5").unwrap();
//! println!("Ad storage: {:?}", consent.ad_storage);
//!
//! // Parse Additional Consent String
//! let ac = parse_ac_string("2~1.35.41~dv.9.21").unwrap();
//! println!("Consented ATPs: {:?}", ac.consented_atps);
//!
//! // Detect consent in cookies
//! let cookies = vec![
//!     Cookie::new("addtl_consent".to_string(), "2~1.35".to_string()),
//!     Cookie::new("_ga".to_string(), "GA1.2.123456.789".to_string()),
//! ];
//! let analysis = detect_google_consent_cookies(&cookies);
//!
//! // Validate compliance
//! let report = validate_google_consent(&analysis);
//! println!("Compliant: {}", report.is_compliant);
//! ```
//!
//! # Examples
//!
//! ## Example 1: Parse Consent Mode V2
//!
//! ```
//! # use icookforms::compliance::google_consent::{parse_gcd_parameter, ConsentState};
//! let gcd = "11l1m1n1p5";
//! let consent = parse_gcd_parameter(gcd).unwrap();
//!
//! assert_eq!(consent.ad_storage, ConsentState::GrantedDefault);
//! assert_eq!(consent.analytics_storage, ConsentState::GrantedUpdate);
//! assert_eq!(consent.ad_user_data, ConsentState::DeniedDefault);
//! assert_eq!(consent.ad_personalization, ConsentState::DeniedUpdate);
//! ```
//!
//! ## Example 2: Parse Additional Consent String
//!
//! ```
//! # use icookforms::compliance::google_consent::parse_ac_string;
//! let ac_string = "2~1.35.41.101~dv.9.21.81";
//! let ac = parse_ac_string(ac_string).unwrap();
//!
//! assert_eq!(ac.version, 2);
//! assert_eq!(ac.consented_atps, vec![1, 35, 41, 101]);
//! assert_eq!(ac.disclosed_atps, vec![9, 21, 81]);
//! assert!(ac.has_consent(35));
//! assert!(ac.is_disclosed(81));
//! ```
//!
//! ## Example 3: Detect Consent in Cookies
//!
//! ```
//! # use icookforms::compliance::google_consent::detect_google_consent_cookies;
//! # use icookforms::types::Cookie;
//! let cookies = vec![
//!     Cookie::new("addtl_consent".to_string(), "2~1.35".to_string()),
//!     Cookie::new("_ga".to_string(), "GA1.2.123456.789".to_string()),
//!     Cookie::new("_gcl_au".to_string(), "1.1234567890.1234567890".to_string()),
//! ];
//!
//! let analysis = detect_google_consent_cookies(&cookies);
//!
//! assert!(analysis.ac_string.is_some());
//! assert!(analysis.has_analytics_cookies);
//! assert!(analysis.has_ads_cookies);
//! assert_eq!(analysis.detected_products().len(), 2);
//! ```
//!
//! ## Example 4: Validate Compliance
//!
//! ```
//! # use icookforms::compliance::google_consent::{GoogleConsentAnalysis, validate_google_consent};
//! let mut analysis = GoogleConsentAnalysis::new();
//! analysis.has_analytics_cookies = true;
//! // No consent cookie or consent mode
//!
//! let report = validate_google_consent(&analysis);
//!
//! assert!(!report.is_compliant);
//! assert!(!report.issues.is_empty());
//! assert!(!report.recommendations.is_empty());
//! println!("Score: {}/100", report.score);
//! ```
//!
//! ## Example 5: Fetch ATP List (requires 'scanner' feature)
//!
//! ```no_run
//! # use icookforms::compliance::google_consent::GoogleATPList;
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let atp_list = GoogleATPList::fetch().await?;
//!
//! if let Some(provider) = atp_list.get_provider(35) {
//!     println!("Provider 35: {}", provider.name);
//! }
//!
//! let index = atp_list.create_index();
//! # Ok(())
//! # }
//! ```
//!
//! # Module Structure
//!
//! - [`mode_v2`]: Consent Mode V2 implementation (gcd/gcs parameters)
//! - [`additional_consent`]: Additional Consent String (AC String) implementation
//! - [`atp_list`]: Google Ad Tech Provider List management
//! - [`detection`]: Consent signal detection from cookies and URLs
//! - [`validation`]: Compliance validation and reporting
//!
//! # Standards Compliance
//!
//! This module implements:
//! - Google Consent Mode V2 (March 2024 specification)
//! - Additional Consent Specification v2 (December 2023)
//! - GDPR requirements for consent management
//! - ePrivacy Directive cookie consent requirements
//!
//! # Feature Flags
//!
//! - `scanner`: Enables ATP List fetching from Google's servers (requires `reqwest`)

// Module declarations
pub mod additional_consent;
pub mod atp_list;
pub mod detection;
pub mod mode_v2;
pub mod validation;

// Re-export main types from mode_v2
pub use mode_v2::{
    encode_gcd_parameter, parse_gcd_parameter, parse_gcs_parameter, ConsentModeV2, ConsentState,
    GcdError, GcsError,
};

// Re-export main types from additional_consent
pub use additional_consent::{
    encode_ac_string, parse_ac_string, validate_ac_string_atps, ACError, ACString,
};

// Re-export main types from atp_list
pub use atp_list::{ATPError, AdTechProvider, GoogleATPList};

// Re-export main types from detection
pub use detection::{
    detect_google_consent_cookies, detect_google_consent_in_url, detect_in_http_request,
    extract_ga_ids, extract_gtm_containers, ConsentSource, GoogleConsentAnalysis,
    GoogleConsentData,
};

// Re-export main types from validation
pub use validation::{
    generate_compliance_summary, validate_ac_string_with_atp_list, validate_consent_mode_v2,
    validate_google_consent, ConsentComplianceReport, ConsentIssue, ConsentWarning, SeverityLevel,
};

/// Module version
pub const VERSION: &str = "1.0.0";

/// Supported Consent Mode versions
pub const SUPPORTED_CONSENT_MODES: &[&str] = &["v1", "v2"];

/// Supported AC String versions
pub const SUPPORTED_AC_VERSIONS: &[u8] = &[1, 2];

/// Official Google ATP List URL
pub const GOOGLE_ATP_LIST_URL: &str = "https://storage.googleapis.com/gac/google-atp-list.json";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Cookie;

    // ========================================================================
    // Integration Tests
    // ========================================================================

    #[test]
    fn test_full_consent_mode_v2_workflow() {
        // Parse gcd parameter
        let gcd = "11l1m1n1p5";
        let consent = parse_gcd_parameter(gcd).unwrap();

        assert_eq!(consent.ad_storage, ConsentState::GrantedDefault);
        assert_eq!(consent.analytics_storage, ConsentState::GrantedUpdate);

        // Encode back
        let encoded = encode_gcd_parameter(&consent);
        assert_eq!(encoded, gcd);

        // Validate
        let report = validate_consent_mode_v2(&consent);
        assert!(report.is_compliant);
    }

    #[test]
    fn test_full_ac_string_workflow() {
        // Parse AC String
        let ac_string = "2~1.35.41.101~dv.9.21.81";
        let ac = parse_ac_string(ac_string).unwrap();

        assert_eq!(ac.version, 2);
        assert_eq!(ac.consented_atps, vec![1, 35, 41, 101]);
        assert_eq!(ac.disclosed_atps, vec![9, 21, 81]);

        // Test methods
        assert!(ac.has_consent(35));
        assert!(ac.is_disclosed(81));
        assert!(!ac.has_consent(999));

        // Encode back
        let encoded = encode_ac_string(&ac);
        assert_eq!(encoded, ac_string);

        // Test ATP list validation
        let atp_list = GoogleATPList::with_providers(vec![
            AdTechProvider::new(1, "Test1".to_string(), vec![]),
            AdTechProvider::new(35, "Test35".to_string(), vec![]),
            AdTechProvider::new(41, "Test41".to_string(), vec![]),
            AdTechProvider::new(101, "Test101".to_string(), vec![]),
            AdTechProvider::new(9, "Test9".to_string(), vec![]),
            AdTechProvider::new(21, "Test21".to_string(), vec![]),
            AdTechProvider::new(81, "Test81".to_string(), vec![]),
        ]);

        let report = validate_ac_string_with_atp_list(&ac, &atp_list);
        assert!(report.is_compliant);
    }

    #[test]
    fn test_full_detection_workflow() {
        // Create test cookies with proper consent mechanism
        let cookies = vec![
            Cookie::new("addtl_consent".to_string(), "2~1.35.41~dv.9.21".to_string()),
            Cookie::new("CookieConsent".to_string(), "accepted".to_string()), // CMP consent cookie
            Cookie::new("_ga".to_string(), "GA1.2.123456.789".to_string()),
            Cookie::new("_gid".to_string(), "GA1.2.987654.321".to_string()),
            Cookie::new("_gcl_au".to_string(), "1.1234567890.1234567890".to_string()),
        ];

        // Detect consent signals
        let analysis = detect_google_consent_cookies(&cookies);

        assert!(analysis.ac_string.is_some());
        assert!(analysis.consent_cookie.is_some());
        assert!(analysis.has_analytics_cookies);
        assert!(analysis.has_ads_cookies);
        assert_eq!(analysis.detected_products().len(), 2);

        // Validate
        let report = validate_google_consent(&analysis);

        // Should be compliant since we have consent cookie and AC String
        assert!(report.is_compliant);
        assert!(report.score > 80.0);
    }

    #[test]
    fn test_full_url_detection_workflow() {
        let url = "https://example.com?gcd=11l1m1n1p5&addtl_consent=2~1.35&utm_source=google";

        let data = detect_google_consent_in_url(url).unwrap();

        assert!(data.consent_mode_v2.is_some());
        assert!(data.ac_string.is_some());

        let consent = data.consent_mode_v2.unwrap();
        assert!(consent.ad_storage.is_granted());

        let ac = data.ac_string.unwrap();
        assert_eq!(ac.version, 2);
        assert!(ac.has_consent(1));
    }

    #[test]
    fn test_full_validation_workflow() {
        // Scenario: Google cookies without consent
        let mut analysis = GoogleConsentAnalysis::new();
        analysis.has_analytics_cookies = true;
        analysis.has_ads_cookies = true;
        // No consent data

        let report = validate_google_consent(&analysis);

        assert!(!report.is_compliant);
        assert!(!report.issues.is_empty());
        assert!(!report.recommendations.is_empty());
        assert!(report.score < 100.0);

        // Generate summary
        let summary = generate_compliance_summary(&report);
        assert!(summary.contains("NON-COMPLIANT"));
        assert!(summary.contains("Critical Issues"));

        // Now add consent
        analysis.consent_mode_v2 = Some(ConsentModeV2::new_granted());
        analysis.ac_string = Some(ACString::with_atps(vec![1, 35], vec![]));

        let report2 = validate_google_consent(&analysis);
        assert!(report2.is_compliant);
        assert!(report2.score > 80.0);
    }
}
