//! Cookie consent mechanism analysis
//!
//! This module analyzes cookie consent mechanisms to determine compliance
//! with various regulations requiring informed consent.

use crate::types::Cookie;
use serde::{Deserialize, Serialize};

/// Analysis of cookie consent mechanism
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct ConsentAnalysis {
    /// Whether a consent banner/notice was detected
    pub banner_present: bool,

    /// Consent mechanism type
    pub mechanism_type: ConsentMechanism,

    /// Whether consent is opt-in (explicit) or opt-out
    pub opt_in_required: bool,

    /// Whether an opt-out option is available
    pub opt_out_available: bool,

    /// Whether granular consent control is provided (per category)
    pub granular_control: bool,

    /// Whether consent can be withdrawn easily
    pub withdrawal_easy: bool,

    /// Whether consent is logged/recorded
    pub consent_logged: bool,

    /// Cookie categories detected
    pub cookie_categories: CookieCategories,

    /// Issues detected with consent mechanism
    pub issues: Vec<String>,

    /// Recommendations for improvement
    pub recommendations: Vec<String>,

    /// Compliance score (0-100)
    pub compliance_score: f32,
}

/// Type of consent mechanism
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsentMechanism {
    /// No consent mechanism detected
    None,

    /// Implied consent (cookies set without explicit consent)
    Implied,

    /// Opt-out only (cookies set by default, user can opt-out)
    OptOut,

    /// Opt-in (explicit consent required before setting cookies)
    OptIn,

    /// Granular opt-in (consent requested per category)
    GranularOptIn,
}

/// Cookie categories for consent management
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CookieCategories {
    /// Strictly necessary/essential cookies
    pub strictly_necessary: Vec<String>,

    /// Functional/preference cookies
    pub functional: Vec<String>,

    /// Performance/analytics cookies
    pub performance: Vec<String>,

    /// Targeting/advertising cookies
    pub targeting: Vec<String>,

    /// Uncategorized cookies
    pub uncategorized: Vec<String>,
}

/// Analyze consent mechanism based on cookies
#[must_use]
pub fn analyze_consent_mechanism(cookies: &[Cookie]) -> ConsentAnalysis {
    let mut analysis = ConsentAnalysis {
        banner_present: false, // Would need page content analysis
        mechanism_type: ConsentMechanism::None,
        opt_in_required: false,
        opt_out_available: false,
        granular_control: false,
        withdrawal_easy: false,
        consent_logged: false,
        cookie_categories: CookieCategories::default(),
        issues: Vec::new(),
        recommendations: Vec::new(),
        compliance_score: 0.0,
    };

    // Categorize cookies
    categorize_cookies(cookies, &mut analysis.cookie_categories);

    // Detect consent mechanism type
    analysis.mechanism_type = detect_consent_mechanism(cookies);

    // Check for consent cookie
    let has_consent_cookie = cookies.iter().any(is_consent_cookie);
    if has_consent_cookie {
        analysis.consent_logged = true;
        analysis.banner_present = true; // Likely has a banner
    }

    // Analyze based on mechanism type
    match analysis.mechanism_type {
        ConsentMechanism::None => {
            analysis
                .issues
                .push("No consent mechanism detected for non-essential cookies".to_string());
            analysis
                .recommendations
                .push("Implement cookie consent banner with opt-in mechanism".to_string());
        }
        ConsentMechanism::Implied => {
            analysis.issues.push(
                "Implied consent is not compliant with GDPR for non-essential cookies".to_string(),
            );
            analysis
                .recommendations
                .push("Switch to explicit opt-in consent mechanism".to_string());
        }
        ConsentMechanism::OptOut => {
            analysis.opt_out_available = true;
            analysis.issues.push(
                "Opt-out consent may not be sufficient for GDPR (requires opt-in)".to_string(),
            );
            analysis
                .recommendations
                .push("Implement opt-in consent for GDPR compliance".to_string());
        }
        ConsentMechanism::OptIn => {
            analysis.opt_in_required = true;
            analysis
                .recommendations
                .push("Consider implementing granular consent for better user control".to_string());
        }
        ConsentMechanism::GranularOptIn => {
            analysis.opt_in_required = true;
            analysis.granular_control = true;
        }
    }

    // Check for non-essential cookies without consent
    if (!analysis.cookie_categories.performance.is_empty()
        || !analysis.cookie_categories.targeting.is_empty())
        && !analysis.opt_in_required
    {
        analysis
            .issues
            .push("Non-essential cookies detected without opt-in consent requirement".to_string());
    }

    // Check for easy withdrawal
    if analysis.consent_logged {
        analysis.recommendations.push(
            "Ensure users can easily withdraw consent (e.g., settings page, banner recall)"
                .to_string(),
        );
    }

    // Calculate compliance score
    analysis.compliance_score = calculate_consent_compliance_score(&analysis);

    analysis
}

/// Categorize cookies into functional categories
fn categorize_cookies(cookies: &[Cookie], categories: &mut CookieCategories) {
    for cookie in cookies {
        let name_lower = cookie.name.to_lowercase();

        if is_strictly_necessary(&name_lower) {
            categories.strictly_necessary.push(cookie.name.clone());
        } else if is_functional(&name_lower) {
            categories.functional.push(cookie.name.clone());
        } else if is_performance(&name_lower) {
            categories.performance.push(cookie.name.clone());
        } else if is_targeting(&name_lower) {
            categories.targeting.push(cookie.name.clone());
        } else {
            categories.uncategorized.push(cookie.name.clone());
        }
    }
}

/// Detect consent mechanism type from cookies
fn detect_consent_mechanism(cookies: &[Cookie]) -> ConsentMechanism {
    // Look for consent management cookies
    let consent_patterns = [
        "consent",
        "cookie_consent",
        "gdpr_consent",
        "ccpa_consent",
        "cookiecontrol",
        "cookieconsent",
        "optanon",
        "onetrust",
        "cmplz",
        "complianz",
        "cookie_notice",
    ];

    let has_consent_cookie = cookies.iter().any(|c| {
        let name_lower = c.name.to_lowercase();
        consent_patterns.iter().any(|p| name_lower.contains(p))
    });

    if has_consent_cookie {
        // Consent cookie exists - try to determine type
        // This is a simplified heuristic; real implementation would need page analysis
        // Always opt-in when consent cookie is present
        ConsentMechanism::OptIn
    } else {
        // No consent cookie found
        if cookies.iter().any(|c| is_targeting(&c.name.to_lowercase())) {
            ConsentMechanism::Implied // Targeting cookies without consent = implied
        } else {
            ConsentMechanism::None
        }
    }
}

/// Check if cookie is a consent management cookie
fn is_consent_cookie(cookie: &Cookie) -> bool {
    let consent_patterns = [
        "consent",
        "gdpr",
        "ccpa",
        "cookie_notice",
        "cookie_consent",
        "optanon",
        "onetrust",
        "cmplz",
        "cookiecontrol",
    ];

    let name_lower = cookie.name.to_lowercase();
    consent_patterns.iter().any(|p| name_lower.contains(p))
}

/// Check if cookie is strictly necessary
fn is_strictly_necessary(name: &str) -> bool {
    let patterns = [
        "session",
        "csrf",
        "xsrf",
        "auth",
        "login",
        "security",
        "load_balancer",
        "jsessionid",
        "phpsessid",
        "asp.net_sessionid",
    ];
    patterns.iter().any(|p| name.contains(p))
}

/// Check if cookie is functional
fn is_functional(name: &str) -> bool {
    let patterns = [
        "lang",
        "language",
        "locale",
        "timezone",
        "currency",
        "theme",
        "preference",
        "settings",
        "region",
    ];
    patterns.iter().any(|p| name.contains(p))
}

/// Check if cookie is for performance/analytics
fn is_performance(name: &str) -> bool {
    let patterns = [
        "_ga",
        "_gid",
        "_gat",
        "analytics",
        "_hjid",
        "_pk",
        "matomo",
        "piwik",
        "clicky",
        "statcounter",
    ];
    patterns.iter().any(|p| name.contains(p))
}

/// Check if cookie is for targeting/advertising
fn is_targeting(name: &str) -> bool {
    let patterns = [
        "_fbp",
        "_fbc",
        "fbclid",
        "doubleclick",
        "adsense",
        "adwords",
        "ads",
        "advertising",
        "remarketing",
        "conversion",
        "campaign",
        "criteo",
        "outbrain",
        "taboola",
        "twitter",
        "linkedin",
    ];
    patterns.iter().any(|p| name.contains(p))
}

/// Calculate consent compliance score
fn calculate_consent_compliance_score(analysis: &ConsentAnalysis) -> f32 {
    let mut score = 0.0;
    let mut total_points = 0.0;

    // Banner present (20 points)
    total_points += 20.0;
    if analysis.banner_present {
        score += 20.0;
    }

    // Opt-in mechanism (30 points)
    total_points += 30.0;
    if analysis.opt_in_required {
        score += 30.0;
    }

    // Granular control (20 points)
    total_points += 20.0;
    if analysis.granular_control {
        score += 20.0;
    }

    // Consent logging (15 points)
    total_points += 15.0;
    if analysis.consent_logged {
        score += 15.0;
    }

    // Easy withdrawal (15 points)
    total_points += 15.0;
    if analysis.withdrawal_easy {
        score += 15.0;
    }

    // Penalize for issues
    #[allow(clippy::cast_precision_loss)]
    let issue_penalty = (analysis.issues.len() as f32 * 10.0).min(30.0);
    score = (score - issue_penalty).max(0.0);

    (score / total_points * 100.0).min(100.0)
}

/// Generate consent recommendations
#[must_use]
pub fn generate_consent_recommendations(analysis: &ConsentAnalysis) -> Vec<String> {
    let mut recommendations = Vec::new();

    if !analysis.banner_present {
        recommendations
            .push("Implement a cookie consent banner visible on first visit".to_string());
    }

    if !analysis.opt_in_required {
        recommendations.push(
            "Require explicit opt-in consent for non-essential cookies (GDPR requirement)"
                .to_string(),
        );
    }

    if !analysis.granular_control {
        recommendations.push(
            "Provide granular consent options (Necessary, Functional, Analytics, Marketing)"
                .to_string(),
        );
    }

    if !analysis.consent_logged {
        recommendations.push("Log consent decisions with timestamp for audit trail".to_string());
    }

    if !analysis.withdrawal_easy {
        recommendations.push(
            "Provide easy consent withdrawal mechanism (settings page or banner recall)"
                .to_string(),
        );
    }

    // Category-specific recommendations
    if !analysis.cookie_categories.targeting.is_empty() {
        recommendations.push(
            "Targeting/advertising cookies require explicit consent - ensure they're blocked until consent".to_string()
        );
    }

    if !analysis.cookie_categories.uncategorized.is_empty() {
        recommendations.push(format!(
            "Categorize {} uncategorized cookies for proper consent management",
            analysis.cookie_categories.uncategorized.len()
        ));
    }

    recommendations
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_strictly_necessary() {
        assert!(is_strictly_necessary("sessionid"));
        assert!(is_strictly_necessary("csrf_token"));
        assert!(!is_strictly_necessary("_ga"));
    }

    #[test]
    fn test_is_functional() {
        assert!(is_functional("language"));
        assert!(is_functional("theme_preference"));
        assert!(!is_functional("_ga"));
    }

    #[test]
    fn test_is_performance() {
        assert!(is_performance("_ga"));
        assert!(is_performance("_gid"));
        assert!(!is_performance("sessionid"));
    }

    #[test]
    fn test_is_targeting() {
        assert!(is_targeting("_fbp"));
        assert!(is_targeting("doubleclick_id"));
        assert!(!is_targeting("sessionid"));
    }

    #[test]
    fn test_consent_cookie_detection() {
        let cookie = Cookie::new("cookie_consent".to_string(), "granted".to_string());
        assert!(is_consent_cookie(&cookie));

        let cookie = Cookie::new("sessionid".to_string(), "abc123".to_string());
        assert!(!is_consent_cookie(&cookie));
    }

    #[test]
    fn test_categorize_cookies() {
        let cookies = vec![
            Cookie::new("sessionid".to_string(), "abc".to_string()),
            Cookie::new("language".to_string(), "en".to_string()),
            Cookie::new("_ga".to_string(), "GA1.2.123".to_string()),
            Cookie::new("_fbp".to_string(), "fb.1.123".to_string()),
        ];

        let mut categories = CookieCategories::default();
        categorize_cookies(&cookies, &mut categories);

        assert_eq!(categories.strictly_necessary.len(), 1);
        assert_eq!(categories.functional.len(), 1);
        assert_eq!(categories.performance.len(), 1);
        assert_eq!(categories.targeting.len(), 1);
    }

    #[test]
    fn test_analyze_consent_mechanism() {
        let cookies = vec![
            Cookie::new("cookie_consent".to_string(), "granted".to_string()),
            Cookie::new("_ga".to_string(), "GA1.2.123".to_string()),
        ];

        let analysis = analyze_consent_mechanism(&cookies);
        assert!(analysis.consent_logged);
        assert!(analysis.compliance_score > 0.0);
    }

    #[test]
    fn test_calculate_compliance_score() {
        let mut analysis = ConsentAnalysis {
            banner_present: true,
            mechanism_type: ConsentMechanism::GranularOptIn,
            opt_in_required: true,
            opt_out_available: true,
            granular_control: true,
            withdrawal_easy: true,
            consent_logged: true,
            cookie_categories: CookieCategories::default(),
            issues: Vec::new(),
            recommendations: Vec::new(),
            compliance_score: 0.0,
        };

        let score = calculate_consent_compliance_score(&analysis);
        assert!(score > 90.0); // Should have high score with all features

        analysis.opt_in_required = false;
        analysis.granular_control = false;
        let low_score = calculate_consent_compliance_score(&analysis);
        assert!(low_score < score);
    }
}
