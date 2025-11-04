//! Tracking and privacy analysis

use std::collections::HashMap;

use crate::types::report::{TrackingInfo, TrackingType};
use crate::types::{Cookie, Severity};

/// Well-known tracking cookie patterns
const TRACKING_PATTERNS: &[(&str, TrackingType, &str)] = &[
    // Analytics
    ("_ga", TrackingType::Analytics, "Google Analytics"),
    ("_gid", TrackingType::Analytics, "Google Analytics"),
    ("_gat", TrackingType::Analytics, "Google Analytics"),
    (
        "__utm",
        TrackingType::Analytics,
        "Google Analytics (legacy)",
    ),
    ("_dc_gtm_", TrackingType::Analytics, "Google Tag Manager"),
    ("_hjid", TrackingType::Analytics, "Hotjar"),
    ("_hjIncludedInSample", TrackingType::Analytics, "Hotjar"),
    // Advertising
    ("_fbp", TrackingType::Advertising, "Facebook Pixel"),
    ("fr", TrackingType::Advertising, "Facebook"),
    ("IDE", TrackingType::Advertising, "Google DoubleClick"),
    (
        "test_cookie",
        TrackingType::Advertising,
        "Google DoubleClick",
    ),
    ("DSID", TrackingType::Advertising, "Google DoubleClick"),
    ("id", TrackingType::Advertising, "Google DoubleClick"),
    // Social Media
    ("datr", TrackingType::SocialMedia, "Facebook"),
    ("sb", TrackingType::SocialMedia, "Facebook"),
    ("c_user", TrackingType::SocialMedia, "Facebook"),
    ("xs", TrackingType::SocialMedia, "Facebook"),
    // Cross-site
    ("__Secure-3PAPISID", TrackingType::CrossSite, "Google"),
    ("__Secure-3PSID", TrackingType::CrossSite, "Google"),
    ("CONSENT", TrackingType::CrossSite, "Google"),
];

/// Analyze cookies for tracking and privacy implications
#[must_use]
pub fn analyze_tracking(cookies: &[Cookie]) -> Vec<TrackingInfo> {
    let mut tracking_info = Vec::new();

    for cookie in cookies {
        if let Some(info) = identify_tracker(cookie) {
            tracking_info.push(info);
        }
    }

    tracking_info
}

/// Detect tracking for a single cookie (public wrapper for `identify_tracker`)
/// This is used by `analyzer/mod.rs`
#[must_use]
pub fn detect_tracking(cookie: &Cookie) -> Option<TrackingInfo> {
    identify_tracker(cookie)
}

/// Identify if a cookie is a known tracker
fn identify_tracker(cookie: &Cookie) -> Option<TrackingInfo> {
    // Check known patterns
    for (pattern, tracking_type, vendor) in TRACKING_PATTERNS {
        if cookie.name.contains(pattern) {
            return Some(TrackingInfo {
                cookie_name: cookie.name.clone(),
                tracking_type: *tracking_type,
                vendor: Some((*vendor).to_string()),
                purpose: get_purpose(*tracking_type),
                risk_level: get_risk_level(*tracking_type),
                data_collected: get_data_collected(*tracking_type),
                third_parties: Vec::new(),
            });
        }
    }

    // Check if third-party cookie (often tracking)
    if cookie.is_third_party {
        return Some(TrackingInfo {
            cookie_name: cookie.name.clone(),
            tracking_type: TrackingType::Unknown,
            vendor: cookie.domain.clone(),
            purpose: "Unknown third-party tracking".to_string(),
            risk_level: Severity::Medium,
            data_collected: vec!["Unknown".to_string()],
            third_parties: Vec::new(),
        });
    }

    None
}

/// Get purpose description for tracking type
fn get_purpose(tracking_type: TrackingType) -> String {
    match tracking_type {
        TrackingType::Analytics => "Website analytics and usage tracking".to_string(),
        TrackingType::Advertising => "Targeted advertising and marketing".to_string(),
        TrackingType::SocialMedia => "Social media integration and sharing".to_string(),
        TrackingType::Functional => "Essential website functionality".to_string(),
        TrackingType::Fingerprinting => "Device and browser fingerprinting".to_string(),
        TrackingType::CrossSite => "Cross-site user tracking".to_string(),
        TrackingType::Unknown => "Unknown tracking purpose".to_string(),
    }
}

/// Get risk level for tracking type
fn get_risk_level(tracking_type: TrackingType) -> Severity {
    match tracking_type {
        TrackingType::Analytics | TrackingType::Functional => Severity::Low,
        TrackingType::Advertising | TrackingType::SocialMedia | TrackingType::Unknown => {
            Severity::Medium
        }
        TrackingType::Fingerprinting | TrackingType::CrossSite => Severity::High,
    }
}

/// Get typical data collected by tracking type
fn get_data_collected(tracking_type: TrackingType) -> Vec<String> {
    match tracking_type {
        TrackingType::Analytics => vec![
            "Page views".to_string(),
            "User interactions".to_string(),
            "Session duration".to_string(),
            "Referrer".to_string(),
        ],
        TrackingType::Advertising => vec![
            "Browsing history".to_string(),
            "Ad interactions".to_string(),
            "User preferences".to_string(),
            "Demographics".to_string(),
        ],
        TrackingType::SocialMedia => vec![
            "Social interactions".to_string(),
            "Likes and shares".to_string(),
            "Profile information".to_string(),
        ],
        TrackingType::Functional => {
            vec!["User preferences".to_string(), "Session state".to_string()]
        }
        TrackingType::Fingerprinting => vec![
            "Device characteristics".to_string(),
            "Browser information".to_string(),
            "Screen resolution".to_string(),
            "Installed fonts".to_string(),
        ],
        TrackingType::CrossSite => vec![
            "Cross-site browsing history".to_string(),
            "User behavior across sites".to_string(),
        ],
        TrackingType::Unknown => vec!["Unknown data collection".to_string()],
    }
}

/// Analyze fingerprinting techniques
#[must_use]
pub fn analyze_fingerprinting(cookies: &[Cookie]) -> Vec<TrackingInfo> {
    let mut fingerprinting_info = Vec::new();

    for cookie in cookies {
        // Check for fingerprinting-related cookies
        if is_fingerprinting_cookie(&cookie.name) {
            fingerprinting_info.push(TrackingInfo {
                cookie_name: cookie.name.clone(),
                tracking_type: TrackingType::Fingerprinting,
                vendor: cookie.domain.clone(),
                purpose: "Device and browser fingerprinting".to_string(),
                risk_level: Severity::High,
                data_collected: get_data_collected(TrackingType::Fingerprinting),
                third_parties: Vec::new(),
            });
        }
    }

    fingerprinting_info
}

/// Check if a cookie name suggests fingerprinting
fn is_fingerprinting_cookie(name: &str) -> bool {
    let fingerprint_patterns = [
        "fingerprint",
        "fp",
        "device_id",
        "browser_id",
        "canvas",
        "webgl",
    ];

    let name_lower = name.to_lowercase();
    fingerprint_patterns
        .iter()
        .any(|pattern| name_lower.contains(pattern))
}

/// Generate privacy report
#[must_use]
pub fn generate_privacy_report(
    cookies: &[Cookie],
    tracking_info: &[TrackingInfo],
) -> HashMap<String, serde_json::Value> {
    let mut report = HashMap::new();

    // Count tracking cookies by type
    let mut by_type: HashMap<TrackingType, usize> = HashMap::new();
    for info in tracking_info {
        *by_type.entry(info.tracking_type).or_insert(0) += 1;
    }

    report.insert(
        "tracking_by_type".to_string(),
        serde_json::json!(by_type
            .iter()
            .map(|(k, v)| (format!("{k:?}"), v))
            .collect::<HashMap<_, _>>()),
    );

    // Third-party cookies
    let third_party_count = cookies.iter().filter(|c| c.is_third_party).count();
    report.insert(
        "third_party_cookies".to_string(),
        serde_json::json!(third_party_count),
    );

    // High-risk tracking
    let high_risk = tracking_info
        .iter()
        .filter(|t| t.risk_level == Severity::High)
        .count();
    report.insert(
        "high_risk_trackers".to_string(),
        serde_json::json!(high_risk),
    );

    // Unique tracking domains
    let unique_domains: std::collections::HashSet<_> = tracking_info
        .iter()
        .filter_map(|t| t.vendor.as_ref())
        .collect();
    report.insert(
        "unique_tracking_domains".to_string(),
        serde_json::json!(unique_domains.len()),
    );

    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identify_google_analytics() {
        let cookie = Cookie {
            name: "_ga".to_string(),
            value: "GA1.2.123456789.123456789".to_string(),
            is_third_party: false,
            ..Default::default()
        };

        let info = identify_tracker(&cookie);
        assert!(info.is_some());
        let info = info.unwrap();
        assert_eq!(info.tracking_type, TrackingType::Analytics);
        assert_eq!(info.vendor, Some("Google Analytics".to_string()));
    }

    #[test]
    fn test_identify_facebook_pixel() {
        let cookie = Cookie {
            name: "_fbp".to_string(),
            value: "fb.1.123456789.123456789".to_string(),
            is_third_party: false,
            ..Default::default()
        };

        let info = identify_tracker(&cookie);
        assert!(info.is_some());
        let info = info.unwrap();
        assert_eq!(info.tracking_type, TrackingType::Advertising);
    }

    #[test]
    fn test_third_party_cookie() {
        let cookie = Cookie {
            name: "unknown_tracker".to_string(),
            value: "xyz123".to_string(),
            is_third_party: true,
            domain: Some("tracker.com".to_string()),
            ..Default::default()
        };

        let info = identify_tracker(&cookie);
        assert!(info.is_some());
        let info = info.unwrap();
        assert_eq!(info.tracking_type, TrackingType::Unknown);
    }

    #[test]
    fn test_non_tracking_cookie() {
        let cookie = Cookie {
            name: "user_preference".to_string(),
            value: "theme=dark".to_string(),
            is_third_party: false,
            ..Default::default()
        };

        let info = identify_tracker(&cookie);
        assert!(info.is_none());
    }

    #[test]
    fn test_fingerprinting_detection() {
        let cookie = Cookie {
            name: "device_fingerprint".to_string(),
            value: "abc123".to_string(),
            ..Default::default()
        };

        assert!(is_fingerprinting_cookie(&cookie.name));
    }

    #[test]
    fn test_privacy_report() {
        let cookies = vec![
            Cookie {
                name: "_ga".to_string(),
                value: "test".to_string(),
                is_third_party: false,
                ..Default::default()
            },
            Cookie {
                name: "tracker".to_string(),
                value: "test".to_string(),
                is_third_party: true,
                ..Default::default()
            },
        ];

        let tracking_info = analyze_tracking(&cookies);
        let report = generate_privacy_report(&cookies, &tracking_info);

        assert!(report.contains_key("third_party_cookies"));
        assert!(report.contains_key("tracking_by_type"));
    }

    #[test]
    fn test_risk_levels() {
        assert_eq!(get_risk_level(TrackingType::Analytics), Severity::Low);
        assert_eq!(get_risk_level(TrackingType::Fingerprinting), Severity::High);
        assert_eq!(get_risk_level(TrackingType::CrossSite), Severity::High);
    }
}
