//! Google Consent Detection Module
//!
//! This module detects and analyzes Google Consent Mode V2 and Additional Consent
//! signals from various sources:
//! - HTTP cookies
//! - URL parameters
//! - HTTP requests
//!
//! # Overview
//!
//! Google Consent signals can appear in multiple places:
//!
//! ## Cookies
//! - `addtl_consent`: AC String (e.g., "2~1.35.41~dv.9.21")
//! - `CookieConsent`, `OptanonConsent`: CMP consent cookies
//! - `_ga`, `_gid`, `_gat`: Google Analytics cookies
//! - `_gcl_au`, `_gcl_aw`: Google Ads cookies
//!
//! ## URL Parameters
//! - `gcd`: Consent Mode V2 parameter (e.g., "11l1m1n1p5")
//! - `gcs`: Legacy Consent Mode V1 parameter (e.g., "G111")
//! - `addtl_consent`: AC String in URL
//!
//! # Examples
//!
//! ```
//! # use icookforms::compliance::google_consent::detect_google_consent_cookies;
//! # use icookforms::types::Cookie;
//! let cookies = vec![
//!     Cookie::new("addtl_consent".to_string(), "2~1.35.41~dv.9.21".to_string()),
//!     Cookie::new("_ga".to_string(), "GA1.2.123456.789".to_string()),
//! ];
//!
//! let analysis = detect_google_consent_cookies(&cookies);
//! assert!(analysis.ac_string.is_some());
//! assert!(analysis.has_analytics_cookies);
//! ```

use super::{parse_ac_string, parse_gcd_parameter, ACString, ConsentModeV2};
use crate::types::Cookie;
use std::collections::HashMap;
use url::Url;

/// Google Consent Analysis Results
///
/// Contains comprehensive analysis of Google consent signals found in cookies,
/// URLs, and HTTP requests.
#[derive(Debug, Clone, Default)]
#[allow(clippy::struct_excessive_bools)]
pub struct GoogleConsentAnalysis {
    /// Parsed Additional Consent String (if found)
    pub ac_string: Option<ACString>,

    /// Parsed Consent Mode V2 data (if found)
    pub consent_mode_v2: Option<ConsentModeV2>,

    /// Legacy Consent Mode V1 string (if found)
    pub gcs_value: Option<String>,

    /// Consent cookie found (various CMPs)
    pub consent_cookie: Option<Cookie>,

    /// Google Analytics cookies detected
    pub has_analytics_cookies: bool,

    /// Google Ads cookies detected
    pub has_ads_cookies: bool,

    /// `DoubleClick` cookies detected
    pub has_doubleclick_cookies: bool,

    /// `YouTube` cookies detected
    pub has_youtube_cookies: bool,

    /// All Google-related cookies found
    pub google_cookies: Vec<Cookie>,

    /// Source of consent data (cookie, url, both)
    pub consent_source: ConsentSource,
}

/// Google Consent Data extracted from URLs or requests
///
/// Contains raw consent data before full analysis.
#[derive(Debug, Clone, Default)]
pub struct GoogleConsentData {
    /// Legacy gcs parameter value
    pub gcs: Option<String>,

    /// Parsed Consent Mode V2 from gcd parameter
    pub consent_mode_v2: Option<ConsentModeV2>,

    /// Parsed AC String from URL parameter
    pub ac_string: Option<ACString>,
}

/// Source of consent information
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsentSource {
    /// No consent information found
    None,

    /// Consent found in cookies only
    Cookie,

    /// Consent found in URL parameters only
    Url,

    /// Consent found in both cookies and URL
    Both,
}

impl Default for ConsentSource {
    fn default() -> Self {
        Self::None
    }
}

impl GoogleConsentAnalysis {
    /// Creates a new empty analysis
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Checks if any consent information was found
    #[must_use]
    pub fn has_consent_data(&self) -> bool {
        self.ac_string.is_some() || self.consent_mode_v2.is_some() || self.consent_cookie.is_some()
    }

    /// Checks if any Google cookies were detected
    #[must_use]
    pub fn has_google_cookies(&self) -> bool {
        self.has_analytics_cookies
            || self.has_ads_cookies
            || self.has_doubleclick_cookies
            || self.has_youtube_cookies
    }

    /// Checks if the configuration appears compliant
    ///
    /// Returns true if:
    /// - No Google cookies are present, OR
    /// - Google cookies are present AND consent data exists
    #[must_use]
    pub fn appears_compliant(&self) -> bool {
        !self.has_google_cookies() || self.has_consent_data()
    }

    /// Gets a summary of detected Google products
    #[must_use]
    pub fn detected_products(&self) -> Vec<String> {
        let mut products = Vec::new();

        if self.has_analytics_cookies {
            products.push("Google Analytics".to_string());
        }
        if self.has_ads_cookies {
            products.push("Google Ads".to_string());
        }
        if self.has_doubleclick_cookies {
            products.push("DoubleClick".to_string());
        }
        if self.has_youtube_cookies {
            products.push("YouTube".to_string());
        }

        products
    }
}

/// Detects Google consent signals in a collection of cookies
///
/// Analyzes cookies to detect:
/// - Additional Consent (AC) Strings
/// - Consent Mode cookies from various CMPs
/// - Google Analytics cookies
/// - Google Ads cookies
/// - `DoubleClick` cookies
/// - `YouTube` cookies
///
/// # Arguments
/// * `cookies` - Slice of cookies to analyze
///
/// # Returns
/// `GoogleConsentAnalysis` with detected signals
///
/// # Examples
/// ```
/// # use icookforms::compliance::google_consent::detect_google_consent_cookies;
/// # use icookforms::types::Cookie;
/// let cookies = vec![
///     Cookie::new("addtl_consent".to_string(), "2~1.35.41~dv.9.21".to_string()),
///     Cookie::new("_ga".to_string(), "GA1.2.123456.789".to_string()),
/// ];
///
/// let analysis = detect_google_consent_cookies(&cookies);
/// assert!(analysis.has_consent_data());
/// assert!(analysis.has_analytics_cookies);
/// ```
#[must_use]
pub fn detect_google_consent_cookies(cookies: &[Cookie]) -> GoogleConsentAnalysis {
    let mut analysis = GoogleConsentAnalysis::new();
    let mut google_cookies = Vec::new();

    for cookie in cookies {
        let name_lower = cookie.name.to_lowercase();

        match name_lower.as_str() {
            // Additional Consent cookie
            "addtl_consent" | "addtlconsent" => {
                if let Ok(ac_string) = parse_ac_string(&cookie.value) {
                    analysis.ac_string = Some(ac_string);
                    analysis.consent_source = match analysis.consent_source {
                        ConsentSource::None => ConsentSource::Cookie,
                        ConsentSource::Url => ConsentSource::Both,
                        _ => analysis.consent_source,
                    };
                }
                google_cookies.push(cookie.clone());
            }

            // Common CMP consent cookies (including "consent" which can also be a Google-wide cookie)
            "cookieconsent" | "optanonconsent" | "cookie_consent" | "euconsent-v2"
            | "cookielaw" | "consent" => {
                analysis.consent_cookie = Some(cookie.clone());
                analysis.consent_source = match analysis.consent_source {
                    ConsentSource::None => ConsentSource::Cookie,
                    ConsentSource::Url => ConsentSource::Both,
                    _ => analysis.consent_source,
                };

                // If it's the "consent" cookie and it's from Google domain, also track it
                if name_lower == "consent" {
                    let is_google_consent = cookie
                        .domain
                        .as_ref()
                        .is_some_and(|d| d.contains(".google."));

                    if is_google_consent {
                        google_cookies.push(cookie.clone());
                    }
                }
            }

            // Google Analytics cookies
            "_ga" | "_gid" | "_gat" | "_gat_gtag_" | "__utma" | "__utmb" | "__utmc" | "__utmz"
            | "__utmt" | "_gac_" => {
                analysis.has_analytics_cookies = true;
                google_cookies.push(cookie.clone());
            }

            // Google Ads cookies
            "_gcl_au" | "_gcl_aw" | "_gcl_dc" | "_gcl_gb" | "_gcl_gf" | "_gcl_ha" => {
                analysis.has_ads_cookies = true;
                google_cookies.push(cookie.clone());
            }

            // DoubleClick cookies
            "test_cookie" | "ide" | "__gads" | "__gac" => {
                let is_doubleclick = cookie
                    .domain
                    .as_ref()
                    .is_some_and(|d| d.contains("doubleclick.net") || d.contains(".google."));

                if is_doubleclick {
                    analysis.has_doubleclick_cookies = true;
                    google_cookies.push(cookie.clone());
                }
            }

            // YouTube cookies
            "visitor_info1_live" | "ysc" | "pref" | "yt-remote-" => {
                let is_youtube = cookie
                    .domain
                    .as_ref()
                    .is_some_and(|d| d.contains("youtube.com") || d.contains("googlevideo.com"));

                if is_youtube {
                    analysis.has_youtube_cookies = true;
                    google_cookies.push(cookie.clone());
                }
            }

            _ => {
                // Check if it's a Google cookie by domain
                if let Some(ref domain) = cookie.domain {
                    if is_google_domain(domain) {
                        google_cookies.push(cookie.clone());
                    }
                }
            }
        }
    }

    analysis.google_cookies = google_cookies;
    analysis
}

/// Detects Google consent signals in a URL
///
/// Parses URL query parameters to extract:
/// - `gcd`: Consent Mode V2 parameter
/// - `gcs`: Legacy Consent Mode V1 parameter
/// - `addtl_consent`: AC String parameter
///
/// # Arguments
/// * `url` - URL string to analyze
///
/// # Returns
/// * `Some(GoogleConsentData)` if consent signals are found
/// * `None` if no consent signals or URL is invalid
///
/// # Examples
/// ```
/// # use icookforms::compliance::google_consent::detect_google_consent_in_url;
/// let url = "https://example.com?gcd=11l1m1n1p5&addtl_consent=2~1.35";
/// let data = detect_google_consent_in_url(url).unwrap();
/// assert!(data.consent_mode_v2.is_some());
/// assert!(data.ac_string.is_some());
/// ```
#[must_use]
pub fn detect_google_consent_in_url(url: &str) -> Option<GoogleConsentData> {
    let parsed = Url::parse(url).ok()?;
    let params: HashMap<_, _> = parsed.query_pairs().collect();

    let mut data = GoogleConsentData::default();
    let mut found_any = false;

    // Detect gcs parameter (v1)
    if let Some(gcs) = params.get("gcs") {
        data.gcs = Some(gcs.to_string());
        found_any = true;
    }

    // Detect gcd parameter (v2)
    if let Some(gcd) = params.get("gcd") {
        if let Ok(consent) = parse_gcd_parameter(gcd) {
            data.consent_mode_v2 = Some(consent);
            found_any = true;
        }
    }

    // Detect addtl_consent parameter
    if let Some(ac) = params.get("addtl_consent") {
        if let Ok(ac_string) = parse_ac_string(ac) {
            data.ac_string = Some(ac_string);
            found_any = true;
        }
    }

    if found_any {
        Some(data)
    } else {
        None
    }
}

/// Detects Google consent signals in an HTTP request
///
/// Combines detection from both cookies and URL parameters.
///
/// # Arguments
/// * `url` - Request URL
/// * `cookies` - Request cookies
///
/// # Returns
/// `GoogleConsentAnalysis` combining all detected signals
///
/// # Examples
/// ```
/// # use icookforms::compliance::google_consent::detect_in_http_request;
/// # use icookforms::types::Cookie;
/// let url = "https://example.com?gcd=11l1m1n1p5";
/// let cookies = vec![
///     Cookie::new("_ga".to_string(), "GA1.2.123456.789".to_string()),
/// ];
///
/// let analysis = detect_in_http_request(url, &cookies);
/// assert!(analysis.consent_mode_v2.is_some());
/// assert!(analysis.has_analytics_cookies);
/// ```
#[must_use]
pub fn detect_in_http_request(url: &str, cookies: &[Cookie]) -> GoogleConsentAnalysis {
    let mut analysis = detect_google_consent_cookies(cookies);

    if let Some(url_data) = detect_google_consent_in_url(url) {
        // Merge URL data with cookie analysis
        if url_data.consent_mode_v2.is_some() {
            analysis.consent_mode_v2 = url_data.consent_mode_v2;
            analysis.consent_source = match analysis.consent_source {
                ConsentSource::None => ConsentSource::Url,
                ConsentSource::Cookie => ConsentSource::Both,
                _ => analysis.consent_source,
            };
        }

        if url_data.gcs.is_some() {
            analysis.gcs_value = url_data.gcs;
            analysis.consent_source = match analysis.consent_source {
                ConsentSource::None => ConsentSource::Url,
                ConsentSource::Cookie => ConsentSource::Both,
                _ => analysis.consent_source,
            };
        }

        if url_data.ac_string.is_some() && analysis.ac_string.is_none() {
            analysis.ac_string = url_data.ac_string;
            analysis.consent_source = match analysis.consent_source {
                ConsentSource::None => ConsentSource::Url,
                ConsentSource::Cookie => ConsentSource::Both,
                _ => analysis.consent_source,
            };
        }
    }

    analysis
}

/// Checks if a domain is a Google domain
///
/// # Arguments
/// * `domain` - Domain string to check
///
/// # Returns
/// `true` if the domain belongs to Google, `false` otherwise
fn is_google_domain(domain: &str) -> bool {
    let google_domains = [
        ".google.com",
        ".google.",
        ".googleapis.com",
        ".googleusercontent.com",
        ".googlesyndication.com",
        ".googletagmanager.com",
        ".googleadservices.com",
        ".google-analytics.com",
        ".doubleclick.net",
        ".youtube.com",
        ".ytimg.com",
        ".googlevideo.com",
        ".ggpht.com",
        ".gstatic.com",
    ];

    google_domains.iter().any(|&g| domain.contains(g))
}

/// Extracts Google Tag Manager container IDs from a URL
///
/// # Arguments
/// * `url` - URL to analyze
///
/// # Returns
/// Vector of GTM container IDs found (e.g., `["GTM-XXXXXX"]`)
#[must_use]
pub fn extract_gtm_containers(url: &str) -> Vec<String> {
    let mut containers = Vec::new();

    if let Ok(parsed) = Url::parse(url) {
        // Check if it's a GTM URL
        if parsed.host_str() == Some("www.googletagmanager.com") {
            if let Some(path) = parsed.path_segments() {
                for segment in path {
                    if segment.starts_with("GTM-") {
                        containers.push(segment.to_string());
                    }
                }
            }
        }

        // Check URL parameters for GTM ID
        let params: HashMap<_, _> = parsed.query_pairs().collect();
        if let Some(id) = params.get("id") {
            if id.starts_with("GTM-") {
                containers.push(id.to_string());
            }
        }
    }

    containers
}

/// Extracts Google Analytics measurement IDs from a URL
///
/// # Arguments
/// * `url` - URL to analyze
///
/// # Returns
/// Vector of GA measurement IDs found (e.g., `["G-XXXXXXXXXX", "UA-XXXXXXXX-X"]`)
#[must_use]
pub fn extract_ga_ids(url: &str) -> Vec<String> {
    let mut ids = Vec::new();

    if let Ok(parsed) = Url::parse(url) {
        let params: HashMap<_, _> = parsed.query_pairs().collect();

        // Check for GA4 measurement ID (G-XXXXXXXXXX)
        if let Some(id) = params.get("id") {
            if id.starts_with("G-") {
                ids.push(id.to_string());
            }
        }

        // Check for Universal Analytics ID (UA-XXXXXXXX-X)
        if let Some(id) = params.get("tid") {
            if id.starts_with("UA-") {
                ids.push(id.to_string());
            }
        }
    }

    ids
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Cookie Detection Tests
    // ========================================================================

    #[test]
    fn test_detect_ac_string_cookie() {
        let cookies = vec![Cookie::new(
            "addtl_consent".to_string(),
            "2~1.35.41~dv.9.21".to_string(),
        )];

        let analysis = detect_google_consent_cookies(&cookies);
        assert!(analysis.ac_string.is_some());
        assert_eq!(analysis.consent_source, ConsentSource::Cookie);
    }

    #[test]
    fn test_detect_analytics_cookies() {
        let cookies = vec![
            Cookie::new("_ga".to_string(), "GA1.2.123456.789".to_string()),
            Cookie::new("_gid".to_string(), "GA1.2.987654.321".to_string()),
        ];

        let analysis = detect_google_consent_cookies(&cookies);
        assert!(analysis.has_analytics_cookies);
        assert_eq!(analysis.google_cookies.len(), 2);
    }

    #[test]
    fn test_detect_ads_cookies() {
        let cookies = vec![
            Cookie::new("_gcl_au".to_string(), "1.1234567890.1234567890".to_string()),
            Cookie::new("_gcl_aw".to_string(), "GCL.1234567890.abcdef".to_string()),
        ];

        let analysis = detect_google_consent_cookies(&cookies);
        assert!(analysis.has_ads_cookies);
        assert_eq!(analysis.google_cookies.len(), 2);
    }

    #[test]
    fn test_detect_consent_cookie() {
        let cookies = vec![Cookie::new(
            "CookieConsent".to_string(),
            "accepted".to_string(),
        )];

        let analysis = detect_google_consent_cookies(&cookies);
        assert!(analysis.consent_cookie.is_some());
    }

    #[test]
    fn test_no_google_cookies() {
        let cookies = vec![
            Cookie::new("session".to_string(), "abc123".to_string()),
            Cookie::new("csrf".to_string(), "xyz789".to_string()),
        ];

        let analysis = detect_google_consent_cookies(&cookies);
        assert!(!analysis.has_google_cookies());
        assert!(analysis.google_cookies.is_empty());
    }

    // ========================================================================
    // URL Detection Tests
    // ========================================================================

    #[test]
    fn test_detect_gcd_in_url() {
        let url = "https://example.com?gcd=11l1m1n1p5";
        let data = detect_google_consent_in_url(url).unwrap();
        assert!(data.consent_mode_v2.is_some());
    }

    #[test]
    fn test_detect_gcs_in_url() {
        let url = "https://example.com?gcs=G111";
        let data = detect_google_consent_in_url(url).unwrap();
        assert!(data.gcs.is_some());
        assert_eq!(data.gcs.unwrap(), "G111");
    }

    #[test]
    fn test_detect_ac_in_url() {
        let url = "https://example.com?addtl_consent=2~1.35.41~dv.9.21";
        let data = detect_google_consent_in_url(url).unwrap();
        assert!(data.ac_string.is_some());
    }

    #[test]
    fn test_detect_multiple_params_in_url() {
        let url = "https://example.com?gcd=11l1m1n1p5&addtl_consent=2~1.35&other=value";
        let data = detect_google_consent_in_url(url).unwrap();
        assert!(data.consent_mode_v2.is_some());
        assert!(data.ac_string.is_some());
    }

    #[test]
    fn test_no_consent_in_url() {
        let url = "https://example.com?page=1&sort=asc";
        let data = detect_google_consent_in_url(url);
        assert!(data.is_none());
    }

    // ========================================================================
    // HTTP Request Detection Tests
    // ========================================================================

    #[test]
    fn test_detect_in_request_cookies_only() {
        let url = "https://example.com";
        let cookies = vec![Cookie::new(
            "_ga".to_string(),
            "GA1.2.123456.789".to_string(),
        )];

        let analysis = detect_in_http_request(url, &cookies);
        assert!(analysis.has_analytics_cookies);
        assert_eq!(analysis.consent_source, ConsentSource::None);
    }

    #[test]
    fn test_detect_in_request_url_only() {
        let url = "https://example.com?gcd=11l1m1n1p5";
        let cookies: Vec<Cookie> = vec![];

        let analysis = detect_in_http_request(url, &cookies);
        assert!(analysis.consent_mode_v2.is_some());
        assert_eq!(analysis.consent_source, ConsentSource::Url);
    }

    #[test]
    fn test_detect_in_request_both_sources() {
        let url = "https://example.com?gcd=11l1m1n1p5";
        let cookies = vec![
            Cookie::new("addtl_consent".to_string(), "2~1.35".to_string()),
            Cookie::new("_ga".to_string(), "GA1.2.123456.789".to_string()),
        ];

        let analysis = detect_in_http_request(url, &cookies);
        assert!(analysis.consent_mode_v2.is_some());
        assert!(analysis.ac_string.is_some());
        assert!(analysis.has_analytics_cookies);
        assert_eq!(analysis.consent_source, ConsentSource::Both);
    }

    // ========================================================================
    // GoogleConsentAnalysis Methods Tests
    // ========================================================================

    #[test]
    fn test_has_consent_data() {
        let mut analysis = GoogleConsentAnalysis::new();
        assert!(!analysis.has_consent_data());

        analysis.ac_string = Some(ACString::new());
        assert!(analysis.has_consent_data());
    }

    #[test]
    fn test_appears_compliant() {
        // No Google cookies = compliant
        let mut analysis = GoogleConsentAnalysis::new();
        assert!(analysis.appears_compliant());

        // Google cookies + no consent = non-compliant
        analysis.has_analytics_cookies = true;
        assert!(!analysis.appears_compliant());

        // Google cookies + consent = compliant
        analysis.ac_string = Some(ACString::new());
        assert!(analysis.appears_compliant());
    }

    #[test]
    fn test_detected_products() {
        let mut analysis = GoogleConsentAnalysis::new();
        assert!(analysis.detected_products().is_empty());

        analysis.has_analytics_cookies = true;
        analysis.has_ads_cookies = true;

        let products = analysis.detected_products();
        assert_eq!(products.len(), 2);
        assert!(products.contains(&"Google Analytics".to_string()));
        assert!(products.contains(&"Google Ads".to_string()));
    }

    // ========================================================================
    // Utility Function Tests
    // ========================================================================

    #[test]
    fn test_is_google_domain() {
        assert!(is_google_domain(".google.com"));
        assert!(is_google_domain("www.google.com"));
        assert!(is_google_domain(".googleapis.com"));
        assert!(is_google_domain(".doubleclick.net"));
        assert!(is_google_domain(".youtube.com"));
        assert!(!is_google_domain("example.com"));
        assert!(!is_google_domain("nogoogle.net"));
    }

    #[test]
    fn test_extract_gtm_containers() {
        let url = "https://www.googletagmanager.com/gtm.js?id=GTM-XXXXXX";
        let containers = extract_gtm_containers(url);
        assert_eq!(containers.len(), 1);
        assert_eq!(containers[0], "GTM-XXXXXX");
    }

    #[test]
    fn test_extract_ga_ids() {
        // GA4
        let url = "https://www.googletagmanager.com/gtag/js?id=G-XXXXXXXXXX";
        let ids = extract_ga_ids(url);
        assert!(ids.contains(&"G-XXXXXXXXXX".to_string()));

        // Universal Analytics
        let url2 = "https://www.google-analytics.com/collect?tid=UA-12345678-1";
        let ids2 = extract_ga_ids(url2);
        assert!(ids2.contains(&"UA-12345678-1".to_string()));
    }
}
