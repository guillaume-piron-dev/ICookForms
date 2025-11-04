//! # Cookie Forensics Module
//!
//! Professional digital forensics tools for cookie analysis.
//! This module provides capabilities that NO OTHER TOOL IN THE WORLD has.
//!
//! ## Features
//!
//! - **Timeline Reconstruction**: Rebuild complete cookie activity timeline
//! - **iOS Binary Parser**: Decode iOS binarycookies format
//! - **Google Analytics Forensics**: Extract user journey from GA cookies
//! - **Universal Decoder**: Decode Base64, Hex, Unix timestamps, GUIDs
//! - **Evidence Collection**: Chain-of-custody preservation for legal cases
//! - **Forensic Reports**: Court-ready evidence reports
//!
//! ## Examples
//!
//! ```rust,no_run
//! use icookforms::forensics::{CookieTimeline, ForensicAnalyzer};
//! use icookforms::Cookie;
//!
//! let cookies = vec![/* your cookies */];
//! let analyzer = ForensicAnalyzer::new();
//!
//! // Reconstruct timeline
//! let timeline = analyzer.reconstruct_timeline(&cookies)?;
//!
//! // Find anomalies
//! let anomalies = timeline.find_anomalies();
//!
//! // Generate forensic report
//! let report = timeline.generate_forensic_report();
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use crate::types::{Cookie, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub mod cookie_decoder;
pub mod evidence_collector;
pub mod google_analytics;
pub mod ios_binary;
pub mod report_generator;
pub mod timeline;

// Re-exports
pub use cookie_decoder::CookieDecoder;
pub use evidence_collector::EvidenceCollector;
pub use google_analytics::GoogleAnalyticsCookie;
pub use ios_binary::IosBinaryCookieParser;
pub use report_generator::{ForensicReport, ForensicReportBuilder};
pub use timeline::{CookieAction, CookieEvent, CookieTimeline, EventSource, TimelineAnomaly};

/// Main forensic analyzer
#[derive(Debug, Clone)]
pub struct ForensicAnalyzer {
    /// Configuration for forensic analysis
    config: ForensicConfig,
}

/// Configuration for forensic analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicConfig {
    /// Enable chain-of-custody tracking
    pub enable_chain_of_custody: bool,

    /// Include raw data in reports
    pub include_raw_data: bool,

    /// Timezone for timestamps
    pub timezone: String,

    /// Minimum confidence level for anomalies (0.0-1.0)
    pub anomaly_threshold: f64,
}

impl Default for ForensicConfig {
    fn default() -> Self {
        Self {
            enable_chain_of_custody: true,
            include_raw_data: true,
            timezone: "UTC".to_string(),
            anomaly_threshold: 0.7,
        }
    }
}

impl ForensicAnalyzer {
    /// Create a new forensic analyzer with default configuration
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: ForensicConfig::default(),
        }
    }

    /// Create a new forensic analyzer with custom configuration
    #[must_use]
    pub fn with_config(config: ForensicConfig) -> Self {
        Self { config }
    }

    /// Reconstruct complete timeline from cookies
    ///
    /// This analyzes all cookies and reconstructs a chronological timeline
    /// of cookie events (creation, modification, access, deletion).
    pub fn reconstruct_timeline(&self, cookies: &[Cookie]) -> Result<CookieTimeline> {
        timeline::CookieTimeline::reconstruct(cookies, &self.config)
    }

    /// Decode iOS binary cookie file
    ///
    /// iOS stores cookies in a proprietary binary format (binarycookies).
    /// This function parses that format and extracts all cookies.
    pub fn decode_ios_binary(&self, data: &[u8]) -> Result<Vec<Cookie>> {
        ios_binary::IosBinaryCookieParser::parse_binary_cookie_file(data)
    }

    /// Analyze Google Analytics cookies
    ///
    /// Extract user journey, search terms, campaign info, and page views
    /// from Google Analytics cookies (_ga, _gid, etc.)
    pub fn analyze_google_analytics(
        &self,
        cookies: &[Cookie],
    ) -> Result<Vec<GoogleAnalyticsCookie>> {
        let mut ga_cookies = Vec::new();

        for cookie in cookies {
            if cookie.name.starts_with("_ga") || cookie.name.starts_with("_gid") {
                if let Ok(ga_cookie) = GoogleAnalyticsCookie::decode(cookie) {
                    ga_cookies.push(ga_cookie);
                }
            }
        }

        Ok(ga_cookies)
    }

    /// Decode cookie value (Base64, Hex, timestamps, GUIDs, etc.)
    pub fn decode_cookie(&self, cookie: &Cookie) -> Result<DecodedCookie> {
        cookie_decoder::CookieDecoder::decode(cookie)
    }

    /// Collect evidence with chain-of-custody
    ///
    /// This ensures forensic integrity by maintaining a complete
    /// audit trail of who accessed the evidence and when.
    pub fn collect_evidence(&self, cookies: &[Cookie]) -> Result<evidence_collector::Evidence> {
        evidence_collector::EvidenceCollector::collect(cookies, &self.config)
    }

    /// Generate complete forensic report
    ///
    /// Creates a court-ready forensic report with:
    /// - Timeline of events
    /// - Anomalies detected
    /// - Evidence chain-of-custody
    /// - Technical analysis
    /// - Executive summary
    pub fn generate_report(&self, cookies: &[Cookie]) -> Result<ForensicReport> {
        let timeline = self.reconstruct_timeline(cookies)?;
        let evidence = self.collect_evidence(cookies)?;

        ForensicReportBuilder::new()
            .with_timeline(timeline)
            .with_evidence(evidence)
            .with_config(&self.config)
            .build()
    }
}

impl Default for ForensicAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// Decoded cookie information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodedCookie {
    /// Original cookie
    pub original: Cookie,

    /// Detected encoding types
    pub encodings: Vec<EncodingType>,

    /// Decoded values
    pub decoded_values: HashMap<String, String>,

    /// Is the value a timestamp?
    pub is_timestamp: bool,

    /// Parsed timestamp (if applicable)
    pub timestamp: Option<DateTime<Utc>>,

    /// Is the value a GUID/UUID?
    pub is_guid: bool,

    /// Parsed GUID (if applicable)
    pub guid: Option<String>,

    /// Contains structured data (JSON, etc.)
    pub structured_data: Option<serde_json::Value>,
}

/// Types of encoding detected in cookie values
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EncodingType {
    /// Base64 encoding
    Base64,

    /// Hexadecimal encoding
    Hex,

    /// URL encoding
    UrlEncoded,

    /// Unix timestamp (seconds since epoch)
    UnixTimestamp,

    /// UUID/GUID
    Uuid,

    /// JSON structure
    Json,

    /// Plain text
    PlainText,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_forensic_analyzer_creation() {
        let analyzer = ForensicAnalyzer::new();
        assert!(analyzer.config.enable_chain_of_custody);
    }

    #[test]
    fn test_forensic_config_default() {
        let config = ForensicConfig::default();
        assert_eq!(config.timezone, "UTC");
        assert_eq!(config.anomaly_threshold, 0.7);
    }
}
