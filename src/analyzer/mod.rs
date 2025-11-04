//! Cookie security and compliance analyzer

pub mod compliance;
pub mod security;
pub mod tracking;

use crate::types::config::AnalysisConfig;
use crate::types::{AnalysisResult, Cookie};

/// Main cookie analyzer
pub struct Analyzer {
    config: AnalysisConfig,
}

impl Analyzer {
    /// Create a new analyzer with default configuration
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: AnalysisConfig::default(),
        }
    }

    /// Create an analyzer with custom configuration
    #[must_use]
    pub fn with_config(config: AnalysisConfig) -> Self {
        Self { config }
    }

    /// Analyze a single cookie
    #[must_use]
    pub fn analyze(&self, cookie: &Cookie) -> AnalysisResult {
        let scan_id = uuid::Uuid::new_v4().to_string();
        let mut result = AnalysisResult::new(scan_id);

        // Security analysis - CORRECTED: Pass slice instead of single cookie
        if self.config.security_enabled {
            let security_issues = security::analyze_security(std::slice::from_ref(cookie));
            result.security_issues.extend(security_issues);
        }

        // Compliance analysis
        if self.config.compliance_enabled {
            for regulation in &self.config.regulations {
                let compliance_issues = compliance::check_compliance(cookie, *regulation);
                result.compliance_issues.extend(compliance_issues);
            }
        }

        // Tracking analysis
        if self.config.tracking_enabled {
            if let Some(tracking) = tracking::detect_tracking(cookie) {
                result.tracking_info.push(tracking);
            }
        }

        // Calculate scores
        result.calculate_scores();

        result
    }

    /// Analyze multiple cookies
    #[must_use]
    pub fn analyze_batch(&self, cookies: &[Cookie]) -> AnalysisResult {
        let scan_id = uuid::Uuid::new_v4().to_string();
        let mut result = AnalysisResult::new(scan_id);

        // Security analysis for all cookies
        if self.config.security_enabled {
            let security_issues = security::analyze_security(cookies);
            result.security_issues.extend(security_issues);
        }

        // Compliance and tracking analysis per cookie
        for cookie in cookies {
            // Compliance analysis
            if self.config.compliance_enabled {
                for regulation in &self.config.regulations {
                    let compliance_issues = compliance::check_compliance(cookie, *regulation);
                    result.compliance_issues.extend(compliance_issues);
                }
            }

            // Tracking analysis
            if self.config.tracking_enabled {
                if let Some(tracking) = tracking::detect_tracking(cookie) {
                    result.tracking_info.push(tracking);
                }
            }
        }

        result.calculate_scores();
        result
    }
}

impl Default for Analyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyzer_creation() {
        let analyzer = Analyzer::new();
        assert!(analyzer.config.security_enabled);
    }

    #[test]
    fn test_analyze_cookie() {
        let analyzer = Analyzer::new();
        let cookie = Cookie::new("test".to_string(), "value".to_string());
        let result = analyzer.analyze(&cookie);

        assert!(!result.id.is_empty());
    }

    #[test]
    fn test_analyze_batch() {
        let analyzer = Analyzer::new();
        let cookies = vec![
            Cookie::new("test1".to_string(), "value1".to_string()),
            Cookie::new("test2".to_string(), "value2".to_string()),
        ];
        let result = analyzer.analyze_batch(&cookies);

        assert!(!result.id.is_empty());
    }
}
