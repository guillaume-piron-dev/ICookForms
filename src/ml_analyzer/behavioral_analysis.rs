//! # Behavioral Analysis
//!
//! Analyzes cookie behavior patterns and detects deviations from normal behavior.

use crate::types::{Cookie, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Behavioral analyzer
#[derive(Debug)]
pub struct BehavioralAnalyzer {
    baseline: Option<BehavioralBaseline>,
}

impl BehavioralAnalyzer {
    /// Create a new behavioral analyzer
    #[must_use]
    pub fn new() -> Self {
        Self { baseline: None }
    }

    /// Train on normal behavior
    pub fn train(&mut self, normal_cookies: &[Cookie]) -> Result<()> {
        let mut baseline = BehavioralBaseline::new();
        baseline.learn(normal_cookies);
        self.baseline = Some(baseline);

        tracing::info!(
            "Learned behavioral baseline from {} cookies",
            normal_cookies.len()
        );
        Ok(())
    }

    /// Detect behavior changes
    pub fn detect_changes(&self, cookies: &[Cookie]) -> Result<Vec<BehaviorChange>> {
        let baseline = self.baseline.as_ref().ok_or_else(|| {
            crate::types::Error::InvalidState("Behavioral analyzer not trained".to_string())
        })?;

        let mut changes = Vec::new();

        for cookie in cookies {
            if let Some(change) = baseline.detect_deviation(cookie) {
                changes.push(change);
            }
        }

        Ok(changes)
    }

    /// Analyze behavior
    pub fn analyze(&self, cookies: &[Cookie]) -> Result<BehaviorReport> {
        let baseline = self.baseline.as_ref().ok_or_else(|| {
            crate::types::Error::InvalidState("Behavioral analyzer not trained".to_string())
        })?;

        Ok(BehaviorReport {
            baseline: baseline.clone(),
            cookies_analyzed: cookies.len(),
            deviations: self.detect_changes(cookies)?,
            timestamp: Utc::now(),
        })
    }
}

impl Default for BehavioralAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// Behavioral baseline learned from normal cookies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralBaseline {
    /// Normal cookie count range
    pub normal_cookie_count: (usize, usize),

    /// Common cookie names
    pub common_names: Vec<String>,

    /// Common domains
    pub common_domains: Vec<String>,

    /// Typical security patterns
    pub security_patterns: SecurityPatterns,
}

impl BehavioralBaseline {
    fn new() -> Self {
        Self {
            normal_cookie_count: (0, 0),
            common_names: Vec::new(),
            common_domains: Vec::new(),
            security_patterns: SecurityPatterns::default(),
        }
    }

    #[allow(clippy::cast_precision_loss)] // Small cookie counts, f64 precision acceptable
    fn learn(&mut self, cookies: &[Cookie]) {
        // Learn cookie count range
        self.normal_cookie_count = (cookies.len().saturating_sub(10), cookies.len() + 10);

        // Extract common names
        let mut name_freq: HashMap<String, usize> = HashMap::new();
        for cookie in cookies {
            *name_freq.entry(cookie.name.clone()).or_insert(0) += 1;
        }
        self.common_names = name_freq
            .into_iter()
            .filter(|(_, count)| *count > cookies.len() / 10)
            .map(|(name, _)| name)
            .collect();

        // Extract common domains
        let mut domain_freq: HashMap<String, usize> = HashMap::new();
        for cookie in cookies {
            if let Some(ref domain) = cookie.domain {
                *domain_freq.entry(domain.clone()).or_insert(0) += 1;
            }
        }
        self.common_domains = domain_freq
            .into_iter()
            .filter(|(_, count)| *count > cookies.len() / 10)
            .map(|(domain, _)| domain)
            .collect();

        // Learn security patterns
        let secure_count = cookies.iter().filter(|c| c.secure).count();
        let httponly_count = cookies.iter().filter(|c| c.http_only).count();

        self.security_patterns.typical_secure_percentage =
            secure_count as f64 / cookies.len() as f64;
        self.security_patterns.typical_httponly_percentage =
            httponly_count as f64 / cookies.len() as f64;
    }

    fn detect_deviation(&self, cookie: &Cookie) -> Option<BehaviorChange> {
        let mut reasons = Vec::new();

        // Check if name is uncommon
        if !self.common_names.contains(&cookie.name) {
            reasons.push("Uncommon cookie name".to_string());
        }

        // Check if domain is uncommon
        if let Some(ref domain) = cookie.domain {
            if !self.common_domains.contains(domain) {
                reasons.push("Uncommon domain".to_string());
            }
        }

        // Check security deviations
        if !cookie.secure && self.security_patterns.typical_secure_percentage > 0.7 {
            reasons.push("Missing Secure flag (uncommon for this site)".to_string());
        }

        if reasons.is_empty() {
            None
        } else {
            Some(BehaviorChange {
                cookie: cookie.clone(),
                reasons,
                severity_score: 0.6,
                description: "Cookie behavior deviates from learned baseline".to_string(),
            })
        }
    }
}

/// Security patterns learned from baseline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPatterns {
    /// Percentage of cookies with `Secure` flag
    pub typical_secure_percentage: f64,

    /// Percentage of cookies with `HttpOnly` flag
    pub typical_httponly_percentage: f64,
}

impl Default for SecurityPatterns {
    fn default() -> Self {
        Self {
            typical_secure_percentage: 0.5,
            typical_httponly_percentage: 0.5,
        }
    }
}

/// Detected behavior change
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorChange {
    /// The cookie with unexpected behavior
    pub cookie: Cookie,

    /// Reasons for the change
    pub reasons: Vec<String>,

    /// Severity score (0.0-1.0)
    pub severity_score: f64,

    /// Description
    pub description: String,
}

/// Behavior analysis report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorReport {
    /// Learned baseline
    pub baseline: BehavioralBaseline,

    /// Number of cookies analyzed
    pub cookies_analyzed: usize,

    /// Detected deviations
    pub deviations: Vec<BehaviorChange>,

    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_behavioral_analyzer_creation() {
        let analyzer = BehavioralAnalyzer::new();
        assert!(analyzer.baseline.is_none());
    }
}
