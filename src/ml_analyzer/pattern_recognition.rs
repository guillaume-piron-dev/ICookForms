//! # Pattern Recognition
//!
//! Recognizes known malicious cookie patterns and suspicious behaviors.

use crate::types::{Cookie, Result};
use serde::{Deserialize, Serialize};

/// Pattern recognizer
#[derive(Debug)]
pub struct PatternRecognizer {
    patterns: Vec<CookiePattern>,
}

impl PatternRecognizer {
    /// Create a new pattern recognizer
    #[must_use]
    pub fn new() -> Self {
        Self {
            patterns: Self::load_default_patterns(),
        }
    }

    /// Train on normal patterns
    pub fn train(&mut self, _cookies: &[Cookie]) -> Result<()> {
        // For now, we use predefined patterns
        tracing::info!(
            "Pattern recognizer using {} predefined patterns",
            self.patterns.len()
        );
        Ok(())
    }

    /// Find suspicious cookies based on patterns
    pub fn find_suspicious(&self, cookies: &[Cookie]) -> Result<Vec<Cookie>> {
        let mut suspicious = Vec::new();

        for cookie in cookies {
            if self.matches_suspicious_pattern(cookie) {
                suspicious.push(cookie.clone());
            }
        }

        Ok(suspicious)
    }

    /// Check if cookie matches any suspicious pattern
    fn matches_suspicious_pattern(&self, cookie: &Cookie) -> bool {
        self.patterns.iter().any(|pattern| pattern.matches(cookie))
    }

    /// Load default suspicious patterns
    fn load_default_patterns() -> Vec<CookiePattern> {
        vec![
            // XSS indicators
            CookiePattern {
                pattern_type: PatternType::XssIndicator,
                name_regex: Some(r"<script|javascript:|onerror=".to_string()),
                value_regex: Some(r"<script|javascript:|onerror=".to_string()),
                description: "Potential XSS attack pattern".to_string(),
            },
            // Session fixation
            CookiePattern {
                pattern_type: PatternType::SessionFixation,
                name_regex: Some(r"(?i)session|sid|token".to_string()),
                value_regex: Some(r"^[a-f0-9]{32,}$".to_string()),
                description: "Potential session fixation".to_string(),
            },
            // Tracking cookies
            CookiePattern {
                pattern_type: PatternType::Tracking,
                name_regex: Some(r"(?i)_ga|_gid|_fbp|_gcl|doubleclick".to_string()),
                value_regex: None,
                description: "Third-party tracking cookie".to_string(),
            },
        ]
    }
}

impl Default for PatternRecognizer {
    fn default() -> Self {
        Self::new()
    }
}

/// Cookie pattern definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookiePattern {
    /// Type of pattern
    pub pattern_type: PatternType,

    /// Regex to match cookie name (optional)
    pub name_regex: Option<String>,

    /// Regex to match cookie value (optional)
    pub value_regex: Option<String>,

    /// Human-readable description
    pub description: String,
}

impl CookiePattern {
    /// Check if cookie matches this pattern
    fn matches(&self, cookie: &Cookie) -> bool {
        let name_match = self
            .name_regex
            .as_ref()
            .is_none_or(|regex| cookie.name.contains(regex));

        let value_match = self
            .value_regex
            .as_ref()
            .is_none_or(|regex| cookie.value.contains(regex));

        name_match && value_match
    }
}

/// Type of cookie pattern
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PatternType {
    /// XSS attack indicator
    XssIndicator,

    /// CSRF attack indicator
    CsrfIndicator,

    /// Session fixation
    SessionFixation,

    /// Tracking cookie
    Tracking,

    /// Fingerprinting
    Fingerprinting,

    /// Malware signature
    Malware,

    /// Data exfiltration
    Exfiltration,

    /// Supply chain attack
    SupplyChain,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_recognizer_creation() {
        let recognizer = PatternRecognizer::new();
        assert!(!recognizer.patterns.is_empty());
    }
}
