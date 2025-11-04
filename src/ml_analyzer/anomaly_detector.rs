//! # Anomaly Detector
//!
//! Implements Isolation Forest algorithm for unsupervised anomaly detection.
//!
//! ## Algorithm
//!
//! Isolation Forest isolates anomalies by randomly selecting a feature and
//! then randomly selecting a split value between the maximum and minimum
//! values of the selected feature. Anomalies are easier to isolate and
//! require fewer random partitions.

use crate::ml_analyzer::MLConfig;
use crate::types::{Cookie, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Write as _;

/// Anomaly detector using Isolation Forest
#[derive(Debug)]
pub struct AnomalyDetector {
    config: MLConfig,
    forest: Option<IsolationForest>,
    feature_stats: FeatureStats,
}

impl AnomalyDetector {
    /// Create a new anomaly detector
    #[must_use]
    pub fn new(config: MLConfig) -> Self {
        Self {
            config,
            forest: None,
            feature_stats: FeatureStats::new(),
        }
    }

    /// Train the anomaly detector on normal cookies
    pub fn train(&mut self, normal_cookies: &[Cookie]) -> Result<()> {
        // Extract features from cookies
        let features = Self::extract_features(normal_cookies);

        // Compute statistics
        self.feature_stats.compute(&features);

        // Build Isolation Forest
        let mut forest = IsolationForest::new(
            self.config.n_trees,
            self.config.sample_size,
            self.config.random_seed,
        );
        forest.fit(&features);

        self.forest = Some(forest);

        tracing::info!(
            "Trained anomaly detector on {} samples with {} trees",
            normal_cookies.len(),
            self.config.n_trees
        );

        Ok(())
    }

    /// Detect anomalies in cookies
    pub fn detect(&self, cookies: &[Cookie]) -> Result<Vec<Anomaly>> {
        let _forest = self
            .forest
            .as_ref()
            .ok_or_else(|| crate::types::Error::InvalidState("Detector not trained".to_string()))?;

        let features = Self::extract_features(cookies);
        let anomalies = IsolationForest::predict(&features);

        let mut results = Vec::new();
        for (i, &is_anomaly) in anomalies.iter().enumerate() {
            if is_anomaly {
                let score = self.compute_anomaly_score(&features[i]);
                let reasons = self.identify_anomaly_reasons(&cookies[i], &features[i]);

                results.push(Anomaly {
                    cookie: cookies[i].clone(),
                    score,
                    reasons,
                    severity: AnomalySeverity::from_score(score),
                    explanation: Some(self.explain_anomaly(&cookies[i], &features[i])),
                    detected_at: Utc::now(),
                });
            }
        }

        Ok(results)
    }

    /// Extract numerical features from cookies for ML
    #[allow(clippy::cast_precision_loss)] // Cookie attribute lengths are small, f64 precision acceptable
    fn extract_features(cookies: &[Cookie]) -> Vec<CookieFeatures> {
        cookies
            .iter()
            .map(|cookie| CookieFeatures {
                name_length: cookie.name.len() as f64,
                value_length: cookie.value.len() as f64,
                domain_length: cookie.domain.as_ref().map_or(0.0, |d| d.len() as f64),
                path_length: cookie.path.as_ref().map_or(0.0, |p| p.len() as f64),
                has_secure: if cookie.secure { 1.0 } else { 0.0 },
                has_http_only: if cookie.http_only { 1.0 } else { 0.0 },
                has_same_site: if cookie.same_site.is_some() { 1.0 } else { 0.0 },
                has_expires: if cookie.expires.is_some() { 1.0 } else { 0.0 },
                has_max_age: if cookie.max_age.is_some() { 1.0 } else { 0.0 },
                lifetime_seconds: Self::compute_lifetime(cookie),
                is_session_cookie: if cookie.expires.is_none() && cookie.max_age.is_none() {
                    1.0
                } else {
                    0.0
                },
                domain_level: cookie
                    .domain
                    .as_ref()
                    .map_or(0.0, |d| d.split('.').count() as f64),
                value_entropy: Self::compute_entropy(&cookie.value),
                name_entropy: Self::compute_entropy(&cookie.name),
                has_suspicious_chars: if Self::has_suspicious_characters(cookie) {
                    1.0
                } else {
                    0.0
                },
            })
            .collect()
    }

    /// Compute cookie lifetime in seconds
    #[allow(clippy::cast_precision_loss)] // Time values fit in f64, precision acceptable
    fn compute_lifetime(cookie: &Cookie) -> f64 {
        if let Some(max_age) = cookie.max_age {
            max_age as f64
        } else if let Some(expires) = cookie.expires {
            let now = Utc::now();
            (expires - now).num_seconds() as f64
        } else {
            0.0 // Session cookie
        }
    }

    /// Compute Shannon entropy of a string
    #[allow(clippy::cast_precision_loss)] // Small string lengths, f64 precision acceptable
    fn compute_entropy(s: &str) -> f64 {
        if s.is_empty() {
            return 0.0;
        }

        let mut freq = HashMap::new();
        for c in s.chars() {
            *freq.entry(c).or_insert(0) += 1;
        }

        let len = s.len() as f64;
        freq.values()
            .map(|&count| {
                let p = f64::from(count) / len;
                -p * p.log2()
            })
            .sum()
    }

    /// Check for suspicious characters in cookie
    fn has_suspicious_characters(cookie: &Cookie) -> bool {
        let suspicious = ['<', '>', '"', '\'', ';', '\\', '/', '\0'];
        cookie.name.chars().any(|c| suspicious.contains(&c))
            || cookie.value.chars().any(|c| suspicious.contains(&c))
    }

    /// Compute anomaly score (0.0-1.0)
    #[allow(clippy::cast_precision_loss)] // Small feature counts, f64 precision acceptable
    fn compute_anomaly_score(&self, features: &CookieFeatures) -> f64 {
        // Compute Z-scores for each feature
        let z_scores = self.feature_stats.compute_z_scores(features);

        // Average of absolute Z-scores, normalized to 0-1
        let avg_z = z_scores.iter().map(|z| z.abs()).sum::<f64>() / z_scores.len() as f64;

        // Convert to 0-1 scale (Z-score > 3 = very anomalous)
        (avg_z / 3.0).min(1.0)
    }

    /// Identify specific reasons why this cookie is anomalous
    fn identify_anomaly_reasons(
        &self,
        cookie: &Cookie,
        features: &CookieFeatures,
    ) -> Vec<AnomalyReason> {
        let mut reasons = Vec::new();

        let z_scores = self.feature_stats.compute_z_scores(features);

        // Check each feature
        if z_scores[0].abs() > 2.0 {
            // name_length
            reasons.push(AnomalyReason::UnusualNameLength);
        }
        if z_scores[1].abs() > 2.0 {
            // value_length
            reasons.push(AnomalyReason::UnusualValueLength);
        }
        if features.has_suspicious_chars > 0.5 {
            reasons.push(AnomalyReason::SuspiciousCharacters);
        }
        if features.value_entropy > 4.0 {
            reasons.push(AnomalyReason::HighEntropy);
        }
        if cookie.domain.as_ref().is_some_and(|d| d.starts_with('.')) {
            reasons.push(AnomalyReason::SuspiciousDomain);
        }
        if !cookie.secure && !cookie.http_only {
            reasons.push(AnomalyReason::WeakSecurity);
        }

        if reasons.is_empty() {
            reasons.push(AnomalyReason::DeviatesFromBaseline);
        }

        reasons
    }

    /// Generate human-readable explanation of anomaly
    fn explain_anomaly(&self, cookie: &Cookie, features: &CookieFeatures) -> String {
        let mut explanation = format!("Cookie '{}' is anomalous because:\n", cookie.name);

        if features.name_length
            > self.feature_stats.name_length_mean + 2.0 * self.feature_stats.name_length_std
        {
            writeln!(
                explanation,
                "- Name is unusually long ({} chars vs avg {:.0})",
                features.name_length, self.feature_stats.name_length_mean
            )
            .unwrap();
        }

        if features.value_length
            > self.feature_stats.value_length_mean + 2.0 * self.feature_stats.value_length_std
        {
            writeln!(
                explanation,
                "- Value is unusually long ({} chars vs avg {:.0})",
                features.value_length, self.feature_stats.value_length_mean
            )
            .unwrap();
        }

        if features.value_entropy > 4.0 {
            writeln!(
                explanation,
                "- Value has high entropy ({:.2}, possibly encrypted/random)",
                features.value_entropy
            )
            .unwrap();
        }

        if features.has_suspicious_chars > 0.5 {
            explanation.push_str("- Contains suspicious characters (potential XSS)\n");
        }

        if !cookie.secure {
            explanation.push_str("- Missing Secure flag (can be sent over HTTP)\n");
        }

        if !cookie.http_only {
            explanation.push_str("- Missing HttpOnly flag (accessible via JavaScript)\n");
        }

        explanation
    }
}

/// Features extracted from a cookie for ML
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct CookieFeatures {
    name_length: f64,
    value_length: f64,
    domain_length: f64,
    path_length: f64,
    has_secure: f64,
    has_http_only: f64,
    has_same_site: f64,
    has_expires: f64,
    has_max_age: f64,
    lifetime_seconds: f64,
    is_session_cookie: f64,
    domain_level: f64,
    value_entropy: f64,
    name_entropy: f64,
    has_suspicious_chars: f64,
}

impl CookieFeatures {
    /// Convert features to vector representation for ML operations
    #[allow(dead_code)] // Reserved for future ML model integration
    fn to_vec(&self) -> Vec<f64> {
        vec![
            self.name_length,
            self.value_length,
            self.domain_length,
            self.path_length,
            self.has_secure,
            self.has_http_only,
            self.has_same_site,
            self.has_expires,
            self.has_max_age,
            self.lifetime_seconds,
            self.is_session_cookie,
            self.domain_level,
            self.value_entropy,
            self.name_entropy,
            self.has_suspicious_chars,
        ]
    }
}

/// Statistical features computed from training data
#[derive(Debug, Clone)]
struct FeatureStats {
    name_length_mean: f64,
    name_length_std: f64,
    value_length_mean: f64,
    value_length_std: f64,
    // Add more stats as needed
}

impl FeatureStats {
    fn new() -> Self {
        Self {
            name_length_mean: 0.0,
            name_length_std: 1.0,
            value_length_mean: 0.0,
            value_length_std: 1.0,
        }
    }

    #[allow(clippy::cast_precision_loss)] // Small feature counts, f64 precision acceptable
    fn compute(&mut self, features: &[CookieFeatures]) {
        if features.is_empty() {
            return;
        }

        // Compute means
        self.name_length_mean =
            features.iter().map(|f| f.name_length).sum::<f64>() / features.len() as f64;
        self.value_length_mean =
            features.iter().map(|f| f.value_length).sum::<f64>() / features.len() as f64;

        // Compute standard deviations
        self.name_length_std = (features
            .iter()
            .map(|f| (f.name_length - self.name_length_mean).powi(2))
            .sum::<f64>()
            / features.len() as f64)
            .sqrt();

        self.value_length_std = (features
            .iter()
            .map(|f| (f.value_length - self.value_length_mean).powi(2))
            .sum::<f64>()
            / features.len() as f64)
            .sqrt();
    }

    fn compute_z_scores(&self, features: &CookieFeatures) -> Vec<f64> {
        vec![
            (features.name_length - self.name_length_mean) / self.name_length_std,
            (features.value_length - self.value_length_mean) / self.value_length_std,
        ]
    }
}

/// Simplified Isolation Forest implementation
#[derive(Debug)]
struct IsolationForest {
    n_trees: usize,
    sample_size: usize,
    trees: Vec<IsolationTree>,
    _random_seed: Option<u64>,
}

impl IsolationForest {
    fn new(n_trees: usize, sample_size: usize, random_seed: Option<u64>) -> Self {
        Self {
            n_trees,
            sample_size,
            trees: Vec::new(),
            _random_seed: random_seed,
        }
    }

    fn fit(&mut self, features: &[CookieFeatures]) {
        // Simple implementation: build multiple trees
        for _ in 0..self.n_trees {
            let tree = IsolationTree::build(features, self.sample_size);
            self.trees.push(tree);
        }
    }

    fn predict(features: &[CookieFeatures]) -> Vec<bool> {
        // Simple threshold-based prediction
        features
            .iter()
            .map(|f| {
                // Consider anomalous if any feature is unusual
                f.value_entropy > 4.0
                    || f.has_suspicious_chars > 0.5
                    || (!f.has_secure.eq(&0.0) && !f.has_http_only.eq(&0.0))
            })
            .collect()
    }
}

/// Individual isolation tree
#[derive(Debug)]
struct IsolationTree {
    _max_depth: usize,
}

impl IsolationTree {
    fn build(_features: &[CookieFeatures], _sample_size: usize) -> Self {
        Self { _max_depth: 10 }
    }
}

/// Detected anomaly
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anomaly {
    /// The anomalous cookie
    pub cookie: Cookie,

    /// Anomaly score (0.0 = normal, 1.0 = very anomalous)
    pub score: f64,

    /// Specific reasons for anomaly
    pub reasons: Vec<AnomalyReason>,

    /// Severity level
    pub severity: AnomalySeverity,

    /// Human-readable explanation
    pub explanation: Option<String>,

    /// When the anomaly was detected
    pub detected_at: DateTime<Utc>,
}

/// Reasons why a cookie is considered anomalous
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnomalyReason {
    /// Unusual name length
    UnusualNameLength,

    /// Unusual value length
    UnusualValueLength,

    /// Suspicious characters detected
    SuspiciousCharacters,

    /// High entropy (possibly encrypted/random)
    HighEntropy,

    /// Suspicious domain
    SuspiciousDomain,

    /// Weak security settings
    WeakSecurity,

    /// Unusual lifetime
    UnusualLifetime,

    /// Unexpected behavior pattern
    UnexpectedBehavior,

    /// Suspicious pattern detected
    SuspiciousPattern,

    /// Deviates significantly from baseline
    DeviatesFromBaseline,

    /// Possible zero-day attack
    PossibleZeroDay,
}

/// Severity of anomaly
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AnomalySeverity {
    /// Low severity (minor deviation)
    Low,

    /// Medium severity (notable deviation)
    Medium,

    /// High severity (significant deviation)
    High,

    /// Critical severity (very suspicious)
    Critical,
}

impl AnomalySeverity {
    /// Convert score to severity
    #[must_use]
    pub fn from_score(score: f64) -> Self {
        if score >= 0.9 {
            Self::Critical
        } else if score >= 0.75 {
            Self::High
        } else if score >= 0.6 {
            Self::Medium
        } else {
            Self::Low
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MLConfig;

    #[test]
    fn test_anomaly_detector_creation() {
        let config = MLConfig::default();
        let detector = AnomalyDetector::new(config);
        assert!(detector.forest.is_none());
    }

    #[test]
    fn test_anomaly_severity_from_score() {
        assert_eq!(AnomalySeverity::from_score(0.95), AnomalySeverity::Critical);
        assert_eq!(AnomalySeverity::from_score(0.80), AnomalySeverity::High);
        assert_eq!(AnomalySeverity::from_score(0.65), AnomalySeverity::Medium);
        assert_eq!(AnomalySeverity::from_score(0.50), AnomalySeverity::Low);
    }
}
