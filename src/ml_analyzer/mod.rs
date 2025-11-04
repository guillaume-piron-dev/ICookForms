//! # Machine Learning Anomaly Detection Module
//!
//! This module provides ML/AI-powered anomaly detection for cookies.
//! **NO OTHER COOKIE TOOL IN THE WORLD HAS THIS CAPABILITY.**
//!
//! ## Features
//!
//! - **Isolation Forest**: Unsupervised anomaly detection
//! - **Behavioral Analysis**: Learn normal patterns, detect deviations
//! - **Pattern Recognition**: Identify suspicious cookie patterns
//! - **Zero-Day Detection**: Detect unknown threats without signatures
//! - **Temporal Analysis**: Analyze cookie behavior over time
//!
//! ## Algorithms
//!
//! 1. **Isolation Forest** - Fast, effective unsupervised learning
//! 2. **Statistical Baselines** - Z-scores, IQR, Mahalanobis distance
//! 3. **Deep Learning** (future) - Autoencoders, LSTM
//!
//! ## Examples
//!
//! ```rust,no_run
//! use icookforms::ml_analyzer::{AnomalyDetector, MLConfig};
//! use icookforms::Cookie;
//!
//! let config = MLConfig::default();
//! let mut detector = AnomalyDetector::new(config);
//!
//! // Train on normal cookies
//! let normal_cookies = vec![/* your normal cookies */];
//! detector.train(&normal_cookies)?;
//!
//! // Detect anomalies in new cookies
//! let test_cookies = vec![/* new cookies to analyze */];
//! let anomalies = detector.detect(&test_cookies)?;
//!
//! for anomaly in anomalies {
//!     println!("Suspicious cookie: {} (score: {:.2})",
//!              anomaly.cookie.name, anomaly.score);
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use crate::types::{Cookie, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub mod anomaly_detector;
pub mod behavioral_analysis;
pub mod models;
pub mod pattern_recognition;
pub mod training;
pub mod zero_day_detector;

// Re-exports
pub use anomaly_detector::{Anomaly, AnomalyDetector, AnomalyReason, AnomalySeverity};
pub use behavioral_analysis::{BehaviorChange, BehaviorReport, BehavioralAnalyzer};
pub use pattern_recognition::{CookiePattern, PatternRecognizer, PatternType};
pub use zero_day_detector::{ZeroDayDetector, ZeroDaySignature};

/// Configuration for ML analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MLConfig {
    /// Anomaly score threshold (0.0-1.0)
    /// Higher = fewer false positives, might miss some anomalies
    pub anomaly_threshold: f64,

    /// Number of trees for Isolation Forest
    pub n_trees: usize,

    /// Sample size for each tree
    pub sample_size: usize,

    /// Enable behavioral baseline learning
    pub enable_behavioral_analysis: bool,

    /// Enable pattern recognition
    pub enable_pattern_recognition: bool,

    /// Enable zero-day detection
    pub enable_zero_day_detection: bool,

    /// Minimum training samples required
    pub min_training_samples: usize,

    /// Maximum features to consider
    pub max_features: usize,

    /// Random seed for reproducibility
    pub random_seed: Option<u64>,
}

impl Default for MLConfig {
    fn default() -> Self {
        Self {
            anomaly_threshold: 0.7,
            n_trees: 100,
            sample_size: 256,
            enable_behavioral_analysis: true,
            enable_pattern_recognition: true,
            enable_zero_day_detection: true,
            min_training_samples: 100,
            max_features: 50,
            random_seed: None,
        }
    }
}

/// Main ML analyzer that combines all ML techniques
#[derive(Debug)]
pub struct MLAnalyzer {
    config: MLConfig,
    anomaly_detector: Option<AnomalyDetector>,
    behavioral_analyzer: Option<BehavioralAnalyzer>,
    pattern_recognizer: Option<PatternRecognizer>,
    #[allow(dead_code)]
    zero_day_detector: Option<ZeroDayDetector>,
    is_trained: bool,
}

impl MLAnalyzer {
    /// Create a new ML analyzer with default configuration
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(&MLConfig::default())
    }

    /// Create a new ML analyzer with custom configuration
    #[must_use]
    pub fn with_config(config: &MLConfig) -> Self {
        Self {
            config: config.clone(),
            anomaly_detector: Some(AnomalyDetector::new(config.clone())),
            behavioral_analyzer: if config.enable_behavioral_analysis {
                Some(BehavioralAnalyzer::new())
            } else {
                None
            },
            pattern_recognizer: if config.enable_pattern_recognition {
                Some(PatternRecognizer::new())
            } else {
                None
            },
            zero_day_detector: if config.enable_zero_day_detection {
                Some(ZeroDayDetector::new())
            } else {
                None
            },
            is_trained: false,
        }
    }

    /// Train the ML models on normal cookies
    ///
    /// This creates a baseline of "normal" cookie behavior that will be used
    /// to detect anomalies in future cookies.
    ///
    /// # Arguments
    ///
    /// * `normal_cookies` - A slice of cookies representing normal behavior
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Not enough training samples
    /// - Training fails for any model
    pub fn train(&mut self, normal_cookies: &[Cookie]) -> Result<TrainingReport> {
        if normal_cookies.len() < self.config.min_training_samples {
            return Err(crate::types::Error::InvalidInput(format!(
                "Not enough training samples: {} < {}",
                normal_cookies.len(),
                self.config.min_training_samples
            )));
        }

        let mut report = TrainingReport {
            samples_used: normal_cookies.len(),
            models_trained: Vec::new(),
            training_duration: std::time::Duration::from_secs(0),
            success: true,
        };

        let start_time = std::time::Instant::now();

        // Train anomaly detector
        if let Some(ref mut detector) = self.anomaly_detector {
            match detector.train(normal_cookies) {
                Ok(()) => report.models_trained.push("Anomaly Detector".to_string()),
                Err(e) => {
                    report.success = false;
                    tracing::error!("Failed to train anomaly detector: {}", e);
                }
            }
        }

        // Train behavioral analyzer
        if let Some(ref mut analyzer) = self.behavioral_analyzer {
            match analyzer.train(normal_cookies) {
                Ok(()) => report
                    .models_trained
                    .push("Behavioral Analyzer".to_string()),
                Err(e) => {
                    report.success = false;
                    tracing::error!("Failed to train behavioral analyzer: {}", e);
                }
            }
        }

        // Train pattern recognizer
        if let Some(ref mut recognizer) = self.pattern_recognizer {
            match recognizer.train(normal_cookies) {
                Ok(()) => report.models_trained.push("Pattern Recognizer".to_string()),
                Err(e) => {
                    report.success = false;
                    tracing::error!("Failed to train pattern recognizer: {}", e);
                }
            }
        }

        report.training_duration = start_time.elapsed();
        self.is_trained = report.success;

        Ok(report)
    }

    /// Detect anomalies in cookies
    ///
    /// Analyzes cookies and returns those that deviate from the trained baseline.
    ///
    /// # Arguments
    ///
    /// * `cookies` - Cookies to analyze for anomalies
    ///
    /// # Errors
    ///
    /// Returns an error if the model hasn't been trained yet
    pub fn detect(&self, cookies: &[Cookie]) -> Result<Vec<Anomaly>> {
        if !self.is_trained {
            return Err(crate::types::Error::InvalidState(
                "ML models must be trained before detection".to_string(),
            ));
        }

        let mut all_anomalies = Vec::new();

        // Detect using anomaly detector
        if let Some(ref detector) = self.anomaly_detector {
            let anomalies = detector.detect(cookies)?;
            all_anomalies.extend(anomalies);
        }

        // Detect using behavioral analyzer
        if let Some(ref analyzer) = self.behavioral_analyzer {
            let behavior_changes = analyzer.detect_changes(cookies)?;
            // Convert behavior changes to anomalies
            for change in behavior_changes {
                all_anomalies.push(Anomaly {
                    cookie: change.cookie,
                    score: change.severity_score,
                    reasons: vec![AnomalyReason::UnexpectedBehavior],
                    severity: AnomalySeverity::from_score(change.severity_score),
                    explanation: Some(change.description),
                    detected_at: Utc::now(),
                });
            }
        }

        // Detect using pattern recognizer
        if let Some(ref recognizer) = self.pattern_recognizer {
            let suspicious_patterns = recognizer.find_suspicious(cookies)?;
            for cookie in suspicious_patterns {
                all_anomalies.push(Anomaly {
                    cookie: cookie.clone(),
                    score: 0.8,
                    reasons: vec![AnomalyReason::SuspiciousPattern],
                    severity: AnomalySeverity::High,
                    explanation: Some("Suspicious pattern detected".to_string()),
                    detected_at: Utc::now(),
                });
            }
        }

        // Sort by score (highest first)
        all_anomalies.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        // Filter by threshold
        Ok(all_anomalies
            .into_iter()
            .filter(|a| a.score >= self.config.anomaly_threshold)
            .collect())
    }

    /// Analyze cookie behavior over time
    ///
    /// This provides insights into how cookie behavior is changing
    pub fn analyze_behavior(&self, cookies: &[Cookie]) -> Result<BehaviorReport> {
        if let Some(ref analyzer) = self.behavioral_analyzer {
            analyzer.analyze(cookies)
        } else {
            Err(crate::types::Error::InvalidState(
                "Behavioral analysis is disabled".to_string(),
            ))
        }
    }

    /// Check if the analyzer is trained
    #[must_use]
    pub fn is_trained(&self) -> bool {
        self.is_trained
    }

    /// Get configuration
    #[must_use]
    pub fn config(&self) -> &MLConfig {
        &self.config
    }
}

impl Default for MLAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// Report from training ML models
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingReport {
    /// Number of samples used for training
    pub samples_used: usize,

    /// Models that were successfully trained
    pub models_trained: Vec<String>,

    /// Total training duration
    #[serde(skip)]
    pub training_duration: std::time::Duration,

    /// Whether training was successful
    pub success: bool,
}

/// Complete ML analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MLAnalysisResult {
    /// Detected anomalies
    pub anomalies: Vec<Anomaly>,

    /// Behavioral analysis
    pub behavior: Option<BehaviorReport>,

    /// Overall risk score (0.0-1.0)
    pub risk_score: f64,

    /// Recommendations
    pub recommendations: Vec<String>,

    /// Timestamp of analysis
    pub analyzed_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ml_config_default() {
        let config = MLConfig::default();
        assert_eq!(config.anomaly_threshold, 0.7);
        assert_eq!(config.n_trees, 100);
        assert!(config.enable_behavioral_analysis);
    }

    #[test]
    fn test_ml_analyzer_creation() {
        let analyzer = MLAnalyzer::new();
        assert!(!analyzer.is_trained());
    }

    #[test]
    fn test_ml_analyzer_requires_training() {
        let analyzer = MLAnalyzer::new();
        let cookies = vec![];
        let result = analyzer.detect(&cookies);
        assert!(result.is_err());
    }
}
