//! # Forensic Report Generator
//!
//! Generate court-ready forensic reports

use crate::forensics::evidence_collector::Evidence;
use crate::forensics::{CookieTimeline, ForensicConfig};
use chrono::Utc;
use serde::{Deserialize, Serialize};

/// Complete forensic report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicReport {
    /// Report ID
    pub id: String,

    /// Generation timestamp
    pub generated_at: chrono::DateTime<Utc>,

    /// Executive summary
    pub executive_summary: String,

    /// Timeline analysis
    pub timeline: Option<CookieTimeline>,

    /// Evidence
    pub evidence: Option<Evidence>,

    /// Findings
    pub findings: Vec<String>,

    /// Conclusions
    pub conclusions: Vec<String>,
}

/// Builder for forensic reports
pub struct ForensicReportBuilder {
    timeline: Option<CookieTimeline>,
    evidence: Option<Evidence>,
    config: Option<ForensicConfig>,
}

impl ForensicReportBuilder {
    /// Create a new forensic report builder
    #[must_use]
    pub fn new() -> Self {
        Self {
            timeline: None,
            evidence: None,
            config: None,
        }
    }

    /// Add timeline to the report
    #[must_use]
    pub fn with_timeline(mut self, timeline: CookieTimeline) -> Self {
        self.timeline = Some(timeline);
        self
    }

    /// Add evidence to the report
    #[must_use]
    pub fn with_evidence(mut self, evidence: Evidence) -> Self {
        self.evidence = Some(evidence);
        self
    }

    /// Add configuration to the report
    #[must_use]
    pub fn with_config(mut self, config: &ForensicConfig) -> Self {
        self.config = Some(config.clone());
        self
    }

    /// Build the forensic report
    pub fn build(self) -> crate::types::Result<ForensicReport> {
        Ok(ForensicReport {
            id: uuid::Uuid::new_v4().to_string(),
            generated_at: Utc::now(),
            executive_summary: "Forensic analysis completed".to_string(),
            timeline: self.timeline,
            evidence: self.evidence,
            findings: Vec::new(),
            conclusions: Vec::new(),
        })
    }
}

impl Default for ForensicReportBuilder {
    fn default() -> Self {
        Self::new()
    }
}
