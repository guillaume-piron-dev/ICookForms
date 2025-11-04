//! Report generation module
//!
//! Supports multiple output formats: JSON, CSV, PDF, HTML

pub mod csv;
pub mod html;
pub mod json;
pub mod pdf;

use crate::types::{AnalysisResult, Error, Result};
use std::path::Path;

/// Report format enum
#[derive(Debug, Clone, Copy)]
pub enum ReportFormat {
    /// JSON report format
    Json,
    /// CSV report format for spreadsheets
    Csv,
    /// PDF report format for professional documents
    Pdf,
    /// HTML report format for web viewing
    Html,
}

/// Main reporter struct
pub struct Reporter {
    format: ReportFormat,
}

impl Reporter {
    /// Create a new reporter with specified format
    #[must_use]
    pub fn new(format: ReportFormat) -> Self {
        Self { format }
    }

    /// Generate report and save to file
    pub fn generate(&self, results: &AnalysisResult, output_path: &Path) -> Result<()> {
        match self.format {
            ReportFormat::Json => json::generate(results, output_path),
            ReportFormat::Csv => csv::generate(results, output_path),
            ReportFormat::Pdf => pdf::generate(results, output_path),
            ReportFormat::Html => html::generate(results, output_path),
        }
    }

    /// Generate report as string
    pub fn generate_string(&self, results: &AnalysisResult) -> Result<String> {
        match self.format {
            ReportFormat::Json => json::generate_string(results),
            ReportFormat::Csv => csv::generate_string(results),
            ReportFormat::Pdf => Err(Error::reporter("PDF cannot be generated as string")),
            ReportFormat::Html => html::generate_string(results),
        }
    }
}

impl ReportFormat {
    /// Parse format from string
    pub fn from_string(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "json" => Ok(Self::Json),
            "csv" => Ok(Self::Csv),
            "pdf" => Ok(Self::Pdf),
            "html" => Ok(Self::Html),
            _ => Err(Error::reporter(format!("Unknown format: {s}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_parsing() {
        assert!(matches!(
            ReportFormat::from_string("json").unwrap(),
            ReportFormat::Json
        ));
        assert!(matches!(
            ReportFormat::from_string("HTML").unwrap(),
            ReportFormat::Html
        ));
    }
}
