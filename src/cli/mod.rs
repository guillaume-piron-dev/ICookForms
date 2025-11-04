//! CLI module for `ICOokForms`
//!
//! This module provides the command-line interface for `ICOokForms`.

pub mod commands;
pub mod output;

use clap::{Parser, Subcommand, ValueEnum};

/// Main CLI structure
#[derive(Parser)]
#[command(name = "icookforms")]
#[command(version, about, long_about = None)]
pub struct Cli {
    /// Command to execute
    #[command(subcommand)]
    pub command: Commands,
}

/// Available CLI commands
#[derive(Subcommand)]
pub enum Commands {
    /// Scan a website for cookies
    Scan(commands::ScanArgs),

    /// Analyze cookies for security and compliance
    Analyze(commands::AnalyzeArgs),

    /// Generate a compliance report
    Report(commands::ReportArgs),

    /// Check compliance with regulations
    Compliance(commands::ComplianceArgs),

    /// Digital forensics analysis
    Forensics(commands::ForensicsArgs),

    /// ML/AI anomaly detection
    Ml(commands::MlArgs),

    /// Display version information
    Version,
}

/// Output format for CLI commands
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum OutputFormat {
    /// Human-readable format with colors
    Human,
    /// JSON format
    Json,
    /// YAML format
    Yaml,
    /// CSV format (for tabular data)
    Csv,
}

impl Default for OutputFormat {
    fn default() -> Self {
        Self::Human
    }
}

impl OutputFormat {
    /// Check if this format is human-readable
    #[must_use]
    pub fn is_human_readable(&self) -> bool {
        matches!(self, Self::Human)
    }

    /// Check if this format is machine-readable
    #[must_use]
    pub fn is_machine_readable(&self) -> bool {
        !self.is_human_readable()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_output_format_default() {
        let format = OutputFormat::default();
        assert!(matches!(format, OutputFormat::Human));
    }

    #[test]
    fn test_output_format_human_readable() {
        assert!(OutputFormat::Human.is_human_readable());
        assert!(!OutputFormat::Json.is_human_readable());
        assert!(!OutputFormat::Yaml.is_human_readable());
    }

    #[test]
    fn test_output_format_machine_readable() {
        assert!(!OutputFormat::Human.is_machine_readable());
        assert!(OutputFormat::Json.is_machine_readable());
        assert!(OutputFormat::Yaml.is_machine_readable());
    }
}
