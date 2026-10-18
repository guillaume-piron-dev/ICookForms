//! # `ICOokForms` - The World's Reference Cookie Audit Software
//!
//! `ICOokForms` is a comprehensive, enterprise-grade cookie analysis and audit tool
//! designed to ensure security, compliance, and privacy for web applications.
//!
//! ## Features
//!
//! - **Security Analysis**: Detect XSS, CSRF, Session Hijacking, and more
//! - **Compliance Checking**: GDPR, CCPA, LGPD, and 50+ regulations
//! - **RFC 6265 Compliance**: Full RFC 6265 and RFC 6265bis support

// Allow multiple crate versions - transitive dependencies from different crates
#![allow(clippy::multiple_crate_versions)]
//! - **🔥 Digital Forensics**: Timeline reconstruction, iOS binary parsing, GA analysis (UNIQUE!)
//! - **🤖 ML/AI Anomaly Detection**: Machine learning-powered anomaly detection (UNIQUE!)

// Temporary allowances for Excellence Achievement - Phase 1
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::format_push_string)]
#![allow(clippy::trivially_copy_pass_by_ref)]
#![allow(clippy::should_implement_trait)]
#![allow(clippy::unnecessary_wraps)]
#![allow(clippy::unused_self)]
#![allow(clippy::redundant_closure)]
#![allow(clippy::redundant_closure_for_method_calls)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::case_sensitive_file_extension_comparisons)]
#![allow(clippy::return_self_not_must_use)]
#![allow(clippy::must_use_candidate)]
//! - **Supply Chain Security**: Detect npm/PyPI vulnerabilities
//! - **Real-time Monitoring**: Track cookies in real-time
//! - **Comprehensive Reporting**: JSON, CSV, PDF, HTML exports
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use icookforms::{Scanner, Analyzer};
//! use icookforms::types::config::ScanConfig;
//! use tokio;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create scanner with configuration
//!     let config = ScanConfig::default();
//!     let scanner = Scanner::new(config)?;
//!     
//!     // Scan a website for cookies
//!     let scan_result = scanner.scan("https://example.com").await?;
//!     
//!     // Analyze cookies for security and compliance
//!     let analyzer = Analyzer::new();
//!     let results = analyzer.analyze_batch(&scan_result.cookies);
//!     
//!     // Print summary
//!     println!("Found {} cookies", scan_result.cookies.len());
//!     println!("Security issues: {}", results.security_issues.len());
//!     println!("Compliance issues: {}", results.compliance_issues.len());
//!     
//!     Ok(())
//! }
//! ```
//!
//! ## Architecture
//!
//! `ICOokForms` is organized into the following modules:
//!
//! - [`scanner`]: HTTP scanning and cookie extraction
//! - [`parser`]: RFC 6265 compliant cookie parsing
//! - [`analyzer`]: Security and compliance analysis
//! - [`compliance`]: GDPR, CCPA, and regulation checking
//! - [`forensics`]: 🔥 **UNIQUE** - Digital forensics (timeline, iOS binary, GA analysis)
//! - [`ml_analyzer`]: 🤖 **UNIQUE** - ML/AI anomaly detection (behavioral analysis, pattern recognition)
//! - [`reporter`]: Report generation (JSON, PDF, CSV, HTML)
//! - [`types`]: Core types and data structures
//!
//! ## Safety and Performance
//!
//! `ICOokForms` is built with safety and performance in mind:
//!
//! - Zero unsafe code (except in well-justified crypto operations)
//! - Comprehensive error handling with `thiserror`
//! - Async/await with Tokio runtime
//! - Zero-copy parsing where possible
//! - Concurrent analysis with Rayon
//!
//! ## License
//!
//! Licensed under the Apache License, Version 2.0

#![warn(missing_docs)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
// Disable cargo lints - multiple crate versions are outside our control (transitive deps)
// #![warn(clippy::cargo)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
// Test assertions: `assert!(x.is_empty())` reads better than `assert_eq!(x, [] as [T; 0])`
#![cfg_attr(test, allow(clippy::assert_is_empty))]

// Public modules
pub mod analyzer;
pub mod cli;
pub mod compliance;
pub mod forensics;
pub mod ml_analyzer;
pub mod parser;
pub mod reporter;
pub mod scanner;
pub mod storage;
pub mod types;
pub mod utils;

// Re-exports for convenience
pub use types::{Config, Cookie, CookieAttribute, Error, Regulation, Result, Severity};

// Re-export types from their correct locations
pub use types::config::{AnalysisConfig, ScanConfig};
pub use types::issue::{ComplianceIssue, Issue, IssueCategory, SecurityIssue};
pub use types::report::{AnalysisResult, ComplianceResult, ScanResult};

// Re-export main components
pub use analyzer::Analyzer;
pub use compliance::ComplianceChecker;
pub use parser::{CookieParser, ParseError};
pub use reporter::{ReportFormat, Reporter};
pub use scanner::{Scanner, ScannerBuilder};

// Re-export ML/AI components
pub use ml_analyzer::{Anomaly, AnomalySeverity, MLAnalyzer, MLConfig};

// Library version and metadata
/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Library name
pub const NAME: &str = env!("CARGO_PKG_NAME");

/// Library authors
pub const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");

/// Library description
pub const DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");

/// Initialize the library with tracing
///
/// This should be called once at the start of your application to set up
/// structured logging with tracing.
///
/// # Examples
///
/// ```rust,no_run
/// use icookforms;
///
/// icookforms::init_tracing();
/// // Your application code
/// ```
pub fn init_tracing() {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("icookforms=info")),
        )
        .init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::const_is_empty)]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn test_name() {
        assert_eq!(NAME, "icookforms");
    }
}
