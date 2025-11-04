//! Core types and data structures for `ICOokForms`

pub mod config;
pub mod cookie;
pub mod error;
pub mod issue;
pub mod regulation;
pub mod report;

// Re-exports
pub use config::{AnalysisConfig, Config, ReportConfig, ScanConfig};
pub use cookie::{Cookie, CookieAttribute, SameSite};
pub use error::{Error, Result};
pub use issue::{ComplianceIssue, Issue, IssueCategory, SecurityIssue, Severity};
pub use regulation::Regulation;
pub use report::{AnalysisResult, ComplianceResult, ScanResult};
