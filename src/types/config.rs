//! Configuration types for `ICOokForms`

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Main configuration for `ICOokForms`
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    /// Scan configuration
    pub scan: ScanConfig,
    /// Analysis configuration  
    pub analysis: AnalysisConfig,
    /// Report configuration
    pub report: ReportConfig,
    /// Storage configuration
    pub storage: StorageConfig,
}

/// Configuration for cookie scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct ScanConfig {
    /// Maximum number of pages to crawl
    pub max_pages: usize,

    /// Maximum depth for crawling
    pub max_depth: usize,

    /// Request timeout
    pub timeout: Duration,

    /// User agent string
    pub user_agent: String,

    /// Follow redirects
    pub follow_redirects: bool,

    /// Maximum redirects to follow
    pub max_redirects: usize,

    /// Verify SSL certificates
    pub verify_ssl: bool,

    /// HTTP proxy URL
    pub proxy: Option<String>,

    /// Custom headers
    pub headers: Vec<(String, String)>,

    /// Analyze JavaScript-set cookies
    pub analyze_js_cookies: bool,

    /// Execute JavaScript
    pub execute_javascript: bool,

    /// Cookie domains to include (empty = all)
    pub include_domains: Vec<String>,

    /// Cookie domains to exclude
    pub exclude_domains: Vec<String>,

    /// Rate limiting (requests per second)
    pub rate_limit: Option<u32>,

    /// Concurrent requests
    pub concurrency: usize,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            max_pages: 100,
            max_depth: 3,
            timeout: Duration::from_secs(30),
            user_agent: "ICOokForms/1.0".to_string(),
            follow_redirects: true,
            max_redirects: 5,
            verify_ssl: true,
            proxy: None,
            headers: Vec::new(),
            analyze_js_cookies: true,
            execute_javascript: false,
            include_domains: Vec::new(),
            exclude_domains: Vec::new(),
            rate_limit: None,
            concurrency: 4,
        }
    }
}

/// Configuration for cookie analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct AnalysisConfig {
    /// Enable security analysis
    pub security_enabled: bool,

    /// Enable compliance checking
    pub compliance_enabled: bool,

    /// Enable tracking detection
    pub tracking_enabled: bool,

    /// Enable fingerprinting detection
    pub fingerprinting_enabled: bool,

    /// Enable supply chain analysis
    pub supply_chain_enabled: bool,

    /// Minimum severity to report
    pub min_severity: crate::types::Severity,

    /// Categories to analyze
    pub categories: Vec<AnalysisCategory>,

    /// Regulations to check
    pub regulations: Vec<crate::types::Regulation>,

    /// Maximum session lifetime (seconds) before flagging
    pub max_session_lifetime: i64,

    /// Warn on cookies without Secure flag
    pub warn_no_secure: bool,

    /// Warn on cookies without `HttpOnly` flag
    pub warn_no_httponly: bool,

    /// Warn on cookies without `SameSite`
    pub warn_no_samesite: bool,

    /// Enable strict mode (all warnings become errors)
    pub strict_mode: bool,
}

/// Analysis category
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AnalysisCategory {
    /// Security analysis
    Security,
    /// Compliance checking
    Compliance,
    /// Privacy analysis
    Privacy,
    /// Performance analysis
    Performance,
    /// Best practices
    BestPractices,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            security_enabled: true,
            compliance_enabled: true,
            tracking_enabled: true,
            fingerprinting_enabled: true,
            supply_chain_enabled: true,
            min_severity: crate::types::Severity::Low,
            categories: vec![
                AnalysisCategory::Security,
                AnalysisCategory::Compliance,
                AnalysisCategory::Privacy,
                AnalysisCategory::BestPractices,
            ],
            regulations: vec![crate::types::Regulation::GDPR],
            max_session_lifetime: 3600, // 1 hour
            warn_no_secure: true,
            warn_no_httponly: true,
            warn_no_samesite: true,
            strict_mode: false,
        }
    }
}

/// Configuration for report generation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct ReportConfig {
    /// Output format
    pub format: ReportFormat,

    /// Output file path
    pub output_path: Option<String>,

    /// Include summary
    pub include_summary: bool,

    /// Include detailed analysis
    pub include_details: bool,

    /// Include recommendations
    pub include_recommendations: bool,

    /// Include raw cookie data
    pub include_raw_data: bool,

    /// Group by domain
    pub group_by_domain: bool,

    /// Group by category
    pub group_by_category: bool,

    /// Sort by severity
    pub sort_by_severity: bool,

    /// Maximum issues to include (0 = all)
    pub max_issues: usize,

    /// Template file for custom reports
    pub template_path: Option<String>,

    /// Report title
    pub title: String,

    /// Report author
    pub author: Option<String>,

    /// Include timestamp
    pub include_timestamp: bool,

    /// Include version info
    pub include_version: bool,
}

/// Report format
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReportFormat {
    /// JSON format
    Json,
    /// YAML format
    Yaml,
    /// CSV format
    Csv,
    /// HTML format
    Html,
    /// PDF format
    Pdf,
    /// Markdown format
    Markdown,
    /// Plain text
    Text,
}

impl Default for ReportConfig {
    fn default() -> Self {
        Self {
            format: ReportFormat::Json,
            output_path: None,
            include_summary: true,
            include_details: true,
            include_recommendations: true,
            include_raw_data: false,
            group_by_domain: true,
            group_by_category: true,
            sort_by_severity: true,
            max_issues: 0,
            template_path: None,
            title: "ICOokForms Cookie Analysis Report".to_string(),
            author: None,
            include_timestamp: true,
            include_version: true,
        }
    }
}

/// Configuration for storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Database path
    pub database_path: String,

    /// Enable caching
    pub cache_enabled: bool,

    /// Cache TTL in seconds
    pub cache_ttl: u64,

    /// Maximum cache size in MB
    pub max_cache_size: usize,

    /// Store scan history
    pub store_history: bool,

    /// Maximum history entries
    pub max_history: usize,

    /// Auto-cleanup old entries
    pub auto_cleanup: bool,

    /// Cleanup interval in days
    pub cleanup_days: u32,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            database_path: "./icookforms.db".to_string(),
            cache_enabled: true,
            cache_ttl: 3600,
            max_cache_size: 100,
            store_history: true,
            max_history: 1000,
            auto_cleanup: true,
            cleanup_days: 30,
        }
    }
}

impl Config {
    /// Create a new configuration with default values
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Load configuration from file
    #[must_use = "Configuration loading failure must be handled"]
    pub fn from_file(path: &str) -> crate::types::Result<Self> {
        let content = std::fs::read_to_string(path)?;

        if std::path::Path::new(path)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
        {
            Ok(serde_json::from_str(&content)?)
        } else if std::path::Path::new(path)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("yaml"))
            || std::path::Path::new(path)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("yml"))
        {
            Ok(serde_yaml::from_str(&content)?)
        } else if std::path::Path::new(path)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("toml"))
        {
            Ok(toml::from_str(&content)
                .map_err(|e| crate::types::Error::config(format!("TOML parse error: {e}")))?)
        } else {
            Err(crate::types::Error::config(
                "Unsupported config file format",
            ))
        }
    }

    /// Save configuration to file
    pub fn save_to_file(&self, path: &str) -> crate::types::Result<()> {
        let content = if std::path::Path::new(path)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
        {
            serde_json::to_string_pretty(self)?
        } else if std::path::Path::new(path)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("yaml"))
            || std::path::Path::new(path)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("yml"))
        {
            serde_yaml::to_string(self)?
        } else if std::path::Path::new(path)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("toml"))
        {
            toml::to_string_pretty(self)
                .map_err(|e| crate::types::Error::config(format!("TOML serialize error: {e}")))?
        } else {
            return Err(crate::types::Error::config(
                "Unsupported config file format",
            ));
        };

        std::fs::write(path, content)?;
        Ok(())
    }

    /// Validate configuration
    #[must_use = "Configuration validation result must be checked"]
    pub fn validate(&self) -> crate::types::Result<()> {
        // Validate scan config
        if self.scan.max_pages == 0 {
            return Err(crate::types::Error::config("max_pages must be > 0"));
        }

        if self.scan.max_depth == 0 {
            return Err(crate::types::Error::config("max_depth must be > 0"));
        }

        if self.scan.concurrency == 0 {
            return Err(crate::types::Error::config("concurrency must be > 0"));
        }

        // Validate analysis config
        if self.analysis.categories.is_empty() {
            return Err(crate::types::Error::config(
                "At least one analysis category must be enabled",
            ));
        }

        if self.analysis.max_session_lifetime == 0 {
            return Err(crate::types::Error::config(
                "max_session_lifetime must be > 0",
            ));
        }

        // Validate storage config
        if self.storage.cache_ttl == 0 {
            return Err(crate::types::Error::config("cache_ttl must be > 0"));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert!(config.scan.max_pages > 0);
        assert!(config.analysis.security_enabled);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validation() {
        let mut config = Config::default();
        config.scan.max_pages = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_scan_config_defaults() {
        let config = ScanConfig::default();
        assert_eq!(config.max_pages, 100);
        assert_eq!(config.max_depth, 3);
        assert!(config.verify_ssl);
    }

    #[test]
    fn test_analysis_config_defaults() {
        let config = AnalysisConfig::default();
        assert!(config.security_enabled);
        assert!(config.compliance_enabled);
        assert!(!config.categories.is_empty());
    }

    #[test]
    fn test_report_format() {
        let format = ReportFormat::Json;
        assert_eq!(format, ReportFormat::Json);
    }
}
