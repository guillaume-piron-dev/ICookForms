//! Report types and structures

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::{ComplianceIssue, Cookie, Issue, Regulation, SecurityIssue, Severity};

/// Result of a cookie scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    /// Scan ID
    pub id: String,

    /// Target URL
    pub url: String,

    /// When the scan started
    pub started_at: DateTime<Utc>,

    /// When the scan completed
    pub completed_at: Option<DateTime<Utc>>,

    /// Scan status
    pub status: ScanStatus,

    /// Cookies found
    pub cookies: Vec<Cookie>,

    /// Total pages scanned
    pub pages_scanned: usize,

    /// Total requests made
    pub requests_made: usize,

    /// Errors encountered
    pub errors: Vec<String>,

    /// Scan configuration used
    pub config: serde_json::Value,
}

/// Status of a scan
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ScanStatus {
    /// Scan is pending
    Pending,
    /// Scan is in progress
    InProgress,
    /// Scan completed successfully
    Completed,
    /// Scan failed
    Failed,
    /// Scan was cancelled
    Cancelled,
}

/// Result of cookie analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    /// Analysis ID
    pub id: String,

    /// Associated scan ID
    pub scan_id: String,

    /// When analysis was performed
    pub analyzed_at: DateTime<Utc>,

    /// Analysis summary
    pub summary: AnalysisSummary,

    /// All issues found
    pub issues: Vec<Issue>,

    /// Security issues
    pub security_issues: Vec<SecurityIssue>,

    /// Compliance issues
    pub compliance_issues: Vec<ComplianceIssue>,

    /// Tracking information
    pub tracking_info: Vec<TrackingInfo>,

    /// Cookies by category
    pub cookies_by_category: HashMap<String, Vec<Cookie>>,

    /// Cookies by domain
    pub cookies_by_domain: HashMap<String, Vec<Cookie>>,

    /// Risk score (0-100)
    pub risk_score: f32,

    /// Compliance score (0-100)
    pub compliance_score: f32,

    /// Privacy score (0-100)
    pub privacy_score: f32,
}

/// Summary of analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisSummary {
    /// Total cookies analyzed
    pub total_cookies: usize,

    /// First-party cookies
    pub first_party_cookies: usize,

    /// Third-party cookies
    pub third_party_cookies: usize,

    /// Session cookies
    pub session_cookies: usize,

    /// Persistent cookies
    pub persistent_cookies: usize,

    /// Secure cookies (with Secure flag)
    pub secure_cookies: usize,

    /// `HttpOnly` cookies
    pub http_only_cookies: usize,

    /// `SameSite` cookies
    pub same_site_cookies: usize,

    /// Total issues found
    pub total_issues: usize,

    /// Issues by severity
    pub issues_by_severity: HashMap<Severity, usize>,

    /// Domains with cookies
    pub unique_domains: usize,

    /// Average cookie size (bytes)
    pub average_cookie_size: f32,

    /// Total cookie data (bytes)
    pub total_cookie_data: usize,
}

impl AnalysisSummary {
    /// Create a new security summary
    #[must_use]
    pub fn new() -> Self {
        Self {
            total_cookies: 0,
            first_party_cookies: 0,
            third_party_cookies: 0,
            session_cookies: 0,
            persistent_cookies: 0,
            secure_cookies: 0,
            http_only_cookies: 0,
            same_site_cookies: 0,
            total_issues: 0,
            issues_by_severity: HashMap::new(),
            unique_domains: 0,
            average_cookie_size: 0.0,
            total_cookie_data: 0,
        }
    }

    /// Create from cookies and issues
    #[must_use]
    pub fn from_cookies_and_issues(cookies: &[Cookie], issues: &[Issue]) -> Self {
        let mut summary = Self::new();

        summary.total_cookies = cookies.len();
        summary.first_party_cookies = cookies.iter().filter(|c| !c.is_third_party).count();
        summary.third_party_cookies = cookies.iter().filter(|c| c.is_third_party).count();
        summary.session_cookies = cookies.iter().filter(|c| c.is_session()).count();
        summary.persistent_cookies = cookies.iter().filter(|c| c.is_persistent()).count();
        summary.secure_cookies = cookies.iter().filter(|c| c.secure).count();
        summary.http_only_cookies = cookies.iter().filter(|c| c.http_only).count();
        summary.same_site_cookies = cookies.iter().filter(|c| c.same_site.is_some()).count();

        summary.total_issues = issues.len();
        for issue in issues {
            *summary
                .issues_by_severity
                .entry(issue.severity)
                .or_insert(0) += 1;
        }

        let domains: std::collections::HashSet<_> =
            cookies.iter().filter_map(|c| c.domain.as_ref()).collect();
        summary.unique_domains = domains.len();

        summary.total_cookie_data = cookies.iter().map(|c| c.size).sum();
        if summary.total_cookies > 0 {
            #[allow(clippy::cast_precision_loss)]
            {
                summary.average_cookie_size =
                    summary.total_cookie_data as f32 / summary.total_cookies as f32;
            }
        }

        summary
    }
}

impl Default for AnalysisSummary {
    fn default() -> Self {
        Self::new()
    }
}

/// Tracking information for a cookie
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackingInfo {
    /// Cookie name
    pub cookie_name: String,

    /// Tracking type
    pub tracking_type: TrackingType,

    /// Vendor/company
    pub vendor: Option<String>,

    /// Purpose
    pub purpose: String,

    /// Privacy risk level
    pub risk_level: Severity,

    /// Data collected
    pub data_collected: Vec<String>,

    /// Third parties with access
    pub third_parties: Vec<String>,
}

/// Type of tracking - CORRECTED: Added Hash derive
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum TrackingType {
    /// Analytics tracking
    Analytics,
    /// Advertising/Marketing
    Advertising,
    /// Social media tracking
    SocialMedia,
    /// Functional tracking
    Functional,
    /// Fingerprinting
    Fingerprinting,
    /// Cross-site tracking
    CrossSite,
    /// Unknown tracking
    Unknown,
}

/// Result of compliance checking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceResult {
    /// Result ID
    pub id: String,

    /// Regulation checked
    pub regulation: Regulation,

    /// When checked
    pub checked_at: DateTime<Utc>,

    /// Overall compliance status
    pub compliant: bool,

    /// Compliance score (0-100)
    pub score: f32,

    /// Issues found
    pub issues: Vec<ComplianceIssue>,

    /// Compliant cookies
    pub compliant_cookies: usize,

    /// Non-compliant cookies
    pub non_compliant_cookies: usize,

    /// Warnings
    pub warnings: Vec<String>,

    /// Recommendations
    pub recommendations: Vec<String>,

    /// Consent mechanism analysis
    pub consent_analysis: Option<ConsentAnalysis>,
}

/// Analysis of consent mechanism
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct ConsentAnalysis {
    /// Consent banner present
    pub banner_present: bool,

    /// Banner blocks cookies before consent
    pub blocks_cookies: bool,

    /// Has reject/decline option
    pub has_reject_option: bool,

    /// Reject option equally prominent
    pub reject_equally_prominent: bool,

    /// Has granular options
    pub granular_options: bool,

    /// Cookie policy link present
    pub policy_link_present: bool,

    /// Consent is freely given
    pub freely_given: bool,

    /// Consent is specific
    pub specific: bool,

    /// Consent is informed
    pub informed: bool,

    /// Consent is unambiguous
    pub unambiguous: bool,

    /// Dark patterns detected
    pub dark_patterns: Vec<String>,
}

/// Complete report structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    /// Report metadata
    pub metadata: ReportMetadata,

    /// Scan results
    pub scan: ScanResult,

    /// Analysis results
    pub analysis: AnalysisResult,

    /// Compliance results (by regulation)
    pub compliance: HashMap<Regulation, ComplianceResult>,

    /// Executive summary
    pub executive_summary: ExecutiveSummary,

    /// Recommendations
    pub recommendations: Vec<Recommendation>,
}

/// Report metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportMetadata {
    /// Report ID
    pub id: String,

    /// Report title
    pub title: String,

    /// Generated at
    pub generated_at: DateTime<Utc>,

    /// Generator (`ICOokForms` version)
    pub generator: String,

    /// Author
    pub author: Option<String>,

    /// Target URL
    pub target_url: String,

    /// Report format
    pub format: String,
}

/// Executive summary for reports
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutiveSummary {
    /// Overall assessment
    pub assessment: String,

    /// Key findings
    pub key_findings: Vec<String>,

    /// Critical issues count
    pub critical_issues: usize,

    /// High issues count
    pub high_issues: usize,

    /// Overall risk level
    pub risk_level: Severity,

    /// Compliance status
    pub compliance_status: String,

    /// Quick stats
    pub quick_stats: HashMap<String, String>,
}

/// Recommendation for improvement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    /// Priority
    pub priority: Severity,

    /// Title
    pub title: String,

    /// Description
    pub description: String,

    /// Implementation steps
    pub steps: Vec<String>,

    /// Expected impact
    pub impact: String,

    /// Estimated effort
    pub effort: EffortLevel,

    /// Related issues
    pub related_issues: Vec<String>,
}

/// Effort level for recommendations
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum EffortLevel {
    /// Low effort (< 1 hour)
    Low,
    /// Medium effort (1-8 hours)
    Medium,
    /// High effort (1-3 days)
    High,
    /// Very high effort (> 3 days)
    VeryHigh,
}

impl ScanResult {
    /// Create a new scan result
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            url: url.into(),
            started_at: Utc::now(),
            completed_at: None,
            status: ScanStatus::Pending,
            cookies: Vec::new(),
            pages_scanned: 0,
            requests_made: 0,
            errors: Vec::new(),
            config: serde_json::Value::Null,
        }
    }

    /// Mark scan as completed
    pub fn complete(&mut self) {
        self.status = ScanStatus::Completed;
        self.completed_at = Some(Utc::now());
    }

    /// Get scan duration
    #[must_use]
    pub fn duration(&self) -> Option<chrono::Duration> {
        self.completed_at.map(|end| end - self.started_at)
    }
}

impl AnalysisResult {
    /// Create a new analysis result
    pub fn new(scan_id: impl Into<String>) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            scan_id: scan_id.into(),
            analyzed_at: Utc::now(),
            summary: AnalysisSummary::new(),
            issues: Vec::new(),
            security_issues: Vec::new(),
            compliance_issues: Vec::new(),
            tracking_info: Vec::new(),
            cookies_by_category: HashMap::new(),
            cookies_by_domain: HashMap::new(),
            risk_score: 0.0,
            compliance_score: 100.0,
            privacy_score: 100.0,
        }
    }

    /// Calculate overall scores
    pub fn calculate_scores(&mut self) {
        // Risk score based on issues
        let critical = self
            .issues
            .iter()
            .filter(|i| i.severity == Severity::Critical)
            .count();
        let high = self
            .issues
            .iter()
            .filter(|i| i.severity == Severity::High)
            .count();
        let medium = self
            .issues
            .iter()
            .filter(|i| i.severity == Severity::Medium)
            .count();

        #[allow(clippy::cast_precision_loss)]
        {
            self.risk_score =
                (critical as f32 * 25.0 + high as f32 * 10.0 + medium as f32 * 5.0).min(100.0);

            // Compliance score (inverse of compliance issues)
            let compliance_issues = self.compliance_issues.len() as f32;
            self.compliance_score = (100.0 - (compliance_issues * 5.0)).max(0.0);

            // Privacy score based on tracking and third-party cookies
            let tracking_cookies = self.tracking_info.len() as f32;
            self.privacy_score = (100.0 - (tracking_cookies * 3.0)).max(0.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_result_creation() {
        let scan = ScanResult::new("https://example.com");
        assert_eq!(scan.url, "https://example.com");
        assert_eq!(scan.status, ScanStatus::Pending);
        assert!(!scan.id.is_empty());
    }

    #[test]
    fn test_scan_completion() {
        let mut scan = ScanResult::new("https://example.com");
        assert!(scan.completed_at.is_none());

        scan.complete();
        assert_eq!(scan.status, ScanStatus::Completed);
        assert!(scan.completed_at.is_some());
    }

    #[test]
    fn test_analysis_result_creation() {
        let analysis = AnalysisResult::new("scan-123");
        assert_eq!(analysis.scan_id, "scan-123");
        assert!(!analysis.id.is_empty());
    }

    #[test]
    fn test_analysis_summary() {
        let cookies = vec![
            Cookie::new("session".to_string(), "abc".to_string()),
            Cookie::new("tracking".to_string(), "def".to_string()),
        ];

        let issues = vec![Issue::new(
            Severity::High,
            super::super::IssueCategory::Security,
            "Test",
            "Test description",
        )];

        let summary = AnalysisSummary::from_cookies_and_issues(&cookies, &issues);
        assert_eq!(summary.total_cookies, 2);
        assert_eq!(summary.total_issues, 1);
    }

    #[test]
    fn test_score_calculation() {
        let mut analysis = AnalysisResult::new("test");
        analysis.calculate_scores();

        assert!(analysis.risk_score >= 0.0 && analysis.risk_score <= 100.0);
        assert!(analysis.compliance_score >= 0.0 && analysis.compliance_score <= 100.0);
        assert!(analysis.privacy_score >= 0.0 && analysis.privacy_score <= 100.0);
    }
}
