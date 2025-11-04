//! Issue types for security and compliance problems

use serde::{Deserialize, Serialize};
use std::fmt;

/// Severity level of an issue
/// Order is from most severe to least severe for correct `Ord` implementation
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// Info - Informational only
    Info,
    /// Low - Nice to fix
    Low,
    /// Medium - Should be addressed
    Medium,
    /// High - Should be fixed as soon as possible
    High,
    /// Critical - Must be fixed immediately
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Critical => write!(f, "CRITICAL"),
            Self::High => write!(f, "HIGH"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::Low => write!(f, "LOW"),
            Self::Info => write!(f, "INFO"),
        }
    }
}

impl Severity {
    /// Get numeric score for severity (higher = more severe)
    #[must_use]
    pub fn score(&self) -> u8 {
        match self {
            Self::Critical => 100,
            Self::High => 75,
            Self::Medium => 50,
            Self::Low => 25,
            Self::Info => 0,
        }
    }

    /// Get emoji representation
    #[must_use]
    pub fn emoji(&self) -> &'static str {
        match self {
            Self::Critical => "🔴",
            Self::High => "🟠",
            Self::Medium => "🟡",
            Self::Low => "🔵",
            Self::Info => "⚪",
        }
    }

    /// Get color code (for terminal output)
    #[must_use]
    pub fn color(&self) -> &'static str {
        match self {
            Self::Critical => "red",
            Self::High => "orange",
            Self::Medium => "yellow",
            Self::Low => "blue",
            Self::Info => "white",
        }
    }
}

/// Category of an issue
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum IssueCategory {
    /// Security vulnerability
    Security,
    /// Compliance violation
    Compliance,
    /// Privacy concern
    Privacy,
    /// Performance issue
    Performance,
    /// Best practice violation
    BestPractice,
    /// Configuration problem
    Configuration,
}

impl fmt::Display for IssueCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Security => write!(f, "Security"),
            Self::Compliance => write!(f, "Compliance"),
            Self::Privacy => write!(f, "Privacy"),
            Self::Performance => write!(f, "Performance"),
            Self::BestPractice => write!(f, "Best Practice"),
            Self::Configuration => write!(f, "Configuration"),
        }
    }
}

/// Generic issue structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Issue {
    /// Unique identifier
    pub id: String,

    /// Issue severity
    pub severity: Severity,

    /// Issue category
    pub category: IssueCategory,

    /// Short title
    pub title: String,

    /// Detailed description
    pub description: String,

    /// Cookie name(s) affected
    pub affected_cookies: Vec<String>,

    /// URL(s) where issue was found
    pub affected_urls: Vec<String>,

    /// Recommendations for fixing
    pub recommendations: Vec<String>,

    /// Reference links (RFC, OWASP, etc.)
    pub references: Vec<String>,

    /// CWE ID (Common Weakness Enumeration)
    pub cwe_id: Option<String>,

    /// CVE ID (Common Vulnerabilities and Exposures)
    pub cve_id: Option<String>,

    /// OWASP category
    pub owasp_category: Option<String>,

    /// Confidence level (0-100)
    pub confidence: u8,

    /// False positive likelihood (0-100)
    pub false_positive_likelihood: u8,
}

impl Issue {
    /// Create a new issue
    pub fn new(
        severity: Severity,
        category: IssueCategory,
        title: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            severity,
            category,
            title: title.into(),
            description: description.into(),
            affected_cookies: Vec::new(),
            affected_urls: Vec::new(),
            recommendations: Vec::new(),
            references: Vec::new(),
            cwe_id: None,
            cve_id: None,
            owasp_category: None,
            confidence: 100,
            false_positive_likelihood: 0,
        }
    }

    /// Add affected cookie
    #[must_use]
    pub fn add_cookie(mut self, cookie: impl Into<String>) -> Self {
        self.affected_cookies.push(cookie.into());
        self
    }

    /// Add affected URL
    #[must_use]
    pub fn add_url(mut self, url: impl Into<String>) -> Self {
        self.affected_urls.push(url.into());
        self
    }

    /// Add recommendation
    #[must_use]
    pub fn add_recommendation(mut self, recommendation: impl Into<String>) -> Self {
        self.recommendations.push(recommendation.into());
        self
    }

    /// Add reference
    #[must_use]
    pub fn add_reference(mut self, reference: impl Into<String>) -> Self {
        self.references.push(reference.into());
        self
    }

    /// Set CWE ID
    #[must_use]
    pub fn with_cwe(mut self, cwe_id: impl Into<String>) -> Self {
        self.cwe_id = Some(cwe_id.into());
        self
    }

    /// Set confidence level
    #[must_use]
    pub fn with_confidence(mut self, confidence: u8) -> Self {
        self.confidence = confidence.min(100);
        self
    }
}

/// Security-specific issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityIssue {
    /// Base issue
    pub issue: Issue,

    /// Vulnerability type
    pub vulnerability_type: VulnerabilityType,

    /// Attack vector
    pub attack_vector: Option<AttackVector>,

    /// Exploitability score (0-10, CVSS)
    pub exploitability: f32,

    /// Impact score (0-10, CVSS)
    pub impact: f32,

    /// CVSS score (0-10)
    pub cvss_score: Option<f32>,
}

/// Types of vulnerabilities
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum VulnerabilityType {
    /// Cross-Site Scripting
    XSS,
    /// Cross-Site Request Forgery
    CSRF,
    /// Session Hijacking
    SessionHijacking,
    /// Cookie Injection
    CookieInjection,
    /// Cookie Tampering
    CookieTampering,
    /// Man-in-the-Middle
    MITM,
    /// Session Fixation
    SessionFixation,
    /// Insecure Transmission
    InsecureTransmission,
    /// Weak Cryptography
    WeakCryptography,
    /// Missing Security Headers
    MissingSecurityHeaders,
    /// Supply Chain Attack
    SupplyChainAttack,
}

impl fmt::Display for VulnerabilityType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::XSS => write!(f, "Cross-Site Scripting (XSS)"),
            Self::CSRF => write!(f, "Cross-Site Request Forgery (CSRF)"),
            Self::SessionHijacking => write!(f, "Session Hijacking"),
            Self::CookieInjection => write!(f, "Cookie Injection"),
            Self::CookieTampering => write!(f, "Cookie Tampering"),
            Self::MITM => write!(f, "Man-in-the-Middle (MITM)"),
            Self::SessionFixation => write!(f, "Session Fixation"),
            Self::InsecureTransmission => write!(f, "Insecure Transmission"),
            Self::WeakCryptography => write!(f, "Weak Cryptography"),
            Self::MissingSecurityHeaders => write!(f, "Missing Security Headers"),
            Self::SupplyChainAttack => write!(f, "Supply Chain Attack"),
        }
    }
}

/// Attack vector classification
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AttackVector {
    /// Network-based attack
    Network,
    /// Adjacent network
    Adjacent,
    /// Local access required
    Local,
    /// Physical access required
    Physical,
}

/// Compliance-specific issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceIssue {
    /// Base issue
    pub issue: Issue,

    /// Regulation violated
    pub regulation: crate::types::Regulation,

    /// Specific article/section violated
    pub article: Option<String>,

    /// Legal requirement text
    pub requirement: String,

    /// Potential fine/penalty
    pub penalty: Option<String>,

    /// Required by law
    pub mandatory: bool,

    /// Grace period for compliance
    pub grace_period: Option<String>,
}

impl SecurityIssue {
    /// Create a new security issue
    pub fn new(
        severity: Severity,
        title: impl Into<String>,
        description: impl Into<String>,
        vulnerability_type: VulnerabilityType,
    ) -> Self {
        Self {
            issue: Issue::new(severity, IssueCategory::Security, title, description),
            vulnerability_type,
            attack_vector: None,
            exploitability: 0.0,
            impact: 0.0,
            cvss_score: None,
        }
    }

    /// Calculate CVSS score
    pub fn calculate_cvss(&mut self) {
        // Simplified CVSS v3.1 calculation
        let base_score = (self.exploitability + self.impact) / 2.0;
        self.cvss_score = Some(base_score.clamp(0.0, 10.0));
    }
}

impl ComplianceIssue {
    /// Create a new compliance issue
    pub fn new(
        severity: Severity,
        regulation: crate::types::Regulation,
        title: impl Into<String>,
        description: impl Into<String>,
        requirement: impl Into<String>,
    ) -> Self {
        Self {
            issue: Issue::new(severity, IssueCategory::Compliance, title, description),
            regulation,
            article: None,
            requirement: requirement.into(),
            penalty: None,
            mandatory: true,
            grace_period: None,
        }
    }

    /// Set article/section
    #[must_use]
    pub fn with_article(mut self, article: impl Into<String>) -> Self {
        self.article = Some(article.into());
        self
    }

    /// Set penalty information
    #[must_use]
    pub fn with_penalty(mut self, penalty: impl Into<String>) -> Self {
        self.penalty = Some(penalty.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn test_severity_score() {
        assert_eq!(Severity::Critical.score(), 100);
        assert_eq!(Severity::High.score(), 75);
        assert_eq!(Severity::Medium.score(), 50);
        assert_eq!(Severity::Low.score(), 25);
        assert_eq!(Severity::Info.score(), 0);
    }

    #[test]
    fn test_issue_creation() {
        let issue = Issue::new(
            Severity::High,
            IssueCategory::Security,
            "Test Issue",
            "Test Description",
        );

        assert_eq!(issue.severity, Severity::High);
        assert_eq!(issue.category, IssueCategory::Security);
        assert_eq!(issue.title, "Test Issue");
        assert!(!issue.id.is_empty());
    }

    #[test]
    fn test_issue_builder() {
        let issue = Issue::new(
            Severity::Critical,
            IssueCategory::Security,
            "XSS Vulnerability",
            "Cookie accessible via JavaScript",
        )
        .add_cookie("session_id")
        .add_url("https://example.com")
        .add_recommendation("Add HttpOnly flag")
        .with_cwe("CWE-79");

        assert_eq!(issue.affected_cookies.len(), 1);
        assert_eq!(issue.affected_urls.len(), 1);
        assert_eq!(issue.recommendations.len(), 1);
        assert_eq!(issue.cwe_id, Some("CWE-79".to_string()));
    }

    #[test]
    fn test_security_issue() {
        let mut issue = SecurityIssue::new(
            Severity::High,
            "XSS via Cookie",
            "Session cookie accessible to JavaScript",
            VulnerabilityType::XSS,
        );

        issue.exploitability = 8.0;
        issue.impact = 7.0;
        issue.calculate_cvss();

        assert!(issue.cvss_score.is_some());
        assert!(issue.cvss_score.unwrap() > 0.0);
    }

    #[test]
    fn test_compliance_issue() {
        let issue = ComplianceIssue::new(
            Severity::High,
            crate::types::Regulation::GDPR,
            "Missing Consent",
            "Analytics cookies set without user consent",
            "Article 6(1)(a) - Consent required for processing",
        )
        .with_article("Art. 6(1)(a)")
        .with_penalty("Up to €20M or 4% of annual revenue");

        assert_eq!(issue.regulation, crate::types::Regulation::GDPR);
        assert!(issue.article.is_some());
        assert!(issue.penalty.is_some());
    }

    #[test]
    fn test_vulnerability_type_display() {
        assert_eq!(
            VulnerabilityType::XSS.to_string(),
            "Cross-Site Scripting (XSS)"
        );
        assert_eq!(
            VulnerabilityType::CSRF.to_string(),
            "Cross-Site Request Forgery (CSRF)"
        );
    }
}
