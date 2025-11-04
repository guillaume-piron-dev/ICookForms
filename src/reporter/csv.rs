//! CSV report generation
//!
//! Generate CSV reports suitable for spreadsheet analysis

use crate::types::{AnalysisResult, Result};
use std::fmt::Write;
use std::path::Path;

/// Generate CSV report and save to file
pub fn generate(results: &AnalysisResult, output_path: &Path) -> Result<()> {
    let csv = generate_string(results)?;
    std::fs::write(output_path, csv)?;
    Ok(())
}

/// Generate CSV report as string
pub fn generate_string(results: &AnalysisResult) -> Result<String> {
    let mut csv = String::new();

    // Header for issues
    csv.push_str(
        "Type,Severity,Category,Title,Description,CookiesAffected,URLsAffected,CWEID,Confidence\n",
    );

    // Add all issues
    for issue in &results.issues {
        writeln!(
            csv,
            "Issue,{},{},{},{},{},{},{},{}",
            escape_csv(&issue.severity.to_string()),
            escape_csv(&issue.category.to_string()),
            escape_csv(&issue.title),
            escape_csv(&issue.description),
            issue.affected_cookies.join("; "),
            issue.affected_urls.join("; "),
            issue.cwe_id.as_deref().unwrap_or("N/A"),
            issue.confidence
        )
        .unwrap();
    }

    // Add security issues
    for sec_issue in &results.security_issues {
        writeln!(
            csv,
            "SecurityIssue,{},{},{},{},{},{},{},{}",
            escape_csv(&sec_issue.issue.severity.to_string()),
            escape_csv(&sec_issue.issue.category.to_string()),
            escape_csv(&sec_issue.issue.title),
            escape_csv(&sec_issue.issue.description),
            sec_issue.issue.affected_cookies.join("; "),
            sec_issue.issue.affected_urls.join("; "),
            sec_issue.issue.cwe_id.as_deref().unwrap_or("N/A"),
            sec_issue.issue.confidence
        )
        .unwrap();
    }

    // Add compliance issues
    for comp_issue in &results.compliance_issues {
        writeln!(
            csv,
            "ComplianceIssue,{},{},{},{},{},{},{},{}",
            escape_csv(&comp_issue.issue.severity.to_string()),
            escape_csv(&comp_issue.issue.category.to_string()),
            escape_csv(&comp_issue.issue.title),
            escape_csv(&comp_issue.issue.description),
            comp_issue.issue.affected_cookies.join("; "),
            comp_issue.issue.affected_urls.join("; "),
            escape_csv(&comp_issue.regulation.to_string()),
            comp_issue.issue.confidence
        )
        .unwrap();
    }

    // Add tracking information section
    csv.push_str("\n\nTracking Cookies\n");
    csv.push_str("CookieName,Type,Vendor,Purpose,RiskLevel,DataCollected\n");

    for tracking in &results.tracking_info {
        writeln!(
            csv,
            "{},{},{},{},{},{}",
            escape_csv(&tracking.cookie_name),
            escape_csv(&format!("{:?}", tracking.tracking_type)),
            escape_csv(&tracking.vendor.clone().unwrap_or("Unknown".to_string())),
            escape_csv(&tracking.purpose),
            escape_csv(&tracking.risk_level.to_string()),
            tracking.data_collected.join("; ")
        )
        .unwrap();
    }

    // Add summary section
    csv.push_str("\n\nSummary\n");
    writeln!(csv, "Total Cookies,{}", results.summary.total_cookies).unwrap();
    writeln!(csv, "First Party,{}", results.summary.first_party_cookies).unwrap();
    writeln!(csv, "Third Party,{}", results.summary.third_party_cookies).unwrap();
    writeln!(csv, "Session Cookies,{}", results.summary.session_cookies).unwrap();
    writeln!(
        csv,
        "Persistent Cookies,{}",
        results.summary.persistent_cookies
    )
    .unwrap();
    writeln!(csv, "Secure Cookies,{}", results.summary.secure_cookies).unwrap();
    writeln!(
        csv,
        "HttpOnly Cookies,{}",
        results.summary.http_only_cookies
    )
    .unwrap();
    writeln!(
        csv,
        "SameSite Cookies,{}",
        results.summary.same_site_cookies
    )
    .unwrap();
    writeln!(csv, "Total Issues,{}", results.summary.total_issues).unwrap();
    writeln!(csv, "Risk Score,{:.2}", results.risk_score).unwrap();
    writeln!(csv, "Compliance Score,{:.2}", results.compliance_score).unwrap();
    writeln!(csv, "Privacy Score,{:.2}", results.privacy_score).unwrap();

    Ok(csv)
}

/// Escape CSV field (handle commas, quotes, newlines)
fn escape_csv(field: &str) -> String {
    if field.contains(',') || field.contains('"') || field.contains('\n') {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_escape_csv() {
        assert_eq!(escape_csv("simple"), "simple");
        assert_eq!(escape_csv("with,comma"), "\"with,comma\"");
        assert_eq!(escape_csv("with\"quote"), "\"with\"\"quote\"");
    }

    #[test]
    fn test_generate_string() {
        let results = AnalysisResult::new("test-scan");
        let csv = generate_string(&results);
        assert!(csv.is_ok());

        let content = csv.unwrap();
        assert!(content.contains("Type,Severity,Category"));
        assert!(content.contains("Summary"));
    }

    #[test]
    fn test_generate_file() {
        let results = AnalysisResult::new("test-scan");
        let temp_file = NamedTempFile::new().unwrap();
        let result = generate(&results, temp_file.path());
        assert!(result.is_ok());

        let content = std::fs::read_to_string(temp_file.path()).unwrap();
        assert!(content.contains("Type,Severity"));
    }
}
