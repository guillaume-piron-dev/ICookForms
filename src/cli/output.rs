//! Output formatting utilities for CLI
//!
//! This module provides utilities for formatting and displaying output in various formats.

use crate::types::{AnalysisResult, ComplianceResult, ScanResult, Severity};
use colored::{ColoredString, Colorize};

/// Format and print a scan result
pub fn print_scan_result(
    result: &ScanResult,
    format: &super::OutputFormat,
) -> crate::types::Result<()> {
    match format {
        super::OutputFormat::Human => {
            print_scan_result_human(result);
            Ok(())
        }
        super::OutputFormat::Json => print_scan_result_json(result),
        super::OutputFormat::Yaml => print_scan_result_yaml(result),
        super::OutputFormat::Csv => {
            print_scan_result_csv(result);
            Ok(())
        }
    }
}

/// Format and print an analysis result
pub fn print_analysis_result(
    result: &AnalysisResult,
    format: &super::OutputFormat,
) -> crate::types::Result<()> {
    match format {
        super::OutputFormat::Human => {
            print_analysis_result_human(result);
            Ok(())
        }
        super::OutputFormat::Json => print_analysis_result_json(result),
        super::OutputFormat::Yaml => print_analysis_result_yaml(result),
        super::OutputFormat::Csv => {
            print_analysis_result_csv(result);
            Ok(())
        }
    }
}

/// Format and print a compliance result
pub fn print_compliance_result(
    result: &ComplianceResult,
    format: &super::OutputFormat,
) -> crate::types::Result<()> {
    match format {
        super::OutputFormat::Human => {
            print_compliance_result_human(result);
            Ok(())
        }
        super::OutputFormat::Json => print_compliance_result_json(result),
        super::OutputFormat::Yaml => print_compliance_result_yaml(result),
        super::OutputFormat::Csv => {
            print_compliance_result_csv(result);
            Ok(())
        }
    }
}

// ============================================================================
// HUMAN FORMAT (with colors and formatting)
// ============================================================================

fn print_scan_result_human(result: &ScanResult) {
    println!("\n{}", "=".repeat(80).bright_blue());
    println!("{}", "SCAN RESULTS".bright_cyan().bold());
    println!("{}", "=".repeat(80).bright_blue());

    println!("\n{} {}", "Target URL:".bold(), result.url);
    println!("{} {}", "Scan ID:".bold(), result.id);
    println!("{} {:?}", "Status:".bold(), result.status);

    // Statistics
    println!("\n{}", "Statistics:".bold().underline());
    println!(
        "  {} {}",
        "Cookies found:".bold(),
        result.cookies.len().to_string().green()
    );
    println!("  {} {}", "Pages scanned:".bold(), result.pages_scanned);
    println!("  {} {}", "Requests made:".bold(), result.requests_made);

    if !result.errors.is_empty() {
        println!("\n{}", "Errors:".red().bold());
        for (i, error) in result.errors.iter().enumerate() {
            println!("  {}. {}", i + 1, error.red());
        }
    }

    // Cookie summary
    if !result.cookies.is_empty() {
        println!("\n{}", "Top Cookies:".bold().underline());
        for (i, cookie) in result.cookies.iter().take(5).enumerate() {
            println!(
                "  {}. {} = {} (domain: {})",
                i + 1,
                cookie.name.bold(),
                if cookie.value.len() > 30 {
                    format!("{}...", &cookie.value[..30])
                } else {
                    cookie.value.clone()
                },
                cookie.domain.as_deref().unwrap_or("N/A")
            );
        }

        if result.cookies.len() > 5 {
            println!("  ... and {} more", result.cookies.len() - 5);
        }
    }

    println!();
}

fn print_analysis_result_human(result: &AnalysisResult) {
    println!("\n{}", "=".repeat(80).bright_blue());
    println!("{}", "ANALYSIS RESULTS".bright_cyan().bold());
    println!("{}", "=".repeat(80).bright_blue());

    println!("\n{} {}", "Analysis ID:".bold(), result.id);

    // Scores
    println!("\n{}", "Scores:".bold().underline());
    println!(
        "  {} {}/100",
        "Risk Score:".bold(),
        format_score(result.risk_score)
    );
    println!(
        "  {} {}/100",
        "Privacy Score:".bold(),
        format_score(result.privacy_score)
    );
    println!(
        "  {} {}/100",
        "Compliance Score:".bold(),
        format_score(result.compliance_score)
    );

    // Security Issues
    if result.security_issues.is_empty() {
        println!("\n{} None found", "Security Issues:".green().bold());
    } else {
        println!(
            "\n{} ({})",
            "Security Issues:".red().bold(),
            result.security_issues.len()
        );
        for (i, issue) in result.security_issues.iter().take(10).enumerate() {
            let severity_str = format_severity(issue.issue.severity);
            println!(
                "  {}. [{}] {:?}: {}",
                i + 1,
                severity_str,
                issue.issue.category,
                issue.issue.description
            );
        }

        if result.security_issues.len() > 10 {
            println!(
                "  ... and {} more issues",
                result.security_issues.len() - 10
            );
        }
    }

    // Compliance Issues
    if result.compliance_issues.is_empty() {
        println!("\n{} None found", "Compliance Issues:".green().bold());
    } else {
        println!(
            "\n{} ({})",
            "Compliance Issues:".yellow().bold(),
            result.compliance_issues.len()
        );
        for (i, issue) in result.compliance_issues.iter().take(10).enumerate() {
            let severity_str = format_severity(issue.issue.severity);
            println!(
                "  {}. [{}] {:?}: {}",
                i + 1,
                severity_str,
                issue.regulation,
                issue.issue.description
            );
        }

        if result.compliance_issues.len() > 10 {
            println!(
                "  ... and {} more issues",
                result.compliance_issues.len() - 10
            );
        }
    }

    println!();
}

fn print_compliance_result_human(result: &ComplianceResult) {
    println!("\n{}", "=".repeat(80).bright_blue());
    println!("{}", "COMPLIANCE RESULTS".bright_cyan().bold());
    println!("{}", "=".repeat(80).bright_blue());

    println!("\n{} {}", "Compliance ID:".bold(), result.id);
    println!("{} {:?}", "Regulation:".bold(), result.regulation);
    println!(
        "{} {}",
        "Checked at:".bold(),
        result.checked_at.format("%Y-%m-%d %H:%M:%S UTC")
    );

    // Compliance status
    println!("\n{}", "Status:".bold().underline());
    if result.compliant {
        println!("  {} {}", "Compliant:".green().bold(), "YES ✓".green());
    } else {
        println!("  {} {}", "Compliant:".red().bold(), "NO ✗".red());
    }
    println!("  {} {}/100", "Score:".bold(), format_score(result.score));

    // Statistics
    println!("\n{}", "Statistics:".bold().underline());
    println!(
        "  {} {}",
        "Compliant cookies:".green(),
        result.compliant_cookies
    );
    println!(
        "  {} {}",
        "Non-compliant cookies:".red(),
        result.non_compliant_cookies
    );

    // Issues
    if !result.issues.is_empty() {
        println!("\n{} ({})", "Issues:".red().bold(), result.issues.len());
        for (i, issue) in result.issues.iter().take(10).enumerate() {
            let severity_str = format_severity(issue.issue.severity);
            println!(
                "  {}. [{}] {}",
                i + 1,
                severity_str,
                issue.issue.description
            );
        }

        if result.issues.len() > 10 {
            println!("  ... and {} more issues", result.issues.len() - 10);
        }
    }

    // Recommendations
    if !result.recommendations.is_empty() {
        println!("\n{}", "Recommendations:".yellow().bold());
        for (i, rec) in result.recommendations.iter().take(5).enumerate() {
            println!("  {}. {}", i + 1, rec);
        }
    }

    println!();
}

// ============================================================================
// JSON FORMAT
// ============================================================================

fn print_scan_result_json(result: &ScanResult) -> crate::types::Result<()> {
    let json = serde_json::to_string_pretty(result)
        .map_err(|e| crate::types::Error::reporter(format!("JSON serialization error: {e}")))?;
    println!("{json}");
    Ok(())
}

fn print_analysis_result_json(result: &AnalysisResult) -> crate::types::Result<()> {
    let json = serde_json::to_string_pretty(result)
        .map_err(|e| crate::types::Error::reporter(format!("JSON serialization error: {e}")))?;
    println!("{json}");
    Ok(())
}

fn print_compliance_result_json(result: &ComplianceResult) -> crate::types::Result<()> {
    let json = serde_json::to_string_pretty(result)
        .map_err(|e| crate::types::Error::reporter(format!("JSON serialization error: {e}")))?;
    println!("{json}");
    Ok(())
}

// ============================================================================
// YAML FORMAT
// ============================================================================

fn print_scan_result_yaml(result: &ScanResult) -> crate::types::Result<()> {
    let yaml = serde_yaml::to_string(result)
        .map_err(|e| crate::types::Error::reporter(format!("YAML serialization error: {e}")))?;
    println!("{yaml}");
    Ok(())
}

fn print_analysis_result_yaml(result: &AnalysisResult) -> crate::types::Result<()> {
    let yaml = serde_yaml::to_string(result)
        .map_err(|e| crate::types::Error::reporter(format!("YAML serialization error: {e}")))?;
    println!("{yaml}");
    Ok(())
}

fn print_compliance_result_yaml(result: &ComplianceResult) -> crate::types::Result<()> {
    let yaml = serde_yaml::to_string(result)
        .map_err(|e| crate::types::Error::reporter(format!("YAML serialization error: {e}")))?;
    println!("{yaml}");
    Ok(())
}

// ============================================================================
// CSV FORMAT
// ============================================================================

fn print_scan_result_csv(result: &ScanResult) {
    println!("name,value,domain,path,secure,http_only,same_site,expires");
    for cookie in &result.cookies {
        println!(
            "{},{},{},{},{},{},{},{}",
            csv_escape(&cookie.name),
            csv_escape(&cookie.value),
            csv_escape(cookie.domain.as_deref().unwrap_or("")),
            csv_escape(cookie.path.as_deref().unwrap_or("")),
            cookie.secure,
            cookie.http_only,
            cookie
                .same_site
                .as_ref()
                .map(|s| format!("{s:?}"))
                .unwrap_or_default(),
            cookie.expires.map(|e| e.to_rfc3339()).unwrap_or_default()
        );
    }
}

fn print_analysis_result_csv(_result: &AnalysisResult) {
    println!("Analysis results in CSV format not yet implemented");
}

fn print_compliance_result_csv(_result: &ComplianceResult) {
    println!("Compliance results in CSV format not yet implemented");
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

fn format_score(score: f32) -> ColoredString {
    let score_str = format!("{score:.1}");
    if score >= 80.0 {
        score_str.green()
    } else if score >= 60.0 {
        score_str.yellow()
    } else {
        score_str.red()
    }
}

fn format_severity(severity: Severity) -> ColoredString {
    match severity {
        Severity::Critical => "CRITICAL".red().bold(),
        Severity::High => "HIGH".red(),
        Severity::Medium => "MEDIUM".yellow(),
        Severity::Low => "LOW".blue(),
        Severity::Info => "INFO".normal(),
    }
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_csv_escape() {
        assert_eq!(csv_escape("simple"), "simple");
        assert_eq!(csv_escape("with,comma"), "\"with,comma\"");
        assert_eq!(csv_escape("with\"quote"), "\"with\"\"quote\"");
    }

    #[test]
    fn test_format_score() {
        let high = format_score(90.0);
        let medium = format_score(70.0);
        let low = format_score(40.0);

        // Just check they don't panic
        assert!(!high.to_string().is_empty());
        assert!(!medium.to_string().is_empty());
        assert!(!low.to_string().is_empty());
    }
}
