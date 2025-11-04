//! Analyze command - Analyze cookies for security and compliance issues

use clap::Parser;
use colored::Colorize;
use std::path::PathBuf;

use crate::analyzer::Analyzer;
use crate::types::{AnalysisResult, Cookie, Error, Result, Severity};

/// Analyze cookies for security and compliance
#[derive(Parser, Debug)]
#[allow(clippy::struct_excessive_bools)]
pub struct AnalyzeArgs {
    /// Input file containing cookies (JSON format)
    #[arg(short, long)]
    pub input: PathBuf,

    /// Enable security analysis
    #[arg(long, default_value_t = true)]
    pub security: bool,

    /// Enable compliance checking
    #[arg(long, default_value_t = true)]
    pub compliance: bool,

    /// Enable tracking detection
    #[arg(long, default_value_t = true)]
    pub tracking: bool,

    /// Regulations to check (gdpr, ccpa, lgpd, etc.)
    #[arg(long, value_delimiter = ',')]
    pub regulations: Vec<String>,

    /// Output file path (JSON format)
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Show detailed issues
    #[arg(short, long, default_value_t = false)]
    pub verbose: bool,

    /// Minimum severity to display (critical, high, medium, low)
    #[arg(long, default_value = "low")]
    pub min_severity: String,
}

impl AnalyzeArgs {
    /// Execute the analyze command
    pub fn execute(&self) -> Result<AnalysisResult> {
        Self::print_banner();

        // Load cookies from file
        let cookies = self.load_cookies()?;

        println!(
            "📂 Loaded {} cookies from {}",
            cookies.len().to_string().bright_cyan().bold(),
            self.input.display().to_string().cyan()
        );

        // Build analyzer configuration
        let config = self.build_config();

        // Create analyzer
        let analyzer = Analyzer::with_config(config);

        // Analyze cookies
        println!();
        println!("🔍 Analyzing cookies...");
        println!();

        let result = analyzer.analyze_batch(&cookies);

        // Display results
        self.print_results(&result);

        // Save to file if requested
        if let Some(ref output) = self.output {
            Self::save_results(&result, output)?;
        }

        Ok(result)
    }

    /// Build analysis configuration
    fn build_config(&self) -> crate::types::config::AnalysisConfig {
        use crate::types::Regulation;

        let regulations = if self.regulations.is_empty() {
            vec![Regulation::GDPR, Regulation::CCPA]
        } else {
            self.regulations
                .iter()
                .filter_map(|r| match r.to_lowercase().as_str() {
                    "gdpr" => Some(Regulation::GDPR),
                    "ccpa" => Some(Regulation::CCPA),
                    "cpra" => Some(Regulation::CPRA),
                    "lgpd" => Some(Regulation::LGPD),
                    "pipeda" => Some(Regulation::PIPEDA),
                    _ => None,
                })
                .collect()
        };

        crate::types::config::AnalysisConfig {
            security_enabled: self.security,
            compliance_enabled: self.compliance,
            tracking_enabled: self.tracking,
            regulations,
            strict_mode: true,
            fingerprinting_enabled: true,
            supply_chain_enabled: true,
            min_severity: Severity::Low,
            categories: vec![],
            max_session_lifetime: 86400,
            warn_no_secure: true,
            warn_no_httponly: true,
            warn_no_samesite: true,
        }
    }

    /// Load cookies from JSON file
    fn load_cookies(&self) -> Result<Vec<Cookie>> {
        let content = std::fs::read_to_string(&self.input).map_err(Error::Io)?;

        // Try to parse as ScanResult first
        if let Ok(scan_result) = serde_json::from_str::<crate::types::ScanResult>(&content) {
            return Ok(scan_result.cookies);
        }

        // Try to parse as direct cookie array
        serde_json::from_str::<Vec<Cookie>>(&content)
            .map_err(|e| Error::analysis(format!("Failed to parse cookies: {e}")))
    }

    /// Print banner
    fn print_banner() {
        println!();
        println!("{}", "🔬 ICOokForms - Cookie Analyzer".bright_cyan().bold());
        println!("{}", "─".repeat(60).bright_black());
        println!();
    }

    /// Print analysis results
    fn print_results(&self, result: &AnalysisResult) {
        println!("{}", "📊 Analysis Results".bright_green().bold());
        println!("{}", "─".repeat(60).bright_black());
        println!();

        Self::print_scores(result);
        self.print_issues(result);
        self.print_tracking_info(result);
        Self::print_issue_summary(result);
        Self::print_recommendations(result);
    }

    /// Print overall scores
    fn print_scores(result: &AnalysisResult) {
        let overall_score =
            (result.risk_score + result.privacy_score + result.compliance_score) / 3.0;

        println!("{}", "🏆 Scores".bright_yellow().bold());
        println!("   Risk Score: {}", Self::format_score(result.risk_score));
        println!(
            "   Privacy Score: {}",
            Self::format_score(result.privacy_score)
        );
        println!(
            "   Compliance Score: {}",
            Self::format_score(result.compliance_score)
        );
        println!("   Overall Score: {}", Self::format_score(overall_score));
        println!();
    }

    /// Print security and compliance issues
    fn print_issues(&self, result: &AnalysisResult) {
        if !result.security_issues.is_empty() {
            println!("{}", "🔒 Security Issues".red().bold());
            self.print_security_issues(&result.security_issues);
            println!();
        }

        if !result.compliance_issues.is_empty() {
            println!("{}", "⚖️  Compliance Issues".yellow().bold());
            self.print_compliance_issues(&result.compliance_issues);
            println!();
        }
    }

    /// Print tracking information
    fn print_tracking_info(&self, result: &AnalysisResult) {
        if !result.tracking_info.is_empty() {
            println!("{}", "🎯 Tracking Detection".magenta().bold());
            println!(
                "   {} tracking cookies detected",
                result.tracking_info.len()
            );
            if self.verbose {
                for (i, tracking) in result.tracking_info.iter().enumerate() {
                    println!(
                        "   {}. {} - {:?}",
                        i + 1,
                        tracking.cookie_name.cyan(),
                        tracking.tracking_type
                    );
                    if let Some(ref vendor) = tracking.vendor {
                        println!("      Vendor: {}", vendor.bright_black());
                    }
                }
            }
            println!();
        }
    }

    /// Print issue summary statistics
    fn print_issue_summary(result: &AnalysisResult) {
        let critical = result
            .security_issues
            .iter()
            .filter(|i| i.issue.severity == Severity::Critical)
            .count()
            + result
                .compliance_issues
                .iter()
                .filter(|i| i.issue.severity == Severity::Critical)
                .count();

        let high = result
            .security_issues
            .iter()
            .filter(|i| i.issue.severity == Severity::High)
            .count()
            + result
                .compliance_issues
                .iter()
                .filter(|i| i.issue.severity == Severity::High)
                .count();

        let medium = result
            .security_issues
            .iter()
            .filter(|i| i.issue.severity == Severity::Medium)
            .count()
            + result
                .compliance_issues
                .iter()
                .filter(|i| i.issue.severity == Severity::Medium)
                .count();

        let low = result
            .security_issues
            .iter()
            .filter(|i| i.issue.severity == Severity::Low)
            .count()
            + result
                .compliance_issues
                .iter()
                .filter(|i| i.issue.severity == Severity::Low)
                .count();

        println!("{}", "📈 Issue Summary".bright_blue().bold());
        println!(
            "   🔴 Critical: {}",
            critical.to_string().bright_red().bold()
        );
        println!("   🟠 High: {}", high.to_string().red());
        println!("   🟡 Medium: {}", medium.to_string().yellow());
        println!("   🟢 Low: {}", low.to_string().green());
        println!();
    }

    /// Print top recommendations
    fn print_recommendations(result: &AnalysisResult) {
        if !result.security_issues.is_empty() || !result.compliance_issues.is_empty() {
            println!("{}", "💡 Top Recommendations".bright_magenta().bold());
            let mut recommendations = Self::get_recommendations(result);
            recommendations.truncate(5);
            for (i, rec) in recommendations.iter().enumerate() {
                println!("   {}. {}", i + 1, rec);
            }
            println!();
        }
    }

    /// Print security issues
    fn print_security_issues(&self, issues: &[crate::types::SecurityIssue]) {
        let min_sev = Self::parse_severity(&self.min_severity);

        for issue in issues {
            if issue.issue.severity < min_sev {
                continue;
            }

            let severity_str = Self::format_severity(issue.issue.severity);
            println!("   {} {}", severity_str, issue.issue.title.bold());

            if self.verbose {
                if !issue.issue.affected_cookies.is_empty() {
                    println!(
                        "      Cookies: {}",
                        issue.issue.affected_cookies.join(", ").cyan()
                    );
                }
                println!("      {}", issue.issue.description.bright_black());
                if !issue.issue.recommendations.is_empty() {
                    println!(
                        "      💡 {}",
                        issue.issue.recommendations.join("; ").green()
                    );
                }
            }
        }
    }

    /// Print compliance issues
    fn print_compliance_issues(&self, issues: &[crate::types::ComplianceIssue]) {
        let min_sev = Self::parse_severity(&self.min_severity);

        for issue in issues {
            if issue.issue.severity < min_sev {
                continue;
            }

            let severity_str = Self::format_severity(issue.issue.severity);
            println!(
                "   {} {} ({})",
                severity_str,
                issue.issue.title.bold(),
                format!("{regulation:?}", regulation = issue.regulation).cyan()
            );

            if self.verbose {
                if !issue.issue.affected_cookies.is_empty() {
                    println!(
                        "      Cookies: {}",
                        issue.issue.affected_cookies.join(", ").cyan()
                    );
                }
                println!("      {}", issue.issue.description.bright_black());
                if let Some(ref article) = issue.article {
                    println!("      📜 {}", article.bright_black());
                }
                if !issue.issue.recommendations.is_empty() {
                    println!(
                        "      💡 {}",
                        issue.issue.recommendations.join("; ").green()
                    );
                }
            }
        }
    }

    /// Format score with color
    fn format_score(score: f32) -> String {
        let score_str = format!("{score:.1}/100");
        if score >= 80.0 {
            score_str.bright_green().bold().to_string()
        } else if score >= 60.0 {
            score_str.yellow().bold().to_string()
        } else if score >= 40.0 {
            score_str.red().bold().to_string()
        } else {
            score_str.bright_red().bold().to_string()
        }
    }

    /// Format severity with emoji and color
    fn format_severity(severity: Severity) -> String {
        match severity {
            Severity::Critical => "🔴 CRITICAL".bright_red().bold().to_string(),
            Severity::High => "🟠 HIGH".red().to_string(),
            Severity::Medium => "🟡 MEDIUM".yellow().to_string(),
            Severity::Low => "🟢 LOW".green().to_string(),
            Severity::Info => "⚪ INFO".white().to_string(),
        }
    }

    /// Parse severity string
    fn parse_severity(s: &str) -> Severity {
        match s.to_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "info" => Severity::Info,
            _ => Severity::Low,
        }
    }

    /// Get top recommendations
    fn get_recommendations(result: &AnalysisResult) -> Vec<String> {
        let mut recs = Vec::new();

        // From security issues
        for issue in &result.security_issues {
            for rec in &issue.issue.recommendations {
                if !recs.contains(rec) {
                    recs.push(rec.clone());
                }
            }
        }

        // From compliance issues
        for issue in &result.compliance_issues {
            for rec in &issue.issue.recommendations {
                if !recs.contains(rec) {
                    recs.push(rec.clone());
                }
            }
        }

        recs
    }

    /// Save results to file
    fn save_results(result: &AnalysisResult, path: &PathBuf) -> Result<()> {
        let json = serde_json::to_string_pretty(result)
            .map_err(|e| Error::reporter(format!("Failed to serialize results: {e}")))?;

        std::fs::write(path, json).map_err(Error::Io)?;

        println!(
            "💾 Results saved to: {}",
            path.display().to_string().bright_green()
        );

        Ok(())
    }
}

/// Execute the analyze command with the given arguments and output format
#[allow(clippy::needless_pass_by_value)]
pub fn execute(args: AnalyzeArgs, _format: crate::cli::OutputFormat) -> Result<()> {
    args.execute()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyze_args() {
        let args = AnalyzeArgs {
            input: PathBuf::from("test.json"),
            security: true,
            compliance: true,
            tracking: true,
            regulations: vec!["gdpr".to_string()],
            output: None,
            verbose: false,
            min_severity: "low".to_string(),
        };

        let config = args.build_config();
        assert!(config.security_enabled);
        assert!(config.compliance_enabled);
        assert!(config.warn_no_secure);
        assert!(config.warn_no_httponly);
        assert!(config.warn_no_samesite);
    }

    #[test]
    fn test_parse_severity() {
        let _args = AnalyzeArgs {
            input: PathBuf::from("test.json"),
            security: true,
            compliance: true,
            tracking: true,
            regulations: Vec::new(),
            output: None,
            verbose: false,
            min_severity: "high".to_string(),
        };

        assert_eq!(AnalyzeArgs::parse_severity("critical"), Severity::Critical);
        assert_eq!(AnalyzeArgs::parse_severity("HIGH"), Severity::High);
        assert_eq!(AnalyzeArgs::parse_severity("medium"), Severity::Medium);
    }
}
