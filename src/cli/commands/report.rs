//! Report command - Generate comprehensive reports from analysis results

use clap::Parser;
use colored::Colorize;
use std::fmt::Write as _;
use std::path::PathBuf;

use crate::types::{AnalysisResult, Error, Result};

/// Generate report from analysis results
#[derive(Parser, Debug)]
#[allow(clippy::struct_excessive_bools)]
pub struct ReportArgs {
    /// Input file containing analysis results (JSON format)
    #[arg(short, long)]
    pub input: PathBuf,

    /// Output file path
    #[arg(short, long)]
    pub output: PathBuf,

    /// Report format (json, csv, pdf, html)
    #[arg(short, long, default_value = "html")]
    pub format: String,

    /// Report title
    #[arg(long, default_value = "Cookie Audit Report")]
    pub title: String,

    /// Include executive summary
    #[arg(long, default_value_t = true)]
    pub summary: bool,

    /// Include detailed findings
    #[arg(long, default_value_t = true)]
    pub details: bool,

    /// Include recommendations
    #[arg(long, default_value_t = true)]
    pub recommendations: bool,

    /// Include charts and visualizations (HTML/PDF only)
    #[arg(long, default_value_t = true)]
    pub charts: bool,

    /// Company name for report header
    #[arg(long)]
    pub company: Option<String>,

    /// Auditor name
    #[arg(long)]
    pub auditor: Option<String>,
}

impl ReportArgs {
    /// Execute the report command
    pub fn execute(&self) -> Result<()> {
        Self::print_banner();

        // Load analysis results
        let results = self.load_results()?;

        println!(
            "📂 Loaded analysis results from {}",
            self.input.display().to_string().cyan()
        );

        // Generate report based on format
        println!(
            "📝 Generating {} report...",
            self.format.to_uppercase().bright_cyan()
        );
        println!();

        match self.format.to_lowercase().as_str() {
            "json" => self.generate_json_report(&results)?,
            "csv" => self.generate_csv_report(&results)?,
            "pdf" => self.generate_pdf_report(&results)?,
            "html" => self.generate_html_report(&results)?,
            _ => {
                return Err(Error::reporter(format!(
                    "Unsupported format: {}",
                    self.format
                )))
            }
        }

        println!();
        println!("✅ Report generated successfully!");
        println!(
            "📄 Output: {}",
            self.output.display().to_string().bright_green().bold()
        );
        println!();

        Ok(())
    }

    /// Load analysis results from file
    fn load_results(&self) -> Result<AnalysisResult> {
        let content = std::fs::read_to_string(&self.input).map_err(Error::Io)?;

        serde_json::from_str(&content)
            .map_err(|e| Error::reporter(format!("Failed to parse results: {e}")))
    }

    /// Print banner
    fn print_banner() {
        println!();
        println!(
            "{}",
            "📊 ICOokForms - Report Generator".bright_cyan().bold()
        );
        println!("{}", "─".repeat(60).bright_black());
        println!();
    }

    /// Generate JSON report
    fn generate_json_report(&self, results: &AnalysisResult) -> Result<()> {
        let json = serde_json::to_string_pretty(results)
            .map_err(|e| Error::reporter(format!("JSON serialization error: {e}")))?;

        std::fs::write(&self.output, json).map_err(Error::Io)?;

        Ok(())
    }

    /// Generate CSV report
    fn generate_csv_report(&self, results: &AnalysisResult) -> Result<()> {
        use std::io::Write;

        let mut csv = Vec::new();

        // Header
        writeln!(&mut csv, "Type,Severity,Cookie,Title,Description")
            .map_err(|e| Error::reporter(format!("CSV write error: {e}")))?;

        // Security issues
        for issue in &results.security_issues {
            let cookie_name = if issue.issue.affected_cookies.is_empty() {
                "N/A".to_string()
            } else {
                issue.issue.affected_cookies[0].clone()
            };

            writeln!(
                &mut csv,
                "Security,{:?},{},{},\"{}\"",
                issue.issue.severity,
                cookie_name,
                issue.issue.title,
                issue.issue.description.replace('"', "\"\"")
            )
            .map_err(|e| Error::reporter(format!("CSV write error: {e}")))?;
        }

        // Compliance issues
        for issue in &results.compliance_issues {
            let cookie_name = if issue.issue.affected_cookies.is_empty() {
                "N/A".to_string()
            } else {
                issue.issue.affected_cookies[0].clone()
            };

            writeln!(
                &mut csv,
                "Compliance,{:?},{},{},\"{}\"",
                issue.issue.severity,
                cookie_name,
                issue.issue.title,
                issue.issue.description.replace('"', "\"\"")
            )
            .map_err(|e| Error::reporter(format!("CSV write error: {e}")))?;
        }

        std::fs::write(&self.output, csv).map_err(Error::Io)?;

        Ok(())
    }

    /// Generate PDF report
    fn generate_pdf_report(&self, results: &AnalysisResult) -> Result<()> {
        use printpdf::{BuiltinFont, Mm, PdfDocument};

        let (doc, page1, layer1) = PdfDocument::new(&self.title, Mm(210.0), Mm(297.0), "Layer 1");

        let current_layer = doc.get_page(page1).get_layer(layer1);

        // Add title
        let font = doc.add_builtin_font(BuiltinFont::Helvetica).unwrap();

        current_layer.use_text(&self.title, 24.0, Mm(20.0), Mm(270.0), &font);

        // Add metadata
        let mut y = 260.0;

        if let Some(ref company) = self.company {
            current_layer.use_text(format!("Company: {company}"), 12.0, Mm(20.0), Mm(y), &font);
            y -= 7.0;
        }

        if let Some(ref auditor) = self.auditor {
            current_layer.use_text(format!("Auditor: {auditor}"), 12.0, Mm(20.0), Mm(y), &font);
            y -= 7.0;
        }

        current_layer.use_text(
            format!("Date: {}", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S")),
            12.0,
            Mm(20.0),
            Mm(y),
            &font,
        );

        // Add summary section
        y -= 15.0;
        current_layer.use_text("Executive Summary", 18.0, Mm(20.0), Mm(y), &font);

        // Calculate overall_score
        let overall_score =
            (results.risk_score + results.privacy_score + results.compliance_score) / 3.0;

        y -= 10.0;
        current_layer.use_text(
            format!("Overall Score: {overall_score:.1}/100"),
            10.0,
            Mm(20.0),
            Mm(y),
            &font,
        );

        y -= 5.0;
        current_layer.use_text(
            format!("Risk Score: {:.1}/100", results.risk_score),
            10.0,
            Mm(20.0),
            Mm(y),
            &font,
        );

        y -= 5.0;
        current_layer.use_text(
            format!("Privacy Score: {:.1}/100", results.privacy_score),
            10.0,
            Mm(20.0),
            Mm(y),
            &font,
        );

        y -= 5.0;
        current_layer.use_text(
            format!("Compliance Score: {:.1}/100", results.compliance_score),
            10.0,
            Mm(20.0),
            Mm(y),
            &font,
        );

        // Add findings
        y -= 15.0;
        current_layer.use_text("Key Findings", 18.0, Mm(20.0), Mm(y), &font);

        y -= 10.0;
        current_layer.use_text(
            format!("Security Issues: {}", results.security_issues.len()),
            10.0,
            Mm(20.0),
            Mm(y),
            &font,
        );

        y -= 5.0;
        current_layer.use_text(
            format!("Compliance Issues: {}", results.compliance_issues.len()),
            10.0,
            Mm(20.0),
            Mm(y),
            &font,
        );

        y -= 5.0;
        current_layer.use_text(
            format!("Tracking Cookies: {}", results.tracking_info.len()),
            10.0,
            Mm(20.0),
            Mm(y),
            &font,
        );

        // Save PDF - FIXED: Use Error::from instead of Error::reporter
        doc.save(&mut std::io::BufWriter::new(
            std::fs::File::create(&self.output).map_err(Error::Io)?,
        ))
        .map_err(Error::from)?;

        Ok(())
    }

    /// Generate HTML report
    fn generate_html_report(&self, results: &AnalysisResult) -> Result<()> {
        let html = self.build_html(results);

        std::fs::write(&self.output, html).map_err(Error::Io)?;

        Ok(())
    }

    /// Build HTML content
    #[allow(clippy::too_many_lines)]
    fn build_html(&self, results: &AnalysisResult) -> String {
        let overall_score =
            (results.risk_score + results.privacy_score + results.compliance_score) / 3.0;

        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #2563eb;
            margin-bottom: 10px;
            font-size: 32px;
        }}
        .metadata {{
            color: #666;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 2px solid #e5e7eb;
        }}
        .scores {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}
        .score-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 24px;
            border-radius: 8px;
            text-align: center;
        }}
        .score-value {{
            font-size: 36px;
            font-weight: bold;
            margin: 10px 0;
        }}
        .score-label {{
            font-size: 14px;
            opacity: 0.9;
        }}
        .section {{
            margin-bottom: 40px;
        }}
        h2 {{
            color: #1f2937;
            margin-bottom: 20px;
            font-size: 24px;
            border-left: 4px solid #2563eb;
            padding-left: 12px;
        }}
        .issue {{
            background: #fef3c7;
            padding: 16px;
            margin-bottom: 12px;
            border-radius: 6px;
            border-left: 4px solid #f59e0b;
        }}
        .issue.critical {{
            background: #fee2e2;
            border-left-color: #dc2626;
        }}
        .issue.high {{
            background: #fed7aa;
            border-left-color: #ea580c;
        }}
        .issue-title {{
            font-weight: 600;
            margin-bottom: 8px;
            color: #1f2937;
        }}
        .issue-desc {{
            color: #4b5563;
            font-size: 14px;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 600;
            margin-right: 8px;
        }}
        .badge.critical {{ background: #dc2626; color: white; }}
        .badge.high {{ background: #ea580c; color: white; }}
        .badge.medium {{ background: #f59e0b; color: white; }}
        .badge.low {{ background: #10b981; color: white; }}
        footer {{
            margin-top: 60px;
            padding-top: 20px;
            border-top: 1px solid #e5e7eb;
            text-align: center;
            color: #6b7280;
            font-size: 14px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🍪 {}</h1>
        <div class="metadata">
            <p><strong>Generated:</strong> {}</p>
            {}
            {}
        </div>

        {}

        <div class="scores">
            <div class="score-card">
                <div class="score-label">Overall Score</div>
                <div class="score-value">{:.1}</div>
            </div>
            <div class="score-card">
                <div class="score-label">Risk Score</div>
                <div class="score-value">{:.1}</div>
            </div>
            <div class="score-card">
                <div class="score-label">Privacy Score</div>
                <div class="score-value">{:.1}</div>
            </div>
            <div class="score-card">
                <div class="score-label">Compliance Score</div>
                <div class="score-value">{:.1}</div>
            </div>
        </div>

        {}

        {}

        <footer>
            <p>Generated by ICOokForms v1.0 | The World's Reference Cookie Audit Software</p>
        </footer>
    </div>
</body>
</html>"#,
            self.title,
            self.title,
            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S"),
            self.company
                .as_ref()
                .map(|c| format!("<p><strong>Company:</strong> {c}</p>"))
                .unwrap_or_default(),
            self.auditor
                .as_ref()
                .map(|a| format!("<p><strong>Auditor:</strong> {a}</p>"))
                .unwrap_or_default(),
            if self.summary {
                Self::build_summary_html(results)
            } else {
                String::new()
            },
            overall_score,
            results.risk_score,
            results.privacy_score,
            results.compliance_score,
            if self.details && !results.security_issues.is_empty() {
                Self::build_security_issues_html(&results.security_issues)
            } else {
                String::new()
            },
            if self.details && !results.compliance_issues.is_empty() {
                Self::build_compliance_issues_html(&results.compliance_issues)
            } else {
                String::new()
            }
        )
    }

    /// Build summary HTML section
    fn build_summary_html(results: &AnalysisResult) -> String {
        let critical = results
            .security_issues
            .iter()
            .filter(|i| i.issue.severity == crate::types::Severity::Critical)
            .count()
            + results
                .compliance_issues
                .iter()
                .filter(|i| i.issue.severity == crate::types::Severity::Critical)
                .count();

        format!(
            r#"
        <div class="section">
            <h2>Executive Summary</h2>
            <p>This report presents a comprehensive analysis of cookie security and compliance.</p>
            <ul style="margin-top: 12px; margin-left: 24px;">
                <li>Total Security Issues: {}</li>
                <li>Total Compliance Issues: {}</li>
                <li>Critical Issues: {}</li>
                <li>Tracking Cookies Detected: {}</li>
            </ul>
        </div>
        "#,
            results.security_issues.len(),
            results.compliance_issues.len(),
            critical,
            results.tracking_info.len()
        )
    }

    /// Build security issues HTML section
    fn build_security_issues_html(issues: &[crate::types::SecurityIssue]) -> String {
        let mut html = String::from(r#"<div class="section"><h2>Security Issues</h2>"#);

        for issue in issues {
            let severity_class = format!("{:?}", issue.issue.severity).to_lowercase();
            let cookie_name = if issue.issue.affected_cookies.is_empty() {
                "N/A".to_string()
            } else {
                issue.issue.affected_cookies[0].clone()
            };

            write!(
                html,
                r#"
                <div class="issue {}">
                    <span class="badge {}">{:?}</span>
                    <div class="issue-title">{}</div>
                    <div class="issue-desc">Cookie: {}</div>
                    <div class="issue-desc">{}</div>
                </div>
            "#,
                severity_class,
                severity_class,
                issue.issue.severity,
                issue.issue.title,
                cookie_name,
                issue.issue.description
            )
            .unwrap();
        }

        html.push_str("</div>");
        html
    }

    /// Build compliance issues HTML section
    fn build_compliance_issues_html(issues: &[crate::types::ComplianceIssue]) -> String {
        let mut html = String::from(r#"<div class="section"><h2>Compliance Issues</h2>"#);

        for issue in issues {
            let severity_class = format!("{:?}", issue.issue.severity).to_lowercase();
            let cookie_name = if issue.issue.affected_cookies.is_empty() {
                "N/A".to_string()
            } else {
                issue.issue.affected_cookies[0].clone()
            };

            write!(
                html,
                r#"
                <div class="issue {}">
                    <span class="badge {}">{:?}</span>
                    <div class="issue-title">{} ({:?})</div>
                    <div class="issue-desc">Cookie: {}</div>
                    <div class="issue-desc">{}</div>
                </div>
            "#,
                severity_class,
                severity_class,
                issue.issue.severity,
                issue.issue.title,
                issue.regulation,
                cookie_name,
                issue.issue.description
            )
            .unwrap();
        }

        html.push_str("</div>");
        html
    }
}

/// Execute the report generation command
///
/// This function serves as the CLI entry point for the report command.
/// It processes the provided arguments and generates a report in the specified format.
///
/// # Arguments
/// * `args` - Report generation arguments including input file, output path, and format
/// * `_format` - Output format specification (currently unused, kept for CLI interface compatibility)
///
/// # Returns
/// * `Result<()>` - Success or error during report generation
#[allow(clippy::needless_pass_by_value)]
pub fn execute(args: ReportArgs, _format: crate::cli::OutputFormat) -> Result<()> {
    args.execute()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_report_args() {
        let args = ReportArgs {
            input: PathBuf::from("input.json"),
            output: PathBuf::from("output.html"),
            format: "html".to_string(),
            title: "Test Report".to_string(),
            summary: true,
            details: true,
            recommendations: true,
            charts: true,
            company: None,
            auditor: None,
        };

        assert_eq!(args.format, "html");
        assert!(args.summary);
    }
}
