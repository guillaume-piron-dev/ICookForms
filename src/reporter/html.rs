//! HTML report generation
//!
//! Generate professional HTML reports with styling and interactivity

use crate::types::{AnalysisResult, Result, Severity};
use std::fmt::Write;
use std::path::Path;

/// Generate HTML report and save to file
pub fn generate(results: &AnalysisResult, output_path: &Path) -> Result<()> {
    let html = generate_string(results)?;
    std::fs::write(output_path, html)?;
    Ok(())
}

/// Generate HTML report as string
#[allow(clippy::too_many_lines)]
pub fn generate_string(results: &AnalysisResult) -> Result<String> {
    let mut html = String::from(HTML_HEADER);

    // Title and metadata
    write!(
        html,
        "<h1>🍪 ICOokForms Cookie Analysis Report</h1>\n\
         <div class='metadata'>\n\
         <p><strong>Analysis ID:</strong> {}</p>\n\
         <p><strong>Scan ID:</strong> {}</p>\n\
         <p><strong>Date:</strong> {}</p>\n\
         </div>\n",
        results.id,
        results.scan_id,
        results.analyzed_at.format("%Y-%m-%d %H:%M:%S UTC")
    )
    .unwrap();

    // Score dashboard
    write!(
        html,
        "<div class='score-dashboard'>\n\
         <div class='score-card {}'>\n\
         <h3>Risk Score</h3>\n\
         <div class='score'>{:.1}</div>\n\
         <div class='score-bar'><div class='score-fill' style='width: {}%'></div></div>\n\
         </div>\n\
         <div class='score-card {}'>\n\
         <h3>Compliance Score</h3>\n\
         <div class='score'>{:.1}</div>\n\
         <div class='score-bar'><div class='score-fill' style='width: {}%'></div></div>\n\
         </div>\n\
         <div class='score-card {}'>\n\
         <h3>Privacy Score</h3>\n\
         <div class='score'>{:.1}</div>\n\
         <div class='score-bar'><div class='score-fill' style='width: {}%'></div></div>\n\
         </div>\n\
         </div>\n",
        get_risk_class(results.risk_score),
        results.risk_score,
        results.risk_score,
        get_compliance_class(results.compliance_score),
        results.compliance_score,
        results.compliance_score,
        get_compliance_class(results.privacy_score),
        results.privacy_score,
        results.privacy_score
    )
    .unwrap();

    // Summary section
    html.push_str("<h2>📊 Summary</h2>\n<div class='summary'>\n");
    write!(html,
        "<div class='summary-item'><strong>Total Cookies:</strong> {}</div>\n\
         <div class='summary-item'><strong>First-Party:</strong> {}</div>\n\
         <div class='summary-item'><strong>Third-Party:</strong> {}</div>\n\
         <div class='summary-item'><strong>Session:</strong> {}</div>\n\
         <div class='summary-item'><strong>Persistent:</strong> {}</div>\n\
         <div class='summary-item'><strong>Secure:</strong> {}</div>\n\
         <div class='summary-item'><strong>HttpOnly:</strong> {}</div>\n\
         <div class='summary-item'><strong>SameSite:</strong> {}</div>\n\
         <div class='summary-item'><strong>Total Issues:</strong> <span class='badge severity-high'>{}</span></div>\n",
        results.summary.total_cookies,
        results.summary.first_party_cookies,
        results.summary.third_party_cookies,
        results.summary.session_cookies,
        results.summary.persistent_cookies,
        results.summary.secure_cookies,
        results.summary.http_only_cookies,
        results.summary.same_site_cookies,
        results.summary.total_issues
    ).unwrap();
    html.push_str("</div>\n");

    // Security Issues
    if !results.security_issues.is_empty() {
        writeln!(
            html,
            "<h2>🔒 Security Issues ({})</h2>",
            results.security_issues.len()
        )
        .unwrap();

        for issue in &results.security_issues {
            let severity_class = get_severity_class(issue.issue.severity);
            write!(
                html,
                "<div class='issue {}'>\n\
                 <div class='issue-header'>\n\
                 <span class='badge {}'>{}</span>\n\
                 <h3>{}</h3>\n\
                 </div>\n\
                 <p class='description'>{}</p>\n",
                severity_class,
                severity_class,
                issue.issue.severity,
                escape_html(&issue.issue.title),
                escape_html(&issue.issue.description)
            )
            .unwrap();

            if !issue.issue.affected_cookies.is_empty() {
                html.push_str("<p><strong>Affected Cookies:</strong> ");
                html.push_str(
                    &issue
                        .issue
                        .affected_cookies
                        .iter()
                        .map(|c| format!("<code>{}</code>", escape_html(c)))
                        .collect::<Vec<_>>()
                        .join(", "),
                );
                html.push_str("</p>\n");
            }

            if !issue.issue.recommendations.is_empty() {
                html.push_str("<details><summary>Recommendations</summary><ul>\n");
                for rec in &issue.issue.recommendations {
                    writeln!(html, "<li>{}</li>", escape_html(rec)).unwrap();
                }
                html.push_str("</ul></details>\n");
            }

            html.push_str("</div>\n");
        }
    }

    // Compliance Issues
    if !results.compliance_issues.is_empty() {
        writeln!(
            html,
            "<h2>📋 Compliance Issues ({})</h2>",
            results.compliance_issues.len()
        )
        .unwrap();

        for issue in &results.compliance_issues {
            let severity_class = get_severity_class(issue.issue.severity);
            write!(
                html,
                "<div class='issue {}'>\n\
                 <div class='issue-header'>\n\
                 <span class='badge {}'>{}</span>\n\
                 <span class='badge badge-regulation'>{}</span>\n\
                 <h3>{}</h3>\n\
                 </div>\n\
                 <p class='description'>{}</p>\n\
                 <p><strong>Requirement:</strong> {}</p>\n",
                severity_class,
                severity_class,
                issue.issue.severity,
                issue.regulation.short_name(),
                escape_html(&issue.issue.title),
                escape_html(&issue.issue.description),
                escape_html(&issue.requirement)
            )
            .unwrap();

            if let Some(ref penalty) = issue.penalty {
                writeln!(
                    html,
                    "<p class='penalty'><strong>⚠️ Potential Penalty:</strong> {}</p>",
                    escape_html(penalty)
                )
                .unwrap();
            }

            html.push_str("</div>\n");
        }
    }

    // Tracking Information
    if !results.tracking_info.is_empty() {
        write!(
            html,
            "<h2>🎯 Tracking Cookies ({})</h2>\n<div class='tracking-list'>\n",
            results.tracking_info.len()
        )
        .unwrap();

        for tracking in &results.tracking_info {
            write!(
                html,
                "<div class='tracking-item'>\n\
                 <h4><code>{}</code></h4>\n\
                 <p><strong>Type:</strong> {:?}</p>\n\
                 <p><strong>Vendor:</strong> {}</p>\n\
                 <p><strong>Purpose:</strong> {}</p>\n\
                 <p><strong>Risk Level:</strong> <span class='badge {}'>{}</span></p>\n",
                escape_html(&tracking.cookie_name),
                tracking.tracking_type,
                escape_html(&tracking.vendor.clone().unwrap_or("Unknown".to_string())),
                escape_html(&tracking.purpose),
                get_severity_class(tracking.risk_level),
                tracking.risk_level
            )
            .unwrap();

            if !tracking.data_collected.is_empty() {
                html.push_str("<details><summary>Data Collected</summary><ul>\n");
                for data in &tracking.data_collected {
                    writeln!(html, "<li>{}</li>", escape_html(data)).unwrap();
                }
                html.push_str("</ul></details>\n");
            }

            html.push_str("</div>\n");
        }

        html.push_str("</div>\n");
    }

    html.push_str(HTML_FOOTER);
    Ok(html)
}

/// Get CSS class for risk score
fn get_risk_class(score: f32) -> &'static str {
    match score {
        s if s >= 75.0 => "score-critical",
        s if s >= 50.0 => "score-high",
        s if s >= 25.0 => "score-medium",
        _ => "score-low",
    }
}

/// Get CSS class for compliance score
fn get_compliance_class(score: f32) -> &'static str {
    match score {
        s if s >= 90.0 => "score-excellent",
        s if s >= 75.0 => "score-good",
        s if s >= 50.0 => "score-fair",
        _ => "score-poor",
    }
}

/// Get CSS class for severity
fn get_severity_class(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "severity-critical",
        Severity::High => "severity-high",
        Severity::Medium => "severity-medium",
        Severity::Low => "severity-low",
        Severity::Info => "severity-info",
    }
}

/// Escape HTML special characters
fn escape_html(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

const HTML_HEADER: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ICOokForms Analysis Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif; 
               line-height: 1.6; color: #333; background: #f5f5f5; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; margin-bottom: 30px; font-size: 2.5em; }
        h2 { color: #34495e; margin: 30px 0 20px; padding-bottom: 10px; border-bottom: 2px solid #3498db; }
        h3 { color: #2c3e50; margin: 15px 0 10px; }
        h4 { color: #555; margin: 10px 0; }
        .metadata { background: #ecf0f1; padding: 15px; border-radius: 5px; margin-bottom: 30px; }
        .metadata p { margin: 5px 0; }
        .score-dashboard { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 30px 0; }
        .score-card { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 25px; border-radius: 10px; text-align: center; }
        .score-card h3 { color: white; margin-bottom: 15px; }
        .score { font-size: 3em; font-weight: bold; margin: 10px 0; }
        .score-bar { background: rgba(255,255,255,0.3); height: 10px; border-radius: 5px; overflow: hidden; margin-top: 15px; }
        .score-fill { background: white; height: 100%; transition: width 0.3s; }
        .score-critical { background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%); }
        .score-high { background: linear-gradient(135deg, #e67e22 0%, #d35400 100%); }
        .score-medium { background: linear-gradient(135deg, #f39c12 0%, #e67e22 100%); }
        .score-low { background: linear-gradient(135deg, #2ecc71 0%, #27ae60 100%); }
        .score-excellent { background: linear-gradient(135deg, #2ecc71 0%, #27ae60 100%); }
        .score-good { background: linear-gradient(135deg, #3498db 0%, #2980b9 100%); }
        .score-fair { background: linear-gradient(135deg, #f39c12 0%, #e67e22 100%); }
        .score-poor { background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%); }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }
        .summary-item { background: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid #3498db; }
        .issue { background: #fff; border: 1px solid #ddd; border-radius: 8px; padding: 20px; margin: 15px 0; }
        .issue-header { display: flex; align-items: center; gap: 10px; margin-bottom: 15px; flex-wrap: wrap; }
        .description { color: #555; margin: 15px 0; }
        .badge { display: inline-block; padding: 5px 12px; border-radius: 20px; font-size: 0.85em; font-weight: bold; }
        .severity-critical { background: #e74c3c; color: white; }
        .severity-high { background: #e67e22; color: white; }
        .severity-medium { background: #f39c12; color: white; }
        .severity-low { background: #3498db; color: white; }
        .severity-info { background: #95a5a6; color: white; }
        .badge-regulation { background: #9b59b6; color: white; }
        .penalty { background: #fff3cd; border-left: 4px solid #ffc107; padding: 10px; margin: 10px 0; }
        code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-family: 'Courier New', monospace; font-size: 0.9em; }
        details { margin: 10px 0; }
        summary { cursor: pointer; font-weight: bold; padding: 10px; background: #f8f9fa; border-radius: 5px; }
        summary:hover { background: #e9ecef; }
        ul { margin: 10px 0 10px 20px; }
        li { margin: 5px 0; }
        .tracking-list { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .tracking-item { background: #f8f9fa; border-left: 4px solid #3498db; padding: 20px; border-radius: 5px; }
    </style>
</head>
<body>
<div class="container">
"#;

const HTML_FOOTER: &str = r#"
<footer style="margin-top: 50px; padding-top: 20px; border-top: 1px solid #ddd; text-align: center; color: #777;">
    <p>Generated by <strong>ICOokForms</strong> - The World's Reference Cookie Audit Software</p>
    <p style="font-size: 0.9em; margin-top: 10px;">© 2025 ICOokForms | Apache 2.0 License</p>
</footer>
</div>
</body>
</html>
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_escape_html() {
        assert_eq!(escape_html("<script>"), "&lt;script&gt;");
        assert_eq!(escape_html("A & B"), "A &amp; B");
    }

    #[test]
    fn test_generate_string() {
        let results = AnalysisResult::new("test-scan");
        let html = generate_string(&results);
        assert!(html.is_ok());

        let content = html.unwrap();
        assert!(content.contains("<!DOCTYPE html>"));
        assert!(content.contains("ICOokForms"));
    }

    #[test]
    fn test_generate_file() {
        let results = AnalysisResult::new("test-scan");
        let temp_file = NamedTempFile::new().unwrap();
        let result = generate(&results, temp_file.path());
        assert!(result.is_ok());

        let content = std::fs::read_to_string(temp_file.path()).unwrap();
        assert!(content.contains("<!DOCTYPE html>"));
    }
}
