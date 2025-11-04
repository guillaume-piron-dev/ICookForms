//! Security analysis example
//!
//! This example demonstrates how to analyze cookies for security vulnerabilities
//!
//! Run with: cargo run --example security_analysis

use icookforms::{
    types::{AnalysisConfig, ScanConfig},
    Analyzer, Scanner,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔒 ICOokForms - Security Analysis Example\n");

    // Scan a website
    let scanner = Scanner::new(ScanConfig::default())?;
    let url = "https://httpbin.org/cookies/set?session=test123";

    println!("📡 Scanning: {}", url);
    let scan_result = scanner.scan(url).await?;
    println!("✅ Found {} cookies\n", scan_result.cookies.len());

    // Analyze for security issues
    let analyzer = Analyzer::with_config(AnalysisConfig::default());
    let analysis = analyzer.analyze_batch(&scan_result.cookies);

    // Display security issues
    println!("🔍 Security Analysis Results\n");
    println!("═══════════════════════════════════════════════════\n");

    if analysis.security_issues.is_empty() {
        println!("✅ No security issues detected!");
    } else {
        println!(
            "⚠️  Found {} security issues:\n",
            analysis.security_issues.len()
        );

        for (i, sec_issue) in analysis.security_issues.iter().enumerate() {
            let issue = &sec_issue.issue;

            println!("{}. {} [{}]", i + 1, issue.title, issue.severity);
            println!("   Category: {:?}", issue.category);
            println!("   Description: {}", issue.description);

            if let Some(cwe) = &issue.cwe_id {
                println!("   CWE: {}", cwe);
            }

            if let Some(cvss) = sec_issue.cvss_score {
                println!("   CVSS Score: {:.1}", cvss);
            }

            if !issue.affected_cookies.is_empty() {
                println!("   Affected Cookies: {}", issue.affected_cookies.join(", "));
            }

            if !issue.recommendations.is_empty() {
                println!("   Recommendations:");
                for rec in &issue.recommendations {
                    println!("     • {}", rec);
                }
            }

            println!();
        }
    }

    // Display summary
    println!("\n📊 Security Summary\n");
    println!("═══════════════════════════════════════════════════\n");
    println!("Risk Score: {:.1}/100", analysis.risk_score);
    println!("Total Issues: {}", analysis.summary.total_issues);
    println!(
        "Secure Cookies: {}/{}",
        analysis.summary.secure_cookies, analysis.summary.total_cookies
    );
    println!(
        "HttpOnly Cookies: {}/{}",
        analysis.summary.http_only_cookies, analysis.summary.total_cookies
    );
    println!(
        "SameSite Cookies: {}/{}",
        analysis.summary.same_site_cookies, analysis.summary.total_cookies
    );

    Ok(())
}
