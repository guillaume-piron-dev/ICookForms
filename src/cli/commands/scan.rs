//! Scan command - Scan websites for cookies
//!
//! This command performs comprehensive cookie scanning of websites

use clap::Parser;
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use std::path::PathBuf;
use tokio::time::Duration;

use crate::scanner::ScannerBuilder;
use crate::types::{Error, Result, ScanConfig, ScanResult};

/// Scan a website for cookies
#[derive(Parser, Debug)]
#[allow(clippy::struct_excessive_bools)]
pub struct ScanArgs {
    /// Target URL to scan
    #[arg(short, long)]
    pub url: String,

    /// Crawl mode - scan multiple pages
    #[arg(short, long, default_value_t = false)]
    pub crawl: bool,

    /// Maximum pages to scan in crawl mode
    #[arg(long, default_value_t = 50)]
    pub max_pages: usize,

    /// Request timeout in seconds
    #[arg(long, default_value_t = 30)]
    pub timeout: u64,

    /// User agent string
    #[arg(long, default_value = "ICOokForms/1.0 (Cookie Audit Tool)")]
    pub user_agent: String,

    /// Disable SSL verification
    #[arg(long, default_value_t = false)]
    pub insecure: bool,

    /// HTTP proxy URL
    #[arg(long)]
    pub proxy: Option<String>,

    /// Rate limit (requests per second)
    #[arg(long)]
    pub rate_limit: Option<u32>,

    /// Follow redirects
    #[arg(long, default_value_t = true)]
    pub follow_redirects: bool,

    /// Maximum redirects to follow
    #[arg(long, default_value_t = 10)]
    pub max_redirects: usize,

    /// Output file path (JSON format)
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Verbose output
    #[arg(short, long, default_value_t = false)]
    pub verbose: bool,
}

impl ScanArgs {
    /// Execute the scan command
    pub async fn execute(&self) -> Result<ScanResult> {
        // Display banner
        Self::print_banner();

        // Build scanner configuration
        let config = self.build_config();

        // Build scanner
        let scanner = ScannerBuilder::new()
            .max_pages(config.max_pages)
            .timeout(config.timeout)
            .user_agent(config.user_agent.clone())
            .verify_ssl(config.verify_ssl)
            .rate_limit(config.rate_limit.unwrap_or(10))
            .build()?;

        if let Some(ref proxy) = config.proxy {
            println!("🌐 Using proxy: {}", proxy.cyan());
        }

        // Create progress bar
        let pb = if self.crawl {
            let pb = ProgressBar::new(self.max_pages as u64);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} pages ({elapsed})")
                    .unwrap()
                    .progress_chars("=>-"),
            );
            Some(pb)
        } else {
            None
        };

        println!("🔍 Scanning: {}", self.url.bright_cyan().bold());

        // Perform scan
        let result = if self.crawl {
            println!("🕷️  Crawl mode: enabled (max {} pages)", self.max_pages);
            scanner.crawl(&self.url).await?
        } else {
            println!("📄 Single page mode");
            scanner.scan(&self.url).await?
        };

        if let Some(pb) = pb {
            pb.finish_with_message("✅ Scan complete");
        }

        // Display results
        self.print_results(&result);

        // Save to file if requested
        if let Some(ref output) = self.output {
            Self::save_results(&result, output)?;
        }

        Ok(result)
    }

    /// Build scan configuration from arguments
    fn build_config(&self) -> ScanConfig {
        // Build complete ScanConfig with all required fields
        ScanConfig {
            max_pages: self.max_pages,
            max_depth: 3, // Default depth for crawling
            timeout: Duration::from_secs(self.timeout),
            user_agent: self.user_agent.clone(),
            follow_redirects: self.follow_redirects,
            max_redirects: self.max_redirects,
            verify_ssl: !self.insecure,
            proxy: self.proxy.clone(),
            headers: Vec::new(), // Empty headers by default
            analyze_js_cookies: true,
            execute_javascript: false,
            include_domains: Vec::new(),
            exclude_domains: Vec::new(),
            rate_limit: self.rate_limit,
            concurrency: 5,
        }
    }

    /// Print banner
    fn print_banner() {
        println!();
        println!("{}", "🍪 ICOokForms - Cookie Scanner".bright_cyan().bold());
        println!("{}", "─".repeat(50).bright_black());
        println!();
    }

    /// Print scan results
    fn print_results(&self, result: &ScanResult) {
        println!();
        println!("{}", "📊 Scan Results".bright_green().bold());
        println!("{}", "─".repeat(50).bright_black());
        println!();

        Self::print_scan_stats(result);
        Self::print_cookie_summary(result);
        self.print_cookie_details(result);

        println!();
    }

    /// Print scan statistics
    fn print_scan_stats(result: &ScanResult) {
        println!(
            "✅ Status: {}",
            format!("{:?}", result.status).bright_green()
        );
        println!(
            "🌐 Pages scanned: {}",
            result.pages_scanned.to_string().cyan()
        );
        println!(
            "🔗 Requests made: {}",
            result.requests_made.to_string().cyan()
        );
        println!(
            "🍪 Cookies found: {}",
            result.cookies.len().to_string().bright_yellow().bold()
        );

        if let Some(duration) = result.duration() {
            #[allow(clippy::cast_precision_loss)]
            let seconds = duration.num_milliseconds() as f64 / 1000.0;
            println!("⏱️  Duration: {seconds:.2}s");
        }

        if !result.errors.is_empty() {
            println!();
            println!("{} Errors: {}", "⚠️".red(), result.errors.len());
            for error in &result.errors {
                println!("  • {}", error.red());
            }
        }

        println!();
    }

    /// Print cookie summary statistics
    fn print_cookie_summary(result: &ScanResult) {
        if !result.cookies.is_empty() {
            println!();
            println!("{}", "🔍 Cookie Summary".bright_cyan());
            println!("{}", "─".repeat(50).bright_black());

            let secure_count = result.cookies.iter().filter(|c| c.secure).count();
            let httponly_count = result.cookies.iter().filter(|c| c.http_only).count();
            let samesite_count = result
                .cookies
                .iter()
                .filter(|c| c.same_site.is_some())
                .count();
            let third_party_count = result.cookies.iter().filter(|c| c.is_third_party).count();

            println!("🔒 Secure flag: {}/{}", secure_count, result.cookies.len());
            println!(
                "🚫 HttpOnly flag: {}/{}",
                httponly_count,
                result.cookies.len()
            );
            println!(
                "🔗 SameSite set: {}/{}",
                samesite_count,
                result.cookies.len()
            );
            println!(
                "🌍 Third-party: {}/{}",
                third_party_count,
                result.cookies.len()
            );
        }
    }

    /// Print detailed cookie information
    fn print_cookie_details(&self, result: &ScanResult) {
        if self.verbose && !result.cookies.is_empty() {
            println!();
            println!("{}", "📝 Cookie Details".bright_cyan());
            println!("{}", "─".repeat(50).bright_black());

            for (i, cookie) in result.cookies.iter().enumerate() {
                println!();
                println!(
                    "{}. {} = {}",
                    i + 1,
                    cookie.name.bright_yellow(),
                    if cookie.value.len() > 50 {
                        format!("{}...", &cookie.value[..50])
                    } else {
                        cookie.value.clone()
                    }
                );

                if let Some(ref domain) = cookie.domain {
                    println!("   Domain: {}", domain.cyan());
                }
                if let Some(ref path) = cookie.path {
                    println!("   Path: {}", path.cyan());
                }
                println!(
                    "   Secure: {}",
                    if cookie.secure {
                        "✓".green()
                    } else {
                        "✗".red()
                    }
                );
                println!(
                    "   HttpOnly: {}",
                    if cookie.http_only {
                        "✓".green()
                    } else {
                        "✗".red()
                    }
                );
                if let Some(same_site) = cookie.same_site {
                    println!("   SameSite: {same_site:?}");
                }
            }
        }
    }

    /// Save results to file
    fn save_results(result: &ScanResult, path: &PathBuf) -> Result<()> {
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

/// Execute the scan command with the given arguments and output format
pub async fn execute(args: ScanArgs, _format: crate::cli::OutputFormat) -> Result<()> {
    args.execute().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_args() {
        let args = ScanArgs {
            url: "https://example.com".to_string(),
            crawl: false,
            max_pages: 50,
            timeout: 30,
            user_agent: "Test/1.0".to_string(),
            insecure: false,
            proxy: None,
            rate_limit: None,
            follow_redirects: true,
            max_redirects: 10,
            output: None,
            verbose: false,
        };

        let config = args.build_config();
        assert_eq!(config.max_pages, 50);
        assert_eq!(config.timeout.as_secs(), 30);
        assert_eq!(config.max_depth, 3);
    }

    #[test]
    fn test_scan_args_with_proxy() {
        let args = ScanArgs {
            url: "https://example.com".to_string(),
            crawl: true,
            max_pages: 100,
            timeout: 60,
            user_agent: "Test/1.0".to_string(),
            insecure: true,
            proxy: Some("http://proxy:8080".to_string()),
            rate_limit: Some(5),
            follow_redirects: false,
            max_redirects: 5,
            output: None,
            verbose: true,
        };

        let config = args.build_config();
        assert_eq!(config.proxy, Some("http://proxy:8080".to_string()));
        assert_eq!(config.rate_limit, Some(5));
        assert!(!config.verify_ssl);
    }
}
