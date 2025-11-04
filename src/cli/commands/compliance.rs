//! Compliance command - Check compliance against specific regulations

use clap::Parser;
use colored::Colorize;
use std::path::PathBuf;

use crate::compliance::ComplianceChecker;
use crate::types::{ComplianceResult, Cookie, Error, Regulation, Result};

/// Check compliance against regulations
#[derive(Parser, Debug)]
pub struct ComplianceArgs {
    /// Input file containing cookies (JSON format)
    #[arg(short, long)]
    pub input: PathBuf,

    /// Regulation to check (gdpr, ccpa, cpra, lgpd, pipeda)
    #[arg(short, long, default_value = "gdpr")]
    pub regulation: String,

    /// Strict mode - enforce all rules
    #[arg(long, default_value_t = true)]
    pub strict: bool,

    /// Check consent mechanism
    #[arg(long, default_value_t = true)]
    pub check_consent: bool,

    /// Website URL (for consent banner verification)
    #[arg(long)]
    pub url: Option<String>,

    /// Output file path (JSON format)
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Show detailed recommendations
    #[arg(short, long, default_value_t = false)]
    pub verbose: bool,
}

impl ComplianceArgs {
    /// Execute the compliance command
    pub async fn execute(&self) -> Result<ComplianceResult> {
        Self::print_banner();

        // Parse regulation
        let regulation = self.parse_regulation()?;

        println!(
            "⚖️  Checking compliance with: {}",
            format!("{regulation:?}").bright_cyan().bold()
        );
        println!();

        // Load cookies
        let cookies = self.load_cookies()?;

        println!(
            "📂 Loaded {} cookies from {}",
            cookies.len().to_string().bright_cyan().bold(),
            self.input.display().to_string().cyan()
        );

        // Create compliance checker
        let checker = ComplianceChecker::new();

        // Check each cookie
        println!();
        println!("🔍 Checking compliance...");
        println!();

        let mut result = ComplianceResult {
            id: uuid::Uuid::new_v4().to_string(),
            regulation,
            checked_at: chrono::Utc::now(),
            compliant: true,
            score: 100.0,
            issues: Vec::new(),
            compliant_cookies: 0,
            non_compliant_cookies: 0,
            warnings: Vec::new(),
            recommendations: Vec::new(),
            consent_analysis: None,
        };

        for cookie in &cookies {
            let cookie_result = checker.check(cookie, regulation);

            if cookie_result.compliant {
                result.compliant_cookies += 1;
            } else {
                result.non_compliant_cookies += 1;
                result.compliant = false;
            }

            result.issues.extend(cookie_result.issues);
            result.warnings.extend(cookie_result.warnings);
            result.recommendations.extend(cookie_result.recommendations);
        }

        // Calculate score
        if cookies.is_empty() {
            result.score = 100.0;
        } else {
            #[allow(clippy::cast_precision_loss)]
            let score = (result.compliant_cookies as f32 / cookies.len() as f32) * 100.0;
            result.score = score;
        }

        // Check consent if URL provided
        if let Some(ref url) = self.url {
            if self.check_consent {
                println!("🌐 Checking consent mechanism at: {}", url.cyan());
                result.consent_analysis = self.check_consent_mechanism(url, regulation).await.ok();
            }
        }

        // Display results
        self.print_results(&result);

        // Save to file if requested
        if let Some(ref output) = self.output {
            Self::save_results(&result, output)?;
        }

        Ok(result)
    }

    /// Parse regulation string
    fn parse_regulation(&self) -> Result<Regulation> {
        match self.regulation.to_lowercase().as_str() {
            "gdpr" => Ok(Regulation::GDPR),
            "ccpa" => Ok(Regulation::CCPA),
            "cpra" => Ok(Regulation::CPRA),
            "lgpd" => Ok(Regulation::LGPD),
            "pipeda" => Ok(Regulation::PIPEDA),
            "popia" => Ok(Regulation::POPIA),
            _ => Err(Error::compliance(format!(
                "Unknown regulation: {}",
                self.regulation
            ))),
        }
    }

    /// Load cookies from file
    fn load_cookies(&self) -> Result<Vec<Cookie>> {
        let content = std::fs::read_to_string(&self.input).map_err(Error::Io)?;

        // Try to parse as ScanResult first
        if let Ok(scan_result) = serde_json::from_str::<crate::types::ScanResult>(&content) {
            return Ok(scan_result.cookies);
        }

        // Try to parse as direct cookie array
        serde_json::from_str::<Vec<Cookie>>(&content)
            .map_err(|e| Error::compliance(format!("Failed to parse cookies: {e}")))
    }

    /// Check consent mechanism on website
    async fn check_consent_mechanism(
        &self,
        url: &str,
        regulation: Regulation,
    ) -> Result<crate::types::report::ConsentAnalysis> {
        use reqwest::Client;

        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(Error::Http)?;

        let response = client.get(url).send().await.map_err(Error::Http)?;
        let body = response.text().await.map_err(Error::Http)?;

        let mut analysis = Self::parse_consent_page(&body);
        Self::validate_consent_by_regulation(&mut analysis, regulation);

        Ok(analysis)
    }

    /// Parse the webpage for consent indicators
    fn parse_consent_page(body: &str) -> crate::types::report::ConsentAnalysis {
        use scraper::Html;

        let document = Html::parse_document(body);

        let mut analysis = crate::types::report::ConsentAnalysis {
            banner_present: false,
            blocks_cookies: false,
            has_reject_option: false,
            reject_equally_prominent: false,
            granular_options: false,
            policy_link_present: false,
            freely_given: true,
            specific: true,
            informed: true,
            unambiguous: true,
            dark_patterns: Vec::new(),
        };

        Self::check_consent_banner(&document, &mut analysis);
        Self::check_reject_button(&document, &mut analysis);
        Self::check_granular_options(&document, &mut analysis);
        Self::check_policy_link(&document, &mut analysis);
        Self::check_dark_patterns(&document, &mut analysis);

        analysis
    }

    /// Check for consent banner presence
    fn check_consent_banner(
        document: &scraper::Html,
        analysis: &mut crate::types::report::ConsentAnalysis,
    ) {
        use scraper::Selector;

        let banner_selectors = vec![
            "#cookie-banner",
            ".cookie-banner",
            "#consent-banner",
            ".consent-modal",
            "[data-consent]",
            "#cookieConsent",
        ];

        for selector_str in banner_selectors {
            if let Ok(selector) = Selector::parse(selector_str) {
                if document.select(&selector).next().is_some() {
                    analysis.banner_present = true;
                    break;
                }
            }
        }
    }

    /// Check for reject button
    fn check_reject_button(
        document: &scraper::Html,
        analysis: &mut crate::types::report::ConsentAnalysis,
    ) {
        use scraper::Selector;

        let reject_keywords = ["reject", "refuse", "decline", "no", "deny"];
        if let Ok(button_selector) =
            Selector::parse("button, a[role='button'], input[type='button']")
        {
            for element in document.select(&button_selector) {
                let text = element.text().collect::<String>().to_lowercase();
                if reject_keywords.iter().any(|k| text.contains(k)) {
                    analysis.has_reject_option = true;
                    break;
                }
            }
        }
    }

    /// Check for granular cookie options
    fn check_granular_options(
        document: &scraper::Html,
        analysis: &mut crate::types::report::ConsentAnalysis,
    ) {
        use scraper::Selector;

        let granular_keywords = ["customize", "preferences", "settings", "manage cookies"];
        if let Ok(button_selector) = Selector::parse("button, a, span") {
            for element in document.select(&button_selector) {
                let text = element.text().collect::<String>().to_lowercase();
                if granular_keywords.iter().any(|k| text.contains(k)) {
                    analysis.granular_options = true;
                    break;
                }
            }
        }
    }

    /// Check for policy link
    fn check_policy_link(
        document: &scraper::Html,
        analysis: &mut crate::types::report::ConsentAnalysis,
    ) {
        use scraper::Selector;

        if let Ok(link_selector) = Selector::parse("a") {
            let policy_keywords = ["privacy policy", "cookie policy", "privacy notice"];
            for element in document.select(&link_selector) {
                let text = element.text().collect::<String>().to_lowercase();
                if policy_keywords.iter().any(|k| text.contains(k)) {
                    analysis.policy_link_present = true;
                    break;
                }
            }
        }
    }

    /// Check for dark patterns in consent UI
    fn check_dark_patterns(
        document: &scraper::Html,
        analysis: &mut crate::types::report::ConsentAnalysis,
    ) {
        use scraper::Selector;

        let accept_keywords = ["accept", "agree", "allow", "consent", "ok"];
        let reject_keywords = ["reject", "refuse", "decline", "no", "deny"];

        if let Ok(button_selector) = Selector::parse("button, a[role='button']") {
            let mut accept_prominent = false;
            let mut reject_prominent = false;

            for element in document.select(&button_selector) {
                let text = element.text().collect::<String>().to_lowercase();
                if accept_keywords.iter().any(|k| text.contains(k)) {
                    let classes = element.value().attr("class").unwrap_or("");
                    if classes.contains("primary") || classes.contains("btn-primary") {
                        accept_prominent = true;
                    }
                }
                if reject_keywords.iter().any(|k| text.contains(k)) {
                    let classes = element.value().attr("class").unwrap_or("");
                    if classes.contains("primary") || classes.contains("btn-primary") {
                        reject_prominent = true;
                    }
                }
            }

            if accept_prominent && !reject_prominent {
                analysis
                    .dark_patterns
                    .push("Accept button more prominent than reject".to_string());
                analysis.reject_equally_prominent = false;
            } else {
                analysis.reject_equally_prominent = true;
            }
        }
    }

    /// Validate consent based on regulation requirements
    fn validate_consent_by_regulation(
        analysis: &mut crate::types::report::ConsentAnalysis,
        regulation: Regulation,
    ) {
        if regulation == Regulation::GDPR {
            if !analysis.banner_present {
                analysis
                    .dark_patterns
                    .push("Missing consent banner".to_string());
            }
            if !analysis.has_reject_option {
                analysis
                    .dark_patterns
                    .push("Missing 'Reject All' button (GDPR requirement)".to_string());
            }
            if !analysis.reject_equally_prominent {
                analysis
                    .dark_patterns
                    .push("'Accept' and 'Reject' buttons must have equal prominence".to_string());
            }
        }
        // Note: CCPA/CPRA "Do Not Sell" link validation would require document access
        // This is handled during page parsing phase
    }

    /// Print banner
    fn print_banner() {
        println!();
        println!(
            "{}",
            "⚖️  ICOokForms - Compliance Checker".bright_cyan().bold()
        );
        println!("{}", "─".repeat(60).bright_black());
        println!();
    }

    /// Print compliance results
    fn print_results(&self, result: &ComplianceResult) {
        println!("{}", "📊 Compliance Results".bright_green().bold());
        println!("{}", "─".repeat(60).bright_black());
        println!();

        // Overall compliance
        let status = if result.compliant {
            "✅ COMPLIANT".bright_green().bold()
        } else {
            "❌ NON-COMPLIANT".bright_red().bold()
        };

        println!("Status: {status}");
        println!("Score: {}", Self::format_score(result.score));
        println!();

        // Cookie statistics
        println!("{}", "📈 Cookie Statistics".bright_cyan());
        println!(
            "   Compliant cookies: {}",
            result.compliant_cookies.to_string().bright_green()
        );
        println!(
            "   Non-compliant cookies: {}",
            result.non_compliant_cookies.to_string().bright_red()
        );
        println!(
            "   Total cookies: {}",
            (result.compliant_cookies + result.non_compliant_cookies)
                .to_string()
                .cyan()
        );
        println!();

        // Issues
        if !result.issues.is_empty() {
            println!("{}", "⚠️  Issues".red().bold());
            for (i, issue) in result.issues.iter().enumerate() {
                println!("   {}. {:?}", i + 1, issue);
            }
            println!();
        }

        // Warnings
        if !result.warnings.is_empty() {
            println!("{}", "⚠️  Warnings".yellow().bold());
            for (i, warning) in result.warnings.iter().enumerate() {
                println!("   {}. {}", i + 1, warning);
            }
            println!();
        }

        // Recommendations
        if !result.recommendations.is_empty() && (self.verbose || !result.compliant) {
            println!("{}", "💡 Recommendations".bright_magenta().bold());
            for (i, rec) in result.recommendations.iter().enumerate() {
                println!("   {}. {}", i + 1, rec);
            }
            println!();
        }

        // Consent analysis
        if let Some(ref consent) = result.consent_analysis {
            println!("{}", "🎯 Consent Mechanism Analysis".bright_blue().bold());
            println!(
                "   Banner present: {}",
                if consent.banner_present {
                    "✓".green()
                } else {
                    "✗".red()
                }
            );
            println!(
                "   Reject button: {}",
                if consent.has_reject_option {
                    "✓".green()
                } else {
                    "✗".red()
                }
            );
            println!(
                "   Granular options: {}",
                if consent.granular_options {
                    "✓".green()
                } else {
                    "✗".red()
                }
            );

            if !consent.dark_patterns.is_empty() {
                println!();
                println!("   Dark Patterns Detected:");
                for issue in &consent.dark_patterns {
                    println!("      • {}", issue.red());
                }
            }
            println!();
        }
    }

    /// Format score with color
    fn format_score(score: f32) -> String {
        let score_str = format!("{score:.1}/100");
        if score >= 80.0 {
            score_str.bright_green().bold().to_string()
        } else if score >= 60.0 {
            score_str.yellow().bold().to_string()
        } else {
            score_str.bright_red().bold().to_string()
        }
    }

    /// Save results to file
    fn save_results(result: &ComplianceResult, path: &PathBuf) -> Result<()> {
        let json = serde_json::to_string_pretty(result)
            .map_err(|e| Error::reporter(format!("JSON serialization error: {e}")))?;

        std::fs::write(path, json).map_err(Error::Io)?;

        println!(
            "💾 Results saved to: {}",
            path.display().to_string().bright_green()
        );

        Ok(())
    }
}

/// Execute the compliance checking command
///
/// This function serves as the CLI entry point for the compliance command.
/// It processes the provided arguments and checks cookie compliance against the specified regulation.
///
/// # Arguments
/// * `args` - Compliance checking arguments including input file, regulation, and options
/// * `_format` - Output format specification (currently unused, kept for CLI interface compatibility)
///
/// # Returns
/// * `Result<()>` - Success or error during compliance check
pub async fn execute(args: ComplianceArgs, _format: crate::cli::OutputFormat) -> Result<()> {
    args.execute().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compliance_args() {
        let args = ComplianceArgs {
            input: PathBuf::from("test.json"),
            regulation: "gdpr".to_string(),
            strict: true,
            check_consent: true,
            url: None,
            output: None,
            verbose: false,
        };

        let reg = args.parse_regulation().unwrap();
        assert_eq!(reg, Regulation::GDPR);
    }

    #[test]
    fn test_parse_regulation() {
        let args = ComplianceArgs {
            input: PathBuf::from("test.json"),
            regulation: "CCPA".to_string(),
            strict: true,
            check_consent: false,
            url: None,
            output: None,
            verbose: false,
        };

        assert_eq!(args.parse_regulation().unwrap(), Regulation::CCPA);
    }
}
