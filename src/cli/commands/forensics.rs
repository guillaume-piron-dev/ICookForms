//! Forensics command
//!
//! Digital forensics analysis for cookies

use crate::cli::OutputFormat;
use crate::forensics::{ForensicAnalyzer, ForensicConfig};
use crate::types::{Cookie, Result};
use clap::{Args, Subcommand};
use colored::Colorize;
use std::fs;
use std::path::PathBuf;

/// Forensics command arguments
#[derive(Args)]
pub struct ForensicsArgs {
    /// Subcommand to execute
    #[command(subcommand)]
    command: ForensicsCommand,
}

/// Forensics subcommands
#[derive(Subcommand)]
enum ForensicsCommand {
    /// Reconstruct complete timeline from cookies
    Timeline(TimelineArgs),

    /// Parse iOS binary cookies file
    IosBinary(IosBinaryArgs),

    /// Analyze Google Analytics cookies
    GoogleAnalytics(GoogleAnalyticsArgs),

    /// Generate full forensic report
    FullReport(FullReportArgs),

    /// Collect evidence with chain-of-custody
    Evidence(EvidenceArgs),

    /// Decode cookie values (Base64, Hex, timestamps, etc.)
    Decode(DecodeArgs),
}

/// Timeline reconstruction arguments
#[derive(Args)]
struct TimelineArgs {
    /// Input file with cookies (JSON format)
    #[arg(short, long)]
    input: PathBuf,

    /// Output file for timeline (JSON format)
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Minimum confidence threshold (0.0-1.0)
    #[arg(long, default_value = "0.7")]
    threshold: f64,

    /// Show detailed anomalies
    #[arg(long)]
    show_anomalies: bool,
}

/// iOS binary cookies arguments
#[derive(Args)]
struct IosBinaryArgs {
    /// Path to iOS Cookies.binarycookies file
    #[arg(short, long)]
    input: PathBuf,

    /// Output file for extracted cookies (JSON format)
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Also extract metadata only (faster)
    #[arg(long)]
    metadata_only: bool,
}

/// Google Analytics arguments
#[derive(Args)]
struct GoogleAnalyticsArgs {
    /// Input file with cookies (JSON format)
    #[arg(short, long)]
    input: PathBuf,

    /// Output file for GA analysis (JSON format)
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Extract user journey
    #[arg(long)]
    user_journey: bool,

    /// Extract search terms
    #[arg(long)]
    search_terms: bool,
}

/// Full forensic report arguments
#[derive(Args)]
struct FullReportArgs {
    /// Input file with cookies (JSON format)
    #[arg(short, long)]
    input: PathBuf,

    /// Output file for report (PDF format)
    #[arg(short, long)]
    output: PathBuf,

    /// Include raw cookie data
    #[arg(long)]
    include_raw: bool,

    /// Timezone for timestamps
    #[arg(long, default_value = "UTC")]
    timezone: String,
}

/// Evidence collection arguments
#[derive(Args)]
struct EvidenceArgs {
    /// Input file with cookies (JSON format)
    #[arg(short, long)]
    input: PathBuf,

    /// Output directory for evidence files
    #[arg(short, long)]
    output: PathBuf,

    /// Enable chain-of-custody tracking
    #[arg(long, default_value = "true")]
    chain_of_custody: bool,

    /// Investigator name
    #[arg(long)]
    investigator: Option<String>,

    /// Case number
    #[arg(long)]
    case_number: Option<String>,
}

/// Decode arguments
#[derive(Args)]
struct DecodeArgs {
    /// Input file with cookies (JSON format)
    #[arg(short, long)]
    input: PathBuf,

    /// Cookie name to decode (decode all if not specified)
    #[arg(long)]
    cookie_name: Option<String>,

    /// Output file for decoded values (JSON format)
    #[arg(short, long)]
    output: Option<PathBuf>,
}

/// Execute forensics command
pub fn execute(args: ForensicsArgs, format: OutputFormat) -> Result<()> {
    match args.command {
        ForensicsCommand::Timeline(timeline_args) => execute_timeline(timeline_args, format),
        ForensicsCommand::IosBinary(ios_args) => execute_ios_binary(ios_args, format),
        ForensicsCommand::GoogleAnalytics(ga_args) => execute_google_analytics(ga_args, format),
        ForensicsCommand::FullReport(report_args) => execute_full_report(report_args, format),
        ForensicsCommand::Evidence(evidence_args) => execute_evidence(evidence_args, format),
        ForensicsCommand::Decode(decode_args) => execute_decode(decode_args, format),
    }
}

/// Execute timeline reconstruction
fn execute_timeline(args: TimelineArgs, format: OutputFormat) -> Result<()> {
    // Load cookies from file
    let cookies = load_cookies(&args.input)?;

    // Create forensic analyzer
    let config = ForensicConfig {
        enable_chain_of_custody: false,
        include_raw_data: false,
        timezone: "UTC".to_string(),
        anomaly_threshold: args.threshold,
    };

    let analyzer = ForensicAnalyzer::with_config(config);

    // Reconstruct timeline
    println!("{}", "🔍 Reconstructing cookie timeline...".cyan().bold());
    let timeline = analyzer.reconstruct_timeline(&cookies)?;

    // Display results
    if format.is_human_readable() {
        println!("\n{}", "Timeline Analysis:".green().bold());
        println!("  Total events: {}", timeline.events.len());
        println!(
            "  Confidence: {:.1}%",
            timeline.reconstruction_confidence * 100.0
        );
        println!(
            "  Time range: {} to {}",
            timeline.start_time.format("%Y-%m-%d %H:%M:%S"),
            timeline.end_time.format("%Y-%m-%d %H:%M:%S")
        );
        println!("  Duration: {} hours", timeline.duration.num_hours());
        println!("  Unique cookies: {}", timeline.statistics.unique_cookies);

        if !timeline.anomalies.is_empty() {
            println!("\n{}", "⚠️  Anomalies Detected:".yellow().bold());
            for (i, anomaly) in timeline.anomalies.iter().enumerate().take(10) {
                println!(
                    "  {}. {} (severity: {:.2})",
                    i + 1,
                    anomaly.description,
                    anomaly.severity
                );

                if args.show_anomalies {
                    println!("     Type: {:?}", anomaly.anomaly_type);
                    println!("     Confidence: {:.1}%", anomaly.confidence * 100.0);
                    println!(
                        "     Time range: {} to {}",
                        anomaly.time_range.0.format("%Y-%m-%d %H:%M:%S"),
                        anomaly.time_range.1.format("%Y-%m-%d %H:%M:%S")
                    );
                }
            }

            if timeline.anomalies.len() > 10 {
                println!("  ... and {} more anomalies", timeline.anomalies.len() - 10);
            }
        }
    } else {
        // JSON output
        let json = serde_json::to_string_pretty(&timeline)?;
        println!("{json}");
    }

    // Save to file if requested
    if let Some(output_path) = args.output {
        let json = serde_json::to_string_pretty(&timeline)?;
        fs::write(&output_path, json)?;
        if format.is_human_readable() {
            println!("\n✅ Timeline saved to: {}", output_path.display());
        }
    }

    Ok(())
}

/// Execute iOS binary cookie parsing
fn execute_ios_binary(args: IosBinaryArgs, format: OutputFormat) -> Result<()> {
    use crate::forensics::IosBinaryCookieParser;

    println!("{}", "📱 Parsing iOS binary cookies...".cyan().bold());

    // Read binary file
    let binary_data = fs::read(&args.input)?;

    if args.metadata_only {
        // Extract metadata only (faster)
        let metadata = IosBinaryCookieParser::extract_metadata(&binary_data)?;

        if format.is_human_readable() {
            println!("\n{}", "Extracted Metadata:".green().bold());
            println!("  Total cookies: {}", metadata.len());
            println!("\n  First 10 cookies:");
            for (i, meta) in metadata.iter().enumerate().take(10) {
                println!(
                    "    {}. Flags: 0x{:08X}, Expiry: {}",
                    i + 1,
                    meta.flags,
                    meta.expiration_date
                );
            }
        } else {
            let json = serde_json::to_string_pretty(&metadata)?;
            println!("{json}");
        }
    } else {
        // Parse full cookies
        let cookies = IosBinaryCookieParser::parse_binary_cookie_file(&binary_data)?;

        if format.is_human_readable() {
            println!("\n{}", "Extracted Cookies:".green().bold());
            println!("  Total cookies: {}", cookies.len());
            println!("\n  Sample cookies:");
            for (i, cookie) in cookies.iter().enumerate().take(5) {
                println!(
                    "    {}. {} = {} (domain: {})",
                    i + 1,
                    cookie.name.cyan(),
                    &cookie.value[..cookie.value.len().min(50)],
                    cookie.domain.as_deref().unwrap_or("N/A")
                );
            }
        } else {
            let json = serde_json::to_string_pretty(&cookies)?;
            println!("{json}");
        }

        // Save to file if requested
        if let Some(output_path) = args.output {
            let json = serde_json::to_string_pretty(&cookies)?;
            fs::write(&output_path, json)?;
            if format.is_human_readable() {
                println!("\n✅ Cookies saved to: {}", output_path.display());
            }
        }
    }

    Ok(())
}

/// Execute Google Analytics analysis
fn execute_google_analytics(args: GoogleAnalyticsArgs, format: OutputFormat) -> Result<()> {
    println!(
        "{}",
        "📊 Analyzing Google Analytics cookies...".cyan().bold()
    );

    // Load cookies
    let cookies = load_cookies(&args.input)?;

    // Create analyzer and analyze GA cookies
    let analyzer = ForensicAnalyzer::new();
    let ga_cookies = analyzer.analyze_google_analytics(&cookies)?;

    if format.is_human_readable() {
        println!("\n{}", "Google Analytics Analysis:".green().bold());
        println!("  GA cookies found: {}", ga_cookies.len());

        for (i, ga_cookie) in ga_cookies.iter().enumerate() {
            println!("\n  Cookie #{}:", i + 1);
            println!("    Client ID: {}", ga_cookie.client_id);

            if let Some(ref session_id) = ga_cookie.session_id {
                println!("    Session ID: {session_id}");
            }

            if let Some(ref campaign) = ga_cookie.campaign_info {
                println!("    Campaign:");
                println!("      Source: {}", campaign.source);
                println!("      Medium: {}", campaign.medium);
                if let Some(ref name) = campaign.name {
                    println!("      Name: {name}");
                }
            }

            if args.search_terms {
                let terms = ga_cookie.extract_search_terms();
                if !terms.is_empty() {
                    println!("    Search terms: {}", terms.join(", "));
                }
            }

            if args.user_journey {
                let journey = ga_cookie.reconstruct_user_journey();
                println!("    User Journey:");
                println!("      Pages visited: {}", journey.pages.len());
                println!("      Duration: {} seconds", journey.total_duration);
                println!("      Bounce: {}", journey.is_bounce);
                if let Some(ref entry) = journey.entry_page {
                    println!("      Entry: {entry}");
                }
                if let Some(ref exit) = journey.exit_page {
                    println!("      Exit: {exit}");
                }
            }
        }
    } else {
        let json = serde_json::to_string_pretty(&ga_cookies)?;
        println!("{json}");
    }

    // Save to file if requested
    if let Some(output_path) = args.output {
        let json = serde_json::to_string_pretty(&ga_cookies)?;
        fs::write(&output_path, json)?;
        if format.is_human_readable() {
            println!("\n✅ Analysis saved to: {}", output_path.display());
        }
    }

    Ok(())
}

/// Execute full forensic report generation
fn execute_full_report(args: FullReportArgs, format: OutputFormat) -> Result<()> {
    println!("{}", "📄 Generating full forensic report...".cyan().bold());

    // Load cookies
    let cookies = load_cookies(&args.input)?;

    // Create config
    let config = ForensicConfig {
        enable_chain_of_custody: true,
        include_raw_data: args.include_raw,
        timezone: args.timezone,
        anomaly_threshold: 0.7,
    };

    // Generate report
    let analyzer = ForensicAnalyzer::with_config(config);
    let report = analyzer.generate_report(&cookies)?;

    if format.is_human_readable() {
        println!("\n{}", "Forensic Report:".green().bold());
        println!("  Report ID: {}", report.id);
        println!(
            "  Generated: {}",
            report.generated_at.format("%Y-%m-%d %H:%M:%S")
        );
        println!("\n  Executive Summary:");
        println!("    {}", report.executive_summary);

        if let Some(ref timeline) = report.timeline {
            println!("\n  Timeline:");
            println!("    Events: {}", timeline.events.len());
            println!("    Anomalies: {}", timeline.anomalies.len());
        }

        println!("\n  Findings: {} items", report.findings.len());
        println!("  Conclusions: {} items", report.conclusions.len());
    }

    // Save report
    let json = serde_json::to_string_pretty(&report)?;
    fs::write(&args.output, json)?;

    if format.is_human_readable() {
        println!("\n✅ Forensic report saved to: {}", args.output.display());
    }

    Ok(())
}

/// Execute evidence collection
#[allow(clippy::needless_pass_by_value)]
fn execute_evidence(args: EvidenceArgs, format: OutputFormat) -> Result<()> {
    use crate::forensics::EvidenceCollector;

    println!(
        "{}",
        "⚖️  Collecting evidence with chain-of-custody..."
            .cyan()
            .bold()
    );

    // Load cookies
    let cookies = load_cookies(&args.input)?;

    // Create config
    let config = ForensicConfig {
        enable_chain_of_custody: args.chain_of_custody,
        include_raw_data: true,
        timezone: "UTC".to_string(),
        anomaly_threshold: 0.7,
    };

    // Collect evidence
    let evidence = EvidenceCollector::collect(&cookies, &config)?;

    // Create output directory
    fs::create_dir_all(&args.output)?;

    // Save evidence
    let evidence_path = args.output.join("evidence.json");
    let json = serde_json::to_string_pretty(&evidence)?;
    fs::write(&evidence_path, &json)?;

    if format.is_human_readable() {
        println!("\n{}", "Evidence Collected:".green().bold());
        println!("  Evidence ID: {}", evidence.id);
        println!(
            "  Collected at: {}",
            evidence.collected_at.format("%Y-%m-%d %H:%M:%S")
        );
        println!("  Items: {}", evidence.items.len());
        println!("  Hash (SHA256): {}", evidence.hash);

        if let Some(ref investigator) = args.investigator {
            println!("  Investigator: {investigator}");
        }
        if let Some(ref case) = args.case_number {
            println!("  Case number: {case}");
        }

        println!("\n✅ Evidence saved to: {}", evidence_path.display());
        println!(
            "  Chain-of-custody log: {}",
            args.output.join("custody_log.txt").display()
        );
    } else {
        println!("{json}");
    }

    Ok(())
}

/// Execute cookie decode
fn execute_decode(args: DecodeArgs, format: OutputFormat) -> Result<()> {
    use crate::forensics::CookieDecoder;

    println!("{}", "🔓 Decoding cookie values...".cyan().bold());

    // Load cookies
    let cookies = load_cookies(&args.input)?;

    // Filter by name if specified
    let cookies_to_decode: Vec<&Cookie> = if let Some(ref name) = args.cookie_name {
        cookies.iter().filter(|c| c.name == *name).collect()
    } else {
        cookies.iter().collect()
    };

    // Decode cookies
    let mut decoded_results = Vec::new();

    for cookie in &cookies_to_decode {
        match CookieDecoder::decode(cookie) {
            Ok(decoded) => decoded_results.push(decoded),
            Err(e) => {
                if format.is_human_readable() {
                    eprintln!("⚠️  Failed to decode {}: {}", cookie.name, e);
                }
            }
        }
    }

    if format.is_human_readable() {
        println!("\n{}", "Decoded Cookies:".green().bold());
        println!(
            "  Successfully decoded: {} / {}",
            decoded_results.len(),
            cookies_to_decode.len()
        );

        for decoded in &decoded_results {
            println!("\n  Cookie: {}", decoded.original.name.cyan());
            println!("    Encodings detected: {:?}", decoded.encodings);

            if !decoded.decoded_values.is_empty() {
                println!("    Decoded values:");
                for (key, value) in &decoded.decoded_values {
                    println!("      {}: {}", key, &value[..value.len().min(100)]);
                }
            }

            if decoded.is_timestamp {
                if let Some(timestamp) = decoded.timestamp {
                    println!("    Timestamp: {}", timestamp.format("%Y-%m-%d %H:%M:%S"));
                }
            }

            if decoded.is_guid {
                if let Some(ref guid) = decoded.guid {
                    println!("    GUID: {guid}");
                }
            }

            if let Some(ref data) = decoded.structured_data {
                println!(
                    "    Structured data: {}",
                    serde_json::to_string_pretty(data)?
                );
            }
        }
    } else {
        let json = serde_json::to_string_pretty(&decoded_results)?;
        println!("{json}");
    }

    // Save to file if requested
    if let Some(output_path) = args.output {
        let json = serde_json::to_string_pretty(&decoded_results)?;
        fs::write(&output_path, json)?;
        if format.is_human_readable() {
            println!("\n✅ Decoded values saved to: {}", output_path.display());
        }
    }

    Ok(())
}

/// Load cookies from JSON file
fn load_cookies(path: &PathBuf) -> Result<Vec<Cookie>> {
    let content = fs::read_to_string(path)?;
    let cookies: Vec<Cookie> = serde_json::from_str(&content)?;
    Ok(cookies)
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_load_cookies() {
        // Test will be implemented when we have sample data
    }
}
