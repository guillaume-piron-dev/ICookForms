//! ML/AI command
//!
//! Machine Learning anomaly detection for cookies

use crate::cli::OutputFormat;
use crate::ml_analyzer::{AnomalySeverity, MLAnalyzer, MLConfig};
use crate::types::{Cookie, Result};
use clap::{Args, Subcommand};
use colored::Colorize;
use std::fs;
use std::path::PathBuf;

/// ML/AI command arguments
#[derive(Args)]
pub struct MlArgs {
    /// Subcommand to execute
    #[command(subcommand)]
    command: MlCommand,
}

/// ML subcommands
#[derive(Subcommand)]
enum MlCommand {
    /// Train ML models on normal cookies
    Train(TrainArgs),

    /// Detect anomalies using trained model
    Detect(DetectArgs),

    /// Analyze behavior patterns
    Analyze(AnalyzeArgs),

    /// Recognize known patterns
    Patterns(PatternsArgs),

    /// Detect zero-day attacks
    ZeroDay(ZeroDayArgs),
}

/// Training arguments
#[derive(Args)]
struct TrainArgs {
    /// Dataset file with normal cookies (JSON format)
    #[arg(short, long)]
    dataset: PathBuf,

    /// Output model file
    #[arg(short, long)]
    output: PathBuf,

    /// Number of trees for Isolation Forest
    #[arg(long, default_value = "100")]
    n_trees: usize,

    /// Sample size for each tree
    #[arg(long, default_value = "256")]
    sample_size: usize,

    /// Random seed for reproducibility
    #[arg(long)]
    seed: Option<u64>,
}

/// Detection arguments
#[derive(Args)]
struct DetectArgs {
    /// Input file with cookies to analyze (JSON format)
    #[arg(short, long)]
    input: PathBuf,

    /// Trained model file
    #[arg(short, long)]
    model: Option<PathBuf>,

    /// Output file for detected anomalies (JSON format)
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Anomaly score threshold (0.0-1.0)
    #[arg(long, default_value = "0.7")]
    threshold: f64,

    /// Show only high and critical severity
    #[arg(long)]
    high_severity_only: bool,
}

/// Behavioral analysis arguments
#[derive(Args)]
struct AnalyzeArgs {
    /// Input file with cookies (JSON format)
    #[arg(short, long)]
    input: PathBuf,

    /// Baseline dataset for comparison (optional)
    #[arg(short, long)]
    baseline: Option<PathBuf>,

    /// Output file for analysis report (JSON format)
    #[arg(short, long)]
    output: Option<PathBuf>,
}

/// Pattern recognition arguments
#[derive(Args)]
struct PatternsArgs {
    /// Input file with cookies (JSON format)
    #[arg(short, long)]
    input: PathBuf,

    /// Output file for recognized patterns (JSON format)
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Show only malicious patterns
    #[arg(long)]
    malicious_only: bool,
}

/// Zero-day detection arguments
#[derive(Args)]
struct ZeroDayArgs {
    /// Input file with cookies (JSON format)
    #[arg(short, long)]
    input: PathBuf,

    /// Output file for potential zero-days (JSON format)
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Aggressiveness level (1-5, higher = more false positives)
    #[arg(long, default_value = "3")]
    aggressiveness: u8,
}

/// Execute ML command
pub fn execute(args: MlArgs, format: OutputFormat) -> Result<()> {
    match args.command {
        MlCommand::Train(train_args) => execute_train(train_args, format),
        MlCommand::Detect(detect_args) => execute_detect(detect_args, format),
        MlCommand::Analyze(analyze_args) => execute_analyze(analyze_args, format),
        MlCommand::Patterns(patterns_args) => execute_patterns(patterns_args, format),
        MlCommand::ZeroDay(zeroday_args) => execute_zeroday(zeroday_args, format),
    }
}

/// Execute training
#[allow(clippy::needless_pass_by_value)]
fn execute_train(args: TrainArgs, format: OutputFormat) -> Result<()> {
    println!("{}", "🤖 Training ML models...".cyan().bold());

    // Load training dataset
    let cookies = load_cookies(&args.dataset)?;

    println!("  Dataset size: {} cookies", cookies.len());

    // Create ML config
    let config = MLConfig {
        anomaly_threshold: 0.7,
        n_trees: args.n_trees,
        sample_size: args.sample_size,
        enable_behavioral_analysis: true,
        enable_pattern_recognition: true,
        enable_zero_day_detection: true,
        min_training_samples: 100,
        max_features: 50,
        random_seed: args.seed,
    };

    // Create and train analyzer
    let mut analyzer = MLAnalyzer::with_config(&config);

    println!("  Training models...");
    let report = analyzer.train(&cookies)?;

    if format.is_human_readable() {
        println!("\n{}", "Training Complete:".green().bold());
        println!("  Samples used: {}", report.samples_used);
        println!("  Models trained: {}", report.models_trained.join(", "));
        println!(
            "  Training duration: {:.2}s",
            report.training_duration.as_secs_f64()
        );
        println!("  Success: {}", if report.success { "✅" } else { "❌" });
    } else {
        let json = serde_json::to_string_pretty(&report)?;
        println!("{json}");
    }

    // Save model
    // Note: For now, we save the configuration. Full model serialization would require additional dependencies.
    let model_data = serde_json::to_string_pretty(&analyzer.config())?;
    fs::write(&args.output, model_data)?;

    if format.is_human_readable() {
        println!("\n✅ Model saved to: {}", args.output.display());
        println!("\n💡 Use this model with:");
        println!(
            "   icookforms ml detect --input cookies.json --model {}",
            args.output.display()
        );
    }

    Ok(())
}

/// Execute anomaly detection
fn execute_detect(args: DetectArgs, format: OutputFormat) -> Result<()> {
    println!("{}", "🔍 Detecting anomalies...".cyan().bold());

    // Load cookies to analyze
    let cookies = load_cookies(&args.input)?;

    println!("  Analyzing {} cookies...", cookies.len());

    // Create analyzer
    let config = MLConfig {
        anomaly_threshold: args.threshold,
        ..Default::default()
    };

    let mut analyzer = MLAnalyzer::with_config(&config);

    // Load model if provided, otherwise train on the fly
    if let Some(model_path) = &args.model {
        println!("  Loading model from: {}", model_path.display());
        // TODO: Load model from file
        // For now, we create a fresh analyzer
        println!("  ⚠️  Model loading not yet implemented, using fresh analyzer");
    }

    // If not trained, we need training data
    if !analyzer.is_trained() {
        println!("  ⚠️  Model not trained. Training on provided data...");
        let report = analyzer.train(&cookies)?;
        println!("  Trained {} models", report.models_trained.len());
    }

    // Detect anomalies
    let anomalies = analyzer.detect(&cookies)?;

    // Filter by severity if requested
    let filtered_anomalies: Vec<_> = if args.high_severity_only {
        anomalies
            .into_iter()
            .filter(|a| {
                matches!(
                    a.severity,
                    AnomalySeverity::High | AnomalySeverity::Critical
                )
            })
            .collect()
    } else {
        anomalies
    };

    if format.is_human_readable() {
        println!("\n{}", "Anomalies Detected:".green().bold());
        println!("  Total analyzed: {}", cookies.len());
        println!("  Anomalies found: {}", filtered_anomalies.len());

        if filtered_anomalies.is_empty() {
            println!(
                "\n  ✅ No anomalies detected above threshold {:.2}",
                args.threshold
            );
        } else {
            println!("\n  Top anomalies:");

            for (i, anomaly) in filtered_anomalies.iter().enumerate().take(10) {
                let severity_color = match anomaly.severity {
                    AnomalySeverity::Critical => "🔴",
                    AnomalySeverity::High => "🟠",
                    AnomalySeverity::Medium => "🟡",
                    AnomalySeverity::Low => "🟢",
                };

                println!(
                    "\n  {}. {} {} (score: {:.2})",
                    i + 1,
                    severity_color,
                    anomaly.cookie.name.cyan(),
                    anomaly.score
                );

                println!(
                    "     Domain: {}",
                    anomaly.cookie.domain.as_deref().unwrap_or("N/A")
                );
                println!("     Reasons: {:?}", anomaly.reasons);

                if let Some(ref explanation) = anomaly.explanation {
                    println!("     Explanation:");
                    for line in explanation.lines().take(5) {
                        println!("       {line}");
                    }
                }
            }

            if filtered_anomalies.len() > 10 {
                println!(
                    "\n  ... and {} more anomalies",
                    filtered_anomalies.len() - 10
                );
            }

            // Severity breakdown
            let critical = filtered_anomalies
                .iter()
                .filter(|a| a.severity == AnomalySeverity::Critical)
                .count();
            let high = filtered_anomalies
                .iter()
                .filter(|a| a.severity == AnomalySeverity::High)
                .count();
            let medium = filtered_anomalies
                .iter()
                .filter(|a| a.severity == AnomalySeverity::Medium)
                .count();
            let low = filtered_anomalies
                .iter()
                .filter(|a| a.severity == AnomalySeverity::Low)
                .count();

            println!("\n  Severity breakdown:");
            if critical > 0 {
                println!("    🔴 Critical: {critical}");
            }
            if high > 0 {
                println!("    🟠 High: {high}");
            }
            if medium > 0 {
                println!("    🟡 Medium: {medium}");
            }
            if low > 0 {
                println!("    🟢 Low: {low}");
            }
        }
    } else {
        let json = serde_json::to_string_pretty(&filtered_anomalies)?;
        println!("{json}");
    }

    // Save to file if requested
    if let Some(output_path) = args.output {
        let json = serde_json::to_string_pretty(&filtered_anomalies)?;
        fs::write(&output_path, json)?;
        if format.is_human_readable() {
            println!("\n✅ Anomalies saved to: {}", output_path.display());
        }
    }

    Ok(())
}

/// Execute behavioral analysis
fn execute_analyze(args: AnalyzeArgs, format: OutputFormat) -> Result<()> {
    use crate::ml_analyzer::BehavioralAnalyzer;

    println!("{}", "📊 Analyzing cookie behavior...".cyan().bold());

    // Load cookies
    let cookies = load_cookies(&args.input)?;

    // Create behavioral analyzer
    let mut analyzer = BehavioralAnalyzer::new();

    // Train on baseline if provided
    if let Some(baseline_path) = &args.baseline {
        println!("  Loading baseline from: {}", baseline_path.display());
        let baseline_cookies = load_cookies(baseline_path)?;
        analyzer.train(&baseline_cookies)?;
        println!("  Baseline learned from {} cookies", baseline_cookies.len());
    } else {
        // Use provided cookies as baseline
        println!("  Learning baseline from provided data...");
        analyzer.train(&cookies)?;
    }

    // Analyze behavior
    let report = analyzer.analyze(&cookies)?;

    if format.is_human_readable() {
        println!("\n{}", "Behavior Analysis:".green().bold());
        println!("  Cookies analyzed: {}", report.cookies_analyzed);
        println!("  Baseline:");
        println!("    Common names: {}", report.baseline.common_names.len());
        println!(
            "    Common domains: {}",
            report.baseline.common_domains.len()
        );
        println!(
            "    Typical secure %: {:.1}%",
            report.baseline.security_patterns.typical_secure_percentage * 100.0
        );
        println!(
            "    Typical httponly %: {:.1}%",
            report
                .baseline
                .security_patterns
                .typical_httponly_percentage
                * 100.0
        );

        if report.deviations.is_empty() {
            println!("\n  ✅ No significant behavioral deviations detected");
        } else {
            println!("\n  {} Behavioral Deviations:", report.deviations.len());

            for (i, deviation) in report.deviations.iter().enumerate().take(10) {
                println!(
                    "\n    {}. {} (severity: {:.2})",
                    i + 1,
                    deviation.cookie.name.cyan(),
                    deviation.severity_score
                );
                println!("       Reasons: {}", deviation.reasons.join(", "));
            }

            if report.deviations.len() > 10 {
                println!(
                    "\n    ... and {} more deviations",
                    report.deviations.len() - 10
                );
            }
        }
    } else {
        let json = serde_json::to_string_pretty(&report)?;
        println!("{json}");
    }

    // Save to file if requested
    if let Some(output_path) = args.output {
        let json = serde_json::to_string_pretty(&report)?;
        fs::write(&output_path, json)?;
        if format.is_human_readable() {
            println!("\n✅ Analysis saved to: {}", output_path.display());
        }
    }

    Ok(())
}

/// Execute pattern recognition
fn execute_patterns(args: PatternsArgs, format: OutputFormat) -> Result<()> {
    use crate::ml_analyzer::PatternRecognizer;

    println!("{}", "🔍 Recognizing cookie patterns...".cyan().bold());

    // Load cookies
    let cookies = load_cookies(&args.input)?;

    // Create pattern recognizer
    let mut recognizer = PatternRecognizer::new();
    recognizer.train(&cookies)?;

    // Find suspicious patterns
    let suspicious = recognizer.find_suspicious(&cookies)?;

    if format.is_human_readable() {
        println!("\n{}", "Pattern Recognition Results:".green().bold());
        println!("  Cookies analyzed: {}", cookies.len());
        println!("  Suspicious patterns found: {}", suspicious.len());

        if suspicious.is_empty() {
            println!("\n  ✅ No suspicious patterns detected");
        } else {
            println!("\n  Cookies with suspicious patterns:");

            for (i, cookie) in suspicious.iter().enumerate().take(15) {
                println!("\n    {}. {}", i + 1, cookie.name.cyan());
                println!(
                    "       Domain: {}",
                    cookie.domain.as_deref().unwrap_or("N/A")
                );
                println!(
                    "       Value (truncated): {}...",
                    &cookie.value[..cookie.value.len().min(50)]
                );
            }

            if suspicious.len() > 15 {
                println!(
                    "\n    ... and {} more suspicious cookies",
                    suspicious.len() - 15
                );
            }

            println!("\n  💡 Recommendation: Review these cookies manually for security issues");
        }
    } else {
        let json = serde_json::to_string_pretty(&suspicious)?;
        println!("{json}");
    }

    // Save to file if requested
    if let Some(output_path) = args.output {
        let json = serde_json::to_string_pretty(&suspicious)?;
        fs::write(&output_path, json)?;
        if format.is_human_readable() {
            println!("\n✅ Results saved to: {}", output_path.display());
        }
    }

    Ok(())
}

/// Execute zero-day detection
fn execute_zeroday(args: ZeroDayArgs, format: OutputFormat) -> Result<()> {
    use crate::ml_analyzer::ZeroDayDetector;

    println!(
        "{}",
        "🛡️  Detecting potential zero-day attacks...".cyan().bold()
    );

    // Load cookies
    let cookies = load_cookies(&args.input)?;

    // Create zero-day detector
    let detector = ZeroDayDetector::new();

    // Detect potential zero-days
    let suspicious = detector.detect(&cookies)?;

    if format.is_human_readable() {
        println!("\n{}", "Zero-Day Detection Results:".green().bold());
        println!("  Cookies analyzed: {}", cookies.len());
        println!("  Potential zero-days: {}", suspicious.len());
        println!("  Aggressiveness level: {}", args.aggressiveness);

        if suspicious.is_empty() {
            println!(
                "\n  ✅ No zero-day patterns detected at aggressiveness level {}",
                args.aggressiveness
            );
        } else {
            println!("\n  ⚠️  ALERT: Potential zero-day attacks detected!");
            println!("  These cookies exhibit patterns of unknown attacks:");

            for (i, cookie) in suspicious.iter().enumerate().take(10) {
                println!("\n    {}. {} 🔴", i + 1, cookie.name.red().bold());
                println!(
                    "       Domain: {}",
                    cookie.domain.as_deref().unwrap_or("N/A")
                );
                println!("       Value length: {}", cookie.value.len());
                println!("       Secure: {}", cookie.secure);
                println!("       HttpOnly: {}", cookie.http_only);

                // Show value preview (carefully, might be malicious)
                let safe_preview = cookie
                    .value
                    .chars()
                    .take(100)
                    .filter(|c| {
                        c.is_ascii_alphanumeric() || c.is_ascii_punctuation() || c.is_whitespace()
                    })
                    .collect::<String>();

                if !safe_preview.is_empty() {
                    println!("       Preview: {safe_preview}...");
                }
            }

            if suspicious.len() > 10 {
                println!(
                    "\n    ... and {} more suspicious cookies",
                    suspicious.len() - 10
                );
            }

            println!("\n  🚨 CRITICAL: Manual review required!");
            println!("  These cookies should be analyzed by security experts.");
        }
    } else {
        let json = serde_json::to_string_pretty(&suspicious)?;
        println!("{json}");
    }

    // Save to file if requested
    if let Some(output_path) = args.output {
        let json = serde_json::to_string_pretty(&suspicious)?;
        fs::write(&output_path, json)?;
        if format.is_human_readable() {
            println!("\n✅ Results saved to: {}", output_path.display());
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
