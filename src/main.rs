//! ICOokForms CLI - Command Line Interface
//!
//! The main entry point for the ICOokForms command-line tool.

use clap::Parser;
use icookforms::cli::Commands;
use icookforms::{init_tracing, VERSION};
use std::process;
use tracing::{error, info};

/// ICOokForms - The World's Reference Cookie Audit Software
#[derive(Parser)]
#[command(name = "icookforms")]
#[command(version = VERSION)]
#[command(author = "guillaume-piron-dev")]
#[command(about = "Complete cookie security and compliance analysis", long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    /// Subcommand to execute
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Output format
    #[arg(short, long, global = true, value_enum, default_value_t = icookforms::cli::OutputFormat::Human)]
    format: icookforms::cli::OutputFormat,

    /// Disable colored output
    #[arg(long, global = true)]
    no_color: bool,
}

#[tokio::main]
async fn main() {
    // Parse CLI arguments
    let cli = Cli::parse();

    // Initialize tracing
    init_tracing();

    // Configure colored output
    if cli.no_color {
        colored::control::set_override(false);
    }

    info!("ICOokForms v{} starting...", VERSION);

    // Execute command
    let result = match cli.command {
        Commands::Scan(args) => icookforms::cli::commands::scan::execute(args, cli.format).await,
        Commands::Analyze(args) => icookforms::cli::commands::analyze::execute(args, cli.format),
        Commands::Report(args) => icookforms::cli::commands::report::execute(args, cli.format),
        Commands::Compliance(args) => {
            icookforms::cli::commands::compliance::execute(args, cli.format).await
        }
        Commands::Forensics(args) => {
            icookforms::cli::commands::forensics::execute(args, cli.format)
        }
        Commands::Ml(args) => icookforms::cli::commands::ml::execute(args, cli.format),
        Commands::Version => {
            println!("ICOokForms v{}", VERSION);
            Ok(())
        }
    };

    // Handle result
    match result {
        Ok(()) => {
            info!("Command completed successfully");
            process::exit(0);
        }
        Err(e) => {
            error!("Command failed: {}", e);
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    }
}
