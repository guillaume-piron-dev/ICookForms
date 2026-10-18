# ICOokForms

Command-line tool and Rust library for auditing HTTP cookies: security, regulatory compliance and forensic analysis.

[![Crates.io](https://img.shields.io/crates/v/icookforms.svg)](https://crates.io/crates/icookforms)
[![Documentation](https://docs.rs/icookforms/badge.svg)](https://docs.rs/icookforms)
[![CI](https://img.shields.io/github/actions/workflow/status/guillaume-piron-dev/ICookForms/ci.yml?branch=main&label=CI)](https://github.com/guillaume-piron-dev/ICookForms/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)

*[Version française](README.md)*

---

## Overview

**ICOokForms** extracts cookies from a website, analyzes their security configuration, checks them against several data protection regulations and provides forensic tooling (timeline reconstruction, iOS/Safari binary cookies, Google Analytics cookies, evidence collection). The project also includes an experimental machine-learning anomaly detection module.

Compliance checks are heuristic technical checks on cookies; they are not a substitute for a legal audit.

---

## Features

### Forensic analysis

#### Timeline reconstruction
- Reconstructs an event timeline from cookies
- Detects temporal anomalies
- Checks timestamp consistency
- Confidence score for each reconstructed event

#### iOS / Safari binary cookie parser
- Reads Apple `.binarycookies` files
- Extracts metadata (flags, expiration, creation)
- JSON or CSV export

#### Google Analytics cookie analysis
- Extracts client IDs and sessions
- Page views and user journey
- Search terms and campaign information (source, medium, name, term, content)

#### Evidence collection (chain-of-custody)
- Collects cookies with chain-of-custody tracking
- SHA-256 fingerprint for integrity checks
- Collection timestamp
- Investigation metadata (investigator, case number)

#### Value decoder
- **Base64**, **Hex** and **URL encoding** decoding
- Unix and ISO **timestamp** detection
- **UUID** recognition
- Structured data detection (JSON)

### Machine learning (experimental)

#### Model training
- Trains an **Isolation Forest** model on a reference set of cookies
- Configurable parameters (number of trees, sample size, seed)
- Trained models can be saved and reused

#### Anomaly detection
- Per-cookie anomaly score
- Severity levels (Low, Medium, High, Critical)
- Explanation of the reasons behind each detection

#### Behavioral analysis
- Comparison against a reference baseline
- Deviation detection

#### Pattern recognition
- Recognition of known patterns (tracking, fingerprinting, malicious patterns)
- Classification by threat type

#### Heuristic detection of unknown ("zero-day") attacks
- Heuristic analysis of unusual cookies
- Configurable aggressiveness (1-5); higher levels increase false positives

### Security
Detects cookie configurations that expose common attacks:
- Missing **Secure**: exposure to interception (MITM)
- Missing **HttpOnly**: exposure to theft via XSS
- Missing or permissive **SameSite**: exposure to CSRF
- **Session fixation** risk
- **Predictable values** that make session hijacking easier
- **Sensitive data** stored in clear text in cookies

### Regulatory compliance
Regulations available in the CLI (`icookforms compliance --regulation <...>`):
- **GDPR** (European Union)
- **CCPA** and **CPRA** (California)
- **LGPD** (Brazil)
- **PIPEDA** (Canada)
- **POPIA** (South Africa)

The Rust API (`ComplianceChecker`) also provides checks for: UK GDPR, the ePrivacy Directive, PDPA (Singapore), the Privacy Act (Australia), APPI (Japan), COPPA, HIPAA and the US state laws VCDPA, CPA, CTDPA and UCPA.

Also available in the library: **IAB TCF 2.2** string decoding and validation, and **Google Consent Mode v2** detection.

### RFC 6265 parsing
- Parses `Set-Cookie` headers per **RFC 6265**, with **RFC 6265bis** support
- Attributes: Domain, Path, Secure, HttpOnly, SameSite, Expires, Max-Age
- Validation and detection of missing or misconfigured attributes
- First-party / third-party distinction

### Platforms
- CI configured on Linux, Windows and macOS (GitHub Actions)
- Dockerfile provided to build the image locally

---

## Installation

### Via Cargo
```bash
# Install from crates.io
cargo install icookforms

# Verify installation
icookforms --version
```

### Build from source
```bash
# Clone the repository
git clone https://github.com/guillaume-piron-dev/ICookForms.git
cd ICookForms

# Build in release mode
cargo build --release

# Run tests
cargo test

# Install locally
cargo install --path .
```

### Via Docker (local image)
No image is published to a registry yet (planned). Build the image from the repository's `Dockerfile`:
```bash
# Build the image
docker build -t icookforms .

# Run ICOokForms
docker run --rm icookforms scan --url https://example.com
```

---

## Usage

### Help and information

```bash
# Display general help
icookforms --help

# Display version
icookforms --version

# Help for a specific command
icookforms scan --help
icookforms forensics --help
icookforms ml --help
```

---

### Scan: cookie extraction

#### Basic scan
```bash
# Scan a website
icookforms scan --url https://example.com

# Scan with JSON output
icookforms scan --url https://example.com --output cookies.json --format json
```

#### Crawling and redirects
```bash
# Crawl multiple pages
icookforms scan --url https://example.com --crawl --max-pages 100

# Follow redirects
icookforms scan --url https://example.com --follow-redirects --max-redirects 10
```

#### Network configuration
```bash
# Use a proxy
icookforms scan --url https://example.com --proxy http://proxy.local:8080

# Custom timeout
icookforms scan --url https://example.com --timeout 60

# Custom User-Agent
icookforms scan --url https://example.com --user-agent "ICOokForms/0.1 Security Audit"

# Limit the request rate
icookforms scan --url https://example.com --rate-limit 5
```

#### Verbose mode
```bash
# Detailed output for debugging
icookforms scan --url https://example.com --verbose --no-color
```

---

### Analyze: security analysis

```bash
# Full analysis
icookforms analyze --input cookies.json

# Analysis with detailed report
icookforms analyze --input cookies.json --verbose --output security_report.json

# Restrict the analysis to specific areas
icookforms analyze --input cookies.json --security --tracking

# Compliance analysis against several regulations
icookforms analyze --input cookies.json --compliance --regulations gdpr,ccpa,lgpd

# Only show findings above a given severity
icookforms analyze --input cookies.json --min-severity high
```

---

### Compliance: regulatory compliance

```bash
# Check GDPR compliance (EU)
icookforms compliance --input cookies.json --regulation gdpr

# Check CCPA compliance (California)
icookforms compliance --input cookies.json --regulation ccpa

# Strict mode (warnings count as failures)
icookforms compliance --input cookies.json --regulation lgpd --strict

# Analyze a site's consent mechanism
icookforms compliance --input cookies.json --check-consent --url https://example.com

# Detailed compliance report
icookforms compliance --input cookies.json --regulation gdpr --verbose --output gdpr_audit.json
```

---

### Report: report generation

```bash
# HTML report
icookforms report --input results.json --format html --output report.html

# PDF report with summary and recommendations
icookforms report --input results.json --format pdf --output executive_report.pdf --summary --recommendations

# JSON report for automated processing
icookforms report --input results.json --format json --output detailed_report.json

# CSV export
icookforms report --input results.json --format csv --output data.csv

# Custom header
icookforms report --input results.json --title "Cookie audit" --company "ACME" --auditor "Jane Doe"
```

---

### Forensics: forensic analysis

#### Timeline reconstruction
```bash
# Reconstruct the event timeline
icookforms forensics timeline --input cookies.json --output timeline.json

# With anomaly detection
icookforms forensics timeline --input cookies.json --show-anomalies --threshold 0.7
```

#### iOS / Safari binary cookie parser
```bash
# Parse a Cookies.binarycookies file
icookforms forensics ios-binary --input Cookies.binarycookies --output ios_cookies.json

# Extract metadata only
icookforms forensics ios-binary --input Cookies.binarycookies --metadata-only
```

#### Google Analytics analysis
```bash
# Analyze Google Analytics cookies
icookforms forensics google-analytics --input cookies.json --output ga_analysis.json

# Extract the user journey
icookforms forensics google-analytics --input cookies.json --user-journey --output journey.json

# Extract search terms
icookforms forensics google-analytics --input cookies.json --search-terms

# Full analysis
icookforms forensics google-analytics --input cookies.json --user-journey --search-terms --output full_ga.json
```

#### Full forensic report
```bash
# Generate a forensic report
icookforms forensics full-report --input cookies.json --output forensic_report.pdf

# Include raw data
icookforms forensics full-report --input cookies.json --include-raw --output complete_report.pdf

# With a timezone
icookforms forensics full-report --input cookies.json --timezone "Europe/Paris" --output report_fr.pdf
```

#### Evidence collection
```bash
# Collect evidence with chain-of-custody
icookforms forensics evidence --input cookies.json --output evidence_dir/ --chain-of-custody

# With investigation information
icookforms forensics evidence \
  --input cookies.json \
  --output evidence/ \
  --investigator "John Doe" \
  --case-number "CASE-001" \
  --chain-of-custody
```

#### Value decoding
```bash
# Decode all cookies
icookforms forensics decode --input cookies.json --output decoded.json

# Decode a specific cookie
icookforms forensics decode --input cookies.json --cookie-name "_ga" --output ga_decoded.json

# Detailed decoding
icookforms forensics decode --input cookies.json --verbose
```

---

### ML: anomaly detection (experimental)

#### Training
```bash
# Train a model on reference cookies
icookforms ml train --dataset normal_cookies.json --output model.bin

# Training with parameters
icookforms ml train \
  --dataset baseline_cookies.json \
  --output trained_model.bin \
  --n-trees 200 \
  --sample-size 512 \
  --seed 42
```

#### Detection
```bash
# Detect anomalies with a trained model
icookforms ml detect --input cookies.json --model trained_model.bin

# Custom threshold
icookforms ml detect --input cookies.json --threshold 0.8 --output anomalies.json

# High-severity anomalies only
icookforms ml detect --input cookies.json --high-severity-only

# Detection with JSON report
icookforms ml detect \
  --input suspicious_cookies.json \
  --model production_model.bin \
  --threshold 0.75 \
  --output ml_report.json \
  --format json
```

#### Behavioral analysis
```bash
# Analyze cookie behavior
icookforms ml analyze --input cookies.json --output behavioral_analysis.json

# Compare against a baseline
icookforms ml analyze \
  --input current_cookies.json \
  --baseline normal_baseline.json \
  --output deviations.json
```

#### Pattern recognition
```bash
# Recognize known patterns
icookforms ml patterns --input cookies.json --output patterns.json

# Malicious patterns only
icookforms ml patterns --input cookies.json --malicious-only
```

#### Heuristic "zero-day" detection
```bash
# Detection with the default aggressiveness
icookforms ml zero-day --input cookies.json --output zero_days.json

# Moderate level
icookforms ml zero-day --input cookies.json --aggressiveness 3

# Maximum level (more false positives)
icookforms ml zero-day --input cookies.json --aggressiveness 5 --output high_alert.json
```

---

### Global options

```bash
# Output format: human (default), json, yaml, csv
icookforms scan --url https://example.com --format json

# Verbose mode
icookforms scan --url https://example.com --verbose

# Disable colors (CI/CD)
icookforms scan --url https://example.com --no-color

# Combine options
icookforms scan \
  --url https://example.com \
  --verbose \
  --format json \
  --output results.json \
  --no-color
```

---

## Using it as a Rust library

### Basic example

```rust
use icookforms::{Analyzer, ScanConfig, Scanner};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Scan a website
    let scanner = Scanner::new(ScanConfig::default())?;
    let scan_result = scanner.scan("https://example.com").await?;

    // Analyze the cookies
    let analyzer = Analyzer::new();
    let analysis = analyzer.analyze_batch(&scan_result.cookies);

    println!("Cookies found: {}", scan_result.cookies.len());
    println!("Security issues: {}", analysis.security_issues.len());
    println!("Compliance issues: {}", analysis.compliance_issues.len());

    Ok(())
}
```

### Anomaly detection

```rust
use icookforms::{AnomalySeverity, Cookie, MLAnalyzer, MLConfig, ScanConfig, Scanner};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Cookies considered normal, used as a reference baseline
    let baseline_cookies: Vec<Cookie> = load_baseline()?;

    let scanner = Scanner::new(ScanConfig::default())?;
    let scan_result = scanner.scan("https://example.com").await?;

    let ml_config = MLConfig {
        anomaly_threshold: 0.8,
        enable_zero_day_detection: true,
        ..Default::default()
    };
    let mut ml_analyzer = MLAnalyzer::with_config(&ml_config);

    // Train on the baseline, then detect
    ml_analyzer.train(&baseline_cookies)?;
    let anomalies = ml_analyzer.detect(&scan_result.cookies)?;

    for anomaly in anomalies
        .iter()
        .filter(|a| a.severity == AnomalySeverity::Critical)
    {
        eprintln!(
            "CRITICAL: {} - {}",
            anomaly.cookie.name,
            anomaly.explanation.as_deref().unwrap_or("")
        );
    }

    Ok(())
}
```

### Forensic analysis

```rust
use icookforms::forensics::{ForensicAnalyzer, ForensicConfig};
use icookforms::Cookie;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cookies: Vec<Cookie> = load_cookies()?;

    let config = ForensicConfig {
        enable_chain_of_custody: true,
        include_raw_data: true,
        timezone: "UTC".to_string(),
        anomaly_threshold: 0.7,
    };
    let analyzer = ForensicAnalyzer::with_config(config);

    // Reconstruct the timeline
    let timeline = analyzer.reconstruct_timeline(&cookies)?;
    println!(
        "Timeline: {} events over {} hours",
        timeline.events.len(),
        timeline.duration.num_hours()
    );

    // Analyze Google Analytics cookies
    for ga in analyzer.analyze_google_analytics(&cookies)? {
        println!("GA client ID: {} ({} page views)", ga.client_id, ga.page_views.len());
    }

    Ok(())
}
```

---

## Architecture

```
icookforms/
├── src/
│   ├── cli/              # Command-line interface
│   │   ├── commands/     #   scan, analyze, compliance, report, forensics, ml
│   │   └── output.rs     #   Output formats (human, json, yaml, csv)
│   ├── scanner/          # HTTP/HTTPS cookie extraction (reqwest, scraper)
│   ├── parser/           # RFC 6265 parsing
│   │   ├── rfc6265.rs
│   │   ├── attributes.rs
│   │   └── validation.rs
│   ├── analyzer/         # Security, compliance and tracking analysis
│   │   ├── security.rs
│   │   ├── compliance.rs
│   │   └── tracking.rs
│   ├── compliance/       # Regulatory compliance
│   │   ├── gdpr.rs
│   │   ├── ccpa.rs
│   │   ├── regulations.rs     # LGPD, PIPEDA, POPIA, CPRA, UK GDPR, ePrivacy, etc.
│   │   ├── consent.rs
│   │   ├── iab_tcf/           # IAB TCF 2.2
│   │   └── google_consent/    # Google Consent Mode v2
│   ├── forensics/        # Forensic analysis
│   │   ├── timeline.rs
│   │   ├── ios_binary.rs
│   │   ├── google_analytics.rs
│   │   ├── evidence_collector.rs
│   │   ├── cookie_decoder.rs
│   │   └── report_generator.rs
│   ├── ml_analyzer/      # Anomaly detection (experimental)
│   │   ├── anomaly_detector.rs     # Isolation Forest
│   │   ├── behavioral_analysis.rs
│   │   ├── pattern_recognition.rs
│   │   ├── zero_day_detector.rs
│   │   ├── models/
│   │   └── training/
│   ├── reporter/         # HTML, PDF, JSON, CSV reports
│   ├── storage/          # SQLite history and sled cache
│   ├── types/            # Data types (cookie, config, issue, report, regulation)
│   └── utils/            # Crypto, HTTP, time, URL helpers
├── tests/                # Integration and property-based tests (proptest)
├── benches/              # Criterion benchmarks
├── docs/                 # Documentation
└── examples/             # Usage examples
```

---

## Documentation

### Project documents

- **[Project vision](docs/00_PROJECT_VISION.md)**
- **[RFC 6265 standards](docs/01_RFC_STANDARDS.md)**
- **[IAB TCF 2.2 implementation](docs/06_IAB_TCF_2_2_IMPLEMENTATION_COMPLETE.md)**
- **[Google Consent Mode v2](docs/07_GOOGLE_CONSENT_MODE_V2_COMPLETE.md)**
- **[Rust ML libraries for anomaly detection](docs/08_RUST_ML_LIBRARIES_ANOMALY_DETECTION.md)**
- **[Cookie tossing and HMAC audit](docs/09_COOKIE_TOSSING_HMAC_AUDIT.md)**

### Checklists

- [GDPR Compliance Checklist](docs/checklists/GDPR_COMPLIANCE_CHECKLIST.md)
- [CCPA Compliance Checklist](docs/checklists/CCPA_COMPLIANCE_CHECKLIST.md)
- [General Compliance Checklist](docs/checklists/GENERAL_COMPLIANCE_CHECKLIST.md)
- [ISO 27001 Checklist](docs/checklists/ISO_27001_CHECKLIST.md)
- [ISO 27701 Checklist](docs/checklists/ISO_27701_CHECKLIST.md)

### Links

- **[API documentation](https://docs.rs/icookforms)**: Rust API reference
- **[Changelog](CHANGELOG.md)**: release history
- **[Contributing guide](CONTRIBUTING.md)**

---

## Development

### Prerequisites

- **Rust 1.75+** (2021 edition)
- **Cargo**
- **Git**
- *(Optional)* **Docker**

### Workflow

```bash
# Build the project
cargo build --release

# Run tests
cargo test

# Code coverage
cargo tarpaulin --out Html

# Benchmarks
cargo bench

# Lint
cargo clippy -- -D warnings

# Format the code
cargo fmt

# Generate documentation
cargo doc --open

# Audit dependencies
cargo audit
```

### Tests

```bash
# Unit tests
cargo test --lib

# Integration tests
cargo test --test '*'

# A specific test
cargo test test_cookie_parsing

# Tests with logs
RUST_LOG=debug cargo test
```

### Benchmarks

```bash
# All benchmarks
cargo bench

# A specific benchmark
cargo bench --bench parser_bench

# Save a baseline
cargo bench -- --save-baseline main
```

---

## Contributing

Contributions are welcome. Please read the [contributing guide](CONTRIBUTING.md).

### Code standards

- Follow Rust naming conventions
- Run `cargo fmt` before each commit
- Run `cargo clippy` and fix warnings
- Write tests for every new feature
- Document public APIs with rustdoc
- Add examples for new features

### Process

1. **Fork** the repository
2. **Create** a branch (`git checkout -b feature/my-feature`)
3. **Commit** your changes (`git commit -m 'Add my-feature'`)
4. **Push** the branch (`git push origin feature/my-feature`)
5. **Open** a Pull Request

---

## License

**ICOokForms** is distributed under the **Apache License 2.0**. See [LICENSE](LICENSE).

---

## Acknowledgements

ICOokForms builds on the work of:

- the Rust community
- the OWASP Foundation (security standards)
- the Mozilla Developer Network (web documentation)
- the IETF (RFC 6265, RFC 6265bis)

---

## Support and contact

- **[Issues](https://github.com/guillaume-piron-dev/ICookForms/issues)**: bugs and feature requests
- **[Pull Requests](https://github.com/guillaume-piron-dev/ICookForms/pulls)**: contributions
- **Email**: untelec.pro@gmail.com
- **GitHub**: [@guillaume-piron-dev](https://github.com/guillaume-piron-dev)

### Reporting a bug

Please open an [issue](https://github.com/guillaume-piron-dev/ICookForms/issues/new) with:
- the ICOokForms version
- your operating system
- a description of the problem
- steps to reproduce it
- error logs, if any

---

## Roadmap

### Planned
- [ ] Docker image published to a public registry
- [ ] WebAssembly (WASM) support
- [ ] REST API for CI/CD integration
- [ ] Web dashboard
- [ ] Additional export formats (Excel, Word)
- [ ] Plugin system
- [ ] Distributed scanning
- [ ] Alerting (Slack, PagerDuty, email)
- [ ] Kubernetes operator
- [ ] Additional ML models (autoencoder, LSTM)
- [ ] 1.0 release with a stabilized API
