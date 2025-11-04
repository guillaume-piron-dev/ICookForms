//! Basic cookie scanning example
//!
//! This example demonstrates how to scan a website for cookies
//!
//! Run with: cargo run --example basic_scan

use icookforms::{types::ScanConfig, Scanner};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🍪 ICOokForms - Basic Cookie Scanner\n");

    // Configure the scanner
    let config = ScanConfig {
        follow_redirects: true,
        max_redirects: 5,
        timeout: Duration::from_secs(30),
        user_agent: "ICOokForms/1.0 (Cookie Auditor)".to_string(),
        ..Default::default()
    };

    // Create scanner
    let scanner = Scanner::new(config)?;

    // Scan a website
    let url = "https://httpbin.org/cookies/set?example=value&test=data";
    println!("📡 Scanning: {}", url);
    println!("⏳ Please wait...\n");

    let result = scanner.scan(url).await?;

    // Display results
    println!("✅ Scan completed!");
    println!("📊 Found {} cookies\n", result.cookies.len());

    if result.cookies.is_empty() {
        println!("ℹ️  No cookies found on this website.");
    } else {
        println!("📋 Cookie Details:\n");
        for (i, cookie) in result.cookies.iter().enumerate() {
            println!("{}. {}", i + 1, cookie.name);
            println!(
                "   Value: {}",
                if cookie.value.len() > 50 {
                    format!("{}...", &cookie.value[..50])
                } else {
                    cookie.value.clone()
                }
            );

            if let Some(domain) = &cookie.domain {
                println!("   Domain: {}", domain);
            }

            if let Some(path) = &cookie.path {
                println!("   Path: {}", path);
            }

            println!("   Secure: {}", if cookie.secure { "✅" } else { "❌" });
            println!(
                "   HttpOnly: {}",
                if cookie.http_only { "✅" } else { "❌" }
            );

            if let Some(same_site) = &cookie.same_site {
                println!("   SameSite: {:?}", same_site);
            }

            if let Some(max_age) = cookie.max_age {
                println!("   Max-Age: {} seconds", max_age);
            }

            println!();
        }
    }

    println!("🆔 Scan ID: {}", result.id);
    if let Some(end) = result.completed_at {
        let duration = end.signed_duration_since(result.started_at);
        println!("⏱️  Duration: {} ms", duration.num_milliseconds());
    }

    Ok(())
}
