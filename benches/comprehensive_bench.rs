//! Comprehensive Benchmarks for ICookForms
//!
//! This benchmark suite provides complete performance metrics for all
//! critical operations in ICookForms. Run with: `cargo bench`

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use icookforms::parser::parse_set_cookie;
use icookforms::types::{AnalysisResult, Cookie, Regulation, ScanResult};

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

fn generate_test_cookies(n: usize) -> Vec<Cookie> {
    (0..n)
        .map(|i| Cookie::new(format!("cookie_{}", i), format!("value_{}", i)))
        .collect()
}

fn create_test_analysis() -> AnalysisResult {
    AnalysisResult::new("test-scan-id")
}

// Reserved for future benchmarks requiring full scan context
#[allow(dead_code)]
fn create_test_scan() -> ScanResult {
    let mut scan = ScanResult::new("https://example.com");
    scan.cookies = generate_test_cookies(100);
    scan
}

// ============================================================================
// PARSER BENCHMARKS
// ============================================================================

fn parser_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("parser");

    // Simple cookie
    group.bench_function("simple_cookie", |b| {
        b.iter(|| parse_set_cookie(black_box("session_id=abc123"), false))
    });

    // Complex cookie with all attributes
    group.bench_function("complex_cookie", |b| {
        b.iter(|| {
            parse_set_cookie(
                black_box(
                    "session=xyz; Domain=.example.com; Path=/; Secure; HttpOnly; \
                     SameSite=Strict; Max-Age=3600; Expires=Wed, 21 Oct 2026 07:28:00 GMT",
                ),
                false,
            )
        })
    });

    // Batch parsing - various sizes
    for size in [10, 50, 100, 500, 1000].iter() {
        group.throughput(Throughput::Elements(*size as u64));
        group.bench_with_input(BenchmarkId::new("batch", size), size, |b, &size| {
            let cookies: Vec<String> = (0..size)
                .map(|i| format!("cookie{}=value{}; Secure; HttpOnly", i, i))
                .collect();

            b.iter(|| {
                for cookie_str in &cookies {
                    let _ = parse_set_cookie(black_box(cookie_str), false);
                }
            });
        });
    }

    group.finish();
}

// ============================================================================
// ANALYZER BENCHMARKS
// ============================================================================

fn analyzer_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("analyzer");

    use icookforms::analyzer::Analyzer;

    let analyzer = Analyzer::new();
    let cookie = Cookie::new("session".to_string(), "abc123".to_string());

    // Security analysis - single cookie
    group.bench_function("security_single", |b| {
        b.iter(|| analyzer.analyze(black_box(&cookie)))
    });

    // Security analysis - batch
    for size in [10, 50, 100].iter() {
        group.throughput(Throughput::Elements(*size as u64));
        group.bench_with_input(
            BenchmarkId::new("security_batch", size),
            size,
            |b, &size| {
                let cookies = generate_test_cookies(size);
                b.iter(|| {
                    for cookie in &cookies {
                        let _ = analyzer.analyze(black_box(cookie));
                    }
                });
            },
        );
    }

    // Tracking detection - single cookie
    group.bench_function("tracking_single", |b| {
        let mut cookie = Cookie::new("_ga".to_string(), "GA1.2.123456789.987654321".to_string());
        cookie.domain = Some(".google.com".to_string());
        b.iter(|| analyzer.analyze(black_box(&cookie)))
    });

    // Tracking detection - batch
    group.bench_function("tracking_batch", |b| {
        let tracking_cookies: Vec<Cookie> = vec![
            "_ga", "_gid", "_fbp", "_gcl_au", "__utma", "__utmz", "fr", "IDE",
        ]
        .into_iter()
        .enumerate()
        .map(|(i, name)| Cookie::new(name.to_string(), format!("value_{}", i)))
        .collect();

        b.iter(|| {
            for cookie in &tracking_cookies {
                let _ = analyzer.analyze(black_box(cookie));
            }
        });
    });

    group.finish();
}

// ============================================================================
// COMPLIANCE BENCHMARKS
// ============================================================================

fn compliance_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("compliance");

    use icookforms::compliance::ComplianceChecker;

    let checker = ComplianceChecker::new();
    let cookie = Cookie::new("session".to_string(), "abc123".to_string());

    // GDPR compliance check - single
    group.bench_function("gdpr_single", |b| {
        b.iter(|| checker.check(black_box(&cookie), Regulation::GDPR))
    });

    // CCPA compliance check - single
    group.bench_function("ccpa_single", |b| {
        b.iter(|| checker.check(black_box(&cookie), Regulation::CCPA))
    });

    // Batch compliance checks
    for size in [10, 50, 100].iter() {
        group.throughput(Throughput::Elements(*size as u64));
        group.bench_with_input(BenchmarkId::new("gdpr_batch", size), size, |b, &size| {
            let cookies = generate_test_cookies(size);
            b.iter(|| {
                for cookie in &cookies {
                    let _ = checker.check(black_box(cookie), Regulation::GDPR);
                }
            });
        });
    }

    group.finish();
}

// ============================================================================
// REPORTER BENCHMARKS
// ============================================================================

fn reporter_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("reporter");

    use icookforms::reporter::Reporter;
    use icookforms::ReportFormat;

    let analysis = create_test_analysis();

    // JSON generation
    group.bench_function("json_generation", |b| {
        let reporter = Reporter::new(ReportFormat::Json);
        b.iter(|| reporter.generate_string(black_box(&analysis)))
    });

    // CSV generation
    group.bench_function("csv_generation", |b| {
        let reporter = Reporter::new(ReportFormat::Csv);
        b.iter(|| reporter.generate_string(black_box(&analysis)))
    });

    // HTML generation
    group.bench_function("html_generation", |b| {
        let reporter = Reporter::new(ReportFormat::Html);
        b.iter(|| reporter.generate_string(black_box(&analysis)))
    });

    group.finish();
}

// ============================================================================
// CRYPTO BENCHMARKS
// ============================================================================

fn crypto_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("crypto");

    use icookforms::utils::crypto::{base64_decode, base64_encode, hmac_sha256, sha256, sha512};

    let data = b"test data for hashing and encoding benchmarks";
    let key = b"secret_key_for_hmac_benchmarking";

    // SHA256 hashing
    group.bench_function("sha256", |b| b.iter(|| sha256(black_box(data))));

    // SHA512 hashing
    group.bench_function("sha512", |b| b.iter(|| sha512(black_box(data))));

    // HMAC-SHA256
    group.bench_function("hmac_sha256", |b| {
        b.iter(|| hmac_sha256(black_box(key), black_box(data)))
    });

    // Base64 encoding
    group.bench_function("base64_encode", |b| {
        b.iter(|| base64_encode(black_box(data)))
    });

    // Base64 decoding
    let encoded = base64_encode(data);
    group.bench_function("base64_decode", |b| {
        b.iter(|| base64_decode(black_box(&encoded)))
    });

    group.finish();
}

// ============================================================================
// STORAGE BENCHMARKS
// ============================================================================

fn storage_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("storage");

    use icookforms::storage::cache::Cache;

    // Cache insert
    group.bench_function("cache_insert", |b| {
        let cache = Cache::new(3600, 1000);
        let mut counter = 0;
        b.iter(|| {
            let _ = cache.set(format!("key_{}", counter), format!("value_{}", counter));
            counter += 1;
        });
    });

    // Cache get
    group.bench_function("cache_get", |b| {
        let cache = Cache::new(3600, 1000);
        for i in 0..100 {
            let _ = cache.set(format!("key_{}", i), format!("value_{}", i));
        }
        b.iter(|| cache.get(black_box("key_50")));
    });

    group.finish();
}

// ============================================================================
// URL BENCHMARKS
// ============================================================================

fn url_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("url");

    use icookforms::utils::url::{extract_domain, is_valid_url, normalize_url};

    let test_url = "https://www.example.com:8080/path/to/resource?query=value#fragment";

    // URL validation
    group.bench_function("is_valid_url", |b| {
        b.iter(|| is_valid_url(black_box(test_url)))
    });

    // Domain extraction
    group.bench_function("extract_domain", |b| {
        b.iter(|| extract_domain(black_box(test_url)))
    });

    // URL normalization
    group.bench_function("normalize_url", |b| {
        b.iter(|| normalize_url(black_box(test_url)))
    });

    group.finish();
}

// ============================================================================
// TIME BENCHMARKS
// ============================================================================

fn time_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("time");

    use icookforms::utils::time::{format_timestamp, is_expired, parse_timestamp};

    let timestamp_str = "Wed, 21 Oct 2026 07:28:00 GMT";

    // Parse timestamp
    group.bench_function("parse_timestamp", |b| {
        b.iter(|| parse_timestamp(black_box(timestamp_str)))
    });

    // Format timestamp
    group.bench_function("format_timestamp", |b| {
        use chrono::Utc;
        let now = Utc::now();
        b.iter(|| format_timestamp(black_box(&now)))
    });

    // Check expiration
    group.bench_function("is_expired", |b| {
        use chrono::{Duration, Utc};
        let future = Utc::now() + Duration::days(30);
        b.iter(|| is_expired(black_box(&future)))
    });

    group.finish();
}

// ============================================================================
// HTTP BENCHMARKS
// ============================================================================

fn http_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("http");

    use icookforms::utils::http::{build_request, extract_cookies_from_headers, parse_user_agent};

    // Build HTTP request
    group.bench_function("build_request", |b| {
        b.iter(|| build_request(black_box(Some("https://example.com"))))
    });

    // Parse User-Agent
    let user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
    group.bench_function("parse_user_agent", |b| {
        b.iter(|| parse_user_agent(black_box(user_agent)))
    });

    // Extract cookies from headers
    let headers = vec![
        (
            "Set-Cookie".to_string(),
            "session=abc123; Secure; HttpOnly".to_string(),
        ),
        (
            "Set-Cookie".to_string(),
            "tracking=xyz; Domain=.example.com".to_string(),
        ),
    ];
    group.bench_function("extract_cookies_from_headers", |b| {
        b.iter(|| extract_cookies_from_headers(black_box(&headers)))
    });

    group.finish();
}

// ============================================================================
// FULL WORKFLOW BENCHMARK
// ============================================================================

fn full_workflow_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("full_workflow");

    use icookforms::analyzer::Analyzer;
    use icookforms::compliance::ComplianceChecker;
    use icookforms::reporter::Reporter;
    use icookforms::ReportFormat;

    // Complete workflow: parse → analyze → check compliance → generate report
    group.bench_function("complete_workflow", |b| {
        let cookie_strs = [
            "session=abc123; Secure; HttpOnly; SameSite=Strict",
            "_ga=GA1.2.123456789.987654321; Domain=.google.com",
            "tracking=xyz; Max-Age=31536000",
        ];

        let analyzer = Analyzer::new();
        let checker = ComplianceChecker::new();
        let reporter = Reporter::new(ReportFormat::Json);

        b.iter(|| {
            // Parse cookies
            let cookies: Vec<Cookie> = cookie_strs
                .iter()
                .filter_map(|s| parse_set_cookie(s, false).ok())
                .collect();

            // Analyze security
            for cookie in &cookies {
                let _ = analyzer.analyze(cookie);
            }

            // Check compliance
            for cookie in &cookies {
                let _ = checker.check(cookie, Regulation::GDPR);
            }

            // Generate report
            let analysis = create_test_analysis();
            let _ = reporter.generate_string(&analysis);
        });
    });

    group.finish();
}

// ============================================================================
// BENCHMARK GROUP CONFIGURATION
// ============================================================================

criterion_group!(
    benches,
    parser_benchmarks,
    analyzer_benchmarks,
    compliance_benchmarks,
    reporter_benchmarks,
    crypto_benchmarks,
    storage_benchmarks,
    url_benchmarks,
    time_benchmarks,
    http_benchmarks,
    full_workflow_benchmark,
);

criterion_main!(benches);
