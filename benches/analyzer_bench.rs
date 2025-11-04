//! Benchmarks for ICOokForms analyzer
//!
//! Run with: cargo bench --bench analyzer_bench

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use icookforms::analyzer::Analyzer;
use icookforms::types::{AnalysisConfig, Cookie};

fn create_test_cookies(count: usize) -> Vec<Cookie> {
    (0..count)
        .map(|i| {
            let mut cookie = Cookie::new(format!("cookie_{}", i), format!("value_{}", i));
            cookie.secure = i % 2 == 0;
            cookie.http_only = i % 3 == 0;
            cookie.domain = Some(if i % 2 == 0 {
                ".example.com".to_string()
            } else {
                "sub.example.com".to_string()
            });
            cookie
        })
        .collect()
}

fn security_analysis_single(c: &mut Criterion) {
    let analyzer = Analyzer::new();
    let cookie = Cookie::new("session".to_string(), "abc123".to_string());

    c.bench_function("security analysis single cookie", |b| {
        b.iter(|| analyzer.analyze(black_box(&cookie)))
    });
}

fn security_analysis_batch(c: &mut Criterion) {
    let mut group = c.benchmark_group("security_batch_analysis");
    let analyzer = Analyzer::new();

    for size in [10, 50, 100, 500].iter() {
        let cookies = create_test_cookies(*size);
        group.bench_with_input(BenchmarkId::from_parameter(size), &cookies, |b, cookies| {
            b.iter(|| analyzer.analyze_batch(black_box(cookies)))
        });
    }

    group.finish();
}

fn tracking_analysis_single(c: &mut Criterion) {
    let analyzer = Analyzer::new();
    let mut cookie = Cookie::new("_ga".to_string(), "GA1.2.xxx".to_string());
    cookie.domain = Some(".google.com".to_string());

    c.bench_function("tracking analysis single cookie", |b| {
        b.iter(|| analyzer.analyze(black_box(&cookie)))
    });
}

fn tracking_analysis_batch(c: &mut Criterion) {
    let mut group = c.benchmark_group("tracking_batch_analysis");
    let analyzer = Analyzer::new();

    for size in [10, 50, 100].iter() {
        let cookies = create_test_cookies(*size);
        group.bench_with_input(BenchmarkId::from_parameter(size), &cookies, |b, cookies| {
            b.iter(|| analyzer.analyze_batch(black_box(cookies)))
        });
    }

    group.finish();
}

fn full_analysis_workflow(c: &mut Criterion) {
    let mut group = c.benchmark_group("full_workflow");
    let config = AnalysisConfig::default();
    let analyzer = Analyzer::with_config(config);

    for size in [10, 50, 100].iter() {
        let cookies = create_test_cookies(*size);
        group.bench_with_input(BenchmarkId::from_parameter(size), &cookies, |b, cookies| {
            b.iter(|| analyzer.analyze_batch(black_box(cookies)))
        });
    }

    group.finish();
}

fn cookie_categorization(c: &mut Criterion) {
    let analyzer = Analyzer::new();

    let mut test_cookies = vec![
        Cookie::new("session_id".to_string(), "abc".to_string()),
        Cookie::new("_ga".to_string(), "GA1.2.xxx".to_string()),
        Cookie::new("_fbp".to_string(), "fb.1.xxx".to_string()),
        Cookie::new("csrf_token".to_string(), "token".to_string()),
        Cookie::new("language".to_string(), "en".to_string()),
    ];

    // Set domains for third-party detection
    test_cookies[1].domain = Some(".google.com".to_string());
    test_cookies[2].domain = Some(".facebook.com".to_string());

    c.bench_function("categorize 5 cookies", |b| {
        b.iter(|| {
            for cookie in &test_cookies {
                let _ = analyzer.analyze(black_box(cookie));
            }
        })
    });
}

criterion_group!(
    benches,
    security_analysis_single,
    security_analysis_batch,
    tracking_analysis_single,
    tracking_analysis_batch,
    full_analysis_workflow,
    cookie_categorization
);

criterion_main!(benches);
