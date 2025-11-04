//! Benchmarks for ICOokForms cookie parser
//!
//! Run with: cargo bench --bench parser_bench

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use icookforms::parser::parse_set_cookie;

fn simple_cookie_parsing(c: &mut Criterion) {
    c.bench_function("parse simple cookie", |b| {
        b.iter(|| parse_set_cookie(black_box("session_id=abc123"), false))
    });
}

fn cookie_with_attributes(c: &mut Criterion) {
    c.bench_function("parse cookie with attributes", |b| {
        b.iter(|| {
            parse_set_cookie(
                black_box("session=xyz; Domain=example.com; Path=/; Secure; HttpOnly"),
                false,
            )
        })
    });
}

fn complex_cookie_parsing(c: &mut Criterion) {
    c.bench_function("parse complex cookie", |b| {
        b.iter(|| {
            parse_set_cookie(
                black_box("token=value; Domain=.example.com; Path=/api; Secure; HttpOnly; SameSite=Strict; Max-Age=3600; Expires=Wed, 09 Jun 2021 10:18:14 GMT"),
                false
            )
        })
    });
}

fn batch_cookie_parsing(c: &mut Criterion) {
    let cookies = vec![
        "simple=value",
        "session=xyz; Secure",
        "token=abc; Domain=.example.com; Path=/",
        "auth=123; HttpOnly; SameSite=Strict",
        "tracking=xyz; Max-Age=31536000",
    ];

    let mut group = c.benchmark_group("batch_parsing");
    group.throughput(Throughput::Elements(cookies.len() as u64));

    group.bench_function("parse 5 cookies", |b| {
        b.iter(|| {
            for cookie_str in &cookies {
                let _ = parse_set_cookie(black_box(cookie_str), false);
            }
        })
    });

    group.finish();
}

fn cookie_validation(c: &mut Criterion) {
    c.bench_function("parse with strict validation", |b| {
        b.iter(|| {
            parse_set_cookie(
                black_box("session=value; Secure; HttpOnly; SameSite=Strict"),
                black_box(true), // strict mode
            )
        })
    });
}

fn malformed_cookie_handling(c: &mut Criterion) {
    c.bench_function("parse malformed cookie", |b| {
        b.iter(|| {
            // Intentionally malformed - missing value
            let _ = parse_set_cookie(black_box("malformed; Secure"), false);
        })
    });
}

fn cookie_size_comparison(c: &mut Criterion) {
    let sizes = vec![10, 100, 500, 1000, 4000];
    let mut group = c.benchmark_group("cookie_sizes");

    for size in sizes {
        let value = "x".repeat(size);
        let cookie_str = format!("big_cookie={}", value);

        group.throughput(Throughput::Bytes(cookie_str.len() as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &cookie_str,
            |b, cookie_str| b.iter(|| parse_set_cookie(black_box(cookie_str), false)),
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    simple_cookie_parsing,
    cookie_with_attributes,
    complex_cookie_parsing,
    batch_cookie_parsing,
    cookie_validation,
    malformed_cookie_handling,
    cookie_size_comparison
);

criterion_main!(benches);
