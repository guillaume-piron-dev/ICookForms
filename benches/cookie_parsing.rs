use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use icookforms::parser::Parser;

fn parse_simple_cookie(c: &mut Criterion) {
    let parser = Parser::new();
    let cookie_str = "session_id=abc123; Path=/; Secure; HttpOnly";

    c.bench_function("parse_simple_cookie", |b| {
        b.iter(|| parser.parse(black_box(cookie_str)));
    });
}

fn parse_complex_cookie(c: &mut Criterion) {
    let parser = Parser::new();
    let cookie_str = "user_pref=theme=dark&lang=en&notifications=true; Domain=.example.com; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=31536000";

    c.bench_function("parse_complex_cookie", |b| {
        b.iter(|| parser.parse(black_box(cookie_str)));
    });
}

fn parse_multiple_cookies(c: &mut Criterion) {
    let parser = Parser::new();

    for size in [10, 50, 100, 500].iter() {
        c.bench_with_input(
            BenchmarkId::new("parse_multiple", size),
            size,
            |b, &size| {
                let cookies: Vec<String> = (0..size)
                    .map(|i| format!("cookie_{}=value_{}; Path=/; Secure", i, i))
                    .collect();

                b.iter(|| {
                    for cookie in &cookies {
                        parser.parse(black_box(cookie.as_str())).ok();
                    }
                });
            },
        );
    }
}

fn parse_batch(c: &mut Criterion) {
    let parser = Parser::new();
    let cookies = vec![
        "session=xyz; HttpOnly",
        "user_id=123; Secure",
        "preferences=dark_mode; Path=/",
        "analytics=tracking_id; Domain=.example.com",
        "auth_token=jwt_token_here; Secure; HttpOnly; SameSite=Strict",
    ];

    c.bench_function("parse_batch_5_cookies", |b| {
        b.iter(|| {
            for cookie in &cookies {
                parser.parse(black_box(cookie)).ok();
            }
        });
    });
}

criterion_group!(
    benches,
    parse_simple_cookie,
    parse_complex_cookie,
    parse_multiple_cookies,
    parse_batch
);
criterion_main!(benches);
