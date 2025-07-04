use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn benchmark_placeholder(c: &mut Criterion) {
    c.bench_function("placeholder", |b| {
        b.iter(|| {
            // Placeholder benchmark - will be replaced with real benchmarks later
            black_box(1 + 1)
        })
    });
}

criterion_group!(benches, benchmark_placeholder);
criterion_main!(benches); 