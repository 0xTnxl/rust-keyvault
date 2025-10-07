use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rust_keyvault::{key::SecretKey, Algorithm};
use std::time::Duration;

/// Benchmark key generation with different algorithms
fn bench_key_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_generation");
    group.measurement_time(Duration::from_secs(10));

    // AES-256-GCM key generation
    group.bench_function("aes256_gcm", |b| {
        b.iter(|| SecretKey::generate(black_box(Algorithm::Aes256Gcm)));
    });

    // ChaCha20-Poly1305 key generation
    group.bench_function("chacha20_poly1305", |b| {
        b.iter(|| SecretKey::generate(black_box(Algorithm::ChaCha20Poly1305)));
    });

    // XChaCha20-Poly1305 key generation
    group.bench_function("xchacha20_poly1305", |b| {
        b.iter(|| SecretKey::generate(black_box(Algorithm::XChaCha20Poly1305)));
    });

    group.finish();
}

criterion_group!(benches, bench_key_generation);
criterion_main!(benches);
