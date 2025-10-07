use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rust_keyvault::{Algorithm, KeyId, KeyMetadata, KeyState, key::{SecretKey, VersionedKey}};
use rust_keyvault::export::ExportedKey;
use std::time::Duration;

/// Helper function to create a test key
fn create_test_key(algorithm: Algorithm) -> VersionedKey {
    let secret_key = SecretKey::generate(algorithm)
        .expect("Failed to generate key");
    let key_id = KeyId::generate().expect("Failed to generate KeyId");
    let base_id = KeyId::generate_base().expect("Failed to generate base ID");
    let metadata = KeyMetadata {
        id: key_id,
        base_id,
        state: KeyState::Active,
        created_at: std::time::SystemTime::now(),
        expires_at: None,
        algorithm,
        version: 1,
    };
    VersionedKey {
        key: secret_key,
        metadata,
    }
}

/// Benchmark key export
fn bench_key_export(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_export");
    group.measurement_time(Duration::from_secs(20));
    
    let key = create_test_key(Algorithm::Aes256Gcm);
    let password = b"benchmark-password-with-sufficient-entropy";
    
    group.bench_function("export_default", |b| {
        b.iter(|| {
            ExportedKey::new(
                black_box(&key.key),
                black_box(key.metadata.clone()),
                black_box(password),
                black_box(Algorithm::XChaCha20Poly1305)
            )
        });
    });
    
    group.finish();
}

/// Benchmark key import (decryption)
fn bench_key_import(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_import");
    group.measurement_time(Duration::from_secs(20));
    
    let key = create_test_key(Algorithm::Aes256Gcm);
    let password = b"benchmark-password-with-sufficient-entropy";
    
    // Pre-export the key
    let exported = ExportedKey::new(&key.key, key.metadata.clone(), password, Algorithm::XChaCha20Poly1305)
        .expect("Failed to export key");
    
    group.bench_function("import_default", |b| {
        b.iter(|| {
            exported.decrypt(black_box(password))
        });
    });
    
    group.finish();
}

/// Benchmark export/import round-trip
fn bench_export_import_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("export_import_roundtrip");
    group.measurement_time(Duration::from_secs(30));
    
    let key = create_test_key(Algorithm::Aes256Gcm);
    let password = b"benchmark-password-with-sufficient-entropy";
    
    group.bench_function("full_roundtrip", |b| {
        b.iter(|| {
            let exported = ExportedKey::new(
                black_box(&key.key),
                black_box(key.metadata.clone()),
                black_box(password),
                black_box(Algorithm::XChaCha20Poly1305)
            ).expect("Failed to export");
            
            exported.decrypt(black_box(password))
                .expect("Failed to import");
        });
    });
    
    group.finish();
}

/// Benchmark JSON serialization/deserialization
fn bench_json_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("json_serialization");
    group.measurement_time(Duration::from_secs(10));
    
    let key = create_test_key(Algorithm::Aes256Gcm);
    let password = b"benchmark-password-with-sufficient-entropy";
    let exported = ExportedKey::new(&key.key, key.metadata.clone(), password, Algorithm::XChaCha20Poly1305)
        .expect("Failed to export key");
    
    // Serialize to JSON
    group.bench_function("to_json", |b| {
        b.iter(|| {
            exported.to_json().expect("Failed to serialize")
        });
    });
    
    // Deserialize from JSON
    let json_data = exported.to_json().expect("Failed to serialize");
    group.bench_function("from_json", |b| {
        b.iter(|| {
            ExportedKey::from_json(black_box(&json_data))
                .expect("Failed to deserialize")
        });
    });
    
    group.finish();
}

criterion_group!(
    benches,
    bench_key_export,
    bench_key_import,
    bench_export_import_roundtrip,
    bench_json_serialization
);
criterion_main!(benches);
