use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use rust_keyvault::storage::{FileStore, KeyStore, MemoryStore, StorageConfig};
use rust_keyvault::{
    key::{SecretKey, VersionedKey},
    Algorithm, KeyId, KeyMetadata, KeyState,
};
use std::time::Duration;
use tempfile::TempDir;

/// Helper function to create a test key
fn create_test_key(algorithm: Algorithm) -> VersionedKey {
    let secret_key = SecretKey::generate(algorithm).expect("Failed to generate key");
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

/// Benchmark MemoryStore operations
fn bench_memory_store(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_store");
    group.measurement_time(Duration::from_secs(10));

    // Store operation
    group.bench_function("store", |b| {
        let mut store = MemoryStore::new();
        let key = create_test_key(Algorithm::Aes256Gcm);

        b.iter(|| {
            store
                .store(black_box(key.clone()))
                .expect("Failed to store key");
        });
    });

    // Retrieve operation
    group.bench_function("retrieve", |b| {
        let mut store = MemoryStore::new();
        let key = create_test_key(Algorithm::Aes256Gcm);
        let key_id = key.metadata.id.clone();
        store.store(key).expect("Failed to store key");

        b.iter(|| {
            store
                .retrieve(black_box(&key_id))
                .expect("Failed to retrieve key");
        });
    });

    // List operation with varying sizes
    for count in [10, 100, 1000].iter() {
        group.bench_with_input(BenchmarkId::new("list", count), count, |b, &count| {
            let mut store = MemoryStore::new();

            // Populate store
            for _i in 0..count {
                let key = create_test_key(Algorithm::Aes256Gcm);
                store.store(key).expect("Failed to store key");
            }

            b.iter(|| {
                black_box(store.list().expect("Failed to list keys"));
            });
        });
    }

    // Delete operation
    group.bench_function("delete", |b| {
        b.iter_batched(
            || {
                let mut store = MemoryStore::new();
                let key = create_test_key(Algorithm::Aes256Gcm);
                let key_id = key.metadata.id.clone();
                store.store(key).expect("Failed to store key");
                (store, key_id)
            },
            |(mut store, key_id)| {
                store
                    .delete(black_box(&key_id))
                    .expect("Failed to delete key");
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

/// Benchmark FileStore operations
fn bench_file_store(c: &mut Criterion) {
    let mut group = c.benchmark_group("file_store");
    group.measurement_time(Duration::from_secs(15));

    // Store operation
    group.bench_function("store", |b| {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let mut store = FileStore::new(temp_dir.path(), StorageConfig::default())
            .expect("Failed to create FileStore");
        let key = create_test_key(Algorithm::Aes256Gcm);

        b.iter(|| {
            store
                .store(black_box(key.clone()))
                .expect("Failed to store key");
        });
    });

    // Retrieve operation
    group.bench_function("retrieve", |b| {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let mut store = FileStore::new(temp_dir.path(), StorageConfig::default())
            .expect("Failed to create FileStore");
        let key = create_test_key(Algorithm::Aes256Gcm);
        let key_id = key.metadata.id.clone();
        store.store(key).expect("Failed to store key");

        b.iter(|| {
            store
                .retrieve(black_box(&key_id))
                .expect("Failed to retrieve key");
        });
    });

    // List operation with varying sizes
    for count in [10, 100].iter() {
        group.bench_with_input(BenchmarkId::new("list", count), count, |b, &count| {
            let temp_dir = TempDir::new().expect("Failed to create temp dir");
            let mut store = FileStore::new(temp_dir.path(), StorageConfig::default())
                .expect("Failed to create FileStore");

            // Populate store
            for _i in 0..count {
                let key = create_test_key(Algorithm::Aes256Gcm);
                store.store(key).expect("Failed to store key");
            }

            b.iter(|| {
                black_box(store.list().expect("Failed to list keys"));
            });
        });
    }

    // Delete operation
    group.bench_function("delete", |b| {
        b.iter_batched(
            || {
                let temp_dir = TempDir::new().expect("Failed to create temp dir");
                let mut store = FileStore::new(temp_dir.path(), StorageConfig::default())
                    .expect("Failed to create FileStore");
                let key = create_test_key(Algorithm::Aes256Gcm);
                let key_id = key.metadata.id.clone();
                store.store(key).expect("Failed to store key");
                (store, key_id)
            },
            |(mut store, key_id)| {
                store
                    .delete(black_box(&key_id))
                    .expect("Failed to delete key");
            },
            criterion::BatchSize::SmallInput,
        );
    });

    // Load operation (cold start)
    group.bench_function("load_cold", |b| {
        b.iter_batched(
            || {
                let temp_dir = TempDir::new().expect("Failed to create temp dir");
                let mut store = FileStore::new(temp_dir.path(), StorageConfig::default())
                    .expect("Failed to create FileStore");

                // Pre-populate with keys
                for _i in 0..10 {
                    let key = create_test_key(Algorithm::Aes256Gcm);
                    store.store(key).expect("Failed to store key");
                }

                temp_dir
            },
            |temp_dir| {
                let _store = FileStore::new(temp_dir.path(), StorageConfig::default())
                    .expect("Failed to load FileStore");
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(benches, bench_memory_store, bench_file_store);
criterion_main!(benches);
