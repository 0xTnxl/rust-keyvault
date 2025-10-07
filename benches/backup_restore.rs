use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use rust_keyvault::{Algorithm, KeyId, KeyMetadata, KeyState, key::{SecretKey, VersionedKey}};
use rust_keyvault::storage::{FileStore, KeyStore, StorageConfig};
use rust_keyvault::backup::BackupConfig;
use tempfile::TempDir;
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

/// Benchmark vault backup creation
fn bench_vault_backup(c: &mut Criterion) {
    let mut group = c.benchmark_group("vault_backup");
    group.measurement_time(Duration::from_secs(20));
    
    let password = b"benchmark-password-with-sufficient-entropy";
    
    // Benchmark with different vault sizes
    for key_count in [10, 50].iter() {
        group.bench_with_input(
            BenchmarkId::new("create_compressed", key_count),
            key_count,
            |b, &count| {
                b.iter_batched(
                    || {
                        // Setup: Create vault with keys
                        let temp_dir = TempDir::new().expect("Failed to create temp dir");
                        let mut store = FileStore::new(temp_dir.path(), StorageConfig::default())
                            .expect("Failed to create FileStore");
                        
                        for _i in 0..count {
                            let key = create_test_key(Algorithm::Aes256Gcm);
                            store.store(key).expect("Failed to store key");
                        }
                        
                        (store, temp_dir)
                    },
                    |(mut store, _temp_dir)| {
                        // Benchmark: Create backup
                        store.backup(
                            black_box(password),
                            black_box(BackupConfig {
                                compress: true,
                                include_audit_logs: true,
                                ..Default::default()
                            })
                        ).expect("Failed to create backup");
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }
    
    group.finish();
}

/// Benchmark vault restore
fn bench_vault_restore(c: &mut Criterion) {
    let mut group = c.benchmark_group("vault_restore");
    group.measurement_time(Duration::from_secs(20));
    
    let password = b"benchmark-password-with-sufficient-entropy";
    
    // Benchmark with different vault sizes
    for key_count in [10, 50].iter() {
        group.bench_with_input(
            BenchmarkId::new("restore_compressed", key_count),
            key_count,
            |b, &count| {
                b.iter_batched(
                    || {
                        // Setup: Create backup
                        let temp_dir = TempDir::new().expect("Failed to create temp dir");
                        let mut store = FileStore::new(temp_dir.path(), StorageConfig::default())
                            .expect("Failed to create FileStore");
                        
                        for _i in 0..count {
                            let key = create_test_key(Algorithm::Aes256Gcm);
                            store.store(key).expect("Failed to store key");
                        }
                        
                        let backup = store.backup(
                            password,
                            BackupConfig {
                                compress: true,
                                include_audit_logs: true,
                                ..Default::default()
                            }
                        ).expect("Failed to create backup");
                        
                        let restore_dir = TempDir::new().expect("Failed to create restore dir");
                        (backup, restore_dir, temp_dir)
                    },
                    |(backup, restore_dir, _temp_dir)| {
                        // Benchmark: Restore backup
                        let mut new_store = FileStore::new(restore_dir.path(), StorageConfig::default())
                            .expect("Failed to create new FileStore");
                        new_store.restore(
                            black_box(&backup),
                            black_box(password)
                        ).expect("Failed to restore backup");
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }
    
    group.finish();
}

/// Benchmark backup/restore round-trip
fn bench_backup_restore_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("backup_restore_roundtrip");
    group.measurement_time(Duration::from_secs(30));
    
    let password = b"benchmark-password-with-sufficient-entropy";
    
    group.bench_function("roundtrip_10_keys", |b| {
        b.iter_batched(
            || {
                let temp_dir = TempDir::new().expect("Failed to create temp dir");
                let mut store = FileStore::new(temp_dir.path(), StorageConfig::default())
                    .expect("Failed to create FileStore");
                
                for _i in 0..10 {
                    let key = create_test_key(Algorithm::Aes256Gcm);
                    store.store(key).expect("Failed to store key");
                }
                
                (store, temp_dir)
            },
            |(mut store, _temp_dir)| {
                let backup = store.backup(
                    black_box(password),
                    black_box(BackupConfig::default())
                ).expect("Failed to create backup");
                
                let restore_dir = TempDir::new().expect("Failed to create restore dir");
                let mut new_store = FileStore::new(restore_dir.path(), StorageConfig::default())
                    .expect("Failed to create new FileStore");
                new_store.restore(
                    black_box(&backup),
                    black_box(password)
                ).expect("Failed to restore backup");
            },
            criterion::BatchSize::SmallInput,
        );
    });
    
    group.finish();
}

criterion_group!(
    benches,
    bench_vault_backup,
    bench_vault_restore,
    bench_backup_restore_roundtrip
);
criterion_main!(benches);
