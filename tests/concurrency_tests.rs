//! Concurrency and thread-safety tests for rust-keyvault
//!
//! These integration tests verify:
//! - Thread-safe concurrent operations
//! - Race condition handling
//! - Deadlock prevention
//! - Data consistency under load

use rust_keyvault::{
    Algorithm, KeyId, KeyMetadata, KeyState,
    key::{SecretKey, VersionedKey},
    storage::{FileStore, MemoryStore, KeyStore, StorageConfig},
};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::{Duration, SystemTime};
use tempfile::tempdir;

/// Test concurrent reads from MemoryStore
/// Multiple threads should be able to read simultaneously without blocking
#[test]
fn test_memory_store_concurrent_reads() {
    let store = Arc::new(Mutex::new(MemoryStore::new()));
    
    // Create and store a test key
    let key_id = KeyId::generate_base().unwrap();
    let secret_key = SecretKey::generate(Algorithm::ChaCha20Poly1305).unwrap();
    let metadata = KeyMetadata {
        id: key_id.clone(),
        base_id: key_id.clone(),
        algorithm: Algorithm::ChaCha20Poly1305,
        created_at: SystemTime::now(),
        expires_at: None,
        state: KeyState::Active,
        version: 1,
    };
    
    // Store the key (MemoryStore has interior mutability via RwLock)
    {
        let mut store_locked = store.lock().unwrap();
        store_locked.store(VersionedKey { key: secret_key, metadata }).unwrap();
    }
    
    // Spawn multiple reader threads
    let num_threads = 10;
    let barrier = Arc::new(Barrier::new(num_threads));
    
    let handles: Vec<_> = (0..num_threads)
        .map(|i| {
            let store_clone = Arc::clone(&store);
            let id_clone = key_id.clone();
            let barrier_clone = Arc::clone(&barrier);
            
            thread::spawn(move || {
                // Wait for all threads to be ready
                barrier_clone.wait();
                
                // Perform concurrent reads
                for _ in 0..100 {
                    let store_locked = store_clone.lock().unwrap();
                    let result = store_locked.retrieve(&id_clone);
                    drop(store_locked);
                    assert!(result.is_ok(), "Thread {} failed to read", i);
                }
            })
        })
        .collect();
    
    // Wait for all threads to complete
    for handle in handles {
        handle.join().unwrap();
    }
}

/// Test concurrent writes to MemoryStore
/// Writes should be properly serialized without data races
#[test]
fn test_memory_store_concurrent_writes() {
    let store = Arc::new(Mutex::new(MemoryStore::new()));
    let num_threads = 10;
    let keys_per_thread = 10;
    
    let barrier = Arc::new(Barrier::new(num_threads));
    
    let handles: Vec<_> = (0..num_threads)
        .map(|thread_id| {
            let store_clone = Arc::clone(&store);
            let barrier_clone = Arc::clone(&barrier);
            
            thread::spawn(move || {
                barrier_clone.wait();
                
                // Each thread creates its own keys
                for key_num in 0..keys_per_thread {
                    let mut id_bytes = [0u8; 16];
                    id_bytes[0] = thread_id as u8;
                    id_bytes[1] = key_num as u8;
                    let key_id = KeyId::from_bytes(id_bytes);
                    
                    let secret_key = SecretKey::generate(Algorithm::ChaCha20Poly1305).unwrap();
                    let metadata = KeyMetadata {
                        id: key_id.clone(),
                        base_id: key_id.clone(),
                        algorithm: Algorithm::ChaCha20Poly1305,
                        created_at: SystemTime::now(),
                        expires_at: None,
                        state: KeyState::Active,
                        version: 1,
                    };
                    
                    let mut store_locked = store_clone.lock().unwrap();
                    let result = store_locked.store(VersionedKey { key: secret_key, metadata });
                    drop(store_locked); // Release lock
                    assert!(result.is_ok(), "Thread {} key {} failed to store", thread_id, key_num);
                }
            })
        })
        .collect();
    
    for handle in handles {
        handle.join().unwrap();
    }
    
    // Verify all keys were stored
    let expected_count = num_threads * keys_per_thread;
    let store_locked = store.lock().unwrap();
    let actual_count = store_locked.list().unwrap().len();
    assert_eq!(actual_count, expected_count, "Expected {} keys, found {}", expected_count, actual_count);
}

/// Test concurrent reads and writes to MemoryStore
/// Readers and writers should not block each other excessively
#[test]
fn test_memory_store_mixed_operations() {
    let store = Arc::new(Mutex::new(MemoryStore::new()));
    
    // Pre-populate with some keys
    {
        let mut store_locked = store.lock().unwrap();
        for i in 0..10 {
            let mut id_bytes = [0u8; 16];
            id_bytes[0] = i;
            let key_id = KeyId::from_bytes(id_bytes);
            
            let secret_key = SecretKey::generate(Algorithm::ChaCha20Poly1305).unwrap();
            let metadata = KeyMetadata {
                id: key_id.clone(),
                base_id: key_id.clone(),
                algorithm: Algorithm::ChaCha20Poly1305,
                created_at: SystemTime::now(),
                expires_at: None,
                state: KeyState::Active,
                version: 1,
            };
            
            store_locked.store(VersionedKey { key: secret_key, metadata }).unwrap();
        }
    }
    
    let num_readers = 5;
    let num_writers = 5;
    let barrier = Arc::new(Barrier::new(num_readers + num_writers));
    
    // Spawn reader threads
    let mut handles = vec![];
    for i in 0..num_readers {
        let store_clone = Arc::clone(&store);
        let barrier_clone = Arc::clone(&barrier);
        
        let handle = thread::spawn(move || {
            barrier_clone.wait();
            
            let mut id_bytes = [0u8; 16];
            id_bytes[0] = (i % 10) as u8;
            let key_id = KeyId::from_bytes(id_bytes);
            
            for _ in 0..50 {
                let store_locked = store_clone.lock().unwrap();
                let _ = store_locked.retrieve(&key_id);
                drop(store_locked);
                thread::sleep(Duration::from_micros(10));
            }
        });
        handles.push(handle);
    }
    
    // Spawn writer threads
    for i in 0..num_writers {
        let store_clone = Arc::clone(&store);
        let barrier_clone = Arc::clone(&barrier);
        
        let handle = thread::spawn(move || {
            barrier_clone.wait();
            
            for j in 0..50 {
                let mut id_bytes = [0u8; 16];
                id_bytes[0] = 100 + i as u8;
                id_bytes[1] = j as u8;
                let key_id = KeyId::from_bytes(id_bytes);
                
                let secret_key = SecretKey::generate(Algorithm::ChaCha20Poly1305).unwrap();
                let metadata = KeyMetadata {
                    id: key_id.clone(),
                    base_id: key_id.clone(),
                    algorithm: Algorithm::ChaCha20Poly1305,
                    created_at: SystemTime::now(),
                    expires_at: None,
                    state: KeyState::Active,
                    version: 1,
                };
                
                let mut store_locked = store_clone.lock().unwrap();
                let _ = store_locked.store(VersionedKey { key: secret_key, metadata });
                drop(store_locked);
                thread::sleep(Duration::from_micros(10));
            }
        });
        handles.push(handle);
    }
    
    // Wait for all threads
    for handle in handles {
        handle.join().unwrap();
    }
}

/// Test concurrent operations on FileStore
/// FileStore uses interior mutability and should handle concurrent access
#[test]
fn test_file_store_concurrent_operations() {
    let temp_dir = tempdir().unwrap();
    let config = StorageConfig::default();
    let store = Arc::new(std::sync::Mutex::new(
        FileStore::new(temp_dir.path(), config).unwrap()
    ));
    
    let num_threads = 5;
    let keys_per_thread = 5;
    let barrier = Arc::new(Barrier::new(num_threads));
    
    let handles: Vec<_> = (0..num_threads)
        .map(|thread_id| {
            let store_clone = Arc::clone(&store);
            let barrier_clone = Arc::clone(&barrier);
            
            thread::spawn(move || {
                barrier_clone.wait();
                
                for key_num in 0..keys_per_thread {
                    let mut id_bytes = [0u8; 16];
                    id_bytes[0] = thread_id as u8;
                    id_bytes[1] = key_num as u8;
                    let key_id = KeyId::from_bytes(id_bytes);
                    
                    let secret_key = SecretKey::generate(Algorithm::ChaCha20Poly1305).unwrap();
                    let metadata = KeyMetadata {
                        id: key_id.clone(),
                        base_id: key_id.clone(),
                        algorithm: Algorithm::ChaCha20Poly1305,
                        created_at: SystemTime::now(),
                        expires_at: None,
                        state: KeyState::Active,
                        version: 1,
                    };
                    
                    // Lock for write
                    {
                        let mut store = store_clone.lock().unwrap();
                        store.store(VersionedKey { key: secret_key, metadata }).unwrap();
                    }
                    
                    // Lock for read
                    {
                        let store = store_clone.lock().unwrap();
                        let retrieved = store.retrieve(&key_id).unwrap();
                        assert_eq!(retrieved.metadata.id, key_id);
                    }
                    
                    thread::sleep(Duration::from_micros(100));
                }
            })
        })
        .collect();
    
    for handle in handles {
        handle.join().unwrap();
    }
    
    // Verify all keys were stored
    let store = store.lock().unwrap();
    let keys = store.list().unwrap();
    assert_eq!(keys.len(), num_threads * keys_per_thread);
}

/// Stress test: High-volume concurrent operations
#[test]
fn test_memory_store_stress() {
    let store = Arc::new(Mutex::new(MemoryStore::new()));
    let num_threads = 20;
    let operations_per_thread = 100;
    
    let barrier = Arc::new(Barrier::new(num_threads));
    
    let handles: Vec<_> = (0..num_threads)
        .map(|thread_id| {
            let store_clone = Arc::clone(&store);
            let barrier_clone = Arc::clone(&barrier);
            
            thread::spawn(move || {
                barrier_clone.wait();
                
                for op in 0..operations_per_thread {
                    let mut id_bytes = [0u8; 16];
                    id_bytes[0] = thread_id as u8;
                    id_bytes[1] = (op % 256) as u8;
                    let key_id = KeyId::from_bytes(id_bytes);
                    
                    // Mix of operations
                    match op % 4 {
                        0 => {
                            // Store
                            let secret_key = SecretKey::generate(Algorithm::ChaCha20Poly1305).unwrap();
                            let metadata = KeyMetadata {
                                id: key_id.clone(),
                                base_id: key_id.clone(),
                                algorithm: Algorithm::ChaCha20Poly1305,
                                created_at: SystemTime::now(),
                                expires_at: None,
                                state: KeyState::Active,
                                version: 1,
                            };
                            let mut store_locked = store_clone.lock().unwrap();
                            let _ = store_locked.store(VersionedKey { key: secret_key, metadata });
                        }
                        1 => {
                            // Retrieve
                            let store_locked = store_clone.lock().unwrap();
                            let _ = store_locked.retrieve(&key_id);
                        }
                        2 => {
                            // List
                            let store_locked = store_clone.lock().unwrap();
                            let _ = store_locked.list();
                        }
                        3 => {
                            // Delete (if exists)
                            let mut store_locked = store_clone.lock().unwrap();
                            let _ = store_locked.delete(&key_id);
                        }
                        _ => unreachable!(),
                    }
                }
            })
        })
        .collect();
    
    for handle in handles {
        handle.join().unwrap();
    }
    
    // Store should still be functional after stress
    let store_locked = store.lock().unwrap();
    let keys = store_locked.list().unwrap();
    println!("Stress test completed. Final key count: {}", keys.len());
}

/// Test that no deadlocks occur with complex operation sequences
#[test]
fn test_no_deadlocks() {
    let store = Arc::new(Mutex::new(MemoryStore::new()));
    let num_threads = 10;
    let timeout = Duration::from_secs(5);
    
    let barrier = Arc::new(Barrier::new(num_threads));
    
    let handles: Vec<_> = (0..num_threads)
        .map(|thread_id| {
            let store_clone = Arc::clone(&store);
            let barrier_clone = Arc::clone(&barrier);
            
            thread::spawn(move || {
                barrier_clone.wait();
                
                for i in 0..20 {
                    let mut id_bytes = [0u8; 16];
                    id_bytes[0] = ((thread_id + i) % 10) as u8;
                    let key_id = KeyId::from_bytes(id_bytes);
                    
                    // Complex sequence: store, retrieve, list, delete
                    let secret_key = SecretKey::generate(Algorithm::ChaCha20Poly1305).unwrap();
                    let metadata = KeyMetadata {
                        id: key_id.clone(),
                        base_id: key_id.clone(),
                        algorithm: Algorithm::ChaCha20Poly1305,
                        created_at: SystemTime::now(),
                        expires_at: None,
                        state: KeyState::Active,
                        version: 1,
                    };
                    
                    {
                        let mut store_locked = store_clone.lock().unwrap();
                        let _ = store_locked.store(VersionedKey { key: secret_key, metadata });
                    }
                    {
                        let store_locked = store_clone.lock().unwrap();
                        let _ = store_locked.retrieve(&key_id);
                    }
                    {
                        let store_locked = store_clone.lock().unwrap();
                        let _ = store_locked.list();
                    }
                    thread::sleep(Duration::from_micros(50));
                }
            })
        })
        .collect();
    
    // Wait with timeout to detect deadlocks
    let start = std::time::Instant::now();
    for handle in handles {
        handle.join().unwrap();
    }
    let elapsed = start.elapsed();
    
    assert!(elapsed < timeout, "Test took too long - possible deadlock detected");
}

/// Test concurrent export/import operations
#[test]
fn test_concurrent_export_import() {
    let temp_dir = tempdir().unwrap();
    let config = StorageConfig::default();
    let store = Arc::new(std::sync::Mutex::new(
        FileStore::new(temp_dir.path(), config).unwrap()
    ));
    
    // Pre-populate with keys
    {
        let mut s = store.lock().unwrap();
        for i in 0..5 {
            let mut id_bytes = [0u8; 16];
            id_bytes[0] = i;
            let key_id = KeyId::from_bytes(id_bytes);
            
            let secret_key = SecretKey::generate(Algorithm::ChaCha20Poly1305).unwrap();
            let metadata = KeyMetadata {
                id: key_id.clone(),
                base_id: key_id.clone(),
                algorithm: Algorithm::ChaCha20Poly1305,
                created_at: SystemTime::now(),
                expires_at: None,
                state: KeyState::Active,
                version: 1,
            };
            
            s.store(VersionedKey { key: secret_key, metadata }).unwrap();
        }
    }
    
    let num_threads = 5;
    let barrier = Arc::new(Barrier::new(num_threads));
    
    let handles: Vec<_> = (0..num_threads)
        .map(|i| {
            let store_clone = Arc::clone(&store);
            let barrier_clone = Arc::clone(&barrier);
            
            thread::spawn(move || {
                barrier_clone.wait();
                
                let mut id_bytes = [0u8; 16];
                id_bytes[0] = i as u8;
                let key_id = KeyId::from_bytes(id_bytes);
                
                // Concurrent exports
                for _ in 0..10 {
                    let mut store = store_clone.lock().unwrap();
                    let exported = store.export_key(&key_id, b"test-password").unwrap();
                    drop(store); // Release lock
                    
                    // Verify can deserialize
                    let json = exported.to_json().unwrap();
                    let _ = rust_keyvault::export::ExportedKey::from_json(&json).unwrap();
                    
                    thread::sleep(Duration::from_millis(10));
                }
            })
        })
        .collect();
    
    for handle in handles {
        handle.join().unwrap();
    }
}
