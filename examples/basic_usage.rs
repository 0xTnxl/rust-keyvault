// Primary example as at v0.1.0

use rust_keyvault::key::{SecretKey, VersionedKey};
use rust_keyvault::storage::*;
use rust_keyvault::*;
use std::time::SystemTime;

fn main() -> Result<()> {
    println!("rust-keyvault basic usage example");

    // Create in-memory store for demo
    let mut store = MemoryStore::new();

    // Generate a new key
    let base_id = KeyId::generate_base()?;
    let secret_key = SecretKey::generate(Algorithm::ChaCha20Poly1305)?;

    let metadata = KeyMetadata {
        id: base_id.clone(),
        base_id: base_id.clone(),
        algorithm: Algorithm::ChaCha20Poly1305,
        created_at: SystemTime::now(),
        expires_at: None,
        state: KeyState::Active,
        version: 1,
    };

    let versioned_key = VersionedKey {
        key: secret_key,
        metadata,
    };

    // Store the key
    let _ = store.store(versioned_key)?;
    println!("Key stored successfully");

    // Retrieve the key and display it
    let retrieve = store.retrieve(&base_id)?;
    println!("Retrieved key: {:?}", retrieve.metadata.algorithm);

    // Rotate the key
    let rotated = store.rotate_key(&base_id)?;
    println!("Rotated to version: {}", rotated.metadata.version);

    // List all the keys
    let keys = store.list()?;
    println!("Total keys in store: {}", keys.len());

    println!("Example completed successfully");

    Ok(())
}
