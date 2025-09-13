# rust-keyvault Usage Examples

This small guide demonstrates practical usage of rust-keyvault based on the actual implementation.

## Table of Contents

1. [Basic Key Management](#basic-key-management)
2. [Encrypted File Storage](#encrypted-file-storage)  
3. [Key Rotation Workflow](#key-rotation-workflow)
4. [Key Lifecycle Management](#key-lifecycle-management)
5. [Error Handling](#error-handling)

## Basic Key Management

### Creating and Storing Keys

```rust
use rust_keyvault::*;
use rust_keyvault::storage::*;
use std::time::SystemTime;

fn basic_key_management() -> Result<()> {
    // Create in-memory store for testing
    let mut store = MemoryStore::new();
    
    // Generate a base key ID for the key family
    let base_id = KeyId::generate_base()?;
    
    // Generate secret key material
    let secret_key = SecretKey::generate(Algorithm::ChaCha20Poly1305)?;
    
    // Create metadata
    let metadata = KeyMetadata {
        id: base_id.clone(),
        base_id: base_id.clone(),
        algorithm: Algorithm::ChaCha20Poly1305,
        created_at: SystemTime::now(),
        expires_at: None,
        state: KeyState::Active,
        version: 1,
    };
    
    // Create versioned key
    let versioned_key = VersionedKey { key: secret_key, metadata };
    
    // Store the key
    store.store(versioned_key)?;
    
    // Retrieve the key
    let retrieved = store.retrieve(&base_id)?;
    println!("Retrieved key: {:?}", retrieved.metadata.id);
    
    // List all keys
    let key_list = store.list()?;
    println!("Total keys: {}", key_list.len());
    
    Ok(())
}
```

### Key Properties and Validation

```rust
fn key_validation_example() -> Result<()> {
    let secret_key = SecretKey::generate(Algorithm::Aes256Gcm)?;
    
    // Check algorithm
    assert_eq!(secret_key.algorithm(), Algorithm::Aes256Gcm);
    
    // Access raw bytes (be careful!)
    let raw_bytes = secret_key.expose_secret();
    println!("Key size: {} bytes", raw_bytes.len());
    
    // Constant-time comparison
    let other_key = SecretKey::generate(Algorithm::Aes256Gcm)?;
    let are_equal = secret_key.ct_eq(&other_key);
    println!("Keys equal: {}", are_equal); // Should be false
    
    Ok(())
}
```

## Encrypted File Storage

### Setting Up Encrypted Storage

```rust
use tempfile::tempdir;

fn encrypted_storage_example() -> Result<()> {
    // Create temporary directory for demo
    let temp_dir = tempdir().map_err(|e| Error::storage(e.to_string()))?;
    
    // Configure encrypted storage
    let config = StorageConfig {
        encrypted: true,
        compressed: false,
        cache_size: 100,
        path: None,
    };
    
    // Create file store
    let mut store = FileStore::new(temp_dir.path(), config)?;
    
    // Initialize with password (uses Argon2 key derivation)
    store.init_with_password(b"my-secure-password-123")?;
    
    // Verify store is unlocked
    assert!(store.is_unlocked());
    
    // Store a key (automatically encrypted)
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
    
    let versioned_key = VersionedKey { key: secret_key, metadata };
    store.store(versioned_key)?;
    
    // Key is automatically encrypted on disk
    println!("Key stored at: {}", store.location());
    
    Ok(())
}
```

### Persistence Across Sessions

```rust
fn persistence_example() -> Result<()> {
    let temp_dir = tempdir().map_err(|e| Error::storage(e.to_string()))?;
    let config = StorageConfig { encrypted: true, ..Default::default() };
    let password = b"persistent-password";
    
    let key_id = KeyId::generate_base()?;
    
    // First session: create and store
    {
        let mut store = FileStore::new(temp_dir.path(), config.clone())?;
        store.init_with_password(password)?;
        
        let secret_key = SecretKey::generate(Algorithm::Aes256Gcm)?;
        let metadata = KeyMetadata {
            id: key_id.clone(),
            base_id: key_id.clone(),
            algorithm: Algorithm::Aes256Gcm,
            created_at: SystemTime::now(),
            expires_at: None,
            state: KeyState::Active,
            version: 1,
        };
        
        let versioned_key = VersionedKey { key: secret_key, metadata };
        store.store(versioned_key)?;
        
        println!("Stored key in session 1");
    } // Store dropped, session ends
    
    // Second session: load and verify
    {
        let mut store = FileStore::new(temp_dir.path(), config)?;
        store.init_with_password(password)?;
        
        let retrieved = store.retrieve(&key_id)?;
        println!("Retrieved key in session 2: {:?}", retrieved.metadata.algorithm);
    }
    
    Ok(())
}
```

## Key Rotation Workflow

### Basic Rotation

```rust
fn key_rotation_example() -> Result<()> {
    let config = StorageConfig { encrypted: true, ..Default::default() };
    let temp_dir = tempdir().map_err(|e| Error::storage(e.to_string()))?;
    let mut store = FileStore::new(temp_dir.path(), config)?;
    store.init_with_password(b"rotation-password")?;
    
    // Create initial key (version 1)
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
    
    let initial_key = VersionedKey { key: secret_key, metadata };
    store.store(initial_key)?;
    
    println!("Initial key stored (version 1)");
    
    // Rotate to version 2
    let rotated_key = store.rotate_key(&base_id)?;
    println!("Rotated to version: {}", rotated_key.metadata.version);
    
    // Check that old key is deprecated
    let old_key = store.retrieve(&base_id)?;
    assert_eq!(old_key.metadata.state, KeyState::Deprecated);
    
    // Get latest active key
    let latest = store.get_latest_key(&base_id)?;
    assert_eq!(latest.metadata.version, 2);
    assert_eq!(latest.metadata.state, KeyState::Active);
    
    // Get all versions
    let versions = store.get_key_versions(&base_id)?;
    println!("Total versions: {}", versions.len()); // Should be 2
    
    Ok(())
}
```

### Multiple Rotations

```rust
fn multiple_rotations_example() -> Result<()> {
    let mut store = MemoryStore::new();
    
    // Create base key
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
    
    let initial_key = VersionedKey { key: secret_key, metadata };
    store.store(initial_key)?;
    
    // Perform multiple rotations
    for i in 2..=5 {
        let rotated = store.rotate_key(&base_id)?;
        println!("Rotated to version: {}", rotated.metadata.version);
        assert_eq!(rotated.metadata.version, i);
    }
    
    // Verify final state
    let versions = store.get_key_versions(&base_id)?;
    assert_eq!(versions.len(), 5);
    
    let latest = store.get_latest_key(&base_id)?;
    assert_eq!(latest.metadata.version, 5);
    
    Ok(())
}
```

## Key Lifecycle Management

### State Transitions

```rust
fn lifecycle_management_example() -> Result<()> {
    let temp_dir = tempdir().map_err(|e| Error::storage(e.to_string()))?;
    let config = StorageConfig::default();
    let mut store = FileStore::new(temp_dir.path(), config)?;
    
    // Create and store key
    let key_id = KeyId::generate_base()?;
    let secret_key = SecretKey::generate(Algorithm::ChaCha20Poly1305)?;
    
    let metadata = KeyMetadata {
        id: key_id.clone(),
        base_id: key_id.clone(),
        algorithm: Algorithm::ChaCha20Poly1305,
        created_at: SystemTime::now(),
        expires_at: None,
        state: KeyState::Active,
        version: 1,
    };
    
    let versioned_key = VersionedKey { key: secret_key, metadata };
    store.store(versioned_key)?;
    
    // Check initial capabilities
    let key = store.retrieve(&key_id)?;
    assert!(key.can_encrypt());
    assert!(key.can_decrypt());
    
    // Deprecate the key
    store.deprecate_key(&key_id)?;
    let deprecated_key = store.retrieve(&key_id)?;
    assert_eq!(deprecated_key.metadata.state, KeyState::Deprecated);
    assert!(!deprecated_key.can_encrypt()); // Can't encrypt
    assert!(deprecated_key.can_decrypt());  // Can still decrypt
    
    // Revoke the key
    store.revoke_key(&key_id)?;
    let revoked_key = store.retrieve(&key_id)?;
    assert_eq!(revoked_key.metadata.state, KeyState::Revoked);
    assert!(!revoked_key.can_encrypt()); // Can't encrypt
    assert!(!revoked_key.can_decrypt()); // Can't decrypt
    
    Ok(())
}
```

### Cleanup Old Versions

```rust
fn cleanup_example() -> Result<()> {
    let mut store = MemoryStore::new();
    
    // Create base key and multiple versions
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
    
    let initial_key = VersionedKey { key: secret_key, metadata };
    store.store(initial_key)?;
    
    // Create 5 versions total
    for _ in 2..=5 {
        store.rotate_key(&base_id)?;
    }
    
    // Manually deprecate some old versions
    let versions = store.get_key_versions(&base_id)?;
    for old_version in &versions[..3] { // First 3 versions
        store.deprecate_key(&old_version.metadata.id)?;
    }
    
    // Cleanup - keep only 2 most recent versions
    let removed = store.cleanup_old_versions(&base_id, 2)?;
    println!("Removed {} old versions", removed.len());
    
    // Verify cleanup
    let remaining = store.get_key_versions(&base_id)?;
    assert!(remaining.len() <= 2);
    
    Ok(())
}
```

## Error Handling

### Comprehensive Error Handling

```rust
fn error_handling_example() {
    use rust_keyvault::Error;
    
    // Handle different error types
    let result = || -> Result<()> {
        let mut store = MemoryStore::new();
        
        // This will cause KeyNotFound error
        let non_existent = KeyId::from_bytes([99; 16]);
        store.retrieve(&non_existent)?;
        
        Ok(())
    }();
    
    match result {
        Err(Error::StorageError(msg)) => {
            println!("Storage error: {}", msg);
        }
        Err(Error::CryptoError(msg)) => {
            println!("Crypto error: {}", msg);
        }
        Err(Error::KeyNotFound(id)) => {
            println!("Key not found: {:?}", id);
        }
        Err(e) => {
            println!("Other error: {}", e);
        }
        Ok(_) => println!("Success"),
    }
}

fn wrong_password_example() -> Result<()> {
    let temp_dir = tempdir().map_err(|e| Error::storage(e.to_string()))?;
    let config = StorageConfig { encrypted: true, ..Default::default() };
    
    // Store with one password
    {
        let mut store = FileStore::new(temp_dir.path(), config.clone())?;
        store.init_with_password(b"correct-password")?;
        
        let key_id = KeyId::generate_base()?;
        let secret_key = SecretKey::generate(Algorithm::ChaCha20Poly1305)?;
        let metadata = KeyMetadata {
            id: key_id.clone(),
            base_id: key_id.clone(),
            algorithm: Algorithm::ChaCha20Poly1305,
            created_at: SystemTime::now(),
            expires_at: None,
            state: KeyState::Active,
            version: 1,
        };
        
        let versioned_key = VersionedKey { key: secret_key, metadata };
        store.store(versioned_key)?;
    }
    
    // Try to access with wrong password
    {
        let mut store = FileStore::new(temp_dir.path(), config)?;
        store.init_with_password(b"wrong-password")?;
        
        let key_id = KeyId::from_bytes([1; 16]);
        match store.retrieve(&key_id) {
            Err(Error::CryptoError(_)) => {
                println!("Expected: Wrong password causes crypto error");
            }
            other => {
                println!("Unexpected result: {:?}", other);
            }
        }
    }
    
    Ok(())
}
```

## Complete Example Application

```rust
//! Complete example showing real-world usage

use rust_keyvault::*;
use rust_keyvault::storage::*;
use std::time::SystemTime;
use tempfile::tempdir;

fn main() -> Result<()> {
    // Setup encrypted storage
    let temp_dir = tempdir().map_err(|e| Error::storage(e.to_string()))?;
    let config = StorageConfig { encrypted: true, ..Default::default() };
    let mut store = FileStore::new(temp_dir.path(), config)?;
    store.init_with_password(b"my-application-password")?;
    
    println!("🔐 Key vault initialized");
    
    // Create application key
    let app_key_id = KeyId::generate_base()?;
    let secret_key = SecretKey::generate(Algorithm::ChaCha20Poly1305)?;
    
    let metadata = KeyMetadata {
        id: app_key_id.clone(),
        base_id: app_key_id.clone(),
        algorithm: Algorithm::ChaCha20Poly1305,
        created_at: SystemTime::now(),
        expires_at: None,
        state: KeyState::Active,
        version: 1,
    };
    
    let versioned_key = VersionedKey { key: secret_key, metadata };
    store.store(versioned_key)?;
    
    println!("🔑 Application key created and stored");
    
    // Simulate key rotation after some time
    println!("🔄 Rotating key...");
    let rotated_key = store.rotate_key(&app_key_id)?;
    println!("✅ Key rotated to version {}", rotated_key.metadata.version);
    
    // List all key versions
    let versions = store.get_key_versions(&app_key_id)?;
    println!("📋 Total key versions: {}", versions.len());
    
    for version in &versions {
        println!("  - Version {}: {:?}", version.metadata.version, version.metadata.state);
    }
    
    // Get latest key for encryption
    let latest = store.get_latest_key(&app_key_id)?;
    println!("🆕 Latest key version: {}", latest.metadata.version);
    
    // Cleanup old versions (keep 2 most recent)
    let removed = store.cleanup_old_versions(&app_key_id, 2)?;
    println!("🧹 Cleaned up {} old versions", removed.len());
    
    println!("✅ Key management workflow completed successfully");
    
    Ok(())
}
```

This example demonstrates a complete key management workflow including creation, rotation, and cleanup in a real application context.